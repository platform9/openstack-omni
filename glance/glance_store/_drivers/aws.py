# Copyright (c) 2016 Platform9 Systems Inc. (http://www.platform9.com)
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import socket

from six.moves import http_client
from six.moves import urllib
from oslo_config import cfg
from ConfigParser import ConfigParser

from glance_store import capabilities
from glance_store import exceptions
from glance_store.i18n import _, _LE
import glance_store.driver
import glance_store.location

import boto3
import botocore.exceptions

LOG = logging.getLogger(__name__)

MAX_REDIRECTS = 5
STORE_SCHEME = 'aws'

aws_opts_group = cfg.OptGroup(name='aws', title='AWS specific options')
aws_opts = [
             cfg.StrOpt('access_key', help='AWS access key ID'),
             cfg.StrOpt('secret_key', help='AWS secret access key'),
             cfg.StrOpt('region_name', help='AWS region name'),
]

class StoreLocation(glance_store.location.StoreLocation):

    """Class describing an AWS URI."""

    def __init__(self, store_specs, conf):
        super(StoreLocation, self).__init__(store_specs, conf)

    def process_specs(self):
        self.scheme = self.specs.get('scheme', STORE_SCHEME)
        self.ami_id = self.specs.get('ami_id')

    def get_uri(self):
        return "{}://{}".format(self.scheme, self.ami_id)

    def parse_uri(self, uri):
        """
        Parse URLs. This method fixes an issue where credentials specified
        in the URL are interpreted differently in Python 2.6.1+ than prior
        versions of Python.
        """
        if not uri.startswith('%s://' % STORE_SCHEME):
            reason = (_("URI %(uri)s must start with %(scheme)s://") %
                      {'uri': uri, 'scheme': STORE_SCHEME})
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)
        pieces = urllib.parse.urlparse(uri)
        self.scheme = pieces.scheme
        ami_id = pieces.netloc
        if ami_id == '':
            LOG.info(_("No image ami_id specified in URL"))
            raise exceptions.BadStoreUri(uri=uri)
        self.ami_id = ami_id


class Store(glance_store.driver.Store):

    """An implementation of the HTTP(S) Backend Adapter"""

    _CAPABILITIES = (capabilities.BitMasks.RW_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)

    def __init__(self, conf):
        super(Store, self).__init__(conf)
        conf.register_group(aws_opts_group)
        conf.register_opts(aws_opts, group = aws_opts_group)
        self.credentials = {}
        self.credentials['aws_access_key_id'] = conf.aws.access_key
        self.credentials['aws_secret_access_key'] = conf.aws.secret_key
        self.credentials['region_name'] = conf.aws.region_name
        self.__ec2_client = None
        self.__ec2_resource = None

    def _get_ec2_client(self):
        if self.__ec2_client is None:
            self.__ec2_client = boto3.client('ec2', **self.credentials)
        return self.__ec2_client

    def _get_ec2_resource(self):
        if self.__ec2_resource is None:
            self.__ec2_resource = boto3.resource('ec2', **self.credentials)
        return self.__ec2_resource


    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        yield ('aws://generic', self.get_size(location, context))

    @capabilities.check
    def delete(self, location, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()
        :raises NotFound if image does not exist
        """
        ami_id = location.get_store_uri().split('/')[2]
        aws_client = self._get_ec2_client()
        aws_imgs = aws_client.describe_images(Owners=['self'])['Images']
        for img in aws_imgs:
            if ami_id == img.get('ImageId'):
                LOG.warn('**** ID of ami being deleted: {}'.format(ami_id))
                aws_client.deregister_image(ImageId=ami_id)


    def get_schemes(self):
        """
        :retval tuple: containing valid scheme names to
                associate with this store driver
        """
        return ('aws',)


    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :retval int: size of image file in bytes
        """
        ami_id = location.get_store_uri().split('/')[2]
        ec2_resource = self._get_ec2_resource()
        image = ec2_resource.Image(ami_id)
        size = 0
        try:
            image.load()
            # no size info for instance-store volumes, so return 0 in that case
            if image.root_device_type == 'ebs':
                for bdm in image.block_device_mappings:
                    if 'Ebs' in bdm and 'VolumeSize' in bdm['Ebs']:
                        LOG.debug('ebs info: %s', bdm['Ebs'])
                        size += bdm['Ebs']['VolumeSize']
                # convert size in gb to bytes
                size *= 1073741824
        except botocore.exceptions.ClientError as ce:
            if ce.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                raise exceptions.ImageDataNotFound()
            else:
                raise exceptions.GlanceStoreException(ce.response['Error']['Code'])
        return size
