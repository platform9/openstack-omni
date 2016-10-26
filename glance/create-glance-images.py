# Copyright (c) 2016 Platform9 Systems Inc. (http://www.platform9.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

'''
Run this script as: python create-glance-credentials.py <access-key> <secret-key> <region-name>
'''

import boto3
import ConfigParser
import hashlib
import keystoneauth1
import os
import requests
import sys
import uuid

from keystoneauth1 import session
from keystoneauth1.identity import v3

class AwsImages(object):

   def __init__(self, credentials):
       self.ec2_client = boto3.client('ec2', **credentials)
       self.glance_client = RestClient()
       self.aws_image_types = {'machine': 'ami', 'kernel': 'aki', 'ramdisk': 'ari'}

   def register_aws_images(self):
       response = self.ec2_client.describe_images(Owners=['self'])
       images = response['Images']

       for img in images:
           self.create_image(self._aws_to_ostack_formatter(img))

   def create_image(self, img_data):
        """
        Create an OpenStack image.
        :param img_data: dict -- Describes AWS AMI
        :returns: dict -- Response from REST call
        :raises: requests.HTTPError
        """
        sys.stdout.write('Creating image: ' + str(img_data) + ' \n')
        glance_id = img_data['id']
        ami_id = img_data['aws_image_id']
        img_props = {
            'locations': [{'url': 'aws://%s/%s' % (ami_id, glance_id),
                           'metadata': {'ami_id': ami_id}}]
        }
        try:
            resp = self.glance_client.request('POST', '/v2/images', json=img_data)
            resp.raise_for_status()
            # Need to update the image in the registry with location information so
            # the status changes from 'queued' to 'active'
            self.update_properties(glance_id, img_props) 
        except keystoneauth1.exceptions.http.Conflict as e:
            # ignore error if image already exists
            pass
        except requests.HTTPError as e:
            raise e

   def update_properties(self, imageid, props):
        """
        Add or update a set of image properties on an image.
        :param imageid: int -- The Ostack image UUID
        :param props: dict -- Image properties to update
        """
        if not props:
            return
        patch_body = []
        for name, value in props.iteritems():
            patch_body.append({
                'op': 'replace',
                'path': '/%s' % name,
                'value': value
            })
        resp = self.glance_client.request('PATCH', '/v2/images/%s' % imageid, json=patch_body)
        resp.raise_for_status()

   def _get_image_uuid(self, ami_id):
        md = hashlib.md5()
        md.update(ami_id)
        return str(uuid.UUID(bytes=md.digest()))

   def _aws_to_ostack_formatter(self, aws_obj):
        """
        Converts aws img data to Openstack img data format.
        :param img(dict): aws img data
        :return(dict): ostack img data
        """
        visibility = 'public' if aws_obj['Public'] is True else 'private'
        # Check number and size (if any) of EBS and instance-store volumes
        ebs_vol_sizes = []
        num_istore_vols = 0
        for bdm in aws_obj.get('BlockDeviceMappings'):
            if 'Ebs' in bdm:
                ebs_vol_sizes.append(bdm['Ebs']['VolumeSize'])
            elif 'VirtualName' in bdm and bdm['VirtualName'].startswith('ephemeral'):
                # for instance-store volumes, size is not available
                num_istore_vols += 1
        if aws_obj.get('RootDeviceType' == 'instance-store') and num_istore_vols == 0:
            # list of bdms can be empty for instance-store volumes
            num_istore_vols = 1
        # generate glance image uuid based on AWS image id
        image_id = self._get_image_uuid(aws_obj.get('ImageId'))

        return {
            'id'                  : image_id,
            'name'                : aws_obj.get('Name') or aws_obj.get('ImageId'),
            'container_format'    : self.aws_image_types[aws_obj.get('ImageType')],
            'disk_format'         : self.aws_image_types[aws_obj.get('ImageType')],
            'visibility'          : visibility,
            'pf9_description'     : aws_obj.get('Description') or 'Discovered image',
            'aws_image_id'        : aws_obj.get('ImageId'),
            'aws_root_device_type': aws_obj.get('RootDeviceType'),
            'aws_ebs_vol_sizes'   : str(ebs_vol_sizes),
            'aws_num_istore_vols' : str(num_istore_vols),
        }



class RestClient(object):
    def __init__(self):
        os_auth_url = os.getenv('OS_AUTH_URL')
        os_auth_url = os_auth_url.replace('v2.0', 'v3')
        if not os_auth_url.endswith('v3'):
            os_auth_url += '/v3'

        os_username = os.getenv('OS_USERNAME')
        os_password = os.getenv('OS_PASSWORD')
        os_tenant_name = os.getenv('OS_TENANT_NAME')
        os_region_name = os.getenv('OS_REGION_NAME')

        self.glance_endpoint = os_auth_url.replace('keystone/v3', 'glance')
        sys.stdout.write('Using glance endpoint: ' + self.glance_endpoint)

        v3_auth = v3.Password(auth_url = os_auth_url, username = os_username,
                              password = os_password, project_name = os_tenant_name,
                              project_domain_name = 'default', user_domain_name = 'default')
        self.sess = session.Session(auth=v3_auth, verify=False) # verify=True

    def request(self, method, path, **kwargs):
        """
        Make a requests request with retry/relogin on auth failure.
        """
        url = self.glance_endpoint + path
        headers = self.sess.get_auth_headers()
        if method == 'PUT' or method == 'PATCH':
            headers['Content-Type'] = 'application/openstack-images-v2.1-json-patch'
            resp = requests.request(method, url, headers=headers, **kwargs)
        else:
            resp = self.sess.request(url, method, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp


### MAIN ###

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.stderr.write('Incorrect usage: this script takes exactly 3 arguments.\n')
        sys.exit(1)

    credentials = {}
    credentials['aws_access_key_id'] = sys.argv[1]
    credentials['aws_secret_access_key'] = sys.argv[2]
    credentials['region_name'] = sys.argv[3]

    aws_images = AwsImages(credentials)
    aws_images.register_aws_images()

