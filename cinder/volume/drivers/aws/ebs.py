"""
Copyright 2016 Platform9 Systems Inc.(http://www.platform9.com)
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import time

from boto import ec2
from boto.regioninfo import RegionInfo
from oslo_service import loopingcall
from oslo_log import log as logging
from oslo_config import cfg

from cinder.i18n import _LE
from cinder.exception import VolumeNotFound, NotFound, APITimeout, InvalidConfigurationValue
from cinder.volume.driver import BaseVD


aws_group = cfg.OptGroup(name='AWS', title='Options to connect to an AWS environment')
aws_opts = [
    cfg.StrOpt('secret_key', help='Secret key of AWS account', secret=True),
    cfg.StrOpt('access_key', help='Access key of AWS account', secret=True),
    cfg.StrOpt('region_name', help='AWS region'),
    cfg.StrOpt('az', help='AWS availability zone'),
    cfg.IntOpt('wait_time_min', help='Maximum wait time for AWS operations', default=5)
]

ebs_opts = [
    cfg.StrOpt('ebs_pool_name', help='Storage pool name'),
    cfg.IntOpt('ebs_free_capacity_gb', help='Free space available on EBS storage pool',
               default=1024),
    cfg.IntOpt('ebs_total_capacity_gb', help='Total space available on EBS storage pool',
               default=1024)
]

CONF = cfg.CONF
CONF.register_group(aws_group)
CONF.register_opts(aws_opts, group=aws_group)
CONF.register_opts(ebs_opts)
LOG = logging.getLogger(__name__)


class EBSDriver(BaseVD):
    """
    Implements cinder volume interface with EBS as storage backend.
    """
    def __init__(self, *args, **kwargs):
        super(EBSDriver, self).__init__(*args, **kwargs)
        self.VERSION = '1.0.0'
        self._wait_time_sec = 60 * (CONF.AWS.wait_time_min)

        self._check_config()
        region_name = CONF.AWS.region_name
        endpoint = '.'.join(['ec2', region_name, 'amazonaws.com'])
        region = RegionInfo(name=region_name, endpoint=endpoint)
        self._conn = ec2.EC2Connection(aws_access_key_id=CONF.AWS.access_key,
                                       aws_secret_access_key=CONF.AWS.secret_key,
                                       region=region)
        # resort to first AZ for now. TODO: expose this through API
        az = CONF.AWS.az
        self._zone = filter(lambda z: z.name == az,
                            self._conn.get_all_zones())[0]
        self.set_initialized()

    def _check_config(self):
        tbl = dict([(n, eval(n)) for n in ['CONF.AWS.access_key',
                                           'CONF.AWS.secret_key',
                                           'CONF.AWS.region_name',
                                           'CONF.AWS.az']])
        for k, v in tbl.iteritems():
            if v is None:
                raise InvalidConfigurationValue(value=None, option=k)

    def do_setup(self, context):
        pass

    def _wait_for_create(self, id, final_state):
        def _wait_for_status(start_time):
            current_time = time.time()

            if current_time - start_time > self._wait_time_sec:
                raise loopingcall.LoopingCallDone(False)

            obj = self._conn.get_all_volumes([id])[0]
            if obj.status == final_state:
                raise loopingcall.LoopingCallDone(True)

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_status, time.time())
        return timer.start(interval=5).wait()

    def _wait_for_snapshot(self, id, final_state):
        def _wait_for_status(start_time):

            if time.time() - start_time > self._wait_time_sec:
                raise loopingcall.LoopingCallDone(False)

            obj = self._conn.get_all_snapshots([id])[0]
            if obj.status == final_state:
                raise loopingcall.LoopingCallDone(True)

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_status, time.time())
        return timer.start(interval=5).wait()

    def create_volume(self, volume):
        size = volume['size']
        ebs_vol = self._conn.create_volume(size, self._zone)
        if self._wait_for_create(ebs_vol.id, 'available') is False:
            raise APITimeout(service='EC2')
        self._conn.create_tags([ebs_vol.id], {'project_id': volume['project_id'],
                                              'uuid': volume['id'],
                                              'is_clone': False,
                                              'created_at': volume['created_at']})

    def _find(self, obj_id, find_func):
        ebs_objs = find_func(filters={'tag:uuid': obj_id})
        if len(ebs_objs) == 0:
            raise NotFound()
        ebs_obj = ebs_objs[0]
        return ebs_obj

    def delete_volume(self, volume):
        try:
            ebs_vol = self._find(volume['id'], self._conn.get_all_volumes)
        except NotFound:
            LOG.error(_LE('Volume %s was not found'), volume['id'])
            return
        self._conn.delete_volume(ebs_vol.id)

    def check_for_setup_error(self):
        # TODO throw errors if AWS config is broken
        pass

    def create_export(self, context, volume, connector):
        pass

    def ensure_export(self, context, volume):
        pass

    def remove_export(self, context, volume):
        pass

    def initialize_connection(self, volume, connector, initiator_data=None):
        try:
            ebs_vol = self._find(volume.id, self._conn.get_all_volumes)
        except NotFound:
            raise VolumeNotFound(volume_id=volume.id)
        conn_info = dict(data=dict(volume_id=ebs_vol.id))
        return conn_info

    def terminate_connection(self, volume, connector, **kwargs):
        pass

    def _update_volume_stats(self):
        data = dict()
        data['volume_backend_name'] = 'ebs'
        data['vendor_name'] = 'Amazon, Inc.'
        data['driver_version'] = '0.1'
        data['storage_protocol'] = 'iscsi'
        pool = dict(pool_name='ebs',
                    free_capacity_gb=CONF.ebs_free_capacity_gb,
                    total_capacity_gb=CONF.ebs_total_capacity_gb,
                    provisioned_capacity_gb=0,
                    reserved_percentage=0,
                    location_info=dict(),
                    QoS_support=False,
                    max_over_subscription_ratio=1.0,
                    thin_provisioning_support=False,
                    thick_provisioning_support=True,
                    total_volumes=0)
        data['pools'] = [pool]
        self._stats = data

    def get_volume_stats(self, refresh=False):
        if refresh is True:
            self._update_volume_stats()
        return self._stats

    def create_snapshot(self, snapshot):
        os_vol = snapshot['volume']
        try:
            ebs_vol = self._find(os_vol['id'], self._conn.get_all_volumes)
        except NotFound:
            raise VolumeNotFound(os_vol['id'])

        ebs_snap = self._conn.create_snapshot(ebs_vol.id)
        if self._wait_for_snapshot(ebs_snap.id, 'completed') is False:
            raise APITimeout(service='EC2')

        self._conn.create_tags([ebs_snap.id], {'project_id': snapshot['project_id'],
                                               'uuid': snapshot['id'],
                                               'is_clone': True,
                                               'created_at': snapshot['created_at']})

    def delete_snapshot(self, snapshot):
        try:
            ebs_ss = self._find(snapshot['id'], self._conn.get_all_snapshots)
        except NotFound:
            LOG.error(_LE('Snapshot %s was not found'), snapshot['id'])
            return
        self._conn.delete_snapshot(ebs_ss.id)







