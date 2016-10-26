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
import mock

from oslo_service import loopingcall
from cinder import context
from cinder import test
from cinder.exception import APITimeout, NotFound, VolumeNotFound
from cinder.volume.drivers.aws import ebs
from moto import mock_ec2

class EBSVolumeTestCase(test.TestCase):

    @mock_ec2
    def setUp(self):
        super(EBSVolumeTestCase, self).setUp()
        ebs.CONF.AWS.region_name = 'us-east-1'
        ebs.CONF.AWS.access_key = 'fake-key'
        ebs.CONF.AWS.secret_key = 'fake-secret'
        ebs.CONF.AWS.az = 'us-east-1a'
        self._driver = ebs.EBSDriver()
        ctxt = context.get_admin_context()
        self._driver.do_setup(ctxt)

    def _stub_volume(self, **kwargs):
        uuid = u'c20aba21-6ef6-446b-b374-45733b4883ba'
        name = u'volume-00000001'
        size = 1
        created_at = '2016-10-19 23:22:33'
        volume = dict()
        volume['id'] = kwargs.get('id', uuid)
        volume['display_name'] = kwargs.get('display_name', name)
        volume['size'] = kwargs.get('size', size)
        volume['provider_location'] = kwargs.get('provider_location', None)
        volume['volume_type_id'] = kwargs.get('volume_type_id', None)
        volume['project_id'] = kwargs.get('project_id', 'aws_proj_700')
        volume['created_at'] = kwargs.get('create_at', created_at)
        return volume

    def _stub_snapshot(self, **kwargs):
        uuid = u'0196f961-c294-4a2a-923e-01ef5e30c2c9'
        created_at = '2016-10-19 23:22:33'
        ss = dict()

        ss['id'] = kwargs.get('id', uuid)
        ss['project_id'] = kwargs.get('project_id', 'aws_proj_700')
        ss['created_at'] = kwargs.get('create_at', created_at)
        ss['volume'] = kwargs.get('volume', self._stub_volume())

        return ss

    @mock_ec2
    def test_volume_create_success(self):
        self.assertIsNone(self._driver.create_volume(self._stub_volume()))

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._wait_for_create')
    def test_volume_create_fails(self, mock_wait):
        def wait(*args):
            def _wait():
                raise loopingcall.LoopingCallDone(False)
            timer = loopingcall.FixedIntervalLoopingCall(_wait)
            return timer.start(interval=1).wait()

        mock_wait.side_effect = wait
        self.assertRaises(APITimeout, self._driver.create_volume, self._stub_volume())

    @mock_ec2
    def test_volume_deletion(self):
        vol = self._stub_volume()
        self._driver.create_volume(vol)
        self.assertIsNone(self._driver.delete_volume(vol))

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._find')
    def test_volume_deletion_not_found(self, mock_find):
        vol = self._stub_volume()
        mock_find.side_effect = NotFound
        self.assertIsNone(self._driver.delete_volume(vol))

    @mock_ec2
    def test_snapshot(self):
        vol = self._stub_volume()
        snapshot = self._stub_snapshot()
        self._driver.create_volume(vol)
        self.assertIsNone(self._driver.create_snapshot(snapshot))

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._find')
    def test_snapshot_volume_not_found(self, mock_find):
        mock_find.side_effect = NotFound
        ss = self._stub_snapshot()
        self.assertRaises(VolumeNotFound, self._driver.create_snapshot, ss)

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._wait_for_snapshot')
    def test_snapshot_create_fails(self, mock_wait):
        def wait(*args):
            def _wait():
                raise loopingcall.LoopingCallDone(False)

            timer = loopingcall.FixedIntervalLoopingCall(_wait)
            return timer.start(interval=1).wait()
        mock_wait.side_effect = wait
        ss = self._stub_snapshot()
        self._driver.create_volume(ss['volume'])
        self.assertRaises(APITimeout, self._driver.create_snapshot, ss)
