# Copyright 2016 Platform9 Systems Inc.
# All Rights Reserved.
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

from moto import mock_ec2
from moto import mock_cloudwatch
from moto.ec2 import ec2_backends
from nova import context
from nova import exception
from nova import objects
from nova import test
from nova.compute import power_state
from nova.compute import vm_states
from nova.compute import task_states
from nova.image.glance import GlanceImageService
from nova.tests.unit import fake_instance
from nova.tests.unit import matchers
from nova.virt.ec2 import EC2Driver
from oslo_config import cfg
from oslo_utils import uuidutils
import base64
import boto
import contextlib
import mock

class EC2DriverTestCase(test.NoDBTestCase):

    @mock_ec2
    @mock_cloudwatch
    def setUp(self):
        super(EC2DriverTestCase, self).setUp()
        self.fake_access_key = 'aws_access_key'
        self.fake_secret_key = 'aws_secret_key'
        self.region_name = 'us-east-1'
        self.region = boto.ec2.get_region(self.region_name)
        self.flags(access_key=self.fake_access_key,
                   secret_key=self.fake_secret_key,
                   # Region name cannot be fake
                   region_name=self.region_name, group='AWS')
        self.conn = EC2Driver(None, False)
        self.type_data = None
        self.project_id = 'fake'
        self.user_id = 'fake'
        self.instance_node = None
        self.uuid = None
        self.instance = None
        self.context = context.RequestContext(self.user_id, self.project_id)
        self.fake_vpc_conn = boto.vpc.VPCConnection(
            region=self.region, aws_access_key_id=self.fake_access_key,
            aws_secret_access_key=self.fake_secret_key)
        self.fake_ec2_conn = boto.ec2.EC2Connection(
            aws_access_key_id=self.fake_access_key,
            aws_secret_access_key=self.fake_secret_key,
            region=self.region)

    def tearDown(self):
        super(EC2DriverTestCase, self).tearDown()

    def reset(self):
        instance_list = self.conn.ec2_conn.get_only_instances()
        # terminated instances are considered deleted and hence ignore them
        instance_id_list = [x.id for x in instance_list if x.state != 'terminated']
        self.conn.ec2_conn.stop_instances(instance_ids=instance_id_list,
                                          force=True)
        self.conn.ec2_conn.terminate_instances(instance_ids=instance_id_list)
        self.type_data = None
        self.instance = None
        self.uuid = None
        self.instance_node = None

    @mock_ec2
    def test_list_instances(self):
        for x in range(0, 5):
            self.conn.ec2_conn.run_instances('ami-1234abc')
        fake_list = self.conn.list_instances()
        self.assertEqual(5, len(fake_list))
        self.reset()

    @mock_ec2
    def test_add_ssh_keys_key_exists(self):
        fake_key = 'fake_key'
        fake_key_data = 'abcdefgh'
        self.conn.ec2_conn.import_key_pair(fake_key, fake_key_data)
        with contextlib.nested(
                mock.patch.object(boto.ec2.EC2Connection, 'get_key_pair'),
                mock.patch.object(boto.ec2.EC2Connection, 'import_key_pair'),
        ) as (fake_get, fake_import):
            fake_get.return_value = True
            self.conn._add_ssh_keys(fake_key, fake_key_data)
            fake_get.assert_called_once_with(fake_key)
            fake_import.assert_not_called()

    @mock_ec2
    def test_add_ssh_keys_key_absent(self):
        fake_key = 'fake_key'
        fake_key_data = 'abcdefgh'
        with contextlib.nested(
                mock.patch.object(boto.ec2.EC2Connection, 'get_key_pair'),
                mock.patch.object(boto.ec2.EC2Connection, 'import_key_pair'),
        ) as (fake_get, fake_import):
            fake_get.return_value = False
            self.conn._add_ssh_keys(fake_key, fake_key_data)
            fake_get.assert_called_once_with(fake_key)
            fake_import.assert_called_once_with(fake_key, fake_key_data)

    def test_process_network_info(self):
        fake_network_info = [
            {
                'profile': {},
                'ovs_interfaceid': None,
                'preserve_on_delete': False,
                'network': {
                    'bridge': None,
                    'subnets': [{
                        'ips': [{
                            'meta': {},
                            'version': 4,
                            'type': 'fixed',
                            'floating_ips': [],
                            'address': u'192.168.100.5'}],
                        'version': 4,
                        'meta': {},
                        'dns': [],
                        'routes': [],
                        'cidr': u'192.168.100.0/24',
                        'gateway': {
                            'meta': {},
                            'version': 4,
                            'type': 'gateway',
                            'address': u'192.168.100.1'}}],
                        'meta': {
                            'injected': True,
                            'tenant_id': '135b1a036a51414ea1f989ab59fefde5'},
                        'id': '4f8ad58d-de60-4b52-94ba-8b988a9b7f33',
                        'label': 'test'},
                'devname': 'tapa9a90cf6-62',
                'vnic_type': 'normal',
                'qbh_params': None,
                'meta': {},
                'details': '{"subnet_id": "subnet-0107db5a",'
                           ' "ip_address": "192.168.100.5"}',
                'address': 'fa:16:3e:23:65:2c',
                'active': True,
                'type': 'vip_type_a',
                'id': 'a9a90cf6-627c-46f3-829d-c5a2ae07aaf0',
                'qbg_params': None
            }
        ]
        aws_subnet_id, aws_fixed_ip, port_id, network_id = \
                self.conn._process_network_info(fake_network_info)
        self.assertEqual(aws_subnet_id, 'subnet-0107db5a')
        self.assertEqual(aws_fixed_ip, '192.168.100.5')
        self.assertEqual(port_id, 'a9a90cf6-627c-46f3-829d-c5a2ae07aaf0')
        self.assertEqual(network_id, '4f8ad58d-de60-4b52-94ba-8b988a9b7f33')

    def _get_instance_flavor_details(self):
        return {
            'memory_mb': 2048.0, 'root_gb': 0, 'deleted_at': None,
            'name': 't2.small', 'deleted': 0, 'created_at': None,
            'ephemeral_gb': 0, 'updated_at': None, 'disabled': False,
            'vcpus': 1, 'extra_specs': {}, 'swap': 0, 'rxtx_factor': 1.0,
            'is_public': True, 'flavorid': '1', 'vcpu_weight': None, 'id': 2
        }

    def _create_instance(self, key_name=None, key_data=None, user_data=None):
        uuid = uuidutils.generate_uuid()
        self.type_data = self._get_instance_flavor_details()
        values = {
            'name': 'fake_instance',
            'id': 1,
            'uuid': uuid,
            'project_id': self.project_id,
            'user_id': self.user_id,
            'kernel_id': 'fake_kernel_id',
            'ramdisk_id': 'fake_ramdisk_id',
            'flavor': objects.flavor.Flavor(**self.type_data),
            'node': 'fake_node',
            'memory_mb': self.type_data['memory_mb'],
            'root_gb': self.type_data['root_gb'],
            'ephemeral_gb': self.type_data['ephemeral_gb'],
            'vpcus': self.type_data['vcpus'],
            'swap': self.type_data['swap'],
            'expected_attrs': ['system_metadata', 'metadata'],
            'display_name': 'fake_instance',
        }
        if key_name and key_data:
            values['key_name'] = key_name
            values['key_data'] = key_data
        if user_data:
            values['user_data'] = user_data
        self.instance_node = 'fake_node'
        self.uuid = uuid
        self.instance = fake_instance.fake_instance_obj(self.context, **values)

    def _create_network(self):
        self.vpc = self.fake_vpc_conn.create_vpc('192.168.100.0/24')
        self.subnet = self.fake_vpc_conn.create_subnet(self.vpc.id,
                                                       '192.168.100.0/24')
        self.subnet_id = self.subnet.id

    def _create_nova_vm(self):
        self.conn.spawn(self.context, self.instance, None, injected_files=[],
                        admin_password=None, network_info=None,
                        block_device_info=None)

    @mock_ec2
    def test_spawn(self):
        self._create_instance()
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None)
            mock_secgrp.return_value = []
            self._create_nova_vm()
            fake_instances = self.fake_ec2_conn.get_only_instances()
            self.assertEqual(len(fake_instances), 1)
            inst = fake_instances[0]
            self.assertEqual(inst.vpc_id, self.vpc.id)
            self.assertEqual(self.subnet_id, inst.subnet_id)
            self.assertEqual(inst.tags['Name'], 'fake_instance')
            self.assertEqual(inst.tags['openstack_id'], self.uuid)
            self.assertEqual(inst.image_id, 'ami-1234abc')
            self.assertEqual(inst.region.name, self.region_name)
            self.assertEqual(inst.key_name, 'None')
            self.assertEqual(inst.instance_type, 't2.small')
        self.reset()

    @mock_ec2
    def test_spawn_with_key(self):
        self._create_instance(key_name='fake_key', key_data='fake_key_data')
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None)
            mock_secgrp.return_value = []
            self._create_nova_vm()
            fake_instances = self.fake_ec2_conn.get_only_instances()
            self.assertEqual(len(fake_instances), 1)
            inst = fake_instances[0]
            self.assertEqual(inst.key_name, 'fake_key')
        self.reset()

    @mock_ec2
    def test_spawn_with_userdata(self):
        userdata = """
        #cloud-config
        password: password
        """
        b64encoded = base64.b64encode(userdata)
        self._create_instance(user_data=b64encoded)
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None)
            mock_secgrp.return_value = []
            fake_run_instance_op = self.fake_ec2_conn.run_instances(
                    'ami-1234abc')
            boto.ec2.EC2Connection.run_instances = mock.Mock()
            boto.ec2.EC2Connection.run_instances.return_value = \
                    fake_run_instance_op
            self._create_nova_vm()
            fake_instances = self.fake_ec2_conn.get_only_instances()
            self.assertEqual(len(fake_instances), 1)
            boto.ec2.EC2Connection.run_instances.assert_called_once_with(
                    instance_type='t2.small', key_name=None,
                    image_id='ami-1234abc', user_data=userdata,
                    subnet_id=self.subnet_id,
                    private_ip_address='192.168.10.5',
                    security_group_ids=[])
        self.reset()

    @mock_ec2
    def test_spawn_with_network_error(self):
        self._create_instance()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (None, None, None, None)
            mock_secgrp.return_value = []
            self.assertRaises(exception.BuildAbortException, self._create_nova_vm)
        self.reset()

    @mock_ec2
    def test_spawn_with_network_error_from_aws(self):
        self._create_instance()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = ('subnet-1234abc', '192.168.10.5',
                                         None, None)
            mock_secgrp.return_value = []
            self.assertRaises(exception.BuildAbortException, self._create_nova_vm)
        self.reset()

    @mock_ec2
    def test_spawn_with_image_error(self):
        self._create_instance()
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.side_effect = exception.BuildAbortException('fake')
            mock_network.return_value = ('subnet-1234abc', '192.168.10.5',
                                         None, None)
            mock_secgrp.return_value = []
            self.assertRaises(exception.BuildAbortException, self._create_nova_vm)
        self.reset()

    @mock_ec2
    def _create_vm_in_aws_nova(self):
        self._create_instance()
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None)
            mock_secgrp.return_value = []
            self._create_nova_vm()

    @mock_ec2
    def test_snapshot(self):
        self._create_vm_in_aws_nova()
        GlanceImageService.update = mock.Mock()
        expected_calls = [
            {'args': (),
             'kwargs':
                {'task_state': task_states.IMAGE_UPLOADING,
                 'expected_state': task_states.IMAGE_SNAPSHOT}}]
        func_call_matcher = matchers.FunctionCallMatcher(expected_calls)
        self.conn.snapshot(self.context, self.instance, 'test-snapshot',
                           func_call_matcher.call)
        self.assertIsNone(func_call_matcher.match())
        context, snapshot_name, metadata = \
                GlanceImageService.update.call_args[0]
        aws_imgs = self.fake_ec2_conn.get_all_images()
        self.assertEqual(1, len(aws_imgs))
        aws_img = aws_imgs[0]
        self.assertEqual(snapshot_name, 'test-snapshot')
        self.assertEqual(aws_img.name, 'test-snapshot')
        self.assertEqual(aws_img.id, metadata['properties']['ec2_image_id'])
        self.reset()

    @mock_ec2
    def test_snapshot_instance_not_found(self):
        boto.ec2.EC2Connection.create_image = mock.Mock()
        self._create_instance()
        GlanceImageService.update = mock.Mock()
        expected_calls = [
            {'args': (),
             'kwargs':
                {'task_state': task_states.IMAGE_UPLOADING,
                 'expected_state': task_states.IMAGE_SNAPSHOT}}]
        func_call_matcher = matchers.FunctionCallMatcher(expected_calls)
        self.assertRaises(exception.InstanceNotFound, self.conn.snapshot,
                          self.context, self.instance, 'test-snapshot',
                          func_call_matcher.call)
        boto.ec2.EC2Connection.create_image.assert_not_called()
        self.reset()

    @mock_ec2
    def test_reboot_soft(self):
        boto.ec2.EC2Connection.reboot_instances = mock.Mock()
        self._create_vm_in_aws_nova()
        fake_inst = self.fake_ec2_conn.get_only_instances()[0]
        self.conn.reboot(self.context, self.instance, None, 'SOFT', None, None)
        boto.ec2.EC2Connection.reboot_instances.assert_called_once_with(
                instance_ids=[fake_inst.id], dry_run=False)
        self.reset()

    @mock_ec2
    def test_reboot_hard(self):
        self._create_vm_in_aws_nova()
        fake_inst = self.fake_ec2_conn.get_only_instances()[0]
        boto.ec2.EC2Connection.stop_instances = mock.Mock()
        boto.ec2.EC2Connection.start_instances = mock.Mock()
        EC2Driver._wait_for_state = mock.Mock()
        self.conn.reboot(self.context, self.instance, None, 'HARD', None, None)
        boto.ec2.EC2Connection.stop_instances.assert_called_once_with(
                instance_ids=[fake_inst.id], force=False, dry_run=False)
        boto.ec2.EC2Connection.start_instances.assert_called_once_with(
                instance_ids=[fake_inst.id], dry_run=False)
        wait_state_calls = EC2Driver._wait_for_state.call_args_list
        self.assertEqual(2, len(wait_state_calls))
        self.assertEqual('stopped', wait_state_calls[0][0][2])
        self.assertEqual(fake_inst.id, wait_state_calls[0][0][1])
        self.assertEqual('running', wait_state_calls[1][0][2])
        self.assertEqual(fake_inst.id, wait_state_calls[0][0][1])
        self.reset()

    @mock_ec2
    def test_reboot_instance_not_found(self):
        self._create_instance()
        boto.ec2.EC2Connection.stop_instances = mock.Mock()
        self.assertRaises(exception.InstanceNotFound, self.conn.reboot,
                          self.context, self.instance, None, 'SOFT', None,
                          None)
        boto.ec2.EC2Connection.stop_instances.assert_not_called()
        self.reset()

    @mock_ec2
    def test_power_off(self):
        self._create_vm_in_aws_nova()
        fake_inst = self.fake_ec2_conn.get_only_instances()[0]
        self.assertEqual(fake_inst.state, 'running')
        self.conn.power_off(self.instance)
        fake_inst = self.fake_ec2_conn.get_only_instances()[0]
        self.assertEqual(fake_inst.state, 'stopped')
        self.reset()

    @mock_ec2
    def test_power_off_instance_not_found(self):
        self._create_instance()
        self.assertRaises(exception.InstanceNotFound, self.conn.power_off,
                          self.instance)
        self.reset()

    @mock_ec2
    def test_power_on(self):
        self._create_vm_in_aws_nova()
        fake_inst = self.fake_ec2_conn.get_only_instances()[0]
        self.fake_ec2_conn.stop_instances(instance_ids=[fake_inst.id])
        self.conn.power_on(self.context, self.instance, None, None)
        fake_inst = self.fake_ec2_conn.get_only_instances()[0]
        self.assertEqual(fake_inst.state, 'running')
        self.reset()

    @mock_ec2
    def test_power_on_instance_not_found(self):
        self._create_instance()
        self.assertRaises(exception.InstanceNotFound, self.conn.power_on,
                          self.context, self.instance, None, None)
        self.reset()

    @mock_ec2
    def test_destroy(self):
        self._create_vm_in_aws_nova()
        self.conn.destroy(self.context, self.instance, None, None)
        fake_instance = self.fake_ec2_conn.get_only_instances()[0]
        self.assertEqual('terminated', fake_instance.state)
        self.reset()

    @mock_ec2
    def test_destroy_instance_not_found(self):
        self._create_instance()
        with contextlib.nested(
            mock.patch.object(boto.ec2.EC2Connection, 'stop_instances'),
            mock.patch.object(boto.ec2.EC2Connection, 'terminate_instances'),
            mock.patch.object(EC2Driver, '_wait_for_state'),
        ) as (fake_stop, fake_terminate, fake_wait):
            self.conn.destroy(self.context, self.instance, None, None)
            fake_stop.assert_not_called()
            fake_terminate.assert_not_called()
            fake_wait.assert_not_called()
        self.reset()

    @mock_ec2
    def test_destory_instance_terminated_on_aws(self):
        self._create_vm_in_aws_nova()
        fake_instances = self.fake_ec2_conn.get_only_instances()
        self.fake_ec2_conn.stop_instances(instance_ids=[fake_instances[0].id])
        self.fake_ec2_conn.terminate_instances(
            instance_ids=[fake_instances[0].id])
        with contextlib.nested(
            mock.patch.object(boto.ec2.EC2Connection, 'stop_instances'),
            mock.patch.object(boto.ec2.EC2Connection, 'terminate_instances'),
            mock.patch.object(EC2Driver, '_wait_for_state'),
        ) as (fake_stop, fake_terminate, fake_wait):
            self.conn.destroy(self.context, self.instance, None, None)
            fake_stop.assert_not_called()
            fake_terminate.assert_not_called()
            fake_wait.assert_not_called()
        self.reset()

    @mock_ec2
    def test_destroy_instance_shut_down_on_aws(self):
        self._create_vm_in_aws_nova()
        fake_instances = self.fake_ec2_conn.get_only_instances()
        self.fake_ec2_conn.stop_instances(instance_ids=[fake_instances[0].id])
        with contextlib.nested(
            mock.patch.object(boto.ec2.EC2Connection, 'stop_instances'),
            mock.patch.object(boto.ec2.EC2Connection, 'terminate_instances'),
            mock.patch.object(EC2Driver, '_wait_for_state'),
        ) as (fake_stop, fake_terminate, fake_wait):
            self.conn.destroy(self.context, self.instance, None, None)
            fake_stop.assert_not_called()
            fake_terminate.assert_called_once_with(instance_ids=[fake_instances[0].id])
        self.reset()

    @mock_ec2
    def test_get_info(self):
        self._create_vm_in_aws_nova()
        vm_info = self.conn.get_info(self.instance)
        self.assertEqual(0, vm_info.state)
        self.assertEqual(self.instance.id, vm_info.id)
        self.reset()

    @mock_ec2
    def test_get_info_instance_not_found(self):
        self._create_instance()
        self.assertRaises(exception.InstanceNotFound, self.conn.get_info,
                          self.instance)
        self.reset()
