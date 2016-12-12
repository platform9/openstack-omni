# Copyright (c) 2014 Thoughtworks.
# Copyright (c) 2016 Platform9 Systems Inc.
# All Rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Connection to the Amazon Web Services - EC2 service"""

import base64
import boto.ec2.cloudwatch
import datetime
import hashlib
import json
import sys
import time
import uuid
from threading import Lock
from boto import ec2, vpc
from boto import exception as boto_exc
from boto.exception import EC2ResponseError
from boto.regioninfo import RegionInfo
from oslo_config import cfg
from nova.i18n import *
from nova import block_device
from nova.compute import power_state
from nova.compute import task_states
from nova.console import type as ctype
from nova import db
from nova import exception
from nova.image import glance
from oslo_log import log as logging
from oslo_service import loopingcall
from nova.virt import driver
from nova.virt import virtapi
from nova.virt import hardware
from nova.virt.ec2.exception_handler import Ec2ExceptionHandler
LOG = logging.getLogger(__name__)

aws_group = cfg.OptGroup(name='AWS', title='Options to connect to an AWS cloud')

aws_opts = [
    cfg.StrOpt('secret_key', help='Secret key of AWS account', secret=True),
    cfg.StrOpt('access_key', help='Access key of AWS account', secret=True),
    cfg.StrOpt('region_name', help='AWS region'),
    cfg.IntOpt('vnc_port',
               default=5900,
               help='VNC starting port'),
    # 500 VCPUs
    cfg.IntOpt('max_vcpus',
               default=500,
               help='Max number of vCPUs that can be used'),
    # 1000 GB RAM
    cfg.IntOpt('max_memory_mb',
               default=1024000,
               help='Max memory MB that can be used'),
    # 1 TB Storage
    cfg.IntOpt('max_disk_gb',
               default=1024,
               help='Max storage in GB that can be used')
]

CONF = cfg.CONF
CONF.import_opt('my_ip', 'nova.netconf')

CONF.register_group(aws_group)
CONF.register_opts(aws_opts, group=aws_group)

EC2_STATE_MAP = {
    "pending": power_state.NOSTATE,
    "running": power_state.RUNNING,
    "shutting-down": power_state.NOSTATE,
    "terminated": power_state.CRASHED,
    "stopping": power_state.NOSTATE,
    "stopped": power_state.SHUTDOWN
}

EC2_FLAVOR_MAP = {
    'c3.2xlarge': {'memory_mb': 15360.0, 'vcpus': 8},
    'c3.4xlarge': {'memory_mb': 30720.0, 'vcpus': 16},
    'c3.8xlarge': {'memory_mb': 61440.0, 'vcpus': 32},
    'c3.large': {'memory_mb': 3840.0, 'vcpus': 2},
    'c3.xlarge': {'memory_mb': 7680.0, 'vcpus': 4},
    'c4.2xlarge': {'memory_mb': 15360.0, 'vcpus': 8},
    'c4.4xlarge': {'memory_mb': 30720.0, 'vcpus': 16},
    'c4.8xlarge': {'memory_mb': 61440.0, 'vcpus': 36},
    'c4.large': {'memory_mb': 3840.0, 'vcpus': 2},
    'c4.xlarge': {'memory_mb': 7680.0, 'vcpus': 4},
    'd2.2xlarge': {'memory_mb': 62464.0, 'vcpus': 8},
    'd2.4xlarge': {'memory_mb': 124928.0, 'vcpus': 16},
    'd2.8xlarge': {'memory_mb': 249856.0, 'vcpus': 36},
    'd2.xlarge': {'memory_mb': 31232.0, 'vcpus': 4},
    'g2.2xlarge': {'memory_mb': 15360.0, 'vcpus': 8},
    'g2.8xlarge': {'memory_mb': 61440.0, 'vcpus': 32},
    'i2.2xlarge': {'memory_mb': 62464.0, 'vcpus': 8},
    'i2.4xlarge': {'memory_mb': 124928.0, 'vcpus': 16},
    'i2.8xlarge': {'memory_mb': 249856.0, 'vcpus': 32},
    'i2.xlarge': {'memory_mb': 31232.0, 'vcpus': 4},
    'm3.2xlarge': {'memory_mb': 30720.0, 'vcpus': 8},
    'm3.large': {'memory_mb': 7680.0, 'vcpus': 2},
    'm3.medium': {'memory_mb': 3840.0, 'vcpus': 1},
    'm3.xlarge': {'memory_mb': 15360.0, 'vcpus': 4},
    'm4.10xlarge': {'memory_mb': 163840.0, 'vcpus': 40},
    'm4.2xlarge': {'memory_mb': 32768.0, 'vcpus': 8},
    'm4.4xlarge': {'memory_mb': 65536.0, 'vcpus': 16},
    'm4.large': {'memory_mb': 8192.0, 'vcpus': 2},
    'm4.xlarge': {'memory_mb': 16384.0, 'vcpus': 4},
    'r3.2xlarge': {'memory_mb': 62464.0, 'vcpus': 8},
    'r3.4xlarge': {'memory_mb': 124928.0, 'vcpus': 16},
    'r3.8xlarge': {'memory_mb': 249856.0, 'vcpus': 32},
    'r3.large': {'memory_mb': 15616.0, 'vcpus': 2},
    'r3.xlarge': {'memory_mb': 31232.0, 'vcpus': 4},
    't2.large': {'memory_mb': 8192.0, 'vcpus': 2},
    't2.medium': {'memory_mb': 4096.0, 'vcpus': 2},
    't2.micro': {'memory_mb': 1024.0, 'vcpus': 1},
    't2.nano': {'memory_mb': 512.0, 'vcpus': 1},
    't2.small': {'memory_mb': 2048.0, 'vcpus': 1},
    'x1.32xlarge': {'memory_mb': 1998848.0, 'vcpus': 128}
}


DIAGNOSTIC_KEYS_TO_FILTER = ['group', 'block_device_mapping']


def set_nodes(nodes):
    """Sets EC2Driver's node.list.

    It has effect on the following methods:
        get_available_nodes()
        get_available_resource
        get_host_stats()

    To restore the change, call restore_nodes()
    """
    global _EC2_NODES
    _EC2_NODES = nodes


def restore_nodes():
    """Resets EC2Driver's node list modified by set_nodes().

    Usually called from tearDown().
    """
    global _EC2_NODES
    _EC2_NODES = [CONF.host]


class EC2Driver(driver.ComputeDriver):
    capabilities = {
        "has_imagecache": True,
        "supports_recreate": True,
    }

    def __init__(self, virtapi, read_only=False):
        super(EC2Driver, self).__init__(virtapi)
        self.host_status_base = {
            'vcpus': CONF.AWS.max_vcpus,
            'memory_mb': CONF.AWS.max_memory_mb,
            'local_gb': CONF.AWS.max_disk_gb,
            'vcpus_used': 0,
            'memory_mb_used': 0,
            'local_gb_used': 0,
            'hypervisor_type': 'EC2',
            'hypervisor_version': '1.0',
            'hypervisor_hostname': CONF.host,
            'cpu_info': {},
            'disk_available_least': CONF.AWS.max_disk_gb,
        }

        self._mounts = {}
        self._interfaces = {}
        self._uuid_to_ec2_instance = {}
        self.ec2_flavor_info = EC2_FLAVOR_MAP
        aws_region = CONF.AWS.region_name
        aws_endpoint = "ec2." + aws_region + ".amazonaws.com"

        region = RegionInfo(name=aws_region, endpoint=aws_endpoint)
        self.ec2_conn = ec2.EC2Connection(aws_access_key_id=CONF.AWS.access_key,
                                          aws_secret_access_key=CONF.AWS.secret_key,
                                          region=region)

        self.cloudwatch_conn = ec2.cloudwatch.connect_to_region(
            aws_region, aws_access_key_id=CONF.AWS.access_key,
            aws_secret_access_key=CONF.AWS.secret_key)

        LOG.info("EC2 driver init with %s region" % aws_region)
        if not '_EC2_NODES' in globals():
            set_nodes([CONF.host])

    def init_host(self, host):
        """
        Initialize anything that is necessary for the driver to function,
        including catching up with currently running VM's on the given host.
        """
        return

    def list_instances(self):
        """
        Return the names of all the instances known to the virtualization
        layer, as a list.
        """
        all_instances = self.ec2_conn.get_only_instances()
        self._uuid_to_ec2_instance.clear()
        instance_ids = []
        for instance in all_instances:
            generate_uuid = False
            if instance.state in ['pending', 'shutting-down', 'terminated']:
                continue
            if len(instance.tags) > 0:
                if 'openstack_id' in instance.tags:
                    self._uuid_to_ec2_instance[instance.tags['openstack_id']] = \
                            instance
                else:
                    generate_uuid = True
            else:
                generate_uuid = True
            if generate_uuid:
                instance_uuid = self._get_uuid_from_aws_id(instance.id)
                self._uuid_to_ec2_instance[instance_uuid] = instance
            instance_ids.append(instance.id)
        return instance_ids

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        pass

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        pass

    def _add_ssh_keys(self, key_name, key_data):
        """
        Adds SSH Keys into AWS EC2 account
        :param key_name:
        :param key_data:
        :return:
        """
        # TODO: Need to handle the cases if a key with the same keyname exists and different key content
        exist_key_pair = self.ec2_conn.get_key_pair(key_name)
        if not exist_key_pair:
            LOG.info("Adding SSH key to AWS")
            self.ec2_conn.import_key_pair(key_name, key_data)
        else:
            LOG.info("SSH key already exists in AWS")

    def _get_image_ami_id_from_meta(self, context, image_lacking_meta):
        """
        Pulls the Image AMI ID from the location attribute of Image Meta
        :param image_meta:
        :return: ami_id
        """
        image_api = glance.get_default_image_service()
        image_meta = image_api._client.call(context, 2, 'get',
                                            image_lacking_meta['id'])
        LOG.info("Calling _get_image_ami_id_from_meta Meta: %s", image_meta)
        try:
            return image_meta['aws_image_id']
        except Exception as e:
            LOG.error("Error in parsing Image Id: %s" % e)
            raise exception.BuildAbortException("Invalid or Non-Existent Image ID Error")

    def _process_network_info(self, network_info):
        """
        Will process network_info object by picking up only one Network out of many
        :param network_info:
        :return:
        """
        LOG.info("Networks to be processed : %s" % network_info)
        subnet_id = None
        fixed_ip = None
        port_id = None
        network_id = None
        if len(network_info) > 1:
            LOG.warn('AWS does not allow connecting 1 instance to multiple '
                     'VPCs.')
        for vif in network_info:
            if 'details' in vif:
                network_dict = json.loads(vif['details'])
                subnet_id = network_dict['subnet_id']
                LOG.info("Adding subnet ID:" + subnet_id)
                fixed_ip = network_dict['ip_address']
                LOG.info("Fixed IP:" + fixed_ip)
                port_id = vif['id']
                network_id = vif['network']['id']
                break
        return subnet_id, fixed_ip, port_id, network_id

    def _get_instance_sec_grps(self, context, port_id, network_id):
        secgrp_ids = []
        from nova import network
        network_api = network.API()
        port_obj = network_api.show_port(context, port_id)
        if port_obj.get('port', {}).get('security_groups', []):
            filters = {'tag-value': port_obj['port']['security_groups']}
            secgrps = self.ec2_conn.get_all_security_groups(filters=filters)
            for secgrp in secgrps:
                if network_id and 'openstack_network_id' in secgrp.tags and \
                        secgrp.tags['openstack_network_id'] == network_id:
                    secgrp_ids.append(secgrp.id)
        return secgrp_ids

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """Create a new instance/VM/domain on the virtualization platform.
        Once this successfully completes, the instance should be
        running (power_state.RUNNING).

        If this fails, any partial instance should be completely
        cleaned up, and the virtualization platform should be in the state
        that it was before this call began.

        :param context: security context <Not Yet Implemented>
        :param instance: nova.objects.instance.Instance
                         This function should use the data there to guide
                         the creation of the new instance.
        :param image_meta: image object returned by nova.image.glance that
                           defines the image from which to boot this instance
        :param injected_files: User files to inject into instance.
        :param admin_password: set in instance. <Not Yet Implemented>
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices to be
                                  attached to the instance.
        """

        image_ami_id = self._get_image_ami_id_from_meta(context, image_meta)

        subnet_id, fixed_ip, port_id, network_id = self._process_network_info(
                network_info)
        if subnet_id is None or fixed_ip is None:
            raise exception.BuildAbortException("Network configuration failure")

        security_groups = self._get_instance_sec_grps(context, port_id, network_id)

        # Flavor
        flavor_dict = instance['flavor']
        flavor_type = flavor_dict['name']

        # SSH Keys
        if instance['key_name'] is not None and instance['key_data'] is not None:
            self._add_ssh_keys(instance['key_name'], instance['key_data'])

        # Creating the EC2 instance
        user_data = None
        # Passing user_data from the openstack instance which is Base64 encoded
        # after decoding it.
        if 'user_data' in instance and instance['user_data'] is not None:
            user_data = instance['user_data']
            user_data = base64.b64decode(user_data)

        try:
            reservation = self.ec2_conn.run_instances(
                    instance_type=flavor_type, key_name=instance['key_name'],
                    image_id=image_ami_id, user_data=user_data,
                    subnet_id=subnet_id, private_ip_address=fixed_ip,
                    security_group_ids=security_groups)
            ec2_instance = reservation.instances
            ec2_instance_obj = ec2_instance[0]
            ec2_id = ec2_instance[0].id
            self._wait_for_state(instance, ec2_id, "running", power_state.RUNNING)
            instance['metadata'].update({'ec2_id': ec2_id})
            ec2_instance_obj.add_tag("Name", instance['display_name'])
            ec2_instance_obj.add_tag("openstack_id", instance['uuid'])
            self._uuid_to_ec2_instance[instance.uuid] = ec2_instance_obj

            # Fetch Public IP of the instance if it has one
            instances = self.ec2_conn.get_only_instances(instance_ids=[ec2_id])
            if len(instances) > 0:
                public_ip = instances[0].ip_address
                if public_ip is not None:
                    instance['metadata'].update({'public_ip_address': public_ip})
        except EC2ResponseError as ec2_exception:
            actual_exception = Ec2ExceptionHandler.get_processed_exception(ec2_exception)
            LOG.info("Error in starting instance %s" % (actual_exception))
            raise exception.BuildAbortException(actual_exception.message)

    def _get_ec2_id_from_instance(self, instance):
        if 'ec2_id' in instance.metadata and instance.metadata['ec2_id']:
            return instance.metadata['ec2_id']
        elif instance.uuid in self._uuid_to_ec2_instance:
            return self._uuid_to_ec2_instance[instance.uuid].id
        # if none of the conditions are met we cannot map OpenStack UUID to
        # AWS ID.
        raise exception.InstanceNotFound('Instance %s not found' % instance.uuid)


    def snapshot(self, context, instance, image_id, update_task_state):
        """Snapshot an image of the specified instance
        on EC2 and create an Image which gets stored in AMI (internally in EBS Snapshot)
        :param context: security context
        :param instance: nova.objects.instance.Instance
        :param image_id: Reference to a pre-created image that will hold the snapshot.
        """
        if instance.metadata.get('ec2_id', None) is None:
            raise exception.InstanceNotFound(instance_id=instance['uuid'])

        # Adding the below line only alters the state of the instance and not
        # its image in OpenStack.
        update_task_state(
            task_state=task_states.IMAGE_UPLOADING,
            expected_state=task_states.IMAGE_SNAPSHOT)
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec_instance_info = self.ec2_conn.get_only_instances(
            instance_ids=[ec2_id], filters=None, dry_run=False,
            max_results=None)
        ec2_instance = ec_instance_info[0]
        if ec2_instance.state == 'running':
            ec2_image_id = ec2_instance.create_image(
                name=str(image_id), description="Image created by OpenStack",
                no_reboot=False, dry_run=False)
            LOG.info("Image created: %s." % ec2_image_id)

        # The instance will be in pending state when it comes up, waiting
        # for it to be in available
        self._wait_for_image_state(ec2_image_id, "available")

        image_api = glance.get_default_image_service()
        image_ref = glance.generate_image_url(image_id)

        metadata = {'is_public': False,
                    'location': image_ref,
                    'properties': {
                        'kernel_id': instance['kernel_id'],
                        'image_state': 'available',
                        'owner_id': instance['project_id'],
                        'ramdisk_id': instance['ramdisk_id'],
                        'ec2_image_id': ec2_image_id }
                    }
        # TODO(jhurt): This currently fails, leaving the status of an instance
        #              as 'snapshotting'
        image_api.update(context, image_id, metadata)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        """
        Reboot the specified instance.
        After this is called successfully, the instance's state
        goes back to power_state.RUNNING. The virtualization
        platform should ensure that the reboot action has completed
        successfully even in cases in which the underlying domain/vm
        is paused or halted/stopped.

        :param instance: nova.objects.instance.Instance
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param reboot_type: Either a HARD or SOFT reboot
        :param block_device_info: Info pertaining to attached volumes
        :param bad_volumes_callback: Function to handle any bad volumes
            encountered
        """
        if reboot_type == 'SOFT':
            self._soft_reboot(
                context, instance, network_info, block_device_info)
        elif reboot_type == 'HARD':
            self._hard_reboot(
                context, instance, network_info, block_device_info)

    def _soft_reboot(self, context, instance, network_info, block_device_info=None):
        ec2_id = self._get_ec2_id_from_instance(instance)
        self.ec2_conn.reboot_instances(instance_ids=[ec2_id], dry_run=False)
        LOG.info("Soft Reboot Complete.")

    def _hard_reboot(self, context, instance, network_info, block_device_info=None):
        self.power_off(instance)
        self.power_on(context, instance, network_info, block_device)
        LOG.info("Hard Reboot Complete.")

    @staticmethod
    def get_host_ip_addr():
        """Retrieves the IP address of the host"""
        return CONF.my_ip

    def set_admin_password(self, instance, new_pass):
        """
        Boto doesn't support setting the password at the time of creating an instance.
        hence not implemented.
        """
        pass

    def inject_file(self, instance, b64_path, b64_contents):
        pass

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        pass

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        pass

    def unrescue(self, instance, network_info):
        pass

    def poll_rebooting_instances(self, timeout, instances):
        pass

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   instance_type, network_info,
                                   block_device_info=None):
        pass

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info=None, power_on=True):
        pass

    def post_live_migration_at_destination(self, context, instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        pass

    def power_off(self, instance, timeout=0, retry_interval=0):
        """
        Power off the specified instance.
        :param instance: nova.objects.instance.Instance
        :param timeout: time to wait for GuestOS to shutdown
        :param retry_interval: How often to signal guest while
                               waiting for it to shutdown
        """
        # TODO: Need to use timeout and retry_interval
        ec2_id = self._get_ec2_id_from_instance(instance)
        self.ec2_conn.stop_instances(
            instance_ids=[ec2_id], force=False, dry_run=False)
        self._wait_for_state(instance, ec2_id, "stopped", power_state.SHUTDOWN)

    def power_on(self, context, instance, network_info, block_device_info):
        """Power on the specified instance."""
        ec2_id = self._get_ec2_id_from_instance(instance)
        self.ec2_conn.start_instances(instance_ids=[ec2_id], dry_run=False)
        self._wait_for_state(instance, ec2_id, "running", power_state.RUNNING)

    def soft_delete(self, instance):
        """Deleting the specified instance"""
        self.destroy(instance)

    def restore(self, instance):
        pass

    def pause(self, instance):
        """
        Boto doesn't support pause and cannot save system state and hence
        we've implemented the closest functionality which is to poweroff the
        instance.
        :param instance: nova.objects.instance.Instance
        """
        self.power_off(instance)

    def unpause(self, instance):
        """
        Since Boto doesn't support pause and cannot save system state, we
        had implemented the closest functionality which is to poweroff the
        instance. and powering on such an instance in this method.
        :param instance: nova.objects.instance.Instance
        """
        self.power_on(
            context=None, instance=instance, network_info=None, block_device_info=None)

    def suspend(self, context, instance):
        """
        Boto doesn't support suspend and cannot save system state and hence
        we've implemented the closest functionality which is to poweroff the
        instance.
        :param instance: nova.objects.instance.Instance
        """
        self.power_off(instance)

    def resume(self, context, instance, network_info, block_device_info=None):
        """
        Since Boto doesn't support suspend and we cannot save system state,
        we've implemented the closest functionality which is to power on the
        instance.
        :param instance: nova.objects.instance.Instance
        """
        self.power_on(context, instance, network_info, block_device_info)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """Destroy the specified instance from the Hypervisor.

        If the instance is not found (for example if networking failed), this
        function should still succeed.  It's probably a good idea to log a
        warning in that case.

        :param context: security context
        :param instance: Instance object as returned by DB layer.
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices that should
                                  be detached from the instance.
        :param destroy_disks: Indicates if disks should be destroyed
        :param migrate_data: implementation specific params
        """
        ec2_id = None
        try:
            ec2_id = self._get_ec2_id_from_instance(instance)
            ec2_instances = self.ec2_conn.get_only_instances(
                    instance_ids=[ec2_id])
        except exception.InstanceNotFound as ex:
            # Exception while fetching instance info from AWS
            LOG.exception('Exception in destroy while fetching EC2 id for '
                          'instance %s' % instance.uuid)
            return
        if len(ec2_instances) == 0:
            # Instance already deleted on hypervisor
            LOG.warning("EC2 instance with ID %s not found" % ec2_id,
                        instance=instance)
            return
        else:
            try:
                if ec2_instances[0].state != 'terminated':
                    if ec2_instances[0].state == 'running':
                        self.ec2_conn.stop_instances(instance_ids=[ec2_id],
                                                     force=True)
                    self.ec2_conn.terminate_instances(instance_ids=[ec2_id])
                    self._wait_for_state(instance, ec2_id, "terminated",
                                         power_state.SHUTDOWN)
            except Exception as ex:
                LOG.exception("Exception while destroying instance: %s" %
                        str(ex))
                raise ex

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach the disk to the instance at mountpoint using info.
        """
        instance_name = instance['name']
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = connection_info

        volume_id = connection_info['data']['volume_id']
        ec2_id = self._get_ec2_id_from_instance(instance)

        # ec2 only attaches volumes at /dev/sdf through /dev/sdp
        self.ec2_conn.attach_volume(volume_id, ec2_id, mountpoint,
                                    dry_run=False)

    def detach_volume(self, connection_info, instance, mountpoint, encryption=None):
        """Detach the disk attached to the instance.
        """
        try:
            del self._mounts[instance['name']][mountpoint]
        except KeyError:
            pass
        volume_id = connection_info['data']['volume_id']
        ec2_id = self._get_ec2_id_from_instance(instance)
        self.ec2_conn.detach_volume(volume_id, instance_id=ec2_id,
                                    device=mountpoint, force=False,
                                    dry_run=False)

    def swap_volume(self, old_connection_info, new_connection_info,
                    instance, mountpoint, resize_to):
        """Replace the disk attached to the instance.
        """
        # TODO: Use resize_to parameter
        instance_name = instance['name']
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = new_connection_info

        old_volume_id = old_connection_info['data']['volume_id']
        new_volume_id = new_connection_info['data']['volume_id']

        self.detach_volume(old_connection_info, instance, mountpoint)
        # wait for the old volume to detach successfully to make sure
        # /dev/sdn is available for the new volume to be attached
        # TODO: remove the sleep and poll AWS for the status of volume
        time.sleep(60)
        ec2_id = self._get_ec2_id_from_instance(instance)
        self.ec2_conn.attach_volume(new_volume_id,
                                    ec2_id, mountpoint,
                                    dry_run=False)
        return True

    def attach_interface(self, instance, image_meta, vif):
        LOG.debug("******* ATTTACH INTERFACE *******")
        if vif['id'] in self._interfaces:
            raise exception.InterfaceAttachFailed('duplicate')
        self._interfaces[vif['id']] = vif

    def detach_interface(self, instance, vif):
        LOG.debug("******* DETACH INTERFACE *******")
        try:
            del self._interfaces[vif['id']]
        except KeyError:
            raise exception.InterfaceDetachFailed('not attached')

    def get_info(self, instance):
        """Get the current status of an instance, by name (not ID!)
        :param instance: nova.objects.instance.Instance object
        Returns a dict containing:
        :state:           the running state, one of the power_state codes
        :max_mem:         (int) the maximum memory in KBytes allowed
        :mem:             (int) the memory in KBytes used by the domain
        :num_cpu:         (int) the number of virtual CPUs for the domain
        :cpu_time:        (int) the CPU time used in nanoseconds
        """

        if instance.uuid in self._uuid_to_ec2_instance:
            ec2_instance = self._uuid_to_ec2_instance[instance.uuid]
        elif 'metadata' in instance and 'ec2_id' in instance['metadata']:
            ec2_id = instance['metadata']['ec2_id']
            ec2_instances = self.ec2_conn.get_only_instances(
                    instance_ids=[ec2_id], filters=None, dry_run=False,
                    max_results=None)
            if len(ec2_instances) == 0:
                LOG.warning(_("EC2 instance with ID %s not found") % ec2_id,
                        instance=instance)
                raise exception.InstanceNotFound(instance_id=instance['name'])
            ec2_instance = ec2_instances[0]
        else:
            raise exception.InstanceNotFound(instance_id=instance['name'])

        power_state = EC2_STATE_MAP.get(ec2_instance.state)
        ec2_flavor = self.ec2_flavor_info.get(ec2_instance.instance_type)
        memory_mb = ec2_flavor['memory_mb']
        vcpus = ec2_flavor['vcpus']

        return hardware.InstanceInfo(
            state=power_state,
            max_mem_kb=memory_mb,
            mem_kb=memory_mb,
            num_cpu=vcpus,
            cpu_time_ns=0,
            id=instance.id)

    def allow_key(self, key):
        for key_to_filter in DIAGNOSTIC_KEYS_TO_FILTER:
            if key == key_to_filter:
                return False
        return True

    def get_diagnostics(self, instance):
        """Return data about VM diagnostics."""

        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_instances = self.ec2_conn.get_only_instances(instance_ids=[ec2_id],
                                                         filters=None,
                                                         dry_run=False,
                                                         max_results=None)
        if len(ec2_instances) == 0:
            LOG.warning(_("EC2 instance with ID %s not found") % ec2_id,
                    instance=instance)
            raise exception.InstanceNotFound(instance_id=instance['name'])
        ec2_instance = ec2_instances[0]

        diagnostics = {}
        for key, value in ec2_instance.__dict__.items():
            if self.allow_key(key):
                diagnostics['instance.' + key] = str(value)

        metrics = self.cloudwatch_conn.list_metrics(dimensions={'InstanceId': ec2_id})

        for metric in metrics:
            end = datetime.datetime.utcnow()
            start = end - datetime.timedelta(hours=1)
            details = metric.query(start, end, 'Average', None, 3600)
            if len(details) > 0:
                diagnostics['metrics.' + str(metric)] = details[0]

        return diagnostics

    def get_all_bw_counters(self, instances):
        """Return bandwidth usage counters for each interface on each
           running VM.
        """
        bw = []
        return bw

    def get_all_volume_usage(self, context, compute_host_bdms):
        """Return usage info for volumes attached to vms on
           a given host.
        """
        volusage = []
        return volusage

    def block_stats(self, instance_name, disk_id):
        return [0L, 0L, 0L, 0L, None]

    def interface_stats(self, instance_name, iface_id):
        return [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]

    def get_vnc_console(self, context, instance):
        ec2_id = self._get_ec2_id_from_instance(instance)
        LOG.info("VNC console connect to %s" % ec2_id)
        reservations = self.ec2_conn.get_all_instances()

        vnc_port = 5901
        # Get the IP of the instance
        host_ip = None
        for reservation in reservations:
            if reservation.instances is not None:
                for instance in reservation.instances:
                    if instance.id == ec2_id:
                        if instance.ip_address is not None:
                            host_ip = instance.ip_address
        if host_ip is not None:
            LOG.info("Found the IP of the instance IP:%s and port:%s" % (host_ip, vnc_port))
            return ctype.ConsoleVNC(host=host_ip, port=vnc_port)
        else:
            LOG.info("Ip not Found for the instance")
            return {'internal_access_path': 'EC2',
                    'host': 'EC2spiceconsole.com',
                    'port': 5901}

    def get_spice_console(self, instance):
        """ Simple Protocol for Independent Computing Environments
        Doesn't seem to be supported by AWS EC2 directly
        """

        return {'internal_access_path': 'EC2',
                'host': 'EC2spiceconsole.com',
                'port': 6969,
                'tlsPort': 6970}

    def get_console_pool_info(self, console_type):
        return {'address': '127.0.0.1',
                'username': 'EC2user',
                'password': 'EC2password'}

    def refresh_provider_fw_rules(self):
        pass

    def get_available_resource(self, nodename):
        """Retrieve resource information.
        Updates compute manager resource info on ComputeNode table.
        This method is called when nova-compute launches and as part of a periodic task that records results in the DB.
        Since we don't have a real hypervisor, pretend we have lots of disk and ram.
        :param nodename:
            node which the caller want to get resources from
            a driver that manages only one node can safely ignore this
        :returns: Dictionary describing resources
        """
        if nodename not in _EC2_NODES:
            return {}

        dic = {'vcpus': CONF.AWS.max_vcpus,
               'memory_mb': CONF.AWS.max_memory_mb,
               'local_gb': CONF.AWS.max_disk_gb,
               'vcpus_used': 0,
               'memory_mb_used': 0,
               'local_gb_used': 0,
               'hypervisor_type': 'EC2',
               'hypervisor_version': '1',
               'hypervisor_hostname': nodename,
               'disk_available_least': 0,
               'cpu_info': '?',
               'numa_topology': None}

        supported_tuple = ('IA64', 'kvm', 'hvm')
        dic["supported_instances"] = [supported_tuple]
        return dic

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        return

    def get_instance_disk_info(self, instance_name):
        return

    def live_migration(self, context, instance_ref, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        post_method(context, instance_ref, dest, block_migration,
                    migrate_data)
        return

    def check_can_live_migrate_destination_cleanup(self, ctxt,
                                                   dest_check_data):
        return

    def check_can_live_migrate_destination(self, ctxt, instance_ref,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        return {}

    def check_can_live_migrate_source(self, ctxt, instance_ref,
                                      dest_check_data):
        return

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None, power_on=True):
        """Completes a resize
        :param migration: the migrate/resize information
        :param instance: nova.objects.instance.Instance being migrated/resized
        :param power_on: is True  the instance should be powered on
        """
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec_instance_info = self.ec2_conn.get_only_instances(
            instance_ids=[ec2_id], filters=None, dry_run=False, max_results=None)
        ec2_instance = ec_instance_info[0]

        # EC2 instance needs to be stopped to modify it's attribute. So we stop the instance,
        # modify the instance type in this case, and then restart the instance.
        ec2_instance.stop()
        self._wait_for_state(instance, ec2_id, "stopped", power_state.SHUTDOWN)
        new_instance_type = flavor_map[migration['new_instance_type_id']]
        ec2_instance.modify_attribute('instanceType', new_instance_type)

    def confirm_migration(self, migration, instance, network_info):
        """Confirms a resize, destroying the source VM.
        :param instance: nova.objects.instance.Instance
        """
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec_instance_info = self.ec2_conn.get_only_instances(
            instance_ids=[ec2_id], filters=None, dry_run=False, max_results=None)
        ec2_instance = ec_instance_info[0]
        ec2_instance.start()
        self._wait_for_state(instance, ec2_id, "running", power_state.RUNNING)

    def pre_live_migration(self, context, instance_ref, block_device_info,
                           network_info, disk, migrate_data=None):
        return

    def unfilter_instance(self, instance_ref, network_info):
        return

    def get_host_stats(self, refresh=False):
        """Return EC2 Host Status of name, ram, disk, network."""
        stats = []
        for nodename in _EC2_NODES:
            host_status = self.host_status_base.copy()
            host_status['hypervisor_hostname'] = nodename
            host_status['host_hostname'] = nodename
            host_status['host_name_label'] = nodename
            host_status['hypervisor_type'] = 'Amazon-EC2'
            host_status['vcpus'] = CONF.AWS.max_vcpus
            host_status['memory_mb'] = CONF.AWS.max_memory_mb
            host_status['local_gb'] = CONF.AWS.max_disk_gb
            stats.append(host_status)
        if len(stats) == 0:
            raise exception.NovaException("EC2Driver has no node")
        elif len(stats) == 1:
            return stats[0]
        else:
            return stats

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        return action

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation.
        """
        if not mode:
            return 'off_maintenance'
        return 'on_maintenance'

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        if enabled:
            return 'enabled'
        return 'disabled'

    def get_disk_available_least(self):
        pass

    def add_to_aggregate(self, context, aggregate, host, **kwargs):
        pass

    def remove_from_aggregate(self, context, aggregate, host, **kwargs):
        pass

    def get_volume_connector(self, instance):
        return {'ip': '127.0.0.1', 'initiator': 'EC2', 'host': 'EC2host'}

    def get_available_nodes(self, refresh=False):
        return _EC2_NODES

    def instance_on_disk(self, instance):
        return False

    def _get_uuid_from_aws_id(self, instance_id):
        m = hashlib.md5()
        m.update(instance_id)
        return str(uuid.UUID(bytes=m.digest(), version=4))

    def list_instance_uuids(self, node=None, template_uuids=None, force=False):
        ec2_instances = self.ec2_conn.get_only_instances()
        # Clear the cache of UUID->EC2 ID mapping
        self._uuid_to_ec2_instance.clear()
        for instance in ec2_instances:
            generate_uuid = False
            if instance.state in ['pending', 'shutting-down', 'terminated']:
                # Instance is being created or destroyed no need to list it
                continue
            if len(instance.tags) > 0:
                if 'openstack_id' in instance.tags:
                    self._uuid_to_ec2_instance[instance.tags['openstack_id']] = \
                            instance
                else:
                    # Possibly a new discovered instance
                    generate_uuid = True
            else:
                generate_uuid = True

            if generate_uuid:
                instance_uuid = self._get_uuid_from_aws_id(instance.id)
                self._uuid_to_ec2_instance[instance_uuid] = instance
        return self._uuid_to_ec2_instance.keys()

    def _wait_for_state(self, instance, ec2_id, desired_state, desired_power_state):
        """Wait for the state of the corrosponding ec2 instance to be in completely available state.
        :params:ec2_id: the instance's corrosponding ec2 id.
        :params:desired_state: the desired state of the instance to be in.
        """
        def _wait_for_power_state():
            """Called at an interval until the VM is running again.
            """
            ec2_instance = self.ec2_conn.get_only_instances(instance_ids=[ec2_id])

            state = ec2_instance[0].state
            if state == desired_state:
                LOG.info("Instance has changed state to %s." % desired_state)
                raise loopingcall.LoopingCallDone()

        def _wait_for_status_check():
            """Power state of a machine might be ON, but status check is the one which gives the real
            """
            ec2_instance = self.ec2_conn.get_all_instance_status(instance_ids=[ec2_id])[0]
            if ec2_instance.system_status.status == 'ok':
                LOG.info("Instance status check is %s / %s" %
                         (ec2_instance.system_status.status, ec2_instance.instance_status.status))
                raise loopingcall.LoopingCallDone()

        #waiting for the power state to change
        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_power_state)
        timer.start(interval=1).wait()

    def _wait_for_image_state(self, ami_id, desired_state):
        """Timer to wait for the image/snapshot to reach a desired state
        :params:ami_id: correspoding image id in Amazon
        :params:desired_state: the desired new state of the image to be in.
        """
        def _wait_for_state():
            """Called at an interval until the AMI image is available."""
            try:
                images = self.ec2_conn.get_all_images(image_ids=[ami_id], owners=None,
                                                      executable_by=None, filters=None, dry_run=None)
                state = images[0].state
                if state == desired_state:
                    LOG.info("Image has changed state to %s." % desired_state)
                    raise loopingcall.LoopingCallDone()
            except boto_exc.EC2ResponseError:
                pass

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_state)
        timer.start(interval=0.5).wait()


class EC2VirtAPI(virtapi.VirtAPI):
    def instance_update(self, context, instance_uuid, updates):
        return db.instance_update_and_get_original(context,
                                                   instance_uuid,
                                                   updates)

    def aggregate_get_by_host(self, context, host, key=None):
        return db.aggregate_get_by_host(context, host, key=key)

    def aggregate_metadata_add(self, context, aggregate, metadata,
                               set_delete=False):
        return db.aggregate_metadata_add(context, aggregate['id'], metadata,
                                         set_delete=set_delete)

    def aggregate_metadata_delete(self, context, aggregate, key):
        return db.aggregate_metadata_delete(context, aggregate['id'], key)

    def security_group_get_by_instance(self, context, instance):
        return db.security_group_get_by_instance(context, instance['uuid'])

    def security_group_rule_get_by_security_group(self, context,
                                                  security_group):
        return db.security_group_rule_get_by_security_group(
            context, security_group['id'])

    def provider_fw_rule_get_all(self, context):
        return db.provider_fw_rule_get_all(context)

    def agent_build_get_by_triple(self, context, hypervisor, os, architecture):
        return db.agent_build_get_by_triple(context,
                                            hypervisor, os, architecture)

    def instance_type_get(self, context, instance_type_id):
        return db.instance_type_get(context, instance_type_id)

    def block_device_mapping_get_all_by_instance(self, context, instance,
                                                 legacy=True):
        bdms = db.block_device_mapping_get_all_by_instance(context,
                                                           instance['uuid'])
        if legacy:
            bdms = block_device.legacy_mapping(bdms)
        return bdms

    def block_device_mapping_update(self, context, bdm_id, values):
        return db.block_device_mapping_update(context, bdm_id, values)
