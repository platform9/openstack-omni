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
from threading import Lock
import base64
import time
from boto import ec2, vpc
import boto.ec2.cloudwatch
from boto import exception as boto_exc
from boto.exception import EC2ResponseError
from boto.regioninfo import RegionInfo
from oslo_config import cfg
from novaclient import client
from ec2_rule_service import EC2RuleService
from ec2_rule_transformer import EC2RuleTransformer
from credentials import Credentials
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
from instance_rule_refresher import InstanceRuleRefresher
from openstack_group_service import OpenstackGroupService
from openstack_rule_service import OpenstackRuleService
from openstack_rule_transformer import OpenstackRuleTransformer
import sys
from group_rule_refresher import GroupRuleRefresher
from nova.virt.ec2.exception_handler import Ec2ExceptionHandler
import json
LOG = logging.getLogger(__name__)

ec2driver_opts = [
    cfg.StrOpt('snapshot_image_format',
               help='Snapshot image format (valid options are : '
                    'raw, qcow2, vmdk, vdi). '
                    'Defaults to same as source image'),
    cfg.StrOpt('datastore_regex',
               help='Regex to match the name of a datastore.'),
    cfg.FloatOpt('task_poll_interval',
                 default=0.5,
                 help='The interval used for polling of remote tasks.'),
    cfg.IntOpt('api_retry_count',
               default=10,
               help='The number of times we retry on failures, e.g., '
                    'socket error, etc.'),
    cfg.IntOpt('vnc_port',
               default=5900,
               help='VNC starting port'),
    cfg.IntOpt('vnc_port_total',
               default=10000,
               help='Total number of VNC ports'),
    cfg.BoolOpt('use_linked_clone',
                default=True,
                help='Whether to use linked clone')
]

aws_group = cfg.OptGroup(name='AWS', title='Options to connect to an AWS cloud')

aws_opts = [
    cfg.StrOpt('secret_key', help='Secret key of AWS account', required=True, secret=True),
    cfg.StrOpt('access_key', help='Access key of AWS account', required=True, secret=True),
    cfg.StrOpt('region_name', help='AWS region', required=True)
]

CONF = cfg.CONF
CONF.register_opts(ec2driver_opts, 'ec2driver')
CONF.import_opt('my_ip', 'nova.netconf')

CONF.register_group(aws_group)
CONF.register_opts(aws_opts, group=aws_group)

# TIME_BETWEEN_API_CALL_RETRIES = 1.0

EC2_STATE_MAP = {
    "pending": power_state.NOSTATE,
    "running": power_state.RUNNING,
    "shutting-down": power_state.NOSTATE,
    "terminated": power_state.SHUTDOWN,
    "stopping": power_state.NOSTATE,
    "stopped": power_state.SHUTDOWN
}

#Default resources available
VCPUS = 100
MEMORY_IN_MBS = 88192
DISK_IN_GB = 1028

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

    """EC2 hypervisor driver. Respurposing for EC2"""

    def __init__(self, virtapi, read_only=False):
        super(EC2Driver, self).__init__(virtapi)
        self.host_status_base = {
            'vcpus': VCPUS,
            'memory_mb': MEMORY_IN_MBS,
            'local_gb': DISK_IN_GB,
            'vcpus_used': 0,
            'memory_mb_used': 0,
            'local_gb_used': 0,
            'hypervisor_type': 'EC2',
            'hypervisor_version': '1.0',
            'hypervisor_hostname': CONF.host,
            'cpu_info': {},
            'disk_available_least': DISK_IN_GB,
        }

        self._mounts = {}
        self._interfaces = {}
        self._pf9_stats = {}
        self.nova_creds = Credentials.get_nova_creds()
        self.nova = None
        if self.nova_creds is None:
            LOG.error("Error fetching the Nova Credentials")
        else:
            VERSION = "2"
            self.nova = client.Client(VERSION, self.nova_creds['OS_USERNAME'], self.nova_creds['OS_PASSWORD'],
                                      tenant_id=self.nova_creds['project_id'], auth_url=self.nova_creds['OS_AUTH_URL'],
                                      region_name=self.nova_creds['OS_REGION_NAME'], insecure=True)

        aws_region = CONF.AWS.region_name
        aws_endpoint = "ec2." + aws_region + ".amazonaws.com"

        region = RegionInfo(name=aws_region, endpoint=aws_endpoint)
        LOG.info("******EC2 init with %s region" % aws_region)
        self.ec2_conn = ec2.EC2Connection(aws_access_key_id=CONF.AWS.access_key,
                                          aws_secret_access_key=CONF.AWS.secret_key,
                                          region=region)

        self.vpc_conn = vpc.VPCConnection(aws_access_key_id=CONF.AWS.access_key,
                                     aws_secret_access_key=CONF.AWS.secret_key,
                                     region=region)

        self.cloudwatch_conn = ec2.cloudwatch.connect_to_region(
            aws_region, aws_access_key_id=CONF.AWS.access_key,
            aws_secret_access_key=CONF.AWS.secret_key)

        self.security_group_lock = Lock()

        self.instance_rule_refresher = InstanceRuleRefresher(
            GroupRuleRefresher(
                ec2_connection=self.ec2_conn,
                openstack_rule_service=OpenstackRuleService(
                    group_service=OpenstackGroupService(self.nova.security_groups),
                    openstack_rule_transformer=OpenstackRuleTransformer()
                ),
                ec2_rule_service=EC2RuleService(
                    ec2_connection=self.ec2_conn,
                    ec2_rule_transformer=EC2RuleTransformer(self.ec2_conn)
                )
            )
        )

        if not '_EC2_NODES' in globals():
            set_nodes([CONF.host])

    def init_host(self, host):
        """Initialize anything that is necessary for the driver to function,
        including catching up with currently running VM's on the given host.
        """
        return

    def list_instances(self):
        """Return the names of all the instances known to the virtualization
        layer, as a list.
        """
        all_instances = self.ec2_conn.get_all_instances()
        instance_ids = []
        for instance in all_instances:
            instance_ids.append(instance.id)
        return instance_ids

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        pass

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        pass

    def _configure_default_security_group(self):
        """ This function will create and configure Platform9's Default Security Group
        """
        LOG.info("Configuring default security groups")
        sec_groups = self.ec2_conn.get_all_security_groups()
        p9_sec_group_name = "pf9-default"
        p9_sec_group_desc = "This is the default Platform9 security group"
        ip_protocol = "TCP"
        from_port = to_port = 22
        cidr_ip = "0.0.0.0/0"

        try:
            for sec_group in sec_groups:
                if sec_group.name == p9_sec_group_name:
                    self.ec2_conn.authorize_security_group(group_name=p9_sec_group_name, ip_protocol=ip_protocol,
                                                           from_port=from_port, to_port=to_port, cidr_ip=cidr_ip)
                    return

            self.ec2_conn.create_security_group(p9_sec_group_name, p9_sec_group_desc)
            self.ec2_conn.authorize_security_group(group_name=p9_sec_group_name, ip_protocol=ip_protocol,
                                                   from_port=from_port, to_port=to_port, cidr_ip=cidr_ip)
        except EC2ResponseError:
            exp = sys.exc_value
            if exp.error_code == "InvalidPermission.Duplicate":
                LOG.info("default security group already exists")
            else:
                LOG.info("Error in _configure_default_security_group: %s" % exp.message)

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
            LOG.info("***** Adding SSH key to AWS")
            self.ec2_conn.import_key_pair(key_name, key_data)
        else:
            LOG.info("***** SSH key already exists in AWS")

    def _get_subnet_id(self):
        """
            Will fetch the Subnet ID of the first Subnet in the VPC
        :return: subnet_id
        """
        subnets = self.vpc_conn.get_all_subnets()
        if len(subnets) > 0:
            subnet_id = subnets[0].id
            LOG.info("***** Calling SPAWN Subnet found is %s" % subnet_id)
            return subnet_id
        return None

    def _get_image_ami_id_from_meta(self, context, image_lacking_meta):
        """
            Pulls the Image AMI ID from the location attribute of Image Meta
        :param image_meta:
        :return: ami_id
        """
        image_api = glance.get_default_image_service()
        image_meta = image_api._client.call(context, 2, 'get', image_lacking_meta['id'])
        LOG.info("***** Calling _get_image_ami_id_from_meta Meta*******: %s", image_meta)
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
        LOG.info("*****Networks ****** %s" % network_info)
        subnet_id = None
        fixed_ip = None
        for vif in network_info:
            LOG.info("*****VIF *****")
            if 'details' in vif:
                network_dict = json.loads(vif['details'])
                subnet_id = network_dict['subnet_id']
                LOG.info("Adding subnet ID:" + subnet_id)
                fixed_ip = network_dict['ip_address']
                LOG.info("Fixed IP:" + fixed_ip)
        return subnet_id, fixed_ip

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
        # image_ami_id = "ami-06116566"

        subnet_id, fixed_ip = self._process_network_info(network_info)
        if subnet_id is None or fixed_ip is None:
            raise exception.BuildAbortException("Network configuration failure")

        #Flavor
        flavor_dict = instance['flavor']
        LOG.info("***** Calling SPAWN Flavor Input******: %s " % flavor_dict)
        # flavor_type = flavor_map[instance.get_flavor().id]
        flavor_type = flavor_dict['name']
        LOG.info("***** Calling SPAWN Flavor after mapping ***: %s" % flavor_type)

        # SSH Keys
        if instance['key_name'] is not None and instance['key_data'] is not None:
            self._add_ssh_keys(instance['key_name'], instance['key_data'])

        #Security groups
        # self._configure_default_security_group()
        # security_groups = ["default"]

        #Creating the EC2 instance
        user_data = None
        #passing user_data from the openstack instance which is Base64 encoded after decoding it.
        if 'user_data' in instance and instance['user_data'] is not None:
            user_data = instance['user_data']
            LOG.info("****** Calling SPAWN user_data.... %s" % user_data)
            user_data = base64.b64decode(user_data)

        try:
            reservation = self.ec2_conn.run_instances(instance_type=flavor_type, key_name=instance['key_name'],
                                                      image_id=image_ami_id,
                                                      user_data=user_data, subnet_id=subnet_id, private_ip_address=fixed_ip)
            ec2_instance = reservation.instances
            ec2_instance_obj = ec2_instance[0]
            ec2_id = ec2_instance[0].id
            self._wait_for_state(instance, ec2_id, "running", power_state.RUNNING)
            LOG.info("****** Instance is UP and Running *********")
            instance['metadata'].update({'ec2_id': ec2_id})
            LOG.debug("*** ADDing Instance name tag %s to the AWS instance" % instance['display_name'])
            ec2_instance_obj.add_tag("Name", instance['display_name'])
            LOG.debug("*** ADDing Openstack uuid tag %s to the AWS instance" % instance['uuid'])
            ec2_instance_obj.add_tag("openstack_id", instance['uuid'])

            # Fetch Public IP of the instance if it has one
            instances = self.ec2_conn.get_only_instances(instance_ids=[ec2_id])
            if len(instances) > 0:
                public_ip = instances[0].ip_address
                if public_ip is not None:
                    LOG.info("****** Updating Public IP address of the device")
                    instance['metadata'].update({'public_ip_address': public_ip})
        except EC2ResponseError as ec2_exception:
            actual_exception = Ec2ExceptionHandler.get_processed_exception(ec2_exception)
            LOG.info("Error in starting instance %s" % (actual_exception))
            raise exception.BuildAbortException(actual_exception.message)



    def snapshot(self, context, instance, image_id, update_task_state):
        """Snapshot an image of the specified instance
        on EC2 and create an Image which gets stored in AMI (internally in EBS Snapshot)
        :param context: security context
        :param instance: nova.objects.instance.Instance
        :param image_id: Reference to a pre-created image that will hold the snapshot.
        """
        if instance['metadata']['ec2_id'] is None:
            raise exception.InstanceNotRunning(instance_id=instance['uuid'])

        # Adding the below line only alters the state of the instance and not
        # its image in OpenStack.
        update_task_state(
            task_state=task_states.IMAGE_UPLOADING, expected_state=task_states.IMAGE_SNAPSHOT)
        ec2_id = instance['metadata']['ec2_id']
        ec_instance_info = self.ec2_conn.get_only_instances(
            instance_ids=[ec2_id], filters=None, dry_run=False, max_results=None)
        ec2_instance = ec_instance_info[0]
        if ec2_instance.state == 'running':
            ec2_image_id = ec2_instance.create_image(name=str(
                image_id), description="Image from OpenStack", no_reboot=False, dry_run=False)
            LOG.info("Image has been created state to %s." % ec2_image_id)

        # The instance will be in pending state when it comes up, waiting forit to be in available
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
        # TODO(jhurt): This currently fails, leaving the status of an instance as 'snapshotting'
        image_api.update(context, image_id, metadata)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):

        """Reboot the specified instance.
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
        ec2_id = instance['metadata']['ec2_id']
        self.ec2_conn.reboot_instances(instance_ids=[ec2_id], dry_run=False)
        LOG.info("Soft Reboot Complete.")

    def _hard_reboot(self, context, instance, network_info, block_device_info=None):
        self.power_off(instance)
        self.power_on(context, instance, network_info, block_device)
        LOG.info("Hard Reboot Complete.")

    @staticmethod
    def get_host_ip_addr():
        """Retrieves the IP address of the dom0
        """
        LOG.info("***** Calling get_host_ip_addr *******************")
        return CONF.my_ip

    def set_admin_password(self, instance, new_pass):
        """Boto doesn't support setting the password at the time of creating an instance.
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
        """Power off the specified instance.
        :param instance: nova.objects.instance.Instance
        :param timeout: time to wait for GuestOS to shutdown
        :param retry_interval: How often to signal guest while
                               waiting for it to shutdown
        """
        # TODO: Need to use timeout and retry_interval
        LOG.info("***** Calling POWER OFF *******************")
        ec2_id = instance['metadata']['ec2_id']
        self.ec2_conn.stop_instances(
            instance_ids=[ec2_id], force=False, dry_run=False)
        self._wait_for_state(instance, ec2_id, "stopped", power_state.SHUTDOWN)

    def power_on(self, context, instance, network_info, block_device_info):
        """Power on the specified instance.
        """
        LOG.info("***** Calling POWER ON *******************")
        ec2_id = instance['metadata']['ec2_id']
        self.ec2_conn.start_instances(instance_ids=[ec2_id], dry_run=False)
        self._wait_for_state(instance, ec2_id, "running", power_state.RUNNING)

    def soft_delete(self, instance):
        """Deleting the specified instance
        """
        self.destroy(instance)

    def restore(self, instance):
        pass

    def pause(self, instance):
        """Boto doesn't support pause and cannot save system state and hence we've implemented the closest functionality
        which is to poweroff the instance.
        :param instance: nova.objects.instance.Instance
        """
        self.power_off(instance)

    def unpause(self, instance):
        """Since Boto doesn't support pause and cannot save system state, we had implemented the closest functionality
        which is to poweroff the instance. and powering on such an instance in this method.
        :param instance: nova.objects.instance.Instance
        """
        self.power_on(
            context=None, instance=instance, network_info=None, block_device_info=None)

    def suspend(self, context, instance):
        """Boto doesn't support suspend and cannot save system state and hence we've implemented the closest
        functionality which is to poweroff the instance.
        :param instance: nova.objects.instance.Instance
        """
        self.power_off(instance)

    def resume(self, context, instance, network_info, block_device_info=None):
        """Since Boto doesn't support suspend and we cannot save system state, we've implemented the closest
        functionality which is to power on the instance.
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
        LOG.info("***** Calling DESTROY *******************")
        if 'ec2_id' not in instance['metadata']:
            LOG.warning("Key '%s' not in EC2 instances" % instance['name'], instance=instance)
            return
        else:
            # Deleting the instance from EC2
            ec2_id = instance['metadata']['ec2_id']
            try:
                ec2_instances = self.ec2_conn.get_only_instances(instance_ids=[ec2_id])
            except Exception:
                return
            if ec2_instances.__len__() == 0:
                LOG.warning("EC2 instance with ID %s not found" % ec2_id, instance=instance)
                return
            else:
                try:
                    self.ec2_conn.stop_instances(instance_ids=[ec2_id], force=True)
                    self.ec2_conn.terminate_instances(instance_ids=[ec2_id])
                    self._wait_for_state(instance, ec2_id, "terminated", power_state.SHUTDOWN)
                except:
                    exp = sys.exc_value
                    LOG.exception("Exception while destroying instance: %s" % exp)
                    raise exception.NovaException("Exception while destroying instance")

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach the disk to the instance at mountpoint using info.
        """
        instance_name = instance['name']
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = connection_info

        volume_id = connection_info['data']['volume_id']
        # ec2 only attaches volumes at /dev/sdf through /dev/sdp
        self.ec2_conn.attach_volume(volume_map[volume_id], instance['metadata']['ec2_id'], "/dev/sdn", dry_run=False)

    def detach_volume(self, connection_info, instance, mountpoint, encryption=None):
        """Detach the disk attached to the instance.
        """
        try:
            del self._mounts[instance['name']][mountpoint]
        except KeyError:
            pass
        volume_id = connection_info['data']['volume_id']
        self.ec2_conn.detach_volume(volume_map[volume_id], instance_id=instance['metadata']['ec2_id'],
                                    device="/dev/sdn", force=False, dry_run=False)

    def swap_volume(self, old_connection_info, new_connection_info,
                    instance, mountpoint):
        """Replace the disk attached to the instance.
        """
        instance_name = instance['name']
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = new_connection_info

        old_volume_id = old_connection_info['data']['volume_id']
        new_volume_id = new_connection_info['data']['volume_id']

        self.detach_volume(old_connection_info, instance, mountpoint)
        # wait for the old volume to detach successfully to make sure
        # /dev/sdn is available for the new volume to be attached
        time.sleep(60)
        self.ec2_conn.attach_volume(volume_map[new_volume_id], instance['metadata']['ec2_id'], "/dev/sdn",
                                    dry_run=False)
        return True

    def attach_interface(self, instance, image_meta, vif):
        LOG.info("******* ATTTACH INTERFACE *******")
        if vif['id'] in self._interfaces:
            raise exception.InterfaceAttachFailed('duplicate')
        self._interfaces[vif['id']] = vif

    def detach_interface(self, instance, vif):
        LOG.info("******* DETACH INTERFACE *******")
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
        LOG.info("*************** GET INFO ********************")
        if 'metadata' not in instance or 'ec2_id' not in instance['metadata']:
            raise exception.InstanceNotFound(instance_id=instance['name'])

        ec2_id = instance['metadata']['ec2_id']
        ec2_instances = self.ec2_conn.get_only_instances(instance_ids=[ec2_id], filters=None, dry_run=False,
                                                         max_results=None)
        if ec2_instances.__len__() == 0:
            LOG.warning(_("EC2 instance with ID %s not found") % ec2_id, instance=instance)
            raise exception.InstanceNotFound(instance_id=instance['name'])
        ec2_instance = ec2_instances[0]
        LOG.info(ec2_instance)
        LOG.info("state %s max_mem %s mem %s flavor %s" %
                 (EC2_STATE_MAP.get(ec2_instance.state), ec2_instance.ramdisk, ec2_instance.get_attribute('ramdisk', dry_run=False), ec2_instance.instance_type))
        # return {'state': ,
        #         'max_mem': ec2_instance.ramdisk,
        #         'mem': ,
        #         'num_cpu': 2,
        #         'cpu_time': 0}
        return hardware.InstanceInfo(
            state=EC2_STATE_MAP.get(ec2_instance.state),
            max_mem_kb=ec2_instance.ramdisk,
            mem_kb=ec2_instance.get_attribute('ramdisk', dry_run=False),
            num_cpu=2,
            cpu_time_ns=0,
            id=instance['id'])

    def allow_key(self, key):
        for key_to_filter in DIAGNOSTIC_KEYS_TO_FILTER:
            if key == key_to_filter:
                return False
        return True

    def get_diagnostics(self, instance_name):
        """Return data about VM diagnostics.
        """
        LOG.info("******* GET DIAGNOSTICS *********************************************")
        instance = self.nova.servers.get(instance_name)

        ec2_id = instance.metadata['ec2_id']
        ec2_instances = self.ec2_conn.get_only_instances(instance_ids=[ec2_id], filters=None, dry_run=False,
                                                         max_results=None)
        if ec2_instances.__len__() == 0:
            LOG.warning(_("EC2 instance with ID %s not found") % ec2_id, instance=instance)
            raise exception.InstanceNotFound(instance_id=instance['name'])
        ec2_instance = ec2_instances[0]

        diagnostics = {}
        for key, value in ec2_instance.__dict__.items():
            if self.allow_key(key):
                diagnostics['instance.' + key] = str(value)

        metrics = self.cloudwatch_conn.list_metrics(dimensions={'InstanceId': ec2_id})
        import datetime

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
        ec2_id = instance['metadata']['ec2_id']
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

    def _get_ec2_instance_ids_with_security_group(self, ec2_security_group):
        return [instance.id for instance in ec2_security_group.instances()]

    def _get_openstack_instances_with_security_group(self, openstack_security_group):
        return [instance for instance in (self.nova.servers.list())
                if openstack_security_group.name in [group['name'] for group in instance.security_groups]]

    def _get_id_of_ec2_instance_to_update_security_group(self, ec2_instance_ids_for_security_group,
                                                         ec2_ids_for_openstack_instances_for_security_group):
        return (set(ec2_ids_for_openstack_instances_for_security_group).symmetric_difference(
            set(ec2_instance_ids_for_security_group))).pop()

    def _should_add_security_group_to_instance(self, ec2_instance_ids_for_security_group,
                                               ec2_ids_for_openstack_instances_for_security_group):
        return len(ec2_instance_ids_for_security_group) < len(ec2_ids_for_openstack_instances_for_security_group)

    def _add_security_group_to_instance(self, ec2_instance_id, ec2_security_group):
        security_group_ids_for_instance = self._get_ec2_security_group_ids_for_instance(ec2_instance_id)
        security_group_ids_for_instance.append(ec2_security_group.id)
        self.ec2_conn.modify_instance_attribute(ec2_instance_id, "groupSet", security_group_ids_for_instance)

    def _remove_security_group_from_instance(self, ec2_instance_id, ec2_security_group):
        security_group_ids_for_instance = self._get_ec2_security_group_ids_for_instance(ec2_instance_id)
        security_group_ids_for_instance.remove(ec2_security_group.id)
        self.ec2_conn.modify_instance_attribute(ec2_instance_id, "groupSet", security_group_ids_for_instance)

    def _get_ec2_security_group_ids_for_instance(self, ec2_instance_id):
        security_groups_for_instance = self.ec2_conn.get_instance_attribute(ec2_instance_id, "groupSet")['groupSet']
        security_group_ids_for_instance = [group.id for group in security_groups_for_instance]
        return security_group_ids_for_instance

    def _get_or_create_ec2_security_group(self, openstack_security_group):
        try:
            return self.ec2_conn.get_all_security_groups(openstack_security_group.name)[0]
        except (EC2ResponseError, IndexError) as e:
            LOG.warning(e)
            return self.ec2_conn.create_security_group(openstack_security_group.name,
                                                       openstack_security_group.description)

    def refresh_security_group_rules(self, security_group_id):
        """This method is called after a change to security groups.

        All security groups and their associated rules live in the datastore,
        and calling this method should apply the updated rules to instances
        running the specified security group.
        An error should be raised if the operation cannot complete.
        """
        LOG.info("************** REFRESH SECURITY GROUP RULES ******************")

        openstack_security_group = self.nova.security_groups.get(security_group_id)
        ec2_security_group = self._get_or_create_ec2_security_group(openstack_security_group)

        ec2_ids_for_ec2_instances_with_security_group = self._get_ec2_instance_ids_with_security_group(
            ec2_security_group)

        ec2_ids_for_openstack_instances_with_security_group = [
            instance.metadata['ec2_id'] for instance
            in self._get_openstack_instances_with_security_group(openstack_security_group)
        ]

        self.security_group_lock.acquire()

        try:
            ec2_instance_to_update = self._get_id_of_ec2_instance_to_update_security_group(
                ec2_ids_for_ec2_instances_with_security_group,
                ec2_ids_for_openstack_instances_with_security_group
            )

            should_add_security_group = self._should_add_security_group_to_instance(
                ec2_ids_for_ec2_instances_with_security_group,
                ec2_ids_for_openstack_instances_with_security_group)

            if should_add_security_group:
                self._add_security_group_to_instance(ec2_instance_to_update, ec2_security_group)
            else:
                self._remove_security_group_from_instance(ec2_instance_to_update, ec2_security_group)
        finally:
            self.security_group_lock.release()

        return True

    def refresh_security_group_members(self, security_group_id):
        LOG.info("************** REFRESH SECURITY GROUP MEMBERS ******************")
        LOG.info(security_group_id)
        return True

    def _get_allowed_group_name_from_openstack_rule_if_present(self, openstack_rule):
        return openstack_rule['group']['name'] if 'name' in openstack_rule['group'] else None

    def _get_allowed_ip_range_from_openstack_rule_if_present(self, openstack_rule):
        return openstack_rule['ip_range']['cidr'] if 'cidr' in openstack_rule['ip_range'] else None

    def refresh_instance_security_rules(self, instance):
        LOG.info("************** REFRESH INSTANCE SECURITY RULES ******************")
        LOG.info(instance)

        # TODO: lock for case when group is associated with multiple instances

        self.instance_rule_refresher.refresh(self.nova.servers.get(instance['id']))

        return

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
        LOG.info("************** GET_AVAILABLE_RESOURCE ******************")

        if nodename not in _EC2_NODES:
            return {}

        dic = {'vcpus': VCPUS,
               'memory_mb': MEMORY_IN_MBS,
               'local_gb': DISK_IN_GB,
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

    def get_host_stats_pf9(self, res_types, refresh=False, nodename=None):
        """Return currently known physical resource consumption
        If 'refresh' is True, run update the stats first.
        :param res_types: An array of resources to be queried
        """
        LOG.info("*** In get_host_stats_pf9**")
        resource_stats = dict()
        for resource_type in res_types:
            LOG.info("Looking for resource:%s" % resource_type)
            resource_dict = self._get_host_stats_pf9(resource_type,
                                                     refresh=refresh)
            resource_stats.update(resource_dict)
        return resource_stats

    def _update_stats_pf9(self, resource_type):
        """Retrieve physical resource utilization
        """
        if resource_type not in self._pf9_stats.keys():
            self._pf9_stats[resource_type] = {}

        data = 0
        self._pf9_stats[resource_type] = data

        return {resource_type: data}

    def _get_host_stats_pf9(self, res_types, refresh=False):
        """Return the current physical resource consumption
        """
        if refresh or not self._pf9_stats:
            self._update_stats_pf9(res_types)

        return self._pf9_stats

    def get_all_networks_pf9(self, node=None):
        ret_list = []
        vpcs = self.vpc_conn.get_all_vpcs()
        for vpc in vpcs:
            ret_list.append({'bridge': vpc.id})
        return ret_list

    def get_all_ip_mapping_pf9(self, needed_uuids=None):
        ip_map = dict()
        ec2_instances = self.ec2_conn.get_all_instances()
        for reservation in ec2_instances:
            if reservation.instances is not None:
                for instance in reservation.instances:
                    if len(instance.tags) > 0:
                        if 'openstack_id' in instance.tags:
                            openstack_id = instance.tags['openstack_id']
                            intf_list = []
                            intf_details = dict()
                            if len(instance.interfaces) > 0:
                                for interface in instance.interfaces:
                                    intf_details['bridge'] = interface.vpc_id
                                    intf_details['ip_address'] = interface.private_ip_address
                                    intf_details['mac_address'] = interface.mac_address
                                    LOG.info(
                                        "ID %s VPC %s and IP %s and MAC %s" % (
                                        openstack_id, interface.vpc_id, instance.private_ip_address, interface.mac_address))
                                    intf_list.append(intf_details)
                                ip_map[openstack_id] = intf_list
        return ip_map

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
        LOG.info("***** Calling FINISH MIGRATION *******************")
        ec2_id = instance['metadata']['ec2_id']
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
        LOG.info("***** Calling CONFIRM MIGRATION *******************")
        ec2_id = instance['metadata']['ec2_id']
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
            host_status['vcpus'] = VCPUS
            host_status['memory_mb'] = MEMORY_IN_MBS
            host_status['local_gb'] = DISK_IN_GB
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

    def list_instance_uuids(self, node=None, template_uuids=None, force=False):
        LOG.info("*** list_instance_uuids **")
        ec2_instances = self.ec2_conn.get_only_instances()
        uuid_list = []
        for instance in ec2_instances:
            if len(instance.tags) > 0:
                if 'openstack_id' in instance.tags:
                    uuid_list.append(instance.tags['openstack_id'])
        return uuid_list

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
