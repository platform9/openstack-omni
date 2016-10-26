# Copyright 2016 Platform9 Systems Inc.(http://www.platform9.com)
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

from oslo_log import log
from neutron.common.aws_utils import AwsUtils
from neutron.common.exceptions import AwsException
from neutron.plugins.ml2 import driver_api as api
import json
import random

LOG = log.getLogger(__name__)

class AwsMechanismDriver(api.MechanismDriver):
    """Ml2 Mechanism driver for AWS"""
    def __init__(self):
        self.aws_utils = None

    def initialize(self):
        self.aws_utils = AwsUtils()

    # NETWORK
    def create_network_precommit(self, context):
        pass

    def create_network_postcommit(self, context):
        pass

    def update_network_precommit(self, context):
        try:
            network_name = context.current['name']
            neutron_network_id = context.current['id']
            tags_list = [{'Key': 'Name', 'Value': network_name}]
            self.aws_utils.create_tags_for_vpc(neutron_network_id, tags_list)
        except Exception as e:
            LOG.error("Error in update subnet precommit: %s" % e)
            raise e

    def update_network_postcommit(self, context):
        pass

    def delete_network_precommit(self, context):
        neutron_network_id = context.current['id']
        # If user is deleting an empty  neutron network then nothing to be done on AWS side
        if len(context.current['subnets']) > 0:
            vpc_id = self.aws_utils.get_vpc_from_neutron_network_id(neutron_network_id)
            if vpc_id is not None:
                LOG.info("Deleting network %s (VPC_ID: %s)" % (neutron_network_id, vpc_id))
                self.aws_utils.delete_vpc(vpc_id=vpc_id)

    def delete_network_postcommit(self, context):
        pass

    # SUBNET
    def create_subnet_precommit(self, context):
        LOG.info("Create subnet for network %s" % context.network.current['id'])
        # External Network doesn't exist on AWS, so no operations permitted
        if 'provider:physical_network' in context.network.current and context.network.current['provider:physical_network'] == "external":
            # Do not create subnets for external & provider networks. Only allow tenant network
            # subnet creation at the moment.
            return

        if context.current['ip_version'] == 6:
            raise AwsException(error_code="IPv6Error", message="Cannot create subnets with IPv6")
        mask = int(context.current['cidr'][-2:])
        if mask < 16 or mask > 28:
            raise AwsException(error_code="InvalidMask", message="Subnet mask has to be >16 and <28")
        try:
            # Check if this is the first subnet to be added to a network
            neutron_network = context.network.current
            associated_vpc_id = self.aws_utils.get_vpc_from_neutron_network_id(neutron_network['id'])
            if associated_vpc_id is None:
                # Need to create EC2 VPC
                vpc_cidr = context.current['cidr'][:-2] + '16'
                tags = [
                    {'Key': 'Name', 'Value': neutron_network['name']},
                    {'Key': 'openstack_network_id', 'Value': neutron_network['id']}
                ]
                associated_vpc_id = self.aws_utils.create_vpc_and_tags(cidr=vpc_cidr,
                                                   tags_list=tags)
            # Create Subnet in AWS
            tags = [
                {'Key': 'Name', 'Value': context.current['name']},
                {'Key': 'openstack_subnet_id', 'Value': context.current['id']}
            ]
            self.aws_utils.create_subnet_and_tags(vpc_id=associated_vpc_id,
                                                  cidr=context.current['cidr'],
                                                  tags_list=tags)
        except Exception as e:
            LOG.error("Error in create subnet precommit: %s" % e)
            raise e

    def create_subnet_postcommit(self, context):
        pass

    def update_subnet_precommit(self, context):
        try:
            subnet_name = context.current['name']
            neutron_subnet_id = context.current['id']
            tags_list = [{'Key': 'Name', 'Value': subnet_name}]
            self.aws_utils.create_subnet_tags(neutron_subnet_id, tags_list)
        except Exception as e:
            LOG.error("Error in update subnet precommit: %s" % e)
            raise e

    def update_subnet_postcommit(self, context):
        pass

    def delete_subnet_precommit(self, context):
        if 'provider:physical_network' in context.network.current and context.network.current[
            'provider:physical_network'] == "external":
            LOG.error("Deleting provider and external networks not supported")
            return
        try:
            LOG.info("Deleting subnet %s" % context.current['id'])
            subnet_id = self.aws_utils.get_subnet_from_neutron_subnet_id(context.current['id'])
            if subnet_id is not None:
                self.aws_utils.delete_subnet(subnet_id=subnet_id)
        except Exception as e:
            LOG.error("Error in delete subnet precommit: %s" % e)
            raise e

    def delete_subnet_postcommit(self, context):
        neutron_network = context.network.current
        if 'provider:physical_network' in context.network.current and context.network.current[
            'provider:physical_network'] == "external":
            return
        try:
            subnets = neutron_network['subnets']
            if len(subnets) == 1 and subnets[0] == context.current['id'] or len(subnets) == 0:
                # Last subnet for this network was deleted, so delete VPC
                # because VPC gets created during first subnet creation under
                # an OpenStack network
                vpc_id = self.aws_utils.get_vpc_from_neutron_network_id(neutron_network['id'])
                LOG.info("Deleting VPC %s since this was the last subnet in the vpc" % vpc_id)
                self.aws_utils.delete_vpc(vpc_id=vpc_id)
        except Exception as e:
            LOG.error("Error in delete subnet postcommit: %s" % e)
            raise e

    def create_port_precommit(self, context):
        pass

    def create_port_postcommit(self, context):
        pass

    def update_port_precommit(self, context):
        pass

    def update_port_postcommit(self, context):
        pass

    def delete_port_precommit(self, context):
        pass

    def delete_port_postcommit(self, context):
        pass

    def bind_port(self, context):
        fixed_ip_dict = dict()
        if 'fixed_ips' in context.current:
            if len(context.current['fixed_ips']) > 0:
                fixed_ip_dict = context.current['fixed_ips'][0]
                fixed_ip_dict['subnet_id'] = self.aws_utils.get_subnet_from_neutron_subnet_id(fixed_ip_dict['subnet_id'])

        segment_id = random.choice(context.network.network_segments)[api.ID]
        context.set_binding(segment_id,
                            "vip_type_a",
                            json.dumps(fixed_ip_dict),
                            status='ACTIVE')
        return True
