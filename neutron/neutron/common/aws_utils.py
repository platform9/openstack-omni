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

from ConfigParser import ConfigParser
import boto3
from novaclient.v2 import client as novaclient
from oslo_log import log as logging
from neutron.common import exceptions
import botocore
from oslo_config import cfg

aws_group = cfg.OptGroup(name='AWS', title='Options to connect to an AWS environment')
aws_opts = [
    cfg.StrOpt('secret_key', help='Secret key of AWS account', secret=True),
    cfg.StrOpt('access_key', help='Access key of AWS account', secret=True),
    cfg.StrOpt('region_name', help='AWS region'),
    cfg.StrOpt('az', help='AWS availability zone'),
    cfg.IntOpt('wait_time_min', help='Maximum wait time for AWS operations', default=5)
]

cfg.CONF.register_group(aws_group)
cfg.CONF.register_opts(aws_opts, group=aws_group)

LOG = logging.getLogger(__name__)

def _process_exception(e, dry_run):
    if dry_run:
        error_code = e.response['Code']
        if not error_code == 'DryRunOperation':
            raise exceptions.AwsException(error_code='AuthFailure',
                message='Check your AWS authorization')
    else:
        if isinstance(e, botocore.exceptions.ClientError):
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            raise exceptions.AwsException(error_code=error_code,
                message=error_message)
        else:
            # TODO: This might display all Exceptions to the user which
            # might be irrelevant, keeping it until it becomes stable
            error_message = e.message
            raise exceptions.AwsException(error_code="NeutronError",
                message=error_message)

def aws_exception(fn):
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            _process_exception(e, kwargs.get('dry_run'))
    return wrapper


class AwsUtils:

    def __init__(self):
        self.__ec2_client = None
        self.__ec2_resource = None
        self._nova_client = None
        self._neutron_credentials = {
            'aws_secret_access_key': cfg.CONF.AWS.secret_key,
            'aws_access_key_id': cfg.CONF.AWS.access_key,
            'region_name': cfg.CONF.AWS.region_name
        }

    def get_nova_client(self):
        if self._nova_client is None:
            self._nova_client = novaclient.Client(username=cfg.CONF.nova_admin_username,
                api_key=cfg.CONF.nova_admin_password, auth_url=cfg.CONF.nova_admin_auth_url,
                tenant_id=cfg.CONF.nova_admin_tenant_id,
                region_name=cfg.CONF.nova_region_name, insecure=True)
        return self._nova_client

    def _get_ec2_client(self):
        if self.__ec2_client is None:
            self.__ec2_client = boto3.client('ec2', **self._neutron_credentials)
        return self.__ec2_client

    def _get_ec2_resource(self):
        if self.__ec2_resource is None:
            self.__ec2_resource = boto3.resource('ec2', **self._neutron_credentials)
        return self.__ec2_resource

    # Internet Gateway Operations
    @aws_exception
    def get_internet_gw_from_router_id(self, router_id, dry_run=False):
        response = self._get_ec2_client().describe_internet_gateways(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'tag-value',
                    'Values': [router_id]
                },
            ]
        )
        if 'InternetGateways' in response:
            for internet_gateway in response['InternetGateways']:
                if 'InternetGatewayId' in internet_gateway:
                    return internet_gateway['InternetGatewayId']

    @aws_exception
    def create_tags_internet_gw_from_router_id(self, router_id, tags_list, dry_run=False):
        ig_id = self.get_internet_gw_from_router_id(router_id, dry_run)
        internet_gw_res = self._get_ec2_resource().InternetGateway(ig_id)
        internet_gw_res.create_tags(Tags=tags_list)

    @aws_exception
    def delete_internet_gateway_by_router_id(self, router_id, dry_run=False):
        ig_id = self.get_internet_gw_from_router_id(router_id, dry_run)
        self._get_ec2_client().delete_internet_gateway(
            DryRun=dry_run,
            InternetGatewayId=ig_id
        )

    @aws_exception
    def attach_internet_gateway(self, ig_id, vpc_id, dry_run=False):
        return self._get_ec2_client().attach_internet_gateway(
            DryRun=dry_run,
            InternetGatewayId=ig_id,
            VpcId=vpc_id
        )

    @aws_exception
    def detach_internet_gateway_by_router_id(self, router_id, dry_run=False):
        ig_id = self.get_internet_gw_from_router_id(router_id)
        ig_res = self._get_ec2_resource().InternetGateway(ig_id)
        if len(ig_res.attachments) > 0:
            vpc_id = ig_res.attachments[0]['VpcId']
            self._get_ec2_client().detach_internet_gateway(
                DryRun=dry_run,
                InternetGatewayId=ig_id,
                VpcId=vpc_id
            )

    @aws_exception
    def create_internet_gateway(self, dry_run=False):
        return self._get_ec2_client().create_internet_gateway(DryRun=dry_run)

    @aws_exception
    def create_internet_gateway_resource(self, dry_run=False):
        internet_gw = self._get_ec2_client().create_internet_gateway(DryRun=dry_run)
        ig_id = internet_gw['InternetGateway']['InternetGatewayId']
        return self._get_ec2_resource().InternetGateway(ig_id)

    # Elastic IP Operations
    @aws_exception
    def get_elastic_addresses_by_elastic_ip(self, elastic_ip, dry_run=False):
        eip_addresses = self._get_ec2_client().describe_addresses(
            DryRun=dry_run,
            PublicIps=[elastic_ip])
        return eip_addresses['Addresses']

    @aws_exception
    def associate_elastic_ip_to_ec2_instance(self, elastic_ip, ec2_instance_id, dry_run=False):
        allocation_id = None
        eid_addresses = self.get_elastic_addresses_by_elastic_ip(elastic_ip, dry_run)
        if len(eid_addresses) > 0:
            if 'AllocationId' in eid_addresses[0]:
                allocation_id = eid_addresses[0]['AllocationId']
        if allocation_id is None:
            raise exceptions.AwsException(error_code="Allocation ID",
                message="Allocation ID not found")
        return self._get_ec2_client().associate_address(
            DryRun=dry_run,
            InstanceId=ec2_instance_id,
            AllocationId=allocation_id
        )

    @aws_exception
    def allocate_elastic_ip(self, dry_run=False):
        response = self._get_ec2_client().allocate_address(
            DryRun=dry_run,
            Domain='vpc'
        )
        return response

    @aws_exception
    def disassociate_elastic_ip_from_ec2_instance(self, elastic_ip, dry_run=False):
        association_id = None
        eid_addresses = self.get_elastic_addresses_by_elastic_ip(elastic_ip, dry_run)
        if len(eid_addresses) > 0:
            if 'AssociationId' in eid_addresses[0]:
                association_id = eid_addresses[0]['AssociationId']
        if association_id is None:
            raise exceptions.AwsException(error_code="Association ID",
                message="Association ID not found")
        return self._get_ec2_client().disassociate_address(
            DryRun=dry_run,
            AssociationId=association_id
        )

    @aws_exception
    def delete_elastic_ip(self, elastic_ip, dry_run=False):
        eid_addresses = self.get_elastic_addresses_by_elastic_ip(elastic_ip, dry_run)
        if len(eid_addresses) > 0:
            if 'AllocationId' in eid_addresses[0]:
                allocation_id = eid_addresses[0]['AllocationId']
        if allocation_id is None:
            raise exceptions.AwsException(error_code="Allocation ID",
                message="Allocation ID not found")
        return self._get_ec2_client().release_address(
            DryRun=dry_run,
            AllocationId=allocation_id)

    # VPC Operations
    @aws_exception
    def get_vpc_from_neutron_network_id(self, neutron_network_id, dry_run=False):
        response = self._get_ec2_client().describe_vpcs(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'tag-value',
                    'Values': [neutron_network_id]
                }
            ]
        )
        if 'Vpcs' in response:
            for vpc in response['Vpcs']:
                if 'VpcId' in vpc:
                    return vpc['VpcId']
        return None

    @aws_exception
    def create_vpc_and_tags(self, cidr, tags_list, dry_run=False):
        vpc_id = self._get_ec2_client().create_vpc(
            DryRun=dry_run,
            CidrBlock=cidr)['Vpc']['VpcId']
        vpc = self._get_ec2_resource().Vpc(vpc_id)
        vpc.create_tags(Tags=tags_list)
        return vpc_id

    @aws_exception
    def delete_vpc(self, vpc_id, dry_run=False):
        self._get_ec2_client().delete_vpc(
            DryRun=dry_run,
            VpcId=vpc_id
        )

    @aws_exception
    def create_tags_for_vpc(self, neutron_network_id, tags_list):
        vpc_id = self.get_vpc_from_neutron_network_id(neutron_network_id)
        vpc_res = self._get_ec2_resource().Vpc(vpc_id)
        vpc_res.create_tags(Tags=tags_list)

    # Subnet Operations
    @aws_exception
    def create_subnet_and_tags(self, vpc_id, cidr, tags_list, dry_run=False):
        vpc = self._get_ec2_resource().Vpc(vpc_id)
        subnet = vpc.create_subnet(
            DryRun=dry_run,
            CidrBlock=cidr)
        subnet.create_tags(Tags=tags_list)

    @aws_exception
    def create_subnet_tags(self, neutron_subnet_id, tags_list, dry_run=False):
        subnet_id = self.get_subnet_from_neutron_subnet_id(neutron_subnet_id)
        subnet = self._get_ec2_resource().Subnet(subnet_id)
        subnet.create_tags(Tags=tags_list)

    @aws_exception
    def delete_subnet(self, subnet_id, dry_run=False):
        self._get_ec2_client().delete_subnet(
            DryRun=dry_run,
            SubnetId=subnet_id
        )

    @aws_exception
    def get_subnet_from_neutron_subnet_id(self, neutron_subnet_id, dry_run=False):
        response = self._get_ec2_client().describe_subnets(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'tag-value',
                    'Values': [neutron_subnet_id]
                }
            ]
        )
        if 'Subnets' in response:
            for subnet in response['Subnets']:
                if 'SubnetId' in subnet:
                    return subnet['SubnetId']
        return None

    # RouteTable Operations
    @aws_exception
    def describe_route_tables_by_vpc_id(self, vpc_id, dry_run=False):
        response = self._get_ec2_client().describe_route_tables(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                },
            ]
        )
        return response['RouteTables']

    @aws_exception
    def get_route_table_by_router_id(self, neutron_router_id, dry_run=False):
        response = self._get_ec2_client().describe_route_tables(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'tag-value',
                    'Values': [neutron_router_id]
                },
            ]
        )
        return response['RouteTables']

    # Has ignore_errors special case so can't use decorator
    def create_default_route_to_ig(self, route_table_id, ig_id, dry_run=False, ignore_errors=False):
        try:
            self._get_ec2_client().create_route(
                DryRun=dry_run,
                RouteTableId=route_table_id,
                DestinationCidrBlock='0.0.0.0/0',
                GatewayId=ig_id,
            )
        except Exception as e:
            LOG.warning("Ignoring failure in creating default route to IG: %s" % e)
            if not ignore_errors:
                _process_exception(e, dry_run)
