# Copyright (c) 2014 ThoughtWorks
# Copyright (c) 2016 Platform9 Systems Inc.
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

class RuleComparator:
    def __init__(self, ec2_connection):
        self.ec2_connection = ec2_connection

    def rules_are_equal(self, openstack_rule, ec2_rule):
        if self._ip_protocols_are_different(ec2_rule, openstack_rule) \
                or self._from_ports_are_different(ec2_rule, openstack_rule) \
                or self._to_ports_are_different(ec2_rule, openstack_rule) \
                or self._ip_ranges_are_present_and_different(ec2_rule, openstack_rule) \
                or self._group_names_are_present_and_different(openstack_rule, ec2_rule):
            return False
        return True

    def _ip_protocols_are_different(self, ec2_rule, openstack_rule):
        return openstack_rule['ip_protocol'] != ec2_rule.ip_protocol

    def _from_ports_are_different(self, ec2_rule, openstack_rule):
        return str(openstack_rule['from_port']) != ec2_rule.from_port

    def _to_ports_are_different(self, ec2_rule, openstack_rule):
        return str(openstack_rule['to_port']) != ec2_rule.to_port

    def _ip_ranges_are_present_and_different(self, ec2_rule, openstack_rule):
        return ('cidr' in openstack_rule['ip_range'] and openstack_rule['ip_range']['cidr'] != ec2_rule.grants[0].cidr_ip)

    def _group_names_are_present_and_different(self, openstack_rule, ec2_rule):
        if 'name' not in openstack_rule['group']:
            return False
        else:
            ec2_group_name = self.ec2_connection.get_all_security_groups(group_ids=ec2_rule.grants[0].group_id)[0].name
            return openstack_rule['group']['name'] != ec2_group_name
