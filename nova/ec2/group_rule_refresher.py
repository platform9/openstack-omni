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

class GroupRuleRefresher:

    def __init__(self, ec2_connection, openstack_rule_service, ec2_rule_service):
        self.ec2_conn = ec2_connection
        self.openstack_rule_service = openstack_rule_service
        self.ec2_rule_service = ec2_rule_service

    def refresh(self, group_name):
        openstack_rules = self.openstack_rule_service.get_rules_for_group(group_name)
        ec2_rules = self.ec2_rule_service.get_rules_for_group(group_name)

        self._add_rules_to_ec2(ec2_rules, group_name, openstack_rules)
        self._remove_rules_from_ec2(ec2_rules, group_name, openstack_rules)

    def _add_rules_to_ec2(self, ec2_rules, group_name, openstack_rules):
        for rule in openstack_rules - ec2_rules:
            self._add_rule_on_ec2(group_name, rule)

    def _remove_rules_from_ec2(self, ec2_rules, group_name, openstack_rules):
        for rule in ec2_rules - openstack_rules:
            self._remove_rule_from_ec2(group_name, rule)

    def _remove_rule_from_ec2(self, group_name, rule):
        self.ec2_conn.revoke_security_group(
            group_name=group_name,
            ip_protocol=rule.ip_protocol,
            from_port=rule.from_port,
            to_port=rule.to_port,
            cidr_ip=rule.ip_range
        )

    def _add_rule_on_ec2(self, group_name, rule):
        self.ec2_conn.authorize_security_group(
            group_name=group_name,
            ip_protocol=rule.ip_protocol,
            from_port=rule.from_port,
            to_port=rule.to_port,
            cidr_ip=rule.ip_range
        )
