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

from copy import deepcopy
from rule import Rule


class EC2RuleTransformer:

    def __init__(self, ec2_connection):
        self.ec2_connection = ec2_connection

    def to_rule(self, ec2_rule):
        rule_args = {}
        rule_args['ip_protocol'] = ec2_rule.ip_protocol
        rule_args['from_port'] = ec2_rule.from_port
        rule_args['to_port'] = ec2_rule.to_port

        if ec2_rule.grants[0].cidr_ip:
            rule_args['ip_range'] = ec2_rule.grants[0].cidr_ip
        else:
            group_id = ec2_rule.grants[0].group_id
            rule_args['group_name'] = self.ec2_connection.get_all_security_groups(group_ids=group_id)[0].name

        return Rule(**rule_args)
