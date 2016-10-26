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

class EC2RuleService:

    def __init__(self, ec2_connection, ec2_rule_transformer):
        self.ec2_connection = ec2_connection
        self.ec2_rule_transformer = ec2_rule_transformer

    def get_rules_for_group(self, group_name):
        group = self.ec2_connection.get_all_security_groups(groupnames=group_name)[0]
        return set([self.ec2_rule_transformer.to_rule(rule) for rule in group.rules])
