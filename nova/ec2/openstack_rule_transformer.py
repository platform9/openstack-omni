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


class OpenstackRuleTransformer:
    def to_rule(self, openstack_rule):
        rule_args = {}
        rule_args['ip_protocol'] = openstack_rule['ip_protocol']
        rule_args['from_port'] = str(openstack_rule['from_port'])
        rule_args['to_port'] = str(openstack_rule['to_port'])

        if 'cidr' in openstack_rule['ip_range']:
            rule_args['ip_range'] = openstack_rule['ip_range']['cidr']
        else:
            rule_args['group_name'] = openstack_rule['group']['name']

        return Rule(**rule_args)
