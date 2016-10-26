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

class InstanceRuleRefresher:

    def __init__(self, group_rule_refresher):
        self.group_rule_refresher = group_rule_refresher

    def refresh(self, instance):
        for group_name in self._get_group_names(instance):
            self.group_rule_refresher.refresh(group_name)

    def _get_group_names(self, instance):
        return [group['name'] for group in instance.security_groups]
