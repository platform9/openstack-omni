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

class Rule:
    def __init__(self, ip_protocol, from_port, to_port, ip_range=None, group_name=None):
        self.ip_protocol = ip_protocol
        self.from_port = from_port
        self.to_port = to_port
        self.ip_range = ip_range
        self.group_name = group_name

    def __key(self):
        return self.ip_protocol, self.from_port, self.to_port, self.ip_range, self.group_name

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __hash__(self):
        return hash(self.__key())
