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

from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import registry
from neutron.callbacks import resources
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def subscribe(mech_driver):
    registry.subscribe(mech_driver.secgroup_callback, resources.SECURITY_GROUP,
                       events.BEFORE_DELETE)
    registry.subscribe(mech_driver.secgroup_callback, resources.SECURITY_GROUP,
                       events.BEFORE_UPDATE)
    registry.subscribe(mech_driver.secgroup_callback, resources.SECURITY_GROUP_RULE,
                       events.BEFORE_DELETE)
    registry.subscribe(mech_driver.secgroup_callback, resources.SECURITY_GROUP_RULE,
                       events.BEFORE_UPDATE)
    registry.subscribe(mech_driver.secgroup_callback, resources.SECURITY_GROUP_RULE,
                       events.BEFORE_CREATE)
