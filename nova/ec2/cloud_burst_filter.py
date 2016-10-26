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

from oslo.config import cfg
from nova import db
from nova.openstack.common import log as logging
from nova.scheduler import filters

opts = [
    cfg.BoolOpt('cloud_burst',
                help='Switch to enable could bursting'),
    cfg.StrOpt('cloud_burst_availability_zone',
                help='The availability zone of only compute hosts with the public cloud driver'),
]
CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

class CloudBurstFilter(filters.BaseHostFilter):
    """Filter for cloud burst availability zone"""

    run_filter_once_per_request = True

    def host_passes(self, host_state, filter_properties):
        context = filter_properties['context'].elevated()
        metadata = db.aggregate_metadata_get_by_host(context, host_state.host, key='availability_zone')

        if CONF.cloud_burst:
                return CONF.cloud_burst_availability_zone in metadata['availability_zone']
        else:
            return CONF.cloud_burst_availability_zone not in metadata['availability_zone']

        return True
