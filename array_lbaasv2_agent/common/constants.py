#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from neutron_lbaas.services.loadbalancer import constants as lb_const
try:
    from neutron_lib import constants as plugin_const
except Exception:
    from neutron.common import constants as plugin_const

TOPIC_PROCESS_ON_HOST_V2 = 'array-lbaasv2-process-on-controller'
TOPIC_LOADBALANCER_AGENT_V2 = 'array-lbaasv2-process-on-agent'

AGENT_BINARY_NAME = 'array-lbaasv2-agent'
ARRAY_ERROR = plugin_const.ERROR
ARRAY_AGENT_TYPE_LOADBALANCERV2 = lb_const.AGENT_TYPE_LOADBALANCERV2

RPC_API_VERSION = '1.0'
