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

import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.common import constants

import logging

LOG = logging.getLogger(__name__)

class ArrayPluginApi(object):

    def __init__(self, topic, host):
        super(ArrayPluginApi, self).__init__()
        self.host = host

        target = oslo_messaging.Target(topic=topic, version='1.0',
                                       namespace=constants.RPC_NAMESPACE_STATE)
        self.client = n_rpc.get_client(target)

    def lb_successful_completion(self, context, obj, delete=False,
            lb_create=False):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'lb_successful_completion', obj=obj,
                delete=delete,
                lb_create=lb_create)

    def lb_failed_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'lb_failed_completion', obj=obj)

    def lb_deleting_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'lb_deleting_completion', obj=obj)

    def listener_successful_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'listener_successful_completion', obj=obj)

    def listener_failed_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'listener_failed_completion', obj=obj)

    def listener_deleting_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'listener_deleting_completion', obj=obj)

    def pool_successful_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'pool_successful_completion', obj=obj)

    def pool_failed_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'pool_failed_completion', obj=obj)

    def pool_deleting_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'pool_deleting_completion', obj=obj)

    def member_successful_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'member_successful_completion', obj=obj)

    def member_failed_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'member_failed_completion', obj=obj)

    def member_deleting_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'member_deleting_completion', obj=obj)

    def hm_successful_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'hm_successful_completion', obj=obj)

    def hm_failed_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'hm_failed_completion', obj=obj)

    def hm_deleting_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'hm_deleting_completion', obj=obj)

    def create_port_on_subnet(self, context, subnet_id, name,
            fixed_address_count=1):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_port_on_subnet',
                subnet_id=subnet_id, name=name,
                fixed_address_count=fixed_address_count)

    def get_subnet(self, context, subnet_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_subnet', subnet_id=subnet_id)

    def get_port(self, context, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_port', port_id=port_id)

    def get_loadbalancer(self, context, loadbalancer_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_loadbalancer', loadbalancer_id=loadbalancer_id)

    def delete_port(self, context, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'delete_port', port_id=port_id)

    def get_vlan_id_by_port_cmcc(self, context, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_vlan_id_by_port_cmcc', port_id=port_id)

