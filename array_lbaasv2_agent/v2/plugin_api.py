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

    def l7rule_successful_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'l7rule_successful_completion', obj=obj)

    def l7rule_failed_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'l7rule_failed_completion', obj=obj)

    def l7rule_deleting_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'l7rule_deleting_completion', obj=obj)

    def l7policy_successful_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'l7policy_successful_completion', obj=obj)

    def l7policy_failed_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'l7policy_failed_completion', obj=obj)

    def l7policy_deleting_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'l7policy_deleting_completion', obj=obj)

    def hm_successful_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'hm_successful_completion', obj=obj)

    def hm_failed_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'hm_failed_completion', obj=obj)

    def hm_deleting_completion(self, context, obj):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'hm_deleting_completion', obj=obj)

    def create_port_on_subnet(self, context, subnet_id, name, host,
            device_id, fixed_address_count=1):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_port_on_subnet',
                subnet_id=subnet_id, name=name, host=host,
                device_id=device_id,
                fixed_address_count=fixed_address_count)

    def get_subnet(self, context, subnet_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_subnet', subnet_id=subnet_id)

    def get_network(self, context, network_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_network', network_id=network_id)

    def get_port(self, context, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_port', port_id=port_id)

    def get_loadbalancer(self, context, loadbalancer_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_loadbalancer', loadbalancer_id=loadbalancer_id)

    def delete_port(self, context, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'delete_port', port_id=port_id)

    def delete_port_by_name(self, context, port_name):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'delete_port_by_name', port_name=port_name)

    def get_vlan_id_by_port_cmcc(self, context, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_vlan_id_by_port_cmcc', port_id=port_id)

    def get_vlan_id_by_port_huawei(self, context, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_vlan_id_by_port_huawei', port_id=port_id)

    def scrub_dead_agents(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'scrub_dead_agents')

    def generate_vapv(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'generate_vapv')

    def generate_tags(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'generate_tags')

    def generate_ha_group_id(self, context, lb_id, subnet_id,
        tenant_id, segment_name):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'generate_ha_group_id',
            lb_id=lb_id, subnet_id=subnet_id,
            tenant_id=tenant_id, segment_name=segment_name)

    def get_vlan_by_subnet_id(self, context, subnet_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_vlan_by_subnet_id', subnet_id=subnet_id)

    def get_segment_name_by_lb_id(self, context, vip_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_segment_name_by_lb_id', vip_id=vip_id)

    def get_va_name_by_lb_id(self, context, vip_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_va_name_by_lb_id', vip_id=vip_id)

    def get_vapv_by_lb_id(self, context, vip_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_vapv_by_lb_id', vip_id=vip_id)

    def get_loadbalancer_ids(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_loadbalancer_ids')

    def create_vapv(self, context, vapv_name, lb_id, subnet_id,
        in_use_lb, pri_port_id, sec_port_id, cluster_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_vapv', vapv_name=vapv_name,
            lb_id=lb_id, subnet_id=subnet_id, pri_port_id=pri_port_id,
            sec_port_id=sec_port_id, in_use_lb=in_use_lb,
            cluster_id=cluster_id)

    def get_port_by_name(self, context, port_name):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_port_by_name', port_name=port_name)

    def delete_vapv(self, context, vapv_name):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'delete_vapv', vapv_name=vapv_name)

    def get_active_agents(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_active_agents')

    def update_member_status(self, context, member_id, operating_status):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_member_status',
            member_id=member_id, operating_status=operating_status)

    def check_subnet_used(self, context, subnet_id,
        lb_id_filter=None, member_id_filter=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'check_subnet_used', subnet_id=subnet_id,
            lb_id_filter=lb_id_filter, member_id_filter=member_id_filter)

    def get_segment_used(self, context, segment_name, lb_id_filter=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_segment_used', segment_name=segment_name,
            lb_id_filter=lb_id_filter)

    def get_members_status_on_agent(self, context, agent_host_name):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_members_status_on_agent',
            agent_host_name=agent_host_name)

    def get_clusterids_by_lb(self, context, lb_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_cluster_id_by_lb_id',
            lb_id=lb_id)

    def get_available_internal_ip(self, context, segment_name, segment_ip, use_for_nat=False):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_available_internal_ip',
            seg_name=segment_name, seg_ip=segment_ip, use_for_nat=use_for_nat)

    def get_internal_ip_by_lb(self, context, segment_name, segment_ip, use_for_nat=False):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_internal_ip_by_lb',
            seg_name=segment_name, seg_ip=segment_ip, use_for_nat=use_for_nat)

    def get_interface(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_interface')

    def get_interface_port(self, context, bond):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_interface_port', bond=bond)

    def get_all_interfaces(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_all_interfaces')

