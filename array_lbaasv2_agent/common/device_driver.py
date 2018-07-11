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

import netaddr

from oslo_config import cfg
from oslo_utils import importutils
import logging


LOG = logging.getLogger(__name__)
DRIVER_NAME = 'ArrayAPV'

OPTS = [
    cfg.StrOpt(
        'array_management_ip',
        default='192.168.0.200',
        help=("APV IP Addresses")
    ),
    cfg.StrOpt(
        'array_interfaces',
        default='port2',
        help=('APV interfaces')
    ),
    cfg.StrOpt(
        'array_api_user',
        default='restful',
        help=('APV Restful API user')
    ),
    cfg.StrOpt(
        'array_api_password',
        default='click1',
        help=('APV Restful API password')
    ),
    cfg.StrOpt(
        'array_device_driver',
        default=('array_lbaasv2_agent.common.apv_driver.ArrayAPVAPIDriver'),
        help=('The driver used to provision ADC product')
    )
]

cfg.CONF.register_opts(OPTS, 'arraynetworks')


class ArrayADCDriver(object):
    """ The implementation on host to push config to
        APV/AVX instance via RESTful API
    """
    def __init__(self, conf, plugin_rpc, context):
        self.plugin_rpc = plugin_rpc
        self.conf = conf
        self.context = context

        self.hosts = self.conf.arraynetworks.array_management_ip.split(',')[0:2]

        self._load_driver()

    def _load_driver(self):
        self.driver = None

        LOG.debug('loading LBaaS driver %s' % self.conf.arraynetworks.array_device_driver)
        try:
            self.driver = importutils.import_object(
                self.conf.arraynetworks.array_device_driver,
                self.hosts,
                self.conf.arraynetworks.array_interfaces,
                self.conf.arraynetworks.array_api_user,
                self.conf.arraynetworks.array_api_password)
            return
        except ImportError as ie:
            msg = ('Error importing loadbalancer device driver: %s error %s'
                   % (self.conf.arraynetworks.array_device_driver, repr(ie)))
            LOG.error(msg)
            raise SystemExit(msg)

    def create_loadbalancer(self, obj):
        """
        Used to allocate the VIP to loadbalancer
        """
        LOG.debug("Create a loadbalancer on Array ADC device")
        lb = obj
        argu = {}

        port_id = lb['vip_port_id']

        ret_vlan = self.plugin_rpc.get_vlan_id_by_port_cmcc(self.context, port_id)
        vlan_tag = ret_vlan['vlan_tag']
        if vlan_tag == '-1':
            LOG.debug("Cann't get the vlan_tag by port_id(%s)", port_id)
            argu['vlan_tag'] = None
        else:
            LOG.debug("Got the vlan_tag(%s) by port_id(%s)", vlan_tag, port_id)
            argu['vlan_tag'] = vlan_tag

        subnet_id = lb['vip_subnet_id']
        subnet = self.plugin_rpc.get_subnet(self.context, subnet_id)
        member_network = netaddr.IPNetwork(subnet['cidr'])

        interface_mapping = {}
        if len(self.hosts) > 1:
            cnt = 0
            LOG.debug("self.hosts(%s): len(%d)", self.hosts, len(self.hosts))
            for host in self.hosts:
                interfaces = {}
                port_name = '_lb-port-' + str(cnt) + '-'+ subnet_id
                cnt += 1
                port = self.plugin_rpc.create_port_on_subnet(self.context, subnet_id, port_name)
                interfaces['address'] = port['fixed_ips'][0]['ip_address']
                interfaces['port_id'] = port['id']
                interface_mapping[host] = interfaces
        argu['interface_mapping'] = interface_mapping

        argu['tenant_id'] = lb['tenant_id']
        argu['vip_id'] = lb['id']
        argu['vip_address'] = lb['vip_address']
        argu['netmask'] = str(member_network.netmask)
        self.driver.create_loadbalancer(argu)


    def update_loadbalancer(self, obj, old_obj):
        # see: https://wiki.openstack.org/wiki/Neutron/LBaaS/API_2.0#Update_a_Load_Balancer
        LOG.debug("Nothing to do at LB updating")


    def delete_loadbalancer(self, obj):
        LOG.debug("Delete a loadbalancer on Array ADC device")
        lb = obj
        argu = {}

        port_id = lb['vip_port_id']
        ret_vlan = self.plugin_rpc.get_vlan_id_by_port_cmcc(self.context, port_id)
        vlan_tag = ret_vlan['vlan_tag']
        if vlan_tag == '-1':
            LOG.debug("Cann't get the vlan_tag by port_id(%s)", port_id)
            argu['vlan_tag'] = None
        else:
            argu['vlan_tag'] = vlan_tag

        argu['tenant_id'] = lb['tenant_id']
        argu['vip_id'] = lb['id']
        argu['vip_address'] = lb['vip_address']

        if len(self.hosts) > 1:
            LOG.debug("Will delete the port created by ourselves.")
            mapping = self.client.get_cached_map(argu)
            if mapping:
                for host in self.hosts:
                    port_id = mapping[host]
                    self.plugin_rpc.delete_port(self.context, port_id)

        self.driver.delete_loadbalancer(argu)


    def get_stats(self, instance):
        pass


    def create_listener(self, obj):
        listener = obj
        lb = listener['loadbalancer']
        argu = {}

        argu['tenant_id'] = listener['tenant_id']
        argu['connection_limit'] = listener['connection_limit']
        argu['protocol'] = listener['protocol']
        argu['protocol_port'] = listener['protocol_port']
        argu['listener_id'] = listener['id']
        argu['vip_address'] = lb['vip_port']['fixed_ips'][0]['ip_address']

        self.driver.create_listener(argu)


    def update_listener(self, obj, old_obj):
        # see: https://wiki.openstack.org/wiki/Neutron/LBaaS/API_2.0#Update_a_Listener
        # handle the change of "connection_limit" only
        if obj['connection_limit'] != old_obj['connection_limit']:
            # firstly delete this listener, it will cause policy is deleted as well
            self.delete_listener(old_obj)

            # re-create listener and policy
            self.create_listener(obj)


    def delete_listener(self, obj):
        listener = obj
        argu = {}

        argu['tenant_id'] = listener['tenant_id']
        argu['listener_id'] = listener['listener_id']
        argu['protocol'] = listener['protocol']

        self.driver.delete_listener(argu)


    def create_pool(self, obj):
        pool = obj
        sp_type = None
        ck_name = None

        argu = {}

        if pool['session_persistence']:
            sp_type = pool['session_persistence']['type']
            ck_name = pool['session_persistence']['cookie_name']

        argu['tenant_id'] = pool['tenant_id']
        argu['pool_id'] = pool['id']
        argu['listener_id'] = pool['listener_id']
        argu['session_persistence_type'] = sp_type
        argu['cookie_name'] = ck_name
        argu['lb_algorithm'] = pool['lb_algorithm']
        self.driver.create_pool(argu)


    def update_pool(self, obj, old_obj):
        # see: https://wiki.openstack.org/wiki/Neutron/LBaaS/API_2.0#Update_a_Pool
        need_recreate = False
        for changed in ('lb_algorithm', 'session_persistence'):
            if obj[changed] != old_obj[changed]:
                need_recreate = True

        if need_recreate:
            LOG.debug("Need to recreate the pool....")

            # firstly delete old group
            self.delete_pool(old_obj)

            # re-create group
            self.create_pool(obj)

            # re-create members
            for member in obj['members']:
                self.create_member(member)

            # re-create healthmonitor
            if obj['healthmonitor']:
                # FIXME: should directly update the hm
                self.update_health_monitor(obj['healthmonitor'], old_obj['healthmonitor'])

    def delete_pool(self, obj):
        pool = obj

        sp_type = None
        ck_name = None
        argu = {}

        if pool['session_persistence']:
            sp_type = pool['session_persistence']['type']
            ck_name = pool['session_persistence']['cookie_name']

        argu['tenant_id'] = pool['tenant_id']
        argu['pool_id'] = pool['id']
        argu['listener_id'] = pool['listener_id']
        argu['session_persistence_type'] = sp_type
        argu['cookie_name'] = ck_name
        argu['lb_algorithm'] = pool['lb_algorithm']
        self.driver.delete_pool(argu)

    def create_member(self, obj):
        member = obj
        pool = member['pool']
        argu = {}

        argu['tenant_id'] = member['tenant_id']
        argu['member_id'] = member['id']
        argu['member_address'] = member['address']
        argu['member_port'] = member['protocol_port']
        argu['protocol'] = pool['protocol']
        argu['pool_id'] = member['pool_id']
        argu['member_weight'] = member['weight']

        self.driver.create_member(argu)

    def update_member(self, obj, old_obj):
        # see: https://wiki.openstack.org/wiki/Neutron/LBaaS/API_2.0#Update_a_Member_of_a_Pool
        if obj['weight'] != old_obj['weight']:
            # FIXME: should directly update the weight
            self.delete_member(old_obj)
            self.create_member(obj)

    def delete_member(self, obj):
        member = obj
        pool = member['pool']
        argu = {}

        argu['tenant_id'] = member['tenant_id']
        argu['member_id'] = member['id']
        argu['protocol'] = pool['protocol']

        self.driver.delete_member(argu)

    def create_health_monitor(self, obj):
        hm = obj
        argu = {}

        argu['tenant_id'] = hm['tenant_id']
        argu['hm_id'] = hm['id']
        argu['hm_type'] = hm['type']
        argu['hm_delay'] = hm['delay']
        argu['hm_max_retries'] = hm['max_retries']
        argu['hm_timeout'] = hm['timeout']
        argu['hm_http_method'] = hm['http_method']
        argu['hm_url'] = hm['url_path']
        argu['hm_expected_codes'] = hm['expected_codes']
        argu['pool_id'] = hm['pool']['id']
        self.driver.create_health_monitor(argu)

    def update_health_monitor(self, obj, old_obj):
        self.delete_health_monitor(old_obj)
        self.create_health_monitor(obj)

    def delete_health_monitor(self, obj):
        hm = obj
        argu = {}

        argu['tenant_id'] = hm['tenant_id']
        argu['hm_id'] = hm['id']
        argu['pool_id'] = hm['pool']['id']
        self.driver.delete_health_monitor(argu)

