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
import six
import time
import traceback

from neutron_lib import constants as n_const
from array_lbaasv2_agent.common.exceptions import ArrayADCException
from array_lbaasv2_agent.common import ssl_api
from array_lbaasv2_agent.common import nuage_api

from array_lbaasv2_agent.common.constants import PROV_SEGMT_ID
from array_lbaasv2_agent.common.constants import PROV_NET_TYPE

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
        'agent_host',
        help=('Array agent host name')
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
        'segment_config_password',
        default='Array123',
        help=('APV Restful API password')
    ),
    cfg.BoolOpt(
        'bonding',
        default=False,
        help=('Enable bonding in APV')
    ),
    cfg.StrOpt(
        'environment_postfix',
        help='environment postfix if need'
    ),
    cfg.StrOpt(
        'array_device_driver',
        default=('array_lbaasv2_agent.common.avx_driver.ArrayAVXAPIDriver'),
        help=('The driver used to provision ADC product')
    ),
    cfg.StrOpt(
        'sdn_vendor',
        default=('Name of supported SDN Vendor'),
        help=('The driver used to provision ADC product')
    ),
    cfg.BoolOpt(
        'net_seg_enable',
        default=False,
        help=('Enable network segment function')
    )
]

cfg.CONF.register_opts(OPTS, 'arraynetworks')


def get_vlinks_by_policy(policy_id):
    return [policy_id + "_v" + str(idx) for idx in range(1, 3)]


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
                self.conf.arraynetworks.array_api_password,
                self.context,
                self.plugin_rpc)
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
        subnet_id = lb['vip_subnet_id']

        vlan_tag = '-1'
        port_status = None
        argu['vlan_uuid'] = None
        if "huawei" in self.conf.arraynetworks.sdn_vendor:
            LOG.debug("Get the status of vip_port")
            for a in six.moves.xrange(5):
                ret_port = self.plugin_rpc.get_port(self.context, port_id)
                if not ret_port:
                    msg = "Failed to get port by port_id %s" % port_id
                    raise ArrayADCException(msg)
                LOG.debug("ret_port: --%s--", ret_port)
                port_status = ret_port['status']
                if port_status == n_const.PORT_STATUS_ERROR:
                    msg = "Failed to create port by the SDN controller"
                    raise ArrayADCException(msg)
                elif port_status == n_const.PORT_STATUS_BUILD:
                    LOG.debug("The port is still building, so waiting...")
                    time.sleep(3)

            if port_status == n_const.PORT_STATUS_ERROR or \
                port_status == n_const.PORT_STATUS_BUILD:
                msg = "Timeout to create port by the SDN controller"
                raise ArrayADCException(msg)
            ret_vlan = self.plugin_rpc.get_vlan_id_by_port_huawei(self.context, port_id)
        elif "cmcc" in self.conf.arraynetworks.sdn_vendor:
            ret_vlan = self.plugin_rpc.get_vlan_id_by_port_cmcc(self.context, port_id)
        elif "nuage" in self.conf.arraynetworks.sdn_vendor:
            ret_vlan = self.plugin_rpc.get_vlan_by_subnet_id(self.context, subnet_id)
            if ret_vlan['vlan_tag'] and (not ret_vlan['vlan_uuid']):
                res = nuage_api.nuage_allocate_vlan(ret_vlan['vlan_tag'])
                vlan_uuid = res['nuage_gateway_vlan']['id']
                if vlan_uuid:
                    nuage_api.nuage_bind_vlan_to_vport(vlan_uuid, port_id)
                    self.plugin_rpc.update_vlan_uuid_by_subnet(self.context,
                        subnet_id, vlan_uuid)
                argu['vlan_uuid'] = vlan_uuid

        vlan_tag = ret_vlan['vlan_tag']
        if vlan_tag == '-1':
            LOG.debug("Cann't get the vlan_tag by port_id(%s)", port_id)
            argu['vlan_tag'] = None
        else:
            LOG.debug("Got the vlan_tag(%s) by port_id(%s)", vlan_tag, port_id)
            argu['vlan_tag'] = vlan_tag

        subnet = self.plugin_rpc.get_subnet(self.context, subnet_id)
        member_network = netaddr.IPNetwork(subnet['cidr'])

        if not argu['vlan_tag']:
            segment_id = None
            network_type = None
            network = self.plugin_rpc.get_network(self.context, subnet['network_id'])
            if PROV_NET_TYPE in network:
                network_type = network[PROV_NET_TYPE]
            if network_type == 'vlan':
                if PROV_SEGMT_ID in network:
                    segment_id = network[PROV_SEGMT_ID]
                if segment_id:
                    argu['vlan_tag'] = str(segment_id)
                if network_type:
                    argu['network_type'] = network_type

        argu['gateway'] = subnet['gateway_ip']
        argu['subnet_id'] = lb['vip_subnet_id']
        argu['tenant_id'] = lb['tenant_id']
        argu['vip_id'] = lb['id']
        argu['vip_address'] = lb['vip_address']
        argu['netmask'] = str(member_network.netmask)
        if member_network.version == 6:
            idx = subnet['cidr'].find('/')
            argu['netmask'] = subnet['cidr'][idx+1:]
        self.driver.reset_off_host()
        self.driver.create_loadbalancer(argu)


    def update_loadbalancer(self, obj, old_obj):
        # see: https://wiki.openstack.org/wiki/Neutron/LBaaS/API_2.0#Update_a_Load_Balancer
        LOG.debug("Nothing to do at LB updating")


    def delete_loadbalancer(self, obj):
        LOG.debug("Delete a loadbalancer on Array ADC device")
        lb = obj
        argu = {}

        port_id = lb['vip_port_id']
        ret_vlan = self.plugin_rpc.get_vlan_id_by_port_huawei(self.context, port_id)
        vlan_tag = ret_vlan['vlan_tag']
        if vlan_tag == '-1':
            LOG.debug("Cann't get the vlan_tag by port_id(%s)", port_id)
            argu['vlan_tag'] = None
        else:
            argu['vlan_tag'] = vlan_tag

        argu['tenant_id'] = lb['tenant_id']
        argu['vip_id'] = lb['id']
        argu['vip_address'] = lb['vip_address']
        argu['subnet_id'] = lb['vip_subnet_id']

        if not argu['vlan_tag']:
            segment_id = None
            network_type = None
            network = self.plugin_rpc.get_network(self.context, lb['vip_port']['network_id'])
            if PROV_NET_TYPE in network:
                network_type = network[PROV_NET_TYPE]
            if 'vlan' == network_type:
                if PROV_SEGMT_ID in network:
                    segment_id = network[PROV_SEGMT_ID]
                if segment_id:
                    argu['vlan_tag'] = str(segment_id)
                if network_type:
                    argu['network_type'] = network_type

        self.driver.reset_off_host()
        self.driver.delete_loadbalancer(argu)


    def get_stats(self, instance):
        pass


    def create_listener(self, obj, updated=False):
        LOG.debug("Create a listener on Array ADC device")
        listener = obj
        lb = listener['loadbalancer']
        argu = {}

        argu['tenant_id'] = listener['tenant_id']
        argu['connection_limit'] = listener['connection_limit']
        argu['protocol'] = listener['protocol']
        argu['protocol_port'] = listener['protocol_port']
        argu['listener_id'] = listener['id']
        argu['vip_address'] = lb['vip_port']['fixed_ips'][0]['ip_address']
        argu['vip_id'] = lb['stats']['loadbalancer_id']

        try:
            argu['redirect_up'] = listener['redirect_up']
            argu['redirect_protocol'] = listener['redirect_protocol']
            argu['redirect_port'] = listener['redirect_port']
        except KeyError:
            argu['redirect_up'] = False

        try:
            argu['bandwidth'] = lb['bandwidth']
        except KeyError:
            argu['bandwidth'] = 0

        pool = listener['default_pool']

        if pool:
            sp_type = None
            ck_name = None
            argu['pool_id'] = pool['id']
            if pool['session_persistence']:
                sp_type = pool['session_persistence']['type']
                ck_name = pool['session_persistence']['cookie_name']
            argu['lb_algorithm'] = pool['lb_algorithm']
            argu['session_persistence_type'] = sp_type
            argu['cookie_name'] = ck_name
        else:
            argu['pool_id'] = None

        if not updated:
            self.driver.reset_off_host()

        self.driver.create_listener(argu)

        if listener['protocol'] == 'TERMINATED_HTTPS':
            if listener['default_tls_container_id']:
                va_name = self.driver.get_va_name(argu)
                ssl_api.config_server_ssls(self.driver, listener, va_name)
                try:
                    if listener['mutual_authentication_up']:
                        ssl_api.config_client_ssl(self.driver, listener, va_name)
                except KeyError as e:
                    LOG.debug("It fails to parse mutual_authentication_up: %s", e.message)
                except Exception as e:
                    LOG.debug("Trace: %s " % traceback.format_exc())
                    LOG.debug("Failed to config client ssl %s" % e.message)

        if not updated:
            self.driver.write_memory(argu)


    def update_listener(self, obj, old_obj):
        # see: https://wiki.openstack.org/wiki/Neutron/LBaaS/API_2.0#Update_a_Listener
        # handle the change of "connection_limit" only
        LOG.debug("Update a listener on Array ADC device")
        if obj['connection_limit'] != old_obj['connection_limit']:
            # firstly delete this listener, it will cause policy is deleted as well
            self.driver.reset_off_host()

            self.delete_listener(old_obj, updated=True)

            self.create_listener(obj, updated=True)
            listener = obj
            argu = {}
            argu['tenant_id'] = listener['tenant_id']
            lb = listener['loadbalancer']
            argu['vip_id'] = lb['stats']['loadbalancer_id']
            self.driver.write_memory(argu)


    def delete_listener(self, obj, updated=False):
        LOG.debug("Delete a listener on Array ADC device")
        listener = obj
        argu = {}

        argu['tenant_id'] = listener['tenant_id']
        argu['listener_id'] = listener['id']
        argu['protocol'] = listener['protocol']
        argu['protocol_port'] = listener['protocol_port']

        lb = listener['loadbalancer']
        argu['vip_id'] = lb['stats']['loadbalancer_id']

        try:
            argu['redirect_up'] = listener['redirect_up']
            argu['redirect_protocol'] = listener['redirect_protocol']
            argu['redirect_port'] = listener['redirect_port']
        except KeyError:
            argu['redirect_up'] = False

        pool = listener['default_pool']
        if pool:
            sp_type = None
            argu['pool_id'] = pool['id']
            if pool['session_persistence']:
                sp_type = pool['session_persistence']['type']
            argu['lb_algorithm'] = pool['lb_algorithm']
            argu['session_persistence_type'] = sp_type
        else:
            argu['pool_id'] = None

        if not updated:
            self.driver.reset_off_host()

        if listener['protocol'] == 'TERMINATED_HTTPS':
            if listener['default_tls_container_id']:
                va_name = self.driver.get_va_name(argu)
                ssl_api.clear_server_ssls(self.driver, listener, va_name)
                try:
                    if listener['mutual_authentication_up']:
                        ssl_api.clear_client_ssl(self.driver, listener, va_name)
                except KeyError as e:
                    LOG.debug("It fails to parse mutual_authentication_up: %s", e.message)
                except Exception as e:
                    LOG.debug("Trace: %s " % traceback.format_exc())
                    LOG.debug("Failed to config client ssl %s" % e.message)

        self.driver.delete_listener(argu)

        if not updated:
            self.driver.write_memory(argu)


    def create_pool(self, obj, updated=False):
        LOG.debug("Create a pool on Array ADC device")
        pool = obj
        sp_type = None
        ck_name = None

        argu = {}

        if pool['session_persistence']:
            sp_type = pool['session_persistence']['type']
            ck_name = pool['session_persistence']['cookie_name']

        argu['tenant_id'] = pool['tenant_id']
        argu['pool_id'] = pool['id']
        argu['session_persistence_type'] = sp_type
        argu['cookie_name'] = ck_name
        argu['lb_algorithm'] = pool['lb_algorithm']

        lb = pool['loadbalancer']
        argu['vip_id'] = lb['stats']['loadbalancer_id']

        listener = pool['listener']
        if listener:
            argu['listener_id'] = listener['id']
        else:
            argu['listener_id'] = None

        if not updated:
            self.driver.reset_off_host()
        self.driver.create_pool(argu)
        if not updated:
            self.driver.write_memory(argu)


    def update_pool(self, obj, old_obj):
        # see: https://wiki.openstack.org/wiki/Neutron/LBaaS/API_2.0#Update_a_Pool
        LOG.debug("Update a pool on Array ADC device")
        need_recreate = False
        for changed in ('lb_algorithm', 'session_persistence'):
            if obj[changed] != old_obj[changed]:
                need_recreate = True

        argu = {}
        if need_recreate:
            LOG.debug("Need to recreate the pool....")

            argu['pool_id'] = obj['id']
            lb = obj['loadbalancer']
            argu['vip_id'] = lb['stats']['loadbalancer_id']
            self.driver.reset_off_host()
            # firstly delete old group
            self.delete_pool(old_obj, updated=True)

            # re-create group
            self.create_pool(obj, updated=True)

            # re-create members
            for member in obj['members']:
                argu['member_id'] = member['id']
                argu['member_weight'] = member['weight']
                self.driver.update_member(argu)

            # re-create healthmonitor
            hm = obj['healthmonitor']
            if hm:
                argu['hm_id'] = hm['id']
                self.driver.update_health_monitor(argu)

            # update L7 policy
            listener = obj['listener']
            if listener:
                for policy in listener['l7_policies']:
                    self.create_l7policy(policy, updated=True)
                    if policy['rules']:
                        self.delete_all_rules(policy)
                        self.create_all_rules(policy)

            self.driver.write_memory(argu)

    def delete_pool(self, obj, updated=False):
        LOG.debug("Delete a pool on Array ADC device")
        pool = obj

        sp_type = None
        ck_name = None
        argu = {}

        if pool['session_persistence']:
            sp_type = pool['session_persistence']['type']
            ck_name = pool['session_persistence']['cookie_name']

        argu['tenant_id'] = pool['tenant_id']
        argu['pool_id'] = pool['id']
        argu['session_persistence_type'] = sp_type
        argu['cookie_name'] = ck_name
        argu['lb_algorithm'] = pool['lb_algorithm']

        lb = pool['loadbalancer']
        argu['vip_id'] = lb['stats']['loadbalancer_id']

        listener = pool['listener']
        if listener:
            argu['listener_id'] = listener['id']
        else:
            argu['listener_id'] = None

        if not updated:
            self.driver.reset_off_host()
        self.driver.delete_pool(argu)
        if not updated:
            self.driver.write_memory(argu)

    def create_member(self, obj):
        LOG.debug("Create a member on Array ADC device")
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

        argu['vip_id'] = member['pool']['loadbalancer_id']
        argu['subnet_id'] = member['subnet_id']

        subnet = self.plugin_rpc.get_subnet(self.context, argu['subnet_id'])
        member_network = netaddr.IPNetwork(subnet['cidr'])
        argu['netmask'] = str(member_network.netmask)
        argu['gateway'] = subnet['gateway_ip']
        if member_network.version == 6:
            idx = subnet['cidr'].find('/')
            argu['netmask'] = subnet['cidr'][idx+1:]

        self.driver.reset_off_host()
        self.driver.create_member(argu)
        self.driver.write_memory(argu)

    def update_member(self, obj, old_obj):
        LOG.debug("Update a member on Array ADC device")
        # see: https://wiki.openstack.org/wiki/Neutron/LBaaS/API_2.0#Update_a_Member_of_a_Pool
        if obj['weight'] != old_obj['weight']:
            # FIXME: should directly update the weight
            self.driver.reset_off_host()
            self.delete_member(old_obj)
            self.create_member(obj)

    def delete_member(self, obj):
        LOG.debug("Delete a member on Array ADC device")
        member = obj
        pool = member['pool']
        argu = {}

        argu['tenant_id'] = member['tenant_id']
        argu['member_id'] = member['id']
        argu['protocol'] = pool['protocol']
        argu['member_port'] = member['protocol_port']

        argu['vip_id'] = member['pool']['loadbalancer_id']
        argu['subnet_id'] = member['subnet_id']
        argu['member_address'] = member['address']

        subnet = self.plugin_rpc.get_subnet(self.context, argu['subnet_id'])
        argu['gateway'] = subnet['gateway_ip']

        members = member['pool']['members']
        #members count in same subnet
        num_mem_same_ip = 0
        for mem in members:
            if mem['address'] == argu['member_address']:
                num_mem_same_ip += 1
        argu['num_of_mem'] = num_mem_same_ip
        self.driver.reset_off_host()
        self.driver.delete_member(argu)
        self.driver.write_memory(argu)

    def create_health_monitor(self, obj):
        LOG.debug("Create a hm on Array ADC device")
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
        argu['vip_id'] = hm['pool']['loadbalancer_id']
        self.driver.reset_off_host()
        self.driver.create_health_monitor(argu)
        self.driver.write_memory(argu)

    def update_health_monitor(self, obj, old_obj):
        LOG.debug("Update a hm on Array ADC device")
        need_recreate = False
        for changed in ('delay', 'timeout', 'max_retries', 'http_method', 'url_path', 'expected_codes'):
            if obj[changed] != old_obj[changed]:
                need_recreate = True

        if need_recreate:
            self.driver.reset_off_host()
            self.delete_health_monitor(old_obj)
            self.create_health_monitor(obj)

    def delete_health_monitor(self, obj):
        LOG.debug("Delete a hm on Array ADC device")
        hm = obj
        argu = {}

        argu['tenant_id'] = hm['tenant_id']
        argu['hm_id'] = hm['id']
        argu['pool_id'] = hm['pool']['id']
        argu['vip_id'] = hm['pool']['loadbalancer_id']
        self.driver.reset_off_host()
        self.driver.delete_health_monitor(argu)
        self.driver.write_memory(argu)

    def create_l7rule(self, rule):
        LOG.debug("Create a L7RULE on Array ADC device")
        argu = {}
        policy = rule['policy']

        argu['tenant_id'] = rule['tenant_id']
        argu['vip_id'] = policy['listener']['loadbalancer_id']
        self.driver.reset_off_host()
        LOG.debug("Delete all rules from policy in create_l7_rule")
        self.delete_all_rules(policy)
        LOG.debug("Create all rules from policy in create_l7_rule")
        self.create_all_rules(policy)
        self.driver.write_memory(argu)


    def update_l7rule(self, rule, old_rule):
        LOG.debug("Update a L7RULE on Array ADC device")
        argu = {}
        argu = {}
        need_recreate = False
        policy_changed = False
        for changed in ('type', 'compare_type', 'l7policy_id', 'key', 'value'):
            if rule[changed] != old_rule[changed]:
                need_recreate = True

        if not need_recreate:
            LOG.debug("It doesn't need do any thing(update_l7_rule)")
            return

        argu['tenant_id'] = rule['tenant_id']
        if rule['l7policy_id'] != old_rule['l7policy_id']:
            policy_changed = True

        old_policy = old_rule['policy']
        policy = rule['policy']
        if policy_changed or need_recreate:
            self.driver.reset_off_host()
            LOG.debug("Delete all rules from old policy in update_l7_rule")
            self.delete_all_rules(old_policy)
            if policy_changed:
                LOG.debug("Delete all rules from new policy in update_l7_rule")
                self.delete_all_rules(policy)

            LOG.debug("Create all rules from new policy in update_l7_rule")
            self.create_all_rules(policy)
            if policy_changed:
                LOG.debug("Create all rules from old policy in update_l7_rule")
                self.create_all_rules(old_policy)
            argu['vip_id'] = policy['listener']['loadbalancer_id']
            self.driver.write_memory(argu)

    def delete_l7rule(self, rule):
        LOG.debug("Delete a L7RULE on Array ADC device")
        argu = {}
        policy = rule['policy']

        argu['tenant_id'] = rule['tenant_id']
        argu['vip_id'] = policy['listener']['loadbalancer_id']
        self.driver.reset_off_host()
        LOG.debug("Delete all rules from policy in delete_l7_rule")
        self.delete_all_rules(policy)
        LOG.debug("Create all rules from policy in delete_l7_rule")
        self.create_all_rules(policy, filt=rule['id'])
        self.driver.write_memory(argu)


    def create_l7policy(self, policy, updated=False):
        LOG.debug("Create a L7Policy on Array ADC device")
        argu = {}

        listener = policy['listener']
        argu['tenant_id'] = policy['tenant_id']
        argu['action'] = policy['action']
        argu['id'] = policy['id']
        argu['listener_id'] = policy['listener_id']
        argu['pool_id'] = policy['redirect_pool_id']
        argu['position'] = policy['position']
        argu['redirect_url'] = policy['redirect_url']
        argu['vip_id'] = listener['loadbalancer_id']

        sp_type = None
        ck_name = None
        pool = policy['redirect_pool']
        if pool:
            if pool['session_persistence']:
                sp_type = pool['session_persistence']['type']
                ck_name = pool['session_persistence']['cookie_name']
            argu['session_persistence_type'] = sp_type
            argu['cookie_name'] = ck_name
            argu['lb_algorithm'] = pool['lb_algorithm']

        if not updated:
            self.driver.reset_off_host()
        self.driver.create_l7_policy(argu, updated=updated)
        if not updated:
            self.driver.write_memory(argu)


    def update_l7policy(self, policy, old_policy):
        LOG.debug("Update a L7Policy on Array ADC device")
        need_recreate = False
        for changed in ('action', 'redirect_pool_id', 'redirect_url'):
            if policy[changed] != old_policy[changed]:
                need_recreate = True

        if not need_recreate:
            LOG.debug("It doesn't need do any thing(update_l7_policy)")
            return

        argu = {}
        argu['tenant_id'] = policy['tenant_id']
        argu['vip_id'] = policy['listener']['loadbalancer_id']
        self.driver.reset_off_host()
        self.delete_l7policy(old_policy, updated=True)
        self.create_l7policy(policy, updated=True)

        self.create_all_rules(policy)
        self.driver.write_memory(argu)


    def delete_l7policy(self, policy, updated=False):
        LOG.debug("Delete a L7Policy on Array ADC device")
        argu = {}
        listener = policy['listener']
        argu['tenant_id'] = policy['tenant_id']
        argu['action'] = policy['action']
        argu['id'] = policy['id']
        argu['listener_id'] = policy['listener_id']
        argu['pool_id'] = policy['redirect_pool_id']
        argu['vip_id'] = listener['loadbalancer_id']

        sp_type = None
        pool = policy['redirect_pool']
        if pool:
            pool = policy['redirect_pool']
            if pool['session_persistence']:
                sp_type = pool['session_persistence']['type']
            argu['session_persistence_type'] = sp_type
            argu['lb_algorithm'] = pool['lb_algorithm']

        if not updated:
            self.driver.reset_off_host()

        LOG.debug("Delete all rules from policy in delete_l7_policy")
        self.delete_all_rules(policy)

        self.driver.delete_l7_policy(argu, updated=updated)
        if not updated:
            self.driver.write_memory(argu)


    def delete_all_rules(self, policy):
        argu = {}
        rules = policy['rules']
        listener = policy['listener']

        argu['vip_id'] = listener['loadbalancer_id']
        argu['tenant_id'] = policy['tenant_id']
        for rule in rules:
            argu['rule_type'] = rule['type']
            argu['rule_id'] = rule['id']
            self.driver.delete_l7_rule(argu)

    def create_all_rules(self, policy, filt = None):
        argu = {}
        rules = policy['rules']
        listener = policy['listener']

        idx = 0
        cnt = len(rules)
        if filt:
            for rule in rules:
                if rule['id'] == filt:
                    break
                idx += 1
            if cnt > idx:
                del rules[idx]
                cnt -= 1

        argu['vip_id'] = listener['loadbalancer_id']
        argu['vs_id'] = policy['listener_id']
        argu['tenant_id'] = policy['tenant_id']
        argu['action'] = policy['action']
        argu['redirect_url'] = policy['redirect_url']
        if policy['redirect_pool']:
            argu['group_id'] = policy['redirect_pool']['id']
        else:
            argu['group_id'] = policy['listener']['default_pool_id']
            if not argu['group_id']:
                pools = listener['loadbalancer']['pools']
                if not pools:
                    msg = "It should create pool before creating l7rule"
                    raise ArrayADCException(msg)
                argu['group_id'] = pools[0]['id']

        if cnt == 0:
            LOG.debug("No any rule needs to be created.")
        elif cnt == 1:
            rule = rules[0]
            argu['rule_invert'] = rule['invert']
            argu['rule_type'] = rule['type']
            argu['compare_type'] = rule['compare_type']
            argu['rule_id'] = rule['id']
            argu['rule_value'] = rule['value']
            argu['rule_key'] = rule['key']
            self.driver.create_l7_rule(argu, action_created=True)
        elif cnt == 2 or cnt == 3:
            created = False
            vlinks = get_vlinks_by_policy(policy['id'])
            for rule_idx in range(cnt):
                rule = rules[rule_idx]

                argu['rule_invert'] = rule['invert']
                argu['rule_type'] = rule['type']
                argu['compare_type'] = rule['compare_type']
                argu['rule_id'] = rule['id']
                argu['rule_value'] = rule['value']
                argu['rule_key'] = rule['key']
                if rule_idx == 0:
                    argu['group_id'] = vlinks[0]
                elif rule_idx == (cnt - 1):
                    created = True
                    if policy['redirect_pool']:
                        argu['group_id'] = policy['redirect_pool']['id']
                    else:
                        argu['group_id'] = policy['listener']['default_pool_id']
                        if not argu['group_id']:
                            pools = listener['loadbalancer']['pools']
                            if not pools:
                                msg = "It should create pool before creating l7rule"
                                raise ArrayADCException(msg)
                            argu['group_id'] = pools[0]['id']
                    if cnt == 2:
                        argu['vs_id'] = vlinks[0];
                    else:
                        argu['vs_id'] = vlinks[1];
                else:
                    argu['group_id'] = vlinks[1]
                    argu['vs_id'] = vlinks[0];
                self.driver.create_l7_rule(argu, action_created=created)
        else:
            LOG.debug("It doesn't support to create more than three rule in one policy.")
