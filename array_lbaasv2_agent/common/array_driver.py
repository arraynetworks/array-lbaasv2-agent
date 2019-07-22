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

import json
import six
import time
import requests

from oslo_log import log as logging
from oslo_config import cfg

from neutron_lbaas.services.loadbalancer import constants as lb_const
from array_lbaasv2_agent.common.adc_device import ADCDevice
from array_lbaasv2_agent.common import exceptions as driver_except

LOG = logging.getLogger(__name__)

HA_GROUP_ID = 1

def get_cluster_id_from_va_name(va_name):
    idx=va_name.find('va')
    return int(va_name[idx+2:])


def get_vlinks_by_policy(policy_id):
    return [policy_id + "_v" + str(idx) for idx in range(1, 3)]


class ArrayCommonAPIDriver(object):
    """ The real implementation on host to push config to
        Array appliance instance via RESTful API
    """

    def __init__(self, in_interface, user_name, user_passwd, context, plugin_rpc):
        self.user_name = user_name
        self.user_passwd = user_passwd
        self.in_interface = in_interface
        self.context = context
        self.plugin_rpc = plugin_rpc


    def get_auth(self):
        return (self.user_name, self.user_passwd)


    def create_loadbalancer(self, argu):
        """ create a loadbalancer """
        if not argu:
            LOG.error("In create_loadbalancer, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        pri_port_id = None
        sec_port_id = None
        # create vip
        if len(self.hostnames) == 1:
            self._create_vip(self.base_rest_urls, argu['vip_address'],
                argu['netmask'], argu['vlan_tag'], argu['gateway'], va_name)
        else:
            interface_mapping = argu['interface_mapping']
            unit_list = []
            pool_name = "pool_" + argu['vip_id']
            for idx, host in enumerate(self.hostnames):
                unit_item = {}
                ip_address = interface_mapping[host]['address']
                unit_item['ip_address'] = ip_address
                if idx == 0:
                    unit_item['priority'] = 100
                    unit_item['name'] = argu['vip_id'][:6] + '_p'
                    pri_port_id = interface_mapping[host]['port_id']
                elif idx == 1:
                    sec_port_id = interface_mapping[host]['port_id']
                    unit_item['name'] = argu['vip_id'][:6] + '_s'
                    unit_item['priority'] = 90
                base_rest_url = self.base_rest_urls[idx]
                self._create_vip(base_rest_url, ip_address, argu['netmask'],
                    argu['vlan_tag'], argu['gateway'], va_name)
                unit_list.append(unit_item)
            for base_rest_url in self.base_rest_urls:
                self.configure_ha(base_rest_url, unit_list,
                    argu['vip_address'], argu['vlan_tag'],
                    pool_name, argu['pool_address'], va_name)

        self.plugin_rpc.create_vapv(self.context, va_name, argu['vip_id'],
            argu['subnet_id'], in_use_lb=1, pri_port_id=pri_port_id,
            sec_port_id=sec_port_id)


    def delete_loadbalancer(self, argu):
        """ Delete a loadbalancer """
        if not argu:
            LOG.error("In delete_loadbalancer, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        # delete vip
        self._delete_vip(argu['vlan_tag'], va_name)

        # clear the HA configuration
        if len(self.hostnames) > 1:
            unit_list = []
            for idx, host in enumerate(self.hostnames):
                unit_item = {}
                if idx == 0:
                    unit_item['name'] = argu['vip_id'][:6] + '_p'
                elif idx == 1:
                    unit_item['name'] = argu['vip_id'][:6] + '_s'
                unit_list.append(unit_item)
            for base_rest_url in self.base_rest_urls:
                self.clear_ha(base_rest_url, unit_list, argu['vip_address'], va_name)

            vapv = self.plugin_rpc.get_vapv_by_lb_id(self.context, argu['vip_id'])
            pool_port_name = argu['vip_id'] + "_pool"
            self.plugin_rpc.delete_port_by_name(self.context, pool_port_name)
            self.plugin_rpc.delete_port(self.context, vapv['pri_port_id'])
            self.plugin_rpc.delete_port(self.context, vapv['sec_port_id'])

        # Delete the apv from database
        self.plugin_rpc.delete_vapv(self.context, va_name)

    def create_listener(self, argu):
        """ create a listener """
        if not argu:
            LOG.error("In create_listener, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        # create vs
        self._create_vs(argu['listener_id'], argu['vip_address'], argu['protocol'],
                        argu['protocol_port'], argu['connection_limit'], va_name)

        if argu['pool_id']:
            self._create_policy(argu['pool_id'], argu['listener_id'],
                                argu['session_persistence_type'], argu['lb_algorithm'],
                                argu['cookie_name'], va_name)


    def delete_listener(self, argu):
        """ Delete VIP in lb_delete_vip """

        if not argu:
            LOG.error("In delete_listener, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        # delete vs
        self._delete_vs(argu['listener_id'], argu['protocol'],
            argu['protocol_port'], va_name)

        if argu['pool_id']:
            self._delete_policy(argu['listener_id'], argu['session_persistence_type'],
                                argu['lb_algorithm'], va_name)


    def _create_vip(self, base_rest_urls, vip_address, netmask, vlan_tag, gateway, va_name):
        """ create vip"""

        cmd_apv_config_vlan = None
        in_interface = self.get_va_interface()
        interface_name = in_interface

        cmd_bond_interfaces = []
        if cfg.CONF.arraynetworks.bonding:
            cmd_bond_interfaces = ADCDevice.bond_interface()

        LOG.debug("Configure the vip address into interface")
        if vlan_tag:
            interface_name = "vlan." + vlan_tag
            cmd_apv_config_vlan = ADCDevice.vlan_device(in_interface, interface_name, vlan_tag)

        cmd_apv_config_ip = ADCDevice.configure_ip(interface_name, vip_address, netmask)
        cmd_apv_config_route = ADCDevice.configure_route(gateway)

        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                for cli in cmd_bond_interfaces:
                    self.run_cli_extend(base_rest_url, cli, va_name)
                if vlan_tag:
                    self.run_cli_extend(base_rest_url, cmd_apv_config_vlan, va_name)
                self.run_cli_extend(base_rest_url, cmd_apv_config_ip, va_name)
                self.run_cli_extend(base_rest_url, cmd_apv_config_route, va_name)
        else:
            for cli in cmd_bond_interfaces:
                self.run_cli_extend(base_rest_urls, cli, va_name)
            if vlan_tag:
                self.run_cli_extend(base_rest_urls, cmd_apv_config_vlan, va_name)
            self.run_cli_extend(base_rest_urls, cmd_apv_config_ip, va_name)
            self.run_cli_extend(base_rest_urls, cmd_apv_config_route, va_name)


    def _delete_vip(self, vlan_tag, va_name):
        cmd_apv_no_vlan_device = None
        interface_name = self.get_va_interface()

        cmd_no_bond_interfaces = []
        if cfg.CONF.arraynetworks.bonding:
            cmd_no_bond_interfaces = ADCDevice.no_bond_interface()

        if vlan_tag:
            interface_name = "vlan." + vlan_tag
            cmd_apv_no_vlan_device = ADCDevice.no_vlan_device(interface_name)

        LOG.debug("no the vip address into interface")
        cmd_apv_no_ip = ADCDevice.no_ip(interface_name)
        cmd_clear_config_all = ADCDevice.clear_config_all()

        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_no_ip, va_name)
            if vlan_tag:
                self.run_cli_extend(base_rest_url, cmd_apv_no_vlan_device, va_name)
            if cmd_no_bond_interfaces:
                for cli in cmd_no_bond_interfaces:
                    self.run_cli_extend(base_rest_url, cli, va_name)
            self.run_cli_extend(base_rest_url, cmd_clear_config_all, va_name,
                connect_timeout=60, read_timeout=60)


    def _create_vs(self,
                   listener_id,
                   vip_address,
                   protocol,
                   protocol_port,
                   connection_limit,
                   va_name):

        cmd_apv_create_vs = ADCDevice.create_virtual_service(
                                                             listener_id,
                                                             vip_address,
                                                             protocol_port,
                                                             protocol,
                                                             connection_limit
                                                            )
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_create_vs, va_name)


    def _delete_vs(self, listener_id, protocol, port, va_name):
        cmd_apv_no_vs = ADCDevice.no_virtual_service(listener_id,
            protocol, port)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_no_vs, va_name)


    def _create_policy(self,
                       pool_id,
                       listener_id,
                       session_persistence_type,
                       lb_algorithm,
                       cookie_name,
                       va_name):
        """ Create SLB policy """

        cmd_apv_create_policy = ADCDevice.create_policy(
                                                        listener_id,
                                                        pool_id,
                                                        lb_algorithm,
                                                        session_persistence_type,
                                                        cookie_name
                                                       )

        for base_rest_url in self.base_rest_urls:
            for cli in cmd_apv_create_policy:
                self.run_cli_extend(base_rest_url, cli, va_name, connect_timeout=60, read_timeout=60)


    def _delete_policy(self, listener_id, session_persistence_type, lb_algorithm, va_name):
        """ Delete SLB policy """
        cmd_apv_no_policy = ADCDevice.no_policy(
                                                listener_id,
                                                lb_algorithm,
                                                session_persistence_type
                                               )
        for base_rest_url in self.base_rest_urls:
            for cli in cmd_apv_no_policy:
                self.run_cli_extend(base_rest_url, cli, va_name)


    def create_pool(self, argu):
        """ Create SLB group in lb-pool-create"""

        if not argu:
            LOG.error("In create_pool, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        cmd_apv_create_group = ADCDevice.create_group(argu['pool_id'],
                                                      argu['lb_algorithm'],
                                                      argu['session_persistence_type']
                                                     )
        cmd_slb_proxyip_group = None
        if len(self.hostnames) > 1:
            pool_name = "pool_" + argu['vip_id']
            cmd_slb_proxyip_group = ADCDevice.slb_proxyip_group(argu['pool_id'], pool_name)
            cmd_ha_on = ADCDevice.ha_on()

        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_create_group, va_name)
            if len(self.hostnames) > 1:
                self.run_cli_extend(base_rest_url, cmd_slb_proxyip_group, va_name)
                self.run_cli_extend(base_rest_url, cmd_ha_on, va_name)
                LOG.debug("In create_pool, waiting for enable ha")
                time.sleep(10)
                LOG.debug("In create_pool, done for waiting for enable ha")

        # create policy
        if argu['listener_id']:
            self._create_policy(argu['pool_id'], argu['listener_id'],
                                argu['session_persistence_type'],
                                argu['lb_algorithm'], argu['cookie_name'], va_name)


    def delete_pool(self, argu):
        """Delete SLB group in lb-pool-delete"""

        if not argu:
            LOG.error("In delete_pool, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        # delete policy
        if argu['listener_id']:
            self._delete_policy(argu['listener_id'], argu['session_persistence_type'],
                                argu['lb_algorithm'], va_name)

        cmd_apv_no_group = ADCDevice.no_group(argu['pool_id'])
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_no_group, va_name)


    def create_member(self, argu):
        """ create a member"""

        if not argu:
            LOG.error("In create_member, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        cmd_apv_create_real_server = ADCDevice.create_real_server(
                                                       argu['member_id'],
                                                       argu['member_address'],
                                                       argu['member_port'],
                                                       argu['protocol']
                                                       )

        cmd_apv_add_rs_into_group = ADCDevice.add_rs_into_group(
                                                               argu['pool_id'],
                                                               argu['member_id'],
                                                               argu['member_weight']
                                                               )
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_create_real_server, va_name)
            self.run_cli_extend(base_rest_url, cmd_apv_add_rs_into_group, va_name)


    def delete_member(self, argu):
        """ Delete a member"""

        if not argu:
            LOG.error("In delete_member, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        cmd_apv_no_rs = ADCDevice.no_real_server(argu['protocol'],
            argu['member_id'], argu['member_port'])

        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_no_rs, va_name)


    def create_health_monitor(self, argu):

        if not argu:
            LOG.error("In create_health_monitor, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        cmd_apv_create_hm = ADCDevice.create_health_monitor(
                                                           argu['hm_id'],
                                                           argu['hm_type'],
                                                           argu['hm_delay'],
                                                           argu['hm_max_retries'],
                                                           argu['hm_timeout'],
                                                           argu['hm_http_method'],
                                                           argu['hm_url'],
                                                           argu['hm_expected_codes']
                                                           )

        cmd_apv_attach_hm = ADCDevice.attach_hm_to_group(argu['pool_id'], argu['hm_id'])
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_create_hm, va_name)
            self.run_cli_extend(base_rest_url, cmd_apv_attach_hm, va_name)


    def delete_health_monitor(self, argu):

        if not argu:
            LOG.error("In delete_health_monitor, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        cmd_apv_detach_hm = ADCDevice.detach_hm_to_group(argu['pool_id'], argu['hm_id'])

        cmd_apv_no_hm = ADCDevice.no_health_monitor(argu['hm_id'])
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_detach_hm, va_name)
            self.run_cli_extend(base_rest_url, cmd_apv_no_hm, va_name)


    def create_l7_policy(self, argu, updated=False):
        if not argu:
            LOG.error("In create_l7_policy, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        if argu['pool_id']:
            self._create_policy(argu['pool_id'], argu['listener_id'],
                                argu['session_persistence_type'],
                                argu['lb_algorithm'], argu['cookie_name'], va_name)

        if not updated:
            vlinks = get_vlinks_by_policy(argu['id'])
            for vlink in vlinks:
                cmd_create_vlink = ADCDevice.create_vlink(vlink)
                for base_rest_url in self.base_rest_urls:
                    self.run_cli_extend(base_rest_url, cmd_create_vlink, va_name)


    def delete_l7_policy(self, argu, updated=False):
        if not argu:
            LOG.error("In delete_l7_policy, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        if argu['pool_id']:
            self._delete_policy(argu['listener_id'], argu['session_persistence_type'],
                                argu['lb_algorithm'], va_name)

        if not updated:
            vlinks = get_vlinks_by_policy(argu['id'])
            for vlink in vlinks:
                cmd_no_vlink = ADCDevice.no_vlink(vlink)
                for base_rest_url in self.base_rest_urls:
                    self.run_cli_extend(base_rest_url, cmd_no_vlink, va_name)


    def create_l7_rule(self, argu, action_created=False):
        if not argu:
            LOG.error("In create_l7_rule, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        cmd_create_rule = ADCDevice.create_l7_rule(argu['rule_id'],
                                                   argu['vs_id'],
                                                   argu['group_id'],
                                                   argu['rule_type'],
                                                   argu['compare_type'],
                                                   argu['rule_value'],
                                                   argu['rule_invert'],
                                                   argu['rule_key'])
        cmd_slb_policy_action = None
        if action_created:
            if argu['action'] == lb_const.L7_POLICY_ACTION_REJECT:
                cmd_slb_policy_action = ADCDevice.slb_policy_action(argu['rule_id'],
                    'block', err_number='403')
            elif argu['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_URL:
                cmd_slb_policy_action = ADCDevice.slb_policy_action(argu['rule_id'],
                    'redirect', redirect_to_url=argu['redirect_url'])

        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_create_rule, va_name)
            self.run_cli_extend(base_rest_url, cmd_slb_policy_action, va_name)

    def delete_l7_rule(self, argu, action_deleted=False):
        if not argu:
            LOG.error("In delete_l7_rule, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        cmd_no_rule = ADCDevice.no_l7_rule(argu['rule_id'], argu['rule_type'])
        cmd_no_slb_policy_action = None
        if action_deleted:
            cmd_no_slb_policy_action = ADCDevice.no_slb_policy_action(argu['rule_id'])
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_no_rule, va_name)
            self.run_cli_extend(base_rest_url, cmd_no_slb_policy_action, va_name)

    def configure_ha(self, base_rest_url, unit_list, vip_address,
        vlan_tag, pool_name, pool_address, va_name):
        in_interface = self.get_va_interface()
        if vlan_tag:
            in_interface = "vlan." + vlan_tag

        cmd_ha_group_id = ADCDevice.ha_group_id(HA_GROUP_ID)
        self.run_cli_extend(base_rest_url, cmd_ha_group_id, va_name)

        cmd_ip_pool = ADCDevice.ip_pool(pool_name, pool_address)
        self.run_cli_extend(base_rest_url, cmd_ip_pool, va_name)

        for unit_item in unit_list:
            unit_name = unit_item['name']
            ip_address = unit_item['ip_address']
            priority = unit_item['priority']
            cmd_ha_unit = ADCDevice.ha_unit(unit_name, ip_address, 65521)
            cmd_synconfig_peer = ADCDevice.synconfig_peer(unit_name, ip_address)
            cmd_ha_group_priority = ADCDevice.ha_group_priority(unit_name, HA_GROUP_ID, priority)
            self.run_cli_extend(base_rest_url, cmd_ha_unit, va_name)
            self.run_cli_extend(base_rest_url, cmd_synconfig_peer, va_name)
            self.run_cli_extend(base_rest_url, cmd_ha_group_priority, va_name)

        cmd_ha_group_fip_vip = ADCDevice.ha_group_fip(HA_GROUP_ID, vip_address, in_interface)
        cmd_ha_group_fip_pool = ADCDevice.ha_group_fip(HA_GROUP_ID, pool_address, in_interface)
        cmd_ha_link_network_on = ADCDevice.ha_link_network_on()
        cmd_ha_group_enable = ADCDevice.ha_group_enable(HA_GROUP_ID)
        cmd_ha_group_preempt_on = ADCDevice.ha_group_preempt_on(HA_GROUP_ID)
        cmd_ha_ssf_on = ADCDevice.ha_ssf_on()
        self.run_cli_extend(base_rest_url, cmd_ha_group_fip_vip, va_name)
        self.run_cli_extend(base_rest_url, cmd_ha_group_fip_pool, va_name)
        self.run_cli_extend(base_rest_url, cmd_ha_link_network_on, va_name)
        self.run_cli_extend(base_rest_url, cmd_ha_group_enable, va_name)
        self.run_cli_extend(base_rest_url, cmd_ha_group_preempt_on, va_name)
        self.run_cli_extend(base_rest_url, cmd_ha_ssf_on, va_name)


    def clear_ha(self, base_rest_url, unit_list, vip_address, va_name):
        cmd_ha_group_disable = ADCDevice.ha_group_disable(HA_GROUP_ID)
        cmd_ha_no_group_fip = ADCDevice.ha_no_group_fip(HA_GROUP_ID, vip_address)
        self.run_cli_extend(base_rest_url, cmd_ha_group_disable, va_name)
        self.run_cli_extend(base_rest_url, cmd_ha_no_group_fip, va_name)

        for unit_item in unit_list:
            unit_name = unit_item['name']
            cmd_no_ha_unit = ADCDevice.no_ha_unit(unit_name)
            self.run_cli_extend(base_rest_url, cmd_no_ha_unit, va_name)


    def start_vhost(self, vhost_name, va_name):
        cmd_start_vhost = ADCDevice.start_vhost(vhost_name)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_start_vhost, va_name)


    def configure_ssl(self, vhost_name, vs_name,
                      key_content, cert_content,
                      domain_name, va_name):
        cmd_create_vhost = None
        cmd_associate_domain_to_vhost = None
        if not domain_name:
            cmd_create_vhost = ADCDevice.create_ssl_vhost(vhost_name, vs_name)
        cmd_import_ssl_key = ADCDevice.import_ssl_key(vhost_name, key_content, domain_name)
        cmd_import_ssl_cert = ADCDevice.import_ssl_cert(vhost_name, cert_content, domain_name)
        cmd_activate_cert = ADCDevice.activate_certificate(vhost_name, domain_name)
        if domain_name:
            cmd_associate_domain_to_vhost = ADCDevice.associate_domain_to_vhost(vhost_name, domain_name)
        for base_rest_url in self.base_rest_urls:
            if cmd_create_vhost:
                self.run_cli_extend(base_rest_url, cmd_create_vhost, va_name)
            if cmd_associate_domain_to_vhost:
                self.run_cli_extend(base_rest_url, cmd_associate_domain_to_vhost, va_name)
            self.run_cli_extend(base_rest_url, cmd_import_ssl_key, va_name)
            self.run_cli_extend(base_rest_url, cmd_import_ssl_cert, va_name)
            self.run_cli_extend(base_rest_url, cmd_activate_cert, va_name)

    def clear_ssl(self, vhost_name, vs_name, domain_name, va_name):
        cmd_stop_vhost = ADCDevice.stop_vhost(vhost_name)
        cmd_deactivate_certificate = ADCDevice.deactivate_certificate(vhost_name, domain_name)
        if domain_name:
            cmd_disassociate_domain_to_vhost = ADCDevice.disassociate_domain_to_vhost(vhost_name, domain_name)
        cmd_no_ssl_cert = ADCDevice.no_ssl_cert(vhost_name)
        cmd_no_ssl_vhost = ADCDevice.no_ssl_vhost(vhost_name, vs_name)
        cmd_clear_ssl_vhost = ADCDevice.clear_ssl_vhost(vhost_name)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_stop_vhost, va_name)
            self.run_cli_extend(base_rest_url, cmd_deactivate_certificate, va_name)
            if domain_name:
                self.run_cli_extend(base_rest_url, cmd_disassociate_domain_to_vhost, va_name)
            self.run_cli_extend(base_rest_url, cmd_no_ssl_cert, va_name)
            self.run_cli_extend(base_rest_url, cmd_no_ssl_vhost, va_name)
            self.run_cli_extend(base_rest_url, cmd_clear_ssl_vhost, va_name)


    def write_memory(self, argu=None):
        va_name = self.get_va_name(argu)
        cmd_apv_write_memory = ADCDevice.write_memory()
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_write_memory, va_name)


    def activation_server(self, address, port, va_name):
        cmd_apv_activation_server = ADCDevice.activation_server(address, str(port))
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_activation_server, va_name)


    def run_cli_extend(self, base_rest_url, cmd, va_name=None,
        connect_timeout=5, read_timeout=5, run_timeout=60):
        exception = None
        if not cmd:
            return
        url = base_rest_url + '/cli_extend'
        if va_name:
            cmd = "va run %s \"%s\"" % (va_name, cmd)
        payload = {
            "cmd": cmd,
            "timeout": run_timeout
        }
        LOG.debug("Run the URL: --%s--", url)
        LOG.debug("Run the CLI: --%s--", cmd)
        conn_max_retries = 3
        conn_retry_interval = 5
        for a in six.moves.xrange(conn_max_retries):
            try:
                r = requests.post(url,
                                  json.dumps(payload),
                                  auth=self.get_auth(),
                                  timeout=(connect_timeout, read_timeout),
                                  verify=False)
                LOG.debug("status_code: %d", r.status_code)
                if r.status_code == 200:
                    time.sleep(1)
                    return r
                else:
                    time.sleep(conn_retry_interval)
            except (requests.ConnectionError, requests.Timeout) as e:
                exception = e
                LOG.warning("Could not connect to instance. Retrying.")
                time.sleep(conn_retry_interval)

        LOG.error("Connection retries (currently set to %(max_retries)s) "
                  "exhausted.  The vapv is unavailable. Reason: "
                  "%(exception)s",
                  {'max_retries': conn_max_retries,
                   'exception': exception})

        raise driver_except.TimeOutException()


    def get_all_health_status(self, va_name):
        status_dic = {}
        host_dic = {}
        cmd_get_status = ADCDevice.get_health_status()
        for idx, base_rest_url in enumerate(self.base_rest_urls):
            r = self.run_cli_extend(base_rest_url, cmd_get_status, va_name)
            status_str_index = r.text.index("status")
            health_check_index = r.text.index("Health Check")
            status_match_str = r.text[status_str_index + 8: health_check_index].strip().strip('-')
            status_match_list = status_match_str.split("\\n")
            for status in status_match_list:
                 if len(status) != 0:
                     space_index = status.index(' ')
                     server_name = status[:space_index]
                     status_value = status[space_index:].strip()
                     host_dic[server_name] = status_value
            host_name = self.hostnames[idx]
            status_dic[host_name] = host_dic
        return status_dic

    def get_status_by_lb_mems(self, lb_mems):
        argu = {}
        for lb_id, members in lb_mems.items():
            argu['vip_id'] = lb_id
            va_name = self.get_va_name(argu)
            all_status = self.get_all_health_status(va_name)
            LOG.debug("all_status: %s" % all_status)
            all_status_values = all_status.values()
            for member_name, status in members.items():
                if all_status.has_key(member_name):
                    if 'DOWN' in all_status[member_name]:
                        lb_mems[lb_id][member_name] = lb_const.OFFLINE
                    elif 'UP' in all_status[member_name]:
                        lb_mems[lb_id][member_name] = lb_const.ONLINE
                if len(all_status_values) == 1:
                    if all_status_values[0].has_key(member_name):
                        if 'DOWN' in all_status_values[0][member_name]:
                            lb_mems[lb_id][member_name] = lb_const.OFFLINE
                        else:
                            lb_mems[lb_id][member_name] = lb_const.ONLINE
                elif len(all_status_values) > 1:
                    if all_status_values[0].has_key(member_name) and \
                        all_status_values[1].has_key(member_name):
                        if 'DOWN' in all_status_values[0][member_name] and \
                            'DOWN' in all_status_values[1][member_name]:
                            lb_mems[lb_id][member_name] = lb_const.OFFLINE
                        else:
                            lb_mems[lb_id][member_name] = lb_const.ONLINE
        return lb_mems

    def get_restful_status(self, base_rest_url):
        cmd_show_ip_addr = ADCDevice.show_ip_addr()
        try:
            self.run_cli_extend(base_rest_url, cmd_show_ip_addr)
        except Exception:
            return False
        return True
