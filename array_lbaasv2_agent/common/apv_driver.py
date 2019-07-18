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
import logging
import json
import six
import time
import requests
import IPy
from oslo_config import cfg
from array_lbaasv2_agent.common.array_driver import ArrayCommonAPIDriver
from array_lbaasv2_agent.common.adc_device import ADCDevice
from array_lbaasv2_agent.common.adc_device import is_driver_apv
from array_lbaasv2_agent.common import exceptions as driver_except

LOG = logging.getLogger(__name__)


class ArrayAPVAPIDriver(ArrayCommonAPIDriver):
    """ The real implementation on host to push config to
        APV via RESTful API
    """
    def __init__(self, management_ip, in_interface, user_name, user_passwd, context, plugin_rpc):
        super(ArrayAPVAPIDriver, self).__init__(in_interface,
                                                user_name,
                                                user_passwd,
                                                context,
                                                plugin_rpc)
        self.hostnames = management_ip
        self.base_rest_urls = ["https://" + host + ":9997/rest/apv" for host in self.hostnames]
        self.segment_user_name = ""
        self.segment_user_passwd = "click1"  #ToDo: get from configuration
        self.segment_enable = True


    def get_va_name(self, argu):
        return None

    def get_segment_auth(self):
        return (self.segment_user_name, self.segment_user_passwd)

    def _create_segment(self, base_rest_urls, segment_name, va_name):
        """ create segment"""

        cmd_create_segment = ADCDevice.create_segment(segment_name)
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_create_segment, va_name, self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_create_segment, va_name, self.segment_enable)


    def _delete_segment(self, base_rest_urls, segment_name, va_name):
        """ create segment"""

        cmd_delete_segment = ADCDevice.delete_segment(segment_name)
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_delete_segment, va_name, self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_delete_segment, va_name, self.segment_enable)


    def _create_segment_user(self, base_rest_urls, segment_name, va_name):
        """ create segment user"""

        segment_user_name = self.segment_user_name
        segment_user_passwd = self.segment_user_passwd
        level = "api"
        cmd_create_segment_user = ADCDevice.create_segment_user(segment_user_name, segment_name, segment_user_passwd, level)
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_create_segment_user, va_name, self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_create_segment_user, va_name, self.segment_enable)


    def _delete_segment_user(self, base_rest_urls, va_name):
        """ create segment user"""

        segment_user_name = self.segment_user_name
        cmd_delete_segment_user = ADCDevice.delete_segment_user(segment_user_name)
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_delete_segment_user, va_name, self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_delete_segment_user, va_name, self.segment_enable)


    def _segment_interface(self, base_rest_urls, vlan_tag, segment_name, va_name):
        cmd_apv_config_vlan = None
        in_interface = self.plugin_rpc.get_interface(self.context)
        if not in_interface:
            return
        interface_name = in_interface

        if vlan_tag:
            interface_name = "vlan." + vlan_tag
            cmd_apv_config_vlan = ADCDevice.vlan_device(in_interface, interface_name, vlan_tag)
        cmd_segment_interface = ADCDevice.segment_interface(segment_name, interface_name)
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                if vlan_tag:
                    self.run_cli_extend(base_rest_url, cmd_apv_config_vlan, va_name, self.segment_enable)
                self.run_cli_extend(base_rest_url, cmd_segment_interface, va_name, self.segment_enable)
        else:
            if vlan_tag:
                self.run_cli_extend(base_rest_urls, cmd_apv_config_vlan, va_name, self.segment_enable)
            self.run_cli_extend(base_rest_urls, cmd_segment_interface, va_name, self.segment_enable)


    def _delete_segment_interface(self, base_rest_urls, vlan_tag, segment_name, va_name):
        interface_name = "vlan." + vlan_tag
        cmd_delete_segment_interface = ADCDevice.delete_segment_interface(segment_name, interface_name)
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_delete_segment_interface, va_name, self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_delete_segment_interface, va_name, self.segment_enable)


    def create_loadbalancer(self, argu):
        """ create a loadbalancer """
        if not argu:
            LOG.error("In create_loadbalancer, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        pri_port_id = None
        sec_port_id = None
        lb_name = argu['vip_id']  #need verify
        self.segment_user_name = argu['vip_id'][:15]  #limit user length is 15
        self.segment_name = lb_name
        # create segment name and user and interface
        self._create_segment(self.base_rest_urls, lb_name, va_name)
        self._create_segment_user(self.base_rest_urls, lb_name, va_name)
        self._segment_interface(self.base_rest_urls, argu['vlan_tag'], lb_name, va_name)
        # create vip
        if len(self.hostnames) == 1:
            self._create_vip(self.base_rest_urls, argu['ip_address'],
                argu['netmask'], argu['vlan_tag'], argu['gateway'], va_name, lb_name)
            self.write_memory(argu, self.segment_enable)
        else:
            vlan_tag = 0
            vlan_tag_map = self.plugin_rpc.generate_tags(self.context)
            if vlan_tag_map:
                vlan_tag  = vlan_tag_map['vlan_tag']
            interface_mapping = argu['interface_mapping']
            unit_list = []
            pool_name = "pool_" + argu['vip_id']
            pool_name = pool_name[:40]
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
                    str(vlan_tag), argu['gateway'], va_name, lb_name)
                unit_list.append(unit_item)
            in_interface = self.plugin_rpc.get_interface(self.context)
            if not in_interface:
                LOG.error("Failed to get the interface from plugin_rpc")
                return 
            self.plugin_rpc.create_vapv(self.context, lb_name[:10], argu['vip_id'],
                    argu['subnet_id'], in_use_lb=1, pri_port_id=pri_port_id,
                    sec_port_id=sec_port_id, cluster_id=vlan_tag)
            for base_rest_url in self.base_rest_urls:
                self.configure_ha(base_rest_url, unit_list,
                    argu['vip_address'], str(vlan_tag), lb_name, pool_name, 
                    argu['pool_address'], va_name, self.context, argu['subnet_id'],
                    in_interface)
            self.write_memory(argu, self.segment_enable)


    def delete_loadbalancer(self, argu):
        """ Delete a loadbalancer """
        if not argu:
            LOG.error("In delete_loadbalancer, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        lb_name = argu['vip_id']  #need verify
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
                self.clear_ha(base_rest_url, unit_list, argu['vip_address'], va_name, lb_name, self.context, argu['subnet_id'])

            pool_port_name = argu['vip_id'] + "_pool"
            self.plugin_rpc.delete_port_by_name(self.context, pool_port_name)
            port_name = 'lb' + '-'+ argu['vip_id'] + "_0"
            self.plugin_rpc.delete_port_by_name(self.context, port_name)
            port_name = 'lb' + '-'+ argu['vip_id'] + "_1"
            self.plugin_rpc.delete_port_by_name(self.context, port_name)

            # Delete the apv from database
            self.plugin_rpc.delete_vapv(self.context, lb_name[:10])
        else:
            port_name = argu['vip_id'] + "_port"
            self.plugin_rpc.delete_port_by_name(self.context, port_name)
        # delete vip
        if not argu['vlan_tag']:
            LOG.error("Failed to got the vlan tag to delete loadbalancer")
            return
        self._delete_segment(self.base_rest_urls, lb_name, va_name)
        self._delete_vip(str(argu['vlan_tag']), va_name)

    def _create_vip(self, base_rest_urls, vip_address, netmask, vlan_tag, gateway, va_name, lb_name):
        """ create vip"""

        in_interface = self.plugin_rpc.get_interface(self.context)
        if not in_interface:
            return
        interface_name = in_interface

        LOG.debug("Configure the vip address into interface")
        if vlan_tag:
            interface_name = "vlan." + vlan_tag
        segment_name = lb_name
        segment_ip = vip_address
        internal_ip = self.plugin_rpc.get_available_internal_ip(self.context, segment_name, segment_ip)
        if internal_ip == 0:
            LOG.error("Failed to get available internal ip address")
            return
        cmd_apv_config_ip = ADCDevice.configure_segment_ip(interface_name, vip_address, netmask, internal_ip)
        cmd_apv_config_route = ADCDevice.configure_route(gateway)

        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_apv_config_ip, va_name, self.segment_enable)
                self.run_cli_extend(base_rest_url, cmd_apv_config_route, va_name)
        else:
            self.run_cli_extend(base_rest_urls, cmd_apv_config_ip, va_name, self.segment_enable)
            self.run_cli_extend(base_rest_urls, cmd_apv_config_route, va_name)


    def _delete_vip(self, vlan_tag, va_name):
        cmd_apv_no_vlan_device = None

        if vlan_tag:
            interface_name = "vlan." + vlan_tag
            cmd_apv_no_vlan_device = ADCDevice.no_vlan_device(interface_name)
        else:
            LOG.debug("Cannot get the vlan tag when delete vip")
            return
        LOG.debug("no the vip address into interface")

        for base_rest_url in self.base_rest_urls:
            if vlan_tag:
                self.run_cli_extend(base_rest_url, cmd_apv_no_vlan_device, va_name, self.segment_enable)


    def create_member(self, argu):
        """ create a member"""

        if not argu:
            LOG.error("In create_member, it should not pass the None.")
            return
        va_name = self.get_va_name(argu)

        member_address = argu['member_address']
        ip_version = IPy.IP(member_address).version()
        netmask = 32 if ip_version == 4 else 128

        segment_name  = argu['lb_id']
        internal_ip = self.plugin_rpc.get_available_internal_ip(self.context, segment_name, member_address)
        if not internal_ip:
            LOG.error("Failed to get available internal ip address in func create_member")
            return
        cmd_segment_nat = ADCDevice.segment_nat(segment_name, internal_ip, member_address, netmask)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_segment_nat, va_name, self.segment_enable)
        cmd_apv_create_real_server = ADCDevice.create_real_server(
                                                       argu['member_id'],
                                                       member_address,
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


    def configure_ha(self, base_rest_url, unit_list, vip_address,
        vlan_tag, segment_name, pool_name, pool_address, va_name, context, vip_subnet_id, in_interface):
        if vlan_tag:
            in_interface = "vlan." + vlan_tag
        group_id = self.find_available_cluster_id(context, vip_subnet_id)
        if group_id == 0:
            LOG.error("Failed to find available group id")
            return
        else:
            LOG.debug("find the available group id: %d", group_id)
        cmd_ha_group_id = ADCDevice.ha_group_id(group_id)
        self.run_cli_extend(base_rest_url, cmd_ha_group_id, va_name, self.segment_enable)

        cmd_ip_pool = ADCDevice.ip_pool(pool_name, pool_address)
        self.run_cli_extend(base_rest_url, cmd_ip_pool, va_name)

        for unit_item in unit_list:
            unit_name = unit_item['name']
            ip_address = unit_item['ip_address']
            peer_ip_address = ip_address
            priority = unit_item['priority']
            cmd_ha_unit = ADCDevice.ha_unit(unit_name, ip_address, 65521)
            cmd_synconfig_peer = ADCDevice.synconfig_peer(unit_name, ip_address)
            cmd_ha_group_priority = ADCDevice.ha_group_priority(unit_name, group_id, priority)
            self.run_cli_extend(base_rest_url, cmd_ha_unit, va_name, self.segment_enable)
            self.run_cli_extend(base_rest_url, cmd_synconfig_peer, va_name, self.segment_enable)
            self.run_cli_extend(base_rest_url, cmd_ha_group_priority, va_name, self.segment_enable)

        cmd_ha_group_fip_vip = ADCDevice.ha_group_fip_apv(group_id, vip_address, segment_name, in_interface)
        cmd_ha_group_fip_pool = ADCDevice.ha_group_fip_apv(group_id, pool_address, segment_name, in_interface)
        cmd_ha_link_network_on = ADCDevice.ha_link_network_on()
        cmd_ha_group_enable = ADCDevice.ha_group_enable(group_id)
        cmd_ha_group_preempt_on = ADCDevice.ha_group_preempt_on(group_id)
        cmd_ha_ssf_peer = ADCDevice.ha_ssf_peer(peer_ip_address)
        cmd_ha_ssf_on = ADCDevice.ha_ssf_on()
        cmd_monitor_vcondition_name = ADCDevice.monitor_vcondition_name()
        cmd_monitor_vcondition_member = ADCDevice.monitor_vcondition_member()
        cmd_ha_decision_rule = ADCDevice.ha_decision_rule()

        self.run_cli_extend(base_rest_url, cmd_ha_link_network_on, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_fip_vip, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_fip_pool, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_enable, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_preempt_on, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_ssf_peer, va_name)
        self.run_cli_extend(base_rest_url, cmd_ha_ssf_on, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_monitor_vcondition_name, va_name, self.segment_enable)
        for cli in cmd_monitor_vcondition_member:
            self.run_cli_extend(base_rest_url, cli, va_name)
        self.run_cli_extend(base_rest_url, cmd_ha_decision_rule, va_name, self.segment_enable)

    def clear_ha(self, base_rest_url, unit_list, vip_address, va_name, segment_name, context, vip_subnet_id):
        group_id = self.find_available_cluster_id(context, vip_subnet_id)
        if group_id == 0:
            LOG.error("Failed to find available group id")
            return
        else:
            LOG.debug("find the available group id: %d", group_id)
        cmd_ha_group_disable = ADCDevice.ha_group_disable(group_id)
        cmd_ha_no_group_fip = ADCDevice.ha_no_group_fip_apv(group_id, vip_address, segment_name)
        self.run_cli_extend(base_rest_url, cmd_ha_group_disable, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_no_group_fip, va_name, self.segment_enable)

        for unit_item in unit_list:
            unit_name = unit_item['name']
            cmd_no_ha_unit = ADCDevice.no_ha_unit(unit_name)
            self.run_cli_extend(base_rest_url, cmd_no_ha_unit, va_name, self.segment_enable)


    def run_cli_extend(self, base_rest_url, cmd, va_name=None, segment_enable=False,
        connect_timeout=60, read_timeout=60):
        exception = None
        if not cmd:
            return
        url = base_rest_url + '/cli_extend'  #need verify
        if va_name and is_driver_apv():
            cmd = "va run %s \"%s\"" % (va_name, cmd)
        payload = {
            "cmd": cmd
        }
        LOG.debug("Run the URL: --%s--", url)
        LOG.debug("Run the CLI: --%s--", cmd)
        conn_max_retries = 2
        conn_retry_interval = 3
        auth_value = self.get_auth()
        if not segment_enable:
            auth_value = self.get_segment_auth()
        LOG.debug("auth_value:(%s)", auth_value)
        for a in six.moves.xrange(conn_max_retries):
            try:
                r = requests.post(url,
                                  json.dumps(payload),
                                  auth=auth_value,
                                  timeout=(connect_timeout, read_timeout),
                                  verify=False)
                LOG.debug("status_code: %d", r.status_code)
                LOG.debug("status_contents: %s", r.text)
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


    def find_available_cluster_id(self, context, subnet_id):
        cluster_ids = self.plugin_rpc.get_clusterids_by_subnet(context, subnet_id)
        LOG.debug("get the cluster ids (%s)", cluster_ids)
        supported_ids = range(1, 256)
        diff_ids=list(set(supported_ids).difference(set(cluster_ids)))
        if len(diff_ids) > 1:
            return diff_ids[0]
        return 0


    def write_memory(self, argu, segment_enable=False):
        cmd_apv_write_memory = ADCDevice.write_memory()
        va_name = self.get_va_name(argu)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_write_memory, va_name, segment_enable)
