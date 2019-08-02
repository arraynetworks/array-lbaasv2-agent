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
import netaddr
import copy
import traceback
import hashlib
from oslo_config import cfg
from array_lbaasv2_agent.common.array_driver import ArrayCommonAPIDriver
from array_lbaasv2_agent.common.adc_device import ADCDevice
from array_lbaasv2_agent.common import exceptions as driver_except
from neutron_lbaas.services.loadbalancer import constants as lb_const

LOG = logging.getLogger(__name__)

g_off_hosts = []
redundant_segments = {}  # for example:{"segment_name1":{"times":2, "url_idx":0}, "segment_name2":{"times":3, "url_idx":1}}

def parse_vlan_result(result, key):
    for line in result.split('\n'):
        line=line.replace("\"", "")
        line=line.replace("\\", "")
        items=line.split()
        if len(items) > 2:
            itm2=str(items[2])
            if itm2 == key:
                return str(items[1])


def parse_segment_name_result(result):
    segment_names = []
    for line in result.split('\n'):
        line=line.replace("\"", "")
        line=line.replace("\\", "")
        items=line.split()
        if items:
            segment_names.append(items[2])
    return segment_names

def parse_segment_nat_result(result):
    segment_nat_cmds = []
    for line in result.split('\n'):
        if line:
            segment_nat_cmds.append(line)
    return segment_nat_cmds

def parse_vlan_by_seg_if(ret_seg_if):
    seg_if = ret_seg_if.split()
    if seg_if:
        return seg_if[:-1]
    else:
        return None

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
        self.segment_user_passwd = "click1@ARRAY"  #ToDo: get from configuration
        self.segment_enable = True
        self.off_host = []
        self.net_seg_enable = cfg.CONF.arraynetworks.net_seg_enable


    def get_va_name(self, argu, segment_name=None):
        if not segment_name:
            if not argu:
                LOG.debug("No argument, return None")
                return None

            vip_id = argu.get('vip_id', None)
            if not vip_id:
                LOG.debug("No loadbalance_id in argument, raise it")
                return None

            ret_segment_name = self.plugin_rpc.get_segment_name_by_lb_id(self.context, vip_id)
            segment_name = ret_segment_name['segment_name']
            if len(segment_name) == 0:
                return None
        segment_user_name = segment_name[:10] + "_api"
        return segment_user_name


    def get_segment_auth(self, segment_user_name):
        return (segment_user_name, self.segment_user_passwd)


    def _create_segment_config(self, base_rest_urls, segment_name):
        """ create segment user"""

        segment_api_user_name = segment_name[:10] + "_api"
        segment_api_user_passwd = "\"%s\"" % self.segment_user_passwd
        api_level = "api"

        segment_conf_user_name = segment_name[:10] + "_conf"
        segment_config_password = cfg.CONF.arraynetworks.segment_config_password
        segment_conf_user_passwd = "\"%s\"" % segment_config_password
        conf_level = "config"

        cmd_create_segment = ADCDevice.create_segment(segment_name)
        cmd_create_segment_api_user = ADCDevice.create_segment_user(segment_api_user_name,
            segment_name, segment_api_user_passwd, api_level)
        cmd_create_segment_conf_user = ADCDevice.create_segment_user(segment_conf_user_name,
            segment_name, segment_conf_user_passwd, conf_level)

        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_create_segment,
                    segment_enable=self.segment_enable)
                self.run_cli_extend(base_rest_url, cmd_create_segment_api_user,
                    segment_enable=self.segment_enable)
                self.run_cli_extend(base_rest_url, cmd_create_segment_conf_user,
                    segment_enable=self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_create_segment,
                segment_enable=self.segment_enable)
            self.run_cli_extend(base_rest_urls, cmd_create_segment_api_user,
                segment_enable=self.segment_enable)
            self.run_cli_extend(base_rest_urls, cmd_create_segment_conf_user,
                segment_enable=self.segment_enable)


    def _delete_segment_config(self, base_rest_urls, segment_name):
        """ create segment user"""

        segment_api_user_name = segment_name[:10] + "_api"
        segment_conf_user_name = segment_name[:10] + "_conf"

        cmd_delete_segment = ADCDevice.delete_segment(segment_name)
        cmd_delete_api_user = ADCDevice.delete_segment_user(segment_api_user_name)
        cmd_delete_conf_user = ADCDevice.delete_segment_user(segment_conf_user_name)

        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_delete_segment,
                    segment_enable=self.segment_enable)
                self.run_cli_extend(base_rest_url, cmd_delete_api_user,
                    segment_enable=self.segment_enable)
                self.run_cli_extend(base_rest_url, cmd_delete_conf_user,
                    segment_enable=self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_delete_segment,
                segment_enable=self.segment_enable)
            self.run_cli_extend(base_rest_urls, cmd_delete_api_user,
                segment_enable=self.segment_enable)
            self.run_cli_extend(base_rest_urls, cmd_delete_conf_user,
                segment_enable=self.segment_enable)


    def _create_vlan_device(self, base_rest_urls, vlan_tag, va_name, in_interface):
        if vlan_tag is None:
            LOG.error("Lack of configuration vlan_tag")
            return

        interface_name = "vlan." + vlan_tag
        cmd_apv_config_vlan = ADCDevice.vlan_device(in_interface, interface_name, vlan_tag)
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_apv_config_vlan, va_name, self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_apv_config_vlan, va_name, self.segment_enable)


    def _segment_interface(self, base_rest_urls, vlan_tag, segment_name, va_name, in_interface):
        if vlan_tag is None:
            LOG.error("Lack of configuration vlan_tag")
            return

        interface_name = "vlan." + vlan_tag
        cmd_segment_interface = ADCDevice.segment_interface(segment_name, interface_name)
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_segment_interface, va_name, self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_segment_interface, va_name, self.segment_enable)


    def _delete_segment_interface(self, base_rest_urls, vlan_tag, segment_name, va_name):
        if not vlan_tag:
            LOG.error("Lack of configuration vlan_tag")
            return
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

        if argu['vlan_tag'] is None:
            LOG.error("Lack of configuration vlan_tag")
            return

        interface = self.plugin_rpc.get_interface(self.context)
        if not interface:
            LOG.error("Failed to get the interface from driver get_interface")
            return

        segment_name = hashlib.sha1("{}-{}".format(argu['subnet_id'], argu['tenant_id'])).hexdigest()

        ha_group_id = 0
        group_id_map = self.plugin_rpc.generate_ha_group_id(self.context,
            lb_id=argu['vip_id'], subnet_id=argu['subnet_id'],
            tenant_id=argu['tenant_id'], segment_name=segment_name)
        if group_id_map:
            ha_group_id = group_id_map['group_id']
        else:
            LOG.debug("Failed to generate ha group id")
            return
        LOG.debug("Find the available group id: %d", ha_group_id)

        va_name = self.get_va_name(argu, segment_name=segment_name)
        existed_segment = self.check_segment_existed_in_devices(segment_name)

        if self.net_seg_enable and existed_segment:
            LOG.debug("No need to create segment configuration")
        else:
            self._create_segment_config(self.base_rest_urls, segment_name)

        if not self.net_seg_enable:
            self.create_port_for_subnet(argu['subnet_id'], argu['vlan_tag'], argu['vip_id'])

        # create vip
        internal_ip = None
        if len(self.hostnames) == 1:
            if self.net_seg_enable:
                if not existed_segment:
                    internal_ip = self.plugin_rpc.get_available_internal_ip(self.context,
                        segment_name, argu['ip_address'])
                    if internal_ip == None:
                        LOG.error("Failed to get available internal ip address for create loadbalancer")
                        return
                    self._create_vlan_device(self.base_rest_urls, argu['vlan_tag'], va_name, interface)
                    self._segment_interface(self.base_rest_urls, argu['vlan_tag'], segment_name, va_name, interface)
                    self._create_vip(self.base_rest_urls, argu['ip_address'],argu['netmask'],
                        argu['vlan_tag'], argu['gateway'], va_name, internal_ip)
            else:
                self._create_vip(self.base_rest_urls, argu['ip_address'],argu['netmask'],
                    argu['vlan_tag'], argu['gateway'], va_name, internal_ip)
        else:
            if self.net_seg_enable:
                if not existed_segment:
                    self._create_vlan_device(self.base_rest_urls,
                        argu['vlan_tag'], va_name, interface)
                    self._segment_interface(self.base_rest_urls,
                        argu['vlan_tag'], segment_name, va_name, interface)
            unit_list = []
            pool_name = "pool_" + argu['vip_id']

            res_inst_ports = None
            if self.net_seg_enable and existed_segment:
                LOG.debug("No need to create instance ports.")
            else:
                res_inst_ports = self.create_instance_ports(argu, segment_name)
            res_lb_port = self.create_ha_pool_port(argu)

            for idx, host in enumerate(self.hostnames):
                unit_item = {}
                if idx == 0:
                    unit_item['priority'] = 100
                    unit_item['name'] = "unit_m"
                elif idx == 1:
                    unit_item['name'] = "unit_s"
                    unit_item['priority'] = 90

                if res_inst_ports:
                    ip_address = res_inst_ports[host]['address']
                    if self.net_seg_enable and not internal_ip:
                        internal_ip = self.plugin_rpc.get_available_internal_ip(self.context,
                            segment_name, argu['vip_address'])
                        if internal_ip == None:
                            LOG.error("Failed to get available internal ip address for create loadbalancer")
                            return
                    base_rest_url = self.base_rest_urls[idx]
                    self._create_vip(base_rest_url, ip_address, argu['netmask'],
                        argu['vlan_tag'], argu['gateway'], va_name, internal_ip)
                unit_list.append(unit_item)
            for base_rest_url in self.base_rest_urls:
                self.configure_ha(base_rest_url, unit_list,
                    argu['vip_address'], argu['vlan_tag'], segment_name, pool_name,
                    res_lb_port['pool_address'], va_name, self.context, argu['subnet_id'],
                    interface, ha_group_id)
        self.write_memory(argu, self.segment_enable)


    def delete_loadbalancer(self, argu):
        """ Delete a loadbalancer """
        if not argu:
            LOG.error("In delete_loadbalancer, it should not pass the None.")
            return

        if argu['vlan_tag'] is None:
            LOG.error("Lack of configuration vlan_tag")
            return

        segment_name = hashlib.sha1("{}-{}".format(argu['subnet_id'], argu['tenant_id'])).hexdigest()

        va_name = self.get_va_name(argu, segment_name)
        lb_name = argu['vip_id']  #need verify
        # clear the HA configuration
        if len(self.hostnames) > 1:
            unit_list = []
            for idx, host in enumerate(self.hostnames):
                unit_item = {}
                if idx == 0:
                    unit_item['name'] = "unit_m"
                elif idx == 1:
                    unit_item['name'] = "unit_s"
                unit_list.append(unit_item)
            group_id = self.find_available_cluster_id(self.context, lb_name)
            LOG.debug("Find the available group id: %d", group_id)
            for idx, base_rest_url in enumerate(self.base_rest_urls):
                try:
                    self.clear_ha(base_rest_url, unit_list, argu['vip_address'], va_name,
                        lb_name, self.context, argu['subnet_id'], group_id)
                except Exception:
                    LOG.debug("Failed to clear ha in host(%s)", self.hostnames[idx])
            self.delete_ha_pool_port(argu)


        if self.net_seg_enable:
            ret_segment_used = self.plugin_rpc.get_segment_used(self.context,
                segment_name, lb_id_filter=lb_name)
            segment_used = ret_segment_used['count']
            LOG.debug("segment_used is %d" % segment_used)
            if segment_used == 0:
                LOG.debug("Will delete segment(%s)" % segment_name)
                self._delete_segment_config(self.base_rest_urls, segment_name)
                LOG.debug("Will delete the ports created by segment")
                self.delete_instance_ports(segment_name)
                self._delete_vip(str(argu['vlan_tag']), va_name)
        else:
            LOG.debug("Will delete the ports created by segment")
            self.delete_instance_ports(segment_name)
            self.delete_port_for_subnet(argu['subnet_id'], argu['vlan_tag'], lb_id_filter=lb_name)
        self.plugin_rpc.delete_vapv(self.context, lb_name[:10])
        self.write_memory(segment_enable=self.segment_enable)


    def _create_vip(self, base_rest_urls, vip_address, netmask,
        vlan_tag, gateway, va_name, internal_ip):
        """ create vip"""
        if vlan_tag is None:
            LOG.error("Lack of configuration vlan_tag")
            return

        interface_name = "vlan." + vlan_tag

        if self.net_seg_enable:
            cmd_apv_config_ip = ADCDevice.configure_segment_ip(interface_name, vip_address, netmask, internal_ip)
        else:
            cmd_apv_config_ip = ADCDevice.configure_ip(interface_name, vip_address, netmask)
        if self.net_seg_enable:
            cmd_apv_config_route = ADCDevice.configure_route(gateway)

        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_apv_config_ip, va_name, self.segment_enable)
                if self.net_seg_enable:
                    self.run_cli_extend(base_rest_url, cmd_apv_config_route, va_name)
        else:
            self.run_cli_extend(base_rest_urls, cmd_apv_config_ip, va_name, self.segment_enable)
            if self.net_seg_enable:
                self.run_cli_extend(base_rest_urls, cmd_apv_config_route, va_name)


    def _delete_vip(self, vlan_tag, va_name):
        if vlan_tag is None:
            LOG.debug("Cannot get the vlan tag when delete vip")
            return
        interface_name = "vlan." + vlan_tag
        cmd_apv_no_vlan_device = ADCDevice.no_vlan_device(interface_name)

        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_no_vlan_device, va_name, self.segment_enable)


    def create_member(self, argu):
        """ create a member"""

        if not argu:
            LOG.error("In create_member, it should not pass the None.")
            return

        ret_segment_name = self.plugin_rpc.get_segment_name_by_lb_id(self.context, argu['vip_id'])
        segment_name = ret_segment_name['segment_name']
        if len(segment_name) == 0:
            LOG.debug("The segment_name is null string.")
            return None
        va_name = self.get_va_name(argu, segment_name)

        member_address = argu['member_address']
        ip_version = netaddr.valid_ipv4(member_address)
        netmask = "255.255.255.255" if ip_version else "128"
        if not self.net_seg_enable:
            self.create_port_for_subnet(argu['subnet_id'], lb_id=argu['vip_id'])

        if self.net_seg_enable:
            internal_ip = self.plugin_rpc.get_available_internal_ip(self.context,
                segment_name, member_address, use_for_nat=True)
            if not internal_ip:
                LOG.error("Failed to get available internal ip address in func create_member")
                return
            cmd_segment_nat = ADCDevice.segment_nat(segment_name, internal_ip, member_address, netmask)
            cmd_static_route = ADCDevice.configure_route_apv(member_address, netmask, argu['gateway'])
            for base_rest_url in self.base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_segment_nat, va_name, self.segment_enable)
                self.run_cli_extend(base_rest_url, cmd_static_route, va_name)

        cmd_apv_create_real_server = ADCDevice.create_real_server(
            argu['member_id'], member_address, argu['member_port'], argu['protocol'])

        cmd_apv_add_rs_into_group = ADCDevice.add_rs_into_group(
            argu['pool_id'], argu['member_id'], argu['member_weight'])

        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_create_real_server, va_name)
            self.run_cli_extend(base_rest_url, cmd_apv_add_rs_into_group, va_name)
        self.write_memory(segment_enable=self.segment_enable) #in order to save segment nat



    def delete_member(self, argu):
        """ Delete a member"""

        if not argu:
            LOG.error("In delete_member, it should not pass the None.")
            return

        ret_segment_name = self.plugin_rpc.get_segment_name_by_lb_id(self.context, argu['vip_id'])
        segment_name = ret_segment_name['segment_name']
        if len(segment_name) == 0:
            LOG.debug("The segment_name is null string.")
            return None
        va_name = self.get_va_name(argu, segment_name)

        cmd_apv_no_rs = ADCDevice.no_real_server(argu['protocol'],
            argu['member_id'], argu['member_port'])
        if self.net_seg_enable and argu['num_of_mem'] == 1:
            member_address = argu['member_address']
            ip_version = netaddr.valid_ipv4(member_address)
            netmask = "255.255.255.255" if ip_version else "128"
            internal_ip = self.plugin_rpc.get_internal_ip_by_lb(self.context,
                segment_name, member_address, use_for_nat=True)
            if not internal_ip:
                LOG.error("Failed to find the internal ip by segment name(%s) and segment ip(%s)" % (argu['vip_id'], member_address))
                return
            cmd_delete_segment_nat = ADCDevice.delete_segment_nat(segment_name, internal_ip, member_address, netmask)
            cmd_delete_route_static = ADCDevice.delete_route_static(member_address, netmask, argu['gateway'])
            for base_rest_url in self.base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_delete_route_static, va_name)
                self.run_cli_extend(base_rest_url, cmd_delete_segment_nat, va_name, segment_enable=self.segment_enable)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_no_rs, va_name)
        self.write_memory(segment_enable=self.segment_enable) #in order to save delete segment nat
        if not self.net_seg_enable and argu['num_of_mem'] > 1:
            self.delete_port_for_subnet(argu['subnet_id'], member_id_filter=argu['member_id'])


    def configure_ha(self, base_rest_url, unit_list, vip_address,
        vlan_tag, segment_name, pool_name, pool_address, va_name,
        context, vip_subnet_id, in_interface, group_id):
        bond = in_interface
        if vlan_tag:
            in_interface = "vlan." + vlan_tag
        cmd_ha_group_id = ADCDevice.ha_group_id(group_id)
        self.run_cli_extend(base_rest_url, cmd_ha_group_id, va_name, self.segment_enable)

        cmd_ip_pool = ADCDevice.ip_pool(pool_name, pool_address)
        self.run_cli_extend(base_rest_url, cmd_ip_pool, va_name)

        for unit_item in unit_list:
            unit_name = unit_item['name']
            priority = unit_item['priority']
            cmd_ha_group_priority = ADCDevice.ha_group_priority(unit_name, group_id, priority)
            self.run_cli_extend(base_rest_url, cmd_ha_group_priority, va_name, self.segment_enable)

        if self.net_seg_enable:
            cmd_ha_group_fip_vip = ADCDevice.ha_group_fip_apv(group_id, vip_address, segment_name, in_interface)
            cmd_ha_group_fip_pool = ADCDevice.ha_group_fip_apv(group_id, pool_address, segment_name, in_interface)
        else:
            cmd_ha_group_fip_vip = ADCDevice.ha_group_fip(group_id, vip_address, in_interface)
            cmd_ha_group_fip_pool = ADCDevice.ha_group_fip(group_id, pool_address, in_interface)
        cmd_ha_group_enable = ADCDevice.ha_group_enable(group_id)
        idx = int(bond[4:])
        cmd_ha_decision_rule = ADCDevice.ha_decision_rule_apv(idx, group_id)

        self.run_cli_extend(base_rest_url, cmd_ha_group_fip_vip, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_fip_pool, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_enable, va_name, self.segment_enable)

        self.run_cli_extend(base_rest_url, cmd_ha_decision_rule, va_name, self.segment_enable)

    def clear_ha(self, base_rest_url, unit_list, vip_address, va_name,
        lb_id, context, vip_subnet_id, group_id):
        # Delete the ip pool
        pool_name = "pool_" + lb_id
        cmd_no_ip_pool = ADCDevice.no_ip_pool(pool_name)
        self.run_cli_extend(base_rest_url, cmd_no_ip_pool, va_name)

        # Delete the group id
        cmd_delete_ha_group_id = ADCDevice.ha_no_group_id(group_id)
        self.run_cli_extend(base_rest_url, cmd_delete_ha_group_id, va_name, self.segment_enable)
        # get ha decision by group id
        cmd_show_ha_decision = ADCDevice.show_ha_config()
        ret = self.run_cli_extend(base_rest_url, cmd_show_ha_decision, None, self.segment_enable)
        data = ret.text
        index_start = data.index(":")
        index_end = data.rindex("\"")
        all_ha_config = data[index_start +2:index_end]
        ha_config = all_ha_config.split("\\n")
        for conf in ha_config:
            if "decision" not in conf:
                continue
            options = conf.split()
            groupid = options[-1]
            vcondition_str = options[3]
            vcondition_name = vcondition_str[2:-2]
            if groupid == str(group_id):
                cmd_no_show_ha_decision = ADCDevice.no_ha_decision_rule(vcondition_name, group_id)
                self.run_cli_extend(base_rest_url, cmd_no_show_ha_decision, va_name, self.segment_enable)


    def run_cli_extend(self, base_rest_url, cmd, va_name=None, segment_enable=False,
        connect_timeout=20, read_timeout=20, auth_val=None, run_timeout=60,
        check_off_host=True):
        exception = None
        if not cmd:
            return
        if check_off_host:
            if base_rest_url in self.off_host:
                LOG.debug("It ignores running the cli(%s) because the url(%s) cannot be connected."\
                    % (cmd, base_rest_url))
                return
        url = base_rest_url + '/cli_extend'  #need verify
        payload = {
            "cmd": cmd,
            "timeout": run_timeout
        }
        LOG.debug("Run the URL: --%s--", url)
        LOG.debug("Run the CLI: --%s--", cmd)
        conn_max_retries = 1
        auth_value = self.get_auth()
        if auth_val:
            auth_value = auth_val
        if not segment_enable and not auth_val:
            auth_value = self.get_segment_auth(va_name)
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
                    return r
            except (requests.ConnectionError, requests.Timeout) as e:
                exception = e
                LOG.warning("Could not connect to instance. Retrying.")

        LOG.error("Connection retries (currently set to %(max_retries)s) "
                  "exhausted.  The apv is unavailable. Reason: "
                  "%(exception)s",
                  {'max_retries': conn_max_retries,
                   'exception': exception})
        return None



    def find_available_cluster_id(self, context, lb_name):
        cluster_ids = self.plugin_rpc.get_clusterids_by_lb(context, lb_name)
        if not cluster_ids:
            LOG.error("Failed to get the cluster_id")
            return -1
        LOG.debug("get the cluster ids (%s)", cluster_ids)
        return cluster_ids[0]


    def write_memory(self, argu=None, segment_enable=False):
        cmd_apv_write_memory = ADCDevice.write_memory()
        va_name = self.get_va_name(argu)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_write_memory, va_name, segment_enable)


    def init_array_device(self):
        if len(self.hostnames) > 1:
            for idx, hostname in enumerate(self.hostnames):
                try:
                    ha_status = self.get_ha_status(idx)
                    if not ha_status:
                        LOG.debug("The HA is off in the device(%s)" % hostname)
                        self.init_one_array_device(idx)
                    else:
                        LOG.debug("The HA is on in the device(%s), ignore to \
                            init the device" % hostname)
                except Exception:
                    LOG.debug("Failed to get ha status...%s" % traceback.format_exc())
        elif len(self.hostnames) == 1:
            try:
                support_exist = self.show_support()
                if not support_exist:
                    LOG.debug("The support configuration is not in the device(%s)" % self.hostnames[0])
                    self.init_single_device()
                else:
                    LOG.debug("The support configuration is in the device(%s), ignore to \
                        init the single device" % self.hostnames[0])
            except Exception:
                LOG.debug("Failed to get support configuration...%s" % traceback.format_exc())

    def check_vlan_existed_in_device(self, vlan_tag):
        device_name = "vlan." + str(vlan_tag)
        cmd_show_interface = ADCDevice.show_interface(device_name)
        for base_rest_url in self.base_rest_urls:
            r = self.run_cli_extend(base_rest_url, cmd_show_interface,
                segment_enable=self.segment_enable)
            if not r:
                continue
            if device_name in r.text:
                return True
        return False

    def create_port_for_subnet(self, subnet_id, vlan_tag = None, lb_id = None):
        '''
        The function should be invoked when create loadbalance and member.
        '''
        if not subnet_id or not lb_id:
            LOG.debug("The argument for create_port_for_subnet isn't right.")
            return False

        port_name = subnet_id + "_port"
        hostname = cfg.CONF.arraynetworks.agent_host
        ret_vlan_tag = vlan_tag
        subnet_port = None

        if ret_vlan_tag is None:
            ret_ports = self.plugin_rpc.get_port_by_name(self.context, port_name)
            if len(ret_ports) > 0:
                subnet_port = ret_ports[0]
                port_id = subnet_port['id']
                ret_vlan = self.plugin_rpc.get_vlan_id_by_port_huawei(self.context, port_id)
                ret_vlan_tag = ret_vlan['vlan_tag']
                if ret_vlan_tag == '-1':
                    LOG.debug("Cannot get the vlan_tag by port_id(%s)", port_id)
                    return False
                else:
                    LOG.debug("Got the vlan_tag(%s) by port_id(%s)", ret_vlan_tag, port_id)
                    if self.check_vlan_existed_in_device(ret_vlan_tag):
                        LOG.debug("The port has been created in device, ignore to create port")
                        return True
            else:
                LOG.debug("Cannot to get port by name(%s), creating the port" % port_name)
                subnet_port = self.plugin_rpc.create_port_on_subnet(self.context,
                    subnet_id, port_name, hostname, lb_id)
        else:
            if self.check_vlan_existed_in_device(ret_vlan_tag):
                LOG.debug("The port has been created in device, ignore to create port")
                return True
            subnet_port = self.plugin_rpc.create_port_on_subnet(self.context,
                subnet_id, port_name, hostname, lb_id)


        ret_vlan_tag = str(ret_vlan_tag)
        device_name = "vlan." + ret_vlan_tag
        interface_name = self.plugin_rpc.get_interface(self.context)

        cmd_vlan_device = ADCDevice.vlan_device(interface_name, device_name, vlan_tag)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_vlan_device,
                segment_enable=self.segment_enable)


    def delete_port_for_subnet(self, subnet_id, vlan_tag = None,
        lb_id_filter=None, member_id_filter=None):
        '''
        The function should be invoked when delete loadbalance and delete member.
        When delete delete loadbalance, the lb_id_filter should be filled and should be
        the id of the loadbalancer which will be deleted.
        When delete delete member, the member_id_filter should be filled and should be
        the id of the member which will be deleted.
        '''
        if not subnet_id:
            LOG.error("The argument for delete_port_for_subnet isn't right.")
            return False

        port_name = subnet_id + "_port"
        if vlan_tag is None:
            ret_ports = self.plugin_rpc.get_port_by_name(self.context, port_name)
            if len(ret_ports) > 0:
                port_id = ret_ports[0]['id']
                ret_vlan = self.plugin_rpc.get_vlan_id_by_port_huawei(self.context, port_id)
                vlan_tag = ret_vlan['vlan_tag']
                if vlan_tag == '-1':
                    LOG.debug("Cannot get the vlan_tag by port_id(%s)", port_id)
                    return False
                else:
                    LOG.debug("Got the vlan_tag(%s) by port_id(%s)", vlan_tag, port_id)
            else:
                LOG.debug("Cannot to get port by name(%s)" % port_name)
                return True

        res_count = self.plugin_rpc.check_subnet_used(self.context,
            subnet_id, lb_id_filter, member_id_filter)
        if not res_count:
            LOG.debug("Failed to get the res count.")
            return False
        if res_count['count'] >= 1:
            LOG.debug("The port is still used by other resource, ignore to delete it")
            return True

        device_name = "vlan." + vlan_tag
        cmd_no_ip = ADCDevice.no_ip(device_name)
        cmd_no_ip_v6 = ADCDevice.no_ip(device_name, version=6)
        cmd_no_vlan_device = ADCDevice.no_vlan_device(device_name)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_no_ip,
                segment_enable=self.segment_enable)
            self.run_cli_extend(base_rest_url, cmd_no_ip_v6,
                segment_enable=self.segment_enable)
            self.run_cli_extend(base_rest_url, cmd_no_vlan_device,
                segment_enable=self.segment_enable)
        self.plugin_rpc.delete_port_by_name(self.context, port_name)


    def init_one_array_device(self, cur_idx):
        base_rest_url = self.base_rest_urls[cur_idx]
        cmd_ha_ssf_timeout = ADCDevice.ha_ssf_timeout(3600)
        self.run_cli_extend(base_rest_url, cmd_ha_ssf_timeout, segment_enable=self.segment_enable)
        cmd_load_error_page = ADCDevice.load_http_error_page()
        self.run_cli_extend(base_rest_url, cmd_load_error_page, segment_enable=self.segment_enable)
        cmd_support_enable = ADCDevice.support_enable()
        self.run_cli_extend(base_rest_url, cmd_support_enable, segment_enable=self.segment_enable)
        tcpidle_value = 3600
        cmd_set_tcpidle = ADCDevice.set_tcpidle(tcpidle_value)
        self.run_cli_extend(base_rest_url, cmd_set_tcpidle, segment_enable=self.segment_enable)
        #monitor vcondition
        bonds = self.plugin_rpc.get_all_interfaces(self.context)
        for bond in bonds:
            idx = int(bond[4:])
            cmd_monitor_vcondition_name = ADCDevice.monitor_vcondition_name_apv(idx)
            port_list = self.plugin_rpc.get_interface_port(self.context, bond)
            if not port_list:
                LOG.error("Got the error port list by bond %s", bond)
                return
            cmd_monitor_vcondition_member = ADCDevice.monitor_vcondition_member_apv(idx, port_list)
            self.run_cli_extend(base_rest_url, cmd_monitor_vcondition_name, None, self.segment_enable)
            for cli in cmd_monitor_vcondition_member:
                self.run_cli_extend(base_rest_url, cli, segment_enable=self.segment_enable)

        for idx, hostname in enumerate(self.hostnames):
            unit_name = "unit_"
            if idx == 0:
                unit_name = "unit_m"
            elif idx == 1:
                unit_name = "unit_s"
            cmd_ha_unit = ADCDevice.ha_unit(unit_name, hostname, 65521)
            cmd_synconfig_peer = ADCDevice.synconfig_peer(unit_name, hostname)
            self.run_cli_extend(base_rest_url, cmd_ha_unit, segment_enable=self.segment_enable)
            self.run_cli_extend(base_rest_url, cmd_synconfig_peer, segment_enable=self.segment_enable)
        peer_ip_address = self.hostnames[1]
        if cur_idx == 1:
            peer_ip_address = self.hostnames[0]
        cmd_ha_link_network_on = ADCDevice.ha_link_network_on()
        cmd_ssh_ip = ADCDevice.ssh_ip(self.hostnames[cur_idx])
        cmd_ha_ssf_peer = ADCDevice.ha_ssf_peer(peer_ip_address)
        cmd_ha_ssf_on = ADCDevice.ha_ssf_on()
        cmd_ha_link_ffo_on = ADCDevice.ha_link_ffo_on()
        cmd_ha_synconfig_bootup_on = ADCDevice.ha_synconfig_bootup_on()
        cmd_ha_on = ADCDevice.ha_on()
        cmd_apv_write_memory = ADCDevice.write_memory()
        if self.net_seg_enable:
            cmd_segment = ADCDevice.segment_enable()
        else:
            cmd_segment = ADCDevice.segment_disable()
        self.run_cli_extend(base_rest_url, cmd_ha_link_network_on, segment_enable=self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ssh_ip, segment_enable=self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_ssf_peer, segment_enable=self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_ssf_on, segment_enable=self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_link_ffo_on, segment_enable=self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_synconfig_bootup_on, segment_enable=self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_on, segment_enable=self.segment_enable)
        time.sleep(10)
        self.run_cli_extend(base_rest_url, cmd_segment, segment_enable=self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_apv_write_memory, segment_enable=self.segment_enable)


    def init_single_device(self):
        base_rest_url = self.base_rest_urls[0]
        cmd_load_error_page = ADCDevice.load_http_error_page()
        self.run_cli_extend(base_rest_url, cmd_load_error_page, segment_enable=self.segment_enable)
        cmd_support_enable = ADCDevice.support_enable()
        self.run_cli_extend(base_rest_url, cmd_support_enable, segment_enable=self.segment_enable)
        tcpidle_value = 3600
        cmd_set_tcpidle = ADCDevice.set_tcpidle(tcpidle_value)
        self.run_cli_extend(base_rest_url, cmd_set_tcpidle, segment_enable=self.segment_enable)
        cmd_ssh_ip = ADCDevice.ssh_ip(self.hostnames[0])
        self.run_cli_extend(base_rest_url, cmd_ssh_ip, segment_enable=self.segment_enable)
        if self.net_seg_enable:
            cmd_segment = ADCDevice.segment_enable()
        else:
            cmd_segment = ADCDevice.segment_disable()
        self.run_cli_extend(base_rest_url, cmd_segment, segment_enable=self.segment_enable)
        cmd_apv_write_memory = ADCDevice.write_memory()
        self.run_cli_extend(base_rest_url, cmd_apv_write_memory, segment_enable=self.segment_enable)
        LOG.debug("Successful download init configuration for single host %s", self.hostnames[0])

    def get_all_health_status(self, va_name, lb_id):
        status_dic = {}
        host_dic = {}
        cmd_get_status = ADCDevice.get_health_status()
        auth_val = (va_name, self.segment_user_passwd)
        for idx, base_rest_url in enumerate(self.base_rest_urls):
            r = self.run_cli_extend(base_rest_url, cmd_get_status, va_name, auth_val=auth_val)
            # TODO: the logical should be reviewed.
            if not r:
                continue
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
            all_status = self.get_all_health_status(va_name, lb_id)
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

    def reset_off_host(self):
        cmd_show_ip_addr = ADCDevice.show_ip_addr()
        LOG.debug("Current self.off_host is %s" % self.off_host)
        for base_rest_url in self.base_rest_urls:
            status = self.run_cli_extend(base_rest_url, cmd_show_ip_addr,
                segment_enable=self.segment_enable, check_off_host=False)
            if not status:
                if base_rest_url not in self.off_host:
                    self.off_host.append(base_rest_url)
                    LOG.debug("Append %s into off_host(%s)", base_rest_url, self.off_host)
            else:
                if base_rest_url in self.off_host:
                    self.off_host = [url for url in self.off_host if url != base_rest_url]
                    LOG.debug("Removed %s into off_host(%s)", base_rest_url, self.off_host)

    def get_restful_status(self, base_rest_url):
        cmd_show_ip_addr = ADCDevice.show_ip_addr()
        status = None
        try:
            status = self.run_cli_extend(base_rest_url, cmd_show_ip_addr,
                segment_enable=self.segment_enable, check_off_host=False)
        except Exception:
            return False
        if not status:
            return False
        return True

    def get_vlan_tag_by_port_name(self, port_name):
        ret_ports = self.plugin_rpc.get_port_by_name(self.context, port_name)
        if len(ret_ports) > 0:
            port_id = ret_ports[0]['id']
            ret_vlan = self.plugin_rpc.get_vlan_id_by_port_huawei(self.context, port_id)
            vlan_tag = ret_vlan['vlan_tag']
            if vlan_tag == '-1':
                LOG.debug("Cannot get the vlan_tag by port_id(%s)", port_id)
                return False
            else:
                LOG.debug("Got the vlan_tag(%s) by port_id(%s)", vlan_tag, port_id)
                return vlan_tag
        LOG.debug("Cannot to get port by name(%s)" % port_name)
        return -1


    def check_segment_existed_in_device(self, base_rest_url, segment_name):
        cmd_show_segment = ADCDevice.show_segment()
        r = self.run_cli_extend(base_rest_url, cmd_show_segment,
            segment_enable=self.segment_enable)
        if not r:
            return False
        if segment_name not in r.text:
            return False
        return True


    def check_segment_existed_in_devices(self, segment_name):
        cmd_show_segment = ADCDevice.show_segment()
        for base_rest_url in self.base_rest_urls:
            r = self.run_cli_extend(base_rest_url, cmd_show_segment,
                segment_enable=self.segment_enable)
            if not r:
                continue
            if segment_name not in r.text:
                return False
        return True


    def get_all_segments_in_one_device(self, base_rest_url):
        cmd_show_segment = ADCDevice.show_segment()
        r = self.run_cli_extend(base_rest_url, cmd_show_segment,
            segment_enable=self.segment_enable)
        if not r:
            return None
        else:
            res_dict = json.loads(r.text)
            return parse_segment_name_result(res_dict['contents'])

    def parse_bond_name_from_device(self, idx, vlan_name):
        base_rest_url = self.base_rest_urls[idx]
        cmd_show_vlan = ADCDevice.show_vlan()
        r = self.run_cli_extend(base_rest_url, cmd_show_vlan,
            segment_enable=self.segment_enable)
        if not r:
            return None
        else:
            res_dict = json.loads(r.text)
            return parse_vlan_result(res_dict['contents'], vlan_name)


    def recovery_segment_configuration(self, idx):
        try:
            lb_ids = self.plugin_rpc.get_loadbalancer_ids(self.context)
            if not lb_ids:
                LOG.debug("No any loadbalancer in our current environment.")
                return True
            base_rest_url = self.base_rest_urls[idx]
            if not self.net_seg_enable:
                for lb_id, subnet_id, vip_address in lb_ids:
                    ret_segment_name = self.plugin_rpc.get_segment_name_by_lb_id(self.context, lb_id)
                    segment_name = ret_segment_name['segment_name']
                    if len(segment_name) == 0:
                        LOG.debug("Failed to get the segment name by lb_id(%s)" % lb_id)
                        continue
                    if self.check_segment_existed_in_device(base_rest_url, segment_name):
                        LOG.debug("The segment(%s) has existed." % segment_name)
                        continue
                    port_name = segment_name + "_" + str(idx)
                    ret_ports = self.plugin_rpc.get_port_by_name(self.context, port_name)
                    if len(ret_ports) > 0:
                        port_id = ret_ports[0]['id']
                        ret_vlan = self.plugin_rpc.get_vlan_id_by_port_huawei(self.context, port_id)
                        vlan_tag = ret_vlan['vlan_tag']
                        if vlan_tag == '-1':
                            LOG.debug("Cannot get the vlan_tag by port_name(%s)", port_name)
                            continue
                        else:
                            LOG.debug("Got the vlan_tag(%s) by port_name(%s)", vlan_tag, port_name)
                            device_name = "vlan." + vlan_tag
                            interface_name = self.parse_bond_name_from_device((1 - idx), device_name)
                            if not interface_name:
                                LOG.debug("Failed to parse to get bond name.")
                                continue
                            cmd_vlan_device = ADCDevice.vlan_device(interface_name, device_name, vlan_tag)
                            self.run_cli_extend(base_rest_url, cmd_vlan_device,
                                segment_enable=self.segment_enable)
                            ip_address = ret_ports[0]['fixed_ips'][0]['ip_address']
                            subnet = self.plugin_rpc.get_subnet(self.context, subnet_id)
                            vip_network = netaddr.IPNetwork(subnet['cidr'])
                            netmask = str(vip_network.netmask)
                            if vip_network.version == 6:
                                idx = subnet['cidr'].find('/')
                                netmask = subnet['cidr'][idx+1:]
                            cmd_configure_ip = ADCDevice.configure_ip(device_name, ip_address, netmask)
                            self.run_cli_extend(base_rest_url, cmd_configure_ip,
                                segment_enable=self.segment_enable)
                    else:
                        LOG.debug("Cannot to get port by name(%s)" % port_name)
                        continue
                    self._create_segment_config(base_rest_url, segment_name)
            else:
                for lb_id, subnet_id, vip_address in lb_ids:
                    ret_segment_name = self.plugin_rpc.get_segment_name_by_lb_id(self.context, lb_id)
                    segment_name = ret_segment_name['segment_name']
                    if len(segment_name) == 0:
                        LOG.debug("Failed to get the segment name by lb_id(%s)" % lb_id)
                        continue
                    if self.check_segment_existed_in_device(base_rest_url, segment_name):
                        LOG.debug("The segment(%s) has existed." % segment_name)
                        continue
                    port_name = segment_name + "_" + str(idx)
                    ret_ports = self.plugin_rpc.get_port_by_name(self.context, port_name)
                    if len(ret_ports) > 0:
                        port_id = ret_ports[0]['id']
                        ret_vlan = self.plugin_rpc.get_vlan_id_by_port_huawei(self.context, port_id)
                        vlan_tag = ret_vlan['vlan_tag']
                        if vlan_tag == '-1':
                            LOG.debug("Cannot get the vlan_tag by port_name(%s)", port_name)
                            continue
                        else:
                            LOG.debug("Got the vlan_tag(%s) by port_name(%s)", vlan_tag, port_name)
                            device_name = "vlan." + vlan_tag
                            interface_name = self.parse_bond_name_from_device((1 - idx), device_name)
                            if not interface_name:
                                LOG.debug("Failed to parse to get bond name.")
                                continue
                            cmd_vlan_device = ADCDevice.vlan_device(interface_name, device_name, vlan_tag)
                            self.run_cli_extend(base_rest_url, cmd_vlan_device,
                                segment_enable=self.segment_enable)
                            self._create_segment_config(base_rest_url, segment_name)
                            self._segment_interface(base_rest_url, vlan_tag, segment_name, None, interface_name)
                            #config segment ip address
                            ip_address = ret_ports[0]['fixed_ips'][0]['ip_address']
                            subnet = self.plugin_rpc.get_subnet(self.context, subnet_id)
                            vip_network = netaddr.IPNetwork(subnet['cidr'])
                            netmask = str(vip_network.netmask)
                            if vip_network.version == 6:
                                idx = subnet['cidr'].find('/')
                                netmask = subnet['cidr'][idx+1:]
                            internal_ip = self.plugin_rpc.get_internal_ip_by_lb(self.context, segment_name, vip_address)
                            if not internal_ip:
                                LOG.error("Failed to find the internal ip by segment name(%s) and segment ip(%s)" % (segment_name, vip_address))
                                return
                            cmd_apv_config_ip = ADCDevice.configure_segment_ip(interface_name, ip_address, netmask, internal_ip)
                            self.run_cli_extend(base_rest_url, cmd_apv_config_ip,
                                segment_enable=self.segment_enable)
                            #config default route
                            cmd_apv_config_route = ADCDevice.configure_route(subnet['gateway_ip'])
                            self.run_cli_extend(base_rest_url, cmd_apv_config_route,
                                segment_enable=self.segment_enable)
                            #add segment nat
                            cmd_show_segment_nat = ADCDevice.show_segment_nat(segment_name)
                            result = self.run_cli_extend(self.base_rest_urls[1 - idx], cmd_show_segment_nat,
                                segment_enable=self.segment_enable)
                            if not result:
                                LOG.debug("Failed to get segment nat from the host %s", self.hostnames[1 - idx])
                                return None
                            else:
                                res_dict = json.loads(result.text)
                                segment_nat_cmds = parse_segment_nat_result(res_dict['contents'])
                                for segment_nat_cmd in segment_nat_cmds:
                                    self.run_cli_extend(self.base_rest_urls[idx], segment_nat_cmd,
                                        segment_enable=self.segment_enable)
                    self.synconfig_from_segment(base_rest_url, idx, segment_name)
            cmd_write_memory = ADCDevice.write_memory()
            self.run_cli_extend(base_rest_url, cmd_write_memory, segment_enable=self.segment_enable)
            cmd_write_segment_memory = ADCDevice.write_segment_memory()
            self.run_cli_extend(base_rest_url, cmd_write_segment_memory, segment_enable=self.segment_enable)
        except Exception:
            LOG.debug("failed to recovery segment configuration: %s" % traceback.format_exc())


    def get_ha_status(self, idx):
        base_rest_url = self.base_rest_urls[idx]
        cmd_show_ha_config = ADCDevice.show_ha_config()
        r = self.run_cli_extend(base_rest_url, cmd_show_ha_config,
            segment_enable=self.segment_enable, connect_timeout=180, read_timeout=180)
        if "ha off" in r.text:
            LOG.debug("The HA is disabled on the host(%s): %s" % (self.hostnames[idx], r.text))
            return False
        return True

    def show_support(self):
        base_rest_url = self.base_rest_urls[0]
        cmd_show_support = ADCDevice.show_support()
        r = self.run_cli_extend(base_rest_url, cmd_show_support, segment_enable=self.segment_enable)
        if "support" not in r.text:
            LOG.debug("The support config is not in the host(%s): %s" % (self.hostnames[0], r.text))
            return False
        return True

    def find_active_host(self, host_filter_idx):
        for idx, base_rest_url in enumerate(self.base_rest_urls):
            if idx == host_filter_idx:
                continue
            host_status = self.get_restful_status(base_rest_url)
            if host_status:
                return idx
        return -1

    def synconfig_from(self, base_rest_url, cur_idx):
        peer_name = "unit_s"
        if cur_idx == 1:
            peer_name = "unit_m"
        cmd_synconfig_from_peer = ADCDevice.synconfig_from_peer(peer_name)
        self.run_cli_extend(base_rest_url, cmd_synconfig_from_peer,
            run_timeout=600, segment_enable=self.segment_enable)

    def synconfig_from_segment(self, base_rest_url, cur_idx, segment_name):
        peer_name = "unit_s"
        if cur_idx == 1:
            peer_name = "unit_m"
        cmd_synconfig_from_segment = ADCDevice.synconfig_from_segment(peer_name, segment_name)
        self.run_cli_extend(base_rest_url, cmd_synconfig_from_segment,
            run_timeout=600, segment_enable=self.segment_enable)

    def get_vlan_conf_by_segment(self, base_rest_url, segment_name):
        """ get VLAN config by segment name in one device"""
        if not base_rest_url and not segment_name:
            LOG.error("Lack of configuration base_rest_url or segment_name")
            return
        cmd_get_segment_interface = ADCDevice.show_segment_interface(segment_name)
        result = self.run_cli_extend(base_rest_url, cmd_get_segment_interface,
            segment_enable=self.segment_enable)
        res_dict = json.loads(result.text)
        return parse_vlan_by_seg_if(res_dict['contents'])


    def delete_redundant_segment_configuration(self):
        try:
            if redundant_segments:
                self.reset_off_host()
                need_write_memory = False
                base_rest_url = ""
                for segment_name in redundant_segments.keys():
                    if redundant_segments[segment_name]["times"] < 3:
                        redundant_segments[segment_name]["times"] += 1
                        continue
                    else:
                        LOG.debug("Will delete the redundant segment %s", segment_name)
                        need_write_memory = True
                        idx = redundant_segments[segment_name]["url_idx"]
                        base_rest_url = self.base_rest_urls[idx]
                        vlan_ifname = self.get_vlan_conf_by_segment(self.base_rest_urls[1 - idx], segment_name)
                        cmd_delete_segment = ADCDevice.delete_segment(segment_name)
                        self.run_cli_extend(base_rest_url, cmd_delete_segment, segment_enable=self.segment_enable)
                        cmd_delete_segment_user = ADCDevice.delete_segment_user(segment_name[:10] + "_api")
                        self.run_cli_extend(base_rest_url, cmd_delete_segment_user, segment_enable=self.segment_enable)
                        if vlan_ifname:
                            cmd_delete_vlan_device = ADCDevice.no_vlan_device(vlan_ifname)
                            self.run_cli_extend(base_rest_url, cmd_delete_vlan_device, segment_enable=self.segment_enable)
                        redundant_segments.pop(segment_name)
                        #delete vlan device
                if need_write_memory:
                    cmd_write_memory = ADCDevice.write_memory()
                    self.run_cli_extend(base_rest_url, cmd_write_memory, segment_enable=self.segment_enable)
        except Exception:
            LOG.debug("Failed to delete redundant segments configuration: %s" % traceback.format_exc())

    def get_all_segment_names_by_lbs(self, lb_ids):
        if lb_ids is None:
            LOG.error("Lack of configuration lb_ids")
            return
        segment_names = []

        if isinstance(lb_ids, list):
            for lb_id, subnet_id, vip_address in lb_ids:
                ret_segment_name = self.plugin_rpc.get_segment_name_by_lb_id(self.context, lb_id)
                segment_name = ret_segment_name['segment_name']
                segment_names.append(segment_name)
        else:
            ret_segment_name = self.plugin_rpc.get_segment_name_by_lb_id(self.context, lb_ids)
            segment_name = ret_segment_name['segment_name']
            segment_names.append(segment_name)
        return segment_names

    def scan_redundant_segment_config(self, idx):
        try:
            need_del_segment_names = []
            base_rest_url = self.base_rest_urls[idx]
            segment_names = self.get_all_segments_in_one_device(base_rest_url)
            lb_ids = self.plugin_rpc.get_loadbalancer_ids(self.context)
            if not lb_ids:
                LOG.debug("No any loadbalancer in our current environment.")
                need_del_segment_names = segment_names
            else:
                segment_name_in_db = self.get_all_segment_names_by_lbs(lb_ids)
                need_del_segment_names = list(set(segment_names).difference(set(segment_name_in_db)))
            #delete the residual segment
            LOG.debug("scanf segment config result: segments(%s) are redundant", need_del_segment_names)
            if not need_del_segment_names:
                return
            global redundant_segments
            for need_del_segment_name in need_del_segment_names:
                if redundant_segments.has_key(need_del_segment_name):
                    redundant_segments[need_del_segment_name]["times"] += 1
                else:
                    info = {}
                    info["times"] = 1
                    info["url_idx"] = idx
                    redundant_segments[need_del_segment_name] = info
            LOG.debug("after scanf, the redundant_segments are (%s)", redundant_segments)

        except Exception:
            LOG.debug("Failed to scanf segment configuration: %s" % traceback.format_exc())


    def recovery_lbs_configuration(self):
        if len(self.hostnames) <= 1:
            LOG.debug("It can't build the HA environment.")
            return True

        active_agents = self.plugin_rpc.get_active_agents(self.context)
        master_agent = active_agents[0]
        agent_host = cfg.CONF.arraynetworks.agent_host
        if master_agent['host'] != agent_host:
            LOG.debug("master_host(%s) is not current agent_host(%s), exiting" % (master_agent['host'], agent_host))
            return True

        global g_off_hosts
        self.reset_off_host()
        LOG.debug("It will check the status of Host, current off hosts is : %s" % g_off_hosts)
        for idx, base_rest_url in enumerate(self.base_rest_urls):
            host_status = self.get_restful_status(base_rest_url)
            hostname = self.hostnames[idx]
            if not host_status:
                LOG.debug("Failed to connect the host(%s)" % hostname)
                if hostname not in g_off_hosts:
                    g_off_hosts.append(hostname)
                    LOG.debug("Append the host(%s) into off_host(%s)" % (hostname, g_off_hosts))
            else:
                if hostname in g_off_hosts:
                    LOG.debug("Host(%s) is currently ON, but it is still on the \
                        g_off_hosts(%s)" % (hostname, g_off_hosts))
                    status = self.get_ha_domain_status(idx)
                    if not status:
                        LOG.debug("The current status is NOT UP, so ignore to sync LB configuration.")
                        continue
                    else:
                        LOG.debug("The current status is UP, will sync LB configuration.")
                    active_idx = self.find_active_host(host_filter_idx=idx)
                    if active_idx != -1:
                        LOG.debug("Recovery segment configuration ...")
                        self.recovery_segment_configuration(1-active_idx)
                        LOG.debug("It synconfig from host(%d:%s)" % (active_idx,
                            self.hostnames[active_idx]))
                        self.scan_redundant_segment_config(1-active_idx)
                    else:
                        LOG.debug("Can't find any active host except the host(%s), so failed to \
                            synconfig", hostname)
                    g_off_hosts.remove(hostname)


    def update_member_status(self, agent_host_name):
        self.reset_off_host()
        lb_members = self.plugin_rpc.get_members_status_on_agent(self.context,
            agent_host_name)
        lb_members_ori = copy.deepcopy(lb_members)
        LOG.debug("lb_members_ori: ----%s----" % lb_members_ori)
        lb_members = self.get_status_by_lb_mems(lb_members)
        LOG.debug("lb_members: ----%s----" % lb_members)
        for lb_id, lb_members_status in lb_members_ori.items():
            for member_id, member_status in lb_members_status.items():
                new_member_status = lb_members[lb_id][member_id]
                LOG.debug("new_member_status(%s)---member_status(%s)" % (new_member_status, member_status))
                if new_member_status != member_status:
                    LOG.debug("--------will update_member_status -------")
                    self.plugin_rpc.update_member_status(self.context,
                        member_id, new_member_status)

    def get_ha_domain_status(self, idx):
        base_rest_url = self.base_rest_urls[idx]
        unit_name = "unit_m"
        if idx == 1:
            unit_name = "unit_s"
        cmd_show_ha_status_domain = ADCDevice.show_ha_status_domain()
        try:
            r = self.run_cli_extend(base_rest_url, cmd_show_ha_status_domain,
                segment_enable=self.segment_enable)
        except Exception:
            return False
        if r:
            res_dict = json.loads(r.text)
            result = res_dict['contents']
            for line in result.split('\n'):
                if (unit_name in line) and ('UP' in line):
                    return True
        return False


