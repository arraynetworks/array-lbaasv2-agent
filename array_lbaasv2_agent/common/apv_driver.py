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
import copy
import netaddr
from oslo_config import cfg
from array_lbaasv2_agent.common.array_driver import ArrayCommonAPIDriver
from array_lbaasv2_agent.common.adc_device import ADCDevice
from array_lbaasv2_agent.common.adc_device import is_driver_apv
from array_lbaasv2_agent.common import exceptions as driver_except
from neutron_lbaas.services.loadbalancer import constants as lb_const

LOG = logging.getLogger(__name__)

off_hosts = []

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
        self.net_seg_enable = cfg.CONF.arraynetworks.net_seg_enable


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


    def _create_vlan_device(self, base_rest_urls, vlan_tag, va_name, in_interface):
        cmd_apv_config_vlan = None

        if vlan_tag:
            interface_name = "vlan." + vlan_tag
            cmd_apv_config_vlan = ADCDevice.vlan_device(in_interface, interface_name, vlan_tag)
        else:
            LOG.error("Lack of configuration vlan_tag")
            return
        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                if vlan_tag:
                    self.run_cli_extend(base_rest_url, cmd_apv_config_vlan, va_name, self.segment_enable)
        else:
            if vlan_tag:
                self.run_cli_extend(base_rest_urls, cmd_apv_config_vlan, va_name, self.segment_enable)


    def _segment_interface(self, base_rest_urls, vlan_tag, segment_name, va_name, in_interface):
        interface_name = in_interface

        if vlan_tag:
            interface_name = "vlan." + vlan_tag
        else:
            LOG.error("Lack of configuration vlan_tag")
            return
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

        va_name = self.get_va_name(argu)
        pri_port_id = None
        sec_port_id = None
        lb_name = argu['vip_id']  #need verify
        self.segment_user_name = argu['vip_id'][:15]  #limit user length is 15
        self.segment_name = lb_name
        if not self.net_seg_enable:
            self.create_port_for_subnet(argu['subnet_id'], argu['vlan_tag'], lb_name)
        interface = self.plugin_rpc.get_interface(self.context)
        if not interface:
            LOG.error("Failed to get the interface from driver get_interface")
            return
        # create segment name and user and interface
        self._create_segment(self.base_rest_urls, lb_name, va_name)
        self._create_segment_user(self.base_rest_urls, lb_name, va_name)
        # create vip
        vlan_tag = 0
        if len(self.hostnames) == 1:
            if self.net_seg_enable:
                self._create_vlan_device(self.base_rest_urls, argu['vlan_tag'], va_name, interface)
            if self.net_seg_enable:
                self._segment_interface(self.base_rest_urls, argu['vlan_tag'], lb_name, va_name, interface)
            self._create_vip(self.base_rest_urls, argu['ip_address'],
                argu['netmask'], argu['vlan_tag'], argu['gateway'], va_name, lb_name, interface)
            self.write_memory(argu, self.segment_enable)
        else:
            vlan_tag_map = self.plugin_rpc.generate_tags(self.context)
            if vlan_tag_map:
                vlan_tag  = vlan_tag_map['vlan_tag']
            if self.net_seg_enable:
                self._create_vlan_device(self.base_rest_urls, str(vlan_tag), va_name, interface)
                self._segment_interface(self.base_rest_urls, str(vlan_tag), lb_name, va_name, interface)
            interface_mapping = argu['interface_mapping']
            unit_list = []
            pool_name = "pool_" + argu['vip_id']
            for idx, host in enumerate(self.hostnames):
                unit_item = {}
                ip_address = interface_mapping[host]['address']
                unit_item['ip_address'] = ip_address
                if idx == 0:
                    unit_item['priority'] = 100
                    unit_item['name'] = "unit_m"
                    pri_port_id = interface_mapping[host]['port_id']
                elif idx == 1:
                    sec_port_id = interface_mapping[host]['port_id']
                    unit_item['name'] = "unit_s"
                    unit_item['priority'] = 90
                base_rest_url = self.base_rest_urls[idx]
                self._create_vip(base_rest_url, ip_address, argu['netmask'],
                   argu ['vlan_tag'], argu['gateway'], va_name, lb_name, interface)
                unit_list.append(unit_item)

            self.plugin_rpc.create_vapv(self.context, lb_name[:10], argu['vip_id'],
                    argu['subnet_id'], in_use_lb=1, pri_port_id=pri_port_id,
                    sec_port_id=sec_port_id, cluster_id=vlan_tag)
            for base_rest_url in self.base_rest_urls:
                self.configure_ha(base_rest_url, unit_list,
                    argu['vip_address'], argu['vlan_tag'], lb_name, pool_name, 
                    argu['pool_address'], va_name, self.context, argu['subnet_id'],
                    interface)
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
                    unit_item['name'] = "unit_m"
                elif idx == 1:
                    unit_item['name'] = "unit_s"
                unit_list.append(unit_item)
            for base_rest_url in self.base_rest_urls:
                self.clear_ha(base_rest_url, unit_list, argu['vip_address'], va_name, lb_name, self.context, argu['subnet_id'])
                self.delete_port_for_subnet(argu['subnet_id'], argu['vlan_tag'], lb_id_filter=lb_name)
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
        self._delete_segment_user(self.base_rest_urls, va_name)
        if self.net_seg_enable:
            self._delete_vip(str(argu['vlan_tag']), va_name)
        else:
            self.delete_port_for_subnet(argu['subnet_id'], argu['vlan_tag'], lb_id_filter=lb_name)


    def _create_vip(self, base_rest_urls, vip_address, netmask, vlan_tag, gateway, va_name, lb_name, in_interface):
        """ create vip"""

        interface_name = in_interface

        LOG.debug("Configure the vip address into interface")
        if vlan_tag:
            interface_name = "vlan." + vlan_tag
        segment_name = lb_name
        segment_ip = vip_address
        if self.net_seg_enable:
            internal_ip = self.plugin_rpc.get_available_internal_ip(self.context, segment_name, segment_ip)
            if internal_ip == 0:
                LOG.error("Failed to get available internal ip address")
                return
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
            self.write_memory(segment_enable=self.segment_enable)


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
            self.write_memory(segment_enable=self.segment_enable)


    def create_member(self, argu):
        """ create a member"""

        if not argu:
            LOG.error("In create_member, it should not pass the None.")
            return
        va_name = self.get_va_name(argu)

        member_address = argu['member_address']
        ip_version = IPy.IP(member_address).version()
        netmask = 32 if ip_version == 4 else 128
        if not self.net_seg_enable:
            self.create_port_for_subnet(argu['subnet_id'], argu['vlan_tag'], argu['lb_id'])

        segment_name  = argu['lb_id']
        if self.net_seg_enable:
            internal_ip = self.plugin_rpc.get_available_internal_ip(self.context, segment_name, member_address, use_for_nat=True)
            if not internal_ip:
                LOG.error("Failed to get available internal ip address in func create_member")
                return
            cmd_segment_nat = ADCDevice.segment_nat(segment_name, internal_ip, member_address, netmask)
            cmd_static_route = ADCDevice.configure_route_apv(member_address, argu['netmask'], argu['gateway'])
            for base_rest_url in self.base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_segment_nat, va_name, self.segment_enable)
                self.run_cli_extend(base_rest_url, cmd_static_route, va_name)
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
            self.write_memory(argu)


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
            self.write_memory(argu)
        if not self.net_seg_enable and argu['num_of_mem'] > 1:
            self.delete_port_for_subnet(argu['subnet_id'], argu['vlan_tag'], member_id_filter=argu['member_id'])

    def configure_ha(self, base_rest_url, unit_list, vip_address,
        vlan_tag, segment_name, pool_name, pool_address, va_name, context, vip_subnet_id, in_interface):
        bond = in_interface
        if vlan_tag:
            in_interface = "vlan." + vlan_tag
        group_id = self.find_available_cluster_id(context, segment_name)
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
            priority = unit_item['priority']
            cmd_ha_group_priority = ADCDevice.ha_group_priority(unit_name, group_id, priority)
            self.run_cli_extend(base_rest_url, cmd_ha_group_priority, va_name, self.segment_enable)

        if self.net_seg_enable:
            cmd_ha_group_fip_vip = ADCDevice.ha_group_fip_apv(group_id, vip_address, segment_name, in_interface)
            cmd_ha_group_fip_pool = ADCDevice.ha_group_fip_apv(group_id, pool_address, segment_name, in_interface)
        else:
            cmd_ha_group_fip_vip = ADCDevice.ha_group_fip(group_id, vip_address, in_interface)
            cmd_ha_group_fip_pool = ADCDevice.ha_group_fip(group_id, pool_address, in_interface)           
        cmd_ha_group_preempt_on = ADCDevice.ha_group_preempt_on(group_id)
        cmd_ha_group_enable = ADCDevice.ha_group_enable(group_id)
        idx = int(bond[4:])
        cmd_ha_decision_rule = ADCDevice.ha_decision_rule_apv(idx, group_id)

        self.run_cli_extend(base_rest_url, cmd_ha_group_fip_vip, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_fip_pool, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_enable, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_preempt_on, va_name, self.segment_enable)

        self.run_cli_extend(base_rest_url, cmd_ha_decision_rule, va_name, self.segment_enable)
        self.write_memory(segment_enable=self.segment_enable)

    def clear_ha(self, base_rest_url, unit_list, vip_address, va_name, segment_name, context, vip_subnet_id):
        group_id = self.find_available_cluster_id(context, segment_name)
        if group_id == 0:
            LOG.error("Failed to find available group id")
            return
        else:
            LOG.debug("find the available group id: %d", group_id)
        cmd_delete_ha_group_id = ADCDevice.ha_no_group_id(group_id)
        self.run_cli_extend(base_rest_url, cmd_delete_ha_group_id, va_name, self.segment_enable)
        self.write_memory(segment_enable=self.segment_enable)


    def run_cli_extend(self, base_rest_url, cmd, va_name=None, segment_enable=False,
        connect_timeout=60, read_timeout=60, auth_val=None, run_timeout=60):
        exception = None
        if not cmd:
            return
        url = base_rest_url + '/cli_extend'  #need verify
        if va_name and is_driver_apv():
            cmd = "va run %s \"%s\"" % (va_name, cmd)
        payload = {
            "cmd": cmd,
            "timeout": run_timeout
        }
        LOG.debug("Run the URL: --%s--", url)
        LOG.debug("Run the CLI: --%s--", cmd)
        conn_max_retries = 2
        conn_retry_interval = 3
        auth_value = self.get_auth()
        if auth_val:
            auth_value = auth_val
        if not segment_enable and not auth_val:
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


    def find_available_cluster_id(self, context, lb_name):
        cluster_ids = self.plugin_rpc.get_clusterids_by_lb(context, lb_name)
        LOG.debug("get the cluster ids (%s)", cluster_ids)
        supported_ids = range(1, 256)
        diff_ids=list(set(supported_ids).difference(set(cluster_ids)))
        if len(diff_ids) > 1:
            return diff_ids[0]
        return 0


    def write_memory(self, argu=None, segment_enable=False):
        cmd_apv_write_memory = ADCDevice.write_memory()
        va_name = self.get_va_name(argu)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_write_memory, va_name, segment_enable)


    def init_array_device(self):
        if len(self.hostnames) > 1:
            for idx, hostname in enumerate(self.hostnames):
                ha_status = self.get_ha_status(idx)
                if not ha_status:
                    LOG.debug("The HA is off in the device(%s)" % hostname)
                    self.init_one_array_device(idx)
                else:
                    LOG.debug("The HA is on in the device(%s), ignore to \
                        init the device" % hostname)


    def check_vlan_existed_in_device(self, vlan_tag):
        device_name = "vlan." + str(vlan_tag)
        base_rest_url = self.base_rest_urls[0]
        cmd_show_interface = ADCDevice.show_interface(device_name)
        r = self.run_cli_extend(base_rest_url, cmd_show_interface)
        if device_name in r.text:
            return True
        return False

    def create_port_for_subnet(self, subnet_id, vlan_tag, lb_id):
        '''
        The function should be invoked when create loadbalance and member.
        '''
        if not subnet_id or not vlan_tag or not lb_id:
            LOG.debug("The argument for create_port_for_subnet isn't right.")
            return False
        if self.check_vlan_existed_in_device(vlan_tag):
            LOG.debug("The port has been created in device, ignore to create port")
            return True

        vlan_tag = str(vlan_tag)
        device_name = "vlan." + vlan_tag
        hostname = self.conf.arraynetworks.agent_host
        port_name = subnet_id + "_port"
        interface_name = self.plugin_rpc.get_interface(self.context)

        subnet = self.plugin_rpc.get_subnet(self.context, subnet_id)
        member_network = netaddr.IPNetwork(subnet['cidr'])
        subnet_port = self.plugin_rpc.create_port_on_subnet(self.context,
            subnet_id, port_name, hostname, lb_id)

        ip_address = subnet_port['fixed_ips'][0]['ip_address']
        netmask = str(member_network.netmask)
        if member_network.version == 6:
            idx = subnet['cidr'].find('/')
            netmask = subnet['cidr'][idx+1:]

        cmd_vlan_device = ADCDevice.vlan_device(interface_name, device_name, vlan_tag)
        cmd_configure_ip = ADCDevice.configure_ip(device_name, ip_address, netmask)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_vlan_device)
            self.run_cli_extend(base_rest_url, cmd_configure_ip)


    def delete_port_for_subnet(self, subnet_id, vlan_tag,
        lb_id_filter=None, member_id_filter=None):
        '''
        The function should be invoked when delete loadbalance and delete member.
        When delete delete loadbalance, the lb_id_filter should be filled and should be
        the id of the loadbalancer which will be deleted.
        When delete delete member, the member_id_filter should be filled and should be
        the id of the member which will be deleted.
        '''
        if not subnet_id or not vlan_tag:
            LOG.error("The argument for delete_port_for_subnet isn't right.")
            return False
        if not self.check_vlan_existed_in_device(vlan_tag):
            LOG.debug("The port wasn't created in device, ignore to delete port")
            return True

        res_count = self.plugin_rpc.check_subnet_used(self.context,
            subnet_id, lb_id_filter, member_id_filter)
        if not res_count:
            LOG.debug("Failed to get the res count.")
            return False
        if res_count['count'] >= 1:
            LOG.debug("The port is still used by other resource, ignore to delete it")
            return True

        port_name = subnet_id + "_port"
        device_name = "vlan." + vlan_tag
        cmd_no_vlan_device = ADCDevice.no_vlan_device(device_name)
        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_no_vlan_device)
        self.plugin_rpc.delete_port_by_name(self.context, port_name)


    def init_one_array_device(self, cur_idx):
        base_rest_url = self.base_rest_urls[cur_idx]
        #rts
        if not self.net_seg_enable:
            cmd_rts_enable = ADCDevice.rts_enable()
            self.run_cli_extend(base_rest_url, cmd_rts_enable, segment_enable=self.segment_enable)

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
        self.run_cli_extend(base_rest_url, cmd_ha_on, segment_enable=self.segment_enable)
        time.sleep(10)
        self.run_cli_extend(base_rest_url, cmd_segment, segment_enable=self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_apv_write_memory, segment_enable=self.segment_enable)


    def get_all_health_status(self, va_name, lb_id):
        status_dic = {}
        host_dic = {}
        cmd_get_status = ADCDevice.get_health_status()
        auth_val = (lb_id[:15], self.segment_user_passwd)
        for idx, base_rest_url in enumerate(self.base_rest_urls):
            r = self.run_cli_extend(base_rest_url, cmd_get_status, va_name, auth_val=auth_val)
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

    def get_restful_status(self, base_rest_url):
        cmd_show_ip_addr = ADCDevice.show_ip_addr()
        try:
            self.run_cli_extend(base_rest_url, cmd_show_ip_addr,
                segment_enable=self.segment_enable)
        except Exception:
            return False
        return True


    def get_ha_status(self, idx):
        base_rest_url = self.base_rest_urls[idx]
        cmd_show_ha_config = ADCDevice.show_ha_config()
        r = self.run_cli_extend(base_rest_url, cmd_show_ha_config,
            segment_enable=self.segment_enable)
        if "ha off" in r.text:
            LOG.debug("The HA is disabled on the host(%s): %s" % (self.hostnames[idx], r.text))
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

    def recovery_lbs_configuration(self):
        if len(self.hostnames) <= 1:
            LOG.debug("It can't build the HA environment.")
            return True

        global off_hosts
        LOG.debug("It will check the status of Host, current off hosts is : %s" % off_hosts)
        for idx, base_rest_url in enumerate(self.base_rest_urls):
            host_status = self.get_restful_status(base_rest_url)
            hostname = self.hostnames[idx]
            if not host_status:
                LOG.debug("Failed to connect the host(%s)" % hostname)
                if hostname not in off_hosts:
                    off_hosts.append(hostname)
                    LOG.debug("Append the host(%s) into off_host(%s)" % (hostname, off_hosts))
            else:
                if hostname in off_hosts:
                    LOG.debug("Host(%s) is currently ON, but it is still on the \
                        off_hosts(%s)" % (hostname, off_hosts))
                    active_idx = self.find_active_host(host_filter_idx=idx)
                    if active_idx != -1:
                        LOG.debug("It synconfig from host(%d:%s)" % (active_idx,
                            self.hostnames[active_idx]))
                        self.synconfig_from(base_rest_url, idx)
                    else:
                        LOG.debug("Can't find any active host except the host(%s), so failed to \
                            synconfig", hostname)
                    off_hosts.remove(hostname)

        LOG.debug("It will check the status of HA")
        for idx, base_rest_url in enumerate(self.base_rest_urls):
            ha_status = self.get_ha_status(idx)
            if not ha_status:
                LOG.debug("Will add the HA config in host(%s)" % self.hostnames[idx])
                self.init_one_array_device(idx)
                active_idx = self.find_active_host(host_filter_idx=idx)
                if active_idx != -1:
                    self.synconfig_from(base_rest_url, idx)


    def update_member_status(self, agent_host_name):
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
