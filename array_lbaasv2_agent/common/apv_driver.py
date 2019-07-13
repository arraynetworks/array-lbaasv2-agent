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
        # create vip
        if len(self.hostnames) == 1:
            self._create_segment(self.base_rest_urls, lb_name, va_name)
            self._create_segment_user(self.base_rest_urls, lb_name, va_name)
            self._segment_interface(self.base_rest_urls, argu['vlan_tag'], lb_name, va_name)
            # self._segment_nat(self.context, self.base_rest_urls, lb_name, argu['vip_address'], va_name)
            self._create_vip(self.base_rest_urls, argu['vip_address'],
                argu['netmask'], argu['vlan_tag'], argu['gateway'], va_name, lb_name)
        else:
            interface_mapping = argu['interface_mapping']
            unit_list = []
            for idx, host in enumerate(self.hostnames):
                unit_item = {}
                ip_address = interface_mapping[host]['address']
                unit_item['ip_address'] = ip_address
                if idx == 0:
                    unit_item['priority'] = 90
                    unit_item['name'] = argu['vip_id'][:6] + '_p'
                    pri_port_id = interface_mapping[host]['port_id']
                elif idx == 1:
                    sec_port_id = interface_mapping[host]['port_id']
                    unit_item['name'] = argu['vip_id'][:6] + '_s'
                    unit_item['priority'] = 100
                base_rest_url = self.base_rest_urls[idx]
                self._create_segment(self.base_rest_urls, lb_name, va_name)
                self._create_segment_user(self.base_rest_urls, lb_name, va_name)
                self._segment_interface(self.base_rest_urls, argu['vlan_tag'], lb_name, va_name)
                # self._segment_nat(self.context, self.base_rest_urls, lb_name, argu['vip_address'], va_name)
                self._create_vip(base_rest_url, ip_address, argu['netmask'],
                    argu['vlan_tag'], argu['gateway'], va_name)
            for base_rest_url in self.base_rest_urls:
                self.configure_ha(base_rest_url, unit_list,
                    argu['vip_address'], argu['vlan_tag'], lb_name, va_name, self.context, argu['subnet_id'])


    def delete_loadbalancer(self, argu):
        """ Delete a loadbalancer """
        if not argu:
            LOG.error("In delete_loadbalancer, it should not pass the None.")
            return

        va_name = self.get_va_name(argu)
        lb_name = argu['vip_id']  #need verify
        # delete vip
        self._delete_vip(argu['vlan_tag'], va_name)
        self._delete_segment_interface(self.base_rest_urls, argu['vlan_tag'], lb_name, va_name)
        # self._delete_segment_nat(self.context, self.base_rest_urls, lb_name, argu['vip_address'], va_name)
        self._delete_segment_user(self.base_rest_urls, va_name)
        self._delete_segment(self.base_rest_urls, lb_name, va_name)
        # clear the HA configuration
        if len(self.hostnames) > 1:
            unit_list = []
            for idx, host in enumerate(self.hostnames):
                unit_item = {}
                if idx == 0:
                    unit_item['name'] = argu['vip_id'][:6] + '_p'
                elif idx == 1:
                    unit_item['name'] = argu['vip_id'][:6] + '_s'
            for base_rest_url in self.base_rest_urls:
                self.clear_ha(base_rest_url, unit_list, argu['vip_address'], va_name, self.context, argu['subnet_id'])

            vapv = self.plugin_rpc.get_vapv_by_lb_id(self.context, argu['vip_id'])
            self.plugin_rpc.delete_port(self.context, vapv['pri_port_id'])
            self.plugin_rpc.delete_port(self.context, vapv['sec_port_id'])


    def _create_vip(self, base_rest_urls, vip_address, netmask, vlan_tag, gateway, va_name, lb_name):
        """ create vip"""

        # cmd_apv_config_vlan = None
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

        if isinstance(base_rest_urls, list):
            for base_rest_url in base_rest_urls:
                self.run_cli_extend(base_rest_url, cmd_apv_config_ip, va_name, self.segment_enable)
        else:
            self.run_cli_extend(base_rest_urls, cmd_apv_config_ip, va_name, self.segment_enable)


    def _delete_vip(self, vlan_tag, va_name):
        cmd_apv_no_vlan_device = None
        interface_name = self.plugin_rpc.get_interface(self.context)
        if not interface_name:
            return

        if vlan_tag:
            interface_name = "vlan." + vlan_tag
            cmd_apv_no_vlan_device = ADCDevice.no_vlan_device(interface_name)

        LOG.debug("no the vip address into interface")
        cmd_apv_no_ip = ADCDevice.no_ip(interface_name)

        for base_rest_url in self.base_rest_urls:
            self.run_cli_extend(base_rest_url, cmd_apv_no_ip, va_name, self.segment_enable)
            if vlan_tag:
                self.run_cli_extend(base_rest_url, cmd_apv_no_vlan_device, va_name, self.segment_enable)


    def configure_ha(self, base_rest_url, unit_list, vip_address,
        vlan_tag, segment_name, va_name, context, vip_subnet_id):
        in_interface = self.plugin_rpc.get_interface(self.context)
        if not in_interface:
            return
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

        for unit_item in unit_list:
            unit_name = unit_item['name']
            ip_address = unit_item['ip_address']
            priority = unit_item['priority']
            cmd_ha_unit = ADCDevice.ha_unit(unit_name, ip_address, 65521)
            cmd_synconfig_peer = ADCDevice.synconfig_peer(unit_name, ip_address)
            cmd_ha_group_priority = ADCDevice.ha_group_priority(unit_name, group_id, priority)
            self.run_cli_extend(base_rest_url, cmd_ha_unit, va_name, self.segment_enable)
            self.run_cli_extend(base_rest_url, cmd_synconfig_peer, va_name, self.segment_enable)
            self.run_cli_extend(base_rest_url, cmd_ha_group_priority, va_name, self.segment_enable)

        cmd_ha_group_fip = ADCDevice.ha_group_fip_apv(group_id, vip_address, segment_name, in_interface)
        cmd_ha_link_network_on = ADCDevice.ha_link_network_on()
        cmd_ha_group_enable = ADCDevice.ha_group_enable(group_id)
        cmd_ha_group_preempt_on = ADCDevice.ha_group_preempt_on(group_id)
        cmd_ha_on = ADCDevice.ha_on()
        self.run_cli_extend(base_rest_url, cmd_ha_group_fip, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_link_network_on, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_enable, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_group_preempt_on, va_name, self.segment_enable)
        self.run_cli_extend(base_rest_url, cmd_ha_on, va_name, self.segment_enable)


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
        conn_max_retries = 3
        conn_retry_interval = 5
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
        cluster_ids = self.plugin_rpc.get_clusterids_by_subnet(context.session, subnet_id)
        supported_ids = range(1, 256)
        diff_ids=list(set(supported_ids).difference(set(cluster_ids)))
        if len(diff_ids) > 1:
            return diff_ids[0]
        return 0

