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
import netaddr

from array_lbaasv2_agent.common.array_driver import ArrayCommonAPIDriver
from array_lbaasv2_agent.common.adc_device import ADCDevice


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

    def get_va_name(self, argu):
        return None


    def init_array_device(self):
        if len(self.hostnames) > 1:
            for idx, hostname in enumerate(self.hostnames):
                LOG.debug("Will init the device whose ip is %s", hostname)
                self.init_one_array_device(idx)

    def check_vlan_existed_in_device(self, vlan_tag):
        device_name = "vlan." + str(vlan_tag)
        base_rest_url = self.base_rest_urls[0]
        cmd_show_interface = ADCDevice.show_interface()
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
        for hostname in self.hostnames:
            unit_name = "u" + hostname.replace('.', '_')
            cmd_ha_unit = ADCDevice.ha_unit(unit_name, hostname, 65521)
            cmd_synconfig_peer = ADCDevice.synconfig_peer(unit_name, hostname)
            self.run_cli_extend(base_rest_url, cmd_ha_unit)
            self.run_cli_extend(base_rest_url, cmd_synconfig_peer)
        peer_ip_address = self.hostnames[1]
        if cur_idx == 1:
            peer_ip_address = self.hostnames[0]
        cmd_ssh_ip = ADCDevice.ssh_ip(self.hostnames[cur_idx])
        cmd_ha_ssf_peer = ADCDevice.ha_ssf_peer(peer_ip_address)
        cmd_ha_ssf_on = ADCDevice.ha_ssf_on()
        cmd_ha_link_ffo_on = ADCDevice.ha_link_ffo_on()
        cmd_ha_on = ADCDevice.ha_on()
        self.run_cli_extend(base_rest_url, cmd_ssh_ip)
        self.run_cli_extend(base_rest_url, cmd_ha_ssf_peer)
        self.run_cli_extend(base_rest_url, cmd_ha_ssf_on)
        self.run_cli_extend(base_rest_url, cmd_ha_link_ffo_on)
        self.run_cli_extend(base_rest_url, cmd_ha_on)

    def recovery_lbs_configuration(self):
        if len(self.hostnames) <= 1:
            LOG.debug("It can't build the HA environment.")
            return True
        cmd_show_ha_config = ADCDevice.show_ha_config()
        for idx, base_rest_url in enumerate(self.base_rest_urls):
            r = self.run_cli_extend(base_rest_url, cmd_show_ha_config)
            if "ha off" in r.text:
                LOG.debug("The HA is disabled on the host(%s): %s" % (self.hostnames[idx], r.text))
                self.init_one_array_device(idx)
                peer_name = "unit_s"
                if idx == 1:
                    peer_name = "unit_m"
                cmd_synconfig_from_peer = ADCDevice.synconfig_from_peer(peer_name)
                self.run_cli_extend(base_rest_url, cmd_synconfig_from_peer,
                    run_timeout=600)
