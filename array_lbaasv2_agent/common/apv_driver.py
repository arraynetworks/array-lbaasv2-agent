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


    def get_va_interface(self):
        pass



    def init_array_device(self):
        if len(self.hostnames) > 1:
            for idx, hostname in enumerate(self.hostnames):
                LOG.debug("Will init the device whose ip is %s", hostname)
                self.init_one_array_device(idx)

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
        pass


