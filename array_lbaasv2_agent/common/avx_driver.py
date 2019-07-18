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
import copy

from oslo_config import cfg
from array_lbaasv2_agent.common.exceptions import ArrayADCException
from array_lbaasv2_agent.common.array_driver import ArrayCommonAPIDriver
from array_lbaasv2_agent.common.adc_device import ADCDevice

LOG = logging.getLogger(__name__)

class ArrayAVXAPIDriver(ArrayCommonAPIDriver):
    """ The real implementation on host to push config to
        vAPV instance of AVX via RESTful API
    """
    def __init__(self, management_ip, in_interface, user_name, user_passwd, context, plugin_rpc):
        super(ArrayAVXAPIDriver, self).__init__(in_interface,
                                                user_name,
                                                user_passwd,
                                                context,
                                                plugin_rpc)
        self.hostnames = management_ip
        self.base_rest_urls = ["https://" + host + ":9997/rest/avx" for host in self.hostnames]
        self.vapv_names = []
        self._init_vapv_names()

    def _init_vapv_names(self):
        for interface in self.in_interface:
            for i in range(1, 33):
                va_name = "%s_va%02d" % (interface, i)
                self.vapv_names.append(va_name)

    def allocate_va(self):
        exist_vapvs = self.plugin_rpc.get_all_vapvs(self.context)
        diff_vas = list(set(exist_vapvs).difference(set(self.vapv_names)))
        if len(diff_vas) > 1:
            return diff_vas[0]
        return None

    def get_va_name(self, argu):
        if not argu:
            msg = "No argument, raise it"
            raise ArrayADCException(msg)

        vip_id = argu.get('vip_id', None)
        if not vip_id:
            msg = "No loadbalance_id in argument, raise it"
            raise ArrayADCException(msg)

        ret_vapv = self.plugin_rpc.get_va_name_by_lb_id(self.context, vip_id)
        if not ret_vapv:
            LOG.debug("Will allocate the va from pools")
            ret_vapv = self.plugin_rpc.generate_vapv(self.context)
            if not ret_vapv:
                msg = "Failed to allocate the vAPV(%s)" % vip_id
                raise ArrayADCException(msg)
        va_name = ret_vapv['vapv_name']
        return va_name

    def get_va_interface(self):
        if cfg.CONF.arraynetworks.bonding:
            return "bond1"
        else:
            return "port1"

    def recovery_va(self, base_rest_url, cur_idx, vapv):
        unit_list = []
        LOG.debug("Try to recovery va(%s) in host(%s)" % (vapv['hostname'], self.hostnames[cur_idx]))

        for idx in range(2):
            unit_item = {}
            if idx == 0:
                if cfg.CONF.arraynetworks.bonding:
                    ip_address = "2.2.2.2"
                unit_item['priority'] = 100
                unit_item['name'] = vapv['lb_id'][:6] + '_p'
            elif idx == 1:
                if cfg.CONF.arraynetworks.bonding:
                    ip_address = "2.2.2.3"
                unit_item['name'] = vapv['lb_id'][:6] + '_s'
                unit_item['priority'] = 90
            unit_item['ip_address'] = ip_address
            unit_list.append(unit_item)
            if idx == cur_idx:
                vlan_tag = vapv['cluster_id']
                self._configure_ip(base_rest_url, vlan_tag, ip_address,
                    "255.255.255.0", vapv['hostname'])
        try:
            LOG.debug("unit_list: --%s--" % unit_list)
            self.configure_basic_ha(base_rest_url, unit_list, cur_idx, vapv['hostname'])
            self.plugin_rpc.update_excepted_vapv_by_name(self.context, vapv['hostname'])
            cmd_apv_write_memory = ADCDevice.write_memory()
            self.run_cli_extend(base_rest_url, cmd_apv_write_memory, vapv['hostname'])
        except Exception as e:
            LOG.debug("Still failed to recovery the va(%s): %s" % (vapv['hostname'], e.message))

    def recovery_lbs_configuration(self):
        if len(self.hostnames) == 1:
            LOG.debug("Don't need to recovery the vas.")
            return

        vapvs = self.plugin_rpc.get_excepted_vapvs(self.context)
        if not vapvs:
            LOG.debug("No any VAs need to be recoveried")
            return
        for vapv in vapvs:
            idx = vapv['in_use_lb'] - 10
            hostname = self.hostnames[idx]
            base_rest_url = "https://" + hostname + ":9997/rest/avx"
            connected = self.get_restful_status(base_rest_url)
            if not connected:
                LOG.debug("Failed to connect the AVX(%s)..." % hostname)
                return
            self.recovery_va(base_rest_url, idx, vapv)

    def update_member_status(self, agent_host_name):
        lb_members = self.plugin_rpc.get_members_status_on_agent(self.context,
            agent_host_name)
        lb_members_ori = copy.deepcopy(lb_members)
        LOG.debug("lb_members_ori: ----%s----" % lb_members_ori)
        lb_members = self.driver.get_status_by_lb_mems(lb_members)
        LOG.debug("lb_members: ----%s----" % lb_members)
        for lb_id, lb_members_status in lb_members_ori.items():
            for member_id, member_status in lb_members_status.items():
                new_member_status = lb_members[lb_id][member_id]
                LOG.debug("new_member_status(%s)---member_status(%s)" % (new_member_status, member_status))
                if new_member_status != member_status:
                    LOG.debug("--------will update_member_status -------")
                    self.plugin_rpc.update_member_status(self.context,
                        member_id, new_member_status)

