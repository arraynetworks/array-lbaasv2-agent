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

from array_lbaasv2_agent.common.exceptions import ArrayADCException
from array_lbaasv2_agent.common.adc_device import ADCDevice
from array_lbaasv2_agent.common.array_driver import ArrayCommonAPIDriver

LOG = logging.getLogger(__name__)

class ArrayAVXAPIDriver(ArrayCommonAPIDriver):
    """ The real implementation on host to push config to
        vAPV instance of AVX via RESTful API
    """
    def __init__(self, management_ip, in_interface, user_name, user_passwd, context):
        super(ArrayAVXAPIDriver, self).__init__(in_interface, user_name, user_passwd, context)
        self.hostnames = management_ip
        self.context = context
        self.base_rest_urls = ["https://" + host + ":9997/rest/avx" for host in self.hostnames]
        self.vapv_names = []
        self._init_vapv_names()

    def _init_vapv_names(self):
        for interface in self.in_interface:
            for i in range(1, 33):
                va_name = "%s_va%02d" % (interface, i)
                self.vapv_names.append(va_name)

    def allocate_va(self):
        exist_vapvs = self.array_db.get_vas()
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

        va_name = self.array_db.get_va_by_lb_id(self.context.session, vip_id)
        if not va_name:
            LOG.debug("Will allocate the va from pools")
            va_name = self.allocate_va()
            if not va_name:
                msg = "Failed to allocate the vAPV(%s)" % vip_id
                raise ArrayADCException(msg)
        return va_name

    def get_va_interface(self):
        return "port2"

