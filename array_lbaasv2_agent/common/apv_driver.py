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

from array_lbaasv2_agent.common.adc_device import ADCDevice
from array_lbaasv2_agent.common.array_driver import ArrayCommonAPIDriver


LOG = logging.getLogger(__name__)


class ArrayAPVAPIDriver(ArrayCommonAPIDriver):
    """ The real implementation on host to push config to
        APV via RESTful API
    """
    def __init__(self, management_ip, in_interface, user_name, user_passwd, context):
        super(ArrayAPVAPIDriver, self).__init__(in_interface, user_name, user_passwd, context)
        self.hostnames = management_ip
        self.context = context
        self.base_rest_urls = ["https://" + host + ":9997/rest/apv" for host in self.hostnames]

    def get_va_name(self, argu):
        return None


    def get_va_interface(self):
        pass
