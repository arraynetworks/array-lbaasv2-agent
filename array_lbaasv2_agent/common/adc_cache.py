#!/usr/bin/python
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

import os
import json
import logging

TENANT_APV_MAPPING = "/usr/share/array_lbaasv2_agent/mapping_apv.json"
TENANT_AVX_MAPPING = "/usr/share/array_lbaasv2_agent/mapping_avx.json"

LOG = logging.getLogger(__name__)
#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
#LOG = logging.getLogger()

class LogicalAPVCache(object):
    """
    The cache of Logical VIP cache in APV
    """
    def __init__(self):
        self.mapping = {}
        self._reload()

    def _reload(self):
        """ Reload the mapping between tenant and VA """
        if not os.path.exists(TENANT_APV_MAPPING):
            return None
        with open(TENANT_APV_MAPPING, 'r') as fd:
            self.mapping = json.load(fd)
            LOG.debug("After loading, the mapping is %s", self.mapping)

    def dump(self):
        with open(TENANT_APV_MAPPING, 'w') as fd:
            json.dump(self.mapping, fd)

    def put(self, vip_id, host, port_id, dump = False):
        if not vip_id or not host or not port_id:
            LOG.debug("The argument cannot be NONE")
            return None
        interface_map = self.mapping.get(vip_id, None)
        if not interface_map:
            interface_map = {}
        interface_map[host] = port_id
        self.mapping[vip_id] = interface_map
        if dump:
            self.dump()

    def remove(self, vip_id):
        if not vip_id:
            LOG.debug("The vip_id cannot be NONE")
            return None
        interface_map = self.mapping.get(vip_id, None)
        if interface_map:
            del self.mapping[vip_id]
            self.dump()
        return interface_map

    def get_interface_map_by_vip(self, vip_id):
        if not vip_id:
            return None
        interface_map = self.mapping.get(vip_id, None)
        return interface_map

    def print_cache(self):
        for k in self.mapping.keys():
            LOG.debug("VIP ID: %s" % k)
            for vk in self.mapping[k]:
                LOG.debug("Host(%s): Port(%s)" % (vk, self.mapping[k][vk]))


class LogicalAVXCache(object):
    """
    The cache of Logical APVs in AVX
    """
    va_name_prefix = "va"
    def __init__(self, in_interface):
        self.mapping = {}
        self.in_interface = in_interface
        self.va_pools = self._generate_va_pools()
        self._reload()

    # FIXME: should automatically generate the VA following
    # AVX's model.
    def _generate_va_pools(self):
        LOG.debug("The va_pools will be generated.")
        vas = []
        for i in range(1, 17):
            va_name = "%s_va%02d" % (self.in_interface, i)
            vas.append(va_name)
        return vas

    def _reload(self):
        """ Reload the mapping between tenant and VA """
        if not os.path.exists(TENANT_AVX_MAPPING):
            return None
        with open(TENANT_AVX_MAPPING, 'r') as fd:
            self.mapping = json.load(fd)
            LOG.debug("After loading, the mapping is %s", self.mapping)
        self.va_pools = self._generate_va_pools()
        for dv in self.mapping.values():
            self.va_pools = [x for x in self.va_pools if x != dv['va_name']]
        LOG.debug("For now, va_pools is %s", self.va_pools)

    def dump(self):
        with open(TENANT_AVX_MAPPING, 'w') as fd:
            json.dump(self.mapping, fd)

    def put(self, tenant_id, vip_id, host, port_id, dump = False):
        lb_item = {}
        interface_map = {}
        va_name = None

        if not vip_id or not host or not port_id:
            LOG.debug("The argument cannot be NONE")
            return va_name

        self._reload()
        lb_item = self.mapping.get(vip_id, None)
        if lb_item:
            va_name = lb_item['va_name']
            interface_map = lb_item.get('host_list', None)
            if not interface_map:
                interface_map = {}
            interface_map[host] = port_id
            lb_item[vip_id] = interface_map
        if dump and va_name:
            self.dump()
        return va_name

    def remove_vip(self, tenant_id, vip_id):
        if not vip_id:
            LOG.debug("The argument cannot be NONE")
            return None
        va_name = None
        self._reload()
        lb_item = self.mapping.get(vip_id, None)
        if lb_item:
            va_name = lb_item['va_name']
            self.va_pools.append(va_name)
            del self.mapping[vip_id]
            self.dump()
            LOG.debug("After running remove_vip, va_pools is %s", self.va_pools)
        return va_name

    def get_va_by_vip(self, tenant_id, vip_id):
        if not vip_id:
            return None
        lb_item = self.mapping.get(vip_id, None)
        va_name = None
        if lb_item:
            va_name = lb_item['va_name']
        else:
            lb_item = {}
            self._reload()
            LOG.debug("Before allocate, va_pools is %s", self.va_pools)
            if len(self.va_pools) == 0:
                LOG.debug("There is no enough VAs")
                return va_name
            va_name = self.va_pools.pop(0)
            lb_item['va_name'] = va_name
            self.mapping[vip_id] = lb_item
            LOG.debug("After allocate, va_pools is %s", self.va_pools)
            self.dump()
        return va_name

    def get_interface_map_by_vip(self, tenant_id, vip_id):
        interface_map = None
        if not vip_id:
            return interface_map

        lb_item = self.mapping.get(vip_id, None)
        if lb_item:
            interface_map = lb_item.get('host_list', None)
        return interface_map

    def print_cache(self):
        LOG.debug("va_pools is %s", self.va_pools)
        for k in self.mapping.keys():
            LOG.debug("VIP ID: %s" % k)
            for vk in self.mapping[k].keys():
                if vk == 'va_name':
		    LOG.debug("va_name: %s" % self.mapping[k][vk])
                elif vk == 'host_list':
                    for vkk in self.mapping[k][vk].keys():
                        LOG.debug("Host(%s): port_id(%s)" % (vkk, self.mapping[k][vk][vkk]))
                else:
                        LOG.debug("shouldn't be print")

'''
if __name__ == '__main__':
    cache = LogicalAVXCache()
    LOG.debug("Before remove_vip: ")
    cache.print_cache()
    #cache.remove_vip("first_tenant_id", "first_vip_id")
    #cache.remove_vip("second_tenant_id", "second_vip_id")
    va_name = cache.get_va_by_vip("first_tenant_id")
    #LOG.debug("va_name: %s" % va_name)
    #va_name = cache.get_va_by_vip("second_tenant_id")
    #LOG.debug("va_name: %s" % va_name)
    cache.put("first_tenant_id", "first_vip_id", "host_1", "first_port_id")
    cache.put("first_tenant_id", "first_vip_id", "host_2", "second_port_id")
    cache.put("first_tenant_id", "second_vip_id", "host_3", "third_port_id")
    cache.put("first_tenant_id", "second_vip_id", "host_4", "fourth_port_id")
    #cache.remove_vip("first_tenant_id", "first_vip_id")
    #cache.remove_vip("first_tenant_id", "second_vip_id")
    cache.dump()
    #cache.remove_group("first_tenant_id")
    #cache.remove_group("first_tenant_id")
    LOG.debug("After remove_vip: ")
    cache.print_cache()

'''
