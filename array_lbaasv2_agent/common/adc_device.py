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

from array_lbaasv2_agent.common.adc_map import service_group_lb_method
from array_lbaasv2_agent.common.adc_map import array_protocol_map
from neutron_lbaas.services.loadbalancer import constants as lb_const
from oslo_config import cfg


def is_driver_apv():
    driver_type = cfg.CONF.arraynetworks.array_device_driver
    if driver_type == "array_lbaasv2_agent.common.apv_driver.ArrayAPVAPIDriver":
        return True
    else:
        return False

def parse_dest_url(dest_url):
    dest_prot = 'http'
    if dest_url.startswith('https'):
        dest_prot = 'https'

    if dest_url.startswith('http'):
        hostidx = dest_url.find('//') + 2
        dest_str = dest_url[hostidx:]
        while dest_str.startswith('/'):
            dest_str = dest_str[1:]
    else:
        dest_str = dest_url
    hostidx = dest_str.find('/')
    host = dest_str[:hostidx]
    path = dest_str[hostidx:]
    return (dest_prot, host, path)

class ADCDevice(object):
    """
        This class is used to generate the command line of Array ADC
        Product by different action.
    """

    @staticmethod
    def create_segment(segment_name):
        cmd = "segment name %s" % (segment_name)
        return cmd

    @staticmethod
    def delete_segment(segment_name):
        cmd = "no segment name %s\nYES\n" % (segment_name)
        return cmd

    @staticmethod
    def create_segment_user(segment_user, segment_name, segment_passwd, level):
        cmd = "segment user %s %s %s %s" % (segment_user, segment_name, segment_passwd, level)
        return cmd

    @staticmethod
    def delete_segment_user(segment_user):
        cmd = "no segment user %s" % (segment_user)
        return cmd

    @staticmethod
    def segment_interface(segment_name, if_name):
        cmd = "segment interface %s %s" % (segment_name, if_name)
        return cmd

    @staticmethod
    def segment_nat(segment_name, internal_ip, segment_ip, netmask):
        cmd = "segment nat %s %s %s %s" % (segment_name, segment_ip, internal_ip, netmask)
        return cmd

    @staticmethod
    def delete_segment_nat(segment_name, internal_ip, segment_ip, netmask):
        cmd = "no segment nat %s %s %s %s" % (segment_name, internal_ip, segment_ip, netmask)
        return cmd

    @staticmethod
    def delete_segment_interface(segment_name, if_name):
        cmd = "no segment interface %s %s" % (segment_name, if_name)
        return cmd

    @staticmethod
    def vlan_device(interface, vlan_device_name, vlan_tag):
        cmd = "vlan %s %s %s" % (interface, vlan_device_name, vlan_tag)
        return cmd

    @staticmethod
    def no_vlan_device(vlan_device_name):
        cmd = "no vlan %s" % vlan_device_name
        return cmd

    @staticmethod
    def configure_ip(interface, ip_address, netmask):
        cmd = "ip address %s %s %s" % (interface, ip_address, netmask)
        return cmd

    @staticmethod
    def configure_segment_ip(interface, ip_address, netmask, internal_ip):
        cmd = "segment ip address %s %s %s %s" % (interface, ip_address, netmask, internal_ip)
        return cmd

    @staticmethod
    def configure_route(gateway_ip):
        cmd = "ip route default %s" % (gateway_ip)
        return cmd

    @staticmethod
    def configure_route_apv(ip_address, netmask, gateway_ip):
        cmd = "ip route static %s %s %s" % (ip_address, netmask, gateway_ip)
        return cmd

    @staticmethod
    def clear_route():
        cmd = "clear ip route"
        return cmd

    @staticmethod
    def ip_pool(pool_name, ip_address):
        cmd = "ip pool %s %s" % (pool_name, ip_address)
        return cmd

    @staticmethod
    def ssh_ip(ip_address):
        cmd = "ssh ip %s" % (ip_address)
        return cmd

    @staticmethod
    def no_ip_pool(pool_name):
        cmd = "no ip pool %s" % pool_name
        return cmd

    @staticmethod
    def no_ip(interface):
        cmd = "no ip address %s" % interface
        return cmd

    @staticmethod
    def no_segment_ip(interface, ip_type):
        cmd = "no segment ip address %s %d" % (interface, ip_type)
        return cmd

    @staticmethod
    def create_virtual_service(name, vip, port, proto, conn_limit):
        protocol = array_protocol_map(proto, str(port))
        max_conn = conn_limit
        if max_conn == -1:
            max_conn = 0
        if protocol != 'ftp':
            cmd = "slb virtual %s %s %s %s arp %s" % (protocol, name, vip, port,
                max_conn)
        else:
            cmd = "slb virtual ftp %s %s %s %s" % (name, vip, port, max_conn)
        return cmd

    @staticmethod
    def no_virtual_service(name, proto, port):
        protocol = array_protocol_map(proto, str(port))
        cmd = "no slb virtual %s %s" % (protocol, name)
        return cmd

    @staticmethod
    def create_ssl_vhost(vhost_name, vs_name):
        cmd = "ssl host virtual %s %s" % (vhost_name, vs_name)
        return cmd

    @staticmethod
    def clear_ssl_vhost(vhost_name):
        cmd = "clear ssl host %s\nYES\n" % (vhost_name)
        return cmd

    @staticmethod
    def no_ssl_vhost(vhost_name, vs_name):
        cmd = "no ssl host virtual %s %s" % (vhost_name, vs_name)
        return cmd

    @staticmethod
    def import_ssl_key(vhost_name, key_content, domain_name=None):
        if domain_name:
            cmd = "ssl import key %s 1 \"%s\"\nYES\n%s\n...\n" % (vhost_name, domain_name, key_content)
        else:
            cmd = "ssl import key %s\nYES\n%s\n...\n" % (vhost_name, key_content)
        return cmd

    @staticmethod
    def import_ssl_cert(vhost_name, cert_content, domain_name=None):
        if domain_name:
            cmd = "ssl import certificate %s 1 \"%s\"\nYES\n%s\n...\n" % (vhost_name, domain_name, cert_content)
        else:
            cmd = "ssl import certificate %s\nYES\n%s\n...\n" % (vhost_name, cert_content)
        return cmd

    @staticmethod
    def no_ssl_cert(vhost_name, domain_name=None):
        if domain_name:
            cmd = "no ssl certificate %s 1 \"%s\"\nYES\n" % (vhost_name, domain_name)
        else:
            cmd = "no ssl certificate %s 1 \"\"\nYES\n" % (vhost_name)
        return cmd

    @staticmethod
    def activate_certificate(vhost_name, domain_name=None):
        if domain_name:
            cmd = "ssl activate certificate %s 1 \"%s\"\nYES\n" % (vhost_name, domain_name)
        else:
            cmd = "ssl activate certificate %s\nYES\n" % (vhost_name)
        return cmd

    @staticmethod
    def deactivate_certificate(vhost_name, domain_name=None):
        if domain_name:
            cmd = "ssl deactivate certificate %s \"%s\" all" % (vhost_name, domain_name)
        else:
            cmd = "ssl deactivate certificate %s \"\" all" % (vhost_name)
        return cmd

    @staticmethod
    def associate_domain_to_vhost(vhost_name, domain_name):
        cmd = "ssl sni %s \"%s\"" % (vhost_name, domain_name)
        return cmd

    @staticmethod
    def disassociate_domain_to_vhost(vhost_name, domain_name):
        cmd = "clear ssl sni %s \"%s\"\nYES\n" % (vhost_name, domain_name)
        return cmd

    @staticmethod
    def start_vhost(vhost_name):
        cmd = 'ssl start %s' % (vhost_name)
        return cmd

    @staticmethod
    def stop_vhost(vhost_name):
        cmd = 'ssl stop %s' % (vhost_name)
        return cmd

    @staticmethod
    def create_group(name, lb_algorithm, sp_type):
        (algorithm, first_choice_method, policy) = \
            service_group_lb_method(lb_algorithm, sp_type)
        cmd = None

        if first_choice_method:
            if algorithm == 'HC':
                cmd = "slb group method %s hc %s" % (name, first_choice_method)
            elif algorithm == 'PI':
                cmd = "slb group method %s pi 32 %s" % (name, first_choice_method)
            elif algorithm == 'IC':
                cmd = "slb group method %s ic array 0 %s" % (name, first_choice_method)
        else:
            if algorithm == 'IC':
                cmd = "slb group method %s ic array" % (name)
            elif algorithm.lower() == 'lc':
                cmd = "slb group method %s %s 1 yes" % (name, algorithm.lower())
            else:
                cmd = "slb group method %s %s" % (name, algorithm.lower())
        return cmd

    @staticmethod
    def no_group(name):
        cmd = "no slb group method %s" % name
        return cmd

    @staticmethod
    def clear_config_all():
        cmd = "clear config all"
        return cmd

    @staticmethod
    def create_policy(vs_name,
                      group_name,
                      lb_algorithm,
                      session_persistence_type,
                      cookie_name
                      ):
        (algorithm, first_choice_method, policy) = \
            service_group_lb_method(lb_algorithm, session_persistence_type)

        cmd = []
        if policy == 'Default':
            cmd.append("slb policy default %s %s" % (vs_name, group_name))
        elif policy == 'PC':
            cmd.append("slb policy default %s %s" % (vs_name, group_name))
            cmd.append("slb policy persistent cookie %s %s %s %s 100" % \
                (vs_name, vs_name, group_name, cookie_name))
        elif policy == 'IC':
            cmd.append("slb policy default %s %s" % (vs_name, group_name))
            cmd.append("slb policy icookie %s %s %s 100" % (vs_name, vs_name, group_name))
        return cmd

    @staticmethod
    def no_policy(vs_name, lb_algorithm, session_persistence_type):
        (_, _, policy) = service_group_lb_method(lb_algorithm, \
                session_persistence_type)
        cmd = []
        if policy == 'Default':
            cmd.append("no slb policy default %s" % vs_name)
        elif policy == 'PC':
            cmd.append("no slb policy persistent cookie %s" % vs_name)
        elif policy == 'IC':
            cmd.append("no slb policy default %s" % vs_name)
            cmd.append("no slb policy icookie %s" % vs_name)
        return cmd

    @staticmethod
    def slb_policy_action(policy_name, action, redirect_to_url = None,
        err_number = None):
        cmd = None
        if action == 'redirect':
            cmd = "slb policy action %s %s %s" % (action, policy_name, redirect_to_url)
        elif action == 'block':
            cmd = "slb policy action %s %s %s" % (action, policy_name, err_number)
        return cmd

    @staticmethod
    def no_slb_policy_action(policy_name):
        cmd = "no slb policy action %s" % policy_name
        return cmd

    @staticmethod
    def create_real_server(member_name,
                           member_address,
                           member_port,
                           proto
                          ):
        protocol = array_protocol_map(proto, str(member_port))
        cmd = "slb real %s %s %s %s 65535 none" % (protocol, member_name,\
                member_address, member_port)
        return cmd

    @staticmethod
    def no_real_server(proto, member_name, member_port):
        protocol = array_protocol_map(proto, str(member_port))
        cmd = "no slb real %s %s" % (protocol, member_name)
        return cmd

    @staticmethod
    def add_rs_into_group(group_name,
                          member_name,
                          member_weight
                         ):
        cmd = "slb group member %s %s %s" % (group_name, member_name, member_weight)
        return cmd

    @staticmethod
    def delete_rs_from_group(group_name, member_name):
        cmd = "no slb group member %s %s" % (group_name, member_name)
        return cmd

    @staticmethod
    def create_health_monitor(hm_name,
                              hm_type,
                              hm_delay,
                              hm_max_retries,
                              hm_timeout,
                              hm_http_method,
                              hm_url,
                              hm_expected_codes
                             ):
        if hm_type == 'PING':
            hm_type = 'ICMP'
        cmd = None
        if hm_type == 'HTTP' or hm_type == 'HTTPS':
            if is_driver_apv():
                cmd = "slb health %s %s %s %s 3 %s %s \"%s\" \"%s\"" % (hm_name, hm_type.lower(), \
                    str(hm_delay), str(hm_timeout), str(hm_max_retries), \
                    hm_http_method, hm_url, str(hm_expected_codes))
            else:
                cmd = "slb health %s %s %s %s 3 %s %s @@%s@@ @@%s@@" % (hm_name, hm_type.lower(), \
                    str(hm_delay), str(hm_timeout), str(hm_max_retries), \
                    hm_http_method, hm_url, str(hm_expected_codes))
        else:
            cmd = "slb health %s %s %s %s 3 %s" % (hm_name, hm_type.lower(), \
                    str(hm_delay), str(hm_timeout), str(hm_max_retries))
        return cmd

    @staticmethod
    def no_health_monitor(hm_name):
        cmd = "no slb health %s" % hm_name
        return cmd

    @staticmethod
    def attach_hm_to_group(group_name, hm_name):
        cmd = "slb group health %s %s" % (group_name, hm_name)
        return cmd

    @staticmethod
    def detach_hm_to_group(group_name, hm_name):
        cmd = "no slb group health %s %s" % (group_name, hm_name)
        return cmd

    @staticmethod
    def cluster_config_virtual_interface(iface_name, cluster_id):
        cmd = "cluster virtual ifname %s %d" % (iface_name, cluster_id)
        return cmd

    @staticmethod
    def cluster_clear_virtual_interface(iface_name, cluster_id):
        cmd = "clear cluster virtual ifname %s %d" % (iface_name, cluster_id)
        return cmd

    @staticmethod
    def cluster_config_vip(iface_name, cluster_id, vip_address):
        cmd = "cluster virtual vip %s %d %s" % (iface_name, cluster_id, vip_address)
        return cmd

    @staticmethod
    def no_cluster_config_vip(iface_name, cluster_id, vip_address):
        cmd = "no cluster virtual vip %s %d %s" % (iface_name, cluster_id, vip_address)
        return cmd

    @staticmethod
    def cluster_config_priority(iface_name, cluster_id, priority):
        cmd = "cluster virtual priority %s %d %s" % (iface_name, cluster_id, priority)
        return cmd

    @staticmethod
    def no_cluster_config_priority(iface_name, cluster_id):
        cmd = "no cluster virtual priority %s %d" % (iface_name, cluster_id)
        return cmd

    @staticmethod
    def cluster_enable(iface_name, cluster_id):
        cmd = "cluster virtual on %d %s" % (cluster_id, iface_name)
        return cmd

    @staticmethod
    def cluster_disable(iface_name, cluster_id):
        cmd = "cluster virtual off %d %s" % (cluster_id, iface_name)
        return cmd

    @staticmethod
    def create_http_error_page(vs_name):
        #FIXME
        cmd = "http import error 456 %s http://10.8.1.23/xx.html" % vs_name
        return cmd

    @staticmethod
    def load_http_error_page():
        cmd = "http error 456 default"
        return cmd

    @staticmethod
    def no_error_page(vs_name):
        cmd = "no http import error 456 %s" % vs_name
        return cmd

    @staticmethod
    def no_load_error_page():
        cmd = "no http error 456 default"
        return cmd

    @staticmethod
    def no_redirect_to_url(vs_name, policy_name):
        cmd = "no http redirect url %s %s" % (vs_name, policy_name)
        return cmd

    @staticmethod
    def redirect_to_url(vs_name, policy_name, dest_url):
        (proto, host, path) = parse_dest_url(dest_url)
        if is_driver_apv():
            cmd = "http redirect url %s %s 1 \"\<regex\>.*\" \"\<regex\>.*\" \"%s\" \"%s\" \"%s\" 302" % \
                (vs_name, policy_name, proto, host, path)
        else:
            cmd = "http redirect url %s %s 1 @@\<regex\>.*@@ @@\<regex\>.*@@ @@%s@@ @@%s@@ @@%s@@ 302" % \
                (vs_name, policy_name, proto, host, path)
        return cmd

    @staticmethod
    def create_l7_rule(rule_id, vs_id, group_id, rule_type, compare_type,
            value, invert, key=None):
        cmd = ""
        v_str = ""
        if rule_type == lb_const.L7_RULE_TYPE_HOST_NAME:
            cmd = "slb policy qos hostname"
        elif rule_type == lb_const.L7_RULE_TYPE_HEADER:
            cmd = "slb policy header"
        elif rule_type == lb_const.L7_RULE_TYPE_COOKIE:
            cmd = "slb policy qos cookie"
        elif rule_type == lb_const.L7_RULE_TYPE_PATH or \
             rule_type == lb_const.L7_RULE_TYPE_FILE_TYPE:
            cmd = "slb policy qos url"

        if compare_type == lb_const.L7_RULE_COMPARE_TYPE_REGEX:
            v_str = "\<regex\>%s" % value
            if key:
                v_key = "\<regex\>%s" % key
        elif compare_type == lb_const.L7_RULE_COMPARE_TYPE_STARTS_WITH:
            v_str = "\<regex\>^%s" % value
            if key:
                v_key = "\<regex\>^%s" % key
        elif compare_type == lb_const.L7_RULE_COMPARE_TYPE_ENDS_WITH:
            v_str = "\<regex\>%s$" % value
            if key:
                v_key = "\<regex\>%s$" % key
        elif compare_type == lb_const.L7_RULE_COMPARE_TYPE_EQUAL_TO:
            v_str = "\<regex\>^%s$" % value
            if key:
                v_key = "\<regex\>^%s$" % key
        elif compare_type == lb_const.L7_RULE_COMPARE_TYPE_CONTAINS:
            v_str = value
            if key:
                v_key = key

        if rule_type == lb_const.L7_RULE_TYPE_COOKIE:
            v_str = "%s=%s" % (v_key, value)
        elif rule_type == lb_const.L7_RULE_TYPE_FILE_TYPE:
            v_str = "\<regex\>\.%s$" % value

        if invert:
            v_str = "!%s" % v_str

        if rule_type == lb_const.L7_RULE_TYPE_HEADER:
            if is_driver_apv():
                cmd += " %s %s %s \"%s\" \"%s\" 1" % (rule_id, vs_id, group_id, key, v_str)
            else:
                cmd += " %s %s %s @@%s@@ @@%s@@ 1" % (rule_id, vs_id, group_id, key, v_str)
        else:
            if is_driver_apv():
                cmd += " %s %s %s \"%s\" 1" % (rule_id, vs_id, group_id, v_str)
            else:
                cmd += " %s %s %s @@%s@@ 1" % (rule_id, vs_id, group_id, v_str)
        return cmd

    @staticmethod
    def no_l7_rule(rule_id, rule_type):
        cmd = ""
        if rule_type == lb_const.L7_RULE_TYPE_HOST_NAME:
            cmd = "no slb policy qos hostname"
        elif rule_type == lb_const.L7_RULE_TYPE_HEADER:
            cmd = "no slb policy header"
        elif rule_type == lb_const.L7_RULE_TYPE_COOKIE:
            cmd = "no slb policy qos cookie"
        elif rule_type == lb_const.L7_RULE_TYPE_PATH or \
             rule_type == lb_const.L7_RULE_TYPE_FILE_TYPE:
            cmd = "no slb policy qos url"
        cmd += " %s" % rule_id
        return cmd

    @staticmethod
    def activation_server(address, port):
        cmd = "activationserver %s %s" % (address, port)
        return cmd

    @staticmethod
    def create_vlink(vlink_name):
        cmd = "slb vlink %s" % vlink_name
        return cmd

    @staticmethod
    def no_vlink(vlink_name):
        cmd = "no slb vlink %s" % vlink_name
        return cmd

    @staticmethod
    def ha_unit(name, ip_address, port):
        if is_driver_apv():
            cmd = "ha unit \"%s\" %s %s" % (name, ip_address, port)
        else:
            cmd = "ha unit @@%s@@ %s %s" % (name, ip_address, port)
        return cmd

    @staticmethod
    def no_ha_unit(name):
        if is_driver_apv():
            cmd = "no ha unit \"%s\"" % name
        else:
            cmd = "no ha unit @@%s@@" % name
        return cmd

    @staticmethod
    def slb_proxyip_group(group_name, ip_pool_name):
        cmd = "slb proxyip group %s %s" % (group_name, ip_pool_name)
        return cmd

    @staticmethod
    def no_slb_proxyip_group(group_name, ip_pool_name):
        cmd = "no slb proxyip group %s %s" % (group_name, ip_pool_name)
        return cmd

    @staticmethod
    def synconfig_peer(name, ip_address):
        if is_driver_apv():
            cmd = "synconfig peer \"%s\" %s" % (name, ip_address)
        else:
            cmd = "synconfig peer @@%s@@ %s" % (name, ip_address)
        return cmd

    @staticmethod
    def ha_link_network_on():
        cmd = "ha link network on"
        return cmd

    @staticmethod
    def ha_link_ffo_on():
        cmd = "ha link ffo on"
        return cmd

    @staticmethod
    def ha_on():
        cmd = "ha on"
        return cmd

    @staticmethod
    def ha_off():
        cmd = "ha off"
        return cmd

    @staticmethod
    def ha_group_id(group_id):
        cmd = "ha group id %d" % group_id
        return cmd

    @staticmethod
    def ha_no_group_id(group_id):
        cmd = "no ha group id %d" % group_id
        return cmd

    @staticmethod
    def ha_group_enable(group_id):
        cmd = "ha group enable %d" % group_id
        return cmd

    @staticmethod
    def ha_group_disable(group_id):
        cmd = "ha group disable %d" % group_id
        return cmd

    @staticmethod
    def ha_group_preempt_on(group_id):
        cmd = "ha group preempt on %d" % group_id
        return cmd

    @staticmethod
    def ha_ssf_peer(peer_address):
        cmd = "ha ssf peer %s" % peer_address
        return cmd

    @staticmethod
    def ha_ssf_on():
        cmd = "ha ssf on"
        return cmd

    @staticmethod
    def ha_group_fip(group_id, ip_address, port_name):
        cmd = "ha group fip %d %s %s" % (group_id, ip_address, port_name)
        return cmd

    @staticmethod
    def ha_group_fip_apv(group_id, ip_address, segment_name, port_name):
        cmd = "segment ha group fip %d %s %s %s" % (group_id, ip_address, segment_name, port_name)
        return cmd

    @staticmethod
    def ha_no_group_fip(group_id, ip_address):
        cmd = "no ha group fip %d %s" % (group_id, ip_address)
        return cmd
    @staticmethod
    def ha_no_group_fip_apv(group_id, ip_address, segment_name):
        cmd = "no segment ha group fip %d %s %s" % (group_id, ip_address, segment_name)
        return cmd

    @staticmethod
    def bond_interface():
        cmd = []
        cmd.append("bond interface bond1 port1")
        cmd.append("bond interface bond1 port2")
        return cmd

    @staticmethod
    def no_bond_interface():
        cmd = []
        cmd.append("no bond interface bond1 port1")
        cmd.append("no bond interface bond1 port2")
        return cmd

    @staticmethod
    def ha_group_priority(unit_name, group_id, priority):
        cmd = "ha group priority %s %d %s" % (unit_name, group_id, priority)
        return cmd

    @staticmethod
    def monitor_vcondition_name():
        cmd = "monitor vcondition name rule1 VCONDITION_1 AND"
        return cmd

    @staticmethod
    def monitor_vcondition_member():
        cmd = []
        cmd.append("monitor vcondition member rule1 PORT_1")
        cmd.append("monitor vcondition member rule1 PORT_2")
        return cmd

    @staticmethod
    def ha_decision_rule():
        cmd = "ha decision rule rule1 Group_Failover 1"
        return cmd

    @staticmethod
    def write_memory():
        cmd = "write memory"
        return cmd

    @staticmethod
    def get_health_status():
        cmd = "show health server"
        return cmd

    @staticmethod
    def show_ip_addr():
        cmd = "show ip addr"
        return cmd

    @staticmethod
    def show_ha_status():
        cmd = "show ha status"
        return cmd

