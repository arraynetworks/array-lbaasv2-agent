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
import requests

from oslo_serialization import jsonutils
from oslo_config import cfg

_REQ = None

OPTS = [
    cfg.StrOpt(
        'nuage_base_url',
        default='http://192.168.0.200:9696/',
        help=("Nuage base URL")
    ),
    cfg.StrOpt(
        'nuage_gateway',
        help=("Nuage Gateway UUID")
    ),
    cfg.StrOpt(
        'nuage_gatewayport',
        help=("Nuage Gateway Port UUID")
    )
]

cfg.CONF.register_opts(OPTS, 'arraynetworks')

LOG = logging.getLogger(__name__)

class NuageRequest(object):

    def __init__(self, auth_session):
        self.base_url = cfg.CONF.arraynetworks.nuage_base_url
        self.auth_session = auth_session

    def request(self, method, url, args=None, headers=None):
        if args:
            args = jsonutils.dumps(args)

        if not headers or not headers.get('X-Auth-Token'):
            headers = headers or {
                'Content-type': 'application/json',
                'User-Agent': 'python-neutronclient',
            }
            headers['X-Auth-Token'] = self.auth_session.get_token()

        LOG.debug("url = %s", '%s%s' % (self.base_url, str(url)))
        LOG.debug("args = %s", args)
        r = requests.request(method,
                             '%s%s' % (self.base_url, str(url)),
                             data=args,
                             headers=headers)
        LOG.debug("NuageRequest Response Code: {0}".format(r.status_code))
        LOG.debug("NuageRequest Response Body: {0}".format(r.content))
        LOG.debug("NuageRequest Response Headers: {0}".format(r.headers))

        if method != 'DELETE':
            return r.json()

    def post(self, url, args):
        return self.request('POST', url, args)

    def put(self, url, args):
        return self.request('PUT', url, args)

    def delete(self, url):
        self.request('DELETE', url)

    def get(self, url):
        return self.request('GET', url)

def _get_req(session):
    global _REQ
    if not _REQ:
        _REQ = NuageRequest(session)
    return _REQ

def nuage_allocate_vlan(session, vlan_tag):
    req = _get_req(session)
    url = "/v2.0/nuage-gateway-vlans"
    argu = {}
    information = {}
    information['value'] = int(vlan_tag)
    information['gatewayport'] = cfg.CONF.arraynetworks.nuage_gatewayport
    information['gateway'] = cfg.CONF.arraynetworks.nuage_gateway
    argu['nuage_gateway_vlan'] = information
    response = req.post(url, argu)
    ret_vlan = json.loads(response['content'])
    return ret_vlan

def nuage_release_vlan(session, vlan_uuid):
    req = _get_req(session)
    url = "/v2.0/nuage-gateway-vlans/%s" % vlan_uuid
    return req.delete(url)

def nuage_bind_vlan_to_vport(session, vlan_uuid, port_id):
    req = _get_req(session)
    argu = {}
    information = {}
    information['gatewayvlan'] = vlan_uuid
    information['port'] = port_id
    argu['nuage_gateway_vlan'] = information
    url = "/v2.0/nuage-gateway-vport"
    ret_bond = req.post(url, argu)
    return ret_bond

