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
from oslo_config import cfg

from neutron_lbaas.common.tls_utils.cert_parser import get_host_names
from array_lbaasv2_agent.common.exceptions import ArrayADCException

try:
    from neutron_lbaas.common.cert_manager import CERT_MANAGER_PLUGIN
except ImportError:
    from neutron_lbaas.common import cert_manager
    CERT_MANAGER_PLUGIN = cert_manager.get_backend()

certificate_manager = CERT_MANAGER_PLUGIN.CertManager()
LOG = logging.getLogger(__name__)

def _get_vhost_id(listener):
    default_cid = listener['default_tls_container_id']
    vhost_id_idx = default_cid.rfind('/') + 1
    return default_cid[vhost_id_idx:]

def _get_service_name():
    service_name = "arrayvapv provider"
    envir = cfg.CONF.arraynetworks.environment_postfix
    if envir:
        service_name = "arrayvapv-%s provider" % envir
    return service_name

def config_ssls(listener, driver, va_name):
    vhost_id = _get_vhost_id(listener)

    # Upload default certificate
    _upload_certificate(driver, listener,
        listener['default_tls_container_id'], vhost_id,
        va_name, default=True)

    # Configure SNI certificates
    if listener['sni_containers']:
        for sni_container in listener['sni_containers']:
            # Get cert from Barbican and upload to APV
            _upload_certificate(driver, listener,
                sni_container['tls_container_id'], vhost_id,
                va_name)

    # Start vhost
    driver.start_vhost(vhost_id, va_name)


def _upload_certificate(driver, listener, container_id, vhost_id,
    va_name, default = False):
    service_name = _get_service_name()

    # Get the certificate from Barbican
    cert = certificate_manager.get_cert(
        project_id=listener['tenant_id'],
        cert_ref=container_id,
        resource_ref=certificate_manager.get_service_url(listener['loadbalancer_id']),
        service_name=service_name,
        check_only=True
    )

    # Check that the private key is not passphrase-protected
    if cert.get_private_key_passphrase():
        msg = "The APV LBaaS provider does not support private keys with a passphrase"
        raise ArrayADCException(msg)

    # Add server certificate to any intermediates
    try:
        cert_chain = cert.get_certificate() + cert.get_intermediates()
    except TypeError:
        cert_chain = cert.get_certificate()

    domain_name = None
    if not default:
        cert_hostnames = get_host_names(cert.get_certificate())
        domain_name = cert_hostnames['cn']

    driver.configure_ssl(vhost_id, listener['id'], cert.get_private_key(),
        cert_chain, domain_name, va_name)


def _no_certificate(driver, listener, container_id, vhost_id, va_name, default=False):
    service_name = _get_service_name()

    cert = certificate_manager.get_cert(
        project_id=listener['tenant_id'],
        cert_ref=container_id,
        resource_ref=certificate_manager.get_service_url(listener['loadbalancer_id']),
        service_name=service_name,
        check_only=True
    )

    domain_name = None
    if not default:
        cert_hostnames = get_host_names(cert.get_certificate())
        domain_name = cert_hostnames['cn']

    driver.clear_ssl_cert(vhost_id, listener['id'], domain_name, va_name)


def clean_up_certificates(listener, driver, va_name):
    vhost_id = _get_vhost_id(listener)

    # Delete default certificate
    _no_certificate(driver, listener, listener['default_tls_container_id'],
        vhost_id, va_name, default=True)

    # Delete SNI certificates
    if listener['sni_containers']:
        for sni_container in listener['sni_containers']:
            _no_certificate(driver, listener, sni_container['tls_container_id'],
                vhost_id, va_name)

