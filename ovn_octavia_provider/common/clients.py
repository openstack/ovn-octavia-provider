#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystoneauth1 import loading as ks_loading
from neutronclient.common import exceptions as n_exc
from neutronclient.neutron import client as neutron_client

from octavia_lib.api.drivers import exceptions as driver_exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from ovn_octavia_provider.common import constants
from ovn_octavia_provider.i18n import _

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

NEUTRON_VERSION = '2.0'


class KeystoneSession():

    def __init__(self, section=constants.SERVICE_AUTH):
        self._session = None
        self._auth = None

        self.section = section
        ks_loading.register_auth_conf_options(cfg.CONF, self.section)
        ks_loading.register_session_conf_options(cfg.CONF, self.section)

    @property
    def session(self):
        """Initialize a Keystone session.

        :return: a Keystone Session object
        """
        if not self._session:
            self._session = ks_loading.load_session_from_conf_options(
                cfg.CONF, self.section, auth=self.auth)
        return self._session

    @property
    def auth(self):
        if not self._auth:
            self._auth = ks_loading.load_auth_from_conf_options(
                cfg.CONF, self.section)
        return self._auth


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args,
                                                                 **kwargs)
        return cls._instances[cls]


class NeutronAuth(metaclass=Singleton):
    def __init__(self, region, service_name=None, endpoint=None,
                 endpoint_type='publicURL', insecure=False,
                 ca_cert=None):
        """Create neutron client object.

        :param region: The region of the service
        :param service_name: The name of the neutron service in the catalog
        :param endpoint: The endpoint of the service
        :param endpoint_type: The endpoint_type of the service
        :param insecure: Turn off certificate validation
        :param ca_cert: CA Cert file path
        :return: a Neutron Client object.
        :raises Exception: if the client cannot be created
        """
        ksession = KeystoneSession()
        kwargs = {'region_name': region,
                  'session': ksession.session,
                  'endpoint_type': endpoint_type,
                  'insecure': insecure}
        if service_name:
            kwargs['service_name'] = service_name
        if endpoint:
            kwargs['endpoint_override'] = endpoint
        if ca_cert:
            kwargs['ca_cert'] = ca_cert
        try:
            self.neutron_client = neutron_client.Client(
                NEUTRON_VERSION, **kwargs)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception("Error creating Neutron client.")


def get_neutron_client():
    try:
        return NeutronAuth(
            endpoint=CONF.neutron.endpoint,
            region=CONF.neutron.region_name,
            endpoint_type=CONF.neutron.endpoint_type,
            service_name=CONF.neutron.service_name,
            insecure=CONF.neutron.insecure,
            ca_cert=CONF.neutron.ca_certificates_file,
        ).neutron_client
    except n_exc.NeutronClientException as e:
        msg = _('Cannot inialize Neutron Client. Exception: %s. '
                'Please verify Neutron service configuration '
                'in Octavia API configuration.') % e
        raise driver_exceptions.DriverError(
            operator_fault_string=msg)
