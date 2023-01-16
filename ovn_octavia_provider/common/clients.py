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

from keystoneauth1 import exceptions as ks_exceptions
from keystoneauth1 import loading as ks_loading

from octavia_lib.api.drivers import exceptions as driver_exceptions
import openstack
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from ovn_octavia_provider.common import constants
from ovn_octavia_provider.i18n import _

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class KeystoneSession():

    def __init__(self, section=constants.SERVICE_AUTH):
        self._session = None
        self._auth = None

        self.section = section

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
            try:
                self._auth = ks_loading.load_auth_from_conf_options(
                    cfg.CONF, self.section)
            except ks_exceptions.auth_plugins.MissingRequiredOptions as e:
                if self.section == constants.SERVICE_AUTH:
                    raise e
                # NOTE(gthiemonge): MissingRequiredOptions is raised: there is
                # one or more missing auth options in the config file. It may
                # be due to the migration from python-neutronclient to
                # openstacksdk.
                # With neutronclient, most of the auth settings were in
                # [service_auth] with a few overrides in [neutron],
                # but with openstacksdk, we have all the auth settings in the
                # [neutron] section. In order to support smooth upgrades, in
                # case those options are missing, we override the undefined
                # options with the existing settings from [service_auth].

                # This code should be removed when all the deployment tools set
                # the correct options in [neutron]

                # The config options are lazily registered/loaded by keystone,
                # it means that we cannot get/set them before invoking
                # 'load_auth_from_conf_options' on 'service_auth'.
                ks_loading.load_auth_from_conf_options(
                    cfg.CONF, constants.SERVICE_AUTH)

                config = getattr(cfg.CONF, self.section)
                for opt in config:
                    # For each option in the [neutron] section, get its setting
                    # location, if the location is 'opt_default' or
                    # 'set_default', it means that the option is not configured
                    # in the config file, it should be replaced with the one
                    # from [service_auth]
                    loc = cfg.CONF.get_location(opt, self.section)
                    if not loc or loc.location in (cfg.Locations.opt_default,
                                                   cfg.Locations.set_default):
                        if hasattr(cfg.CONF.service_auth, opt):
                            cur_value = getattr(config, opt)
                            value = getattr(cfg.CONF.service_auth, opt)
                            if value != cur_value:
                                log_value = (value if opt != "password"
                                             else "<hidden>")
                                LOG.debug("Overriding [%s].%s with '%s'",
                                          self.section, opt, log_value)
                                cfg.CONF.set_override(opt, value, self.section)

                # Now we can call load_auth_from_conf_options for this specific
                # service with the newly defined options.
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
    def __init__(self):
        """Create neutron client object."""
        try:
            ksession = KeystoneSession('neutron')

            kwargs = {}
            if CONF.neutron.endpoint_override:
                kwargs['network_endpoint_override'] = (
                    CONF.neutron.endpoint_override)

            self.network_proxy = openstack.connection.Connection(
                session=ksession.session, **kwargs).network
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception("Error creating Neutron client.")


def get_neutron_client():
    try:
        return NeutronAuth().network_proxy
    except Exception as e:
        msg = _('Cannot initialize OpenStackSDK. Exception: %s. '
                'Please verify Neutron service configuration '
                'in Octavia API configuration.') % e
        raise driver_exceptions.DriverError(
            operator_fault_string=msg)
