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
from oslo_config import cfg
from oslo_config import types
from oslo_log import log as logging

from ovn_octavia_provider.i18n import _

LOG = logging.getLogger(__name__)


ovn_opts = [
    cfg.ListOpt('ovn_nb_connection',
                default=['tcp:127.0.0.1:6641'],
                item_type=types.String(regex=r'^(tcp|ssl|unix):.+'),
                help=_('The connection string for the OVN_Northbound OVSDB.\n'
                       'Use tcp:IP:PORT for TCP connection.\n'
                       'Use ssl:IP:PORT for SSL connection. The '
                       'ovn_nb_private_key, ovn_nb_certificate and '
                       'ovn_nb_ca_cert are mandatory.\n'
                       'Use unix:FILE for unix domain socket connection.')),
    cfg.StrOpt('ovn_nb_private_key',
               default='',
               help=_('The PEM file with private key for SSL connection to '
                      'OVN-NB-DB')),
    cfg.StrOpt('ovn_nb_certificate',
               default='',
               help=_('The PEM file with certificate that certifies the '
                      'private key specified in ovn_nb_private_key')),
    cfg.StrOpt('ovn_nb_ca_cert',
               default='',
               help=_('The PEM file with CA certificate that OVN should use to'
                      ' verify certificates presented to it by SSL peers')),
    cfg.ListOpt('ovn_sb_connection',
                default=['tcp:127.0.0.1:6642'],
                item_type=types.String(regex=r'^(tcp|ssl|unix):.+'),
                help=_('The connection string for the OVN_Southbound OVSDB.\n'
                       'Use tcp:IP:PORT for TCP connection.\n'
                       'Use ssl:IP:PORT for SSL connection. The '
                       'ovn_sb_private_key, ovn_sb_certificate and '
                       'ovn_sb_ca_cert are mandatory.\n'
                       'Use unix:FILE for unix domain socket connection.')),
    cfg.StrOpt('ovn_sb_private_key',
               default='',
               help=_('The PEM file with private key for SSL connection to '
                      'OVN-SB-DB')),
    cfg.StrOpt('ovn_sb_certificate',
               default='',
               help=_('The PEM file with certificate that certifies the '
                      'private key specified in ovn_sb_private_key')),
    cfg.StrOpt('ovn_sb_ca_cert',
               default='',
               help=_('The PEM file with CA certificate that OVN should use to'
                      ' verify certificates presented to it by SSL peers')),
    cfg.IntOpt('ovsdb_connection_timeout',
               default=180,
               help=_('Timeout in seconds for the OVSDB '
                      'connection transaction')),
    cfg.IntOpt('ovsdb_retry_max_interval',
               default=180,
               help=_('Max interval in seconds between '
                      'each retry to get the OVN NB and SB IDLs')),
    cfg.IntOpt('ovsdb_probe_interval',
               min=0,
               default=60000,
               help=_('The probe interval in for the OVSDB session in '
                      'milliseconds. If this is zero, it disables the '
                      'connection keepalive feature. If non-zero the value '
                      'will be forced to at least 1000 milliseconds. Defaults '
                      'to 60 seconds.')),
]

neutron_opts = [
    cfg.StrOpt('endpoint', help=_('A new endpoint to override the endpoint '
                                  'in the keystone catalog.'),
               deprecated_for_removal=True,
               deprecated_reason=_('The endpoint_override option defined by '
                                   'keystoneauth1 is the new name for this '
                                   'option.'),
               deprecated_since='Antelope'),
    cfg.StrOpt('endpoint_type', help=_('Endpoint interface in identity '
                                       'service to use'),
               deprecated_for_removal=True,
               deprecated_reason=_('This option was replaced by the '
                                   'valid_interfaces option defined by '
                                   'keystoneauth.'),
               deprecated_since='Antelope'),
    cfg.StrOpt('ca_certificates_file',
               help=_('CA certificates file path'),
               deprecated_for_removal=True,
               deprecated_reason=_('The cafile option defined by '
                                   'keystoneauth1 is the new name for this '
                                   'option.'),
               deprecated_since='Antelope'),
]


def handle_neutron_deprecations():
    # Apply neutron deprecated options to their new setting if needed

    # Basicaly: if the value of the deprecated option is not the default:
    # * convert it to a valid "new" value if needed
    # * set it as the default for the new option
    # Thus [neutron].<new_option> has an higher precedence than
    # [neutron].<deprecated_option>
    loc = cfg.CONF.get_location('endpoint', 'neutron')
    if loc and loc.location != cfg.Locations.opt_default:
        cfg.CONF.set_default('endpoint_override', cfg.CONF.neutron.endpoint,
                             'neutron')

    loc = cfg.CONF.get_location('endpoint_type', 'neutron')
    if loc and loc.location != cfg.Locations.opt_default:
        endpoint_type = cfg.CONF.neutron.endpoint_type.replace('URL', '')
        cfg.CONF.set_default('valid_interfaces', [endpoint_type],
                             'neutron')

    loc = cfg.CONF.get_location('ca_certificates_file', 'neutron')
    if loc and loc.location != cfg.Locations.opt_default:
        cfg.CONF.set_default('cafile', cfg.CONF.neutron.ca_certificates_file,
                             'neutron')


def register_opts():
    # NOTE (froyo): just to not try to re-register options already done
    # by Neutron, specially in test scope, that will get a DuplicateOptError
    not_found_msg = 'Not found any opts under group ovn registered by Neutron'
    _register_opts(ovn_opts, 'ovn', not_found_msg)

    # Do the same for neutron options that have been already registered by
    # Octavia
    _register_opts(neutron_opts, 'neutron')

    ks_loading.register_auth_conf_options(cfg.CONF, 'service_auth')
    _register_opts(ks_loading.session.get_conf_options(), 'service_auth')
    # adapter accepts either '-' or '_' in config name, so need to check both.
    _register_opts(
        ks_loading.adapter.get_conf_options(include_deprecated=False),
        'service_auth', replace=('-', '_')
    )

    ks_loading.register_auth_conf_options(cfg.CONF, 'neutron')
    _register_opts(ks_loading.session.get_conf_options(), 'neutron')

    # adapter accepts either '-' or '_' in config name, so need to check both.
    _register_opts(
        ks_loading.adapter.get_conf_options(include_deprecated=False),
        'neutron', replace=('-', '_')
    )

    # Override default auth_type for plugins with the default from service_auth
    auth_type = cfg.CONF.service_auth.auth_type
    cfg.CONF.set_default('auth_type', auth_type, 'neutron')

    handle_neutron_deprecations()


def _register_opts(opts, group, not_found_msg=None, replace=('', '')):
    # NOTE (ricolin): To prevent DuplicateOptError
    missing_opts = opts
    try:
        registered_opts = [opt for opt in getattr(cfg.CONF, group)]
        missing_opts = [
            opt for opt in opts if (
                opt.name not in registered_opts and
                opt.name.replace(replace[0], replace[1]) not in registered_opts
            )
        ]
    except cfg.NoSuchOptError:
        msg = not_found_msg if not_found_msg else (
            f"Not found any opts under group {group}")
        LOG.info(msg)
    cfg.CONF.register_opts(missing_opts, group=group)


def list_opts():
    return [
        ('ovn', ovn_opts),
        ('neutron', neutron_opts),
    ]


def get_ovn_nb_connection():
    return ','.join(cfg.CONF.ovn.ovn_nb_connection)


def get_ovn_nb_private_key():
    return cfg.CONF.ovn.ovn_nb_private_key


def get_ovn_nb_certificate():
    return cfg.CONF.ovn.ovn_nb_certificate


def get_ovn_nb_ca_cert():
    return cfg.CONF.ovn.ovn_nb_ca_cert


def get_ovn_sb_connection():
    return ','.join(cfg.CONF.ovn.ovn_sb_connection)


def get_ovn_sb_private_key():
    return cfg.CONF.ovn.ovn_sb_private_key


def get_ovn_sb_certificate():
    return cfg.CONF.ovn.ovn_sb_certificate


def get_ovn_sb_ca_cert():
    return cfg.CONF.ovn.ovn_sb_ca_cert


def get_ovn_ovsdb_timeout():
    return cfg.CONF.ovn.ovsdb_connection_timeout


def get_ovn_ovsdb_retry_max_interval():
    return cfg.CONF.ovn.ovsdb_retry_max_interval


def get_ovn_ovsdb_probe_interval():
    return cfg.CONF.ovn.ovsdb_probe_interval
