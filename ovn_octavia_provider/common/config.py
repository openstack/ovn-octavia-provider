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
from oslo_log import log as logging

from ovn_octavia_provider.i18n import _

LOG = logging.getLogger(__name__)


ovn_opts = [
    cfg.StrOpt('ovn_nb_connection',
               default='tcp:127.0.0.1:6641',
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
    cfg.StrOpt('ovn_sb_connection',
               default='tcp:127.0.0.1:6642',
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
    cfg.StrOpt('service_name',
               help=_('The name of the neutron service in the '
                      'keystone catalog')),
    cfg.StrOpt('endpoint', help=_('A new endpoint to override the endpoint '
                                  'in the keystone catalog.')),
    cfg.StrOpt('region_name',
               help=_('Region in Identity service catalog to use for '
                      'communication with the OpenStack services.')),
    cfg.StrOpt('endpoint_type', default='publicURL',
               help=_('Endpoint interface in identity service to use')),
    cfg.StrOpt('ca_certificates_file',
               help=_('CA certificates file path')),
    cfg.BoolOpt('insecure',
                default=False,
                help=_('Disable certificate validation on SSL connections ')),
]


def register_opts():
    # NOTE (froyo): just to not try to re-register options already done
    # by Neutron, specially in test scope, that will get a DuplicateOptError
    missing_opts = ovn_opts
    try:
        neutron_registered_opts = [opt for opt in cfg.CONF.ovn]
        missing_opts = [opt for opt in ovn_opts
                        if opt.name not in neutron_registered_opts]
    except cfg.NoSuchOptError:
        LOG.info('Not found any opts under group ovn registered by Neutron')

    cfg.CONF.register_opts(missing_opts, group='ovn')
    cfg.CONF.register_opts(neutron_opts, group='neutron')
    ks_loading.register_auth_conf_options(cfg.CONF, 'service_auth')
    ks_loading.register_session_conf_options(cfg.CONF, 'service_auth')


def list_opts():
    return [
        ('ovn', ovn_opts),
        ('neutron', neutron_opts),
    ]


def get_ovn_nb_connection():
    return cfg.CONF.ovn.ovn_nb_connection


def get_ovn_nb_private_key():
    return cfg.CONF.ovn.ovn_nb_private_key


def get_ovn_nb_certificate():
    return cfg.CONF.ovn.ovn_nb_certificate


def get_ovn_nb_ca_cert():
    return cfg.CONF.ovn.ovn_nb_ca_cert


def get_ovn_sb_connection():
    return cfg.CONF.ovn.ovn_sb_connection


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
