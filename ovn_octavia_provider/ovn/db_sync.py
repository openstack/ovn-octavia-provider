#    Copyright 2026 Red Hat, Inc. All rights reserved.
#
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

import contextlib
import os

from neutron_lib.ovn import constants as ovn_const
from neutron_lib.ovn import db_sync
from oslo_config import cfg
from oslo_log import log

from ovn_octavia_provider.common import clients
from ovn_octavia_provider.common import config as ovn_octavia_config
from ovn_octavia_provider import driver

LOG = log.getLogger(__name__)

DEFAULT_OCTAVIA_CONFIG_PATHS = (
    '/etc/octavia/octavia.conf',
    os.path.expanduser('~/octavia.conf'),
    './octavia.conf',
)


class OctaviaOvnSynchronizer(db_sync.BaseOvnDbSynchronizer):
    """Synchronizer for Octavia Load Balancers in OVN.

    This plugin synchronizes Octavia Load Balancers (OVN provider) with the
    OVN Northbound database. It can be invoked as part of the
    neutron-ovn-db-sync-util tool.

    The synchronizer does not support LOG mode (read-only verification).
    It will skip synchronization in LOG mode and only perform repairs in
    REPAIR mode.

    Note on configuration handling:
        The ovn-octavia-provider code uses cfg.CONF globally for accessing
        Octavia configuration (database connection, service_auth, etc.).
        To avoid conflicts with Neutron's cfg.CONF, this synchronizer:
        1. Loads Octavia config into a separate ConfigOpts instance
        2. Temporarily swaps cfg.CONF when calling Octavia code
        3. Restores Neutron's cfg.CONF afterwards

        When invoked via neutron-ovn-db-sync-util, Octavia configuration is
        loaded from ``--octavia-config-file`` (or the default location) into
        an isolated ConfigOpts object and passed as ``plugin_conf``.
    """

    # Explicitly require 'ovn-sync' mechanism driver.
    # This is required for the plugin to work when invoked with
    # --sync_plugin octavia_ovn_sync (isolated execution).
    # Note: We explicitly set this instead of relying on inheritance
    # because BaseOvnDbSynchronizer in some neutron-lib versions may
    # not have this attribute yet (depends on patch 970267 being merged).
    _required_mechanism_drivers = ['ovn-sync']

    # No additional Neutron service plugins required
    _required_service_plugins = []

    # No additional ML2 extension drivers required
    _required_ml2_ext_drivers = []

    @classmethod
    def register_additional_cli_opts(cls, conf):
        conf.register_cli_opts([
            cfg.ListOpt(
                'octavia-config-file',
                default=[],
                deprecated_opts=[cfg.DeprecatedOpt('octavia_config_file')],
                help='Path(s) to Octavia configuration file(s).'),
        ])

    @classmethod
    def register_plugin_config_opts(cls, conf):
        ovn_octavia_config.register_plugin_opts(conf)
        log.register_options(conf)

    @classmethod
    def get_plugin_config_files(cls, global_conf):
        if global_conf.octavia_config_file:
            return global_conf.octavia_config_file
        default = cls._find_octavia_config()
        return [default] if default else []

    def __init__(self, core_plugin, ovn_driver, mode, is_maintenance=False,
                 plugin_conf=None):
        """Initialize the Octavia OVN synchronizer.

        :param core_plugin: Neutron core plugin instance
        :param ovn_driver: OVN mechanism driver instance
        :param mode: Sync mode (log, repair, migrate)
        :param is_maintenance: Whether running in maintenance mode
        :param plugin_conf: Isolated ConfigOpts with Octavia configuration
        """
        super().__init__(
            core_plugin, ovn_driver, mode, is_maintenance,
            plugin_conf=plugin_conf)

        self.octavia_conf = plugin_conf or self._load_octavia_config_fallback()

        # Initialize the Octavia OVN provider driver with Octavia config
        with self._use_octavia_config():
            self.ovn_octavia_driver = driver.OvnProviderDriver()

        # Share the OVN NB API connection from Neutron
        if hasattr(self.ovn_octavia_driver, '_ovn_helper'):
            self.ovn_octavia_driver._ovn_helper._nb_idl = self.ovn_nb_api

    @classmethod
    def _find_octavia_config(cls):
        """Find Octavia configuration file in standard locations."""
        for location in DEFAULT_OCTAVIA_CONFIG_PATHS:
            if os.path.exists(location):
                return location
        return None

    def _load_octavia_config_fallback(self):
        """Load Octavia configuration when plugin_conf is not provided."""
        octavia_conf = cfg.ConfigOpts()
        self.register_plugin_config_opts(octavia_conf)

        octavia_conf_file = self._find_octavia_config()
        if octavia_conf_file:
            try:
                octavia_conf(
                    args=[],
                    project='octavia',
                    default_config_files=[octavia_conf_file]
                )
                LOG.info("Loaded Octavia configuration from %s",
                         octavia_conf_file)
            except Exception as e:
                LOG.warning("Failed to load Octavia configuration from %s: %s",
                            octavia_conf_file, e)
        else:
            LOG.warning("Octavia configuration file not found")

        return octavia_conf

    @contextlib.contextmanager
    def _use_octavia_config(self):
        """Context manager to temporarily use Octavia configuration."""
        original_conf = cfg.CONF

        try:
            cfg.CONF = self.octavia_conf
            clients.CONF = self.octavia_conf
            yield
        finally:
            cfg.CONF = original_conf
            clients.CONF = original_conf

    def do_sync(self):
        """Synchronize Octavia Load Balancers with OVN NB DB.

        Behavior by mode:
        - OFF: No synchronization is performed
        - LOG: Skipped (not supported, logs a warning)
        - REPAIR: Synchronizes all OVN provider load balancers
        - MIGRATE: Same as REPAIR for Octavia resources
        """
        if self.mode == ovn_const.OVN_DB_SYNC_MODE_OFF:
            LOG.debug("Octavia OVN sync mode is OFF")
            return

        if self.mode == ovn_const.OVN_DB_SYNC_MODE_LOG:
            LOG.warning(
                "Octavia OVN synchronizer does not support LOG mode. "
                "To synchronize Octavia load balancers with OVN, use "
                "REPAIR mode. Skipping Octavia synchronization."
            )
            return

        LOG.info("Starting Octavia OVN Load Balancers synchronization")

        try:
            with self._use_octavia_config():
                lb_filters = {'provider': 'ovn'}
                self.ovn_octavia_driver.do_sync(**lb_filters)

            LOG.info("Octavia OVN Load Balancers synchronization completed")
        except Exception as e:
            LOG.error("Error during Octavia OVN synchronization: %s", e,
                      exc_info=True)
            if self.mode == ovn_const.OVN_DB_SYNC_MODE_REPAIR:
                raise

    def stop(self):
        """Stop the synchronizer and cleanup resources."""
        super().stop()
