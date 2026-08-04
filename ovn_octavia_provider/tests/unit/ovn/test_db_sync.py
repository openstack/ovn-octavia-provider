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

from unittest import mock

from oslo_config import cfg

from neutron.tests import base
from neutron_lib.ovn import db_sync as neutron_db_sync
from ovn_octavia_provider.ovn import db_sync


class TestOctaviaOvnSynchronizer(base.BaseTestCase):
    """Test cases for the Octavia OVN DB synchronizer plugin."""

    def setUp(self):
        super().setUp()

        # Create mock instances for init parameters
        self.mock_core_plugin = mock.Mock()
        self.mock_ovn_driver = mock.Mock()
        self.mock_ovn_nb_api = mock.Mock()
        self.mock_ovn_sb_api = mock.Mock()

        # Mock the BaseOvnDbSynchronizer to avoid neutron-lib dependencies
        # The mock needs to set the attributes that the real __init__ would set
        def _mock_base_init(self_instance, core_plugin, ovn_driver, mode,
                            is_maintenance=False, plugin_conf=None):
            self_instance.core_plugin = core_plugin
            self_instance.ovn_driver = ovn_driver
            self_instance.ovn_nb_api = self.mock_ovn_nb_api
            self_instance.ovn_sb_api = self.mock_ovn_sb_api
            self_instance.mode = mode
            self_instance.is_maintenance = is_maintenance
            self_instance.plugin_conf = plugin_conf

        self.mock_base_init = mock.patch.object(
            neutron_db_sync.BaseOvnDbSynchronizer,
            '__init__',
            new=_mock_base_init
        ).start()

        # Mock configuration registration
        mock.patch(
            'ovn_octavia_provider.ovn.db_sync.ovn_octavia_config.'
            'register_plugin_opts'
        ).start()
        mock.patch(
            'ovn_octavia_provider.ovn.db_sync.OctaviaOvnSynchronizer.'
            '_load_octavia_config_fallback',
            return_value=mock.Mock()
        ).start()

        # Mock the OvnProviderDriver
        self.mock_driver = mock.patch(
            'ovn_octavia_provider.ovn.db_sync.driver.OvnProviderDriver'
        ).start()

        self.addCleanup(mock.patch.stopall)

    def _create_synchronizer(self, mode='repair', is_maintenance=False,
                             plugin_conf=None):
        """Helper to create a synchronizer instance."""
        return db_sync.OctaviaOvnSynchronizer(
            self.mock_core_plugin,
            self.mock_ovn_driver,
            mode,
            is_maintenance,
            plugin_conf=plugin_conf,
        )

    def test_class_attributes(self):
        """Test that the synchronizer has the correct class attributes."""
        # Verify that the synchronizer explicitly declares 'ovn-sync'
        cls = db_sync.OctaviaOvnSynchronizer

        # The class must explicitly set _required_mechanism_drivers
        # to include 'ovn-sync' because BaseOvnDbSynchronizer in
        # neutron-lib has this as [] (empty) by design
        self.assertEqual(['ovn-sync'], cls._required_mechanism_drivers)

        # And should specify empty lists for service plugins/extensions
        self.assertEqual([], cls._required_service_plugins)
        self.assertEqual([], cls._required_ml2_ext_drivers)

    def test_init(self):
        """Test synchronizer initialization."""
        self._create_synchronizer()

        # Verify that the OVN provider driver was created
        self.assertTrue(self.mock_driver.called)

        # Verify that the driver's NB IDL is set to share the connection
        mock_driver_instance = self.mock_driver.return_value
        self.assertEqual(self.mock_ovn_nb_api,
                         mock_driver_instance._ovn_helper._nb_idl)

    @mock.patch('ovn_octavia_provider.ovn.db_sync.LOG')
    def test_do_sync_mode_off(self, mock_log):
        """Test that sync is skipped when mode is OFF."""
        sync = self._create_synchronizer(mode='off')

        sync.do_sync()

        # Verify debug log was called
        self.assertTrue(mock_log.debug.called)
        self.assertIn('OFF', mock_log.debug.call_args[0][0])

        # Verify driver sync was not called
        mock_driver_instance = self.mock_driver.return_value
        mock_driver_instance.do_sync.assert_not_called()

    @mock.patch('ovn_octavia_provider.ovn.db_sync.LOG')
    def test_do_sync_mode_log(self, mock_log):
        """Test that sync is skipped with warning in LOG mode."""
        sync = self._create_synchronizer(mode='log')

        sync.do_sync()

        # Verify warning was logged
        self.assertTrue(mock_log.warning.called)
        warning_msg = mock_log.warning.call_args[0][0]
        self.assertIn('does not support LOG mode', warning_msg)

        # Verify driver sync was not called
        mock_driver_instance = self.mock_driver.return_value
        mock_driver_instance.do_sync.assert_not_called()

    @mock.patch('ovn_octavia_provider.ovn.db_sync.LOG')
    def test_do_sync_mode_repair(self, mock_log):
        """Test that sync is performed in REPAIR mode."""
        sync = self._create_synchronizer(mode='repair')

        sync.do_sync()

        # Verify info logs were called
        self.assertEqual(2, mock_log.info.call_count)

        # Verify driver sync was called with correct filters
        mock_driver_instance = self.mock_driver.return_value
        mock_driver_instance.do_sync.assert_called_once_with(provider='ovn')

    @mock.patch('ovn_octavia_provider.ovn.db_sync.LOG')
    def test_do_sync_mode_migrate(self, mock_log):
        """Test that sync is performed in MIGRATE mode."""
        sync = self._create_synchronizer(mode='migrate')

        sync.do_sync()

        # Verify driver sync was called
        mock_driver_instance = self.mock_driver.return_value
        mock_driver_instance.do_sync.assert_called_once_with(provider='ovn')

    @mock.patch('ovn_octavia_provider.ovn.db_sync.LOG')
    def test_do_sync_driver_exception_in_repair_mode(self, mock_log):
        """Test that exceptions are raised in REPAIR mode."""
        sync = self._create_synchronizer(mode='repair')

        # Make the driver raise an exception
        mock_driver_instance = self.mock_driver.return_value
        test_exception = RuntimeError("Test error")
        mock_driver_instance.do_sync.side_effect = test_exception

        # Verify the exception is raised
        self.assertRaises(RuntimeError, sync.do_sync)

        # Verify error was logged
        self.assertTrue(mock_log.error.called)
        error_msg = mock_log.error.call_args[0][0]
        self.assertIn('Error during Octavia OVN synchronization',
                      error_msg)

    @mock.patch('ovn_octavia_provider.ovn.db_sync.LOG')
    def test_do_sync_driver_exception_in_log_mode(self, mock_log):
        """Test that LOG mode doesn't raise exceptions (it skips sync)."""
        sync = self._create_synchronizer(mode='log')

        # Make the driver raise an exception (though it shouldn't be called)
        mock_driver_instance = self.mock_driver.return_value
        mock_driver_instance.do_sync.side_effect = Exception("Test error")

        # Should not raise because sync is skipped in LOG mode
        sync.do_sync()

        # Verify driver was not called
        mock_driver_instance.do_sync.assert_not_called()

    def test_stop(self):
        """Test synchronizer stop method."""
        sync = self._create_synchronizer()

        # Mock the parent stop method
        with mock.patch(
            'neutron_lib.ovn.db_sync.BaseOvnDbSynchronizer.stop'
        ) as mock_parent_stop:
            sync.stop()

            # Verify parent stop was called
            self.assertTrue(mock_parent_stop.called)

    def test_get_required_mechanism_drivers(self):
        """Test getting required mechanism drivers."""
        cls = db_sync.OctaviaOvnSynchronizer
        result = cls.get_required_mechanism_drivers()
        # Should include only the base class requirement 'ovn-sync'
        # The class itself doesn't add any additional drivers
        self.assertIsInstance(result, list)

    def test_get_required_service_plugins(self):
        """Test getting required service plugins."""
        cls = db_sync.OctaviaOvnSynchronizer
        result = cls.get_required_service_plugins()
        self.assertIsInstance(result, list)

    def test_get_required_ml2_extension_drivers(self):
        """Test getting required ML2 extension drivers."""
        cls = db_sync.OctaviaOvnSynchronizer
        result = cls.get_required_ml2_extension_drivers()
        self.assertIsInstance(result, list)

    def test_register_additional_cli_opts(self):
        conf = cfg.ConfigOpts()
        db_sync.OctaviaOvnSynchronizer.register_additional_cli_opts(conf)
        conf(['--octavia-config-file', '/etc/octavia/octavia.conf'])
        self.assertEqual(['/etc/octavia/octavia.conf'],
                         conf.octavia_config_file)

    def test_register_additional_cli_opts_deprecated_name(self):
        conf = cfg.ConfigOpts()
        db_sync.OctaviaOvnSynchronizer.register_additional_cli_opts(conf)
        conf(['--octavia_config_file', '/etc/octavia/octavia.conf'])
        self.assertEqual(['/etc/octavia/octavia.conf'],
                         conf.octavia_config_file)

    @mock.patch(
        'ovn_octavia_provider.ovn.db_sync.ovn_octavia_config.'
        'register_plugin_opts'
    )
    def test_register_plugin_config_opts(self, mock_register):
        conf = cfg.ConfigOpts()
        db_sync.OctaviaOvnSynchronizer.register_plugin_config_opts(conf)
        mock_register.assert_called_once_with(conf)

    def test_get_plugin_config_files_from_cli(self):
        conf = cfg.ConfigOpts()
        db_sync.OctaviaOvnSynchronizer.register_additional_cli_opts(conf)
        conf(['--octavia-config-file', '/custom/octavia.conf'])
        files = db_sync.OctaviaOvnSynchronizer.get_plugin_config_files(conf)
        self.assertEqual(['/custom/octavia.conf'], files)

    @mock.patch.object(db_sync.OctaviaOvnSynchronizer, '_find_octavia_config',
                       return_value='/etc/octavia/octavia.conf')
    def test_get_plugin_config_files_default(self, mock_find):
        conf = cfg.ConfigOpts()
        db_sync.OctaviaOvnSynchronizer.register_additional_cli_opts(conf)
        files = db_sync.OctaviaOvnSynchronizer.get_plugin_config_files(conf)
        mock_find.assert_called_once_with()
        self.assertEqual(['/etc/octavia/octavia.conf'], files)

    def test_init_uses_plugin_conf(self):
        plugin_conf = mock.Mock()
        sync = self._create_synchronizer(plugin_conf=plugin_conf)
        self.assertIs(plugin_conf, sync.octavia_conf)
