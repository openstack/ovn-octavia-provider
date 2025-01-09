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
#
import sys
from unittest import mock

from oslo_config import cfg
from oslo_log import log

from ovn_octavia_provider.cmd import octavia_ovn_db_sync_util
from ovn_octavia_provider import driver
from ovn_octavia_provider.tests.unit import base as ovn_base


class TestCMD(ovn_base.TestOvnOctaviaBase):

    def setUp(self):
        super().setUp()
        mock.patch.object(log, 'register_options').start()
        self.m_cfg = mock.patch.object(
            cfg.ConfigOpts, '__call__').start()

    @mock.patch.object(driver.OvnProviderDriver, 'do_sync')
    def test_octavia_ovn_db_sync_util(self, m_sync):
        octavia_ovn_db_sync_util.main()
        m_sync.assert_called_once_with(provider='ovn')

    @mock.patch.object(cfg.CONF, 'set_override')
    @mock.patch.object(driver.OvnProviderDriver, 'do_sync')
    def test_octavia_ovn_db_sync_util_with_debug(self, m_sync, m_cfg_or):
        return_value = ['octavia-ovn-db-sync-util',
                        '--debug']
        return_value_no_debug = ['octavia-ovn-db-sync-util']
        with mock.patch.object(sys, 'argv', return_value):
            octavia_ovn_db_sync_util.main()
        with mock.patch.object(sys, 'argv', return_value_no_debug):
            octavia_ovn_db_sync_util.main()
        m_cfg_or.assert_has_calls([mock.call('debug', True),
                                   mock.call('debug', False)])

    @mock.patch.object(octavia_ovn_db_sync_util, 'LOG')
    def test_octavia_ovn_db_sync_util_config_error(self, m_log):
        self.m_cfg.side_effect = [TypeError()]
        self.assertRaises(TypeError, octavia_ovn_db_sync_util.main)
        msg = ("Error parsing the configuration values. Please verify.")
        m_log.error.assert_called_once_with(msg)
