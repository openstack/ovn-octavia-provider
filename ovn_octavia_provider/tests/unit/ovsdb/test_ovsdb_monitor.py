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

from unittest import mock

from oslo_config import cfg
import testscenarios

from ovn_octavia_provider.ovsdb import ovsdb_monitor
from ovn_octavia_provider.tests.unit import base as base_test


OPTS = ('ovn_nb_private_key', 'ovn_nb_certificate',
        'ovn_nb_ca_cert', 'ovn_sb_private_key',
        'ovn_sb_certificate', 'ovn_sb_ca_cert')


class TestOvsdbMonitor(testscenarios.WithScenarios,
                       base_test.TestOvnOctaviaBase):

    scenarios = [
        ('OVN_Northbound', {'schema': 'OVN_Northbound',
                            'private_key': 'ovn_nb_private_key',
                            'certificate': 'ovn_nb_certificate',
                            'ca_cert': 'ovn_nb_ca_cert'}),
        ('OVN_Southbound', {'schema': 'OVN_Southbound',
                            'private_key': 'ovn_sb_private_key',
                            'certificate': 'ovn_sb_certificate',
                            'ca_cert': 'ovn_sb_ca_cert'})
    ]

    def setUp(self):
        super().setUp()
        self._register_opts()
        self.mock_os_path = mock.patch('os.path.exists').start()
        self.mock_stream = mock.patch.object(ovsdb_monitor, 'Stream').start()

    @staticmethod
    def _register_opts():
        for opt in OPTS:
            try:
                cfg.CONF.register_opt(cfg.StrOpt(opt), group='ovn')
            except cfg.DuplicateOptError:
                pass

    def test_set_ssl(self):
        cfg.CONF.set_override(self.private_key, 'key', group='ovn')
        cfg.CONF.set_override(self.certificate, 'cert', group='ovn')
        cfg.CONF.set_override(self.ca_cert, 'ca-cert', group='ovn')
        self.mock_os_path.return_value = True
        ovsdb_monitor.check_and_set_ssl_files(self.schema)
        self.mock_stream.ssl_set_private_key_file.assert_called_with('key')
        self.mock_stream.ssl_set_certificate_file.assert_called_with('cert')
        self.mock_stream.ssl_set_ca_cert_file.assert_called_with('ca-cert')

    def test_no_key_and_certs(self):
        cfg.CONF.set_override(self.private_key, '', group='ovn')
        cfg.CONF.set_override(self.certificate, '', group='ovn')
        cfg.CONF.set_override(self.ca_cert, '', group='ovn')
        self.mock_os_path.return_value = False
        ovsdb_monitor.check_and_set_ssl_files(self.schema)
        self.mock_stream.ssl_set_private_key_file.assert_not_called()
        self.mock_stream.ssl_set_certificate_file.assert_not_called()
        self.mock_stream.ssl_set_ca_cert_file.assert_not_called()

    def test_no_nonexisting_files(self):
        cfg.CONF.set_override(self.private_key, 'key', group='ovn')
        cfg.CONF.set_override(self.certificate, 'cert', group='ovn')
        cfg.CONF.set_override(self.ca_cert, 'ca-cert', group='ovn')
        self.mock_os_path.return_value = False

        with self.assertLogs():
            ovsdb_monitor.check_and_set_ssl_files(self.schema)

        self.mock_stream.ssl_set_private_key_file.assert_not_called()
        self.mock_stream.ssl_set_certificate_file.assert_not_called()
        self.mock_stream.ssl_set_ca_cert_file.assert_not_called()
