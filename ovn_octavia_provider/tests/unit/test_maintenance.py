
# Copyright 2023 Red Hat, Inc.
# All Rights Reserved.
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

from futurist import periodics
from neutron_lib import constants as n_const

from ovn_octavia_provider.common import config as ovn_conf
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider import maintenance
from ovn_octavia_provider.tests.unit import base as ovn_base
from ovn_octavia_provider.tests.unit import fakes


class TestDBInconsistenciesPeriodics(ovn_base.TestOvnOctaviaBase):

    def setUp(self):
        ovn_conf.register_opts()
        super(TestDBInconsistenciesPeriodics, self).setUp()
        self.maint = maintenance.DBInconsistenciesPeriodics()
        self.ovn_nbdb_api = mock.patch.object(self.maint, 'ovn_nbdb_api')
        self.ovn_nbdb_api.start()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_change_device_owner_lb_hm_ports(self, net_cli):
        ovn_lb_hm_ports = {
            'ports': [
                fakes.FakePort.create_one_port(
                    attrs={
                        'id': 'foo',
                        'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                        'name': 'ovn-metadata-foo'}),
                fakes.FakePort.create_one_port(
                    attrs={
                        'id': 'foo1',
                        'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                        'name': 'ovn-lb-hm-foo1'}),
                fakes.FakePort.create_one_port(
                    attrs={
                        'id': 'foo2',
                        'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                        'name': 'ovn-lb-hm-foo2'})]}

        net_cli.return_value.list_ports.return_value = ovn_lb_hm_ports
        self.assertRaises(periodics.NeverAgain,
                          self.maint.change_device_owner_lb_hm_ports)
        expected_dict_1 = {
            'port': {
                'device_owner': ovn_const.OVN_LB_HM_PORT_DISTRIBUTED,
                'device_id': 'ovn-lb-hm-foo1'}}
        expected_dict_2 = {
            'port': {
                'device_owner': ovn_const.OVN_LB_HM_PORT_DISTRIBUTED,
                'device_id': 'ovn-lb-hm-foo2'}}
        expected_call = [
            mock.call(),
            mock.call().list_ports(
                device_owner=n_const.DEVICE_OWNER_DISTRIBUTED),
            mock.call().update_port('foo1', expected_dict_1),
            mock.call().update_port('foo2', expected_dict_2)]
        net_cli.assert_has_calls(expected_call)
        self.maint.ovn_nbdb_api.db_find_rows.assert_called_once_with(
            "Logical_Switch_Port", ("name", "=", 'foo1'))

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_change_device_owner_lb_hm_ports_neutron_version_doesnt_match(
            self, net_cli):
        ovn_lb_hm_ports = {
            'ports': [
                fakes.FakePort.create_one_port(
                    attrs={
                        'id': 'foo',
                        'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                        'name': 'ovn-metadata-foo'}),
                fakes.FakePort.create_one_port(
                    attrs={
                        'id': 'foo1',
                        'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                        'name': 'ovn-lb-hm-foo1'}),
                fakes.FakePort.create_one_port(
                    attrs={
                        'id': 'foo2',
                        'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                        'name': 'ovn-lb-hm-foo2'})]}

        net_cli.return_value.list_ports.return_value = ovn_lb_hm_ports
        self.maint.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [
                fakes.FakeOvsdbRow.create_one_ovsdb_row(
                    attrs={
                        'id': 'uuid-foo',
                        'type': 'foo'})]
        self.maint.change_device_owner_lb_hm_ports()
        expected_dict_change = {
            'port': {
                'device_owner': ovn_const.OVN_LB_HM_PORT_DISTRIBUTED,
                'device_id': 'ovn-lb-hm-foo1'}}
        expected_dict_rollback = {
            'port': {
                'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                'device_id': ''}}
        expected_call = [
            mock.call(),
            mock.call().list_ports(
                device_owner=n_const.DEVICE_OWNER_DISTRIBUTED),
            mock.call().update_port('foo1', expected_dict_change),
            mock.call().update_port('foo1', expected_dict_rollback)]
        net_cli.assert_has_calls(expected_call)
        self.maint.ovn_nbdb_api.db_find_rows.assert_called_once_with(
            "Logical_Switch_Port", ("name", "=", 'foo1'))

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_change_device_owner_lb_hm_ports_no_ports_to_change(self, net_cli):
        ovn_lb_hm_ports = {'ports': []}
        net_cli.return_value.list_ports.return_value = ovn_lb_hm_ports

        self.assertRaises(periodics.NeverAgain,
                          self.maint.change_device_owner_lb_hm_ports)
        expected_call = [
            mock.call(),
            mock.call().list_ports(
                device_owner=n_const.DEVICE_OWNER_DISTRIBUTED),
        ]
        net_cli.assert_has_calls(expected_call)
        self.maint.ovn_nbdb_api.db_find_rows.assert_not_called()
