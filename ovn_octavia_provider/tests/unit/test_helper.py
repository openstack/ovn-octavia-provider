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
import copy
from unittest import mock

from neutron_lib import constants as n_const
from neutronclient.common import exceptions as n_exc
from octavia_lib.api.drivers import data_models
from octavia_lib.api.drivers import exceptions
from octavia_lib.common import constants
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

from ovn_octavia_provider.common import clients
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider import event as ovn_event
from ovn_octavia_provider import helper as ovn_helper
from ovn_octavia_provider.tests.unit import base as ovn_base
from ovn_octavia_provider.tests.unit import fakes


class TestOvnProviderHelper(ovn_base.TestOvnOctaviaBase):

    def setUp(self):
        super().setUp()
        self.helper = ovn_helper.OvnProviderHelper()
        self.real_helper_find_ovn_lb_with_pool_key = (
            self.helper._find_ovn_lb_with_pool_key)
        mock.patch.object(self.helper, '_update_status_to_octavia').start()
        self.octavia_driver_lib = mock.patch.object(
            self.helper, '_octavia_driver_lib').start()
        self.listener = {'id': self.listener_id,
                         'loadbalancer_id': self.loadbalancer_id,
                         'protocol': 'TCP',
                         'protocol_port': 80,
                         'default_pool_id': self.pool_id,
                         'admin_state_up': False}
        self.lb = {'id': self.loadbalancer_id,
                   'vip_address': self.vip_address,
                   'cascade': False,
                   'vip_network_id': self.vip_network_id,
                   'admin_state_up': False}
        self.ports = {'ports': [{
            'fixed_ips': [{'ip_address': self.vip_address,
                           'subnet_id': uuidutils.generate_uuid()}],
            'network_id': self.vip_network_id,
            'id': self.port1_id}]}
        self.pool = {'id': self.pool_id,
                     'loadbalancer_id': self.loadbalancer_id,
                     'listener_id': self.listener_id,
                     'protocol': 'TCP',
                     'lb_algorithm': constants.LB_ALGORITHM_SOURCE_IP_PORT,
                     'admin_state_up': False}
        self.member = {'id': self.member_id,
                       'address': self.member_address,
                       'protocol_port': self.member_port,
                       'subnet_id': self.member_subnet_id,
                       'pool_id': self.member_pool_id,
                       'admin_state_up': True,
                       'old_admin_state_up': True}
        self.health_monitor = {'id': self.healthmonitor_id,
                               'pool_id': self.pool_id,
                               'type': constants.HEALTH_MONITOR_TCP,
                               'interval': 6,
                               'timeout': 7,
                               'failure_count': 5,
                               'success_count': 3,
                               'admin_state_up': True}
        self.health_mon_udp = {'id': self.healthmonitor_id,
                               'pool_id': self.pool_id,
                               'type': constants.HEALTH_MONITOR_UDP_CONNECT,
                               'interval': 6,
                               'timeout': 7,
                               'failure_count': 5,
                               'success_count': 3,
                               'admin_state_up': True}
        self.ovn_nbdb_api = mock.patch.object(self.helper, 'ovn_nbdb_api')
        self.ovn_nbdb_api.start()
        add_req_thread = mock.patch.object(ovn_helper.OvnProviderHelper,
                                           'add_request')
        self.mock_add_request = add_req_thread.start()
        self.ovn_lb = mock.MagicMock()
        self.ovn_lb.protocol = ['tcp']
        self.ovn_lb.uuid = uuidutils.generate_uuid()
        self.ovn_lb.health_check = []
        self.ovn_hm_lb = mock.MagicMock()
        self.ovn_hm_lb.protocol = ['tcp']
        self.ovn_hm_lb.uuid = uuidutils.generate_uuid()
        self.ovn_hm_lb.health_check = []
        self.ovn_hm = mock.MagicMock()
        self.ovn_hm.uuid = self.healthmonitor_id
        self.ovn_hm.external_ids = {
            ovn_const.LB_EXT_IDS_HM_KEY: self.ovn_hm.uuid}
        self.member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.123',
            ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_port',
            'enabled': True,
            'pool_%s' % self.pool_id: self.member_line,
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        self.ovn_hm_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.99',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.99',
            ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_hm_port',
            'enabled': True,
            'pool_%s' % self.pool_id: [],
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        self.helper.ovn_nbdb_api.db_find.return_value.\
            execute.return_value = [self.ovn_lb]
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.return_value = [self.ovn_lb]
        self.mock_find_lb_pool_key = mock.patch.object(
            self.helper,
            '_find_ovn_lb_with_pool_key',
            return_value=self.ovn_lb).start()

        self.mock_find_ovn_lbs = mock.patch.object(
            ovn_helper.OvnProviderHelper, '_find_ovn_lbs',
            side_effect=lambda x, protocol=None:
                self.ovn_lb if protocol else [self.ovn_lb])
        self.mock_find_ovn_lbs.start()

        mock.patch.object(self.helper,
                          '_get_pool_listeners',
                          return_value=[]).start()
        self._update_lb_to_ls_association = mock.patch.object(
            self.helper,
            '_update_lb_to_ls_association',
            return_value=[])
        self._update_lb_to_ls_association.start()
        self._update_lb_to_lr_association = mock.patch.object(
            self.helper,
            '_update_lb_to_lr_association',
            return_value=[])
        self._update_lb_to_lr_association.start()

        # NOTE(mjozefcz): Create foo router and network.
        net_id = uuidutils.generate_uuid()
        router_id = uuidutils.generate_uuid()
        self.ref_lb1 = fakes.FakeLB(
            uuid=uuidutils.generate_uuid(),
            admin_state_up=True,
            listeners=[],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb1',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id,
            ext_ids={
                ovn_const.LB_EXT_IDS_LR_REF_KEY: 'neutron-%s' % net_id,
                ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                    '{\"neutron-%s\": 1}' % net_id})
        self.ref_lb2 = fakes.FakeLB(
            uuid=uuidutils.generate_uuid(),
            admin_state_up=True,
            listeners=[],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb2',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id,
            ext_ids={
                ovn_const.LB_EXT_IDS_LR_REF_KEY: 'neutron-%s' % net_id,
                ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                    '{\"neutron-%s\": 1}' % net_id})
        # TODO(mjozefcz): Consider using FakeOVNRouter.
        self.router = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'load_balancer': [self.ref_lb1],
                   'name': 'neutron-%s' % router_id,
                   'ports': []})
        # TODO(mjozefcz): Consider using FakeOVNSwitch.
        self.network = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'load_balancer': [self.ref_lb2],
                   'name': 'neutron-%s' % net_id,
                   'ports': [],
                   'uuid': net_id})
        self.mock_get_nw = mock.patch.object(
            self.helper, '_get_nw_router_info_on_interface_event',
            return_value=(self.router, self.network))
        self.mock_get_nw.start()
        (self.helper.ovn_nbdb_api.ls_get.return_value.
            execute.return_value) = self.network

    def test__is_lb_empty(self):
        f = self.helper._is_lb_empty
        self.assertFalse(f(self.ovn_lb.external_ids))
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        self.assertFalse(f(self.ovn_lb.external_ids))
        self.ovn_lb.external_ids.pop('pool_%s' % self.pool_id)
        self.assertTrue(f(self.ovn_lb.external_ids))

    def test__delete_disabled_from_status(self):
        f = self.helper._delete_disabled_from_status
        status = {
            'pools': [
                {'id': 'f:D', 'provisioning_status': 'ACTIVE',
                 'operating_status': 'ONLINE'}],
            'members': [
                {'id': 'foo:D',
                 'provisioning_status': 'ACTIVE'}]}
        expected = {
            'pools': [
                {'id': 'f', 'provisioning_status': 'ACTIVE',
                 'operating_status': 'ONLINE'}],
            'members': [
                {'id': 'foo',
                 'provisioning_status': 'ACTIVE'}]}
        self.assertEqual(f(status), expected)
        self.assertEqual(f(expected), expected)
        status = {}
        self.assertFalse(f(status))

    def test__find_ovn_lb_with_pool_key(self):
        pool_key = self.helper._get_pool_key(uuidutils.generate_uuid())
        test_lb = mock.MagicMock()
        test_lb.external_ids = {
            ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                ovn_const.PORT_FORWARDING_PLUGIN,
            pool_key: 'it_is_a_pool_party',
        }
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.return_value = [test_lb]
        f = self.real_helper_find_ovn_lb_with_pool_key

        # Ensure lb is not found, due to its device owner
        found = f(pool_key)
        self.assertIsNone(found)

        # Remove device owner from test_lb.external_ids and make sure test_lb
        # is found as expected
        test_lb.external_ids.pop(ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY)
        found = f(pool_key)
        self.assertEqual(found, test_lb)

    def test__find_ovn_lbs(self):
        self.mock_find_ovn_lbs.stop()
        f = self.helper._find_ovn_lbs
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb]

        # Without protocol specified return a list
        found = f(self.ovn_lb.id)
        self.assertListEqual(found, [self.ovn_lb])
        self.helper.ovn_nbdb_api.db_find_rows.assert_called_once_with(
            'Load_Balancer', ('name', '=', self.ovn_lb.id))
        self.helper.ovn_nbdb_api.db_find_rows.reset_mock()

        # With protocol specified return an instance
        found = f(self.ovn_lb.id, protocol='tcp')
        self.assertEqual(found, self.ovn_lb)
        self.helper.ovn_nbdb_api.db_find_rows.reset_mock()

        # LB with given protocol not found
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = []
        self.assertRaises(
            idlutils.RowNotFound,
            f,
            self.ovn_lb.id,
            protocol='UDP')

        # LB with given protocol not found
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = []
        self.assertRaises(
            idlutils.RowNotFound,
            f,
            self.ovn_lb.id,
            protocol='SCTP')

        # Multiple protocols
        udp_lb = copy.copy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        sctp_lb = copy.copy(self.ovn_lb)
        sctp_lb.protocol = ['sctp']
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb, udp_lb, sctp_lb]
        found = f(self.ovn_lb.id)
        self.assertListEqual(found, [self.ovn_lb, udp_lb, sctp_lb])

    def test__get_subnet_from_pool(self):
        f = self.helper._get_subnet_from_pool

        lb = data_models.LoadBalancer(
            loadbalancer_id=self.loadbalancer_id,
            name='The LB',
            vip_address=self.vip_address,
            vip_subnet_id=self.vip_subnet_id,
            vip_network_id=self.vip_network_id)

        lb_pool = data_models.Pool(
            loadbalancer_id=self.loadbalancer_id,
            name='The pool',
            pool_id=self.pool_id,
            protocol='TCP')

        with mock.patch.object(self.helper, '_octavia_driver_lib') as dlib:
            dlib.get_pool.return_value = None
            found = f('not_found')
            self.assertIsNone(found)

            dlib.get_pool.return_value = lb_pool
            dlib.get_loadbalancer.return_value = lb
            found = f(self.pool_id)
            self.assertEqual(found, lb.vip_subnet_id)

    def test__get_or_create_ovn_lb_no_lb_found(self):
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = []
        self.assertRaises(
            idlutils.RowNotFound,
            self.helper._get_or_create_ovn_lb,
            self.ovn_lb.name,
            protocol='TCP',
            admin_state_up='True')

    @mock.patch.object(ovn_helper.OvnProviderHelper, 'lb_create')
    def test__get_or_create_ovn_lb_required_proto_not_found(self, lbc):
        udp_lb = copy.copy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.side_effect = [[udp_lb], [self.ovn_lb]]
        self.helper._get_or_create_ovn_lb(
            self.ovn_lb.name,
            protocol='TCP',
            admin_state_up='True')
        expected_lb_info = {
            'id': self.ovn_lb.name,
            'protocol': 'tcp',
            'lb_algorithm': constants.LB_ALGORITHM_SOURCE_IP_PORT,
            'vip_address': udp_lb.external_ids.get(
                ovn_const.LB_EXT_IDS_VIP_KEY),
            'vip_port_id':
                udp_lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY),
            ovn_const.LB_EXT_IDS_LR_REF_KEY:
                udp_lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_LR_REF_KEY),
            ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                udp_lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_LS_REFS_KEY),
            'admin_state_up': 'True',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY:
                udp_lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_VIP_FIP_KEY)}
        lbc.assert_called_once_with(expected_lb_info, protocol='tcp')

    def test__get_or_create_ovn_lb_found(self):
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb]
        found = self.helper._get_or_create_ovn_lb(
            self.ovn_lb.name,
            protocol='TCP',
            admin_state_up='True')
        self.assertEqual(found, self.ovn_lb)

    def test__get_or_create_ovn_lb_lb_without_protocol(self):
        self.mock_find_ovn_lbs.stop()
        self.ovn_lb.protocol = []
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb]
        found = self.helper._get_or_create_ovn_lb(
            self.ovn_lb.name,
            protocol='TCP',
            admin_state_up='True')
        self.assertEqual(found, self.ovn_lb)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, ('protocol', 'tcp'))

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_create_disabled(self, net_cli):
        self.lb['admin_state_up'] = False
        net_cli.return_value.list_ports.return_value = self.ports
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer', external_ids={
                ovn_const.LB_EXT_IDS_VIP_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: mock.ANY,
                'enabled': 'False'},
            name=mock.ANY,
            protocol=[],
            selection_fields=['ip_src', 'ip_dst', 'tp_src', 'tp_dst'])

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_create_enabled(self, net_cli):
        self.lb['admin_state_up'] = True
        net_cli.return_value.list_ports.return_value = self.ports
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer', external_ids={
                ovn_const.LB_EXT_IDS_VIP_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: mock.ANY,
                'enabled': 'True'},
            name=mock.ANY,
            protocol=[],
            selection_fields=['ip_src', 'ip_dst', 'tp_src', 'tp_dst'])

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_create_selection_fields_not_supported(self, net_cli):
        self.lb['admin_state_up'] = True
        net_cli.return_value.list_ports.return_value = self.ports
        self.helper._are_selection_fields_supported = (
            mock.Mock(return_value=False))
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer', external_ids={
                ovn_const.LB_EXT_IDS_VIP_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: mock.ANY,
                'enabled': 'True'},
            name=mock.ANY,
            protocol=[])

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_create_selection_fields_not_supported_algo(self, net_cli):
        self.lb['admin_state_up'] = True
        net_cli.return_value.list_ports.return_value = self.ports
        net_cli.return_value.show_subnet.return_value = {
            'subnet': mock.MagicMock()}
        self.pool['lb_algoritm'] = 'foo'
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        # NOTE(mjozefcz): Make sure that we use the same selection
        # fields as for default algorithm - source_ip_port.
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer', external_ids={
                ovn_const.LB_EXT_IDS_VIP_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: mock.ANY,
                'enabled': 'True'},
            name=mock.ANY,
            protocol=[],
            selection_fields=['ip_src', 'ip_dst', 'tp_src', 'tp_dst'])

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def _test_lb_create_on_multi_protocol(self, protocol, net_cli):
        """This test situation when new protocol is added

           to the same loadbalancer and we need to add
           additional OVN lb with the same name.
        """
        self.lb['admin_state_up'] = True
        self.lb['protocol'] = protocol
        self.lb[ovn_const.LB_EXT_IDS_LR_REF_KEY] = 'foo'
        self.lb[ovn_const.LB_EXT_IDS_LS_REFS_KEY] = '{\"neutron-foo\": 1}'
        net_cli.return_value.list_ports.return_value = self.ports
        status = self.helper.lb_create(self.lb, protocol=protocol)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer', external_ids={
                ovn_const.LB_EXT_IDS_VIP_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_LR_REF_KEY: 'foo',
                'enabled': 'True'},
            name=mock.ANY,
            protocol=protocol.lower(),
            selection_fields=['ip_src', 'ip_dst', 'tp_src', 'tp_dst'])
        self.helper._update_lb_to_ls_association.assert_has_calls([
            mock.call(self.ovn_lb, associate=True,
                      network_id=self.lb['vip_network_id']),
            mock.call(self.ovn_lb, associate=True, network_id='foo')])

    def test_lb_create_on_multi_protocol_UDP(self):
        self._test_lb_create_on_multi_protocol('UDP')

    def test_lb_create_on_multi_protocol_SCTP(self):
        self._test_lb_create_on_multi_protocol('SCTP')

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_vip_port')
    def test_lb_create_exception(self, del_port, net_cli):
        self.helper._find_ovn_lbs.side_effect = [RuntimeError]
        net_cli.return_value.list_ports.return_value = self.ports
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        del_port.assert_called_once_with(self.ports.get('ports')[0]['id'])

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_vip_port')
    def test_lb_delete(self, del_port, net_cli):
        net_cli.return_value.delete_port.return_value = None
        status = self.helper.lb_delete(self.ovn_lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_called_once_with('foo_port')

    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_vip_port')
    def test_lb_delete_row_not_found(self, del_port):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        del_port.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_vip_port')
    def test_lb_delete_exception(self, del_port):
        self.helper.ovn_nbdb_api.lb_del.side_effect = [RuntimeError]
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_called_once_with('foo_port')

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_vip_port')
    def test_lb_delete_port_not_found(self, del_port, net_cli):
        net_cli.return_value.delete_port.side_effect = (
            [n_exc.PortNotFoundClient])
        status = self.helper.lb_delete(self.ovn_lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_called_once_with('foo_port')

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_delete_cascade(self, net_cli):
        net_cli.return_value.delete_port.return_value = None
        self.lb['cascade'] = True
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.DELETED)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_delete_ls_lr(self, net_cli):
        self.ovn_lb.external_ids.update({
            ovn_const.LB_EXT_IDS_LR_REF_KEY: self.router.name,
            ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                '{\"neutron-%s\": 1}' % self.network.uuid})
        net_cli.return_value.delete_port.return_value = None
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.helper.ovn_nbdb_api.lookup.return_value = self.router
        self.helper.lb_delete(self.ovn_lb)
        self.helper.ovn_nbdb_api.ls_lb_del.assert_called_once_with(
            self.network.uuid, self.ovn_lb.uuid)
        self.helper.ovn_nbdb_api.lr_lb_del.assert_called_once_with(
            self.router.uuid, self.ovn_lb.uuid)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_delete_multiple_protocols(self, net_cli):
        net_cli.return_value.delete_port.return_value = None
        self.mock_find_ovn_lbs.stop()
        udp_lb = copy.copy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        udp_lb.uuid = 'foo_uuid'
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb, udp_lb]
        self.helper.lb_delete(self.lb)
        self.helper.ovn_nbdb_api.lb_del.assert_has_calls([
            mock.call(self.ovn_lb.uuid),
            mock.call(udp_lb.uuid)])

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_lb_update_disabled(self, refresh_vips):
        self.lb['admin_state_up'] = False
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('external_ids', {'enabled': 'False'}))

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_lb_update_enabled(self, refresh_vips):
        # Change the mock, its enabled by default.
        self.ovn_lb.external_ids.update({'enabled': False})
        self.lb['admin_state_up'] = True
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('external_ids', {'enabled': 'True'}))

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_lb_update_enabled_multiple_protocols(self, refresh_vips):
        self.mock_find_ovn_lbs.stop()
        self.ovn_lb.external_ids.update({'enabled': 'False'})
        udp_lb = copy.deepcopy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        udp_lb.uuid = 'foo_uuid'
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb, udp_lb]
        self.lb['admin_state_up'] = True
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        refresh_vips.assert_has_calls([
            mock.call(self.ovn_lb.uuid, self.ovn_lb.external_ids),
            mock.ANY,
            mock.ANY,
            mock.call(udp_lb.uuid, udp_lb.external_ids)],
            any_order=False)
        self.helper.ovn_nbdb_api.db_set.assert_has_calls([
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {'enabled': 'True'})),
            mock.call('Load_Balancer', udp_lb.uuid,
                      ('external_ids', {'enabled': 'True'}))])

    def test_lb_update_exception(self):
        self.helper._find_ovn_lbs.side_effect = [RuntimeError]
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)

    def test_lb_update_no_admin_state_up(self):
        self.lb.pop('admin_state_up')
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper._find_ovn_lbs.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_create_disabled(self, refresh_vips):
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        status = self.helper.listener_create(self.listener)
        # Set expected as disabled
        self.ovn_lb.external_ids.update({
            'listener_%s:D' % self.listener_id: '80:pool_%s' % self.pool_id})
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)
        expected_calls = [
            mock.call(
                'Load_Balancer', self.ovn_lb.uuid,
                ('external_ids', {
                    'listener_%s:D' % self.listener_id:
                        '80:pool_%s' % self.pool_id})),
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('protocol', 'tcp'))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(expected_calls)
        self.assertEqual(
            len(expected_calls),
            self.helper.ovn_nbdb_api.db_set.call_count)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_create_enabled(self, refresh_vips):
        self.listener['admin_state_up'] = True
        status = self.helper.listener_create(self.listener)
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)
        expected_calls = [
            mock.call(
                'Load_Balancer', self.ovn_lb.uuid,
                ('external_ids', {
                    'listener_%s' % self.listener_id:
                        '80:pool_%s' % self.pool_id}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(expected_calls)
        self.assertEqual(
            len(expected_calls),
            self.helper.ovn_nbdb_api.db_set.call_count)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)

    def test_listener_create_no_default_pool(self):
        self.listener['admin_state_up'] = True
        self.listener.pop('default_pool_id')
        self.helper.listener_create(self.listener)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('external_ids', {
                'listener_%s' % self.listener_id: '80:'})),
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips', {}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)
        self.assertEqual(
            len(expected_calls),
            self.helper.ovn_nbdb_api.db_set.call_count)

    def test_listener_create_exception(self):
        self.helper.ovn_nbdb_api.db_set.side_effect = [RuntimeError]
        status = self.helper.listener_create(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ERROR)

    def test_listener_update(self):
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.listener['admin_state_up'] = True
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_listener_update_row_not_found(self):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ERROR)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_update_exception(self, refresh_vips):
        refresh_vips.side_effect = [RuntimeError]
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_update_listener_enabled(self, refresh_vips):
        self.listener['admin_state_up'] = True
        # Update the listener port.
        self.listener.update({'protocol_port': 123})
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('external_ids', {
                'listener_%s' % self.listener_id:
                '123:pool_%s' % self.pool_id}))
        # Update expected listener, because it was updated.
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        self.ovn_lb.external_ids.update(
            {'listener_%s' % self.listener_id: '123:pool_%s' % self.pool_id})
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_update_listener_disabled(self, refresh_vips):
        self.listener['admin_state_up'] = False
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, 'external_ids',
            'listener_%s' % self.listener_id)
        # It gets disabled, so update the key
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        self.ovn_lb.external_ids.update(
            {'listener_%s:D' % self.listener_id: '80:pool_%s' % self.pool_id})
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_update_no_admin_state_up(self, refresh_vips):
        self.listener.pop('admin_state_up')
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_update_no_admin_state_up_or_default_pool_id(
            self, refresh_vips):
        self.listener.pop('admin_state_up')
        self.listener.pop('default_pool_id')
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()
        refresh_vips.assert_not_called()

    def test_listener_delete_no_external_id(self):
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()

    def test_listener_delete_row_not_found(self):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)

    def test_listener_delete_exception(self):
        self.helper.ovn_nbdb_api.db_remove.side_effect = [RuntimeError]
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_delete_external_id(self, refresh_vips):
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_is_lb_empty')
    def test_listener_delete_ovn_lb_not_empty(self, lb_empty):
        lb_empty.return_value = False
        self.helper.listener_delete(self.listener)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_is_lb_empty')
    def test_listener_delete_ovn_lb_empty_octavia_lb_empty(self, lb_empty):
        """That test situation when the OVN and Octavia LBs are empty.

           That test situation when both OVN and Octavia LBs are empty,
           but we cannot remove OVN LB row.
        """
        lb_empty.return_value = True
        self.helper.listener_delete(self.listener)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        # Assert that protocol has been set to [].
        self.helper.ovn_nbdb_api.db_set.assert_has_calls([
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('protocol', []))])

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_is_lb_empty')
    def test_listener_delete_ovn_lb_empty_octavia_lb_not_empty(self, lb_empty):
        """We test if we can remove one LB with not used protocol"""
        ovn_lb_udp = copy.copy(self.ovn_lb)
        ovn_lb_udp.protocol = ['udp']
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.side_effect = [[self.ovn_lb], [self.ovn_lb, ovn_lb_udp]]
        lb_empty.return_value = True
        self.helper.listener_delete(self.listener)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        # Validate that the vips column hasn't been touched, because
        # in previous command we remove the LB, so there is no need
        # to update it.
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test_pool_create(self):
        status = self.helper.pool_create(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        self.pool['admin_state_up'] = True
        # Pool Operating status shouldnt change if member isnt present.
        status = self.helper.pool_create(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        # Pool without listener set should be OFFLINE
        self.pool['listener_id'] = None
        status = self.helper.pool_create(self.pool)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)

    def test_pool_create_exception(self):
        self.helper.ovn_nbdb_api.db_set.side_effect = [RuntimeError]
        status = self.helper.pool_create(self.pool)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_pool_update(self):
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)
        self.pool['admin_state_up'] = True
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)

    def test_pool_update_exception_not_found(self):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)

    def test_pool_update_exception(self):
        self.helper._get_pool_listeners.side_effect = [RuntimeError]
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)

    def test_pool_update_unset_admin_state_up(self):
        self.pool.pop('admin_state_up')
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_pool_update_pool_disabled_change_to_up(self):
        self.pool.update({'admin_state_up': True})
        disabled_p_key = self.helper._get_pool_key(self.pool_id,
                                                   is_enabled=False)
        p_key = self.helper._get_pool_key(self.pool_id)
        self.ovn_lb.external_ids.update({
            disabled_p_key: self.member_line})
        self.ovn_lb.external_ids.pop(p_key)
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids',
                          {'pool_%s' % self.pool_id: self.member_line})),
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips', {'10.22.33.4:80': '192.168.2.149:1010',
                                '123.123.123.123:80': '192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_pool_update_pool_up_change_to_disabled(self):
        self.pool.update({'admin_state_up': False})
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids',
                          {'pool_%s:D' % self.pool_id: self.member_line})),
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('vips', {}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_pool_update_listeners(self):
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_pool_delete(self):
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)
        self.helper.ovn_nbdb_api.db_clear.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, 'vips')
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s' % self.pool_id)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('vips', {})),
            mock.call(
                'Load_Balancer', self.ovn_lb.uuid,
                ('external_ids', {
                    ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
                    ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.123',
                    ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_port',
                    'enabled': True,
                    'listener_%s' % self.listener_id: '80:'}))]
        self.assertEqual(self.helper.ovn_nbdb_api.db_set.call_count,
                         len(expected_calls))
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_pool_delete_row_not_found(self):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test_pool_delete_exception(self):
        self.helper.ovn_nbdb_api.db_set.side_effect = [RuntimeError]
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)

    def test_pool_delete_associated_listeners(self):
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper.ovn_nbdb_api.db_set.assert_called_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('external_ids', {
                'enabled': True,
                'listener_%s' % self.listener_id: '80:',
                ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
                ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.123',
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_port'}))

    def test_pool_delete_pool_disabled(self):
        disabled_p_key = self.helper._get_pool_key(self.pool_id,
                                                   is_enabled=False)
        p_key = self.helper._get_pool_key(self.pool_id)
        self.ovn_lb.external_ids.update({
            disabled_p_key: self.member_line})
        self.ovn_lb.external_ids.pop(p_key)
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s:D' % self.pool_id)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_is_lb_empty')
    def test_pool_delete_ovn_lb_not_empty(self, lb_empty):
        lb_empty.return_value = False
        self.helper.pool_delete(self.pool)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s' % self.pool_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_is_lb_empty')
    def test_pool_delete_ovn_lb_empty_lb_empty(self, lb_empty):
        lb_empty.return_value = True
        self.helper.pool_delete(self.pool)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s' % self.pool_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        # Assert that protocol has been set to [].
        self.helper.ovn_nbdb_api.db_set.assert_called_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('protocol', []))

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_is_lb_empty')
    def test_pool_delete_ovn_lb_empty_lb_not_empty(self, lb_empty):
        ovn_lb_udp = copy.copy(self.ovn_lb)
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.side_effect = [[self.ovn_lb], [self.ovn_lb, ovn_lb_udp]]
        lb_empty.return_value = True
        self.helper.pool_delete(self.pool)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s' % self.pool_id)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_member_create(self, net_cli):
        net_cli.return_value.show_subnet.side_effect = [
            idlutils.RowNotFound, idlutils.RowNotFound]
        self.ovn_lb.external_ids = mock.MagicMock()
        status = self.helper.member_create(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.member['admin_state_up'] = False
        status = self.helper.member_create(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.OFFLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_lr_of_ls')
    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_member_create_lb_add_from_lr(self, net_cli, f_lr, folbpi):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        net_cli.return_value.show_subnet.return_value = {'subnet': fake_subnet}
        f_lr.return_value = self.router
        pool_key = 'pool_%s' % self.pool_id
        folbpi.return_value = (pool_key, self.ovn_lb)
        self.ovn_lb.external_ids = mock.MagicMock()
        status = self.helper.member_create(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        f_lr.assert_called_once_with(self.network, fake_subnet['gateway_ip'])
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.ovn_lb, self.router)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ls_for_lr')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_lr_of_ls')
    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_member_create_lb_add_from_lr_no_ls(self, net_cli, f_lr, f_ls):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        net_cli.return_value.show_subnet.return_value = {'subnet': fake_subnet}
        self.ovn_lb.external_ids = mock.MagicMock()
        (self.helper.ovn_nbdb_api.ls_get.return_value.
            execute.side_effect) = [n_exc.NotFound]
        status = self.helper.member_create(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            assert_called_once_with(check_error=True))
        f_lr.assert_not_called()
        f_ls.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_add_member')
    def test_member_create_exception(self, mock_add_member):
        mock_add_member.side_effect = [RuntimeError]
        status = self.helper.member_create(self.member)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)

    def test_member_create_lb_disabled(self):
        self.helper._find_ovn_lb_with_pool_key.side_effect = [
            None, self.ovn_lb]
        self.helper.member_create(self.member)
        self.helper._find_ovn_lb_with_pool_key.assert_has_calls(
            [mock.call('pool_%s' % self.pool_id),
             mock.call('pool_%s%s' % (self.pool_id, ':D'))])

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_member_create_listener(self, net_cli):
        net_cli.return_value.show_subnet.side_effect = [idlutils.RowNotFound]
        self.ovn_lb.external_ids = mock.MagicMock()
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.member_create(self.member)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['id'],
                         'listener1')

    def test_member_create_already_exists(self):
        self.helper.member_create(self.member)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test_member_create_first_member_in_pool(self):
        self.ovn_lb.external_ids.update({
            'pool_' + self.pool_id: ''})
        self.helper.member_create(self.member)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids',
                       {'pool_%s' % self.pool_id: self.member_line})),
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips', {
                          '10.22.33.4:80': '192.168.2.149:1010',
                          '123.123.123.123:80': '192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_member_create_second_member_in_pool(self):
        member2_id = uuidutils.generate_uuid()
        member2_subnet_id = uuidutils.generate_uuid()
        member2_port = '1010'
        member2_address = '192.168.2.150'
        member2_line = ('member_%s_%s:%s_%s' %
                        (member2_id, member2_address,
                         member2_port, member2_subnet_id))
        self.ovn_lb.external_ids.update(
            {'pool_%s' % self.pool_id: member2_line})
        self.helper.member_create(self.member)
        all_member_line = (
            '%s,member_%s_%s:%s_%s' %
            (member2_line, self.member_id,
             self.member_address, self.member_port,
             self.member_subnet_id))
        # We have two members now.
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {
                          'pool_%s' % self.pool_id: all_member_line})),
            mock.call(
                'Load_Balancer', self.ovn_lb.uuid,
                ('vips', {
                    '10.22.33.4:80':
                        '192.168.2.150:1010,192.168.2.149:1010',
                    '123.123.123.123:80':
                        '192.168.2.150:1010,192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_member_update(self):
        self.ovn_lb.external_ids = mock.MagicMock()
        status = self.helper.member_update(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ONLINE)
        self.member['admin_state_up'] = False
        status = self.helper.member_update(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.OFFLINE)
        self.member['old_admin_state_up'] = False
        self.member['admin_state_up'] = True
        status = self.helper.member_update(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.NO_MONITOR)

    def test_member_update_disabled_lb(self):
        self.helper._find_ovn_lb_with_pool_key.side_effect = [
            None, self.ovn_lb]
        self.helper.member_update(self.member)
        self.helper._find_ovn_lb_with_pool_key.assert_has_calls(
            [mock.call('pool_%s' % self.pool_id),
             mock.call('pool_%s%s' % (self.pool_id, ':D'))])

    def test_member_update_pool_listeners(self):
        self.ovn_lb.external_ids = mock.MagicMock()
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.member_update(self.member)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['id'],
                         'listener1')

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_update_member')
    def test_member_update_exception(self, mock_update_member):
        mock_update_member.side_effect = [RuntimeError]
        status = self.helper.member_update(self.member)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_member_update_new_member_line(self):
        old_member_line = (
            'member_%s_%s:%s' %
            (self.member_id, self.member_address,
             self.member_port))
        new_member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        self.ovn_lb.external_ids.update(
            {'pool_%s' % self.pool_id: old_member_line})
        self.helper.member_update(self.member)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {
                          'pool_%s' % self.pool_id: new_member_line}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_member_update_new_port(self):
        new_port = 11
        member_line = ('member_%s_%s:%s_%s' %
                       (self.member_id, self.member_address,
                        new_port, self.member_subnet_id))
        self.ovn_lb.external_ids.update(
            {'pool_%s' % self.pool_id: member_line})
        self.helper.member_update(self.member)
        new_member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {
                          'pool_%s' % self.pool_id: new_member_line})),
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('vips', {
                '10.22.33.4:80': '192.168.2.149:1010',
                '123.123.123.123:80': '192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_refresh_lb_vips')
    def test_member_delete(self, mock_vip_command):
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.DELETED)

    def test_member_delete_one_left(self):
        member2_id = uuidutils.generate_uuid()
        member2_port = '1010'
        member2_address = '192.168.2.150'
        member2_subnet_id = uuidutils.generate_uuid()
        member_line = (
            'member_%s_%s:%s_%s,member_%s_%s:%s_%s' %
            (self.member_id, self.member_address, self.member_port,
             self.member_subnet_id,
             member2_id, member2_address, member2_port, member2_subnet_id))
        self.ovn_lb.external_ids.update({
            'pool_' + self.pool_id: member_line})
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_remove_member')
    def test_member_delete_exception(self, mock_remove_member):
        mock_remove_member.side_effect = [RuntimeError]
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_member_delete_disabled_lb(self):
        self.helper._find_ovn_lb_with_pool_key.side_effect = [
            None, self.ovn_lb]
        self.helper.member_delete(self.member)
        self.helper._find_ovn_lb_with_pool_key.assert_has_calls(
            [mock.call('pool_%s' % self.pool_id),
             mock.call('pool_%s%s' % (self.pool_id, ':D'))])

    def test_member_delete_pool_listeners(self):
        member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address, self.member_port,
             self.member_subnet_id))
        self.ovn_lb.external_ids.update({
            'pool_' + self.pool_id: member_line})
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['id'],
                         'listener1')

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_logical_router_port_event_create(self, net_cli):
        self.router_port_event = ovn_event.LogicalRouterPortEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'gateway_chassis': []})
        self.router_port_event.run('create', row, mock.ANY)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network},
            'type': 'lb_create_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_logical_router_port_event_delete(self, net_cli):
        self.router_port_event = ovn_event.LogicalRouterPortEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'gateway_chassis': []})
        self.router_port_event.run('delete', row, mock.ANY)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network},
            'type': 'lb_delete_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_logical_router_port_event_gw_port(self, net_cli):
        self.router_port_event = ovn_event.LogicalRouterPortEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'gateway_chassis': ['temp-gateway-chassis']})
        self.router_port_event.run(mock.ANY, row, mock.ANY)
        self.mock_add_request.assert_not_called()

    def test__get_nw_router_info_on_interface_event(self):
        self.mock_get_nw.stop()
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1',
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'network1'}
            })
        self.helper._get_nw_router_info_on_interface_event(lrp)
        expected_calls = [
            mock.call.lookup('Logical_Router', 'neutron-router1'),
            mock.call.lookup('Logical_Switch', 'network1')]
        self.helper.ovn_nbdb_api.assert_has_calls(expected_calls)

    def test__get_nw_router_info_on_interface_event_not_found(self):
        self.mock_get_nw.stop()
        self.helper.ovn_nbdb_api.lookup.side_effect = [idlutils.RowNotFound]
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1'}
            })
        self.assertRaises(
            idlutils.RowNotFound,
            self.helper._get_nw_router_info_on_interface_event,
            lrp)

    def test_lb_delete_lrp_assoc_handler(self):
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        self.helper.lb_delete_lrp_assoc_handler(lrp)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network},
            'type': 'lb_delete_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    def test_lb_delete_lrp_assoc_handler_info_not_found(self):
        self.mock_get_nw.stop()
        self.helper.ovn_nbdb_api.lookup.side_effect = [idlutils.RowNotFound]
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1'}
            })
        self.helper.lb_delete_lrp_assoc_handler(lrp)
        self.mock_add_request.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test_lb_delete_lrp_assoc_no_net_lb_no_r_lb(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.network.load_balancer = []
        self.router.load_balancer = []
        self.helper.lb_delete_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_not_called()
        mock_execute.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test_lb_delete_lrp_assoc_no_net_lb_r_lb(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.network.load_balancer = []
        self.helper.lb_delete_lrp_assoc(info)
        expected = [
            self.helper.ovn_nbdb_api.ls_lb_del(
                self.network.uuid,
                self.router.load_balancer[0].uuid
            ),
        ]
        self.helper._update_lb_to_lr_association.assert_not_called()
        mock_execute.assert_called_once_with(expected)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test_lb_delete_lrp_assoc_net_lb_no_r_lb(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.router.load_balancer = []
        self.helper.lb_delete_lrp_assoc(info)
        mock_execute.assert_not_called()
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router, delete=True
        )

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test_lb_delete_lrp_assoc(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.helper.lb_delete_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router, delete=True
        )
        expected = [
            self.helper.ovn_nbdb_api.ls_lb_del(
                self.network.uuid,
                self.router.load_balancer[0].uuid
            ),
        ]
        mock_execute.assert_called_once_with(expected)

    def test_lb_create_lrp_assoc_handler(self):
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        self.helper.lb_create_lrp_assoc_handler(lrp)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network},
            'type': 'lb_create_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    def test_lb_create_lrp_assoc_handler_row_not_found(self):
        self.mock_get_nw.stop()
        self.helper.ovn_nbdb_api.lookup.side_effect = [idlutils.RowNotFound]
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1'}
            })
        self.helper.lb_create_lrp_assoc_handler(lrp)
        self.mock_add_request.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test_lb_create_lrp_assoc(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.helper.lb_create_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router
        )
        expected = [
            self.helper.ovn_nbdb_api.ls_lb_add(
                self.network.uuid,
                self.router.load_balancer[0].uuid
            ),
        ]
        mock_execute.assert_called_once_with(expected)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test_lb_create_lrp_assoc_uniq_lb(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        # Make it already uniq.
        self.network.load_balancer = self.router.load_balancer
        self.helper.lb_create_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_not_called()
        mock_execute.assert_not_called()

    def test__find_lb_in_ls(self):
        net_lb = self.helper._find_lb_in_ls(self.network)
        for lb in self.network.load_balancer:
            self.assertIn(lb, net_lb)

    def test__find_lb_in_ls_wrong_ref(self):
        # lets break external_ids refs
        self.network.load_balancer[0].external_ids.update({
            ovn_const.LB_EXT_IDS_LS_REFS_KEY: 'foo'})
        net_lb = self.helper._find_lb_in_ls(self.network)
        for lb in self.network.load_balancer:
            self.assertNotIn(lb, net_lb)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__find_ls_for_lr(self, net_cli):
        fake_subnet1 = fakes.FakeSubnet.create_one_subnet()
        fake_subnet1['network_id'] = 'foo1'
        fake_subnet2 = fakes.FakeSubnet.create_one_subnet()
        fake_subnet2['network_id'] = 'foo2'
        net_cli.return_value.show_subnet.side_effect = [
            {'subnet': fake_subnet1},
            {'subnet': fake_subnet2}]
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_SUBNET_EXT_IDS_KEY:
                '%s %s' % (fake_subnet1.id,
                           fake_subnet2.id)}})
        self.router.ports.append(p1)
        res = self.helper._find_ls_for_lr(self.router)
        self.assertListEqual(['neutron-foo1', 'neutron-foo2'],
                             res)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__find_ls_for_lr_subnet_not_found(self, net_cli):
        fake_subnet1 = fakes.FakeSubnet.create_one_subnet()
        fake_subnet1['network_id'] = 'foo1'
        fake_subnet2 = fakes.FakeSubnet.create_one_subnet()
        fake_subnet2['network_id'] = 'foo2'
        net_cli.return_value.show_subnet.side_effect = [
            {'subnet': fake_subnet1},
            n_exc.NotFound]
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_SUBNET_EXT_IDS_KEY:
                '%s %s' % (fake_subnet1.id,
                           fake_subnet2.id)}})
        self.router.ports.append(p1)
        res = self.helper._find_ls_for_lr(self.router)
        self.assertListEqual(['neutron-foo1'], res)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__find_ls_for_lr_gw_port(self, net_cli):
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': ['foo-gw-chassis'],
            'external_ids': {
                ovn_const.OVN_SUBNET_EXT_IDS_KEY: self.member_subnet_id}})
        self.router.ports.append(p1)
        result = self.helper._find_ls_for_lr(self.router)
        self.assertListEqual([], result)

    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_del_lb_to_lr_association')
    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_add_lb_to_lr_association')
    def test__update_lb_to_lr_association(self, add, delete):
        self._update_lb_to_lr_association.stop()
        self.helper._update_lb_to_lr_association(self.ref_lb1, self.router)
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        add.assert_called_once_with(self.ref_lb1, self.router, lr_ref)
        delete.assert_not_called()

    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_del_lb_to_lr_association')
    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_add_lb_to_lr_association')
    def test__update_lb_to_lr_association_delete(self, add, delete):
        self._update_lb_to_lr_association.stop()
        self.helper._update_lb_to_lr_association(
            self.ref_lb1, self.router, delete=True)
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        add.assert_not_called()
        delete.assert_called_once_with(self.ref_lb1, self.router, lr_ref)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__del_lb_to_lr_association(self, net_cli):
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        upd_lr_ref = '%s,%s' % (lr_ref, self.router.name)
        self.helper._del_lb_to_lr_association(
            self.ref_lb1, self.router, upd_lr_ref)
        expected_calls = [
            mock.call.db_set(
                'Load_Balancer', self.ref_lb1.uuid,
                (('external_ids',
                  {ovn_const.LB_EXT_IDS_LR_REF_KEY: lr_ref}))),
            mock.call.lr_lb_del(
                self.router.uuid, self.ref_lb1.uuid,
                if_exists=True)]
        self.helper.ovn_nbdb_api.assert_has_calls(
            expected_calls)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__del_lb_to_lr_association_no_lr_ref(self, net_cli):
        lr_ref = ''
        self.helper._del_lb_to_lr_association(
            self.ref_lb1, self.router, lr_ref)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()
        self.helper.ovn_nbdb_api.lr_lb_del.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__del_lb_to_lr_association_lr_ref_empty_after(self, net_cli):
        lr_ref = self.router.name
        self.helper._del_lb_to_lr_association(
            self.ref_lb1, self.router, lr_ref)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, 'external_ids',
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        self.helper.ovn_nbdb_api.lr_lb_del.assert_called_once_with(
            self.router.uuid, self.ref_lb1.uuid, if_exists=True)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ls_for_lr')
    def test__del_lb_to_lr_association_from_ls(self, f_ls):
        # This test if LB is deleted from Logical_Router_Port
        # Logical_Switch.
        f_ls.return_value = ['neutron-xyz', 'neutron-qwr']
        self.helper._del_lb_to_lr_association(self.ref_lb1, self.router, '')
        self.helper.ovn_nbdb_api.ls_lb_del.assert_has_calls([
            (mock.call('neutron-xyz', self.ref_lb1.uuid, if_exists=True)),
            (mock.call('neutron-qwr', self.ref_lb1.uuid, if_exists=True))])

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ls_for_lr')
    def test__add_lb_to_lr_association(self, f_ls):
        lr_ref = 'foo'
        f_ls.return_value = ['neutron-xyz', 'neutron-qwr']
        self.helper._add_lb_to_lr_association(
            self.ref_lb1, self.router, lr_ref)
        self.helper.ovn_nbdb_api.lr_lb_add.assert_called_once_with(
            self.router.uuid, self.ref_lb1.uuid, may_exist=True)
        self.helper.ovn_nbdb_api.ls_lb_add.assert_has_calls([
            (mock.call('neutron-xyz', self.ref_lb1.uuid, may_exist=True)),
            (mock.call('neutron-qwr', self.ref_lb1.uuid, may_exist=True))])
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid,
            ('external_ids', {'lr_ref': 'foo,%s' % self.router.name}))

    def test__find_lr_of_ls(self):
        lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1',
                    'neutron:cidrs': '10.10.10.1/24',
                    ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                        n_const.DEVICE_OWNER_ROUTER_INTF},
                'type': 'router',
                'options': {
                    'router-port': 'lrp-foo-name'},
            })
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router2',
                    'neutron:cidrs': '10.10.10.2/24',
                    ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                        n_const.DEVICE_OWNER_ROUTER_INTF},
                'type': 'router',
                'options': {
                    'router-port': 'lrp-bar-name'},
            })
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'name': 'lrp-foo-name',
            })
        lr = fakes.FakeOVNRouter.create_one_router(
            attrs={
                'name': 'router1',
                'ports': [lrp]})
        ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [lsp2, lsp]})

        (self.helper.ovn_nbdb_api.get_lrs.return_value.
            execute.return_value) = [lr]
        returned_lr = self.helper._find_lr_of_ls(ls, '10.10.10.1')
        self.assertEqual(lr, returned_lr)

    def test__find_lr_of_ls_gw_port_id(self):
        lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1',
                    ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                        n_const.DEVICE_OWNER_ROUTER_INTF},
                'type': 'router',
                'options': {
                    'router-port': 'lrp-lrp-foo-name'}
            })
        lr = fakes.FakeOVNRouter.create_one_router(
            attrs={
                'name': 'router1',
                'ports': [],
                'external_ids': {
                    'neutron:gw_port_id': 'lrp-foo-name'}})
        ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [lsp]})

        (self.helper.ovn_nbdb_api.get_lrs.return_value.
            execute.return_value) = [lr]
        returned_lr = self.helper._find_lr_of_ls(ls)
        self.assertEqual(lr, returned_lr)

    def test__find_lr_of_ls_no_lrp_name(self):
        lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1'},
                'type': 'router',
                'options': {
                    'router-port': None}
            })
        ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [lsp]})
        returned_lr = self.helper._find_lr_of_ls(ls)
        self.assertIsNone(returned_lr)

    def test__find_lr_of_ls_no_lrp(self):
        ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': []})
        returned_lr = self.helper._find_lr_of_ls(ls)
        (self.helper.ovn_nbdb_api.tables['Logical_Router'].rows.
            values.assert_not_called())
        self.assertIsNone(returned_lr)

    def test__update_lb_to_ls_association_empty_network_and_subnet(self):
        self._update_lb_to_ls_association.stop()
        returned_commands = self.helper._update_lb_to_ls_association(
            self.ref_lb1, associate=True)
        self.assertListEqual(returned_commands, [])

    def test__update_lb_to_ls_association_network(self):
        self._update_lb_to_ls_association.stop()

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=True)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        ls_refs = {'ls_refs': '{"%s": 2}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', ls_refs))

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__update_lb_to_ls_association_subnet(self, net_cli):
        self._update_lb_to_ls_association.stop()
        subnet = fakes.FakeSubnet.create_one_subnet(
            attrs={'id': 'foo_subnet_id',
                   'name': 'foo_subnet_name',
                   'network_id': 'foo_network_id'})
        net_cli.return_value.show_subnet.return_value = {
            'subnet': subnet}
        self.helper._update_lb_to_ls_association(
            self.ref_lb1, subnet_id=subnet.id, associate=True)
        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            'neutron-foo_network_id')

    def test__update_lb_to_ls_association_empty_ls_refs(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.ref_lb1.external_ids.pop('ls_refs')

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid)

        self.helper.ovn_nbdb_api.ls_lb_add.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, may_exist=True)
        ls_refs = {'ls_refs': '{"%s": 1}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', ls_refs))

    def test__update_lb_to_ls_association_no_ls(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            side_effect) = [idlutils.RowNotFound]

        returned_commands = self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.assertListEqual([], returned_commands)

    def test__update_lb_to_ls_association_network_disassociate(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid,
            ('external_ids', {'ls_refs': '{}'}))
        self.helper.ovn_nbdb_api.ls_lb_del.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, if_exists=True)

    def test__update_lb_to_ls_association_network_dis_ls_not_found(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            side_effect) = [idlutils.RowNotFound]

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid,
            ('external_ids', {'ls_refs': '{}'}))
        self.helper.ovn_nbdb_api.ls_lb_del.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__update_lb_to_ls_association_network_dis_net_not_found(
            self, net_cli):
        net_cli.return_value.show_subnet.side_effect = n_exc.NotFound
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.helper._update_lb_to_ls_association(
            self.ref_lb1, subnet_id='foo', associate=False)
        self.helper.ovn_nbdb_api.ls_get.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()
        self.helper.ovn_nbdb_api.ls_lb_del.assert_not_called()

    def test__update_lb_to_ls_association_disassoc_ls_not_in_ls_refs(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.ref_lb1.external_ids.pop('ls_refs')

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=False)

        self.helper.ovn_nbdb_api.ls_lb_del.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test__update_lb_to_ls_association_disassoc_multiple_refs(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        # multiple refs
        ls_refs = {'ls_refs': '{"%s": 2}' % self.network.name}
        self.ref_lb1.external_ids.update(ls_refs)

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        exp_ls_refs = {'ls_refs': '{"%s": 1}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', exp_ls_refs))

    def test_logical_switch_port_update_event_vip_port(self):
        self.switch_port_event = ovn_event.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, 'foo')
        attrs = {
            'external_ids':
            {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name,
             ovn_const.OVN_PORT_FIP_EXT_ID_KEY: '10.0.0.1'}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        expected_call = {
            'info':
                {'action': 'associate',
                 'vip_fip': '10.0.0.1',
                 'ovn_lb': self.ovn_lb},
            'type': 'handle_vip_fip'}
        self.mock_add_request.assert_called_once_with(expected_call)

    def test_logical_switch_port_update_event_missing_port_name(self):
        self.switch_port_event = ovn_event.LogicalSwitchPortUpdateEvent(
            self.helper)
        attrs = {'external_ids': {}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        self.mock_add_request.assert_not_called()

    def test_logical_switch_port_update_event_empty_fip(self):
        self.switch_port_event = ovn_event.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, 'foo')
        attrs = {'external_ids':
                 {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        expected_call = {
            'info':
                {'action': 'disassociate',
                 'vip_fip': None,
                 'ovn_lb': self.ovn_lb},
            'type': 'handle_vip_fip'}
        self.mock_add_request.assert_called_once_with(expected_call)

    def test_logical_switch_port_update_event_not_vip_port(self):
        self.switch_port_event = ovn_event.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = 'foo'
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids':
                   {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}})
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        self.mock_add_request.assert_not_called()

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_vip_port_update_handler_lb_not_found(self, lb):
        lb.side_effect = [idlutils.RowNotFound for _ in range(5)]
        self.switch_port_event = ovn_event.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, 'foo')
        attrs = {'external_ids':
                 {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        self.mock_add_request.assert_not_called()

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_vip_port_update_handler_multiple_lbs(self, lb):
        lb1 = mock.MagicMock()
        lb2 = mock.MagicMock()
        lb.return_value = [lb1, lb2]
        self.switch_port_event = ovn_event.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, 'foo')
        attrs = {'external_ids':
                 {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)

        def expected_call(lb):
            return {'type': 'handle_vip_fip',
                    'info':
                        {'action': mock.ANY,
                         'vip_fip': None,
                         'ovn_lb': lb}}

        self.mock_add_request.assert_has_calls([
            mock.call(expected_call(lb1)),
            mock.call(expected_call(lb2))])

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_handle_vip_fip_disassociate(self, flb):
        lb = mock.MagicMock()
        fip_info = {
            'action': 'disassociate',
            'vip_fip': None,
            'ovn_lb': lb}
        flb.return_value = lb
        self.helper.handle_vip_fip(fip_info)
        calls = [
            mock.call.db_remove(
                'Load_Balancer', lb.uuid, 'external_ids', 'neutron:vip_fip'),
            mock.call.db_clear('Load_Balancer', lb.uuid, 'vips'),
            mock.call.db_set('Load_Balancer', lb.uuid, ('vips', {}))]
        self.helper.ovn_nbdb_api.assert_has_calls(calls)

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_handle_vip_fip_associate(self, fb):
        lb = mock.MagicMock()
        fip_info = {
            'action': 'associate',
            'vip_fip': '10.0.0.123',
            'ovn_lb': lb}
        members = 'member_%s_%s:%s_%s' % (self.member_id,
                                          self.member_address,
                                          self.member_port,
                                          self.member_subnet_id)
        external_ids = {
            'listener_foo': '80:pool_%s' % self.pool_id,
            'pool_%s' % self.pool_id: members,
            'neutron:vip': '172.26.21.20'}

        lb.external_ids = external_ids
        fb.return_value = lb

        self.helper.handle_vip_fip(fip_info)
        calls = [
            mock.call.db_set(
                'Load_Balancer', lb.uuid,
                ('external_ids', {'neutron:vip_fip': '10.0.0.123'})),
            mock.call.db_clear('Load_Balancer', lb.uuid, 'vips'),
            mock.call.db_set(
                'Load_Balancer', lb.uuid,
                ('vips', {'10.0.0.123:80': '192.168.2.149:1010',
                          '172.26.21.20:80': '192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.assert_has_calls(calls)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_handle_member_dvr_lb_has_no_fip(self, net_cli):
        lb = mock.MagicMock()
        info = {
            'id': self.member_id,
            'pool_id': self.pool_id,
            'action': ovn_const.REQ_INFO_MEMBER_ADDED}
        external_ids = {
            'neutron:vip_fip': ''}
        lb.external_ids = external_ids
        self.mock_find_lb_pool_key.return_value = lb
        self.helper.handle_member_dvr(info)
        net_cli.show_subnet.assert_not_called()
        self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_handle_member_dvr_lb_fip_no_ls_ports(self, net_cli):
        lb = mock.MagicMock()
        info = {
            'id': self.member_id,
            'subnet_id': self.member_subnet_id,
            'pool_id': self.pool_id,
            'action': ovn_const.REQ_INFO_MEMBER_ADDED}
        external_ids = {
            'neutron:vip_fip': '11.11.11.11'}
        lb.external_ids = external_ids
        self.mock_find_lb_pool_key.return_value = lb
        fake_ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {},
                'ports': {}})
        self.helper.ovn_nbdb_api.lookup.return_value = fake_ls
        self.helper.handle_member_dvr(info)
        self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_handle_member_dvr_lb_fip_no_subnet(self, net_cli):
        lb = mock.MagicMock()
        info = {
            'id': self.member_id,
            'subnet_id': self.member_subnet_id,
            'pool_id': self.pool_id,
            'action': ovn_const.REQ_INFO_MEMBER_ADDED}
        external_ids = {
            'neutron:vip_fip': '11.11.11.11'}
        lb.external_ids = external_ids
        self.mock_find_lb_pool_key.return_value = lb
        net_cli.return_value.show_subnet.side_effect = [n_exc.NotFound]
        self.helper.handle_member_dvr(info)
        self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_handle_member_dvr_lb_fip_no_ls(self, net_cli):
        lb = mock.MagicMock()
        info = {
            'id': self.member_id,
            'subnet_id': self.member_subnet_id,
            'pool_id': self.pool_id,
            'action': ovn_const.REQ_INFO_MEMBER_ADDED}
        external_ids = {
            'neutron:vip_fip': '11.11.11.11'}
        lb.external_ids = external_ids
        self.mock_find_lb_pool_key.return_value = lb
        self.helper.ovn_nbdb_api.lookup.side_effect = [idlutils.RowNotFound]
        self.helper.handle_member_dvr(info)
        self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    def _test_handle_member_dvr_lb_fip(
            self, net_cli, action=ovn_const.REQ_INFO_MEMBER_ADDED):
        lb = mock.MagicMock()
        fake_port = fakes.FakePort.create_one_port(
            attrs={'allowed_address_pairs': ''})
        info = {
            'id': self.member_id,
            'address': fake_port['fixed_ips'][0]['ip_address'],
            'pool_id': self.pool_id,
            'subnet_id': fake_port['fixed_ips'][0]['subnet_id'],
            'action': action}
        member_subnet = fakes.FakeSubnet.create_one_subnet()
        member_subnet['id'] = self.member_subnet_id
        member_subnet['network_id'] = 'foo'
        net_cli.return_value.show_subnet.return_value = {
            'subnet': member_subnet}
        fake_lsp = fakes.FakeOVNPort.from_neutron_port(
            fake_port)
        fake_ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {},
                'name': 'foo',
                'ports': [fake_lsp]})
        self.helper.ovn_nbdb_api.lookup.return_value = fake_ls
        fake_nat = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ip': '22.22.22.22',
                'external_ids': {
                    ovn_const.OVN_FIP_EXT_ID_KEY: 'fip_id'}})
        fip_info = {
            'floatingip': {
                'description': 'bar'}}
        net_cli.return_value.show_floatingip.return_value = fip_info
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [fake_nat]
        external_ids = {
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '11.11.11.11'}
        lb.external_ids = external_ids
        self.mock_find_lb_pool_key.return_value = lb
        self.helper.handle_member_dvr(info)

        if action == ovn_const.REQ_INFO_MEMBER_ADDED:
            calls = [
                mock.call.lookup('Logical_Switch', 'neutron-foo'),
                mock.call.db_find_rows('NAT', ('external_ids', '=', {
                    ovn_const.OVN_FIP_PORT_EXT_ID_KEY: fake_lsp.name})),
                mock.ANY,
                mock.call.db_clear('NAT', fake_nat.uuid, 'external_mac'),
                mock.ANY,
                mock.call.db_clear('NAT', fake_nat.uuid, 'logical_port'),
                mock.ANY]
            self.helper.ovn_nbdb_api.assert_has_calls(calls)
        else:
            (net_cli.return_value.show_floatingip.
             assert_called_once_with('fip_id'))
            (net_cli.return_value.update_floatingip.
             assert_called_once_with('fip_id', {
                 'floatingip': {'description': 'bar'}}))
            self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_handle_member_dvr_lb_fip_member_added(self, net_cli):
        self._test_handle_member_dvr_lb_fip(net_cli)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_handle_member_dvr_lb_fip_member_deleted(self, net_cli):
        self._test_handle_member_dvr_lb_fip(
            net_cli, action=ovn_const.REQ_INFO_MEMBER_DELETED)

    def test_ovsdb_connections(self):
        ovn_helper.OvnProviderHelper.ovn_nbdb_api = None
        ovn_helper.OvnProviderHelper.ovn_nbdb_api_for_events = None
        prov_helper1 = ovn_helper.OvnProviderHelper()
        prov_helper2 = ovn_helper.OvnProviderHelper()
        # One connection for API requests
        self.assertIs(prov_helper1.ovn_nbdb_api,
                      prov_helper2.ovn_nbdb_api)
        # One connection to handle events
        self.assertIs(prov_helper1.ovn_nbdb_api_for_events,
                      prov_helper2.ovn_nbdb_api_for_events)
        prov_helper2.shutdown()
        prov_helper1.shutdown()

    def test_create_vip_port_vip_selected(self):
        expected_dict = {
            'port': {'name': '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                                       self.loadbalancer_id),
                     'fixed_ips': [{'subnet_id':
                                    self.vip_dict['vip_subnet_id'],
                                    'ip_address':'10.1.10.1'}],
                     'network_id': self.vip_dict['vip_network_id'],
                     'admin_state_up': True,
                     'project_id': self.project_id}}
        with mock.patch.object(clients, 'get_neutron_client') as net_cli:
            self.vip_dict['vip_address'] = '10.1.10.1'
            self.helper.create_vip_port(self.project_id,
                                        self.loadbalancer_id,
                                        self.vip_dict)
            expected_call = [
                mock.call().create_port(expected_dict)]
            net_cli.assert_has_calls(expected_call)

    def test_create_vip_port_vip_not_selected(self):
        expected_dict = {
            'port': {'name': '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                                       self.loadbalancer_id),
                     'fixed_ips': [{'subnet_id':
                                    self.vip_dict['vip_subnet_id']}],
                     'network_id': self.vip_dict['vip_network_id'],
                     'admin_state_up': True,
                     'project_id': self.project_id}}
        with mock.patch.object(clients, 'get_neutron_client') as net_cli:
            self.helper.create_vip_port(self.project_id,
                                        self.loadbalancer_id,
                                        self.vip_dict)
            expected_call = [
                mock.call().create_port(expected_dict)]
            net_cli.assert_has_calls(expected_call)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_create_vip_port_vip_selected_already_exist(self, net_cli):
        net_cli.return_value.create_port.side_effect = [
            n_exc.IpAddressAlreadyAllocatedClient]
        net_cli.return_value.list_ports.return_value = {
            'ports': [
                {'name': 'ovn-lb-vip-' + self.loadbalancer_id,
                 'id': self.loadbalancer_id}]}
        self.vip_dict['vip_address'] = '10.1.10.1'
        ret = self.helper.create_vip_port(
            self.project_id,
            self.loadbalancer_id,
            self.vip_dict)
        expected = {
            'port': {
                'name': '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                                  self.loadbalancer_id),
                'id': self.loadbalancer_id}}
        self.assertDictEqual(expected, ret)
        expected_call = [
            mock.call().list_ports(
                network_id='%s' % self.vip_dict['vip_network_id'],
                name='%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                               self.loadbalancer_id))]
        net_cli.assert_has_calls(expected_call)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_create_vip_port_vip_selected_other_allocation_exist(
            self, net_cli):
        net_cli.return_value.create_port.side_effect = [
            n_exc.IpAddressAlreadyAllocatedClient]
        net_cli.return_value.list_ports.return_value = {
            'ports': []}
        self.vip_dict['vip_address'] = '10.1.10.1'
        self.assertRaises(
            n_exc.IpAddressAlreadyAllocatedClient,
            self.helper.create_vip_port,
            self.project_id,
            self.loadbalancer_id,
            self.vip_dict)
        expected_call = [
            mock.call().list_ports(
                network_id='%s' % self.vip_dict['vip_network_id'],
                name='%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                               self.loadbalancer_id))]
        net_cli.assert_has_calls(expected_call)
        self.helper._update_status_to_octavia.assert_not_called()

    def test_get_pool_member_id(self):
        ret = self.helper.get_pool_member_id(
            self.pool_id, mem_addr_port='192.168.2.149:1010')
        self.assertEqual(self.member_id, ret)

    def test__get_existing_pool_members(self):
        ret = self.helper._get_existing_pool_members(self.pool_id)
        self.assertEqual(ret, self.member_line)

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lb_by_pool_id')
    def test__get_existing_pool_members_exception(self, folbpi):
        folbpi.return_value = (None, None)
        self.assertRaises(exceptions.DriverError,
                          self.helper._get_existing_pool_members,
                          self.pool_id)

    def test__frame_lb_vips(self):
        ret = self.helper._frame_vip_ips(self.ovn_lb.external_ids)
        expected = {'10.22.33.4:80': '192.168.2.149:1010',
                    '123.123.123.123:80': '192.168.2.149:1010'}
        self.assertEqual(expected, ret)

    def test__frame_lb_vips_disabled(self):
        self.ovn_lb.external_ids['enabled'] = 'False'
        ret = self.helper._frame_vip_ips(self.ovn_lb.external_ids)
        self.assertEqual({}, ret)

    def test__frame_lb_vips_ipv6(self):
        self.member_address = '2001:db8::1'
        self.member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: 'fc00::',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '2002::',
            'pool_%s' % self.pool_id: self.member_line,
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        ret = self.helper._frame_vip_ips(self.ovn_lb.external_ids)
        expected = {'[2002::]:80': '[2001:db8::1]:1010',
                    '[fc00::]:80': '[2001:db8::1]:1010'}
        self.assertEqual(expected, ret)

    def test_check_lb_protocol(self):
        self.ovn_lb.protocol = ['tcp']
        ret = self.helper.check_lb_protocol(self.listener_id, 'udp')
        self.assertFalse(ret)
        ret = self.helper.check_lb_protocol(self.listener_id, 'UDP')
        self.assertFalse(ret)

        ret = self.helper.check_lb_protocol(self.listener_id, 'sctp')
        self.assertFalse(ret)
        ret = self.helper.check_lb_protocol(self.listener_id, 'SCTP')
        self.assertFalse(ret)

        ret = self.helper.check_lb_protocol(self.listener_id, 'tcp')
        self.assertTrue(ret)
        ret = self.helper.check_lb_protocol(self.listener_id, 'TCP')
        self.assertTrue(ret)

    def test_check_lb_protocol_no_listener(self):
        self.ovn_lb.external_ids = []
        ret = self.helper.check_lb_protocol(self.listener_id, 'TCP')
        self.assertTrue(ret)

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_check_lb_protocol_no_lb(self, fol):
        fol.return_value = None
        ret = self.helper.check_lb_protocol(self.listener_id, 'TCP')
        self.assertFalse(ret)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_update_hm_members')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def _test_hm_create(self, protocol, members, folbpi, uhm, net_cli):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.protocol = [protocol]
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        uhm.return_value = True
        net_cli.return_value.show_subnet.return_value = {'subnet': fake_subnet}
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        if members:
            self.assertEqual(status['members'][0]['provisioning_status'],
                             constants.ACTIVE)
            self.assertEqual(status['members'][0]['operating_status'],
                             constants.ONLINE)
        vip = (self.ovn_hm_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_KEY] +
               ':' + str(self.listener['protocol_port']))
        options = {'interval': '6',
                   'timeout': '7',
                   'failure_count': '5',
                   'success_count': '3'}
        external_ids = {ovn_const.LB_EXT_IDS_HM_KEY: self.healthmonitor_id}
        kwargs = {'vip': vip,
                  'options': options,
                  'external_ids': external_ids}
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer_Health_Check', **kwargs)
        self.helper.ovn_nbdb_api.db_add.assert_called_once_with(
            'Load_Balancer', self.ovn_hm_lb.uuid, 'health_check', mock.ANY)

    def test_hm_create_tcp(self):
        self._test_hm_create('tcp', False)

    def test_hm_create_udp(self):
        self._test_hm_create('udp', False)

    def test_hm_create_tcp_pool_members(self):
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids[pool_key] = self.member_line
        self._test_hm_create('tcp', True)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_no_vip_port(self, folbpi):
        pool_key = 'pool_%s' % self.pool_id
        listener_key = 'listener_%s' % self.listener_id
        self.ovn_hm_lb.external_ids.pop(listener_key)
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ONLINE)
        vip = []
        options = {'interval': '6',
                   'timeout': '7',
                   'failure_count': '5',
                   'success_count': '3'}
        self.ovn_hm.external_ids.pop(ovn_const.LB_EXT_IDS_HM_KEY)
        external_ids = {ovn_const.LB_EXT_IDS_HM_KEY: self.healthmonitor_id}
        kwargs = {'vip': vip,
                  'options': options,
                  'external_ids': external_ids}
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer_Health_Check', **kwargs)
        self.helper.ovn_nbdb_api.db_add.assert_called_once_with(
            'Load_Balancer', self.ovn_hm_lb.uuid, 'health_check', mock.ANY)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_offline(self, folbpi):
        pool_key = 'pool_%s' % self.pool_id
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        self.health_monitor['admin_state_up'] = False
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.OFFLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_lb_not_found(self, folbpi):
        folbpi.return_value = (None, None)
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.NO_MONITOR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_pool_not_found(self, folbpi):
        folbpi.return_value = ('pool_closed', self.ovn_hm_lb)
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.NO_MONITOR)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_vip_not_found(self, folbpi):
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids.pop(ovn_const.LB_EXT_IDS_VIP_KEY)
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_lsp_not_found(self, folbpi, net_cli):
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids[pool_key] = self.member_line
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        net_cli.return_value.show_subnet.side_effect = [n_exc.NotFound]
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_hm_port_not_found(self, folbpi, net_cli):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        fake_port = fakes.FakePort.create_one_port(
            attrs={'allowed_address_pairs': ''})
        member = {'id': uuidutils.generate_uuid(),
                  'address': fake_port['fixed_ips'][0]['ip_address'],
                  'protocol_port': '9999',
                  'subnet_id': fake_subnet['id'],
                  'pool_id': self.pool_id,
                  'admin_state_up': True,
                  'old_admin_state_up': True}
        member_line = (
            'member_%s_%s:%s_%s' %
            (member['id'], member['address'],
             member['protocol_port'], member['subnet_id']))
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids[pool_key] = member_line
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        net_cli.return_value.show_subnet.return_value = {'subnet': fake_subnet}
        net_cli.return_value.list_ports.return_value = {'ports': []}
        fake_lsp = fakes.FakeOVNPort.from_neutron_port(fake_port)
        fake_ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {},
                'ports': [fake_lsp]})
        self.helper.ovn_nbdb_api.lookup.return_value = fake_ls
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_hm_source_ip_not_found(self, folbpi, net_cli):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        fake_port = fakes.FakePort.create_one_port(
            attrs={'allowed_address_pairs': ''})
        member = {'id': uuidutils.generate_uuid(),
                  'address': fake_port['fixed_ips'][0]['ip_address'],
                  'protocol_port': '9999',
                  'subnet_id': fake_subnet['id'],
                  'pool_id': self.pool_id,
                  'admin_state_up': True,
                  'old_admin_state_up': True}
        member_line = (
            'member_%s_%s:%s_%s' %
            (member['id'], member['address'],
             member['protocol_port'], member['subnet_id']))
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids[pool_key] = member_line
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        net_cli.return_value.show_subnet.return_value = {'subnet': fake_subnet}
        fake_lsp = fakes.FakeOVNPort.from_neutron_port(fake_port)
        fake_ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {},
                'ports': [fake_lsp]})
        self.helper.ovn_nbdb_api.lookup.return_value = fake_ls
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_db_exception(self, folbpi):
        pool_key = 'pool_%s' % self.pool_id
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        self.helper.ovn_nbdb_api.db_create.side_effect = [RuntimeError]
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_lookup_hm_by_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_get_or_create_ovn_lb')
    def test_hm_create_then_listener_create(self, get_ovn_lb, lookup_hm):
        get_ovn_lb.return_value = self.ovn_hm_lb
        lookup_hm.return_value = self.ovn_hm
        self.ovn_hm_lb.health_check = self.ovn_hm
        self.listener['admin_state_up'] = True
        status = self.helper.listener_create(self.listener)
        vip = (self.ovn_hm_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_KEY] +
               ':' + str(self.listener['protocol_port']))
        self.helper.ovn_nbdb_api.db_set.assert_called_with(
            'Load_Balancer_Health_Check', self.ovn_hm.uuid, ('vip', vip))
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_lookup_hm_by_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_get_or_create_ovn_lb')
    def test_hm_create_then_listener_create_no_hm(self, get_ovn_lb, lookup_hm):
        get_ovn_lb.return_value = self.ovn_hm_lb
        lookup_hm.return_value = None
        self.ovn_hm_lb.health_check = self.ovn_hm
        self.listener['admin_state_up'] = True
        status = self.helper.listener_create(self.listener)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_lookup_hm_by_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_get_or_create_ovn_lb')
    def test_hm_create_then_listener_create_no_vip(self, get_ovn_lb,
                                                   lookup_hm, refresh_vips):
        get_ovn_lb.return_value = self.ovn_hm_lb
        lookup_hm.return_value = self.ovn_hm
        self.ovn_hm_lb.health_check = self.ovn_hm
        self.ovn_hm_lb.external_ids.pop(ovn_const.LB_EXT_IDS_VIP_KEY)
        self.listener['admin_state_up'] = True
        status = self.helper.listener_create(self.listener)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update(self, folbfhi):
        folbfhi.return_value = (self.ovn_hm, self.ovn_hm_lb)
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update_no_admin_state_up(self, folbfhi):
        folbfhi.return_value = (self.ovn_hm, self.ovn_hm_lb)
        self.ovn_hm_lb.pop('admin_state_up')
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update_offline(self, folbfhi):
        folbfhi.return_value = (self.ovn_hm, self.ovn_hm_lb)
        self.health_monitor['admin_state_up'] = False
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.OFFLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update_hm_not_found(self, folbfhi):
        folbfhi.return_value = (None, None)
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_update_lb_not_found(self, folbpi, folbfhi):
        folbfhi.return_value = (self.ovn_hm, None)
        folbpi.return_value = (None, None)
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    def test_hm_delete(self):
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.return_value = [self.ovn_hm]
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_hm_lb]
        status = self.helper.hm_delete(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.NO_MONITOR)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        expected_clear_calls = [
            mock.call('Load_Balancer', self.ovn_hm_lb.uuid,
                      'ip_port_mappings')]
        expected_remove_calls = [
            mock.call('Load_Balancer', self.ovn_hm_lb.uuid, 'health_check',
                      self.ovn_hm.uuid)]
        expected_destroy_calls = [
            mock.call('Load_Balancer_Health_Check', self.ovn_hm.uuid)]
        self.helper.ovn_nbdb_api.db_clear.assert_has_calls(
            expected_clear_calls)
        self.helper.ovn_nbdb_api.db_remove.assert_has_calls(
            expected_remove_calls)
        self.helper.ovn_nbdb_api.db_destroy.assert_has_calls(
            expected_destroy_calls)

    def test_hm_delete_row_not_found(self):
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.return_value = [self.ovn_hm]
        self.helper.ovn_nbdb_api.db_find_rows.side_effect = (
            [idlutils.RowNotFound])
        status = self.helper.hm_delete(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.NO_MONITOR)
        self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    def test_hm_delete_hm_not_found(self):
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.return_value = [self.ovn_hm]
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_hm_lb]
        self.health_monitor['id'] = 'id_not_found'
        status = self.helper.hm_delete(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.NO_MONITOR)
        self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    def test_hm_update_event_offline(self):
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_hm_lb]
        self.hm_update_event = ovn_event.ServiceMonitorUpdateEvent(
            self.helper)
        src_ip = '10.22.33.4'
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip': self.member_address,
                   'logical_port': 'a-logical-port',
                   'src_ip': src_ip,
                   'port': self.member_port,
                   'protocol': self.ovn_hm_lb.protocol,
                   'status': ['offline']})
        self.hm_update_event.run('update', row, mock.ANY)
        expected = {
            'info':
                {'ovn_lb': self.ovn_hm_lb,
                 'ip': self.member_address,
                 'port': self.member_port,
                 'status': ['offline']},
            'type': 'hm_update_event'}
        self.mock_add_request.assert_called_once_with(expected)
        self.helper.ovn_nbdb_api.db_find_rows.assert_called_once_with(
            'Load_Balancer',
            (('ip_port_mappings', '=',
              {self.member_address: 'a-logical-port:' + src_ip}),
             ('protocol', '=', self.ovn_hm_lb.protocol)))

    def test_hm_update_event_lb_not_found(self):
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = []
        self.hm_update_event = ovn_event.ServiceMonitorUpdateEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip': self.member_address,
                   'logical_port': 'a-logical-port',
                   'src_ip': '10.22.33.4',
                   'port': self.member_port,
                   'protocol': self.ovn_hm_lb.protocol,
                   'status': ['offline']})
        self.hm_update_event.run('update', row, mock.ANY)
        self.mock_add_request.assert_not_called()

    def test_hm_update_event_lb_row_not_found(self):
        self.helper.ovn_nbdb_api.db_find_rows.\
            side_effect = [idlutils.RowNotFound]
        self.hm_update_event = ovn_event.ServiceMonitorUpdateEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip': self.member_address,
                   'logical_port': 'a-logical-port',
                   'src_ip': '10.22.33.4',
                   'port': self.member_port,
                   'protocol': self.ovn_hm_lb.protocol,
                   'status': ['offline']})
        self.hm_update_event.run('update', row, mock.ANY)
        self.mock_add_request.assert_not_called()

    def test_hm_update_event_lb_protocol_not_found(self):
        self.helper.ovn_nbdb_api.db_find_rows.\
            side_effect = [self.ovn_hm_lb, idlutils.RowNotFound]
        self.hm_update_event = ovn_event.ServiceMonitorUpdateEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip': self.member_address,
                   'logical_port': 'a-logical-port',
                   'src_ip': '10.22.33.4',
                   'port': self.member_port,
                   'protocol': 'unknown',
                   'status': ['offline']})
        self.hm_update_event.run('update', row, mock.ANY)
        self.mock_add_request.assert_not_called()

    def _test_hm_update_no_member(self, bad_ip, bad_port):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        fake_port = fakes.FakePort.create_one_port(
            attrs={'allowed_address_pairs': ''})
        ip = fake_port['fixed_ips'][0]['ip_address']
        member = {'id': uuidutils.generate_uuid(),
                  'address': ip,
                  'protocol_port': self.member_port,
                  'subnet_id': fake_subnet['id'],
                  'pool_id': self.pool_id,
                  'admin_state_up': True,
                  'old_admin_state_up': True}
        member_line = (
            'member_%s_%s:%s_%s' %
            (member['id'], member['address'],
             member['protocol_port'], member['subnet_id']))
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids[pool_key] = member_line

        if bad_ip:
            ip = 'bad-ip'
        port = self.member_port
        if bad_port:
            port = 'bad-port'
        info = {
            'ovn_lb': self.ovn_hm_lb,
            'ip': ip,
            'logical_port': 'a-logical-port',
            'src_ip': '10.22.33.4',
            'port': port,
            'protocol': self.ovn_hm_lb.protocol,
            'status': ['offline']}

        status = self.helper.hm_update_event(info)
        self.assertIsNone(status)

    def test_hm_update_event_member_ip_not_found(self):
        self._test_hm_update_no_member(True, False)

    def test_hm_update_event_member_port_not_found(self):
        self._test_hm_update_no_member(False, True)

    def _test_hm_update_status(self, ip, port, member_status,
                               lb_status=constants.ONLINE,
                               pool_status=constants.ONLINE):
        fake_lb = fakes.FakeLB(
            uuid=uuidutils.generate_uuid(),
            admin_state_up=True,
            name='fake_lb',
            ext_ids={})
        fake_pool = fakes.FakePool(
            uuid=uuidutils.generate_uuid(),
            admin_state_up=True,
            name='fake_pool')
        info = {
            'ovn_lb': self.ovn_hm_lb,
            'ip': ip,
            'logical_port': 'a-logical-port',
            'src_ip': '10.22.33.4',
            'port': port,
            'protocol': self.ovn_hm_lb.protocol,
            'status': [member_status]}

        fake_lb.operating_status = lb_status
        fake_pool.operating_status = pool_status
        self.octavia_driver_lib.get_pool.return_value = fake_pool
        self.octavia_driver_lib.get_loadbalancer.return_value = fake_lb
        status = self.helper.hm_update_event(info)
        return status

    def _add_member(self, subnet, port):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'allowed_address_pairs': ''})
        ip = fake_port['fixed_ips'][0]['ip_address']
        member = {'id': uuidutils.generate_uuid(),
                  'address': ip,
                  'protocol_port': port,
                  'subnet_id': subnet['id'],
                  'pool_id': self.pool_id,
                  'admin_state_up': True,
                  'old_admin_state_up': True}
        member_line = (
            'member_%s_%s:%s_%s' %
            (member['id'], member['address'],
             member['protocol_port'], member['subnet_id']))
        pool_key = 'pool_%s' % self.pool_id

        existing_members = self.ovn_hm_lb.external_ids[pool_key]
        if existing_members:
            existing_members = ','.join([existing_members, member_line])
            self.ovn_hm_lb.external_ids[pool_key] = existing_members
        else:
            self.ovn_hm_lb.external_ids[pool_key] = member_line
        return member

    def test_hm_update_status_offline(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member = self._add_member(fake_subnet, 8080)
        status = self._test_hm_update_status(member['address'], '8080',
                                             'offline')

        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)

    def test_hm_update_status_offline_lb_pool_offline(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member = self._add_member(fake_subnet, 8080)
        status = self._test_hm_update_status(member['address'], '8080',
                                             'offline',
                                             lb_status=constants.OFFLINE,
                                             pool_status=constants.OFFLINE)

        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)

    def test_hm_update_status_online(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member = self._add_member(fake_subnet, 8080)
        status = self._test_hm_update_status(member['address'], '8080',
                                             'online')

        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)

    def test_hm_update_status_online_lb_pool_offline(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member = self._add_member(fake_subnet, 8080)
        status = self._test_hm_update_status(member['address'], '8080',
                                             'online',
                                             lb_status=constants.OFFLINE,
                                             pool_status=constants.OFFLINE)

        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)

    def test_hm_update_status_offline_two_members(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member_1 = self._add_member(fake_subnet, 8080)
        ip_1 = member_1['address']
        member_2 = self._add_member(fake_subnet, 8081)
        ip_2 = member_2['address']
        # This is the Octavia API version
        fake_member = fakes.FakeMember(
            uuid=member_2['id'],
            admin_state_up=True,
            name='member_2',
            project_id=self.project_id,
            address=ip_2,
            protocol_port=8081)

        # Second member ONLINE, operating_status should be DEGRADED
        # for Pool and Loadbalancer
        fake_member.operating_status = constants.ONLINE
        self.octavia_driver_lib.get_member.return_value = fake_member

        status = self._test_hm_update_status(ip_1, '8081', 'offline')
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.DEGRADED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.DEGRADED)

        # Second member ERROR, operating_status should be ERROR
        # for Pool and Loadbalancer
        fake_member.operating_status = constants.ERROR
        self.octavia_driver_lib.get_member.return_value = fake_member
        status = self._test_hm_update_status(ip_1, '8081', 'offline')
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)

    def test_hm_update_status_online_two_members(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member_1 = self._add_member(fake_subnet, 8080)
        ip_1 = member_1['address']
        member_2 = self._add_member(fake_subnet, 8081)
        ip_2 = member_2['address']
        # This is the Octavia API version
        fake_member = fakes.FakeMember(
            uuid=member_2['id'],
            admin_state_up=True,
            name='member_2',
            project_id=self.project_id,
            address=ip_2,
            protocol_port=8081)

        # Second member ERROR, operating_status should be DEGRADED
        # for Pool and Loadbalancer
        fake_member.operating_status = constants.ERROR
        self.octavia_driver_lib.get_member.return_value = fake_member

        status = self._test_hm_update_status(ip_1, '8081', 'online')
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.DEGRADED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.DEGRADED)

        # Second member ONLINE, operating_status should be ONLINE
        # for Pool and Loadbalancer
        fake_member.operating_status = constants.ONLINE
        self.octavia_driver_lib.get_member.return_value = fake_member
        status = self._test_hm_update_status(ip_1, '8081', 'online')
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
