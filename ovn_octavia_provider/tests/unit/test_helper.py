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

from neutron_lib.api.definitions import provider_net
from neutron_lib import constants as n_const
from neutronclient.common import exceptions as n_exc
from octavia_lib.api.drivers import data_models
from octavia_lib.api.drivers import exceptions
from octavia_lib.common import constants
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

from ovn_octavia_provider.common import clients
from ovn_octavia_provider.common import config as ovn_conf
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider import event as ovn_event
from ovn_octavia_provider import helper as ovn_helper
from ovn_octavia_provider.tests.unit import base as ovn_base
from ovn_octavia_provider.tests.unit import fakes


class TestOvnProviderHelper(ovn_base.TestOvnOctaviaBase):

    def setUp(self):
        super().setUp()
        ovn_conf.register_opts()
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
        self.ovn_hm = mock.MagicMock()
        self.ovn_hm.uuid = self.healthmonitor_id
        self.ovn_hm.external_ids = {
            ovn_const.LB_EXT_IDS_HM_KEY: self.ovn_hm.uuid}
        self.ovn_hm_lb.health_check = [self.ovn_hm.uuid]
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
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id,
            ovn_const.OVN_MEMBER_STATUS_KEY: '{"%s": "%s"}'
            % (self.member_id, constants.NO_MONITOR)}
        self.ovn_hm_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.99',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.99',
            ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_hm_port',
            ovn_const.LB_EXT_IDS_HMS_KEY: '["%s"]' % (self.ovn_hm.uuid),
            'enabled': True,
            'pool_%s' % self.pool_id: [],
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id,
            ovn_const.OVN_MEMBER_STATUS_KEY: '{}'}
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

        self._get_pool_listeners = mock.patch.object(
            self.helper,
            '_get_pool_listeners',
            return_value=[])
        self._get_pool_listeners.start()
        self._update_lb_to_ls_association = mock.patch.object(
            self.helper,
            '_update_lb_to_ls_association',
            return_value=[])
        self._update_lb_to_ls_association.start()
        self._get_lb_to_ls_association_commands = mock.patch.object(
            self.helper,
            '_get_lb_to_ls_association_commands',
            return_value=[])
        self._get_lb_to_ls_association_commands.start()
        self._update_lb_to_lr_association = mock.patch.object(
            self.helper,
            '_update_lb_to_lr_association',
            return_value=[])
        self._update_lb_to_lr_association.start()
        self._get_lb_to_lr_association_commands = mock.patch.object(
            self.helper,
            '_get_lb_to_lr_association_commands',
            return_value=[])
        self._get_lb_to_lr_association_commands.start()
        self._update_lb_to_lr_association_by_step = \
            mock.patch.object(
                self.helper,
                '_update_lb_to_lr_association_by_step',
                return_value=[])
        self._update_lb_to_lr_association_by_step.start()

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
                    '{\"neutron-%s\": 1}' % net_id,
                ovn_const.LB_EXT_IDS_VIP_KEY: self.vip_address})
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
                    '{\"neutron-%s\": 1}' % net_id,
                ovn_const.LB_EXT_IDS_VIP_KEY: self.vip_address})
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

    def test__update_external_ids_member_status(self):
        self.helper._update_external_ids_member_status(
            self.ovn_lb, self.member_id, constants.NO_MONITOR)
        member_status = {
            ovn_const.OVN_MEMBER_STATUS_KEY: '{"%s": "%s"}'
            % (self.member_id, constants.NO_MONITOR)}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, ('external_ids', member_status))

    def test__update_external_ids_member_status_delete(self):
        self.helper._update_external_ids_member_status(
            self.ovn_lb, self.member_id, None, True)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, 'external_ids',
            ovn_const.OVN_MEMBER_STATUS_KEY)

    def test__update_external_ids_member_status_delete_not_found(self):
        self.helper._update_external_ids_member_status(
            self.ovn_lb, 'fool', None, True)
        member_status = {
            ovn_const.OVN_MEMBER_STATUS_KEY: '{"%s": "%s"}'
            % (self.member_id, constants.NO_MONITOR)}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, ('external_ids', member_status))

    def test__find_member_status(self):
        status = self.helper._find_member_status(self.ovn_lb, self.member_id)
        self.assertEqual(status, constants.NO_MONITOR)
        status = self.helper._find_member_status(
            self.ovn_hm_lb, self.member_id)
        self.assertEqual(status, constants.NO_MONITOR)

    def test__find_member_status_exception(self):
        status = self.helper._find_member_status(self.ovn_hm_lb, 'foo')
        self.assertEqual(status, constants.NO_MONITOR)

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test__clean_lb_if_empty(self, lb):
        lb.side_effect = [idlutils.RowNotFound]
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        self.ovn_lb.external_ids.pop('pool_%s' % self.pool_id)
        commands, lb_to_delete = self.helper._clean_lb_if_empty(
            self.ovn_lb, self.ovn_lb.uuid, self.ovn_lb.external_ids)
        self.assertEqual([], commands)
        self.assertFalse(lb_to_delete)

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

        # Ensure lb is not found, due to its pool_key not found
        found = f(self.helper._get_pool_key(uuidutils.generate_uuid()))
        self.assertIsNone(found)

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

        # Multiple protocols, just one with correct protocol
        udp_lb = copy.copy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [udp_lb, self.ovn_lb]
        found = f(self.ovn_lb.id, protocol='tcp')
        self.assertEqual(found, self.ovn_lb)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__get_subnet_from_pool(self, net_cli):
        net_cli.return_value.show_subnet.return_value = {
            'subnet': {'cidr': '10.22.33.0/24'}}

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
            self.assertEqual((None, None), found)

            dlib.get_pool.return_value = lb_pool
            dlib.get_loadbalancer.return_value = lb
            found = f(self.pool_id)
            self.assertEqual(found, (lb.vip_subnet_id, '10.22.33.0/24'))

    def test__get_subnet_from_pool_lb_no_vip_subnet_id(self):
        f = self.helper._get_subnet_from_pool

        lb = data_models.LoadBalancer(
            loadbalancer_id=self.loadbalancer_id,
            name='The LB',
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id)

        lb_pool = data_models.Pool(
            loadbalancer_id=self.loadbalancer_id,
            name='The pool',
            pool_id=self.pool_id,
            protocol='TCP')

        with mock.patch.object(self.helper, '_octavia_driver_lib') as dlib:
            dlib.get_pool.return_value = None
            found = f('not_found')
            self.assertEqual((None, None), found)

            dlib.get_pool.return_value = lb_pool
            dlib.get_loadbalancer.return_value = lb
            found = f(self.pool_id)
            self.assertEqual((None, None), found)

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

    @mock.patch.object(ovn_helper.OvnProviderHelper, 'lb_create')
    def test__get_or_create_ovn_lb_no_vip_fip(self, lbc):
        self.mock_find_ovn_lbs.stop()
        udp_lb = copy.copy(self.ovn_lb)
        udp_lb.external_ids.pop(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
        udp_lb.protocol = ['udp']
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
            'admin_state_up': 'True'}
        lbc.assert_called_once_with(expected_lb_info, protocol='tcp')

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

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_lr_of_ls')
    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_create_assoc_lb_to_lr_by_step(self, net_cli, f_lr):
        self.mock_find_ovn_lbs.stop()
        self.helper._find_ovn_lbs
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb]
        self._update_lb_to_ls_association.stop()
        self.lb['admin_state_up'] = True
        f_lr.return_value = self.router
        net_cli.return_value.list_ports.return_value = self.ports
        self.helper._update_lb_to_lr_association.side_effect = [
            idlutils.RowNotFound]
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
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.ovn_lb, self.router
        )
        self.helper._update_lb_to_lr_association_by_step \
            .assert_called_once_with(
                self.ovn_lb,
                self.router)

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
    def _test_lb_create_on_multi_protocol(self, protocol, provider, net_cli):
        """This test situation when new protocol is added

           to the same loadbalancer and we need to add
           additional OVN lb with the same name.
        """
        self.lb['admin_state_up'] = True
        self.lb['protocol'] = protocol
        self.lb[ovn_const.LB_EXT_IDS_LR_REF_KEY] = 'foo'
        self.lb[ovn_const.LB_EXT_IDS_LS_REFS_KEY] = '{\"neutron-foo\": 1}'
        net_cli.return_value.list_ports.return_value = self.ports
        fake_network = {'id': self.lb['vip_network_id'],
                        provider_net.PHYSICAL_NETWORK: provider}
        net_cli.return_value.show_network.return_value = {
            'network': fake_network}

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
        if provider:
            self.helper._update_lb_to_ls_association.assert_not_called()
        else:
            self.helper._update_lb_to_ls_association.assert_has_calls([
                mock.call(self.ovn_lb, associate=True,
                          network_id=self.lb['vip_network_id'],
                          update_ls_ref=True),
                mock.call(self.ovn_lb, associate=True, network_id='foo',
                          update_ls_ref=True)])

    def test_lb_create_on_multi_protocol_UDP(self):
        self._test_lb_create_on_multi_protocol('UDP', None)

    def test_lb_create_on_multi_protocol_SCTP(self):
        self._test_lb_create_on_multi_protocol('SCTP', None)

    def _test_lb_create_on_provider_network(self):
        # Test case for LB created on provider network.
        # Ensure LB is not associated to the LS in that case
        self._test_lb_create_on_multi_protocol('TCP', "provider")

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_lb_create_neutron_client_exception(self, net_cli):
        net_cli.return_value.list_ports.return_value = self.ports
        net_cli.return_value.show_subnet.side_effect = [n_exc.NotFound]
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_lb_create_exception(self, del_port, net_cli):
        self.helper._find_ovn_lbs.side_effect = [RuntimeError]
        net_cli.return_value.list_ports.return_value = self.ports
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        del_port.assert_called_once_with(self.ports.get('ports')[0]['id'])
        del_port.side_effect = [Exception]
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
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

    @mock.patch.object(ovn_helper.OvnProviderHelper,
                       '_get_vip_port_from_loadbalancer_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_lb_delete_row_not_found(self, del_port, get_vip_port):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        get_vip_port.return_value = None
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        del_port.assert_not_called()
        get_vip_port.assert_called_once_with(self.lb['id'])

    @mock.patch.object(ovn_helper.OvnProviderHelper,
                       '_get_vip_port_from_loadbalancer_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_lb_delete_row_not_found_port_leftover(
            self, del_port, get_vip_port):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        get_vip_port.return_value = 'foo'
        del_port.side_effect = [Exception]
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        del_port.assert_called_once_with('foo')
        get_vip_port.assert_called_once_with(self.lb['id'])

    @mock.patch.object(ovn_helper.OvnProviderHelper,
                       '_get_vip_port_from_loadbalancer_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_lb_delete_row_not_found_vip_leak(self, del_port, get_vip_port):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        get_vip_port.return_value = 'foo_port'
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        del_port.assert_called_once_with('foo_port')
        get_vip_port.assert_called_once_with(self.lb['id'])

    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_lb_delete_exception(self, del_port):
        self.helper.ovn_nbdb_api.lb_del.side_effect = [RuntimeError]
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_lb_delete_step_by_step(self, del_port):
        self.helper.ovn_nbdb_api.lr_lb_del.side_effect = [idlutils.RowNotFound]
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_called_once_with('foo_port')

    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_lb_delete_step_by_step_exception(self, del_port):
        self.helper.ovn_nbdb_api.lb_del.side_effect = [idlutils.RowNotFound]
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
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

    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_lb_delete_port_exception(self, del_port):
        del_port.side_effect = [Exception]
        status = self.helper.lb_delete(self.ovn_lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
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
        # update to re-enable
        self.ovn_lb.external_ids.update({'enabled': True})
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
        # As it is marked disabled, a second call should not try and remove it
        self.helper.ovn_nbdb_api.db_remove.reset_mock()
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()

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

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_is_lb_empty')
    def test_listener_delete_ovn_lb_empty_ovn_lb_not_found(self, lb_empty):
        """That test situation when the OVN and Octavia LBs are empty.

           That test situation when both OVN and Octavia LBs are empty,
           but we cannot find the OVN LB row when cleaning.
        """
        self.helper._find_ovn_lbs.side_effect = [
            self.ovn_lb, idlutils.RowNotFound]
        lb_empty.return_value = True
        self.helper.listener_delete(self.listener)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        # vip refresh will have been called
        self.helper.ovn_nbdb_api.db_clear.assert_has_calls([
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips'))])
        self.helper.ovn_nbdb_api.db_set.assert_has_calls([
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips', {}))])

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
        self.helper.ovn_nbdb_api.db_set.side_effect = [
            RuntimeError, RuntimeError]
        status = self.helper.pool_create(self.pool)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.pool['listener_id'] = None
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

    def test_pool_update_pool_disabled_change_to_down(self):
        self.pool.update({'admin_state_up': False})
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
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

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

    def test_pool_update_listeners_none(self):
        status = self.helper.pool_update(self.pool)
        self.assertFalse(status['listeners'])

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
                    'listener_%s' % self.listener_id: '80:',
                    ovn_const.OVN_MEMBER_STATUS_KEY: '{"%s": "%s"}'
                    % (self.member_id, constants.NO_MONITOR)}))]
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
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_port',
                ovn_const.OVN_MEMBER_STATUS_KEY: '{"%s": "%s"}'
                % (self.member_id, constants.NO_MONITOR)}))

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

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_lr_of_ls')
    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_member_create_lb_add_from_lr_retry(self, net_cli, f_lr, folbpi):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        net_cli.return_value.show_subnet.return_value = {'subnet': fake_subnet}
        f_lr.return_value = self.router
        pool_key = 'pool_%s' % self.pool_id
        folbpi.return_value = (pool_key, self.ovn_lb)
        self.helper._update_lb_to_lr_association.side_effect = [
            idlutils.RowNotFound]
        self.ovn_lb.external_ids = mock.MagicMock()
        status = self.helper.member_create(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        f_lr.assert_called_once_with(self.network, fake_subnet['gateway_ip'])
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.ovn_lb, self.router)
        self.helper._update_lb_to_lr_association_by_step \
            .assert_called_once_with(
                self.ovn_lb,
                self.router)

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
        member_status = {
            ovn_const.OVN_MEMBER_STATUS_KEY: '{"%s": "%s"}'
            % (self.member_id, constants.NO_MONITOR)}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer',
            self.ovn_lb.uuid,
            ('external_ids', member_status))

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
                         constants.NO_MONITOR)
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
        self.member.pop('admin_state_up')
        status = self.helper.member_update(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
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
        fake_member = fakes.FakeMember(
            uuid=self.member_id,
            admin_state_up=True,
            address=self.member_address,
            protocol_port=self.member_port)
        self.octavia_driver_lib.get_member.return_value = fake_member
        self.member['old_admin_state_up'] = None
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

    def test_member_delete_none(self):
        self.ovn_lb.external_ids.update({'pool_' + self.pool_id: ''})
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ERROR)
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
                 'network': self.network,
                 'gateway_chassis': []},
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
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network,
                 'gateway_chassis': ['temp-gateway-chassis']},
            'type': 'lb_create_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    def test__get_pool_listeners(self):
        self._get_pool_listeners.stop()
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: 'fc00::',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '2002::',
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        ret = self.helper._get_pool_listeners(
            self.ovn_lb, 'pool_%s' % self.pool_id)
        self.assertEqual([self.listener_id], ret)

    def test__get_pool_listeners_not_found(self):
        self._get_pool_listeners.stop()
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: 'fc00::',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '2002::',
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        ret = self.helper._get_pool_listeners(
            self.ovn_lb, 'pool_foo')
        self.assertEqual([], ret)

    def test___get_pool_listener_port(self):
        self._get_pool_listeners.stop()
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: 'fc00::',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '2002::',
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        ret = self.helper._get_pool_listener_port(
            self.ovn_lb, 'pool_foo')
        self.assertIsNone(ret)

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

    def test_lb_delete_lrp_assoc_no_net_lb_r_lb(self):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.network.load_balancer = []
        self.helper.lb_delete_lrp_assoc(info)

        self.helper._update_lb_to_lr_association.assert_not_called()
        self.helper._update_lb_to_ls_association.assert_called_once_with(
            self.router.load_balancer[0],
            network_id=info['network'].uuid,
            associate=False,
            update_ls_ref=False
        )

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

    def test_lb_delete_lrp_assoc_r_lb_exception(self):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.helper._update_lb_to_ls_association.side_effect = [
            idlutils.RowNotFound]
        with self.assertLogs(level='WARN') as cm:
            self.helper.lb_delete_lrp_assoc(info)
            self.assertEqual(
                cm.output,
                ['WARNING:ovn_octavia_provider.helper:'
                 'The disassociation of loadbalancer '
                 '%s to the logical switch %s failed, just keep going on'
                 % (self.router.load_balancer[0].uuid, self.network.uuid)])

    def test_lb_delete_lrp_assoc(self):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.helper.lb_delete_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router, delete=True
        )
        self.helper._update_lb_to_ls_association.assert_called_once_with(
            self.router.load_balancer[0],
            network_id=self.network.uuid,
            associate=False, update_ls_ref=False
        )

    def test_lb_delete_lrp_assoc_ls_by_step(self):
        self._update_lb_to_ls_association.stop()
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.helper._update_lb_to_lr_association.side_effect = [
            idlutils.RowNotFound]
        self.helper.lb_delete_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router, delete=True
        )
        self.helper._update_lb_to_lr_association_by_step \
            .assert_called_once_with(
                self.network.load_balancer[0],
                self.router, delete=True)

    def test_lb_create_lrp_assoc_handler(self):
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'gateway_chassis': []})
        self.helper.lb_create_lrp_assoc_handler(lrp)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network,
                 'gateway_chassis': []},
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

    def test_lb_create_lrp_assoc(self):
        info = {
            'network': self.network,
            'router': self.router,
            'gateway_chassis': [],
        }
        self.helper.lb_create_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router
        )

    def test_lb_create_lrp_assoc_r_lb_exception(self):
        info = {
            'network': self.network,
            'router': self.router,
            'gateway_chassis': [],
        }
        self.helper._update_lb_to_ls_association.side_effect = [
            idlutils.RowNotFound]
        with self.assertLogs(level='WARN') as cm:
            self.helper.lb_create_lrp_assoc(info)
            self.assertEqual(
                cm.output,
                ['WARNING:ovn_octavia_provider.helper:'
                 'The association of loadbalancer '
                 '%s to the logical switch %s failed, just keep going on'
                 % (self.router.load_balancer[0].uuid, self.network.uuid)])

    def test_lb_create_lrp_assoc_ls_by_step(self):
        self._update_lb_to_ls_association.stop()
        info = {
            'network': self.network,
            'router': self.router,
            'gateway_chassis': 'fake-chassis',
        }
        self.helper._update_lb_to_lr_association.side_effect = [
            idlutils.RowNotFound]
        self.helper.lb_create_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router
        )
        self.helper._update_lb_to_lr_association_by_step \
            .assert_called_once_with(
                self.network.load_balancer[0],
                self.router)

    def test_lb_create_lrp_assoc_uniq_lb(self):
        info = {
            'network': self.network,
            'router': self.router,
            'gateway_chassis': 'fake-chassis',
        }
        # Make it already uniq.
        self.network.load_balancer = self.router.load_balancer
        self.helper.lb_create_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_not_called()

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

    def test__find_ls_for_lr(self):
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'foo1'},
            'networks': ["10.0.0.1/24"]})
        p2 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'foo2'},
            'networks': ["10.0.10.1/24"]})
        self.router.ports.append(p1)
        self.router.ports.append(p2)
        res = self.helper._find_ls_for_lr(self.router, n_const.IP_VERSION_4)
        self.assertListEqual(['neutron-foo1', 'neutron-foo2'], res)

    def test__find_ls_for_lr_net_not_found(self):
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'foo1'},
            'networks': ["10.0.0.1/24"]})
        p2 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {},
            'networks': ["10.0.10.1/24"]})
        self.router.ports.append(p2)
        self.router.ports.append(p1)
        res = self.helper._find_ls_for_lr(self.router, n_const.IP_VERSION_4)
        self.assertListEqual(['neutron-foo1'], res)

    def test__find_ls_for_lr_different_ip_version(self):
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'foo1'},
            'networks': ["10.0.0.1/24"]})
        p2 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'foo2'},
            'networks': ["fdaa:4ad8:e8fb::/64"]})
        self.router.ports.append(p2)
        self.router.ports.append(p1)
        res = self.helper._find_ls_for_lr(self.router, n_const.IP_VERSION_4)
        self.assertListEqual(['neutron-foo1'], res)
        res = self.helper._find_ls_for_lr(self.router, n_const.IP_VERSION_6)
        self.assertListEqual(['neutron-foo2'], res)

    def test__find_ls_for_lr_gw_port(self):
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': ['foo-gw-chassis'],
            'external_ids': {
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'foo1'},
            'networks': ["10.0.0.1/24"]})
        self.router.ports.append(p1)
        result = self.helper._find_ls_for_lr(self.router, n_const.IP_VERSION_4)
        self.assertListEqual([], result)

    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_del_lb_to_lr_association')
    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_add_lb_to_lr_association')
    def test__get_lb_to_lr_association_commands(self, add, delete):
        self._get_lb_to_lr_association_commands.stop()
        self.helper._get_lb_to_lr_association_commands(
            self.ref_lb1, self.router)
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        add.assert_called_once_with(self.ref_lb1, self.router, lr_ref)
        delete.assert_not_called()

    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_del_lb_to_lr_association')
    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_add_lb_to_lr_association')
    def test__get_lb_to_lr_association_commands_delete(self, add, delete):
        self._get_lb_to_lr_association_commands.stop()
        self.helper._get_lb_to_lr_association_commands(
            self.ref_lb1, self.router, delete=True)
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        add.assert_not_called()
        delete.assert_called_once_with(self.ref_lb1, self.router, lr_ref)

    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_del_lb_to_lr_association')
    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_add_lb_to_lr_association')
    def test__get_lb_to_lr_association_commands_by_step(
            self, add, delete):
        self._update_lb_to_lr_association_by_step.stop()
        self._get_lb_to_lr_association_commands.stop()
        self.helper._update_lb_to_lr_association_by_step(
            self.ref_lb1, self.router)
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        add.assert_called_once_with(self.ref_lb1, self.router, lr_ref)
        delete.assert_not_called()

    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_del_lb_to_lr_association')
    @mock.patch.object(
        ovn_helper.OvnProviderHelper, '_add_lb_to_lr_association')
    def test__get_lb_to_lr_association_commands_by_step_delete(
            self, add, delete):
        self._update_lb_to_lr_association_by_step.stop()
        self._get_lb_to_lr_association_commands.stop()
        self.helper._update_lb_to_lr_association_by_step(
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

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ls_for_lr')
    def test__add_lb_to_lr_association_lr_already_associated(self, f_ls):
        self.ref_lb1.external_ids.update({
            ovn_const.LB_EXT_IDS_LR_REF_KEY: self.router.name})
        lr_ref = self.ref_lb1.external_ids.get(ovn_const.LB_EXT_IDS_LR_REF_KEY)
        f_ls.return_value = ['neutron-xyz', 'neutron-qwr']
        self.helper._add_lb_to_lr_association(
            self.ref_lb1,
            self.router,
            lr_ref)
        self.helper.ovn_nbdb_api.lr_lb_add.assert_called_once_with(
            self.router.uuid, self.ref_lb1.uuid, may_exist=True)
        self.helper.ovn_nbdb_api.ls_lb_add.assert_has_calls([
            (mock.call('neutron-xyz', self.ref_lb1.uuid, may_exist=True)),
            (mock.call('neutron-qwr', self.ref_lb1.uuid, may_exist=True))])
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ls_for_lr')
    def test__add_lb_to_lr_association_no_lr_rf(self, f_ls):
        lr_ref = ''
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
            ('external_ids', {'lr_ref': '%s' % self.router.name}))

    def test__extract_listener_key_value(self):
        self.assertEqual(
            (None, None),
            self.helper._extract_listener_key_value('listener'))
        self.assertEqual(
            ('listener', '123'),
            self.helper._extract_listener_key_value('listener:123'))

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
        lrp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'name': 'lrp-foo-name2',
            })
        lr2 = fakes.FakeOVNRouter.create_one_router(
            attrs={
                'name': 'router2',
                'ports': [lrp2]})
        ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [lsp2, lsp]})

        (self.helper.ovn_nbdb_api.get_lrs.return_value.
            execute.return_value) = [lr2, lr]
        returned_lr = self.helper._find_lr_of_ls(ls, '10.10.10.1')
        self.assertEqual(lr, returned_lr)

    def test__find_lr_of_ls_no_lrs(self):
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
        ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [lsp2, lsp]})
        (self.helper.ovn_nbdb_api.get_lrs.return_value.
            execute.return_value) = []
        returned_lr = self.helper._find_lr_of_ls(ls, '10.10.10.1')
        self.assertIsNone(returned_lr)

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
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1',
                    ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                        n_const.DEVICE_OWNER_ROUTER_INTF},
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

    def test__get_lb_to_ls_association_command_empty_network_and_subnet(self):
        self._get_lb_to_ls_association_commands.stop()
        returned_commands = self.helper._get_lb_to_ls_association_commands(
            self.ref_lb1, associate=True, update_ls_ref=True)
        self.assertListEqual(returned_commands, [])

    def test__get_member_info(self):
        fake_member = fakes.FakeMember(
            uuid=self.member['id'],
            member_id=self.member['id'],
            admin_state_up=True,
            name='member_2',
            project_id=self.project_id,
            address=self.member['address'],
            protocol_port=self.member['protocol_port'],
            subnet_id=self.member['subnet_id'])
        result = (
            ovn_const.LB_EXT_IDS_MEMBER_PREFIX + fake_member.member_id +
            '_' + fake_member.address + ':' + fake_member.protocol_port +
            '_' + fake_member.subnet_id)
        self.assertEqual(
            result, self.helper._get_member_info(fake_member))
        result = (
            ovn_const.LB_EXT_IDS_MEMBER_PREFIX + self.member['id'] + '_' +
            self.member['address'] + ':' + self.member['protocol_port'] +
            '_' + self.member['subnet_id'])
        self.assertEqual(
            result, self.helper._get_member_info(self.member))
        self.assertEqual('', self.helper._get_member_info(None))

    def test__update_lb_to_ls_association_network(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=True, update_ls_ref=True)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        ls_refs = {'ls_refs': '{"%s": 2}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', ls_refs))

    def test__update_lb_to_ls_association_network_no_update_ls_ref(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=True, update_ls_ref=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test__update_lb_to_ls_association_network_no_assoc_no_update_ls_ref(
            self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=False, update_ls_ref=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test__update_lb_to_ls_association_network_no_assoc_update_ls_ref(
            self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=False, update_ls_ref=True)

        self.helper.ovn_nbdb_api.ls_lb_del.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, if_exists=True)
        ls_refs = {'ls_refs': '{}'}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', ls_refs))

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__update_lb_to_ls_association_subnet(self, net_cli):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        subnet = fakes.FakeSubnet.create_one_subnet(
            attrs={'id': 'foo_subnet_id',
                   'name': 'foo_subnet_name',
                   'network_id': 'foo_network_id'})
        net_cli.return_value.show_subnet.return_value = {
            'subnet': subnet}
        self.helper._update_lb_to_ls_association(
            self.ref_lb1, subnet_id=subnet.id,
            associate=True, update_ls_ref=True)
        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            'neutron-foo_network_id')

    def test__update_lb_to_ls_association_empty_ls_refs(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.ref_lb1.external_ids.pop('ls_refs')

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            update_ls_ref=True)

        self.helper.ovn_nbdb_api.ls_lb_add.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, may_exist=True)
        ls_refs = {'ls_refs': '{"%s": 1}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', ls_refs))

    def test__update_lb_to_ls_association_empty_ls_refs_no_ls(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = None
        self.ref_lb1.external_ids.pop('ls_refs')

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            update_ls_ref=False)

        self.helper.ovn_nbdb_api.ls_lb_add.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test__update_lb_to_ls_association_no_ls(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            side_effect) = [idlutils.RowNotFound]

        returned_commands = self.helper._get_lb_to_ls_association_commands(
            self.ref_lb1, network_id=self.network.uuid,
            update_ls_ref=True)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.assertListEqual([], returned_commands)

    def test__update_lb_to_ls_association_network_disassociate(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=False, update_ls_ref=True)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid,
            ('external_ids', {'ls_refs': '{}'}))
        self.helper.ovn_nbdb_api.ls_lb_del.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, if_exists=True)

    def test__update_lb_to_ls_association_net_disassoc_no_update_ls_ref(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=False, update_ls_ref=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()
        self.helper.ovn_nbdb_api.ls_lb_del.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, if_exists=True)

    def test__update_lb_to_ls_association_dissasoc_net_not_assoc(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id='foo',
            associate=False, update_ls_ref=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            'neutron-foo')
        self.helper.ovn_nbdb_api.db_set.assert_not_called()
        self.helper.ovn_nbdb_api.ls_lb_del.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, if_exists=True)

    def test__update_lb_to_ls_association_net_ls_ref_wrong_format(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()

        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network

        self.ref_lb1.external_ids.update({
            ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                '{\"neutron-%s\"}'})

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=False, update_ls_ref=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test__update_lb_to_ls_association_network_dis_ls_not_found(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            side_effect) = [idlutils.RowNotFound]

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=False, update_ls_ref=True)

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
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.helper._update_lb_to_ls_association(
            self.ref_lb1, subnet_id='foo',
            associate=False, update_ls_ref=True)
        self.helper.ovn_nbdb_api.ls_get.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()
        self.helper.ovn_nbdb_api.ls_lb_del.assert_not_called()

    def test__update_lb_to_ls_association_disassoc_ls_not_in_ls_refs(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.ref_lb1.external_ids.pop('ls_refs')

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=False, update_ls_ref=True)

        self.helper.ovn_nbdb_api.ls_lb_del.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test__update_lb_to_ls_association_disassoc_multiple_refs(self):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        # multiple refs
        ls_refs = {'ls_refs': '{"%s": 2}' % self.network.name}
        self.ref_lb1.external_ids.update(ls_refs)

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid,
            associate=False, update_ls_ref=True)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        exp_ls_refs = {'ls_refs': '{"%s": 1}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', exp_ls_refs))

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test__update_lb_to_ls_association_retry(self, execute):
        self._update_lb_to_ls_association.stop()
        self._get_lb_to_ls_association_commands.stop()
        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid)
        expected = self.helper._get_lb_to_ls_association_commands(
            self.ref_lb1, network_id=self.network.uuid)
        execute.assert_called_once_with(expected)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test__update_lb_to_ls_association_retry_failed(self, execute):
        execute.side_effect = [idlutils.RowNotFound for _ in range(4)]
        self._update_lb_to_ls_association.stop()
        self.assertRaises(
            idlutils.RowNotFound,
            self.helper._update_lb_to_ls_association,
            self.ref_lb1,
            network_id=self.network.uuid)

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

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test_delete_port_not_found(self, net_cli):
        net_cli.return_value.delete_port.side_effect = (
            [n_exc.PortNotFoundClient])
        self.helper.delete_port('foo')

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

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test__update_lb_to_lr_association_retry(self, execute):
        self._update_lb_to_lr_association.stop()
        self._get_lb_to_lr_association_commands.stop()
        self.helper._update_lb_to_lr_association(self.ref_lb1, self.router)
        expected = self.helper._get_lb_to_lr_association_commands(
            self.ref_lb1, self.router)
        execute.assert_called_once_with(expected)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_execute_commands')
    def test__update_lb_to_lr_association_retry_failed(self, execute):
        execute.side_effect = [idlutils.RowNotFound for _ in range(4)]
        self._update_lb_to_lr_association.stop()
        self.assertRaises(
            idlutils.RowNotFound,
            self.helper._update_lb_to_lr_association,
            self.ref_lb1,
            self.router)

    def test__update_lb_to_lr_association_by_step(self):
        self._get_lb_to_lr_association_commands.stop()
        self._update_lb_to_lr_association_by_step.stop()
        self.helper._update_lb_to_lr_association_by_step(
            self.network.load_balancer[0],
            self.router)
        self.helper.ovn_nbdb_api.db_set.assert_called()
        self.helper.ovn_nbdb_api.lr_lb_add.assert_called()

    def test__update_lb_to_lr_association_by_step_exception_raise(
            self):
        self._get_lb_to_lr_association_commands.stop()
        self._update_lb_to_lr_association_by_step.stop()
        (self.helper.ovn_nbdb_api.db_set.return_value.execute.
            side_effect) = [idlutils.RowNotFound]
        self.assertRaises(
            idlutils.RowNotFound,
            self.helper._update_lb_to_lr_association_by_step,
            self.network.load_balancer[0],
            self.router)

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
        vip_fip = '10.0.0.123'
        external_ids = {
            'neutron:vip': '172.26.21.20',
            'neutron:vip_fip': vip_fip}

        lb.external_ids = external_ids
        lb_hc = mock.MagicMock()
        lb_hc.uuid = "fake_lb_hc"
        lb_hc.vip = "{}:80".format(vip_fip)
        lb.health_check = [lb_hc]

        fip_info = {
            'action': 'disassociate',
            'vip_fip': vip_fip,
            'ovn_lb': lb}
        flb.return_value = lb
        self.helper.handle_vip_fip(fip_info)
        calls = [
            mock.call.db_remove(
                'Load_Balancer', lb.uuid, 'external_ids', 'neutron:vip_fip'),
            mock.call.db_remove(
                'Load_Balancer', lb.uuid, 'health_check', lb_hc.uuid),
            mock.call.db_destroy('Load_Balancer_Health_Check', lb_hc.uuid),
            mock.call.db_clear('Load_Balancer', lb.uuid, 'vips'),
            mock.call.db_set('Load_Balancer', lb.uuid, ('vips', {}))]
        self.helper.ovn_nbdb_api.assert_has_calls(calls)

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_handle_vip_fip_disassociate_no_lbhc(self, flb):
        lb = mock.MagicMock()
        vip_fip = '10.0.0.123'
        external_ids = {
            'neutron:vip': '172.26.21.20',
            'neutron:vip_fip': vip_fip}

        lb.external_ids = external_ids
        lb.health_check = []

        fip_info = {
            'action': 'disassociate',
            'vip_fip': vip_fip,
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
    def test_handle_vip_fip_disassociate_no_matching_lbhc(self, flb):
        lb = mock.MagicMock()
        vip_fip = '10.0.0.123'
        external_ids = {
            'neutron:vip': '172.26.21.20',
            'neutron:vip_fip': vip_fip}

        lb.external_ids = external_ids
        lb_hc = mock.MagicMock()
        lb_hc.uuid = "fake_lb_hc"
        lb_hc.vip = "10.0.0.222:80"
        lb.health_check = [lb_hc]
        lb.health_check = []

        fip_info = {
            'action': 'disassociate',
            'vip_fip': vip_fip,
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

        kwargs = {
            'vip': fip_info['vip_fip'],
            'options': lb.health_check[0].options,
            'external_ids': lb.health_check[0].external_ids}
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer_Health_Check', **kwargs)
        self.helper.ovn_nbdb_api.db_add.assert_called_once_with(
            'Load_Balancer', lb.uuid, 'health_check', mock.ANY)
        expected_db_set_calls = [
            mock.call('Load_Balancer', lb.uuid,
                      ('external_ids', {'neutron:vip_fip': '10.0.0.123'})),
            mock.call('Load_Balancer', lb.uuid,
                      ('vips', {'10.0.0.123:80': '192.168.2.149:1010',
                                '172.26.21.20:80': '192.168.2.149:1010'}))
        ]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(expected_db_set_calls)
        self.helper.ovn_nbdb_api.db_clear.assert_called_once_with(
            'Load_Balancer', lb.uuid, 'vips')

    @mock.patch('ovn_octavia_provider.helper.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_handle_vip_fip_associate_no_lbhc(self, fb):
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
        lb.health_check = []
        fb.return_value = lb

        self.helper.handle_vip_fip(fip_info)

        self.helper.ovn_nbdb_api.db_create.assert_not_called()
        self.helper.ovn_nbdb_api.db_add.assert_not_called()
        expected_db_set_calls = [
            mock.call('Load_Balancer', lb.uuid,
                      ('external_ids', {'neutron:vip_fip': '10.0.0.123'})),
            mock.call('Load_Balancer', lb.uuid,
                      ('vips', {'10.0.0.123:80': '192.168.2.149:1010',
                                '172.26.21.20:80': '192.168.2.149:1010'}))
        ]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(expected_db_set_calls)
        self.helper.ovn_nbdb_api.db_clear.assert_called_once_with(
            'Load_Balancer', lb.uuid, 'vips')

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

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test_create_vip_port_vip_neutron_client_other_exception(
            self, del_port, net_cli):
        net_cli.return_value.create_port.side_effect = [
            n_exc.NeutronClientException]
        net_cli.return_value.list_ports.return_value = {
            'ports': [
                {'name': 'ovn-lb-vip-' + self.loadbalancer_id,
                 'id': self.loadbalancer_id}]}
        self.assertRaises(
            n_exc.NeutronClientException,
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
        del_port.assert_called_once_with(self.loadbalancer_id)
        self.helper._update_status_to_octavia.assert_not_called()

    def test_get_pool_member_id(self):
        ret = self.helper.get_pool_member_id(
            self.pool_id, mem_addr_port='192.168.2.149:1010')
        self.assertEqual(self.member_id, ret)

    def test_get_pool_member_id_not_found(self):
        ret = self.helper.get_pool_member_id(
            self.pool_id, mem_addr_port='192.168.2.149:9999')
        self.assertIsNone(ret)

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

    def test__frame_lb_vips_no_vip_fip(self):
        self.ovn_lb.external_ids.pop(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
        ret = self.helper._frame_vip_ips(self.ovn_lb.external_ids)
        expected = {'10.22.33.4:80': '192.168.2.149:1010'}
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
    def _test_hm_create(self, protocol, members, fip, folbpi, uhm,
                        net_cli):
        self._get_pool_listeners.stop()
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.protocol = [protocol]
        folbpi.return_value = (pool_key, self.ovn_hm_lb)
        uhm.return_value = True
        net_cli.return_value.show_subnet.return_value = {'subnet': fake_subnet}
        if not fip:
            del self.ovn_hm_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_FIP_KEY]
        status = self.helper.hm_create(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)
        if members:
            self.assertEqual(status['members'][0]['provisioning_status'],
                             constants.ACTIVE)
            self.assertEqual(status['members'][0]['operating_status'],
                             constants.ONLINE)
        vip = (self.ovn_hm_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_KEY] +
               ':' + str(self.listener['protocol_port']))
        if fip:
            fip = (self.ovn_hm_lb.external_ids[
                   ovn_const.LB_EXT_IDS_VIP_FIP_KEY] +
                   ':' + str(self.listener['protocol_port']))
        options = {'interval': '6',
                   'timeout': '7',
                   'failure_count': '5',
                   'success_count': '3'}
        external_ids = {ovn_const.LB_EXT_IDS_HM_KEY: self.healthmonitor_id}
        kwargs = {'vip': vip,
                  'options': options,
                  'external_ids': external_ids}
        if fip:
            fip_kwargs = {'vip': fip,
                          'options': options,
                          'external_ids': external_ids}

        expected_lbhc_calls = [
            mock.call('Load_Balancer_Health_Check', **kwargs)]
        if fip:
            expected_lbhc_calls.append(
                mock.call('Load_Balancer_Health_Check', **fip_kwargs)
            )
        self.helper.ovn_nbdb_api.db_create.assert_has_calls(
            expected_lbhc_calls)

        if fip:
            self.assertEqual(self.helper.ovn_nbdb_api.db_add.call_count, 2)
        else:
            self.helper.ovn_nbdb_api.db_add.assert_called_once_with(
                'Load_Balancer', self.ovn_hm_lb.uuid, 'health_check', mock.ANY)

    def test_hm_create_tcp(self):
        self._test_hm_create('tcp', False, True)

    def test_hm_create_tcp_no_fip(self):
        self._test_hm_create('tcp', False, False)

    def test_hm_create_udp(self):
        self._test_hm_create('udp', False, True)

    def test_hm_create_tcp_pool_members(self):
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids[pool_key] = self.member_line
        self._test_hm_create('tcp', True, True)

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
        expected_lbhc_calls = [
            mock.call('Load_Balancer_Health_Check', **kwargs),
            mock.call('Load_Balancer_Health_Check', **kwargs)]
        self.helper.ovn_nbdb_api.db_create.has_calls(expected_lbhc_calls)
        self.assertEqual(self.helper.ovn_nbdb_api.db_add.call_count, 2)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_create_offline(self, folbpi):
        self._get_pool_listeners.stop()
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
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
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
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ONLINE)

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

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_get_or_create_ovn_lb')
    def test_hm_create_then_listener_create(self, get_ovn_lb):
        vip = (self.ovn_hm_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_KEY] +
               ':' + str(self.listener['protocol_port']))
        fip = (self.ovn_hm_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_FIP_KEY] +
               ':' + str(self.listener['protocol_port']))
        self.ovn_hm.vip = []
        self.ovn_hm_lb.health_check = [self.ovn_hm]
        get_ovn_lb.return_value = self.ovn_hm_lb
        self.listener['admin_state_up'] = True
        kwargs = {
            'vip': fip,
            'options': self.ovn_hm.options,
            'external_ids': self.ovn_hm.external_ids}

        status = self.helper.listener_create(self.listener)

        self.helper.ovn_nbdb_api.db_set.assert_called_with(
            'Load_Balancer_Health_Check', self.ovn_hm.uuid, ('vip', vip))
        self.helper.ovn_nbdb_api.db_create.assert_called_with(
            'Load_Balancer_Health_Check', **kwargs)
        self.helper.ovn_nbdb_api.db_add.assert_called_with(
            'Load_Balancer', self.ovn_hm_lb.uuid, 'health_check', mock.ANY)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_get_or_create_ovn_lb')
    def test_hm_create_then_listener_create_no_fip(self, get_ovn_lb):
        vip = (self.ovn_hm_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_KEY] +
               ':' + str(self.listener['protocol_port']))
        self.ovn_hm.vip = []
        self.ovn_hm_lb.health_check = [self.ovn_hm]
        get_ovn_lb.return_value = self.ovn_hm_lb
        self.listener['admin_state_up'] = True
        del self.ovn_hm_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_FIP_KEY]

        status = self.helper.listener_create(self.listener)

        self.helper.ovn_nbdb_api.db_set.assert_called_with(
            'Load_Balancer_Health_Check', self.ovn_hm.uuid, ('vip', vip))
        self.helper.ovn_nbdb_api.db_create.assert_not_called()
        self.helper.ovn_nbdb_api.db_add.assert_not_called()
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_lookup_lbhcs_by_hm_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_get_or_create_ovn_lb')
    def test_hm_create_then_listener_create_no_hm(self, get_ovn_lb, lookup_hm):
        get_ovn_lb.return_value = self.ovn_hm_lb
        lookup_hm.return_value = []
        self.ovn_hm_lb.health_check = [self.ovn_hm]
        self.listener['admin_state_up'] = True
        status = self.helper.listener_create(self.listener)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_refresh_lb_vips')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_lookup_lbhcs_by_hm_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_get_or_create_ovn_lb')
    def test_hm_create_then_listener_create_no_vip(self, get_ovn_lb,
                                                   lookup_hm, refresh_vips):
        get_ovn_lb.return_value = self.ovn_hm_lb
        lookup_hm.return_value = [self.ovn_hm]
        self.ovn_hm_lb.health_check = [self.ovn_hm]
        self.ovn_hm_lb.external_ids.pop(ovn_const.LB_EXT_IDS_VIP_KEY)
        self.listener['admin_state_up'] = True
        status = self.helper.listener_create(self.listener)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_update_lbhc_vip')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lbs')
    def test_hm_create_then_listener_update(self, find_ovn_lbs,
                                            update_lbhc_vip):
        find_ovn_lbs.return_value = self.ovn_hm_lb
        self.helper.listener_update(self.listener)
        update_lbhc_vip.assert_called_once_with(
            self.ovn_hm_lb, self.listener[constants.PROTOCOL_PORT])

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update(self, folbfhi):
        folbfhi.return_value = ([self.ovn_hm], self.ovn_hm_lb)
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update_no_admin_state_up(self, folbfhi):
        folbfhi.return_value = ([self.ovn_hm], self.ovn_hm_lb)
        self.ovn_hm_lb.pop('admin_state_up')
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update_offline(self, folbfhi):
        folbfhi.return_value = ([self.ovn_hm], self.ovn_hm_lb)
        self.health_monitor['admin_state_up'] = False
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.OFFLINE)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update_hm_not_found(self, folbfhi):
        folbfhi.return_value = ([], None)
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_by_pool_id')
    def test_hm_update_lb_not_found(self, folbpi, folbfhi):
        folbfhi.return_value = ([self.ovn_hm], None)
        folbpi.return_value = (None, None)
        status = self.helper.hm_update(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_find_ovn_lb_from_hm_id')
    def test_hm_update_just_interval(self, folbfhi):
        folbfhi.return_value = ([self.ovn_hm], self.ovn_hm_lb)
        self.health_monitor['interval'] = 3
        self.helper.hm_update(self.health_monitor)
        options = {
            'interval': str(self.health_monitor['interval']),
            'timeout': str(self.health_monitor['timeout']),
            'success_count': str(self.health_monitor['success_count']),
            'failure_count': str(self.health_monitor['failure_count'])}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer_Health_Check',
            self.ovn_hm.uuid,
            ('options', options))

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_clean_up_hm_port')
    def test_hm_delete(self, del_hm_port):
        self._get_pool_listeners.stop()
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids[pool_key] = self.member_line
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.side_effect = [[self.ovn_hm_lb], [self.ovn_hm]]
        status = self.helper.hm_delete(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.NO_MONITOR)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        expected_clear_calls = [
            mock.call('Load_Balancer', self.ovn_hm_lb.uuid,
                      'ip_port_mappings')]
        expected_remove_calls = [
            mock.call('Load_Balancer', self.ovn_hm_lb.uuid, 'health_check',
                      self.ovn_hm.uuid)]
        expected_destroy_calls = [
            mock.call('Load_Balancer_Health_Check', self.ovn_hm.uuid)]
        del_hm_port.assert_called_once_with(self.member_subnet_id)
        self.helper.ovn_nbdb_api.db_clear.assert_has_calls(
            expected_clear_calls)
        self.helper.ovn_nbdb_api.db_remove.assert_has_calls(
            expected_remove_calls)
        self.helper.ovn_nbdb_api.db_destroy.assert_has_calls(
            expected_destroy_calls)

    @mock.patch.object(ovn_helper.OvnProviderHelper, '_clean_up_hm_port')
    def test_hm_delete_without_members_in_pool(self, del_hm_port):
        self._get_pool_listeners.stop()
        pool_key = 'pool_%s' % self.pool_id
        self.ovn_hm_lb.external_ids[pool_key] = ''
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.side_effect = [[self.ovn_hm_lb], [self.ovn_hm]]
        status = self.helper.hm_delete(self.health_monitor)
        self.assertEqual(status['healthmonitors'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['healthmonitors'][0]['operating_status'],
                         constants.NO_MONITOR)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        expected_clear_calls = [
            mock.call('Load_Balancer', self.ovn_hm_lb.uuid,
                      'ip_port_mappings')]
        expected_remove_calls = [
            mock.call('Load_Balancer', self.ovn_hm_lb.uuid, 'health_check',
                      self.ovn_hm.uuid)]
        expected_destroy_calls = [
            mock.call('Load_Balancer_Health_Check', self.ovn_hm.uuid)]
        del_hm_port.assert_not_called()
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
                   'status': ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE})
        self.hm_update_event.run('update', row, mock.ANY)
        expected = {
            'info':
                {'ovn_lbs': [self.ovn_hm_lb],
                 'ip': self.member_address,
                 'port': self.member_port,
                 'status': ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE},
            'type': 'hm_update_event'}
        self.mock_add_request.assert_called_once_with(expected)
        self.helper.ovn_nbdb_api.db_find_rows.assert_called_once_with(
            'Load_Balancer',
            ('ip_port_mappings', '=',
             {self.member_address: 'a-logical-port:' + src_ip}),
            ('protocol', '=', self.ovn_hm_lb.protocol[0]))

    def test_hm_update_event_offline_by_delete(self):
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
                   'status': ovn_const.HM_EVENT_MEMBER_PORT_ONLINE})
        self.hm_update_event.run('delete', row, mock.ANY)
        expected = {
            'info':
                {'ovn_lbs': [self.ovn_hm_lb],
                 'ip': self.member_address,
                 'port': self.member_port,
                 'status': ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE},
            'type': 'hm_update_event'}
        self.mock_add_request.assert_called_once_with(expected)
        self.helper.ovn_nbdb_api.db_find_rows.assert_called_once_with(
            'Load_Balancer',
            ('ip_port_mappings', '=',
             {self.member_address: 'a-logical-port:' + src_ip}),
            ('protocol', '=', self.ovn_hm_lb.protocol[0]))

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
                   'status': ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE})
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
                   'status': ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE})
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
            'ovn_lbs': [self.ovn_hm_lb],
            'ip': ip,
            'logical_port': 'a-logical-port',
            'src_ip': '10.22.33.4',
            'port': port,
            'protocol': self.ovn_hm_lb.protocol,
            'status': ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE}

        status = self.helper.hm_update_event(info)
        self.assertIsNone(status)

    def test_hm_update_event_member_ip_not_found(self):
        self._test_hm_update_no_member(True, False)

    def test_hm_update_event_member_port_not_found(self):
        self._test_hm_update_no_member(False, True)

    def _test_hm_update_status(self, ovn_lbs, member_id, ip, port,
                               member_status):
        info = {
            'ovn_lbs': ovn_lbs,
            'ip': ip,
            'logical_port': 'a-logical-port',
            'src_ip': '10.22.33.4',
            'port': port,
            'protocol': ovn_lbs[0].protocol,
            'status': [member_status]}
        self._update_external_ids_member_status(self.ovn_hm_lb, member_id,
                                                member_status)
        status = self.helper.hm_update_event(info)
        return status

    def _update_external_ids_member_status(self, lb, member_id, member_status):
        status = constants.ONLINE
        if member_status == 'offline':
            status = constants.ERROR
        try:
            existing_member_status = lb.external_ids[
                ovn_const.OVN_MEMBER_STATUS_KEY]
            member_statuses = jsonutils.loads(existing_member_status)
        except Exception:
            member_statuses = {}

        member_statuses[member_id] = status
        lb.external_ids[
            ovn_const.OVN_MEMBER_STATUS_KEY] = jsonutils.dumps(
                member_statuses)

    def _add_member(self, lb, subnet, port, pool_id=None, ip=None):
        if not pool_id:
            pool_id = self.pool_id

        if not ip:
            fake_port = fakes.FakePort.create_one_port(
                attrs={'allowed_address_pairs': ''})
            ip = fake_port['fixed_ips'][0]['ip_address']

        member = {'id': uuidutils.generate_uuid(),
                  'address': ip,
                  'protocol_port': port,
                  'subnet_id': subnet['id'],
                  'pool_id': pool_id,
                  'admin_state_up': True,
                  'old_admin_state_up': True}
        member_line = (
            'member_%s_%s:%s_%s' %
            (member['id'], member['address'],
             member['protocol_port'], member['subnet_id']))
        pool_key = 'pool_%s' % pool_id

        existing_members = lb.external_ids[pool_key]
        existing_member_status = lb.external_ids[
            ovn_const.OVN_MEMBER_STATUS_KEY]

        try:
            member_statuses = jsonutils.loads(existing_member_status)
        except Exception:
            member_statuses = {}

        if existing_members:
            existing_members = ','.join([existing_members, member_line])
            lb.external_ids[pool_key] = existing_members
            member_statuses[member['id']] = constants.ONLINE
            lb.external_ids[
                ovn_const.OVN_MEMBER_STATUS_KEY] = jsonutils.dumps(
                    member_statuses)
        else:
            lb.external_ids[pool_key] = member_line
            member_status = '{"%s": "%s"}' % (member['id'],
                                              constants.ONLINE)
            lb.external_ids[
                ovn_const.OVN_MEMBER_STATUS_KEY] = member_status
        return member

    def test__create_hm_port(self):
        expected_dict = {
            'port': {'name': '%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                                       self.vip_dict['vip_subnet_id']),
                     'network_id': self.vip_dict['vip_network_id'],
                     'fixed_ips': [{'subnet_id':
                                    self.vip_dict['vip_subnet_id']}],
                     'admin_state_up': True,
                     'port_security_enabled': False,
                     'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                     'project_id': self.project_id
                     }}
        with mock.patch.object(clients, 'get_neutron_client') as net_cli:
            hm_port = self.helper._create_hm_port(
                self.vip_dict['vip_network_id'],
                self.vip_dict['vip_subnet_id'],
                self.project_id)
            expected_call = [
                mock.call().create_port(expected_dict)]
            net_cli.assert_has_calls(expected_call)
            self.assertIsNotNone(hm_port)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    def test__create_hm_port_neutron_client_exception(
            self, net_cli):
        net_cli.return_value.create_port.side_effect = [
            n_exc.NeutronClientException]
        net_cli.return_value.list_ports.return_value = {
            'ports': []}
        expected_dict = {
            'port': {'name': '%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                                       self.vip_dict['vip_subnet_id']),
                     'network_id': self.vip_dict['vip_network_id'],
                     'fixed_ips': [{'subnet_id':
                                    self.vip_dict['vip_subnet_id']}],
                     'admin_state_up': True,
                     'port_security_enabled': False,
                     'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                     'project_id': self.project_id
                     }}
        hm_port = self.helper._create_hm_port(
            self.vip_dict['vip_network_id'],
            self.vip_dict['vip_subnet_id'],
            self.project_id)
        expected_call = [
            mock.call(),
            mock.call().create_port(expected_dict),
            mock.call(),
            mock.call().list_ports(
                name='%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                               self.vip_dict['vip_subnet_id']))]
        net_cli.assert_has_calls(expected_call)
        self.assertIsNone(hm_port)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, '_clean_up_hm_port')
    def test__create_hm_port_neutron_client_exception_clean_up_hm_port(
            self, del_hm_port, net_cli):
        net_cli.return_value.create_port.side_effect = [
            n_exc.NeutronClientException]
        net_cli.return_value.list_ports.return_value = {
            'ports': [
                {'name': '%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                                   self.vip_dict['vip_subnet_id']),
                 'id': 'fake_uuid'}]}
        expected_dict = {
            'port': {'name': '%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                                       self.vip_dict['vip_subnet_id']),
                     'network_id': self.vip_dict['vip_network_id'],
                     'fixed_ips': [{
                         'subnet_id': self.vip_dict['vip_subnet_id']}],
                     'admin_state_up': True,
                     'port_security_enabled': False,
                     'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                     'project_id': self.project_id
                     }}
        hm_port = self.helper._create_hm_port(
            self.vip_dict['vip_network_id'],
            self.vip_dict['vip_subnet_id'],
            self.project_id)
        expected_call = [
            mock.call(),
            mock.call().create_port(expected_dict)]
        net_cli.assert_has_calls(expected_call)
        del_hm_port.assert_called_once_with(self.vip_dict['vip_subnet_id'])
        self.assertIsNone(hm_port)

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test__clean_up_hm_port(self, del_port, net_cli):
        net_cli.return_value.list_ports.return_value = {
            'ports': [
                {'name': '%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                                   self.vip_dict['vip_subnet_id']),
                 'id': 'fake_uuid',
                 'fixed_ips': [{'subnet_id': 'another_subnet_id',
                                'ip_address': '10.1.2.3'},
                               {'subnet_id': self.vip_dict['vip_subnet_id'],
                                'ip_address': '10.0.0.3'}]}]}
        self.helper._clean_up_hm_port(self.vip_dict['vip_subnet_id'])
        expected_call = [
            mock.call(),
            mock.call().list_ports(
                name='%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                               self.vip_dict['vip_subnet_id']))]
        net_cli.assert_has_calls(expected_call)
        del_port.assert_called_once_with('fake_uuid')

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test__clean_up_hm_port_in_use(self, del_port, net_cli):
        net_cli.return_value.list_ports.return_value = {
            'ports': [
                {'name': '%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                                   self.vip_dict['vip_subnet_id']),
                 'id': 'fake_uuid',
                 'fixed_ips': [{'subnet_id': 'another_subnet_id',
                                'ip_address': '10.1.2.3'},
                               {'subnet_id': self.vip_dict['vip_subnet_id'],
                                'ip_address': '10.0.0.3'}]}]}
        fake_lb_unrelated = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'ip_port_mappings': {'10.1.2.4': 'fake_member_lgp:10.1.2.3'}})
        fake_lb_hm_port_in_use = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'ip_port_mappings': {'10.1.2.4': 'fake_member_lgp:10.1.2.3',
                                     '10.0.0.4': 'fake_member_lgp:10.0.0.3'}})
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [fake_lb_unrelated, fake_lb_hm_port_in_use]
        self.helper._clean_up_hm_port(self.vip_dict['vip_subnet_id'])
        expected_call = [
            mock.call(),
            mock.call().list_ports(
                name='%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                               self.vip_dict['vip_subnet_id']))]
        net_cli.assert_has_calls(expected_call)
        del_port.assert_not_called()

    @mock.patch('ovn_octavia_provider.common.clients.get_neutron_client')
    @mock.patch.object(ovn_helper.OvnProviderHelper, 'delete_port')
    def test__clean_up_hm_port_not_found(self, del_port, net_cli):
        net_cli.return_value.list_ports.return_value = {
            'ports': []}
        self.helper._clean_up_hm_port(self.vip_dict['vip_subnet_id'])
        expected_call = [
            mock.call(),
            mock.call().list_ports(
                name='%s%s' % (ovn_const.LB_HM_PORT_PREFIX,
                               self.vip_dict['vip_subnet_id']))]
        net_cli.assert_has_calls(expected_call)
        del_port.assert_not_called()

    def test_hm_update_status_offline(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member = self._add_member(self.ovn_hm_lb, fake_subnet, 8080)
        status = self._test_hm_update_status(
            [self.ovn_hm_lb], member['id'], member['address'], '8080',
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

    def test_hm_update_status_offline_two_lbs_affected(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        ovn_hm_lb_2 = copy.deepcopy(self.ovn_hm_lb)
        ovn_hm_lb_2.uuid = uuidutils.generate_uuid()
        member = self._add_member(self.ovn_hm_lb, fake_subnet, 8080)
        member_2 = self._add_member(
            ovn_hm_lb_2, fake_subnet, 8080, ip=member['address'])

        info = {
            'ovn_lbs': [self.ovn_hm_lb, ovn_hm_lb_2],
            'ip': member['address'],
            'logical_port': 'a-logical-port',
            'src_ip': '10.22.33.4',
            'port': '8080',
            'protocol': self.ovn_hm_lb.protocol,
            'status': ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE}
        self._update_external_ids_member_status(self.ovn_hm_lb, member['id'],
                                                'offline')
        self._update_external_ids_member_status(ovn_hm_lb_2, member_2['id'],
                                                'offline')
        status = self.helper.hm_update_event(info)

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
        self.assertEqual(status['pools'][1]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][1]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['members'][1]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][1]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][1]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][1]['operating_status'],
                         constants.ERROR)

    def test_hm_update_status_offline_lb_pool_offline(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member = self._add_member(self.ovn_hm_lb, fake_subnet, 8080)
        status = self._test_hm_update_status(
            [self.ovn_hm_lb], member['id'], member['address'], '8080',
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

    def test_hm_update_status_online(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member = self._add_member(self.ovn_hm_lb, fake_subnet, 8080)
        status = self._test_hm_update_status(
            [self.ovn_hm_lb], member['id'], member['address'], '8080',
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
        member = self._add_member(self.ovn_hm_lb, fake_subnet, 8080)
        status = self._test_hm_update_status(
            [self.ovn_hm_lb], member['id'], member['address'], '8080',
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

    def test_hm_update_status_offline_two_members_diff_lbs_port(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        ovn_hm_lb2 = mock.MagicMock()
        ovn_hm_lb2.uuid = uuidutils.generate_uuid()
        listener_id_2 = uuidutils.generate_uuid()
        pool_id_2 = uuidutils.generate_uuid()
        ovn_hm_lb2.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.98',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.98',
            ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_hm_port_2',
            'enabled': True,
            'pool_%s' % pool_id_2: [],
            'listener_%s' % listener_id_2: '8081:pool_%s' % pool_id_2,
            ovn_const.OVN_MEMBER_STATUS_KEY: '{}'}

        member_lb1 = self._add_member(self.ovn_hm_lb, fake_subnet, 8080)
        ip_member = member_lb1['address']
        member_lb2 = self._add_member(ovn_hm_lb2, fake_subnet, 8081,
                                      pool_id=pool_id_2, ip=ip_member)

        # member lb2 OFFLINE, so lb2 operating_status should be ERROR
        # for Pool and Loadbalancer, but lb1 should keep ONLINE
        self._update_external_ids_member_status(ovn_hm_lb2, member_lb2['id'],
                                                'offline')

        info = {
            'ovn_lbs': [self.ovn_hm_lb, ovn_hm_lb2],
            'ip': ip_member,
            'logical_port': 'a-logical-port',
            'src_ip': '10.22.33.4',
            'port': '8081',
            'protocol': ovn_hm_lb2.protocol,
            'status': ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE}

        status = self.helper.hm_update_event(info)

        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['members'][0]['id'], member_lb2['id'])

    def test_hm_update_status_offline_two_members(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member_1 = self._add_member(self.ovn_hm_lb, fake_subnet, 8080)
        ip_1 = member_1['address']
        member_2 = self._add_member(self.ovn_hm_lb, fake_subnet, 8081)
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

        status = self._test_hm_update_status(
            [self.ovn_hm_lb], member_1['id'], ip_1, '8080', 'offline')

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
        status = self._test_hm_update_status(
            [self.ovn_hm_lb], member_2['id'], ip_2, '8081', 'offline')
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)

    def test_hm_update_status_online_two_members(self):
        fake_subnet = fakes.FakeSubnet.create_one_subnet()
        member_1 = self._add_member(self.ovn_hm_lb, fake_subnet, 8080)
        member_2 = self._add_member(self.ovn_hm_lb, fake_subnet, 8081)
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
        status = self._test_hm_update_status(
            [self.ovn_hm_lb], member_2['id'], ip_2, '8081', 'offline')
        member_status = {
            ovn_const.OVN_MEMBER_STATUS_KEY: '{"%s": "%s", "%s": "%s"}'
            % (member_1['id'],
               constants.ONLINE,
               member_2['id'],
               constants.ERROR,)}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer',
            self.ovn_hm_lb.uuid,
            ('external_ids', member_status))
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
        status = self._test_hm_update_status(
            [self.ovn_hm_lb], member_2['id'], ip_2, '8081', 'online')
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
