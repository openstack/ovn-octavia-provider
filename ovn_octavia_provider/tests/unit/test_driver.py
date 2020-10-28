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

from octavia_lib.api.drivers import data_models
from octavia_lib.api.drivers import exceptions
from octavia_lib.common import constants
from oslo_utils import uuidutils

from ovn_octavia_provider.common import clients
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider import driver as ovn_driver
from ovn_octavia_provider import helper as ovn_helper
from ovn_octavia_provider.tests.unit import base as ovn_base


class TestOvnProviderDriver(ovn_base.TestOvnOctaviaBase):

    def setUp(self):
        super(TestOvnProviderDriver, self).setUp()
        self.driver = ovn_driver.OvnProviderDriver()
        add_req_thread = mock.patch.object(ovn_helper.OvnProviderHelper,
                                           'add_request')
        self.member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        self.ovn_lb = mock.MagicMock()
        self.ovn_lb.name = 'foo_ovn_lb'
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
            'pool_%s' % self.pool_id: self.member_line,
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        self.mock_add_request = add_req_thread.start()
        self.project_id = uuidutils.generate_uuid()

        self.fail_member = data_models.Member(
            address='198.51.100.4',
            admin_state_up=True,
            member_id=self.member_id,
            monitor_address="100.200.200.100",
            monitor_port=66,
            name='Amazin',
            pool_id=self.pool_id,
            protocol_port=99,
            subnet_id=self.member_subnet_id,
            weight=55)
        self.ref_member = data_models.Member(
            address='198.52.100.4',
            admin_state_up=True,
            member_id=self.member_id,
            monitor_address=data_models.Unset,
            monitor_port=data_models.Unset,
            name='Amazing',
            pool_id=self.pool_id,
            protocol_port=99,
            subnet_id=self.member_subnet_id,
            weight=55)
        self.update_member = data_models.Member(
            address='198.53.100.4',
            admin_state_up=False,
            member_id=self.member_id,
            monitor_address=data_models.Unset,
            monitor_port=data_models.Unset,
            name='Amazin',
            pool_id=self.pool_id,
            protocol_port=99,
            subnet_id=self.member_subnet_id,
            weight=55)
        self.ref_update_pool = data_models.Pool(
            admin_state_up=False,
            description='pool',
            name='Peter',
            lb_algorithm=constants.LB_ALGORITHM_SOURCE_IP_PORT,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            pool_id=self.pool_id,
            protocol='TCP',
            session_persistence={'type': 'fix'})
        self.ref_pool = data_models.Pool(
            admin_state_up=True,
            description='pool',
            name='Peter',
            lb_algorithm=constants.LB_ALGORITHM_SOURCE_IP_PORT,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            pool_id=self.pool_id,
            protocol='TCP',
            session_persistence={'type': 'fix'})
        self.ref_http_pool = data_models.Pool(
            admin_state_up=True,
            description='pool',
            lb_algorithm=constants.LB_ALGORITHM_SOURCE_IP_PORT,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            name='Groot',
            pool_id=self.pool_id,
            protocol='HTTP',
            session_persistence={'type': 'fix'})
        self.ref_lc_pool = data_models.Pool(
            admin_state_up=True,
            description='pool',
            lb_algorithm=constants.LB_ALGORITHM_LEAST_CONNECTIONS,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            name='Groot',
            pool_id=self.pool_id,
            protocol='HTTP',
            session_persistence={'type': 'fix'})
        self.ref_listener = data_models.Listener(
            admin_state_up=False,
            connection_limit=5,
            default_pool=self.ref_pool,
            default_pool_id=self.pool_id,
            listener_id=self.listener_id,
            loadbalancer_id=self.loadbalancer_id,
            name='listener',
            protocol='TCP',
            protocol_port=42)
        self.ref_listener_udp = data_models.Listener(
            admin_state_up=False,
            connection_limit=5,
            default_pool=self.ref_pool,
            default_pool_id=self.pool_id,
            listener_id=self.listener_id,
            loadbalancer_id=self.loadbalancer_id,
            name='listener',
            protocol='UDP',
            protocol_port=42)
        self.fail_listener = data_models.Listener(
            admin_state_up=False,
            connection_limit=5,
            default_pool=self.ref_pool,
            default_pool_id=self.pool_id,
            listener_id=self.listener_id,
            loadbalancer_id=self.loadbalancer_id,
            name='listener',
            protocol='http',
            protocol_port=42)
        self.ref_lb0 = data_models.LoadBalancer(
            admin_state_up=False,
            listeners=[self.ref_listener],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb0',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id)
        self.ref_lb1 = data_models.LoadBalancer(
            admin_state_up=True,
            listeners=[self.ref_listener],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb1',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id)
        mock.patch.object(
            ovn_helper.OvnProviderHelper, '_find_ovn_lbs',
            side_effect=lambda x, protocol=None:
                self.ovn_lb if protocol else [self.ovn_lb]).start()
        self.mock_find_lb_pool_key = mock.patch.object(
            ovn_helper.OvnProviderHelper,
            '_find_ovn_lb_with_pool_key',
            return_value=self.ovn_lb).start()

    def test__ip_version_differs(self):
        self.assertFalse(self.driver._ip_version_differs(self.ref_member))
        self.ref_member.address = 'fc00::1'
        self.assertTrue(self.driver._ip_version_differs(self.ref_member))

    def test__ip_version_differs_pool_disabled(self):
        self.mock_find_lb_pool_key.side_effect = [None, self.ovn_lb]
        self.driver._ip_version_differs(self.ref_member)
        self.mock_find_lb_pool_key.assert_has_calls([
            mock.call('pool_%s' % self.pool_id),
            mock.call('pool_%s:D' % self.pool_id)])

    def test_member_create(self):
        info = {'id': self.ref_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'subnet_id': self.ref_member.subnet_id,
                'admin_state_up': self.ref_member.admin_state_up}
        expected_dict = {'type': ovn_const.REQ_TYPE_MEMBER_CREATE,
                         'info': info}
        info_dvr = {
            'id': self.ref_member.member_id,
            'address': self.ref_member.address,
            'pool_id': self.ref_member.pool_id,
            'subnet_id': self.ref_member.subnet_id,
            'action': ovn_const.REQ_INFO_MEMBER_ADDED}
        expected_dict_dvr = {
            'type': ovn_const.REQ_TYPE_HANDLE_MEMBER_DVR,
            'info': info_dvr}
        self.driver.member_create(self.ref_member)
        expected = [
            mock.call(expected_dict),
            mock.call(expected_dict_dvr)]
        self.mock_add_request.assert_has_calls(expected)

    def test_member_create_failure(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.fail_member)

    def test_member_create_different_ip_version(self):
        self.ref_member.address = 'fc00::1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)

    def test_member_create_different_ip_version_lb_disable(self):
        self.driver._ovn_helper._find_ovn_lb_with_pool_key.side_effect = [
            None, self.ovn_lb]
        self.ref_member.address = 'fc00::1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)
        self.driver._ovn_helper._find_ovn_lb_with_pool_key.assert_has_calls(
            [mock.call('pool_%s' % self.pool_id),
             mock.call('pool_%s%s' % (self.pool_id, ':D'))])

    def test_member_create_no_subnet_provided(self):
        self.ref_member.subnet_id = data_models.UnsetType()
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)
        self.ref_member.subnet_id = None
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)

    def test_member_create_monitor_opts(self):
        self.ref_member.monitor_address = '172.20.20.1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)
        self.ref_member.monitor_port = '80'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)

    def test_member_create_no_set_admin_state_up(self):
        self.ref_member.admin_state_up = data_models.UnsetType()
        info = {'id': self.ref_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'subnet_id': self.ref_member.subnet_id,
                'admin_state_up': True}
        expected_dict = {'type': ovn_const.REQ_TYPE_MEMBER_CREATE,
                         'info': info}
        expected_dict_dvr = {'type': ovn_const.REQ_TYPE_HANDLE_MEMBER_DVR,
                             'info': mock.ANY}
        expected = [
            mock.call(expected_dict),
            mock.call(expected_dict_dvr)]
        self.driver.member_create(self.ref_member)
        self.mock_add_request.assert_has_calls(expected)

    def test_member_update(self):
        info = {'id': self.update_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'admin_state_up': self.update_member.admin_state_up,
                'old_admin_state_up': self.ref_member.admin_state_up,
                'subnet_id': self.ref_member.subnet_id}
        expected_dict = {'type': ovn_const.REQ_TYPE_MEMBER_UPDATE,
                         'info': info}
        self.driver.member_update(self.ref_member, self.update_member)
        self.mock_add_request.assert_called_once_with(expected_dict)

    @mock.patch.object(ovn_driver.OvnProviderDriver, '_ip_version_differs')
    def test_member_update_no_ip_addr(self, mock_ip_differs):
        self.update_member.address = None
        self.driver.member_update(self.ref_member, self.update_member)
        mock_ip_differs.assert_not_called()

    def test_member_batch_update(self):
        self.driver.member_batch_update(self.pool_id,
                                        [self.ref_member, self.update_member])
        self.assertEqual(self.mock_add_request.call_count, 3)

    def test_member_batch_update_no_members(self):
        pool_key = 'pool_%s' % self.pool_id
        ovn_lb = copy.copy(self.ovn_lb)
        ovn_lb.external_ids[pool_key] = []
        self.mock_find_lb_pool_key.return_value = ovn_lb
        self.driver.member_batch_update(self.pool_id,
                                        [self.ref_member, self.update_member])
        self.assertEqual(self.mock_add_request.call_count, 2)

    def test_member_batch_update_skipped_monitor(self):
        self.ref_member.monitor_address = '10.11.1.1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_batch_update,
                          self.pool_id,
                          [self.ref_member])

    def test_member_batch_update_skipped_mixed_ip(self):
        self.ref_member.address = 'fc00::1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_batch_update,
                          self.pool_id,
                          [self.ref_member])

    def test_member_batch_update_unset_admin_state_up(self):
        self.ref_member.admin_state_up = data_models.UnsetType()
        self.driver.member_batch_update(self.pool_id, [self.ref_member])
        self.assertEqual(self.mock_add_request.call_count, 2)

    def test_member_batch_update_missing_subnet_id(self):
        self.ref_member.subnet_id = None
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_batch_update,
                          self.pool_id, [self.ref_member])

    def test_member_update_failure(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_update, self.ref_member,
                          self.fail_member)

    def test_member_update_different_ip_version(self):
        self.ref_member.address = 'fc00::1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_update, self.ref_member,
                          self.ref_member)

    def test_member_delete(self):
        info = {'id': self.ref_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'subnet_id': self.ref_member.subnet_id}
        expected_dict = {'type': ovn_const.REQ_TYPE_MEMBER_DELETE,
                         'info': info}
        info_dvr = {
            'id': self.ref_member.member_id,
            'address': self.ref_member.address,
            'pool_id': self.ref_member.pool_id,
            'subnet_id': self.ref_member.subnet_id,
            'action': ovn_const.REQ_INFO_MEMBER_DELETED}
        expected_dict_dvr = {
            'type': ovn_const.REQ_TYPE_HANDLE_MEMBER_DVR,
            'info': info_dvr}
        self.driver.member_delete(self.ref_member)
        expected = [
            mock.call(expected_dict),
            mock.call(expected_dict_dvr)]
        self.mock_add_request.assert_has_calls(expected)

    def test_listener_create(self):
        info = {'id': self.ref_listener.listener_id,
                'protocol': self.ref_listener.protocol,
                'protocol_port': self.ref_listener.protocol_port,
                'default_pool_id': self.ref_listener.default_pool_id,
                'admin_state_up': self.ref_listener.admin_state_up,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        expected_dict = {'type': ovn_const.REQ_TYPE_LISTENER_CREATE,
                         'info': info}
        self.driver.listener_create(self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_listener_create_unset_admin_state_up(self):
        self.ref_listener.admin_state_up = data_models.UnsetType()
        info = {'id': self.ref_listener.listener_id,
                'protocol': self.ref_listener.protocol,
                'protocol_port': self.ref_listener.protocol_port,
                'default_pool_id': self.ref_listener.default_pool_id,
                'admin_state_up': True,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        expected_dict = {'type': ovn_const.REQ_TYPE_LISTENER_CREATE,
                         'info': info}
        self.driver.listener_create(self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_listener_create_unsupported_protocol(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.listener_create, self.fail_listener)

    def test_listener_create_multiple_protocols(self):
        self.ovn_lb.protocol = ['tcp']
        info = {'id': self.ref_listener.listener_id,
                'protocol': self.ref_listener.protocol,
                'protocol_port': self.ref_listener.protocol_port,
                'default_pool_id': self.ref_listener.default_pool_id,
                'admin_state_up': self.ref_listener.admin_state_up,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        expected_dict = {'type': ovn_const.REQ_TYPE_LISTENER_CREATE,
                         'info': info}
        self.driver.listener_create(self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)
        self.ovn_lb.protocol = ['UDP']
        info['protocol'] = 'UDP'
        expected_dict = {'type': ovn_const.REQ_TYPE_LISTENER_CREATE,
                         'info': info}
        self.driver.listener_create(self.ref_listener)

    def test_listener_update(self):
        info = {'id': self.ref_listener.listener_id,
                'protocol_port': self.ref_listener.protocol_port,
                'protocol': self.ref_pool.protocol,
                'admin_state_up': self.ref_listener.admin_state_up,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        if self.ref_listener.default_pool_id:
            info['default_pool_id'] = self.ref_listener.default_pool_id
        expected_dict = {'type': ovn_const.REQ_TYPE_LISTENER_UPDATE,
                         'info': info}
        self.driver.listener_update(self.ref_listener, self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_listener_delete(self):
        info = {'id': self.ref_listener.listener_id,
                'protocol_port': self.ref_listener.protocol_port,
                'protocol': self.ref_pool.protocol,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        expected_dict = {'type': ovn_const.REQ_TYPE_LISTENER_DELETE,
                         'info': info}
        self.driver.listener_delete(self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_create(self):
        info = {'id': self.ref_lb0.loadbalancer_id,
                'vip_address': self.ref_lb0.vip_address,
                'vip_network_id': self.ref_lb0.vip_network_id,
                'admin_state_up': self.ref_lb0.admin_state_up}
        expected_dict = {'type': ovn_const.REQ_TYPE_LB_CREATE,
                         'info': info}
        self.driver.loadbalancer_create(self.ref_lb0)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_create_unset_admin_state_up(self):
        self.ref_lb0.admin_state_up = data_models.UnsetType()
        info = {'id': self.ref_lb0.loadbalancer_id,
                'vip_address': self.ref_lb0.vip_address,
                'vip_network_id': self.ref_lb0.vip_network_id,
                'admin_state_up': True}
        expected_dict = {'type': ovn_const.REQ_TYPE_LB_CREATE,
                         'info': info}
        self.driver.loadbalancer_create(self.ref_lb0)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_update(self):
        info = {'id': self.ref_lb1.loadbalancer_id,
                'admin_state_up': self.ref_lb1.admin_state_up}
        expected_dict = {'type': ovn_const.REQ_TYPE_LB_UPDATE,
                         'info': info}
        self.driver.loadbalancer_update(self.ref_lb0, self.ref_lb1)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_delete(self):
        info = {'id': self.ref_lb0.loadbalancer_id,
                'cascade': False}
        expected_dict = {'type': ovn_const.REQ_TYPE_LB_DELETE,
                         'info': info}
        self.driver.loadbalancer_delete(self.ref_lb1)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_failover(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.loadbalancer_failover,
                          self.ref_lb0.loadbalancer_id)

    def test_pool_create_unsupported_protocol(self):
        self.ref_pool.protocol = 'HTTP'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.pool_create, self.ref_pool)

    def test_pool_create_leastcount_algo(self):
        self.ref_pool.lb_algorithm = constants.LB_ALGORITHM_LEAST_CONNECTIONS
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.pool_create, self.ref_pool)

    def test_pool_create(self):
        info = {'id': self.ref_pool.pool_id,
                'loadbalancer_id': self.ref_pool.loadbalancer_id,
                'listener_id': self.ref_pool.listener_id,
                'protocol': self.ref_pool.protocol,
                'lb_algorithm': constants.LB_ALGORITHM_SOURCE_IP_PORT,
                'admin_state_up': self.ref_pool.admin_state_up}
        expected_dict = {'type': ovn_const.REQ_TYPE_POOL_CREATE,
                         'info': info}
        self.driver.pool_create(self.ref_pool)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_pool_create_unset_admin_state_up(self):
        self.ref_pool.admin_state_up = data_models.UnsetType()
        info = {'id': self.ref_pool.pool_id,
                'loadbalancer_id': self.ref_pool.loadbalancer_id,
                'protocol': self.ref_pool.protocol,
                'lb_algorithm': constants.LB_ALGORITHM_SOURCE_IP_PORT,
                'listener_id': self.ref_pool.listener_id,
                'admin_state_up': True}
        expected_dict = {'type': ovn_const.REQ_TYPE_POOL_CREATE,
                         'info': info}
        self.driver.pool_create(self.ref_pool)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_pool_delete(self):
        # Pretent we don't have members
        self.ref_pool.members = []
        info = {'id': self.ref_pool.pool_id,
                'protocol': self.ref_pool.protocol,
                'loadbalancer_id': self.ref_pool.loadbalancer_id}
        expected = {'type': ovn_const.REQ_TYPE_POOL_DELETE,
                    'info': info}
        self.driver.pool_delete(self.ref_pool)
        self.mock_add_request.assert_called_once_with(expected)

    def test_pool_delete_with_members(self):
        info = {'id': self.ref_pool.pool_id,
                'protocol': self.ref_pool.protocol,
                'loadbalancer_id': self.ref_pool.loadbalancer_id}
        expected = {'type': ovn_const.REQ_TYPE_POOL_DELETE,
                    'info': info}
        info_member = {'id': self.ref_member.member_id,
                       'pool_id': self.ref_member.pool_id,
                       'subnet_id': self.ref_member.subnet_id,
                       'protocol_port': self.ref_member.protocol_port,
                       'address': self.ref_member.address}
        expected_members = {
            'type': ovn_const.REQ_TYPE_MEMBER_DELETE,
            'info': info_member}
        expected_members_dvr = {
            'type': ovn_const.REQ_TYPE_HANDLE_MEMBER_DVR,
            'info': mock.ANY}
        calls = [mock.call(expected_members),
                 mock.call(expected_members_dvr),
                 mock.call(expected)]
        self.driver.pool_delete(self.ref_pool)
        self.mock_add_request.assert_has_calls(calls)

    def test_pool_update(self):
        info = {'id': self.ref_update_pool.pool_id,
                'loadbalancer_id': self.ref_update_pool.loadbalancer_id,
                'protocol': self.ref_pool.protocol,
                'admin_state_up': self.ref_update_pool.admin_state_up}
        expected_dict = {'type': ovn_const.REQ_TYPE_POOL_UPDATE,
                         'info': info}
        self.driver.pool_update(self.ref_pool, self.ref_update_pool)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_create_vip_port(self):
        with mock.patch.object(clients, 'get_neutron_client'):
            port_dict = self.driver.create_vip_port(self.loadbalancer_id,
                                                    self.project_id,
                                                    self.vip_dict)
            self.assertIsNotNone(port_dict.pop('vip_address', None))
            self.assertIsNotNone(port_dict.pop('vip_port_id', None))
            # The network_driver function is mocked, therefore the
            # created port vip_address and vip_port_id are also mocked.
            # Check if it exists and move on.
            # The finally output is include vip_address, vip_port_id,
            # vip_network_id and vip_subnet_id.
            for key, value in port_dict.items():
                self.assertEqual(value, self.vip_output[key])

    def test_create_vip_port_exception(self):
        with mock.patch.object(clients, 'get_neutron_client',
                               side_effect=[RuntimeError]):
            self.assertRaises(
                exceptions.DriverError,
                self.driver.create_vip_port,
                self.loadbalancer_id,
                self.project_id,
                self.vip_dict)
