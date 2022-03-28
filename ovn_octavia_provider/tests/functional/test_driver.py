# Copyright 2018 Red Hat, Inc.
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

from octavia_lib.api.drivers import exceptions as o_exceptions
from octavia_lib.common import constants as o_constants

from ovn_octavia_provider.tests.functional import base as ovn_base


class TestOvnOctaviaProviderDriver(ovn_base.TestOvnOctaviaBase):

    def test_loadbalancer(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._update_load_balancer_and_validate(lb_data, admin_state_up=False)
        self._update_load_balancer_and_validate(lb_data, admin_state_up=True)
        self._delete_load_balancer_and_validate(lb_data)
        # create load balance with admin state down
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'}, admin_state_up=False)
        self._delete_load_balancer_and_validate(lb_data)

    def test_create_lb_custom_network(self):
        self._create_load_balancer_custom_lr_ls_and_validate(
            admin_state_up=True, create_router=True,
            force_retry_ls_to_lr_assoc=False)

    def test_create_lb_custom_network_retry(self):
        self._create_load_balancer_custom_lr_ls_and_validate(
            admin_state_up=True, create_router=True,
            force_retry_ls_to_lr_assoc=True)

    def test_delete_lb_on_nonexisting_lb(self):
        # LoadBalancer doesnt exist anymore, so just create a model and delete
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '19.0.0.0/24'},
            only_model=True)
        self.ovn_driver.loadbalancer_delete(lb_data['model'])
        expected_status = {
            'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                               "provisioning_status": "DELETED",
                               "operating_status": "OFFLINE"}],
            'listeners': [],
            'pools': [],
            'members': [],
        }
        del lb_data['model']
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def test_pool(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._create_pool_and_validate(lb_data, "p_TCP_1", protocol='TCP')
        self._update_pool_and_validate(lb_data, "p_TCP_1")
        self._create_pool_and_validate(lb_data, "p_UDP_1", protocol='UDP')
        self._create_pool_and_validate(lb_data, "p_SCTP_1", protocol='SCTP')
        self._create_pool_and_validate(lb_data, "p_TCP_2", protocol='TCP')
        self._update_pool_and_validate(lb_data, "p_TCP_2",
                                       admin_state_up=False)
        self._update_pool_and_validate(lb_data, "p_TCP_2",
                                       admin_state_up=True)
        self._update_pool_and_validate(lb_data, "p_TCP_2",
                                       admin_state_up=False)
        self._create_pool_and_validate(lb_data, "p_UDP_2", protocol='UDP')
        self._create_pool_and_validate(lb_data, "p_SCTP_2", protocol='SCTP')
        self._delete_pool_and_validate(lb_data, "p_SCTP_1")
        self._delete_pool_and_validate(lb_data, "p_UDP_1")
        self._delete_pool_and_validate(lb_data, "p_TCP_1")
        self._delete_load_balancer_and_validate(lb_data)

    def test_member(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})

        # TCP Pool
        self._create_pool_and_validate(lb_data, "p_TCP", protocol='TCP')

        # UDP Pool
        self._create_pool_and_validate(lb_data, "p_UDP", protocol='UDP')

        # SCTP Pool
        self._create_pool_and_validate(lb_data, "p_SCTP", protocol='SCTP')

        pool_TCP_id = lb_data['pools'][0].pool_id
        pool_UDP_id = lb_data['pools'][1].pool_id
        pool_SCTP_id = lb_data['pools'][2].pool_id

        # Members for TCP Pool
        self._create_member_and_validate(
            lb_data, pool_TCP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')
        self._update_member_and_validate(lb_data, pool_TCP_id, "10.0.0.10")
        self._create_member_and_validate(
            lb_data, pool_TCP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.11')

        # Members for UDP Pool
        self._create_member_and_validate(
            lb_data, pool_UDP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')
        self._update_member_and_validate(lb_data, pool_UDP_id, "10.0.0.10")
        self._create_member_and_validate(
            lb_data, pool_UDP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.11')

        # Members for SCTP Pool
        self._create_member_and_validate(
            lb_data, pool_SCTP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')
        self._update_member_and_validate(lb_data, pool_SCTP_id, "10.0.0.10")
        self._create_member_and_validate(
            lb_data, pool_SCTP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.11')

        # Disable loadbalancer
        self._update_load_balancer_and_validate(lb_data,
                                                admin_state_up=False)
        # Enable loadbalancer back
        self._update_load_balancer_and_validate(lb_data,
                                                admin_state_up=True)

        # Delete members from TCP Pool
        self._delete_member_and_validate(lb_data, pool_TCP_id,
                                         lb_data['vip_net_info'][0],
                                         '10.0.0.10')
        self._delete_member_and_validate(lb_data, pool_TCP_id,
                                         lb_data['vip_net_info'][0],
                                         '10.0.0.11')
        # Add again member to TCP Pool
        self._create_member_and_validate(
            lb_data, pool_TCP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')

        # Create new networks and add member to TCP pool from it.
        net20_info = self._create_net('net20', '20.0.0.0/24')
        net20 = net20_info[0]
        subnet20 = net20_info[1]
        self._create_member_and_validate(lb_data, pool_TCP_id, subnet20, net20,
                                         '20.0.0.4')
        self._create_member_and_validate(lb_data, pool_TCP_id, subnet20, net20,
                                         '20.0.0.6')
        net30_info = self._create_net('net30', '30.0.0.0/24')
        net30 = net30_info[0]
        subnet30 = net30_info[1]
        self._create_member_and_validate(lb_data, pool_TCP_id, subnet30, net30,
                                         '30.0.0.6')
        self._delete_member_and_validate(lb_data, pool_TCP_id, net20,
                                         '20.0.0.6')

        # Deleting the pool should also delete the members.
        self._delete_pool_and_validate(lb_data, "p_TCP")

        # Delete the whole LB.
        self._delete_load_balancer_and_validate(lb_data)

    def test_member_no_subnet(self):
        self._o_driver_lib.get_pool.return_value = None

        # Test creating Member without subnet and unknown pool
        m_member = self._create_member_model('pool_from_nowhere',
                                             None,
                                             '30.0.0.7', 80)
        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self.ovn_driver.member_create, m_member)

        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})

        # TCP Pool
        self._create_pool_and_validate(lb_data, "p_TCP", protocol='TCP')
        pool_TCP_id = lb_data['pools'][0].pool_id

        self._o_driver_lib.get_pool.return_value = lb_data['pools'][0]
        self._o_driver_lib.get_loadbalancer.return_value = lb_data['model']

        # Test deleting a member without subnet
        self._create_member_and_validate(
            lb_data, pool_TCP_id, None,
            lb_data['vip_net_info'][0], '10.0.0.10',
            expected_subnet=lb_data['vip_net_info'][1])
        self._delete_member_and_validate(
            lb_data, pool_TCP_id, lb_data['vip_net_info'][0],
            '10.0.0.10', remove_subnet_id=True)

        # Test update member without subnet
        self._create_member_and_validate(
            lb_data, pool_TCP_id, None,
            lb_data['vip_net_info'][0], '10.0.0.10',
            expected_subnet=lb_data['vip_net_info'][1])
        self._update_member_and_validate(
            lb_data, pool_TCP_id, "10.0.0.10", remove_subnet_id=True)

        # Test creating a Member without subnet but with pool
        self._create_member_and_validate(
            lb_data, pool_TCP_id, None,
            lb_data['vip_net_info'][0], '10.0.0.11',
            expected_subnet=lb_data['vip_net_info'][1])

        # Deleting the pool should also delete the members.
        self._delete_pool_and_validate(lb_data, "p_TCP")

        # Delete the whole LB.
        self._delete_load_balancer_and_validate(lb_data)

    def test_listener(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._create_pool_and_validate(lb_data, "p_TCP", protocol='TCP')
        self._create_pool_and_validate(lb_data, "p_UDP", protocol='UDP')
        self._create_pool_and_validate(lb_data, "p_SCTP", protocol='SCTP')
        pool_TCP_id = lb_data['pools'][0].pool_id
        pool_UDP_id = lb_data['pools'][1].pool_id
        pool_SCTP_id = lb_data['pools'][2].pool_id
        net_info = self._create_net('net1', '20.0.0.0/24')

        # Create member in TCP pool
        self._create_member_and_validate(
            lb_data, pool_TCP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.4')
        self._create_member_and_validate(lb_data, pool_TCP_id,
                                         net_info[1], net_info[0], '20.0.0.4')

        # Create member in UDP pool
        self._create_member_and_validate(
            lb_data, pool_UDP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.4')
        self._create_member_and_validate(lb_data, pool_UDP_id,
                                         net_info[1], net_info[0], '20.0.0.4')

        # Create member in SCTP pool
        self._create_member_and_validate(
            lb_data, pool_SCTP_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.4')
        self._create_member_and_validate(lb_data, pool_SCTP_id,
                                         net_info[1], net_info[0], '20.0.0.4')

        # Play around first listener linked to TCP pool
        self._create_listener_and_validate(
            lb_data, pool_TCP_id, 80, protocol='TCP')
        self._update_listener_and_validate(lb_data, protocol_port=80)
        self._update_listener_and_validate(
            lb_data, protocol_port=80, admin_state_up=True)
        self._update_listener_and_validate(
            lb_data, protocol_port=80, admin_state_up=False)
        self._update_listener_and_validate(
            lb_data, protocol_port=80, admin_state_up=True)
        self._create_listener_and_validate(
            lb_data, pool_TCP_id, protocol_port=82, protocol='TCP')

        # Play around second listener linked to UDP pool
        self._create_listener_and_validate(
            lb_data, pool_UDP_id, 53, protocol='UDP')
        self._update_listener_and_validate(lb_data, 53, protocol='UDP')
        self._update_listener_and_validate(
            lb_data, protocol_port=53, protocol='UDP', admin_state_up=True)
        self._update_listener_and_validate(
            lb_data, protocol_port=53, protocol='UDP', admin_state_up=False)
        self._update_listener_and_validate(
            lb_data, protocol_port=53, protocol='UDP', admin_state_up=True)
        self._create_listener_and_validate(
            lb_data, pool_UDP_id, protocol_port=21, protocol='UDP')

        # Play around third listener linked to SCTP pool
        self._create_listener_and_validate(
            lb_data, pool_SCTP_id, 8081, protocol='SCTP')
        self._update_listener_and_validate(lb_data, 8081, protocol='SCTP')
        self._update_listener_and_validate(
            lb_data, protocol_port=8081, protocol='SCTP', admin_state_up=True)
        self._update_listener_and_validate(
            lb_data, protocol_port=8081, protocol='SCTP', admin_state_up=False)
        self._update_listener_and_validate(
            lb_data, protocol_port=8081, protocol='SCTP', admin_state_up=True)
        self._create_listener_and_validate(
            lb_data, pool_SCTP_id, protocol_port=8082, protocol='SCTP')

        # Delete listeners linked to TCP pool
        self._delete_listener_and_validate(
            lb_data, protocol_port=82, protocol='TCP')
        self._delete_listener_and_validate(
            lb_data, protocol_port=80, protocol='TCP')
        # Delete TCP pool members
        self._delete_member_and_validate(lb_data, pool_TCP_id,
                                         net_info[0], '20.0.0.4')
        self._delete_member_and_validate(lb_data, pool_TCP_id,
                                         lb_data['vip_net_info'][0],
                                         '10.0.0.4')
        # Delete empty, TCP pool
        self._delete_pool_and_validate(lb_data, "p_TCP")
        # Delete the rest
        self._delete_load_balancer_and_validate(lb_data)

    def _test_cascade_delete(self, pool=True, listener=True, member=True):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        if pool:
            self._create_pool_and_validate(lb_data, "p_TCP", protocol='TCP')
            self._create_pool_and_validate(lb_data, "p_UDP", protocol='UDP')
            self._create_pool_and_validate(lb_data, "p_SCTP", protocol='SCTP')
            pool_TCP_id = lb_data['pools'][0].pool_id
            pool_UDP_id = lb_data['pools'][1].pool_id
            pool_SCTP_id = lb_data['pools'][2].pool_id
            if member:
                self._create_member_and_validate(
                    lb_data, pool_TCP_id, lb_data['vip_net_info'][1],
                    lb_data['vip_net_info'][0], '10.0.0.10')
                self._create_member_and_validate(
                    lb_data, pool_UDP_id, lb_data['vip_net_info'][1],
                    lb_data['vip_net_info'][0], '10.0.0.10')
                self._create_member_and_validate(
                    lb_data, pool_SCTP_id, lb_data['vip_net_info'][1],
                    lb_data['vip_net_info'][0], '10.0.0.10')
            if listener:
                self._create_listener_and_validate(
                    lb_data, pool_TCP_id, protocol_port=80, protocol='TCP')
                self._create_listener_and_validate(
                    lb_data, pool_UDP_id, protocol_port=53, protocol='UDP')
                self._create_listener_and_validate(
                    lb_data, pool_SCTP_id, protocol_port=8081, protocol='SCTP')

        self._delete_load_balancer_and_validate(lb_data, cascade=True)

    def test_lb_listener_pools_cascade(self):
        self._test_cascade_delete(member=False)

    def test_lb_pool_cascade(self):
        self._test_cascade_delete(member=False, listener=False)

    def test_cascade_delete(self):
        self._test_cascade_delete()

    def test_for_unsupported_options(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})

        m_pool = self._create_pool_model(lb_data['model'].loadbalancer_id,
                                         'lb1')
        m_pool.protocol = o_constants.PROTOCOL_HTTP
        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self.ovn_driver.pool_create, m_pool)

        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self.ovn_driver.loadbalancer_failover,
                          lb_data['model'].loadbalancer_id)

        m_listener = self._create_listener_model(
            lb_data['model'].loadbalancer_id, m_pool.pool_id, 80)
        m_listener.protocol = o_constants.PROTOCOL_HTTP
        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self.ovn_driver.listener_create, m_listener)
        self._create_listener_and_validate(lb_data)
        self._delete_load_balancer_and_validate(lb_data)

    def test_lb_listener_pool_workflow(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._create_listener_and_validate(lb_data)
        self._create_pool_and_validate(
            lb_data, "p1", listener_id=lb_data['listeners'][0].listener_id)
        self._delete_pool_and_validate(
            lb_data, "p1", listener_id=lb_data['listeners'][0].listener_id)
        self._delete_listener_and_validate(lb_data)
        self._delete_load_balancer_and_validate(lb_data)

    def test_lb_member_batch_update(self):
        # Create a LoadBalancer
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        # Create a pool
        self._create_pool_and_validate(lb_data, "p1")
        pool_id = lb_data['pools'][0].pool_id
        # Create Member-1 and associate it with lb_data
        self._create_member_and_validate(
            lb_data, pool_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')
        # Create Member-2
        m_member = self._create_member_model(pool_id,
                                             lb_data['vip_net_info'][1],
                                             '10.0.0.12')
        # Update ovn's Logical switch reference
        self._update_ls_refs(lb_data, lb_data['vip_net_info'][0])
        lb_data['pools'][0].members.append(m_member)
        # Add a new member to the LB
        members = [m_member] + [lb_data['pools'][0].members[0]]
        self._update_members_in_batch_and_validate(lb_data, pool_id, members)
        # Deleting one member, while keeping the other member available
        self._update_members_in_batch_and_validate(lb_data, pool_id,
                                                   [m_member])
        self._delete_load_balancer_and_validate(lb_data)
