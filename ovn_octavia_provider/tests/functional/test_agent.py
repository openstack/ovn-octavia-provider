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

import atexit
import multiprocessing as mp

from neutron.common import utils as n_utils
from oslo_utils import uuidutils

from ovn_octavia_provider import agent as ovn_agent
from ovn_octavia_provider.common import config as ovn_config
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider import event as ovn_event
from ovn_octavia_provider import helper as ovn_helper
from ovn_octavia_provider.ovsdb import impl_idl_ovn
from ovn_octavia_provider.tests.functional import base as ovn_base


class TestOvnOctaviaProviderAgent(ovn_base.TestOvnOctaviaBase):

    def setUp(self):
        super().setUp()
        self._initialize_ovn_da()

    def _initialize_ovn_da(self):
        # NOTE(mjozefcz): In theory this is separate process
        # with IDL running, but to make it easier for now
        # we can initialize this IDL here instead spawning
        # another process.
        ovn_config.register_opts()
        da_helper = ovn_helper.OvnProviderHelper()
        events = [ovn_event.LogicalRouterPortEvent(da_helper),
                  ovn_event.LogicalSwitchPortUpdateEvent(da_helper)]
        ovn_nb_idl_for_events = impl_idl_ovn.OvnNbIdlForLb(
            event_lock_name='func_test')
        ovn_nb_idl_for_events.notify_handler.watch_events(events)
        ovn_nb_idl_for_events.start()
        atexit.register(da_helper.shutdown)

    def _test_lrp_event_handler(self, cascade=False):
        # Create Network N1 on router R1 and LBA on N1
        network_N1 = self._create_net('N' + uuidutils.generate_uuid()[:4])
        network_id, subnet_id = self._create_subnet_from_net(
            network_N1, '10.0.0.0/24')
        port_address, port_id = self._create_port_on_network(network_N1)

        # Create Network N2, connect it to R1
        network_N2 = self._create_net('N' + uuidutils.generate_uuid()[:4])
        network_id2, subnet2_id = self._create_subnet_from_net(
            network_N2, '10.0.1.0/24')
        port_address2, port_id2 = self._create_port_on_network(network_N2)

        # Create Network N3
        network_N3 = self._create_net('N' + uuidutils.generate_uuid()[:4])
        network_id3, subnet3_id = self._create_subnet_from_net(
            network_N3, '10.0.2.0/24')
        port_address3, port_id3 = self._create_port_on_network(network_N3)

        r1_id = self._create_router('r' + uuidutils.generate_uuid()[:4])
        self._attach_router_to_subnet(subnet_id, r1_id)
        self._attach_router_to_subnet(subnet2_id, r1_id)

        lba_data = self._create_load_balancer_and_validate(
            network_id, subnet_id, port_address, port_id, router_id=r1_id)

        # Check if LBA exists in N2 LS
        n_utils.wait_until_true(
            lambda: self._is_lb_associated_to_ls(
                lba_data['model'].loadbalancer_id,
                ovn_const.LR_REF_KEY_HEADER + network_id2),
            timeout=10)

        lbb_data = self._create_load_balancer_and_validate(
            network_id3, subnet3_id, port_address3, port_id3, multiple_lb=True)
        # Add N3 to R1
        self.l3_plugin.add_router_interface(
            self.context, lba_data[
                ovn_const.LB_EXT_IDS_LR_REF_KEY][
                    len(ovn_const.LR_REF_KEY_HEADER):],
            {'subnet_id': lbb_data['vip_net_info'][1]})

        # Check LBB exists on R1
        n_utils.wait_until_true(
            lambda: self._is_lb_associated_to_lr(
                lbb_data['model'].loadbalancer_id,
                lba_data[ovn_const.LB_EXT_IDS_LR_REF_KEY]),
            timeout=10)
        # Check LBA connected to N3
        n_utils.wait_until_true(
            lambda: self._is_lb_associated_to_ls(
                lba_data['model'].loadbalancer_id,
                ovn_const.LR_REF_KEY_HEADER + lbb_data['vip_net_info'][0]),
            timeout=10)
        # Check LBB connected to N1
        n_utils.wait_until_true(
            lambda: self._is_lb_associated_to_ls(
                lbb_data['model'].loadbalancer_id,
                ovn_const.LR_REF_KEY_HEADER + lba_data['vip_net_info'][0]),
            timeout=10)
        # Check LBB connected to N2
        n_utils.wait_until_true(
            lambda: self._is_lb_associated_to_ls(
                lbb_data['model'].loadbalancer_id,
                ovn_const.LR_REF_KEY_HEADER + network_id2),
            timeout=10)

        lbb_id = lbb_data['model'].loadbalancer_id
        if not cascade:
            # N3 removed from R1
            self.l3_plugin.remove_router_interface(
                self.context, lba_data[
                    ovn_const.LB_EXT_IDS_LR_REF_KEY][
                        len(ovn_const.LR_REF_KEY_HEADER):],
                {'subnet_id': lbb_data['vip_net_info'][1]})
        else:
            # Delete LBB Cascade
            self._delete_load_balancer_and_validate(lbb_data, cascade=True,
                                                    multiple_lb=True)

        # Check LBB doesn't exists on R1
        n_utils.wait_until_true(
            lambda: not self._is_lb_associated_to_lr(
                lbb_id, lba_data[ovn_const.LB_EXT_IDS_LR_REF_KEY]),
            timeout=10)
        # Check LBB not connected to N1
        n_utils.wait_until_true(
            lambda: not self._is_lb_associated_to_ls(
                lbb_id,
                ovn_const.LR_REF_KEY_HEADER + lba_data['vip_net_info'][0]),
            timeout=10)
        # Check LBB not connected to N2
        n_utils.wait_until_true(
            lambda: not self._is_lb_associated_to_ls(
                lbb_id, ovn_const.LR_REF_KEY_HEADER + network_id2),
            timeout=10)

    def test_lrp_event_handler_with_interface_delete(self):
        self._test_lrp_event_handler()

    def test_lrp_event_handler_with_loadbalancer_cascade_delete(self):
        self._test_lrp_event_handler(cascade=True)

    def test_lrp_event_handler_lrp_with_external_gateway(self):
        # Create Network N1 on router R1 and LBA on N1
        network_N1 = self._create_net('N' + uuidutils.generate_uuid()[:4])
        network_id, subnet_id = self._create_subnet_from_net(
            network_N1, '10.0.0.0/24')
        port_address, port_id = self._create_port_on_network(network_N1)
        r1_id = self._create_router('r' + uuidutils.generate_uuid()[:4])
        self._attach_router_to_subnet(subnet_id, r1_id)

        lba_data = self._create_load_balancer_and_validate(
            network_id, subnet_id, port_address, port_id, router_id=r1_id)

        # Create provider network N2, connect it to R1
        provider_net, provider_subnet = self._create_provider_network()
        self.l3_plugin.update_router(
            self.context,
            r1_id,
            {'router': {
                'id': r1_id,
                'external_gateway_info': {
                    'enable_snat': True,
                    'network_id': provider_net['network']['id'],
                    'external_fixed_ips': [
                        {'ip_address': '100.0.0.2',
                         'subnet_id': provider_subnet['subnet']['id']}]}}})

        # Check if LBA doesn't exist in provider network LS
        n_utils.wait_until_true(
            lambda: not self._is_lb_associated_to_ls(
                lba_data['model'].loadbalancer_id,
                ovn_const.LR_REF_KEY_HEADER + provider_net['network']['id']),
            timeout=10)

    def test_fip_on_lb_vip(self):
        """This test checks if FIP on LB VIP is configured.

           This test validates if Load_Balancer VIP field
           consist Floating IP address that is configured
           on LB VIP port.
        """
        network_N1 = self._create_net('N' + uuidutils.generate_uuid()[:4])
        network_id, subnet_id = self._create_subnet_from_net(
            network_N1, '10.0.0.0/24')
        port_address, port_id = self._create_port_on_network(network_N1)
        r1_id = self._create_router('r' + uuidutils.generate_uuid()[:4])
        self._attach_router_to_subnet(subnet_id, r1_id)

        lb_data = self._create_load_balancer_and_validate(
            network_id, subnet_id, port_address, port_id, router_id=r1_id)

        # Create a pool
        self._create_pool_and_validate(lb_data, "p1")
        pool_id = lb_data['pools'][0].pool_id
        # Create listener
        self._create_listener_and_validate(lb_data, pool_id, 80)
        # Create Member-1 and associate it with lb_data
        self._create_member_and_validate(
            lb_data, pool_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')

        # Create provider network.
        e1, e1_s1 = self._create_provider_network()

        # Configure external_gateway for router
        router_id = lb_data['lr_ref'][8::]
        self.l3_plugin.update_router(
            self.context,
            router_id,
            {'router': {
                'id': router_id,
                'external_gateway_info': {
                    'enable_snat': True,
                    'network_id': e1['network']['id'],
                    'external_fixed_ips': [
                        {'ip_address': '100.0.0.2',
                         'subnet_id': e1_s1['subnet']['id']}]}}})

        # Create floating IP on LB VIP port
        vip_port_id = lb_data['model'].vip_port_id
        vip_port = self.core_plugin.get_ports(
            self.context, filters={'id': [vip_port_id]})[0]
        self.l3_plugin.create_floatingip(
            self.context, {'floatingip': {
                'tenant_id': self._tenant_id,
                'floating_network_id': e1['network']['id'],
                'subnet_id': None,
                'floating_ip_address': '100.0.0.20',
                'port_id': vip_port['id']}})

        # Validate if FIP is stored as VIP in LB
        lbs = self._get_loadbalancers()
        expected_vips = {
            '%s:80' % vip_port['fixed_ips'][0]['ip_address']: '10.0.0.10:80',
            '100.0.0.20:80': '10.0.0.10:80'}
        self.assertDictEqual(expected_vips,
                             lbs[0].get('vips'))

        provider_net = 'neutron-%s' % e1['network']['id']
        tenant_net = 'neutron-%s' % lb_data['model'].vip_network_id
        for ls in self.nb_api.tables['Logical_Switch'].rows.values():
            if ls.name == tenant_net:
                # Make sure that LB1 is added to tenant network
                self.assertIn(
                    lb_data['model'].loadbalancer_id,
                    [lb.name for lb in ls.load_balancer])
            elif ls.name == provider_net:
                # Make sure that LB1 is not added to provider net - e1 LS
                self.assertListEqual([], ls.load_balancer)

    def test_fip_on_lb_additional_vip(self):
        """This test checks if FIP on LB additional VIP is configured.

           This test validates if Load_Balancer additional VIP field
           consist Floating IP address that is configured
           on LB additional VIP port.
        """
        network_N1 = self._create_net('N' + uuidutils.generate_uuid()[:4])
        network_id, subnet_id = self._create_subnet_from_net(
            network_N1, '10.0.0.0/24')
        port_address, port_id = self._create_port_on_network(network_N1)

        network_ida, subnet_ida = self._create_subnet_from_net(
            network_N1, '10.0.1.0/24')
        port_addressa, port_ida = self._create_port_on_network(network_N1)
        additional_vips_list = [{
            'ip_address': port_addressa,
            'port_id': port_ida,
            'network_id': network_ida,
            'subnet_id': subnet_ida
        }]

        r1_id = self._create_router('r' + uuidutils.generate_uuid()[:4])
        self._attach_router_to_subnet(subnet_id, r1_id)
        self._attach_router_to_subnet(subnet_ida, r1_id)

        # Create LB
        lb_data = self._create_load_balancer_and_validate(
            network_id, subnet_id, port_address, port_id, router_id=r1_id,
            additional_vips=additional_vips_list)
        # Create a pool
        self._create_pool_and_validate(lb_data, "p1")
        pool_id = lb_data['pools'][0].pool_id
        # Create listener
        self._create_listener_and_validate(lb_data, pool_id, 80)
        # Create Member-1 and associate it with lb_data
        self._create_member_and_validate(
            lb_data, pool_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')

        # Create provider network.
        e1, e1_s1 = self._create_provider_network()

        # Configure external_gateway for router
        self.l3_plugin.update_router(
            self.context,
            r1_id,
            {'router': {
                'id': r1_id,
                'external_gateway_info': {
                    'enable_snat': True,
                    'network_id': e1['network']['id'],
                    'external_fixed_ips': [
                        {'ip_address': '100.0.0.2',
                         'subnet_id': e1_s1['subnet']['id']}]}}})

        vip_port_id = lb_data['model'].vip_port_id
        vip_port = self.core_plugin.get_ports(
            self.context, filters={'id': [vip_port_id]})[0]

        # Create floating IP on LB additional VIP port
        addi_vip_port_id = lb_data['model'].additional_vips[0]['port_id']
        vipaddi_vip_port = self.core_plugin.get_ports(
            self.context, filters={'id': [addi_vip_port_id]})[0]
        self.l3_plugin.create_floatingip(
            self.context, {'floatingip': {
                'tenant_id': self._tenant_id,
                'floating_network_id': e1['network']['id'],
                'subnet_id': None,
                'floating_ip_address': '100.0.0.20',
                'port_id': vipaddi_vip_port['id']}})

        # Validate if FIP is stored as VIP in LB
        lbs = self._get_loadbalancers()
        expected_vips = {
            '%s:80' % vip_port['fixed_ips'][0]['ip_address']: '10.0.0.10:80',
            '%s:80' % vipaddi_vip_port['fixed_ips'][0]['ip_address']:
                '10.0.0.10:80',
            '100.0.0.20:80': '10.0.0.10:80'}
        self.assertDictEqual(expected_vips,
                             lbs[0].get('vips'))

        provider_net = 'neutron-%s' % e1['network']['id']
        tenant_net = 'neutron-%s' % lb_data['model'].vip_network_id
        for ls in self.nb_api.tables['Logical_Switch'].rows.values():
            if ls.name == tenant_net:
                # Make sure that LB1 is added to tenant network
                self.assertIn(
                    lb_data['model'].loadbalancer_id,
                    [lb.name for lb in ls.load_balancer])
            elif ls.name == provider_net:
                # Make sure that LB1 is not added to provider net - e1 LS
                self.assertListEqual([], ls.load_balancer)

    def test_agent_exit(self):
        exit_event = mp.Event()
        agent = mp.Process(target=ovn_agent.OvnProviderAgent,
                           args=[exit_event])
        agent.start()
        self.assertTrue(agent.is_alive())
        exit_event.set()
        agent.join()
        self.assertFalse(agent.is_alive())
