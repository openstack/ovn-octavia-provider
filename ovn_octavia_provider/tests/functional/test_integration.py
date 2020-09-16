# Copyright 2020 Red Hat, Inc.
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

from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider.common import utils
from ovn_octavia_provider.tests.functional import base as ovn_base

from neutron_lib.api.definitions import floating_ip_port_forwarding as pf_def
from neutron_lib.utils import runtime
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

LOG = logging.getLogger(__name__)


class TestOvnOctaviaProviderIntegration(ovn_base.TestOvnOctaviaBase):

    def setUp(self):
        super().setUp()
        # Add port_forwarding as a configured service plugin (if needed)
        svc_plugins = set(cfg.CONF.service_plugins)
        svc_plugins.add("port_forwarding")
        cfg.CONF.set_override("service_plugins", list(svc_plugins))
        if not self.pf_plugin:
            # OVN does not use RPC: disable it for port-forwarding tests
            self.pf_plugin = self._load_port_forwarding_class()
            self.pf_plugin._rpc_notifications_required = False
        self.assertIsNotNone(self.pf_plugin,
                             "TestOVNFunctionalBase is expected to have "
                             "port forwarding plugin configured")

    @staticmethod
    def _load_port_forwarding_class():
        """Load port forwarding plugin

        :returns: instance of plugin that is loaded
        :raises ImportError: if fails to load plugin
        """

        try:
            loaded_class = runtime.load_class_by_alias_or_classname(
                'neutron.service_plugins', 'port_forwarding')
            return loaded_class()
        except ImportError:
            with excutils.save_and_reraise_exception():
                LOG.error("Error loading port_forwarding plugin")

    def _find_pf_lb(self, router_id, fip_id=None):
        result = []
        for ovn_lb in self.nb_api.get_router_floatingip_lbs(
                utils.ovn_name(router_id)):
            ext_ids = ovn_lb.external_ids
            if not fip_id or fip_id == ext_ids[ovn_const.OVN_FIP_EXT_ID_KEY]:
                result.append(ovn_lb)
        return result or None

    def _loadbalancer_operation(self, lb_data=None, update=False,
                                delete=False):
        if not lb_data:
            lb_data = self._create_load_balancer_and_validate(
                {'vip_network': 'vip_network', 'cidr': '10.0.0.0/24'})
        if update:
            self._update_load_balancer_and_validate(lb_data,
                                                    admin_state_up=False)
            self._update_load_balancer_and_validate(lb_data,
                                                    admin_state_up=True)
        if delete:
            self._delete_load_balancer_and_validate(lb_data)
        return None if delete else lb_data

    def _validate_from_lb_data(self, lb_data):
        expected_lbs = self._make_expected_lbs(lb_data)
        self._validate_loadbalancers(expected_lbs)

    def test_port_forwarding(self):

        def _verify_pf_lb(test, protocol, vip_ext_port, vip_int_port):
            ovn_lbs = test._find_pf_lb(router_id, fip_id)
            test.assertEqual(len(ovn_lbs), 1)
            test.assertEqual(ovn_lbs[0].name,
                             'pf-floatingip-{}-{}'.format(fip_id, protocol))
            self.assertEqual(ovn_lbs[0].vips, {
                '{}:{}'.format(fip_ip, vip_ext_port):
                    '{}:{}'.format(p1_ip, vip_int_port)})

        n1, s1 = self._create_provider_network()
        ext_net = n1['network']
        ext_subnet = s1['subnet']

        gw_info = {
            'enable_snat': True,
            'network_id': ext_net['id'],
            'external_fixed_ips': [
                {'ip_address': '100.0.0.2', 'subnet_id': ext_subnet['id']}]}
        router_id = self._create_router('routertest', gw_info=gw_info)

        # Create Network N2, connect it to router
        n2_id, sub2_id, p1_ip, p1_id = self._create_net(
            "N2", "10.0.1.0/24", router_id)

        fip_info = {'floatingip': {
            'tenant_id': self._tenant_id,
            'floating_network_id': ext_net['id'],
            'port_id': None,
            'fixed_ip_address': None}}
        fip = self.l3_plugin.create_floatingip(self.context, fip_info)
        fip_id = fip['id']
        fip_ip = fip['floating_ip_address']

        # Create floating ip port forwarding. This will create an
        # OVN load balancer
        fip_pf_args = {
            pf_def.EXTERNAL_PORT: 2222,
            pf_def.INTERNAL_PORT: 22,
            pf_def.INTERNAL_PORT_ID: p1_id,
            pf_def.PROTOCOL: 'tcp',
            pf_def.INTERNAL_IP_ADDRESS: p1_ip}
        fip_attrs = {pf_def.RESOURCE_NAME: {pf_def.RESOURCE_NAME: fip_pf_args}}
        pf_obj = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, fip_id, **fip_attrs)

        # Check pf_lb with no octavia_provider_lb
        _verify_pf_lb(self, 'tcp', 2222, 22)

        # Create octavia_provider_lb
        lb_data = self._loadbalancer_operation()
        expected_lbs = self._make_expected_lbs(lb_data)
        _verify_pf_lb(self, 'tcp', 2222, 22)

        fip_pf_args2 = {pf_def.EXTERNAL_PORT: 5353, pf_def.INTERNAL_PORT: 53,
                        pf_def.PROTOCOL: 'udp'}
        fip_attrs2 = {pf_def.RESOURCE_NAME: {
            pf_def.RESOURCE_NAME: fip_pf_args2}}
        self.pf_plugin.update_floatingip_port_forwarding(
            self.context, pf_obj['id'], fip_id, **fip_attrs2)

        # Make sure octavia_provider_lb is not disturbed
        self._validate_loadbalancers(expected_lbs)

        # Update octavia_provider_lb
        self._loadbalancer_operation(lb_data, update=True)
        _verify_pf_lb(self, 'udp', 5353, 53)

        # Delete octavia_provider_lb
        self._loadbalancer_operation(lb_data, delete=True)
        _verify_pf_lb(self, 'udp', 5353, 53)

        # Delete pf_lb after creating octavia_provider_lb
        lb_data = self._loadbalancer_operation()
        expected_lbs = self._make_expected_lbs(lb_data)

        self.pf_plugin.delete_floatingip_port_forwarding(
            self.context, pf_obj['id'], fip_id)
        self._loadbalancer_operation(lb_data, update=True)
        self.assertIsNone(self._find_pf_lb(router_id, fip_id))

        # Make sure octavia_provider_lb is not disturbed
        self._validate_loadbalancers(expected_lbs)
        self._loadbalancer_operation(lb_data, delete=True)
