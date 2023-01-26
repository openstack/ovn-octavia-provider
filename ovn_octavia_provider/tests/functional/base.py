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

import copy
from unittest import mock

from neutron.common import utils as n_utils
from neutron_lib.plugins import directory
from octavia_lib.api.drivers import data_models as octavia_data_model
from octavia_lib.api.drivers import driver_lib
from octavia_lib.common import constants as o_constants
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from ovsdbapp.schema.ovn_northbound import impl_idl as nb_idl_ovn
from ovsdbapp.schema.ovn_southbound import impl_idl as sb_idl_ovn

# NOTE(mjozefcz): We need base neutron functionals because we need
# mechanism driver and l3 plugin.
from neutron.tests.functional import base
from ovn_octavia_provider.common import clients
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider import driver as ovn_driver


class TestOvnOctaviaBase(base.TestOVNFunctionalBase,
                         base.BaseLoggingTestCase):

    def setUp(self):
        super().setUp()
        nb_idl_ovn.OvnNbApiIdlImpl.ovsdb_connection = None
        sb_idl_ovn.OvnSbApiIdlImpl.ovsdb_connection = None
        # TODO(mjozefcz): Use octavia listeners to provide needed
        # sockets and modify tests in order to verify if fake
        # listener (status) has received valid value.
        try:
            mock.patch.object(
                driver_lib.DriverLibrary, '_check_for_socket_ready').start()
        except AttributeError:
            # Backward compatiblity with octavia-lib < 1.3.1
            pass
        self.ovn_driver = ovn_driver.OvnProviderDriver()
        self.ovn_driver._ovn_helper._octavia_driver_lib = mock.MagicMock()
        self._o_driver_lib = self.ovn_driver._ovn_helper._octavia_driver_lib
        self._o_driver_lib.update_loadbalancer_status = mock.Mock()
        self.fake_neutron_client = mock.MagicMock()
        clients.get_neutron_client = mock.MagicMock()
        clients.get_neutron_client.return_value = self.fake_neutron_client
        self.fake_neutron_client.show_network = self._mock_show_network
        self.fake_neutron_client.show_subnet = self._mock_show_subnet
        self.fake_neutron_client.list_ports = self._mock_list_ports
        self.fake_neutron_client.show_port = self._mock_show_port
        self.fake_neutron_client.delete_port.return_value = True
        self._local_net_cache = {}
        self._local_cidr_cache = {}
        self._local_port_cache = {'ports': []}
        self.core_plugin = directory.get_plugin()

    def _mock_show_network(self, network_id):
        network = {}
        network['id'] = network_id
        network['provider:physical_network'] = None
        return {'network': network}

    def _mock_show_subnet(self, subnet_id):
        subnet = {}
        subnet['network_id'] = self._local_net_cache[subnet_id]
        subnet['cidr'] = self._local_cidr_cache[subnet_id]
        return {'subnet': subnet}

    def _mock_list_ports(self, **kwargs):
        return self._local_port_cache

    def _mock_show_port(self, port_id):
        for port in self._local_port_cache['ports']:
            if port['id'] == port_id:
                return {'port': port}

    def _create_provider_network(self):
        e1 = self._make_network(self.fmt, 'e1', True,
                                arg_list=('router:external',
                                          'provider:network_type',
                                          'provider:physical_network'),
                                **{'router:external': True,
                                   'provider:network_type': 'flat',
                                   'provider:physical_network': 'public'})
        res = self._create_subnet(self.fmt, e1['network']['id'],
                                  '100.0.0.0/24', gateway_ip='100.0.0.254',
                                  allocation_pools=[{'start': '100.0.0.2',
                                                     'end': '100.0.0.253'}],
                                  enable_dhcp=False)
        e1_s1 = self.deserialize(self.fmt, res)
        return e1, e1_s1

    def _create_lb_model(self, vip=None, vip_network_id=None,
                         vip_subnet_id=None, vip_port_id=None,
                         admin_state_up=True):
        lb = octavia_data_model.LoadBalancer()
        lb.loadbalancer_id = uuidutils.generate_uuid()

        if vip:
            lb.vip_address = vip
        else:
            lb.vip_address = '10.0.0.4'

        if vip_network_id:
            lb.vip_network_id = vip_network_id
        if vip_subnet_id:
            lb.vip_subnet_id = vip_subnet_id
        if vip_port_id:
            lb.vip_port_id = vip_port_id
        lb.admin_state_up = admin_state_up
        return lb

    def _create_pool_model(
            self, loadbalancer_id, pool_name,
            protocol=o_constants.PROTOCOL_TCP,
            lb_algorithm=o_constants.LB_ALGORITHM_SOURCE_IP_PORT,
            admin_state_up=True, listener_id=None):
        m_pool = octavia_data_model.Pool()
        if protocol:
            m_pool.protocol = protocol
        else:
            m_pool.protocol = o_constants.PROTOCOL_TCP
        m_pool.name = pool_name
        m_pool.pool_id = uuidutils.generate_uuid()
        m_pool.loadbalancer_id = loadbalancer_id
        m_pool.members = []
        m_pool.admin_state_up = admin_state_up
        m_pool.lb_algorithm = lb_algorithm
        if listener_id:
            m_pool.listener_id = listener_id
        return m_pool

    def _create_member_model(self, pool_id, subnet_id, address,
                             protocol_port=None, admin_state_up=True):
        m_member = octavia_data_model.Member()
        if protocol_port:
            m_member.protocol_port = protocol_port
        else:
            m_member.protocol_port = 80

        m_member.member_id = uuidutils.generate_uuid()
        m_member.pool_id = pool_id
        if subnet_id:
            m_member.subnet_id = subnet_id
        m_member.address = address
        m_member.admin_state_up = admin_state_up
        return m_member

    def _create_listener_model(self, loadbalancer_id, pool_id=None,
                               protocol_port=80, protocol=None,
                               admin_state_up=True):
        m_listener = octavia_data_model.Listener()
        if protocol:
            m_listener.protocol = protocol
        else:
            m_listener.protocol = o_constants.PROTOCOL_TCP

        m_listener.listener_id = uuidutils.generate_uuid()
        m_listener.loadbalancer_id = loadbalancer_id
        if pool_id:
            m_listener.default_pool_id = pool_id
        m_listener.protocol_port = protocol_port
        m_listener.admin_state_up = admin_state_up
        return m_listener

    def _get_loadbalancers(self):
        lbs = []
        for lb in self.nb_api.tables['Load_Balancer'].rows.values():
            external_ids = dict(lb.external_ids)
            # Skip load balancers used by port forwarding plugin
            if external_ids.get(ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY) == (
                    ovn_const.PORT_FORWARDING_PLUGIN):
                continue
            ls_refs = external_ids.get(ovn_const.LB_EXT_IDS_LS_REFS_KEY)
            if ls_refs:
                external_ids[
                    ovn_const.LB_EXT_IDS_LS_REFS_KEY] = jsonutils.loads(
                        ls_refs)
            member_status = external_ids.get(ovn_const.OVN_MEMBER_STATUS_KEY)
            if member_status:
                external_ids[
                    ovn_const.OVN_MEMBER_STATUS_KEY] = jsonutils.loads(
                        member_status)
            lb_dict = {'name': lb.name, 'protocol': lb.protocol,
                       'vips': lb.vips, 'external_ids': external_ids}
            try:
                lb_dict['selection_fields'] = lb.selection_fields
            except AttributeError:
                pass
            lbs.append(lb_dict)
        return lbs

    def _get_loadbalancer_id(self, lb_name):
        for lb in self.nb_api.tables['Load_Balancer'].rows.values():
            if lb.name == lb_name:
                return lb.uuid

    def _validate_loadbalancers(self, expected_lbs):
        observed_lbs = self._get_loadbalancers()
        # NOTE (mjozefcz): assertCountEqual works only on first level
        # of comparison, if dicts inside dicts are in different
        # order it would fail.
        self.assertEqual(len(expected_lbs), len(observed_lbs))
        for expected_lb in expected_lbs:
            # search for LB with same name and protocol
            found = False
            for observed_lb in observed_lbs:
                if (observed_lb.get('name') ==
                        expected_lb.get('name') and
                    observed_lb.get('protocol') ==
                        expected_lb.get('protocol')):
                    self.assertEqual(expected_lb, observed_lb)
                    found = True
            if not found:
                raise Exception("Expected LB %s for protocol %s "
                                "not found in observed_lbs" % (
                                    expected_lb.get('name'),
                                    expected_lb.get('proto')))

    def _is_lb_associated_to_ls(self, lb_name, ls_name):
        return self._is_lb_associated_to_tab(
            'Logical_Switch', lb_name, ls_name)

    def _is_lb_associated_to_lr(self, lb_name, lr_name):
        return self._is_lb_associated_to_tab(
            'Logical_Router', lb_name, lr_name)

    def _is_lb_associated_to_tab(self, table, lb_name, ls_name):
        lb_uuid = self._get_loadbalancer_id(lb_name)
        for ls in self.nb_api.tables[table].rows.values():
            if ls.name == ls_name:
                ls_lbs = [lb.uuid for lb in ls.load_balancer]
                return lb_uuid in ls_lbs
        return False

    def _create_router(self, name, gw_info=None):
        router = {'router':
                  {'name': name,
                   'admin_state_up': True,
                   'tenant_id': self._tenant_id}}
        if gw_info:
            router['router']['external_gateway_info'] = gw_info
        router = self.l3_plugin.create_router(self.context, router)
        return router['id']

    def _create_net(self, name, cidr, router_id=None):
        n1 = self._make_network(self.fmt, name, True)
        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  cidr)
        subnet = self.deserialize(self.fmt, res)['subnet']
        self._local_net_cache[subnet['id']] = n1['network']['id']
        self._local_cidr_cache[subnet['id']] = subnet['cidr']

        port = self._make_port(self.fmt, n1['network']['id'])
        if router_id:
            self.l3_plugin.add_router_interface(
                self.context, router_id, {'subnet_id': subnet['id']})
        self._local_port_cache['ports'].append(port['port'])
        vip_port_address = port['port']['fixed_ips'][0]['ip_address']
        return (n1['network']['id'], subnet['id'], vip_port_address,
                port['port']['id'])

    def _update_ls_refs(self, lb_data, net_id, add_ref=True):
        if not net_id.startswith(ovn_const.LR_REF_KEY_HEADER):
            net_id = ovn_const.LR_REF_KEY_HEADER + '%s' % net_id

        if add_ref:
            if net_id not in lb_data[ovn_const.LB_EXT_IDS_LS_REFS_KEY]:
                lb_data[ovn_const.LB_EXT_IDS_LS_REFS_KEY][net_id] = 1
        else:
            ref_ct = lb_data[ovn_const.LB_EXT_IDS_LS_REFS_KEY][net_id]
            if ref_ct <= 0:
                del lb_data[ovn_const.LB_EXT_IDS_LS_REFS_KEY][net_id]

    def _wait_for_status(self, expected_statuses, check_call=True):
        call_count = len(expected_statuses)
        update_loadbalancer_status = (
            self._o_driver_lib.update_loadbalancer_status)
        n_utils.wait_until_true(
            lambda: update_loadbalancer_status.call_count == call_count,
            timeout=10)
        if check_call:
            # NOTE(mjozefcz): The updates are send in parallel and includes
            # dicts with unordered lists inside. So we can't simply use
            # assert_has_calls here. Sample structure:
            # {'listeners': [],
            #  'loadbalancers': [{'id': 'a', 'provisioning_status': 'ACTIVE'}],
            #  'members': [{'id': 'b', 'provisioning_status': 'DELETED'},
            #              {'id': 'c', 'provisioning_status': 'DELETED'}],
            #  'pools': [{'id': 'd', 'operating_status': 'ONLINE',
            #             'provisioning_status': 'ACTIVE'}]},
            updated_statuses = []
            for call in update_loadbalancer_status.mock_calls:
                updated_statuses.append(call[1][0])
            calls_found = []
            for expected_status in expected_statuses:
                for updated_status in updated_statuses:
                    # Find status update having equal keys
                    if (sorted(updated_status.keys()) ==
                            sorted(expected_status.keys())):
                        val_check = []
                        # Withing this status update check if all values of
                        # expected keys match.
                        for k, v in expected_status.items():
                            val_check.append(
                                sorted(expected_status[k],
                                       key=lambda x: x['id']) ==
                                sorted(updated_status[k],
                                       key=lambda x: x['id']))
                        if False in val_check:
                            # At least one value don't match.
                            continue
                        calls_found.append(expected_status)
                        break
            # Validate if we found all expected calls.
            self.assertCountEqual(expected_statuses, calls_found)

    def _wait_for_status_and_validate(self, lb_data, expected_status,
                                      check_call=True):
        self._wait_for_status(expected_status, check_call)
        expected_lbs = self._make_expected_lbs(lb_data)
        self._validate_loadbalancers(expected_lbs)

    def _create_load_balancer_custom_lr_ls_and_validate(
        self, admin_state_up=True, create_router=True,
            force_retry_ls_to_lr_assoc=True):

        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        r_id = self._create_router('r1') if create_router else None

        net_info = []
        net_info.append(self._create_net("n1", "10.0.1.0/24", r_id))
        net_info.append(self._create_net("n2", "10.0.2.0/24", r_id))
        net_info.append(self._create_net("n3", "10.0.3.0/24", r_id))

        lb_data = {}
        lb_data['model'] = self._create_lb_model(
            vip=net_info[0][2],
            vip_network_id=net_info[0][0],
            vip_subnet_id=net_info[0][1],
            vip_port_id=net_info[0][3],
            admin_state_up=admin_state_up)

        lb_data[ovn_const.LB_EXT_IDS_LR_REF_KEY] = \
            (ovn_const.LR_REF_KEY_HEADER + r_id)
        lb_data['vip_net_info'] = net_info[0]
        lb_data[ovn_const.LB_EXT_IDS_LS_REFS_KEY] = {}
        lb_data['listeners'] = []
        lb_data['pools'] = []
        self._update_ls_refs(lb_data, net_info[0][0])
        ls = [ovn_const.LR_REF_KEY_HEADER + net[0] for net in net_info]

        if force_retry_ls_to_lr_assoc:
            ls_foo = copy.deepcopy(ls)
            ls_foo.append('neutron-foo')
            self.ovn_driver._ovn_helper._find_ls_for_lr = mock.MagicMock()
            self.ovn_driver._ovn_helper._find_ls_for_lr.side_effect = \
                [ls_foo, ls]

        self.ovn_driver.loadbalancer_create(lb_data['model'])

        name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                         lb_data['model'].loadbalancer_id)
        self.driver.update_port(
            self.context, net_info[0][3], {'port': {'name': name}})

        if lb_data['model'].admin_state_up:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.ONLINE}]
            }
        else:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.OFFLINE}]
            }
        self._wait_for_status_and_validate(lb_data, [expected_status])
        self.assertTrue(
            self._is_lb_associated_to_ls(
                lb_data['model'].loadbalancer_id,
                ovn_const.LR_REF_KEY_HEADER + net_info[0][0]))

        # NOTE(froyo): Just to check all net connected to lr have a
        # reference to lb
        for net_id in ls:
            self.assertTrue(
                self._is_lb_associated_to_ls(
                    lb_data['model'].loadbalancer_id,
                    net_id))

        return lb_data

    def _create_load_balancer_and_validate(self, lb_info,
                                           admin_state_up=True,
                                           only_model=False,
                                           create_router=True,
                                           multiple_lb=False):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        lb_data = {}
        r_id = self._create_router("r1") if create_router else None
        if r_id:
            lb_data[ovn_const.LB_EXT_IDS_LR_REF_KEY] = (
                ovn_const.LR_REF_KEY_HEADER + r_id)
        net_info = self._create_net(lb_info['vip_network'], lb_info['cidr'],
                                    router_id=r_id)
        lb_data['vip_net_info'] = net_info
        lb_data['model'] = self._create_lb_model(vip=net_info[2],
                                                 vip_network_id=net_info[0],
                                                 vip_subnet_id=net_info[1],
                                                 vip_port_id=net_info[3],
                                                 admin_state_up=admin_state_up)
        lb_data[ovn_const.LB_EXT_IDS_LS_REFS_KEY] = {}
        lb_data['listeners'] = []
        lb_data['pools'] = []
        self._update_ls_refs(lb_data, net_info[0])
        if only_model:
            return lb_data

        self.ovn_driver.loadbalancer_create(lb_data['model'])

        name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                         lb_data['model'].loadbalancer_id)
        self.driver.update_port(
            self.context, net_info[3], {'port': {'name': name}})

        if lb_data['model'].admin_state_up:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.ONLINE}]
            }
        else:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.OFFLINE}]
            }
        if not multiple_lb:
            self._wait_for_status_and_validate(lb_data, [expected_status])
        else:
            l_id = lb_data['model'].loadbalancer_id
            self._wait_for_status([expected_status])
            self.assertIn(l_id,
                          [lb['name'] for lb in self._get_loadbalancers()])
        self.assertTrue(
            self._is_lb_associated_to_ls(
                lb_data['model'].loadbalancer_id,
                ovn_const.LR_REF_KEY_HEADER + net_info[0]))
        return lb_data

    def _update_load_balancer_and_validate(self, lb_data,
                                           admin_state_up=None):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        if admin_state_up is not None:
            lb_data['model'].admin_state_up = admin_state_up
        self.ovn_driver.loadbalancer_update(
            lb_data['model'], lb_data['model'])

        if lb_data['model'].admin_state_up:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.ONLINE}]
            }
        else:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.OFFLINE}]
            }

        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _delete_load_balancer_and_validate(self, lb_data, cascade=False,
                                           multiple_lb=False):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.loadbalancer_delete(lb_data['model'], cascade)
        expected_status = {
            'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                               "provisioning_status": "DELETED",
                               "operating_status": "OFFLINE"}]
        }
        if cascade:
            expected_status['pools'] = []
            expected_status['members'] = []
            expected_status['listeners'] = []
            for pool in lb_data['pools']:
                expected_status['pools'].append({
                    'id': pool.pool_id,
                    'provisioning_status': 'DELETED'})
                for member in pool.members:
                    expected_status['members'].append({
                        "id": member.member_id,
                        "provisioning_status": "DELETED"})
            for listener in lb_data['listeners']:
                expected_status['listeners'].append({
                    "id": listener.listener_id,
                    "provisioning_status": "DELETED",
                    "operating_status": "OFFLINE"})
            expected_status = {
                key: value for key, value in expected_status.items() if value}
        l_id = lb_data['model'].loadbalancer_id
        lb = lb_data['model']
        del lb_data['model']
        if not multiple_lb:
            self._wait_for_status_and_validate(lb_data, [expected_status])
        else:
            self._wait_for_status([expected_status])
            self.assertNotIn(
                l_id, [lbs['name'] for lbs in self._get_loadbalancers()])
        vip_net_id = lb_data['vip_net_info'][0]
        self.assertFalse(
            self._is_lb_associated_to_ls(
                lb.loadbalancer_id,
                ovn_const.LR_REF_KEY_HEADER + vip_net_id))

    def _make_expected_lbs(self, lb_data):
        def _get_lb_field_by_protocol(protocol, field='external_ids'):
            "Get needed external_ids and pass by reference"
            lb = [lb for lb in expected_lbs
                  if lb.get('protocol') == [protocol]]
            return lb[0].get(field)

        if not lb_data or not lb_data.get('model'):
            return []

        vip_net_info = lb_data['vip_net_info']
        external_ids = {ovn_const.LB_EXT_IDS_LS_REFS_KEY: {},
                        'neutron:vip': lb_data['model'].vip_address,
                        'neutron:vip_port_id': vip_net_info[3],
                        'enabled': str(lb_data['model'].admin_state_up)}
        # NOTE(mjozefcz): By default we don't set protocol. We don't know if
        # listener/pool would be TCP, UDP or SCTP, so do not set it.
        expected_protocols = set()

        # Lets fetch list of L4 protocols defined for this LB.
        for p in lb_data['pools']:
            expected_protocols.add(p.protocol.lower())
        for listener in lb_data['listeners']:
            expected_protocols.add(listener.protocol.lower())
        # If there is no protocol lets add default - empty [].
        expected_protocols = list(expected_protocols)
        if len(expected_protocols) == 0:
            expected_protocols.append(None)

        expected_lbs = []
        for protocol in expected_protocols:
            lb = {'name': lb_data['model'].loadbalancer_id,
                  'protocol': [protocol] if protocol else [],
                  'vips': {},
                  'external_ids': copy.deepcopy(external_ids)}
            if self.ovn_driver._ovn_helper._are_selection_fields_supported():
                lb['selection_fields'] = ovn_const.LB_SELECTION_FIELDS_MAP[
                    o_constants.LB_ALGORITHM_SOURCE_IP_PORT]
            expected_lbs.append(lb)

        # For every connected subnet to the LB set the ref
        # counter.
        for net_id, ref_ct in lb_data[
                ovn_const.LB_EXT_IDS_LS_REFS_KEY].items():
            for lb in expected_lbs:
                # If given LB hasn't VIP configured from
                # this network we shouldn't touch it here.
                if net_id == 'neutron-%s' % lb_data['model'].vip_network_id:
                    lb.get('external_ids')[
                        ovn_const.LB_EXT_IDS_LS_REFS_KEY][net_id] = 1

        # For every connected router set it here.
        if lb_data.get(ovn_const.LB_EXT_IDS_LR_REF_KEY):
            for lb in expected_lbs:
                lb.get('external_ids')[
                    ovn_const.LB_EXT_IDS_LR_REF_KEY] = lb_data[
                        ovn_const.LB_EXT_IDS_LR_REF_KEY]

        pool_info = {}
        for p in lb_data.get('pools', []):
            member_status = {}
            external_ids = _get_lb_field_by_protocol(
                p.protocol.lower(),
                field='external_ids')
            p_members = ""
            for m in p.members:
                if not m.admin_state_up:
                    continue
                m_info = 'member_' + m.member_id + '_' + m.address
                m_info += ":" + str(m.protocol_port)
                m_info += "_" + str(m.subnet_id)
                if p_members:
                    p_members += "," + m_info
                else:
                    p_members = m_info
                # Bump up LS refs counter if needed.
                if m.subnet_id:
                    # Need to get the network_id.
                    for port in self._local_port_cache['ports']:
                        for fixed_ip in port['fixed_ips']:
                            if fixed_ip['subnet_id'] == m.subnet_id:
                                ex = external_ids[
                                    ovn_const.LB_EXT_IDS_LS_REFS_KEY]
                                act = ex.get(
                                    'neutron-%s' % port['network_id'], 0)
                                ex['neutron-%s' % port['network_id']] = act + 1
                                break
                member_status[m.member_id] = o_constants.NO_MONITOR
            pool_key = 'pool_' + p.pool_id
            if not p.admin_state_up:
                pool_key += ':D'
            external_ids[pool_key] = p_members
            pool_info[p.pool_id] = p_members
            if member_status:
                external_ids[ovn_const.OVN_MEMBER_STATUS_KEY] = member_status

        for listener in lb_data['listeners']:
            expected_vips = _get_lb_field_by_protocol(
                listener.protocol.lower(),
                field='vips')
            external_ids = _get_lb_field_by_protocol(
                listener.protocol.lower(),
                field='external_ids')
            listener_k = 'listener_' + str(listener.listener_id)
            if lb_data['model'].admin_state_up and listener.admin_state_up:
                vip_k = lb_data['model'].vip_address + ":" + str(
                    listener.protocol_port)
                if not isinstance(listener.default_pool_id,
                                  octavia_data_model.UnsetType) and pool_info[
                                      listener.default_pool_id]:
                    expected_vips[vip_k] = self._extract_member_info(
                        pool_info[listener.default_pool_id])
            else:
                listener_k += ':D'
            external_ids[listener_k] = str(listener.protocol_port) + ":"
            if not isinstance(listener.default_pool_id,
                              octavia_data_model.UnsetType):
                external_ids[listener_k] += 'pool_' + listener.default_pool_id
            elif lb_data.get('pools', []):
                external_ids[listener_k] += 'pool_' + lb_data[
                    'pools'][0].pool_id
        return expected_lbs

    def _extract_member_info(self, member):
        mem_info = ''
        if member:
            for item in member.split(','):
                mem_info += item.split('_')[2] + ","
        return mem_info[:-1]

    def _create_pool_and_validate(self, lb_data, pool_name,
                                  protocol=None,
                                  listener_id=None):
        lb_pools = lb_data['pools']
        m_pool = self._create_pool_model(lb_data['model'].loadbalancer_id,
                                         pool_name,
                                         protocol=protocol,
                                         listener_id=listener_id)
        lb_pools.append(m_pool)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.pool_create(m_pool)
        operating_status = (
            o_constants.ONLINE
            if listener_id else o_constants.OFFLINE)

        expected_status = {
            'pools': [{'id': m_pool.pool_id,
                       'provisioning_status': 'ACTIVE',
                       'operating_status': operating_status}],
            'loadbalancers': [{'id': m_pool.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}]
        }
        if listener_id:
            expected_status['listeners'] = [
                {'id': listener_id,
                 'provisioning_status': 'ACTIVE'}]

        self._wait_for_status_and_validate(lb_data, [expected_status])

        expected_lbs = self._make_expected_lbs(lb_data)
        self._validate_loadbalancers(expected_lbs)

    def _update_pool_and_validate(self, lb_data, pool_name,
                                  admin_state_up=None):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        m_pool = self._get_pool_from_lb_data(lb_data, pool_name=pool_name)
        old_admin_state_up = m_pool.admin_state_up
        operating_status = 'ONLINE'
        if admin_state_up is not None:
            m_pool.admin_state_up = admin_state_up
            if not admin_state_up:
                operating_status = 'OFFLINE'

        pool_listeners = self._get_pool_listeners(lb_data, m_pool.pool_id)
        expected_listener_status = [
            {'id': listener.listener_id, 'provisioning_status': 'ACTIVE'}
            for listener in pool_listeners]
        self.ovn_driver.pool_update(m_pool, m_pool)
        expected_status = {
            'pools': [{'id': m_pool.pool_id,
                       'provisioning_status': 'ACTIVE',
                       'operating_status': operating_status}],
            'loadbalancers': [{'id': m_pool.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}],
            'listeners': expected_listener_status
        }

        if old_admin_state_up != m_pool.admin_state_up:
            if m_pool.admin_state_up:
                oper_status = o_constants.ONLINE
            else:
                oper_status = o_constants.OFFLINE
            expected_status['pools'][0]['operating_status'] = oper_status
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _delete_pool_and_validate(self, lb_data, pool_name,
                                  listener_id=None):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        p = self._get_pool_from_lb_data(lb_data, pool_name=pool_name)
        self.ovn_driver.pool_delete(p)
        lb_data['pools'].remove(p)
        expected_status = []
        # When a pool is deleted and if it has any members, there are
        # expected to be deleted.
        for m in p.members:
            expected_status.append(
                {'pools': [{"id": p.pool_id,
                            "provisioning_status": o_constants.ACTIVE,
                            "operating_status": o_constants.ONLINE}],
                 'members': [{"id": m.member_id,
                              "provisioning_status": "DELETED"}],
                 'loadbalancers': [{"id": p.loadbalancer_id,
                                    "provisioning_status": "ACTIVE"}],
                 'listeners': []})
            self._update_ls_refs(
                lb_data, self._local_net_cache[m.subnet_id], add_ref=False)
        if p.members:
            # If Pool has members, delete all members of the pool. When the
            # last member is processed set Operating status of Pool as Offline
            expected_status[-1]['pools'][0][
                'operating_status'] = o_constants.OFFLINE
        pool_dict = {
            'pools': [{'id': p.pool_id,
                       'provisioning_status': 'DELETED'}],
            'loadbalancers': [{'id': p.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}],
            'listeners': []
        }
        if listener_id:
            pool_dict['listeners'] = [{'id': listener_id,
                                       'provisioning_status': 'ACTIVE'}]
        expected_status.append(pool_dict)
        self._wait_for_status_and_validate(lb_data, expected_status)

    def _get_pool_from_lb_data(self, lb_data, pool_id=None,
                               pool_name=None):
        for p in lb_data['pools']:
            if pool_id and p.pool_id == pool_id:
                return p

            if pool_name and p.name == pool_name:
                return p

    def _get_listener_from_lb_data(self, lb_data, protocol, protocol_port):
        for listener in lb_data['listeners']:
            if (listener.protocol_port == protocol_port and
                    listener.protocol == protocol):
                return listener

    def _get_pool_listeners(self, lb_data, pool_id):
        listeners = []
        for listener in lb_data['listeners']:
            if listener.default_pool_id == pool_id:
                listeners.append(listener)

        return listeners

    def _create_member_and_validate(self, lb_data, pool_id, subnet_id,
                                    network_id, address, expected_subnet=None):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)
        pool_status = {'id': pool.pool_id,
                       'provisioning_status': o_constants.ACTIVE,
                       'operating_status': o_constants.ONLINE}

        m_member = self._create_member_model(pool.pool_id, subnet_id, address)
        # The "expected" member value, which might be different from what
        # we pass to member_create(), for example, if an expected_subnet
        # was given.
        if expected_subnet:
            e_member = copy.deepcopy(m_member)
            e_member.subnet_id = expected_subnet
        else:
            e_member = m_member
        pool.members.append(e_member)

        self.ovn_driver.member_create(m_member)
        self._update_ls_refs(lb_data, network_id)
        pool_listeners = self._get_pool_listeners(lb_data, pool_id)
        expected_listener_status = [
            {'id': listener.listener_id, 'provisioning_status': 'ACTIVE'}
            for listener in pool_listeners]

        expected_status = {
            'pools': [pool_status],
            'members': [{"id": m_member.member_id,
                         "provisioning_status": "ACTIVE"}],
            'loadbalancers': [{'id': pool.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}],
            'listeners': expected_listener_status
        }
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _get_pool_member(self, pool, member_address):
        for m in pool.members:
            if m.address == member_address:
                return m

    def _update_member_and_validate(self, lb_data, pool_id, member_address,
                                    remove_subnet_id=False):
        pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)

        member = self._get_pool_member(pool, member_address)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        old_member = copy.deepcopy(member)

        # NOTE(froyo): In order to test update of member without passing the
        # subnet_id parameter of the member, just to cover the case when a new
        # member has been created without passing that argument
        if remove_subnet_id:
            old_member.subnet_id = None

        self.ovn_driver.member_update(old_member, member)
        expected_status = {
            'pools': [{'id': pool.pool_id,
                       'provisioning_status': 'ACTIVE'}],
            'members': [{"id": member.member_id,
                         'provisioning_status': 'ACTIVE'}],
            'loadbalancers': [{'id': pool.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}],
            'listeners': []
        }
        if getattr(member, 'admin_state_up', None):
            expected_status['members'][0][
                'operating_status'] = o_constants.NO_MONITOR
        else:
            expected_status['members'][0]['operating_status'] = "OFFLINE"
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _update_members_in_batch_and_validate(self, lb_data, pool_id,
                                              members):
        pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)
        expected_status = []
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.member_batch_update(pool_id, members)
        for member in members:
            expected_status.append(
                {'pools': [{'id': pool.pool_id,
                           'provisioning_status': 'ACTIVE'}],
                 'members': [{'id': member.member_id,
                              'provisioning_status': 'ACTIVE',
                              'operating_status': 'ONLINE'}],
                 'loadbalancers': [{'id': pool.loadbalancer_id,
                                   'provisioning_status': 'ACTIVE'}],
                 'listeners': []})
        for m in pool.members:
            found = False
            for member in members:
                if member.member_id == m.member_id:
                    found = True
                    break
            if not found:
                expected_status.append(
                    {'pools': [{'id': pool.pool_id,
                                'provisioning_status': 'ACTIVE'}],
                     'members': [{'id': m.member_id,
                                  'provisioning_status': 'DELETED'}],
                     'loadbalancers': [{'id': pool.loadbalancer_id,
                                        'provisioning_status': 'ACTIVE'}],
                     'listeners': []})
                # Delete member from lb_data
                pool.members.remove(m)
        self._wait_for_status_and_validate(lb_data, expected_status,
                                           check_call=False)

    def _delete_member_and_validate(self, lb_data, pool_id, network_id,
                                    member_address, remove_subnet_id=False):
        pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)
        member = self._get_pool_member(pool, member_address)
        pool.members.remove(member)
        pool_status = {"id": pool.pool_id,
                       "provisioning_status": o_constants.ACTIVE,
                       "operating_status": o_constants.ONLINE}
        if not pool.members:
            pool_status['operating_status'] = o_constants.OFFLINE

        self._o_driver_lib.update_loadbalancer_status.reset_mock()

        # NOTE(froyo): In order to test deletion of member without passing
        # the subnet_id parameter of the member, just to cover the case when
        # a new member has been created without passing that argument
        m_member = copy.deepcopy(member)
        if remove_subnet_id:
            m_member.subnet_id = None

        self.ovn_driver.member_delete(m_member)
        expected_status = {
            'pools': [pool_status],
            'members': [{"id": member.member_id,
                         "provisioning_status": "DELETED"}],
            'loadbalancers': [{"id": pool.loadbalancer_id,
                               "provisioning_status": "ACTIVE"}],
            'listeners': []}

        self._update_ls_refs(lb_data, network_id, add_ref=False)
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _create_listener_and_validate(self, lb_data, pool_id=None,
                                      protocol_port=80,
                                      admin_state_up=True, protocol='TCP'):
        if pool_id:
            pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)
            loadbalancer_id = pool.loadbalancer_id
            pool_id = pool.pool_id
        else:
            loadbalancer_id = lb_data['model'].loadbalancer_id
            pool_id = None
        m_listener = self._create_listener_model(loadbalancer_id,
                                                 pool_id, protocol_port,
                                                 protocol=protocol,
                                                 admin_state_up=admin_state_up)
        lb_data['listeners'].append(m_listener)

        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.listener_create(m_listener)
        expected_status = {
            'listeners': [{'id': m_listener.listener_id,
                           'provisioning_status': 'ACTIVE',
                           'operating_status': 'ONLINE'}],
            'loadbalancers': [{'id': m_listener.loadbalancer_id,
                               'provisioning_status': "ACTIVE"}]}

        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _update_listener_and_validate(self, lb_data, protocol_port=80,
                                      admin_state_up=None, protocol='TCP'):
        m_listener = self._get_listener_from_lb_data(
            lb_data, protocol, protocol_port)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        old_admin_state_up = m_listener.admin_state_up
        operating_status = 'ONLINE'
        if admin_state_up is not None:
            m_listener.admin_state_up = admin_state_up
            if not admin_state_up:
                operating_status = 'OFFLINE'
        m_listener.protocol = protocol
        self.ovn_driver.listener_update(m_listener, m_listener)
        pool_status = [{'id': m_listener.default_pool_id,
                        'provisioning_status': 'ACTIVE'}]
        expected_status = {
            'listeners': [{'id': m_listener.listener_id,
                           'provisioning_status': 'ACTIVE',
                           'operating_status': operating_status}],
            'loadbalancers': [{"id": m_listener.loadbalancer_id,
                               "provisioning_status": "ACTIVE"}],
            'pools': pool_status}

        if old_admin_state_up != m_listener.admin_state_up:
            if m_listener.admin_state_up:
                oper_status = o_constants.ONLINE
            else:
                oper_status = o_constants.OFFLINE
            expected_status['listeners'][0]['operating_status'] = oper_status

        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _delete_listener_and_validate(self, lb_data, protocol='TCP',
                                      protocol_port=80):
        m_listener = self._get_listener_from_lb_data(
            lb_data, protocol, protocol_port)
        lb_data['listeners'].remove(m_listener)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.listener_delete(m_listener)
        expected_status = {
            'listeners': [{"id": m_listener.listener_id,
                           "provisioning_status": "DELETED",
                           "operating_status": "OFFLINE"}],
            'loadbalancers': [{"id": m_listener.loadbalancer_id,
                               "provisioning_status": "ACTIVE"}]}

        self._wait_for_status_and_validate(lb_data, [expected_status])
