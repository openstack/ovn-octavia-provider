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

from neutron.tests import base
from octavia_lib.api.drivers import driver_lib
from oslo_utils import uuidutils


class TestOvnOctaviaBase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.listener_id = uuidutils.generate_uuid()
        self.loadbalancer_id = uuidutils.generate_uuid()
        self.pool_id = uuidutils.generate_uuid()
        self.member_id = uuidutils.generate_uuid()
        self.member_subnet_id = uuidutils.generate_uuid()
        self.member_port = '1010'
        self.member_pool_id = self.pool_id
        self.member_address = '192.168.2.149'
        self.port1_id = uuidutils.generate_uuid()
        self.port2_id = uuidutils.generate_uuid()
        self.project_id = uuidutils.generate_uuid()
        self.vip_network_id = uuidutils.generate_uuid()
        self.vip_port_id = uuidutils.generate_uuid()
        self.vip_subnet_id = uuidutils.generate_uuid()
        self.healthmonitor_id = uuidutils.generate_uuid()
        ovn_nb_idl = mock.patch(
            'ovn_octavia_provider.ovsdb.impl_idl_ovn.OvnNbIdlForLb')
        self.mock_ovn_nb_idl = ovn_nb_idl.start()
        ovn_sb_idl = mock.patch(
            'ovn_octavia_provider.ovsdb.impl_idl_ovn.OvnSbIdlForLb')
        self.mock_ovn_sb_idl = ovn_sb_idl.start()
        self.member_address = '192.168.2.149'
        self.vip_address = '192.148.210.109'
        self.vip_dict = {'vip_network_id': uuidutils.generate_uuid(),
                         'vip_subnet_id': uuidutils.generate_uuid()}
        self.vip_output = {'vip_network_id': self.vip_dict['vip_network_id'],
                           'vip_subnet_id': self.vip_dict['vip_subnet_id']}
        mock.patch(
            'ovsdbapp.backend.ovs_idl.idlutils.get_schema_helper').start()
        mock.patch.object(
            driver_lib.DriverLibrary, '_check_for_socket_ready').start()
