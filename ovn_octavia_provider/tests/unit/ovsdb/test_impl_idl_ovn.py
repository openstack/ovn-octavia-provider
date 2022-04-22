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

import os
from unittest import mock

from neutron.tests import base
from ovs.db import idl as ovs_idl
from ovsdbapp.backend import ovs_idl as real_ovs_idl
from ovsdbapp.backend.ovs_idl import idlutils

from ovn_octavia_provider.common import config as ovn_config
from ovn_octavia_provider.ovsdb import impl_idl_ovn

basedir = os.path.dirname(os.path.abspath(__file__))
schema_files = {
    'OVN_Northbound': os.path.join(basedir,
                                   '..', 'schemas', 'ovn-nb.ovsschema'),
    'OVN_Southbound': os.path.join(basedir,
                                   '..', 'schemas', 'ovn-sb.ovsschema')}


class TestOvnNbIdlForLb(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        ovn_config.register_opts()
        # TODO(haleyb) - figure out why every test in this class generates
        # this warning, think it's in relation to reading this schema file:
        # sys:1: ResourceWarning: unclosed file <_io.FileIO name=1 mode='wb'
        # closefd=True> ResourceWarning: Enable tracemalloc to get the object
        # allocation traceback
        self.mock_gsh = mock.patch.object(
            idlutils, 'get_schema_helper',
            side_effect=lambda x, y: ovs_idl.SchemaHelper(
                location=schema_files['OVN_Northbound'])).start()
        self.idl = impl_idl_ovn.OvnNbIdlForLb()

    def test__get_ovsdb_helper(self):
        self.mock_gsh.reset_mock()
        self.idl._get_ovsdb_helper('foo')
        self.mock_gsh.assert_called_once_with('foo', 'OVN_Northbound')

    @mock.patch.object(real_ovs_idl.Backend, 'autocreate_indices', mock.Mock(),
                       create=True)
    def test_start(self):
        with mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection',
                        side_effect=lambda x, timeout: mock.Mock()):
            idl1 = impl_idl_ovn.OvnNbIdlForLb()
            ret1 = idl1.start()
            id1 = id(ret1.ovsdb_connection)
            idl2 = impl_idl_ovn.OvnNbIdlForLb()
            ret2 = idl2.start()
            id2 = id(ret2.ovsdb_connection)
            self.assertNotEqual(id1, id2)

    @mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection')
    def test_stop(self, mock_conn):
        mock_conn.stop.return_value = False
        with (
            mock.patch.object(
                self.idl.notify_handler, 'shutdown')) as mock_notify, (
                mock.patch.object(self.idl, 'close')) as mock_close:
            self.idl.start()
            self.idl.stop()
        mock_notify.assert_called_once_with()
        mock_close.assert_called_once_with()

    @mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection')
    def test_stop_no_connection(self, mock_conn):
        mock_conn.stop.return_value = False
        with (
            mock.patch.object(
                self.idl.notify_handler, 'shutdown')) as mock_notify, (
                mock.patch.object(self.idl, 'close')) as mock_close:
            self.idl.stop()
        mock_notify.assert_called_once_with()
        mock_close.assert_called_once_with()

    def test_setlock(self):
        with mock.patch.object(impl_idl_ovn.OvnNbIdlForLb,
                               'set_lock') as set_lock:
            self.idl = impl_idl_ovn.OvnNbIdlForLb(event_lock_name='foo')
        set_lock.assert_called_once_with('foo')


class TestOvnSbIdlForLb(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        ovn_config.register_opts()
        # TODO(haleyb) - figure out why every test in this class generates
        # this warning, think it's in relation to reading this schema file:
        # sys:1: ResourceWarning: unclosed file <_io.FileIO name=1 mode='wb'
        # closefd=True> ResourceWarning: Enable tracemalloc to get the object
        # allocation traceback
        self.mock_gsh = mock.patch.object(
            idlutils, 'get_schema_helper',
            side_effect=lambda x, y: ovs_idl.SchemaHelper(
                location=schema_files['OVN_Southbound'])).start()
        self.idl = impl_idl_ovn.OvnSbIdlForLb()

    @mock.patch.object(real_ovs_idl.Backend, 'autocreate_indices', mock.Mock(),
                       create=True)
    def test_start(self):
        with mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection',
                        side_effect=lambda x, timeout: mock.Mock()):
            idl1 = impl_idl_ovn.OvnSbIdlForLb()
            ret1 = idl1.start()
            id1 = id(ret1.ovsdb_connection)
            idl2 = impl_idl_ovn.OvnSbIdlForLb()
            ret2 = idl2.start()
            id2 = id(ret2.ovsdb_connection)
            self.assertNotEqual(id1, id2)

    @mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection')
    def test_stop(self, mock_conn):
        mock_conn.stop.return_value = False
        with (
            mock.patch.object(
                self.idl.notify_handler, 'shutdown')) as mock_notify, (
                mock.patch.object(self.idl, 'close')) as mock_close:
            self.idl.start()
            self.idl.stop()
        mock_notify.assert_called_once_with()
        mock_close.assert_called_once_with()

    @mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection')
    def test_stop_no_connection(self, mock_conn):
        mock_conn.stop.return_value = False
        with (
            mock.patch.object(
                self.idl.notify_handler, 'shutdown')) as mock_notify, (
                mock.patch.object(self.idl, 'close')) as mock_close:
            self.idl.stop()
        mock_notify.assert_called_once_with()
        mock_close.assert_called_once_with()

    def test_setlock(self):
        with mock.patch.object(impl_idl_ovn.OvnSbIdlForLb,
                               'set_lock') as set_lock:
            self.idl = impl_idl_ovn.OvnSbIdlForLb(event_lock_name='foo')
        set_lock.assert_called_once_with('foo')
