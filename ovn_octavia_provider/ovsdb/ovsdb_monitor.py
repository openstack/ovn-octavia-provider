# Copyright 2020 Red Hat, Inc.
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

import abc

from oslo_config import cfg
from oslo_log import log
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp import event

from ovn_octavia_provider.common import config as ovn_config

CONF = cfg.CONF
LOG = log.getLogger(__name__)


class BaseOvnIdl(connection.OvsdbIdl):
    @classmethod
    def from_server(cls, connection_string, schema_name):
        _check_and_set_ssl_files(schema_name)
        helper = idlutils.get_schema_helper(connection_string, schema_name)
        helper.register_all()
        return cls(connection_string, helper)


class OvnIdl(BaseOvnIdl):

    def __init__(self, driver, remote, schema):
        super().__init__(remote, schema)
        self.driver = driver
        self.notify_handler = OvnDbNotifyHandler(driver)
        # ovsdb lock name to acquire.
        # This event lock is used to handle the notify events sent by idl.Idl
        # idl.Idl will call notify function for the "update" rpc method it
        # receives from the ovsdb-server.
        # This event lock is required for the following reasons
        #  - If there are multiple neutron servers running, OvnWorkers of
        #    these neutron servers would receive the notify events from
        #    idl.Idl
        #
        #  - we do not want all the neutron servers to handle these events
        #
        #  - only the neutron server which has the lock will handle the
        #    notify events.
        #
        #  - In case the neutron server which owns this lock goes down,
        #    ovsdb server would assign the lock to one of the other neutron
        #    servers.
        self.event_lock_name = "ovn_provider_driver_event_lock"

    def notify(self, event, row, updates=None):
        # Do not handle the notification if the event lock is requested,
        # but not granted by the ovsdb-server.
        if self.is_lock_contended:
            return
        row = idlutils.frozen_row(row)
        self.notify_handler.notify(event, row, updates)

    @abc.abstractmethod
    def post_connect(self):
        """Should be called after the idl has been initialized"""


class OvnDbNotifyHandler(event.RowEventHandler):
    def __init__(self, driver):
        super().__init__()
        self.driver = driver


def _check_and_set_ssl_files(schema_name):
    if schema_name == 'OVN_Northbound':
        priv_key_file = ovn_config.get_ovn_nb_private_key()
        cert_file = ovn_config.get_ovn_nb_certificate()
        ca_cert_file = ovn_config.get_ovn_nb_ca_cert()

        Stream.ssl_set_private_key_file(priv_key_file)
        Stream.ssl_set_certificate_file(cert_file)
        Stream.ssl_set_ca_cert_file(ca_cert_file)

    if schema_name == 'OVN_Southbound':
        priv_key_file = ovn_config.get_ovn_sb_private_key()
        cert_file = ovn_config.get_ovn_sb_certificate()
        ca_cert_file = ovn_config.get_ovn_sb_ca_cert()

        Stream.ssl_set_private_key_file(priv_key_file)
        Stream.ssl_set_certificate_file(cert_file)
        Stream.ssl_set_ca_cert_file(ca_cert_file)
