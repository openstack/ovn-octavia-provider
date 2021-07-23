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
from oslo_utils import uuidutils

from ovn_octavia_provider.common import constants
from ovn_octavia_provider.common import utils


class FakeResource(dict):

    def __init__(self, manager=None, info=None, loaded=False, methods=None):
        """Set attributes and methods for a resource.

        :param manager:
            The resource manager
        :param Dictionary info:
            A dictionary with all attributes
        :param bool loaded:
            True if the resource is loaded in memory
        :param Dictionary methods:
            A dictionary with all methods
        """
        info = info or {}
        super().__init__(info)
        methods = methods or {}

        self.__name__ = type(self).__name__
        self.manager = manager
        self._info = info
        self._add_details(info)
        self._add_methods(methods)
        self._loaded = loaded
        # Add a revision number by default
        setattr(self, 'revision_number', 1)

    @property
    def db_obj(self):
        return self

    def _add_details(self, info):
        for (k, v) in info.items():
            setattr(self, k, v)

    def _add_methods(self, methods):
        """Fake methods with MagicMock objects.

        For each <@key, @value> pairs in methods, add an callable MagicMock
        object named @key as an attribute, and set the mock's return_value to
        @value. When users access the attribute with (), @value will be
        returned, which looks like a function call.
        """
        for (name, ret) in methods.items():
            method = mock.MagicMock(return_value=ret)
            setattr(self, name, method)

    def __repr__(self):
        reprkeys = sorted(k for k in self.__dict__.keys() if k[0] != '_' and
                          k != 'manager')
        info = ", ".join("%s=%s" % (k, getattr(self, k)) for k in reprkeys)
        return "<%s %s>" % (self.__class__.__name__, info)

    def keys(self):
        return self._info.keys()

    def info(self):
        return self._info

    def update(self, info):
        super().update(info)
        self._add_details(info)


class FakeOvsdbRow(FakeResource):
    """Fake one or more OVSDB rows."""

    @staticmethod
    def create_one_ovsdb_row(attrs=None, methods=None):
        """Create a fake OVSDB row.

        :param Dictionary attrs:
            A dictionary with all attributes
        :param Dictionary methods:
            A dictionary with all methods
        :return:
            A FakeResource object faking the OVSDB row
        """
        attrs = attrs or {}
        methods = methods or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        ovsdb_row_attrs = {
            'uuid': fake_uuid,
            'name': 'name-' + fake_uuid,
            'external_ids': {},
        }

        # Set default methods.
        ovsdb_row_methods = {
            'addvalue': None,
            'delete': None,
            'delvalue': None,
            'verify': None,
            'setkey': None,
        }

        # Overwrite default attributes and methods.
        ovsdb_row_attrs.update(attrs)
        ovsdb_row_methods.update(methods)

        return FakeResource(info=copy.deepcopy(ovsdb_row_attrs),
                            loaded=True,
                            methods=copy.deepcopy(ovsdb_row_methods))


class FakeSubnet():
    """Fake one or more subnets."""

    @staticmethod
    def create_one_subnet(attrs=None):
        """Create a fake subnet.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the subnet
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        subnet_attrs = {
            'id': 'subnet-id-' + fake_uuid,
            'name': 'subnet-name-' + fake_uuid,
            'network_id': 'network-id-' + fake_uuid,
            'cidr': '10.10.10.0/24',
            'tenant_id': 'project-id-' + fake_uuid,
            'enable_dhcp': True,
            'dns_nameservers': [],
            'allocation_pools': [],
            'host_routes': [],
            'ip_version': 4,
            'gateway_ip': '10.10.10.1',
            'ipv6_address_mode': 'None',
            'ipv6_ra_mode': 'None',
            'subnetpool_id': None,
        }

        # Overwrite default attributes.
        subnet_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(subnet_attrs),
                            loaded=True)


class FakeOVNPort():
    """Fake one or more ports."""

    @staticmethod
    def create_one_port(attrs=None):
        """Create a fake ovn port.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the port
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        port_attrs = {
            'addresses': [],
            'dhcpv4_options': '',
            'dhcpv6_options': [],
            'enabled': True,
            'external_ids': {},
            'name': fake_uuid,
            'options': {},
            'parent_name': [],
            'port_security': [],
            'tag': [],
            'tag_request': [],
            'type': '',
            'up': False,
        }

        # Overwrite default attributes.
        port_attrs.update(attrs)
        return type('Logical_Switch_Port', (object, ), port_attrs)

    @staticmethod
    def from_neutron_port(port):
        """Create a fake ovn port based on a neutron port."""
        external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY:
                utils.ovn_name(port['network_id']),
            constants.OVN_SG_IDS_EXT_ID_KEY:
                ' '.join(port['security_groups']),
            constants.OVN_DEVICE_OWNER_EXT_ID_KEY:
                port.get('device_owner', '')}
        addresses = [port['mac_address'], ]
        addresses += [x['ip_address'] for x in port.get('fixed_ips', [])]
        port_security = (
            addresses + [x['ip_address'] for x in
                         port.get('allowed_address_pairs', [])])
        return FakeOVNPort.create_one_port(
            {'external_ids': external_ids, 'addresses': addresses,
             'port_security': port_security})


class FakeOVNRouter():

    @staticmethod
    def create_one_router(attrs=None):
        router_attrs = {
            'enabled': False,
            'external_ids': {},
            'load_balancer': [],
            'name': '',
            'nat': [],
            'options': {},
            'ports': [],
            'static_routes': [],
        }

        # Overwrite default attributes.
        router_attrs.update(attrs)
        return type('Logical_Router', (object, ), router_attrs)


class FakePort():
    """Fake one or more ports."""

    @staticmethod
    def create_one_port(attrs=None):
        """Create a fake port.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the port
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        port_attrs = {
            'admin_state_up': True,
            'allowed_address_pairs': [{}],
            'binding:host_id': 'binding-host-id-' + fake_uuid,
            'binding:profile': {},
            'binding:vif_details': {},
            'binding:vif_type': 'ovs',
            'binding:vnic_type': 'normal',
            'device_id': 'device-id-' + fake_uuid,
            'device_owner': 'compute:nova',
            'dns_assignment': [{}],
            'dns_name': 'dns-name-' + fake_uuid,
            'extra_dhcp_opts': [{}],
            'fixed_ips': [{'subnet_id': 'subnet-id-' + fake_uuid,
                           'ip_address': '10.10.10.20'}],
            'id': 'port-id-' + fake_uuid,
            'mac_address': 'fa:16:3e:a9:4e:72',
            'name': 'port-name-' + fake_uuid,
            'network_id': 'network-id-' + fake_uuid,
            'port_security_enabled': True,
            'security_groups': [],
            'status': 'ACTIVE',
            'tenant_id': 'project-id-' + fake_uuid,
        }

        # Overwrite default attributes.
        port_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(port_attrs),
                            loaded=True)


class FakeLB(data_models.LoadBalancer):
    def __init__(self, *args, **kwargs):
        self.external_ids = kwargs.pop('ext_ids')
        self.uuid = kwargs.pop('uuid')
        super().__init__(*args, **kwargs)

    def __hash__(self):
        # Required for Python3, not for Python2
        return self.__sizeof__()


class FakePool(data_models.Pool):
    def __init__(self, *args, **kwargs):
        self.uuid = kwargs.pop('uuid')
        super().__init__(*args, **kwargs)

    def __hash__(self):
        # Required for Python3, not for Python2
        return self.__sizeof__()


class FakeMember(data_models.Member):
    def __init__(self, *args, **kwargs):
        self.uuid = kwargs.pop('uuid')
        super().__init__(*args, **kwargs)

    def __hash__(self):
        # Required for Python3, not for Python2
        return self.__sizeof__()
