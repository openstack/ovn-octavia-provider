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

from keystoneauth1 import exceptions as ks_exceptions
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslotest import base

from ovn_octavia_provider.common import clients
from ovn_octavia_provider.common import config


class TestKeystoneSession(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        config.register_opts()
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

    @mock.patch(
        'keystoneauth1.loading.load_auth_from_conf_options')
    def test_auth(self, kl_auth):
        missing_options = [mock.Mock(dest='username')]
        auth = mock.Mock()

        # service_auth with missing option
        kl_auth.side_effect = [
            ks_exceptions.auth_plugins.MissingRequiredOptions(missing_options)
        ]

        ksession = clients.KeystoneSession()
        self.assertRaises(
            ks_exceptions.auth_plugins.MissingRequiredOptions,
            lambda: ksession.auth)

        # neutron with missing option, missing option also in service_auth
        kl_auth.reset_mock()
        kl_auth.side_effect = [
            ks_exceptions.auth_plugins.MissingRequiredOptions(missing_options),
            auth,
            ks_exceptions.auth_plugins.MissingRequiredOptions(missing_options),
        ]

        ksession = clients.KeystoneSession('neutron')
        self.assertRaises(
            ks_exceptions.auth_plugins.MissingRequiredOptions,
            lambda: ksession.auth)

        # neutron with missing option, it is copied from service_auth
        kl_auth.reset_mock()
        kl_auth.side_effect = [
            ks_exceptions.auth_plugins.MissingRequiredOptions(missing_options),
            auth,
            auth,
        ]

        self.conf.config(group='service_auth',
                         endpoint_override='foo')

        ksession = clients.KeystoneSession('neutron')
        self.assertEqual(ksession.auth, auth)
        self.assertEqual(cfg.CONF.neutron.endpoint_override, 'foo')

    @mock.patch(
        'keystoneauth1.loading.load_session_from_conf_options')
    @mock.patch(
        'keystoneauth1.loading.load_auth_from_conf_options')
    def test_cached_session(self, kl_auth, kl_session):
        ksession = clients.KeystoneSession('neutron')
        self.assertIs(
            ksession.session,
            ksession.session)
        kl_session.assert_called_once_with(
            mock.ANY, 'neutron', auth=ksession.auth)

    @mock.patch(
        'keystoneauth1.loading.load_auth_from_conf_options')
    def test_cached_auth(self, kl):
        ksession = clients.KeystoneSession('neutron')
        self.assertIs(
            ksession.auth,
            ksession.auth)
        kl.assert_called_once_with(mock.ANY, 'neutron')


class TestNeutronAuth(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        config.register_opts()
        self.mock_client = mock.patch(
            'openstack.connection.Connection').start()
        clients.Singleton._instances = {}

    @mock.patch.object(clients, 'KeystoneSession')
    def test_init(self, mock_ks):
        clients.NeutronAuth()
        self.mock_client.assert_called_once_with(
            session=mock_ks().session)

    def test_singleton(self):
        c1 = clients.NeutronAuth()
        c2 = clients.NeutronAuth()
        self.assertIs(c1, c2)

    def test_singleton_exception(self):
        mock_client = mock.Mock()
        mock_client.network_proxy = 'foo'
        with mock.patch(
            'openstack.connection.Connection',
                side_effect=[RuntimeError,
                             mock_client, mock_client]) as os_sdk:
            self.assertRaises(
                RuntimeError,
                clients.NeutronAuth)
            c2 = clients.NeutronAuth()
            c3 = clients.NeutronAuth()
            self.assertIs(c2, c3)
            self.assertEqual(os_sdk._mock_call_count, 2)
