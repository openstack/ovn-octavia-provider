# Copyright 2022 Red Hat, Inc.
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
#

from unittest import mock

from neutron.tests import base

from ovn_octavia_provider.common import config as ovn_config
from ovn_octavia_provider.common import utils


class TestRetryDecorator(base.BaseTestCase):
    DEFAULT_RETRY_VALUE = 10

    def setUp(self):
        super().setUp()
        mock.patch.object(
            ovn_config, "get_ovn_ovsdb_retry_max_interval",
            return_value=self.DEFAULT_RETRY_VALUE).start()

    def test_default_retry_value(self):
        with mock.patch('tenacity.wait_exponential') as m_wait:
            @utils.retry()
            def decorated_method():
                pass

            decorated_method()
        m_wait.assert_called_with(max=self.DEFAULT_RETRY_VALUE)

    def test_custom_retry_value(self):
        custom_value = 3
        with mock.patch('tenacity.wait_exponential') as m_wait:
            @utils.retry(max_=custom_value)
            def decorated_method():
                pass

            decorated_method()
        m_wait.assert_called_with(max=custom_value)

    def test_positive_result(self):
        number_of_exceptions = 3
        method = mock.Mock(
            side_effect=[Exception() for i in range(number_of_exceptions)])

        @utils.retry(max_=0.001)
        def decorated_method():
            try:
                method()
            except StopIteration:
                return

        decorated_method()

        # number of exceptions + one successful call
        self.assertEqual(number_of_exceptions + 1, method.call_count)
