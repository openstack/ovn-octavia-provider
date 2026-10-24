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

from ovn_octavia_provider import event as ovn_event
from ovn_octavia_provider.tests.unit import base as ovn_base


class TestLoadBalancerMemberStatusEvent(ovn_base.TestOvnOctaviaBase):

    def setUp(self):
        super().setUp()
        self.driver = mock.Mock()
        self.sb_api = mock.Mock()
        self.event = ovn_event.LoadBalancerMemberStatusEvent(
            self.driver, self.sb_api)

    def test_match(self):
        row = mock.Mock(ip_port_mappings={'10.0.0.1': 'lsp:10.0.0.100'})
        self.assertTrue(self.event.match_fn(self.event.ROW_CREATE, row, None))
        self.assertTrue(self.event.match_fn(
            self.event.ROW_UPDATE, row, mock.Mock(spec=['external_ids'])))
        # Only a change of external_ids leaves a member without a status.
        self.assertFalse(self.event.match_fn(
            self.event.ROW_UPDATE, row, mock.Mock(spec=[])))
        # Without monitors there is nothing to replay.
        row.ip_port_mappings = {}
        self.assertFalse(self.event.match_fn(
            self.event.ROW_CREATE, row, None))

    def test_run(self):
        row = mock.Mock()
        self.event.run(self.event.ROW_UPDATE, row, mock.Mock())
        self.driver.lb_member_status_handler.assert_called_once_with(
            row, self.sb_api)
