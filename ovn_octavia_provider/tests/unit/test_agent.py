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

from ovn_octavia_provider import agent as ovn_agent
from ovn_octavia_provider.tests.unit import base as ovn_base


class TestOvnProviderAgent(ovn_base.TestOvnOctaviaBase):

    def test_exit(self):
        mock_exit_event = mock.MagicMock()
        mock_exit_event.is_set.side_effect = [False, False, False, False, True]
        ovn_agent.OvnProviderAgent(mock_exit_event)
        self.assertEqual(1, mock_exit_event.wait.call_count)
        self.assertEqual(2, self.mock_ovn_nb_idl.call_count)
        self.assertEqual(1, self.mock_ovn_sb_idl.call_count)
