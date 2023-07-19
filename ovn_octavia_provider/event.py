#    Copyright 2020 Red Hat, Inc. All rights reserved.
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

from oslo_log import log as logging
from ovsdbapp.backend.ovs_idl import event as row_event

# TODO(mjozefcz): Start consuming const and utils
# from neutron-lib once released.
from ovn_octavia_provider.common import constants as ovn_const

LOG = logging.getLogger(__name__)


class LogicalRouterPortEvent(row_event.RowEvent):

    def __init__(self, driver):
        table = 'Logical_Router_Port'
        events = (self.ROW_CREATE, self.ROW_DELETE)
        super().__init__(events, table, None)
        self.event_name = 'LogicalRouterPortEvent'
        self.driver = driver

    def run(self, event, row, old):
        LOG.debug('LogicalRouterPortEvent logged, '
                  '%(event)s, %(row)s',
                  {'event': event,
                   'row': row})
        if event == self.ROW_CREATE:
            self.driver.lb_create_lrp_assoc_handler(row)
        elif event == self.ROW_DELETE:
            self.driver.lb_delete_lrp_assoc_handler(row)


class LogicalSwitchPortUpdateEvent(row_event.RowEvent):

    def __init__(self, driver):
        table = 'Logical_Switch_Port'
        events = (self.ROW_UPDATE,)
        super().__init__(events, table, None)
        self.event_name = 'LogicalSwitchPortUpdateEvent'
        self.driver = driver

    def match_fn(self, event, row, old):
        port_name = row.external_ids.get(
            ovn_const.OVN_PORT_NAME_EXT_ID_KEY, '')
        if hasattr(old, 'external_ids') and port_name.startswith(
                ovn_const.LB_VIP_PORT_PREFIX):
            return True
        return False

    def run(self, event, row, old):
        LOG.debug('LogicalSwitchPortUpdateEvent logged, '
                  '%(event)s, %(row)s',
                  {'event': event,
                   'row': row})
        fip_old = old.external_ids.get(ovn_const.OVN_PORT_FIP_EXT_ID_KEY)
        fip_new = row.external_ids.get(ovn_const.OVN_PORT_FIP_EXT_ID_KEY)
        if fip_old != fip_new:
            if fip_old and fip_new is None:
                action = ovn_const.REQ_INFO_ACTION_DISASSOCIATE
                fip = fip_old
            else:
                action = ovn_const.REQ_INFO_ACTION_ASSOCIATE
                fip = fip_new
            self.driver.vip_port_update_handler(row, fip, action)


class ServiceMonitorUpdateEvent(row_event.RowEvent):

    def __init__(self, driver):
        table = 'Service_Monitor'
        events = (self.ROW_UPDATE, self.ROW_DELETE)
        super().__init__(events, table, None)
        self.event_name = 'ServiceMonitorUpdateEvent'
        self.driver = driver

    def run(self, event, row, old):
        LOG.debug('ServiceMonitorUpdateEvent logged, '
                  '%(event)s, %(row)s',
                  {'event': event,
                   'row': row})
        if event == self.ROW_DELETE:
            self.driver.sm_update_event_handler(row, sm_delete_event=True)
        elif event == self.ROW_UPDATE:
            self.driver.sm_update_event_handler(row)
