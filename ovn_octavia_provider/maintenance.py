#    Copyright 2023 Red Hat, Inc. All rights reserved.
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

import inspect
import threading

from futurist import periodics
from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log as logging

from ovn_octavia_provider.common import clients
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider.ovsdb import impl_idl_ovn

CONF = cfg.CONF  # Gets Octavia Conf as it runs under o-api domain

LOG = logging.getLogger(__name__)


class MaintenanceThread(object):

    def __init__(self):
        self._callables = []
        self._thread = None
        self._worker = None

    def add_periodics(self, obj):
        for name, member in inspect.getmembers(obj):
            if periodics.is_periodic(member):
                LOG.info('Periodic task found: %(owner)s.%(member)s',
                         {'owner': obj.__class__.__name__, 'member': name})
                self._callables.append((member, (), {}))

    def start(self):
        if self._thread is None:
            self._worker = periodics.PeriodicWorker(self._callables)
            self._thread = threading.Thread(target=self._worker.start)
            self._thread.daemon = True
            self._thread.start()

    def stop(self):
        self._worker.stop()
        self._worker.wait()
        self._thread.join()
        self._worker = self._thread = None


class DBInconsistenciesPeriodics(object):

    def __init__(self):
        self.ovn_nbdb = impl_idl_ovn.OvnNbIdlForLb()
        self.ovn_nbdb_api = self.ovn_nbdb.start()

    @periodics.periodic(spacing=600, run_immediately=True)
    def change_device_owner_lb_hm_ports(self):
        """Change the device_owner for the OVN LB HM port existing.

        The OVN LB HM port used for send the health checks to the backend
        members has a new device_owner, it will use the value
        onv-lb-hm:distributed in order to keep the behaviour on Neutron as a
        LOCALPORT. Also this change will add device-id as ovn-lb-hm:{subnet}
        to get more robust.
        """
        LOG.debug('Maintenance task: checking device_owner for OVN LB HM '
                  'ports.')
        neutron_client = clients.get_neutron_client()
        ovn_lb_hm_ports = neutron_client.list_ports(**{
            'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED})

        check_neutron_support_new_device_owner = True
        for port in ovn_lb_hm_ports['ports']:
            if port['name'].startswith('ovn-lb-hm'):
                LOG.debug('Maintenance task: updating device_owner and '
                          'adding device_id for port id %s', port['id'])
                update_port_info = {
                    'port': {
                        'device_owner': ovn_const.OVN_LB_HM_PORT_DISTRIBUTED,
                        'device_id': port['name']
                    }
                }
                neutron_client.update_port(port['id'], update_port_info)
                # NOTE(froyo): Check that the port is now of type LOCALPORT in
                # the OVN NB DB or perform a rollback in other cases. Such
                # cases could indicate that Neutron is in the process of being
                # updated or that the user has forgotten to update Neutron to a
                # version that supports this change
                if check_neutron_support_new_device_owner:
                    port_ovn = self.ovn_nbdb_api.db_find_rows(
                        "Logical_Switch_Port",
                        ("name", "=", port['id'])).execute(check_error=True)
                    if len(port_ovn) and port_ovn[0].type != 'localport':
                        LOG.debug('Maintenance task: port %s updated but '
                                  'looks like Neutron does not support this '
                                  'new device_owner, or maybe is updating '
                                  'version, so restoring to old values and '
                                  'waiting another iteration of this task',
                                  port['id'])
                        update_port_info = {
                            'port': {
                                'device_owner':
                                    n_const.DEVICE_OWNER_DISTRIBUTED,
                                'device_id': ''
                            }
                        }
                        neutron_client.update_port(port['id'],
                                                   update_port_info)
                        # Break the loop as do not make sense change the rest
                        break
                    check_neutron_support_new_device_owner = False
        else:
            # NOTE(froyo): No ports found to update, or all of them done.
            LOG.debug('Maintenance task: no more ports left, stopping the '
                      'periodic task.')
            raise periodics.NeverAgain()
        LOG.debug('Maintenance task: device_owner and device_id checked for '
                  'OVN LB HM ports.')
