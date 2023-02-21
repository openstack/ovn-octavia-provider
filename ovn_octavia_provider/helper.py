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

import copy
import queue
import re
import threading

import netaddr
from neutron_lib.api.definitions import provider_net
from neutron_lib import constants as n_const
from neutronclient.common import exceptions as n_exc
from octavia_lib.api.drivers import data_models as o_datamodels
from octavia_lib.api.drivers import driver_lib as o_driver_lib
from octavia_lib.api.drivers import exceptions as driver_exceptions
from octavia_lib.common import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.schema.ovn_northbound import commands as cmd

import tenacity

from ovn_octavia_provider.common import clients
from ovn_octavia_provider.common import config as ovn_conf
# TODO(mjozefcz): Start consuming const and utils
# from neutron-lib once released.
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider.common import utils
from ovn_octavia_provider.i18n import _
from ovn_octavia_provider.ovsdb import impl_idl_ovn

CONF = cfg.CONF  # Gets Octavia Conf as it runs under o-api domain

LOG = logging.getLogger(__name__)


class OvnProviderHelper():

    def __init__(self):
        self.requests = queue.Queue()
        self.helper_thread = threading.Thread(target=self.request_handler)
        self.helper_thread.daemon = True
        self._octavia_driver_lib = o_driver_lib.DriverLibrary()
        self._check_and_set_ssl_files()
        self._init_lb_actions()

        # NOTE(mjozefcz): This API is only for handling octavia API requests.
        self.ovn_nbdb = impl_idl_ovn.OvnNbIdlForLb()
        self.ovn_nbdb_api = self.ovn_nbdb.start()

        self.helper_thread.start()

    def _init_lb_actions(self):
        self._lb_request_func_maps = {
            ovn_const.REQ_TYPE_LB_CREATE: self.lb_create,
            ovn_const.REQ_TYPE_LB_DELETE: self.lb_delete,
            ovn_const.REQ_TYPE_LB_UPDATE: self.lb_update,
            ovn_const.REQ_TYPE_LISTENER_CREATE: self.listener_create,
            ovn_const.REQ_TYPE_LISTENER_DELETE: self.listener_delete,
            ovn_const.REQ_TYPE_LISTENER_UPDATE: self.listener_update,
            ovn_const.REQ_TYPE_POOL_CREATE: self.pool_create,
            ovn_const.REQ_TYPE_POOL_DELETE: self.pool_delete,
            ovn_const.REQ_TYPE_POOL_UPDATE: self.pool_update,
            ovn_const.REQ_TYPE_MEMBER_CREATE: self.member_create,
            ovn_const.REQ_TYPE_MEMBER_DELETE: self.member_delete,
            ovn_const.REQ_TYPE_MEMBER_UPDATE: self.member_update,
            ovn_const.REQ_TYPE_LB_CREATE_LRP_ASSOC: self.lb_create_lrp_assoc,
            ovn_const.REQ_TYPE_LB_DELETE_LRP_ASSOC: self.lb_delete_lrp_assoc,
            ovn_const.REQ_TYPE_HANDLE_VIP_FIP: self.handle_vip_fip,
            ovn_const.REQ_TYPE_HANDLE_MEMBER_DVR: self.handle_member_dvr,
            ovn_const.REQ_TYPE_HM_CREATE: self.hm_create,
            ovn_const.REQ_TYPE_HM_UPDATE: self.hm_update,
            ovn_const.REQ_TYPE_HM_DELETE: self.hm_delete,
            ovn_const.REQ_TYPE_HM_UPDATE_EVENT: self.hm_update_event,
        }

    @staticmethod
    def _is_lb_empty(external_ids):
        """Check if there is no pool or listener defined."""
        return not any(k.startswith('listener') or k.startswith('pool')
                       for k in external_ids)

    @staticmethod
    def _delete_disabled_from_status(status):
        # pylint: disable=multiple-statements
        d_regex = f':{ovn_const.DISABLED_RESOURCE_SUFFIX}$'
        return {
            k: [{c: re.sub(d_regex, '', d) for c, d in i.items()}
                for i in v]
            for k, v in status.items()}

    def _check_and_set_ssl_files(self):
        # TODO(reedip): Make ovsdb_monitor's _check_and_set_ssl_files() public
        # This is a copy of ovsdb_monitor._check_and_set_ssl_files
        priv_key_file = ovn_conf.get_ovn_nb_private_key()
        cert_file = ovn_conf.get_ovn_nb_certificate()
        ca_cert_file = ovn_conf.get_ovn_nb_ca_cert()
        if priv_key_file:
            Stream.ssl_set_private_key_file(priv_key_file)

        if cert_file:
            Stream.ssl_set_certificate_file(cert_file)

        if ca_cert_file:
            Stream.ssl_set_ca_cert_file(ca_cert_file)

    def shutdown(self):
        self.requests.put({'type': ovn_const.REQ_TYPE_EXIT})
        self.helper_thread.join()
        self.ovn_nbdb.stop()
        del self.ovn_nbdb_api

    @staticmethod
    def _map_val(row, col, key):
        # If the row doesnt exist, RowNotFound is raised by the _map_val
        # and is expected to be caught by the caller.
        try:
            return getattr(row, col)[key]
        except KeyError as e:
            raise idlutils.RowNotFound(table=row._table.name,
                                       col=col, match=key) from e

    def _create_hm_port(self, network_id, subnet_id, project_id):
        port = {'port': {'name': ovn_const.LB_HM_PORT_PREFIX + str(subnet_id),
                         'network_id': network_id,
                         'fixed_ips': [{'subnet_id': subnet_id}],
                         'admin_state_up': True,
                         'port_security_enabled': False,
                         'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
                         'project_id': project_id}}
        neutron_client = clients.get_neutron_client()
        try:
            hm_port = neutron_client.create_port(port)
            return hm_port['port'] if hm_port['port'] else None
        except n_exc.NeutronClientException:
            # NOTE (froyo): whatever other exception as e.g. Timeout
            # we should try to ensure no leftover port remains
            self._clean_up_hm_port(subnet_id)
            return None

    def _clean_up_hm_port(self, subnet_id):
        # Method to delete the hm port created for subnet_id it there isn't any
        # other health monitor using it
        neutron_client = clients.get_neutron_client()
        hm_port_ip = None

        hm_checks_port = self._neutron_list_ports(neutron_client, **{
            'name': f'{ovn_const.LB_HM_PORT_PREFIX}{subnet_id}'})
        if hm_checks_port['ports']:
            # NOTE(froyo): Just to cover the case that we have more than one
            # hm-port created by a race condition on create_hm_port and we need
            # to ensure no leftover ports remains
            for hm_port in hm_checks_port['ports']:
                for fixed_ip in hm_port.get('fixed_ips', []):
                    if fixed_ip['subnet_id'] == subnet_id:
                        hm_port_ip = fixed_ip['ip_address']

                if hm_port_ip:
                    lbs = self.ovn_nbdb_api.db_find_rows(
                        'Load_Balancer', ('health_check', '!=', [])).execute()
                    for lb in lbs:
                        for k, v in lb.ip_port_mappings.items():
                            if hm_port_ip in v:
                                return
                    # Not found any other health monitor using the hm port
                    self.delete_port(hm_port['id'])

    def _ensure_hm_ovn_port(self, network_id, subnet_id, project_id):
        # We will use a dedicated port for this, so we should find the one
        # related to the network id, if not found, create a new one and use it.

        neutron_client = clients.get_neutron_client()
        hm_checks_port = self._neutron_list_ports(neutron_client, **{
            'network_id': network_id,
            'name': f'{ovn_const.LB_HM_PORT_PREFIX}{subnet_id}'})
        if hm_checks_port['ports']:
            return hm_checks_port['ports'][0]
        else:
            return self._create_hm_port(network_id, subnet_id, project_id)

    def _get_nw_router_info_on_interface_event(self, lrp):
        """Get the Router and Network information on an interface event

        This function is called when a new interface between a router and
        a network is added or deleted.
        Input: Logical Router Port row which is coming from
               LogicalRouterPortEvent.
        Output: A row from router table and network table matching the router
                and network for which the event was generated.
        Exception: RowNotFound exception can be generated.
        """
        router = self.ovn_nbdb_api.lookup(
            'Logical_Router', utils.ovn_name(self._map_val(
                lrp, 'external_ids', ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY)))
        network = self.ovn_nbdb_api.lookup(
            'Logical_Switch',
            self._map_val(lrp, 'external_ids',
                          ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY))
        return router, network

    def _clean_lb_if_empty(self, ovn_lb, lb_id, external_ids):
        commands = []
        lb_to_delete = False
        if OvnProviderHelper._is_lb_empty(external_ids):
            # Verify if its only OVN LB defined. If so - leave with
            # undefined protocol. If there is different for other protocol
            # remove this one.
            try:
                defined_ovn_lbs = self._find_ovn_lbs(lb_id)
            except idlutils.RowNotFound:
                defined_ovn_lbs = []
            if len(defined_ovn_lbs) == 1:
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid, ('protocol', [])))
            elif len(defined_ovn_lbs) > 1:
                # Delete the lb.
                commands.append(self.ovn_nbdb_api.lb_del(ovn_lb.uuid))
                lb_to_delete = True
        return (commands, lb_to_delete)

    def lb_delete_lrp_assoc_handler(self, row):
        try:
            router, network = self._get_nw_router_info_on_interface_event(row)
        except idlutils.RowNotFound:
            LOG.debug("Router or network information not found")
            return
        request_info = {'network': network,
                        'router': router}
        self.add_request({'type': ovn_const.REQ_TYPE_LB_DELETE_LRP_ASSOC,
                          'info': request_info})

    def lb_delete_lrp_assoc(self, info):
        # TODO(reedip): When OVS>=2.12, LB can be deleted without removing
        # Network and Router references as pushed in the patch
        # https://github.com/openvswitch/ovs/commit
        # /612f80fa8ebf88dad2e204364c6c02b451dca36c
        network = info['network']
        router = info['router']

        # Find all loadbalancers which have a reference with the network
        nw_lb = self._find_lb_in_ls(network=network)
        # Find all loadbalancers which have a reference with the router
        r_lb = set(router.load_balancer) - nw_lb
        # Delete all LB on N/W from Router
        for nlb in nw_lb:
            try:
                self._update_lb_to_lr_association(nlb, router, delete=True)
            except idlutils.RowNotFound:
                LOG.warning("The disassociation of loadbalancer %s to the "
                            "logical router %s failed, trying step by step",
                            nlb.uuid, router.uuid)
                self._update_lb_to_lr_association_by_step(
                    nlb, router, delete=True)

        # Delete all LB on Router from N/W
        for rlb in r_lb:
            try:
                self._update_lb_to_ls_association(
                    rlb,
                    network_id=utils.ovn_uuid(network.name),
                    associate=False,
                    update_ls_ref=False)
            except idlutils.RowNotFound:
                LOG.warning("The disassociation of loadbalancer %s to the "
                            "logical switch %s failed, just keep going on",
                            rlb.uuid, utils.ovn_uuid(network.name))
                pass

    def lb_create_lrp_assoc_handler(self, row):
        try:
            router, network = self._get_nw_router_info_on_interface_event(row)
        except idlutils.RowNotFound:
            LOG.debug("Router or network information not found")
            return
        request_info = {'network': network,
                        'router': router,
                        'gateway_chassis': row.gateway_chassis}
        self.add_request({'type': ovn_const.REQ_TYPE_LB_CREATE_LRP_ASSOC,
                          'info': request_info})

    def lb_create_lrp_assoc(self, info):
        router_lb = set(info['router'].load_balancer)
        network_lb = set(info['network'].load_balancer)
        # Add only those lb to routers which are unique to the network
        for lb in (network_lb - router_lb):
            try:
                self._update_lb_to_lr_association(lb, info['router'])
            except idlutils.RowNotFound:
                LOG.warning("The association of loadbalancer %s to the "
                            "logical router %s failed, trying step by step",
                            lb.uuid, info['router'].uuid)
                self._update_lb_to_lr_association_by_step(lb, info['router'])

        # if gateway_chassis ports, there is no need to re-add the
        # loadbalancers from the router into the provider network.
        # This will be already done for loadbalancer created with VIPs on
        # provider networks, regardless of the gateway_chassis lrp port
        # existence. And it should never be there when the VIPs are on
        # tenant networks.
        if info['gateway_chassis']:
            return

        # Add those lb to the network which are unique to the router
        for lb in (router_lb - network_lb):
            try:
                self._update_lb_to_ls_association(
                    lb,
                    network_id=utils.ovn_uuid(info['network'].name),
                    associate=True,
                    update_ls_ref=False)
            except idlutils.RowNotFound:
                LOG.warning("The association of loadbalancer %s to the "
                            "logical switch %s failed, just keep going on",
                            lb.uuid, utils.ovn_uuid(info['network'].name))
                pass

    def vip_port_update_handler(self, vip_lp):
        """Handler for VirtualIP port updates.

        If a floating ip is associated to a vip port, then networking-ovn sets
        the fip in the external_ids column of the logical port as:
        Logical_Switch_Port.external_ids:port_fip = <FIP>.
        Then, in the Load_Balancer table for the vip, networking-ovn creates
        another vip entry for the FIP.
        If a floating ip is disassociated from the vip, then it deletes
        the vip entry for the FIP.
        """

        port_name = vip_lp.external_ids.get(ovn_const.OVN_PORT_NAME_EXT_ID_KEY)
        lb_id = port_name[len(ovn_const.LB_VIP_PORT_PREFIX):]
        try:
            ovn_lbs = self._find_ovn_lbs_with_retry(lb_id)
        except idlutils.RowNotFound:
            LOG.debug("Loadbalancer %s not found!", lb_id)
            return

        # Loop over all defined LBs with given ID, because it is possible
        # than there is more than one (for more than 1 L4 protocol).
        for lb in ovn_lbs:
            fip = vip_lp.external_ids.get(ovn_const.OVN_PORT_FIP_EXT_ID_KEY)
            lb_vip_fip = lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
            request_info = {'ovn_lb': lb,
                            'vip_fip': fip}
            if fip and fip != lb_vip_fip:
                request_info['action'] = ovn_const.REQ_INFO_ACTION_ASSOCIATE
            elif fip is None and fip != lb_vip_fip:
                request_info['action'] = ovn_const.REQ_INFO_ACTION_DISASSOCIATE
            else:
                continue
            self.add_request({'type': ovn_const.REQ_TYPE_HANDLE_VIP_FIP,
                              'info': request_info})

    def _find_lb_in_ls(self, network):
        """Find LB associated to a Network using Network information

        This function retrieves those loadbalancers whose ls_ref
        column in the OVN northbound database's load_balancer table
        has the network's name. Though different networks can be
        associated with a loadbalancer, but ls_ref of a loadbalancer
        points to the network where it was actually created, and this
        function tries to retrieve all those loadbalancers created on this
        network.
        Input : row of type Logical_Switch
        Output: set of rows of type Load_Balancer or empty set
        """
        return {lb for lb in network.load_balancer
                if network.name in lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_LS_REFS_KEY,
                    [])}

    def _find_lb_in_table(self, lb, table):
        return self.ovn_nbdb_api.find_lb_in_table(
            lb, table).execute(check_error=True)

    def request_handler(self):
        while True:
            request = self.requests.get()
            request_type = request['type']
            if request_type == ovn_const.REQ_TYPE_EXIT:
                break

            request_handler = self._lb_request_func_maps.get(request_type)
            try:
                if request_handler:
                    LOG.debug("Handling request %(req)s with info %(info)s",
                              {'req': request_type, 'info': request['info']})
                    status = request_handler(request['info'])
                    if status:
                        self._update_status_to_octavia(status)
                self.requests.task_done()
            except driver_exceptions.UpdateStatusError as e:
                LOG.error("Error while updating the load balancer status: %s",
                          e.fault_string)
                # TODO(haleyb): The resource(s) we were updating status for
                # should be cleaned-up
            except Exception:
                # If any unexpected exception happens we don't want the
                # notify_loop to exit.
                LOG.exception('Unexpected exception in request_handler')

    def add_request(self, req):
        self.requests.put(req)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(
            driver_exceptions.UpdateStatusError),
        wait=tenacity.wait_exponential(max=75),
        stop=tenacity.stop_after_attempt(15),
        reraise=True)
    def _update_status_to_octavia(self, status):
        status = OvnProviderHelper._delete_disabled_from_status(status)
        LOG.debug('Updating status to octavia: %s', status)
        self._octavia_driver_lib.update_loadbalancer_status(status)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(idlutils.RowNotFound),
        wait=tenacity.wait_exponential(),
        stop=tenacity.stop_after_delay(10),
        reraise=True)
    def _find_ovn_lbs_with_retry(self, lb_id, protocol=None):
        return self._find_ovn_lbs(lb_id, protocol=protocol)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(n_exc.NeutronClientException),
        wait=tenacity.wait_exponential(),
        stop=tenacity.stop_after_delay(10),
        reraise=True)
    def _neutron_list_ports(self, neutron_client, **params):
        return neutron_client.list_ports(**params)

    def _find_ovn_lbs(self, lb_id, protocol=None):
        """Find the Loadbalancers in OVN with the given lb_id as its name

        This function searches for the LoadBalancers whose Name has the pattern
        passed in lb_id.
        @param lb_id: LoadBalancer ID provided by Octavia in its API
               request. Note that OVN saves the above ID in the 'name' column.
        @type lb_id: str
        @param protocol: Loadbalancer protocol.
        @type protocol: str or None if not defined.

        :returns: LoadBalancer row if protocol specified
                  or list of rows matching the lb_id.
        :raises:  RowNotFound can be generated if the LoadBalancer is not
                  found.
        """
        lbs = self.ovn_nbdb_api.db_find_rows(
            'Load_Balancer', ('name', '=', lb_id)).execute()
        if not protocol:
            if lbs:
                return lbs
            raise idlutils.RowNotFound(table='Load_Balancer',
                                       col='name', match=lb_id)
        # If there is only one LB without protocol defined, so
        # it is 'clean' LB record without any listener.
        if len(lbs) == 1 and not lbs[0].protocol:
            return lbs[0]
        # Search for other lbs.
        for lb in lbs:
            if lb.protocol[0].upper() == protocol.upper():
                return lb
        raise idlutils.RowNotFound(table='Load_Balancer',
                                   col='name', match=lb_id)

    def _get_or_create_ovn_lb(
            self, lb_id, protocol, admin_state_up,
            lb_algorithm=constants.LB_ALGORITHM_SOURCE_IP_PORT):
        """Find or create ovn lb with given protocol

           Find the loadbalancer configured with given protocol or
           create required if not found
        """
        # TODO(mjozefcz): For now we support only one LB algorithm.
        # As we may extend that in the future we would need to
        # look here also for lb_algorithm, along with protocol.
        # Make sure that its lowercase - OVN NBDB stores lowercases
        # for this field.
        protocol = protocol.lower()
        ovn_lbs = self._find_ovn_lbs(lb_id)
        lbs_with_required_protocol = [
            ovn_lb for ovn_lb in ovn_lbs
            if protocol in ovn_lb.protocol]
        lbs_with_no_protocol = [ovn_lb for ovn_lb in ovn_lbs
                                if not ovn_lb.protocol]
        if lbs_with_required_protocol:
            # We found existing LB with required
            # protocol, just return it.
            return lbs_with_required_protocol[0]
        elif lbs_with_no_protocol:
            ovn_lb = lbs_with_no_protocol[0]
            # Set required protocol here.
            self.ovn_nbdb_api.db_set(
                'Load_Balancer', ovn_lb.uuid,
                ('protocol', protocol)).execute(check_error=True)
        else:
            # NOTE(mjozefcz): Looks like loadbalancer with given protocol
            # doesn't exist. Try to add it with required protocol
            # by copy the existing one data.
            lb_info = {
                'id': lb_id,
                'protocol': protocol,
                constants.LB_ALGORITHM: lb_algorithm,
                'vip_address': ovn_lbs[0].external_ids.get(
                    ovn_const.LB_EXT_IDS_VIP_KEY),
                'vip_port_id':
                    ovn_lbs[0].external_ids.get(
                        ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY),
                ovn_const.LB_EXT_IDS_LR_REF_KEY:
                    ovn_lbs[0].external_ids.get(
                        ovn_const.LB_EXT_IDS_LR_REF_KEY),
                ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                    ovn_lbs[0].external_ids.get(
                        ovn_const.LB_EXT_IDS_LS_REFS_KEY),
                'admin_state_up': admin_state_up}
            # NOTE(mjozefcz): Handle vip_fip info if exists.
            vip_fip = ovn_lbs[0].external_ids.get(
                ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
            if vip_fip:
                lb_info.update({ovn_const.LB_EXT_IDS_VIP_FIP_KEY: vip_fip})
            self.lb_create(lb_info, protocol=protocol)
        # Looks like we've just added new LB
        # or updated exising, empty one.
        return self._find_ovn_lbs(lb_id, protocol=protocol)

    def _find_ovn_lb_with_pool_key(self, pool_key):
        lbs = self.ovn_nbdb_api.db_list_rows(
            'Load_Balancer').execute(check_error=True)
        for lb in lbs:
            # Skip load balancers used by port forwarding plugin
            if lb.external_ids.get(ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY) == (
                    ovn_const.PORT_FORWARDING_PLUGIN):
                continue
            if pool_key in lb.external_ids:
                return lb

    def _find_ovn_lb_by_pool_id(self, pool_id):
        pool_key = self._get_pool_key(pool_id)
        ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
        if not ovn_lb:
            pool_key = self._get_pool_key(pool_id, is_enabled=False)
            ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
        return pool_key, ovn_lb

    def _check_ip_in_subnet(self, ip, subnet):
        return (netaddr.IPAddress(ip) in netaddr.IPNetwork(subnet))

    def _get_subnet_from_pool(self, pool_id):
        pool = self._octavia_driver_lib.get_pool(pool_id)
        if not pool:
            return None, None
        lb = self._octavia_driver_lib.get_loadbalancer(pool.loadbalancer_id)
        if lb and lb.vip_subnet_id:
            neutron_client = clients.get_neutron_client()
            try:
                subnet = neutron_client.show_subnet(lb.vip_subnet_id)
                vip_subnet_cidr = subnet['subnet']['cidr']
            except n_exc.NotFound:
                LOG.warning('Subnet %s not found while trying to '
                            'fetch its data.', lb.vip_subnet_id)
                return None, None
            return lb.vip_subnet_id, vip_subnet_cidr
        return None, None

    def _execute_commands(self, commands):
        with self.ovn_nbdb_api.transaction(check_error=True) as txn:
            for command in commands:
                txn.add(command)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(idlutils.RowNotFound),
        wait=tenacity.wait_exponential(),
        stop=tenacity.stop_after_attempt(3),
        reraise=True)
    def _update_lb_to_ls_association(self, ovn_lb, network_id=None,
                                     subnet_id=None, associate=True,
                                     update_ls_ref=True):
        # Note(froyo): Large topologies can change from the time we
        # list the ls association commands and the execution, retry
        # if this situation arises.
        commands = self._get_lb_to_ls_association_commands(
            ovn_lb, network_id, subnet_id, associate, update_ls_ref)
        self._execute_commands(commands)

    def _get_lb_to_ls_association_commands(self, ovn_lb, network_id=None,
                                           subnet_id=None, associate=True,
                                           update_ls_ref=True):
        """Update LB association with Logical Switch

           This function deals with updating the References of Logical Switch
           in LB and addition of LB to LS.
        """
        commands = []
        if not network_id and not subnet_id:
            return commands

        if network_id:
            ls_name = utils.ovn_name(network_id)
        else:
            neutron_client = clients.get_neutron_client()
            try:
                subnet = neutron_client.show_subnet(subnet_id)
                ls_name = utils.ovn_name(subnet['subnet']['network_id'])
            except n_exc.NotFound:
                LOG.warning('Subnet %s not found while trying to '
                            'fetch its data.', subnet_id)
                ls_name = None
                ovn_ls = None

        if ls_name:
            try:
                ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                    check_error=True)
            except idlutils.RowNotFound:
                LOG.warning("LogicalSwitch %s could not be found.", ls_name)
                if associate:
                    LOG.warning('Cannot associate LB %(lb)s to '
                                'LS %(ls)s because LS row '
                                'not found in OVN NBDB. Exiting.',
                                {'ls': ls_name, 'lb': ovn_lb.name})
                    return commands
                ovn_ls = None

        ls_refs = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_LS_REFS_KEY)
        if ls_refs:
            try:
                ls_refs = jsonutils.loads(ls_refs)
            except ValueError:
                ls_refs = {}
        else:
            ls_refs = {}

        if associate and ls_name:
            if ls_name in ls_refs:
                ref_ct = ls_refs[ls_name]
                ls_refs[ls_name] = ref_ct + 1
            else:
                ls_refs[ls_name] = 1
                if ovn_ls:
                    commands.append(self.ovn_nbdb_api.ls_lb_add(
                        ovn_ls.uuid, ovn_lb.uuid, may_exist=True))
        else:
            if ls_name not in ls_refs:
                if ovn_ls:
                    commands.append(self.ovn_nbdb_api.ls_lb_del(
                        ovn_ls.uuid, ovn_lb.uuid, if_exists=True))
                # Nothing else to be done.
                return commands

            ref_ct = ls_refs[ls_name]
            if ref_ct == 1:
                del ls_refs[ls_name]
                if ovn_ls:
                    commands.append(self.ovn_nbdb_api.ls_lb_del(
                        ovn_ls.uuid, ovn_lb.uuid, if_exists=True))
            else:
                ls_refs[ls_name] = ref_ct - 1

        if update_ls_ref:
            ls_refs = {
                ovn_const.LB_EXT_IDS_LS_REFS_KEY: jsonutils.dumps(ls_refs)}
            commands.append(self.ovn_nbdb_api.db_set(
                'Load_Balancer', ovn_lb.uuid,
                ('external_ids', ls_refs)))

        return commands

    def _del_lb_to_lr_association(self, ovn_lb, ovn_lr, lr_ref):
        commands = []
        if lr_ref:
            try:
                lr_ref = [r for r in
                          [lr.strip() for lr in lr_ref.split(',')]
                          if r != ovn_lr.name]
            except ValueError:
                LOG.warning('The loadbalancer %(lb)s is not associated with '
                            'the router %(router)s',
                            {'lb': ovn_lb.name, 'router': ovn_lr.name})
            if lr_ref:
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('external_ids',
                         {ovn_const.LB_EXT_IDS_LR_REF_KEY: ','.join(lr_ref)})))
            else:
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid, 'external_ids',
                        (ovn_const.LB_EXT_IDS_LR_REF_KEY)))
            commands.append(
                self.ovn_nbdb_api.lr_lb_del(ovn_lr.uuid, ovn_lb.uuid,
                                            if_exists=True))
        lb_vip = netaddr.IPNetwork(
            ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_KEY))
        for net in self._find_ls_for_lr(ovn_lr, ip_version=lb_vip.version):
            commands.append(self.ovn_nbdb_api.ls_lb_del(
                net, ovn_lb.uuid, if_exists=True))
        return commands

    def _add_lb_to_lr_association(self, ovn_lb, ovn_lr, lr_rf):
        commands = []
        commands.append(
            self.ovn_nbdb_api.lr_lb_add(ovn_lr.uuid, ovn_lb.uuid,
                                        may_exist=True))
        lb_vip = netaddr.IPNetwork(
            ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_KEY))
        for net in self._find_ls_for_lr(ovn_lr, ip_version=lb_vip.version):
            commands.append(self.ovn_nbdb_api.ls_lb_add(
                net, ovn_lb.uuid, may_exist=True))

        if ovn_lr.name not in str(lr_rf):
            # Multiple routers in lr_rf are separated with ','
            if lr_rf:
                lr_rf = {ovn_const.LB_EXT_IDS_LR_REF_KEY:
                         f"{lr_rf},{ovn_lr.name}"}
            else:
                lr_rf = {ovn_const.LB_EXT_IDS_LR_REF_KEY: ovn_lr.name}
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', lr_rf)))
        return commands

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(idlutils.RowNotFound),
        wait=tenacity.wait_exponential(),
        stop=tenacity.stop_after_attempt(3),
        reraise=True)
    def _update_lb_to_lr_association(self, ovn_lb, ovn_lr, delete=False):
        # Note(froyo): Large topologies can change from the time we
        # list the ls associated to lr until we execute the
        # association command, retry if this situation arises.
        commands = self._get_lb_to_lr_association_commands(
            ovn_lb, ovn_lr, delete)
        self._execute_commands(commands)

    def _update_lb_to_lr_association_by_step(self, ovn_lb, ovn_lr,
                                             delete=False):
        # Note(froyo): just to make association commands step by
        # step, in order to keep going on when LsLbAdd or LsLbDel
        # happen.
        commands = self._get_lb_to_lr_association_commands(
            ovn_lb, ovn_lr, delete)
        for command in commands:
            try:
                command.execute(check_error=True)
            except idlutils.RowNotFound:
                if isinstance(command, (cmd.LsLbAddCommand,
                                        cmd.LsLbDelCommand)):
                    LOG.warning('action lb to ls fail because ls '
                                '%s is not found, keep going on...',
                                getattr(command, 'switch', ''))
                else:
                    raise

    def _get_lb_to_lr_association_commands(
            self, ovn_lb, ovn_lr, delete=False):
        lr_ref = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_LR_REF_KEY)
        if delete:
            return self._del_lb_to_lr_association(ovn_lb, ovn_lr, lr_ref)
        return self._add_lb_to_lr_association(ovn_lb, ovn_lr, lr_ref)

    def _find_ls_for_lr(self, router, ip_version):
        ls = []
        for port in router.ports:
            if port.gateway_chassis:
                continue
            if netaddr.IPNetwork(port.networks[0]).version != ip_version:
                continue
            port_network_name = port.external_ids.get(
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY)
            if port_network_name:
                ls.append(utils.ovn_name(port_network_name))
        return ls

    def _find_lr_of_ls(self, ovn_ls, subnet_gateway_ip=None):
        lsp_router_port = None
        for port in ovn_ls.ports or []:
            if (port.type == 'router' and
                    port.external_ids.get(
                        ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY) ==
                    n_const.DEVICE_OWNER_ROUTER_INTF):
                if subnet_gateway_ip:
                    port_cidr = netaddr.IPNetwork(
                        port.external_ids[
                            ovn_const.OVN_PORT_CIDR_EXT_ID_KEY]).ip
                    if netaddr.IPAddress(subnet_gateway_ip) != port_cidr:
                        continue
                lsp_router_port = port
                break
        else:
            return

        lrp_name = lsp_router_port.options.get('router-port')
        if not lrp_name:
            return

        lrs = self.ovn_nbdb_api.get_lrs().execute(check_error=True)
        for lr in lrs:
            for lrp in lr.ports:
                if lrp.name == lrp_name:
                    return lr
            # Handles networks with only gateway port in the router
            if (utils.ovn_lrouter_port_name(
                    lr.external_ids.get(ovn_const.OVN_GW_PORT_EXT_ID_KEY)) ==
                    lrp_name):
                return lr

    def _get_listener_key(self, listener_id, is_enabled=True):
        listener_key = ovn_const.LB_EXT_IDS_LISTENER_PREFIX + str(listener_id)
        if not is_enabled:
            listener_key += ':' + ovn_const.DISABLED_RESOURCE_SUFFIX
        return listener_key

    def _get_pool_key(self, pool_id, is_enabled=True):
        pool_key = ovn_const.LB_EXT_IDS_POOL_PREFIX + str(pool_id)
        if not is_enabled:
            pool_key += ':' + ovn_const.DISABLED_RESOURCE_SUFFIX
        return pool_key

    def _extract_member_info(self, member):
        mem_info = []
        if member:
            for mem in member.split(','):
                mem_split = mem.split('_')
                mem_ip_port = mem_split[2]
                mem_ip, mem_port = mem_ip_port.rsplit(':', 1)
                mem_subnet = mem_split[3]
                mem_info.append((mem_ip, mem_port, mem_subnet))
        return mem_info

    def _get_member_info(self, member):
        member_info = ''
        if isinstance(member, dict):
            subnet_id = member.get(constants.SUBNET_ID, '')
            member_info = (
                f'{ovn_const.LB_EXT_IDS_MEMBER_PREFIX}{member[constants.ID]}_'
                f'{member[constants.ADDRESS]}:'
                f'{member[constants.PROTOCOL_PORT]}_{subnet_id}')
        elif isinstance(member, o_datamodels.Member):
            subnet_id = member.subnet_id or ''
            member_info = (
                f'{ovn_const.LB_EXT_IDS_MEMBER_PREFIX}{member.member_id}_'
                f'{member.address}:{member.protocol_port}_{subnet_id}')
        return member_info

    def _make_listener_key_value(self, listener_port, pool_id):
        return str(listener_port) + ':' + pool_id

    def _extract_listener_key_value(self, listener_value):
        v = listener_value.split(':')
        if len(v) == 2:
            return (v[0], v[1])
        else:
            return (None, None)

    def _is_listener_disabled(self, listener_key):
        v = listener_key.split(':')
        if len(v) == 2 and v[1] == ovn_const.DISABLED_RESOURCE_SUFFIX:
            return True

        return False

    def _get_pool_listeners(self, ovn_lb, pool_key):
        pool_listeners = []
        for k, v in ovn_lb.external_ids.items():
            if ovn_const.LB_EXT_IDS_LISTENER_PREFIX not in k:
                continue
            vip_port, p_key = self._extract_listener_key_value(v)
            if pool_key == p_key:
                pool_listeners.append(
                    k[len(ovn_const.LB_EXT_IDS_LISTENER_PREFIX):])
        return pool_listeners

    def _get_pool_listener_port(self, ovn_lb, pool_key):
        for k, v in ovn_lb.external_ids.items():
            if ovn_const.LB_EXT_IDS_LISTENER_PREFIX not in k:
                continue
            vip_port, p_key = self._extract_listener_key_value(v)
            if pool_key == p_key:
                return vip_port
        return None

    def _frame_vip_ips(self, lb_external_ids):
        vip_ips = {}
        # If load balancer is disabled, return
        if lb_external_ids.get('enabled') == 'False':
            return vip_ips

        lb_vip = lb_external_ids[ovn_const.LB_EXT_IDS_VIP_KEY]
        vip_fip = lb_external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)

        for k, v in lb_external_ids.items():
            if (ovn_const.LB_EXT_IDS_LISTENER_PREFIX not in k or
                    self._is_listener_disabled(k)):
                continue

            vip_port, pool_id = self._extract_listener_key_value(v)
            if not vip_port or not pool_id:
                continue

            if pool_id not in lb_external_ids or not lb_external_ids[pool_id]:
                continue

            ips = []
            for member_ip, member_port, subnet in self._extract_member_info(
                    lb_external_ids[pool_id]):
                if netaddr.IPNetwork(member_ip).version == 6:
                    ips.append(f'[{member_ip}]:{member_port}')
                else:
                    ips.append(f'{member_ip}:{member_port}')

            if netaddr.IPNetwork(lb_vip).version == 6:
                lb_vip = f'[{lb_vip}]'
            vip_ips[lb_vip + ':' + vip_port] = ','.join(ips)

            if vip_fip:
                if netaddr.IPNetwork(vip_fip).version == 6:
                    vip_fip = f'[{vip_fip}]'
                vip_ips[vip_fip + ':' + vip_port] = ','.join(ips)

        return vip_ips

    def _refresh_lb_vips(self, ovn_lb_uuid, lb_external_ids):
        vip_ips = self._frame_vip_ips(lb_external_ids)
        return [self.ovn_nbdb_api.db_clear('Load_Balancer', ovn_lb_uuid,
                                           'vips'),
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb_uuid,
                                         ('vips', vip_ips))]

    def _is_listener_in_lb(self, lb):
        for key in list(lb.external_ids):
            if key.startswith(ovn_const.LB_EXT_IDS_LISTENER_PREFIX):
                return True
        return False

    def _are_selection_fields_supported(self):
        return self.ovn_nbdb_api.is_col_present(
            'Load_Balancer', 'selection_fields')

    @staticmethod
    def _get_selection_keys(lb_algorithm):
        # pylint: disable=multiple-statements
        return ovn_const.LB_SELECTION_FIELDS_MAP[lb_algorithm]

    def check_lb_protocol(self, lb_id, listener_protocol):
        ovn_lb = self._find_ovn_lbs(lb_id, protocol=listener_protocol)
        if not ovn_lb:
            return False
        elif not self._is_listener_in_lb(ovn_lb):
            return True
        else:
            return str(listener_protocol).lower() in ovn_lb.protocol

    def lb_create(self, loadbalancer, protocol=None):
        port = None
        subnet = {}
        try:
            neutron_client = clients.get_neutron_client()
            if loadbalancer.get(constants.VIP_PORT_ID):
                # In case we don't have vip_network_id
                port = neutron_client.show_port(
                    loadbalancer[constants.VIP_PORT_ID])['port']
                for ip in port['fixed_ips']:
                    if ip['ip_address'] == loadbalancer[constants.VIP_ADDRESS]:
                        subnet = neutron_client.show_subnet(
                            ip['subnet_id'])['subnet']
                        break
            elif (loadbalancer.get(constants.VIP_NETWORK_ID) and
                  loadbalancer.get(constants.VIP_ADDRESS)):
                ports = self._neutron_list_ports(neutron_client, **{
                    'network_id': loadbalancer[constants.VIP_NETWORK_ID]})
                for p in ports['ports']:
                    for ip in p['fixed_ips']:
                        if ip['ip_address'] == loadbalancer[
                                constants.VIP_ADDRESS]:
                            port = p
                            subnet = neutron_client.show_subnet(
                                ip['subnet_id'])['subnet']
                            break
        except Exception:
            LOG.error('Cannot get info from neutron client')
            LOG.exception(ovn_const.EXCEPTION_MSG, "creation of loadbalancer")
            # Any Exception set the status to ERROR
            if isinstance(port, dict):
                try:
                    self.delete_port(port.get('id'))
                    LOG.warning("Deleting the VIP port %s since LB went into "
                                "ERROR state", str(port.get('id')))
                except Exception:
                    LOG.exception("Error deleting the VIP port %s upon "
                                  "loadbalancer %s creation failure",
                                  str(port.get('id')),
                                  str(loadbalancer[constants.ID]))
            status = {
                constants.LOADBALANCERS: [
                    {constants.ID: loadbalancer[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR,
                     constants.OPERATING_STATUS: constants.ERROR}]}
            return status

        # If protocol set make sure its lowercase
        protocol = protocol.lower() if protocol else []
        # In case port is not found for the vip_address we will see an
        # exception when port['id'] is accessed.
        external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: loadbalancer[constants.VIP_ADDRESS],
            ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY:
                loadbalancer.get(constants.VIP_PORT_ID) or port['id'],
            'enabled': str(loadbalancer[constants.ADMIN_STATE_UP])}
        # In case vip_fip was passed - use it.
        vip_fip = loadbalancer.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
        if vip_fip:
            external_ids[ovn_const.LB_EXT_IDS_VIP_FIP_KEY] = vip_fip
        # In case of lr_ref passed - use it.
        lr_ref = loadbalancer.get(ovn_const.LB_EXT_IDS_LR_REF_KEY)
        if lr_ref:
            external_ids[ovn_const.LB_EXT_IDS_LR_REF_KEY] = lr_ref
        # In case we have LB algoritm set
        lb_algorithm = loadbalancer.get(constants.LB_ALGORITHM)
        kwargs = {
            'name': loadbalancer[constants.ID],
            'protocol': protocol,
            'external_ids': external_ids}
        if self._are_selection_fields_supported():
            kwargs['selection_fields'] = self._get_selection_keys(lb_algorithm)
        try:
            self.ovn_nbdb_api.db_create(
                'Load_Balancer',
                **kwargs).execute(check_error=True)
            ovn_lb = self._find_ovn_lbs(
                loadbalancer[constants.ID],
                protocol=protocol)
            ovn_lb = ovn_lb if protocol else ovn_lb[0]

            # NOTE(ltomasbo): If the VIP is on a provider network, it does
            # not need to be associated to its LS
            network = neutron_client.show_network(
                port['network_id'])['network']
            if not network.get(provider_net.PHYSICAL_NETWORK, False):
                # NOTE(froyo): This is the association of the lb to the VIP ls
                # so this is executed right away
                self._update_lb_to_ls_association(
                    ovn_lb, network_id=port['network_id'],
                    associate=True, update_ls_ref=True)
            ls_name = utils.ovn_name(port['network_id'])
            ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                check_error=True)
            ovn_lr = self._find_lr_of_ls(ovn_ls, subnet.get('gateway_ip'))
            if ovn_lr:
                try:
                    # NOTE(froyo): This is the association of the lb to the
                    # router associated to VIP ls and all ls connected to that
                    # router we try atomically, if it fails we will go step by
                    # step, discarding the associations from lb to a
                    # non-existent ls, but we will demand the association of
                    # lb to lr
                    self._update_lb_to_lr_association(ovn_lb, ovn_lr)
                except idlutils.RowNotFound:
                    LOG.warning("The association of loadbalancer %s to the "
                                "logical router %s failed, trying step by "
                                "step", ovn_lb.uuid, ovn_lr.uuid)
                    self._update_lb_to_lr_association_by_step(ovn_lb, ovn_lr)

            # NOTE(mjozefcz): In case of LS references where passed -
            # apply LS to the new LB. That could happend in case we
            # need another loadbalancer for other L4 protocol.
            ls_refs = loadbalancer.get(ovn_const.LB_EXT_IDS_LS_REFS_KEY)
            if ls_refs:
                try:
                    ls_refs = jsonutils.loads(ls_refs)
                except ValueError:
                    ls_refs = {}
                for ls in ls_refs:
                    # Skip previously added LS because we don't want
                    # to duplicate.
                    if ls == ovn_ls.name:
                        continue
                    self._update_lb_to_ls_association(
                        ovn_lb, network_id=utils.ovn_uuid(ls),
                        associate=True, update_ls_ref=True)

            operating_status = constants.ONLINE
            # The issue is that since OVN doesnt support any HMs,
            # we ideally should never put the status as 'ONLINE'
            if not loadbalancer.get(constants.ADMIN_STATE_UP, True):
                operating_status = constants.OFFLINE
            status = {
                constants.LOADBALANCERS: [
                    {constants.ID: loadbalancer[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE,
                     constants.OPERATING_STATUS: operating_status}]}
        # If the connection with the OVN NB db server is broken, then
        # ovsdbapp will throw either TimeOutException or RunTimeError.
        # May be we can catch these specific exceptions.
        # It is important to report the status to octavia. We can report
        # immediately or reschedule the lb_create request later.
        # For now lets report immediately.
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "creation of loadbalancer")
            # Any Exception set the status to ERROR
            if isinstance(port, dict):
                try:
                    self.delete_port(port.get('id'))
                    LOG.warning("Deleting the VIP port %s since LB went into "
                                "ERROR state", str(port.get('id')))
                except Exception:
                    LOG.exception("Error deleting the VIP port %s upon "
                                  "loadbalancer %s creation failure",
                                  str(port.get('id')),
                                  str(loadbalancer[constants.ID]))
            status = {
                constants.LOADBALANCERS: [
                    {constants.ID: loadbalancer[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR,
                     constants.OPERATING_STATUS: constants.ERROR}]}
        return status

    def lb_delete(self, loadbalancer):
        port_id = None
        lbalancer_status = {
            constants.ID: loadbalancer[constants.ID],
            constants.PROVISIONING_STATUS: constants.DELETED,
            constants.OPERATING_STATUS: constants.OFFLINE}
        status = {
            constants.LOADBALANCERS: [lbalancer_status],
            constants.LISTENERS: [],
            constants.POOLS: [],
            constants.MEMBERS: []}

        ovn_lbs = None
        try:
            ovn_lbs = self._find_ovn_lbs(loadbalancer[constants.ID])
        except idlutils.RowNotFound:
            LOG.warning("Loadbalancer %s not found in OVN Northbound DB. "
                        "Setting the Loadbalancer status to DELETED "
                        "in Octavia", str(loadbalancer[constants.ID]))

            # NOTE(ltomasbo): In case the previous loadbalancer deletion
            # action failed at VIP deletion step, this ensures the VIP
            # is not leaked
            try:
                vip_port_id = self._get_vip_port_from_loadbalancer_id(
                    loadbalancer[constants.ID])
                if vip_port_id:
                    LOG.warning("Deleting the VIP port %s associated to LB "
                                "missing in OVN DBs", str(vip_port_id))
                    self.delete_port(vip_port_id)
            except Exception:
                LOG.exception("Error deleting the VIP port %s",
                              str(vip_port_id))
                lbalancer_status[constants.PROVISIONING_STATUS] = (
                    constants.ERROR)
                lbalancer_status[constants.OPERATING_STATUS] = constants.ERROR
            return status

        try:
            port_id = ovn_lbs[0].external_ids[
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY]
            for ovn_lb in ovn_lbs:
                status = self._lb_delete(loadbalancer, ovn_lb, status)
            # Clear the status dict of any key having [] value
            # Python 3.6 doesnt allow deleting an element in a
            # dict while iterating over it. So first get a list of keys.
            # https://cito.github.io/blog/never-iterate-a-changing-dict/
            status = {key: value for key, value in status.items() if value}
            # Delete VIP port from neutron.
            self.delete_port(port_id)
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "deletion of loadbalancer")
            lbalancer_status[constants.PROVISIONING_STATUS] = constants.ERROR
            lbalancer_status[constants.OPERATING_STATUS] = constants.ERROR

        return status

    def _lb_delete(self, loadbalancer, ovn_lb, status):
        commands = []
        member_subnets = []
        clean_up_hm_port_required = False
        if loadbalancer['cascade']:
            # Delete all pools
            for key, value in ovn_lb.external_ids.items():
                if key.startswith(ovn_const.LB_EXT_IDS_POOL_PREFIX):
                    pool_id = key.split('_')[1]
                    # Delete all members in the pool
                    if value and len(value.split(',')) > 0:
                        for mem_info in value.split(','):
                            member_subnets.append(mem_info.split('_')[3])
                            status[constants.MEMBERS].append({
                                constants.ID: mem_info.split('_')[1],
                                constants.PROVISIONING_STATUS:
                                    constants.DELETED})
                    status[constants.POOLS].append(
                        {constants.ID: pool_id,
                         constants.PROVISIONING_STATUS: constants.DELETED})

                if key.startswith(ovn_const.LB_EXT_IDS_LISTENER_PREFIX):
                    status[constants.LISTENERS].append({
                        constants.ID: key.split('_')[1],
                        constants.PROVISIONING_STATUS: constants.DELETED,
                        constants.OPERATING_STATUS: constants.OFFLINE})

        if ovn_lb.health_check:
            clean_up_hm_port_required = True
            commands.append(
                self.ovn_nbdb_api.db_clear('Load_Balancer', ovn_lb.uuid,
                                           'health_check'))

        ls_refs = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_LS_REFS_KEY, {})
        if ls_refs:
            try:
                ls_refs = jsonutils.loads(ls_refs)
            except ValueError:
                ls_refs = {}
        for ls_name in ls_refs.keys():
            try:
                ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                    check_error=True)
                commands.append(
                    self.ovn_nbdb_api.ls_lb_del(ovn_ls.uuid, ovn_lb.uuid))
            except idlutils.RowNotFound:
                LOG.warning("LogicalSwitch %s could not be found. Cannot "
                            "delete Load Balancer from it", ls_name)
        # Delete LB from all Networks the LB is indirectly associated
        for ls in self._find_lb_in_table(ovn_lb, 'Logical_Switch'):
            commands.append(
                self.ovn_nbdb_api.ls_lb_del(ls.uuid, ovn_lb.uuid,
                                            if_exists=True))
        lr_ref = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_LR_REF_KEY, {})
        if lr_ref:
            try:
                lr = self.ovn_nbdb_api.lookup('Logical_Router', lr_ref)
                commands.append(self.ovn_nbdb_api.lr_lb_del(
                    lr.uuid, ovn_lb.uuid))
            except idlutils.RowNotFound:
                pass
        # Delete LB from all Routers the LB is indirectly associated
        for lr in self._find_lb_in_table(ovn_lb, 'Logical_Router'):
            commands.append(
                self.ovn_nbdb_api.lr_lb_del(lr.uuid, ovn_lb.uuid,
                                            if_exists=True))
        commands.append(self.ovn_nbdb_api.lb_del(ovn_lb.uuid))

        try:
            self._execute_commands(commands)
        except idlutils.RowNotFound:
            # NOTE(froyo): If any of the Ls or Lr had been deleted between
            # time to list and time to execute txn, we will received a
            # RowNotFound exception, if this case we will run every command
            # one by one passing exception in case the command is related to
            # deletion of Ls or Lr already deleted. Any other case will raise
            # exception and upper function will report the LB in ERROR status
            for command in commands:
                try:
                    command.execute(check_error=True)
                except idlutils.RowNotFound:
                    if isinstance(command, (cmd.LsLbDelCommand)):
                        LOG.warning('delete lb from ls fail because ls '
                                    '%s is not found, keep going on...',
                                    getattr(command, 'switch', ''))
                    elif isinstance(command, (cmd.LrLbDelCommand)):
                        LOG.warning('delete lb to lr fail because lr '
                                    '%s is not found, keep going on...',
                                    getattr(command, 'router', ''))
                    else:
                        raise

        # NOTE(froyo): we should remove the hm-port if the LB was using a HM
        # and no more LBs are using it
        if clean_up_hm_port_required:
            for subnet_id in list(set(member_subnets)):
                self._clean_up_hm_port(subnet_id)

        return status

    def lb_update(self, loadbalancer):
        lb_status = {constants.ID: loadbalancer[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}
        status = {constants.LOADBALANCERS: [lb_status]}
        if constants.ADMIN_STATE_UP not in loadbalancer:
            return status
        lb_enabled = loadbalancer[constants.ADMIN_STATE_UP]

        try:
            ovn_lbs = self._find_ovn_lbs(loadbalancer[constants.ID])
            # It should be unique for all the LBS for all protocols,
            # so we could just easly loop over all defined for given
            # Octavia LB.
            for ovn_lb in ovn_lbs:
                if str(ovn_lb.external_ids['enabled']) != str(lb_enabled):
                    commands = []
                    enable_info = {'enabled': str(lb_enabled)}
                    ovn_lb.external_ids['enabled'] = str(lb_enabled)
                    commands.append(
                        self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                                 ('external_ids', enable_info))
                    )
                    commands.extend(
                        self._refresh_lb_vips(ovn_lb.uuid,
                                              ovn_lb.external_ids))
                    self._execute_commands(commands)
                if lb_enabled:
                    operating_status = constants.ONLINE
                else:
                    operating_status = constants.OFFLINE
                lb_status[constants.OPERATING_STATUS] = operating_status
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "update of loadbalancer")
            lb_status[constants.PROVISIONING_STATUS] = constants.ERROR
            lb_status[constants.OPERATING_STATUS] = constants.ERROR
        return status

    def _get_vip_port_from_loadbalancer_id(self, lb_id):
        lb = self._octavia_driver_lib.get_loadbalancer(lb_id)
        if lb and lb.vip_port_id:
            return lb.vip_port_id

    def listener_create(self, listener):
        ovn_lb = self._get_or_create_ovn_lb(
            listener[constants.LOADBALANCER_ID],
            listener[constants.PROTOCOL],
            listener[constants.ADMIN_STATE_UP])

        external_ids = copy.deepcopy(ovn_lb.external_ids)
        listener_key = self._get_listener_key(
            listener[constants.ID],
            is_enabled=listener[constants.ADMIN_STATE_UP])

        if listener.get(constants.DEFAULT_POOL_ID):
            pool_key = self._get_pool_key(listener[constants.DEFAULT_POOL_ID])
        else:
            pool_key = ''
        external_ids[listener_key] = self._make_listener_key_value(
            listener[constants.PROTOCOL_PORT], pool_key)

        listener_info = {listener_key: external_ids[listener_key]}
        try:
            commands = []
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', listener_info)))
            if not self._is_listener_in_lb(ovn_lb):
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('protocol',
                         str(listener[constants.PROTOCOL]).lower())))
            commands.extend(self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            self._execute_commands(commands)
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "creation of listener")
            status = {
                constants.LISTENERS: [
                    {constants.ID: listener[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR,
                     constants.OPERATING_STATUS: constants.ERROR}],
                constants.LOADBALANCERS: [
                    {constants.ID: listener[constants.LOADBALANCER_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}
            return status

        operating_status = constants.ONLINE
        if not listener.get(constants.ADMIN_STATE_UP, True):
            operating_status = constants.OFFLINE

        if (ovn_lb.health_check and
                not self._update_lbhc_vip(ovn_lb,
                                          listener[constants.PROTOCOL_PORT])):
            operating_status = constants.ERROR

        status = {
            constants.LISTENERS: [
                {constants.ID: listener[constants.ID],
                 constants.PROVISIONING_STATUS: constants.ACTIVE,
                 constants.OPERATING_STATUS: operating_status}],
            constants.LOADBALANCERS: [
                {constants.ID: listener[constants.LOADBALANCER_ID],
                 constants.PROVISIONING_STATUS: constants.ACTIVE}]}
        return status

    def listener_delete(self, listener):
        status = {
            constants.LISTENERS: [
                {constants.ID: listener[constants.ID],
                 constants.PROVISIONING_STATUS: constants.DELETED,
                 constants.OPERATING_STATUS: constants.OFFLINE}],
            constants.LOADBALANCERS: [
                {constants.ID: listener[constants.LOADBALANCER_ID],
                 constants.PROVISIONING_STATUS: constants.ACTIVE}]}
        try:
            ovn_lb = self._find_ovn_lbs(
                listener[constants.LOADBALANCER_ID],
                protocol=listener[constants.PROTOCOL])
        except idlutils.RowNotFound:
            # Listener already deleted.
            return status

        external_ids = copy.deepcopy(ovn_lb.external_ids)
        listener_key = self._get_listener_key(listener[constants.ID])
        if listener_key in external_ids:
            try:
                commands = []
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid, 'external_ids',
                        (listener_key)))
                # Drop current listener from LB.
                del external_ids[listener_key]

                # Set LB protocol to undefined only if there are no more
                # listeners and pools defined in the LB.
                cmds, lb_to_delete = self._clean_lb_if_empty(
                    ovn_lb, listener[constants.LOADBALANCER_ID], external_ids)
                commands.extend(cmds)
                # Do not refresh vips if OVN LB for given protocol
                # has pending delete operation.
                if not lb_to_delete:
                    commands.extend(
                        self._refresh_lb_vips(ovn_lb.uuid, external_ids))
                self._execute_commands(commands)
            except Exception:
                LOG.exception(ovn_const.EXCEPTION_MSG, "deletion of listener")
                status = {
                    constants.LISTENERS: [
                        {constants.ID: listener[constants.ID],
                         constants.PROVISIONING_STATUS: constants.ERROR,
                         constants.OPERATING_STATUS: constants.ERROR}],
                    constants.LOADBALANCERS: [
                        {constants.ID: listener[constants.LOADBALANCER_ID],
                         constants.PROVISIONING_STATUS: constants.ACTIVE}]}
        return status

    def listener_update(self, listener):
        # NOTE(mjozefcz): Based on
        # https://docs.openstack.org/api-ref/load-balancer/v2/?expanded=update-a-listener-detail
        # there is no possibility to update listener protocol or port.
        listener_status = {constants.ID: listener[constants.ID],
                           constants.PROVISIONING_STATUS: constants.ACTIVE}
        lbalancer_status = {
            constants.ID: listener[constants.LOADBALANCER_ID],
            constants.PROVISIONING_STATUS: constants.ACTIVE}
        pool_status = []
        status = {
            constants.LISTENERS: [listener_status],
            constants.LOADBALANCERS: [lbalancer_status],
            constants.POOLS: pool_status}

        try:
            ovn_lb = self._find_ovn_lbs(
                listener[constants.LOADBALANCER_ID],
                protocol=listener[constants.PROTOCOL])
        except idlutils.RowNotFound:
            LOG.exception(ovn_const.EXCEPTION_MSG, "update of listener")
            # LB row not found during update of a listener. That is a problem.
            listener_status[constants.PROVISIONING_STATUS] = constants.ERROR
            lbalancer_status[constants.PROVISIONING_STATUS] = constants.ERROR
            return status

        l_key_when_enabled = self._get_listener_key(listener[constants.ID])
        l_key_when_disabled = self._get_listener_key(
            listener[constants.ID], is_enabled=False)

        external_ids = copy.deepcopy(ovn_lb.external_ids)
        if constants.ADMIN_STATE_UP not in listener and (
                constants.DEFAULT_POOL_ID not in listener):
            return status

        l_key_to_add = {}
        if l_key_when_enabled in external_ids:
            present_l_key = l_key_when_enabled
        elif l_key_when_disabled in external_ids:
            present_l_key = l_key_when_disabled
        else:
            # Something is terribly wrong. This cannot happen.
            return status

        try:
            commands = []
            new_l_key = None
            l_key_to_remove = None
            if constants.ADMIN_STATE_UP in listener:
                if listener[constants.ADMIN_STATE_UP]:
                    # We need to enable the listener
                    new_l_key = l_key_when_enabled
                    listener_status[constants.OPERATING_STATUS] = (
                        constants.ONLINE)
                else:
                    # We need to disable the listener
                    new_l_key = l_key_when_disabled
                    listener_status[constants.OPERATING_STATUS] = (
                        constants.OFFLINE)

                if present_l_key != new_l_key:
                    external_ids[new_l_key] = external_ids[present_l_key]
                    l_key_to_add[new_l_key] = external_ids[present_l_key]
                    del external_ids[present_l_key]
                    l_key_to_remove = present_l_key

                if l_key_to_remove:
                    commands.append(
                        self.ovn_nbdb_api.db_remove(
                            'Load_Balancer', ovn_lb.uuid, 'external_ids',
                            (l_key_to_remove)))
            else:
                new_l_key = present_l_key

            if constants.DEFAULT_POOL_ID in listener:
                pool_key = self._get_pool_key(
                    listener[constants.DEFAULT_POOL_ID])
                l_key_value = self._make_listener_key_value(
                    listener[constants.PROTOCOL_PORT], pool_key)
                l_key_to_add[new_l_key] = l_key_value
                external_ids[new_l_key] = l_key_value
                pool_status.append(
                    {constants.ID: listener[constants.DEFAULT_POOL_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE})

            if l_key_to_add:
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('external_ids', l_key_to_add)))

            commands.extend(
                self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            self._execute_commands(commands)
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "update of listener")
            status = {
                constants.LISTENERS: [
                    {constants.ID: listener[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR}],
                constants.LOADBALANCERS: [
                    {constants.ID: listener[constants.LOADBALANCER_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}
        if ovn_lb.health_check:
            self._update_lbhc_vip(ovn_lb, listener[constants.PROTOCOL_PORT])
        return status

    def pool_create(self, pool):
        ovn_lb = self._get_or_create_ovn_lb(
            pool[constants.LOADBALANCER_ID],
            pool[constants.PROTOCOL],
            pool[constants.ADMIN_STATE_UP],
            lb_algorithm=pool[constants.LB_ALGORITHM])

        external_ids = copy.deepcopy(ovn_lb.external_ids)
        pool_key = self._get_pool_key(
            pool[constants.ID], is_enabled=pool[constants.ADMIN_STATE_UP])
        external_ids[pool_key] = ''
        if pool[constants.LISTENER_ID]:
            listener_key = self._get_listener_key(pool[constants.LISTENER_ID])
            if listener_key in ovn_lb.external_ids:
                external_ids[listener_key] = str(
                    external_ids[listener_key]) + str(pool_key)
        try:
            self.ovn_nbdb_api.db_set(
                'Load_Balancer', ovn_lb.uuid,
                ('external_ids', external_ids)).execute(check_error=True)

            # Pool status will be set to Online after a member is added to it
            # or when it is created with listener.
            operating_status = constants.OFFLINE
            if pool[constants.LISTENER_ID]:
                operating_status = constants.ONLINE

            status = {
                constants.POOLS: [
                    {constants.ID: pool[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE,
                     constants.OPERATING_STATUS: operating_status}],
                constants.LOADBALANCERS: [
                    {constants.ID: pool[constants.LOADBALANCER_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}
            if pool[constants.LISTENER_ID]:
                listener_status = [
                    {constants.ID: pool[constants.LISTENER_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]
                status[constants.LISTENERS] = listener_status
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "creation of pool")
            status = {
                constants.POOLS: [
                    {constants.ID: pool[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR}],
                constants.LOADBALANCERS: [
                    {constants.ID: pool[constants.LOADBALANCER_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}
            if pool[constants.LISTENER_ID]:
                listener_status = [
                    {constants.ID: pool[constants.LISTENER_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]
                status[constants.LISTENERS] = listener_status

        return status

    def pool_delete(self, pool):
        status = {
            constants.POOLS: [
                {constants.ID: pool[constants.ID],
                 constants.PROVISIONING_STATUS: constants.DELETED}],
            constants.LOADBALANCERS: [
                {constants.ID: pool[constants.LOADBALANCER_ID],
                 constants.PROVISIONING_STATUS: constants.ACTIVE}]}
        try:
            ovn_lb = self._find_ovn_lbs(
                pool[constants.LOADBALANCER_ID],
                pool[constants.PROTOCOL])
        except idlutils.RowNotFound:
            # LB row not found that means pool is deleted.
            return status

        pool_key = self._get_pool_key(pool[constants.ID])
        commands = []
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        pool_listeners = []
        try:
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            if pool_key in ovn_lb.external_ids:
                commands.append(
                    self.ovn_nbdb_api.db_remove('Load_Balancer', ovn_lb.uuid,
                                                'external_ids', (pool_key)))
                del external_ids[pool_key]
                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            # Remove Pool from Listener if it is associated
            for key, value in ovn_lb.external_ids.items():
                if (key.startswith(ovn_const.LB_EXT_IDS_LISTENER_PREFIX) and
                        pool_key in value):
                    external_ids[key] = value.split(':')[0] + ':'
                    commands.append(
                        self.ovn_nbdb_api.db_set(
                            'Load_Balancer', ovn_lb.uuid,
                            ('external_ids', external_ids)))

            pool_key_when_disabled = self._get_pool_key(pool[constants.ID],
                                                        is_enabled=False)
            if pool_key_when_disabled in ovn_lb.external_ids:
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid,
                        'external_ids', (pool_key_when_disabled)))

            commands.extend(
                self._clean_lb_if_empty(
                    ovn_lb, pool[constants.LOADBALANCER_ID], external_ids)[0])
            self._execute_commands(commands)

        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "deletion of pool")
            status = {
                constants.POOLS: [
                    {constants.ID: pool[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR}],
                constants.LOADBALANCERS: [
                    {constants.ID: pool[constants.LOADBALANCER_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}

        listener_status = []
        for listener in pool_listeners:
            listener_status.append(
                {constants.ID: listener,
                 constants.PROVISIONING_STATUS: constants.ACTIVE})
        status[constants.LISTENERS] = listener_status

        return status

    def pool_update(self, pool):
        pool_status = {constants.ID: pool[constants.ID],
                       constants.PROVISIONING_STATUS: constants.ACTIVE}
        lbalancer_status = {constants.ID: pool[constants.LOADBALANCER_ID],
                            constants.PROVISIONING_STATUS: constants.ACTIVE}
        status = {
            constants.POOLS: [pool_status],
            constants.LOADBALANCERS: [lbalancer_status]}
        if constants.ADMIN_STATE_UP not in pool:
            return status
        try:
            ovn_lb = self._find_ovn_lbs(
                pool[constants.LOADBALANCER_ID],
                protocol=pool[constants.PROTOCOL])
        except idlutils.RowNotFound:
            LOG.exception(ovn_const.EXCEPTION_MSG, "update of pool")
            # LB row not found during update of a listener. That is a problem.
            pool_status[constants.PROVISIONING_STATUS] = constants.ERROR
            lbalancer_status[constants.PROVISIONING_STATUS] = constants.ERROR
            return status

        pool_key = self._get_pool_key(pool[constants.ID])
        p_key_when_disabled = self._get_pool_key(pool[constants.ID],
                                                 is_enabled=False)
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        p_key_to_remove = None
        p_key_to_add = {}

        pool_listeners = []

        try:
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            if pool[constants.ADMIN_STATE_UP]:
                if p_key_when_disabled in external_ids:
                    p_key_to_add[pool_key] = external_ids[p_key_when_disabled]
                    external_ids[pool_key] = external_ids[p_key_when_disabled]
                    del external_ids[p_key_when_disabled]
                    p_key_to_remove = p_key_when_disabled
            else:
                if pool_key in external_ids:
                    p_key_to_add[p_key_when_disabled] = external_ids[pool_key]
                    external_ids[p_key_when_disabled] = external_ids[pool_key]
                    del external_ids[pool_key]
                    p_key_to_remove = pool_key

            if p_key_to_remove:
                commands = []
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid, 'external_ids',
                        (p_key_to_remove)))

                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('external_ids', p_key_to_add)))

                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids))
                self._execute_commands(commands)
            if pool[constants.ADMIN_STATE_UP]:
                operating_status = constants.ONLINE
            else:
                operating_status = constants.OFFLINE
            pool_status[constants.OPERATING_STATUS] = operating_status

        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "update of pool")
            status = {
                constants.POOLS: [
                    {constants.ID: pool[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR}],
                constants.LOADBALANCERS: [
                    {constants.ID: pool[constants.LOADBALANCER_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}

        listener_status = []
        for listener in pool_listeners:
            listener_status.append(
                {constants.ID: listener,
                 constants.PROVISIONING_STATUS: constants.ACTIVE})
        status[constants.LISTENERS] = listener_status

        return status

    def _find_member_status(self, ovn_lb, member_id):
        # NOTE (froyo): Search on lb.external_ids under tag
        # neutron:member_status, if member not found we will return
        # NO_MONITOR
        try:
            existing_members = ovn_lb.external_ids.get(
                ovn_const.OVN_MEMBER_STATUS_KEY)
            existing_members = jsonutils.loads(existing_members)
            return existing_members[member_id]
        except TypeError:
            LOG.debug("no member status on external_ids: %s",
                      str(existing_members))
        except KeyError:
            LOG.debug("Error member_id %s not found on member_status",
                      str(member_id))
        return constants.NO_MONITOR

    def _update_member_statuses(self, ovn_lb, pool_id, provisioning_status,
                                operating_status):
        member_statuses = []
        existing_members = ovn_lb.external_ids.get(
            ovn_const.LB_EXT_IDS_POOL_PREFIX + str(pool_id))
        if len(existing_members) > 0:
            for mem_info in existing_members.split(','):
                member_statuses.append({
                    constants.ID: mem_info.split('_')[1],
                    constants.PROVISIONING_STATUS: provisioning_status,
                    constants.OPERATING_STATUS: operating_status})
                self._update_external_ids_member_status(
                    ovn_lb,
                    mem_info.split('_')[1],
                    operating_status)
        return member_statuses

    def _update_external_ids_member_status(self, ovn_lb, member, status=None,
                                           delete=False):
        existing_members = ovn_lb.external_ids.get(
            ovn_const.OVN_MEMBER_STATUS_KEY)
        try:
            existing_members = jsonutils.loads(existing_members)
        except TypeError:
            LOG.debug("no member status on external_ids: %s",
                      str(existing_members))
            existing_members = {}

        if delete:
            if member in existing_members:
                del existing_members[member]
        else:
            existing_members[member] = status

        try:
            if existing_members:
                member_status = {
                    ovn_const.OVN_MEMBER_STATUS_KEY:
                        jsonutils.dumps(existing_members)}
                self.ovn_nbdb_api.db_set(
                    'Load_Balancer', ovn_lb.uuid,
                    ('external_ids', member_status)).execute()
            else:
                self.ovn_nbdb_api.db_remove(
                    'Load_Balancer', ovn_lb.uuid, 'external_ids',
                    (ovn_const.OVN_MEMBER_STATUS_KEY)).execute()
        except Exception:
            LOG.exception("Error storing member status on external_ids member:"
                          " %s delete: %s status: %s", str(member),
                          str(delete), str(status))

    def _add_member(self, member, ovn_lb, pool_key):
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key]
        if existing_members:
            existing_members = existing_members.split(",")
        member_info = self._get_member_info(member)
        if member_info in existing_members:
            # Member already present
            return None
        if existing_members:
            existing_members.append(member_info)
            pool_data = {pool_key: ",".join(existing_members)}
        else:
            pool_data = {pool_key: member_info}

        commands = []
        commands.append(
            self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                     ('external_ids', pool_data)))

        external_ids[pool_key] = pool_data[pool_key]
        commands.extend(self._refresh_lb_vips(ovn_lb.uuid, external_ids))
        # Note (froyo): commands are now splitted to separate atomic process,
        # leaving outside the not mandatory ones to allow add_member
        # finish correctly
        self._execute_commands(commands)

        subnet_id = member[constants.SUBNET_ID]
        self._update_lb_to_ls_association(
            ovn_lb, subnet_id=subnet_id, associate=True, update_ls_ref=True)

        # Make sure that all logical switches related to logical router
        # are associated with the load balancer. This is needed to handle
        # potential race that happens when lrp and lb are created at the
        # same time.
        neutron_client = clients.get_neutron_client()
        ovn_lr = None
        try:
            subnet = neutron_client.show_subnet(subnet_id)
            ls_name = utils.ovn_name(subnet['subnet']['network_id'])
            ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                check_error=True)
            ovn_lr = self._find_lr_of_ls(
                ovn_ls, subnet['subnet'].get('gateway_ip'))
        except n_exc.NotFound:
            pass
        except idlutils.RowNotFound:
            pass

        if ovn_lr:
            try:
                self._update_lb_to_lr_association(ovn_lb, ovn_lr)
            except idlutils.RowNotFound:
                LOG.warning("The association of loadbalancer %s to the "
                            "logical router %s failed, trying step by step",
                            ovn_lb.uuid, ovn_lr.uuid)
                self._update_lb_to_lr_association_by_step(ovn_lb, ovn_lr)

        return member_info

    def member_create(self, member):
        new_member = None
        pool_listeners = []
        try:
            pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(
                member[constants.POOL_ID])
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            new_member = self._add_member(member, ovn_lb, pool_key)
            pool = {constants.ID: member[constants.POOL_ID],
                    constants.PROVISIONING_STATUS: constants.ACTIVE,
                    constants.OPERATING_STATUS: constants.ONLINE}
            member_status = {constants.ID: member[constants.ID],
                             constants.PROVISIONING_STATUS: constants.ACTIVE}
            if not member[constants.ADMIN_STATE_UP]:
                member_status[constants.OPERATING_STATUS] = constants.OFFLINE
            status = {
                constants.POOLS: [pool],
                constants.MEMBERS: [member_status],
                constants.LOADBALANCERS: [
                    {constants.ID: ovn_lb.name,
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "creation of member")
            status = {
                constants.POOLS: [
                    {constants.ID: member[constants.POOL_ID],
                     constants.PROVISIONING_STATUS: constants.ERROR}],
                constants.MEMBERS: [
                    {constants.ID: member[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}],
                constants.LOADBALANCERS: [
                    {constants.ID: ovn_lb.name,
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}

        listener_status = []
        for listener in pool_listeners:
            listener_status.append(
                {constants.ID: listener,
                 constants.PROVISIONING_STATUS: constants.ACTIVE})
        status[constants.LISTENERS] = listener_status

        operating_status = constants.NO_MONITOR
        if new_member and ovn_lb.health_check:
            operating_status = constants.ONLINE
            if not self._update_hm_members(ovn_lb, pool_key):
                operating_status = constants.ERROR
            member_status[constants.OPERATING_STATUS] = operating_status

        self._update_external_ids_member_status(
            ovn_lb,
            member[constants.ID],
            operating_status)

        return status

    def _remove_member(self, member, ovn_lb, pool_key):
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key].split(",")
        member_info = self._get_member_info(member)
        if member_info in existing_members:
            commands = []
            existing_members.remove(member_info)

            if not existing_members:
                pool_status = constants.OFFLINE
            else:
                pool_status = constants.ONLINE
            pool_data = {pool_key: ",".join(existing_members)}
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', pool_data)))
            external_ids[pool_key] = ",".join(existing_members)
            commands.extend(
                self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            self._execute_commands(commands)
            self._update_lb_to_ls_association(
                ovn_lb, subnet_id=member.get(constants.SUBNET_ID),
                associate=False, update_ls_ref=True)
            return pool_status
        else:
            msg = f"Member {member[constants.ID]} not found in the pool"
            raise driver_exceptions.DriverError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def member_delete(self, member):
        pool_listeners = []
        try:
            pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(
                member[constants.POOL_ID])
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            pool_status = self._remove_member(member, ovn_lb, pool_key)
            pool = {constants.ID: member[constants.POOL_ID],
                    constants.PROVISIONING_STATUS: constants.ACTIVE,
                    constants.OPERATING_STATUS: pool_status}
            if ovn_lb.health_check:
                self._update_hm_members(ovn_lb, pool_key)
                # NOTE(froyo): if the pool status is OFFLINE there are no more
                # members. So we should ensure the hm-port is deleted if no
                # more LB are using it. We need to do this call after the
                # cleaning of the ip_port_mappings for the ovn LB.
                if pool_status == constants.OFFLINE:
                    self._clean_up_hm_port(member['subnet_id'])
            status = {
                constants.POOLS: [pool],
                constants.MEMBERS: [
                    {constants.ID: member[constants.ID],
                     constants.PROVISIONING_STATUS: constants.DELETED}],
                constants.LOADBALANCERS: [
                    {constants.ID: ovn_lb.name,
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "deletion of member")
            status = {
                constants.POOLS: [
                    {constants.ID: member[constants.POOL_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}],
                constants.MEMBERS: [
                    {constants.ID: member[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR}],
                constants.LOADBALANCERS: [
                    {constants.ID: ovn_lb.name,
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}

        self._update_external_ids_member_status(
            ovn_lb, member[constants.ID], None, delete=True)

        listener_status = []
        for listener in pool_listeners:
            listener_status.append(
                {constants.ID: listener,
                 constants.PROVISIONING_STATUS: constants.ACTIVE})
        status[constants.LISTENERS] = listener_status

        return status

    def _update_member(self, member, ovn_lb, pool_key):
        commands = []
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key].split(",")
        member_info = self._get_member_info(member)
        for mem in existing_members:
            if (member_info.split('_')[1] == mem.split('_')[1] and
                    mem != member_info):
                existing_members.remove(mem)
                existing_members.append(member_info)
                pool_data = {pool_key: ",".join(existing_members)}
                commands.append(
                    self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                             ('external_ids', pool_data)))
                external_ids[pool_key] = ",".join(existing_members)
                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids))
                self._execute_commands(commands)

    def member_update(self, member):
        pool_listeners = []
        try:
            pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(
                member[constants.POOL_ID])
            member_status = {constants.ID: member[constants.ID],
                             constants.PROVISIONING_STATUS: constants.ACTIVE}
            status = {
                constants.POOLS: [
                    {constants.ID: member[constants.POOL_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}],
                constants.MEMBERS: [member_status],
                constants.LOADBALANCERS: [
                    {constants.ID: ovn_lb.name,
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            self._update_member(member, ovn_lb, pool_key)
            if constants.ADMIN_STATE_UP in member:
                if member[constants.ADMIN_STATE_UP]:
                    # if HM exists trust on neutron:member_status
                    # as the last status valid for the member
                    if ovn_lb.health_check:
                        # search status of member_uuid
                        last_status = self._find_member_status(
                            ovn_lb, member[constants.ID])
                        member_status[constants.OPERATING_STATUS] = last_status
                    else:
                        member_status[constants.OPERATING_STATUS] = (
                            constants.NO_MONITOR)
                else:
                    member_status[constants.OPERATING_STATUS] = (
                        constants.OFFLINE)
        except Exception:
            LOG.exception(ovn_const.EXCEPTION_MSG, "update of member")
            status = {
                constants.POOLS: [
                    {constants.ID: member[constants.POOL_ID],
                     constants.PROVISIONING_STATUS: constants.ACTIVE}],
                constants.MEMBERS: [
                    {constants.ID: member[constants.ID],
                     constants.PROVISIONING_STATUS: constants.ERROR}],
                constants.LOADBALANCERS: [
                    {constants.ID: ovn_lb.name,
                     constants.PROVISIONING_STATUS: constants.ACTIVE}]}

        if constants.OPERATING_STATUS in member_status:
            self._update_external_ids_member_status(
                ovn_lb,
                member[constants.ID],
                member_status[constants.OPERATING_STATUS])

        listener_status = []
        for listener in pool_listeners:
            listener_status.append(
                {constants.ID: listener,
                 constants.PROVISIONING_STATUS: constants.ACTIVE})
        status[constants.LISTENERS] = listener_status
        return status

    def _get_existing_pool_members(self, pool_id):
        pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(pool_id)
        if not ovn_lb:
            msg = _("Loadbalancer with pool %s does not exist") % pool_key
            raise driver_exceptions.DriverError(msg)
        external_ids = dict(ovn_lb.external_ids)
        return external_ids[pool_key]

    def get_pool_member_id(self, pool_id, mem_addr_port=None):
        '''Gets Member information

        :param pool_id: ID of the Pool whose member information is reqd.
        :param mem_addr_port: Combination of Member Address+Port. Default=None
        :returns: UUID -- ID of the Member if member exists in pool.
        :returns: None -- if no member exists in the pool
        :raises: Exception if Loadbalancer is not found for a Pool ID
        '''
        existing_members = self._get_existing_pool_members(pool_id)
        # Members are saved in OVN in the form of
        # member1_UUID_IP:Port, member2_UUID_IP:Port
        # Match the IP:Port for all members with the mem_addr_port
        # information and return the UUID.
        for meminf in existing_members.split(','):
            if mem_addr_port == meminf.split('_')[2]:
                return meminf.split('_')[1]

    def create_vip_port(self, project_id, lb_id, vip_d):
        port = {'port': {'name': ovn_const.LB_VIP_PORT_PREFIX + str(lb_id),
                         'network_id': vip_d[constants.VIP_NETWORK_ID],
                         'fixed_ips': [{'subnet_id': vip_d['vip_subnet_id']}],
                         'admin_state_up': True,
                         'project_id': project_id}}
        try:
            port['port']['fixed_ips'][0]['ip_address'] = (
                vip_d[constants.VIP_ADDRESS])
        except KeyError:
            pass
        neutron_client = clients.get_neutron_client()
        try:
            return neutron_client.create_port(port)
        except n_exc.IpAddressAlreadyAllocatedClient as e:
            # Sometimes the VIP is already created (race-conditions)
            # Lets get the it from Neutron API.
            ports = self._neutron_list_ports(neutron_client, **{
                'network_id': vip_d[constants.VIP_NETWORK_ID],
                'name': f'{ovn_const.LB_VIP_PORT_PREFIX}{lb_id}'})
            if not ports['ports']:
                LOG.error('Cannot create/get LoadBalancer VIP port with '
                          'fixed IP: %s', vip_d[constants.VIP_ADDRESS])
                raise e
            # there should only be one port returned
            port = ports['ports'][0]
            LOG.debug('VIP Port already exists, uuid: %s', port['id'])
            return {'port': port}
        except n_exc.NeutronClientException as e:
            # NOTE (froyo): whatever other exception as e.g. Timeout
            # we should try to ensure no leftover port remains
            ports = self._neutron_list_ports(neutron_client, **{
                'network_id': vip_d[constants.VIP_NETWORK_ID],
                'name': f'{ovn_const.LB_VIP_PORT_PREFIX}{lb_id}'})
            if ports['ports']:
                port = ports['ports'][0]
                LOG.debug('Leftover port %s has been found. Trying to '
                          'delete it', port['id'])
                self.delete_port(port['id'])
            raise e

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(
            n_exc.NeutronClientException),
        wait=tenacity.wait_exponential(max=75),
        stop=tenacity.stop_after_attempt(15),
        reraise=True)
    def delete_port(self, port_id):
        neutron_client = clients.get_neutron_client()
        try:
            neutron_client.delete_port(port_id)
        except n_exc.PortNotFoundClient:
            LOG.warning("Port %s could not be found. Please "
                        "check Neutron logs. Perhaps port "
                        "was already deleted.", port_id)

    def handle_vip_fip(self, fip_info):
        ovn_lb = fip_info['ovn_lb']
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        commands = []

        if fip_info['action'] == ovn_const.REQ_INFO_ACTION_ASSOCIATE:
            external_ids[ovn_const.LB_EXT_IDS_VIP_FIP_KEY] = (
                fip_info['vip_fip'])
            vip_fip_info = {
                ovn_const.LB_EXT_IDS_VIP_FIP_KEY: fip_info['vip_fip']}
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', vip_fip_info)))
            if ovn_lb.health_check:
                kwargs = {
                    'vip': fip_info['vip_fip'],
                    'options': ovn_lb.health_check[0].options,
                    'external_ids': ovn_lb.health_check[0].external_ids}
                with self.ovn_nbdb_api.transaction(check_error=True) as txn:
                    fip_lbhc = txn.add(
                        self.ovn_nbdb_api.db_create(
                            'Load_Balancer_Health_Check', **kwargs))
                    txn.add(self.ovn_nbdb_api.db_add(
                        'Load_Balancer', ovn_lb.uuid,
                        'health_check', fip_lbhc))
        else:
            external_ids.pop(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
            commands.append(
                self.ovn_nbdb_api.db_remove(
                    'Load_Balancer', ovn_lb.uuid, 'external_ids',
                    (ovn_const.LB_EXT_IDS_VIP_FIP_KEY)))
            old_fip = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
            for lbhc in ovn_lb.health_check:
                # FIPs can only be ipv4, so not dealing with ipv6 [] here
                if lbhc.vip.split(":")[0] == old_fip:
                    commands.append(
                        self.ovn_nbdb_api.db_remove('Load_Balancer',
                                                    ovn_lb.uuid,
                                                    'health_check',
                                                    lbhc.uuid))
                    commands.append(self.ovn_nbdb_api.db_destroy(
                        'Load_Balancer_Health_Check', lbhc.uuid))
                    break

        commands.extend(self._refresh_lb_vips(ovn_lb.uuid, external_ids))
        self._execute_commands(commands)

    def handle_member_dvr(self, info):
        pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(info['pool_id'])
        if not ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY):
            LOG.debug("LB %(lb)s has no FIP on VIP configured. "
                      "There is no need to centralize member %(member)s "
                      "traffic.",
                      {'lb': ovn_lb.uuid, 'member': info['id']})
            return

        # Find out if member has FIP assigned.
        neutron_client = clients.get_neutron_client()
        try:
            subnet = neutron_client.show_subnet(info['subnet_id'])
            ls_name = utils.ovn_name(subnet['subnet']['network_id'])
        except n_exc.NotFound:
            LOG.exception('Subnet %s not found while trying to '
                          'fetch its data.', info['subnet_id'])
            return

        try:
            ls = self.ovn_nbdb_api.lookup('Logical_Switch', ls_name)
        except idlutils.RowNotFound:
            LOG.warning("Logical Switch %s not found. "
                        "Cannot verify member FIP configuration.",
                        ls_name)
            return

        fip = None
        f = utils.remove_macs_from_lsp_addresses
        for port in ls.ports:
            if info['address'] in f(port.addresses):
                # We found particular port
                fip = self.ovn_nbdb_api.db_find_rows(
                    'NAT', ('external_ids', '=', {
                        ovn_const.OVN_FIP_PORT_EXT_ID_KEY: port.name})
                ).execute(check_error=True)
                fip = fip[0] if fip else fip
                break

        if not fip:
            LOG.debug('Member %s has no FIP assigned. '
                      'There is no need to modify its NAT.',
                      info['id'])
            return

        if info['action'] == ovn_const.REQ_INFO_MEMBER_ADDED:
            LOG.info('Member %(member)s is added to Load Balancer %(lb)s '
                     'and both have FIP assigned. Member FIP %(fip)s '
                     'needs to be centralized in those conditions. '
                     'Deleting external_mac/logical_port from it.',
                     {'member': info['id'],
                      'lb': ovn_lb.uuid,
                      'fip': fip.external_ip})
            self.ovn_nbdb_api.db_clear(
                'NAT', fip.uuid, 'external_mac').execute(check_error=True)
            self.ovn_nbdb_api.db_clear(
                'NAT', fip.uuid, 'logical_port').execute(check_error=True)
        else:
            LOG.info('Member %(member)s is deleted from Load Balancer '
                     '%(lb)s and both have FIP assigned. Member FIP %(fip)s '
                     'can be decentralized now if environment has DVR '
                     'enabled.  Updating FIP object for recomputation.',
                     {'member': info['id'],
                      'lb': ovn_lb.uuid,
                      'fip': fip.external_ip})
            # NOTE(mjozefcz): We don't know if this env is DVR or not.
            # We should call neutron API to do 'empty' update of the FIP.
            # It will bump revision number and do recomputation of the FIP.
            try:
                fip_info = neutron_client.show_floatingip(
                    fip.external_ids[ovn_const.OVN_FIP_EXT_ID_KEY])
                empty_update = {
                    "floatingip": {
                        'description': fip_info['floatingip']['description']}}
                neutron_client.update_floatingip(
                    fip.external_ids[ovn_const.OVN_FIP_EXT_ID_KEY],
                    empty_update)
            except n_exc.NotFound:
                LOG.warning('Member %(member)s FIP %(fip)s not found in '
                            'Neutron. Cannot update it.',
                            {'member': info['id'],
                             'fip': fip.external_ip})

    def _get_member_lsp(self, member_ip, member_subnet_id):
        neutron_client = clients.get_neutron_client()
        try:
            member_subnet = neutron_client.show_subnet(member_subnet_id)
        except n_exc.NotFound:
            LOG.exception('Subnet %s not found while trying to '
                          'fetch its data.', member_subnet_id)
            return
        ls_name = utils.ovn_name(member_subnet['subnet']['network_id'])
        try:
            ls = self.ovn_nbdb_api.lookup('Logical_Switch', ls_name)
        except idlutils.RowNotFound:
            LOG.warning("Logical Switch %s not found.", ls_name)
            return
        f = utils.remove_macs_from_lsp_addresses
        for port in ls.ports:
            if member_ip in f(port.addresses):
                # We found particular port
                return port

    def _add_lbhc(self, ovn_lb, pool_key, info):
        hm_id = info[constants.ID]
        status = {constants.ID: hm_id,
                  constants.PROVISIONING_STATUS: constants.ERROR,
                  constants.OPERATING_STATUS: constants.ERROR}
        # Example
        # MONITOR_PRT = 80
        # ID=$(ovn-nbctl --bare --column _uuid find
        #    Load_Balancer_Health_Check vip="${LB_VIP_ADDR}\:${MONITOR_PRT}")
        # In our case the monitor port will be the members protocol port
        vip = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_KEY)
        fip = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
        if not vip:
            LOG.error("Could not find VIP for HM %s, LB external_ids: %s",
                      hm_id, ovn_lb.external_ids)
            return status
        vip_port = self._get_pool_listener_port(ovn_lb, pool_key)
        if not vip_port:
            # This is not fatal as we can add it when a listener is created
            vip = []
            if fip:
                fip = []
        else:
            vip = vip + ':' + vip_port
            if fip:
                fip = fip + ':' + vip_port

        # ovn-nbctl --wait=sb --
        #  set Load_Balancer_Health_Check ${ID} options:\"interval\"=6 --
        #  set Load_Balancer_Health_Check ${ID} options:\"timeoutl\"=2 --
        #  set Load_Balancer_Health_Check ${ID} options:\"success_count\"=1 --
        #  set Load_Balancer_Health_Check ${ID} options:\"failure_count\"=3
        options = {
            'interval': str(info['interval']),
            'timeout': str(info['timeout']),
            'success_count': str(info['success_count']),
            'failure_count': str(info['failure_count'])}

        # This is to enable lookups by Octavia DB ID value
        external_ids = {ovn_const.LB_EXT_IDS_HM_KEY: hm_id}

        # Just seems like this needs ovsdbapp support, see:
        #  ovsdbapp/schema/ovn_northbound/impl_idl.py - lb_add()
        #  ovsdbapp/schema/ovn_northbound/commands.py - LbAddCommand()
        # then this could just be self.ovn_nbdb_api.lb_hm_add()
        kwargs = {
            'vip': vip,
            'options': options,
            'external_ids': external_ids}
        if fip is not None:
            fip_kwargs = {
                'vip': fip,
                'options': options,
                'external_ids': external_ids}

        operating_status = constants.ONLINE
        if not info['admin_state_up']:
            operating_status = constants.OFFLINE

        hms_key = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_HMS_KEY, [])
        if hms_key:
            hms_key = jsonutils.loads(hms_key)
        try:
            with self.ovn_nbdb_api.transaction(check_error=True) as txn:
                health_check = txn.add(
                    self.ovn_nbdb_api.db_create(
                        'Load_Balancer_Health_Check',
                        **kwargs))
                txn.add(self.ovn_nbdb_api.db_add(
                    'Load_Balancer', ovn_lb.uuid,
                    'health_check', health_check))
                if fip is not None:
                    fip_health_check = txn.add(
                        self.ovn_nbdb_api.db_create(
                            'Load_Balancer_Health_Check',
                            **fip_kwargs))
                    txn.add(self.ovn_nbdb_api.db_add(
                        'Load_Balancer', ovn_lb.uuid,
                        'health_check', fip_health_check))
                hms_key.append(hm_id)
                txn.add(self.ovn_nbdb_api.db_set(
                    'Load_Balancer', ovn_lb.uuid,
                    ('external_ids', {ovn_const.LB_EXT_IDS_HMS_KEY:
                                      jsonutils.dumps(hms_key)})))
            status = {constants.ID: hm_id,
                      constants.PROVISIONING_STATUS: constants.ACTIVE,
                      constants.OPERATING_STATUS: operating_status}
        except Exception:
            # Any Exception will return ERROR status
            LOG.exception(ovn_const.EXCEPTION_MSG, "set of health check")
        return status

    def _update_lbhc_vip(self, ovn_lb, vip_port):
        vip = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_KEY)
        if not vip:
            LOG.error("Could not find VIP for LB external_ids: %s",
                      ovn_lb.external_ids)
            return False

        vip_version = netaddr.IPAddress(vip).version
        if vip_version == 6:
            vip_lbhc = [lbhc for lbhc in ovn_lb.health_check
                        if lbhc.vip == [] or lbhc.vip[1:].split("]")[0] == vip]
        else:
            vip_lbhc = [lbhc for lbhc in ovn_lb.health_check
                        if lbhc.vip == [] or lbhc.vip.split(":")[0] == vip]
        if not vip_lbhc:
            LOG.error("Could not find HC associated to VIP: %s", vip)
            return False

        vip = vip + ':' + str(vip_port)
        fip = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
        create_fip_lbhc = False
        if fip:
            fip = fip + ':' + str(vip_port)
            if len(ovn_lb.health_check) != 2:
                LOG.warning("There should be two HCs associated to the Load "
                            "Balancer %s as it has a FIP associated to it",
                            ovn_lb.uuid)
                create_fip_lbhc = True

        commands = []
        commands.append(
            self.ovn_nbdb_api.db_set(
                'Load_Balancer_Health_Check', ovn_lb.health_check[0].uuid,
                ('vip', vip)))
        if fip:
            if create_fip_lbhc:
                # For upgrades purposes we need to recover from this situation
                # and create the health_check for the FIP
                kwargs = {
                    'vip': fip,
                    'options': vip_lbhc[0].options,
                    'external_ids': vip_lbhc[0].external_ids}
                with self.ovn_nbdb_api.transaction(check_error=True) as txn:
                    fip_lbhc = txn.add(
                        self.ovn_nbdb_api.db_create(
                            'Load_Balancer_Health_Check', **kwargs))
                    txn.add(self.ovn_nbdb_api.db_add(
                        'Load_Balancer', ovn_lb.uuid,
                        'health_check', fip_lbhc))
            else:
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer_Health_Check',
                        ovn_lb.health_check[1].uuid, ('vip', fip)))
        self._execute_commands(commands)
        return True

    def _update_hm_members(self, ovn_lb, pool_key):
        mappings = {}
        # For each member, set it's HM
        for member_ip, member_port, member_subnet in self._extract_member_info(
                ovn_lb.external_ids[pool_key]):
            member_lsp = self._get_member_lsp(member_ip, member_subnet)
            if not member_lsp:
                # NOTE(froyo): In order to continue evaluating the rest of
                # the members, we just warn about the member issue,
                # assuming that it will be in OFFLINE status as soon as the
                # HM does the first evaluation.
                LOG.error("Member %(member)s Logical_Switch_Port not found, "
                          "when creating a Health Monitor for pool %(pool)s.",
                          {'member': member_ip, 'pool': pool_key})
                continue

            network_id = member_lsp.external_ids.get(
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY).split('neutron-')[1]
            project_id = member_lsp.external_ids.get(
                ovn_const.OVN_PROJECT_EXT_ID_KEY)
            hm_port = self._ensure_hm_ovn_port(
                network_id, member_subnet, project_id)
            if not hm_port:
                LOG.error("No port on network %(network)s available for "
                          "health monitoring. Cannot create a Health Monitor "
                          "for pool %(pool)s.",
                          {'network': network_id,
                           'pool': pool_key})
                return False
            hm_source_ip = None
            for fixed_ip in hm_port['fixed_ips']:
                if fixed_ip['subnet_id'] == member_subnet:
                    hm_source_ip = fixed_ip['ip_address']
                    break
            if not hm_source_ip:
                LOG.error("No port on subnet %(subnet)s available for "
                          "health monitoring member IP %(member)s. Cannot "
                          "create a Health Monitor for pool %(pool)s.",
                          {'subnet': member_subnet,
                           'member': member_ip,
                           'pool': pool_key})
                return False
            # ovn-nbctl set load_balancer ${OVN_LB_ID}
            #   ip_port_mappings:${MEMBER_IP}=${LSP_NAME_MEMBER}:${HEALTH_SRC}
            # where:
            #  OVN_LB_ID: id of LB
            #  MEMBER_IP: IP of member_lsp
            #  HEALTH_SRC: source IP of hm_port

            # need output like this
            # vips: {"172.24.4.246:80"="10.0.0.10:80"}
            # ip_port_mappings: {"10.0.0.10"="ID:10.0.0.2"}
            # ip_port_mappings: {"MEMBER_IP"="LSP_NAME_MEMBER:HEALTH_SRC"}
            # OVN does not support IPv6 Health Checks, but we check anyways
            member_src = f'{member_lsp.name}:'
            if netaddr.IPNetwork(hm_source_ip).version == 6:
                member_src += f'[{hm_source_ip}]'
            else:
                member_src += f'{hm_source_ip}'

            if netaddr.IPNetwork(member_ip).version == 6:
                member_ip = f'[{member_ip}]'
            mappings[member_ip] = member_src

        commands = []
        # NOTE(froyo): This db_clear over field ip_port_mappings is needed just
        # to clean the old values (including the removed member) and the
        # following db_set will update the using the mappings calculated some
        # lines above with reemaining members only.
        # TODO(froyo): use the ovsdbapp commands to add/del members to
        # ip_port_mappings field
        commands.append(
            self.ovn_nbdb_api.db_clear('Load_Balancer', ovn_lb.uuid,
                                       'ip_port_mappings'))
        if mappings:
            commands.append(
                self.ovn_nbdb_api.db_set(
                    'Load_Balancer', ovn_lb.uuid,
                    ('ip_port_mappings', mappings)))
        self._execute_commands(commands)
        return True

    def _lookup_lbhcs_by_hm_id(self, hm_id):
        lbhc_rows = self.ovn_nbdb_api.db_list_rows(
            'Load_Balancer_Health_Check').execute(check_error=True)
        lbhcs = []
        for lbhc in lbhc_rows:
            if (ovn_const.LB_EXT_IDS_HM_KEY in lbhc.external_ids and
                    lbhc.external_ids[ovn_const.LB_EXT_IDS_HM_KEY] == hm_id):
                lbhcs.append(lbhc)
        if lbhcs:
            return lbhcs
        raise idlutils.RowNotFound(table='Load_Balancer_Health_Check',
                                   col='external_ids', match=hm_id)

    def _find_ovn_lb_from_hm_id(self, hm_id):
        lbs = self.ovn_nbdb_api.db_list_rows(
            'Load_Balancer').execute(check_error=True)
        ovn_lb = None
        for lb in lbs:
            if (ovn_const.LB_EXT_IDS_HMS_KEY in lb.external_ids.keys() and
                    hm_id in lb.external_ids[ovn_const.LB_EXT_IDS_HMS_KEY]):
                ovn_lb = lb
                break

        try:
            lbhcs = self._lookup_lbhcs_by_hm_id(hm_id)
        except idlutils.RowNotFound:
            LOG.debug("Loadbalancer health check %s not found!", hm_id)
            return [], ovn_lb

        return lbhcs, ovn_lb

    def hm_create(self, info):
        status = {
            constants.HEALTHMONITORS: [
                {constants.ID: info[constants.ID],
                 constants.OPERATING_STATUS: constants.NO_MONITOR,
                 constants.PROVISIONING_STATUS: constants.ERROR}]}

        pool_id = info[constants.POOL_ID]
        pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(pool_id)
        if not ovn_lb:
            LOG.debug("Could not find LB with pool id %s", pool_id)
            return status

        status[constants.LOADBALANCERS] = [
            {constants.ID: ovn_lb.name,
             constants.PROVISIONING_STATUS: constants.ACTIVE}]
        if pool_key not in ovn_lb.external_ids:
            # Returning early here will cause the pool to go into
            # PENDING_UPDATE state, which is not good
            LOG.error("Could not find pool with key %s, LB external_ids: %s",
                      pool_key, ovn_lb.external_ids)
            status[constants.POOLS] = [
                {constants.ID: pool_id,
                 constants.OPERATING_STATUS: constants.OFFLINE}]
            return status
        status[constants.POOLS] = [
            {constants.ID: pool_id,
             constants.PROVISIONING_STATUS: constants.ACTIVE,
             constants.OPERATING_STATUS: constants.ONLINE}]

        pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)

        status[constants.LISTENERS] = []
        for listener in pool_listeners:
            status[constants.LISTENERS].append(
                {constants.ID: listener,
                 constants.PROVISIONING_STATUS: constants.ACTIVE,
                 constants.OPERATING_STATUS: constants.ONLINE})

        # Update status for all members in the pool
        member_status = self._update_member_statuses(ovn_lb, pool_id,
                                                     constants.ACTIVE,
                                                     constants.ONLINE)
        status[constants.MEMBERS] = member_status

        # MONITOR_PRT = 80
        # ovn-nbctl --wait=sb -- --id=@hc create Load_Balancer_Health_Check
        #   vip="${LB_VIP_ADDR}\:${MONITOR_PRT}" -- add Load_Balancer
        #   ${OVN_LB_ID} health_check @hc
        # options here are interval, timeout, failure_count and success_count
        # from info object passed-in
        hm_status = self._add_lbhc(ovn_lb, pool_key, info)
        if hm_status[constants.PROVISIONING_STATUS] == constants.ACTIVE:
            if not self._update_hm_members(ovn_lb, pool_key):
                hm_status[constants.PROVISIONING_STATUS] = constants.ERROR
                hm_status[constants.OPERATING_STATUS] = constants.ERROR
        status[constants.HEALTHMONITORS] = [hm_status]
        return status

    def hm_update(self, info):
        status = {
            constants.HEALTHMONITORS: [
                {constants.ID: info[constants.ID],
                 constants.OPERATING_STATUS: constants.ERROR,
                 constants.PROVISIONING_STATUS: constants.ERROR}]}

        hm_id = info[constants.ID]
        pool_id = info[constants.POOL_ID]

        lbhcs, ovn_lb = self._find_ovn_lb_from_hm_id(hm_id)
        if not lbhcs:
            LOG.debug("Loadbalancer health check %s not found!", hm_id)
            return status
        if not ovn_lb:
            LOG.debug("Could not find LB with health monitor id %s", hm_id)
            # Do we really need to try this hard?
            pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(pool_id)
            if not ovn_lb:
                LOG.debug("Could not find LB with pool id %s", pool_id)
                return status

        options = {}
        if info['interval']:
            options['interval'] = str(info['interval'])
        if info['timeout']:
            options['timeout'] = str(info['timeout'])
        if info['success_count']:
            options['success_count'] = str(info['success_count'])
        if info['failure_count']:
            options['failure_count'] = str(info['failure_count'])

        commands = []
        for lbhc in lbhcs:
            commands.append(
                self.ovn_nbdb_api.db_set(
                    'Load_Balancer_Health_Check', lbhc.uuid,
                    ('options', options)))
        self._execute_commands(commands)

        operating_status = constants.ONLINE
        if not info['admin_state_up']:
            operating_status = constants.OFFLINE
        status = {
            constants.LOADBALANCERS: [
                {constants.ID: ovn_lb.name,
                 constants.PROVISIONING_STATUS: constants.ACTIVE}],
            constants.POOLS: [
                {constants.ID: pool_id,
                 constants.PROVISIONING_STATUS: constants.ACTIVE}],
            constants.HEALTHMONITORS: [
                {constants.ID: info[constants.ID],
                 constants.OPERATING_STATUS: operating_status,
                 constants.PROVISIONING_STATUS: constants.ACTIVE}]}
        return status

    def hm_delete(self, info):
        hm_id = info[constants.ID]
        pool_id_related = info[constants.POOL_ID]

        status = {
            constants.HEALTHMONITORS: [
                {constants.ID: hm_id,
                 constants.OPERATING_STATUS: constants.NO_MONITOR,
                 constants.PROVISIONING_STATUS: constants.DELETED}]}
        lbhcs, ovn_lb = self._find_ovn_lb_from_hm_id(hm_id)
        if not lbhcs or not ovn_lb:
            LOG.debug("Loadbalancer Health Check associated to Health Monitor "
                      "%s not found in OVN Northbound DB. Setting the "
                      "Loadbalancer Health Monitor status to DELETED in "
                      "Octavia", hm_id)
            return status

        # Need to send pool info in status update to avoid immutable objects,
        # the LB should have this info. Also in order to delete the hm port
        # used for health checks we need to get all subnets from the members
        # on the pool
        pool_id = None
        pool_listeners = []
        member_subnets = []
        for k, v in ovn_lb.external_ids.items():
            if ovn_const.LB_EXT_IDS_POOL_PREFIX in k:
                members = self._extract_member_info(ovn_lb.external_ids[k])
                member_subnets = list(
                    set([mem_subnet for (_, _, mem_subnet) in members])
                )
                pool_id = k.split('_')[1]
                pool_listeners = self._get_pool_listeners(
                    ovn_lb, self._get_pool_key(pool_id))
                break

        # ovn-nbctl clear load_balancer ${OVN_LB_ID} ip_port_mappings
        # ovn-nbctl clear load_balancer ${OVN_LB_ID} health_check
        # TODO(haleyb) remove just the ip_port_mappings for this hm
        hms_key = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_HMS_KEY, [])

        # Update status for members in the pool related to HM
        member_status = self._update_member_statuses(ovn_lb, pool_id_related,
                                                     constants.ACTIVE,
                                                     constants.NO_MONITOR)

        if hms_key:
            hms_key = jsonutils.loads(hms_key)
            if hm_id in hms_key:
                hms_key.remove(hm_id)
        commands = []
        commands.append(
            self.ovn_nbdb_api.db_clear('Load_Balancer', ovn_lb.uuid,
                                       'ip_port_mappings'))
        for lbhc in lbhcs:
            commands.append(
                self.ovn_nbdb_api.db_remove('Load_Balancer', ovn_lb.uuid,
                                            'health_check', lbhc.uuid))
        commands.append(
            self.ovn_nbdb_api.db_set(
                'Load_Balancer', ovn_lb.uuid,
                ('external_ids', {ovn_const.LB_EXT_IDS_HMS_KEY:
                                  jsonutils.dumps(hms_key)})))
        for lbhc in lbhcs:
            commands.append(
                self.ovn_nbdb_api.db_destroy('Load_Balancer_Health_Check',
                                             lbhc.uuid))
        self._execute_commands(commands)

        # Delete the hm port if not in use by other health monitors
        for subnet in member_subnets:
            self._clean_up_hm_port(subnet)

        status = {
            constants.LOADBALANCERS: [
                {constants.ID: ovn_lb.name,
                 constants.PROVISIONING_STATUS: constants.ACTIVE}],
            constants.HEALTHMONITORS: [
                {constants.ID: info[constants.ID],
                 constants.OPERATING_STATUS: constants.NO_MONITOR,
                 constants.PROVISIONING_STATUS: constants.DELETED}]}
        if pool_id:
            status[constants.POOLS] = [
                {constants.ID: pool_id,
                 constants.PROVISIONING_STATUS: constants.ACTIVE}]

            if member_status:
                status[constants.MEMBERS] = member_status

            status[constants.LISTENERS] = []
            for listener in pool_listeners:
                status[constants.LISTENERS].append(
                    {constants.ID: listener,
                     constants.PROVISIONING_STATUS: constants.ACTIVE})
        else:
            LOG.warning('Pool not found for load balancer %s, status '
                        'update will have incomplete data', ovn_lb.name)
        return status

    def _get_lbs_on_hm_event(self, row):
        """Get the Load Balancer information on a health_monitor event

        This function is called when the status of a member has
        been updated. As no duplicate entries are created on a same
        member for different LBs we will search all LBs affected by
        the member reported in the health check event

        Input: Service Monitor row which is coming from
               ServiceMonitorUpdateEvent.
        Output: Rows from load_balancer table table matching the member
                for which the event was generated.
        Exception: RowNotFound exception can be generated.
        """
        # ip_port_mappings: {"MEMBER_IP"="LSP_NAME_MEMBER:HEALTH_SRC"}
        # There could be more than one entry in ip_port_mappings!
        mappings = {}
        hm_source_ip = str(row.src_ip)
        member_ip = str(row.ip)
        member_src = f'{row.logical_port}:'
        if netaddr.IPNetwork(hm_source_ip).version == 6:
            member_src += f'[{hm_source_ip}]'
        else:
            member_src += f'{hm_source_ip}'
        if netaddr.IPNetwork(member_ip).version == 6:
            member_ip = f'[{member_ip}]'
        mappings[member_ip] = member_src
        lbs = self.ovn_nbdb_api.db_find_rows(
            'Load_Balancer', ('ip_port_mappings', '=', mappings),
            ('protocol', '=', row.protocol[0])).execute()
        return lbs if lbs else None

    def sm_update_event_handler(self, row, sm_delete_event=False):
        # NOTE(froyo): When a delete event is triggered, the Service_Monitor
        # deleted row will include the last valid information, e.g. when the
        # port is directly removed from the VM, the status will be 'online',
        # in order to protect from this behaviour, we will set manually the
        # status to 'offline' if sm_delete_event is reported as True.
        try:
            ovn_lbs = self._get_lbs_on_hm_event(row)
        except idlutils.RowNotFound:
            LOG.debug("Load balancer information not found")
            return

        if not ovn_lbs:
            LOG.debug("Load balancer not found")
            return

        request_info = {
            "ovn_lbs": ovn_lbs,
            "ip": row.ip,
            "port": str(row.port),
            "status": row.status
            if not sm_delete_event
            else ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE,
        }
        self.add_request({'type': ovn_const.REQ_TYPE_HM_UPDATE_EVENT,
                          'info': request_info})

    def _get_current_operating_statuses(self, ovn_lb):
        # NOTE (froyo) We would base all logic in the external_ids field
        # 'neutron:member_status' that should include all LB member status
        # in order to calculate the global LB status (listeners, pools, members
        # included)
        status = {
            constants.LOADBALANCERS: [],
            constants.LISTENERS: [],
            constants.POOLS: [],
            constants.MEMBERS: []
        }

        listeners = {}
        pools = {}
        member_statuses = ovn_lb.external_ids.get(
            ovn_const.OVN_MEMBER_STATUS_KEY)

        try:
            member_statuses = jsonutils.loads(member_statuses)
        except TypeError:
            LOG.debug("no member status on external_ids: %s",
                      str(member_statuses))
            member_statuses = {}

        for k, v in ovn_lb.external_ids.items():
            if ovn_const.LB_EXT_IDS_LISTENER_PREFIX in k:
                listeners[k.split('_')[1]] = [
                    x.split('_')[1] for x in v.split(',')]
                continue
            if ovn_const.LB_EXT_IDS_POOL_PREFIX in k:
                pools[k.split('_')[1]] = [
                    x.split('_')[1] for x in v.split(',')]
                continue

        for member_id, member_status in member_statuses.items():
            status[constants.MEMBERS].append({
                constants.ID: member_id,
                constants.PROVISIONING_STATUS: constants.ACTIVE,
                constants.OPERATING_STATUS: member_status})

        # get pool statuses
        for pool_id, members in pools.items():
            for i, member in enumerate(members):
                if member in member_statuses:
                    members[i] = member_statuses[member]
                else:
                    # if we don't have local info we assume best option
                    members[i] = constants.ONLINE

            _pool = self._octavia_driver_lib.get_pool(pool_id)
            if not _pool.admin_state_up:
                pools[pool_id] = constants.OFFLINE
            elif all(constants.ERROR == member_status
                     for member_status in pools[pool_id]):
                pools[pool_id] = constants.ERROR
            elif any(constants.ERROR == member_status
                     for member_status in pools[pool_id]):
                pools[pool_id] = constants.DEGRADED
            else:
                pools[pool_id] = constants.ONLINE

            status[constants.POOLS].append(
                {constants.ID: pool_id,
                 constants.PROVISIONING_STATUS: constants.ACTIVE,
                 constants.OPERATING_STATUS: pools[pool_id]})

        # get listener statuses
        for listener_id, listener_pools in listeners.items():
            for i, pool in enumerate(listener_pools):
                if pool in pools:
                    listener_pools[i] = pools[pool]
                else:
                    # if we don't have local info we assume best option
                    listener_pools[i] = constants.ONLINE

            _listener = self._octavia_driver_lib.get_listener(listener_id)
            if not _listener.admin_state_up:
                listeners[listener_id] = constants.OFFLINE
            elif any(constants.ERROR == pool_status
                     for pool_status in listeners[listener_id]):
                listeners[listener_id] = constants.ERROR
            elif any(constants.DEGRADED == pool_status
                     for pool_status in listeners[listener_id]):
                listeners[listener_id] = constants.DEGRADED
            else:
                listeners[listener_id] = constants.ONLINE

            status[constants.LISTENERS].append(
                {constants.ID: listener_id,
                 constants.PROVISIONING_STATUS: constants.ACTIVE,
                 constants.OPERATING_STATUS: listeners[listener_id]})

        # get LB status
        lb_status = constants.ONLINE
        _lb = self._octavia_driver_lib.get_loadbalancer(ovn_lb.name)
        if not _lb.admin_state_up:
            lb_status = constants.OFFLINE
        elif any(constants.ERROR == status
                 for status in listeners.values()):
            lb_status = constants.ERROR
        elif any(constants.DEGRADED == status
                 for status in listeners.values()):
            lb_status = constants.DEGRADED
        status[constants.LOADBALANCERS].append({
            constants.ID: ovn_lb.name,
            constants.PROVISIONING_STATUS: constants.ACTIVE,
            constants.OPERATING_STATUS: lb_status})

        return status

    def hm_update_event(self, info):
        ovn_lbs = info['ovn_lbs']
        statuses = []

        for ovn_lb in ovn_lbs:
            # Lookup member
            member_id = None
            for k, v in ovn_lb.external_ids.items():
                if ovn_const.LB_EXT_IDS_POOL_PREFIX not in k:
                    continue
                for (
                    member_ip,
                    member_port,
                    subnet,
                ) in self._extract_member_info(v):
                    if info['ip'] != member_ip:
                        continue
                    if info['port'] != member_port:
                        continue
                    # match
                    member_id = [mb.split('_')[1] for mb in v.split(',')
                                 if member_ip in mb and member_port in mb][0]
                    break

                # found it in inner loop
                if member_id:
                    break

            if not member_id:
                LOG.warning('Member for event not found, info: %s', info)
            else:
                member_status = constants.ONLINE
                if info['status'] == ovn_const.HM_EVENT_MEMBER_PORT_OFFLINE:
                    member_status = constants.ERROR

                self._update_external_ids_member_status(ovn_lb, member_id,
                                                        member_status)
                statuses.append(self._get_current_operating_statuses(ovn_lb))

        if not statuses:
            return

        status = {}

        for status_lb in statuses:
            for k in status_lb.keys():
                if k not in status:
                    status[k] = []
                status[k].extend(status_lb[k])

        return status
