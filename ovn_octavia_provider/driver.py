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

import netaddr
from octavia_lib.api.drivers import data_models as o_datamodels
from octavia_lib.api.drivers import exceptions as driver_exceptions
from octavia_lib.api.drivers import provider_base as driver_base
from octavia_lib.common import constants
from oslo_log import log as logging

from ovn_octavia_provider.common import config as ovn_conf
# TODO(mjozefcz): Start consuming const and utils
# from neutron-lib once released.
from ovn_octavia_provider.common import constants as ovn_const
from ovn_octavia_provider.common import exceptions as ovn_exc
from ovn_octavia_provider import helper as ovn_helper
from ovn_octavia_provider.i18n import _


LOG = logging.getLogger(__name__)


class OvnProviderDriver(driver_base.ProviderDriver):

    def __init__(self):
        super().__init__()

        # NOTE (froyo): Move inside init method in order to
        # avoid the issues on test scope colliding with Neutron
        # already registered options when this register was
        # called from outside of the class a soon this module
        # was imported, also to cover requirement from
        # OvnProviderHelper and intra references modules
        ovn_conf.register_opts()
        self._ovn_helper = ovn_helper.OvnProviderHelper()

    def __del__(self):
        self._ovn_helper.shutdown()

    def _is_health_check_supported(self):
        return self._ovn_helper.ovn_nbdb_api.is_col_present(
            'Load_Balancer', 'health_check')

    def _check_for_supported_protocols(self, protocol):
        if protocol not in ovn_const.OVN_NATIVE_LB_PROTOCOLS:
            msg = _('OVN provider does not support %s protocol') % protocol
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def _check_for_supported_algorithms(self, algorithm):
        if algorithm not in ovn_const.OVN_NATIVE_LB_ALGORITHMS:
            msg = _('OVN provider does not support %s algorithm') % algorithm
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def _check_for_allowed_cidrs(self, allowed_cidrs):
        # TODO(haleyb): add support for this
        if isinstance(allowed_cidrs, o_datamodels.UnsetType):
            allowed_cidrs = []
        if allowed_cidrs:
            msg = _('OVN provider does not support allowed_cidrs option')
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def loadbalancer_create(self, loadbalancer):
        admin_state_up = loadbalancer.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': loadbalancer.loadbalancer_id,
                        'vip_address': loadbalancer.vip_address,
                        'vip_network_id': loadbalancer.vip_network_id,
                        'admin_state_up': admin_state_up}

        request = {'type': ovn_const.REQ_TYPE_LB_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

        if not isinstance(loadbalancer.listeners, o_datamodels.UnsetType):
            for listener in loadbalancer.listeners:
                self.listener_create(listener)

        if not isinstance(loadbalancer.pools, o_datamodels.UnsetType):
            for pool in loadbalancer.pools:
                self.pool_create(pool)
                for member in pool.members:
                    if not member.subnet_id:
                        member.subnet_id = loadbalancer.vip_network_id
                    self.member_create(member)

    def loadbalancer_delete(self, loadbalancer, cascade=False):
        request_info = {'id': loadbalancer.loadbalancer_id,
                        'cascade': cascade}
        request = {'type': ovn_const.REQ_TYPE_LB_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def loadbalancer_failover(self, loadbalancer_id):
        msg = _('OVN provider does not support loadbalancer failover')
        raise driver_exceptions.UnsupportedOptionError(
            user_fault_string=msg,
            operator_fault_string=msg)

    def loadbalancer_update(self, old_loadbalancer, new_loadbalancer):
        request_info = {'id': new_loadbalancer.loadbalancer_id}
        if not isinstance(
                new_loadbalancer.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_loadbalancer.admin_state_up
        request = {'type': ovn_const.REQ_TYPE_LB_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    # Pool
    def pool_create(self, pool):
        self._check_for_supported_protocols(pool.protocol)
        self._check_for_supported_algorithms(pool.lb_algorithm)
        admin_state_up = pool.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': pool.pool_id,
                        'loadbalancer_id': pool.loadbalancer_id,
                        'protocol': pool.protocol,
                        'lb_algorithm': pool.lb_algorithm,
                        'listener_id': pool.listener_id,
                        'admin_state_up': admin_state_up}
        request = {'type': ovn_const.REQ_TYPE_POOL_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)
        if pool.healthmonitor is not None and not isinstance(
                pool.healthmonitor, o_datamodels.UnsetType):
            self.health_monitor_create(pool.healthmonitor)

    def pool_delete(self, pool):
        for member in pool.members:
            self.member_delete(member)

        request_info = {'id': pool.pool_id,
                        'protocol': pool.protocol,
                        'loadbalancer_id': pool.loadbalancer_id}
        request = {'type': ovn_const.REQ_TYPE_POOL_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def pool_update(self, old_pool, new_pool):
        if not isinstance(new_pool.protocol, o_datamodels.UnsetType):
            self._check_for_supported_protocols(new_pool.protocol)
        if not isinstance(new_pool.lb_algorithm, o_datamodels.UnsetType):
            self._check_for_supported_algorithms(new_pool.lb_algorithm)
        request_info = {'id': old_pool.pool_id,
                        'protocol': old_pool.protocol,
                        'loadbalancer_id': old_pool.loadbalancer_id}

        if not isinstance(new_pool.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_pool.admin_state_up
        request = {'type': ovn_const.REQ_TYPE_POOL_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def listener_create(self, listener):
        self._check_for_supported_protocols(listener.protocol)
        self._check_for_allowed_cidrs(listener.allowed_cidrs)
        admin_state_up = listener.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': listener.listener_id,
                        'protocol': listener.protocol,
                        'loadbalancer_id': listener.loadbalancer_id,
                        'protocol_port': listener.protocol_port,
                        'default_pool_id': listener.default_pool_id,
                        'admin_state_up': admin_state_up}
        request = {'type': ovn_const.REQ_TYPE_LISTENER_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def listener_delete(self, listener):
        request_info = {'id': listener.listener_id,
                        'loadbalancer_id': listener.loadbalancer_id,
                        'protocol_port': listener.protocol_port,
                        'protocol': listener.protocol}
        request = {'type': ovn_const.REQ_TYPE_LISTENER_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def listener_update(self, old_listener, new_listener):
        self._check_for_allowed_cidrs(new_listener.allowed_cidrs)

        request_info = {'id': new_listener.listener_id,
                        'loadbalancer_id': old_listener.loadbalancer_id,
                        'protocol': old_listener.protocol,
                        'protocol_port': old_listener.protocol_port}

        if not isinstance(new_listener.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_listener.admin_state_up

        if not isinstance(new_listener.default_pool_id,
                          o_datamodels.UnsetType):
            request_info['default_pool_id'] = new_listener.default_pool_id

        request = {'type': ovn_const.REQ_TYPE_LISTENER_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    # Member
    def _check_monitor_options(self, member):
        if (isinstance(member.monitor_address, o_datamodels.UnsetType) and
                isinstance(member.monitor_port, o_datamodels.UnsetType)):
            return False
        if member.monitor_address or member.monitor_port:
            return True
        return False

    def _check_member_monitor_options(self, member):
        if self._check_monitor_options(member):
            msg = _('OVN Load Balancer does not support different member '
                    'monitor address or port.')
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def _ip_version_differs(self, member):
        _, ovn_lb = self._ovn_helper._find_ovn_lb_by_pool_id(member.pool_id)
        if not ovn_lb:
            return False
        lb_vip = ovn_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_KEY]
        return netaddr.IPNetwork(lb_vip).version != (
            netaddr.IPNetwork(member.address).version)

    def member_create(self, member):
        # Validate monitoring options if present
        self._check_member_monitor_options(member)
        if self._ip_version_differs(member):
            raise ovn_exc.IPVersionsMixingNotSupportedError()
        admin_state_up = member.admin_state_up
        subnet_id = member.subnet_id
        if (isinstance(subnet_id, o_datamodels.UnsetType) or not subnet_id):
            subnet_id, subnet_cidr = self._ovn_helper._get_subnet_from_pool(
                member.pool_id)
            if not (subnet_id and
                    self._ovn_helper._check_ip_in_subnet(member.address,
                                                         subnet_cidr)):
                msg = _('Subnet is required, or Loadbalancer associated with '
                        'Pool must have a subnet, for Member creation '
                        'with OVN Provider Driver if it is not the same as '
                        'LB VIP subnet')
                raise driver_exceptions.UnsupportedOptionError(
                    user_fault_string=msg,
                    operator_fault_string=msg)

        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'protocol_port': member.protocol_port,
                        'pool_id': member.pool_id,
                        'subnet_id': subnet_id,
                        'admin_state_up': admin_state_up}
        request = {'type': ovn_const.REQ_TYPE_MEMBER_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

        # NOTE(mjozefcz): If LB has FIP on VIP
        # and member has FIP we need to centralize
        # traffic for member.
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'pool_id': member.pool_id,
                        'subnet_id': subnet_id,
                        'action': ovn_const.REQ_INFO_MEMBER_ADDED}
        request = {'type': ovn_const.REQ_TYPE_HANDLE_MEMBER_DVR,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_delete(self, member):
        # NOTE(froyo): OVN provider allow to create member without param
        # subnet_id, in that case the driver search it according to the
        # pool_id, but it is not propagated to Octavia. In this case, if
        # the member is deleted, Octavia send the object without subnet_id.
        subnet_id = member.subnet_id
        if (isinstance(subnet_id, o_datamodels.UnsetType) or not subnet_id):
            subnet_id, subnet_cidr = self._ovn_helper._get_subnet_from_pool(
                member.pool_id)
            if not (subnet_id and
                    self._ovn_helper._check_ip_in_subnet(member.address,
                                                         subnet_cidr)):
                msg = _('Subnet is required, or Loadbalancer associated with '
                        'Pool must have a subnet, for Member deletion if it is'
                        'with OVN Provider Driver if it is not the same as '
                        'LB VIP subnet')
                raise driver_exceptions.UnsupportedOptionError(
                    user_fault_string=msg,
                    operator_fault_string=msg)

        request_info = {'id': member.member_id,
                        'address': member.address,
                        'protocol_port': member.protocol_port,
                        'pool_id': member.pool_id,
                        'subnet_id': subnet_id}
        request = {'type': ovn_const.REQ_TYPE_MEMBER_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)
        # NOTE(mjozefcz): If LB has FIP on VIP
        # and member had FIP we can decentralize
        # the traffic now.
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'pool_id': member.pool_id,
                        'subnet_id': subnet_id,
                        'action': ovn_const.REQ_INFO_MEMBER_DELETED}
        request = {'type': ovn_const.REQ_TYPE_HANDLE_MEMBER_DVR,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_update(self, old_member, new_member):
        # NOTE(froyo): OVN provider allow to create member without param
        # subnet_id, in that case the driver search it according to the
        # pool_id, but it is not propagated to Octavia. In this case, if
        # the member is updated, Octavia send the object without subnet_id.
        subnet_id = old_member.subnet_id
        if (isinstance(subnet_id, o_datamodels.UnsetType) or not subnet_id):
            subnet_id, subnet_cidr = self._ovn_helper._get_subnet_from_pool(
                old_member.pool_id)
            if not (subnet_id and
                    self._ovn_helper._check_ip_in_subnet(new_member.address,
                                                         subnet_cidr)):
                msg = _('Subnet is required, or Loadbalancer associated with '
                        'Pool must have a subnet, for Member update '
                        'with OVN Provider Driver if it is not the same as '
                        'LB VIP subnet')
                raise driver_exceptions.UnsupportedOptionError(
                    user_fault_string=msg,
                    operator_fault_string=msg)

        # Validate monitoring options if present
        self._check_member_monitor_options(new_member)
        if new_member.address and self._ip_version_differs(new_member):
            raise ovn_exc.IPVersionsMixingNotSupportedError()
        request_info = {'id': new_member.member_id,
                        'address': old_member.address,
                        'protocol_port': old_member.protocol_port,
                        'pool_id': old_member.pool_id,
                        'subnet_id': subnet_id,
                        'old_admin_state_up': old_member.admin_state_up}
        if not isinstance(new_member.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_member.admin_state_up
        request = {'type': ovn_const.REQ_TYPE_MEMBER_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_batch_update(self, pool_id, members):
        request_list = []
        skipped_members = []
        pool_key, ovn_lb = self._ovn_helper._find_ovn_lb_by_pool_id(pool_id)
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        pool = external_ids[pool_key]
        existing_members = pool.split(',') if pool else []
        members_to_delete = copy.copy(existing_members)
        pool_subnet_id = None
        for member in members:
            if (self._check_monitor_options(member) or
                    member.address and self._ip_version_differs(member)):
                skipped_members.append(member.member_id)
                continue
            # NOTE(froyo): if subnet_id not provided, lets try to get it
            # from the member pool_id
            subnet_id = member.subnet_id
            if (isinstance(subnet_id, o_datamodels.UnsetType) or
                    not subnet_id):
                if not pool_subnet_id:
                    pool_subnet_id, pool_subnet_cidr = (
                        self._ovn_helper._get_subnet_from_pool(pool_id))
                if pool_subnet_id:
                    if (self._ovn_helper._check_ip_in_subnet(
                            member.address, pool_subnet_cidr)):
                        member.subnet_id = pool_subnet_id
                # NOTE(mjozefcz): We need to have subnet_id information.
                if not member.subnet_id:
                    msg = _('Subnet is required, or Loadbalancer associated '
                            'with Pool must have a subnet, for Member '
                            'batch update with OVN Provider Driver if it is '
                            'not the same as LB VIP subnet')
                    raise driver_exceptions.UnsupportedOptionError(
                        user_fault_string=msg,
                        operator_fault_string=msg)

            admin_state_up = member.admin_state_up
            if isinstance(admin_state_up, o_datamodels.UnsetType):
                admin_state_up = True

            member_info = self._ovn_helper._get_member_info(member)
            if member_info not in existing_members:
                req_type = ovn_const.REQ_TYPE_MEMBER_CREATE
            else:
                # If member exists in pool, then Update
                req_type = ovn_const.REQ_TYPE_MEMBER_UPDATE
                # Remove all updating members so only deleted ones are left
                members_to_delete.remove(member_info)

            request_info = {'id': member.member_id,
                            'address': member.address,
                            'protocol_port': member.protocol_port,
                            'pool_id': member.pool_id,
                            'subnet_id': member.subnet_id,
                            'admin_state_up': admin_state_up}
            request = {'type': req_type,
                       'info': request_info}
            request_list.append(request)

        for member in members_to_delete:
            member_info = member.split('_')
            member_ip, member_port, subnet_id = (
                self._ovn_helper._extract_member_info(member)[0])
            request_info = {'id': member_info[1],
                            'address': member_ip,
                            'protocol_port': member_port,
                            'pool_id': pool_id}
            if len(member_info) == 4:
                request_info['subnet_id'] = subnet_id
            request = {'type': ovn_const.REQ_TYPE_MEMBER_DELETE,
                       'info': request_info}
            request_list.append(request)

        for request in request_list:
            self._ovn_helper.add_request(request)
        if skipped_members:
            msg = (_('OVN provider does not support monitor options, '
                     'so following members skipped: %s') % skipped_members)
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def create_vip_port(self, lb_id, project_id, vip_dict,
                        additional_vip_dicts=None):
        """Create the VIP port of a load balancer

        :param lb_id: The ID of the load balancer
        :param project_id: The ID of the project that owns the load balancer
        :param vip_dict: A dict that contains the provider VIP information
               ('network_id', 'port_id', 'subnet_id' and/or 'ip_address')
        :param additional_vip_dicts: An optional list of dicts of additional
               VIP. An additional VIP dict might contain the 'ip_address',
               'network_id', 'port_id' and/or 'subnet_id' of the secondary
               VIPs.
        :return: a tuple that contains the VIP provider dictionary and a list
                 of additional VIP dictionaries
        """
        # TODO(gthiemonge): implement additional_vip_dicts
        try:
            port = self._ovn_helper.create_vip_port(
                project_id, lb_id, vip_dict)['port']
            vip_dict[constants.VIP_PORT_ID] = port['id']
            vip_dict[constants.VIP_ADDRESS] = (
                port['fixed_ips'][0]['ip_address'])
        except Exception as e:
            kwargs = {}
            if hasattr(e, 'message'):
                kwargs = {'user_fault_string': e.message,
                          'operator_fault_string': e.message}
            raise driver_exceptions.DriverError(
                **kwargs)
        return vip_dict, []

    def _validate_hm_support(self, hm, action='create'):
        if not self._is_health_check_supported():
            msg = _('OVN Load Balancer supports Health Check provider '
                    'from version 2.12. Upgrade OVN in order to use it.')
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)
        # type is only required for create
        if action == 'create':
            if isinstance(hm.type, o_datamodels.UnsetType):
                msg = _('OVN provider health monitor type not specified.')
                # seems this should be other than "unsupported"?
                raise driver_exceptions.UnsupportedOptionError(
                    user_fault_string=msg,
                    operator_fault_string=msg)
            if hm.type not in ovn_const.SUPPORTED_HEALTH_MONITOR_TYPES:
                msg = (_('OVN provider does not support %s '
                         'health monitor type. Supported types: %s') %
                        (hm.type,
                         ', '.join(ovn_const.SUPPORTED_HEALTH_MONITOR_TYPES)))
                raise driver_exceptions.UnsupportedOptionError(
                    user_fault_string=msg,
                    operator_fault_string=msg)

    def health_monitor_create(self, healthmonitor):
        self._validate_hm_support(healthmonitor)
        admin_state_up = healthmonitor.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': healthmonitor.healthmonitor_id,
                        'pool_id': healthmonitor.pool_id,
                        'type': healthmonitor.type,
                        'interval': healthmonitor.delay,
                        'timeout': healthmonitor.timeout,
                        'failure_count': healthmonitor.max_retries_down,
                        'success_count': healthmonitor.max_retries,
                        'admin_state_up': admin_state_up}
        request = {'type': ovn_const.REQ_TYPE_HM_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def health_monitor_update(self, old_healthmonitor, new_healthmonitor):
        self._validate_hm_support(new_healthmonitor, action='update')
        admin_state_up = new_healthmonitor.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': new_healthmonitor.healthmonitor_id,
                        'pool_id': old_healthmonitor.pool_id,
                        'interval': new_healthmonitor.delay,
                        'timeout': new_healthmonitor.timeout,
                        'failure_count': new_healthmonitor.max_retries_down,
                        'success_count': new_healthmonitor.max_retries,
                        'admin_state_up': admin_state_up}
        request = {'type': ovn_const.REQ_TYPE_HM_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def health_monitor_delete(self, healthmonitor):
        request_info = {'id': healthmonitor.healthmonitor_id,
                        'pool_id': healthmonitor.pool_id}
        request = {'type': ovn_const.REQ_TYPE_HM_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)
