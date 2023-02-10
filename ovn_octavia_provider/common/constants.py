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

from octavia_lib.common import constants


# TODO(mjozefcz): Use those variables from neutron-lib once released.
LRP_PREFIX = "lrp-"
OVN_NAME_PREFIX = "neutron-"
LB_HM_PORT_PREFIX = "ovn-lb-hm-"
LB_VIP_PORT_PREFIX = "ovn-lb-vip-"
OVN_PORT_NAME_EXT_ID_KEY = 'neutron:port_name'
OVN_ROUTER_NAME_EXT_ID_KEY = 'neutron:router_name'
OVN_PORT_FIP_EXT_ID_KEY = 'neutron:port_fip'
OVN_SUBNET_EXT_ID_KEY = 'neutron:subnet_id'
OVN_SUBNET_EXT_IDS_KEY = 'neutron:subnet_ids'
OVN_NETWORK_NAME_EXT_ID_KEY = 'neutron:network_name'
OVN_PROJECT_EXT_ID_KEY = 'neutron:project_id'
OVN_SG_IDS_EXT_ID_KEY = 'neutron:security_group_ids'
OVN_DEVICE_OWNER_EXT_ID_KEY = 'neutron:device_owner'
OVN_FIP_EXT_ID_KEY = 'neutron:fip_id'
OVN_FIP_PORT_EXT_ID_KEY = 'neutron:fip_port_id'
OVN_GW_PORT_EXT_ID_KEY = 'neutron:gw_port_id'
OVN_PORT_CIDR_EXT_ID_KEY = 'neutron:cidrs'
OVN_MEMBER_STATUS_KEY = 'neutron:member_status'

LB_EXT_IDS_LS_REFS_KEY = 'ls_refs'
LB_EXT_IDS_LR_REF_KEY = 'lr_ref'
LB_EXT_IDS_POOL_PREFIX = 'pool_'
LB_EXT_IDS_LISTENER_PREFIX = 'listener_'
LB_EXT_IDS_MEMBER_PREFIX = 'member_'
LB_EXT_IDS_HM_KEY = 'octavia:healthmonitor'
LB_EXT_IDS_HMS_KEY = 'octavia:healthmonitors'
LB_EXT_IDS_VIP_KEY = 'neutron:vip'
LB_EXT_IDS_VIP_FIP_KEY = 'neutron:vip_fip'
LB_EXT_IDS_VIP_PORT_ID_KEY = 'neutron:vip_port_id'

PORT_FORWARDING_PLUGIN = 'port_forwarding_plugin'

# Auth sections
SERVICE_AUTH = 'service_auth'

# Request type constants
REQ_TYPE_LB_CREATE = 'lb_create'
REQ_TYPE_LB_DELETE = 'lb_delete'
REQ_TYPE_LB_UPDATE = 'lb_update'
REQ_TYPE_LISTENER_CREATE = 'listener_create'
REQ_TYPE_LISTENER_DELETE = 'listener_delete'
REQ_TYPE_LISTENER_UPDATE = 'listener_update'
REQ_TYPE_POOL_CREATE = 'pool_create'
REQ_TYPE_POOL_DELETE = 'pool_delete'
REQ_TYPE_POOL_UPDATE = 'pool_update'
REQ_TYPE_MEMBER_CREATE = 'member_create'
REQ_TYPE_MEMBER_DELETE = 'member_delete'
REQ_TYPE_MEMBER_UPDATE = 'member_update'
REQ_TYPE_LB_CREATE_LRP_ASSOC = 'lb_create_lrp_assoc'
REQ_TYPE_LB_DELETE_LRP_ASSOC = 'lb_delete_lrp_assoc'
REQ_TYPE_HANDLE_VIP_FIP = 'handle_vip_fip'
REQ_TYPE_HANDLE_MEMBER_DVR = 'handle_member_dvr'
REQ_TYPE_HM_CREATE = 'hm_create'
REQ_TYPE_HM_UPDATE = 'hm_update'
REQ_TYPE_HM_DELETE = 'hm_delete'
REQ_TYPE_HM_UPDATE_EVENT = 'hm_update_event'

REQ_TYPE_EXIT = 'exit'

# Request information constants
REQ_INFO_ACTION_ASSOCIATE = 'associate'
REQ_INFO_ACTION_DISASSOCIATE = 'disassociate'
REQ_INFO_MEMBER_ADDED = 'member_added'
REQ_INFO_MEMBER_DELETED = 'member_deleted'

# Disabled resources have a ':D' at the end
DISABLED_RESOURCE_SUFFIX = 'D'

# This driver only supports TCP, UDP and SCTP, with a single LB algorithm
OVN_NATIVE_LB_PROTOCOLS = [constants.PROTOCOL_TCP,
                           constants.PROTOCOL_UDP,
                           constants.PROTOCOL_SCTP, ]
OVN_NATIVE_LB_ALGORITHMS = [constants.LB_ALGORITHM_SOURCE_IP_PORT, ]

# This driver only supports UDP Connect and TCP health monitors
SUPPORTED_HEALTH_MONITOR_TYPES = [constants.HEALTH_MONITOR_UDP_CONNECT,
                                  constants.HEALTH_MONITOR_TCP]

# Prepended to exception log messages
EXCEPTION_MSG = "Exception occurred during %s"

# Used in functional tests
LR_REF_KEY_HEADER = 'neutron-'

# LB selection fields to represent LB algorithm
LB_SELECTION_FIELDS_MAP = {
    constants.LB_ALGORITHM_SOURCE_IP_PORT: ["ip_dst", "ip_src",
                                            "tp_dst", "tp_src"],
    constants.LB_ALGORITHM_SOURCE_IP: ["ip_src", "ip_dst"],
    None: ["ip_src", "ip_dst", "tp_src", "tp_dst"],
}

# HM events status
HM_EVENT_MEMBER_PORT_ONLINE = ['online']
HM_EVENT_MEMBER_PORT_OFFLINE = ['offline']
