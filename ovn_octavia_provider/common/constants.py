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
LB_VIP_PORT_PREFIX = "ovn-lb-vip-"
OVN_PORT_NAME_EXT_ID_KEY = 'neutron:port_name'
OVN_ROUTER_NAME_EXT_ID_KEY = 'neutron:router_name'
OVN_PORT_NAME_EXT_ID_KEY = 'neutron:port_name'
OVN_PORT_FIP_EXT_ID_KEY = 'neutron:port_fip'
OVN_SUBNET_EXT_ID_KEY = 'neutron:subnet_id'
OVN_SUBNET_EXT_IDS_KEY = 'neutron:subnet_ids'
OVN_NETWORK_NAME_EXT_ID_KEY = 'neutron:network_name'
OVN_SG_IDS_EXT_ID_KEY = 'neutron:security_group_ids'
OVN_DEVICE_OWNER_EXT_ID_KEY = 'neutron:device_owner'
OVN_FIP_EXT_ID_KEY = 'neutron:fip_id'
OVN_FIP_PORT_EXT_ID_KEY = 'neutron:fip_port_id'

LB_EXT_IDS_LS_REFS_KEY = 'ls_refs'
LB_EXT_IDS_LR_REF_KEY = 'lr_ref'
LB_EXT_IDS_POOL_PREFIX = 'pool_'
LB_EXT_IDS_LISTENER_PREFIX = 'listener_'
LB_EXT_IDS_MEMBER_PREFIX = 'member_'
LB_EXT_IDS_VIP_KEY = 'neutron:vip'
LB_EXT_IDS_VIP_FIP_KEY = 'neutron:vip_fip'
LB_EXT_IDS_VIP_PORT_ID_KEY = 'neutron:vip_port_id'

# Auth sections
SERVICE_AUTH = 'service_auth'

# LB selection fields to represent LB algorithm
LB_SELECTION_FIELDS_MAP = {
    constants.LB_ALGORITHM_SOURCE_IP_PORT: ["ip_dst", "ip_src",
                                            "tp_dst", "tp_src"],
    constants.LB_ALGORITHM_SOURCE_IP: ["ip_src", "ip_dst"],
    None: ["ip_src", "ip_dst", "tp_src", "tp_dst"],
}
