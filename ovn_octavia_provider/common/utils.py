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

from oslo_utils import netutils
import tenacity

from ovn_octavia_provider.common import config
from ovn_octavia_provider.common import constants


def ovn_uuid(name):
    # Get the UUID of a neutron OVN entry (neutron-<UUID>)
    return name.replace(constants.OVN_NAME_PREFIX, '')


def ovn_name(id):
    # The name of the OVN entry will be neutron-<UUID>
    # This is due to the fact that the OVN application checks if the name
    # is a UUID. If so then there will be no matches.
    # We prefix the UUID to enable us to use the Neutron UUID when
    # updating, deleting etc.
    # To be sure that just one prefix is used, we will check it before
    # return concatenation.
    if not id.startswith(constants.OVN_NAME_PREFIX):
        return constants.OVN_NAME_PREFIX + '%s' % id
    return id


def ovn_lrouter_port_name(id):
    # The name of the OVN lrouter port entry will be lrp-<UUID>
    # This is to distinguish with the name of the connected lswitch patch port,
    # which is named with neutron port uuid, so that OVS patch ports are
    # generated properly. The pairing patch port names will be:
    #   - patch-lrp-<UUID>-to-<UUID>
    #   - patch-<UUID>-to-lrp-<UUID>
    # lrp stands for Logical Router Port
    return constants.LRP_PREFIX + '%s' % id


def remove_macs_from_lsp_addresses(addresses):
    """Remove the mac addreses from the Logical_Switch_Port addresses column.

    :param addresses: The list of addresses from the Logical_Switch_Port.
        Example: ["80:fa:5b:06:72:b7 158.36.44.22",
                  "ff:ff:ff:ff:ff:ff 10.0.0.2"]
    :returns: A list of IP addesses (v4 and v6)
    """
    ip_list = []
    for addr in addresses:
        ip_list.extend([x for x in addr.split() if
                       (netutils.is_valid_ipv4(x) or
                        netutils.is_valid_ipv6(x))])
    return ip_list


def retry(max_=None):
    def inner(func):
        def wrapper(*args, **kwargs):
            local_max = max_ or config.get_ovn_ovsdb_retry_max_interval()
            return tenacity.retry(
                wait=tenacity.wait_exponential(max=local_max),
                reraise=True)(func)(*args, **kwargs)
        return wrapper
    return inner
