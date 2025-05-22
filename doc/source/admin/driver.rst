.. _driver:

====================================
OVN as a Provider Driver for Octavia
====================================

Octavia has integrated support for provider drivers where any third party
Load Balancer driver can be integrated with Octavia. Functionality related
to this has been developed in OVN and now OVN can now be supported as a
provider driver for Octavia.

The OVN Provider driver has a few advantages when used as a provider driver
for Octavia over Amphora, like:

* OVN can be deployed without VMs, so there is no additional overhead as
  is required currently in Octavia when using the default Amphora driver.

* OVN Load Balancers can be deployed faster than default Load Balancers in
  Octavia (which use Amphora currently) because of no additional deployment
  requirement.

* Since OVN supports virtual networking for both VMs and containers, OVN as a
  Load Balancer driver can be used succesfully with Kuryr Kubernetes[1].

Limitations of the OVN Provider Driver
--------------------------------------

OVN has its own set of limitations when considered as an Load Balancer driver.
These include:

* OVN currently supports TCP, UDP and SCTP, so Layer-7 based load balancing
  is not possible with OVN.

* Currently, the OVN Provider Driver supports a 1:1 protocol mapping between
  Listeners and associated Pools, i.e. a Listener which can handle TCP
  protocols can only be used with pools associated to the TCP protocol.
  Pools handling UDP protocols cannot be linked with TCP based Listeners.
  This limitation will be handled in an upcoming core OVN release.

* IPv6 support is not tested by Tempest.

* Mixed IPv4 and IPv6 members are not supported.

* Only the SOURCE_IP_PORT load balancing algorithm is supported, others
  like ROUND_ROBIN and LEAST_CONNECTIONS are not currently supported.

* OVN supports health checks for TCP and UDP-CONNECT protocols, but not for
  SCTP. Therefore, when configuring a health monitor, you cannot use SCTP as
  the type.

* Due to nature of OVN octavia driver (flows distributed in all the nodes)
  there is no need for some of the amphora specific functionality that is
  specific to the fact that a VM is created for the load balancing actions. As
  an example, there is no need for flavors (no VM is created), failovers (no
  need to recover a VM), or HA (no need to create extra VMs as in the
  ovn-octavia case the flows are injected in all the nodes, i.e., it is HA by
  default).

Creating an OVN based Load Balancer
-----------------------------------

The OVN provider driver can be tested out on DevStack using the configuration
options in:

.. literalinclude:: ../../../devstack/local.conf.sample

Kindly note that the configuration allows the user to create
Load Balancers of both Amphora and OVN types.

Once the DevStack run is complete, the user can create a load balancer
in Openstack::

    $ openstack loadbalancer create --vip-network-id public --provider ovn
    +---------------------+--------------------------------------+
    | Field               | Value                                |
    +---------------------+--------------------------------------+
    | admin_state_up      | True                                 |
    | created_at          | 2018-12-13T09:08:14                  |
    | description         |                                      |
    | flavor              |                                      |
    | id                  | 94e7c431-912b-496c-a247-d52875d44ac7 |
    | listeners           |                                      |
    | name                |                                      |
    | operating_status    | OFFLINE                              |
    | pools               |                                      |
    | project_id          | af820b57868c4864957d523fb32ccfba     |
    | provider            | ovn                                  |
    | provisioning_status | PENDING_CREATE                       |
    | updated_at          | None                                 |
    | vip_address         | 172.24.4.9                           |
    | vip_network_id      | ee97665d-69d0-4995-a275-27855359956a |
    | vip_port_id         | c98e52d0-5965-4b22-8a17-a374f4399193 |
    | vip_qos_policy_id   | None                                 |
    | vip_subnet_id       | 3eed0c05-6527-400e-bb80-df6e59d248f1 |
    +---------------------+--------------------------------------+

The user can see the different types of loadbalancers with their associated
providers as below::

    +--------------------------------------+------+----------------------------------+-------------+---------------------+----------+
    | id                                   | name | project_id                       | vip_address | provisioning_status | provider |
    +--------------------------------------+------+----------------------------------+-------------+---------------------+----------+
    | c5f2070c-d51d-46f0-bec6-dd05e7c19370 |      | af820b57868c4864957d523fb32ccfba | 172.24.4.10 | ACTIVE              | amphora  |
    | 94e7c431-912b-496c-a247-d52875d44ac7 |      | af820b57868c4864957d523fb32ccfba | 172.24.4.9  | ACTIVE              | ovn      |
    +--------------------------------------+------+----------------------------------+-------------+---------------------+----------+

Now we can see that OVN will show the load balancer in its *loadbalancer*
table::

    $ ovn-nbctl list load_balancer
    _uuid               : c72de15e-5c2e-4c1b-a21b-8e9a6721193c
    external_ids        : {enabled=True,
                           lr_ref="neutron-3d2a873b-b5b4-4d14-ac24-47a835fd47b2",
                           ls_refs="{\"neutron-ee97665d-69d0-4995-a275-27855359956a\": 1}",
                           "neutron:vip"="172.24.4.9",
                           "neutron:vip_port_id"="c98e52d0-5965-4b22-8a17-a374f4399193"}
    name                : "94e7c431-912b-496c-a247-d52875d44ac7"
    protocol            : tcp
    vips                : {}

Next, a Listener can be created for the associated Load Balancer::

    $ openstack loadbalancer listener create --protocol TCP --protocol-port /
      64015 94e7c431-912b-496c-a247-d52875d44ac7
    +---------------------------+--------------------------------------+
    | Field                     | Value                                |
    +---------------------------+--------------------------------------+
    | admin_state_up            | True                                 |
    | connection_limit          | -1                                   |
    | created_at                | 2018-12-13T09:14:51                  |
    | default_pool_id           | None                                 |
    | default_tls_container_ref | None                                 |
    | description               |                                      |
    | id                        | 21e77cde-854f-4c3e-bd8c-9536ae0443bc |
    | insert_headers            | None                                 |
    | l7policies                |                                      |
    | loadbalancers             | 94e7c431-912b-496c-a247-d52875d44ac7 |
    | name                      |                                      |
    | operating_status          | OFFLINE                              |
    | project_id                | af820b57868c4864957d523fb32ccfba     |
    | protocol                  | TCP                                  |
    | protocol_port             | 64015                                |
    | provisioning_status       | PENDING_CREATE                       |
    | sni_container_refs        | []                                   |
    | timeout_client_data       | 50000                                |
    | timeout_member_connect    | 5000                                 |
    | timeout_member_data       | 50000                                |
    | timeout_tcp_inspect       | 0                                    |
    | updated_at                | None                                 |
    +---------------------------+--------------------------------------+

OVN updates the Listener information in the Load Balancer table::

    $ ovn-nbctl list load_balancer
    _uuid               : c72de15e-5c2e-4c1b-a21b-8e9a6721193c
    external_ids        : {enabled=True, "listener_21e77cde-854f-4c3e-bd8c-9536ae0443bc"="64015:", lr_ref="neutron-3d2a873b-b5b4-4d14-ac24-47a835fd47b2", ls_refs="{\"neutron-ee97665d-69d0-4995-a275-27855359956a\": 1}", "neutron:vip"="172.24.4.9", "neutron:vip_port_id"="c98e52d0-5965-4b22-8a17-a374f4399193"}
    name                : "94e7c431-912b-496c-a247-d52875d44ac7"
    protocol            : tcp
    vips                : {}

Next, a Pool is associated with the Listener::

    $ openstack loadbalancer pool create --protocol TCP --lb-algorithm /
    SOURCE_IP_PORT --listener 21e77cde-854f-4c3e-bd8c-9536ae0443bc
    +---------------------+--------------------------------------+
    | Field               | Value                                |
    +---------------------+--------------------------------------+
    | admin_state_up      | True                                 |
    | created_at          | 2018-12-13T09:21:37                  |
    | description         |                                      |
    | healthmonitor_id    |                                      |
    | id                  | 898be8a2-5185-4f3b-8658-a56457f595a9 |
    | lb_algorithm        | SOURCE_IP_PORT                       |
    | listeners           | 21e77cde-854f-4c3e-bd8c-9536ae0443bc |
    | loadbalancers       | 94e7c431-912b-496c-a247-d52875d44ac7 |
    | members             |                                      |
    | name                |                                      |
    | operating_status    | OFFLINE                              |
    | project_id          | af820b57868c4864957d523fb32ccfba     |
    | protocol            | TCP                                  |
    | provisioning_status | PENDING_CREATE                       |
    | session_persistence | None                                 |
    | updated_at          | None                                 |
    +---------------------+--------------------------------------+

OVN's Load Balancer table is modified as below::

    $ ovn-nbctl list load_balancer
    _uuid               : c72de15e-5c2e-4c1b-a21b-8e9a6721193c
    external_ids        : {enabled=True, "listener_21e77cde-854f-4c3e-bd8c-9536ae0443bc"="64015:", lr_ref="neutron-3d2a873b-b5b4-4d14-ac24-47a835fd47b2", ls_refs="{\"neutron-ee97665d-69d0-4995-a275-27855359956a\": 1}", "neutron:vip"="172.24.4.9", "neutron:vip_port_id"="c98e52d0-5965-4b22-8a17-a374f4399193", "pool_898be8a2-5185-4f3b-8658-a56457f595a9"=""}
    name                : "94e7c431-912b-496c-a247-d52875d44ac7"
    protocol            : tcp
    vips                : {}

Lastly, when a member is created, OVN's Load Balancer table is complete::

    $ openstack loadbalancer member create --address 10.10.10.10 /
    --protocol-port 63015 898be8a2-5185-4f3b-8658-a56457f595a9
    +---------------------+--------------------------------------+
    | Field               | Value                                |
    +---------------------+--------------------------------------+
    | address             | 10.10.10.10                          |
    | admin_state_up      | True                                 |
    | created_at          | 2018-12-13T09:26:05                  |
    | id                  | adf55e70-3d50-4e62-99fd-dd77eababb1c |
    | name                |                                      |
    | operating_status    | NO_MONITOR                           |
    | project_id          | af820b57868c4864957d523fb32ccfba     |
    | protocol_port       | 63015                                |
    | provisioning_status | PENDING_CREATE                       |
    | subnet_id           | None                                 |
    | updated_at          | None                                 |
    | weight              | 1                                    |
    | monitor_port        | None                                 |
    | monitor_address     | None                                 |
    | backup              | False                                |
    +---------------------+--------------------------------------+
    $ ovn-nbctl list load_balancer
    _uuid               : c72de15e-5c2e-4c1b-a21b-8e9a6721193c
    external_ids        : {enabled=True, "listener_21e77cde-854f-4c3e-bd8c-9536ae0443bc"="64015:pool_898be8a2-5185-4f3b-8658-a56457f595a9", lr_ref="neutron-3d2a873b-b5b4-4d14-ac24-47a835fd47b2", ls_refs="{\"neutron-ee97665d-69d0-4995-a275-27855359956a\": 1}", "neutron:vip"="172.24.4.9", "neutron:vip_port_id"="c98e52d0-5965-4b22-8a17-a374f4399193", "pool_898be8a2-5185-4f3b-8658-a56457f595a9"="member_adf55e70-3d50-4e62-99fd-dd77eababb1c_10.10.10.10:63015"}
    name                : "94e7c431-912b-496c-a247-d52875d44ac7"
    protocol            : tcp
    vips                : {"172.24.4.9:64015"="10.10.10.10:63015"}

Octavia DB to OVN database population
--------------------------------------

In case of OVN DB clustering failure and Load Balancer data loss as a result, you can always re-populate data in OVN NB/SB from the information store in Octavia database.
With that objective the tool octavia-ovn-db-sync-util was created. It is a command-line tool that allows synchronizing the state of Octavia resources (such as Load Balancers, Listeners, Pools, etc.) with the OVN Northbound (NB)/Southbound (SB) database. This is especially useful in situations where:

* Inconsistencies have occurred between Octavia and OVN.

* The OVN database has been restored or recreated.

* A migration or repair of load balancing resources is required.

For that, you can execute the following::

    (venv) stack@ubuntu2404:~/ovn-octavia-provider$ octavia-ovn-db-sync-util
    INFO ovn_octavia_provider.cmd.octavia_ovn_db_sync_util [-] OVN Octavia DB sync start.
    INFO ovn_octavia_provider.driver [-] Starting sync OVN DB with Loadbalancer filter {'provider': 'ovn'}
    INFO ovn_octavia_provider.driver [-] Starting sync OVN DB with Loadbalancer lb1
    DEBUG ovn_octavia_provider.driver [-] OVN loadbalancer 5bcaab92-3f8e-4460-b34d-4437a86909ef not found. Start create process. {{(pid=837681) _ensure_loadbalancer /opt/stack/ovn-octavia-provider/ovn_octavia_provider/driver.py:684}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): DbCreateCommand(_result=None, table=Load_Balancer, columns={'name': '5bcaab92-3f8e-4460-b34d-4437a86909ef', 'protocol': [], 'external_ids': {'neutron:vip': '192.168.100.188', 'neutron:vip_port_id': 'e60041e8-01e8-459b-956e-a55608eb5255', 'enabled': 'True'}, 'selection_fields': ['ip_src', 'ip_dst', 'tp_src', 'tp_dst']}, row=False) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): LsLbAddCommand(_result=None, switch=000a1a3e-edff-45ad-9241-5ab8894ac0e0, lb=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, may_exist=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=1): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('external_ids', {'ls_refs': '{"neutron-000a1a3e-edff-45ad-9241-5ab8894ac0e0": 1}'}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): LrLbAddCommand(_result=None, router=f17e58b5-37d2-4daf-a02f-82fb4974f7b8, lb=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, may_exist=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=1): LsLbAddCommand(_result=None, switch=neutron-000a1a3e-edff-45ad-9241-5ab8894ac0e0, lb=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, may_exist=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=2): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('external_ids', {'lr_ref': 'neutron-d2dd599c-76c7-43c1-8383-1bae5593681a'}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('protocol', 'tcp'),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('external_ids', {'listener_30ac9d4e-4fdd-4885-8949-6a2e7355beb2': '80:pool_5814b9e6-db7e-425d-a4cf-1cb668ba7080'}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=1): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('protocol', 'tcp'),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=2): DbClearCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, column=vips) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=3): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('vips', {}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('external_ids', {'enabled': 'True', 'neutron:vip': '192.168.100.188', 'neutron:vip_port_id': 'e60041e8-01e8-459b-956e-a55608eb5255', 'ls_refs': '{"neutron-000a1a3e-edff-45ad-9241-5ab8894ac0e0": 1}', 'lr_ref': 'neutron-d2dd599c-76c7-43c1-8383-1bae5593681a', 'listener_30ac9d4e-4fdd-4885-8949-6a2e7355beb2': '80:pool_5814b9e6-db7e-425d-a4cf-1cb668ba7080', 'pool_5814b9e6-db7e-425d-a4cf-1cb668ba7080': ''}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovn_octavia_provider.helper [-] no member status on external_ids: None {{(pid=837681) _find_member_status /opt/stack/ovn-octavia-provider/ovn_octavia_provider/helper.py:2490}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('external_ids', {'pool_5814b9e6-db7e-425d-a4cf-1cb668ba7080': 'member_94ceacd8-1a81-4de9-ac0e-18b8e41cf80f_192.168.100.194:80_b97280a1-b19f-4989-a56c-2eb341c23171'}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=1): DbClearCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, column=vips) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=2): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('vips', {'192.168.100.188:80': '192.168.100.194:80'}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('external_ids', {'ls_refs': '{"neutron-000a1a3e-edff-45ad-9241-5ab8894ac0e0": 2}'}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): LrLbAddCommand(_result=None, router=f17e58b5-37d2-4daf-a02f-82fb4974f7b8, lb=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, may_exist=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=1): LsLbAddCommand(_result=None, switch=neutron-000a1a3e-edff-45ad-9241-5ab8894ac0e0, lb=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, may_exist=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Transaction caused no change {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:129}}
    DEBUG ovn_octavia_provider.helper [-] no member status on external_ids: None {{(pid=837681) _update_external_ids_member_status /opt/stack/ovn-octavia-provider/ovn_octavia_provider/helper.py:2521}}
    DEBUG ovsdbapp.backend.ovs_idl.transaction [-] Running txn n=1 command(idx=0): DbSetCommand(_result=None, table=Load_Balancer, record=d69e29cd-0069-4d7f-a1ed-08c246bfb3da, col_values=(('external_ids', {'neutron:member_status': '{"94ceacd8-1a81-4de9-ac0e-18b8e41cf80f": "NO_MONITOR"}'}),), if_exists=True) {{(pid=837681) do_commit /opt/stack/ovn-octavia-provider/venv/lib/python3.12/site-packages/ovsdbapp/backend/ovs_idl/transaction.py:89}}
    DEBUG ovn_octavia_provider.helper [-] Updating status to octavia: {'loadbalancers': [{'id': '5bcaab92-3f8e-4460-b34d-4437a86909ef', 'provisioning_status': 'ACTIVE', 'operating_status': 'ONLINE'}], 'listeners': [{'id': '30ac9d4e-4fdd-4885-8949-6a2e7355beb2', 'provisioning_status': 'ACTIVE', 'operating_status': 'ONLINE'}], 'pools': [{'id': '5814b9e6-db7e-425d-a4cf-1cb668ba7080', 'provisioning_status': 'ACTIVE', 'operating_status': 'ONLINE'}], 'members': [{'id': '94ceacd8-1a81-4de9-ac0e-18b8e41cf80f', 'provisioning_status': 'ACTIVE', 'operating_status': 'NO_MONITOR'}]} {{(pid=837681) _update_status_to_octavia /opt/stack/ovn-octavia-provider/ovn_octavia_provider/helper.py:428}}
    INFO ovn_octavia_provider.driver [-] Starting sync floating IP for loadbalancer 5bcaab92-3f8e-4460-b34d-4437a86909ef
    WARNING ovn_octavia_provider.driver [-] Floating IP not found for loadbalancer 5bcaab92-3f8e-4460-b34d-4437a86909ef
    INFO ovn_octavia_provider.cmd.octavia_ovn_db_sync_util [-] OVN Octavia DB sync finish.


[1]: https://docs.openstack.org/kuryr-kubernetes/latest/installation/services.html

