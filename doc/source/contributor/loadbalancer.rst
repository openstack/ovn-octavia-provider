.. _loadbalancer:

==================================
OpenStack LoadBalancer API and OVN
==================================

Introduction
------------

Load balancing is essential for enabling simple or automatic delivery
scaling and availability since application delivery, scaling and
availability are considered vital features of any cloud.
Octavia is an open source, operator-scale load balancing solution designed
to work with OpenStack.

The purpose of this document is to propose a design for how we can use OVN
as the backend for OpenStack's LoadBalancer API provided by Octavia.

Octavia LoadBalancers Today
---------------------------

A Detailed design analysis of Octavia is available here:

https://docs.openstack.org/octavia/latest/contributor/design/version0.5/component-design.html

Currently, Octavia uses the built-in Amphorae driver to fulfill the
Loadbalancing requests in Openstack. Amphorae can be a Virtual machine,
container, dedicated hardware, appliance or device that actually performs the
task of load balancing in the Octavia system. More specifically, an amphora
takes requests from clients on the front-end and distributes these to back-end
systems. Amphorae communicates with its controllers over the LoadBalancer's
network through a driver interface on the controller.

Amphorae needs a placeholder, such as a separate VM/Container for deployment,
so that it can handle the LoadBalancer's requests. Along with this,
it also needs a separate network (termed as lb-mgmt-network) which handles all
Amphorae requests.

Amphorae has the capability to handle L4 (TCP/UDP) as well as L7 (HTTP)
LoadBalancer requests and provides monitoring features using HealthMonitors.

Octavia with OVN
----------------

The OVN native LoadBalancer currently supports L4 protocols, with support for
L7 protocols aimed for future releases. It does not need any extra
hardware/VM/Container for deployment, which is a major positive point when
compared with Amphorae. Also, it does not need any special network to
handle the LoadBalancer's requests as they are taken care by OpenFlow rules
directly. And, though OVN does not have support for TLS, it is in development
and once implemented can be integrated with Octavia.

This following section details how OVN can be used as an Octavia driver.

Overview of Proposed Approach
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The OVN Driver for Octavia runs under the scope of Octavia. The Octavia API
receives and forwards calls to the OVN Driver.

**Step 1** - Creating a LoadBalancer

The Octavia API receives and issues a LoadBalancer creation request on
a network to the OVN Provider driver. The OVN driver creates a LoadBalancer
in the OVN NorthBound DB and asynchronously updates the Octavia DB
with the status response. A VIP port is created in Neutron when the
LoadBalancer creation is complete. The VIP information however is not updated
in the NorthBound DB until the Members are associated with the
LoadBalancer's Pool.

**Step 2** - Creating LoadBalancer entities (Pools, Listeners, Members)

Once a LoadBalancer is created by OVN in its NorthBound DB, users can now
create Pools, Listeners and Members associated with the LoadBalancer using
the Octavia API. With the creation of each entity, the LoadBalancer's
*external_ids* column in the NorthBound DB will be updated and corresponding
Logical and Openflow rules will be added for handling them.

**Step 3** - LoadBalancer request processing

When a user sends a request to the VIP IP address, the OVN pipeline takes
care of load balancing the VIP request to one of the backend members.
More information about this can be found in the ovn-northd man pages.

OVN LoadBalancer Driver Logic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* On startup: Open and maintain a connection to the OVN Northbound DB
  (using the ovsdbapp library). On first connection, and anytime a reconnect
  happens:

  * Do a full sync.

* Register a callback when a new interface is added or deleted from a router
  or switch. The LogicalSwitchPortUpdateEvent and LogicalRouterPortEvent
  are registered to process these events.

* When a new LoadBalancer L1 is created, create a Row in OVN's
  ``Load_Balancer`` table and update its entries for name and network
  references. If the network on which the LoadBalancer is created is
  associated with a router, say R1, then add the router reference to the
  LoadBalancer's *external_ids* and associate the LoadBalancer to the router.
  Also associate the LoadBalancer L1 with all those networks which have an
  interface on the router R1. This is required so that Logical Flows for
  inter-network communication while using the LoadBalancer L1 is possible.
  Also, during this time, a new port is created via Neutron which acts as a
  VIP Port. The information of this new port is not visible in OVN's
  NorthBound DB until a member is added to the LoadBalancer.

* If a new network interface is added to the router R1 described above, all
  the LoadBalancers on that network are associated with the router R1 and all
  the LoadBalancers on the router are associated with the new network.

* If a network interface is removed from the router R1, then all the
  LoadBalancers which have been solely created on that network (identified
  using the *ls_ref* attribute in the LoadBalancer's *external_ids*) are
  removed from the router. Similarly, those LoadBalancers which are associated
  with the network but not actually created on that network are removed from
  the network.

* A LoadBalancer can either be deleted with all its children entities using
  the *cascade* option, or its members/pools/listeners can be individually
  deleted. When the LoadBalancer is deleted, its references and
  associations from all networks and routers are removed. This might change
  in the future once the association of LoadBalancers with networks/routers
  are changed to *weak* from *strong* [3]. Also the VIP port is deleted
  when the LoadBalancer is deleted.

OVN LoadBalancer at work
~~~~~~~~~~~~~~~~~~~~~~~~

OVN Northbound schema [5] has a table to store LoadBalancers.
The table looks like::

    "Load_Balancer": {
        "columns": {
            "name": {"type": "string"},
            "vips": {
                "type": {"key": "string", "value": "string",
                         "min": 0, "max": "unlimited"}},
            "protocol": {
                "type": {"key": {"type": "string",
                                 "enum": ["set", ["tcp", "udp"]]},
                                 "min": 0, "max": 1}},
            "external_ids": {
                "type": {"key": "string", "value": "string",
                         "min": 0, "max": "unlimited"}}},
            "isRoot": true},

There is a ``load_balancer`` column in the Logical_Switch table (which
corresponds to a Neutron network) as well as the Logical_Router table
(which corresponds to a Neutron router) referring back to the 'Load_Balancer'
table.

The OVN driver updates the OVN Northbound DB. When a LoadBalancer is created,
a row in this table is created. When the listeners and members are added,
the 'vips' column and the Logical_Switch's ``load_balancer`` column are
updated accordingly.

The ovn-northd service, which monitors for changes to the OVN Northbound DB,
generates OVN logical flows to enable load balancing, and ovn-controller
running on each compute node translates the logical flows into actual
OpenFlow rules.

The status of each entity in the Octavia DB is managed according to [4]

Below are a few examples on what happens when LoadBalancer commands are
executed and what changes in the Load_Balancer Northbound DB table.

1. Create a LoadBalancer::

    $ openstack loadbalancer create --provider ovn --vip-subnet-id=private lb1

    $ ovn-nbctl list load_balancer
    _uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
    external_ids  : {
        lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
        ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 1}",
        neutron:vip="10.0.0.10",
        neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
    name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
    protocol      : []
    vips          : {}

2.  Create a pool::

     $ openstack loadbalancer pool create --name p1 --loadbalancer lb1
     --protocol TCP --lb-algorithm SOURCE_IP_PORT

     $ ovn-nbctl list load_balancer
     _uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
     external_ids  : {
         lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
         ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 1}",
         "pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9"="", neutron:vip="10.0.0.10",
         neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
     name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
     protocol      : []
     vips          : {}

3. Create a member::

    $ openstack loadbalancer member create --address 10.0.0.107
     --subnet-id 2d54ec67-c589-473b-bc67-41f3d1331fef --protocol-port 80 p1

    $ ovn-nbctl list load_balancer
    _uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
    external_ids  : {
        lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
        ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 2}",
        "pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9"=
        "member_579c0c9f-d37d-4ba5-beed-cabf6331032d_10.0.0.107:80",
        neutron:vip="10.0.0.10",
        neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
    name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
    protocol      : []
    vips          : {}

4. Create another member::

    $ openstack loadbalancer member create --address 20.0.0.107
     --subnet-id c2e2da10-1217-4fe2-837a-1c45da587df7 --protocol-port 80 p1

    $ ovn-nbctl list load_balancer
    _uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
    external_ids  : {
        lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
        ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 2,
              \"neutron-12c42705-3e15-4e2d-8fc0-070d1b80b9ef\": 1}",
        "pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9"=
        "member_579c0c9f-d37d-4ba5-beed-cabf6331032d_10.0.0.107:80,
         member_d100f2ed-9b55-4083-be78-7f203d095561_20.0.0.107:80",
        neutron:vip="10.0.0.10",
        neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
    name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
    protocol      : []
    vips          : {}

5. Create a listener::

    $ openstack loadbalancer listener create --name l1 --protocol TCP
     --protocol-port 82 --default-pool p1 lb1

    $ ovn-nbctl list load_balancer
    _uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
    external_ids  : {
        lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
        ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 2,
                  \"neutron-12c42705-3e15-4e2d-8fc0-070d1b80b9ef\": 1}",
        "pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9"="10.0.0.107:80,20.0.0.107:80",
        "listener_12345678-2501-43f2-b34e-38a9cb7e4132"=
            "82:pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9",
        neutron:vip="10.0.0.10",
        neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
    name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
    protocol      : []
    vips          : {"10.0.0.10:82"="10.0.0.107:80,20.0.0.107:80"}

As explained earlier in the design section:

- If a network N1 has a LoadBalancer LB1 associated to it and one of
  its interfaces is added to a router R1, LB1 is associated with R1 as well.

- If a network N2 has a LoadBalancer LB2 and one of its interfaces is added
  to the router R1, then R1 will have both LoadBalancers LB1 and LB2. N1 and
  N2 will also have both the LoadBalancers associated to them. However, kindly
  note that although network N1 would have both LB1 and LB2 LoadBalancers
  associated with it, only LB1 would be the LoadBalancer which has a direct
  reference to the network N1, since LB1 was created on N1. This is visible
  in the ``ls_ref`` key of the ``external_ids`` column in LB1's entry in
  the ``load_balancer`` table.

- If a network N3 is added to the router R1, N3 will also have both
  LoadBalancers (LB1, LB2) associated to it.

- If the interface to network N2 is removed from R1, network N2 will now only
  have LB2 associated with it. Networks N1 and N3 and router R1 will have
  LoadBalancer LB1 associated with them.

Limitations
-----------
The Following actions are not supported by the OVN Provider Driver:

- Creating a LoadBalancer/Listener/Pool with an L7 Protocol

- Currently only one algorithm is supported for pool management
  (Source IP Port)

- Due to nature of OVN octavia driver (flows distributed in all the nodes)
  there is no need for some of the amphora specific functionality that is
  specific to the fact that a VM is created for the load balancing actions. As
  an example, there is no need for flavors (no VM is created), failovers (no
  need to recover a VM), or HA (no need to create extra VMs as in the
  ovn-octavia case the flows are injected in all the nodes, i.e., it is HA by
  default).

Support Matrix
--------------
A detailed matrix of the operations supported by OVN Provider driver in Octavia
can be found in https://docs.openstack.org/octavia/latest/user/feature-classification/index.html

Octavia DB to OVN database population
--------------------------------------

In case of OVN DB clustering failure and Load Balancer data loss as a result, you can always re-populate data in OVN NB/SB from the information store in Octavia database.
With that objective the tool octavia-ovn-db-sync-util was created. It is a command-line tool that allows synchronizing the state of Octavia resources (such as Load Balancers, Listeners, Pools, etc.) with the OVN Northbound (NB)/Southbound (SB) database. This is especially useful in situations where:

- Inconsistencies have occurred between Octavia and OVN.

- The OVN database has been restored or recreated.

- A migration or repair of load balancing resources is required.

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


Other References
----------------
[1] Octavia API:
https://docs.openstack.org/api-ref/load-balancer/v2/

[2] Octavia Glossary:
https://docs.openstack.org/octavia/latest/reference/glossary.html

[3] https://github.com/openvswitch/ovs/commit/612f80fa8ebf88dad2e204364c6c02b451dca36c

[4] https://docs.openstack.org/api-ref/load-balancer/v2/index.html#status-codes

[5] https://github.com/openvswitch/ovs/blob/d1b235d7a6246e00d4afc359071d3b6b3ed244c3/ovn/ovn-nb.ovsschema#L117
