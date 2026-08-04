===================================
OVN Integration Module
===================================

This module contains OVN-related integrations for the Octavia OVN provider
that extend Neutron's OVN functionality.

Contents
========

db_sync.py
----------

Implements the ``OctaviaOvnSynchronizer`` class, which is a plugin for
Neutron's ``neutron-ovn-db-sync-util`` CLI tool.

The synchronizer allows Octavia load balancers (OVN provider) to be
synchronized with the OVN Northbound database as part of the standard
Neutron OVN database synchronization process.

**Key Features:**

* Inherits from ``BaseOvnDbSynchronizer`` (from neutron-lib or neutron)
* Registered via ``neutron.ovn.db_sync`` entry point
* Reuses OVN Northbound connection from Neutron
* Supports REPAIR and MIGRATE modes
* Filters to only sync OVN provider load balancers

**Entry Point Registration:**

The plugin is registered in ``setup.cfg``:

.. code-block:: ini

    [entry_points]
    neutron.ovn.db_sync =
        octavia_ovn_sync = ovn_octavia_provider.ovn.db_sync:OctaviaOvnSynchronizer

**Usage:**

The plugin is automatically loaded when running ``neutron-ovn-db-sync-util``:

.. code-block:: bash

    neutron-ovn-db-sync-util \
        --config-file /etc/neutron/neutron.conf \
        --config-file /etc/neutron/plugins/ml2/ml2_conf.ini \
        --ovn-neutron_sync_mode repair

**Important:** Do NOT pass ``/etc/octavia/octavia.conf`` via ``--config-file``.
Use ``--octavia-config-file`` instead (or rely on the default path) to avoid
conflicts with Neutron's database connection configuration.

For more details, see the administration documentation in
``doc/source/admin/ovn-db-sync-plugin.rst``.

Implementation Notes
====================

BaseOvnDbSynchronizer Import
----------------------------

The module imports ``BaseOvnDbSynchronizer`` from ``neutron_lib.ovn.db_sync``.
This base class was moved from Neutron to neutron-lib to allow stadium projects
and third-party plugins to implement their own OVN database synchronizers.

Mode Support
------------

The synchronizer currently supports:

* **REPAIR**: Full synchronization with repairs
* **MIGRATE**: Same as REPAIR for Octavia resources
* **OFF**: No synchronization

The synchronizer explicitly **does not support**:

* **LOG**: Read-only mode is not implemented. If the utility is run in LOG
  mode, the Octavia plugin will skip synchronization and log a warning.

This limitation exists because the current Octavia OVN provider driver
(``do_sync`` method) always performs repairs and does not have a read-only
verification mode.

Future enhancements could add LOG mode support by implementing comparison
logic that doesn't modify the OVN database.

Relationship to Standalone Tool
================================

The ``octavia-ovn-db-sync-util`` standalone CLI tool remains available and
uses the same underlying synchronization logic from the OVN provider driver.

The key difference is:

* **Standalone tool**: Creates its own OVN connection, runs independently
* **Plugin**: Reuses Neutron's OVN connection, runs as part of integrated sync

Both approaches call the same ``driver.OvnProviderDriver.do_sync()`` method.
