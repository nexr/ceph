===================
Lineage Integration
===================

.. versionadded:: Apex (nes)

You can record the Ceph Object Gateway data flows to lineage management system (e.g. apache atlas).

How it works
============

.. ditaa::
           +---------------------+
           | Ceph Object Gateway |
           |   +-----------------+   data flow info   +---------------------+
           |   | Lineage Manager + -----------------> + Lineage MGMT System |
           +---+-----------------+                    +---------------------+

The Ceph Object Gateway record request process information in particular data structures.
The Lineage Manager read the data structures, and send data flow to the backend lineage management system.
In the lineage management system, we can see the data flow with graphical image and search the wanted history simply.

You can use the apache atlas as backend lineage management system.
Currently, Lineage Manager support only apache atlas.
The kind of backend lineage management system would be expanded some day.

There are two mothod to connect to apache atlas: "rest API" and "kafka".
But, "kafka" method is not implemented now.

Requirements
============

- **Lineage management system:** A running Lineage management system instance accessible by the Ceph Object Gateway

Define Ceph Object Gateway customed models
=============

Define custom models for Ceph Object Gateway to exchange messages with backend lineage management system.

In ``/usr/share/ceph/rgw/lineage_defs``, we can find the custom model definition files.
The custom model definition could be applied to lineage management system.

Apache Atlas define custom model like this.

::

  // Copy custom definition file to backend apache atlas.
  [user@ceph-rgw]# scp -r /usr/share/ceph/rgw/lineage_defs/atlas/models ${atlas_host}:${atlas_server_dir}

  // Restart the apache atlas server.
  [user@atlas]# su atlas -c ${atlas_server_dir}/bin/atlas_stop.py 
  [user@atlas]# su atlas -c ${atlas_server_dir}/bin/atlas_start.py 

.. note:: Custom model definition step can be replaced with "rgw_lineage_init_definition" configuration.

Configuring the Ceph Object Gateway to use Lineage Integration
==============================================================

The following parameters in the Ceph configuration file are related to the Lineage Integration:

- ``rgw_lineage_enable``: Enable lineage integration.
- ``rgw_lineage_manager_interval``:  Interval for lineage manager to fetch lineage request. The default value is 3 second.
- ``rgw_lineage_manager_retries``: The number of retries for failed lineage request. The default value is 5 tries.
- ``rgw_lineage_init_definition``: Enable init_definition step. The default value is "false".
  If true, define custom model to backend lineage management system automatically.
  It alternates the "Define Ceph Object Gateway customed models" step.
- ``rgw_lineage_record_getobj``: Enable GET_OBJ recoding to the backend system. The default value is "false".
- ``rgw_lineage_record_external_in``: Enable external_in recoding to the backend system. The default value is "true".
- ``rgw_lineage_record_external_out``: Enable external_out recoding to the backend system. The default value is "false".
- ``rgw_lineage_backend``: Type of backend linenage system. Supported type: atlas. The default value is "atlas".

Using apache atlas as backend lineage management system
=================================================

When ``rgw_lineage_backend`` is "atlas", the apache atlas could be a backend lineage management system.
The "atlas" is default value of ``rgw_lineage_backend``.

Specifying a method to connect to apache atlas
----------------------------------------------

The apache atlas connetion method is specified by ``rgw_lineage_atlas_mode`` value.
The ``rgw_lineage_atlas_mode`` config can be "rest" or "kafka"(not_implemeted).
The "rest" is default value of ``rgw_lineage_atlas_mode``.

Configuring apache atlas rest API connection
--------------------------------------------

The following parameters in the Ceph configuration file are related to the apache atlas rest API connection:

- ``rgw_lineage_atlas_rest_url``: Atlas url address of atlas endpoint.
  The atlas url address with protocol and port. ex) http[s]://x.x.x.x:yy.
- ``rgw_lineage_atlas_rest_url_prefix``: The atlas url prefix. The default value is "api/atlas".
- ``rgw_lineage_atlas_rest_version``: The atlas api version. The default value is "v2".
- ``rgw_lineage_atlas_rest_admin_user``: Atlas admin user.
- ``rgw_lineage_atlas_rest_admin_password``: Atlas admin password. The password take the form of plane text. 
- ``rgw_lineage_atlas_rest_admin_password_path``: Path to a file containing the Atlas admin password. This overrides ``rgw_lineage_atlas_rest_admin_password``.

Apache atlas config example
---------------------------

::
  
  [client.rgw.atlas]

  ...

  ## rgw lineage feature on/off
  rgw_lineage_enable = true

  rgw_lineage_init_definition = true

  ## lineage backend configure
  # rgw_lineage_backend: "atlas" only
  rgw_lineage_backend = atlas

  # rgw_lineage_atlas_mode: "rest" or "kafka".
  # kafka mode is not implemented.
  rgw_lineage_atlas_mode = rest

  ## lineage atlas rest endpoint config
  rgw_lineage_atlas_rest_url = http://192.168.80.61:21000

  ## lineage atlas rest authoriztion config
  rgw_lineage_atlas_rest_admin_user = admin
  rgw_lineage_atlas_rest_admin_password = admin
  # rgw_lineage_atlas_rest_admin_password_path = /var/lib/ceph/radosgw/ceph-rgw.atlas/atlas_pass

When use this config, "atlas" Ceph Object Gateway record data flow to apache atlas(192.168.80.61:21000) with restAPI.

