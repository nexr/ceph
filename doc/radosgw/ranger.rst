==================
Ranger Integration
==================

.. versionadded:: Apex (nes 1.1.1)

You can decide whether to allow Ceph Object Gateway requests by referring to the ranger's authorization policy.

How it works
============

.. ditaa::

 +--------+  1. send request
 | Client +------------------+
 +---+----+                  |
     ^                       v         2. query
     |                +------+------+     access policy  +------------------------+
     +--------------- + Ceph Object + -----------------> + Apache Ranger          |
     3. allow or deny | Gateway     + <----------------- + security policy System |
        request       +-------------+                    +------------------------+

When The Ceph Object Gateway receives a request from a client, it determines whether the request is authorized or not.
In this case, by using the Ranger Integration feature, The Ceph Object Gateway can refer to the authorization policy of the apache ranger.

Requirements
============

- **External Apache Ranger:** One or more running Ranger security policy system instance accessible by the Ceph Object Gateway. (Ranger version >= 1.1.0)

Install S3 ranger plugin to external ranger
=============

Install S3 ranger plugin to external ranger to define s3 access policies.

In ``/usr/share/ceph/rgw/ranger_plugins/s3``, we can find the s3 ranger plugin jar and service definition file.

To install s3 rnager plugin, do like bellow.
::

  // Copy ranger plugin jar and service definition file to external apache ranger.
  [user@ceph-rgw]# scp -r /usr/share/ceph/rgw/ranger_plugins/s3 ${ranger_host}:${ranger_admin_dir}/ews/webapp/WEB-INF/classes/ranger-plugins

  // Apply s3 service definition to external apache ranger server.
  [user@ceph-rgw]# curl -u ${ranger_admin_user}:${ranger_admin_passwd} \
                        -d "@/usr/share/ceph/rgw/ranger_plugins/s3/s3-service-definition.json" \
                        -X POST \
                        -H "Accept: application/json" -H "Content-Type: application/json" \
                        ${ranger_url}/service/public/v2/api/servicedef

Configuring the Ceph Object Gateway to use Ranger Integration
=============================================================

The following parameters in the Ceph configuration file are related to the Ranger Integration:

- ``rgw_use_ranger_authz``: Should Ranger be used to authorize client requests. The default value is "false".
  If it is true, radosgw check ranger access policies when authorizing requests.
- ``rgw_ranger_url``: URL to Ranger server. example) http[s]://1.2.3.4:6080
- ``rgw_ranger_admin_user``: The Ranger admin user name to authenticate ranger requests.
- ``rgw_ranger_admin_password``: The Ranger admin user password to authenticate ranger.
- ``rgw_ranger_admin_password_path``: Path to a file containing the Ranger admin password. It override ``rgw_ranger_admin_password``.
- ``rgw_ranger_tenant``: The ranger group name for tenant of this cluster. The default value is "nes".
- ``rgw_ranger_verify_ssl``: Should RGW verify the Ranger server SSL certificate. The default value is "true".
- ``rgw_ranger_cache_dir``: The directory path to save cached ranger policies.
- ``rgw_ranger_cache_update_interval``: The interval (in seconds) to update cached ranger policy. The default value is 60.
- ``rgw_ranger_use_cached_one_if_not_cache_updating``: If it's true, rgw use cached policy when cache update is not needed.
  This option can reduce request latency dramatically, but some audit log could be lost while ``rgw_ranger_cache_update_interval``.
- ``rgw_ranger_cache_age``: The age (in seconds) of cached ranger policy. The default value is 2592000 (30 days)
  If the age is over, the cached policy replace with a remote policy.
  If 0, cache eviction becomes diabled.
- ``rgw_ranger_engine``: Ranger integration engine type. One of 'native', 'jni'.
- ``rgw_ranger_jni_config_dir``: The directory path to jni class files. It's only used when ``rgw_ranger_engine`` is 'jni'.
- ``rgw_ranger_jni_engine_jar``: The file path to jni engine jar. It's only user when ``rgw_ranger_engine`` is 'jni'.
- ``rgw_ranger_audit_config_age``: The age (in seconds) of ranger audit config. If the age is over, ranger audit config replace with a new one.
- ``rgw_ranger_audit_url``: URL to Solr server to log ranger audit. example) http[s]://1.2.3.4:6083/solr/ranger_audits

Apache atlas config example 1: native ranger engine
---------------------------

::

  [client.rgw.ranger]

  ...

  ## rgw ranger feature on/off
  rgw_use_ranger_authz = true

  ## set ranger engine type
  rgw_ranger_engine = native

  ## make engine to use cached one when cache_update not occurs
  rgw_ranger_use_cached_one_if_not_cache_updating = true

  ## ranger rest endpoint config
  rgw_ranger_url = http://192.168.80.61:6080
  rgw_ranger_verify_ssl = false
  # rgw_ranger_tenant = nes

  ## ranger authentication config
  rgw_ranger_admin_user = admin
  rgw_ranger_admin_password = admin
  # rgw_ranger_admin_password_path = /var/lib/ceph/radosgw/ceph-rgw.ranger/ranger_pass

When use this config, "ranger" Ceph Object Gateway refers access policies of apache ranger(192.168.80.61:6080) to authorize client requests.
If ``endpoints`` of user is not defined, ranger integration use policies of config-indicated ranger service.
If ``rgw_ranger_engine`` is "native", ranger integration use cpp-based engine. (low latency, but no audit log)

Apache atlas config example 2: jni ranger engine
---------------------------

::

  [client.rgw.ranger]

  ...

  ## rgw ranger feature on/off
  rgw_use_ranger_authz = true

  ## set ranger engine type
  rgw_ranger_engine = jni

  ## make engine to use cached one when cache_update not occurs
  rgw_ranger_use_cached_one_if_not_cache_updating = false

  ## ranger rest endpoint config
  rgw_ranger_url = http://192.168.80.61:6080
  rgw_ranger_verify_ssl = false
  # rgw_ranger_tenant = nes

  ## ranger audit endpoint config
  rgw_ranger_audit_url = http://192.168.80.61:6083/solr/ranger_audits


When use this config, "ranger" Ceph Object Gateway refers access policies of apache ranger(192.168.80.61:6080) to authorize client requests.
And result of authoizing process would be recorded to ranger audit server(192.168.80.61:6083).
If ``endpoints`` of user is not defined, ranger integration use policies of config-indicated ranger service.
If ``rgw_ranger_engine`` is "jni", ranger integration use java-based engine. (high latency, can record audit log)

(Optional) Specify user-dedicated ranger endpoint
=================================================

Ranger Integration feature support ``endpoints`` of user infomation.
If a 'ranger' type endpoint is defined in specific user infomation,
requests related to the user would be allowed or denied based on the ranger service indicated by the endpoint information.

If a 'ranger_audit' type endpoint is defined in specific user infomation,
results related to the user would be recorded to the ranger audit server indicated by the endpoint information.

For how to create/modify/delete user endpoint, refer to :ref:`radosgw_admin_user_endpoints` and :ref:`radosgw_adminops_user_endpoints`.

.. ditaa::
                                          +-------------------------------+
                                          | Use endpoint indicated ranger |
                                          +-------------------------------+
                                                           ^
                        +------------------------------+   |
 +-----------+    +---> | If 'ranger' endpoint defined +---+
 | rgw  {io} |    |     +------------------------------+
 | user      + ---+
 | request   |    |     +------+          +---------------------------------+
 +-----------+    +---> | else + -------> | Use rgw config indicated ranger |
                        +------+          +---------------------------------+


