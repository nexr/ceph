#ifndef CEPH_RGW_LINEAGE_INTERFACES_H
#define CEPH_RGW_LINEAGE_INTERFACES_H
#include "rgw_request.h"

#define dout_subsys ceph_subsys_rgw
#define dout_context g_ceph_context

typedef struct {
  using time = ceph::coarse_real_clock::time_point;

  string req_id;

  time   req_time;
  string req_addr;
  string req_agent;

  RGWOpType op_type;
  string op_type_str;

  string server_id;
  string server_addr;
  string server_host;
  string server_owner;
  string server_fsid;

  string account;

  string zonegroup;

  string bucket;
  string bucket_owner_id;
  string bucket_owner_name;

  string object;
  string object_etag;
  long   object_size;
  string object_owner_id;
  string object_owner_name;

  string src_bucket;
  string src_object;

  // body content
  bufferlist data;

} lineage_req;


class RGWLineage
{
protected:
  CephContext* cct;

public:
  virtual ~RGWLineage(){};

  virtual int apply_lineage_init_definition() = 0;
  virtual int apply_lineage_bucket_creation(lineage_req * const lr) = 0;
  virtual int apply_lineage_bucket_deletion(lineage_req * const lr) = 0;
  virtual int apply_lineage_object_creation(lineage_req * const lr) = 0;
  virtual int apply_lineage_object_gotten(lineage_req * const lr) = 0;
  virtual int apply_lineage_object_deletion(lineage_req * const lr) = 0;
  virtual int apply_lineage_object_multi_deletion(lineage_req * const lr) = 0;
  virtual int apply_lineage_object_copy(lineage_req * const lr) = 0;

  virtual bool is_lineage_health_ok() = 0;
};

class RGWLineageAtlasImpl
{
protected:
  CephContext* cct;

  bool record_external_in  = true;
  bool record_external_out = true;

  const string make_s3_qname(const string bucket, const string object = "") {
    string qname  = "s3://";

    qname += bucket;
 
    if (!object.empty()) {
      qname += "/" + object;
    }

    return qname;
  };

public:
  RGWLineageAtlasImpl(CephContext* const _cct) {
    cct = _cct;
    record_external_in  = cct->_conf->rgw_lineage_record_external_in;
    record_external_out = cct->_conf->rgw_lineage_record_external_out;
  };
  virtual ~RGWLineageAtlasImpl(){};

  virtual int atlas_init_definition() = 0;
  virtual int atlas_bucket_creation(lineage_req * const lr) = 0;
  virtual int atlas_bucket_deletion(lineage_req * const lr) = 0;
  virtual int atlas_object_creation(lineage_req * const lr) = 0;
  virtual int atlas_object_gotten(lineage_req * const lr) = 0;
  virtual int atlas_object_deletion(lineage_req * const lr) = 0;
  virtual int atlas_object_multi_deletion(lineage_req * const lr) = 0;
  virtual int atlas_object_copy(lineage_req * const lr) = 0;

  virtual bool is_atlas_health_ok() = 0;
};

#endif
