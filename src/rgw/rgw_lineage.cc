#include "rgw_lineage.h"
#include "rgw_lineage_atlas.h"
#include "rgw_rest.h"

RGWLineageManager::RGWLineageManager(CephContext* const _cct): cct(_cct)
{
  string backend_type = cct->_conf->rgw_lineage_backend;

  if (backend_type.compare("atlas") == 0) {
    rgw_lineage  = new RGWLineageAtlas(cct);
    backend_type = RGWLineageManager::BackendType::LINEAGE_BACKEND_TYPE_ATLAS;
  }
  else {
    rgw_lineage = nullptr;
  }

  record_getobj = cct->_conf->rgw_lineage_record_getobj;

  wait_sec = cct->_conf->rgw_lineage_manager_interval;
  retries  = cct->_conf->rgw_lineage_manager_retries;

  can_init = cct->_conf->rgw_lineage_init_definition;

  user_tenancy = cct->_conf->rgw_lineage_user_tenancy;
}

RGWLineageManager::~RGWLineageManager()
{
  if (is_started()) {
    join();
  }

  if (rgw_lineage != nullptr) {
    delete rgw_lineage;
  }
}

const string RGWLineageManager::optype_to_string(RGWOpType op_type)
{
  switch(op_type) {
    case RGW_OP_CREATE_BUCKET:
      return "CREATE_BUCKET";
      break;
    case RGW_OP_DELETE_BUCKET:
      return "DELETE_BUCKET";
      break;
    case RGW_OP_PUT_OBJ:
    case RGW_OP_COMPLETE_MULTIPART:
      return "PUT_OBJ";
      break;
    case RGW_OP_POST_OBJ:
      return "POST_OBJ";
      break;
    case RGW_OP_GET_OBJ:
      return "GET_OBJ";
      break;
    case RGW_OP_DELETE_OBJ:
      return "DELETE_OBJ";
      break;
    case RGW_OP_COPY_OBJ:
      return "COPY_OBJ";
      break;
    case RGW_OP_DELETE_MULTI_OBJ:
      return "DELETE_MULTI_OBJ";
      break;
    default:
      return "UNKNOWN_OP";
  }
};

const string RGWLineageManager::get_etag(RGWOp* op)
{
  string etag;

  if (op != NULL) {
    switch (op->get_type()) {
      case RGW_OP_PUT_OBJ:
        etag = ((RGWPutObj*)op)->get_etag();
        break;
      case RGW_OP_POST_OBJ:
        etag = ((RGWPostObj*)op)->get_etag();
        break;
      case RGW_OP_COPY_OBJ:
        etag = ((RGWCopyObj*)op)->get_etag();
        break;
      case RGW_OP_COMPLETE_MULTIPART:
        etag = ((RGWCompleteMultipart*)op)->get_etag();
        break;
      default:
        etag = "";
    }
  }

  return etag;
};

const bufferlist RGWLineageManager::get_data(RGWOp* op)
{
  bufferlist data;

  if (op != NULL) {
    switch (op->get_type()) {
      case RGW_OP_DELETE_MULTI_OBJ:
        data = ((RGWDeleteMultiObj*)op)->get_data();
        break;
      default:
        data.clear();
    }
  }

  return data;
};

long RGWLineageManager::get_size(req_state* rs, RGWOp* op)
{
  long size = 0;

  if (rs->op_type == RGW_OP_COMPLETE_MULTIPART) {
    size = ((RGWCompleteMultipart *)op)->get_total_size();
  }
  else {
    size = (long) rs->obj_size;
  }

  return size;
}

void RGWLineageManager::enqueue(req_state* rs, RGWOp* op)
{
  dout(20) << __func__ << "(): entry!!" << dendl;

  if (rs->err.is_err()) {
    dout(10) << __func__ << "(): The failed request don't be applied to lineage(" << rs->trans_id << ")" << dendl;
    return;
  }

  string op_type_str = optype_to_string(rs->op_type);

  if (!op_type_str.compare("UNKNOWN_OP")) {
    dout(10) << __func__ << "(): The UNKNOWN_OP request don't be applied to lineage(" << rs->trans_id << ")" << dendl;
    return;
  }

  string object_name = rs->object.to_str();
  string mp_num_str  = rs->info.args.get("partNumber");

  // skip multipart object request
  if (!object_name.empty() && !mp_num_str.empty()) return;

  lineage_req lr;

  lr.req_id = rs->trans_id;

  lr.req_time  = rs->time;
  lr.req_addr  = rs->env["aws:SourceIp"];
  lr.req_agent = rs->env["aws:UserAgent"];

  lr.op_type     = rs->op_type;
  lr.op_type_str = op_type_str;

  lr.server_id    = cct->_conf->name.to_str();
  lr.server_host  = cct->_conf->host;
  lr.server_addr  = rs->info.host;
  lr.server_owner = cct->_conf->cluster;
  lr.server_fsid  = cct->_conf.get_val<uuid_d>("fsid").to_string();

  lr.account = rs->user->get_id().to_str();

  lr.zonegroup = (!rs->zonegroup_name.empty()) ? rs->zonegroup_name : "default";

  lr.bucket            = rs->bucket_name;
  lr.bucket_owner_id   = rs->bucket_owner.get_id().to_str();
  lr.bucket_owner_name = rs->bucket_owner.get_display_name();

  lr.object            = object_name;
  lr.object_etag       = get_etag(op);
  lr.object_size       = get_size(rs, op);
  lr.object_owner_id   = rs->owner.get_id().to_str();
  lr.object_owner_name = rs->owner.get_display_name();

  lr.src_bucket = rs->src_bucket_name;
  lr.src_object = rs->src_object.name;

  lr.tenant = (user_tenancy) ? lr.bucket_owner_id : "";

  lr.data = get_data(op);

  lr_queue.push(lr);
  dout(10) << __func__ << "(): " << lr.op_type_str << " lineage request enqueued. "
           << "tenant: " << lr.tenant << ", "
           << "bucket: " << lr.bucket << ", "
           << "object: " << lr.object << dendl;
}

void RGWLineageManager::start()
{
  down_flag = false;
  create(thread_name.c_str());
}

void RGWLineageManager::stop()
{
  if (is_started()) {
    down_flag = true;
    join();
  }
}

void * RGWLineageManager::entry()
{
  if (rgw_lineage == NULL) {
    dout(0) << __func__ << "(): rgw_lineage implementation not initialized" << dendl;
    return NULL;
  }

  bool need_wait = false;
  int tries = 0;

  while (true)
  {
    if (need_wait) { sleep(wait_sec); }
    else { need_wait = true; }

    if (lr_queue.empty()) {
      if (down_flag) { break; } else { continue; }
    }
    dout(20) << __func__ << "(): lr_queue size = " << lr_queue.size() << dendl;

    lineage_req * lr = &(lr_queue.front());
    string tenant = lr->tenant;

    if (can_init && tenant_init.find(tenant) == tenant_init.end()) {
      rgw_lineage->apply_lineage_init_definition(tenant);
      tenant_init.insert({tenant, true});
    }

    if (lr->op_type_str.compare("UNKNOWN_OP") == 0) {
      need_wait = false;
      lr_queue.pop();
      continue;
    }

    if (!rgw_lineage->is_lineage_health_ok(tenant)) {
      if (down_flag) { break; } else { continue; }
    }

    int ret = -1;
    switch (lr->op_type) {
      case RGW_OP_CREATE_BUCKET:
        ret = rgw_lineage->apply_lineage_bucket_creation(lr, tenant);
        break;
      case RGW_OP_DELETE_BUCKET:
        ret = rgw_lineage->apply_lineage_bucket_deletion(lr, tenant);
        break;
      case RGW_OP_PUT_OBJ:
      case RGW_OP_POST_OBJ:
      case RGW_OP_COMPLETE_MULTIPART:
        ret = rgw_lineage->apply_lineage_object_creation(lr, tenant);
        break;
      case RGW_OP_GET_OBJ:
        if (record_getobj) {
          ret = rgw_lineage->apply_lineage_object_gotten(lr, tenant);
        }
        else {
          ret = 200;
        }
        break;
      case RGW_OP_DELETE_OBJ:
        ret = rgw_lineage->apply_lineage_object_deletion(lr, tenant);
        break;
      case RGW_OP_COPY_OBJ:
        ret = rgw_lineage->apply_lineage_object_copy(lr, tenant);
        break;
      case RGW_OP_DELETE_MULTI_OBJ:
        ret = rgw_lineage->apply_lineage_object_multi_deletion(lr, tenant);
        break;
      default:
        ret = 200;
    }

    if (ret != 200 && tries < retries) {
      dout(20) << __func__ << "(): Failed to handle " << lr->op_type_str
                           << " (ret: " << ret << ")"
                           << dendl;
      dout(10) << __func__ << "(): lineange request retry occur!!"
                           << " (tries = " << tries << ")"
                           << dendl;
      tries++;
      continue;
    }

    need_wait = false;

    tries = 0;
    lr_queue.pop();
  }

  return NULL;
}

