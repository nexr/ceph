// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "common/ceph_json.h"

#include "rgw_op.h"
#include "rgw_user.h"
#include "rgw_rest_user.h"

#include "include/str_list.h"
#include "include/ceph_assert.h"

#include "services/svc_zone.h"
#include "services/svc_sys_obj.h"
#include "rgw_zone.h"

#define dout_subsys ceph_subsys_rgw

class RGWOp_User_List : public RGWRESTOp {

public:
  RGWOp_User_List() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_READ);
  }

  void execute() override;

  const char* name() const override { return "list_user"; }
};

void RGWOp_User_List::execute()
{
  RGWUserAdminOpState op_state;

  uint32_t max_entries;
  std::string marker;
  RESTArgs::get_uint32(s, "max-entries", 1000, &max_entries);
  RESTArgs::get_string(s, "marker", marker, &marker);

  op_state.max_entries = max_entries;
  op_state.marker = marker;
  http_ret = RGWUserAdminOp_User::list(store, op_state, flusher);
}

class RGWOp_User_Info : public RGWRESTOp {

public:
  RGWOp_User_Info() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_READ);
  }

  void execute() override;

  const char* name() const override { return "get_user_info"; }
};

void RGWOp_User_Info::execute()
{
  RGWUserAdminOpState op_state;

  std::string uid_str, access_key_str;
  bool fetch_stats;
  bool sync_stats;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  RESTArgs::get_string(s, "access-key", access_key_str, &access_key_str);

  // if uid was not supplied in rest argument, error out now, otherwise we'll
  // end up initializing anonymous user, for which keys.init will eventually
  // return -EACESS
  if (uid_str.empty() && access_key_str.empty()){
    http_ret=-EINVAL;
    return;
  }

  rgw_user uid(uid_str);

  RESTArgs::get_bool(s, "stats", false, &fetch_stats);

  RESTArgs::get_bool(s, "sync", false, &sync_stats);

  op_state.set_user_id(uid);
  op_state.set_access_key(access_key_str);
  op_state.set_fetch_stats(fetch_stats);
  op_state.set_sync_stats(sync_stats);

  http_ret = RGWUserAdminOp_User::info(store, op_state, flusher);
}

class RGWOp_User_Create : public RGWRESTOp {

public:
  RGWOp_User_Create() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "create_user"; }
};

void RGWOp_User_Create::execute()
{
  std::string uid_str;
  std::string display_name;
  std::string email;
  std::string access_key;
  std::string secret_key;
  std::string key_type_str;
  std::string caps;
  std::string tenant_name;
  std::string op_mask_str;
  std::string default_placement_str;
  std::string placement_tags_str;
  std::string endp_type, endp_url, endp_tenant;
  std::string endp_admin, endp_admin_pw, endp_admin_pw_path;

  bool endp_enabled;
  bool gen_key;
  bool suspended;
  bool system;
  bool exclusive;

  int32_t max_buckets;
  const int32_t default_max_buckets =
    s->cct->_conf.get_val<int64_t>("rgw_user_max_buckets");

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "display-name", display_name, &display_name);
  RESTArgs::get_string(s, "email", email, &email);
  RESTArgs::get_string(s, "access-key", access_key, &access_key);
  RESTArgs::get_string(s, "secret-key", secret_key, &secret_key);
  RESTArgs::get_string(s, "key-type", key_type_str, &key_type_str);
  RESTArgs::get_string(s, "user-caps", caps, &caps);
  RESTArgs::get_string(s, "tenant", tenant_name, &tenant_name);
  RESTArgs::get_bool(s, "generate-key", true, &gen_key);
  RESTArgs::get_bool(s, "suspended", false, &suspended);
  RESTArgs::get_int32(s, "max-buckets", default_max_buckets, &max_buckets);
  RESTArgs::get_bool(s, "system", false, &system);
  RESTArgs::get_bool(s, "exclusive", false, &exclusive);
  RESTArgs::get_string(s, "op-mask", op_mask_str, &op_mask_str);
  RESTArgs::get_string(s, "default-placement", default_placement_str, &default_placement_str);
  RESTArgs::get_string(s, "placement-tags", placement_tags_str, &placement_tags_str);
  RESTArgs::get_string(s, "endpoint-type", endp_type, &endp_type);
  RESTArgs::get_string(s, "endpoint-url",  endp_url,  &endp_url);
  RESTArgs::get_string(s, "endpoint-tenant",  "nes",  &endp_tenant);
  RESTArgs::get_string(s, "endpoint-admin",  endp_admin, &endp_admin);
  RESTArgs::get_string(s, "endpoint-admin-passwd",  endp_admin_pw, &endp_admin_pw);
  RESTArgs::get_string(s, "endpoint-admin-passwd-path",  endp_admin_pw_path, &endp_admin_pw_path);
  RESTArgs::get_bool(s, "endpoint-enabled", true, &endp_enabled);

  if (!s->user->get_info().system && system) {
    ldout(s->cct, 0) << "cannot set system flag by non-system user" << dendl;
    http_ret = -EINVAL;
    return;
  }

  if (!tenant_name.empty()) {
    uid.tenant = tenant_name;
  }

  // TODO: validate required args are passed in. (for eg. uid and display_name here)
  op_state.set_user_id(uid);
  op_state.set_display_name(display_name);
  op_state.set_user_email(email);
  op_state.set_caps(caps);
  op_state.set_access_key(access_key);
  op_state.set_secret_key(secret_key);

  if (!op_mask_str.empty()) {
    uint32_t op_mask;
    int ret = rgw_parse_op_type_list(op_mask_str, &op_mask);
    if (ret < 0) {
      ldout(s->cct, 0) << "failed to parse op_mask: " << ret << dendl;
      http_ret = -EINVAL;
      return;
    }
    op_state.set_op_mask(op_mask);
  }

  if (!key_type_str.empty()) {
    int32_t key_type = KEY_TYPE_UNDEFINED;
    if (key_type_str.compare("swift") == 0)
      key_type = KEY_TYPE_SWIFT;
    else if (key_type_str.compare("s3") == 0)
      key_type = KEY_TYPE_S3;

    op_state.set_key_type(key_type);
  }

  if (max_buckets != default_max_buckets) {
    if (max_buckets < 0) {
      max_buckets = -1;
    }
    op_state.set_max_buckets(max_buckets);
  }

  if (s->info.args.exists("suspended"))
    op_state.set_suspension(suspended);

  if (s->info.args.exists("system"))
    op_state.set_system(system);

  if (s->info.args.exists("exclusive"))
    op_state.set_exclusive(exclusive);

  if (gen_key)
    op_state.set_generate_key();

  if (!default_placement_str.empty()) {
    rgw_placement_rule target_rule;
    target_rule.from_str(default_placement_str);
    if (!store->svc()->zone->get_zone_params().valid_placement(target_rule)) {
      ldout(s->cct, 0) << "NOTICE: invalid dest placement: " << target_rule.to_str() << dendl;
      http_ret = -EINVAL;
      return;
    }
    op_state.set_default_placement(target_rule);
  }

  if (!placement_tags_str.empty()) {
    list<string> placement_tags_list;
    get_str_list(placement_tags_str, ",", placement_tags_list);
    op_state.set_placement_tags(placement_tags_list);
  }

  if (s->info.args.exists("endpoint-type")) {
    RGWUserEndpoint user_endpoint(endp_type,
                                  endp_url,
                                  endp_tenant,
                                  endp_admin,
                                  endp_admin_pw,
                                  endp_admin_pw_path,
                                  endp_enabled);

    op_state.set_user_endpoint(user_endpoint);
  }

  if (!store->svc()->zone->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, nullptr, store, data, nullptr);
    if (op_ret < 0) {
      ldpp_dout(this, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }
  http_ret = RGWUserAdminOp_User::create(store, op_state, flusher);
}

class RGWOp_User_Modify : public RGWRESTOp {

public:
  RGWOp_User_Modify() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "modify_user"; }
};

void RGWOp_User_Modify::execute()
{
  std::string uid_str;
  std::string display_name;
  std::string email;
  std::string access_key;
  std::string secret_key;
  std::string key_type_str;
  std::string caps;
  std::string op_mask_str;
  std::string default_placement_str;
  std::string placement_tags_str;
  std::string endp_type, endp_url, endp_tenant;
  std::string endp_admin, endp_admin_pw, endp_admin_pw_path;

  bool endp_enabled;
  bool gen_key;
  bool suspended;
  bool system;
  bool email_set;
  bool quota_set;
  int32_t max_buckets;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "display-name", display_name, &display_name);
  RESTArgs::get_string(s, "email", email, &email, &email_set);
  RESTArgs::get_string(s, "access-key", access_key, &access_key);
  RESTArgs::get_string(s, "secret-key", secret_key, &secret_key);
  RESTArgs::get_string(s, "user-caps", caps, &caps);
  RESTArgs::get_bool(s, "generate-key", false, &gen_key);
  RESTArgs::get_bool(s, "suspended", false, &suspended);
  RESTArgs::get_int32(s, "max-buckets", RGW_DEFAULT_MAX_BUCKETS, &max_buckets, &quota_set);
  RESTArgs::get_string(s, "key-type", key_type_str, &key_type_str);

  RESTArgs::get_bool(s, "system", false, &system);
  RESTArgs::get_string(s, "op-mask", op_mask_str, &op_mask_str);
  RESTArgs::get_string(s, "default-placement", default_placement_str, &default_placement_str);
  RESTArgs::get_string(s, "placement-tags", placement_tags_str, &placement_tags_str);

  bool is_endp_type_exists, is_endp_url_exists, is_endp_tenant_exists;
  RESTArgs::get_string(s, "endpoint-type",   endp_type,   &endp_type,   &is_endp_type_exists);
  RESTArgs::get_string(s, "endpoint-url",    endp_url,    &endp_url,    &is_endp_url_exists);
  RESTArgs::get_string(s, "endpoint-tenant", endp_tenant, &endp_tenant, &is_endp_tenant_exists);

  bool is_endp_admin_user_exists, is_endp_admin_pw_exists, is_endp_admin_pw_path_exists;
  RESTArgs::get_string(s, "endpoint-admin", endp_admin, &endp_admin, &is_endp_admin_user_exists);
  RESTArgs::get_string(s, "endpoint-admin-passwd", endp_admin_pw, &endp_admin_pw, &is_endp_admin_pw_exists);
  RESTArgs::get_string(s, "endpoint-admin-passwd-path", endp_admin_pw_path, &endp_admin_pw_path, &is_endp_admin_pw_path_exists);

  bool is_endp_enabled_exists;
  RESTArgs::get_bool(s, "endpoint-enabled", true, &endp_enabled, &is_endp_enabled_exists);

  if (!s->user->get_info().system && system) {
    ldout(s->cct, 0) << "cannot set system flag by non-system user" << dendl;
    http_ret = -EINVAL;
    return;
  }

  op_state.set_user_id(uid);
  op_state.set_display_name(display_name);

  if (email_set)
    op_state.set_user_email(email);

  op_state.set_caps(caps);
  op_state.set_access_key(access_key);
  op_state.set_secret_key(secret_key);

  if (quota_set) {
    if (max_buckets < 0 ) {
      max_buckets = -1;
    }
    op_state.set_max_buckets(max_buckets);
  }
  if (gen_key)
    op_state.set_generate_key();

  if (!key_type_str.empty()) {
    int32_t key_type = KEY_TYPE_UNDEFINED;
    if (key_type_str.compare("swift") == 0)
      key_type = KEY_TYPE_SWIFT;
    else if (key_type_str.compare("s3") == 0)
      key_type = KEY_TYPE_S3;

    op_state.set_key_type(key_type);
  }

  if (!op_mask_str.empty()) {
    uint32_t op_mask;
    if (rgw_parse_op_type_list(op_mask_str, &op_mask) < 0) {
        ldout(s->cct, 0) << "failed to parse op_mask" << dendl;
        http_ret = -EINVAL;
        return;
    }
    op_state.set_op_mask(op_mask);
  }

  if (s->info.args.exists("suspended"))
    op_state.set_suspension(suspended);

  if (s->info.args.exists("system"))
    op_state.set_system(system);

  if (!op_mask_str.empty()) {
    uint32_t op_mask;
    int ret = rgw_parse_op_type_list(op_mask_str, &op_mask);
    if (ret < 0) {
      ldout(s->cct, 0) << "failed to parse op_mask: " << ret << dendl;
      http_ret = -EINVAL;
      return;
    }
    op_state.set_op_mask(op_mask);
  }

  if (!default_placement_str.empty()) {
    rgw_placement_rule target_rule;
    target_rule.from_str(default_placement_str);
    if (!store->svc()->zone->get_zone_params().valid_placement(target_rule)) {
      ldout(s->cct, 0) << "NOTICE: invalid dest placement: " << target_rule.to_str() << dendl;
      http_ret = -EINVAL;
      return;
    }
    op_state.set_default_placement(target_rule);
  }

  if (!placement_tags_str.empty()) {
    list<string> placement_tags_list;
    get_str_list(placement_tags_str, ",", placement_tags_list);
    op_state.set_placement_tags(placement_tags_list);
  }

  if (is_endp_type_exists) {
    if (is_endp_url_exists && endp_url.empty()) { endp_url = "-"; }
    if (is_endp_tenant_exists && endp_tenant.empty()) { endp_tenant = "-"; }
    if (is_endp_admin_user_exists && endp_admin.empty()) { endp_admin = "-"; }
    if (is_endp_admin_pw_exists && endp_admin_pw.empty()) { endp_admin_pw = "-"; }
    if (is_endp_admin_pw_path_exists && endp_admin_pw_path.empty()) { endp_admin_pw_path = "-"; }

    RGWUserEndpoint user_endpoint(endp_type,
                                  endp_url,
                                  endp_tenant,
                                  endp_admin,
                                  endp_admin_pw,
                                  endp_admin_pw_path,
                                  endp_enabled);

    op_state.set_user_endpoint(user_endpoint);

    op_state.endp_enabled_specified = is_endp_enabled_exists;
  }

  if (!store->svc()->zone->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, nullptr, store, data, nullptr);
    if (op_ret < 0) {
      ldpp_dout(this, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }
  http_ret = RGWUserAdminOp_User::modify(store, op_state, flusher);
}

class RGWOp_User_Remove : public RGWRESTOp {

public:
  RGWOp_User_Remove() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "remove_user"; }
};

void RGWOp_User_Remove::execute()
{
  std::string uid_str;
  bool purge_data;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_bool(s, "purge-data", false, &purge_data);

  // FIXME: no double checking
  if (!uid.empty())
    op_state.set_user_id(uid);

  op_state.set_purge_data(purge_data);

  if (!store->svc()->zone->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, nullptr, store, data, nullptr);
    if (op_ret < 0) {
      ldpp_dout(this, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }
  http_ret = RGWUserAdminOp_User::remove(store, op_state, flusher, s->yield);
}

class RGWOp_Subuser_Create : public RGWRESTOp {

public:
  RGWOp_Subuser_Create() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "create_subuser"; }
};

void RGWOp_Subuser_Create::execute()
{
  std::string uid_str;
  std::string subuser;
  std::string secret_key;
  std::string access_key;
  std::string perm_str;
  std::string key_type_str;

  bool gen_subuser = false; // FIXME placeholder
  bool gen_secret;
  bool gen_access;

  uint32_t perm_mask = 0;
  int32_t key_type = KEY_TYPE_SWIFT;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "subuser", subuser, &subuser);
  RESTArgs::get_string(s, "access-key", access_key, &access_key);
  RESTArgs::get_string(s, "secret-key", secret_key, &secret_key);
  RESTArgs::get_string(s, "access", perm_str, &perm_str);
  RESTArgs::get_string(s, "key-type", key_type_str, &key_type_str);
  //RESTArgs::get_bool(s, "generate-subuser", false, &gen_subuser);
  RESTArgs::get_bool(s, "generate-secret", false, &gen_secret);
  RESTArgs::get_bool(s, "gen-access-key", false, &gen_access);

  perm_mask = rgw_str_to_perm(perm_str.c_str());
  op_state.set_perm(perm_mask);

  op_state.set_user_id(uid);
  op_state.set_subuser(subuser);
  op_state.set_access_key(access_key);
  op_state.set_secret_key(secret_key);
  op_state.set_generate_subuser(gen_subuser);

  if (gen_access)
    op_state.set_gen_access();

  if (gen_secret)
    op_state.set_gen_secret();

  if (!key_type_str.empty()) {
    if (key_type_str.compare("swift") == 0)
      key_type = KEY_TYPE_SWIFT;
    else if (key_type_str.compare("s3") == 0)
      key_type = KEY_TYPE_S3;
  }
  op_state.set_key_type(key_type);

  if (!store->svc()->zone->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, nullptr, store, data, nullptr);
    if (op_ret < 0) {
      ldpp_dout(this, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }
  http_ret = RGWUserAdminOp_Subuser::create(store, op_state, flusher);
}

class RGWOp_Subuser_Modify : public RGWRESTOp {

public:
  RGWOp_Subuser_Modify() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "modify_subuser"; }
};

void RGWOp_Subuser_Modify::execute()
{
  std::string uid_str;
  std::string subuser;
  std::string secret_key;
  std::string key_type_str;
  std::string perm_str;

  RGWUserAdminOpState op_state;

  uint32_t perm_mask;
  int32_t key_type = KEY_TYPE_SWIFT;

  bool gen_secret;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "subuser", subuser, &subuser);
  RESTArgs::get_string(s, "secret-key", secret_key, &secret_key);
  RESTArgs::get_string(s, "access", perm_str, &perm_str);
  RESTArgs::get_string(s, "key-type", key_type_str, &key_type_str);
  RESTArgs::get_bool(s, "generate-secret", false, &gen_secret);

  perm_mask = rgw_str_to_perm(perm_str.c_str());
  op_state.set_perm(perm_mask);

  op_state.set_user_id(uid);
  op_state.set_subuser(subuser);

  if (!secret_key.empty())
    op_state.set_secret_key(secret_key);

  if (gen_secret)
    op_state.set_gen_secret();

  if (!key_type_str.empty()) {
    if (key_type_str.compare("swift") == 0)
      key_type = KEY_TYPE_SWIFT;
    else if (key_type_str.compare("s3") == 0)
      key_type = KEY_TYPE_S3;
  }
  op_state.set_key_type(key_type);

  if (!store->svc()->zone->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, nullptr, store, data, nullptr);
    if (op_ret < 0) {
      ldpp_dout(this, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }
  http_ret = RGWUserAdminOp_Subuser::modify(store, op_state, flusher);
}

class RGWOp_Subuser_Remove : public RGWRESTOp {

public:
  RGWOp_Subuser_Remove() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "remove_subuser"; }
};

void RGWOp_Subuser_Remove::execute()
{
  std::string uid_str;
  std::string subuser;
  bool purge_keys;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "subuser", subuser, &subuser);
  RESTArgs::get_bool(s, "purge-keys", true, &purge_keys);

  op_state.set_user_id(uid);
  op_state.set_subuser(subuser);

  if (purge_keys)
    op_state.set_purge_keys();

  if (!store->svc()->zone->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, nullptr, store, data, nullptr);
    if (op_ret < 0) {
      ldpp_dout(this, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }
  http_ret = RGWUserAdminOp_Subuser::remove(store, op_state, flusher);
}

class RGWOp_Key_Create : public RGWRESTOp {

public:
  RGWOp_Key_Create() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "create_access_key"; }
};

void RGWOp_Key_Create::execute()
{
  std::string uid_str;
  std::string subuser;
  std::string access_key;
  std::string secret_key;
  std::string key_type_str;

  bool gen_key;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "subuser", subuser, &subuser);
  RESTArgs::get_string(s, "access-key", access_key, &access_key);
  RESTArgs::get_string(s, "secret-key", secret_key, &secret_key);
  RESTArgs::get_string(s, "key-type", key_type_str, &key_type_str);
  RESTArgs::get_bool(s, "generate-key", true, &gen_key);

  op_state.set_user_id(uid);
  op_state.set_subuser(subuser);
  op_state.set_access_key(access_key);
  op_state.set_secret_key(secret_key);

  if (gen_key)
    op_state.set_generate_key();

  if (!key_type_str.empty()) {
    int32_t key_type = KEY_TYPE_UNDEFINED;
    if (key_type_str.compare("swift") == 0)
      key_type = KEY_TYPE_SWIFT;
    else if (key_type_str.compare("s3") == 0)
      key_type = KEY_TYPE_S3;

    op_state.set_key_type(key_type);
  }

  http_ret = RGWUserAdminOp_Key::create(store, op_state, flusher);
}

class RGWOp_Key_Remove : public RGWRESTOp {

public:
  RGWOp_Key_Remove() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "remove_access_key"; }
};

void RGWOp_Key_Remove::execute()
{
  std::string uid_str;
  std::string subuser;
  std::string access_key;
  std::string key_type_str;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "subuser", subuser, &subuser);
  RESTArgs::get_string(s, "access-key", access_key, &access_key);
  RESTArgs::get_string(s, "key-type", key_type_str, &key_type_str);

  op_state.set_user_id(uid);
  op_state.set_subuser(subuser);
  op_state.set_access_key(access_key);

  if (!key_type_str.empty()) {
    int32_t key_type = KEY_TYPE_UNDEFINED;
    if (key_type_str.compare("swift") == 0)
      key_type = KEY_TYPE_SWIFT;
    else if (key_type_str.compare("s3") == 0)
      key_type = KEY_TYPE_S3;

    op_state.set_key_type(key_type);
  }

  http_ret = RGWUserAdminOp_Key::remove(store, op_state, flusher);
}

class RGWOp_Caps_Add : public RGWRESTOp {

public:
  RGWOp_Caps_Add() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "add_user_caps"; }
};

void RGWOp_Caps_Add::execute()
{
  std::string uid_str;
  std::string caps;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "user-caps", caps, &caps);

  op_state.set_user_id(uid);
  op_state.set_caps(caps);

  if (!store->svc()->zone->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, nullptr, store, data, nullptr);
    if (op_ret < 0) {
      ldpp_dout(this, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }
  http_ret = RGWUserAdminOp_Caps::add(store, op_state, flusher);
}

class RGWOp_Caps_Remove : public RGWRESTOp {

public:
  RGWOp_Caps_Remove() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "remove_user_caps"; }
};

void RGWOp_Caps_Remove::execute()
{
  std::string uid_str;
  std::string caps;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "user-caps", caps, &caps);

  op_state.set_user_id(uid);
  op_state.set_caps(caps);

  if (!store->svc()->zone->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, nullptr, store, data, nullptr);
    if (op_ret < 0) {
      ldpp_dout(this, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }
  http_ret = RGWUserAdminOp_Caps::remove(store, op_state, flusher);
}

struct UserQuotas {
  RGWQuotaInfo bucket_quota;
  RGWQuotaInfo user_quota;

  UserQuotas() {}

  explicit UserQuotas(RGWUserInfo& info) : bucket_quota(info.bucket_quota),
				  user_quota(info.user_quota) {}

  void dump(Formatter *f) const {
    encode_json("bucket_quota", bucket_quota, f);
    encode_json("user_quota", user_quota, f);
  }
  void decode_json(JSONObj *obj) {
    JSONDecoder::decode_json("bucket_quota", bucket_quota, obj);
    JSONDecoder::decode_json("user_quota", user_quota, obj);
  }
};

class RGWOp_Quota_Info : public RGWRESTOp {

public:
  RGWOp_Quota_Info() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_READ);
  }

  void execute() override;

  const char* name() const override { return "get_quota_info"; }
};


void RGWOp_Quota_Info::execute()
{
  RGWUserAdminOpState op_state;

  std::string uid_str;
  std::string quota_type;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  RESTArgs::get_string(s, "quota-type", quota_type, &quota_type);

  if (uid_str.empty()) {
    http_ret = -EINVAL;
    return;
  }

  rgw_user uid(uid_str);

  bool show_all = quota_type.empty();
  bool show_bucket = show_all || (quota_type == "bucket");
  bool show_user = show_all || (quota_type == "user");

  if (!(show_all || show_bucket || show_user)) {
    http_ret = -EINVAL;
    return;
  }

  op_state.set_user_id(uid);

  RGWUser user;
  http_ret = user.init(store, op_state);
  if (http_ret < 0)
    return;

  if (!op_state.has_existing_user()) {
    http_ret = -ERR_NO_SUCH_USER;
    return;
  }

  RGWUserInfo info;
  string err_msg;
  http_ret = user.info(info, &err_msg);
  if (http_ret < 0)
    return;

  flusher.start(0);
  if (show_all) {
    UserQuotas quotas(info);
    encode_json("quota", quotas, s->formatter);
  } else if (show_user) {
    encode_json("user_quota", info.user_quota, s->formatter);
  } else {
    encode_json("bucket_quota", info.bucket_quota, s->formatter);
  }

  flusher.flush();
}

class RGWOp_Quota_Set : public RGWRESTOp {

public:
  RGWOp_Quota_Set() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "set_quota_info"; }
};

/**
 * set quota
 *
 * two different ways to set the quota info: as json struct in the message body or via http params.
 *
 * as json:
 *
 * PUT /admin/user?uid=<uid>[&quota-type=<type>]
 *
 * whereas quota-type is optional and is either user, or bucket
 *
 * if quota-type is not specified then we expect to get a structure that contains both quotas,
 * otherwise we'll only get the relevant configuration.
 *
 * E.g., if quota type not specified:
 * {
 *    "user_quota" : {
 *      "max_size_kb" : 4096,
 *      "max_objects" : -1,
 *      "enabled" : false
 *    },
 *    "bucket_quota" : {
 *      "max_size_kb" : 1024,
 *      "max_objects" : -1,
 *      "enabled" : true
 *    }
 * }
 *
 *
 * or if quota type is specified:
 * {
 *   "max_size_kb" : 4096,
 *   "max_objects" : -1,
 *   "enabled" : false
 * }
 *
 * Another option is not to pass any body and set the following http params:
 *
 *
 * max-size-kb=<size>
 * max-objects=<max objects>
 * enabled[={true,false}]
 *
 * all params are optionals and default to the current settings. With this type of configuration the
 * quota-type param is mandatory.
 *
 */

void RGWOp_Quota_Set::execute()
{
  RGWUserAdminOpState op_state;

  std::string uid_str;
  std::string quota_type;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  RESTArgs::get_string(s, "quota-type", quota_type, &quota_type);

  if (uid_str.empty()) {
    http_ret = -EINVAL;
    return;
  }

  rgw_user uid(uid_str);

  bool set_all = quota_type.empty();
  bool set_bucket = set_all || (quota_type == "bucket");
  bool set_user = set_all || (quota_type == "user");

  if (!(set_all || set_bucket || set_user)) {
    ldout(store->ctx(), 20) << "invalid quota type" << dendl;
    http_ret = -EINVAL;
    return;
  }

  bool use_http_params;

  if (s->content_length > 0) {
    use_http_params = false;
  } else {
    const char *encoding = s->info.env->get("HTTP_TRANSFER_ENCODING");
    use_http_params = (!encoding || strcmp(encoding, "chunked") != 0);
  }

  if (use_http_params && set_all) {
    ldout(store->ctx(), 20) << "quota type was not specified, can't set all quotas via http headers" << dendl;
    http_ret = -EINVAL;
    return;
  }

  op_state.set_user_id(uid);

  RGWUser user;
  http_ret = user.init(store, op_state);
  if (http_ret < 0) {
    ldout(store->ctx(), 20) << "failed initializing user info: " << http_ret << dendl;
    return;
  }

  if (!op_state.has_existing_user()) {
    http_ret = -ERR_NO_SUCH_USER;
    return;
  }

#define QUOTA_INPUT_MAX_LEN 1024
  if (set_all) {
    UserQuotas quotas;

    if ((http_ret = rgw_rest_get_json_input(store->ctx(), s, quotas, QUOTA_INPUT_MAX_LEN, NULL)) < 0) {
      ldout(store->ctx(), 20) << "failed to retrieve input" << dendl;
      return;
    }

    op_state.set_user_quota(quotas.user_quota);
    op_state.set_bucket_quota(quotas.bucket_quota);
  } else {
    RGWQuotaInfo quota;

    if (!use_http_params) {
      bool empty;
      http_ret = rgw_rest_get_json_input(store->ctx(), s, quota, QUOTA_INPUT_MAX_LEN, &empty);
      if (http_ret < 0) {
        ldout(store->ctx(), 20) << "failed to retrieve input" << dendl;
        if (!empty)
          return;

        /* was probably chunked input, but no content provided, configure via http params */
        use_http_params = true;
      }
    }

    if (use_http_params) {
      RGWUserInfo info;
      string err_msg;
      http_ret = user.info(info, &err_msg);
      if (http_ret < 0) {
        ldout(store->ctx(), 20) << "failed to get user info: " << http_ret << dendl;
        return;
      }
      RGWQuotaInfo *old_quota;
      if (set_user) {
        old_quota = &info.user_quota;
      } else {
        old_quota = &info.bucket_quota;
      }

      RESTArgs::get_int64(s, "max-objects", old_quota->max_objects, &quota.max_objects);
      RESTArgs::get_int64(s, "max-size", old_quota->max_size, &quota.max_size);
      int64_t max_size_kb;
      bool has_max_size_kb = false;
      RESTArgs::get_int64(s, "max-size-kb", 0, &max_size_kb, &has_max_size_kb);
      if (has_max_size_kb) {
        quota.max_size = max_size_kb * 1024;
      }
      RESTArgs::get_bool(s, "enabled", old_quota->enabled, &quota.enabled);
    }

    if (set_user) {
      op_state.set_user_quota(quota);
    } else {
      op_state.set_bucket_quota(quota);
    }
  }

  string err;
  http_ret = user.modify(op_state, &err);
  if (http_ret < 0) {
    ldout(store->ctx(), 20) << "failed updating user info: " << http_ret << ": " << err << dendl;
    return;
  }
}

class RGWOp_Endpoint_Create : public RGWRESTOp {

public:
  RGWOp_Endpoint_Create() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "create_endpoint"; }
};

void RGWOp_Endpoint_Create::execute()
{
  std::string uid_str;
  std::string endp_type, endp_url, endp_tenant;
  std::string endp_admin, endp_admin_pw, endp_admin_pw_path;

  bool endp_enabled;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "endpoint-type", endp_type, &endp_type);
  RESTArgs::get_string(s, "endpoint-url",  endp_url,  &endp_url);
  RESTArgs::get_string(s, "endpoint-tenant",  "nes",  &endp_tenant);

  RESTArgs::get_string(s, "endpoint-admin",  endp_admin, &endp_admin);
  RESTArgs::get_string(s, "endpoint-admin-passwd",  endp_admin_pw, &endp_admin_pw);
  RESTArgs::get_string(s, "endpoint-admin-passwd-path",  endp_admin_pw_path, &endp_admin_pw_path);

  RESTArgs::get_bool(s, "endpoint-enabled", true, &endp_enabled);

  op_state.set_user_id(uid);
  RGWUserEndpoint user_endpoint(endp_type,
                                endp_url,
                                endp_tenant,
                                endp_admin,
                                endp_admin_pw,
                                endp_admin_pw_path,
                                endp_enabled);

  op_state.set_user_endpoint(user_endpoint);

  http_ret = RGWUserAdminOp_Endpoint::create(store, op_state, flusher);
}

class RGWOp_Endpoint_Modify : public RGWRESTOp {

public:
  RGWOp_Endpoint_Modify() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "modify_endpoint"; }
};

void RGWOp_Endpoint_Modify::execute()
{
  std::string uid_str;
  std::string endp_type, endp_url, endp_tenant;
  std::string endp_admin, endp_admin_pw, endp_admin_pw_path;

  bool endp_enabled;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  bool is_endp_type_exists, is_endp_url_exists, is_endp_tenant_exists;
  RESTArgs::get_string(s, "endpoint-type",   endp_type,   &endp_type,   &is_endp_type_exists);
  RESTArgs::get_string(s, "endpoint-url",    endp_url,    &endp_url,    &is_endp_url_exists);
  RESTArgs::get_string(s, "endpoint-tenant", endp_tenant, &endp_tenant, &is_endp_tenant_exists);

  bool is_endp_admin_user_exists, is_endp_admin_pw_exists, is_endp_admin_pw_path_exists;
  RESTArgs::get_string(s, "endpoint-admin", endp_admin, &endp_admin, &is_endp_admin_user_exists);
  RESTArgs::get_string(s, "endpoint-admin-passwd", endp_admin_pw, &endp_admin_pw, &is_endp_admin_pw_exists);
  RESTArgs::get_string(s, "endpoint-admin-passwd-path", endp_admin_pw_path, &endp_admin_pw_path, &is_endp_admin_pw_path_exists);

  bool is_endp_enabled_exists;
  RESTArgs::get_bool(s, "endpoint-enabled", true, &endp_enabled, &is_endp_enabled_exists);

  op_state.set_user_id(uid);

  if (is_endp_type_exists) {
    if (is_endp_url_exists           && endp_url.empty()) { endp_url = "-"; }
    if (is_endp_tenant_exists        && endp_tenant.empty()) { endp_tenant = "-"; }
    if (is_endp_admin_user_exists    && endp_admin.empty()) { endp_admin = "-"; }
    if (is_endp_admin_pw_exists      && endp_admin_pw.empty()) { endp_admin_pw = "-"; }
    if (is_endp_admin_pw_path_exists && endp_admin_pw_path.empty()) { endp_admin_pw_path = "-"; }

    RGWUserEndpoint user_endpoint(endp_type,
                                  endp_url,
                                  endp_tenant,
                                  endp_admin,
                                  endp_admin_pw,
                                  endp_admin_pw_path,
                                  endp_enabled);

    op_state.set_user_endpoint(user_endpoint);

    op_state.endp_enabled_specified = is_endp_enabled_exists;
  }

  http_ret = RGWUserAdminOp_Endpoint::modify(store, op_state, flusher);
}

class RGWOp_Endpoint_Remove : public RGWRESTOp {

public:
  RGWOp_Endpoint_Remove() {}

  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("users", RGW_CAP_WRITE);
  }

  void execute() override;

  const char* name() const override { return "remove_endpoint"; }
};

void RGWOp_Endpoint_Remove::execute()
{
  std::string uid_str;
  std::string endp_type;

  RGWUserAdminOpState op_state;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_string(s, "endpoint-type", endp_type, &endp_type);

  op_state.set_user_id(uid);
  op_state.user_endpoint.type = endp_type;

  http_ret = RGWUserAdminOp_Endpoint::remove(store, op_state, flusher);
}

RGWOp *RGWHandler_User::op_get()
{
  if (s->info.args.sub_resource_exists("quota"))
    return new RGWOp_Quota_Info;

  if (s->info.args.sub_resource_exists("list"))
    return new RGWOp_User_List;

  return new RGWOp_User_Info;
}

RGWOp *RGWHandler_User::op_put()
{
  if (s->info.args.sub_resource_exists("subuser"))
    return new RGWOp_Subuser_Create;

  if (s->info.args.sub_resource_exists("key"))
    return new RGWOp_Key_Create;

  if (s->info.args.sub_resource_exists("caps"))
    return new RGWOp_Caps_Add;

  if (s->info.args.sub_resource_exists("quota"))
    return new RGWOp_Quota_Set;

  if (s->info.args.sub_resource_exists("endpoint"))
    return new RGWOp_Endpoint_Create;

  return new RGWOp_User_Create;
}

RGWOp *RGWHandler_User::op_post()
{
  if (s->info.args.sub_resource_exists("subuser"))
    return new RGWOp_Subuser_Modify;

 if (s->info.args.sub_resource_exists("endpoint"))
    return new RGWOp_Endpoint_Modify;

  return new RGWOp_User_Modify;
}

RGWOp *RGWHandler_User::op_delete()
{
  if (s->info.args.sub_resource_exists("subuser"))
    return new RGWOp_Subuser_Remove;

  if (s->info.args.sub_resource_exists("key"))
    return new RGWOp_Key_Remove;

  if (s->info.args.sub_resource_exists("caps"))
    return new RGWOp_Caps_Remove;

  if (s->info.args.sub_resource_exists("endpoint"))
    return new RGWOp_Endpoint_Remove;

  return new RGWOp_User_Remove;
}

