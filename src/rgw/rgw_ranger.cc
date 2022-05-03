#include "rgw_ranger.h"
#include "rgw_user.h"

#include <dirent.h>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

RGWRangerManager* rgw_rm = nullptr;

void init_global_ranger_manager(CephContext* const cct, RGWRados* store) {
  if (rgw_rm != nullptr) { return; }

  string ranger_engine = cct->_conf->rgw_ranger_engine;

  if (ranger_engine == "jni") {
    ldout(cct, 10) << __func__ << "(): Init global RGWRangerJniManager instance" << dendl;
    rgw_rjm = new RGWRangerJniManager(cct, store, true);
    rgw_rm  = (RGWRangerManager*) rgw_rjm;
  }
  else if (ranger_engine == "native") {
    ldout(cct, 10) << __func__ << "(): Init global RGWRangerNativeManager instance" << dendl;
    rgw_rnm = new RGWRangerNativeManager(cct);
    rgw_rm  = (RGWRangerManager*) rgw_rnm;
  }
};

void destroy_global_ranger_manager() {
  if (rgw_rm == nullptr) { return; }

  delete rgw_rm;
};

bool get_ranger_endpoint(RGWUserEndpoint& out, RGWRados* store, req_state * const s) {
  RGWUserInfo owner_info;
  rgw_user bucket_owner = s->bucket_owner.get_id();

  int ret = rgw_get_user_info_by_uid(store, bucket_owner, owner_info, NULL, NULL, NULL);
  if (ret < 0) { return ret; }

  RGWUserEndpoints* user_endps = &(owner_info.endpoints);

  RGWUserEndpoint* ranger_endp = user_endps->get("ranger");
  if (ranger_endp != nullptr && ranger_endp->enabled) {
    out = *ranger_endp;
  }
  else {
    out.url = s->cct->_conf->rgw_ranger_url;
    if (out.url == "") {
      dout(2) << __func__ << "(): RNAGER_URL not provided" << dendl;
      return false;
    }

    out.use_ssl = s->cct->_conf->rgw_ranger_verify_ssl;

    out.admin_user = s->cct->_conf->rgw_ranger_admin_user;

    out.admin_passwd = s->cct->_conf->rgw_ranger_admin_password;
    out.admin_passwd_path = s->cct->_conf->rgw_ranger_admin_password_path;

    out.tenant = s->cct->_conf->rgw_ranger_tenant;

    out.enabled = true;
  }

  return true;
}

int rgw_ranger_authorize(RGWRados* store, RGWOp *& op, req_state * const s)
{
  // check wheter ranger authorize is needed or not
  const string bucket_owner = s->bucket_owner.get_id().to_str();
  if (bucket_owner == "") {
    ldpp_dout(op, 5) << __func__ << "(): The ranger authorizing is not needed. Skip the steps." << dendl;
    return 0;
  }

  ldpp_dout(op, 5) << __func__ << "(): authorizing request using Ranger" << dendl;

  RGWUserEndpoint endpoint;
  if (!get_ranger_endpoint(endpoint, store, s)) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to parse ranger endpoint of " << bucket_owner << dendl;
    return -ERR_INVALID_REQUEST;
  }

  if (rgw_rm == NULL) {
    return -ERR_INTERNAL_ERROR;
  }

  int ret = rgw_rm->is_access_allowed(endpoint, op, s);

  if (ret == 0) {
    ldpp_dout(op, 2) << __func__ << "(): Ranger accepting request" << dendl;
  }
  else if (ret == -EPERM) {
    ldpp_dout(op, 2) << __func__ << "(): Ranger rejecting request because any allow policy is not exist" << dendl;
  }

  return ret;
}

void prepare_cache_dir(CephContext* const cct) {
  string ranger_cache_dir = cct->_conf->rgw_ranger_cache_dir.c_str();
  int dir_len = ranger_cache_dir.length();
  if (ranger_cache_dir.rfind("/") == size_t(dir_len - 1)) {
    ranger_cache_dir = ranger_cache_dir.substr(0, dir_len-1);
  }

  dout(20) << __func__ << "ranger cache dir: " << ranger_cache_dir << dendl;

  struct stat f_stat;
  if (stat(ranger_cache_dir.c_str(), &f_stat) != 0) {
    if (mkdir(ranger_cache_dir.c_str(), 0755) == -1) {
      chown(ranger_cache_dir.c_str(), cct->get_set_uid(), cct->get_set_gid());
    }
    else {
      derr << __func__ << "(): Failed to create " << ranger_cache_dir
                       << " (error = " << strerror(errno) << ")" << dendl;
    }
  }

  int ranger_cache_age = cct->_conf->rgw_ranger_cache_age;

  if (ranger_cache_age == 0) {
    dout(5) << __func__ << "(): The 'rgw_ranger_cache_age' is 0. "
                        << "Skip ranger cache eviction." << dendl;
    return;
  }

  DIR* dir = opendir(ranger_cache_dir.c_str());
  if (dir == NULL) {
    derr << __func__ << "(): Failed to open directory '" << ranger_cache_dir << "' "
                     << "(error = " << strerror(errno) << ")" << dendl;
    return;
  }

  time_t current = time(NULL);

  struct dirent* dir_entry = readdir(dir);
  for (; dir_entry != NULL; dir_entry = readdir(dir)) {
    string entry_name = dir_entry->d_name;

    if (entry_name.rfind(".json") != size_t(entry_name.length() -1 -5)) { continue; }

    string entry_path = ranger_cache_dir + "/" + entry_name;

    struct stat e_stat;
    stat(entry_path.c_str(), &e_stat);

    time_t last_modified = e_stat.st_mtime;

    if (current - last_modified > ranger_cache_age) {
      dout(10) << __func__ << "(): Remove cached policy because of expiration "
                           << "(cached file = " << entry_path << ")" << dendl;
      std::remove(entry_path.c_str());
    }
  }

  closedir(dir);

  return;
}
