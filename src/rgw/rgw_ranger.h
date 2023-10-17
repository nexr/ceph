#ifndef RGW_RANGER_H
#define RGW_RANGER_H

#include "rgw_common.h"
#include "rgw_op.h"
#include "rgw_http_client.h"

#include <jni.h>
#include <regex>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

class RGWRangerManager {
protected:
  CephContext* cct;
  void trim_path(string& path);

  bool is_file_exist(string file) {
    struct stat f_stat;
    return (stat(file.c_str(), &f_stat) == 0);
  };

  time_t get_file_age(string file) {
    struct stat f_stat;

    if (stat(file.c_str(), &f_stat) != 0) { return -1; }

    time_t mtime = f_stat.st_mtime;
    time_t ctime = time(NULL);

    return ctime - mtime;
  }

  bool is_file_age_older(string file, time_t age) {
    time_t file_age = get_file_age(file);

    if (file_age < 0) { return false; }

    return (file_age > age);
  }

  bool is_file_age_younger(string file, time_t age) {
    time_t file_age = get_file_age(file);

    if (file_age < 0) { return false; }

    return (file_age <= age);
  }

  bool is_connection_ok(RGWUserEndpoint endpoint) {
    bufferlist tmp;
    RGWHTTPTransceiver req(cct, "GET", endpoint.url.c_str(), &tmp);

    // check if we want to verify Ranger server SSL certificate
    req.set_verify_ssl(endpoint.use_ssl);

    // send request
    req.process(null_yield);

    // if connection failed, http_status code is 0
    if (req.get_http_status() != 0) {
      return true;
    }
    else {
      ldout(cct, 5) << "There is no connection to " << endpoint.url << dendl;
      return false;
    }
  }

  bool ts_map_clipping = false;
  int  ts_map_size = 1024;
  map<string, time_t> svc_read_ts_map;
  bool use_cached_one;

  void clip_svc_read_ts_map() {
    ldout(cct, 15) << __func__ << "(): start to clip svc_read_ts_map" << dendl;

    ts_map_clipping = true;

    time_t current = time(NULL);
    map<string, time_t>::iterator iter = svc_read_ts_map.begin();
    for (; iter != svc_read_ts_map.end();) {
      time_t each_ts = iter->second;
      if (current - each_ts < cache_update_interval) {
        iter++;
      }
      else {
        iter = svc_read_ts_map.erase(iter);
      }
    }

    ts_map_clipping = false;
  }

  void set_svc_read_ts(string service) {
    if ((int) svc_read_ts_map.size() > ts_map_size * 3/4) {
      clip_svc_read_ts_map();
    }

    svc_read_ts_map[service] = time(NULL);
  }

  time_t get_svc_read_ts(string service) {
    if (ts_map_clipping) { return 0; }

    return svc_read_ts_map[service];
  }

  bool can_i_use_cached_policy(string service) {
    time_t ts = get_svc_read_ts(service);

    if (ts == 0) { return false; }

    time_t current = time(NULL);
    return (current - ts < cache_update_interval);
  }

  string policy_cache_dir;
  time_t cache_update_interval;
  // cache_update
  std::mutex cu_mutex;

  string change_owner_to_svc_name(string owner_name) {
    string svc_name = owner_name;
    svc_name = regex_replace(svc_name, regex("@"), "_at_");
    svc_name = regex_replace(svc_name, regex("\\."), "_dot_");
    ldout(cct, 20) << __func__ << "(): owner '" << owner_name << "' refers the '" << svc_name << "' ranger service" << dendl;
    return svc_name;
  }

public:
  RGWRangerManager(CephContext* const _cct) : cct(_cct) {
    use_cached_one = cct->_conf->rgw_ranger_use_cached_one_if_not_cache_updating;

    policy_cache_dir = cct->_conf->rgw_ranger_cache_dir;
    trim_path(policy_cache_dir);

    cache_update_interval = cct->_conf->rgw_ranger_cache_update_interval;
  };
  virtual ~RGWRangerManager(){};

  virtual int is_access_allowed(RGWUserEndpoint endp, RGWOp *& op, req_state * const s) = 0;
};
extern RGWRangerManager* rgw_rm;

inline void RGWRangerManager::trim_path(string& path) {
  int path_len = path.length();
  if ( path.rfind("/") == size_t(path_len-1) ) {
    path = path.substr(0, path_len-1);
  }
}

typedef struct {
  int id;
  bool isEnabled;
  vector<string> paths;
  bool isRecursive;
  bool isExcludes;
  struct item {
    bool read_checked;
    bool write_checked;
    vector<string> users;
    vector<string> groups;
    struct condition {
      string type;
      vector<string> cidrs;
    };
    vector<condition> conditions;
  };
  vector<item> allow_policies;
  vector<item> allow_exceptions;
  vector<item> deny_policies;
  vector<item> deny_exceptions;
} ranger_policy;

class RGWRangerNativeManager : RGWRangerManager {
private:
  bool cached_mode;

  bool parse_policy_items(vector<ranger_policy::item>& out, vector<string> policy_items);
  bool parse_policy(ranger_policy& out, string& policy_str);
  bool is_policy_related(req_state * const s, ranger_policy& policy);
  bool is_item_related(req_state * const s, ranger_policy::item& policy_item, string tenant_group = "");
  bool is_authz_allowed(uint32_t op_mask, req_state * const s, ranger_policy& policy, string tenant_group = "");
  bool is_authz_denied(uint32_t op_mask, req_state * const s, ranger_policy& policy, string tenant_group = "");

  int get_related_policies(vector<ranger_policy>& ret_vec, RGWUserEndpoint endpoint, req_state * const s, string service);
  int get_related_policies_from_remote(vector<ranger_policy>& ret_vec, RGWUserEndpoint endpoint, req_state * const s, string service);
  int get_related_policies_from_cache(vector<ranger_policy>& ret_vec, req_state * const s, string service);

public:
  RGWRangerNativeManager(CephContext* const _cct, bool _cached_mode = false) : RGWRangerManager(_cct), cached_mode(_cached_mode) {};
  ~RGWRangerNativeManager() {};

  int is_access_allowed(RGWUserEndpoint endpoint, RGWOp *& op, req_state * const s) override;
};

extern RGWRangerNativeManager* rgw_rnm;

class RGWRangerJniManager;

class RGWRangerJniThread : public Thread {
  friend RGWRangerJniManager;

private:
  CephContext* cct;

  RGWRangerJniManager* parent;

  bool reserved;
  int result;

  void * entry() override;

protected:
  // entry
  std::mutex e_mutex;
  std::condition_variable e_cond;

  // main function
  std::mutex f_mutex;
  std::condition_variable f_cond;

  // reserve
  std::mutex r_mutex;
  std::condition_variable r_cond;

  // audit_config
  std::mutex ac_mutex;

public:
  bool down_flag = false;

  string service;
  string url;
  string path;
  string access_type;
  string user;
  string group;

  vector<string> addr_trace;

  string audit_url;
  bool audit_service_specific;

  RGWRangerJniThread(CephContext* const _cct, RGWRangerJniManager* parent);

  bool reserve();

  bool is_down() { return down_flag; }
  bool is_reserved() { return reserved; }
  int get_result() { return result; }

  bool config_audit();

  int is_access_allowed();

  void organize_cached_policy();
};

class RGWRangerJniManager : RGWRangerManager {
  friend RGWRangerJniThread;

private:
  string thread_name_prefix = "ranger_jni";

  int thread_pool_size;
  RGWRangerJniThread** threads;

  rgw::sal::RGWRadosStore * store;

protected:
  string app_id;

  JavaVM *jvm;

  JavaVMInitArgs vm_args;

  jclass jcls;

  jmethodID constructor_mid;
  jmethodID isAccessAllowed_mid;

  string jni_config_dir;
  time_t audit_conf_age;

public:
  RGWRangerJniManager(CephContext* const _cct,  rgw::sal::RGWRadosStore* const store, bool start_vm = false);
  ~RGWRangerJniManager();

  void start_thread();
  void stop_thread();

  int start_jvm();
  void stop_jvm();
  int is_access_allowed(RGWUserEndpoint endp, RGWOp *& op, req_state * const s) override;
};


extern RGWRangerJniManager* rgw_rjm;

void init_global_ranger_manager(CephContext* const cct, rgw::sal::RGWRadosStore* store);
void destroy_global_ranger_manager();

int rgw_ranger_authorize(rgw::sal::RGWRadosStore* store, RGWOp*& op, req_state* s);

void prepare_cache_dir(CephContext* const cct);

#endif /* RGW_RANGER_H */
