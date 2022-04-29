#ifndef RGW_RANGER_H
#define RGW_RANGER_H

#include "rgw_common.h"
#include "rgw_op.h"

#include <jni.h>

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
    req.process();

    // if connection failed, http_status code is 0
    if (req.get_http_status() != 0) {
      return true;
    }
    else {
      ldout(cct, 5) << "There is no connection to " << endpoint.url << dendl;
      return false;
    }
  }

  string policy_cache_dir;
  time_t cache_update_interval;

public:
  RGWRangerManager(CephContext* const _cct) : cct(_cct) {
    policy_cache_dir = cct->_conf->rgw_ranger_cache_dir;
    trim_path(policy_cache_dir);

    cache_update_interval = cct->_conf->rgw_ranger_cache_update_interval;
  };
  virtual ~RGWRangerManager(){};

  virtual int is_access_allowed(RGWUserEndpoint endp, RGWOp *& op, req_state * const s) = 0;
};

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

  bool ts_map_clipping = false;
  int  ts_map_size = 1024;
  map<string, time_t> svc_read_ts_map;

  void clip_svc_read_ts_map();

  void   set_svc_read_ts(string service);
  time_t get_svc_read_ts(string service);

  bool can_i_use_cached_policy(string service);

  RGWRados* store;

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
  RGWRangerJniManager(CephContext* const _cct, RGWRados* const _store, bool start_vm = false);
  ~RGWRangerJniManager();

  void start_thread();
  void stop_thread();

  int start_jvm();
  void stop_jvm();
  int is_access_allowed(RGWUserEndpoint endp, RGWOp *& op, req_state * const s) override;
};


extern RGWRangerJniManager* rgw_rjm;
void init_global_ranger_jni_manager(CephContext* const cct, RGWRados* store, bool start_vm = false);
void destroy_global_ranger_jni_manager();

/* authorize request using Ranger */
int rgw_ranger_authorize(RGWRados* store, RGWOp*& op, req_state* s);

void prepare_cache_dir(CephContext* const cct);

#endif /* RGW_RANGER_H */
