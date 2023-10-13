#include "rgw_ranger.h"

#include <unistd.h>
#include <time.h>
#include <fstream>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

RGWRangerJniManager* rgw_rjm = nullptr;

RGWRangerJniManager::RGWRangerJniManager(CephContext* const _cct, rgw::sal::RGWRadosStore* const _store, bool start_vm): RGWRangerManager(_cct), store(_store) {
  jni_config_dir = cct->_conf->rgw_ranger_jni_config_dir;
  trim_path(jni_config_dir);
  dout(10) << __func__ << "(): ranger jni config dir = " << jni_config_dir << dendl;

  audit_conf_age = cct->_conf->rgw_ranger_audit_config_age;

  app_id = cct->_conf->name.to_str();

  struct stat f_stat;
  if (stat(jni_config_dir.c_str(), &f_stat) != 0) {
    if (mkdir(jni_config_dir.c_str(), 0755) != -1) {
      chown(jni_config_dir.c_str(), cct->get_set_uid(), cct->get_set_gid());
    }
    else {
      derr << __func__ << "(): Failed to create " << jni_config_dir
                       << " (error = " << strerror(errno) << ")" << dendl;
    }
  }

  // make configurable
  string jvm_class_path_opt = "";
  jvm_class_path_opt  = "-Djava.class.path=";
  jvm_class_path_opt += jni_config_dir;
  jvm_class_path_opt += ":";
  jvm_class_path_opt += cct->_conf->rgw_ranger_jni_engine_jar;

  JavaVMOption jvmopt[1];
  jvmopt[0].optionString = (char*) jvm_class_path_opt.c_str();

  JNI_GetDefaultJavaVMInitArgs(&vm_args);
  vm_args.version = JNI_VERSION_1_8;
  vm_args.nOptions = 1;
  vm_args.options = jvmopt;
  vm_args.ignoreUnrecognized = JNI_TRUE;

  thread_pool_size = cct->_conf->rgw_thread_pool_size;
  threads = new RGWRangerJniThread* [thread_pool_size];

  if (start_vm) {
    start_jvm();
    start_thread();
  }
}

RGWRangerJniManager::~RGWRangerJniManager() {
  if (jvm != NULL) {
    stop_jvm();
  }
  stop_thread();

  delete threads;
}

void RGWRangerJniManager::start_thread()
{
  for (int i = 0; i < thread_pool_size; i++) {
    RGWRangerJniThread* t = new RGWRangerJniThread(cct, this);
    threads[i] = t;

    if (!t->is_started()) {
      t->down_flag = false;

      string t_name = thread_name_prefix + to_string(i);
      t->create((char*) t_name.c_str());
    }
  }
}

void RGWRangerJniManager::stop_thread()
{
  for (int i = 0; i < thread_pool_size; i++) {
    RGWRangerJniThread* t = threads[i];

    if (t->is_started()) {
      t->down_flag = true;
      t->e_cond.notify_one();
    }
  }

  for (int i = 0; i < thread_pool_size; i++) {
    RGWRangerJniThread* t = threads[i];

    if (t->is_started()) {
      t->join();
      delete t;
    }
  }
}

int RGWRangerJniManager::start_jvm() {
  JNIEnv *jni_env;

  long flag = JNI_CreateJavaVM(&jvm, (void**) &jni_env, &vm_args);
  if (flag == JNI_ERR) {
    jvm = NULL;

    ldout(cct, 2) << __func__ << "(): Error creating VM. Exiting..." << dendl;
    return 1;
  }
  ldout(cct, 10) << __func__ << "(): JVM created!" << dendl;

  // XXX: The jvm creation change locale implicitly.. (It's terrible!)
  // restore locale to en_US
  std::setlocale(LC_ALL, "en_US.UTF-8");

  jclass tmp_jcls = jni_env->FindClass("nexr/nes/ranger/NesRangerEngine");
  if (tmp_jcls == NULL) {
    jni_env->ExceptionDescribe();
    jvm->DestroyJavaVM();
    jvm = NULL;

    ldout(cct, 2) << __func__ << "(): Error find NesRangerEngine class. Exiting..." << dendl;
    return 2;
  }
  else {
    jcls = (jclass) jni_env->NewGlobalRef(tmp_jcls);
    jni_env->DeleteLocalRef(tmp_jcls);
  }
  ldout(cct, 10) << __func__ << "(): NesRangerEngine class founded!" << dendl;

  constructor_mid = jni_env->GetMethodID(jcls, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V");
  if (constructor_mid == NULL) {
    ldout(cct, 2) << __func__ << "(): Error find constructor of NesRangerEngine. Exiting..." << dendl;
    return 3;
  }
  ldout(cct, 10) << __func__ << "(): constructor of NesRangerEngine fetched!" << dendl;

  isAccessAllowed_mid = jni_env->GetMethodID(jcls, "isAccessAllowed", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z");
  if (isAccessAllowed_mid == NULL) {
    ldout(cct, 2) << "Error find isAccessAllowed(...). Exiting..." << dendl;
    return 4;
  }
  ldout(cct, 10) << __func__ << "(): isAccessAllowed(serviceName, rangerUrl, path, "
                             << "accessType, user, group, addrTrace) method fetched!" << dendl;

  return 0;
}

void RGWRangerJniManager::stop_jvm() {
  // double check it's all ok
  jvm->DestroyJavaVM();

  jvm = NULL;
  isAccessAllowed_mid = NULL;
  constructor_mid = NULL;
}

int RGWRangerJniManager::is_access_allowed(RGWUserEndpoint endp, RGWOp *& op, req_state * const s) {
  static unsigned int thread_counter = 0;

  rgw_user bucket_owner = s->bucket_owner.get_id();

  string service_name = bucket_owner.to_str();

 if ( (use_cached_one && can_i_use_cached_policy(service_name)) \
   || (!is_connection_ok(endp)) )
  {
    RGWRangerNativeManager cached_rnm(cct, true);
    return cached_rnm.is_access_allowed(endp, op, s);
  }

  RGWRangerJniThread* allocated_t;
  while (true) {
    int t_idx = thread_counter++ % thread_pool_size;
    allocated_t = threads[t_idx];
    if (allocated_t->is_reserved()) {
      unique_lock<std::mutex> r_lock(allocated_t->r_mutex);
      allocated_t->r_cond.wait(r_lock);

      if (allocated_t->is_down()) { return -EINVAL; }
    }

    if (allocated_t->reserve()) { break; }

    ldout(cct, 5) << __func__ << "(): failed to reserve ranger_jni_thread-" << t_idx << dendl;
  }

  string req_target = "/" + s->bucket_name + "/" + s->object.to_str();
  trim_path(req_target);

  ldout(cct, 20) << __func__ << "(): req_target = " << req_target << dendl;

  uint32_t op_mask = op->op_mask();
  bool need_read_access = (op_mask & RGW_OP_TYPE_READ);

  allocated_t->service = service_name;
  allocated_t->url = endp.url;
  allocated_t->path = req_target;
  allocated_t->access_type = (need_read_access) ? "read" : "write";
  allocated_t->user = s->user->get_id().to_str();
  allocated_t->group = endp.tenant;

  allocated_t->addr_trace.clear();

  const auto& m = s->info.env->get_map();
  auto i = m.find("HTTP_X_FORWARDED_FOR");
  if (i != m.end()) {
    string ips = i->second;

    size_t pos = 0;
    string token;
    while ((pos = ips.find(",")) != string::npos) {
      token = ips.substr(0, pos);
      allocated_t->addr_trace.push_back(token);
      ips = ips.substr(pos + 1);
    }

    if (!ips.empty()) {
      allocated_t->addr_trace.push_back(ips);
    }
  }

  allocated_t->addr_trace.push_back(s->env["aws:SourceIp"]);

  RGWUserInfo owner_info;

  int ret = rgw_get_user_info_by_uid(store->ctl()->user, bucket_owner, owner_info);
  if (ret < 0) { return ret; }

  RGWUserEndpoints* user_endps = &(owner_info.endpoints);
  RGWUserEndpoint* ranger_audit_endp = user_endps->get("ranger_audit");

  bool user_specific = (ranger_audit_endp != nullptr && ranger_audit_endp->enabled);

  allocated_t->audit_service_specific = user_specific;
  allocated_t->audit_url = (user_specific) ? ranger_audit_endp->url \
                                           : s->cct->_conf->rgw_ranger_audit_url;

  {
    unique_lock<std::mutex> f_lock(allocated_t->f_mutex);
    allocated_t->e_cond.notify_one();
    allocated_t->f_cond.wait(f_lock);
  }

  int ret_int = allocated_t->get_result();

  if (use_cached_one) {
    set_svc_read_ts(service_name);
  }

  return ret_int;
}

RGWRangerJniThread::RGWRangerJniThread(CephContext* const _cct, RGWRangerJniManager* _parent)
{
  cct = _cct;
  parent = _parent;
  down_flag = false;
}

bool RGWRangerJniThread::reserve() {
  ldout(cct, 2) << __func__ << "(): try to reserve ranger_jni thread (tid = " << get_thread_id() << ")" << dendl;

  if (reserved == false) {
    reserved = true;
    return true;
  }
  else {
    return false;
  }
}

void * RGWRangerJniThread::entry()
{
  if (parent->jvm == NULL) {
    ldout(cct, 2) << __func__ << "(): java virtual machine is not initialized" << dendl;
    return NULL;
  }

  while (true)
  {
    unique_lock<std::mutex> e_lock(e_mutex);

    reserved = false;
    r_cond.notify_all();
    e_cond.wait(e_lock);

    if (down_flag) {
      r_cond.notify_all();
      break;
    }

    if (!config_audit()) {
      ldout(cct, 2) << __func__ << "(): Failed to config ranger audit" << dendl;
    }

    ldout(cct, 10) << __func__ << "(): Call RGWRangerJniManager::is_access_allowed()" << dendl;
    result = is_access_allowed();

    ldout(cct, 10) << __func__ << "(): Try organize cahced policy of " << service << dendl;
    organize_cached_policy();

    f_cond.notify_one();
  }

  return NULL;
}

bool RGWRangerJniThread::config_audit()
{
  if (audit_url.empty()) {
    ldout(cct, 20) << __func__ << "(): ranger audit_url is empty. Skip configuring audit" << dendl;
    return true;
  }

  ldout(cct, 10) << __func__ << "(): ranger_audit_url = " << audit_url << dendl;

  string default_audit_conf = parent->jni_config_dir + "/ranger-s3-audit.xml";
  string service_audit_conf = parent->jni_config_dir + "/ranger-s3-" + service + "-audit.xml";

  if (!audit_service_specific && parent->is_file_exist(service_audit_conf)) {
    std::remove(service_audit_conf.c_str());
  }

  string target_audit_conf = (audit_service_specific) ? service_audit_conf : default_audit_conf;

  unique_lock<std::mutex> ac_lock(ac_mutex);

  if (parent->is_file_age_younger(target_audit_conf, parent->audit_conf_age))
  {
    return true;
  }

  ldout(cct, 10) << __func__ << "(): Try to write audit conf "
                             << "(conf_file = " << target_audit_conf << ")" << dendl;

  Formatter* f = new XMLFormatter;
  {
    f->open_object_section("configuration");
    {
      f->open_object_section("property");
      encode_xml("name", "xasecure.audit.destination.solr", f);
      encode_xml("value", true, f);
      f->close_section();
    }
    {
      f->open_object_section("property");
      encode_xml("name", "xasecure.audit.destination.solr.urls", f);
      encode_xml("value", audit_url, f);
      f->close_section();
    }
    f->close_section();
  }

  stringstream ss;
  f->flush(ss);

  // write File
  ofstream write_stream;
  write_stream.open(target_audit_conf);

  if (write_stream.is_open()) {
    ldout(cct, 20) << __func__ << "(): The contents of " << target_audit_conf << " = " << ss.str() << dendl;

    write_stream << ss.str() << std::endl;
    write_stream.close();
  }
  else {
    ldout(cct, 2) << __func__ << "(): Failed open " << target_audit_conf
                  << "(error = " << strerror(errno) << ")" << dendl;
    return false;
  }

  return true;
}

int RGWRangerJniThread::is_access_allowed() {
  ldout(cct, 20) << __func__ << "(service: " << service << ", url: " << url << ", path: " << path << ", access_type: " << access_type << ", user: " << user << ", group: " << group << ")" << dendl;

  JavaVM* jvm = parent->jvm;
  JavaVMInitArgs* vm_args = &(parent->vm_args);

  JNIEnv* jni_env;
  JavaVMAttachArgs args { vm_args->version, NULL, NULL };

  int getEnvStat = jvm->GetEnv((void **)&jni_env, vm_args->version);
  if (getEnvStat == JNI_EDETACHED) {
    ldout(cct, 20) << __func__ << "(): jni_env not attached. Try to get jni_env." << dendl;
    if (jvm->AttachCurrentThreadAsDaemon((void **) &jni_env, &args) != 0) {
      ldout(cct, 5) << __func__ << "(): Failed to attach jni_env" << dendl;
      return -EINVAL;
    }
    else {
      ldout(cct, 20) << __func__ << "(): jni_env attachment is success!" << dendl;
    }
  } else if (getEnvStat == JNI_OK) {
    ldout(cct, 20) << __func__ << "(): jni_env attached." << dendl;
  } else if (getEnvStat == JNI_EVERSION) {
    ldout(cct, 20) << __func__ << "(): jni version not supported" << dendl;
  }

  bool is_allowed = false;

  try {
    jstring appIdString = jni_env->NewStringUTF(parent->app_id.c_str());
    jstring cacheDirString = jni_env->NewStringUTF(parent->policy_cache_dir.c_str());

    jobject jinst = jni_env->NewObject(parent->jcls, parent->constructor_mid, appIdString, cacheDirString);
    if (jni_env->ExceptionOccurred()) {
      jni_env->ExceptionDescribe();

      ldout(cct, 10) << __func__ << "(): Error construct NesRangerEngine obj. Exiting..." << dendl;
      return -EINVAL;
    }

    jobjectArray jarr_addr_trace = (jobjectArray)jni_env->NewObjectArray(addr_trace.size(),
                                                                         jni_env->FindClass("java/lang/String"),
                                                                         0);

    for (size_t k = 0; k < addr_trace.size(); k++)
    {
      jstring jstr_each_addr = jni_env->NewStringUTF(addr_trace[k].c_str());
      jni_env->SetObjectArrayElement(jarr_addr_trace, k, jstr_each_addr);
    }

    is_allowed = (bool) jni_env->CallBooleanMethod(jinst, parent->isAccessAllowed_mid,
                                                   jni_env->NewStringUTF(service.c_str()),
                                                   jni_env->NewStringUTF(url.c_str()),
                                                   jni_env->NewStringUTF(path.c_str()),
                                                   jni_env->NewStringUTF(access_type.c_str()),
                                                   jni_env->NewStringUTF(user.c_str()),
                                                   jni_env->NewStringUTF(group.c_str()),
                                                   jarr_addr_trace);

    jni_env->DeleteLocalRef(jinst);
  }
  catch(...) {
    if (jni_env->ExceptionOccurred()) {
      jni_env->ExceptionDescribe();
      jni_env->ExceptionClear();
    }
  }

  string result_str;
  if (is_allowed) {
    result_str = "allowed";
  }
  else {
    result_str = "denied";
  }

  string result_msg = "The '" + user + "' " + access_type + " request for '" + path + "' is " + result_str;

  ldout(cct, 10) << __func__ << "(): " << result_msg << dendl;

  return (is_allowed) ? 0 : -EPERM;
}

void RGWRangerJniThread::organize_cached_policy() {
  string cache_dir = parent->policy_cache_dir;
  string app_id = parent->app_id;

  string cached_policy = cache_dir + "/" + app_id + "_" + service + ".json";
  string cached_role   = cache_dir + "/" + app_id + "_" + service + "_roles.json";

  string dest_file = cache_dir + "/" + service + ".json";

  std::remove(cached_role.c_str());

  unique_lock<std::mutex> cu_lock(parent->cu_mutex);

  if (parent->is_file_age_younger(dest_file, parent->cache_update_interval))
  {
    std::remove(cached_policy.c_str());
    return;
  }

  std::rename(cached_policy.c_str(), dest_file.c_str());
  ldout(cct, 10) << __func__ << "(): The cached '" << service << "' policy was updated: " << dest_file << dendl;
}
