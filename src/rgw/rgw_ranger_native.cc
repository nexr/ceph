#include "rgw_ranger.h"

#include "include/ipaddr.h"

#include <regex>
#include <fstream>

RGWRangerNativeManager* rgw_rnm = nullptr;

inline bool is_in_vector(const string subject, vector<string> vec) {
  vector<string>::iterator iter = vec.begin();
  for (; iter != vec.end(); iter++) {
    if (*iter == subject) { return true; }
  }

  return false;
}

static inline std::string read_secret(const std::string& file_path)
{
  constexpr int16_t size{1024};
  char buf[size];
  string s;

  s.reserve(size);
  FILE* pFile = fopen(file_path.c_str(), "r"); //read mode
  if(pFile == NULL)
  {
    dout(10) << __func__ << "(): The passwd file is not exists. passwd file = " << file_path << dendl;
    return "";
  }

  fgets(buf, size, pFile);
  fclose(pFile);

  s.append(buf);

  boost::algorithm::trim(s);

  if (s.back() == '\n') {
    s.pop_back();
  }

  return s;
}

// return true if success
bool RGWRangerNativeManager::parse_policy_items(vector<ranger_policy::item>& out, vector<string> policy_items) {
  vector<string>::iterator policy_items_iter = policy_items.begin();
  for (; policy_items_iter != policy_items.end(); ++policy_items_iter) {
    string each_policy_str = *policy_items_iter;

    struct ranger_policy::item new_item;
    new_item.read_checked  = false;
    new_item.write_checked = false;

    JSONParser item_parser;
    if (!item_parser.parse(each_policy_str.c_str(), each_policy_str.length())) {
      ldout(cct, 2) << __func__ << "(): policy_item parse error. malformed json"
                                << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
      return false;
    }

    JSONObj* accesses_obj = item_parser.find_obj("accesses");
    if (accesses_obj == NULL) {
      ldout(cct, 2) << __func__ << "(): Failed to find accesses in the policy_item"
                                << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
      return false;
    }

    vector<string> accesses;
    decode_json_obj(accesses, accesses_obj);

    vector<string>::iterator access_iter = accesses.begin();
    for (; access_iter != accesses.end(); ++access_iter) {
      string each_access_str = *access_iter;
      JSONParser access_parser;
      if (!access_parser.parse(each_access_str.c_str(), each_access_str.length())) {
        ldout(cct, 2) << __func__ << "(): access_item parse error. malformed json"
                                  << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
        return false;
      }

      string acc_type;
      JSONObj* accesses_type_obj = access_parser.find_obj("type");
      if (accesses_type_obj == NULL) {
        ldout(cct, 2) << __func__ << "(): Failed to find accesses/[]/type in the policy_item"
                                  << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
        return false;
      }
      decode_json_obj(acc_type, accesses_type_obj);

      bool is_allowed;
      JSONObj* accesses_isallowed_obj = access_parser.find_obj("isAllowed");
      if (accesses_isallowed_obj == NULL) {
        ldout(cct, 2) << __func__ << "(): Failed to find accesses/[]/isAllowed in the policy_item"
                                  << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
        return false;
      }
      decode_json_obj(is_allowed, accesses_isallowed_obj);

      if (acc_type == "read") {
        new_item.read_checked = is_allowed;
      }
      else if (acc_type == "write") {
        new_item.write_checked = is_allowed;
      }
    }

    JSONObj* users_obj = item_parser.find_obj("users");
    if (users_obj == NULL) {
      ldout(cct, 2) << __func__ << "(): Failed to find users in the policy_item"
                                << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
      return false;
    }

    decode_json_obj(new_item.users, users_obj);

    JSONObj* groups_obj = item_parser.find_obj("groups");
    if (groups_obj == NULL) {
      ldout(cct, 2) << __func__ << "(): Failed to find groups in the policy_item"
                                << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
      return false;
    }

    decode_json_obj(new_item.groups, groups_obj);

    JSONObj* condition_obj = item_parser.find_obj("conditions");
    if (condition_obj == NULL) {
      ldout(cct, 2) << __func__ << "(): Failed to find conditions in the policy_item"
                                << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
      return false;
    }

    vector<string> conditions;
    decode_json_obj(conditions, condition_obj);

    vector<string>::iterator condition_iter = conditions.begin();
    for (; condition_iter != conditions.end(); ++condition_iter) {
      string each_condition_str = *condition_iter;

      JSONParser condition_parser;
      if (!condition_parser.parse(each_condition_str.c_str(), each_condition_str.length())) {
        ldout(cct, 2) << __func__ << "(): condition_item parse error. malformed json" << dendl;
        return false;
      }

      ranger_policy::item::condition new_cond;

      JSONObj* type_obj = condition_parser.find_obj("type");
      decode_json_obj(new_cond.type, type_obj);

      JSONObj* values_obj = condition_parser.find_obj("values");
      decode_json_obj(new_cond.cidrs, values_obj);

      new_item.conditions.push_back(new_cond);
    }

    out.push_back(new_item);
  }

  return true;
}

// return true if success
bool RGWRangerNativeManager::parse_policy(ranger_policy& out, string& policy_str) {
  JSONParser parser;

  if (!parser.parse(policy_str.c_str(), policy_str.length())) {
    ldout(cct, 2) << __func__ << "(): policy parse error. malformed json"
                              << " (policy_str = " << policy_str << ")" << dendl;
    return false;
  }

  // policy.id
  JSONObj* id_obj = parser.find_obj("id");
  if (id_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find id of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.id, id_obj);

  // policy.isEnabled
  JSONObj* enabled_obj = parser.find_obj("isEnabled");
  if (enabled_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find isEnabled of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.isEnabled, enabled_obj);

  // policy.paths & policy.isRecursive
  JSONObj* resources_obj = parser.find_obj("resources");
  if (resources_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find resources of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  JSONObj* resources_path_obj = resources_obj->find_obj("path");
  if (resources_path_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find path of the resources/entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  // policy.paths
  JSONObj* resources_path_values_obj = resources_path_obj->find_obj("values");
  if (resources_path_values_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find resources/path/values of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.paths, resources_path_values_obj);

  // policy.isRecursive
  JSONObj* resources_path_isrecursive_obj = resources_path_obj->find_obj("isRecursive");
  if (resources_path_isrecursive_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find resources/path/isRecursive of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.isRecursive, resources_path_isrecursive_obj);

  // policy.isExcludes
  JSONObj* resources_path_isexcludes_obj = resources_path_obj->find_obj("isExcludes");
  if (resources_path_isexcludes_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find resources/path/isExcludes of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.isExcludes, resources_path_isexcludes_obj);

  // policy.allow_policies
  JSONObj* policyitems_obj = parser.find_obj("policyItems");
  if (policyitems_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find policyItems of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  vector<string> policy_items;
  decode_json_obj(policy_items, policyitems_obj);

  if (!parse_policy_items(out.allow_policies, policy_items)) {
    ldout(cct, 2) << __func__ << "(): Failed to parse allow policyItems" << dendl;
    return false;
  }

  // policy.allow_exceptions
  JSONObj* allowexceptions_obj = parser.find_obj("allowExceptions");
  if (allowexceptions_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find allowExceptions of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  vector<string> allow_exceptions;
  decode_json_obj(allow_exceptions, allowexceptions_obj);

  if (!parse_policy_items(out.allow_exceptions, allow_exceptions)) {
    ldout(cct, 2) << __func__ << "(): Failed to parse allow exceptions"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  // policy.deny_policies
  JSONObj* denypolicyitems_obj = parser.find_obj("denyPolicyItems");
  if (denypolicyitems_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find denyPolicyItems of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  vector<string> deny_policy_items;
  decode_json_obj(deny_policy_items, denypolicyitems_obj);

  if (!parse_policy_items(out.deny_policies, deny_policy_items)) {
    ldout(cct, 2) << __func__ << "(): Failed to parse deny policyItems"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  // policy.deny_exceptions
  JSONObj* denyexceptions_obj = parser.find_obj("denyExceptions");
  if (denyexceptions_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Failed to find denyExceptions of the entity"
                              << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  vector<string> deny_exceptions;
  decode_json_obj(deny_exceptions, denyexceptions_obj);

  if (!parse_policy_items(out.deny_exceptions, deny_exceptions)) {
    ldout(cct, 2) << __func__ << "(): Failed to parse deny exceptions" << dendl;
    return false;
  }

  return true;
}

bool RGWRangerNativeManager::is_policy_related(req_state * const s, ranger_policy& policy) {
  if (!policy.isEnabled) { return false; }

  bool ret = false;

  string req_target = "/" + s->bucket_name + "/" + s->object.to_str();
  trim_path(req_target);
  ldout(cct, 20) << __func__ << "(): req_target = " << req_target << dendl;

  string req_user     = s->user->get_id().to_str();
  string bucket_owner = s->bucket_owner.get_id().to_str();

  vector<string>::iterator path_iter = policy.paths.begin();
  for (;path_iter != policy.paths.end(); path_iter++) {
    string each_path = *path_iter;
    trim_path(each_path);

    string path_regex;
    path_regex += "^";
    path_regex += each_path;
    path_regex  = regex_replace(path_regex, regex("\\{USER\\}"), req_user);
    path_regex  = regex_replace(path_regex, regex("\\{OWNER\\}"), bucket_owner);
    path_regex  = regex_replace(path_regex, regex("\\{|\\}"), "");
    path_regex  = regex_replace(path_regex, regex("\\*+"), "[A-Za-z0-9_=@,.:-\\\\/]*");
    path_regex += (path_regex  ==  "^") ? "[A-Za-z0-9_=@,.:-\\\\/]*" : "";
    path_regex += (!policy.isRecursive) ? "$" : "";
    ldout(cct, 20) << __func__ << "(): each path_regex = " << path_regex << dendl;

    smatch m;
    ret = regex_search(req_target, m, regex(path_regex));
    if (ret) {
      ldout(cct, 10) << __func__ << "(): req_target '" << req_target << "' matched with " << path_regex << dendl;
      break;
    }
  }

  if (policy.isExcludes) { ret = !ret; }

  return ret;
}

bool RGWRangerNativeManager::is_item_related(req_state * const s, ranger_policy::item& policy_item, string tenant_group) {
  bool ret = false;

  string req_user = s->user->get_id().to_str();
  string bucket_owner = s->bucket_owner.get_id().to_str();
  ldout(cct, 20) << __func__ << "(): req_user = " << req_user << dendl;
  ldout(cct, 20) << __func__ << "(): bucket_owner = " << bucket_owner << dendl;

  vector<string>::iterator policy_user_iter = policy_item.users.begin();
  for (; policy_user_iter != policy_item.users.end(); policy_user_iter++) {
    string each_policy_user = *policy_user_iter;

    if ( (each_policy_user == "{USER}") \
      || (each_policy_user == req_user) \
      || (each_policy_user == "{OWNER}" && req_user == bucket_owner) )
    {
      ret = true;
      break;
    }
  }

  if (ret == true) {
    ldout(cct, 5) << __func__ << "(): The user '" << req_user << "' is related to the policy_item!" << dendl;
  }
  // one more chance! check group relation.
  else {
    ldout(cct, 10) << __func__ << "(): The user '" << req_user << "' is not related to the policy_item."
                               << " Check group relation" << dendl;

    ldout(cct, 20) << __func__ << "(): ranger_tenant_group = " << tenant_group << dendl;
    ret = is_in_vector(tenant_group, policy_item.groups);

    if (ret == false) { return false; }
    ldout(cct, 5) << __func__ << "(): The group of '" << req_user << "' is related to the policy_item." << dendl;
  }

  if (policy_item.conditions.size() == 0) { return true; }
  ldout(cct, 10) << __func__ << "(): There are conditions to check." << dendl;

  vector<string> remote_ips_str;
  const auto& m = s->info.env->get_map();
  auto i = m.find("HTTP_X_FORWARDED_FOR");
  if (i != m.end()) {
    string ips = i->second;

    size_t pos = 0;
    string token;
    while ((pos = ips.find(",")) != string::npos) {
      token = ips.substr(0, pos);
      remote_ips_str.push_back(token);
      ips = ips.substr(pos + 1);
    }

    if (!ips.empty()) {
      remote_ips_str.push_back(ips);
    }
  }

  remote_ips_str.push_back(s->env["aws:SourceIp"]);

  vector<entity_addr_t> remote_ips;
  vector<string>::iterator ip_iter = remote_ips_str.begin();
  for (; ip_iter != remote_ips_str.end(); ip_iter++) {
    string each_ip = *ip_iter;
    ldout(cct, 20) << __func__ << "(): each remote ip = " << each_ip << dendl;

    unsigned int tmp;
    entity_addr_t new_addr;
    parse_network((each_ip + "/32").c_str(), &new_addr, &tmp);
    remote_ips.push_back(new_addr);
  }

  vector<ranger_policy::item::condition>::iterator cond_iter = policy_item.conditions.begin();
  for (; cond_iter != policy_item.conditions.end(); cond_iter++) {
    ranger_policy::item::condition each_cond = *cond_iter;

    bool is_all_type = (each_cond.type == "cidrAllUserIPs");
    bool is_any_type = (each_cond.type == "cidrAnyUserIPs");

    if (is_all_type) {
      ldout(cct, 20) << __func__ << "(): condition type = cidrAllUserIPs" << dendl;
    }
    else if (is_any_type) {
      ldout(cct, 20) << __func__ << "(): condition type = cidrAnyUserIPs" << dendl;
    }

    bool is_ip_contained = (is_all_type) ? true : false;

    vector<entity_addr_t>::iterator ip_iter = remote_ips.begin();
    for (; ip_iter != remote_ips.end(); ip_iter++) {
      bool is_each_ip_contained = false;

      vector<string>::iterator cidr_iter = each_cond.cidrs.begin();
      for (;cidr_iter != each_cond.cidrs.end(); cidr_iter++) {
        string each_cidr = *cidr_iter;
        if (each_cidr.rfind("/") == string::npos) {
          each_cidr += "/32";
        }

        entity_addr_t network;
        unsigned int prefix;
        parse_network(each_cidr.c_str(), &network, &prefix);

        ldout(cct, 20) << __func__ << "(): each condition network = " << network.ip_only_to_str() << "/" << prefix << dendl;

        is_each_ip_contained = network_contains(network, prefix, *ip_iter);
        if (is_each_ip_contained) {
          ldout(cct, 10) << __func__ << "(): The ip " << ip_iter->get_sockaddr() << " is contained"
                                     << " in network: " << network.ip_only_to_str() << "/" << prefix << "!" << dendl;
          break;
        }
      }

      if (is_all_type) {
        is_ip_contained = is_ip_contained && is_each_ip_contained;
        if (!is_ip_contained) { break; }
      }
      else if (is_any_type) {
        is_ip_contained = is_ip_contained || is_each_ip_contained;
        if (is_ip_contained) { break; }
      }
    }

    if (is_ip_contained) {
      ldout(cct, 5) << __func__ << "(): The request is agreed with the condition" << dendl;
      return true;
    }
  }

  return false;
}

bool RGWRangerNativeManager::is_authz_allowed(uint32_t op_mask, req_state * const s, ranger_policy& policy, string tenant_group)
{
  bool is_allowed = false;

  ldout(cct, 20) << __func__ << "(): op mask of request = " << op_mask << dendl;

  bool need_read_access  = (op_mask & RGW_OP_TYPE_READ);
  bool need_write_access = (op_mask & RGW_OP_TYPE_MODIFY);

  if (need_read_access) {
    ldout(cct, 20) << __func__ << "(): The request need read_access" << dendl;
  }
  else if (need_write_access) {
    ldout(cct, 20) << __func__ << "(): The request need write_access" << dendl;
  }

  vector<ranger_policy::item> allow_policies = policy.allow_policies;
  vector<ranger_policy::item>::iterator allow_iter = allow_policies.begin();
  for (; allow_iter != allow_policies.end(); allow_iter++) {
    ranger_policy::item each_allow = *allow_iter;

    if (!is_item_related(s, each_allow, tenant_group)) { continue; }

    if ( ( need_read_access  &&  each_allow.read_checked  ) \
      || ( need_write_access &&  each_allow.write_checked ) )
    {
      is_allowed = true;
      break;
    }
  }

  if (!is_allowed) { return false; }

  ldout(cct, 10) << __func__ << "(): The request is accepted. Try to check exceptions." << dendl;

  vector<ranger_policy::item> allow_exceptions = policy.allow_exceptions;
  vector<ranger_policy::item>::iterator except_iter = allow_exceptions.begin();
  for (; except_iter != allow_exceptions.end(); except_iter++) {
    ranger_policy::item each_except = *except_iter;

    if (!is_item_related(s, each_except, tenant_group)) { continue; }

    if ( !( need_read_access  &&  !each_except.read_checked  ) \
      && !( need_write_access &&  !each_except.write_checked ) )
    {
      ldout(cct, 10) << __func__ << "(): The request is caught in allow exception." << dendl;
      return false;
    }
  }

  return true;
}

bool RGWRangerNativeManager::is_authz_denied(uint32_t op_mask, req_state * const s, ranger_policy& policy, string tenant_group)
{
  bool is_denied = false;

  ldout(cct, 20) << __func__ << "(): op mask of request = " << op_mask << dendl;

  bool need_read_access  = (op_mask & RGW_OP_TYPE_READ);
  bool need_write_access = (op_mask & RGW_OP_TYPE_MODIFY);

  if (need_read_access) {
    ldout(cct, 20) << __func__ << "(): The request need read_access" << dendl;
  }
  else if (need_write_access) {
    ldout(cct, 20) << __func__ << "(): The request need write_access" << dendl;
  }

  vector<ranger_policy::item> deny_policies = policy.deny_policies;
  vector<ranger_policy::item>::iterator deny_iter = deny_policies.begin();
  for (; deny_iter != deny_policies.end(); deny_iter++) {
    ranger_policy::item each_deny = *deny_iter;

    if (!is_item_related(s, each_deny, tenant_group)) { continue; }

    if ( !( need_read_access  &&  !each_deny.read_checked  ) \
      && !( need_write_access &&  !each_deny.write_checked ) )
    {
      is_denied = true;
      break;
    }
  }

  if (!is_denied) { return false; }
  ldout(cct, 10) << __func__ << "(): The request is denied. Try to check exceptions." << dendl;

  vector<ranger_policy::item> deny_exceptions = policy.deny_exceptions;
  vector<ranger_policy::item>::iterator except_iter = deny_exceptions.begin();
  for (; except_iter != deny_exceptions.end(); except_iter++) {
    ranger_policy::item each_except = *except_iter;

    if (!is_item_related(s, each_except, tenant_group)) { continue; }

    if ( ( need_read_access  &&  each_except.read_checked  ) \
      || ( need_write_access &&  each_except.write_checked ) )
    {
      ldout(cct, 10) << __func__ << "(): The request is caught in deny exception." << dendl;
      return false;
    }
  }

  return true;
}

int RGWRangerNativeManager::get_related_policies(vector<ranger_policy>& ret_vec, RGWUserEndpoint endpoint, req_state * const s, string service) {
  if ( (cached_mode)
    || (use_cached_one && can_i_use_cached_policy(service)) )
  {
    return get_related_policies_from_cache(ret_vec, s, service);
  }
  else if (is_connection_ok(endpoint)) {
    return get_related_policies_from_remote(ret_vec, endpoint, s, service);
  }
  else {
    return get_related_policies_from_cache(ret_vec, s, service);
  }
}

int RGWRangerNativeManager::get_related_policies_from_remote(vector<ranger_policy>& ret_vec, RGWUserEndpoint endpoint, req_state * const s, string service) {
  ldout(cct, 20) << __func__ << "(): Policy will be fetched from remote." << dendl;

  string url;
  url  = endpoint.url;
  url += "/service/plugins/policies/service/name/";
  url += service;
  url  = regex_replace(url, regex("/+"), "/");
  url  = regex_replace(url, regex(":/"), "://");

  ldout(cct, 10) << __func__ << "(): RANGER URL= " << url.c_str() << dendl;

  // get authentication info for Ranger
  string ranger_user = endpoint.admin_user;
  string ranger_pass = "";

  string endp_admin_pw_path = endpoint.admin_passwd_path;
  if (endp_admin_pw_path.empty()) {
    ranger_pass = endpoint.admin_passwd;
  }
  else {
    ranger_pass = read_secret(endp_admin_pw_path);
    ldout(cct, 30) << __func__ << "(): read ranger admin_password from " << endp_admin_pw_path
                               << " = " << ranger_pass << dendl;
  }

  bufferlist auth_bl;
  auth_bl.append(ranger_user);
  auth_bl.append(":");
  auth_bl.append(ranger_pass);

  bufferlist encoded_bl;
  auth_bl.encode_base64(encoded_bl);

  bool need_continue = true;
  int offset = 0;

  string cached_policy_file = policy_cache_dir + "/" + service + ".json";
  string policies_to_cache = "";

  while (need_continue) {
    int ret;
    bufferlist bl;

    string url_with_offset = url +  "?startIndex=" + to_string(offset);
    RGWHTTPTransceiver req(cct, "GET", url_with_offset.c_str(), &bl);

    // set required headers for Ranger request
    req.append_header("Authorization", "Basic " + encoded_bl.to_str());
    req.append_header("Content-Type", "application/json");

    // check if we want to verify Ranger server SSL certificate
    req.set_verify_ssl(endpoint.use_ssl);

    // send request
    ret = req.process(null_yield);
    if (ret < 0) {
      ldout(cct, 2) << __func__ << "(): Ranger process error:" << bl.c_str() << dendl;
      return ret;
    }

    ldout(cct, 10) << __func__ << "(): received response status=" << req.get_http_status()
                               << ", body=" << bl.c_str() << dendl;

    // check Ranger response
    JSONParser parser;
    if (!parser.parse(bl.c_str(), bl.length())) {
      ldout(cct, 2) << __func__ << "(): Ranger parse error. malformed json"
                                << " (response_str = " << bl.c_str() << ")" << dendl;
      return -EINVAL;
    }

    JSONObj* resultsize_obj = parser.find_obj("resultSize");
    if (resultsize_obj == NULL) {
      ldout(cct, 2) << __func__ << "(): Invalid resultSize of ranger result" << dendl;
      return -EINVAL;
    }

    int result_size;
    decode_json_obj(result_size, resultsize_obj);

    // There are no policies at all
    if (result_size == 0) {
      ldout(cct, 2) << __func__ << "(): Ranger rejecting request because of zero policy" << dendl;
      return -EPERM;
    }

    JSONObj* pagesize_obj = parser.find_obj("pageSize");
    if (pagesize_obj == NULL) {
      ldout(cct, 2) << __func__ << "(): Invalid pageSize of ranger page" << dendl;
      return -EINVAL;
    }

    int page_size;
    decode_json_obj(page_size, pagesize_obj);

    need_continue = (result_size == page_size);
    if (need_continue) {
      offset = offset + page_size;
    }

    JSONObj* policies_obj = parser.find_obj("policies");
    if (policies_obj == NULL) {
      ldout(cct, 2) << __func__ << "(): Invalid policies of ranger result" << dendl;
      return -EINVAL;
    }

    string policies_part_to_cache;
    policies_part_to_cache = policies_obj->get_data();
    policies_part_to_cache = policies_part_to_cache.substr(1, (policies_part_to_cache.length() - 1) - 1); // truncate '[' and ']'

    policies_to_cache = (policies_to_cache.empty()) ? policies_part_to_cache
                                                    : policies_to_cache + "," + policies_part_to_cache;

    vector<string> policies_str = policies_obj->get_array_elements();

    vector<string>::iterator policy_iter = policies_str.begin();
    for (; policy_iter != policies_str.end(); ++policy_iter) {
      ranger_policy policy;
      if (!parse_policy(policy, *policy_iter)) {
        ldout(cct, 2) << __func__ << "(): Failed to parse ranger result" << dendl;
        return -EINVAL;
      }

      if (is_policy_related(s, policy)) {
        ret_vec.push_back(policy);
      }
      else {
        ldout(cct, 5) << __func__ << "(): The '" << policy.id << "' policy is not related. Skip checking." << dendl;
      }
    }
  }

  unique_lock<std::mutex> cu_lock(cu_mutex);

  bool need_caching = ( !is_file_exist(cached_policy_file) \
                     || is_file_age_older(cached_policy_file, cache_update_interval) );

  if (need_caching) {
    ldout(cct, 10) << __func__ << "(): Try to write cached policy (" << cached_policy_file << ")" << dendl;

    policies_to_cache = "{\"policies\":[" + policies_to_cache + "]}";

    // write File
    ofstream write_stream;
    write_stream.open(cached_policy_file);

    if (write_stream.is_open()) {
      write_stream << policies_to_cache;
      write_stream.close();

      if (use_cached_one) {
        set_svc_read_ts(service);
      }
    }
    else {
      ldout(cct, 2) << __func__ << "(): Failed to cached file (error = " << strerror(errno) << ")" << dendl;
      return 0;
    }
  }

  return 0;
}

int RGWRangerNativeManager::get_related_policies_from_cache(vector<ranger_policy>& ret_vec, req_state * const s, string service) {
  ldout(cct, 20) << __func__ << "(): Policy will be fetched from cache." << dendl;

  struct stat f_stat;

  string cached_policy_file = policy_cache_dir + "/" + service + ".json";

  int fd = open(cached_policy_file.c_str(), O_RDONLY);
  if (fd < 0) {
    ldout(cct, 2) << __func__ << "(): Failed to open cached policy(" << cached_policy_file \
                              << ") -> " << strerror(errno) << dendl;
    return -EINVAL;
  }

  fstat(fd, &f_stat);

  string raw_policy_str;
  raw_policy_str.resize(f_stat.st_size);
  read(fd, (char*)(raw_policy_str.data()), f_stat.st_size);
  close(fd);

  ldout(cct, 30) << __func__ << "(): The contents of cached policy = " << raw_policy_str << dendl;

  // check Ranger response
  JSONParser parser;
  if (!parser.parse(raw_policy_str.c_str(), raw_policy_str.length())) {
    ldout(cct, 2) << __func__ << "(): Ranger parse error. malformed json"
                              << " (response_str = " << raw_policy_str.c_str() << ")" << dendl;
    return -EINVAL;
  }

  JSONObj* policies_obj = parser.find_obj("policies");
  if (policies_obj == NULL) {
    ldout(cct, 2) << __func__ << "(): Invalid policies of ranger result" << dendl;
    return -EINVAL;
  }

  vector<string> policies_str = policies_obj->get_array_elements();

  // There are no policies at all
  if (policies_str.size() == 0) {
    ldout(cct, 2) << __func__ << "(): Ranger rejecting request because of zero policy" << dendl;
    return -EPERM;
  }

  vector<string>::iterator policy_iter = policies_str.begin();
  for (; policy_iter != policies_str.end(); ++policy_iter) {
    ranger_policy policy;
    if (!parse_policy(policy, *policy_iter)) {
      ldout(cct, 2) << __func__ << "(): Failed to parse ranger result" << dendl;
      return -EINVAL;
    }

    if (is_policy_related(s, policy)) {
      ret_vec.push_back(policy);
    }
    else {
      ldout(cct, 5) << __func__ << "(): The '" << policy.id << "' policy is not related. Skip checking." << dendl;
    }
  }

  return 0;
}

int RGWRangerNativeManager::is_access_allowed(RGWUserEndpoint endpoint, RGWOp *& op, req_state * const s)
{
  const string bucket_owner = s->bucket_owner.get_id().to_str();

  vector<ranger_policy> related_policies;
  int ret = get_related_policies(related_policies, endpoint, s, bucket_owner);
  if (ret != 0) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to get related policies" << dendl;
    return ret;
  }

  int deny_policy_id = 0;
  vector<ranger_policy>::iterator deny_policy_iter = related_policies.begin();
  for (; deny_policy_iter != related_policies.end(); ++deny_policy_iter) {
    ranger_policy policy = *deny_policy_iter;
    if (is_authz_denied(op->op_mask(), s, policy, endpoint.tenant)) {
      deny_policy_id = policy.id;
      break;
    }
  }

  if (deny_policy_id != 0) {
    ldpp_dout(op, 2) << __func__ << "(): Ranger rejecting request according to the '" << deny_policy_id << "' policy" << dendl;
    return -EPERM;
  }

  int allow_policy_id = 0;
  vector<ranger_policy>::iterator allow_policy_iter = related_policies.begin();
  for (; allow_policy_iter != related_policies.end(); ++allow_policy_iter) {
    ranger_policy policy = *allow_policy_iter;
    if (is_authz_allowed(op->op_mask(), s, policy, endpoint.tenant)) {
      allow_policy_id = policy.id;
      break;
    }
  }

  if (allow_policy_id != 0) {
    ldpp_dout(op, 2) << __func__ << "(): Ranger accepting request according to the '" << allow_policy_id << "' policy" << dendl;
    return 0;
  }
  else {
    ldpp_dout(op, 2) << __func__ << "(): Ranger rejecting request because any allow policy is not exist" << dendl;
    return -EPERM;
  }
}
