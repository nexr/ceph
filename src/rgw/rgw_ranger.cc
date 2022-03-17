#include "rgw_ranger.h"
#include "include/ipaddr.h"
#include <regex>
#include <fstream>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

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

inline void trim_path(string& path) {
  if ( path.find("/") == 0 ) {
    path = path.substr(1);
  }

  int path_len = path.length();
  if ( path.rfind("/") == size_t(path_len-1) ) {
    path = path.substr(0, path_len-1);
  }
}

inline bool is_in_vector(const string subject, vector<string> vec) {
  vector<string>::iterator iter = vec.begin();
  for (; iter != vec.end(); iter++) {
    if (*iter == subject) { return true; }
  }

  return false;
}

inline bool parse_ip(entity_addr_t *network, string addr) {
  // try parsing as ipv4
  int ok;
  ok = inet_pton(AF_INET, addr.c_str(), &((struct sockaddr_in*)network)->sin_addr);
  if (ok) {
    network->set_family(AF_INET);
    return true;
  }

  // try parsing as ipv6
  ok = inet_pton(AF_INET6, addr.c_str(), &((struct sockaddr_in6*)network)->sin6_addr);
  if (ok) {
    network->set_family(AF_INET6);
    return true;
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

bool get_ranger_endpoint(RGWUserEndpoint& out, RGWOp *& op, req_state * const s) {

  RGWUserEndpoints* user_endps = &(s->user->endpoints);
  RGWUserEndpoint* found_endp  = user_endps->get("ranger");

  if (found_endp != nullptr && found_endp->enabled) {
    out = *found_endp;
  }
  else {
    out.url = s->cct->_conf->rgw_ranger_url;
    if (out.url == "") {
      ldpp_dout(op, 2) << __func__ << "(): RNAGER_URL not provided" << dendl;
      return false;
    }

    out.use_ssl = s->cct->_conf->rgw_ranger_verify_ssl;

    out.admin_user = s->cct->_conf->rgw_ranger_admin_user;

    out.admin_passwd = s->cct->_conf->rgw_ranger_admin_password;
    out.admin_passwd_path = s->cct->_conf->rgw_ranger_admin_password;

    out.tenant = s->cct->_conf->rgw_ranger_tenant;

    out.enabled = true;
  }

  return true;
}

// return true if success
bool parse_policy_items(vector<ranger_policy::item>& out, vector<string> policy_items, RGWOp *& op) {
  vector<string>::iterator policy_items_iter = policy_items.begin();
  for (; policy_items_iter != policy_items.end(); ++policy_items_iter) {
    string each_policy_str = *policy_items_iter;

    struct ranger_policy::item new_item;
    new_item.read_checked  = false;
    new_item.write_checked = false;

    JSONParser item_parser;
    if (!item_parser.parse(each_policy_str.c_str(), each_policy_str.length())) {
      ldpp_dout(op, 2) << __func__ << "(): policy_item parse error. malformed json"
                       << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
      return false;
    }

    JSONObj* accesses_obj = item_parser.find_obj("accesses");
    if (accesses_obj == NULL) {
      ldpp_dout(op, 2) << __func__ << "(): Failed to find accesses in the policy_item"
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
        ldpp_dout(op, 2) << __func__ << "(): access_item parse error. malformed json"
                         << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
        return false;
      }

      string acc_type;
      JSONObj* accesses_type_obj = access_parser.find_obj("type");
      if (accesses_type_obj == NULL) {
        ldpp_dout(op, 2) << __func__ << "(): Failed to find accesses/[]/type in the policy_item"
                         << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
        return false;
      }
      decode_json_obj(acc_type, accesses_type_obj);

      bool is_allowed;
      JSONObj* accesses_isallowed_obj = access_parser.find_obj("isAllowed");
      if (accesses_isallowed_obj == NULL) {
        ldpp_dout(op, 2) << __func__ << "(): Failed to find accesses/[]/isAllowed in the policy_item"
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
      ldpp_dout(op, 2) << __func__ << "(): Failed to find users in the policy_item"
                       << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
      return false;
    }

    decode_json_obj(new_item.users, users_obj);

    JSONObj* groups_obj = item_parser.find_obj("groups");
    if (groups_obj == NULL) {
      ldpp_dout(op, 2) << __func__ << "(): Failed to find groups in the policy_item"
                       << " (policy_item_str = " << each_policy_str.c_str() << ")" << dendl;
      return false;
    }

    decode_json_obj(new_item.groups, groups_obj);

    JSONObj* condition_obj = item_parser.find_obj("conditions");
    if (condition_obj == NULL) {
      ldpp_dout(op, 2) << __func__ << "(): Failed to find conditions in the policy_item"
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
        ldpp_dout(op, 2) << __func__ << "(): condition_item parse error. malformed json" << dendl;
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
bool parse_policy(ranger_policy& out, string& policy_str, RGWOp *& op) {
  JSONParser parser;

  if (!parser.parse(policy_str.c_str(), policy_str.length())) {
    ldpp_dout(op, 2) << __func__ << "(): policy parse error. malformed json"
                     << " (policy_str = " << policy_str << ")" << dendl;
    return false;
  }

  // policy.id
  JSONObj* id_obj = parser.find_obj("id");
  if (id_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find id of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.id, id_obj);

  // policy.isEnabled
  JSONObj* enabled_obj = parser.find_obj("isEnabled");
  if (enabled_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find isEnabled of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.isEnabled, enabled_obj);

  // policy.paths & policy.isRecursive
  JSONObj* resources_obj = parser.find_obj("resources");
  if (resources_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find resources of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  JSONObj* resources_path_obj = resources_obj->find_obj("path");
  if (resources_path_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find path of the resources/entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  // policy.paths
  JSONObj* resources_path_values_obj = resources_path_obj->find_obj("values");
  if (resources_path_values_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find resources/path/values of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.paths, resources_path_values_obj);

  // policy.isRecursive
  JSONObj* resources_path_isrecursive_obj = resources_path_obj->find_obj("isRecursive");
  if (resources_path_isrecursive_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find resources/path/isRecursive of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.isRecursive, resources_path_isrecursive_obj);

  // policy.isExcludes
  JSONObj* resources_path_isexcludes_obj = resources_path_obj->find_obj("isExcludes");
  if (resources_path_isexcludes_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find resources/path/isExcludes of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  decode_json_obj(out.isExcludes, resources_path_isexcludes_obj);

  // policy.allow_policies
  JSONObj* policyitems_obj = parser.find_obj("policyItems");
  if (policyitems_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find policyItems of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  vector<string> policy_items;
  decode_json_obj(policy_items, policyitems_obj);

  if (!parse_policy_items(out.allow_policies, policy_items, op)) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to parse allow policyItems" << dendl;
    return false;
  }

  // policy.allow_exceptions
  JSONObj* allowexceptions_obj = parser.find_obj("allowExceptions");
  if (allowexceptions_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find allowExceptions of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  vector<string> allow_exceptions;
  decode_json_obj(allow_exceptions, allowexceptions_obj);

  if (!parse_policy_items(out.allow_exceptions, allow_exceptions, op)) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to parse allow exceptions"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  // policy.deny_policies
  JSONObj* denypolicyitems_obj = parser.find_obj("denyPolicyItems");
  if (denypolicyitems_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find denyPolicyItems of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  vector<string> deny_policy_items;
  decode_json_obj(deny_policy_items, denypolicyitems_obj);

  if (!parse_policy_items(out.deny_policies, deny_policy_items, op)) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to parse deny policyItems"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  // policy.deny_exceptions
  JSONObj* denyexceptions_obj = parser.find_obj("denyExceptions");
  if (denyexceptions_obj == NULL) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to find denyExceptions of the entity"
                     << " (policy_str = " << policy_str.c_str() << ")" << dendl;
    return false;
  }

  vector<string> deny_exceptions;
  decode_json_obj(deny_exceptions, denyexceptions_obj);

  if (!parse_policy_items(out.deny_exceptions, deny_exceptions, op)) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to parse deny exceptions" << dendl;
    return false;
  }

  return true;
}

bool is_policy_related(RGWOp *& op, req_state * const s, ranger_policy& policy) {
  if (!policy.isEnabled) { return false; }

  bool ret = false;

  string req_target = s->bucket_name + "/" + s->object.to_str();
  trim_path(req_target);
  ldpp_dout(op, 20) << __func__ << "(): req_target = " << req_target << dendl;

  string req_user = s->user->user_id.to_str();
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
    ldpp_dout(op, 20) << __func__ << "(): each path_regex = " << path_regex << dendl;

    smatch m;
    ret = regex_search(req_target, m, regex(path_regex));
    if (ret) {
      ldpp_dout(op, 10) << __func__ << "(): req_target '" << req_target << "' matched with " << path_regex << dendl;
      break;
    }
  }

  if (policy.isExcludes) { ret = !ret; }

  return ret;
}

bool is_item_related(RGWOp *& op, req_state * const s, ranger_policy::item& policy_item) {
  bool ret = false;

  string req_user = s->user->user_id.to_str();
  string bucket_owner = s->bucket_owner.get_id().to_str();
  ldpp_dout(op, 20) << __func__ << "(): req_user = " << req_user << dendl;

  vector<string>::iterator policy_user_iter = policy_item.users.begin();
  for (; policy_user_iter != policy_item.users.end(); policy_user_iter++) {
    string each_policy_user = *policy_user_iter;

    if ( (each_policy_user == "{USER}") \
      || (each_policy_user == "{OWNER}" && bucket_owner == req_user) \
      || (each_policy_user == req_user) )
    {
      ret = true;
      break;
    }
  }

  if (ret == true) {
    ldpp_dout(op, 5) << __func__ << "(): The user '" << req_user << "' is related to the policy_item!" << dendl;
  }
  // one more chance! check group relation.
  else {
    ldpp_dout(op, 10) << __func__ << "(): The user '" << req_user << "' is not related to the policy_item."
                      << " Check group relation" << dendl;

    RGWUserEndpoint endpoint;
    if (!get_ranger_endpoint(endpoint, op, s)) {
      ldpp_dout(op, 2) << __func__ << "(): Failed to parse ranger endpoint of " << bucket_owner << dendl;
      return -ERR_INVALID_REQUEST;
    }

    const string& ranger_tenant_group = endpoint.tenant;
    ldpp_dout(op, 20) << __func__ << "(): ranger_tenant_group = " << ranger_tenant_group << dendl;

    ret = is_in_vector(ranger_tenant_group, policy_item.groups);

    if (ret == false) { return false; }
    ldpp_dout(op, 5) << __func__ << "(): The group of '" << req_user << "' is related to the policy_item." << dendl;
  }

  if (policy_item.conditions.size() == 0) { return true; }
  ldpp_dout(op, 10) << __func__ << "(): There are conditions to check." << dendl;

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
    ldpp_dout(op, 20) << __func__ << "(): each remote ip = " << each_ip << dendl;

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
      ldpp_dout(op, 20) << __func__ << "(): condition type = cidrAllUserIPs" << dendl;
    }
    else if (is_any_type) {
      ldpp_dout(op, 20) << __func__ << "(): condition type = cidrAnyUserIPs" << dendl;
    }

    bool is_ip_contained = (is_all_type) ? true : false;
    vector<string>::iterator cidr_iter = each_cond.cidrs.begin();
    for (;cidr_iter != each_cond.cidrs.end(); cidr_iter++) {
      string each_cidr = *cidr_iter;
      if (each_cidr.rfind("/") == string::npos) {
        each_cidr += "/32";
      }

      entity_addr_t network;
      unsigned int prefix;
      parse_network(each_cidr.c_str(), &network, &prefix);

      ldpp_dout(op, 20) << __func__ << "(): each condition network = " << network.ip_only_to_str() << "/" << prefix << dendl;

      bool is_each_ip_contained = false;
      vector<entity_addr_t>::iterator ip_iter = remote_ips.begin();
      for (; ip_iter != remote_ips.end(); ip_iter++) {
        is_each_ip_contained = network_contains(network, prefix, *ip_iter);

        if (is_each_ip_contained) { break; }
      }

      if (is_each_ip_contained) {
        ldpp_dout(op, 10) << __func__ << "(): The ip " << *ip_iter << " is contained"
                          << " in network: " << network.ip_only_to_str() << "/" << prefix << "!" << dendl;
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
      ldpp_dout(op, 5) << __func__ << "(): The request is agreed with the condition" << dendl;
      return true;
    }
  }

  return false;
}

bool is_authz_allowed(RGWOp *& op, req_state * const s, ranger_policy& policy)
{
  bool is_allowed = false;

  uint32_t op_mask = op->op_mask();
  ldpp_dout(op, 20) << __func__ << "(): op mask of request = " << op_mask << dendl;

  bool need_read_access  = (op_mask & RGW_OP_TYPE_READ);
  bool need_write_access = (op_mask & RGW_OP_TYPE_MODIFY);
  bool need_all_access   = (need_read_access && need_write_access);

  if (need_read_access) {
    ldpp_dout(op, 20) << __func__ << "(): The request need read_access" << dendl;
  }
  else if (need_write_access) {
    ldpp_dout(op, 20) << __func__ << "(): The request need write_access" << dendl;
  }
  else if (need_all_access) {
    ldpp_dout(op, 20) << __func__ << "(): The request need all_access" << dendl;
  }

  vector<ranger_policy::item> allow_policies = policy.allow_policies;
  vector<ranger_policy::item>::iterator allow_iter = allow_policies.begin();
  for (; allow_iter != allow_policies.end(); allow_iter++) {
    ranger_policy::item each_allow = *allow_iter;

    if (!is_item_related(op, s, each_allow)) { continue; }

    if ( ( need_all_access   && (each_allow.read_checked && each_allow.write_checked) ) \
      || ( need_read_access  &&  each_allow.read_checked  ) \
      || ( need_write_access &&  each_allow.write_checked ) )
    {
      is_allowed = true;
      break;
    }
  }

  if (!is_allowed) { return false; }

  ldpp_dout(op, 10) << __func__ << "(): The request is accepted. Try to check exceptions." << dendl;

  vector<ranger_policy::item> allow_exceptions = policy.allow_exceptions;
  vector<ranger_policy::item>::iterator except_iter = allow_exceptions.begin();
  for (; except_iter != allow_exceptions.end(); except_iter++) {
    ranger_policy::item each_except = *except_iter;

    if (!is_item_related(op, s, each_except)) { continue; }

    if ( !( need_all_access   && (!each_except.read_checked && !each_except.write_checked) ) \
      && !( need_read_access  &&  !each_except.read_checked  ) \
      && !( need_write_access &&  !each_except.write_checked ) )
    {
      ldpp_dout(op, 10) << __func__ << "(): The request is caught in allow exception." << dendl;
      return false;
    }
  }

  return true;
}

bool is_authz_denied(RGWOp *& op, req_state * const s, ranger_policy& policy)
{
  bool is_denied = false;

  uint32_t op_mask = op->op_mask();
  ldpp_dout(op, 20) << __func__ << "(): op mask of request = " << op_mask << dendl;

  bool need_read_access  = (op_mask & RGW_OP_TYPE_READ);
  bool need_write_access = (op_mask & RGW_OP_TYPE_MODIFY);
  bool need_all_access   = (need_read_access && need_write_access);

  if (need_read_access) {
    ldpp_dout(op, 20) << __func__ << "(): The request need read_access" << dendl;
  }
  else if (need_write_access) {
    ldpp_dout(op, 20) << __func__ << "(): The request need write_access" << dendl;
  }
  else if (need_all_access) {
    ldpp_dout(op, 20) << __func__ << "(): The request need all_access" << dendl;
  }

  vector<ranger_policy::item> deny_policies = policy.deny_policies;
  vector<ranger_policy::item>::iterator deny_iter = deny_policies.begin();
  for (; deny_iter != deny_policies.end(); deny_iter++) {
    ranger_policy::item each_deny = *deny_iter;

    if (!is_item_related(op, s, each_deny)) { continue; }

    if ( !( need_all_access   && (!each_deny.read_checked && !each_deny.write_checked) ) \
      && !( need_read_access  &&  !each_deny.read_checked  ) \
      && !( need_write_access &&  !each_deny.write_checked ) )
    {
      is_denied = true;
      break;
    }
  }

  if (!is_denied) { return false; }
  ldpp_dout(op, 10) << __func__ << "(): The request is denied. Try to check exceptions." << dendl;

  vector<ranger_policy::item> deny_exceptions = policy.deny_exceptions;
  vector<ranger_policy::item>::iterator except_iter = deny_exceptions.begin();
  for (; except_iter != deny_exceptions.end(); except_iter++) {
    ranger_policy::item each_except = *except_iter;

    if (!is_item_related(op, s, each_except)) { continue; }

    if ( ( need_all_access   && (each_except.read_checked && each_except.write_checked) ) \
      || ( need_read_access  &&  each_except.read_checked  ) \
      || ( need_write_access &&  each_except.write_checked ) )
    {
      ldpp_dout(op, 10) << __func__ << "(): The request is caught in deny exception." << dendl;
      return false;
    }
  }

  return true;
}

int rgw_ranger_authorize(RGWOp *& op, req_state * const s)
{
  // check wheter ranger authorize is needed or not
  const string bucket_owner = s->bucket_owner.get_id().to_str();
  if (bucket_owner == "") {
    ldpp_dout(op, 5) << __func__ << "(): The ranger authorizing is not needed. Skip the steps." << dendl;
    return 0;
  }

  ldpp_dout(op, 5) << __func__ << "(): authorizing request using Ranger" << dendl;

  RGWUserEndpoint endpoint;
  if (!get_ranger_endpoint(endpoint, op, s)) {
    ldpp_dout(op, 2) << __func__ << "(): Failed to parse ranger endpoint of " << bucket_owner << dendl;
    return -ERR_INVALID_REQUEST;
  }

  string url;
  url  = endpoint.url;
  url += "/plugins/policies/service/name/";
  url += bucket_owner;
  url  = regex_replace(url, regex("/+"), "/");
  url  = regex_replace(url, regex(":/"), "://");

  ldpp_dout(op, 10) << __func__ << "(): RANGER URL= " << url.c_str() << dendl;

  // get authentication info for Ranger
  string ranger_user = endpoint.admin_user;
  string ranger_pass = "";

  string endp_admin_pw_path = endpoint.admin_passwd_path;
  if (endp_admin_pw_path.empty()) {
    ranger_pass = endpoint.admin_passwd;
  }
  else {
    ranger_pass = read_secret(endp_admin_pw_path);
    ldpp_dout(op, 30) << __func__ << "(): read ranger admin_password from " << endp_admin_pw_path
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

  vector<ranger_policy> related_policies;
  while (need_continue) {
    int ret;
    bufferlist bl;

    string url_with_offset = url +  "?startIndex=" + to_string(offset);
    RGWHTTPTransceiver req(s->cct, "GET", url_with_offset.c_str(), &bl);

    // set required headers for Ranger request
    req.append_header("Authorization", "Basic " + encoded_bl.to_str());
    req.append_header("Content-Type", "application/json");

    // check if we want to verify Ranger server SSL certificate
    req.set_verify_ssl(endpoint.use_ssl);

    // send request
    ret = req.process();
    if (ret < 0) {
      ldpp_dout(op, 2) << __func__ << "(): Ranger process error:" << bl.c_str() << dendl;
      return ret;
    }

    ldpp_dout(op, 10) << __func__ << "(): received response status=" << req.get_http_status()
                      << ", body=" << bl.c_str() << dendl;

    // check Ranger response
    JSONParser parser;
    if (!parser.parse(bl.c_str(), bl.length())) {
      ldpp_dout(op, 2) << __func__ << "(): Ranger parse error. malformed json"
                       << " (response_str = " << bl.c_str() << ")" << dendl;
      return -EINVAL;
    }

    JSONObj* resultsize_obj = parser.find_obj("resultSize");
    if (resultsize_obj == NULL) {
      ldpp_dout(op, 2) << __func__ << "(): Invalid resultSize of ranger result" << dendl;
      return -EINVAL;
    }

    int result_size;
    decode_json_obj(result_size, resultsize_obj);

    // There are no policies at all
    if (result_size == 0) {
      ldpp_dout(op, 2) << __func__ << "(): Ranger rejecting request because of zero policy" << dendl;
      return -EPERM;
    }

    JSONObj* pagesize_obj = parser.find_obj("pageSize");
    if (pagesize_obj == NULL) {
      ldpp_dout(op, 2) << __func__ << "(): Invalid pageSize of ranger page" << dendl;
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
      ldpp_dout(op, 2) << __func__ << "(): Invalid policies of ranger result" << dendl;
      return -EINVAL;
    }

    vector<string> policies_str = policies_obj->get_array_elements();

    vector<string>::iterator policy_iter = policies_str.begin();
    for (; policy_iter != policies_str.end(); ++policy_iter) {
      ranger_policy policy;
      if (!parse_policy(policy, *policy_iter, op)) {
        ldpp_dout(op, 2) << __func__ << "(): Failed to parse ranger result" << dendl;
        return -EINVAL;
      }

      if (is_policy_related(op, s, policy)) {
        related_policies.push_back(policy);
      }
      else {
        ldpp_dout(op, 5) << __func__ << "(): The '" << policy.id << "' policy is not related. Skip checking." << dendl;
      }
    }
  }

  int deny_policy_id = 0;
  vector<ranger_policy>::iterator deny_policy_iter = related_policies.begin();
  for (; deny_policy_iter != related_policies.end(); ++deny_policy_iter) {
    ranger_policy policy = *deny_policy_iter;
    if (is_authz_denied(op, s, policy)) {
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
    if (is_authz_allowed(op, s, policy)) {
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
