#include "rgw_lineage_atlas_rest.h"
#include "rgw_lineage.h"
#include "rgw_http_client.h"
#include "rgw_multi_del.h"
#include <regex>

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

int RGWLineageAtlasRest::send_curl(const string& method, const string& path, bufferlist * const ret_body_bl, const string& data, bool versioned)
{
  string rest_endpoint = cct->_conf->rgw_lineage_atlas_rest_url;
  string rest_prefix   = cct->_conf->rgw_lineage_atlas_rest_url_prefix;
  string rest_version  = cct->_conf->rgw_lineage_atlas_rest_version;

  string url;
  url  = rest_endpoint;
  url += "/";
  url += rest_prefix;
  url += "/";
  url += (versioned) ? rest_version + "/" : "";
  url += path;
  url  = regex_replace(url, regex("/+"), "/");
  url  = regex_replace(url, regex(":/"), "://");

  dout(20) << __func__ << "(): " << method << " " << url << dendl;

  string admin_user        = cct->_conf->rgw_lineage_atlas_rest_admin_user;
  string admin_passwd      = cct->_conf->rgw_lineage_atlas_rest_admin_password;
  string admin_passwd_path = cct->_conf->rgw_lineage_atlas_rest_admin_password_path;

  if (! admin_passwd_path.empty()) {
    admin_passwd = read_secret(admin_passwd_path);

    dout(20) << __func__ << "(): read admin_password from " << admin_passwd_path << " = " << admin_passwd << dendl;
  }

  bufferlist auth_bl;
  auth_bl.append(admin_user);
  auth_bl.append(":");
  auth_bl.append(admin_passwd);

  bufferlist encoded_bl;
  auth_bl.encode_base64(encoded_bl);

  bufferlist tmp;
  bufferlist* ret_buffer = (ret_body_bl != NULL) ? ret_body_bl : &tmp;

  RGWHTTPTransceiver http_tx(cct, method, url, ret_buffer);

  http_tx.append_header("Authorization", "Basic " + encoded_bl.to_str());

  http_tx.append_header("Content-Type", "application/json");
  http_tx.append_header("Accept", "application/json");

  dout(20) << __func__ << "(): send data = " << data << dendl;

  http_tx.set_post_data(data);

  http_tx.process();

  dout(15) << __func__ << "(): received response status=" << http_tx.get_http_status()
                       << ", body=" << ret_buffer->to_str() << dendl;

  return http_tx.get_http_status();
}

int RGWLineageAtlasRest::search_entities(vector<string> & out, const string qname, const string type_name, bool execlude_deleted_entities)
{
  int count;

  string path;
  path  = "search/basic";
  path += "?query=" + qname;
  path += (type_name.empty()) ? "" : "&typeName=" + type_name;
  path += "&excludeDeletedEntities=";
  path += (execlude_deleted_entities) ? "true" : "false";
  
  dout(25) << __func__ << "(): query path = " << path << dendl;
  
  bufferlist search_ret_body;
  int ret = send_curl("GET", path, &search_ret_body);

  if (ret != 200) {
    dout(10) << __func__ << "(): Failed to get search result form atlas" << dendl;
    return -1;
  }

  JSONParser jp;
  if (! jp.parse(search_ret_body.c_str(), search_ret_body.length())) {
    dout(0) << __func__ << "(): Failed to parse search result" << dendl;
    return -1;
  }

  JSONObjIter count_iter = jp.find_first("approximateCount");
  if (count_iter.end()) {
    dout(10) << __func__ << "(): 'approximateCount' is not exist in search result" << dendl;
    return -1;
  }

  decode_json_obj(count, *count_iter);
  if (count == 0) return count;


  JSONObjIter entity_iter = jp.find_first("entities");
  if (entity_iter.end() || !(*entity_iter)->is_array()) {
    dout(15) << __func__ << "(): Invalid entities of search result" << dendl;
    count = 0;
  }

  out = (*entity_iter)->get_array_elements();

  return count;
}

bool RGWLineageAtlasRest::is_entity_exist_with_qname(const string qualified_name, const string type_name, bool execlude_deleted_entities)
{
  vector<string> entities;
  int count = search_entities(entities, qualified_name, type_name, execlude_deleted_entities);

  return (count > 0);
}

const string RGWLineageAtlasRest::extract_guid_from_entity(const string entity_str)
{
  string guid = "";

  JSONParser jp;
  if (! jp.parse(entity_str.c_str(), entity_str.length()))
  {
    dout(10) << __func__ << "(): Failed to parse entity"
                         << " (entity_str = " << entity_str << ")" << dendl;
    return guid;
  }

  JSONObjIter guid_iter = jp.find_first("guid");
  if (guid_iter.end()) {
    dout(10) << __func__ << "(): Failed to find guid of the entity"
                         << " (entity_str = " << entity_str << ")" << dendl;
    return guid;
  }

  decode_json_obj(guid, *guid_iter);

  return guid;
}

int RGWLineageAtlasRest::query_guid_first_with_qname(string& guid, const string qualified_name, const string type_name, bool execlude_deleted_entities)
{
  vector<string> entities;
  int count = search_entities(entities, qualified_name, type_name, execlude_deleted_entities);

  if (count == 0) {
    dout(20) << __func__ << "(): The search entity not exists." << dendl;
    return 0;
  }
  else if (count < 0) {
    dout(10) << __func__ << "(): Failed atlas query request." << dendl;
    return -1;
  }

  guid = extract_guid_from_entity(*(entities.begin()));

  if (guid.empty()) {
    dout(10) << __func__ << "(): Failed to find guid of the entity." << dendl;
    return -1;
  }

  return 0;
}

int RGWLineageAtlasRest::query_attribute_value(string& value, const string guid, const string attr)
{
  if (guid.empty()) return -1;
  if (attr.empty()) return -1;

  bufferlist entity_ret_body;
  int ret = send_curl("GET", "/entity/guid/" + guid, &entity_ret_body);

  if (ret != 200) {
    dout(10) << __func__ << "(): Failed to get entity result form atlas. guid = " << guid << dendl;
    return -1;
  }

  string body_str = entity_ret_body.to_str();

  JSONParser entity_jp;
  if (! entity_jp.parse(body_str.c_str(), body_str.length()))
  {
    dout(10) << __func__ << "(): Failed to parse entity"
                         << " (body_str = " << body_str << ")" << dendl;
    return -1;
  }

  JSONObjIter entity_iter = entity_jp.find_first("entity");
  if (entity_iter.end()) {
    dout(10) << __func__ << "(): Failed to find 'entity' of the entity"
                         << " (body_str = " << body_str << ")" << dendl;
    return -1;
  }

  string entity_str;
  decode_json_obj(entity_str, *entity_iter);

  JSONParser attrs_jp;
  if (! attrs_jp.parse(entity_str.c_str(), entity_str.length()))
  {
    dout(10) << __func__ << "(): Failed to parse entity"
                         << " (entity_str = " << entity_str << ")" << dendl;
    return -1;
  }

  JSONObjIter attrs_iter = attrs_jp.find_first("attributes");
  if (attrs_iter.end()) {
    dout(10) << __func__ << "(): Failed to find 'attributes' of the entity"
                         << " (entity_str = " << entity_str << ")" << dendl;
    return -1;
  }

  string attrs_str;
  decode_json_obj(attrs_str, *attrs_iter);

  JSONParser target_jp;
  if (! target_jp.parse(attrs_str.c_str(), attrs_str.length()))
  {
    dout(10) << __func__ << "(): Failed to parse attributes"
                         << " (entity_str = " << entity_str << ")" << dendl;
    return -1;
  }

  JSONObjIter target_iter = target_jp.find_first(attr);
  if (target_iter.end()) {
    dout(10) << __func__ << "(): Failed to find '" << attr << "' of the attributes"
                         << " (entity_str = " << entity_str << ")" << dendl;
    return -1;
  }

  decode_json_obj(value, *target_iter);

  return 0;
}

long RGWLineageAtlasRest::time_to_long_msec(lineage_req::time & t)
{
  long ret = 0;

  ret  = t.time_since_epoch().count(); // nanoseconds
  ret /= 1000; // microseconds
  ret /= 1000; // milliseconds

  return ret;
}

int RGWLineageAtlasRest::record_request(lineage_req * const lr, JSONFormattable* in, JSONFormattable* out)
{
  int ret = 0;

  string server_id    = lr->server_id;
  string server_host  = lr->server_host;
  string server_owner = lr->server_owner;
  string server_fsid  = lr->server_fsid;
  string server_addr  = lr->server_addr;

  string server_qname = server_id + "/" + server_fsid;

  string server_guid;
  ret = query_guid_first_with_qname(server_guid, server_qname, "aws_s3_server");
  if (ret != 0) {
    dout(10) << __func__ << "(): Failed to get server guid" << dendl;
    return ret;
  }

  stringstream ss;
  JSONFormatter jf;

  if ( server_guid.empty() ) {
    {
      jf.open_object_section("");
      {
        jf.open_object_section("entity");
        encode_json("typeName", "aws_s3_server", &jf);
        {
          jf.open_object_section("attributes");
          encode_json("name", server_id, &jf);
          encode_json("qualifiedName", server_qname, &jf);
          encode_json("owner", server_owner, &jf);
          encode_json("description", "Request via NES", &jf);
          encode_json("server_name", server_id, &jf);
          encode_json("ip_address", server_addr, &jf);
          encode_json("server_fsid", server_fsid, &jf);
          encode_json("server_host", server_host, &jf);
          jf.close_section(); // attributes
        }
        jf.close_section(); // entity
      }
      jf.close_section(); // json
    }

    jf.flush(ss);
  
    ret = send_curl("POST", "/entity", ss.str());
  
    if (ret != 200) {
      dout(10) << __func__ << "(): Failed to create server entity" << dendl;
      return ret;
    }
  }

  string req_id;
  req_id = lr->req_id; // "tx0000xxx-xxxx-xxxxx-region"
  req_id.erase(0, 2); // "0000xxx-xxxx-xxxxx-region"
  req_id.erase(0, req_id.find_first_not_of('0')); // "xxx-xxxx-xxxxx-region"

  string req_op_type = lr->op_type_str;
  string req_account = lr->account;
  string req_agent   = lr->req_agent;
  string req_addr    = lr->req_addr;
  long   req_time    = time_to_long_msec(lr->req_time);

  ss.str("");
  jf.reset();
  {
    jf.open_object_section("");
    {
      jf.open_object_section("entity");
      encode_json("typeName", "aws_s3_request", &jf);
      {
        jf.open_object_section("attributes");
        encode_json("name", "request-" + req_id, &jf);
        encode_json("qualifiedName", "request-" + req_id, &jf);
        encode_json("description", "Request via NES", &jf);
        encode_json("operation", req_op_type, &jf);
        encode_json("run_as", req_account, &jf);
        encode_json("request_time", req_time, &jf);
        encode_json("request_agent", req_agent, &jf);
        encode_json("requester_address", req_addr, &jf);
        {
          jf.open_object_section("server");
          {
            encode_json("typeName", "aws_s3_server", &jf);
            jf.open_object_section("uniqueAttributes");
            encode_json("qualifiedName", server_qname, &jf);
            jf.close_section(); // uniqueAttributes
          }
          jf.close_section();
        }
        if (in != nullptr) {
          if (in->is_array()) {
            encode_json("inputs", *in, &jf);
          }
          else {
            jf.open_array_section("inputs");
            encode_json("", *in, &jf);
            jf.close_section(); // inputs
          }
        }
        if (out != nullptr) {
          if (out->is_array()) {
            encode_json("outputs", *out, &jf);
          }
          else {
            jf.open_array_section("outputs");
            encode_json("", *out, &jf);
            jf.close_section(); // outputs
          }
        }
        jf.close_section(); // attributes
      }
      jf.close_section(); // entity
    }
    jf.close_section(); // json
  }

  jf.flush(ss);

  ret = send_curl("POST", "/entity", ss.str());

  return ret;
}

int RGWLineageAtlasRest::create_bucket(lineage_req * const lr)
{
  int ret = -1;

  string bucket_name = lr->bucket;
  string account     = lr->account;
  string owner_id    = lr->bucket_owner_id;
  string owner_name  = lr->bucket_owner_name;
  long   ctime       = time_to_long_msec(lr->req_time);
  string region      = lr->zonegroup;

  JSONFormatter jf;
  {
    jf.open_object_section("");
    {
      jf.open_object_section("entity");
      {
        encode_json("typeName", "aws_s3_v2_bucket", &jf);
        {
          jf.open_object_section("attributes");
          encode_json("name", bucket_name, &jf);
          encode_json("qualifiedName", make_s3_qname(bucket_name), &jf);
          encode_json("accountId", account, &jf);
          encode_json("ownerId", owner_id, &jf);
          encode_json("ownerName", owner_name, &jf);
          encode_json("description", "Request via NES", &jf);
          encode_json("creationTime", ctime, &jf);
          encode_json("region", region, &jf);
          jf.close_section(); // attributes
        }
      }
      jf.close_section(); // entity
    }
    jf.close_section(); // json
  }

  stringstream ss;
  jf.flush(ss);

  ret = send_curl("POST", "/entity", ss.str());

  if (ret != 200) {
    dout(10) << __func__ << "(): Failed to create '" << bucket_name << "' bucket entity" << dendl;
  }

  return ret;
}

int RGWLineageAtlasRest::create_object(lineage_req * const lr)
{
  int ret = -1;

  string bucket_name = lr->bucket;
  string object_name = lr->object;
  string account     = lr->account;
  string owner_id    = lr->object_owner_id;
  string owner_name  = lr->object_owner_name;
  long   mtime       = time_to_long_msec(lr->req_time);
  string region      = lr->zonegroup;
  long   size        = lr->object_size;
  string etag        = lr->object_etag;

  if (! is_entity_exist_with_qname(make_s3_qname(bucket_name), "aws_s3_v2_bucket")) {
    ret = create_bucket(lr);
    if (ret != 200) {
      dout(10) << __func__ << "(): Failed to create dummy bucket '" << bucket_name << "'" << dendl;
      return ret;
    }
  }

  JSONFormatter jf;
  {
    jf.open_object_section("");
    {
      jf.open_array_section("entities");
      {
        jf.open_object_section(""); // entities[0]
        encode_json("typeName", "aws_s3_v2_object", &jf);
        {
          jf.open_object_section("attributes");
          encode_json("name", object_name, &jf);
          encode_json("qualifiedName", make_s3_qname(bucket_name, object_name), &jf);
          encode_json("size", size, &jf);
          encode_json("accountId", account, &jf);
          encode_json("ownerId", owner_id, &jf);
          encode_json("ownerName", owner_name, &jf);
          encode_json("description", "Request via NES", &jf);
          encode_json("lastModifiedTime", mtime, &jf);
          encode_json("bucketName", bucket_name, &jf);
          encode_json("region", region, &jf);
          encode_json("eTag", etag, &jf);
          {
            jf.open_object_section("container");
            encode_json("typeName", "aws_s3_v2_bucket", &jf);
            {
              jf.open_object_section("uniqueAttributes");
              encode_json("qualifiedName", make_s3_qname(bucket_name), &jf);
              jf.close_section(); // uniqueAttributes
            }
            jf.close_section(); // container
          }
          jf.close_section(); // attributes
        }
        jf.close_section(); // entities[0]
      }
      if (record_external_in) {
        jf.open_object_section(""); // entities[1]
        encode_json("typeName", "fs_path", &jf);
        {
          jf.open_object_section("attributes");
          encode_json("name", "external_in", &jf);
          encode_json("qualifiedName", "external_in", &jf);
          encode_json("description", "object input from external source", &jf);
          encode_json("path", "external_in", &jf);
          jf.close_section(); // attributes
        }
        jf.close_section(); // entities[1]
      }
      jf.close_section(); // entities
    }
    jf.close_section(); // json
  }

  stringstream ss;
  jf.flush(ss);

  ret = send_curl("POST", "/entity/bulk", ss.str());
  if (ret != 200) {
    dout(10) << __func__ << "(): Failed to create '" << bucket_name
                         << "/" << object_name << "' object entity" << dendl;
  }

  return ret;
}

int RGWLineageAtlasRest::atlas_init_definition()
{
  int ret = 0;

  JSONFormatter jf;
  {
    jf.open_object_section("");
    {
      jf.open_array_section("entityDefs");
      {
        jf.open_object_section(""); // entityDefs[0]
        {
          jf.open_array_section("superTypes");
          encode_json("", "Infrastructure", &jf);
          jf.close_section(); // superTypes
        }
        encode_json("name", "aws_s3_server", &jf);
        encode_json("category", "ENTITY", &jf);
        encode_json("serviceType", "aws", &jf);
        encode_json("description", "a type definition for server machine", &jf);
        encode_json("typeVersion", "1.0", &jf);
        {
          jf.open_array_section("attributeDefs");
          {
            jf.open_object_section(""); // attributeDefs[0]
            encode_json("name", "server_name", &jf);
            encode_json("typeName", "string", &jf);
            encode_json("isOptional", false, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", true, &jf);
            encode_json("isIndexable", true, &jf);
            jf.close_section(); // attributeDefs[0]
          }
          {
            jf.open_object_section(""); // attributeDefs[1]
            encode_json("name", "ip_address", &jf);
            encode_json("typeName", "string", &jf);
            encode_json("isOptional", false, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", false, &jf);
            encode_json("isIndexable", true, &jf);
            jf.close_section(); // attributeDefs[1]
          }
          {
            jf.open_object_section(""); // attributeDefs[2]
            encode_json("name", "server_host", &jf);
            encode_json("typeName", "string", &jf);
            encode_json("isOptional", true, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", false, &jf);
            encode_json("isIndexable", true, &jf);
            jf.close_section(); // attributeDefs[2]
          }
          {
            jf.open_object_section(""); // attributeDefs[3]
            encode_json("name", "server_fsid", &jf);
            encode_json("typeName", "string", &jf);
            encode_json("isOptional", true, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", false, &jf);
            encode_json("isIndexable", true, &jf);
            jf.close_section(); // attributeDefs[3]
          }
          jf.close_section(); // attributeDefs
        }
        jf.close_section(); // entityDefs[0]
      }
      {
        jf.open_object_section(""); // entityDefs[1]
        {
          jf.open_array_section("superTypes");
          encode_json("", "Process", &jf);
          jf.close_section(); // superTypes
        }
        encode_json("name", "aws_s3_request", &jf);
        encode_json("category", "ENTITY", &jf);
        encode_json("serviceType", "aws", &jf);
        encode_json("description", "a type definition for AWS tools", &jf);
        encode_json("typeVersion", "1.0", &jf);
        {
          jf.open_array_section("attributeDefs");
          {
            jf.open_object_section(""); // attributeDefs[0]
            encode_json("name", "operation", &jf);
            encode_json("typeName", "string", &jf);
            encode_json("isOptional", true, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", false, &jf);
            encode_json("isIndexable", false, &jf);
            jf.close_section(); // attributeDefs[0]
          }
          {
            jf.open_object_section(""); // attributeDefs[1]
            encode_json("name", "run_as", &jf);
            encode_json("typeName", "string", &jf);
            encode_json("isOptional", false, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", false, &jf);
            encode_json("isIndexable", true, &jf);
            jf.close_section(); // attributeDefs[1]
          }
          {
            jf.open_object_section(""); // attributeDefs[2]
            encode_json("name", "request_time", &jf);
            encode_json("typeName", "date", &jf);
            encode_json("isOptional", false, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", false, &jf);
            encode_json("isIndexable", true, &jf);
            jf.close_section(); // attributeDefs[2]
          }
          {
            jf.open_object_section(""); // attributeDefs[3]
            encode_json("name", "request_agent", &jf);
            encode_json("typeName", "string", &jf);
            encode_json("isOptional", true, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", false, &jf);
            encode_json("isIndexable", true, &jf);
            jf.close_section(); // attributeDefs[3]
          }
          {
            jf.open_object_section(""); // attributeDefs[4]
            encode_json("name", "requester_address", &jf);
            encode_json("typeName", "string", &jf);
            encode_json("isOptional", true, &jf);
            encode_json("cardinality", "SINGLE", &jf);
            encode_json("valuesMinCount", 1, &jf);
            encode_json("valuesMaxCount", 1, &jf);
            encode_json("isUnique", false, &jf);
            encode_json("isIndexable", true, &jf);
            jf.close_section(); // attributeDefs[4]
          }
          jf.close_section(); // attributeDefs
        }
        jf.close_section(); // entityDefs[1]
      }
      jf.close_section(); // entityDefs
    }
    {
      jf.open_array_section("relationshipDefs");
      {
        jf.open_object_section(""); // relationshipDefs[0]
        encode_json("name", "aws_s3_request_server", &jf);
        encode_json("serviceType", "aws", &jf);
        encode_json("typeVersion", "1.0", &jf);
        encode_json("relationshipCategory", "ASSOCIATION", &jf);
        {
          jf.open_object_section("endDef1");
          encode_json("name", "requests", &jf);
          encode_json("type", "aws_s3_server", &jf);
          encode_json("cardinality", "SET", &jf);
          jf.close_section(); // endDef1
        }
        {
          jf.open_object_section("endDef2");
          encode_json("name", "server", &jf);
          encode_json("type", "aws_s3_request", &jf);
          encode_json("cardinality", "SINGLE", &jf);
          jf.close_section(); // endDef2
        }
        encode_json("propagateTags", "NONE", &jf);
        jf.close_section(); // relationshipDefs[0]
      }
      jf.close_section(); // relationshipDefs
    }
    jf.close_section(); // json
  }
  
  stringstream ss;
  jf.flush(ss);

  ret = send_curl("POST", "/types/typedefs", ss.str());

  if (ret == 409) { ret = 200; } //* return 409 if already exist*/ 

  if (ret != 200) {
    dout(10) << __func__ << "(): Failed to initialize atlas entity definition" << dendl;
  }

  return ret;
}

int RGWLineageAtlasRest::atlas_bucket_creation(lineage_req * const lr)
{
  int ret = 0;

  ret = create_bucket(lr);
  if (ret != 200) return ret;

  string bucket_name = lr->bucket;

  JSONFormattable out_jf;
  {
    out_jf.open_object_section("");
    encode_json("typeName", "aws_s3_v2_bucket", &out_jf);
    {
      out_jf.open_object_section("uniqueAttributes");
      encode_json("qualifiedName", make_s3_qname(bucket_name), &out_jf);
      out_jf.close_section(); // uniqueAttributes
    }
    out_jf.close_section(); // ""
  }

  return record_request(lr, NULL, &out_jf);
}

int RGWLineageAtlasRest::atlas_bucket_deletion(lineage_req * const lr)
{
  int ret = 0;

  string bucket_name = lr->bucket;

  string bucket_guid;
  ret = query_guid_first_with_qname(bucket_guid, make_s3_qname(bucket_name), "aws_s3_v2_bucket");
  if (ret != 0) {
    dout(10) << __func__ << "(): Failed to get guid" << dendl;
    return ret;
  }

  if (bucket_guid.empty()) {
    dout(20) << __func__ << "(): The '" << bucket_name << "' bucket was already deleted!" << dendl;
    return 200;
  }

  JSONFormattable in_jf;
  {
    in_jf.open_object_section(""); // {
    encode_json("typeName", "aws_s3_v2_bucket", &in_jf);
    encode_json("guid", bucket_guid, &in_jf);
    in_jf.close_section(); // }
  }

  ret = record_request(lr, &in_jf, NULL);
  if (ret != 200) {
    dout(10) << __func__ << "(): Failed to record request before delete bucket entity" << dendl;
    return ret;
  }

  ret = send_curl("DELETE", "/entity/guid/"+bucket_guid);

  return ret;
}

int RGWLineageAtlasRest::atlas_object_creation(lineage_req * const lr)
{
  int ret = -1;

  ret = create_object(lr);
  if (ret != 200) return ret;

  string bucket_name = lr->bucket;
  string object_name = lr->object;

  JSONFormattable in_jf;
  if (record_external_in) {
    in_jf.open_object_section(""); // {
    encode_json("typeName", "fs_path", &in_jf);
    {
      in_jf.open_object_section("uniqueAttributes");
      encode_json("qualifiedName", "external_in", &in_jf);
      in_jf.close_section(); // uniqueAttributes
    }
    in_jf.close_section(); // }
  }

  JSONFormattable out_jf;
  {
    out_jf.open_object_section(""); // {
    encode_json("typeName", "aws_s3_v2_object", &out_jf);
    {
      out_jf.open_object_section("uniqueAttributes");
      encode_json("qualifiedName", make_s3_qname(bucket_name, object_name), &out_jf);
      out_jf.close_section(); // uniqueAttributes
    }
    out_jf.close_section(); // }
  }

  return record_request(lr, &in_jf, &out_jf);
}

int RGWLineageAtlasRest::atlas_object_gotten(lineage_req * const lr)
{
  int ret = -1;

  string bucket_name = lr->bucket;
  string object_name = lr->object;

  if (! is_entity_exist_with_qname(make_s3_qname(bucket_name, object_name), "aws_s3_v2_object")) {
    ret = create_object(lr);
    if (ret != 200) {
      dout(10) << __func__ << "(): Failed to create dummy object '" << object_name << "'" << dendl;
      return ret;
    }
  }

  if (record_external_out) {
    JSONFormatter jf;
    {
      jf.open_object_section("");
      {
        jf.open_object_section("entity");
        encode_json("typeName", "fs_path", &jf);
        {
          jf.open_object_section("attributes");
          encode_json("name", "external_out", &jf);
          encode_json("qualifiedName", "external_out", &jf);
          encode_json("description", "object output to external destination", &jf);
          encode_json("path", "external_out", &jf);
          jf.close_section(); // attributes
        }
        jf.close_section(); // entity
      }
      jf.close_section(); // json
    }
  
    stringstream ss;
    jf.flush(ss);
  
    ret = send_curl("POST", "/entity", ss.str());
    if (ret != 200) {
      dout(10) << __func__ << "(): Failed to create 'external_out' entity" << dendl;
      return ret;
    }
  }

  JSONFormattable in_jf;
  {
    in_jf.open_object_section(""); // {
    encode_json("typeName", "aws_s3_v2_object", &in_jf);
    {
      in_jf.open_object_section("uniqueAttributes");
      encode_json("qualifiedName", make_s3_qname(bucket_name, object_name), &in_jf);
      in_jf.close_section(); // uniqueAttributes
    }
    in_jf.close_section(); // }
  }

  JSONFormattable out_jf;
  if (record_external_out) {
    out_jf.open_object_section(""); // {
    encode_json("typeName", "fs_path", &out_jf);
    {
      out_jf.open_object_section("uniqueAttributes");
      encode_json("qualifiedName", "external_out", &out_jf);
      out_jf.close_section(); // uniqueAttributes
    }
    out_jf.close_section(); // }
  }

  return record_request(lr, &in_jf, &out_jf);
}

int RGWLineageAtlasRest::atlas_object_deletion(lineage_req * const lr)
{
  int ret = -1;

  string bucket_name = lr->bucket;
  string object_name = lr->object;

  string object_guid;
  ret = query_guid_first_with_qname(object_guid, make_s3_qname(bucket_name, object_name), "aws_s3_v2_object");
  if (ret != 0) {
    dout(10) << __func__ << "(): Failed to get guid of " << bucket_name << "/" << object_name << dendl;
    return ret;
  }

  if (object_guid.empty()) {
    dout(20) << "The '" << object_name << "' object was already deleted!" << dendl;
    return ret;
  }

  JSONFormattable in_jf;
  {
    in_jf.open_object_section(""); // {
    encode_json("typeName", "aws_s3_v2_object", &in_jf);
    encode_json("guid", object_guid, &in_jf);
    in_jf.close_section(); // }
  }

  ret = record_request(lr, &in_jf, NULL);

  if (ret != 200) {
    dout(10) << __func__ << "(): Failed to record request before delete object entity" << dendl;
    return ret;
  }

  ret = send_curl("DELETE", "/entity/guid/"+object_guid);

  return ret;
}

int RGWLineageAtlasRest::atlas_object_multi_deletion(lineage_req * const lr)
{
  int ret = 0;

  bufferlist data = lr->data;
  if (data.length() == 0) {
    dout(10) << __func__ << "(): invalid MultiDelete data (data = "
                         << data.to_str() << ")" << dendl;
    return ret;
  }

  dout(20) << __func__ << "(): multi object delete body = " << data.to_str() << dendl;

  RGWMultiDelXMLParser mdxp;
  if (! mdxp.init()) {
    dout(10) << __func__ << "(): Failed to init XMLParser" << dendl;
    return -1;
  }

  if (! mdxp.parse(data.c_str(), data.length(), 1)) {
    dout(10) << __func__ << "(): Failed to parse MultiDelete data (data = "
                         << data.to_str() << ")" << dendl;
    return -1;
  }

  RGWMultiDelDelete *multi_delete;
  multi_delete = static_cast<RGWMultiDelDelete *>(mdxp.find_first("Delete"));

  vector<rgw_obj_key>::iterator iter = multi_delete->objects.begin();
  for (; iter != multi_delete->objects.end(); ++iter) {
    lineage_req each_lr;
    each_lr = *lr;
    each_lr.object = (*iter).name;

    ret = atlas_object_deletion(&each_lr);
    if (ret != 200) { 
      dout(10) << __func__ << "(): Failed to delete '"
                           << each_lr.object << "' object" << dendl;
      continue;
    }
  }

  return ret;
}

int RGWLineageAtlasRest::atlas_object_copy(lineage_req * const lr)
{
  int ret = -1;

  stringstream ss;

  string src_bucket_name = lr->src_bucket;
  string src_object_name = lr->src_object;

  string src_qname = make_s3_qname(src_bucket_name, src_object_name);
  if (! is_entity_exist_with_qname(src_qname, "aws_s3_v2_object")) {
    lineage_req dummy_put_obj;

    dummy_put_obj.bucket = src_bucket_name;

    dummy_put_obj.object      = src_object_name;
    dummy_put_obj.object_size = lr->object_size;

    dummy_put_obj.object_owner_id   = lr->object_owner_id;
    dummy_put_obj.object_owner_name = lr->object_owner_name;

    dummy_put_obj.zonegroup = lr->zonegroup;

    ret = create_object(&dummy_put_obj);
    if (ret != 200) {
      dout(10) << __func__ << "(): Failed to create dummy object '" << src_object_name << "'" << dendl;
      return ret;
    }
  }
  else if (lr->object_size == 0) {
    string found_guid;
    query_guid_first_with_qname(found_guid, src_qname, "aws_s3_v2_object");

    string queried_size;
    query_attribute_value(queried_size, found_guid, "size");

    lr->object_size = (queried_size.empty()) ? 0 : stol(queried_size);
  }

  ret = create_object(lr);
  if (ret != 200) {
    dout(10) << __func__ << "(): Failed to create '" << lr->object << "' object entity" << dendl;
    return ret;
  }

  JSONFormattable in_jf;
  {
    in_jf.open_object_section(""); // {
    encode_json("typeName", "aws_s3_v2_object", &in_jf);
    {
      in_jf.open_object_section("uniqueAttributes");
      encode_json("qualifiedName", make_s3_qname(src_bucket_name, src_object_name), &in_jf);
      in_jf.close_section(); // uniqueAttributes
    }
    in_jf.close_section(); // }
  }

  JSONFormattable out_jf;
  {
    out_jf.open_object_section(""); // {
    encode_json("typeName", "aws_s3_v2_object", &out_jf);
    {
      out_jf.open_object_section("uniqueAttributes");
      encode_json("qualifiedName", make_s3_qname(lr->bucket, lr->object), &out_jf);
      out_jf.close_section(); // uniqueAttributes
    }
    out_jf.close_section(); // }
  }

  return record_request(lr, &in_jf, &out_jf);
}

bool RGWLineageAtlasRest::is_atlas_health_ok() {
  int ret = send_curl("GET", "/admin/version", false);

  return ( ret == 200 );
}

