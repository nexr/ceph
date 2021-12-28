#include "rgw_lineage_interfaces.h"

class RGWLineageAtlasRest: public RGWLineageAtlasImpl {
private:
  int send_curl(const string& method,
    const string& path,
    bufferlist * const ret_body_bl = NULL,
    const string& data = string(),
    bool versioned = true);
  int send_curl(const string& method, const string& path, const string& data, bool versioned = true) {
    return send_curl(method, path, NULL, data, versioned);
  };
  int send_curl(const string& method, const string& path, bool versioned) {
    return send_curl(method, path, NULL, string(), versioned);
  };

  int search_entities(
    vector<string> & out,
    const string qualified_name,
    const string type_name = string(),
    bool execlude_deleted_entities = true);

  bool is_entity_exist_with_qname(
    const string qualified_name,
    const string type_name = string(),
    bool execlude_deleted_entities = true);

  const string extract_guid_from_entity(const string entity_str);

  int query_guid_first_with_qname(
    string& guid,
    const string qualified_name,
    const string type_name = string(),
    bool execlude_deleted_entities = true);

  int query_attribute_value(
    string& value,
    const string guid,
    const string attr);

  long time_to_long_msec(lineage_req::time & t);

  int record_request(lineage_req * const lr,
    JSONFormattable* in,
    JSONFormattable* out);

  int create_bucket(lineage_req * const lr);
  int create_object(lineage_req * const lr);

public:
  RGWLineageAtlasRest(CephContext* const _cct): RGWLineageAtlasImpl(_cct) {} 

  int atlas_init_definition() override;
  int atlas_bucket_creation(lineage_req * const lr) override;
  int atlas_bucket_deletion(lineage_req * const lr) override;
  int atlas_object_creation(lineage_req * const lr) override;
  int atlas_object_gotten(lineage_req * const lr) override;
  int atlas_object_deletion(lineage_req * const lr) override;
  int atlas_object_multi_deletion(lineage_req * const lr) override;
  int atlas_object_copy(lineage_req * const lr) override;

  bool is_atlas_health_ok() override;
};

