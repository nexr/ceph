#include "rgw_lineage_interfaces.h"

class RGWLineageAtlas : public RGWLineage
{
public:
  enum ImplType {
    ATLAS_IMPL_TYPE_REST = 0,
    ATLAS_IMPL_TYPE_KAFKA = 1,
  };

private:
  RGWLineageAtlasImpl * impl;
  ImplType impl_type;

public:
  RGWLineageAtlas(CephContext* const _cct);
  ~RGWLineageAtlas() override;

  ImplType get_impl_type() { return impl_type; }

  int apply_lineage_init_definition(const string tenant) override;

  int apply_lineage_bucket_creation(lineage_req * const lr, const string tenant) override;
  int apply_lineage_bucket_deletion(lineage_req * const lr, const string tenant) override;
  int apply_lineage_object_creation(lineage_req * const lr, const string tenant) override;
  int apply_lineage_object_gotten(lineage_req * const lr, const string tenant) override;
  int apply_lineage_object_deletion(lineage_req * const lr, const string tenant) override;
  int apply_lineage_object_multi_deletion(lineage_req * const lr, const string tenant) override;
  int apply_lineage_object_copy(lineage_req * const lr, const string tenant) override;

  bool is_lineage_health_ok(const string tenant) override;
};
