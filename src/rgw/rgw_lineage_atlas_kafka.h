#include "rgw_lineage_interfaces.h"

class RGWLineageAtlasKafka: public RGWLineageAtlasImpl {
public:
  RGWLineageAtlasKafka(CephContext* const _cct): RGWLineageAtlasImpl(_cct) {} 

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
