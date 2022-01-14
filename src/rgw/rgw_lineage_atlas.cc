#include "rgw_lineage_atlas.h"
#include "rgw_lineage_atlas_rest.h"
#include "rgw_lineage_atlas_kafka.h"

RGWLineageAtlas::RGWLineageAtlas(CephContext* const _cct)
{
  cct = _cct;

  string atlas_mode = cct->_conf->rgw_lineage_atlas_mode;
  if (atlas_mode.compare("rest") == 0) {
    impl_type = RGWLineageAtlas::ImplType::ATLAS_IMPL_TYPE_REST;
    impl      = new RGWLineageAtlasRest(cct);
  }
  else if (atlas_mode.compare("kafka") == 0) {
    impl_type = RGWLineageAtlas::ImplType::ATLAS_IMPL_TYPE_KAFKA;
    impl      = new RGWLineageAtlasKafka(cct);
  }
  else {
    dout(0) << __func__ << "(): Invalid atlas implementation"
                        << " (rgw_lineage_atlas_mode = " << atlas_mode << ")"
                        << dendl;
  }
}

RGWLineageAtlas::~RGWLineageAtlas()
{
  if (impl != NULL) {
    delete impl;
  }
}

int RGWLineageAtlas::apply_lineage_init_definition(const string tenant)
{
  return impl->atlas_init_definition(tenant);
}

int RGWLineageAtlas::apply_lineage_bucket_creation(lineage_req * const lr, const string tenant)
{
  return impl->atlas_bucket_creation(lr, tenant);
}

int RGWLineageAtlas::apply_lineage_bucket_deletion(lineage_req * const lr, const string tenant)
{
  return impl->atlas_bucket_deletion(lr, tenant);
}

int RGWLineageAtlas::apply_lineage_object_creation(lineage_req * const lr, const string tenant)
{
  return impl->atlas_object_creation(lr, tenant);
}

int RGWLineageAtlas::apply_lineage_object_gotten(lineage_req * const lr, const string tenant)
{
  return impl->atlas_object_gotten(lr, tenant);
}

int RGWLineageAtlas::apply_lineage_object_deletion(lineage_req * const lr, const string tenant)
{
  return impl->atlas_object_deletion(lr, tenant);
}

int RGWLineageAtlas::apply_lineage_object_multi_deletion(lineage_req * const lr, const string tenant)
{
  return impl->atlas_object_multi_deletion(lr, tenant);
}

int RGWLineageAtlas::apply_lineage_object_copy(lineage_req * const lr, const string tenant)
{
  return impl->atlas_object_copy(lr, tenant);
}

bool RGWLineageAtlas::is_lineage_health_ok(const string tenant)
{
  return impl->is_atlas_health_ok(tenant);
}
