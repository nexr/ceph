#ifndef RGW_RANGER_H
#define RGW_RANGER_H

#include "rgw_common.h"
#include "rgw_op.h"

/* authorize request using Ranger */
int rgw_ranger_authorize(RGWOp*& op, req_state* s);

#endif /* RGW_RANGER_H */
