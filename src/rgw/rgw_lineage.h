#include "rgw_lineage_interfaces.h"
#include "common/Thread.h"

class RGWLineageManager: public Thread {
private:
  CephContext* const cct;
  RGWLineage* rgw_lineage;
  queue<lineage_req> lr_queue;

  string thread_name = "rgw_lineage_man";
  bool down_flag = false;

  bool record_getobj = false;

  int retries  = 1;
  int wait_sec = 3;

  bool can_init = false;

  const string optype_to_string(RGWOpType op_type);
  const string get_etag(RGWOp * op);
  const bufferlist get_data(RGWOp* op);
  long get_size(req_state* rs, RGWOp * op);

  void * entry() override;

public:
  RGWLineageManager(CephContext* const _cct);

  ~RGWLineageManager();

  void enqueue(req_state* rs, RGWOp * op = NULL);

  void start();
  void stop();
};
