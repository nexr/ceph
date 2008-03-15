// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

/*
 * Placement Group Monitor. Placement Groups are logical sets of objects
 * that are replicated by the same set of devices.
 */

#ifndef __PGMONITOR_H
#define __PGMONITOR_H

#include <map>
#include <set>
using namespace std;

#include "include/types.h"
#include "msg/Messenger.h"
#include "PaxosService.h"

#include "PGMap.h"

class MPGStats;
class MStatfs;

class PGMonitor : public PaxosService {
public:

private:
  PGMap pg_map;
  PGMap::Incremental pending_inc;

  void create_initial();
  bool update_from_paxos();
  void create_pending();  // prepare a new pending
  void encode_pending(bufferlist &bl);  // propose pending update to peers

  void committed();

  bool preprocess_query(Message *m);  // true if processed.
  bool prepare_update(Message *m);

  bool prepare_pg_stats(MPGStats *stats);

  void handle_statfs(MStatfs *statfs);

  void print_summary_stats(int dbl=5);

  map<int,utime_t> last_sent_pg_create;  // per osd throttle

 public:
  PGMonitor(Monitor *mn, Paxos *p) : PaxosService(mn, p) { }
  
  void tick();  // check state, take actions


  void register_new_pgs();
  void send_pg_creates();

};

#endif
