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

#ifndef CEPH_MMONCOMMANDACK_H
#define CEPH_MMONCOMMANDACK_H

#include "messages/PaxosServiceMessage.h"

using TOPNSPC::common::cmdmap_from_json;
using TOPNSPC::common::cmd_getval;

class MMonCommandAck : public PaxosServiceMessage {
public:
  std::vector<std::string> cmd;
  errorcode32_t r;
  std::string rs;

  MMonCommandAck() : PaxosServiceMessage{MSG_MON_COMMAND_ACK, 0} {}
  MMonCommandAck(const std::vector<std::string>& c, int _r, std::string s, version_t v) :
    PaxosServiceMessage{MSG_MON_COMMAND_ACK, v},
    cmd(c), r(_r), rs(s) { }
private:
  ~MMonCommandAck() override {}

public:
  std::string_view get_type_name() const override { return "mon_command"; }
  void print(std::ostream& o) const override {
    cmdmap_t cmdmap;
    stringstream ss;
    string prefix;
    cmdmap_from_json(cmd, &cmdmap, ss);
    cmd_getval(cmdmap, "prefix", prefix);
    // Some config values contain sensitive data, so don't log them
    o << "mon_command_ack(";
    if (prefix == "config set") {
      string name;
      cmd_getval(cmdmap, "name", name);
      o << "[{prefix=" << prefix
        << ", name=" << name << "}]"
        << "=" << r << " " << rs << " v" << version << ")";
    } else if (prefix == "config-key set") {
      string key;
      cmd_getval(cmdmap, "key", key);
      o << "[{prefix=" << prefix << ", key=" << key << "}]"
        << "=" << r << " " << rs << " v" << version << ")";
    } else {
      o << cmd;
    }
    o << "=" << r << " " << rs << " v" << version << ")";
  }
  
  void encode_payload(uint64_t features) override {
    using ceph::encode;
    paxos_encode();
    encode(r, payload);
    encode(rs, payload);
    encode(cmd, payload);
  }
  void decode_payload() override {
    using ceph::decode;
    auto p = payload.cbegin();
    paxos_decode(p);
    decode(r, p);
    decode(rs, p);
    decode(cmd, p);
  }
private:
  template<class T, typename... Args>
  friend boost::intrusive_ptr<T> ceph::make_message(Args&&... args);
};

#endif
