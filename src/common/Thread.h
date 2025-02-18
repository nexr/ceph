// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2011 New Dream Network
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */


#ifndef CEPH_THREAD_H
#define CEPH_THREAD_H

#include <functional>
#include <string_view>
#include <system_error>
#include <thread>

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

#include "include/compat.h"

extern pid_t ceph_gettid();

class Thread {
 private:
  pthread_t thread_id;
  pid_t pid;
  int cpuid;
  const char *thread_name;

  void *entry_wrapper();

 public:
  Thread(const Thread&) = delete;
  Thread& operator=(const Thread&) = delete;

  Thread();
  virtual ~Thread();

 protected:
  virtual void *entry() = 0;

 private:
  static void *_entry_func(void *arg);

 public:
  const pthread_t &get_thread_id() const;
  pid_t get_pid() const { return pid; }
  bool is_started() const;
  bool am_self() const;
  int kill(int signal);
  int try_create(size_t stacksize);
  void create(const char *name, size_t stacksize = 0);
  int join(void **prval = 0);
  int detach();
  int set_affinity(int cpuid);
};

// Functions for with std::thread

void set_thread_name(std::thread& t, const std::string& s);
std::string get_thread_name(const std::thread& t);
void kill(std::thread& t, int signal);

template<typename Fun, typename... Args>
std::thread make_named_thread(std::string_view n,
			      Fun&& fun,
			      Args&& ...args) {

  return std::thread([n = std::string(n)](auto&& fun, auto&& ...args) {
		       ceph_pthread_setname(pthread_self(), n.data());
		       std::invoke(std::forward<Fun>(fun),
				   std::forward<Args>(args)...);
		     }, std::forward<Fun>(fun), std::forward<Args>(args)...);
}

// The "void" ReturnType is not implemented... Use "void*" instaed.
template<typename ReturnType, typename ... Params>
class ThreadLambda: public Thread {
private:
  const char* op_thread_name = "thread_op";

  bool  done = false;
  bool* done_track = NULL;

  using Lambda = std::function<ReturnType (Params ...)>;
  Lambda lambda = NULL;

  ReturnType result;
  ReturnType* result_track = NULL;

  using ParamTuple = std::tuple<Params...>;
  ParamTuple params;

public:

  ThreadLambda() {}
  ThreadLambda(Lambda&& _lambda) : lambda(_lambda) {}
  ThreadLambda(Lambda&& _lambda, Params... _params) : lambda(_lambda), params(make_tuple(_params...)) {}
  ~ThreadLambda() {
    if (is_started()) {
      stop();
    }
  }

  void set_lambda(Lambda&& _lambda) { lambda = _lambda; }
  void set_param(Params... _params) { params = std::make_tuple(_params...); }
  void set_done_track(bool* _done_track) { done_track = _done_track; }
  void set_result_track(ReturnType* _result_track) { result_track = _result_track; }

  bool is_done() { return done; }
  bool reset_done() {
    if (done) {
      stop();

      done = false;

      return true;
    }
    else {
      return false;
    }
  }

  ParamTuple get_param() { return params; }
  ReturnType get_result() { return result; }

  void * entry() override
  {
    if (done_track != NULL) {
      *done_track = false;
    }

    result = process(params);
    done = true;

    if (result_track != NULL) {
      *result_track = result;
      result_track = NULL;
    }

    if (done_track != NULL) {
      *done_track = true;
      done_track = NULL;
    }

    return NULL;
  }

  template <typename Tuple>
  ReturnType process(Tuple const& tuple)
  {
    return process(tuple, std::make_index_sequence<std::tuple_size<Tuple>::value>());
  }

  template <typename Tuple, std::size_t... I>
  ReturnType process(Tuple const& tuple, std::index_sequence<I...>)
  {
    return lambda(std::get<I>(tuple)...);
  }

  void start() {
    create(op_thread_name);
  }

  void restart() {
    stop();

    done = false;

    start();
  }

  void stop() { if (is_started()) { join(); } }

  bool wait_done(int usec_wait = -1)
  {
    if (lambda == NULL) { return true; }

    if (!is_started()) { return true; }

    int usec_taken = 0;
    while (!done) {
      if (usec_wait != -1 && usec_wait <= usec_taken++) { break; }
      usleep(1);
    }

    return done;
  }
};

#endif
