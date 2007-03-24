// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
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

#include "MDS.h"
#include "Server.h"
#include "Locker.h"
#include "MDCache.h"
#include "MDLog.h"
#include "Migrator.h"
#include "MDBalancer.h"
//#include "Renamer.h"
#include "AnchorClient.h"

#include "msg/Messenger.h"

#include "messages/MClientMount.h"
#include "messages/MClientMountAck.h"
#include "messages/MClientRequest.h"
#include "messages/MClientReply.h"

#include "messages/MLock.h"

#include "messages/MDentryUnlink.h"
#include "messages/MInodeLink.h"

#include "events/EString.h"
#include "events/EUpdate.h"
#include "events/EMount.h"

#include "include/filepath.h"
#include "common/Timer.h"
#include "common/Logger.h"
#include "common/LogType.h"

#include <errno.h>
#include <fcntl.h>

#include <list>
#include <iostream>
using namespace std;

#include "config.h"
#undef dout
#define  dout(l)    if (l<=g_conf.debug || l <= g_conf.debug_mds) cout << g_clock.now() << " mds" << mds->get_nodeid() << ".server "
#define  derr(l)    if (l<=g_conf.debug || l <= g_conf.debug_mds) cout << g_clock.now() << " mds" << mds->get_nodeid() << ".server "


void Server::dispatch(Message *m) 
{
  // active?
  if (!mds->is_active()) {
    dout(3) << "not active yet, waiting" << endl;
    mds->queue_waitfor_active(new C_MDS_RetryMessage(mds, m));
    return;
  }

  switch (m->get_type()) {
  case MSG_CLIENT_MOUNT:
    handle_client_mount((MClientMount*)m);
    return;
  case MSG_CLIENT_UNMOUNT:
    handle_client_unmount(m);
    return;
  case MSG_CLIENT_REQUEST:
    handle_client_request((MClientRequest*)m);
    return;

  }

  dout(1) << " main unknown message " << m->get_type() << endl;
  assert(0);
}



// ----------------------------------------------------------
// MOUNT and UNMOUNT


class C_MDS_mount_finish : public Context {
  MDS *mds;
  Message *m;
  bool mount;
  version_t cmapv;
public:
  C_MDS_mount_finish(MDS *m, Message *msg, bool mnt, version_t mv) :
    mds(m), m(msg), mount(mnt), cmapv(mv) { }
  void finish(int r) {
    assert(r == 0);

    // apply
    if (mount)
      mds->clientmap.add_mount(m->get_source_inst());
    else
      mds->clientmap.rem_mount(m->get_source().num());
    
    assert(cmapv == mds->clientmap.get_version());
    
    // reply
    if (mount) {
      // mounted
      mds->messenger->send_message(new MClientMountAck((MClientMount*)m, mds->mdsmap, mds->osdmap), 
				   m->get_source_inst());
      delete m;
    } else {
      // ack by sending back to client
      mds->messenger->send_message(m, m->get_source_inst());

      // unmounted
      if (g_conf.mds_shutdown_on_last_unmount &&
	  mds->clientmap.get_mount_set().empty()) {
	dout(3) << "all clients done, initiating shutdown" << endl;
	mds->shutdown_start();
      }
    }
  }
};


void Server::handle_client_mount(MClientMount *m)
{
  dout(3) << "mount by " << m->get_source() << " oldv " << mds->clientmap.get_version() << endl;

  // journal it
  version_t cmapv = mds->clientmap.inc_projected();
  mdlog->submit_entry(new EMount(m->get_source_inst(), true, cmapv),
		      new C_MDS_mount_finish(mds, m, true, cmapv));
}

void Server::handle_client_unmount(Message *m)
{
  dout(3) << "unmount by " << m->get_source() << " oldv " << mds->clientmap.get_version() << endl;

  // journal it
  version_t cmapv = mds->clientmap.inc_projected();
  mdlog->submit_entry(new EMount(m->get_source_inst(), false, cmapv),
		      new C_MDS_mount_finish(mds, m, false, cmapv));
}



/*******
 * some generic stuff for finishing off requests
 */

/** C_MDS_CommitRequest
 */

class C_MDS_CommitRequest : public Context {
  Server *server;
  MClientRequest *req;
  MClientReply *reply;
  CInode *tracei;    // inode to include a trace for
  LogEvent *event;

public:
  C_MDS_CommitRequest(Server *server,
                      MClientRequest *req, MClientReply *reply, CInode *tracei, 
                      LogEvent *event=0) {
    this->server = server;
    this->req = req;
    this->tracei = tracei;
    this->reply = reply;
    this->event = event;
  }
  void finish(int r) {
    if (r != 0) {
      // failure.  set failure code and reply.
      reply->set_result(r);
    }
    if (event) {
      server->commit_request(req, reply, tracei, event);
    } else {
      // reply.
      server->reply_request(req, reply, tracei);
    }
  }
};


/*
 * send generic response (just and error code)
 */
void Server::reply_request(MClientRequest *req, int r, CInode *tracei)
{
  reply_request(req, new MClientReply(req, r), tracei);
}


/*
 * send given reply
 * include a trace to tracei
 */
void Server::reply_request(MClientRequest *req, MClientReply *reply, CInode *tracei) 
{
  dout(10) << "reply_request " << reply->get_result() 
	   << " (" << strerror(-reply->get_result())
	   << ") " << *req << endl;

  // include trace
  if (tracei) {
    reply->set_trace_dist( tracei, mds->get_nodeid() );
  }
  
  // send reply
  messenger->send_message(reply,
                          req->get_client_inst());

  // discard request
  mdcache->request_finish(req);

  // stupid stats crap (FIXME)
  stat_ops++;
}


void Server::submit_update(MClientRequest *req,
			   CInode *wrlockedi,
			   LogEvent *event,
			   Context *oncommit)
{
  // log
  mdlog->submit_entry(event);

  // pin
  mdcache->request_pin_inode(req, wrlockedi);

  // wait
  mdlog->wait_for_sync(oncommit);
}


/* 
 * commit event(s) to the metadata journal, then reply.
 * or, be sloppy and do it concurrently (see g_conf.mds_log_before_reply)
 *
 * NOTE: this is old and bad (write-behind!)
 */
void Server::commit_request(MClientRequest *req,
                         MClientReply *reply,
                         CInode *tracei,
                         LogEvent *event,
                         LogEvent *event2) 
{      
  // log
  if (event) mdlog->submit_entry(event);
  if (event2) mdlog->submit_entry(event2);
  
  if (g_conf.mds_log_before_reply && g_conf.mds_log && event) {
    // SAFE mode!

    // pin inode so it doesn't go away!
    if (tracei) mdcache->request_pin_inode(req, tracei);

    // wait for log sync
    mdlog->wait_for_sync(new C_MDS_CommitRequest(this, req, reply, tracei)); 
    return;
  }
  else {
    // just reply
    reply_request(req, reply, tracei);
  }
}



/***
 * process a client request
 */

void Server::handle_client_request(MClientRequest *req)
{
  dout(4) << "req " << *req << endl;

  if (!mds->is_active()) {
    dout(5) << " not active, discarding client request." << endl;
    delete req;
    return;
  }
  
  if (!mdcache->get_root()) {
    dout(5) << "need to open root" << endl;
    mdcache->open_root(new C_MDS_RetryMessage(mds, req));
    return;
  }

  // okay, i want
  CInode           *ref = 0;
  vector<CDentry*> trace;      // might be blank, for fh guys

  bool follow_trailing_symlink = false;

  // operations on fh's or other non-files
  switch (req->get_op()) {
    /*
  case MDS_OP_FSTAT:
    reply = handle_client_fstat(req, cur);
    break; ****** fiX ME ***
    */
    
  case MDS_OP_TRUNCATE:
    if (!req->args.truncate.ino) break;   // can be called w/ either fh OR path
    
  case MDS_OP_FSYNC:
    ref = mdcache->get_inode(req->args.fsync.ino);   // fixme someday no ino needed?

    if (!ref) {
      int next = mds->get_nodeid() + 1;
      if (next >= mds->mdsmap->get_num_mds()) next = 0;
      dout(10) << "got request on ino we don't have, passing buck to " << next << endl;
      mds->send_message_mds(req, next, MDS_PORT_SERVER);
      return;
    }
  }

  if (!ref) {
    // we need to traverse a path
    filepath refpath = req->get_filepath();
    
    // ops on non-existing files --> directory paths
    switch (req->get_op()) {
    case MDS_OP_OPEN:
      if (!(req->args.open.flags & O_CREAT)) break;
      
    case MDS_OP_MKNOD:
    case MDS_OP_MKDIR:
    case MDS_OP_SYMLINK:
    case MDS_OP_LINK:
    case MDS_OP_UNLINK:   // also wrt parent dir, NOT the unlinked inode!!
    case MDS_OP_RMDIR:
    case MDS_OP_RENAME:
      // remove last bit of path
      refpath = refpath.prefixpath(refpath.depth()-1);
      break;
    }
    dout(10) << "refpath = " << refpath << endl;
    
    Context *ondelay = new C_MDS_RetryMessage(mds, req);
    
    if (req->get_op() == MDS_OP_LSTAT) {
      follow_trailing_symlink = false;
    }

    // do trace
    int r = mdcache->path_traverse(refpath, trace, follow_trailing_symlink,
                                   req, ondelay,
                                   MDS_TRAVERSE_FORWARD,
                                   0,
                                   true); // is MClientRequest
    
    if (r > 0) return; // delayed
    if (r == -ENOENT ||
        r == -ENOTDIR ||
        r == -EISDIR) {
      // error! 
      dout(10) << " path traverse error " << r << ", replying" << endl;
      
      // send error
      messenger->send_message(new MClientReply(req, r),
                              req->get_client_inst());

      // <HACK>
      // is this a special debug command?
      if (refpath.depth() - 1 == trace.size() &&
	  refpath.last_dentry().find(".ceph.") == 0) {
	/*
FIXME dirfrag
	CDir *dir = 0;
	if (!trace.empty()) 
	  dir = mdcache->get_root()->dir;
	else
	  dir = trace[trace.size()-1]->get_inode()->dir;

	dout(1) << "** POSSIBLE CEPH DEBUG COMMAND '" << refpath.last_dentry() << "' in " << *dir << endl;

	if (refpath.last_dentry() == ".ceph.hash" &&
	    refpath.depth() > 1) {
	  dout(1) << "got explicit hash command " << refpath << endl;
	  /// ....
	}
	else if (refpath.last_dentry() == ".ceph.commit") {
	  dout(1) << "got explicit commit command on  " << *dir << endl;
	  dir->commit(0, 0);
	}
*/
      }
      // </HACK>


      delete req;
      return;
    }
    
    if (trace.size()) 
      ref = trace[trace.size()-1]->inode;
    else
      ref = mdcache->get_root();
  }
  
  dout(10) << "ref is " << *ref << endl;
  
  // rename doesn't pin src path (initially)
  if (req->get_op() == MDS_OP_RENAME) trace.clear();

  // register
  if (!mdcache->request_start(req, ref, trace))
    return;
  
  // process
  dispatch_request(req, ref);
}



void Server::dispatch_request(Message *m, CInode *ref)
{
  MClientRequest *req = 0;

  // MLock or MClientRequest?
  /* this is a little weird.
     client requests and mlocks both initial dentry xlocks, path pins, etc.,
     and thus both make use of the context C_MDS_RetryRequest.
  */
  switch (m->get_type()) {
  case MSG_CLIENT_REQUEST:
    req = (MClientRequest*)m;
    break; // continue below!

  case MSG_MDS_LOCK:
    mds->locker->handle_lock_dn((MLock*)m);
    return; // done

  default:
    assert(0);  // shouldn't get here
  }

  // MClientRequest.

  dout(7) << "handle_client " << *m << " ref " << *ref << endl;

  switch (req->get_op()) {
    
    // files
  case MDS_OP_OPEN:
    if (req->args.open.flags & O_CREAT) 
      handle_client_openc(req, ref);
    else 
      handle_client_open(req, ref);
    break;
  case MDS_OP_TRUNCATE:
    handle_client_truncate(req, ref);
    break;
    /*
  case MDS_OP_FSYNC:
    handle_client_fsync(req, ref);
    break;
    */
    /*
  case MDS_OP_RELEASE:
    handle_client_release(req, ref);
    break;
    */

    // inodes
  case MDS_OP_STAT:
  case MDS_OP_LSTAT:
    handle_client_stat(req, ref);
    break;
  case MDS_OP_UTIME:
    handle_client_utime(req, ref);
    break;
  case MDS_OP_CHMOD:
    handle_client_chmod(req, ref);
    break;
  case MDS_OP_CHOWN:
    handle_client_chown(req, ref);
    break;

    // namespace
  case MDS_OP_READDIR:
    handle_client_readdir(req, ref);
    break;
  case MDS_OP_MKNOD:
    handle_client_mknod(req, ref);
    break;
  case MDS_OP_LINK:
    handle_client_link(req, ref);
    break;
  case MDS_OP_UNLINK:
    handle_client_unlink(req, ref);
    break;
  case MDS_OP_RENAME:
    handle_client_rename(req, ref);
    break;
  case MDS_OP_RMDIR:
    handle_client_unlink(req, ref);
    break;
  case MDS_OP_MKDIR:
    handle_client_mkdir(req, ref);
    break;
  case MDS_OP_SYMLINK:
    handle_client_symlink(req, ref);
    break;



  default:
    dout(1) << " unknown client op " << req->get_op() << endl;
    assert(0);
  }

  return;
}


// FIXME: this probably should go somewhere else.

CDir* Server::try_open_auth_dir(CInode *diri, frag_t fg, MClientRequest *req)
{
  CDir *dir = diri->get_dirfrag(fg);

  // not open and inode not mine?
  if (!dir && !diri->is_auth()) {
    int inauth = diri->authority().first;
    dout(7) << "try_open_auth_dir: not open, not inode auth, fw to mds" << inauth << endl;
    mdcache->request_forward(req, inauth);
    return 0;
  }

  // not open and inode frozen?
  if (!dir && diri->is_frozen_dir()) {
    dout(10) << "try_open_dir: dir inode is frozen, waiting " << *diri << endl;
    assert(diri->get_parent_dir());
    diri->get_parent_dir()->add_waiter(CDir::WAIT_UNFREEZE,
				       new C_MDS_RetryRequest(mds, req, diri));
    return 0;
  }

  // invent?
  if (!dir) {
    assert(diri->is_auth());
    dir = diri->get_or_open_dirfrag(mds->mdcache, fg);
  }
  assert(dir);
 
  // am i auth for the dirfrag?
  if (!dir->is_auth()) {
    int auth = dir->authority().first;
    dout(7) << "try_open_auth_dir: not auth for " << *dir
	    << ", fw to mds" << auth << endl;
    mdcache->request_forward(req, auth);
    return 0;
  }

  return dir;
}

CDir* Server::try_open_dir(CInode *diri, frag_t fg, 
			   MClientRequest *req, CInode *ref)
{
  CDir *dir = diri->get_dirfrag(fg);
  if (dir) 
    return dir;

  if (diri->is_auth()) {
    // auth
    // not open and inode frozen?
    if (!dir && diri->is_frozen_dir()) {
      dout(10) << "try_open_dir: dir inode is auth+frozen, waiting " << *diri << endl;
      assert(diri->get_parent_dir());
      diri->get_parent_dir()->add_waiter(CDir::WAIT_UNFREEZE,
					 new C_MDS_RetryRequest(mds, req, diri));
      return 0;
    }
    
    // invent?
    if (!dir) {
      assert(diri->is_auth());
      dir = diri->get_or_open_dirfrag(mds->mdcache, fg);
    }
    assert(dir);
    return dir;
  } else {
    // not auth
    mdcache->open_remote_dir(diri, fg,
			     new C_MDS_RetryRequest(mds, req, ref));
    return 0;
  }
}


// ===============================================================================
// STAT

void Server::handle_client_stat(MClientRequest *req,
				CInode *ref)
{
  // FIXME: this is really not the way to handle the statlite mask.

  // do I need file info?
  int mask = req->args.stat.mask;
  if (mask & (INODE_MASK_SIZE|INODE_MASK_MTIME)) {
    // yes.  do a full stat.
    if (!mds->locker->inode_file_read_start(ref, req, ref))
      return;  // syncing
    mds->locker->inode_file_read_finish(ref);
  } else {
    // nope!  easy peasy.
  }
  
  mds->balancer->hit_inode(ref, META_POP_IRD);   
  
  // reply
  //dout(10) << "reply to " << *req << " stat " << ref->inode.mtime << endl;
  MClientReply *reply = new MClientReply(req);
  reply_request(req, reply, ref);
}




// ===============================================================================
// INODE UPDATES


/* 
 * finisher: do a inode_file_write_finish and reply.
 */
class C_MDS_utime_finish : public Context {
  MDS *mds;
  MClientRequest *req;
  CInode *in;
  version_t pv;
  time_t mtime, atime;
public:
  C_MDS_utime_finish(MDS *m, MClientRequest *r, CInode *i, version_t pdv, time_t mt, time_t at) :
    mds(m), req(r), in(i), 
    pv(pdv),
    mtime(mt), atime(at) { }
  void finish(int r) {
    assert(r == 0);

    // apply
    in->inode.mtime = mtime;
    in->inode.atime = atime;
    in->mark_dirty(pv);

    // unlock
    mds->locker->inode_file_write_finish(in);

    // reply
    MClientReply *reply = new MClientReply(req, 0);
    reply->set_result(0);
    mds->server->reply_request(req, reply, in);
  }
};


// utime

void Server::handle_client_utime(MClientRequest *req,
				 CInode *cur)
{
  // auth pin
  if (!cur->can_auth_pin()) {
    dout(7) << "waiting for authpinnable on " << *cur << endl;
    cur->add_waiter(CInode::WAIT_AUTHPINNABLE, new C_MDS_RetryRequest(mds, req, cur));
    return;
  }
  mdcache->request_auth_pin(req, cur);

  // write
  if (!mds->locker->inode_file_write_start(cur, req, cur))
    return;  // fw or (wait for) sync

  mds->balancer->hit_inode(cur, META_POP_IWR);   

  // prepare
  version_t pdv = cur->pre_dirty();
  time_t mtime = req->args.utime.modtime;
  time_t atime = req->args.utime.actime;
  C_MDS_utime_finish *fin = new C_MDS_utime_finish(mds, req, cur, pdv, 
						   mtime, atime);

  // log + wait
  EUpdate *le = new EUpdate("utime");
  le->metablob.add_client_req(req->get_reqid());
  le->metablob.add_dir_context(cur->get_parent_dir());
  inode_t *pi = le->metablob.add_dentry(cur->parent, true);
  pi->mtime = mtime;
  pi->atime = mtime;
  pi->ctime = g_clock.gettime();
  pi->version = pdv;
  
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);
}


// --------------

/* 
 * finisher: do a inode_hard_write_finish and reply.
 */
class C_MDS_chmod_finish : public Context {
  MDS *mds;
  MClientRequest *req;
  CInode *in;
  version_t pv;
  int mode;
public:
  C_MDS_chmod_finish(MDS *m, MClientRequest *r, CInode *i, version_t pdv, int mo) :
    mds(m), req(r), in(i), pv(pdv), mode(mo) { }
  void finish(int r) {
    assert(r == 0);

    // apply
    in->inode.mode &= ~04777;
    in->inode.mode |= (mode & 04777);
    in->mark_dirty(pv);

    // unlock
    mds->locker->inode_hard_write_finish(in);

    // reply
    MClientReply *reply = new MClientReply(req, 0);
    reply->set_result(0);
    mds->server->reply_request(req, reply, in);
  }
};


// chmod

void Server::handle_client_chmod(MClientRequest *req,
				 CInode *cur)
{
  // auth pin
  if (!cur->can_auth_pin()) {
    dout(7) << "waiting for authpinnable on " << *cur << endl;
    cur->add_waiter(CInode::WAIT_AUTHPINNABLE, new C_MDS_RetryRequest(mds, req, cur));
    return;
  }
  mdcache->request_auth_pin(req, cur);

  // write
  if (!mds->locker->inode_hard_write_start(cur, req, cur))
    return;  // fw or (wait for) lock

  mds->balancer->hit_inode(cur, META_POP_IWR);   

  // prepare
  version_t pdv = cur->pre_dirty();
  int mode = req->args.chmod.mode;
  C_MDS_chmod_finish *fin = new C_MDS_chmod_finish(mds, req, cur, pdv,
						   mode);

  // log + wait
  EUpdate *le = new EUpdate("chmod");
  le->metablob.add_client_req(req->get_reqid());
  le->metablob.add_dir_context(cur->get_parent_dir());
  inode_t *pi = le->metablob.add_dentry(cur->parent, true);
  pi->mode = mode;
  pi->version = pdv;
  pi->ctime = g_clock.gettime();
  
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);
}


// chown

class C_MDS_chown_finish : public Context {
  MDS *mds;
  MClientRequest *req;
  CInode *in;
  version_t pv;
  int uid, gid;
public:
  C_MDS_chown_finish(MDS *m, MClientRequest *r, CInode *i, version_t pdv, int u, int g) :
    mds(m), req(r), in(i), pv(pdv), uid(u), gid(g) { }
  void finish(int r) {
    assert(r == 0);

    // apply
    if (uid >= 0) in->inode.uid = uid;
    if (gid >= 0) in->inode.gid = gid;
    in->mark_dirty(pv);

    // unlock
    mds->locker->inode_hard_write_finish(in);

    // reply
    MClientReply *reply = new MClientReply(req, 0);
    reply->set_result(0);
    mds->server->reply_request(req, reply, in);
  }
};


void Server::handle_client_chown(MClientRequest *req,
				 CInode *cur)
{
  // auth pin
  if (!cur->can_auth_pin()) {
    dout(7) << "waiting for authpinnable on " << *cur << endl;
    cur->add_waiter(CInode::WAIT_AUTHPINNABLE, new C_MDS_RetryRequest(mds, req, cur));
    return;
  }
  mdcache->request_auth_pin(req, cur);

  // write
  if (!mds->locker->inode_hard_write_start(cur, req, cur))
    return;  // fw or (wait for) lock

  mds->balancer->hit_inode(cur, META_POP_IWR);   

  // prepare
  version_t pdv = cur->pre_dirty();
  int uid = req->args.chown.uid;
  int gid = req->args.chown.gid;
  C_MDS_chown_finish *fin = new C_MDS_chown_finish(mds, req, cur, pdv,
						   uid, gid);

  // log + wait
  EUpdate *le = new EUpdate("chown");
  le->metablob.add_client_req(req->get_reqid());
  le->metablob.add_dir_context(cur->get_parent_dir());
  inode_t *pi = le->metablob.add_dentry(cur->parent, true);
  if (uid >= 0) pi->uid = uid;
  if (gid >= 0) pi->gid = gid;
  pi->version = pdv;
  pi->ctime = g_clock.gettime();
  
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);
}







// =================================================================
// DIRECTORY and NAMESPACE OPS

// READDIR

int Server::encode_dir_contents(CDir *dir, 
				list<InodeStat*>& inls,
				list<string>& dnls)
{
  int numfiles = 0;

  for (CDir_map_t::iterator it = dir->begin(); 
       it != dir->end(); 
       it++) {
    CDentry *dn = it->second;
    
    if (dn->is_null()) continue;

    CInode *in = dn->inode;
    if (!in) 
      continue;  // hmm, fixme!, what about REMOTE links?  
    
    dout(12) << "including inode " << *in << endl;

    // add this item
    // note: InodeStat makes note of whether inode data is readable.
    dnls.push_back( it->first );
    inls.push_back( new InodeStat(in, mds->get_nodeid()) );
    numfiles++;
  }
  return numfiles;
}


void Server::handle_client_readdir(MClientRequest *req,
				   CInode *diri)
{
  // it's a directory, right?
  if (!diri->is_dir()) {
    // not a dir
    dout(10) << "reply to " << *req << " readdir -ENOTDIR" << endl;
    reply_request(req, -ENOTDIR);
    return;
  }

  // which frag?
  frag_t fg = req->args.readdir.frag;

  // does it exist?
  if (diri->dirfragtree[fg] != fg) {
    dout(10) << "frag " << fg << " doesn't appear in fragtree " << diri->dirfragtree << endl;
    reply_request(req, -EAGAIN);
    return;
  }
  
  CDir *dir = try_open_auth_dir(diri, fg, req);
  if (!dir) return;

  // ok!
  assert(dir->is_auth());

  // check perm
  if (!mds->locker->inode_hard_read_start(diri, req, diri))
    return;
  mds->locker->inode_hard_read_finish(diri);

  if (!dir->is_complete()) {
    // fetch
    dout(10) << " incomplete dir contents for readdir on " << *dir << ", fetching" << endl;
    dir->fetch(new C_MDS_RetryRequest(mds, req, diri));
    return;
  }

  // build dir contents
  list<InodeStat*> inls;
  list<string> dnls;
  int numfiles = encode_dir_contents(dir, inls, dnls);
  
  // . too
  dnls.push_back(".");
  inls.push_back(new InodeStat(diri, mds->get_nodeid()));
  ++numfiles;
  
  // yay, reply
  MClientReply *reply = new MClientReply(req);
  reply->take_dir_items(inls, dnls, numfiles);
  
  dout(10) << "reply to " << *req << " readdir " << numfiles << " files" << endl;
  reply->set_result(fg);
  
  //balancer->hit_dir(diri->dir);
  
  // reply
  reply_request(req, reply, diri);
}



// ------------------------------------------------

// MKNOD

class C_MDS_mknod_finish : public Context {
  MDS *mds;
  MClientRequest *req;
  CDentry *dn;
  CInode *newi;
  version_t pv;
public:
  C_MDS_mknod_finish(MDS *m, MClientRequest *r, CDentry *d, CInode *ni) :
    mds(m), req(r), dn(d), newi(ni),
    pv(d->get_projected_version()) {}
  void finish(int r) {
    assert(r == 0);

    // link the inode
    dn->get_dir()->link_inode(dn, newi);

    // dirty inode, dn, dir
    newi->mark_dirty(pv);

    // unlock
    mds->locker->dentry_xlock_finish(dn);

    // hit pop
    mds->balancer->hit_inode(newi, META_POP_IWR);

    // reply
    MClientReply *reply = new MClientReply(req, 0);
    reply->set_result(0);
    mds->server->reply_request(req, reply, newi);
  }
};

void Server::handle_client_mknod(MClientRequest *req, CInode *diri)
{
  CDir *dir = 0;
  CDentry *dn = 0;

  // create null dentry
  if (!prepare_null_dentry(req, diri, &dir, &dn)) 
    return;
  assert(dir);
  assert(dn);

  // xlock dentry
  if (!mds->locker->dentry_xlock_start(dn, req, diri))
    return;

  CInode *newi = prepare_new_inode(req, dir);
  assert(newi);

  // it's a file.
  dn->pre_dirty();
  newi->inode.mode = req->args.mknod.mode;
  newi->inode.mode &= ~INODE_TYPE_MASK;
  newi->inode.mode |= INODE_MODE_FILE;
  
  // prepare finisher
  C_MDS_mknod_finish *fin = new C_MDS_mknod_finish(mds, req, dn, newi);
  EUpdate *le = new EUpdate("mknod");
  le->metablob.add_client_req(req->get_reqid());
  le->metablob.add_dir_context(dir);
  inode_t *pi = le->metablob.add_primary_dentry(dn, true, newi);
  pi->version = dn->get_projected_version();
  
  // log + wait
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);
}



/** validate_dentry_dir
 *
 * verify that the dir exists and would own the dname.
 * do not check if the dentry exists.
 */
CDir *Server::validate_dentry_dir(MClientRequest *req, CInode *ref, CInode *diri, const string& name)
{
  // make sure parent is a dir?
  if (!diri->is_dir()) {
    dout(7) << "validate_dentry_dir: not a dir" << endl;
    reply_request(req, -ENOTDIR);
    return false;
  }

  // which dirfrag?
  frag_t fg = diri->pick_dirfrag(name);

  CDir *dir = try_open_auth_dir(diri, fg, req);
  if (!dir)
    return 0;

  /*
  // dir auth pinnable?
  if (!dir->can_auth_pin()) {
    dout(7) << "validate_dentry_dir: dir " << *dir << " not pinnable, waiting" << endl;
    dir->add_waiter(CDir::WAIT_AUTHPINNABLE,
		    new C_MDS_RetryRequest(mds, req, diri));
    return false;
  }
  */

  // frozen?
  if (dir->is_frozen()) {
    dout(7) << "dir is frozen " << *dir << endl;
    dir->add_waiter(CDir::WAIT_UNFREEZE,
                    new C_MDS_RetryRequest(mds, req, ref));
    return false;
  }

  return dir;
}

/** prepare_null_dentry
 *
 * prepare a mknod-type operation (mknod, mkdir, symlink, open+create).
 * create the inode and dentry, but do not link them.
 * pre_dirty the dentry+dir.
 * xlock the dentry.
 *
 * return val
 *  0 - wait for something
 *  1 - created
 *  2 - already exists (only if okexist=true)
 */
int Server::prepare_null_dentry(MClientRequest *req,
				CInode *diri, CDir **pdir, CDentry **pdn, 
				bool okexist) 
{
  // get containing directory (without last bit)
  filepath dirpath = req->get_filepath().prefixpath(req->get_filepath().depth() - 1);
  string name = req->get_filepath().last_dentry();
  
  return prepare_null_dentry(req, diri, 
			     diri, name,
			     pdir, pdn, okexist);
}

int Server::prepare_null_dentry(MClientRequest *req, CInode *ref, 
				CInode *diri, const string& name, 
				CDir **pdir, CDentry **pdn, 
				bool okexist) 
{
  dout(10) << "prepare_null_dentry " << name << " in " << *diri << endl;
  
  CDir *dir = *pdir = validate_dentry_dir(req, ref, diri, name);
  if (!dir) return 0;

  // make sure name doesn't already exist
  *pdn = dir->lookup(name);
  if (*pdn) {
    if (!(*pdn)->can_read(req)) {
      dout(10) << "waiting on (existing!) unreadable dentry " << **pdn << endl;
      dir->add_waiter(CDir::WAIT_DNREAD, name, new C_MDS_RetryRequest(mds, req, ref));
      return 0;
    }

    if (!(*pdn)->is_null()) {
      // name already exists
      if (okexist) {
        dout(10) << "dentry " << name << " exists in " << *dir << endl;
        return 2;
      } else {
        dout(10) << "dentry " << name << " exists in " << *dir << endl;
        reply_request(req, -EEXIST);
        return 0;
      }
    }
  }

  // make sure dir is complete
  if (!dir->is_complete()) {
    dout(7) << " incomplete dir contents for " << *dir << ", fetching" << endl;
    dir->fetch(new C_MDS_RetryRequest(mds, req, ref));
    return 0;
  }

  // create null dentry
  if (!*pdn) {
    *pdn = dir->add_dentry(name, 0);
    dout(10) << "prepare_null_dentry added " << **pdn << endl;
  } else {
    dout(10) << "prepare_null_dentry had " << **pdn << endl;
  }


  return 1;
}


/** prepare_new_inode
 *
 * create a new inode.  set c/m/atime.  hit dir pop.
 */
CInode* Server::prepare_new_inode(MClientRequest *req, CDir *dir) 
{
  CInode *in = mdcache->create_inode();
  in->inode.uid = req->get_caller_uid();
  in->inode.gid = req->get_caller_gid();
  in->inode.ctime = in->inode.mtime = in->inode.atime = g_clock.gettime();   // now
  dout(10) << "prepare_new_inode " << *in << endl;

  // bump modify pop
  mds->balancer->hit_dir(dir, META_POP_DWR);

  return in;
}





// MKDIR

void Server::handle_client_mkdir(MClientRequest *req, CInode *diri)
{
  CDir *dir = 0;
  CDentry *dn = 0;
  
  // make dentry 
  if (!prepare_null_dentry(req, diri, &dir, &dn)) 
    return;
  assert(dir);
  assert(dn);

  // xlock
  if (!mds->locker->dentry_xlock_start(dn, req, diri))
    return;

  // new inode
  CInode *newi = prepare_new_inode(req, dir);  
  assert(newi);

  // it's a directory.
  dn->pre_dirty();
  newi->inode.mode = req->args.mkdir.mode;
  newi->inode.mode &= ~INODE_TYPE_MASK;
  newi->inode.mode |= INODE_MODE_DIR;
  newi->inode.layout = g_OSD_MDDirLayout;

  // ...and that new dir is empty.
  CDir *newdir = newi->get_or_open_dirfrag(mds->mdcache, frag_t());
  newdir->mark_complete();
  newdir->mark_dirty(newdir->pre_dirty());

  // prepare finisher
  C_MDS_mknod_finish *fin = new C_MDS_mknod_finish(mds, req, dn, newi);
  EUpdate *le = new EUpdate("mkdir");
  le->metablob.add_client_req(req->get_reqid());
  le->metablob.add_dir_context(dir);
  inode_t *pi = le->metablob.add_primary_dentry(dn, true, newi);
  pi->version = dn->get_projected_version();
  le->metablob.add_dir(newdir, true);
  
  // log + wait
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);


  /* old export heuristic.  pbly need to reimplement this at some point.    
  if (
      diri->dir->is_auth() &&
      diri->dir->is_rep() &&
      newdir->is_auth() &&
      !newdir->is_hashing()) {
    int dest = rand() % mds->mdsmap->get_num_mds();
    if (dest != whoami) {
      dout(10) << "exporting new dir " << *newdir << " in replicated parent " << *diri->dir << endl;
      mdcache->migrator->export_dir(newdir, dest);
    }
  }
  */
}



// SYMLINK

void Server::handle_client_symlink(MClientRequest *req, CInode *diri)
{
  CDir *dir = 0;
  CDentry *dn = 0;

  // make null dentry 
  if (!prepare_null_dentry(req, diri, &dir, &dn)) 
    return;
  assert(dir);
  assert(dn);

  // xlock
  if (!mds->locker->dentry_xlock_start(dn, req, diri))
    return;

  CInode *newi = prepare_new_inode(req, dir);
  assert(newi);

  // it's a symlink
  dn->pre_dirty();
  newi->inode.mode &= ~INODE_TYPE_MASK;
  newi->inode.mode |= INODE_MODE_SYMLINK;
  newi->symlink = req->get_sarg();

  // prepare finisher
  C_MDS_mknod_finish *fin = new C_MDS_mknod_finish(mds, req, dn, newi);
  EUpdate *le = new EUpdate("symlink");
  le->metablob.add_client_req(req->get_reqid());
  le->metablob.add_dir_context(dir);
  inode_t *pi = le->metablob.add_primary_dentry(dn, true, newi);
  pi->version = dn->get_projected_version();
  
  // log + wait
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);
}





// LINK

class C_MDS_LinkTraverse : public Context {
  Server *server;
  MClientRequest *req;
  CInode *ref;
public:
  vector<CDentry*> trace;
  C_MDS_LinkTraverse(Server *server, MClientRequest *req, CInode *ref) {
    this->server = server;
    this->req = req;
    this->ref = ref;
  }
  void finish(int r) {
    server->handle_client_link_2(r, req, ref, trace);
  }
};

void Server::handle_client_link(MClientRequest *req, CInode *ref)
{
  string dname = req->get_filepath().last_dentry();
  dout(7) << "handle_client_link " << dname << " in " << *ref
	  << " to " << req->get_sarg()
	  << endl;

  // make sure we own the dname
  CDir *dir = validate_dentry_dir(req, ref, ref, dname);
  if (!dir) return;

  // discover link target
  filepath target = req->get_sarg();
  dout(7) << "handle_client_link discovering target " << target << endl;
  C_MDS_LinkTraverse *onfinish = new C_MDS_LinkTraverse(this, req, ref);
  Context *ondelay = new C_MDS_RetryRequest(mds, req, ref);
  
  mdcache->path_traverse(target, onfinish->trace, false,
                         req, ondelay,
                         MDS_TRAVERSE_DISCOVER,  //XLOCK, 
                         onfinish);
}


void Server::handle_client_link_2(int r, MClientRequest *req, CInode *diri, vector<CDentry*>& trace)
{
  // target dne?
  if (r < 0) {
    dout(7) << "target " << req->get_sarg() << " dne" << endl;
    reply_request(req, r);
    return;
  }
  assert(r == 0);

  // identify target inode
  CInode *targeti = mdcache->get_root();
  if (trace.size()) targeti = trace[trace.size()-1]->inode;
  assert(targeti);

  // not a dir?
  dout(7) << "target is " << *targeti << endl;
  if (targeti->is_dir()) {
    dout(7) << "target is a dir, failing" << endl;
    reply_request(req, -EINVAL);
    return;
  }

  // does the target need an anchor?
  if (targeti->is_auth()) {
    if (targeti->get_parent_dir()->get_inode() == diri) {
      dout(7) << "target is in the same dir, sweet" << endl;
    } 
    else if (targeti->is_anchored() && !targeti->is_unanchoring()) {
      dout(7) << "target anchored already (nlink=" << targeti->inode.nlink << "), sweet" << endl;
    } 
    else {
      dout(7) << "target needs anchor, nlink=" << targeti->inode.nlink << ", creating anchor" << endl;
      
      mdcache->anchor_create(targeti,
			     new C_MDS_RetryRequest(mds, req, diri));
      return;
    }
  }

  // can we create the dentry?
  CDir *dir = 0;
  CDentry *dn = 0;
  
  // make dentry and inode, xlock dentry.
  r = prepare_null_dentry(req, diri, &dir, &dn);
  if (!r) 
    return; // wait on something
  assert(dir);
  assert(dn);

  // local or remote?
  if (targeti->is_auth()) 
    _link_local(req, diri, dn, targeti);
  else 
    _link_remote(req, diri, dn, targeti);
}


class C_MDS_link_local_finish : public Context {
  MDS *mds;
  MClientRequest *req;
  CDentry *dn;
  CInode *targeti;
  version_t dpv;
  time_t tctime;
  time_t tpv;
public:
  C_MDS_link_local_finish(MDS *m, MClientRequest *r, CDentry *d, CInode *ti, time_t ct) :
    mds(m), req(r), dn(d), targeti(ti),
    dpv(d->get_projected_version()),
    tctime(ct), 
    tpv(targeti->get_parent_dn()->get_projected_version()) {}
  void finish(int r) {
    assert(r == 0);
    mds->server->_link_local_finish(req, dn, targeti, dpv, tctime, tpv);
  }
};


void Server::_link_local(MClientRequest *req, CInode *diri,
			CDentry *dn, CInode *targeti)
{
  dout(10) << "_link_local " << *dn << " to " << *targeti << endl;

  // first, auth pin the dentry dir and targeti.
  if (!mdcache->request_auth_pinned(req, dn->get_dir()) &&
      !dn->get_dir()->can_auth_pin()) {
    dn->get_dir()->add_waiter(CDir::WAIT_AUTHPINNABLE,
			      new C_MDS_RetryRequest(mds, req, diri));
    return;
  }
  if (!mdcache->request_auth_pinned(req, targeti) &&
      !targeti->can_auth_pin()) {
    targeti->add_waiter(CDir::WAIT_AUTHPINNABLE,
			new C_MDS_RetryRequest(mds, req, diri));
    return;
  }
  mdcache->request_auth_pin(req, dn->get_dir());
  mdcache->request_auth_pin(req, targeti);
  
  // sweet.  let's get our locks.
  // lock dentry, target inode
  if (!mds->locker->dentry_xlock_start(dn, req, diri))
    return;
  if (!mds->locker->inode_hard_write_start(targeti, req, diri))
    return;

  // ok, let's do it.
  // prepare log entry
  EUpdate *le = new EUpdate("link_local");
  le->metablob.add_client_req(req->get_reqid());

  // predirty
  dn->pre_dirty();
  version_t tpdv = targeti->pre_dirty();
  
  // add to event
  le->metablob.add_dir_context(dn->get_dir());
  le->metablob.add_remote_dentry(dn, true, targeti->ino());  // new remote
  le->metablob.add_dir_context(targeti->get_parent_dir());
  inode_t *pi = le->metablob.add_primary_dentry(targeti->parent, true, targeti);  // update old primary

  // update journaled target inode
  pi->nlink++;
  pi->ctime = g_clock.gettime();
  pi->version = tpdv;

  // finisher
  C_MDS_link_local_finish *fin = new C_MDS_link_local_finish(mds, req, dn, targeti, pi->ctime);
  
  // log + wait
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);
}

void Server::_link_local_finish(MClientRequest *req, CDentry *dn, CInode *targeti,
				version_t dpv, time_t tctime, version_t tpv)
{
  dout(10) << "_link_local_finish " << *dn << " to " << *targeti << endl;

  // link and unlock the new dentry
  dn->dir->link_inode(dn, targeti->ino());
  dn->set_version(dpv);
  dn->mark_dirty(dpv);

  // update the target
  targeti->inode.nlink++;
  targeti->inode.ctime = tctime;
  targeti->mark_dirty(tpv);

  // unlock the new dentry and target inode
  mds->locker->dentry_xlock_finish(dn);
  mds->locker->inode_hard_write_finish(targeti);

  // bump target popularity
  mds->balancer->hit_inode(targeti, META_POP_IWR);

  // reply
  MClientReply *reply = new MClientReply(req, 0);
  reply_request(req, reply, dn->get_dir()->get_inode());  // FIXME: imprecise ref
}



void Server::_link_remote(MClientRequest *req, CInode *ref,
			 CDentry *dn, CInode *targeti)
{
  dout(10) << "_link_remote " << *dn << " to " << *targeti << endl;

  // pin the target replica in our cache
  assert(!targeti->is_auth());
  mdcache->request_pin_inode(req, targeti);

  // 1. send LinkPrepare to dest (lock target on dest, journal target update)




  // 2. create+journal new dentry, as with link_local.
  // 3. send LinkCommit to dest (unlocks target on dest, journals commit)  

  // IMPLEMENT ME
  MClientReply *reply = new MClientReply(req, -EXDEV);
  reply_request(req, reply, dn->get_dir()->get_inode());
}


/*
void Server::handle_client_link_finish(MClientRequest *req, CInode *ref,
				       CDentry *dn, CInode *targeti)
{
  // create remote link
  dn->dir->link_inode(dn, targeti->ino());
  dn->link_remote( targeti );   // since we have it
  dn->_mark_dirty(); // fixme
  
  mds->balancer->hit_dir(dn->dir, META_POP_DWR);

  // done!
  commit_request(req, new MClientReply(req, 0), ref,
                 0);          // FIXME i should log something
}
*/

/*
class C_MDS_RemoteLink : public Context {
  Server *server;
  MClientRequest *req;
  CInode *ref;
  CDentry *dn;
  CInode *targeti;
public:
  C_MDS_RemoteLink(Server *server, MClientRequest *req, CInode *ref, CDentry *dn, CInode *targeti) {
    this->server = server;
    this->req = req;
    this->ref = ref;
    this->dn = dn;
    this->targeti = targeti;
  }
  void finish(int r) {
    if (r > 0) { // success
      // yay
      server->handle_client_link_finish(req, ref, dn, targeti);
    } 
    else if (r == 0) {
      // huh?  retry!
      assert(0);
      server->dispatch_request(req, ref);      
    } else {
      // link failed
      server->reply_request(req, r);
    }
  }
};


  } else {
    // remote: send nlink++ request, wait
    dout(7) << "target is remote, sending InodeLink" << endl;
    mds->send_message_mds(new MInodeLink(targeti->ino(), mds->get_nodeid()), targeti->authority().first, MDS_PORT_CACHE);
    
    // wait
    targeti->add_waiter(CInode::WAIT_LINK,
                        new C_MDS_RemoteLink(this, req, diri, dn, targeti));
    return;
  }

*/





// UNLINK

void Server::handle_client_unlink(MClientRequest *req, CInode *diri)
{
  // rmdir or unlink?
  bool rmdir = false;
  if (req->get_op() == MDS_OP_RMDIR) rmdir = true;
 
  // find it
  if (req->get_filepath().depth() == 0) {
    dout(7) << "can't rmdir root" << endl;
    reply_request(req, -EINVAL);
    return;
  }
  string name = req->get_filepath().last_dentry();

  // make sure parent is a dir?
  if (!diri->is_dir()) {
    dout(7) << "parent not a dir " << *diri << endl;
    reply_request(req, -ENOTDIR);
    return;
  }

  // get the dir, if it's not frozen etc.
  CDir *dir = validate_dentry_dir(req, diri, diri, name);
  if (!dir) return;
  // ok, it's auth, and authpinnable.

  // does the dentry exist?
  CDentry *dn = dir->lookup(name);
  if (!dn) {
    if (!dir->is_complete()) {
      dout(7) << "handle_client_rmdir/unlink missing dn " << name
	      << " but dir not complete, fetching " << *dir << endl;
      dir->fetch(new C_MDS_RetryRequest(mds, req, diri));
    } else {
      dout(7) << "handle_client_rmdir/unlink dne " << name << " in " << *dir << endl;
      reply_request(req, -ENOENT);
    }
    return;
  }

  if (rmdir) {
    dout(7) << "handle_client_rmdir on " << *dn << endl;
  } else {
    dout(7) << "handle_client_unlink on " << *dn << endl;
  }

  // have it.  locked?
  if (!dn->can_read(req)) {
    dout(10) << " waiting on " << *dn << endl;
    dir->add_waiter(CDir::WAIT_DNREAD, name,
                    new C_MDS_RetryRequest(mds, req, diri));
    return;
  }

  // null?
  if (dn->is_null()) {
    dout(10) << "unlink on null dn " << *dn << endl;
    reply_request(req, -ENOENT);
    return;
  }
  // dn looks ok.

  // get/open inode.
  CInode *in = mdcache->get_dentry_inode(dn, req, diri);
  if (!in) return;

  // rmdir vs is_dir 
  if (in->is_dir()) {
    if (rmdir) {
      // do empty directory checks
      if (!_verify_rmdir(req, diri, in))
	return;
    } else {
      dout(7) << "handle_client_unlink on dir " << *in << ", returning error" << endl;
      reply_request(req, -EISDIR);
      return;
    }
  } else {
    if (rmdir) {
      // unlink
      dout(7) << "handle_client_rmdir on non-dir " << *in << ", returning error" << endl;
      reply_request(req, -ENOTDIR);
      return;
    }
  }

  dout(7) << "handle_client_unlink/rmdir on " << *in << endl;


  // ok!
  if (dn->is_remote() && !dn->inode->is_auth()) 
    _unlink_remote(req, dn);
  else
    _unlink_local(req, dn);
}



class C_MDS_unlink_local_finish : public Context {
  MDS *mds;
  MClientRequest *req;
  CDentry *dn;
  CDentry *straydn;
  version_t ipv;  // referred inode
  time_t ictime;
  version_t dpv;  // deleted dentry
public:
  C_MDS_unlink_local_finish(MDS *m, MClientRequest *r, CDentry *d, CDentry *sd,
			    version_t v, time_t ct) :
    mds(m), req(r), dn(d), straydn(sd),
    ipv(v), ictime(ct),
    dpv(d->get_projected_version()) { }
  void finish(int r) {
    assert(r == 0);
    mds->server->_unlink_local_finish(req, dn, straydn, ipv, ictime, dpv);
  }
};


void Server::_unlink_local(MClientRequest *req, CDentry *dn)
{
  dout(10) << "_unlink_local " << *dn << endl;

  // auth pin
  if (!mdcache->request_auth_pinned(req, dn->get_dir()) &&
      !dn->get_dir()->can_auth_pin()) {
    dn->get_dir()->add_waiter(CDir::WAIT_AUTHPINNABLE,
			      new C_MDS_RetryRequest(mds, req, dn->get_dir()->get_inode()));
    return;
  }
  if (!mdcache->request_auth_pinned(req, dn->inode) &&
      !dn->inode->can_auth_pin()) {
    dn->inode->add_waiter(CInode::WAIT_AUTHPINNABLE,
			  new C_MDS_RetryRequest(mds, req, dn->get_dir()->get_inode()));
    return;
  }
  mdcache->request_auth_pin(req, dn->get_dir());
  mdcache->request_auth_pin(req, dn->inode);

  // lock
  if (!mds->locker->dentry_xlock_start(dn, req, dn->get_dir()->get_inode()))
    return;
  if (!mds->locker->inode_hard_write_start(dn->inode, req, dn->get_dir()->get_inode()))
    return;


  // get stray dn ready?
  CDentry *straydn = 0;
  if (dn->is_primary()) {
    string straydname;
    dn->inode->name_stray_dentry(straydname);
    frag_t fg = mdcache->get_stray()->pick_dirfrag(straydname);
    CDir *straydir = mdcache->get_stray()->get_or_open_dirfrag(mdcache, fg);
    straydn = straydir->add_dentry(straydname, 0);
    dout(10) << "_unlink_local straydn is " << *straydn << endl;
  }

  
  // ok, let's do it.
  // prepare log entry
  EUpdate *le = new EUpdate("unlink_local");
  le->metablob.add_client_req(req->get_reqid());

  version_t ipv = 0;  // dirty inode version
  inode_t *pi = 0;    // the inode

  if (dn->is_primary()) {
    // primary link.  add stray dentry.
    assert(straydn);
    ipv = straydn->pre_dirty(dn->inode->inode.version);
    le->metablob.add_dir_context(straydn->dir);
    pi = le->metablob.add_primary_dentry(straydn, true, dn->inode);
  } else {
    // remote link.  update remote inode.
    ipv = dn->inode->pre_dirty();
    le->metablob.add_dir_context(dn->inode->get_parent_dir());
    pi = le->metablob.add_primary_dentry(dn->inode->parent, true, dn->inode);  // update primary
  }
  
  // the unlinked dentry
  dn->pre_dirty();
  le->metablob.add_dir_context(dn->get_dir());
  le->metablob.add_null_dentry(dn, true);

  // update journaled target inode
  pi->nlink--;
  pi->ctime = g_clock.gettime();
  pi->version = ipv;
  
  // finisher
  C_MDS_unlink_local_finish *fin = new C_MDS_unlink_local_finish(mds, req, dn, straydn, 
								 ipv, pi->ctime);
  
  // log + wait
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);
  
  mds->balancer->hit_dir(dn->dir, META_POP_DWR);
}

void Server::_unlink_local_finish(MClientRequest *req, 
				  CDentry *dn, CDentry *straydn,
				  version_t ipv, time_t ictime, version_t dpv) 
{
  dout(10) << "_unlink_local " << *dn << endl;

  // unlink main dentry
  CInode *in = dn->inode;
  dn->dir->unlink_inode(dn);

  // relink as stray?  (i.e. was primary link?)
  if (straydn) straydn->dir->link_inode(straydn, in);  

  // nlink--
  in->inode.ctime = ictime;
  in->inode.nlink--;
  in->mark_dirty(ipv);  // dirty inode
  dn->mark_dirty(dpv);  // dirty old dentry

  // share unlink news with replicas
  for (map<int,int>::iterator it = dn->replicas_begin();
       it != dn->replicas_end();
       it++) {
    dout(7) << "_unlink_local_finish sending MDentryUnlink to mds" << it->first << endl;
    MDentryUnlink *unlink = new MDentryUnlink(dn->dir->dirfrag(), dn->name);
    if (straydn) {
      unlink->strayin = straydn->dir->inode->replicate_to(it->first);
      unlink->straydir = straydn->dir->replicate_to(it->first);
      unlink->straydn = straydn->replicate_to(it->first);
    }
    mds->send_message_mds(unlink, it->first, MDS_PORT_CACHE);
  }

  // unlock
  mds->locker->dentry_xlock_finish(dn);
  mds->locker->inode_hard_write_finish(in);
  
  // bump target popularity
  mds->balancer->hit_dir(dn->dir, META_POP_DWR);

  // reply
  MClientReply *reply = new MClientReply(req, 0);
  reply_request(req, reply, dn->dir->get_inode());  // FIXME: imprecise ref

  if (straydn)
    mdcache->eval_stray(straydn);
}



void Server::_unlink_remote(MClientRequest *req, CDentry *dn) 
{


  // IMPLEMENT ME
  MClientReply *reply = new MClientReply(req, -EXDEV);
  reply_request(req, reply, dn->get_dir()->get_inode());
}




/** _verify_rmdir
 *
 * verify that a directory is empty (i.e. we can rmdir it),
 * and make sure it is part of the same subtree (i.e. local)
 * so that rmdir will occur locally.
 *
 * @param in is the inode being rmdir'd.
 */
bool Server::_verify_rmdir(MClientRequest *req, CInode *ref, CInode *in)
{
  dout(10) << "_verify_rmdir " << *in << endl;
  assert(in->is_auth());

  list<frag_t> frags;
  in->dirfragtree.get_leaves(frags);

  for (list<frag_t>::iterator p = frags.begin();
       p != frags.end();
       ++p) {
    CDir *dir = in->get_dirfrag(*p);
    if (!dir) 
      dir = in->get_or_open_dirfrag(mdcache, *p);
    assert(dir);

    // dir looks empty but incomplete?
    if (dir->is_auth() &&
	dir->get_size() == 0 && 
	!dir->is_complete()) {
      dout(7) << "_verify_rmdir fetching incomplete dir " << *dir << endl;
      dir->fetch(new C_MDS_RetryRequest(mds, req, ref));
      return false;
    }
    
    // does the frag _look_ empty?
    if (dir->get_size()) {
      dout(10) << "_verify_rmdir still " << dir->get_size() << " items in frag " << *dir << endl;
      reply_request(req, -ENOTEMPTY);
      return false;
    }
    
    // not dir auth?
    if (!dir->is_auth()) {
      // hmm. we need it to import.  how to make that happen?
      // and wait on it?
      assert(0);  // IMPLEMENT ME
    }
  }

  return true;
}
/*
      // export sanity check
      if (!in->is_auth()) {
        // i should be exporting this now/soon, since the dir is empty.
        dout(7) << "handle_client_rmdir dir is auth, but not inode." << endl;
	mdcache->migrator->export_empty_import(in->dir);          
        in->dir->add_waiter(CDir::WAIT_UNFREEZE,
                            new C_MDS_RetryRequest(mds, req, diri));
        return;
      }
*/





// RENAME

class C_MDS_RenameTraverseDst : public Context {
  Server *server;
  MClientRequest *req;
  CInode *ref;
  CInode *srci;
  CDir *srcdir;
  CDentry *srcdn;
  filepath destpath;
public:
  vector<CDentry*> trace;
  
  C_MDS_RenameTraverseDst(Server *server,
                          MClientRequest *req, 
                          CInode *ref,
                          CDentry *srcdn,
                          filepath& destpath) {
    this->server = server;
    this->req = req;
    this->ref = ref;
    this->srcdn = srcdn;
    this->destpath = destpath;
  }
  void finish(int r) {
    server->handle_client_rename_2(req, ref,
				   srcdn, destpath,
				   trace, r);
  }
};


/** handle_client_rename
 *
 * NOTE: caller did not path_pin the ref (srcdir) inode, as it normally does.
 *  

  weirdness iwith rename:
    - ref inode is what was originally srcdiri, but that may change by the time
      the rename actually happens.  for all practical purpose, ref is useless except
      for C_MDS_RetryRequest

 */

bool Server::_rename_open_dn(CDir *dir, CDentry *dn, bool mustexist, MClientRequest *req, CInode *ref)
{
  // xlocked?
  if (dn && !dn->can_read(req)) {
    dout(10) << "_rename_open_dn waiting on " << *dn << endl;
    dir->add_waiter(CDir::WAIT_DNREAD,
			dn->name,
			new C_MDS_RetryRequest(mds, req, ref));
    return false;
  }
  
  if (mustexist && 
      ((dn && dn->is_null()) ||
       (!dn && dir->is_complete()))) {
    dout(10) << "_rename_open_dn dn dne in " << *dir << endl;
    reply_request(req, -ENOENT);
    return false;
  }
  
  if (!dn && !dir->is_complete()) {
    dout(10) << "_rename_open_dn readding incomplete dir" << endl;
    dir->fetch(new C_MDS_RetryRequest(mds, req, ref));
    return false;
  }
  assert(dn && !dn->is_null());
  
  dout(10) << "_rename_open_dn dn is " << *dn << endl;
  CInode *in = mdcache->get_dentry_inode(dn, req, ref);
  if (!in) return false;
  dout(10) << "_rename_open_dn inode is " << *in << endl;
  
  return true;
}

void Server::handle_client_rename(MClientRequest *req, CInode *ref)
{
  dout(7) << "handle_client_rename on " << *req << endl;

  // traverse to source
  /*
    this is abnoraml, just for rename.  since we don't pin source path 
    (because we don't want to screw up the lock ordering) the ref inode 
    (normally/initially srcdiri) may move, and this may fail.
   */
  filepath refpath = req->get_filepath();
  string srcname = refpath.last_dentry();
  refpath = refpath.prefixpath(refpath.depth()-1);

  dout(7) << "handle_client_rename src traversing to srcdir " << refpath << endl;
  vector<CDentry*> trace;
  int r = mdcache->path_traverse(refpath, trace, true,
                                 req, new C_MDS_RetryRequest(mds, req, ref),
                                 MDS_TRAVERSE_FORWARD);
  if (r > 0) return;
  if (r < 0) {   // dne or something.  got renamed out from under us, probably!
    dout(7) << "traverse r=" << r << endl;
    reply_request(req, r);
    return;
  }
  
  CInode *srcdiri;
  if (trace.size()) 
    srcdiri = trace[trace.size()-1]->inode;
  else
    srcdiri = mdcache->get_root();

  dout(7) << "handle_client_rename srcdiri is " << *srcdiri << endl;

  dout(7) << "handle_client_rename srcname is " << srcname << endl;

  // make sure parent is a dir?
  if (!srcdiri->is_dir()) {
    dout(7) << "srcdiri not a dir " << *srcdiri << endl;
    reply_request(req, -EINVAL);
    return;
  }

  frag_t srcfg = srcdiri->pick_dirfrag(srcname);

  // open dirfrag?  is it mine?
  CDir *srcdir = try_open_auth_dir(srcdiri, srcfg, req);
  if (!srcdir) return;
  dout(7) << "handle_client_rename srcdir is " << *srcdir << endl;
  
  // ok, done passing buck.
  
  // src dentry
  CDentry *srcdn = srcdir->lookup(srcname);
  if (!_rename_open_dn(srcdir, srcdn, true, req, ref))
    return;

  // pin src dentry in cache (so it won't expire)
  mdcache->request_pin_dn(req, srcdn);
  
  // find the destination, normalize
  // discover, etc. on the way... just get it on the local node.
  filepath destpath = req->get_sarg();   

  C_MDS_RenameTraverseDst *onfinish = new C_MDS_RenameTraverseDst(this, req, ref, srcdn, destpath);
  Context *ondelay = new C_MDS_RetryRequest(mds, req, ref);
  
  mdcache->path_traverse(destpath, onfinish->trace, false,
                         req, ondelay,
                         MDS_TRAVERSE_DISCOVER, 
                         onfinish);
}

void Server::handle_client_rename_2(MClientRequest *req,
				    CInode *ref,
				    CDentry *srcdn,
				    filepath& destpath,
				    vector<CDentry*>& trace,
				    int r)
{
  dout(7) << "handle_client_rename_2 on " << *req << endl;
  dout(12) << " r = " << r << " trace depth " << trace.size()
	   << "  destpath depth " << destpath.depth() << endl;

  // make sure srcdn is readable, srci is still there.
  if (!_rename_open_dn(srcdn->dir, srcdn, true, req, ref))
    return;
  CInode *srci = srcdn->inode;

  // note: trace includes root, destpath doesn't (include leading /)
  if (trace.size() && trace[trace.size()-1]->is_null()) {
    dout(10) << "dropping null dentry from tail of trace" << endl;
    trace.pop_back();    // drop it!
  }

  // identify dest  
  CDentry* lastdn = 0;
  CInode* lastin = 0;
  if (trace.size()) {
    lastdn = trace[trace.size()-1];
    dout(10) << "handle_client_rename_2 traced to " << *lastdn 
	     << ", trace size = " << trace.size()
	     << ", destpath = " << destpath.depth() << endl;
    lastin = mdcache->get_dentry_inode(lastdn, req, ref);
    if (!lastin) return;
  } else {
    dout(10) << "handle_client_rename_2 traced to root" << endl;
    lastin = mdcache->get_root();
  }
  assert(lastin);
  
  // make sure i can open the dir?
  frag_t dfg;
  CDir* destdir = 0;
  string destname;
  CDentry *destdn = 0;

  if (trace.size() == destpath.depth()) {
    // mv /some/thing /to/some/existing_other_thing
    if (lastin->is_dir() && !srci->is_dir()) {
      reply_request(req, -EISDIR);
      return;
    }
    if (!lastin->is_dir() && srci->is_dir()) {
      reply_request(req, -ENOTDIR);
      return;
    }

    // they are both files or both dirs.
    destdn = lastdn;
    destname = destdn->name;
    destdir = destdn->dir;

    if (lastin->is_dir()) {
      // is it empty?
      if (!_verify_rmdir(req, ref, lastin))
	return;
    }
  }
  else if (trace.size() == destpath.depth()-1) {
    if (!lastin->is_dir()) {
      // mv /some/thing /to/some/existing_file/blah
      dout(7) << "not a dir " << *lastin << endl;
      reply_request(req, -ENOTDIR);
      return;
    }

    // mv /some/thing /to/some/thing_that_dne
    destname = destpath.last_dentry();             // "thing_that_dne"
    dfg = lastin->pick_dirfrag(destname);
    destdir = try_open_dir(lastin, dfg, req, ref); // /to/some
    if (!destdir) return;
  }
  else {
    assert(trace.size() < destpath.depth()-1);

    // check traverse return value
    if (r > 0) return;  // discover, readdir, etc.

    assert(r < 0 || trace.size() == 0);  // musta been an error
    
    dout(7) << " rename dest " << destpath << " dne" << endl;
    reply_request(req, -EINVAL);
    return;
  }

  string srcpath = req->get_path();
  dout(10) << "handle_client_rename_2 srcpath " << srcpath << endl;
  dout(10) << "handle_client_rename_2 destpath " << destpath << endl;

  // src == dest?
  if (srcdn->get_dir() == destdir && srcdn->name == destname) {
    dout(7) << "rename src=dest, noop" << endl;
    reply_request(req, 0);
    return;
  }

  // dest a child of src?
  // e.g. mv /usr /usr/foo
  CDentry *pdn = destdir->inode->parent;
  while (pdn) {
    if (pdn == srcdn) {
      reply_request(req, -EINVAL);
      return;
    }
    pdn = pdn->dir->inode->parent;
  }

  // does destination exist?  (is this an overwrite?)
  CInode  *oldin = 0;
  if (destdn) {
    if (!destdn->is_null()) {
      oldin = mdcache->get_dentry_inode(destdn, req, ref);
      if (!oldin) return;
      dout(7) << "dest dn exists " << *destdn << " " << *oldin << endl;
    } else {
      dout(7) << "dest dn exists " << *destdn << endl;
    }
  } else {
    dout(7) << "dest dn dne (yet)" << endl;
  }
  
  // local or remote?
  dout(7) << "handle_client_rename_2 destname " << destname
	  << " destdir " << *destdir
	  << endl;

  // 
  if (!srcdn->is_auth() || !destdir->is_auth() ||
      (oldin && !oldin->is_auth())) {
    dout(7) << "rename has remote dest, or overwrites remote inode" << endl;
    dout(7) << "FOREIGN RENAME" << endl;
    
    reply_request(req, -EINVAL);   // for now!

  } else {
    dout(7) << "rename is local" << endl;

    _rename_local(req, ref,
		  srcdn, 
		  destdir, destdn, destname);
  }
}




class C_MDS_rename_local_finish : public Context {
  MDS *mds;
  MClientRequest *req;
  CDentry *srcdn;
  CDentry *destdn;
  CDentry *straydn;
  version_t ipv;
  version_t straypv;
  version_t destpv;
  version_t srcpv;
  time_t ictime;
public:
  version_t atid1;
  version_t atid2;
  C_MDS_rename_local_finish(MDS *m, MClientRequest *r, 
			    CDentry *sdn, CDentry *ddn, CDentry *stdn,
			    version_t v, time_t ct) :
    mds(m), req(r), 
    srcdn(sdn), destdn(ddn), straydn(stdn),
    ipv(v), 
    straypv(straydn ? straydn->get_projected_version():0),
    destpv(destdn->get_projected_version()),
    srcpv(srcdn->get_projected_version()),
    ictime(ct),
    atid1(0), atid2(0) { }
  void finish(int r) {
    assert(r == 0);
    mds->server->_rename_local_finish(req, srcdn, destdn, straydn,
				      srcpv, destpv, straypv, ipv, ictime, 
				      atid1, atid2);
  }
};

class C_MDS_rename_local_anchor : public Context {
  Server *server;
public:
  LogEvent *le;
  C_MDS_rename_local_finish *fin;
  version_t atid1;
  version_t atid2;
  
  C_MDS_rename_local_anchor(Server *s) : server(s), le(0), fin(0), atid1(0), atid2(0) { }
  void finish(int r) {
    server->_rename_local_reanchored(le, fin, atid1, atid2);
  }
};

void Server::_rename_local(MClientRequest *req,
			   CInode *ref,
			   CDentry *srcdn,
			   CDir *destdir,
			   CDentry *destdn,
			   const string& destname)
{
  dout(10) << "_rename_local " << *srcdn << " to " << destname << " in " << *destdir << endl;

  // make sure target (possibly null) dentry exists
  int r = prepare_null_dentry(req, ref, 
			      destdir->inode, destname, 
			      &destdir, &destdn, true);
  if (!r) return;
  dout(10) << "destdn " << *destdn << endl;

  // auth pins
  if (!mdcache->request_auth_pinned(req, srcdn->get_dir()) &&
      !srcdn->get_dir()->can_auth_pin()) {
    srcdn->get_dir()->add_waiter(CDir::WAIT_AUTHPINNABLE,
				 new C_MDS_RetryRequest(mds, req, ref));
    return;
  }
  if (!mdcache->request_auth_pinned(req, destdn->get_dir()) &&
      !destdn->get_dir()->can_auth_pin()) {
    destdn->get_dir()->add_waiter(CDir::WAIT_AUTHPINNABLE,
				  new C_MDS_RetryRequest(mds, req, ref));
    return;
  }
  if (destdn->inode &&
      !mdcache->request_auth_pinned(req, destdn->inode) &&
      !destdn->inode->can_auth_pin()) {
    destdn->inode->add_waiter(CInode::WAIT_AUTHPINNABLE,
			      new C_MDS_RetryRequest(mds, req, ref));
    return;
  }
  mdcache->request_auth_pin(req, srcdn->dir);
  mdcache->request_auth_pin(req, destdn->dir);
  if (destdn->inode)
    mdcache->request_auth_pin(req, destdn->inode);

  // locks
  bool dosrc = *srcdn < *destdn;
  for (int i=0; i<2; i++) {
    if (dosrc) {
      if (!mds->locker->dentry_xlock_start(srcdn, req, ref))
	return;
    } else {
      if (!mds->locker->dentry_xlock_start(destdn, req, ref))
	return;
    }
    dosrc = !dosrc;
  }
  if (destdn->inode &&
      !mds->locker->inode_hard_write_start(destdn->inode, req, ref))
    return;
  

  // verify rmdir?
  if (destdn->inode && destdn->inode->is_dir() &&
      !_verify_rmdir(req, ref, destdn->inode))
    return;

  // let's go.
  EUpdate *le = new EUpdate("rename_local");
  le->metablob.add_client_req(req->get_reqid());

  CDentry *straydn = 0;
  inode_t *pi = 0;
  version_t ipv = 0;
  
  C_MDS_rename_local_anchor *anchorfin = 0;
  C_Gather *anchorgather = 0;

  // primary+remote link merge?
  bool linkmerge = (srcdn->inode == destdn->inode &&
		    (srcdn->is_primary() || destdn->is_primary()));
  if (linkmerge) {
    dout(10) << "will merge remote+primary links" << endl;
    
    // destdn -> primary
    le->metablob.add_dir_context(destdn->dir);
    ipv = destdn->pre_dirty(destdn->inode->inode.version);
    pi = le->metablob.add_primary_dentry(destdn, true, destdn->inode); 
    
    // do src dentry
    le->metablob.add_dir_context(srcdn->dir);
    srcdn->pre_dirty();
    le->metablob.add_null_dentry(srcdn, true);

    // anchor update?
    if (srcdn->is_primary() && srcdn->inode->is_anchored() &&
	srcdn->dir != destdn->dir) {
      dout(10) << "reanchoring src->dst " << *srcdn->inode << endl;
      vector<Anchor> trace;
      destdn->make_anchor_trace(trace, srcdn->inode);
      anchorfin = new C_MDS_rename_local_anchor(this);
      mds->anchorclient->prepare_update(srcdn->inode->ino(), trace, &anchorfin->atid1, anchorfin);
    }

  } else {
    // move to stray?
    if (destdn->is_primary()) {
      // primary.
      // move inode to stray dir.
      string straydname;
      destdn->inode->name_stray_dentry(straydname);
      frag_t fg = mdcache->get_stray()->pick_dirfrag(straydname);
      CDir *straydir = mdcache->get_stray()->get_or_open_dirfrag(mdcache, fg);
      straydn = straydir->add_dentry(straydname, 0);
      dout(10) << "straydn is " << *straydn << endl;

      // renanchor?
      if (destdn->inode->is_anchored()) {
	dout(10) << "reanchoring dst->stray " << *destdn->inode << endl;
	vector<Anchor> trace;
	straydn->make_anchor_trace(trace, destdn->inode);
	anchorfin = new C_MDS_rename_local_anchor(this);
	anchorgather = new C_Gather(anchorfin);
	mds->anchorclient->prepare_update(destdn->inode->ino(), trace, &anchorfin->atid1, 
					  anchorgather->new_sub());
      }

      // link-- inode, move to stray dir.
      le->metablob.add_dir_context(straydn->dir);
      ipv = straydn->pre_dirty(destdn->inode->inode.version);
      pi = le->metablob.add_primary_dentry(straydn, true, destdn->inode);
    } 
    else if (destdn->is_remote()) {
      // remote.
      // nlink-- targeti
      le->metablob.add_dir_context(destdn->inode->get_parent_dir());
      ipv = destdn->inode->pre_dirty();
      pi = le->metablob.add_primary_dentry(destdn->inode->parent, true, destdn->inode);  // update primary
      dout(10) << "remote targeti (nlink--) is " << *destdn->inode << endl;
    }
    else {
      assert(destdn->is_null());
    }

    // add dest dentry
    le->metablob.add_dir_context(destdn->dir);
    if (srcdn->is_primary()) {
      dout(10) << "src is a primary dentry" << endl;
      destdn->pre_dirty(srcdn->inode->inode.version);
      le->metablob.add_primary_dentry(destdn, true, srcdn->inode); 

      if (srcdn->inode->is_anchored()) {
	dout(10) << "reanchoring src->dst " << *srcdn->inode << endl;
	vector<Anchor> trace;
	destdn->make_anchor_trace(trace, srcdn->inode);
	if (!anchorfin) anchorfin = new C_MDS_rename_local_anchor(this);
	if (!anchorgather) anchorgather = new C_Gather(anchorfin);
	mds->anchorclient->prepare_update(srcdn->inode->ino(), trace, &anchorfin->atid2, 
					  anchorgather->new_sub());
	
      }
    } else {
      assert(srcdn->is_remote());
      dout(10) << "src is a remote dentry" << endl;
      destdn->pre_dirty();
      le->metablob.add_remote_dentry(destdn, true, srcdn->get_remote_ino()); 
    }
    
    // remove src dentry
    le->metablob.add_dir_context(srcdn->dir);
    srcdn->pre_dirty();
    le->metablob.add_null_dentry(srcdn, true);
  }

  if (pi) {
    // update journaled target inode
    pi->nlink--;
    pi->ctime = g_clock.gettime();
    pi->version = ipv;
  }

  C_MDS_rename_local_finish *fin = new C_MDS_rename_local_finish(mds, req, 
								 srcdn, destdn, straydn,
								 ipv, pi ? pi->ctime:0);
  
  if (anchorfin) {
    // doing anchor update prepare first
    anchorfin->fin = fin;
    anchorfin->le = le;
  } else {
    // log + wait
    mdlog->submit_entry(le);
    mdlog->wait_for_sync(fin);
  }
}


void Server::_rename_local_reanchored(LogEvent *le, C_MDS_rename_local_finish *fin, 
				      version_t atid1, version_t atid2)
{
  dout(10) << "_rename_local_reanchored, logging " << *le << endl;
  
  // note anchor transaction ids
  fin->atid1 = atid1;
  fin->atid2 = atid2;

  // log + wait
  mdlog->submit_entry(le);
  mdlog->wait_for_sync(fin);
}


void Server::_rename_local_finish(MClientRequest *req, 
				  CDentry *srcdn, CDentry *destdn, CDentry *straydn,
				  version_t srcpv, version_t destpv, version_t straypv, version_t ipv,
				  time_t ictime,
				  version_t atid1, version_t atid2)
{
  dout(10) << "_rename_local_finish " << *req << endl;

  CInode *oldin = destdn->inode;
  
  // primary+remote link merge?
  bool linkmerge = (srcdn->inode == destdn->inode &&
		    (srcdn->is_primary() || destdn->is_primary()));

  if (linkmerge) {
    assert(ipv);
    if (destdn->is_primary()) {
      dout(10) << "merging remote onto primary link" << endl;

      // nlink-- in place
      destdn->inode->inode.nlink--;
      destdn->inode->inode.ctime = ictime;
      destdn->inode->mark_dirty(destpv);

      // unlink srcdn
      srcdn->dir->unlink_inode(srcdn);
      srcdn->mark_dirty(srcpv);
    } else {
      dout(10) << "merging primary onto remote link" << endl;
      assert(srcdn->is_primary());
      
      // move inode to dest
      srcdn->dir->unlink_inode(srcdn);
      destdn->dir->unlink_inode(destdn);
      destdn->dir->link_inode(destdn, oldin);
      
      // nlink--
      destdn->inode->inode.nlink--;
      destdn->inode->inode.ctime = ictime;
      destdn->inode->mark_dirty(destpv);
      
      // mark src dirty
      srcdn->mark_dirty(srcpv);
    }
  } 
  else {
    // unlink destdn?
    if (!destdn->is_null())
      destdn->dir->unlink_inode(destdn);
    
    if (straydn) {
      // relink oldin to stray dir
      assert(oldin);
      straydn->dir->link_inode(straydn, oldin);
      assert(straypv == ipv);
    }
    
    if (oldin) {
      // nlink--
      oldin->inode.nlink--;
      oldin->inode.ctime = ictime;
      oldin->mark_dirty(ipv);
    }
    
    CInode *in = srcdn->inode;
    assert(in);
    if (srcdn->is_remote()) {
      srcdn->dir->unlink_inode(srcdn);
      destdn->dir->link_inode(destdn, in->ino());    
    } else {
      srcdn->dir->unlink_inode(srcdn);
      destdn->dir->link_inode(destdn, in);
    }
    destdn->mark_dirty(destpv);
    srcdn->mark_dirty(srcpv);
  }

  // commit anchor updates?
  if (atid1) mds->anchorclient->commit(atid1);
  if (atid2) mds->anchorclient->commit(atid2);

  // update subtree map?
  if (destdn->inode->is_dir()) 
    mdcache->adjust_subtree_after_rename(destdn->inode, srcdn->dir);

  // share news with replicas
  // ***

  // unlock
  mds->locker->dentry_xlock_finish(srcdn);
  mds->locker->dentry_xlock_finish(destdn);
  if (oldin)
    mds->locker->inode_hard_write_finish(oldin);

  // reply
  MClientReply *reply = new MClientReply(req, 0);
  reply_request(req, reply, destdn->dir->get_inode());  // FIXME: imprecise ref

  // clean up?
  if (straydn) 
    mdcache->eval_stray(straydn);
}




/*
void Server::handle_client_rename_local(MClientRequest *req,
					CInode *ref,
					const string& srcpath,
					CInode *srcdiri,
					CDentry *srcdn,
					const string& destpath,
					CDir *destdir,
					CDentry *destdn,
					const string& destname)
{
*/
  //bool everybody = false;
  //if (true || srcdn->inode->is_dir()) {
    /* overkill warning: lock w/ everyone for simplicity.  FIXME someday!  along with the foreign rename crap!
       i could limit this to cases where something beneath me is exported.
       could possibly limit the list.    (maybe.)
       Underlying constraint is that, regardless of the order i do the xlocks, and whatever
       imports/exports might happen in the process, the destdir _must_ exist on any node
       importing something beneath me when rename finishes, or else mayhem ensues when
       their import is dangling in the cache.
     */
    /*
      having made a proper mess of this on the first pass, here is my plan:
      
      - xlocks of src, dest are done in lex order
      - xlock is optional.. if you have the dentry, lock it, if not, don't.
      - if you discover an xlocked dentry, you get the xlock.

      possible trouble:
      - you have an import beneath the source, and don't have the dest dir.
        - when the actual rename happens, you discover the dest
        - actually, do this on any open dir, so we don't detach whole swaths
          of our cache.
      
      notes:
      - xlocks are initiated from authority, as are discover_replies, so replicas are 
        guaranteed to either not have dentry, or to have it xlocked. 
      - 
      - foreign xlocks are eventually unraveled by the initiator on success or failure.

      todo to make this work:
      - hose bool everybody param crap
      /- make handle_lock_dn not discover, clean up cases
      /- put dest path in MRenameNotify
      /- make rename_notify discover if its a dir
      /  - this will catch nested imports too, obviously
      /- notify goes to merged list on local rename
      /- notify goes to everybody on a foreign rename 
      /- handle_notify needs to gracefully ignore spurious notifies
    */
  //dout(7) << "handle_client_rename_local: overkill?  doing xlocks with _all_ nodes" << endl;
  //everybody = true;
  //}
/*
  bool srclocal = srcdn->dir->dentry_authority(srcdn->name).first == mds->get_nodeid();
  bool destlocal = destdir->dentry_authority(destname).first == mds->get_nodeid();

  dout(7) << "handle_client_rename_local: src local=" << srclocal << " " << *srcdn << endl;
  if (destdn) {
    dout(7) << "handle_client_rename_local: dest local=" << destlocal << " " << *destdn << endl;
  } else {
    dout(7) << "handle_client_rename_local: dest local=" << destlocal << " dn dne yet" << endl;
  }

  // lock source and dest dentries, in lexicographic order.
  bool dosrc = srcpath < destpath;
  for (int i=0; i<2; i++) {
    if (dosrc) {

      // src
      if (srclocal) {
        if (!srcdn->is_xlockedbyme(req) &&
            !mds->locker->dentry_xlock_start(srcdn, req, ref))
          return;  
      } else {
        if (!srcdn || srcdn->xlockedby != req) {
          mds->locker->dentry_xlock_request(srcdn->dir, srcdn->name, false, req, new C_MDS_RetryRequest(mds, req, ref));
          return;
        }
      }
      dout(7) << "handle_client_rename_local: srcdn is xlock " << *srcdn << endl;
      
    } else {

      if (destlocal) {
        // dest
        if (!destdn) destdn = destdir->add_dentry(destname);
        if (!destdn->is_xlockedbyme(req) &&
            !mds->locker->dentry_xlock_start(destdn, req, ref)) {
          if (destdn->is_clean() && destdn->is_null() && destdn->is_sync()) destdir->remove_dentry(destdn);
          return;
        }
      } else {
        if (!destdn || destdn->xlockedby != req) {
          // NOTE: require that my xlocked item be a leaf/file, NOT a dir.  in case
          // my traverse and determination of dest vs dest/srcfilename was out of date.
          mds->locker->dentry_xlock_request(destdir, destname, true, req, new C_MDS_RetryRequest(mds, req, ref));
          return;
        }
      }
      dout(7) << "handle_client_rename_local: destdn is xlock " << *destdn << endl;

    }
    
    dosrc = !dosrc;
  }

  
  // final check: verify if dest exists that src is a file

  // FIXME: is this necessary?

  if (destdn->inode) {
    if (destdn->inode->is_dir()) {
      dout(7) << "handle_client_rename_local failing, dest exists and is a dir: " << *destdn->inode << endl;
      assert(0);
      reply_request(req, -EINVAL);  
      return; 
    }
    if (srcdn->inode->is_dir()) {
      dout(7) << "handle_client_rename_local failing, dest exists and src is a dir: " << *destdn->inode << endl;
      assert(0);
      reply_request(req, -EINVAL);  
      return; 
    }
  } else {
    // if destdn->inode is null, then we know it's a non-existent dest,
    // why?  because if it's local, it dne.  and if it's remote, we xlocked with 
    // REQXLOCKC, which will only allow you to lock a file.
    // so we know dest is a file, or non-existent
    if (!destlocal) {
      if (srcdn->inode->is_dir()) { 
        // help: maybe the dest exists and is a file?   ..... FIXME
      } else {
        // we're fine, src is file, dest is file|dne
      }
    }
  }
  
  mds->balancer->hit_dir(srcdn->dir, META_POP_DWR);
  mds->balancer->hit_dir(destdn->dir, META_POP_DWR);

  // we're golden.
  // everything is xlocked by us, we rule, etc.
  MClientReply *reply = new MClientReply(req, 0);
  mdcache->renamer->file_rename( srcdn, destdn,
				 new C_MDS_CommitRequest(this, req, reply, srcdn->inode,
							 new EString("file rename fixme")) );
}



*/







// ===================================
// TRUNCATE, FSYNC

/*
 * FIXME: this truncate implemention is WRONG WRONG WRONG
 */

void Server::handle_client_truncate(MClientRequest *req, CInode *cur)
{
  // auth pin
  if (!cur->can_auth_pin()) {
    dout(7) << "waiting for authpinnable on " << *cur << endl;
    cur->add_waiter(CInode::WAIT_AUTHPINNABLE, new C_MDS_RetryRequest(mds, req, cur));
    return;
  }
  mdcache->request_auth_pin(req, cur);

  // write
  if (!mds->locker->inode_file_write_start(cur, req, cur))
    return;  // fw or (wait for) lock

  // check permissions
  
  // do update
  cur->inode.size = req->args.truncate.length;
  cur->_mark_dirty(); // fixme

  mds->locker->inode_file_write_finish(cur);

  mds->balancer->hit_inode(cur, META_POP_IWR);   

  // start reply
  MClientReply *reply = new MClientReply(req, 0);

  // commit
  commit_request(req, reply, cur,
                 new EString("truncate fixme"));
}



// ===========================
// open, openc, close

void Server::handle_client_open(MClientRequest *req, CInode *cur)
{
  int flags = req->args.open.flags;
  int cmode = req->get_open_file_mode();

  dout(7) << "open " << flags << " on " << *cur << endl;
  dout(10) << "open flags = " << flags << "  filemode = " << cmode << endl;

  // is it a file?
  if (!(cmode & INODE_MODE_FILE)) {
    dout(7) << "not a regular file" << endl;
    reply_request(req, -EINVAL);                 // FIXME what error do we want?
    return;
  }

  // auth for write access
  if (cmode != FILE_MODE_R && cmode != FILE_MODE_LAZY &&
      !cur->is_auth()) {
    int auth = cur->authority().first;
    assert(auth != mds->get_nodeid());
    dout(9) << "open writeable on replica for " << *cur << " fw to auth " << auth << endl;
    
    mdcache->request_forward(req, auth);
    return;
  }

  // O_TRUNC
  if (flags & O_TRUNC) {
    // auth pin
    if (!cur->can_auth_pin()) {
      dout(7) << "waiting for authpinnable on " << *cur << endl;
      cur->add_waiter(CInode::WAIT_AUTHPINNABLE, new C_MDS_RetryRequest(mds, req, cur));
      return;
    }
    mdcache->request_auth_pin(req, cur);

    // write
    if (!mds->locker->inode_file_write_start(cur, req, cur))
      return;  // fw or (wait for) lock
    
    // do update
    cur->inode.size = 0;
    cur->_mark_dirty(); // fixme
    
    mds->locker->inode_file_write_finish(cur);
  }


  // hmm, check permissions or something.


  // can we issue the caps they want?
  version_t fdv = mds->locker->issue_file_data_version(cur);
  Capability *cap = mds->locker->issue_new_caps(cur, cmode, req);
  if (!cap) return; // can't issue (yet), so wait!

  dout(12) << "open gets caps " << cap_string(cap->pending()) << " for " << req->get_source() << " on " << *cur << endl;

  mds->balancer->hit_inode(cur, META_POP_IRD);

  // reply
  MClientReply *reply = new MClientReply(req, 0);
  reply->set_file_caps(cap->pending());
  reply->set_file_caps_seq(cap->get_last_seq());
  reply->set_file_data_version(fdv);
  reply_request(req, reply, cur);
}


class C_MDS_openc_finish : public Context {
  MDS *mds;
  MClientRequest *req;
  CDentry *dn;
  CInode *newi;
  version_t pv;
public:
  C_MDS_openc_finish(MDS *m, MClientRequest *r, CDentry *d, CInode *ni) :
    mds(m), req(r), dn(d), newi(ni),
    pv(d->get_projected_version()) {}
  void finish(int r) {
    assert(r == 0);

    // link the inode
    dn->get_dir()->link_inode(dn, newi);

    // dirty inode, dn, dir
    newi->mark_dirty(pv);

    // unlock
    mds->locker->dentry_xlock_finish(dn);

    // hit pop
    mds->balancer->hit_inode(newi, META_POP_IWR);

    // ok, do the open.
    mds->server->handle_client_open(req, newi);
  }
};


void Server::handle_client_openc(MClientRequest *req, CInode *diri)
{
  dout(7) << "open w/ O_CREAT on " << req->get_filepath() << endl;

  CDir *dir = 0;
  CDentry *dn = 0;
  
  // make dentry and inode, xlock dentry.
  bool excl = (req->args.open.flags & O_EXCL);
  int r = prepare_null_dentry(req, diri, &dir, &dn, !excl);  // okexist = !excl
  if (r == 0) return; // wait on something
  assert(dir);
  assert(dn);


  if (r == 1) {
    // created null dn.
    
    // xlock
    if (!mds->locker->dentry_xlock_start(dn, req, diri))
      return;

    // create inode.
    CInode *in = prepare_new_inode(req, dir);
    assert(in);

    // it's a file.
    dn->pre_dirty();
    in->inode.mode = 0644;              // FIXME req should have a umask
    in->inode.mode |= INODE_MODE_FILE;

    // prepare finisher
    C_MDS_openc_finish *fin = new C_MDS_openc_finish(mds, req, dn, in);
    EUpdate *le = new EUpdate("openc");
    le->metablob.add_client_req(req->get_reqid());
    le->metablob.add_dir_context(dir);
    inode_t *pi = le->metablob.add_primary_dentry(dn, true, in);
    pi->version = dn->get_projected_version();
    
    // log + wait
    mdlog->submit_entry(le);
    mdlog->wait_for_sync(fin);

    /*
      FIXME. this needs to be rewritten when the write capability stuff starts
      getting journaled.  
    */
  } else {
    // exists!

    // O_EXCL?
    if (req->args.open.flags & O_EXCL) {
      // fail.
      dout(10) << "O_EXCL, target exists, failing with -EEXIST" << endl;
      reply_request(req, -EEXIST, diri);
      return;
    } 

    // get inode
    CInode *in = mdcache->get_dentry_inode(dn, req, diri);
    if (!in) return;
        
    // FIXME: do i need to repin path based existent inode? hmm.
    handle_client_open(req, in);
  }
}














