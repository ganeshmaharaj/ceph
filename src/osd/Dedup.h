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

#ifndef CEPH_DEDUPE_H
#define CEPH_DEDUPE_H

#include "include/types.h"

#include <map>
#include <deque>
#include <boost/scoped_ptr.hpp>
#include <fstream>
#include <iostream>
#include <errno.h>

using namespace std;

#include "kv/KeyValueDB.h"
#include "common/ceph_context.h"

#include "common/errno.h"

#include "include/assert.h"
#include "common/config.h"

#include "common/ceph_crypto.h"
using ceph::crypto::SHA1;
//#include <openssl/sha.h>

#include "common/debug.h"
#include "rgw/rgw_common.h"
//#include "rgw/rgw_common.h"
#include "common/simple_cache.hpp"

/*
 * To Do
 * 1. contents defined chunking
 * 2. support digest (writeback mode)
 * 3. snap
 * 4. object version (1 object --> chunks)
 */

#define DEREFERENCE_OID "dec_ref_cnt"
#define REFERENCE_OID "inc_ref_cnt"
#define CHECK_INC_REFERENCE_OID "chk_inc_ref_cnt"
#define REFERENCE_KEY "ref"

#define DEDUPE_INFO "DEDUPE_INFO"
#define DEDUPE_OFFSET "_DEDUPE_OFFSET_"

#define DEDUPE_READ_BLOCK (4*1024*1024)

enum {
  DEUPE_NOP,
  DEDUPE_WRITE,
  DEDUPE_READ,
  DEDUPE_SETXATTR,
  DEDUPE_OVERWRITE,
};

enum chunk_modes {
  FIXED_CHUNK,
  COTEND_DEFINED_CHUNK // To Do
};

enum fp_modes {
  FP_SHA1,
  FP_SHA256,
  FP_SHA512,
  FP_MD5
};

enum object_states {
  IN_CACHE,
  IN_STORAGE
};

enum chunk_state {
  C_NO_STATE,
  C_CLEAN,
  C_MODIFIED,
  C_PRE_CAL,
};

enum writeback_mode {
  DE_PASSIVE,
  DE_ACTIVE 
};

struct ChunkEntry {
  uint64_t start_pos;
  uint64_t len;
  unsigned char fingerprint[CEPH_CRYPTO_SHA1_DIGESTSIZE + 1];
  //unsigned char fingerprint[SHA_DIGEST_LENGTH + 1];
  ChunkEntry() : start_pos(0), len(0) {
    for (int i=0; i<CEPH_CRYPTO_SHA1_DIGESTSIZE; i++) {
    //for (int i=0; i<SHA_DIGEST_LENGTH; i++) {
      fingerprint[i] = 0;
    }
  }
};

class ChunkData {
public:
  int mode;
  vector<ChunkEntry *> chunks;
  ChunkData() : mode(0) {}
  void init() {
    for (vector<ChunkEntry *>::iterator i = chunks.begin();
	i != chunks.end();
	++i) {
      delete *i;
    }
  }
  ~ChunkData() {
    init();
  }
};

class ChunknFP {
  int chunk_mode;
  int chunk_size;
  int fp_mode;
  ChunkData cd;
  bufferlist data;
public:
  bool do_cnf(bufferlist & list);
  bool do_cnf();
  bool chunk_data(bufferlist & list, ChunkData & cd);
  bool do_fingerprint(bufferlist & list, ChunkData & cd);
  string get_fp_to_string(int idx);
  string get_fp_to_string(char * ptr);
  int get_entry_size() {
    return cd.chunks.size();
  }
  uint64_t get_chunk_offset(unsigned int idx) {
    if (idx >= cd.chunks.size()) return 0;
    return cd.chunks[idx]->start_pos;
  }
  uint64_t get_chunk_len(unsigned int idx) {
    if (idx >= cd.chunks.size()) return 0;
    return cd.chunks[idx]->len;
  }
  void init_chunk_size(uint64_t c_size) {
    switch (c_size) {
      case 4*1024:
      case 8*1024 :
      case 16*1024 :
      case 32*1024 :
      case 64*1024 :
      case 128*1024 :
      case 256*1024 :
      case 512*1024 :
      case 1024*1024 :
      case 2*1024*1024 :
      case 4*1024*1024 :
	chunk_size = c_size;
	break;
      default :
	assert(0);
    }
  }

  ChunknFP (int chunk_mode_from, uint64_t chunk_block_from, int fp_mode) : fp_mode(fp_mode) {
    chunk_mode = chunk_mode_from;
    init_chunk_size(chunk_block_from);
  }

  ChunknFP (int chunk_mode_from, uint64_t chunk_block_from, int fp_mode, bufferlist &ob_data) : 
	    fp_mode(fp_mode), data(ob_data) {
    chunk_mode = chunk_mode_from;
    init_chunk_size(chunk_block_from);
  }
  //typedef ceph::shared_ptr<ChunknFP> Ref;
};

typedef ceph::shared_ptr<ChunknFP> ChunknFPRef;

#endif
