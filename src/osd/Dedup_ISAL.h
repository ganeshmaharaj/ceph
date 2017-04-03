#ifndef DEDUPE_ISAL_H
#define DEDUPE_ISAL_H

#include "isa-l_crypto/sha1_mb.h"
#include "Dedup.h"
#include "common/ceph_crypto.h"
#include <stdlib.h>

class IsalFP {
public:
  int job_num;
  int fp_mode;

  SHA1_HASH_CTX_MGR *mgr = NULL;
  SHA1_HASH_CTX *ctxpool = NULL;

  IsalFP (int job_num, int fp_mode) : job_num(job_num), fp_mode(fp_mode){
	posix_memalign((void **)&mgr, 16, sizeof(SHA1_HASH_CTX_MGR));
	sha1_ctx_mgr_init(mgr);

	ctxpool = new SHA1_HASH_CTX[job_num];
	for (int i = 0; i < job_num; i++) {
		hash_ctx_init(&ctxpool[i]);
		ctxpool[i].user_data = (void *)((uint64_t) i);
	}
  }
  ~IsalFP(){
	  delete[] ctxpool;
	  ctxpool = NULL;
  }
  void fp_transform(SHA1_HASH_CTX *ctx, ChunkData & cd){
	  uint32_t t,j;
	  t = (unsigned long)(ctx->user_data);
	  ChunkEntry * ce = cd.chunks[t];

	  for (j=0; j<CEPH_CRYPTO_SHA1_DIGESTSIZE; j++){
		ce->fingerprint[j] = (uint8_t)((ctxpool[t].job.result_digest[j>>2] >> ((3-(j & 3)) * 8) ) & 255);
	  }
}
  void fp_submit(char* ptr,ChunkData & cd){
	  uint32_t i;
	  SHA1_HASH_CTX *ctx = NULL;
          vector<ChunkEntry *>::iterator tmpEntry;
	  for (tmpEntry = cd.chunks.begin(),i=0;
			  tmpEntry != cd.chunks.end(); ++tmpEntry,++i) {
		  ctx = sha1_ctx_mgr_submit(mgr,&ctxpool[i], (const unsigned char *)ptr+(*tmpEntry)->start_pos,
			  (*tmpEntry)->len, HASH_ENTIRE);
		  if (ctx) {
			  fp_transform(ctx,cd);
		  }
	  }

  }
  void fp_finish(ChunkData & cd){
         SHA1_HASH_CTX *ctx = NULL;
	  while ((ctx = sha1_ctx_mgr_flush(mgr))!= NULL) {
		  fp_transform(ctx, cd);
	  }
  }
};
typedef ceph::shared_ptr<IsalFP> IsalFPRef;
#endif
