
#include "Dedup.h"
#include "Dedup_ISAL.h"

#define USING_ISAL  1

bool ChunknFP::do_cnf(bufferlist & list) 
{
  generic_dout(20) << __func__ << " " << __LINE__ << " chunk_mode: " << chunk_mode 
	  << " fp_mode: " << fp_mode << 
	  " chunk_size: " << chunk_size << " buffer length: " << list.length() <<  dendl;
  out <<"---do_chunk------"<<" ";
  if (!chunk_data(list, cd)) {
    assert(0);
  }
  if (!do_fingerprint(list, cd)) {
    assert(0);
  }

  return true;
}

bool ChunknFP::do_cnf()
{
  assert(data.length());
  
  generic_dout(20) << __func__ << " " << __LINE__ << " chunk_mode: " << chunk_mode 
	  << " fp_mode: " << fp_mode << 
	  " chunk_size: " << chunk_size << " buffer length: " << data.length() <<  dendl;

  if (!chunk_data(data, cd)) {
    assert(0);
  }
  if (!do_fingerprint(data, cd)) {
    assert(0);
  }
  
  return true;
}

bool ChunknFP::chunk_data(bufferlist & list, ChunkData & cd) 
{
  char * ptr = list.c_str();
  if (!ptr) {
    return false;
  }
  int total_size = list.length();
  uint64_t pos = 0;
  generic_dout(20) << __func__ << " " << __LINE__ << " data size: " << total_size <<
	  " chunk_size " << chunk_size << dendl;

  assert(!(total_size % chunk_size));

  while (total_size > 0) {
    /* to do 
	content defined chunking */
    if (chunk_mode == FIXED_CHUNK) {
      ChunkEntry * ce = new ChunkEntry;
      //cd.chunks.insert(pos, ce);
      ce->start_pos = pos;
      ce->len = chunk_size;
      cd.chunks.push_back(ce);
      generic_dout(20) << __func__ << " " << __LINE__ << " pos: " << pos 
	      << dendl;
      pos += chunk_size;
      total_size = total_size - chunk_size;
    } else {
      assert(0);
    }
  }
  return true;
}

bool ChunknFP::do_fingerprint(bufferlist & list, ChunkData & cd)
{
  char * ptr = list.c_str();
  if (!ptr) {
    return false;
  }
  int total_size = list.length();

  generic_dout(20) << __func__ << " " << __LINE__ << " data size: " << total_size
	  << dendl;
#ifdef USING_ISAL
  if (chunk_mode == FIXED_CHUNK) {
      //unsigned char fingerprint[CEPH_CRYPTO_SHA1_DIGESTSIZE] = {0};
      if (fp_mode == FP_SHA1) {

  out <<"---using_ISAL------"<<" ";
    	  IsalFPRef isalnf(std::make_shared<IsalFP>(cd.chunks.size(), FP_SHA1));
    	  isalnf->fp_submit(ptr,cd);
    	  isalnf->fp_finish(cd);
      }else {
		assert(0);
      }
	} else {
		  assert(0);
  }
#else
  for (vector<ChunkEntry *>::iterator i = cd.chunks.begin();
      i != cd.chunks.end(); 
      ++i) {
    if (chunk_mode == FIXED_CHUNK) {
      //unsigned char fingerprint[CEPH_CRYPTO_SHA1_DIGESTSIZE] = {0};
      if (fp_mode == FP_SHA1) {

	SHA1 sha1_gen;
	//SHA_CTX sha1_gen;
	//SHA1_Init(&sha1_gen);
	sha1_gen.Update((const unsigned char *)ptr+(*i)->start_pos, (*i)->len);
	//SHA1_Update(&sha1_gen, (const unsigned char *)ptr+(*i)->start_pos, (*i)->len);
	sha1_gen.Final((unsigned char *)((*i)->fingerprint));
	//SHA1_Final((unsigned char *)((*i)->fingerprint), &sha1_gen);
#if 0
	SHA1().CalculateDigest((unsigned char*)(*i)->fingerprint,
			  (const unsigned char *)ptr+(*i)->start_pos, (*i)->len);
#endif
	//sha1_gen.Update((const unsigned char *)ptr+(*i)->start_pos, (*i)->len);
	//sha1_gen.Final((unsigned char *)((*i)->fingerprint));
	generic_dout(20) << __func__ << " " << __LINE__ << " data pos: " << (*i)->start_pos
		<< " finger print: " << (*i)->fingerprint << dendl;
      } else {
	assert(0);
      }
    } else {
      assert(0);
    }
  }
#endif
  return true;
}

#if 0
static inline void buf_to_hex(const unsigned char *buf, int len, char *str)
{
  int i;
  str[0] = '\0';
  for (i = 0; i < len; i++) {
    sprintf(&str[i*2], "%02x", (int)buf[i]);
  }
}
#endif

string ChunknFP::get_fp_to_string(int idx) 
{
  ChunkEntry * ce = cd.chunks[idx];
  assert(ce);

  if (fp_mode == FP_SHA1) {
    char p_str[CEPH_CRYPTO_SHA1_DIGESTSIZE*2+1] = {0};
    //char p_str[SHA_DIGEST_LENGTH*2+1] = {0};
    buf_to_hex(ce->fingerprint, CEPH_CRYPTO_SHA1_DIGESTSIZE, p_str);
    //buf_to_hex(ce->fingerprint, SHA_DIGEST_LENGTH, p_str);
    string fp_str(p_str);
    return fp_str;
  } else {
    /* to do */
    assert(0);
  }
}

string ChunknFP::get_fp_to_string(char * ptr)
{
  unsigned char * up_ptr = (unsigned char*)ptr;
  if (fp_mode == FP_SHA1) {
    char p_str[CEPH_CRYPTO_SHA1_DIGESTSIZE*2+1] = {0};
    //char p_str[SHA_DIGEST_LENGTH*2+1] = {0};
    buf_to_hex(up_ptr, CEPH_CRYPTO_SHA1_DIGESTSIZE, p_str);
    //buf_to_hex(up_ptr, SHA_DIGEST_LENGTH, p_str);
    //dout(0) << __func__ << " p_str: " << p_str << dendl;
    string fp_str = p_str;
    return fp_str;
  } else {
    /* to do */
    assert(0);
  }
}

