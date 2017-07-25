/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2017 Intel Corporation
 *
 * Author: Qiaowei Ren <qiaowei.ren@intel.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 */

#ifndef OPENSSL_CRYPTO_ACCEL_H
#define OPENSSL_CRYPTO_ACCEL_H

#include "crypto/crypto_accel.h"
#include "openssl/ossl_typ.h"
#include "openssl/crypto.h"
#include "openssl/engine.h"
#include "openssl/evp.h"

class OpenSSLCryptoAccel : public CryptoAccel {
 public:
  OpenSSLCryptoAccel();
	/*
  {
  	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG |
						OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
  }
	*/
  virtual ~OpenSSLCryptoAccel() {}

  bool cbc_encrypt(unsigned char* out, const unsigned char* in, size_t size,
                   const unsigned char (&iv)[AES_256_IVSIZE],
                   const unsigned char (&key)[AES_256_KEYSIZE]) override;
  bool cbc_decrypt(unsigned char* out, const unsigned char* in, size_t size,
                   const unsigned char (&iv)[AES_256_IVSIZE],
                   const unsigned char (&key)[AES_256_KEYSIZE]) override;
  /*
 private:
  ENGINE *eng;
  EVP_CIPHER_CTX ecctx;
  int final_len = 0;
  int err = 0;
  */
};
#endif
