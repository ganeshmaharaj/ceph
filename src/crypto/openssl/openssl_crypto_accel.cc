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

#include "crypto/openssl/openssl_crypto_accel.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include "stdio.h"
#include <iostream>

OpenSSLCryptoAccel::OpenSSLCryptoAccel()
{
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
//	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ENGINE_load_builtin_engines();

}

bool OpenSSLCryptoAccel::cbc_encrypt(unsigned char* out, const unsigned char* in, size_t size,
                             const unsigned char (&iv)[AES_256_IVSIZE],
                             const unsigned char (&key)[AES_256_KEYSIZE])
{
	ENGINE *eng;
	eng = ENGINE_by_id("qat");
	int isize = static_cast<int>(size);
	int *isize_ptr = &isize;
	if(eng)
	{
		std::cout << "Ganesh::: Unable to load engine" << std::endl;
	}
	EVP_CIPHER_CTX *ecctx;
	ecctx = EVP_CIPHER_CTX_new();
	int *final_len = new int(0);

  	if ((size % AES_256_IVSIZE) != 0) {
  	  return false;
  	}

	EVP_CIPHER_CTX_init(ecctx);
	EVP_EncryptInit_ex(ecctx, EVP_aes_256_cbc(), eng, ( unsigned char *)key, ( unsigned char * )iv);
	EVP_EncryptUpdate(ecctx, out, isize_ptr, in, isize);
	EVP_EncryptFinal_ex(ecctx, out, final_len);
	EVP_CIPHER_CTX_cleanup(ecctx);

  	return true;
}
bool OpenSSLCryptoAccel::cbc_decrypt(unsigned char* out, const unsigned char* in, size_t size,
                             const unsigned char (&iv)[AES_256_IVSIZE],
                             const unsigned char (&key)[AES_256_KEYSIZE])
{
  if ((size % AES_256_IVSIZE) != 0) {
    return false;
  }

  AES_KEY aes_key;
  if(AES_set_decrypt_key(const_cast<unsigned char*>(&key[0]), 256, &aes_key) < 0)
    return false;

  AES_cbc_encrypt(const_cast<unsigned char*>(in), out, size, &aes_key,
                  const_cast<unsigned char*>(&iv[0]), AES_DECRYPT);
  return true;
}
