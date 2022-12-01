// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <openssl/evp.h>
#include "accel_test.h"
#include "iaa_crypto.h"

/* Dump aes_key to log */
static void dump_aes_key(uint8_t *aes_key)
{
	int i;
	uint32_t *raw = (uint32_t *)aes_key;

	dbg("aes_key addr: %p\n", aes_key);

	for (i = 0; i < (32 / 4); i++)
		dbg("aes_key[0x%X]: 0x%08x\n", i * 4, raw[i]);
}

/* Dump aes_iv to log */
static void dump_aes_iv(uint8_t *aes_iv)
{
	int i;
	uint32_t *raw = (uint32_t *)aes_iv;

	dbg("aes_iv addr: %p\n", aes_iv);

	for (i = 0; i < (16 / 4); i++)
		dbg("aes_iv[0x%X]: 0x%08x\n", i * 4, raw[i]);
}

int iaa_do_crypto(uint8_t *out, uint8_t *in, int in_len, uint8_t *aes_key, uint8_t *aes_iv,
		  int key_size, enum _crypto_type_t crypto_type, int do_encrypt)
{
	int out_len = 0, out_final_len = 0;
	uint8_t *out_ptr = out;
	EVP_CIPHER_CTX *ctx;

	dbg("%s: in_len=%d, key_size=%d, crypto_type=%d, do_encrypt=%d\n",
	    __func__, in_len, key_size, crypto_type, do_encrypt);
	dump_aes_key(aes_key);
	dump_aes_iv(aes_iv);

	/* Don't set key or IV right away; we want to check lengths */
	ctx = EVP_CIPHER_CTX_new();

	switch (crypto_type) {
	case IAA_AES_GCM:
		if (key_size == 128) {
			EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(),
					  NULL, NULL, NULL, do_encrypt);
			OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 12);
			OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
		} else {
			EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(),
					  NULL, NULL, NULL, do_encrypt);
			OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 12);
			OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
		}
		break;
	case IAA_AES_CFB:
		if (key_size == 128) {
			EVP_CipherInit_ex(ctx, EVP_aes_128_cfb(),
					  NULL, NULL, NULL, do_encrypt);
			OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
			OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
		} else {
			EVP_CipherInit_ex(ctx, EVP_aes_256_cfb(),
					  NULL, NULL, NULL, do_encrypt);
			OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
			OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
		}
		break;
	case IAA_AES_XTS:
		if (key_size == 128) {
			EVP_CipherInit_ex(ctx, EVP_aes_128_xts(),
					  NULL, NULL, NULL, do_encrypt);
			OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
			OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
		} else {
			EVP_CipherInit_ex(ctx, EVP_aes_256_xts(),
					  NULL, NULL, NULL, do_encrypt);
			OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
			OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 64);
		}
		break;
	default:
		printf("Unknown crypto type\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	/* Now we can set key and IV */
	EVP_CipherInit_ex(ctx, NULL, NULL, aes_key, aes_iv, do_encrypt);

	if (!EVP_CipherUpdate(ctx, out_ptr, &out_len, in, in_len)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	out_ptr += out_len;

	if (!EVP_CipherFinal_ex(ctx, out_ptr, &out_final_len)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	EVP_CIPHER_CTX_free(ctx);

	return (out_len + out_final_len);
}
