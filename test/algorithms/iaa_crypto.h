/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef _IAA_CRYPT_H_
#define _IAA_CRYPT_H_

#define IAA_CRYPTO_MASK_KEY_SIZE (0x02)
#define IAA_CRYPTO_MASK_FLUSH_CRYPTO_IN_ACCUM (0x08)
#define IAA_CRYPTO_AECS_SIZE (192)
#define IAA_CRYPTO_SRC2_SIZE (IAA_CRYPTO_AECS_SIZE * 2)

enum _crypto_type_t {
	IAA_AES_GCM = 0,
	IAA_AES_CFB,
	IAA_AES_XTS
};

struct iaa_crypto_aecs_t {
	uint32_t	filter_rsvd[6];
	uint8_t		crypto_algorithm;
	uint8_t		crypto_flags;
	uint16_t	crypto_accum_sizes;
	uint32_t	crypto_rsvd;
	uint32_t	crypto_input_accum[6];
	uint32_t	crypto_output_accum[4];
	uint32_t	aes_key_low[4];
	uint32_t	aes_key_high[4];
	uint32_t	crypto_rsvd2[4];
	uint32_t	counter_iv[4];
	uint32_t	gcm_h[4];
	uint32_t	hash[4];
	uint8_t		complement[24];
};

int iaa_do_crypto(uint8_t *out, uint8_t *in, int in_len, uint8_t *aes_key, uint8_t *aes_iv,
		  int key_size, enum _crypto_type_t crypto_type, int do_encrypt);

#endif
