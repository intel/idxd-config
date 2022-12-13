// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "accel_test.h"
#include "algorithms/iaa_zcompress.h"

#define IAA_ZCOMPRESS_BLOCK_SIZE (128)

static uint16_t iaa_zcompress16_get_word_pattern(uint64_t pattern)
{
	uint16_t word_pattern = 0;
	int position = (get_random_value() % 4);

	word_pattern = (uint16_t)((pattern & (0xFFFF << (16 * position))) >> (16 * position));
	return word_pattern;
}

void iaa_zcompress16_randomize_input(void *dst, uint64_t pattern, int len)
{
	int i;
	int num_words = len / 2;

	for (i = 0; i < num_words; i++) {
		if (get_random_value() % 2)
			((uint16_t *)dst)[i] = iaa_zcompress16_get_word_pattern(pattern);
		else
			((uint16_t *)dst)[i] = 0;
	}
}

int iaa_do_zcompress8(void *dst, void *src, int src_len)
{
	int i, j, dst_len = 0;
	uint8_t *tags;
	int num_blocks = src_len / IAA_ZCOMPRESS_BLOCK_SIZE;
	int remainder_bytes = src_len % IAA_ZCOMPRESS_BLOCK_SIZE;
	uint8_t *src_ptr = (uint8_t *)src;
	uint8_t *dst_ptr = (uint8_t *)dst;

	for (i = 0; i < num_blocks; i++) {
		tags = dst_ptr;
		dst_ptr += 16;
		dst_len += 16;
		for (j = 0; j < (IAA_ZCOMPRESS_BLOCK_SIZE); j++) {
			if (*src_ptr != 0) {
				tags[j / 8] |= ((uint8_t)1 << (j % 8));
				*dst_ptr++ = *src_ptr;
				dst_len += 1;
			}

			src_ptr++;
		}
	}

	if (remainder_bytes) {
		tags = dst_ptr;
		for (i = 0; i < 16; i++)
			tags[i] = 0xFF;
		dst_ptr += 16;
		dst_len += 16;

		for (i = 0; i < (remainder_bytes); i++) {
			if (*src_ptr == 0) {
				tags[i / 8] &= ~((uint8_t)1 << (i % 8));
			} else {
				*dst_ptr++ = *src_ptr;
				dst_len += 1;
			}

			src_ptr++;
		}
	}

	return dst_len;
}

int iaa_do_zcompress16(void *dst, void *src, int src_len)
{
	int i, j, dst_len = 0;
	uint16_t *tags;
	int num_blocks = src_len / IAA_ZCOMPRESS_BLOCK_SIZE;
	int remainder_bytes = src_len % IAA_ZCOMPRESS_BLOCK_SIZE;
	uint16_t *src_ptr = (uint16_t *)src;
	uint16_t *dst_ptr = (uint16_t *)dst;

	for (i = 0; i < num_blocks; i++) {
		tags = dst_ptr;
		dst_ptr += 4;
		dst_len += 8;
		for (j = 0; j < (IAA_ZCOMPRESS_BLOCK_SIZE / 2); j++) {
			if (*src_ptr != 0) {
				tags[j / 16] |= ((uint16_t)1 << (j % 16));
				*dst_ptr++ = *src_ptr;
				dst_len += 2;
			}

			src_ptr++;
		}
	}

	if (remainder_bytes) {
		tags = dst_ptr;
		tags[0] = 0xFFFF;
		tags[1] = 0xFFFF;
		tags[2] = 0xFFFF;
		tags[3] = 0xFFFF;
		dst_ptr += 4;
		dst_len += 8;

		for (i = 0; i < (remainder_bytes / 2); i++) {
			if (*src_ptr == 0) {
				tags[i / 16] &= ~((uint16_t)1 << (i % 16));
			} else {
				*dst_ptr++ = *src_ptr;
				dst_len += 2;
			}

			src_ptr++;
		}
	}

	return dst_len;
}

int iaa_do_zcompress32(void *dst, void *src, int src_len)
{
	int i, j, dst_len = 0;
	uint32_t *tags;
	int num_blocks = src_len / IAA_ZCOMPRESS_BLOCK_SIZE;
	int remainder_bytes = src_len % IAA_ZCOMPRESS_BLOCK_SIZE;
	uint32_t *src_ptr = (uint32_t *)src;
	uint32_t *dst_ptr = (uint32_t *)dst;

	for (i = 0; i < num_blocks; i++) {
		tags = dst_ptr;
		dst_ptr += 1;
		dst_len += 4;
		for (j = 0; j < (IAA_ZCOMPRESS_BLOCK_SIZE / 4); j++) {
			if (*src_ptr != 0) {
				*tags |= ((uint32_t)1 << j);
				*dst_ptr++ = *src_ptr;
				dst_len += 4;
			}

			src_ptr++;
		}
	}

	if (remainder_bytes) {
		tags = dst_ptr;
		*tags = 0xFFFFFFFF;
		dst_ptr += 1;
		dst_len += 4;

		for (i = 0; i < (remainder_bytes / 4); i++) {
			if (*src_ptr == 0) {
				*tags &= ~((uint32_t)1 << i);
			} else {
				*dst_ptr++ = *src_ptr;
				dst_len += 4;
			}

			src_ptr++;
		}
	}

	return dst_len;
}

int iaa_do_zdecompress8(void *dst, void *src, int src_len)
{
	int i, j, dst_len = 0;
	uint64_t tags[2];
	int remainder_len = src_len;
	uint8_t *src_ptr = (uint8_t *)src;
	uint8_t *dst_ptr = (uint8_t *)dst;

	for (i = 0; i < (src_len); i++) {
		tags[0] = (((uint64_t)src_ptr[7]) << 56) | (((uint64_t)src_ptr[6]) << 48) |
			  (((uint64_t)src_ptr[5]) << 40) | (((uint64_t)src_ptr[4]) << 32) |
			  (((uint64_t)src_ptr[3]) << 24) | (((uint64_t)src_ptr[2]) << 16) |
			  (((uint64_t)src_ptr[1]) << 8) | ((uint64_t)src_ptr[0]);
		tags[1] = (((uint64_t)src_ptr[15]) << 56) | (((uint64_t)src_ptr[14]) << 48) |
			  (((uint64_t)src_ptr[13]) << 40) | (((uint64_t)src_ptr[12]) << 32) |
			  (((uint64_t)src_ptr[11]) << 24) | (((uint64_t)src_ptr[10]) << 16) |
			  (((uint64_t)src_ptr[9]) << 8) | ((uint64_t)src_ptr[8]);
		src_ptr += 16;
		remainder_len -= 16;

		for (j = 0; j < 128; j++) {
			if (tags[j / 64] & ((uint64_t)1 << (j % 64))) {
				if (remainder_len <= 0)
					break;
				*dst_ptr++ = *src_ptr++;
				remainder_len -= 1;
			} else {
				*dst_ptr++ = 0;
			}

			dst_len += 1;
		}

		if (remainder_len <= 0)
			break;
	}

	return dst_len;
}

int iaa_do_zdecompress16(void *dst, void *src, int src_len)
{
	int i, j, dst_len = 0;
	uint64_t tags;
	int remainder_len = src_len;
	uint16_t *src_ptr = (uint16_t *)src;
	uint16_t *dst_ptr = (uint16_t *)dst;

	for (i = 0; i < (src_len / 2); i++) {
		tags = (((uint64_t)src_ptr[3]) << 48) | (((uint64_t)src_ptr[2]) << 32) |
		       (((uint64_t)src_ptr[1]) << 16) | ((uint64_t)src_ptr[0]);
		src_ptr += 4;
		remainder_len -= 8;

		for (j = 0; j < 64; j++) {
			if (tags & ((uint64_t)1 << j)) {
				if (remainder_len <= 0)
					break;
				*dst_ptr++ = *src_ptr++;
				remainder_len -= 2;
			} else {
				*dst_ptr++ = 0;
			}

			dst_len += 2;
		}

		if (remainder_len <= 0)
			break;
	}

	return dst_len;
}

int iaa_do_zdecompress32(void *dst, void *src, int src_len)
{
	int i, j, dst_len = 0;
	uint32_t tags;
	int remainder_len = src_len;
	uint32_t *src_ptr = (uint32_t *)src;
	uint32_t *dst_ptr = (uint32_t *)dst;

	for (i = 0; i < (src_len / 4); i++) {
		tags = *src_ptr++;
		remainder_len -= 4;

		for (j = 0; j < 32; j++) {
			if (tags & ((uint32_t)1 << j)) {
				if (remainder_len <= 0)
					break;
				*dst_ptr++ = *src_ptr++;
				remainder_len -= 4;
			} else {
				*dst_ptr++ = 0;
			}

			dst_len += 4;
		}

		if (remainder_len <= 0)
			break;
	}

	return dst_len;
}
