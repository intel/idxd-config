/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef _IAA_ZCOMPRESS_H_
#define _IAA_ZCOMPRESS_H_

#include <stdint.h>

void iaa_zcompress16_randomize_input(void *dst, uint64_t pattern, int len);
int iaa_do_zcompress16(void *dst, void *src, int src_len);
int iaa_do_zdecompress16(void *dst, void *src, int src_len);
int iaa_do_zcompress32(void *dst, void *src, int src_len);
int iaa_do_zdecompress32(void *dst, void *src, int src_len);

#endif
