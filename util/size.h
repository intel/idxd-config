/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */

#ifndef _ACCFG_SIZE_H_
#define _ACCFG_SIZE_H_

#include <stdint.h>

#define SZ_1K     0x00000400
#define SZ_4K     0x00001000
#define SZ_1M     0x00100000
#define SZ_2M     0x00200000
#define SZ_4M     0x00400000
#define SZ_16M    0x01000000
#define SZ_64M    0x04000000
#define SZ_1G     0x40000000
#define SZ_1T 0x10000000000ULL

uint64_t parse_size64(const char *str);
uint64_t __parse_size64(const char *str, uint64_t *units);

#define ALIGN(x, a) ((((uint64_t) x) + (a - 1)) & ~(a - 1))
#define ALIGN_DOWN(x, a) (((((uint64_t) x) + a) & ~(a - 1)) - a)
#define BITS_PER_LONG (sizeof(uint64_t) * 8)
#define HPAGE_SIZE (2 << 20)

#endif /* _ACCFG_SIZE_H_ */
