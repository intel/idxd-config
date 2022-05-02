/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef _USR_CRC64_H_
#define _USR_CRC64_H_

#include <stdint.h>
#include <stdbool.h>

#define IAA_CRC64_EXTRA_FLAGS_BIT_ORDER 0x8000
#define IAA_CRC64_EXTRA_FLAGS_INVERT_CRC 0x4000

/* crc64-ecma-182 */
#define IAA_CRC64_POLYNOMIAL 0x42F0E1EBA9EA3693

uint64_t iaa_calculate_crc64(uint64_t poly, uint8_t *buf, uint32_t len,
			     uint8_t msb, uint8_t invcrc);

#endif
