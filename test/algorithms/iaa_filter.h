/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef _IAA_FILTER_H_
#define _IAA_FILTER_H_

#include <stdint.h>

#define IAA_FILTER_MAX_DEST_SIZE (2097152 * 2)
#define IAA_FILTER_MAX_SRC2_SIZE (2097152)

#define IAA_FILTER_AECS_SIZE (32)

struct iaa_filter_flags_t {
	uint32_t	src1_parse:2;
	uint32_t	src1_width:5;
	uint32_t	src2_width:5;
	uint32_t	src2_bit_order:1;
	uint32_t	output_width:2;
	uint32_t	output_bit_order:1;
	uint32_t	invert_output:1;
	uint32_t	drop_low_bits:5;
	uint32_t	drop_high_bits:5;
	uint32_t	rsvd:5;
};

struct iaa_filter_aecs_t {
	uint32_t	rsvd;
	uint32_t	rsvd2;
	uint32_t	low_filter_param;
	uint32_t	high_filter_param;
	uint32_t	rsvd3;
	uint32_t	rsvd4;
	uint32_t	rsvd5;
	uint32_t	rsvd6;
};

uint32_t iaa_do_scan(void *dst, void *src1, void *src2,
		     uint32_t num_inputs, uint32_t filter_flags);
uint32_t iaa_do_set_membership(void *dst, void *src1, void *src2,
			       uint32_t num_inputs, uint32_t filter_flags);
uint32_t iaa_do_extract(void *dst, void *src1, void *src2,
			uint32_t num_inputs, uint32_t filter_flags);
uint32_t iaa_do_select(void *dst, void *src1, void *src2,
		       uint32_t num_inputs, uint32_t filter_flags);
uint32_t iaa_do_rle_burst(void *dst, void *src1, void *src2,
			  uint32_t num_inputs, uint32_t filter_flags);
uint32_t iaa_do_find_unique(void *dst, void *src1, void *src2,
			    uint32_t num_inputs, uint32_t filter_flags);
uint32_t iaa_do_expand(void *dst, void *src1, void *src2,
		       uint32_t num_inputs, uint32_t filter_flags);

#endif
