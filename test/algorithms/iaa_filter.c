// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <stdint.h>
#include "iaa_filter.h"

static uint32_t get_element(uint32_t *src1_ptr, uint32_t num_inputs,
			    struct iaa_filter_flags_t *flags_ptr, uint32_t input_idx)
{
	uint64_t qword;
	uint32_t start_bit;
	uint32_t element;
	uint32_t row;

	uint32_t element_width = flags_ptr->src1_width + 1;
	/* For Scan, Extract, Select, RLE Burst and Expand,
	 * drop_high_bits and drop_low_bits will always be 0
	 */
	uint32_t valid_width = element_width -
			       flags_ptr->drop_high_bits -
			       flags_ptr->drop_low_bits;
	uint64_t element_size = ((uint64_t)1) << valid_width;
	uint32_t mask = element_size - 1;

	row = (input_idx * element_width) / 32;

	if (input_idx < (num_inputs - 1))
		qword = (((uint64_t)src1_ptr[row + 1]) << 32) | ((uint64_t)src1_ptr[row]);
	else
		qword = (uint64_t)src1_ptr[row];

	start_bit = (input_idx * element_width) % 32;
	element = ((qword >> start_bit) >> flags_ptr->drop_low_bits) & mask;

	return element;
}

static void set_element(uint32_t *dst_ptr, uint32_t element,
			struct iaa_filter_flags_t *flags_ptr, uint32_t input_idx)
{
	uint64_t *qword_addr;
	uint32_t dword_offset;
	uint32_t bit_offset;
	uint32_t element_width = flags_ptr->src1_width + 1;
	/* For Scan, Extract, Select, RLE Burst and Expand,
	 * drop_high_bits and drop_low_bits will always be 0
	 */
	uint32_t valid_width = element_width -
			       flags_ptr->drop_high_bits -
			       flags_ptr->drop_low_bits;

	dword_offset = (valid_width * input_idx) / 32;
	bit_offset = (valid_width * input_idx) % 32;
	qword_addr = (uint64_t *)&dst_ptr[dword_offset];
	*qword_addr |= ((uint64_t)element) << bit_offset;
}

uint32_t iaa_do_scan(void *dst, void *src1, void *src2,
		     uint32_t num_inputs, uint32_t filter_flags)
{
	uint32_t input_idx;
	uint32_t dst_size;
	uint32_t *src1_ptr = (uint32_t *)src1;
	struct iaa_filter_aecs_t *src2_ptr = (struct iaa_filter_aecs_t *)src2;
	uint32_t *dst_ptr = (uint32_t *)dst;
	struct iaa_filter_flags_t *flags_ptr = (struct iaa_filter_flags_t *)(&filter_flags);
	uint32_t element_width = flags_ptr->src1_width + 1;
	uint64_t element_size = ((uint64_t)1) << element_width;
	uint32_t mask = element_size - 1;
	uint32_t element;

	for (input_idx = 0; input_idx < num_inputs; input_idx++) {
		element = get_element(src1_ptr, num_inputs,
				      (struct iaa_filter_flags_t *)&filter_flags, input_idx);
		if (element >= (src2_ptr->low_filter_param & mask) &&
		    element <= (src2_ptr->high_filter_param & mask)) {
			dst_ptr[input_idx / 32] |= 1 << (input_idx % 32);
		}
	}

	if (num_inputs % 8)
		dst_size = num_inputs / 8 + 1;
	else
		dst_size = num_inputs / 8;

	return dst_size;
}

uint32_t iaa_do_set_membership(void *dst, void *src1, void *src2,
			       uint32_t num_inputs, uint32_t filter_flags)
{
	uint32_t input_idx;
	uint32_t dst_size;
	uint32_t *src1_ptr = (uint32_t *)src1;
	uint32_t *src2_ptr = (uint32_t *)src2;
	uint32_t *dst_ptr = (uint32_t *)dst;
	uint32_t element;

	for (input_idx = 0; input_idx < num_inputs; input_idx++) {
		element = get_element(src1_ptr, num_inputs,
				      (struct iaa_filter_flags_t *)&filter_flags, input_idx);

		dst_ptr[input_idx / 32] |= ((src2_ptr[element / 32] >> (element % 32)) & 0x1) <<
					   (input_idx % 32);
	}

	if (num_inputs % 8)
		dst_size = num_inputs / 8 + 1;
	else
		dst_size = num_inputs / 8;

	return dst_size;
}

uint32_t iaa_do_extract(void *dst, void *src1, void *src2,
			uint32_t num_inputs, uint32_t filter_flags)
{
	uint32_t input_idx;
	uint32_t dst_size;
	uint32_t bit_size;
	uint32_t *src1_ptr = (uint32_t *)src1;
	struct iaa_filter_aecs_t *src2_ptr = (struct iaa_filter_aecs_t *)src2;
	uint32_t *dst_ptr = (uint32_t *)dst;
	struct iaa_filter_flags_t *flags_ptr = (struct iaa_filter_flags_t *)(&filter_flags);
	uint32_t element_width = flags_ptr->src1_width + 1;
	uint32_t element;

	for (input_idx = src2_ptr->low_filter_param;
	     input_idx <= src2_ptr->high_filter_param;
	     input_idx++) {
		element = get_element(src1_ptr, num_inputs,
				      (struct iaa_filter_flags_t *)&filter_flags, input_idx);
		set_element(dst_ptr, element,
			    (struct iaa_filter_flags_t *)&filter_flags,
			    input_idx - src2_ptr->low_filter_param);
	}

	if ((num_inputs - 1) < src2_ptr->low_filter_param)
		bit_size = 0;
	else if ((num_inputs - 1) < src2_ptr->high_filter_param)
		bit_size = (num_inputs - src2_ptr->low_filter_param) * element_width;
	else
		bit_size = (src2_ptr->high_filter_param - src2_ptr->low_filter_param + 1) *
			   element_width;

	if (bit_size % 8)
		dst_size = bit_size / 8 + 1;
	else
		dst_size = bit_size / 8;

	return dst_size;
}

uint32_t iaa_do_select(void *dst, void *src1, void *src2,
		       uint32_t num_inputs, uint32_t filter_flags)
{
	uint32_t input_idx, output_idx = 0;
	uint32_t dst_size, bit_size;
	uint32_t *src1_ptr = (uint32_t *)src1;
	uint32_t *src2_ptr = (uint32_t *)src2;
	uint32_t *dst_ptr = (uint32_t *)dst;
	struct iaa_filter_flags_t *flags_ptr = (struct iaa_filter_flags_t *)(&filter_flags);
	uint32_t element_width = flags_ptr->src1_width + 1;
	uint32_t element;

	for (input_idx = 0; input_idx < num_inputs; input_idx++) {
		if ((src2_ptr[input_idx / 32] >> (input_idx % 32)) & 0x1) {
			element = get_element(src1_ptr, num_inputs,
					      (struct iaa_filter_flags_t *)&filter_flags,
					      input_idx);
			set_element(dst_ptr, element,
				    (struct iaa_filter_flags_t *)&filter_flags, output_idx++);
		}
	}

	bit_size = output_idx * element_width;
	if (bit_size % 8)
		dst_size = bit_size / 8 + 1;
	else
		dst_size = bit_size / 8;

	return dst_size;
}

uint32_t iaa_do_rle_burst(void *dst, void *src1, void *src2,
			  uint32_t num_inputs, uint32_t filter_flags)
{
	uint32_t input_idx, i;
	uint32_t dst_size;
	uint32_t replica_times, total_replica_times = 0;
	uint32_t *src2_ptr = (uint32_t *)src2;
	uint32_t *dst_ptr = (uint32_t *)dst;
	struct iaa_filter_flags_t *flags_ptr = (struct iaa_filter_flags_t *)(&filter_flags);
	uint32_t element_width = flags_ptr->src1_width + 1;

	if (element_width == 8) {
		for (input_idx = 0; input_idx < num_inputs; input_idx++) {
			replica_times = ((uint8_t *)src1)[input_idx];
			if ((src2_ptr[input_idx / 32] >> (input_idx % 32)) & 0x1) {
				for (i = total_replica_times;
				     i < (total_replica_times + replica_times); i++)
					dst_ptr[i / 32] |= (1 << (i % 32));
			} else {
				for (i = total_replica_times;
				     i < (total_replica_times + replica_times); i++)
					dst_ptr[i / 32] &= ~(1 << (i % 32));
			}
			total_replica_times += replica_times;
		}
	} else if (element_width == 16) {
		for (input_idx = 0; input_idx < num_inputs; input_idx++) {
			replica_times = ((uint16_t *)src1)[input_idx];
			if ((src2_ptr[input_idx / 32] >> (input_idx % 32)) & 0x1) {
				for (i = total_replica_times;
				     i < (total_replica_times + replica_times); i++)
					dst_ptr[i / 32] |= (1 << (i % 32));
			} else {
				for (i = total_replica_times;
				     i < (total_replica_times + replica_times); i++)
					dst_ptr[i / 32] &= ~(1 << (i % 32));
			}
			total_replica_times += replica_times;
		}
	} else if (element_width == 32) {
		for (input_idx = 0; input_idx < (num_inputs - 1); input_idx++) {
			replica_times = ((uint32_t *)src1)[input_idx + 1] -
					((uint32_t *)src1)[input_idx];
			if ((src2_ptr[input_idx / 32] >> (input_idx % 32)) & 0x1) {
				for (i = total_replica_times;
				     i < (total_replica_times + replica_times); i++)
					dst_ptr[i / 32] |= (1 << (i % 32));
			} else {
				for (i = total_replica_times;
				     i < (total_replica_times + replica_times); i++)
					dst_ptr[i / 32] &= ~(1 << (i % 32));
			}
			total_replica_times += replica_times;
		}
	}

	if (total_replica_times % 8)
		dst_size = total_replica_times / 8 + 1;
	else
		dst_size = total_replica_times / 8;

	return dst_size;
}

uint32_t iaa_do_find_unique(void *dst, void *src1, void *src2,
			    uint32_t num_inputs, uint32_t filter_flags)
{
	uint32_t input_idx;
	uint32_t dst_size;
	uint32_t *src1_ptr = (uint32_t *)src1;
	uint32_t *dst_ptr = (uint32_t *)dst;
	struct iaa_filter_flags_t *flags_ptr = (struct iaa_filter_flags_t *)(&filter_flags);
	uint32_t element_width = flags_ptr->src1_width + 1;
	uint32_t valid_width = element_width -
			       flags_ptr->drop_high_bits -
			       flags_ptr->drop_low_bits;
	uint32_t element_size = 1 << valid_width;
	uint32_t element;

	for (input_idx = 0; input_idx < num_inputs; input_idx++) {
		element = get_element(src1_ptr, num_inputs,
				      (struct iaa_filter_flags_t *)&filter_flags, input_idx);
		dst_ptr[element / 32] |= 1 << (element % 32);
	}

	if (element_size % 8)
		dst_size = element_size / 8 + 1;
	else
		dst_size = element_size / 8;

	return dst_size;
}

uint32_t iaa_do_expand(void *dst, void *src1, void *src2,
		       uint32_t num_inputs, uint32_t filter_flags)
{
	uint32_t input_idx, output_idx = 0;
	uint32_t dst_size, bit_size;
	uint32_t *src1_ptr = (uint32_t *)src1;
	uint32_t *src2_ptr = (uint32_t *)src2;
	uint32_t *dst_ptr = (uint32_t *)dst;
	struct iaa_filter_flags_t *flags_ptr = (struct iaa_filter_flags_t *)(&filter_flags);
	uint32_t element_width = flags_ptr->src1_width + 1;
	uint32_t element;

	for (input_idx = 0; input_idx < num_inputs; input_idx++) {
		if ((src2_ptr[input_idx / 32] >> (input_idx % 32)) & 0x1) {
			element = get_element(src1_ptr, num_inputs,
					      (struct iaa_filter_flags_t *)&filter_flags,
					      output_idx++);
			set_element(dst_ptr, element,
				    (struct iaa_filter_flags_t *)&filter_flags, input_idx);
		} else {
			set_element(dst_ptr, 0,
				    (struct iaa_filter_flags_t *)&filter_flags, input_idx);
		}
	}

	bit_size = input_idx * element_width;
	if (bit_size % 8)
		dst_size = bit_size / 8 + 1;
	else
		dst_size = bit_size / 8;

	return dst_size;
}
