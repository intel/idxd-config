// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <accfg/idxd.h>
#include "accel_test.h"
#include "iaa.h"

void iaa_prep_noop(struct task *tsk)
{
	info("preparing descriptor for noop\n");

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	acctest_prep_desc_common(tsk->desc, tsk->opcode, 0,
				 (uint64_t)(tsk->src1), 0, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void iaa_prep_crc64(struct task *tsk)
{
	info("preparing descriptor for crc64\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, 0,
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_crc64_flags = tsk->iaa_crc64_flags;
	tsk->desc->iax_crc64_poly = tsk->iaa_crc64_poly;
	tsk->comp->status = 0;
}

void iaa_prep_zcompress8(struct task *tsk)
{
	info("preparing descriptor for zcompress8\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}

void iaa_prep_zdecompress8(struct task *tsk)
{
	info("preparing descriptor for zdecompress8\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}

void iaa_prep_zcompress16(struct task *tsk)
{
	info("preparing descriptor for zcompress16\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}

void iaa_prep_zdecompress16(struct task *tsk)
{
	info("preparing descriptor for zdecompress16\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}

void iaa_prep_zcompress32(struct task *tsk)
{
	info("preparing descriptor for zcompress32\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}

void iaa_prep_zdecompress32(struct task *tsk)
{
	info("preparing descriptor for zdecompress32\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}

void iaa_prep_compress(struct task *tsk)
{
	info("preparing descriptor for compress\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_compr_flags = tsk->iaa_compr_flags;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}

void iaa_prep_decompress(struct task *tsk)
{
	info("preparing descriptor for decompress\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_decompr_flags = tsk->iaa_decompr_flags;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}

void iaa_prep_scan(struct task *tsk)
{
	info("preparing descriptor for scan\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_filter_flags = tsk->iaa_filter_flags;
	tsk->desc->iax_num_inputs = tsk->iaa_num_inputs;
	tsk->comp->status = 0;
}

void iaa_prep_set_membership(struct task *tsk)
{
	info("preparing descriptor for set membership\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_filter_flags = tsk->iaa_filter_flags;
	tsk->desc->iax_num_inputs = tsk->iaa_num_inputs;
	tsk->comp->status = 0;
}

void iaa_prep_extract(struct task *tsk)
{
	info("preparing descriptor for extract\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_filter_flags = tsk->iaa_filter_flags;
	tsk->desc->iax_num_inputs = tsk->iaa_num_inputs;
	tsk->comp->status = 0;
}

void iaa_prep_select(struct task *tsk)
{
	info("preparing descriptor for select\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_filter_flags = tsk->iaa_filter_flags;
	tsk->desc->iax_num_inputs = tsk->iaa_num_inputs;
	tsk->comp->status = 0;
}

void iaa_prep_rle_burst(struct task *tsk)
{
	info("preparing descriptor for rle burst\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_filter_flags = tsk->iaa_filter_flags;
	tsk->desc->iax_num_inputs = tsk->iaa_num_inputs;
	tsk->comp->status = 0;
}

void iaa_prep_find_unique(struct task *tsk)
{
	info("preparing descriptor for find unique\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_filter_flags = tsk->iaa_filter_flags;
	tsk->desc->iax_num_inputs = tsk->iaa_num_inputs;
	tsk->comp->status = 0;
}

void iaa_prep_expand(struct task *tsk)
{
	info("preparing descriptor for expand\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_filter_flags = tsk->iaa_filter_flags;
	tsk->desc->iax_num_inputs = tsk->iaa_num_inputs;
	tsk->comp->status = 0;
}

void iaa_prep_transl_fetch(struct task *tsk)
{
	info("preparing descriptor for transl_fetch\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, 0,
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void iaa_prep_encrypto(struct task *tsk)
{
	info("preparing descriptor for encrypto\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->desc->iax_cipher_flags = tsk->iaa_cipher_flags;
	tsk->comp->status = 0;
}

void iaa_prep_decrypto(struct task *tsk)
{
	info("preparing descriptor for decrypto\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->iax_src2_addr = (uint64_t)(tsk->src2);
	tsk->desc->iax_src2_xfer_size = tsk->iaa_src2_xfer_size;
	tsk->desc->iax_max_dst_size = tsk->iaa_max_dst_size;
	tsk->comp->status = 0;
}
