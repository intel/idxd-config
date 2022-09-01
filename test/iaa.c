// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/vfio.h>
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "accel_test.h"
#include "iaa.h"
#include "algorithms/iaa_crc64.h"
#include "algorithms/iaa_zcompress.h"
#include "algorithms/iaa_compress.h"
#include "algorithms/iaa_filter.h"

static struct iaa_filter_aecs_t iaa_filter_aecs = {
	.rsvd = 0,
	.rsvd2 = 0,
	.rsvd3 = 0,
	.rsvd4 = 0,
	.rsvd5 = 0,
	.rsvd6 = 0
};

static int init_crc64(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = src1_xfer_size;

	tsk->src1 = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, src1_xfer_size);
	tsk->iaa_crc64_poly = IAA_CRC64_POLYNOMIAL;

	return ACCTEST_STATUS_OK;
}

static int init_zcompress16(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = src1_xfer_size;

	tsk->src1 = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	iaa_zcompress16_randomize_input(tsk->src1, tsk->pattern, src1_xfer_size);

	tsk->dst1 = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size * 2);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, 0, src1_xfer_size * 2);

	tsk->output = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size * 2);
	if (!tsk->output)
		return -ENOMEM;
	memset_pattern(tsk->output, 0, src1_xfer_size * 2);

	tsk->iaa_max_dst_size = src1_xfer_size * 2;

	return ACCTEST_STATUS_OK;
}

static int init_zdecompress16(struct task *tsk, int tflags, int opcode, unsigned long input_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;

	tsk->input = aligned_alloc(ADDR_ALIGNMENT, input_size);
	if (!tsk->input)
		return -ENOMEM;
	iaa_zcompress16_randomize_input(tsk->input, tsk->pattern, input_size);

	tsk->src1 = aligned_alloc(ADDR_ALIGNMENT, input_size * 2);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, 0, input_size * 2);
	tsk->xfer_size = iaa_do_zcompress16(tsk->src1, tsk->input, input_size);

	tsk->dst1 = aligned_alloc(ADDR_ALIGNMENT, input_size);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, 0, input_size);

	tsk->output = aligned_alloc(ADDR_ALIGNMENT, input_size);
	if (!tsk->output)
		return -ENOMEM;
	memset_pattern(tsk->output, 0, input_size);

	tsk->iaa_max_dst_size = input_size;

	return ACCTEST_STATUS_OK;
}

static int init_zcompress32(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = src1_xfer_size;

	tsk->src1 = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	iaa_zcompress16_randomize_input(tsk->src1, tsk->pattern, src1_xfer_size);

	tsk->dst1 = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size * 2);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, 0, src1_xfer_size * 2);

	tsk->output = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size * 2);
	if (!tsk->output)
		return -ENOMEM;
	memset_pattern(tsk->output, 0, src1_xfer_size * 2);

	tsk->iaa_max_dst_size = src1_xfer_size * 2;

	return ACCTEST_STATUS_OK;
}

static int init_zdecompress32(struct task *tsk, int tflags, int opcode, unsigned long input_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;

	tsk->input = aligned_alloc(ADDR_ALIGNMENT, input_size);
	if (!tsk->input)
		return -ENOMEM;
	iaa_zcompress16_randomize_input(tsk->input, tsk->pattern, input_size);

	tsk->src1 = aligned_alloc(ADDR_ALIGNMENT, input_size * 2);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, 0, input_size * 2);
	tsk->xfer_size = iaa_do_zcompress32(tsk->src1, tsk->input, input_size);

	tsk->dst1 = aligned_alloc(ADDR_ALIGNMENT, input_size);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, 0, input_size);

	tsk->output = aligned_alloc(ADDR_ALIGNMENT, input_size);
	if (!tsk->output)
		return -ENOMEM;
	memset_pattern(tsk->output, 0, input_size);

	tsk->iaa_max_dst_size = input_size;

	return ACCTEST_STATUS_OK;
}

static int init_compress(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = src1_xfer_size;

	tsk->src1 = aligned_alloc(32, src1_xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, src1_xfer_size);

	tsk->src2 = aligned_alloc(32, IAA_COMPRESS_SRC2_SIZE);
	if (!tsk->src2)
		return -ENOMEM;
	memset_pattern(tsk->src2, 0, IAA_COMPRESS_SRC2_SIZE);

	tsk->dst1 = aligned_alloc(32, IAA_COMPRESS_MAX_DEST_SIZE);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, 0, IAA_COMPRESS_MAX_DEST_SIZE);

	tsk->output = aligned_alloc(32, IAA_COMPRESS_MAX_DEST_SIZE);
	if (!tsk->output)
		return -ENOMEM;
	memset_pattern(tsk->output, 0, IAA_COMPRESS_MAX_DEST_SIZE);

	return ACCTEST_STATUS_OK;
}

static int init_decompress(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->test_flags = tflags;
	tsk->xfer_size = src1_xfer_size;
	tsk->input_size = src1_xfer_size;

	tsk->input = aligned_alloc(32, src1_xfer_size);
	if (!tsk->input)
		return -ENOMEM;
	memset_pattern(tsk->input, tsk->pattern, src1_xfer_size);

	tsk->src1 = aligned_alloc(32, IAA_DECOMPRESS_MAX_DEST_SIZE);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, 0, IAA_DECOMPRESS_MAX_DEST_SIZE);
	memcpy(tsk->src1, tsk->input, src1_xfer_size);

	tsk->src2 = aligned_alloc(32, IAA_DECOMPRESS_SRC2_SIZE);
	if (!tsk->src2)
		return -ENOMEM;
	memset_pattern(tsk->src2, 0, IAA_DECOMPRESS_SRC2_SIZE);

	tsk->dst1 = aligned_alloc(32, IAA_DECOMPRESS_MAX_DEST_SIZE);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, 0, IAA_DECOMPRESS_MAX_DEST_SIZE);

	return ACCTEST_STATUS_OK;
}

static int init_scan(struct task *tsk, int tflags,
		     int opcode, unsigned long src1_xfer_size)
{
	uint32_t i;
	uint32_t pattern = 0x98765432;

	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = src1_xfer_size;

	tsk->src1 = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	for (i = 0; i < (src1_xfer_size / 4); i++)
		((uint32_t *)tsk->src1)[i] = pattern++;

	tsk->src2 = aligned_alloc(32, IAA_FILTER_AECS_SIZE);
	if (!tsk->src2)
		return -ENOMEM;
	memset_pattern(tsk->src2, 0, IAA_FILTER_AECS_SIZE);
	iaa_filter_aecs.low_filter_param = 0x98765440;
	iaa_filter_aecs.high_filter_param = 0x98765540;
	memcpy(tsk->src2, (void *)&iaa_filter_aecs, IAA_FILTER_AECS_SIZE);
	tsk->iaa_src2_xfer_size = IAA_FILTER_AECS_SIZE;

	tsk->dst1 = aligned_alloc(ADDR_ALIGNMENT, IAA_FILTER_MAX_DEST_SIZE);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, 0, IAA_FILTER_MAX_DEST_SIZE);

	tsk->iaa_max_dst_size = IAA_FILTER_MAX_DEST_SIZE;

	tsk->output = aligned_alloc(ADDR_ALIGNMENT, IAA_FILTER_MAX_DEST_SIZE);
	if (!tsk->output)
		return -ENOMEM;
	memset_pattern(tsk->output, 0, IAA_FILTER_MAX_DEST_SIZE);

	return ACCTEST_STATUS_OK;
}

static int init_set_membership(struct task *tsk, int tflags,
			       int opcode, unsigned long src1_xfer_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = src1_xfer_size;

	tsk->src1 = aligned_alloc(ADDR_ALIGNMENT, src1_xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, src1_xfer_size);

	tsk->src2 = aligned_alloc(32, IAA_FILTER_MAX_SRC2_SIZE);
	if (!tsk->src2)
		return -ENOMEM;
	memset_pattern(tsk->src2, 0xa5a5a5a55a5a5a5a, IAA_FILTER_MAX_SRC2_SIZE);
	tsk->iaa_src2_xfer_size = IAA_FILTER_MAX_SRC2_SIZE;

	tsk->dst1 = aligned_alloc(ADDR_ALIGNMENT, IAA_FILTER_MAX_DEST_SIZE);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, 0, IAA_FILTER_MAX_DEST_SIZE);

	tsk->iaa_max_dst_size = IAA_FILTER_MAX_DEST_SIZE;

	tsk->output = aligned_alloc(ADDR_ALIGNMENT, IAA_FILTER_MAX_DEST_SIZE);
	if (!tsk->output)
		return -ENOMEM;
	memset_pattern(tsk->output, 0, IAA_FILTER_MAX_DEST_SIZE);

	return ACCTEST_STATUS_OK;
}

int init_task(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size)
{
	int rc = 0;

	dbg("initilizing single task %#lx\n", tsk);

	/* allocate memory: src1*/
	switch (opcode) {
	case IAX_OPCODE_CRC64: /* intentionally empty */
		rc = init_crc64(tsk, tflags, opcode, src1_xfer_size);
		break;
	case IAX_OPCODE_ZCOMPRESS16:
		rc = init_zcompress16(tsk, tflags, opcode, src1_xfer_size);
		break;
	case IAX_OPCODE_ZDECOMPRESS16:
		rc = init_zdecompress16(tsk, tflags, opcode, src1_xfer_size);
		break;
	case IAX_OPCODE_ZCOMPRESS32:
		rc = init_zcompress32(tsk, tflags, opcode, src1_xfer_size);
		break;
	case IAX_OPCODE_ZDECOMPRESS32:
		rc = init_zdecompress32(tsk, tflags, opcode, src1_xfer_size);
		break;
	case IAX_OPCODE_COMPRESS:
		rc = init_compress(tsk, tflags, opcode, src1_xfer_size);
		break;
	case IAX_OPCODE_DECOMPRESS:
		rc = init_decompress(tsk, tflags, opcode, src1_xfer_size);
		break;
	case IAX_OPCODE_SCAN:
		rc = init_scan(tsk, tflags, opcode, src1_xfer_size);
		break;
	case IAX_OPCODE_SET_MEMBERSHIP:
		rc = init_set_membership(tsk, tflags, opcode, src1_xfer_size);
		break;
	}

	if (rc != ACCTEST_STATUS_OK) {
		err("init: opcode %d data failed\n", opcode);
		return rc;
	}

	dbg("Mem allocated: s1 %#lx s2 %#lx d %#lx\n",
	    tsk->src1, tsk->src2, tsk->dst1);

	return ACCTEST_STATUS_OK;
}

static int iaa_wait_noop(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("noop desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_noop_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);

		iaa_prep_noop(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}
	tsk_node = ctx->multi_task_node;
	info("Submitted all noop jobs\n");

	while (tsk_node) {
		ret = iaa_wait_noop(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}
	return ret;
}

static int iaa_wait_crc64(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("crc64 desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_crc64_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		iaa_prep_crc64(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all crc64 jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_crc64(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

static int iaa_wait_zcompress16(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("zcompress16 desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_zcompress16_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		iaa_prep_zcompress16(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all zcompress16 jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_zcompress16(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

static int iaa_wait_zdecompress16(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("zdecompress16 desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_zdecompress16_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		iaa_prep_zdecompress16(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all zdecompress16 jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_zdecompress16(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

static int iaa_wait_zcompress32(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("zcompress32 desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_zcompress32_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		iaa_prep_zcompress32(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all zcompress32 jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_zcompress32(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

static int iaa_wait_zdecompress32(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("zdecompress32 desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_zdecompress32_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		iaa_prep_zdecompress32(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all zdecompress32 jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_zdecompress32(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

static int iaa_wait_compress(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("compress desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_compress_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_WR_SRC2_CMPL | IDXD_OP_FLAG_RD_SRC2_AECS);
		tsk_node->tsk->iaa_src2_xfer_size = IAA_COMPRESS_AECS_SIZE;

		memcpy(tsk_node->tsk->src2, (void *)iaa_compress_aecs, IAA_COMPRESS_AECS_SIZE);

		tsk_node->tsk->iaa_compr_flags = (IDXD_COMPRESS_FLAG_EOB_BFINAL |
						  IDXD_COMPRESS_FLAG_FLUSH_OUTPUT);
		tsk_node->tsk->iaa_max_dst_size = ctx->wq_max_xfer_size;

		iaa_prep_compress(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all compress jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_compress(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

static int iaa_wait_decompress(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("decompress desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_decompress_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	// Compress
	while (tsk_node) {
		tsk_node->tsk->opcode = IAX_OPCODE_COMPRESS;
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_WR_SRC2_CMPL | IDXD_OP_FLAG_RD_SRC2_AECS);
		tsk_node->tsk->iaa_src2_xfer_size = IAA_COMPRESS_AECS_SIZE;

		memcpy(tsk_node->tsk->src2, (void *)iaa_compress_aecs, IAA_COMPRESS_AECS_SIZE);

		tsk_node->tsk->iaa_compr_flags = (IDXD_COMPRESS_FLAG_EOB_BFINAL |
						  IDXD_COMPRESS_FLAG_FLUSH_OUTPUT);
		tsk_node->tsk->iaa_max_dst_size = ctx->wq_max_xfer_size;

		iaa_prep_compress(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all compress jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_compress(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	if (ret) {
		printf("Before decompress, compress failed\n");
		return ret;
	}

	// Decompress
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		memset_pattern(tsk_node->tsk->src1, 0, tsk_node->tsk->xfer_size);
		memcpy(tsk_node->tsk->src1, tsk_node->tsk->dst1,
		       tsk_node->tsk->comp->iax_output_size);

		tsk_node->tsk->opcode = IAX_OPCODE_DECOMPRESS;
		tsk_node->tsk->xfer_size = tsk_node->tsk->comp->iax_output_size;

		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		tsk_node->tsk->dflags &= ~(IDXD_OP_FLAG_WR_SRC2_CMPL |
					   IDXD_OP_FLAG_RD_SRC2_AECS);
		tsk_node->tsk->iaa_src2_xfer_size = 0;
		tsk_node->tsk->src2 = 0;

		tsk_node->tsk->iaa_decompr_flags = (IDXD_DECOMPRESS_FLAG_SELECT_EOB_BFINAL |
						    IDXD_DECOMPRESS_FLAG_CHECK_EOB |
						    IDXD_DECOMPRESS_FLAG_STOP_ON_EOB |
						    IDXD_DECOMPRESS_FLAG_FLUSH_OUTPUT |
						    IDXD_DECOMPRESS_FLAG_EN_DECOMPRESS);
		tsk_node->tsk->iaa_max_dst_size = ctx->wq_max_xfer_size;

		iaa_prep_decompress(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all decompress jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_decompress(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

static int iaa_wait_scan(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("scan desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_scan_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		tsk_node->tsk->dflags |= IDXD_OP_FLAG_RD_SRC2_AECS;

		iaa_prep_scan(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all scan jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_scan(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

static int iaa_wait_set_membership(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *comp = tsk->comp;
	int rc;

	rc = acctest_wait_on_desc_timeout(comp, ctx, ms_timeout);
	if (rc < 0) {
		err("set membership desc timeout\n");
		return ACCTEST_STATUS_TIMEOUT;
	}

	return ACCTEST_STATUS_OK;
}

int iaa_set_membership_multi_task_nodes(struct acctest_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags |= (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR);
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		tsk_node->tsk->dflags |= IDXD_OP_FLAG_RD_SRC2_2ND;

		iaa_prep_set_membership(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all set membership jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		acctest_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = iaa_wait_set_membership(ctx, tsk_node->tsk);
		if (ret != ACCTEST_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

/* mismatch_expected: expect mismatched buffer with success status 0x1 */
int iaa_task_result_verify(struct task *tsk, int mismatch_expected)
{
	int ret = ACCTEST_STATUS_OK;

	info("verifying task result for %#lx\n", tsk);

	if (tsk->comp->status != IAX_COMP_SUCCESS)
		return tsk->comp->status;

	switch (tsk->opcode) {
	case IAX_OPCODE_CRC64:
		ret = task_result_verify_crc64(tsk, mismatch_expected);
		break;
	case IAX_OPCODE_ZCOMPRESS16:
		ret = task_result_verify_zcompress16(tsk, mismatch_expected);
		break;
	case IAX_OPCODE_ZDECOMPRESS16:
		ret = task_result_verify_zdecompress16(tsk, mismatch_expected);
		break;
	case IAX_OPCODE_ZCOMPRESS32:
		ret = task_result_verify_zcompress32(tsk, mismatch_expected);
		break;
	case IAX_OPCODE_ZDECOMPRESS32:
		ret = task_result_verify_zdecompress32(tsk, mismatch_expected);
		break;
	case IAX_OPCODE_COMPRESS:
		ret = task_result_verify_compress(tsk, mismatch_expected);
		break;
	case IAX_OPCODE_SCAN:
		ret = task_result_verify_scan(tsk, mismatch_expected);
		break;
	case IAX_OPCODE_SET_MEMBERSHIP:
		ret = task_result_verify_set_membership(tsk, mismatch_expected);
		break;
	}

	if (ret == ACCTEST_STATUS_OK)
		info("test with op %d passed\n", tsk->opcode);

	return ret;
}

int iaa_task_result_verify_task_nodes(struct acctest_context *ctx, int mismatch_expected)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = ACCTEST_STATUS_OK;

	while (tsk_node) {
		ret = iaa_task_result_verify(tsk_node->tsk, mismatch_expected);
		if (ret != ACCTEST_STATUS_OK) {
			err("memory result verify failed %d\n", ret);
			return ret;
		}
		tsk_node = tsk_node->next;
	}

	return ret;
}

int task_result_verify_crc64(struct task *tsk, int mismatch_expected)
{
	int rc;
	uint64_t crc;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	if (tsk->iaa_crc64_flags == IAA_CRC64_EXTRA_FLAGS_BIT_ORDER) {
		crc = iaa_calculate_crc64(tsk->iaa_crc64_poly, tsk->src1,
					  tsk->xfer_size, 1, 0);
	} else if (tsk->iaa_crc64_flags == IAA_CRC64_EXTRA_FLAGS_INVERT_CRC) {
		crc = iaa_calculate_crc64(tsk->iaa_crc64_poly, tsk->src1,
					  tsk->xfer_size, 0, 1);
	} else {
		err("Unsupported extra flags %#x\n", tsk->iaa_crc64_flags);
		return -EINVAL;
	}

	rc = memcmp((void *)(&tsk->comp->crc64_result), (void *)(&crc), sizeof(uint64_t));

	if (!mismatch_expected) {
		if (rc) {
			err("crc64 mismatch, memcmp rc %d\n", rc);
			err("expected crc=0x%llX, actual crc=0x%llX\n",
			    crc, tsk->comp->crc64_result);
			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch in crc 0x%llX\n", tsk->comp->crc64_result);
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}

int task_result_verify_zcompress16(struct task *tsk, int mismatch_expected)
{
	int i;
	int rc;
	int expected_len;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	expected_len = iaa_do_zcompress16(tsk->output, tsk->src1, tsk->xfer_size);
	rc = memcmp(tsk->dst1, tsk->output, expected_len);

	if (!mismatch_expected) {
		if (expected_len - tsk->comp->iax_output_size) {
			err("zcompress16 mismatch, exp len %d, act len %d\n",
			    expected_len, tsk->comp->iax_output_size);

			return -ENXIO;
		}
		if (rc) {
			err("zcompress16 mismatch, memcmp rc %d\n", rc);
			for (i = 0; i < (expected_len / 2); i++) {
				printf("Exp[%d]=0x%04X, Act[%d]=0x%04X\n",
				       i, ((uint16_t *)tsk->output)[i],
				       i, ((uint16_t *)tsk->dst1)[i]);
			}

			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch\n");
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}

int task_result_verify_zdecompress16(struct task *tsk, int mismatch_expected)
{
	int i;
	int rc;
	int expected_len;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	expected_len = iaa_do_zdecompress16(tsk->output, tsk->src1, tsk->xfer_size);
	rc = memcmp(tsk->dst1, tsk->output, expected_len);

	if (!mismatch_expected) {
		if (expected_len - tsk->comp->iax_output_size) {
			err("zdecompress16 mismatch, exp len %d, act len %d\n",
			    expected_len, tsk->comp->iax_output_size);

			return -ENXIO;
		}
		if (rc) {
			err("zdecompress16 mismatch, memcmp rc %d\n", rc);
			for (i = 0; i < (expected_len / 2); i++) {
				printf("Exp[%d]=0x%04X, Act[%d]=0x%04X\n",
				       i, ((uint16_t *)tsk->output)[i],
				       i, ((uint16_t *)tsk->dst1)[i]);
			}

			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch\n");
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}

int task_result_verify_zcompress32(struct task *tsk, int mismatch_expected)
{
	int i;
	int rc;
	int expected_len;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	expected_len = iaa_do_zcompress32(tsk->output, tsk->src1, tsk->xfer_size);
	rc = memcmp(tsk->dst1, tsk->output, expected_len);

	if (!mismatch_expected) {
		if (expected_len - tsk->comp->iax_output_size) {
			err("zcompress32 mismatch, exp len %d, act len %d\n",
			    expected_len, tsk->comp->iax_output_size);

			return -ENXIO;
		}
		if (rc) {
			err("zcompress32 mismatch, memcmp rc %d\n", rc);
			for (i = 0; i < (expected_len / 4); i++) {
				printf("Exp[%d]=0x%08X, Act[%d]=0x%08X\n",
				       i, ((uint32_t *)tsk->output)[i],
				       i, ((uint32_t *)tsk->dst1)[i]);
			}

			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch\n");
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}

int task_result_verify_zdecompress32(struct task *tsk, int mismatch_expected)
{
	int i;
	int rc;
	int expected_len;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	expected_len = iaa_do_zdecompress32(tsk->output, tsk->src1, tsk->xfer_size);
	rc = memcmp(tsk->dst1, tsk->output, expected_len);

	if (!mismatch_expected) {
		if (expected_len - tsk->comp->iax_output_size) {
			err("zdecompress32 mismatch, exp len %d, act len %d\n",
			    expected_len, tsk->comp->iax_output_size);

			return -ENXIO;
		}
		if (rc) {
			err("zdecompress32 mismatch, memcmp rc %d\n", rc);
			for (i = 0; i < (expected_len / 4); i++) {
				printf("Exp[%d]=0x%08X, Act[%d]=0x%08X\n",
				       i, ((uint32_t *)tsk->output)[i],
				       i, ((uint32_t *)tsk->dst1)[i]);
			}

			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch\n");
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}

int task_result_verify_compress(struct task *tsk, int mismatch_expected)
{
	int i = 0;
	int rc;
	int expected_len;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	rc = iaa_do_decompress(tsk->output, tsk->dst1, tsk->comp->iax_output_size, &expected_len);
	if (rc)
		return -ENXIO;
	rc = memcmp(tsk->src1, tsk->output, expected_len);

	if (!mismatch_expected) {
		if (expected_len - tsk->xfer_size) {
			err("Compress mismatch, exp len %d, act len %d\n",
			    expected_len, tsk->xfer_size);

			return -ENXIO;
		}
		if (rc) {
			err("Compress mismatch, memcmp rc %d\n", rc);
			for (i = 0; i < (expected_len / 4); i++) {
				printf("Exp[%d]=0x%04X, Act[%d]=0x%04X\n",
				       i, ((uint32_t *)tsk->output)[i],
				       i, ((uint32_t *)tsk->src1)[i]);
			}

			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch\n");
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}

int task_result_verify_decompress(struct task *tsk, int mismatch_expected)
{
	int i = 0;
	int rc;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	rc = memcmp(tsk->input, tsk->dst1, tsk->input_size);

	if (!mismatch_expected) {
		if (tsk->input_size - tsk->comp->iax_output_size) {
			err("Decompress mismatch, exp len %d, act len %d\n",
			    tsk->input_size, tsk->comp->iax_output_size);

			return -ENXIO;
		}
		if (rc) {
			err("Decompress mismatch, memcmp rc %d\n", rc);
			for (i = 0; i < (tsk->input_size / 4); i++) {
				printf("Exp[%d]=0x%04X, Act[%d]=0x%04X\n",
				       i, ((uint32_t *)tsk->input)[i],
				       i, ((uint32_t *)tsk->dst1)[i]);
			}

			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch\n");
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}

int task_result_verify_scan(struct task *tsk, int mismatch_expected)
{
	uint32_t i;
	int rc;
	uint32_t expected_len;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	expected_len = iaa_do_scan(tsk->output, tsk->src1, tsk->src2,
				   tsk->iaa_num_inputs, tsk->iaa_filter_flags);
	rc = memcmp(tsk->dst1, tsk->output, expected_len);

	if (!mismatch_expected) {
		if (expected_len - tsk->comp->iax_output_size) {
			err("Scan mismatch, exp len %d, act len %d\n",
			    expected_len, tsk->comp->iax_output_size);

			return -ENXIO;
		}
		if (rc) {
			err("Scan mismatch, memcmp rc %d\n", rc);
			for (i = 0; i < (expected_len / 4); i++) {
				printf("Exp[%d]=0x%08X, Act[%d]=0x%08X\n",
				       i, ((uint32_t *)tsk->output)[i],
				       i, ((uint32_t *)tsk->dst1)[i]);
			}

			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch\n");
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}

int task_result_verify_set_membership(struct task *tsk, int mismatch_expected)
{
	uint32_t i;
	int rc;
	uint32_t expected_len;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	expected_len = iaa_do_set_membership(tsk->output, tsk->src1, tsk->src2,
					     tsk->iaa_num_inputs, tsk->iaa_filter_flags);
	rc = memcmp(tsk->dst1, tsk->output, expected_len);

	if (!mismatch_expected) {
		if (expected_len - tsk->comp->iax_output_size) {
			err("set membership mismatch, exp len %d, act len %d\n",
			    expected_len, tsk->comp->iax_output_size);

			return -ENXIO;
		}
		if (rc) {
			err("set membership mismatch, memcmp rc %d\n", rc);
			for (i = 0; i < (expected_len / 4); i++) {
				printf("Exp[%d]=0x%08X, Act[%d]=0x%08X\n",
				       i, ((uint32_t *)tsk->output)[i],
				       i, ((uint32_t *)tsk->dst1)[i]);
			}

			return -ENXIO;
		}
		return ACCTEST_STATUS_OK;
	}

	/* mismatch_expected */
	if (rc) {
		info("expected mismatch\n");
		return ACCTEST_STATUS_OK;
	}

	return -ENXIO;
}
