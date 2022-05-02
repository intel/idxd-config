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

static int init_crc64(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size)
{
	tsk->pattern = 0x98765432abcdef01;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = src1_xfer_size;

	tsk->src1 = malloc(src1_xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, src1_xfer_size);
	tsk->iaa_crc64_poly = IAA_CRC64_POLYNOMIAL;

	return ACCTEST_STATUS_OK;
}

/* this function is re-used by batch task */
int init_task(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size)
{
	int rc = 0;

	dbg("initilizing single task %#lx\n", tsk);

	/* allocate memory: src1*/
	switch (opcode) {
	case IAX_OPCODE_CRC64: /* intentionally empty */
		rc = init_crc64(tsk, tflags, opcode, src1_xfer_size);
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
