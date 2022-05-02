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

/* mismatch_expected: expect mismatched buffer with success status 0x1 */
int iaa_task_result_verify(struct task *tsk, int mismatch_expected)
{
	info("verifying task result for %#lx\n", tsk);

	if (tsk->comp->status != IAX_COMP_SUCCESS)
		return tsk->comp->status;

	info("test with op %d passed\n", tsk->opcode);

	return ACCTEST_STATUS_OK;
}
