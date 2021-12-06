// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include "dsa.h"

#define DSA_TEST_SIZE 20000
#define SHARED 1
#define DEDICATED 0

static void usage(void)
{
	printf("<app_name> [options]\n"
	"-w <wq_type> ; 0=dedicated, 1=shared\n"
	"-l <length>  ; total test buffer size\n"
	"-f <test_flags> ; 0x1: block-on-fault\n"
	"                ; 0x4: reserved\n"
	"                ; 0x8: prefault buffers\n"
	"-o <opcode>     ; opcode, same value as in DSA spec\n"
	"-b <opcode> ; if batch opcode, opcode in the batch\n"
	"-c <batch_size> ; if batch opcode, number of descriptors for batch\n"
	"-d              ; wq device such as dsa0/wq0.0\n"
	"-t <ms timeout> ; ms to wait for descs to complete\n"
	"-v              ; verbose\n"
	"-h              ; print this message\n");
}

static int test_batch(struct dsa_context *ctx, size_t buf_size,
		      int tflags, uint32_t bopcode, unsigned int bsize)
{
	unsigned long dflags;
	int rc = 0;

	info("batch: len %#lx tflags %#x bopcode %#x batch_no %d\n",
	     buf_size, tflags, bopcode, bsize);

	if (bopcode == DSA_OPCODE_BATCH) {
		err("Can't have batch op inside batch op\n");
		return -EINVAL;
	}

	ctx->is_batch = 1;

	rc = alloc_batch_task(ctx, bsize);
	if (rc != DSA_STATUS_OK)
		return rc;

	dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tflags & TEST_FLAGS_BOF) && ctx->bof)
		dflags |= IDXD_OP_FLAG_BOF;

	rc = init_batch_task(ctx->batch_task, bsize, tflags, bopcode,
			     buf_size, dflags);
	if (rc != DSA_STATUS_OK)
		return rc;

	switch (bopcode) {
	case DSA_OPCODE_NOOP:
		dsa_prep_batch_noop(ctx->batch_task);
		break;
	case DSA_OPCODE_MEMMOVE:
		dsa_prep_batch_memcpy(ctx->batch_task);
		break;

	case DSA_OPCODE_MEMFILL:
		dsa_prep_batch_memfill(ctx->batch_task);
		break;

	case DSA_OPCODE_COMPARE:
		dsa_prep_batch_compare(ctx->batch_task);
		break;

	case DSA_OPCODE_COMPVAL:
		dsa_prep_batch_compval(ctx->batch_task);
		break;
	case DSA_OPCODE_DUALCAST:
		dsa_prep_batch_dualcast(ctx->batch_task);
		break;
	default:
		err("Unsupported op %#x\n", bopcode);
		return -EINVAL;
	}

	dsa_prep_batch(ctx->batch_task, dflags);
	dump_sub_desc(ctx->batch_task);
	dsa_desc_submit(ctx, ctx->batch_task->core_task->desc);

	rc = dsa_wait_batch(ctx);
	if (rc != DSA_STATUS_OK) {
		err("batch failed stat %d\n", rc);
		rc = -ENXIO;
	}

	rc = batch_result_verify(ctx->batch_task, dflags & IDXD_OP_FLAG_BOF);

	return rc;
}

static int test_noop(struct dsa_context *ctx, int tflags)
{
	struct task *tsk;
	int rc;

	info("noop: tflags %#x\n", tflags);

	ctx->is_batch = 0;

	rc = alloc_task(ctx);
	if (rc != DSA_STATUS_OK) {
		err("noop: alloc task failed, rc=%d\n", rc);
		return rc;
	}

	tsk = ctx->single_task;

	rc = dsa_noop(ctx);
	if (rc != DSA_STATUS_OK) {
		err("noop failed stat %d\n", rc);
		return rc;
	}

	rc = task_result_verify(tsk, 0);
	if (rc != DSA_STATUS_OK)
		return rc;

	return rc;
}

static int test_memory(struct dsa_context *ctx, size_t buf_size,
		       int tflags, uint32_t opcode)
{
	struct task *tsk;
	int rc;

	info("mem: len %#lx tflags %#x opcode %d\n", buf_size, tflags, opcode);

	ctx->is_batch = 0;

	rc = alloc_task(ctx);
	if (rc != DSA_STATUS_OK) {
		err("mem: alloc task failed opcode %d, rc=%d\n", opcode, rc);
		return rc;
	}

	tsk = ctx->single_task;
	rc = init_task(tsk, tflags, opcode, buf_size);
	if (rc != DSA_STATUS_OK) {
		err("mem: init task failed opcode %d, rc=%d\n", opcode, rc);
		return rc;
	}

	switch (opcode) {
	case DSA_OPCODE_MEMMOVE:
		rc = dsa_memcpy(ctx);
		if (rc != DSA_STATUS_OK)
			return rc;

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			return rc;
		break;

	case DSA_OPCODE_MEMFILL:
		rc = dsa_memfill(ctx);
		if (rc != DSA_STATUS_OK)
			return rc;

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			return rc;
		break;

	case DSA_OPCODE_COMPARE:
		rc = dsa_compare(ctx);
		if (rc != DSA_STATUS_OK)
			return rc;

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			return rc;

		info("Testing mismatch buffers\n");
		info("creating a diff at index %#lx\n", tsk->xfer_size / 2);
		((uint8_t *)(tsk->src1))[tsk->xfer_size / 2] = 0;
		((uint8_t *)(tsk->src2))[tsk->xfer_size / 2] = 1;

		memset(tsk->comp, 0, sizeof(struct dsa_completion_record));

		rc = dsa_compare(ctx);
		if (rc != DSA_STATUS_OK)
			return rc;

		rc = task_result_verify(tsk, 1);
		if (rc != DSA_STATUS_OK)
			return rc;
		break;

	case DSA_OPCODE_COMPVAL:
		rc = dsa_compval(ctx);
		if (rc != DSA_STATUS_OK)
			return rc;

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			return rc;

		info("Testing mismatching buffers\n");
		info("creating a diff at index %#lx\n", tsk->xfer_size / 2);
		((uint8_t *)(tsk->src1))[tsk->xfer_size / 2] =
				~(((uint8_t *)(tsk->src1))[tsk->xfer_size / 2]);

		memset(tsk->comp, 0, sizeof(struct dsa_completion_record));

		rc = dsa_compval(ctx);
		if (rc != DSA_STATUS_OK)
			return rc;

		rc = task_result_verify(tsk, 1);
		if (rc != DSA_STATUS_OK)
			return rc;
		break;

	case DSA_OPCODE_DUALCAST:
		rc = dsa_dualcast(ctx);
		if (rc != DSA_STATUS_OK)
			return rc;

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			return rc;
		break;

	default:
		err("Unsupported opcode %#x\n", opcode);
		return -EINVAL;
	}

	return rc;
}

int main(int argc, char *argv[])
{
	struct dsa_context *dsa;
	int rc = 0;
	unsigned long buf_size = DSA_TEST_SIZE;
	int wq_type = SHARED;
	int opcode = DSA_OPCODE_MEMMOVE;
	int bopcode = DSA_OPCODE_MEMMOVE;
	int tflags = TEST_FLAGS_BOF;
	int opt;
	unsigned int bsize = 0;
	char dev_type[MAX_DEV_LEN];
	int wq_id = DSA_DEVICE_ID_NO_INPUT;
	int dev_id = DSA_DEVICE_ID_NO_INPUT;
	int dev_wq_id = DSA_DEVICE_ID_NO_INPUT;

	while ((opt = getopt(argc, argv, "w:l:f:o:b:c:d:t:p:vh")) != -1) {
		switch (opt) {
		case 'w':
			wq_type = atoi(optarg);
			break;
		case 'l':
			buf_size = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			tflags = strtoul(optarg, NULL, 0);
			break;
		case 'o':
			opcode = strtoul(optarg, NULL, 0);
			break;
		case 'b':
			bopcode = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			bsize = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			if (sscanf(optarg, "%[a-z]%u/%*[a-z]%u.%u", dev_type,
				   &dev_id, &dev_wq_id, &wq_id) != 4) {
				err("invalid input device:dev_wq_id:%d ,wq_id:%d\n",
				    dev_wq_id, wq_id);
				return -EINVAL;
			}
			break;
		case 't':
			ms_timeout = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			debug_logging = 1;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			break;
		}
	}

	dsa = dsa_init();

	if (!dsa)
		return -ENOMEM;

	rc = dsa_alloc(dsa, wq_type, dev_id, wq_id);
	if (rc < 0)
		return -ENOMEM;

	if (buf_size > dsa->max_xfer_size) {
		err("invalid transfer size: %lu\n", buf_size);
		return -EINVAL;
	}

	switch (opcode) {
	case DSA_OPCODE_NOOP:
		rc = test_noop(dsa, tflags);
		if (rc != DSA_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_BATCH:
		if (bsize > dsa->max_batch_size || bsize < 2) {
			err("invalid num descs: %d\n", bsize);
			rc = -EINVAL;
			goto error;
		}
		rc = test_batch(dsa, buf_size, tflags, bopcode, bsize);
		if (rc < 0)
			goto error;
		break;

	case DSA_OPCODE_MEMMOVE:
	case DSA_OPCODE_MEMFILL:
	case DSA_OPCODE_COMPARE:
	case DSA_OPCODE_COMPVAL:
	case DSA_OPCODE_DUALCAST:
		rc = test_memory(dsa, buf_size, tflags, opcode);
		if (rc != DSA_STATUS_OK)
			goto error;
		break;

	default:
		rc = -EINVAL;
		break;
	}

 error:
	dsa_free(dsa);
	return rc;
}
