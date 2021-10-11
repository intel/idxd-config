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

	while ((opt = getopt(argc, argv, "w:l:f:o:b:c:t:p:vh")) != -1) {
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

	if (dsa == NULL)
		return -ENOMEM;

	rc = dsa_alloc(dsa, wq_type);
	if (rc < 0)
		return -ENOMEM;

	if (buf_size > dsa->max_xfer_size) {
		err("invalid transfer size: %lu\n", buf_size);
		return -EINVAL;
	}

	switch (opcode) {
	case DSA_OPCODE_NOOP: {
		struct task *tsk;

		info("noop: len %#lx tflags %#x\n", buf_size, tflags);

		rc = alloc_task(dsa);
		if (rc != DSA_STATUS_OK) {
			err("noop: alloc task failed, rc=%d\n", rc);
			goto error;
		}

		tsk = dsa->single_task;

		rc = dsa_noop(dsa);
		if (rc != DSA_STATUS_OK) {
			err("noop failed stat %d\n", rc);
			rc = -ENXIO;
			break;
		}

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			goto error;

		break;
	}

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

	case DSA_OPCODE_MEMMOVE: {
		struct task *tsk;

		info("memcpy: len %#lx tflags %#x\n", buf_size, tflags);

		rc = alloc_task(dsa);
		if (rc != DSA_STATUS_OK) {
			err("memcpy: alloc task failed, rc=%d\n", rc);
			goto error;
		}

		tsk = dsa->single_task;
		rc = init_task(tsk, tflags, opcode, buf_size);
		if (rc != DSA_STATUS_OK) {
			err("memcpy: init task failed\n");
			goto error;
		}

		rc = dsa_memcpy(dsa);
		if (rc != DSA_STATUS_OK) {
			err("memcpy failed stat %d\n", rc);
			rc = -ENXIO;
			break;
		}

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			goto error;

		break;
	}

	case DSA_OPCODE_MEMFILL: {
		struct task *tsk;

		info("memfill: len %#lx tflags %#x\n", buf_size, tflags);

		rc = alloc_task(dsa);
		if (rc != DSA_STATUS_OK) {
			err("memfill: alloc task failed, rc=%d\n", rc);
			goto error;
		}

		tsk = dsa->single_task;
		rc = init_task(tsk, tflags, opcode, buf_size);
		if (rc != DSA_STATUS_OK) {
			err("memfill: init task failed\n");
			goto error;
		}

		rc = dsa_memfill(dsa);
		if (rc != DSA_STATUS_OK) {
			err("memfill failed stat %d\n", rc);
			rc = -ENXIO;
			goto error;
		}

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			goto error;

		break;
	}

	case DSA_OPCODE_COMPARE: {
		struct task *tsk;

		info("compare: matching buffers len %#lx tflags %#x\n",
				buf_size, tflags);

		rc = alloc_task(dsa);
		if (rc != DSA_STATUS_OK) {
			err("compare: alloc task failed, rc=%d\n", rc);
			goto error;
		}

		tsk = dsa->single_task;
		rc = init_task(tsk, tflags, opcode, buf_size);
		if (rc != DSA_STATUS_OK) {
			err("compare: init task failed\n");
			goto error;
		}

		rc = dsa_compare(dsa);
		if (rc != DSA_STATUS_OK) {
			err("compare1 failed stat %d\n", rc);
			rc = -ENXIO;
			goto error;
		}

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			goto error;

		info("Testing mismatch buffers\n");
		info("creating a diff at index %#lx\n", tsk->xfer_size/2);
		((uint8_t *)(tsk->src1))[tsk->xfer_size/2] = 0;
		((uint8_t *)(tsk->src2))[tsk->xfer_size/2] = 1;

		memset(tsk->comp, 0, sizeof(struct dsa_completion_record));

		rc = dsa_compare(dsa);
		if (rc != DSA_STATUS_OK) {
			err("compare2 failed stat %d\n", rc);
			rc = -ENXIO;
			goto error;
		}

		rc = task_result_verify(tsk, 1);
		if (rc != DSA_STATUS_OK)
			goto error;

		break;
	}

	case DSA_OPCODE_COMPVAL: {
		struct task *tsk;

		info("compval: matching buffer len %#lx tflags %#x\n",
				buf_size, tflags);

		rc = alloc_task(dsa);
		if (rc != DSA_STATUS_OK) {
			err("compval: alloc task failed, rc=%d\n", rc);
			goto error;
		}

		tsk = dsa->single_task;
		rc = init_task(tsk, tflags, opcode, buf_size);
		if (rc != DSA_STATUS_OK) {
			err("compval: init task failed\n");
			goto error;
		}

		rc = dsa_compval(dsa);
		if (rc != DSA_STATUS_OK) {
			err("compval1 failed stat %d\n", rc);
			rc = -ENXIO;
			goto error;
		}

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			goto error;

		info("Testing mismatching buffers\n");
		info("creating a diff at index %#lx\n", tsk->xfer_size/2);
		((uint8_t *)(tsk->src1))[tsk->xfer_size/2] =
				~(((uint8_t *)(tsk->src1))[tsk->xfer_size/2]);

		memset(tsk->comp, 0, sizeof(struct dsa_completion_record));

		rc = dsa_compval(dsa);
		if (rc != DSA_STATUS_OK) {
			err("compval2 failed stat %d\n", rc);
			rc = -ENXIO;
			goto error;
		}

		rc = task_result_verify(tsk, 1);
		if (rc != DSA_STATUS_OK)
			goto error;

		break;
	}

	case DSA_OPCODE_DUALCAST: {
		struct task *tsk;

		info("dualcast: len %#lx tflags %#x\n", buf_size, tflags);

		rc = alloc_task(dsa);
		if (rc != DSA_STATUS_OK) {
			err("dualcast: alloc task failed, rc=%d\n", rc);
			goto error;
		}

		tsk = dsa->single_task;
		rc = init_task(tsk, tflags, opcode, buf_size);
		if (rc != DSA_STATUS_OK) {
			err("dualcast: init task failed\n");
			goto error;
		}

		rc = dsa_dualcast(dsa);
		if (rc != DSA_STATUS_OK) {
			err("dualcast failed stat %d\n", rc);
			rc = -ENXIO;
			goto error;
		}

		rc = task_result_verify(tsk, 0);
		if (rc != DSA_STATUS_OK)
			goto error;

		break;
	}

	default:
		rc = -EINVAL;
		break;
	}

 error:
	dsa_free(dsa);
	return rc;
}
