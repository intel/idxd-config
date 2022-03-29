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
	"-n <number of descriptors> ;descriptor count to submit\n"
	"-t <ms timeout> ; ms to wait for descs to complete\n"
	"-v              ; verbose\n"
	"-h              ; print this message\n");
}

static int test_batch(struct dsa_context *ctx, size_t buf_size,
		      int tflags, uint32_t bopcode, unsigned int bsize, int num_desc)
{
	struct btask_node *btsk_node;
	unsigned long dflags;
	int rc = DSA_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("batch: len %#lx tflags %#x bopcode %#x batch_no %d num_desc %ld\n",
	     buf_size, tflags, bopcode, bsize, num_desc);

	if (bopcode == DSA_OPCODE_BATCH) {
		err("Can't have batch op inside batch op\n");
		return -EINVAL;
	}

	ctx->is_batch = 1;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == DSA_STATUS_OK) {
		i = (itr < range) ? itr : range;
		rc = alloc_batch_task(ctx, bsize, i);
		if (rc != DSA_STATUS_OK)
			return rc;

		dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tflags & TEST_FLAGS_BOF) && ctx->bof)
			dflags |= IDXD_OP_FLAG_BOF;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		btsk_node = ctx->multi_btask_node;
		while (btsk_node) {
			rc = init_batch_task(btsk_node->btsk, bsize, tflags, bopcode,
					     buf_size, dflags);
			if (rc != DSA_STATUS_OK)
				return rc;

			switch (bopcode) {
			case DSA_OPCODE_NOOP:
				dsa_prep_batch_noop(btsk_node->btsk);
				break;

			case DSA_OPCODE_MEMMOVE:
				dsa_prep_batch_memcpy(btsk_node->btsk);
				break;

			case DSA_OPCODE_MEMFILL:
				dsa_prep_batch_memfill(btsk_node->btsk);
				break;

			case DSA_OPCODE_COMPARE:
				dsa_prep_batch_compare(btsk_node->btsk);
				break;
			case DSA_OPCODE_COMPVAL:
				dsa_prep_batch_compval(btsk_node->btsk);
				break;

			case DSA_OPCODE_DUALCAST:
				dsa_prep_batch_dualcast(btsk_node->btsk);
				break;

			case DSA_OPCODE_CR_DELTA:
				dsa_prep_batch_cr_delta(btsk_node->btsk);
				break;

			case DSA_OPCODE_AP_DELTA:
				dsa_prep_batch_cr_delta(btsk_node->btsk);
				break;

			case DSA_OPCODE_CRCGEN:
				dsa_prep_batch_crcgen(btsk_node->btsk);
				break;

			case DSA_OPCODE_COPY_CRC:
				dsa_prep_batch_crc_copy(btsk_node->btsk);
				break;

			case DSA_OPCODE_DIF_CHECK:
				dsa_prep_batch_dif_check(btsk_node->btsk);
				break;

			case DSA_OPCODE_DIF_INS:
				dsa_prep_batch_dif_insert(btsk_node->btsk);
				break;

			case DSA_OPCODE_DIF_STRP:
				dsa_prep_batch_dif_strip(btsk_node->btsk);
				break;

			case DSA_OPCODE_DIF_UPDT:
				dsa_prep_batch_dif_update(btsk_node->btsk);
				break;

			case DSA_OPCODE_CFLUSH:
				dsa_prep_batch_cflush(btsk_node->btsk);
				break;

			default:
				err("Unsupported op %#x\n", bopcode);
				return -EINVAL;
			}

			btsk_node = btsk_node->next;
		}

		btsk_node = ctx->multi_btask_node;
		while (btsk_node) {
			dsa_prep_batch(btsk_node->btsk, dflags);
			dump_sub_desc(btsk_node->btsk);
			btsk_node = btsk_node->next;
		}

		btsk_node = ctx->multi_btask_node;
		while (btsk_node) {
			dsa_desc_submit(ctx, btsk_node->btsk->core_task->desc);
			btsk_node = btsk_node->next;
		}

		btsk_node = ctx->multi_btask_node;
		while (btsk_node) {
			rc = dsa_wait_batch(btsk_node->btsk);
			if (rc != DSA_STATUS_OK) {
				err("batch failed stat %d\n", rc);
				return rc;
			}
			btsk_node = btsk_node->next;
		}

		/* ap delta test. First run cr delta, then run ap delta */
		if (bopcode == DSA_OPCODE_AP_DELTA) {
			btsk_node = ctx->multi_btask_node;
			while (btsk_node) {
				dsa_prep_batch_ap_delta(btsk_node->btsk);
				btsk_node = btsk_node->next;
			}

			btsk_node = ctx->multi_btask_node;
			while (btsk_node) {
				dsa_prep_batch(btsk_node->btsk, dflags);
				dump_sub_desc(btsk_node->btsk);
				btsk_node = btsk_node->next;
			}

			btsk_node = ctx->multi_btask_node;
			while (btsk_node) {
				dsa_desc_submit(ctx, btsk_node->btsk->core_task->desc);
				btsk_node = btsk_node->next;
			}

			btsk_node = ctx->multi_btask_node;
			while (btsk_node) {
				rc = dsa_wait_batch(btsk_node->btsk);
				if (rc != DSA_STATUS_OK) {
					err("batch failed stat %d\n", rc);
					return rc;
				}
				btsk_node = btsk_node->next;
			}
		}

		btsk_node = ctx->multi_btask_node;
		while (btsk_node) {
			rc = batch_result_verify(btsk_node->btsk, dflags & IDXD_OP_FLAG_BOF);
			if (rc != DSA_STATUS_OK) {
				err("batch verification failed stat %d\n", rc);
				return rc;
			}
			btsk_node = btsk_node->next;
		}

		dsa_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_dif(struct dsa_context *ctx, size_t buf_size,
		    int tflags, uint32_t opcode, int num_desc)
{
	struct task_node *tsk_node;
	int rc = DSA_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testmemory: opcode %d len %#lx tflags %#x num_desc %ld\n",
	     opcode, buf_size, tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == DSA_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = alloc_multiple_tasks(ctx, i);
		if (rc != DSA_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->xfer_size = buf_size;
			tsk_node->tsk->blk_idx_flg = get_dif_blksz_flg(tsk_node->tsk->xfer_size);

			rc = init_task(tsk_node->tsk, tflags, opcode, buf_size);
			if (rc != DSA_STATUS_OK)
				return rc;

			tsk_node = tsk_node->next;
		}

		switch (opcode) {
		case DSA_OPCODE_DIF_CHECK:
			rc = dsa_dif_check_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_DIF_INS:
			rc = dsa_dif_ins_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_DIF_STRP:
			rc = dsa_dif_strp_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_DIF_UPDT:
			rc = dsa_dif_updt_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		default:
			err("Unsupported op %#x\n", opcode);
			return -EINVAL;
		}

		/* Verification of all the nodes*/
		rc = task_result_verify_task_nodes(ctx, 0);
		if (rc != DSA_STATUS_OK)
			return rc;

		dsa_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_noop(struct dsa_context *ctx, int tflags, int num_desc)
{
	struct task_node *tsk_node;
	int rc = DSA_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testnoop: tflags %#x num_desc %ld\n", tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == DSA_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = alloc_multiple_tasks(ctx, i);
		if (rc != DSA_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->opcode = DSA_OPCODE_NOOP;
			tsk_node->tsk->test_flags = tflags;
			tsk_node = tsk_node->next;
		}

		rc = dsa_noop_multi_task_nodes(ctx);
		if (rc != DSA_STATUS_OK)
			return rc;

		/* Verification of all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			rc = task_result_verify(tsk_node->tsk, 0);
			tsk_node = tsk_node->next;
		}

		dsa_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_memory(struct dsa_context *ctx, size_t buf_size,
		       int tflags, uint32_t opcode, int num_desc)
{
	struct task_node *tsk_node;
	int rc = DSA_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testmemory: opcode %d len %#lx tflags %#x num_desc %ld\n",
	     opcode, buf_size, tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == DSA_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = alloc_multiple_tasks(ctx, i);
		if (rc != DSA_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->xfer_size = buf_size;

			rc = init_task(tsk_node->tsk, tflags, opcode, buf_size);
			if (rc != DSA_STATUS_OK)
				return rc;

			tsk_node = tsk_node->next;
		}

		switch (opcode) {
		case DSA_OPCODE_DRAIN:
			rc = dsa_memcpy_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			rc = dsa_drain_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_MEMMOVE:
			rc = dsa_memcpy_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_MEMFILL:
			rc = dsa_memfill_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_COMPARE:
			rc = dsa_compare_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != DSA_STATUS_OK)
				return rc;

			info("Testing mismatch buffers\n");
			tsk_node = ctx->multi_task_node;
			while (tsk_node) {
				((uint8_t *)(tsk_node->tsk->src1))[tsk_node->tsk->xfer_size / 2] =
					0;
				((uint8_t *)(tsk_node->tsk->src2))[tsk_node->tsk->xfer_size / 2] =
					1;
				memset(tsk_node->tsk->comp, 0,
				       sizeof(struct dsa_completion_record));
				tsk_node = tsk_node->next;
			}

			rc = dsa_compare_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 1);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_COMPVAL:
			rc = dsa_compval_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != DSA_STATUS_OK)
				return rc;

			info("Testing mismatching buffers\n");
			tsk_node = ctx->multi_task_node;
			while (tsk_node) {
				((uint8_t *)(tsk_node->tsk->src1))[tsk_node->tsk->xfer_size / 2] =
				~(((uint8_t *)(tsk_node->tsk->src1))[tsk_node->tsk->xfer_size / 2]);
				memset(tsk_node->tsk->comp, 0,
				       sizeof(struct dsa_completion_record));
				tsk_node = tsk_node->next;
			}

			rc = dsa_compval_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 1);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;
		case DSA_OPCODE_DUALCAST:
			rc = dsa_dualcast_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;
		case DSA_OPCODE_CFLUSH:
			rc = dsa_cflush_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;
		default:
			err("Unsupported op %#x\n", opcode);
			return -EINVAL;
		}

		dsa_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_delta(struct dsa_context *ctx, size_t buf_size,
		      int tflags, uint32_t opcode, int num_desc)
{
	struct task_node *tsk_node;
	int rc = DSA_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testmemory: opcode %d len %#lx tflags %#x num_desc %ld\n",
	     opcode, buf_size, tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == DSA_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = alloc_multiple_tasks(ctx, i);
		if (rc != DSA_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->xfer_size = buf_size;

			rc = init_task(tsk_node->tsk, tflags, opcode, buf_size);
			if (rc != DSA_STATUS_OK)
				return rc;

			tsk_node = tsk_node->next;
		}

		switch (opcode) {
		case DSA_OPCODE_CR_DELTA:
			rc = dsa_cr_delta_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_AP_DELTA:
			rc = dsa_cr_delta_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;

			rc = dsa_ap_delta_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		default:
			err("Unsupported op %#x\n", opcode);
			return -EINVAL;
		}

		/* Verification of all the nodes*/
		rc = task_result_verify_task_nodes(ctx, 0);
		if (rc != DSA_STATUS_OK)
			return rc;

		dsa_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_crc(struct dsa_context *ctx, size_t buf_size,
		    int tflags, uint32_t opcode, int num_desc)
{
	struct task_node *tsk_node;
	int rc = DSA_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testmemory: opcode %d len %#lx tflags %#x num_desc %ld\n",
	     opcode, buf_size, tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == DSA_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = alloc_multiple_tasks(ctx, i);
		if (rc != DSA_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->xfer_size = buf_size;

			rc = init_task(tsk_node->tsk, tflags, opcode, buf_size);
			if (rc != DSA_STATUS_OK)
				return rc;

			tsk_node = tsk_node->next;
		}

		switch (opcode) {
		case DSA_OPCODE_CRCGEN:
			rc = dsa_crcgen_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_COPY_CRC:
			rc = dsa_crc_copy_multi_task_nodes(ctx);
			if (rc != DSA_STATUS_OK)
				return rc;
			break;

		default:
			err("Unsupported op %#x\n", opcode);
			return -EINVAL;
		}

		/* Verification of all the nodes*/
		rc = task_result_verify_task_nodes(ctx, 0);
		if (rc != DSA_STATUS_OK)
			return rc;

		dsa_free_task(ctx);
		itr = itr - range;
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
	unsigned int num_desc = 1;

	while ((opt = getopt(argc, argv, "w:l:f:o:b:c:d:n:t:p:vh")) != -1) {
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
		case 'n':
			num_desc = strtoul(optarg, NULL, 0);
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
		rc = test_noop(dsa, tflags, num_desc);
		if (rc != DSA_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_BATCH:
		if (bsize > dsa->max_batch_size || bsize < 2) {
			err("invalid num descs: %d\n", bsize);
			rc = -EINVAL;
			goto error;
		}
		rc = test_batch(dsa, buf_size, tflags, bopcode, bsize, num_desc);
		if (rc < 0)
			goto error;
		break;

	case DSA_OPCODE_DRAIN:
	case DSA_OPCODE_MEMMOVE:
	case DSA_OPCODE_MEMFILL:
	case DSA_OPCODE_COMPARE:
	case DSA_OPCODE_COMPVAL:
	case DSA_OPCODE_DUALCAST:
	case DSA_OPCODE_CFLUSH:
		rc = test_memory(dsa, buf_size, tflags, opcode, num_desc);
		if (rc != DSA_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_CR_DELTA:
	case DSA_OPCODE_AP_DELTA:
		rc = test_delta(dsa, buf_size, tflags, opcode, num_desc);
		if (rc != DSA_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_CRCGEN:
	case DSA_OPCODE_COPY_CRC:
		rc = test_crc(dsa, buf_size, tflags, opcode, num_desc);
		if (rc != DSA_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_DIF_CHECK:
	case DSA_OPCODE_DIF_INS:
	case DSA_OPCODE_DIF_STRP:
	case DSA_OPCODE_DIF_UPDT:
		rc = test_dif(dsa, buf_size, tflags, opcode, num_desc);
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
