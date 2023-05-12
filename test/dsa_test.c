// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include "accel_test.h"
#include "dsa.h"

#define DSA_TEST_SIZE 20000
#pragma GCC diagnostic ignored "-Wformat"

static void usage(void)
{
	printf("<app_name> [options]\n"
	"-w <wq_type> ; 0=dedicated, 1=shared\n"
	"-l <length>  ; total test buffer size\n"
	"-f <test_flags> ; 0x1: block-on-fault\n"
	"		 ; 0x2: no umwait\n"
	"                ; 0x4: reserved\n"
	"                ; 0x8: prefault buffers\n"
	"                ; 0x10: fault on completion record\n"
	"                ; 0x20: fault on batch record\n"
	"-o <opcode>     ; opcode, same value as in DSA spec\n"
	"-b <opcode> ; if batch opcode, opcode in the batch\n"
	"-c <batch_size> ; if batch opcode, number of descriptors for batch\n"
	"-d              ; wq device such as dsa0/wq0.0\n"
	"-n <number of descriptors> ;descriptor count to submit\n"
	"-t <ms timeout> ; ms to wait for descs to complete\n"
	"-e              ; evl pattern <batch>:<desc><..>\n"
	"                ; <bc_fault:bc_wr_fail:bd_fault:bd_fault_idx>:<desc_fault:cp_fault:cp_wr_fail:fence>:\n"
	"-v              ; verbose\n"
	"-h              ; print this message\n");
}

static int test_batch(struct acctest_context *ctx, struct evl_desc_list *edl, size_t buf_size,
		      int tflags, uint32_t bopcode, unsigned int bsize, int num_desc)
{
	struct btask_node *btsk_node;
	unsigned long dflags;
	int rc = ACCTEST_STATUS_OK;
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

	while (itr > 0 && rc == ACCTEST_STATUS_OK) {
		i = (itr < range) ? itr : range;
		rc = alloc_batch_task(ctx, bsize, i);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tflags & TEST_FLAGS_BOF) && ctx->bof)
			dflags |= IDXD_OP_FLAG_BOF;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		btsk_node = ctx->multi_btask_node;
		while (btsk_node) {
			if (edl) {
				struct batch_task *btsk = btsk_node->btsk;
				struct batch_desc_info *bdi = &edl->bdi;
				struct hw_desc *descs;

				/*
				 * adjust sub_descs so &btsk->sub_descs[bdi->da_fault_idx]
				 * is aligned to a page boundary
				 */
				if (bdi->da_fault) {
					descs = (struct hw_desc *)((char *)btsk->sub_descs +
						 PAGE_SIZE);
					btsk->sub_descs = descs - bdi->da_fault_idx;
				}
				btsk->edl = edl;
			}
			rc = init_batch_task(btsk_node->btsk, bsize, tflags, bopcode,
					     buf_size, dflags);
			if (rc != ACCTEST_STATUS_OK)
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

			case DSA_OPCODE_TRANSL_FETCH:
				dsa_prep_batch_transl_fetch(btsk_node->btsk);
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
			case DSA_OPCODE_DIX_GEN:
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
			if (tflags & TEST_FLAGS_BTFLT) {
				madvise(btsk_node->btsk->sub_descs,
					PAGE_ALIGN(64 * btsk_node->btsk->task_num),
					MADV_DONTNEED);
				mprotect(btsk_node->btsk->sub_descs,
					 PAGE_ALIGN(64 * btsk_node->btsk->task_num), PROT_NONE);
			}

			if (tflags & TEST_FLAGS_CPFLT)
				madvise(btsk_node->btsk->sub_comps,
					PAGE_SIZE * btsk_node->btsk->task_num,
					MADV_DONTNEED);

			if (edl) {
				struct batch_task *btsk = btsk_node->btsk;
				struct batch_desc_info *bdi = &edl->bdi;

				for (i = 0; i < (int)bsize; i++) {
					struct desc_info *di = &edl->di[i];

					if (di->desc_fault) {
						madvise(btsk->sub_tasks[i].src1,
							PAGE_SIZE, MADV_DONTNEED);
						mprotect(btsk->sub_tasks[i].src1,
							 PAGE_SIZE, PROT_NONE);
					}
					if (di->cp_fault)
						madvise(btsk->sub_tasks[i].comp,
							PAGE_SIZE, MADV_DONTNEED);
					if (di->cp_wr_fail) {
						madvise(btsk->sub_tasks[i].comp,
							PAGE_SIZE, MADV_DONTNEED);
						mprotect(btsk->sub_tasks[i].comp,
							 PAGE_SIZE, PROT_NONE);
					}
					if (di->fence)
						btsk->sub_descs[i].flags |= IDXD_OP_FLAG_FENCE;
				}

				if (bdi->bc_fault) {
					madvise(btsk->core_task->comp, PAGE_SIZE, MADV_DONTNEED);
					if (bdi->bc_wr_fail) {
						madvise(btsk->core_task->comp,
							PAGE_SIZE, MADV_DONTNEED);
						mprotect(btsk->core_task->comp,
							 PAGE_SIZE, PROT_NONE);
					}
				}

				if (bdi->da_fault) {
					madvise(&btsk->sub_descs[bdi->da_fault_idx],
						PAGE_SIZE, MADV_DONTNEED);
					mprotect(&btsk->sub_descs[bdi->da_fault_idx],
						 PAGE_SIZE, PROT_NONE);
				}
			}

			acctest_desc_submit(ctx, btsk_node->btsk->core_task->desc);
			btsk_node = btsk_node->next;
		}

		btsk_node = ctx->multi_btask_node;
		while (btsk_node) {
			if (edl && btsk_node->btsk->edl->bdi.bc_wr_fail) {
				info("batch completion unmapped not checking completions, done\n");
				return 0;
			}

			rc = dsa_wait_batch(btsk_node->btsk, ctx);
			if (rc != ACCTEST_STATUS_OK) {
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
				acctest_desc_submit(ctx, btsk_node->btsk->core_task->desc);
				btsk_node = btsk_node->next;
			}

			btsk_node = ctx->multi_btask_node;
			while (btsk_node) {
				rc = dsa_wait_batch(btsk_node->btsk, ctx);
				if (rc != ACCTEST_STATUS_OK) {
					err("batch failed stat %d\n", rc);
					return rc;
				}
				btsk_node = btsk_node->next;
			}
		}

		btsk_node = ctx->multi_btask_node;
		while (btsk_node) {
			rc = batch_result_verify(btsk_node->btsk, dflags & IDXD_OP_FLAG_BOF,
						 tflags & TEST_FLAGS_CPFLT);
			if (rc != ACCTEST_STATUS_OK) {
				err("batch verification failed stat %d\n", rc);
				return rc;
			}

			if (edl) {
				struct batch_task *btsk = btsk_node->btsk;
				struct batch_desc_info *bdi = &edl->bdi;
				struct hw_desc *descs;

				if (bdi->da_fault) {
					descs = &btsk->sub_descs[bdi->da_fault_idx];
					btsk->sub_descs = (struct hw_desc *)((char *)descs
							   - PAGE_SIZE);
				}
			}

			btsk_node = btsk_node->next;
		}

		acctest_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_dif(struct acctest_context *ctx, size_t buf_size,
		    int tflags, uint32_t opcode, int num_desc)
{
	struct task_node *tsk_node;
	int rc = ACCTEST_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testmemory: opcode %d len %#lx tflags %#x num_desc %ld\n",
	     opcode, buf_size, tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == ACCTEST_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = acctest_alloc_multiple_tasks(ctx, i);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->xfer_size = buf_size;
			tsk_node->tsk->blk_idx_flg = get_dif_blksz_flg(tsk_node->tsk->xfer_size);

			rc = init_task(tsk_node->tsk, tflags, opcode, buf_size);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			tsk_node = tsk_node->next;
		}

		switch (opcode) {
		case DSA_OPCODE_DIF_CHECK:
			rc = dsa_dif_check_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_DIF_INS:
		case DSA_OPCODE_DIX_GEN:
			rc = dsa_dif_ins_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_DIF_STRP:
			rc = dsa_dif_strp_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_DIF_UPDT:
			rc = dsa_dif_updt_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		default:
			err("Unsupported op %#x\n", opcode);
			return -EINVAL;
		}

		/* Verification of all the nodes*/
		rc = task_result_verify_task_nodes(ctx, 0);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		acctest_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_noop(struct acctest_context *ctx, int tflags, int num_desc)
{
	struct task_node *tsk_node;
	int rc = ACCTEST_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testnoop: tflags %#x num_desc %ld\n", tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == ACCTEST_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = acctest_alloc_multiple_tasks(ctx, i);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->opcode = DSA_OPCODE_NOOP;
			tsk_node->tsk->test_flags = tflags;
			tsk_node = tsk_node->next;
		}

		rc = dsa_noop_multi_task_nodes(ctx);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		/* Verification of all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			rc = task_result_verify(tsk_node->tsk, 0);
			tsk_node = tsk_node->next;
		}

		acctest_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_memory(struct acctest_context *ctx, size_t buf_size,
		       int tflags, uint32_t opcode, int num_desc)
{
	struct task_node *tsk_node;
	int rc = ACCTEST_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testmemory: opcode %d len %#lx tflags %#x num_desc %ld\n",
	     opcode, buf_size, tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == ACCTEST_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = acctest_alloc_multiple_tasks(ctx, i);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->xfer_size = buf_size;

			rc = init_task(tsk_node->tsk, tflags, opcode, buf_size);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			tsk_node = tsk_node->next;
		}

		switch (opcode) {
		case DSA_OPCODE_DRAIN:
			rc = dsa_memcpy_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			rc = dsa_drain_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_MEMMOVE:
			rc = dsa_memcpy_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_MEMFILL:
			rc = dsa_memfill_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_COMPARE:
			rc = dsa_compare_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			info("Testing mismatch buffers\n");
			tsk_node = ctx->multi_task_node;
			while (tsk_node) {
				((uint8_t *)(tsk_node->tsk->src1))[tsk_node->tsk->xfer_size / 2] =
					0;
				((uint8_t *)(tsk_node->tsk->src2))[tsk_node->tsk->xfer_size / 2] =
					1;
				memset(tsk_node->tsk->comp, 0,
				       sizeof(struct completion_record));
				tsk_node = tsk_node->next;
			}

			rc = dsa_compare_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 1);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_COMPVAL:
			rc = dsa_compval_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			info("Testing mismatching buffers\n");
			tsk_node = ctx->multi_task_node;
			while (tsk_node) {
				((uint8_t *)(tsk_node->tsk->src1))[tsk_node->tsk->xfer_size / 2] =
				~(((uint8_t *)(tsk_node->tsk->src1))[tsk_node->tsk->xfer_size / 2]);
				memset(tsk_node->tsk->comp, 0,
				       sizeof(struct completion_record));
				tsk_node = tsk_node->next;
			}

			rc = dsa_compval_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 1);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;
		case DSA_OPCODE_DUALCAST:
			rc = dsa_dualcast_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;
		case DSA_OPCODE_TRANSL_FETCH:
			rc = dsa_transl_fetch_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			/* Verification of all the nodes*/
			rc = task_result_verify_task_nodes(ctx, 0);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;
		case DSA_OPCODE_CFLUSH:
			rc = dsa_cflush_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;
		default:
			err("Unsupported op %#x\n", opcode);
			return -EINVAL;
		}

		acctest_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_delta(struct acctest_context *ctx, size_t buf_size,
		      int tflags, uint32_t opcode, int num_desc)
{
	struct task_node *tsk_node;
	int rc = ACCTEST_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testmemory: opcode %d len %#lx tflags %#x num_desc %ld\n",
	     opcode, buf_size, tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == ACCTEST_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = acctest_alloc_multiple_tasks(ctx, i);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->xfer_size = buf_size;

			rc = init_task(tsk_node->tsk, tflags, opcode, buf_size);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			tsk_node = tsk_node->next;
		}

		switch (opcode) {
		case DSA_OPCODE_CR_DELTA:
			rc = dsa_cr_delta_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_AP_DELTA:
			rc = dsa_cr_delta_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			rc = dsa_ap_delta_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		default:
			err("Unsupported op %#x\n", opcode);
			return -EINVAL;
		}

		/* Verification of all the nodes*/
		rc = task_result_verify_task_nodes(ctx, 0);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		acctest_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static int test_crc(struct acctest_context *ctx, size_t buf_size,
		    int tflags, uint32_t opcode, int num_desc)
{
	struct task_node *tsk_node;
	int rc = ACCTEST_STATUS_OK;
	int itr = num_desc, i = 0, range = 0;

	info("testmemory: opcode %d len %#lx tflags %#x num_desc %ld\n",
	     opcode, buf_size, tflags, num_desc);

	ctx->is_batch = 0;

	if (ctx->dedicated == ACCFG_WQ_SHARED)
		range = ctx->threshold;
	else
		range = ctx->wq_size;

	while (itr > 0 && rc == ACCTEST_STATUS_OK) {
		i = (itr < range) ? itr : range;
		/* Allocate memory to all the task nodes, desc, completion record*/
		rc = acctest_alloc_multiple_tasks(ctx, i);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		/* allocate memory to src and dest buffers and fill in the desc for all the nodes*/
		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tsk_node->tsk->xfer_size = buf_size;

			rc = init_task(tsk_node->tsk, tflags, opcode, buf_size);
			if (rc != ACCTEST_STATUS_OK)
				return rc;

			tsk_node = tsk_node->next;
		}

		switch (opcode) {
		case DSA_OPCODE_CRCGEN:
			rc = dsa_crcgen_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		case DSA_OPCODE_COPY_CRC:
			rc = dsa_crc_copy_multi_task_nodes(ctx);
			if (rc != ACCTEST_STATUS_OK)
				return rc;
			break;

		default:
			err("Unsupported op %#x\n", opcode);
			return -EINVAL;
		}

		/* Verification of all the nodes*/
		rc = task_result_verify_task_nodes(ctx, 0);
		if (rc != ACCTEST_STATUS_OK)
			return rc;

		acctest_free_task(ctx);
		itr = itr - range;
	}

	return rc;
}

static struct evl_desc_list *parse_evl_desc(char *s, int nr_desc)
{
	char *cur;
	struct evl_desc_list *edl;
	struct batch_desc_info *bdi;
	int i;
	unsigned char status;
	int cp_fault;

	cur = strtok(s, ":");
	if (!cur)
		return NULL;

	edl = calloc(sizeof(*edl) + nr_desc * sizeof(edl->di[0]), 1);
	if (!edl)
		return NULL;

	bdi = &edl->bdi;
	if (sscanf(cur, "%d,%d,%d,%hu", &bdi->bc_fault, &bdi->bc_wr_fail, &bdi->da_fault,
		   &bdi->da_fault_idx) < 4)
		printf("%d: bc_fault %d bc_wr_fail %d da_fault %hu da_fault_idx\n",
		       bdi->bc_fault, bdi->bc_wr_fail, bdi->da_fault, bdi->da_fault_idx);
	if (bdi->da_fault) {
		if (bdi->da_fault_idx >= nr_desc) {
			err("desc addr fault idxd %d >= num desc in batch %d\n",
			    bdi->da_fault_idx, nr_desc);
			free(edl);
			return NULL;
		}
	}

	bdi->desc_completed = bdi->da_fault ? bdi->da_fault_idx : nr_desc;
	bdi->status = bdi->da_fault ? DSA_COMP_BATCH_PAGE_FAULT :
					DSA_COMP_SUCCESS;
	bdi->result = 0;

	i = 0;
	cp_fault = 0;
	status = DSA_COMP_SUCCESS;

	while ((cur = strtok(NULL, ":")) && i < nr_desc) {
		int nr_read;
		struct desc_info *di = &edl->di[i];

		nr_read = sscanf(cur, "%d,%d,%d,%d", &di->desc_fault,
				 &di->cp_fault, &di->cp_wr_fail, &di->fence);
		printf("%d: desc_fault %d cp_fault %d cp_wr_fail %d di_fence %d\n",
		       i, di->desc_fault, di->cp_fault, di->cp_wr_fail, di->fence);

		if (nr_read < 4)
			break;

		if (di->desc_fault || di->cp_wr_fail) {
			bdi->status = DSA_COMP_BATCH_FAIL;
			bdi->result = 1;
		}

		cp_fault = cp_fault | di->cp_fault;

		if (di->fence && (status != DSA_COMP_SUCCESS || cp_fault)) {
			if (cp_fault) {
				bdi->status = DSA_COMP_BATCH_FAIL;
				bdi->result = 1;
			}
			bdi->desc_completed = i;
			break;
		}

		if (bdi->da_fault && i == bdi->da_fault_idx) {
			bdi->status = DSA_COMP_BATCH_PAGE_FAULT;
			break;
		}

		i++;
	}

	return edl;
}

int main(int argc, char *argv[])
{
	struct acctest_context *dsa;
	int rc = 0;
	unsigned long buf_size = DSA_TEST_SIZE;
	int wq_type = SHARED;
	int opcode = DSA_OPCODE_MEMMOVE;
	int bopcode = DSA_OPCODE_MEMMOVE;
	int tflags = TEST_FLAGS_BOF;
	int opt;
	unsigned int bsize = 0;
	char dev_type[MAX_DEV_LEN];
	int wq_id = ACCTEST_DEVICE_ID_NO_INPUT;
	int dev_id = ACCTEST_DEVICE_ID_NO_INPUT;
	int dev_wq_id = ACCTEST_DEVICE_ID_NO_INPUT;
	unsigned int num_desc = 1;
	struct evl_desc_list *edl = NULL;
	char *edl_str = NULL;

	while ((opt = getopt(argc, argv, "e:w:l:f:o:b:c:d:n:t:p:vh")) != -1) {
		switch (opt) {
		case 'e':
			edl_str = optarg;
			break;
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

	dsa = acctest_init(tflags);
	dsa->dev_type = ACCFG_DEVICE_DSA;

	if (!dsa)
		return -ENOMEM;

	if (edl_str && opcode == 1) {
		edl = parse_evl_desc(edl_str, bsize);
		if (!edl)
			return -EINVAL;
		dsa->is_evl_test = 1;
	}

	rc = acctest_alloc(dsa, wq_type, dev_id, wq_id);
	if (rc < 0)
		return -ENOMEM;

	if (buf_size > dsa->max_xfer_size) {
		err("invalid transfer size: %lu\n", buf_size);
		return -EINVAL;
	}

	switch (opcode) {
	case DSA_OPCODE_NOOP:
		rc = test_noop(dsa, tflags, num_desc);
		if (rc != ACCTEST_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_BATCH:
		if (bsize > dsa->max_batch_size || bsize < 2) {
			err("invalid num descs: %d\n", bsize);
			rc = -EINVAL;
			goto error;
		}
		rc = test_batch(dsa, edl, buf_size, tflags, bopcode, bsize, num_desc);
		if (rc < 0)
			goto error;
		break;

	case DSA_OPCODE_DRAIN:
	case DSA_OPCODE_MEMMOVE:
	case DSA_OPCODE_MEMFILL:
	case DSA_OPCODE_COMPARE:
	case DSA_OPCODE_COMPVAL:
	case DSA_OPCODE_DUALCAST:
	case DSA_OPCODE_TRANSL_FETCH:
	case DSA_OPCODE_CFLUSH:
		rc = test_memory(dsa, buf_size, tflags, opcode, num_desc);
		if (rc != ACCTEST_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_CR_DELTA:
	case DSA_OPCODE_AP_DELTA:
		rc = test_delta(dsa, buf_size, tflags, opcode, num_desc);
		if (rc != ACCTEST_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_CRCGEN:
	case DSA_OPCODE_COPY_CRC:
		rc = test_crc(dsa, buf_size, tflags, opcode, num_desc);
		if (rc != ACCTEST_STATUS_OK)
			goto error;
		break;

	case DSA_OPCODE_DIF_CHECK:
	case DSA_OPCODE_DIF_INS:
	case DSA_OPCODE_DIF_STRP:
	case DSA_OPCODE_DIF_UPDT:
	case DSA_OPCODE_DIX_GEN:
		rc = test_dif(dsa, buf_size, tflags, opcode, num_desc);
		if (rc != ACCTEST_STATUS_OK)
			goto error;
		break;

	default:
		rc = -EINVAL;
		break;
	}

 error:
	free(edl);
	acctest_free(dsa);
	return rc;
}
