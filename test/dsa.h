/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __TEST_DSA_H__
#define __TEST_DSA_H__
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "accfg_test.h"
#include "accel_test.h"
#include "crc16_t10_lookup.h"

#define DSA_MAX_OPS 0x20

#define DSA_BATCH_OPCODES 0x278

#define DSA_CAP_MAX_BATCH_MASK                  0x0000000001E00000
#define DSA_CAP_MAX_BATCH_SHIFT                 21

/* CRC Flags */
#define READ_CRC_SEED		((unsigned long)(1 << 16))
#define BYPASS_CRC_INV_REF	((unsigned long)(1 << 17))
#define BYPASS_DATA_REF		((unsigned long)(1 << 18))

/* DIF index */
#define DIF_BLK_GRD_1  0
#define DIF_BLK_GRD_2  1
#define DIF_APP_TAG_1  2
#define DIF_APP_TAG_2  3
#define DIF_REF_TAG_1  4
#define DIF_REF_TAG_2  5
#define DIF_REF_TAG_3  6
#define DIF_REF_TAG_4  7

#define DIF_INVERT_CRC_SEED         ((unsigned long)(1 << 2))
#define DIF_INVERT_CRC_RESULT       ((unsigned long)(1 << 3))

#define MIN_DELTA_RECORD_SIZE 80

/* dump all sub descriptors for a batch task */
static inline void dump_sub_desc(struct batch_task *btsk)
{
	int i;

	for (i = 0; i < btsk->task_num; i++) {
		dbg("sub_desc[%d]:\n", i);
		dump_desc(btsk->sub_tasks[i].desc);
	}
}

/* dump all sub completion records for a batch task */
static inline void dump_sub_compl_rec(struct batch_task *btsk, int compl_size)
{
	int i;

	for (i = 0; i < btsk->task_num; i++) {
		dbg("sub_comp[%d]:\n", i);
		if (btsk->edl && !btsk->edl->di[i].cp_wr_fail)
			dump_compl_rec(btsk->sub_tasks[i].comp, compl_size);
		else
			dbg("comp address mmap'ed PROT_NONE\n");
	}
}

int init_memcpy(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_memfill(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_compare(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_compval(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dualcast(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_transl_fetch(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_cr_delta(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_crcgen(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_copy_crc(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dif_check(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dif_ins(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dif_strp(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dif_updt(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_cflush(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_task(struct task *tsk, int tflags, int opcode,
	      unsigned long xfer_size);

int dsa_noop_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_noop(struct acctest_context *ctx, struct task *tsk);

int dsa_drain_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_drain(struct acctest_context *ctx, struct task *tsk);

int dsa_memcpy_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_memcpy(struct acctest_context *ctx, struct task *tsk);

int dsa_memfill_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_memfill(struct acctest_context *ctx, struct task *tsk);

int dsa_compare_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_compare(struct acctest_context *ctx, struct task *tsk);

int dsa_compval_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_compval(struct acctest_context *ctx, struct task *tsk);

int dsa_dualcast_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_dualcast(struct acctest_context *ctx, struct task *tsk);

int dsa_transl_fetch_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_transl_fetch(struct acctest_context *ctx, struct task *tsk);

int dsa_cr_delta_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_cr_delta(struct acctest_context *ctx, struct task *tsk);

int dsa_ap_delta_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_ap_delta(struct acctest_context *ctx, struct task *tsk);

int dsa_crcgen_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_crcgen(struct acctest_context *ctx, struct task *tsk);

int dsa_crc_copy_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_crc_copy(struct acctest_context *ctx, struct task *tsk);

int dsa_dif_check_multi_task_nodes(struct acctest_context *ctx);
int dsa_dif_ins_multi_task_nodes(struct acctest_context *ctx);
int dsa_dif_strp_multi_task_nodes(struct acctest_context *ctx);
int dsa_dif_updt_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_dif(struct acctest_context *ctx, struct task *tsk);

int dsa_cflush_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_cflush(struct acctest_context *ctx, struct task *tsk);

void dsa_prep_noop(struct task *tsk);
void dsa_prep_drain(struct task *tsk);
void dsa_reprep_batch(struct batch_task *btsk, struct acctest_context *ctx);
void dsa_prep_memcpy(struct task *tsk);
void dsa_reprep_memcpy(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_memfill(struct task *tsk);
void dsa_reprep_memfill(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_compare(struct task *tsk);
void dsa_reprep_compare(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_compval(struct task *tsk);
void dsa_reprep_compval(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_dualcast(struct task *tsk);
void dsa_reprep_dualcast(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_transl_fetch(struct task *tsk);
void dsa_prep_cr_delta(struct task *tsk);
void dsa_reprep_cr_delta(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_ap_delta(struct task *tsk);
void dsa_reprep_ap_delta(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_crcgen(struct task *tsk);
void dsa_reprep_crcgen(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_crc_copy(struct task *tsk);
void dsa_reprep_crc_copy(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_dif_check(struct task *tsk);
void dsa_prep_dif_insert(struct task *tsk);
void dsa_prep_dif_strip(struct task *tsk);
void dsa_prep_dif_update(struct task *tsk);
void dsa_reprep_dif(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_cflush(struct task *tsk);
void dsa_reprep_cflush(struct acctest_context *ctx, struct task *tsk);

int task_result_verify(struct task *tsk, int mismatch_expected);
int task_result_verify_task_nodes(struct acctest_context *ctx, int mismatch_expected);
int task_result_verify_memcpy(struct task *tsk, int mismatch_expected);
int task_result_verify_memfill(struct task *tsk, int mismatch_expected);
int task_result_verify_compare(struct task *tsk, int mismatch_expected);
int task_result_verify_compval(struct task *tsk, int mismatch_expected);
int task_result_verify_dualcast(struct task *tsk, int mismatch_expected);
int task_result_verify_ap_delta(struct task *tsk, int mismatch_expected);
int task_result_verify_crcgen(struct task *tsk, int mismatch_expected);
int task_result_verify_crc_copy(struct task *tsk, int mismatch_expected);
int task_result_verify_dif(struct task *tsk, unsigned long xfer_size, int mismatch_expected);
int task_result_verify_dif_tags(struct task *tsk, unsigned long xfer_size);
int batch_result_verify(struct batch_task *btsk, int bof, int cp_fault);

int alloc_batch_task(struct acctest_context *ctx, unsigned int task_num, int num_itr);
int init_batch_task(struct batch_task *btsk, int task_num, int tflags,
		    int opcode, unsigned long xfer_size, unsigned long dflags);

void dsa_prep_batch(struct batch_task *btsk, unsigned long desc_flags);
void dsa_prep_batch_noop(struct batch_task *btsk);
void dsa_prep_batch_memcpy(struct batch_task *btsk);
void dsa_prep_batch_memfill(struct batch_task *btsk);
void dsa_prep_batch_compare(struct batch_task *btsk);
void dsa_prep_batch_compval(struct batch_task *btsk);
void dsa_prep_batch_dualcast(struct batch_task *btsk);
void dsa_prep_batch_transl_fetch(struct batch_task *btsk);
void dsa_prep_batch_cr_delta(struct batch_task *btsk);
void dsa_prep_batch_ap_delta(struct batch_task *btsk);
void dsa_prep_batch_crcgen(struct batch_task *btsk);
void dsa_prep_batch_crc_copy(struct batch_task *btsk);
void dsa_prep_batch_dif_check(struct batch_task *btsk);
void dsa_prep_batch_dif_insert(struct batch_task *btsk);
void dsa_prep_batch_dif_strip(struct batch_task *btsk);
void dsa_prep_batch_dif_update(struct batch_task *btsk);
void dsa_prep_batch_cflush(struct batch_task *btsk);
int dsa_wait_batch(struct batch_task *btsk, struct acctest_context *ctx);

uint16_t dsa_calculate_crc_t10dif(unsigned char *buffer, size_t len, int flags);
int get_dif_blksz_flg(unsigned long xfer_size);
unsigned long get_blks(unsigned long xfer_size);
#endif
