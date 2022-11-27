// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <accfg/idxd.h>
#include "accel_test.h"
#include "dsa.h"

unsigned int dif_arr[] = {512, 520, 4096, 4104};

void dsa_prep_noop(struct task *tsk)
{
	info("preparing descriptor for noop\n");

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), 0, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_prep_drain(struct task *tsk)
{
	info("preparing descriptor for drain\n");

	if (tsk->opcode == DSA_OPCODE_MEMMOVE)
		tsk->opcode = DSA_OPCODE_DRAIN;

	acctest_prep_desc_common(tsk->desc, tsk->opcode, 0,
				 0, 0, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_batch(struct batch_task *btsk, struct acctest_context *ctx)
{
	struct task *ctsk = btsk->core_task;
	struct completion_record *compl = ctsk->comp;
	struct hw_desc *hw = ctsk->desc;

	info("batch PF addr %#lx dir %d dc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->descs_completed);

	mprotect((void *)(compl->fault_addr & ~0xfff), 4096, PROT_READ | PROT_WRITE);
	hw->desc_list_addr += compl->descs_completed * 64;
	hw->desc_count -= compl->descs_completed;

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_memcpy(struct task *tsk)
{
	info("preparing descriptor for memcpy\n");

	if (tsk->opcode == DSA_OPCODE_DRAIN)
		tsk->opcode = DSA_OPCODE_MEMMOVE;

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_memcpy(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	if (compl->result == 0) {
		hw->src_addr += compl->bytes_completed;
		hw->dst_addr += compl->bytes_completed;
	}

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_noop(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;
	uint32_t dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1),
					 (uint64_t)(sub_task->src1),
					 0, dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
	}
}

/* Performs no error or bound checking */
void dsa_prep_batch_memcpy(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1),
					 (uint64_t)(sub_task->src1),
					 sub_task->xfer_size, sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
	}
}

void dsa_prep_memfill(struct task *tsk)
{
	info("preparing descriptor for memfill\n");

	/* src_addr is the location of pattern for memfill descriptor */
	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 tsk->pattern, tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_memfill(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->dst_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_memfill(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1),
					 sub_task->pattern,
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
	}
}

void dsa_prep_compare(struct task *tsk)
{
	info("preparing descriptor for compare\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->src1),
				 (uint64_t)(tsk->src2), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_compare(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;
	hw->dst_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_compare(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->src1),
					 (uint64_t)(sub_task->src2),
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
	}
}

void dsa_prep_compval(struct task *tsk)
{
	info("preparing descriptor for compval\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, tsk->pattern,
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_compval(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_compval(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 sub_task->pattern,
					 (uint64_t)(sub_task->src1),
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
	}
}

void dsa_prep_dualcast(struct task *tsk)
{
	info("preparing descriptor for dualcast\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->dest2 = (uint64_t)(tsk->dst2);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_dualcast(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;
	hw->dst_addr += compl->bytes_completed;
	hw->dest2 += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_dualcast(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1),
					 (uint64_t)(sub_task->src1),
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->dest2 = (uint64_t)(sub_task->dst2);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
	}
}

void dsa_prep_transl_fetch(struct task *tsk)
{
	info("preparing descriptor for transl fetch\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, 0,
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_prep_batch_transl_fetch(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 0,
					 (uint64_t)(sub_task->src1),
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
	}
}

void dsa_prep_batch_cr_delta(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		if (sub_task->opcode == DSA_OPCODE_AP_DELTA)
			sub_task->opcode = DSA_OPCODE_CR_DELTA;
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->src2),
					 (uint64_t)(sub_task->src1),
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->desc->delta_addr = (uint64_t)sub_task->delta1;
		sub_task->desc->max_delta_size = 2 * sub_task->xfer_size;
		sub_task->comp->status = 0;
	}
}

void dsa_prep_cr_delta(struct task *tsk)
{
	info("preparing descriptor for cr delta\n");

	if (tsk->opcode == DSA_OPCODE_AP_DELTA)
		tsk->opcode = DSA_OPCODE_CR_DELTA;
	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->src2),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->max_delta_size = 2 * tsk->xfer_size;//need to made configurable
	tsk->desc->delta_addr = (uint64_t)tsk->delta1;
	if (tsk->desc->max_delta_size < MIN_DELTA_RECORD_SIZE)
		tsk->desc->max_delta_size = MIN_DELTA_RECORD_SIZE;
	tsk->comp->status = 0;
}

void dsa_reprep_cr_delta(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;
	hw->dst_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_ap_delta(struct task *tsk)
{
	info("preparing descriptor for ap delta\n");

	if (tsk->opcode == DSA_OPCODE_CR_DELTA)
		tsk->opcode = DSA_OPCODE_AP_DELTA;
	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->delta1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->desc->delta_addr = 0;
	tsk->desc->delta_rec_size = tsk->comp->delta_rec_size;
	tsk->desc->max_delta_size = 0;
	tsk->comp->status = 0;
}

void dsa_reprep_ap_delta(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;
	hw->dst_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_ap_delta(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		if (sub_task->opcode == DSA_OPCODE_CR_DELTA)
			sub_task->opcode = DSA_OPCODE_AP_DELTA;
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1),
					 (uint64_t)(sub_task->delta1),
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->desc->delta_addr = 0;
		sub_task->desc->delta_rec_size = sub_task->comp->delta_rec_size;
		sub_task->desc->max_delta_size = 0;
		sub_task->comp->status = 0;
	}
}

void dsa_prep_crcgen(struct task *tsk)
{
	info("preparing descriptor for crcgen\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
	tsk->desc->crc_seed = tsk->crc_seed;
	tsk->desc->seed_addr = (uint64_t)tsk->crc_seed_addr;
}

void dsa_reprep_crcgen(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_crcgen(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1),
					 (uint64_t)(sub_task->src1),
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
		sub_task->desc->crc_seed = sub_task->crc_seed;
	}
}

void dsa_prep_crc_copy(struct task *tsk)
{
	info("preparing descriptor for crc copy\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
	tsk->desc->crc_seed = tsk->crc_seed;
	tsk->desc->seed_addr = (uint64_t)tsk->crc_seed_addr;
}

void dsa_reprep_crc_copy(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;
	hw->dst_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_crc_copy(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1),
					 (uint64_t)(sub_task->src1),
					 sub_task->xfer_size,
					 sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
		sub_task->desc->crc_seed = sub_task->crc_seed;
	}
}

void dsa_prep_dif_check(struct task *tsk)
{
	info("preparing descriptor for dif check\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
	tsk->desc->chk_app_tag_seed = tsk->apptag;
	tsk->desc->chk_ref_tag_seed = tsk->reftag;
	tsk->desc->dif_chk_flags = tsk->blk_idx_flg;
}

void dsa_prep_dif_insert(struct task *tsk)
{
	info("preparing descriptor for dif insert\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
	tsk->desc->ins_app_tag_seed = tsk->apptag;
	tsk->desc->ins_ref_tag_seed = tsk->reftag;
	tsk->desc->dif_ins_flags = tsk->blk_idx_flg;
}

void dsa_prep_dif_strip(struct task *tsk)
{
	info("preparing descriptor for dif strip\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
	tsk->desc->chk_app_tag_seed = tsk->apptag;
	tsk->desc->chk_ref_tag_seed = tsk->reftag;
	tsk->desc->dif_chk_flags = tsk->blk_idx_flg;
}

void dsa_prep_dif_update(struct task *tsk)
{
	info("preparing descriptor for dif update\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
	tsk->desc->src_app_tag_seed = tsk->apptag;
	tsk->desc->src_ref_tag_seed = tsk->reftag;
	tsk->desc->dest_ref_tag_seed = tsk->reftag;
	tsk->desc->dest_app_tag_seed = tsk->apptag;
	tsk->desc->src_upd_flags = 0x80;
	tsk->desc->upd_dest_flags = 0x80;
	tsk->desc->dif_upd_flags = tsk->blk_idx_flg;
}

void dsa_reprep_dif(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;
	unsigned long blks_completed = 0;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->src_addr += compl->bytes_completed;
	hw->ins_ref_tag_seed = compl->dif_ins_ref_tag;
	if (tsk->opcode == DSA_OPCODE_DIF_INS) {
		blks_completed = compl->bytes_completed / (dif_arr[tsk->blk_idx_flg]);
		hw->xfer_size -= compl->bytes_completed;
		hw->dst_addr += compl->bytes_completed + 8 * blks_completed;
		hw->ins_app_tag_seed = compl->dif_ins_app_tag;
		hw->ins_ref_tag_seed = compl->dif_ins_ref_tag;
	}

	if (tsk->opcode == DSA_OPCODE_DIF_STRP) {
		blks_completed = compl->bytes_completed / (dif_arr[tsk->blk_idx_flg] + 8);
		hw->xfer_size -= compl->bytes_completed;
		hw->dst_addr += dif_arr[tsk->blk_idx_flg] * blks_completed;
		hw->chk_app_tag_seed = compl->dif_chk_app_tag;
		hw->chk_ref_tag_seed = compl->dif_chk_ref_tag;
	}

	if (tsk->opcode == DSA_OPCODE_DIF_UPDT) {
		blks_completed = compl->bytes_completed / (dif_arr[tsk->blk_idx_flg] + 8);
		hw->xfer_size -= compl->bytes_completed;
		hw->dst_addr += (dif_arr[tsk->blk_idx_flg] + 8) * blks_completed;
		hw->src_app_tag_seed = compl->dif_upd_src_app_tag;
		hw->dest_app_tag_seed = compl->dif_upd_dest_app_tag;
		hw->src_ref_tag_seed = compl->dif_upd_dest_ref_tag;
		hw->dest_ref_tag_seed = compl->dif_upd_dest_ref_tag;
	}
	if (tsk->opcode == DSA_OPCODE_DIF_CHECK) {
		hw->xfer_size -= compl->bytes_completed;
		hw->chk_app_tag_seed = compl->dif_chk_app_tag;
		hw->chk_ref_tag_seed = compl->dif_chk_ref_tag;
	}

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_dif_check(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		sub_task->xfer_size = btsk->sub_tasks[i].xfer_size;
		sub_task->desc->dif_chk_flags = btsk->sub_tasks[i].blk_idx_flg;
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1), (uint64_t)(sub_task->src1),
					 sub_task->xfer_size, sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
		sub_task->desc->chk_app_tag_seed = sub_task->apptag;
		sub_task->desc->chk_ref_tag_seed = sub_task->reftag;
	}
}

void dsa_prep_batch_dif_insert(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		sub_task->xfer_size = btsk->sub_tasks[i].xfer_size;
		sub_task->desc->dif_chk_flags = btsk->sub_tasks[i].blk_idx_flg;
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1), (uint64_t)(sub_task->src1),
					 sub_task->xfer_size, sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
		sub_task->desc->ins_app_tag_seed = sub_task->apptag;
		sub_task->desc->ins_ref_tag_seed = sub_task->reftag;
	}
}

void dsa_prep_batch_dif_strip(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		sub_task->xfer_size = btsk->sub_tasks[i].xfer_size;
		sub_task->desc->dif_chk_flags = btsk->sub_tasks[i].blk_idx_flg;
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1), (uint64_t)(sub_task->src1),
					 sub_task->xfer_size, sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
		sub_task->desc->chk_app_tag_seed = sub_task->apptag;
		sub_task->desc->chk_ref_tag_seed = sub_task->reftag;
	}
}

void dsa_prep_batch_dif_update(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		sub_task->xfer_size = btsk->sub_tasks[i].xfer_size;
		sub_task->desc->dif_chk_flags = btsk->sub_tasks[i].blk_idx_flg;
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1), (uint64_t)(sub_task->src1),
					 sub_task->xfer_size, sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
		sub_task->desc->src_app_tag_seed = sub_task->apptag;
		sub_task->desc->src_ref_tag_seed = sub_task->reftag;
		sub_task->desc->dest_ref_tag_seed = sub_task->reftag;
		sub_task->desc->dest_app_tag_seed = sub_task->apptag;
		sub_task->desc->src_upd_flags = 0x80;
		sub_task->desc->upd_dest_flags = 0x80;
	}
}

void dsa_prep_cflush(struct task *tsk)
{
	info("preparing descriptor for cflush\n");

	acctest_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
				 (uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_cflush(struct acctest_context *ctx, struct task *tsk)
{
	struct completion_record *compl = tsk->comp;
	struct hw_desc *hw = tsk->desc;

	info("PF addr %#lx dir %d bc %#x\n",
	     compl->fault_addr, compl->result,
	     compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	acctest_desc_submit(ctx, hw);
}

void dsa_prep_batch_cflush(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &btsk->sub_tasks[i];
		acctest_prep_desc_common(sub_task->desc, sub_task->opcode,
					 (uint64_t)(sub_task->dst1),
					 (uint64_t)(sub_task->src1),
					 sub_task->xfer_size, sub_task->dflags);
		sub_task->desc->completion_addr = (uint64_t)(sub_task->comp);
		sub_task->comp->status = 0;
	}
}

void dsa_prep_batch(struct batch_task *btsk, unsigned long desc_flags)
{
	struct task *ctsk = btsk->core_task;

	info("preparing batch descriptor\n");

	/* BOF bit is reserved for batch descriptor, turn it off */
	desc_flags &= ~IDXD_OP_FLAG_BOF;

	acctest_prep_desc_common(ctsk->desc, DSA_OPCODE_BATCH,
				 0, (uint64_t)(btsk->sub_descs),
				 btsk->task_num, desc_flags);
	ctsk->desc->completion_addr = (uint64_t)(ctsk->comp);
	ctsk->desc->desc_count = (uint32_t)(btsk->task_num);

	ctsk->comp->status = 0;
}
