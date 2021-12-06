// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <accfg/idxd.h>
#include "dsa.h"

void dsa_prep_desc_common(struct dsa_hw_desc *hw, char opcode,
		uint64_t dest, uint64_t src, size_t len, unsigned long dflags)
{
	hw->flags = dflags;
	hw->opcode = opcode;
	hw->src_addr = src;
	hw->dst_addr = dest;
	hw->xfer_size = len;
}

void dsa_desc_submit(struct dsa_context *ctx, struct dsa_hw_desc *hw)
{
	dump_desc(hw);

	/* use MOVDIR64B for DWQ */
	if (ctx->dedicated)
		movdir64b(ctx->wq_reg, hw);
	else /* use ENQCMD for SWQ */
		if (dsa_enqcmd(ctx, hw))
			usleep(10000);
}

void dsa_prep_noop(struct task *tsk)
{
	info("preparing descriptor for noop\n");

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	dsa_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
			(uint64_t)(tsk->src1), 0, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_prep_memcpy(struct task *tsk)
{
	info("preparing descriptor for memcpy\n");

	dsa_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
			(uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_memcpy(struct dsa_context *ctx)
{
	struct dsa_completion_record *compl = ctx->single_task->comp;
	struct dsa_hw_desc *hw = ctx->single_task->desc;

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

	dsa_desc_submit(ctx, hw);
}

void dsa_prep_batch_noop(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;
	uint32_t dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &(btsk->sub_tasks[i]);
		dsa_prep_desc_common(sub_task->desc, sub_task->opcode,
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
		sub_task = &(btsk->sub_tasks[i]);
		dsa_prep_desc_common(sub_task->desc, sub_task->opcode,
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
	dsa_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
			tsk->pattern, tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_memfill(struct dsa_context *ctx)
{
	struct dsa_completion_record *compl = ctx->single_task->comp;
	struct dsa_hw_desc *hw = ctx->single_task->desc;

	info("PF addr %#lx dir %d bc %#x\n",
			compl->fault_addr, compl->result,
			compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->dst_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_prep_batch_memfill(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &(btsk->sub_tasks[i]);
		dsa_prep_desc_common(sub_task->desc, sub_task->opcode,
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

	dsa_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->src1),
			(uint64_t)(tsk->src2), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_compare(struct dsa_context *ctx)
{
	struct dsa_completion_record *compl = ctx->single_task->comp;
	struct dsa_hw_desc *hw = ctx->single_task->desc;

	info("PF addr %#lx dir %d bc %#x\n",
			compl->fault_addr, compl->result,
			compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;
	hw->dst_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_prep_batch_compare(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &(btsk->sub_tasks[i]);
		dsa_prep_desc_common(sub_task->desc, sub_task->opcode,
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

	dsa_prep_desc_common(tsk->desc, tsk->opcode, tsk->pattern,
			(uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_compval(struct dsa_context *ctx)
{
	struct dsa_completion_record *compl = ctx->single_task->comp;
	struct dsa_hw_desc *hw = ctx->single_task->desc;

	info("PF addr %#lx dir %d bc %#x\n",
			compl->fault_addr, compl->result,
			compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_prep_batch_compval(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &(btsk->sub_tasks[i]);
		dsa_prep_desc_common(sub_task->desc, sub_task->opcode,
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

	dsa_prep_desc_common(tsk->desc, tsk->opcode, (uint64_t)(tsk->dst1),
			(uint64_t)(tsk->src1), tsk->xfer_size, tsk->dflags);
	tsk->desc->dest2 = (uint64_t)(tsk->dst2);
	tsk->desc->completion_addr = (uint64_t)(tsk->comp);
	tsk->comp->status = 0;
}

void dsa_reprep_dualcast(struct dsa_context *ctx)
{
	struct dsa_completion_record *compl = ctx->single_task->comp;
	struct dsa_hw_desc *hw = ctx->single_task->desc;

	info("PF addr %#lx dir %d bc %#x\n",
			compl->fault_addr, compl->result,
			compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;
	hw->dst_addr += compl->bytes_completed;
	hw->dest2 += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_prep_batch_dualcast(struct batch_task *btsk)
{
	int i;
	struct task *sub_task;

	for (i = 0; i < btsk->task_num; i++) {
		sub_task = &(btsk->sub_tasks[i]);
		dsa_prep_desc_common(sub_task->desc, sub_task->opcode,
				(uint64_t)(sub_task->dst1),
				(uint64_t)(sub_task->src1),
				sub_task->xfer_size,
				sub_task->dflags);
		sub_task->desc->dest2 = (uint64_t)(sub_task->dst2);
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

	dsa_prep_desc_common(ctsk->desc, DSA_OPCODE_BATCH,
			0, (uint64_t)(btsk->sub_descs),
			btsk->task_num, desc_flags);
	ctsk->desc->completion_addr = (uint64_t)(ctsk->comp);
	ctsk->desc->desc_count = (uint32_t)(btsk->task_num);

	ctsk->comp->status = 0;
}
