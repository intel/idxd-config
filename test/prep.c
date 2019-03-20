// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/idxd.h>
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

static inline void dsa_desc_submit(struct dsa_context *ctx,
				struct dsa_hw_desc *hw)
{
	dump_desc(hw);

	/* use MOVDIR64B for DWQ */
	if (ctx->dedicated)
		movdir64b(hw, ctx->wq_reg);
	else /* use ENQCMD for SWQ */
		if (dsa_enqcmd(ctx, hw))
			usleep(10000);
}

static void dsa_prep_submit_memcpy(struct dsa_context *ctx,
		struct dsa_ring_ent *desc, uint64_t dst, uint64_t src,
		size_t len, unsigned long desc_flags)
{
	struct dsa_hw_desc *hw;

	hw = &desc->hw;

	dsa_prep_desc_common(hw, DSA_OPCODE_MEMMOVE, dst, src, len,
			desc_flags);

	desc->comp->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_reprep_memcpy(struct dsa_context *ctx, struct dsa_ring_ent *desc)
{
	struct dsa_completion_record *compl = desc->comp;
	struct dsa_hw_desc *hw = &desc->hw;

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

/* Performs no error or bound checking */
void dsa_prep_batch_memcpy(struct dsa_batch *batch, int idx, int n,
		uint64_t dst, uint64_t src, size_t len, unsigned long dflags)
{
	int i;
	struct dsa_hw_desc *hw;

	hw = &batch->descs[idx];
	for (i = 0; i < n; i++) {
		size_t copy = len;

		dsa_prep_desc_common(hw, DSA_OPCODE_MEMMOVE, dst, src, copy,
				dflags);
		dst += copy;
		src += copy;
		hw++;
	}
}

int dsa_prep_memcpy(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *dest, void *src, size_t len, unsigned int dflags)
{
	int i, n = desc->n;

	for (i = 0; i < n; i++) {
		size_t copy = len;

		if (copy > ctx->max_xfer_size)
			copy = ctx->max_xfer_size;

		dsa_prep_submit_memcpy(ctx, desc, (uint64_t)dest,
				(uint64_t)src, copy, dflags);
		info("prepared desc %d s %p d %p c %#lx sz %#lx\n",
				i, src, dest, desc->hw.completion_addr, copy);

		len -= copy;
		dest = (char *)dest + copy;
		src = (char *)src + copy;
		desc++;
	}
	return 0;
}

static void dsa_prep_submit_memfill(struct dsa_context *ctx,
		struct dsa_ring_ent *desc, uint64_t dst, uint64_t value,
		size_t len, unsigned long desc_flags)
{
	struct dsa_hw_desc *hw;

	hw = &desc->hw;

	/* src_addr is the location of value for memfill descriptor */
	dsa_prep_desc_common(hw, DSA_OPCODE_MEMFILL, dst, value, len,
						desc_flags);
	desc->comp->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_reprep_memfill(struct dsa_context *ctx, struct dsa_ring_ent *desc)
{
	struct dsa_completion_record *compl = desc->comp;
	struct dsa_hw_desc *hw = &desc->hw;

	info("PF addr %#lx dir %d bc %#x\n",
			compl->fault_addr, compl->result,
			compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->dst_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	dsa_desc_submit(ctx, hw);
}

int dsa_prep_memfill(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *dst, uint64_t value, size_t len, unsigned long dflags)
{
	int i, n = desc->n;

	for (i = 0; i < n; i++) {
		size_t fill = len;

		if (fill > ctx->max_xfer_size)
			fill = ctx->max_xfer_size;

		dsa_prep_submit_memfill(ctx, desc, (uint64_t)dst, value,
				fill, dflags);
		info("prepared desc %d d %p c %#lx sz %#lx\n",
				i, dst, desc->hw.completion_addr, fill);

		len -= fill;
		dst = (char *)dst + fill;
		desc++;
	}
	return 0;
}

void dsa_prep_batch_memfill(struct dsa_batch *batch, int idx, int n,
		uint64_t dst, uint64_t val, size_t len, unsigned long dflags)
{
	int i;
	struct dsa_hw_desc *hw;

	hw = &batch->descs[idx];
	for (i = 0; i < n; i++) {
		size_t fill = len;

		dsa_prep_desc_common(hw, DSA_OPCODE_MEMFILL, dst, val, fill,
				dflags);
		info("prepared batch desc %d d %#lx c %#lx sz %#lx\n",
				i, dst, hw->completion_addr, fill);
		dst += fill;
		hw++;
	}
}

static void dsa_prep_submit_compare(struct dsa_context *ctx,
		struct dsa_ring_ent *desc, uint64_t src1, uint64_t src2,
		size_t len, unsigned long dflags)
{
	struct dsa_hw_desc *hw;

	hw = &desc->hw;

	dsa_prep_desc_common(hw, DSA_OPCODE_COMPARE, src1, src2, len, dflags);

	desc->comp->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_reprep_compare(struct dsa_context *ctx, struct dsa_ring_ent *desc)
{
	struct dsa_completion_record *compl = desc->comp;
	struct dsa_hw_desc *hw = &desc->hw;

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

int dsa_prep_compare(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *src1, void *src2, size_t len, unsigned long dflags)
{
	int i, n = desc->n;

	for (i = 0; i < n; i++) {
		size_t comp = len;

		if (comp > ctx->max_xfer_size)
			comp = ctx->max_xfer_size;

		dsa_prep_submit_compare(ctx, desc, (uint64_t)src1,
				(uint64_t)src2, comp, dflags);
		info("prepared desc %d s %p d %p c %#lx sz %#lx\n",
				i, src1, src2, desc->hw.completion_addr, comp);

		len -= comp;
		src1 = (char *)src1 + comp;
		src2 = (char *)src2 + comp;
		desc++;
	}
	return 0;
}

void dsa_prep_batch_compare(struct dsa_batch *batch, int idx, int n,
		uint64_t src1, uint64_t src2, size_t len, unsigned long dflags)
{
	int i;
	struct dsa_hw_desc *hw;

	hw = &batch->descs[idx];

	for (i = 0; i < n; i++) {
		size_t comp = len;

		dsa_prep_desc_common(hw, DSA_OPCODE_COMPARE, src1, src2, comp,
				dflags);
		src1 += comp;
		src2 += comp;
		hw++;
	}
}

static void dsa_prep_submit_compval(struct dsa_context *ctx,
		struct dsa_ring_ent *desc, uint64_t val, uint64_t src,
		size_t len, unsigned long dflags)
{
	struct dsa_hw_desc *hw;

	hw = &desc->hw;

	dsa_prep_desc_common(hw, DSA_OPCODE_COMPVAL, val, src, len, dflags);

	desc->comp->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_reprep_compval(struct dsa_context *ctx, struct dsa_ring_ent *desc)
{
	struct dsa_completion_record *compl = desc->comp;
	struct dsa_hw_desc *hw = &desc->hw;

	info("PF addr %#lx dir %d bc %#x\n",
			compl->fault_addr, compl->result,
			compl->bytes_completed);

	hw->xfer_size -= compl->bytes_completed;

	hw->src_addr += compl->bytes_completed;

	resolve_page_fault(compl->fault_addr, compl->status);

	compl->status = 0;

	dsa_desc_submit(ctx, hw);
}

int dsa_prep_compval(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		uint64_t val, void *src, size_t len, unsigned long dflags)
{
	int i, n = desc->n;

	for (i = 0; i < n; i++) {
		size_t comp = len;

		if (comp > ctx->max_xfer_size)
			comp = ctx->max_xfer_size;

		dsa_prep_submit_compval(ctx, desc, val,
				(uint64_t)src, comp, dflags);
		info("prepared desc %d s %p c %#lx sz %#lx\n",
				i, src, desc->hw.completion_addr, comp);

		len -= comp;
		src = (char *)src + comp;
		desc++;
	}
	return 0;
}

void dsa_prep_batch_compval(struct dsa_batch *batch, int idx, int n,
		uint64_t val, uint64_t src, size_t len, unsigned long dflags)
{
	int i;
	struct dsa_hw_desc *hw;

	hw = &batch->descs[idx];

	for (i = 0; i < n; i++) {
		size_t comp = len;

		dsa_prep_desc_common(hw, DSA_OPCODE_COMPVAL, val, src, comp,
				dflags);
		info("prepared batch desc %d s %#lx c %#lx sz %#lx\n",
				i, src, hw->completion_addr, comp);
		src += comp;
		hw++;
	}
}

static void dsa_prep_submit_dualcast(struct dsa_context *ctx,
		struct dsa_ring_ent *desc, uint64_t dst1,
		uint64_t dst2, uint64_t src, size_t len, unsigned long dflags)
{
	struct dsa_hw_desc *hw;

	hw = &desc->hw;

	dsa_prep_desc_common(hw, DSA_OPCODE_DUALCAST, dst1, src, len, dflags);
	hw->dest2 = dst2;

	desc->comp->status = 0;

	dsa_desc_submit(ctx, hw);
}

void dsa_reprep_dualcast(struct dsa_context *ctx, struct dsa_ring_ent *desc)
{
	struct dsa_completion_record *compl = desc->comp;
	struct dsa_hw_desc *hw = &desc->hw;

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

int dsa_prep_dualcast(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *dst1, void *dst2, void *src, size_t len,
		unsigned long dflags)
{
	int i, n = desc->n;

	for (i = 0; i < n; i++) {
		size_t copy = len;

		if (copy > ctx->max_xfer_size)
			copy = ctx->max_xfer_size;

		dsa_prep_submit_dualcast(ctx, desc, (uint64_t)dst1,
				(uint64_t)dst2, (uint64_t)src, copy, dflags);

		info("prepared desc %d s %p d1 %p d2 %p c %#lx sz %#lx\n",
				i, src, dst1, dst2,
				desc->hw.completion_addr, copy);

		len -= copy;
		src = (char *)src + copy;
		dst1 = (char *)dst1 + copy;
		dst2 = (char *)dst2 + copy;
		desc++;
	}
	return 0;
}

void dsa_prep_batch_dualcast(struct dsa_batch *batch, int idx, int n,
		uint64_t dst1, uint64_t dst2, uint64_t src, size_t len,
		unsigned long dflags)
{
	int i;
	struct dsa_hw_desc *hw;

	hw = &batch->descs[idx];

	for (i = 0; i < n; i++) {
		size_t copy = len;

		dsa_prep_desc_common(hw, DSA_OPCODE_DUALCAST, dst1, src, copy,
				dflags);
		hw->dest2 = dst2;
		info("prepared batch desc %d s %#lx d1 %#lx d2 %#lx\n",
				i, src, dst1, dst2);
		info("c %#lx sz %#lx\n", hw->completion_addr, copy);
		src += copy;
		dst1 += copy;
		dst2 += copy;
		hw++;
	}
}

void dsa_prep_submit_batch(struct dsa_batch *batch, int idx, int n,
		struct dsa_ring_ent *desc, unsigned long desc_flags)
{
	struct dsa_context *ctx = batch->ctx;
	struct dsa_hw_desc *hw;
	uint64_t batch_addr = (uint64_t)&batch->descs[idx];

	info("preparing batch using %d %d %#lx h:t %d:%d\n",
			idx, n, batch_addr, ctx->head, ctx->tail);

	hw = &desc->hw;

	dsa_prep_desc_common(hw, DSA_OPCODE_BATCH, 0, batch_addr,
				n, desc_flags);

	desc->comp->status = 0;

	dsa_desc_submit(ctx, hw);
}
