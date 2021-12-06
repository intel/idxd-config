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
#include "dsa.h"

#define DSA_COMPL_RING_SIZE 64

unsigned int ms_timeout = 5000;
int debug_logging;
static int umwait_support;

static inline void cpuid(unsigned int *eax, unsigned int *ebx,
		unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
		: "=a" (*eax),
		"=b" (*ebx),
		"=c" (*ecx),
		"=d" (*edx)
		: "0" (*eax), "2" (*ecx)
		: "memory");
}

struct dsa_context *dsa_init(void)
{
	struct dsa_context *dctx;
	unsigned int unused[2];
	unsigned int leaf, waitpkg;
	int rc;
	struct accfg_ctx *ctx;

	/* detect umwait support */
	leaf = 7;
	waitpkg = 0;
	cpuid(&leaf, unused, &waitpkg, unused+1);
	if (waitpkg & 0x20) {
		dbg("umwait supported\n");
		umwait_support = 1;
	}

	dctx = malloc(sizeof(struct dsa_context));
	if (!dctx)
		return NULL;
	memset(dctx, 0, sizeof(struct dsa_context));

	rc = accfg_new(&ctx);
	if (rc < 0) {
		free(dctx);
		return NULL;
	}

	dctx->ctx = ctx;
	return dctx;
}

static int dsa_setup_wq(struct dsa_context *ctx, struct accfg_wq *wq)
{
	char path[PATH_MAX];
	int rc;

	rc = accfg_wq_get_user_dev_path(wq, path, PATH_MAX);
	if (rc) {
		fprintf(stderr, "Error getting uacce device path\n");
		return rc;
	}

	ctx->fd = open(path, O_RDWR);
	if (ctx->fd < 0) {
		perror("open");
		return -errno;
	}

	ctx->wq_reg = mmap(NULL, 0x1000, PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ctx->fd, 0);
	if (ctx->wq_reg == MAP_FAILED) {
		perror("mmap");
		return -errno;
	}

	return 0;
}

static struct accfg_wq *dsa_get_wq(struct dsa_context *ctx,
		int dev_id, int shared)
{
	struct accfg_device *device;
	struct accfg_wq *wq;
	int rc;

	accfg_device_foreach(ctx->ctx, device) {
		enum accfg_device_state dstate;

		/* Make sure that the device is enabled */
		dstate = accfg_device_get_state(device);
		if (dstate != ACCFG_DEVICE_ENABLED)
			continue;

		/* Match the device to the id requested */
		if (accfg_device_get_id(device) != dev_id &&
				dev_id != -1)
			continue;

		accfg_wq_foreach(device, wq) {
			enum accfg_wq_state wstate;
			enum accfg_wq_mode mode;
			enum accfg_wq_type type;

			/* Get a workqueue that's enabled */
			wstate = accfg_wq_get_state(wq);
			if (wstate != ACCFG_WQ_ENABLED)
				continue;

			/* The wq type should be user */
			type = accfg_wq_get_type(wq);
			if (type != ACCFG_WQT_USER)
				continue;

			/* Make sure the mode is correct */
			mode = accfg_wq_get_mode(wq);
			if ((mode == ACCFG_WQ_SHARED && !shared)
				|| (mode == ACCFG_WQ_DEDICATED && shared))
				continue;

			rc = dsa_setup_wq(ctx, wq);
			if (rc < 0)
				return NULL;

			return wq;
		}
	}

	return NULL;
}

static struct accfg_wq *dsa_get_wq_byid(struct dsa_context *ctx,
					 int dev_id, int wq_id)
{
	struct accfg_device *device;
	struct accfg_wq *wq;
	int rc;

	accfg_device_foreach(ctx->ctx, device) {

		/* Make sure that the device is enabled */
		if (accfg_device_get_state(device) != ACCFG_DEVICE_ENABLED)
			continue;

		/* Match the device to the id requested */
		if (accfg_device_get_id(device) != dev_id &&
				dev_id != DSA_DEVICE_ID_NO_INPUT)
			continue;

		accfg_wq_foreach(device, wq) {

			/* Get a workqueue that's enabled */
			if (accfg_wq_get_state(wq) != ACCFG_WQ_ENABLED)
				continue;

			/* The wq type should be user */
			if (accfg_wq_get_type(wq) != ACCFG_WQT_USER)
				continue;

			/* Make sure the wq id is correct */
			if (wq_id != accfg_wq_get_id(wq))
				continue;

			rc = dsa_setup_wq(ctx, wq);
			if (rc < 0)
				return NULL;

			return wq;
		}
	}

	return NULL;
}

static uint32_t bsr(uint32_t val)
{
	uint32_t msb;

	msb = (val == 0) ? 0 : 32 - __builtin_clz(val);
	return msb - 1;
}

int dsa_alloc(struct dsa_context *ctx, int shared, int dev_id, int wq_id)
{
	struct accfg_device *dev;

	/* Is wq already allocated? */
	if (ctx->wq_reg)
		return 0;

	if (wq_id != DSA_DEVICE_ID_NO_INPUT)
		ctx->wq = dsa_get_wq_byid(ctx, dev_id, wq_id);
	else
		ctx->wq = dsa_get_wq(ctx, dev_id, shared);

	if (!ctx->wq) {
		err("No usable wq found\n");
		return -ENODEV;
	}
	dev = accfg_wq_get_device(ctx->wq);
	ctx->dedicated = accfg_wq_get_mode(ctx->wq);
	ctx->wq_size = accfg_wq_get_size(ctx->wq);
	ctx->wq_idx = accfg_wq_get_id(ctx->wq);
	ctx->bof = accfg_wq_get_block_on_fault(ctx->wq);
	ctx->wq_max_batch_size = accfg_wq_get_max_batch_size(ctx->wq);
	ctx->wq_max_xfer_size = accfg_wq_get_max_transfer_size(ctx->wq);
	ctx->ats_disable = accfg_wq_get_ats_disable(ctx->wq);

	ctx->max_batch_size = accfg_device_get_max_batch_size(dev);
	ctx->max_xfer_size = accfg_device_get_max_transfer_size(dev);
	ctx->max_xfer_bits = bsr(ctx->max_xfer_size);

	info("alloc wq %d shared %d size %d addr %p batch sz %#x xfer sz %#x\n",
			ctx->wq_idx, ctx->dedicated, ctx->wq_size, ctx->wq_reg,
			ctx->max_batch_size, ctx->max_xfer_size);

	return 0;
}

int alloc_task(struct dsa_context *ctx)
{
	ctx->single_task = __alloc_task();
	if (!ctx->single_task)
		return -ENOMEM;

	dbg("single task allocated, desc %#lx comp %#lx\n",
			ctx->single_task->desc, ctx->single_task->comp);

	return DSA_STATUS_OK;
}

struct task *__alloc_task(void)
{
	struct task *tsk;

	tsk = malloc(sizeof(struct task));
	if (!tsk)
		return NULL;
	memset(tsk, 0, sizeof(struct task));

	tsk->desc = malloc(sizeof(struct dsa_hw_desc));
	if (!tsk->desc) {
		free_task(tsk);
		return NULL;
	}
	memset(tsk->desc, 0, sizeof(struct dsa_hw_desc));

	/* completion record need to be 32bits aligned */
	tsk->comp = aligned_alloc(32, sizeof(struct dsa_completion_record));
	if (!tsk->comp) {
		free_task(tsk);
		return NULL;
	}
	memset(tsk->comp, 0, sizeof(struct dsa_completion_record));

	return tsk;
}

/* this function is re-used by batch task */
int init_task(struct task *tsk, int tflags, int opcode,
		unsigned long xfer_size)
{
	dbg("initilizing single task %#lx\n", tsk);

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	/* allocate memory: src1*/
	switch (opcode) {
	case DSA_OPCODE_MEMMOVE: /* intentionally empty */
	case DSA_OPCODE_COMPARE: /* intentionally empty */
	case DSA_OPCODE_COMPVAL: /* intentionally empty */
	case DSA_OPCODE_DUALCAST:
		tsk->src1 = malloc(xfer_size);
		if (!tsk->src1)
			return -ENOMEM;
		memset_pattern(tsk->src1, tsk->pattern, xfer_size);
	}

	/* allocate memory: src2*/
	switch (opcode) {
	case DSA_OPCODE_COMPARE:
		tsk->src2 = malloc(xfer_size);
		if (!tsk->src2)
			return -ENOMEM;
		memset_pattern(tsk->src2, tsk->pattern, xfer_size);
	}

	/* allocate memory: dst1*/
	switch (opcode) {
	case DSA_OPCODE_MEMMOVE: /* intentionally empty */
	case DSA_OPCODE_MEMFILL: /* intentionally empty */
	case DSA_OPCODE_DUALCAST:
		/* DUALCAST: dst1/dst2 lower 12 bits must be same */
		tsk->dst1 = aligned_alloc(1<<12, xfer_size);
		if (!tsk->dst1)
			return -ENOMEM;
		if (tflags & TEST_FLAGS_PREF)
			memset(tsk->dst1, 0, xfer_size);
	}

	/* allocate memory: dst2*/
	switch (opcode) {
	case DSA_OPCODE_DUALCAST:
		/* DUALCAST: dst1/dst2 lower 12 bits must be same */
		tsk->dst2 = aligned_alloc(1<<12, xfer_size);
		if (!tsk->dst2)
			return -ENOMEM;
		if (tflags & TEST_FLAGS_PREF)
			memset(tsk->dst2, 0, xfer_size);
	}

	dbg("Mem allocated: s1 %#lx s2 %#lx d1 %#lx d2 %#lx\n",
			tsk->src1, tsk->src2, tsk->dst1, tsk->dst2);

	return DSA_STATUS_OK;
}

int alloc_batch_task(struct dsa_context *ctx, unsigned int task_num)
{
	struct batch_task *btsk;

	if (!ctx->is_batch) {
		err("%s is valid only if 'is_batch' is enabled", __func__);
		return -EINVAL;
	}

	ctx->batch_task = malloc(sizeof(struct batch_task));
	if (!ctx->batch_task)
		return -ENOMEM;
	memset(ctx->batch_task, 0, sizeof(struct batch_task));

	btsk = ctx->batch_task;

	btsk->core_task = __alloc_task();
	if (!btsk->core_task)
		return -ENOMEM;

	btsk->sub_tasks = malloc(task_num * sizeof(struct task));
	if (!btsk->sub_tasks)
		return -ENOMEM;
	memset(btsk->sub_tasks, 0, task_num * sizeof(struct task));

	btsk->sub_descs = aligned_alloc(64,
			task_num * sizeof(struct dsa_hw_desc));
	if (!btsk->sub_descs)
		return -ENOMEM;
	memset(btsk->sub_descs, 0, task_num * sizeof(struct dsa_hw_desc));

	btsk->sub_comps = aligned_alloc(32,
			task_num * sizeof(struct dsa_completion_record));
	if (!btsk->sub_comps)
		return -ENOMEM;
	memset(btsk->sub_comps, 0,
			task_num * sizeof(struct dsa_completion_record));

	dbg("batch task allocated %#lx, ctask %#lx, sub_tasks %#lx\n",
			btsk, btsk->core_task, btsk->sub_tasks);
	dbg("sub_descs %#lx, sub_comps %#lx\n",
			btsk->sub_descs, btsk->sub_comps);

	return DSA_STATUS_OK;
}

int init_batch_task(struct batch_task *btsk, int task_num, int tflags,
		int opcode, unsigned long xfer_size, unsigned long dflags)
{
	int i, rc;

	btsk->task_num = task_num;
	btsk->test_flags = tflags;

	for (i = 0; i < task_num; i++) {
		btsk->sub_tasks[i].desc = &(btsk->sub_descs[i]);
		btsk->sub_tasks[i].comp = &(btsk->sub_comps[i]);
		btsk->sub_tasks[i].dflags = dflags;
		rc = init_task(&(btsk->sub_tasks[i]), tflags, opcode,
				xfer_size);
		if (rc != DSA_STATUS_OK) {
			err("batch: init sub-task failed\n");
			return rc;
		}
	}

	return DSA_STATUS_OK;
}

int dsa_enqcmd(struct dsa_context *ctx, struct dsa_hw_desc *hw)
{
	int retry_count = 0;
	int ret = 0;

	while (retry_count < 3) {
		if (!enqcmd(ctx->wq_reg, hw))
			break;

		info("retry\n");
		retry_count++;
	}

	return ret;
}

static inline unsigned long rdtsc(void)
{
	uint32_t a, d;

	asm volatile("rdtsc" : "=a"(a), "=d"(d));
	return ((uint64_t)d << 32) | (uint64_t)a;
}

static inline void umonitor(void *addr)
{
	asm volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xf0" : : "a"(addr));
}

static inline int umwait(unsigned long timeout, unsigned int state)
{
	uint8_t r;
	uint32_t timeout_low = (uint32_t)timeout;
	uint32_t timeout_high = (uint32_t)(timeout >> 32);

	asm volatile(".byte 0xf2, 0x48, 0x0f, 0xae, 0xf1\t\n"
		"setc %0\t\n"
		: "=r"(r)
		: "c"(state), "a"(timeout_low), "d"(timeout_high));
	return r;
}

static int dsa_wait_on_desc_timeout(struct dsa_completion_record *comp,
		unsigned int msec_timeout)
{
	unsigned int j = 0;

	if (!umwait_support) {
		while (j < msec_timeout && comp->status == 0) {
			usleep(1000);
			j++;
		}
	} else {
		unsigned long timeout = (ms_timeout * 1000000) * 3;
		int r = 1;
		unsigned long t = 0;

		timeout += rdtsc();
		while (comp->status == 0) {
			if (!r) {
				t = rdtsc();
				if (t >= timeout) {
					err("umwait timeout %#lx\n", t);
					break;
				}
			}

			umonitor((uint8_t *)comp);
			if (comp->status != 0)
				break;
			r = umwait(timeout, 0);
		}
		if (t >= timeout)
			j = msec_timeout;
	}

	dump_compl_rec(comp);

	return (j == msec_timeout) ? -EAGAIN : 0;
}

/* the pattern is 8 bytes long while the dst can with any length */
void memset_pattern(void *dst, uint64_t pattern, size_t len)
{
	size_t len_8_aligned, len_remainding, mask = 0x7;
	uint64_t *aligned_end, *tmp_64;

	/* 8 bytes aligned part */
	len_8_aligned = len & ~mask;
	aligned_end = (uint64_t *)((uint8_t *)dst + len_8_aligned);
	tmp_64 = (uint64_t *)dst;
	while (tmp_64 < aligned_end) {
		*tmp_64 = pattern;
		tmp_64++;
	}

	/* non-aligned part */
	len_remainding = len & mask;
	memcpy(aligned_end, &pattern, len_remainding);
}

/* return 0 if src is a repeatation of pattern, -1 otherwise */
/* the pattern is 8 bytes long and the src could be with any length */
int memcmp_pattern(const void *src, const uint64_t pattern, size_t len)
{
	size_t len_8_aligned, len_remainding, mask = 0x7;
	uint64_t *aligned_end, *tmp_64;

	/* 8 bytes aligned part */
	len_8_aligned = len & ~mask;
	aligned_end = (void *)((uint8_t *)src + len_8_aligned);
	tmp_64 = (uint64_t *)src;
	while (tmp_64 < aligned_end) {
		if (*tmp_64 != pattern)
			return -1;
		tmp_64++;
	}

	/* non-aligned part */
	len_remainding = len & mask;
	if (memcmp(aligned_end, &pattern, len_remainding))
		return -1;

	return 0;
}

void dsa_free(struct dsa_context *ctx)
{
	if (munmap(ctx->wq_reg, 0x1000))
		err("munmap failed %d\n", errno);

	close(ctx->fd);

	accfg_unref(ctx->ctx);
	dsa_free_task(ctx);
	free(ctx);
}

void dsa_free_task(struct dsa_context *ctx)
{
	if (!ctx->is_batch)
		free_task(ctx->single_task);
	else
		free_batch_task(ctx->batch_task);
}

void free_task(struct task *tsk)
{
	__clean_task(tsk);
	free(tsk);
}

/* The components of task is free but not the struct task itself */
/* This function is re-used by free_batch_task() */
void __clean_task(struct task *tsk)
{
	if (!tsk)
		return;

	free(tsk->desc);
	free(tsk->comp);
	free(tsk->src1);
	free(tsk->src2);
	free(tsk->dst1);
	free(tsk->dst2);
}

void free_batch_task(struct batch_task *btsk)
{
	int i;

	if (!btsk)
		return;

	free_task(btsk->core_task);

	for (i = 0; i < btsk->task_num; i++) {
		/* pointing to part of the 'btsk->sub_descs/comps', need to */
		/* free the buffer as a whole out of the loop. Set to NULL */
		/* to avoid being free in __clean_task()*/
		btsk->sub_tasks[i].desc = NULL;
		btsk->sub_tasks[i].comp = NULL;
		/* sub_tasks is an array "btsk->sub_tasks", we don't free */
		/* btsk->sub_tasks[i] itself here */
		__clean_task(&(btsk->sub_tasks[i]));
	}

	free(btsk->sub_tasks);
	free(btsk->sub_descs);
	free(btsk->sub_comps);
	free(btsk);
}

int dsa_wait_noop(struct dsa_context *ctx)
{
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("noop desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	return DSA_STATUS_OK;
}

int dsa_noop(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;

	dsa_prep_noop(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_noop(ctx);

	return ret;
}

int dsa_wait_batch(struct dsa_context *ctx)
{
	int rc;

	struct batch_task *btsk = ctx->batch_task;
	struct task *ctsk = btsk->core_task;

	info("wait batch\n");

	rc = dsa_wait_on_desc_timeout(ctsk->comp, ms_timeout);
	if (rc < 0) {
		err("batch desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	dump_sub_compl_rec(btsk);
	return DSA_STATUS_OK;
}

int dsa_wait_memcpy(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("memcpy desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_memcpy(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_memcpy(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_memcpy(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_memcpy(ctx);

	return ret;
}

int dsa_wait_memfill(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);

	if (rc < 0) {
		err("memfill desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_memfill(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_memfill(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_memfill(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_memfill(ctx);

	return ret;
}

int dsa_wait_compare(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);

	if (rc < 0) {
		err("compare desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_compare(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_compare(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_compare(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_compare(ctx);

	return ret;
}

int dsa_wait_compval(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);

	if (rc < 0) {
		err("compval desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_compval(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_compval(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_compval(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_compval(ctx);

	return ret;
}

int dsa_wait_dualcast(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("dualcast desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_dualcast(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_dualcast(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_dualcast(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_dualcast(ctx);

	return ret;
}

/* mismatch_expected: expect mismatched buffer with success status 0x1 */
int task_result_verify(struct task *tsk, int mismatch_expected)
{
	int rc;

	info("verifying task result for %#lx\n", tsk);

	if (tsk->comp->status != DSA_COMP_SUCCESS)
		return tsk->comp->status;

	switch (tsk->opcode) {
	case DSA_OPCODE_MEMMOVE:
		rc = task_result_verify_memcpy(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_MEMFILL:
		rc = task_result_verify_memfill(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_COMPARE:
		rc = task_result_verify_compare(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_COMPVAL:
		rc = task_result_verify_compval(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_DUALCAST:
		rc = task_result_verify_dualcast(tsk, mismatch_expected);
		return rc;
	}

	info("test with op %d passed\n", tsk->opcode);

	return DSA_STATUS_OK;
}

int task_result_verify_memcpy(struct task *tsk, int mismatch_expected)
{
	int rc;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	rc = memcmp(tsk->src1, tsk->dst1, tsk->xfer_size);
	if (rc) {
		err("memcpy mismatch, memcmp rc %d\n", rc);
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

int task_result_verify_memfill(struct task *tsk, int mismatch_expected)
{
	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	if (memcmp_pattern(tsk->dst1, tsk->pattern, tsk->xfer_size)) {
		err("memfill test failed\n");
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

int task_result_verify_compare(struct task *tsk, int mismatch_expected)
{
	if (!mismatch_expected) {
		if (tsk->comp->result) {
			err("compval failed at %#x\n",
					tsk->comp->bytes_completed);
			return -ENXIO;
		}
		return DSA_STATUS_OK;
	}

	/* mismatch_expected */
	if (tsk->comp->result) {
		info("expected mismatch at index %#x\n",
				tsk->comp->bytes_completed);
		return DSA_STATUS_OK;
	}

	err("DSA wrongly says matching buffers\n");
	return -ENXIO;
}

int task_result_verify_compval(struct task *tsk, int mismatch_expected)
{
	if (!mismatch_expected) {
		if (tsk->comp->result) {
			err("compval failed at %#x\n",
					tsk->comp->bytes_completed);
			return -ENXIO;
		}
		return DSA_STATUS_OK;
	}

	/* mismatch_expected */
	if (tsk->comp->result) {
		info("expected mismatch at index %#x\n",
				tsk->comp->bytes_completed);
		return DSA_STATUS_OK;
	}

	err("DSA wrongly says matching buffers\n");
	return -ENXIO;
}

int task_result_verify_dualcast(struct task *tsk, int mismatch_expected)
{
	int rc;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	rc = memcmp(tsk->src1, tsk->dst1, tsk->xfer_size);
	if (rc) {
		err("ducalcast mismatch dst1, memcmp rc %d\n", rc);
		return -ENXIO;
	}

	rc = memcmp(tsk->src1, tsk->dst2, tsk->xfer_size);
	if (rc) {
		err("ducalcast mismatch dst2, memcmp rc %d\n", rc);
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

int batch_result_verify(struct batch_task *btsk, int bof)
{
	uint8_t core_stat, sub_stat;
	int i, rc;
	struct task *tsk;

	core_stat = stat_val(btsk->core_task->comp->status);
	if (core_stat == DSA_COMP_SUCCESS)
		info("core task success, chekcing sub-tasks\n");
	else if (!bof && core_stat == DSA_COMP_BATCH_FAIL)
		info("partial complete with NBOF, checking sub-tasks\n");
	else {
		err("batch core task failed with status %d\n", core_stat);
		return DSA_STATUS_FAIL;
	}

	for (i = 0; i < btsk->task_num; i++) {
		tsk = &(btsk->sub_tasks[i]);
		sub_stat = stat_val(tsk->comp->status);

		if (!bof && sub_stat == DSA_COMP_PAGE_FAULT_NOBOF)
			dbg("PF in sub-task[%d], consider as passed\n", i);
		else if (sub_stat == DSA_COMP_SUCCESS) {
			rc = task_result_verify(tsk, 0);
			if (rc != DSA_STATUS_OK) {
				err("Sub-task[%d] failed with rc=%d", i, rc);
				return rc;
			}
		} else {
			err("Sub-task[%d] failed with stat=%d", i, sub_stat);
			return DSA_STATUS_FAIL;
		}
	}

	return DSA_STATUS_OK;
}
