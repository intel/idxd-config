// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "accel_test.h"

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

int get_random_value(void)
{
	static int extra_seed;

	srand(time(NULL) + (extra_seed++));
	return rand();
}

struct acctest_context *acctest_init(int tflags)
{
	struct acctest_context *dctx;
	unsigned int unused[2];
	unsigned int leaf, waitpkg;
	int rc;
	struct accfg_ctx *ctx;

	/* detect umwait support */
	leaf = 7;
	waitpkg = 0;
	cpuid(&leaf, unused, &waitpkg, unused + 1);
	if (waitpkg & 0x20) {
		dbg("umwait supported\n");
		umwait_support = 1;
	}

	dctx = malloc(sizeof(struct acctest_context));
	if (!dctx)
		return NULL;
	memset(dctx, 0, sizeof(struct acctest_context));

	rc = accfg_new(&ctx);
	if (rc < 0) {
		free(dctx);
		return NULL;
	}

	dctx->ctx = ctx;
	return dctx;
}

static int acctest_setup_wq(struct acctest_context *ctx, struct accfg_wq *wq)
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

	ctx->wq_reg = mmap(NULL, PAGE_SIZE, PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, ctx->fd, 0);
	if (ctx->wq_reg == MAP_FAILED) {
		perror("mmap");
		return -errno;
	}

	return 0;
}

static struct accfg_wq *acctest_get_wq(struct acctest_context *ctx,
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

			/* Make sure iaa_test will not use dsa wq, vice versa*/
			if (accfg_device_get_type(device) != ctx->dev_type)
				continue;

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
			if ((mode == ACCFG_WQ_SHARED && !shared) ||
			    (mode == ACCFG_WQ_DEDICATED && shared))
				continue;

			rc = acctest_setup_wq(ctx, wq);
			if (rc < 0)
				return NULL;

			return wq;
		}
	}

	return NULL;
}

static struct accfg_wq *acctest_get_wq_byid(struct acctest_context *ctx,
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
		    dev_id != ACCTEST_DEVICE_ID_NO_INPUT)
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

			rc = acctest_setup_wq(ctx, wq);
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

int acctest_alloc(struct acctest_context *ctx, int shared, int dev_id, int wq_id)
{
	struct accfg_device *dev;

	/* Is wq already allocated? */
	if (ctx->wq_reg)
		return 0;

	if (wq_id != ACCTEST_DEVICE_ID_NO_INPUT)
		ctx->wq = acctest_get_wq_byid(ctx, dev_id, wq_id);
	else
		ctx->wq = acctest_get_wq(ctx, dev_id, shared);

	if (!ctx->wq) {
		err("No usable wq found\n");
		return -ENODEV;
	}
	dev = accfg_wq_get_device(ctx->wq);
	ctx->dedicated = accfg_wq_get_mode(ctx->wq);
	ctx->wq_size = accfg_wq_get_size(ctx->wq);
	ctx->threshold = accfg_wq_get_threshold(ctx->wq);
	ctx->wq_idx = accfg_wq_get_id(ctx->wq);
	ctx->bof = accfg_wq_get_block_on_fault(ctx->wq);
	ctx->wq_max_batch_size = accfg_wq_get_max_batch_size(ctx->wq);
	ctx->wq_max_xfer_size = accfg_wq_get_max_transfer_size(ctx->wq);
	ctx->ats_disable = accfg_wq_get_ats_disable(ctx->wq);

	ctx->max_batch_size = accfg_device_get_max_batch_size(dev);
	ctx->max_xfer_size = accfg_device_get_max_transfer_size(dev);
	ctx->max_xfer_bits = bsr(ctx->max_xfer_size);
	ctx->compl_size = accfg_device_get_compl_size(dev);

	info("alloc wq %d %s size %d addr %p batch sz %#x xfer sz %#x\n",
	     ctx->wq_idx, (ctx->dedicated == ACCFG_WQ_SHARED) ? "shared" : "dedicated",
	     ctx->wq_size, ctx->wq_reg, ctx->max_batch_size, ctx->max_xfer_size);

	return 0;
}

int acctest_alloc_multiple_tasks(struct acctest_context *ctx, int num_itr)
{
	struct task_node *tmp_tsk_node;
	int cnt = 0;

	while (cnt < num_itr) {
		tmp_tsk_node = ctx->multi_task_node;
		ctx->multi_task_node = (struct task_node *)malloc(sizeof(struct task_node));
		if (!ctx->multi_task_node)
			return -ENOMEM;

		ctx->multi_task_node->tsk = acctest_alloc_task(ctx);
		if (!ctx->multi_task_node->tsk)
			return -ENOMEM;
		ctx->multi_task_node->next = tmp_tsk_node;
		cnt++;
	}
	return ACCTEST_STATUS_OK;
}

struct task *acctest_alloc_task(struct acctest_context *ctx)
{
	struct task *tsk;

	tsk = malloc(sizeof(struct task));
	if (!tsk)
		return NULL;
	memset(tsk, 0, sizeof(struct task));

	tsk->desc = malloc(sizeof(struct hw_desc));
	if (!tsk->desc) {
		free_task(tsk);
		return NULL;
	}
	memset(tsk->desc, 0, sizeof(struct hw_desc));

	/* page fault test, alloc 4k size */
	if (ctx->is_evl_test)
		tsk->comp = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
	else
		tsk->comp = aligned_alloc(ctx->compl_size, sizeof(struct completion_record));
	if (!tsk->comp) {
		free(tsk->desc);
		free_task(tsk);
		return NULL;
	}
	memset(tsk->comp, 0, sizeof(struct completion_record));

	return tsk;
}

static int acctest_enqcmd(struct acctest_context *ctx, struct hw_desc *hw)
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

int acctest_wait_on_desc_timeout(struct completion_record *comp,
				 struct acctest_context *ctx,
				 unsigned int msec_timeout)
{
	unsigned int j = 0;

	if (!umwait_support) {
		while (j < msec_timeout && comp->status == 0) {
			usleep(1000);
			j++;
		}
	} else {
		unsigned long timeout = (msec_timeout * 1000000UL) * 3;
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

	dump_compl_rec(comp, ctx->compl_size);

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

void acctest_free(struct acctest_context *ctx)
{
	if (munmap(ctx->wq_reg, PAGE_SIZE))
		err("munmap failed %d\n", errno);

	close(ctx->fd);

	accfg_unref(ctx->ctx);
	acctest_free_task(ctx);
	free(ctx);
}

void acctest_free_task(struct acctest_context *ctx)
{
	if (!ctx->is_batch) {
		struct task_node *tsk_node = NULL, *tmp_node = NULL;

		tsk_node = ctx->multi_task_node;
		while (tsk_node) {
			tmp_node = tsk_node->next;
			free_task(tsk_node->tsk);
			tsk_node->tsk = NULL;
			free(tsk_node);
			tsk_node = tmp_node;
		}
		ctx->multi_task_node = NULL;
	} else {
		struct btask_node *tsk_node = NULL, *tmp_node = NULL;

		tsk_node = ctx->multi_btask_node;
		while (tsk_node) {
			tmp_node = tsk_node->next;
			free_batch_task(tsk_node->btsk);
			tsk_node->btsk = NULL;
			free(tsk_node);
			tsk_node = tmp_node;
		}
		ctx->multi_task_node = NULL;
	}
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
	mprotect(tsk->src1, PAGE_SIZE, PROT_READ | PROT_WRITE);
	free(tsk->src1);
	free(tsk->src2);
	free(tsk->dst1);
	free(tsk->dst2);
	free(tsk->input);
	free(tsk->output);
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
		__clean_task(&btsk->sub_tasks[i]);
	}

	free(btsk->sub_tasks);
	if (btsk->edl) {
		munmap(btsk->sub_descs, PAGE_ALIGN(btsk->task_num * sizeof(struct hw_desc)));
		munmap(btsk->sub_comps, btsk->task_num * PAGE_SIZE);
	} else {
		free(btsk->sub_descs);
		free(btsk->sub_comps);
	}
	free(btsk);
}

void acctest_prep_desc_common(struct hw_desc *hw, char opcode,
			      uint64_t dest, uint64_t src, size_t len, unsigned long dflags)
{
	hw->flags = dflags;
	hw->opcode = opcode;
	hw->src_addr = src;
	hw->dst_addr = dest;
	hw->xfer_size = len;
}

void acctest_desc_submit(struct acctest_context *ctx, struct hw_desc *hw)
{
	dump_desc(hw);

	/* use MOVDIR64B for DWQ */
	if (ctx->dedicated)
		movdir64b(ctx->wq_reg, hw);
	else /* use ENQCMD for SWQ */
		if (acctest_enqcmd(ctx, hw))
			usleep(10000);
}
