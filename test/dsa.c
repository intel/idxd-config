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
#include "dsa_crc32.h"

#define DSA_COMPL_RING_SIZE 64

unsigned int ms_timeout = 5000;
int debug_logging;
static int umwait_support;

unsigned int dif_blk_arr[] = {512, 520, 4096, 4104};

int get_dif_blksz_flg(unsigned long xfer_size)
{
	int blk_idx_flg = 3;

	while (blk_idx_flg) {
		if (xfer_size % dif_blk_arr[blk_idx_flg] == 0)
			break;
		blk_idx_flg--;
	}
	return blk_idx_flg;
}

unsigned long get_blks(unsigned long xfer_size)
{
	int blk_idx_flg = 3;
	unsigned long num_blks;

	while (blk_idx_flg) {
		if (xfer_size % dif_blk_arr[blk_idx_flg] == 0)
			break;
		blk_idx_flg--;
	}

	num_blks = xfer_size / dif_blk_arr[blk_idx_flg];
	return num_blks;
}

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

struct dsa_context *dsa_init(int tflags)
{
	struct dsa_context *dctx;
	unsigned int unused[2];
	unsigned int leaf, waitpkg;
	int rc;
	struct accfg_ctx *ctx;

	/* detect umwait support */
	leaf = 7;
	waitpkg = 0;
	cpuid(&leaf, unused, &waitpkg, unused + 1);
	if ((waitpkg & 0x20) && !(tflags & TEST_FLAGS_NO_UMWAIT)) {
		dbg("umwait supported\n");
		umwait_support = 1;
	} else {
		dbg("no umwait, active poll\n");
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
			if ((mode == ACCFG_WQ_SHARED && !shared) ||
			    (mode == ACCFG_WQ_DEDICATED && shared))
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
	ctx->threshold = accfg_wq_get_threshold(ctx->wq);
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

int alloc_multiple_tasks(struct dsa_context *ctx, int num_itr)
{
	struct task_node *tmp_tsk_node;
	int cnt = 0;

	while (cnt < num_itr) {
		tmp_tsk_node = ctx->multi_task_node;
		ctx->multi_task_node = (struct task_node *)malloc(sizeof(struct task_node));
		if (!ctx->multi_task_node)
			return -ENOMEM;

		ctx->multi_task_node->tsk = __alloc_task();
		if (!ctx->multi_task_node->tsk)
			return -ENOMEM;
		ctx->multi_task_node->next = tmp_tsk_node;
		cnt++;
	}
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

int init_memcpy(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;

	tsk->pattern = 0x0123456789abcdef;
	tsk->pattern2 = 0xfedcba9876543210;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->src1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, xfer_size);

	tsk->dst1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, tsk->pattern2, xfer_size);

	return DSA_STATUS_OK;
}

int init_memfill(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;

	tsk->pattern = 0x0123456789abcdef;
	tsk->pattern2 = 0xfedcba9876543210;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->dst1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->dst1)
		return -ENOMEM;
	memset(tsk->dst1, tsk->pattern2, xfer_size);

	return DSA_STATUS_OK;
}

int init_compare(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->src1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, xfer_size);

	tsk->src2 = aligned_alloc(force_align, xfer_size);
	if (!tsk->src2)
		return -ENOMEM;
	memset_pattern(tsk->src2, tsk->pattern, xfer_size);

	return DSA_STATUS_OK;
}

int init_compval(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->src1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, xfer_size);

	return DSA_STATUS_OK;
}

int init_dualcast(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;

	tsk->pattern = 0x0123456789abcdef;
	tsk->pattern2 = 0xfedcba9876543210;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->src1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, xfer_size);

	tsk->dst1 = aligned_alloc(1 << 12, xfer_size);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, tsk->pattern2, xfer_size);

	tsk->dst2 = aligned_alloc(1 << 12, xfer_size);
	if (!tsk->dst2)
		return -ENOMEM;
	memset_pattern(tsk->dst2, tsk->pattern2, xfer_size);

	return DSA_STATUS_OK;
}

int init_cr_delta(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;
	unsigned long delta_size;

	tsk->pattern = 0x1234;
	tsk->pattern2 = 0x1233;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->src1 = aligned_alloc(force_align, tsk->xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, tsk->xfer_size);

	tsk->src2 = aligned_alloc(force_align, tsk->xfer_size);
	if (!tsk->src2)
		return -ENOMEM;
	memset_pattern(tsk->src2, tsk->pattern2, tsk->xfer_size);
	delta_size = 2 * xfer_size;

	tsk->delta1 = aligned_alloc(force_align, delta_size);
	if (!tsk->delta1)
		return -ENOMEM;

	if (opcode == DSA_OPCODE_AP_DELTA) {
		tsk->dst1 = aligned_alloc(force_align, tsk->xfer_size);
		if (!tsk->dst1)
			return -ENOMEM;
	}

	return DSA_STATUS_OK;
}

int init_crcgen(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->src1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, xfer_size);
	tsk->crc_seed = 0x12345678;
	if (tsk->test_flags & (unsigned int)(READ_CRC_SEED)) {
		tsk->crc_seed_addr = aligned_alloc(ADDR_ALIGNMENT, sizeof(tsk->crc_seed));
		*tsk->crc_seed_addr = tsk->crc_seed;
		tsk->crc_seed = 0x0;
	}

	return DSA_STATUS_OK;
}

int init_copy_crc(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;

	tsk->pattern = 0x0123456789abcdef;
	tsk->pattern2 = 0xfedcba9876543210;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->src1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, xfer_size);

	tsk->dst1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, tsk->pattern2, xfer_size);

	tsk->crc_seed = 0x12345678;
	if (tsk->test_flags & (unsigned int)(READ_CRC_SEED)) {
		tsk->crc_seed_addr = aligned_alloc(ADDR_ALIGNMENT, sizeof(tsk->crc_seed));
		*tsk->crc_seed_addr = tsk->crc_seed;
		tsk->crc_seed = 0x0;
	}

	return DSA_STATUS_OK;
}

int init_dif_check(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long buf_size;
	unsigned long force_align = ADDR_ALIGNMENT;
	unsigned char *src;
	unsigned int dif_reftag;
	unsigned int dif_apptag;
	unsigned int dif_guardtag;
	unsigned long blks = 0;
	unsigned long i;
	unsigned long dif_size;

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->apptag = 0xFACE;
	tsk->reftag = 0xABBA;

	tsk->blk_idx_flg = get_dif_blksz_flg(tsk->xfer_size);
	blks = tsk->xfer_size / dif_blk_arr[tsk->blk_idx_flg];
	tsk->blks = blks;

	buf_size = tsk->xfer_size / blks;
	/* 8 bytes for inclusion of tags */
	tsk->xfer_size += 8 * blks;
	tsk->src1 = aligned_alloc(force_align, tsk->xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	src = (unsigned char *)tsk->src1;
	dif_reftag = tsk->reftag;
	dif_apptag = tsk->apptag;

	for (i = 1; i <= blks; i++) {
		dif_size = (buf_size + 8) * (i - 1);
		memset_pattern((src + dif_size), tsk->pattern, buf_size);
		dif_guardtag = dsa_calculate_crc_t10dif((src + dif_size), buf_size, 0);
		src[buf_size + DIF_BLK_GRD_1 + dif_size] = (dif_guardtag >> 8) & 0xFF;
		src[buf_size + DIF_BLK_GRD_2 + dif_size] = dif_guardtag & 0xFF;
		src[buf_size + DIF_APP_TAG_1 + dif_size] = (dif_apptag >> 8) & 0xFF;
		src[buf_size + DIF_APP_TAG_2 + dif_size] = (dif_apptag) & 0xFF;
		src[buf_size + DIF_REF_TAG_1 + dif_size] = (dif_reftag >> 24) & 0xFF;
		src[buf_size + DIF_REF_TAG_2 + dif_size] = (dif_reftag >> 16) & 0xFF;
		src[buf_size + DIF_REF_TAG_3 + dif_size] = (dif_reftag >> 8) & 0xFF;
		src[buf_size + DIF_REF_TAG_4 + dif_size] = dif_reftag & 0xFF;
		dif_reftag++;
	}

	return DSA_STATUS_OK;
}

int init_dif_ins(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;
	unsigned long blks = 0;

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->apptag = 0xFACE;
	tsk->reftag = 0xABBA;
	tsk->blk_idx_flg = get_dif_blksz_flg(tsk->xfer_size);
	blks = tsk->xfer_size / dif_blk_arr[tsk->blk_idx_flg];
	tsk->blks = blks;

	tsk->src1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->src1)
		return -ENOMEM;
	memset_pattern(tsk->src1, tsk->pattern, xfer_size);
	blks = get_blks(xfer_size);
	xfer_size += 8 * blks;
	tsk->dst1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->dst1)
		return -ENOMEM;

	return DSA_STATUS_OK;
}

int init_dif_strp(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long buf_size;
	unsigned long force_align = ADDR_ALIGNMENT;
	unsigned char *src;
	unsigned int dif_reftag;
	unsigned int dif_apptag;
	unsigned int dif_guardtag;
	unsigned long blks = 0;
	unsigned long i;
	unsigned long dif_size;

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->apptag = 0xFACE;
	tsk->reftag = 0xABBA;

	tsk->blk_idx_flg = get_dif_blksz_flg(tsk->xfer_size);
	blks = tsk->xfer_size / dif_blk_arr[tsk->blk_idx_flg];
	tsk->blks = blks;
	buf_size = tsk->xfer_size / blks;
	/* 8 bytes for inclusion of tags */
	tsk->xfer_size += 8 * blks;
	tsk->src1 = aligned_alloc(force_align, tsk->xfer_size);
	if (!tsk->src1)
		return -ENOMEM;

	src = (unsigned char *)tsk->src1;
	dif_reftag = tsk->reftag;
	dif_apptag = tsk->apptag;

	for (i = 1; i <= blks; i++) {
		dif_size = (buf_size + 8) * (i - 1);
		memset_pattern((src + dif_size), tsk->pattern, buf_size);
		dif_guardtag = dsa_calculate_crc_t10dif((src + dif_size), buf_size, 0);
		src[buf_size + DIF_BLK_GRD_1 + dif_size] = (dif_guardtag >> 8) & 0xFF;
		src[buf_size + DIF_BLK_GRD_2 + dif_size] = dif_guardtag & 0xFF;
		src[buf_size + DIF_APP_TAG_1 + dif_size] = (dif_apptag >> 8) & 0xFF;
		src[buf_size + DIF_APP_TAG_2 + dif_size] = (dif_apptag) & 0xFF;
		src[buf_size + DIF_REF_TAG_1 + dif_size] = (dif_reftag >> 24) & 0xFF;
		src[buf_size + DIF_REF_TAG_2 + dif_size] = (dif_reftag >> 16) & 0xFF;
		src[buf_size + DIF_REF_TAG_3 + dif_size] = (dif_reftag >> 8) & 0xFF;
		src[buf_size + DIF_REF_TAG_4 + dif_size] = dif_reftag & 0xFF;
		dif_reftag++;
	}

	tsk->dst1 = aligned_alloc(force_align, tsk->xfer_size - 8 * blks);
	if (!tsk->dst1)
		return -ENOMEM;

	return DSA_STATUS_OK;
}

int init_dif_updt(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long buf_size;
	unsigned long force_align = ADDR_ALIGNMENT;
	unsigned char *src;
	unsigned int dif_reftag;
	unsigned int dif_apptag;
	unsigned int dif_guardtag;
	unsigned long blks = 0;
	unsigned long i;
	unsigned long dif_size;

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->apptag = 0xFACE;
	tsk->reftag = 0xABBA;

	tsk->blk_idx_flg = get_dif_blksz_flg(tsk->xfer_size);
	blks = tsk->xfer_size / dif_blk_arr[tsk->blk_idx_flg];
	tsk->blks = blks;
	buf_size = tsk->xfer_size / blks;
	tsk->xfer_size += 8 * blks;
	tsk->src1 = aligned_alloc(force_align, tsk->xfer_size);
	if (!tsk->src1)
		return -ENOMEM;

	src = (unsigned char *)tsk->src1;
	dif_reftag = tsk->reftag;
	dif_apptag = tsk->apptag;

	for (i = 1; i <= blks; i++) {
		dif_size = (buf_size + 8) * (i - 1);
		memset_pattern((src + dif_size), tsk->pattern, buf_size);
		dif_guardtag = dsa_calculate_crc_t10dif((src + dif_size), buf_size, 0);
		src[buf_size + DIF_BLK_GRD_1 + dif_size] = (dif_guardtag >> 8) & 0xFF;
		src[buf_size + DIF_BLK_GRD_2 + dif_size] = dif_guardtag & 0xFF;
		src[buf_size + DIF_APP_TAG_1 + dif_size] = (dif_apptag >> 8) & 0xFF;
		src[buf_size + DIF_APP_TAG_2 + dif_size] = (dif_apptag) & 0xFF;
		src[buf_size + DIF_REF_TAG_1 + dif_size] = (dif_reftag >> 24) & 0xFF;
		src[buf_size + DIF_REF_TAG_2 + dif_size] = (dif_reftag >> 16) & 0xFF;
		src[buf_size + DIF_REF_TAG_3 + dif_size] = (dif_reftag >> 8) & 0xFF;
		src[buf_size + DIF_REF_TAG_4 + dif_size] = dif_reftag & 0xFF;
	}
	tsk->dst1 = aligned_alloc(force_align, tsk->xfer_size);
	if (!tsk->dst1)
		return -ENOMEM;

	return DSA_STATUS_OK;
}

int init_cflush(struct task *tsk, int tflags, int opcode, unsigned long xfer_size)
{
	unsigned long force_align = ADDR_ALIGNMENT;

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	tsk->dst1 = aligned_alloc(force_align, xfer_size);
	if (!tsk->dst1)
		return -ENOMEM;
	memset_pattern(tsk->dst1, tsk->pattern, xfer_size);

	return DSA_STATUS_OK;
}

/* this function is re-used by batch task */
int init_task(struct task *tsk, int tflags, int opcode,
	      unsigned long xfer_size)
{
	int rc = 0;

	dbg("initilizing task %#lx\n", tsk);

	switch (opcode) {
	/* After memory move, do drain opcode test */
	case DSA_OPCODE_DRAIN:
	case DSA_OPCODE_MEMMOVE:
		rc = init_memcpy(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_MEMFILL:
		rc = init_memfill(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_COMPARE:
		rc = init_compare(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_COMPVAL:
		rc = init_compval(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_DUALCAST:
		rc = init_dualcast(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_AP_DELTA:
	case DSA_OPCODE_CR_DELTA:
		rc = init_cr_delta(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_CRCGEN:
		rc = init_crcgen(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_COPY_CRC:
		rc = init_copy_crc(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_DIF_CHECK:
		rc = init_dif_check(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_DIF_INS:
		rc = init_dif_ins(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_DIF_STRP:
		rc = init_dif_strp(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_DIF_UPDT:
		rc = init_dif_updt(tsk, tflags, opcode, xfer_size);
		break;

	case DSA_OPCODE_CFLUSH:
		rc = init_cflush(tsk, tflags, opcode, xfer_size);
		break;
	}

	if (rc != DSA_STATUS_OK) {
		err("init: opcode %d data failed\n", opcode);
		return rc;
	}

	dbg("Mem allocated: s1 %#lx s2 %#lx d1 %#lx d2 %#lx\n",
	    tsk->src1, tsk->src2, tsk->dst1, tsk->dst2);

	return DSA_STATUS_OK;
}

int alloc_batch_task(struct dsa_context *ctx, unsigned int task_num, int num_itr)
{
	struct btask_node *btsk_node;
	struct batch_task *btsk;
	int cnt = 0;

	if (!ctx->is_batch) {
		err("%s is valid only if 'is_batch' is enabled", __func__);
		return -EINVAL;
	}

	while (cnt < num_itr) {
		btsk_node = ctx->multi_btask_node;

		ctx->multi_btask_node = (struct btask_node *)
			malloc(sizeof(struct btask_node));
		if (!ctx->multi_btask_node)
			return -ENOMEM;

		ctx->multi_btask_node->btsk = malloc(sizeof(struct batch_task));
		if (!ctx->multi_btask_node->btsk)
			return -ENOMEM;
		memset(ctx->multi_btask_node->btsk, 0, sizeof(struct batch_task));

		btsk = ctx->multi_btask_node->btsk;

		btsk->core_task = __alloc_task();
		if (!btsk->core_task)
			return -ENOMEM;

		btsk->sub_tasks = malloc(task_num * sizeof(struct task));
		if (!btsk->sub_tasks)
			return -ENOMEM;
		memset(btsk->sub_tasks, 0, task_num * sizeof(struct task));

		btsk->sub_descs = aligned_alloc(64, task_num * sizeof(struct dsa_hw_desc));
		if (!btsk->sub_descs)
			return -ENOMEM;
		memset(btsk->sub_descs, 0, task_num * sizeof(struct dsa_hw_desc));

		btsk->sub_comps =
			aligned_alloc(32, task_num * sizeof(struct dsa_completion_record));
		if (!btsk->sub_comps)
			return -ENOMEM;
		memset(btsk->sub_comps, 0,
		       task_num * sizeof(struct dsa_completion_record));

		dbg("batch task allocated %#lx, ctask %#lx, sub_tasks %#lx\n",
		    btsk, btsk->core_task, btsk->sub_tasks);
		dbg("sub_descs %#lx, sub_comps %#lx\n",
		    btsk->sub_descs, btsk->sub_comps);
		ctx->multi_btask_node->next = btsk_node;
		cnt++;
	}

	return DSA_STATUS_OK;
}

int init_batch_task(struct batch_task *btsk, int task_num, int tflags,
		    int opcode, unsigned long xfer_size, unsigned long dflags)
{
	int i, rc;

	btsk->task_num = task_num;
	btsk->test_flags = tflags;

	for (i = 0; i < task_num; i++) {
		btsk->sub_tasks[i].desc = &btsk->sub_descs[i];
		btsk->sub_tasks[i].comp = &btsk->sub_comps[i];
		btsk->sub_tasks[i].dflags = dflags;
		rc = init_task(&btsk->sub_tasks[i], tflags, opcode, xfer_size);
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
		__clean_task(&btsk->sub_tasks[i]);
	}

	free(btsk->sub_tasks);
	free(btsk->sub_descs);
	free(btsk->sub_comps);
	free(btsk);
}

int dsa_wait_noop(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_completion_record *comp = tsk->comp;
	int rc;

	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("noop desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	return DSA_STATUS_OK;
}

int dsa_noop_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;

		dsa_prep_noop(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}
	tsk_node = ctx->multi_task_node;
	info("Submitted all noop jobs\n");

	while (tsk_node) {
		ret = dsa_wait_noop(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}
	return ret;
}

int dsa_wait_batch(struct batch_task *btsk)
{
	int rc;

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

int dsa_wait_drain(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_completion_record *comp = tsk->comp;
	int rc;

	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("drain desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	return DSA_STATUS_OK;
}

int dsa_drain_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		/* Block on fault is reserved for Drain */
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;

		dsa_prep_drain(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}
	tsk_node = ctx->multi_task_node;
	info("Submitted all drain jobs\n");

	while (tsk_node) {
		ret = dsa_wait_drain(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}
	return ret;
}

int dsa_wait_memcpy(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
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
		dsa_reprep_memcpy(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_memcpy_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_memcpy(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all memcpy jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_memcpy(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_memfill(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
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
		dsa_reprep_memfill(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_memfill_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_memfill(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all memcpy jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_memfill(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_compare(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
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
		dsa_reprep_compare(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_compare_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_compare(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all memcpy jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_compare(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_compval(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
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
		dsa_reprep_compval(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_compval_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_compval(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all memcpy jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_compval(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_dualcast(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
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
		dsa_reprep_dualcast(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_dualcast_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_dualcast(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all memcpy jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_dualcast(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_cr_delta(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
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
		dsa_reprep_cr_delta(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_cr_delta_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_cr_delta(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all cr delta jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_cr_delta(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_ap_delta(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
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
		dsa_reprep_ap_delta(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_ap_delta_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_ap_delta(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all ap delta jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_ap_delta(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_crcgen(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("CRC desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
	    !(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_crcgen(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_crcgen_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_crcgen(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all crcgen jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_crcgen(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_crc_copy(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("CRC copy desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
	    !(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_crc_copy(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_crc_copy_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_crc_copy(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	info("Submitted all crcgen jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_crc_copy(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_wait_dif(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("DIF desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
	    !(desc->flags & IDXD_OP_FLAG_BOF)) {
		task_result_verify(tsk, 0);
		dsa_reprep_dif(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_dif_check_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_dif_check(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	info("Submitted all dif check jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_dif(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n", tsk_node->tsk->desc,
			     tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}
	return ret;
}

int dsa_dif_ins_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_dif_insert(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}
	tsk_node = ctx->multi_task_node;
	info("Submitted all dif insert jobs\n");
	while (tsk_node) {
		ret = dsa_wait_dif(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n", tsk_node->tsk->desc,
			     tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}
	return ret;
}

int dsa_dif_strp_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_dif_strip(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}

	info("Submitted all dif strp jobs\n");
	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		ret = dsa_wait_dif(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n", tsk_node->tsk->desc,
			     tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}

	return ret;
}

int dsa_dif_updt_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_dif_update(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}
	tsk_node = ctx->multi_task_node;

	info("Submitted all dif update jobs\n");
	while (tsk_node) {
		ret = dsa_wait_dif(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n", tsk_node->tsk->desc,
			     tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}
	return ret;
}

int dsa_wait_cflush(struct dsa_context *ctx, struct task *tsk)
{
	struct dsa_hw_desc *desc = tsk->desc;
	struct dsa_completion_record *comp = tsk->comp;

	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("cflush desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
	    !(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_cflush(ctx, tsk);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_cflush_multi_task_nodes(struct dsa_context *ctx)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		tsk_node->tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		if ((tsk_node->tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tsk_node->tsk->dflags |= IDXD_OP_FLAG_BOF;

		dsa_prep_cflush(tsk_node->tsk);
		tsk_node = tsk_node->next;
	}

	tsk_node = ctx->multi_task_node;
	while (tsk_node) {
		dsa_desc_submit(ctx, tsk_node->tsk->desc);
		tsk_node = tsk_node->next;
	}
	tsk_node = ctx->multi_task_node;
	info("Submitted all cflush jobs\n");

	while (tsk_node) {
		ret = dsa_wait_cflush(ctx, tsk_node->tsk);
		if (ret != DSA_STATUS_OK)
			info("Desc: %p failed with ret: %d\n",
			     tsk_node->tsk->desc, tsk_node->tsk->comp->status);
		tsk_node = tsk_node->next;
	}
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
	case DSA_OPCODE_AP_DELTA:
		rc = task_result_verify_ap_delta(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_CRCGEN:
		rc = task_result_verify_crcgen(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_COPY_CRC:
		rc = task_result_verify_crc_copy(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_DIF_INS:
		rc = task_result_verify_dif(tsk, tsk->xfer_size, mismatch_expected);
		rc = task_result_verify_dif_tags(tsk, tsk->xfer_size);
		return rc;
	case DSA_OPCODE_DIF_STRP:
		rc = task_result_verify_dif(tsk, tsk->xfer_size - 8 * tsk->blks,
					    mismatch_expected);
		return rc;
	case DSA_OPCODE_DIF_UPDT:
		rc = task_result_verify_dif(tsk, tsk->xfer_size - 8 * tsk->blks,
					    mismatch_expected);
		rc = task_result_verify_dif_tags(tsk, tsk->xfer_size - 8 * tsk->blks);
		return rc;
	}

	info("test with op %d passed\n", tsk->opcode);

	return DSA_STATUS_OK;
}

int task_result_verify_task_nodes(struct dsa_context *ctx, int mismatch_expected)
{
	struct task_node *tsk_node = ctx->multi_task_node;
	int ret = DSA_STATUS_OK;

	while (tsk_node) {
		ret = task_result_verify(tsk_node->tsk, mismatch_expected);
		if (ret != DSA_STATUS_OK) {
			err("memory result verify failed %d\n", ret);
			return ret;
		}
		tsk_node = tsk_node->next;
	}

	return ret;
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

int task_result_verify_ap_delta(struct task *tsk, int mismatch_expected)
{
	int rc;
	int data_size = (tsk->comp->status == DSA_COMP_SUCCESS) ?
			 tsk->desc->xfer_size : tsk->comp->bytes_completed;

	rc = memcmp((unsigned char *)tsk->desc->dst_addr,
		    (unsigned char *)tsk->desc->src2_addr, data_size);
	if (rc) {
		err("apply delta mismatch, memcmp rc %d\n", rc);
		return -ENXIO;
	}
	return DSA_STATUS_OK;
}

static uint8_t reverse_u8(uint8_t x)
{
	const char *rev = "\x0\x8\x4\xC\x2\xA\x6\xE\x1\x9\x5\xD\x3\xB\x7\xF";
	return rev[(x & 0xf0) >> 4] | (rev[x & 0x0f] << 4);
}

static unsigned int reverse(unsigned int num)
{
	unsigned int rev_num = 0;

	for (int i = 0; i < (int)sizeof(num); i++) {
		rev_num |= (reverse_u8((num >> i * 8) & 0xFF));
		if (i < (int)sizeof(num) - 1)
			rev_num = rev_num << 8;
	}
	return rev_num;
}

static uint32_t dsa_calculate_crc32(void *data, size_t length, uint32_t seed, uint32_t flags)
{
	uint32_t one;
	uint32_t two;
	uint8_t *current_char;
	uint32_t *current = (uint32_t *)data;
	uint32_t crc = 0;

	if (flags & BYPASS_CRC_INV_REF)
		crc = reverse(seed);
	else
		crc = ~seed;

	if (!(flags & BYPASS_DATA_REF)) {
		while (length >= 8) {
			one = *current++ ^ crc;
			two = *current++;
			crc = crc32_lookup[7][one & 0xff] ^
			crc32_lookup[6][(one >> 8)  & 0xff] ^
			crc32_lookup[5][(one >> 16) & 0xff] ^
			crc32_lookup[4][one >> 24] ^
			crc32_lookup[3][two & 0xff] ^
			crc32_lookup[2][(two >> 8)  & 0xff] ^
			crc32_lookup[1][(two >> 16) & 0xff] ^
			crc32_lookup[0][two >> 24];
		length -= 8;
		}
		current_char = (uint8_t *)current;
		/* Remaining 1 to 7 bytes (standard CRC table-based algorithm) */
		while (length--)
			crc = (crc >> 8) ^ crc32_lookup[0][(crc & 0xff) ^ *current_char++];

	} else {
		/* Process one byte and invert the data */
		current_char = (uint8_t *)current;
		while (length--)
			crc = crc32c_table[(crc ^ reverse_u8(*current_char++)) & 0xff] ^ (crc >> 8);
	}
	if (flags & BYPASS_CRC_INV_REF)
		return reverse(crc);
	/* Same as crc ^ 0xFFFFFFFF */
	return ~crc;
}

int task_result_verify_crcgen(struct task *tsk, int mismatch_expected)
{
	unsigned int expected_crc = 0x0;
	unsigned int seed = 0;
	int data_size = (tsk->comp->status == DSA_COMP_SUCCESS) ?
			 tsk->desc->xfer_size : tsk->comp->bytes_completed;

	if (tsk->dflags & READ_CRC_SEED)
		seed = *tsk->crc_seed_addr;
	else
		seed = tsk->crc_seed;
	expected_crc = dsa_calculate_crc32((void *)tsk->desc->src_addr,
					   data_size, seed, tsk->dflags);
	printf("expected crc = %x\n", expected_crc);

	if (!mismatch_expected) {
		if (tsk->comp->crc_val != expected_crc) {
			printf("\033[0;31m");
			printf("error occurred");
			err("Generated Crc %#x is different than expected Crc %#x\n",
			    tsk->comp->crc_val, expected_crc);
			printf("\033[0m");
			return -ENXIO;
		}
		return DSA_STATUS_OK;
	}

	/* mismatch_expected */
	if (tsk->comp->crc_val != expected_crc) {
		info("expected mismatch in crcgen %#x\n",
		     tsk->comp->crc_val);
		return DSA_STATUS_OK;
	}
	return DSA_STATUS_OK;
}

int task_result_verify_crc_copy(struct task *tsk, int mismatch_expected)
{
	int rc;
	unsigned int seed = 0;
	unsigned int expected_crc = 0x0;
	int data_size = (tsk->comp->status == DSA_COMP_SUCCESS) ?
			 tsk->desc->xfer_size : tsk->comp->bytes_completed;

	if (tsk->dflags & READ_CRC_SEED)
		seed = *tsk->crc_seed_addr;
	else
		seed = tsk->crc_seed;
	expected_crc = dsa_calculate_crc32((void *)tsk->desc->src_addr,
					   data_size, seed, tsk->dflags);
	rc = memcmp((unsigned char *)tsk->desc->src_addr,
		    (unsigned char *)tsk->desc->dst_addr, data_size);
	printf("rc memcmp = %x and expected crc = %x\n", rc, expected_crc);

	if (rc) {
		printf("\033[0;31m");
		printf("error occurred");
		err("dif mismatch dst1, memcmp rc %d\n", rc);
		printf("\033[0m");
		return -ENXIO;
	}
	if (tsk->comp->crc_val != expected_crc) {
		printf("\033[0;31m");
		printf("error occurred");
		err("Generated Crc %#x is different than expected Crc %#x\n",
		    tsk->comp->crc_val, expected_crc);
		printf("\033[0m");
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

/**
 * This function calculates the CRC16 T10 checksum for the DIF descriptors.
 * @param *buffer pointer to the data buffer.
 * @param len size of the buffer.
 *
 **/
uint16_t dsa_calculate_crc_t10dif(unsigned char *buffer, size_t len, int flags)
{
	unsigned short crc;
	unsigned int i = 0;

	crc = (flags & DIF_INVERT_CRC_SEED) ? 0xFFFF : 0;

	for (i = 0; i < len; i++)
		crc = (crc << 8) ^ t10_dif_crc_table[((crc >> 8) ^ buffer[i]) & 0xff];

	return (flags & DIF_INVERT_CRC_RESULT) ? ~crc : crc;
}

static int task_result_verify_dif_page_fault(struct task *tsk, unsigned long xfer_size,
					     int mismatch_expected)
{
	struct dsa_hw_desc *hw = tsk->desc;
	int rc = 0;
	unsigned char *src1 = (unsigned char *)hw->src_addr;
	unsigned char *dst1 = (unsigned char *)hw->dst_addr;
	unsigned long i, blks;

	if (tsk->comp->status == 0x16 || xfer_size == 0)
		return DSA_STATUS_OK;

	info("Partial DIF Src and Dest Check Ongoing\n");

	if (tsk->opcode == DSA_OPCODE_DIF_INS) {
		blks = xfer_size / dif_blk_arr[tsk->blk_idx_flg];
		for (i = 0; i < blks; i++)
			rc = memcmp(&src1[dif_blk_arr[tsk->blk_idx_flg] * i],
				    &dst1[(dif_blk_arr[tsk->blk_idx_flg] + 8) * i],
				    dif_blk_arr[tsk->blk_idx_flg]);
	}

	if (tsk->opcode == DSA_OPCODE_DIF_STRP) {
		blks = xfer_size / (dif_blk_arr[tsk->blk_idx_flg] + 8);
		for (i = 0; i < blks; i++)
			rc = memcmp(&src1[(dif_blk_arr[tsk->blk_idx_flg] + 8) * i],
				    &dst1[dif_blk_arr[tsk->blk_idx_flg] * i],
				    dif_blk_arr[tsk->blk_idx_flg]);
	}

	if (tsk->opcode == DSA_OPCODE_DIF_UPDT) {
		blks = xfer_size / (dif_blk_arr[tsk->blk_idx_flg] + 8);
		for (i = 0; i < blks; i++)
			rc = memcmp(&src1[(dif_blk_arr[tsk->blk_idx_flg] + 8) * i],
				    &dst1[(dif_blk_arr[tsk->blk_idx_flg] + 8) * i],
				    dif_blk_arr[tsk->blk_idx_flg]);
	}

	if (rc) {
		err("dif mismatch dst1, memcmp rc %d\n", rc);
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

int task_result_verify_dif(struct task *tsk, unsigned long xfer_size, int mismatch_expected)
{
	int rc;
	unsigned long i;
	unsigned long blks = tsk->blks;
	unsigned long buf_size = dif_blk_arr[tsk->blk_idx_flg];
	unsigned char *src1 = (unsigned char *)tsk->src1;
	unsigned char *dst1 = (unsigned char *)tsk->dst1;

	if (tsk->comp->status == DSA_COMP_PAGE_FAULT_NOBOF ||
	    tsk->comp->status == DSA_COMP_PAGE_FAULT_IR ||
	    tsk->comp->status == 0x83) {
		rc = task_result_verify_dif_page_fault(tsk, tsk->comp->bytes_completed, 0);
		info("Partial DIF Src and Dest Checking Done\n");
		if (!rc)
			return DSA_STATUS_OK;
	}

	if (tsk->comp->status == 0x16)
		return DSA_STATUS_OK;

	info("Checking Src & Dst buffers\n");
	if (tsk->opcode == DSA_OPCODE_DIF_INS) {
		for (i = 0; i < blks; i++)
			rc = memcmp(&src1[buf_size * i], &dst1[(buf_size + 8) * i], buf_size);
	}

	if (tsk->opcode == DSA_OPCODE_DIF_STRP) {
		for (i = 0; i < blks; i++)
			rc = memcmp(&src1[(buf_size + 8) * i], &dst1[buf_size * i], buf_size);
	}

	if (tsk->opcode == DSA_OPCODE_DIF_UPDT) {
		for (i = 0; i < blks; i++)
			rc = memcmp(&src1[(buf_size + 8) * i], &dst1[(buf_size + 8) * i], buf_size);
	}

	if (rc) {
		err("dif mismatch dst1, memcmp rc %d\n", rc);
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

static int task_result_verify_dif_tags_page_fault(struct task *tsk, unsigned long xfer_size)
{
	struct dsa_hw_desc *hw = tsk->desc;
	unsigned long blks;
	unsigned long buf_size;
	unsigned char *dst1 = (uint8_t *)hw->dst_addr;
	unsigned char *src1 = (uint8_t *)hw->src_addr;
	unsigned long g_count = 0;
	unsigned long a_count = 0;
	unsigned long r_count = 0;
	unsigned short dif_apptag = 0;
	unsigned long dif_reftag = 0;
	unsigned int dif_guardtag = 0;
	unsigned char tmp_buf;
	unsigned char dst_tag;
	unsigned long i;

	info("Checking Partial DIF Tags\n");

	if (tsk->comp->status == 0x16 || xfer_size == 0)
		return DSA_STATUS_OK;

	if (tsk->opcode != DSA_OPCODE_DIF_UPDT)
		blks = xfer_size / dif_blk_arr[tsk->blk_idx_flg];
	else
		blks = xfer_size / (dif_blk_arr[tsk->blk_idx_flg] + 8);

	switch (tsk->opcode) {
	case DSA_OPCODE_DIF_INS:
		dif_reftag = hw->ins_ref_tag_seed;
		dif_apptag = hw->ins_app_tag_seed;
		break;

	case DSA_OPCODE_DIF_CHECK:
	case DSA_OPCODE_DIF_STRP:
		dif_reftag = hw->chk_ref_tag_seed;
		dif_apptag = hw->chk_app_tag_seed;
		break;

	case DSA_OPCODE_DIF_UPDT:
		dif_reftag = hw->dest_ref_tag_seed;
		dif_apptag = hw->dest_app_tag_seed;
		break;
	}

	buf_size = dif_blk_arr[tsk->blk_idx_flg];
	for (i = 0; i < blks; i++) {
		if (tsk->opcode == DSA_OPCODE_DIF_INS)
			dif_guardtag = dsa_calculate_crc_t10dif((src1 + buf_size * i),
								buf_size, 0);
		else
			dif_guardtag = dsa_calculate_crc_t10dif((src1 + (buf_size + 8) * i),
								buf_size, 0);

		dst_tag = dst1[buf_size + DIF_BLK_GRD_1 + (buf_size + 8) * i];
		tmp_buf = (dif_guardtag >> 8) & 0xff;
		if (tmp_buf != dst_tag)
			g_count++;

		dst_tag = dst1[buf_size + DIF_BLK_GRD_2 + (buf_size + 8) * i];
		tmp_buf = dif_guardtag & 0xff;
		if (tmp_buf != dst_tag)
			g_count++;

		dst_tag = dst1[buf_size + DIF_APP_TAG_1 + (buf_size + 8) * i];
		tmp_buf = (dif_apptag >> 8) & 0xff;
		if (tmp_buf != dst_tag)
			a_count++;

		dst_tag = dst1[buf_size + DIF_APP_TAG_2 + (buf_size + 8) * i];
		tmp_buf = (dif_apptag) & 0xff;
		if (tmp_buf != dst_tag)
			a_count++;

		dst_tag = dst1[buf_size + DIF_REF_TAG_1 + (buf_size + 8) * i];
		tmp_buf = (dif_reftag >> 24) & 0xff;
		if (tmp_buf != dst_tag)
			r_count++;

		dst_tag = dst1[buf_size + DIF_REF_TAG_2 + (buf_size + 8) * i];
		tmp_buf = (dif_reftag >> 16) & 0xff;
		if (tmp_buf != dst_tag)
			r_count++;

		dst_tag = dst1[buf_size + DIF_REF_TAG_3 + (buf_size + 8) * i];
		tmp_buf = (dif_reftag >> 8) & 0xff;
		if (tmp_buf != dst_tag)
			r_count++;

		dst_tag = dst1[buf_size + DIF_REF_TAG_4 + (buf_size + 8) * i];
		tmp_buf = dif_reftag & 0xff;
		if (tmp_buf != dst_tag)
			r_count++;

		if (tsk->opcode != DSA_OPCODE_DIF_UPDT)
			dif_reftag++;
	}

	if (g_count || a_count || r_count)
		err("Tag Errors Found g: %ld a: %ld r: %ld\n", g_count, a_count, r_count);
	else
		info("All Tags Validated\n", g_count, a_count, r_count);

	return DSA_STATUS_OK;
}

int task_result_verify_dif_tags(struct task *tsk, unsigned long xfer_size)
{
	int rc;
	unsigned long blks;
	unsigned long buf_size;
	unsigned char *dst1 = (unsigned char *)tsk->dst1;
	unsigned char *src1 = (unsigned char *)tsk->src1;
	unsigned long g_count = 0;
	unsigned long a_count = 0;
	unsigned long r_count = 0;
	unsigned int dif_reftag = tsk->reftag;
	unsigned int dif_apptag = tsk->apptag;
	unsigned int dif_guardtag = 0;
	unsigned char tmp_buf;
	unsigned char dst_tag;
	unsigned long i;

	info("compsts: %x\n", tsk->comp->status);
	if (tsk->comp->status == 0x83 ||
	    tsk->comp->status == DSA_COMP_PAGE_FAULT_NOBOF ||
	    tsk->comp->status == DSA_COMP_PAGE_FAULT_IR) {
		rc = task_result_verify_dif_tags_page_fault(tsk, tsk->comp->bytes_completed);
		info("Partial DIF Tags Checking Done\n");
		if (!rc)
			return DSA_STATUS_OK;
	}

	info("Checking All Tags\n");
	if (tsk->opcode != DSA_OPCODE_DIF_UPDT)
		blks = xfer_size / dif_blk_arr[tsk->blk_idx_flg];
	else
		blks = tsk->blks;

	buf_size = dif_blk_arr[tsk->blk_idx_flg];
	tsk->reftag = 0xABBA;
	tsk->apptag = 0xFACE;

	for (i = 0; i < blks; i++) {
		if (tsk->opcode == DSA_OPCODE_DIF_INS)
			dif_guardtag = dsa_calculate_crc_t10dif((src1 + (buf_size) * i),
								buf_size, 0);
		else
			dif_guardtag = dsa_calculate_crc_t10dif((src1 + (buf_size + 8) * i),
								buf_size, 0);

		dst_tag = dst1[buf_size + DIF_BLK_GRD_1 + (buf_size + 8) * i];
		tmp_buf = (dif_guardtag >> 8) & 0xff;
		if (tmp_buf != dst_tag)
			g_count++;

		dst_tag = dst1[buf_size + DIF_BLK_GRD_2 + (buf_size + 8) * i];
		tmp_buf = dif_guardtag & 0xff;
		if (tmp_buf != dst_tag)
			g_count++;

		dst_tag = dst1[buf_size + DIF_APP_TAG_1 + (buf_size + 8) * i];
		tmp_buf = (dif_apptag >> 8) & 0xff;
		if (tmp_buf != dst_tag)
			a_count++;

		dst_tag = dst1[buf_size + DIF_APP_TAG_2 + (buf_size + 8) * i];
		tmp_buf = (dif_apptag) & 0xff;
		if (tmp_buf != dst_tag)
			a_count++;

		dst_tag = dst1[buf_size + DIF_REF_TAG_1 + (buf_size + 8) * i];
		tmp_buf = (dif_reftag >> 24) & 0xff;
		if (tmp_buf != dst_tag)
			r_count++;

		dst_tag = dst1[buf_size + DIF_REF_TAG_2 + (buf_size + 8) * i];
		tmp_buf = (dif_reftag >> 16) & 0xff;
		if (tmp_buf != dst_tag)
			r_count++;

		dst_tag = dst1[buf_size + DIF_REF_TAG_3 + (buf_size + 8) * i];
		tmp_buf = (dif_reftag >> 8) & 0xff;
		if (tmp_buf != dst_tag)
			r_count++;

		dst_tag = dst1[buf_size + DIF_REF_TAG_4 + (buf_size + 8) * i];
		tmp_buf = dif_reftag & 0xff;
		if (tmp_buf != dst_tag)
			r_count++;

		if (tsk->opcode != DSA_OPCODE_DIF_UPDT)
			dif_reftag++;
	}

	if (g_count || a_count || r_count)
		err("Tag Errors Found g: %ld a: %ld r: %ld\n", g_count, a_count, r_count);
	else
		info("All Tags Validated\n", g_count, a_count, r_count);

	return DSA_STATUS_OK;
}

int batch_result_verify(struct batch_task *btsk, int bof)
{
	uint8_t core_stat, sub_stat;
	int i, rc;
	struct task *tsk;

	core_stat = stat_val(btsk->core_task->comp->status);
	if (core_stat == DSA_COMP_SUCCESS) {
		info("core task success, chekcing sub-tasks\n");
	} else if (!bof && core_stat == DSA_COMP_BATCH_FAIL) {
		info("partial complete with NBOF, checking sub-tasks\n");
	} else {
		err("batch core task failed with status %d\n", core_stat);
		return DSA_STATUS_FAIL;
	}

	for (i = 0; i < btsk->task_num; i++) {
		tsk = &btsk->sub_tasks[i];
		sub_stat = stat_val(tsk->comp->status);

		if (!bof && sub_stat == DSA_COMP_PAGE_FAULT_NOBOF) {
			dbg("PF in sub-task[%d], consider as passed\n", i);
		} else if (sub_stat == DSA_COMP_SUCCESS) {
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
