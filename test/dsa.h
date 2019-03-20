// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __TEST_DSA_H__
#define __TEST_DSA_H__
#include <accfg/libaccel_config.h>
#include <linux/idxd.h>

#define MAX_PATH_LENGTH 1024

#define DSA_MAX_OPS 0x20

#define DSA_FLAGS_BOF 0x1 /* Block on page faults */
#define DSA_FLAGS_BLOCK 0x2 /* Spin in user space */
#define DSA_FLAGS_WAIT 0x4  /* Wait in kernel */
#define DSA_FLAGS_PREF 0x8 /* Pre-fault the buffers */

#define DSA_STATUS_OK    0x0
#define DSA_STATUS_RETRY 0x1
#define DSA_STATUS_FAIL  0x2
#define DSA_STATUS_RPF   0x3
#define DSA_STATUS_URPF  0x4
#define DSA_STATUS_TIMEOUT 0x5

#define DSA_BATCH_OPCODES 0x278

typedef struct dsa_completion_record dsa_completion_t;

struct dsa_batch {
	struct dsa_context *ctx;
	unsigned int num_descs;
	unsigned int flags;
	struct dsa_completion_record *comp_unaligned;
	struct dsa_completion_record *comp;
	struct dsa_hw_desc *descs;
	struct dsa_hw_desc descs_unaligned[0];
};

extern unsigned int ms_timeout;

struct dsa_ring_ent {
	struct dsa_hw_desc hw;
	struct dsa_completion_record *comp;
	struct dsa_batch *batch;
	unsigned int flags;
	uint16_t idx;
	uint16_t n;
};

struct dsa_context {
	struct accfg_ctx *ctx;
	int fd;
	int groupfd;
	int groupid;
	char *name;

	struct accfg_wq *wq;

	unsigned long opcap;
	unsigned int max_batch_size;
	unsigned int max_xfer_size;
	unsigned int max_xfer_bits;

	int wq_idx;
	void *wq_reg;
	int wq_size;
	int dedicated;
	int bof;
	struct dsa_ring_ent *ring;
	void    *comp_ring_buf;
	struct dsa_completion_record *comp_aligned;
	uint16_t num_entries;
	uint16_t head;
	uint16_t tail;
	uint16_t dmacount;
	uint16_t issued;
	uint16_t completed;          /* cumulative number */
	uint32_t comp_ring_size;
	struct dsa_batch batch;
};

#define DSA_CAP_BLOCK_ON_FAULT                  0x0000000000000001
#define DSA_CAP_OVERLAP_COPY                    0x0000000000000002
#define DSA_CAP_CACHE_MEM_CTRL                  0x0000000000000004
#define DSA_CAP_CACHE_FLUSH_CTRL                0x0000000000000008
#define DSA_CAP_DEST_RDBACK                     0x0000000000000100
#define DSA_CAP_DUR_WRITE                       0x0000000000000200

#define DSA_CAP_MAX_BATCH_MASK                  0x0000000001E00000
#define DSA_CAP_MAX_BATCH_SHIFT                 21

#define DSA_CAP_MAX_XFER_MASK                   0x00000000001F0000
#define DSA_CAP_MAX_XFER_SHIFT                  16

static inline unsigned char enqcmd(struct dsa_hw_desc *desc,
			volatile void *reg)
{
	unsigned char retry;

	asm volatile(".byte 0xf2, 0x0f, 0x38, 0xf8, 0x02\t\n"
			"setz %0\t\n"
			: "=r"(retry): "a" (reg), "d" (desc));
	return retry;
}

static inline void movdir64b(struct dsa_hw_desc *desc,
			volatile void *reg)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02\t\n"
		: : "a" (reg), "d" (desc));
}

static inline int dsa_add_idx(struct dsa_context *ctx, int idx, int val)
{
	idx += val;

	if (idx >= ctx->num_entries)
		idx = idx - ctx->num_entries;

	return idx;
}

static inline int dsa_inc_idx(struct dsa_context *ctx, int idx)
{
        return dsa_add_idx(ctx, idx, 1);
}

static inline struct dsa_ring_ent *dsa_get_ring_ent(struct dsa_context *ctx,
		uint16_t idx)
{
	return &ctx->ring[idx];
}

static inline struct dsa_ring_ent *dsa_alloc_desc(struct dsa_context *ctx)
{
	struct dsa_ring_ent *desc;

	desc = dsa_get_ring_ent(ctx, ctx->head);

	ctx->head = dsa_inc_idx(ctx, ctx->head);

	return desc;
}

static inline uint32_t dsa_ring_size(struct dsa_context *ctx)
{
	return ctx->num_entries;
}

/* count of descriptors in flight with the engine */
static inline uint16_t dsa_ring_active(struct dsa_context *ctx)
{
	if (ctx->issued >= ctx->tail)
		return ctx->issued - ctx->tail;
	else
		return dsa_ring_size(ctx) - (ctx->tail - ctx->issued);
}

/* count of descriptors pending submission to hardware */
static inline uint16_t dsa_ring_pending(struct dsa_context *ctx)
{
	if (ctx->head >= ctx->issued)
		return ctx->head - ctx->issued;
	else
		return dsa_ring_size(ctx) - (ctx->issued - ctx->head);
}

static inline uint16_t dsa_ring_space(struct dsa_context *ctx)
{
	return dsa_ring_size(ctx) - dsa_ring_active(ctx);
}

static inline uint16_t dsa_xferlen_to_descs(struct dsa_context *ctx, size_t len)
{
	uint16_t num_descs = len >> ctx->max_xfer_bits;
	num_descs += !!(len & (ctx->max_xfer_size - 1));

	return num_descs;
}

int dsa_enqcmd(struct dsa_context *ctx, struct dsa_hw_desc *hw);

struct dsa_context *dsa_init(void);
int dsa_alloc(struct dsa_context *ctx, int shared);

int dsa_memcpy(struct dsa_context *ctx, void *dest, void *src, size_t len,
			unsigned int flags, dsa_completion_t *c);
struct dsa_ring_ent *dsa_memcpy_nb(struct dsa_context *ctx, void *dest,
		void *src, size_t len, unsigned int flags);

struct dsa_ring_ent *dsa_batch_memcpy_nb(struct dsa_context *ctx, void *dest,
			void *src, size_t len, unsigned int flags);
int dsa_batch_memcpy(struct dsa_context *ctx, void *dest, void *src, size_t len,
			unsigned int flags, dsa_completion_t *c);
int dsa_wait_memcpy(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_memset(struct dsa_context *ctx, void *dest, uint64_t val, size_t len,
			unsigned int flags, dsa_completion_t *c);
struct dsa_ring_ent *dsa_memset_nb(struct dsa_context *ctx, void *dest,
		uint64_t val, size_t len, unsigned int flags);

struct dsa_ring_ent *dsa_batch_memset_nb(struct dsa_context *ctx, void *dest,
			uint64_t val, size_t len, unsigned int flags);
int dsa_batch_memset(struct dsa_context *ctx, void *dest, uint64_t val,
			size_t len, unsigned int flags, dsa_completion_t *c);
int dsa_wait_memset(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_compare(struct dsa_context *ctx, void *src1, void *src2, size_t len,
			unsigned int flags, dsa_completion_t *c);
struct dsa_ring_ent *dsa_compare_nb(struct dsa_context *ctx, void *src1,
		void *src2, size_t len, unsigned int flags);

struct dsa_ring_ent *dsa_batch_compare_nb(struct dsa_context *ctx, void *src1,
			void *src2, size_t len, unsigned int flags);
int dsa_batch_compare(struct dsa_context *ctx, void *src1, void *src2,
			size_t len, unsigned int flags, dsa_completion_t *c);
int dsa_wait_compare(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_compval(struct dsa_context *ctx, uint64_t val, void *src, size_t len,
			unsigned int flags, dsa_completion_t *c);
struct dsa_ring_ent *dsa_compval_nb(struct dsa_context *ctx, uint64_t val,
		void *src, size_t len, unsigned int flags);

struct dsa_ring_ent *dsa_batch_compval_nb(struct dsa_context *ctx, uint64_t val,
			void *src, size_t len, unsigned int flags);
int dsa_batch_compval(struct dsa_context *ctx, uint64_t val, void *src,
			size_t len, unsigned int flags, dsa_completion_t *c);
int dsa_wait_compval(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_dualcast(struct dsa_context *ctx, void *dest1, void *dest2, void *src,
			size_t len, unsigned int flags, dsa_completion_t *c);
struct dsa_ring_ent *dsa_dualcast_nb(struct dsa_context *ctx, void *dest1,
		void *dest2, void *src, size_t len, unsigned int flags);

struct dsa_ring_ent *dsa_batch_dualcast_nb(struct dsa_context *ctx, void *dest1,
			void *dest2, void *src, size_t len, unsigned int flags);
int dsa_batch_dualcast(struct dsa_context *ctx, void *dest1, void *dest2,
		void *src, size_t len, unsigned int flags, dsa_completion_t *c);
int dsa_wait_dualcast(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_prep_memcpy(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *dest, void *src, size_t len, unsigned int flags);
void dsa_reprep_memcpy(struct dsa_context *ctx, struct dsa_ring_ent *desc);
int dsa_prep_memset(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *dst, uint64_t value, size_t len, unsigned long flags);
void dsa_reprep_memset(struct dsa_context *ctx, struct dsa_ring_ent *desc);
int dsa_prep_compare(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *src1, void *src2, size_t len, unsigned long flags);
void dsa_reprep_compare(struct dsa_context *ctx, struct dsa_ring_ent *desc);
int dsa_prep_compval(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		uint64_t val, void *src, size_t len, unsigned long flags);
void dsa_reprep_compval(struct dsa_context *ctx, struct dsa_ring_ent *desc);
int dsa_prep_dualcast(struct dsa_context *ctx, struct dsa_ring_ent *desc,
	void *dst1, void *dst2, void *src, size_t len, unsigned long flags);
void dsa_reprep_dualcast(struct dsa_context *ctx, struct dsa_ring_ent *desc);


void dsa_prep_batch_memcpy(struct dsa_batch *batch, int idx, int n,
		uint64_t dst, uint64_t src, size_t len, unsigned long flags);
void dsa_prep_batch_memset(struct dsa_batch *batch, int idx, int n,
		uint64_t dst, uint64_t val, size_t len, unsigned long flags);
void dsa_prep_batch_compare(struct dsa_batch *batch, int idx, int n,
		uint64_t src1, uint64_t src2, size_t len, unsigned long flags);
void dsa_prep_batch_compval(struct dsa_batch *batch, int idx, int n,
		uint64_t val, uint64_t src, size_t len, unsigned long flags);
void dsa_prep_batch_dualcast(struct dsa_batch *batch, int idx, int n,
		uint64_t dst1, uint64_t dst2, uint64_t src, size_t len,
		unsigned long flags);
int dsa_wait_batch(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c, int idx, int num_descs);

void dsa_free (struct dsa_context *ctx);

struct dsa_batch *dsa_alloc_batch_buffers(struct dsa_context *ctx,
			int num_descs);
void dsa_free_batch_buffers (struct dsa_batch *batch);

void dsa_prep_submit_batch(struct dsa_batch *batch, int idx, int n,
		struct dsa_ring_ent *desc, unsigned long desc_flags);

void dsa_prep_desc_common(struct dsa_hw_desc *hw, char opcode,
	uint64_t dest, uint64_t src, size_t len, unsigned long flags);

struct dsa_ring_ent *dsa_reserve_space(struct dsa_context *ctx, int n);
void dsa_free_desc(struct dsa_context *ctx, struct dsa_ring_ent *desc);
#endif
