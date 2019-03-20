/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __TEST_DSA_H__
#define __TEST_DSA_H__
#include <accfg/libaccel_config.h>
#include <linux/idxd.h>

#define MAX_PATH_LENGTH 1024

#define DSA_MAX_OPS 0x20

#define TEST_FLAGS_BOF     0x1     /* Block on page faults */
#define TEST_FLAGS_WAIT    0x4     /* Wait in kernel */
#define TEST_FLAGS_PREF    0x8     /* Pre-fault the buffers */

#define DSA_STATUS_OK    0x0
#define DSA_STATUS_RETRY 0x1
#define DSA_STATUS_FAIL  0x2
#define DSA_STATUS_RPF   0x3
#define DSA_STATUS_URPF  0x4
#define DSA_STATUS_TIMEOUT 0x5

#define DSA_BATCH_OPCODES 0x278

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

#define DSA_COMP_STAT_CODE_MASK                 0x3F
#define DSA_COMP_STAT_RW_MASK                   0x80

/* helper macro to get lower 6 bits (ret code) from completion status */
#define stat_val(status) ((status) & DSA_COMP_STAT_CODE_MASK)

typedef struct dsa_completion_record dsa_completion_t;

struct dsa_batch {
	struct dsa_context *ctx;
	unsigned int num_descs;
	struct dsa_completion_record *comp_unaligned;
	struct dsa_completion_record *comp;
	struct dsa_hw_desc *descs;
	struct dsa_hw_desc descs_unaligned[0];
};

extern unsigned int ms_timeout;
extern int debug_logging;

struct dsa_ring_ent {
	struct dsa_hw_desc hw;
	struct dsa_completion_record *comp;
	struct dsa_batch *batch;
	uint16_t idx;
	uint16_t n;
};

struct dsa_context {
	struct accfg_ctx *ctx;
	struct accfg_wq *wq;

	unsigned int max_batch_size;
	unsigned int max_xfer_size;
	unsigned int max_xfer_bits;

	int fd;
	int wq_idx;
	void *wq_reg;
	int wq_size;
	int dedicated;
	int bof;
	struct dsa_ring_ent *ring;
	void *comp_ring_buf;
	struct dsa_completion_record *comp_aligned;
	uint16_t num_entries;
	uint16_t head;
	uint16_t tail;
	uint16_t issued;
};

static inline void vprint_log(const char *tag, const char *msg, va_list args)
{
	printf("[%5s] ", tag);
	vprintf(msg, args);
}

static inline void vprint_err(const char *tag, const char *msg, va_list args)
{
	fprintf(stderr, "[%5s] ", tag);
	vfprintf(stderr, msg, args);
}

static inline void err(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	vprint_err("error", msg, args);
	va_end(args);
}

static inline void warn(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	vprint_err("warn", msg, args);
	va_end(args);
}

static inline void info(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	vprint_log("info", msg, args);
	va_end(args);
}

static inline void dbg(const char *msg, ...)
{
	va_list args;

	if (!debug_logging)
		return;

	va_start(args, msg);
	vprint_log("debug", msg, args);
	va_end(args);
}

static inline unsigned char enqcmd(struct dsa_hw_desc *desc,
			volatile void *reg)
{
	unsigned char retry;

	asm volatile(".byte 0xf2, 0x0f, 0x38, 0xf8, 0x02\t\n"
			"setz %0\t\n"
			: "=r"(retry) : "a" (reg), "d" (desc));
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

/* Dump DSA hardware descriptor to log */
static inline void dump_desc(struct dsa_hw_desc *hw)
{
	struct dsa_raw_desc *rhw = (void *)hw;
	int i;

	dbg("desc addr: %p\n", hw);

	for (i = 0; i < 8; i++)
		dbg("desc[%d]: 0x%016lx\n", i, rhw->field[i]);
}

/* Dump DSA completion record to log */
static inline void dump_compl_rec(struct dsa_completion_record *compl)
{
	struct dsa_raw_completion_record *rcompl = (void *)compl;
	int i;

	dbg("completion record addr: %p\n", compl);

	for (i = 0; i < 4; i++)
		dbg("compl[%d]: 0x%016lx\n", i, rcompl->field[i]);
}

static inline void resolve_page_fault(uint64_t addr, uint8_t status)
{
	uint8_t *addr_u8 = (uint8_t *)addr;

	/* This line solve the PF by writing to the address.*/
	/* For PF at write, we can change the value as the address will be */
	/* overwritten again by the DSA HW */
	*addr_u8 =  ~(*addr_u8);

	/* For PF at read, we need to restore it to the orginal value */
	if (!(status & DSA_COMP_STAT_RW_MASK))
		*addr_u8 = ~(*addr_u8);
}

int dsa_enqcmd(struct dsa_context *ctx, struct dsa_hw_desc *hw);

struct dsa_context *dsa_init(void);
int dsa_alloc(struct dsa_context *ctx, int shared);

int dsa_memcpy(struct dsa_context *ctx, void *dest, void *src, size_t len,
		unsigned int tflags, dsa_completion_t *c);
int dsa_wait_memcpy(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_memfill(struct dsa_context *ctx, void *dest, uint64_t val, size_t len,
		unsigned int tflags, dsa_completion_t *c);
int dsa_wait_memfill(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_compare(struct dsa_context *ctx, void *src1, void *src2, size_t len,
		unsigned int tflags, dsa_completion_t *c);
int dsa_wait_compare(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_compval(struct dsa_context *ctx, uint64_t val, void *src, size_t len,
		unsigned int tflags, dsa_completion_t *c);
int dsa_wait_compval(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_dualcast(struct dsa_context *ctx, void *dest1, void *dest2, void *src,
		size_t len, unsigned int tflags, dsa_completion_t *c);
int dsa_wait_dualcast(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c);

int dsa_prep_memcpy(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *dest, void *src, size_t len, unsigned int tflags);
void dsa_reprep_memcpy(struct dsa_context *ctx, struct dsa_ring_ent *desc);
int dsa_prep_memfill(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *dst, uint64_t value, size_t len, unsigned long dflags);
void dsa_reprep_memfill(struct dsa_context *ctx, struct dsa_ring_ent *desc);
int dsa_prep_compare(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *src1, void *src2, size_t len, unsigned long dflags);
void dsa_reprep_compare(struct dsa_context *ctx, struct dsa_ring_ent *desc);
int dsa_prep_compval(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		uint64_t val, void *src, size_t len, unsigned long dflags);
void dsa_reprep_compval(struct dsa_context *ctx, struct dsa_ring_ent *desc);
int dsa_prep_dualcast(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		void *dst1, void *dst2, void *src, size_t len,
		unsigned long dflags);
void dsa_reprep_dualcast(struct dsa_context *ctx, struct dsa_ring_ent *desc);


void dsa_prep_batch_memcpy(struct dsa_batch *batch, int idx, int n,
		uint64_t dst, uint64_t src, size_t len, unsigned long dflags);
void dsa_prep_batch_memfill(struct dsa_batch *batch, int idx, int n,
		uint64_t dst, uint64_t val, size_t len, unsigned long dflags);
void dsa_prep_batch_compare(struct dsa_batch *batch, int idx, int n,
		uint64_t src1, uint64_t src2, size_t len, unsigned long dflags);
void dsa_prep_batch_compval(struct dsa_batch *batch, int idx, int n,
		uint64_t val, uint64_t src, size_t len, unsigned long dflags);
void dsa_prep_batch_dualcast(struct dsa_batch *batch, int idx, int n,
		uint64_t dst1, uint64_t dst2, uint64_t src, size_t len,
		unsigned long dflags);
int dsa_wait_batch(struct dsa_context *ctx, struct dsa_ring_ent *desc,
		dsa_completion_t *c, int idx, int num_descs);

void dsa_free(struct dsa_context *ctx);

struct dsa_batch *dsa_alloc_batch_buffers(struct dsa_context *ctx,
			int num_descs);
void dsa_free_batch_buffers(struct dsa_batch *batch);

void dsa_prep_submit_batch(struct dsa_batch *batch, int idx, int n,
		struct dsa_ring_ent *desc, unsigned long desc_flags);

void dsa_prep_desc_common(struct dsa_hw_desc *hw, char opcode,
		uint64_t dest, uint64_t src, size_t len, unsigned long dflags);

struct dsa_ring_ent *dsa_reserve_space(struct dsa_context *ctx, int n);
void dsa_free_desc(struct dsa_context *ctx, struct dsa_ring_ent *desc);
#endif
