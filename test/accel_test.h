/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __ACCEL_TEST_H__
#define __ACCEL_TEST_H__
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "accfg_test.h"

#pragma GCC diagnostic ignored "-Wpedantic"

#define SHARED 1
#define DEDICATED 0

#define ADDR_ALIGNMENT 32
#define MAX_PATH_LENGTH 1024

#define ACCTEST_DEVICE_ID_NO_INPUT -1

#define TEST_FLAGS_BOF     0x1     /* Block on page faults */
#define TEST_FLAGS_WAIT    0x4     /* Wait in kernel */
#define TEST_FLAGS_PREF    0x8     /* Pre-fault the buffers */
#define TEST_FLAGS_CPFLT   0x10    /* Gen fault on completion record */
#define TEST_FLAGS_BTFLT   0x20    /* Gen fault on batch desc. list */

#define PAGE_ALIGN(s)      ((((s) - 1) / 4096 + 1) * 4096)
#define ACCTEST_STATUS_OK    0x0
#define ACCTEST_STATUS_RETRY 0x1
#define ACCTEST_STATUS_FAIL  0x2
#define ACCTEST_STATUS_RPF   0x3
#define ACCTEST_STATUS_URPF  0x4
#define ACCTEST_STATUS_TIMEOUT 0x5

#define ACCTEST_CAP_BLOCK_ON_FAULT                  0x0000000000000001
#define ACCTEST_CAP_OVERLAP_COPY                    0x0000000000000002
#define ACCTEST_CAP_CACHE_MEM_CTRL                  0x0000000000000004
#define ACCTEST_CAP_CACHE_FLUSH_CTRL                0x0000000000000008
#define ACCTEST_CAP_DEST_RDBACK                     0x0000000000000100
#define ACCTEST_CAP_DUR_WRITE                       0x0000000000000200

#define ACCTEST_CAP_MAX_XFER_MASK                   0x00000000001F0000
#define ACCTEST_CAP_MAX_XFER_SHIFT                  16

#define ACCTEST_COMP_STAT_CODE_MASK                 0x3F
#define ACCTEST_COMP_STAT_RW_MASK                   0x80

/* helper macro to get lower 6 bits (ret code) from completion status */
#define stat_val(status) ((status) & ACCTEST_COMP_STAT_CODE_MASK)

extern unsigned int ms_timeout;
extern int debug_logging;

struct task {
	struct hw_desc *desc;
	struct completion_record *comp;
	uint32_t opcode;
	void *src1;
	void *src2;
	void *dst1;
	void *dst2;
	void *delta1;
	void *input;
	void *output;
	int input_size;
	uint64_t pattern;
	uint64_t pattern2;
	uint64_t xfer_size;
	uint32_t dflags;
	int test_flags;
	int crc_seed;
	unsigned long long *crc_seed_addr;
	int reftag;
	int apptag;
	int guardtag;
	unsigned long blks;
	int blk_idx_flg;

	/* Dedicate for IAA test */
	union {
		uint16_t iaa_compr_flags;
		uint16_t iaa_decompr_flags;
		uint16_t iaa_crc64_flags;
		uint16_t iaa_cipher_flags;
	};
	uint32_t iaa_max_dst_size;
	uint32_t iaa_src2_xfer_size;
	union {
		struct {
			uint32_t iaa_filter_flags;
			uint32_t iaa_num_inputs;
		};
		uint64_t iaa_crc64_poly;
	};
	struct {
		uint8_t algorithm;
		uint8_t flags;
	} crypto_aecs;
};

struct task_node {
	struct task *tsk;
	struct task_node *next;
};

struct batch_desc_info {
	int bc_fault;
	int bc_wr_fail;
	int da_fault;
	unsigned short da_fault_idx;
	unsigned char result;
	unsigned char status;
	unsigned short desc_completed;
};

struct desc_info {
	int desc_fault; /* desc src/dst generates page fault */
	int cp_fault;	/* cp generates page fault */
	int cp_wr_fail;	/* driver fails to write cp rec to application */
	int fence;	/* desc has fence flag */
};

struct evl_desc_list {
	struct batch_desc_info bdi;
	struct desc_info di[0];
};

/* metadata for batch DSA task */
struct batch_task {
	struct task *core_task;     /* core task with batch opcode 0x1*/
	struct task *sub_tasks;     /* array of sub-tasks in the batch */
	struct hw_desc *sub_descs;              /* for sub-tasks */
	struct completion_record *sub_comps;    /* for sub-tasks */
	struct evl_desc_list *edl;
	int task_num;
	int test_flags;
};

struct btask_node {
	struct batch_task *btsk;
	struct btask_node *next;
};

struct acctest_context {
	struct accfg_ctx *ctx;
	struct accfg_wq *wq;

	unsigned int max_batch_size;
	unsigned int max_xfer_size;
	unsigned int max_xfer_bits;
	unsigned int compl_size;

	int fd;
	int wq_idx;
	void *wq_reg;
	int wq_size;
	int threshold;
	int dedicated;
	int bof;
	unsigned int wq_max_batch_size;
	unsigned long wq_max_xfer_size;
	int ats_disable;
	enum accfg_device_type dev_type;

	int is_batch;
	int is_evl_test;
	union {
		struct task_node *multi_task_node;
		struct btask_node *multi_btask_node;
	};
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

/* Dump hardware descriptor to log */
static inline void dump_desc(struct hw_desc *hw)
{
	struct raw_desc *rhw = (void *)hw;
	int i;

	dbg("desc addr: %p\n", hw);

	for (i = 0; i < 8; i++)
		dbg("desc[%d]: 0x%016lx\n", i, rhw->field[i]);
}

/* Dump completion record to log */
static inline void dump_compl_rec(struct completion_record *compl, int compl_size)
{
	int i;
	struct raw_completion_record *rcompl = (void *)compl;
	int num_qword = compl_size / sizeof(uint64_t);

	dbg("completion record addr: %p\n", compl);

	/* To be compatible with IAX, completion record was allocated 64 bytes*/
	for (i = 0; i < num_qword; i++)
		dbg("compl[%d]: 0x%016lx\n", i, rcompl->field[i]);
}

/* Dump src2 to log */
static inline void dump_src2(void *src2, int src2_size)
{
	int i;
	uint32_t *raw = (uint32_t *)src2;

	dbg("src2 addr: %p\n", src2);

	for (i = 0; i < (src2_size / 4); i++)
		dbg("src2[0x%X]: 0x%08x\n", i * 4, raw[i]);
}

static inline void resolve_page_fault(uint64_t addr, uint8_t status)
{
	uint8_t *addr_u8 = (uint8_t *)addr;

	/* This line solve the PF by writing to the address.*/
	/* For PF at write, we can change the value as the address will be */
	/* overwritten again by the HW */
	*addr_u8 =  ~(*addr_u8);

	/* For PF at read, we need to restore it to the original value */
	if (!(status & ACCTEST_COMP_STAT_RW_MASK))
		*addr_u8 = ~(*addr_u8);
}

int get_random_value(void);
struct acctest_context *acctest_init(int tflags);
int acctest_alloc(struct acctest_context *ctx, int shared, int dev_id, int wq_id);
int acctest_alloc_multiple_tasks(struct acctest_context *ctx, int num_itr);
struct task *acctest_alloc_task(struct acctest_context *ctx);

int acctest_wait_on_desc_timeout(struct completion_record *comp,
				 struct acctest_context *ctx,
				 unsigned int msec_timeout);

void memset_pattern(void *dst, uint64_t pattern, size_t len);
int memcmp_pattern(const void *src, const uint64_t pattern, size_t len);

void acctest_free(struct acctest_context *ctx);
void acctest_free_task(struct acctest_context *ctx);
void free_task(struct task *tsk);
void __clean_task(struct task *tsk);
void free_batch_task(struct batch_task *btsk);

void acctest_prep_desc_common(struct hw_desc *hw, char opcode,
			      uint64_t dest, uint64_t src, size_t len, unsigned long dflags);
void acctest_desc_submit(struct acctest_context *ctx, struct hw_desc *hw);

#endif
