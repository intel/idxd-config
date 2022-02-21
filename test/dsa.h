/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __TEST_DSA_H__
#define __TEST_DSA_H__
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "accfg_test.h"

#define MAX_PATH_LENGTH 1024

#define DSA_DEVICE_ID_NO_INPUT -1

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

#define ADDR_ALIGNMENT 32

#define MIN_DELTA_RECORD_SIZE 80
/* helper macro to get lower 6 bits (ret code) from completion status */
#define stat_val(status) ((status) & DSA_COMP_STAT_CODE_MASK)

extern unsigned int ms_timeout;
extern int debug_logging;

/* metadata for single DSA task */
struct task {
	struct dsa_hw_desc *desc;
	struct dsa_completion_record *comp;
	uint32_t opcode;
	void *src1;
	void *src2;
	void *dst1;
	void *dst2;
	void *delta1;
	uint64_t pattern;
	uint64_t pattern2;
	uint64_t xfer_size;
	uint32_t dflags;
	int test_flags;
};

struct task_node {
	struct task *tsk;
	struct task_node *next;
};

/* metadata for batch DSA task */
struct batch_task {
	struct task *core_task;     /* core task with batch opcode 0x1*/
	struct task *sub_tasks;     /* array of sub-tasks in the batch */
	struct dsa_hw_desc *sub_descs;              /* for sub-tasks */
	struct dsa_completion_record *sub_comps;    /* for sub-tasks */
	int task_num;
	int test_flags;
};

struct btask_node {
	struct batch_task *btsk;
	struct btask_node *next;
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
	int threshold;
	int dedicated;
	int bof;
	unsigned int wq_max_batch_size;
	unsigned long wq_max_xfer_size;
	int ats_disable;

	int is_batch;
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

/* Dump DSA hardware descriptor to log */
static inline void dump_desc(struct dsa_hw_desc *hw)
{
	struct dsa_raw_desc *rhw = (void *)hw;
	int i;

	dbg("desc addr: %p\n", hw);

	for (i = 0; i < 8; i++)
		dbg("desc[%d]: 0x%016lx\n", i, rhw->field[i]);
}

/* dump all sub descriptors for a batch task */
static inline void dump_sub_desc(struct batch_task *btsk)
{
	int i;

	for (i = 0; i < btsk->task_num; i++) {
		dbg("sub_desc[%d]:\n", i);
		dump_desc(btsk->sub_tasks[i].desc);
	}
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

/* dump all sub completion records for a batch task */
static inline void dump_sub_compl_rec(struct batch_task *btsk)
{
	int i;

	for (i = 0; i < btsk->task_num; i++) {
		dbg("sub_comp[%d]:\n", i);
		dump_compl_rec(btsk->sub_tasks[i].comp);
	}
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

void memset_pattern(void *dst, uint64_t pattern, size_t len);
int memcmp_pattern(const void *src, const uint64_t pattern, size_t len);
int dsa_enqcmd(struct dsa_context *ctx, struct dsa_hw_desc *hw);

struct dsa_context *dsa_init(void);
int dsa_alloc(struct dsa_context *ctx, int shared, int dev_id, int wq_id);
int alloc_multiple_tasks(struct dsa_context *ctx, int num_itr);
struct task *__alloc_task(void);
int init_memcpy(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_memfill(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_compare(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_compval(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dualcast(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_cr_delta(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_task(struct task *tsk, int tflags, int opcode,
	      unsigned long xfer_size);

int dsa_noop_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_noop(struct dsa_context *ctx, struct task *tsk);

int dsa_drain_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_drain(struct dsa_context *ctx, struct task *tsk);

int dsa_memcpy_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_memcpy(struct dsa_context *ctx, struct task *tsk);

int dsa_memfill_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_memfill(struct dsa_context *ctx, struct task *tsk);

int dsa_compare_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_compare(struct dsa_context *ctx, struct task *tsk);

int dsa_compval_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_compval(struct dsa_context *ctx, struct task *tsk);

int dsa_dualcast_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_dualcast(struct dsa_context *ctx, struct task *tsk);

int dsa_cr_delta_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_cr_delta(struct dsa_context *ctx, struct task *tsk);

int dsa_ap_delta_multi_task_nodes(struct dsa_context *ctx);
int dsa_wait_ap_delta(struct dsa_context *ctx, struct task *tsk);

void dsa_prep_noop(struct task *tsk);
void dsa_prep_drain(struct task *tsk);
void dsa_prep_memcpy(struct task *tsk);
void dsa_reprep_memcpy(struct dsa_context *ctx, struct task *tsk);
void dsa_prep_memfill(struct task *tsk);
void dsa_reprep_memfill(struct dsa_context *ctx, struct task *tsk);
void dsa_prep_compare(struct task *tsk);
void dsa_reprep_compare(struct dsa_context *ctx, struct task *tsk);
void dsa_prep_compval(struct task *tsk);
void dsa_reprep_compval(struct dsa_context *ctx, struct task *tsk);
void dsa_prep_dualcast(struct task *tsk);
void dsa_reprep_dualcast(struct dsa_context *ctx, struct task *tsk);
void dsa_prep_cr_delta(struct task *tsk);
void dsa_reprep_cr_delta(struct dsa_context *ctx, struct task *tsk);
void dsa_prep_ap_delta(struct task *tsk);
void dsa_reprep_ap_delta(struct dsa_context *ctx, struct task *tsk);

int task_result_verify(struct task *tsk, int mismatch_expected);
int task_result_verify_task_nodes(struct dsa_context *ctx, int mismatch_expected);
int task_result_verify_memcpy(struct task *tsk, int mismatch_expected);
int task_result_verify_memfill(struct task *tsk, int mismatch_expected);
int task_result_verify_compare(struct task *tsk, int mismatch_expected);
int task_result_verify_compval(struct task *tsk, int mismatch_expected);
int task_result_verify_dualcast(struct task *tsk, int mismatch_expected);
int task_result_verify_ap_delta(struct task *tsk, int mismatch_expected);
int batch_result_verify(struct batch_task *btsk, int bof);

int alloc_batch_task(struct dsa_context *ctx, unsigned int task_num, int num_itr);
int init_batch_task(struct batch_task *btsk, int task_num, int tflags,
		    int opcode, unsigned long xfer_size, unsigned long dflags);

void dsa_prep_batch(struct batch_task *btsk, unsigned long desc_flags);
void dsa_prep_batch_noop(struct batch_task *btsk);
void dsa_prep_batch_memcpy(struct batch_task *btsk);
void dsa_prep_batch_memfill(struct batch_task *btsk);
void dsa_prep_batch_compare(struct batch_task *btsk);
void dsa_prep_batch_compval(struct batch_task *btsk);
void dsa_prep_batch_dualcast(struct batch_task *btsk);
void dsa_prep_batch_cr_delta(struct batch_task *btsk);
void dsa_prep_batch_ap_delta(struct batch_task *btsk);
int dsa_wait_batch(struct batch_task *btsk);

void dsa_free(struct dsa_context *ctx);
void dsa_free_task(struct dsa_context *ctx);
void free_task(struct task *tsk);
void __clean_task(struct task *tsk);
void free_batch_task(struct batch_task *btsk);

void dsa_prep_desc_common(struct dsa_hw_desc *hw, char opcode,
			  uint64_t dest, uint64_t src, size_t len, unsigned long dflags);
void dsa_desc_submit(struct dsa_context *ctx, struct dsa_hw_desc *hw);
#endif
