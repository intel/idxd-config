/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __TEST_DSA_H__
#define __TEST_DSA_H__
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "accfg_test.h"
#include "crc16_t10_lookup.h"

#define MAX_PATH_LENGTH 1024

#define ACCTEST_DEVICE_ID_NO_INPUT -1

#define DSA_MAX_OPS 0x20

#define TEST_FLAGS_BOF     0x1     /* Block on page faults */
#define TEST_FLAGS_NO_UMWAIT	0x2	/* Disable umwait usage */
#define TEST_FLAGS_WAIT    0x4     /* Wait in kernel */
#define TEST_FLAGS_PREF    0x8     /* Pre-fault the buffers */

#define ACCTEST_STATUS_OK    0x0
#define ACCTEST_STATUS_RETRY 0x1
#define ACCTEST_STATUS_FAIL  0x2
#define ACCTEST_STATUS_RPF   0x3
#define ACCTEST_STATUS_URPF  0x4
#define ACCTEST_STATUS_TIMEOUT 0x5

#define DSA_BATCH_OPCODES 0x278

#define ACCTEST_CAP_BLOCK_ON_FAULT                  0x0000000000000001
#define ACCTEST_CAP_OVERLAP_COPY                    0x0000000000000002
#define ACCTEST_CAP_CACHE_MEM_CTRL                  0x0000000000000004
#define ACCTEST_CAP_CACHE_FLUSH_CTRL                0x0000000000000008
#define ACCTEST_CAP_DEST_RDBACK                     0x0000000000000100
#define ACCTEST_CAP_DUR_WRITE                       0x0000000000000200

#define DSA_CAP_MAX_BATCH_MASK                  0x0000000001E00000
#define DSA_CAP_MAX_BATCH_SHIFT                 21

#define ACCTEST_CAP_MAX_XFER_MASK                   0x00000000001F0000
#define ACCTEST_CAP_MAX_XFER_SHIFT                  16

#define ACCTEST_COMP_STAT_CODE_MASK                 0x3F
#define ACCTEST_COMP_STAT_RW_MASK                   0x80

/* CRC Flags */
#define READ_CRC_SEED		((unsigned long)(1 << 16))
#define BYPASS_CRC_INV_REF	((unsigned long)(1 << 17))
#define BYPASS_DATA_REF		((unsigned long)(1 << 18))

/* DIF index */
#define DIF_BLK_GRD_1  0
#define DIF_BLK_GRD_2  1
#define DIF_APP_TAG_1  2
#define DIF_APP_TAG_2  3
#define DIF_REF_TAG_1  4
#define DIF_REF_TAG_2  5
#define DIF_REF_TAG_3  6
#define DIF_REF_TAG_4  7

#define DIF_INVERT_CRC_SEED         ((unsigned long)(1 << 2))
#define DIF_INVERT_CRC_RESULT       ((unsigned long)(1 << 3))

#define ADDR_ALIGNMENT 32

#define MIN_DELTA_RECORD_SIZE 80
/* helper macro to get lower 6 bits (ret code) from completion status */
#define stat_val(status) ((status) & ACCTEST_COMP_STAT_CODE_MASK)

extern unsigned int ms_timeout;
extern int debug_logging;

/* metadata for single DSA task */
struct task {
	struct hw_desc *desc;
	struct completion_record *comp;
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
	int crc_seed;
	unsigned long long *crc_seed_addr;
	int reftag;
	int apptag;
	int guardtag;
	unsigned long blks;
	int blk_idx_flg;

	/* Dedicate for IAA test */
	union {
		uint16_t iax_compr_flags;
		uint16_t iax_decompr_flags;
		uint16_t iax_crc64_flags;
	};
	uint32_t iax_max_dst_size;
	uint32_t iax_src2_xfer_size;
	union {
		struct {
			uint32_t iax_filter_flags;
			uint32_t iax_num_inputs;
		};
	uint64_t iax_crc64_poly;
	};
};

struct task_node {
	struct task *tsk;
	struct task_node *next;
};

/* metadata for batch DSA task */
struct batch_task {
	struct task *core_task;     /* core task with batch opcode 0x1*/
	struct task *sub_tasks;     /* array of sub-tasks in the batch */
	struct hw_desc *sub_descs;              /* for sub-tasks */
	struct completion_record *sub_comps;    /* for sub-tasks */
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
static inline void dump_desc(struct hw_desc *hw)
{
	struct raw_desc *rhw = (void *)hw;
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
static inline void dump_compl_rec(struct completion_record *compl, int compl_size)
{
	int i;
	struct raw_completion_record *rcompl = (void *)compl;
	int num_qword = compl_size / sizeof(uint64_t);

	dbg("completion record addr: %p\n", compl);

	for (i = 0; i < num_qword; i++)
		dbg("compl[%d]: 0x%016lx\n", i, rcompl->field[i]);
}

/* dump all sub completion records for a batch task */
static inline void dump_sub_compl_rec(struct batch_task *btsk, int compl_size)
{
	int i;

	for (i = 0; i < btsk->task_num; i++) {
		dbg("sub_comp[%d]:\n", i);
		dump_compl_rec(btsk->sub_tasks[i].comp, compl_size);
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
	if (!(status & ACCTEST_COMP_STAT_RW_MASK))
		*addr_u8 = ~(*addr_u8);
}

void memset_pattern(void *dst, uint64_t pattern, size_t len);
int memcmp_pattern(const void *src, const uint64_t pattern, size_t len);
int acctest_enqcmd(struct acctest_context *ctx, struct hw_desc *hw);

struct acctest_context *acctest_init(int tflags);
int acctest_alloc(struct acctest_context *ctx, int shared, int dev_id, int wq_id);
int acctest_alloc_multiple_tasks(struct acctest_context *ctx, int num_itr);
struct task *acctest_alloc_task(struct acctest_context *ctx);
int init_memcpy(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_memfill(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_compare(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_compval(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dualcast(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_cr_delta(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_crcgen(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_copy_crc(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dif_check(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dif_ins(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dif_strp(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_dif_updt(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_cflush(struct task *tsk, int tflags, int opcode, unsigned long xfer_size);
int init_task(struct task *tsk, int tflags, int opcode,
	      unsigned long xfer_size);

int dsa_noop_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_noop(struct acctest_context *ctx, struct task *tsk);

int dsa_drain_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_drain(struct acctest_context *ctx, struct task *tsk);

int dsa_memcpy_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_memcpy(struct acctest_context *ctx, struct task *tsk);

int dsa_memfill_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_memfill(struct acctest_context *ctx, struct task *tsk);

int dsa_compare_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_compare(struct acctest_context *ctx, struct task *tsk);

int dsa_compval_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_compval(struct acctest_context *ctx, struct task *tsk);

int dsa_dualcast_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_dualcast(struct acctest_context *ctx, struct task *tsk);

int dsa_cr_delta_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_cr_delta(struct acctest_context *ctx, struct task *tsk);

int dsa_ap_delta_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_ap_delta(struct acctest_context *ctx, struct task *tsk);

int dsa_crcgen_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_crcgen(struct acctest_context *ctx, struct task *tsk);

int dsa_crc_copy_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_crc_copy(struct acctest_context *ctx, struct task *tsk);

int dsa_dif_check_multi_task_nodes(struct acctest_context *ctx);
int dsa_dif_ins_multi_task_nodes(struct acctest_context *ctx);
int dsa_dif_strp_multi_task_nodes(struct acctest_context *ctx);
int dsa_dif_updt_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_dif(struct acctest_context *ctx, struct task *tsk);

int dsa_cflush_multi_task_nodes(struct acctest_context *ctx);
int dsa_wait_cflush(struct acctest_context *ctx, struct task *tsk);

void dsa_prep_noop(struct task *tsk);
void dsa_prep_drain(struct task *tsk);
void dsa_prep_memcpy(struct task *tsk);
void dsa_reprep_memcpy(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_memfill(struct task *tsk);
void dsa_reprep_memfill(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_compare(struct task *tsk);
void dsa_reprep_compare(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_compval(struct task *tsk);
void dsa_reprep_compval(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_dualcast(struct task *tsk);
void dsa_reprep_dualcast(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_cr_delta(struct task *tsk);
void dsa_reprep_cr_delta(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_ap_delta(struct task *tsk);
void dsa_reprep_ap_delta(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_crcgen(struct task *tsk);
void dsa_reprep_crcgen(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_crc_copy(struct task *tsk);
void dsa_reprep_crc_copy(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_dif_check(struct task *tsk);
void dsa_prep_dif_insert(struct task *tsk);
void dsa_prep_dif_strip(struct task *tsk);
void dsa_prep_dif_update(struct task *tsk);
void dsa_reprep_dif(struct acctest_context *ctx, struct task *tsk);
void dsa_prep_cflush(struct task *tsk);
void dsa_reprep_cflush(struct acctest_context *ctx, struct task *tsk);

int task_result_verify(struct task *tsk, int mismatch_expected);
int task_result_verify_task_nodes(struct acctest_context *ctx, int mismatch_expected);
int task_result_verify_memcpy(struct task *tsk, int mismatch_expected);
int task_result_verify_memfill(struct task *tsk, int mismatch_expected);
int task_result_verify_compare(struct task *tsk, int mismatch_expected);
int task_result_verify_compval(struct task *tsk, int mismatch_expected);
int task_result_verify_dualcast(struct task *tsk, int mismatch_expected);
int task_result_verify_ap_delta(struct task *tsk, int mismatch_expected);
int task_result_verify_crcgen(struct task *tsk, int mismatch_expected);
int task_result_verify_crc_copy(struct task *tsk, int mismatch_expected);
int task_result_verify_dif(struct task *tsk, unsigned long xfer_size, int mismatch_expected);
int task_result_verify_dif_tags(struct task *tsk, unsigned long xfer_size);
int batch_result_verify(struct batch_task *btsk, int bof);

int alloc_batch_task(struct acctest_context *ctx, unsigned int task_num, int num_itr);
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
void dsa_prep_batch_crcgen(struct batch_task *btsk);
void dsa_prep_batch_crc_copy(struct batch_task *btsk);
void dsa_prep_batch_dif_check(struct batch_task *btsk);
void dsa_prep_batch_dif_insert(struct batch_task *btsk);
void dsa_prep_batch_dif_strip(struct batch_task *btsk);
void dsa_prep_batch_dif_update(struct batch_task *btsk);
void dsa_prep_batch_cflush(struct batch_task *btsk);
int dsa_wait_batch(struct batch_task *btsk, struct acctest_context *ctx);

void acctest_free(struct acctest_context *ctx);
void acctest_free_task(struct acctest_context *ctx);
void free_task(struct task *tsk);
void __clean_task(struct task *tsk);
void free_batch_task(struct batch_task *btsk);

void acctest_prep_desc_common(struct hw_desc *hw, char opcode,
			      uint64_t dest, uint64_t src, size_t len, unsigned long dflags);
void acctest_desc_submit(struct acctest_context *ctx, struct hw_desc *hw);

uint16_t dsa_calculate_crc_t10dif(unsigned char *buffer, size_t len, int flags);
int get_dif_blksz_flg(unsigned long xfer_size);
unsigned long get_blks(unsigned long xfer_size);
#endif
