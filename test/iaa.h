/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __TEST_IAA_H__
#define __TEST_IAA_H__
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "accel_test.h"
#include "accfg_test.h"

int init_task(struct task *tsk, int tflags, int opcode, unsigned long src1_xfer_size);

int iaa_noop_multi_task_nodes(struct acctest_context *ctx);
int iaa_crc64_multi_task_nodes(struct acctest_context *ctx);
int iaa_zcompress8_multi_task_nodes(struct acctest_context *ctx);
int iaa_zdecompress8_multi_task_nodes(struct acctest_context *ctx);
int iaa_zcompress16_multi_task_nodes(struct acctest_context *ctx);
int iaa_zdecompress16_multi_task_nodes(struct acctest_context *ctx);
int iaa_zcompress32_multi_task_nodes(struct acctest_context *ctx);
int iaa_zdecompress32_multi_task_nodes(struct acctest_context *ctx);
int iaa_compress_multi_task_nodes(struct acctest_context *ctx);
int iaa_decompress_multi_task_nodes(struct acctest_context *ctx);
int iaa_scan_multi_task_nodes(struct acctest_context *ctx);
int iaa_set_membership_multi_task_nodes(struct acctest_context *ctx);
int iaa_extract_multi_task_nodes(struct acctest_context *ctx);
int iaa_select_multi_task_nodes(struct acctest_context *ctx);
int iaa_rle_burst_multi_task_nodes(struct acctest_context *ctx);
int iaa_find_unique_multi_task_nodes(struct acctest_context *ctx);
int iaa_expand_multi_task_nodes(struct acctest_context *ctx);
int iaa_transl_fetch_multi_task_nodes(struct acctest_context *ctx);
int iaa_encrypto_multi_task_nodes(struct acctest_context *ctx);
int iaa_decrypto_multi_task_nodes(struct acctest_context *ctx);

void iaa_prep_noop(struct task *tsk);
void iaa_prep_crc64(struct task *tsk);
void iaa_prep_zcompress8(struct task *tsk);
void iaa_prep_zdecompress8(struct task *tsk);
void iaa_prep_zcompress16(struct task *tsk);
void iaa_prep_zdecompress16(struct task *tsk);
void iaa_prep_zcompress32(struct task *tsk);
void iaa_prep_zdecompress32(struct task *tsk);
void iaa_prep_compress(struct task *tsk);
void iaa_prep_decompress(struct task *tsk);
void iaa_prep_scan(struct task *tsk);
void iaa_prep_set_membership(struct task *tsk);
void iaa_prep_extract(struct task *tsk);
void iaa_prep_select(struct task *tsk);
void iaa_prep_rle_burst(struct task *tsk);
void iaa_prep_find_unique(struct task *tsk);
void iaa_prep_expand(struct task *tsk);
void iaa_prep_transl_fetch(struct task *tsk);
void iaa_prep_encrypto(struct task *tsk);
void iaa_prep_decrypto(struct task *tsk);

int iaa_task_result_verify(struct task *tsk, int mismatch_expected);
int iaa_task_result_verify_task_nodes(struct acctest_context *ctx, int mismatch_expected);
int task_result_verify_crc64(struct task *tsk, int mismatch_expected);
int task_result_verify_zcompress8(struct task *tsk, int mismatch_expected);
int task_result_verify_zdecompress8(struct task *tsk, int mismatch_expected);
int task_result_verify_zcompress16(struct task *tsk, int mismatch_expected);
int task_result_verify_zdecompress16(struct task *tsk, int mismatch_expected);
int task_result_verify_zcompress32(struct task *tsk, int mismatch_expected);
int task_result_verify_zdecompress32(struct task *tsk, int mismatch_expected);
int task_result_verify_compress(struct task *tsk, int mismatch_expected);
int task_result_verify_decompress(struct task *tsk, int mismatch_expected);
int task_result_verify_scan(struct task *tsk, int mismatch_expected);
int task_result_verify_set_membership(struct task *tsk, int mismatch_expected);
int task_result_verify_extract(struct task *tsk, int mismatch_expected);
int task_result_verify_select(struct task *tsk, int mismatch_expected);
int task_result_verify_rle_burst(struct task *tsk, int mismatch_expected);
int task_result_verify_find_unique(struct task *tsk, int mismatch_expected);
int task_result_verify_expand(struct task *tsk, int mismatch_expected);
int task_result_verify_transl_fetch(struct task *tsk, int mismatch_expected);
int task_result_verify_encrypto(struct task *tsk, int mismatch_expected);
int task_result_verify_decrypto(struct task *tsk, int mismatch_expected);

#endif
