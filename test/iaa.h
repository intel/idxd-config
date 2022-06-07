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
int iaa_zcompress16_multi_task_nodes(struct acctest_context *ctx);
int iaa_zdecompress16_multi_task_nodes(struct acctest_context *ctx);
int iaa_zcompress32_multi_task_nodes(struct acctest_context *ctx);
int iaa_zdecompress32_multi_task_nodes(struct acctest_context *ctx);
int iaa_compress_multi_task_nodes(struct acctest_context *ctx);

void iaa_prep_noop(struct task *tsk);
void iaa_prep_crc64(struct task *tsk);
void iaa_prep_zcompress16(struct task *tsk);
void iaa_prep_zdecompress16(struct task *tsk);
void iaa_prep_zcompress32(struct task *tsk);
void iaa_prep_zdecompress32(struct task *tsk);
void iaa_prep_compress(struct task *tsk);

int iaa_task_result_verify(struct task *tsk, int mismatch_expected);
int iaa_task_result_verify_task_nodes(struct acctest_context *ctx, int mismatch_expected);
int task_result_verify_crc64(struct task *tsk, int mismatch_expected);
int task_result_verify_zcompress16(struct task *tsk, int mismatch_expected);
int task_result_verify_zdecompress16(struct task *tsk, int mismatch_expected);
int task_result_verify_zcompress32(struct task *tsk, int mismatch_expected);
int task_result_verify_zdecompress32(struct task *tsk, int mismatch_expected);
int task_result_verify_compress(struct task *tsk, int mismatch_expected);

#endif
