/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __TEST_IAX_H__
#define __TEST_IAX_H__
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "accel_test.h"
#include "accfg_test.h"

int iax_noop_multi_task_nodes(struct acctest_context *ctx);

void iax_prep_noop(struct task *tsk);

int iax_task_result_verify(struct task *tsk, int mismatch_expected);

#endif
