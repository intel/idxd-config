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
#include "accel_test.h"
#include "iaa.h"

/* mismatch_expected: expect mismatched buffer with success status 0x1 */
int iax_task_result_verify(struct task *tsk, int mismatch_expected)
{
	info("verifying task result for %#lx\n", tsk);

	if (tsk->comp->status != IAX_COMP_SUCCESS)
		return tsk->comp->status;

	info("test with op %d passed\n", tsk->opcode);

	return ACCTEST_STATUS_OK;
}
