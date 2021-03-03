/*
 * Copyright(c) 2015-2019 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#ifndef __TEST_H__
#define __TEST_H__
#include <stdbool.h>

#define EXIT_SKIP 77
struct accfg_test;
struct accfg_ctx;
struct util_filter_ctx;
struct accfg_test *accfg_test_new(unsigned int kver);
int accfg_test_result(struct accfg_test *test, int rc);
int accfg_test_get_skipped(struct accfg_test *test);
int accfg_test_get_attempted(struct accfg_test *test);
int __accfg_test_attempt(struct accfg_test *test, unsigned int kver,
		const char *caller, int line);
#define accfg_test_attempt(t, v) __accfg_test_attempt(t, v, __func__, __LINE__)
void __accfg_test_skip(struct accfg_test *test, const char *caller, int line);
#define accfg_test_skip(t) __accfg_test_skip(t, __func__, __LINE__)
int test_libaccfg(int loglevel, struct accfg_test *test, struct accfg_ctx *ctx);
int device_enum(struct accfg_ctx *ctx, struct util_filter_ctx *fctx);
#endif /* __TEST_H__ */
