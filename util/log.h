/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */

#ifndef __UTIL_LOG_H__
#define __UTIL_LOG_H__
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

struct log_ctx;
typedef void (*log_fn)(struct log_ctx *ctx, int priority, const char *file,
		int line, const char *fn, const char *format, va_list args);

struct log_ctx {
	log_fn log_fn;
	const char *owner;
	int log_priority;
};


void do_log(struct log_ctx *ctx, int priority, const char *file, int line,
		const char *fn, const char *format, ...)
	__attribute__((format(printf, 6, 7)));
void log_init(struct log_ctx *ctx, const char *owner, const char *log_env);
static inline void __attribute__((always_inline, format(printf, 2, 3)))
	log_null(struct log_ctx *ctx, const char *format, ...) {}

#define log_cond(ctx, prio, ...) \
do { \
	if ((ctx)->log_priority >= prio) \
		do_log(ctx, prio, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} while (0)

#ifdef ENABLE_LOGGING
#  ifdef ENABLE_DEBUG
#    define log_dbg(ctx, ...) log_cond(ctx, LOG_DEBUG, __VA_ARGS__)
#  else
#    define log_dbg(ctx, ...) log_null(ctx, __VA_ARGS__)
#  endif
#  define log_info(ctx, ...) log_cond(ctx, LOG_INFO, __VA_ARGS__)
#  define log_err(ctx, ...) log_cond(ctx, LOG_ERR,  __VA_ARGS__)
#  define log_notice(ctx, ...) log_cond(ctx, LOG_NOTICE, __VA_ARGS__)
#else
#  define log_dbg(ctx, ...) log_null(ctx, __VA_ARGS__)
#  define log_info(ctx, ...) log_null(ctx, __VA_ARGS__)
#  define log_err(ctx, ...) log_null(ctx, __VA_ARGS__)
#  define log_notice(ctx, ...) log_null(ctx, __VA_ARGS__)
#endif

#define dbg(x, ...) log_dbg(&(x)->ctx, __VA_ARGS__)
#define info(x, ...) log_info(&(x)->ctx, __VA_ARGS__)
#define err(x, ...) log_err(&(x)->ctx, __VA_ARGS__)
#define notice(x, ...) log_notice(&(x)->ctx, __VA_ARGS__)

#ifndef HAVE_SECURE_GETENV
#  ifdef HAVE___SECURE_GETENV
#    define secure_getenv __secure_getenv
#  else
#    warning neither secure_getenv nor __secure_getenv is available.
#    define secure_getenv getenv
#  endif
#endif

#endif /* __UTIL_LOG_H__ */
