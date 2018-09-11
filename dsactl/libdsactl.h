/*
 * Copyright (c) 2014-2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 */
#ifndef _LIBDSACTL_H_
#define _LIBDSACTL_H_

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BUF_LEN 64

/* no need to save device state */
enum dsactl_device_state {
	DSACTL_DEVICE_DISABLED = 0,
	DSACTL_DEVICE_ENABLED,
};

enum dsactl_wq_mode {
	DSACTL_WQ_SHARED = 0,
	DSACTL_WQ_DEDICATED,
};

enum dsactl_wq_state {
	DSACTL_WQ_DISABLED = 0,
	DSACTL_WQ_ENABLED,
	DSACTL_WQ_QUIESCING,
};

/* no need to save device error */
struct dsactl_error {
        uint64_t val[4];
};

int str_to_int(char *buf);
struct dsactl_ctx;
struct dsactl_ctx *dsactl_ref(struct dsactl_ctx *ctx);
struct dsactl_ctx *dsactl_unref(struct dsactl_ctx *ctx);
int dsactl_new(struct dsactl_ctx **ctx);
void dsactl_set_log_fn(struct dsactl_ctx *ctx,
void (*log_fn) (struct dsactl_ctx * ctx,
	       int priority, const char *file,
	       int line, const char *fn,
	       const char *format,
	       va_list args));
int dsactl_get_log_priority(struct dsactl_ctx *ctx);
void dsactl_set_log_priority(struct dsactl_ctx *ctx, int priority);

/* helper function for sysfs read*/
long get_param_long(int dfd, char *name);
unsigned long long get_param_unsigned_llong(int dfd, char *name);
char *get_param_str(int dfd, char *name);

/* libdsactl function for device */
struct dsactl_device;
struct dsactl_device *dsactl_device_get_first(struct dsactl_ctx *ctx);
struct dsactl_device *dsactl_device_get_next(struct dsactl_device *device);
#define dsactl_device_foreach(ctx, device) \
        for (device = dsactl_device_get_first(ctx); \
             device != NULL; \
             device = dsactl_device_get_next(device))
struct dsactl_ctx *dsactl_device_get_ctx(struct dsactl_device *);
const char *dsactl_device_get_devname(struct dsactl_device *device);
unsigned int dsactl_device_get_id(struct dsactl_device *device);
unsigned int dsactl_device_get_max_groups(struct dsactl_device *device);
unsigned int dsactl_device_get_max_work_queues(struct dsactl_device *device);
unsigned int dsactl_device_get_max_engines(struct dsactl_device *device);
unsigned int dsactl_device_get_max_work_queues_size(struct dsactl_device *device);
int dsactl_device_get_numa_node(struct dsactl_device *device);
unsigned int dsactl_device_get_ims_size(struct dsactl_device *device);
unsigned int dsactl_device_get_max_batch_size(struct dsactl_device *device);
unsigned long dsactl_device_get_max_transfer_size(struct dsactl_device *device);
unsigned long dsactl_device_get_op_cap(struct dsactl_device *device);
unsigned int dsactl_device_get_configurable(struct dsactl_device *device);
bool dsactl_device_get_pasid_enabled(struct dsactl_device  *device);
int dsactl_device_get_errors(struct dsactl_device *device, struct dsactl_error *error);
enum dsactl_device_state dsactl_device_get_state(struct dsactl_device *device);
unsigned int dsactl_device_get_max_tokens(struct dsactl_device *device);
unsigned int dsactl_device_get_max_batch_size(struct dsactl_device *device);
unsigned int dsactl_device_get_token_limit(struct dsactl_device *device);
int dsactl_device_is_active(struct dsactl_device *device);

/* libdsactl function for group */
struct dsactl_group;
struct dsactl_group *dsactl_group_get_first(struct dsactl_device *device);
struct dsactl_group *dsactl_group_get_next(struct dsactl_group *group);
#define dsactl_group_foreach(device, group) \
        for (group = dsactl_group_get_first(device); \
             group != NULL; \
             group = dsactl_group_get_next(group))
unsigned int dsactl_group_get_id(struct dsactl_group *group);
unsigned int dsactl_group_get_device_id(struct dsactl_group *group);
const char *dsactl_group_get_devname(struct dsactl_group *group);
unsigned long dsactl_group_get_size(struct dsactl_group *group);
unsigned long dsactl_group_get_available_size(struct dsactl_group *group);
struct dsactl_device *dsactl_group_get_device(struct dsactl_group *group);
struct dsactl_ctx *dsactl_group_get_ctx(struct dsactl_group *group);
int dsactl_group_get_numa_node(struct dsactl_group *group);
int dsactl_group_get_tokens_reserved(struct dsactl_group *group);
int dsactl_group_get_tokens_allowed(struct dsactl_group *group);
int dsactl_group_get_use_token_limit(struct dsactl_group *group);
int dsactl_group_get_traffic_class_a(struct dsactl_group *group);
int dsactl_group_get_traffic_class_b(struct dsactl_group *group);

/* libdsactl function for wq */
struct dsactl_wq;
struct dsactl_wq *dsactl_wq_get_first(struct dsactl_device *device);
struct dsactl_wq *dsactl_wq_get_next(struct dsactl_wq *wq);
#define dsactl_wq_foreach(device, wq) \
        for (wq = dsactl_wq_get_first(device); \
             wq != NULL; \
             wq = dsactl_wq_get_next(wq))
struct dsactl_ctx *dsactl_wq_get_ctx(struct dsactl_wq *wq);
struct dsactl_device *dsactl_wq_get_device(struct dsactl_wq *wq);
struct dsactl_group *dsactl_wq_get_group(struct dsactl_wq *wq);
unsigned int dsactl_wq_get_id(struct dsactl_wq *wq);
const char *dsactl_wq_get_devname(struct dsactl_wq *wq);
enum dsactl_wq_mode dsactl_wq_get_mode(struct dsactl_wq *wq);
unsigned long dsactl_wq_get_size(struct dsactl_wq *wq);
unsigned int dsactl_wq_get_group_id(struct dsactl_wq *wq);
unsigned int dsactl_wq_get_priority(struct dsactl_wq *wq);
unsigned int dsactl_wq_get_priv(struct dsactl_wq *wq);
bool dsactl_wq_get_block_on_fault(struct dsactl_wq *wq);
enum dsactl_wq_state dsactl_wq_get_state(struct dsactl_wq *wq);
unsigned int dsactl_wq_get_enforce_order(struct dsactl_wq *wq);
int dsactl_wq_is_enabled(struct dsactl_wq *wq);

/* libdsactl function for engine */
struct dsactl_engine;
struct dsactl_engine *dsactl_engine_get_first(struct dsactl_device *device);
struct dsactl_engine *dsactl_engine_get_next(struct dsactl_engine *dsaengine);
#define dsactl_engine_foreach(device, dsaengine) \
        for (dsaengine = dsactl_engine_get_first(device); \
             dsaengine != NULL; \
             dsaengine = dsactl_engine_get_next(dsaengine))
struct dsactl_ctx *dsactl_engine_get_ctx(struct dsactl_engine *dsaengine);
struct dsactl_device *dsactl_engine_get_device(struct dsactl_engine *dsaengine);
struct dsactl_group *dsactl_engine_get_group(struct dsactl_engine *dsaengine);
int dsactl_engine_get_group_id(struct dsactl_engine *dsaengine);
unsigned int dsactl_engine_get_id(struct dsactl_engine *dsaengine);
const char *dsactl_engine_get_devname(struct dsactl_engine *dsaengine);
#ifdef __cplusplus
}				/* extern "C" */
#endif
#endif
