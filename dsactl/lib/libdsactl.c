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
#include <poll.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <ccan/list/list.h>
#include <ccan/minmax/minmax.h>
#include <ccan/array_size/array_size.h>
#include <ccan/build_assert/build_assert.h>
#include <util/sysfs.h>
#include <dsactl/libdsactl.h>
#include "private.h"

#define  MAX_PARAM_LEN 64

long get_param_long(int dfd, char *name)
{
	int fd = openat(dfd, name, O_RDONLY);
	char buf[MAX_PARAM_LEN + 1];
	int n;

	if (fd == -1) {
		fprintf(stderr, "get_param_long open %s failed: %s\n",
			name, strerror(errno));
		close(fd);
		return -errno;
	}
	n = read(fd, buf, MAX_PARAM_LEN);
	close(fd);
	if (n <= 0)
		return -ENXIO;
	if (buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	else
		buf[n] = '\0';

	return strtol(buf, NULL, 0);
}

unsigned long long get_param_unsigned_llong(int dfd, char *name)
{
	int fd = openat(dfd, name, O_RDONLY);
	char buf[MAX_PARAM_LEN + 1];
	int n;

	if (fd == -1) {
		fprintf(stderr, "get_param_unsigned_llong open %s failed: %s\n",
			name, strerror(errno));
		close(fd);
		return -errno;
	}
	n = read(fd, buf, MAX_PARAM_LEN);
	close(fd);
	if (n <= 0)
		return -ENXIO;
	if (buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	else
		buf[n] = '\0';

	return strtoull(buf, NULL, 0);
}

char *get_param_str(int dfd, char *name)
{
	int fd = openat(dfd, name, O_RDONLY);
	char buf[MAX_PARAM_LEN + 1];
	int n;

	if (fd == -1) {
		fprintf(stderr, "get_param_str open %s failed: %s\n",
			name, strerror(errno));
		close(fd);
		return 0;
	}
	n = read(fd, buf, MAX_PARAM_LEN);
	close(fd);
	if (n <= 0)
		return 0;
	if (buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	else
		buf[n] = '\0';

	return strdup(buf);
}

static void free_engine(struct dsactl_engine *dsaengine, struct list_head *head)
{
	if (head)
		list_del_from(head, &dsaengine->list);
	free(dsaengine->dsa_engine_path);
	free(dsaengine->dsa_engine_buf);
	free(dsaengine);
}

static void free_engines(struct dsactl_group *dsagroup)
{
	struct dsactl_engine *dsaengine, *next;

	list_for_each_safe(&dsagroup->engines, dsaengine, next, list)
	    free_engine(dsaengine, &dsagroup->engines);
}

static void free_wq(struct dsactl_wq *dsawq, struct list_head *head)
{
	if (head)
		list_del_from(head, &dsawq->list);
	free(dsawq->dsawq_path);
	free(dsawq->dsawq_buf);
	free(dsawq);
}

static void free_wqs(struct dsactl_group *dsagroup)
{
	struct dsactl_wq *dsawq, *next;

	list_for_each_safe(&dsagroup->wqs, dsawq, next, list)
	    free_wq(dsawq, &dsagroup->wqs);
}

static void free_group(struct dsactl_group *group)
{
	struct dsactl_device *device = group->device;

	free_wqs(group);
	free_engines(group);
	list_del_from(&device->groups, &group->list);
	free(group->group_buf);
	free(group->group_path);
	free(group);
}

static void free_device(struct dsactl_device *device, struct list_head *head)
{
	struct dsactl_group *group, *_r;

	list_for_each_safe(&device->groups, group, _r, list)
	    free_group(group);
	if (head)
		list_del_from(head, &device->list);
	free(device->device_path);
	free(device->device_buf);
	free(device);
}

static void free_context(struct dsactl_ctx *ctx)
{
	struct dsactl_device *device, *_b;

	list_for_each_safe(&ctx->devices, device, _b, list)
	    free_device(device, &ctx->devices);
	free(ctx);
}

DSACTL_EXPORT unsigned long dsactl_wq_get_size(struct dsactl_wq *dsawq)
{
	return dsawq->wq_size;
}

DSACTL_EXPORT enum dsactl_wq_mode dsactl_wq_get_mode(struct dsactl_wq *dsawq)
{
	enum dsactl_wq_mode wq_mode;
	char* read_mode;
	int dfd = open(dsawq->dsawq_path, O_PATH);

	read_mode = get_param_str(dfd, "mode");
	if(strcmp(read_mode, "shared") == 0) {
		wq_mode = 0;
		close(dfd);
		return wq_mode;
	} else {
		wq_mode = 1;
		close(dfd);
		return wq_mode;
	}
}

DSACTL_EXPORT int dsactl_engine_get_group_id(struct dsactl_engine *dsaengine)
{
	return dsaengine->group_id;
}

DSACTL_EXPORT const char *dsactl_engine_get_devname(struct dsactl_engine
						    *dsaengine)
{
	return devpath_to_devname(dsaengine->dsa_engine_path);
}

static int is_enabled(struct dsactl_device *device, const char *drvpath)
{
	struct stat st;
	struct dsactl_ctx *ctx = dsactl_device_get_ctx(device);

	if (lstat(drvpath, &st) < 0) {
		err(ctx, "find symbolic link of device failed\n");
		return 0;
	}
	else
		return 1;
}

DSACTL_EXPORT struct dsactl_ctx *dsactl_group_get_ctx(struct dsactl_group
						      *group)
{
	return group->device->ctx;
}

DSACTL_EXPORT int dsactl_wq_is_enabled(struct dsactl_wq *wq)
{
	struct dsactl_ctx *ctx = dsactl_wq_get_ctx(wq);
	char *path = wq->dsawq_buf;
	int len = wq->buf_len;

	if (snprintf(path, len, "%s/mode", wq->dsawq_path) >= len) {
		err(ctx, "%s: buffer too small!\n", dsactl_wq_get_devname(wq));
		return 0;
	}

	return is_enabled(dsactl_wq_get_device(wq), path);
}

/**
 * dsactl_new - instantiate a new library context
 * @ctx: context to establish
 *
 * Returns zero on success and stores an opaque pointer in ctx.  The
 * context is freed by dsactl_unref(), i.e. dsactl_new() implies an
 * internal dsactl_ref().
 */
DSACTL_EXPORT int dsactl_new(struct dsactl_ctx **ctx)
{
	struct dsactl_ctx *c;
	const char *env;
	int rc = 0;

	c = calloc(1, sizeof(struct dsactl_ctx));
	if (!c) {
		rc = -ENOMEM;
		return rc;
	}

	c->refcount = 1;
	log_init(&c->ctx, "libdsactl", "DSACTL_LOG");
	c->timeout = 5000;
	list_head_init(&c->devices);

	info(c, "ctx %p created\n", c);
	dbg(c, "log_priority=%d\n", c->ctx.log_priority);
	*ctx = c;

	env = secure_getenv("DSACTL_TIMEOUT");
	if (env != NULL) {
		unsigned long tmo;
		char *end;

		tmo = strtoul(env, &end, 0);
		if (tmo < ULONG_MAX && !end)
			c->timeout = tmo;
		dbg(c, "timeout = %ld\n", tmo);
	}

	return 0;
}

/**
 * dsactl_ref - take an additional reference on the context
 * @ctx: context established by dsactl_new()
 */
DSACTL_EXPORT struct dsactl_ctx *dsactl_ref(struct dsactl_ctx *ctx)
{
	if (ctx == NULL)
		return NULL;
	ctx->refcount++;
	return ctx;
}

/**
 * dsactl_unref - drop a context reference count
 * @ctx: context established by dsactl_new()
 *
 * Drop a reference and if the resulting reference count is 0 destroy
 * the context.
 */
DSACTL_EXPORT struct dsactl_ctx *dsactl_unref(struct dsactl_ctx *ctx)
{
	if (ctx == NULL)
		return NULL;
	ctx->refcount--;
	if (ctx->refcount > 0)
		return NULL;
	info(ctx, "context %p released\n", ctx);
	free_context(ctx);
	return NULL;
}

/**
 * dsactl_set_log_fn - override default log routine
 * @ctx: dsactl library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be overridden by a
 * custom function, to plug log messages into the user's logging
 * functionality.
 */
DSACTL_EXPORT void dsactl_set_log_fn(struct dsactl_ctx *ctx,
				     void (*dsactl_log_fn) (struct dsactl_ctx *
							    ctx, int priority,
							    const char *file,
							    int line,
							    const char *fn,
							    const char *format,
							    va_list args))
{
	ctx->ctx.log_fn = (log_fn) dsactl_log_fn;
	info(ctx, "ctx is %p, custom logging function %p registered\n", ctx,
	     dsactl_log_fn);
}

/**
 * dsactl_get_log_priority - retrieve current library loglevel (syslog)
 * @ctx: dsactl library context
 */
DSACTL_EXPORT int dsactl_get_log_priority(struct dsactl_ctx *ctx)
{
	return ctx->ctx.log_priority;
}

/**
 * dsactl_set_log_priority - set log verbosity
 * @priority: from syslog.h, LOG_ERR, LOG_INFO, LOG_DEBUG
 *
 * Note: LOG_DEBUG requires library be built with "configure --enable-debug"
 */
DSACTL_EXPORT void dsactl_set_log_priority(struct dsactl_ctx *ctx, int priority)
{
	ctx->ctx.log_priority = priority;
}

static int device_parse(struct dsactl_ctx *ctx, struct dsactl_device *device,
			const char *base_path, const char *dev_name,
			void *parent, add_dev_fn add_dev)
{
	return sysfs_device_parse(ctx, base_path, dev_name, parent, add_dev);
}

/* Translate function to convert string into integer type */
int str_to_int(char *buf)
{
	if (strcmp(buf, "false") == 0) {
		return 0;
	} else if (strcmp(buf, "true") == 0) {
		return 1;
	}
	return 0;
}

static void *add_device(void *parent, int id, const char *ctl_base)
{
	struct dsactl_ctx *ctx = parent;
	struct dsactl_device *device;
	char *path = calloc(1, strlen(ctl_base) + 100);
	int dfd = open(ctl_base, O_PATH);

	if (!path) {
		err(ctx, "allocation of path in add_device failed\n");
		return NULL;
	}
	/* Only one device so far, device DSA0 */
	device = calloc(1, sizeof(*device));
	if (!device) {
		err(ctx, "allocation of device failed\n");
		goto err_device;
	}

	list_head_init(&device->groups);
	list_head_init(&device->wqs);
	list_head_init(&device->engines);

	device->ctx = ctx;
	device->id = id;
	device->max_groups = get_param_long(dfd, "max_groups");
	device->max_work_queues = get_param_long(dfd, "max_work_queues");
	device->max_engines = get_param_long(dfd, "max_engines");
	device->max_work_queues_size =
	    get_param_long(dfd, "max_work_queues_size");
	device->numa_node = get_param_long(dfd, "numa_node");
	device->ims_size = get_param_long(dfd, "ims_size");
	device->max_batch_size = get_param_long(dfd, "max_batch_size");
	device->max_transfer_size =
	    get_param_unsigned_llong(dfd, "max_transfer_size");
	device->opcap = get_param_unsigned_llong(dfd, "op_cap");
	device->configurable = get_param_unsigned_llong(dfd, "configurable");
	device->pasid_enabled = get_param_str(dfd, "pasid_enabled");
	device->max_tokens = get_param_long(dfd, "max_tokens");
	device->token_limit = get_param_long(dfd, "token_limit");
	device->device_path = realpath(ctl_base, NULL);
	close(dfd);
	if (!device->device_path) {
		err(ctx, "get realpath of device_path failed\n");
		goto err_dev_path;
	}

	device->device_buf = calloc(1, strlen(device->device_path) + 50);
	if (!device->device_buf) {
		err(ctx, "allocation of device buffer failed\n");
		goto err_read;
	}

	device->buf_len = strlen(device->device_path) + 50;

	list_add(&ctx->devices, &device->list);
	free(path);
	return device;

err_dev_path:
err_read:
	free(device->device_buf);
	free(device);
err_device:
	free(path);

	return NULL;
}

static void *add_wq(void *parent, int id, const char *dsawq_base)
{
	struct dsactl_wq *dsawq;
	struct dsactl_device *device = parent;
	struct dsactl_group *group = device->group;
	struct dsactl_ctx *ctx = dsactl_device_get_ctx(device);
	char *path = calloc(1, strlen(dsawq_base) + 100);
	int dfd = open(dsawq_base, O_PATH);

	if (!path) {
		err(ctx, "allocation of path in add_wq failed\n");
		return NULL;
	}

	dsawq = calloc(1, sizeof(*dsawq));
	if (!dsawq) {
		err(ctx, "allocation of dsa wq failed\n");
		free(path);
		return NULL;
	}

	dsawq->id = id;
	dsawq->group = group;
	dsawq->device = device;
	dsawq->group_id = get_param_long(dfd, "group_id");
	dsawq->wq_size = get_param_long(dfd, "size");
	dsawq->priority = get_param_long(dfd, "priority");
	dsawq->enforce_order = get_param_long(dfd, "enforce_order");
	dsawq->block_on_fault = get_param_long(dfd, "block_on_fault");
	dsawq->mode = get_param_str(dfd, "mode");
	dsawq->state = get_param_str(dfd, "state");

	close(dfd);
	dsawq->dsawq_path = strdup(dsawq_base);
	if (!dsawq->dsawq_path) {
		err(ctx, "forming of dsa wq path failed\n");
		goto err_read;
	}

	dsawq->dsawq_buf = calloc(1, strlen(dsawq_base) + 50);
	if (!dsawq->dsawq_buf) {
		err(ctx, "allocation of dsa wq buffer failed\n");
		goto err_read;
	}
	dsawq->buf_len = strlen(dsawq_base) + 50;

	list_add(&device->wqs, &dsawq->list);
	free(path);
	return dsawq;

err_read:
	free(dsawq->dsawq_buf);
	free(dsawq->dsawq_path);
	free(dsawq);
	return NULL;
}

static void *add_group(void *parent, int id, const char *group_base)
{
	struct dsactl_group *group;
	struct dsactl_device *device = parent;
	struct dsactl_ctx *ctx = dsactl_device_get_ctx(device);
	char *path = calloc(1, strlen(group_base) + 100);
	int dfd = open(group_base, O_PATH);

	if (!path) {
		err(ctx, "allocation of path in add_group failed\n");
		return NULL;
	}
	group = calloc(1, sizeof(*group));
	if (!group) {
		err(ctx, "allocation of dsa group failed\n");
		goto err_group;
	}

	group->group_path = (char *)group_base;
	group->device = device;
	device->group = group;
	group->id = id;
	group->group_engines = get_param_str(dfd, "engines");
	group->group_wqs = get_param_str(dfd, "work_queues");
	group->tokens_reserved = get_param_long(dfd, "tokens_reserved");
	group->tokens_allowed = get_param_long(dfd, "tokens_allowed");
	group->use_token_limit = get_param_long(dfd, "use_token_limit");
	group->traffic_class_a = get_param_long(dfd, "traffic_class_a");
	group->traffic_class_b = get_param_long(dfd, "traffic_class_b");

	close(dfd);
	group->group_buf = calloc(1, strlen(group_base) + 50);
	if (!group->group_buf) {
		err(ctx, "allocation of group buffere failed\n");
		goto err_read;
	}
	group->buf_len = strlen(group_base) + 50;

	group->group_path = strdup(group_base);
	if (!group->group_path) {
		err(ctx, "forming of group path failed\n");
		goto err_read;
	}

	list_add(&device->groups, &group->list);
	free(path);
	return group;

err_read:
	free(group->group_buf);
	free(group);
err_group:
	free(path);
	return NULL;
}

static void *add_engine(void *parent, int id, const char *dsaengine_base)
{
	struct dsactl_engine *dsaengine;
	struct dsactl_device *device = parent;
	struct dsactl_ctx *ctx = dsactl_device_get_ctx(device);
	struct dsactl_group *group = device->group;
	char *path = calloc(1, strlen(dsaengine_base) + 100);
	int dfd = open(dsaengine_base, O_PATH);

	if (!path) {
		err(ctx, "allocation of path in add_engine failed\n");
		return NULL;
	}

	dsaengine = calloc(1, sizeof(*dsaengine));
	if (!dsaengine) {
		err(ctx, "allocation of dsa engine failed\n");
		goto err_engine;
	}

	dsaengine->id = id;
	dsaengine->group = group;
	dsaengine->device = device;
	dsaengine->group_id = get_param_long(dfd, "group_id");
	close(dfd);

	dsaengine->dsa_engine_path = strdup(dsaengine_base);
	if (!dsaengine->dsa_engine_path) {
		err(ctx, "forming of dsa engine path failed\n");
		goto err_read;
	}

	dsaengine->dsa_engine_buf = calloc(1, strlen(dsaengine_base) + 50);
	if (!dsaengine->dsa_engine_buf) {
		err(ctx, "allocation of dsa engine buffer failed\n");
		goto err_read;
	}
	dsaengine->buf_len = strlen(dsaengine_base) + 50;

	list_add(&device->engines, &dsaengine->list);
	free(path);
	return dsaengine;

err_read:
	free(dsaengine->dsa_engine_buf);
	free(dsaengine->dsa_engine_path);
	free(dsaengine);
err_engine:
	free(path);
	return NULL;
}

static void devices_init(struct dsactl_ctx *ctx)
{
	if (ctx->devices_init) {
		info(ctx, "device is initialized already\n");
		return;
	}
	ctx->devices_init = 1;
	device_parse(ctx, NULL, "/sys/bus/dsa/devices", "dsa", ctx, add_device);
}

static void groups_init(struct dsactl_device *device)
{
	struct dsactl_ctx *ctx = device->ctx;

	if (device->group_init) {
		info(ctx, "group is intialized already\n");
		return;
	}
	device->group_init = 1;
	device_parse(device->ctx, device, device->device_path, "group", device,
		     add_group);
}

static void engines_init(struct dsactl_device *device)
{
	struct dsactl_group *group = device->group;
	struct dsactl_ctx *ctx = device->ctx;

	if (group) {
		if (group->engines_init) {
			info(ctx, "engine is initialized already\n");
			return;
		}
		group->engines_init = 1;
	}
	device_parse(ctx, device, device->device_path, "engine", device,
		     add_engine);
}

/**
 * dsactl_device_get_first - retrieve first "dsa device" in the system
 * @ctx: context established by dsactl_new
 *
 * Returns an dsactl_device if an dsa device exists in the system.  This return
 * value can be used to iterate to the next available device in the system
 * ia dsactl_device_get_next()
 */
DSACTL_EXPORT struct dsactl_device *dsactl_device_get_first(struct dsactl_ctx
							    *ctx)
{
	devices_init(ctx);

	return list_top(&ctx->devices, struct dsactl_device, list);
}

DSACTL_EXPORT struct dsactl_ctx *dsactl_device_get_ctx(struct dsactl_device
						       *device)
{
	return device->ctx;
}

/**
 * dsactl_device_get_next - retrieve the "next" dsa device in the system
 * @device: dsactl_device instance returned from dsactl_device_get_{first|next}
 *
 * Returns NULL if @device was the "last" device available in the system
 */
DSACTL_EXPORT struct dsactl_device *dsactl_device_get_next(struct dsactl_device
							   *device)
{
	struct dsactl_ctx *ctx = device->ctx;
	return list_next(&ctx->devices, device, list);
}

DSACTL_EXPORT const char *dsactl_device_get_devname(struct dsactl_device
						    *device)
{
	return devpath_to_devname(device->device_path);
}

DSACTL_EXPORT unsigned int dsactl_device_get_id(struct dsactl_device *device)
{
	return device->id;
}

DSACTL_EXPORT unsigned int dsactl_device_get_max_groups(struct dsactl_device
							*device)
{
	return device->max_groups;
}

DSACTL_EXPORT unsigned int dsactl_device_get_max_work_queues(struct
							     dsactl_device
							     *device)
{
	return device->max_work_queues;
}

DSACTL_EXPORT unsigned int dsactl_device_get_max_engines(struct dsactl_device
							 *device)
{
	return device->max_engines;
}

DSACTL_EXPORT unsigned int dsactl_device_get_max_work_queues_size(struct
								  dsactl_device
								  *device)
{
	return device->max_work_queues_size;
}

DSACTL_EXPORT int dsactl_device_get_numa_node(struct dsactl_device
						       *device)
{
	return device->numa_node;
}

DSACTL_EXPORT unsigned int dsactl_device_get_ims_size(struct dsactl_device
						      *device)
{
	return device->ims_size;
}

DSACTL_EXPORT unsigned int dsactl_device_get_max_batch_size(struct dsactl_device
							    *device)
{
	return device->max_batch_size;
}

DSACTL_EXPORT unsigned long dsactl_device_get_max_transfer_size(struct
								     dsactl_device
								     *device)
{
	return device->max_transfer_size;
}

DSACTL_EXPORT unsigned long dsactl_device_get_op_cap(struct dsactl_device *device)
{
	return device->opcap;
}

DSACTL_EXPORT unsigned int dsactl_device_get_configurable(struct dsactl_device
							  *device)
{
	return device->configurable;
}

DSACTL_EXPORT bool dsactl_device_get_pasid_enabled(struct dsactl_device
							  *device)
{
	return device->pasid_enabled;
}

DSACTL_EXPORT int dsactl_device_get_errors(struct dsactl_device *device,
					   struct dsactl_error *error)
{
	char *read_error;
	int dfd = open(device->device_path, O_PATH);

	read_error = get_param_str(dfd, "errors");
	if (sscanf(read_error, "%lx %lx %lx %lx", &error->val[0], &error->val[1],
				&error->val[2], &error->val[3]) == 4) {
		close(dfd);
		return 1;
	}
	else {
		close(dfd);
		return 0;
	}
}

DSACTL_EXPORT enum dsactl_device_state dsactl_device_get_state(struct dsactl_device
						  *device)
{
	enum dsactl_device_state dev_state;
	char* read_state;
	int dfd = open(device->device_path, O_PATH);

	read_state = get_param_str(dfd, "state");
	if (strcmp(read_state, "disabled") == 0) {
		dev_state = 0;
		close(dfd);
		return dev_state;
	} else {
		dev_state = 1;
		close(dfd);
		return dev_state;
	}
}

DSACTL_EXPORT unsigned int dsactl_device_get_max_tokens(struct dsactl_device
							*device)
{
	return device->max_tokens;
}

DSACTL_EXPORT unsigned int dsactl_device_get_token_limit(struct dsactl_device
							*device)
{
	return device->token_limit;
}

DSACTL_EXPORT int dsactl_device_is_active(struct dsactl_device *device)
{
	struct dsactl_ctx *ctx = dsactl_device_get_ctx(device);
	char *path = device->device_buf;
	int len = device->buf_len;
	char buf[20];

	if (snprintf(path, len, "%s/state", device->device_path) >= len) {
		err(ctx, "%s: buffer too small!\n",
		    dsactl_device_get_devname(device));
		return -ENOMEM;
	}

	if (sysfs_read_attr(ctx, path, buf) < 0)
		return -ENXIO;

	if (strcmp(buf, "enabled") == 0)
		return 1;

	return 0;
}

DSACTL_EXPORT struct dsactl_device *dsactl_group_get_device(struct dsactl_group
							    *group)
{
	return group->device;
}

DSACTL_EXPORT struct dsactl_group *dsactl_group_get_first(struct dsactl_device
							  *device)
{
	groups_init(device);

	return list_top(&device->groups, struct dsactl_group, list);
}

DSACTL_EXPORT struct dsactl_group *dsactl_group_get_next(struct dsactl_group
							 *group)
{
	struct dsactl_device *device = group->device;

	return list_next(&device->groups, group, list);
}

DSACTL_EXPORT unsigned int dsactl_group_get_id(struct dsactl_group *group)
{
	return group->id;
}

DSACTL_EXPORT unsigned int dsactl_group_get_device_id(struct dsactl_group *group)
{
	struct dsactl_device *device = group->device;

	return device->id;

}

DSACTL_EXPORT const char *dsactl_group_get_devname(struct dsactl_group *group)
{
	return devpath_to_devname(group->group_path);
}

DSACTL_EXPORT int dsactl_group_get_tokens_reserved(struct dsactl_group *group)
{
	return group->tokens_reserved;
}

DSACTL_EXPORT int dsactl_group_get_tokens_allowed(struct dsactl_group *group)
{
	return group->tokens_allowed;
}

DSACTL_EXPORT int dsactl_group_get_use_token_limit(struct dsactl_group *group)
{
	return group->use_token_limit;
}

DSACTL_EXPORT int dsactl_group_get_traffic_class_a(struct dsactl_group *group)
{
	return group->traffic_class_a;
}

DSACTL_EXPORT int dsactl_group_get_traffic_class_b(struct dsactl_group *group)
{
	return group->traffic_class_b;
}

static void wqs_init(struct dsactl_device *device)
{
	struct dsactl_ctx *ctx = device->ctx;
	struct dsactl_group *group = device->group;

	if (group) {
		if (group->wqs_init) {
			info(ctx, "wq is initialized already\n");
			return;
		}
		group->wqs_init = 1;
	}

	device_parse(ctx, device, device->device_path, "wq", device, add_wq);
}

DSACTL_EXPORT struct dsactl_wq *dsactl_wq_get_first(struct dsactl_device
						    *device)
{
	wqs_init(device);

	return list_top(&device->wqs, struct dsactl_wq, list);
}

DSACTL_EXPORT struct dsactl_wq *dsactl_wq_get_next(struct dsactl_wq *dsawq)
{
	struct dsactl_device *device = dsawq->device;

	return list_next(&device->wqs, dsawq, list);
}

DSACTL_EXPORT unsigned int dsactl_wq_get_group_id(struct dsactl_wq *dsawq)
{
	return dsawq->group_id;
}

DSACTL_EXPORT unsigned int dsactl_wq_get_priority(struct dsactl_wq *dsawq)
{
	return dsawq->priority;
}

DSACTL_EXPORT unsigned int dsactl_wq_get_priv(struct dsactl_wq *dsawq)
{
	return dsawq->priv;
}

DSACTL_EXPORT struct dsactl_group *dsactl_wq_get_group(struct dsactl_wq *dsawq)
{
	return dsawq->group;
}

DSACTL_EXPORT struct dsactl_device *dsactl_wq_get_device(struct dsactl_wq
							 *dsawq)
{
	return dsawq->device;
}

DSACTL_EXPORT struct dsactl_ctx *dsactl_wq_get_ctx(struct dsactl_wq *dsawq)
{
	return dsawq->group->device->ctx;
}

DSACTL_EXPORT const char *dsactl_wq_get_devname(struct dsactl_wq *dsawq)
{
	return devpath_to_devname(dsawq->dsawq_path);
}

DSACTL_EXPORT bool dsactl_wq_get_block_on_fault(struct dsactl_wq *dsawq)
{
	return dsawq->block_on_fault;
}

DSACTL_EXPORT enum dsactl_wq_state dsactl_wq_get_state(struct dsactl_wq *dsawq)
{
	enum dsactl_wq_state wq_state;
	char* read_state;
	int dfd = open(dsawq->dsawq_path, O_PATH);

	read_state = get_param_str(dfd, "state");
        if (strcmp(read_state, "disabled") == 0) {
                wq_state = 0;
		close(dfd);
                return wq_state;
        } else if (strcmp(read_state, "enabled") == 0) {
                wq_state = 1;
		close(dfd);
                return wq_state;
        } else {
		wq_state = 2;
		close(dfd);
		return wq_state;
	}
}

DSACTL_EXPORT unsigned int dsactl_wq_get_enforce_order(struct dsactl_wq *dsawq)
{
	return dsawq->enforce_order;
}

DSACTL_EXPORT struct dsactl_engine *dsactl_engine_get_first(struct dsactl_device
							    *device)
{
	engines_init(device);

	return list_top(&device->engines, struct dsactl_engine, list);
}

DSACTL_EXPORT struct dsactl_engine *dsactl_engine_get_next(struct dsactl_engine
							   *dsaengine)
{
	struct dsactl_device *device = dsaengine->device;

	return list_next(&device->engines, dsaengine, list);
}

DSACTL_EXPORT unsigned int dsactl_engine_get_id(struct dsactl_engine *dsaengine)
{
	return dsaengine->id;
}

DSACTL_EXPORT struct dsactl_group *dsactl_engine_get_group(struct dsactl_engine
							   *dsaengine)
{
	return dsaengine->group;
}

DSACTL_EXPORT struct dsactl_device *dsactl_engine_get_device(struct
							     dsactl_engine
							     *dsaengine)
{
	return dsaengine->group->device;
}

DSACTL_EXPORT struct dsactl_ctx *dsactl_engine_get_ctx(struct dsactl_engine
						       *dsaengine)
{
	return dsaengine->group->device->ctx;
}

DSACTL_EXPORT int dsactl_group_get_numa_node(struct dsactl_group *group)
{
	return group->numa_node;
}

DSACTL_EXPORT unsigned long dsactl_group_get_size(struct dsactl_group
						       *group)
{
	return group->size;
}

DSACTL_EXPORT unsigned long dsactl_group_get_available_size(struct
								 dsactl_group
								 *group)
{
	struct dsactl_ctx *ctx = dsactl_group_get_ctx(group);
	char *path = group->group_buf;
	int len = group->buf_len;
	char buf[SYSFS_ATTR_SIZE];

	if (snprintf(path, len, "%s/available_size", group->group_path) >= len) {
		err(ctx, "%s: buffer too small!\n",
		    dsactl_group_get_devname(group));
		return ULLONG_MAX;
	}

	if (sysfs_read_attr(ctx, path, buf) < 0)
		return ULLONG_MAX;

	return strtoull(buf, NULL, 0);
}
