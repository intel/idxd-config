// SPDX-License-Identifier: LGPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <poll.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <ccan/list/list.h>
#include <ccan/minmax/minmax.h>
#include <ccan/array_size/array_size.h>
#include <ccan/build_assert/build_assert.h>
#include <util/sysfs.h>
#include <accfg/libaccel_config.h>
#include "private.h"

#define MDEV_POSTFIX "mdev_supported_types"

const char *accfg_wq_mode_str[] = {
	[ACCFG_WQ_SHARED]	= "shared",
	[ACCFG_WQ_DEDICATED]	= "dedicated",
};

static char *filename_prefix;
static int filename_prefix_len;

ACCFG_EXPORT char *accfg_basenames[] = {
        [ACCFG_DEVICE_DSA]      = "dsa",
	[ACCFG_DEVICE_IAX]      = "iax",
	NULL
};

ACCFG_EXPORT char *accfg_mdev_basenames[] = {
	[ACCFG_MDEV_TYPE_1_DWQ]      = "1dwq",
	[ACCFG_MDEV_TYPE_1_SWQ]      = "1swq",
	NULL
};

enum {
	ACCFG_CMD_STATUS_MAX = 0x45,
};

const char *accfg_device_cmd_status[] = {
	[0x1]	= "Invalid command code",
	[0x2]	= "Invalid WQ index",
	[0x3]	= "Internal or platform hardware error",
	[0x4]	= "Non-zero reserved field in comand",
	[0x10]	= "Device not disabled",
	[0x11]	= "Unspecified error in config for device enable",
	[0x12]	= "Bus master enable is 0",
	[0x13]	= "PRSREQALLOC value unsupported",
	[0x14]	= "Sum of WQCFG size fields out of range",
	[0x15]	= "Invalid group config: lack of wq or engines",
	[0x16]	= "Invalid group config: wq misconfigured",
	[0x17]	= "Invalid group config: engine misconfigured",
	[0x18]	= "Invalid group config: invalid bandwith tokens config",
	[0x20]	= "Device not enabled",
	[0x21]	= "WQ is not disabled",
	[0x22]	= "WQ size is 0",
	[0x23]	= "WQ priority is 0",
	[0x24]	= "Invalid WQ mode",
	[0x25]	= "Invalid block on fault setting",
	[0x26]	= "Invalid value for WQ pasid enable",
	[0x27]	= "Invalid WQ max batch size",
	[0x28]	= "Invalid WQ max transfer size",
	[0x2a]	= "PCIe pasid cap Priv mode enable = 0",
	[0x2b]	= "Invalid WQ Occupancy Interrupt table or handle",
	[0x2c]	= "WQ ATS config mismatched",
	[0x31]	= "Device is not enabled",
	[0x32]	= "WQ(s) not enabled",
	[0x41]	= "Invalid interrupt table index",
	[0x42]	= "No interrupt handle available",
	[0x43]	= "No interrupt handles associated with the index",
	[0x44]	= "No revoked handles associted with the index",
	[ACCFG_CMD_STATUS_MAX]	= "",
};

static long accfg_get_param_long(struct accfg_ctx *ctx, int dfd, char *name)
{
	int fd = openat(dfd, name, O_RDONLY);
	char buf[MAX_PARAM_LEN + 1];
	int n;

	if (fd == -1)
		return -errno;

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

static unsigned long long accfg_get_param_unsigned_llong(
		struct accfg_ctx *ctx, int dfd, char *name)
{
	int fd = openat(dfd, name, O_RDONLY);
	char buf[MAX_PARAM_LEN + 1];
	int n;

	if (fd == -1)
		return -errno;

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

static char *accfg_get_param_str(struct accfg_ctx *ctx, int dfd, char *name)
{
	int fd = openat(dfd, name, O_RDONLY);
	char buf[MAX_PARAM_LEN + 1];
	int n;

	if (fd == -1)
		return NULL;

	n = read(fd, buf, MAX_PARAM_LEN);
	close(fd);
	if (n <= 0)
		return NULL;

	if (buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	else
		buf[n] = '\0';

	return strdup(buf);
}

static void free_engine(struct accfg_engine *engine)
{
	struct accfg_device *device = engine->device;

	list_del_from(&device->engines, &engine->list);
	free(engine->engine_path);
	free(engine->engine_buf);
	free(engine);
}

static void free_wq(struct accfg_wq *wq)
{
	struct accfg_device *device = wq->device;

	list_del_from(&device->wqs, &wq->list);
	free(wq->wq_path);
	free(wq->wq_buf);
	free(wq);
}

static void free_group(struct accfg_group *group)
{
	struct accfg_device *device = group->device;

	list_del_from(&device->groups, &group->list);
	free(group->group_buf);
	free(group->group_path);
	free(group);
}

static void free_device(struct accfg_device *device, struct list_head *head)
{
	struct accfg_group *group, *_r;
	struct accfg_wq *wq, *wq_next;
	struct accfg_engine *engine, *engine_next;

	list_for_each_safe(&device->groups, group, _r, list)
		free_group(group);
	list_for_each_safe(&device->wqs, wq, wq_next, list)
		free_wq(wq);
	list_for_each_safe(&device->engines, engine, engine_next, list)
		free_engine(engine);

	if (head)
		list_del_from(head, &device->list);
	free(device->device_path);
	free(device->device_buf);
	free(device->mdev_path);
	free(device);
}

static void free_context(struct accfg_ctx *ctx)
{
	struct accfg_device *device, *_b;

	list_for_each_safe(&ctx->devices, device, _b, list)
		free_device(device, &ctx->devices);
	free(ctx);
}

ACCFG_EXPORT enum accfg_wq_mode accfg_wq_get_mode(struct accfg_wq *wq)
{
	enum accfg_wq_mode wq_mode;
	char *read_mode;
	int dfd;
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq);

	dfd = open(wq->wq_path, O_PATH);
	if (dfd < 0)
		return -errno;

	read_mode = accfg_get_param_str(ctx, dfd, "mode");
	if (strcmp(read_mode, accfg_wq_mode_str[ACCFG_WQ_SHARED]) == 0)
		wq_mode = ACCFG_WQ_SHARED;
	else
		wq_mode = ACCFG_WQ_DEDICATED;

	free(read_mode);
	close(dfd);
	return wq_mode;
}

ACCFG_EXPORT const char *accfg_engine_get_devname(
		struct accfg_engine *engine)
{
	return devpath_to_devname(engine->engine_path);
}

static int is_enabled(struct accfg_device *device, const char *drvpath)
{
	struct stat st;
	struct accfg_ctx *ctx;

	if (!device)
		return -EINVAL;

	ctx = accfg_device_get_ctx(device);

	if (lstat(drvpath, &st) < 0) {
		err(ctx, "find symbolic link of device failed\n");
		return 0;
	} else
		return 1;
}

ACCFG_EXPORT struct accfg_ctx *accfg_group_get_ctx(
		struct accfg_group *group)
{
	return group->device->ctx;
}

ACCFG_EXPORT int accfg_wq_is_enabled(struct accfg_wq *wq)
{
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq);
	char *path = wq->wq_buf;
	int len = wq->buf_len;

	if (snprintf(path, len, "%s/mode", wq->wq_path) >= len) {
		err(ctx, "%s: buffer too small!\n", accfg_wq_get_devname(wq));
		return -ENOMEM;
	}

	return is_enabled(accfg_wq_get_device(wq), path);
}

/**
 * accfg_new - instantiate a new library context
 * @ctx: context to establish
 *
 * Returns zero on success and stores an opaque pointer in ctx.  The
 * context is freed by accfg_unref(), i.e. accfg_new() implies an
 * internal accfg_ref().
 */
ACCFG_EXPORT int accfg_new(struct accfg_ctx **ctx)
{
	struct accfg_ctx *c;
	const char *env;

	c = calloc(1, sizeof(struct accfg_ctx));
	if (!c)
		return -ENOMEM;

	c->refcount = 1;
	log_init(&c->ctx, "libaccfg", "ACCFG_LOG");
	c->timeout = 5000;
	list_head_init(&c->devices);

	info(c, "ctx %p created\n", c);
	dbg(c, "log_priority=%d\n", c->ctx.log_priority);
	*ctx = c;

	env = secure_getenv("ACCFG_TIMEOUT");
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
 * accfg_ref - take an additional reference on the context
 * @ctx: context established by accfg_new()
 */
ACCFG_EXPORT struct accfg_ctx *accfg_ref(struct accfg_ctx *ctx)
{
	if (ctx == NULL)
		return NULL;
	ctx->refcount++;
	return ctx;
}

/**
 * accfg_unref - drop a context reference count
 * @ctx: context established by accfg_new()
 *
 * Drop a reference and if the resulting reference count is 0 destroy
 * the context.
 */
ACCFG_EXPORT struct accfg_ctx *accfg_unref(struct accfg_ctx *ctx)
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
 * accfg_set_log_fn - override default log routine
 * @ctx: accfg library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be overridden by a
 * custom function, to plug log messages into the user's logging
 * functionality.
 */
ACCFG_EXPORT void accfg_set_log_fn(struct accfg_ctx *ctx,
		void (*accfg_log_fn)(struct accfg_ctx *ctx,
			int priority, const char *file,
			int line, const char *fn, const char *format,
			va_list args))
{
	ctx->ctx.log_fn = (log_fn) accfg_log_fn;
	info(ctx, "ctx is %p, custom logging function %p registered\n",
			ctx, accfg_log_fn);
}

/**
 * accfg_get_log_priority - retrieve current library loglevel (syslog)
 * @ctx: accfg library context
 */
ACCFG_EXPORT int accfg_get_log_priority(struct accfg_ctx *ctx)
{
	return ctx->ctx.log_priority;
}

/**
 * accfg_set_log_priority - set log verbosity
 * @priority: from syslog.h, LOG_ERR, LOG_INFO, LOG_DEBUG
 *
 * Note: LOG_DEBUG requires library be built with "configure --enable-debug"
 */
ACCFG_EXPORT void accfg_set_log_priority(struct accfg_ctx *ctx,
		int priority)
{
	ctx->ctx.log_priority = priority;
}

static int device_parse(struct accfg_ctx *ctx, const char *base_path,
			char *dev_prefix, int (*filter)(const struct dirent *),
			void *parent, add_dev_fn add_dev)
{
	return sysfs_device_parse(ctx, base_path, dev_prefix,
			filter, parent, add_dev);
}

static int device_parse_type(struct accfg_device *device)
{
	if (!device)
		return -EINVAL;

	if (!strcmp(device->device_type_str, "dsa"))
		device->type = ACCFG_DEVICE_DSA;
	else if (!strcmp(device->device_type_str, "iax"))
		device->type = ACCFG_DEVICE_IAX;
	else
		device->type = ACCFG_DEVICE_TYPE_UNKNOWN;

	return 0;
}

static int mdev_str_to_type(char *mdev_type_str)
{
	char **b;
	char *s;
	int l, i;

	s = strchr(mdev_type_str, '-');
	if (!s)
		s = mdev_type_str;
	else
		s++;
	l = (int) (strchrnul(s, '-') - s);

	for (b = accfg_mdev_basenames, i = 0; *b != NULL; b++, i++)
		if (!strncmp(*b, s, l))
			return i;

	return ACCFG_MDEV_TYPE_UNKNOWN;
}

static int add_device_mdevs(struct accfg_ctx *ctx, struct accfg_device *dev)
{
	struct accfg_device_mdev *dev_mdev;
	uuid_t uu;
	struct dirent **d;
	char *f, *mdev_type_str;
	char p[PATH_MAX];
	char mdev_path[PATH_MAX];
	int n, n1, rc = 0;

	n1 = n = scandir(dev->mdev_path, &d, NULL, alphasort);
	if (n < 0) {
		err(ctx, "scandir failed\n");
		return -ENOENT;
	}

	while (n--) {
		f = &d[n]->d_name[0];
		if (*f == '.' || uuid_parse(f, uu))
			continue;
		sprintf(p, "%s/%s/mdev_type", dev->mdev_path, f);
		if (!realpath(p, mdev_path))
			continue;
		dev_mdev = calloc(1,
			sizeof(struct accfg_device_mdev));
		if (!dev_mdev) {
			err(ctx, "allocation failed\n");
			rc = -ENOMEM;
			goto exit_add_mdev;
		}
		uuid_copy(dev_mdev->uuid, uu);
		mdev_type_str = strrchr(mdev_path, '/') + 1;
		dev_mdev->device = dev;
		dev_mdev->type = mdev_str_to_type(mdev_type_str);
		if (dev_mdev->type == ACCFG_MDEV_TYPE_UNKNOWN) {
			err(ctx, "mdev type error\n");
			free(dev_mdev);
			rc = -EINVAL;
			goto exit_add_mdev;
		}
		list_add_tail(&dev->mdev_list, &dev_mdev->list);
	}

exit_add_mdev:
	while (n1--)
		free(d[n1]);
	free(d);

	return rc;
}

static void *add_device(void *parent, int id, const char *ctl_base, char *dev_prefix)
{
	struct accfg_ctx *ctx = parent;
	struct accfg_device *device;
	char *path;
	int dfd;
	int rc;
	char *p;

	path = calloc(1, strlen(ctl_base) + MAX_PARAM_LEN);
	if (!path) {
		err(ctx, "%s: allocation of path failed\n", __func__);
		return NULL;
	}

	dfd = open(ctl_base, O_PATH);
	if (dfd == -1) {
		err(ctx, "%s open failed: %s\n", __func__, strerror(errno));
		free(path);
		return NULL;
	}

	device = calloc(1, sizeof(*device));
	if (!device) {
		err(ctx, "allocation of device failed\n");
		close(dfd);
		goto err_device;
	}

	list_head_init(&device->groups);
	list_head_init(&device->wqs);
	list_head_init(&device->engines);
	list_head_init(&device->mdev_list);

	device->ctx = ctx;
	device->id = id;

	device->max_groups = accfg_get_param_long(ctx, dfd, "max_groups");
	device->max_work_queues = accfg_get_param_long(ctx, dfd,
			"max_work_queues");
	device->max_engines = accfg_get_param_long(ctx, dfd, "max_engines");
	device->max_work_queues_size =
		accfg_get_param_long(ctx, dfd, "max_work_queues_size");
	device->numa_node = accfg_get_param_long(ctx, dfd, "numa_node");
	device->ims_size = accfg_get_param_long(ctx, dfd, "ims_size");
	device->max_batch_size = accfg_get_param_long(ctx, dfd,
			"max_batch_size");
	device->max_transfer_size =
	    accfg_get_param_unsigned_llong(ctx, dfd, "max_transfer_size");
	device->opcap = accfg_get_param_unsigned_llong(ctx, dfd, "op_cap");
	device->gencap = accfg_get_param_unsigned_llong(ctx, dfd, "gen_cap");
	device->configurable = accfg_get_param_unsigned_llong(ctx, dfd,
			"configurable");
	device->pasid_enabled = accfg_get_param_str(ctx, dfd,
			"pasid_enabled");
	device->max_tokens = accfg_get_param_long(ctx, dfd, "max_tokens");
	device->token_limit = accfg_get_param_long(ctx, dfd, "token_limit");
	device->cdev_major = accfg_get_param_long(ctx, dfd, "cdev_major");
	device->version = accfg_get_param_unsigned_llong(ctx, dfd, "version");
	device->device_path = realpath(ctl_base, NULL);
	close(dfd);
	if (!device->device_path) {
		err(ctx, "get realpath of device_path failed\n");
		goto err_dev_path;
	}

	device->mdev_path = strdup(device->device_path);
	if (!device->mdev_path) {
		err(ctx, "strdup of device_path failed\n");
		goto err_dev_path;
	}

	if (asprintf(&p, "%s/%s", MDEV_BUS,
			basename(dirname(device->mdev_path))) < 0) {
		err(ctx, "device mdev_path allocation failed\n");
		goto err_dev_path;
	}
	free(device->mdev_path);
	device->mdev_path = p;

	device->device_buf = calloc(1, strlen(device->device_path) +
			MAX_PARAM_LEN);
	if (!device->device_buf) {
		err(ctx, "allocation of device buffer failed\n");
		goto err_read;
	}

	device->buf_len = strlen(device->device_path) + MAX_BUF_LEN;
	device->device_type_str = dev_prefix;
	rc = device_parse_type(device);
	if (rc < 0)
		goto err_dev_path;
	list_add_tail(&ctx->devices, &device->list);
	free(path);

	if (add_device_mdevs(ctx, device))
		goto err_dev_path;

	return device;

err_dev_path:
err_read:
	free(device->device_buf);
	free(device->mdev_path);
	free(device);
err_device:
	free(path);
	return NULL;
}

static int wq_parse_type(struct accfg_wq *wq, char *wq_type)
{
	char *type;
	char *ptype;

	type = strdup(wq_type);
	if (!type)
		return -ENOMEM;

	ptype = strtok(type, ":");

	if (!ptype) {
		free(type);
		return -EINVAL;
	}

	if (strcmp(ptype, "kernel") == 0)
		wq->type = ACCFG_WQT_KERNEL;
	else if (strcmp(ptype, "user") == 0)
		wq->type = ACCFG_WQT_USER;
	else
		wq->type = ACCFG_WQT_NONE;

	free(type);

	return 0;
}

static void *add_wq(void *parent, int id, const char *wq_base,
		char *dev_prefix)
{
	struct accfg_wq *wq;
	struct accfg_device *device = parent;
	struct accfg_group *group;
	struct accfg_ctx *ctx;
	char *path;
	char *wq_base_string;
	unsigned long device_id, wq_id;
	int dfd;
	char *wq_type;

	if (!device)
		return NULL;

	group = device->group;
	ctx = accfg_device_get_ctx(device);
	dfd = open(wq_base, O_PATH);
	if (dfd < 0)
		return NULL;

	path = calloc(1, strlen(wq_base) + 100);
	if (!path) {
		err(ctx, "%s: allocation of path failed\n", __func__);
		close(dfd);
		return NULL;
	}

	wq = calloc(1, sizeof(*wq));
	if (!wq) {
		err(ctx, "allocation of wq failed\n");
		close(dfd);
		free(path);
		return NULL;
	}

	wq_base_string = strdup(wq_base);
	if (!wq_base_string) {
		err(ctx, "conversion of wq_base_string failed\n");
		close(dfd);
		goto err_wq;
	}

	if (sscanf(basename(wq_base_string),
				"wq%ld.%ld", &device_id, &wq_id) != 2) {
		close(dfd);
		goto err_wq;
	}

	wq->id = wq_id;
	wq->group = group;
	wq->device = device;
	wq->group_id = accfg_get_param_long(ctx, dfd, "group_id");
	wq->size = accfg_get_param_long(ctx, dfd, "size");
	wq->priority = accfg_get_param_long(ctx, dfd, "priority");
	wq->block_on_fault = accfg_get_param_long(ctx, dfd,
			"block_on_fault");
	wq->mode = accfg_get_param_str(ctx, dfd, "mode");
	wq->state = accfg_get_param_str(ctx, dfd, "state");
	wq->cdev_minor = accfg_get_param_long(ctx, dfd, "cdev_minor");
	wq_type = accfg_get_param_str(ctx, dfd, "type");
	wq->name = accfg_get_param_str(ctx, dfd, "name");
	wq->threshold =  accfg_get_param_long(ctx, dfd, "threshold");
	wq->max_batch_size =  accfg_get_param_long(ctx, dfd, "max_batch_size");
	wq->max_transfer_size =  accfg_get_param_long(ctx, dfd, "max_transfer_size");

	wq_parse_type(wq, wq_type);
	free(wq_type);

	close(dfd);
	wq->wq_path = strdup(wq_base);
	if (!wq->wq_path) {
		err(ctx, "forming of wq path failed\n");
		goto err_read;
	}

	wq->wq_buf = calloc(1, strlen(wq_base) + MAX_BUF_LEN);
	if (!wq->wq_buf) {
		err(ctx, "allocation of wq buffer failed\n");
		goto err_read;
	}
	wq->buf_len = strlen(wq_base) + MAX_BUF_LEN;

	list_add_tail(&device->wqs, &wq->list);
	free(path);
	return wq;

err_read:
	free(wq->wq_buf);
	free(wq->wq_path);
err_wq:
	free(wq);
	free(path);
	return NULL;
}

static void *add_group(void *parent, int id, const char *group_base,
		char *dev_prefix)
{
	struct accfg_group *group;
	struct accfg_device *device = parent;
	struct accfg_ctx *ctx;
	char *path;
	char *group_base_string;
	int dfd;
	unsigned long device_id, group_id;

	if (!device)
		return NULL;
	ctx = accfg_device_get_ctx(device);

	dfd = open(group_base, O_PATH);
	if (dfd < 0)
		return NULL;

	path = calloc(1, strlen(group_base) + 100);
	if (!path) {
		err(ctx, "%s: allocation of path failed\n", __func__);
		close(dfd);
		return NULL;
	}
	group = calloc(1, sizeof(*group));
	if (!group) {
		err(ctx, "allocation of group failed\n");
		close(dfd);
		goto err_group;
	}

	group_base_string = strdup(group_base);
	if (!group_base_string) {
		err(ctx, "conversion of group_base_string failed\n");
		free(group);
		close(dfd);
		goto err_group;
	}
	if (sscanf(basename(group_base_string),
				"group%ld.%ld", &device_id, &group_id) != 2) {
		free(group);
		close(dfd);
		goto err_group;
	}
	group->group_path = (char *)group_base;
	group->device = device;
	device->group = group;
	group->id = group_id;
	group->group_engines = accfg_get_param_str(ctx, dfd, "engines");
	group->group_wqs = accfg_get_param_str(ctx, dfd, "work_queues");
	group->tokens_reserved = accfg_get_param_long(ctx, dfd,
			"tokens_reserved");
	group->tokens_allowed = accfg_get_param_long(ctx, dfd,
			"tokens_allowed");
	group->use_token_limit = accfg_get_param_long(ctx, dfd,
			"use_token_limit");
	group->traffic_class_a = accfg_get_param_long(ctx, dfd,
			"traffic_class_a");
	group->traffic_class_b = accfg_get_param_long(ctx, dfd,
			"traffic_class_b");

	close(dfd);
	group->group_buf = calloc(1, strlen(group_base) + MAX_BUF_LEN);
	if (!group->group_buf) {
		err(ctx, "allocation of group buffer failed\n");
		goto err_read;
	}
	group->buf_len = strlen(group_base) + MAX_BUF_LEN;

	group->group_path = strdup(group_base);
	if (!group->group_path) {
		err(ctx, "forming of group path failed\n");
		goto err_read;
	}

	list_add_tail(&device->groups, &group->list);
	free(path);
	return group;

err_read:
	free(group->group_buf);
	free(group);
err_group:
	free(path);
	return NULL;
}

static void *add_engine(void *parent, int id, const char *engine_base,
		char *dev_prefix)
{
	struct accfg_engine *engine;
	struct accfg_device *device = parent;
	struct accfg_ctx *ctx;
	struct accfg_group *group;
	char *path;
	char *engine_base_string;
	int dfd;
	unsigned long device_id, engine_id;

	if (!device)
		return NULL;

	group = device->group;
	ctx = accfg_device_get_ctx(device);
	dfd = open(engine_base, O_PATH);
	if (dfd < 0)
		return NULL;

	path = calloc(1, strlen(engine_base) + 100);
	if (!path) {
		err(ctx, "%s: allocation of path failed\n", __func__);
		close(dfd);
		return NULL;
	}

	engine = calloc(1, sizeof(*engine));
	if (!engine) {
		err(ctx, "allocation of engine failed\n");
		close(dfd);
		goto err_engine;
	}

	engine_base_string = strdup(engine_base);
	if (!engine_base_string) {
		err(ctx, "conversion of engine_base_string failed\n");
		close(dfd);
		free(engine);
		goto err_engine;
	}
	if (sscanf(basename(engine_base_string),
			"engine%ld.%ld", &device_id, &engine_id) != 2) {
		close(dfd);
		free(path);
		free(engine);
		return NULL;
	}

	engine->id = engine_id;
	engine->group = group;
	engine->device = device;
	engine->group_id = accfg_get_param_long(ctx, dfd, "group_id");
	close(dfd);

	engine->engine_path = strdup(engine_base);
	if (!engine->engine_path) {
		err(ctx, "forming of engine path failed\n");
		goto err_read;
	}

	engine->engine_buf = calloc(1, strlen(engine_base) + MAX_BUF_LEN);
	if (!engine->engine_buf) {
		err(ctx, "allocation of engine buffer failed\n");
		goto err_read;
	}
	engine->buf_len = strlen(engine_base) + MAX_BUF_LEN;

	list_add_tail(&device->engines, &engine->list);
	free(path);
	return engine;

err_read:
	free(engine->engine_buf);
	free(engine->engine_path);
	free(engine);
err_engine:
	free(path);
	return NULL;
}

static void set_filename_prefix(char *pfx)
{
	filename_prefix = pfx;
	filename_prefix_len = strlen(pfx);
}

static int filter_file_name_prefix(const struct dirent *d)
{
	return !strncmp(filename_prefix, d->d_name, filename_prefix_len);
}

static void devices_init(struct accfg_ctx *ctx)
{
	char **accel_name;
	char *path;

	if (ctx->devices_init) {
		dbg(ctx, "device is initialized already\n");
		return;
	}
	ctx->devices_init = 1;

	for (accel_name = accfg_basenames; *accel_name != NULL;
		accel_name++) {
		if (asprintf(&path, "/sys/bus/%s/devices", *accel_name) < 0) {
			err(ctx, "devices_init set path failed\n");
			continue;
		}
		set_filename_prefix(*accel_name);
		device_parse(ctx, path, *accel_name,
				filter_file_name_prefix, ctx, add_device);
		free(path);
	}
}

static void groups_init(struct accfg_device *device)
{
	struct accfg_ctx *ctx = device->ctx;

	if (device->group_init) {
		dbg(ctx, "group is intialized already\n");
		return;
	}
	device->group_init = 1;
	set_filename_prefix("group");
	device_parse(device->ctx, device->device_path, "group",
			filter_file_name_prefix,
			device, add_group);
}

static void engines_init(struct accfg_device *device)
{
	struct accfg_group *group = device->group;
	struct accfg_ctx *ctx = device->ctx;

	if (group) {
		if (group->engines_init) {
			dbg(ctx, "engine is initialized already\n");
			return;
		}
		group->engines_init = 1;
	}
	set_filename_prefix("engine");
	device_parse(ctx, device->device_path, "engine",
			filter_file_name_prefix, device,
			add_engine);
}

ACCFG_EXPORT struct accfg_device_mdev *accfg_device_first_mdev(struct accfg_device *device)
{
	return list_top(&device->mdev_list, struct accfg_device_mdev, list);
}

ACCFG_EXPORT struct accfg_device_mdev *accfg_device_next_mdev(struct accfg_device_mdev *mdev)
{
	struct accfg_device *device = mdev->device;

	return list_next(&device->mdev_list, mdev, list);
}

ACCFG_EXPORT void accfg_mdev_get_uuid(struct accfg_device_mdev *mdev, uuid_t uuid)
{
	uuid_copy(uuid, mdev->uuid);
}

ACCFG_EXPORT enum accfg_mdev_type accfg_mdev_get_type(struct accfg_device_mdev *mdev)
{
	return mdev->type;
}

/**
 * accfg_device_get_first - retrieve first device in the system
 * @ctx: context established by accfg_new
 *
 * Returns an accfg_device if a device exists in the system. This return
 * value can be used to iterate to the next available device in the system
 * ia accfg_device_get_next()
 */
ACCFG_EXPORT struct accfg_device *accfg_device_get_first(struct accfg_ctx *ctx)
{
	devices_init(ctx);

	return list_top(&ctx->devices, struct accfg_device, list);
}

ACCFG_EXPORT struct accfg_ctx *accfg_device_get_ctx(struct accfg_device *device)
{
	return device->ctx;
}

/**
 * accfg_device_get_next - retrieve the "next" device in the system
 * @device: accfg_device instance returned from
 * accfg_device_get_{first|next}
 *
 * Returns NULL if @device was the "last" device available in the system
 */
ACCFG_EXPORT struct accfg_device *accfg_device_get_next(
		struct accfg_device *device)
{
	struct accfg_ctx *ctx = device->ctx;

	return list_next(&ctx->devices, device, list);
}

ACCFG_EXPORT const char *accfg_device_get_devname(struct accfg_device *device)
{
	return devpath_to_devname(device->device_path);
}

ACCFG_EXPORT int accfg_device_get_id(struct accfg_device *device)
{
	return device->id;
}

ACCFG_EXPORT struct accfg_device *accfg_ctx_device_get_by_id(
		struct accfg_ctx *ctx, int id)
{
	struct accfg_device *dev;

	accfg_device_foreach(ctx, dev)
		if (accfg_device_get_id(dev) == id)
			return dev;
	return NULL;
}

ACCFG_EXPORT unsigned int accfg_device_get_max_groups(
		struct accfg_device *device)
{
	return device->max_groups;
}

ACCFG_EXPORT unsigned int accfg_device_get_max_work_queues(
		struct accfg_device *device)
{
	return device->max_work_queues;
}

ACCFG_EXPORT unsigned int accfg_device_get_max_engines(
		struct accfg_device *device)
{
	return device->max_engines;
}

ACCFG_EXPORT unsigned int accfg_device_get_max_work_queues_size(
		struct accfg_device *device)
{
	return device->max_work_queues_size;
}

ACCFG_EXPORT int accfg_device_get_numa_node(struct accfg_device *device)
{
	return device->numa_node;
}

ACCFG_EXPORT unsigned int accfg_device_get_ims_size(
		struct accfg_device *device)
{
	return device->ims_size;
}

ACCFG_EXPORT unsigned int accfg_device_get_max_batch_size(
		struct accfg_device *device)
{
	return device->max_batch_size;
}

ACCFG_EXPORT unsigned long accfg_device_get_max_transfer_size(
		struct accfg_device *device)
{
	return device->max_transfer_size;
}

ACCFG_EXPORT unsigned long accfg_device_get_op_cap(
		struct accfg_device *device)
{
	return device->opcap;
}

ACCFG_EXPORT unsigned long accfg_device_get_gen_cap(struct accfg_device *device)
{
	return device->gencap;
}

ACCFG_EXPORT unsigned int accfg_device_get_configurable(
		struct accfg_device *device)
{
	return device->configurable;
}

ACCFG_EXPORT bool accfg_device_get_pasid_enabled(
		struct accfg_device *device)
{
	return device->pasid_enabled;
}

ACCFG_EXPORT int accfg_device_get_errors(struct accfg_device *device,
		struct accfg_error *error)
{
	char *read_error;
	int dfd;
	int rc;
	struct accfg_ctx *ctx;

	if (!device)
		return -EINVAL;

	ctx = accfg_device_get_ctx(device);
	dfd = open(device->device_path, O_PATH);
	if (dfd < 0)
		return -errno;
	read_error = accfg_get_param_str(ctx, dfd, "errors");
	close(dfd);
	rc = sscanf(read_error, "%lx %lx %lx %lx",
			&error->val[0], &error->val[1],
			&error->val[2], &error->val[3]);
	if (rc < 0) {
		free(read_error);
		return -errno;
	}
	else if (rc != 4) {
		free(read_error);
		return 0;
	}

	free(read_error);
	return 1;
}

ACCFG_EXPORT enum accfg_device_state accfg_device_get_state(
		struct accfg_device *device)
{
	struct accfg_ctx *ctx;
	char read_state[SYSFS_ATTR_SIZE];
	char *path;
	int len;

	if (!device)
		return ACCFG_DEVICE_UNKNOWN;

	ctx = accfg_device_get_ctx(device);
	path = device->device_buf;
	len = device->buf_len;

	if (snprintf(path, len, "%s/state", device->device_path) >= len) {
		err(ctx, "%s: buffer too small!\n", __func__);
		return ACCFG_DEVICE_UNKNOWN;
	}

	if (sysfs_read_attr(ctx, path, read_state) < 0) {
		err(ctx, "%s: sysfs_read_attr failed '%s': %s\n",
				__func__, device->device_path,
				strerror(errno));
		return ACCFG_DEVICE_UNKNOWN;
	}

	if (strcmp(read_state, "disabled") == 0)
		return ACCFG_DEVICE_DISABLED;
	else if (strcmp(read_state, "enabled") == 0)
		return ACCFG_DEVICE_ENABLED;

	return ACCFG_DEVICE_UNKNOWN;
}

ACCFG_EXPORT unsigned int accfg_device_get_max_tokens(
		struct accfg_device *device)
{
	return device->max_tokens;
}

ACCFG_EXPORT unsigned int accfg_device_get_token_limit(
		struct accfg_device *device)
{
	return device->token_limit;
}

ACCFG_EXPORT unsigned int accfg_device_get_cdev_major(
		struct accfg_device *device)
{
	return device->cdev_major;
}

ACCFG_EXPORT unsigned int accfg_device_get_version(
		struct accfg_device *device)
{
	return device->version;
}

ACCFG_EXPORT int accfg_device_get_clients(struct accfg_device *device)
{
	struct accfg_ctx *ctx;
	char buf[SYSFS_ATTR_SIZE];
	char *path;
	int len;
	int rc;

	if (!device)
		return -EINVAL;

	ctx = accfg_device_get_ctx(device);
	path = device->device_buf;
	len = device->buf_len;

	rc = snprintf(path, len, "%s/clients", device->device_path);
	if (rc >= len || rc < 0) {
		err(ctx, "%s: snprintf error: %d\n", __func__, -errno);
		return -errno;
	}

	if (sysfs_read_attr(ctx, path, buf) < 0) {
		err(ctx, "%s: retrieve clients failed '%s': %s\n",
				__func__, path, strerror(errno));
		return -errno;
	}

	return atoi(buf);
}

ACCFG_EXPORT int accfg_device_set_token_limit(struct accfg_device *dev, int val)
{
	struct accfg_ctx *ctx;
	char *path;
	char buf[SYSFS_ATTR_SIZE];

	if (!dev)
		return -EINVAL;

	path = dev->device_buf;
	ctx = accfg_device_get_ctx(dev);

	if (sprintf(path, "%s/token_limit", dev->device_path) >=
			(int)dev->buf_len) {
		err(ctx, "%s; buf len exceeded.\n",
				accfg_device_get_devname(dev));
		return -errno;
	}

	if (sprintf(buf, "%d", val) < 0) {
		err(ctx, "%s: sprintf to buf failed: %s\n",
				accfg_device_get_devname(dev), strerror(errno));
		return -errno;
	}

	if (sysfs_write_attr(ctx, path, buf) < 0) {
		err(ctx, "%s: write failed: %s\n",
				accfg_device_get_devname(dev), strerror(errno));
		return -errno;
	}

	dev->token_limit = val;

	return 0;
}

ACCFG_EXPORT int accfg_device_is_active(struct accfg_device *device)
{
	struct accfg_ctx *ctx;
	char *path;
	int len;
	char buf[SYSFS_ATTR_SIZE];

	if (!device)
		return -EINVAL;

	ctx = accfg_device_get_ctx(device);
	path = device->device_buf;
	len = device->buf_len;

	if (snprintf(path, len, "%s/state", device->device_path) >= len) {
		err(ctx, "%s: buffer too small!\n",
				accfg_device_get_devname(device));
		return 0;
	}

	if (sysfs_read_attr(ctx, path, buf) < 0)
		return 0;

	if (strcmp(buf, "enabled") == 0)
		return 1;

	return 0;
}

ACCFG_EXPORT int accfg_device_get_cmd_status(struct accfg_device *device)
{
	struct accfg_ctx *ctx;
	long status;
	char *path;
	int len;
	char buf[SYSFS_ATTR_SIZE], *end_ptr;

	if (!device)
		return -EINVAL;

	ctx = accfg_device_get_ctx(device);
	path = device->device_buf;
	len = device->buf_len;

	if (snprintf(path, len, "%s/cmd_status", device->device_path) >= len) {
		err(ctx, "%s: buffer too small!\n",
				accfg_device_get_devname(device));
		return 0;
	}

	if (sysfs_read_attr(ctx, path, buf) < 0)
		return 0;

	status = strtol(buf, &end_ptr, 0);
	if ((errno == ERANGE && (status == LONG_MAX || status == LONG_MIN)) ||
	    (errno != 0 && status == 0))
		return -ERANGE;

	/* Nothing was found */
	if (end_ptr == buf)
		return -ENXIO;

	return (int)status;
}

ACCFG_EXPORT const char * accfg_device_get_cmd_status_str(struct accfg_device *device)
{
	int status;
	const char *stat_str;

	status = accfg_device_get_cmd_status(device);
	if (status < 0)
		return NULL;

	if (status > ACCFG_CMD_STATUS_MAX)
		return NULL;

	stat_str = accfg_device_cmd_status[status];
	if (strlen(stat_str) == 0)
		return NULL;

	return stat_str;
}

/* Helper function to validate device type in the defined device array based on
 * device name */
ACCFG_EXPORT int accfg_device_type_validate(const char *dev_name)
{
	char **accel_type;

	for (accel_type = accfg_basenames;
		*accel_type != NULL;
		accel_type++) {
		if (strstr(dev_name, *accel_type))
			return 1;
	}

	if (*accel_type == NULL) {
		fprintf(stderr, "no such device type\n");
		return 0;
	}

	return 0;
}

/* Helper function to retrieve device_type */
ACCFG_EXPORT enum accfg_device_type accfg_device_get_type(struct accfg_device *device)
{
	return device->type;
}

/* Helper function to retrieve device_type_str */
ACCFG_EXPORT char *accfg_device_get_type_str(struct accfg_device *device)
{
	return device->device_type_str;
}

/* Helper function to parse the device enable flag */
static int accfg_device_control(struct accfg_device *device,
		enum accfg_control_flag flag, bool force)
{
	int rc = 0;
	struct accfg_ctx *ctx;
	char *path = NULL;

	if (!device)
		return -EINVAL;

	ctx = accfg_device_get_ctx(device);

	if (flag == ACCFG_DEVICE_ENABLE) {
		rc = asprintf(&path, "/sys/bus/%s/drivers/%s/bind",
				device->device_type_str, device->device_type_str);
		if (rc < 0)
			return rc;
	} else if (flag == ACCFG_DEVICE_DISABLE) {
		int clients;

		rc = asprintf(&path, "/sys/bus/%s/drivers/%s/unbind",
				device->device_type_str, device->device_type_str);
		if (rc < 0)
			return rc;

		clients = accfg_device_get_clients(device);
		if (clients > 0) {
			err(ctx, "Device has clients: %d.\n", clients);
			if (force) {
				err(ctx, "\n");
			} else {
				err(ctx, "Device disable refused.\n");
				return -EPERM;
			}
		}
	}

	if (path) {
		rc = sysfs_write_attr(ctx, path, accfg_device_get_devname(device));
		free(path);
		if (rc < 0) {
			return rc;
		}
	}

	return 0;
}

ACCFG_EXPORT int accfg_device_enable(struct accfg_device *device)
{
	return accfg_device_control(device, ACCFG_DEVICE_ENABLE, false);
}

ACCFG_EXPORT int accfg_device_disable(struct accfg_device *device, bool force)
{
	return accfg_device_control(device, ACCFG_DEVICE_DISABLE, force);
}

ACCFG_EXPORT struct accfg_device *accfg_group_get_device(
		struct accfg_group *group)
{
	return group->device;
}

ACCFG_EXPORT struct accfg_group *accfg_group_get_first(
		struct accfg_device *device)
{
	groups_init(device);

	return list_top(&device->groups, struct accfg_group, list);
}

ACCFG_EXPORT struct accfg_group *accfg_group_get_next(
		struct accfg_group *group)
{
	struct accfg_device *device = group->device;

	return list_next(&device->groups, group, list);
}

ACCFG_EXPORT int accfg_group_get_id(struct accfg_group *group)
{
	return group->id;
}

ACCFG_EXPORT struct accfg_group *accfg_device_group_get_by_id(
		struct accfg_device *dev, int id)
{
	struct accfg_group *group;

	accfg_group_foreach(dev, group)
		if (accfg_group_get_id(group) == id)
			return group;
	return NULL;
}

ACCFG_EXPORT int accfg_group_get_device_id(
		struct accfg_group *group)
{
	struct accfg_device *device = group->device;

	return device->id;

}

ACCFG_EXPORT const char *accfg_group_get_devname(struct accfg_group *group)
{
	return devpath_to_devname(group->group_path);
}

ACCFG_EXPORT unsigned long accfg_group_get_size(struct accfg_group *group)
{
	return group->size;
}

ACCFG_EXPORT unsigned long accfg_group_get_available_size(
		struct accfg_group *group)
{
	struct accfg_ctx *ctx = accfg_group_get_ctx(group);
	char *path = group->group_buf;
	int len = group->buf_len;
	char buf[SYSFS_ATTR_SIZE];

	if (snprintf(path, len, "%s/available_size",
				group->group_path) >= len) {
		err(ctx, "%s: buffer too small!\n",
		    accfg_group_get_devname(group));
		return ULLONG_MAX;
	}

	if (sysfs_read_attr(ctx, path, buf) < 0)
		return ULLONG_MAX;

	return strtoull(buf, NULL, 0);
}

#define accfg_group_set_field(group, val, field) \
ACCFG_EXPORT int accfg_group_set_##field( \
		struct accfg_group *group, int val) \
{ \
	struct accfg_ctx *ctx = accfg_group_get_ctx(group); \
	char *path = group->group_buf; \
	char buf[SYSFS_ATTR_SIZE]; \
	int rc; \
	rc = sprintf(group->group_buf, "%s/%s", group->group_path, #field); \
	if (rc < 0) \
		return -errno; \
	if (sprintf(buf, "%d", val) < 0) { \
		err(ctx, "%s: sprintf to buf failed: %s\n", \
				accfg_group_get_devname(group), \
				strerror(errno)); \
		return -errno; \
	} \
	if (sysfs_write_attr(ctx, path, buf) < 0) { \
		err(ctx, "%s: write failed: %s\n", \
				accfg_group_get_devname(group), \
				strerror(errno)); \
		return -errno; \
	} \
	group->field = val; \
	return 0; \
}

accfg_group_set_field(group, val, tokens_reserved)
accfg_group_set_field(group, val, tokens_allowed)
accfg_group_set_field(group, val, use_token_limit)
accfg_group_set_field(group, val, traffic_class_a)
accfg_group_set_field(group, val, traffic_class_b)

#define accfg_group_get_field(group, field) \
ACCFG_EXPORT int accfg_group_get_##field( \
		struct accfg_group *group) \
{ \
	return group->field; \
}

accfg_group_get_field(group, tokens_reserved);
accfg_group_get_field(group, tokens_allowed);
accfg_group_get_field(group, use_token_limit);
accfg_group_get_field(group, traffic_class_a);
accfg_group_get_field(group, traffic_class_b);

static void wqs_init(struct accfg_device *device)
{
	struct accfg_ctx *ctx = device->ctx;
	struct accfg_group *group = device->group;

	if (group) {
		if (group->wqs_init) {
			dbg(ctx, "wq is initialized already\n");
			return;
		}
		group->wqs_init = 1;
	}
	set_filename_prefix("wq");
	device_parse(ctx, device->device_path, "wq",
			filter_file_name_prefix, device, add_wq);
}

ACCFG_EXPORT struct accfg_wq *accfg_wq_get_first(
		struct accfg_device *device)
{
	wqs_init(device);

	return list_top(&device->wqs, struct accfg_wq, list);
}

ACCFG_EXPORT struct accfg_wq *accfg_wq_get_next(struct accfg_wq *wq)
{
	struct accfg_device *device = wq->device;

	return list_next(&device->wqs, wq, list);
}

ACCFG_EXPORT int accfg_wq_get_id(struct accfg_wq *wq)
{
	return wq->id;
}

ACCFG_EXPORT struct accfg_wq *accfg_device_wq_get_by_id(
		struct accfg_device *dev, int id)
{
	struct accfg_wq *wq;

	accfg_wq_foreach(dev, wq)
		if (accfg_wq_get_id(wq) == id)
			return wq;
	return NULL;
}

ACCFG_EXPORT struct accfg_device *accfg_ctx_device_get_by_name(
		struct accfg_ctx *ctx, const char *dev_name)
{
	struct accfg_device *dev;

	accfg_device_foreach(ctx, dev)
		if (!strcmp(accfg_device_get_devname(dev), dev_name))
			return dev;
	return NULL;
}

ACCFG_EXPORT unsigned int accfg_wq_get_priv(struct accfg_wq *wq)
{
	return wq->priv;
}

ACCFG_EXPORT struct accfg_group *accfg_wq_get_group(
		struct accfg_wq *wq)
{
	return wq->group;
}

ACCFG_EXPORT struct accfg_device *accfg_wq_get_device(
		struct accfg_wq *wq)
{
	return wq->device;
}

ACCFG_EXPORT struct accfg_ctx *accfg_wq_get_ctx(struct accfg_wq *wq)
{
	return wq->device->ctx;
}

ACCFG_EXPORT const char *accfg_wq_get_devname(struct accfg_wq *wq)
{
	return devpath_to_devname(wq->wq_path);
}

ACCFG_EXPORT int accfg_wq_get_cdev_minor(struct accfg_wq *wq)
{
	return wq->cdev_minor;
}

ACCFG_EXPORT enum accfg_wq_type accfg_wq_get_type(struct accfg_wq *wq)
{
	return wq->type;
}

ACCFG_EXPORT const char *accfg_wq_get_type_name(struct accfg_wq *wq)
{
	return wq->name;
}

ACCFG_EXPORT unsigned long accfg_wq_get_size(struct accfg_wq *wq)
{
	return wq->size;
}

ACCFG_EXPORT unsigned int accfg_wq_get_max_batch_size(struct accfg_wq *wq)
{
	return wq->max_batch_size;
}

ACCFG_EXPORT unsigned long accfg_wq_get_max_transfer_size(struct accfg_wq *wq)
{
	return wq->max_transfer_size;
}

ACCFG_EXPORT int accfg_wq_get_clients(struct accfg_wq *wq)
{
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq);
	char *path = wq->wq_buf;
	char buf[SYSFS_ATTR_SIZE];
	int len = wq->buf_len;
	int rc;

	rc = snprintf(wq->wq_buf, len, "%s/%s", wq->wq_path, "clients");
	if (rc < 0 || rc >= len) {
		err(ctx, "%s: snprintf error: %d\n", __func__, -errno);
		return -errno;
	}

	if (sysfs_read_attr(ctx, path, buf) < 0) {
		err(ctx, "%s: retrieve clients failed: '%s': %s\n",
				__func__, wq->wq_path, strerror(errno));
		return -errno;
	}

	return atoi(buf);
}

ACCFG_EXPORT int accfg_wq_priority_boundary(struct accfg_wq *wq)
{
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq);

	if (wq->priority > WQ_PRIORITY_LIMIT) {
		err(ctx, "wq_priority exceeds %d\n", WQ_PRIORITY_LIMIT);
		return -ERANGE;
	}
	return 0;
}

static int accfg_wq_retrieve_cdev_minor(struct accfg_wq *wq)
{
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq);
	char *path = wq->wq_buf;
	char buf[SYSFS_ATTR_SIZE];
	int rc;

	rc = sprintf(wq->wq_buf, "%s/%s", wq->wq_path, "cdev_minor");
	if (rc < 0)
		return -errno;

	if (sysfs_read_attr(ctx, path, buf) < 0) {
		err(ctx, "%s: retrieve cdev minor failed: '%s': %s\n",
				__func__, wq->wq_path, strerror(errno));
		return -errno;
	}

	wq->cdev_minor = atoi(buf);
	return 0;
}

static int accfg_wq_post_enable(struct accfg_wq *wq)
{
	enum accfg_wq_type type;
	int rc;

	type = accfg_wq_get_type(wq);

	if (type == ACCFG_WQT_USER) {
		rc = accfg_wq_retrieve_cdev_minor(wq);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int accfg_wq_post_disable(struct accfg_wq *wq)
{
	enum accfg_wq_type type;

	type = accfg_wq_get_type(wq);

	if (type == ACCFG_WQT_USER)
		wq->cdev_minor = -1;

	return 0;
}

static int accfg_wq_control_post_processing(struct accfg_wq *wq,
		enum accfg_control_flag flag)
{
	if (flag == ACCFG_WQ_ENABLE)
		return accfg_wq_post_enable(wq);
	else if (flag == ACCFG_WQ_DISABLE)
		return accfg_wq_post_disable(wq);
	else
		return -EINVAL;

	return 0;
}

static bool accfg_wq_state_expected(struct accfg_wq *wq,
		enum accfg_control_flag flag)
{
	enum accfg_wq_state state, expected;

	if (flag == ACCFG_WQ_DISABLE)
		expected = ACCFG_WQ_DISABLED;
	else if (flag == ACCFG_WQ_ENABLE)
		expected = ACCFG_WQ_ENABLED;
	else
		return false;

	state = accfg_wq_get_state(wq);
	if (state != expected)
		return false;
	return true;
}

/* Helper function to parse the wq enable flag */
static int accfg_wq_control(struct accfg_wq *wq, enum accfg_control_flag flag,
		bool force)
{
	int rc = 0;
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq);
	char *path = NULL;
	struct accfg_device *device = accfg_wq_get_device(wq);
	const char *wq_name = accfg_wq_get_devname(wq);

	if (flag == ACCFG_WQ_ENABLE) {
		rc = asprintf(&path, "/sys/bus/%s/drivers/%s/bind",
				device->device_type_str, device->device_type_str);
		if (rc < 0)
			return rc;
	} else if (flag == ACCFG_WQ_DISABLE) {
		int clients;

		rc = asprintf(&path, "/sys/bus/%s/drivers/%s/unbind",
				device->device_type_str, device->device_type_str);
		if (rc < 0)
			return rc;

		clients = accfg_wq_get_clients(wq);
		if (clients > 0) {
			err(ctx, "wq has clients: %d.\n", clients);
			if (!force) {
				err(ctx, " wq disable refused.\n");
				return -EPERM;
			}
		}
	}

	if (path) {
		rc = sysfs_write_attr(ctx, path, wq_name);
		if (rc < 0) {
			free(path);
			return rc;
		}
	}

	free(path);

	/* verify state */
	if (!accfg_wq_state_expected(wq, flag)) {
		err(ctx, "WQ not in expected state.");
		return -ENXIO;
	}

	/* post processing */
	rc = accfg_wq_control_post_processing(wq, flag);
	if (rc < 0)
		return rc;

	return 0;
}

ACCFG_EXPORT int accfg_wq_enable(struct accfg_wq *wq)
{
	return accfg_wq_control(wq, ACCFG_WQ_ENABLE, false);
}

ACCFG_EXPORT int accfg_wq_disable(struct accfg_wq *wq, bool force)
{
	return accfg_wq_control(wq, ACCFG_WQ_DISABLE, force);
}

ACCFG_EXPORT enum accfg_wq_state accfg_wq_get_state(struct accfg_wq *wq)
{
	char read_state[SYSFS_ATTR_SIZE];
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq);
	char *path = wq->wq_buf;
	int len = wq->buf_len;

	if (snprintf(path, len, "%s/state", wq->wq_path) >= len) {
		err(ctx, "%s: buffer too small!\n", __func__);
		return ACCFG_WQ_UNKNOWN;
	}

	if (sysfs_read_attr(ctx, path, read_state) < 0) {
		err(ctx, "%s: sysfs_read_attr failed '%s': %s\n",
				__func__, wq->wq_path, strerror(errno));
		return ACCFG_WQ_UNKNOWN;
	}

	if (strcmp(read_state, "disabled") == 0)
		return ACCFG_WQ_DISABLED;
	else if (strcmp(read_state, "enabled") == 0)
		return ACCFG_WQ_ENABLED;
	else if (strcmp(read_state, "quiescing") == 0)
		return ACCFG_WQ_QUIESCING;

	return ACCFG_WQ_UNKNOWN;
}

ACCFG_EXPORT int accfg_wq_size_boundary(struct accfg_device *device,
		int wq_num)
{
	int max_wqs, total_wq_size = 0;
	struct accfg_wq *wq, *next;
	struct accfg_ctx *ctx;

	if (!device)
		return -EINVAL;
	ctx = accfg_device_get_ctx(device);

	max_wqs = accfg_device_get_max_work_queues(device);
	if (wq_num > max_wqs) {
		err(ctx, "number of wq in the device exceeds %d\n", max_wqs);
		return -ERANGE;
	}

	list_for_each_safe(&device->wqs, wq, next, list) {
		total_wq_size += wq->size;
		if (total_wq_size > device->max_work_queues_size) {
			err(ctx, "accumulated wq size exceeds %d\n",
					device->max_work_queues_size);
			return -ERANGE;
		}
	}

	return 0;
}

#define accfg_wq_set_field(wq, val, field) \
ACCFG_EXPORT int accfg_wq_set_##field( \
		struct accfg_wq *wq, int val) \
{ \
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq); \
	char *path = wq->wq_buf; \
	char buf[SYSFS_ATTR_SIZE]; \
	int rc; \
	rc = sprintf(wq->wq_buf, "%s/%s", wq->wq_path, #field); \
	if (rc < 0) \
		return -errno; \
	if (sprintf(buf, "%d", val) < 0) { \
		err(ctx, "%s: sprintf to buf failed: %s\n", \
				accfg_wq_get_devname(wq), \
				strerror(errno)); \
		return -errno; \
	} \
	if (!accfg_device_get_configurable(wq->device)) { \
		if (!strcmp(#field, "threshold")) { \
			err(ctx, "device is not configurable\n"); \
			return -errno; \
		} \
	} \
	if (sysfs_write_attr(ctx, path, buf) < 0) { \
		err(ctx, "%s: write failed: %s\n", \
				accfg_wq_get_devname(wq), \
				strerror(errno)); \
		return -errno; \
	} \
	wq->field = val; \
	return 0; \
}

accfg_wq_set_field(wq, val, size)
accfg_wq_set_field(wq, val, priority)
accfg_wq_set_field(wq, val, group_id)
accfg_wq_set_field(wq, val, block_on_fault)
accfg_wq_set_field(wq, val, threshold)
accfg_wq_set_field(wq, val, max_batch_size)

#define accfg_wq_set_long_field(wq, val, field) \
ACCFG_EXPORT int accfg_wq_set_##field( \
		struct accfg_wq *wq, unsigned long val) \
{ \
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq); \
	char *path = wq->wq_buf; \
	char buf[SYSFS_ATTR_SIZE]; \
	int rc; \
	rc = sprintf(wq->wq_buf, "%s/%s", wq->wq_path, #field); \
	if (rc < 0) \
		return -errno; \
	if (sprintf(buf, "%ld", val) < 0) { \
		err(ctx, "%s: sprintf to buf failed: %s\n", \
				accfg_wq_get_devname(wq), \
				strerror(errno)); \
		return -errno; \
	} \
	if (!accfg_device_get_configurable(wq->device)) { \
		err(ctx, "device is not configurable\n"); \
		return -errno; \
	} \
	if (sysfs_write_attr(ctx, path, buf) < 0) { \
		err(ctx, "%s: write failed: %s\n", \
				accfg_wq_get_devname(wq), \
				strerror(errno)); \
		return -errno; \
	} \
	wq->field = val; \
	return 0; \
}

accfg_wq_set_long_field(wq, val, max_transfer_size)

#define accfg_wq_set_str_field(wq, val, field) \
ACCFG_EXPORT int accfg_wq_set_str_##field( \
		struct accfg_wq *wq, const char *val) \
{ \
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq); \
	char *path = wq->wq_buf; \
	char buf[SYSFS_ATTR_SIZE]; \
	int rc; \
	rc = sprintf(wq->wq_buf, "%s/%s", wq->wq_path, #field); \
	if (rc < 0) \
		return -errno; \
	if (sprintf(buf, "%s", val) < 0) { \
		err(ctx, "%s: sprintf to buf failed: %s\n", \
				accfg_wq_get_devname(wq), \
				strerror(errno)); \
		return -errno; \
	} \
	if (!accfg_device_get_configurable(wq->device)) { \
		if (strcmp(#field, "name")!= 0) { \
			err(ctx, "device is not configurable\n"); \
			return -errno; \
		} \
	} \
	if (sysfs_write_attr(ctx, path, buf) < 0) { \
		err(ctx, "%s: write failed: %s\n", \
				accfg_wq_get_devname(wq), \
				strerror(errno)); \
		return -errno; \
	} \
	if (wq->field) \
		free(wq->field); \
	wq->field = strdup(val); \
	if (!wq->field) \
		return -ENOMEM; \
	return 0; \
}

accfg_wq_set_str_field(wq, val, mode)
accfg_wq_set_str_field(wq, val, name)

static int wq_parse_type(struct accfg_wq *wq, char *wq_type);

ACCFG_EXPORT int accfg_wq_set_str_type(struct accfg_wq *wq, const char *val)
{
	struct accfg_ctx *ctx = accfg_wq_get_ctx(wq);
	char *path = wq->wq_buf;
	char buf[SYSFS_ATTR_SIZE];
	int rc;
	char *tmp;

	rc = sprintf(wq->wq_buf, "%s/%s", wq->wq_path, "type");
	if (rc < 0)
		return -errno;

	if (sprintf(buf, "%s", val) < 0) {
		err(ctx, "%s: sprintf to buf failed: %s\n",
				accfg_wq_get_devname(wq),
				strerror(errno));
		return -errno;
	}

	if (sysfs_write_attr(ctx, path, buf) < 0) {
		err(ctx, "%s: write failed: %s\n",
				accfg_wq_get_devname(wq),
				strerror(errno));
		return -errno;
	}

	tmp = strdup(val);
	if (!tmp)
		return -ENOMEM;

	rc = wq_parse_type(wq, tmp);
	free(tmp);
	if (rc < 0)
		return rc;

	return 0;
}

#define accfg_wq_get_field(wq, field) \
ACCFG_EXPORT int accfg_wq_get_##field( \
		struct accfg_wq *wq) \
{ \
	return wq->field; \
}

accfg_wq_get_field(wq, priority)
accfg_wq_get_field(wq, threshold)
accfg_wq_get_field(wq, group_id)
accfg_wq_get_field(wq, block_on_fault)

ACCFG_EXPORT int accfg_wq_set_mode(struct accfg_wq *wq,
		enum accfg_wq_mode wq_mode)
{
	if (wq_mode >= ACCFG_WQ_MODE_UNKNOWN)
		return -EINVAL;
	return accfg_wq_set_str_mode(wq, accfg_wq_mode_str[wq_mode]);
}

ACCFG_EXPORT struct accfg_engine *accfg_engine_get_first(
		struct accfg_device *device)
{
	engines_init(device);

	return list_top(&device->engines, struct accfg_engine, list);
}

ACCFG_EXPORT struct accfg_engine *accfg_engine_get_next(
		struct accfg_engine *engine)
{
	struct accfg_device *device = engine->device;

	return list_next(&device->engines, engine, list);
}

ACCFG_EXPORT int accfg_engine_get_id(
		struct accfg_engine *engine)
{
	return engine->id;
}

ACCFG_EXPORT struct accfg_engine *accfg_device_engine_get_by_id(
		struct accfg_device *dev, int id)
{
	struct accfg_engine *engine;

	accfg_engine_foreach(dev, engine)
		if (accfg_engine_get_id(engine) == id)
			return engine;
	return NULL;
}

ACCFG_EXPORT struct accfg_group *accfg_engine_get_group(
		struct accfg_engine *engine)
{
	return engine->group;
}

ACCFG_EXPORT struct accfg_device *accfg_engine_get_device(
		struct accfg_engine *engine)
{
	return engine->group->device;
}

ACCFG_EXPORT struct accfg_ctx *accfg_engine_get_ctx(
		struct accfg_engine *engine)
{
	return engine->device->ctx;
}

#define accfg_engine_set_field(engine, val, field) \
ACCFG_EXPORT int accfg_engine_set_##field( \
		struct accfg_engine *engine, int val) \
{ \
	struct accfg_ctx *ctx = accfg_engine_get_ctx(engine); \
	char *path = engine->engine_buf; \
	char buf[SYSFS_ATTR_SIZE]; \
	int rc; \
	rc = sprintf(engine->engine_buf, "%s/%s", \
			engine->engine_path, #field); \
	if (rc < 0) \
		return -errno; \
	if (sprintf(buf, "%d", val) < 0) { \
		err(ctx, "%s: sprintf to buf failed: %s\n", \
				accfg_engine_get_devname(engine), \
				strerror(errno)); \
		return -errno; \
	} \
	if (sysfs_write_attr(ctx, path, buf) < 0) { \
		err(ctx, "%s: write failed: %s\n", \
				accfg_engine_get_devname(engine), \
				strerror(errno)); \
		return -errno; \
	} \
	engine->field = val; \
	return 0; \
}

accfg_engine_set_field(engine, val, group_id)

#define accfg_engine_get_field(engine, field) \
ACCFG_EXPORT int accfg_engine_get_##field( \
		struct accfg_engine *engine) \
{ \
	return engine->field; \
}

accfg_engine_get_field(engine, group_id)
