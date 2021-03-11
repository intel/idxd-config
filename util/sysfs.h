/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */

#ifndef __UTIL_SYSFS_H__
#define __UTIL_SYSFS_H__

#include <string.h>
#include <dirent.h>

typedef void *(*add_dev_fn)(void *parent, int id, const char *dev_path,
		char *dev_prefix, char *bus_type);

#define SYSFS_ATTR_SIZE 1024

struct log_ctx;
int __sysfs_read_attr(struct log_ctx *ctx, const char *path, char *buf);
int __sysfs_write_attr(struct log_ctx *ctx, const char *path, const char *buf);
int __sysfs_write_attr_quiet(struct log_ctx *ctx, const char *path,
		const char *buf);
int __sysfs_device_parse(struct log_ctx *ctx, const char *base_path,
		char *dev_prefix, char *bus_type,
		int (*filter)(const struct dirent *),
		void *parent, add_dev_fn add_dev);

#define sysfs_read_attr(c, p, b) __sysfs_read_attr(&(c)->ctx, (p), (b))
#define sysfs_write_attr(c, p, b) __sysfs_write_attr(&(c)->ctx, (p), (b))
#define sysfs_write_attr_quiet(c, p, b) __sysfs_write_attr_quiet(&(c)->ctx, (p), (b))
#define sysfs_device_parse(c, b, d, bt, m, p, fn) __sysfs_device_parse(&(c)->ctx, \
		(b), (d), (bt), (m), (p), (fn))

static inline const char *devpath_to_devname(const char *devpath)
{
	return strrchr(devpath, '/') + 1;
}
#endif /* __UTIL_SYSFS_H__ */
