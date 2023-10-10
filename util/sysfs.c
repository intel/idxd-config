/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
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

#include <util/log.h>
#include <util/sysfs.h>

int __sysfs_read_attr(struct log_ctx *ctx, const char *path, char *buf)
{
	int fd = open(path, O_RDONLY|O_CLOEXEC);
	int n;

	if (fd < 0) {
		return -errno;
	}
	n = read(fd, buf, SYSFS_ATTR_SIZE);
	close(fd);
	if (n < 0 || n >= SYSFS_ATTR_SIZE) {
		buf[0] = 0;
		log_dbg(ctx, "failed to read %s: %s\n", path, strerror(errno));
		return -errno;
	}
	buf[n] = 0;
	if (n && buf[n-1] == '\n'){
		buf[n-1] = 0;
	}
	return 0;
}

static int write_attr(struct log_ctx *ctx, const char *path,
		const char *buf, int quiet)
{
	int fd = open(path, O_WRONLY|O_CLOEXEC);
	int n, len = strlen(buf), rc;

	if (fd < 0) {
		rc = -errno;
		log_dbg(ctx, "failed to open %s: %s\n", path, strerror(errno));
		return rc;
	}
	n = write(fd, buf, len);
	rc = -errno;
	close(fd);
	if (n < len) {
		if (!quiet)
			log_dbg(ctx, "failed to write %s to %s: %s\n", buf, path,
					strerror(errno));
		return rc;
	}
	return 0;
}

int __sysfs_write_attr(struct log_ctx *ctx, const char *path,
		const char *buf)
{
	return write_attr(ctx, path, buf, 0);
}

int __sysfs_write_attr_quiet(struct log_ctx *ctx, const char *path,
		const char *buf)
{
	return write_attr(ctx, path, buf, 1);
}

int __sysfs_device_parse(struct log_ctx *ctx, const char *base_path,
			char *dev_prefix, char *bus_type,
			int (*filter)(const struct dirent *),
			void *parent, add_dev_fn add_dev)
{
	int add_errors = 0;
	struct dirent **d, *de;
	int i, n;

	n = scandir(base_path, &d, filter, alphasort);
	if (n == -1)
		return -ENODEV;

	for (i = 0; i < n; i++) {
		char *dev_path;
		void *dev;
		int id;

		de = d[i];
		if (sscanf(de->d_name, "%*[a-z]%d", &id) < 0) {
			while (n--)
				free(d[n]);
			free(d);
			return -EINVAL;
		}
		if (strchr(de->d_name, '!'))
			continue;
		if (asprintf(&dev_path, "%s/%s", base_path, de->d_name) < 0) {
			log_err(ctx, "%s%d: path allocation failure\n",
				de->d_name, id);
			continue;
		}
		dev = add_dev(parent, id, dev_path, dev_prefix, bus_type);
		free(dev_path);
		if (!dev) {
			add_errors++;
			log_err(ctx, "%d: add_dev() failed\n", id);
		} else
			log_dbg(ctx, "%d: processed\n", id);
	}
	while (n--)
		free(d[n]);
	free(d);

	return add_errors;
}
