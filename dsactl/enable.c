/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json.h>
#include <libgen.h>
#include <dirent.h>
#include <linux/limits.h>
#include <util/json.h>
#include <util/filter.h>
#include <util/util.h>
#include <util/parse-options.h>
#include <util/strbuf.h>
#include <dsactl/libdsactl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <dsactl.h>
#include "private.h"

#define MAX_PARAM_LEN 50

const char *DSA_BIND_PATH = "/sys/bus/dsa/drivers/dsa_bus/bind";
const char *DSA_UNBIND_PATH = "/sys/bus/dsa/drivers/dsa_bus/unbind";
const char *CTL_BASE = "/sys/bus/dsa/devices";

enum dev_action {
	DEV_ACTION_ENABLE = 0,
	DEV_ACTION_DISABLE,
};

enum wq_action {
	WQ_ACTION_ENABLE = 0,
	WQ_ACTION_DISABLE,
};

static struct {
	bool verbose;
} param;

static const struct option device_options[] = {
	OPT_BOOLEAN('v', "verbose", &param.verbose, "turn on debug"),
	OPT_END(),
};

/* Helper function to check write access to file */
static bool user_write_access_check(int fd)
{
	struct stat stat;
	int rc;

	rc = fstat(fd, &stat);

	if (rc < 0) {
		rc = errno;
		return EXIT_FAILURE;
	}

	if (stat.st_mode & S_IWUSR) {
		return true;
	}

	return false;
}

/* Helper function to enable/disable the part in device */
static int dsactl_enable(const char *name, int flag)
{
	int rc = 0;
	int len = strlen(name) + 1;
	int fd = 0;

	if (flag == 1)
		fd = open(DSA_BIND_PATH, O_WRONLY);
	else
		fd = open(DSA_UNBIND_PATH, O_WRONLY);

	if (fd < 0) {
		rc = -errno;
		fprintf(stderr,
			"dsactl_enable: open bind path failed for '%s': %s\n",
			name, strerror(errno));
		close(fd);
		return rc;
	}

	if (user_write_access_check(fd) == false) {
		rc = -errno;
		fprintf(stderr,
			"dsactl_enable: write access check failed for '%s': %s\n",
			name, strerror(errno));
		close(fd);
		return rc;
	}

	rc = write(fd, name, len);
	if (rc < 0) {
		rc = -errno;
		fprintf(stderr,
			"dsactl_enable: write failed in device for '%s': %s\n",
			name, strerror(errno));
		close(fd);
		return rc;
	}

	close(fd);
	return 0;
}

/* Helper function to read the state value in the device and workqueue */
static char *get_state_str(int dfd, const char *name)
{
	int fd = openat(dfd, name, O_RDONLY);
	char buf[MAX_PARAM_LEN + 1];
	int n;

	if (fd == -1) {
		fprintf(stderr,
			"get_state_str: could not open '%s: %s\n'", name,
			strerror(errno));
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

static int action_disable_device(struct dsactl_device *device)
{
	const char *device_name = dsactl_device_get_devname(device);

	if (!dsactl_device_is_active(device)) {
		fprintf(stderr, "%s is disabled, skipping...\n",
			dsactl_device_get_devname(device));
		return -EINVAL;
	}

	return dsactl_enable(device_name, 0);
}

static int action_enable_device(struct dsactl_device *device)
{
	const char *device_name = dsactl_device_get_devname(device);

	if (dsactl_device_is_active(device)) {
		fprintf(stderr, "%s is enabled, skipping...\n",
			dsactl_device_get_devname(device));
		return -EBUSY;
	}

	return dsactl_enable(device_name, 1);
}

static int dev_action_switch(struct dsactl_device *device,
			     enum dev_action action)
{
	switch (action) {
	case DEV_ACTION_ENABLE:
		return action_enable_device(device);
	case DEV_ACTION_DISABLE:
		return action_disable_device(device);
	default:
		return -EINVAL;
	}
}

static int device_action(int argc, const char **argv, const char *usage,
			 const struct option *options, enum dev_action action,
			 struct dsactl_ctx *ctx)
{
	const char *const u[] = {
		usage,
		NULL
	};
	unsigned long id;
	int i, dfd, rc = 0, success = 0, fail = 0, fail_reason = 0;
	struct dsactl_device *device;
	const char *all = "all";
	char open_path[PATH_MAX];
	char *state;

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0) {
		argc = 1;
		argv = &all;
		usage_with_options(u, options);
	} else {
		for (i = 0; i < argc; i++) {
			if (strcmp(argv[i], "all") == 0) {
				argv[0] = "all";
				argc = 1;
				break;
			}
		}
	}

	for (i = 0; i < argc; i++) {
		int found = 0;

		if (sscanf(argv[i], "dsa%lu", &id) != 1) {
			fprintf(stderr, "'%s' is not a valid device name\n",
				argv[i]);
			return -EINVAL;
		}

		dsactl_device_foreach(ctx, device) {
			if (!util_device_filter(device, argv[i]))
				continue;
			found++;
			rc = dev_action_switch(device, action);
			if (rc == 0) {
				/* double check if the state of the device matches with the
				 * enable/disable */
				sprintf(open_path, "%s%s%s", CTL_BASE, "/",
					argv[i]);
				dfd = open(open_path, O_PATH);
				if (dfd < 0) {
					fprintf(stderr,
						"device_action: could not open '%s': %s\n",
						open_path, strerror(errno));
					rc = errno;
					close(dfd);
					return rc;
				}
				state = get_state_str(dfd, "state");
				if ((strcmp(state, "enabled") == 0
				     && (action == DEV_ACTION_ENABLE))
				    || (strcmp(state, "disabled") == 0
					&& (action == DEV_ACTION_DISABLE)))
					success++;
				else
					fail++;
				close(dfd);
			} else if (!fail) {
				fail_reason = rc;
				fprintf(stderr, "failed in %s\n", argv[i]);
			}
		}

		if (!found && param.verbose)
			fprintf(stderr, "no device matches id: %s\n", argv[i]);
	}

	if (success) {
		if (action == DEV_ACTION_ENABLE)
			fprintf(stderr, "successfully enabled %d dsa%s\n", success,
				success > 1 ? "s" : "");
		else
			fprintf(stderr, "successfully disabled %d dsa%s\n", success,
				success > 1 ? "s" : "");
		return success;
	}

	if (fail) {
		if (action == DEV_ACTION_ENABLE)
			fprintf(stderr, "failed to enable %d dsa%s\n", fail,
				fail > 1 ? "s" : "");
		else
			fprintf(stderr, "failed to disable %d dsa%s\n", fail,
				fail > 1 ? "s" : "");

		return fail;
	}

	if (fail_reason) {
		fprintf(stderr, "failed due to reason %d\n",
			 fail_reason);
		return fail_reason;
	}

	return -ENXIO;
}

static int action_disable_wq(struct dsactl_wq *wq)
{
	const char *wq_name = dsactl_wq_get_devname(wq);
	enum dsactl_wq_state wq_state = dsactl_wq_get_state(wq);

	if (wq_state == 0) {
		fprintf(stderr,
			"%s is in disabled mode already, skipping...\n",
			wq_name);
		return -EBUSY;
	} else if (wq_state == 2) {
		fprintf(stderr,
			"%s is in quiescing mode, skipping...\n", wq_name);
		return -EBUSY;
	}
	return dsactl_enable(wq_name, 0);
}

static int action_enable_wq(struct dsactl_wq *wq)
{
	const char *wq_name = dsactl_wq_get_devname(wq);
	enum dsactl_wq_state wq_state = dsactl_wq_get_state(wq);

	if (wq_state == 1) {
		fprintf(stderr,
			"%s is in enabled mode already, skipping...\n",
			wq_name);
		return -EBUSY;
	} else if (wq_state == 2) {
		fprintf(stderr,
			"%s is in quiescing mode, skipping...\n", wq_name);
		return -EBUSY;
	}
	return dsactl_enable(wq_name, 1);
}

static int wq_action_switch(struct dsactl_wq *wq, enum wq_action action)
{
	switch (action) {
	case WQ_ACTION_ENABLE:
		return action_enable_wq(wq);
	case WQ_ACTION_DISABLE:
		return action_disable_wq(wq);
	default:
		return -EINVAL;
	}
}

static int wq_action(int argc, const char **argv, const char *usage,
		     const struct option *options, enum wq_action action,
		     struct dsactl_ctx *ctx)
{
	const char *const u[] = {
		usage,
		NULL
	};
	unsigned long dev_id, wq_id;
	int i, dfd, rc = 0, success = 0, fail = 0, fail_reason = 0;
	const char *all = "all";
	char open_path[PATH_MAX];
	char *state;

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0) {
		argc = 1;
		argv = &all;
		usage_with_options(u, options);
	} else {
		for (i = 0; i < argc; i++) {
			if (strcmp(argv[i], "all") == 0) {
				argv[0] = "all";
				argc = 1;
				break;
			}
		}
	}

	for (i = 0; i < argc; i++) {
		struct dsactl_device *device;
		struct dsactl_wq *wq;
		char dev_name[MAX_BUF_LEN];
		int found = 0;
		if (sscanf(argv[i], "wq%lu.%lu", &dev_id, &wq_id) != 2) {
			fprintf(stderr, "'%s' is not a valid device name\n",
				argv[i]);
			return -EINVAL;
		}

		sprintf(dev_name, "%s%lu", "dsa", dev_id);

		dsactl_device_foreach(ctx, device) {
			if (!util_device_filter(device, dev_name))
				continue;
			dsactl_wq_foreach(device, wq) {
				if (!util_wq_filter(wq, argv[i]))
					continue;
				found++;
				rc = wq_action_switch(wq, action);
				if (rc == 0) {
					/* double check if the state of the wq matches with the
					 * enable/disable */
					sprintf(open_path, "%s%s%s", CTL_BASE,
						"/", argv[i]);
					dfd = open(open_path, O_PATH);
					if (dfd < 0) {
						fprintf(stderr,
							"wq_action: could not open '%s': %s\n",
							open_path,
							strerror(errno));
						close(dfd);
						rc = errno;
						return rc;
					}
					state = get_state_str(dfd, "state");
					if ((strcmp(state, "enabled") == 0
					     && (action == WQ_ACTION_ENABLE))
					    || (strcmp(state, "disabled") == 0
						&& (action ==
						    WQ_ACTION_DISABLE)))
						success++;
					else
						fail++;
					close(dfd);
				} else if (!fail) {
					fail_reason = rc;
					fprintf(stderr, "failed in %s\n",
						argv[i]);
				}
			}
		}

		if (!found && param.verbose)
			fprintf(stderr, "no wq matches id: %s\n", argv[i]);
	}

	if (success) {
		if (action == WQ_ACTION_ENABLE)
			fprintf(stderr, "successfully enabled %d wq%s\n", success,
			success > 1 ? "s" : "");
		else
			fprintf(stderr, "successfully disabled %d wq%s\n", success,
			success > 1 ? "s" : "");
		return success;
	}

	if (fail) {
		if (action == WQ_ACTION_ENABLE)
			fprintf(stderr, "failed to enable %d wq%s\n",
			fail, fail > 1 ? "s" : "");
		else
			fprintf(stderr, "failed to disable %d wq%s\n",
			fail, fail > 1 ? "s" : "");
		return fail;
	}

	if (fail_reason) {
		fprintf(stderr, "failed due to reason %d\n",
			fail_reason);
		return fail_reason;
	}
	return -ENXIO;
}

int cmd_disable_device(int argc, const char **argv, void *ctx)
{
	char *usage =
	    "dsactl disable-device <dsa0> [<dsa1>..<dsaN>] [<options>]";
	int count = device_action(argc, argv, usage, device_options,
				  DEV_ACTION_DISABLE, ctx);
	return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_enable_device(int argc, const char **argv, void *ctx)
{
	char *usage =
	    "dsactl enable-device <dsa0> [<dsa1>..<dsaN>] [<options>]";
	int count = device_action(argc, argv, usage, device_options,
				  DEV_ACTION_ENABLE, ctx);
	return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_disable_wq(int argc, const char **argv, void *ctx)
{
	char *usage =
	    "dsactl disable-wq <wqX.0> [<wqX.1>..<wqX.N>] [<options>] X is the device number where wq belongs to";
	int count = wq_action(argc, argv, usage, device_options,
			      WQ_ACTION_DISABLE, ctx);
	return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_enable_wq(int argc, const char **argv, void *ctx)
{
	char *usage =
	    "dsactl enable-wq <wqX.0> [<wqX.1>..<wqX.N>] [<options>] X is the device number where wq belongs to";
	int count = wq_action(argc, argv, usage, device_options,
			      WQ_ACTION_ENABLE, ctx);

	return count >= 0 ? 0 : EXIT_FAILURE;
}
