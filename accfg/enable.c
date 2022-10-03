// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2019 Intel Corporation. All rights reserved.

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
#include <accfg/libaccel_config.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <accfg.h>
#include "private.h"

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
	bool force;
} param;

static const struct option device_options[] = {
	OPT_BOOLEAN('v', "verbose", &param.verbose, "turn on debug"),
	OPT_END(),
};

static const struct option device_disable_options[] = {
	OPT_BOOLEAN('v', "verbose", &param.verbose, "turn on debug"),
	OPT_BOOLEAN('f', "force", &param.force, "force action"),
	OPT_END(),
};

static int action_disable_device(struct accfg_device *device)
{
	if (!accfg_device_is_active(device)) {
		fprintf(stderr, "%s is in disabled state already, skipping...\n",
			accfg_device_get_devname(device));
		return -EBUSY;
	}

	return accfg_device_disable(device, param.force);
}

static int action_enable_device(struct accfg_device *device)
{
	if (accfg_device_is_active(device)) {
		fprintf(stderr, "%s is in enabled state already, skipping...\n",
			accfg_device_get_devname(device));
		return -EBUSY;
	}

	return accfg_device_enable(device);
}

static int dev_action_switch(struct accfg_device *device,
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
			 struct accfg_ctx *ctx)
{
	const char *const u[] = {
		usage,
		NULL
	};
	int i, rc = -EINVAL, success = 0;
	enum accfg_device_state state;

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0)
		usage_with_options(u, options); /* exits app */

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "all") == 0) {
			argv[0] = "all";
			argc = 1;
			break;
		}
	}

	for (i = 0; i < argc; i++) {
		struct accfg_device *device;

		if (parse_device_name(ctx, argv[i], &device)) {
			if (param.verbose)
				fprintf(stderr,
					"%s device not found\n", argv[i]);
			continue;
		}

		rc = dev_action_switch(device, action);
		if (rc == 0) {
			/*
			 * Double check if the state of the device
			 * matches with the enable/disable
			 */
			state = accfg_device_get_state(device);
			if (((state != ACCFG_DEVICE_ENABLED) &&
					(action == DEV_ACTION_ENABLE)) ||
					((state != ACCFG_DEVICE_DISABLED) &&
					(action == DEV_ACTION_DISABLE)))
				rc = ENXIO;
		}
		if (rc == 0)
			success++;
		else
			fprintf(stderr, "failed in %s\n", argv[i]);
	}

	fprintf(stderr, "%s %d device(s) out of %d\n",
			action == DEV_ACTION_ENABLE ? "enabled" : "disabled",
				success, argc);

	if (success)
		return 0;

	return rc;
}

static int action_disable_wq(struct accfg_wq *wq, const char *wq_name)
{
	enum accfg_wq_state wq_state = accfg_wq_get_state(wq);

	if (wq_state == ACCFG_WQ_DISABLED) {
		fprintf(stderr,
			"%s is in disabled mode already, skipping...\n",
			wq_name);
		return -ENXIO;
	} else if (wq_state == ACCFG_WQ_QUIESCING) {
		fprintf(stderr,
			"%s is in quiescing mode, skipping...\n",
			wq_name);
		return -EBUSY;
	}
	return accfg_wq_disable(wq, param.force);
}

static int action_enable_wq(struct accfg_wq *wq, const char *wq_name)
{
	enum accfg_wq_state wq_state = accfg_wq_get_state(wq);

	if (wq_state == ACCFG_WQ_ENABLED || wq_state == ACCFG_WQ_LOCKED) {
		fprintf(stderr,
			"%s is in enabled or locked mode, skipping...\n",
			wq_name);
		return -ENXIO;
	} else if (wq_state == ACCFG_WQ_QUIESCING) {
		fprintf(stderr,
			"%s is in quiescing mode, skipping...\n",
			wq_name);
		return -EBUSY;
	}
	return accfg_wq_enable(wq);
}

static int wq_action_switch(struct accfg_wq *wq, enum wq_action action,
				const char *wq_name)
{
	switch (action) {
	case WQ_ACTION_ENABLE:
		return action_enable_wq(wq, wq_name);
	case WQ_ACTION_DISABLE:
		return action_disable_wq(wq, wq_name);
	default:
		return -EINVAL;
	}
}

static int wq_action(int argc, const char **argv, const char *usage,
			const struct option *options, enum wq_action action,
			struct accfg_ctx *ctx)
{
	const char *const u[] = {
		usage,
		NULL
	};
	int i, rc = -EINVAL, success = 0;

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0)
		usage_with_options(u, options); /* exits app */

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "all") == 0) {
			argv[0] = "all";
			argc = 1;
			break;
		}
	}

	for (i = 0; i < argc; i++) {
		struct accfg_device *device;
		struct accfg_wq *wq;

		if (parse_wq_name(ctx, argv[i], &device, &wq)) {
			if (param.verbose)
				fprintf(stderr, "%s wq not found\n", argv[i]);
			continue;
		}

		rc = wq_action_switch(wq, action, argv[i]);
		if (rc == 0)
			success++;
		else
			fprintf(stderr, "failed in %s\n", argv[i]);
	}

	fprintf(stderr, "%s %d wq(s) out of %d\n",
			action == WQ_ACTION_ENABLE ? "enabled" : "disabled",
				success, argc);

	if (success)
		return 0;

	return rc;
}

int cmd_disable_device(int argc, const char **argv, void *ctx)
{
	char *usage =
	    "accel-config disable-device <accel_basename0> [<accel_basename1>..<accel_basenameN>] [<options>]";
	int count = device_action(argc, argv, usage, device_disable_options,
				  DEV_ACTION_DISABLE, ctx);
	return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_enable_device(int argc, const char **argv, void *ctx)
{
	char *usage =
	    "accel-config enable-device <accel_basename0> [<accel_basename1>..<accel_basenameN>] [<options>]";
	int count = device_action(argc, argv, usage, device_options,
				  DEV_ACTION_ENABLE, ctx);
	return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_disable_wq(int argc, const char **argv, void *ctx)
{
	char *usage =
	    "accel-config disable-wq <accel_basenameX>/<wqX.0> [<wqX.1>..<wqX.N>] [<options>] X is the device number where wq belongs to";
	int count = wq_action(argc, argv, usage, device_disable_options,
			      WQ_ACTION_DISABLE, ctx);
	return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_enable_wq(int argc, const char **argv, void *ctx)
{
	char *usage =
	    "accel-config enable-wq <accel_basenameX>/<wqX.0> [<wqX.1>..<wqX.N>] [<options>] X is the device number where wq belongs to";
	int count = wq_action(argc, argv, usage, device_options,
			      WQ_ACTION_ENABLE, ctx);

	return count >= 0 ? 0 : EXIT_FAILURE;
}
