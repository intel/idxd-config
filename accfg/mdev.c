/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>
#include <linux/limits.h>
#include <linux/uuid.h>
#include <util/filter.h>
#include <util/util.h>
#include <util/parse-options.h>
#include <util/strbuf.h>
#include <accfg/libaccel_config.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <accfg.h>

static int opt_called;
static struct accfg_device *device;

static int opt_cb_create_mdev(const struct option *opt, const char *arg, int unset)
{
	char **m;

	if (opt->short_name != 'l')
		return -1;

	printf("Available mdev types:\n");
	for (m = accfg_mdev_basenames; *m; m++)
		printf("\t%s\n", *m);

	opt_called = true;

	return 0;
}

static int opt_cb_remove_mdev(const struct option *opt, const char *arg, int unset)
{
	uuid_t uuid;
	char uuid_str[UUID_STR_LEN];
	struct accfg_device_mdev *mdev;
	enum accfg_mdev_type type;

	if (opt->short_name != 'l')
		return -1;

	printf("Available mdevs:\n");
	accfg_device_mdev_foreach(device, mdev) {
		accfg_mdev_get_uuid(mdev, uuid);
		type = accfg_mdev_get_type(mdev);
		uuid_unparse(uuid, uuid_str);
		printf("\tuuid:%s, type:%s\n", uuid_str,
				accfg_mdev_basenames[type]);
	}
	opt_called = true;

	return 0;
}

int cmd_create_mdev(int argc, const char **argv, void *ctx)
{
	char **m;
	int rc, t;
	uuid_t uuid;
	char uuid_str[UUID_STR_LEN];

	const struct option options[] = {
		OPT_CALLBACK_NOOPT('l', "list-mdev-types", NULL, NULL,
				"will list available mdev types", opt_cb_create_mdev),
		OPT_END(),
	};

	const char *const u[] = {
		"accfg create-mdev <device name> [<mdev type>|<options>]",
		NULL
	};

	if (argc < 3)
		usage_with_options(u, options);

	device = accfg_ctx_device_get_by_name(ctx, argv[1]);
	if (!device) {
		fprintf(stderr, "Enter a valid device to create mdev\n");
		usage_with_options(u, options);
	}

	if (!accfg_device_get_mdev_enabled(device)) {
		fprintf(stderr, "mdev support not available\n");
		return 0;
	}

	parse_options(argc, argv, options, u, 0);
	if (opt_called)
		return 0;

	for (m = accfg_mdev_basenames, t = 0; *m; m++, t++)
		if (!strcmp(argv[1], *m))
			break;
	if (!*m) {
		fprintf(stderr, "Invalid mdev type\n");
		usage_with_options(u, options);
	}

	rc = accfg_create_mdev(device, t, uuid);
	if (rc < 0)
		return rc;

	uuid_unparse(uuid, uuid_str);
	printf("Created mdev with uuid: %s\n", uuid_str);

	return 0;
}

int cmd_remove_mdev(int argc, const char **argv, void *ctx)
{
	int rc;
	uuid_t uuid;

	const struct option options[] = {
		OPT_CALLBACK_NOOPT('l', "list-mdevs", NULL, NULL,
				"will list available mdevs", opt_cb_remove_mdev),
		OPT_END(),
	};

	const char *const u[] = {
		"accfg remove-mdev <device name> [<uuid>|<options>]",
		"Pass \"all\" to remove all mdevs",
		NULL
	};

	if (argc < 3)
		usage_with_options(u, options);

	device = accfg_ctx_device_get_by_name(ctx, argv[1]);
	if (!device) {
		fprintf(stderr, "Enter a valid device to remove mdev\n");
		usage_with_options(u, options);
	}

	if (!accfg_device_get_mdev_enabled(device)) {
		fprintf(stderr, "mdev support not available\n");
		return 0;
	}

	parse_options(argc, argv, options, u, 0);
	if (opt_called)
		return 0;

	if (!strcmp(argv[1], "all"))
		uuid_clear(uuid);
	else if (uuid_parse(argv[1], uuid) < 0) {
		fprintf(stderr, "Invalid uuid\n");
		usage_with_options(u, options);
	}

	rc = accfg_remove_mdev(device, uuid);

	return rc;
}
