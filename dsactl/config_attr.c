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

struct util_filter_params param;
const char *ctl_base = "/sys/bus/dsa/devices/";

static struct dev_parameters {
	unsigned int token_limit;
} dev_param;

static struct group_parameters {
	unsigned int tokens_reserved;
	unsigned int tokens_allowed;
	unsigned int use_token_limit;
	int traffic_class_a;
	int traffic_class_b;
} group_param = {
	.tokens_reserved = UINT_MAX,
	.tokens_allowed = UINT_MAX,
	.use_token_limit = UINT_MAX,
	.traffic_class_a = UINT_MAX,
	.traffic_class_b = UINT_MAX
};

static struct wq_parameters {
	unsigned int group_id;
	unsigned int wq_size;
	int priority;
	int enforce_order;
	int block_on_fault;
	const char *mode;
} wq_param = {
	.group_id = UINT_MAX,
	.wq_size = UINT_MAX,
	.priority = UINT_MAX,
	.enforce_order = UINT_MAX,
	.block_on_fault = UINT_MAX
};

static struct engine_parameters {
	unsigned int group_id;
} engine_param;

static int set_param(int dfd, char *name, const char *buf)
{
	int rc, written = 0;
	int len = strlen(buf);
	int fd = openat(dfd, name, O_RDWR);

	if (fd < 0) {
		fprintf(stderr, "set_param: could not open '%s': %s\n",
			name, strerror(errno));
		close(fd);
		return -errno;
	}

	do {
		rc = write(fd, buf + written, len - written);
		if (rc < 0) {
			fprintf(stderr, "write failed with %s\n",
				strerror(errno));
			rc = -errno;
			close(fd);
			return rc;
		}
		written += rc;
	} while (written != len);

	close(fd);
	return 0;
}

static int parse_group_attribs(const char *group)
{
	char group_path[PATH_MAX];
	char buf[MAX_BUF_LEN];
	int group_dfd, rc;

	if (group_param.tokens_reserved > 1 &&
		group_param.tokens_reserved != UINT_MAX) {
		fprintf(stderr,
			"configured value for group is not within range\n");
		return -EINVAL;
	}

	if (group_param.tokens_allowed > 1 &&
		group_param.tokens_allowed != UINT_MAX) {
		fprintf(stderr, "valid tokens-reserved should be 0 or 1\n");
		return -EINVAL;
	}

	if (group_param.use_token_limit > 1 &&
		group_param.use_token_limit != UINT_MAX) {
		fprintf(stderr, "valid use-token-limit should be 0 or 1\n");
		return -EINVAL;
	}

	if (group_param.traffic_class_a < -1) {
		fprintf(stderr,
			"valid traffic-class-a should be positive\n");
		return -EINVAL;
	}

	if (group_param.traffic_class_b < -1) {
		fprintf(stderr,
			"valid traffic-class-b should be positive\n");
		return -EINVAL;
	}

	sprintf(group_path, "%s%s", ctl_base, group);
	group_dfd = open(group_path, O_PATH);
	if (group_dfd < 0) {
		fprintf(stderr, "cmd_config_group: could not open '%s': %s\n",
				group_path, strerror(errno));
		rc = -errno;
		close(group_dfd);
		return rc;
	}

	if (group_param.tokens_reserved != UINT_MAX) {
		sprintf(buf, "%u", group_param.tokens_reserved);
		rc = set_param(group_dfd, "tokens_reserved", buf);
		if (rc != 0)
			return rc;
	}

	if (group_param.tokens_allowed != UINT_MAX) {
		sprintf(buf, "%u", group_param.tokens_allowed);
		rc = set_param(group_dfd, "tokens_allowed", buf);
		if (rc != 0)
			return rc;
	}

	if (group_param.use_token_limit != UINT_MAX) {
		sprintf(buf, "%u", group_param.use_token_limit);
		rc = set_param(group_dfd, "use_token_limit", buf);
		if (rc != 0)
			return rc;
	}

	if ((unsigned int)group_param.traffic_class_a != UINT_MAX) {
		sprintf(buf, "%u", group_param.traffic_class_a);
		rc = set_param(group_dfd, "traffic_class_a", buf);
		if (rc != 0)
			return rc;
	}

	if ((unsigned int)group_param.traffic_class_b != UINT_MAX) {
		sprintf(buf, "%u", group_param.traffic_class_b);
		rc = set_param(group_dfd, "traffic_class_b", buf);
		if (rc != 0)
			return rc;
	}

	close(group_dfd);
	return 0;
}

static int parse_wq_attribs(const char *wq, unsigned int max_groups, unsigned int max_wq_size)
{
	char wq_path[PATH_MAX];
	char buf[MAX_BUF_LEN];
	int wq_dfd = 0, rc;

	if (wq_param.mode) {
		if ((strcmp(wq_param.mode, "shared") != 0) &&
			(strcmp(wq_param.mode, "dedicated") != 0)) {
			fprintf(stderr,
				"valid mode should be shared or dedicated\n");
			return -EINVAL;
		}
	}

	if ((wq_param.wq_size > max_wq_size)
		&& (wq_param.wq_size != UINT_MAX)) {
		fprintf(stderr,
			"valid size should be 0 to %d\n", max_wq_size);
		return -EINVAL;
	}

	if ((wq_param.group_id > max_groups)
		&& (wq_param.group_id != UINT_MAX)) {
		fprintf(stderr,
			"valid group_id should be 0 to %d\n", max_groups);
		return -EINVAL;
	}

	if (wq_param.priority < -1) {
		fprintf(stderr,
			"valid set priority should be more than 0\n");
		return -EINVAL;
	}

	if ((wq_param.enforce_order > 1)
		&& ((unsigned int)wq_param.enforce_order != UINT_MAX)) {
		fprintf(stderr,
			"valid enforce-order should be either 0 or 1\n");
		return -EINVAL;
	}

	if (wq_param.block_on_fault > 1
		&& ((unsigned int)wq_param.block_on_fault != UINT_MAX)) {
		fprintf(stderr,
			"valid block-on-default should be either 0 or 1\n");
		return -EINVAL;
	}

	sprintf(wq_path, "%s%s", ctl_base, wq);
	wq_dfd = open(wq_path, O_PATH);
	if (wq_dfd < 0) {
		fprintf(stderr,
			"cmd_config_wq: could not open '%s': %s\n",
			wq_path, strerror(errno));
		rc = -errno;
		close(wq_dfd);
		return -rc;
	}

	if (wq_param.mode) {
		sprintf(buf, "%s", wq_param.mode);
		rc = set_param(wq_dfd, "mode", buf);
		if (rc != 0)
			return rc;
	}

	if (wq_param.wq_size != UINT_MAX) {
		sprintf(buf, "%u", wq_param.wq_size);
		rc = set_param(wq_dfd, "size", buf);
		if (rc != 0)
			return rc;
	}

	if (wq_param.group_id != UINT_MAX) {
		sprintf(buf, "%u", wq_param.group_id);
		rc = set_param(wq_dfd, "group_id", buf);
		if (rc != 0)
			return rc;
	}

	if ((unsigned int)wq_param.priority != UINT_MAX) {
		sprintf(buf, "%u", wq_param.priority);
		rc = set_param(wq_dfd, "priority", buf);
		if (rc != 0)
			return rc;
	}

	if ((unsigned int)wq_param.enforce_order != UINT_MAX) {
		sprintf(buf, "%u", wq_param.enforce_order);
		rc = set_param(wq_dfd, "enforce_order",
				buf);
		if (rc != 0)
			return rc;
	}

	if ((unsigned int)wq_param.block_on_fault != UINT_MAX) {
		sprintf(buf, "%u", wq_param.block_on_fault);
		rc = set_param(wq_dfd, "block_on_fault",
			buf);
		if (rc != 0)
			return rc;
	}

	close(wq_dfd);
	return 0;
}

int cmd_config_device(int argc, const char **argv, void *ctx)
{
	char dev_path[PATH_MAX];
	char buf[MAX_BUF_LEN];
	struct dsactl_device *device;
	int i, device_dfd, rc = 0;

	const struct option options[] = {
		OPT_UINTEGER('l', "token-limit", &dev_param.token_limit,
			     "specify token limit by device"),
		OPT_END(),
	};

	const char *const u[] = {
		"dsactl config-device <device name> [<options>]",
		NULL
	};

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0)
		error("specify a device name to configure attributes\n");
	else {
		for (i = 0; i < argc; i++) {
			if (strcmp(argv[i], "all") == 0) {
				argv[0] = "all";
				argc = 1;
				break;
			}
		}
	}

	for (i = 0; i < argc; i++) {
		if (strstr(argv[i], "dsa") != NULL) {
			/* walkthrough device */
			dsactl_device_foreach(ctx, device) {
				if (!util_device_filter(device, argv[i]))
					continue;

				sprintf(dev_path, "%s%s", ctl_base, argv[i]);
				device_dfd = open(dev_path, O_PATH);
				if (device_dfd < 0) {
					fprintf(stderr,
						"cmd_config_device: could not open '%s': %s\n",
						dev_path, strerror(errno));
					close(device_dfd);
					return -errno;
				}
				if (!dev_param.token_limit) {
					fprintf(stderr,
						"token_limit needs to be larger than 0\n");
					return -EINVAL;
				}
				sprintf(buf, "%u", dev_param.token_limit);
				rc = set_param(device_dfd, "token_limit", buf);
				if (rc != 0)
					return rc;
			}
		}
	}

	return 0;
}

int cmd_config_group(int argc, const char **argv, void *ctx)
{
	int i, rc = 0;
	unsigned int dev_id, group_id;

	const struct option options[] = {
		OPT_UINTEGER('r', "tokens-reserved",
			     &group_param.tokens_reserved,
			     "specify tokens reserved by group"),
		OPT_UINTEGER('t', "tokens-allowed", &group_param.tokens_allowed,
			     "specify tokens allowed by group"),
		OPT_UINTEGER('l', "use-token-limit",
			     &group_param.use_token_limit,
			     "specify token limit by group"),
		OPT_INTEGER('a', "traffic-class-a",
			    &group_param.traffic_class_a,
			    "specify traffic-class-a by group"),
		OPT_INTEGER('b', "traffic-class-b",
			    &group_param.traffic_class_b,
			    "specify traffic-class-b by group"),
		OPT_END(),
	};

	const char *const u[] = {
		"dsactl config-group <group name> [<options>]",
		NULL
	};

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0)
		error("specify a group name to configure attributes\n");
	else {
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
		struct dsactl_group *group;
		char dev_name[MAX_BUF_LEN];

		if (strstr(argv[i], "group") == NULL) {
			fprintf(stderr, "need to provide group name\n");
			return -EINVAL;
		}

		/* walk through group */
		if (sscanf(argv[i], "group%u.%u", &dev_id, &group_id)
		    != 2) {
			fprintf(stderr,
				"'%s' is not a valid group name\n", argv[i]);
			return -EINVAL;
		}

		sprintf(dev_name, "%s%u", "dsa", dev_id);
		dsactl_device_foreach(ctx, device) {
			if (!util_device_filter(device, dev_name))
				continue;

			dsactl_group_foreach(device, group) {
				/* FIXME add util_group_filter(group, argv[i]
				 * here will cause continue to the end */
				//if (!util_group_filter(group, argv[i]))
				//      continue;

				rc = parse_group_attribs(argv[i]);
				if (rc < 0)
					return rc;
			}
		}
	}

	return 0;
}

int cmd_config_wq(int argc, const char **argv, void *ctx)
{
	int i, rc = 0;
	unsigned int dev_id, wq_id;

	const struct option options[] = {
		OPT_UINTEGER('g', "group-id", &wq_param.group_id,
			     "specify group-id used by wq"),
		OPT_UINTEGER('s', "wq-size", &wq_param.wq_size,
			     "specify wq-size used by wq"),
		OPT_INTEGER('p', "priority", &wq_param.priority,
			    "specify priority used by wq"),
		OPT_INTEGER('e', "enforce-order", &wq_param.enforce_order,
			    "specify enforce-order by wq"),
		OPT_INTEGER('b', "block-on-fault", &wq_param.block_on_fault,
			    "specify block-on-fault by wq"),
		OPT_STRING('m', "mode", &wq_param.mode, "mode",
			   "specify mode by wq"),
		OPT_END(),
	};

	const char *const u[] = {
		"dsactl config-wq <wq name> [<options>]",
		NULL
	};

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0)
		error("specify a wq name to configure attributes\n");
	else {
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
		unsigned int max_groups, max_wq_size;

		/* walk through wq */
		if (strstr(argv[i], "wq") != NULL) {
			if (sscanf(argv[i], "wq%u.%u", &dev_id, &wq_id) != 2) {
				fprintf(stderr, "'%s' is not a valid wq name\n",
					argv[i]);
				return -EINVAL;
			}
		}

		sprintf(dev_name, "%s%u", "dsa", dev_id);
		dsactl_device_foreach(ctx, device) {
			if (!util_device_filter(device, dev_name))
				continue;

			max_groups = dsactl_device_get_max_groups(device);
			max_wq_size = dsactl_device_get_max_work_queues_size(device);

			dsactl_wq_foreach(device, wq) {
				if (!util_wq_filter(wq, argv[i]))
					continue;

				rc = parse_wq_attribs(argv[i], max_groups, max_wq_size);
				if (rc < 0)
					return rc;
			}
		}
	}

	return 0;
}

int cmd_config_engine(int argc, const char **argv, void *ctx)
{
	int i, engine_dfd, rc = 0;
	unsigned int dev_id, engine_id;

	const struct option options[] = {
		OPT_UINTEGER('g', "group-id", &engine_param.group_id,
			     "specify group-id used by engine"),
		OPT_END(),
	};

	const char *const u[] = {
		"dsactl config-engine <engine name> [<options>]",
		NULL
	};

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0)
		error("specify an engine name to configure attributes\n");
	else {
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
		struct dsactl_engine *engine;
		char engine_path[PATH_MAX];
		char buf[MAX_BUF_LEN];
		char dev_name[MAX_BUF_LEN];
		unsigned int max_groups;

		if (strstr(argv[i], "engine") != NULL) {
			if (sscanf(argv[i], "engine%u.%u", &dev_id,
			     &engine_id) != 2) {
				fprintf(stderr, "'%s' is not a valid engine name\n",
					argv[i]);
				return -EINVAL;
			}
		}

		/* walk through engine */
		sprintf(dev_name, "%s%u", "dsa", dev_id);
		dsactl_device_foreach(ctx, device) {
			if (!util_device_filter(device, dev_name))
				continue;
			max_groups = dsactl_device_get_max_groups(device);

			dsactl_engine_foreach(device, engine) {
				if (!util_engine_filter(engine, argv[i]))
					continue;

				sprintf(engine_path, "%s%s", ctl_base, argv[i]);
				engine_dfd = open(engine_path, O_PATH);

				if (engine_dfd < 0) {
					fprintf(stderr,
						"cmd_config_engine: could not open '%s': %s\n", engine_path, strerror(errno));
					close(engine_dfd);
					return -errno;
				}

				if (engine_param.group_id < max_groups) {
					sprintf(buf, "%u", engine_param.group_id);
					rc = set_param(engine_dfd, "group_id",
						       buf);
					if (rc != 0)
						return rc;
				}

				else {
					fprintf(stderr, "configured value for engine is not within range\n");
					fprintf(stderr, "valid group_id should be 0 to %d\n",max_groups);
					return -EINVAL;
				}
			}
		}
	}

	return 0;
}
