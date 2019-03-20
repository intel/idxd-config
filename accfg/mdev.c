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

static struct wq_parameters wq_param;

int cmd_create_mdev(int argc, const char **argv, void *ctx)
{
	int i = 0;
	unsigned int dev_id = 0, wq_id = 0;
	const char *const u[] = {
		"accfg create-mdev <wq name>",
		NULL
	};
	uuid_t uuid;
	char uuid_str[UUID_STR_LEN];

	argc = parse_options(argc, argv, NULL, u, 0);

	if (argc == 0)
		fprintf(stderr, "specify a wq name to create mdev\n");

	for (i = 0; i < argc; i++) {
		struct accfg_device *device;
		struct accfg_wq *wq;
		char dev_name[MAX_DEV_LEN], wq_name[MAX_DEV_LEN];
		enum accfg_wq_state wq_state;
		int rc = 0;

		/* walk through wq */
		if (strstr(argv[i], "wq") != NULL) {
			if (sscanf(argv[i], "%[^/]/wq%u.%u",
					dev_name, &dev_id, &wq_id) != 3) {
				fprintf(stderr, "'%s' is not a valid wq name\n",
						argv[i]);
				return -EINVAL;
			}
		}

		if (!accfg_device_type_validate(dev_name))
			return -EINVAL;

		rc = sprintf(wq_name, "wq%u.%u", dev_id, wq_id);
		if (rc < 0)
			return rc;

		accfg_device_foreach(ctx, device) {
			if (!util_device_filter(device, dev_name))
				continue;

			accfg_wq_foreach(device, wq) {
				if (!util_wq_filter(wq, wq_name))
					continue;

				wq_state = accfg_wq_get_state(wq);
				if (wq_state == ACCFG_WQ_DISABLED
					|| wq_state == ACCFG_WQ_QUIESCING) {
					fprintf(stderr,
						"wq in wrong mode: %d\n",
						wq_state);
					return -ENXIO;
				}

				rc = accfg_wq_create_mdev(wq, uuid);
				if (rc != 0)
					return rc;
				uuid_unparse(uuid, uuid_str);
				printf("%s attached to %s\n",
						uuid_str,
						accfg_wq_get_devname(wq));
			}
		}
	}

	return 0;
}

int cmd_remove_mdev(int argc, const char **argv, void *ctx)
{
	int i = 0;
	unsigned int dev_id = 0, wq_id = 0;

	const struct option options[] = {
		OPT_STRING('u', "uuid", &wq_param.uuid_str, "uuid",
			   "specify uuid to be removed"),
		OPT_END(),
	};

	const char *const u[] = {
		"accfg remove-mdev <device name>/<wq name> [<uuid>] to remove single uuid",
		"accfg remove-mdev <device name>/<wq name> to removel all uuid for this wq",
		NULL
	};

	argc = parse_options(argc, argv, options, u, 0);

	if (argc == 0)
		fprintf(stderr, "specify a wq name to clear uuid\n");
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
		struct accfg_device *device;
		struct accfg_wq *wq;
		char dev_name[MAX_DEV_LEN], wq_name[MAX_DEV_LEN];
		uuid_t uuid, uuid_zero;
		enum accfg_wq_state wq_state;
		int rc = 0;

		/* walk through wq */
		if (strstr(argv[i], "wq") != NULL) {
			if (sscanf(argv[i], "%[^/]/wq%u.%u",
					dev_name, &dev_id, &wq_id) != 3) {
				fprintf(stderr,
					"'%s' is not a valid wq name\n",
					argv[i]);
				return -EINVAL;
			}
		}

		if (!accfg_device_type_validate(dev_name))
			return -EINVAL;

		rc = sprintf(wq_name, "wq%u.%u", dev_id, wq_id);
                if (rc < 0)
                        return rc;

		accfg_device_foreach(ctx, device) {
			if (!util_device_filter(device, dev_name))
				continue;

			accfg_wq_foreach(device, wq) {
				if (!util_wq_filter(wq, wq_name))
					continue;

				wq_state = accfg_wq_get_state(wq);
				if (wq_state == ACCFG_WQ_DISABLED
					|| wq_state == ACCFG_WQ_QUIESCING) {
					fprintf(stderr,
						"wq in wrong mode: %d\n",
						wq_state);
					return -ENXIO;
				}

				if (wq_param.uuid_str) {
					uuid_parse(wq_param.uuid_str,
							uuid);
					rc = accfg_wq_remove_mdev(wq,
							uuid);
					if (rc != 0)
						return rc;
				} else {
					/* generate null uuid */
					uuid_generate(uuid_zero);
					uuid_clear(uuid_zero);
					rc = accfg_wq_remove_mdev(wq,
							uuid_zero);
					if (rc != 0)
						return rc;
				}
			}
		}
	}

	return 0;
}
