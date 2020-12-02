/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <util/json.h>
#include <util/filter.h>
#include <syslog.h>
#include <libkmod.h>
#include <sys/wait.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/version.h>
#include <sys/mman.h>
#include <x86intrin.h>
#include <ccan/array_size/array_size.h>
#include <accfg/libaccel_config.h>
#include <test.h>
#include <linux/idxd.h>
#include <util/log.h>
#include "accfg_test.h"

#define PORTAL_SIZE	4096
#define BUF_SIZE	4096

struct accfg_wq_ctx {
	int major;
	int minor;
	void *portal;
	enum accfg_wq_mode mode;
	int fd;
};

static struct dev_parameters device0_param = {
	.token_limit = 10,
};

static struct dev_parameters device1_param = {
	.token_limit = 20,
};

static struct group_parameters group00_param = {
	.tokens_reserved = 1,
	.tokens_allowed = 8,
	.use_token_limit = 1,
	.traffic_class_a = 2,
	.traffic_class_b = 3
};

static struct group_parameters group01_param = {
	.tokens_reserved = 1,
	.tokens_allowed = 8,
	.use_token_limit = 0,
	.traffic_class_a = 4,
	.traffic_class_b = 5
};

static struct group_parameters group13_param = {
	.tokens_reserved = 1,
	.tokens_allowed = 8,
	.use_token_limit = 0,
	.traffic_class_a = 7,
	.traffic_class_b = 7
};

static struct wq_parameters wq00_param = {
	.group_id = 0,
	.wq_size = 16,
	.priority = 10,
	.block_on_fault = 1,
	.threshold = 15,
	.max_batch_size = 1,
	.max_transfer_size = 1,
	.mode = "shared",
	.type = "user",
	.name = "myapp1"
};

static struct wq_parameters wq01_param = {
	.group_id = 1,
	.wq_size = 8,
	.priority = 10,
	.block_on_fault = 0,
	.max_batch_size = (1 << 4),
	.max_transfer_size = (1l << 16),
	.mode = "dedicated",
	.type = "user",
	.name = "myapp2"

};

static struct wq_parameters wq02_param = {
	.group_id = 0,
	.wq_size = 16,
	.priority = 10,
	.block_on_fault = 1,
	.threshold = 8,
	.max_batch_size = (1 << 8),
	.max_transfer_size = (1l << 30),
	.mode = "shared",
	.type = "user",
	.name = "guest1"
};

static struct wq_parameters wq03_param = {
	.group_id = 1,
	.wq_size = 7,
	.priority = 10,
	.block_on_fault = 0,
	.max_batch_size = (1 << 9),
	.max_transfer_size = (1l << 31),
	.mode = "dedicated",
	.type = "user",
	.name = "guest2"

};

/* Following three wqs are set the size to the max_work_queues_size
 * and set into a same group, to trigger max_total_size(128) of a device */
static struct wq_parameters wq12_param = {
	.group_id = 3,
	.wq_size = 64,
	.priority = 15,
	.block_on_fault = 1,
	.threshold = 50,
	.max_batch_size = 1,
	.max_transfer_size = 1,
	.mode = "shared",
	.type = "user",
	.name = "myapp3"
};

static struct wq_parameters wq13_param = {
	.group_id = 3,
	.wq_size = 64,
	.priority = 15,
	.block_on_fault = 1,
	.threshold = 50,
	.max_batch_size = 1,
	.max_transfer_size = 1,
	.mode = "shared",
	.type = "user",
	.name = "myapp3"
};

static struct wq_parameters wq14_param = {
	.group_id = 3,
	.wq_size = 64,
	.priority = 15,
	.block_on_fault = 1,
	.threshold = 50,
	.max_batch_size = 1,
	.max_transfer_size = 1,
	.mode = "shared",
	.type = "user",
	.name = "myapp3"
};

static struct engine_parameters engine00_param = {
	.group_id = 0,
};

static struct engine_parameters engine01_param = {
	.group_id = 0,
};

static struct engine_parameters engine02_param = {
	.group_id = 1,
};

static struct engine_parameters engine03_param = {
	.group_id = 1,
};

static int config_device(struct accfg_ctx *ctx, int device_id,
			struct dev_parameters dev_param, const char *dev_name)
{
	struct accfg_device *device;

	accfg_device_foreach(ctx, device) {
		enum accfg_device_state dstate;

		if (strcmp(accfg_device_get_devname(device), dev_name))
			continue;

		/* check if device is disabled before configuration */
		dstate = accfg_device_get_state(device);
		if (dstate == ACCFG_DEVICE_ENABLED) {
			fprintf(stderr, "device %s is in enabled mode and can not be configured\n", dev_name);
			continue;
		}

		if (accfg_device_set_token_limit(device,
			device0_param.token_limit) != 0)
			return -EINVAL;
	}

	return 0;
}

static int check_device(struct accfg_ctx *ctx, int device_id,
			struct dev_parameters dev_param, const char *dev_name)
{
	struct accfg_device *device;

	accfg_device_foreach(ctx, device) {
		if (strcmp(accfg_device_get_devname(device), dev_name))
			continue;
		if (dev_param.token_limit != accfg_device_get_token_limit(device)) {
			fprintf(stderr, "check_device failed on token_limit\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int config_group(struct accfg_ctx *ctx, int dev_id, int group_id,
			struct group_parameters group_param, const char *dev_name)
{
	struct accfg_device *device;
	struct accfg_group *group;

	accfg_device_foreach(ctx, device) {
		enum accfg_device_state dstate;

		if (strcmp(accfg_device_get_devname(device), dev_name))
			continue;

		/* check if device is disabled before configuration */
		dstate = accfg_device_get_state(device);
		if (dstate == ACCFG_DEVICE_ENABLED) {
			fprintf(stderr, "device %s is in enabled mode and can not configure its group\n", dev_name);
			continue;
		}


		accfg_group_foreach(device, group) {
			if (accfg_group_get_id(group) != group_id)
				continue;

			accfg_group_set_tokens_reserved(group,
					group_param.tokens_reserved);
			accfg_group_set_tokens_allowed(group,
					group_param.tokens_allowed);
			accfg_group_set_use_token_limit(group,
					group_param.use_token_limit);
			accfg_group_set_traffic_class_a(group,
					group_param.traffic_class_a);
			accfg_group_set_traffic_class_b(group,
					group_param.traffic_class_b);
		}
	}

	return 0;
}

static int check_group(struct accfg_ctx *ctx, int dev_id, int group_id,
		struct group_parameters group_param, const char *dev_name)
{
	struct accfg_device *device;
	struct accfg_group *group;

	accfg_device_foreach(ctx, device) {
		if (strcmp(accfg_device_get_devname(device), dev_name))
			continue;

		accfg_group_foreach(device, group) {
			if (accfg_group_get_id(group) != group_id)
				continue;

			if (group_param.tokens_reserved !=
				(unsigned int)accfg_group_get_tokens_reserved(group)) {
				fprintf(stderr, "check_group failed on tokens_reserved\n");
				return -EINVAL;
			}

			if (group_param.tokens_allowed !=
				(unsigned int)accfg_group_get_tokens_allowed(group)) {
				fprintf(stderr, "check_group failed on tokens_allowed\n");
				return -EINVAL;
			}

			if (group_param.use_token_limit !=
				(unsigned int)accfg_group_get_use_token_limit(group)) {
				fprintf(stderr, "check_group failed on use_token_limit\n");
				return -EINVAL;
			}

			if (group_param.traffic_class_a !=
					accfg_group_get_traffic_class_a(group)) {
				fprintf(stderr, "check_group failed on traffic_class_a\n");
				return -EINVAL;
			}

			if (group_param.traffic_class_b !=
					accfg_group_get_traffic_class_b(group)) {
				fprintf(stderr, "check_group failed on traffic_class_b\n");
				return -EINVAL;
			}
		}
	}

	return 0;

}

static int config_wq(struct accfg_ctx *ctx, int dev_id, int wq_id,
			struct wq_parameters wq_param, const char *dev_name)
{
	struct accfg_device *device;
	struct accfg_wq *wq;

	accfg_device_foreach(ctx, device) {
		if (strcmp(accfg_device_get_devname(device), dev_name))
			continue;

		accfg_wq_foreach(device, wq) {
			enum accfg_wq_state wstate;

			if (accfg_wq_get_id(wq) != wq_id)
				continue;

			/* check if wq is disabled before configuration */
			wstate = accfg_wq_get_state(wq);
			if (wstate == ACCFG_WQ_ENABLED || wstate == ACCFG_WQ_LOCKED) {
				fprintf(stderr,
					"wq%d in %s is in enabled or locked mode and cannot be configured\n",
					wq_id, dev_name);
				continue;
			}

			accfg_wq_set_str_mode(wq, wq_param.mode);
			accfg_wq_set_str_type(wq, wq_param.type);
			accfg_wq_set_str_name(wq, wq_param.name);
			accfg_wq_set_size(wq, wq_param.wq_size);
			accfg_wq_set_group_id(wq, wq_param.group_id);
			accfg_wq_set_priority(wq, wq_param.priority);
			accfg_wq_set_block_on_fault(wq, wq_param.block_on_fault);
			accfg_wq_set_max_batch_size(wq, wq_param.max_batch_size);
			accfg_wq_set_max_transfer_size(wq, wq_param.max_transfer_size);
			if (wq_param.threshold)
				accfg_wq_set_threshold(wq, wq_param.threshold);
		}
	}

	return 0;
}


static int check_wq(struct accfg_ctx *ctx, int dev_id, int wq_id,
		struct wq_parameters wq_param, const char *dev_name)
{
	struct accfg_device *device;
	struct accfg_wq *wq;

	accfg_device_foreach(ctx, device) {
		if (strcmp(accfg_device_get_devname(device), dev_name))
			continue;

		accfg_wq_foreach(device, wq) {
			if (accfg_wq_get_id(wq) != wq_id)
				continue;

			if (wq_param.wq_size != accfg_wq_get_size(wq)) {
				fprintf(stderr, "check_wq failed on wq_size\n");
				return -EINVAL;
			}
			if (wq_param.group_id !=
					accfg_wq_get_group_id(wq)) {
				fprintf(stderr, "check_wq failed on group_id\n");
				return -EINVAL;
			}
			if (wq_param.priority !=
					(unsigned int)accfg_wq_get_priority(wq)) {
				fprintf(stderr, "check_wq failed on priority\n");
				return -EINVAL;
			}
			if (wq_param.block_on_fault !=
					accfg_wq_get_block_on_fault(wq)) {
				fprintf(stderr, "check_wq failed on block_on_fault\n");
				return -EINVAL;
			}
			if (wq_param.threshold !=
					(unsigned int)accfg_wq_get_threshold(wq)) {
				fprintf(stderr, "check_wq failed on threshold\n");
				return -EINVAL;
			}
			if (wq_param.max_batch_size !=
					accfg_wq_get_max_batch_size(wq)) {
				fprintf(stderr, "%s failed on max_batch_size\n", __func__);
				return -EINVAL;
			}
			if (wq_param.max_transfer_size !=
					accfg_wq_get_max_transfer_size(wq)) {
				fprintf(stderr, "%s failed on max_transfer_size\n", __func__);
				return -EINVAL;
			}
			if (strcmp(wq_param.name, accfg_wq_get_type_name(wq)) != 0) {
				fprintf(stderr, "check wq failed on wq name\n");
				return -EINVAL;
			}
		}
	}

	return 0;
}

static int config_engine(struct accfg_ctx *accfg_ctx, int dev_id, int engine_id,
				struct engine_parameters engine_param,
				const char *dev_name)
{
	struct accfg_device *device;
	struct accfg_engine *engine;

	accfg_device_foreach(accfg_ctx, device) {
		enum accfg_device_state dstate;

		if (strcmp(accfg_device_get_devname(device), dev_name))
			continue;

		/* check if device is disabled before configuration */
		dstate = accfg_device_get_state(device);
		if (dstate == ACCFG_DEVICE_ENABLED) {
			fprintf(stderr, "device %s is in enabled mode and can not configure its engine\n", dev_name);
			continue;
		}

		accfg_engine_foreach(device, engine) {
			if (accfg_engine_get_id(engine) != engine_id)
			 continue;

			accfg_engine_set_group_id(engine,
				engine_param.group_id);
		}
	}

	return 0;
}

static int check_engine(struct accfg_ctx *ctx, int dev_id, int engine_id,
		struct engine_parameters engine_param, const char *dev_name)
{
	struct accfg_device *device;
	struct accfg_engine *engine;

	accfg_device_foreach(ctx, device) {
		if (strcmp(accfg_device_get_devname(device), dev_name))
			continue;

		accfg_engine_foreach(device, engine) {
			if (accfg_engine_get_id(engine) != engine_id)
				continue;

			if (engine_param.group_id !=
				accfg_engine_get_group_id(engine)) {
				fprintf(stderr, "check_engine failed on group_id\n");
				return -EINVAL;
			}

		}
	}

	return 0;
}

static int device_test_reset(struct accfg_ctx *ctx, const char *dev_name)
{
	int rc = 0;
	struct accfg_device *device;
	struct accfg_wq *wq;
	enum accfg_wq_state wq_state;

	device = accfg_ctx_device_get_by_name(ctx, dev_name);
	if (!device)
		return -EINVAL;

	/* make sure device is disabled before configuration */
	if (accfg_device_is_active(device)) {
		/* make sure each wq is disabled */
		accfg_wq_foreach(device, wq) {
			wq_state = accfg_wq_get_state(wq);

			if (wq_state == ACCFG_WQ_DISABLED ||
					wq_state == ACCFG_WQ_QUIESCING) {
				continue;
			}

			rc = accfg_wq_disable(wq, true);
			if (rc < 0) {
				fprintf(stderr, "wq under %s disable failed\n", dev_name);
				return rc;
			}
		}
		rc = accfg_device_disable(device, true);
		if (rc < 0) {
			fprintf(stderr, "%s should be disabled before config but failed\n", dev_name);
			return rc;
		}
	}

	return 0;

}

static int set_config(struct accfg_ctx *ctx, const char *dev_name)
{
	int rc = 0;

	printf("configure device 0\n");
	rc = config_device(ctx, 0, device0_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config device %s failed\n", dev_name);
		return rc;
	}

	printf("configure group0.0\n");
	rc = config_group(ctx, 0, 0, group00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config group group0.0 failed\n");
		return rc;
	}

	printf("configure wq0.0\n");
	rc = config_wq(ctx, 0, 0, wq00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq0.0 failed\n");
		return rc;
	}

	printf("configure engine0.0\n");
	rc = config_engine(ctx, 0, 0, engine00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config engine engine0.0 failed\n");
		return rc;
	}

	printf("configure engine0.1\n");
	rc = config_engine(ctx, 0, 1, engine01_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config engine engine0.1 failed\n");
		return rc;
	}

	printf("configure group0.1\n");
	rc = config_group(ctx, 0, 1, group01_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config group group0.1 failed\n");
		return rc;
	}

	printf("configure wq0.1\n");
	rc = config_wq(ctx, 0, 1, wq01_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq0.1 failed\n");
		return rc;
	}

	printf("configure wq0.2\n");
	rc = config_wq(ctx, 0, 2, wq02_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq0.2 failed\n");
		return rc;
	}

	printf("configure wq0.3\n");
	rc = config_wq(ctx, 0, 3, wq03_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq0.3 failed\n");
		return rc;
	}

	printf("configure engine0.2\n");
	rc = config_engine(ctx, 0, 2, engine02_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config engine engine0.2 failed\n");
		return rc;
	}

	printf("configure engine0.3\n");
	rc = config_engine(ctx, 0, 3, engine03_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config engine engine0.3 failed\n");
		return rc;
	}

	return 0;
}

static int check_config(struct accfg_ctx *ctx, const char *dev_name)
{
	int rc = 0;

	printf("check device0\n");
	rc = check_device(ctx, 0, device0_param, "dsa0");
	if (rc != 0) {
		fprintf(stderr, "check device dsa0 failed\n");
		return rc;
	}

	printf("check group0.0\n");
	rc = check_group(ctx, 0, 0, group00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check group group0.0 failed\n");
		return rc;
	}

	printf("check group0.1\n");
	rc = check_group(ctx, 0, 1, group01_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check group group0.1 failed\n");
		return rc;
	}

	printf("check wq0.0\n");
	rc = check_wq(ctx, 0, 0, wq00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check wq wq0.0 failed\n");
		return rc;
	}

	printf("check wq0.1\n");
	rc = check_wq(ctx, 0, 1, wq01_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check wq wq0.1 failed\n");
		return rc;
	}

	printf("check wq0.2\n");
	rc = check_wq(ctx, 0, 2, wq02_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check wq wq0.2 failed\n");
		return rc;
	}

	printf("check wq0.3\n");
	rc = check_wq(ctx, 0, 3, wq03_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check wq wq0.3 failed\n");
		return rc;
	}

	printf("check engine0.0\n");
	rc = check_engine(ctx, 0, 0, engine00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check engine engine0.0 failed\n");
		return rc;
	}

	printf("check engine0.1\n");
	rc = check_engine(ctx, 0, 1, engine01_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check engine engine0.1 failed\n");
		return rc;
	}

	printf("check engine0.2\n");
	rc = check_engine(ctx, 0, 2, engine02_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check engine engine0.2 failed\n");
		return rc;
	}

	printf("check engine0.3\n");
	rc = check_engine(ctx, 0, 3, engine03_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "check engine engine0.3 failed\n");
		return rc;
	}
	return 0;
}

static int set_exceed_config(struct accfg_ctx *ctx, const char *dev_name)
{
	int rc = 0;

	printf("configure device 1\n");
	rc = config_device(ctx, 1, device1_param, "dsa1");
	if (rc != 0) {
		fprintf(stderr, "config device dsa1 failed\n");
		return rc;
	}

	printf("configure group1.3\n");
	rc = config_group(ctx, 1, 3, group13_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config group group1.3 failed\n");
		return rc;
	}
	printf("configure wq1.2\n");
	rc = config_wq(ctx, 1, 2, wq12_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq1.2 failed\n");
		return rc;
	}

	printf("configure wq1.3\n");
	rc = config_wq(ctx, 1, 3, wq13_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq1.3 failed\n");
		return rc;
	}

	printf("configure wq1.4\n");
	rc = config_wq(ctx, 1, 4, wq14_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq1.4 failed\n");
		return rc;
	}

	return 0;
}

static int wq_bounds_test(struct accfg_ctx *ctx, const char *dev_name)
{
	struct accfg_device *device;
	int rc = 0;

	printf("configure device 0, group 0.0, wq0.0 for bounds test\n");
	rc = config_device(ctx, 0, device0_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config device %s failed\n", dev_name);
		return rc;
	}

	device = accfg_ctx_device_get_by_name(ctx, dev_name);
	if (!device)
		return -EINVAL;

	rc = config_group(ctx, 0, 0, group00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config group group0.0 failed\n");
		return rc;
	}

	/* should not be 0  */
	wq00_param.max_batch_size = 0;
	wq00_param.max_transfer_size = 0;
	rc = config_wq(ctx, 0, 0, wq00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq0.0 failed\n");
		return rc;
	}
	/* should not be greater device max_batch_size/max_transfer_size */
	wq00_param.max_batch_size =
		(accfg_device_get_max_batch_size(device) << 1);
	wq00_param.max_transfer_size =
		(accfg_device_get_max_transfer_size(device) << 1);
	rc = config_wq(ctx, 0, 0, wq00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq0.0 failed\n");
		return rc;
	}

	/* reset to valid values for following tests */
	wq00_param.max_batch_size = 1;
	wq00_param.max_transfer_size = 1;
	rc = config_wq(ctx, 0, 0, wq00_param, dev_name);
	if (rc != 0) {
		fprintf(stderr, "config wq wq0.0 failed\n");
		return rc;
	}

	return 0;
}

/* test the set and get libaccfg functions for all components in dsa0 */
static int test_config(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, "dsa0");
	if (rc != 0)
		return rc;

	/* set configuration of each attribute */
	rc = set_config(ctx, "dsa0");
	if (rc != 0)
		return rc;

	/* get configuration to see if match */
	rc = check_config(ctx, "dsa0");
	if (rc != 0)
		return rc;

	rc = device_test_reset(ctx, "dsa0");
	if (rc != 0)
		return rc;

	return 0;
}

/* set large wq to exceed max total size in dsa */
static int test_max_wq_size(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, "dsa1");
	if (rc != 0)
		return rc;

	rc = set_exceed_config(ctx, "dsa1");
	if (rc != 0)
		return rc;

	rc = device_test_reset(ctx, "dsa1");
	if (rc != 0)
		return rc;

	return 0;
}

/* test the boundary conditions for wq max_batch_size and max_transfer_size */
static int test_wq_boundary_conditions(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, "dsa0");
	if (rc != 0)
		return rc;

	rc = wq_bounds_test(ctx, "dsa0");
	if (rc != 0)
		return rc;

	rc = device_test_reset(ctx, "dsa0");
	if (rc != 0)
		return rc;

	return 0;
}

static int mdev_test(struct accfg_ctx *ctx, const char *dev_name,
		char *mdev_type_str, int num_mdevs)
{
	struct accfg_device *device;
	enum accfg_mdev_type type;
	int rc, i;
	char **m;
	uuid_t uuid;

	device = accfg_ctx_device_get_by_name(ctx, dev_name);
	if (!device) {
		fprintf(stderr, "Device %s not found\n", dev_name);
		return -EINVAL;
	}

	for (m = accfg_mdev_basenames, type = 0; *m; m++, type++)
		if (!strcmp(*m, mdev_type_str))
			break;

	if (!*m) {
		fprintf(stderr, "Invalid mdev type\n");
		return -EINVAL;
	}

	for (i = 0; i < num_mdevs; i++) {
		rc = accfg_create_mdev(device, type, uuid);
		if (rc) {
			fprintf(stderr, "mdev creation failed\n");
			return rc;
		}
	}

	/* Remove all mdevs */
	uuid_clear(uuid);
	rc = accfg_remove_mdev(device, uuid);
	if (rc) {
		fprintf(stderr, "mdev removal failed\n");
		return rc;
	}

	return rc;
}

static int enable_wq(struct accfg_ctx *ctx, const char *dev_name, int wq_id)
{
	struct accfg_device *device;
	struct accfg_wq *wq;
	enum accfg_wq_state wq_state;
	int rc;

	device = accfg_ctx_device_get_by_name(ctx, dev_name);
	if (!device) {
		fprintf(stderr, "Device %s not found\n", dev_name);
		return -EINVAL;
	}
	if (!accfg_device_is_active(device)) {
		rc = accfg_device_enable(device);
		if (rc < 0) {
			fprintf(stderr, "device enable of %s failed\n",
					dev_name);
			return rc;
		}
	}

	wq = accfg_device_wq_get_by_id(device, wq_id);
	if (!wq) {
		fprintf(stderr, "wq with id %d not found for device %s\n",
				wq_id, dev_name);
		return -EINVAL;
	}

	wq_state = accfg_wq_get_state(wq);
	if (wq_state == ACCFG_WQ_ENABLED || wq_state == ACCFG_WQ_LOCKED)
		return 0;

	return accfg_wq_enable(wq);
}

/* test 1swq type mdev creation and removal */
static int test_mdev_1swq(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, "dsa0");
	if (rc)
		return rc;

	rc = set_config(ctx, "dsa0");
	if (rc != 0)
		return rc;

	rc = enable_wq(ctx, "dsa0", 2);
	if (rc) {
		fprintf(stderr, "enable wq wq0.2 failed");
		return rc;
	}

	/* create and remove 5 1swq mdevs */
	rc = mdev_test(ctx, "dsa0", "1swq", 5);
	if (rc)
		return rc;

	rc = device_test_reset(ctx, "dsa0");
	if (rc)
		return rc;

	return 0;
}

/* test 1dwq type mdev creation and removal */
static int test_mdev_1dwq(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, "dsa0");
	if (rc)
		return rc;

	rc = set_config(ctx, "dsa0");
	if (rc != 0)
		return rc;

	rc = enable_wq(ctx, "dsa0", 3);
	if (rc) {
		fprintf(stderr, "enable wq wq0.3 failed");
		return rc;
	}

	/* create and remove 1 1dwq mdev */
	rc = mdev_test(ctx, "dsa0", "1dwq", 1);
	if (rc)
		return rc;

	rc = device_test_reset(ctx, "dsa0");
	if (rc)
		return rc;

	return 0;
}

typedef int (*do_test_fn)(struct accfg_ctx *ctx);
struct _test_case {
	do_test_fn test_fn;
	char *desc;
	bool enabled;
};

static struct _test_case test_cases[] = {
	{
		.test_fn = test_config,
		.desc = "set and get configurations",
		.enabled = true,
	},
	{
		.test_fn = test_max_wq_size,
		.desc = "max wq size",
		.enabled = true,
	},
	{
		.test_fn = test_wq_boundary_conditions,
		.desc = "wq boundary conditions",
		.enabled = true,
	},
	{
		.test_fn = test_mdev_1swq,
		.desc = "1swq type mdev creation and removal",
		.enabled = true,
	},
	{
		.test_fn = test_mdev_1dwq,
		.desc = "1dwq type mdev creation and removal",
		.enabled = true,
	},
};

static int idxd_kmod_init(struct kmod_ctx **ctx, struct kmod_module **mod,
		int log_level)
{
	struct log_ctx log_ctx;
	int rc;

	log_init(&log_ctx, "test/init", "LIB-ACCELCONFIG_TEST");
	log_ctx.log_priority = log_level;

	*ctx = kmod_new(NULL, NULL);
	if (!*ctx)
		return -ENXIO;
	kmod_set_log_priority(*ctx, log_level);

	rc = kmod_module_new_from_name(*ctx, "idxd", mod);
	if (rc < 0) {
		kmod_unref(*ctx);
		return rc;
	}

	rc = kmod_module_get_initstate(*mod);
	return rc;
}

int test_libaccfg(int loglevel, struct accfg_test *test,
		struct accfg_ctx *ctx)
{
	unsigned int i;
	int err, result = EXIT_FAILURE;
	struct kmod_ctx *kmod_ctx;
	struct kmod_module *mod;
	struct accfg_device *device;

	if (!accfg_test_attempt(test, KERNEL_VERSION(5, 6, 0)))
		return EXIT_SKIP;

	accfg_set_log_priority(ctx, loglevel);
	err = idxd_kmod_init(&kmod_ctx, &mod, loglevel);
	if (err < 0) {
		accfg_test_skip(test);
		fprintf(stderr, "idxd kmod unavailable skipping tests\n");
		return EXIT_SKIP;
	}

	/*
	 * iterate to check the state of each device, skip entire test if any of
	 * them is active
	 */
	accfg_device_foreach(ctx, device) {
		if (accfg_device_is_active(device)) {
			accfg_test_skip(test);
			fprintf(stderr, "device is active, skipping tests\n");
			return EXIT_SKIP;
		}

		/*
		 * Skip tests if pasid not enabled as there's no good support for
		 * when pasid support isn't there.
		 */
		if (!accfg_device_get_pasid_enabled(device)) {
			accfg_test_skip(test);
			fprintf(stderr, "device has no pasid support, skipping tests\n");
			return EXIT_SKIP;
		}
	}

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		if (!test_cases[i].enabled) {
			fprintf(stderr, "\naccfg-test%d *disabled*\n", i);
			continue;
		}
		printf("\nRunning accfg-test%d: %s\n", i, test_cases[i].desc);
		err = test_cases[i].test_fn(ctx);
		if (err < 0) {
			fprintf(stderr, "accfg-test%d *failed*: %d\n", i, err);
			break;
		}
		printf("accfg-test%d passed!\n", i);
	}

	if (i >= ARRAY_SIZE(test_cases))
		result = EXIT_SUCCESS;

	kmod_module_remove_module(mod, 0);
	kmod_module_probe_insert_module(mod, 0, NULL, NULL, NULL, NULL);
	kmod_unref(kmod_ctx);

	return result;
}

int __attribute__((weak)) main(int argc, char *argv[])
{
	struct accfg_test *test = accfg_test_new(0);
	struct accfg_ctx *ctx;
	int rc;

	if (!test) {
		fprintf(stderr, "failed to initialize test\n");
		return EXIT_FAILURE;
	}

	rc = accfg_new(&ctx);
	if (rc)
		return accfg_test_result(test, rc);

	rc = test_libaccfg(LOG_DEBUG, test, ctx);

	accfg_unref(ctx);
	return accfg_test_result(test, rc);
}
