// SPDX-License-Identifier: GPL-2.0
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
#include <accfg/idxd.h>
#include <util/log.h>
#include "accfg_test.h"

static struct dev_parameters device0_param = {
	.read_buffer_limit = 10,
};

static struct group_parameters group00_param = {
	.read_buffers_reserved = 1,
	.read_buffers_allowed = 8,
	.use_read_buffer_limit = 1,
};

static struct group_parameters group01_param = {
	.read_buffers_reserved = 1,
	.read_buffers_allowed = 8,
	.use_read_buffer_limit = 0,
};

static struct group_parameters *group_params[] = {
	&group00_param,
	&group01_param
};

static struct wq_parameters wq00_param = {
	.group_id = 0,
	.wq_size = 16,
	.priority = 10,
	.block_on_fault = 1,
	.threshold = 15,
	.max_batch_size = 16,
	.max_transfer_size = 16,
	.ats_disable = 0,
	.mode = "shared",
	.type = "user",
	.driver_name = "user",
	.name = "myapp1"
};

static struct wq_parameters wq01_param = {
	.group_id = 1,
	.wq_size = 8,
	.priority = 10,
	.block_on_fault = 0,
	.max_batch_size = (1 << 4),
	.max_transfer_size = (1l << 16),
	.ats_disable = 0,
	.mode = "dedicated",
	.type = "user",
	.driver_name = "user",
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
	.ats_disable = 0,
	.mode = "shared",
	.type = "user",
	.driver_name = "user",
	.name = "guest1"
};

static struct wq_parameters wq03_param = {
	.group_id = 1,
	.wq_size = 7,
	.priority = 10,
	.block_on_fault = 0,
	.max_batch_size = (1 << 9),
	.max_transfer_size = (1l << 31),
	.ats_disable = 0,
	.mode = "dedicated",
	.type = "user",
	.driver_name = "user",
	.name = "guest2"
};

static struct wq_parameters *wq_params[4] = {
	&wq00_param,
	&wq01_param,
	&wq02_param,
	&wq03_param
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

static struct engine_parameters *engine_params[4] = {
	&engine00_param,
	&engine01_param,
	&engine02_param,
	&engine03_param
};

static struct config_test_ctx {
	struct accfg_device *device;
	struct accfg_group *group[2];
	struct accfg_engine *engine[4];
	struct accfg_wq *wq[4];
	struct dev_parameters *dev_param;
	struct group_parameters *group_param[2];
	struct engine_parameters *engine_param[4];
	struct wq_parameters *wq_param[4];
} test_ctx;

static int config_device(struct accfg_ctx *ctx, struct accfg_device *device,
		struct dev_parameters *dev_param)
{
	return accfg_device_set_read_buffer_limit(device,
				dev_param->read_buffer_limit);
}

static int check_device(struct accfg_ctx *ctx, struct accfg_device *device,
		struct dev_parameters *dev_param)
{

	if (dev_param->read_buffer_limit != accfg_device_get_read_buffer_limit(device)) {
		fprintf(stderr, "%s failed on read_buffer_limit\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int config_group(struct accfg_ctx *ctx, struct accfg_device *device,
		struct accfg_group *group,
		struct group_parameters *group_param)
{
	int rc = 0;

	rc = accfg_group_set_read_buffers_reserved(group,
				group_param->read_buffers_reserved);
	if (rc)
		return rc;
	rc = accfg_group_set_read_buffers_allowed(group,
				group_param->read_buffers_allowed);
	if (rc)
		return rc;
	rc = accfg_group_set_use_read_buffer_limit(group,
				group_param->use_read_buffer_limit);

	return rc;
}

static int check_group(struct accfg_ctx *ctx, struct accfg_device *device,
		struct accfg_group *group,
		struct group_parameters *group_param)
{

	if (group_param->read_buffers_reserved !=
			(unsigned int) accfg_group_get_read_buffers_reserved(group)) {
		fprintf(stderr, "%s failed on read_buffers_reserved\n", __func__);
		return -EINVAL;
	}

	if (group_param->read_buffers_allowed !=
			(unsigned int) accfg_group_get_read_buffers_allowed(group)) {
		fprintf(stderr, "%s failed on read_buffers_allowed\n", __func__);
		return -EINVAL;
	}

	if (group_param->use_read_buffer_limit !=
			(unsigned int) accfg_group_get_use_read_buffer_limit(group)) {
		fprintf(stderr, "%s failed on use_read_buffer_limit\n", __func__);
		return -EINVAL;
	}

	if (accfg_device_get_version(device) < ACCFG_DEVICE_VERSION_2)
		return 0;

	return 0;
}

static int config_wq(struct accfg_ctx *ctx, struct accfg_device *device,
		struct accfg_wq *wq, struct wq_parameters *wq_param)
{
	int rc = 0;

	rc = accfg_wq_set_str_mode(wq, wq_param->mode);
	if (rc)
		return rc;
	rc = accfg_wq_set_str_type(wq, wq_param->type);
	if (rc)
		return rc;
	rc = accfg_wq_set_str_driver_name(wq, wq_param->driver_name);
	if (rc)
		return rc;
	rc = accfg_wq_set_str_name(wq, wq_param->name);
	if (rc)
		return rc;
	rc = accfg_wq_set_size(wq, wq_param->wq_size);
	if (rc)
		return rc;
	rc = accfg_wq_set_group_id(wq, wq_param->group_id);
	if (rc)
		return rc;
	rc = accfg_wq_set_priority(wq, wq_param->priority);
	if (rc)
		return rc;
	rc = accfg_wq_set_block_on_fault(wq, wq_param->block_on_fault);
	if (rc)
		return rc;
	rc = accfg_wq_set_max_batch_size(wq, wq_param->max_batch_size);
	if (rc)
		return rc;
	rc = accfg_wq_set_max_transfer_size(wq,
				wq_param->max_transfer_size);
	if (rc)
		return rc;
	if (wq_param->threshold) {
		rc = accfg_wq_set_threshold(wq, wq_param->threshold);
		if (rc)
			return rc;
	}

	rc = accfg_wq_set_ats_disable(wq, wq_param->ats_disable);
	/* Don't fail test if per wq ats disable is not supported */
	if (rc == -ENOENT)
		rc = 0;

	return rc;
}

static int check_wq(struct accfg_ctx *ctx, struct accfg_device *device,
		struct accfg_wq *wq, struct wq_parameters *wq_param)
{
	int ats_disable;

	if (wq_param->wq_size != accfg_wq_get_size(wq)) {
		fprintf(stderr, "%s failed on wq_size\n", __func__);
		return -EINVAL;
	}
	if (wq_param->group_id !=
			accfg_wq_get_group_id(wq)) {
		fprintf(stderr, "%s failed on group_id\n", __func__);
		return -EINVAL;
	}
	if (wq_param->priority !=
			(unsigned int)accfg_wq_get_priority(wq)) {
		fprintf(stderr, "%s failed on priority\n", __func__);
		return -EINVAL;
	}
	if (wq_param->block_on_fault !=
			accfg_wq_get_block_on_fault(wq)) {
		fprintf(stderr, "%s failed on block_on_fault\n", __func__);
		return -EINVAL;
	}
	if (wq_param->threshold !=
			(unsigned int)accfg_wq_get_threshold(wq)) {
		fprintf(stderr, "%s failed on threshold\n", __func__);
		return -EINVAL;
	}
	if (wq_param->max_batch_size !=
			accfg_wq_get_max_batch_size(wq)) {
		fprintf(stderr, "%s failed on max_batch_size\n", __func__);
		return -EINVAL;
	}
	if (wq_param->max_transfer_size !=
			accfg_wq_get_max_transfer_size(wq)) {
		fprintf(stderr, "%s failed on max_transfer_size\n", __func__);
		return -EINVAL;
	}
	if (strcmp(wq_param->name, accfg_wq_get_type_name(wq)) != 0) {
		fprintf(stderr, "%s failed on wq name\n", __func__);
		return -EINVAL;
	}
	ats_disable = accfg_wq_get_ats_disable(wq);
	if (ats_disable >= 0 && wq_param->ats_disable != ats_disable) {
		fprintf(stderr, "%s failed on ats_disable\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int config_engine(struct accfg_ctx *accfg_ctx,
		struct accfg_device *device, struct accfg_engine *engine,
		struct engine_parameters *engine_param)
{
	return accfg_engine_set_group_id(engine, engine_param->group_id);
}

static int check_engine(struct accfg_ctx *ctx, struct accfg_device *device,
		struct accfg_engine *engine,
		struct engine_parameters *engine_param)
{

	if (engine_param->group_id != accfg_engine_get_group_id(engine)) {
		fprintf(stderr, "%s failed on group_id\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int device_test_reset(struct accfg_ctx *ctx,
		struct accfg_device *device, bool forced)
{
	int rc = 0;
	struct accfg_wq *wq;
	enum accfg_wq_state wq_state;

	if (accfg_device_is_active(device)) {

		/* make sure each wq is disabled */
		accfg_wq_foreach(device, wq) {
			wq_state = accfg_wq_get_state(wq);

			if (wq_state == ACCFG_WQ_DISABLED ||
					wq_state == ACCFG_WQ_QUIESCING) {
				continue;
			}

			rc = accfg_wq_disable(wq, true);
			if (rc < 0 && !forced) {
				fprintf(stderr, "error disabling wq %s\n",
						accfg_wq_get_devname(wq));
				return rc;
			}
		}
		rc = accfg_device_disable(device, true);
		if (rc < 0) {
			fprintf(stderr, "error disabling device %s\n",
					accfg_device_get_devname(device));
			return rc;
		}
	}

	accfg_wq_foreach(device, wq)
		accfg_wq_set_size(wq, 0);

	return 0;

}

static void test_cleanup(struct accfg_ctx *ctx)
{
	struct accfg_device *device;

	accfg_device_foreach(ctx, device)
		device_test_reset(ctx, device, true);
}

static int set_config(struct accfg_ctx *ctx, struct config_test_ctx *ct_ctx,
		char *wq_mode)
{
	int rc = 0;
	struct accfg_device *device;
	struct accfg_group *group;
	struct accfg_engine *engine;
	struct accfg_wq *wq;
	int i;

	device = ct_ctx->device;
	printf("configuring device %s\n", accfg_device_get_devname(device));
	rc = config_device(ctx, device, ct_ctx->dev_param);
	if (rc) {
		fprintf(stderr, "config device failed\n");
		return rc;
	}

	for (i = 0; i < 2; i++) {
		group = ct_ctx->group[i];
		printf("configuring group %s\n", accfg_group_get_devname(group));
		rc = config_group(ctx, device, group, ct_ctx->group_param[i]);
		if (rc) {
			fprintf(stderr, "config group failed\n");
			return rc;
		}
	}

	for (i = 0; i < 4; i++) {
		if (wq_mode && strcmp(ct_ctx->wq_param[i]->mode, wq_mode))
			continue;

		wq = ct_ctx->wq[i];
		printf("configuring wq %s\n", accfg_wq_get_devname(wq));
		rc = config_wq(ctx, device, wq, ct_ctx->wq_param[i]);
		if (rc) {
			fprintf(stderr, "config wq failed\n");
			return rc;
		}
	}

	for (i = 0; i < 4; i++) {
		engine = ct_ctx->engine[i];
		printf("configuring engine %s\n", accfg_engine_get_devname(engine));
		rc = config_engine(ctx, device, engine, ct_ctx->engine_param[i]);
		if (rc) {
			fprintf(stderr, "config engine failed\n");
			return rc;
		}
	}

	return 0;
}

static int check_config(struct accfg_ctx *ctx, struct config_test_ctx *ct_ctx,
		char *wq_mode)
{
	int rc = 0;
	struct accfg_device *device;
	struct accfg_group *group;
	struct accfg_engine *engine;
	struct accfg_wq *wq;
	int i;

	device = ct_ctx->device;
	printf("check device %s\n", accfg_device_get_devname(device));
	rc = check_device(ctx, device, ct_ctx->dev_param);
	if (rc) {
		fprintf(stderr, "check device failed\n");
		return rc;
	}

	for (i = 0; i < 2; i++) {
		group = ct_ctx->group[i];
		printf("check group %s\n", accfg_group_get_devname(group));
		rc = check_group(ctx, device, group, ct_ctx->group_param[i]);
		if (rc) {
			fprintf(stderr, "check group failed\n");
			return rc;
		}
	}

	for (i = 0; i < 4; i++) {
		if (wq_mode && strcmp(ct_ctx->wq_param[i]->mode, wq_mode))
			continue;

		wq = ct_ctx->wq[i];
		printf("check wq %s\n", accfg_wq_get_devname(wq));
		rc = check_wq(ctx, device, wq, ct_ctx->wq_param[i]);
		if (rc) {
			fprintf(stderr, "check wq failed\n");
			return rc;
		}
	}

	for (i = 0; i < 4; i++) {
		engine = ct_ctx->engine[i];
		printf("check engine %s\n", accfg_engine_get_devname(engine));
		rc = check_engine(ctx, device, engine, ct_ctx->engine_param[i]);
		if (rc) {
			fprintf(stderr, "check engine failed\n");
			return rc;
		}
	}

	return 0;
}

static int set_exceed_config(struct accfg_ctx *ctx,
		struct config_test_ctx *ct_ctx)
{
	int rc = 0;
	struct accfg_device *device;
	struct accfg_wq *wq;
	struct accfg_group *group;
	unsigned int max_wq_size;

	device = ct_ctx->device;
	rc = config_device(ctx, device, ct_ctx->dev_param);
	if (rc) {
		fprintf(stderr, "config device failed\n");
		return rc;
	}

	group = ct_ctx->group[0];
	printf("configuring group %s\n", accfg_group_get_devname(group));
	rc = config_group(ctx, device, group, ct_ctx->group_param[0]);
	if (rc) {
		fprintf(stderr, "config group failed\n");
		return rc;
	}

	/* configure 2 wqs with some wq sizes */
	wq = ct_ctx->wq[1];
	printf("configuring wq %s\n", accfg_wq_get_devname(wq));
	rc = config_wq(ctx, device, wq, ct_ctx->wq_param[1]);
	if (rc) {
		fprintf(stderr, "config wq failed\n");
		return rc;
	}

	wq = ct_ctx->wq[3];
	printf("configuring wq %s\n", accfg_wq_get_devname(wq));
	rc = config_wq(ctx, device, wq, ct_ctx->wq_param[3]);
	if (rc) {
		fprintf(stderr, "config wq failed\n");
		return rc;
	}

	/* setting max wq size on 2nd wq should fail */
	printf("trying to set wq size exceeding max wq size\n");
	max_wq_size =
		accfg_device_get_max_work_queues_size(device);
	rc = accfg_wq_set_size(wq, max_wq_size);

	/* return error if write succeeds */
	if (!rc) {
		fprintf(stderr, "total wq size exceeds max wq size\n");
		return -EINVAL;
	}

	printf("wq size exceeding max wq size was not accepted\n");

	return 0;
}

static int wq_bounds_test(struct accfg_ctx *ctx, struct config_test_ctx *ct_ctx)
{
	int rc = 0;
	struct accfg_device *device;
	struct accfg_wq *wq;
	struct accfg_group *group;

	device = ct_ctx->device;
	group = ct_ctx->group[0];
	wq = ct_ctx->wq[1];

	printf("configure device %s, group %s, wq %s for bounds test\n",
			accfg_device_get_devname(device),
			accfg_group_get_devname(group),
			accfg_wq_get_devname(wq));

	rc = config_device(ctx, device, ct_ctx->dev_param);
	if (rc) {
		fprintf(stderr, "config device failed\n");
		return rc;
	}

	rc = config_group(ctx, device, group, ct_ctx->group_param[0]);
	if (rc) {
		fprintf(stderr, "config group failed\n");
		return rc;
	}

	rc = config_wq(ctx, device, wq, ct_ctx->wq_param[1]);
	if (rc) {
		fprintf(stderr, "config wq failed\n");
		return rc;
	}

	/* should not be 0  */
	printf("trying to set wq max_batch_size = 0\n");
	rc = accfg_wq_set_max_batch_size(wq, 0);
	if (!rc) {
		fprintf(stderr, "max_batch_size accepts 0 value\n");
		return -EINVAL;
	}

	printf("trying to set wq max_transfer_size = 0\n");
	rc = accfg_wq_set_max_transfer_size(wq, 0);
	if (!rc) {
		fprintf(stderr, "max_transfer_size accepts 0 value\n");
		return -EINVAL;
	}

	/* should not be greater device max_batch_size/max_transfer_size */
	printf("trying to set wq max_batch_size exceeding device max\n");
	rc = accfg_wq_set_max_batch_size(wq,
			(accfg_device_get_max_batch_size(device) << 1));
	if (!rc) {
		fprintf(stderr, "max_batch_size exceeds device max size\n");
		return -EINVAL;
	}

	printf("trying to set wq max_transfer_size exceeding device max\n");
	rc = accfg_wq_set_max_transfer_size(wq,
			(accfg_device_get_max_transfer_size(device) << 1));
	if (!rc) {
		fprintf(stderr, "max_transfer_size exceeds device max size\n");
		return -EINVAL;
	}

	printf("0 and greater than device max values were not accepted\n");

	return 0;
}

static int fill_test_ctx(struct accfg_ctx *ctx)
{
	int i;
	struct accfg_device *device;

	device = accfg_ctx_device_get_by_id(ctx, 0);
	if (!device)
		return -EINVAL;

	for (i = 0; i < 2; i++) {
		test_ctx.group[i] = accfg_device_group_get_by_id(device, i);
		if (!test_ctx.group[i])
			return -EINVAL;
		test_ctx.group_param[i] = group_params[i];
	}

	for (i = 0; i < 4; i++) {
		test_ctx.engine[i] = accfg_device_engine_get_by_id(device, i);
		if (!test_ctx.engine[i])
			return -EINVAL;
		test_ctx.engine_param[i] = engine_params[i];
	}

	for (i = 0; i < 4; i++) {
		test_ctx.wq[i] = accfg_device_wq_get_by_id(device, i);
		if (!test_ctx.wq[i])
			return -EINVAL;
		test_ctx.wq_param[i] = wq_params[i];
	}

	test_ctx.device = device;
	test_ctx.dev_param = &device0_param;

	return 0;
}

/* test set and get libaccfg functions for shared wqs */
static int test_config_shared(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	rc = set_config(ctx, &test_ctx, "shared");
	if (rc) {
		if (rc == -EINVAL) {
			fprintf(stderr, "shared wq support not available\n");
			device_test_reset(ctx, test_ctx.device, false);
			return -EOPNOTSUPP;
		}
		return rc;
	}

	rc = check_config(ctx, &test_ctx, "shared");
	if (rc)
		return rc;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	return 0;
}

/* test set and get libaccfg functions for dedicated wqs */
static int test_config_dedicated(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	rc = set_config(ctx, &test_ctx, "dedicated");
	if (rc)
		return rc;

	rc = check_config(ctx, &test_ctx, "dedicated");
	if (rc)
		return rc;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	return 0;
}

/* set large wq size to exceed max total wq size */
static int test_max_wq_size(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	rc = set_exceed_config(ctx, &test_ctx);
	if (rc)
		return rc;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	return 0;
}

/* test the boundary conditions for wq max_batch_size and max_transfer_size */
static int test_wq_boundary_conditions(struct accfg_ctx *ctx)
{
	int rc = 0;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	rc = wq_bounds_test(ctx, &test_ctx);
	if (rc)
		return rc;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	return 0;
}

static int compare_bitmask(uint32_t *bit_array1, uint32_t *bit_array2)
{
	int i;
	int rc;

	for (i = 0; i < 8; i++) {
		rc = bit_array1[i] - bit_array2[i];
		if (rc)
			return rc;
	}

	return 0;
}

static int op_config_test(struct accfg_ctx *ctx, struct accfg_wq *wq)
{
	int rc;
	struct accfg_op_config op_config, op_config1;
	struct accfg_op_cap op_cap;
	struct accfg_device *device;
	int i;

	device = accfg_wq_get_device(wq);
	rc = accfg_device_get_op_cap(device, &op_cap);
	if (rc) {
		printf("Error getting op cap\n");
		return rc;
	}

	for (i = 0; i < 8; i++)
		op_config.bits[i] = op_cap.bits[i];

	rc = accfg_wq_set_op_config(wq, &op_config);
	if (rc) {
		printf("Error setting op config\n");
		return rc;
	}

	rc = accfg_wq_get_op_config(wq, &op_config1);
	if (rc) {
		printf("Error getting op config\n");
		return rc;
	}

	if (compare_bitmask(op_config.bits, op_config1.bits)) {
		printf("Error setting op config\n");
		return rc;
	}

	for (i = 0; i < 8; i++)
		op_config.bits[i] = ~op_config.bits[i];

	rc = accfg_wq_set_op_config(wq, &op_config);
	if (!rc) {
		printf("Error - invalid op config was allowed\n");
		return -EINVAL;
	}

	for (i = 0; i < 8; i++)
		op_config.bits[i] = 0;

	rc = accfg_wq_set_op_config(wq, &op_config);
	if (rc) {
		printf("Error - clearing all op_config bits failed\n");
		return rc;
	}

	return 0;
}

/* test setting of valid op_config bitmask */
static int test_op_config(struct accfg_ctx *ctx)
{
	struct accfg_op_config op_config;
	int rc = 0;

	if (accfg_wq_get_op_config(test_ctx.wq[1], &op_config))
		return -EOPNOTSUPP;

	rc = device_test_reset(ctx, test_ctx.device, false);
	if (rc)
		return rc;

	rc = set_config(ctx, &test_ctx, "dedicated");
	if (rc)
		return rc;

	rc = op_config_test(ctx, test_ctx.wq[1]);
	if (rc)
		return rc;

	rc = device_test_reset(ctx, test_ctx.device, false);
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
		.test_fn = test_config_shared,
		.desc = "set and get configurations for shared wqs",
		.enabled = true,
	},
	{
		.test_fn = test_config_dedicated,
		.desc = "set and get configurations for dedicated wqs",
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
		.test_fn = test_op_config,
		.desc = "setting op_config bitmask",
		.enabled = true,
	},
};

int test_libaccfg(int loglevel, struct accfg_test *test,
		struct accfg_ctx *ctx)
{
	unsigned int i;
	int err, result = EXIT_FAILURE;
	struct accfg_device *device;
	struct log_ctx log_ctx;

	if (!accfg_test_attempt(test, KERNEL_VERSION(5, 6, 0)))
		return EXIT_SKIP;

	accfg_set_log_priority(ctx, loglevel);
	log_init(&log_ctx, "test/init", "LIB-ACCELCONFIG_TEST");
	log_ctx.log_priority = loglevel;

	if (access("/sys/module/idxd", F_OK)) {
		accfg_test_skip(test);
		fprintf(stderr, "idxd kernel module not loaded\n");
		return EXIT_SKIP;
	}

	/*
	 * iterate to check the state of each device, skip entire test if any of
	 * them is active or not configurable
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

		if (!accfg_device_get_configurable(device)) {
			accfg_test_skip(test);
			fprintf(stderr, "device is not configuratble, skipping tests\n");
			return EXIT_SKIP;
		}
	}

	if (fill_test_ctx(ctx)) {
		accfg_test_skip(test);
		fprintf(stderr, "error getting devices, skipping tests\n");
		return EXIT_SKIP;
	}

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		if (!test_cases[i].enabled) {
			fprintf(stderr, "\naccfg-test%d *disabled*\n", i);
			continue;
		}

		printf("\nRunning accfg-test%d: %s\n", i, test_cases[i].desc);
		err = test_cases[i].test_fn(ctx);
		if (err == -EOPNOTSUPP) {
			fprintf(stderr,
				"accfg-test%d *skipped*: required feature not found\n",
				i);
			continue;
		}
		if (err < 0) {
			fprintf(stderr, "accfg-test%d *failed*: %d\n", i, err);
			break;
		}
		printf("accfg-test%d passed!\n", i);
	}

	if (i >= ARRAY_SIZE(test_cases))
		result = EXIT_SUCCESS;

	test_cleanup(ctx);

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
