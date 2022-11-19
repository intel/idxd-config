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

#define DEV_EVL_SIZE_MIN	0x0040
#define DEV_EVL_SIZE_MAX	0xffff

static struct dev_parameters dev_param = {
	.read_buffer_limit = UINT_MAX,
	.event_log_size = INT_MAX,
};

static struct group_parameters group_param = {
	.read_buffers_reserved = UINT_MAX,
	.read_buffers_allowed = UINT_MAX,
	.use_read_buffer_limit = UINT_MAX,
	.traffic_class_a = INT_MAX,
	.traffic_class_b = INT_MAX,
	.desc_progress_limit = INT_MAX,
	.batch_progress_limit = INT_MAX,
};

static struct wq_parameters wq_param = {
	.group_id = INT_MAX,
	.wq_size = INT_MAX,
	.priority = INT_MAX,
	.block_on_fault = INT_MAX,
	.threshold = INT_MAX,
	.max_batch_size = INT_MAX,
	.max_transfer_size = INT_MAX,
	.ats_disable = INT_MAX,
	.prs_disable = INT_MAX,
};

static struct engine_parameters engine_param;

static int accel_config_parse_device_attribs(struct accfg_device *dev,
		struct dev_parameters *device_param)
{
	int rc = 0;

	if ((device_param->event_log_size != INT_MAX) &&
			(device_param->event_log_size < DEV_EVL_SIZE_MIN ||
			 device_param->event_log_size > DEV_EVL_SIZE_MAX)) {
		fprintf(stderr,
			"configured event-log-size for device is not within range (%d-%d)\n",
			DEV_EVL_SIZE_MIN, DEV_EVL_SIZE_MAX);
		return -EINVAL;
	}

	if (device_param->read_buffer_limit != UINT_MAX) {
		rc = accfg_device_set_read_buffer_limit(dev,
				device_param->read_buffer_limit);
		if (rc < 0)
			return rc;
	}

	if (device_param->event_log_size != INT_MAX) {
		rc = accfg_device_set_event_log_size(dev,
				device_param->event_log_size);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int accel_config_parse_group_attribs(struct accfg_group *group,
		struct group_parameters *group_params)
{
	int rc = 0;
	struct accfg_device *device;

	device = accfg_group_get_device(group);
	if (accfg_device_get_version(device) < ACCFG_DEVICE_VERSION_2 &&
			(group_params->traffic_class_a != INT_MAX ||
			 group_params->traffic_class_b != INT_MAX)) {
		fprintf(stderr, "traffic-class cannot be configured\n");
		return -EINVAL;
	}

	if (group_params->read_buffers_reserved != UINT_MAX &&
			group_params->read_buffers_reserved >= UCHAR_MAX) {
		fprintf(stderr,
			"configured read-buffers-reserved for group is not within range\n");
		return -EINVAL;
	}

	if (group_params->desc_progress_limit != INT_MAX &&
			(group_params->desc_progress_limit < 0 ||
			 group_params->desc_progress_limit > 3)) {
		fprintf(stderr,
			"configured desc-progress-limit reserved for group is not within range\n");
		return -EINVAL;
	}

	if (group_params->batch_progress_limit != INT_MAX &&
			(group_params->batch_progress_limit < 0 ||
			 group_params->batch_progress_limit > 3)) {
		fprintf(stderr,
			"configured batch-progress-limit reserved for group is not within range\n");
		return -EINVAL;
	}

	if (group_params->read_buffers_allowed != UINT_MAX &&
			group_params->read_buffers_allowed >= UCHAR_MAX) {
		fprintf(stderr, "invalid read-buffers-allowed value\n");
		return -EINVAL;
	}

	if (group_params->use_read_buffer_limit > 1 &&
		group_params->use_read_buffer_limit != UINT_MAX) {
		fprintf(stderr, "valid use-read-buffer-limit should be either 0 or 1\n");
		return -EINVAL;
	}

	if (group_params->traffic_class_a < 0 ||
			((group_params->traffic_class_a > 7) &&
			(group_params->traffic_class_a != INT_MAX))) {
		fprintf(stderr,
			"valid traffic-class-a should be from 0 to 7\n");
		return -EINVAL;
	}

	if (group_params->traffic_class_b < 0 ||
			((group_params->traffic_class_b > 7) &&
			(group_params->traffic_class_b != INT_MAX))) {
		fprintf(stderr,
			"valid traffic-class-b should be from 0 to 7\n");
		return -EINVAL;
	}

	if (group_params->use_read_buffer_limit != UINT_MAX) {
		rc = accfg_group_set_use_read_buffer_limit(group,
			group_params->use_read_buffer_limit);
		if (rc < 0)
			return rc;
	}

	if (group_params->read_buffers_reserved != UINT_MAX) {
		rc = accfg_group_set_read_buffers_reserved(group,
			group_params->read_buffers_reserved);
		if (rc < 0)
			return rc;
	}

	if (group_params->read_buffers_allowed != UINT_MAX) {
		rc = accfg_group_set_read_buffers_allowed(group,
			group_params->read_buffers_allowed);
		if (rc < 0)
			return rc;
	}

	if (group_params->traffic_class_a != INT_MAX) {
		rc = accfg_group_set_traffic_class_a(group,
			group_params->traffic_class_a);
		if (rc < 0)
			return rc;
	}

	if (group_params->traffic_class_b != INT_MAX) {
		rc = accfg_group_set_traffic_class_b(group,
			group_params->traffic_class_b);
		if (rc < 0)
			return rc;
	}

	if (group_params->desc_progress_limit != INT_MAX) {
		rc = accfg_group_set_desc_progress_limit(group,
			group_params->desc_progress_limit);
		if (rc < 0)
			return rc;
	}

	if (group_params->batch_progress_limit != INT_MAX) {
		rc = accfg_group_set_batch_progress_limit(group,
			group_params->batch_progress_limit);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int accel_config_parse_wq_attribs(struct accfg_device *device,
		struct accfg_wq *wq, struct wq_parameters *wq_params)
{
	int max_groups;
	unsigned int max_wq_size, max_batch_size;
	uint64_t max_transfer_size;
	int rc = 0;

	if (wq_params->mode) {
		if ((strcmp(wq_params->mode, "shared") != 0) &&
			(strcmp(wq_params->mode, "dedicated") != 0)) {
			fprintf(stderr,
				"valid mode should be shared or dedicated\n");
			return -EINVAL;
		}
	}

	max_groups = accfg_device_get_max_groups(device);
	max_wq_size = accfg_device_get_max_work_queues_size(device);
	max_batch_size = accfg_device_get_max_batch_size(device);
	max_transfer_size = accfg_device_get_max_transfer_size(device);

	if ((wq_params->wq_size > max_wq_size)
		&& (wq_params->wq_size != INT_MAX)) {
		fprintf(stderr,
			"valid size should be 0 to %d\n", max_wq_size);
		return -EINVAL;
	}

	if ((wq_params->group_id >= max_groups) &&
			(wq_params->group_id != INT_MAX)) {
		fprintf(stderr,
			"valid group id should be 0 to %d or -1 to dissociate the wq from groups\n",
			max_groups-1);
		return -EINVAL;
	}

	if (wq_params->block_on_fault > 1
		&& (wq_params->block_on_fault != INT_MAX)) {
		fprintf(stderr,
			"valid block-on-default should be either 0 or 1\n");
		return -EINVAL;
	}

	if (wq_params->prs_disable > 1
		&& (wq_params->prs_disable != INT_MAX)) {
		fprintf(stderr,
			"prs-disable value should be either 0 or 1\n");
		return -EINVAL;
	}

	if ((wq_params->max_batch_size < 1
		|| wq_params->max_batch_size > max_batch_size)
		&& (wq_params->max_batch_size != INT_MAX)) {
		fprintf(stderr,
			"valid max-batch-size should be 1 to %d\n", max_batch_size);
		return -EINVAL;
	}

	if ((wq_params->max_transfer_size < 1
		|| wq_params->max_transfer_size > max_transfer_size)
		&& (wq_params->max_transfer_size != INT_MAX)) {
		fprintf(stderr,
			"valid max-transfer-size should be 1 to %" PRIu64 "\n", max_transfer_size);
		return -EINVAL;
	}

	if (wq_params->ats_disable > 1
		&& (wq_params->ats_disable != INT_MAX)) {
		fprintf(stderr,
			"valid ats-disable should be either 0 or 1\n");
		return -EINVAL;
	}

	if (wq_params->mode) {
		rc = accfg_wq_set_str_mode(wq, wq_params->mode);
		if (rc < 0)
			return rc;
	}

	if (wq_params->type) {
		rc = accfg_wq_set_str_type(wq, wq_params->type);
		if (rc < 0)
			return rc;
	}

	if (wq_params->name) {
		rc = accfg_wq_set_str_name(wq, wq_params->name);
		if (rc < 0)
			return rc;
	}

	if (wq_params->driver_name) {
		if (!accfg_wq_driver_name_validate(wq, wq_params->driver_name)) {
			fprintf(stderr, "Invalid driver name \"%s\"\n",
					wq_params->driver_name);
			return -ENOENT;

		}
		rc = accfg_wq_set_str_driver_name(wq, wq_params->driver_name);
		if (rc < 0)
			return rc;
	}

	if (wq_params->op_config) {
		rc = accfg_wq_set_op_config_str(wq, wq_params->op_config);
		if (rc < 0) {
			fprintf(stderr, "Invalid op config \"%s\"\n",
					wq_params->op_config);
			return rc;
		}
	}

	if (wq_params->wq_size != INT_MAX) {
		rc = accfg_wq_set_size(wq, wq_params->wq_size);
		if (rc < 0)
			return rc;
	}

	if (wq_params->group_id != INT_MAX) {
		rc = accfg_wq_set_group_id(wq, wq_params->group_id);
		if (rc < 0)
			return rc;
	}

	if (wq_params->priority != INT_MAX) {
		rc = accfg_wq_set_priority(wq, wq_params->priority);
		if (rc < 0)
			return rc;
	}

	if (wq_params->block_on_fault != INT_MAX) {
		rc = accfg_wq_set_block_on_fault(wq,
					wq_params->block_on_fault);
		if (rc < 0)
			return rc;
	}

	if (wq_params->prs_disable != INT_MAX) {
		rc = accfg_wq_set_prs_disable(wq,
					wq_params->prs_disable);
		if (rc < 0)
			return rc;
	}

	if (wq_params->threshold != INT_MAX) {
		rc = accfg_wq_set_threshold(wq, wq_params->threshold);
		if (rc < 0)
			return rc;
	}

	if (wq_params->max_batch_size != INT_MAX) {
		rc = accfg_wq_set_max_batch_size(wq, wq_params->max_batch_size);
		if (rc < 0)
			return rc;
	}

	if (wq_params->max_transfer_size != INT_MAX) {
		rc = accfg_wq_set_max_transfer_size(wq, wq_params->max_transfer_size);
		if (rc < 0)
			return rc;
	}

	if (wq_params->ats_disable != INT_MAX) {
		rc = accfg_wq_set_ats_disable(wq, wq_params->ats_disable);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int accel_config_parse_engine_attribs(struct accfg_device *device,
	struct accfg_engine *engine, struct engine_parameters *engine_params)
{
	int max_groups, rc = 0;

	max_groups = accfg_device_get_max_groups(device);

	if (engine_params->group_id >= max_groups) {
		fprintf(stderr,
			"valid group id should be 0 to %d or -1 to dissociate from groups\n",
			max_groups - 1);
		return -EINVAL;
	}

	if (engine_params->group_id != INT_MAX) {
		rc = accfg_engine_set_group_id(engine,
					    engine_params->group_id);
		if (rc < 0)
			return rc;
	}

	return 0;
}

int cmd_config_device(int argc, const char **argv, void *ctx)
{
	struct accfg_device *device;
	int i, rc = 0;

	const struct option options[] = {
		OPT_UINTEGER('l', "read-buffer-limit", &dev_param.read_buffer_limit,
			     "specify read buffer limit by device"),
		OPT_INTEGER('e', "event-log-size", &dev_param.event_log_size,
			     "specify event log size for device"),
		OPT_END(),
	};

	const char *const u[] = {
		"accel-config config-device <device name> [<options>]",
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
		if (parse_device_name(ctx, argv[i], &device)) {
			fprintf(stderr,
				"%s is not a valid device name\n", argv[i]);
			continue;
		}

		rc = accel_config_parse_device_attribs(device, &dev_param);
		if (rc != 0) {
			fprintf(stderr,
					"accel_config_parse_device_attribs failed\n");
			return rc;
		}
	}

	return 0;
}

int cmd_config_group(int argc, const char **argv, void *ctx)
{
	int i, rc = 0;

	const struct option options[] = {
		OPT_UINTEGER('r', "read-buffers-reserved",
			     &group_param.read_buffers_reserved,
			     "specify read buffers reserved by group"),
		OPT_UINTEGER('t', "read-buffers-allowed",
				&group_param.read_buffers_allowed,
			     "specify read buffers allowed by group"),
		OPT_UINTEGER('l', "use-read-buffer-limit",
			     &group_param.use_read_buffer_limit,
			     "specify read buffer limit by group"),
		OPT_INTEGER('a', "traffic-class-a",
			    &group_param.traffic_class_a,
			    "specify traffic-class-a by group"),
		OPT_INTEGER('b', "traffic-class-b",
			    &group_param.traffic_class_b,
			    "specify traffic-class-b by group"),
		OPT_INTEGER('d', "desc-progress-limit",
			     &group_param.desc_progress_limit,
			     "specify desc progress limit for group"),
		OPT_INTEGER('p', "batch-progress-limit",
			     &group_param.batch_progress_limit,
			     "specify batch progress limit for group"),
		OPT_END(),
	};

	const char *const u[] = {
		"accel-config config-group <device name>/<group name> [<options>]",
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
		struct accfg_group *group;

		if (parse_group_name(ctx, argv[i], NULL, &group)) {
			fprintf(stderr,
				"%s is not a valid group name\n", argv[i]);
			continue;
		}

		rc = accel_config_parse_group_attribs(group, &group_param);
		if (rc < 0)
			return rc;
	}

	return 0;
}

int cmd_config_wq(int argc, const char **argv, void *ctx)
{
	int i, rc = 0;

	const struct option options[] = {
		OPT_INTEGER('g', "group-id", &wq_param.group_id,
			     "specify group-id used by wq"),
		OPT_UINTEGER('s', "wq-size", &wq_param.wq_size,
			     "specify wq-size used by wq"),
		OPT_UINTEGER('p', "priority", &wq_param.priority,
			    "specify priority used by wq"),
		OPT_INTEGER('b', "block-on-fault", &wq_param.block_on_fault,
			    "specify block-on-fault by wq"),
		OPT_INTEGER('r', "prs-disable", &wq_param.prs_disable,
			    "specify prs-disable for wq"),
		OPT_UINTEGER('t', "threshold", &wq_param.threshold,
			    "specify threshold by wq"),
		OPT_STRING('y', "type", &wq_param.type, "type",
			   "specify type by wq"),
		OPT_STRING('n', "name", &wq_param.name, "name",
			   "specify name by wq"),
		OPT_STRING('d', "driver-name", &wq_param.driver_name,
				"driver name", "specify wq driver name"),
		OPT_STRING('o', "op-config", &wq_param.op_config,
				"op config", "specify wq op config"),
		OPT_STRING('m', "mode", &wq_param.mode, "mode",
			   "specify mode by wq"),
		OPT_UINTEGER('c', "max-batch-size", &wq_param.max_batch_size,
			     "specify max-batch-size used by wq"),
		OPT_U64('x', "max-transfer-size", &wq_param.max_transfer_size,
			     "specify max-transfer-size used by wq"),
		OPT_INTEGER('a', "ats-disable", &wq_param.ats_disable,
			    "specify per wq ats-disable"),
		OPT_END(),
	};

	const char *const u[] = {
		"accel-config config-wq <device name>/<wq name> [<options>]",
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
		struct accfg_device *device;
		struct accfg_wq *wq;

		if (parse_wq_name(ctx, argv[i], &device, &wq)) {
			fprintf(stderr,
				"%s is not a valid workqueue name\n", argv[i]);
			continue;
		}

		rc = accel_config_parse_wq_attribs(device, wq, &wq_param);
		if (rc < 0)
			return rc;
	}

	return 0;
}

int cmd_config_engine(int argc, const char **argv, void *ctx)
{
	int i, rc = 0;

	const struct option options[] = {
		OPT_INTEGER('g', "group-id", &engine_param.group_id,
			     "specify group-id used by engine"),
		OPT_END(),
	};

	const char *const u[] = {
		"accel-config config-engine <device name>/<engine name> [<options>]",
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
		struct accfg_device *device;
		struct accfg_engine *engine;

		if (parse_engine_name(ctx, argv[i], &device, &engine)) {
			fprintf(stderr,
				"%s is not a valid engine name\n", argv[i]);
			continue;
		}

		rc = accel_config_parse_engine_attribs(device,
				engine, &engine_param);
		if (rc != 0) {
			fprintf(stderr,
					"accel_config_parse_engine_attribs failed\n");
			return rc;
		}
	}

	return 0;
}
