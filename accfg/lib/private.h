// SPDX-License-Identifier: LGPL-2.1
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#ifndef _LIBACCFG_PRIVATE_H_
#define _LIBACCFG_PRIVATE_H_

#include <errno.h>
#include <stdbool.h>
#include <syslog.h>
#include <string.h>
#include <inttypes.h>
#include <util/log.h>
#include <uuid/uuid.h>
#include <ccan/list/list.h>
#include <ccan/array_size/array_size.h>
#include <accfg/libaccel_config.h>
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>

struct accfg_device {
	struct accfg_ctx *ctx;
	unsigned int id;
	struct accfg_group *group;
	struct accfg_wq *wq;
	struct accfg_engine *engine;
	struct list_head groups;
	struct list_head wqs;
	struct list_head engines;
	struct list_node list;
	int group_init;
	char *device_path;
	char *device_buf;
	char *bus_type_str;
	char *device_type_str;
	enum accfg_device_type type;
	size_t buf_len;

	/* Device Attributes */
	struct accfg_error errors;
	int max_groups;
	int max_work_queues;
	int max_engines;
	int max_work_queues_size;
	int numa_node;
	int ims_size;
	int max_batch_size;
	int compl_size;
	int configurable;
	int max_read_buffers;
	unsigned int read_buffer_limit;
	int event_log_size;
	unsigned int cdev_major;
	unsigned int version;
	uint64_t max_transfer_size;
	uint64_t opcap;
	uint64_t gencap;
	int pasid_enabled;
};

struct accfg_group {
	struct accfg_device *device;
	int id;
	int buf_len;
	int size;
	char *group_path;
	char *group_buf;
	char *group_engines;
	char *group_wqs;
	struct list_head wqs;
	struct list_head engines;
	struct list_node list;
	int numa_node;
	int group_id;
	int wqs_init;
	int engines_init;

	/* Group Attributes */
	unsigned int read_buffers_reserved;
	unsigned int read_buffers_allowed;
	unsigned int use_read_buffer_limit;
	int traffic_class_a;
	int traffic_class_b;
	unsigned int desc_progress_limit;
	unsigned int batch_progress_limit;
};

struct accfg_engine {
	struct accfg_device *device;
	struct accfg_group *group;
	struct list_node list;
	char *engine_path;
	char *engine_buf;
	int type, id, buf_len;
	int numa_node;

	/* Engine Attributes */
	int group_id;
};

struct accfg_wq {
	struct accfg_device *device;
	struct accfg_group *group;
	struct list_node list;
	char *wq_path;
	char *wq_buf;
	int id, buf_len;
	int numa_node;

	/* Workqueue Attributes */
	int group_id;
	int size;
	int priv;
	int priority;
	int block_on_fault;
	int cdev_minor;
	unsigned int threshold;
	char *mode;
	char *name;
	char *driver_name;
	enum accfg_wq_type type;
	char *state;
	unsigned int max_batch_size;
	uint64_t max_transfer_size;
	int ats_disable;
	int prs_disable;
};

#define ACCFG_EXPORT __attribute__ ((visibility("default")))

struct accfg_error_ctx {
	unsigned int cmd_status;
	struct accfg_device *device;
	struct accfg_group *group;
	struct accfg_wq *wq;
	struct accfg_engine *engine;
};

/**
 * struct accfg_ctx - library user context to find device instances
 *
 * Instantiate with accfg_new(), which takes an initial reference. Free
 * the context by dropping the reference count to zero with
 * accfg_unref(), or take additional references with accfg_ref()
 * @timeout: default library timeout in milliseconds
 */
struct accfg_ctx {
	/* log_ctx must be first member for accfg_set_log_fn compat */
	struct log_ctx ctx;
	int refcount;
	int devices_init;
	int groups_init;
	struct list_head devices;
	uint64_t timeout;
	void *private_data;
	bool compat;
	struct accfg_error_ctx *error_ctx;
};

#endif /* _LIBACCFG_PRIVATE_H_ */
