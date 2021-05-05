/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */
#ifndef _UTIL_FILTER_H_
#define _UTIL_FILTER_H_
#include <stdbool.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>

struct accfg_device;
struct accfg_group;
struct accfg_wq;
struct accfg_engine;
struct json_object;

/* json object hierarchy for device */
struct accfg_json_container {
	/* array of json group */
	struct json_object *jgroups;
	/* each json group */
	struct json_object *jgroup;
	/* array to track group with assigned wq/engine */
	struct json_object **jgroup_assigned;
	/* array for assigned wqs in group */
	struct json_object **jwq_group;
	/* array for unassigend wqs in group */
	struct json_object *jwq_ungroup;
	/* array for assigned engines in group */
	struct json_object **jengine_group;
	/* array for unassigned engines in group */
	struct json_object *jengine_ungroup;
	/* store group_id when a jgroup is created */
	int *jgroup_id;
	/* device_id bonded with this container */
	int device_id;
	/* device name bonded with this container */
	const char *device_name;
	/* list node to represent each container on linked list */
	struct list_node list;
};

/* json object device for the util_filter_walk() by cmd_list() and cmd_config() */
struct list_filter_arg {
	/* json object for device array */
	struct json_object *jdevices;
	/* json object for each device */
	struct json_object *jdevice;
	/* linked list to add accfg_json_container for each device */
	struct list_head jdev_list;
	/* linked list node for each list_filter_arg */
	struct list_node list;
	/* flags to indicate command options */
	uint64_t flags;
	/* track device number during walk-through */
	int dev_num;
	/* track group_num during walk-through */
	int group_num;


};

/*
 * struct util_filter_ctx - control and callbacks for util_filter_walk()
 * ->filter_device() and ->filter_group() return bool because the
 * child-object filter routines can not be called if the parent context
 * is not established. ->filter_wq() and ->filter_engine() are leaf
 * objects, so no child dependencies to check.
 */
struct util_filter_ctx {
	bool (*filter_device)(struct accfg_device *device, struct util_filter_ctx *ctx);
	bool (*filter_group)(struct accfg_group *group, struct util_filter_ctx *ctx);
	bool (*filter_wq)(struct accfg_wq *wq,
			struct util_filter_ctx *ctx);
	bool (*filter_engine)(struct accfg_engine *engine,
			struct util_filter_ctx *ctx);
	union {
		void *arg;
		struct list_filter_arg *list;
	};
};

struct util_filter_params {
	const char *device;
	const char *group;
	const char *wq;
	const char *engine;
};

struct accfg_ctx;

int scan_device_type_id(const char *name, char *dev_type,
		unsigned int *dev_id);
int scan_parent_child_names(const char *name, char *parent_name,
		char *child_name);
int scan_parent_child_ids(const char *name, unsigned int *parent_id,
		unsigned int *child_id);
int parse_device_name(struct accfg_ctx *ctx, const char *name,
		struct accfg_device **device);
int parse_wq_name(struct accfg_ctx *ctx, const char *name,
		struct accfg_device **device, struct accfg_wq **wq);
int parse_group_name(struct accfg_ctx *ctx, const char *name,
		struct accfg_device **device, struct accfg_group **group);
int parse_engine_name(struct accfg_ctx *ctx, const char *name,
		struct accfg_device **device, struct accfg_engine **engine);
int util_filter_walk(struct accfg_ctx *ctx, struct util_filter_ctx *fctx,
		struct util_filter_params *param);
int match_device(struct accfg_device *device, struct accfg_json_container *jc);
#endif
