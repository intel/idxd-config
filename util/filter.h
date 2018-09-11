/*
 * Copyright(c) 2015-2019 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#ifndef _UTIL_FILTER_H_
#define _UTIL_FILTER_H_
#include <stdbool.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#define MAX_GROUP_NUM 4
struct dsactl_device *util_device_filter(struct dsactl_device *device, const char *ident);
struct dsactl_group *util_group_filter(struct dsactl_group *group,
		const char *ident);
struct dsactl_wq *util_wq_filter(struct dsactl_wq *wq,
		const char *ident);
struct dsactl_engine *util_engine_filter(struct dsactl_engine *engine, const char *ident);

struct dsactl_device *util_device_filter_by_group(struct dsactl_device *device,
                const char *ident);
struct dsactl_group *util_group_filter_by_wq(struct dsactl_group *group,
		const char *ident);
struct dsactl_group *util_group_filter_by_engine(struct dsactl_group *group,
		const char *ident);
struct dsactl_wq *util_wq_filter_by_group(struct dsactl_wq *wq,
		const char *ident);
struct dsactl_engine *util_engine_filter_by_group(struct dsactl_engine *engine,
		const char *ident);
struct json_object;

/* json object hierarchy for device */
struct device_org {
	struct json_object *jgroups;
	struct json_object *jgroup;
	struct json_object **jwqs;
	/* array for assigned wqs in group */
	struct json_object **jwq_array;
	/* array for unassigend wqs in group */
	struct json_object *jwq_device;
	/* array for assigned engines in group */
	struct json_object **jengine_array;
	/* array for unassigned engines in group */
        struct json_object *jengine_device;
	/* add a group pointer array to point the particular group on the list
	 * */
	struct json_object **jgroup_index;
	int *jgroup_id;
	struct list_node list;
};

/* json object device for the util_filter_walk() by cmd_list() and cmd_config() */
struct list_filter_arg {
        struct json_object *jdevices;
        struct json_object *jdevice;
        /* linked list to track device hierarchy */
	struct device_org *dev_org;
	struct list_head dev_container;
	unsigned long flags;
};

struct config_filter_arg {
	unsigned long flags;
};

/*
 * struct util_filter_ctx - control and callbacks for util_filter_walk()
 * ->filter_device() and ->filter_group() return bool because the
 * child-object filter routines can not be called if the parent context
 * is not established. ->filter_wq() and ->filter_engine() are leaf
 * objects, so no child dependencies to check.
 */
struct util_filter_ctx {
	bool (*filter_device)(struct dsactl_device *device, struct util_filter_ctx *ctx);
	bool (*filter_group)(struct dsactl_group *group, struct util_filter_ctx *ctx);
	bool (*filter_wq)(struct dsactl_wq *wq,
			struct util_filter_ctx *ctx);
	bool (*filter_engine)(struct dsactl_engine *engine,
			struct util_filter_ctx *ctx);
	union {
		void *arg;
		struct list_filter_arg *list;
		struct monitor_filter_arg *monitor;
	};
};

struct util_filter_params {
	const char *device;
	const char *group;
	const char *wq;
	const char *engine;
};

struct dsactl_ctx;
int util_filter_walk(struct dsactl_ctx *ctx, struct util_filter_ctx *fctx,
		struct util_filter_params *param);
#endif
