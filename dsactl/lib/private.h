/*
 * Copyright (c) 2014-2016, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 */


#ifndef _LIBDSACTL_PRIVATE_H_
#define _LIBDSACTL_PRIVATE_H_

#include <errno.h>
#include <stdbool.h>
#include <syslog.h>
#include <string.h>
#include <libudev.h>
#include <libkmod.h>
#include <util/log.h>
#include <ccan/list/list.h>
#include <ccan/array_size/array_size.h>

#include <dsactl/libdsactl.h>
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>

struct dsactl_device {
	struct dsactl_ctx *ctx;
        unsigned int id;
	struct dsactl_group* group;
	struct dsactl_wq* wq;
	struct dsactl_engine* engine;
	struct list_head groups;
	struct list_head wqs;
	struct list_head engines;
        struct list_node list;
	int group_init;
        int wq_init;
	int engine_init;
        char *device_path;
        char *device_buf;
        size_t buf_len;

	/* Device Attributes */
	struct dsactl_error errors;
	int max_groups;
        int max_work_queues;
        int max_engines;
        int max_work_queues_size;
        int numa_node;
        int ims_size;
        int max_batch_size;
	int configurable;
	int max_tokens;
	unsigned int token_limit;
	unsigned long max_transfer_size;
	unsigned long opcap;
	char *pasid_enabled;
};

struct dsactl_group {
        struct dsactl_device *device;
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
	unsigned int tokens_reserved;
	unsigned int tokens_allowed;
	unsigned int use_token_limit;
	int traffic_class_a;
	int traffic_class_b;
};

struct dsactl_engine {
	struct dsactl_device *device;
        struct dsactl_group *group;
	struct list_head engine_head;
        struct list_node list;
        char *dsa_engine_path;
        char *dsa_engine_buf;
        int type, id, buf_len;
        int numa_node;

	/* Engine Attributes */
	int group_id;
};

struct dsactl_wq {
	struct dsactl_device *device;
        struct dsactl_group *group;
        struct list_head wq_head;
	struct list_node list;
	char *dsawq_path;
        char *dsawq_buf;
        int type, id, buf_len;
        int numa_node;

	/* Workqueue Attributes */
	int group_id;
        int wq_size;
	int priv;
        int priority;
	int enforce_order;
	int block_on_fault;
	char* mode;
	char* state;
};

struct dsactl_cmd{};

#define DSACTL_EXPORT __attribute__ ((visibility("default")))

/**
 * struct dsactl_ctx - library user context to find "dsa" instances
 *
 * Instantiate with dsactl_new(), which takes an initial reference.  Free
 * the context by dropping the reference count to zero with
 * dsa_unref(), or take additional references with dsa_ref()
 * @timeout: default library timeout in milliseconds
 */
struct dsactl_ctx {
        /* log_ctx must be first member for dsactl_set_log_fn compat */
        struct log_ctx ctx;
        int refcount;
        int devices_init;
	int groups_init;
	struct list_head devices;
        unsigned long timeout;
        void *private_data;
};

static inline int check_udev(struct udev *udev)
{
        return udev ? 0 : -ENXIO;
}

static inline int check_kmod(struct kmod_ctx *kmod_ctx)
{
        return kmod_ctx ? 0 : -ENXIO;
}
#endif /* _LIBDSACTL_PRIVATE_H_ */
