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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <util/util.h>
#include <sys/types.h>
#include <dsactl/dsactl.h>
#include <util/filter.h>
#include <dsactl/libdsactl.h>
#include <dsactl/lib/private.h>

#define NUMA_NO_NODE    (-1)

struct dsactl_device *util_device_filter(struct dsactl_device *device,
					 const char *__ident)
{
	char *end = NULL, *ident, *save;
	unsigned long device_id, id;
	const char *devname, *name;

	if (!__ident)
		return device;
	ident = strdup(__ident);
	if (!ident)
		return NULL;
	for (name = strtok_r(ident, " ", &save); name;
	     name = strtok_r(NULL, " ", &save)) {
		if (strcmp(name, "all") == 0)
			break;

		device_id = strtoul(ident, &end, 0);
		if (end == ident || end[0])
			device_id = ULONG_MAX;

		devname = dsactl_device_get_devname(device);
		id = dsactl_device_get_id(device);
		if (device_id < ULONG_MAX && device_id == id)
			break;

		if (device_id == ULONG_MAX || strcmp(devname, name) == 0)
			break;
	}
	free(ident);

	if (name) {
		return device;
	}
	return NULL;
}

struct dsactl_group *util_group_filter(struct dsactl_group *group,
				       const char *__ident)
{
	char *ident, *save;
	const char *name;
	unsigned long device_id, group_id;

	if (!__ident) {
		return group;
	}

	ident = strdup(__ident);
	if (!ident)
		return NULL;

	for (name = strtok_r(ident, " ", &save); name;
	     name = strtok_r(NULL, " ", &save)) {
		if (strcmp(name, "all") == 0)
			break;

		if (strcmp(name, dsactl_group_get_devname(group)) == 0) {
			break;
		}

		if (sscanf(name, "%ld.%ld", &device_id, &group_id) == 2
		    && dsactl_group_get_id(group) == group_id
		    && dsactl_group_get_device_id(group) == device_id) {
			break;
		}
	}
	free(ident);
	if (name) {
		return group;
	}
	return NULL;
}

struct dsactl_wq *util_wq_filter(struct dsactl_wq *dsawq, const char *__ident)
{
	struct dsactl_group *group = dsactl_wq_get_group(dsawq);
	unsigned long group_id, dsawq_id;
	const char *name;
	char *ident, *save;

	if (!__ident)
		return dsawq;

	ident = strdup(__ident);
	if (!ident)
		return NULL;

	for (name = strtok_r(ident, " ", &save); name;
	     name = strtok_r(NULL, " ", &save)) {
		if (strcmp(name, dsactl_wq_get_devname(dsawq)) == 0)
			break;

		if (sscanf(name, "%ld.%ld", &group_id, &dsawq_id) == 2
		    && dsactl_group_get_id(group) == group_id
		    && dsactl_wq_get_group_id(dsawq) == dsawq_id)
			break;
	}
	free(ident);

	if (name)
		return dsawq;
	return NULL;
}

struct dsactl_engine *util_engine_filter(struct dsactl_engine *dsaengine,
					 const char *__ident)
{
	struct dsactl_group *group = dsactl_engine_get_group(dsaengine);
	unsigned long group_id, dsaengine_id;
	const char *name;
	char *ident, *save;

	if (!__ident)
		return dsaengine;

	ident = strdup(__ident);
	if (!ident)
		return NULL;

	for (name = strtok_r(ident, " ", &save); name;
	     name = strtok_r(NULL, " ", &save)) {
		if (strcmp(name, dsactl_engine_get_devname(dsaengine)) == 0)
			break;

		if (sscanf(name, "%ld.%ld", &group_id, &dsaengine_id) == 2
		    && dsactl_group_get_id(group) == group_id
		    && dsactl_engine_get_id(dsaengine) == dsaengine_id)
			break;
	}
	free(ident);

	if (name)
		return dsaengine;
	return NULL;
}

struct dsactl_device *util_device_filter_by_group(struct dsactl_device *device,
						  const char *ident)
{
	struct dsactl_group *group;

	if (!ident || strcmp(ident, "all") == 0) {
		return device;
	}

	dsactl_group_foreach(device, group) {
		if (util_group_filter(group, ident)) {
			return device;
		}
	}
	return NULL;
}

struct dsactl_device *util_device_filter_by_wq(struct dsactl_device *device,
					       const char *ident)
{
	struct dsactl_group *group;
	struct dsactl_wq *dsawq;

	if (!ident || strcmp(ident, "all") == 0)
		return device;

	dsactl_group_foreach(device, group)
	    dsactl_wq_foreach(device, dsawq)
	    if (util_wq_filter(dsawq, ident))
		return device;
	return NULL;
}

struct dsactl_device *util_device_filter_by_engine(struct dsactl_device *device,
						   const char *ident)
{
	struct dsactl_group *group;
	struct dsactl_engine *dsaengine;

	if (!ident || strcmp(ident, "all") == 0)
		return device;

	dsactl_group_foreach(device, group)
	    dsactl_engine_foreach(device, dsaengine)
	    if (util_engine_filter(dsaengine, ident))
		return device;
	return NULL;
}

struct dsactl_group *util_group_filter_by_wq(struct dsactl_group *group,
					     const char *ident)
{
	struct dsactl_wq *dsawq;
	struct dsactl_device *device = group->device;

	if (!ident || strcmp(ident, "all") == 0)
		return group;

	dsactl_wq_foreach(device, dsawq)
	    if (util_wq_filter(dsawq, ident))
		return group;
	return NULL;
}

struct dsactl_group *util_group_filter_by_engine(struct dsactl_group *group,
						 const char *ident)
{
	struct dsactl_engine *dsaengine;
	struct dsactl_device *device = group->device;

	if (!ident || strcmp(ident, "all") == 0)
		return group;

	dsactl_engine_foreach(device, dsaengine)
	    if (util_engine_filter(dsaengine, ident))
		return group;
	return NULL;
}

int util_filter_walk(struct dsactl_ctx *ctx, struct util_filter_ctx *fctx,
		     struct util_filter_params *param)
{
	struct dsactl_device *device;
	struct dsactl_wq *dsawq;
	struct dsactl_engine *dsaengine;
	struct dsactl_group *group;

	dsactl_device_foreach(ctx, device) {
		if (!util_device_filter(device, param->device)
		    || !util_device_filter_by_group(device, param->group)
		    || !util_device_filter_by_wq(device, param->wq)
		    || !util_device_filter_by_engine(device, param->engine))
			continue;

		if (!fctx->filter_device(device, fctx))
			continue;

		dsactl_group_foreach(device, group) {
			if (!util_group_filter(group, param->group))
				continue;

			if (!fctx->filter_group(group, fctx))
				continue;
		}

		dsactl_wq_foreach(device, dsawq) {
			if (!fctx->filter_wq) {
				break;
			}

			if (!util_wq_filter(dsawq, param->wq))
				continue;

			fctx->filter_wq(dsawq, fctx);
		}

		dsactl_engine_foreach(device, dsaengine) {
			if (!fctx->filter_engine)
				break;

			if (!util_engine_filter(dsaengine, param->engine))
				continue;

			fctx->filter_engine(dsaengine, fctx);
		}
	}
	return 0;
}
