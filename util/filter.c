// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2015-2019 Intel Corporation. All rights reserved.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <util/util.h>
#include <sys/types.h>
#include <accfg/accfg.h>
#include <util/filter.h>
#include <accfg/libaccel_config.h>
#include <accfg/lib/private.h>

#define NUMA_NO_NODE    (-1)

struct accfg_device *util_device_filter(struct accfg_device *device,
					 const char *__ident)
{
	char *end = NULL, *ident, *save;
	int device_id, id;
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
			device_id = UINT_MAX;

		devname = accfg_device_get_devname(device);
		id = accfg_device_get_id(device);
		if ((unsigned int)device_id < UINT_MAX && device_id == id)
			break;
		if ((unsigned int)device_id == UINT_MAX && strcmp(devname, name) == 0)
			break;
	}
	free(ident);

	if (name)
		return device;

	return NULL;
}

struct accfg_group *util_group_filter(struct accfg_group *group,
				       const char *__ident)
{
	char *ident, *save;
	const char *name;
	int device_id, group_id;

	if (!__ident)
		return group;

	ident = strdup(__ident);
	if (!ident)
		return NULL;

	for (name = strtok_r(ident, " ", &save); name;
	     name = strtok_r(NULL, " ", &save)) {
		if (strcmp(name, "all") == 0)
			break;

		if (strcmp(name, accfg_group_get_devname(group)) == 0)
			break;

		if (sscanf(name, "%d.%d", &device_id, &group_id) == 2
		    && accfg_group_get_id(group) == group_id
		    && accfg_group_get_device_id(group) == device_id) {
			break;
		}
	}
	free(ident);
	if (name)
		return group;

	return NULL;
}

struct accfg_wq *util_wq_filter(struct accfg_wq *wq, const char *__ident)
{
	struct accfg_group *group = accfg_wq_get_group(wq);
	int group_id, wq_id;
	const char *name;
	char *ident, *save;

	if (!__ident)
		return wq;

	ident = strdup(__ident);
	if (!ident)
		return NULL;

	for (name = strtok_r(ident, " ", &save); name;
	     name = strtok_r(NULL, " ", &save)) {
		if (strcmp(name, accfg_wq_get_devname(wq)) == 0)
			break;

		if (sscanf(name, "%d.%d", &group_id, &wq_id) == 2
		    && accfg_group_get_id(group) == group_id
		    && accfg_wq_get_group_id(wq) == wq_id)
			break;
	}
	free(ident);

	if (name)
		return wq;
	return NULL;
}

struct accfg_engine *util_engine_filter(struct accfg_engine *engine,
					 const char *__ident)
{
	struct accfg_group *group = accfg_engine_get_group(engine);
	int group_id, engine_id;
	const char *name;
	char *ident, *save;

	if (!__ident)
		return engine;

	ident = strdup(__ident);
	if (!ident)
		return NULL;

	for (name = strtok_r(ident, " ", &save); name;
	     name = strtok_r(NULL, " ", &save)) {
		if (strcmp(name, accfg_engine_get_devname(engine)) == 0)
			break;

		if (sscanf(name, "%d.%d", &group_id, &engine_id) == 2
		    && accfg_group_get_id(group) == group_id
		    && accfg_engine_get_id(engine) == engine_id)
			break;
	}
	free(ident);

	if (name)
		return engine;
	return NULL;
}

struct accfg_device *util_device_filter_by_group(struct accfg_device *device,
						  const char *ident)
{
	struct accfg_group *group;

	if (!ident || strcmp(ident, "all") == 0)
		return device;

	accfg_group_foreach(device, group) {
		if (util_group_filter(group, ident))
			return device;
	}
	return NULL;
}

struct accfg_device *util_device_filter_by_wq(struct accfg_device *device,
					       const char *ident)
{
	struct accfg_group *group;
	struct accfg_wq *wq;

	if (!ident || strcmp(ident, "all") == 0)
		return device;

	accfg_group_foreach(device, group)
		accfg_wq_foreach(device, wq)
			if (util_wq_filter(wq, ident))
				return device;
	return NULL;
}

struct accfg_device *util_device_filter_by_engine(struct accfg_device *device,
						   const char *ident)
{
	struct accfg_group *group;
	struct accfg_engine *engine;

	if (!ident || strcmp(ident, "all") == 0)
		return device;

	accfg_group_foreach(device, group)
		accfg_engine_foreach(device, engine)
			if (util_engine_filter(engine, ident))
				return device;
	return NULL;
}

struct accfg_group *util_group_filter_by_wq(struct accfg_group *group,
					     const char *ident)
{
	struct accfg_wq *wq;
	struct accfg_device *device = group->device;

	if (!ident || strcmp(ident, "all") == 0)
		return group;

	accfg_wq_foreach(device, wq)
		if (util_wq_filter(wq, ident))
			return group;
	return NULL;
}

struct accfg_group *util_group_filter_by_engine(struct accfg_group *group,
						 const char *ident)
{
	struct accfg_engine *engine;
	struct accfg_device *device = group->device;

	if (!ident || strcmp(ident, "all") == 0)
		return group;

	accfg_engine_foreach(device, engine)
		if (util_engine_filter(engine, ident))
			return group;
	return NULL;
}

int match_device(struct accfg_device *dev, struct accfg_json_container *jc)
{
	if ((accfg_device_get_id(dev) == jc->device_id) &&
		strcmp(accfg_device_get_devname(dev),
		jc->device_name) == 0)
		return 1;
	return 0;
}

int util_filter_walk(struct accfg_ctx *ctx, struct util_filter_ctx *fctx,
		     struct util_filter_params *param)
{
	struct accfg_device *device;
	struct accfg_wq *wq;
	struct accfg_engine *engine;
	struct accfg_group *group;

	accfg_device_foreach(ctx, device) {
		if (!util_device_filter(device, param->device)
		    || !util_device_filter_by_group(device, param->group)
		    || !util_device_filter_by_wq(device, param->wq)
		    || !util_device_filter_by_engine(device, param->engine))
			continue;

		if (!fctx->filter_device(device, fctx))
			continue;

		accfg_group_foreach(device, group) {
			if (!util_group_filter(group, param->group))
				continue;
			if (!fctx->filter_group(group, fctx))
				continue;
		}

		accfg_wq_foreach(device, wq) {
			if (!fctx->filter_wq)
				break;

			if (!util_wq_filter(wq, param->wq))
				continue;

			fctx->filter_wq(wq, fctx);
		}

		accfg_engine_foreach(device, engine) {
			if (!fctx->filter_engine)
				break;

			if (!util_engine_filter(engine, param->engine))
				continue;

			fctx->filter_engine(engine, fctx);
		}
	}
	return 0;
}
