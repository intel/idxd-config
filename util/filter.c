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

int match_device(struct accfg_device *dev, struct accfg_json_container *jc)
{
	return !strcmp(accfg_device_get_devname(dev), jc->device_name);
}

int scan_device_type_id(const char *name, char *dev_type,
		unsigned int *dev_id)
{
	char type[MAX_DEV_LEN];
	unsigned int id;

	if (sscanf(name, "%[a-z]%u", type, &id) != 2)
		return -EINVAL;

	if (dev_type)
		strcpy(dev_type, type);

	if (dev_id)
		*dev_id = id;

	return 0;
}

int scan_parent_child_names(const char *name, char *parent_name,
		char *child_name)
{
	char p_name[MAX_DEV_LEN], c_name[MAX_DEV_LEN];

	if (sscanf(name, "%[^/]/%s", p_name, c_name) != 2)
		return -EINVAL;

	if (parent_name)
		strcpy(parent_name, p_name);

	if (child_name)
		strcpy(child_name, c_name);

	return 0;
}

int scan_parent_child_ids(const char *name, unsigned int *parent_id,
		unsigned int *child_id)
{
	unsigned int p_id, c_id;

	if (sscanf(name, "%*[a-z]%u.%u", &p_id, &c_id) != 2)
		return -EINVAL;

	if (parent_id)
		*parent_id = p_id;

	if (child_id)
		*child_id = c_id;

	return 0;
}

int parse_device_name(struct accfg_ctx *ctx, const char *name,
		struct accfg_device **device)
{
	struct accfg_device *dev;
	char dev_type[MAX_DEV_LEN];
	int rc;

	rc = scan_device_type_id(name, dev_type, NULL);
	if (rc || !accfg_device_type_validate(dev_type))
		return -EINVAL;

	accfg_device_foreach(ctx, dev)
		if (!strcmp(name, accfg_device_get_devname(dev)))
			break;

	if (!dev) {
		fprintf(stderr, "%s device not found\n", name);
		return -EINVAL;
	}

	if (device)
		*device = dev;

	return 0;
}

int parse_wq_name(struct accfg_ctx *ctx, const char *name,
		struct accfg_device **device, struct accfg_wq **wq)
{
	struct accfg_device *dev;
	struct accfg_wq *q;
	char dev_name[MAX_DEV_LEN], wq_name[MAX_DEV_LEN];
	int rc;

	rc = scan_parent_child_names(name, dev_name, wq_name);
	if (rc)
		return rc;

	rc = parse_device_name(ctx, dev_name, &dev);
	if (rc)
		return rc;

	accfg_wq_foreach(dev, q)
		if (!strcmp(wq_name, accfg_wq_get_devname(q)))
			break;

	if (!q) {
		fprintf(stderr, "%s workqueue not found\n", name);
		return -EINVAL;
	}

	if (device)
		*device = dev;

	if (wq)
		*wq = q;

	return 0;
}

int parse_group_name(struct accfg_ctx *ctx, const char *name,
		struct accfg_device **device, struct accfg_group **group)
{
	struct accfg_device *dev;
	struct accfg_group *g;
	char dev_name[MAX_DEV_LEN], group_name[MAX_DEV_LEN];
	int rc;

	rc = scan_parent_child_names(name, dev_name, group_name);
	if (rc)
		return rc;

	rc = parse_device_name(ctx, dev_name, &dev);
	if (rc)
		return rc;

	accfg_group_foreach(dev, g)
		if (!strcmp(group_name, accfg_group_get_devname(g)))
			break;

	if (!g) {
		fprintf(stderr, "%s group not found\n", name);
		return -EINVAL;
	}

	if (device)
		*device = dev;

	if (group)
		*group = g;

	return 0;
}

int parse_engine_name(struct accfg_ctx *ctx, const char *name,
		struct accfg_device **device, struct accfg_engine **engine)
{
	struct accfg_device *dev;
	struct accfg_engine *e;
	char dev_name[MAX_DEV_LEN], engine_name[MAX_DEV_LEN];
	int rc;

	rc = scan_parent_child_names(name, dev_name, engine_name);
	if (rc)
		return rc;

	rc = parse_device_name(ctx, dev_name, &dev);
	if (rc)
		return rc;

	accfg_engine_foreach(dev, e)
		if (!strcmp(engine_name, accfg_engine_get_devname(e)))
			break;

	if (!e) {
		fprintf(stderr, "%s engine not found\n", name);
		return -EINVAL;
	}

	if (device)
		*device = dev;

	if (engine)
		*engine = e;

	return 0;
}

int util_filter_walk(struct accfg_ctx *ctx, struct util_filter_ctx *fctx,
		     struct util_filter_params *param)
{
	struct accfg_device *device, *dev  = NULL;
	struct accfg_wq *wq, *q = NULL;
	struct accfg_engine *engine, *e  = NULL;
	struct accfg_group *group, *g = NULL;
	bool b, found = false;
	int rc = 0;

	if (param->device)
		rc = parse_device_name(ctx, param->device, &dev);
	else if (param->group)
		rc = parse_group_name(ctx, param->group, &dev, &g);
	else if (param->wq)
		rc = parse_wq_name(ctx, param->wq, &dev, &q);
	else if (param->engine)
		rc = parse_engine_name(ctx, param->engine, &dev, &e);
	else
		found = true;

	if (rc)
		return rc;

	accfg_device_foreach(ctx, device) {
		if (dev && dev != device)
			continue;

		if (!fctx->filter_device(device, fctx))
			continue;

		if (param->device)
			found = true;

		accfg_group_foreach(device, group) {
			if (g && g != group)
				continue;
			b = fctx->filter_group(group, fctx);
			if (g) {
				found = b;
				break;
			}
		}

		accfg_wq_foreach(device, wq) {
			if (q && q != wq)
				continue;
			b = fctx->filter_wq(wq, fctx);
			if (q) {
				found = b;
				break;
			}
		}

		accfg_engine_foreach(device, engine) {
			if (e && e != engine)
				continue;
			b = fctx->filter_engine(engine, fctx);
			if (e) {
				found = b;
				break;
			}
		}

		if (dev)
			break;
	}

	if (!found) {
		fprintf(stderr, "No matching device found\n");
		return -EINVAL;
	}

	return 0;
}
