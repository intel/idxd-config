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
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <util/json.h>
#include <util/filter.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <dsactl/libdsactl.h>
#include <util/parse-options.h>
#include <ccan/array_size/array_size.h>
#include <dsactl.h>
#include "private.h"

static struct {
	bool devices;
	bool groups;
	bool engines;
	bool wqs;
	bool idle;
	bool health;
	bool media_errors;
	bool firmware;
} list;

static unsigned long listopts_to_flags(void)
{
	unsigned long flags = 0;

	if (list.idle)
		flags |= UTIL_JSON_IDLE;
	if (list.media_errors)
		flags |= UTIL_JSON_MEDIA_ERRORS;
	return flags;
}

static struct config_save {
	const char *saved_file;
} config_save;

struct util_filter_params param;
static int did_fail;
static unsigned int group_counter = 0;
static unsigned int wq_index = 0;
static unsigned int engine_index = 0;
static unsigned int dev_num;
static unsigned int max_groups;		/* max group number per device */

#define fail(fmt, ...) \
do { \
	did_fail = 1; \
	fprintf(stderr, "dsactl-%s:%s:%d: " fmt, \
			VERSION, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)

static struct json_object *group_to_json(struct dsactl_group *group,
					 unsigned long flags)
{
	struct json_object *jgroup = json_object_new_object();
	struct json_object *jobj = NULL;

	if (!jgroup)
		return NULL;

	jobj = json_object_new_string(dsactl_group_get_devname(group));
	if (!jobj)
		goto err;
	json_object_object_add(jgroup, "dev", jobj);

	jobj = json_object_new_int(dsactl_group_get_tokens_reserved(group));
	if (!jobj)
		goto err;
	json_object_object_add(jgroup, "tokens_reserved", jobj);

	jobj = json_object_new_int(dsactl_group_get_use_token_limit(group));
	if (!jobj)
		goto err;
	json_object_object_add(jgroup, "use_token_limit", jobj);

	jobj = json_object_new_int(dsactl_group_get_tokens_allowed(group));
	if (!jobj)
		goto err;
	json_object_object_add(jgroup, "tokens_allowed", jobj);

	jobj = json_object_new_int(dsactl_group_get_traffic_class_a(group));
	if (!jobj)
		goto err;
	json_object_object_add(jgroup, "traffic_class_a", jobj);

	jobj = json_object_new_int(dsactl_group_get_traffic_class_b(group));
	if (!jobj)
		goto err;
	json_object_object_add(jgroup, "traffic_class_b", jobj);

	return jgroup;
err:
	fail("\n");
	json_object_put(jgroup);
	return NULL;
}

static bool filter_wq(struct dsactl_wq *dsawq, struct util_filter_ctx *ctx)
{
	struct json_object *jdsawq;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	unsigned int group_index;
	bool within_group = false;

	if (!list.idle && !dsactl_wq_is_enabled(dsawq)) {
		return true;
	}

	jdsawq = util_wq_to_json(dsawq, lfa->flags);
	if (!jdsawq) {
		fail("\n");
		return false;
	}
	if (!lfa->dev_org->jwqs[wq_index]) {
		lfa->dev_org->jwqs[wq_index] = json_object_new_array();
		if (!lfa->dev_org->jwqs[wq_index]) {
			fail("\n");
			return false;
		}

		for (group_index = 0; group_index < max_groups; group_index++) {
			/* group array will only be created if group contains the wq */
			if (dsawq->group_id ==
			    lfa->dev_org->jgroup_id[group_index]) {
				within_group = true;
				container =
				    lfa->dev_org->jgroup_index[group_index];
				if (!lfa->dev_org->jwq_array[group_index]) {
					/* need to create wq array per group */
					lfa->dev_org->jwq_array[group_index] =
					    json_object_new_array();
					if (!lfa->dev_org->
					    jwq_array[group_index]) {
						fail("\n");
						return false;
					}
					if (container)
						json_object_object_add
						    (container, "workqueues",
						     lfa->
						     dev_org->jwq_array
						     [group_index]);
				}
				json_object_array_add(lfa->
						      dev_org->jwq_array
						      [group_index], jdsawq);
			}
		}

		/* for the rest, add into device directly */
		if (!lfa->dev_org->jwq_device) {
			lfa->dev_org->jwq_device = json_object_new_array();
			if (!lfa->dev_org->jwq_device) {
				fail("\n");
				return false;
			}
			container = lfa->jdevice;
			json_object_object_add(container,
					       "unassigned workqueues",
					       lfa->dev_org->jwq_device);
		}
		if (!within_group) {
			json_object_array_add(lfa->dev_org->jwq_device, jdsawq);
		}
	}
	wq_index++;
	return true;
}

static bool filter_engine(struct dsactl_engine *dsaengine,
			  struct util_filter_ctx *ctx)
{
	struct json_object *jdsaengine;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	unsigned int group_index;
	bool within_group = false;

	jdsaengine = util_engine_to_json(dsaengine, lfa->flags);
	if (!jdsaengine) {
		fail("\n");
		return false;
	}

	for (group_index = 0; group_index < max_groups; group_index++) {
			/* group array will only be created if group contains the engine */
			if (dsaengine->group_id ==
			    lfa->dev_org->jgroup_id[group_index]) {
				within_group = true;
				container =
				    lfa->dev_org->jgroup_index[group_index];
				if (!lfa->dev_org->jengine_array[group_index]) {
					/* need to create engine array per group */
					lfa->dev_org->
					    jengine_array[group_index] =
					    json_object_new_array();
					if (!lfa->dev_org->
					    jengine_array[group_index]) {
						fail("\n");
						return false;
					}
					if (container)
						json_object_object_add
						    (container, "engines",
						     lfa->
						     dev_org->jengine_array
						     [group_index]);
				}
				json_object_array_add(lfa->
						      dev_org->jengine_array
						      [group_index],
						      jdsaengine);
			}
		}

		/* for the rest, add into device directly */
		if (!lfa->dev_org->jengine_device) {
			lfa->dev_org->jengine_device =
				    json_object_new_array();
			if (!lfa->dev_org->jengine_device) {
				fail("\n");
				return false;
			}
			container = lfa->jdevice;
			json_object_object_add(container,
					       "unassigned engines",
					       lfa->dev_org->
					       jengine_device);
		}

		if (!within_group) {
			json_object_array_add(lfa->dev_org->jengine_device,
			      jdsaengine);
		}
	engine_index++;
	return true;
}

static bool filter_group(struct dsactl_group *group,
			 struct util_filter_ctx *ctx)
{
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *jgroup;
	struct json_object *container = lfa->jdevice;
	unsigned long device_id, group_id;
	unsigned int group_index;
	const char *group_name;

#if 0
	if (!list.groups) {
		return true;
	}

	if (!list.idle) {
		return true;
	}
#endif

	if (!lfa->dev_org->jgroups) {
		lfa->dev_org->jgroups = json_object_new_array();
		if (!lfa->dev_org->jgroups) {
			fail("\n");
			return false;
		}
		if (container)
			json_object_object_add(container, "groups",
					       lfa->dev_org->jgroups);
	}
	jgroup = group_to_json(group, lfa->flags);
	if (!jgroup) {
		fail("\n");
		return false;
	}

	lfa->dev_org->jgroup = jgroup;
	group_name = dsactl_group_get_devname(group);
	if (sscanf(group_name, "group%ld.%ld", &device_id, &group_id) != 2) {
		return false;
	}

	lfa->dev_org->jgroup_id[group_counter % max_groups] = group_id;
	lfa->dev_org->jgroup_index[group_counter % max_groups] = jgroup;
	group_counter++;

	/*
	 * We've started a new group, any previous jwqs and jengines will
	 * have been parented to the last group. Clear out jwqs and jengines
	 * so we start a new array per group.
	 */
	for (group_index = 0; group_index < group_counter % max_groups;
	     group_index++) {
		lfa->dev_org->jwq_array[group_index] = NULL;
		lfa->dev_org->jengine_array[group_index] = NULL;
	}

	json_object_array_add(lfa->dev_org->jgroups, jgroup);
	return true;
}

static bool filter_device(struct dsactl_device *device,
			  struct util_filter_ctx *ctx)
{
	struct list_filter_arg *lfa = ctx->list;
	unsigned int group_index;
	int max_wqs;

	max_groups = dsactl_device_get_max_groups(device);
	max_wqs = dsactl_device_get_max_work_queues(device);

#if 0
	//comment out list.devices option for phase 1
	if (!list.devices)
		return true;
#endif
	if (!lfa->jdevices) {
		lfa->jdevices = json_object_new_array();
		if (!lfa->jdevices) {
			fail("\n");
			return false;
		}
		list_head_init(&lfa->dev_container);
	}

	lfa->jdevice = util_device_to_json(device, lfa->flags);
	if (!lfa->jdevices) {
		fail("\n");
		return false;
	}
	lfa->dev_org = (struct device_org *)malloc(sizeof(struct device_org));
	if (!lfa->dev_org)
		return false;
	lfa->dev_org->jgroup_index =
	    (struct json_object **)calloc(max_groups,
					  sizeof(struct json_object *));
	if (!lfa->dev_org->jgroup_index)
		return false;
	lfa->dev_org->jwq_array =
	    (struct json_object **)calloc(max_groups,
					  sizeof(struct json_object *));
	if (!lfa->dev_org->jwq_array)
		return false;
	lfa->dev_org->jengine_array =
	    (struct json_object **)calloc(max_groups,
					  sizeof(struct json_object *));
	if (!lfa->dev_org->jengine_array)
		return false;
	lfa->dev_org->jwqs =
	    (struct json_object **)calloc(max_wqs,
					  sizeof(struct json_object *));
	if (!lfa->dev_org->jwqs)
		return false;
	lfa->dev_org->jgroup_id = (int *)calloc(max_groups, sizeof(int));
	if (!lfa->dev_org->jgroup_id)
		return false;

	list_add(&lfa->dev_container, &lfa->dev_org->list);

	/* a fresh dev_org will be null */
	lfa->dev_org->jgroups = NULL;
	for (group_index = 0; group_index < max_groups; group_index++) {
		lfa->dev_org->jwq_array[group_index] = NULL;
		lfa->dev_org->jengine_array[group_index] = NULL;
	}
	lfa->dev_org->jwq_device = NULL;
	lfa->dev_org->jengine_device = NULL;
	lfa->dev_org->jengine_device = NULL;

	json_object_array_add(lfa->jdevices, lfa->jdevice);
	dev_num++;

	return true;
}

static int save_config(struct list_filter_arg *lfa, const char* saved_file)
{
	struct json_object *jdevices = lfa->jdevices;
	FILE *fd = fopen(saved_file, "w");
	if (!fd) {
		perror("open saved_config failed\n");
		return false;
	}

	if (jdevices)
		__util_display_json_array(fd, jdevices, lfa->flags);

	/* free all the allocated dev_org data structure */
	if (!lfa->dev_org->jgroup_index)
		free(lfa->dev_org->jgroup_index);
	if (!lfa->dev_org->jwq_array)
		free(lfa->dev_org->jwq_array);
	if (!lfa->dev_org->jengine_array)
		free(lfa->dev_org->jengine_array);
	if (!lfa->dev_org->jwqs)
		free(lfa->dev_org->jwqs);
	if (!lfa->dev_org->jgroup_id)
		free(lfa->dev_org->jgroup_id);
	if (!lfa->dev_org)
		free(lfa->dev_org);
	return 0;
}

static int list_display(struct list_filter_arg *lfa)
{
	struct json_object *jdevices = lfa->jdevices;
	int jflag = JSON_C_TO_STRING_PRETTY;
	unsigned int i = 0, index = 0, flag;

	if (!list.devices && !list.groups && !list.wqs && !list.engines) {
		if (jdevices)
			util_display_json_array(stdout, jdevices, lfa->flags);
	} else if (list.devices) {
		if (jdevices && (!param.device))
			util_display_json_array(stdout, jdevices, lfa->flags);
		if (param.device) {
			unsigned int device_id;
			struct json_object *jdevice;
			if  (sscanf(param.device, "dsa%d", &device_id) != 1)
				return false;

			if (device_id > dev_num) {
				fprintf(stderr, "device_id out of range\n");
				return false;
			}

			jdevice = json_object_array_get_idx(jdevices, device_id);
			printf("%s\n",
			json_object_to_json_string_ext(jdevice, jflag));
		}
	} else if (list.groups) {
			if ((!param.group)) {
				struct device_org *dev_org =
					list_top(&lfa->dev_container,
					struct device_org, list);
				while (i < dev_num) {
					struct json_object *jgroups = dev_org->jgroups;
					util_display_json_array(stdout, jgroups,
							lfa->flags);
					dev_org = list_next(&lfa->dev_container,
							dev_org, list);
					i++;
				}
			} else if (param.group) {
				unsigned int device_id, group_id;
				struct json_object *jgroups;

				if (sscanf(param.group, "group%d.%d", &device_id,
							&group_id) != 2)
                                         return false;
                                if (device_id > dev_num || group_id > max_groups) {
                                         fprintf(stderr, "device_id or group_id  out of range\n");
                                         return false;
                                }

				if (!lfa->dev_org)
					return false;

				jgroups = lfa->dev_org->jgroups;
				for (i = 0; i < dev_num; i++) {
					if (jgroups)
					 util_display_json_array(stdout, jgroups,
							 lfa->flags);
				}
			}
	} else if (list.wqs) {
		unsigned device_id, wq_id;
		struct json_object *jwq_array[max_groups];
		struct json_object *jwq_device;

		fprintf(stdout, "%s\n", "workqueues:");

		if (param.wq) {
			if  (sscanf(param.wq, "wq%d.%d", &device_id, &wq_id) != 2)
				return false;

			if (device_id > dev_num || wq_id > max_groups) {
				fprintf(stderr, "device_id or wq_id out of range\n");
				return false;
			}

			if (!lfa->dev_org)
				return false;

			jwq_device = lfa->dev_org->jwq_device;

			for (i = 0; i < dev_num; i++) {
				flag = 0;
				for (index = 0; index < max_groups; index++) {
					jwq_array[index] =
					lfa->dev_org->jwq_array[index];
					if (jwq_array[index] != NULL) {
					util_display_json_array(stdout,
								jwq_array
								[index],
								lfa->flags);
					flag = 1;
					}
				}
				if (jwq_device && (!flag)) {
				fprintf(stdout, "%s\n",
					"unassigned workqueues:");
				util_display_json_array(stdout, jwq_device,
						lfa->flags);
				}
			}
		} else {
			struct device_org *dev_org = list_top(&lfa->dev_container,
					struct device_org, list);
			for (i = 0; i < dev_num; i++) {
				for (index = 0; index < max_groups; index++) {
					if (dev_org->jwq_array[index] != NULL)
						util_display_json_array(stdout,
						dev_org->jwq_array[index], lfa->flags);
				}
				util_display_json_array(stdout, dev_org->jwq_device,
						lfa->flags);
				dev_org = list_next(&lfa->dev_container, dev_org, list);
			}
		}
	} else if (list.engines) {
		unsigned device_id, engine_id;
		struct json_object *jengine_array[max_groups];
		struct json_object *jengine_device;

		fprintf(stdout, "%s\n", "engines:");

		if (param.engine) {
			if  (sscanf(param.engine, "engine%d.%d", &device_id,
						&engine_id) != 2)
				return false;

			if (device_id > dev_num || engine_id > max_groups) {
				fprintf(stderr, "device_id or engine_id out of range\n");
				return false;
			}

			if (!lfa->dev_org)
				return false;

			jengine_device = lfa->dev_org->jengine_device;

			for (i = 0; i < dev_num; i++) {
				flag = 0;
				for (index = 0; index < max_groups; index++) {
					jengine_array[index] =
					lfa->dev_org->jengine_array[index];
					if (jengine_array[index]) {
					util_display_json_array(stdout,
								jengine_array
								[index],
								lfa->flags);
					flag = 1;
					}
				}
				if (jengine_device && (!flag)) {
				fprintf(stdout, "%s\n", "unassigned engines:");
				util_display_json_array(stdout, jengine_device,
							lfa->flags);
				}
			}
		} else {
			struct device_org *dev_org = list_top(&lfa->dev_container,
					struct device_org, list);
			for (i = 0; i < dev_num; i++) {
				for (index = 0; index < max_groups; index++) {
					if (dev_org->jengine_array[index] != NULL)
						util_display_json_array(stdout,
						dev_org->jengine_array[index], lfa->flags);
				}
				util_display_json_array(stdout, dev_org->jengine_device,
						lfa->flags);
				dev_org = list_next(&lfa->dev_container, dev_org, list);
			}
		}
	}

	/* free all the allocated dev_org data structure */
	if (!lfa->dev_org->jgroup_index)
		free(lfa->dev_org->jgroup_index);
	if (!lfa->dev_org->jwq_array)
		free(lfa->dev_org->jwq_array);
	if (!lfa->dev_org->jengine_array)
		free(lfa->dev_org->jengine_array);
	if (!lfa->dev_org->jwqs)
		free(lfa->dev_org->jwqs);
	if (!lfa->dev_org->jgroup_id)
		free(lfa->dev_org->jgroup_id);
	if (!lfa->dev_org)
		free(lfa->dev_org);
	return 0;
}

static int num_list_flags(void)
{
	return list.devices + list.groups + list.wqs + list.engines;
}

int cmd_list(int argc, const char **argv, void *ctx)
{
	const struct option options[] = {
		OPT_STRING('d', "device", &param.device, "device-id",
			   "filter by device"),
		OPT_STRING('g', "group", &param.group, "group-id",
			   "filter by group"),
		OPT_STRING('q', "workqueue", &param.wq, "wq-id",
			   "filter by workqueue"),
		OPT_STRING('e', "engine", &param.engine, "engine-id",
			   "filter by engine"),
		OPT_BOOLEAN('G', "groups", &list.groups, "include group info"),
		OPT_BOOLEAN('D', "devices", &list.devices,
			    "include device info"),
		OPT_BOOLEAN('E', "engines", &list.engines,
			    "include engine info"),
		OPT_BOOLEAN('Q', "workqueues", &list.wqs,
			    "include workqueue info"),
		OPT_BOOLEAN('i', "idle", &list.idle, "include idle components"),
		OPT_END(),
	};
	const char *const u[] = {
		"dsactl list [<options>]",
		NULL
	};
	struct util_filter_ctx fctx = { 0 };
	struct list_filter_arg lfa = { 0 };
	int i, rc;

	argc = parse_options(argc, argv, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);
	if (num_list_flags() == 0) {
		list.devices = ! !param.device;
		list.groups = ! !param.group;
		list.wqs = ! !param.wq;
		list.engines = ! !param.engine;
	}

	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &lfa;
	lfa.flags = listopts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &param);
	if (rc)
		return rc;

	if (list_display(&lfa) || did_fail)
		return -ENOMEM;
	return 0;
}

int cmd_save(int argc, const char **argv, void *ctx)
{
	const struct option options[] = {
		OPT_STRING('s', "saved-file", &config_save.saved_file,
			"saved-file", "specify saved file name and path"),
		OPT_END(),
	};
	const char *const u[] = {
		"dsactl save-config [<options>]",
		NULL
	};
	struct util_filter_ctx fctx = { 0 };
	struct list_filter_arg lfa = { 0 };
	int i, rc;

	argc = parse_options(argc, argv, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);

	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &lfa;
	lfa.flags = listopts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &param);
	if (rc)
		return rc;

	if (save_config(&lfa, config_save.saved_file))
		return -ENOMEM;
	return 0;
}
