/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <util/json.h>
#include <util/filter.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <accfg/libaccel_config.h>
#include <util/parse-options.h>
#include <ccan/array_size/array_size.h>
#include <accfg.h>

static struct util_filter_params util_param;
static struct {
	bool devices;
	bool groups;
	bool engines;
	bool wqs;
	bool idle;
	bool save_conf;
} list;

static uint64_t listopts_to_flags(void)
{
	uint64_t flags = 0;

	if (list.idle)
		flags |= UTIL_JSON_IDLE;
	if (list.save_conf)
		flags |= UTIL_JSON_SAVE;
	return flags;
}

static struct config_save {
	const char *saved_file;
} config_save;

static int did_fail;

#define fail(fmt, ...) \
do { \
	did_fail = 1; \
	fprintf(stderr, "accfg-%s:%s:%d: " fmt, \
			VERSION, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)

static struct json_object *group_to_json(struct accfg_group *group,
		uint64_t flags)
{
	struct json_object *jgroup = json_object_new_object();
	struct json_object *jobj = NULL;
	struct accfg_device *dev = NULL;

	dev = accfg_group_get_device(group);

	if (!jgroup)
		return NULL;

	jobj = json_object_new_string(accfg_group_get_devname(group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "dev", jobj);
	jobj = json_object_new_int(accfg_group_get_tokens_reserved(group));
	if (!jobj)
		goto err;

	if (accfg_device_get_type(dev) != ACCFG_DEVICE_IAX) {
		json_object_object_add(jgroup, "tokens_reserved", jobj);
		jobj = json_object_new_int(accfg_group_get_use_token_limit(group));
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "use_token_limit", jobj);
		jobj = json_object_new_int(accfg_group_get_tokens_allowed(group));
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "tokens_allowed", jobj);
		jobj = json_object_new_int(accfg_group_get_traffic_class_a(
				group));
		if (!jobj)
			goto err;
	}

	json_object_object_add(jgroup, "traffic_class_a", jobj);
	jobj = json_object_new_int(accfg_group_get_traffic_class_b(
				group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "traffic_class_b", jobj);
	return jgroup;

err:
	fail("\n");
	json_object_put(jgroup);
	return NULL;
}

static bool filter_wq(struct accfg_wq *wq, struct util_filter_ctx *ctx)
{
	unsigned int i;
	bool in_group = false;
	struct json_object *jwq;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	struct accfg_device *dev = accfg_wq_get_device(wq);
	unsigned int max_groups = accfg_device_get_max_groups(dev);
	struct accfg_json_container *jc = NULL, *iter;

	list_for_each(&lfa->jdev_list, iter, list) {
		if (match_device(dev, iter))
			jc = iter;
	}
	if (!jc)
		return false;

	if (!list.idle && !accfg_wq_is_enabled(wq))
		return true;

	jwq = util_wq_to_json(wq, lfa->flags);
	if (!jwq)
		return false;

	for (i = 0; i < max_groups; i ++) {
		/*
		 * Group array will be created only if group contains
		 * the wq.
		 */
		if (accfg_wq_get_group_id(wq) ==
				jc->jgroup_id[i]) {
			in_group = true;
			container = jc->jgroup_assigned[i];

			if (!jc->jwq_group[i]) {
				/* need to create wq array per group */
				jc->jwq_group[i] = json_object_new_array();
				if (!jc->jwq_group[i])
					return false;

				if (container)
					json_object_object_add(container,
							"grouped_workqueues",
							jc->jwq_group[i]);
			}

			json_object_array_add(jc->jwq_group[i], jwq);
		}
	}

	/* for the rest, add into device jobj directly */
	if (!in_group) {
		if (!jc->jwq_ungroup && (lfa->flags & UTIL_JSON_IDLE)) {
			jc->jwq_ungroup = json_object_new_array();
			if (!jc->jwq_ungroup)
				return false;

			container = lfa->jdevice;
			json_object_object_add(container, "ungrouped workqueues",
					       jc->jwq_ungroup);
		}

		json_object_array_add(jc->jwq_ungroup, jwq);
	}

	return true;
}

static bool filter_engine(struct accfg_engine *engine,
			  struct util_filter_ctx *ctx)
{
	unsigned int i;
	bool in_group = false;
	struct json_object *jengine;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	struct accfg_device *dev = accfg_engine_get_device(engine);
	unsigned int max_groups = accfg_device_get_max_groups(dev);
	struct accfg_json_container *jc = NULL, *iter;

	if (accfg_device_get_state(dev) != ACCFG_DEVICE_ENABLED &&
			!(lfa->flags & UTIL_JSON_IDLE))
		return false;

	list_for_each(&lfa->jdev_list, iter, list) {
		if (match_device(dev, iter))
			jc = iter;
	}
	if (!jc)
		return false;

	jengine = util_engine_to_json(engine, lfa->flags);
	if (!jengine)
		return false;

	for (i = 0; i < max_groups; i++) {
		/*
		 * group array will be created only if group contains
		 * the engine
		 */
		if (accfg_engine_get_group_id(engine) ==
				jc->jgroup_id[i]) {
			in_group = true;
			container = jc->jgroup_assigned[i];

			if (!jc->jengine_group[i]) {
				/* need to create engine array per group */
				jc->jengine_group[i] =
				    json_object_new_array();
				if (!jc->jengine_group[i])
					return false;

				if (container)
					json_object_object_add(container,
						"grouped_engines",
						jc->jengine_group[i]);
			}

			json_object_array_add(jc->jengine_group[i],
					jengine);
		}
	}

	/* for the rest, add into device directly */
	if (!in_group) {
		if (!jc->jengine_ungroup) {
			jc->jengine_ungroup = json_object_new_array();
			if (!jc->jengine_ungroup)
				return false;

			container = lfa->jdevice;
			json_object_object_add(container,
					       "ungrouped_engines",
					       jc->jengine_ungroup);
		}

		json_object_array_add(jc->jengine_ungroup, jengine);
	}

	return true;
}

static bool filter_group(struct accfg_group *group,
			 struct util_filter_ctx *ctx)
{
	uint64_t group_id;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *jgroup;
	struct json_object *container = lfa->jdevice;
	struct accfg_device *dev = accfg_group_get_device(group);
	unsigned int max_groups = accfg_device_get_max_groups(dev);
	struct accfg_json_container *jc = NULL, *iter;

	list_for_each(&lfa->jdev_list, iter, list) {
		if (match_device(dev, iter))
			jc = iter;
	}
	if (!jc)
		return false;

	if (!jc->jgroups) {
		jc->jgroups = json_object_new_array();
		if (!jc->jgroups)
			return false;

		if (container)
			json_object_object_add(container, "groups",
					       jc->jgroups);
	}

	jgroup = group_to_json(group, lfa->flags);
	if (!jgroup) {
		fail("\n");
		return false;
	}

	jc->jgroup = jgroup;
	group_id = accfg_group_get_id(group);
	jc->jgroup_id[lfa->group_num % max_groups] = group_id;
	jc->jgroup_assigned[lfa->group_num % max_groups] = jgroup;
	lfa->group_num++;

	json_object_array_add(jc->jgroups, jgroup);

	return true;
}

static bool filter_device(struct accfg_device *device,
			  struct util_filter_ctx *ctx)
{
	struct list_filter_arg *lfa = ctx->list;
	struct accfg_json_container *jc;
	unsigned int max_groups;

	max_groups = accfg_device_get_max_groups(device);

	lfa->jdevice = util_device_to_json(device, lfa->flags);
	if (!lfa->jdevice)
		return false;

	jc = malloc(sizeof(struct accfg_json_container));
	if (!jc)
		return false;

       jc->jgroup_assigned = calloc(max_groups, sizeof(struct json_object *));
       if (!jc->jgroup_assigned)
               goto err_jc;

	jc->jwq_group = calloc(max_groups, sizeof(struct json_object *));
	if (!jc->jwq_group)
		goto err_jc;

	jc->jengine_group = calloc(max_groups, sizeof(struct json_object *));
	if (!jc->jengine_group)
		goto err_jc;

	jc->jgroup_id = calloc(max_groups, sizeof(int));
	if (!jc->jgroup_id)
		goto err_jc;

	jc->device_id = accfg_device_get_id(device);
	jc->device_name = accfg_device_get_devname(device);
	list_add(&lfa->jdev_list, &jc->list);

	/* a fresh container will be null */
	jc->jgroups = NULL;
	jc->jwq_ungroup = NULL;
	jc->jengine_ungroup = NULL;

	json_object_array_add(lfa->jdevices, lfa->jdevice);
	lfa->dev_num++;

	return true;
err_jc:
	free(jc);
	return false;
}

static void free_containers(struct list_filter_arg *lfa)
{
	struct accfg_json_container *jc, *next;

	list_for_each_safe(&lfa->jdev_list, jc, next, list) {
		if (!jc)
			break;
		if (jc->jgroup_assigned)
			free(jc->jgroup_assigned);
		if (jc->jwq_group)
			free(jc->jwq_group);
		if (jc->jengine_group)
			free(jc->jengine_group);
		if (jc->jgroup_id)
			free(jc->jgroup_id);
		free(jc);
	}
}

static int save_config(struct list_filter_arg *lfa, const char* saved_file)
{
	struct json_object *jdevices = lfa->jdevices;
	FILE *fd = fopen(saved_file, "w");

	if (!fd) {
		fprintf(stderr, "Failed to open %s for save: %s\n",
				saved_file, strerror(errno));
		return false;
	}

	if (jdevices)
		__util_display_json_array(fd, jdevices, lfa->flags);

	/* free all the allocated container data structure */
	free_containers(lfa);
	fclose(fd);

	return 0;
}

static int display_device(struct json_object *jdevices,
		struct list_filter_arg *lfa)
{
	int jflag = JSON_C_TO_STRING_PRETTY;
	char **accel_type;
	int device_id;
	struct json_object *jdevice;
	char dev_type[MAX_DEV_LEN];

	printf("%s\n", "devices:");

	if (jdevices && (!util_param.device))
		util_display_json_array(stdout, jdevices, lfa->flags);

	if (!util_param.device)
		return true;

	if (sscanf(util_param.device, "%[a-z]%d", dev_type, &device_id) != 2)
		return false;

	for (accel_type = accfg_basenames; *accel_type != NULL; accel_type++)
		if (!strcmp(dev_type, *accel_type))
			break;

	if (*accel_type == NULL) {
		fprintf(stderr, "device type not matched\n");
		return false;
	}

	if (device_id > lfa->dev_num) {
		fprintf(stderr, "device_id out of range\n");
		return false;
	}

	jdevice = json_object_array_get_idx(jdevices, 0);
	printf("%s\n", json_object_to_json_string_ext(jdevice, jflag));

	return true;
}

static int display_group(struct list_filter_arg *lfa, struct accfg_ctx *ctx)
{
	struct accfg_json_container *iter;
	int device_id;
	unsigned int group_id, max_groups;
	struct json_object *jgroups;
	struct accfg_device *dev;
	struct accfg_json_container *jc = NULL;

	printf("%s\n", "groups:");

	if (!util_param.group) {
		list_for_each(&lfa->jdev_list, iter, list)
			util_display_json_array(stdout, iter->jgroups,
					lfa->flags);
		return true;

	}

	if (sscanf(util_param.group, "group%d.%d", &device_id, &group_id) != 2)
		return false;

	accfg_device_foreach(ctx, dev) {
		if (accfg_device_get_id(dev) != device_id)
			break;

		max_groups = accfg_device_get_max_groups(dev);
		if (device_id > lfa->dev_num || group_id > max_groups) {
			fprintf(stderr,
				"device_id or group_id out of range\n");
			return false;
		}

		list_for_each(&lfa->jdev_list, iter, list) {
			if (!match_device(dev, iter))
				continue;
			jc = iter;
			if (!jc)
				return false;
			printf("device %s:\n", iter->device_name);
			jgroups = jc->jgroups;
			if (jgroups)
				util_display_json_array(stdout, jgroups,
						lfa->flags);
		}
	}

	return true;
}

static int display_wq(struct list_filter_arg *lfa, struct accfg_ctx *ctx)
{
	int device_id;
	unsigned int wq_id, max_wqs, max_groups, i = 0, index = 0;
	struct accfg_device *dev;
	struct accfg_json_container *jc = NULL, *iter;

	printf("%s\n", "workqueues:");

	if (!util_param.wq) {
		list_for_each(&lfa->jdev_list, iter, list) {
			dev = accfg_ctx_device_get_by_id(ctx, i);
			max_groups = accfg_device_get_max_groups(dev);

			printf("device %s:\n", iter->device_name);
			for (index = 0; index < max_groups; index++) {
				if (iter->jwq_group[index] != NULL)
					util_display_json_array(stdout,
						iter->jwq_group[index],
						lfa->flags);
			}

		}
		return true;
	}

	if (sscanf(util_param.wq, "wq%d.%d", &device_id, &wq_id) != 2)
		return false;

	accfg_device_foreach(ctx, dev) {
		if (accfg_device_get_id(dev) == device_id) {
			max_groups = accfg_device_get_max_groups(dev);
			max_wqs = accfg_device_get_max_work_queues(dev);

			if (device_id > lfa->dev_num || wq_id > max_wqs) {
				fprintf(stderr,
					"device_id or wq_id out of range\n");
				return false;
			}

			list_for_each(&lfa->jdev_list, iter, list)
				if (match_device(dev, iter))
					jc = iter;
			if (!jc)
				return false;

			printf("device %s:\n", jc->device_name);
			for (index = 0; index < max_groups; index++) {
				struct json_object *jwq_group[max_groups];

				if (wq_id != index || (lfa->flags & UTIL_JSON_IDLE))
					continue;
				jwq_group[index] = jc->jwq_group[index];
				if (jwq_group[index] != NULL) {
					util_display_json_array(stdout,
							jwq_group[index],
							lfa->flags);
				}
			}
		}
	}

	return true;
}

static int display_engine(struct list_filter_arg *lfa, struct accfg_ctx *ctx)
{
	int device_id;
	unsigned int engine_id, max_groups, max_engines,
		     i = 0, index = 0;
	struct accfg_json_container *jc = NULL, *iter;
	struct accfg_device *dev;

	printf("%s\n", "engines:");

	if (!util_param.engine) {
		list_for_each(&lfa->jdev_list, iter, list) {
			dev = accfg_ctx_device_get_by_id(ctx, i);
			max_groups = accfg_device_get_max_groups(dev);

			printf("device %s:\n", iter->device_name);
			for (index = 0; index < max_groups; index++) {
				if (iter->jengine_group[index] != NULL)
					util_display_json_array(stdout,
						iter->jengine_group[index],
						lfa->flags);
			}

		}
		return true;
	}

	if  (sscanf(util_param.engine, "engine%d.%d", &device_id, &engine_id) != 2)
		return false;

	accfg_device_foreach(ctx, dev) {
		if (accfg_device_get_id(dev) == device_id) {
			max_groups = accfg_device_get_max_groups(dev);
			max_engines = accfg_device_get_max_engines(dev);

			if (device_id > lfa->dev_num
					|| engine_id > max_engines) {
				fprintf(stderr,
					"dev id or engine id out of range\n");
				return false;
			}

			list_for_each(&lfa->jdev_list, iter, list)
				if (match_device(dev, iter))
					jc = iter;
			if (!jc)
				return false;

			printf("device %s:\n", jc->device_name);
			for (index = 0; index < max_groups; index++) {
				struct json_object *jengine_group[max_groups];

				if (lfa->flags & UTIL_JSON_IDLE)
					continue;
				jengine_group[index] =
					jc->jengine_group[index];
				if (jengine_group[index]) {
					util_display_json_array(stdout,
							jengine_group[index],
							lfa->flags);
				}
			}
		}
	}

	return true;
}

static int list_display(struct list_filter_arg *lfa, struct accfg_ctx *ctx)
{
	struct json_object *jdevices = lfa->jdevices;

	if (!list.devices && !list.groups && !list.wqs && !list.engines) {
		if (jdevices)
			util_display_json_array(stdout, jdevices, lfa->flags);
	} else if (list.devices) {
		return display_device(jdevices, lfa);
	} else if (list.groups) {
		return display_group(lfa, ctx);
	} else if (list.wqs) {
		return display_wq(lfa, ctx);
	} else if (list.engines) {
		return display_engine(lfa, ctx);
	}

	/* free all the allocated container data structure */
	free_containers(lfa);

	return 0;
}

static int num_list_flags(void)
{
	return list.devices + list.groups + list.wqs + list.engines;
}

int cmd_list(int argc, const char **argv, void *ctx)
{
	const struct option options[] = {
		OPT_STRING('d', "device", &util_param.device, "device-id",
			   "filter by device"),
		OPT_STRING('g', "group", &util_param.group, "group-id",
			   "filter by group"),
		OPT_STRING('q', "workqueue", &util_param.wq, "wq-id",
			   "filter by workqueue"),
		OPT_STRING('e', "engine", &util_param.engine, "engine-id",
			   "filter by engine"),
		OPT_BOOLEAN('G', "groups", &list.groups,
				"include group info"),
		OPT_BOOLEAN('D', "devices", &list.devices,
			    "include device info"),
		OPT_BOOLEAN('E', "engines", &list.engines,
			    "include engine info"),
		OPT_BOOLEAN('Q', "workqueues", &list.wqs,
			    "include workqueue info"),
		OPT_BOOLEAN('i', "idle", &list.idle,
				"include idle components"),
		OPT_END(),
	};
	const char *const u[] = {
		"accel-config list [<options>]",
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
		list.devices = !!util_param.device;
		list.groups = !!util_param.group;
		list.wqs = !!util_param.wq;
		list.engines = !!util_param.engine;
	}

	lfa.jdevices = json_object_new_array();
	if (!lfa.jdevices)
		return -ENOMEM;
	list_head_init(&lfa.jdev_list);

	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &lfa;
	lfa.flags = listopts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &util_param);
	if (rc)
		return rc;

	if (list_display(&lfa, ctx) || did_fail)
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
		"accel-config save-config [<options>]",
		NULL
	};
	struct util_filter_ctx fctx = { 0 };
	struct list_filter_arg lfa = { 0 };
	int i, rc;
	char *config_file;

	argc = parse_options(argc, argv, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);

	lfa.jdevices = json_object_new_array();
	if (!lfa.jdevices)
		return -ENOMEM;
	list_head_init(&lfa.jdev_list);

	list.save_conf = true;
	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &lfa;
	lfa.flags = listopts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &util_param);
	if (rc)
		return rc;

	if (config_save.saved_file)
		config_file = strdup(config_save.saved_file);
	else
		config_file = strdup(ACCFG_CONF_FILE);
	if (!config_file) {
		fprintf(stderr, "strdup failed\n");
		return -ENOMEM;
	}

	rc = save_config(&lfa, config_file);
	free(config_file);
	if (rc < 0)
		return rc;
	return 0;
}
