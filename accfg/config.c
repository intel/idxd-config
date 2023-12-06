/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
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

static bool verbose;
static bool enable;
static bool forced;
static struct util_filter_params util_param;
static bool warn_once = true;

static LIST_HEAD(activate_dev_list);
static LIST_HEAD(activate_wq_list);
struct activate_dev {
	void *dev;
	struct list_node list;
};

static struct config {
	bool devices;
	bool groups;
	bool engines;
	bool wqs;
	const char *config_file;
	const char *user_default_wq_name;
	char *buf;
} config;

static uint64_t config_opts_to_flags(void)
{
	uint64_t flags = 0;
	return flags;
}

struct device_set_table {
	char *name;
	int (*set_int_func)(struct accfg_device *device, int val);
	int (*set_str_func)(struct accfg_device *device, const char *val);
};

struct wq_set_table {
	char *name;
	int (*set_int_func)(struct accfg_wq *wq, int val);
	int (*set_long_func)(struct accfg_wq *wq, uint64_t val);
	int (*set_str_func)(struct accfg_wq *wq, const char *val);
	bool (*is_writable)(struct accfg_wq *wq, int val);
};

struct group_set_table {
	char *name;
	int (*set_int_func)(struct accfg_group *group, int val);
	int (*set_str_func)(struct accfg_group *group, const char *val);
	bool (*is_writable)(struct accfg_group *group, int val);
};

struct engine_set_table {
	char *name;
	int (*set_int_func)(struct accfg_engine *engine, int val);
	int (*set_str_func)(struct accfg_engine *engine, const char *val);
};

static const struct device_set_table device_table[] = {
	{ "token_limit", accfg_device_set_read_buffer_limit, NULL },
	{ "read_buffer_limit", accfg_device_set_read_buffer_limit, NULL },
	{ "event_log_size", accfg_device_set_event_log_size, NULL },
};

static bool is_group_traffic_class_writable(struct accfg_group *group,
		int val);
static bool is_group_read_buffer_attribs_writable(struct accfg_group *group,
		int val);
static bool is_group_read_buffer_limit_writable(struct accfg_group *group,
		int val);
static bool is_group_desc_progress_limit_writable(struct accfg_group *group,
		int val);
static bool is_group_batch_progress_limit_writable(struct accfg_group *group,
		int val);

static const struct group_set_table group_table[] = {
	{ "tokens_reserved", accfg_group_set_read_buffers_reserved, NULL,
		is_group_read_buffer_attribs_writable },
	{ "read_buffers_reserved", accfg_group_set_read_buffers_reserved, NULL,
		is_group_read_buffer_attribs_writable },
	{ "use_token_limit", accfg_group_set_use_read_buffer_limit, NULL,
		is_group_read_buffer_limit_writable },
	{ "use_read_buffer_limit", accfg_group_set_use_read_buffer_limit, NULL,
		is_group_read_buffer_limit_writable },
	{ "tokens_allowed", accfg_group_set_read_buffers_allowed, NULL,
		is_group_read_buffer_attribs_writable },
	{ "read_buffers_allowed", accfg_group_set_read_buffers_allowed, NULL,
		is_group_read_buffer_attribs_writable },
	{ "traffic_class_a", accfg_group_set_traffic_class_a, NULL,
		is_group_traffic_class_writable},
	{ "traffic_class_b", accfg_group_set_traffic_class_b, NULL,
		is_group_traffic_class_writable},
	{ "desc_progress_limit", accfg_group_set_desc_progress_limit, NULL,
		is_group_desc_progress_limit_writable },
	{ "batch_progress_limit", accfg_group_set_batch_progress_limit, NULL,
		is_group_batch_progress_limit_writable },
};

static bool is_wq_threshold_writable(struct accfg_wq *wq, int val);
static bool is_wq_prs_disable_writable(struct accfg_wq *wq, int val);
static bool is_wq_ats_disable_writable(struct accfg_wq *wq, int val);

static int get_wq_size(struct accfg_device *dev)
{
	int max_wq_size, max_wqs;

	max_wq_size = accfg_device_get_max_work_queues_size(dev);
	max_wqs = accfg_device_get_max_work_queues(dev);

	return max_wq_size / max_wqs;
}

static int config_default_wq_set_prs_disable(struct accfg_wq *wq, int val)
{
	if (!is_wq_prs_disable_writable(wq, val))
		return -EPERM;

	return accfg_wq_set_prs_disable(wq, val);
}

static int config_default_wq_set_ats_disable(struct accfg_wq *wq, int val)
{
	if (!is_wq_ats_disable_writable(wq, val))
		return -EPERM;

	return accfg_wq_set_ats_disable(wq, val);
}

static int config_default_wq_set_threshold(struct accfg_wq *wq, int val)
{
	if (!is_wq_threshold_writable(wq, val))
		return -EPERM;

	return accfg_wq_set_threshold(wq, val);
}

static struct conf_def_wq_param {
	struct wq_parameters param;
	bool configured;
} conf_def_wq_param[ACCFG_DEVICE_MAX];

static bool config_default_file;

/* Return WQ parameter for dev type. */
static struct wq_parameters *get_conf_def_wq_param(enum accfg_device_type type)
{
	if (type == ACCFG_DEVICE_DSA)
		return &conf_def_wq_param[ACCFG_DEVICE_DSA].param;
	else if (type == ACCFG_DEVICE_IAX)
		return &conf_def_wq_param[ACCFG_DEVICE_IAX].param;

	return NULL;
}

/* Check if dev is configured. */
static bool conf_def_dev_configured(struct accfg_device *dev)
{
	if (accfg_device_get_type(dev) == ACCFG_DEVICE_DSA)
		return conf_def_wq_param[ACCFG_DEVICE_DSA].configured;
	else if (accfg_device_get_type(dev) == ACCFG_DEVICE_IAX)
		return conf_def_wq_param[ACCFG_DEVICE_IAX].configured;

	return false;
}

/* Set WQ parameters based on device cap: size and threshold. */
static int config_default_wq_set_on_dev(struct accfg_device *dev)
{
	enum accfg_device_type dev_type;
	struct wq_parameters *p;

	dev_type = accfg_device_get_type(dev);
	p = get_conf_def_wq_param(dev_type);
	if (!p)
		return -EINVAL;

	p->wq_size = get_wq_size(dev);
	if (p->wq_size <= 0)
		return -ENOSPC;

	p->threshold = p->wq_size;

	return 0;
}

static const struct wq_set_table wq_table[] = {
	{ "size", accfg_wq_set_size, NULL, NULL, NULL },
	{ "priority", accfg_wq_set_priority, NULL, NULL, NULL },
	{ "group_id", accfg_wq_set_group_id, NULL, NULL, NULL },
	{ "block_on_fault", accfg_wq_set_block_on_fault, NULL, NULL, NULL },
	{ "type", NULL, NULL, accfg_wq_set_str_type, NULL },
	{ "name", NULL, NULL, accfg_wq_set_str_name, NULL },
	{ "driver_name", NULL, NULL, accfg_wq_set_str_driver_name, NULL },
	{ "op_config", NULL, NULL, accfg_wq_set_op_config_str, NULL },
	{ "mode", NULL, NULL, accfg_wq_set_str_mode, NULL },
	{ "max_batch_size", accfg_wq_set_max_batch_size, NULL, NULL, NULL },
	{ "max_transfer_size", NULL, accfg_wq_set_max_transfer_size, NULL, NULL },
	{ "threshold", accfg_wq_set_threshold, NULL, NULL,
		is_wq_threshold_writable },
	{ "ats_disable", accfg_wq_set_ats_disable, NULL, NULL,
		is_wq_ats_disable_writable },
	{ "prs_disable", accfg_wq_set_prs_disable, NULL, NULL,
		is_wq_prs_disable_writable },
};

static const struct engine_set_table engine_table[] = {
	{ "group_id", accfg_engine_set_group_id, NULL }
};

static int json_parse_array(struct accfg_ctx *ctx,
				json_object *jobj, char *key);
static int json_parse(struct accfg_ctx *ctx, json_object *jobj);
static int configure_json_value(struct accfg_ctx *ctx,
				json_object *jobj, char *key);
static int read_config_file(struct accfg_ctx *ctx, struct config *to_config,
			    struct util_filter_params *util_param);

static bool is_group_read_buffer_limit_writable(struct accfg_group *group,
		int val)
{
	struct accfg_device *dev;
	unsigned int read_buffer_limit;

	dev = accfg_group_get_device(group);
	read_buffer_limit = accfg_device_get_read_buffer_limit(dev);
	if (read_buffer_limit)
		return true;

	return false;
}


static bool is_group_read_buffer_attribs_writable(struct accfg_group *group,
		int val)
{
	if (val == -1)
		return false;

	return true;
}

static bool is_group_desc_progress_limit_writable(struct accfg_group *group,
		int val)
{
	if (val < 0 || val > 3)
		return false;

	if (accfg_group_get_desc_progress_limit(group) < 0)
		return false;

	return true;
}

static bool is_group_batch_progress_limit_writable(struct accfg_group *group,
		int val)
{
	if (val < 0 || val > 3)
		return false;

	if (accfg_group_get_batch_progress_limit(group) < 0)
		return false;

	return true;
}

static bool is_group_traffic_class_writable(struct accfg_group *group,
		int val)
{
	struct accfg_device *device;

	device = accfg_group_get_device(group);
	if (accfg_device_get_version(device) < ACCFG_DEVICE_VERSION_2)
		return false;

	if (val == -1)
		return false;

	return true;
}

static bool is_wq_threshold_writable(struct accfg_wq *wq, int val)
{
	if (accfg_wq_get_mode(wq) == ACCFG_WQ_DEDICATED)
		return false;

	return true;
}

static bool is_wq_prs_disable_writable(struct accfg_wq *wq, int val)
{
	if (val < 0 || val > 1)
		return false;

	if (accfg_wq_get_prs_disable(wq) < 0)
		return false;

	return true;
}

static bool is_wq_ats_disable_writable(struct accfg_wq *wq, int val)
{
	if (val < 0 || val > 1)
		return false;

	if (accfg_wq_get_ats_disable(wq) < 0)
		return false;

	return true;
}

static int device_attribute_filter(char *key)
{
	for (int i = 0; i < (int)ARRAY_SIZE(device_table); i++) {
		if (strcmp(key, device_table[i].name) == 0)
			return 1;
	}

	return 0;
}

static int group_attribute_filter(char *key)
{
	for (int i = 0; i < (int)ARRAY_SIZE(group_table); i++) {
		if (strcmp(key, group_table[i].name) == 0)
			return 1;
	}

	return 0;
}


static int wq_attribute_filter(char *key)
{
	for (int i = 0; i < (int)ARRAY_SIZE(wq_table); i++) {
		if (strcmp(key, wq_table[i].name) == 0)
			return 1;
	}

	return 0;
}

static int engine_attribute_filter(char *key)
{
	for (int i = 0; i < (int)ARRAY_SIZE(engine_table); i++) {
		if (strcmp(key, engine_table[i].name) == 0)
			return 1;
	}

	return 0;
}

static int device_json_set_val(struct accfg_device *dev, json_object *jobj,
		char *key)
{
	int rc, i;

	if (!dev || !jobj || !key)
		return -EINVAL;

	if (!device_attribute_filter(key))
		return 0;

	for (i = 0; i < (int)ARRAY_SIZE(device_table); i++) {
		if (strcmp(key, device_table[i].name) == 0) {
			if (device_table[i].set_int_func) {
				int val;

				errno = 0;
				val = json_object_get_int(jobj);

				if (val == 0 && errno == EINVAL)
					return -EINVAL;

				rc = device_table[i].set_int_func(dev, val);
				if (rc != 0)
					return rc;

				return 0;
			} else if (device_table[i].set_str_func) {
				const char *val =
					json_object_get_string(jobj);

				if (!val)
					return -EINVAL;

				rc = device_table[i].set_str_func(dev, val);
				if (rc != 0)
					return rc;

				return 0;
			}
		}
	}

	return -ENOENT;
}

static int wq_json_set_val(struct accfg_wq *wq, json_object *jobj, char *key)
{
	int rc, i;

	if (!wq || !jobj || !key)
		return -EINVAL;

	if (!wq_attribute_filter(key))
		return 0;

	for (i = 0; i < (int)ARRAY_SIZE(wq_table); i++) {
		if (strcmp(key, wq_table[i].name) == 0) {
			if (wq_table[i].set_int_func) {
				int val;

				errno = 0;
				val = json_object_get_int(jobj);

				if ((val == 0) && (errno == EINVAL))
					return -errno;

				if (wq_table[i].is_writable &&
					!wq_table[i].is_writable(wq, val))
					return 0;

				rc = wq_table[i].set_int_func(wq, val);
				if (rc != 0)
					return rc;

				return 0;
			} else if (wq_table[i].set_long_func) {
				uint64_t val;

				errno = 0;
				val = json_object_get_int64(jobj);

				if ((val == 0) && (errno == EINVAL))
					return -errno;

				if (wq_table[i].is_writable &&
					!wq_table[i].is_writable(wq, val))
					return 0;

				rc = wq_table[i].set_long_func(wq, val);
				if (rc != 0)
					return rc;

				return 0;
			} else if (wq_table[i].set_str_func) {
				const char *val =
					json_object_get_string(jobj);

				if (!val)
					return -EINVAL;

				rc = wq_table[i].set_str_func(wq, val);
				if (rc != 0)
					return rc;

				return 0;
			}
		}
	}

	return -ENOENT;
}

static int group_json_set_val(struct accfg_group *group,
		json_object *jobj, char *key)
{
	int rc, i;
	struct accfg_device *dev = NULL;

	if (group)
		dev = accfg_group_get_device(group);

	if (!group || !jobj || !key)
		return -EINVAL;

	if (!group_attribute_filter(key))
		return 0;

	for (i = 0; i < (int)ARRAY_SIZE(group_table); i++) {
		if (strcmp(key, group_table[i].name) == 0) {
			if (group_table[i].set_int_func) {
				int val;

				errno = 0;
				val = json_object_get_int(jobj);
				if (((val == 0) && (errno == EINVAL))
						|| (val < 0))
					return -EINVAL;

				if ((accfg_device_get_type(dev) == ACCFG_DEVICE_IAX)
						&& ((!strcmp(group_table[i].name,
								"tokens_reserved"))
						|| (!strcmp(group_table[i].name,
								"use_token_limit"))
						|| (!strcmp(group_table[i].name,
								"tokens_allowed"))
						|| (!strcmp(group_table[i].name,
								"read_buffers_reserved"))
						|| (!strcmp(group_table[i].name,
								"use_read_buffer_limit"))
						|| (!strcmp(group_table[i].name,
								"read_buffers_allowed"))))
					return 0;

				if (group_table[i].is_writable &&
					!group_table[i].is_writable(group,
						val))
					return 0;
				rc = group_table[i].set_int_func(group, val);
				if (rc != 0)
					return rc;

				return 0;
			} else if (group_table[i].set_str_func) {
				const char *val =
					json_object_get_string(jobj);

				if (!val)
					return -EINVAL;

				rc = group_table[i].set_str_func(group, val);
				if (rc != 0)
					return rc;

				return 0;
			}
		}
	}

	return -ENOENT;
}

static int engine_json_set_val(struct accfg_engine *engine,
		json_object *jobj, char *key)
{
	int rc, i;

	if (!engine || !jobj || !key)
		return -EINVAL;

	if (!engine_attribute_filter(key))
		return 0;

	for (i = 0; i < (int)ARRAY_SIZE(engine_table); i++) {
		if (!engine_table[i].name)
			return -EINVAL;

		if (strcmp(key, engine_table[i].name) == 0) {
			if (engine_table[i].set_int_func) {
				int val;

				errno = 0;
				val = json_object_get_int(jobj);

				if ((val == 0) && (errno == EINVAL))
					return -EINVAL;

				rc = engine_table[i].set_int_func(engine,
						val);
				if (rc != 0)
					return rc;

				return 0;
			}

			if (engine_table[i].set_str_func) {
				const char *val =
					json_object_get_string(jobj);
				if (!val)
					return -EINVAL;

				rc = engine_table[i].set_str_func(engine,
						val);
				if (rc != 0)
					return rc;

				return 0;
			}

		}
	}

	return -ENOENT;
}

/*
 * Add configured devices and wqs to activation list
 */
static int add_to_activation_list(struct list_head *activate_list, void *dev)
{
	struct activate_dev *act_dev;

	act_dev = calloc(1, sizeof(struct activate_dev));
	if (!act_dev) {
		fprintf(stderr, "Error allocating memory for activation list\n");
		return -ENOMEM;
	}
	act_dev->dev = dev;
	list_add(activate_list, &act_dev->list);

	return 0;
}

/*
 * Enable devices in activation list
 */
static int activate_devices(void)
{
	struct activate_dev *iter, *next;
	int rc;

	list_for_each_safe(&activate_dev_list, iter, next, list) {
		printf("Enabling device %s\n",
				accfg_device_get_devname(iter->dev));
		rc = accfg_device_enable(iter->dev);
		if (rc) {
			fprintf(stderr, "Error enabling device\n");
			return rc;
		}

		free(iter);
	}

	list_for_each_safe(&activate_wq_list, iter, next, list) {
		printf("Enabling wq %s\n", accfg_wq_get_devname(iter->dev));
		rc = accfg_wq_enable(iter->dev);
		if (rc) {
			fprintf(stderr, "Error enabling wq\n");
			return rc;
		}
		free(iter);
	}

	return 0;
}

static void config_default_json(struct accfg_wq *wq,
				json_object *jobj, char *key)
{
	enum accfg_device_type dev_type;
	struct accfg_device *dev;
	struct wq_parameters *p;
	char *dev_type_str;

	dev = accfg_wq_get_device(wq);
	dev_type = accfg_device_get_type(dev);
	dev_type_str = accfg_device_get_type_str(dev);
	p = get_conf_def_wq_param(dev_type);
	if (!p) {
		fprintf(stderr, "parsing dev type %s failed\n", dev_type_str);

		return;
	}

	printf("dev type = %s, key = %s\n", dev_type_str, key);
	if (!strcmp(key, "name"))
		p->name = strdup(json_object_get_string(jobj));
	else if (!strcmp(key, "priority"))
		p->priority = json_object_get_int(jobj);
	else if (!strcmp(key, "group_id"))
		p->group_id = json_object_get_int(jobj);
	else if (!strcmp(key, "block_on_fault"))
		p->block_on_fault = json_object_get_int(jobj);
	else if (!strcmp(key, "ats_disable"))
		p->ats_disable = json_object_get_int(jobj);
	else if (!strcmp(key, "prs_disable"))
		p->prs_disable = json_object_get_int(jobj);
}

/*
 * Configuring the value corresponding to integer and strings
 */
static int configure_json_value(struct accfg_ctx *ctx,
		json_object *jobj, char *key)
{
	int dev_id, id, rc, i = 0;
	char *parsed_string;
	char dev_type[MAX_DEV_LEN];
	char *accel_type = NULL;
	static struct accfg_device *dev, *parent;
	static struct accfg_wq *wq;
	static struct accfg_engine *engine;
	static struct accfg_group *group;
	enum accfg_device_state dev_state = ACCFG_DEVICE_DISABLED;
	enum accfg_wq_state wq_state = ACCFG_WQ_DISABLED;

	if (!ctx || !jobj || !key)
		return -EINVAL;

	if (strcmp(key, "dev") == 0) {
		parsed_string = (char *)json_object_get_string(jobj);
		if (!parsed_string)
			return -EINVAL;
		dev = NULL;
		group = NULL;
		wq = NULL;
		engine = NULL;
		for (accel_type = accfg_basenames[0]; accel_type != NULL; i++) {
			memset(dev_type, 0, MAX_DEV_LEN);
			if (strstr(parsed_string, accel_type) != NULL) {
				if(strlen(accel_type) > MAX_DEV_LEN)
					return -EINVAL;
				strcpy(dev_type, accel_type);
				rc = sscanf(&parsed_string[strlen(dev_type)],
							"%d", &dev_id);
				if (rc != 1)
					return -EINVAL;
			}

			if (!strcmp(dev_type, accel_type)) {
				parent = NULL;
				dev = accfg_ctx_device_get_by_name(ctx,
						parsed_string);
				if (!dev) {
					fprintf(stderr, "device is not available\n");
					return -ENOENT;
				}
				dev_state = accfg_device_get_state(dev);
				if (dev_state == ACCFG_DEVICE_ENABLED) {
					fprintf(stderr, "%s is active. ",
							parsed_string);
					if (forced) {
						fprintf(stderr, "Disabling...\n");
						rc = accfg_device_disable(dev, true);
						if (rc) {
							fprintf(stderr,
								"Failed disabling device\n");
							return rc;
						}
					} else {
						fprintf(stderr, "Skipping...\n");
						dev = NULL;
						return 0;
					}
				}

				if (enable) {
					rc = add_to_activation_list(&activate_dev_list, dev);
					if (rc)
						return rc;
				}

				parent = dev;

				break;
			}
			accel_type = accfg_basenames[i];
		}

		/* Skip if device configuration was skipped */
		if (!parent)
			return 0;

		if (strstr(parsed_string, "wq") != NULL) {
			rc = sscanf(&parsed_string[strlen("wq")], "%d.%d",
					&dev_id, &id);
			if (rc != 2)
				return -EINVAL;

			wq = accfg_device_wq_get_by_id(parent, id);
			if (!wq)
				return -ENOENT;
			wq_state = accfg_wq_get_state(wq);
			if (wq_state == ACCFG_WQ_ENABLED || wq_state == ACCFG_WQ_LOCKED) {
				fprintf(stderr, "%s is active, will skip...\n", parsed_string);
				wq = NULL;
				return 0;
			}

			if (enable) {
				rc = add_to_activation_list(&activate_wq_list, wq);
				if (rc)
					return rc;
			}
		}

		if (strstr(parsed_string, "engine") != NULL) {
			rc = sscanf(&parsed_string[strlen("engine")], "%d.%d",
					&dev_id, &id);
			if (rc != 2)
				return -EINVAL;

			engine = accfg_device_engine_get_by_id(parent, id);
			if (!engine)
				return -ENOENT;

		}

		if (strstr(parsed_string, "group") != NULL) {
			rc = sscanf(&parsed_string[strlen("group")], "%d.%d",
					&dev_id, &id);
			if (rc != 2)
				return -EINVAL;

			group = accfg_device_group_get_by_id(parent, id);
			if (!group)
				return -ENOENT;
		}

		return 0;
	}

	/* Skip if device configuration was skipped */
	if (!parent)
		return 0;

	if (warn_once && strstr(key, "token")) {
		fprintf(stderr, "Warning: \"token\" attributes are deprecated\n");
		warn_once = false;
	}

	if (wq && config_default_file) {
		config_default_json(wq, jobj, key);

		return 0;
	}

	if (dev && dev_state != ACCFG_DEVICE_ENABLED) {
		rc = device_json_set_val(dev, jobj, key);
		if (rc < 0) {
			fprintf(stderr, "device set %s value failed\n",
					key);
			return rc;
		}
	} else if (group) {
		rc = group_json_set_val(group, jobj, key);
		if (rc < 0) {
			fprintf(stderr, "group set %s value failed\n",
					key);
			return rc;
		}
	} else if (wq && wq_state != ACCFG_WQ_ENABLED &&
			wq_state != ACCFG_WQ_LOCKED) {
		rc = wq_json_set_val(wq, jobj, key);
		if (rc < 0) {
			fprintf(stderr, "wq set %s value failed\n",
					key);
			return rc;
		}
	} else if (engine) {
		rc = engine_json_set_val(engine, jobj, key);
		if (rc < 0) {
			fprintf(stderr, "engine set %s value failed\n",
					key);
			return rc;
		}
	} else {
		fprintf(stderr, "device type not matched\n");
		return -EINVAL;
	}

	return 0;
}

static struct json_object *config_group_to_json(struct accfg_group *group,
						uint64_t flags)
{
	struct json_object *jgroup = json_object_new_object();
	struct json_object *jobj = NULL;
	int dpl, gpl;

	if (!jgroup)
		return NULL;

	jobj = json_object_new_string(accfg_group_get_devname(group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "dev", jobj);
	jobj = json_object_new_int(accfg_group_get_read_buffers_reserved(group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "read_buffers_reserved", jobj);
	jobj = json_object_new_int(accfg_group_get_use_read_buffer_limit(group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "use_read_buffer_limit", jobj);
	jobj = json_object_new_int(accfg_group_get_read_buffers_allowed(group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "read_buffers_allowed", jobj);
	jobj = json_object_new_int(accfg_group_get_traffic_class_a(
				group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "traffic_class_a", jobj);
	jobj = json_object_new_int(accfg_group_get_traffic_class_b(
				group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "traffic_class_b", jobj);

	dpl = accfg_group_get_desc_progress_limit(group);
	if (dpl >= 0) {
		jobj = json_object_new_int(dpl);
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "desc_progress_limit", jobj);
	}

	gpl = accfg_group_get_batch_progress_limit(group);
	if (gpl >= 0) {
		jobj = json_object_new_int(gpl);
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "batch_progress_limit", jobj);
	}

	return jgroup;

err:
	json_object_put(jgroup);
	return NULL;
}

/* Parsing the json object */
static int json_parse(struct accfg_ctx *ctx, json_object *jobj)
{
	enum json_type type;
	json_object_iter iter;
	char *key;

	/* parse through every array element */
	json_object_object_foreachC(jobj, iter) {
		type = json_object_get_type(iter.val);
		key = iter.key;
		switch (type) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			if (configure_json_value(ctx, iter.val, key) != 0)
				return -1;
			break;
		case json_type_object:
			if (!json_object_object_get_ex(jobj, iter.key, &jobj))
				return -1;
			json_parse(ctx, jobj);
			break;
		case json_type_array:
			if (json_parse_array(ctx, jobj, iter.key) != 0)
				return -1;
			break;
		case json_type_null:
			break;
		default:
			return -1;
		}
	}

	return 0;
}

static int json_parse_array(struct accfg_ctx *ctx, json_object *jobj,
		char *key)
{
	enum json_type type;
	int arraylen;
	int i;
	json_object *jvalue;
	json_object *jarray;

	jarray = jobj;
	if (key) {
		if (!json_object_object_get_ex(jobj, key, &jarray))
			return -1;
	}

	arraylen = json_object_array_length(jarray);
	if (!arraylen)
		return -1;

	for (i = 0; i < arraylen; i++) {
		jvalue = json_object_array_get_idx(jarray, i);
		if (!jvalue)
			return -1;
		type = json_object_get_type(jvalue);
		if (!type)
			return -1;
		if (type == json_type_array) {
			if (json_parse_array(ctx, jvalue, NULL) != 0)
				return -1;
		} else if (type != json_type_object) {
			if (configure_json_value(ctx, jvalue, NULL) != 0)
				return -1;
		} else {
			if (json_parse(ctx, jvalue) != 0)
				return -1;
		}
	}

	return 0;
}

static int parse_config(struct accfg_ctx *ctx, struct config *conf)
{
	int rc;
	json_object *jobj;

	if (!conf->buf)
		return -EINVAL;

	jobj = json_tokener_parse(conf->buf);
	if (!jobj)
		return -ENOMEM;

	rc = json_parse_array(ctx, jobj, NULL);
	if (rc < 0)
		return rc;

	return 0;
}

static int read_config_file(struct accfg_ctx *ctx, struct config *conf,
			    struct util_filter_params *param)
{
	FILE *f;
	char *config_file;
	int rc = 0, len, buf_length;
	struct stat st;

	if (conf->config_file)
		config_file = strdup(conf->config_file);
	else
		config_file = strdup(ACCFG_CONF_FILE);
	if (!config_file) {
		fprintf(stderr, "strdup default config file failed\n");
		return -ENOMEM;
	}

	f = fopen(config_file, "r");
	if (!f) {
		fprintf(stderr, "config-file: %s cannot be opened: %s\n",
				config_file, strerror(errno));
		rc = -errno;
		goto fopen_err;
	}

	rc = fstat(fileno(f), &st);
	if (rc < 0) {
		fprintf(stderr, "fstat failed: %s\n", strerror(errno));
		rc = -errno;
		goto err;
	}

	buf_length = st.st_size;
	conf->buf = malloc(buf_length);
	if (!conf->buf) {
		fprintf(stderr, "malloc read config-file buf error\n");
		rc = -ENOMEM;
		goto err;
	}

	len = fread(conf->buf, 1, buf_length, f);
	if (len != buf_length) {
		fprintf(stderr, "fread of buffer failed\n");
		goto err;
	}

 err:
	fclose(f);
 fopen_err:
	free(config_file);
	return rc;
}

static bool filter_device(struct accfg_device *device,
			  struct util_filter_ctx *ctx)
{
	struct list_filter_arg *lfa = ctx->list;
	int max_groups;
	struct accfg_json_container *jc;

	max_groups = accfg_device_get_max_groups(device);

	lfa->jdevice = util_device_to_json(device, lfa->flags);
	if (!lfa->jdevices)
		return false;

	jc = malloc(sizeof(struct accfg_json_container));
	if (!jc)
		return false;

	jc->jgroup_assigned = calloc(max_groups,
			sizeof(struct json_object *));
	if (!jc->jgroup_assigned)
		goto err;

	jc->jwq_group = calloc(max_groups, sizeof(struct json_object *));
	if (!jc->jwq_group)
		goto err;

	jc->jengine_group = calloc(max_groups, sizeof(struct json_object *));
	if (!jc->jengine_group)
		goto err;

	jc->jgroup_id = calloc(max_groups, sizeof(int));
	if (!jc->jgroup_id)
		goto err;

	jc->device_id = accfg_device_get_id(device);
	jc->device_name = accfg_device_get_devname(device);
	list_add(&lfa->jdev_list, &jc->list);

	/* a fresh dev_org will be null */
	jc->jgroups = NULL;
	jc->jwq_ungroup = NULL;
	jc->jengine_ungroup = NULL;

	json_object_array_add(lfa->jdevices, lfa->jdevice);

	return true;

err:
	free(jc);
	return false;
}

static bool filter_group(struct accfg_group *group,
			 struct util_filter_ctx *ctx)
{
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *jgroup;
	struct json_object *container = lfa->jdevice;
	uint64_t group_id;
	struct accfg_device *dev = accfg_group_get_device(group);
	int max_groups = accfg_device_get_max_groups(dev);
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

	jgroup = config_group_to_json(group, lfa->flags);
	if (!jgroup)
		return false;

	jc->jgroup = jgroup;
	group_id = accfg_group_get_id(group);
	/*
	 * to track group_id when one jgroup is created, this will be used to
	 * assign wq or engine to a particular group later.
	 */
	jc->jgroup_id[lfa->group_num % max_groups] = group_id;
	jc->jgroup_assigned[lfa->group_num % max_groups] = jgroup;
	lfa->group_num++;
	json_object_array_add(jc->jgroups, jgroup);

	return true;
}

static bool filter_wq(struct accfg_wq *wq, struct util_filter_ctx *ctx)
{
	struct json_object *jwq;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	int i;
	struct accfg_device *dev = accfg_wq_get_device(wq);
	int max_groups = accfg_device_get_max_groups(dev);
	struct accfg_json_container *jc = NULL, *iter;

	list_for_each(&lfa->jdev_list, iter, list) {
		if (match_device(dev, iter))
			jc = iter;
	}
	if (!jc)
		return false;

	if (!accfg_wq_is_enabled(wq))
		return true;

	jwq = util_wq_to_json(wq, lfa->flags);
	if (!jwq)
		return false;

	for (i = 0; i < max_groups; i++) {
		/*
		 * Group array will only be created if group contains the wq
		 */
		if (accfg_wq_get_group_id(wq) == jc->jgroup_id[i]) {
			container = jc->jgroup_assigned[i];

			if (!jc->jwq_group[i]) {
				/* need to create engine array per group */
				jc->jwq_group[i] =
					json_object_new_array();
				if (!jc->jwq_group[i])
					return false;

				json_object_object_add(container,
						"grouped_workqueues",
						jc->jwq_group[i]);
			}

			json_object_array_add(jc->jwq_group[i], jwq);
		}
	}

	return true;
}

static bool filter_engine(struct accfg_engine *engine,
			  struct util_filter_ctx *ctx)
{
	struct json_object *jengine;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	int i;
	struct accfg_device *dev = accfg_engine_get_device(engine);
	int max_groups = accfg_device_get_max_groups(dev);
	struct accfg_json_container *jc = NULL, *iter;

	list_for_each(&lfa->jdev_list, iter, list) {
		if (match_device(dev, iter))
			jc = iter;
	}
	if (!jc)
		return false;

	jengine = util_engine_to_json(engine, lfa->flags);
	if (!jengine)
		return false;

	/* group array will only be created if group contains the engine */
	for (i = 0; i < max_groups; i++) {
		if (accfg_engine_get_group_id(engine)
				== jc->jgroup_id[i]) {
			container = jc->jgroup_assigned[i];

			if (!jc->jengine_group[i]) {
				/* need to create engine array per group */
				jc->jengine_group[i] =
					json_object_new_array();
				if (!jc->jengine_group[i])
					return false;

				json_object_object_add(container,
						       "grouped_engines",
						       jc->jengine_group[i]);
			}

			json_object_array_add(jc->jengine_group[i],
					jengine);
		}
	}

	return true;
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

int cmd_config(int argc, const char **argv, void *ctx)
{
	int i, rc;
	const struct option options[] = {
		OPT_FILENAME('c', "config-file",
			     &config.config_file,
			     "config-file",
			     "override the default config"),
		OPT_BOOLEAN('v', "verbose", &verbose,
				"emit extra debug messages to stderr"),
		OPT_BOOLEAN('e', "enable", &enable,
				"enable configured devices and wqs"),
		OPT_BOOLEAN('f', "forced", &forced,
				"enabled devices will be disabled before configuring"),
		OPT_END(),
	};
	const char *const u[] = {
		"accfg load-config [<options>]", NULL
	};
	const char *prefix = "./";
	struct util_filter_ctx fctx = {
		0
	};
	struct list_filter_arg cfa = {
		0
	};

	argc = parse_options_prefix(argc, argv, prefix, options, u, 0);
	for (i = 0; i < argc; i++) {
		error("unknown parameter \"%s\"\n", argv[i]);
	}
	if (argc)
		usage_with_options(u, options);

	cfa.jdevices = json_object_new_array();
	if (!cfa.jdevices)
		return -ENOMEM;
	list_head_init(&cfa.jdev_list);

	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &cfa;
	cfa.flags = config_opts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &util_param);
	if (rc)
		return rc;

	rc = read_config_file((struct accfg_ctx *)ctx, &config, &util_param);
	if (rc < 0)
		fprintf(stderr, "Reading config file failed: %d\n", rc);

	rc = parse_config((struct accfg_ctx *)ctx, &config);
	if (rc < 0)
		fprintf(stderr, "Parse json and set device fail: %d\n", rc);

	free_containers(&cfa);

	if (enable && !rc)
		rc = activate_devices();

	return rc;
}

static int config_default_wq(struct accfg_wq *wq)
{
	struct accfg_device *dev = accfg_wq_get_device(wq);
	enum accfg_device_type dev_type;
	struct wq_parameters *p;

	if (!conf_def_dev_configured(dev))
		return 0;

	dev_type = accfg_device_get_type(dev);
	p = get_conf_def_wq_param(dev_type);
	if (!p)
		return -EINVAL;

	accfg_wq_set_priority(wq, p->priority);
	accfg_wq_set_group_id(wq, p->group_id);
	accfg_wq_set_block_on_fault(wq, p->block_on_fault);
	accfg_wq_set_str_mode(wq, p->mode);
	accfg_wq_set_str_type(wq, p->type);
	accfg_wq_set_str_name(wq, p->name);
	accfg_wq_set_str_driver_name(wq, p->driver_name);

	accfg_wq_set_size(wq, p->wq_size);
	config_default_wq_set_threshold(wq, p->threshold);
	config_default_wq_set_prs_disable(wq, p->prs_disable);
	config_default_wq_set_ats_disable(wq, p->ats_disable);

	return 0;
}

static int config_default_engine(struct accfg_engine *engine,
				 struct accfg_device *dev)
{
	enum accfg_device_type dev_type;
	struct wq_parameters *p;

	/* Engine's group_id is same as WQ's. */
	dev_type = accfg_device_get_type(dev);
	p = get_conf_def_wq_param(dev_type);
	if (!p)
		return -EINVAL;

	return accfg_engine_set_group_id(engine, p->group_id);
}

static void config_default_activate_devices(void *ctx)
{
	enum accfg_device_state dev_state;
	const char *dev_name, *wq_name;
	struct accfg_engine *engine;
	struct accfg_device *dev;
	struct accfg_wq *wq;
	int rc = 0;

	accfg_device_foreach(ctx, dev) {
		/* Skip device that is not configured. */
		if (!conf_def_dev_configured(dev))
			continue;

		/* Don't enable WQs/engines on partially enabled devices. */
		dev_state = accfg_device_get_state(dev);
		if (dev_state == ACCFG_DEVICE_ENABLED)
			continue;

		/* Set WQ parameters calculated based on dev. */
		config_default_wq_set_on_dev(dev);

		/* Config WQs */
		accfg_wq_foreach(dev, wq) {
			if (verbose)
				printf("config %s\n", accfg_wq_get_devname(wq));

			config_default_wq(wq);
		}

		/* Config engines */
		accfg_engine_foreach(dev, engine)
			config_default_engine(engine, dev);

		/* Enable device */
		dev_name = accfg_device_get_devname(dev);
		if (verbose)
			printf("enable %s\n", dev_name);
		rc = accfg_device_enable(dev);
		if (rc) {
			fprintf(stderr, "Error enabling %s\n", dev_name);
			continue;
		}

		/* Enable WQs */
		accfg_wq_foreach(dev, wq) {
			wq_name = accfg_wq_get_devname(wq);
			if (verbose)
				printf("enable %s\n", wq_name);

			rc = accfg_wq_enable(wq);
			if (rc) {
				fprintf(stderr, "Error enabling %s\n", wq_name);
				continue;
			}
		}
	}
}

#define CONFIG_DEFAULT_WQ_PRIORITY		10
#define CONFIG_DEFAULT_WQ_GROUP_ID		0
#define CONFIG_DEFAULT_WQ_BLOCK_ON_FAULT	1
#define CONFIG_DEFAULT_WQ_PRS_DISABLE		1
#define CONFIG_DEFAULT_WQ_ATS_DISABLE		0
#define CONFIG_DEFAULT_WQ_NAME			"user_default_wq"
#define CONFIG_DEFAULT_WQ_TYPE			"user"
#define CONFIG_DEFAULT_WQ_MODE			"shared"
#define CONFIG_DEFAULT_WQ_DRV_NAME		"user"

/* Set fixed WQ parameters: mode, type, driver_name */
static int config_default_wq_set_fixed(void)
{
	struct wq_parameters *p;
	int i;

	for (i = 0; i < ACCFG_DEVICE_MAX; i++) {
		p = &conf_def_wq_param[i].param;

		p->mode = strdup(CONFIG_DEFAULT_WQ_MODE);
		if (!p->mode) {
			fprintf(stderr, "strdup WQ mode failed\n");
			return -ENOMEM;
		}

		p->type = strdup(CONFIG_DEFAULT_WQ_TYPE);
		if (!p->type) {
			fprintf(stderr, "strdup WQ type failed\n");
			return -ENOMEM;
		}

		p->driver_name = strdup(CONFIG_DEFAULT_WQ_DRV_NAME);
		if (!p->driver_name) {
			fprintf(stderr, "strdup WQ driver_name failed\n");
			return -ENOMEM;
		}
	}

	return 0;
}

static void config_default(void *ctx)
{
	struct wq_parameters *p;
	int i;

	/*
	 * Configure WQ parameters except:
	 * 1. size and threshold will be configured when enabling WQs.
	 * 2. max_buffer_size, max_batch_size, op_config will be default values
	 *    which have been initialized by driver.
	 */
	for (i = 0; i < ACCFG_DEVICE_MAX; i++) {
		p = &conf_def_wq_param[i].param;

		p->priority = CONFIG_DEFAULT_WQ_PRIORITY;
		p->group_id = CONFIG_DEFAULT_WQ_GROUP_ID;
		p->block_on_fault = CONFIG_DEFAULT_WQ_BLOCK_ON_FAULT;
		p->mode = strdup(CONFIG_DEFAULT_WQ_MODE);
		p->type = strdup(CONFIG_DEFAULT_WQ_TYPE);
		p->name = strdup(CONFIG_DEFAULT_WQ_NAME);
		p->driver_name = strdup(CONFIG_DEFAULT_WQ_DRV_NAME);
		p->prs_disable = CONFIG_DEFAULT_WQ_PRS_DISABLE;
		p->ats_disable = CONFIG_DEFAULT_WQ_ATS_DISABLE;

		conf_def_wq_param[i].configured = true;
	}
}

static void config_default_param_free(void)
{
	struct wq_parameters *p;
	int i;

	for (i = 0; i < ACCFG_DEVICE_MAX; i++) {
		if (!conf_def_wq_param[i].configured)
			continue;

		p = &conf_def_wq_param[i].param;

		free((char *)p->name);
		free((char *)p->type);
		free((char *)p->mode);
		free((char *)p->driver_name);
	}
}

static int config_default_from_file(void *ctx)
{
	int rc;

	rc = read_config_file(ctx, &config, &util_param);
	if (rc < 0) {
		fprintf(stderr, "Reading config file failed: %d\n", rc);
			return rc;
	}

	config_default_file = true;
	rc = parse_config(ctx, &config);
	if (rc < 0) {
		fprintf(stderr, "Parse json and set device fail: %d\n", rc);
		return rc;
	}

	config_default_wq_set_fixed();
	if (conf_def_wq_param[ACCFG_DEVICE_DSA].param.name)
		conf_def_wq_param[ACCFG_DEVICE_DSA].configured = true;
	if (conf_def_wq_param[ACCFG_DEVICE_IAX].param.name)
		conf_def_wq_param[ACCFG_DEVICE_IAX].configured = true;

	return 0;
}

void config_default_disable(void *ctx)
{
	char *user_default_wq_name;
	struct accfg_device *dev;

	if (config.user_default_wq_name)
		user_default_wq_name = strdup(config.user_default_wq_name);
	else
		user_default_wq_name = strdup(CONFIG_DEFAULT_WQ_NAME);
	if (!user_default_wq_name) {
		fprintf(stderr, "strdup user default wq name failed\n");
		return;
	}

	printf("disable WQs named as %s\n", user_default_wq_name);

	accfg_device_foreach(ctx, dev) {
		enum accfg_device_state dev_state;
		enum accfg_wq_state wq_state;
		bool non_default_wq_enabled;
		struct accfg_wq *wq;
		const char *wq_name;

		non_default_wq_enabled = false;
		/* Disable enabled default WQs */
		accfg_wq_foreach(dev, wq) {
			wq_name = accfg_wq_get_type_name(wq);
			wq_state = accfg_wq_get_state(wq);
			if (wq_state == ACCFG_WQ_DISABLED)
				continue;

			if (!strcmp(wq_name, user_default_wq_name)) {
				if (verbose) {
					printf("disable %s\n",
					       accfg_wq_get_devname(wq));
				}
				accfg_wq_disable(wq, true);
			} else {
				non_default_wq_enabled = true;
			}
		}

		/* Disable enabled device only when all WQs are disabled. */
		dev_state = accfg_device_get_state(dev);
		if (dev_state == ACCFG_DEVICE_ENABLED &&
		    !non_default_wq_enabled) {
			if (verbose) {
				printf("enable %s\n",
				       accfg_device_get_devname(dev));
			}
			accfg_device_disable(dev, true);
		}
	}
	free(user_default_wq_name);
}

int cmd_config_default(int argc, const char **argv, void *ctx)
{
	bool disable = false;
	const struct option options[] = {
		OPT_FILENAME('c', "config-file", &config.config_file, "config-file",
			     "override the default config"),
		OPT_BOOLEAN('d', "disable", &disable,
			    "disable configured default devices and wqs"),
		OPT_STRING('n', "name", &config.user_default_wq_name, "user default wq name",
			   "specify user default wq name. Default \"user_default_wq\""),
		OPT_BOOLEAN('v', "verbose", &verbose,
			    "emit extra debug messages to stderr"),
		OPT_END(),
	};
	const char *const u[] = {
		"accfg config-default [<options>]", NULL
	};
	struct util_filter_ctx fctx = {
		0
	};
	struct list_filter_arg cfa = {
		0
	};
	const char *prefix = "./";
	int i, rc = 0;

	argc = parse_options_prefix(argc, argv, prefix, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);
	if (argc)
		usage_with_options(u, options);

	cfa.jdevices = json_object_new_array();
	if (!cfa.jdevices)
		return -ENOMEM;
	list_head_init(&cfa.jdev_list);

	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &cfa;
	cfa.flags = config_opts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &util_param);
	if (rc)
		return rc;

	free_containers(&cfa);

	if (disable) {
		config_default_disable(ctx);

		return 0;
	}

	if (config.config_file) {
		/* Parse the default config file and set configs. */
		rc = config_default_from_file(ctx);
	} else {
		config_default(ctx);
	}

	if (!rc)
		config_default_activate_devices(ctx);

	config_default_param_free();

	return 0;
}
