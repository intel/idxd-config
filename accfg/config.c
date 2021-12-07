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
static struct util_filter_params util_param;

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
	{ "token_limit", accfg_device_set_token_limit, NULL }
};

static bool is_group_traffic_class_writable(struct accfg_group *group,
		int val);
static bool is_group_token_attribs_writable(struct accfg_group *group,
		int val);
static bool is_group_token_limit_writable(struct accfg_group *group,
		int val);

static const struct group_set_table group_table[] = {
	{ "tokens_reserved", accfg_group_set_tokens_reserved, NULL,
		is_group_token_attribs_writable },
	{ "use_token_limit", accfg_group_set_use_token_limit, NULL,
		is_group_token_limit_writable },
	{ "tokens_allowed", accfg_group_set_tokens_allowed, NULL,
		is_group_token_attribs_writable },
	{ "traffic_class_a", accfg_group_set_traffic_class_a, NULL,
		is_group_traffic_class_writable},
	{ "traffic_class_b", accfg_group_set_traffic_class_b, NULL,
		is_group_traffic_class_writable},
};

static bool is_wq_threshold_writable(struct accfg_wq *wq, int val);

static const struct wq_set_table wq_table[] = {
	{ "size", accfg_wq_set_size, NULL, NULL, NULL },
	{ "priority", accfg_wq_set_priority, NULL, NULL, NULL },
	{ "group_id", accfg_wq_set_group_id, NULL, NULL, NULL },
	{ "block_on_fault", accfg_wq_set_block_on_fault, NULL, NULL, NULL },
	{ "type", NULL, NULL, accfg_wq_set_str_type, NULL },
	{ "name", NULL, NULL, accfg_wq_set_str_name, NULL },
	{ "mode", NULL, NULL, accfg_wq_set_str_mode, NULL },
	{ "max_batch_size", accfg_wq_set_max_batch_size, NULL, NULL, NULL },
	{ "max_transfer_size", NULL, accfg_wq_set_max_transfer_size, NULL, NULL },
	{ "threshold", accfg_wq_set_threshold, NULL, NULL,
		is_wq_threshold_writable },
	{ "ats_disable", accfg_wq_set_ats_disable, NULL, NULL, NULL },
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

static bool is_group_token_limit_writable(struct accfg_group *group,
		int val)
{
	struct accfg_device *dev;
	unsigned int token_limit;

	dev = accfg_group_get_device(group);
	token_limit = accfg_device_get_token_limit(dev);
	if (token_limit)
		return true;

	return false;
}


static bool is_group_token_attribs_writable(struct accfg_group *group,
		int val)
{
	if (val == -1)
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
				int val = json_object_get_int(jobj);

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
				int val = json_object_get_int(jobj);

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
				uint64_t val = json_object_get_int64(jobj);

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
				int val = json_object_get_int(jobj);
				if (((val == 0) && (errno == EINVAL))
						|| (val < 0))
					return -EINVAL;

				if ((accfg_device_get_type(dev) == ACCFG_DEVICE_IAX)
					&& ((!strcmp(group_table[i].name, "tokens_reserved"))
					|| (!strcmp(group_table[i].name, "use_token_limit"))
					|| (!strcmp(group_table[i].name, "tokens_allowed")))) {
					return 0;
				}
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
				int val = json_object_get_int(jobj);

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
					fprintf(stderr,
						"%s is active, will skip...\n", parsed_string);
					dev = NULL;
					return 0;
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

	if (!jgroup)
		return NULL;

	jobj = json_object_new_string(accfg_group_get_devname(group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "dev", jobj);
	jobj = json_object_new_int(accfg_group_get_tokens_reserved(group));
	if (!jobj)
		goto err;

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

	json_object_object_add(jgroup, "traffic_class_a", jobj);
	jobj = json_object_new_int(accfg_group_get_traffic_class_b(
				group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "traffic_class_b", jobj);
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
