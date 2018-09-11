/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
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
#include <dsactl/libdsactl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <dsactl.h>
#include "private.h"

struct util_filter_params param;
static int dev_num;
static int max_groups;
static int max_wqs;
static int max_engines;
static int *wq_dfd;
static int *engine_dfd;
static int wq_i, engine_i;
static int did_fail;
static int group_counter;
static int wq_index;
static int engine_index;
static char **dev_path_matrix;
static bool verbose;

static struct config {
	bool devices;
	bool groups;
	bool engines;
	bool wqs;
	const char *logging;
	const char *config_file;
} config;

static unsigned long config_opts_to_flags(void)
{
	unsigned long flags = 0;
	return flags;
}

#define fail(fmt, ...) \
do { \
        did_fail = 1; \
        dbg(ctx, "dsactl-%s:%s:%d: " fmt, \
                        VERSION, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)

#define debug(fmt, ...) \
	({if (verbose) { \
		fprintf(stderr, "%s:%d: " fmt, __func__, __LINE__, ##__VA_ARGS__); \
	} else { \
		do { } while (0); \
	}})

static int json_parse_array(json_object * jobj, char *key);
static int json_parse(json_object * jobj);
static bool user_file_writable(int fd);
static int set_param(int dfd, char *name, const char *buf);
static int configure_json_value(json_object * jobj, char *key);
static int read_config_file(struct dsactl_ctx *ctx, struct config *to_config,
			    struct util_filter_params *util_param);

static void log_syslog(struct dsactl_ctx *ctx, int priority, const char *file,
		       int line, const char *fn, const char *format,
		       va_list args)
{
	char *buf;
	if (vasprintf(&buf, format, args) < 0) {
		fail("vasprintf error\n");
		return;
	}
	syslog(priority, "%s", buf);

	free(buf);
	return;
}

static void log_standard(struct dsactl_ctx *ctx, int priority, const char *file,
			 int line, const char *fn, const char *format,
			 va_list args)
{
	char *buf;
	if (vasprintf(&buf, format, args) < 0) {
		fail("vasprintf error\n");
		return;
	}

	if (priority == 6)
		fprintf(stdout, "%s", buf);
	else
		fprintf(stderr, "%s", buf);

	free(buf);
	return;
}

static void log_file(struct dsactl_ctx *ctx, int priority, const char *file,
		     int line, const char *fn, const char *format, va_list args)
{
	FILE *f;
	char *buf;
	struct timespec ts;
	char timestamp[MAX_BUF_LEN];

	if (vasprintf(&buf, format, args) < 0) {
		fail("vasprintf error\n");
		return;
	}

	f = fopen(config.logging, "a+");
	if (!f) {
		dsactl_set_log_fn(ctx, log_syslog);
		err(ctx, "open logfile %s failed, forward messages to syslog\n",
		    config.logging);
		did_fail = 1;
		notice(ctx, "%s\n", buf);
		goto end;
	}

	if (priority != LOG_NOTICE) {
		clock_gettime(CLOCK_REALTIME, &ts);
		sprintf(timestamp, "%10ld.%09ld", ts.tv_sec, ts.tv_nsec);
		fprintf(f, "[%s] [%d] %s", timestamp, getpid(), buf);
	} else
		fprintf(f, "%s", buf);

	fflush(f);
	fclose(f);
end:
	free(buf);
	fclose(f);
	return;
}

static int *wq_dfd_allocation(struct dsactl_device *device)
{
	max_wqs = dsactl_device_get_max_work_queues(device);
	if (!max_wqs)
		return NULL;
	wq_dfd = malloc(max_wqs * sizeof(int));
	if (!wq_dfd)
		return NULL;

	return wq_dfd;
}

static int *engine_dfd_allocation(struct dsactl_device *device)
{
	max_engines = dsactl_device_get_max_engines(device);
	if (!max_engines)
		return NULL;
	engine_dfd = malloc(max_engines * sizeof(int));
	if (!engine_dfd)
		return NULL;

	return engine_dfd;
}

/* Helper function to check write access to file */
static bool user_file_writable(int fd)
{
	struct stat stat;
	int rc;

	rc = fstat(fd, &stat);
	if (rc < 0)
		return false;

	if (stat.st_mode & S_IWUSR)
		return true;

	return false;
}

/* Helper function to set value into json integer object */
static void json_set_int(json_object * jobj, char *key, char *name, int dfd)
{
	int value;
	char buf[MAX_BUF_LEN];

	if (strcmp(key, name) == 0) {
		value = json_object_get_int(jobj);
		if (!value)
			return;
		sprintf(buf, "%u", value);
		if (set_param(dfd, key, buf) != 0)
			return;
	}
}

/* Helper function to set value into json string object */
static void json_set_string(json_object * jobj, char *key, char *name, int dfd)
{
	char *value;
	char buf[MAX_BUF_LEN];

	if (strcmp(key, name) == 0) {
		value = (char *)json_object_get_string(jobj);
		if (!value)
			return;
		sprintf(buf, "%s", value);
		if (set_param(dfd, key, buf) != 0) {
			close(dfd);
			return;
		}
	}
}

static int set_param(int dfd, char *name, const char *buf)
{
	int rc = 0, written = 0;
	int len = strlen(buf);
	int fd = openat(dfd, name, O_RDWR);

	if (fd < 0) {
		close(fd);
		return rc;
	}

	if (user_file_writable(fd) == false) {
		close(fd);
		return -EPERM ;
	}

	do {
		rc = write(fd, buf + written, len - written);
		if (rc < 0) {
			fprintf(stderr, "write failed with %s\n", strerror(rc));
			close(fd);
			return rc;
		}
		written += rc;
	} while (written != len);

	close(fd);
	return 0;
}

/* Configuring the value corresponding to boolean, double, integer and strings */
static int configure_json_value(json_object * jobj, char *key)
{
	const char *ctl_base = "sys/bus/dsa/devices/";
	char *parsed_string;
	char dev_path[PATH_MAX];
	char open_path[PATH_MAX];
	int device_index;
	int device_dfd = 0, group_dfd = 0;

	if (strcmp(key, "dev") == 0) {
		parsed_string = (char *)json_object_get_string(jobj);
		fprintf(stdout, "parsed_string is %s\n", parsed_string);
		if (!parsed_string)
			return -1;
		if (strstr(parsed_string, "dsa") != NULL) {
			sprintf(dev_path, "%s%s", ctl_base, parsed_string);
			device_index = (int)(parsed_string[3] - '0');
			strcpy(dev_path_matrix[device_index], dev_path);
			device_dfd = open(dev_path, O_PATH);
			if (device_dfd < 0) {
				close(device_dfd);
				return -1;
			}
		}

		if (strstr(parsed_string, "wq") != NULL) {
			wq_i++;
			device_index = (int)(parsed_string[2] - '0');
			sprintf(open_path, "%s%s%s", dev_path_matrix[device_index], "/", parsed_string);
			wq_dfd[wq_i] = open(open_path, O_PATH);
			if (wq_dfd[wq_i] < 0) {
				close(wq_dfd[wq_i]);
				return -1;
			}
		}

		if (strstr(parsed_string, "engine") != NULL) {
			engine_i++;
			device_index = (int)(parsed_string[6] - '0');
			sprintf(open_path, "%s%s%s", dev_path_matrix[device_index], "/", parsed_string);
			engine_dfd[engine_i] = open(open_path, O_PATH);
			if (engine_dfd[engine_i] < 0) {
				close(engine_dfd[engine_i]);
				return -1;
			}
		}

		if (strstr(parsed_string, "group") != NULL) {
			sprintf(dev_path, "%s%s", ctl_base, parsed_string);
			group_dfd = open(dev_path, O_PATH);
			if (group_dfd < 0) {
				close(group_dfd);
				return -1;
			}
		}
	}

	/* configure attribute in each device */
	if (device_dfd) {
		json_set_int(jobj, key, "token_limit", device_dfd);
		debug("token_limit is set in device_id %d\n", device_dfd);
		close(device_dfd);
	}

	/* configure attribute in each group */
	if (group_dfd) {
		json_set_int(jobj, key, "tokens_reserved", group_dfd);
		debug("tokens_reserved in group_dfd %d\n", group_dfd);
		json_set_int(jobj, key, "use_token_limit", group_dfd);
		debug("use_token_limit in group_dfd %d\n", group_dfd);
		json_set_int(jobj, key, "tokens_allowed", group_dfd);
		debug("tokens_allowed in group_dfd %d\n", group_dfd);
		json_set_int(jobj, key, "traffic_class_a", group_dfd);
		debug("traffic_class_a in group_dfd %d\n", group_dfd);
		json_set_int(jobj, key, "traffic_class_b", group_dfd);
		debug("use_token_limit in group_dfd %d\n", group_dfd);
		close(group_dfd);
	}

	/* configure attribute in each workqueue */
	if (wq_dfd[wq_i]) {
		json_set_int(jobj, key, "size", wq_dfd[wq_i]);
		debug("size in wq_dfd %d\n", wq_dfd[wq_i]);
		json_set_int(jobj, key, "priority", wq_dfd[wq_i]);
		debug("priority in wq_dfd %d\n", wq_dfd[wq_i]);
		json_set_int(jobj, key, "group_id", wq_dfd[wq_i]);
		debug("group_id in wq_dfd %d\n", wq_dfd[wq_i]);
		json_set_int(jobj, key, "enforce_order", wq_dfd[wq_i]);
		debug("enforce_order in wq_dfd %d\n", wq_dfd[wq_i]);
		json_set_int(jobj, key, "block_on_fault", wq_dfd[wq_i]);
		debug("block_on_default in wq_dfd %d\n", wq_dfd[wq_i]);
		json_set_string(jobj, key, "mode", wq_dfd[wq_i]);
		debug("mode in wq_dfd %d\n", wq_dfd[wq_i]);
		close(wq_dfd[wq_i]);
	}

	/* configure attribute in each engine */
	if (engine_dfd[engine_i]) {
		json_set_int(jobj, key, "group_id", engine_dfd[engine_i]);
		debug("group_id in engine_dfd %d\n", engine_dfd[engine_i]);
		close(engine_dfd[engine_i]);
	}

	return 0;
}

static struct json_object *config_group_to_json(struct dsactl_group *group,
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

	return jgroup;
err:
	json_object_put(jgroup);
	return NULL;
}

/* Parsing the json object */
static int json_parse(json_object * jobj)
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
			if (configure_json_value(iter.val, key) != 0)
				return -1;
			break;
		case json_type_object:
			jobj = json_object_object_get(jobj, iter.key);
			if (!jobj)
				return -1;
			json_parse(jobj);
			break;
		case json_type_array:
			if (json_parse_array(jobj, iter.key) !=0)
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

static int json_parse_array(json_object * jobj, char *key)
{
	enum json_type type;
	int arraylen;
	int i;
	json_object *jvalue;
	json_object *jarray;

	jarray = jobj;
	if (key) {
		jarray = json_object_object_get(jobj, key);
		if(!jarray)
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
			if (json_parse_array(jvalue, NULL) != 0)
				return -1;
		} else if (type != json_type_object) {
			if (configure_json_value(jvalue, NULL)!= 0)
				return -1;
		} else {
			if (json_parse(jvalue)!= 0)
				return -1;
		}
	}

	return 0;
}

static int read_config_file(struct dsactl_ctx *ctx, struct config *to_config,
			    struct util_filter_params *util_param)
{
	FILE *f;
	char *buf = NULL;
	char *config_file;
	int rc = 0, len, buf_length;
	json_object *jobj;

	if (to_config->config_file)
		config_file = strdup(to_config->config_file);
	else
		config_file = strdup(DSACTL_CONF_FILE);
	if (!config_file) {
		fail("strdup default config file failed\n");
		rc = -ENOMEM;
		goto out;
	}

	f = fopen(config_file, "r");
	if (!f) {
		err(ctx, "config-file: %s cannot be opened\n", config_file);
		rc = -errno;
		fclose(f);
		fprintf(stderr, "open config_file failed with %s\n", strerror(errno));
		goto out;
	}

	fseek(f, 0, SEEK_END);
	buf_length = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(buf_length);
	if (!buf) {
		fail("malloc read config-file buf error\n");
		rc = -ENOMEM;
		goto out;
	}
	len = fread(buf, 1, buf_length, f);
	if (len != buf_length) {
		fail("fread of buffer failed\n");
		fclose(f);
		goto out;
	}
	fclose(f);

	jobj = json_tokener_parse(buf);
	if (!jobj)
		goto out;
	if (json_parse_array(jobj, NULL) != 0)
		goto out;
	return 0;

out:
	free(buf);
	free(config_file);
	return rc;
}

static bool filter_device(struct dsactl_device *device,
			  struct util_filter_ctx *ctx)
{
	struct list_filter_arg *lfa = ctx->list;
	int group_index;

	max_groups = dsactl_device_get_max_groups(device);

	if (!lfa->jdevices) {
		lfa->jdevices = json_object_new_array();
		if (!lfa->jdevices)
			return false;
		list_head_init(&lfa->dev_container);
	}

	lfa->jdevice = util_device_to_json(device, lfa->flags);
	if (!lfa->jdevices)
		return false;
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
	for (group_index = 0; group_index < MAX_GROUP_NUM; group_index++) {
		lfa->dev_org->jwq_array[group_index] = NULL;
		lfa->dev_org->jengine_array[group_index] = NULL;
	}
	lfa->dev_org->jwq_device = NULL;
	lfa->dev_org->jengine_device = NULL;

	json_object_array_add(lfa->jdevices, lfa->jdevice);
	wq_dfd = wq_dfd_allocation(device);
	engine_dfd = engine_dfd_allocation(device);
	dev_num++;

	return true;
}

static bool filter_group(struct dsactl_group *group,
			 struct util_filter_ctx *ctx)
{
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *jgroup;
	struct json_object *container = lfa->jdevice;
	unsigned long device_id, group_id;
	int group_index;
	const char *group_name;

	if (!lfa->dev_org->jgroups) {
		lfa->dev_org->jgroups = json_object_new_array();
		if (!lfa->dev_org->jgroups) {
			return false;
		}

		if (container)
			json_object_object_add(container, "groups",
					       lfa->dev_org->jgroups);
	}

	jgroup = config_group_to_json(group, lfa->flags);
	if (!jgroup) {
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
	 * We've started a new group, any previous jwq_array and jengine_array will
	 * have been parented to the last group. Clear out jwqs and
	 * jengine_array
	 * so we start a new array per group.
	 */
	for (group_index = 0; group_index < group_counter % max_groups;
	     group_index++) {
		lfa->dev_org->jwq_array[group_index] = NULL;
		lfa->dev_org->jengine_array[group_index] = NULL;
	}

	/*
	 * Without a device we are collecting groups anonymously across
	 * the platform (this applies to DSA??).
	 */

	json_object_array_add(lfa->dev_org->jgroups, jgroup);
	return true;
}

static bool filter_wq(struct dsactl_wq *dsawq, struct util_filter_ctx *ctx)
{
	struct json_object *jdsawq;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	int group_index;
	bool within_group = false;

	if (!dsactl_wq_is_enabled(dsawq)) {
		return true;
	}

	jdsawq = util_wq_to_json(dsawq, lfa->flags);
	if (!jdsawq) {
		return false;
	}

	if (!lfa->dev_org->jwqs[wq_index]) {
		lfa->dev_org->jwqs[wq_index] = json_object_new_array();
		if (!lfa->dev_org->jwqs[wq_index]) {
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
					/* need to create engine array per group */
					lfa->dev_org->jwq_array[group_index] =
					    json_object_new_array();
					if (!lfa->
					    dev_org->jwq_array[group_index]) {
						return false;
					}
					json_object_object_add(container,
							       "grouped_workqueues",
							       lfa->dev_org->
							       jwq_array
							       [group_index]);
				}
				json_object_array_add(lfa->dev_org->jwq_array
						      [group_index], jdsawq);
			}
		}

		/* for the rest, add into device directly */
		if (!lfa->dev_org->jwq_device) {
			lfa->dev_org->jwq_device = json_object_new_array();
			if (!lfa->dev_org->jwq_device) {
				return false;
			}
			container = lfa->jdevice;
			json_object_object_add(container,
					       "non_grouped_workqueues",
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
	int group_index;
	bool within_group = false;

	jdsaengine = util_engine_to_json(dsaengine, lfa->flags);
	if (!jdsaengine) {
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
					lfa->
					    dev_org->jengine_array[group_index]
					    = json_object_new_array();
					if (!lfa->
					    dev_org->jengine_array[group_index])
					{
						return false;
					}
					json_object_object_add(container,
							       "grouped_engines",
							       lfa->dev_org->
							       jengine_array
							       [group_index]);
				}
				json_object_array_add(lfa->dev_org->
						      jengine_array
						      [group_index],
						      jdsaengine);
			}
		}

		/* for the rest, add into device directly */
		if (!within_group) {
			if (!lfa->dev_org->jengine_device) {
				lfa->dev_org->jengine_device =
				    json_object_new_array();
				if (!lfa->dev_org->jengine_device) {
					return false;
				}
				container = lfa->jdevice;
				json_object_object_add(container,
						       "none_grouped_engines",
						       lfa->
						       dev_org->jengine_device);
			}
			json_object_array_add(lfa->dev_org->jengine_device,
					      jdsaengine);
		}
	engine_index++;

	return true;
}

static void free_dev_org(struct list_filter_arg *cfa)
{
	/* free all the allocated dev_org data structure */
	if (!cfa->dev_org->jgroup_index)
		free(cfa->dev_org->jgroup_index);
	if (!cfa->dev_org->jwq_array)
		free(cfa->dev_org->jwq_array);
	if (!cfa->dev_org->jengine_array)
		free(cfa->dev_org->jengine_array);
	if (!cfa->dev_org->jwqs)
		free(cfa->dev_org->jwqs);
	if (!cfa->dev_org->jgroup_id)
		free(cfa->dev_org->jgroup_id);
	if (!cfa->dev_org)
		free(cfa->dev_org);
}

int cmd_config(int argc, const char **argv, void *ctx)
{
	int i, rc;
	FILE *f;
	const struct option options[] = {
		OPT_FILENAME('l', "log", &config.logging,
			     "<file> | syslog | standard",
			     "where to output the config's notification"),
		OPT_FILENAME('c', "config-file",
			     &config.config_file,
			     "config-file",
			     "override the default config"),
		OPT_BOOLEAN('v', "verbose", &verbose,
				"emit extra debug messages to stderr"),
		OPT_END(),
	};
	const char *const u[] = {
		"dsactl load-config [<options>]", NULL
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

	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &cfa;
	cfa.flags = config_opts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &param);
	if (rc)
		return rc;

	dev_path_matrix = (char **)malloc(dev_num * sizeof(PATH_MAX));

	/* default to log_standard */
	dsactl_set_log_fn((struct dsactl_ctx *)ctx, log_standard);

	if (verbose)
		dsactl_set_log_priority((struct dsactl_ctx *)ctx, LOG_DEBUG);
	else
		dsactl_set_log_priority((struct dsactl_ctx *)ctx, LOG_INFO);

	rc = read_config_file((struct dsactl_ctx *)ctx, &config, &param);
	if (rc)
		goto out;

	if (config.logging) {
		if (strncmp(config.logging, "./", 2) != 0)
			fix_filename(prefix, (const char **)&config.logging);
		if (strncmp(config.logging, "./syslog", 8) == 0) {
			dsactl_set_log_fn((struct dsactl_ctx *)ctx, log_syslog);
		} else if (strncmp(config.logging, "./standard", 10) == 0) ;
		else {
			f = fopen(config.logging, "a+");
			if (!f) {
				error("open %s failed\n", config.logging);
				rc = -errno;
				fclose(f);
				goto out;
			}
			fclose(f);
			dsactl_set_log_fn((struct dsactl_ctx *)ctx, log_file);
		}
	}

	free_dev_org(&cfa);
out:
	return rc;
}
