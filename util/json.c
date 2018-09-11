/*
 * Copyright(c) 2015-2017 Intel Corporation. All rights reserved.
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
#include <limits.h>
#include <string.h>
#include <util/json.h>
#include <util/filter.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <uuid/uuid.h>
#include <json-c/json.h>
#include <json-c/printbuf.h>
#include <dsactl/libdsactl.h>
#include <ccan/array_size/array_size.h>
#include <ccan/short_types/short_types.h>
#include <dsactl.h>
#include <dsactl/libdsactl.h>

/* adapted from mdadm::human_size_brief() */
static int display_size(struct json_object *jobj, struct printbuf *pbuf,
			int level, int flags)
{
	unsigned long long bytes = json_object_get_int64(jobj);
	static char buf[128];
	int c;

	/*
	 * We convert bytes to either centi-M{ega,ibi}bytes or
	 * centi-G{igi,ibi}bytes, with appropriate rounding, and then print
	 * 1/100th of those as a decimal.  We allow upto 2048Megabytes before
	 * converting to gigabytes, as that shows more precision and isn't too
	 * large a number.  Terabytes are not yet handled.
	 *
	 * If prefix == IEC, we mean prefixes like kibi,mebi,gibi etc.
	 * If prefix == JEDEC, we mean prefixes like kilo,mega,giga etc.
	 */

	if (bytes < 5000 * 1024)
		snprintf(buf, sizeof(buf), "%lld", bytes);
	else {
		/* IEC */
		if (bytes < 2 * 1024LL * 1024LL * 1024LL) {
			long cMiB = (bytes * 200LL / (1LL << 20) + 1) / 2;

			c = snprintf(buf, sizeof(buf), "\"%ld.%02ld MiB",
				     cMiB / 100, cMiB % 100);
		} else {
			long cGiB = (bytes * 200LL / (1LL << 30) + 1) / 2;

			c = snprintf(buf, sizeof(buf), "\"%ld.%02ld GiB",
				     cGiB / 100, cGiB % 100);
		}

		/* JEDEC */
		if (bytes < 2 * 1024LL * 1024LL * 1024LL) {
			long cMB = (bytes / (1000000LL / 200LL) + 1) / 2;

			snprintf(buf + c, sizeof(buf) - c, " (%ld.%02ld MB)\"",
				 cMB / 100, cMB % 100);
		} else {
			long cGB = (bytes / (1000000000LL / 200LL) + 1) / 2;

			snprintf(buf + c, sizeof(buf) - c, " (%ld.%02ld GB)\"",
				 cGB / 100, cGB % 100);
		}
	}

	return printbuf_memappend(pbuf, buf, strlen(buf));
}

static int display_hex(struct json_object *jobj, struct printbuf *pbuf,
		       int level, int flags)
{
	unsigned long long val = json_object_get_int64(jobj);
	static char buf[32];
	snprintf(buf, sizeof(buf), "\"%#llx\"", val);
	return printbuf_memappend(pbuf, buf, strlen(buf));
}

struct json_object *util_json_object_size(unsigned long long size,
					  unsigned long flags)
{
	struct json_object *jobj = json_object_new_int64(size);

	if (jobj && (flags & UTIL_JSON_HUMAN))
		json_object_set_serializer(jobj, display_size, NULL, NULL);
	return jobj;
}

struct json_object *util_json_object_hex(unsigned long long val,
					 unsigned long flags)
{
	struct json_object *jobj = json_object_new_int64(val);

	if (jobj)
		json_object_set_serializer(jobj, display_hex, NULL, NULL);
	return jobj;
}

/* API used to output json object display to console */
void util_display_json_array(FILE * f_out, struct json_object *jarray,
			     unsigned long flags)
{
	int len = json_object_array_length(jarray);
	int jflag = JSON_C_TO_STRING_PRETTY;

	if (json_object_array_length(jarray) > 1 || !(flags & UTIL_JSON_HUMAN))
		fprintf(f_out, "%s\n",
			json_object_to_json_string_ext(jarray, jflag));
	else if (len) {
		struct json_object *jobj;
		jobj = json_object_array_get_idx(jarray, 0);
		fprintf(f_out, "%s\n",
			json_object_to_json_string_ext(jobj, jflag));
	}
	json_object_put(jarray);
}

/* API used to output json object display to specified file */
void __util_display_json_array(FILE * fd, struct json_object *jarray,
			     unsigned long flags)
{
	int len = json_object_array_length(jarray);
	int jflag = JSON_C_TO_STRING_PRETTY;

	if (json_object_array_length(jarray) > 1 || !(flags & UTIL_JSON_HUMAN))
		fprintf(fd, "%s\n",
			json_object_to_json_string_ext(jarray, jflag));
	else if (len) {
		struct json_object *jobj;
		jobj = json_object_array_get_idx(jarray, 0);
		fprintf(fd, "%s\n",
			json_object_to_json_string_ext(jobj, jflag));
	}
	json_object_put(jarray);
}

struct json_object *util_device_to_json(struct dsactl_device *device,
					unsigned long flags)
{
	struct json_object *jdevice = json_object_new_object();
	struct json_object *jobj;
	struct dsactl_error *error;
	enum dsactl_device_state dev_state;

	if (!jdevice)
		return NULL;

	error = malloc(sizeof(struct dsactl_error));
	if (!error)
		return NULL;

	jobj = json_object_new_string(dsactl_device_get_devname(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "dev", jobj);

	jobj = json_object_new_int(dsactl_device_get_max_groups(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "max_groups", jobj);

	jobj = json_object_new_int(dsactl_device_get_max_work_queues(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "max_work_queues", jobj);

	jobj = json_object_new_int(dsactl_device_get_max_engines(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "max_engines", jobj);

	jobj =
	    json_object_new_int(dsactl_device_get_max_work_queues_size
				(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "work_queue_size", jobj);

	jobj = json_object_new_int(dsactl_device_get_numa_node(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "numa_node", jobj);

	if (dsactl_device_get_errors(device, error) == 1) {
		jobj = json_object_new_array();
		if (!jobj)
			goto err;
		for(int i = 0; i < 4; i++) {
			struct json_object *json_error;
			json_error = util_json_object_hex(error->val[i], flags);
			json_object_array_add(jobj, json_error);
		}
		json_object_object_add(jdevice, "errors", jobj);
		free(error);
	}

	jobj = util_json_object_hex(dsactl_device_get_op_cap(device),
			flags);
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "op_cap", jobj);

	dev_state = dsactl_device_get_state(device);
	if (dev_state == 1)
		jobj = json_object_new_string("enabled");
	else if (dev_state == 0)
		jobj = json_object_new_string("disabled");
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "state", jobj);

	jobj = json_object_new_int(dsactl_device_get_max_tokens(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "max_tokens", jobj);

	jobj = json_object_new_int(dsactl_device_get_max_batch_size(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "max_batch_size", jobj);

	jobj = json_object_new_int(dsactl_device_get_ims_size(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "ims_size", jobj);
	jobj = json_object_new_int(dsactl_device_get_max_batch_size(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "max_batch_size", jobj);

	jobj = json_object_new_int64(dsactl_device_get_max_transfer_size(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "max_transfer_size", jobj);

	jobj = json_object_new_int(dsactl_device_get_configurable(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "configurable", jobj);
	jobj = json_object_new_int(dsactl_device_get_pasid_enabled(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "pasid_enabled", jobj);

	jobj = json_object_new_int(dsactl_device_get_token_limit(device));
	if (!jobj)
		goto err;
	json_object_object_add(jdevice, "token_limit", jobj);

	return jdevice;
err:
	json_object_put(jdevice);
	return NULL;
}

struct json_object *util_wq_to_json(struct dsactl_wq *dsawq,
				    unsigned long flags)
{
	struct json_object *jdsa = json_object_new_object();
	struct json_object *jobj = NULL;
	unsigned long size = ULLONG_MAX;
	enum dsactl_wq_mode wq_mode;
	enum dsactl_wq_state wq_state;

	if (!jdsa)
		return NULL;

	jobj = json_object_new_string(dsactl_wq_get_devname(dsawq));
	if (!jobj)
		goto err;
	json_object_object_add(jdsa, "dev", jobj);

	wq_mode = dsactl_wq_get_mode(dsawq);
	if (wq_mode == 0)
		jobj = json_object_new_string("shared");
	if (wq_mode == 1)
		jobj = json_object_new_string("dedicated");
	if (!jobj)
		goto err;
	json_object_object_add(jdsa, "mode", jobj);

	size = dsactl_wq_get_size(dsawq);
	if (size < ULLONG_MAX) {
		jobj = util_json_object_size(size, flags);
		if (jobj)
			json_object_object_add(jdsa, "size", jobj);
	}

	jobj = json_object_new_int(dsactl_wq_get_group_id(dsawq));
	if (jobj)
		json_object_object_add(jdsa, "group_id", jobj);

	jobj = json_object_new_int(dsactl_wq_get_priority(dsawq));
	if (jobj)
		json_object_object_add(jdsa, "priority", jobj);
	jobj = json_object_new_int(dsactl_wq_get_enforce_order(dsawq));
	if (jobj)
		json_object_object_add(jdsa, "enforce_order", jobj);

	jobj = json_object_new_int(dsactl_wq_get_block_on_fault(dsawq));
	if (jobj)
		json_object_object_add(jdsa, "block_on_fault", jobj);

	wq_state = dsactl_wq_get_state(dsawq);
	if (wq_state == 0)
		jobj = json_object_new_string("disabled");
	else if (wq_state == 1)
		jobj = json_object_new_string("enabled");
	else if (wq_state == 2)
		jobj = json_object_new_string("quiescing");
	if (jobj)
		json_object_object_add(jdsa, "state", jobj);
	return jdsa;
err:
	json_object_put(jdsa);
	return NULL;
}

struct json_object *util_engine_to_json(struct dsactl_engine *dsaengine,
					unsigned long flags)
{
	struct json_object *jdsa = json_object_new_object();
	struct json_object *jobj = NULL;

	if (!jdsa) {
		return NULL;
	}
	jobj = json_object_new_string(dsactl_engine_get_devname(dsaengine));
	if (!jobj)
		goto err;
	json_object_object_add(jdsa, "dev", jobj);

	jobj = json_object_new_int(dsactl_engine_get_group_id(dsaengine));
	if (!jobj)
		goto err;
	json_object_object_add(jdsa, "group_id", jobj);

	return jdsa;
err:
	json_object_put(jdsa);
	return NULL;
}
