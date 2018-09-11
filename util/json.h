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
#ifndef __DSACTL_JSON_H__
#define __DSACTL_JSON_H__
#include <stdio.h>
#include <stdbool.h>
#include <dsactl/libdsactl.h>
#include <ccan/short_types/short_types.h>

enum util_json_flags {
	UTIL_JSON_IDLE = (1 << 0),
	UTIL_JSON_MEDIA_ERRORS = (1 << 1),
	UTIL_JSON_DAX = (1 << 2),
	UTIL_JSON_DAX_DEVS = (1 << 3),
	UTIL_JSON_HUMAN = (1 << 4),
	UTIL_JSON_VERBOSE = (1 << 5),
};

struct json_object;
void util_display_json_array(FILE *f_out, struct json_object *jarray,
		unsigned long flags);
void __util_display_json_array(FILE *fd, struct json_object *jarray,
                unsigned long flags);
struct json_object *util_device_to_json(struct dsactl_device *device,
		unsigned long flags);
struct json_object *util_wq_to_json(struct dsactl_wq *dsawq,
		unsigned long flags);
struct json_object *util_engine_to_json(struct dsactl_engine *dsaengine,
                unsigned long flags);
struct json_object *util_json_object_size(unsigned long long size,
		unsigned long flags);
struct json_object *util_json_object_hex(unsigned long long val,
		unsigned long flags);
#endif /* __DSACTL_JSON_H__ */
