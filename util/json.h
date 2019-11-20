
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */
#ifndef __ACCFG_JSON_H__
#define __ACCFG_JSON_H__
#include <stdio.h>
#include <stdbool.h>
#include <accfg/libaccel_config.h>
#include <ccan/short_types/short_types.h>

enum util_json_flags {
	UTIL_JSON_IDLE = (1 << 0),
	UTIL_JSON_HUMAN = (1 << 1),
	UTIL_JSON_VERBOSE = (1 << 2),
	UTIL_JSON_SAVE = (1 << 3),
};

struct json_object;
void util_display_json_array(FILE *f_out, struct json_object *jarray,
		unsigned long flags);
void __util_display_json_array(FILE *fd, struct json_object *jarray,
                unsigned long flags);
struct json_object *util_device_to_json(struct accfg_device *device,
		unsigned long flags);
struct json_object *util_wq_to_json(struct accfg_wq *accfg_wq,
		unsigned long flags);
struct json_object *util_engine_to_json(struct accfg_engine *accfg_engine,
                unsigned long flags);
struct json_object *util_json_object_size(unsigned long long size,
		unsigned long flags);
struct json_object *util_json_object_hex(unsigned long long val,
		unsigned long flags);
#endif /* __ACCFG_JSON_H__ */
