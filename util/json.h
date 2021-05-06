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
		uint64_t flags);
struct json_object *util_device_to_json(struct accfg_device *device,
		uint64_t flags);
struct json_object *util_wq_to_json(struct accfg_wq *accfg_wq,
		uint64_t flags);
struct json_object *util_engine_to_json(struct accfg_engine *accfg_engine,
		uint64_t flags);
struct json_object *util_json_object_size(uint64_t size,
		uint64_t flags);
struct json_object *util_json_object_hex(uint64_t val,
		uint64_t flags);
#endif /* __ACCFG_JSON_H__ */
