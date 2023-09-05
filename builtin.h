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
#ifndef _ACCFG_BUILTIN_H_
#define _ACCFG_BUILTIN_H_
extern const char accfg_usage_string[];

struct cmd_struct {
	const char *cmd;
	int (*fn) (int, const char **, void *ctx);
};
int cmd_list(int argc, const char **argv, void *ctx);
int cmd_config(int argc, const char **argv, void *ctx);
int cmd_save(int argc, const char **argv, void *ctx);
int cmd_disable_device(int argc, const char **argv, void *ctx);
int cmd_enable_device(int argc, const char **argv, void *ctx);
int cmd_disable_wq(int argc, const char **argv, void *ctx);
int cmd_enable_wq(int argc, const char **argv, void *ctx);
int cmd_config_device(int argc, const char **argv, void *ctx);
int cmd_config_group(int argc, const char **argv, void *ctx);
int cmd_config_wq(int argc, const char **argv, void *ctx);
int cmd_config_engine(int argc, const char **argv, void *ctx);
int cmd_config_default(int argc, const char **argv, void *ctx);
#ifdef ENABLE_TEST
int cmd_test(int argc, const char **argv, void *ctx);
#endif
#endif /* _ACCFG_BUILTIN_H_ */
