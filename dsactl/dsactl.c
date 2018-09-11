/*
 * Copyright(c) 2015-2017 Intel Corporation. All rights reserved.
 * Copyright(c) 2005 Andreas Ericsson. All rights reserved.
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

/* originally copied from perf and git */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <builtin.h>
#include <dsactl/libdsactl.h>
#include <ccan/array_size/array_size.h>

#include <util/parse-options.h>
#include <util/strbuf.h>
#include <util/util.h>
#include <util/main.h>

const char dsactl_usage_string[] = "dsactl [--version] [--help] COMMAND [ARGS]";
const char dsactl_more_info_string[] =
    "See 'dsactl help COMMAND' for more information on a specific command.\n"
    " dsactl --list-cmds to see all available commands";

static int cmd_version(int argc, const char **argv, void *ctx)
{
	printf("%s\n", VERSION);
	return 0;
}

static int cmd_help(int argc, const char **argv, void *ctx)
{
	const char *const builtin_help_subcommands[] = {
		"enable-workqueue", "disable-workqueue", "zero-labels",
		"enable-group", "disable-group", NULL
	};
	struct option builtin_help_options[] = {
		OPT_END(),
	};
	const char *builtin_help_usage[] = {
		"dsactl help [command]",
		NULL
	};

	argc = parse_options_subcommand(argc, argv, builtin_help_options,
					builtin_help_subcommands,
					builtin_help_usage, 0);

	if (!argv[0]) {
		printf("\n usage: %s\n\n", dsactl_usage_string);
		printf("\n %s\n\n", dsactl_more_info_string);
		return 0;
	}

	return help_show_man_page(argv[0], "dsactl", "DSACTL_MAN_VIEWER");
}

static struct cmd_struct commands[] = {
	{"version", cmd_version},
	{"list", cmd_list},
	{"load-config", cmd_config},
	{"save-config",  cmd_save},
	{"help", cmd_help},
	{"disable-device", cmd_disable_device},
	{"enable-device", cmd_enable_device},
	{"disable-wq", cmd_disable_wq},
	{"enable-wq", cmd_enable_wq},
	{"config-device", cmd_config_device},
	{"config-group", cmd_config_group},
	{"config-wq", cmd_config_wq},
	{"config-engine", cmd_config_engine},
#ifdef ENABLE_TEST
	{"test", cmd_test},
#endif
#ifdef ENABLE_DESTRUCTIVE
	{"bat", cmd_bat},
#endif
};

int main(int argc, const char **argv)
{
	struct dsactl_ctx *ctx;
	int rc;

	/* Look for flags.. */
	argv++;
	argc--;
	main_handle_options(&argv, &argc, dsactl_usage_string, commands,
			    ARRAY_SIZE(commands));

	if (argc > 0) {
		if (!prefixcmp(argv[0], "--"))
			argv[0] += 2;
	} else {
		/* The user didn't specify a command; give them help */
		printf("\n usage: %s\n\n", dsactl_usage_string);
		printf("\n %s\n\n", dsactl_more_info_string);
		goto out;
	}

	rc = dsactl_new(&ctx);
	if (rc)
		goto out;
	main_handle_internal_command(argc, argv, ctx, commands,
				     ARRAY_SIZE(commands));
	dsactl_unref(ctx);
	fprintf(stderr, "Unknown command: '%s'\n", argv[0]);
out:
	return 1;
}
