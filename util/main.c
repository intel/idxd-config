/*
 * Copyright(c) 2015-2019 Intel Corporation. All rights reserved.
 * Copyright(c) 2006 Linus Torvalds. All rights reserved.
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

#include <util/strbuf.h>
#include <util/util.h>
#include <util/main.h>

void main_handle_options(const char **argv, int argc, const char *usage_msg,
		struct cmd_struct *cmds, int num_cmds)
{
	int i;

	if (argc < 2) {
		help_show_man_page(NULL, argv[0], "ACCFG_MAN_VIEWER");
		goto exit_app;
	}

	if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-v")) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (argv[1][0] != '-') {
		for (i = 0; i < num_cmds; i++)
			if (!strcmp(argv[1], cmds[i].cmd)) {
				if (argc > 2 &&
						(!strcmp(argv[2], "--help") ||
						 !strcmp(argv[2], "-h"))) {
					help_show_man_page(argv[1], argv[0],
							"ACCFG_MAN_VIEWER");
					goto exit_app;
				} else
					return;
			}
		fprintf(stderr, "Unknown command: '%s'\n", argv[1]);
		goto exit_app;
	}

	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		if (argc > 2)
			help_show_man_page(argv[2], argv[0], "ACCFG_MAN_VIEWER");
		else
			help_show_man_page(NULL, argv[0], "ACCFG_MAN_VIEWER");
	}

	if (!strcmp(argv[1], "--list-cmds")) {
		for (i = 0; i < num_cmds; i++)
			printf("%s %s\n", argv[0], cmds[i].cmd);
		exit(0);
	}

exit_app:
	/* Exits app if not already */
	usage(usage_msg);
}

int main_handle_internal_command(int argc, const char **argv, void *ctx,
		struct cmd_struct *cmds, int num_cmds)
{
	int i;

	for (i = 0; i < num_cmds; i++) {
		struct cmd_struct *p = cmds+i;
		if (strcmp(p->cmd, argv[0]))
			continue;
		return p->fn(argc, argv, ctx);
	}

	fprintf(stderr, "Unknown command: '%s'\n", argv[0]);

	return -EINVAL;
}
