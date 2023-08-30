/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <builtin.h>
#include <accfg/libaccel_config.h>
#include <ccan/array_size/array_size.h>
#include <util/parse-options.h>
#include <util/strbuf.h>
#include <util/util.h>
#include <util/main.h>

const char accfg_usage_string[] =
	"accel-config [--list-cmds] [-h | --help] [-v | --version] COMMAND [ARGS]\n\n"
	" 'accel-config --help COMMAND' for information on a specific command\n"
	" 'accel-config --list-cmds' for a list of available commands\n"
	" 'accel-config --version' for version info";

static struct cmd_struct commands[] = {
	{"list", cmd_list},
	{"load-config", cmd_config},
	{"save-config",  cmd_save},
	{"disable-device", cmd_disable_device},
	{"enable-device", cmd_enable_device},
	{"disable-wq", cmd_disable_wq},
	{"enable-wq", cmd_enable_wq},
	{"config-device", cmd_config_device},
	{"config-group", cmd_config_group},
	{"config-wq", cmd_config_wq},
	{"config-engine", cmd_config_engine},
	{"config-user-default", cmd_config_default},
#ifdef ENABLE_TEST
	{"test", cmd_test},
#endif
};

int main(int argc, const char **argv)
{
	struct accfg_ctx *ctx;
	unsigned int last_error;
	int rc;

	/* Look for flags.. */
	main_handle_options(argv, argc, accfg_usage_string, commands,
			    ARRAY_SIZE(commands));

	if (access("/sys/module/idxd", F_OK)) {
		fprintf(stderr, "idxd kernel module not loaded\n");
		return EXIT_FAILURE;
	}

	rc = accfg_new(&ctx);
	if (rc)
		goto error_exit;

	argv++;
	argc--;
	rc = main_handle_internal_command(argc, argv, ctx, commands,
				     ARRAY_SIZE(commands));

	last_error = accfg_ctx_get_last_error(ctx);
	if (rc && last_error) {
		struct accfg_device *d;
		struct accfg_group *g;
		struct accfg_wq *w;
		struct accfg_engine *e;

		printf("Error[%#10x] ", last_error);
		d = accfg_ctx_get_last_error_device(ctx);
		g = accfg_ctx_get_last_error_group(ctx);
		w = accfg_ctx_get_last_error_wq(ctx);
		e = accfg_ctx_get_last_error_engine(ctx);
		if (d)
			printf("%s", accfg_device_get_devname(d));
		if (g)
			printf("/%s", accfg_group_get_devname(g));
		if (w)
			printf("/%s", accfg_wq_get_devname(w));
		if (e)
			printf("/%s", accfg_engine_get_devname(e));
		printf(": %s\n", accfg_ctx_get_last_error_str(ctx));
	}
	accfg_unref(ctx);

	if (!rc)
		return EXIT_SUCCESS;
error_exit:
	errno = abs(rc);

	return EXIT_FAILURE;
}
