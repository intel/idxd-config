/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <limits.h>
#include <syslog.h>
#include <test.h>
#include <util/parse-options.h>

static char *result(int rc)
{
	if (rc == EXIT_SKIP)
		return "SKIP";
	else if (rc)
		return "FAIL";
	else
		return "PASS";
}

int cmd_test(int argc, const char **argv, struct accfg_ctx *ctx)
{
	struct accfg_test *test;
	int loglevel = LOG_DEBUG, i, rc;
	const char * const u[] = {
		"accel-config test [<options>]",
		NULL
	};
	const struct option options[] = {
	OPT_INTEGER('l', "loglevel", &loglevel,
		"set the log level (default LOG_DEBUG)"),
	OPT_END(),
	};

	argc = parse_options(argc, argv, options, u, 0);

	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);
	else
		test = accfg_test_new(0);
	if (!test)
		return EXIT_FAILURE;

	printf("run test_libaccfg\n");
	rc = test_libaccfg(loglevel, test, ctx);
	fprintf(stderr, "test-libaccfg: %s\n", result(rc));
	free(test);
	if (rc)
		return rc;
	printf("SUCCESS!\n");

	return 0;
}
