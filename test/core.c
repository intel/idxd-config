/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */

#include <linux/version.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <test.h>

#include <util/log.h>
#include <util/sysfs.h>
#include <accfg/libaccel_config.h>
#include <ccan/array_size/array_size.h>

#define KVER_STRLEN 20

struct accfg_test {
	unsigned int kver;
	int attempt;
	int skip;
};

static unsigned int get_system_kver(void)
{
	const char *kver = getenv("KVER");
	struct utsname utsname;
	int a, b, c;

	if (!kver) {
		uname(&utsname);
		kver = utsname.release;
	}

	if (sscanf(kver, "%d.%d.%d", &a, &b, &c) != 3)
		return LINUX_VERSION_CODE;

	return KERNEL_VERSION(a,b,c);
}

struct accfg_test *accfg_test_new(unsigned int kver)
{
	struct accfg_test *test = calloc(1, sizeof(*test));

	if (!test)
		return NULL;

	if (!kver)
		test->kver = get_system_kver();
	else
		test->kver = kver;

	return test;
}

int accfg_test_result(struct accfg_test *test, int rc)
{
	if (accfg_test_get_skipped(test))
		fprintf(stderr, "attempted: %d skipped: %d\n",
				accfg_test_get_attempted(test),
				accfg_test_get_skipped(test));
	if (rc && rc != EXIT_SKIP)
		return rc;
	if (accfg_test_get_skipped(test) >= accfg_test_get_attempted(test))
		return EXIT_SKIP;
	/* return success if no failures and at least one test not skipped */
	return 0;
}

static char *kver_str(char *buf, unsigned int kver)
{
	snprintf(buf, KVER_STRLEN, "%d.%d.%d",  (kver >> 16) & 0xffff,
			(kver >> 8) & 0xff, kver & 0xff);
	return buf;
}

int __accfg_test_attempt(struct accfg_test *test, unsigned int kver,
		const char *caller, int line)
{
	char requires[KVER_STRLEN], current[KVER_STRLEN];

	test->attempt++;
	if (kver <= test->kver)
		return 1;
	fprintf(stderr, "%s: skip %s:%d requires: %s current: %s\n",
			__func__, caller, line, kver_str(requires, kver),
			kver_str(current, test->kver));
	test->skip++;
	return 0;
}

void __accfg_test_skip(struct accfg_test *test, const char *caller, int line)
{
	test->skip++;
	test->attempt = test->skip;
	fprintf(stderr, "%s: explicit skip %s:%d\n", __func__, caller, line);
}

int accfg_test_get_attempted(struct accfg_test *test)
{
	return test->attempt;
}

int accfg_test_get_skipped(struct accfg_test *test)
{
	return test->skip;
}
