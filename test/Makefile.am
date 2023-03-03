include $(top_srcdir)/Makefile.am.in

TESTS =\
	libaccfg \
	dsa_user_test_runner.sh \
	iaa_user_test_runner.sh \
	dsa_config_test_runner.sh

EXTRA_DIST += $(TESTS)

check_PROGRAMS =\
	libaccfg \
	dsa_test \
	iaa_test

if ENABLE_TEST
testprogdir = $(prefix)/libexec/accel-config/test/
testprog_DATA = common
testprog_SCRIPTS = dsa_user_test_runner.sh iaa_user_test_runner.sh dsa_config_test_runner.sh
testprog_PROGRAMS = dsa_test iaa_test

testconfdir = $(testprogdir)/configs/
testconf_DATA = configs/2g2q_user_1.conf configs/2g2q_user_2.conf
endif

LIBACCFG_LIB =\
       ../accfg/lib/libaccel-config.la

testcore =\
	core.c \
	../util/log.c \
	../util/sysfs.c \
	dsa.h \
	accfg_test.h

iaa_test_LDFLAGS = -lz -lcrypto

libaccfg_SOURCES = libaccfg.c $(testcore)
libaccfg_LDADD = $(LIBACCFG_LIB) $(UUID_LIBS)

dsa_test_SOURCES = dsa_test.c dsa.c dsa_prep.c accel_test.c
dsa_test_LDADD = $(LIBACCFG_LIB) $(UUID_LIBS)

iaa_test_SOURCES = iaa_test.c iaa.c iaa_prep.c accel_test.c \
		   algorithms/iaa_crc64.c algorithms/iaa_zcompress.c algorithms/iaa_compress.c \
		   algorithms/iaa_filter.c algorithms/iaa_crypto.c
iaa_test_LDADD = $(LIBACCFG_LIB) $(UUID_LIBS)
