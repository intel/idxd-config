include $(top_srcdir)/Makefile.am.in

TESTS =\
	libaccfg \
	dsa_user_test_runner.sh

EXTRA_DIST += $(TESTS)

check_PROGRAMS =\
	libaccfg \
	dsa_test

if ENABLE_TEST
testprogdir = $(datadir)/accel-config/test/
testprog_DATA = common
testprog_SCRIPTS = dsa_user_test_runner.sh
testprog_PROGRAMS = dsa_test

testconfdir = $(testprogdir)/configs/
testconf_DATA = configs/2g2q_user_1.conf
endif

LIBACCFG_LIB =\
       ../accfg/lib/libaccel-config.la

testcore =\
	core.c \
	../util/log.c \
	../util/sysfs.c \
	dsa.h \
	accfg_test.h

libaccfg_SOURCES = libaccfg.c $(testcore)
libaccfg_LDADD = $(LIBACCFG_LIB) $(UUID_LIBS)

dsa_test_SOURCES = dsa_test.c dsa.c prep.c
dsa_test_LDADD = $(LIBACCFG_LIB) $(UUID_LIBS)
