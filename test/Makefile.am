include $(top_srcdir)/Makefile.am.in

TESTS =\
	libaccfg

check_PROGRAMS =\
	libaccfg \
	dsa_test

LIBACCFG_LIB =\
       ../accfg/lib/libaccel-config.la

testcore =\
	core.c \
	../util/log.c \
	../util/sysfs.c

libaccfg_SOURCES = libaccfg.c $(testcore)
libaccfg_LDADD = $(LIBACCFG_LIB) $(UUID_LIBS) $(KMOD_LIBS)

dsa_test_SOURCES = dsa_test.c dsa.c prep.c
dsa_test_LDADD = $(LIBACCFG_LIB) $(UUID_LIBS)
