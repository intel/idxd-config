include $(top_srcdir)/Makefile.am.in

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

pkginclude_HEADERS = ../libaccel_config.h
lib_LTLIBRARIES = libaccel-config.la

libaccel_config_la_SOURCES =\
	private.h \
	../../util/list.h \
	../../util/log.c \
	../../util/log.h \
	../../util/sysfs.c \
	../../util/sysfs.h \
	libaccfg.c

libaccel_config_la_LIBADD =\
	$(UUID_LIBS)

EXTRA_DIST += libaccel-config.sym

libaccel_config_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBACCFG_CURRENT):$(LIBACCFG_REVISION):$(LIBACCFG_AGE) \
	-Wl,--version-script=$(top_srcdir)/accfg/lib/libaccel-config.sym
libaccel_config_la_DEPENDENCIES = libaccel-config.sym

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libaccel-config.pc
EXTRA_DIST += libaccel-config.pc.in
CLEANFILES += libaccel-config.pc
