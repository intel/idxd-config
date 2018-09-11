include $(top_srcdir)/Makefile.am.in

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

pkginclude_HEADERS = ../libdsactl.h ../dsactl.h
lib_LTLIBRARIES = libdsactl.la

libdsactl_la_SOURCES =\
	libdsactl.h \
	private.h \
	../../util/log.c \
	../../util/log.h \
	../../util/sysfs.c \
	../../util/sysfs.h \
	libdsactl.c

libdsactl_la_LIBADD =\
	$(UDEV_LIBS) \
	$(UUID_LIBS) \
	$(KMOD_LIBS)

EXTRA_DIST += libdsactl.sym

libdsactl_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBDSACTL_CURRENT):$(LIBDSACTL_REVISION):$(LIBDSACTL_AGE) \
	-Wl,--version-script=$(top_srcdir)/dsactl/lib/libdsactl.sym
libdsactl_la_DEPENDENCIES = libdsactl.sym

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdsactl.pc
EXTRA_DIST += libdsactl.pc.in
CLEANFILES += libdsactl.pc
