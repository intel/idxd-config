include $(top_srcdir)/Makefile.am.in

TESTS =\
	libdsactl \
	config.sh

check_PROGRAMS =\
	libdsactl

LIBDSACTL_LIB =\
       ../dsactl/lib/libdsactl.la

testcore =\
	core.c \
	../util/log.c \
	../util/sysfs.c

libdsactl_SOURCES = libdsactl.c $(testcore)
libdsactl_LDADD = $(LIBDSACTL_LIB) $(UUID_LIBS) $(KMOD_LIBS)
