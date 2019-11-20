include Makefile.am.in

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
SUBDIRS = . accfg/lib accfg
if ENABLE_DOCS
SUBDIRS += Documentation/accfg
endif
SUBDIRS += test

BUILT_SOURCES = version.m4
version.m4: FORCE
	$(AM_V_GEN)$(top_srcdir)/git-version-gen

FORCE:

noinst_SCRIPTS = rhel/accfg.spec
CLEANFILES += $(noinst_SCRIPTS)

do_rhel_subst = sed -e 's,VERSION,$(VERSION),g' \
            -e 's,DNAME,accel-config-devel,g' \
            -e '/^%defattr.*/d' \
	    -e 's,LNAME,accel-config-libs,g'

rhel/accfg.spec: accfg.spec.in Makefile.am version.m4
	$(AM_V_GEN)$(MKDIR_P) rhel; $(do_rhel_subst) < $< > $@

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
endif

accfgconf_file = contrib/accel-config.conf.sample
accfgconfdir = $(sysconfdir)/accel-config/
accfgconf_DATA = $(accfgconf_file)

noinst_LIBRARIES = libccan.a
libccan_a_SOURCES = \
        ccan/str/str.h \
        ccan/str/str_debug.h \
        ccan/str/str.c \
        ccan/str/debug.c \
        ccan/list/list.h \
        ccan/list/list.c \
        ccan/container_of/container_of.h \
        ccan/check_type/check_type.h \
        ccan/build_assert/build_assert.h \
        ccan/array_size/array_size.h \
        ccan/minmax/minmax.h \
        ccan/short_types/short_types.h \
        ccan/endian/endian.h


noinst_LIBRARIES += libutil.a
libutil_a_SOURCES = \
	util/parse-options.c \
	util/parse-options.h \
	util/usage.c \
	util/size.c \
	util/main.c \
	util/help.c \
	util/strbuf.c \
	util/wrapper.c \
	util/filter.c \
	util/bitmap.c \
	util/abspath.c
