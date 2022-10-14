include Makefile.am.in

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
SUBDIRS = . accfg/lib accfg
if ENABLE_DOCS
SUBDIRS += Documentation/accfg
endif
if ENABLE_TEST
SUBDIRS += test
endif

BUILT_SOURCES = version.m4
version.m4: FORCE
	$(AM_V_GEN)$(top_srcdir)/git-version-gen

FORCE:

noinst_SCRIPTS = rhel/accfg.spec rhel/accfg-test.spec
CLEANFILES += $(noinst_SCRIPTS)

do_rhel_subst = sed -e 's,VERSION,$(VERSION),g' \
            -e 's,DNAME,accel-config-devel,g' \
            -e '/^%defattr.*/d' \
	    -e 's,LNAME,accel-config-libs,g'

rhel/accfg.spec: accfg.spec.in Makefile.am version.m4
	$(AM_V_GEN)$(MKDIR_P) rhel; $(do_rhel_subst) < $< > $@

rhel/accfg-test.spec: accfg-test.spec.in Makefile.am version.m4
	$(AM_V_GEN)$(MKDIR_P) rhel; $(do_rhel_subst) < $< > $@

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
endif

contrib_configs = contrib/configs/*
contribdir = $(sysconfdir)/accel-config/contrib/configs
contrib_DATA = $(contrib_configs)

EXTRA_DIST += $(contrib_configs) accfg.spec.in accfg-test.spec.in

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
	util/abspath.c \
	util/bitmap.c \
	util/bitmap.h \
	util/filter.c \
	util/filter.h \
	util/help.c \
	util/json.h \
	util/list.h \
	util/log.h \
	util/main.c \
	util/main.h \
	util/parse-options.c \
	util/parse-options.h \
	util/size.c \
	util/size.h \
	util/strbuf.c \
	util/strbuf.h \
	util/sysfs.h \
	util/usage.c \
	util/util.h \
	util/wrapper.c \
	builtin.h \
	test.h
