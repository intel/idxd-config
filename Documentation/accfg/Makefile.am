#SPDX-License-Identifier: GPL-2.0
#Copyright(c) 2023-2026 Intel Corporation. All rights reserved

if USE_ASCIIDOCTOR

do_subst = sed -e 's,@Utility@,Dsactl,g' -e's,@utility@,accfg,g'
CONFFILE = asciidoctor-extensions.rb
asciidoctor-extensions.rb: ../asciidoctor-extensions.rb.in
	$(AM_V_GEN) $(do_subst) < $< > $@

else

do_subst = sed -e 's,UTILITY,accfg,g'
CONFFILE = asciidoc.conf
asciidoc.conf: ../asciidoc.conf.in
	$(AM_V_GEN) $(do_subst) < $< > $@

endif

man1_MANS = \
	accel-config.1 \
	accel-config-list.1 \
	accel-config-load-config.1 \
	accel-config-save-config.1 \
	accel-config-config-device.1 \
	accel-config-config-engine.1 \
	accel-config-config-group.1 \
	accel-config-config-wq.1 \
	accel-config-disable-device.1 \
	accel-config-disable-wq.1 \
	accel-config-enable-wq.1 \
	accel-config-enable-device.1 \
	accel-config-config-user-default.1

EXTRA_DIST = \
	$(man1_MANS) \
	accel-config.txt \
	accel-config-list.txt \
	accel-config-load-config.txt \
	accel-config-save-config.txt \
	accel-config-config-device.txt \
	accel-config-config-engine.txt \
	accel-config-config-group.txt \
	accel-config-config-wq.txt \
	accel-config-disable-device.txt \
	accel-config-disable-wq.txt \
	accel-config-enable-wq.txt \
	accel-config-enable-device.txt \
	accel-config-config-user-default.txt

CLEANFILES = $(man1_MANS)

XML_DEPS = \
	../../version.m4 \
	Makefile \
	$(CONFFILE) \
	../copyright.txt

RM ?= rm -f

if USE_ASCIIDOCTOR

%.1: %.txt $(XML_DEPS)
	$(AM_V_GEN)$(RM) $@+ $@ && \
		$(ASCIIDOC) -b manpage -d manpage -acompat-mode \
		-I. -rasciidoctor-extensions \
		-amansource=accfg -amanmanual="accfg Manual" \
		-aaccfg_version=$(VERSION) -o $@+ $< && \
		mv $@+ $@

else

%.xml: %.txt $(XML_DEPS)
	$(AM_V_GEN)$(RM) $@+ $@ && \
		$(ASCIIDOC) -b docbook -d manpage -f asciidoc.conf \
		--unsafe -aaccfg_version=$(VERSION) -o $@+ $< && \
		mv $@+ $@

%.1: %.xml $(XML_DEPS)
	$(AM_V_GEN)$(RM) $@ && \
		$(XMLTO) -o . -m ../manpage-normal.xsl man $<

endif
