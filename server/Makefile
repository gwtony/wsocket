include config.mk

all:
%:
	make -C src $@
	make -C doc $@

install:
	[ -d $(PREFIX) ] || mkdir -p $(PREFIX)
	[ -d $(SBINDIR) ] || mkdir $(SBINDIR)
	[ -d $(CONFDIR) ] || mkdir $(CONFDIR)
	[ -d $(MODDIR) ] || mkdir $(MODDIR)

	make -C src $@
	make -C doc $@

	$(INSTALL) dist/sbin/* $(SBINDIR)/
	[ -e dist/conf/main.conf ] || $(INSTALL) dist/conf/*.conf $(CONFDIR)/

clean:
	make -C src $@
	make -C doc $@
	rm -rf dist/sbin/*
	rm -rf dist/conf/*

