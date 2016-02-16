include config.mk

all:
%:
	make -C src $@

install:
	[ -d $(PREFIX) ] || mkdir -p $(PREFIX)
	[ -d $(LIBDIR) ] || mkdir $(LIBDIR)
	[ -d $(INCDIR) ] || mkdir $(INCDIR)

	make -C src $@
	$(INSTALL) include/* $(INCDIR)/

clean:
	make -C src $@

