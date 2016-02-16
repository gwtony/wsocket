################ Edit lines below #################

PREFIX=/usr/local/weibo_socket
LIBDIR=$(PREFIX)/lib
HEADERDIR=$(PREFIX)/include

INSTALL=install

################ DON'T Edit lines below #################

CFLAGS+=-I. -Wall -g -D_GNU_SOURCE -O2 -fPIC

LDFLAGS+=-lm -lz -lcrypto -lssl -shared

SERVERFNAME=$(APPNAME)d

sources=my_crypt.c frame.c

objects=$(sources:.c=.o)

all: libweibosocket_protocol.ld.so.conf libweibosocket_protocol.so libweibosocket_protocol.a

libweibosocket_protocol.ld.so.conf: libweibosocket_protocol.ld.so.conf.tmpl
	@echo "Generating $@"
	@echo $(LIBDIR) | sed 's/\//\\\//g' > /tmp/.sdfasdsdsfa
	@sed "s/__LIBDIR__/`cat /tmp/.sdfasdsdsfa`/g" $< > $@
	@rm -f /tmp/.sdfasdsdsfa

libweibosocket_protocol.so: $(objects)
	$(CC) $(LDFLAGS) -o $@ $^

libweibosocket_protocol.a: $(objects)
	ar -cr $@ $^
	ranlib $@

install: all
	[ -d $(PREFIX) ] || mkdir -p $(PREFIX)
	[ -d $(LIBDIR) ] || mkdir $(LIBDIR)
	[ -d $(HEADERDIR) ] || mkdir $(HEADERDIR)

	$(INSTALL) libweibosocket_protocol.so $(LIBDIR)
	$(INSTALL) libweibosocket_protocol.a $(LIBDIR)
	$(INSTALL) *.h $(HEADERDIR)
	$(INSTALL) libweibosocket_protocol.ld.so.conf /etc/ld.so.conf.d/
	ldconfig

clean:
	rm -f $(objects) libweibosocket_protocol.so libweibosocket_protocol.a libweibosocket_protocol.ld.so.conf

