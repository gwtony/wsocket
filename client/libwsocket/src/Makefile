include ../config.mk

CFLAGS+=-I../include -I$(INCDIR_LIBWSOCKET_PROTOCOL) -Wall -g -D_GNU_SOURCE -O0 -fPIC

LDFLAGS+=-lm -L$(LIBDIR_LIBWSOCKET_PROTOCOL) -lweibosocket_protocol -lcrypto -lssl -lz -shared

sources=context.c  ds_hasht.c  ds_llist.c ds_stack.c engine.c  socket_end.c util_streambuf.c  util_time.c

objects=$(sources:.c=.o)

all: libweibosocket.ld.so.conf libweibosocket.so libweibosocket.a

libweibosocket.ld.so.conf: libweibosocket.ld.so.conf.tmpl
	@echo "Generating $@"
	@echo $(LIBDIR) | sed 's/\//\\\//g' > /tmp/.sdfsasasdsdsfa
	@sed "s/__LIBDIR__/`cat /tmp/.sdfsasasdsdsfa`/g" $< > $@
	@rm -f /tmp/.sdfsasasdsdsfa

libweibosocket.so: $(objects)
	$(CC) -o $@ $^ $(LDFLAGS)

libweibosocket.a: $(objects)
	ar -cr $@ $^
	ranlib $@

install: all
	$(INSTALL) libweibosocket.so $(LIBDIR)
	$(INSTALL) libweibosocket.ld.so.conf /etc/ld.so.conf.d/
	ldconfig

clean:
	rm -f $(objects) libweibosocket.a libweibosocket.so libweibosocket.ld.so.conf *.gcda *.gcno

