include ../config.mk

CFLAGS+=-I. -pthread -Wall -g -D_GNU_SOURCE -O3

LDFLAGS+=-lpthread -lm -lssl -lcrypto -lrt -lweibosocket_protocol -lz

SERVERFNAME=$(APPNAME)d
ADMINNAME=$(APPNAME)d_admin

sources=cJSON.c ds_llist.c ds_olist.c  ds_queue2.c ds_stack.c util_time.c util_streambuf.c util_log.c util_syscall.c json_conf.c  main.c  pipeline_end.c  socket_end.c l7server.c upstream.c thr_monitor.c http_xff.c

objects=$(sources:.c=.o)

all: $(SERVERFNAME)

$(SERVERFNAME): $(objects)
	$(CC) -o $@ $^ $(LDFLAGS)
	cp admin.sh $(ADMINNAME) && chmod a+x $(ADMINNAME)

install: all
	$(INSTALL) $(SERVERFNAME) $(ADMINNAME) ../dist/sbin/

clean:
	rm -f $(objects) $(SERVERFNAME) $(ADMINNAME)

