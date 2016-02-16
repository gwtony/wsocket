include ../config.mk
OUTPUTDIR=./output

LCOV    := /usr/bin/lcov
GENHTML := /usr/bin/genhtml
GENDESC := /usr/bin/gendesc
GENPNG  := /usr/bin/genpng

CFLAGS+=-I../include -I$(INCDIR_LIBWSOCKET_PROTOCOL) -O0 -fprofile-arcs -ftest-coverage -g

LDFLAGS+=-L../src -lweibosocket -L$(LIBDIR_LIBWSOCKET_PROTOCOL) -lweibosocket_protocol -pthread -lz -lm -lssl -lgcov

all: client

client: client.o
	gcc $^ -o $@ $(LDFLAGS)

test: client get_1k post_8k crypt_zip post_crypt post_zip keep_alive
	 [ -d $(OUTPUTDIR) ] || mkdir $(OUTPUTDIR)
	$(GENHTML) -q -o $(OUTPUTDIR) ./*.info	
	zip -r output.zip $(OUTPUTDIR)/*

get_1k:
	@echo
	@echo '*'
	@echo '* Test case 1: running ./client 1000 http://10.73.31.119/1k.html'
	@echo '*'
	@echo
	$(LCOV) --zerocounters --directory ../
	./client 1000 http://10.73.31.119/1k.html
	$(LCOV) --capture --directory ../ --output-file get_1k.info --test-name get_1k

post_8k:
	@echo
	@echo '*'
	@echo '* Test case 2: running ./client 8000 http://10.73.31.119/8k.html 8192'
	@echo '*'
	@echo
	[ -f /tmp/client.crt ] && rm /tmp/client.crt
	$(LCOV) --zerocounters --directory ../
	./client 8000 http://10.73.31.119/8k.html 8192
	$(LCOV) --capture --directory ../ --output-file post_8k.info --test-name post_8k

crypt_zip:
	@echo
	@echo '*'
	@echo '* Test case 3: running ./client 8000 http://10.73.31.119/8k.html 8192 1 1'
	@echo '*'
	@echo
	export WSOCKET_KEEPALIVE="0"
	$(LCOV) --zerocounters --directory ../
	./client 10000 http://10.73.31.119/8k.html 8192 1 1
	$(LCOV) --capture --directory ../ --output-file crypt_zip.info --test-name crypt_zip

post_crypt:
	@echo
	@echo '*'
	@echo '* Test case 3: running ./client 8000 http://10.73.31.119/8k.html 8192 1 0'
	@echo '*'
	@echo
	$(LCOV) --zerocounters --directory ../
	./client 8000 http://10.73.31.119/8k.html 8192 1 0
	$(LCOV) --capture --directory ../ --output-file post_crypt.info --test-name post_crypt

post_zip:
	@echo
	@echo '*'
	@echo '* Test case 3: running ./client 8000 http://10.73.31.119/8k.html 8192 0 1'
	@echo '*'
	@echo
	$(LCOV) --zerocounters --directory ../
	./client 8000 http://10.73.31.119/8k.html 8192 0 1
	$(LCOV) --capture --directory ../ --output-file post_zip.info --test-name post_zip

keep_alive:
	@echo
	@echo '*'
	@echo '* Test case 3: running ./client 8000 http://10.73.31.119/8k.html 8192 1 1'
	@echo '*'
	@echo
	export WSOCKET_KEEPALIVE="1"
	export WSOCKET_SERVER="10.75.13.92"
	export WSOCKET_PORT="8001"
	export WSOCKET_CERT_CA="/tmp/ca.crt"
	export WSOCKET_CERT_SERVER="/tmp/client.crt"
	$(LCOV) --zerocounters --directory ../
	./client 10000 http://10.73.31.119/8k.html 8192 1 1
	$(LCOV) --capture --directory ../ --output-file keep_alive.info --test-name keep_alive

clean:
	rm -rf *.o client *.info *.gcda *.gcno *.zip ./output/*

