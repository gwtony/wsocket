include ../../config.mk

templates=l7_nginx_phpfpm.tmpl  main.tmpl

objects=$(templates:.tmpl=.conf)

all: $(objects)

%.conf: %.tmpl
	@echo "Generating $@"
	@echo $(PREFIX) | sed 's/\//\\\//g' > /tmp/.template
	@sed "s/__PREFIX__/`cat /tmp/.template`/g" $< > $@
	@rm -f /tmp/.template

clean:
	rm -rf $(objects)

install:
	$(INSTALL) $(objects) ../../dist/conf/

