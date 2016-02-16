all: devel.pdf devel.html

#check:
#	xmlstarlet val --err --xsd /usr/share/xml/docbook/schema/xsd/5.0/docbook.xsd devel.db5.xml

prepare: wqy_mhei.xml wqy_mhei_m.xml custom.xsl fop.custom.conf

custom_titlepage.xsl: custom_titlepage.xsl.tmpl
	xsltproc /usr/share/xml/docbook/stylesheet/docbook-xsl-ns/template/titlepage.xsl $< > $@

custom_pdf.xsl: custom_pdf.xsl.tmpl custom_titlepage.xsl
	pwd | sed 's/\//\\\//g' > $@.pwdstr
	echo "s/__PWD__/`cat $@.pwdstr`/g;s/__FB_TTF__/`cat $@.pwdstr`\/fallbacks.ttf/g" > $@.sedscp
	sed `cat $@.sedscp` $< > $@
	rm -f $@.pwdstr $@.sedscp

custom_html.xsl: custom_html.xsl.tmpl
	pwd | sed 's/\//\\\//g' > $@.pwdstr
	echo "s/__PWD__/`cat $@.pwdstr`/g;s/__FB_TTF__/`cat $@.pwdstr`\/fallbacks.ttf/g" > $@.sedscp
	sed `cat $@.sedscp` $< > $@
	rm -f $@.pwdstr $@.sedscp

fop.custom.conf: fop.custom.conf.tmpl fallback.xml fallback_mono.xml
	pwd | sed 's/\//\\\//g' > $@.pwdstr
	echo "s/__PWD__/`cat $@.pwdstr`/g;s/__FB_TTF__/`cat $@.pwdstr`\/fallbacks.ttf/g" > $@.sedscp
	sed `cat $@.sedscp` $< > $@
	rm -f $@.pwdstr $@.sedscp

fallback.xml: fallbacks.ttf
	fop-ttfreader -fn -ttcname 'WenQuanYi Micro Hei' -fn 'Fallback' $< $@

fallback_mono.xml: fallbacks.ttf
	fop-ttfreader -ttcname 'WenQuanYi Micro Hei Mono' -fn 'FallbackMono' $< $@

%.html: %.db5.xml custom_html.xsl
	xsltproc custom_html.xsl $< > $@

%.pdf: %.db5.xml custom_pdf.xsl fop.custom.conf
	xsltproc custom_pdf.xsl $< > $@.fo
	fop -c fop.custom.conf -fo $@.fo -pdf $@
	rm -f $@.fo

clean:
	rm -f *.pdf *.html *.fo

