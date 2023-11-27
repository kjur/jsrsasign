.PHONY: all

FILES_MIN = \
	min/asn1-1.0.min.js \
	min/asn1hex-1.1.min.js \
	min/asn1x509-1.0.min.js \
	min/asn1cms-1.0.min.js \
	min/asn1tsp-1.0.min.js \
	min/asn1cades-1.0.min.js \
	min/asn1csr-1.0.min.js \
	min/asn1ocsp-1.0.min.js \
	min/base64x-1.1.min.js \
	min/crypto-1.1.min.js \
	min/ecdsa-modified-1.0.min.js \
	min/ecparam-1.0.min.js \
	min/dsa-2.0.min.js \
	min/keyutil-1.0.min.js \
	min/rsapem-1.1.min.js \
	min/rsasign-1.2.min.js \
	min/x509-1.1.min.js \
	min/jws-3.3.min.js \
	min/jwsjs-2.0.min.js \
	min/x509crl.min.js \
	min/nodeutil-1.0.min.js

JSDOC_SRC = \
	asn1hex-1.1.js \
	rsapem-1.1.js \
	rsasign-1.2.js \
	x509-1.1.js \
	keyutil-1.0.js \
	asn1-1.0.js \
	asn1x509-1.0.js \
	asn1cms-1.0.js \
	asn1tsp-1.0.js \
	asn1cades-1.0.js \
	asn1csr-1.0.js \
	asn1ocsp-1.0.js \
	crypto-1.1.js \
	ecdsa-modified-1.0.js \
	ecparam-1.0.js \
	dsa-2.0.js \
	base64x-1.1.js \
	jws-3.3.js \
	jwsjs-2.0.js \
	x509crl.js \
	nodeutil-1.0.js

FILES_EXT_MIN = \
	ext/ec-min.js \
	ext/rsa-min.js \
	ext/rsa2-min.js

JSRUN=jsrun-jsrsasign.sh

JSDOCOUTDIR1=_tmp

APIDOCDIR=api

jsdoc:
	rm -rf $(APIDOCDIR)
	mkdir $(APIDOCDIR)
	( \
	cd src; \
	${JSRUN} $(JSDOC_SRC) \
	-d=../$(APIDOCDIR) -v \
	)
	mv $(APIDOCDIR)/symbols/_global_.html $(APIDOCDIR)/symbols/global__.html
	find $(APIDOCDIR) -type f -name "*.html" -print0 | xargs -0 sed -i.bak -e "s/_global_/global__/g"
	find $(APIDOCDIR) -type f -name "*.html" -print0 | xargs -0 sed -i.bak -e "s/2012-2020/2012-2023/g"
	find $(APIDOCDIR) -type f -name "*.html.bak" -exec rm {} \;
	rm -rf ../../_gitpg/jsrsasign/api
	cp -r $(APIDOCDIR) ../../_gitpg/jsrsasign/api

all-min: $(FILES_MIN)
	@echo "all min converted."

all-ext-min: $(FILES_EXT_MIN)
	@echo "all ext min converted."

min/%.min.js: src/%.js
	yuicmp $^ -o $@

ext/%-min.js: ext/%.js
	yuicmp $^ -o $@

gitadd-all-doc:
	git add api/*.html api/symbols/*.html api/symbols/src/*.html LICENSE.txt

gitadd-release:
	git add ChangeLog.txt Makefile jsrsasign-*-min.js min/*.js src/*.js npm/package.json npm/lib/jsrsasign*.js npm/lib/{header,footer,lib}.js src/*.js test/qunit-do-*.html test/x509crl.html README.md npm/README.md tool/*.html npm_util/*.* npm_util/lib/*.* npm/test/t_*.js

gitadd: gitadd-all-doc gitadd-release
	@echo done

rsync-test:
	rsync -n -av api/ ../../_gitpg/jsrsasign/api
	rsync -n -av --include="[a-z]*.js" --exclude="*" src/ ../../_gitpg/jsrsasign/src
	rsync -n -av --include="[a-z]*.min.js" --exclude="*" min/ ../../_gitpg/jsrsasign/min
	rsync -n -av --include="[a-z]*.js" --exclude="*" ext/ ../../_gitpg/jsrsasign/ext
	rsync -n -av --include="[a-z]*.html" --exclude="*" test/ ../../_gitpg/jsrsasign/test

rsync:
	rsync -av api/ ../../_gitpg/jsrsasign/api
	rsync -av --include="[a-z]*.js" --exclude="*" src/ ../../_gitpg/jsrsasign/src
	rsync -av --include="[a-z]*.min.js" --exclude="*" min/ ../../_gitpg/jsrsasign/min
	rsync -av --include="[a-z]*.js" --exclude="*" ext/ ../../_gitpg/jsrsasign/ext
	rsync -av --include="[a-z]*.html" --exclude="*" test/ ../../_gitpg/jsrsasign/test


