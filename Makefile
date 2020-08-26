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
	min/x509crl.min.js
 
FILES_EXT_MIN = \
	ext/ec-min.js \
	ext/rsa-min.js \
	ext/rsa2-min.js

all-min: $(FILES_MIN)
	@echo "all min converted."

all-ext-min: $(FILES_EXT_MIN)
	@echo "all ext min converted."

min/%.min.js: src/%.js
	yuicmp $^ -o $@

ext/%-min.js: ext/%.js
	yuicmp $^ -o $@

gitadd-all-doc:
	git add api/*.html api/symbols/*.html api/symbols/src/*.html

gitadd-release:
	git add ChangeLog.txt Makefile bower.json jsrsasign-*-min.js min/*.js src/*.js npm/package.json npm/lib/jsrsasign*.js src/*.js test/qunit-do-*.html

gitadd: gitadd-all-doc gitadd-release
	@echo done