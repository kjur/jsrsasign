.PHONY: all

FILES = \
	jsrsasign-header.js \
	ext/yahoo-min.js \
	ext/cj/cryptojs-312-core-fix-min.js \
	ext/cj/x64-core_min.js \
	ext/cj/cipher-core_min.js \
	ext/cj/aes_min.js \
	ext/cj/tripledes_min.js \
	ext/cj/enc-base64_min.js \
	ext/cj/md5_min.js \
	ext/cj/sha1_min.js \
	ext/cj/sha256_min.js \
	ext/cj/sha224_min.js \
	ext/cj/sha512_min.js \
	ext/cj/sha384_min.js \
	ext/cj/ripemd160_min.js \
	ext/cj/hmac_min.js \
	ext/cj/pbkdf2_min.js \
	ext/base64-min.js \
	ext/jsbn-min.js \
	ext/jsbn2-min.js \
	ext/prng4-min.js \
	ext/rng-min.js \
	ext/rsa-min.js \
	ext/rsa2-min.js \
	ext/ec-min.js \
	ext/ec-patch-min.js \
	ext/json-sans-eval-min.js \
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
	min/dsa-modified-1.0.min.js \
	min/pkcs5pkey-1.0.min.js \
	min/keyutil-1.0.min.js \
	min/rsapem-1.1.min.js \
	min/rsasign-1.2.min.js \
	min/x509-1.1.min.js \
	min/jws-3.3.min.js \
	min/jwsjs-2.0.min.js


min/%.min.js: %.js
	java -jar ./yuicompressor-2.4.8.jar $^ -o $@


all: npm/lib/jsrsasign.js min/nodeutil-1.0.min.js

jsrsasign-latest-all-min.js: $(FILES)
	cat $^ | sed "s/\/\*! /\n\/\*! /g" > jsrsasign-4.9.0-mdcone-all-min.js
	cp jsrsasign-4.9.0-mdcone-all-min.js $@

npm/lib/jsrsasign.js: npm/lib/header.js jsrsasign-latest-all-min.js npm/lib/footer.js
	cat $^ > $@

