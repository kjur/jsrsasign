all:
	join-minify

join-minify:
	( \
		cat \
		ext/yahoo-min.js \
		ext/cryptojs-312-core-fix-min.js \
		ext/sha256-min.js ext/sha512-min.js \
		ext/md5-min.js \
		ext/sha1-min.js ext/ripemd160-min.js \
		ext/base64-min.js ext/jsbn-min.js ext/jsbn2-min.js ext/prng4-min.js ext/rng-min.js \
		ext/rsa-min.js ext/rsa2-min.js ext/ec-min.js ext/ec-patch-min.js \
		asn1-1.0.min.js asn1hex-1.1.min.js asn1x509-1.0.min.js asn1csr-1.0.min.js asn1tsp-1.0.min.js\
		base64x-1.1.min.js crypto-1.1.min.js ecdsa-modified-1.0.min.js ecparam-1.0.min.js \
		dsa-modified-1.0.min.js jws-3.2.min.js jwsjs-2.0.min.js\
		pkcs5pkey-1.0.min.js keyutil-1.0.min.js rsapem-1.1.min.js rsasign-1.2.min.js x509-1.1.min.js \
		| sed "s/\/*! /\n\/*! /g" > jsrsasign-4.9.0-mdcone-all-min.js ; \
		cp jsrsasign-4.9.0-mdcone-all-min.js jsrsasign-latest-all-min.js \
		)
