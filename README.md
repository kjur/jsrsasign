jsrsasign
=========

The 'jsrsasign' (RSA-Sign JavaScript Library) is an opensource free pure JavaScript cryptographic library supports RSA/RSAPSS/ECDSA/DSA signing/validation, ASN.1, PKCS#1/5/8 private/public key, X.509 certificate, CRL, CMS SignedData, TimeStamp and CAdES and JSON Web Signature(JWS)/Token(JWT)/Key(JWK).

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://github.com/kjur/jsrsasign/blob/master/LICENSE.txt)
[![bower](https://img.shields.io/bower/v/jsrsasign.svg?maxAge=2592000)](https://libraries.io/bower/jsrsasign)
[![npm version](https://badge.fury.io/js/jsrsasign.svg)](https://badge.fury.io/js/jsrsasign)
[![CDNJS](https://img.shields.io/cdnjs/v/jsrsasign.svg)](https://cdnjs.com/libraries/jsrsasign)

Public page is https://kjur.github.io/jsrsasign .

[github TOP](https://kjur.github.io/jsrsasign/)|[API doc](https://kjur.github.io/jsrsasign/api/)|[Wiki](https://github.com/kjur/jsrsasign/wiki)|[Node sample](https://github.com/kjur/jsrsasign/tree/master/sample_node)

DIFFERENCE WITH CRYPTO MODULE
-----------------------------

Here is the difference between bundled ['Crypto' module](http://nodejs.org/api/crypto.html) 
and this 'jsrsasign' module.

- Crypto module
    - fast
    - works only on Node.js
    - OpenSSL based
    - lacking ASN.1 functionality
    - provides symmetric ciphers
    - lacking RSAPSS signing
- jsrsasign module
    - slow
    - implemented in pure JavaScript
    - works on both Node.js(server) and browsers(client)
    - provides ASN.1 parsing/generation functionality
    - lacking symmetric ciphers
    - provides RSAPSS signing
    - also provides support for JSON Web Signatures (JWS) and JSON Web Token (JWT)

AVAILABLE CLASSES AND METHODS
-----------------------------

Most of the classes and methods defined in jsrsasign 
available in this jsrsasign npm module.

After loading the module,

    > var r = require('jsrsasign');
    > var r = require('jsrsasign-util'); // for file I/O utilities

You can refer name spaces, classes, methods and functions 
by following variables:

- r.BigInteger - BigInteger class
- r.RSAKey - [RSAKey class](https://kjur.github.io/jsrsasign/api/symbols/RSAKey.html)
- r.ECDSA - [KJUR.crypto.ECDSA class](https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.ECDSA.html)
- r.DSA - [KJUR.crypto.DSA class](https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.DSA.html)
- r.Signature - [KJUR.crypto.Signature class](https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html)
- r.MessageDigest - [KJUR.crypto.MessageDigest class](https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.MessageDigest.html)
- r.Mac - [KJUR.crypto.Mac class](https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Mac.html)
- r.KEYUTIL - [KEYUTIL class](https://kjur.github.io/jsrsasign/api/symbols/KEYUTIL.html)
- r.ASN1HEX - [ASN1HEX class](https://kjur.github.io/jsrsasign/api/symbols/ASN1HEX.html)
- r.crypto - [KJUR.crypto name space](https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.html)
- r.asn1 - [KJUR.asn1 name space](https://kjur.github.io/jsrsasign/api/symbols/KJUR.asn1.html)
- r.jws - [KJUR.jws name space](https://kjur.github.io/jsjws/api/)

Please see API reference in the above links.

EXAMPLE(1) SIGNATURE
--------------------

Loading encrypted PKCS#5 private key:

    > var rs = require('jsrsasign');
    > var rsu = require('jsrsasign-util');
    > var pem = rsu.readFile('z1.prv.p5e.pem');
    > var prvKey = rs.KEYUTIL.getKey(pem, 'passwd');

Sign string 'aaa' with the loaded private key:

    > var sig = new a.Signature({alg: 'SHA1withRSA'});
    > sig.init(prvKey);
    > sig.updateString('aaa');
    > var sigVal = sig.sign();
    > sigVal
    'd764dcacb...'

MORE TUTORIALS AND SAMPLES
--------------------
- [Tutorials in GitHub Wiki](https://github.com/kjur/jsrsasign/wiki)
- [Sample Node Scripts](https://github.com/kjur/jsrsasign/tree/master/sample_node)

