jsrsasign
=========

The 'jsrsasign' (RSA-Sign JavaScript Library) is an opensource free pure JavaScript cryptographic library supports RSA/RSAPSS/ECDSA/DSA signing/validation, ASN.1, PKCS#1/5/8 private/public key, X.509 certificate, CRL, CMS SignedData, TimeStamp and CAdES and JSON Web Signature(JWS)/Token(JWT)/Key(JWK).

Public page is http://kjur.github.com/jsrsasign .

[github TOP](http://kjur.github.io/jsrsasign/)|[API doc](http://kjur.github.io/jsrsasign/api/)|[Wiki](https://github.com/kjur/jsrsasign/wiki)|[Node sample](https://github.com/kjur/jsrsasign/tree/master/sample_node)

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

Most of the classes and methods defined in jsrsasign and jsjws are
available in this jsrsasign npm module.

After loading the module,

    > var r = require('jsrsasign');

You can refer name spaces, classes, methods and functions 
by following variables:

- r.BigInteger - BigInteger class
- r.RSAKey - [RSAKey class](http://kjur.github.io/jsrsasign/api/symbols/RSAKey.html)
- r.ECDSA - [KJUR.crypto.ECDSA class](http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.ECDSA.html)
- r.DSA - [KJUR.crypto.DSA class](http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.DSA.html)
- r.Signature - [KJUR.crypto.Signature class](http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html)
- r.MessageDigest - [KJUR.crypto.MessageDigest class](http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.MessageDigest.html)
- r.Mac - [KJUR.crypto.Mac class](http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Mac.html)
- r.KEYUTIL - [KEYUTIL class](http://kjur.github.io/jsrsasign/api/symbols/KEYUTIL.html)
- r.ASN1HEX - [ASN1HEX class](http://kjur.github.io/jsrsasign/api/symbols/ASN1HEX.html)
- r.crypto - [KJUR.crypto name space](http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.html)
- r.asn1 - [KJUR.asn1 name space](http://kjur.github.io/jsrsasign/api/symbols/KJUR.asn1.html)
- r.jws - [KJUR.jws name space](http://kjur.github.io/jsjws/api/)

Please see API reference in the above links.

EXAMPLE(1) SIGNATURE
--------------------

Loading encrypted PKCS#5 private key:

    > var fs = require('fs');
    > var pem = fs.readFileSync('z1.prv.p5e.pem', 'binary');
    > var prvKey = a.KEYUTIL.getKey(pem, 'passwd');

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

