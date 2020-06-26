jsrsasign
=========

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://github.com/kjur/jsrsasign/blob/master/LICENSE.txt)
[![bower](https://img.shields.io/bower/v/jsrsasign.svg?maxAge=2592000)](https://libraries.io/bower/jsrsasign)
[![npm version](https://badge.fury.io/js/jsrsasign.svg)](https://badge.fury.io/js/jsrsasign)
[![npm downloads](https://img.shields.io/npm/dm/jsrsasign.svg)](https://www.npmjs.com/package/jsrsasign)
[![CDNJS](https://img.shields.io/cdnjs/v/jsrsasign.svg)](https://cdnjs.com/libraries/jsrsasign)

The 'jsrsasign' (RSA-Sign JavaScript Library) is an opensource free cryptography library supporting RSA/RSAPSS/ECDSA/DSA signing/validation, ASN.1, PKCS#1/5/8 private/public key, X.509 certificate, CRL, OCSP, CMS SignedData, TimeStamp, CAdES JSON Web Signature/Token/Key in pure JavaScript.

Public page is https://kjur.github.io/jsrsasign .

Your bugfix and pull request contribution are always welcomed :)

## RECENT SECURITY ADVISORY

|published|fixed version|title/advisory|CVE|CVSS|
|:---|:---|:---|:---|:---|
|2020Jun22|8.0.19|[ECDSA signature validation vulnerability by accepting wrong ASN.1 encoding](https://github.com/kjur/jsrsasign/security/advisories/GHSA-p8c3-7rj8-q963)|CVE-2020-14966|5.5|
|2020Jun22|8.0.18|[RSA RSAES-PKCS1-v1_5 and RSA-OAEP decryption vulnerability with prepending zeros](https://github.com/kjur/jsrsasign/security/advisories/GHSA-xxxq-chmp-67g4)|CVE-2020-14967|4.8|
|2020Jun22|8.0.17|[RSA-PSS signature validation vulnerability by prepending zeros](https://github.com/kjur/jsrsasign/security/advisories/GHSA-q3gh-5r98-j4h3)|CVE-2020-14968|4.2|

Here is [full published security advisory list](https://github.com/kjur/jsrsasign/security/advisories?state=published).

