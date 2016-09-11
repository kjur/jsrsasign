[TOP](https://kjur.github.io/jsrsasign/) | 
[GIT](https://github.com/kjur/jsrsasign/) | [SAMPLE NODE SCRIPTS](https://github.com/kjur/jsrsasign/tree/master/sample_node)
***

## SAMPLE NODE SCRIPTS

Here is sample node utility scripts using 'jsrsasign' module.

NOTE: From jsrsasign 6.0.0 (2016-Sep-11), please install "jsrsasign", "jsrsasign-util" and "commander" npm packages to use scripts here because codes using "fs" have been separated and moved into new "jsrsasign-util" package.

1. [jwtverify](https://github.com/kjur/jsrsasign/tree/master/sample_node/jwtverify) - JWT and JWS verification tool

This script is to verify JWT(JSON Web Token) or JWS(JSON Web Signature) for HMAC password or public key.
using [KJUR.jws.JWS.verifyJWT()](http://kjur.github.io/jsrsasign/api/symbols/KJUR.jws.JWS.html#.verifyJWT) method. 
See [here](https://github.com/kjur/jsrsasign/wiki/Sample-Node-Script---jwtverify) in detail.

1. [asn1dump](https://github.com/kjur/jsrsasign/tree/master/sample_node/asn1dump) - simple ASN.1 dumper

This script dumps ASN.1 DER formatted binary file.

    % asn1dump aaa.pub.p8.der
    SEQUENCE
      SEQUENCE
        ObjectIdentifier rsaEncryption (1 2 840 113549 1 1 1)
        NULL
      BITSTRING 003081890...(total ???bytes)...

1. [jwssign](https://github.com/kjur/jsrsasign/tree/master/sample_node/jwssign) - sign JWS by header and payload file or string

This script is to sign JWS(JSON Web Signature) for specified header and payload file or string
using [KJUR.jws.JWS.sign()](http://kjur.github.io/jsrsasign/api/symbols/KJUR.jws.JWS.html#.sign) method. 
See [here](https://github.com/kjur/jsrsasign/wiki/Sample-Node-Script---jwssign) in detail.

1. [pemtobin](https://github.com/kjur/jsrsasign/tree/master/sample_node/pemtobin) - convert any PEM file to binary

This script converts from any PEM format file to binary.

    % pemtobin aaa.pem aaa.der


## REQUIRED NPMS

To execute above scripts some npm packages are reuiqred:

    % npm install -g commander
    % npm install -g jsrsasign
    % npm install -g jsrsasign-util

