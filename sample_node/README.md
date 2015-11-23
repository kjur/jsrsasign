[TOP](https://kjur.github.io/jsrsasign/) | 
[GIT](https://github.com/kjur/jsrsasign/) | [SAMPLE NODE SCRIPTS](https://github.com/kjur/jsrsasign/tree/master/sample_node)
***

## SAMPLE NODE SCRIPTS

Here is sample node utility scripts using 'jsrsasign' module.

1. [jwtverify](https://github.com/kjur/jsrsasign/tree/master/sample_node/jwtverify) - JWT and JWS verification tool

This script is to verify JWT(JSON Web Token) or JWS(JSON Web Signature) file or string 
using [KJUR.jws.JWS.verifyJWT()](http://kjur.github.io/jsrsasign/api/symbols/KJUR.jws.JWS.html#.verifyJWT) method. It has following features:

..* HS256/384/512,RS256/384/512,PS256/384/512,ES256/384 signature algorithm support
..* string, hexadecimal and Base64URL passcode support for HS* signatures
..* JWS and JWT validation
..* JWT/JWS signature can be provided by a file or a string argument.
..* Verbose mode for validation in detail.

To verify JWS, provide simplly passcode or public key:

    % jwtverify -s password aaa.jws // passcode is 'password'
    % jwtverify -x 616161 aaa.jws   // passcode is 0x616161 (i.e. aaa)
    % jwtverify -k aaa.pub aaa.jws  // verify by PKCS#8 public key

You can specify a JWS signature to verify as script argument not a file.

    % jwtverify -s aaa eyJhbGciOiJIUzI1NiIsInR5c...

Verifying JWT is very similar to JWS however you can specify optional arguments:

    % jwtverify -s aaa --verify_at 20051231235959Z aaa.jwt // verify at 2005 Dec 31.
                                                           // current time by default.
    % jwtverify -s aaa --accept_iss "http://example.com" aaa.jwt // acceptable issuer
    % jwtverify -s aaa --accept_sub "http://example.com" aaa.jwt // acceptable subject

2. [asn1dump](https://github.com/kjur/jsrsasign/tree/master/sample_node/asn1dump) - simple ASN.1 dumper

    % asn1dump aaa.pub.p8.der
    SEQUENCE
      SEQUENCE
        ObjectIdentifier rsaEncryption (1 2 840 113549 1 1 1)
        NULL
      BITSTRING 003081890...(total ???bytes)...

3. [pemtobin](https://github.com/kjur/jsrsasign/tree/master/sample_node/pemtobin) - convert any PEM file to binary

    % pemtobin aaa.pem aaa.der


## REQUIRED NPMS

To execute above scripts some npm packages are reuiqred:

    % npm install -g commander
    % npm install -g jsrsasign

## ONLINE HELP

All above scripts supports '-h' or '--help' option:

    % ./jwtverify -h
  
    Usage: jwtverify [options] <JWT/JWS file or string to verify>
  
    verify JWT/jWS file or string
  
    Options:
  
      -h, --help                       output usage information
      -V, --version                    output the version number
      -s, --hmacpassstr <pass string>  Hmac(HS*) pass string (ex. passwd)
      -x, --hmacpasshex <pass hex>     Hmac(HS*) pass hex (ex. 7e5f...)
      -b, --hmacpassb64u <pass b64u>   Hmac(HS*) pass base 64 url encoding)
      -k, --pubkey <file>              public key file (ex. PKCS#8 PEM or JWK)
      -v, --verbose                    show header and payload
      --accept_iss <iss1,...>          check iss is in the iss list (ex. a@a.com,b@b.com)
      --accept_sub <sub1,...>          check sub is in the sub list (ex. a@a.com,b@b.com)
      --verify_at <YYYYMMDDHHmmSSZ>    verify at specified UTC time(ex. 20151123235959Z)
