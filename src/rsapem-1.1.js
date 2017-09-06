/* rsapem-1.3.0.js (c) 2012-2017 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * rsapem.js - Cryptographic Algorithm Provider class
 *
 * Copyright (c) 2013-2017 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name rsapem-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 8.0.0 rsapem 1.3.0 (2017-Jun-24)
 * @since jsrsasign 1.0
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * static method to get array of field positions from hexadecimal PKCS#5 RSA private key.<br/>
 * @name getPosArrayOfChildrenFromHex
 * @memberOf RSAKey
 * @function
 * @param {String} sPEMPrivateKey PEM PKCS#1/5 s private key string
 * @return {Array} array of field positions
 * @example
 * RSAKey.getPosArrayOfChildrenFromHex("3082...") &rarr; [8, 32, ...]
 */
RSAKey.getPosArrayOfChildrenFromHex = function(hPrivateKey) {
    return ASN1HEX.getChildIdx(hPrivateKey, 0);
};

/**
 * static method to get array of hex field values from hexadecimal PKCS#5 RSA private key.<br/>
 * @name getHexValueArrayOfChildrenFromHex
 * @memberOf RSAKey
 * @function
 * @param {String} sPEMPrivateKey PEM PKCS#1/5 s private key string
 * @return {Array} array of field hex value
 * @example
 * RSAKey.getHexValueArrayOfChildrenFromHex("3082...") &rarr; ["00", "3b42...", ...]
 */
RSAKey.getHexValueArrayOfChildrenFromHex = function(hPrivateKey) {
    var _ASN1HEX = ASN1HEX;
    var _getV = _ASN1HEX.getV;
    var a = RSAKey.getPosArrayOfChildrenFromHex(hPrivateKey);
    var h_v =  _getV(hPrivateKey, a[0]);
    var h_n =  _getV(hPrivateKey, a[1]);
    var h_e =  _getV(hPrivateKey, a[2]);
    var h_d =  _getV(hPrivateKey, a[3]);
    var h_p =  _getV(hPrivateKey, a[4]);
    var h_q =  _getV(hPrivateKey, a[5]);
    var h_dp = _getV(hPrivateKey, a[6]);
    var h_dq = _getV(hPrivateKey, a[7]);
    var h_co = _getV(hPrivateKey, a[8]);
    var a = new Array();
    a.push(h_v, h_n, h_e, h_d, h_p, h_q, h_dp, h_dq, h_co);
    return a;
};

/**
 * read PKCS#1 private key from a string<br/>
 * @name readPrivateKeyFromPEMString
 * @memberOf RSAKey#
 * @function
 * @param {String} keyPEM string of PKCS#1 private key.
 */
RSAKey.prototype.readPrivateKeyFromPEMString = function(keyPEM) {
    var keyHex = pemtohex(keyPEM);
    var a = RSAKey.getHexValueArrayOfChildrenFromHex(keyHex);
    this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
};

/**
 * read an ASN.1 hexadecimal string of PKCS#1/5 plain RSA private key<br/>
 * @name readPKCS5PrvKeyHex
 * @memberOf RSAKey#
 * @function
 * @param {String} h hexadecimal string of PKCS#1/5 plain RSA private key
 * @since jsrsasign 7.1.0 rsapem 1.2.0
 * @see {@link RSAKey.readPrivateKeyFromASN1HexString} former method
 */
RSAKey.prototype.readPKCS5PrvKeyHex = function(h) {
    var a = RSAKey.getHexValueArrayOfChildrenFromHex(h);
    this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
};

/**
 * read an ASN.1 hexadecimal string of PKCS#8 plain RSA private key<br/>
 * @name readPKCS8PrvKeyHex
 * @memberOf RSAKey#
 * @function
 * @param {String} h hexadecimal string of PKCS#8 plain RSA private key
 * @since jsrsasign 7.1.0 rsapem 1.2.0
 */
RSAKey.prototype.readPKCS8PrvKeyHex = function(h) {
    var hN, hE, hD, hP, hQ, hDP, hDQ, hCO;
    var _ASN1HEX = ASN1HEX;
    var _getVbyList = _ASN1HEX.getVbyList;

    if (_ASN1HEX.isASN1HEX(h) === false)
	throw "not ASN.1 hex string";

    try {
	hN  = _getVbyList(h, 0, [2, 0, 1], "02");
	hE  = _getVbyList(h, 0, [2, 0, 2], "02");
	hD  = _getVbyList(h, 0, [2, 0, 3], "02");
	hP  = _getVbyList(h, 0, [2, 0, 4], "02");
	hQ  = _getVbyList(h, 0, [2, 0, 5], "02");
	hDP = _getVbyList(h, 0, [2, 0, 6], "02");
	hDQ = _getVbyList(h, 0, [2, 0, 7], "02");
	hCO = _getVbyList(h, 0, [2, 0, 8], "02");
    } catch(ex) {
	throw "malformed PKCS#8 plain RSA private key";
    }

    this.setPrivateEx(hN, hE, hD, hP, hQ, hDP, hDQ, hCO);
};

/**
 * read an ASN.1 hexadecimal string of PKCS#5 RSA public key<br/>
 * @name readPKCS5PubKeyHex
 * @memberOf RSAKey#
 * @function
 * @param {String} h hexadecimal string of PKCS#5 public key
 * @since jsrsasign 7.1.0 rsapem 1.2.0
 */
RSAKey.prototype.readPKCS5PubKeyHex = function(h) {
    var _ASN1HEX = ASN1HEX;
    var _getV = _ASN1HEX.getV;

    if (_ASN1HEX.isASN1HEX(h) === false)
	throw "keyHex is not ASN.1 hex string";
    var aIdx = _ASN1HEX.getChildIdx(h, 0);
    if (aIdx.length !== 2 ||
	h.substr(aIdx[0], 2) !== "02" ||
	h.substr(aIdx[1], 2) !== "02")
	throw "wrong hex for PKCS#5 public key";
    var hN = _getV(h, aIdx[0]);
    var hE = _getV(h, aIdx[1]);
    this.setPublic(hN, hE);
};

/**
 * read an ASN.1 hexadecimal string of PKCS#8 RSA public key<br/>
 * @name readPKCS8PubKeyHex
 * @memberOf RSAKey#
 * @function
 * @param {String} h hexadecimal string of PKCS#8 public key
 * @since jsrsasign 7.1.0 rsapem 1.2.0
 */
RSAKey.prototype.readPKCS8PubKeyHex = function(h) {
    var _ASN1HEX = ASN1HEX;
    if (_ASN1HEX.isASN1HEX(h) === false)
	throw "not ASN.1 hex string";

    // 06092a864886f70d010101: OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
    if (_ASN1HEX.getTLVbyList(h, 0, [0, 0]) !== "06092a864886f70d010101")
	throw "not PKCS8 RSA public key";

    var p5hex = _ASN1HEX.getTLVbyList(h, 0, [1, 0]);
    this.readPKCS5PubKeyHex(p5hex);
};

/**
 * read an ASN.1 hexadecimal string of X.509 RSA public key certificate<br/>
 * @name readCertPubKeyHex
 * @memberOf RSAKey#
 * @function
 * @param {String} h hexadecimal string of X.509 RSA public key certificate
 * @param {Integer} nthPKI nth index of publicKeyInfo. (DEFAULT: 6 for X509v3)
 * @since jsrsasign 7.1.0 rsapem 1.2.0
 */
RSAKey.prototype.readCertPubKeyHex = function(h, nthPKI) {
    var x, hPub;
    x = new X509();
    x.readCertHex(h);
    hPub = x.getPublicKeyHex();
    this.readPKCS8PubKeyHex(hPub);
};
