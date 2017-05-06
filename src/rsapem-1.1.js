/*! rsapem-1.2.0.js (c) 2012-2017 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * rsapem.js - Cryptographic Algorithm Provider class
 *
 * Copyright (c) 2013-2017 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name rsapem-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.2.0 (2017-Jan-21)
 * @since jsrsasign 1.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * static method to extract Base64 string from PKCS#5 PEM RSA private key.<br/>
 * @name pemToBase64
 * @memberOf RSAKey
 * @function
 * @param {String} sPEMPrivateKey PEM PKCS#1/5 s private key string
 * @return {String} Base64 string of private key
 * @description
 * removing PEM header, PEM footer and space characters including
 * new lines from PEM formatted RSA private key string.
 * @example
 * RSAKey.pemToBase64("----BEGIN PRIVATE KEY-...") &rarr; "MIICW..."
 */
RSAKey.pemToBase64 = function(sPEMPrivateKey) {
    var s = sPEMPrivateKey;
    s = s.replace("-----BEGIN RSA PRIVATE KEY-----", "");
    s = s.replace("-----END RSA PRIVATE KEY-----", "");
    s = s.replace(/[ \n]+/g, "");
    return s;
};

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
    var a = new Array();
    var idx_v = ASN1HEX.getStartPosOfV_AtObj(hPrivateKey, 0);
    var idx_n = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, idx_v);
    var idx_e = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, idx_n);
    var idx_d = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, idx_e);
    var idx_p = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, idx_d);
    var idx_q = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, idx_p);
    var idx_dp = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, idx_q);
    var idx_dq = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, idx_dp);
    var idx_co = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, idx_dq);
    a.push(idx_v, idx_n, idx_e, idx_d, idx_p, idx_q, idx_dp, idx_dq, idx_co);
    return a;
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
    var posArray = RSAKey.getPosArrayOfChildrenFromHex(hPrivateKey);
    var h_v =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[0]);
    var h_n =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[1]);
    var h_e =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[2]);
    var h_d =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[3]);
    var h_p =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[4]);
    var h_q =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[5]);
    var h_dp = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[6]);
    var h_dq = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[7]);
    var h_co = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[8]);
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
    var keyB64 = RSAKey.pemToBase64(keyPEM);
    var keyHex = b64tohex(keyB64) // depends base64.js
    var a = RSAKey.getHexValueArrayOfChildrenFromHex(keyHex);
    this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
};

/**
 * (DEPRECATED) read RSA private key from a ASN.1 hexadecimal string<br/>
 * @name readPrivateKeyFromASN1HexString
 * @memberOf RSAKey#
 * @function
 * @param {String} keyHex ASN.1 hexadecimal string of PKCS#1 private key.
 * @since rsapem 1.1.1
 * @deprecated since jsrsasign 7.1.0 rsapem 1.2.0, please use {@link RSAKey.readPKCS5PrvKeyHex} instead.
 */
RSAKey.prototype.readPrivateKeyFromASN1HexString = function(keyHex) {
    this.readPKCS5PrvKeyHex(keyHex);
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
    if (ASN1HEX.isASN1HEX(h) === false)
	throw "keyHex is not ASN.1 hex string";
    var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0);
    if (aIdx.length !== 2 ||
	h.substr(aIdx[0], 2) !== "02" ||
	h.substr(aIdx[1], 2) !== "02")
	throw "wrong hex for PKCS#5 public key";
    var hN = ASN1HEX.getHexOfV_AtObj(h, aIdx[0]);
    var hE = ASN1HEX.getHexOfV_AtObj(h, aIdx[1]);
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
    if (ASN1HEX.isASN1HEX(h) === false)
	throw "not ASN.1 hex string";

    // 06092a864886f70d010101: OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
    if (ASN1HEX.getDecendantHexTLVByNthList(h, 0, [0, 0]) !== "06092a864886f70d010101")
	throw "not PKCS8 RSA public key";

    var p5hex = ASN1HEX.getDecendantHexTLVByNthList(h, 0, [1, 0]);
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
    if (nthPKI !== 5) nthPKI = 6;
    if (ASN1HEX.isASN1HEX(h) === false)
	throw "not ASN.1 hex string";

    var p8hex = ASN1HEX.getDecendantHexTLVByNthList(h, 0, [0, nthPKI]);
    this.readPKCS8PubKeyHex(p8hex);
};
