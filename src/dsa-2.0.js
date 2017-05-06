/*! dsa-2.1.0.js (c) 2016-2017 Kenji Urushimma | kjur.github.com/jsrsasign/license
 */
/*
 * dsa.js - new DSA class
 *
 * Copyright (c) 2016-2017 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name dsa-2.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version dsa 2.1.0 (2017-Jan-21)
 * @since jsrsasign 7.0.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * class for DSA signing and verification
 * @name KJUR.crypto.DSA
 * @class class for DSA signing and verifcation
 * @since jsrsasign 7.0.0 dsa 2.0.0
 * @description
 * <p>
 * CAUTION: Most of the case, you don't need to use this class.
 * Please use {@link KJUR.crypto.Signature} class instead.
 * </p>
 * <p>
 * NOTE: Until jsrsasign 6.2.3, DSA class have used codes from openpgpjs library 1.0.0
 * licenced under LGPL licence. To avoid license issue dsa-2.0.js was re-written with
 * my own codes in jsrsasign 7.0.0. 
 * Some random number generators used in dsa-2.0.js was newly defined
 * in KJUR.crypto.Util class. Now all of LGPL codes are removed.
 * </p>
 */
KJUR.crypto.DSA = function() {
    this.p = null;
    this.q = null;
    this.g = null;
    this.y = null;
    this.x = null;
    this.type = "DSA";
    this.isPrivate = false;
    this.isPublic = false;

    //===========================
    // PUBLIC METHODS
    //===========================

    /**
     * set DSA private key by key parameters of BigInteger object
     * @name setPrivate
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {BigInteger} p prime P parameter
     * @param {BigInteger} q sub prime Q parameter
     * @param {BigInteger} g base G parameter
     * @param {BigInteger} y public key Y or null
     * @param {BigInteger} x private key X
     * @since jsrsasign 7.0.0 dsa 2.0.0
     */
    this.setPrivate = function(p, q, g, y, x) {
	this.isPrivate = true;
	this.p = p;
	this.q = q;
	this.g = g;
	this.y = y;
	this.x = x;
    };

    /**
     * set DSA private key by key parameters of hexadecimal string
     * @name setPrivateHex
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} hP prime P parameter
     * @param {String} hQ sub prime Q parameter
     * @param {String} hG base G parameter
     * @param {String} hY public key Y or null
     * @param {String} hX private key X
     * @since jsrsasign 7.1.0 dsa 2.1.0
     */
    this.setPrivateHex = function(hP, hQ, hG, hY, hX) {
	var biP, biQ, biG, biY, biX;
        biP = new BigInteger(hP, 16);
        biQ = new BigInteger(hQ, 16);
        biG = new BigInteger(hG, 16);
	if (typeof hY === "string" && hY.length > 1) {
            biY = new BigInteger(hY, 16);
	} else {
	    biY = null;
	}
        biX = new BigInteger(hX, 16);
        this.setPrivate(biP, biQ, biG, biY, biX);
    };

    /**
     * set DSA public key by key parameters of BigInteger object
     * @name setPublic
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {BigInteger} p prime P parameter
     * @param {BigInteger} q sub prime Q parameter
     * @param {BigInteger} g base G parameter
     * @param {BigInteger} y public key Y
     * @since jsrsasign 7.0.0 dsa 2.0.0
     */
    this.setPublic = function(p, q, g, y) {
	this.isPublic = true;
	this.p = p;
	this.q = q;
	this.g = g;
	this.y = y;
	this.x = null;
    };

    /**
     * set DSA public key by key parameters of hexadecimal string
     * @name setPublicHex
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} hP prime P parameter
     * @param {String} hQ sub prime Q parameter
     * @param {String} hG base G parameter
     * @param {String} hY public key Y
     * @since jsrsasign 7.1.0 dsa 2.1.0
     */
    this.setPublicHex = function(hP, hQ, hG, hY) {
	var biP, biQ, biG, biY;
        biP = new BigInteger(hP, 16);
        biQ = new BigInteger(hQ, 16);
        biG = new BigInteger(hG, 16);
        biY = new BigInteger(hY, 16);
        this.setPublic(biP, biQ, biG, biY);
    };

    /**
     * sign to hashed message by this DSA private key object
     * @name signWithMessageHash
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} sHashHex hexadecimal string of hashed message
     * @return {String} hexadecimal string of ASN.1 encoded DSA signature value
     * @since jsrsasign 7.0.0 dsa 2.0.0
     */
    this.signWithMessageHash = function(sHashHex) {
	var p = this.p; // parameter p
	var q = this.q; // parameter q
	var g = this.g; // parameter g
	var y = this.y; // public key (p q g y)
	var x = this.x; // private key

	// NIST FIPS 186-4 4.5 DSA Per-Message Secret Number (p18)
	// 1. get random k where 0 < k < q
	var k = KJUR.crypto.Util.getRandomBigIntegerMinToMax(BigInteger.ONE.add(BigInteger.ONE),
							     q.subtract(BigInteger.ONE));

	// NIST FIPS 186-4 4.6 DSA Signature Generation (p19)
	// 2. get z where the left most min(N, outlen) bits of Hash(M)
	var hZ = sHashHex.substr(0, q.bitLength() / 4);
	var z = new BigInteger(hZ, 16);

	// 3. get r where (g^k mod p) mod q, r != 0
	var r = (g.modPow(k,p)).mod(q); 

	// 4. get s where k^-1 (z + xr) mod q, s != 0
	var s = (k.modInverse(q).multiply(z.add(x.multiply(r)))).mod(q);

	// 5. signature (r, s)
	var result = KJUR.asn1.ASN1Util.jsonToASN1HEX({
	    "seq": [{"int": {"bigint": r}}, {"int": {"bigint": s}}] 
	});
	return result;
    };

    /**
     * verify signature by this DSA public key object
     * @name verifyWithMessageHash
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} sHashHex hexadecimal string of hashed message
     * @param {String} hSigVal hexadecimal string of ASN.1 encoded DSA signature value
     * @return {Boolean} true if the signature is valid otherwise false.
     * @since jsrsasign 7.0.0 dsa 2.0.0
     */
    this.verifyWithMessageHash = function(sHashHex, hSigVal) {
	var p = this.p; // parameter p
	var q = this.q; // parameter q
	var g = this.g; // parameter g
	var y = this.y; // public key (p q g y)

	// 1. parse ASN.1 signature (r, s)
	var rs = this.parseASN1Signature(hSigVal);
        var r = rs[0];
        var s = rs[1];

	// NIST FIPS 186-4 4.6 DSA Signature Generation (p19)
	// 2. get z where the left most min(N, outlen) bits of Hash(M)
	var hZ = sHashHex.substr(0, q.bitLength() / 4);
	var z = new BigInteger(hZ, 16);

	// NIST FIPS 186-4 4.7 DSA Signature Validation (p19)
	// 3.1. 0 < r < q
	if (BigInteger.ZERO.compareTo(r) > 0 || r.compareTo(q) > 0)
	    throw "invalid DSA signature";

	// 3.2. 0 < s < q
	if (BigInteger.ZERO.compareTo(s) > 0 || s.compareTo(q) > 0)
	    throw "invalid DSA signature";

	// 4. get w where w = s^-1 mod q
	var w = s.modInverse(q);

	// 5. get u1 where u1 = z w mod q
	var u1 = z.multiply(w).mod(q);

	// 6. get u2 where u2 = r w mod q
	var u2 = r.multiply(w).mod(q);

	// 7. get v where v = ((g^u1 y^u2) mod p) mod q
	var v = g.modPow(u1,p).multiply(y.modPow(u2,p)).mod(p).mod(q);

	// 8. signature is valid when v == r
	return v.compareTo(r) == 0;
    };

    /**
     * parse hexadecimal ASN.1 DSA signature value
     * @name parseASN1Signature
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} hSigVal hexadecimal string of ASN.1 encoded DSA signature value
     * @return {Array} array [r, s] of DSA signature value. Both r and s are BigInteger.
     * @since jsrsasign 7.0.0 dsa 2.0.0
     */
    this.parseASN1Signature = function(hSigVal) {
	try {
	    var r = new BigInteger(ASN1HEX.getVbyList(hSigVal, 0, [0], "02"), 16);
	    var s = new BigInteger(ASN1HEX.getVbyList(hSigVal, 0, [1], "02"), 16);
	    return [r, s];
	} catch (ex) {
	    throw "malformed ASN.1 DSA signature";
	}
    }

    /**
     * read an ASN.1 hexadecimal string of PKCS#1/5 plain DSA private key<br/>
     * @name readPKCS5PrvKeyHex
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} h hexadecimal string of PKCS#1/5 DSA private key
     * @since jsrsasign 7.1.0 dsa 2.1.0
     */
    this.readPKCS5PrvKeyHex = function(h) {
	var hP, hQ, hG, hY, hX;
	var _ASN1HEX = ASN1HEX;
	var _getVbyList = _ASN1HEX.getVbyList;

	if (_ASN1HEX.isASN1HEX(h) === false)
	    throw "not ASN.1 hex string";

	try {
	    hP = _getVbyList(h, 0, [1], "02");
	    hQ = _getVbyList(h, 0, [2], "02");
	    hG = _getVbyList(h, 0, [3], "02");
	    hY = _getVbyList(h, 0, [4], "02");
	    hX = _getVbyList(h, 0, [5], "02");
	} catch(ex) {
	    console.log("EXCEPTION:" + ex);
	    throw "malformed PKCS#1/5 plain DSA private key";
	}

	this.setPrivateHex(hP, hQ, hG, hY, hX);
    };

    /**
     * read an ASN.1 hexadecimal string of PKCS#8 plain DSA private key<br/>
     * @name readPKCS8PrvKeyHex
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} h hexadecimal string of PKCS#8 DSA private key
     * @since jsrsasign 7.1.0 dsa 2.1.0
     */
    this.readPKCS8PrvKeyHex = function(h) {
	var hP, hQ, hG, hX;
	var _ASN1HEX = ASN1HEX;
	var _getVbyList = _ASN1HEX.getVbyList;

	if (_ASN1HEX.isASN1HEX(h) === false)
	    throw "not ASN.1 hex string";

	try {
	    hP = _getVbyList(h, 0, [1, 1, 0], "02");
	    hQ = _getVbyList(h, 0, [1, 1, 1], "02");
	    hG = _getVbyList(h, 0, [1, 1, 2], "02");
	    hX = _getVbyList(h, 0, [2, 0], "02");
	} catch(ex) {
	    console.log("EXCEPTION:" + ex);
	    throw "malformed PKCS#8 plain DSA private key";
	}

	this.setPrivateHex(hP, hQ, hG, null, hX);
    };

    /**
     * read an ASN.1 hexadecimal string of PKCS#8 plain DSA private key<br/>
     * @name readPKCS8PubKeyHex
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} h hexadecimal string of PKCS#8 DSA private key
     * @since jsrsasign 7.1.0 dsa 2.1.0
     */
    this.readPKCS8PubKeyHex = function(h) {
	var hP, hQ, hG, hY;
	var _ASN1HEX = ASN1HEX;
	var _getVbyList = _ASN1HEX.getVbyList;

	if (_ASN1HEX.isASN1HEX(h) === false)
	    throw "not ASN.1 hex string";

	try {
	    hP = _getVbyList(h, 0, [0, 1, 0], "02");
	    hQ = _getVbyList(h, 0, [0, 1, 1], "02");
	    hG = _getVbyList(h, 0, [0, 1, 2], "02");
	    hY = _getVbyList(h, 0, [1, 0], "02");
	} catch(ex) {
	    console.log("EXCEPTION:" + ex);
	    throw "malformed PKCS#8 DSA public key";
	}

	this.setPublicHex(hP, hQ, hG, hY);
    };

    /**
     * read an ASN.1 hexadecimal string of X.509 DSA public key certificate<br/>
     * @name readCertPubKeyHex
     * @memberOf KJUR.crypto.DSA#
     * @function
     * @param {String} h hexadecimal string of X.509 DSA public key certificate
     * @param {Integer} nthPKI nth index of publicKeyInfo. (DEFAULT: 6 for X509v3)
     * @since jsrsasign 7.1.0 dsa 2.1.0
     */
    this.readCertPubKeyHex = function(h, nthPKI) {
	if (nthPKI !== 5) nthPKI = 6;
	var hP, hQ, hG, hY;
	var _ASN1HEX = ASN1HEX;
	var _getVbyList = _ASN1HEX.getVbyList;

	if (_ASN1HEX.isASN1HEX(h) === false)
	    throw "not ASN.1 hex string";

	try {
	    hP = _getVbyList(h, 0, [0, nthPKI, 0, 1, 0], "02");
	    hQ = _getVbyList(h, 0, [0, nthPKI, 0, 1, 1], "02");
	    hG = _getVbyList(h, 0, [0, nthPKI, 0, 1, 2], "02");
	    hY = _getVbyList(h, 0, [0, nthPKI, 1, 0], "02");
	} catch(ex) {
	    console.log("EXCEPTION:" + ex);
	    throw "malformed X.509 certificate DSA public key";
	}

	this.setPublicHex(hP, hQ, hG, hY);
    };
}
