/*! jwsjs-2.1.0 (c) 2010-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * jwsjs.js - JSON Web Signature JSON Serialization (JWSJS) Class
 *
 * version: 2.1.0 (2016 Sep 6)
 *
 * Copyright (c) 2010-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name jwsjs-2.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 2.1.0 (2016 Sep 6)
 * @since jsjws 1.2, jsrsasign 4.8.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.jws == "undefined" || !KJUR.jws) KJUR.jws = {};

/**
 * JSON Web Signature JSON Serialization (JWSJS) class.<br/>
 * @class JSON Web Signature JSON Serialization (JWSJS) class
 * @name KJUR.jws.JWSJS
 * @property {array of String} aHeader array of Encoded JWS Headers
 * @property {String} sPayload Encoded JWS payload
 * @property {array of String} aSignature array of Encoded JWS signature value
 * @author Kenji Urushima
 * @version 2.1.0 (2016 Sep 6)
 * @see <a href="http://kjur.github.com/jsjws/">old jwjws home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 * @see <a href="http://tools.ietf.org/html/draft-jones-json-web-signature-json-serialization-01">IETF I-D JSON Web Signature JSON Serialization (JWS-JS) specification</a>
 *
 * @description
 * This class generates and verfies "JSON Web Signature JSON Serialization (JWSJS)" of
 * <a href="http://tools.ietf.org/html/draft-jones-json-web-signature-json-serialization-01">
 * IETF Internet Draft</a>. Here is major methods of this class:
 * <ul>
 * <li>{@link KJUR.jws.JWSJS#readJWSJS} - initialize with string or JSON object of JWSJS.</li>
 * <li>{@link KJUR.jws.JWSJS#initWithJWS} - initialize with JWS as first signature.</li>
 * <li>{@link KJUR.jws.JWSJS#addSignature} - append signature to JWSJS object.</li>
 * <li>{@link KJUR.jws.JWSJS#verifyAll} - verify all signatures in JWSJS object.</li>
 * <li>{@link KJUR.jws.JWSJS#getJSON} - get result of JWSJS object as JSON object.</li>
 * </ul>
 *
 * @example
 * // initialize
 * jwsjs1 = new KJUR.jws.JWSJS();
 * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
 * 
 * // add PS256 signature with RSA private key object
 * prvKeyObj = KEYUTIL.getKey("-----BEGIN PRIVATE KEY...");
 * jwsjs1.addSignature("PS256", {alg: "PS256"}, prvKeyObj);
 * // add HS256 signature with HMAC password "secret"
 * jwsjs1.addSignature(null, {alg: "HS256"}, {utf8: "secret"});
 * 
 * // get result finally
 * jwsjsObj1 = jwsjs1.getJSON();
 *
 * // verify all signatures
 * isValid = jwsjs1.verifyAll([["-----BEGIN CERT...", ["RS256"]],
 *                             [{utf8: "secret"}, ["HS256"]]]); 
 * 
 */
KJUR.jws.JWSJS = function() {
    var ns1 = KJUR.jws.JWS;
    var nJWS = KJUR.jws.JWS;

    this.aHeader = [];
    this.sPayload = "";
    this.aSignature = [];

    // == initialize ===================================================================
    /**
     * (re-)initialize this object.<br/>
     * @name init
     * @memberOf KJUR.jws.JWSJS#
     * @function
     */
    this.init = function() {
	this.aHeader = [];
	this.sPayload = undefined;
	this.aSignature = [];
    };

    /**
     * (re-)initialize and set first signature with JWS.<br/>
     * @name initWithJWS
     * @memberOf KJUR.jws.JWSJS#
     * @param {String} sJWS JWS signature to set
     * @function
     * @example
     * jwsjs1 = new KJUR.jws.JWSJWS();
     * jwsjs1.initWithJWS("eyJ...");
     */
    this.initWithJWS = function(sJWS) {
	this.init();

	var a = sJWS.split(".");
	if (a.length != 3)
	    throw "malformed input JWS";

	this.aHeader.push(a[0]);
	this.sPayload = a[1];
	this.aSignature.push(a[2]);
    };

    // == add signature ===================================================================
    /**
     * add a signature to existing JWS-JS by algorithm, header and key.<br/>
     * @name addSignature
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @param {String} alg JWS algorithm. If null, alg in header will be used.
     * @param {Object} spHead string or object of JWS Header to add.
     * @param {Object} key JWS key to sign. key object, PEM private key or HMAC key
     * @param {String} pass optional password for encrypted PEM private key
     * @throw if signature append failed.
     * @example
     * // initialize
     * jwsjs1 = new KJUR.jws.JWSJS();
     * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
     *
     * // add PS256 signature with RSA private key object
     * prvKeyObj = KEYUTIL.getKey("-----BEGIN PRIVATE KEY...");
     * jwsjs1.addSignature("PS256", {alg: "PS256"}, prvKeyObj);
     *
     * // add HS256 signature with HMAC password "secret"
     * jwsjs1.addSignature(null, {alg: "HS256"}, {utf8: "secret"});
     *
     * // get result finally
     * jwsjsObj1 = jwsjs1.getJSON();
     */
    this.addSignature = function(alg, spHead, key, pass) {
	if (this.sPayload === undefined || this.sPayload === null)
	    throw "there's no JSON-JS signature to add.";

	var sigLen = this.aHeader.length;
	if (this.aHeader.length != this.aSignature.length)
	    throw "aHeader.length != aSignature.length";

	try {
	    var sJWS = KJUR.jws.JWS.sign(alg, spHead, this.sPayload, key, pass);
	    var a = sJWS.split(".");
	    var sHeader2 = a[0];
	    var sSignature2 = a[2];
	    this.aHeader.push(a[0]);
	    this.aSignature.push(a[2]);
	} catch(ex) {
	    if (this.aHeader.length > sigLen) this.aHeader.pop();
	    if (this.aSignature.length > sigLen) this.aSignature.pop();
	    throw "addSignature failed: " + ex;
	}
    };

    /**
     * add a signature to existing JWS-JS by Header and PKCS1 private key.<br/>
     * @name addSignatureByHeaderKey
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @param {String} sHead JSON string of JWS Header for adding signature.
     * @param {String} sPemPrvKey string of PKCS1 private key
     * @deprecated from jwsjs 2.1.0 jsrsasign 5.1.0
     */
    this.addSignatureByHeaderKey = function(sHead, sPemPrvKey) {
	var sPayload = b64utoutf8(this.sPayload);

	var jws = new KJUR.jws.JWS();
	var sJWS = jws.generateJWSByP1PrvKey(sHead, sPayload, sPemPrvKey);
  
	this.aHeader.push(jws.parsedJWS.headB64U);
	this.aSignature.push(jws.parsedJWS.sigvalB64U);
    };

    /**
     * add a signature to existing JWS-JS by Header, Payload and PKCS1 private key.<br/>
     * This is to add first signature to JWS-JS object.
     * @name addSignatureByHeaderPayloadKey
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @param {String} sHead JSON string of JWS Header for adding signature.
     * @param {String} sPayload string of JWS Payload for adding signature.
     * @param {String} sPemPrvKey string of PKCS1 private key
     * @deprecated from jwsjs 2.1.0 jsrsasign 5.1.0
     */
    this.addSignatureByHeaderPayloadKey = function(sHead, sPayload, sPemPrvKey) {
	var jws = new KJUR.jws.JWS();
	var sJWS = jws.generateJWSByP1PrvKey(sHead, sPayload, sPemPrvKey);
  
	this.aHeader.push(jws.parsedJWS.headB64U);
	this.sPayload = jws.parsedJWS.payloadB64U;
	this.aSignature.push(jws.parsedJWS.sigvalB64U);
    };

    // == verify signature ===================================================================
    /**
     * verify all signature of JWS-JS object by array of key and acceptAlgs.<br/>
     * @name verifyAll
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @param {array of key and acceptAlgs} aKeyAlg a array of key and acceptAlgs
     * @return true if all signatures are valid otherwise false
     * @since jwsjs 2.1.0 jsrsasign 5.1.0
     * @example
     * jwsjs1 = new KJUR.jws.JWSJS();
     * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
     * isValid = jwsjs1.verifyAll([["-----BEGIN CERT...", ["RS256"]],
     *                             [{utf8: "secret"}, ["HS256"]]]); 
     */
    this.verifyAll = function(aKeyAlg) {
	if (this.aHeader.length !== aKeyAlg.length ||
	    this.aSignature.length !== aKeyAlg.length)
	    return false;

	for (var i = 0; i < aKeyAlg.length; i++) {
	    var keyAlg = aKeyAlg[i];
	    if (keyAlg.length  !== 2) return false;
	    var result = this.verifyNth(i, keyAlg[0], keyAlg[1]);
	    if (result === false) return false;
	}
	return true;
    };

    /**
     * verify Nth signature of JWS-JS object by key and acceptAlgs.<br/>
     * @name verifyNth
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @param {Integer} idx nth index of JWS-JS signature to verify
     * @param {Object} key key to verify
     * @param {array of String} acceptAlgs array of acceptable signature algorithms
     * @return true if signature is valid otherwise false
     * @since jwsjs 2.1.0 jsrsasign 5.1.0
     * @example
     * jwsjs1 = new KJUR.jws.JWSJS();
     * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
     * isValid1 = jwsjs1.verifyNth(0, "-----BEGIN CERT...", ["RS256"]);
     * isValid2 = jwsjs1.verifyNth(1, {utf8: "secret"}, ["HS256"]);
     */
    this.verifyNth = function(idx, key, acceptAlgs) {
	if (this.aHeader.length <= idx || this.aSignature.length <= idx)
	    return false;
	var sHeader = this.aHeader[idx];
	var sSignature = this.aSignature[idx];
	var sJWS = sHeader + "." + this.sPayload + "." + sSignature;
	var result = false;
	try {
	    result = nJWS.verify(sJWS, key, acceptAlgs);
	} catch (ex) {
	    return false;
	}
	return result;
    };

    /**
     * verify JWS-JS object with array of certificate string.<br/>
     * @name verifyWithCerts
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @param {array of String} aCert array of string for X.509 PEM certificate.
     * @return 1 if signature is valid.
     * @throw if JWS-JS signature is invalid.
     * @deprecated from jwsjs 2.1.0 jsrsasign 5.1.0
     */
    this.verifyWithCerts = function(aCert) {
	if (this.aHeader.length != aCert.length) 
	    throw "num headers does not match with num certs";
	if (this.aSignature.length != aCert.length) 
	    throw "num signatures does not match with num certs";

	var payload = this.sPayload;
	var errMsg = "";
	for (var i = 0; i < aCert.length; i++) {
	    var cert = aCert[i];
	    var header = this.aHeader[i];
	    var sig = this.aSignature[i];
	    var sJWS = header + "." + payload + "." + sig;

	    var jws = new KJUR.jws.JWS();
	    try {
		var result = jws.verifyJWSByPemX509Cert(sJWS, cert);
		if (result != 1) {
		    errMsg += (i + 1) + "th signature unmatch. ";
		}
	    } catch (ex) {
		errMsg += (i + 1) + "th signature fail(" + ex + "). ";
	    }
	}

	if (errMsg == "") {
	    return 1;
	} else {
	    throw errMsg;
	}
    };

    /**
     * read JWS-JS string or object<br/>
     * @name readJWSJS
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @param {Object} spJWSJS string or JSON object of JWS-JS to load.
     * @throw if sJWSJS is malformed or not JSON string.
     * @description
     * NOTE: Loading from JSON object is suppored from 
     * jsjws 2.1.0 jsrsasign 5.1.0 (2016-Sep-06).
     * @example
     * // load JWSJS from string
     * jwsjs1 = new KJUR.jws.JWSJS();
     * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
     *
     * // load JWSJS from JSON object
     * jwsjs1 = new KJUR.jws.JWSJS();
     * jwsjs1.readJWSJS({headers: [...], payload: "eyJ...", signatures: [...]});
     */
    this.readJWSJS = function(spJWSJS) {
	if (typeof spJWSJS === "string") {
	    var oJWSJS = ns1.readSafeJSONString(spJWSJS);
	    if (oJWSJS == null) throw "argument is not safe JSON object string";

	    this.aHeader = oJWSJS.headers;
	    this.sPayload = oJWSJS.payload;
	    this.aSignature = oJWSJS.signatures;
	} else {
	    try {
		if (spJWSJS.headers.length > 0) {
		    this.aHeader = spJWSJS.headers;
		} else {
		    throw "malformed header";
		}
		if (typeof spJWSJS.payload === "string") {
		    this.sPayload = spJWSJS.payload;
		} else {
		    throw "malformed signatures";
		}
		if (spJWSJS.signatures.length > 0) {
		    this.signatures = spJWSJS.signatures;
		} else {
		    throw "malformed signatures";
		}
	    } catch (ex) {
		throw "malformed JWS-JS JSON object: " + ex;
	    }
	}
    };

    // == utility ===================================================================
    /**
     * get JSON object for this JWS-JS object.<br/>
     * @name getJSON
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @example
     * jwsj1 = new KJUR.jws.JWSJS();
     * // do some jwsj1 operation then get result by getJSON()
     * jwsjsObj1 = jwsjs1.getJSON();
     * // jwsjsObj1 &rarr; { headers: [...], payload: "ey...", signatures: [...] }
     */
    this.getJSON = function() {
	return { "headers": this.aHeader,
		 "payload": this.sPayload,
		 "signatures": this.aSignature }; 
    };

    /**
     * check if this JWS-JS object is empty.<br/>
     * @name isEmpty
     * @memberOf KJUR.jws.JWSJS#
     * @function
     * @return 1 if there is no signatures in this object, otherwise 0.
     */
    this.isEmpty = function() {
	if (this.aHeader.length == 0) return 1; 
	return 0;
    };
};

