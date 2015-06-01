/*! jwsjs-2.0.2 (c) 2010-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * jwsjs.js - JSON Web Signature JSON Serialization (JWSJS) Class
 *
 * version: 2.0.2 (2015 May 29)
 *
 * Copyright (c) 2010-2015 Kenji Urushima (kenji.urushima@gmail.com)
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
 * @version 2.0.2 (2015 May 29)
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
 * @version 1.0 (18 May 2012)
 * @requires base64x.js, json-sans-eval.js, jws.js and jsrsasign library
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 * @see <a href="http://tools.ietf.org/html/draft-jones-json-web-signature-json-serialization-01">IETF I-D JSON Web Signature JSON Serialization (JWS-JS) specification</a>
 */
KJUR.jws.JWSJS = function() {
	var ns1 = KJUR.jws.JWS;

    this.aHeader = [];
    this.sPayload = "";
    this.aSignature = [];

    // == initialize ===================================================================
    /**
     * (re-)initialize this object.<br/>
     * @name init
     * @memberOf KJUR.jws.JWSJS
     * @function
     */
    this.init = function() {
		this.aHeader = [];
		this.sPayload = "";
		this.aSignature = [];
    };

    /**
     * (re-)initialize and set first signature with JWS.<br/>
     * @name initWithJWS
     * @memberOf KJUR.jws.JWSJS
     * @param {String} sJWS JWS signature to set
     * @function
     */
    this.initWithJWS = function(sJWS) {
		this.init();

		var jws = new KJUR.jws.JWS();
		jws.parseJWS(sJWS);

		this.aHeader.push(jws.parsedJWS.headB64U);
		this.sPayload = jws.parsedJWS.payloadB64U;
		this.aSignature.push(jws.parsedJWS.sigvalB64U);
    };

    // == add signature ===================================================================
    /**
     * add a signature to existing JWS-JS by Header and PKCS1 private key.<br/>
     * @name addSignatureByHeaderKey
     * @memberOf KJUR.jws.JWSJS
     * @function
     * @param {String} sHead JSON string of JWS Header for adding signature.
     * @param {String} sPemPrvKey string of PKCS1 private key
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
     * @memberOf KJUR.jws.JWSJS
     * @function
     * @param {String} sHead JSON string of JWS Header for adding signature.
     * @param {String} sPayload string of JWS Payload for adding signature.
     * @param {String} sPemPrvKey string of PKCS1 private key
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
     * verify JWS-JS object with array of certificate string.<br/>
     * @name verifyWithCerts
     * @memberOf KJUR.jws.JWSJS
     * @function
     * @param {array of String} aCert array of string for X.509 PEM certificate.
     * @return 1 if signature is valid.
     * @throw if JWS-JS signature is invalid.
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
     * read JWS-JS string.<br/>
     * @name raedJWSJS
     * @memberOf KJUR.jws.JWSJS
     * @function
     * @param {String} string of JWS-JS to load.
     * @throw if sJWSJS is malformed or not JSON string.
     */
    this.readJWSJS = function(sJWSJS) {
		var oJWSJS = ns1.readSafeJSONString(sJWSJS);
		if (oJWSJS == null) throw "argument is not JSON string: " + sJWSJS;

		this.aHeader = oJWSJS.headers;
		this.sPayload = oJWSJS.payload;
		this.aSignature = oJWSJS.signatures;
    };

    // == utility ===================================================================
    /**
     * get JSON object for this JWS-JS object.<br/>
     * @name getJSON
     * @memberOf KJUR.jws.JWSJS
     * @function
     */
    this.getJSON = function() {
		return { "headers": this.aHeader,
				 "payload": this.sPayload,
				 "signatures": this.aSignature }; 
    };

    /**
     * check if this JWS-JS object is empty.<br/>
     * @name isEmpty
     * @memberOf KJUR.jws.JWSJS
     * @function
     * @return 1 if there is no signatures in this object, otherwise 0.
     */
    this.isEmpty = function() {
		if (this.aHeader.length == 0) return 1; 
		return 0;
    };
};

