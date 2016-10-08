/*! jws-3.3.5 (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * jws.js - JSON Web Signature(JWS) and JSON Web Token(JWT) Class
 *
 * version: 3.3.4 (2016 May 17)
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
 * @name jws-3.3.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 3.3.5 (2016-Oct-08)
 * @since jsjws 1.0, jsrsasign 4.8.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/**
 * kjur's JSON Web Signature/Token(JWS/JWT) library name space
 * <p>
 * This namespace privides following JWS/JWS related classes.
 * <ul>
 * <li>{@link KJUR.jws.JWS} - JSON Web Signature/Token(JWS/JWT) class</li>
 * <li>{@link KJUR.jws.JWSJS} - JWS JSON Serialization(JWSJS) class</li>
 * <li>{@link KJUR.jws.IntDate} - UNIX origin time utility class</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.jws
 * @namespace
 */
if (typeof KJUR.jws == "undefined" || !KJUR.jws) KJUR.jws = {};

/**
 * JSON Web Signature(JWS) class.<br/>
 * @name KJUR.jws.JWS
 * @class JSON Web Signature(JWS) class
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 * @see <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14">IETF I-D JSON Web Algorithms (JWA)</a>
 * @since jsjws 1.0
 * @description
 * This class provides JSON Web Signature(JWS)/JSON Web Token(JWT) signing and validation.
 *
 * <h4>METHOD SUMMARY</h4>
 * Here is major methods of {@link KJUR.jws.JWS} class.
 * <ul>
 * <li><b>SIGN</b><br/>
 * <li>{@link KJUR.jws.JWS.sign} - sign JWS</li>
 * </li>
 * <li><b>VERIFY</b><br/>
 * <li>{@link KJUR.jws.JWS.verify} - verify JWS signature</li>
 * <li>{@link KJUR.jws.JWS.verifyJWT} - verify properties of JWT token at specified time</li>
 * </li>
 * <li><b>UTILITY</b><br/>
 * <li>{@link KJUR.jws.JWS.getJWKthumbprint} - get RFC 7638 JWK thumbprint</li>
 * <li>{@link KJUR.jws.JWS.isSafeJSONString} - check whether safe JSON string or not</li>
 * <li>{@link KJUR.jws.JWS.readSafeJSONString} - read safe JSON string only</li>
 * </li>
 * </ul> 
 *
 * <h4>SUPPORTED SIGNATURE ALGORITHMS</h4>
 * Here is supported algorithm names for {@link KJUR.jws.JWS.sign} and
 * {@link KJUR.jws.JWS.verify} methods.
 * <table>
 * <tr><th>alg value</th><th>spec requirement</th><th>jsjws support</th></tr>
 * <tr><td>HS256</td><td>REQUIRED</td><td>SUPPORTED</td></tr>
 * <tr><td>HS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>HS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>RS256</td><td>RECOMMENDED</td><td>SUPPORTED</td></tr>
 * <tr><td>RS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>RS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>ES256</td><td>RECOMMENDED+</td><td>SUPPORTED</td></tr>
 * <tr><td>ES384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>ES512</td><td>OPTIONAL</td><td>-</td></tr>
 * <tr><td>PS256</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>PS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>PS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>none</td><td>REQUIRED</td><td>SUPPORTED(signature generation only)</td></tr>
 * </table>
 * <dl>
 * <dt><b>NOTE1</b>
 * <dd>HS384 is supported since jsjws 3.0.2 with jsrsasign 4.1.4.
 * <dt><b>NOTE2</b>
 * <dd>Some deprecated methods have been removed since jws 3.3 of jsrsasign 4.10.0.
 * Removed methods are following:
 * <ul>
 * <li>JWS.verifyJWSByNE</li>
 * <li>JWS.verifyJWSByKey</li>
 * <li>JWS.generateJWSByNED</li>
 * <li>JWS.generateJWSByKey</li>
 * <li>JWS.generateJWSByP1PrvKey</li>
 * </ul>
 * </dl>
 * <b>EXAMPLE</b><br/>
 * @example
 * // JWS signing 
 * sJWS = KJUR.jws.JWS.sign(null, '{"alg":"HS256", "cty":"JWT"}', '{"age": 21}', {"utf8": "password"});
 * // JWS validation
 * isValid = KJUR.jws.JWS.verify('eyJjdHkiOiJKV1QiLCJhbGc...', {"utf8": "password"});
 * // JWT validation
 * isValid = KJUR.jws.JWS.verifyJWT('eyJh...', {"utf8": "password"}, {
 *   alg: ['HS256', 'HS384'],
 *   iss: ['http://foo.com']
 * });
 */
KJUR.jws.JWS = function() {
    var ns1 = KJUR.jws.JWS;

    // === utility =============================================================

    /**
     * parse JWS string and set public property 'parsedJWS' dictionary.<br/>
     * @name parseJWS
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be parsed.
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     * @since jws 1.1
     */
    this.parseJWS = function(sJWS, sigValNotNeeded) {
	if ((this.parsedJWS !== undefined) &&
	    (sigValNotNeeded || (this.parsedJWS.sigvalH !== undefined))) {
	    return;
	}
    var matchResult = sJWS.match(/^([^.]+)\.([^.]+)\.([^.]+)$/);
	if (matchResult == null) {
	    throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
	}
	var b6Head = matchResult[1];
	var b6Payload = matchResult[2];
	var b6SigVal = matchResult[3];
	var sSI = b6Head + "." + b6Payload;
	this.parsedJWS = {};
	this.parsedJWS.headB64U = b6Head;
	this.parsedJWS.payloadB64U = b6Payload;
	this.parsedJWS.sigvalB64U = b6SigVal;
	this.parsedJWS.si = sSI;

	if (!sigValNotNeeded) {
	    var hSigVal = b64utohex(b6SigVal);
	    var biSigVal = parseBigInt(hSigVal, 16);
	    this.parsedJWS.sigvalH = hSigVal;
	    this.parsedJWS.sigvalBI = biSigVal;
	}

	var sHead = b64utoutf8(b6Head);
	var sPayload = b64utoutf8(b6Payload);
	this.parsedJWS.headS = sHead;
	this.parsedJWS.payloadS = sPayload;

	if (! ns1.isSafeJSONString(sHead, this.parsedJWS, 'headP'))
	    throw "malformed JSON string for JWS Head: " + sHead;
    };
};

// === major static method ========================================================

/**
 * generate JWS signature by specified key<br/>
 * @name sign
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} alg JWS algorithm name to sign and force set to sHead or null 
 * @param {String} spHead string or object of JWS Header
 * @param {String} spPayload string or object of JWS Payload
 * @param {String} key string of private key or mac key object to sign
 * @param {String} pass (OPTION)passcode to use encrypted asymmetric private key 
 * @return {String} JWS signature string
 * @since jws 3.0.0
 * @see <a href="http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html">jsrsasign KJUR.crypto.Signature method</a>
 * @see <a href="http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Mac.html">jsrsasign KJUR.crypto.Mac method</a>
 * @description
 * This method supports following algorithms.
 * <table>
 * <tr><th>alg value</th><th>spec requirement</th><th>jsjws support</th></tr>
 * <tr><td>HS256</td><td>REQUIRED</td><td>SUPPORTED</td></tr>
 * <tr><td>HS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>HS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>RS256</td><td>RECOMMENDED</td><td>SUPPORTED</td></tr>
 * <tr><td>RS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>RS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>ES256</td><td>RECOMMENDED+</td><td>SUPPORTED</td></tr>
 * <tr><td>ES384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>ES512</td><td>OPTIONAL</td><td>-</td></tr>
 * <tr><td>PS256</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>PS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>PS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>none</td><td>REQUIRED</td><td>SUPPORTED(signature generation only)</td></tr>
 * </table>
 * <dl>
 * <dt>NOTE1:
 * <dd>salt length of RSAPSS signature is the same as the hash algorithm length
 * because of <a href="http://www.ietf.org/mail-archive/web/jose/current/msg02901.html">IETF JOSE ML discussion</a>.
 * <dt>NOTE2:
 * <dd>To support HS384, patched version of CryptoJS is used.
 * <a href="https://code.google.com/p/crypto-js/issues/detail?id=84">See here for detail</a>.
 * <dt>NOTE3:
 * From jsrsasign 4.10.0 jws 3.3.0, Way to provide password
 * for HS* algorithm is changed. The 'key' attribute value is
 * passed to {@link KJUR.crypto.Mac.setPassword} so please see
 * {@link KJUR.crypto.Mac.setPassword} for detail.
 * As for backword compatibility, if key is a string, has even length and
 * 0..9, A-F or a-f characters, key string is treated as a hexadecimal
 * otherwise it is treated as a raw string.
 * <dd>
 * </dl>
 * <b>EXAMPLE</b><br/>
 * @example
 * // sign HS256 signature with password "aaa" implicitly handled as string
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "HS256", cty: "JWT"}, {age: 21}, "aaa");
 * // sign HS256 signature with password "6161" implicitly handled as hex
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "HS256", cty: "JWT"}, {age: 21}, "6161");
 * // sign HS256 signature with base64 password
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "HS256"}, {age: 21}, {b64: "Mi/8..a="});
 * // sign RS256 signature with PKCS#8 PEM RSA private key
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "RS256"}, {age: 21}, "-----BEGIN PRIVATE KEY...");
 * // sign RS256 signature with PKCS#8 PEM ECC private key with passcode
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "ES256"}, {age: 21}, 
 *                          "-----BEGIN PRIVATE KEY...", "keypass");
 * // header and payload can be passed by both string and object
 * sJWS = KJUR.jws.JWS.sign(null, '{alg:"HS256",cty:"JWT"}', '{age:21}', "aaa");
 */
KJUR.jws.JWS.sign = function(alg, spHeader, spPayload, key, pass) {
    var ns1 = KJUR.jws.JWS;
    var sHeader, pHeader, sPayload;

    // 1. check signatureInput(Header, Payload) is string or object
    if (typeof spHeader != 'string' && typeof spHeader != 'object')
	throw "spHeader must be JSON string or object: " + spHeader;

    if (typeof spHeader == 'object') {
	pHeader = spHeader;
	sHeader = JSON.stringify(pHeader);
    }

    if (typeof spHeader == 'string') {
	sHeader = spHeader;
	if (! ns1.isSafeJSONString(sHeader))
	    throw "JWS Head is not safe JSON string: " + sHeader;
	pHeader = ns1.readSafeJSONString(sHeader);

    }

    sPayload = spPayload;
    if (typeof spPayload == 'object') sPayload = JSON.stringify(spPayload);

    // 2. use alg if defined in sHeader
    if ((alg == '' || alg == null) &&
	pHeader['alg'] !== undefined) {
	alg = pHeader['alg'];
    }

    // 3. update sHeader to add alg if alg undefined
    if ((alg != '' && alg != null) &&
	pHeader['alg'] === undefined) {
	pHeader['alg'] = alg;
	sHeader = JSON.stringify(pHeader);
    }

    // 4. check explicit algorithm doesn't match with JWS header.
    if (alg !== pHeader.alg)
	throw "alg and sHeader.alg doesn't match: " + alg + "!=" + pHeader.alg;

    // 5. set signature algorithm like SHA1withRSA
    var sigAlg = null;
    if (ns1.jwsalg2sigalg[alg] === undefined) {
	throw "unsupported alg name: " + alg;
    } else {
	sigAlg = ns1.jwsalg2sigalg[alg];
    }
    
    var uHeader = utf8tob64u(sHeader);
    var uPayload = utf8tob64u(sPayload);
    var uSignatureInput = uHeader + "." + uPayload
    // 6. sign
    var hSig = "";
    if (sigAlg.substr(0, 4) == "Hmac") {
	if (key === undefined)
	    throw "mac key shall be specified for HS* alg";
	//alert("sigAlg=" + sigAlg);
	var mac = new KJUR.crypto.Mac({'alg': sigAlg, 'prov': 'cryptojs', 'pass': key});
	mac.updateString(uSignatureInput);
	hSig = mac.doFinal();
    } else if (sigAlg.indexOf("withECDSA") != -1) {
	var sig = new KJUR.crypto.Signature({'alg': sigAlg});
	sig.init(key, pass);
	sig.updateString(uSignatureInput);
	hASN1Sig = sig.sign();
	hSig = KJUR.crypto.ECDSA.asn1SigToConcatSig(hASN1Sig);
    } else if (sigAlg != "none") {
	var sig = new KJUR.crypto.Signature({'alg': sigAlg});
	sig.init(key, pass);
	sig.updateString(uSignatureInput);
	hSig = sig.sign();
    }

    var uSig = hextob64u(hSig);
    return uSignatureInput + "." + uSig;
};

/**
 * verify JWS signature by specified key or certificate<br/>
 * @name verify
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} sJWS string of JWS signature to verify
 * @param {Object} key string of public key, certificate or key object to verify
 * @param {String} acceptAlgs array of algorithm name strings (OPTION)
 * @return {Boolean} true if the signature is valid otherwise false
 * @since jws 3.0.0
 * @see <a href="http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html">jsrsasign KJUR.crypto.Signature method</a>
 * @see <a href="http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Mac.html">jsrsasign KJUR.crypto.Mac method</a>
 * @description
 * <p>
 * This method verifies a JSON Web Signature Compact Serialization string by the validation 
 * algorithm as described in 
 * <a href="http://self-issued.info/docs/draft-jones-json-web-signature-04.html#anchor5">
 * the section 5 of Internet Draft draft-jones-json-web-signature-04.</a>
 * </p>
 * <p>
 * Since 3.2.0 strict key checking has been provided against a JWS algorithm
 * in a JWS header.
 * <ul>
 * <li>In case 'alg' is 'HS*' in the JWS header,
 * 'key' shall be hexadecimal string for Hmac{256,384,512} shared secret key.
 * Otherwise it raise an error.</li>
 * <li>In case 'alg' is 'RS*' or 'PS*' in the JWS header,
 * 'key' shall be a RSAKey object or a PEM string of
 * X.509 RSA public key certificate or PKCS#8 RSA public key.
 * Otherwise it raise an error.</li>
 * <li>In case 'alg' is 'ES*' in the JWS header,
 * 'key' shall be a KJUR.crypto.ECDSA object or a PEM string of
 * X.509 ECC public key certificate or PKCS#8 ECC public key.
 * Otherwise it raise an error.</li>
 * <li>In case 'alg' is 'none' in the JWS header,
 * validation not supported after jsjws 3.1.0.</li>
 * </ul>
 * </p>
 * <p>
 * NOTE1: The argument 'acceptAlgs' is supported since 3.2.0.
 * Strongly recommended to provide acceptAlgs to mitigate
 * signature replacement attacks.<br/>
 * </p>
 * <p>
 * NOTE2: From jsrsasign 4.9.0 jws 3.2.5, Way to provide password
 * for HS* algorithm is changed. The 'key' attribute value is
 * passed to {@link KJUR.crypto.Mac.setPassword} so please see
 * {@link KJUR.crypto.Mac.setPassword} for detail.
 * As for backword compatibility, if key is a string, has even length and
 * 0..9, A-F or a-f characters, key string is treated as a hexadecimal
 * otherwise it is treated as a raw string.
 * </p>
 * @example
 * // 1) verify a RS256 JWS signature by a certificate string.
 * isValid = KJUR.jws.JWS.verify('eyJh...', '-----BEGIN...', ['RS256']);
 * 
 * // 2) verify a HS256 JWS signature by a certificate string.
 * isValid = KJUR.jws.JWS.verify('eyJh...', {hex: '6f62ad...'}, ['HS256']);
 * isValid = KJUR.jws.JWS.verify('eyJh...', {b64: 'Mi/ab8...a=='}, ['HS256']);
 * isValid = KJUR.jws.JWS.verify('eyJh...', {utf8: 'Secret秘密'}, ['HS256']);
 * isValid = KJUR.jws.JWS.verify('eyJh...', '6f62ad', ['HS256']); // implicit hex
 * isValid = KJUR.jws.JWS.verify('eyJh...', '6f62ada', ['HS256']); // implicit raw string
 *
 * // 3) verify a ES256 JWS signature by a KJUR.crypto.ECDSA key object.
 * var pubkey = KEYUTIL.getKey('-----BEGIN CERT...');
 * var isValid = KJUR.jws.JWS.verify('eyJh...', pubkey);
 */
KJUR.jws.JWS.verify = function(sJWS, key, acceptAlgs) {
    var jws = KJUR.jws.JWS;
    var a = sJWS.split(".");
    var uHeader = a[0];
    var uPayload = a[1];
    var uSignatureInput = uHeader + "." + uPayload;
    var hSig = b64utohex(a[2]);

    // 1. parse JWS header
    var pHeader = jws.readSafeJSONString(b64utoutf8(a[0]));
    var alg = null;
    var algType = null; // HS|RS|PS|ES|no
    if (pHeader.alg === undefined) {
	throw "algorithm not specified in header";
    } else {
	alg = pHeader.alg;
	algType = alg.substr(0, 2);
    }

    // 2. check whether alg is acceptable algorithms
    if (acceptAlgs != null &&
        Object.prototype.toString.call(acceptAlgs) === '[object Array]' &&
        acceptAlgs.length > 0) {
	var acceptAlgStr = ":" + acceptAlgs.join(":") + ":";
	if (acceptAlgStr.indexOf(":" + alg + ":") == -1) {
	    throw "algorithm '" + alg + "' not accepted in the list";
	}
    }

    // 3. check whether key is a proper key for alg.
    if (alg != "none" && key === null) {
	throw "key shall be specified to verify.";
    }

    // 3.1. There is no key check for HS* because Mac will check it.
    //      since jsrsasign 5.0.0.

    // 3.2. convert key object if key is a public key or cert PEM string
    if (typeof key == "string" &&
	key.indexOf("-----BEGIN ") != -1) {
	key = KEYUTIL.getKey(key);
    }

    // 3.3. check whether key is RSAKey obj if alg is RS* or PS*.
    if (algType == "RS" || algType == "PS") {
	if (!(key instanceof RSAKey)) {
	    throw "key shall be a RSAKey obj for RS* and PS* algs";
	}
    }

    // 3.4. check whether key is ECDSA obj if alg is ES*.
    if (algType == "ES") {
	if (!(key instanceof KJUR.crypto.ECDSA)) {
	    throw "key shall be a ECDSA obj for ES* algs";
	}
    }

    // 3.5. check when alg is 'none'
    if (alg == "none") {
    }

    // 4. check whether alg is supported alg in jsjws.
    var sigAlg = null;
    if (jws.jwsalg2sigalg[pHeader.alg] === undefined) {
	throw "unsupported alg name: " + alg;
    } else {
	sigAlg = jws.jwsalg2sigalg[alg];
    }

    // 5. verify
    if (sigAlg == "none") {
        throw "not supported";
    } else if (sigAlg.substr(0, 4) == "Hmac") {
	var hSig2 = null;
	if (key === undefined)
	    throw "hexadecimal key shall be specified for HMAC";
	//try {
	    var mac = new KJUR.crypto.Mac({'alg': sigAlg, 'pass': key});
	    mac.updateString(uSignatureInput);
	    hSig2 = mac.doFinal();
	//} catch(ex) {};
	return hSig == hSig2;
    } else if (sigAlg.indexOf("withECDSA") != -1) {
	var hASN1Sig = null;
        try {
	    hASN1Sig = KJUR.crypto.ECDSA.concatSigToASN1Sig(hSig);
	} catch (ex) {
	    return false;
	}
	var sig = new KJUR.crypto.Signature({'alg': sigAlg});
	sig.init(key)
	sig.updateString(uSignatureInput);
	return sig.verify(hASN1Sig);
    } else {
	var sig = new KJUR.crypto.Signature({'alg': sigAlg});
	sig.init(key)
	sig.updateString(uSignatureInput);
	return sig.verify(hSig);
    }
};

/**
 * parse header and payload of JWS signature<br/>
 * @name parse
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} sJWS string of JWS signature to parse
 * @return {Array} associative array of parsed header and payload. See below.
 * @throws if sJWS is malformed JWS signature
 * @since jws 3.3.3
 * @description
 * This method parses JWS signature string. 
 * Resulted associative array has following properties:
 * <ul>
 * <li>headerObj - JSON object of header</li>
 * <li>payloadObj - JSON object of payload if payload is JSON string otherwise undefined</li>
 * <li>headerPP - pretty printed JSON header by stringify</li>
 * <li>payloadPP - pretty printed JSON payload by stringify if payload is JSON otherwise Base64URL decoded raw string of payload</li>
 * <li>sigHex - hexadecimal string of signature</li>
 * </ul>
 * @example
 * KJUR.jws.JWS.parse(sJWS) ->
 * { 
 *   headerObj: {"alg": "RS256", "typ": "JWS"},
 *   payloadObj: {"product": "orange", "quantity": 100},
 *   headerPP: 
 *   '{
 *     "alg": "RS256",
 *     "typ": "JWS"
 *   }',
 *   payloadPP: 
 *   '{
 *     "product": "orange",
 *     "quantity": 100
 *   }',
 *   sigHex: "91f3cd..." 
 * }
 */
KJUR.jws.JWS.parse = function(sJWS) {
    var a = sJWS.split(".");
    var result = {};
    var uHeader, uPayload, uSig;
    if (a.length != 2 && a.length != 3)
	throw "malformed sJWS: wrong number of '.' splitted elements";

    uHeader = a[0];
    uPayload = a[1];
    if (a.length == 3) uSig = a[2]; 

    result.headerObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(uHeader));
    result.payloadObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(uPayload));

    result.headerPP = JSON.stringify(result.headerObj, null, "  ");
    if (result.payloadObj == null) {
	result.payloadPP = b64utoutf8(uPayload);
    } else {
	result.payloadPP = JSON.stringify(result.payloadObj, null, "  ");
    }

    if (uSig !== undefined) {
	result.sigHex = b64utohex(uSig);
    }

    return result;
};

/**
 * @name verifyJWT
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} sJWT string of JSON Web Token(JWT) to verify
 * @param {Object} key string of public key, certificate or key object to verify
 * @param {Array} acceptField associative array of acceptable fields (OPTION)
 * @return {Boolean} true if the JWT token is valid otherwise false
 * @since jws 3.2.3 jsrsasign 4.8.0
 *
 * @description
 * This method verifies a
 * <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a> 
 * JSON Web Token(JWT).
 * It will verify following:
 * <ul>
 * <li>Header.alg
 * <ul>
 * <li>alg is specified in JWT header.</li>
 * <li>alg is included in acceptField.alg array. (MANDATORY)</li>
 * <li>alg is proper for key.</li>
 * </ul>
 * </li>
 * <li>Payload.iss (issuer) - Payload.iss is included in acceptField.iss array if specified. (OPTION)</li>
 * <li>Payload.sub (subject) - Payload.sub is included in acceptField.sub array if specified. (OPTION)</li>
 * <li>Payload.aud (audience) - Payload.aud is included in acceptField.aud array or 
 *     the same as value if specified. (OPTION)</li>
 * <li>Time validity
 * <ul>
 * <li>
 * If acceptField.verifyAt as number of UNIX origin time is specifed for validation time, 
 * this method will verify at the time for it, otherwise current time will be used to verify.
 * </li>
 * <li>
 * Clock of JWT generator or verifier can be fast or slow. If these clocks are
 * very different, JWT validation may fail. To avoid such case, 'jsrsasign' supports
 * 'acceptField.gracePeriod' parameter which specifies acceptable time difference
 * of those clocks in seconds. So if you want to accept slow or fast in 2 hours,
 * you can specify <code>acceptField.gracePeriod = 2 * 60 * 60;</code>.
 * "gracePeriod" is zero by default.
 * "gracePeriod" is supported since jsrsasign 5.0.12.
 * </li>
 * <li>Payload.exp (expire) - Validation time is smaller than Payload.exp + gracePeriod.</li>
 * <li>Payload.nbf (not before) - Validation time is greater than Payload.nbf - gracePeriod.</li>
 * <li>Payload.iat (issued at) - Validation time is greater than Payload.iat - gracePeriod.</li>
 * </ul>
 * </li>
 * <li>Payload.jti (JWT id) - Payload.jti is included in acceptField.jti if specified. (OPTION)</li>
 * <li>JWS signature of JWS is valid for specified key.</li>
 * </ul>
 *
 * <h4>acceptField parameters</h4>
 * Here is available acceptField argument parameters:
 * <ul>
 * <li>alg - array of acceptable signature algorithm names (ex. ["HS256", "HS384"])</li>
 * <li>iss - array of acceptable issuer names (ex. ['http://foo.com'])</li>
 * <li>sub - array of acceptable subject names (ex. ['mailto:john@foo.com'])</li>
 * <li>aud - array or string of acceptable audience name(s) (ex. ['http://foo.com'])</li>
 * <li>jti - string of acceptable JWT ID (OPTION) (ex. 'id1234')</li>
 * <li>
 * verifyAt - time to verify 'nbf', 'iat' and 'exp' in UNIX seconds 
 * (OPTION) (ex. 1377663900).  
 * If this is not specified, current time of verifier will be used. 
 * {@link KJUR.jws.IntDate} may be useful to specify it.
 * </li>
 * <li>gracePeriod - acceptable time difference between signer and verifier
 * in seconds (ex. 3600). If this is not specified, zero will be used.</li>
 * </ul>
 *
 * @example
 * // simple validation for HS256
 * isValid = KJUR.jws.JWS.verifyJWT("eyJhbG...", "616161", {alg: ["HS256"]}),
 *
 * // full validation for RS or PS
 * pubkey = KEYUTIL.getKey('-----BEGIN CERT...');
 * isValid = KJUR.jws.JWS.verifyJWT('eyJh...', pubkey, {
 *   alg: ['RS256', 'RS512', 'PS256', 'PS512'],
 *   iss: ['http://foo.com'],
 *   sub: ['mailto:john@foo.com', 'mailto:alice@foo.com'],
 *   verifyAt: KJUR.jws.IntDate.get('20150520235959Z'),
 *   aud: ['http://foo.com'], // aud: 'http://foo.com' is fine too.
 *   jti: 'id123456',
 *   gracePeriod: 1 * 60 * 60 // accept 1 hour slow or fast
 * });
 */
KJUR.jws.JWS.verifyJWT = function(sJWT, key, acceptField) {
    var ns1 = KJUR.jws.JWS;

    // 1. parse JWT
    var a = sJWT.split(".");
    var uHeader = a[0];
    var uPayload = a[1];
    var uSignatureInput = uHeader + "." + uPayload;
    var hSig = b64utohex(a[2]);

    // 2. parse JWS header
    var pHeader = ns1.readSafeJSONString(b64utoutf8(uHeader));

    // 3. parse JWS payload
    var pPayload = ns1.readSafeJSONString(b64utoutf8(uPayload));

    // 4. algorithm ('alg' in header) check
    if (pHeader.alg === undefined) return false;
    if (acceptField.alg === undefined)
	throw "acceptField.alg shall be specified";
    if (! ns1.inArray(pHeader.alg, acceptField.alg)) return false;

    // 5. issuer ('iss' in payload) check
    if (pPayload.iss !== undefined && typeof acceptField.iss === "object") {
	if (! ns1.inArray(pPayload.iss, acceptField.iss)) return false;
    }

    // 6. subject ('sub' in payload) check
    if (pPayload.sub !== undefined && typeof acceptField.sub === "object") {
	if (! ns1.inArray(pPayload.sub, acceptField.sub)) return false;
    }

    // 7. audience ('aud' in payload) check
    if (pPayload.aud !== undefined && typeof acceptField.aud === "object") {
	if (typeof pPayload.aud == "string") {
	    if (! ns1.inArray(pPayload.aud, acceptField.aud))
		return false;
	} else if (typeof pPayload.aud == "object") {
	    if (! ns1.includedArray(pPayload.aud, acceptField.aud))
		return false;
	}
    }

    // 8. time validity 
    //   (nbf - gracePeriod < now < exp + gracePeriod) && (iat - gracePeriod < now)
    var now = KJUR.jws.IntDate.getNow();
    if (acceptField.verifyAt !== undefined && typeof acceptField.verifyAt === "number") {
	now = acceptField.verifyAt;
    }
    if (acceptField.gracePeriod === undefined || 
        typeof acceptField.gracePeriod !== "number") {
	acceptField.gracePeriod = 0;
    }

    // 8.1 expired time 'exp' check
    if (pPayload.exp !== undefined && typeof pPayload.exp == "number") {
	if (pPayload.exp + acceptField.gracePeriod < now) return false;
    }

    // 8.2 not before time 'nbf' check
    if (pPayload.nbf !== undefined && typeof pPayload.nbf == "number") {
	if (now < pPayload.nbf - acceptField.gracePeriod) return false;
    }
    
    // 8.3 issued at time 'iat' check
    if (pPayload.iat !== undefined && typeof pPayload.iat == "number") {
	if (now < pPayload.iat - acceptField.gracePeriod) return false;
    }

    // 9 JWT id 'jti' check
    if (pPayload.jti !== undefined && acceptField.jti !== undefined) {
      if (pPayload.jti !== acceptField.jti) return false;
    }

    // 10 JWS signature check
    if (! KJUR.jws.JWS.verify(sJWT, key, acceptField.alg)) return false;

    // 11 passed all check
    return true;
};

/**
 * check whether array is included by another array
 * @name includedArray
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {Array} a1 check whether set a1 is included by a2
 * @param {Array} a2 check whether set a1 is included by a2
 * @return {Boolean} check whether set a1 is included by a2
 * @since jws 3.2.3
 * This method verifies whether an array is included by another array.
 * It doesn't care about item ordering in a array.
 * @example
 * KJUR.jws.JWS.includedArray(['b'], ['b', 'c', 'a']) => true
 * KJUR.jws.JWS.includedArray(['a', 'b'], ['b', 'c', 'a']) => true
 * KJUR.jws.JWS.includedArray(['a', 'b'], ['b', 'c']) => false
 */
KJUR.jws.JWS.includedArray = function(a1, a2) {
    var inArray = KJUR.jws.JWS.inArray;
    if (a1 === null) return false;
    if (typeof a1 !== "object") return false;
    if (typeof a1.length !== "number") return false;

    for (var i = 0; i < a1.length; i++) {
	if (! inArray(a1[i], a2)) return false;
    }
    return true;
};

/**
 * check whether item is included by array
 * @name inArray
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} item check whether item is included by array
 * @param {Array} a check whether item is included by array
 * @return {Boolean} check whether item is included by array
 * @since jws 3.2.3
 * This method verifies whether an item is included by an array.
 * It doesn't care about item ordering in an array.
 * @example
 * KJUR.jws.JWS.inArray('b', ['b', 'c', 'a']) => true
 * KJUR.jws.JWS.inArray('a', ['b', 'c', 'a']) => true
 * KJUR.jws.JWS.inArray('a', ['b', 'c']) => false
 */
KJUR.jws.JWS.inArray = function(item, a) {
    if (a === null) return false;
    if (typeof a !== "object") return false;
    if (typeof a.length !== "number") return false;
    for (var i = 0; i < a.length; i++) {
	if (a[i] == item) return true;
    }
    return false;
};

/**
 * static associative array of general signature algorithm name from JWS algorithm name
 * @since jws 3.0.0
 */
KJUR.jws.JWS.jwsalg2sigalg = {
    "HS256":	"HmacSHA256",
    "HS384":	"HmacSHA384",
    "HS512":	"HmacSHA512",
    "RS256":	"SHA256withRSA",
    "RS384":	"SHA384withRSA",
    "RS512":	"SHA512withRSA",
    "ES256":	"SHA256withECDSA",
    "ES384":	"SHA384withECDSA",
    //"ES512":	"SHA512withECDSA", // unsupported because of jsrsasign's bug
    "PS256":	"SHA256withRSAandMGF1",
    "PS384":	"SHA384withRSAandMGF1",
    "PS512":	"SHA512withRSAandMGF1",
    "none":	"none",
};

// === utility static method ==================================================

/**
 * check whether a String "s" is a safe JSON string or not.<br/>
 * If a String "s" is a malformed JSON string or an other object type
 * this returns 0, otherwise this returns 1.
 * @name isSafeJSONString
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} s JSON string
 * @return {Number} 1 or 0
 */
KJUR.jws.JWS.isSafeJSONString = function(s, h, p) {
    var o = null;
    try {
	o = jsonParse(s);
	if (typeof o != "object") return 0;
	if (o.constructor === Array) return 0;
	if (h) h[p] = o;
	return 1;
    } catch (ex) {
	return 0;
    }
};

/**
 * read a String "s" as JSON object if it is safe.<br/>
 * If a String "s" is a malformed JSON string or not JSON string,
 * this returns null, otherwise returns JSON object.
 * @name readSafeJSONString
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} s JSON string
 * @return {Object} JSON object or null
 * @since 1.1.1
 */
KJUR.jws.JWS.readSafeJSONString = function(s) {
    var o = null;
    try {
	o = jsonParse(s);
	if (typeof o != "object") return null;
	if (o.constructor === Array) return null;
	return o;
    } catch (ex) {
	return null;
    }
};

/**
 * get Encoed Signature Value from JWS string.<br/>
 * @name getEncodedSignatureValueFromJWS
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} sJWS JWS signature string to be verified
 * @return {String} string of Encoded Signature Value 
 * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
 */
KJUR.jws.JWS.getEncodedSignatureValueFromJWS = function(sJWS) {
    var matchResult = sJWS.match(/^[^.]+\.[^.]+\.([^.]+)$/);
    if (matchResult == null) {
	throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
    }
    return matchResult[1];
};

/**
 * get RFC 7638 JWK thumbprint from JWK object
 * @name getJWKthumbprint
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {Object} o JWK object to be calculated thumbprint
 * @return {String} Base64 URL encoded JWK thumbprint value
 * @since jsrsasign 5.0.2 jws 3.3.2
 * @description
 * This method calculates JWK thmubprint for specified JWK object
 * as described in 
 * <a href="https://tools.ietf.org/html/rfc7638">RFC 7638</a>.
 * It supports all type of "kty". (i.e. "RSA", "EC" and "oct"
 * (for symmetric key))
 * Working sample is 
 * <a href="https://kjur.github.io/jsrsasign/sample/tool_jwktp.html">here</a>.
 * @example
 * jwk = {"kty":"RSA", "n":"0vx...", "e":"AQAB", ...};
 * thumbprint = KJUR.jws.JWS.getJWKthumbprint(jwk);
 */
KJUR.jws.JWS.getJWKthumbprint = function(o) {
    if (o.kty !== "RSA" &&
	o.kty !== "EC" &&
	o.kty !== "oct")
	throw "unsupported algorithm for JWK Thumprint";

    // 1. get canonically ordered json string
    var s = '{';
    if (o.kty === "RSA") {
	if (typeof o.n != "string" || typeof o.e != "string")
	    throw "wrong n and e value for RSA key";
	s += '"' + 'e' + '":"' + o.e + '",';
	s += '"' + 'kty' + '":"' + o.kty + '",';
	s += '"' + 'n' + '":"' + o.n + '"}';
    } else if (o.kty === "EC") {
	if (typeof o.crv != "string" || 
	    typeof o.x != "string" ||
	    typeof o.y != "string")
	    throw "wrong crv, x and y value for EC key";
	s += '"' + 'crv' + '":"' + o.crv + '",';
	s += '"' + 'kty' + '":"' + o.kty + '",';
	s += '"' + 'x' + '":"' + o.x + '",';
	s += '"' + 'y' + '":"' + o.y + '"}';
    } else if (o.kty === "oct") {
	if (typeof o.k != "string")
	    throw "wrong k value for oct(symmetric) key";
	s += '"' + 'kty' + '":"' + o.kty + '",';
	s += '"' + 'k' + '":"' + o.k + '"}';
    }
    //alert(s);

    // 2. get thumb print
    var hJWK = rstrtohex(s);
    var hash = KJUR.crypto.Util.hashHex(hJWK, "sha256");
    var hashB64U = hextob64u(hash);

    return hashB64U;
};

/**
 * IntDate class for time representation for JSON Web Token(JWT)
 * @class KJUR.jws.IntDate class
 * @name KJUR.jws.IntDate
 * @since jws 3.0.1
 * @description
 * Utility class for IntDate which is integer representation of UNIX origin time
 * used in JSON Web Token(JWT).
 */
KJUR.jws.IntDate = {};

/**
 * get UNIX origin time from by string
 * @name get
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @param {String} s string of time representation
 * @return {Integer} UNIX origin time in seconds for argument 's'
 * @since jws 3.0.1
 * @throws "unsupported format: s" when malformed format
 * @description
 * This method will accept following representation of time.
 * <ul>
 * <li>now - current time</li>
 * <li>now + 1hour - after 1 hour from now</li>
 * <li>now + 1day - after 1 day from now</li>
 * <li>now + 1month - after 30 days from now</li>
 * <li>now + 1year - after 365 days from now</li>
 * <li>YYYYmmDDHHMMSSZ - UTC time (ex. 20130828235959Z)</li>
 * <li>number - UNIX origin time (seconds from 1970-01-01 00:00:00) (ex. 1377714748)</li>
 * </ul>
 */
KJUR.jws.IntDate.get = function(s) {
    if (s == "now") {
	return KJUR.jws.IntDate.getNow();
    } else if (s == "now + 1hour") {
	return KJUR.jws.IntDate.getNow() + 60 * 60;
    } else if (s == "now + 1day") {
	return KJUR.jws.IntDate.getNow() + 60 * 60 * 24;
    } else if (s == "now + 1month") {
	return KJUR.jws.IntDate.getNow() + 60 * 60 * 24 * 30;
    } else if (s == "now + 1year") {
	return KJUR.jws.IntDate.getNow() + 60 * 60 * 24 * 365;
    } else if (s.match(/Z$/)) {
	return KJUR.jws.IntDate.getZulu(s);
    } else if (s.match(/^[0-9]+$/)) {
	return parseInt(s);
    }
    throw "unsupported format: " + s;
};

/**
 * get UNIX origin time from Zulu time representation string
 * @name getZulu
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @param {String} s string of Zulu time representation (ex. 20151012125959Z)
 * @return {Integer} UNIX origin time in seconds for argument 's'
 * @since jws 3.0.1
 * @throws "unsupported format: s" when malformed format
 * @description
 * This method provides UNIX origin time from Zulu time.
 * Following representations are supported:
 * <ul>
 * <li>YYYYMMDDHHmmSSZ - GeneralizedTime format</li>
 * <li>YYMMDDHHmmSSZ - UTCTime format. If YY is greater or equal to 
 * 50 then it represents 19YY otherwise 20YY.</li>
 * </ul>
 * @example
 * KJUR.jws.IntDate.getZulu("20151012125959Z") => 1478...
 * KJUR.jws.IntDate.getZulu("151012125959Z") => 1478...
 */
KJUR.jws.IntDate.getZulu = function(s) {
    var matchResult = s.match(/(\d+)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z/);
    if (matchResult) {
        var sYear = matchResult[1];
	var year = parseInt(sYear);
	if (sYear.length == 4) {
        } else if (sYear.length == 2) {
	    if (50 <= year && year < 100) {
		year = 1900 + year;
	    } else if (0 <= year && year < 50) {
		year = 2000 + year;
	    } else {
		throw "malformed year string for UTCTime";
	    }
	} else {
	    throw "malformed year string";
	}
	var month = parseInt(matchResult[2]) - 1;
	var day = parseInt(matchResult[3]);
	var hour = parseInt(matchResult[4]);
	var min = parseInt(matchResult[5]);
	var sec = parseInt(matchResult[6]);
	var d = new Date(Date.UTC(year, month, day, hour, min, sec));
	return ~~(d / 1000);
    }
    throw "unsupported format: " + s;
};

/**
 * get UNIX origin time of current time
 * @name getNow
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @return {Integer} UNIX origin time for current time
 * @since jws 3.0.1
 * @description
 * This method provides UNIX origin time for current time
 * @example
 * KJUR.jws.IntDate.getNow() => 1478...
 */
KJUR.jws.IntDate.getNow = function() {
    var d = ~~(new Date() / 1000);
    return d;
};

/**
 * get UTC time string from UNIX origin time value
 * @name intDate2UTCString
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @param {Integer} intDate UNIX origin time value (ex. 1478...)
 * @return {String} UTC time string
 * @since jws 3.0.1
 * @description
 * This method provides UTC time string for UNIX origin time value.
 * @example
 * KJUR.jws.IntDate.intDate2UTCString(1478...) => "2015 Oct ..."
 */
KJUR.jws.IntDate.intDate2UTCString = function(intDate) {
    var d = new Date(intDate * 1000);
    return d.toUTCString();
};

/**
 * get UTC time string from UNIX origin time value
 * @name intDate2Zulu
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @param {Integer} intDate UNIX origin time value (ex. 1478...)
 * @return {String} Zulu time string
 * @since jws 3.0.1
 * @description
 * This method provides Zulu time string for UNIX origin time value.
 * @example
 * KJUR.jws.IntDate.intDate2UTCString(1478...) => "20151012...Z"
 */
KJUR.jws.IntDate.intDate2Zulu = function(intDate) {
    var d = new Date(intDate * 1000);
    var year = ("0000" + d.getUTCFullYear()).slice(-4);    
    var mon =  ("00" + (d.getUTCMonth() + 1)).slice(-2);    
    var day =  ("00" + d.getUTCDate()).slice(-2);    
    var hour = ("00" + d.getUTCHours()).slice(-2);    
    var min =  ("00" + d.getUTCMinutes()).slice(-2);    
    var sec =  ("00" + d.getUTCSeconds()).slice(-2);    
    return year + mon + day + hour + min + sec + "Z";
};

