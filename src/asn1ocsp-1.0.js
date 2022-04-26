/* asn1ocsp-1.1.8.js (c) 2016-2022 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * asn1ocsp.js - ASN.1 DER encoder classes for OCSP protocol
 *
 * Copyright (c) 2016-2021 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1ocsp-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.20 asn1ocsp 1.1.8 (2022-Apr-25)
 * @since jsrsasign 6.1.0
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

/**
 * ASN.1 classes for OCSP protocol<br/>
 * <p>
 * This name space provides 
 * <a href="https://tools.ietf.org/html/rfc6960">RFC 6960
 * Online Certificate Status Protocol (OCSP)</a> ASN.1 request and response generator.
 *
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily generate OCSP data by JSON object</li>
 * </ul>
 * 
 * <h4>OCSP Response Encoder Classes</h4>
 * <ul>
 * <li>{@link KJUR.asn1.ocsp.OCSPResponse}</li>
 * <li>{@link KJUR.asn1.ocsp.ResponseBytes}</li>
 * <li>{@link KJUR.asn1.ocsp.BasicOCSPResponse}</li>
 * <li>{@link KJUR.asn1.ocsp.ResponseData}</li>
 * <li>{@link KJUR.asn1.ocsp.ResponderID}</li>
 * <li>{@link KJUR.asn1.ocsp.SingleResponseList}</li>
 * <li>{@link KJUR.asn1.ocsp.SingleResponse}</li>
 * <li>{@link KJUR.asn1.ocsp.CertID}</li>
 * <li>{@link KJUR.asn1.ocsp.CertStatus}</li>
 * </ul>
 *
 * <h4>OCSP Request Encoder Classes</h4>
 * <ul>
 * <li>{@link KJUR.asn1.ocsp.OCSPRequest}</li>
 * <li>{@link KJUR.asn1.ocsp.TBSRequest}</li>
 * <li>{@link KJUR.asn1.ocsp.Request}</li>
 * <li>{@link KJUR.asn1.ocsp.CertID}</li>
 * </ul>
 *
 * <h4>OCSP Utility classes</h4>
 * <ul>
 * <li>{@link KJUR.asn1.ocsp.OCSPUtil} - simple request parser</li>
 * <li>{@link KJUR.asn1.ocsp.OCSPParser} - request parser</li>
 * </ul>
 * </p>
 * @name KJUR.asn1.ocsp
 * @namespace
 */
if (typeof KJUR.asn1.ocsp == "undefined" || !KJUR.asn1.ocsp) KJUR.asn1.ocsp = {};

KJUR.asn1.ocsp.DEFAULT_HASH = "sha1";

/**
 * OCSPResponse ASN.1 class encoder<br/>
 * @name KJUR.asn1.ocsp.OCSPResponse
 * @class OCSPResponse ASN.1 class encoder
 * @param {Array} params JSON object of constructor parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 * @see KJUR.asn1.ocsp.ResponseBytes
 *
 * @description
 * OCSPResponse ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
 * <pre>
 * OCSPResponse ::= SEQUENCE {
 *    responseStatus         OCSPResponseStatus,
 *    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
 * OCSPResponseStatus ::= ENUMERATED {
 *     successful            (0),  -- Response has valid confirmations
 *     malformedRequest      (1),  -- Illegal confirmation request
 *     internalError         (2),  -- Internal error in issuer
 *     tryLater              (3),  -- Try again later
 *                                 -- (4) is not used
 *     sigRequired           (5),  -- Must sign the request
 *     unauthorized          (6)   -- Request unauthorized
 * } 
 * </pre>
 * This constructor accepts all parameter of
 * {@link KJUR.asn1.ocsp.ResponseBytes} for "successful" response.
 * Further more following property is needed:
 * <ul>
 * <li>{Number or String}resstats - responseStatus value by
 * a number or name. (ex. 2, "internalError")</li>
 * </ul>
 *
 * @example
 * // default constructor for "successful"
 * o = new KJUR.asn1.ocsp.OCSPResponse({
 *   resstatus: "successful",
 *   <<ResponseBytes parameters>>
 * });
 * // constructor for error
 * new KJUR.asn1.ocsp.OCSPResponse({resstatus: 1})
 * new KJUR.asn1.ocsp.OCSPResponse({resstatus: "unauthorized"})
 */
KJUR.asn1.ocsp.OCSPResponse = function(params) {
    KJUR.asn1.ocsp.OCSPResponse.superclass.constructor.call(this);

    var _DEREnumerated = KJUR.asn1.DEREnumerated,
	_newObject = KJUR.asn1.ASN1Util.newObject,
	_ResponseBytes = KJUR.asn1.ocsp.ResponseBytes;

    var _aSTATUSNAME = ["successful", "malformedRequest", "internalError",
			"tryLater", "_not_used_", "sigRequired", "unauthorized"]; 

    this.params = null;

    this._getStatusCode = function() {
	var code = this.params.resstatus;
	if (typeof code == "number") return code;
	if (typeof code != "string") return -1;
	return _aSTATUSNAME.indexOf(code);
    };

    this.setByParam = function(params) {
	this.params = params;
    };

    this.tohex = function() {
	var params = this.params;

	var code = this._getStatusCode();
	if (code == -1) {
	    throw new Error("responseStatus not supported: " +
			    params.resstatus);
	}

	if (code != 0) {
	    return _newObject({seq: [{'enum': {'int': code}}]}).tohex();
	}
	
	var dResBytes = new _ResponseBytes(params);
	return _newObject({seq: [
	    {'enum': {'int': 0}},
	    {tag: {tag: "a0", explicit: true, obj: dResBytes}}
	]}).tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.OCSPResponse, KJUR.asn1.ASN1Object);

/**
 * ResponseBytes ASN.1 class encoder<br/>
 * @name KJUR.asn1.ocsp.ResponseBytes
 * @class ResponseBytes ASN.1 class encoder
 * @param {Array} params JSON object of constructor parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 * @see KJUR.asn1.ocsp.OCSPResponse
 * @see KJUR.asn1.ocsp.BasicOCSPResponse
 *
 * @description
 * OCSPResponse ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
 * <pre>
 * ResponseBytes ::=       SEQUENCE {
 *     responseType   OBJECT IDENTIFIER,
 *     response       OCTET STRING }
 * id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
 * id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
 * </pre>
 * This constructor accepts all parameter of
 * {@link KJUR.asn1.ocsp.BasicOCSPResponse}.
 * Further more following property is needed:
 * <ul>
 * <li>{String}restype - only "ocspBasic" can be available</li>
 * </ul>
 *
 * @example
 * o = new KJUR.asn1.ocsp.ResponseBytes({
 *   restype: "ocspBasic",
 *   // BasicOCSPResponse properties shall be specified
 * });
 */
KJUR.asn1.ocsp.ResponseBytes = function(params) {
    KJUR.asn1.ocsp.ResponseBytes.superclass.constructor.call(this);

    var _KJUR_asn1 = KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_BasicOCSPResponse = _KJUR_asn1.ocsp.BasicOCSPResponse;

    this.params = null;

    this.setByParam = function(params) {
	this.params = params;
    };

    this.tohex = function() {
	var params = this.params;

	if (params.restype != "ocspBasic") {
	    throw new Error("not supported responseType: " + params.restype);
	}

	var dBasic = new _BasicOCSPResponse(params);

	var a = [];
	a.push(new _DERObjectIdentifier({name: "ocspBasic"}));
	a.push(new _DEROctetString({hex: dBasic.tohex()}));

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.ResponseBytes, KJUR.asn1.ASN1Object);

/**
 * BasicOCSPResponse ASN.1 class encoder<br/>
 * @name KJUR.asn1.ocsp.BasicOCSPResponse
 * @class BasicOCSPResponse ASN.1 class encoder
 * @param {Array} params JSON object of constructor parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 * @see KJUR.asn1.ocsp.OCSPResponse
 * @see KJUR.asn1.ocsp.ResponseBytes
 * @see KJUR.asn1.ocsp.BasicOCSPResponse
 * @see KJUR.asn1.ocsp.ResponseData
 *
 * @description
 * OCSPResponse ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
 * <pre>
 * BasicOCSPResponse       ::= SEQUENCE {
 *    tbsResponseData      ResponseData,
 *    signatureAlgorithm   AlgorithmIdentifier,
 *    signature            BIT STRING,
 *    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 * </pre>
 * This constructor accepts all parameter of
 * {@link KJUR.asn1.ocsp.ResponseData}.
 * Further more following properties are available:
 * <ul>
 * <li>{ASN1Object}tbsresp (OPTION) - {@link KJUR.asn1.ASN1Object} or its
 * sub class object for tbsReponseData,
 * genelally {@link KJUR.asn1.ocsp.ResponseData}.
 * When "tbsresp" not specified, tbsresp will be set by
 * other parameters internally.</li>
 * <li>{String}sigalg - signatureAlgrithm name (ex. "SHA256withRSA")</li>
 * <li>{Object}reskey (OPTION) - specifies OCSP response signing private key.
 * Parameter "reskey" or "sighex" shall be specified.
 * Following values can be specified:
 *   <ul>
 *   <li>PKCS#1/5 or PKCS#8 PEM string of private key</li>
 *   <li>RSAKey/DSA/ECDSA key object. {@link KEYUTIL.getKey} is useful
 *   to generate a key object.</li>
 *   </ul>
 * </li>
 * <li>{String}sighex (OPTION) - hexadecimal string of signature value
 * (i.e. ASN.1 value(V) of signatureValue BIT STRING without
 * unused bits)</li>
 * <li>{Array}certs (OPTION) - array of PEM or hexadecimal string of
 * certificate such as OCSP responder certificate</li>
 * </ul>
 *
 * @example
 * // response data will be signed by "reskey"
 * new KJUR.asn1.ocsp.BasicOCSPResponse({
 *   ...<<ResponseData properties...>>...
 *   sigalg: "SHA256withRSA",
 *   reskey: <<OCSP Responder private key PEM or object>>,
 *   certs: [<<PEMorHEXstringOfCert1>>,...] });
 *
 * // explicitly specify "signature" by "sighex"
 * new KJUR.asn1.ocsp.BasicOCSPResponse({
 *   ...<<ResponseData properties...>>...
 *   sigalg: "SHA256withRSA",
 *   sighex: "12abcd...",
 *   certs: [<<PEMorHEXstringOfCert1>>,...] });
 * 
 * // explicitly specify "tbsResponseData" and sign
 * new KJUR.asn1.ocsp.BasicOCSPResponse({
 * { tbsresp: <<subclass of ASN1Object>>,
 *   sigalg: "SHA256withRSA",
 *   reskey: <<OCSP Responder private key PEM or object>>,
 *   certs: [<<PEMorHEXstringOfCert1>>,...] }
 */
KJUR.asn1.ocsp.BasicOCSPResponse = function(params) {
    KJUR.asn1.ocsp.BasicOCSPResponse.superclass.constructor.call(this);

    var _Error = Error,
	_KJUR_asn1 = KJUR.asn1,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERGeneralizedTime = _KJUR_asn1.DERGeneralizedTime,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_DERBitString = _KJUR_asn1.DERBitString,
	_Extensions = _KJUR_asn1.x509.Extensions,
	_AlgorithmIdentifier = _KJUR_asn1.x509.AlgorithmIdentifier,
	_KJUR_asn1_ocsp = _KJUR_asn1.ocsp,
	_ResponderID = _KJUR_asn1_ocsp.ResponderID;
	_SingleResponseList = _KJUR_asn1_ocsp.SingleResponseList,
	_ResponseData = _KJUR_asn1_ocsp.ResponseData;

    this.params = null;

    this.setByParam = function(params) {
	this.params = params;
    };

    this.sign = function() {
	var params = this.params;
	var hTBS = params.tbsresp.tohex();
	var sig = new KJUR.crypto.Signature({alg: params.sigalg});
	sig.init(params.reskey);
	sig.updateHex(hTBS);
	params.sighex = sig.sign();
    };

    this.tohex = function() {
	var params = this.params;

	if (params.tbsresp == undefined) {
	    params.tbsresp = new _ResponseData(params);
	}

	if (params.sighex == undefined && params.reskey != undefined) {
	    this.sign();
	}

	var a = [];
	a.push(params.tbsresp);
	a.push(new _AlgorithmIdentifier({name: params.sigalg}));
	a.push(new _DERBitString({hex: "00" + params.sighex}));

	if (params.certs != undefined &&
	    params.certs.length != undefined) {
	    var aCert = [];
	    for (var i = 0; i < params.certs.length; i++) {
		var sCert = params.certs[i];
		var hCert = null;
		if (ASN1HEX.isASN1HEX(sCert)) {
		    hCert = sCert;
		} else if (sCert.match(/-----BEGIN/)) {
		    hCert = pemtohex(sCert);
		} else {
		    throw new _Error("certs[" + i + "] not hex or PEM");
		}
		aCert.push(new _ASN1Object({tlv: hCert}));
	    }
	    var seqCert = new _DERSequence({array: aCert});
	    a.push(new _DERTaggedObject({tag:'a0',explicit:true,obj:seqCert}));
	}
	
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.BasicOCSPResponse, KJUR.asn1.ASN1Object);

/**
 * ResponseData ASN.1 class encoder<br/>
 * @name KJUR.asn1.ocsp.ResponseData
 * @class ResponseData ASN.1 class encoder
 * @param {Array} params JSON object of constructor parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 * @see KJUR.asn1.ocsp.OCSPResponse
 * @see KJUR.asn1.ocsp.ResponseBytes
 * @see KJUR.asn1.ocsp.BasicOCSPResponse
 * @see KJUR.asn1.ocsp.ResponseData
 * @see KJUR.asn1.ocsp.SingleResponse
 * @see KJUR.asn1.x509.Extensions
 * @see KJUR.asn1.DERGeneralizedTime
 *
 * @description
 * ResponseData ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
 * <pre>
 * ResponseData ::= SEQUENCE {
 *    version              [0] EXPLICIT Version DEFAULT v1,
 *    responderID              ResponderID,
 *    producedAt               GeneralizedTime,
 *    responses                SEQUENCE OF SingleResponse,
 *    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 * </pre>
 * Following properties are available:
 * <ul>
 * <li>{Array}respid - JSON object of {@link KJUR.asn1.ocsp.ResponseID} parameter
 * for "responderID"</li>
 * <li>{Object}prodat - string or JSON parameter of 
 * {@link KJUR.asn1.DERGeneralizedTime} (ex. "20200904235959Z")</li>
 * <li>{Array}responses - array of {@link KJUR.asn1.ocsp.SingleResponse}
 * parameters</li>
 * <li>{Array}ext (OPTION) - array of extension parameters
 * for "responseExtensions".</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.ocsp.ResponseData({
 *   respid: {key: "12ab..."},
 *   prodat: "20200903235959Z",
 *   array: [
 *     <<SingleResponse parameter1>>, ...
 *   ],
 *   ext: [{extname:"ocspNonce",hex:"12ab..."}]
 * });
 */
KJUR.asn1.ocsp.ResponseData = function(params) {
    KJUR.asn1.ocsp.ResponseData.superclass.constructor.call(this);

    var _Error = Error,
	_KJUR_asn1 = KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERGeneralizedTime = _KJUR_asn1.DERGeneralizedTime,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_Extensions = _KJUR_asn1.x509.Extensions,
	_KJUR_asn1_ocsp = _KJUR_asn1.ocsp,
	_ResponderID = _KJUR_asn1_ocsp.ResponderID;
	_SingleResponseList = _KJUR_asn1_ocsp.SingleResponseList;
    
    this.params = null;

    this.tohex = function() {
	var params = this.params;
	if (params.respid != undefined) new _Error("respid not specified");
	if (params.prodat != undefined) new _Error("prodat not specified");
	if (params.array != undefined) new _Error("array not specified");

	var a = [];
	a.push(new _ResponderID(params.respid));
	a.push(new _DERGeneralizedTime(params.prodat));
	a.push(new _SingleResponseList(params.array));

	if (params.ext != undefined) {
	    var dExt = new _Extensions(params.ext);
	    a.push(new _DERTaggedObject({tag:'a1', explicit:true, obj:dExt}));
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.ResponseData, KJUR.asn1.ASN1Object);

/**
 * ResponderID ASN.1 class encoder<br/>
 * @name KJUR.asn1.ocsp.ResponderID
 * @class ResponderID ASN.1 class encoder
 * @param {Array} params JSON object of constructor parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 * @see KJUR.asn1.ocsp.OCSPResponse
 * @see KJUR.asn1.ocsp.ResponseBytes
 * @see KJUR.asn1.ocsp.BasicOCSPResponse
 * @see KJUR.asn1.ocsp.ResponseData
 * @see X509#getSubject
 * @see X509#getExtSubjectKeyIdentifier
 *
 * @description
 * ResponderID ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
 * <pre>
 * ResponderID ::= CHOICE {
 *    byName               [1] Name,
 *    byKey                [2] KeyHash }
 * KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
 *                             (excluding the tag and length fields)
 * </pre>
 * Following properties are available:
 * <ul>
 * <li>{Array}name (OPTION) - JSON object of {@link KJUR.asn1.x509.X500Name} parameter,
 * PEM string of X.509 certificate or {@link X509} object for "byName",</li>
 * <li>{String}key (OPTION) - hexadecimal string of KeyHash value,
 * PEM string of X.509 certificate or {@link X509} object for "byKey"</li>
 * </ul>
 * <br/>
 * NOTE: From jsrsasign 10.5.20, "name" and "key" member values can be
 * specified by PEM string of X.509 certificate or {@link X509} object.
 * For "name", subject field of the certificate will be used and
 * for "key", subjectKeyIdentifier extension value of the certificate will be used
 * respectively.
 *
 * @example
 * new KJUR.asn1.ocsp.ResponderID({key: "12ab..."})
 * new KJUR.asn1.ocsp.ResponderID({name: {str: "/C=JP/O=Resp"}})
 * new KJUR.asn1.ocsp.ResponderID({name: {array: [[{type:"C",value:"JP",ds:"prn"}]...]}})
 * // by certificate
 * new KJUR.asn1.ocsp.ResponderID({key: "-----BEGIN CERTIFICATE..."})
 * new KJUR.asn1.ocsp.ResponderID({name: "-----BEGIN CERTIFICATE..."})
 * // by X509 object
 * new KJUR.asn1.ocsp.ResponderID({key: new X509(...)})
 * new KJUR.asn1.ocsp.ResponderID({name: new X509(...)})
 */
KJUR.asn1.ocsp.ResponderID = function(params) {
    KJUR.asn1.ocsp.ResponderID.superclass.constructor.call(this);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_newObject = _KJUR_asn1.ASN1Util.newObject,
	_X500Name = _KJUR_asn1.x509.X500Name,
	_isHex = _KJUR.lang.String.isHex,
	_Error = Error;
    
    this.params = null;
    
    this.tohex = function() {
	var params = this.params;
	if (params.key != undefined) {
	    var hKey = null;
	    if (typeof params.key == "string") {
		if (_isHex(params.key)) hKey = params.key;
		if (params.key.match(/-----BEGIN CERTIFICATE/)) {
		    var x = new X509(params.key);
		    var extSKID = x.getExtSubjectKeyIdentifier();
		    if (extSKID != null) hKey = extSKID.kid.hex;
		}
	    } else if (params.key instanceof X509) {
		var extSKID = params.key.getExtSubjectKeyIdentifier();
		if (extSKID != null) hKey = extSKID.kid.hex;
	    }
	    if (hKey == null) throw new _Error("wrong key member value");
	    var dTag = _newObject({tag: {tag:"a2",
					 explicit:true,
					 obj:{octstr:{hex:hKey}}}});
	    return dTag.tohex();
	} else if (params.name != undefined) {
	    var pName = null;
	    if (typeof params.name == "string" &&
		params.name.match(/-----BEGIN CERTIFICATE/)) {
		var x = new X509(params.name);
		pName = x.getSubject();
	    } else if (params.name instanceof X509) {
		pName = params.name.getSubject();
	    } else if (typeof params.name == "object" &&
		       (params.name.array != undefined ||
			params.name.str != undefined)) {
		pName = params.name;
	    }
	    if (pName == null) throw new _Error("wrong name member value");
	    var dTag = _newObject({tag: {tag:"a1",
					 explicit:true,
					 obj:new _X500Name(pName)}});
	    return dTag.tohex();
	}
	throw new _Error("key or name not specified");
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.ResponderID, KJUR.asn1.ASN1Object);

/**
 * ASN.1 class encoder for SEQUENCE OF SingleResponse<br/>
 * @name KJUR.asn1.ocsp.SingleResponseList
 * @class ASN.1 class encoder for SEQUENCE OF SingleResponse
 * @param {Array} params array of JSON object for SingleResponse parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 * @see KJUR.asn1.ocsp.OCSPResponse
 * @see KJUR.asn1.ocsp.ResponseBytes
 * @see KJUR.asn1.ocsp.BasicOCSPResponse
 * @see KJUR.asn1.ocsp.ResponseData
 * @see KJUR.asn1.ocsp.SingleResponse
 *
 * @description
 * ASN.1 class of SEQUENCE OF SingleResponse is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
 * <pre>
 * ResponseData ::= SEQUENCE {
 *    version              [0] EXPLICIT Version DEFAULT v1,
 *    responderID              ResponderID,
 *    producedAt               GeneralizedTime,
 *    responses                SEQUENCE OF SingleResponse,
 *    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 * SingleResponse ::= SEQUENCE {
 *    certID                       CertID,
 *    certStatus                   CertStatus,
 *    thisUpdate                   GeneralizedTime,
 *    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
 *    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
 * </pre>
 * Following properties are available:
 * <ul>
 * <li>{Array}name (OPTION) - JSON object of {@link KJUR.asn1.x509.X500Name} parameter
 * for "byName"</li>
 * <li>{String}key (OPTION) - hexadecimal string of KeyHash value</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.ocsp.SingleResponseList([{
 *   certid: {alg:"sha1",issname:"12ab",isskey:"12ab",sbjsn:"12ab"},
 *   status: {status: "good"},
 *   thisupdate: "20200903235959Z"
 * },{
 *   certid: {alg:"sha1",issname:"24ab",isskey:"24ab",sbjsn:"24ab"},
 *   status: {status: "good"},
 *   thisupdate: "20200904235959Z"
 * ])
 */
KJUR.asn1.ocsp.SingleResponseList = function(params) {
    KJUR.asn1.ocsp.SingleResponseList.superclass.constructor.call(this);

    var _KJUR_asn1 = KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_SingleResponse = _KJUR_asn1.ocsp.SingleResponse;

    this.params = null;
    
    this.tohex = function() {
	var params = this.params;

	if (typeof params != "object" || params.length == undefined) {
	    throw new Error("params not specified properly");
	}

	var a = [];
	for (var i = 0; i < params.length; i++) {
	    a.push(new _SingleResponse(params[i]));
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.SingleResponseList, KJUR.asn1.ASN1Object);

/**
 * SingleResponse ASN.1 class encoder<br/>
 * @name KJUR.asn1.ocsp.SingleResponse
 * @class SingleResponse ASN.1 class encoder
 * @param {Array} params JSON object for SingleResponse parameter
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 * @see KJUR.asn1.ocsp.OCSPResponse
 * @see KJUR.asn1.ocsp.ResponseBytes
 * @see KJUR.asn1.ocsp.BasicOCSPResponse
 * @see KJUR.asn1.ocsp.ResponseData
 * @see KJUR.asn1.ocsp.SingleResponse
 * @see KJUR.asn1.ocsp.CertID
 * @see KJUR.asn1.ocsp.CertStatus
 *
 * @description
 * ASN.1 class of SEQUENCE OF SingleResponse is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
 * <pre>
 * SingleResponse ::= SEQUENCE {
 *    certID                       CertID,
 *    certStatus                   CertStatus,
 *    thisUpdate                   GeneralizedTime,
 *    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
 *    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
 * </pre>
 * Following properties are available:
 * <ul>
 * <li>{Array}certid - JSON object of {@link KJUR.asn1.ocsp.CertID} parameter</li>
 * <li>{Array}status - JSON object of {@link KJUR.asn1.ocsp.CertStatus} parameter</li>
 * <li>{Object}thisupdate - {@link KJUR.asn1.DERGeneralizedTime} parameter
 * for "thisUpdate"</li>
 * <li>{Object}nextupdate (OPTION) - {@link KJUR.asn1.DERGeneralizedTime} parameter
 * for "nextUpdate"</li>
 * <li>{Array}ext (OPTION) - array of JSON object 
 * {@link KJUR.asn1.x509.Extension} sub class parameter for
 * "singleExtensions"</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.ocsp.SingleResponse({
 *   certid: {alg:"sha1",issname:"12ab",isskey:"12ab",sbjsn:"12ab"},
 *   status: {status: "good"},
 *   thisupdate: "20200903235959Z",
 *   nextupdate: "20200913235959Z",
 *   ext: [<<Extension parameters>>...]
 * })
 */
KJUR.asn1.ocsp.SingleResponse = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERGeneralizedTime = _KJUR_asn1.DERGeneralizedTime,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_KJUR_asn1_ocsp = _KJUR_asn1.ocsp,
	_CertID = _KJUR_asn1_ocsp.CertID,
	_CertStatus = _KJUR_asn1_ocsp.CertStatus,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_Extensions = _KJUR_asn1_x509.Extensions;

    _KJUR_asn1_ocsp.SingleResponse.superclass.constructor.call(this);

    this.params = null;
    
    this.tohex = function() {
	var params = this.params;
	var a = [];

	if (params.certid == undefined) throw new _Error("certid unspecified");
	if (params.status == undefined) throw new _Error("status unspecified");
	if (params.thisupdate == undefined) throw new _Error("thisupdate unspecified");

	a.push(new _CertID(params.certid));
	a.push(new _CertStatus(params.status));
	a.push(new _DERGeneralizedTime(params.thisupdate));

	if (params.nextupdate != undefined) {
	    var dTime = new _DERGeneralizedTime(params.nextupdate);
	    a.push(new _DERTaggedObject({tag:'a0', explicit:true, obj:dTime}));
	}

	if (params.ext != undefined) {
	    var dExt = new _Extensions(params.ext);
	    a.push(new _DERTaggedObject({tag:'a1', explicit:true, obj:dExt}));
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.SingleResponse, KJUR.asn1.ASN1Object);

/**
 * ASN.1 CertID class for OCSP<br/>
 * @name KJUR.asn1.ocsp.CertID
 * @class ASN.1 CertID class for OCSP
 * @param {Array} params JSON object of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
 * @see KJUR.asn1.ocsp.SingleResponse
 * @see KJUR.asn1.x509.AlgorithmIdentifier
 *
 * @description
 * CertID ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
 * <pre>
 * CertID ::= SEQUENCE {
 *   hashAlgorithm   AlgorithmIdentifier,
 *   issuerNameHash  OCTET STRING, -- Hash of issuer's DN
 *   issuerKeyHash   OCTET STRING, -- Hash of issuer's public key
 *   serialNumber    CertificateSerialNumber }
 * </pre>
 * Following properties are available in "params" of the constructor:
 * <ul>
 * <li>{String}alg (OPTION) - hash algorithm name. Default is "sha1" (ex, "sha1")</li>
 * <li>{String}issname (OPTION) - hexadecimal string of issuerNameHash</li>
 * <li>{String}isskey (OPTION) - hexadecimal string of issuerKeyHash</li>
 * <li>{String}sbjsn (OPTION) - hexadecimal string of serial number of subject certificate</li>
 * <li>{String}issuerCert (OPTION) - PEM string of issuer certificate.
 * Property "issname" and "isskey" will be set by "issuerCert".</li>
 * <li>{String}subjectCert (OPTION) - PEM string of issuer certificate.
 * Property "sbjsn" will be set by "subjectCert".</li>
 * </ul>
 * <br/>
 * NOTE: Properties "namehash", "keyhash" and "serial" are
 * changed to "issname", "isskey", and "sbjsn" respectively
 * since jsrsasign 9.1.6 asn1ocsp 1.1.0.
 *
 * @example
 * // constructor with explicit values (changed since jsrsasign 9.1.6)
 * new KJUR.asn1.ocsp.CertID({issname: "1a...", isskey: "ad...", sbjsn: "1234", alg: "sha256"});
 *
 * // constructor with certs (sha1 is used by default)
 * o = new KJUR.asn1.ocsp.CertID({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN..."});
 *
 * // constructor with certs and sha256
 * o = new KJUR.asn1.ocsp.CertID({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"});
 */
KJUR.asn1.ocsp.CertID = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier,
	_KJUR_asn1_ocsp = _KJUR_asn1.ocsp,
	_DEFAULT_HASH = _KJUR_asn1_ocsp.DEFAULT_HASH,
	_KJUR_crypto = _KJUR.crypto,
	_hashHex = _KJUR_crypto.Util.hashHex,
	_X509 = X509,
	_ASN1HEX = ASN1HEX,
	_getVbyList = _ASN1HEX.getVbyList;

    _KJUR_asn1_ocsp.CertID.superclass.constructor.call(this);

    this.DEFAULT_HASH = "sha1";
    this.params = null;

    /**
     * set CertID ASN.1 object by values.<br/>
     * @name setByValue
     * @memberOf KJUR.asn1.ocsp.CertID#
     * @function
     * @param {String} issuerNameHashHex hexadecimal string of hash value of issuer name
     * @param {String} issuerKeyHashHex hexadecimal string of hash value of issuer public key
     * @param {String} serialNumberHex hexadecimal string of certificate serial number to be verified
     * @param {String} algName hash algorithm name used for above arguments (ex. "sha1") DEFAULT: sha1
     * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
     * @example
     * o = new KJUR.asn1.ocsp.CertID();
     * o.setByValue("1fac...", "fd3a...", "1234"); // sha1 is used by default
     * o.setByValue("1fac...", "fd3a...", "1234", "sha256");
     */
    this.setByValue = function(issuerNameHashHex, issuerKeyHashHex,
			       serialNumberHex, algName) {
	if (algName == undefined) algName = this.DEFAULT_HASH;
	this.params = {
	    alg: algName,
	    issname: issuerNameHashHex,
	    isskey: issuerKeyHashHex,
	    sbjsn: serialNumberHex
	};
    };

    /**
     * set CertID ASN.1 object by PEM certificates.<br/>
     * @name setByCert
     * @memberOf KJUR.asn1.ocsp.CertID#
     * @function
     * @param {String} issuerCert string of PEM issuer certificate
     * @param {String} subjectCert string of PEM subject certificate to be verified by OCSP
     * @param {String} algName hash algorithm name used for above arguments (ex. "sha1") DEFAULT: sha1
     * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
     * @deprecated since jsrsasign 10.5.7 asn1ocsp 1.1.6. Please use setByParam instead.
     *
     * @example
     * o = new KJUR.asn1.ocsp.CertID();
     * o.setByCert("-----BEGIN...", "-----BEGIN..."); // sha1 is used by default
     * o.setByCert("-----BEGIN...", "-----BEGIN...", "sha256");
     */
    this.setByCert = function(issuerCert, subjectCert, algName) {
	if (algName == undefined) algName = this.DEFAULT_HASH;
	this.params = {
	    alg: algName,
	    issuerCert: issuerCert,
	    subjectCert: subjectCert,
	};
    };

    /**
     * calculate CertID parameter by certificates.<br/>
     * @name getParamByCerts
     * @memberOf KJUR.asn1.ocsp.CertID#
     * @function
     * @param {string} issuerCert string of PEM issuer certificate
     * @param {string} subjectCert string of PEM subject certificate to be verified by OCSP
     * @param {string} algName hash algorithm name used for above arguments (ex. "sha1") DEFAULT: sha1
     * @param {object} associative array with alg, issname, isskey and sbjsn members
     * @since jsrsasign 10.5.7 asn1ocsp 1.1.6
     *
     * @description
     * This method calculates issuer name hash, issuer key hash and subject serial
     * number then returns an associative array with alg, issname, isskey and sbjsn members.
     *
     * @example
     * o = new KJUR.asn1.ocsp.CertID();
     * o.getParamByCerts("-----BEGIN...", "-----BEGIN...", "sha256") &rarr;
     * {
     *   alg: "sha256",
     *   issname: "12abcd...",
     *   isskey: "23cdef...",
     *   sbjsn: "57b3..."
     * }
     */
    this.getParamByCerts = function(issCert, sbjCert, algName) {
	if (algName == undefined) algName = this.DEFAULT_HASH;
	var xISS = new _X509(issCert);
	var xSBJ = new _X509(sbjCert);
	var issname = _hashHex(xISS.getSubjectHex(), algName);
	var hSPKI = xISS.getPublicKeyHex();
	var isskey = _hashHex(_getVbyList(hSPKI, 0, [1], "03", true), algName);
	var sbjsn = xSBJ.getSerialNumberHex();
	var info = {
	    alg: algName,
	    issname: issname,
	    isskey: isskey,
	    sbjsn: sbjsn
	};
	return info;
    };

    this.tohex = function() {
	if (typeof this.params != "object") throw new Error("params not set");
	    
	var p = this.params;
	var issname, isskey, sbjsn, alg;

	if (p.alg == undefined) {
	    alg = this.DEFAULT_HASH;
	} else {
	    alg = p.alg;
	}

	if (p.issuerCert != undefined &&
	    p.subjectCert != undefined) {
	    var info = this.getParamByCerts(p.issuerCert, p.subjectCert, alg);
	    issname = info.issname;
	    isskey = info.isskey;
	    sbjsn = info.sbjsn;
	} else if (p.issname != undefined &&
		   p.isskey != undefined &&
		   p.sbjsn != undefined) {
	    issname = p.issname;
	    isskey = p.isskey;
	    sbjsn = p.sbjsn;
	} else {
	    throw new Error("required param members not defined");
	}

	var dAlg = new _AlgorithmIdentifier({name: alg});
	var dIssName = new _DEROctetString({hex: issname});
	var dIssKey = new _DEROctetString({hex: isskey});
	var dSbjSn = new _DERInteger({hex: sbjsn});
	var seq = new _DERSequence({array: [dAlg, dIssName, dIssKey, dSbjSn]});
        this.hTLV = seq.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.CertID, KJUR.asn1.ASN1Object);

/**
 * CertStatus ASN.1 class encoder<br/>
 * @name KJUR.asn1.ocsp.CertStatus
 * @class CertStatus ASN.1 class encoder
 * @param {Array} params JSON object for CertStatus parameter
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 * @see KJUR.asn1.ocsp.OCSPResponse
 * @see KJUR.asn1.ocsp.ResponseBytes
 * @see KJUR.asn1.ocsp.BasicOCSPResponse
 * @see KJUR.asn1.ocsp.ResponseData
 * @see KJUR.asn1.ocsp.SingleResponse
 * @see KJUR.asn1.ocsp.CertID
 * @see KJUR.asn1.ocsp.CertStatus
 *
 * @description
 * ASN.1 class of SEQUENCE OF SingleResponse is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
 * <pre>
 * CertStatus ::= CHOICE {
 *     good        [0]     IMPLICIT NULL,
 *     revoked     [1]     IMPLICIT RevokedInfo,
 *     unknown     [2]     IMPLICIT UnknownInfo }
 * RevokedInfo ::= SEQUENCE {
 *     revocationTime              GeneralizedTime,
 *     revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
 * UnknownInfo ::= NULL
 * CRLReason ::= ENUMERATED {
 *      unspecified             (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6),
 *           -- value 7 is not used
 *      removeFromCRL           (8),
 *      privilegeWithdrawn      (9),
 *      aACompromise           (10) }
 * </pre>
 * Following properties are available:
 * <ul>
 * <li>{String}status - "good", "revoked" or "unknown"</li>
 * <li>{String}time (OPTION) - revocationTime YYYYMMDDHHmmSSZ (ex. "20200904235959Z")</li>
 * <li>{Number}reason (OPTION) - revocationReason code number</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.ocsp.CertStatus({status: "good"})
 * new KJUR.asn1.ocsp.CertStatus({status: "revoked", time: "20200903235959Z"})
 * new KJUR.asn1.ocsp.CertStatus({status: "revoked", time: "20200903235959Z", reason: 3})
 * new KJUR.asn1.ocsp.CertStatus({status: "unknown"})
 */
KJUR.asn1.ocsp.CertStatus = function(params) {
    KJUR.asn1.ocsp.CertStatus.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;
	if (params.status == "good") return "8000";
	if (params.status == "unknown") return "8200";
	if (params.status == "revoked") {
	    var a = [{gentime: {str: params.time}}];
	    if (params.reason != undefined) {
		a.push({tag: {tag: 'a0', 
			      explicit: true,
			      obj: {'enum': {'int': params.reason}}}});
	    }
	    var tagParam = {tag: 'a1', explicit: false, obj: {seq: a}};
	    return KJUR.asn1.ASN1Util.newObject({tag: tagParam}).tohex();
	}
	throw new Error("bad status");
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.ocsp.CertStatus, KJUR.asn1.ASN1Object);

// ---- END OF Classes for OCSP response -----------------------------------

/**
 * ASN.1 Request class for OCSP<br/>
 * @name KJUR.asn1.ocsp.Request
 * @class ASN.1 Request class for OCSP
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
 * @description
 * Request ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
 * singleRequestExtensions is not supported yet in this version such as nonce.
 * <pre>
 * Request ::= SEQUENCE {
 *   reqCert                  CertID,
 *   singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL }
 * </pre>
 * @example
 * // default constructor
 * o = new KJUR.asn1.ocsp.Request();
 * // constructor with certs (sha1 is used by default)
 * o = new KJUR.asn1.ocsp.Request({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN..."});
 * // constructor with certs and sha256
 * o = new KJUR.asn1.ocsp.Request({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"});
 * // constructor with values
 * o = new KJUR.asn1.ocsp.Request({namehash: "1a...", keyhash: "ad...", serial: "1234", alg: "sha256"});
 */
KJUR.asn1.ocsp.Request = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_ocsp = _KJUR_asn1.ocsp;
    
    _KJUR_asn1_ocsp.Request.superclass.constructor.call(this);
    this.dReqCert = null;
    this.dExt = null;
    
    this.tohex = function() {
	var a = [];

	// 1. reqCert
	if (this.dReqCert === null)
	    throw "reqCert not set";
	a.push(this.dReqCert);

	// 2. singleRequestExtensions (not supported yet)

	// 3. construct SEQUENCE
	var seq = new _DERSequence({array: a});
        this.hTLV = seq.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (typeof params !== "undefined") {
	var o = new _KJUR_asn1_ocsp.CertID(params);
	this.dReqCert = o;
    }
};
extendClass(KJUR.asn1.ocsp.Request, KJUR.asn1.ASN1Object);

/**
 * ASN.1 TBSRequest class for OCSP<br/>
 * @name KJUR.asn1.ocsp.TBSRequest
 * @class ASN.1 TBSRequest class for OCSP
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
 * @description
 * TBSRequest ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
 * <pre>
 * TBSRequest ::= SEQUENCE {
 *   version            [0] EXPLICIT Version DEFAULT v1,
 *   requestorName      [1] EXPLICIT GeneralName OPTIONAL,
 *   requestList            SEQUENCE OF Request,
 *   requestExtensions  [2] EXPLICIT Extensions OPTIONAL }
 * </pre>
 * @example
 * // default constructor
 * o = new KJUR.asn1.ocsp.TBSRequest();
 * // constructor with requestList parameter
 * o = new KJUR.asn1.ocsp.TBSRequest({reqList:[
 *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg:},
 *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"}
 * ]});
 */
KJUR.asn1.ocsp.TBSRequest = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_ocsp = _KJUR_asn1.ocsp;

    _KJUR_asn1_ocsp.TBSRequest.superclass.constructor.call(this);
    this.version = 0;
    this.dRequestorName = null;
    this.dRequestList = [];
    this.dRequestExt = null;

    /**
     * set TBSRequest ASN.1 object by array of parameters.<br/>
     * @name setRequestListByParam
     * @memberOf KJUR.asn1.ocsp.TBSRequest#
     * @function
     * @param {Array} aParams array of parameters for Request class
     * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
     * @example
     * o = new KJUR.asn1.ocsp.TBSRequest();
     * o.setRequestListByParam([
     *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg:},
     *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"}
     * ]);
     */
    this.setRequestListByParam = function(aParams) {
	var a = [];
	for (var i = 0; i < aParams.length; i++) {
	    var dReq = new _KJUR_asn1_ocsp.Request(aParams[0]);
	    a.push(dReq);
	}
	this.dRequestList = a;
    };

    this.tohex = function() {
	var a = [];

	// 1. version
	if (this.version !== 0)
	    throw "not supported version: " + this.version;

	// 2. requestorName
	if (this.dRequestorName !== null)
	    throw "requestorName not supported";

	// 3. requestList
	var seqRequestList = 
	    new _DERSequence({array: this.dRequestList});
	a.push(seqRequestList);

	// 4. requestExtensions
	if (this.dRequestExt !== null)
	    throw "requestExtensions not supported";

	// 5. construct SEQUENCE
	var seq = new _DERSequence({array: a});
        this.hTLV = seq.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
	if (params.reqList !== undefined)
	    this.setRequestListByParam(params.reqList);
    }
};
extendClass(KJUR.asn1.ocsp.TBSRequest, KJUR.asn1.ASN1Object);


/**
 * ASN.1 OCSPRequest class for OCSP<br/>
 * @name KJUR.asn1.ocsp.OCSPRequest
 * @class ASN.1 OCSPRequest class for OCSP
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
 * @description
 * OCSPRequest ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
 * A signed request is not supported yet in this version.
 * <pre>
 * OCSPRequest ::= SEQUENCE {
 *   tbsRequest             TBSRequest,
 *   optionalSignature  [0] EXPLICIT Signature OPTIONAL }
 * </pre>
 * @example
 * // default constructor
 * o = new KJUR.asn1.ocsp.OCSPRequest();
 * // constructor with requestList parameter
 * o = new KJUR.asn1.ocsp.OCSPRequest({reqList:[
 *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg:},
 *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"}
 * ]});
 */
KJUR.asn1.ocsp.OCSPRequest = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_ocsp = _KJUR_asn1.ocsp;

    _KJUR_asn1_ocsp.OCSPRequest.superclass.constructor.call(this);
    this.dTbsRequest = null;
    this.dOptionalSignature = null;

    this.tohex = function() {
	var a = [];

	// 1. tbsRequest
	if (this.dTbsRequest !== null) {
	    a.push(this.dTbsRequest);
	} else {
	    throw "tbsRequest not set";
	}

	// 2. optionalSignature
	if (this.dOptionalSignature !== null)
	    throw "optionalSignature not supported";

	// 3. construct SEQUENCE
	var seq = new _DERSequence({array: a});
        this.hTLV = seq.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
	if (params.reqList !== undefined) {
	    var o = new _KJUR_asn1_ocsp.TBSRequest(params);
	    this.dTbsRequest = o;
	}
    }
};
extendClass(KJUR.asn1.ocsp.OCSPRequest, KJUR.asn1.ASN1Object);

/**
 * Utility class for OCSP<br/>
 * @name KJUR.asn1.ocsp.OCSPUtil
 * @class Utility class for OCSP
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
 * @description
 * This class provides utility static methods for OCSP.
 * <ul>
 * <li>{@link KJUR.asn1.ocsp.OCSPUtil.getRequestHex} - generates hexadecimal string of OCSP request</li>
 * </ul>
 */
KJUR.asn1.ocsp.OCSPUtil = {};

/**
 * generates hexadecimal string of OCSP request<br/>
 * @name getRequestHex
 * @memberOf KJUR.asn1.ocsp.OCSPUtil
 * @function
 * @param {String} issuerCert string of PEM issuer certificate
 * @param {String} subjectCert string of PEM subject certificate to be verified by OCSP
 * @param {String} algName hash algorithm name used for above arguments (ex. "sha1") DEFAULT: sha1
 * @return {String} hexadecimal string of generated OCSP request
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
 * @description
 * This static method generates hexadecimal string of OCSP request.
 * @example
 * // generate OCSP request using sha1 algorithnm by default.
 * hReq = KJUR.asn1.ocsp.OCSPUtil.getRequestHex("-----BEGIN...", "-----BEGIN...");
 */
KJUR.asn1.ocsp.OCSPUtil.getRequestHex = function(issuerCert, subjectCert, alg) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_ocsp = _KJUR_asn1.ocsp;

    if (alg === undefined) alg = _KJUR_asn1_ocsp.DEFAULT_HASH;
    var param = {alg: alg, issuerCert: issuerCert, subjectCert: subjectCert};
    var o = new _KJUR_asn1_ocsp.OCSPRequest({reqList: [param]});
    return o.tohex();
};

/**
 * simple parser for OCSPResponse (DEPRECATED)<br/>
 * @name getOCSPResponseInfo
 * @memberOf KJUR.asn1.ocsp.OCSPUtil
 * @function
 * @param {String} h hexadecimal string of DER OCSPResponse
 * @return {Object} JSON object of parsed OCSPResponse
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.1
 * @deprecated since jsrsasign 10.4.0 asn1ocsp 1.1.5 Please use OCSPParser.getOCSPRespnose
 *
 * @description
 * This static method parse a hexadecimal string of DER OCSPResponse and
 * returns JSON object of its parsed result.
 * Its result has following properties:
 * <ul>
 * <li>responseStatus - integer of responseStatus</li>
 * <li>certStatus - string of certStatus (ex. good, revoked or unknown)</li>
 * <li>thisUpdate - string of thisUpdate in Zulu(ex. 20151231235959Z)</li>
 * <li>nextUpdate - string of nextUpdate in Zulu(ex. 20151231235959Z)</li>
 * </ul>
 * NOTE: This method may not work preperly. Please use 
 * {@link KJUR.asn1.ocsp.OCSPParser#getOCSPResponse}.
 *
 * @example
 * info = KJUR.asn1.ocsp.OCSPUtil.getOCSPResponseInfo("3082...");
 */
KJUR.asn1.ocsp.OCSPUtil.getOCSPResponseInfo = function(h) {
    var _ASN1HEX = ASN1HEX,
	_getVbyList = _ASN1HEX.getVbyList,
	_getVbyListEx = _ASN1HEX.getVbyListEx,
	_getIdxbyList = _ASN1HEX.getIdxbyList,
	_getIdxbyListEx = _ASN1HEX.getIdxbyListEx,
	_getV = _ASN1HEX.getV;

    var result = {};
    try {
	var v = _getVbyListEx(h, 0, [0], "0a");
	result.responseStatus = parseInt(v, 16);
    } catch(ex) {};
    if (result.responseStatus !== 0) return result;

    try {
	// certStatus
	var idxCertStatus = _getIdxbyList(h, 0, [1,0,1,0,0,2,0,1]);
	if (h.substr(idxCertStatus, 2) === "80") {
	    result.certStatus = "good";
	} else if (h.substr(idxCertStatus, 2) === "a1") {
	    result.certStatus = "revoked";
	    result.revocationTime = 
		hextoutf8(_getVbyList(h, idxCertStatus, [0]));
	} else if (h.substr(idxCertStatus, 2) === "82") {
	    result.certStatus = "unknown";
	}
    } catch (ex) {};

    // thisUpdate
    try {
	var idxThisUpdate = _getIdxbyList(h, 0, [1,0,1,0,0,2,0,2]);
	result.thisUpdate = hextoutf8(_getV(h, idxThisUpdate));
    } catch (ex) {};

    // nextUpdate
    try {
	var idxEncapNextUpdate = _getIdxbyList(h, 0, [1,0,1,0,0,2,0,3]);
	if (h.substr(idxEncapNextUpdate, 2) === "a0") {
	    result.nextUpdate = 
		hextoutf8(_getVbyList(h, idxEncapNextUpdate, [0]));
	}
    } catch (ex) {};

    return result;
};

/**
 * OCSP request and response parser<br/>
 * @name KJUR.asn1.ocsp.OCSPParser
 * @class OCSP request and response parser
 * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
 *
 * @description
 * This class provides ASN.1 parser for
 * OCSP related ASN.1 data. <br/>
 * NOTE: OCSPResponse parser supported from jsrsasign 10.4.0.
 * <br/>
 * This parser supports following OCSP ASN.1 classes:
 * <ul>
 * <li>OCSP REQUEST
 * <ul>
 * <li>OCSPRequest - {@link KJUR.asn1.ocsp.OCSPParser#getOCSPRequest}</li>
 * <li>TBSRequest - {@link KJUR.asn1.ocsp.OCSPParser#getTBSRequest}</li>
 * <li>SEQUENCE OF Request - {@link KJUR.asn1.ocsp.OCSPParser#getRequestList}</li>
 * <li>Request - {@link KJUR.asn1.ocsp.OCSPParser#getRequest}</li>
 * </ul>
 * </li>
 * <li>OCSP RESPONSE
 * <ul>
 * <li>OCSPResponse - {@link KJUR.asn1.ocsp.OCSPParser#getOCSPResponse}</li>
 * <li>ResponseBytes - {@link KJUR.asn1.ocsp.OCSPParser#getResponseBytes}</li>
 * <li>BasicOCSPResponse - {@link KJUR.asn1.ocsp.OCSPParser#getBasicOCSPResponse}</li>
 * <li>ResponseData - {@link KJUR.asn1.ocsp.OCSPParser#getResponseData}</li>
 * <li>ResponderID - {@link KJUR.asn1.ocsp.OCSPParser#getResponderID}</li>
 * <li>SEQUENCE OF SingleResponse - {@link KJUR.asn1.ocsp.OCSPParser#getSingleResponseList}</li>
 * <li>SingleResponse - {@link KJUR.asn1.ocsp.OCSPParser#getSingleResponse}</li>
 * <li>CertStatus - {@link KJUR.asn1.ocsp.OCSPParser#getCertStatus}</li>
 * </ul>
 * </li>
 * <li>common
 * <ul>
 * <li>CertID - {@link KJUR.asn1.ocsp.OCSPParser#getCertID}</li>
 * </ul>
 * </li>
 * </ul>
 */
KJUR.asn1.ocsp.OCSPParser = function() {
    var _Error = Error,
	_X509 = X509,
	_x509obj = new _X509(),
	_ASN1HEX = ASN1HEX,
	_getV = _ASN1HEX.getV,
	_getTLV = _ASN1HEX.getTLV,
	_getIdxbyList = _ASN1HEX.getIdxbyList,
	_getVbyList = _ASN1HEX.getVbyList,
	_getTLVbyList = _ASN1HEX.getTLVbyList,
	_getVbyListEx = _ASN1HEX.getVbyListEx,
	_getTLVbyListEx = _ASN1HEX.getTLVbyListEx,
	_getChildIdx = _ASN1HEX.getChildIdx;

    /**
     * parse ASN.1 OCSPRequest<br/>
     * @name getOCSPRequest
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 OCSPRequest
     * @return {Array} array of JSON object of OCSPRequest parameter
     * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
     *
     * @description
     * This method will parse a hexadecimal string of 
     * OCSPRequest ASN.1 class is defined in 
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
     * <pre>
     * OCSPRequest ::= SEQUENCE {
     *   tbsRequest              TBSRequest,
     *   optionalSignature  [0]  EXPLICIT Signature OPTIONAL }
     * TBSRequest  ::=  SEQUENCE {
     *   version            [0]  EXPLICIT Version DEFAULT v1,
     *   requestorName      [1]  EXPLICIT GeneralName OPTIONAL,
     *   requestList             SEQUENCE OF Request,
     *   requestExtensions  [2]  EXPLICIT Extensions OPTIONAL }
     * Signature       ::=     SEQUENCE {
     *   signatureAlgorithm      AlgorithmIdentifier,
     *   signature               BIT STRING,
     *   certs              [0] EXPLICIT SEQUENCE OF Certificate
     *                          OPTIONAL}
     * </pre>
     * Currently Signature in OCSPRequest is not supported.
     * <br/>
     * 
     * @see KJUR.asn1.ocsp.OCSPParser#getTBSRequest
     * @see KJUR.asn1.ocsp.OCSPRequest
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getOCSPRequest("30...") &rarr;
     * { array: [{
     *    "alg": "sha1",
     *    "issname": "105fa67a80089db5279f35ce830b43889ea3c70d",
     *    "isskey": "0f80611c823161d52f28e78d4638b42ce1c6d9e2",
     *    "sbjsn": "0fef62075d715dc5e1d8bd03775c9686" }]}
     */
    this.getOCSPRequest = function(h) {
	var a = _getChildIdx(h, 0);

	if (a.length != 1 && a.length != 2) {
	    throw new _Error("wrong number elements: " + a.length);
	}

	var result = this.getTBSRequest(_getTLV(h, a[0]));
	return result;
    };

    /**
     * parse ASN.1 TBSRequest of OCSP<br/>
     * @name getTBSRequest
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 TBSRequest of OCSP
     * @return {Array} array of JSON object of TBSRequest parameter
     * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
     *
     * @description
     * This method will parse
     * TBSRequest ASN.1 class is defined in 
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
     * <pre>
     * TBSRequest  ::=  SEQUENCE {
     *   version            [0]  EXPLICIT Version DEFAULT v1,
     *   requestorName      [1]  EXPLICIT GeneralName OPTIONAL,
     *   requestList             SEQUENCE OF Request,
     *   requestExtensions  [2]  EXPLICIT Extensions OPTIONAL }
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParser#getOCSPRequest
     * @see KJUR.asn1.ocsp.OCSPParser#getRequestList
     * @see KJUR.asn1.ocsp.TBSRequest
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getTBSRequest("30...") &rarr;
     * {array: [{
     *   "alg": "sha1",
     *   "issname": "105fa67a80089db5279f35ce830b43889ea3c70d",
     *   "isskey": "0f80611c823161d52f28e78d4638b42ce1c6d9e2",
     *   "sbjsn": "0fef62075d715dc5e1d8bd03775c9686" }]}
     */
    this.getTBSRequest = function(h) {
	var result = {};
	var hReqList = _getTLVbyListEx(h, 0, [0], "30");
	result.array = this.getRequestList(hReqList);
	var hExt = _getTLVbyListEx(h, 0, ["[2]", 0], "30");
	if (hExt != null) {
	    result.ext = _x509obj.getExtParamArray(hExt);
	}

	return result;
    };

    /**
     * parse ASN.1 SEQUENCE OF Request in OCSP<br/>
     * @name getRequestList
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 SEQUENCE OF Request in OCSP
     * @return {Array} array of JSON object of Request parameter
     * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
     *
     * @description
     * This method will parse a hexadecimal string of
     * SEQUENCE OF Request ASN.1 class is defined in 
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
     * <br/>
     * NOTE: singleRequestExtensions is not supported yet in this version such as nonce.
     * <pre>
     * TBSRequest  ::=  SEQUENCE {
     *   version            [0]  EXPLICIT Version DEFAULT v1,
     *   requestorName      [1]  EXPLICIT GeneralName OPTIONAL,
     *   requestList             SEQUENCE OF Request,
     *   requestExtensions  [2]  EXPLICIT Extensions OPTIONAL }
     * Request ::= SEQUENCE {
     *   reqCert                  CertID,
     *   singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL }      
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParser#getTBSRequest
     * @see KJUR.asn1.ocsp.OCSPParser#getRequest
     * @see KJUR.asn1.ocsp.RequestList
     * @see KJUR.asn1.ocsp.Request
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getRequestList("30...") &rarr;
     * [{ alg: "sha1"
     *   issname: "...hex...",
     *   isskey: "...hex...",
     *   sbjsn: "...hex...",
     *   ext: [<<singleRequestExtension parameters>>...] }]
     */
    this.getRequestList = function(h) {
	var result = [];
	var a = _getChildIdx(h, 0);
	for (var i = 0; i < a.length; i++) {
	    var h = _getTLV(h, a[i]);
	    result.push(this.getRequest(h));
	}
	return result;
    };

    /**
     * parse ASN.1 Request of OCSP<br/>
     * @name getRequest
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 Request of OCSP
     * @return JSON object of Request parameter
     * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
     *
     * @description
     * This method will parse a hexadecimal string of
     * Request ASN.1 class is defined in 
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
     * <pre>
     * Request ::= SEQUENCE {
     *   reqCert                  CertID,
     *   singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL }      
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParser#getTBSRequest
     * @see KJUR.asn1.ocsp.OCSPParser#getRequestList
     * @see KJUR.asn1.ocsp.OCSPParser#getCertID
     * @see KJUR.asn1.ocsp.RequestList
     * @see KJUR.asn1.ocsp.Request
     * @see KJUR.asn1.ocsp.CertID
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getRequest("30...") &rarr;
     * { alg: "sha1"
     *   issname: "...hex...",
     *   isskey: "...hex...",
     *   sbjsn: "...hex...",
     *   ext: [<<singleRequestExtension parameters>>...] }
     */
    this.getRequest = function(h) {
	var a = _getChildIdx(h, 0);
	if (a.length != 1 && a.length != 2) {
	    throw new _Error("wrong number elements: " + a.length);
	}
	
	var params = this.getCertID(_getTLV(h, a[0]));

	if (a.length == 2) {
	    var idxExt = _getIdxbyList(h, 0, [1, 0]);
	    params.ext = _x509obj.getExtParamArray(_getTLV(h, idxExt));
	}

	return params;
    };

    /**
     * parse ASN.1 CertID of OCSP<br/>
     * @name getCertID
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of CertID
     * @return JSON object of CertID parameter
     * @since jsrsasign 9.1.6 asn1ocsp 1.1.0
     *
     * @description
     * This method will parse a hexadecimal string of
     * CertID ASN.1 class is defined in 
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
     * <pre>
     * CertID ::= SEQUENCE {
     *   hashAlgorithm   AlgorithmIdentifier,
     *   issuerNameHash  OCTET STRING, -- Hash of issuer's DN
     *   issuerKeyHash   OCTET STRING, -- Hash of issuer's public key
     *   serialNumber    CertificateSerialNumber }
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParser#getRequest
     * @see KJUR.asn1.ocsp.OCSPParser#getSingleResponse
     * @see KJUR.asn1.ocsp.CertID
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getCertID("30...") &rarr;
     * { alg: "sha1"
     *   issname: "...hex...",
     *   isskey: "...hex...",
     *   sbjsn: "...hex..." }
     */
    this.getCertID = function(h) {
	var a = _getChildIdx(h, 0);
	if (a.length != 4) {
	    throw new _Error("wrong number elements: " + a.length);
	}
	
	var x = new _X509();
	var result = {};
	result.alg = x.getAlgorithmIdentifierName(_getTLV(h, a[0]));
	result.issname = _getV(h, a[1]);
	result.isskey = _getV(h, a[2]);
	result.sbjsn = _getV(h, a[3]);
	
	return result;
    };

    /**
     * parse ASN.1 OCSPResponse of OCSP<br/>
     * @name getOCSPResponse
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of OCSPResponse
     * @return JSON object of OCSResponse parameter
     * @since jsrsasign 10.4.0 asn1ocsp 1.1.5
     *
     * @description
     * This method will parse a hexadecimal string of
     * ASN.1 OCSPResponse defined in
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
     * <pre>
     * OCSPResponse ::= SEQUENCE {
     *    responseStatus         OCSPResponseStatus,
     *    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
     * OCSPResponseStatus ::= ENUMERATED {
     *     successful            (0),  -- Response has valid confirmations
     *     malformedRequest      (1),  -- Illegal confirmation request
     *     internalError         (2),  -- Internal error in issuer
     *     tryLater              (3),  -- Try again later
     *                                 -- (4) is not used
     *     sigRequired           (5),  -- Must sign the request
     *     unauthorized          (6)   -- Request unauthorized }
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParser#getResponseBytes
     * @see KJUR.asn1.ocsp.OCSPResponse
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getOCSPResponse("30..") &rarr;
     * { resstatus: 0,
     *   restype: "ocspBasic",
     *   respid: {key: "12ab"},
     *   prodat: "20200903235959Z",
     *   array: [{
     *     certid: {alg:"sha1",issname:"12ab",isskey:"12ab",sbjsn:"12ab"},
     *     status: {status: "good"},
     *     thisupdate: "20200903235959Z" }],
     *   ext: [{extname: "ocspNonce", hex: "1234abcd"}],
     *   alg: "SHA256withRSA",
     *   sighex: "12ab",
     *   certs: ["3082...", "3082..."] }
     */
    this.getOCSPResponse = function(h) {
	var a = _getChildIdx(h, 0);
	var result;

	var hStatusV = _getV(h, a[0]);
	var iStatusV = parseInt(hStatusV);
	
	if (a.length == 1) return {resstatus: iStatusV};

	var hResponseBytes = _getTLVbyList(h, 0, [1, 0]);
	result = this.getResponseBytes(hResponseBytes);
	result.resstatus = iStatusV;
	
	return result;
    };

    /**
     * parse ASN.1 ResponseBytes of OCSP<br/>
     * @name getResponseBytes
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of ResponseBytes
     * @return JSON object of ResponseBytes parameter
     * @since jsrsasign 10.4.0 asn1ocsp 1.1.5
     *
     * @description
     * This method will parse a hexadecimal string of
     * ASN.1 ResponseBytes defined in
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
     * <pre>
     * ResponseBytes ::=       SEQUENCE {
     *     responseType   OBJECT IDENTIFIER,
     *     response       OCTET STRING }
     * id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
     * id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
     *
     * BasicOCSPResponse       ::= SEQUENCE {
     *    tbsResponseData      ResponseData,
     *    signatureAlgorithm   AlgorithmIdentifier,
     *    signature            BIT STRING,
     *    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParser#getOCSPResponse
     * @see KJUR.asn1.ocsp.OCSPParser#getBasicOCSPResponse
     * @see KJUR.asn1.ocsp.ResponseBytes
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getResponseBytes("30..") &rarr;
     * { restype: "ocspBasic",
     *   ...<<BasicOCSPResponse properties...>>...
     */
    this.getResponseBytes = function(h) {
	var a = _getChildIdx(h, 0);
	var result;

	var hBasicOCSPResponse = _getTLVbyList(h, 0, [1, 0]);
	result = this.getBasicOCSPResponse(hBasicOCSPResponse);

	var hResTypeV = _getV(h, a[0]);
	result.restype = KJUR.asn1.x509.OID.oid2name(hextooid(hResTypeV));
	
	return result;
    };

    /**
     * parse ASN.1 BasicOCSPResponse of OCSP<br/>
     * @name getBasicOCSPResponse
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of BasicOCSPResponse
     * @return JSON object of BasicOCSPResponse parameter
     * @since jsrsasign 10.4.0 asn1ocsp 1.1.5
     *
     * @description
     * This method will parse a hexadecimal string of
     * BasicOCSPResponse defined in 
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
     * <pre>
     * BasicOCSPResponse       ::= SEQUENCE {
     *    tbsResponseData      ResponseData,
     *    signatureAlgorithm   AlgorithmIdentifier,
     *    signature            BIT STRING,
     *    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParser#getResponseBytes
     * @see KJUR.asn1.ocsp.OCSPParser#getResponseData
     * @see KJUR.asn1.ocsp.BasicOCSPResponse
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getBasicOCSPResponse("30..") &rarr;
     * { ...<<ResponseData properties...>>...
     *   sigalg: "SHA256withRSA",
     *   sighex: "12abcd...",
     *   certs: [<<PEMorHEXstringOfCert1>>,...] });
     */
    this.getBasicOCSPResponse = function(h) {
	var a = _getChildIdx(h, 0);
	var result;

	result = this.getResponseData(_getTLV(h, a[0]));

	var x = new X509();
	result.alg = x.getAlgorithmIdentifierName(_getTLV(h, a[1]));

	var hSigHex = _getV(h, a[2]);
	result.sighex = hSigHex.substr(2);
	
	var hExt = _getVbyListEx(h, 0, ["[0]"]);
	if (hExt != null) {
	    var aCertIdx = _getChildIdx(hExt, 0);
	    var aCert = [];
	    for (var i = 0; i < aCertIdx.length; i++) {
		var hCert = _getTLV(hExt, aCertIdx[i]);
		aCert.push(hCert);
	    }
	    result.certs = aCert;
	}

	return result;
    };

    /**
     * parse ASN.1 ResponseData of OCSP<br/>
     * @name getResponseData
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of ResponseData
     * @return JSON object of ResponseData parameter
     * @since jsrsasign 10.4.0 asn1ocsp 1.1.5
     *
     * @description
     * This method will parse a hexadecimal string of
     * ASN.1 ResponseData defined in
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
     * <pre>
     * ResponseData ::= SEQUENCE {
     *    version              [0] EXPLICIT Version DEFAULT v1,
     *    responderID              ResponderID,
     *    producedAt               GeneralizedTime,
     *    responses                SEQUENCE OF SingleResponse,
     *    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParser#getBasicOCSPResponse
     * @see KJUR.asn1.ocsp.OCSPParser#getSingleResponse
     * @see KJUR.asn1.ocsp.ResponseData
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getResponseData("30..") &rarr;
     * { respid: {key: "12ab..."},
     *   prodat: "20200903235959Z",
     *   array: [<<SingleResponse parameter1>>, ...],
     *   ext: [
     *     {extname:"ocspNonce",hex:"12ab..."}]}
     */
    this.getResponseData = function(h) {
	var a = _getChildIdx(h, 0);
	var alen = a.length;
	var result = {};
	var idx = 0;

	// skip to relax interoperability even though explicit DEFAULT
	if (h.substr(a[0], 2) == "a0") idx++;

	result.respid = this.getResponderID(_getTLV(h, a[idx++]));
	
	var hProdAtV = _getV(h, a[idx++]);
	result.prodat = hextoutf8(hProdAtV);
	
	result.array = this.getSingleResponseList(_getTLV(h, a[idx++]));

	if (h.substr(a[alen - 1], 2) == "a1") {
	    var hExt =  _getTLVbyList(h, a[alen - 1], [0]);
	    var x = new X509();
	    result.ext = x.getExtParamArray(hExt);
	}

	return result;
    };

    /**
     * parse ASN.1 ResponderID of OCSP<br/>
     * @name getResponderID
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of ResponderID
     * @return JSON object of ResponderID parameter
     * @since jsrsasign 10.4.0 asn1ocsp 1.1.5
     * @see KJUR.asn1.ocsp.ResponderID
     *
     * @description
     * <pre>
     * ResponderID ::= CHOICE {
     *    byName               [1] Name,
     *    byKey                [2] KeyHash }
     * KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
     *                             (excluding the tag and length fields)
     * </pre>
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getResponderID("a1..") &rarr; {name: {array: [[{type:"C",value:"JP",ds:"prn"}]...]}}
     * o.getResponderID("a2..") &rarr; {key: "12ab..."}
     */
    this.getResponderID = function(h) {
	var result = {};

	if (h.substr(0, 2) == "a2") {
	    var hKeyV = _getVbyList(h, 0, [0]);
	    result.key = hKeyV;
	}
	if (h.substr(0, 2) == "a1") {
	    var hName = _getTLVbyList(h, 0, [0]);
	    var x = new X509();
	    result.name = x.getX500Name(hName);
	}
	
	return result;
    };

    /**
     * parse ASN.1 SEQUENCE OF SingleResponse of OCSP<br/>
     * @name getSingleResponseList
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of SEQUENCE OF SingleResponse
     * @return array of SingleResponse parameter JSON object
     * @since jsrsasign 10.4.0 asn1ocsp 1.1.5
     *
     * @description
     * This method will parse a hexadecimal string of
     * ASN.1 class of SEQUENCE OF SingleResponse is defined in 
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
     * <pre>
     * ResponseData ::= SEQUENCE {
     *    version              [0] EXPLICIT Version DEFAULT v1,
     *    responderID              ResponderID,
     *    producedAt               GeneralizedTime,
     *    responses                SEQUENCE OF SingleResponse,
     *    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
     * SingleResponse ::= SEQUENCE {
     *    certID                       CertID,
     *    certStatus                   CertStatus,
     *    thisUpdate                   GeneralizedTime,
     *    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
     *    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParse#getResponseData
     * @see KJUR.asn1.ocsp.OCSPParse#getSingleResponse
     * @see KJUR.asn1.ocsp.OCSPParse#getCertID
     * @see KJUR.asn1.ocsp.SingleResponseList
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getSingleResponseList("30..") &rarr;
     * [{ certid: {alg:"sha1",issname:"12ab",isskey:"12ab",sbjsn:"12ab"},
     *    status: {status: "good"},
     *    thisupdate: "20200903235959Z",
     *    nextupdate: "20200913235959Z",
     *    ext: [<<Extension parameters>>...] }]
     */
    this.getSingleResponseList = function(h) {
	var a = _getChildIdx(h, 0);
	var result = [];

	for (var i = 0; i < a.length; i++) {
	    var p = this.getSingleResponse(_getTLV(h, a[i]));
	    result.push(p);
	}
	return result;
    };

    /**
     * parse ASN.1 SingleResponse of OCSP<br/>
     * @name getSingleResponse
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of SingleResponse
     * @return JSON object of SingleResponse parameter
     * @since jsrsasign 10.4.0 asn1ocsp 1.1.5
     *
     * @description
     * This method will parse a hexadecimal string of
     * ASN.1 class of SingleResponse is defined in 
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.1">RFC 6960 4.2.1</a>. 
     * <pre>
     * SingleResponse ::= SEQUENCE {
     *    certID                       CertID,
     *    certStatus                   CertStatus,
     *    thisUpdate                   GeneralizedTime,
     *    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
     *    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
     * </pre>
     *
     * @see KJUR.asn1.ocsp.OCSPParse#getSingleResponseList
     * @see KJUR.asn1.ocsp.OCSPParse#getCertID
     * @see KJUR.asn1.ocsp.SingleResponse
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getSingleResponse("30..") &rarr;
     * { certid: {alg:"sha1",issname:"12ab",isskey:"12ab",sbjsn:"12ab"},
     *   status: {status: "good"},
     *   thisupdate: "20200903235959Z",
     *   nextupdate: "20200913235959Z",
     *   ext: [<<Extension parameters>>...] }
     */
    this.getSingleResponse = function(h) {
	var a = _getChildIdx(h, 0);
	var result = {};

	// 1. CertID
	var pCertID = this.getCertID(_getTLV(h, a[0]));
	result.certid = pCertID;

	// 2. CertStatus
	var pCertStatus = this.getCertStatus(_getTLV(h, a[1]));
	result.status = pCertStatus;

	// 3. ThisUpdate(GeneralizedTime)
	if (h.substr(a[2], 2) == "18") {
	    var hThisUpdateV = _getV(h, a[2]);
	    result.thisupdate = hextoutf8(hThisUpdateV);
	}
	
	// 4. OPTIONAL(nextUpdate, singleExtensions)
	for (var i = 3; i < a.length; i++) {
	    if (h.substr(a[i], 2) == "a0") { // nextUpdate
		var hNextUpdateV = _getVbyList(h, a[i], [0], "18");
		result.nextupdate = hextoutf8(hNextUpdateV);
	    }
	    if (h.substr(a[i], 2) == "a1") { // singleExtensions
		var x = new X509();
		var hExt = _getTLVbyList(h, 0, [i, 0]);
		result.ext = x.getExtParamArray(hExt);
	    }
	}

	return result;
    };

    /**
     * parse ASN.1 CertStatus of OCSP<br/>
     * @name getCertStatus
     * @memberOf KJUR.asn1.ocsp.OCSPParser#
     * @function
     * @param {String} h hexadecimal string of CertStatus
     * @return JSON object of CertStatus parameter
     * @since jsrsasign 10.4.0 asn1ocsp 1.1.5
     * @see KJUR.asn1.ocsp.CertStatus
     *
     * @description
     * <pre>
     * CertStatus ::= CHOICE {
     *     good        [0]     IMPLICIT NULL,
     *     revoked     [1]     IMPLICIT RevokedInfo,
     *     unknown     [2]     IMPLICIT UnknownInfo }
     * RevokedInfo ::= SEQUENCE {
     *     revocationTime              GeneralizedTime,
     *     revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
     * UnknownInfo ::= NULL
     * </pre>
     * NOTE: Currently revocationReason not supported.
     *
     * @example
     * o = new KJUR.asn1.ocsp.OCSPParser();
     * o.getCertStatus("8000") &rarr; {status: "good"}
     * o.getCertStatus("8200") &rarr; {status: "unknown"}
     * o.getCertStatus("a1..") &rarr; {status: "revoked", time: "2021...Z"}
     */
    this.getCertStatus = function(h) {
	var result = {};
	if (h == "8000") return {status: "good"};
	if (h == "8200") return {status: "unknown"};
	if (h.substr(0, 2) == "a1") {
	    result.status = "revoked";
	    var hTime = _getVbyList(h, 0, [0]);
	    var sTime = hextoutf8(hTime);
	    result.time = sTime;
	}
	return result;
    };
};

