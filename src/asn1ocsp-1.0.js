/* asn1ocsp-1.0.3.js (c) 2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1ocsp.js - ASN.1 DER encoder classes for OCSP protocol
 *
 * Copyright (c) 2016-2017 Kenji Urushima (kenji.urushima@gmail.com)
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
 * @version jsrsasign 7.2.1 asn1ocsp 1.0.3 (2017-Jun-03)
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
 * <li>easily generate OCSP data</li>
 * </ul>
 * 
 * <h4>PROVIDED CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.ocsp.CertID} for ASN.1 class as defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. </li>
 * <li>{@link KJUR.asn1.ocsp.Request} for ASN.1 class as defined in
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. </li>
 * <li>{@link KJUR.asn1.ocsp.TBSRequest} for ASN.1 class as defined in
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. </li>
 * <li>{@link KJUR.asn1.ocsp.OCSPRequest} for ASN.1 class as defined in
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. </li>
 * <li>{@link KJUR.asn1.ocsp.OCSPUtil} for static utility methods.</li>
 * </ul>
 * </p>
 * @name KJUR.asn1.ocsp
 * @namespace
 */
if (typeof KJUR.asn1.ocsp == "undefined" || !KJUR.asn1.ocsp) KJUR.asn1.ocsp = {};

KJUR.asn1.ocsp.DEFAULT_HASH = "sha1";

/**
 * ASN.1 CertID class for OCSP<br/>
 * @name KJUR.asn1.ocsp.CertID
 * @class ASN.1 CertID class for OCSP
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.0
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
 * @example
 * // default constructor
 * o = new KJUR.asn1.ocsp.CertID();
 * // constructor with certs (sha1 is used by default)
 * o = new KJUR.asn1.ocsp.CertID({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN..."});
 * // constructor with certs and sha256
 * o = new KJUR.asn1.ocsp.CertID({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"});
 * // constructor with values
 * o = new KJUR.asn1.ocsp.CertID({namehash: "1a...", keyhash: "ad...", serial: "1234", alg: "sha256"});
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
	_ASN1HEX = ASN1HEX;

    _KJUR_asn1_ocsp.CertID.superclass.constructor.call(this);

    this.dHashAlg = null;
    this.dIssuerNameHash = null;
    this.dIssuerKeyHash = null;
    this.dSerialNumber = null;

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
	if (algName === undefined) algName = _DEFAULT_HASH;
	this.dHashAlg =        new _AlgorithmIdentifier({name: algName});
	this.dIssuerNameHash = new _DEROctetString({hex: issuerNameHashHex});
	this.dIssuerKeyHash =  new _DEROctetString({hex: issuerKeyHashHex});
	this.dSerialNumber =   new _DERInteger({hex: serialNumberHex});
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
     * @example
     * o = new KJUR.asn1.ocsp.CertID();
     * o.setByCert("-----BEGIN...", "-----BEGIN..."); // sha1 is used by default
     * o.setByCert("-----BEGIN...", "-----BEGIN...", "sha256");
     */
    this.setByCert = function(issuerCert, subjectCert, algName) {
	if (algName === undefined) algName = _DEFAULT_HASH;

	var xSbj = new _X509();
	xSbj.readCertPEM(subjectCert);
	var xIss = new _X509();
	xIss.readCertPEM(issuerCert);

	var hISS_SPKI = xIss.getPublicKeyHex();
	var issuerKeyHex = _ASN1HEX.getTLVbyList(hISS_SPKI, 0, [1, 0], "30");

	var serialNumberHex = xSbj.getSerialNumberHex();
	var issuerNameHashHex = _hashHex(xIss.getSubjectHex(), algName);
	var issuerKeyHashHex = _hashHex(issuerKeyHex, algName);
	this.setByValue(issuerNameHashHex, issuerKeyHashHex,
			serialNumberHex, algName);
	this.hoge = xSbj.getSerialNumberHex();
    };

    this.getEncodedHex = function() {
	if (this.dHashAlg === null && 
	    this.dIssuerNameHash === null &&
	    this.dIssuerKeyHash === null &&
	    this.dSerialNumber === null)
	    throw "not yet set values";

	var a = [this.dHashAlg, this.dIssuerNameHash,
		 this.dIssuerKeyHash, this.dSerialNumber];
	var seq = new _DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
	var p = params;
	if (p.issuerCert !== undefined &&
	    p.subjectCert !== undefined) {
	    var alg = _DEFAULT_HASH;
	    if (p.alg === undefined) alg = undefined;
	    this.setByCert(p.issuerCert, p.subjectCert, alg);
	} else if (p.namehash !== undefined &&
		   p.keyhash !== undefined &&
		   p.serial !== undefined) {
	    var alg = _DEFAULT_HASH;
	    if (p.alg === undefined) alg = undefined;
	    this.setByValue(p.namehash, p.keyhash, p.serial, alg);
	} else {
	    throw "invalid constructor arguments";
	}
    }
};
YAHOO.lang.extend(KJUR.asn1.ocsp.CertID, KJUR.asn1.ASN1Object);

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
    
    this.getEncodedHex = function() {
	var a = [];

	// 1. reqCert
	if (this.dReqCert === null)
	    throw "reqCert not set";
	a.push(this.dReqCert);

	// 2. singleRequestExtensions (not supported yet)

	// 3. construct SEQUENCE
	var seq = new _DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params !== "undefined") {
	var o = new _KJUR_asn1_ocsp.CertID(params);
	this.dReqCert = o;
    }
};
YAHOO.lang.extend(KJUR.asn1.ocsp.Request, KJUR.asn1.ASN1Object);

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

    this.getEncodedHex = function() {
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
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
	if (params.reqList !== undefined)
	    this.setRequestListByParam(params.reqList);
    }
};
YAHOO.lang.extend(KJUR.asn1.ocsp.TBSRequest, KJUR.asn1.ASN1Object);


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

    this.getEncodedHex = function() {
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
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
	if (params.reqList !== undefined) {
	    var o = new _KJUR_asn1_ocsp.TBSRequest(params);
	    this.dTbsRequest = o;
	}
    }
};
YAHOO.lang.extend(KJUR.asn1.ocsp.OCSPRequest, KJUR.asn1.ASN1Object);

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
    return o.getEncodedHex();
};

/**
 * parse OCSPResponse<br/>
 * @name getOCSPResponseInfo
 * @memberOf KJUR.asn1.ocsp.OCSPUtil
 * @function
 * @param {String} h hexadecimal string of DER OCSPResponse
 * @return {Object} JSON object of parsed OCSPResponse
 * @since jsrsasign 6.1.0 asn1ocsp 1.0.1
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
 * @example
 * info = KJUR.asn1.ocsp.OCSPUtil.getOCSPResponseInfo("3082...");
 */
KJUR.asn1.ocsp.OCSPUtil.getOCSPResponseInfo = function(h) {
    var _ASN1HEX = ASN1HEX;
    var _getVbyList = _ASN1HEX.getVbyList;
    var _getIdxbyList = _ASN1HEX.getIdxbyList;
    var _getVbyList = _ASN1HEX.getVbyList;
    var _getV = _ASN1HEX.getV;

    var result = {};
    try {
	var v = _getVbyList(h, 0, [0], "0a");
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

