/* asn1csr-2.0.5.js (c) 2015-2022 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * asn1csr.js - ASN.1 DER encoder classes for PKCS#10 CSR
 *
 * Copyright (c) 2015-2020 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1csr-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.16 asn1csr 2.0.5 (2022-Apr-08)
 * @since jsrsasign 4.9.0
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * kjur's ASN.1 class for CSR/PKCS#10 name space
 * <p>
 * This name space is a sub name space for {@link KJUR.asn1}.
 * This name space contains classes for
 * <a href="https://tools.ietf.org/html/rfc2986">RFC 2986</a>
 * certificate signing request(CSR/PKCS#10) and its utilities
 * to be issued your certificate from certification authorities.
 * <h4>PROVIDING ASN.1 STRUCTURES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.csr.CertificationRequest}</li>
 * <li>{@link KJUR.asn1.csr.CertificationRequestInfo}</li>
 * </ul>
 * <h4>PROVIDING UTILITY CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.csr.CSRUtil}</li>
 * </ul>
 * </p>
 * @name KJUR.asn1.csr
 * @namespace
 */
if (typeof KJUR.asn1.csr == "undefined" || !KJUR.asn1.csr) KJUR.asn1.csr = {};

/**
 * ASN.1 CertificationRequest structure class
 * @name KJUR.asn1.csr.CertificationRequest
 * @class ASN.1 CertificationRequest structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.9.0 asn1csr 1.0.0
 * @see KJUR.asn1.csr.CertificationRequestInfo
 * @description
 * This class provides CertificateRequestInfo ASN.1 structure
 * defined in 
 * <a href="https://tools.ietf.org/html/rfc2986#page-5">
 * RFC 2986 4.2</a>.
 * <pre>
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo CertificationRequestInfo,
 *   signatureAlgorithm       AlgorithmIdentifier{{ SignatureAlgorithms }},
 *   signature                BIT STRING }
 * CertificationRequestInfo ::= SEQUENCE {
 *   version       INTEGER { v1(0) } (v1,...),
 *   subject       Name,
 *   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *   attributes    [0] Attributes{{ CRIAttributes }} }
 * </pre>
 *
 * Argument "params" JSON object can have following keys:
 * <ul>
 * <li>{Array}subject - parameter to be passed to {@link KJUR.asn1.x509.X500Name}</li>
 * <li>{Object}sbjpubkey - PEM string or key object to be passed to {@link KEYUTIL.getKey}</li>
 * <li>{Array}extreq - array of certificate extension parameters</li>
 * <li>{String}sigalg - signature algorithm name (ex. SHA256withRSA)</li>
 * <li>{Object}sbjprvkey - PEM string or key object to be passed to {@link KEYUTIL.getKey} 
 * (OPTION)</li>
 * <li>{String}sighex - hexadecimal string of signature value. 
 * When this is not defined and
 * sbjprvkey is specified, sighex will be set automatically
 * during getEncodedHex() is called. (OPTION)</li>
 * </ul>
 *
 * <br/>
 * CAUTION: 
 * Argument "params" JSON value format have been changed without 
 * backward compatibility since jsrsasign 9.0.0 asn1csr 2.0.0.
 *
 * @example
 * // sign by private key
 * csr = new KJUR.asn1.csr.CertificationRequest({
 *   subject: {str:"/C=US/O=Test"},
 *   sbjpubkey: "-----BEGIN PUBLIC KEY...",
 *   extreq: [{extname:"subjectAltName",array:[{dns:"example.com"}]}]
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: "-----BEGIN PRIVATE KEY..."
 * });
 * pem = csr.getPEM(); // signed with sbjprvkey automatically
 *
 * // or specifying signature value
 * csr = new KJUR.asn1.csr.CertificationRequest({
 *   subject: {str:"/C=US/O=Test"},
 *   sbjpubkey: "-----BEGIN PUBLIC KEY...",
 *   extreq: [{extname:"subjectAltName",array:[{dns:"example.com"}]}]
 *   sigalg: "SHA256withRSA",
 *   sighex: "1234abcd..."
 * });
 * pem = csr.getPEM();
 */
KJUR.asn1.csr.CertificationRequest = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERBitString = _KJUR_asn1.DERBitString,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_csr = _KJUR_asn1.csr,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_CertificationRequestInfo = _KJUR_asn1_csr.CertificationRequestInfo;

    _KJUR_asn1_csr.CertificationRequest.superclass.constructor.call(this);

    /**
     * set parameter<br/>
     * @name setByParam
     * @memberOf KJUR.asn1.csr.CertificationRequest#
     * @function
     * @param params {Array} JSON object of CSR parameters
     * @since jsrsasign 9.0.0 asn1csr 2.0.0
     * @description
     * This method will set parameter to this object.
     * @example
     * csr = new KJUR.asn1.x509.CertificationRequest();
     * csr.setByParam({
     *   subject: {str: "/C=JP/O=Test"},
     *   ...
     * });
     */
    this.setByParam = function(params) {
	this.params = params;
    };

    /**
     * sign CertificationRequest and set signature value internally<br/>
     * @name sign
     * @memberOf KJUR.asn1.csr.CertificationRequest#
     * @function
     * @description
     * This method self-signs CertificateRequestInfo with a subject's
     * private key and set signature value internally.
     * <br/>
     * @example
     * csr = new KJUR.asn1.csr.CertificationRequest({
     *   subject: "/C=JP/O=Test",
     *   sbjpubkey: ...
     * });
     * csr.sign();
     */
    this.sign = function() {
	var hCSRI = 
	    (new _CertificationRequestInfo(this.params)).tohex();
	var sig = new KJUR.crypto.Signature({alg: this.params.sigalg});
	sig.init(this.params.sbjprvkey);
	sig.updateHex(hCSRI);
	var sighex = sig.sign();
	this.params.sighex = sighex;
    };

    /**
     * get PEM formatted certificate signing request (CSR/PKCS#10)<br/>
     * @name getPEM
     * @memberOf KJUR.asn1.csr.CertificationRequest#
     * @function
     * @return PEM formatted string of CSR/PKCS#10
     * @description
     * This method is to a get CSR PEM string
     * <br/>
     * @example
     * csr = new KJUR.asn1.csr.CertificationRequest({
     *   subject: "/C=JP/O=Test",
     *   sbjpubkey: ...
     * });
     * csr.getPEM() &rarr; "-----BEGIN CERTIFICATE REQUEST..."
     */
    this.getPEM = function() {
	return hextopem(this.tohex(), "CERTIFICATE REQUEST");
    };

    this.tohex = function() {
	var params = this.params;
	var csri = new KJUR.asn1.csr.CertificationRequestInfo(this.params);
	var algid = 
	    new KJUR.asn1.x509.AlgorithmIdentifier({name: params.sigalg});

	if (params.sighex == undefined && params.sbjprvkey != undefined) {
	    this.sign();
	}

	if (params.sighex == undefined) {
	    throw new Error("sighex or sbjprvkey parameter not defined");
	}

	var asn1Sig = new _DERBitString({hex: "00" + params.sighex});
	
	var seq = new _DERSequence({array: [csri, algid, asn1Sig]});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.csr.CertificationRequest, KJUR.asn1.ASN1Object);

/**
 * ASN.1 CertificationRequestInfo structure class
 * @name KJUR.asn1.csr.CertificationRequestInfo
 * @class ASN.1 CertificationRequestInfo structure class
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.9.0 asn1csr 1.0.0
 * @see KJUR.asn1.csr.CertificationRequest
 * @description
 * This class provides CertificateRequestInfo ASN.1 structure
 * defined in 
 * <a href="https://tools.ietf.org/html/rfc2986#page-5">
 * RFC 2986 4.1</a>.
 * <pre>
 * CertificationRequestInfo ::= SEQUENCE {
 *   version       INTEGER { v1(0) } (v1,...),
 *   subject       Name,
 *   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *   attributes    [0] Attributes{{ CRIAttributes }} }
 * </pre>
 * <br/>
 * <br/>
 * CAUTION: 
 * Argument "params" JSON value format have been changed without 
 * backward compatibility since jsrsasign 9.0.0 asn1csr 2.0.0.
 *
 * @example
 * csri = new KJUR.asn1.csr.CertificationRequestInfo({
 *   subject: {str: '/C=US/CN=b'},
 *   sbjpubkey: <<PUBLIC KEY PEM>>,
 *   extreq: [
 *     {extname:"subjectAltName", array:[{dns:"example.com"}]}
 *   ]});
 * csri.tohex() &rarr; "30..."
 */
KJUR.asn1.csr.CertificationRequestInfo = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERBitString = _KJUR_asn1.DERBitString,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERUTF8String = _KJUR_asn1.DERUTF8String,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_newObject = _KJUR_asn1.ASN1Util.newObject,
	_KJUR_asn1_csr = _KJUR_asn1.csr,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_X500Name = _KJUR_asn1_x509.X500Name,
	_Extensions = _KJUR_asn1_x509.Extensions,
	_SubjectPublicKeyInfo = _KJUR_asn1_x509.SubjectPublicKeyInfo;
    
    _KJUR_asn1_csr.CertificationRequestInfo.superclass.constructor.call(this);

    this.params = null;

    this.setByParam = function(params) {
	if (params != undefined) this.params = params;
    };

    this.tohex = function() {
	var params = this.params;
	var a = [];
	a.push(new _DERInteger({'int': 0})); // version
	a.push(new _X500Name(params.subject));
	a.push(new _SubjectPublicKeyInfo(KEYUTIL.getKey(params.sbjpubkey)));
	if (params.extreq != undefined) {
	    var extseq = new _Extensions(params.extreq);
	    var tagobj = _newObject({
		tag: {
		    tag:'a0',
		    explict:true,
		    obj:{seq: [{oid: "1.2.840.113549.1.9.14"},
			       {set: [extseq]}]}
		}
	    });
	    a.push(tagobj);
	} else {
	    a.push(new _DERTaggedObject({tag:"a0",
					 explicit:false,
					 obj:new _DERUTF8String({str:''})}));
	}
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};

extendClass(KJUR.asn1.csr.CertificationRequestInfo, KJUR.asn1.ASN1Object);

/**
 * Certification Request (CSR/PKCS#10) utilities class<br/>
 * @name KJUR.asn1.csr.CSRUtil
 * @class Certification Request (CSR/PKCS#10) utilities class
 * @description
 * This class provides utility static methods for CSR/PKCS#10.
 * Here is a list of methods:
 * <ul>
 * <li>{@link KJUR.asn1.csr.CSRUtil.newCSRPEM} (DEPRECATED)</li>
 * <li>{@link KJUR.asn1.csr.CSRUtil.getParam}</li>
 * </ul>
 * <br/>
 */
KJUR.asn1.csr.CSRUtil = new function() {
};

/**
 * generate a PEM format of CSR/PKCS#10 certificate signing request (DEPRECATED)<br/>
 * @name newCSRPEM
 * @memberOf KJUR.asn1.csr.CSRUtil
 * @function
 * @param {Array} param parameter to generate CSR
 * @since jsrsasign 4.9.0 asn1csr 1.0.0
 * @deprecated since jsrsasign 9.0.0 asn1csr 2.0.0. please use {@link KJUR.asn1.csr.CertificationRequest} constructor.
 * @description
 * This method can generate a CSR certificate signing.
 * 
 * @example
 * // 1) by key object
 * pem = KJUR.asn1.csr.CSRUtil.newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   sbjpubkey: pubKeyObj,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: prvKeyObj,
 *   extreq: [{
 *     extname: "subjectAltName",
 *     array: [{dns:"example.com"}]
 *   }]
 * });
 *
 * // 2) by private/public key PEM 
 * pem = KJUR.asn1.csr.CSRUtil.newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   sbjpubkey: pubKeyPEM,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: prvKeyPEM
 * });
 *
 * // 3) with generateKeypair
 * kp = KEYUTIL.generateKeypair("RSA", 2048);
 * pem = KJUR.asn1.csr.CSRUtil.newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   sbjpubkey: kp.pubKeyObj,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: kp.prvKeyObj
 * });
 *
 * // 4) by private/public key PEM with extension
 * pem = KJUR.asn1.csr.CSRUtil.newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   ext: [
 *     {subjectAltName: {array: [{dns: 'example.net'}]}}
 *   ],
 *   sbjpubkey: pubKeyPEM,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: prvKeyPEM
 * });
 */
KJUR.asn1.csr.CSRUtil.newCSRPEM = function(param) {
    var _KEYUTIL = KEYUTIL,
	_KJUR_asn1_csr = KJUR.asn1.csr;

    var csr = new _KJUR_asn1_csr.CertificationRequest(param);
    var pem = csr.getPEM();
    return pem;
};

/**
 * get field values from CSR/PKCS#10 PEM string<br/>
 * @name getParam
 * @memberOf KJUR.asn1.csr.CSRUtil
 * @function
 * @param {String} sPEM PEM string of CSR/PKCS#10
 * @returns {Array} JSON object with parsed parameters such as name or public key
 * @since jsrsasign 9.0.0 asn1csr 2.0.0
 * @see KJUR.asn1.csr.CertificationRequest
 * @see KJUR.asn1.x509.X500Name
 * @see X509#getExtParamArray
 * @description
 * This method parses PEM CSR/PKCS#1 string and retrieves
 * fields such as subject name and public key. 
 * Following parameters are available in the
 * resulted JSON object.
 * <ul>
 * <li>{X500Name}subject - subject name parameters </li>
 * <li>{String}sbjpubkey - PEM string of subject public key</li>
 * <li>{Array}extreq - array of extensionRequest parameters</li>
 * <li>{String}sigalg - name of signature algorithm field</li>
 * <li>{String}sighex - hexadecimal string of signature value</li>
 * </ul>
 * Returned JSON object can be passed to 
 * {@link KJUR.asn1.csr.CertificationRequest} class constructor.
 * <br/>
 * CAUTION: 
 * Returned JSON value format have been changed without 
 * backward compatibility since jsrsasign 9.0.0 asn1csr 2.0.0.
 *
 * @example
 * KJUR.asn1.csr.CSRUtil.getParam("-----BEGIN CERTIFICATE REQUEST...") &rarr;
 * {
 *   subject: { array:[[{type:"C",value:"JP",ds:"prn"}],...],
 *              str: "/C=JP/O=Test"},
 *   sbjpubkey: "-----BEGIN PUBLIC KEY...",
 *   extreq: [{extname:"subjectAltName",array:[{dns:"example.com"}]}]
 *   sigalg: "SHA256withRSA",
 *   sighex: "1ab3df.."
 * }
 */
KJUR.asn1.csr.CSRUtil.getParam = function(sPEM) {
    var _ASN1HEX = ASN1HEX,
	_getV = _ASN1HEX.getV,
	_getIdxbyList = _ASN1HEX.getIdxbyList,
	_getTLVbyList = _ASN1HEX.getTLVbyList,
	_getTLVbyListEx = _ASN1HEX.getTLVbyListEx,
	_getVbyListEx = _ASN1HEX.getVbyListEx;

    /*
     * get a hexadecimal string of sequence of extension request attribute value
     * @param {String} h hexadecimal string of whole CSR
     * @return {String} hexadecimal string of SEQUENCE of extension request attribute value
     */
    var _getExtReqSeqHex = function(h) {
	var idx1 = _getIdxbyList(h, 0, [0, 3, 0, 0], "06"); // extreq attr OID idx
	if (_getV(h, idx1) != "2a864886f70d01090e") {
	    return null;
	}

	return _getTLVbyList(h, 0, [0, 3, 0, 1, 0], "30"); // ext seq idx
    };

    var result = {};

    if (sPEM.indexOf("-----BEGIN CERTIFICATE REQUEST") == -1)
	throw new Error("argument is not PEM file");

    var hex = pemtohex(sPEM, "CERTIFICATE REQUEST");

    try {
	var hSubject = _getTLVbyListEx(hex, 0, [0, 1]);
	if (hSubject == "3000") {
	    result.subject = {};
	} else {
	    var x = new X509();
	    result.subject = x.getX500Name(hSubject);
	}
    } catch (ex) {};

    var hPubKey = _getTLVbyListEx(hex, 0, [0, 2]);
    var pubkeyobj = KEYUTIL.getKey(hPubKey, null, "pkcs8pub");
    result.sbjpubkey = KEYUTIL.getPEM(pubkeyobj, "PKCS8PUB");

    var hExtReqSeq = _getExtReqSeqHex(hex);
    var x = new X509();
    if (hExtReqSeq != null) {
	result.extreq = x.getExtParamArray(hExtReqSeq);
    }

    try {
	var hSigAlg = _getTLVbyListEx(hex, 0, [1], "30");
	var x = new X509();
	result.sigalg = x.getAlgorithmIdentifierName(hSigAlg);
    } catch (ex) {};

    try {
	var hSig = _getVbyListEx(hex, 0, [2]);
	result.sighex = hSig;
    } catch (ex) {};

    return result;
};


