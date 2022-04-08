/* asn1cms-2.0.5.js (c) 2013-2020 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * asn1cms.js - ASN.1 DER encoder and verifier classes for Cryptographic Message Syntax(CMS)
 *
 * Copyright (c) 2013-2020 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1cms-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.16 asn1cms 2.0.5 (2022-Apr-08)
 * @since jsrsasign 4.2.4
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * // already documented in asn1-1.0.js
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/**
 * kjur's ASN.1 class library name space
 * // already documented in asn1-1.0.js
 * @name KJUR.asn1
 * @namespace
 */
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

/**
 * kjur's ASN.1 class for Cryptographic Message Syntax(CMS)
 * <p>
 * This name space provides 
 * <a href="https://tools.ietf.org/html/rfc5652">RFC 5652
 * Cryptographic Message Syntax (CMS)</a> SignedData generator.
 *
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily generate CMS SignedData</li>
 * <li>easily verify CMS SignedData</li>
 * <li>APIs are very similar to BouncyCastle library ASN.1 classes. So easy to learn.</li>
 * </ul>
 * 
 * <h4>PROVIDED CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.cms.SignedData}</li>
 * <li>{@link KJUR.asn1.cms.SignerInfo}</li>
 * <li>{@link KJUR.asn1.cms.AttributeList}</li>
 * <li>{@link KJUR.asn1.cms.ContentInfo}</li>
 * <li>{@link KJUR.asn1.cms.EncapsulatedContentInfo}</li>
 * <li>{@link KJUR.asn1.cms.IssuerAndSerialNumber}</li>
 * <li>{@link KJUR.asn1.cms.IssuerSerial}</li>
 * <li>{@link KJUR.asn1.cms.CMSUtil}</li>
 * <li>{@link KJUR.asn1.cms.Attribute}</li>
 * <li>{@link KJUR.asn1.cms.ContentType}</li>
 * <li>{@link KJUR.asn1.cms.MessageDigest}</li>
 * <li>{@link KJUR.asn1.cms.SigningTime}</li>
 * <li>{@link KJUR.asn1.cms.SigningCertificate}</li>
 * <li>{@link KJUR.asn1.cms.SigningCertificateV2}</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. 
 * This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.asn1.cms
 * @namespace
 */
if (typeof KJUR.asn1.cms == "undefined" || !KJUR.asn1.cms) KJUR.asn1.cms = {};

/**
 * Attribute class for base of CMS attribute<br/>
 * @name KJUR.asn1.cms.Attribute
 * @class Attribute class for base of CMS attribute
 * @param {Array} params JSON object for constructor
 * @property {Array} params JSON object for ASN.1 encode
 * @property {String} typeOid attribute type OID string
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 *
 * @description
 * This is an abstract class for CMS attribute
 * ASN.1 encoder as defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-5.3">
 * RFC 5652 CMS 5.3 SignerInfo.
 * <pre>
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * </pre>
 */
KJUR.asn1.cms.Attribute = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERSet = _KJUR_asn1.DERSet,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier;

    this.params = null;
    this.typeOid = null;

    this.setByParam = function(params) {
	this.params = params;
    };

    /**
     * get ASN1Object array for Attributes<br/>
     * @name getValueArray
     * @memberOf KJUR.asn1.cms.Attribute#
     * @function
     * @return {Array} array of Attribute value ASN1Object
     *
     * @description
     * This method shall be implemented in subclass.
     */
    this.getValueArray = function() {
	throw new _Error("not yet implemented abstract");
    };

    this.tohex = function() {
	var dType = new _DERObjectIdentifier({oid: this.typeOid});
	var dValueSet = new _DERSet({array: this.getValueArray()});
	var seq = new _DERSequence({array: [dType, dValueSet]});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };
};
extendClass(KJUR.asn1.cms.Attribute, KJUR.asn1.ASN1Object);

/**
 * class for CMS ContentType attribute
 * @name KJUR.asn1.cms.ContentType
 * @class class for CMS ContentType attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 *
 * @description
 * This is an ASN.1 encoder for ContentType attribute
 * defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-11.1">
 * RFC 5652 CMS section 11.1</a>.
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * Constructor may have following property in argument:
 * <ul>
 * <li>{String}type - name or OID string</li>
 * </ul>
 *
 * @example
 * o = new KJUR.asn1.cms.ContentType({type: 'data'});
 * o = new KJUR.asn1.cms.ContentType({type: '1.2.840.113549.1.9.16.1.4'});
 */
KJUR.asn1.cms.ContentType = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1;

    _KJUR_asn1.cms.ContentType.superclass.constructor.call(this);

    this.typeOid = "1.2.840.113549.1.9.3";

    this.getValueArray = function() {
        var dOid = new _KJUR_asn1.DERObjectIdentifier(this.params.type);
        return [dOid];
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.ContentType, KJUR.asn1.cms.Attribute);

/**
 * class for CMS MessageDigest attribute
 * @name KJUR.asn1.cms.MessageDigest
 * @class class for CMS MessageDigest attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 *
 * @description
 * This is an ASN.1 encoder for ContentType attribute
 * defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-11.2">
 * RFC 5652 CMS section 11.2</a>.
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * MessageDigest ::= OCTET STRING
 * </pre>
 *
 * @example
 * o = new KJUR.asn1.cms.MessageDigest({hex: 'a1a2a3a4...'});
 */
KJUR.asn1.cms.MessageDigest = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_KJUR_asn1_cms = _KJUR_asn1.cms;

    _KJUR_asn1_cms.MessageDigest.superclass.constructor.call(this);

    this.typeOid = "1.2.840.113549.1.9.4";

    this.getValueArray = function() {
	var dHash = new _DEROctetString(this.params);
	return [dHash];
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.MessageDigest, KJUR.asn1.cms.Attribute);

/**
 * class for CMS SigningTime attribute
 * @name KJUR.asn1.cms.SigningTime
 * @class class for CMS SigningTime attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 *
 * @description
 * This is an ASN.1 encoder for ContentType attribute
 * defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-11.3">
 * RFC 5652 CMS section 11.3</a>.
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * SigningTime  ::= Time
 * Time ::= CHOICE {
 *    utcTime UTCTime,
 *    generalTime GeneralizedTime }
 * </pre>
 *
 * @example
 * o = new KJUR.asn1.cms.SigningTime(); // current time UTCTime by default
 * o = new KJUR.asn1.cms.SigningTime({type: 'gen'}); // current time GeneralizedTime
 * o = new KJUR.asn1.cms.SigningTime({str: '20140517093800Z'}); // specified GeneralizedTime
 * o = new KJUR.asn1.cms.SigningTime({str: '140517093800Z'}); // specified UTCTime
 */
KJUR.asn1.cms.SigningTime = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1;

    _KJUR_asn1.cms.SigningTime.superclass.constructor.call(this);

    this.typeOid = "1.2.840.113549.1.9.5";

    this.getValueArray = function() {
	var dTime = new _KJUR_asn1.x509.Time(this.params);
	return [dTime];
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.SigningTime, KJUR.asn1.cms.Attribute);

/**
 * class for CMS SigningCertificate attribute<br/>
 * @name KJUR.asn1.cms.SigningCertificate
 * @class class for CMS SigningCertificate attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.5.1 asn1cms 1.0.1
 * @see KJUR.asn1.cms.ESSCertID
 * @see KJUR.asn1.cms.IssuerSerial
 *
 * @description
 * This is an ASN.1 encoder for SigningCertificate attribute
 * defined in
 * <a href="https://tools.ietf.org/html/rfc5035#section-5">
 * RFC 5035 section 5</a>.
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * SigningCertificate ::= SEQUENCE {
 *    certs SEQUENCE OF ESSCertID,
 *    policies SEQUENCE OF PolicyInformation OPTIONAL }
 * ESSCertID ::= SEQUENCE {
 *    certHash Hash,
 *    issuerSerial IssuerSerial OPTIONAL }
 * IssuerSerial ::= SEQUENCE {
 *    issuer GeneralNames,
 *    serialNumber CertificateSerialNumber }
 * </pre>
 *
 * @example
 * o = new KJUR.asn1.cms.SigningCertificate({array: [certPEM]});
 */
KJUR.asn1.cms.SigningCertificate = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_ESSCertID = _KJUR_asn1_cms.ESSCertID,
	_KJUR_crypto = _KJUR.crypto;

    _KJUR_asn1_cms.SigningCertificate.superclass.constructor.call(this);
    this.typeOid = "1.2.840.113549.1.9.16.2.12";

    this.getValueArray = function() {
	if (this.params == null || 
	    this.params == undefined || 
	    this.params.array == undefined) {
	    throw new _Error("parameter 'array' not specified");
	}
	var aESSCertIDParam = this.params.array;
	var aESSCertID = [];
	for (var i = 0; i < aESSCertIDParam.length; i++) {
	    var idparam = aESSCertIDParam[i];

	    if (params.hasis == false &&
		(typeof idparam == "string" &&
		 (idparam.indexOf("-----BEGIN") != -1 ||
		  ASN1HEX.isASN1HEX(idparam)))) {
		idparam = {cert: idparam};
	    }

	    if (idparam.hasis != false && params.hasis == false) {
		idparam.hasis = false;
	    }

	    aESSCertID.push(new _ESSCertID(idparam));
	}
	var dCerts = new _DERSequence({array: aESSCertID});
	var dSigningCertificate = new _DERSequence({array: [dCerts]});
	return [dSigningCertificate];
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.SigningCertificate, KJUR.asn1.cms.Attribute);

/**
 * class for CMS ESSCertID ASN.1 encoder<br/>
 * @name KJUR.asn1.cms.ESSCertID
 * @class class for CMS ESSCertID ASN.1 encoder
 * @param {Object} params PEM certificate string or JSON of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cms 2.0.0
 * @see KJUR.asn1.cms.SigningCertificate
 * @see KJUR.asn1.cms.IssuerSerial
 * @see KJUR.asn1.cms.ESSCertIDv2
 * @see KJUR.asn1.cades.OtherCertID
 *
 * @description
 * This is an ASN.1 encoder for ESSCertID class
 * defined in
 * <a href="https://tools.ietf.org/html/rfc5035#section-6">
 * RFC 5035 section 6</a>.
 * <pre>
 * ESSCertID ::= SEQUENCE {
 *    certHash Hash,
 *    issuerSerial IssuerSerial OPTIONAL }
 * IssuerSerial ::= SEQUENCE {
 *    issuer GeneralNames,
 *    serialNumber CertificateSerialNumber }
 * </pre>
 *
 * @example
 * new KJUR.asn1.cms.ESSCertID("-----BEGIN...")
 * new KJUR.asn1.cms.ESSCertID({cert: "-----BEGIN..."})
 * new KJUR.asn1.cms.ESSCertID({cert: "-----BEGIN...", hasis: false})
 * new KJUR.asn1.cms.ESSCertID({
 *   hash: "3f2d...",
 *   issuer: {str: "/C=JP/O=T1"},
 *   serial: {hex: "12ab..."}
 * })
 */
KJUR.asn1.cms.ESSCertID = function(params) {
    KJUR.asn1.cms.ESSCertID.superclass.constructor.call(this);

    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_DERSequence = _KJUR_asn1.DERSequence,
	_IssuerSerial = _KJUR_asn1.cms.IssuerSerial;

    this.params = null;

    this.getCertHash = function(params, defaultAlg) {
	if (params.hash != undefined) return params.hash;

	// hash 
	if (typeof params == "string" &&
	    params.indexOf("-----BEGIN") == -1 &&
	    ! ASN1HEX.isASN1HEX(params)) {
	    return params;
	}

	var certPEMorHex;
	if (typeof params == "string") {
	    certPEMorHex = params;
	} else if (params.cert != undefined) {
	    certPEMorHex = params.cert;
	} else {
	    throw new _Error("hash nor cert unspecified");
	}

	var hCert;
	if (certPEMorHex.indexOf("-----BEGIN") != -1) {
	    hCert = pemtohex(certPEMorHex);
	} else {
	    hCert = certPEMorHex;
	}


	if (typeof params == "string") {
	    if (params.indexOf("-----BEGIN") != -1) {
		hCert = pemtohex(params);
	    } else if (ASN1HEX.isASN1HEX(params)) {
		hCert = params;
	    }
	}

	var alg;
	if (params.alg != undefined) {
	    alg = params.alg;
	} else if (defaultAlg != undefined) {
	    alg = defaultAlg;
	} else {
	    throw new _Error("hash alg unspecified");
	}
	
	return _KJUR.crypto.Util.hashHex(hCert, alg);
    };

    this.tohex = function() {
	var params = this.params;

	var hCertHash = this.getCertHash(params, 'sha1');

	var a = [];
	a.push(new _DEROctetString({hex: hCertHash}));
	if ((typeof params == "string" &&
	     params.indexOf("-----BEGIN") != -1) ||
	    (params.cert != undefined &&
	     params.hasis != false) ||
	    (params.issuer != undefined &&
	     params.serial != undefined))
	    a.push(new _IssuerSerial(params));
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.ESSCertID, KJUR.asn1.ASN1Object);

/**
 * class for CMS SigningCertificateV2 attribute<br/>
 * @name KJUR.asn1.cms.SigningCertificateV2
 * @class class for CMS SigningCertificateV2 attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.5.1 asn1cms 1.0.1
 *
 * @description
 * This is an ASN.1 encoder for SigningCertificateV2 attribute
 * defined in
 * <a href="https://tools.ietf.org/html/rfc5035#section-3">
 * RFC 5035 section 3</a>.
 * <pre>
 * oid-signingCertificateV2 = 1.2.840.113549.1.9.16.2.47
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * SigningCertificateV2 ::=  SEQUENCE {
 *    certs        SEQUENCE OF ESSCertIDv2,
 *    policies     SEQUENCE OF PolicyInformation OPTIONAL }
 * ESSCertIDv2 ::=  SEQUENCE {
 *    hashAlgorithm           AlgorithmIdentifier
 *                            DEFAULT {algorithm id-sha256},
 *    certHash                Hash,
 *    issuerSerial            IssuerSerial OPTIONAL }
 * Hash ::= OCTET STRING
 * IssuerSerial ::= SEQUENCE {
 *    issuer                  GeneralNames,
 *    serialNumber            CertificateSerialNumber }
 * </pre>
 *
 * @example
 * new KJUR.asn1.cms.SigningCertificateV2({array: [certPEM]}); // DEFAULT sha256
 * new KJUR.asn1.cms.SigningCertificateV2({array: [certPEM],
 *                                         hashAlg: 'sha512'});
 * new KJUR.asn1.cms.SigningCertificateV2({
 *   array: [
 *     {cert: certPEM1, hashAlg: 'sha512'},
 *     {cert: certPEM2, hashAlg: 'sha256'},
 *     {cert: certPEM3}, // DEFAULT sha256
 *     certPEM4 // DEFAULT sha256
 *   ]
 * })
 * new KJUR.asn1.cms.SigningCertificateV2({
 *   array: [
 *     {cert: certPEM1, hashAlg: 'sha512'},
 *     {cert: certPEM2, hashAlg: 'sha256'},
 *     {cert: certPEM3}, // DEFAULT sha256
 *     certPEM4 // DEFAULT sha256
 *   ]
 * })
 */
KJUR.asn1.cms.SigningCertificateV2 = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_ESSCertIDv2 = _KJUR_asn1_cms.ESSCertIDv2,
	_KJUR_crypto = _KJUR.crypto;

    _KJUR_asn1_cms.SigningCertificateV2.superclass.constructor.call(this);
    this.typeOid = "1.2.840.113549.1.9.16.2.47";

    this.getValueArray = function() {
	if (this.params == null || 
	    this.params == undefined || 
	    this.params.array == undefined) {
	    throw new _Error("parameter 'array' not specified");
	}
	var aESSCertIDv2Param = this.params.array;
	var aESSCertIDv2 = [];
	for (var i = 0; i < aESSCertIDv2Param.length; i++) {
	    var idparam = aESSCertIDv2Param[i];

	    if ((params.alg != undefined ||
		 params.hasis == false) &&
		(typeof idparam == "string" &&
		 (idparam.indexOf("-----BEGIN") != -1 ||
		  ASN1HEX.isASN1HEX(idparam)))) {
		idparam = {cert: idparam};
	    }

	    if (idparam.alg == undefined && params.alg != undefined) {
		idparam.alg = params.alg;
	    }

	    if (idparam.hasis != false && params.hasis == false) {
		idparam.hasis = false;
	    }

	    aESSCertIDv2.push(new _ESSCertIDv2(idparam));
	}
	var dCerts = new _DERSequence({array: aESSCertIDv2});
	var dSigningCertificatev2 = new _DERSequence({array: [dCerts]});
	return [dSigningCertificatev2];
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.SigningCertificateV2, KJUR.asn1.cms.Attribute);

/**
 * class for CMS ESSCertIDv2 ASN.1 encoder<br/>
 * @name KJUR.asn1.cms.ESSCertIDv2
 * @class class for CMS ESSCertIDv2 ASN.1 encoder
 * @param {Object} params PEM certificate string or JSON of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cms 2.0.0
 * @see KJUR.asn1.cms.SigningCertificate
 * @see KJUR.asn1.cms.IssuerSerial
 * @see KJUR.asn1.cms.ESSCertID
 *
 * @description
 * This is an ASN.1 encoder for SigningCertificateV2 attribute
 * defined in
 * <a href="https://tools.ietf.org/html/rfc5035#section-4">
 * RFC 5035 section 4</a>.
 * <pre>
 * ESSCertIDv2 ::=  SEQUENCE {
 *    hashAlgorithm           AlgorithmIdentifier
 *                            DEFAULT {algorithm id-sha256},
 *    certHash                Hash,
 *    issuerSerial            IssuerSerial OPTIONAL }
 * Hash ::= OCTET STRING
 * IssuerSerial ::= SEQUENCE {
 *    issuer                  GeneralNames,
 *    serialNumber            CertificateSerialNumber }
 * </pre>
 *
 * @example
 * new KJUR.asn1.cms.ESSCertIDv2("-----BEGIN...")
 * new KJUR.asn1.cms.ESSCertIDv2({cert: "-----BEGIN..."})
 * new KJUR.asn1.cms.ESSCertIDv2({cert: "-----BEGIN...", hasis: false})
 * new KJUR.asn1.cms.ESSCertIDv2({
 *   hash: "3f2d...",
 *   alg: "sha512",
 *   issuer: {str: "/C=JP/O=T1"},
 *   serial: {hex: "12ab..."}
 * })
 */
KJUR.asn1.cms.ESSCertIDv2 = function(params) {
    KJUR.asn1.cms.ESSCertIDv2.superclass.constructor.call(this);

    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_DERSequence = _KJUR_asn1.DERSequence,
	_IssuerSerial = _KJUR_asn1.cms.IssuerSerial,
	_AlgorithmIdentifier = _KJUR_asn1.x509.AlgorithmIdentifier;

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var hCertHash = this.getCertHash(params, 'sha256');

	var a = [];
	if (params.alg != undefined && params.alg != "sha256")
	    a.push(new _AlgorithmIdentifier({name: params.alg}));
	a.push(new _DEROctetString({hex: hCertHash}));
	if ((typeof params == "string" &&
	     params.indexOf("-----BEGIN") != -1) ||
	    (params.cert != undefined &&
	     params.hasis != false) ||
	    (params.issuer != undefined &&
	     params.serial != undefined))
	    a.push(new _IssuerSerial(params));
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.ESSCertIDv2, KJUR.asn1.cms.ESSCertID);

/**
 * class for IssuerSerial ASN.1 structure for CMS<br/>
 * @name KJUR.asn1.cms.IssuerSerial
 * @class class for CMS IssuerSerial ASN.1 structure for CMS
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 8.0.24 asn1cms 1.0.8
 * @see KJUR.asn1.cms.IssuerAndSerialNumber
 * @see KJUR.asn1.cms.SigningCertificate
 * @see KJUR.asn1.cms.SigningCertificateV2
 * @see KJUR.asn1.cms.ESSCertID
 * @see KJUR.asn1.cms.ESSCertIDv2
 * @see KJUR.asn1.x509.GeneralNames
 * @see KJUR.asn1.x509.X500Name
 *
 * @description
 * This class represents IssuerSerial ASN.1 structure
 * used by ESSCertID/v2 of SigningCertificate/V2 attribute
 * defined in 
 * <a href="https://tools.ietf.org/html/rfc5035#page-6">
 * RFC 5034 section 4</a>.
 * <pre>
 * IssuerSerial ::= SEQUENCE {
 *    issuer          GeneralNames,
 *    serialNumber    CertificateSerialNumber }
 * CertificateSerialNumber ::= INTEGER
 * </pre>
 *
 * @example
 * // specify by X500Name parameter and DERInteger
 * o = new KJUR.asn1.cms.IssuerSerial(
 *      {issuer: {str: '/C=US/O=T1'}, serial {int: 3}});
 * // specify by PEM certificate
 * o = new KJUR.asn1.cms.IssuerSerial({cert: certPEM});
 * o = new KJUR.asn1.cms.IssuerSerial(certPEM); // since 1.0.3
 */
KJUR.asn1.cms.IssuerSerial = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_GeneralNames = _KJUR_asn1_x509.GeneralNames,
	_X509 = X509;

    _KJUR_asn1_cms.IssuerSerial.superclass.constructor.call(this);

    this.setByParam = function(params) {
	this.params = params;
    };

    this.tohex = function() {
	var params = this.params;

	var pIssuer, pSerial;
	if ((typeof params == "string" &&
	     params.indexOf("-----BEGIN") != -1) ||
	    params.cert != undefined) {
	    var pem;

	    if (params.cert != undefined) {
		pem = params.cert;
	    } else {
		pem = params;
	    }

	    var x = new _X509();
	    x.readCertPEM(pem);
	    pIssuer = x.getIssuer();
	    pSerial = {hex: x.getSerialNumberHex()};
	} else if (params.issuer != undefined && params.serial) {
	    pIssuer = params.issuer;
	    pSerial = params.serial;
	} else {
	    throw new _Error("cert or issuer and serial parameter not specified");
	}
	
	var dIssuer = new _GeneralNames([{dn: pIssuer}]);
	var dSerial = new _DERInteger(pSerial);
	var seq = new _DERSequence({array: [dIssuer, dSerial]});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.IssuerSerial, KJUR.asn1.ASN1Object);

/**
 * class for SignerIdentifier ASN.1 structure for CMS
 * @name KJUR.asn1.cms.SignerIdentifier
 * @class class for CMS SignerIdentifier ASN.1 structure for CMS
 * @param {Array} params JSON object of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cms 2.0.0
 * @see KJUR.asn1.cms.SignedData
 * @see KJUR.asn1.cms.SignerInfo
 * @see KJUR.asn1.cms.IssuerAndSerialNumber
 * @see KJUR.asn1.cms.SubjectKeyIdentifier
 * @see KJUR.asn1.x509.X500Name
 *
 * @description
 * This is an ASN.1 encoder for SignerIdentifier
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-5.3">
 * RFC 5652 CMS section 5.3</a>.
 * <pre>
 * SignerIdentifier ::= CHOICE {
 *    issuerAndSerialNumber IssuerAndSerialNumber,
 *    subjectKeyIdentifier [0] SubjectKeyIdentifier }
 * </pre>
 * Constructor argument can have following properties:
 * <ul>
 * <li>{String}type - "isssn" for IssuerAndSerialNumber or "skid"
 * for SubjectKeyIdentifier</li>
 * <li>{Array}issuer - {@link KJUR.asn1.x509.X500Name} parameter for issuer</li>
 * <li>{Array}serial - {@link KJUR.asn1.DERInteger} parameter for serial number</li>
 * <li>{String}skid - hexadecimal string of subject key identifier</li>
 * <li>{String}cert - PEM certificate string for type "isssn" or "skid"</li>
 * </ul>
 * Constructor argument properties can have following combination:
 * <ul>
 * <li>type=isssn, issuer, serial - IssuerAndSerialNumber</li>
 * <li>type=isssn, cert - IssuerAndSerialNumber</li>
 * <li>type=skid, skid - SubjectKeyIdentifier</li>
 * <li>type=skdi, cert - SubjectKeyIdentifier</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.cms.SignerIdentifier({
 *   type: "isssn",
 *   issuer: {str: "/C=JP/O=T1"},
 *   serial: {hex: "12ab..."}
 * })
 * new KJUR.asn1.cms.SignerIdentifier({
 *   type: "isssn",
 *   cert: "-----BEGIN..."
 * })
 * new KJUR.asn1.cms.SignerIdentifier({
 *   type: "skid",
 *   skid: "12ab..."
 * })
 * new KJUR.asn1.cms.SignerIdentifier({
 *   type: "skid",
 *   cert: "-----BEGIN..."
 * })
 */
KJUR.asn1.cms.SignerIdentifier = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_IssuerAndSerialNumber = _KJUR_asn1_cms.IssuerAndSerialNumber,
	_SubjectKeyIdentifier = _KJUR_asn1_cms.SubjectKeyIdentifier,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_X500Name = _KJUR_asn1_x509.X500Name,
	_X509 = X509,
	_Error = Error;

    _KJUR_asn1_cms.SignerIdentifier.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;
	if (params.type == "isssn") {
	    var dISSSN = new _IssuerAndSerialNumber(params);
	    return dISSSN.tohex();
	} else if (params.type == "skid") {
	    var dSKID = new _SubjectKeyIdentifier(params);
	    return dSKID.tohex();
	} else {
	    throw new Error("wrong property for isssn or skid");
	}
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.SignerIdentifier, KJUR.asn1.ASN1Object);

/**
 * class for IssuerAndSerialNumber ASN.1 structure for CMS<br/>
 * @name KJUR.asn1.cms.IssuerAndSerialNumber
 * @class class for CMS IssuerAndSerialNumber ASN.1 structure for CMS
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @see KJUR.asn1.cms.IssuerSerial
 *
 * @description
 * This class encodes IssuerAndSerialNumber ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.4">
 * RFC 5662 CMS 10.2.4</a>. 
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *    issuer           Name,
 *    serialNumber     CertificateSerialNumber }
 * CertificateSerialNumber ::= INTEGER
 * </pre>
 * Constructor of this class can have following parameters:
 * <ul>
 * <li>{String}cert (OPTION) - PEM certificate string to specify issuer and serial</li>
 * <li>{Array}issuer (OPTION) - {@link KJUR.asn1.x509.X500Name} parameter for issuer name</li>
 * <li>{Array}serial (OPTION) - {@link KJUR.asn1.DERInteger} parameter for serialNumber</li>
 * </ul>
 *
 * @example
 * // specify by X500Name and DERInteger
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber(
 *      {issuer: {str: '/C=US/O=T1'}, serial: {int: 3}});
 * // specify by PEM certificate
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber({cert: certPEM});
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber(certPEM); // since 1.0.3
 */
KJUR.asn1.cms.IssuerAndSerialNumber = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_X500Name = _KJUR_asn1_x509.X500Name,
	_X509 = X509,
	_Error = Error;

    _KJUR_asn1_cms.IssuerAndSerialNumber.superclass.constructor.call(this);
    
    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var pIssuer, pSerial;
	if ((typeof params == "string" && params.indexOf("-----BEGIN") != -1) ||
	    params.cert != undefined) {
	    var pem;

	    if (params.cert != undefined) {
		pem = params.cert;
	    } else {
		pem = params;
	    }

	    var x = new _X509();
	    x.readCertPEM(pem);
	    pIssuer = x.getIssuer();
	    pSerial = {hex: x.getSerialNumberHex()};
	} else if (params.issuer != undefined && params.serial) {
	    pIssuer = params.issuer;
	    pSerial = params.serial;
	} else {
	    throw new _Error("cert or issuer and serial parameter not specified");
	}
	
	var dIssuer = new _X500Name(pIssuer);
	var dSerial = new _DERInteger(pSerial);
	var seq = new _DERSequence({array: [dIssuer, dSerial]});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    }

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.IssuerAndSerialNumber, KJUR.asn1.ASN1Object);

/**
 * class for SubjectKeyIdentifier ASN.1 structure for CMS SignerInfo<br/>
 * @name KJUR.asn1.cms.SubjectKeyIdentifier
 * @class class for SubjectKeyIdentifier ASN.1 structure for CMS SignerInfo
 * @param {Array} params JSON object of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cms 2.0.0
 *
 * @description
 * This class encodes SubjectKeyIdentifier ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-12.1">
 * RFC 5652 CMS 12.1</a>. 
 * <pre>
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 *
 * @example
 * new KJUR.asn1.cms.SubjectKeyIdentifier({cert: "-----BEGIN..."})
 * new KJUR.asn1.cms.SubjectKeyIdentifier({skid: "12ab..."})
 */
KJUR.asn1.cms.SubjectKeyIdentifier = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence,
	_newObject = _KJUR_asn1.ASN1Util.newObject,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_IssuerAndSerialName = _KJUR_asn1_cms.IssuerAndSerialName,
	_SubjectKeyIdentifier = _KJUR_asn1_cms.SubjectKeyIdentifier,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_X500Name = _KJUR_asn1_x509.X500Name,
	_X509 = X509,
	_Error = Error;

    _KJUR_asn1_cms.SubjectKeyIdentifier.superclass.constructor.call(this);

    this.tohex = function() {
	var params = this.params;

	if (params.cert == undefined && params.skid == undefined)
	    throw new _Error("property cert nor skid undefined");

	var hSKID;
	if (params.cert != undefined) {
	    var x = new _X509(params.cert);
	    var pSKID = x.getExtSubjectKeyIdentifier();
	    hSKID = pSKID.kid.hex;
	} else if (params.skid != undefined) {
	    hSKID = params.skid;
	}
	var dSKID = 
	    _newObject({tag:{tage:"a0",obj:{octstr:{hex:hSKID}}}});
	return dSKID.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.SubjectKeyIdentifier, KJUR.asn1.ASN1Object);

/**
 * class for Attributes ASN.1 structure for CMS<br/>
 * @name KJUR.asn1.cms.AttributeList
 * @class class for Attributes ASN.1 structure for CMS
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 *
 * @description
 * <pre>
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * </pre>
 *
 * @example
 * new KJUR.asn1.cms.AttributeList({
 *   array: [{
 *     attr: "contentType",
 *     type: "data"
 *   }],
 *   sortflag: false
 * })
 */
KJUR.asn1.cms.AttributeList = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSet = _KJUR_asn1.DERSet,
	_KJUR_asn1_cms = _KJUR_asn1.cms;

    _KJUR_asn1_cms.AttributeList.superclass.constructor.call(this);

    this.params = null;
    this.hTLV = null;

    this.setByParam = function(params) {
	this.params = params;
    };

    this.tohex = function() {
	var params = this.params;
	if (this.hTLV != null) return this.hTLV;

	var sortflag = true;
	if (params.sortflag != undefined) {
	    sortflag = params.sortflag;
	}

        var aAttrParam = params.array;
	var a = [];
	for (var i = 0; i < aAttrParam.length; i++) {
	    var pAttr = aAttrParam[i];
	    var attrName = pAttr.attr;
	    if (attrName == "contentType") {
		a.push(new _KJUR_asn1_cms.ContentType(pAttr));
	    } else if (attrName == "messageDigest") {
		a.push(new _KJUR_asn1_cms.MessageDigest(pAttr));
	    } else if (attrName == "signingTime") {
		a.push(new _KJUR_asn1_cms.SigningTime(pAttr));
	    } else if (attrName == "signingCertificate") {
		a.push(new _KJUR_asn1_cms.SigningCertificate(pAttr));
	    } else if (attrName == "signingCertificateV2") {
		a.push(new _KJUR_asn1_cms.SigningCertificateV2(pAttr));
	    } else if (attrName == "signaturePolicyIdentifier") {
		a.push(new KJUR.asn1.cades.SignaturePolicyIdentifier(pAttr));
	    } else if (attrName == "signatureTimeStamp" ||
		       attrName == "timeStampToken") {
		a.push(new KJUR.asn1.cades.SignatureTimeStamp(pAttr));
	    } else {
		throw new _Error("unknown attr: " + attrName);
	    }
	}
	
	var dSet = new _DERSet({array: a, sortflag: sortflag});
	this.hTLV = dSet.tohex();
	return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.AttributeList, KJUR.asn1.ASN1Object);

/**
 * class for SignerInfo ASN.1 structure of CMS SignedData<br/>
 * @name KJUR.asn1.cms.SignerInfo
 * @class class for Attributes ASN.1 structure of CMS SigndData
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @see KJUR.asn1.cms.SignerIdentifier
 * @see KJUR.asn1.x509.AlgorithmIdentifier
 * @see KJUR.asn1.cms.AttributeList
 *
 * @description
 * This class is an ASN.1 encoder for SignerInfo structure
 * defined in
 * <a https://tools.ietf.org/html/rfc5652#section-5.3">
 * RFC 5652 CMS section 5.3</a>.
 * <pre>
 * SignerInfo ::= SEQUENCE {
 *    version CMSVersion,
 *    sid SignerIdentifier,
 *    digestAlgorithm DigestAlgorithmIdentifier,
 *    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *    signatureAlgorithm SignatureAlgorithmIdentifier,
 *    signature SignatureValue,
 *    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
 * </pre>
 * Constractor parameter can have following properties:
 * <ul>
 * <li>{Integer}version - version of SignerInfo. </li>
 * <li>{Array}id - {@link KJUR.asn1.cms.SignerIdentifier} parameter for sid</li>
 * <li>{String}hashalg - digestAlgorithm name string (ex. "sha256")</li>
 * <li>{Array}sattrs - {@link KJUR.asn1.cms.AttributeList} parameter for 
 * signedAttributes</li>
 * <li>{String}sigalg - string for signatureAlgorithm name</a>
 * <li>{String}signkey (OPTION) - specifies signing private key.
 * Parameter "signkey" or "sighex" shall be specified. Following
 * values can be specified:
 *   <ul>
 *   <li>PKCS#1/5 or PKCS#8 PEM string of private key</li>
 *   <li>RSAKey/DSA/ECDSA key object. {@link KEYUTIL.getKey} is useful
 *   to generate a key object.</li>
 *   </ul>
 * </li>
 * <li>{String}sighex (OPTION) - hexadecimal string of signature value
 * (i.e. ASN.1 value(V) of signatureValue BIT STRING without
 * unused bits)</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.cms.SignerInfo({
 *   version: 1,
 *   id: {type: 'isssn', issuer: {str: '/C=US/O=T1'}, serial: {int: 1}},
 *   hashalg: "sha1",
 *   sattrs: {array: [{
 *     attr: "contentType",
 *     type: '1.2.840.113549.1.7.1'
 *   },{
 *     attr: "messageDigest",
 *     hex: 'a1a2a3a4a5a6a7a8a9a0a1a2a3a4a5a6a7a8a9a0'
 *   }]},
 *   sigalg: "SHA1withRSA",
 *   sighex: 'b1b2b...'
 * })
 */
KJUR.asn1.cms.SignerInfo = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_SignerIdentifier = _KJUR_asn1_cms.SignerIdentifier,
	_AttributeList = _KJUR_asn1_cms.AttributeList,
	_ContentType = _KJUR_asn1_cms.ContentType,
	_EncapsulatedContentInfo = _KJUR_asn1_cms.EncapsulatedContentInfo,
	_MessageDigest = _KJUR_asn1_cms.MessageDigest,
	_SignedData = _KJUR_asn1_cms.SignedData,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier,
	_KJUR_crypto = _KJUR.crypto,
	_KEYUTIL = KEYUTIL;

    _KJUR_asn1_cms.SignerInfo.superclass.constructor.call(this);

    this.params = null;
    
    /**
     * sign SignerInfo<br/>
     * @name sign
     * @memberOf KJUR.asn1.cms.SignerInfo#
     * @function
     *
     * @description
     * This method signs SignerInfo with a specified 
     * private key and algorithm by 
     * "params.signkey" and "params.sigalg" parameter.
     * In general, you don't need to call this method.
     * It will be called when tohex() method if necessary.
     *
     * @example
     * si = new KJUR.asn1.cms.SignerInfo({...});
     * si.sign()
     */
    this.sign = function() {
	var params = this.params;
	var sigalg = params.sigalg;

	var hData = (new _AttributeList(params.sattrs)).tohex();
	var prvkey = _KEYUTIL.getKey(params.signkey);
	var sig = new _KJUR_crypto.Signature({alg: sigalg});
	sig.init(prvkey);
	sig.updateHex(hData);
	var hSig = sig.sign();
	params.sighex = hSig;
    };

    this.tohex = function() {
	var params = this.params;

	var a = [];
        a.push(new _DERInteger({"int": params.version}));
	a.push(new _SignerIdentifier(params.id));
	a.push(new _AlgorithmIdentifier({name: params.hashalg}));
	if (params.sattrs != undefined) {
	    var dList = new _AttributeList(params.sattrs);
	    try {
		a.push(new _DERTaggedObject({tag: "a0", 
					     explicit: false,
					     obj: dList}));
	    } catch(ex) {
		throw new _Error("si sattr error: " + ex);
	    }
	}

	if (params.sigalgfield != undefined) {
	    a.push(new _AlgorithmIdentifier({name: params.sigalgfield}));
	} else {
	    a.push(new _AlgorithmIdentifier({name: params.sigalg}));
	}

	if (params.sighex == undefined &&
	    params.signkey != undefined) {
	    this.sign();
	}
	a.push(new _DEROctetString({hex: params.sighex}));

	if (params.uattrs != undefined) {
	    var dList = new _AttributeList(params.uattrs);
	    try {
		a.push(new _DERTaggedObject({tag: "a1", 
					     explicit: false,
					     obj: dList}));
	    } catch(ex) {
		throw new _Error("si uattr error: " + ex);
	    }
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.SignerInfo, KJUR.asn1.ASN1Object);

/**
 * class for EncapsulatedContentInfo ASN.1 structure for CMS<br/>
 * @name KJUR.asn1.cms.EncapsulatedContentInfo
 * @class class for EncapsulatedContentInfo ASN.1 structure for CMS
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 *
 * @description
 * <pre>
 * EncapsulatedContentInfo ::= SEQUENCE {
 *    eContentType ContentType,
 *    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 *
 * @example
 * new KJUR.asn1.cms.EncapsulatedContentInfo({
 *  type: "data",
 *  content: {str: "aaa"}
 * })
 * new KJUR.asn1.cms.EncapsulatedContentInfo({
 *  type: "data",
 *  content: {hex: "616161"}
 * })
 * new KJUR.asn1.cms.EncapsulatedContentInfo({
 *  type: "data",
 *  content: {hex: "616161"},
 *  isDetached: true
 * })
 * new KJUR.asn1.cms.EncapsulatedContentInfo({
 *  type: "tstinfo",
 *  content: ...TSTInfo parameters...
 * })
 */
KJUR.asn1.cms.EncapsulatedContentInfo = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_KJUR_asn1_cms = _KJUR_asn1.cms;

    _KJUR_asn1_cms.EncapsulatedContentInfo.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var a = [];

	a.push(new _DERObjectIdentifier(params.type));

	if (params.content != undefined &&
	    (params.content.hex != undefined || 
	     params.content.str != undefined) &&
	    params.isDetached != true) {
	    var dOctStr = new _DEROctetString(params.content);
	    var dEContent = new _DERTaggedObject({tag: "a0",
						  explicit: true,
						  obj: dOctStr});
	    a.push(dEContent);
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.EncapsulatedContentInfo, KJUR.asn1.ASN1Object);

// - type
// - obj
/**
 * class for ContentInfo ASN.1 structure for CMS
 * @name KJUR.asn1.cms.ContentInfo
 * @class class for ContentInfo ASN.1 structure for CMS
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *    contentType ContentType,
 *    content [0] EXPLICIT ANY DEFINED BY contentType }
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @example
 * a = [new KJUR.asn1.DERInteger({int: 1}),
 *      new KJUR.asn1.DERInteger({int: 2})];
 * seq = new KJUR.asn1.DERSequence({array: a});
 * o = new KJUR.asn1.cms.ContentInfo({type: 'data', obj: seq});
 */
KJUR.asn1.cms.ContentInfo = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_name2obj = _KJUR_asn1_x509.OID.name2obj;

    KJUR.asn1.cms.ContentInfo.superclass.constructor.call(this);
    
    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var a = [];
	a.push(new _DERObjectIdentifier(params.type));

	var dContent0 = new _DERTaggedObject({
	    tag: "a0",
	    explicit: true,
	    obj: params.obj
	});
	a.push(dContent0);

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.ContentInfo, KJUR.asn1.ASN1Object);

/**
 * class for SignerInfo ASN.1 structure of CMS SignedData
 * @name KJUR.asn1.cms.SignedData
 * @class class for Attributes ASN.1 structure of CMS SigndData
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 *
 * @description
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *    contentType ContentType,
 *    content [0] EXPLICIT ANY DEFINED BY contentType }
 * ContentType ::= OBJECT IDENTIFIER
 * SignedData ::= SEQUENCE {
 *    version CMSVersion,
 *    digestAlgorithms DigestAlgorithmIdentifiers,
 *    encapContentInfo EncapsulatedContentInfo,
 *    certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *    signerInfos SignerInfos }
 * SignerInfos ::= SET OF SignerInfo
 * CertificateSet ::= SET OF CertificateChoices
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * CertificateSet ::= SET OF CertificateChoices
 * RevocationInfoChoices ::= SET OF RevocationInfoChoice
 * </pre>
 *
 * @example
 * sd = new KJUR.asn1.cms.SignedData({
 *   version: 1,
 *   hashalgs: ["sha1"],
 *   econtent: {
 *     type: "data",
 *     content: {
 *       hex: "616161"
 *     }
 *   },
 *   certs: [PEM1,...],
 *   revinfos: {array: [...]},
 *   sinfos: [{
 *     version: 1,
 *     id: {type:'isssn', issuer: {str: '/C=US/O=T1'}, serial: {int: 1}},
 *     hashalg: "sha1",
 *     sattrs: {array: [{
 *       attr: "contentType",
 *       type: '1.2.840.113549.1.7.1'
 *     },{
 *       attr: "messageDigest",
 *       hex: 'abcd'
 *     }]},
 *     sigalg: "SHA1withRSA",
 *     signkey: PEMPRIVATEKEY
 *   }]
 * });
 * hex = sd.getContentInfoEncodedHex();
 */
KJUR.asn1.cms.SignedData = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSet = _KJUR_asn1.DERSet,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_EncapsulatedContentInfo = _KJUR_asn1_cms.EncapsulatedContentInfo,
	_SignerInfo = _KJUR_asn1_cms.SignerInfo,
	_ContentInfo = _KJUR_asn1_cms.ContentInfo,
	_CertificateSet = _KJUR_asn1_cms.CertificateSet,
	_RevocationInfoChoices = _KJUR_asn1_cms.RevocationInfoChoices,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier;

    KJUR.asn1.cms.SignedData.superclass.constructor.call(this);

    this.params = null;

    /**
     * fix fields before ASN.1 encode<br/>
     * @name checkAndFixParam
     * @memberOf KJUR.asn1.cms.SignedData#
     * @function
     *
     * @description
     * Update following values of "params" property
     * as defined in RFC 5652:
     * <ul>
     * <li>set "digestAlgorithms" field of "signedData" by
     * signerInfos</li>
     * <li>set all "contentType" signed attribute value to
     * the same value of eContent</li>
     * <li>set all "messageDigest" signed attribute value
     * to hash value of eContent contents value</li>
     * <li>all signerInfo version by their fields</li>
     * <li>signedData version by their fields</li>
     * </ul>
     * In general, you don't need to call this method.
     * It will be called automatically when
     * getEncodedHex() method is called.
     * <br>
     * NOTE: If you don't want to do such property value
     * update, set "params.fixed" property to "true".
     */
    this.checkAndFixParam = function() {
	var sdparams = this.params;
	this._setDigestAlgs(sdparams);
	this._setContentTypeByEContent(sdparams);
	this._setMessageDigestByEContent(sdparams);
	this._setSignerInfoVersion(sdparams);
	this._setSignedDataVersion(sdparams);
    };

    /*
     * @description
     * Get params.sinfos[*].hashalg for all "signerInfo"
     * and set "params.hashalgs" of "signedData" as
     * array of hash algorithm names.
     */
    this._setDigestAlgs = function(sdparams) {
	var pHash = {};
	var sinfos = sdparams.sinfos;
	for (var i = 0; i < sinfos.length; i++) {
	    var sinfo = sinfos[i];
	    pHash[sinfo.hashalg] = 1;
	}
	sdparams.hashalgs = Object.keys(pHash).sort();
    };

    /*
     * @description
     * set "contentType" attribute value in 
     * "params.sinfos[*].sattrs" to "params.econtent.type"
     * value.
     */
    this._setContentTypeByEContent = function(sdparams) {
	var type = sdparams.econtent.type;
	var sinfos = sdparams.sinfos;
	for (var i = 0; i < sinfos.length; i++) {
	    var sinfo = sinfos[i];
	    var ctParam = this._getAttrParamByName(sinfo, "contentType");
	    //console.log(ctParam.type + " > " + type);
	    ctParam.type = type;
	}
    };

    /*
     * @description
     * set "messageDigest" attribute value in
     * "params.sinfos[*].sattrs" to a
     * calculated hash value by "econtent.content.hex"
     * with "params.sinfos[*].hashalg" algorithm.
     */
    this._setMessageDigestByEContent = function(sdparams) {
	var econtent = sdparams.econtent;
	var type = sdparams.econtent.type;

	var hContent = econtent.content.hex;
	if (hContent == undefined &&
	    econtent.type == "data" &&
	    econtent.content.str != undefined) {
	    hContent = rstrtohex(econtent.content.str);
	}

	var sinfos = sdparams.sinfos;
	for (var i = 0; i < sinfos.length; i++) {
	    var sinfo = sinfos[i];
	    var hashalg = sinfo.hashalg;
	    var mdParam = this._getAttrParamByName(sinfo, "messageDigest");

	    var hNew = KJUR.crypto.Util.hashHex(hContent, hashalg);

	    //console.log(mdParam.hex + " > " + hNew);
	    mdParam.hex = hNew;
	}
    };

    /*
     * @param {Array}siParam "signerInfo" JSON parameter reference
     * @param {String}attrName attribute name string
     * @return {Array} attribute JSON parameter reference
     * @description
     * Find signed attribute parameter from signerInfo parameter
     * by attribute name.
     */
    this._getAttrParamByName = function(siParam, attrName) {
	var aSattrs = siParam.sattrs.array;
	for (var i = 0; i < aSattrs.length; i++) {
	    if (aSattrs[i].attr == attrName) return aSattrs[i];
	}
    };

    /*
     * @description
     * set signerInfo version "params.sinfos[*].version" 
     * of all signerInfos by signerInfo parameter.
     * Version will be identified by "signerIdentifier" is
     * "skid" or not.
     */
    this._setSignerInfoVersion = function(sdparams) {
	var sinfos = sdparams.sinfos;
	for (var i = 0; i < sinfos.length; i++) {
	    var sinfo = sinfos[i];
	    var newVersion = 1;
	    if (sinfo.id.type == "skid") newVersion = 3;
	    sinfo.version = newVersion;
	}
    };

    /*
     * @description
     * set "signedData" version "params.version"
     * to value by _getSignedDataVersion()
     */
    this._setSignedDataVersion = function(sdparams) {
	var newVersion = this._getSignedDataVersion(sdparams);
	//console.log("sd version: " + sdparams.version + " > " + newVersion);
	sdparams.version = newVersion;
    };

    /*
     * @description
     * get "signedData" version from parameters.
     * If "revinfos" "ocsp" exists, then version 5.
     * If "signerInfo" version 3 exists, then version 3.
     * If "params.econtent.type" is not "data" then version 3.
     * Otherwise version 1.
     */
    this._getSignedDataVersion = function(sdparams) {
	//alert(JSON.stringify(sdparams));

	if (sdparams.revinfos != undefined) {
	    var revinfos = sdparams.revinfos;
	    for (var i = 0; i < revinfos.length; i++) {
		var revinfo = revinfos[i];
		if (revinfo.ocsp != undefined) return 5;
	    }
	}

	var sinfos = sdparams.sinfos;
	for (var i = 0; i < sinfos.length; i++) {
	    var sinfo = sdparams.sinfos[i];
	    if (sinfo.version == 3) return 3;
	}

	if (sdparams.econtent.type != "data") return 3;
	return 1;
    };

    this.tohex = function() {
	var params = this.params;

	if (this.getEncodedHexPrepare != undefined) {
	    this.getEncodedHexPrepare();
	}

	if (params.fixed != true) {
	    this.checkAndFixParam();
	}

	var a = [];

	a.push(new _DERInteger({"int": params.version}));

	var aHashAlg = [];
	for (var i = 0; i < params.hashalgs.length; i++) {
	    var name = params.hashalgs[i];
	    aHashAlg.push(new _AlgorithmIdentifier({name: name}));
	}
	a.push(new _DERSet({array: aHashAlg}));

	a.push(new _EncapsulatedContentInfo(params.econtent));

	if (params.certs != undefined) {
	    a.push(new _CertificateSet(params.certs));
	}

	if (params.revinfos != undefined) {
	    a.push(new _RevocationInfoChoices(params.revinfos));
	}

	var aSignerInfo = [];
	for (var i = 0; i < params.sinfos.length; i++) {
	    var pSI = params.sinfos[i];
	    aSignerInfo.push(new _SignerInfo(pSI));
	}
	a.push(new _DERSet({array: aSignerInfo}));

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    /**
     * get CotentInfo ASN.1 object concluding CMS SignedData<br/>
     * @name getContentInfo
     * @memberOf KJUR.asn1.cms.SignedData#
     * @function
     * @return {Object} ContentInfo of SigneData as {@link KJUR.asn1.ASN1Object}
     * @see KJUR.asn1.cms.ContentInfo
     *
     * @description
     * This method returns a {@link KJUR.asn1.ASN1Object}
     * of 
     * ContentInfo concludes SignedData.
     *
     * @example
     * sd = new KJUR.asn1.cms.SignedData({...});
     * sd.getContentInfo();
     */
    this.getContentInfo = function() {
	var dContentInfo = new _ContentInfo({
	    type: 'signed-data',
	    obj: this
	});
	return dContentInfo;
    };

    /**
     * get hex of entire ContentInfo of CMS SignedData<br/>
     * @name getContentInfoEncodedHex
     * @memberOf KJUR.asn1.cms.SignedData#
     * @function
     * @return {String} hexadecimal string of entire ContentInfo of CMS SignedData
     * @see KJUR.asn1.cms.SignedData#getContentInfo
     * @see KJUR.asn1.cms.ContentInfo
     *
     * @description
     * This method returns a hexadecimal string of
     * ContentInfo concludes SignedData.
     *
     * @example
     * sd = new KJUR.asn1.cms.SignedData({...});
     * sd.getContentInfoEncodedHex() &rarr "3082..."
     */
    this.getContentInfoEncodedHex = function() {
	return this.getContentInfo().tohex();
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.SignedData, KJUR.asn1.ASN1Object);

/**
 * class for CertificateSet ASN.1 structure for CMS SignedData<br/>
 * @name KJUR.asn1.cms.CertificateSet
 * @class class for CertificateSet ASN.1 structure for CMS SignedData
 * @param {Array} params array of RevocationInfoChoice parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cms 2.0.0
 * @see KJUR.asn1.cms.SignedData
 * @see KJUR.asn1.cms.RevocationInfoChoice
 *
 * @description
 * This is an ASN.1 encoder for CertificateSet
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.3">
 * RFC 5652 CMS section 10.2.3</a> and 
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.2">
 * section 10.2.2</a>.
 * <pre>
 * CertificateSet ::= SET OF CertificateChoices
 * CertificateChoices ::= CHOICE {
 *   certificate Certificate,
 *   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
 *   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
 *   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
 *   other [3] IMPLICIT OtherCertificateFormat }
 * OtherCertificateFormat ::= SEQUENCE {
 *   otherCertFormat OBJECT IDENTIFIER,
 *   otherCert ANY DEFINED BY otherCertFormat }
 * </pre>
 * Currently only "certificate" is supported in
 * CertificateChoices.
 * 
 * @example
 * new KJUR.asn1.cms.CertificateSet([certpem1,certpem2,...])
 * new KJUR.asn1.cms.CertificateSet({
 *   array: [certpem1,certpem2,...],
 *   sortflag: false
 * })
 */
KJUR.asn1.cms.CertificateSet = function(params) {
    KJUR.asn1.cms.CertificateSet.superclass.constructor.call(this);

    var _Error = Error,
	_KJUR_asn1 = KJUR.asn1,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_DERSet = _KJUR_asn1.DERSet,
	_ASN1Object = _KJUR_asn1.ASN1Object;

    this.params = null;

    this.tohex = function() {
	var params = this.params;
	var a = [];

	var aParam;
	if (params instanceof Array) {
	    aParam = params;
	} else if (params.array != undefined) {
	    aParam = params.array;
	} else {
	    throw new _Error("cert array not specified");
	}

	for (var i = 0; i < aParam.length; i++) {
	    var pem = aParam[i];
	    var hCert = pemtohex(pem);
	    var dCert = new _ASN1Object();
	    dCert.hTLV = hCert;
	    a.push(dCert);
	}
	var pSet = {array: a};
	if (params.sortflag == false) pSet.sortflag = false;
	var dSet = new _DERSet(pSet);

	var dTagObj = new _DERTaggedObject({
	    tag: "a0",
	    explicit: false,
	    obj: dSet
	});
	return dTagObj.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.CertificateSet, KJUR.asn1.ASN1Object);

/**
 * class for RevocationInfoChoices ASN.1 structure for CMS SignedData<br/>
 * @name KJUR.asn1.cms.RevocationInfoChoices
 * @class class for RevocationInfoChoices ASN.1 structure for CMS SignedData
 * @param {Array} params array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cms 2.0.0
 * @see KJUR.asn1.cms.SignedData
 *
 * @description
 * This is an ASN.1 encoder for RevocationInfoChoices
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.1">
 * RFC 5652 CMS section 10.2.1</a>.
 * <pre>
 * RevocationInfoChoices ::= SET OF RevocationInfoChoice
 * RevocationInfoChoice ::= CHOICE {
 *   crl CertificateList,
 *   other [1] IMPLICIT OtherRevocationInfoFormat }
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *   otherRevInfoFormat OBJECT IDENTIFIER,
 *   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
 * </pre>
 *
 * @example
 * new KJUR.asn1.cms.RevocationInfoChoices([
 *   {crl: CRLPEMorHex1},
 *   {ocsp: OCSPResponseHex1},
 *   ...
 * ]})
 */
KJUR.asn1.cms.RevocationInfoChoices = function(params) {
    KJUR.asn1.cms.RevocationInfoChoices.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	if (! params instanceof Array)
	    throw new Error("params is not array");

	var a = [];
	for (var i = 0; i < params.length; i++) {
	    a.push(new KJUR.asn1.cms.RevocationInfoChoice(params[i]));
	}
	var dRevInfos = KJUR.asn1.ASN1Util.newObject({tag: {tagi:"a1",obj:{set:a}}});
	return dRevInfos.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.RevocationInfoChoices, KJUR.asn1.ASN1Object);

/**
 * class for RevocationInfoChoice ASN.1 structure for CMS SignedData<br/>
 * @name KJUR.asn1.cms.RevocationInfoChoice
 * @class class for RevocationInfoChoice ASN.1 structure for CMS SignedData
 * @param {Array} params array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cms 2.0.0
 * @see KJUR.asn1.cms.SignedData
 * @see KJUR.asn1.cms.RevocationInfoChoices
 *
 * @description
 * This is an ASN.1 encoder for RevocationInfoChoice
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.1">
 * RFC 5652 CMS section 10.2.1</a>.
 * <pre>
 * RevocationInfoChoice ::= CHOICE {
 *   crl CertificateList,
 *   other [1] IMPLICIT OtherRevocationInfoFormat }
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *   otherRevInfoFormat OBJECT IDENTIFIER,
 *   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
 * </pre>
 *
 * @example
 * new KJUR.asn1.cms.RevocationInfoChoice({
 *   crl: CRLPEMorHex
 * })
 * new KJUR.asn1.cms.RevocationInfoChoice({
 *   ocsp: OCSPResponseHex
 * })
 */
KJUR.asn1.cms.RevocationInfoChoice = function(params) {
    KJUR.asn1.cms.RevocationInfoChoice.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	if (params.crl != undefined && typeof params.crl == "string") {
	    var hCRL = params.crl;
	    if (params.crl.indexOf("-----BEGIN") != -1) {
		hCRL = pemtohex(params.crl);
	    }
	    return hCRL;
	} else if (params.ocsp != undefined) {
	    var dTag1 = KJUR.asn1.ASN1Util.newObject({tag: {
		tagi: "a1",
		obj: new KJUR.asn1.cms.OtherRevocationFormat(params)
	    }});
	    return dTag1.tohex();
	} else {
	    throw new Error("property crl or ocsp undefined");
	}
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.RevocationInfoChoice, KJUR.asn1.ASN1Object);

/**
 * class for OtherRevocationFormat ASN.1 structure for CMS SignedData<br/>
 * @name KJUR.asn1.cms.OtherRevocationFormat
 * @class class for OtherRevocationFormat ASN.1 structure for CMS SignedData
 * @param {Array} params array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cms 2.0.0
 * @see KJUR.asn1.cms.SignedData
 * @see KJUR.asn1.cms.RevocationInfoChoices
 * @see KJUR.asn1.cms.RevocationInfoChoice
 *
 * @description
 * This is an ASN.1 encoder for OtherRevocationFormat
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc5940">
 * RFC 5652</a>.
 * <pre>
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *   otherRevInfoFormat  OBJECT IDENTIFIER,
 *   otherRevInfo        ANY DEFINED BY otherRevInfoFormat }
 * id-ri OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *   dod(6) internet(1) security(5) mechanisms(5) pkix(7) ri(16) }
 * id-ri-ocsp-response OBJECT IDENTIFIER ::= { id-ri 2 }
 * --  id-ri-ocsp-response 1.3.6.1.5.5.7.16.2
 * </pre>
 * NOTE: Currently this class only supports "ocsp"
 *
 * @example
 * new KJUR.asn1.cms.OtherRevocationFormat({
 *   ocsp: OCSPResponseHex
 * })
 */
KJUR.asn1.cms.OtherRevocationFormat = function(params) {
    KJUR.asn1.cms.OtherRevocationFormat.superclass.constructor.call(this);

    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_newObject = _KJUR_asn1.ASN1Util.newObject,
	_isHex = _KJUR.lang.String.isHex;

    this.params = null;

    this.tohex = function() {
	var params = this.params;
	if (params.ocsp == undefined)
	    throw new _Error("property ocsp not specified");
	if (! _isHex(params.ocsp) ||
	    ! ASN1HEX.isASN1HEX(params.ocsp))
	    throw new _Error("ocsp value not ASN.1 hex string");
	
	var dOtherRev = _newObject({
	    seq: [
		{oid: "1.3.6.1.5.5.7.16.2"},
		{asn1: {tlv: params.ocsp}}
	    ]
	});
	return dOtherRev.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cms.OtherRevocationFormat, KJUR.asn1.ASN1Object);

/**
 * CMS utiliteis class
 * @name KJUR.asn1.cms.CMSUtil
 * @class CMS utilities class
 */
KJUR.asn1.cms.CMSUtil = new function() {
};

/**
 * generate SignedData object specified by JSON parameters (DEPRECATED)<br/>
 * @name newSignedData
 * @memberOf KJUR.asn1.cms.CMSUtil
 * @function
 * @param {Array} params JSON parameter to generate CMS SignedData
 * @return {KJUR.asn1.cms.SignedData} object just generated
 * @deprecated since jsrsasign 10.0.0 asn1cms 2.0.0. 
 *
 * @description
 * This class generates {@link KJUR.asn1.cms.SignedData} object.
 * However this class is deprecated.
 * Please use {@link KJUR.asn1.cms.SignedData} class constructor
 * instead. As for "params" parameter, 
 * {@link KJUR.asn1.cms.SignedData} parameters are available.
 */
KJUR.asn1.cms.CMSUtil.newSignedData = function(param) {
    return new KJUR.asn1.cms.SignedData(param);
};

/**
 * verify SignedData specified by JSON parameters
 * @name verifySignedData
 * @memberOf KJUR.asn1.cms.CMSUtil
 * @function
 * @param {Array} param JSON parameter to verify CMS SignedData
 * @return {Object} JSON data as the result of validation
 * @since jsrsasign 8.0.4 asn1cms 1.0.5
 * @description
 * This method provides validation for CMS SignedData.
 * Following parameters can be applied:
 * <ul>
 * <li>cms - hexadecimal data of DER CMS SignedData (aka. PKCS#7 or p7s)</li>
 *     to verify (OPTION)</li>
 * </ul>
 * @example
 * KJUR.asn1.cms.CMSUtil.verifySignedData({ cms: "3082058a..." }) 
 * &rarr;
 * {
 *   isValid: true,
 *   parse: ... // parsed data
 *   signerInfos: [
 *     {
 *     }
 *   ]
 * }
 */
KJUR.asn1.cms.CMSUtil.verifySignedData = function(param) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_SignerInfo = _KJUR_asn1_cms.SignerInfo,
	_SignedData = _KJUR_asn1_cms.SignedData,
	_SigningTime = _KJUR_asn1_cms.SigningTime,
	_SigningCertificate = _KJUR_asn1_cms.SigningCertificate,
	_SigningCertificateV2 = _KJUR_asn1_cms.SigningCertificateV2,
	_KJUR_asn1_cades = _KJUR_asn1.cades,
	_SignaturePolicyIdentifier = _KJUR_asn1_cades.SignaturePolicyIdentifier,
	_isHex = _KJUR.lang.String.isHex,
	_ASN1HEX = ASN1HEX,
	_getVbyList = _ASN1HEX.getVbyList,
	_getTLVbyList = _ASN1HEX.getTLVbyList,
	_getIdxbyList = _ASN1HEX.getIdxbyList,
	_getChildIdx = _ASN1HEX.getChildIdx,
	_getTLV = _ASN1HEX.getTLV,
	_oidname = _ASN1HEX.oidname,
	_hashHex = _KJUR.crypto.Util.hashHex;

    if (param.cms === undefined &&
        ! _isHex(param.cms)) {
    }

    var hCMS = param.cms;

    var _findSignerInfos = function(hCMS, result) {
	var idx;
	for (var i = 3; i < 6; i++) {
	    idx = _getIdxbyList(hCMS, 0, [1, 0, i]);
	    if (idx !== undefined) {
		var tag = hCMS.substr(idx, 2);
		if (tag === "a0") result.certsIdx = idx;
		if (tag === "a1") result.revinfosIdx = idx;
		if (tag === "31") result.signerinfosIdx = idx;
	    }
	}
    };

    var _parseSignerInfos = function(hCMS, result) {
	var idxSignerInfos = result.signerinfosIdx;
	if (idxSignerInfos === undefined) return;
	var idxList = _getChildIdx(hCMS, idxSignerInfos);
	result.signerInfoIdxList = idxList;
	for (var i = 0; i < idxList.length; i++) {
	    var idxSI = idxList[i];
	    var info = { idx: idxSI };
	    _parseSignerInfo(hCMS, info);
	    result.signerInfos.push(info);
	};
    };

    var _parseSignerInfo = function(hCMS, info) {
	var idx = info.idx;

	// 1. signer identifier
	info.signerid_issuer1 = _getTLVbyList(hCMS, idx, [1, 0], "30");
	info.signerid_serial1 = _getVbyList(hCMS, idx, [1, 1], "02");

	// 2. hash alg
	info.hashalg = _oidname(_getVbyList(hCMS, idx, [2, 0], "06"));

	// 3. [0] singedAtttrs
	var idxSignedAttrs = _getIdxbyList(hCMS, idx, [3], "a0");
	info.idxSignedAttrs = idxSignedAttrs;
	_parseSignedAttrs(hCMS, info, idxSignedAttrs);

	var aIdx = _getChildIdx(hCMS, idx);
	var n = aIdx.length;
	if (n < 6) throw "malformed SignerInfo";
	
	info.sigalg = _oidname(_getVbyList(hCMS, idx, [n - 2, 0], "06"));
	info.sigval = _getVbyList(hCMS, idx, [n - 1], "04");
	//info.sigval = _getVbyList(hCMS, 0, [1, 0, 4, 0, 5], "04");
	//info.sigval = hCMS;
    };

    var _parseSignedAttrs = function(hCMS, info, idx) {
	var aIdx = _getChildIdx(hCMS, idx);
	info.signedAttrIdxList = aIdx;
	for (var i = 0; i < aIdx.length; i++) {
	    var idxAttr = aIdx[i];
	    var hAttrType = _getVbyList(hCMS, idxAttr, [0], "06");
	    var v;

	    if (hAttrType === "2a864886f70d010905") { // siging time
		v = hextoutf8(_getVbyList(hCMS, idxAttr, [1, 0]));
		info.saSigningTime = v;
	    } else if (hAttrType === "2a864886f70d010904") { // message digest
		v = _getVbyList(hCMS, idxAttr, [1, 0], "04");
		info.saMessageDigest = v;
	    }
	}
    };

    var _parseSignedData = function(hCMS, result) {
	// check if signedData (1.2.840.113549.1.7.2) type
	if (_getVbyList(hCMS, 0, [0], "06") !== "2a864886f70d010702") {
	    return result;
	}
	result.cmsType = "signedData";

	// find eContent data
	result.econtent = _getVbyList(hCMS, 0, [1, 0, 2, 1, 0]);

	// find certificates,revInfos,signerInfos index
	_findSignerInfos(hCMS, result);

	result.signerInfos = [];
	_parseSignerInfos(hCMS, result);
    };

    var _verify = function(hCMS, result) {
	var aSI = result.parse.signerInfos;
	var n = aSI.length;
	var isValid = true;
	for (var i = 0; i < n; i++) {
	    var si = aSI[i];
	    _verifySignerInfo(hCMS, result, si, i);
	    if (! si.isValid)
		isValid = false;
	}
	result.isValid = isValid;
    };

    /*
     * _findCert
     * 
     * @param hCMS {String} hexadecimal string of CMS signed data
     * @param result {Object} JSON object of validation result
     * @param si {Object} JSON object of signerInfo in the result above
     * @param idx {Number} index of signerInfo???
     */
    var _findCert = function(hCMS, result, si, idx) {
	var certsIdx = result.parse.certsIdx;
	var aCert;

	if (result.certs === undefined) {
	    aCert = [];
	    result.certkeys = [];
	    var aIdx = _getChildIdx(hCMS, certsIdx);
	    for (var i = 0; i < aIdx.length; i++) {
		var hCert = _getTLV(hCMS, aIdx[i]);
		var x = new X509();
		x.readCertHex(hCert);
		aCert[i] = x;
		result.certkeys[i] = x.getPublicKey();
	    }
	    result.certs = aCert;
	} else {
	    aCert = result.certs;
	}

	result.cccc = aCert.length;
	result.cccci = aIdx.length;

	for (var i = 0; i < aCert.length; i++) {
	    var issuer2 = x.getIssuerHex();
	    var serial2 = x.getSerialNumberHex();
	    if (si.signerid_issuer1 === issuer2 &&
		si.signerid_serial1 === serial2) {
		si.certkey_idx = i;
	    }
	}
    };

    var _verifySignerInfo = function(hCMS, result, si, idx) {
	si.verifyDetail = {};

	var _detail = si.verifyDetail;

	var econtent = result.parse.econtent;

	// verify MessageDigest signed attribute
	var hashalg = si.hashalg;
	var saMessageDigest = si.saMessageDigest;
	
	// verify messageDigest
	_detail.validMessageDigest = false;
	//_detail._econtent = econtent;
	//_detail._hashalg = hashalg;
	//_detail._saMD = saMessageDigest;
	if (_hashHex(econtent, hashalg) === saMessageDigest)
	    _detail.validMessageDigest = true;

	// find signing certificate
	_findCert(hCMS, result, si, idx);
	//if (si.signerid_cert === undefined)
	//    throw Error("can't find signer certificate");

	// verify signature value
	_detail.validSignatureValue = false;
	var sigalg = si.sigalg;
	var hSignedAttr = "31" + _getTLV(hCMS, si.idxSignedAttrs).substr(2);
	si.signedattrshex = hSignedAttr;
	var pubkey = result.certs[si.certkey_idx].getPublicKey();
	var sig = new KJUR.crypto.Signature({alg: sigalg});
	sig.init(pubkey);
	sig.updateHex(hSignedAttr);
	var isValid = sig.verify(si.sigval);
	_detail.validSignatureValue_isValid = isValid;
	if (isValid === true)
	    _detail.validSignatureValue = true;

	// verify SignerInfo totally
	si.isValid =false;
	if (_detail.validMessageDigest &&
	    _detail.validSignatureValue) {
	    si.isValid = true;
	}
    };

    var _findSignerCert = function() {
    };

    var result = { isValid: false, parse: {} };
    _parseSignedData(hCMS, result.parse);

    _verify(hCMS, result);
    
    return result;
};

/**
 * class for parsing CMS SignedData<br/>
 * @name KJUR.asn1.cms.CMSParser
 * @class CMS SignedData parser class
 * @since jsrsasign 10.1.0 asn1cms 2.0.1
 *
 * @description
 * This is an ASN.1 parser for CMS SignedData defined in
 * <a href="https://tools.ietf.org/html/rfc5652">RFC 5652
 * Cryptographic Message Syntax (CMS)</a>.
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *    contentType ContentType,
 *    content [0] EXPLICIT ANY DEFINED BY contentType }
 * ContentType ::= OBJECT IDENTIFIER
 * SignedData ::= SEQUENCE {
 *    version CMSVersion,
 *    digestAlgorithms DigestAlgorithmIdentifiers,
 *    encapContentInfo EncapsulatedContentInfo,
 *    certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *    signerInfos SignerInfos }
 * SignerInfos ::= SET OF SignerInfo
 * CertificateSet ::= SET OF CertificateChoices
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * CertificateSet ::= SET OF CertificateChoices
 * RevocationInfoChoices ::= SET OF RevocationInfoChoice
 * </pre>
 */
KJUR.asn1.cms.CMSParser = function() {
    var _Error = Error,
	_X509 = X509,
	_x509obj = new _X509(),
	_ASN1HEX = ASN1HEX,
	_getV = _ASN1HEX.getV,
	_getTLV = _ASN1HEX.getTLV,
	_getIdxbyList = _ASN1HEX.getIdxbyList,
	_getTLVbyList = _ASN1HEX.getTLVbyList,
	_getTLVbyListEx = _ASN1HEX.getTLVbyListEx,
	_getVbyList = _ASN1HEX.getVbyList,
	_getVbyListEx = _ASN1HEX.getVbyListEx,
	_getChildIdx = _ASN1HEX.getChildIdx;

    /**
     * parse ASN.1 ContentInfo with SignedData<br/>
     * @name getCMSSignedData
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 ContentInfo with SignedData
     * @return {Array} array of JSON object of SignedData parameter
     * @see KJUR.asn1.cms.SignedData
     * @see KJUR.asn1.cms.CMSParser#getSignedData
     *
     * @description
     * This method parses ASN.1 ContentInfo with SignedData defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-3">section 3</a>
     * and 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5">section 5</a>.
     * The result parameter can be passed to
     * {@link KJUR.asn1.cms.SignedData} constructor.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getCMSSignedData("30...") &rarr;
     * {
     *   version: 1,
     *   hashalgs: ["sha1"],
     *   econtent: {
     *     type: "data",
     *     content: {hex:"616161"}
     *   },
     *   certs: [PEM1,...],
     *   sinfos: [{
     *     version: 1,
     *     id: {type:'isssn',issuer:{str:'/C=US/O=T1'},serial:{int: 1}},
     *     hashalg: "sha1",
     *     sattrs: {array: [{
     *       attr: "contentType",
     *       type: '1.2.840.113549.1.7.1'
     *     },{
     *       attr: "messageDigest",
     *       hex: 'abcd'
     *     }]},
     *     sigalg: "SHA1withRSA",
     *     sighex: "1234abcd..."
     *   }]
     * }
     */
    this.getCMSSignedData = function(h) {
	var hSignedData = _getTLVbyList(h, 0, [1, 0]);
	var pResult = this.getSignedData(hSignedData);
	return pResult;
    };

    /**
     * parse ASN.1 SignedData<br/>
     * @name getSignedData
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 SignedData
     * @return {Array} array of JSON object of SignedData parameter
     * @see KJUR.asn1.cms.SignedData
     * @see KJUR.asn1.cms.CMSParser#getSignedData
     *
     * @description
     * This method parses ASN.1 SignedData defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5">section 5</a>.
     * The result parameter can be passed to
     * {@link KJUR.asn1.cms.SignedData} constructor.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getSignedData("30...")
     */
    this.getSignedData = function(h) {
	var aIdx = _getChildIdx(h, 0);
	var pResult = {};

	var hVersion = _getV(h, aIdx[0]);
	var iVersion = parseInt(hVersion, 16);
	pResult.version = iVersion;
	
	var hHashAlgs = _getTLV(h, aIdx[1]);
	pResult.hashalgs = this.getHashAlgArray(hHashAlgs);

	var hEContent = _getTLV(h, aIdx[2]);
	pResult.econtent = this.getEContent(hEContent);

	var hCerts = _getTLVbyListEx(h, 0, ["[0]"]);
	if (hCerts != null) {
	    pResult.certs = this.getCertificateSet(hCerts);
	}

	// RevocationInfoChoices not supported yet
	var hRevInfos = _getTLVbyListEx(h, 0, ["[1]"]);
	if (hRevInfos != null) {
	}

	var hSignerInfos = _getTLVbyListEx(h, 0, [3]);
	pResult.sinfos = this.getSignerInfos(hSignerInfos);

	return pResult;
    };

    /**
     * parse ASN.1 DigestAlgorithmIdentifiers<br/>
     * @name getHashAlgArray
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 DigestAlgorithmIdentifiers
     * @return {Array} array of JSON object of digest algorithm names
     * @see KJUR.asn1.cms.SignedData
     * @see KJUR.asn1.cms.CMSParser#getSignedData
     *
     * @description
     * This method parses ASN.1 SignedData defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5.1</a>.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getHashAlgArray("30...") &rarr; ["sha256"]
     */
    this.getHashAlgArray = function(h) {
	var aIdx = _getChildIdx(h, 0);
	var x = new _X509();
	var a = [];
	for (var i = 0; i < aIdx.length; i++) {
	    var hAlg = _getTLV(h, aIdx[i]);
	    var sAlg = x.getAlgorithmIdentifierName(hAlg);
	    a.push(sAlg);
	}
	return a;
    };

    /**
     * parse ASN.1 EncapsulatedContentInfo<br/>
     * @name getEContent
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 EncapsulatedContentInfo
     * @return {Array} array of JSON object of EncapsulatedContentInfo parameter
     * @see KJUR.asn1.cms.EncapsulatedContentInfo
     * @see KJUR.asn1.cms.CMSParser#getSignedData
     *
     * @description
     * This method parses ASN.1 SignedData defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     * The result parameter can be passed to
     * {@link KJUR.asn1.cms.EncapsulatedContentInfo} constructor.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getEContent("30...") &rarr;
     * {type: "tstinfo", content: {hex: "30..."}}
     */
    this.getEContent = function(h) {
	var pResult = {};
	var hType = _getVbyList(h, 0, [0]);
	var hContent = _getVbyList(h, 0, [1, 0]);
	pResult.type = KJUR.asn1.x509.OID.oid2name(ASN1HEX.hextooidstr(hType));
	pResult.content = {hex: hContent};
	return pResult;
    };

    /**
     * parse ASN.1 SignerInfos<br/>
     * @name getSignerInfos
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 SignerInfos
     * @return {Array} array of JSON object of SignerInfos parameter
     * @see KJUR.asn1.cms.SignerInfos
     * @see KJUR.asn1.cms.CMSParser#getSignedData
     *
     * @description
     * This method parses ASN.1 SignerInfos defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getSignerInfos("30...") &rarr;
     * [{
     *   version: 1,
     *   id: {type: 'isssn', issuer: {str: '/C=US/O=T1'}, serial: {int: 1}},
     *   hashalg: "sha1",
     *   sattrs: {array: [{
     *     attr: "contentType",
     *     type: '1.2.840.113549.1.7.1'
     *   },{
     *     attr: "messageDigest",
     *     hex: 'a1a2a3a4a5a6a7a8a9a0a1a2a3a4a5a6a7a8a9a0'
     *   }]},
     *   sigalg: "SHA1withRSA",
     *   sighex: 'b1b2b...'
     * }]
     */
    this.getSignerInfos = function(h) {
	var aResult = [];

	var aIdx = _getChildIdx(h, 0);
	for (var i = 0; i < aIdx.length; i++) {
	    var hSignerInfo = _getTLV(h, aIdx[i]);
	    var pSignerInfo = this.getSignerInfo(hSignerInfo);
	    aResult.push(pSignerInfo);
	}

	return aResult;
    };

    /**
     * parse ASN.1 SignerInfo<br/>
     * @name getSignerInfo
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 SignerInfo
     * @return {Array} array of JSON object of SignerInfo parameter
     * @see KJUR.asn1.cms.SignerInfo
     * @see KJUR.asn1.cms.CMSParser#getSignedData
     *
     * @description
     * This method parses ASN.1 SignerInfos defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     * <pre>
     * SignerInfo ::= SEQUENCE {
     *    version CMSVersion,
     *    sid SignerIdentifier,
     *    digestAlgorithm DigestAlgorithmIdentifier,
     *    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
     *    signatureAlgorithm SignatureAlgorithmIdentifier,
     *    signature SignatureValue,
     *    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
     * </pre>
     * The result parameter can be passed to
     * {@link KJUR.asn1.cms.SignerInfo} constructor.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getSignerInfos("30...") &rarr;
     * [{
     *   version: 1,
     *   id: {type: 'isssn', issuer: {str: '/C=US/O=T1'}, serial: {int: 1}},
     *   hashalg: "sha1",
     *   sattrs: {array: [{
     *     attr: "contentType",
     *     type: '1.2.840.113549.1.7.1'
     *   },{
     *     attr: "messageDigest",
     *     hex: 'a1a2a3a4a5a6a7a8a9a0a1a2a3a4a5a6a7a8a9a0'
     *   }]},
     *   sigalg: "SHA1withRSA",
     *   sighex: 'b1b2b...'
     * }]
     */
    this.getSignerInfo = function(h) {
	var pResult = {};
	var aIdx = _getChildIdx(h, 0);

	var iVersion = _ASN1HEX.getInt(h, aIdx[0], -1);
	if (iVersion != -1) pResult.version = iVersion;

	var hSI = _getTLV(h, aIdx[1]);
	var pSI = this.getIssuerAndSerialNumber(hSI);
	pResult.id = pSI;

	var hAlg = _getTLV(h, aIdx[2]);
	//alert(hAlg);
	var sAlg = _x509obj.getAlgorithmIdentifierName(hAlg);
	pResult.hashalg = sAlg;

	var hSattrs = _getTLVbyListEx(h, 0, ["[0]"]);
	if (hSattrs != null) {
	    var aSattrs = this.getAttributeList(hSattrs);
	    pResult.sattrs = aSattrs;
	}

	var hSigAlg = _getTLVbyListEx(h, 0, [3]);
	var sSigAlg = _x509obj.getAlgorithmIdentifierName(hSigAlg);
	pResult.sigalg = sSigAlg;

	var hSigHex = _getVbyListEx(h, 0, [4]);
	pResult.sighex = hSigHex;

	var hUattrs = _getTLVbyListEx(h, 0, ["[1]"]);
	if (hUattrs != null) {
	    var aUattrs = this.getAttributeList(hUattrs);
	    pResult.uattrs = aUattrs;
	}

	return pResult;
    };

    /**
     * parse ASN.1 SignerIdentifier<br/>
     * @name getSignerIdentifier
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 SignerIdentifier
     * @return {Array} array of JSON object of SignerIdentifier parameter
     * @see KJUR.asn1.cms.SignerInfo
     * @see KJUR.asn1.cms.SignerIdentifier
     * @see KJUR.asn1.cms.CMSParser#getSignedData
     *
     * @description
     * This method parses ASN.1 SignerIdentifier defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getSignerIdentifier("30...") &rarr;
     * { type: "isssn",
     *   issuer: {
     *     array: [[{type:"C",value:"JP",ds:"prn"},...]]
     *     str: '/C=US/O=T1'
     *   },
     *   serial: {int: 1} }
     */
    this.getSignerIdentifier = function(h) {
	if (h.substr(0, 2) == "30") {
	    return this.getIssuerAndSerialNumber(h);
	} else {
	    throw new Error("SKID of signerIdentifier not supported");
	}
    };

    /**
     * parse ASN.1 IssuerAndSerialNumber<br/>
     * @name getIssuerAndSerialNumber
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 IssuerAndSerialNumber
     * @return {Array} array of JSON object of IssuerAndSerialNumber parameter
     * @see KJUR.asn1.cms.SignerInfo
     * @see KJUR.asn1.cms.CMSParser#getSignedData
     *
     * @description
     * This method parses ASN.1 IssuerAndSerialNumber defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getIssuerAndSerialNumber("30...") &rarr;
     * { type: "isssn",
     *   issuer: {
     *     array: [[{type:"C",value:"JP",ds:"prn"},...]]
     *     str: '/C=US/O=T1'
     *   },
     *   serial: {int: 1} }
     */
    this.getIssuerAndSerialNumber = function(h) {
	var pResult = {type: "isssn"};

	var aIdx = _getChildIdx(h, 0);

	var hName = _getTLV(h, aIdx[0]);
	pResult.issuer = _x509obj.getX500Name(hName);

	var hSerial = _getV(h, aIdx[1]);
	pResult.serial = {hex: hSerial};

	return pResult;
    };

    /**
     * parse ASN.1 SET OF Attributes<br/>
     * @name getAttributeList
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 SET OF Attribute
     * @return {Array} array of JSON object of Attribute parameter
     * @see KJUR.asn1.cms.SignerInfo
     * @see KJUR.asn1.cms.CMSParser#getAttribute
     *
     * @description
     * This method parses ASN.1 SET OF Attribute defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     * This can be used for SignedAttributes and UnsignedAttributes.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getAttributeList("30...") &rarr;
     * [{attr: "contentType", type: "tstinfo"},
     *  {attr: "messageDigest", hex: "1234abcd..."}]
     */
    this.getAttributeList = function(h) {
	var a = [];

	var aIdx = _getChildIdx(h, 0);
	for (var i = 0; i < aIdx.length; i++) {
	    var hAttr = _getTLV(h, aIdx[i]);
	    var pAttr = this.getAttribute(hAttr);
	    a.push(pAttr);
	}

	return {array: a};
    };

    /**
     * parse ASN.1 Attributes<br/>
     * @name getAttribute
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 Attribute
     * @return {Array} array of JSON object of Attribute parameter
     * @see KJUR.asn1.cms.SignerInfo
     * @see KJUR.asn1.cms.CMSParser#getAttributeList
     *
     * @description
     * This method parses ASN.1 Attribute defined in 
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     * Following attribute type are supported in the
     * latest version:
     * <ul>
     * <li>contentType - {@link KJUR.asn1.cms.CMSParser.setContentType}</li>
     * <li>messageDigest - {@link KJUR.asn1.cms.CMSParser.setMessageDigest}</li>
     * <li>signingTime - {@link KJUR.asn1.cms.CMSParser.setSigningTime}</li>
     * <li>signingCertificate - {@link KJUR.asn1.cms.CMSParser.setSigningCertificate}</li>
     * <li>signingCertificateV2 - {@link KJUR.asn1.cms.CMSParser.setSigningCertificateV2}</li>
     * </ul>
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getAttribute("30...") &rarr;
     * {attr: "contentType", type: "tstinfo"}
     */
    this.getAttribute = function(h) {
	var pResult = {};
	var aIdx = _getChildIdx(h, 0);

	var attrTypeOID = _ASN1HEX.getOID(h, aIdx[0]);
	var attrType = KJUR.asn1.x509.OID.oid2name(attrTypeOID);
	pResult.attr = attrType;

	var hSet = _getTLV(h, aIdx[1]);
	var aSetIdx = _getChildIdx(hSet, 0);
	if (aSetIdx.length == 1) {
	    pResult.valhex = _getTLV(hSet, aSetIdx[0]);
	} else {
	    var a = [];
	    for (var i = 0; i < aSetIdx.length; i++) {
		a.push(_getTLV(hSet, aSetIdx[i]));
	    }
	    pResult.valhex = a;
	}

	if (attrType == "contentType") {
	    this.setContentType(pResult);
	} else if (attrType == "messageDigest") {
	    this.setMessageDigest(pResult);
	} else if (attrType == "signingTime") {
	    this.setSigningTime(pResult);
	} else if (attrType == "signingCertificate") {
	    this.setSigningCertificate(pResult);
	} else if (attrType == "signingCertificateV2") {
	    this.setSigningCertificateV2(pResult);
	} else if (attrType == "signaturePolicyIdentifier") {
	    this.setSignaturePolicyIdentifier(pResult);
	}

	return pResult;
    };

    /**
     * set ContentType attribute<br/>
     * @name setContentType
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {Array} pAttr JSON object of attribute parameter
     * @see KJUR.asn1.cms.CMSParser#getAttribute
     *
     * @description
     * This sets an attribute as ContentType defined in
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     *
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * pAttr = {
     *   attr: "contentType"
     *   valhex: '060b2a864886f70d0109100104'
     * };
     * parser.setContentInfo(pAttr);
     * pAttr &rarr; {
     *   attr: "contentType"
     *   type: "tstinfo"
     * }
     */
    this.setContentType = function(pAttr) {
	var contentType = _ASN1HEX.getOIDName(pAttr.valhex, 0, null);
	if (contentType != null) {
	    pAttr.type = contentType;
	    delete pAttr.valhex;
	}
    };

    /**
     * set SigningTime attribute<br/>
     * @name setSigningTime
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {Array} pAttr JSON object of attribute parameter
     * @see KJUR.asn1.cms.CMSParser#getAttribute
     *
     * @description
     * This sets an attribute as SigningTime defined in
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     *
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * pAttr = {
     *   attr: "signingTime"
     *   valhex: '170d3230313233313233353935395a'
     * };
     * parser.setSigningTime(pAttr);
     * pAttr &rarr; {
     *   attr: "signingTime",
     *   str: "2012315959Z"
     * }
     */
    this.setSigningTime = function(pAttr) {
	var hSigningTime = _getV(pAttr.valhex, 0);
	var signingTime = hextoutf8(hSigningTime);
	pAttr.str = signingTime;
	delete pAttr.valhex;
    };

    /**
     * set MessageDigest attribute<br/>
     * @name setMessageDigest
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {Array} pAttr JSON object of attribute parameter
     * @see KJUR.asn1.cms.CMSParser#getAttribute
     *
     * @description
     * This sets an attribute as SigningTime defined in
     * RFC 5652 
     * <a href="https://tools.ietf.org/html/rfc5652#section-5.1">
     * section 5</a>.
     *
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * pAttr = {
     *   attr: "messageDigest"
     *   valhex: '0403123456'
     * };
     * parser.setMessageDigest(pAttr);
     * pAttr &rarr; {
     *   attr: "messageDigest",
     *   hex: "123456"
     * }
     */
    this.setMessageDigest = function(pAttr) {
	var hMD = _getV(pAttr.valhex, 0);
	pAttr.hex = hMD;
	delete pAttr.valhex;
    };

    /**
     * set SigningCertificate attribute<br/>
     * @name setSigningCertificate
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {Array} pAttr JSON object of attribute parameter
     * @see KJUR.asn1.cms.CMSParser#getAttribute
     *
     * @description
     * This sets an attribute as SigningCertificate defined in
     * <a href="https://tools.ietf.org/html/rfc5035#section-5">
     * RFC 5035 section 5</a>.
     *
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * pAttr = {
     *   attr: "signingCertificate"
     *   valhex: '...'
     * };
     * parser.setSigningCertificate(pAttr);
     * pAttr &rarr; {
     *   attr: "signingCertificate",
     *   array: [{
     *     hash: "123456...",
     *     issuer: {
     *       array: [[{type:"C",value:"JP",ds:"prn"},...]],
     *       str: "/C=JP/O=T1"
     *     },
     *     serial: {hex: "123456..."}
     *   }]
     * }
     */
    this.setSigningCertificate = function(pAttr) {
	var aIdx = _getChildIdx(pAttr.valhex, 0);
	if (aIdx.length > 0) {
	    var hCerts = _getTLV(pAttr.valhex, aIdx[0]);
	    var aCertIdx = _getChildIdx(hCerts, 0);
	    var a = [];
	    for (var i = 0; i < aCertIdx.length; i++) {
		var hESSCertID = _getTLV(hCerts, aCertIdx[i]);
		var pESSCertID = this.getESSCertID(hESSCertID);
		a.push(pESSCertID);
	    }
	    pAttr.array = a;
	}

	if (aIdx.length > 1) {
	    var hPolicies = _getTLV(pAttr.valhex, aIdx[1]);
	    pAttr.polhex = hPolicies;
	}
	delete pAttr.valhex;
    };

    /**
     * set SignaturePolicyIdentifier attribute<br/>
     * @name setSignaturePolicyIdentifier
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {Array} pAttr JSON object of attribute parameter
     * @since jsrsasign 10.1.5 asn1cms 2.0.4
     * @see KJUR.asn1.cms.CMSParser#getAttribute
     * @see KJUR.asn1.cades.SignaturePolicyIdentifier
     *
     * @description
     * This sets an attribute as SignaturePolicyIdentifier defined in
     * <a href="https://tools.ietf.org/html/rfc5126#section-5.8.1">
     * RFC 5126 CAdES section 5.8.1</a>.
     *
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * pAttr = {
     *   attr: "signaturePolicyIdentifier"
     *   valhex: '...'
     * };
     * parser.setSignaturePolicyIdentifier(pAttr);
     * pAttr &rarr; {
     *   attr: "signaturePolicyIdentifier",
     *   oid: "1.2.3.4.5",
     *   alg: "sha1",
     *   hash: "1a2b..."
     * }
     */
    this.setSignaturePolicyIdentifier = function(pAttr) {
	var aIdx = _getChildIdx(pAttr.valhex, 0);
	if (aIdx.length > 0) {
	    var oid = _ASN1HEX.getOID(pAttr.valhex, aIdx[0]);
	    pAttr.oid = oid;
	}
	if (aIdx.length > 1) {
	    var x = new _X509();
	    var a2Idx = _getChildIdx(pAttr.valhex, aIdx[1]);
	    var hAlg = _getTLV(pAttr.valhex, a2Idx[0]);
	    var sAlg = x.getAlgorithmIdentifierName(hAlg);
	    pAttr.alg = sAlg;

	    var hHash = _getV(pAttr.valhex, a2Idx[1]);
	    pAttr.hash = hHash;
	}
	delete pAttr.valhex;
    };

    /**
     * set SigningCertificateV2 attribute<br/>
     * @name setSigningCertificateV2
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {Array} pAttr JSON object of attribute parameter
     * @since jsrsasign 10.1.2 asn1cms 2.0.3
     * @see KJUR.asn1.cms.CMSParser#getAttribute
     * @see KJUR.asn1.cms.CMSParser#getESSCertIDv2
     * @see KJUR.asn1.cms.SigningCertificateV2
     * @see KJUR.asn1.cms.ESSCertIDv2
     *
     * @description
     * This sets an attribute as SigningCertificateV2 defined in
     * <a href="https://tools.ietf.org/html/rfc5035#section-3">
     * RFC 5035 section 3</a>.
     *
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * pAttr = {
     *   attr: "signingCertificateV2"
     *   valhex: '...'
     * };
     * parser.setSigningCertificateV2(pAttr);
     * pAttr &rarr; {
     *   attr: "signingCertificateV2",
     *   array: [{
     *     hash: "123456...",
     *     alg: "sha256",
     *     issuer: {
     *       array: [[{type:"C",value:"JP",ds:"prn"},...]],
     *       str: "/C=JP/O=T1"
     *     },
     *     serial: {hex: "123456..."}
     *   }]
     * }
     */
    this.setSigningCertificateV2 = function(pAttr) {
	var aIdx = _getChildIdx(pAttr.valhex, 0);
	if (aIdx.length > 0) {
	    var hCerts = _getTLV(pAttr.valhex, aIdx[0]);
	    var aCertIdx = _getChildIdx(hCerts, 0);
	    var a = [];
	    for (var i = 0; i < aCertIdx.length; i++) {
		var hESSCertIDv2 = _getTLV(hCerts, aCertIdx[i]);
		var pESSCertIDv2 = this.getESSCertIDv2(hESSCertIDv2);
		a.push(pESSCertIDv2);
	    }
	    pAttr.array = a;
	}

	if (aIdx.length > 1) {
	    var hPolicies = _getTLV(pAttr.valhex, aIdx[1]);
	    pAttr.polhex = hPolicies;
	}
	delete pAttr.valhex;
    };

    /**
     * parse ASN.1 ESSCertID<br/>
     * @name getESSCertID
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 ESSCertID
     * @return {Array} array of JSON object of ESSCertID parameter
     * @see KJUR.asn1.cms.ESSCertID
     *
     * @description
     * This method parses ASN.1 ESSCertID defined in 
     * <a href="https://tools.ietf.org/html/rfc5035#section-6">
     * RFC 5035 section 6</a>.
     * <pre>
     * ESSCertID ::= SEQUENCE {
     *    certHash Hash,
     *    issuerSerial IssuerSerial OPTIONAL }
     * IssuerSerial ::= SEQUENCE {
     *    issuer GeneralNames,
     *    serialNumber CertificateSerialNumber }
     * </pre>
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getESSCertID("30...") &rarr;
     * { hash: "12ab...",
     *   issuer: {
     *     array: [[{type:"C",value:"JP",ds:"prn"}],...],
     *     str: "/C=JP/O=T1"
     *   },
     *   serial: {hex: "12ab..."} }
     */
    this.getESSCertID = function(h) {
	var pResult = {};
	var aIdx = _getChildIdx(h, 0);

	if (aIdx.length > 0) {
	    var hCertHash = _getV(h, aIdx[0]);
	    pResult.hash = hCertHash;
	}

	if (aIdx.length > 1) {
	    var hIssuerSerial = _getTLV(h, aIdx[1]);
	    var pIssuerSerial = 
		this.getIssuerSerial(hIssuerSerial);

	    if (pIssuerSerial.serial != undefined)
		pResult.serial = pIssuerSerial.serial;

	    if (pIssuerSerial.issuer != undefined)
		pResult.issuer = pIssuerSerial.issuer;
	}

	return pResult;
    };

    /**
     * parse ASN.1 ESSCertIDv2<br/>
     * @name getESSCertIDv2
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 ESSCertIDv2
     * @return {Array} array of JSON object of ESSCertIDv2 parameter
     * @since jsrsasign 10.1.2 asn1cms 2.0.3
     * @see KJUR.asn1.cms.ESSCertIDv2
     * @see KJUR.asn1.cms.CMSParser.getESSCertID
     *
     * @description
     * This method parses ASN.1 ESSCertIDv2 defined in 
     * <a href="https://tools.ietf.org/html/rfc5035#section-4">
     * RFC 5035 section 4</a>.
     * <pre>
     * ESSCertIDv2 ::=  SEQUENCE {
     *    hashAlgorithm           AlgorithmIdentifier
     *                            DEFAULT {algorithm id-sha256},
     *    certHash                Hash,
     *    issuerSerial            IssuerSerial OPTIONAL }
     * Hash ::= OCTET STRING
     * IssuerSerial ::= SEQUENCE {
     *    issuer                  GeneralNames,
     *    serialNumber            CertificateSerialNumber }
     * </pre>
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getESSCertID("30...") &rarr;
     * {
     *   hash: "3f2d...",
     *   alg: "sha512",
     *   issuer: {str: "/C=JP/O=T1"},
     *   serial: {hex: "12ab..."}
     * }
     */
    this.getESSCertIDv2 = function(h) {
	var aResult = {};
	var aIdx = _getChildIdx(h, 0); 

	if (aIdx.length < 1 || 3 < aIdx.length)
	    throw new _Error("wrong number of elements");

	var offset = 0;
	if (h.substr(aIdx[0], 2) == "30") {
	    var hHashAlg = _getTLV(h, aIdx[0]);
	    aResult.alg = 
		_x509obj.getAlgorithmIdentifierName(hHashAlg);
	    offset++;
	} else {
	    aResult.alg = "sha256";
	}

	var hHash = _getV(h, aIdx[offset]);
	aResult.hash = hHash;

	if (aIdx.length > offset + 1) {
	    var hIssuerSerial = _getTLV(h, aIdx[offset + 1]);
	    var pIssuerSerial = 
		this.getIssuerSerial(hIssuerSerial);
	    aResult.issuer = pIssuerSerial.issuer;
	    aResult.serial = pIssuerSerial.serial;
	}

	return aResult;
    };

    /**
     * parse ASN.1 IssuerSerial<br/>
     * @name getIssuerSerial
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 IssuerSerial
     * @return {Array} array of JSON object of IssuerSerial parameter
     * @see KJUR.asn1.cms.IssuerSerial
     * @see KJUR.asn1.x509.X500Name
     *
     * @description
     * This method parses ASN.1 IssuerSerial defined in 
     * <a href="https://tools.ietf.org/html/rfc5035#section-6">
     * RFC 5035 section 6</a>.
     * <pre>
     * IssuerSerial ::= SEQUENCE {
     *    issuer GeneralNames,
     *    serialNumber CertificateSerialNumber }
     * </pre>
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getIssuerSerial("30...") &rarr;
     * { issuer: {
     *     array: [[{type:"C",value:"JP",ds:"prn"}],...],
     *     str: "/C=JP/O=T1",
     *   },
     *   serial: {hex: "12ab..."} }
     */
    this.getIssuerSerial = function(h) {
	var pResult = {};
	var aIdx = _getChildIdx(h, 0);

	var hIssuer = _getTLV(h, aIdx[0]);
	var pIssuerGN = _x509obj.getGeneralNames(hIssuer);
	var pIssuerName = pIssuerGN[0].dn;
	pResult.issuer = pIssuerName;

	var hSerial = _getV(h, aIdx[1]);
	pResult.serial = {hex: hSerial};

	return pResult;
    };

    /**
     * parse ASN.1 CertificateSet<br/>
     * @name getCertificateSet
     * @memberOf KJUR.asn1.cms.CMSParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 CertificateSet
     * @return {Array} array of JSON object of CertificateSet parameter
     * @see KJUR.asn1.cms.CertificateSet
     *
     * @description
     * This method parses ASN.1 IssuerSerial defined in 
     * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.3">
     * RFC 5652 CMS section 10.2.3</a> and 
     * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.2">
     * section 10.2.2</a>.
     * <pre>
     * CertificateSet ::= SET OF CertificateChoices
     * CertificateChoices ::= CHOICE {
     *   certificate Certificate,
     *   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
     *   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
     *   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
     *   other [3] IMPLICIT OtherCertificateFormat }
     * OtherCertificateFormat ::= SEQUENCE {
     *   otherCertFormat OBJECT IDENTIFIER,
     *   otherCert ANY DEFINED BY otherCertFormat }
     * </pre>
     * Currently only "certificate" is supported in
     * CertificateChoices.
     * 
     * @example
     * parser = new KJUR.asn1.cms.CMSParser();
     * parser.getCertificateSet("a0...") &rarr;
     * [ "-----BEGIN CERTIFICATE...", ... ]
     */
    this.getCertificateSet = function(h) {
	var aIdx = _getChildIdx(h, 0);
	var  a = [];
	for (var i = 0; i < aIdx.length; i++) {
	    var hCert = _getTLV(h, aIdx[i]);
	    if (hCert.substr(0, 2) == "30") {
		var pem = hextopem(hCert, "CERTIFICATE");
		a.push(pem);
	    }
	}
	return {array: a, sortflag: false};
    };
};
