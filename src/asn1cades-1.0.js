/* asn1cades-2.0.2.js (c) 2014-2022 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * asn1cades.js - ASN.1 DER encoder classes for RFC 5126 CAdES long term signature
 *
 * Copyright (c) 2014-2022 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1cades-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.16 asn1cades 2.0.2 (2022-Apr-08)
 * @since jsrsasign 4.7.0
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
 * kjur's ASN.1 class for RFC 5126 CAdES long term signature
 * <p>
 * This name space provides 
 * <a href="https://tools.ietf.org/html/rfc5126">RFC 5126
 * CAdES(CMS Advanced Electronic Signature)</a> generator.
 *
 * <h4>SUPPORTED FORMATS</h4>
 * Following CAdES formats is supported by this library.
 * <ul>
 * <li>CAdES-BES - CAdES Basic Electronic Signature</li>
 * <li>CAdES-EPES - CAdES Explicit Policy-based Electronic Signature</li>
 * <li>CAdES-T - Electronic Signature with Time</li>
 * </ul>
 * </p>
 *
 * <h4>PROVIDED ATTRIBUTE CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.cades.SignaturePolicyIdentifier} - for CAdES-EPES
 *   <ul>
 *   <li>{@link KJUR.asn1.cades.SignaturePolicyId}</li>
 *   </ul>
 * </li>
 * <li>{@link KJUR.asn1.cades.SignatureTimeStamp} - for CAdES-T</li>
 * <li>{@link KJUR.asn1.cades.CompleteCertificateRefs} - for CAdES-C(for future use)
 *   <ul>
 *   <li>{@link KJUR.asn1.cades.OtherCertID}</li>
 *   <li>{@link KJUR.asn1.cades.OtherHash}</li>
 *   <li>{@link KJUR.asn1.cades.OtherHashAlgAndValue}</li>
 *   <li>{@link KJUR.asn1.cades.OtherHashValue}</li>
 *   </ul>
 * </li>
 * </ul>
 * NOTE: Currntly CAdES-C is not supported since parser can't
 * handle unsigned attribute.
 * 
 * <h4>OTHER CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.cades.CAdESUtil} - utilities for CAdES</li>
 * </ul>
 *
 * <h4>GENERATE CAdES-BES</h4>
 * To generate CAdES-BES, {@link KJUR.asn.cades} namespace 
 * classes are not required and already {@link KJUR.asn.cms} namespace 
 * provides attributes for CAdES-BES.
 * Create {@link KJUR.asn1.cms.SignedData} with following
 * mandatory attribute in CAdES-BES:
 * <ul>
 * <li>{@link KJUR.asn1.cms.ContentType}</li>
 * <li>{@link KJUR.asn1.cms.MessageDigest}</li>
 * <li>{@link KJUR.asn1.cms.SigningCertificate} or </li>
 * <li>{@link KJUR.asn1.cms.SigningCertificateV2}</li>
 * </ul>
 * CMSUtil.newSignedData method is very useful to generate CAdES-BES.
 * <pre>
 * sd = KJUR.asn1.cms.CMSUtil.newSignedData({
 *   content: {str: "aaa"},
 *   certs: [certPEM],
 *   signerInfos: [{
 *     hashAlg: 'sha256',
 *     sAttr: {SigningCertificateV2: {array: [certPEM]}},
 *     signerCert: certPEM,
 *     sigAlg: 'SHA256withRSA',
 *     signerPrvKey: pkcs8PrvKeyPEM
 *   }]
 * });
 * signedDataHex = sd.getContentInfoEncodedHex();
 * </pre>
 * NOTE: ContentType and MessageDigest signed attributes
 * are automatically added by default.
 *
 * <h4>GENERATE CAdES-BES with multiple signers</h4>
 * If you need signature by multiple signers, you can 
 * specify one or more items in 'signerInfos' property as below.
 * <pre>
 * sd = KJUR.asn1.cms.CMSUtil.newSignedData({
 *   content: {str: "aaa"},
 *   certs: [certPEM1, certPEM2],
 *   signerInfos: [{
 *     hashAlg: 'sha256',
 *     sAttr: {SigningCertificateV2: {array: [certPEM1]}},
 *     signerCert: certPEM1,
 *     sigAlg: 'SHA256withRSA',
 *     signerPrvKey: pkcs8PrvKeyPEM1
 *   },{
 *     hashAlg: 'sha1',
 *     sAttr: {SigningCertificateV2: {array: [certPEM2]}},
 *     signerCert: certPEM2,
 *     sigAlg: 'SHA1withRSA',
 *     signerPrvKey: pkcs8PrvKeyPEM2
 *   }]
 * });
 * signedDataHex = sd.getContentInfoEncodedHex();
 * </pre>
 *
 * <h4>GENERATE CAdES-EPES</h4>
 * When you need a CAdES-EPES signature,
 * you just need to add 'SignaturePolicyIdentifier'
 * attribute as below.
 * <pre>
 * sd = KJUR.asn1.cms.CMSUtil.newSignedData({
 *   content: {str: "aaa"},
 *   certs: [certPEM],
 *   signerInfos: [{
 *     hashAlg: 'sha256',
 *     sAttr: {
 *       SigningCertificateV2: {array: [certPEM]},
 *       SignaturePolicyIdentifier: {
 *         oid: '1.2.3.4.5',
 *         hash: {alg: 'sha1', hash: 'b1b2b3b4b...'}
 *       },
 *     },
 *     signerCert: certPEM,
 *     sigAlg: 'SHA256withRSA',
 *     signerPrvKey: pkcs8PrvKeyPEM
 *   }]
 * });
 * signedDataHex = sd.getContentInfoEncodedHex();
 * </pre>
 *
 * <h4>GENERATE CAdES-T</h4>
 * After a signed CAdES-BES or CAdES-EPES signature have been generated,
 * you can generate CAdES-T by adding SigningTimeStamp unsigned attribute.
 * <pre>
 * beshex = "30..."; // hex of CAdES-BES or EPES data 
 * info = KJUR.asn1.cades.CAdESUtil.parseSignedDataForAddingUnsigned(beshex);
 * // You can refer a hexadecimal string of signature value 
 * // in the first signerInfo in the CAdES-BES/EPES with a variable:
 * // 'info.si[0].sigval'. You need to get RFC 3161 TimeStampToken
 * // from a trusted time stamp authority. Otherwise you can also 
 * // get it by 'KJUR.asn1.tsp' module. We suppose that we could 
 * // get proper time stamp.
 * tsthex0 = "30..."; // hex of TimeStampToken for signerInfo[0] sigval
 * si0 = info.obj.signerInfoList[0];
 * si0.addUnsigned(new KJUR.asn1.cades.SignatureTimeStamp({tst: tsthex0});
 * esthex = info.obj.getContentInfoEncodedHex(); // CAdES-T
 * </pre>
 * </p>
 *
 * <h4>SAMPLE CODES</h4>
 * <ul>
 * <li><a href="../../tool_cades.html">demo program for CAdES-BES/EPES/T generation</a></li>
 * <li><a href="../../test/qunit-do-asn1cades.html">Unit test code for KJUR.asn1.cades package</a></li>
 * <li><a href="../../test/qunit-do-asn1tsp.html">Unit test code for KJUR.asn1.tsp package (See SimpleTSAAdaptor test)</a></li>
 * <li><a href="../../test/qunit-do-asn1cms.html">Unit test code for KJUR.asn1.cms package (See newSignedData test)</a></li>
 * </ul>
 * 
 * @name KJUR.asn1.cades
 * @namespace
 */
if (typeof KJUR.asn1.cades == "undefined" || !KJUR.asn1.cades) KJUR.asn1.cades = {};

/**
 * class for RFC 5126 CAdES SignaturePolicyIdentifier attribute
 * @name KJUR.asn1.cades.SignaturePolicyIdentifier
 * @class class for RFC 5126 CAdES SignaturePolicyIdentifier attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 * @see KJUR.asn1.cms.AttributeList
 * @see KJUR.asn1.cms.CMSParser#setSignaturePolicyIdentifier
 * @see KJUR.asn1.cades.SignaturePolicyId
 * @see KJUR.asn1.cades.OtherHashAlgAndValue
 *
 * @description
 * This class provides ASN.1 encoder for
 * <a href="https://tools.ietf.org/html/rfc5126#section-5.8.1">
 * SignaturePolicyIdentifier defined in RFC 5126 CAdES section 5.8.1</a>.
 * <pre>
 * SignaturePolicyIdentifier ::= CHOICE {
 *    signaturePolicyId       SignaturePolicyId,
 *    signaturePolicyImplied  SignaturePolicyImplied } -- not used
 *
 * SignaturePolicyImplied ::= NULL
 * SignaturePolicyId ::= SEQUENCE {
 *    sigPolicyId           SigPolicyId,
 *    sigPolicyHash         SigPolicyHash,
 *    sigPolicyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                             SigPolicyQualifierInfo OPTIONAL }
 * SigPolicyId ::= OBJECT IDENTIFIER
 * SigPolicyHash ::= OtherHashAlgAndValue
 * </pre>
 *
 * @example
 * new KJUR.asn1.cades.SignaturePolicyIdentifier({
 *   attr: "signaturePolicyIdentifier",
 *   oid: '1.2.3.4.5',
 *   alg: 'sha1',
 *   hash: 'a1a2a3a4...'
 * })
 */
KJUR.asn1.cades.SignaturePolicyIdentifier = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_cades = _KJUR_asn1.cades,
	_SignaturePolicyId = _KJUR_asn1_cades.SignaturePolicyId;
	
    _KJUR_asn1_cades.SignaturePolicyIdentifier.superclass.constructor.call(this);

    this.typeOid = "1.2.840.113549.1.9.16.2.15";

    this.params = null;

    this.getValueArray = function() {
	return [new _SignaturePolicyId(this.params)];
    };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cades.SignaturePolicyIdentifier,
                  KJUR.asn1.cms.Attribute);

/**
 * RFC 5126 CAdES SignaturePolicyId ASN.1 structure class<br/>
 * @name KJUR.asn1.cades.SignaturePolicyId
 * @class RFC 5126 CAdES SignaturePolicyId ASN.1 structure class
 * @param {Array} params JSON object of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cades 2.0.0
 * @see KJUR.asn1.cades.SignaturePolicyIdentifier
 * @see KJUR.asn1.cades.OtherHashAlgAndValue
 *
 * @description
 * This class provides ASN.1 encoder for
 * <a href="https://tools.ietf.org/html/rfc5126#section-5.8.1">
 * SignaturePolicyId defined in RFC 5126 CAdES section 5.8.1</a>.
 * <pre>
 * SignaturePolicyId ::= SEQUENCE {
 *    sigPolicyId           SigPolicyId,
 *    sigPolicyHash         SigPolicyHash,
 *    sigPolicyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                             SigPolicyQualifierInfo OPTIONAL }
 * SigPolicyId ::= OBJECT IDENTIFIER
 * SigPolicyHash ::= OtherHashAlgAndValue
 * OtherHashAlgAndValue ::= SEQUENCE {
 *    hashAlgorithm   AlgorithmIdentifier,
 *    hashValue       OtherHashValue }
 * OtherHashValue ::= OCTET STRING
 * </pre>
 * Following properties can be apply to constructor arguments 
 * adding to {@link KJUR.asn1.cades.OtherHashAlgAndValue} constructor:
 * <ul>
 * <li>{String} oid - signature policy OID string or name (ex. 1.2.3.4)</li>
 * </ul>
 * 
 * @example
 * new KJUR.asn1.cades.SignaturePolicyId({
 *   oid: "1.2.3.4.5",
 *   alg: "sha256",
 *   hash: "1234abcd..."
 * });
 */
KJUR.asn1.cades.SignaturePolicyId = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier,
	_KJUR_asn1_cades = _KJUR_asn1.cades,
	_SignaturePolicyId = _KJUR_asn1_cades.SignaturePolicyId,
	_OtherHashAlgAndValue = _KJUR_asn1_cades.OtherHashAlgAndValue;

    _SignaturePolicyId.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var a = [];
	a.push(new _DERObjectIdentifier(params.oid));
	a.push(new _OtherHashAlgAndValue(params));
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.setByParam = function(params) {
	this.params = params;
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cades.SignaturePolicyId, KJUR.asn1.ASN1Object);

/**
 * class for OtherHashAlgAndValue ASN.1 object<br/>
 * @name KJUR.asn1.cades.OtherHashAlgAndValue
 * @class class for OtherHashAlgAndValue ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 *
 * @description
 * This class provides ASN.1 encoder for
 * <a href="https://tools.ietf.org/html/rfc5126#section-5.8.1">
 * OtherHashAlgAndValue defined in RFC 5126 CAdES section 5.8.1</a>.
 * <pre>
 * OtherHashAlgAndValue ::= SEQUENCE {
 *    hashAlgorithm   AlgorithmIdentifier,
 *    hashValue       OtherHashValue }
 * OtherHashValue ::= OCTET STRING
 * </pre>
 * Following properties can be apply to constructor arguments:
 * <ul>
 * <li>{String} alg - hash algorithm name for "hashAlgorithm" field</li>
 * <li>{String} hash - hexadecimal string for "hashValue" field</li>
 * </ul>
 * 
 * @example
 * // specify by hash
 * new KJUR.asn1.cades.OtherHashAlgAndValue({
 *   alg: "sha256",
 *   hash: "12abcd..."
 * })
 *
 * // or specify by cert PEM or hex
 * new KJUR.asn1.cades.OtherHashAlgAndValue({
 *   alg: "sha256",
 *   cert: "-----BEGIN..."
 * })
 * new KJUR.asn1.cades.OtherHashAlgAndValue({
 *   alg: "sha256",
 *   cert: "3082..."
 * })
 */
KJUR.asn1.cades.OtherHashAlgAndValue = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier,
	_KJUR_asn1_cades = _KJUR_asn1.cades,
	_OtherHashAlgAndValue = _KJUR_asn1_cades.OtherHashAlgAndValue;

    _OtherHashAlgAndValue.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	if (params.alg == undefined)
	    throw new _Error("property 'alg' not specified");

	if (params.hash == undefined && params.cert == undefined)
	    throw new _Error("property 'hash' nor 'cert' not specified");

	var hHash = null;
	if (params.hash != undefined) {
	    hHash = params.hash;
	} else if (params.cert != undefined) {
	    if (typeof params.cert != "string")
		throw new _Error("cert not string");

	    var hCert = params.cert;
	    if (params.cert.indexOf("-----BEGIN") != -1) {
		hCert = pemtohex(params.cert);
	    }
	    hHash = KJUR.crypto.Util.hashHex(hCert, params.alg);
	}

	var a = [];
	a.push(new _AlgorithmIdentifier({name: params.alg}));
	a.push(new _DEROctetString({hex: hHash}));
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cades.OtherHashAlgAndValue, KJUR.asn1.ASN1Object);

/**
 * class for OtherHashValue ASN.1 object<br/>
 * @name KJUR.asn1.cades.OtherHashValue
 * @class class for OtherHashValue ASN.1 object
 * @param {Array} params JSON object of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 10.0.0 asn1cades 2.0.0
 *
 * This class provides ASN.1 encoder for
 * <a href="https://tools.ietf.org/html/rfc5126#section-5.8.1">
 * OtherHashAlgAndValue defined in RFC 5126 CAdES section 5.8.1</a>.
 * <pre>
 * OtherHashValue ::= OCTET STRING
 * </pre>
 *
 * @example
 * new KJUR.asn1.cades.OtherHashValue({hash: "12ab..."})
 * new KJUR.asn1.cades.OtherHashValue({cert: "-----BEGIN..."})
 * new KJUR.asn1.cades.OtherHashValue({cert: "3081..."})
 */
KJUR.asn1.cades.OtherHashValue = function(params) {
    KJUR.asn1.cades.OtherHashValue.superclass.constructor.call(this);

    var _Error = Error,
	_KJUR = KJUR,
	_isHex = _KJUR.lang.String.isHex,
	_KJUR_asn1 = _KJUR.asn1,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_hashHex = _KJUR.crypto.Util.hashHex;
    
    this.params = null;

    this.tohex = function() {
	var params = this.params;

	if (params.hash == undefined && params.cert == undefined) {
	    throw new _Error("hash or cert not specified");
	}

	var hHash = null;
	if (params.hash != undefined) {
	    hHash = params.hash;
	} else if (params.cert != undefined) {
	    if (typeof params.cert != "string") {
		throw new _Error("cert not string");
	    }
	    var hCert = params.cert;
	    if (params.cert.indexOf("-----BEGIN") != -1) {
		hCert = pemtohex(params.cert);
	    }
	    hHash = KJUR.crypto.Util.hashHex(hCert, "sha1");
	}
	return (new _DEROctetString({hex: hHash})).tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cades.OtherHashValue, KJUR.asn1.ASN1Object);

/**
 * class for RFC 5126 CAdES SignatureTimeStamp attribute<br/>
 * @name KJUR.asn1.cades.SignatureTimeStamp
 * @class class for RFC 5126 CAdES SignatureTimeStamp attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 * @description
 * <pre>
 * id-aa-signatureTimeStampToken OBJECT IDENTIFIER ::=
 *    1.2.840.113549.1.9.16.2.14
 * SignatureTimeStampToken ::= TimeStampToken
 * </pre>
 *
 * @example
 * // by TimeStampToken hex
 * new KJUR.asn1.cades.SignatureTimeStamp({
 *   attr: "timeStampToken",
 *   tst: "3082..."})
 *
 * // by TimeStampToken or ASN1Object
 * new KJUR.asn1.cades.SignatureTimeStamp({
 *   attr: "timeStampToken",
 *   tst: new TimeStampToken(...)})
 *
 * // by TimeStampResponse hex
 * new KJUR.asn1.cades.SignatureTimeStamp({
 *   attr: "timeStampToken",
 *   res: "3082..."})
 *
 * // by TimeStampToken or ASN1Object
 * new KJUR.asn1.cades.SignatureTimeStamp({
 *   attr: "timeStampToken",
 *   res: new TimeStampResponse(...)})
 */
KJUR.asn1.cades.SignatureTimeStamp = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_isHex = _KJUR.lang.String.isHex,
	_KJUR_asn1 = _KJUR.asn1,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_KJUR_asn1_cades = _KJUR_asn1.cades;

    _KJUR_asn1_cades.SignatureTimeStamp.superclass.constructor.call(this);
    this.typeOid = "1.2.840.113549.1.9.16.2.14";
    this.params = null;

    this.getValueArray = function() {
	var params = this.params;

	if (params.tst != undefined) {
	    if (_isHex(params.tst)) {
		var dTST = new _ASN1Object();
		dTST.hTLV = params.tst;
		return [dTST];
	    } else if (params.tst instanceof _ASN1Object) {
		return [params.tst];
	    } else {
		throw new _Error("params.tst has wrong value");
	    }
	} else if (params.res != undefined) {
	    var hRes = params.res;
	    if (hRes instanceof _ASN1Object) {
		hRes = hRes.tohex();
	    }
	    if (typeof hRes != "string" || (! _isHex(hRes))) {
		throw new _Error("params.res has wrong value");
	    }
	    var hTST = ASN1HEX.getTLVbyList(hRes, 0, [1]);
	    var dTST = new _ASN1Object();
	    dTST.hTLV = params.tst;
	    return [dTST];
	}
    };

    if (params != null) this.setByParam(params);
};
extendClass(KJUR.asn1.cades.SignatureTimeStamp,
                  KJUR.asn1.cms.Attribute);

/**
 * class for RFC 5126 CAdES CompleteCertificateRefs attribute<br/>
 * @name KJUR.asn1.cades.CompleteCertificateRefs
 * @class class for RFC 5126 CAdES CompleteCertificateRefs attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 *
 * @description
 * <pre>
 * id-aa-ets-certificateRefs OBJECT IDENTIFIER = 
 *    1.2.840.113549.1.9.16.2.21
 * CompleteCertificateRefs ::=  SEQUENCE OF OtherCertID
 * OtherCertID ::= SEQUENCE {
 *    otherCertHash    OtherHash,
 *    issuerSerial     IssuerSerial OPTIONAL }
 * OtherHash ::= CHOICE {
 *    sha1Hash   OtherHashValue,  -- This contains a SHA-1 hash
 *    otherHash  OtherHashAlgAndValue}
 * OtherHashAlgAndValue ::= SEQUENCE {
 *    hashAlgorithm   AlgorithmIdentifier,
 *    hashValue       OtherHashValue }
 * OtherHashValue ::= OCTET STRING
 * </pre>
 *
 * @example
 * o = new KJUR.asn1.cades.CompleteCertificateRefs({
 *   array: [certPEM1,certPEM2],
 *   otherhash: true // OPTION
 * });
 */
KJUR.asn1.cades.CompleteCertificateRefs = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_cades = _KJUR_asn1.cades,
	_OtherCertID = _KJUR_asn1_cades.OtherCertID,
	_isHex = _KJUR.lang.String.isHex;

    _KJUR_asn1_cades.CompleteCertificateRefs.superclass.constructor.call(this);
    this.typeOid = "1.2.840.113549.1.9.16.2.21";
    
    this.params = null;

    this.getValueArray = function() {
	var params = this.params;
	var a = [];

	for (var i = 0; i < params.array.length; i++) {
	    var pOtherCertID = params.array[i];

	    if (typeof pOtherCertID == "string") {
		if (pOtherCertID.indexOf("-----BEGIN") != -1) {
		    pOtherCertID = {cert: pOtherCertID};
		} else if (_isHex(pOtherCertID)) {
		    pOtherCertID = {hash: pOtherCertID};
		} else {
		    throw new _Error("unsupported value: " + pOtherCertID);
		}
	    }

	    if (params.alg != undefined && pOtherCertID.alg == undefined)
		pOtherCertID.alg = params.alg;

	    if (params.hasis != undefined && pOtherCertID.hasis == undefined)
		pOtherCertID.hasis = params.hasis;

	    var dOtherCertID = new _OtherCertID(pOtherCertID);
	    a.push(dOtherCertID);
	}

	var seq = new _DERSequence({array: a});
	return [seq];
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cades.CompleteCertificateRefs,
                  KJUR.asn1.cms.Attribute);

/**
 * class for OtherCertID ASN.1 object
 * @name KJUR.asn1.cades.OtherCertID
 * @class class for OtherCertID ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 * @see KJUR.asn1.cms.IssuerSerial
 * @see KJUR.asn1.cms.ESSCertID
 * @see KJUR.asn1.cms.ESSCertIDv2
 *
 * @description
 * <pre>
 * OtherCertID ::= SEQUENCE {
 *    otherCertHash    OtherHash,
 *    issuerSerial     IssuerSerial OPTIONAL }
 * IssuerSerial ::= SEQUENCE {
 *    issuer GeneralNames,
 *    serialNumber CertificateSerialNumber }
 * OtherHash ::= CHOICE {
 *    sha1Hash   OtherHashValue,  -- This contains a SHA-1 hash
 *    otherHash  OtherHashAlgAndValue}
 * OtherHashValue ::= OCTET STRING
 * OtherHashAlgAndValue ::= SEQUENCE {
 *    hashAlgorithm   AlgorithmIdentifier,
 *    hashValue       OtherHashValue }
 * </pre>
 *
 * @example
 * new KJUR.asn1.cades.OtherCertID(certPEM)
 * new KJUR.asn1.cades.OtherCertID({cert:certPEM, hasis: false})
 */
KJUR.asn1.cades.OtherCertID = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_IssuerSerial = _KJUR_asn1_cms.IssuerSerial,
	_KJUR_asn1_cades = _KJUR_asn1.cades,
	_OtherHashValue = _KJUR_asn1_cades.OtherHashValue,
	_OtherHashAlgAndValue = _KJUR_asn1_cades.OtherHashAlgAndValue;

    _KJUR_asn1_cades.OtherCertID.superclass.constructor.call(this);

    this.params = params;

    this.tohex = function() {
	var params = this.params;

	if (typeof params == "string") {
	    if (params.indexOf("-----BEGIN") != -1) {
		params = {cert: params};
	    } else if (_isHex(params)) {
		params = {hash: params};
	    }
	}

	var a = [];

	var dOtherHash = null;
	if (params.alg != undefined) {
	    dOtherHash = new _OtherHashAlgAndValue(params);
	} else {
	    dOtherHash = new _OtherHashValue(params);
	}
	a.push(dOtherHash);

	if ((params.cert != undefined && params.hasis == true) ||
	    (params.issuer != undefined && params.serial != undefined)) {
	    var dIssuerSerial = new _IssuerSerial(params);
	    a.push(dIssuerSerial);
	}
	
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cades.OtherCertID, KJUR.asn1.ASN1Object);

/**
 * class for OtherHash ASN.1 object<br/>
 * @name KJUR.asn1.cades.OtherHash
 * @class class for OtherHash ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 * @link KJUR.asn1.cades.OtherHashAlgAndValue
 * @link KJUR.asn1.cades.OtherHashValue
 *
 * @description
 * <pre>
 * OtherHash ::= CHOICE {
 *    sha1Hash   OtherHashValue,  -- This contains a SHA-1 hash
 *    otherHash  OtherHashAlgAndValue}
 * OtherHashValue ::= OCTET STRING
 * </pre>
 *
 * @example
 * // OtherHashAlgAndValue with SHA256 by PEM or Hex Cert
 * o = new KJUR.asn1.cades.OtherHash({alg: 'sha256', cert: certPEMorHex});
 * // OtherHashAlgAndValue with SHA256 by hash value
 * o = new KJUR.asn1.cades.OtherHash({alg: 'sha256', hash: '1234'});
 * // OtherHashValue(sha1) by PEM or Hex Cert
 * o = new KJUR.asn1.cades.OtherHash({cert: certPEM});
 * // OtherHashValue(sha1) by PEM or Hex Cert
 * o = new KJUR.asn1.cades.OtherHash(certPEMStr);
 * // OtherHashValue(sha1) by hash value
 * o = new KJUR.asn1.cades.OtherHash("1234");
 */
KJUR.asn1.cades.OtherHash = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_KJUR_asn1_cades = _KJUR_asn1.cades,
	_OtherHashAlgAndValue = _KJUR_asn1_cades.OtherHashAlgAndValue,
	_OtherHashValue = _KJUR_asn1_cades.OtherHashValue,
	_hashHex = _KJUR.crypto.Util.hashHex,
	_isHex = _KJUR.lang.String.isHex;

    _KJUR_asn1_cades.OtherHash.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	if (typeof params == "string") {
	    if (params.indexOf("-----BEGIN") != -1) {
		params = {cert: params};
	    } else if (_isHex(params)) {
		params = {hash: params};
	    }
	}

	var dOtherHash = null;
	if (params.alg != undefined) {
	    dOtherHash = new _OtherHashAlgAndValue(params);
	} else {
	    dOtherHash = new _OtherHashValue(params);
	}
	return dOtherHash.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.cades.OtherHash, KJUR.asn1.ASN1Object);


// == BEGIN UTILITIES =====================================================

/**
 * CAdES utiliteis class
 * @name KJUR.asn1.cades.CAdESUtil
 * @class CAdES utilities class
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 */
KJUR.asn1.cades.CAdESUtil = new function() {
};

/**
 * parse CMS SignedData to add unsigned attributes
 * @name parseSignedDataForAddingUnsigned
 * @memberOf KJUR.asn1.cades.CAdESUtil
 * @function
 * @param {String} hex hexadecimal string of ContentInfo of CMS SignedData
 * @return {Object} associative array of parsed data
 * @see KJUR.asn1.cms.CMSParser#getCMSSignedData
 * @see KJUR.asn1.cms.SignedData
 *
 * @description
 * This method will parse a hexadecimal string of 
 * ContentInfo with CMS SignedData to add a attribute
 * to unsigned attributes field in a signerInfo field.
 *
 * @example
 * param = KJUR.asn1.cades.CAdESUtil.parseSignedDataForAddingUnsigned(beshex);
 * &rarr;
 * {
 *   version: 1,
 *   hashalgs: ["sha256"],
 *   econtent: ...,
 *   sinfos: [{
 *     version: 1
 *     id: ...
 *     hashalg: "sha256",
 *     sattrs: {array: [...]},
 *     sigalg: "SHA256withRSA",
 *     sighex: ...
 *   }]
 * }
 */
KJUR.asn1.cades.CAdESUtil.parseSignedDataForAddingUnsigned = function(hex) {
    var parser = new KJUR.asn1.cms.CMSParser();
    var param = parser.getCMSSignedData(hex);
    return param;
};

/**
 * parse SignerInfo to add unsigned attributes (DEPRECATED)
 * @name parseSignerInfoForAddingUnsigned
 * @memberOf KJUR.asn1.cades.CAdESUtil
 * @function
 * @param {String} hex hexadecimal string of SignerInfo
 * @return {Object} associative array of parsed data
 * @deprecated since jsrsasign 10.1.5 no more necessary becase parseSignedDataForAddingUnsigned don't call this
 *
 * @description
 * This method will parse a hexadecimal string of 
 * SignerInfo to add a attribute
 * to unsigned attributes field in a signerInfo field.
 * Parsed result will be an associative array which has
 * following properties:
 * <ul>
 * <li>version - hex TLV of version</li>
 * <li>si - hex TLV of SignerIdentifier</li>
 * <li>digalg - hex TLV of DigestAlgorithm</li>
 * <li>sattrs - hex TLV of SignedAttributes</li>
 * <li>sigalg - hex TLV of SignatureAlgorithm</li>
 * <li>sig - hex TLV of signature</li>
 * <li>sigval = hex V of signature</li>
 * <li>obj - parsed KJUR.asn1.cms.SignerInfo object</li>
 * </ul>
 * NOTE: Parsing of unsigned attributes will be provided in the
 * future version. That's way this version provides support
 * for CAdES-T and not for CAdES-C.
 */
KJUR.asn1.cades.CAdESUtil.parseSignerInfoForAddingUnsigned = function(hex, iSI, nth) {
    var _ASN1HEX = ASN1HEX,
	_getChildIdx = _ASN1HEX.getChildIdx,
	_getTLV = _ASN1HEX.getTLV,
	_getV = _ASN1HEX.getV,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_AttributeList = _KJUR_asn1_cms.AttributeList,
	_SignerInfo = _KJUR_asn1_cms.SignerInfo;

    var r = {};
    var aSIChildIdx = _getChildIdx(hex, iSI);
    //alert(aSIChildIdx.join("="));

    if (aSIChildIdx.length != 6)
        throw "not supported items for SignerInfo (!=6)"; 

    // 1. SignerInfo.CMSVersion
    var iVersion = aSIChildIdx.shift();
    r.version = _getTLV(hex, iVersion);

    // 2. SignerIdentifier(IssuerAndSerialNumber)
    var iIdentifier = aSIChildIdx.shift();
    r.si = _getTLV(hex, iIdentifier);

    // 3. DigestAlgorithm
    var iDigestAlg = aSIChildIdx.shift();
    r.digalg = _getTLV(hex, iDigestAlg);

    // 4. SignedAttrs
    var iSignedAttrs = aSIChildIdx.shift();
    r.sattrs = _getTLV(hex, iSignedAttrs);

    // 5. SigAlg
    var iSigAlg = aSIChildIdx.shift();
    r.sigalg = _getTLV(hex, iSigAlg);

    // 6. Signature
    var iSig = aSIChildIdx.shift();
    r.sig = _getTLV(hex, iSig);
    r.sigval = _getV(hex, iSig);

    // 7. obj(SignerInfo)
    var tmp = null;
    r.obj = new _SignerInfo();

    tmp = new _ASN1Object();
    tmp.hTLV = r.version;
    r.obj.dCMSVersion = tmp;

    tmp = new _ASN1Object();
    tmp.hTLV = r.si;
    r.obj.dSignerIdentifier = tmp;

    tmp = new _ASN1Object();
    tmp.hTLV = r.digalg;
    r.obj.dDigestAlgorithm = tmp;

    tmp = new _ASN1Object();
    tmp.hTLV = r.sattrs;
    r.obj.dSignedAttrs = tmp;

    tmp = new _ASN1Object();
    tmp.hTLV = r.sigalg;
    r.obj.dSigAlg = tmp;

    tmp = new _ASN1Object();
    tmp.hTLV = r.sig;
    r.obj.dSig = tmp;

    r.obj.dUnsignedAttrs = new _AttributeList();

    return r;
};

