/*! asn1cades-1.0.0.js (c) 2013-2014 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1cades.js - ASN.1 DER encoder classes for RFC 5126 CAdES long term signature
 *
 * Copyright (c) 2014 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1cades-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.0 (2014-May-28)
 * @since jsrsasign 4.7.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
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
 * <li>{@link KJUR.asn1.cades.SignaturePolicyIdentifier} - for CAdES-EPES</li>
 * <li>{@link KJUR.asn1.cades.SignatureTimeStamp} - for CAdES-T</li>
 * <li>{@link KJUR.asn1.cades.CompleteCertificateRefs} - for CAdES-C(for future use)</li>
 * </ul>
 * NOTE: Currntly CAdES-C is not supported since parser can't
 * handle unsigned attribute.
 * 
 * <h4>OTHER CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.cades.OtherHashAlgAndValue}</li>
 * <li>{@link KJUR.asn1.cades.OtherHash}</li>
 * <li>{@link KJUR.asn1.cades.OtherCertID}</li>
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
 * @description
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
 * @example
 * var o = new KJUR.asn1.cades.SignaturePolicyIdentifier({
 *   oid: '1.2.3.4.5',
 *   hash: {alg: 'sha1', hash: 'a1a2a3a4...'}
 * });
 */
/*
 * id-aa-ets-sigPolicyId OBJECT IDENTIFIER ::= { iso(1)
 *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 *    smime(16) id-aa(2) 15 }
 *
 * signature-policy-identifier attribute values have ASN.1 type
 * SignaturePolicyIdentifier:
 *
 * SigPolicyQualifierInfo ::= SEQUENCE {
 *    sigPolicyQualifierId  SigPolicyQualifierId,
 *    sigQualifier          ANY DEFINED BY sigPolicyQualifierId } 
 *
 * sigpolicyQualifierIds defined in the present document:
 * SigPolicyQualifierId ::= OBJECT IDENTIFIER
 * id-spq-ets-uri OBJECT IDENTIFIER ::= { iso(1)
 *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 *    smime(16) id-spq(5) 1 }
 *
 * SPuri ::= IA5String
 *
 * id-spq-ets-unotice OBJECT IDENTIFIER ::= { iso(1)
 *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 *    smime(16) id-spq(5) 2 }
 *
 * SPUserNotice ::= SEQUENCE {
 *    noticeRef        NoticeReference OPTIONAL,
 *    explicitText     DisplayText OPTIONAL}
 *
 * NoticeReference ::= SEQUENCE {
 *    organization     DisplayText,
 *    noticeNumbers    SEQUENCE OF INTEGER }
 *
 * DisplayText ::= CHOICE {
 *    visibleString    VisibleString  (SIZE (1..200)),
 *    bmpString        BMPString      (SIZE (1..200)),
 *    utf8String       UTF8String     (SIZE (1..200)) }
 */
KJUR.asn1.cades.SignaturePolicyIdentifier = function(params) {
    KJUR.asn1.cades.SignaturePolicyIdentifier.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.15";
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cades;

    if (typeof params != "undefined") {
        if (typeof params.oid == "string" &&
            typeof params.hash == "object") {
            var dOid = new nA.DERObjectIdentifier({oid: params.oid});
            var dHash = new nC.OtherHashAlgAndValue(params.hash);
            var seq = new nA.DERSequence({array: [dOid, dHash]});
            this.valueList = [seq];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.SignaturePolicyIdentifier,
                  KJUR.asn1.cms.Attribute);

/**
 * class for OtherHashAlgAndValue ASN.1 object
 * @name KJUR.asn1.cades.OtherHashAlgAndValue
 * @class class for OtherHashAlgAndValue ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 * @description
 * <pre>
 * OtherHashAlgAndValue ::= SEQUENCE {
 *    hashAlgorithm   AlgorithmIdentifier,
 *    hashValue       OtherHashValue }
 * OtherHashValue ::= OCTET STRING
 * </pre>
 */
KJUR.asn1.cades.OtherHashAlgAndValue = function(params) {
    KJUR.asn1.cades.OtherHashAlgAndValue.superclass.constructor.call(this);
    var nA = KJUR.asn1;
    var nX = KJUR.asn1.x509;
    this.dAlg = null;
    this.dHash = null;

    this.getEncodedHex = function() {
        var seq = new nA.DERSequence({array: [this.dAlg, this.dHash]});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params != "undefined") {
        if (typeof params.alg == "string" &&
            typeof params.hash == "string") {
            this.dAlg = new nX.AlgorithmIdentifier({name: params.alg});
            this.dHash = new nA.DEROctetString({hex: params.hash});
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.OtherHashAlgAndValue, KJUR.asn1.ASN1Object);

/**
 * class for RFC 5126 CAdES SignatureTimeStamp attribute
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
 */
KJUR.asn1.cades.SignatureTimeStamp = function(params) {
    KJUR.asn1.cades.SignatureTimeStamp.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.14";
    this.tstHex = null;
    var nA = KJUR.asn1;

    if (typeof params != "undefined") {
        if (typeof params.res != "undefined") {
            if (typeof params.res == "string" &&
                params.res.match(/^[0-9A-Fa-f]+$/)) {
            } else if (params.res instanceof KJUR.asn1.ASN1Object) {
            } else {
                throw "res param shall be ASN1Object or hex string";
            }
        }
        if (typeof params.tst != "undefined") {
            if (typeof params.tst == "string" &&
                params.tst.match(/^[0-9A-Fa-f]+$/)) {
                var d = new nA.ASN1Object();
                this.tstHex = params.tst;
                d.hTLV = this.tstHex;
                d.getEncodedHex();
                this.valueList = [d];
            } else if (params.tst instanceof KJUR.asn1.ASN1Object) {
            } else {
                throw "tst param shall be ASN1Object or hex string";
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.SignatureTimeStamp,
                  KJUR.asn1.cms.Attribute);

/**
 * class for RFC 5126 CAdES CompleteCertificateRefs attribute
 * @name KJUR.asn1.cades.CompleteCertificateRefs
 * @class class for RFC 5126 CAdES CompleteCertificateRefs attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 * @description
 * <pre>
 * id-aa-ets-certificateRefs OBJECT IDENTIFIER = 
 *    1.2.840.113549.1.9.16.2.21
 * CompleteCertificateRefs ::=  SEQUENCE OF OtherCertID
 * </pre>
 * @example
 * o = new KJUR.asn1.cades.CompleteCertificateRefs([certPEM1,certPEM2]);
 */
KJUR.asn1.cades.CompleteCertificateRefs = function(params) {
    KJUR.asn1.cades.CompleteCertificateRefs.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.21";
    var nA = KJUR.asn1;
    var nD = KJUR.asn1.cades;

    /**
     * set value by array
     * @name setByArray
     * @memberOf KJUR.asn1.cades.CompleteCertificateRefs
     * @function
     * @param {Array} a array of {@link KJUR.asn1.cades.OtherCertID} argument
     * @return unspecified
     * @description
     */
    this.setByArray = function(a) {
        this.valueList = [];
        for (var i = 0; i < a.length; i++) {
            var o = new nD.OtherCertID(a[i]);
            this.valueList.push(o);
        }
    };

    if (typeof params != "undefined") {
        if (typeof params == "object" &&
            typeof params.length == "number") {
            this.setByArray(params);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.CompleteCertificateRefs,
                  KJUR.asn1.cms.Attribute);

/**
 * class for OtherCertID ASN.1 object
 * @name KJUR.asn1.cades.OtherCertID
 * @class class for OtherCertID ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 * @description
 * <pre>
 * OtherCertID ::= SEQUENCE {
 *    otherCertHash    OtherHash,
 *    issuerSerial     IssuerSerial OPTIONAL }
 * </pre>
 * @example
 * o = new KJUR.asn1.cades.OtherCertID(certPEM);
 * o = new KJUR.asn1.cades.OtherCertID({cert:certPEM, hasis: false});
 */
KJUR.asn1.cades.OtherCertID = function(params) {
    KJUR.asn1.cades.OtherCertID.superclass.constructor.call(this);
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cms;
    var nD = KJUR.asn1.cades;
    this.hasIssuerSerial = true;
    this.dOtherCertHash = null;
    this.dIssuerSerial = null;

    /**
     * set value by PEM string of certificate
     * @name setByCertPEM
     * @memberOf KJUR.asn1.cades.OtherCertID
     * @function
     * @param {String} certPEM PEM string of certificate
     * @return unspecified
     * @description
     * This method will set value by a PEM string of a certificate.
     * This will add IssuerAndSerialNumber by default 
     * which depends on hasIssuerSerial flag.
     */
    this.setByCertPEM = function(certPEM) {
        this.dOtherCertHash = new nD.OtherHash(certPEM);
        if (this.hasIssuerSerial)
            this.dIssuerSerial = new nC.IssuerAndSerialNumber(certPEM);
    };

    this.getEncodedHex = function() {
        if (this.hTLV != null) return this.hTLV;
        if (this.dOtherCertHash == null)
            throw "otherCertHash not set";
        var a = [this.dOtherCertHash];
        if (this.dIssuerSerial != null)
            a.push(this.dIssuerSerial);
        var seq = new nA.DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params != "undefined") {
        if (typeof params == "string" &&
            params.indexOf("-----BEGIN ") != -1) {
            this.setByCertPEM(params);
        }
        if (typeof params == "object") {
            if (params.hasis === false)
                this.hasIssuerSerial = false;
            if (typeof params.cert == "string")
                this.setByCertPEM(params.cert);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.OtherCertID, KJUR.asn1.ASN1Object);

/**
 * class for OtherHash ASN.1 object
 * @name KJUR.asn1.cades.OtherHash
 * @class class for OtherHash ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 * @description
 * <pre>
 * OtherHash ::= CHOICE {
 *    sha1Hash   OtherHashValue,  -- This contains a SHA-1 hash
 *    otherHash  OtherHashAlgAndValue}
 * OtherHashValue ::= OCTET STRING
 * </pre>
 * @example
 * o = new KJUR.asn1.cades.OtherHash("1234");
 * o = new KJUR.asn1.cades.OtherHash(certPEMStr); // default alg=sha256
 * o = new KJUR.asn1.cades.OtherHash({alg: 'sha256', hash: '1234'});
 * o = new KJUR.asn1.cades.OtherHash({alg: 'sha256', cert: certPEM});
 * o = new KJUR.asn1.cades.OtherHash({cert: certPEM});
 */
KJUR.asn1.cades.OtherHash = function(params) {
    KJUR.asn1.cades.OtherHash.superclass.constructor.call(this);
    var nA = KJUR.asn1;
    var nD = KJUR.asn1.cades;
    this.alg = 'sha256';
    this.dOtherHash = null;

    /**
     * set value by PEM string of certificate
     * @name setByCertPEM
     * @memberOf KJUR.asn1.cades.OtherHash
     * @function
     * @param {String} certPEM PEM string of certificate
     * @return unspecified
     * @description
     * This method will set value by a PEM string of a certificate.
     * An algorithm used to hash certificate data will
     * be defined by 'alg' property and 'sha256' is default.
     */
    this.setByCertPEM = function(certPEM) {
        if (certPEM.indexOf("-----BEGIN ") == -1)
            throw "certPEM not to seem PEM format";
        var hex = X509.pemToHex(certPEM);
        var hash = KJUR.crypto.Util.hashHex(hex, this.alg);
        this.dOtherHash = 
            new nD.OtherHashAlgAndValue({alg: this.alg, hash: hash});
    };

    this.getEncodedHex = function() {
        if (this.dOtherHash == null)
            throw "OtherHash not set";
        return this.dOtherHash.getEncodedHex();
    };

    if (typeof params != "undefined") {
        if (typeof params == "string") {
            if (params.indexOf("-----BEGIN ") != -1) {
                this.setByCertPEM(params);
            } else if (params.match(/^[0-9A-Fa-f]+$/)) {
                this.dOtherHash = new nA.DEROctetString({hex: params});
            } else {
                throw "unsupported string value for params";
            }
        } else if (typeof params == "object") {
            if (typeof params.cert == "string") {
                if (typeof params.alg == "string")
                    this.alg = params.alg;
                this.setByCertPEM(params.cert);
            } else {
                this.dOtherHash = new nD.OtherHashAlgAndValue(params);
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.OtherHash, KJUR.asn1.ASN1Object);


// == BEGIN UTILITIES =====================================================

/**
 * CAdES utiliteis class
 * @name KJUR.asn1.cades.CAdESUtil
 * @class CAdES utilities class
 * @since jsrsasign 4.7.0 asn1cades 1.0.0
 */
KJUR.asn1.cades.CAdESUtil = new function() {
};
/*
 *
 */
KJUR.asn1.cades.CAdESUtil.addSigTS = function(dCMS, siIdx, sigTSHex) {
};
/**
 * parse CMS SignedData to add unsigned attributes
 * @name parseSignedDataForAddingUnsigned
 * @memberOf KJUR.asn1.cades.CAdESUtil
 * @function
 * @param {String} hex hexadecimal string of ContentInfo of CMS SignedData
 * @return {Object} associative array of parsed data
 * @description
 * This method will parse a hexadecimal string of 
 * ContentInfo with CMS SignedData to add a attribute
 * to unsigned attributes field in a signerInfo field.
 * Parsed result will be an associative array which has
 * following properties:
 * <ul>
 * <li>version - hex of CMSVersion ASN.1 TLV</li>
 * <li>algs - hex of DigestAlgorithms ASN.1 TLV</li>
 * <li>encapcontent - hex of EncapContentInfo ASN.1 TLV</li>
 * <li>certs - hex of Certificates ASN.1 TLV</li>
 * <li>revs - hex of RevocationInfoChoices ASN.1 TLV</li>
 * <li>si[] - array of SignerInfo properties</li>
 * <li>obj - parsed KJUR.asn1.cms.SignedData object</li>
 * </ul>
 * @example
 * info = KJUR.asn1.cades.CAdESUtil.parseSignedDataForAddingUnsigned(beshex);
 * sd = info.obj;
 */
KJUR.asn1.cades.CAdESUtil.parseSignedDataForAddingUnsigned = function(hex) {
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cms;
    var nU = KJUR.asn1.cades.CAdESUtil;
    var r = {};

    // 1. not oid signed-data then error
    if (ASN1HEX.getDecendantHexTLVByNthList(hex, 0, [0]) != 
        "06092a864886f70d010702")
        throw "hex is not CMS SignedData";

    var iSD = ASN1HEX.getDecendantIndexByNthList(hex, 0, [1, 0]);
    var aSDChildIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, iSD);
    if (aSDChildIdx.length < 4)
        throw "num of SignedData elem shall be 4 at least";

    // 2. HEXs of SignedData children
    // 2.1. SignedData.CMSVersion
    var iVersion = aSDChildIdx.shift();
    r.version = ASN1HEX.getHexOfTLV_AtObj(hex, iVersion);

    // 2.2. SignedData.DigestAlgorithms
    var iAlgs = aSDChildIdx.shift();
    r.algs = ASN1HEX.getHexOfTLV_AtObj(hex, iAlgs);

    // 2.3. SignedData.EncapContentInfo
    var iEncapContent = aSDChildIdx.shift();
    r.encapcontent = ASN1HEX.getHexOfTLV_AtObj(hex, iEncapContent);

    // 2.4. [0]Certs 
    r.certs = null;
    r.revs = null;
    r.si = [];

    var iNext = aSDChildIdx.shift();
    if (hex.substr(iNext, 2) == "a0") {
        r.certs = ASN1HEX.getHexOfTLV_AtObj(hex, iNext);
        iNext = aSDChildIdx.shift();
    }

    // 2.5. [1]Revs
    if (hex.substr(iNext, 2) == "a1") {
        r.revs = ASN1HEX.getHexOfTLV_AtObj(hex, iNext);
        iNext = aSDChildIdx.shift();
    }

    // 2.6. SignerInfos
    var iSignerInfos = iNext;
    if (hex.substr(iSignerInfos, 2) != "31")
        throw "Can't find signerInfos";

    var aSIIndex = ASN1HEX.getPosArrayOfChildren_AtObj(hex, iSignerInfos);
    //alert(aSIIndex.join("-"));

    for (var i = 0; i < aSIIndex.length; i++) {
        var iSI = aSIIndex[i];
        var pSI = nU.parseSignerInfoForAddingUnsigned(hex, iSI, i);
        r.si[i] = pSI;
    }

    // x. obj(SignedData)
    var tmp = null;
    r.obj = new nC.SignedData();

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.version;
    r.obj.dCMSVersion = tmp;

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.algs;
    r.obj.dDigestAlgs = tmp;

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.encapcontent;
    r.obj.dEncapContentInfo = tmp;

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.certs;
    r.obj.dCerts = tmp;

    r.obj.signerInfoList = [];
    for (var i = 0; i < r.si.length; i++) {
        r.obj.signerInfoList.push(r.si[i].obj);
    }

    return r;
};

/**
 * parse SignerInfo to add unsigned attributes
 * @name parseSignerInfoForAddingUnsigned
 * @memberOf KJUR.asn1.cades.CAdESUtil
 * @function
 * @param {String} hex hexadecimal string of SignerInfo
 * @return {Object} associative array of parsed data
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
KJUR.asn1.cades.CAdESUtil.parseSignerInfoForAddingUnsigned = 
    function(hex, iSI, nth) {
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cms;
    var r = {};
    var aSIChildIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, iSI);
    //alert(aSIChildIdx.join("="));

    if (aSIChildIdx.length != 6)
        throw "not supported items for SignerInfo (!=6)"; 

    // 1. SignerInfo.CMSVersion
    var iVersion = aSIChildIdx.shift();
    r.version = ASN1HEX.getHexOfTLV_AtObj(hex, iVersion);

    // 2. SignerIdentifier(IssuerAndSerialNumber)
    var iIdentifier = aSIChildIdx.shift();
    r.si = ASN1HEX.getHexOfTLV_AtObj(hex, iIdentifier);

    // 3. DigestAlgorithm
    var iDigestAlg = aSIChildIdx.shift();
    r.digalg = ASN1HEX.getHexOfTLV_AtObj(hex, iDigestAlg);

    // 4. SignedAttrs
    var iSignedAttrs = aSIChildIdx.shift();
    r.sattrs = ASN1HEX.getHexOfTLV_AtObj(hex, iSignedAttrs);

    // 5. SigAlg
    var iSigAlg = aSIChildIdx.shift();
    r.sigalg = ASN1HEX.getHexOfTLV_AtObj(hex, iSigAlg);

    // 6. Signature
    var iSig = aSIChildIdx.shift();
    r.sig = ASN1HEX.getHexOfTLV_AtObj(hex, iSig);
    r.sigval = ASN1HEX.getHexOfV_AtObj(hex, iSig);

    // 7. obj(SignerInfo)
    var tmp = null;
    r.obj = new nC.SignerInfo();

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.version;
    r.obj.dCMSVersion = tmp;

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.si;
    r.obj.dSignerIdentifier = tmp;

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.digalg;
    r.obj.dDigestAlgorithm = tmp;

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.sattrs;
    r.obj.dSignedAttrs = tmp;

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.sigalg;
    r.obj.dSigAlg = tmp;

    tmp = new nA.ASN1Object();
    tmp.hTLV = r.sig;
    r.obj.dSig = tmp;

    r.obj.dUnsignedAttrs = new nC.AttributeList();

    return r;
};

