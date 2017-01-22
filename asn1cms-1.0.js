/*! asn1cms-1.0.3.js (c) 2013-2017 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1cms.js - ASN.1 DER encoder classes for Cryptographic Message Syntax(CMS)
 *
 * Copyright (c) 2013-2017 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1cms-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.3 (2017-Jan-14)
 * @since jsrsasign 4.2.4
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
 * kjur's ASN.1 class for Cryptographic Message Syntax(CMS)
 * <p>
 * This name space provides 
 * <a href="https://tools.ietf.org/html/rfc5652">RFC 5652
 * Cryptographic Message Syntax (CMS)</a> SignedData generator.
 *
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily generate CMS SignedData</li>
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
 * Attribute class for base of CMS attribute
 * @name KJUR.asn1.cms.Attribute
 * @class Attribute class for base of CMS attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
 * <pre>
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * </pre>
 */
KJUR.asn1.cms.Attribute = function(params) {
    KJUR.asn1.cms.Attribute.superclass.constructor.call(this);
    var valueList = []; // array of values

    this.getEncodedHex = function() {
        var attrTypeASN1, attrValueASN1, seq;
        attrTypeASN1 = new KJUR.asn1.DERObjectIdentifier({"oid": this.attrTypeOid});

        attrValueASN1 = new KJUR.asn1.DERSet({"array": this.valueList});
        try {
            attrValueASN1.getEncodedHex();
        } catch (ex) {
            throw "fail valueSet.getEncodedHex in Attribute(1)/" + ex;
        }

        seq = new KJUR.asn1.DERSequence({"array": [attrTypeASN1, attrValueASN1]});
        try {
            this.hTLV = seq.getEncodedHex();
        } catch (ex) {
            throw "failed seq.getEncodedHex in Attribute(2)/" + ex;
        }

        return this.hTLV;
    };
};
YAHOO.lang.extend(KJUR.asn1.cms.Attribute, KJUR.asn1.ASN1Object);

/**
 * class for CMS ContentType attribute
 * @name KJUR.asn1.cms.ContentType
 * @class class for CMS ContentType attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @example
 * o = new KJUR.asn1.cms.ContentType({name: 'data'});
 * o = new KJUR.asn1.cms.ContentType({oid: '1.2.840.113549.1.9.16.1.4'});
 */
KJUR.asn1.cms.ContentType = function(params) {
    KJUR.asn1.cms.ContentType.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.3";
    var contentTypeASN1 = null;

    if (typeof params != "undefined") {
        var contentTypeASN1 = new KJUR.asn1.DERObjectIdentifier(params);
        this.valueList = [contentTypeASN1];
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.ContentType, KJUR.asn1.cms.Attribute);

/**
 * class for CMS MessageDigest attribute
 * @name KJUR.asn1.cms.MessageDigest
 * @class class for CMS MessageDigest attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * MessageDigest ::= OCTET STRING
 * </pre>
 * @example
 * o = new KJUR.asn1.cms.MessageDigest({hex: 'a1a2a3a4...'});
 */
KJUR.asn1.cms.MessageDigest = function(params) {
    KJUR.asn1.cms.MessageDigest.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.4";

    if (typeof params != "undefined") {
        if (params.eciObj instanceof KJUR.asn1.cms.EncapsulatedContentInfo &&
            typeof params.hashAlg == "string") {
            var dataHex = params.eciObj.eContentValueHex;
            var hashAlg = params.hashAlg;
            var hashValueHex = KJUR.crypto.Util.hashHex(dataHex, hashAlg);
            var dAttrValue1 = new KJUR.asn1.DEROctetString({hex: hashValueHex});
            dAttrValue1.getEncodedHex();
            this.valueList = [dAttrValue1];
        } else {
            var dAttrValue1 = new KJUR.asn1.DEROctetString(params);
            dAttrValue1.getEncodedHex();
            this.valueList = [dAttrValue1];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.MessageDigest, KJUR.asn1.cms.Attribute);

/**
 * class for CMS SigningTime attribute
 * @name KJUR.asn1.cms.SigningTime
 * @class class for CMS SigningTime attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
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
 * @example
 * o = new KJUR.asn1.cms.SigningTime(); // current time UTCTime by default
 * o = new KJUR.asn1.cms.SigningTime({type: 'gen'}); // current time GeneralizedTime
 * o = new KJUR.asn1.cms.SigningTime({str: '20140517093800Z'}); // specified GeneralizedTime
 * o = new KJUR.asn1.cms.SigningTime({str: '140517093800Z'}); // specified UTCTime
 */
KJUR.asn1.cms.SigningTime = function(params) {
    KJUR.asn1.cms.SigningTime.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.5";

    if (typeof params != "undefined") {
        var asn1 = new KJUR.asn1.x509.Time(params);
        try {
            asn1.getEncodedHex();
        } catch (ex) {
            throw "SigningTime.getEncodedHex() failed/" + ex;
        }
        this.valueList = [asn1];
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningTime, KJUR.asn1.cms.Attribute);

/**
 * class for CMS SigningCertificate attribute
 * @name KJUR.asn1.cms.SigningCertificate
 * @class class for CMS SigningCertificate attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.5.1 asn1cms 1.0.1
 * @description
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
 * @example
 * o = new KJUR.asn1.cms.SigningCertificate({array: [certPEM]});
 */
KJUR.asn1.cms.SigningCertificate = function(params) {
    KJUR.asn1.cms.SigningCertificate.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.12";
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cms;
    var nY = KJUR.crypto;

    this.setCerts = function(listPEM) {
        var list = [];
        for (var i = 0; i < listPEM.length; i++) {
            var hex = ASN1HEX.pemToHex(listPEM[i]);
            var certHashHex = nY.Util.hashHex(hex, 'sha1');
            var dCertHash = new nA.DEROctetString({hex: certHashHex});
            dCertHash.getEncodedHex();
            var dIssuerSerial =
                new nC.IssuerAndSerialNumber({cert: listPEM[i]});
            dIssuerSerial.getEncodedHex();
            var dESSCertID =
                new nA.DERSequence({array: [dCertHash, dIssuerSerial]});
            dESSCertID.getEncodedHex();
            list.push(dESSCertID);
        }

        var dValue = new nA.DERSequence({array: list});
        dValue.getEncodedHex();
        this.valueList = [dValue];
    };

    if (typeof params != "undefined") {
        if (typeof params.array == "object") {
            this.setCerts(params.array);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningCertificate, KJUR.asn1.cms.Attribute);

/**
 * class for CMS SigningCertificateV2 attribute
 * @name KJUR.asn1.cms.SigningCertificateV2
 * @class class for CMS SigningCertificateV2 attribute
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.cms.Attribute
 * @since jsrsasign 4.5.1 asn1cms 1.0.1
 * @description
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
 * @example
 * // hash algorithm is sha256 by default:
 * o = new KJUR.asn1.cms.SigningCertificateV2({array: [certPEM]});
 * o = new KJUR.asn1.cms.SigningCertificateV2({array: [certPEM],
 *                                             hashAlg: 'sha512'});
 */
KJUR.asn1.cms.SigningCertificateV2 = function(params) {
    KJUR.asn1.cms.SigningCertificateV2.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.47";
    var nA = KJUR.asn1;
    var nX = KJUR.asn1.x509;
    var nC = KJUR.asn1.cms;
    var nY = KJUR.crypto;

    this.setCerts = function(listPEM, hashAlg) {
        var list = [];
        for (var i = 0; i < listPEM.length; i++) {
            var hex = ASN1HEX.pemToHex(listPEM[i]);

            var a = [];
            if (hashAlg != "sha256")
                a.push(new nX.AlgorithmIdentifier({name: hashAlg}));

            var certHashHex = nY.Util.hashHex(hex, hashAlg);
            var dCertHash = new nA.DEROctetString({hex: certHashHex});
            dCertHash.getEncodedHex();
            a.push(dCertHash);

            var dIssuerSerial =
                new nC.IssuerAndSerialNumber({cert: listPEM[i]});
            dIssuerSerial.getEncodedHex();
            a.push(dIssuerSerial);

            var dESSCertIDv2 =
                new nA.DERSequence({array: a});
            dESSCertIDv2.getEncodedHex();
            list.push(dESSCertIDv2);
        }

        var dValue = new nA.DERSequence({array: list});
        dValue.getEncodedHex();
        this.valueList = [dValue];
    };

    if (typeof params != "undefined") {
        if (typeof params.array == "object") {
            var hashAlg = "sha256"; // sha2 default
            if (typeof params.hashAlg == "string") 
                hashAlg = params.hashAlg;
            this.setCerts(params.array, hashAlg);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningCertificateV2, KJUR.asn1.cms.Attribute);

/**
 * class for IssuerAndSerialNumber ASN.1 structure for CMS
 * @name KJUR.asn1.cms.IssuerAndSerialNumber
 * @class class for CMS IssuerAndSerialNumber ASN.1 structure for CMS
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *    issuer Name,
 *    serialNumber CertificateSerialNumber }
 * CertificateSerialNumber ::= INTEGER
 * </pre>
 * @example
 * // specify by X500Name and DERInteger
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber(
 *      {issuer: {str: '/C=US/O=T1'}, serial {int: 3}});
 * // specify by PEM certificate
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber({cert: certPEM});
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber(certPEM); // since 1.0.3
 */
KJUR.asn1.cms.IssuerAndSerialNumber = function(params) {
    KJUR.asn1.cms.IssuerAndSerialNumber.superclass.constructor.call(this);
    var dIssuer = null;
    var dSerial = null;
    var nA = KJUR.asn1;
    var nX = nA.x509;

    /*
     * @since asn1cms 1.0.1
     */
    this.setByCertPEM = function(certPEM) {
        var certHex = ASN1HEX.pemToHex(certPEM);
        var x = new X509();
        x.hex = certHex;
        var issuerTLVHex = x.getIssuerHex();
        this.dIssuer = new nX.X500Name();
        this.dIssuer.hTLV = issuerTLVHex;
        var serialVHex = x.getSerialNumberHex();
        this.dSerial = new nA.DERInteger({hex: serialVHex});
    };

    this.getEncodedHex = function() {
        var seq = new KJUR.asn1.DERSequence({"array": [this.dIssuer,
                                                       this.dSerial]});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params != "undefined") {
        if (typeof params == "string" &&
            params.indexOf("-----BEGIN ") != -1) {
            this.setByCertPEM(params);
        }
        if (params.issuer && params.serial) {
            if (params.issuer instanceof KJUR.asn1.x509.X500Name) {
                this.dIssuer = params.issuer;
            } else {
                this.dIssuer = new KJUR.asn1.x509.X500Name(params.issuer);
            }
            if (params.serial instanceof KJUR.asn1.DERInteger) {
                this.dSerial = params.serial;
            } else {
                this.dSerial = new KJUR.asn1.DERInteger(params.serial);
            }
        }
        if (typeof params.cert == "string") {
            this.setByCertPEM(params.cert);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.IssuerAndSerialNumber, KJUR.asn1.ASN1Object);

/**
 * class for Attributes ASN.1 structure for CMS
 * @name KJUR.asn1.cms.AttributeList
 * @class class for Attributes ASN.1 structure for CMS
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
 * <pre>
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * </pre>
 * @example
 * // specify by X500Name and DERInteger
 * o = new KJUR.asn1.cms.AttributeList({sorted: false}); // ASN.1 BER unsorted SET OF
 * o = new KJUR.asn1.cms.AttributeList();  // ASN.1 DER sorted by default
 * o.clear();                              // clear list of Attributes
 * n = o.length();                         // get number of Attribute
 * o.add(new KJUR.asn1.cms.SigningTime()); // add SigningTime attribute
 * hex = o.getEncodedHex();                // get hex encoded ASN.1 data
 */
KJUR.asn1.cms.AttributeList = function(params) {
    KJUR.asn1.cms.AttributeList.superclass.constructor.call(this);
    this.list = new Array();
    this.sortFlag = true;

    this.add = function(item) {
        if (item instanceof KJUR.asn1.cms.Attribute) {
            this.list.push(item);
        }
    };

    this.length = function() {
        return this.list.length;
    };

    this.clear = function() {
        this.list = new Array();
        this.hTLV = null;
        this.hV = null;
    };

    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") return this.hTLV;
        var set = new KJUR.asn1.DERSet({array: this.list, 
                                        sortflag: this.sortFlag});
        this.hTLV = set.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params != "undefined") {
        if (typeof params.sortflag != "undefined" &&
            params.sortflag == false)
            this.sortFlag = false;
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.AttributeList, KJUR.asn1.ASN1Object);

/**
 * class for SignerInfo ASN.1 structure of CMS SignedData
 * @name KJUR.asn1.cms.SignerInfo
 * @class class for Attributes ASN.1 structure of CMS SigndData
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
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
 * @example
 * o = new KJUR.asn1.cms.SignerInfo();
 * o.setSignerIdentifier(certPEMstring);
 * o.dSignedAttrs.add(new KJUR.asn1.cms.ContentType({name: 'data'}));
 * o.dSignedAttrs.add(new KJUR.asn1.cms.MessageDigest({hex: 'a1b2...'}));
 * o.dSignedAttrs.add(new KJUR.asn1.cms.SigningTime());
 * o.sign(privteKeyParam, "SHA1withRSA");
 */
KJUR.asn1.cms.SignerInfo = function(params) {
    KJUR.asn1.cms.SignerInfo.superclass.constructor.call(this);
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cms;
    var nX = KJUR.asn1.x509;

    this.dCMSVersion = new nA.DERInteger({'int': 1});
    this.dSignerIdentifier = null;
    this.dDigestAlgorithm = null;
    this.dSignedAttrs = new nC.AttributeList();
    this.dSigAlg = null;
    this.dSig = null;
    this.dUnsignedAttrs = new nC.AttributeList();

    this.setSignerIdentifier = function(params) {
        if (typeof params == "string" &&
            params.indexOf("CERTIFICATE") != -1 &&
            params.indexOf("BEGIN") != -1 &&
            params.indexOf("END") != -1) {

            var certPEM = params;
            this.dSignerIdentifier = 
                new nC.IssuerAndSerialNumber({cert: params});
        }
    };

    /**
     * set ContentType/MessageDigest/DigestAlgorithms for SignerInfo/SignedData
     * @name setForContentAndHash
     * @memberOf KJUR.asn1.cms.SignerInfo
     * @param {Array} params JSON parameter to set content related field
     * @description
     * This method will specify following fields by a parameters:
     * <ul>
     * <li>add ContentType signed attribute by encapContentInfo</li>
     * <li>add MessageDigest signed attribute by encapContentInfo and hashAlg</li>
     * <li>add a hash algorithm used in MessageDigest to digestAlgorithms field of SignedData</li>
     * <li>set a hash algorithm used in MessageDigest to digestAlgorithm field of SignerInfo</li>
     * </ul>
     * Argument 'params' is an associative array having following elements:
     * <ul>
     * <li>eciObj - {@link KJUR.asn1.cms.EncapsulatedContentInfo} object</li>
     * <li>sdObj - {@link KJUR.asn1.cms.SignedData} object (Option) to set DigestAlgorithms</li>
     * <li>hashAlg - string of hash algorithm name which is used for MessageDigest attribute</li>
     * </ul>
     * some of elements can be omited.
     * @example
     * sd = new KJUR.asn1.cms.SignedData();
     * signerInfo.setForContentAndHash({sdObj: sd,
     *                                  eciObj: sd.dEncapContentInfo,
     *                                  hashAlg: 'sha256'});
     */
    this.setForContentAndHash = function(params) {
        if (typeof params != "undefined") {
            if (params.eciObj instanceof KJUR.asn1.cms.EncapsulatedContentInfo) {
                this.dSignedAttrs.add(new nC.ContentType({oid: '1.2.840.113549.1.7.1'}));
                this.dSignedAttrs.add(new nC.MessageDigest({eciObj: params.eciObj,
                                                            hashAlg: params.hashAlg}));
            }
            if (typeof params.sdObj != "undefined" &&
                params.sdObj instanceof KJUR.asn1.cms.SignedData) {
                if (params.sdObj.digestAlgNameList.join(":").indexOf(params.hashAlg) == -1) {
                    params.sdObj.digestAlgNameList.push(params.hashAlg);
                }
            }
            if (typeof params.hashAlg == "string") {
                this.dDigestAlgorithm = new nX.AlgorithmIdentifier({name: params.hashAlg});
            }
        }
    };

    this.sign = function(keyParam, sigAlg) {
        // set algorithm
        this.dSigAlg = new nX.AlgorithmIdentifier({name: sigAlg});

        // set signature
        var data = this.dSignedAttrs.getEncodedHex();
        var prvKey = KEYUTIL.getKey(keyParam);
        var sig = new KJUR.crypto.Signature({alg: sigAlg});
        sig.init(prvKey);
        sig.updateHex(data);
        var sigValHex = sig.sign();
        this.dSig = new nA.DEROctetString({hex: sigValHex});
    };

    /*
     * @since asn1cms 1.0.3
     */
    this.addUnsigned = function(attr) {
        this.hTLV = null;
        this.dUnsignedAttrs.hTLV = null;
        this.dUnsignedAttrs.add(attr);
    };

    this.getEncodedHex = function() {
        //alert("sattrs.hTLV=" + this.dSignedAttrs.hTLV);
        if (this.dSignedAttrs instanceof KJUR.asn1.cms.AttributeList &&
            this.dSignedAttrs.length() == 0) {
            throw "SignedAttrs length = 0 (empty)";
        }
        var sa = new nA.DERTaggedObject({obj: this.dSignedAttrs,
                                         tag: 'a0', explicit: false});
        var ua = null;;
        if (this.dUnsignedAttrs.length() > 0) {
            ua = new nA.DERTaggedObject({obj: this.dUnsignedAttrs,
                                         tag: 'a1', explicit: false});
        }

        var items = [
            this.dCMSVersion,
            this.dSignerIdentifier,
            this.dDigestAlgorithm,
            sa,
            this.dSigAlg,
            this.dSig,
        ];
        if (ua != null) items.push(ua);

        var seq = new nA.DERSequence({array: items});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };
};
YAHOO.lang.extend(KJUR.asn1.cms.SignerInfo, KJUR.asn1.ASN1Object);

/**
 * class for EncapsulatedContentInfo ASN.1 structure for CMS
 * @name KJUR.asn1.cms.EncapsulatedContentInfo
 * @class class for EncapsulatedContentInfo ASN.1 structure for CMS
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.2.4 asn1cms 1.0.0
 * @description
 * <pre>
 * EncapsulatedContentInfo ::= SEQUENCE {
 *    eContentType ContentType,
 *    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @example
 * o = new KJUR.asn1.cms.EncapsulatedContentInfo();
 * o.setContentType('1.2.3.4.5');     // specify eContentType by OID
 * o.setContentType('data');          // specify eContentType by name
 * o.setContentValueHex('a1a2a4...'); // specify eContent data by hex string
 * o.setContentValueStr('apple');     // specify eContent data by UTF-8 string
 * // for detached contents (i.e. data not concluded in eContent)
 * o.isDetached = true;               // false as default 
 */
KJUR.asn1.cms.EncapsulatedContentInfo = function(params) {
    KJUR.asn1.cms.EncapsulatedContentInfo.superclass.constructor.call(this);
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cms;
    var nX = KJUR.asn1.x509;
    this.dEContentType = new nA.DERObjectIdentifier({name: 'data'});
    this.dEContent = null;
    this.isDetached = false;
    this.eContentValueHex = null;
    
    this.setContentType = function(nameOrOid) {
        if (nameOrOid.match(/^[0-2][.][0-9.]+$/)) {
            this.dEContentType = new nA.DERObjectIdentifier({oid: nameOrOid});
        } else {
            this.dEContentType = new nA.DERObjectIdentifier({name: nameOrOid});
        }
    };

    this.setContentValue = function(params) {
        if (typeof params != "undefined") {
            if (typeof params.hex == "string") {
                this.eContentValueHex = params.hex;
            } else if (typeof params.str == "string") {
                this.eContentValueHex = utf8tohex(params.str);
            }
        }
    };

    this.setContentValueHex = function(valueHex) {
        this.eContentValueHex = valueHex;
    };

    this.setContentValueStr = function(valueStr) {
        this.eContentValueHex = utf8tohex(valueStr);
    };

    this.getEncodedHex = function() {
        if (typeof this.eContentValueHex != "string") {
            throw "eContentValue not yet set";
        }

        var dValue = new nA.DEROctetString({hex: this.eContentValueHex});
        this.dEContent = new nA.DERTaggedObject({obj: dValue,
                                                 tag: 'a0',
                                                 explicit: true});

        var a = [this.dEContentType];
        if (! this.isDetached) a.push(this.dEContent);
        var seq = new nA.DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };
};
YAHOO.lang.extend(KJUR.asn1.cms.EncapsulatedContentInfo, KJUR.asn1.ASN1Object);

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
    KJUR.asn1.cms.ContentInfo.superclass.constructor.call(this);
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cms;
    var nX = KJUR.asn1.x509;

    this.dContentType = null;
    this.dContent = null;

    this.setContentType = function(params) {
        if (typeof params == "string") {
            this.dContentType = nX.OID.name2obj(params);
        }
    };

    this.getEncodedHex = function() {
        var dContent0 = new nA.DERTaggedObject({obj: this.dContent, tag: 'a0', explicit: true});
        var seq = new nA.DERSequence({array: [this.dContentType, dContent0]});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params != "undefined") {
        if (params.type) this.setContentType(params.type);
        if (params.obj && params.obj instanceof nA.ASN1Object) this.dContent = params.obj;
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.ContentInfo, KJUR.asn1.ASN1Object);

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
 * sd = new KJUR.asn1.cms.SignedData();
 * sd.dEncapContentInfo.setContentValueStr("test string");
 * sd.signerInfoList[0].setForContentAndHash({sdObj: sd,
 *                                            eciObj: sd.dEncapContentInfo,
 *                                            hashAlg: 'sha256'});
 * sd.signerInfoList[0].dSignedAttrs.add(new KJUR.asn1.cms.SigningTime());
 * sd.signerInfoList[0].setSignerIdentifier(certPEM);
 * sd.signerInfoList[0].sign(prvP8PEM, "SHA256withRSA");
 * hex = sd.getContentInfoEncodedHex();
 */
KJUR.asn1.cms.SignedData = function(params) {
    KJUR.asn1.cms.SignedData.superclass.constructor.call(this);
    var nA = KJUR.asn1;
    var nC = KJUR.asn1.cms;
    var nX = KJUR.asn1.x509;

    this.dCMSVersion = new nA.DERInteger({'int': 1});
    this.dDigestAlgs = null;
    this.digestAlgNameList = [];
    this.dEncapContentInfo = new nC.EncapsulatedContentInfo();
    this.dCerts = null;
    this.certificateList = [];
    this.crlList = [];
    this.signerInfoList = [new nC.SignerInfo()];

    this.addCertificatesByPEM = function(certPEM) {
        var hex = ASN1HEX.pemToHex(certPEM);
        var o = new nA.ASN1Object();
        o.hTLV = hex;
        this.certificateList.push(o);
    };

    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") return this.hTLV;
        
        if (this.dDigestAlgs == null) {
            var digestAlgList = [];
            for (var i = 0; i < this.digestAlgNameList.length; i++) {
                var name = this.digestAlgNameList[i];
                var o = new nX.AlgorithmIdentifier({name: name});
                digestAlgList.push(o);
            }
            this.dDigestAlgs = new nA.DERSet({array: digestAlgList});
        }

        var a = [this.dCMSVersion,
                 this.dDigestAlgs,
                 this.dEncapContentInfo];

        if (this.dCerts == null) {
            if (this.certificateList.length > 0) {
                var o1 = new nA.DERSet({array: this.certificateList});
                this.dCerts
                    = new nA.DERTaggedObject({obj: o1,
                                              tag: 'a0',
                                              explicit: false});
            }
        }
        if (this.dCerts != null) a.push(this.dCerts);
        
        var dSignerInfos = new nA.DERSet({array: this.signerInfoList});
        a.push(dSignerInfos);

        var seq = new nA.DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    this.getContentInfo = function() {
        this.getEncodedHex();
        var ci = new nC.ContentInfo({type: 'signed-data', obj: this});
        return ci;
    };

    this.getContentInfoEncodedHex = function() {
        var ci = this.getContentInfo();
        var ciHex = ci.getEncodedHex();
        return ciHex;
    };

    this.getPEM = function() {
        var hex = this.getContentInfoEncodedHex();
        var pem = nA.ASN1Util.getPEMStringFromHex(hex, "CMS");
        return pem;
    };
};
YAHOO.lang.extend(KJUR.asn1.cms.SignedData, KJUR.asn1.ASN1Object);

/**
 * CMS utiliteis class
 * @name KJUR.asn1.cms.CMSUtil
 * @class CMS utilities class
 */
KJUR.asn1.cms.CMSUtil = new function() {
};
/**
 * generate SignedData object specified by JSON parameters
 * @name newSignedData
 * @memberOf KJUR.asn1.cms.CMSUtil
 * @function
 * @param {Array} param JSON parameter to generate CMS SignedData
 * @return {KJUR.asn1.cms.SignedData} object just generated
 * @description
 * This method provides more easy way to genereate
 * CMS SignedData ASN.1 structure by JSON data.
 * @example
 * var sd = KJUR.asn1.cms.CMSUtil.newSignedData({
 *   content: {str: "jsrsasign"},
 *   certs: [certPEM],
 *   signerInfos: [{
 *     hashAlg: 'sha256',
 *     sAttr: {
 *       SigningTime: {}
 *       SigningCertificateV2: {array: [certPEM]},
 *     },
 *     signerCert: certPEM,
 *     sigAlg: 'SHA256withRSA',
 *     signerPrvKey: prvPEM
 *   }]
 * });
 */
KJUR.asn1.cms.CMSUtil.newSignedData = function(param) {
    var nC = KJUR.asn1.cms;
    var nE = KJUR.asn1.cades;
    var sd = new nC.SignedData();

    sd.dEncapContentInfo.setContentValue(param.content);

    if (typeof param.certs == "object") {
        for (var i = 0; i < param.certs.length; i++) {
            sd.addCertificatesByPEM(param.certs[i]);
        }
    }
    
    sd.signerInfoList = [];
    for (var i = 0; i < param.signerInfos.length; i++) {
        var siParam = param.signerInfos[i];
        var si = new nC.SignerInfo();
        si.setSignerIdentifier(siParam.signerCert);

        si.setForContentAndHash({sdObj: sd,
                                 eciObj: sd.dEncapContentInfo,
                                 hashAlg: siParam.hashAlg});

        for (attrName in siParam.sAttr) {
            var attrParam = siParam.sAttr[attrName];
            if (attrName == "SigningTime") {
                var attr = new nC.SigningTime(attrParam);
                si.dSignedAttrs.add(attr);
            }
            if (attrName == "SigningCertificate") {
                var attr = new nC.SigningCertificate(attrParam);
                si.dSignedAttrs.add(attr);
            }
            if (attrName == "SigningCertificateV2") {
                var attr = new nC.SigningCertificateV2(attrParam);
                si.dSignedAttrs.add(attr);
            }
            if (attrName == "SignaturePolicyIdentifier") {
                var attr = new nE.SignaturePolicyIdentifier(attrParam);
                si.dSignedAttrs.add(attr);
            }
        }

        si.sign(siParam.signerPrvKey, siParam.sigAlg);
        sd.signerInfoList.push(si);
    }

    return sd;
};

