/*! asn1csr-1.0.3.js (c) 2015-2017 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1csr.js - ASN.1 DER encoder classes for PKCS#10 CSR
 *
 * Copyright (c) 2015-2017 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1csr-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.3 (2017-Jan-14)
 * @since jsrsasign 4.9.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
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
 * {@link KJUR.asn1.csr.CSRUtil.newCSRPEM} method is very useful to
 * get your certificate signing request (CSR/PKCS#10) file.
 * </p>
 * @name KJUR.asn1.csr
 * @namespace
 */
if (typeof KJUR.asn1.csr == "undefined" || !KJUR.asn1.csr) KJUR.asn1.csr = {};

/**
 * ASN.1 CertificationRequest structure class
 * @name KJUR.asn1.csr.CertificationRequest
 * @class ASN.1 CertificationRequest structure class
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.9.0 asn1csr 1.0.0
 * @description
 * <br/>
 * @example
 * csri = new KJUR.asn1.csr.CertificationRequestInfo();
 * csri.setSubjectByParam({'str': '/C=US/O=Test/CN=example.com'});
 * csri.setSubjectPublicKeyByGetKey(pubKeyObj);
 * csr = new KJUR.asn1.csr.CertificationRequest({'csrinfo': csri});
 * csr.sign("SHA256withRSA", prvKeyObj);
 * pem = csr.getPEMString();
 * 
 * // -- DEFINITION OF ASN.1 SYNTAX --
 * // CertificationRequest ::= SEQUENCE {
 * //   certificationRequestInfo CertificationRequestInfo,
 * //   signatureAlgorithm       AlgorithmIdentifier{{ SignatureAlgorithms }},
 * //   signature                BIT STRING }
 * //
 * // CertificationRequestInfo ::= SEQUENCE {
 * //   version       INTEGER { v1(0) } (v1,...),
 * //   subject       Name,
 * //   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 * //   attributes    [0] Attributes{{ CRIAttributes }} }
 */
KJUR.asn1.csr.CertificationRequest = function(params) {
    KJUR.asn1.csr.CertificationRequest.superclass.constructor.call(this);
    var asn1CSRInfo = null;
    var asn1SignatureAlg = null;
    var asn1Sig = null;
    var hexSig = null;
    var prvKey = null;

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
     * csr = new KJUR.asn1.csr.CertificationRequest({'csrinfo': csri});
     * csr.sign("SHA256withRSA", prvKeyObj);
     */
    this.sign = function(sigAlgName, prvKeyObj) {
	if (this.prvKey == null) this.prvKey = prvKeyObj;

	this.asn1SignatureAlg = 
	    new KJUR.asn1.x509.AlgorithmIdentifier({'name': sigAlgName});

        sig = new KJUR.crypto.Signature({'alg': sigAlgName});
        sig.initSign(this.prvKey);
        sig.updateHex(this.asn1CSRInfo.getEncodedHex());
        this.hexSig = sig.sign();

        this.asn1Sig = new KJUR.asn1.DERBitString({'hex': '00' + this.hexSig});
        var seq = new KJUR.asn1.DERSequence({'array': [this.asn1CSRInfo,
                                                       this.asn1SignatureAlg,
                                                       this.asn1Sig]});
        this.hTLV = seq.getEncodedHex();
        this.isModified = false;
    };

    /**
     * get PEM formatted certificate signing request (CSR/PKCS#10)<br/>
     * @name getPEMString
     * @memberOf KJUR.asn1.csr.CertificationRequest#
     * @function
     * @return PEM formatted string of CSR/PKCS#10
     * @description
     * This method is to a get CSR PEM string after signed.
     * <br/>
     * @example
     * csr = new KJUR.asn1.csr.CertificationRequest({'csrinfo': csri});
     * csr.sign();
     * pem =  csr.getPEMString();
     * // pem will be following:
     * // -----BEGIN CERTIFICATE REQUEST-----
     * // MII ...snip...
     * // -----END CERTIFICATE REQUEST-----
     */
    this.getPEMString = function() {
	var pem = KJUR.asn1.ASN1Util.getPEMStringFromHex(this.getEncodedHex(),
							 "CERTIFICATE REQUEST");
	return pem;
    };

    this.getEncodedHex = function() {
        if (this.isModified == false && this.hTLV != null) return this.hTLV;
        throw "not signed yet";
    };

    if (typeof params != "undefined") {
        if (typeof params['csrinfo'] != "undefined") {
            this.asn1CSRInfo = params['csrinfo'];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.csr.CertificationRequest, KJUR.asn1.ASN1Object);

/**
 * ASN.1 CertificationRequestInfo structure class
 * @name KJUR.asn1.csr.CertificationRequestInfo
 * @class ASN.1 CertificationRequestInfo structure class
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.9.0 asn1csr 1.0.0
 * @description
 * <pre>
 * // -- DEFINITION OF ASN.1 SYNTAX --
 * // CertificationRequestInfo ::= SEQUENCE {
 * //   version       INTEGER { v1(0) } (v1,...),
 * //   subject       Name,
 * //   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 * //   attributes    [0] Attributes{{ CRIAttributes }} }
 * </pre>
 * <br/>
 * @example
 * csri = new KJUR.asn1.csr.CertificationRequestInfo();
 * csri.setSubjectByParam({'str': '/C=US/O=Test/CN=example.com'});
 * csri.setSubjectPublicKeyByGetKey(pubKeyObj);
 */
KJUR.asn1.csr.CertificationRequestInfo = function(params) {
    KJUR.asn1.csr.CertificationRequestInfo.superclass.constructor.call(this);

    this._initialize = function() {
        this.asn1Array = new Array();

	this.asn1Version = new KJUR.asn1.DERInteger({'int': 0});
	this.asn1Subject = null;
	this.asn1SubjPKey = null;
	this.extensionsArray = new Array();
    };

    /**
     * set subject name field by parameter
     * @name setSubjectByParam
     * @memberOf KJUR.asn1.csr.CertificationRequestInfo#
     * @function
     * @param {Array} x500NameParam X500Name parameter
     * @description
     * @example
     * csri.setSubjectByParam({'str': '/C=US/CN=b'});
     * @see KJUR.asn1.x509.X500Name
     */
    this.setSubjectByParam = function(x500NameParam) {
        this.asn1Subject = new KJUR.asn1.x509.X500Name(x500NameParam);
    };

    /**
     * set subject public key info by RSA/ECDSA/DSA key parameter
     * @name setSubjectPublicKeyByGetKey
     * @memberOf KJUR.asn1.csr.CertificationRequestInfo#
     * @function
     * @param {Object} keyParam public key parameter which passed to {@link KEYUTIL.getKey} argument
     * @description
     * @example
     * csri.setSubjectPublicKeyByGetKeyParam(certPEMString); // or 
     * csri.setSubjectPublicKeyByGetKeyParam(pkcs8PublicKeyPEMString); // or 
     * csir.setSubjectPublicKeyByGetKeyParam(kjurCryptoECDSAKeyObject); // et.al.
     * @see KJUR.asn1.x509.SubjectPublicKeyInfo
     * @see KEYUTIL.getKey
     */
    this.setSubjectPublicKeyByGetKey = function(keyParam) {
        var keyObj = KEYUTIL.getKey(keyParam);
        this.asn1SubjPKey = new KJUR.asn1.x509.SubjectPublicKeyInfo(keyObj);
    };

    /**
     * append X.509v3 extension to this object by name and parameters
     * @name appendExtensionByName
     * @memberOf KJUR.asn1.csr.CertificationRequestInfo#
     * @function
     * @param {name} name name of X.509v3 Extension object
     * @param {Array} extParams parameters as argument of Extension constructor.
     * @see KJUR.asn1.x509.Extension
     * @description
     * @example
     * var o = new KJUR.asn1.csr.CertificationRequestInfo();
     * o.appendExtensionByName('BasicConstraints', {'cA':true, 'critical': true});
     * o.appendExtensionByName('KeyUsage', {'bin':'11'});
     * o.appendExtensionByName('CRLDistributionPoints', {uri: 'http://aaa.com/a.crl'});
     * o.appendExtensionByName('ExtKeyUsage', {array: [{name: 'clientAuth'}]});
     * o.appendExtensionByName('AuthorityKeyIdentifier', {kid: '1234ab..'});
     * o.appendExtensionByName('AuthorityInfoAccess', {array: [{accessMethod:{oid:...},accessLocation:{uri:...}}]});
     */
    this.appendExtensionByName = function(name, extParams) {
	KJUR.asn1.x509.Extension.appendByNameToArray(name,
						     extParams,
						     this.extensionsArray);
    };

    this.getEncodedHex = function() {
        this.asn1Array = new Array();

        this.asn1Array.push(this.asn1Version);
        this.asn1Array.push(this.asn1Subject);
        this.asn1Array.push(this.asn1SubjPKey);

	// extensionRequest
	if (this.extensionsArray.length > 0) {
            var extSeq = new KJUR.asn1.DERSequence({array: this.extensionsArray});
	    var extSet = new KJUR.asn1.DERSet({array: [extSeq]});
	    var extSeq2 = new KJUR.asn1.DERSequence({array: [
		new KJUR.asn1.DERObjectIdentifier({oid: "1.2.840.113549.1.9.14"}),
		extSet
	    ]});
            var extTagObj = new KJUR.asn1.DERTaggedObject({
		explicit: true,
		tag: 'a0',
		obj: extSeq2
	    });
            this.asn1Array.push(extTagObj);
	} else {
            var extTagObj = new KJUR.asn1.DERTaggedObject({
		explicit: false,
		tag: 'a0',
		obj: new KJUR.asn1.DERNull()
	    });
            this.asn1Array.push(extTagObj);
	}

        var o = new KJUR.asn1.DERSequence({"array": this.asn1Array});
        this.hTLV = o.getEncodedHex();
        this.isModified = false;
        return this.hTLV;
    };

    this._initialize();
};
YAHOO.lang.extend(KJUR.asn1.csr.CertificationRequestInfo, KJUR.asn1.ASN1Object);

/**
 * Certification Request (CSR/PKCS#10) utilities class<br/>
 * @name KJUR.asn1.csr.CSRUtil
 * @class Certification Request (CSR/PKCS#10) utilities class
 * @description
 * This class provides utility static methods for CSR/PKCS#10.
 * Here is a list of methods:
 * <ul>
 * <li>{@link KJUR.asn1.csr.CSRUtil.newCSRPEM}</li>
 * <li>{@link KJUR.asn1.csr.CSRUtil.getInfo}</li>
 * </ul>
 * <br/>
 */
KJUR.asn1.csr.CSRUtil = new function() {
};

/**
 * generate a PEM format of CSR/PKCS#10 certificate signing request
 * @name newCSRPEM
 * @memberOf KJUR.asn1.csr.CSRUtil
 * @function
 * @param {Array} param parameter to generate CSR
 * @since jsrsasign 4.9.0 asn1csr 1.0.0
 * @description
 * This method can generate a CSR certificate signing
 * request by a simple JSON object which has following parameters:
 * <ul>
 * <li>subject - parameter to be passed to {@link KJUR.asn1.x509.X500Name}</li>
 * <li>sbjpubkey - parameter to be passed to {@link KEYUTIL.getKey}</li>
 * <li>sigalg - signature algorithm name (ex. SHA256withRSA)</li>
 * <li>sbjprvkey - parameter to be passed to {@link KEYUTIL.getKey}</li>
 * </ul>
 *
 * @example
 * // 1) by key object
 * pem = KJUR.asn1.csr.CSRUtil.newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   sbjpubkey: pubKeyObj,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: prvKeyObj
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
 *     {subjectAltName: {array: [{dns: 'example.net'}]}
 *   ],
 *   sbjpubkey: pubKeyPEM,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: prvKeyPEM
 * });
 */
KJUR.asn1.csr.CSRUtil.newCSRPEM = function(param) {
    var ns1 = KJUR.asn1.csr;

    if (param.subject === undefined) throw "parameter subject undefined";
    if (param.sbjpubkey === undefined) throw "parameter sbjpubkey undefined";
    if (param.sigalg === undefined) throw "parameter sigalg undefined";
    if (param.sbjprvkey === undefined) throw "parameter sbjpubkey undefined";

    var csri = new ns1.CertificationRequestInfo();
    csri.setSubjectByParam(param.subject);
    csri.setSubjectPublicKeyByGetKey(param.sbjpubkey);

    if (param.ext !== undefined && param.ext.length !== undefined) {
	for (var i = 0; i < param.ext.length; i++) {
	    for (key in param.ext[i]) {
                csri.appendExtensionByName(key, param.ext[i][key]);
	    }
	}
    }

    var csr = new ns1.CertificationRequest({'csrinfo': csri});
    var prvKey = KEYUTIL.getKey(param.sbjprvkey);
    csr.sign(param.sigalg, prvKey);

    var pem = csr.getPEMString();
    return pem;
};

/**
 * get field values from CSR/PKCS#10 PEM string<br/>
 * @name getInfo
 * @memberOf KJUR.asn1.csr.CSRUtil
 * @function
 * @param {String} sPEM PEM string of CSR/PKCS#10
 * @returns {Object} JSON object with parsed parameters such as name or public key
 * @since jsrsasign 6.1.3 asn1csr 1.0.1
 * @description
 * This method parses PEM CSR/PKCS#1 string and retrieves
 * subject name and public key. Following parameters are available in the
 * resulted JSON object.
 * <ul>
 * <li>subject.name - subject name string (ex. /C=US/O=Test)</li>
 * <li>subject.hex - hexadecimal string of X.500 Name of subject</li>
 * <li>pubkey.obj - subject public key object such as RSAKey, KJUR.crypto.{ECDSA,DSA}</li>
 * <li>pubkey.hex - hexadecimal string of subject public key</li>
 * </ul>
 *
 * @example
 * o = KJUR.asn1.csr.CSRUtil.getInfo("-----BEGIN CERTIFICATE REQUEST...");
 * console.log(o.subject.name) &rarr; "/C=US/O=Test"
 */
KJUR.asn1.csr.CSRUtil.getInfo = function(sPEM) {
    var result = {};
    result.subject = {};
    result.pubkey = {};

    if (sPEM.indexOf("-----BEGIN CERTIFICATE REQUEST") == -1)
	throw "argument is not PEM file";

    var hex = ASN1HEX.pemToHex(sPEM, "CERTIFICATE REQUEST");

    result.subject.hex = ASN1HEX.getDecendantHexTLVByNthList(hex, 0, [0, 1]);
    result.subject.name = X509.hex2dn(result.subject.hex);

    result.pubkey.hex = ASN1HEX.getDecendantHexTLVByNthList(hex, 0, [0, 2]);
    result.pubkey.obj = KEYUTIL.getKey(result.pubkey.hex, null, "pkcs8pub");

    return result;
};


