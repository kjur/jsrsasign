/* asn1x509-2.1.16.js (c) 2013-2022 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * asn1x509.js - ASN.1 DER encoder classes for X.509 certificate
 *
 * Copyright (c) 2013-2022 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1x509-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.22 asn1x509 2.1.16 (2022-May-24)
 * @since jsrsasign 2.1
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
 * kjur's ASN.1 class for X.509 certificate library name space
 * <p>
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily issue any kind of certificate</li>
 * <li>APIs are very similar to BouncyCastle library ASN.1 classes. So easy to learn.</li>
 * </ul>
 * </p>
 * <h4>PROVIDED CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.x509.Certificate}</li>
 * <li>{@link KJUR.asn1.x509.TBSCertificate}</li>
 * <li>{@link KJUR.asn1.x509.Extension} abstract class</li>
 * <li>{@link KJUR.asn1.x509.Extensions}</li>
 * <li>{@link KJUR.asn1.x509.SubjectPublicKeyInfo}</li>
 * <li>{@link KJUR.asn1.x509.AlgorithmIdentifier}</li>
 * <li>{@link KJUR.asn1.x509.GeneralNames}</li>
 * <li>{@link KJUR.asn1.x509.GeneralName}</li>
 * <li>{@link KJUR.asn1.x509.X500Name}</li>
 * <li>{@link KJUR.asn1.x509.RDN}</li>
 * <li>{@link KJUR.asn1.x509.AttributeTypeAndValue}</li>
 * <li>{@link KJUR.asn1.x509.DistributionPointName}</li>
 * <li>{@link KJUR.asn1.x509.DistributionPoint}</li>
 * <li>{@link KJUR.asn1.x509.PolicyInformation}</li>
 * <li>{@link KJUR.asn1.x509.PolicyQualifierInfo}</li>
 * <li>{@link KJUR.asn1.x509.UserNotice}</li>
 * <li>{@link KJUR.asn1.x509.NoticeReference}</li>
 * <li>{@link KJUR.asn1.x509.DisplayText}</li>
 * <li>{@link KJUR.asn1.x509.GeneralSubtree}</li>
 * <li>{@link KJUR.asn1.x509.CRL}</li>
 * <li>{@link KJUR.asn1.x509.TBSCertList}</li>
 * <li>{@link KJUR.asn1.x509.CRLEntry} (DEPRECATED)</li>
 * <li>{@link KJUR.asn1.x509.OID}</li>
 * </ul>
 * <h4>SUPPORTED EXTENSIONS</h4>
 * <ul>
 * <li>{@link KJUR.asn1.x509.AuthorityKeyIdentifier}</li>
 * <li>{@link KJUR.asn1.x509.SubjectKeyIdentifier}</li>
 * <li>{@link KJUR.asn1.x509.KeyUsage}</li>
 * <li>{@link KJUR.asn1.x509.CertificatePolicies}</li>
 * <li>{@link KJUR.asn1.x509.SubjectAltName}</li>
 * <li>{@link KJUR.asn1.x509.IssuerAltName}</li>
 * <li>{@link KJUR.asn1.x509.BasicConstraints}</li>
 * <li>{@link KJUR.asn1.x509.NameConstraints}</li>
 * <li>{@link KJUR.asn1.x509.ExtKeyUsage}</li>
 * <li>{@link KJUR.asn1.x509.CRLDistributionPoints}</li>
 * <li>{@link KJUR.asn1.x509.AuthorityInfoAccess}</li>
 * <li>{@link KJUR.asn1.x509.CRLNumber}</li>
 * <li>{@link KJUR.asn1.x509.CRLReason}</li>
 * <li>{@link KJUR.asn1.x509.OCSPNonce}</li>
 * <li>{@link KJUR.asn1.x509.OCSPNoCheck}</li>
 * <li>{@link KJUR.asn1.x509.AdobeTimeStamp}</li>
 * <li>{@link KJUR.asn1.x509.SubjectDirectoryAttributes}</li>
 * <li>{@link KJUR.asn1.x509.PrivateExtension}</li>
 * </ul>
 * NOTE1: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.<br/>
 * NOTE2: SubjectAltName and IssuerAltName supported since 
 * jsrsasign 6.2.3 asn1x509 1.0.19.<br/>
 * NOTE3: CeritifcatePolicies supported supported since
 * jsrsasign 8.0.23 asn1x509 1.1.12<br/>
 * @name KJUR.asn1.x509
 * @namespace
 */
if (typeof KJUR.asn1.x509 == "undefined" || !KJUR.asn1.x509) KJUR.asn1.x509 = {};

// === BEGIN Certificate ===================================================

/**
 * X.509 Certificate class to sign and generate hex encoded certificate
 * @name KJUR.asn1.x509.Certificate
 * @class X.509 Certificate class to sign and generate hex encoded certificate
 * @property {Array} params JSON object of parameters
 * @param {Array} params JSON object for Certificate parameters
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * This class provides Certificate ASN.1 class structure
 * defined in 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.1">
 * RFC 5280 4.1</a>.
 * <pre>
 * Certificate  ::=  SEQUENCE  {
 *      tbsCertificate       TBSCertificate,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING  }
 * </pre>
 * Parameter "params" JSON object can be
 * the same as {@link KJUR.asn1.x509.TBSCertificate}. 
 * Then they are used to generate TBSCertificate.
 * Additionally just for Certificate, following parameters can be used:
 * <ul>
 * <li>{TBSCertfificate}tbsobj - 
 * specifies {@link KJUR.asn1.x509.TBSCertificate} 
 * object to be signed if needed. 
 * When this isn't specified, 
 * this will be set from other parametes of TBSCertificate.</li>
 * <li>{Object}cakey (OPTION) - specifies certificate signing private key.
 * Parameter "cakey" or "sighex" shall be specified. Following
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
 * CAUTION: APIs of this class have been totally updated without
 * backward compatibility since jsrsasign 9.0.0.<br/>
 * NOTE1: 'params' can be omitted.<br/>
 * NOTE2: DSA/ECDSA is also supported for CA signging key from asn1x509 1.0.6.
 * @example
 * var cert = new KJUR.asn1.x509.Certificate({
 *  version: 3,
 *  serial: {hex: "1234..."},
 *  sigalg: "SHA256withRSAandMGF1",
 *  ...
 *  sighex: "1d3f..." // sign() method won't be called
 * });
 *
 * // sighex will by calculated by signing with cakey
 * var cert = new KJUR.asn1.x509.Certificate({
 *  version: 3,
 *  serial: {hex: "2345..."},
 *  sigalg: "SHA256withRSA",
 *  ...
 *  cakey: "-----BEGIN PRIVATE KEY..."
 * });
 *
 * // use TBSCertificate object to sign
 * var cert = new KJUR.asn1.x509.Certificate({
 *  tbsobj: <<OBJ>>,
 *  sigalg: "SHA256withRSA",
 *  cakey: "-----BEGIN PRIVATE KEY..."
 * });
 */
KJUR.asn1.x509.Certificate = function(params) {
    KJUR.asn1.x509.Certificate.superclass.constructor.call(this);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERBitString = _KJUR_asn1.DERBitString,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_TBSCertificate = _KJUR_asn1_x509.TBSCertificate,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier;

    this.params = undefined;

    /**
     * set parameter<br/>
     * @name setByParam
     * @memberOf KJUR.asn1.x509.Certificate#
     * @function
     * @param params {Array} JSON object of certificate parameters
     * @since jsrsasign 9.0.0 asn1hex 2.0.0
     * @description
     * This method will set parameter 
     * {@link KJUR.asn1.x509.Certificate#params}
     * to this object.
     * @example
     * cert = new KJUR.asn1.x509.Certificate();
     * cert.setByParam({
     *   version: 3,
     *   serial: {hex: "1234..."},
     *   ...
     * });
     */
    this.setByParam = function(params) {
	this.params = params;
    };

    /**
     * sign certificate<br/>
     * @name sign
     * @memberOf KJUR.asn1.x509.Certificate#
     * @function
     * @description
     * This method signs TBSCertificate with a specified 
     * private key and algorithm by 
     * this.params.cakey and this.params.sigalg parameter.
     * @example
     * cert = new KJUR.asn1.x509.Certificate({...});
     * cert.sign()
     */
    this.sign = function() {
	var params = this.params;

	var sigalg = params.sigalg;
	if (params.sigalg.name != undefined) 
	    sigalg = params.sigalg.name;

	var hTBS = params.tbsobj.tohex();
	var sig = new KJUR.crypto.Signature({alg: sigalg});
	sig.init(params.cakey);
	sig.updateHex(hTBS);
	params.sighex = sig.sign();
    };

    /**
     * get PEM formatted certificate string after signed
     * @name getPEM
     * @memberOf KJUR.asn1.x509.Certificate#
     * @function
     * @return PEM formatted string of certificate
     * @since jsrsasign 9.0.0 asn1hex 2.0.0
     * @description
     * This method returns a string of PEM formatted 
     * certificate.
     * @example
     * cert = new KJUR.asn1.x509.Certificate({...});
     * cert.getPEM() &rarr;
     * "-----BEGIN CERTIFICATE-----\r\n..."
     */
    this.getPEM = function() {
	return hextopem(this.tohex(), "CERTIFICATE");
    };

    this.tohex = function() {
	var params = this.params;
	
	if (params.tbsobj == undefined || params.tbsobj == null) {
	    params.tbsobj = new _TBSCertificate(params);
	}

	if (params.sighex == undefined && params.cakey != undefined) {
	    this.sign();
	}

	if (params.sighex == undefined) {
	    throw new Error("sighex or cakey parameter not defined");
	}

	var a = [];
	a.push(params.tbsobj);
	a.push(new _AlgorithmIdentifier({name: params.sigalg}));
	a.push(new _DERBitString({hex: "00" + params.sighex}));
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.params = params;
};
extendClass(KJUR.asn1.x509.Certificate, KJUR.asn1.ASN1Object);

/**
 * ASN.1 TBSCertificate structure class<br/>
 * @name KJUR.asn1.x509.TBSCertificate
 * @class ASN.1 TBSCertificate structure class
 * @property {Array} params JSON object of parameters
 * @param {Array} params JSON object of TBSCertificate parameters
 * @extends KJUR.asn1.ASN1Object
 * @see KJUR.asn1.x509.Certificate
 *
 * @description
 * <br/>
 * NOTE: TBSCertificate class is updated without backward 
 * compatibility from jsrsasign 9.0.0 asn1x509 2.0.0.
 * Most of methods are removed and parameters can be set
 * by JSON object.
 *
 * @example
 * new TBSCertificate({
 *  version: 3, // this can be omitted, the default is 3.
 *  serial: {hex: "1234..."}, // DERInteger parameter
 *  sigalg: "SHA256withRSA",
 *  issuer: {array:[[{type:'O',value:'Test',ds:'prn'}]]}, // X500Name parameter
 *  notbefore: "151231235959Z", // string, passed to Time
 *  notafter: "251231235959Z", // string, passed to Time
 *  subject: {array:[[{type:'O',value:'Test',ds:'prn'}]]}, // X500Name parameter
 *  sbjpubkey: "-----BEGIN...", // KEYUTIL.getKey pubkey parameter
 *  // As for extension parameters, please see extension class
 *  // All extension parameters need to have "extname" parameter additionaly.
 *  ext:[{ 
 *   extname:"keyUsage",critical:true,
 *   names:["digitalSignature","keyEncipherment"]
 *  },{
 *   extname:"cRLDistributionPoints",
 *   array:[{dpname:{full:[{uri:"http://example.com/a1.crl"}]}}]
 *  }, ...]
 * })
 *
 * var tbsc = new TBSCertificate();
 * tbsc.setByParam({version:3,serial:{hex:'1234...'},...});
 */
KJUR.asn1.x509.TBSCertificate = function(params) {
    KJUR.asn1.x509.TBSCertificate.superclass.constructor.call(this);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier,
	_Time = _KJUR_asn1_x509.Time,
	_X500Name = _KJUR_asn1_x509.X500Name,
	_Extensions = _KJUR_asn1_x509.Extensions,
	_SubjectPublicKeyInfo = _KJUR_asn1_x509.SubjectPublicKeyInfo;

    this.params = null;

    /**
     * get array of ASN.1 object for extensions<br/>
     * @name setByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Array} JSON object of TBSCertificate parameters
     * @example
     * tbsc = new KJUR.asn1.x509.TBSCertificate();
     * tbsc.setByParam({version:3, serial:{hex:'1234...'},...});
     */
    this.setByParam = function(params) {
	this.params = params;
    };

    this.tohex = function() {
	var a = [];
	var params = this.params;

	// X.509v3 default if params.version not defined
	if (params.version != undefined || params.version != 1) {
	    var version = 2; 
	    if (params.version != undefined) version = params.version - 1;
	    var obj = 
		new _DERTaggedObject({obj: new _DERInteger({'int': version})}) 
	    a.push(obj);
	}

	a.push(new _DERInteger(params.serial));
	a.push(new _AlgorithmIdentifier({name: params.sigalg}));
	a.push(new _X500Name(params.issuer));
	a.push(new _DERSequence({array:[new _Time(params.notbefore),
					new _Time(params.notafter)]}));
	a.push(new _X500Name(params.subject));
	a.push(new _SubjectPublicKeyInfo(KEYUTIL.getKey(params.sbjpubkey)));
	if (params.ext !== undefined && params.ext.length > 0) {
	    a.push(new _DERTaggedObject({tag: "a3",
					 obj: new _Extensions(params.ext)}));
	}

	var seq = new KJUR.asn1.DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.x509.TBSCertificate, KJUR.asn1.ASN1Object);

/**
 * Extensions ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.Extensions
 * @class Extensions ASN.1 structure class
 * @param {Array} aParam array of JSON extension parameter
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 9.1.0 asn1x509 2.1.0
 * @see KJUR.asn1.x509.TBSCertificate
 * @see KJUR.asn1.x509.TBSCertList
 * @see KJUR.asn1.csr.CertificationRequestInfo
 * @see KJUR.asn1.x509.PrivateExtension
 * @see KJUR.asn1.ocsp.ResponseData
 * @see KJUR.asn1.ocsp.BasicOCSPResponse 
 *
 * @description
 * This class represents
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.1">
 * Extensions defined in RFC 5280 4.1</a> and
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.1.2.9">
 * 4.1.2.9</a>.
 * <pre>
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 * </pre>
 * <p>NOTE: From jsrsasign 9.1.1, private extension or
 * undefined extension have been supported by
 * {@link KJUR.asn1.x509.PrivateExtension}.</p>
 * 
 * Here is a list of available extensions:
 * <ul>
 * <li>{@link KJUR.asn1.x509.BasicConstraints}</li>
 * <li>{@link KJUR.asn1.x509.KeyUsage}</li>
 * <li>{@link KJUR.asn1.x509.SubjectKeyIdentifier}</li>
 * <li>{@link KJUR.asn1.x509.AuthorityKeyIdentifier}</li>
 * <li>{@link KJUR.asn1.x509.SubjectAltName}</li>
 * <li>{@link KJUR.asn1.x509.IssuerAltName}</li>
 * <li>{@link KJUR.asn1.x509.CRLDistributionPoints}</li>
 * <li>{@link KJUR.asn1.x509.CertificatePolicies}</li>
 * <li>{@link KJUR.asn1.x509.CRLNumber}</li>
 * <li>{@link KJUR.asn1.x509.CRLReason}</li>
 * <li>{@link KJUR.asn1.x509.OCSPNonce}</li>
 * <li>{@link KJUR.asn1.x509.OCSPNoCheck}</li>
 * <li>{@link KJUR.asn1.x509.AdobeTimeStamp}</li>
 * <li>{@link KJUR.asn1.x509.SubjectDirectoryAttributes}</li>
 * <li>{@link KJUR.asn1.x509.PrivateExtension}</li>
 * </ul>
 * You can also use {@link KJUR.asn1.x509.PrivateExtension} object
 * to specify a unsupported extension.
 *
 * @example
 * o = new KJUR.asn1.x509.Extensions([
 *   {extname:"keyUsage",critical:true,names:["digitalSignature"]},
 *   {extname:"subjectAltName",array:[{dns:"example.com"}]},
 *   {extname:"1.2.3.4",extn:{prnstr:"aa"}} // private extension
 * ]);
 * o.tohex() &rarr; "30..."
 */
KJUR.asn1.x509.Extensions = function(aParam) {
    KJUR.asn1.x509.Extensions.superclass.constructor.call(this);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_x509 = _KJUR_asn1.x509;
    this.aParam = [];

    this.setByParam = function(aParam) { this.aParam = aParam; }

    this.tohex = function() {
	var a = [];
	for (var i = 0; i < this.aParam.length; i++) {
	    var param = this.aParam[i];
	    var extname = param.extname;
	    var obj = null;

	    if (param.extn != undefined) {
		obj = new _KJUR_asn1_x509.PrivateExtension(param);
	    } else if (extname == "subjectKeyIdentifier") {
		obj = new _KJUR_asn1_x509.SubjectKeyIdentifier(param);
	    } else if (extname == "keyUsage") {
		obj = new _KJUR_asn1_x509.KeyUsage(param);
	    } else if (extname == "subjectAltName") {
		obj = new _KJUR_asn1_x509.SubjectAltName(param);
	    } else if (extname == "issuerAltName") {
		obj = new _KJUR_asn1_x509.IssuerAltName(param);
	    } else if (extname == "basicConstraints") {
		obj = new _KJUR_asn1_x509.BasicConstraints(param);
	    } else if (extname == "nameConstraints") {
		obj = new _KJUR_asn1_x509.NameConstraints(param);
	    } else if (extname == "cRLDistributionPoints") {
		obj = new _KJUR_asn1_x509.CRLDistributionPoints(param);
	    } else if (extname == "certificatePolicies") {
		obj = new _KJUR_asn1_x509.CertificatePolicies(param);
	    } else if (extname == "authorityKeyIdentifier") {
		obj = new _KJUR_asn1_x509.AuthorityKeyIdentifier(param);
	    } else if (extname == "extKeyUsage") {
		obj = new _KJUR_asn1_x509.ExtKeyUsage(param);
	    } else if (extname == "authorityInfoAccess") {
		obj = new _KJUR_asn1_x509.AuthorityInfoAccess(param);
	    } else if (extname == "cRLNumber") {
		obj = new _KJUR_asn1_x509.CRLNumber(param);
	    } else if (extname == "cRLReason") {
		obj = new _KJUR_asn1_x509.CRLReason(param);
	    } else if (extname == "ocspNonce") {
		obj = new _KJUR_asn1_x509.OCSPNonce(param);
	    } else if (extname == "ocspNoCheck") {
		obj = new _KJUR_asn1_x509.OCSPNoCheck(param);
	    } else if (extname == "adobeTimeStamp") {
		obj = new _KJUR_asn1_x509.AdobeTimeStamp(param);
	    } else if (extname == "subjectDirectoryAttributes") {
		obj = new _KJUR_asn1_x509.SubjectDirectoryAttributes(param);
	    } else {
		throw new Error("extension not supported:"
				+ JSON.stringify(param));
	    }
	    if (obj != null) a.push(obj);
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (aParam != undefined) this.setByParam(aParam);
};
extendClass(KJUR.asn1.x509.Extensions, KJUR.asn1.ASN1Object);


// === END   TBSCertificate ===================================================

// === BEGIN X.509v3 Extensions Related =======================================

/**
 * base Extension ASN.1 structure class
 * @name KJUR.asn1.x509.Extension
 * @class base Extension ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'critical': true})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <pre>
 * Extension  ::=  SEQUENCE  {
 *     extnID      OBJECT IDENTIFIER,
 *     critical    BOOLEAN DEFAULT FALSE,
 *     extnValue   OCTET STRING  }
 * </pre>
 * @example
 */
KJUR.asn1.x509.Extension = function(params) {
    KJUR.asn1.x509.Extension.superclass.constructor.call(this);
    var asn1ExtnValue = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_DERBitString = _KJUR_asn1.DERBitString,
	_DERBoolean = _KJUR_asn1.DERBoolean,
	_DERSequence = _KJUR_asn1.DERSequence;

    this.tohex = function() {
        var asn1Oid = new _DERObjectIdentifier({'oid': this.oid});
        var asn1EncapExtnValue =
            new _DEROctetString({'hex': this.getExtnValueHex()});

        var asn1Array = new Array();
        asn1Array.push(asn1Oid);
        if (this.critical) asn1Array.push(new _DERBoolean());
        asn1Array.push(asn1EncapExtnValue);

        var asn1Seq = new _DERSequence({'array': asn1Array});
        return asn1Seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.critical = false;
    if (params !== undefined) {
        if (params.critical !== undefined) {
            this.critical = params.critical;
        }
    }
};
extendClass(KJUR.asn1.x509.Extension, KJUR.asn1.ASN1Object);

/**
 * KeyUsage ASN.1 structure class
 * @name KJUR.asn1.x509.KeyUsage
 * @class KeyUsage ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'bin': '11', 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @description
 * This class is for <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.3" target="_blank">KeyUsage</a> X.509v3 extension.
 * <pre>
 * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 * KeyUsage ::= BIT STRING {
 *   digitalSignature   (0),
 *   nonRepudiation     (1),
 *   keyEncipherment    (2),
 *   dataEncipherment   (3),
 *   keyAgreement       (4),
 *   keyCertSign        (5),
 *   cRLSign            (6),
 *   encipherOnly       (7),
 *   decipherOnly       (8) }
 * </pre><br/>
 * NOTE: 'names' parameter is supprted since jsrsasign 8.0.14.
 * @example
 * o = new KJUR.asn1.x509.KeyUsage({bin: "11"});
 * o = new KJUR.asn1.x509.KeyUsage({critical: true, bin: "11"});
 * o = new KJUR.asn1.x509.KeyUsage({names: ['digitalSignature', 'keyAgreement']});
 */
KJUR.asn1.x509.KeyUsage = function(params) {
    KJUR.asn1.x509.KeyUsage.superclass.constructor.call(this, params);

    var _Error = Error;

    var _nameValue = {
	digitalSignature:	0,
	nonRepudiation:		1,
	keyEncipherment:	2,
	dataEncipherment:	3,
	keyAgreement:		4,
	keyCertSign:		5,
	cRLSign:		6,
	encipherOnly:		7,
	decipherOnly:		8
    };

    this.getExtnValueHex = function() {
	var binString = this.getBinValue();
        this.asn1ExtnValue = new KJUR.asn1.DERBitString({bin: binString});
        return this.asn1ExtnValue.tohex();
    };

    this.getBinValue = function() {
	var params = this.params;

	if (typeof params != "object" ||
	    (typeof params.names != "object" && typeof params.bin != "string"))
	    throw new _Error("parameter not yet set");

	if (params.names != undefined) {
	    return namearraytobinstr(params.names, _nameValue);
	} else if (params.bin != undefined) {
	    return params.bin;
	} else {
	    throw new _Error("parameter not set properly");
	}
    };

    this.oid = "2.5.29.15";
    if (params !== undefined) this.params = params;
};
extendClass(KJUR.asn1.x509.KeyUsage, KJUR.asn1.x509.Extension);

/**
 * BasicConstraints ASN.1 structure class
 * @name KJUR.asn1.x509.BasicConstraints
 * @class BasicConstraints ASN.1 structure class
 * @param {Array} params JSON object for parameters (ex. {cA:true,critical:true})
 * @extends KJUR.asn1.x509.Extension
 * @see {@link X509#getExtBasicConstraints}
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.9">
 * BasicConstraints extension defined in RFC 5280 4.2.1.9</a>.
 * <pre>
 *  id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
 *  BasicConstraints ::= SEQUENCE {
 *       cA                      BOOLEAN DEFAULT FALSE,
 *       pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 * </pre>
 * Its constructor can have following parameters:
 * <ul>
 * <li>{Boolean}cA - cA flag</li>
 * <li>{Integer}pathLen - pathLen field value</li>
 * <li>{Boolean}critical - critical flag</li>
 * </ul>
 * @example
 * new KJUR.asn1.x509.BasicConstraints({
 *   cA: true,
 *   pathLen: 3,
 *   critical: true
 * })
 */
KJUR.asn1.x509.BasicConstraints = function(params) {
    KJUR.asn1.x509.BasicConstraints.superclass.constructor.call(this, params);
    var _KJUR_asn1 = KJUR.asn1,
	_DERBoolean = _KJUR_asn1.DERBoolean,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence;

    var cA = false;
    var pathLen = -1;

    this.getExtnValueHex = function() {
        var asn1Array = new Array();
        if (this.cA) asn1Array.push(new _DERBoolean());
        if (this.pathLen > -1)
            asn1Array.push(new _DERInteger({'int': this.pathLen}));
        var asn1Seq = new _DERSequence({'array': asn1Array});
        this.asn1ExtnValue = asn1Seq;
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.19";
    this.cA = false;
    this.pathLen = -1;
    if (params !== undefined) {
        if (params.cA !== undefined) {
            this.cA = params.cA;
        }
        if (params.pathLen !== undefined) {
            this.pathLen = params.pathLen;
        }
    }
};
extendClass(KJUR.asn1.x509.BasicConstraints, KJUR.asn1.x509.Extension);

/**
 * CRLDistributionPoints ASN.1 structure class
 * @name KJUR.asn1.x509.CRLDistributionPoints
 * @class CRLDistributionPoints ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'uri': 'http://a.com/', 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @see {@link X509#getExtCRLDistributionPoints}
 * @see {@link KJUR.asn1.x509.DistributionPoint}
 * @see {@link KJUR.asn1.x509.GeneralNames}
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.13">
 * CRLDistributionPoints extension defined in RFC 5280 4.2.1.13</a>.
 * <pre>
 * id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }
 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
 * DistributionPointName ::= CHOICE {
 *      fullName                [0]     GeneralNames,
 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 * </pre>
 * Constructor can have following parameter:
 * <ul>
 * <li>{Array}array - array of {@link KJUR.asn1.x509.DistributionPoint} parameter</li>
 * <li>{Boolean}critical - critical flag</li>
 * </ul>
 * @example
 * new KJUR.asn1.x509.CRLDistributionPoints({
 *   array: [{fulluri: "http://aaa.com/"}, {fulluri: "ldap://aaa.com/"}],
 *   critical: true
 * })
 */
KJUR.asn1.x509.CRLDistributionPoints = function(params) {
    KJUR.asn1.x509.CRLDistributionPoints.superclass.constructor.call(this, params);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509;

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.tohex();
    };

    this.setByDPArray = function(dpArray) {
	var asn1Array = [];
	for (var i = 0; i < dpArray.length; i++) {
	    if (dpArray[i] instanceof KJUR.asn1.ASN1Object) {
		asn1Array.push(dpArray[i]);
	    } else {
		var dp = new _KJUR_asn1_x509.DistributionPoint(dpArray[i]);
		asn1Array.push(dp);
	    }
	}
        this.asn1ExtnValue = new _KJUR_asn1.DERSequence({'array': asn1Array});
    };

    this.setByOneURI = function(uri) {
        var dp1 = new _KJUR_asn1_x509.DistributionPoint({fulluri: uri});
        this.setByDPArray([dp1]);
    };

    this.oid = "2.5.29.31";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setByDPArray(params.array);
        } else if (params.uri !== undefined) {
            this.setByOneURI(params.uri);
        }
    }
};
extendClass(KJUR.asn1.x509.CRLDistributionPoints, KJUR.asn1.x509.Extension);

/**
 * DistributionPoint ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.DistributionPoint
 * @class DistributionPoint ASN.1 structure class
 * @param {Array} params JSON object of parameters (OPTIONAL)
 * @extends KJUR.asn1.ASN1Object
 * @see {@link KJUR.asn1.x509.CRLDistributionPoints}
 * @see {@link KJUR.asn1.x509.DistributionPointName}
 * @see {@link KJUR.asn1.x509.GeneralNames}
 * @see {@link X509#getDistributionPoint}
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.13">
 * DistributionPoint defined in RFC 5280 4.2.1.13</a>.
 * <pre>
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
 * </pre>
 * Constructor can have following parameter:
 * <ul>
 * <li>{String}fulluri - uri string for fullName uri. This has the same meaning for '{dpname: {full: [{uri: "..."]}}'.</li>
 * <li>{Array}dpname - JSON object for {@link KJUR.asn1.x509.DistributionPointName} parameters</li>
 * <li>{DistrubutionPoint}dpobj - {@link KJUR.asn1.x509.DistributionPointName} object (DEPRECATED)</li>
 * </ul>
 * <br/>
 * NOTE1: Parameter "fulluri" and "dpname" supported 
 * since jsrsasign 9.0.0 asn1x509 2.0.0.
 * <br/>
 * NOTE2: The "reasons" and "cRLIssuer" fields are currently
 * not supported.
 * @example
 * new KJUR.asn1.x509.DistributionPoint(
 *   {fulluri: "http://example.com/crl1.crl"})
 * new KJUR.asn1.x509.DistributionPoint(
 *   {dpname: {full: [{uri: "http://example.com/crl1.crl"}]}})
 * new KJUR.asn1.x509.DistributionPoint(
 *   {dpobj: new DistributionPoint(...)})
 */
KJUR.asn1.x509.DistributionPoint = function(params) {
    KJUR.asn1.x509.DistributionPoint.superclass.constructor.call(this);
    var asn1DP = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DistributionPointName = _KJUR_asn1.x509.DistributionPointName;

    this.tohex = function() {
        var seq = new _KJUR_asn1.DERSequence();
        if (this.asn1DP != null) {
            var o1 = new _KJUR_asn1.DERTaggedObject({'explicit': true,
                                                     'tag': 'a0',
                                                     'obj': this.asn1DP});
            seq.appendASN1Object(o1);
        }
        this.hTLV = seq.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
        if (params.dpobj !== undefined) {
            this.asn1DP = params.dpobj;
        } else if (params.dpname !== undefined) {
            this.asn1DP = new _DistributionPointName(params.dpname);
	} else if (params.fulluri !== undefined) {
            this.asn1DP = new _DistributionPointName({full: [{uri: params.fulluri}]});
	}
    }
};
extendClass(KJUR.asn1.x509.DistributionPoint, KJUR.asn1.ASN1Object);

/**
 * DistributionPointName ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.DistributionPointName
 * @class DistributionPointName ASN.1 structure class
 * @param {Array} params JSON object of parameters or GeneralNames object
 * @extends KJUR.asn1.ASN1Object
 * @see {@link KJUR.asn1.x509.CRLDistributionPoints}
 * @see {@link KJUR.asn1.x509.DistributionPoint}
 * @see {@link KJUR.asn1.x509.GeneralNames}
 * @see {@link X509#getDistributionPointName}
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.13">
 * DistributionPointName defined in RFC 5280 4.2.1.13</a>.
 * <pre>
 * DistributionPointName ::= CHOICE {
 *      fullName                [0]     GeneralNames,
 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 * </pre>
 * Constructor can have following parameter:
 * <ul>
 * <li>{String}full - JSON object parameter of {@link KJUR.asn1.x509.GeneralNames} for 'fullName' field</li>
 * <li>{GeneralNames} - {@link KJUR.asn1.x509.GeneralNames} object for 'fullName'</li>
 * </ul>
 * NOTE1: 'full' parameter have been suppored since jsrsasign 9.0.0 asn1x509 2.0.0.
 * <br>
 * NOTE2: The 'nameRelativeToCRLIssuer' field is currently not supported.
 * @example
 * new KJUR.asn1.x509.DistributionPointName({full: <<GeneralNamesParameter>>})
 * new KJUR.asn1.x509.DistributionPointName({full: [{uri: <<CDPURI>>}]})
 * new KJUR.asn1.x509.DistributionPointName({full: [{dn: <<DN Parameter>>}]}
 * new KJUR.asn1.x509.DistributionPointName({full: [{uri: "http://example.com/root.crl"}]})
 * new KJUR.asn1.x509.DistributionPointName({full: [{dn {str: "/C=US/O=Test"}}]})
 * new KJUR.asn1.x509.DistributionPointName(new GeneralNames(...))
 */
KJUR.asn1.x509.DistributionPointName = function(params) {
    KJUR.asn1.x509.DistributionPointName.superclass.constructor.call(this);
    var asn1Obj = null,
	type = null,
	tag = null,
	asn1V = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject;

    this.tohex = function() {
        if (this.type != "full")
            throw new Error("currently type shall be 'full': " + this.type);
        this.asn1Obj = new _DERTaggedObject({'explicit': false,
                                             'tag': this.tag,
                                             'obj': this.asn1V});
        this.hTLV = this.asn1Obj.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
        if (_KJUR_asn1.x509.GeneralNames.prototype.isPrototypeOf(params)) {
            this.type = "full";
            this.tag = "a0";
            this.asn1V = params;
	} else if (params.full !== undefined) {
            this.type = "full";
            this.tag = "a0";
            this.asn1V = new _KJUR_asn1.x509.GeneralNames(params.full);
        } else {
            throw new Error("This class supports GeneralNames only as argument");
        }
    }
};
extendClass(KJUR.asn1.x509.DistributionPointName, KJUR.asn1.ASN1Object);

/**
 * CertificatePolicies ASN.1 structure class
 * @name KJUR.asn1.x509.CertificatePolicies
 * @class CertificatePolicies ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 8.0.23 asn1x509 1.1.12
 * @see KJUR.asn1.x509.CertificatePolicies
 * @see KJUR.asn1.x509.PolicyInformation
 * @see KJUR.asn1.x509.PolicyQualifierInfo
 * @see KJUR.asn1.x509.UserNotice
 * @see KJUR.asn1.x509.NoticeReference
 * @see KJUR.asn1.x509.DisplayText
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
 * CertificatePolicies extension defined in RFC 5280 4.2.1.4</a>.
 * <pre>
 * id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
 * CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 * </pre>
 * Its constructor can have following parameters:
 * <ul>
 * <li>array - array of {@link KJUR.asn1.x509.PolicyInformation} parameter</li>
 * <li>critical - boolean: critical flag</li>
 * </ul>
 * NOTE: Returned JSON value format have been changed without 
 * backward compatibility since jsrsasign 9.0.0 asn1x509 2.0.0.
 * @example
 * e1 = new KJUR.asn1.x509.CertificatePolicies({
 *   array: [
 *     { policyoid: "1.2.3.4.5",
 *       array: [
 *         { cps: "https://example.com/repository" },
 *         { unotice: {
 *           noticeref: { // CA SHOULD NOT use this by RFC
 *             org: {type: "ia5", str: "Sample Org"},
 *             noticenum: [{int: 5}, {hex: "01af"}]
 *           },
 *           exptext: {type: "ia5", str: "Sample Policy"}
 *         }}
 *       ]
 *     }
 *   ],
 *   critical: true
 * });
 */
KJUR.asn1.x509.CertificatePolicies = function(params) {
    KJUR.asn1.x509.CertificatePolicies.superclass.constructor.call(this, params);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_DERSequence = _KJUR_asn1.DERSequence,
	_PolicyInformation = _KJUR_asn1_x509.PolicyInformation;

    this.params = null;

    this.getExtnValueHex = function() {
	var aPI = [];
	for (var i = 0; i < this.params.array.length; i++) {
	    aPI.push(new _PolicyInformation(this.params.array[i]));
	}
	var seq = new _DERSequence({array: aPI});
	this.asn1ExtnValue = seq;
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.32";
    if (params !== undefined) {
	this.params = params;
    }
};
extendClass(KJUR.asn1.x509.CertificatePolicies, KJUR.asn1.x509.Extension);

// ===== BEGIN CertificatePolicies related classes =====
/**
 * PolicyInformation ASN.1 structure class
 * @name KJUR.asn1.x509.PolicyInformation
 * @class PolicyInformation ASN.1 structure class
 * @param {Array} params JSON object of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 8.0.23 asn1x509 1.1.12
 * @see KJUR.asn1.x509.CertificatePolicies
 * @see KJUR.asn1.x509.PolicyInformation
 * @see KJUR.asn1.x509.PolicyQualifierInfo
 * @see KJUR.asn1.x509.UserNotice
 * @see KJUR.asn1.x509.NoticeReference
 * @see KJUR.asn1.x509.DisplayText
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
 * PolicyInformation defined in RFC 5280 4.2.1.4</a>.
 * <pre>
 * PolicyInformation ::= SEQUENCE {
 *      policyIdentifier   CertPolicyId,
 *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                         PolicyQualifierInfo OPTIONAL }
 * CertPolicyId ::= OBJECT IDENTIFIER
 * Its constructor can have following parameters:
 * <ul>
 * <li>{String}policyoid - policy OID (ex. "1.2.3.4.5")</li>
 * <li>{Object}array - array of {@link KJUR.asn1.x509.PolicyQualifierInfo}
 * parameters (OPTIONAL)</li>
 * </ul>
 * @example
 * new KJUR.asn1.x509.PolicyInformation({
 *   policyoid: "1.2.3.4.5",
 *   array: [
 *     { cps: "https://example.com/repository" },
 *     { unotice: {
 *       noticeref: { // CA SHOULD NOT use this by RFC
 *         org: {type: "ia5", str: "Sample Org"},
 *         noticenum: [{int: 5}, {hex: "01af"}]
 *       },
 *       exptext: {type: "ia5", str: "Sample Policy"}
 *     }}
 *   ]
 * })
 */
KJUR.asn1.x509.PolicyInformation = function(params) {
    KJUR.asn1.x509.PolicyInformation.superclass.constructor.call(this,
								 params);
    var _KJUR_asn1 = KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_PolicyQualifierInfo = _KJUR_asn1.x509.PolicyQualifierInfo;

    this.params = null;

    this.tohex = function() {
	if (this.params.policyoid === undefined &&
	    this.params.array === undefined)
	    throw new Error("parameter oid and array missing");

	// policy oid
	var a = [new _DERObjectIdentifier(this.params.policyoid)];

	// array of ASN1Object of PolicyQualifierInfo
	if (this.params.array !== undefined) {
	    var aPQI = [];
	    for (var i = 0; i < this.params.array.length; i++) {
		aPQI.push(new _PolicyQualifierInfo(this.params.array[i]));
	    }
	    if (aPQI.length > 0) {
		a.push(new _DERSequence({array: aPQI}));
	    }
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
	this.params = params;
    }
};
extendClass(KJUR.asn1.x509.PolicyInformation, KJUR.asn1.ASN1Object);

/**
 * PolicyQualifierInfo ASN.1 structure class
 * @name KJUR.asn1.x509.PolicyQualifierInfo
 * @class PolicyQualifierInfo ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 8.0.23 asn1x509 1.1.12
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
 * PolicyQualifierInfo defined in RFC 5280 4.2.1.4</a>.
 * <pre>
 * PolicyQualifierInfo ::= SEQUENCE {
 *      policyQualifierId  PolicyQualifierId,
 *      qualifier          ANY DEFINED BY policyQualifierId }
 * PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 * CPSuri ::= IA5String
 * </pre>
 * Its constructor can have one of following two parameters:
 * <ul>
 * <li>{String}cps - URI string for CPS</li>
 * <li>{Object}unotice - {@link KJUR.asn1.x509.UserNotice} parameter</li>
 * </ul>
 * @example
 * new PolicyQualifierInfo({
 *   cps: "https://example.com/repository/cps"
 * })
 *
 * new PolicyQualifierInfo({
 *   unotice: {
 *     noticeref: { // CA SHOULD NOT use this by RFC
 *       org: {type: "bmp", str: "Sample Org"},
 *       noticenum: [{int: 3}, {hex: "01af"}]
 *     },
 *     exptext: {type: "ia5", str: "Sample Policy"}
 *   }
 * })
 */
KJUR.asn1.x509.PolicyQualifierInfo = function(params) {
    KJUR.asn1.x509.PolicyQualifierInfo.superclass.constructor.call(this,
								   params);
    var _KJUR_asn1 = KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERIA5String = _KJUR_asn1.DERIA5String,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_UserNotice = _KJUR_asn1.x509.UserNotice;

    this.params = null;

    this.tohex = function() {
	if (this.params.cps !== undefined) {
	    var seq = new _DERSequence({array: [
		new _DERObjectIdentifier({oid: '1.3.6.1.5.5.7.2.1'}),
		new _DERIA5String({str: this.params.cps})
	    ]});
	    return seq.tohex();
	}
	if (this.params.unotice != undefined) {
	    var seq = new _DERSequence({array: [
		new _DERObjectIdentifier({oid: '1.3.6.1.5.5.7.2.2'}),
		new _UserNotice(this.params.unotice)
	    ]});
	    return seq.tohex();
	}
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
	this.params = params;
    }
};
extendClass(KJUR.asn1.x509.PolicyQualifierInfo, KJUR.asn1.ASN1Object);


/**
 * UserNotice ASN.1 structure class
 * @name KJUR.asn1.x509.UserNotice
 * @class UserNotice ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 8.0.23 asn1x509 1.1.12
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
 * UserNotice defined in RFC 5280 4.2.1.4</a>.
 * <pre>
 * UserNotice ::= SEQUENCE {
 *      noticeRef        NoticeReference OPTIONAL,
 *      explicitText     DisplayText OPTIONAL }
 * </pre>
 * Its constructor can have following two parameters:
 * <ul>
 * <li>{Object}noticeref - {@link KJUR.asn1.x509.NoticeReference} parameter.
 * This SHALL NOT be set for conforming CA by RFC 5280. (OPTIONAL)</li>
 * <li>{Object}exptext - explicitText value
 * by {@link KJUR.asn1.x509.DisplayText} parameter (OPTIONAL)</li>
 * </ul>
 * @example
 * new UserNotice({
 *   noticeref: {
 *     org: {type: "bmp", str: "Sample Org"},
 *     noticenum: [{int: 3}, {hex: "01af"}]
 *   },
 *   exptext: {type: "ia5", str: "Sample Policy"}
 * })
 */
KJUR.asn1.x509.UserNotice = function(params) {
    KJUR.asn1.x509.UserNotice.superclass.constructor.call(this, params);
    var _DERSequence = KJUR.asn1.DERSequence,
	_DERInteger = KJUR.asn1.DERInteger,
	_DisplayText = KJUR.asn1.x509.DisplayText,
	_NoticeReference = KJUR.asn1.x509.NoticeReference;

    this.params = null;

    this.tohex = function() {
	var a = [];
	if (this.params.noticeref !== undefined) {
	    a.push(new _NoticeReference(this.params.noticeref));
	}
	if (this.params.exptext !== undefined) {
	    a.push(new _DisplayText(this.params.exptext));
	}
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
	this.params = params;
    }
};
extendClass(KJUR.asn1.x509.UserNotice, KJUR.asn1.ASN1Object);

/**
 * NoticeReference ASN.1 structure class
 * @name KJUR.asn1.x509.NoticeReference
 * @class NoticeReference ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 8.0.23 asn1x509 1.1.12
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
 * NoticeReference defined in RFC 5280 4.2.1.4</a>.
 * <pre>
 * NoticeReference ::= SEQUENCE {
 *      organization     DisplayText,
 *      noticeNumbers    SEQUENCE OF INTEGER }
 * </pre>
 * Its constructor can have following two parameters:
 * <ul>
 * <li>{Object}org - organization by {@link KJUR.asn1.x509.DisplayText}
 * parameter.</li>
 * <li>{Object}noticenum - noticeNumbers value by an array of
 * {@link KJUR.asn1.DERInteger} parameter</li>
 * </ul>
 * @example
 * new NoticeReference({
 *   org: {type: "bmp", str: "Sample Org"},
 *   noticenum: [{int: 3}, {hex: "01af"}]
 * })
 */
KJUR.asn1.x509.NoticeReference = function(params) {
    KJUR.asn1.x509.NoticeReference.superclass.constructor.call(this, params);
    var _DERSequence = KJUR.asn1.DERSequence,
	_DERInteger = KJUR.asn1.DERInteger,
	_DisplayText = KJUR.asn1.x509.DisplayText;

    this.params = null;

    this.tohex = function() {
	var a = [];
	if (this.params.org !== undefined) {
	    a.push(new _DisplayText(this.params.org));
	}
	if (this.params.noticenum !== undefined) {
	    var aNoticeNum = [];
	    var aNumParam = this.params.noticenum;
	    for (var i = 0; i < aNumParam.length; i++) {
		aNoticeNum.push(new _DERInteger(aNumParam[i]));
	    }
	    a.push(new _DERSequence({array: aNoticeNum}));
	}
	if (a.length == 0) throw new Error("parameter is empty");
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    }
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
	this.params = params;
    }
};
extendClass(KJUR.asn1.x509.NoticeReference, KJUR.asn1.ASN1Object);

/**
 * DisplayText ASN.1 structure class
 * @name KJUR.asn1.x509.DisplayText
 * @class DisplayText ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.DERAbstractString
 * @since jsrsasign 8.0.23 asn1x509 1.1.12
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
 * DisplayText defined in RFC 5280 4.2.1.4</a>.
 * <pre>
 * -- from RFC 5280 Appendix A
 * DisplayText ::= CHOICE {
 *      ia5String        IA5String      (SIZE (1..200)),
 *      visibleString    VisibleString  (SIZE (1..200)),
 *      bmpString        BMPString      (SIZE (1..200)),
 *      utf8String       UTF8String     (SIZE (1..200)) }
 * </pre>
 * {@link KJUR.asn1.DERAbstractString} parameters and methods
 * can be used.
 * Its constructor can also have following parameter:
 * <ul>
 * <li>{String} type - DirectoryString type of DisplayText.
 * "ia5" for IA5String, "vis" for VisibleString,
 * "bmp" for BMPString and "utf8" for UTF8String.
 * Default is "utf8". (OPTIONAL)</li>
 * </ul>
 * @example
 * new DisplayText({type: "bmp", str: "Sample Org"})
 * new DisplayText({type: "ia5", str: "Sample Org"})
 * new DisplayText({str: "Sample Org"})
 */
KJUR.asn1.x509.DisplayText = function(params) {
    KJUR.asn1.x509.DisplayText.superclass.constructor.call(this, params);

    this.hT = "0c"; // DEFAULT "utf8"

    if (params !== undefined) {
	if (params.type === "ia5") {
	    this.hT = "16";
	} else if (params.type === "vis") {
	    this.hT = "1a";
	} else if (params.type === "bmp") {
	    this.hT = "1e";
	}
    }
};
extendClass(KJUR.asn1.x509.DisplayText, KJUR.asn1.DERAbstractString);
// ===== END CertificatePolicies related classes =====

// =====================================================================
/**
 * NameConstraints ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.NameConstraints
 * @class NameConstraints ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 10.5.16 asn1x509 2.1.13
 * @see X509#getExtNameConstraints
 * @see KJUR.asn1.x509.GeneralSubtree
 * @see KJUR.asn1.x509.GeneralName

 * @description
 * This class provides X.509v3 NameConstraints extension.
 * defined in 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.10">
 * RFC 5280 4.2.1.10</a>.
 * <pre>
 * id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }
 * NameConstraints ::= SEQUENCE {
 *   permittedSubtrees  [0]  GeneralSubtrees OPTIONAL,
 *   excludedSubtrees   [1]  GeneralSubtrees OPTIONAL }
 * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
 * GeneralSubtree ::= SEQUENCE {
 *   base           GeneralName,
 *   minimum   [0]  BaseDistance DEFAULT 0,
 *   maximum   [1]  BaseDistance OPTIONAL }
 * BaseDistance ::= INTEGER (0..MAX)
 * </pre>
 *
 * @example
 * new NameConstraints({permit: [{dns: "example.com"}], critical: true})
 * new NameConstraints({exclude: [{uri: "example.com"}], critical: true})
 * new NameConstraints({exclude: [{dn: "/C=JP/O=T1"}], critical: true})
 * new NameConstraints({
 *   critical: true,
 *   permit: [{dn: "/C=JP/O=T1"}],
 *   exclude: [{dn: "/C=US/O=T1", max: 2}]})
 */
KJUR.asn1.x509.NameConstraints = function(params) {
    KJUR.asn1.x509.NameConstraints.superclass.constructor.call(this, params);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_newObject = _KJUR_asn1.ASN1Util.newObject,
	_GeneralSubtree = _KJUR_asn1_x509.GeneralSubtree;

    this.params = null;

    this.getExtnValueHex = function() {
	var params = this.params;
	var aItem = [];
	if (params.permit != undefined &&
	    params.permit.length != undefined) {
	    var aPermit = [];
	    for (var i = 0; i < params.permit.length; i++) {
		aPermit.push(new _GeneralSubtree(params.permit[i]));
	    }
	    aItem.push({tag: {tagi: "a0", obj: {seq: aPermit}}});
	}

	if (params.exclude != undefined &&
	    params.exclude.length != undefined) {
	    var aExclude = [];
	    for (var i = 0; i < params.exclude.length; i++) {
		aExclude.push(new _GeneralSubtree(params.exclude[i]));
	    }
	    aItem.push({tag: {tagi: "a1", obj: {seq: aExclude}}});
	}

	this.asn1ExtnValue = _newObject({seq: aItem});
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.30";
    if (params !== undefined) this.params = params;
};
extendClass(KJUR.asn1.x509.NameConstraints, KJUR.asn1.x509.Extension);

/**
 * GeneralSubtree ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.GeneralSubtree
 * @class GeneralSubtree ASN.1 structure class
 * @since jsrsasign 10.5.16 asn1x509 2.1.13
 * @see KJUR.asn1.x509.NameConstraints
 * @see KJUR.asn1.x509.GeneralName
 * @see X509#getExtNameConstraints
 * @see X509#getGeneralSubtree
 *
 * @description
 * This class provides a encoder for GeneralSubtree 
 * defined in 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.10">
 * RFC 5280 4.2.1.10</a>. 
 * This will be used for nameConstraints extension.
 * <br>
 * Here is definition of the ASN.1 syntax:
 * <pre>
 * GeneralSubtree ::= SEQUENCE {
 *   base           GeneralName,
 *   minimum   [0]  BaseDistance DEFAULT 0,
 *   maximum   [1]  BaseDistance OPTIONAL }
 * BaseDistance ::= INTEGER (0..MAX)
 * </pre>
 * An argument for constructor is the same as
 * {@link KJUR.asn1.x509.GeneralName} except
 * this has following optional members:
 * <ul>
 * <li>min - {Number} value for the minimum field</li>
 * <li>max - {Number} value for the maximum field</li>
 * </ul>
 * Please note that min and max can't be specified since
 * they are prohibited in RFC 5280.
 *
 * @example
 * new GeneralSubtree({dns: "example.com"})
 * new GeneralSubtree({uri: ".example.com"})
 * new GeneralSubtree({dn: "/C=JP/O=Test1"})
 */
KJUR.asn1.x509.GeneralSubtree = function(params) {
    KJUR.asn1.x509.GeneralSubtree.superclass.constructor.call(this);

    var _KJUR_asn1 = KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_GeneralName = _KJUR_asn1_x509.GeneralName,
	_newObject = _KJUR_asn1.ASN1Util.newObject;

    this.params = null;

    this.setByParam = function(params) {
	this.params = params;
    };

    this.tohex = function() {
	var params = this.params;

	var aItem = [new _GeneralName(params)];
	if (params.min != undefined)
	    aItem.push({tag: {tagi:"80", obj: {"int": params.min}}});
	if (params.max != undefined)
	    aItem.push({tag: {tagi:"81", obj: {"int": params.max}}});

	var dSeq = _newObject({seq: aItem});
	return dSeq.tohex();
    }
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.x509.GeneralSubtree, KJUR.asn1.ASN1Object);

// =====================================================================
/**
 * KeyUsage ASN.1 structure class
 * @name KJUR.asn1.x509.ExtKeyUsage
 * @class ExtKeyUsage ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.x509.Extension
 * @description
 * @example
 * e1 = new KJUR.asn1.x509.ExtKeyUsage({
 *   critical: true,
 *   array: [
 *     {oid: '2.5.29.37.0'},  // anyExtendedKeyUsage
 *     {name: 'clientAuth'},
 *     "1.2.3.4",
 *     "serverAuth"
 *   ]
 * });
 * // id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
 * // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 * // KeyPurposeId ::= OBJECT IDENTIFIER
 */
KJUR.asn1.x509.ExtKeyUsage = function(params) {
    KJUR.asn1.x509.ExtKeyUsage.superclass.constructor.call(this, params);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1;

    this.setPurposeArray = function(purposeArray) {
        this.asn1ExtnValue = new _KJUR_asn1.DERSequence();
        for (var i = 0; i < purposeArray.length; i++) {
            var o = new _KJUR_asn1.DERObjectIdentifier(purposeArray[i]);
            this.asn1ExtnValue.appendASN1Object(o);
        }
    };

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.37";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setPurposeArray(params.array);
        }
    }
};
extendClass(KJUR.asn1.x509.ExtKeyUsage, KJUR.asn1.x509.Extension);

/**
 * AuthorityKeyIdentifier ASN.1 structure class
 * @name KJUR.asn1.x509.AuthorityKeyIdentifier
 * @class AuthorityKeyIdentifier ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {kid: {hex: '89ab...'}, critical: true})
 * @extends KJUR.asn1.x509.Extension
 * @since asn1x509 1.0.8
 * @description
 * This class represents ASN.1 structure for <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.1">AuthorityKeyIdentifier in RFC 5280</a>.
 * Constructor of this class may have following parameters.: 
 * <ul>
 * <li>kid - When key object (RSA, KJUR.crypto.ECDSA/DSA) or PEM string of issuing authority public key or issuer certificate is specified, key identifier will be automatically calculated by the method specified in RFC 5280. When a hexadecimal string is specifed, kid will be set explicitly by it.</li>
 * <li>isscert - When PEM string of authority certificate is specified, both authorityCertIssuer and authorityCertSerialNumber will be set by the certificate.</li>
 * <li>issuer - {@link KJUR.asn1.x509.X500Name} parameter to specify issuer name explicitly.</li>
 * <li>sn - hexadecimal string to specify serial number explicitly.</li>
 * <li>critical - boolean to specify criticality of this extension
 * however conforming CA must mark this extension as non-critical in RFC 5280.</li>
 * </ul>
 * 
 * <pre>
 * d-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 * KeyIdentifier ::= OCTET STRING
 * </pre>
 *
 * @example
 * // 1. kid by key object
 * keyobj = KEYUTIL.getKey("-----BEGIN PUBLIC KEY...");
 * e1 = new KJUR.asn1.x509.AuthorityKeyIdentifier({kid: keyobj});
 * // 2. kid by PEM string of authority certificate or public key
 * e1 = new KJUR.asn1.x509.AuthorityKeyIdentifier({kid: "-----BEGIN..."});
 * // 3. specify kid explicitly
 * e1 = new KJUR.asn1.x509.AuthorityKeyIdentifier({kid: "8ab1d3..."});
 * });
 * // 4. issuer and serial number by auhtority PEM certificate
 * e1 = new KJUR.asn1.x509.AuthorityKeyIdentifier({isscert: "-----BEGIN..."});
 * // 5. issuer and serial number explicitly
 * e1 = new KJUR.asn1.x509.AuthorityKeyIdentifier({
 *   issuer: {ldapstr: "O=test,C=US"},
 *   sn: {hex: "1ac7..."}});
 * // 6. combination
 * e1 = new KJUR.asn1.x509.AuthorityKeyIdentifier({
 *   kid: "-----BEGIN CERTIFICATE...",
 *   isscert: "-----BEGIN CERTIFICATE..."});
 */
KJUR.asn1.x509.AuthorityKeyIdentifier = function(params) {
    KJUR.asn1.x509.AuthorityKeyIdentifier.superclass.constructor.call(this, params);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_GeneralNames = _KJUR_asn1.x509.GeneralNames,
	_isKey = _KJUR.crypto.Util.isKey;

    this.asn1KID = null;
    this.asn1CertIssuer = null; // X500Name hTLV
    this.asn1CertSN = null;

    this.getExtnValueHex = function() {
        var a = new Array();
        if (this.asn1KID)
            a.push(new _DERTaggedObject({'explicit': false,
                                         'tag': '80',
                                         'obj': this.asn1KID}));

        if (this.asn1CertIssuer)
            a.push(new _DERTaggedObject({'explicit': false,
                                         'tag': 'a1',
                                         'obj': new _GeneralNames([{dn: this.asn1CertIssuer}])}));

        if (this.asn1CertSN)
            a.push(new _DERTaggedObject({'explicit': false,
                                         'tag': '82',
                                         'obj': this.asn1CertSN}));

        var asn1Seq = new _KJUR_asn1.DERSequence({'array': a});
        this.asn1ExtnValue = asn1Seq;
        return this.asn1ExtnValue.tohex();
    };

    /**
     * set keyIdentifier value by DEROctetString parameter, key object or PEM file
     * @name setKIDByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier#
     * @function
     * @param {Array} param parameter to set key identifier
     * @since asn1x509 1.0.8
     * @description
     * This method will set keyIdentifier by param.
     * Its key identifier value can be set by following type of param argument:
     * <ul>
     * <li>{str: "123"} - by raw string</li>
     * <li>{hex: "01af..."} - by hexadecimal value</li>
     * <li>RSAKey/DSA/ECDSA - by RSAKey, KJUR.crypto.{DSA/ECDSA} public key object.
     * key identifier value will be calculated by the method described in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2">RFC 5280 4.2.1.2 (1)</a>.
     * </li>
     * <li>certificate PEM string - extract subjectPublicKeyInfo from specified PEM
     * certificate and
     * key identifier value will be calculated by the method described in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2">RFC 5280 4.2.1.2 (1)</a>.
     * <li>PKCS#1/#8 public key PEM string - pem will be converted to a key object and
     * to PKCS#8 ASN.1 structure then calculate 
     * a key identifier value will be calculated by the method described in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2">RFC 5280 4.2.1.2 (1)</a>.
     * </ul>
     *
     * NOTE1: Automatic key identifier calculation is supported
     * since jsrsasign 8.0.16.
     *
     * @see KEYUTIL.getKeyID
     * 
     * @example
     * o = new KJUR.asn1.x509.AuthorityKeyIdentifier();
     * // set by hexadecimal string
     * o.setKIDByParam({hex: '1ad9...'});
     * // set by SubjectPublicKeyInfo of PEM certificate string
     * o.setKIDByParam("-----BEGIN CERTIFICATE...");
     * // set by PKCS#8 PEM public key string
     * o.setKIDByParam("-----BEGIN PUBLIC KEY...");
     * // set by public key object
     * pubkey = KEYUTIL.getKey("-----BEGIN CERTIFICATE...");
     * o.setKIDByParam(pubkey);
     */
    this.setKIDByParam = function(param) {
	if (param.str !== undefined ||
	    param.hex !== undefined) {
	    this.asn1KID = new KJUR.asn1.DEROctetString(param);
	} else if ((typeof param === "object" &&
		    KJUR.crypto.Util.isKey(param)) ||
		   (typeof param === "string" &&
		    param.indexOf("BEGIN ") != -1)) {

	    var keyobj = param;
	    if (typeof param === "string") {
		keyobj = KEYUTIL.getKey(param);
	    }

	    var kid = KEYUTIL.getKeyID(keyobj);
	    this.asn1KID = new KJUR.asn1.DEROctetString({hex: kid});
	}
    };

    /**
     * set authorityCertIssuer value by X500Name parameter
     * @name setCertIssuerByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier#
     * @function
     * @param {Array} param parameter to set issuer name
     * @since asn1x509 1.0.8
     * @description
     * This method will set authorityCertIssuer name by param.
     * Issuer name can be set by following type of param argument:
     * <ul>
     * <li>str/ldapstr/hex/certsubject/certissuer - 
     * set issuer by {@link KJUR.asn1.x509.X500Name}
     * object with specified parameters.</li>
     * <li>PEM CERTIFICATE STRING - extract its subject name from 
     * specified issuer PEM certificate and set.
     * </ul>
     * NOTE1: Automatic authorityCertIssuer setting by certificate
     * is supported since jsrsasign 8.0.16.
     *
     * @see KJUR.asn1.x509.X500Name
     * @see KJUR.asn1.x509.GeneralNames
     * @see X509.getSubjectHex
     *
     * @example
     * var o = new KJUR.asn1.x509.AuthorityKeyIdentifier();
     * // 1. set it by string
     * o.setCertIssuerByParam({str: '/C=US/O=Test'});
     * // 2. set it by issuer PEM certificate
     * o.setCertIssuerByParam("-----BEGIN CERTIFICATE...");
     *
     */
    this.setCertIssuerByParam = function(param) {
	if (param.str !== undefined ||
	    param.ldapstr !== undefined ||
	    param.hex !== undefined ||
	    param.certsubject !== undefined ||
	    param.certissuer !== undefined) {
            this.asn1CertIssuer = new KJUR.asn1.x509.X500Name(param);
	} else if (typeof param === "string" &&
		   param.indexOf("BEGIN ") != -1 &&
		   param.indexOf("CERTIFICATE") != -1) {
            this.asn1CertIssuer = new KJUR.asn1.x509.X500Name({certissuer: param});
	}
    };

    /**
     * set authorityCertSerialNumber value
     * @name setCertSerialNumberByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier#
     * @function
     * @param {Object} param parameter to set serial number
     * @since asn1x509 1.0.8
     * @description
     * This method will set authorityCertSerialNumber by param.
     * Serial number can be set by following type of param argument:
     *
     * <ul>
     * <li>{int: 123} - by integer value</li>
     * <li>{hex: "01af"} - by hexadecimal integer value</li>
     * <li>{bigint: new BigInteger(...)} - by hexadecimal integer value</li>
     * <li>PEM CERTIFICATE STRING - extract serial number from issuer certificate and
     * set serial number.
     * 
     * NOTE1: Automatic authorityCertSerialNumber setting by certificate
     * is supported since jsrsasign 8.0.16.
     *
     * @see X509.getSerialNumberHex
     */
    this.setCertSNByParam = function(param) {
	if (param.str !== undefined ||
	    param.bigint !== undefined ||
	    param.hex !== undefined) {
            this.asn1CertSN = new KJUR.asn1.DERInteger(param);
	} else if (typeof param === "string" &&
		   param.indexOf("BEGIN ") != -1 &&
		   param.indexOf("CERTIFICATE")) {

            var x = new X509();
            x.readCertPEM(param);
	    var sn = x.getSerialNumberHex();
	    this.asn1CertSN = new KJUR.asn1.DERInteger({hex: sn});
	}
    };

    this.oid = "2.5.29.35";
    if (params !== undefined) {
        if (params.kid !== undefined) {
            this.setKIDByParam(params.kid);
        }
        if (params.issuer !== undefined) {
            this.setCertIssuerByParam(params.issuer);
        }
        if (params.sn !== undefined) {
            this.setCertSNByParam(params.sn);
        }

	if (params.issuersn !== undefined &&
	    typeof params.issuersn === "string" &&
	    params.issuersn.indexOf("BEGIN ") != -1 &&
	    params.issuersn.indexOf("CERTIFICATE")) {
	    this.setCertSNByParam(params.issuersn);
	    this.setCertIssuerByParam(params.issuersn);
	}
    }
};
extendClass(KJUR.asn1.x509.AuthorityKeyIdentifier, KJUR.asn1.x509.Extension);

/**
 * SubjectKeyIdentifier extension ASN.1 structure class
 * @name KJUR.asn1.x509.SubjectKeyIdentifier
 * @class SubjectKeyIdentifier ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {kid: {hex: '89ab...'}, critical: true})
 * @extends KJUR.asn1.x509.Extension
 * @since asn1x509 1.1.7 jsrsasign 8.0.14
 * @description
 * This class represents ASN.1 structure for 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2">
 * SubjectKeyIdentifier in RFC 5280</a>.
 * Constructor of this class may have following parameters:
 * <ul>
 * <li>kid - When key object (RSA, KJUR.crypto.ECDSA/DSA) or PEM string of subject public key or certificate is specified, key identifier will be automatically calculated by the method specified in RFC 5280. When a hexadecimal string is specifed, kid will be set explicitly by it.</li>
 * <li>critical - boolean to specify criticality of this extension
 * however conforming CA must mark this extension as non-critical in RFC 5280.</li>
 * </ul>
 * <pre>
 * d-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }
 * SubjectKeyIdentifier ::= KeyIdentifier
 * KeyIdentifier ::= OCTET STRING
 * </pre>
 *
 * @example
 * // set by hexadecimal string
 * e = new KJUR.asn1.x509.SubjectKeyIdentifier({kid: {hex: '89ab'}});
 * // set by PEM public key or certificate string
 * e = new KJUR.asn1.x509.SubjectKeyIdentifier({kid: "-----BEGIN CERTIFICATE..."});
 * // set by public key object
 * pubkey = KEYUTIL.getKey("-----BEGIN CERTIFICATE...");
 * e = new KJUR.asn1.x509.SubjectKeyIdentifier({kid: pubkey});
 */
KJUR.asn1.x509.SubjectKeyIdentifier = function(params) {
    KJUR.asn1.x509.SubjectKeyIdentifier.superclass.constructor.call(this, params);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DEROctetString = _KJUR_asn1.DEROctetString;

    this.asn1KID = null;

    this.getExtnValueHex = function() {
        this.asn1ExtnValue = this.asn1KID;
        return this.asn1ExtnValue.tohex();
    };

    /**
     * set keyIdentifier value by DEROctetString parameter, key object or PEM file
     * @name setKIDByParam
     * @memberOf KJUR.asn1.x509.SubjectKeyIdentifier#
     * @function
     * @param {Array} param array of {@link KJUR.asn1.DERInteger} parameter
     * @since asn1x509 1.1.7 jsrsasign 8.0.14
     * @description
     * <ul>
     * <li>{str: "123"} - by raw string</li>
     * <li>{hex: "01af..."} - by hexadecimal value</li>
     * <li>RSAKey/DSA/ECDSA - by RSAKey, KJUR.crypto.{DSA/ECDSA} public key object.
     * key identifier value will be calculated by the method described in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2">RFC 5280 4.2.1.2 (1)</a>.
     * </li>
     * <li>certificate PEM string - extract subjectPublicKeyInfo from specified PEM
     * certificate and
     * key identifier value will be calculated by the method described in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2">RFC 5280 4.2.1.2 (1)</a>.
     * <li>PKCS#1/#8 public key PEM string - pem will be converted to a key object and
     * to PKCS#8 ASN.1 structure then calculate 
     * a key identifier value will be calculated by the method described in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2">RFC 5280 4.2.1.2 (1)</a>.
     * </ul>
     *
     * NOTE1: Automatic key identifier calculation is supported
     * since jsrsasign 8.0.16.
     *
     * @see KEYUTIL.getKeyID
     *
     * @example
     * o = new KJUR.asn1.x509.SubjectKeyIdentifier();
     * // set by hexadecimal string
     * o.setKIDByParam({hex: '1ad9...'});
     * // set by SubjectPublicKeyInfo of PEM certificate string
     * o.setKIDByParam("-----BEGIN CERTIFICATE...");
     * // set by PKCS#8 PEM public key string
     * o.setKIDByParam("-----BEGIN PUBLIC KEY...");
     * // set by public key object
     * pubkey = KEYUTIL.getKey("-----BEGIN CERTIFICATE...");
     * o.setKIDByParam(pubkey);
     */
    this.setKIDByParam = function(param) {
	if (param.str !== undefined ||
	    param.hex !== undefined) {
	    this.asn1KID = new _DEROctetString(param);
	} else if ((typeof param === "object" &&
		    KJUR.crypto.Util.isKey(param)) ||
		   (typeof param === "string" &&
		    param.indexOf("BEGIN") != -1)) {

	    var keyobj = param;
	    if (typeof param === "string") {
		keyobj = KEYUTIL.getKey(param);
	    }

	    var kid = KEYUTIL.getKeyID(keyobj);
	    this.asn1KID = new KJUR.asn1.DEROctetString({hex: kid});
	}
    };

    this.oid = "2.5.29.14";
    if (params !== undefined) {
	if (params.kid !== undefined) {
	    this.setKIDByParam(params.kid);
	}
    }
};
extendClass(KJUR.asn1.x509.SubjectKeyIdentifier, KJUR.asn1.x509.Extension);

/**
 * AuthorityInfoAccess ASN.1 structure class
 * @name KJUR.asn1.x509.AuthorityInfoAccess
 * @class AuthorityInfoAccess ASN.1 structure class
 * @param {Array} params JSON object of AuthorityInfoAccess parameters
 * @extends KJUR.asn1.x509.Extension
 * @since asn1x509 1.0.8
 * @see {@link X509#getExtAuthorityInfoAccess}
 * @description
 * This class represents 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.2.1">
 * AuthorityInfoAccess extension defined in RFC 5280 4.2.2.1</a>.
 * <pre>
 * id-pe OBJECT IDENTIFIER  ::=  { id-pkix 1 }
 * id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
 * AuthorityInfoAccessSyntax  ::=
 *         SEQUENCE SIZE (1..MAX) OF AccessDescription
 * AccessDescription  ::=  SEQUENCE {
 *         accessMethod          OBJECT IDENTIFIER,
 *         accessLocation        GeneralName  }
 * id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
 * id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
 * id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 * </pre>
 * NOTE: Acceptable parameters have been changed since
 * from jsrsasign 9.0.0 asn1x509 2.0.0.
 * Parameter generated by {@link X509#getAuthorityInfoAccess}
 * can be accepted as a argument of this constructor.
 * @example
 * e1 = new KJUR.asn1.x509.AuthorityInfoAccess({
 *   array: [
 *     {ocsp: 'http://ocsp.example.org'},
 *     {caissuer: 'https://repository.example.org/aaa.crt'}
 *   ]
 * });
 */
KJUR.asn1.x509.AuthorityInfoAccess = function(params) {
    KJUR.asn1.x509.AuthorityInfoAccess.superclass.constructor.call(this, params);

    this.setAccessDescriptionArray = function(aParam) {
        var aASN1 = new Array(),
	    _KJUR = KJUR,
	    _KJUR_asn1 = _KJUR.asn1,
	    _DERSequence = _KJUR_asn1.DERSequence,
	    _DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	    _GeneralName = _KJUR_asn1.x509.GeneralName;

        for (var i = 0; i < aParam.length; i++) {
	    var adseq;
	    var adparam = aParam[i];

	    if (adparam.ocsp !== undefined) {
		adseq = new _DERSequence({array: [
		    new _DERObjectIdentifier({oid: "1.3.6.1.5.5.7.48.1"}),
		    new _GeneralName({uri: adparam.ocsp})
		]});
	    } else if (adparam.caissuer !== undefined) {
		adseq = new _DERSequence({array: [
		    new _DERObjectIdentifier({oid: "1.3.6.1.5.5.7.48.2"}),
		    new _GeneralName({uri: adparam.caissuer})
		]});
	    } else {
		throw new Error("unknown AccessMethod parameter: " +
				JSON.stringify(adparam));
	    }
	    aASN1.push(adseq);
        }
        this.asn1ExtnValue = new _DERSequence({'array':aASN1});
    };

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "1.3.6.1.5.5.7.1.1";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setAccessDescriptionArray(params.array);
        }
    }
};
extendClass(KJUR.asn1.x509.AuthorityInfoAccess, KJUR.asn1.x509.Extension);

/**
 * SubjectAltName ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.SubjectAltName
 * @class SubjectAltName ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 6.2.3 asn1x509 1.0.19
 * @see KJUR.asn1.x509.GeneralNames
 * @see KJUR.asn1.x509.GeneralName
 * @description
 * This class provides X.509v3 SubjectAltName extension.
 * <pre>
 * id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
 * SubjectAltName ::= GeneralNames
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 * GeneralName ::= CHOICE {
 *   otherName                  [0] OtherName,
 *   rfc822Name                 [1] IA5String,
 *   dNSName                    [2] IA5String,
 *   x400Address                [3] ORAddress,
 *   directoryName              [4] Name,
 *   ediPartyName               [5] EDIPartyName,
 *   uniformResourceIdentifier  [6] IA5String,
 *   iPAddress                  [7] OCTET STRING,
 *   registeredID               [8] OBJECT IDENTIFIER }
 * </pre>
 * @example
 * e1 = new KJUR.asn1.x509.SubjectAltName({
 *   critical: true,
 *   array: [{uri: 'http://aaa.com/'}, {uri: 'http://bbb.com/'}]
 * });
 */
KJUR.asn1.x509.SubjectAltName = function(params) {
    KJUR.asn1.x509.SubjectAltName.superclass.constructor.call(this, params)

    this.setNameArray = function(paramsArray) {
	this.asn1ExtnValue = new KJUR.asn1.x509.GeneralNames(paramsArray);
    };

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.17";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setNameArray(params.array);
        }
    }
};
extendClass(KJUR.asn1.x509.SubjectAltName, KJUR.asn1.x509.Extension);

/**
 * IssuerAltName ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.IssuerAltName
 * @class IssuerAltName ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 6.2.3 asn1x509 1.0.19
 * @see KJUR.asn1.x509.GeneralNames
 * @see KJUR.asn1.x509.GeneralName
 * @description
 * This class provides X.509v3 IssuerAltName extension.
 * <pre>
 * id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 18 }
 * IssuerAltName ::= GeneralNames
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 * GeneralName ::= CHOICE {
 *   otherName                  [0] OtherName,
 *   rfc822Name                 [1] IA5String,
 *   dNSName                    [2] IA5String,
 *   x400Address                [3] ORAddress,
 *   directoryName              [4] Name,
 *   ediPartyName               [5] EDIPartyName,
 *   uniformResourceIdentifier  [6] IA5String,
 *   iPAddress                  [7] OCTET STRING,
 *   registeredID               [8] OBJECT IDENTIFIER }
 * </pre>
 * @example
 * e1 = new KJUR.asn1.x509.IssuerAltName({
 *   critical: true,
 *   array: [{uri: 'http://aaa.com/'}, {uri: 'http://bbb.com/'}]
 * });
 */
KJUR.asn1.x509.IssuerAltName = function(params) {
    KJUR.asn1.x509.IssuerAltName.superclass.constructor.call(this, params)

    this.setNameArray = function(paramsArray) {
	this.asn1ExtnValue = new KJUR.asn1.x509.GeneralNames(paramsArray);
    };

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.18";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setNameArray(params.array);
        }
    }
};
extendClass(KJUR.asn1.x509.IssuerAltName, KJUR.asn1.x509.Extension);

/**
 * SubjectDirectoryAttributes ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.SubjectDirectoryAttributes
 * @class SubjectDirectoryAttributes ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 10.1.9 asn1x509 2.1.7
 * @description
 * This class provides X.509v3 SubjectDirectoryAttributes extension
 * defined in <a href="https://tools.ietf.org/html/rfc3739#section-3.3.2">
 * RFC 3739 Qualified Certificate Profile section 3.3.2</a>.
 * <pre>
 * SubjectDirectoryAttributes ::= Attributes
 * Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
 * Attribute ::= SEQUENCE {
 *   type AttributeType 
 *   values SET OF AttributeValue }
 * AttributeType ::= OBJECT IDENTIFIER
 * AttributeValue ::= ANY DEFINED BY AttributeType
 * </pre>
 * @example
 * e1 = new KJUR.asn1.x509.SubjectDirectoryAttributes({
 *   extname: "subjectDirectoryAttributes",
 *   array: [
 *     { attr: "dateOfBirth", str: "19701231230000Z" },
 *     { attr: "placeOfBirth", str: "Tokyo" },
 *     { attr: "gender", str: "F" },
 *     { attr: "countryOfCitizenship", str: "JP" },
 *     { attr: "countryOfResidence", str: "JP" }
 *   ]
 * });
 */
KJUR.asn1.x509.SubjectDirectoryAttributes = function(params) {
    KJUR.asn1.x509.SubjectDirectoryAttributes.superclass.constructor.call(this, params);
    var _KJUR_asn1 = KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_newObject = _KJUR_asn1.ASN1Util.newObject,
	_name2oid = _KJUR_asn1.x509.OID.name2oid;

    this.params = null;

    this.getExtnValueHex = function() {
	var a = [];
	for (var i = 0; i < this.params.array.length; i++) {
	    var pAttr = this.params.array[i];

	    var newparam = {
		"seq": [
		    {"oid": "1.2.3.4"},
		    {"set": [{"utf8str": "DE"}]}
		]
	    };

	    if (pAttr.attr == "dateOfBirth") {
		newparam.seq[0].oid = _name2oid(pAttr.attr);
		newparam.seq[1].set[0] = {"gentime": pAttr.str};
	    } else if (pAttr.attr == "placeOfBirth") {
		newparam.seq[0].oid = _name2oid(pAttr.attr);
		newparam.seq[1].set[0] = {"utf8str": pAttr.str};
	    } else if (pAttr.attr == "gender") {
		newparam.seq[0].oid = _name2oid(pAttr.attr);
		newparam.seq[1].set[0] = {"prnstr": pAttr.str};
	    } else if (pAttr.attr == "countryOfCitizenship") {
		newparam.seq[0].oid = _name2oid(pAttr.attr);
		newparam.seq[1].set[0] = {"prnstr": pAttr.str};
	    } else if (pAttr.attr == "countryOfResidence") {
		newparam.seq[0].oid = _name2oid(pAttr.attr);
		newparam.seq[1].set[0] = {"prnstr": pAttr.str};
	    } else {
		throw new Error("unsupported attribute: " + pAttr.attr);
	    }
	    a.push(new _newObject(newparam));
	}
	var seq = new _DERSequence({array: a});
	this.asn1ExtnValue = seq;
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.9";
    if (params !== undefined) {
	this.params = params;
    }
};
extendClass(KJUR.asn1.x509.SubjectDirectoryAttributes, KJUR.asn1.x509.Extension);


/**
 * priavte extension ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.PrivateExtension
 * @class private extension ASN.1 structure class
 * @param {Array} params JSON object of private extension
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 9.1.1 asn1x509 
 * @see KJUR.asn1.ASN1Util.newObject
 *
 * @description
 * This class is to represent private extension or 
 * unsupported extension. 
 * <pre>
 * Extension  ::=  SEQUENCE  {
 *      extnID      OBJECT IDENTIFIER,
 *      critical    BOOLEAN DEFAULT FALSE,
 *      extnValue   OCTET STRING }
 * </pre>
 * Following properties can be set for JSON parameter:
 * <ul>
 * <li>{String}extname - string of OID or predefined extension name</li>
 * <li>{Boolean}critical - critical flag</li>
 * <li>{Object}extn - hexadecimal string or 
 * of {@link KJUR.asn1.ASN1Util.newObject} 
 * JSON parameter for extnValue field</li>
 * </li>
 * </ul>
 *
 * @example
 * // extn by hexadecimal
 * new KJUR.asn1.x509.PrivateExtension({
 *   extname: "1.2.3.4",
 *   critical: true,
 *   extn: "13026161" // means PrintableString "aa"
 * });
 *
 * // extn by JSON parameter
 * new KJUR.asn1.x509.PrivateExtension({
 *   extname: "1.2.3.5",
 *   extn: {seq: [{prnstr:"abc"},{utf8str:"def"}]}
 * });
 */
KJUR.asn1.x509.PrivateExtension = function(params) {
    KJUR.asn1.x509.PrivateExtension.superclass.constructor.call(this, params)

    var _KJUR = KJUR,
	_isHex = _KJUR.lang.String.isHex,
	_KJUR_asn1 = _KJUR.asn1,
	_name2oid = _KJUR_asn1.x509.OID.name2oid,
	_newObject = _KJUR_asn1.ASN1Util.newObject;

    this.params = null;

    this.setByParam = function(params) {
	this.oid = _name2oid(params.extname);
	this.params = params;
    };

    this.getExtnValueHex = function() {
	if (this.params.extname == undefined ||
	    this.params.extn == undefined) {
	    throw new Error("extname or extnhex not specified");
	}

	var extn = this.params.extn;
	if (typeof extn == "string" && _isHex(extn)) {
	    return extn;
	} else if (typeof extn == "object") {
	    try {
		return _newObject(extn).tohex();
	    } catch(ex) {}
	}
	throw new Error("unsupported extn value");
    };

    if (params != undefined) {
	this.setByParam(params);
    }
};
extendClass(KJUR.asn1.x509.PrivateExtension, KJUR.asn1.x509.Extension);

// === END   X.509v3 Extensions Related =======================================

// === BEGIN CRL Related ===================================================
/**
 * X.509 CRL class to sign and generate hex encoded CRL<br/>
 * @name KJUR.asn1.x509.CRL
 * @class X.509 CRL class to sign and generate hex encoded certificate
 * @property {Array} params JSON object of parameters
 * @param {Array} params JSON object of CRL parameters
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 * @see KJUR.asn1.x509.TBSCertList
 * 
 * @description
 * This class represents CertificateList ASN.1 structur of X.509 CRL
 * defined in <a href="https://tools.ietf.org/html/rfc5280#section-5.1">
 * RFC 5280 5.1</a>
 * <pre>
 * CertificateList  ::=  SEQUENCE  {
 *     tbsCertList          TBSCertList,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING  }
 * </pre>
 * NOTE: CRL class is updated without backward 
 * compatibility from jsrsasign 9.1.0 asn1x509 2.1.0.
 * Most of methods are removed and parameters can be set
 * by JSON object.
 * <br/>
 * Constructor of this class can accept all
 * parameters of {@link KJUR.asn1.x509.TBSCertList}.
 * It also accept following parameters additionally:
 * <ul>
 * <li>{TBSCertList}tbsobj (OPTION) - 
 * specifies {@link KJUR.asn1.x509.TBSCertList} 
 * object to be signed if needed. 
 * When this isn't specified, 
 * this will be set from other parametes of TBSCertList.</li>
 * <li>{Object}cakey (OPTION) - specifies CRL signing private key.
 * Parameter "cakey" or "sighex" shall be specified. Following
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
 * var crl = new KJUR.asn1.x509.CRL({
 *  sigalg: "SHA256withRSA",
 *  issuer: {str:'/C=JP/O=Test1'},
 *  thisupdate: "200821235959Z",
 *  nextupdate: "200828235959Z", // OPTION
 *  revcert: [{sn: {hex: "12ab"}, date: "200401235959Z"}],
 *  ext: [
 *   {extname: "cRLNumber", num: {'int': 8}},
 *   {extname: "authorityKeyIdentifier", "kid": {hex: "12ab"}}
 *  ],
 *  cakey: prvkey
 * });
 * crl.gettohex() &rarr; "30..."
 * crl.getPEM() &rarr; "-----BEGIN X509 CRL..."
 */
KJUR.asn1.x509.CRL = function(params) {
    KJUR.asn1.x509.CRL.superclass.constructor.call(this);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERBitString = _KJUR_asn1.DERBitString,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier,
	_TBSCertList = _KJUR_asn1_x509.TBSCertList;

    this.params = undefined;

    this.setByParam = function(params) {
	this.params = params;
    };

    /**
     * sign CRL<br/>
     * @name sign
     * @memberOf KJUR.asn1.x509.CRL#
     * @function
     * @description
     * This method signs TBSCertList with a specified 
     * private key and algorithm by 
     * this.params.cakey and this.params.sigalg parameter.
     * @example
     * crl = new KJUR.asn1.x509.CRL({..., cakey:prvkey});
     * crl.sign()
     */
    this.sign = function() {
	var hTBSCL = (new _TBSCertList(this.params)).tohex();
	var sig = new KJUR.crypto.Signature({alg: this.params.sigalg});
	sig.init(this.params.cakey);
	sig.updateHex(hTBSCL);
	var sighex = sig.sign();
	this.params.sighex = sighex;
    };

    /**
     * get PEM formatted CRL string after signed<br/>
     * @name getPEM
     * @memberOf KJUR.asn1.x509.CRL#
     * @function
     * @return PEM formatted string of CRL
     * @since jsrsasign 9.1.0 asn1hex 2.1.0
     * @description
     * This method returns a string of PEM formatted 
     * CRL.
     * @example
     * crl = new KJUR.asn1.x509.CRL({...});
     * crl.getPEM() &rarr;
     * "-----BEGIN X509 CRL-----\r\n..."
     */
    this.getPEM = function() {
	return hextopem(this.tohex(), "X509 CRL");
    };

    this.tohex = function() {
	var params = this.params;

	if (params.tbsobj == undefined) {
	    params.tbsobj = new _TBSCertList(params);
	}

	if (params.sighex == undefined && params.cakey != undefined) {
	    this.sign();
	}

	if (params.sighex == undefined) {
	    throw new Error("sighex or cakey parameter not defined");
	}
	
	var a = [];
	a.push(params.tbsobj);
	a.push(new _AlgorithmIdentifier({name: params.sigalg}));
	a.push(new _DERBitString({hex: "00" + params.sighex}));
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.params = params;
};
extendClass(KJUR.asn1.x509.CRL, KJUR.asn1.ASN1Object);

/**
 * ASN.1 TBSCertList ASN.1 structure class for CRL<br/>
 * @name KJUR.asn1.x509.TBSCertList
 * @class TBSCertList ASN.1 structure class for CRL
 * @property {Array} params JSON object of parameters
 * @param {Array} params JSON object of TBSCertList parameters
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 *
 * @description
 * This class represents TBSCertList of CRL defined in
 * <a href="https://tools.ietf.org/html/rfc5280#section-5.1">
 * RFC 5280 5.1</a>.
 * <pre>
 * TBSCertList  ::=  SEQUENCE  {
 *       version                 Version OPTIONAL,
 *                                    -- if present, MUST be v2
 *       signature               AlgorithmIdentifier,
 *       issuer                  Name,
 *       thisUpdate              Time,
 *       nextUpdate              Time OPTIONAL,
 *       revokedCertificates     SEQUENCE OF SEQUENCE  {
 *            userCertificate         CertificateSerialNumber,
 *            revocationDate          Time,
 *            crlEntryExtensions      Extensions OPTIONAL
 *                                     -- if present, version MUST be v2
 *                                 }  OPTIONAL,
 *       crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 * }
 * </pre>
 * NOTE: TBSCertList class is updated without backward 
 * compatibility from jsrsasign 9.1.0 asn1x509 2.1.0.
 * Most of methods are removed and parameters can be set
 * by JSON object.
 * <br/>
 * Constructor of this class may have following parameters:
 * <ul>
 * <li>{Integer}version (OPTION) - version number. Omitted by default.</li>
 * <li>{String}sigalg - signature algorithm name</li>
 * <li>{Array}issuer - issuer parameter of {@link KJUR.asn1.x509.X500Name}</li>
 * <li>{String}thisupdate - thisUpdate field value</li>
 * <li>{String}nextupdate (OPTION) - thisUpdate field value</li>
 * <li>{Array}revcert (OPTION) - revokedCertificates field value as array
 *   Its element may have following property:
 *   <ul>
 *   <li>{Array}sn - serialNumber of userCertificate field specified
 *   by {@link KJUR.asn1.DERInteger}</li>
 *   <li>{String}date - revocationDate field specified by
 *   a string of {@link KJUR.asn1.x509.Time} parameter</li>
 *   <li>{Array}ext (OPTION) - array of CRL entry extension parameter</li>
 *   </ul>
 * </li>
 * </ul>
 * 
 * @example
 * var o = new KJUR.asn1.x509.TBSCertList({
 *  sigalg: "SHA256withRSA",
 *  issuer: {array: [[{type:'C',value:'JP',ds:'prn'}],
 *                   [{type:'O',value:'T1',ds:'prn'}]]},
 *  thisupdate: "200821235959Z",
 *  nextupdate: "200828235959Z", // OPTION
 *  revcert: [
 *   {sn: {hex: "12ab"}, date: "200401235959Z", ext: [{extname: "cRLReason", code:1}]},
 *   {sn: {hex: "12bc"}, date: "200405235959Z", ext: [{extname: "cRLReason", code:2}]}
 *  ],
 *  ext: [
 *   {extname: "cRLNumber", num: {'int': 8}},
 *   {extname: "authorityKeyIdentifier", "kid": {hex: "12ab"}}
 *  ]
 * });
 * o.tohex() &rarr; "30..."
 */
KJUR.asn1.x509.TBSCertList = function(params) {
    KJUR.asn1.x509.TBSCertList.superclass.constructor.call(this);
    var	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier,
	_Time = _KJUR_asn1_x509.Time,
	_Extensions = _KJUR_asn1_x509.Extensions,
	_X500Name = _KJUR_asn1_x509.X500Name;
    this.params = null;

    /**
     * get array of ASN.1 object for extensions<br/>
     * @name setByParam
     * @memberOf KJUR.asn1.x509.TBSCertList#
     * @function
     * @param {Array} JSON object of TBSCertList parameters
     * @example
     * tbsc = new KJUR.asn1.x509.TBSCertificate();
     * tbsc.setByParam({version:3, serial:{hex:'1234...'},...});
     */
    this.setByParam = function(params) {
	this.params = params;
    };

    /**
     * get DERSequence for revokedCertificates<br/>
     * @name getRevCertSequence
     * @memberOf KJUR.asn1.x509.TBSCertList#
     * @function
     * @return {@link KJUR.asn1.DERSequence} of revokedCertificates
     */
    this.getRevCertSequence = function() {
	var a = [];
	var aRevCert = this.params.revcert;
	for (var i = 0; i < aRevCert.length; i++) {
	    var aEntry = [
		new _DERInteger(aRevCert[i].sn),
		new _Time(aRevCert[i].date)
	    ];
	    if (aRevCert[i].ext != undefined) {
		aEntry.push(new _Extensions(aRevCert[i].ext));
	    }
	    a.push(new _DERSequence({array: aEntry}));
	}
	return new _DERSequence({array: a});
    };

    this.tohex = function() {
	var a = [];
	var params = this.params;

	if (params.version != undefined) {
	    var version = params.version - 1; 
	    var obj = new _DERInteger({'int': version});
	    a.push(obj);
	}

	a.push(new _AlgorithmIdentifier({name: params.sigalg}));
	a.push(new _X500Name(params.issuer));
	a.push(new _Time(params.thisupdate));
	if (params.nextupdate != undefined) 
	    a.push(new _Time(params.nextupdate))
	if (params.revcert != undefined) {
	    a.push(this.getRevCertSequence());
	}
	if (params.ext != undefined) {
	    var dExt = new _Extensions(params.ext);
	    a.push(new _DERTaggedObject({tag:'a0',
					 explicit:true,
					 obj:dExt}));
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.x509.TBSCertList, KJUR.asn1.ASN1Object);

/**
 * ASN.1 CRLEntry structure class for CRL (DEPRECATED)<br/>
 * @name KJUR.asn1.x509.CRLEntry
 * @class ASN.1 CRLEntry structure class for CRL
 * @param {Array} params JSON object for CRL entry parameter
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 * @see KJUR.asn1.x509.TBSCertList
 * @deprecated since jsrsasign 9.1.0 asn1x509 2.1.0
 * @description
 * This class is to represent revokedCertificate in TBSCertList.
 * However this is no more used by TBSCertList since
 * jsrsasign 9.1.0. So this class have been deprecated in 
 * jsrsasign 9.1.0.
 * <pre>
 * revokedCertificates     SEQUENCE OF SEQUENCE  {
 *     userCertificate         CertificateSerialNumber,
 *     revocationDate          Time,
 *     crlEntryExtensions      Extensions OPTIONAL
 *                             -- if present, version MUST be v2 }
 * </pre>
 * @example
 * var e = new KJUR.asn1.x509.CRLEntry({'time': {'str': '130514235959Z'}, 'sn': {'int': 234}});
 */
KJUR.asn1.x509.CRLEntry = function(params) {
    KJUR.asn1.x509.CRLEntry.superclass.constructor.call(this);
    var sn = null,
	time = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1;

    /**
     * set DERInteger parameter for serial number of revoked certificate
     * @name setCertSerial
     * @memberOf KJUR.asn1.x509.CRLEntry
     * @function
     * @param {Array} intParam DERInteger parameter for certificate serial number
     * @description
     * @example
     * entry.setCertSerial({'int': 3});
     */
    this.setCertSerial = function(intParam) {
        this.sn = new _KJUR_asn1.DERInteger(intParam);
    };

    /**
     * set Time parameter for revocation date
     * @name setRevocationDate
     * @memberOf KJUR.asn1.x509.CRLEntry
     * @function
     * @param {Array} timeParam Time parameter for revocation date
     * @description
     * @example
     * entry.setRevocationDate({'str': '130508235959Z'});
     */
    this.setRevocationDate = function(timeParam) {
        this.time = new _KJUR_asn1.x509.Time(timeParam);
    };

    this.tohex = function() {
        var o = new _KJUR_asn1.DERSequence({"array": [this.sn, this.time]});
        this.TLV = o.tohex();
        return this.TLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
        if (params.time !== undefined) {
            this.setRevocationDate(params.time);
        }
        if (params.sn !== undefined) {
            this.setCertSerial(params.sn);
        }
    }
};
extendClass(KJUR.asn1.x509.CRLEntry, KJUR.asn1.ASN1Object);

/**
 * CRLNumber CRL extension ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.CRLNumber
 * @class CRLNumber CRL extension ASN.1 structure class
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 9.1.0 asn1x509 2.1.0
 * @see KJUR.asn1.x509.TBSCertList
 * @see KJUR.asn1.x509.Extensions
 * @description
 * This class represents ASN.1 structure for
 * CRLNumber CRL extension defined in
 * <a href="https://tools.ietf.org/html/rfc5280#section-5.2.3">
 * RFC 5280 5.2.3</a>.
 * <pre>
 * id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 }
 * CRLNumber ::= INTEGER (0..MAX)
 * </pre>
 * Constructor of this class may have following parameters:
 * <ul>
 * <li>{String}extname - name "cRLNumber". It is ignored in this class but
 * required to use with {@link KJUR.asn1.x509.Extensions} class. (OPTION)</li>
 * <li>{Object}num - CRLNumber value to specify
 * {@link KJUR.asn1.DERInteger} parameter.</li>
 * <li>{Boolean}critical - critical flag. Generally false and not specified
 * in this class.(OPTION)</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.x509.CRLNumber({extname:'cRLNumber',
 *                               num:{'int':147}})
 */
KJUR.asn1.x509.CRLNumber = function(params) {
    KJUR.asn1.x509.CRLNumber.superclass.constructor.call(this, params);
    this.params = undefined;

    this.getExtnValueHex = function() {
        this.asn1ExtnValue = new KJUR.asn1.DERInteger(this.params.num);
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.20";
    if (params != undefined) this.params = params;
};
extendClass(KJUR.asn1.x509.CRLNumber, KJUR.asn1.x509.Extension);

/**
 * CRLReason CRL entry extension ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.CRLReason
 * @class CRLReason CRL entry extension ASN.1 structure class
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 9.1.0 asn1x509 2.1.0
 * @see KJUR.asn1.x509.TBSCertList
 * @see KJUR.asn1.x509.Extensions
 * @description
 * This class represents ASN.1 structure for
 * CRLReason CRL entry extension defined in
 * <a href="https://tools.ietf.org/html/rfc5280#section-5.3.1">
 * RFC 5280 5.3.1</a>
 * <pre>
 * id-ce-cRLReasons OBJECT IDENTIFIER ::= { id-ce 21 }
 * -- reasonCode ::= { CRLReason }
 * CRLReason ::= ENUMERATED {
 *      unspecified             (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6),
 *      removeFromCRL           (8),
 *      privilegeWithdrawn      (9),
 *      aACompromise           (10) }
 * </pre>
 * Constructor of this class may have following parameters:
 * <ul>
 * <li>{String}extname - name "cRLReason". It is ignored in this class but
 * required to use with {@link KJUR.asn1.x509.Extensions} class. (OPTION)</li>
 * <li>{Integer}code - reasonCode value</li>
 * <li>{Boolean}critical - critical flag. Generally false and not specified
 * in this class.(OPTION)</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.x509.CRLReason({extname:'cRLReason',code:4})
 */
KJUR.asn1.x509.CRLReason = function(params) {
    KJUR.asn1.x509.CRLReason.superclass.constructor.call(this, params);
    this.params = undefined;

    this.getExtnValueHex = function() {
        this.asn1ExtnValue = new KJUR.asn1.DEREnumerated(this.params.code);
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "2.5.29.21";
    if (params != undefined) this.params = params;
};
extendClass(KJUR.asn1.x509.CRLReason, KJUR.asn1.x509.Extension);

// === END   CRL Related ===================================================

// === BEGIN OCSP Related ===================================================
/**
 * Nonce OCSP extension ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.OCSPNonce
 * @class Nonce OCSP extension ASN.1 structure class
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 9.1.6 asn1x509 2.1.2
 * @param {Array} params JSON object for Nonce extension
 * @see KJUR.asn1.ocsp.ResponseData
 * @see KJUR.asn1.x509.Extensions
 * @see X509#getExtOCSPNonce
 * @description
 * This class represents
 * Nonce OCSP extension value defined in
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.4.1">
 * RFC 6960 4.4.1</a> as JSON object.
 * <pre>
 * id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
 * id-pkix-ocsp-nonce     OBJECT IDENTIFIER ::= { id-pkix-ocsp 2 }
 * Nonce ::= OCTET STRING
 * </pre>
 * Constructor of this class may have following parameters:
 * <ul>
 * <li>{String}extname - name "ocspNonce". It is ignored in this class but
 * required to use with {@link KJUR.asn1.x509.Extensions} class. (OPTION)</li>
 * <li>{String}hex - hexadecimal string of nonce value</li>
 * <li>{Number}int - integer of nonce value. "hex" or "int" needs to be
 * specified.</li>
 * <li>{Boolean}critical - critical flag. Generally false and not specified
 * in this class.(OPTION)</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.x509.OCSPNonce({extname:'ocspNonce',
 *                               hex: '12ab...'})
 */
KJUR.asn1.x509.OCSPNonce = function(params) {
    KJUR.asn1.x509.OCSPNonce.superclass.constructor.call(this, params);
    this.params = undefined;

    this.getExtnValueHex = function() {
        this.asn1ExtnValue = new KJUR.asn1.DEROctetString(this.params);
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "1.3.6.1.5.5.7.48.1.2";
    if (params != undefined) this.params = params;
};
extendClass(KJUR.asn1.x509.OCSPNonce, KJUR.asn1.x509.Extension);

/**
 * OCSPNoCheck certificate ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.OCSPNoCheck
 * @class OCSPNoCheck extension ASN.1 structure class
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 9.1.6 asn1x509 2.1.2
 * @param {Array} params JSON object for OCSPNoCheck extension
 * @see KJUR.asn1.x509.Extensions
 * @see X509#getExtOCSPNoCheck
 * @description
 * This class represents
 * OCSPNoCheck extension value defined in
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.2.2.1">
 * RFC 6960 4.2.2.2.1</a> as JSON object.
 * <pre>
 * id-pkix-ocsp-nocheck OBJECT IDENTIFIER ::= { id-pkix-ocsp 5 }
 * </pre>
 * Constructor of this class may have following parameters:
 * <ul>
 * <li>{String}extname - name "ocspNoCheck". It is ignored in this class but
 * required to use with {@link KJUR.asn1.x509.Extensions} class. (OPTION)</li>
 * <li>{Boolean}critical - critical flag. Generally false and not specified
 * in this class.(OPTION)</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.x509.OCSPNonce({extname:'ocspNoCheck'})
 */
KJUR.asn1.x509.OCSPNoCheck = function(params) {
    KJUR.asn1.x509.OCSPNoCheck.superclass.constructor.call(this, params);
    this.params = undefined;

    this.getExtnValueHex = function() {
        this.asn1ExtnValue = new KJUR.asn1.DERNull();
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "1.3.6.1.5.5.7.48.1.5";
    if (params != undefined) this.params = params;
};
extendClass(KJUR.asn1.x509.OCSPNoCheck, KJUR.asn1.x509.Extension);

// === END   OCSP Related ===================================================

// === BEGIN Other X.509v3 Extensions========================================

/**
 * AdobeTimeStamp X.509v3 extension ASN.1 encoder class<br/>
 * @name KJUR.asn1.x509.AdobeTimeStamp
 * @class AdobeTimeStamp X.509v3 extension ASN.1 encoder class
 * @extends KJUR.asn1.x509.Extension
 * @since jsrsasign 10.0.1 asn1x509 2.1.4
 * @param {Array} params JSON object for AdobeTimeStamp extension parameter
 * @see KJUR.asn1.x509.Extensions
 * @see X509#getExtAdobeTimeStamp
 * @description
 * This class represents
 * AdobeTimeStamp X.509v3 extension value defined in
 * <a href="https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/oids.html">
 * Adobe site</a> as JSON object.
 * <pre>
 * adbe- OBJECT IDENTIFIER ::=  { adbe(1.2.840.113583) acrobat(1) security(1) x509Ext(9) 1 }
 *  ::= SEQUENCE {
 *     version INTEGER  { v1(1) }, -- extension version
 *     location GeneralName (In v1 GeneralName can be only uniformResourceIdentifier)
 *     requiresAuth        boolean (default false), OPTIONAL }
 * </pre>
 * Constructor of this class may have following parameters:
 * <ul>
 * <li>{String}uri - RFC 3161 time stamp service URL</li>
 * <li>{Boolean}reqauth - authentication required or not</li>
 * </ul>
 * </pre>
 * <br/>
 * NOTE: This extesion doesn't seem to have official name. This may be called as "pdfTimeStamp".
 * @example
 * new KJUR.asn1.x509.AdobeTimesStamp({
 *   uri: "http://tsa.example.com/",
 *   reqauth: true
 * }
 */
KJUR.asn1.x509.AdobeTimeStamp = function(params) {
    KJUR.asn1.x509.AdobeTimeStamp.superclass.constructor.call(this, params);

    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERBoolean = _KJUR_asn1.DERBoolean,
	_DERSequence = _KJUR_asn1.DERSequence,
	_GeneralName = _KJUR_asn1.x509.GeneralName;

    this.params = null;

    this.getExtnValueHex = function() {
	var params = this.params;
	var a = [new _DERInteger(1)];
	a.push(new _GeneralName({uri: params.uri}));
	if (params.reqauth != undefined) {
	    a.push(new _DERBoolean(params.reqauth));
	}

        this.asn1ExtnValue = new _DERSequence({array: a});
        return this.asn1ExtnValue.tohex();
    };

    this.oid = "1.2.840.113583.1.1.9.1";
    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.x509.AdobeTimeStamp, KJUR.asn1.x509.Extension);
 
// === END   Other X.509v3 Extensions========================================


// === BEGIN X500Name Related =================================================
/**
 * X500Name ASN.1 structure class
 * @name KJUR.asn1.x509.X500Name
 * @class X500Name ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'str': '/C=US/O=a'})
 * @extends KJUR.asn1.ASN1Object
 * @see KJUR.asn1.x509.X500Name
 * @see KJUR.asn1.x509.RDN
 * @see KJUR.asn1.x509.AttributeTypeAndValue
 * @see X509#getX500Name
 * @description
 * This class provides DistinguishedName ASN.1 class structure
 * defined in <a href="https://tools.ietf.org/html/rfc2253#section-2">RFC 2253 section 2</a>.
 * <blockquote><pre>
 * DistinguishedName ::= RDNSequence
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF
 *   AttributeTypeAndValue
 * AttributeTypeAndValue ::= SEQUENCE {
 *   type  AttributeType,
 *   value AttributeValue }
 * </pre></blockquote>
 * <br/>
 * Argument for the constructor can be one of following parameters:
 * <ul>
 * <li>{Array}array - array of {@link KJUR.asn1.x509.RDN} parameter</li>
 * <li>`String}str - string for distingish name in OpenSSL One line foramt (ex: /C=US/O=test/CN=test) See <a href="https://github.com/kjur/jsrsasign/wiki/NOTE-distinguished-name-representation-in-jsrsasign">this</a> in detail.</li>
 * <li>{String}ldapstr - string for distinguish name in LDAP format (ex: CN=test,O=test,C=US)</li>
 * <li>{String}hex - hexadecimal string for ASN.1 distinguish name structure</li>
 * <li>{String}certissuer - issuer name in the specified PEM certificate</li>
 * <li>{String}certsubject - subject name in the specified PEM certificate</li>
 * <li>{String}rule - DirectoryString rule (ex. "prn" or "utf8")</li>
 * </ul>
 * <br/>
 * NOTE1: The "array" and "rule" parameters have been supported
 * since jsrsasign 9.0.0 asn1x509 2.0.0.
 * <br/>
 * NOTE2: Multi-valued RDN in "str" parameter have been
 * supported since jsrsasign 6.2.1 asn1x509 1.0.17.
 * @example
 * // 1. construct with array
 * new KJUR.asn1.x509.X500Name({array:[
 *   [{type:'C',value:'JP',ds:'prn'}],
 *   [{type:'O',value:'aaa',ds:'utf8'}, // multi-valued RDN
 *    {type:'CN',value:'bob@example.com',ds:'ia5'}]
 * ]})
 * // 2. construct with string
 * new KJUR.asn1.x509.X500Name({str: "/C=US/ST=NY/L=Ballston Spa/STREET=915 Stillwater Ave"});
 * new KJUR.asn1.x509.X500Name({str: "/CN=AAA/2.5.4.42=John/surname=Ray"});
 * new KJUR.asn1.x509.X500Name({str: "/C=US/O=aaa+CN=contact@example.com"}); // multi valued
 * // 3. construct by LDAP string
 * new KJUR.asn1.x509.X500Name({ldapstr: "CN=foo@example.com,OU=bbb,C=US"});
 * // 4. construct by ASN.1 hex string
 * new KJUR.asn1.x509.X500Name({hex: "304c3120..."});
 * // 5. construct by issuer of PEM certificate
 * new KJUR.asn1.x509.X500Name({certsubject: "-----BEGIN CERT..."});
 * // 6. construct by subject of PEM certificate
 * new KJUR.asn1.x509.X500Name({certissuer: "-----BEGIN CERT..."});
 * // 7. construct by object (DEPRECATED)
 * new KJUR.asn1.x509.X500Name({C:"US",O:"aaa",CN:"http://example.com/"});
 */
KJUR.asn1.x509.X500Name = function(params) {
    KJUR.asn1.x509.X500Name.superclass.constructor.call(this);
    this.asn1Array = [];
    this.paramArray = [];
    this.sRule = "utf8";
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_RDN = _KJUR_asn1_x509.RDN,
	_pemtohex = pemtohex;

    /**
     * set DN by OpenSSL oneline distinguished name string<br/>
     * @name setByString
     * @memberOf KJUR.asn1.x509.X500Name#
     * @function
     * @param {String} dnStr distinguished name by string (ex. /C=US/O=aaa)
     * @description
     * Sets distinguished name by string. 
     * dnStr must be formatted as 
     * "/type0=value0/type1=value1/type2=value2...".
     * No need to escape a slash in an attribute value.
     * @example
     * name = new KJUR.asn1.x509.X500Name();
     * name.setByString("/C=US/O=aaa/OU=bbb/CN=foo@example.com");
     * // no need to escape slash in an attribute value
     * name.setByString("/C=US/O=aaa/CN=1980/12/31");
     */
    this.setByString = function(dnStr, sRule) {
	if (sRule !== undefined) this.sRule = sRule;
        var a = dnStr.split('/');
        a.shift();

	var a1 = [];
	for (var i = 0; i < a.length; i++) {
	  if (a[i].match(/^[^=]+=.+$/)) {
	    a1.push(a[i]);
	  } else {
	    var lastidx = a1.length - 1;
	    a1[lastidx] = a1[lastidx] + "/" + a[i];
	  }
	}

        for (var i = 0; i < a1.length; i++) {
            this.asn1Array.push(new _RDN({'str':a1[i], rule:this.sRule}));
        }
    };

    /**
     * set DN by LDAP(RFC 2253) distinguished name string<br/>
     * @name setByLdapString
     * @memberOf KJUR.asn1.x509.X500Name#
     * @function
     * @param {String} dnStr distinguished name by LDAP string (ex. O=aaa,C=US)
     * @since jsrsasign 6.2.2 asn1x509 1.0.18
     * @see {@link KJUR.asn1.x509.X500Name.ldapToCompat}
     * @description
     * @example
     * name = new KJUR.asn1.x509.X500Name();
     * name.setByLdapString("CN=foo@example.com,OU=bbb,O=aaa,C=US");
     */
    this.setByLdapString = function(dnStr, sRule) {
	if (sRule !== undefined) this.sRule = sRule;
	var compat = _KJUR_asn1_x509.X500Name.ldapToCompat(dnStr);
	this.setByString(compat, sRule);
    };

    /**
     * set DN by associative array<br/>
     * @name setByObject
     * @memberOf KJUR.asn1.x509.X500Name#
     * @function
     * @param {Array} dnObj associative array of DN (ex. {C: "US", O: "aaa"})
     * @since jsrsasign 4.9. asn1x509 1.0.13
     * @description
     * @example
     * name = new KJUR.asn1.x509.X500Name();
     * name.setByObject({C: "US", O: "aaa", CN="http://example.com/"1});
     */
    this.setByObject = function(dnObj, sRule) {
	if (sRule !== undefined) this.sRule = sRule;

        // Get all the dnObject attributes and stuff them in the ASN.1 array.
        for (var x in dnObj) {
            if (dnObj.hasOwnProperty(x)) {
                var newRDN = new _RDN({str: x + '=' + dnObj[x], rule: this.sRule});
                // Initialize or push into the ANS1 array.
                this.asn1Array ? this.asn1Array.push(newRDN)
                    : this.asn1Array = [newRDN];
            }
        }
    };

    this.setByParam = function(params) {
	if (params.rule !== undefined) this.sRule = params.rule;

	if (params.array !== undefined) {
	    this.paramArray = params.array;
	} else {
            if (params.str !== undefined) {
		this.setByString(params.str);
            } else if (params.ldapstr !== undefined) {
		this.setByLdapString(params.ldapstr);
	    } else if (params.hex !== undefined) {
		this.hTLV = params.hex;
            } else if (params.certissuer !== undefined) {
		var x = new X509();
		x.readCertPEM(params.certissuer);
		this.hTLV = x.getIssuerHex();
            } else if (params.certsubject !== undefined) {
		var x = new X509();
		x.readCertPEM(params.certsubject);
		this.hTLV = x.getSubjectHex();
		// If params is an object, then set the ASN1 array
		// just using the object attributes. 
		// This is nice for fields that have lots of special
		// characters (i.e. CN: 'https://www.github.com/kjur//').
            } else if (typeof params === "object" &&
		       params.certsubject === undefined &&
		       params.certissuer === undefined) {
		this.setByObject(params);
            }
	}
    }

    this.tohex = function() {
        if (typeof this.hTLV == "string") return this.hTLV;

	if (this.asn1Array.length == 0 && this.paramArray.length > 0) {
	    for (var i = 0; i < this.paramArray.length; i++) {
		var param = {array: this.paramArray[i]};
		if (this.sRule != "utf8") param.rule = this.sRule;
		var asn1RDN = new _RDN(param);
		this.asn1Array.push(asn1RDN);
	    }
	}

        var o = new _KJUR_asn1.DERSequence({"array": this.asn1Array});
        this.hTLV = o.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.x509.X500Name, KJUR.asn1.ASN1Object);

/**
 * convert OpenSSL compat distinguished name format string to LDAP(RFC 2253) format<br/>
 * @name compatToLDAP
 * @memberOf KJUR.asn1.x509.X500Name
 * @function
 * @param {String} s distinguished name string in OpenSSL oneline compat (ex. /C=US/O=test)
 * @return {String} distinguished name string in LDAP(RFC 2253) format (ex. O=test,C=US)
 * @since jsrsasign 8.0.19 asn1x509 1.1.20
 * @description
 * This static method converts a distinguished name string in OpenSSL compat
 * format to LDAP(RFC 2253) format.
 * @see <a href="https://github.com/kjur/jsrsasign/wiki/NOTE-distinguished-name-representation-in-jsrsasign">jsrsasign wiki: distinguished name string difference between OpenSSL compat and LDAP(RFC 2253)</a>
 * @see <a href="https://www.openssl.org/docs/man1.0.2/man1/openssl-x509.html#NAME-OPTIONS">OpenSSL x509 command manual - NAME OPTIONS</a>
 * @example
 * KJUR.asn1.x509.X500Name.compatToLDAP("/C=US/O=test") &rarr; 'O=test,C=US'
 * KJUR.asn1.x509.X500Name.compatToLDAP("/C=US/O=a,a") &rarr; 'O=a\,a,C=US'
 */
KJUR.asn1.x509.X500Name.compatToLDAP = function(s) {
    if (s.substr(0, 1) !== "/") throw "malformed input";

    var result = "";
    s = s.substr(1);

    var a = s.split("/");
    a.reverse();
    a = a.map(function(s) {return s.replace(/,/, "\\,")});

    return a.join(",");
};

/**
 * convert OpenSSL compat distinguished name format string to LDAP(RFC 2253) format (DEPRECATED)<br/>
 * @name onelineToLDAP
 * @memberOf KJUR.asn1.x509.X500Name
 * @function
 * @param {String} s distinguished name string in OpenSSL compat format (ex. /C=US/O=test)
 * @return {String} distinguished name string in LDAP(RFC 2253) format (ex. O=test,C=US)
 * @since jsrsasign 6.2.2 asn1x509 1.0.18
 * @see KJUR.asn1.x509.X500Name.compatToLDAP
 * @description
 * This method is deprecated. Please use 
 * {@link KJUR.asn1.x509.X500Name.compatToLDAP} instead.
 */
KJUR.asn1.x509.X500Name.onelineToLDAP = function(s) {
    return KJUR.asn1.x509.X500Name.compatToLDAP(s);
}

/**
 * convert LDAP(RFC 2253) distinguished name format string to OpenSSL compat format<br/>
 * @name ldapToCompat
 * @memberOf KJUR.asn1.x509.X500Name
 * @function
 * @param {String} s distinguished name string in LDAP(RFC 2253) format (ex. O=test,C=US)
 * @return {String} distinguished name string in OpenSSL compat format (ex. /C=US/O=test)
 * @since jsrsasign 8.0.19 asn1x509 1.1.10
 * @description
 * This static method converts a distinguished name string in 
 * LDAP(RFC 2253) format to OpenSSL compat format.
 * @see <a href="https://github.com/kjur/jsrsasign/wiki/NOTE-distinguished-name-representation-in-jsrsasign">jsrsasign wiki: distinguished name string difference between OpenSSL compat and LDAP(RFC 2253)</a>
 * @example
 * KJUR.asn1.x509.X500Name.ldapToCompat('O=test,C=US') &rarr; '/C=US/O=test'
 * KJUR.asn1.x509.X500Name.ldapToCompat('O=a\,a,C=US') &rarr; '/C=US/O=a,a'
 * KJUR.asn1.x509.X500Name.ldapToCompat('O=a/a,C=US')  &rarr; '/C=US/O=a\/a'
 */
KJUR.asn1.x509.X500Name.ldapToCompat = function(s) {
    var a = s.split(",");

    // join \,
    var isBSbefore = false;
    var a2 = [];
    for (var i = 0; a.length > 0; i++) {
	var item = a.shift();
	//console.log("item=" + item);

	if (isBSbefore === true) {
	    var a2last = a2.pop();
	    var newitem = (a2last + "," + item).replace(/\\,/g, ",");
	    a2.push(newitem);
	    isBSbefore = false;
	} else {
	    a2.push(item);
	}

	if (item.substr(-1, 1) === "\\") isBSbefore = true;
    }

    a2 = a2.map(function(s) {return s.replace("/", "\\/")});
    a2.reverse();
    return "/" + a2.join("/");
};

/**
 * convert LDAP(RFC 2253) distinguished name format string to OpenSSL compat format (DEPRECATED)<br/>
 * @name ldapToOneline
 * @memberOf KJUR.asn1.x509.X500Name
 * @function
 * @param {String} s distinguished name string in LDAP(RFC 2253) format (ex. O=test,C=US)
 * @return {String} distinguished name string in OpenSSL compat format (ex. /C=US/O=test)
 * @since jsrsasign 6.2.2 asn1x509 1.0.18
 * @description
 * This method is deprecated. Please use 
 * {@link KJUR.asn1.x509.X500Name.ldapToCompat} instead.
 */
KJUR.asn1.x509.X500Name.ldapToOneline = function(s) {
    return KJUR.asn1.x509.X500Name.ldapToCompat(s);
};

/**
 * RDN (Relative Distinguished Name) ASN.1 structure class
 * @name KJUR.asn1.x509.RDN
 * @class RDN (Relative Distinguished Name) ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'str': 'C=US'})
 * @extends KJUR.asn1.ASN1Object
 * @see KJUR.asn1.x509.X500Name
 * @see KJUR.asn1.x509.RDN
 * @see KJUR.asn1.x509.AttributeTypeAndValue
 * @description
 * This class provides RelativeDistinguishedName ASN.1 class structure
 * defined in <a href="https://tools.ietf.org/html/rfc2253#section-2">RFC 2253 section 2</a>.
 * <blockquote><pre>
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF
 *   AttributeTypeAndValue
 *
 * AttributeTypeAndValue ::= SEQUENCE {
 *   type  AttributeType,
 *   value AttributeValue }
 * </pre></blockquote>
 * <br/>
 * NOTE1: The "array" and "rule" parameters have been supported
 * since jsrsasign 9.0.0 asn1x509 2.0.0.
 * <br/>
 * NOTE2: Multi-valued RDN in "str" parameter have been
 * supported since jsrsasign 6.2.1 asn1x509 1.0.17.
 * @example
 * new KJUR.asn1.x509.RDN({array: [ // multi-valued
 *    {type:"CN",value:"Bob",ds:"prn"},
 *    {type:"CN",value:"bob@example.com", ds:"ia5"}
 * ]});
 * new KJUR.asn1.x509.RDN({str: "CN=test"});
 * new KJUR.asn1.x509.RDN({str: "O=a+O=bb+O=c"}); // multi-valued
 * new KJUR.asn1.x509.RDN({str: "O=a+O=b\\+b+O=c"}); // plus escaped
 * new KJUR.asn1.x509.RDN({str: "O=a+O=\"b+b\"+O=c"}); // double quoted
 */
KJUR.asn1.x509.RDN = function(params) {
    KJUR.asn1.x509.RDN.superclass.constructor.call(this);
    this.asn1Array = [];
    this.paramArray = [];
    this.sRule = "utf8"; // DEFAULT "utf8"
    var _AttributeTypeAndValue = KJUR.asn1.x509.AttributeTypeAndValue;

    this.setByParam = function(params) {
	if (params.rule !== undefined) this.sRule = params.rule;
        if (params.str !== undefined) {
            this.addByMultiValuedString(params.str);
        }
	if (params.array !== undefined) this.paramArray = params.array;
    };

    /**
     * add one AttributeTypeAndValue by string<br/>
     * @name addByString
     * @memberOf KJUR.asn1.x509.RDN#
     * @function
     * @param {String} s string of AttributeTypeAndValue
     * @return {Object} unspecified
     * @description
     * This method add one AttributeTypeAndValue to RDN object.
     * @example
     * rdn = new KJUR.asn1.x509.RDN();
     * rdn.addByString("CN=john");
     * rdn.addByString("serialNumber=1234"); // for multi-valued RDN
     */
    this.addByString = function(s) {
        this.asn1Array.push(new KJUR.asn1.x509.AttributeTypeAndValue({'str': s, rule: this.sRule}));
    };

    /**
     * add one AttributeTypeAndValue by multi-valued string<br/>
     * @name addByMultiValuedString
     * @memberOf KJUR.asn1.x509.RDN#
     * @function
     * @param {String} s string of multi-valued RDN
     * @return {Object} unspecified
     * @since jsrsasign 6.2.1 asn1x509 1.0.17
     * @description
     * This method add multi-valued RDN to RDN object.
     * @example
     * rdn = new KJUR.asn1.x509.RDN();
     * rdn.addByMultiValuedString("CN=john+O=test");
     * rdn.addByMultiValuedString("O=a+O=b\+b\+b+O=c"); // multi-valued RDN with quoted plus
     * rdn.addByMultiValuedString("O=a+O=\"b+b+b\"+O=c"); // multi-valued RDN with quoted quotation
     */
    this.addByMultiValuedString = function(s) {
	var a = KJUR.asn1.x509.RDN.parseString(s);
	for (var i = 0; i < a.length; i++) {
	    this.addByString(a[i]);
	}
    };

    this.tohex = function() {
	if (this.asn1Array.length == 0 && this.paramArray.length > 0) {
	    for (var i = 0; i < this.paramArray.length; i++) {
		var param = this.paramArray[i];
		if (param.rule !== undefined &&
		    this.sRule != "utf8") {
		    param.rule = this.sRule;
		}
		//alert(JSON.stringify(param));
		var asn1ATV = new _AttributeTypeAndValue(param);
		this.asn1Array.push(asn1ATV);
	    }
	}
        var o = new KJUR.asn1.DERSet({"array": this.asn1Array});
        this.TLV = o.tohex();
        return this.TLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
	this.setByParam(params);
    }
};
extendClass(KJUR.asn1.x509.RDN, KJUR.asn1.ASN1Object);

/**
 * parse multi-valued RDN string and split into array of 'AttributeTypeAndValue'<br/>
 * @name parseString
 * @memberOf KJUR.asn1.x509.RDN
 * @function
 * @param {String} s multi-valued string of RDN
 * @return {Array} array of string of AttributeTypeAndValue
 * @since jsrsasign 6.2.1 asn1x509 1.0.17
 * @description
 * This static method parses multi-valued RDN string and split into
 * array of AttributeTypeAndValue.
 * @example
 * KJUR.asn1.x509.RDN.parseString("CN=john") &rarr; ["CN=john"]
 * KJUR.asn1.x509.RDN.parseString("CN=john+OU=test") &rarr; ["CN=john", "OU=test"]
 * KJUR.asn1.x509.RDN.parseString('CN="jo+hn"+OU=test') &rarr; ["CN=jo+hn", "OU=test"]
 * KJUR.asn1.x509.RDN.parseString('CN=jo\+hn+OU=test') &rarr; ["CN=jo+hn", "OU=test"]
 * KJUR.asn1.x509.RDN.parseString("CN=john+OU=test+OU=t1") &rarr; ["CN=john", "OU=test", "OU=t1"]
 */
KJUR.asn1.x509.RDN.parseString = function(s) {
    var a = s.split(/\+/);

    // join \+
    var isBSbefore = false;
    var a2 = [];
    for (var i = 0; a.length > 0; i++) {
	var item = a.shift();
	//console.log("item=" + item);

	if (isBSbefore === true) {
	    var a2last = a2.pop();
	    var newitem = (a2last + "+" + item).replace(/\\\+/g, "+");
	    a2.push(newitem);
	    isBSbefore = false;
	} else {
	    a2.push(item);
	}

	if (item.substr(-1, 1) === "\\") isBSbefore = true;
    }

    // join quote
    var beginQuote = false;
    var a3 = [];
    for (var i = 0; a2.length > 0; i++) {
	var item = a2.shift();

	if (beginQuote === true) {
	    var a3last = a3.pop();
	    if (item.match(/"$/)) {
		var newitem = (a3last + "+" + item).replace(/^([^=]+)="(.*)"$/, "$1=$2");
		a3.push(newitem);
		beginQuote = false;
	    } else {
		a3.push(a3last + "+" + item);
	    }
	} else {
	    a3.push(item);
	}

	if (item.match(/^[^=]+="/)) {
	    //console.log(i + "=" + item);
	    beginQuote = true;
	}
    }
    return a3;
};

/**
 * AttributeTypeAndValue ASN.1 structure class
 * @name KJUR.asn1.x509.AttributeTypeAndValue
 * @class AttributeTypeAndValue ASN.1 structure class
 * @param {Array} params JSON object for parameters (ex. {str: 'C=US'})
 * @extends KJUR.asn1.ASN1Object
 * @see KJUR.asn1.x509.X500Name
 * @see KJUR.asn1.x509.RDN
 * @see KJUR.asn1.x509.AttributeTypeAndValue
 * @see X509#getAttrTypeAndValue
 * @description
 * This class generates AttributeTypeAndValue defined in
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.1.2.4">
 * RFC 5280 4.1.2.4</a>.
 * <pre>
 * AttributeTypeAndValue ::= SEQUENCE {
 *   type     AttributeType,
 *   value    AttributeValue }
 * AttributeType ::= OBJECT IDENTIFIER
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 * </pre>
 * The constructor argument can have following parameters:
 * <ul>
 * <li>{String}type - AttributeType name or OID(ex. C,O,CN)</li>
 * <li>{String}value - raw string of ASN.1 value of AttributeValue</li>
 * <li>{String}ds - DirectoryString type of AttributeValue</li>
 * <li>{String}rule - DirectoryString type rule (ex. "prn" or "utf8")
 * set DirectoryString type automatically when "ds" not specified.</li>
 * <li>{String}str - AttributeTypeAndVale string (ex. "C=US").
 * When type and value don't exists, 
 * this "str" will be converted to "type" and "value".
 * </li>
 * </ul>
 * <br
 * NOTE: Parameters "type", "value,", "ds" and "rule" have
 * been supported since jsrsasign 9.0.0 asn1x509 2.0.0.
 * @example
 * new KJUR.asn1.x509.AttributeTypeAndValue({type:'C',value:'US',ds:'prn'})
 * new KJUR.asn1.x509.AttributeTypeAndValue({type:'givenName',value:'John',ds:'prn'})
 * new KJUR.asn1.x509.AttributeTypeAndValue({type:'2.5.4.9',value:'71 Bowman St',ds:'prn'})
 * new KJUR.asn1.x509.AttributeTypeAndValue({str:'O=T1'})
 * new KJUR.asn1.x509.AttributeTypeAndValue({str:'streetAddress=71 Bowman St'})
 * new KJUR.asn1.x509.AttributeTypeAndValue({str:'O=T1',rule='prn'})
 * new KJUR.asn1.x509.AttributeTypeAndValue({str:'O=T1',rule='utf8'})
 */
KJUR.asn1.x509.AttributeTypeAndValue = function(params) {
    KJUR.asn1.x509.AttributeTypeAndValue.superclass.constructor.call(this);
    this.sRule = "utf8";
    this.sType = null;
    this.sValue = null;
    this.dsType = null;
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERUTF8String = _KJUR_asn1.DERUTF8String,
	_DERPrintableString = _KJUR_asn1.DERPrintableString,
	_DERTeletexString = _KJUR_asn1.DERTeletexString,
	_DERIA5String = _KJUR_asn1.DERIA5String,
	_DERVisibleString = _KJUR_asn1.DERVisibleString,
	_DERBMPString = _KJUR_asn1.DERBMPString,
	_isMail = _KJUR.lang.String.isMail,
	_isPrintable = _KJUR.lang.String.isPrintable;

    this.setByParam = function(params) {
	if (params.rule !== undefined) this.sRule = params.rule;
	if (params.ds !== undefined)   this.dsType = params.ds;

        if (params.value === undefined &&
	    params.str !== undefined) {
	    var str = params.str;
            var matchResult = str.match(/^([^=]+)=(.+)$/);
            if (matchResult) {
		this.sType = matchResult[1];
		this.sValue = matchResult[2];
            } else {
		throw new Error("malformed attrTypeAndValueStr: " +
				attrTypeAndValueStr);
            }
	    
	    //this.setByString(params.str);
        } else {
	    this.sType = params.type;
	    this.sValue = params.value;
	}
    };

    /*
     * @deprecated
     */
    this.setByString = function(sTypeValue, sRule) {
	if (sRule !== undefined) this.sRule = sRule;
        var matchResult = sTypeValue.match(/^([^=]+)=(.+)$/);
        if (matchResult) {
            this.setByAttrTypeAndValueStr(matchResult[1], matchResult[2]);
        } else {
            throw new Error("malformed attrTypeAndValueStr: " +
			    attrTypeAndValueStr);
        }
    };

    this._getDsType = function() {
	var sType = this.sType;
	var sValue = this.sValue;
	var sRule = this.sRule;

	if (sRule === "prn") {
	    if (sType == "CN" && _isMail(sValue)) return "ia5";
	    if (_isPrintable(sValue)) return "prn";
	    return "utf8";
	} else if (sRule === "utf8") {
	    if (sType == "CN" && _isMail(sValue)) return "ia5";
	    if (sType == "C") return "prn";
	    return "utf8";
	}
	return "utf8"; // default
    };

    this.setByAttrTypeAndValueStr = function(sType, sValue, sRule) {
	if (sRule !== undefined) this.sRule = sRule;
	this.sType = sType;
	this.sValue = sValue;
    };

    this.getValueObj = function(dsType, valueStr) {
        if (dsType == "utf8") return new _DERUTF8String({"str": valueStr});
        if (dsType == "prn")  return new _DERPrintableString({"str": valueStr});
        if (dsType == "tel")  return new _DERTeletexString({"str": valueStr});
        if (dsType == "ia5")  return new _DERIA5String({"str": valueStr});
        if (dsType == "vis")  return new _DERVisibleString({"str": valueStr});
        if (dsType == "bmp")  return new _DERBMPString({"str": valueStr});
        throw new Error("unsupported directory string type: type=" +
			dsType + " value=" + valueStr);
    };

    this.tohex = function() {
	if (this.dsType == null) this.dsType = this._getDsType();
	var asn1Type = KJUR.asn1.x509.OID.atype2obj(this.sType);
	var asn1Value = this.getValueObj(this.dsType, this.sValue);
        var o = new _DERSequence({"array": [asn1Type, asn1Value]});
        this.TLV = o.tohex();
        return this.TLV;
    }

    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
	this.setByParam(params);
    }
};
extendClass(KJUR.asn1.x509.AttributeTypeAndValue, KJUR.asn1.ASN1Object);

// === END   X500Name Related =================================================

// === BEGIN Other ASN1 structure class  ======================================

/**
 * SubjectPublicKeyInfo ASN.1 structure class
 * @name KJUR.asn1.x509.SubjectPublicKeyInfo
 * @class SubjectPublicKeyInfo ASN.1 structure class
 * @param {Object} params parameter for subject public key
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>{@link RSAKey} object</li>
 * <li>{@link KJUR.crypto.ECDSA} object</li>
 * <li>{@link KJUR.crypto.DSA} object</li>
 * </ul>
 * NOTE1: 'params' can be omitted.<br/>
 * NOTE2: DSA/ECDSA key object is also supported since asn1x509 1.0.6.<br/>
 * <h4>EXAMPLE</h4>
 * @example
 * spki = new KJUR.asn1.x509.SubjectPublicKeyInfo(RSAKey_object);
 * spki = new KJUR.asn1.x509.SubjectPublicKeyInfo(KJURcryptoECDSA_object);
 * spki = new KJUR.asn1.x509.SubjectPublicKeyInfo(KJURcryptoDSA_object);
 */
KJUR.asn1.x509.SubjectPublicKeyInfo = function(params) {
    KJUR.asn1.x509.SubjectPublicKeyInfo.superclass.constructor.call(this);
    var asn1AlgId = null,
	asn1SubjPKey = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERBitString = _KJUR_asn1.DERBitString,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_DERSequence = _KJUR_asn1.DERSequence,
	_newObject = _KJUR_asn1.ASN1Util.newObject,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier,
	_KJUR_crypto = _KJUR.crypto,
	_KJUR_crypto_ECDSA = _KJUR_crypto.ECDSA,
	_KJUR_crypto_DSA = _KJUR_crypto.DSA;

    /*
     * @since asn1x509 1.0.7
     */
    this.getASN1Object = function() {
        if (this.asn1AlgId == null || this.asn1SubjPKey == null)
            throw "algId and/or subjPubKey not set";
        var o = new _DERSequence({'array':
                                  [this.asn1AlgId, this.asn1SubjPKey]});
        return o;
    };

    this.tohex = function() {
        var o = this.getASN1Object();
        this.hTLV = o.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    /**
     * @name setPubKey
     * @memberOf KJUR.asn1.x509.SubjectPublicKeyInfo#
     * @function
     * @param {Object} {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.DSA} object
     * @since jsrsasign 8.0.0 asn1x509 1.1.0
     * @description
     * @example
     * spki = new KJUR.asn1.x509.SubjectPublicKeyInfo();
     * pubKey = KEYUTIL.getKey(PKCS8PUBKEYPEM);
     * spki.setPubKey(pubKey);
     */
    this.setPubKey = function(key) {
	try {
	    if (key instanceof RSAKey) {
		var asn1RsaPub = _newObject({
		    'seq': [{'int': {'bigint': key.n}}, {'int': {'int': key.e}}]
		});
		var rsaKeyHex = asn1RsaPub.tohex();
		this.asn1AlgId = new _AlgorithmIdentifier({'name':'rsaEncryption'});
		this.asn1SubjPKey = new _DERBitString({'hex':'00'+rsaKeyHex});
	    }
	} catch(ex) {};

	try {
	    if (key instanceof KJUR.crypto.ECDSA) {
		var asn1Params = new _DERObjectIdentifier({'name': key.curveName});
		this.asn1AlgId =
		    new _AlgorithmIdentifier({'name': 'ecPublicKey',
					      'asn1params': asn1Params});
		this.asn1SubjPKey = new _DERBitString({'hex': '00' + key.pubKeyHex});
	    }
	} catch(ex) {};

	try {
	    if (key instanceof KJUR.crypto.DSA) {
		var asn1Params = new _newObject({
		    'seq': [{'int': {'bigint': key.p}},
			    {'int': {'bigint': key.q}},
			    {'int': {'bigint': key.g}}]
		});
		this.asn1AlgId =
		    new _AlgorithmIdentifier({'name': 'dsa',
					      'asn1params': asn1Params});
		var pubInt = new _DERInteger({'bigint': key.y});
		this.asn1SubjPKey = 
		    new _DERBitString({'hex': '00' + pubInt.tohex()});
	    }
	} catch(ex) {};
    };

    if (params !== undefined) {
	this.setPubKey(params);
    }
};
extendClass(KJUR.asn1.x509.SubjectPublicKeyInfo, KJUR.asn1.ASN1Object);

/**
 * Time ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.Time
 * @class Time ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'str': '130508235959Z'})
 * @extends KJUR.asn1.ASN1Object
 * @see KJUR.asn1.DERUTCTime
 * @see KJUR.asn1.DERGeneralizedTime
 * @description
 * This class represents Time ASN.1 structure defined in 
 * <a href="https://tools.ietf.org/html/rfc5280">RFC 5280</a>
 * <pre>
 * Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 * </pre>
 *
 * @example
 * var t1 = new KJUR.asn1.x509.Time{'str': '130508235959Z'} // UTCTime by default
 * var t2 = new KJUR.asn1.x509.Time{'type': 'gen',  'str': '20130508235959Z'} // GeneralizedTime
 */
KJUR.asn1.x509.Time = function(params) {
    KJUR.asn1.x509.Time.superclass.constructor.call(this);
    var type = null,
	timeParams = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERUTCTime = _KJUR_asn1.DERUTCTime,
	_DERGeneralizedTime = _KJUR_asn1.DERGeneralizedTime;
    this.params = null;
    this.type = null;

    // deprecated
    this.setTimeParams = function(timeParams) {
        this.timeParams = timeParams;
    }

    this.setByParam = function(params) {
	this.params = params;
    };

    this.getType = function(s) {
        if (s.match(/^[0-9]{12}Z$/)) return "utc";
        if (s.match(/^[0-9]{14}Z$/)) return "gen";
        if (s.match(/^[0-9]{12}\.[0-9]+Z$/)) return "utc";
        if (s.match(/^[0-9]{14}\.[0-9]+Z$/)) return "gen";
	return null;
    };

    this.tohex = function() {
	var params = this.params;
        var o = null;

	if (typeof params == "string") params = {str: params};
	if (params != null &&
	    params.str && 
	    (params.type == null || params.type == undefined)) {
	    params.type = this.getType(params.str);
	}

	if (params != null && params.str) {
	    if (params.type == "utc") o = new _DERUTCTime(params.str);
	    if (params.type == "gen") o = new _DERGeneralizedTime(params.str);
	} else {
	    if (this.type == "gen") {
		o = new _DERGeneralizedTime();
	    } else {
		o = new _DERUTCTime();
	    }
	}

	if (o == null) throw new Error("wrong setting for Time");
        this.TLV = o.tohex();
        return this.TLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};

KJUR.asn1.x509.Time_bak = function(params) {
    KJUR.asn1.x509.Time_bak.superclass.constructor.call(this);
    var type = null,
	timeParams = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERUTCTime = _KJUR_asn1.DERUTCTime,
	_DERGeneralizedTime = _KJUR_asn1.DERGeneralizedTime;

    this.setTimeParams = function(timeParams) {
        this.timeParams = timeParams;
    }

    this.tohex = function() {
        var o = null;

        if (this.timeParams != null) {
            if (this.type == "utc") {
                o = new _DERUTCTime(this.timeParams);
            } else {
                o = new _DERGeneralizedTime(this.timeParams);
            }
        } else {
            if (this.type == "utc") {
                o = new _DERUTCTime();
            } else {
                o = new _DERGeneralizedTime();
            }
        }
        this.TLV = o.tohex();
        return this.TLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.type = "utc";
    if (params !== undefined) {
        if (params.type !== undefined) {
            this.type = params.type;
        } else {
            if (params.str !== undefined) {
                if (params.str.match(/^[0-9]{12}Z$/)) this.type = "utc";
                if (params.str.match(/^[0-9]{14}Z$/)) this.type = "gen";
            }
        }
        this.timeParams = params;
    }
};
extendClass(KJUR.asn1.x509.Time, KJUR.asn1.ASN1Object);

/**
 * AlgorithmIdentifier ASN.1 structure class
 * @name KJUR.asn1.x509.AlgorithmIdentifier
 * @class AlgorithmIdentifier ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'name': 'SHA1withRSA'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * The 'params' argument is an associative array and has following parameters:
 * <ul>
 * <li>name: algorithm name (MANDATORY, ex. sha1, SHA256withRSA)</li>
 * <li>asn1params: explicitly specify ASN.1 object for algorithm.
 * (OPTION)</li>
 * <li>paramempty: set algorithm parameter to NULL by force.
 * If paramempty is false, algorithm parameter will be set automatically.
 * If paramempty is false and algorithm name is "*withDSA" or "withECDSA" parameter field of
 * AlgorithmIdentifier will be ommitted otherwise
 * it will be NULL by default.
 * (OPTION, DEFAULT = false)</li>
 * </ul>
 * RSA-PSS algorithm names such as SHA{,256,384,512}withRSAandMGF1 are
 * special names. They will set a suite of algorithm OID and multiple algorithm
 * parameters. Its ASN.1 schema is defined in 
 * <a href="https://tools.ietf.org/html/rfc3447#appendix-A.2.3">RFC 3447 PKCS#1 2.1
 * section A.2.3</a>.
 * <blockquote><pre>
 * id-RSASSA-PSS  OBJECT IDENTIFIER ::= { pkcs-1 10 }
 * RSASSA-PSS-params ::= SEQUENCE {
 *   hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
 *   maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
 *   saltLength         [2] INTEGER          DEFAULT 20,
 *   trailerField       [3] TrailerField     DEFAULT trailerFieldBC }
 * mgf1SHA1    MaskGenAlgorithm ::= {
 *   algorithm   id-mgf1,
 *   parameters  HashAlgorithm : sha1 }
 * id-mgf1     OBJECT IDENTIFIER ::= { pkcs-1 8 }
 * TrailerField ::= INTEGER { trailerFieldBC(1) }
 * </pre></blockquote>
 * Here is a table for PSS parameters:
 * <table>
 * <tr><th>Name</th><th>alg oid</th><th>pss hash</th><th>maskgen</th></th><th>pss saltlen</th><th>trailer</th></tr>
 * <tr><td>SHAwithRSAandMGF1</td><td>1.2.840.113549.1.1.10(rsapss)</td><td>default(sha1)</td><td>default(mgf1sha1)</td><td>default(20)</td><td>default(1)</td></tr>
 * <tr><td>SHA256withRSAandMGF1</td><td>1.2.840.113549.1.1.10(rsapss)</td><td>sha256</td><td>mgf1sha256</td><td>32</td><td>default(1)</td></tr>
 * <tr><td>SHA384withRSAandMGF1</td><td>1.2.840.113549.1.1.10(rsapss)</td><td>sha384</td><td>mgf1sha384</td><td>48</td><td>default(1)</td></tr>
 * <tr><td>SHA512withRSAandMGF1</td><td>1.2.840.113549.1.1.10(rsapss)</td><td>sha512</td><td>mgf1sha512</td><td>64</td><td>default(1)</td></tr>
 * </table>
 * Default value is omitted as defined in ASN.1 schema.
 * These parameters are interoperable to OpenSSL or IAIK toolkit.
 * <br/>
 * NOTE: RSA-PSS algorihtm names are supported since jsrsasign 8.0.21. 
 * @example
 * new KJUR.asn1.x509.AlgorithmIdentifier({name: "sha1"})
 * new KJUR.asn1.x509.AlgorithmIdentifier({name: "SHA256withRSA"})
 * new KJUR.asn1.x509.AlgorithmIdentifier({name: "SHA512withRSAandMGF1"}) // set parameters automatically
 * new KJUR.asn1.x509.AlgorithmIdentifier({name: "SHA256withRSA", paramempty: true})
 * new KJUR.asn1.x509.AlgorithmIdentifier({name: "rsaEncryption"})
 */
KJUR.asn1.x509.AlgorithmIdentifier = function(params) {
    KJUR.asn1.x509.AlgorithmIdentifier.superclass.constructor.call(this);
    this.nameAlg = null;
    this.asn1Alg = null;
    this.asn1Params = null;
    this.paramEmpty = false;

    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_PSSNAME2ASN1TLV = _KJUR_asn1.x509.AlgorithmIdentifier.PSSNAME2ASN1TLV;

    this.tohex = function() {
        if (this.nameAlg === null && this.asn1Alg === null) {
            throw new Error("algorithm not specified");
        }

	// for RSAPSS algorithm name
	//  && this.hTLV === null
	if (this.nameAlg !== null) {
	    var hTLV = null;
	    for (var key in _PSSNAME2ASN1TLV) {
		if (key === this.nameAlg) {
		    hTLV = _PSSNAME2ASN1TLV[key];
		}
	    }
	    if (hTLV !== null) {
		this.hTLV = hTLV;
		return this.hTLV;
	    }
	}

        if (this.nameAlg !== null && this.asn1Alg === null) {
            this.asn1Alg = _KJUR_asn1.x509.OID.name2obj(this.nameAlg);
        }
        var a = [this.asn1Alg];
        if (this.asn1Params !== null) a.push(this.asn1Params);

        var o = new _KJUR_asn1.DERSequence({'array': a});
        this.hTLV = o.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
        if (params.name !== undefined) {
            this.nameAlg = params.name;
        }
        if (params.asn1params !== undefined) {
            this.asn1Params = params.asn1params;
        }
        if (params.paramempty !== undefined) {
            this.paramEmpty = params.paramempty;
        }
    }

    // set algorithm parameters will be ommitted for
    // "*withDSA" or "*withECDSA" otherwise will be NULL.
    if (this.asn1Params === null &&
	this.paramEmpty === false &&
	this.nameAlg !== null) {

	if (this.nameAlg.name !== undefined) {
	    this.nameAlg = this.nameAlg.name;
	}
	var lcNameAlg = this.nameAlg.toLowerCase();

	if (lcNameAlg.substr(-7, 7) !== "withdsa" &&
	    lcNameAlg.substr(-9, 9) !== "withecdsa") {
            this.asn1Params = new _KJUR_asn1.DERNull();
	}
    }
};
extendClass(KJUR.asn1.x509.AlgorithmIdentifier, KJUR.asn1.ASN1Object);

/**
 * AlgorithmIdentifier ASN.1 TLV string associative array for RSA-PSS algorithm names
 * @const
 */
KJUR.asn1.x509.AlgorithmIdentifier.PSSNAME2ASN1TLV = {
    "SHAwithRSAandMGF1":
    "300d06092a864886f70d01010a3000",
    "SHA256withRSAandMGF1":
    "303d06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a203020120",
    "SHA384withRSAandMGF1":
    "303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a203020130",
    "SHA512withRSAandMGF1":
    "303d06092a864886f70d01010a3030a00d300b0609608648016503040203a11a301806092a864886f70d010108300b0609608648016503040203a203020140"
};

/**
 * GeneralName ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.GeneralName
 * @class GeneralName ASN.1 structure class
 * @see KJUR.asn1.x509.OtherName
 * @see KJUR.asn1.x509.X500Name
 *
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>rfc822 - rfc822Name[1] (ex. user1@foo.com)</li>
 * <li>dns - dNSName[2] (ex. foo.com)</li>
 * <li>uri - uniformResourceIdentifier[6] (ex. http://foo.com/)</li>
 * <li>dn - directoryName[4] 
 * distinguished name string or X500Name class parameters can be
 * specified (ex. "/C=US/O=Test", {hex: '301c...')</li>
 * <li>ldapdn - directoryName[4] (ex. O=Test,C=US)</li>
 * <li>certissuer - directoryName[4] (PEM or hex string of cert)</li>
 * <li>certsubj - directoryName[4] (PEM or hex string of cert)</li>
 * <li>ip - iPAddress[7] (ex. 192.168.1.1, 2001:db3::43, 3faa0101...)</li>
 * </ul>
 * NOTE1: certissuer and certsubj were supported since asn1x509 1.0.10.<br/>
 * NOTE2: dn and ldapdn were supported since jsrsasign 6.2.3 asn1x509 1.0.19.<br/>
 * NOTE3: ip were supported since jsrsasign 8.0.10 asn1x509 1.1.4.<br/>
 * NOTE4: X500Name parameters in dn were supported since jsrsasign 8.0.16.<br/>
 * NOTE5: otherName is supported since jsrsasign 10.5.3.<br/>
 *
 * Here is definition of the ASN.1 syntax:
 * <pre>
 * -- NOTE: under the CHOICE, it will always be explicit.
 * GeneralName ::= CHOICE {
 *   otherName                  [0] OtherName,
 *   rfc822Name                 [1] IA5String,
 *   dNSName                    [2] IA5String,
 *   x400Address                [3] ORAddress,
 *   directoryName              [4] Name,
 *   ediPartyName               [5] EDIPartyName,
 *   uniformResourceIdentifier  [6] IA5String,
 *   iPAddress                  [7] OCTET STRING,
 *   registeredID               [8] OBJECT IDENTIFIER }
 *
 * OtherName ::= SEQUENCE {
 *   type-id    OBJECT IDENTIFIER,
 *   value      [0] EXPLICIT ANY DEFINED BY type-id }
 * </pre>
 *
 * @example
 * gn = new KJUR.asn1.x509.GeneralName({dn:     '/C=US/O=Test'});
 * gn = new KJUR.asn1.x509.GeneralName({dn:     X500NameObject);
 * gn = new KJUR.asn1.x509.GeneralName({dn:     {str: /C=US/O=Test'});
 * gn = new KJUR.asn1.x509.GeneralName({dn:     {ldapstr: 'O=Test,C=US'});
 * gn = new KJUR.asn1.x509.GeneralName({dn:     {hex: '301c...'});
 * gn = new KJUR.asn1.x509.GeneralName({dn:     {certissuer: PEMCERTSTRING});
 * gn = new KJUR.asn1.x509.GeneralName({dn:     {certsubject: PEMCERTSTRING});
 * gn = new KJUR.asn1.x509.GeneralName({ip:     '192.168.1.1'});
 * gn = new KJUR.asn1.x509.GeneralName({ip:     '2001:db4::4:1'});
 * gn = new KJUR.asn1.x509.GeneralName({ip:     'c0a80101'});
 * gn = new KJUR.asn1.x509.GeneralName({rfc822: 'test@aaa.com'});
 * gn = new KJUR.asn1.x509.GeneralName({dns:    'aaa.com'});
 * gn = new KJUR.asn1.x509.GeneralName({uri:    'http://aaa.com/'});
 * gn = new KJUR.asn1.x509.GeneralName({other: {
 *   oid: "1.2.3.4",
 *   value: {utf8: "example"} // any ASN.1 which passed to ASN1Util.newObject
 * }});
 *
 * gn = new KJUR.asn1.x509.GeneralName({ldapdn:     'O=Test,C=US'}); // DEPRECATED
 * gn = new KJUR.asn1.x509.GeneralName({certissuer: certPEM});       // DEPRECATED
 * gn = new KJUR.asn1.x509.GeneralName({certsubj:   certPEM});       // DEPRECATED
 */
KJUR.asn1.x509.GeneralName = function(params) {
    KJUR.asn1.x509.GeneralName.superclass.constructor.call(this);

    var pTag = { rfc822: '81', dns: '82', dn: 'a4',  
		 uri: '86', ip: '87', otherName: 'a0'},
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_X500Name = _KJUR_asn1_x509.X500Name,
	_OtherName = _KJUR_asn1_x509.OtherName,
	_DERIA5String = _KJUR_asn1.DERIA5String,
	_DERPrintableString = _KJUR_asn1.DERPrintableString,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_Error = Error;

    this.params = null;

    this.setByParam = function(params) {
	this.params = params;
    };

    this.tohex = function() {
	var params = this.params;
	var hTag, explicitFlag, dObj;
	var explicitFlag = false;
	if (params.other !== undefined) {
	    hTag = "a0",
	    dObj = new _OtherName(params.other);
	} else if (params.rfc822 !== undefined) {
	    hTag = "81";
	    dObj = new _DERIA5String({str: params.rfc822});
	} else if (params.dns !== undefined) {
	    hTag = "82";
	    dObj = new _DERIA5String({str: params.dns});
	} else if (params.dn !== undefined) {
	    hTag = "a4";
	    explicitFlag = true;
	    if (typeof params.dn === "string") {
		dObj = new _X500Name({str: params.dn});
	    } else if (params.dn instanceof KJUR.asn1.x509.X500Name) {
		dObj = params.dn;
	    } else {
		dObj = new _X500Name(params.dn);
	    }
	} else if (params.ldapdn !== undefined) {
	    hTag = "a4";
	    explicitFlag = true;
	    dObj = new _X500Name({ldapstr: params.ldapdn});
	} else if (params.certissuer !== undefined ||
		   params.certsubj !== undefined) {
	    hTag = "a4";
	    explicitFlag = true;
	    var isIssuer, certStr;
	    var certHex = null;
	    if (params.certsubj !== undefined) {
		isIssuer = false;
		certStr = params.certsubj;
	    } else {
		isIssuer = true;
		certStr = params.certissuer;
	    }

	    if (certStr.match(/^[0-9A-Fa-f]+$/)) {
		certHex == certStr;
            }
	    if (certStr.indexOf("-----BEGIN ") != -1) {
		certHex = pemtohex(certStr);
	    }
	    if (certHex == null) 
		throw new Error("certsubj/certissuer not cert");

	    var x = new X509();
	    x.hex = certHex;

	    var hDN;
	    if (isIssuer) {
		hDN = x.getIssuerHex();
	    } else {
		hDN = x.getSubjectHex();
	    }
	    dObj = new _ASN1Object();
	    dObj.hTLV = hDN;
	} else if (params.uri !== undefined) {
	    hTag = "86";
	    dObj = new _DERIA5String({str: params.uri});
	} else if (params.ip !== undefined) {
	    hTag = "87";
	    var hIP;
	    var ip = params.ip;
	    try {
		if (ip.match(/^[0-9a-f]+$/)) {
		    var len = ip.length;
		    if (len == 8 || len == 16 || len == 32 || len == 64) {
			hIP = ip;
		    } else {
			throw "err";
		    }
		} else {
		    hIP = iptohex(ip);
		}
	    } catch(ex) {
		throw new _Error("malformed IP address: " + params.ip + ":" + ex.message);
	    }
	    dObj = new _DEROctetString({hex: hIP});
	} else {
	    throw new _Error("improper params");
	}

	var dTag = new _DERTaggedObject({tag: hTag,
					 explicit: explicitFlag,
					 obj: dObj});
	return dTag.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.x509.GeneralName, KJUR.asn1.ASN1Object);

/**
 * GeneralNames ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.GeneralNames
 * @class GeneralNames ASN.1 structure class
 * @description
 * <br/>
 * <h4>EXAMPLE AND ASN.1 SYNTAX</h4>
 * @example
 * gns = new KJUR.asn1.x509.GeneralNames([{'uri': 'http://aaa.com/'}, {'uri': 'http://bbb.com/'}]);
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 */
KJUR.asn1.x509.GeneralNames = function(paramsArray) {
    KJUR.asn1.x509.GeneralNames.superclass.constructor.call(this);
    var asn1Array = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1;

    /**
     * set a array of {@link KJUR.asn1.x509.GeneralName} parameters<br/>
     * @name setByParamArray
     * @memberOf KJUR.asn1.x509.GeneralNames#
     * @function
     * @param {Array} paramsArray Array of {@link KJUR.asn1.x509.GeneralNames}
     * @description
     * <br/>
     * <h4>EXAMPLES</h4>
     * @example
     * gns = new KJUR.asn1.x509.GeneralNames();
     * gns.setByParamArray([{uri: 'http://aaa.com/'}, {uri: 'http://bbb.com/'}]);
     */
    this.setByParamArray = function(paramsArray) {
        for (var i = 0; i < paramsArray.length; i++) {
            var o = new _KJUR_asn1.x509.GeneralName(paramsArray[i]);
            this.asn1Array.push(o);
        }
    };

    this.tohex = function() {
        var o = new _KJUR_asn1.DERSequence({'array': this.asn1Array});
        return o.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    this.asn1Array = new Array();
    if (typeof paramsArray != "undefined") {
        this.setByParamArray(paramsArray);
    }
};
extendClass(KJUR.asn1.x509.GeneralNames, KJUR.asn1.ASN1Object);

/**
 * OtherName of GeneralName ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.OtherName
 * @class OtherName ASN.1 structure class
 * @since jsrsasign 10.5.3 asn1x509 2.1.12
 * @see KJUR.asn1.x509.GeneralName
 * @see KJUR.asn1.ASN1Util.newObject
 *
 * @description
 * This class is for OtherName of GeneralName ASN.1 structure.
 * Constructor has two members:
 * <ul>
 * <li>oid - oid string (ex. "1.2.3.4")</li>
 * <li>value - associative array passed to ASN1Util.newObject</li>
 * </ul>
 *
 * <pre>
 * OtherName ::= SEQUENCE {
 *   type-id    OBJECT IDENTIFIER,
 *   value      [0] EXPLICIT ANY DEFINED BY type-id }
 * </pre>
 *
 * @example
 * new KJUR.asn1.x509.OtherName({
 *   oid: "1.2.3.4",
 *   value: {prnstr: {str: "abc"}}
 * })
 */
KJUR.asn1.x509.OtherName = function(params) {
    KJUR.asn1.x509.OtherName.superclass.constructor.call(this);

    var asn1Obj = null,
	type = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_DERSequence = _KJUR_asn1.DERSequence,
	_newObject = _KJUR_asn1.ASN1Util.newObject;

    this.params = null;

    this.setByParam = function(params) {
	this.params = params;
    };

    this.tohex = function() {
	var params = this.params;

	if (params.oid == undefined || params.value == undefined)
	    throw new Error("oid or value not specified");

	var dOid = new _DERObjectIdentifier({oid: params.oid});
	var dValue = _newObject({tag: {tag: "a0",
				       explicit: true,
				       obj: params.value}});
	var dSeq = new _DERSequence({array: [dOid, dValue]});

        return dSeq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.x509.OtherName, KJUR.asn1.ASN1Object);

/**
 * static object for OID
 * @name KJUR.asn1.x509.OID
 * @class static object for OID
 * @property {Assoc Array} atype2oidList for short attribute type name and oid (ex. 'C' and '2.5.4.6')
 * @property {Assoc Array} name2oidList for oid name and oid (ex. 'keyUsage' and '2.5.29.15')
 * @property {Assoc Array} objCache for caching name and DERObjectIdentifier object
 *
 * @description
 * This class defines OID name and values.
 * AttributeType names registered in OID.atype2oidList are following:
 * <table style="border-width: thin; border-style: solid; witdh: 100%">
 * <tr><th>short</th><th>long</th><th>OID</th></tr>
 * <tr><td>CN</td>commonName<td></td><td>2.5.4.3</td></tr>
 * <tr><td>L</td><td>localityName</td><td>2.5.4.7</td></tr>
 * <tr><td>ST</td><td>stateOrProvinceName</td><td>2.5.4.8</td></tr>
 * <tr><td>O</td><td>organizationName</td><td>2.5.4.10</td></tr>
 * <tr><td>OU</td><td>organizationalUnitName</td><td>2.5.4.11</td></tr>
 * <tr><td>C</td><td></td>countryName<td>2.5.4.6</td></tr>
 * <tr><td>STREET</td>streetAddress<td></td><td>2.5.4.6</td></tr>
 * <tr><td>DC</td><td>domainComponent</td><td>0.9.2342.19200300.100.1.25</td></tr>
 * <tr><td>UID</td><td>userId</td><td>0.9.2342.19200300.100.1.1</td></tr>
 * <tr><td>SN</td><td>surname</td><td>2.5.4.4</td></tr>
 * <tr><td>DN</td><td>distinguishedName</td><td>2.5.4.49</td></tr>
 * <tr><td>E</td><td>emailAddress</td><td>1.2.840.113549.1.9.1</td></tr>
 * <tr><td></td><td>businessCategory</td><td>2.5.4.15</td></tr>
 * <tr><td></td><td>postalCode</td><td>2.5.4.17</td></tr>
 * <tr><td></td><td>jurisdictionOfIncorporationL</td><td>1.3.6.1.4.1.311.60.2.1.1</td></tr>
 * <tr><td></td><td>jurisdictionOfIncorporationSP</td><td>1.3.6.1.4.1.311.60.2.1.2</td></tr>
 * <tr><td></td><td>jurisdictionOfIncorporationC</td><td>1.3.6.1.4.1.311.60.2.1.3</td></tr>
 * </table>
 *
 * @example
 */
KJUR.asn1.x509.OID = new function() {
    var _DERObjectIdentifier = KJUR.asn1.DERObjectIdentifier;

    this.name2oidList = {
        'sha1':                 '1.3.14.3.2.26',
        'sha256':               '2.16.840.1.101.3.4.2.1',
        'sha384':               '2.16.840.1.101.3.4.2.2',
        'sha512':               '2.16.840.1.101.3.4.2.3',
        'sha224':               '2.16.840.1.101.3.4.2.4',
        'md5':                  '1.2.840.113549.2.5',
        'md2':                  '1.3.14.7.2.2.1',
        'ripemd160':            '1.3.36.3.2.1',

        'MD2withRSA':           '1.2.840.113549.1.1.2',
        'MD4withRSA':           '1.2.840.113549.1.1.3',
        'MD5withRSA':           '1.2.840.113549.1.1.4',
        'SHA1withRSA':          '1.2.840.113549.1.1.5',
	'pkcs1-MGF':		'1.2.840.113549.1.1.8',
	'rsaPSS':		'1.2.840.113549.1.1.10',
        'SHA224withRSA':        '1.2.840.113549.1.1.14',
        'SHA256withRSA':        '1.2.840.113549.1.1.11',
        'SHA384withRSA':        '1.2.840.113549.1.1.12',
        'SHA512withRSA':        '1.2.840.113549.1.1.13',

        'SHA1withECDSA':        '1.2.840.10045.4.1',
        'SHA224withECDSA':      '1.2.840.10045.4.3.1',
        'SHA256withECDSA':      '1.2.840.10045.4.3.2',
        'SHA384withECDSA':      '1.2.840.10045.4.3.3',
        'SHA512withECDSA':      '1.2.840.10045.4.3.4',

        'dsa':                  '1.2.840.10040.4.1',
        'SHA1withDSA':          '1.2.840.10040.4.3',
        'SHA224withDSA':        '2.16.840.1.101.3.4.3.1',
        'SHA256withDSA':        '2.16.840.1.101.3.4.3.2',

        'rsaEncryption':        '1.2.840.113549.1.1.1',

	// X.500 AttributeType defined in RFC 4514
        'commonName':			'2.5.4.3',
        'countryName':			'2.5.4.6',
        'localityName':			'2.5.4.7',
        'stateOrProvinceName':		'2.5.4.8',
        'streetAddress':		'2.5.4.9',
        'organizationName':		'2.5.4.10',
        'organizationalUnitName':	'2.5.4.11',
        'domainComponent':		'0.9.2342.19200300.100.1.25',
        'userId':			'0.9.2342.19200300.100.1.1',
	// other AttributeType name string
	'surname':			'2.5.4.4',
        'givenName':                    '2.5.4.42',
        'title':			'2.5.4.12',
	'distinguishedName':		'2.5.4.49',
	'emailAddress':			'1.2.840.113549.1.9.1',
	// other AttributeType name string (no short name)
	'description':			'2.5.4.13',
	'businessCategory':		'2.5.4.15',
	'postalCode':			'2.5.4.17',
	'uniqueIdentifier':		'2.5.4.45',
	'organizationIdentifier':	'2.5.4.97',
	'jurisdictionOfIncorporationL':	'1.3.6.1.4.1.311.60.2.1.1',
	'jurisdictionOfIncorporationSP':'1.3.6.1.4.1.311.60.2.1.2',
	'jurisdictionOfIncorporationC':	'1.3.6.1.4.1.311.60.2.1.3',

        'subjectDirectoryAttributes': '2.5.29.9',
        'subjectKeyIdentifier': '2.5.29.14',
        'keyUsage':             '2.5.29.15',
        'subjectAltName':       '2.5.29.17',
        'issuerAltName':        '2.5.29.18',
        'basicConstraints':     '2.5.29.19',
        'cRLNumber':     	'2.5.29.20',
        'cRLReason':     	'2.5.29.21',
        'nameConstraints':      '2.5.29.30',
        'cRLDistributionPoints':'2.5.29.31',
        'certificatePolicies':  '2.5.29.32',
        'anyPolicy':  		'2.5.29.32.0',
        'authorityKeyIdentifier':'2.5.29.35',
        'policyConstraints':    '2.5.29.36',
        'extKeyUsage':          '2.5.29.37',
        'authorityInfoAccess':  '1.3.6.1.5.5.7.1.1',
        'ocsp':                 '1.3.6.1.5.5.7.48.1',
        'ocspBasic':            '1.3.6.1.5.5.7.48.1.1',
        'ocspNonce':            '1.3.6.1.5.5.7.48.1.2',
        'ocspNoCheck':          '1.3.6.1.5.5.7.48.1.5',
        'caIssuers':            '1.3.6.1.5.5.7.48.2',

        'anyExtendedKeyUsage':  '2.5.29.37.0',
        'serverAuth':           '1.3.6.1.5.5.7.3.1',
        'clientAuth':           '1.3.6.1.5.5.7.3.2',
        'codeSigning':          '1.3.6.1.5.5.7.3.3',
        'emailProtection':      '1.3.6.1.5.5.7.3.4',
        'timeStamping':         '1.3.6.1.5.5.7.3.8',
        'ocspSigning':          '1.3.6.1.5.5.7.3.9',

        'dateOfBirth':          '1.3.6.1.5.5.7.9.1',
        'placeOfBirth':         '1.3.6.1.5.5.7.9.2',
        'gender':               '1.3.6.1.5.5.7.9.3',
        'countryOfCitizenship': '1.3.6.1.5.5.7.9.4',
        'countryOfResidence':   '1.3.6.1.5.5.7.9.5',

        'ecPublicKey':          '1.2.840.10045.2.1',
        'P-256':                '1.2.840.10045.3.1.7',
        'secp256r1':            '1.2.840.10045.3.1.7',
        'secp256k1':            '1.3.132.0.10',
        'secp384r1':            '1.3.132.0.34',
        'secp521r1':            '1.3.132.0.35',

        'pkcs5PBES2':           '1.2.840.113549.1.5.13',
        'pkcs5PBKDF2':          '1.2.840.113549.1.5.12',

        'des-EDE3-CBC':         '1.2.840.113549.3.7',

        'data':                 '1.2.840.113549.1.7.1', // CMS data
        'signed-data':          '1.2.840.113549.1.7.2', // CMS signed-data
        'enveloped-data':       '1.2.840.113549.1.7.3', // CMS enveloped-data
        'digested-data':        '1.2.840.113549.1.7.5', // CMS digested-data
        'encrypted-data':       '1.2.840.113549.1.7.6', // CMS encrypted-data
        'authenticated-data':   '1.2.840.113549.1.9.16.1.2', // CMS authenticated-data
        'tstinfo':              '1.2.840.113549.1.9.16.1.4', // RFC3161 TSTInfo
	'signingCertificate':	'1.2.840.113549.1.9.16.2.12',// SMIME
	'timeStampToken':	'1.2.840.113549.1.9.16.2.14',// sigTS
	'signaturePolicyIdentifier':	'1.2.840.113549.1.9.16.2.15',// cades
	'etsArchiveTimeStamp':	'1.2.840.113549.1.9.16.2.27',// SMIME
	'signingCertificateV2':	'1.2.840.113549.1.9.16.2.47',// SMIME
	'etsArchiveTimeStampV2':'1.2.840.113549.1.9.16.2.48',// SMIME
        'extensionRequest':     '1.2.840.113549.1.9.14',// CSR extensionRequest
	'contentType':		'1.2.840.113549.1.9.3',//PKCS#9
	'messageDigest':	'1.2.840.113549.1.9.4',//PKCS#9
	'signingTime':		'1.2.840.113549.1.9.5',//PKCS#9
	'counterSignature':	'1.2.840.113549.1.9.6',//PKCS#9
	'archiveTimeStampV3':	'0.4.0.1733.2.4',//ETSI EN29319122/TS101733
	'pdfRevocationInfoArchival':'1.2.840.113583.1.1.8', //Adobe
	'adobeTimeStamp':	'1.2.840.113583.1.1.9.1', // Adobe
    };

    this.atype2oidList = {
	// RFC 4514 AttributeType name string (MUST recognized)
        'CN':		'2.5.4.3',
        'L':		'2.5.4.7',
        'ST':		'2.5.4.8',
        'O':		'2.5.4.10',
        'OU':		'2.5.4.11',
        'C':		'2.5.4.6',
        'STREET':	'2.5.4.9',
        'DC':		'0.9.2342.19200300.100.1.25',
        'UID':		'0.9.2342.19200300.100.1.1',
	// other AttributeType name string
	// http://blog.livedoor.jp/k_urushima/archives/656114.html
        'SN':		'2.5.4.4', // surname
        'T':		'2.5.4.12', // title
        'DN':		'2.5.4.49', // distinguishedName
        'E':		'1.2.840.113549.1.9.1', // emailAddress in MS.NET or Bouncy
	// other AttributeType name string (no short name)
	'description':			'2.5.4.13',
	'businessCategory':		'2.5.4.15',
	'postalCode':			'2.5.4.17',
	'serialNumber':			'2.5.4.5',
	'uniqueIdentifier':		'2.5.4.45',
	'organizationIdentifier':	'2.5.4.97',
	'jurisdictionOfIncorporationL':	'1.3.6.1.4.1.311.60.2.1.1',
	'jurisdictionOfIncorporationSP':'1.3.6.1.4.1.311.60.2.1.2',
	'jurisdictionOfIncorporationC':	'1.3.6.1.4.1.311.60.2.1.3'
    };
    
    this.objCache = {};

    /**
     * get DERObjectIdentifier by registered OID name
     * @name name2obj
     * @memberOf KJUR.asn1.x509.OID
     * @function
     * @param {String} name OID
     * @return {Object} DERObjectIdentifier instance
     * @see KJUR.asn1.DERObjectIdentifier
     *
     * @description
     * This static method returns DERObjectIdentifier object
     * for the specified OID.
     *
     * @example
     * var asn1ObjOID = KJUR.asn1.x509.OID.name2obj('SHA1withRSA');
     */
    this.name2obj = function(name) {
        if (typeof this.objCache[name] != "undefined")
            return this.objCache[name];
        if (typeof this.name2oidList[name] == "undefined")
            throw "Name of ObjectIdentifier not defined: " + name;
        var oid = this.name2oidList[name];
        var obj = new _DERObjectIdentifier({'oid': oid});
        this.objCache[name] = obj;
        return obj;
    };

    /**
     * get DERObjectIdentifier by registered attribute type name such like 'C' or 'CN'<br/>
     * @name atype2obj
     * @memberOf KJUR.asn1.x509.OID
     * @function
     * @param {String} atype short attribute type name such like 'C', 'CN' or OID
     * @return KJUR.asn1.DERObjectIdentifier instance
     * @description
     * @example
     * KJUR.asn1.x509.OID.atype2obj('CN') &rarr; DERObjectIdentifier of 2.5.4.3
     * KJUR.asn1.x509.OID.atype2obj('OU') &rarr; DERObjectIdentifier of 2.5.4.11
     * KJUR.asn1.x509.OID.atype2obj('streetAddress') &rarr; DERObjectIdentifier of 2.5.4.9
     * KJUR.asn1.x509.OID.atype2obj('2.5.4.9') &rarr; DERObjectIdentifier of 2.5.4.9
     */
    this.atype2obj = function(atype) {
        if (this.objCache[atype] !== undefined)
            return this.objCache[atype];

	var oid;

	if (atype.match(/^\d+\.\d+\.[0-9.]+$/)) {
	    oid = atype;
	} else if (this.atype2oidList[atype] !== undefined) {
	    oid = this.atype2oidList[atype];
	} else if (this.name2oidList[atype] !== undefined) {
	    oid = this.name2oidList[atype];
    	} else {
            throw new Error("AttributeType name undefined: " + atype);
	}
        var obj = new _DERObjectIdentifier({'oid': oid});
        this.objCache[atype] = obj;
        return obj;
    };

    /**
     * register OID list<br/>
     * @name registerOIDs
     * @memberOf KJUR.asn1.x509.OID
     * @function
     * @param {object} oids associative array of names and oids
     * @since jsrsasign 10.5.2 asn1x509 2.1.11
     * @see KJUR.asn1.x509.OID.checkOIDs
     * 
     * @description
     * This static method to register an oids to existing list
     * additionally.
     *
     * @example
     * KJUR.asn1.x509.OID.checkOIDs({
     *   "test1": "4.5.7.8"
     * }) // do nothing for invalid list
     *
     * KJUR.asn1.x509.OID.registerOIDs({
     *   "test1": "1.2.3",
     *   "test2": "0.2.3.4.23",
     * }) // successfully registered
     *
     * KJUR.asn1.x509.OID.name2oid("test1") &rarr; "1.2.3"
     */
    this.registerOIDs = function(oids) {
	if (! this.checkOIDs(oids)) return;
	for (var name in oids) {
	    this.name2oidList[name] = oids[name];
	}
    };

    /**
     * check validity for OID list<br/>
     * @name checkOIDs
     * @memberOf KJUR.asn1.x509.OID
     * @function
     * @param {object} oids associative array of names and oids
     * @return {boolean} return true when valid OID list otherwise false
     * @since jsrsasign 10.5.2 asn1x509 2.1.11
     * @see KJUR.asn1.x509.OID.registOIDs
     * 
     * @description
     * This static method validates an associative array
     * as oid list.
     *
     * @example
     * KJUR.asn1.x509.OID.checkOIDs(*non-assoc-array*) &rarr; false
     * KJUR.asn1.x509.OID.checkOIDs({}) &rarr; false
     * KJUR.asn1.x509.OID.checkOIDs({"test1": "apple"}) &rarr; false
     * KJUR.asn1.x509.OID.checkOIDs({
     *   "test1": "1.2.3",
     *   "test2": "0.2.3.4.23",
     * }) &rarr; true // valid oids
     * KJUR.asn1.x509.OID.checkOIDs({
     *   "test1": "4.5.7.8"
     * }) &rarr; false // invalid oid
     */
    this.checkOIDs = function(oids) {
	try {
	    var nameList = Object.keys(oids);
	    if (nameList.length == 0)
		return false;
	    nameList.map(function(value, index, array) {
		var oid = this[value];
		if (! oid.match(/^[0-2]\.[0-9.]+$/))
		    throw new Error("value is not OID");
	    }, oids);
	    return true;
	} catch(ex) {
	    return false;
	}
    };


};

/**
 * convert OID to name<br/>
 * @name oid2name
 * @memberOf KJUR.asn1.x509.OID
 * @function
 * @param {String} oid dot noted Object Identifer string (ex. 1.2.3.4)
 * @return {String} OID name if registered otherwise empty string
 * @since asn1x509 1.0.9
 * @description
 * This static method converts OID string to its name.
 * If OID is undefined then it returns empty string (i.e. '').
 * @example
 * KJUR.asn1.x509.OID.oid2name("1.3.6.1.5.5.7.1.1") &rarr; 'authorityInfoAccess'
 */
KJUR.asn1.x509.OID.oid2name = function(oid) {
    var list = KJUR.asn1.x509.OID.name2oidList;
    for (var name in list) {
        if (list[name] == oid) return name;
    }
    return '';
};

/**
 * convert OID to AttributeType name<br/>
 * @name oid2atype
 * @memberOf KJUR.asn1.x509.OID
 * @function
 * @param {String} oid dot noted Object Identifer string (ex. 1.2.3.4)
 * @return {String} OID AttributeType name if registered otherwise oid
 * @since jsrsasign 6.2.2 asn1x509 1.0.18
 * @description
 * This static method converts OID string to its AttributeType name.
 * If OID is not defined in OID.atype2oidList associative array then it returns OID
 * specified as argument.
 * @example
 * KJUR.asn1.x509.OID.oid2atype("2.5.4.3") &rarr; CN
 * KJUR.asn1.x509.OID.oid2atype("1.3.6.1.4.1.311.60.2.1.3") &rarr; jurisdictionOfIncorporationC
 * KJUR.asn1.x509.OID.oid2atype("0.1.2.3.4") &rarr; 0.1.2.3.4 // unregistered OID
 */
KJUR.asn1.x509.OID.oid2atype = function(oid) {
    var list = KJUR.asn1.x509.OID.atype2oidList;
    for (var atype in list) {
        if (list[atype] == oid) return atype;
    }
    return oid;
};

/**
 * convert OID name to OID value<br/>
 * @name name2oid
 * @memberOf KJUR.asn1.x509.OID
 * @function
 * @param {String} name OID name or OID (ex. "sha1" or "1.2.3.4")
 * @return {String} dot noted Object Identifer string (ex. 1.2.3.4)
 * @since asn1x509 1.0.11
 * @description
 * This static method converts from OID name to OID string.
 * If OID is undefined then it returns empty string (i.e. '').
 * @example
 * KJUR.asn1.x509.OID.name2oid("authorityInfoAccess") &rarr; "1.3.6.1.5.5.7.1.1"
 * KJUR.asn1.x509.OID.name2oid("1.2.3.4") &rarr; "1.2.3.4"
 * KJUR.asn1.x509.OID.name2oid("UNKNOWN NAME") &rarr; ""
 */
KJUR.asn1.x509.OID.name2oid = function(name) {
    if (name.match(/^[0-9.]+$/)) return name;
    var list = KJUR.asn1.x509.OID.name2oidList;
    if (list[name] === undefined) return '';
    return list[name];
};

/**
 * X.509 certificate and CRL utilities class<br/>
 * @name KJUR.asn1.x509.X509Util
 * @class X.509 certificate and CRL utilities class
 */
KJUR.asn1.x509.X509Util = {};

/**
 * issue a certificate in PEM format (DEPRECATED)
 * @name newCertPEM
 * @memberOf KJUR.asn1.x509.X509Util
 * @function
 * @param {Array} param JSON object of parameter to issue a certificate
 * @since asn1x509 1.0.6
 * @deprecated since jsrsasign 9.0.0 asn1x509 2.0.0. please move to {@link KJUR.asn1.x509.Certificate} constructor
 * @description
 * This method can issue a certificate by a simple
 * JSON object.
 * Signature value will be provided by signing with
 * private key using 'cakey' parameter or
 * hexadecimal signature value by 'sighex' parameter.
 * <br/>
 * NOTE: Algorithm parameter of AlgorithmIdentifier will
 * be set automatically by default. 
 * (see {@link KJUR.asn1.x509.AlgorithmIdentifier})
 * from jsrsasign 7.1.1 asn1x509 1.0.20.
 * <br/>
 * NOTE2: 
 * RSA-PSS algorithm has been supported from jsrsasign 8.0.21.
 * As for RSA-PSS signature algorithm names and signing parameters 
 * such as MGF function and salt length, please see
 * {@link KJUR.asn1.x509.AlgorithmIdentifier} class.
 *
 * @example
 * var certPEM = KJUR.asn1.x509.X509Util.newCertPEM({
 *   serial: {int: 4},
 *   sigalg: {name: 'SHA1withECDSA'},
 *   issuer: {str: '/C=US/O=a'},
 *   notbefore: {'str': '130504235959Z'},
 *   notafter: {'str': '140504235959Z'},
 *   subject: {str: '/C=US/O=b'},
 *   sbjpubkey: pubKeyObj,
 *   ext: [
 *     {basicConstraints: {cA: true, critical: true}},
 *     {keyUsage: {bin: '11'}},
 *   ],
 *   cakey: prvKeyObj
 * });
 * // -- or --
 * var certPEM = KJUR.asn1.x509.X509Util.newCertPEM({
 *   serial: {int: 4},
 *   sigalg: {name: 'SHA1withECDSA'},
 *   issuer: {str: '/C=US/O=a'},
 *   notbefore: {'str': '130504235959Z'},
 *   notafter: {'str': '140504235959Z'},
 *   subject: {str: '/C=US/O=b'},
 *   sbjpubkey: pubKeyPEM,
 *   ext: [
 *     {basicConstraints: {cA: true, critical: true}},
 *     {keyUsage: {bin: '11'}},
 *   ],
 *   cakey: [prvkey, pass]}
 * );
 * // -- or --
 * var certPEM = KJUR.asn1.x509.X509Util.newCertPEM({
 *   serial: {int: 1},
 *   sigalg: {name: 'SHA1withRSA'},
 *   issuer: {str: '/C=US/O=T1'},
 *   notbefore: {'str': '130504235959Z'},
 *   notafter: {'str': '140504235959Z'},
 *   subject: {str: '/C=US/O=T1'},
 *   sbjpubkey: pubKeyObj,
 *   sighex: '0102030405..'
 * });
 * // for the issuer and subject field, another
 * // representation is also available
 * var certPEM = KJUR.asn1.x509.X509Util.newCertPEM({
 *   serial: {int: 1},
 *   sigalg: {name: 'SHA256withRSA'},
 *   issuer: {C: "US", O: "T1"},
 *   notbefore: {'str': '130504235959Z'},
 *   notafter: {'str': '140504235959Z'},
 *   subject: {C: "US", O: "T1", CN: "http://example.com/"},
 *   sbjpubkey: pubKeyObj,
 *   sighex: '0102030405..'
 * });
 */
KJUR.asn1.x509.X509Util.newCertPEM = function(param) {
    var _KJUR_asn1_x509 = KJUR.asn1.x509,
	_TBSCertificate = _KJUR_asn1_x509.TBSCertificate,
	_Certificate = _KJUR_asn1_x509.Certificate;
    var cert = new _Certificate(param);
    return cert.getPEM();
};

