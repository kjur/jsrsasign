/* asn1x509-1.1.6.js (c) 2013-2018 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1x509.js - ASN.1 DER encoder classes for X.509 certificate
 *
 * Copyright (c) 2013-2018 Kenji Urushima (kenji.urushima@gmail.com)
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
 * @version jsrsasign 8.0.12 asn1x509 1.1.6 (2018-Apr-22)
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
 * <li>{@link KJUR.asn1.x509.Extension}</li>
 * <li>{@link KJUR.asn1.x509.X500Name}</li>
 * <li>{@link KJUR.asn1.x509.RDN}</li>
 * <li>{@link KJUR.asn1.x509.AttributeTypeAndValue}</li>
 * <li>{@link KJUR.asn1.x509.SubjectPublicKeyInfo}</li>
 * <li>{@link KJUR.asn1.x509.AlgorithmIdentifier}</li>
 * <li>{@link KJUR.asn1.x509.GeneralName}</li>
 * <li>{@link KJUR.asn1.x509.GeneralNames}</li>
 * <li>{@link KJUR.asn1.x509.DistributionPointName}</li>
 * <li>{@link KJUR.asn1.x509.DistributionPoint}</li>
 * <li>{@link KJUR.asn1.x509.CRL}</li>
 * <li>{@link KJUR.asn1.x509.TBSCertList}</li>
 * <li>{@link KJUR.asn1.x509.CRLEntry}</li>
 * <li>{@link KJUR.asn1.x509.OID}</li>
 * </ul>
 * <h4>SUPPORTED EXTENSIONS</h4>
 * <ul>
 * <li>{@link KJUR.asn1.x509.BasicConstraints}</li>
 * <li>{@link KJUR.asn1.x509.KeyUsage}</li>
 * <li>{@link KJUR.asn1.x509.CRLDistributionPoints}</li>
 * <li>{@link KJUR.asn1.x509.ExtKeyUsage}</li>
 * <li>{@link KJUR.asn1.x509.AuthorityKeyIdentifier}</li>
 * <li>{@link KJUR.asn1.x509.AuthorityInfoAccess}</li>
 * <li>{@link KJUR.asn1.x509.SubjectAltName}</li>
 * <li>{@link KJUR.asn1.x509.IssuerAltName}</li>
 * </ul>
 * NOTE1: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.<br/>
 * NOTE2: SubjectAltName and IssuerAltName extension were supported since 
 * jsrsasign 6.2.3 asn1x509 1.0.19.<br/>
 * @name KJUR.asn1.x509
 * @namespace
 */
if (typeof KJUR.asn1.x509 == "undefined" || !KJUR.asn1.x509) KJUR.asn1.x509 = {};

// === BEGIN Certificate ===================================================

/**
 * X.509 Certificate class to sign and generate hex encoded certificate
 * @name KJUR.asn1.x509.Certificate
 * @class X.509 Certificate class to sign and generate hex encoded certificate
 * @param {Array} params associative array of parameters (ex. {'tbscertobj': obj, 'prvkeyobj': key})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>tbscertobj - specify {@link KJUR.asn1.x509.TBSCertificate} object</li>
 * <li>prvkeyobj - specify {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.DSA} object for CA private key to sign the certificate</li>
 * </ul>
 * NOTE1: 'params' can be omitted.<br/>
 * NOTE2: DSA/ECDSA is also supported for CA signging key from asn1x509 1.0.6.
 * @example
 * var caKey = KEYUTIL.getKey(caKeyPEM); // CA's private key
 * var cert = new KJUR.asn1x509.Certificate({'tbscertobj': tbs, 'prvkeyobj': caKey});
 * cert.sign(); // issue certificate by CA's private key
 * var certPEM = cert.getPEMString();
 *
 * // Certificate  ::=  SEQUENCE  {
 * //     tbsCertificate       TBSCertificate,
 * //     signatureAlgorithm   AlgorithmIdentifier,
 * //     signature            BIT STRING  }
 */
KJUR.asn1.x509.Certificate = function(params) {
    KJUR.asn1.x509.Certificate.superclass.constructor.call(this);
    var asn1TBSCert = null,
	asn1SignatureAlg = null,
	asn1Sig = null,
	hexSig = null,
        prvKey = null,
	_KJUR = KJUR,
	_KJUR_crypto = _KJUR.crypto,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERBitString = _KJUR_asn1.DERBitString;

    /**
     * sign TBSCertificate and set signature value internally
     * @name sign
     * @memberOf KJUR.asn1.x509.Certificate#
     * @function
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.Certificate({tbscertobj: tbs, prvkeyobj: prvKey});
     * cert.sign();
     */
    this.sign = function() {
        this.asn1SignatureAlg = this.asn1TBSCert.asn1SignatureAlg;
	
        var sig = new KJUR.crypto.Signature({alg: this.asn1SignatureAlg.nameAlg});
        sig.init(this.prvKey);
        sig.updateHex(this.asn1TBSCert.getEncodedHex());
        this.hexSig = sig.sign();

        this.asn1Sig = new _DERBitString({'hex': '00' + this.hexSig});

        var seq = new _DERSequence({'array': [this.asn1TBSCert,
                                              this.asn1SignatureAlg,
                                              this.asn1Sig]});
        this.hTLV = seq.getEncodedHex();
        this.isModified = false;
    };

    /**
     * set signature value internally by hex string
     * @name setSignatureHex
     * @memberOf KJUR.asn1.x509.Certificate#
     * @function
     * @since asn1x509 1.0.8
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.Certificate({'tbscertobj': tbs});
     * cert.setSignatureHex('01020304');
     */
    this.setSignatureHex = function(sigHex) {
        this.asn1SignatureAlg = this.asn1TBSCert.asn1SignatureAlg;
        this.hexSig = sigHex;
        this.asn1Sig = new _DERBitString({'hex': '00' + this.hexSig});

        var seq = new _DERSequence({'array': [this.asn1TBSCert,
                                              this.asn1SignatureAlg,
                                              this.asn1Sig]});
        this.hTLV = seq.getEncodedHex();
        this.isModified = false;
    };

    this.getEncodedHex = function() {
        if (this.isModified == false && this.hTLV != null) return this.hTLV;
        throw "not signed yet";
    };

    /**
     * get PEM formatted certificate string after signed
     * @name getPEMString
     * @memberOf KJUR.asn1.x509.Certificate#
     * @function
     * @return PEM formatted string of certificate
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.Certificate({'tbscertobj': tbs, 'prvkeyobj': prvKey});
     * cert.sign();
     * var sPEM = cert.getPEMString();
     */
    this.getPEMString = function() {
	var pemBody = hextob64nl(this.getEncodedHex());
        return "-----BEGIN CERTIFICATE-----\r\n" + 
	    pemBody + 
	    "\r\n-----END CERTIFICATE-----\r\n";
    };

    if (params !== undefined) {
        if (params.tbscertobj !== undefined) {
            this.asn1TBSCert = params.tbscertobj;
        }
        if (params.prvkeyobj !== undefined) {
            this.prvKey = params.prvkeyobj;
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.Certificate, KJUR.asn1.ASN1Object);

/**
 * ASN.1 TBSCertificate structure class
 * @name KJUR.asn1.x509.TBSCertificate
 * @class ASN.1 TBSCertificate structure class
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * <h4>EXAMPLE</h4>
 * @example
 *  var o = new KJUR.asn1.x509.TBSCertificate();
 *  o.setSerialNumberByParam({'int': 4});
 *  o.setSignatureAlgByParam({'name': 'SHA1withRSA'});
 *  o.setIssuerByParam({'str': '/C=US/O=a'});
 *  o.setNotBeforeByParam({'str': '130504235959Z'});
 *  o.setNotAfterByParam({'str': '140504235959Z'});
 *  o.setSubjectByParam({'str': '/C=US/CN=b'});
 *  o.setSubjectPublicKey(rsaPubKey);
 *  o.appendExtension(new KJUR.asn1.x509.BasicConstraints({'cA':true}));
 *  o.appendExtension(new KJUR.asn1.x509.KeyUsage({'bin':'11'}));
 */
KJUR.asn1.x509.TBSCertificate = function(params) {
    KJUR.asn1.x509.TBSCertificate.superclass.constructor.call(this);

    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_Time = _KJUR_asn1_x509.Time,
	_X500Name = _KJUR_asn1_x509.X500Name,
	_SubjectPublicKeyInfo = _KJUR_asn1_x509.SubjectPublicKeyInfo;

    this._initialize = function() {
        this.asn1Array = new Array();

        this.asn1Version =
            new _DERTaggedObject({'obj': new _DERInteger({'int': 2})});
        this.asn1SerialNumber = null;
        this.asn1SignatureAlg = null;
        this.asn1Issuer = null;
        this.asn1NotBefore = null;
        this.asn1NotAfter = null;
        this.asn1Subject = null;
        this.asn1SubjPKey = null;
        this.extensionsArray = new Array();
    };

    /**
     * set serial number field by parameter
     * @name setSerialNumberByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Array} intParam DERInteger param
     * @description
     * @example
     * tbsc.setSerialNumberByParam({'int': 3});
     */
    this.setSerialNumberByParam = function(intParam) {
        this.asn1SerialNumber = new _DERInteger(intParam);
    };

    /**
     * set signature algorithm field by parameter
     * @name setSignatureAlgByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Array} algIdParam AlgorithmIdentifier parameter
     * @description
     * @example
     * tbsc.setSignatureAlgByParam({'name': 'SHA1withRSA'});
     */
    this.setSignatureAlgByParam = function(algIdParam) {
        this.asn1SignatureAlg = new _KJUR_asn1_x509.AlgorithmIdentifier(algIdParam);
    };

    /**
     * set issuer name field by parameter
     * @name setIssuerByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Array} x500NameParam X500Name parameter
     * @description
     * @example
     * tbsc.setIssuerParam({'str': '/C=US/CN=b'});
     * @see KJUR.asn1.x509.X500Name
     */
    this.setIssuerByParam = function(x500NameParam) {
        this.asn1Issuer = new _X500Name(x500NameParam);
    };

    /**
     * set notBefore field by parameter
     * @name setNotBeforeByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Array} timeParam Time parameter
     * @description
     * @example
     * tbsc.setNotBeforeByParam({'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.setNotBeforeByParam = function(timeParam) {
        this.asn1NotBefore = new _Time(timeParam);
    };

    /**
     * set notAfter field by parameter
     * @name setNotAfterByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Array} timeParam Time parameter
     * @description
     * @example
     * tbsc.setNotAfterByParam({'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.setNotAfterByParam = function(timeParam) {
        this.asn1NotAfter = new _Time(timeParam);
    };

    /**
     * set subject name field by parameter
     * @name setSubjectByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Array} x500NameParam X500Name parameter
     * @description
     * @example
     * tbsc.setSubjectParam({'str': '/C=US/CN=b'});
     * @see KJUR.asn1.x509.X500Name
     */
    this.setSubjectByParam = function(x500NameParam) {
        this.asn1Subject = new _X500Name(x500NameParam);
    };

    /**
     * set subject public key info field by key object
     * @name setSubjectPublicKey
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Array} param {@link KJUR.asn1.x509.SubjectPublicKeyInfo} class constructor parameter
     * @description
     * @example
     * tbsc.setSubjectPublicKey(keyobj);
     * @see KJUR.asn1.x509.SubjectPublicKeyInfo
     */
    this.setSubjectPublicKey = function(param) {
        this.asn1SubjPKey = new _SubjectPublicKeyInfo(param);
    };

    /**
     * set subject public key info by RSA/ECDSA/DSA key parameter
     * @name setSubjectPublicKeyByGetKey
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Object} keyParam public key parameter which passed to {@link KEYUTIL.getKey} argument
     * @description
     * @example
     * tbsc.setSubjectPublicKeyByGetKeyParam(certPEMString); // or
     * tbsc.setSubjectPublicKeyByGetKeyParam(pkcs8PublicKeyPEMString); // or
     * tbsc.setSubjectPublicKeyByGetKeyParam(kjurCryptoECDSAKeyObject); // et.al.
     * @see KJUR.asn1.x509.SubjectPublicKeyInfo
     * @see KEYUTIL.getKey
     * @since asn1x509 1.0.6
     */
    this.setSubjectPublicKeyByGetKey = function(keyParam) {
        var keyObj = KEYUTIL.getKey(keyParam);
        this.asn1SubjPKey = new _SubjectPublicKeyInfo(keyObj);
    };

    /**
     * append X.509v3 extension to this object
     * @name appendExtension
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {Extension} extObj X.509v3 Extension object
     * @description
     * @example
     * tbsc.appendExtension(new KJUR.asn1.x509.BasicConstraints({'cA':true, 'critical': true}));
     * tbsc.appendExtension(new KJUR.asn1.x509.KeyUsage({'bin':'11'}));
     * @see KJUR.asn1.x509.Extension
     */
    this.appendExtension = function(extObj) {
        this.extensionsArray.push(extObj);
    };

    /**
     * append X.509v3 extension to this object by name and parameters
     * @name appendExtensionByName
     * @memberOf KJUR.asn1.x509.TBSCertificate#
     * @function
     * @param {name} name name of X.509v3 Extension object
     * @param {Array} extParams parameters as argument of Extension constructor.
     * @description
     * This method adds a X.509v3 extension specified by name 
     * and extParams to internal extension array of X.509v3 extension objects.
     * Here is supported names of extension:
     * <ul>
     * <li>BasicConstraints - {@link KJUR.asn1.x509.BasicConstraints}</li>
     * <li>KeyUsage - {@link KJUR.asn1.x509.KeyUsage}</li>
     * <li>CRLDistributionPoints - {@link KJUR.asn1.x509.CRLDistributionPoints}</li>
     * <li>ExtKeyUsage - {@link KJUR.asn1.x509.ExtKeyUsage}</li>
     * <li>AuthorityKeyIdentifier - {@link KJUR.asn1.x509.AuthorityKeyIdentifier}</li>
     * <li>AuthorityInfoAccess - {@link KJUR.asn1.x509.AuthorityInfoAccess}</li>
     * <li>SubjectAltName - {@link KJUR.asn1.x509.SubjectAltName}</li>
     * <li>IssuerAltName - {@link KJUR.asn1.x509.IssuerAltName}</li>
     * </ul>
     * @example
     * var o = new KJUR.asn1.x509.TBSCertificate();
     * o.appendExtensionByName('BasicConstraints', {'cA':true, 'critical': true});
     * o.appendExtensionByName('KeyUsage', {'bin':'11'});
     * o.appendExtensionByName('CRLDistributionPoints', {uri: 'http://aaa.com/a.crl'});
     * o.appendExtensionByName('ExtKeyUsage', {array: [{name: 'clientAuth'}]});
     * o.appendExtensionByName('AuthorityKeyIdentifier', {kid: '1234ab..'});
     * o.appendExtensionByName('AuthorityInfoAccess', {array: [{accessMethod:{oid:...},accessLocation:{uri:...}}]});
     * @see KJUR.asn1.x509.Extension
     */
    this.appendExtensionByName = function(name, extParams) {
	KJUR.asn1.x509.Extension.appendByNameToArray(name,
						     extParams,
						     this.extensionsArray);
    };

    this.getEncodedHex = function() {
        if (this.asn1NotBefore == null || this.asn1NotAfter == null)
            throw "notBefore and/or notAfter not set";
        var asn1Validity =
            new _DERSequence({'array':[this.asn1NotBefore, this.asn1NotAfter]});

        this.asn1Array = new Array();

        this.asn1Array.push(this.asn1Version);
        this.asn1Array.push(this.asn1SerialNumber);
        this.asn1Array.push(this.asn1SignatureAlg);
        this.asn1Array.push(this.asn1Issuer);
        this.asn1Array.push(asn1Validity);
        this.asn1Array.push(this.asn1Subject);
        this.asn1Array.push(this.asn1SubjPKey);

        if (this.extensionsArray.length > 0) {
            var extSeq = new _DERSequence({"array": this.extensionsArray});
            var extTagObj = new _DERTaggedObject({'explicit': true,
                                                  'tag': 'a3',
                                                  'obj': extSeq});
            this.asn1Array.push(extTagObj);
        }

        var o = new _DERSequence({"array": this.asn1Array});
        this.hTLV = o.getEncodedHex();
        this.isModified = false;
        return this.hTLV;
    };

    this._initialize();
};
YAHOO.lang.extend(KJUR.asn1.x509.TBSCertificate, KJUR.asn1.ASN1Object);

// === END   TBSCertificate ===================================================

// === BEGIN X.509v3 Extensions Related =======================================

/**
 * base Extension ASN.1 structure class
 * @name KJUR.asn1.x509.Extension
 * @class base Extension ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'critical': true})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @example
 * // Extension  ::=  SEQUENCE  {
 * //     extnID      OBJECT IDENTIFIER,
 * //     critical    BOOLEAN DEFAULT FALSE,
 * //     extnValue   OCTET STRING  }
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

    this.getEncodedHex = function() {
        var asn1Oid = new _DERObjectIdentifier({'oid': this.oid});
        var asn1EncapExtnValue =
            new _DEROctetString({'hex': this.getExtnValueHex()});

        var asn1Array = new Array();
        asn1Array.push(asn1Oid);
        if (this.critical) asn1Array.push(new _DERBoolean());
        asn1Array.push(asn1EncapExtnValue);

        var asn1Seq = new _DERSequence({'array': asn1Array});
        return asn1Seq.getEncodedHex();
    };

    this.critical = false;
    if (params !== undefined) {
        if (params.critical !== undefined) {
            this.critical = params.critical;
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.Extension, KJUR.asn1.ASN1Object);

/**
 * append X.509v3 extension to any specified array<br/>
 * @name appendByNameToArray
 * @memberOf KJUR.asn1.x509.Extension
 * @function
 * @param {String} name X.509v3 extension name
 * @param {Object} extParams associative array of extension parameters
 * @param {Array} a array to add specified extension
 * @see KJUR.asn1.x509.Extension
 * @since jsrsasign 6.2.3 asn1x509 1.0.19
 * @description
 * This static function add a X.509v3 extension specified by name and extParams to
 * array 'a' so that 'a' will be an array of X.509v3 extension objects.
 * See {@link KJUR.asn1.x509.TBSCertificate#appendExtensionByName}
 * for supported names of extensions.
 * @example
 * var a = new Array();
 * KJUR.asn1.x509.Extension.appendByNameToArray("BasicConstraints", {'cA':true, 'critical': true}, a);
 * KJUR.asn1.x509.Extension.appendByNameToArray("KeyUsage", {'bin':'11'}, a);
 */
KJUR.asn1.x509.Extension.appendByNameToArray = function(name, extParams, a) {
    var _lowname = name.toLowerCase(),
	_KJUR_asn1_x509 = KJUR.asn1.x509;
    
    if (_lowname == "basicconstraints") {
        var extObj = new _KJUR_asn1_x509.BasicConstraints(extParams);
        a.push(extObj);
    } else if (_lowname == "keyusage") {
        var extObj = new _KJUR_asn1_x509.KeyUsage(extParams);
        a.push(extObj);
    } else if (_lowname == "crldistributionpoints") {
        var extObj = new _KJUR_asn1_x509.CRLDistributionPoints(extParams);
        a.push(extObj);
    } else if (_lowname == "extkeyusage") {
        var extObj = new _KJUR_asn1_x509.ExtKeyUsage(extParams);
        a.push(extObj);
    } else if (_lowname == "authoritykeyidentifier") {
        var extObj = new _KJUR_asn1_x509.AuthorityKeyIdentifier(extParams);
        a.push(extObj);
    } else if (_lowname == "authorityinfoaccess") {
        var extObj = new _KJUR_asn1_x509.AuthorityInfoAccess(extParams);
        a.push(extObj);
    } else if (_lowname == "subjectaltname") {
        var extObj = new _KJUR_asn1_x509.SubjectAltName(extParams);
        a.push(extObj);
    } else if (_lowname == "issueraltname") {
        var extObj = new _KJUR_asn1_x509.IssuerAltName(extParams);
        a.push(extObj);
    } else {
        throw "unsupported extension name: " + name;
    }
};

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
    var _KEYUSAGE_NAME = X509.KEYUSAGE_NAME;

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.oid = "2.5.29.15";
    if (params !== undefined) {
        if (params.bin !== undefined) {
            this.asn1ExtnValue = new KJUR.asn1.DERBitString(params);
        }
	if (params.names !== undefined &&
	    params.names.length !== undefined) {
	    var names = params.names;
	    var s = "000000000";
	    for (var i = 0; i < names.length; i++) {
		for (var j = 0; j < _KEYUSAGE_NAME.length; j++) {
		    if (names[i] === _KEYUSAGE_NAME[j]) {
			s = s.substring(0, j) + '1' + 
			    s.substring(j + 1, s.length);
		    }
		}
	    }
            this.asn1ExtnValue = new KJUR.asn1.DERBitString({bin: s});
	}
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.KeyUsage, KJUR.asn1.x509.Extension);

/**
 * BasicConstraints ASN.1 structure class
 * @name KJUR.asn1.x509.BasicConstraints
 * @class BasicConstraints ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'cA': true, 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @description
 * @example
 */
KJUR.asn1.x509.BasicConstraints = function(params) {
    KJUR.asn1.x509.BasicConstraints.superclass.constructor.call(this, params);
    var cA = false;
    var pathLen = -1;

    this.getExtnValueHex = function() {
        var asn1Array = new Array();
        if (this.cA) asn1Array.push(new KJUR.asn1.DERBoolean());
        if (this.pathLen > -1)
            asn1Array.push(new KJUR.asn1.DERInteger({'int': this.pathLen}));
        var asn1Seq = new KJUR.asn1.DERSequence({'array': asn1Array});
        this.asn1ExtnValue = asn1Seq;
        return this.asn1ExtnValue.getEncodedHex();
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
YAHOO.lang.extend(KJUR.asn1.x509.BasicConstraints, KJUR.asn1.x509.Extension);

/**
 * CRLDistributionPoints ASN.1 structure class
 * @name KJUR.asn1.x509.CRLDistributionPoints
 * @class CRLDistributionPoints ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'uri': 'http://a.com/', 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @description
 * <pre>
 * id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }
 *
 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 *
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
 *
 * DistributionPointName ::= CHOICE {
 *      fullName                [0]     GeneralNames,
 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 * 
 * ReasonFlags ::= BIT STRING {
 *      unused                  (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6),
 *      privilegeWithdrawn      (7),
 *      aACompromise            (8) }
 * </pre>
 * @example
 */
KJUR.asn1.x509.CRLDistributionPoints = function(params) {
    KJUR.asn1.x509.CRLDistributionPoints.superclass.constructor.call(this, params);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509;

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.setByDPArray = function(dpArray) {
        this.asn1ExtnValue = new _KJUR_asn1.DERSequence({'array': dpArray});
    };

    this.setByOneURI = function(uri) {
        var gn1 = new _KJUR_asn1_x509.GeneralNames([{'uri': uri}]);
        var dpn1 = new _KJUR_asn1_x509.DistributionPointName(gn1);
        var dp1 = new _KJUR_asn1_x509.DistributionPoint({'dpobj': dpn1});
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
YAHOO.lang.extend(KJUR.asn1.x509.CRLDistributionPoints, KJUR.asn1.x509.Extension);

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
 *     {name: 'clientAuth'}
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
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.oid = "2.5.29.37";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setPurposeArray(params.array);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.ExtKeyUsage, KJUR.asn1.x509.Extension);

/**
 * AuthorityKeyIdentifier ASN.1 structure class
 * @name KJUR.asn1.x509.AuthorityKeyIdentifier
 * @class AuthorityKeyIdentifier ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'uri': 'http://a.com/', 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @since asn1x509 1.0.8
 * @description
 * <pre>
 * d-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 * KeyIdentifier ::= OCTET STRING
 * </pre>
 * @example
 * e1 = new KJUR.asn1.x509.AuthorityKeyIdentifier({
 *   critical: true,
 *   kid:    {hex: '89ab'},
 *   issuer: {str: '/C=US/CN=a'},
 *   sn:     {hex: '1234'}
 * });
 */
KJUR.asn1.x509.AuthorityKeyIdentifier = function(params) {
    KJUR.asn1.x509.AuthorityKeyIdentifier.superclass.constructor.call(this, params);
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject;

    this.asn1KID = null;
    this.asn1CertIssuer = null;
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
                                         'obj': this.asn1CertIssuer}));
        if (this.asn1CertSN)
            a.push(new _DERTaggedObject({'explicit': false,
                                         'tag': '82',
                                         'obj': this.asn1CertSN}));

        var asn1Seq = new _KJUR_asn1.DERSequence({'array': a});
        this.asn1ExtnValue = asn1Seq;
        return this.asn1ExtnValue.getEncodedHex();
    };

    /**
     * set keyIdentifier value by DERInteger parameter
     * @name setKIDByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier#
     * @function
     * @param {Array} param array of {@link KJUR.asn1.DERInteger} parameter
     * @since asn1x509 1.0.8
     * @description
     * NOTE: Automatic keyIdentifier value calculation by an issuer
     * public key will be supported in future version.
     */
    this.setKIDByParam = function(param) {
        this.asn1KID = new KJUR.asn1.DEROctetString(param);
    };

    /**
     * set authorityCertIssuer value by X500Name parameter
     * @name setCertIssuerByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier#
     * @function
     * @param {Array} param array of {@link KJUR.asn1.x509.X500Name} parameter
     * @since asn1x509 1.0.8
     * @description
     * NOTE: Automatic authorityCertIssuer name setting by an issuer
     * certificate will be supported in future version.
     */
    this.setCertIssuerByParam = function(param) {
        this.asn1CertIssuer = new KJUR.asn1.x509.X500Name(param);
    };

    /**
     * set authorityCertSerialNumber value by DERInteger parameter
     * @name setCertSerialNumberByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier#
     * @function
     * @param {Array} param array of {@link KJUR.asn1.DERInteger} parameter
     * @since asn1x509 1.0.8
     * @description
     * NOTE: Automatic authorityCertSerialNumber setting by an issuer
     * certificate will be supported in future version.
     */
    this.setCertSNByParam = function(param) {
        this.asn1CertSN = new KJUR.asn1.DERInteger(param);
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
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AuthorityKeyIdentifier, KJUR.asn1.x509.Extension);

/**
 * AuthorityInfoAccess ASN.1 structure class
 * @name KJUR.asn1.x509.AuthorityInfoAccess
 * @class AuthorityInfoAccess ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.x509.Extension
 * @since asn1x509 1.0.8
 * @description
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
 * @example
 * e1 = new KJUR.asn1.x509.AuthorityInfoAccess({
 *   array: [{
 *     accessMethod:{'oid': '1.3.6.1.5.5.7.48.1'},
 *     accessLocation:{'uri': 'http://ocsp.cacert.org'}
 *   }]
 * });
 */
KJUR.asn1.x509.AuthorityInfoAccess = function(params) {
    KJUR.asn1.x509.AuthorityInfoAccess.superclass.constructor.call(this, params);

    this.setAccessDescriptionArray = function(accessDescriptionArray) {
        var array = new Array(),
	    _KJUR = KJUR,
	    _KJUR_asn1 = _KJUR.asn1,
	    _DERSequence = _KJUR_asn1.DERSequence;

        for (var i = 0; i < accessDescriptionArray.length; i++) {
            var o = new _KJUR_asn1.DERObjectIdentifier(accessDescriptionArray[i].accessMethod);
            var gn = new _KJUR_asn1.x509.GeneralName(accessDescriptionArray[i].accessLocation);
            var accessDescription = new _DERSequence({'array':[o, gn]});
            array.push(accessDescription);
        }
        this.asn1ExtnValue = new _DERSequence({'array':array});
    };

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.oid = "1.3.6.1.5.5.7.1.1";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setAccessDescriptionArray(params.array);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AuthorityInfoAccess, KJUR.asn1.x509.Extension);

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
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.oid = "2.5.29.17";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setNameArray(params.array);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.SubjectAltName, KJUR.asn1.x509.Extension);

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
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.oid = "2.5.29.18";
    if (params !== undefined) {
        if (params.array !== undefined) {
            this.setNameArray(params.array);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.IssuerAltName, KJUR.asn1.x509.Extension);

// === END   X.509v3 Extensions Related =======================================

// === BEGIN CRL Related ===================================================
/**
 * X.509 CRL class to sign and generate hex encoded CRL
 * @name KJUR.asn1.x509.CRL
 * @class X.509 CRL class to sign and generate hex encoded certificate
 * @param {Array} params associative array of parameters (ex. {'tbsobj': obj, 'rsaprvkey': key})
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>tbsobj - specify {@link KJUR.asn1.x509.TBSCertList} object to be signed</li>
 * <li>rsaprvkey - specify {@link RSAKey} object CA private key</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 * <h4>EXAMPLE</h4>
 * @example
 * var prvKey = new RSAKey(); // CA's private key
 * prvKey.readPrivateKeyFromASN1HexString("3080...");
 * var crl = new KJUR.asn1x509.CRL({'tbsobj': tbs, 'prvkeyobj': prvKey});
 * crl.sign(); // issue CRL by CA's private key
 * var hCRL = crl.getEncodedHex();
 *
 * // CertificateList  ::=  SEQUENCE  {
 * //     tbsCertList          TBSCertList,
 * //     signatureAlgorithm   AlgorithmIdentifier,
 * //     signatureValue       BIT STRING  }
 */
KJUR.asn1.x509.CRL = function(params) {
    KJUR.asn1.x509.CRL.superclass.constructor.call(this);

    var asn1TBSCertList = null,
	asn1SignatureAlg = null,
	asn1Sig = null,
	hexSig = null,
	prvKey = null;

    /**
     * sign TBSCertList and set signature value internally
     * @name sign
     * @memberOf KJUR.asn1.x509.CRL#
     * @function
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.CRL({'tbsobj': tbs, 'prvkeyobj': prvKey});
     * cert.sign();
     */
    this.sign = function() {
        this.asn1SignatureAlg = this.asn1TBSCertList.asn1SignatureAlg;

        sig = new KJUR.crypto.Signature({'alg': 'SHA1withRSA', 'prov': 'cryptojs/jsrsa'});
        sig.init(this.prvKey);
        sig.updateHex(this.asn1TBSCertList.getEncodedHex());
        this.hexSig = sig.sign();

        this.asn1Sig = new KJUR.asn1.DERBitString({'hex': '00' + this.hexSig});

        var seq = new KJUR.asn1.DERSequence({'array': [this.asn1TBSCertList,
                                                       this.asn1SignatureAlg,
                                                       this.asn1Sig]});
        this.hTLV = seq.getEncodedHex();
        this.isModified = false;
    };

    this.getEncodedHex = function() {
        if (this.isModified == false && this.hTLV != null) return this.hTLV;
        throw "not signed yet";
    };

    /**
     * get PEM formatted CRL string after signed
     * @name getPEMString
     * @memberOf KJUR.asn1.x509.CRL#
     * @function
     * @return PEM formatted string of certificate
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.CRL({'tbsobj': tbs, 'rsaprvkey': prvKey});
     * cert.sign();
     * var sPEM =  cert.getPEMString();
     */
    this.getPEMString = function() {
        var pemBody = hextob64nl(this.getEncodedHex());
        return "-----BEGIN X509 CRL-----\r\n" + 
	    pemBody + 
	    "\r\n-----END X509 CRL-----\r\n";
    };

    if (params !== undefined) {
        if (params.tbsobj !== undefined) {
            this.asn1TBSCertList = params.tbsobj;
        }
        if (params.prvkeyobj !== undefined) {
            this.prvKey = params.prvkeyobj;
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.CRL, KJUR.asn1.ASN1Object);

/**
 * ASN.1 TBSCertList structure class for CRL
 * @name KJUR.asn1.x509.TBSCertList
 * @class ASN.1 TBSCertList structure class for CRL
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 * @description
 * <br/>
 * <h4>EXAMPLE</h4>
 * @example
 *  var o = new KJUR.asn1.x509.TBSCertList();
 *  o.setSignatureAlgByParam({'name': 'SHA1withRSA'});
 *  o.setIssuerByParam({'str': '/C=US/O=a'});
 *  o.setNotThisUpdateByParam({'str': '130504235959Z'});
 *  o.setNotNextUpdateByParam({'str': '140504235959Z'});
 *  o.addRevokedCert({'int': 4}, {'str':'130514235959Z'}));
 *  o.addRevokedCert({'hex': '0f34dd'}, {'str':'130514235959Z'}));
 *
 * // TBSCertList  ::=  SEQUENCE  {
 * //        version                 Version OPTIONAL,
 * //                                     -- if present, MUST be v2
 * //        signature               AlgorithmIdentifier,
 * //        issuer                  Name,
 * //        thisUpdate              Time,
 * //        nextUpdate              Time OPTIONAL,
 * //        revokedCertificates     SEQUENCE OF SEQUENCE  {
 * //             userCertificate         CertificateSerialNumber,
 * //             revocationDate          Time,
 * //             crlEntryExtensions      Extensions OPTIONAL
 * //                                      -- if present, version MUST be v2
 * //                                  }  OPTIONAL,
 * //        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 */
KJUR.asn1.x509.TBSCertList = function(params) {
    KJUR.asn1.x509.TBSCertList.superclass.constructor.call(this);
    var aRevokedCert = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_Time = _KJUR_asn1_x509.Time;

    /**
     * set signature algorithm field by parameter
     * @name setSignatureAlgByParam
     * @memberOf KJUR.asn1.x509.TBSCertList#
     * @function
     * @param {Array} algIdParam AlgorithmIdentifier parameter
     * @description
     * @example
     * tbsc.setSignatureAlgByParam({'name': 'SHA1withRSA'});
     */
    this.setSignatureAlgByParam = function(algIdParam) {
        this.asn1SignatureAlg = 
	    new _KJUR_asn1_x509.AlgorithmIdentifier(algIdParam);
    };

    /**
     * set issuer name field by parameter
     * @name setIssuerByParam
     * @memberOf KJUR.asn1.x509.TBSCertList#
     * @function
     * @param {Array} x500NameParam X500Name parameter
     * @description
     * @example
     * tbsc.setIssuerParam({'str': '/C=US/CN=b'});
     * @see KJUR.asn1.x509.X500Name
     */
    this.setIssuerByParam = function(x500NameParam) {
        this.asn1Issuer = new _KJUR_asn1_x509.X500Name(x500NameParam);
    };

    /**
     * set thisUpdate field by parameter
     * @name setThisUpdateByParam
     * @memberOf KJUR.asn1.x509.TBSCertList#
     * @function
     * @param {Array} timeParam Time parameter
     * @description
     * @example
     * tbsc.setThisUpdateByParam({'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.setThisUpdateByParam = function(timeParam) {
        this.asn1ThisUpdate = new _Time(timeParam);
    };

    /**
     * set nextUpdate field by parameter
     * @name setNextUpdateByParam
     * @memberOf KJUR.asn1.x509.TBSCertList#
     * @function
     * @param {Array} timeParam Time parameter
     * @description
     * @example
     * tbsc.setNextUpdateByParam({'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.setNextUpdateByParam = function(timeParam) {
        this.asn1NextUpdate = new _Time(timeParam);
    };

    /**
     * add revoked certificate by parameter
     * @name addRevokedCert
     * @memberOf KJUR.asn1.x509.TBSCertList#
     * @function
     * @param {Array} snParam DERInteger parameter for certificate serial number
     * @param {Array} timeParam Time parameter for revocation date
     * @description
     * @example
     * tbsc.addRevokedCert({'int': 3}, {'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.addRevokedCert = function(snParam, timeParam) {
        var param = {};
        if (snParam != undefined && snParam != null)
	    param['sn'] = snParam;
        if (timeParam != undefined && timeParam != null)
	    param['time'] = timeParam;
        var o = new _KJUR_asn1_x509.CRLEntry(param);
        this.aRevokedCert.push(o);
    };

    this.getEncodedHex = function() {
        this.asn1Array = new Array();

        if (this.asn1Version != null) this.asn1Array.push(this.asn1Version);
        this.asn1Array.push(this.asn1SignatureAlg);
        this.asn1Array.push(this.asn1Issuer);
        this.asn1Array.push(this.asn1ThisUpdate);
        if (this.asn1NextUpdate != null) this.asn1Array.push(this.asn1NextUpdate);

        if (this.aRevokedCert.length > 0) {
            var seq = new _DERSequence({'array': this.aRevokedCert});
            this.asn1Array.push(seq);
        }

        var o = new _DERSequence({"array": this.asn1Array});
        this.hTLV = o.getEncodedHex();
        this.isModified = false;
        return this.hTLV;
    };

    this._initialize = function() {
        this.asn1Version = null;
        this.asn1SignatureAlg = null;
        this.asn1Issuer = null;
        this.asn1ThisUpdate = null;
        this.asn1NextUpdate = null;
        this.aRevokedCert = new Array();
    };

    this._initialize();
};
YAHOO.lang.extend(KJUR.asn1.x509.TBSCertList, KJUR.asn1.ASN1Object);

/**
 * ASN.1 CRLEntry structure class for CRL
 * @name KJUR.asn1.x509.CRLEntry
 * @class ASN.1 CRLEntry structure class for CRL
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 * @description
 * @example
 * var e = new KJUR.asn1.x509.CRLEntry({'time': {'str': '130514235959Z'}, 'sn': {'int': 234}});
 *
 * // revokedCertificates     SEQUENCE OF SEQUENCE  {
 * //     userCertificate         CertificateSerialNumber,
 * //     revocationDate          Time,
 * //     crlEntryExtensions      Extensions OPTIONAL
 * //                             -- if present, version MUST be v2 }
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

    this.getEncodedHex = function() {
        var o = new _KJUR_asn1.DERSequence({"array": [this.sn, this.time]});
        this.TLV = o.getEncodedHex();
        return this.TLV;
    };

    if (params !== undefined) {
        if (params.time !== undefined) {
            this.setRevocationDate(params.time);
        }
        if (params.sn !== undefined) {
            this.setCertSerial(params.sn);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.CRLEntry, KJUR.asn1.ASN1Object);

// === END   CRL Related ===================================================

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
 * @description
 * This class provides DistinguishedName ASN.1 class structure
 * defined in <a href="https://tools.ietf.org/html/rfc2253#section-2">RFC 2253 section 2</a>.
 * <blockquote><pre>
 * DistinguishedName ::= RDNSequence
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF
 *   AttributeTypeAndValue
 *
 * AttributeTypeAndValue ::= SEQUENCE {
 *   type  AttributeType,
 *   value AttributeValue }
 * </pre></blockquote>
 * <br/>
 * For string representation of distinguished name in jsrsasign,
 * OpenSSL oneline format is used. Please see <a href="https://github.com/kjur/jsrsasign/wiki/NOTE-distinguished-name-representation-in-jsrsasign">wiki article</a> for it.
 * <br/>
 * NOTE: Multi-valued RDN is supported since jsrsasign 6.2.1 asn1x509 1.0.17.
 * @example
 * // 1. construct with string
 * o = new KJUR.asn1.x509.X500Name({str: "/C=US/O=aaa/OU=bbb/CN=foo@example.com"});
 * o = new KJUR.asn1.x509.X500Name({str: "/C=US/O=aaa+CN=contact@example.com"}); // multi valued
 * // 2. construct by object
 * o = new KJUR.asn1.x509.X500Name({C: "US", O: "aaa", CN: "http://example.com/"});
 */
KJUR.asn1.x509.X500Name = function(params) {
    KJUR.asn1.x509.X500Name.superclass.constructor.call(this);
    this.asn1Array = new Array();
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
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
    this.setByString = function(dnStr) {
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
            this.asn1Array.push(new _KJUR_asn1_x509.RDN({'str':a1[i]}));
        }
    };

    /**
     * set DN by LDAP(RFC 2253) distinguished name string<br/>
     * @name setByLdapString
     * @memberOf KJUR.asn1.x509.X500Name#
     * @function
     * @param {String} dnStr distinguished name by LDAP string (ex. O=aaa,C=US)
     * @since jsrsasign 6.2.2 asn1x509 1.0.18
     * @description
     * @example
     * name = new KJUR.asn1.x509.X500Name();
     * name.setByLdapString("CN=foo@example.com,OU=bbb,O=aaa,C=US");
     */
    this.setByLdapString = function(dnStr) {
	var oneline = _KJUR_asn1_x509.X500Name.ldapToOneline(dnStr);
	this.setByString(oneline);
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
    this.setByObject = function(dnObj) {
        // Get all the dnObject attributes and stuff them in the ASN.1 array.
        for (var x in dnObj) {
            if (dnObj.hasOwnProperty(x)) {
                var newRDN = new KJUR.asn1.x509.RDN(
                    {'str': x + '=' + dnObj[x]});
                // Initialize or push into the ANS1 array.
                this.asn1Array ? this.asn1Array.push(newRDN)
                    : this.asn1Array = [newRDN];
            }
        }
    };

    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") return this.hTLV;
        var o = new _KJUR_asn1.DERSequence({"array": this.asn1Array});
        this.hTLV = o.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (params.str !== undefined) {
            this.setByString(params.str);
        } else if (params.ldapstr !== undefined) {
	    this.setByLdapString(params.ldapstr);
        // If params is an object, then set the ASN1 array just using the object
        // attributes. This is nice for fields that have lots of special
        // characters (i.e. CN: 'https://www.github.com/kjur//').
        } else if (typeof params === "object") {
            this.setByObject(params);
        }

        if (params.certissuer !== undefined) {
            var x = new X509();
            x.hex = _pemtohex(params.certissuer);
            this.hTLV = x.getIssuerHex();
        }
        if (params.certsubject !== undefined) {
            var x = new X509();
            x.hex = _pemtohex(params.certsubject);
            this.hTLV = x.getSubjectHex();
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.X500Name, KJUR.asn1.ASN1Object);

/**
 * convert OpenSSL oneline distinguished name format string to LDAP(RFC 2253) format<br/>
 * @name onelineToLDAP
 * @memberOf KJUR.asn1.x509.X500Name
 * @function
 * @param {String} s distinguished name string in OpenSSL oneline format (ex. /C=US/O=test)
 * @return {String} distinguished name string in LDAP(RFC 2253) format (ex. O=test,C=US)
 * @since jsrsasign 6.2.2 asn1x509 1.0.18
 * @description
 * This static method converts a distinguished name string in OpenSSL oneline 
 * format to LDAP(RFC 2253) format.
 * @see <a href="https://github.com/kjur/jsrsasign/wiki/NOTE-distinguished-name-representation-in-jsrsasign">jsrsasign wiki: distinguished name string difference between OpenSSL oneline and LDAP(RFC 2253)</a>
 * @example
 * KJUR.asn1.x509.X500Name.onelineToLDAP("/C=US/O=test") &rarr; 'O=test,C=US'
 * KJUR.asn1.x509.X500Name.onelineToLDAP("/C=US/O=a,a") &rarr; 'O=a\,a,C=US'
 */
KJUR.asn1.x509.X500Name.onelineToLDAP = function(s) {
    if (s.substr(0, 1) !== "/") throw "malformed input";

    var result = "";
    s = s.substr(1);

    var a = s.split("/");
    a.reverse();
    a = a.map(function(s) {return s.replace(/,/, "\\,")});

    return a.join(",");
};

/**
 * convert LDAP(RFC 2253) distinguished name format string to OpenSSL oneline format<br/>
 * @name ldapToOneline
 * @memberOf KJUR.asn1.x509.X500Name
 * @function
 * @param {String} s distinguished name string in LDAP(RFC 2253) format (ex. O=test,C=US)
 * @return {String} distinguished name string in OpenSSL oneline format (ex. /C=US/O=test)
 * @since jsrsasign 6.2.2 asn1x509 1.0.18
 * @description
 * This static method converts a distinguished name string in 
 * LDAP(RFC 2253) format to OpenSSL oneline format.
 * @see <a href="https://github.com/kjur/jsrsasign/wiki/NOTE-distinguished-name-representation-in-jsrsasign">jsrsasign wiki: distinguished name string difference between OpenSSL oneline and LDAP(RFC 2253)</a>
 * @example
 * KJUR.asn1.x509.X500Name.ldapToOneline('O=test,C=US') &rarr; '/C=US/O=test'
 * KJUR.asn1.x509.X500Name.ldapToOneline('O=a\,a,C=US') &rarr; '/C=US/O=a,a'
 * KJUR.asn1.x509.X500Name.ldapToOneline('O=a/a,C=US')  &rarr; '/C=US/O=a\/a'
 */
KJUR.asn1.x509.X500Name.ldapToOneline = function(s) {
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
 * NOTE: Multi-valued RDN is supported since jsrsasign 6.2.1 asn1x509 1.0.17.
 * @example
 * rdn = new KJUR.asn1.x509.RDN({str: "CN=test"});
 * rdn = new KJUR.asn1.x509.RDN({str: "O=a+O=bb+O=c"}); // multi-valued
 * rdn = new KJUR.asn1.x509.RDN({str: "O=a+O=b\\+b+O=c"}); // plus escaped
 * rdn = new KJUR.asn1.x509.RDN({str: "O=a+O=\"b+b\"+O=c"}); // double quoted
 */
KJUR.asn1.x509.RDN = function(params) {
    KJUR.asn1.x509.RDN.superclass.constructor.call(this);
    this.asn1Array = new Array();

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
        this.asn1Array.push(new KJUR.asn1.x509.AttributeTypeAndValue({'str': s}));
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

    this.getEncodedHex = function() {
        var o = new KJUR.asn1.DERSet({"array": this.asn1Array});
        this.TLV = o.getEncodedHex();
        return this.TLV;
    };

    if (params !== undefined) {
        if (params.str !== undefined) {
            this.addByMultiValuedString(params.str);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.RDN, KJUR.asn1.ASN1Object);

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
 * @param {Array} params associative array of parameters (ex. {'str': 'C=US'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.x509.X500Name
 * @see KJUR.asn1.x509.RDN
 * @see KJUR.asn1.x509.AttributeTypeAndValue
 * @example
 */
KJUR.asn1.x509.AttributeTypeAndValue = function(params) {
    KJUR.asn1.x509.AttributeTypeAndValue.superclass.constructor.call(this);
    var typeObj = null,
	valueObj = null,
	defaultDSType = "utf8",
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1;

    this.setByString = function(attrTypeAndValueStr) {
        var matchResult = attrTypeAndValueStr.match(/^([^=]+)=(.+)$/);
        if (matchResult) {
            this.setByAttrTypeAndValueStr(matchResult[1], matchResult[2]);
        } else {
            throw "malformed attrTypeAndValueStr: " + attrTypeAndValueStr;
        }
    };

    this.setByAttrTypeAndValueStr = function(shortAttrType, valueStr) {
        this.typeObj = KJUR.asn1.x509.OID.atype2obj(shortAttrType);
        var dsType = defaultDSType;
        if (shortAttrType == "C") dsType = "prn";
        this.valueObj = this.getValueObj(dsType, valueStr);
    };

    this.getValueObj = function(dsType, valueStr) {
        if (dsType == "utf8")   return new _KJUR_asn1.DERUTF8String({"str": valueStr});
        if (dsType == "prn")    return new _KJUR_asn1.DERPrintableString({"str": valueStr});
        if (dsType == "tel")    return new _KJUR_asn1.DERTeletexString({"str": valueStr});
        if (dsType == "ia5")    return new _KJUR_asn1.DERIA5String({"str": valueStr});
        throw "unsupported directory string type: type=" + dsType + " value=" + valueStr;
    };

    this.getEncodedHex = function() {
        var o = new _KJUR_asn1.DERSequence({"array": [this.typeObj, this.valueObj]});
        this.TLV = o.getEncodedHex();
        return this.TLV;
    };

    if (params !== undefined) {
        if (params.str !== undefined) {
            this.setByString(params.str);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AttributeTypeAndValue, KJUR.asn1.ASN1Object);

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

    this.getEncodedHex = function() {
        var o = this.getASN1Object();
        this.hTLV = o.getEncodedHex();
        return this.hTLV;
    };

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
		var rsaKeyHex = asn1RsaPub.getEncodedHex();
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
		    new _DERBitString({'hex': '00' + pubInt.getEncodedHex()});
	    }
	} catch(ex) {};
    };

    if (params !== undefined) {
	this.setPubKey(params);
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.SubjectPublicKeyInfo, KJUR.asn1.ASN1Object);

/**
 * Time ASN.1 structure class
 * @name KJUR.asn1.x509.Time
 * @class Time ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'str': '130508235959Z'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * <h4>EXAMPLES</h4>
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

    this.setTimeParams = function(timeParams) {
        this.timeParams = timeParams;
    }

    this.getEncodedHex = function() {
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
        this.TLV = o.getEncodedHex();
        return this.TLV;
    };

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
YAHOO.lang.extend(KJUR.asn1.x509.Time, KJUR.asn1.ASN1Object);

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
 * @example
 * algId = new KJUR.asn1.x509.AlgorithmIdentifier({name: "sha1"});
 * // set parameter to NULL authomatically if algorithm name is "*withRSA".
 * algId = new KJUR.asn1.x509.AlgorithmIdentifier({name: "SHA256withRSA"});
 * // set parameter to NULL authomatically if algorithm name is "rsaEncryption".
 * algId = new KJUR.asn1.x509.AlgorithmIdentifier({name: "rsaEncryption"});
 * // SHA256withRSA and set parameter empty by force
 * algId = new KJUR.asn1.x509.AlgorithmIdentifier({name: "SHA256withRSA", paramempty: true});
 */
KJUR.asn1.x509.AlgorithmIdentifier = function(params) {
    KJUR.asn1.x509.AlgorithmIdentifier.superclass.constructor.call(this);
    this.nameAlg = null;
    this.asn1Alg = null;
    this.asn1Params = null;
    this.paramEmpty = false;
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1;

    this.getEncodedHex = function() {
        if (this.nameAlg === null && this.asn1Alg === null) {
            throw "algorithm not specified";
        }
        if (this.nameAlg !== null && this.asn1Alg === null) {
            this.asn1Alg = _KJUR_asn1.x509.OID.name2obj(this.nameAlg);
        }
        var a = [this.asn1Alg];
        if (this.asn1Params !== null) a.push(this.asn1Params);

        var o = new _KJUR_asn1.DERSequence({'array': a});
        this.hTLV = o.getEncodedHex();
        return this.hTLV;
    };

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
	var lcNameAlg = this.nameAlg.toLowerCase();
	if (lcNameAlg.substr(-7, 7) !== "withdsa" &&
	    lcNameAlg.substr(-9, 9) !== "withecdsa") {
            this.asn1Params = new _KJUR_asn1.DERNull();
	}
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AlgorithmIdentifier, KJUR.asn1.ASN1Object);

/**
 * GeneralName ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.GeneralName
 * @class GeneralName ASN.1 structure class
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>rfc822 - rfc822Name[1] (ex. user1@foo.com)</li>
 * <li>dns - dNSName[2] (ex. foo.com)</li>
 * <li>uri - uniformResourceIdentifier[6] (ex. http://foo.com/)</li>
 * <li>dn - directoryName[4] (ex. /C=US/O=Test)</li>
 * <li>ldapdn - directoryName[4] (ex. O=Test,C=US)</li>
 * <li>certissuer - directoryName[4] (PEM or hex string of cert)</li>
 * <li>certsubj - directoryName[4] (PEM or hex string of cert)</li>
 * <li>ip - iPAddress[7] (ex. 192.168.1.1, 2001:db3::43, 3faa0101...)</li>
 * </ul>
 * NOTE1: certissuer and certsubj were supported since asn1x509 1.0.10.<br/>
 * NOTE2: dn and ldapdn were supported since jsrsasign 6.2.3 asn1x509 1.0.19.<br/>
 * NOTE3: ip were supported since jsrsasign 8.0.10 asn1x509 1.1.4.<br/>
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
 * </pre>
 *
 * @example
 * gn = new KJUR.asn1.x509.GeneralName({rfc822:     'test@aaa.com'});
 * gn = new KJUR.asn1.x509.GeneralName({dns:        'aaa.com'});
 * gn = new KJUR.asn1.x509.GeneralName({uri:        'http://aaa.com/'});
 * gn = new KJUR.asn1.x509.GeneralName({dn:         '/C=US/O=Test'});
 * gn = new KJUR.asn1.x509.GeneralName({ldapdn:     'O=Test,C=US'});
 * gn = new KJUR.asn1.x509.GeneralName({certissuer: certPEM});
 * gn = new KJUR.asn1.x509.GeneralName({certsubj:   certPEM});
 * gn = new KJUR.asn1.x509.GeneralName({ip:         '192.168.1.1'});
 * gn = new KJUR.asn1.x509.GeneralName({ip:         '2001:db4::4:1'});
 * gn = new KJUR.asn1.x509.GeneralName({ip:         'c0a80101'});
 */
KJUR.asn1.x509.GeneralName = function(params) {
    KJUR.asn1.x509.GeneralName.superclass.constructor.call(this);
    var asn1Obj = null,
	type = null,
	pTag = {rfc822: '81', dns: '82', dn: 'a4',  uri: '86', ip: '87'},
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_DERIA5String = _KJUR_asn1.DERIA5String,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_X500Name = _KJUR_asn1.x509.X500Name,
	_pemtohex = pemtohex;
	
    this.explicit = false;

    this.setByParam = function(params) {
        var str = null;
        var v = null;

	if (params === undefined) return;

        if (params.rfc822 !== undefined) {
            this.type = 'rfc822';
            v = new _DERIA5String({str: params[this.type]});
        }

        if (params.dns !== undefined) {
            this.type = 'dns';
            v = new _DERIA5String({str: params[this.type]});
        }

        if (params.uri !== undefined) {
            this.type = 'uri';
            v = new _DERIA5String({str: params[this.type]});
        }

        if (params.dn !== undefined) {
	    this.type = 'dn';
	    this.explicit = true;
	    v = new _X500Name({str: params.dn});
	}

        if (params.ldapdn !== undefined) {
	    this.type = 'dn';
	    this.explicit = true;
	    v = new _X500Name({ldapstr: params.ldapdn});
	}

	if (params.certissuer !== undefined) {
	    this.type = 'dn';
	    this.explicit = true;
	    var certStr = params.certissuer;
	    var certHex = null;

	    if (certStr.match(/^[0-9A-Fa-f]+$/)) {
		certHex == certStr;
            }

	    if (certStr.indexOf("-----BEGIN ") != -1) {
		certHex = _pemtohex(certStr);
	    }

	    if (certHex == null) throw "certissuer param not cert";
	    var x = new X509();
	    x.hex = certHex;
	    var dnHex = x.getIssuerHex();
	    v = new _ASN1Object();
	    v.hTLV = dnHex;
	}

	if (params.certsubj !== undefined) {
	    this.type = 'dn';
	    this.explicit = true;
	    var certStr = params.certsubj;
	    var certHex = null;
	    if (certStr.match(/^[0-9A-Fa-f]+$/)) {
		certHex == certStr;
            }
	    if (certStr.indexOf("-----BEGIN ") != -1) {
		certHex = _pemtohex(certStr);
	    }
	    if (certHex == null) throw "certsubj param not cert";
	    var x = new X509();
	    x.hex = certHex;
	    var dnHex = x.getSubjectHex();
	    v = new _ASN1Object();
	    v.hTLV = dnHex;
	}

	if (params.ip !== undefined) {
	    this.type = 'ip';
	    this.explicit = false;
	    var ip = params.ip;
	    var hIP;
	    var malformedIPMsg = "malformed IP address";
	    if (ip.match(/^[0-9.]+[.][0-9.]+$/)) { // ipv4
		hIP = intarystrtohex("[" + ip.split(".").join(",") + "]");
		if (hIP.length !== 8) throw malformedIPMsg;
	    } else if (ip.match(/^[0-9A-Fa-f:]+:[0-9A-Fa-f:]+$/)) { // ipv6
		hIP = ipv6tohex(ip);
	    } else if (ip.match(/^([0-9A-Fa-f][0-9A-Fa-f]){1,}$/)) { // hex
		hIP = ip;
	    } else {
		throw malformedIPMsg;
	    }
	    v = new _DEROctetString({hex: hIP});
	}

        if (this.type == null)
            throw "unsupported type in params=" + params;
        this.asn1Obj = new _DERTaggedObject({'explicit': this.explicit,
                                             'tag': pTag[this.type],
                                             'obj': v});
    };

    this.getEncodedHex = function() {
        return this.asn1Obj.getEncodedHex();
    }

    if (params !== undefined) {
        this.setByParam(params);
    }

};
YAHOO.lang.extend(KJUR.asn1.x509.GeneralName, KJUR.asn1.ASN1Object);

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

    this.getEncodedHex = function() {
        var o = new _KJUR_asn1.DERSequence({'array': this.asn1Array});
        return o.getEncodedHex();
    };

    this.asn1Array = new Array();
    if (typeof paramsArray != "undefined") {
        this.setByParamArray(paramsArray);
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.GeneralNames, KJUR.asn1.ASN1Object);

/**
 * DistributionPointName ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.DistributionPointName
 * @class DistributionPointName ASN.1 structure class
 * @description
 * <pre>
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
 *
 * DistributionPointName ::= CHOICE {
 *      fullName                [0]     GeneralNames,
 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 * 
 * ReasonFlags ::= BIT STRING {
 *      unused                  (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6),
 *      privilegeWithdrawn      (7),
 *      aACompromise            (8) }
 * </pre>
 * @example
 */
KJUR.asn1.x509.DistributionPointName = function(gnOrRdn) {
    KJUR.asn1.x509.DistributionPointName.superclass.constructor.call(this);
    var asn1Obj = null,
	type = null,
	tag = null,
	asn1V = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject;

    this.getEncodedHex = function() {
        if (this.type != "full")
            throw "currently type shall be 'full': " + this.type;
        this.asn1Obj = new _DERTaggedObject({'explicit': false,
                                             'tag': this.tag,
                                             'obj': this.asn1V});
        this.hTLV = this.asn1Obj.getEncodedHex();
        return this.hTLV;
    };

    if (gnOrRdn !== undefined) {
        if (_KJUR_asn1.x509.GeneralNames.prototype.isPrototypeOf(gnOrRdn)) {
            this.type = "full";
            this.tag = "a0";
            this.asn1V = gnOrRdn;
        } else {
            throw "This class supports GeneralNames only as argument";
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.DistributionPointName, KJUR.asn1.ASN1Object);

/**
 * DistributionPoint ASN.1 structure class<br/>
 * @name KJUR.asn1.x509.DistributionPoint
 * @class DistributionPoint ASN.1 structure class
 * @description
 * <pre>
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
 *
 * DistributionPointName ::= CHOICE {
 *      fullName                [0]     GeneralNames,
 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 * 
 * ReasonFlags ::= BIT STRING {
 *      unused                  (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6),
 *      privilegeWithdrawn      (7),
 *      aACompromise            (8) }
 * </pre>
 * @example
 */
KJUR.asn1.x509.DistributionPoint = function(params) {
    KJUR.asn1.x509.DistributionPoint.superclass.constructor.call(this);
    var asn1DP = null,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1;

    this.getEncodedHex = function() {
        var seq = new _KJUR_asn1.DERSequence();
        if (this.asn1DP != null) {
            var o1 = new _KJUR_asn1.DERTaggedObject({'explicit': true,
                                                     'tag': 'a0',
                                                     'obj': this.asn1DP});
            seq.appendASN1Object(o1);
        }
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (params.dpobj !== undefined) {
            this.asn1DP = params.dpobj;
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.DistributionPoint, KJUR.asn1.ASN1Object);

/**
 * static object for OID
 * @name KJUR.asn1.x509.OID
 * @class static object for OID
 * @property {Assoc Array} atype2oidList for short attribute type name and oid (ex. 'C' and '2.5.4.6')
 * @property {Assoc Array} name2oidList for oid name and oid (ex. 'keyUsage' and '2.5.29.15')
 * @property {Assoc Array} objCache for caching name and DERObjectIdentifier object
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
KJUR.asn1.x509.OID = new function(params) {
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

        'subjectKeyIdentifier': '2.5.29.14',
        'keyUsage':             '2.5.29.15',
        'subjectAltName':       '2.5.29.17',
        'issuerAltName':        '2.5.29.18',
        'basicConstraints':     '2.5.29.19',
        'nameConstraints':      '2.5.29.30',
        'cRLDistributionPoints':'2.5.29.31',
        'certificatePolicies':  '2.5.29.32',
        'authorityKeyIdentifier':'2.5.29.35',
        'policyConstraints':    '2.5.29.36',
        'extKeyUsage':          '2.5.29.37',
        'authorityInfoAccess':  '1.3.6.1.5.5.7.1.1',
        'ocsp':                 '1.3.6.1.5.5.7.48.1',
        'caIssuers':            '1.3.6.1.5.5.7.48.2',

        'anyExtendedKeyUsage':  '2.5.29.37.0',
        'serverAuth':           '1.3.6.1.5.5.7.3.1',
        'clientAuth':           '1.3.6.1.5.5.7.3.2',
        'codeSigning':          '1.3.6.1.5.5.7.3.3',
        'emailProtection':      '1.3.6.1.5.5.7.3.4',
        'timeStamping':         '1.3.6.1.5.5.7.3.8',
        'ocspSigning':          '1.3.6.1.5.5.7.3.9',

        'ecPublicKey':          '1.2.840.10045.2.1',
        'secp256r1':            '1.2.840.10045.3.1.7',
        'secp256k1':            '1.3.132.0.10',
        'secp384r1':            '1.3.132.0.34',

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
        'extensionRequest':     '1.2.840.113549.1.9.14',// CSR extensionRequest
    };

    this.objCache = {};

    /**
     * get DERObjectIdentifier by registered OID name
     * @name name2obj
     * @memberOf KJUR.asn1.x509.OID
     * @function
     * @param {String} name OID
     * @description
     * @example
     * var asn1ObjOID = OID.name2obj('SHA1withRSA');
     */
    this.name2obj = function(name) {
        if (typeof this.objCache[name] != "undefined")
            return this.objCache[name];
        if (typeof this.name2oidList[name] == "undefined")
            throw "Name of ObjectIdentifier not defined: " + name;
        var oid = this.name2oidList[name];
        var obj = new KJUR.asn1.DERObjectIdentifier({'oid': oid});
        this.objCache[name] = obj;
        return obj;
    };

    /**
     * get DERObjectIdentifier by registered attribute type name such like 'C' or 'CN'<br/>
     * @name atype2obj
     * @memberOf KJUR.asn1.x509.OID
     * @function
     * @param {String} atype short attribute type name such like 'C' or 'CN'
     * @description
     * @example
     * KJUR.asn1.x509.OID.atype2obj('CN') &rarr; 2.5.4.3
     * KJUR.asn1.x509.OID.atype2obj('OU') &rarr; 2.5.4.11
     */
    this.atype2obj = function(atype) {
        if (typeof this.objCache[atype] != "undefined")
            return this.objCache[atype];
        if (typeof this.atype2oidList[atype] == "undefined")
            throw "AttributeType name undefined: " + atype;
        var oid = this.atype2oidList[atype];
        var obj = new KJUR.asn1.DERObjectIdentifier({'oid': oid});
        this.objCache[atype] = obj;
        return obj;
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
 * @param {String} OID name
 * @return {String} dot noted Object Identifer string (ex. 1.2.3.4)
 * @since asn1x509 1.0.11
 * @description
 * This static method converts from OID name to OID string.
 * If OID is undefined then it returns empty string (i.e. '').
 * @example
 * KJUR.asn1.x509.OID.name2oid("authorityInfoAccess") &rarr; 1.3.6.1.5.5.7.1.1
 */
KJUR.asn1.x509.OID.name2oid = function(name) {
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
 * issue a certificate in PEM format
 * @name newCertPEM
 * @memberOf KJUR.asn1.x509.X509Util
 * @function
 * @param {Array} param parameter to issue a certificate
 * @since asn1x509 1.0.6
 * @description
 * This method can issue a certificate by a simple
 * JSON object.
 * Signature value will be provided by signing with
 * private key using 'cakey' parameter or
 * hexa decimal signature value by 'sighex' parameter.
 * <br/>
 * NOTE: Algorithm parameter of AlgorithmIdentifier will
 * be set automatically by default. (see {@link KJUR.asn1.x509.AlgorithmIdentifier})
 * from jsrsasign 7.1.1 asn1x509 1.0.20.
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
    var o = new _TBSCertificate();

    if (param.serial !== undefined)
        o.setSerialNumberByParam(param.serial);
    else
        throw "serial number undefined.";

    if (typeof param.sigalg.name === 'string')
        o.setSignatureAlgByParam(param.sigalg);
    else
        throw "unproper signature algorithm name";

    if (param.issuer !== undefined)
        o.setIssuerByParam(param.issuer);
    else
        throw "issuer name undefined.";

    if (param.notbefore !== undefined)
        o.setNotBeforeByParam(param.notbefore);
    else
        throw "notbefore undefined.";

    if (param.notafter !== undefined)
        o.setNotAfterByParam(param.notafter);
    else
        throw "notafter undefined.";

    if (param.subject !== undefined)
        o.setSubjectByParam(param.subject);
    else
        throw "subject name undefined.";

    if (param.sbjpubkey !== undefined)
        o.setSubjectPublicKeyByGetKey(param.sbjpubkey);
    else
        throw "subject public key undefined.";

    if (param.ext !== undefined && param.ext.length !== undefined) {
        for (var i = 0; i < param.ext.length; i++) {
            for (key in param.ext[i]) {
                o.appendExtensionByName(key, param.ext[i][key]);
            }
        }
    }

    // set signature
    if (param.cakey === undefined && param.sighex === undefined)
        throw "param cakey and sighex undefined.";

    var caKey = null;
    var cert = null;

    if (param.cakey) {
	if (param.cakey.isPrivate === true) {
	    caKey = param.cakey;
	} else {
            caKey = KEYUTIL.getKey.apply(null, param.cakey);
	}
        cert = new _Certificate({'tbscertobj': o, 'prvkeyobj': caKey});
        cert.sign();
    }

    if (param.sighex) {
        cert = new _Certificate({'tbscertobj': o});
        cert.setSignatureHex(param.sighex);
    }

    return cert.getPEMString();
};

