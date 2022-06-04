/* x509-2.0.17.js (c) 2012-2022 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * x509.js - X509 class to read subject public key from certificate.
 *
 * Copyright (c) 2010-2022 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name x509-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.24 x509 2.0.17 (2022-Jun-04)
 * @since jsrsasign 1.x.x
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * hexadecimal X.509 certificate ASN.1 parser class.<br/>
 * @class hexadecimal X.509 certificate ASN.1 parser class
 * @property {String} hex hexacedimal string for X.509 certificate.
 * @property {Number} version format version (1: X509v1, 3: X509v3, otherwise: unknown) since jsrsasign 7.1.4
 * @property {Array} aExtInfo (DEPRECATED) array of parameters for extensions
 * @author Kenji Urushima
 * @version 1.0.1 (08 May 2012)
 * @see <a href="https://kjur.github.io/jsrsasigns/">'jsrsasign'(RSA Sign JavaScript Library) home page https://kjur.github.io/jsrsasign/</a>
 * @description
 * X509 class provides following functionality:
 * <ul>
 * <li>parse X.509 certificate ASN.1 structure</li>
 * <li>get basic fields, extensions, signature algorithms and signature values</li>
 * <li>read PEM certificate</li>
 * </ul>
 *
 * <ul>
 * <li><b>TO GET FIELDS</b>
 *   <ul>
 *   <li>serial - {@link X509#getSerialNumberHex}</li>
 *   <li>signature algorithm field - {@link X509#getSignatureAlgorithmField}</li>
 *   <li>issuer - {@link X509#getIssuerHex}</li>
 *   <li>issuer - {@link X509#getIssuerString}</li>
 *   <li>notBefore - {@link X509#getNotBefore}</li>
 *   <li>notAfter - {@link X509#getNotAfter}</li>
 *   <li>subject - {@link X509#getSubjectHex}</li>
 *   <li>subject - {@link X509#getSubjectString}</li>
 *   <li>subjectPublicKeyInfo - {@link X509#getPublicKey}</li>
 *   <li>subjectPublicKeyInfo - {@link X509#getPublicKeyHex}</li>
 *   <li>subjectPublicKeyInfo - {@link X509#getPublicKeyIdx}</li>
 *   <li>subjectPublicKeyInfo - {@link X509.getPublicKeyFromCertPEM}</li>
 *   <li>subjectPublicKeyInfo - {@link X509.getPublicKeyFromCertHex}</li>
 *   <li>subjectPublicKeyInfo - {@link X509#getPublicKeyContentIdx}</li>
 *   <li>signature algorithm - {@link X509#getSignatureAlgorithmName}</li>
 *   <li>signature value - {@link X509#getSignatureValueHex}</li>
 *   </ul>
 * </li>
 * <li><b>X509 METHODS TO GET EXTENSIONS</b>
 *   <ul>
 *   <li>authorityKeyIdentifier - {@link X509#getExtAuthorityKeyIdentifier}</li>
 *   <li>subjectKeyIdentifier - {@link X509#getExtSubjectKeyIdentifier}</li>
 *   <li>keyUsage - {@link X509#getExtKeyUsage}</li>
 *   <li>keyUsage - {@link X509#getExtKeyUsageBin}</li>
 *   <li>keyUsage - {@link X509#getExtKeyUsageString}</li>
 *   <li>certificatePolicies - {@link X509#getExtCertificatePolicies}</li>
 *   <li>subjectAltName - {@link X509#getExtSubjectAltName}</li>
 *   <li>subjectAltName2 - {@link X509#getExtSubjectAltName2} (DEPRECATED)</li>
 *   <li>issuerAltName - {@link X509#getExtIssuerAltName}</li>
 *   <li>basicConstraints - {@link X509#getExtBasicConstraints}</li>
 *   <li>nameConstraints - {@link X509#getExtNameConstraints}</li>
 *   <li>extKeyUsage - {@link X509#getExtExtKeyUsage}</li>
 *   <li>extKeyUsage - {@link X509#getExtExtKeyUsageName} (DEPRECATED)</li>
 *   <li>cRLDistributionPoints - {@link X509#getExtCRLDistributionPoints}</li>
 *   <li>cRLDistributionPoints - {@link X509#getExtCRLDistributionPointsURI} (DEPRECATED)</li>
 *   <li>authorityInfoAccess - {@link X509#getExtAuthorityInfoAccess}</li>
 *   <li>authorityInfoAccess - {@link X509#getExtAIAInfo} (DEPRECATED)</li>
 *   <li>cRLNumber - {@link X509#getExtCRLNumber}</li>
 *   <li>cRLReason - {@link X509#getExtCRLReason}</li>
 *   <li>ocspNonce - {@link X509#getExtOcspNonce}</li>
 *   <li>ocspNoCheck - {@link X509#getExtOcspNoCheck}</li>
 *   <li>adobeTimeStamp - {@link X509#getExtAdobeTimeStamp}</li>
 *   </ul>
 * </li>
 * <li><b>UTILITIES</b>
 *   <ul>
 *   <li>reading PEM X.509 certificate - {@link X509#readCertPEM}</li>
 *   <li>reading hexadecimal string of X.509 certificate - {@link X509#readCertHex}</li>
 *   <li>get all certificate information - {@link X509#getInfo}</li>
 *   <li>get specified extension information - {@link X509#getExtInfo}</li>
 *   <li>verify signature value - {@link X509#verifySignature}</li>
 *   </ul>
 * </li>
 * </ul>
 */
function X509(params) {
    var _ASN1HEX = ASN1HEX,
	_getChildIdx = _ASN1HEX.getChildIdx,
	_getV = _ASN1HEX.getV,
	_dump = _ASN1HEX.dump,
	_ASN1HEX_parse = _ASN1HEX.parse,
	_getTLV = _ASN1HEX.getTLV,
	_getVbyList = _ASN1HEX.getVbyList,
	_getVbyListEx = _ASN1HEX.getVbyListEx,
	_getTLVbyList = _ASN1HEX.getTLVbyList,
	_getTLVbyListEx = _ASN1HEX.getTLVbyListEx,
	_getIdxbyList = _ASN1HEX.getIdxbyList,
	_getIdxbyListEx = _ASN1HEX.getIdxbyListEx,
	_getVidx = _ASN1HEX.getVidx,
	_getInt = _ASN1HEX.getInt,
	_oidname = _ASN1HEX.oidname,
	_hextooidstr = _ASN1HEX.hextooidstr,
	_X509 = X509,
	_pemtohex = pemtohex,
	_PSSNAME2ASN1TLV;

    try {
	_PSSNAME2ASN1TLV = KJUR.asn1.x509.AlgorithmIdentifier.PSSNAME2ASN1TLV;
    } catch (ex) {};
    this.HEX2STAG = {"0c": "utf8", "13": "prn", "16": "ia5",
		     "1a": "vis" , "1e": "bmp"};

    this.hex = null;
    this.version = 0; // version (1: X509v1, 3: X509v3, others: unspecified)
    this.foffset = 0; // field index offset (-1: for X509v1, 0: for X509v3)
    this.aExtInfo = null;

    // ===== get basic fields from hex =====================================

    /**
     * get format version (X.509v1 or v3 certificate)<br/>
     * @name getVersion
     * @memberOf X509#
     * @function
     * @return {Number} 1 for X509v1, 3 for X509v3, otherwise 0
     * @since jsrsasign 7.1.14 x509 1.1.13
     * @description
     * This method returns a format version of X.509 certificate.
     * It returns 1 for X.509v1 certificate and 3 for v3 certificate.
     * Otherwise returns 0.
     * This method will be automatically called in
     * {@link X509#readCertPEM}. After then, you can use
     * {@link X509.version} parameter.
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * version = x.getVersion();    // 1 or 3
     * sn = x.getSerialNumberHex(); // return string like "01ad..."
     */
    this.getVersion = function() {
	if (this.hex === null || this.version !== 0) return this.version;

	// check if the first item of tbsCertificate "[0] { INTEGER 2 }"
	var hFirstObj = _getTLVbyList(this.hex, 0, [0, 0]);
	if (hFirstObj.substr(0, 2) == "a0") {
	    var hVersionTLV = _getTLVbyList(hFirstObj, 0, [0]);
	    var iVersion = _getInt(hVersionTLV, 0);
	    if (iVersion < 0 || 2 < iVersion) {
		throw new Error("malformed version field");
	    }
	    this.version = iVersion + 1;
	    return this.version;
	} else {
	    this.version = 1;
	    this.foffset = -1;
	    return 1;
	}
    };

    /**
     * get hexadecimal string of serialNumber field of certificate.<br/>
     * @name getSerialNumberHex
     * @memberOf X509#
     * @function
     * @return {String} hexadecimal string of certificate serial number
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var sn = x.getSerialNumberHex(); // return string like "01ad..."
     */
    this.getSerialNumberHex = function() {
	return _getVbyListEx(this.hex, 0, [0, 0], "02");
    };

    /**
     * get signature algorithm name in basic field
     * @name getSignatureAlgorithmField
     * @memberOf X509#
     * @function
     * @return {String} signature algorithm name (ex. SHA1withRSA, SHA256withECDSA, SHA512withRSAandMGF1)
     * @since x509 1.1.8
     * @see X509#getAlgorithmIdentifierName
     * @description
     * This method will get a name of signature algorithm in 
     * basic field of certificate.
     * <br/>
     * NOTE: From jsrsasign 8.0.21, RSA-PSS certificate is also supported.
     * For supported RSA-PSS algorithm name and PSS parameters,
     * see {@link X509#getSignatureAlgorithmField}.
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * algName = x.getSignatureAlgorithmField();
     */
    this.getSignatureAlgorithmField = function() {
	var hTLV = _getTLVbyListEx(this.hex, 0, [0, 1]);
	return this.getAlgorithmIdentifierName(hTLV);
    };

    /**
     * get algorithm name name of AlgorithmIdentifier ASN.1 structure
     * @name getAlgorithmIdentifierName
     * @memberOf X509#
     * @function
     * @param {String} hTLV hexadecimal string of AlgorithmIdentifier
     * @return {String} algorithm name (ex. SHA1withRSA, SHA256withECDSA, SHA512withRSAandMGF1, SHA1)
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @description
     * This method will get a name of AlgorithmIdentifier.
     * <br/>
     * @example
     * var x = new X509();
     * algName = x.getAlgorithmIdentifierName("30...");
     */
    this.getAlgorithmIdentifierName = function(hTLV) {
	for (var key in _PSSNAME2ASN1TLV) {
	    if (hTLV === _PSSNAME2ASN1TLV[key]) {
		return key;
	    }
	}
	return _oidname(_getVbyListEx(hTLV, 0, [0], "06"));
    };

    /**
     * get JSON object of issuer field<br/>
     * @name getIssuer
     * @memberOf X509#
     * @function
     * @return {Array} JSON object of issuer field
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getX500Name
     * @description
     * @example
     * var x = new X509(sCertPEM);
     * x.getIssuer() &rarr;
     * { array: [[{type:'C',value:'JP',ds:'prn'}],...],
     *   str: "/C=JP/..." }
     */
    this.getIssuer = function() {
	return this.getX500Name(this.getIssuerHex())
    };

    /**
     * get hexadecimal string of issuer field TLV of certificate.<br/>
     * @name getIssuerHex
     * @memberOf X509#
     * @function
     * @return {String} hexadecial string of issuer DN ASN.1
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var issuer = x.getIssuerHex(); // return string like "3013..."
     */
    this.getIssuerHex = function() {
	return _getTLVbyList(this.hex, 0, [0, 3 + this.foffset], "30");
    };

    /**
     * get string of issuer field of certificate.<br/>
     * @name getIssuerString
     * @memberOf X509#
     * @function
     * @return {String} issuer DN string
     * @see X509#getIssuer
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var dn1 = x.getIssuerString(); // return string like "/C=US/O=TEST"
     * var dn2 = KJUR.asn1.x509.X500Name.compatToLDAP(dn1); // returns "O=TEST, C=US"
     */
    this.getIssuerString = function() {
	var pIssuer = this.getIssuer();
	return pIssuer.str;
    };

    /**
     * get JSON object of subject field<br/>
     * @name getSubject
     * @memberOf X509#
     * @function
     * @return {Array} JSON object of subject field
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getX500Name
     * @description
     * @example
     * var x = new X509(sCertPEM);
     * x.getSubject() &rarr;
     * { array: [[{type:'C',value:'JP',ds:'prn'}],...],
     *   str: "/C=JP/..." }
     */
    this.getSubject = function() {
	return this.getX500Name(this.getSubjectHex());
    };

    /**
     * get hexadecimal string of subject field of certificate.<br/>
     * @name getSubjectHex
     * @memberOf X509#
     * @function
     * @return {String} hexadecial string of subject DN ASN.1
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var subject = x.getSubjectHex(); // return string like "3013..."
     */
    this.getSubjectHex = function() {
	return _getTLVbyList(this.hex, 0, [0, 5 + this.foffset], "30");
    };

    /**
     * get string of subject field of certificate.<br/>
     * @name getSubjectString
     * @memberOf X509#
     * @function
     * @return {String} subject DN string
     * @see X509#getSubject
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var dn1 = x.getSubjectString(); // return string like "/C=US/O=TEST"
     * var dn2 = KJUR.asn1.x509.X500Name.compatToLDAP(dn1); // returns "O=TEST, C=US"
     */
    this.getSubjectString = function() {
	var pSubject = this.getSubject();
	return pSubject.str;
    };

    /**
     * get notBefore field string of certificate.<br/>
     * @name getNotBefore
     * @memberOf X509#
     * @function
     * @return {String} not before time value (ex. "151231235959Z")
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var notBefore = x.getNotBefore(); // return string like "151231235959Z"
     */
    this.getNotBefore = function() {
        var s = _getVbyList(this.hex, 0, [0, 4 + this.foffset, 0]);
        s = s.replace(/(..)/g, "%$1");
        s = decodeURIComponent(s);
        return s;
    };

    /**
     * get notAfter field string of certificate.<br/>
     * @name getNotAfter
     * @memberOf X509#
     * @function
     * @return {String} not after time value (ex. "151231235959Z")
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var notAfter = x.getNotAfter(); // return string like "151231235959Z"
     */
    this.getNotAfter = function() {
	var s = _getVbyList(this.hex, 0, [0, 4 + this.foffset, 1]);
        s = s.replace(/(..)/g, "%$1");
        s = decodeURIComponent(s);
        return s;
    };

    /**
     * get a hexadecimal string of subjectPublicKeyInfo field.<br/>
     * @name getPublicKeyHex
     * @memberOf X509#
     * @function
     * @return {String} ASN.1 SEQUENCE hexadecimal string of subjectPublicKeyInfo field
     * @since jsrsasign 7.1.4 x509 1.1.13
     * @deprecated since jsrsasign 10.5.7 x509 2.0.13. Please use {@link X509#getSPKI} instead.
     *
     * @example
     * x = new X509(sCertPEM);
     * hSPKI = x.getPublicKeyHex(); // return string like "30820122..."
     */
    this.getPublicKeyHex = function() {
	return this.getSPKI();
    };

    /**
     * get ASN.1 TLV hexadecimal string of subjectPublicKeyInfo field.<br/>
     * @name getSPKI
     * @memberOf X509#
     * @function
     * @return {string} ASN.1 SEQUENCE hexadecimal string of subjectPublicKeyInfo field
     * @since jsrsasign 10.5.8 x509 2.0.13
     * @see X509#getPublicKeyHex
     * @see X509#getSPKIValue
     *
     * @description
     * Get a hexadecimal string of SubjectPublicKeyInfo ASN.1 TLV of the certificate.<br/>
     * <pre>
     * SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *    algorithm         AlgorithmIdentifier,
     *    subjectPublicKey  BIT STRING  }
     * </pre>
     *
     * @example
     * x = new X509(sCertPEM);
     * hSPKI = x.getSPKI(); // return string like "30820122..."
     */
    this.getSPKI = function() {
	return _getTLVbyList(this.hex, 0, [0, 6 + this.foffset], "30");
    };

    /**
     * get hexadecimal string of subjectPublicKey of subjectPublicKeyInfo field.<br/>
     * @name getSPKIValue
     * @memberOf X509#
     * @function
     * @return {string} ASN.1 hexadecimal string of subjectPublicKey
     * @since jsrsasign 10.5.8 x509 2.0.13
     * @see X509#getSPKI
     *
     * @description
     * Get a hexadecimal string of subjectPublicKey ASN.1 value of SubjectPublicKeyInfo 
     * of the certificate without unusedbit "00".
     * The "subjectPublicKey" is encapsulated by BIT STRING.
     * This method returns BIT STRING value without unusedbits.
     * <br/>
     * <pre>
     * SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *    algorithm         AlgorithmIdentifier,
     *    subjectPublicKey  BIT STRING  }
     * </pre>
     *
     * @example
     * x = new X509(sCertPEM);
     * hSPKIValue = x.getSPKIValue(); // without BIT STRING Encapusulation.
     */
    this.getSPKIValue = function() {
	var hSPKI = this.getSPKI();
	if (hSPKI == null) return null;
	return _getVbyList(hSPKI, 0, [1], "03", true); // true: remove unused bit
    };

    /**
     * get a string index of subjectPublicKeyInfo field for hexadecimal string certificate.<br/>
     * @name getPublicKeyIdx
     * @memberOf X509#
     * @function
     * @return {Number} string index of subjectPublicKeyInfo field for hexadecimal string certificate.
     * @since jsrsasign 7.1.4 x509 1.1.13
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM);
     * idx = x.getPublicKeyIdx(); // return string index in x.hex parameter
     */
    this.getPublicKeyIdx = function() {
	return _getIdxbyList(this.hex, 0, [0, 6 + this.foffset], "30");
    };

    /**
     * get a string index of contents of subjectPublicKeyInfo BITSTRING value from hexadecimal certificate<br/>
     * @name getPublicKeyContentIdx
     * @memberOf X509#
     * @function
     * @return {Integer} string index of key contents
     * @since jsrsasign 8.0.0 x509 1.2.0
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM);
     * idx = x.getPublicKeyContentIdx(); // return string index in x.hex parameter
     */
    // NOTE: Without BITSTRING encapsulation.
    this.getPublicKeyContentIdx = function() {
	var idx = this.getPublicKeyIdx();
	return _getIdxbyList(this.hex, idx, [1, 0], "30");
    };

    /**
     * get a RSAKey/ECDSA/DSA public key object of subjectPublicKeyInfo field.<br/>
     * @name getPublicKey
     * @memberOf X509#
     * @function
     * @return {Object} RSAKey/ECDSA/DSA public key object of subjectPublicKeyInfo field
     * @since jsrsasign 7.1.4 x509 1.1.13
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM);
     * pubkey= x.getPublicKey();
     */
    this.getPublicKey = function() {
	return KEYUTIL.getKey(this.getPublicKeyHex(), null, "pkcs8pub");
    };

    /**
     * get signature algorithm name from hexadecimal certificate data
     * @name getSignatureAlgorithmName
     * @memberOf X509#
     * @function
     * @return {String} signature algorithm name (ex. SHA1withRSA, SHA256withECDSA)
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @see X509#getAlgorithmIdentifierName
     * @description
     * This method will get signature algorithm name of certificate:
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * x.getSignatureAlgorithmName() &rarr; "SHA256withRSA"
     */
    this.getSignatureAlgorithmName = function() {
	var hTLV = _getTLVbyList(this.hex, 0, [1], "30");
	return this.getAlgorithmIdentifierName(hTLV);
    };

    /**
     * get signature value as hexadecimal string<br/>
     * @name getSignatureValueHex
     * @memberOf X509#
     * @function
     * @return {String} signature value hexadecimal string without BitString unused bits
     * @since jsrsasign 7.2.0 x509 1.1.14
     *
     * @description
     * This method will get signature value of certificate:
     *
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * x.getSignatureValueHex() &rarr "8a4c47913..."
     */
    this.getSignatureValueHex = function() {
	return _getVbyList(this.hex, 0, [2], "03", true);
    };

    /**
     * verifies signature value by public key<br/>
     * @name verifySignature
     * @memberOf X509#
     * @function
     * @param {Object} pubKey public key object
     * @return {Boolean} true if signature value is valid otherwise false
     * @since jsrsasign 7.2.0 x509 1.1.14
     *
     * @description
     * This method verifies signature value of hexadecimal string of 
     * X.509 certificate by specified public key object.
     * The signature algorithm used to verify will refer
     * signatureAlgorithm field. (See {@link X509#getSignatureAlgorithmField})
     * RSA-PSS signature algorithms (SHA{,256,384,512}withRSAandMGF1)
     * are available.
     *
     * @example
     * pubKey = KEYUTIL.getKey(pemPublicKey); // or certificate
     * x = new X509();
     * x.readCertPEM(pemCert);
     * x.verifySignature(pubKey) &rarr; true, false or raising exception
     */
    this.verifySignature = function(pubKey) {
	var algName = this.getSignatureAlgorithmField();
	var hSigVal = this.getSignatureValueHex();
	var hTbsCert = _getTLVbyList(this.hex, 0, [0], "30");
	
	var sig = new KJUR.crypto.Signature({alg: algName});
	sig.init(pubKey);
	sig.updateHex(hTbsCert);
	return sig.verify(hSigVal);
    };

    // ===== parse extension ======================================
    /**
     * set array of X.509v3 and CSR extesion information such as extension OID, criticality and value index. (DEPRECATED)<br/>
     * @name parseExt
     * @memberOf X509#
     * @function
     * @param {String} hCSR - PEM string of certificate signing requrest(CSR) (OPTION)
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @deprecated jsrsasign 9.1.1 x509 2.0.1
     *
     * @description
     * This method will set an array of X.509v3 extension information having 
     * following parameters:
     * <ul>
     * <li>oid - extension OID (ex. 2.5.29.19)</li>
     * <li>critical - true or false</li>
     * <li>vidx - string index for extension value</li>
     * <br/>
     * When you want to parse extensionRequest of CSR,
     * argument 'hCSR' shall be specified.
     * <br/>
     * NOTE: CSR is supported from jsrsasign 8.0.20 x509 1.1.22.
     * <br/>
     * This method and X509.aExtInfo property
     * have been *deprecated* since jsrsasign 9.1.1.
     * All extension parser method such as X509.getExt* shall be
     * call with argument "hExtV" and "critical" explicitly.
     *
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     *
     * x.aExtInfo &rarr;
     * [ { oid: "2.5.29,19", critical: true, vidx: 2504 }, ... ]
     *
     * // to parse CSR
     * X = new X509()
     * x.parseExt("-----BEGIN CERTIFICATE REQUEST-----...");
     * x.aExtInfo &rarr;
     * [ { oid: "2.5.29,19", critical: true, vidx: 2504 }, ... ]
     */
    this.parseExt = function(hCSR) {
	var iExtSeq, aExtIdx, h;

	if (hCSR === undefined) {
	    h = this.hex;
	    if (this.version !== 3) return -1;
	    iExtSeq = _getIdxbyList(h, 0, [0, 7, 0], "30");
	    aExtIdx = _getChildIdx(h, iExtSeq);
	} else {
	    h = pemtohex(hCSR);
	    var idx1 = _getIdxbyList(h, 0, [0, 3, 0, 0], "06");

	    if (_getV(h, idx1) != "2a864886f70d01090e") {
		this.aExtInfo = new Array();
		return;
	    }

	    iExtSeq = _getIdxbyList(h, 0, [0, 3, 0, 1, 0], "30");
	    aExtIdx = _getChildIdx(h, iExtSeq);

	    this.hex = h;
	}
	    
	this.aExtInfo = new Array();
	for (var i = 0; i < aExtIdx.length; i++) {
	    var item = {};
	    item.critical = false;
	    var a = _getChildIdx(h, aExtIdx[i]);
	    var offset = 0;

	    if (a.length === 3) {
		item.critical = true;
		offset = 1;
	    }

	    item.oid = _ASN1HEX.hextooidstr(_getVbyList(h, aExtIdx[i], [0], "06"));
	    var octidx = _getIdxbyList(h, aExtIdx[i], [1 + offset]);
	    item.vidx = _getVidx(h, octidx);
	    this.aExtInfo.push(item);
	}
    };

    /**
     * get a X.509v3 extesion information such as extension OID, criticality and value index for specified oid or name.<br/>
     * @name getExtInfo
     * @memberOf X509#
     * @function
     * @param {String} oidOrName X.509 extension oid or name (ex. keyUsage or 2.5.29.19)
     * @return X.509 extension information such as extension OID or value indx (see {@link X509#parseExt})
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @description
     * This method will get an X.509v3 extension information JSON object
     * having extension OID, criticality and value idx for specified
     * extension OID or name.
     * If there is no such extension, this returns undefined.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     *
     * x.getExtInfo("keyUsage") &rarr; { oid: "2.5.29.15", critical: true, vidx: 1714 }
     * x.getExtInfo("unknownExt") &rarr; undefined
     */
    this.getExtInfo = function(oidOrName) {
	var a = this.aExtInfo;
	var oid = oidOrName;
	if (! oidOrName.match(/^[0-9.]+$/)) {
	    oid = KJUR.asn1.x509.OID.name2oid(oidOrName);
	}
	if (oid === '') return undefined;

	for (var i = 0; i < a.length; i++) {
	    if (a[i].oid === oid) return a[i];
	}
	return undefined;
    };

    /**
     * get BasicConstraints extension value as object in the certificate
     * @name getExtBasicConstraints
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Array} JSON object of BasicConstraints parameter or undefined
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @see KJUR.asn1.x509.BasicConstraints
     * @description
     * This method will get basic constraints extension value as object with following paramters.
     * <ul>
     * <li>{Boolean}cA - CA flag whether CA or not</li>
     * <li>{Integer}pathLen - maximum intermediate certificate length</li>
     * <li>{Boolean}critical - critical flag</li>
     * </ul>
     * There are use cases for return values:
     * <ul>
     * <li>{cA:true,pathLen:3,critical:true} - cA flag is true and pathLen is 3</li>
     * <li>{cA:true,critical:true} - cA flag is true and no pathLen</li>
     * <li>{} - basic constraints has no value in case of end entity certificate</li>
     * <li>undefined - there is no basic constraints extension</li>
     * </ul>
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtBasicConstraints() &rarr; {cA:true,pathLen:3,critical:true}
     */
    this.getExtBasicConstraints = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("basicConstraints");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"basicConstraints"};
	if (critical) result.critical = true;

	if (hExtV === '3000') return result;
	if (hExtV === '30030101ff') {
	    result.cA = true;
	    return result;
	}
	if (hExtV.substr(0, 12) === '30060101ff02') {
	    var pathLexHex = _getV(hExtV, 10);
	    var pathLen = parseInt(pathLexHex, 16);
	    result.cA = true;
	    result.pathLen = pathLen;
	    return result;
	}
	throw new Error("hExtV parse error: " + hExtV);
    };

    /**
     * get NameConstraints extension value as object in the certificate<br/>
     * @name getExtNameConstraints
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Object} JSON object of NamConstraints parameter or undefined
     * @since jsrsasign 10.5.16 x509 2.0.16
     * @see KJUR.asn1.x509.NameConstraints
     * @see KJUR.asn1.x509.GeneralSubtree
     * @see KJUR.asn1.x509.GeneralName
     * @see X509#getGeneralSubtree
     * @see X509#getGeneralName
     *
     * @description
     * This method will get name constraints extension value as object with following paramters.
     * <ul>
     * <li>{Array}permit - array of {@link KJUR.asn1.x509.GeneralSubtree} parameter</li>
     * <li>{Array}exclude - array of {@link KJUR.asn1.x509.GeneralSubtree} parameter</li>
     * <li>{Boolean}critical - critical flag</li>
     * </ul>
     *
     * @example
     * x = new X509(sCertPEM);
     * x.getExtNameConstraints() &rarr; {
     *   critical: true,
     *   permit: [{dns: 'example.com'},{rfc822: 'john@example.com'}],
     *   exclude: [{dn: {...X500Name parameter...}}]
     * }
     */
    this.getExtNameConstraints = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("nameConstraints");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"nameConstraints"};
	if (critical) result.critical = true;

	var aIdx = _getChildIdx(hExtV, 0);
	for (var i = 0; i < aIdx.length; i++) {
	    var aList = [];
	    var aIdx2 = _getChildIdx(hExtV, aIdx[i]);
	    for (var j = 0; j < aIdx2.length; j++) {
		var hSub = _getTLV(hExtV, aIdx2[j]);
		var p = this.getGeneralSubtree(hSub);
		aList.push(p);
	    }

	    var tag = hExtV.substr(aIdx[i], 2); 
	    if (tag == "a0") {
		result.permit = aList;
	    } else if (tag == "a1") {
		result.exclude = aList;
	    }
	}
	return result;
    };

    /**
     * get GeneralSubtree ASN.1 structure parameter as JSON object<br/>
     * @name getGeneralSubtree
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of GeneralSubtree
     * @return {Object} JSON object of GeneralSubtree parameters or undefined
     * @since jsrsasign 10.5.16 x509 2.0.16
     * @see KJUR.asn1.x509.GeneralSubtree
     * @see KJUR.asn1.x509.GeneralName
     * @see X509#getExtNameConstraints
     * @see X509#getGeneralName
     *
     * @description
     * This method will get GeneralSubtree parameters defined in
     * <a href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10">
     * RFC 5280 4.2.1.10</a>.
     * <pre>
     * GeneralSubtree ::= SEQUENCE {
     *      base                    GeneralName,
     *      minimum         [0]     BaseDistance DEFAULT 0,
     *      maximum         [1]     BaseDistance OPTIONAL }
     * BaseDistance ::= INTEGER (0..MAX)
     * </pre>
     * Result of this method can be passed to
     * {@link KJUR.asn1.x509.GeneralSubtree} constructor.
     * 
     * @example
     * x = new X509(sPEM);
     * x.getGeneralSubtree("30...") &rarr; { dn: ...X500NameObject..., min: 1, max: 3 }
     * x.getGeneralSubtree("30...") &rarr; { dns: ".example.com" }
     */
    this.getGeneralSubtree = function(h) {
	var aIdx = _getChildIdx(h, 0);
	var len = aIdx.length;
	if (len < 1 || 2 < len) throw new Error("wrong num elements");
	var result = this.getGeneralName(_getTLV(h, aIdx[0]));

	for (var i = 1; i < len; i++) {
	    var tag = h.substr(aIdx[i], 2);
	    var hV = _getV(h, aIdx[i]);
	    var minmaxValue = parseInt(hV, 16);
	    if (tag == "80") result.min = minmaxValue;
	    if (tag == "81") result.max = minmaxValue;
	}
	return result;
    };

    /**
     * get KeyUsage extension value as JSON object
     * @memberOf X509#
     * @function
     * @name getExtKeyUsage
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Array} JSON object of KeyUsage parameter or undefined
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see KJUR.asn1.x509.KeyUsage
     * @see X509#getExtKeyUsageString
     * @description
     * This method parse keyUsage extension. When arguments are
     * not specified, its extension in X509 object will be parsed.
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.KeyUsage} constructor.
     * <br>
     * When hExtV and critical specified as arguments, return value
     * will be generated from them.
     * <pre>
     * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
     * KeyUsage ::= BIT STRING {
     *      digitalSignature        (0),
     *      nonRepudiation          (1),
     *      keyEncipherment         (2),
     *      dataEncipherment        (3),
     *      keyAgreement            (4),
     *      keyCertSign             (5),
     *      cRLSign                 (6),
     *      encipherOnly            (7),
     *      decipherOnly            (8) }     
     * </pre>
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtKeyUsage() &rarr;
     * {
     *   critial: true,
     *   names: ["digitalSignature", "decipherOnly"]
     * }
     *
     * x = new X509();
     * x.getExtKeyUsage("306230...") 
     * x.getExtKeyUsage("306230...", true) 
     */
    this.getExtKeyUsage = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("keyUsage");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"keyUsage"};
	if (critical) result.critical = true;

	result.names = this.getExtKeyUsageString(hExtV).split(",");

	return result;
    };

    /**
     * get KeyUsage extension value as binary string in the certificate<br/>
     * @name getExtKeyUsageBin
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @return {String} binary string of key usage bits (ex. '101')
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @see X509#getExtKeyUsage
     * @description
     * This method will get key usage extension value
     * as binary string such like '101'.
     * Key usage bits definition is in the RFC 5280.
     * If there is no key usage extension in the certificate,
     * it returns empty string (i.e. '').
     * <br/>
     * NOTE: argument 'hExtV' supported since jsrsasign 9.0.0 x509 2.0.0.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtKeyUsageBin() &rarr; '101'
     * // 1 - digitalSignature
     * // 0 - nonRepudiation
     * // 1 - keyEncipherment
     */
    this.getExtKeyUsageBin = function(hExtV) {
	if (hExtV === undefined) {
	    var info = this.getExtInfo("keyUsage");
	    if (info === undefined) return '';
	    hExtV = _getTLV(this.hex, info.vidx);
	}
	
	if (hExtV.length != 8 && hExtV.length != 10)
	    throw new Error("malformed key usage value: " + hExtV);

	var s = "000000000000000" + parseInt(hExtV.substr(6), 16).toString(2);
	if (hExtV.length == 8) s = s.slice(-8);
	if (hExtV.length == 10) s = s.slice(-16);
	s = s.replace(/0+$/, '');
	if (s == '') s = '0';
	return s;
    };

    /**
     * get KeyUsage extension value as names in the certificate<br/>
     * @name getExtKeyUsageString
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @return {String} comma separated string of key usage
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @see X509#getExtKeyUsage
     * @description
     * This method will get key usage extension value
     * as comma separated string of usage names.
     * If there is no key usage extension in the certificate,
     * it returns empty string (i.e. '').
     * <br/>
     * NOTE: argument 'hExtV' supported since jsrsasign 9.0.0 x509 2.0.0.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtKeyUsageString() &rarr; "digitalSignature,keyEncipherment"
     */
    this.getExtKeyUsageString = function(hExtV) {
	var bKeyUsage = this.getExtKeyUsageBin(hExtV);
	var a = new Array();
	for (var i = 0; i < bKeyUsage.length; i++) {
	    if (bKeyUsage.substr(i, 1) == "1") a.push(X509.KEYUSAGE_NAME[i]);
	}
	return a.join(",");
    };

    /**
     * get subjectKeyIdentifier value as hexadecimal string in the certificate<br/>
     * @name getExtSubjectKeyIdentifier
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Array} JSON object of SubjectKeyIdentifier parameter or undefined
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @description
     * This method will get 
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2">
     * SubjectKeyIdentifier extension</a> value as JSON object.
     * <br>
     * When hExtV and critical specified as arguments, return value
     * will be generated from them.
     * If there is no such extension in the certificate, it returns undefined.
     * <br>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.SubjectKeyIdentifier} constructor.
     * <pre>
     * id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }
     * SubjectKeyIdentifier ::= KeyIdentifier
     * </pre>
     * <br>
     * CAUTION:
     * Returned JSON value format have been changed without 
     * backward compatibility since jsrsasign 9.0.0 x509 2.0.0.
     *
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtSubjectKeyIdentifier() &rarr; 
     * { kid: {hex: "1b3347ab..."}, critical: true };
     */
    this.getExtSubjectKeyIdentifier = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("subjectKeyIdentifier");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"subjectKeyIdentifier"};
	if (critical) result.critical = true;

	var hKID = _getV(hExtV, 0);
	result.kid = {hex: hKID};

	return result;
    };

    /**
     * get authorityKeyIdentifier value as JSON object in the certificate<br/>
     * @name getExtAuthorityKeyIdentifier
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Array} JSON object of AuthorityKeyIdentifier parameter or undefined
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @see KJUR.asn1.x509.AuthorityKeyIdentifier
     * @description
     * This method will get 
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.1">
     * AuthorityKeyIdentifier extension</a> value as JSON object.
     * <br>
     * When hExtV and critical specified as arguments, return value
     * will be generated from them.
     * If there is no such extension in the certificate, it returns undefined.
     * <br/>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.AuthorityKeyIdentifier} constructor.
     * <pre>
     *    id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
     *    AuthorityKeyIdentifier ::= SEQUENCE {
     *       keyIdentifier             [0] KeyIdentifier           OPTIONAL,
     *       authorityCertIssuer       [1] GeneralNames            OPTIONAL,
     *       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
     *    KeyIdentifier ::= OCTET STRING
     * </pre>
     * Constructor may have following parameters:
     * <ul>
     * <li>{Array}kid - JSON object of {@link KJUR.asn1.DEROctetString} parameters</li>
     * <li>{Array}issuer - JSON object of {@link KJUR.asn1.x509.X500Name} parameters</li>
     * <li>{Array}sn - JSON object of {@link KJUR.asn1.DERInteger} parameters</li>
     * <li>{Boolean}critical - critical flag</li>
     * </ul>
     * <br>
     * NOTE: The 'authorityCertIssuer' and 'authorityCertSerialNumber'
     * supported since jsrsasign 9.0.0 x509 2.0.0.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtAuthorityKeyIdentifier() &rarr; 
     * { kid: {hex: "1234abcd..."},
     *   issuer: {hex: "30..."},
     *   sn: {hex: "1234..."},
     *   critical: true}
     */
    this.getExtAuthorityKeyIdentifier = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("authorityKeyIdentifier");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"authorityKeyIdentifier"};
	if (critical) result.critical = true;

	var a = _getChildIdx(hExtV, 0);
	for (var i = 0; i < a.length; i++) {
	    var tag = hExtV.substr(a[i], 2);
	    if (tag === "80") {
		result.kid = {hex: _getV(hExtV, a[i])};
	    }
	    if (tag === "a1") {
		var hGNS = _getTLV(hExtV, a[i]);
		var gnsParam = this.getGeneralNames(hGNS);
		result.issuer = gnsParam[0]["dn"];
	    }
	    if (tag === "82") {
		result.sn = {hex: _getV(hExtV, a[i])};
	    }
	}
	return result;
    };

    /**
     * get extKeyUsage value as JSON object
     * @name getExtExtKeyUsage
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Array} JSON object of ExtKeyUsage parameter or undefined
     * @return {Object} JSONarray of extended key usage ID name or oid
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see KJUR.asn1.x509.ExtKeyUsage
     * @description
     * This method parse extKeyUsage extension. When arguments are
     * not specified, its extension in X509 object will be parsed.
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.ExtKeyUsage} constructor.
     * <br>
     * When hExtV and critical specified as arguments, return value
     * will be generated from them.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtExtKeyUsage() &rarr;
     * { array: ["clientAuth", "emailProtection", "1.3.6.1.4.1.311.10.3.4"], 
     *   critical: true},
     */
    this.getExtExtKeyUsage = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("extKeyUsage");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"extKeyUsage",array:[]};
	if (critical) result.critical = true;

	var a = _getChildIdx(hExtV, 0);

	for (var i = 0; i < a.length; i++) {
	    result.array.push(_oidname(_getV(hExtV, a[i])));
	}

	return result;
    };

    /**
     * get extKeyUsage value as array of name string in the certificate(DEPRECATED)<br/>
     * @name getExtExtKeyUsageName
     * @memberOf X509#
     * @function
     * @return {Object} array of extended key usage ID name or oid
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @deprecated since jsrsasign 9.0.0 x509 2.0.0
     * @description
     * This method will get extended key usage extension value
     * as array of name or OID string.
     * If there is this in the certificate, it returns undefined;
     * <br>
     * NOTE: Supported extended key usage ID names are defined in
     * name2oidList parameter in asn1x509.js file.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtExtKeyUsageName() &rarr; ["serverAuth", "clientAuth", "0.1.2.3.4.5"]
     */
    this.getExtExtKeyUsageName = function() {
	var info = this.getExtInfo("extKeyUsage");
	if (info === undefined) return info;

	var result = new Array();
	
	var h = _getTLV(this.hex, info.vidx);
	if (h === '') return result;

	var a = _getChildIdx(h, 0);
	for (var i = 0; i < a.length; i++) {
	    result.push(_oidname(_getV(h, a[i])));
	}

	return result;
    };

    /**
     * get subjectAltName value as array of string in the certificate
     * @name getExtSubjectAltName
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Array} JSON object of SubjectAltName parameters or undefined
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @see KJUR.asn1.x509.SubjectAltName
     * @see X509#getExtIssuerAltName
     * @description
     * This method will get subjectAltName value
     * as an array of JSON object which has properties defined
     * in {@link KJUR.asn1.x509.SubjectAltName}.
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.SubjectAltName} constructor.
     * If there is no this extension in the certificate,
     * it returns undefined.
     * <br>
     * When hExtV and critical specified as arguments, return value
     * will be generated from them.
     * <br>
     * CAUTION: return value of JSON object format have been changed
     * from jsrsasign 9.0.0 x509 2.0.0 without backword compatibility.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtSubjectAltName() &rarr; 
     * { array: [
     *     {uri: "http://example.com/"},
     *     {rfc822: "user1@example.com"},
     *     {dns: "example.com"}
     *   ],
     *   critical: true
     * }
     *
     * x.getExtSubjectAltName("3026...") &rarr;
     * { array: [{ip: "192.168.1.1"}] }
     */
    this.getExtSubjectAltName = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("subjectAltName");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"subjectAltName",array:[]};
	if (critical) result.critical = true;

	result.array = this.getGeneralNames(hExtV);

	return result;
    };

    /**
     * get issuerAltName value as array of string in the certificate
     * @name getExtIssuerAltName
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Array} JSON object of IssuerAltName parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see KJUR.asn1.x509.IssuerAltName
     * @see X509#getExtSubjectAltName
     * @description
     * This method will get issuerAltName value
     * as an array of JSON object which has properties defined
     * in {@link KJUR.asn1.x509.IssuerAltName}.
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.IssuerAltName} constructor.
     * If there is no this extension in the certificate,
     * it returns undefined.
     * <br>
     * When hExtV and critical specified as arguments, return value
     * will be generated from them.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtIssuerAltName() &rarr; 
     * { array: [
     *     {uri: "http://example.com/"},
     *     {rfc822: "user1@example.com"},
     *     {dns: "example.com"}
     *   ],
     *   critical: true
     * }
     *
     * x.getExtIssuerAltName("3026...") &rarr;
     * { array: [{ip: "192.168.1.1"}] }
     */
    this.getExtIssuerAltName = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("issuerAltName");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"issuerAltName",array:[]};
	if (critical) result.critical = true;

	result.array = this.getGeneralNames(hExtV);

	return result;
    };

    /**
     * get GeneralNames ASN.1 structure parameter as JSON object
     * @name getGeneralNames
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of GeneralNames
     * @return {Array} array of GeneralNames parameters
     * @see KJUR.asn1.x509.GeneralNames
     * @see KJUR.asn1.x509.GeneralName
     * @see X509#getGeneralNames
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @description
     * This method will get GeneralNames parameters defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.6">
     * RFC 5280 4.2.1.6</a>.
     * <pre>
     * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
     * </pre>
     * Result of this method can be passed to
     * {@link KJUR.asn1.x509.GeneralNames} constructor.
     * @example
     * x = new X509();
     * x.getGeneralNames("3011860f687474703a2f2f6161612e636f6d2f")
     * &rarr; [{uri: "http://aaa.com/"}]
     *
     * x.getGeneralNames("301ea41c30...") &rarr;
     * [{ dn: {
     *     array: [
     *       [{type:"C", value:"JP", ds:"prn"}],
     *       [{type:"O", value:"T1", ds:"utf8"}]
     *     ],
     *     str: "/C=JP/O=T1" } }]
     */
    this.getGeneralNames = function(h) {
	var aIdx = _getChildIdx(h, 0);
	var result = [];
	for (var i = 0; i < aIdx.length; i++) {
	    var gnParam = this.getGeneralName(_getTLV(h, aIdx[i]));
	    if (gnParam !== undefined) result.push(gnParam);
	}
	return result;
    };

    /**
     * get GeneralName ASN.1 structure parameter as JSON object<br/>
     * @name getGeneralName
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of GeneralName
     * @return {Array} JSON object of GeneralName parameters or undefined
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see KJUR.asn1.x509.GeneralNames
     * @see KJUR.asn1.x509.GeneralName
     * @see KJUR.asn1.x509.OtherName
     * @see X509#getGeneralName
     * @see X509#getOtherName
     *
     * @description
     * This method will get GeneralName parameters defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.6">
     * RFC 5280 4.2.1.6</a>.
     * <pre>
     * GeneralName ::= CHOICE {
     *      otherName                       [0]     OtherName,
     *      rfc822Name                      [1]     IA5String,
     *      dNSName                         [2]     IA5String,
     *      x400Address                     [3]     ORAddress,
     *      directoryName                   [4]     Name,
     *      ediPartyName                    [5]     EDIPartyName,
     *      uniformResourceIdentifier       [6]     IA5String,
     *      iPAddress                       [7]     OCTET STRING,
     *      registeredID                    [8]     OBJECT IDENTIFIER }
     * </pre>
     * Result of this method can be passed to
     * {@link KJUR.asn1.x509.GeneralName} constructor.
     * @example
     * x = new X509();
     * x.getGeneralName("860f687474703a2f2f6161612e636f6d2f") 
     * &rarr; {uri: "http://aaa.com/"}
     * x.getGeneralName("a41c30...") &rarr;
     * { dn: {
     *     array: [
     *       [{type:"C", value:"JP", ds:"prn"}],
     *       [{type:"O", value:"T1", ds:"utf8"}]
     *     ],
     *     str: "/C=JP/O=T1" } }
     */
    this.getGeneralName = function(h) {
	var tag = h.substr(0, 2);
	var hValue = _getV(h, 0);
	var sValue = hextorstr(hValue);
	if (tag == "81") return {rfc822: sValue};
	if (tag == "82") return {dns: sValue};
	if (tag == "86") return {uri: sValue};
	if (tag == "87") return {ip: hextoip(hValue)};
	if (tag == "a4") return {dn: this.getX500Name(hValue)};
	if (tag == "a0") return {other: this.getOtherName(h)};
	return undefined;
    };

    /**
     * get subjectAltName value as array of string in the certificate (DEPRECATED)
     * @name getExtSubjectAltName2
     * @memberOf X509#
     * @function
     * @return {Object} array of alt name array
     * @since jsrsasign 8.0.1 x509 1.1.17
     * @deprecated jsrsasign 9.0.0 x509 2.0.0
     * @description
     * This method will get subject alt name extension value
     * as array of type and name.
     * If there is this in the certificate, it returns undefined;
     * Type of GeneralName will be shown as following:
     * <ul>
     * <li>"MAIL" - [1]rfc822Name</li>
     * <li>"DNS"  - [2]dNSName</li>
     * <li>"DN"   - [4]directoryName</li>
     * <li>"URI"  - [6]uniformResourceIdentifier</li>
     * <li>"IP"   - [7]iPAddress</li>
     * </ul>
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtSubjectAltName2() &rarr;
     * [["DNS",  "example.com"],
     *  ["DNS",  "example.org"],
     *  ["MAIL", "foo@example.com"],
     *  ["IP",   "192.168.1.1"],
     *  ["IP",   "2001:db8::2:1"],
     *  ["DN",   "/C=US/O=TEST1"]]
     */
    this.getExtSubjectAltName2 = function() {
	var gnValueHex, gnValueStr, gnTag;
	var info = this.getExtInfo("subjectAltName");
	if (info === undefined) return info;

	var result = new Array();
	var h = _getTLV(this.hex, info.vidx);

	var a = _getChildIdx(h, 0);
	for (var i = 0; i < a.length; i++) {
	    gnTag = h.substr(a[i], 2);
	    gnValueHex = _getV(h, a[i]);
	    
	    if (gnTag === "81") { // rfc822Name [1]
		gnValueStr = hextoutf8(gnValueHex);
		result.push(["MAIL", gnValueStr]);
	    }
	    if (gnTag === "82") { // dNSName [2]
		gnValueStr = hextoutf8(gnValueHex);
		result.push(["DNS", gnValueStr]);
	    }
	    if (gnTag === "84") { // directoryName [4]
		gnValueStr = X509.hex2dn(gnValueHex, 0);
		result.push(["DN", gnValueStr]);
	    }
	    if (gnTag === "86") { // uniformResourceIdentifier [6]
		gnValueStr = hextoutf8(gnValueHex);
		result.push(["URI", gnValueStr]);
	    }
	    if (gnTag === "87") { // iPAddress [7]
		gnValueStr = hextoip(gnValueHex);
		result.push(["IP", gnValueStr]);
	    }
	}
	return result;
    };

    /**
     * get CRLDistributionPoints extension value as JSON object
     * @name getExtCRLDistributionPoints
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Object} JSON object of CRLDistributionPoints parameters or undefined
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see KJUR.asn1.x509.CRLDistributionPoints
     * @see X509#getDistributionPoint
     * @see X509#getDistributionPointName
     * @see X509#getGeneralNames
     * @see X509#getGeneralName
     * @description
     * This method will get certificate policies value
     * as an array of JSON object which has properties defined
     * in {@link KJUR.asn1.x509.CRLDistributionPoints}.
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.CRLDistributionPoints} constructor.
     * If there is no this extension in the certificate,
     * it returns undefined.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtCRLDistributionPoints() &rarr; 
     * {array: [
     *   {dpname: {full: [{uri: "http://example.com/"}]}},
     *   {dpname: {full: [{uri: "ldap://example.com/"}]}}
     *  ],
     *  critical: true}
     */
    this.getExtCRLDistributionPoints = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("cRLDistributionPoints");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"cRLDistributionPoints",array:[]};
	if (critical) result.critical = true;

	var a = _getChildIdx(hExtV, 0);
	for (var i = 0; i < a.length; i++) {
	    var hTLV = _getTLV(hExtV, a[i]);
	    result.array.push(this.getDistributionPoint(hTLV));
	}

	return result;
    };

    /**
     * get DistributionPoint ASN.1 structure parameter as JSON object
     * @name getDistributionPoint
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of DistributionPoint
     * @return {Object} JSON object of DistributionPoint parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getExtCRLDistributionPoints
     * @see X509#getDistributionPointName
     * @see X509#getGeneralNames
     * @see X509#getGeneralName
     * @description
     * This method will get DistributionPoint parameters.
     * Result of this method can be passed to
     * {@link KJUR.asn1.x509.DistributionPoint} constructor.
     * <br/>
     * NOTE: reasons[1] and CRLIssuer[2] field not supported
     * @example
     * x = new X509();
     * x.getDistributionPoint("30...") &rarr;
     * {dpname: {full: [{uri: "http://aaa.com/"}]}}
     */
    this.getDistributionPoint = function(h) {
	var result = {};
	var a = _getChildIdx(h, 0);
	for (var i = 0; i < a.length; i++) {
	    var tag = h.substr(a[i], 2);
	    var hTLV = _getTLV(h, a[i]);
	    if (tag == "a0") {
		result.dpname = this.getDistributionPointName(hTLV);
	    }
	}
	return result;
    };

    /**
     * get DistributionPointName ASN.1 structure parameter as JSON object
     * @name getDistributionPointName
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of DistributionPointName
     * @return {Object} JSON object of DistributionPointName parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getExtCRLDistributionPoints
     * @see X509#getDistributionPoint
     * @see X509#getGeneralNames
     * @see X509#getGeneralName
     * @description
     * This method will get DistributionPointName parameters.
     * Result of this method can be passed to
     * {@link KJUR.asn1.x509.DistributionPointName} constructor.
     * <br/>
     * NOTE: nameRelativeToCRLIssuer[1] not supported
     * @example
     * x = new X509();
     * x.getDistributionPointName("a0...") &rarr;
     * {full: [{uri: "http://aaa.com/"}]}
     */
    this.getDistributionPointName = function(h) {
	var result = {};
	var a = _getChildIdx(h, 0);
	for (var i = 0; i < a.length; i++) {
	    var tag = h.substr(a[i], 2);
	    var hTLV = _getTLV(h, a[i]);
	    if (tag == "a0") {
		result.full = this.getGeneralNames(hTLV);
	    }
	}
	return result;
    };

    /**
     * get array of string for fullName URIs in cRLDistributionPoints(CDP) in the certificate (DEPRECATED)
     * @name getExtCRLDistributionPointsURI
     * @memberOf X509#
     * @function
     * @return {Object} array of fullName URIs of CDP of the certificate
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @description
     * This method will get all fullName URIs of cRLDistributionPoints extension
     * in the certificate as array of URI string.
     * If there is this in the certificate, it returns undefined;
     * <br>
     * NOTE: Currently this method supports only fullName URI so that
     * other parameters will not be returned.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtCRLDistributionPointsURI() &rarr;
     * ["http://example.com/aaa.crl", "http://example.org/aaa.crl"]
     */
    this.getExtCRLDistributionPointsURI = function() {
	var p = this.getExtCRLDistributionPoints();
	if (p == undefined) return p;
	var a = p.array;
	var result = [];
	for (var i = 0; i < a.length; i++) {
	    try {
		if (a[i].dpname.full[0].uri != undefined) {
		    result.push(a[i].dpname.full[0].uri);
		}
	    } catch(ex) {}
	}
	return result;
    };

    /**
     * get AuthorityInfoAccess extension value in the certificate as associative array
     * @name getExtAIAInfo
     * @memberOf X509#
     * @function
     * @return {Object} associative array of AIA extension properties
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @description
     * This method will get authority info access value
     * as associate array which has following properties:
     * <ul>
     * <li>ocsp - array of string for OCSP responder URL</li>
     * <li>caissuer - array of string for caIssuer value (i.e. CA certificates URL)</li>
     * </ul>
     * If there is this in the certificate, it returns undefined;
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtAIAInfo(hCert) &rarr; 
     * { ocsp:     ["http://ocsp.foo.com"],
     *   caissuer: ["http://rep.foo.com/aaa.p8m"] }
     */
    this.getExtAIAInfo = function() {
	var info = this.getExtInfo("authorityInfoAccess");
	if (info === undefined) return info;

	var result = { ocsp: [], caissuer: [] };
	var a = _getChildIdx(this.hex, info.vidx);
	for (var i = 0; i < a.length; i++) {
	    var hOID = _getVbyList(this.hex, a[i], [0], "06");
	    var hName = _getVbyList(this.hex, a[i], [1], "86");
	    if (hOID === "2b06010505073001") {
		result.ocsp.push(hextoutf8(hName));
	    }
	    if (hOID === "2b06010505073002") {
		result.caissuer.push(hextoutf8(hName));
	    }
	}

	return result;
    };

    /**
     * get AuthorityInfoAccess extension value as JSON object
     * @name getExtAuthorityInfoAccess
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Array} JSON object of AuthorityInfoAccess parameters or undefined
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see KJUR.asn1.x509.AuthorityInfoAccess
     * @description
     * This method parse authorityInfoAccess extension. When arguments are
     * not specified, its extension in X509 object will be parsed.
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.AuthorityInfoAccess} constructor.
     * <br>
     * When hExtV and critical specified as arguments, return value
     * will be generated from them.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtAuthorityInfoAccess() &rarr;
     * {
     *   critial: true, // 
     *   array: [{ocsp: http://ocsp.example.com/},
     *           {caissuer: https://repository.example.com/}]
     * }
     *
     * x = new X509();
     * x.getExtAuthorityInfoAccesss("306230...") 
     * x.getExtAuthorityInfoAccesss("306230...", true) 
     */
    this.getExtAuthorityInfoAccess = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("authorityInfoAccess");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"authorityInfoAccess",array:[]};
	if (critical) result.critical = true;

	var a = _getChildIdx(hExtV, 0);
	for (var i = 0; i < a.length; i++) {
	    var hMethod = _getVbyListEx(hExtV, a[i], [0], "06");
	    var hLoc = _getVbyList(hExtV, a[i], [1], "86");
	    var sLoc = hextoutf8(hLoc);
	    if (hMethod == "2b06010505073001") {
		result.array.push({ocsp: sLoc});
	    } else if (hMethod == "2b06010505073002") {
		result.array.push({caissuer: sLoc});
	    } else {
		throw new Error("unknown method: " + hMethod);
	    }
	}

	return result;
    }

    /**
     * get CertificatePolicies extension value as JSON object
     * @name getExtCertificatePolicies
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value (OPTIONAL)
     * @param {Boolean} critical flag (OPTIONAL)
     * @return {Object} JSON object of CertificatePolicies parameters or undefined
     * @since jsrsasign 7.2.0 x509 1.1.14
     * @description
     * This method will get certificate policies value
     * as an array of JSON object which has properties defined
     * in {@link KJUR.asn1.x509.CertificatePolicies}.
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.CertificatePolicies} constructor.
     * If there is no this extension in the certificate,
     * it returns undefined.
     * <br>
     * CAUTION: return value of JSON object format have been changed
     * from jsrsasign 9.0.0 without backword compatibility.
     * <br>
     * When hExtV and critical specified as arguments, return value
     * will be generated from them.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtCertificatePolicies() &rarr; 
     * { array: [
     *   { policyoid: "1.2.3.4" }
     *   { policyoid: "1.2.3.5",
     *     array: [
     *       { cps: "https://example.com/" },
     *       { unotice: { exptext: { type: "bmp", str: "sample text" } } }
     *     ] 
     *   }
     * ]}
     */
    this.getExtCertificatePolicies = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("certificatePolicies");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}
	var result = {extname:"certificatePolicies",array:[]};
	if (critical) result.critical = true;

	var aIdxPI = _getChildIdx(hExtV, 0); // PolicyInformation list index
	for (var i = 0; i < aIdxPI.length; i++) {
	    var hPolicyInformation = _getTLV(hExtV, aIdxPI[i]);
	    var polinfo = this.getPolicyInformation(hPolicyInformation);
	    result.array.push(polinfo);
	}
	return result;
    }

    /**
     * get PolicyInformation ASN.1 structure parameter as JSON object
     * @name getPolicyInformation
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of PolicyInformation
     * @return {Object} JSON object of PolicyInformation parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @description
     * This method will get PolicyInformation parameters defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
     * RFC 5280 4.2.1.4</a>.
     * <pre>
     * PolicyInformation ::= SEQUENCE {
     *      policyIdentifier   CertPolicyId,
     *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
     *                              PolicyQualifierInfo OPTIONAL }
     * </pre>
     * Result of this method can be passed to
     * {@link KJUR.asn1.x509.PolicyInformation} constructor.
     * @example
     * x = new X509();
     * x.getPolicyInformation("30...") &rarr;
     * {
     *     policyoid: "2.16.840.1.114412.2.1",
     *     array: [{cps: "https://www.digicert.com/CPS"}]
     * }
     */
    this.getPolicyInformation = function(h) {
	var result = {};

	var hPOLICYOID = _getVbyList(h, 0, [0], "06");
	result.policyoid = _oidname(hPOLICYOID);
	
	var idxPQSEQ = _getIdxbyListEx(h, 0, [1], "30");
	if (idxPQSEQ != -1) {
	    result.array = [];
	    var aIdx = _getChildIdx(h, idxPQSEQ);
	    for (var j = 0; j < aIdx.length; j++) {
		var hPQI = _getTLV(h, aIdx[j]);
		var pqinfo = this.getPolicyQualifierInfo(hPQI);
		result.array.push(pqinfo);
	    }
	}

	return result;
    };

    /**
     * getOtherName ASN.1 structure parameter as JSON object<br/>
     * @name getOtherName
     * @memberOf X509#
     * @param {String} h hexadecimal string of GeneralName
     * @return {Array} associative array of OtherName
     * @since jsrsasign 10.5.3 x509 2.0.12
     * @see KJUR.asn1.x509.GeneralNames
     * @see KJUR.asn1.x509.GeneralName
     * @see KJUR.asn1.x509.OtherName
     * @see X509#getGeneralName
     * @see ASN1HEX#parse
     *
     * @description
     * This method will get OtherName parameters defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.6">
     * RFC 5280 4.2.1.6</a>.
     * <pre>
     * OtherName ::= SEQUENCE {
     *    type-id    OBJECT IDENTIFIER,
     *    value      [0] EXPLICIT ANY DEFINED BY type-id }
     * </pre>
     * The value of member "other" is converted by 
     * {@link ASN1HEX#parse}.
     *
     * @example
     * x = new X509();
     * x.getOtherName("30...") &rarr;
     * { oid: "1.2.3.4",
     *   other: {utf8str: {str: "aaa"}} }
     */
    this.getOtherName = function(h) {
        var result = {};

        var a = _getChildIdx(h, 0);
        var hOID = _getVbyList(h, a[0], [], "06");
        var hValue = _getVbyList(h, a[1], []);
        result.oid = KJUR.asn1.ASN1Util.oidHexToInt(hOID);
        result.obj = _ASN1HEX_parse(hValue);
        return result;
    };

    /**
     * get PolicyQualifierInfo ASN.1 structure parameter as JSON object
     * @name getPolicyQualifierInfo
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of PolicyQualifierInfo
     * @return {Object} JSON object of PolicyQualifierInfo parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getExtCertificatePolicies
     * @see X509#getPolicyInformation
     * @description
     * This method will get 
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
     * PolicyQualifierInfo</a> parameters.
     * <pre>
     * PolicyQualifierInfo ::= SEQUENCE {
     *      policyQualifierId  PolicyQualifierId,
     *      qualifier          ANY DEFINED BY policyQualifierId }
     * id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
     * id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
     * id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
     * PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
     * Qualifier ::= CHOICE {
     *      cPSuri           CPSuri,
     *      userNotice       UserNotice }
     * CPSuri ::= IA5String
     * </pre>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.PolicyQualifierInfo} constructor.
     * @example
     * x = new X509();
     * x.getPolicyQualifierInfo("30...") 
     * &rarr; {unotice: {exptext: {type: 'utf8', str: 'aaa'}}}
     * x.getPolicyQualifierInfo("30...") 
     * &rarr; {cps: "https://repository.example.com/"}
     */
    this.getPolicyQualifierInfo = function(h) {
	var result = {};
	var hPQOID = _getVbyList(h, 0, [0], "06");
	if (hPQOID === "2b06010505070201") { // cps
	    var hCPSURI = _getVbyListEx(h, 0, [1], "16");
	    result.cps = hextorstr(hCPSURI);
	} else if (hPQOID === "2b06010505070202") { // unotice
	    var hUserNotice = _getTLVbyList(h, 0, [1], "30");
	    result.unotice = this.getUserNotice(hUserNotice);
	}
	return result;
    };

    /**
     * get UserNotice ASN.1 structure parameter as JSON object
     * @name getUserNotice
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of UserNotice
     * @return {Object} JSON object of UserNotice parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getExtCertificatePolicies
     * @see X509#getPolicyInformation
     * @see X509#getPolicyQualifierInfo
     * @description
     * This method will get 
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
     * UserNotice</a> parameters.
     * <pre>
     * UserNotice ::= SEQUENCE {
     *      noticeRef        NoticeReference OPTIONAL,
     *      explicitText     DisplayText OPTIONAL }
     * </pre>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.NoticeReference} constructor.
     * <br/>
     * NOTE: NoticeReference parsing is currently not supported and
     * it will be ignored.
     * @example
     * x = new X509();
     * x.getUserNotice("30...") &rarr; {exptext: {type: 'utf8', str: 'aaa'}}
     */
    this.getUserNotice = function(h) {
	var result = {};
	var a = _getChildIdx(h, 0);
	for (var i = 0; i < a.length; i++) {
	    var hItem = _getTLV(h, a[i]);
	    if (hItem.substr(0, 2) != "30") {
		result.exptext = this.getDisplayText(hItem);
	    }
	}
	return result;
    };

    /**
     * get DisplayText ASN.1 structure parameter as JSON object
     * @name getDisplayText
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of DisplayText
     * @return {Object} JSON object of DisplayText parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getExtCertificatePolicies
     * @see X509#getPolicyInformation
     * @description
     * This method will get 
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.4">
     * DisplayText</a> parameters.
     * <pre>
     * DisplayText ::= CHOICE {
     *      ia5String        IA5String      (SIZE (1..200)),
     *      visibleString    VisibleString  (SIZE (1..200)),
     *      bmpString        BMPString      (SIZE (1..200)),
     *      utf8String       UTF8String     (SIZE (1..200)) }     
     * </pre>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.DisplayText} constructor.
     * @example
     * x = new X509();
     * x.getDisplayText("0c03616161") &rarr {type: 'utf8', str: 'aaa'}
     * x.getDisplayText("1e03616161") &rarr {type: 'bmp',  str: 'aaa'}
     */
    this.getDisplayText = function(h) {
	var _DISPLAYTEXTTAG = {"0c": "utf8", "16": "ia5", "1a": "vis" , "1e": "bmp"};
	var result = {};
	result.type = _DISPLAYTEXTTAG[h.substr(0, 2)];
	result.str = hextorstr(_getV(h, 0));
	return result;
    };

    /**
     * parse cRLNumber CRL extension as JSON object<br/>
     * @name getExtCRLNumber
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value
     * @param {Boolean} critical flag
     * @since jsrsasign 9.1.1 x509 2.0.1
     * @see KJUR.asn1.x509.CRLNumber
     * @see X509#getExtParamArray
     * @description
     * This method parses
     * CRLNumber CRL extension value defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-5.2.3">
     * RFC 5280 5.2.3</a> as JSON object.
     * <pre>
     * id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 }
     * CRLNumber ::= INTEGER (0..MAX)
     * </pre>
     * <br/>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.CRLNumber} constructor.
     * @example
     * crl = X509CRL("-----BEGIN X509 CRL...");
     * ... get hExtV and critical flag ...
     * crl.getExtCRLNumber("02...", false) &rarr;
     * {extname: "cRLNumber", num: {hex: "12af"}}
     */
    this.getExtCRLNumber = function(hExtV, critical) {
	var result = {extname:"cRLNumber"};
	if (critical) result.critical = true;

	if (hExtV.substr(0, 2) == "02") {
	    result.num = {hex: _getV(hExtV, 0)};
	    return result;
	}
	throw new Error("hExtV parse error: " + hExtV);
    };

    /**
     * parse cRLReason CRL entry extension as JSON object<br/>
     * @name getExtCRLReason
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value
     * @param {Boolean} critical flag
     * @since jsrsasign 9.1.1 x509 2.0.1
     * @see KJUR.asn1.x509.CRLReason
     * @see X509#getExtParamArray
     * @description
     * This method parses
     * CRLReason CRL entry extension value defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-5.3.1">
     * RFC 5280 5.3.1</a> as JSON object.
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
     * <br/>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.CRLReason} constructor.
     * @example
     * crl = X509CRL("-----BEGIN X509 CRL...");
     * ... get hExtV and critical flag ...
     * crl.getExtCRLReason("02...", false) &rarr;
     * {extname: "cRLReason", code: 3}
     */
    this.getExtCRLReason = function(hExtV, critical) {
	var result = {extname:"cRLReason"};
	if (critical) result.critical = true;

	if (hExtV.substr(0, 2) == "0a") {
	    result.code = parseInt(_getV(hExtV, 0), 16);
	    return result;
	}
	throw new Error("hExtV parse error: " + hExtV);
    };

    /**
     * parse OCSPNonce OCSP extension as JSON object<br/>
     * @name getExtOcspNonce
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value
     * @param {Boolean} critical flag
     * @return {Array} JSON object of parsed OCSPNonce extension
     * @since jsrsasign 9.1.6 x509 2.0.3
     * @see KJUR.asn1.x509.OCSPNonce
     * @see X509#getExtParamArray
     * @see X509#getExtParam
     * @description
     * This method parses
     * Nonce OCSP extension value defined in
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.4.1">
     * RFC 6960 4.4.1</a> as JSON object.
     * <pre>
     * id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
     * id-pkix-ocsp-nonce     OBJECT IDENTIFIER ::= { id-pkix-ocsp 2 }
     * Nonce ::= OCTET STRING
     * </pre>
     * <br/>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.OCSPNonce} constructor.
     * @example
     * x = new X509();
     * x.getExtOcspNonce(<<extn hex value >>) &rarr;
     * { extname: "ocspNonce", hex: "1a2b..." }
     */
    this.getExtOcspNonce = function(hExtV, critical) {
	var result = {extname:"ocspNonce"};
	if (critical) result.critical = true;

	var hNonce = _getV(hExtV, 0);
	result.hex = hNonce;

	return result;
    };

    /**
     * parse OCSPNoCheck OCSP extension as JSON object<br/>
     * @name getExtOcspNoCheck
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value
     * @param {Boolean} critical flag
     * @return {Array} JSON object of parsed OCSPNoCheck extension
     * @since jsrsasign 9.1.6 x509 2.0.3
     * @see KJUR.asn1.x509.OCSPNoCheck
     * @see X509#getExtParamArray
     * @see X509#getExtParam
     * @description
     * This method parses
     * OCSPNoCheck extension value defined in
     * <a href="https://tools.ietf.org/html/rfc6960#section-4.2.2.2.1">
     * RFC 6960 4.2.2.2.1</a> as JSON object.
     * <pre>
     * id-pkix-ocsp-nocheck OBJECT IDENTIFIER ::= { id-pkix-ocsp 5 }
     * </pre>
     * <br/>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.OCSPNoCheck} constructor.
     * @example
     * x = new X509();
     * x.getExtOcspNoCheck(<<extn hex value >>) &rarr;
     * { extname: "ocspNoCheck" }
     */
    this.getExtOcspNoCheck = function(hExtV, critical) {
	var result = {extname:"ocspNoCheck"};
	if (critical) result.critical = true;

	return result;
    };

    /**
     * parse AdobeTimeStamp extension as JSON object<br/>
     * @name getExtAdobeTimeStamp
     * @memberOf X509#
     * @function
     * @param {String} hExtV hexadecimal string of extension value
     * @param {Boolean} critical flag
     * @return {Array} JSON object of parsed AdobeTimeStamp extension
     * @since jsrsasign 10.0.1 x509 2.0.5
     * @see KJUR.asn1.x509.AdobeTimeStamp
     * @see X509#getExtParamArray
     * @see X509#getExtParam
     * @description
     * This method parses
     * X.509v3 AdobeTimeStamp private extension value defined in the
     * <a href="https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/oids.html">
     * Adobe site</a> as JSON object.
     * This extension provides the URL location for time stamp service.
     * <pre>
     * adbe- OBJECT IDENTIFIER ::=  { adbe(1.2.840.113583) acrobat(1) security(1) x509Ext(9) 1 }
     *  ::= SEQUENCE {
     *     version INTEGER  { v1(1) }, -- extension version
     *     location GeneralName (In v1 GeneralName can be only uniformResourceIdentifier)
     *     requiresAuth        boolean (default false), OPTIONAL }
     * </pre>
     * <br/>
     * Result of this method can be passed to 
     * {@link KJUR.asn1.x509.AdobeTimeStamp} constructor.
     * <br/>
     * NOTE: This extesion doesn't seem to have official name. This may be called as "pdfTimeStamp".
     * @example
     * x.getExtAdobeTimeStamp(<<extn hex value >>) &rarr;
     * { extname: "adobeTimeStamp", uri: "http://tsa.example.com/" reqauth: true }
     */
    this.getExtAdobeTimeStamp = function(hExtV, critical) {
	if (hExtV === undefined && critical === undefined) {
	    var info = this.getExtInfo("adobeTimeStamp");
	    if (info === undefined) return undefined;
	    hExtV = _getTLV(this.hex, info.vidx);
	    critical = info.critical;
	}

	var result = {extname:"adobeTimeStamp"};
	if (critical) result.critical = true;

	var a = _getChildIdx(hExtV, 0);
	if (a.length > 1) {
	    var hGN = _getTLV(hExtV, a[1])
	    var gnParam = this.getGeneralName(hGN);
	    if (gnParam.uri != undefined) {
		result.uri = gnParam.uri;
	    }
	}
	if (a.length > 2) {
	    var hBool = _getTLV(hExtV, a[2]);
	    if (hBool == "0101ff") result.reqauth = true;
	    if (hBool == "010100") result.reqauth = false;
	}

	return result;
    };

    // ===== BEGIN X500Name related =====================================
    /*
     * convert ASN.1 parsed object to attrTypeAndValue assoc array<br/>
     * @name _convATV
     * @param p associative array of parsed attrTypeAndValue object
     * @return attrTypeAndValue associative array
     * @since jsrsasign 10.5.12 x509 2.0.14
     * @example
     * _convATV({seq: [...]} &rarr: {type:"C",value:"JP",ds:"prn"}
     */
    var _convATV = function(p) {
	var result = {};
	try {
	    var name = p.seq[0].oid;
	    var oid = KJUR.asn1.x509.OID.name2oid(name);
	    result.type = KJUR.asn1.x509.OID.oid2atype(oid);
	    var item1 = p.seq[1];
	    if (item1.utf8str != undefined) {
		result.ds = "utf8";
		result.value = item1.utf8str.str;
	    } else if (item1.numstr != undefined) {
		result.ds = "num";
		result.value = item1.numstr.str;
	    } else if (item1.telstr != undefined) {
		result.ds = "tel";
		result.value = item1.telstr.str;
	    } else if (item1.prnstr != undefined) {
		result.ds = "prn";
		result.value = item1.prnstr.str;
	    } else if (item1.ia5str != undefined) {
		result.ds = "ia5";
		result.value = item1.ia5str.str;
	    } else if (item1.visstr != undefined) {
		result.ds = "vis";
		result.value = item1.visstr.str;
	    } else if (item1.bmpstr != undefined) {
		result.ds = "bmp";
		result.value = item1.bmpstr.str;
	    } else {
		throw "error";
	    }
	    return result;
	} catch(ex) {
	    throw new Erorr("improper ASN.1 parsed AttrTypeAndValue");
	}
    };

    /*
     * convert ASN.1 parsed object to RDN array<br/>
     * @name _convRDN
     * @param p associative array of parsed RDN object
     * @return RDN array
     * @since jsrsasign 10.5.12 x509 2.0.14
     * @example
     * _convRDN({set: [...]} &rarr: [{type:"C",value:"JP",ds:"prn"}]
     */
    var _convRDN = function(p) {
	try {
	    return p.set.map(function(pATV){return _convATV(pATV)});
	} catch(ex) {
	    throw new Error("improper ASN.1 parsed RDN: " + ex);
	}
    };

    /*
     * convert ASN.1 parsed object to X500Name array<br/>
     * @name _convX500Name
     * @param p associative array of parsed X500Name array object
     * @return RDN array
     * @since jsrsasign 10.5.12 x509 2.0.14
     * @example
     * _convX500Name({seq: [...]} &rarr: [[{type:"C",value:"JP",ds:"prn"}]]
     */
    var _convX500Name = function(p) {
	try {
	    return p.seq.map(function(pRDN){return _convRDN(pRDN)});
	} catch(ex) {
	    throw new Error("improper ASN.1 parsed X500Name: " + ex);
	}
    };

    this.getX500NameRule = function(aDN) {
	var isPRNRule = true;
	var isUTF8Rule = true;
	var isMixedRule = false;
	var logfull = "";
	var logcheck = "";
	var lasttag = null;

	var a = [];
	for (var i = 0; i < aDN.length; i++) {
	    var aRDN = aDN[i];
	    for (var j = 0; j < aRDN.length; j++) {
		a.push(aRDN[j]);
	    }
	}

	for (var i = 0; i < a.length; i++) {
	    var item = a[i];
	    var tag = item.ds;
	    var value = item.value;
	    var type = item.type;
	    logfull += ":" + tag;
	    
	    if (tag != "prn" && tag != "utf8" && tag != "ia5") {
		return "mixed";
	    }
	    if (tag == "ia5") {
		if (type != "CN") {
		    return "mixed";
		} else {
		    if (! KJUR.lang.String.isMail(value)) {
			return "mixed";
		    } else {
			continue;
		    }
		}
	    }
	    if (type == "C") {
		if (tag == "prn") {
		    continue;
		} else {
		    return "mixed";
		}
	    }
	    logcheck += ":" + tag;
	    if (lasttag == null) {
		lasttag = tag;
	    } else {
		if (lasttag !== tag) return "mixed";
	    }
	}
	if (lasttag == null) {
	    return "prn";
	} else {
	    return lasttag;
	}
    };

    /**
     * get AttributeTypeAndValue ASN.1 structure parameter as JSON object<br/>
     * @name getAttrTypeAndValue
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of AttributeTypeAndValue
     * @return {Object} JSON object of AttributeTypeAndValue parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getX500Name
     * @see X509#getRDN
     * @description
     * This method will get AttributeTypeAndValue parameters defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.1.2.4">
     * RFC 5280 4.1.2.4</a>.
     * <pre>
     * AttributeTypeAndValue ::= SEQUENCE {
     *   type     AttributeType,
     *   value    AttributeValue }
     * AttributeType ::= OBJECT IDENTIFIER
     * AttributeValue ::= ANY -- DEFINED BY AttributeType
     * </pre>
     * <ul>
     * <li>{String}type - AttributeType name or OID(ex. C,O,CN)</li>
     * <li>{String}value - raw string of ASN.1 value of AttributeValue</li>
     * <li>{String}ds - DirectoryString type of AttributeValue</li>
     * </ul>
     * "ds" has one of following value:
     * <ul>
     * <li>utf8 - (0x0c) UTF8String</li>
     * <li>num  - (0x12) NumericString</li>
     * <li>prn  - (0x13) PrintableString</li>
     * <li>tel  - (0x14) TeletexString</li>
     * <li>ia5  - (0x16) IA5String</li>
     * <li>vis  - (0x1a) VisibleString</li>
     * <li>bmp  - (0x1e) BMPString</li>
     * </ul>
     * @example
     * x = new X509();
     * x.getAttrTypeAndValue("30...") &rarr;
     * {type:"CN",value:"john.smith@example.com",ds:"ia5"} or
     * {type:"O",value:"Sample Corp.",ds:"prn"}
     */
    // unv  - (0x1c??) UniversalString ... for future
    this.getAttrTypeAndValue = function(h) {
	var p = _ASN1HEX_parse(h);
	return _convATV(p);
    };

    /**
     * get RelativeDistinguishedName ASN.1 structure parameter array<br/>
     * @name getRDN
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of RDN
     * @return {Array} array of AttrTypeAndValue parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getX500Name
     * @see X509#getRDN
     * @see X509#getAttrTypeAndValue
     * @description
     * This method will get RelativeDistinguishedName parameters defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.1.2.4">
     * RFC 5280 4.1.2.4</a>.
     * <pre>
     * RelativeDistinguishedName ::=
     *   SET SIZE (1..MAX) OF AttributeTypeAndValue
     * </pre>
     * @example
     * x = new X509();
     * x.getRDN("31...") &rarr;
     * [{type:"C",value:"US",ds:"prn"}] or
     * [{type:"O",value:"Sample Corp.",ds:"prn"}] or
     * [{type:"CN",value:"john.smith@example.com",ds:"ia5"}]
     */
    this.getRDN = function(h) {
	var p = _ASN1HEX_parse(h);
	return _convRDN(p);
    };

    /**
     * get X.500 Name ASN.1 structure parameter array<br/>
     * @name getX500NameArray
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of Name
     * @return {Array} array of RDN parameter array
     * @since jsrsasign 10.0.6 x509 2.0.9
     * @see X509#getX500Name
     * @see X509#getRDN
     * @see X509#getAttrTypeAndValue
     * @description
     * This method will get Name parameter defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.1.2.4">
     * RFC 5280 4.1.2.4</a>.
     * <pre>
     * Name ::= CHOICE { -- only one possibility for now --
     *   rdnSequence  RDNSequence }
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     * </pre>
     * @example
     * x = new X509();
     * x.getX500NameArray("30...") &rarr;
     * [[{type:"C",value:"US",ds:"prn"}],
     *  [{type:"O",value:"Sample Corp.",ds:"utf8"}],
     *  [{type:"CN",value:"john.smith@example.com",ds:"ia5"}]]
     */
    this.getX500NameArray = function(h) {
	var p = _ASN1HEX_parse(h);
	return _convX500Name(p);
    };

    /**
     * get Name ASN.1 structure parameter array<br/>
     * @name getX500Name
     * @memberOf X509#
     * @function
     * @param {String} h hexadecimal string of Name
     * @return {Array} array of RDN parameter array
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see X509#getX500NameArray
     * @see X509#getRDN
     * @see X509#getAttrTypeAndValue
     * @see KJUR.asn1.x509.X500Name
     * @see KJUR.asn1.x509.GeneralName
     * @see KJUR.asn1.x509.GeneralNames
     * @description
     * This method will get Name parameter defined in
     * <a href="https://tools.ietf.org/html/rfc5280#section-4.1.2.4">
     * RFC 5280 4.1.2.4</a>.
     * <pre>
     * Name ::= CHOICE { -- only one possibility for now --
     *   rdnSequence  RDNSequence }
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     * </pre>
     * @example
     * x = new X509();
     * x.getX500Name("30...") &rarr;
     * { array: [
     *     [{type:"C",value:"US",ds:"prn"}],
     *     [{type:"O",value:"Sample Corp.",ds:"utf8"}],
     *     [{type:"CN",value:"john.smith@example.com",ds:"ia5"}]
     *   ],
     *   str: "/C=US/O=Sample Corp./CN=john.smith@example.com",
     *   hex: "30..."
     * }
     */
    this.getX500Name = function(h) {
	var a = this.getX500NameArray(h);
	var s = this.dnarraytostr(a);
	return { array: a, str: s };
    };

    // ===== END X500Name related =====================================

    // ===== BEGIN read certificate =====================================
    /**
     * read PEM formatted X.509 certificate from string.<br/>
     * @name readCertPEM
     * @memberOf X509#
     * @function
     * @param {String} sCertPEM string for PEM formatted X.509 certificate
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // read certificate
     */
    this.readCertPEM = function(sCertPEM) {
        this.readCertHex(_pemtohex(sCertPEM));
    };

    /**
     * read a hexadecimal string of X.509 certificate<br/>
     * @name readCertHex
     * @memberOf X509#
     * @function
     * @param {String} sCertHex hexadecimal string of X.509 certificate
     * @since jsrsasign 7.1.4 x509 1.1.13
     * @description
     * NOTE: {@link X509#parseExt} will called internally since jsrsasign 7.2.0.
     * @example
     * x = new X509();
     * x.readCertHex("3082..."); // read certificate
     */
    this.readCertHex = function(sCertHex) {
        this.hex = sCertHex;
	this.getVersion(); // set version parameter

	try {
	    _getIdxbyList(this.hex, 0, [0, 7], "a3"); // has [3] v3ext
	    this.parseExt();
	} catch(ex) {};
    };

    // ===== END read certificate =====================================

    /**
     * get JSON object of certificate parameters<br/>
     * @name getParam
     * @memberOf X509#
     * @function
     * @param {Object} option optional setting for return object
     * @return {Object} JSON object of certificate parameters
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see KJUR.asn1.x509.X509Util.newCertPEM
     *
     * @description
     * This method returns a JSON object of the certificate
     * parameters. Return value can be passed to
     * {@link KJUR.asn1.x509.X509Util.newCertPEM}.
     * <br>
     * NOTE1: From jsrsasign 10.5.16, optional argument can be applied.
     * It can have following members:
     * <ul>
     * <li>tbshex - if this is true, tbshex member with hex value of
     * tbsCertificate will be added</li>
     * <li>nodnarray - if this is true, array member for subject and
     * issuer will be deleted to simplify it<li>
     * </ul>
     *
     * @example
     * x = new X509();
     * x.readCertPEM("-----BEGIN CERTIFICATE...");
     * x.getParam() &rarr;
     * {version:3,
     *  serial:{hex:"12ab"},
     *  sigalg:"SHA256withRSA",
     *  issuer: {array:[[{type:'CN',value:'CA1',ds:'prn'}]],str:"/O=CA1"},
     *  notbefore:"160403023700Z",
     *  notafter:"160702023700Z",
     *  subject: {array:[[{type:'CN',value:'Test1',ds:'prn'}]],str:"/CN=Test1"},
     *  sbjpubkey:"-----BEGIN PUBLIC KEY...",
     *  ext:[
     *   {extname:"keyUsage",critical:true,names:["digitalSignature"]},
     *   {extname:"basicConstraints",critical:true},
     *   {extname:"subjectKeyIdentifier",kid:{hex:"f2eb..."}},
     *   {extname:"authorityKeyIdentifier",kid:{hex:"12ab..."}},
     *   {extname:"authorityInfoAccess",array:[{ocsp:"http://ocsp.example.com/"}]},
     *   {extname:"certificatePolicies",array:[{policyoid:"2.23.140.1.2.1"}]}
     *  ],
     *  sighex:"0b76...8"
     * };
     *
     * x.getParam({tbshex: true}) &rarr; { ... , tbshex: "30..." }
     * x.getParam({nodnarray: true}) &rarr; {issuer: {str: "/C=JP"}, ...}
     */
    this.getParam = function(option) {
	var result = {};
	result.version = this.getVersion();
	result.serial = {hex: this.getSerialNumberHex()};
	result.sigalg = this.getSignatureAlgorithmField();
	result.issuer = this.getIssuer();
	result.notbefore = this.getNotBefore();
	result.notafter = this.getNotAfter();
	result.subject = this.getSubject();
	result.sbjpubkey = hextopem(this.getPublicKeyHex(), "PUBLIC KEY");
	if (this.aExtInfo != undefined &&
	    this.aExtInfo.length > 0) {
	    result.ext = this.getExtParamArray();
	}
	result.sighex = this.getSignatureValueHex();

	// for options
	if (typeof option == "object") {
	    if (option.tbshex == true) {
		result.tbshex = _getTLVbyList(this.hex, 0, [0]);
	    }
	    if (option.nodnarray == true) {
		delete result.issuer.array;
		delete result.subject.array;
	    }
	}
	return result;
    };

    /** 
     * get array of certificate extension parameter JSON object<br/>
     * @name getExtParamArray
     * @memberOf X509#
     * @function
     * @param {String} hExtSeq hexadecimal string of SEQUENCE of Extension
     * @return {Array} array of certificate extension parameter JSON object
     * @since jsrsasign 9.0.0 x509 2.0.0
     * @see KJUR.asn1.x509.X509Util.newCertPEM
     * @see X509#getParam
     * @see X509#getExtParam
     * @see X509CRL#getParam
     * @see KJUR.asn1.csr.CSRUtil.getParam
     *
     * @description
     * This method returns an array of certificate extension
     * parameters. 
     * <br/>
     * NOTE: Argument "hExtSeq" have been supported since jsrsasign 9.1.1.
     *
     * @example
     * x = new X509();
     * x.readCertPEM("-----BEGIN CERTIFICATE...");
     * x.getExtParamArray() &rarr;
     * [ {extname:"keyUsage",critical:true,names:["digitalSignature"]},
     *   {extname:"basicConstraints",critical:true},
     *   {extname:"subjectKeyIdentifier",kid:{hex:"f2eb..."}},
     *   {extname:"authorityKeyIdentifier",kid:{hex:"12ab..."}},
     *   {extname:"authorityInfoAccess",array:[{ocsp:"http://ocsp.example.com/"}]},
     *   {extname:"certificatePolicies",array:[{policyoid:"2.23.140.1.2.1"}]}]
     */
    this.getExtParamArray = function(hExtSeq) {
	if (hExtSeq == undefined) {
	    // for X.509v3 certificate
	    var idx1 = _getIdxbyListEx(this.hex, 0, [0, "[3]"]);
	    if (idx1 != -1) {
		hExtSeq = _getTLVbyListEx(this.hex, 0, [0, "[3]", 0], "30");
	    }
	}
	var result = [];
	var aIdx = _getChildIdx(hExtSeq, 0);

	for (var i = 0; i < aIdx.length; i++) {
	    var hExt = _getTLV(hExtSeq, aIdx[i]);
	    var extParam = this.getExtParam(hExt);
	    if (extParam != null) result.push(extParam);
	}

	return result;
    };

    /** 
     * get a extension parameter JSON object<br/>
     * @name getExtParam
     * @memberOf X509#
     * @function
     * @param {String} hExt hexadecimal string of Extension
     * @return {Array} Extension parameter JSON object
     * @since jsrsasign 9.1.1 x509 2.0.1
     * @see KJUR.asn1.x509.X509Util.newCertPEM
     * @see X509#getParam
     * @see X509#getExtParamArray
     * @see X509CRL#getParam
     * @see KJUR.asn1.csr.CSRUtil.getParam
     *
     * @description
     * This method returns a extension parameters as JSON object. 
     *
     * @example
     * x = new X509();
     * ...
     * x.getExtParam("30...") &rarr;
     * {extname:"keyUsage",critical:true,names:["digitalSignature"]}
     */
    this.getExtParam = function(hExt) {
	var result = {};
	var aIdx = _getChildIdx(hExt, 0);
	var aIdxLen = aIdx.length;
	if (aIdxLen != 2 && aIdxLen != 3)
	    throw new Error("wrong number elements in Extension: " + 
			    aIdxLen + " " + hExt);

	var oid = _hextooidstr(_getVbyList(hExt, 0, [0], "06"));

	var critical = false;
	if (aIdxLen == 3 && _getTLVbyList(hExt, 0, [1]) == "0101ff")
	    critical = true;

	var hExtV = _getTLVbyList(hExt, 0, [aIdxLen - 1, 0]);

	var extParam = undefined;
	if (oid == "2.5.29.14") {
	    extParam = this.getExtSubjectKeyIdentifier(hExtV, critical);
	} else if (oid == "2.5.29.15") {
	    extParam = this.getExtKeyUsage(hExtV, critical);
	} else if (oid == "2.5.29.17") {
	    extParam = this.getExtSubjectAltName(hExtV, critical);
	} else if (oid == "2.5.29.18") {
	    extParam = this.getExtIssuerAltName(hExtV, critical);
	} else if (oid == "2.5.29.19") {
	    extParam = this.getExtBasicConstraints(hExtV, critical);
	} else if (oid == "2.5.29.30") {
	    extParam = this.getExtNameConstraints(hExtV, critical);
	} else if (oid == "2.5.29.31") {
	    extParam = this.getExtCRLDistributionPoints(hExtV, critical);
	} else if (oid == "2.5.29.32") {
	    extParam = this.getExtCertificatePolicies(hExtV, critical);
	} else if (oid == "2.5.29.35") {
	    extParam = this.getExtAuthorityKeyIdentifier(hExtV, critical);
	} else if (oid == "2.5.29.37") {
	    extParam = this.getExtExtKeyUsage(hExtV, critical);
	} else if (oid == "1.3.6.1.5.5.7.1.1") {
	    extParam = this.getExtAuthorityInfoAccess(hExtV, critical);
	} else if (oid == "2.5.29.20") {
	    extParam = this.getExtCRLNumber(hExtV, critical);
	} else if (oid == "2.5.29.21") {
	    extParam = this.getExtCRLReason(hExtV, critical);
	} else if (oid == "1.3.6.1.5.5.7.48.1.2") {
	    extParam = this.getExtOcspNonce(hExtV, critical);
	} else if (oid == "1.3.6.1.5.5.7.48.1.5") {
	    extParam = this.getExtOcspNoCheck(hExtV, critical);
	} else if (oid == "1.2.840.113583.1.1.9.1") {
	    extParam = this.getExtAdobeTimeStamp(hExtV, critical);
	}
	if (extParam != undefined) return extParam;

	var privateParam = { extname: oid, extn: hExtV };
	if (critical) privateParam.critical = true;
	return privateParam;
    };

    /**
     * find extension parameter in array<br/>
     * @name findExt
     * @memberOf X509#
     * @function
     * @param {Array} aExt array of extension parameters
     * @param {String} extname extension name
     * @return {Array} extension parameter in the array or null
     * @since jsrsasign 10.0.3 x509 2.0.7
     * @see X509#getParam
     *
     * @description
     * This method returns an extension parameter for
     * specified extension name in the array.
     * This method is useful to update extension parameter value.
     * When there is no such extension with the extname,
     * this returns "null".
     *
     * @example
     * // (1) 
     * x = new X509(CERTPEM);
     * params = x.getParam();
     * pSKID = x.findExt(params.ext, "subjectKeyIdentifier");
     * pSKID.kid = "1234abced..."; // skid in the params is updated.
     *   // then params was updated
     *
     * // (2) another example
     * aExt = [
     *   {extname:"keyUsage",critical:true,names:["digitalSignature"]},
     *   {extname:"basicConstraints",critical:true},
     *   {extname:"subjectKeyIdentifier",kid:{hex:"f2eb..."}},
     *   {extname:"authorityKeyIdentifier",kid:{hex:"12ab..."}},
     *   {extname:"authorityInfoAccess",array:[{ocsp:"http://ocsp.example.com/"}]},
     *   {extname:"certificatePolicies",array:[{policyoid:"2.23.140.1.2.1"}]}
     * ];
     * var x = new X509();
     * x.findExt(aExt, "authorityKeyInfoAccess").array[0].ocsp = "http://aaa.com";
     * pKU = x.findExt(aExt, "keyUsage");
     * delete pKU["critical"]; // clear criticla flag
     * pKU.names = ["keyCertSign", "cRLSign"];
     *   // then aExt was updated
     */
    this.findExt = function(aExt, extname) {
	for (var i = 0; i < aExt.length; i++) {
	    if (aExt[i].extname == extname) return aExt[i];
	}
	return null;

    };

    /**
     * update CRLDistributionPoints Full URI in parameter<br/>
     * @name updateCDPFullURI
     * @memberOf X509#
     * @function
     * @param {Array} aExt array of extension parameters
     * @param {String} newURI string of new uri
     * @since jsrsasign 10.0.4 x509 2.0.8
     * @see X509#findExt
     * @see KJUR.asn1.x509.CRLDistributionPoints
     *
     * @description
     * This method updates Full URI of CRLDistributionPoints extension
     * in the extension parameter array if it exists.
     *
     * @example
     * aExt = [
     *   {extname:"authorityKeyIdentifier",kid:{hex:"12ab..."}},
     *   {extname:"cRLDistributionPoints",
     *    array:[{dpname:{full:[{uri:"http://example.com/a.crl"}]}}]},
     * ];
     * x = new X509();
     * x.updateCDPFullURI(aExt, "http://crl2.example.new/b.crl");
     */
    this.updateExtCDPFullURI = function(aExt, newURI) {
	var pExt = this.findExt(aExt, "cRLDistributionPoints");
	if (pExt == null) return;
	if (pExt.array == undefined) return;
	var aDP = pExt.array;
	for (var i = 0; i < aDP.length; i++) {
	    if (aDP[i].dpname == undefined) continue;
	    if (aDP[i].dpname.full == undefined) continue;
	    var aURI = aDP[i].dpname.full;
	    for (var j = 0; j < aURI.length; j++) {
		var pURI = aURI[i];
		if (pURI.uri == undefined) continue;
		pURI.uri = newURI;
	    }
	}
    };

    /**
     * update authorityInfoAccess ocsp in parameter<br/>
     * @name updateAIAOCSP
     * @memberOf X509#
     * @function
     * @param {Array} aExt array of extension parameters
     * @param {String} newURI string of new uri
     * @since jsrsasign 10.0.4 x509 2.0.8
     * @see X509#findExt
     * @see KJUR.asn1.x509.AuthorityInfoAccess
     *
     * @description
     * This method updates "ocsp" accessMethod URI of 
     * AuthorityInfoAccess extension
     * in the extension parameter array if it exists.
     *
     * @example
     * aExt = [
     *   {extname:"authorityKeyIdentifier",kid:{hex:"12ab..."}},
     *   {extname:"authoriyInfoAccess",
     *    array:[
     *      {ocsp: "http://ocsp1.example.com"},
     *      {caissuer: "http://example.com/a.crt"}
     *    ]}
     * ];
     * x = new X509();
     * x.updateAIAOCSP(aExt, "http://ocsp2.example.net");
     */
    this.updateExtAIAOCSP = function(aExt, newURI) {
	var pExt = this.findExt(aExt, "authorityInfoAccess");
	if (pExt == null) return;
	if (pExt.array == undefined) return;
	var a = pExt.array;
	for (var i = 0; i < a.length; i++) {
	    if (a[i].ocsp != undefined) a[i].ocsp = newURI;
	}
    };

    /**
     * update authorityInfoAccess caIssuer in parameter<br/>
     * @name updateAIACAIssuer
     * @memberOf X509#
     * @function
     * @param {Array} aExt array of extension parameters
     * @param {String} newURI string of new uri
     * @since jsrsasign 10.0.4 x509 2.0.8
     * @see X509#findExt
     * @see KJUR.asn1.x509.AuthorityInfoAccess
     *
     * @description
     * This method updates "caIssuer" accessMethod URI of 
     * AuthorityInfoAccess extension
     * in the extension parameter array if it exists.
     *
     * @example
     * aExt = [
     *   {extname:"authorityKeyIdentifier",kid:{hex:"12ab..."}},
     *   {extname:"authoriyInfoAccess",
     *    array:[
     *      {ocsp: "http://ocsp1.example.com"},
     *      {caissuer: "http://example.com/a.crt"}
     *    ]}
     * ];
     * x = new X509();
     * x.updateAIACAIssuer(aExt, "http://example.net/b.crt");
     */
    this.updateExtAIACAIssuer = function(aExt, newURI) {
	var pExt = this.findExt(aExt, "authorityInfoAccess");
	if (pExt == null) return;
	if (pExt.array == undefined) return;
	var a = pExt.array;
	for (var i = 0; i < a.length; i++) {
	    if (a[i].caissuer != undefined) a[i].caissuer = newURI;
	}
    };

    /**
     * convert array for X500 distinguish name to distinguish name string<br/>
     * @name dnarraytostr
     * @memberOf X509#
     * @function
     * @param {Array} aDN array for X500 distinguish name
     * @return {String} distinguish name
     * @since jsrsasign 10.0.6 x509 2.0.8
     * @see X509#getX500Name
     * @see X509#getX500NameArray
     * @see KJUR.asn1.x509.X500Name
     *
     * @description
     * This method converts from an array representation of 
     * X.500 distinguished name to X.500 name string.
     * This supports multi-valued RDN.
     * 
     * @example
     * var x = new X509();
     * x.dnarraytostr(
     *   [[{type:"C",value:"JP",ds:"prn"}],
     *   [{type:"O",value:"T1",ds:"prn"}]]) &rarr; "/C=JP/O=T1"
     * x.dnarraytostr(
     *   [[{type:"C",value:"JP",ds:"prn"}],
     *   [{type:"O",value:"T1",ds:"prn"}
     *    {type:"CN",value:"Bob",ds:"prn"}]]) &rarr; "/C=JP/O=T1+CN=Bob"
     */
    this.dnarraytostr = function(aDN) {
	function rdnarraytostr(aRDN) {
	    return aRDN.map(function(x){return atvtostr(x).replace(/\+/,"\\+");}).join("+");
	};

	function atvtostr(pATV) {
	    return pATV.type + "=" + pATV.value;
	};

	return "/" + aDN.map(function(x){return rdnarraytostr(x).replace(/\//, "\\/");}).join("/");
    };

    /**
     * get certificate information as string.<br/>
     * @name getInfo
     * @memberOf X509#
     * @function
     * @return {String} certificate information string
     * @since jsrsasign 5.0.10 x509 1.1.8
     * @example
     * x = new X509();
     * x.readCertPEM(certPEM);
     * console.log(x.getInfo());
     * // this shows as following
     * Basic Fields
     *   serial number: 02ac5c266a0b409b8f0b79f2ae462577
     *   signature algorithm: SHA1withRSA
     *   issuer: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
     *   notBefore: 061110000000Z
     *   notAfter: 311110000000Z
     *   subject: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
     *   subject public key info:
     *     key algorithm: RSA
     *     n=c6cce573e6fbd4bb...
     *     e=10001
     * X509v3 Extensions:
     *   keyUsage CRITICAL:
     *     digitalSignature,keyCertSign,cRLSign
     *   basicConstraints CRITICAL:
     *     cA=true
     *   subjectKeyIdentifier :
     *     b13ec36903f8bf4701d498261a0802ef63642bc3
     *   authorityKeyIdentifier :
     *     kid=b13ec36903f8bf4701d498261a0802ef63642bc3
     * signature algorithm: SHA1withRSA
     * signature: 1c1a0697dcd79c9f...
     */
    this.getInfo = function() {
	var _getSubjectAltNameStr = function(params) {
	    var s = JSON.stringify(params.array).replace(/[\[\]\{\}\"]/g, '');
	    return s;
	};
	var _getCertificatePoliciesStr = function(params) {
	    var s = "";
	    var a = params.array;
	    for (var i = 0; i < a.length; i++) {
		var pi = a[i];
		s += "    policy oid: " + pi.policyoid + "\n";
		if (pi.array === undefined) continue;
		for (var j = 0; j < pi.array.length; j++) {
		    var pqi = pi.array[j];
		    if (pqi.cps !== undefined) {
			s += "    cps: " + pqi.cps + "\n";
		    }
		}
	    }
	    return s;
	};
	var _getCRLDistributionPointsStr = function(params) {
	    var s = "";
	    var a = params.array;
	    for (var i = 0; i < a.length; i++) {
		var dp = a[i];
		try {
		    if (dp.dpname.full[0].uri !== undefined)
			s += "    " + dp.dpname.full[0].uri + "\n";
		} catch(ex) {};
		try {
		    if (dp.dname.full[0].dn.hex !== undefined)
			s += "    " + X509.hex2dn(dp.dpname.full[0].dn.hex) + "\n";
		} catch(ex) {};
	    }
	    return s;
	}
	var _getAuthorityInfoAccessStr = function(params) {
	    var s = "";
	    var a = params.array;
	    for (var i = 0; i < a.length; i++) {
		var ad = a[i];

		if (ad.caissuer !== undefined)
		    s += "    caissuer: " + ad.caissuer + "\n";
		if (ad.ocsp !== undefined)
		    s += "    ocsp: " + ad.ocsp + "\n";
	    }
	    return s;
	};
	var _X509 = X509;
	var s, pubkey, aExt;
	s  = "Basic Fields\n";
        s += "  serial number: " + this.getSerialNumberHex() + "\n";
	s += "  signature algorithm: " + this.getSignatureAlgorithmField() + "\n";
	s += "  issuer: " + this.getIssuerString() + "\n";
	s += "  notBefore: " + this.getNotBefore() + "\n";
	s += "  notAfter: " + this.getNotAfter() + "\n";
	s += "  subject: " + this.getSubjectString() + "\n";
	s += "  subject public key info: " + "\n";

	// subject public key info
	pubkey = this.getPublicKey();
	s += "    key algorithm: " + pubkey.type + "\n";

	if (pubkey.type === "RSA") {
	    s += "    n=" + hextoposhex(pubkey.n.toString(16)).substr(0, 16) + "...\n";
	    s += "    e=" + hextoposhex(pubkey.e.toString(16)) + "\n";
	}

	// X.509v3 Extensions
        aExt = this.aExtInfo;

	if (aExt !== undefined && aExt !== null) {
            s += "X509v3 Extensions:\n";
	    
            for (var i = 0; i < aExt.length; i++) {
		var info = aExt[i];

		// show extension name and critical flag
		var extName = KJUR.asn1.x509.OID.oid2name(info["oid"]);
		if (extName === '') extName = info["oid"];

		var critical = '';
		if (info["critical"] === true) critical = "CRITICAL";

		s += "  " + extName + " " + critical + ":\n";

		// show extension value if supported
		if (extName === "basicConstraints") {
		    var bc = this.getExtBasicConstraints();
		    if (bc.cA === undefined) {
			s += "    {}\n";
		    } else {
			s += "    cA=true";
			if (bc.pathLen !== undefined)
			    s += ", pathLen=" + bc.pathLen;
			s += "\n";
		    }
		} else if (extName === "keyUsage") {
		    s += "    " + this.getExtKeyUsageString() + "\n";
		} else if (extName === "subjectKeyIdentifier") {
		    s += "    " + this.getExtSubjectKeyIdentifier().kid.hex + "\n";
		} else if (extName === "authorityKeyIdentifier") {
		    var akid = this.getExtAuthorityKeyIdentifier();
		    if (akid.kid !== undefined)
			s += "    kid=" + akid.kid.hex + "\n";
		} else if (extName === "extKeyUsage") {
		    var eku = this.getExtExtKeyUsage().array;
		    s += "    " + eku.join(", ") + "\n";
		} else if (extName === "subjectAltName") {
		    var san = _getSubjectAltNameStr(this.getExtSubjectAltName());
		    s += "    " + san + "\n";
		} else if (extName === "cRLDistributionPoints") {
		    var cdp = this.getExtCRLDistributionPoints();
		    s += _getCRLDistributionPointsStr(cdp);
		} else if (extName === "authorityInfoAccess") {
		    var aia = this.getExtAuthorityInfoAccess();
		    s += _getAuthorityInfoAccessStr(aia);
		} else if (extName === "certificatePolicies") {
		    s += _getCertificatePoliciesStr(this.getExtCertificatePolicies());
		}
	    }
        }

	s += "signature algorithm: " + this.getSignatureAlgorithmName() + "\n";
	s += "signature: " + this.getSignatureValueHex().substr(0, 16) + "...\n";
	return s;
    };

    if (typeof params == "string") {
	if (params.indexOf("-----BEGIN") != -1) {
	    this.readCertPEM(params);
	} else if (KJUR.lang.String.isHex(params)) {
	    this.readCertHex(params);
	}
    }
};
// ----- END of X509 class -----

/**
 * get distinguished name string in OpenSSL online format from hexadecimal string of ASN.1 DER X.500 name<br/>
 * @name hex2dn
 * @memberOf X509
 * @function
 * @param {String} hex hexadecimal string of ASN.1 DER distinguished name
 * @param {Integer} idx index of hexadecimal string (DEFAULT=0)
 * @return {String} OpenSSL online format distinguished name
 * @description
 * This static method converts from a hexadecimal string of 
 * distinguished name (DN)
 * specified by 'hex' and 'idx' to OpenSSL oneline string representation (ex. /C=US/O=a).
 * @example
 * X509.hex2dn("3031310b3...") &rarr; /C=US/O=a/CN=b2+OU=b1
 */
X509.hex2dn = function(hex, idx) {
    if (idx === undefined) idx = 0;
    var x = new X509();
    var hDN = ASN1HEX.getTLV(hex, idx);
    var pDN = x.getX500Name(hex);
    return pDN.str;
};

/**
 * get relative distinguished name string in OpenSSL online format from hexadecimal string of ASN.1 DER RDN<br/>
 * @name hex2rdn
 * @memberOf X509
 * @function
 * @param {String} hex hexadecimal string of ASN.1 DER concludes relative distinguished name
 * @param {Integer} idx index of hexadecimal string (DEFAULT=0)
 * @return {String} OpenSSL online format relative distinguished name
 * @description
 * This static method converts from a hexadecimal string of 
 * relative distinguished name (RDN)
 * specified by 'hex' and 'idx' to LDAP string representation (ex. O=test+CN=test).<br/>
 * NOTE: Multi-valued RDN is supported since jsnrsasign 6.2.2 x509 1.1.10.
 * @example
 * X509.hex2rdn("310a3008060355040a0c0161") &rarr; O=a
 * X509.hex2rdn("31143008060355040a0c01613008060355040a0c0162") &rarr; O=a+O=b
 */
X509.hex2rdn = function(hex, idx) {
    if (idx === undefined) idx = 0;
    if (hex.substr(idx, 2) !== "31") throw new Error("malformed RDN");

    var a = new Array();

    var aIdx = ASN1HEX.getChildIdx(hex, idx);
    for (var i = 0; i < aIdx.length; i++) {
	a.push(X509.hex2attrTypeValue(hex, aIdx[i]));
    }

    a = a.map(function(s) { return s.replace("+", "\\+"); });
    return a.join("+");
};

/**
 * get string from hexadecimal string of ASN.1 DER AttributeTypeAndValue<br/>
 * @name hex2attrTypeValue
 * @memberOf X509
 * @function
 * @param {String} hex hexadecimal string of ASN.1 DER concludes AttributeTypeAndValue
 * @param {Integer} idx index of hexadecimal string (DEFAULT=0)
 * @return {String} string representation of AttributeTypeAndValue (ex. C=US)
 * @description
 * This static method converts from a hexadecimal string of AttributeTypeAndValue
 * specified by 'hex' and 'idx' to LDAP string representation (ex. C=US).
 * @example
 * X509.hex2attrTypeValue("3008060355040a0c0161") &rarr; O=a
 * X509.hex2attrTypeValue("300806035504060c0161") &rarr; C=a
 * X509.hex2attrTypeValue("...3008060355040a0c0161...", 128) &rarr; O=a
 */
X509.hex2attrTypeValue = function(hex, idx) {
    var _ASN1HEX = ASN1HEX;
    var _getV = _ASN1HEX.getV;

    if (idx === undefined) idx = 0;
    if (hex.substr(idx, 2) !== "30") 
	throw new Error("malformed attribute type and value");

    var aIdx = _ASN1HEX.getChildIdx(hex, idx);
    if (aIdx.length !== 2 || hex.substr(aIdx[0], 2) !== "06")
	"malformed attribute type and value";

    var oidHex = _getV(hex, aIdx[0]);
    var oidInt = KJUR.asn1.ASN1Util.oidHexToInt(oidHex);
    var atype = KJUR.asn1.x509.OID.oid2atype(oidInt);

    var hV = _getV(hex, aIdx[1]);
    var rawV = hextorstr(hV);

    return atype + "=" + rawV;
};

/**
 * get RSA/DSA/ECDSA public key object from X.509 certificate hexadecimal string<br/>
 * @name getPublicKeyFromCertHex
 * @memberOf X509
 * @function
 * @param {String} h hexadecimal string of X.509 certificate for RSA/ECDSA/DSA public key
 * @return returns RSAKey/KJUR.crypto.{ECDSA,DSA} object of public key
 * @since jsrasign 7.1.0 x509 1.1.11
 */
X509.getPublicKeyFromCertHex = function(h) {
    var x = new X509();
    x.readCertHex(h);
    return x.getPublicKey();
};

/**
 * get RSA/DSA/ECDSA public key object from PEM certificate string
 * @name getPublicKeyFromCertPEM
 * @memberOf X509
 * @function
 * @param {String} sCertPEM PEM formatted RSA/ECDSA/DSA X.509 certificate
 * @return returns RSAKey/KJUR.crypto.{ECDSA,DSA} object of public key
 * @since x509 1.1.1
 * @description
 * NOTE: DSA is also supported since x509 1.1.2.
 */
X509.getPublicKeyFromCertPEM = function(sCertPEM) {
    var x = new X509();
    x.readCertPEM(sCertPEM);
    return x.getPublicKey();
};

/**
 * get public key information from PEM certificate
 * @name getPublicKeyInfoPropOfCertPEM
 * @memberOf X509
 * @function
 * @param {String} sCertPEM string of PEM formatted certificate
 * @return {Hash} hash of information for public key
 * @since x509 1.1.1
 * @description
 * Resulted associative array has following properties:<br/>
 * <ul>
 * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
 * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
 * <li>keyhex - hexadecimal string of key in the certificate</li>
 * </ul>
 * NOTE: X509v1 certificate is also supported since x509.js 1.1.9.
 */
X509.getPublicKeyInfoPropOfCertPEM = function(sCertPEM) {
    var _ASN1HEX = ASN1HEX;
    var _getVbyList = _ASN1HEX.getVbyList;

    var result = {};
    var x, hSPKI, pubkey;
    result.algparam = null;

    x = new X509();
    x.readCertPEM(sCertPEM);

    hSPKI = x.getPublicKeyHex();
    result.keyhex = _getVbyList(hSPKI, 0, [1], "03").substr(2);
    result.algoid = _getVbyList(hSPKI, 0, [0, 0], "06");

    if (result.algoid === "2a8648ce3d0201") { // ecPublicKey
	result.algparam = _getVbyList(hSPKI, 0, [0, 1], "06");
    };

    return result;
};

/* ======================================================================
 *   Specific V3 Extensions
 * ====================================================================== */

X509.KEYUSAGE_NAME = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly"
];
