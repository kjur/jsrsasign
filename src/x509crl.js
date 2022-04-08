/* x509crl.js (c) 2012-2022 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * x509crl.js - X509CRL class to parse X.509 CRL
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
 * @name x509crl.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.16 x509crl 1.0.5 (2022-Apr-08)
 * @since jsrsasign 10.1.0
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * hexadecimal X.509 CRL ASN.1 parser class.<br/>
 * @class hexadecimal X.509 CRL ASN.1 parser class
 * @param {String} params X.509 CRL PEM string or hexadecimal string
 * @property {String} hex hexadecimal string of X.509 CRL ASN.1 data
 * @property {Integer} posSigAlg index of SignatureAlgorithm field in TBSCertList position depends on CRL version field
 * @property {Integer} posRevCert index of revokedCertificates field in TBSCertList depends on CRL version and nextUpdate field
 * @author Kenji Urushima
 * @version 1.0.0 (2020-Aug-26)
 * @see X509
 * @see <a href="https://kjur.github.io/jsrsasigns/">jsrsasign home page https://kjur.github.io/jsrsasign/</a>
 *
 * @description
 * This class parses X.509 CRL. Following methods are provided to
 * get field value:<br/>
 * <b>BASIC FIELD</b><br/>
 * <ul>
 * <li>version - {@link X509CRL#getVersion}</li>
 * <li>signatureAlgorithm - {@link X509CRL#getSignatureAlgorithmField}</li>
 * <li>issuer - {@link X509CRL#getIssuer}</li>
 * <li>issuer - {@link X509CRL#getIssuerHex}</li>
 * <li>thisUpdate - {@link X509CRL#getThisUpdate}</li>
 * <li>nextUpdate - {@link X509CRL#getNextUpdate}</li>
 * <li>revokedCertificates - {@link X509CRL#getRevCertArray}</li>
 * <li>revokedCertificate - {@link X509CRL#getRevCert}</li>
 * <li>signature - {@link X509CRL#getSignatureValueHex}</li>
 * </ul>
 * <b>UTILITIES</b><br/>
 * <ul>
 * <li>{@link X509CRL#getParam} - get all parameters</li>
 * </ul>
 *
 * @example
 * // constructor
 * crl = new X509CRL("-----BEGIN X509 CRL...");
 * crl = new X509CRL("3082...");
 */
var X509CRL = function(params) {
    var _KJUR = KJUR,
	_isHex = _KJUR.lang.String.isHex,
	_ASN1HEX = ASN1HEX,
	_getV = _ASN1HEX.getV,
	_getTLV = _ASN1HEX.getTLV,
	_getVbyList = _ASN1HEX.getVbyList,
	_getTLVbyList = _ASN1HEX.getTLVbyList,
	_getTLVbyListEx = _ASN1HEX.getTLVbyListEx,
	_getIdxbyList = _ASN1HEX.getIdxbyList,
	_getIdxbyListEx = _ASN1HEX.getIdxbyListEx,
	_getChildIdx = _ASN1HEX.getChildIdx,
	_x509obj = new X509();
    
    this.hex = null;
    this.posSigAlg = null;
    this.posRevCert = null;
    this.parsed = null;

    /*
     * set field position of SignatureAlgorithm and revokedCertificates<br/>
     * @description
     * This method will set "posSigAlg" and "posRevCert" properties.
     */
    this._setPos = function() {
	// for sigAlg
	var idx = _getIdxbyList(this.hex, 0, [0, 0]);
	var tag = this.hex.substr(idx, 2);
	if (tag == "02") {
	    this.posSigAlg = 1;
	} else if (tag == "30") {
	    this.posSigAlg = 0;
	} else {
	    throw new Error("malformed 1st item of TBSCertList: " + tag);
	}

	// for revCerts
	var idx2 = _getIdxbyList(this.hex, 0, [0, this.posSigAlg + 3]);
	var tag2 = this.hex.substr(idx2, 2);
	if (tag2 == "17" || tag2 == "18") {
	    var idx3, tag3;
	    idx3 = _getIdxbyList(this.hex, 0, [0, this.posSigAlg + 4]);
	    this.posRevCert = null;
	    if (idx3 != -1) {
		tag3 = this.hex.substr(idx3, 2);
		if (tag3 == "30") {
		    this.posRevCert = this.posSigAlg + 4;
		}
	    }
	} else if (tag2 == "30") { // found revCert
	    this.posRevCert = this.posSigAlg + 3;
	} else if (tag2 == "a0") { // no nextUpdate and revCert
	    this.posRevCert = null;
	} else {
	    throw new Error("malformed nextUpdate or revCert tag: " + tag2);
	}
    };

    /**
     * get X.509 CRL format version<br/>
     * @name getVersion
     * @memberOf X509CRL#
     * @function
     * @return {Number} version field value (generally 2) or null
     * @description
     * This method returns a version field value TBSCertList.
     * This returns null if there is no such field.
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * crl.getVersion() &rarr; 2
     */
    this.getVersion = function() {
	if (this.posSigAlg == 0) return null;
	return parseInt(_getVbyList(this.hex, 0, [0, 0], "02"), 16) + 1;
    }

    /**
     * get signature algorithm name in basic field
     * @name getSignatureAlgorithmField
     * @memberOf X509CRL#
     * @function
     * @return {String} signature algorithm name (ex. SHA1withRSA, SHA256withECDSA, SHA512withRSAandMGF1)
     * @see X509#getSignatureAlgorithmField
     * @see KJUR.asn1.x509.AlgirithmIdentifier
     * 
     * @description
     * This method will get a name of signature algorithm in CRL.
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * crl.getSignatureAlgorithmField() &rarr; "SHA256withRSAandMGF1"
     */
    this.getSignatureAlgorithmField = function() {
	var hTLV = _getTLVbyList(this.hex, 0, [0, this.posSigAlg], "30");
	return _x509obj.getAlgorithmIdentifierName(hTLV);
    };

    /**
     * get JSON object of issuer field<br/>
     * @name getIssuer
     * @memberOf X509CRL#
     * @function
     * @return {Array} JSON object of issuer field
     * @see X509#getIssuer
     * @see X509#getX500Name
     * @see KJUR.asn1.x509.X500Name
     *
     * @description
     * This method returns parsed issuer field value as
     * JSON object.
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * x.getIssuer() &rarr;
     * { array: [[{type:'C',value:'JP',ds:'prn'}],...],
     *   str: "/C=JP/..." }
     */
    this.getIssuer = function() {
	return _x509obj.getX500Name(this.getIssuerHex());
    };

    /**
     * get hexadecimal string of issuer field TLV of certificate.<br/>
     * @name getIssuerHex
     * @memberOf X509CRL#
     * @function
     * @return {string} hexadecial string of issuer DN ASN.1
     * @see X509CRL#getIssuer
     * @since jsrsasign 10.5.5 x509crl 1.0.3
     *
     * @description
     * This method returns ASN.1 DER hexadecimal string of
     * issuer field.
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * x.getIssuerHex() &rarr; "30..."
     */
    this.getIssuerHex = function() {
	return _getTLVbyList(this.hex, 0, [0, this.posSigAlg + 1], "30");
    };

    /**
     * get JSON object of thisUpdate field<br/>
     * @name getThisUpdate
     * @memberOf X509CRL#
     * @function
     * @return {String} string of thisUpdate field (ex. "YYMMDDHHmmSSZ")
     * @see X509#getNotBefore
     * @see X509CRL#getNextUpdate
     * @see KJUR.asn1.x509.Time
     *
     * @description
     * This method returns parsed thisUpdate field value as
     * string.
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * x.getThisUpdate() &rarr; "200825235959Z"
     */
    this.getThisUpdate = function() {
	var hThisUpdate = _getVbyList(this.hex, 0, [0, this.posSigAlg + 2]);
	return result = hextorstr(hThisUpdate);
    };

    /**
     * get JSON object of nextUpdate field<br/>
     * @name getNextUpdate
     * @memberOf X509CRL#
     * @function
     * @return {String} string of nextUpdate field or null
     * @see X509#getNotBefore
     * @see X509CRL#getThisUpdate
     * @see KJUR.asn1.x509.Time
     *
     * @description
     * This method returns parsed nextUpdate field value as
     * string. "nextUpdate" is OPTIONAL field so 
     * when nextUpdate field doesn't exists, this returns null.
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * crl.getNextUpdate() &rarr; "200825235959Z"
     */
    this.getNextUpdate = function() {
	var idx = _getIdxbyList(this.hex, 0, [0, this.posSigAlg + 3]);
	var tag = this.hex.substr(idx, 2);
	if (tag != "17" && tag != "18") return null;
	return hextorstr(_getV(this.hex, idx));
    };

    /**
     * get array for revokedCertificates field<br/>
     * @name getRevCertArray
     * @memberOf X509CRL#
     * @function
     * @return {Array} array of revokedCertificate parameter or null
     * @see X509CRL#getRevCert
     *
     * @description
     * This method returns parsed revokedCertificates field value as
     * array of revokedCertificate parameter.
     * If the field doesn't exists, it returns null.
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * crl.getRevCertArray() &rarr;
     * [{sn:"123a", date:"208025235959Z", ext: [{extname:"cRLReason",code:3}]},
     *  {sn:"123b", date:"208026235959Z", ext: [{extname:"cRLReason",code:0}]}]
     */
    this.getRevCertArray = function() {
	if (this.posRevCert == null) return null;
	var a = [];
	var idx = _getIdxbyList(this.hex, 0, [0, this.posRevCert]);
	var aIdx = _getChildIdx(this.hex, idx);
	for (var i = 0; i < aIdx.length; i++) {
	    var hRevCert = _getTLV(this.hex, aIdx[i]);
	    a.push(this.getRevCert(hRevCert));
	}
	return a;
    };

    /**
     * get revokedCertificate JSON parameter<br/>
     * @name getRevCert
     * @memberOf X509CRL#
     * @function
     * @return {Array} JSON object for revokedCertificate parameter
     * @see X509CRL#getRevCertArray
     *
     * @description
     * This method returns parsed revokedCertificate parameter
     * as JSON object.
     *
     * @example
     * crl = new X509CRL();
     * crl.getRevCertArray("30...") &rarr;
     * {sn:"123a", date:"208025235959Z", ext: [{extname:"cRLReason",code:3}]}
     */
    this.getRevCert = function(hRevCert) {
	var param = {};
	var aIdx = _getChildIdx(hRevCert, 0);

	param.sn = {hex: _getVbyList(hRevCert, 0, [0], "02")};
	param.date = hextorstr(_getVbyList(hRevCert, 0, [1]));
	if (aIdx.length == 3) {
	    param.ext = 
		_x509obj.getExtParamArray(_getTLVbyList(hRevCert, 0, [2]));
	}

	return param;
    };

    /**
     * get revokedCertificate associative array for checking certificate<br/>
     * @name findRevCert
     * @memberOf X509CRL#
     * @function
     * @param {string} PEM or hexadecimal string of certificate to be revocation-checked
     * @return {object} JSON object for revokedCertificate or null
     * @see X509CRL#getParam
     * @see X509CRL#findRevCertBySN
     * @since jsrsasign 10.5.5 x509crl 1.0.3
     *
     * @description
     * This method will find revokedCertificate entry as JSON object
     * for a specified certificate. <br/>
     * When the serial number is not found in the entry, this returns null.<br/>
     * Before finding, {@link X509CRL#getParam} is called internally
     * to parse CRL.<br/>
     * NOTE: This method will just find an entry for a serial number.
     * You need to check whether CRL is proper one or not
     * for checking certificate such as signature validation or
     * name checking.
     *
     * @example
     * crl = new X509CRL(PEMCRL);
     *
     * crl.findRevCert(PEMCERT-REVOKED) &rarr; 
     * {sn:"123a", date:"208025235959Z", ext: [{extname:"cRLReason",code:3}]}
     *
     * crl.findRevCert(PEMCERT-NOTREVOKED) &rarr; null
     * 
     * crl.findRevCert(CERT-HEX) &rarr; null or {sn:...}
     */
    this.findRevCert = function(sCert) {
	var x = new X509(sCert);
	var hSN = x.getSerialNumberHex();
	return this.findRevCertBySN(hSN);
    };
    
    /**
     * get revokedCertificate associative array for serial number<br/>
     * @name findRevCertBySN
     * @memberOf X509CRL#
     * @function
     * @param {string} hexadecimal string of checking certificate serial number
     * @return {object} JSON object for revokedCertificate or null
     * @see X509CRL#getParam
     * @see X509CRL#findRevCert
     * @since jsrsasign 10.5.5 x509crl 1.0.3
     *
     * @description
     * This method will find revokedCertificate entry as JSON object
     * for a specified serial number. <br/>
     * When the serial number is not found in the entry, this returns null.<br/>
     * Before finding, {@link X509CRL#getParam} is called internally
     * to parse CRL.<br/>
     * NOTE: This method will just find an entry for a serial number.
     * You need to check whether CRL is proper one or not
     * for checking certificate such as signature validation or
     * name checking.
     *
     * @example
     * crl = new X509CRL(PEMCRL);
     * crl.findRevCertBySN("123a") &rarr; // revoked
     * {sn:"123a", date:"208025235959Z", ext: [{extname:"cRLReason",code:3}]}
     *
     * crl.findRevCertBySN("0000") &rarr; null // not revoked
     */
    this.findRevCertBySN = function(hSN) {
	if (this.parsed == null) this.getParam();
	if (this.parsed.revcert == null) return null;
	var revcert = this.parsed.revcert;
	for (var i = 0; i < revcert.length; i++) {
	    if (hSN == revcert[i].sn.hex) return revcert[i];
	}
	return null;
    };

    /**
     * get signature value as hexadecimal string<br/>
     * @name getSignatureValueHex
     * @memberOf X509CRL#
     * @function
     * @return {String} signature value hexadecimal string without BitString unused bits
     *
     * @description
     * This method will get signature value of CRL.
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * crl.getSignatureValueHex() &rarr "8a4c47913..."
     */
    this.getSignatureValueHex = function() {
	return _getVbyList(this.hex, 0, [2], "03", true);
    };

    /**
     * verifies signature value by public key<br/>
     * @name verifySignature
     * @memberOf X509CRL#
     * @function
     * @param {Object} pubKey public key object, pubkey PEM or PEM issuer cert
     * @return {Boolean} true if signature value is valid otherwise false
     * @see X509#verifySignature
     * @see KJUR.crypto.Signature
     *
     * @description
     * This method verifies signature value of hexadecimal string of 
     * X.509 CRL by specified public key.
     * The signature algorithm used to verify will refer
     * signatureAlgorithm field. 
     * (See {@link X509CRL#getSignatureAlgorithmField})
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * x.verifySignature(pubKey) &rarr; true, false or raising exception
     */
    this.verifySignature = function(pubKey) {
	var algName = this.getSignatureAlgorithmField();
	var hSigVal = this.getSignatureValueHex();
	var hTbsCertList = _getTLVbyList(this.hex, 0, [0], "30");
	
	var sig = new KJUR.crypto.Signature({alg: algName});
	sig.init(pubKey);
	sig.updateHex(hTbsCertList);
	return sig.verify(hSigVal);
    };

    /**
     * get JSON object for CRL parameters<br/>
     * @name getParam
     * @memberOf X509CRL#
     * @function
     * @return {Array} JSON object for CRL parameters
     * @see KJUR.asn1.x509.CRL
     *
     * @description
     * This method returns a JSON object of the CRL
     * parameters. 
     * Return value can be passed to
     * {@link KJUR.asn1.x509.CRL} constructor.
     * <br/>
     * NOTE1: From jsrsasign 10.5.16, optional argument can be applied.
     * It can have following members:
     * <ul>
     * <li>tbshex - if this is true, tbshex member with hex value of
     * tbsCertList will be added</li>
     * <li>nodnarray - if this is true, array member for subject and
     * issuer will be deleted to simplify it<li>
     * </ul>
     *
     * @example
     * crl = new X509CRL("-----BEGIN X509 CRL...");
     * crl.getParam() &rarr;
     * {version: 2,
     *  sigalg: "SHA256withRSA",
     *  issuer: {array:
     *    [[{type:"C",value:"JP",ds:"prn"}],[{type:"O",value:"T1",ds:"prn"}]]},
     *  thisupdate: "200820212434Z",
     *  nextupdate: "200910212434Z",
     *  revcert: [
     *   {sn:{hex:"123d..."},
     *    date:"061110000000Z",
     *    ext:[{extname:"cRLReason",code:4}]}],
     *  ext: [
     *   {extname:"authorityKeyIdentifier",kid:{hex: "03de..."}},
     *   {extname:"cRLNumber",num:{hex:"0211"}}],
     *  sighex: "3c5e..."}
     *
     * crl.getParam({tbshex: true}) &rarr; { ... , tbshex: "30..." }
     * crl.getParam({nodnarray: true}) &rarr; {issuer: {str: "/C=JP"}, ...}
     */
    this.getParam = function(option) {
	var result = {};

	var version = this.getVersion();
	if (version != null) result.version = version;
	
	result.sigalg = this.getSignatureAlgorithmField();
	result.issuer = this.getIssuer();
	result.thisupdate = this.getThisUpdate();

	var nextUpdate = this.getNextUpdate();
	if (nextUpdate != null) result.nextupdate = nextUpdate;

	var revCerts = this.getRevCertArray();
	if (revCerts != null) result.revcert = revCerts;

	var idxExt = _getIdxbyListEx(this.hex, 0, [0, "[0]"]);
	if (idxExt != -1) {
	    var hExtSeq = _getTLVbyListEx(this.hex, 0, [0, "[0]", 0]);
	    result.ext = _x509obj.getExtParamArray(hExtSeq);
	}

	result.sighex = this.getSignatureValueHex();

	this.parsed = result;

	// for options
	if (typeof option == "object") {
	    if (option.tbshex == true) {
		result.tbshex = _getTLVbyList(this.hex, 0, [0]);
	    }
	    if (option.nodnarray == true) {
		delete result.issuer.array;
	    }
	}

	return result;
    };

    if (typeof params == "string") {
	if (_isHex(params)) {
	    this.hex = params;
	} else if (params.match(/-----BEGIN X509 CRL/)) {
	    this.hex = pemtohex(params);
	}
	this._setPos();
    }
};
