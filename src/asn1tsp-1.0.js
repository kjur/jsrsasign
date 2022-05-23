/* asn1tsp-2.0.9.js (c) 2014-2022 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * asn1tsp.js - ASN.1 DER encoder classes for RFC 3161 Time Stamp Protocol
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
 * @name asn1tsp-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.22 asn1tsp 2.0.9 (2022-May-24)
 * @since jsrsasign 4.5.1
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/* 
 * kjur's class library name space
 * // already documented in asn1-1.0.js
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/*
 * kjur's ASN.1 class library name space
 * // already documented in asn1-1.0.js
 * @name KJUR.asn1
 * @namespace
 */
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

/**
 * kjur's ASN.1 class for RFC 3161 Time Stamp Protocol
 * <p>
 * This name space provides 
 * <a href="https://tools.ietf.org/html/rfc3161">RFC 3161
 * Time-Stamp Protocol(TSP)</a> data generator.
 *
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily generate CMS SignedData</li>
 * <li>APIs are very similar to BouncyCastle library ASN.1 classes. So easy to learn.</li>
 * </ul>
 * 
 * <h4>PROVIDED CLASSES</h4>
 * <ul>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.asn1.tsp
 * @namespace
 */
if (typeof KJUR.asn1.tsp == "undefined" || !KJUR.asn1.tsp) KJUR.asn1.tsp = {};

/**
 * class for TSP TimeStampToken ASN.1 object<br/>
 * @name KJUR.asn1.tsp.TimeStampToken
 * @class class for TSP TimeStampToken ASN.1 object
 * @param {Array} params JSON object for constructor parameters
 * @extends KJUR.asn1.cms.SignedData
 * @since jsrsasign 10.0.0 asn1tsp 2.0.0
 * @see KJUR.asn1.tsp.TimeStampResp
 * @see KJUR.asn1.tsp.TSTInfo
 *
 * @description
 * This is an ASN.1 encoder for TimeStampToken
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc3161#section-2.4.2">
 * RFC 3161 TSP section 2.4.2</a>.
 * <pre>
 * TimeStampToken ::= ContentInfo
 *   -- contentType is id-signedData ([CMS])
 *   -- content is SignedData ([CMS])
 * id-ct-TSTInfo  OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4}
 * </pre>
 * Constructor argument "params" is similar to
 * {@link KJUR.asn1.cms.SignedData} however "econtent"
 * value is different as follows:
 * <ul>
 * <li>econtent.type - shall be "tstinfo"</li>
 * <li>econtent.content - shall be {@link KJUR.asn1.tsp.TSTInfo} parameter</li>
 * </ul>
 *
 * @example
 * new KJUR.asn1.tsp.TimeStampToken({
 *   version: 1,
 *   hashalgs: ["sha256"],
 *   econtent: {
 *     type: "tstinfo",
 *     content: {
 *       policy: '1.2.3.4.5',
 *       messageImprint: { hashAlg: 'sha1', hashValue: 'a1a2a3a4' },
 *       serial: {'int': 3},
 *       genTime: {str: '20131231235959.123Z', millis: true},
 *       accuracy: { millis: 500 },
 *       ordering: true,
 *       nonce: {'int': 3},
 *     }
 *   },
 *   sinfos: [{
 *     version: 1,
 *     id: {type:'isssn', cert: sZ4_CERPEM},
 *     hashalg: "sha256",
 *     sattrs: {array: [{
 *       attr: "contentType",
 *       type: "data"
 *     },{
 *       attr: "signingTime",
 *       str: '131231235959Z'
 *     },{
 *       attr: "messageDigest",
 *       hex: 'ffff'
 *     }]},
 *     sigalg: "SHA256withRSA",
 *     signkey: sZ4_PRVP8PPEM
 *   }]
 * })
 */
KJUR.asn1.tsp.TimeStampToken = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp;

    _KJUR_asn1_tsp.TimeStampToken.superclass.constructor.call(this);

    this.params = null;

    this.getEncodedHexPrepare = function() {
	//alert("getEncodedHexPrepare called...");
	var dTSTInfo = new _KJUR_asn1_tsp.TSTInfo(this.params.econtent.content);
	this.params.econtent.content.hex = dTSTInfo.tohex();
    };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.TimeStampToken, KJUR.asn1.cms.SignedData);

/**
 * class for TSP TSTInfo ASN.1 object
 * @name KJUR.asn1.tsp.TSTInfo
 * @class class for TSP TSTInfo ASN.1 object
 * @param {Array} params JSON object for TSTInfo parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @see KJUR.asn1.x509.X500Name
 * @see KJUR.asn1.x509.GeneralName
 * @description
 * This class represents TSTInfo ASN.1 structure.
 * <pre>
 * TSTInfo ::= SEQUENCE  {
 *    version         INTEGER  { v1(1) },
 *    policy          TSAPolicyId,
 *    messageImprint  MessageImprint,
 *    serialNumber    INTEGER, -- up to 160bit
 *    genTime         GeneralizedTime,
 *    accuracy        Accuracy                 OPTIONAL,
 *    ordering        BOOLEAN                  DEFAULT FALSE,
 *    nonce           INTEGER                  OPTIONAL,
 *    tsa             [0] GeneralName          OPTIONAL,
 *    extensions      [1] IMPLICIT Extensions  OPTIONAL   }
 * </pre>
 * For "params" arguent, following properties are accepted:
 * <ul>
 * <li>{Array}tsa - {@link KJUR.asn1.x509.X500Name} parameter for
 * tsa field even though tsa field is GeneralName.</li>
 * </ul>
 * @example
 * o = new KJUR.asn1.tsp.TSTInfo({
 *     policy:    '1.2.3.4.5',
 *     messageImprint: {alg: 'sha256', hash: '1abc...'},
 *     serial:    {int: 3},
 *     genTime:   {millis: true},         // OPTION
 *     accuracy:  {micros: 500},          // OPTION
 *     ordering:  true,                   // OPITON
 *     nonce:     {hex: '52fab1...'},     // OPTION
 *     tsa:       {str: '/C=US/O=TSA1'}   // OPITON
 * });
 */
KJUR.asn1.tsp.TSTInfo = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERBoolean = _KJUR_asn1.DERBoolean,
	_DERGeneralizedTime = _KJUR_asn1.DERGeneralizedTime,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_MessageImprint = _KJUR_asn1_tsp.MessageImprint,
	_Accuracy = _KJUR_asn1_tsp.Accuracy,
        _X500Name = _KJUR_asn1.x509.X500Name,
        _GeneralName = _KJUR_asn1.x509.GeneralName;
	

    _KJUR_asn1_tsp.TSTInfo.superclass.constructor.call(this);

    this.dVersion = new _DERInteger({'int': 1});
    this.dPolicy = null;
    this.dMessageImprint = null;
    this.dSerial = null;
    this.dGenTime = null;
    this.dAccuracy = null;
    this.dOrdering = null;
    this.dNonce = null;
    this.dTsa = null;

    this.tohex = function() {
        var a = [this.dVersion];

        if (this.dPolicy == null) throw new Error("policy shall be specified.");
        a.push(this.dPolicy);

        if (this.dMessageImprint == null)
            throw new Error("messageImprint shall be specified.");
        a.push(this.dMessageImprint);

        if (this.dSerial == null)
            throw new Error("serialNumber shall be specified.");
        a.push(this.dSerial);

        if (this.dGenTime == null)
            throw new Error("genTime shall be specified.");
        a.push(this.dGenTime);

        if (this.dAccuracy != null) a.push(this.dAccuracy);
        if (this.dOrdering != null) a.push(this.dOrdering);
        if (this.dNonce != null) a.push(this.dNonce);
        if (this.dTsa != null) a.push(this.dTsa);

        var seq = new _DERSequence({array: a});
        this.hTLV = seq.tohex();
        return this.hTLV;
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) {
        if (typeof params.policy == "string") {
            if (! params.policy.match(/^[0-9.]+$/))
                throw "policy shall be oid like 0.1.4.134";
            this.dPolicy = new _DERObjectIdentifier({oid: params.policy});
        }
        if (params.messageImprint !== undefined) {
            this.dMessageImprint = new _MessageImprint(params.messageImprint);
        }
        if (params.serial !== undefined) {
            this.dSerial = new _DERInteger(params.serial);
        }
        if (params.genTime !== undefined) {
            this.dGenTime = new _DERGeneralizedTime(params.genTime);
        }
        if (params.accuracy !== undefined) {
            this.dAccuracy = new _Accuracy(params.accuracy);
        }
        if (params.ordering !== undefined &&
            params.ordering == true) {
            this.dOrdering = new _DERBoolean();
        }
        if (params.nonce !== undefined) {
            this.dNonce = new _DERInteger(params.nonce);
        }
        if (params.tsa !== undefined) {
            this.dTsa = new _DERTaggedObject({
		tag: "a0",
		explicit: true,
		obj: new _GeneralName({dn: params.tsa})
	    });
        }
    }
};
extendClass(KJUR.asn1.tsp.TSTInfo, KJUR.asn1.ASN1Object);

/**
 * class for TSP Accuracy ASN.1 object
 * @name KJUR.asn1.tsp.Accuracy
 * @class class for TSP Accuracy ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 *
 * @description
 * This is an ASN.1 encoder for Accuracy
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc3161#section-2.4.2">
 * RFC 3161 TSP section 2.4.2</a>.
 * <pre>
 * Accuracy ::= SEQUENCE {
 *    seconds        INTEGER              OPTIONAL,
 *    millis     [0] INTEGER  (1..999)    OPTIONAL,
 *    micros     [1] INTEGER  (1..999)    OPTIONAL  }
 * </pre>
 *
 * @example
 * new KJUR.asn1.tsp.Accuracy({
 *   seconds: 1,   // OPTION
 *   millis: 500,  // OPTION
 *   micros: 500   // OPTION
 * });
 */
KJUR.asn1.tsp.Accuracy = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_newObject = _KJUR_asn1.ASN1Util.newObject;

    _KJUR_asn1.tsp.Accuracy.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;
	var a = [];
	if (params.seconds != undefined &&
	    typeof params.seconds == "number") {
	    a.push({"int": params.seconds});
	}
	if (params.millis != undefined &&
	    typeof params.millis == "number") {
	    a.push({tag: {tagi:"80", obj:{"int": params.millis}}});
	}
	if (params.micros != undefined &&
	    typeof params.micros == "number") {
	    a.push({tag: {tagi:"81", obj:{"int": params.micros}}});
	}
	return _newObject({"seq": a}).tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.Accuracy, KJUR.asn1.ASN1Object);

/**
 * class for TSP MessageImprint ASN.1 object
 * @name KJUR.asn1.tsp.MessageImprint
 * @class class for TSP MessageImprint ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 *
 * @description
 * This is an ASN.1 encoder for Accuracy
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc3161#section-2.4.2">
 * RFC 3161 TSP section 2.4.2</a>.
 * <pre>
 * MessageImprint ::= SEQUENCE  {
 *      hashAlgorithm                AlgorithmIdentifier,
 *      hashedMessage                OCTET STRING  }
 * </pre>
 *
 * @example
 * // OLD
 * new KJUR.asn1.tsp.MessageImprint({
 *   hashAlg: 'sha256',
 *   hashValue: '1f3dea...'
 * });
 * // NEW
 * new KJUR.asn1.tsp.MessageImprint({
 *   alg: 'sha256',
 *   hash: '1f3dea...'
 * });
 */
KJUR.asn1.tsp.MessageImprint = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier;

    _KJUR_asn1.tsp.MessageImprint.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;
	var dAlg = new _AlgorithmIdentifier({name: params.alg});
	var dHash = new _DEROctetString({hex: params.hash});
	var seq = new _DERSequence({array: [dAlg, dHash]});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params !== undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.MessageImprint, KJUR.asn1.ASN1Object);

/**
 * class for TSP TimeStampReq ASN.1 object<br/>
 * @name KJUR.asn1.tsp.TimeStampReq
 * @class class for TSP TimeStampReq ASN.1 object
 * @param {Array} params JSON object of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @see KJUR.asn1.tsp.MessageImprint
 *
 * @description
 * <pre>
 * TimeStampReq ::= SEQUENCE  {
 *    version          INTEGER  { v1(1) },
 *    messageImprint   MessageImprint,
 *    reqPolicy        TSAPolicyId               OPTIONAL,
 *    nonce            INTEGER                   OPTIONAL,
 *    certReq          BOOLEAN                   DEFAULT FALSE,
 *    extensions       [0] IMPLICIT Extensions   OPTIONAL  }
 * </pre>
 *
 * @example
 * new KJUR.asn1.tsp.TimeStampReq({
 *   messageImprint: {alg: "sha256", hash: "12ab..."},
 *   policy: "1.2.3.4.5",
 *   nonce: {hex: "1a2b..."},
 *   certreq: true
 * })
 */
KJUR.asn1.tsp.TimeStampReq = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERBoolean = _KJUR_asn1.DERBoolean,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_MessageImprint = _KJUR_asn1_tsp.MessageImprint;

    _KJUR_asn1_tsp.TimeStampReq.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var a = [];
	a.push(new _DERInteger({'int': 1}));
	if (params.messageImprint instanceof KJUR.asn1.ASN1Object) {
	    a.push(params.messageImprint);
	} else {
	    a.push(new _MessageImprint(params.messageImprint));
	}
	if (params.policy != undefined)
	    a.push(new _DERObjectIdentifier(params.policy));
	if (params.nonce != undefined)
	    a.push(new _DERInteger(params.nonce));
	if (params.certreq == true)
	    a.push(new _DERBoolean());

        var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.TimeStampReq, KJUR.asn1.ASN1Object);

/**
 * class for TSP TimeStampResp ASN.1 object<br/>
 * @name KJUR.asn1.tsp.TimeStampResp
 * @class class for TSP TimeStampResp ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @see KJUR.asn1.tsp.TimeStampToken
 * @see KJUR.asn1.tsp.PKIStatusInfo
 *
 * @description
 * This is an ASN.1 encoder for TimeStampResp
 * ASN.1 structure defined in
 * <a href="https://tools.ietf.org/html/rfc3161#section-2.4.2">
 * RFC 3161 TSP section 2.4.2</a>.
 * 
 * <pre>
 * TimeStampResp ::= SEQUENCE  {
 *    status                  PKIStatusInfo,
 *    timeStampToken          TimeStampToken     OPTIONAL  }
 *
 * TimeStampToken ::= ContentInfo
 *
 * TSTInfo ::= SEQUENCE  {
 *    version           INTEGER  { v1(1) },
 *    policy            TSAPolicyId,
 *    messageImprint    MessageImprint,
 *    serialNumber      INTEGER,
 *    genTime           GeneralizedTime,
 *    accuracy          Accuracy                 OPTIONAL,
 *    ordering          BOOLEAN                  DEFAULT FALSE,
 *    nonce             INTEGER                  OPTIONAL,
 *    tsa               [0] GeneralName          OPTIONAL,
 *    extensions        [1] IMPLICIT Extensions  OPTIONAL  }
 * </pre>
 *
 * The constructor argument "params" can be used all of 
 * {@link KJUR.asn1.tsp.TimeStampToken} object further more
 * following members can be specified:
 * <ul>
 * <li>statusinfo: any {@link KJUR.asn1.tsp.PKIStatusInfo} parameter.
 * When parameters for TimeStampToken is specified and statusinfo member is omitted, 
 * status will be "granted" by default. (OPTIONAL)</li>
 * <li>tst: {@link KJUR.asn1.tsp.TimeStampToken} object instead of TimeStampToken members (OPTIONAL)</li>
 * </ul>
 *
 * @example
 * // by TimeStampToken parameters (statusinfo will be "granted" by default)
 * new KJUR.asn1.tsp.TimeStampResp({
 *   version: 1,
 *   hashalgs: ["sha256"],
 *   econtent: {
 *     type: "tstinfo",
 *     content: {
 *       policy: "1.2.3.4.5",
 *       messageImprint: {alg:"sha256", hash:"12ab..."},
 *       serial: {"int": 3},
 *       genTime: {millis: true}, // current time with millis
 *       accuracy: { millis: 500 }
 *     }
 *   }
 *   certs: [...],
 *   sinfos: [{
 *     version: 1,
 *     id: {type:"isssn", cert: ...},
 *     hashalg: "sha256",
 *     sattrs: {array: [{...}]},
 *     sigalg: "SHA256withRSA",
 *     signkey: ...
 *   }]
 * })
 * // by TimeStampToken object
 * new KJUR.asn1.tsp.TimeStampResp({
 *   tst: new KJUR.asn1.tsp.TimeStapToken(...)
 * })
 * // error case
 * new KJUR.asn1.tsp.TimeStampResp({statusinfo: "rejection"}})
 * new KJUR.asn1.tsp.TimeStampResp({
 *    statusinfo: {
 *      status: "rejection",
 *      statusstr: ["policy shall be 1.2.3.4.5"],
 *      failinfo: "unacceptedPolicy"
 *    }
 * })
 * // finally, encode to hexadecimal string
 * new KJUR.asn1.tsp.TimeStampResp(...).tohex() &rarr; "3082..."
 */
KJUR.asn1.tsp.TimeStampResp = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_PKIStatusInfo = _KJUR_asn1_tsp.PKIStatusInfo;

    _KJUR_asn1_tsp.TimeStampResp.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var a = [];

	if (params.econtent != undefined || params.tst != undefined) {
	    // statusInfo
	    if (params.statusinfo != undefined) {
		a.push(new _PKIStatusInfo(params.statusinfo));
	    } else {
		a.push(new _PKIStatusInfo("granted"));
	    }
	    
	    // TimeStampToken
	    if (params.econtent != undefined) {
		a.push((new _KJUR_asn1_tsp.TimeStampToken(params)).getContentInfo());
	    } else if (params.tst instanceof _KJUR_asn1.ASN1Object) {
		a.push(params.tst);
	    } else {
		throw new Error("improper member tst value");
	    }
	} else if (params.statusinfo != undefined) {
	    a.push(new _PKIStatusInfo(params.statusinfo));
	} else {
	    throw new Error("parameter for token nor statusinfo not specified");
	}
	    
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.TimeStampResp, KJUR.asn1.ASN1Object);

// --- BEGIN OF RFC 2510 CMP -----------------------------------------------

/**
 * class for TSP PKIStatusInfo ASN.1 object
 * @name KJUR.asn1.tsp.PKIStatusInfo
 * @class class for TSP PKIStatusInfo ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @see KJUR.asn1.tsp.PKIStatus
 * @see KJUR.asn1.tsp.PKIFreeText
 * @see KJUR.asn1.tsp.PKIFailureInfo
 * @see KJUR.asn1.tsp.TSPParser#getPKIStatusInfo
 *
 * @description
 * This class provides ASN.1 PKIStatusInfo encoder
 * defined in 
 * <a href="https://tools.ietf.org/html/rfc3161#section-2.4.2">
 * RFC 3161 section 2.4.2</a>.
 * <pre>
 * PKIStatusInfo ::= SEQUENCE {
 *    status                  PKIStatus,
 *    statusString            PKIFreeText     OPTIONAL,
 *    failInfo                PKIFailureInfo  OPTIONAL  }
 * </pre>
 *
 * @example
 * new KJUR.asn1.tsp.PKIStatusInfo("granted")
 * new KJUR.asn1.tsp.PKIStatusInfo({status: "granted"})
 * new KJUR.asn1.tsp.PKIStatusInfo({
 *   status: 2, // rejection
 *   statusstr: ["unsupported algorithm"], // OPTION
 *   failinfo: 'badAlg' // OPTION
 * })
 */
KJUR.asn1.tsp.PKIStatusInfo = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_PKIStatus = _KJUR_asn1_tsp.PKIStatus,
	_PKIFreeText = _KJUR_asn1_tsp.PKIFreeText,
	_PKIFailureInfo = _KJUR_asn1_tsp.PKIFailureInfo;

    _KJUR_asn1_tsp.PKIStatusInfo.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var a = [];
	if (typeof params == "string") {
	    a.push(new _PKIStatus(params));
	} else {
	    if (params.status == undefined)
		throw new _Error("property 'status' unspecified");

	    a.push(new _PKIStatus(params.status));

	    if (params.statusstr != undefined)
		a.push(new _PKIFreeText(params.statusstr));

	    if (params.failinfo != undefined)
		a.push(new _PKIFailureInfo(params.failinfo));
	}

	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.PKIStatusInfo, KJUR.asn1.ASN1Object);

/**
 * class for TSP PKIStatus ASN.1 object
 * @name KJUR.asn1.tsp.PKIStatus
 * @class class for TSP PKIStatus ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
 * <pre>
 * PKIStatus ::= INTEGER {
 *    granted                (0),
 *    grantedWithMods        (1),
 *    rejection              (2),
 *    waiting                (3),
 *    revocationWarning      (4),
 *    revocationNotification (5) }
 * </pre>
 *
 * @example
 * new KJUR.asn1.tsp.PKIStatus('granted')
 * new KJUR.asn1.tsp.PKIStatus(2)
 */
KJUR.asn1.tsp.PKIStatus = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp;

    _KJUR_asn1_tsp.PKIStatus.superclass.constructor.call(this);

    var _nameValue = {
	granted:                0,
	grantedWithMods:        1,
	rejection:              2,
	waiting:                3,
	revocationWarning:      4,
	revocationNotification: 5
    };

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	var dObj, value;

	if (typeof params == "string") {
	    try {
		value = _nameValue[params];
	    } catch (ex) {
		throw new _Error("undefined name: " + params);
		}
	} else if (typeof params == "number") {
	    value = params;
	} else {
	    throw new _Error("unsupported params");
	}

	return (new _DERInteger({"int": value})).tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.PKIStatus, KJUR.asn1.ASN1Object);

/**
 * class for TSP PKIFreeText ASN.1 object
 * @name KJUR.asn1.tsp.PKIFreeText
 * @class class for TSP PKIFreeText ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
 * This class provides ASN.1 encoder for PKIFreeText
 * defined in <a href="https://tools.ietf.org/html/rfc4210#section-5.1.1">
 * RFC 4210 CMP section 5.1.1</a>.
 * <pre>
 * PKIFreeText ::= SEQUENCE { SIZE (1..MAX) OF UTF8String }
 * </pre>
 * 
 * @example
 * new KJUR.asn1.tsp.PKIFreeText([
 *   "aaa", "bbb", "ccc"
 * ])
 */
KJUR.asn1.tsp.PKIFreeText = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERUTF8String = _KJUR_asn1.DERUTF8String,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp;

    _KJUR_asn1_tsp.PKIFreeText.superclass.constructor.call(this);

    this.params = null;

    this.tohex = function() {
	var params = this.params;

	if (! params instanceof Array)
	    throw new _Error("wrong params: not array");

	var a = [];
	for (var i = 0; i < params.length; i++) {
	    a.push(new _DERUTF8String({str: params[i]}));
	};
	
	var seq = new _DERSequence({array: a});
	return seq.tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.PKIFreeText, KJUR.asn1.ASN1Object);

/**
 * class for TSP PKIFailureInfo ASN.1 object<br/>
 * @name KJUR.asn1.tsp.PKIFailureInfo
 * @class class for TSP PKIFailureInfo ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @see KJUR.asn1.tsp.PKIStatusInfo
 *
 * @description
 * This class provides ASN.1 PKIFailureInfo encoder
 * defined in 
 * <a href="https://tools.ietf.org/html/rfc3161#section-2.4.2">
 * RFC 3161 section 2.4.2</a>.
 * <pre>
 * PKIFailureInfo ::= BIT STRING {
 *    badAlg                 (0),
 *    badRequest             (2),
 *    badDataFormat          (5),
 *    timeNotAvailable       (14),
 *    unacceptedPolicy       (15),
 *    unacceptedExtension    (16),
 *    addInfoNotAvailable    (17),
 *    systemFailure          (25) }
 * </pre>
 * NOTE: Constructor of an array of failureInfo names string
 * has been supported since jsrsasign 10.5.21.
 * Ordering of names will be ignored so that
 * ['unacceptedPolicy', 'badAlg'] is also fine.
 * 
 * @example
 * new KJUR.asn1.tsp.PKIFailureInfo('badAlg')
 * new KJUR.asn1.tsp.PKIFailureInfo(5)
 * new KJUR.asn1.tsp.PKIFailureInfo(['badAlg', 'unacceptedPolicy'])
 */
KJUR.asn1.tsp.PKIFailureInfo = function(params) {
    var _Error = Error,
	_KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERBitString = _KJUR_asn1.DERBitString,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_PKIFailureInfo = _KJUR_asn1_tsp.PKIFailureInfo;

    var _nameValue = {
	badAlg:                 0,
	badRequest:             2,
	badDataFormat:          5,
	timeNotAvailable:       14,
	unacceptedPolicy:       15,
	unacceptedExtension:    16,
	addInfoNotAvailable:    17,
	systemFailure:          25
    };

    _PKIFailureInfo.superclass.constructor.call(this);

    this.params = null;

    this.getBinValue = function() {
	var params = this.params;

	var d = 0;

	if (typeof params == "number" && 
	    0 <= params && params <= 25) {
	    d |= 1 << params;
	    var s = d.toString(2);
	    var r = "";
	    for (var i = s.length - 1; i >= 0; i--) r += s[i];
	    return r;
	} else if (typeof params == "string" &&
		   _nameValue[params] != undefined) {
	    return namearraytobinstr([params], _nameValue);
	} else if (typeof params == "object" &&
		   params.length != undefined) {
	    return namearraytobinstr(params, _nameValue);
	} else {
	    throw new _Error("wrong params");
	}

	return 
    };

    this.tohex = function() {
	var params = this.params;

	var binValue = this.getBinValue();
	return (new _DERBitString({"bin": binValue})).tohex();
    };
    this.getEncodedHex = function() { return this.tohex(); };

    if (params != undefined) this.setByParam(params);
};
extendClass(KJUR.asn1.tsp.PKIFailureInfo, KJUR.asn1.ASN1Object);

// --- END OF RFC 2510 CMP -------------------------------------------

/**
 * abstract class for TimeStampToken generator (DEPRECATED)<br/>
 * @name KJUR.asn1.tsp.AbstractTSAAdapter
 * @class abstract class for TimeStampToken generator
 * @param {Array} params associative array of parameters
 * @since jsrsasign 4.7.0 asn1tsp 1.0.1
 * @deprecated since jsrsasign 10.0.0 asn1tsp 2.0.0
 *
 * @description
 * This is abstract class for TimeStampToken generator.
 */
KJUR.asn1.tsp.AbstractTSAAdapter = function(params) {
    this.getTSTHex = function(msgHex, hashAlg) {
        throw "not implemented yet";
    };
};

/**
 * class for simple TimeStampToken generator (DEPRECATED)<br/>
 * @name KJUR.asn1.tsp.SimpleTSAAdapter
 * @class class for simple TimeStampToken generator
 * @extends KJUR.asn1.tsp.AbstractTSAAdapter
 * @param {Array} params associative array of parameters
 * @since jsrsasign 4.7.0 asn1tsp 1.0.1
 * @deprecated since jsrsasign 10.0.0 asn1tsp 2.0.0
 *
 * @description
 * This is a simple TimeStampToken generator class.
 */
KJUR.asn1.tsp.SimpleTSAAdapter = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_hashHex = _KJUR.crypto.Util.hashHex;

    _KJUR_asn1_tsp.SimpleTSAAdapter.superclass.constructor.call(this);
    this.params = null;
    this.serial = 0;

    this.getTSTHex = function(msgHex, hashAlg) {
        // messageImprint
        var hashHex = _hashHex(msgHex, hashAlg);
        this.params.econtent.content.messageImprint =
            {alg: hashAlg, hash: hashHex};

        // serial
        this.params.econtent.content.serial =
	    {'int': this.serial++};

        // nonce
        var nonceValue = Math.floor(Math.random() * 1000000000);
        this.params.econtent.content.nonce =
	    {'int': nonceValue};

        var obj = 
            new _KJUR_asn1_tsp.TimeStampToken(this.params);
        return obj.getContentInfoEncodedHex();
    };

    if (params !== undefined) this.params = params;
};
extendClass(KJUR.asn1.tsp.SimpleTSAAdapter,
            KJUR.asn1.tsp.AbstractTSAAdapter);

/**
 * class for fixed TimeStampToken generator (DEPRECATED)<br/>
 * @name KJUR.asn1.tsp.FixedTSAAdapter
 * @class class for fixed TimeStampToken generator
 * @extends KJUR.asn1.tsp.AbstractTSAAdapter
 * @param {Array} params associative array of parameters
 * @since jsrsasign 4.7.0 asn1tsp 1.0.1
 * @deprecated since jsrsasign 10.0.0 asn1tsp 2.0.0
 *
 * @description
 * This class generates fixed TimeStampToken except messageImprint
 * for testing purpose.
 * General TSA generates TimeStampToken which varies following
 * fields:
 * <ul>
 * <li>genTime</li>
 * <li>serialNumber</li>
 * <li>nonce</li>
 * </ul>
 * Those values are provided by initial parameters.
 */
KJUR.asn1.tsp.FixedTSAAdapter = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_hashHex = _KJUR.crypto.Util.hashHex;

    _KJUR_asn1_tsp.FixedTSAAdapter.superclass.constructor.call(this);
    this.params = null;

    this.getTSTHex = function(msgHex, hashAlg) {
        // fixed serialNumber
        // fixed nonce        
        var hashHex = _hashHex(msgHex, hashAlg);
        this.params.econtent.content.messageImprint =
            {alg: hashAlg, hash: hashHex};
        var obj = new _KJUR_asn1_tsp.TimeStampToken(this.params);
        return obj.getContentInfoEncodedHex();
    };

    if (params !== undefined) this.params = params;
};
extendClass(KJUR.asn1.tsp.FixedTSAAdapter,
            KJUR.asn1.tsp.AbstractTSAAdapter);

// --- TSP utilities -------------------------------------------------

/**
 * TSP utiliteis class
 * @name KJUR.asn1.tsp.TSPUtil
 * @class TSP utilities class
 */
KJUR.asn1.tsp.TSPUtil = new function() {
};
/**
 * generate TimeStampToken ASN.1 object specified by JSON parameters (DEPRECATED)<br/>
 * @name newTimeStampToken
 * @memberOf KJUR.asn1.tsp.TSPUtil
 * @function
 * @param {Array} param JSON parameter to generate TimeStampToken
 * @return {KJUR.asn1.cms.SignedData} object just generated
 * @deprecated since jsrsasign 10.0.0 asn1tsp 2.0.0. Please use TimeStampToken class
 * @see KJUR.asn1.tsp.TimeStampToken
 *
 * @description
 * @example
 */
KJUR.asn1.tsp.TSPUtil.newTimeStampToken = function(params) {
    return new KJUR.asn1.tsp.TimeStampToken(params);
};

/**
 * parse hexadecimal string of TimeStampReq
 * @name parseTimeStampReq
 * @memberOf KJUR.asn1.tsp.TSPUtil
 * @function
 * @param {String} hexadecimal string of TimeStampReq
 * @return {Array} JSON object of parsed parameters
 * @see KJUR.asn1.tsp.TSPParser#getTimeStampReq
 * @deprecated since jsrsasign 10.5.18 asn1tsp 2.0.6. Please use TSPParser.getTimeStampReq instead.
 *
 * @description
 * This method parses a hexadecimal string of TimeStampReq
 * and returns parsed their fields:
 *
 * @example
 * var json = KJUR.asn1.tsp.TSPUtil.parseTimeStampReq("302602...");
 * // resulted DUMP of above 'json':
 * {
 *  messageImprint: {
 *       alg: 'sha256',          // MessageImprint hashAlg
 *       hash: 'a1a2a3a4...'},   // MessageImprint hashValue
 *  policy: '1.2.3.4.5',             // tsaPolicy (OPTION)
 *  nonce: '9abcf318...',            // nonce (OPTION)
 *  certreq: true}                   // certReq (OPTION)
 */
KJUR.asn1.tsp.TSPUtil.parseTimeStampReq = function(reqHex) {
    var parser = new KJUR.asn1.tsp.TSPParser();
    return parser.getTimeStampReq(reqHex);
};

/**
 * parse hexadecimal string of MessageImprint
 * @name parseMessageImprint
 * @memberOf KJUR.asn1.tsp.TSPUtil
 * @function
 * @param {String} hexadecimal string of MessageImprint
 * @return {Array} JSON object of parsed parameters
 * @see KJUR.asn1.tsp.TSPParser#getMessageImprint
 * @deprecated since jsrsasign 10.5.18 asn1tsp 2.0.6. Please use TSPParser.getMessageImprint instead.
 *
 * @description
 * This method parses a hexadecimal string of MessageImprint
 * and returns parsed their fields:
 *
 * @example
 * KJUR.asn1.tsp.TSPUtil.parseMessageImprint("302602...") &rarr;
 * { alg:  'sha256', hash: 'a1a2a3a4...'}
 */
KJUR.asn1.tsp.TSPUtil.parseMessageImprint = function(miHex) {
    var parser = new KJUR.asn1.tsp.TSPParser();
    return parser.getMessageImprint(miHex);
/*
    var _ASN1HEX = ASN1HEX;
    var _getChildIdx = _ASN1HEX.getChildIdx;
    var _getV = _ASN1HEX.getV;
    var _getIdxbyList = _ASN1HEX.getIdxbyList;
    var json = {};

    if (miHex.substr(0, 2) != "30")
        throw "head of messageImprint hex shall be '30'";

    var idxList = _getChildIdx(miHex, 0);
    var hashAlgOidIdx = _getIdxbyList(miHex, 0, [0, 0]);
    var hashAlgHex = _getV(miHex, hashAlgOidIdx);
    var hashAlgOid = _ASN1HEX.hextooidstr(hashAlgHex);
    var hashAlgName = KJUR.asn1.x509.OID.oid2name(hashAlgOid);
    if (hashAlgName == '')
        throw "hashAlg name undefined: " + hashAlgOid;
    var hashAlg = hashAlgName;
    var hashValueIdx = _getIdxbyList(miHex, 0, [1]);

    json.alg = hashAlg;
    json.hash = _getV(miHex, hashValueIdx); 

    return json;
*/
};

/**
 * class for parsing RFC 3161 TimeStamp protocol data<br/>
 * @name KJUR.asn1.tsp.TSPParser
 * @class RFC 3161 TimeStamp protocol parser class
 * @since jsrsasign 10.1.0 asn1tsp 2.0.1
 *
 * @description
 * This is an ASN.1 parser for 
 * <a href="https://tools.ietf.org/html/rfc3161">RFC 3161</a>.
 */
KJUR.asn1.tsp.TSPParser = function() {
    var _Error = Error,
	_X509 = X509,
	_x509obj = new _X509(),
	_ASN1HEX = ASN1HEX,
	_getV = _ASN1HEX.getV,
	_getTLV = _ASN1HEX.getTLV,
	_getIdxbyList = _ASN1HEX.getIdxbyList,
	_getTLVbyListEx = _ASN1HEX.getTLVbyListEx,
	_getChildIdx = _ASN1HEX.getChildIdx;
    var _aSTATUSSTR = [
	"granted", "grantedWithMods", "rejection", "waiting",
	"revocationWarning", "revocationNotification" ];
    var _pFAILUREINFO = {
	0: "badAlg", 2: "badRequest", 5: "badDataFormat",
	14: "timeNotAvailable", 15: "unacceptedPolicy",
	16: "unacceptedExtension", 17: "addInfoNotAvailable",
	25: "systemFailure"
    };
    
    /**
     * parse ASN.1 TimeStampResp<br/>
     * @name getResponse
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 TimeStampResp
     * @return {Array} JSON object of TimeStampResp parameter
     * @see KJUR.asn1.tsp.TimeStampResp
     * @see KJUR.asn1.tsp.TimeStampToken
     * @see KJUR.asn1.cms.CMSParser#getCMSSignedData
     *
     * @description
     * This method parses ASN.1 TimeStampRsp defined in RFC 3161.
     * <pre>
     * TimeStampResp ::= SEQUENCE {
     *   status          PKIStatusInfo,
     *   timeStampToken  TimeStampToken  OPTIONAL }
     * </pre>
     * When "h" is a TSP error response,
     * returned parameter contains "statusinfo" only.
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getResponse("30...") &rarr;
     * { 
     *   statusinfo: 'granted',
     *   ... // almost the same as CMS SignedData parameters
     *   econtent: {
     *     type: "tstinfo",
     *     content: { // TSTInfo parameter
     *       policy: '1.2.3.4.5',
     *       messageImprint: {alg: 'sha256', hash: 'a1a2a3a4...'},
     *       serial: {'int': 3},
     *       genTime: {str: '20131231235959.123Z'},
     *       accuracy: {millis: 500},
     *       ordering: true,
     *       nonce: {int: 3}
     *     }
     *   },
     *   ...
     * }
     */
    this.getResponse = function(h) {
	var aIdx = _getChildIdx(h, 0);
	
	if (aIdx.length == 1) {
	    return this.getPKIStatusInfo(_getTLV(h, aIdx[0]));
	} else if (aIdx.length > 1) {
	    var pPKIStatusInfo = this.getPKIStatusInfo(_getTLV(h, aIdx[0]));
	    var hTST = _getTLV(h, aIdx[1]);
	    var pResult = this.getToken(hTST);
	    pResult.statusinfo = pPKIStatusInfo;
	    return pResult;
	}
    };

    /**
     * parse ASN.1 TimeStampToken<br/>
     * @name getToken
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 TimeStampToken
     * @return {Array} JSON object of TimeStampToken parameter
     * @see KJUR.asn1.tsp.TimeStampToken
     * @see KJUR.asn1.cms.CMSParser#getCMSSignedData
     * @see KJUR.asn1.tsp.TSPParser#setTSTInfo
     *
     * @description
     * This method parses ASN.1 TimeStampRsp defined in RFC 3161.
     * This method will parse "h" as CMS SigneData by
     * {@link KJUR.asn1.cms.CMSParser#getCMSSignedData}, then
     * parse and modify "econtent.content" parameter by
     * {@link KJUR.asn1.tsp.TSPParser#setTSTInfo} method.
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getToken("30...") &rarr;
     * { 
     *   ... // almost the same as CMS SignedData parameters
     *   econtent: {
     *     type: "tstinfo",
     *     content: { // TSTInfo parameter
     *       policy: '1.2.3.4.5',
     *       messageImprint: {alg: 'sha256', hash: 'a1a2a3a4...'},
     *       serial: {'int': 3},
     *       genTime: {str: '20131231235959.123Z'},
     *       accuracy: {millis: 500},
     *       ordering: true,
     *       nonce: {int: 3}
     *     }
     *   },
     *   ...
     * }
     */
    this.getToken = function(h) {
	var _CMSParser = new KJUR.asn1.cms.CMSParser;
	var p = _CMSParser.getCMSSignedData(h);
	this.setTSTInfo(p);
	return p;
    };

    /**
     * set ASN.1 TSTInfo parameter to CMS SignedData parameter<br/>
     * @name setTSTInfo
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {Array} pCMSSignedData JSON object of CMS SignedData parameter
     * @see KJUR.asn1.tsp.TimeStampToken
     * @see KJUR.asn1.cms.CMSParser#getCMSSignedData
     *
     * @description
     * This method modifies "econtent.content" of CMS SignedData parameter
     * to parsed TSTInfo.
     * <pre>
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * pCMSSignedData = { 
     *   ... // almost the same as CMS SignedData parameters
     *   econtent: {
     *     type: "tstinfo",
     *     content: { hex: "30..." }
     *   },
     *   ...
     * };
     * parser.setTSTInfo(pCMSSignedData);
     * pCMSSignedData &rarr; { 
     *   ... // almost the same as CMS SignedData parameters
     *   econtent: {
     *     type: "tstinfo",
     *     content: { // TSTInfo parameter
     *       policy: '1.2.3.4.5',
     *       messageImprint: {alg: 'sha256', hash: 'a1a2a3a4...'},
     *       serial: {int: 3},
     *       genTime: {str: '20131231235959.123Z'},
     *       accuracy: {millis: 500},
     *       ordering: true,
     *       nonce: {int: 3}
     *     }
     *   },
     *   ...
     * };
     */
    this.setTSTInfo = function(pCMSSignedData) {
	var pEContent = pCMSSignedData.econtent;
	if (pEContent.type == "tstinfo") {
	    var hContent = pEContent.content.hex;
	    var pTSTInfo = this.getTSTInfo(hContent);
	    //pTSTInfo.hex_ = hContent;
	    pEContent.content = pTSTInfo;
	}
    };

    /**
     * parse ASN.1 TSTInfo<br/>
     * @name getTSTInfo
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 TSTInfo
     * @return {Array} JSON object of TSTInfo parameter
     * @see KJUR.asn1.tsp.TSTInfo
     *
     * @description
     * This method parses ASN.1 TSTInfo defined in RFC 3161.
     * <pre>
     * TSTInfo ::= SEQUENCE  {
     *    version          INTEGER  { v1(1) },
     *    policy           TSAPolicyId,
     *    messageImprint   MessageImprint,
     *    serialNumber     INTEGER,
     *    genTime          GeneralizedTime,
     *    accuracy         Accuracy                 OPTIONAL,
     *    ordering         BOOLEAN             DEFAULT FALSE,
     *    nonce            INTEGER                  OPTIONAL,
     *    tsa              [0] GeneralName          OPTIONAL,
     *    extensions       [1] IMPLICIT Extensions  OPTIONAL }
     * </pre>
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getTSTInfo("30...") &rarr;
     * {
     *   policy: '1.2.3.4.5',
     *   messageImprint: {alg: 'sha256', hash: 'a1a2a3a4...'},
     *   serial: {'int': 3},
     *   genTime: {str: '20131231235959.123Z'},
     *   accuracy: {millis: 500},
     *   ordering: true,
     *   nonce: {int: 3}
     * }
     */
    this.getTSTInfo = function(h) {
	var pResult = {};
	var aIdx = _getChildIdx(h, 0);

	var hPolicy = _getV(h, aIdx[1]);
	pResult.policy = hextooid(hPolicy);

	var hMessageImprint = _getTLV(h, aIdx[2]);
	pResult.messageImprint = this.getMessageImprint(hMessageImprint);

	var hSerial = _getV(h, aIdx[3]);
	pResult.serial = {hex: hSerial};

	var hGenTime = _getV(h, aIdx[4]);
	pResult.genTime = {str: hextoutf8(hGenTime)};

	var offset = 0;

	if (aIdx.length > 5 && h.substr(aIdx[5], 2) == "30") {
	    var hAccuracy = _getTLV(h, aIdx[5]);
	    pResult.accuracy = this.getAccuracy(hAccuracy);
	    offset++;
	}

	if (aIdx.length > 5 + offset && 
	    h.substr(aIdx[5 + offset], 2) == "01") {
	    var hOrdering = _getV(h, aIdx[5 + offset]);
	    if (hOrdering == "ff") pResult.ordering = true;
	    offset++;
	}

	if (aIdx.length > 5 + offset &&
	    h.substr(aIdx[5 + offset], 2) == "02") {
	    var hNonce = _getV(h, aIdx[5 + offset]);
	    pResult.nonce = {hex: hNonce};
	    offset++;
	}

	if (aIdx.length > 5 + offset &&
	    h.substr(aIdx[5 + offset], 2) == "a0") {
	    var hGeneralNames = _getTLV(h, aIdx[5 + offset]);
	    hGeneralNames = "30" + hGeneralNames.substr(2);
	    pGeneralNames = _x509obj.getGeneralNames(hGeneralNames);
	    var pName = pGeneralNames[0].dn;
	    pResult.tsa = pName;
	    offset++;
	}

	if (aIdx.length > 5 + offset &&
	    h.substr(aIdx[5 + offset], 2) == "a1") {
	    var hExt = _getTLV(h, aIdx[5 + offset]);
	    hExt = "30" + hExt.substr(2);
	    var aExt = _x509obj.getExtParamArray(hExt);
	    pResult.ext = aExt;
	    offset++;
	}

	return pResult;
    };

    /**
     * parse ASN.1 Accuracy<br/>
     * @name getAccuracy
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 Accuracy
     * @return {Array} JSON object of Accuracy parameter
     * @see KJUR.asn1.tsp.Accuracy
     *
     * @description
     * This method parses ASN.1 Accuracy defined in RFC 3161.
     * <pre>
     * Accuracy ::= SEQUENCE {
     *    seconds        INTEGER              OPTIONAL,
     *    millis     [0] INTEGER  (1..999)    OPTIONAL,
     *    micros     [1] INTEGER  (1..999)    OPTIONAL  }
     * </pre>
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getAccuracy("30...") &rarr; {millis: 500}
     */
    this.getAccuracy = function(h) {
	var pResult = {};

	var aIdx = _getChildIdx(h, 0);

	for (var i = 0; i < aIdx.length; i++) {
	    var tag = h.substr(aIdx[i], 2);
	    var hV = _getV(h, aIdx[i]);
	    var iV = parseInt(hV, 16);

	    if (tag == "02") {
		pResult.seconds = iV;
	    } else if (tag == "80") {
		pResult.millis = iV;
	    } else if (tag == "81") {
		pResult.micros = iV;
	    }
	}

	return pResult;
    };

    /**
     * parse ASN.1 MessageImprint<br/>
     * @name getMessageImprint
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 MessageImprint
     * @return {Array} JSON object of MessageImprint parameter
     * @see KJUR.asn1.tsp.MessageImprint
     *
     * @description
     * This method parses ASN.1 MessageImprint defined in RFC 3161.
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getMessageImprint("30...") &rarr; 
     * { alg: "sha256", hash: "12ab..." }
     */
    this.getMessageImprint = function(h) {
	if (h.substr(0, 2) != "30")
            throw new Error("head of messageImprint hex shall be x30");

	var json = {};
	var idxList = _getChildIdx(h, 0);
	var hashAlgOidIdx = _getIdxbyList(h, 0, [0, 0]);
	var hashAlgHex = _getV(h, hashAlgOidIdx);
	var hashAlgOid = _ASN1HEX.hextooidstr(hashAlgHex);
	var hashAlgName = KJUR.asn1.x509.OID.oid2name(hashAlgOid);
	if (hashAlgName == '')
            throw new Error("hashAlg name undefined: " + hashAlgOid);
	var hashAlg = hashAlgName;
	var hashValueIdx = _getIdxbyList(h, 0, [1]);
	
	json.alg = hashAlg;
	json.hash = _getV(h, hashValueIdx); 

	return json;
    };

    /**
     * parse ASN.1 PKIStatusInfo<br/>
     * @name getPKIStatusInfo
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 PKIStatusInfo
     * @return {Array} JSON object of PKIStatusInfo parameter
     * @see KJUR.asn1.tsp.PKIStatusInfo
     *
     * @description
     * This method parses ASN.1 PKIStatusInfo defined in RFC 3161.
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getPKIStatusInfo("30...") &rarr; 
     * { status: "rejection",
     *   statusstr: ["unsupported algorithm"],
     *   failinfo: "badAlg" }
     */
    this.getPKIStatusInfo = function(h) {
	var pResult = {};
	var aIdx = _getChildIdx(h, 0);
	var offset = 0;

	try {
	    var hStatus = _getV(h, aIdx[0]);
	    var iStatus = parseInt(hStatus, 16);
	    pResult.status = _aSTATUSSTR[iStatus];
	} catch(ex) {};

	if (aIdx.length > 1 && h.substr(aIdx[1], 2) == "30") {
	    var hPKIFreeText = _getTLV(h, aIdx[1]);
	    pResult.statusstr = 
		this.getPKIFreeText(hPKIFreeText);
	    offset++;
	}

	if (aIdx.length > offset &&
	    h.substr(aIdx[1 + offset], 2) == "03") {
	    var hPKIFailureInfo = _getTLV(h, aIdx[1 + offset]);
	    pResult.failinfo = 
		this.getPKIFailureInfo(hPKIFailureInfo);
	}

	return pResult;
    };

    /**
     * parse ASN.1 PKIFreeText<br/>
     * @name getPKIFreeText
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 PKIFreeText
     * @return {Array} array of string
     * @since jsrsasign 10.1.3 asn1tsp 2.0.3
     * @see KJUR.asn1.tsp.PKIFreeText
     *
     * @description
     * This method parses ASN.1 PKIFreeText defined in RFC 3161.
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getPKIFreeText("300a0c036161610c03616161") &rarr; 
     * ["aaa", "aaa"]
     */
    this.getPKIFreeText = function(h) {
	var aResult = [];
	var aIdx = _getChildIdx(h, 0);
	for (var i = 0; i < aIdx.length; i++) {
	    aResult.push(_ASN1HEX.getString(h, aIdx[i]));
	}
	return aResult;
    };

    /**
     * parse ASN.1 PKIFailureInfo<br/>
     * @name getPKIFailureInfo
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of ASN.1 PKIFailureInfo
     * @return {Object} failureInfo string or number
     * @since jsrsasign 10.1.3 asn1tsp 2.0.3
     * @see KJUR.asn1.tsp.PKIFailureInfo
     *
     * @description
     * This method parses ASN.1 PKIFailureInfo defined in RFC 3161.
     *
     * @example
     * parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getPKIFailureInfo("03020700") &rarr; "badAlg"
     * parser.getPKIFailureInfo("03020780") &rarr; 1
     * parser.getPKIFailureInfo("030203c8") &rarr; "systemFailure"
     */
    this.getPKIFailureInfo = function(h) {
	var n = _ASN1HEX.getInt(h, 0);
	if (_pFAILUREINFO[n] != undefined) {
	    return _pFAILUREINFO[n];
	} else {
	    return n;
	}
    };

    /**
     * parse hexadecimal string of TimeStampReq<br/>
     * @name getTimeStampReq
     * @memberOf KJUR.asn1.tsp.TSPParser#
     * @function
     * @param {String} h hexadecimal string of TimeStampReq
     * @return {Array} JSON object of parsed parameters
     * @since jsrsasign 10.5.18 asn1tsp 2.0.6
     * @see KJUR.asn1.tsp.TimeStampReq
     * @see KJUR.asn1.tsp.TSPUtil.parseTimeStampReq
     *
     * @description
     * This method parses a hexadecimal string of TimeStampReq
     * and returns parsed their fields:
     *
     * @example
     * var parser = new KJUR.asn1.tsp.TSPParser();
     * parser.getTimeStampReq("302602...") &rarr;
     * { messageImprint: {
     *       alg: 'sha256',          // MessageImprint hashAlg
     *       hash: 'a1a2a3a4...'},   // MessageImprint hashValue
     *   policy: '1.2.3.4.5',         // tsaPolicy (OPTION)
     *   nonce: '9abcf318...',        // nonce (OPTION)
     *   certreq: true }              // certReq (OPTION)
     */
    this.getTimeStampReq = function(h) {
	var json = {};
	json.certreq = false;

	var idxList = _getChildIdx(h, 0);

	if (idxList.length < 2)
            throw new Error("TimeStampReq must have at least 2 items");

	var miHex = _getTLV(h, idxList[1]);
	json.messageImprint = KJUR.asn1.tsp.TSPUtil.parseMessageImprint(miHex); 

	for (var i = 2; i < idxList.length; i++) {
            var idx = idxList[i];
            var tag = h.substr(idx, 2);
            if (tag == "06") { // case OID
		var policyHex = _getV(h, idx);
		json.policy = _ASN1HEX.hextooidstr(policyHex);
            }
            if (tag == "02") { // case INTEGER
		json.nonce = _getV(h, idx);
            }
            if (tag == "01") { // case BOOLEAN
		json.certreq = true;
            }
	}

	return json;
    };
};
