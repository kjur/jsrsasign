/* asn1tsp-1.0.3.js (c) 2014-2017 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1tsp.js - ASN.1 DER encoder classes for RFC 3161 Time Stamp Protocol
 *
 * Copyright (c) 2014-2017 Kenji Urushima (kenji.urushima@gmail.com)
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
 * @version jsrsasign 7.2.1 asn1tsp 1.0.3 (2017-Jun-03)
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
 * class for TSP Accuracy ASN.1 object
 * @name KJUR.asn1.tsp.Accuracy
 * @class class for TSP Accuracy ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
 * <pre>
 * Accuracy ::= SEQUENCE {
 *       seconds        INTEGER              OPTIONAL,
 *       millis     [0] INTEGER  (1..999)    OPTIONAL,
 *       micros     [1] INTEGER  (1..999)    OPTIONAL  }
 * </pre>
 * @example
 * o = new KJUR.asn1.tsp.Accuracy({seconds: 1,
 *                                 millis: 500,
 *                                 micros: 500});
 */
KJUR.asn1.tsp.Accuracy = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERTaggedObject = _KJUR_asn1.DERTaggedObject;

    _KJUR_asn1.tsp.Accuracy.superclass.constructor.call(this);

    this.seconds = null;
    this.millis = null;
    this.micros = null;

    this.getEncodedHex = function() {
        var dSeconds = null;
        var dTagMillis = null;
        var dTagMicros = null;
        
        var a = [];
        if (this.seconds != null) {
            dSeconds = new _DERInteger({'int': this.seconds});
            a.push(dSeconds);
        }
        if (this.millis != null) {
            var dMillis = new _DERInteger({'int': this.millis});
            dTagMillis = new _DERTaggedObject({obj: dMillis,
                                               tag: '80',
                                               explicit: false});
            a.push(dTagMillis);
        }
        if (this.micros != null) {
            var dMicros = new _DERInteger({'int': this.micros});
            dTagMicros = new _DERTaggedObject({obj: dMicros,
                                               tag: '81',
                                               explicit: false});
            a.push(dTagMicros);
        }
        var seq = new _DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params.seconds == "number") this.seconds = params.seconds;
        if (typeof params.millis == "number") this.millis = params.millis;
        if (typeof params.micros == "number") this.micros = params.micros;
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.Accuracy, KJUR.asn1.ASN1Object);

/**
 * class for TSP MessageImprint ASN.1 object
 * @name KJUR.asn1.tsp.MessageImprint
 * @class class for TSP MessageImprint ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
 * <pre>
 * MessageImprint ::= SEQUENCE  {
 *      hashAlgorithm                AlgorithmIdentifier,
 *      hashedMessage                OCTET STRING  }
 * </pre>
 * @example
 * o = new KJUR.asn1.tsp.MessageImprint({hashAlg: 'sha1',
 *                                       hashValue: '1f3dea...'});
 */
KJUR.asn1.tsp.MessageImprint = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DEROctetString = _KJUR_asn1.DEROctetString,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_AlgorithmIdentifier = _KJUR_asn1_x509.AlgorithmIdentifier;

    _KJUR_asn1.tsp.MessageImprint.superclass.constructor.call(this);

    this.dHashAlg = null;
    this.dHashValue = null;

    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") return this.hTLV;
        var seq = 
            new _DERSequence({array: [this.dHashAlg, this.dHashValue]});
        return seq.getEncodedHex();
    };

    if (params !== undefined) {
        if (typeof params.hashAlg == "string") {
            this.dHashAlg = new _AlgorithmIdentifier({name: params.hashAlg});
        } 
        if (typeof params.hashValue == "string") {
            this.dHashValue = new _DEROctetString({hex: params.hashValue});
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.MessageImprint, KJUR.asn1.ASN1Object);

/**
 * class for TSP TimeStampReq ASN.1 object
 * @name KJUR.asn1.tsp.TimeStampReq
 * @class class for TSP TimeStampReq ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
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
 */
KJUR.asn1.tsp.TimeStampReq = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERBoolean = _KJUR_asn1.DERBoolean,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_MessageImprint = _KJUR_asn1_tsp.MessageImprint;

    _KJUR_asn1_tsp.TimeStampReq.superclass.constructor.call(this);

    this.dVersion = new _DERInteger({'int': 1});
    this.dMessageImprint = null;
    this.dPolicy = null;
    this.dNonce = null;
    this.certReq = true;

    this.setMessageImprint = function(params) {
        if (params instanceof _MessageImprint) {
            this.dMessageImprint = params;
            return;
        }
        if (typeof params == "object") {
            this.dMessageImprint = new _MessageImprint(params);
        }
    };

    this.getEncodedHex = function() {
        if (this.dMessageImprint == null)
            throw "messageImprint shall be specified";

        var a = [this.dVersion, this.dMessageImprint];
        if (this.dPolicy != null) a.push(this.dPolicy);
        if (this.dNonce != null)  a.push(this.dNonce);
        if (this.certReq)         a.push(new _DERBoolean());

        var seq = new _DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params.mi == "object") {
            this.setMessageImprint(params.mi);
        }
        if (typeof params.policy == "object") {
            this.dPolicy = new _DERObjectIdentifier(params.policy);
        }
        if (typeof params.nonce == "object") {
            this.dNonce = new _DERInteger(params.nonce);
        }
        if (typeof params.certreq == "boolean") {
            this.certReq = params.certreq;
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.TimeStampReq, KJUR.asn1.ASN1Object);

/**
 * class for TSP TSTInfo ASN.1 object
 * @name KJUR.asn1.tsp.TSTInfo
 * @class class for TSP TSTInfo ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
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
 * @example
 * o = new KJUR.asn1.tsp.TSTInfo({
 *     policy:    '1.2.3.4.5',
 *     messageImprint: {hashAlg: 'sha256', hashMsgHex: '1abc...'},
 *     genTime:   {withMillis: true},     // OPTION
 *     accuracy:  {micros: 500},          // OPTION
 *     ordering:  true,                   // OPITON
 *     nonce:     {hex: '52fab1...'},     // OPTION
 *     tsa:       {str: '/C=US/O=TSA1'}   // OPITON
 * });
 */
KJUR.asn1.tsp.TSTInfo = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERInteger = _KJUR_asn1.DERInteger,
	_DERBoolean = _KJUR_asn1.DERBoolean,
	_DERGeneralizedTime = _KJUR_asn1.DERGeneralizedTime,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_MessageImprint = _KJUR_asn1_tsp.MessageImprint,
	_Accuracy = _KJUR_asn1_tsp.Accuracy,
        _X500Name = _KJUR_asn1.x509.X500Name;

    _KJUR_asn1_tsp.TSTInfo.superclass.constructor.call(this);

    this.dVersion = new _DERInteger({'int': 1});
    this.dPolicy = null;
    this.dMessageImprint = null;
    this.dSerialNumber = null;
    this.dGenTime = null;
    this.dAccuracy = null;
    this.dOrdering = null;
    this.dNonce = null;
    this.dTsa = null;

    this.getEncodedHex = function() {
        var a = [this.dVersion];

        if (this.dPolicy == null) throw "policy shall be specified.";
        a.push(this.dPolicy);

        if (this.dMessageImprint == null)
            throw "messageImprint shall be specified.";
        a.push(this.dMessageImprint);

        if (this.dSerialNumber == null)
            throw "serialNumber shall be specified.";
        a.push(this.dSerialNumber);

        if (this.dGenTime == null)
            throw "genTime shall be specified.";
        a.push(this.dGenTime);

        if (this.dAccuracy != null) a.push(this.dAccuracy);
        if (this.dOrdering != null) a.push(this.dOrdering);
        if (this.dNonce != null) a.push(this.dNonce);
        if (this.dTsa != null) a.push(this.dTsa);

        var seq = new _DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params.policy == "string") {
            if (! params.policy.match(/^[0-9.]+$/))
                throw "policy shall be oid like 0.1.4.134";
            this.dPolicy = new _DERObjectIdentifier({oid: params.policy});
        }
        if (params.messageImprint !== undefined) {
            this.dMessageImprint = new _MessageImprint(params.messageImprint);
        }
        if (params.serialNumber !== undefined) {
            this.dSerialNumber = new _DERInteger(params.serialNumber);
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
            this.dTsa = new _X500Name(params.tsa);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.TSTInfo, KJUR.asn1.ASN1Object);

/**
 * class for TSP TimeStampResp ASN.1 object
 * @name KJUR.asn1.tsp.TimeStampResp
 * @class class for TSP TimeStampResp ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
 * <pre>
 * TimeStampResp ::= SEQUENCE  {
 *    status                  PKIStatusInfo,
 *    timeStampToken          TimeStampToken     OPTIONAL  }
 * </pre>
 */
KJUR.asn1.tsp.TimeStampResp = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_ASN1Object = _KJUR_asn1.ASN1Object,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_PKIStatusInfo = _KJUR_asn1_tsp.PKIStatusInfo;

    _KJUR_asn1_tsp.TimeStampResp.superclass.constructor.call(this);

    this.dStatus = null;
    this.dTST = null;

    this.getEncodedHex = function() {
        if (this.dStatus == null)
            throw "status shall be specified";
        var a = [this.dStatus];
        if (this.dTST != null) a.push(this.dTST);
        var seq = new _DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params.status == "object") {
            this.dStatus = new _PKIStatusInfo(params.status);
        }
        if (params.tst !== undefined &&
            params.tst instanceof _ASN1Object) {
            this.dTST = params.tst.getContentInfo();
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.TimeStampResp, KJUR.asn1.ASN1Object);

// --- BEGIN OF RFC 2510 CMP -----------------------------------------------

/**
 * class for TSP PKIStatusInfo ASN.1 object
 * @name KJUR.asn1.tsp.PKIStatusInfo
 * @class class for TSP PKIStatusInfo ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
 * <pre>
 * PKIStatusInfo ::= SEQUENCE {
 *    status                  PKIStatus,
 *    statusString            PKIFreeText     OPTIONAL,
 *    failInfo                PKIFailureInfo  OPTIONAL  }
 * </pre>
 */
KJUR.asn1.tsp.PKIStatusInfo = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_PKIStatus = _KJUR_asn1_tsp.PKIStatus,
	_PKIFreeText = _KJUR_asn1_tsp.PKIFreeText,
	_PKIFailureInfo = _KJUR_asn1_tsp.PKIFailureInfo;

    _KJUR_asn1_tsp.PKIStatusInfo.superclass.constructor.call(this);

    this.dStatus = null;
    this.dStatusString = null;
    this.dFailureInfo = null;

    this.getEncodedHex = function() {
        if (this.dStatus == null)
            throw "status shall be specified";
        var a = [this.dStatus];
        if (this.dStatusString != null) a.push(this.dStatusString);
        if (this.dFailureInfo != null) a.push(this.dFailureInfo);
        var seq = new _DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params.status == "object") { // param for int
            this.dStatus = new _PKIStatus(params.status);
        }
        if (typeof params.statstr == "object") { // array of str
            this.dStatusString = 
                new _PKIFreeText({array: params.statstr});
        }
        if (typeof params.failinfo == "object") {
            this.dFailureInfo = 
                new _PKIFailureInfo(params.failinfo); // param for bitstr
        }
    };
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIStatusInfo, KJUR.asn1.ASN1Object);

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
 */
KJUR.asn1.tsp.PKIStatus = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERInteger = _KJUR_asn1.DERInteger,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_PKIStatus = _KJUR_asn1_tsp.PKIStatus;

    _KJUR_asn1_tsp.PKIStatus.superclass.constructor.call(this);

    var dStatus = null;

    this.getEncodedHex = function() {
        this.hTLV = this.dStatus.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (params.name !== undefined) {
            var list = _PKIStatus.valueList;
            if (list[params.name] === undefined)
                throw "name undefined: " + params.name;
            this.dStatus = 
                new _DERInteger({'int': list[params.name]});
        } else {
            this.dStatus = new _DERInteger(params);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIStatus, KJUR.asn1.ASN1Object);

KJUR.asn1.tsp.PKIStatus.valueList = {
    granted:                0,
    grantedWithMods:        1,
    rejection:              2,
    waiting:                3,
    revocationWarning:      4,
    revocationNotification: 5
};

/**
 * class for TSP PKIFreeText ASN.1 object
 * @name KJUR.asn1.tsp.PKIFreeText
 * @class class for TSP PKIFreeText ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
 * <pre>
 * PKIFreeText ::= SEQUENCE {
 *    SIZE (1..MAX) OF UTF8String }
 * </pre>
 */
KJUR.asn1.tsp.PKIFreeText = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERSequence = _KJUR_asn1.DERSequence,
	_DERUTF8String = _KJUR_asn1.DERUTF8String,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp;

    _KJUR_asn1_tsp.PKIFreeText.superclass.constructor.call(this);

    this.textList = [];

    this.getEncodedHex = function() {
        var a = [];
        for (var i = 0; i < this.textList.length; i++) {
            a.push(new _DERUTF8String({str: this.textList[i]}));
        }
        var seq = new _DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params.array == "object") {
            this.textList = params.array;
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIFreeText, KJUR.asn1.ASN1Object);

/**
 * class for TSP PKIFailureInfo ASN.1 object
 * @name KJUR.asn1.tsp.PKIFailureInfo
 * @class class for TSP PKIFailureInfo ASN.1 object
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.ASN1Object
 * @since jsrsasign 4.6.0 asn1tsp 1.0.0
 * @description
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
 */
KJUR.asn1.tsp.PKIFailureInfo = function(params) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERBitString = _KJUR_asn1.DERBitString,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_PKIFailureInfo = _KJUR_asn1_tsp.PKIFailureInfo;

    _PKIFailureInfo.superclass.constructor.call(this);

    this.value = null;

    this.getEncodedHex = function() {
        if (this.value == null)
            throw "value shall be specified";
        var binValue = new Number(this.value).toString(2);
        var dValue = new _DERBitString();
        dValue.setByBinaryString(binValue);
        this.hTLV = dValue.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params.name == "string") {
            var list = _PKIFailureInfo.valueList;
            if (list[params.name] === undefined)
                throw "name undefined: " + params.name;
            this.value = list[params.name];
        } else if (typeof params['int'] == "number") {
            this.value = params['int'];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIFailureInfo, KJUR.asn1.ASN1Object);

KJUR.asn1.tsp.PKIFailureInfo.valueList = {
    badAlg:                 0,
    badRequest:             2,
    badDataFormat:          5,
    timeNotAvailable:       14,
    unacceptedPolicy:       15,
    unacceptedExtension:    16,
    addInfoNotAvailable:    17,
    systemFailure:          25
};

// --- END OF RFC 2510 CMP -------------------------------------------

/**
 * abstract class for TimeStampToken generator
 * @name KJUR.asn1.tsp.AbstractTSAAdapter
 * @class abstract class for TimeStampToken generator
 * @param {Array} params associative array of parameters
 * @since jsrsasign 4.7.0 asn1tsp 1.0.1
 * @description
 */
KJUR.asn1.tsp.AbstractTSAAdapter = function(params) {
    this.getTSTHex = function(msgHex, hashAlg) {
        throw "not implemented yet";
    };
};

/**
 * class for simple TimeStampToken generator
 * @name KJUR.asn1.tsp.SimpleTSAAdapter
 * @class class for simple TimeStampToken generator
 * @param {Array} params associative array of parameters
 * @since jsrsasign 4.7.0 asn1tsp 1.0.1
 * @description
 */
KJUR.asn1.tsp.SimpleTSAAdapter = function(initParams) {
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
        this.params.tstInfo.messageImprint =
            {hashAlg: hashAlg, hashValue: hashHex};

        // serial
        this.params.tstInfo.serialNumber = {'int': this.serial++};

        // nonce
        var nonceValue = Math.floor(Math.random() * 1000000000);
        this.params.tstInfo.nonce = {'int': nonceValue};

        var obj = 
            _KJUR_asn1_tsp.TSPUtil.newTimeStampToken(this.params);
        return obj.getContentInfoEncodedHex();
    };

    if (initParams !== undefined) {
        this.params = initParams;
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.SimpleTSAAdapter,
                  KJUR.asn1.tsp.AbstractTSAAdapter);

/**
 * class for fixed TimeStampToken generator
 * @name KJUR.asn1.tsp.FixedTSAAdapter
 * @class class for fixed TimeStampToken generator
 * @param {Array} params associative array of parameters
 * @since jsrsasign 4.7.0 asn1tsp 1.0.1
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
KJUR.asn1.tsp.FixedTSAAdapter = function(initParams) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_hashHex = _KJUR.crypto.Util.hashHex; //o

    _KJUR_asn1_tsp.FixedTSAAdapter.superclass.constructor.call(this);
    this.params = null;

    this.getTSTHex = function(msgHex, hashAlg) {
        // fixed serialNumber
        // fixed nonce        
        var hashHex = _hashHex(msgHex, hashAlg);
        this.params.tstInfo.messageImprint =
            {hashAlg: hashAlg, hashValue: hashHex};
        var obj = 
            _KJUR_asn1_tsp.TSPUtil.newTimeStampToken(this.params);
        return obj.getContentInfoEncodedHex();
    };

    if (initParams !== undefined) {
        this.params = initParams;
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.FixedTSAAdapter,
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
 * generate TimeStampToken ASN.1 object specified by JSON parameters
 * @name newTimeStampToken
 * @memberOf KJUR.asn1.tsp.TSPUtil
 * @function
 * @param {Array} param JSON parameter to generate TimeStampToken
 * @return {KJUR.asn1.cms.SignedData} object just generated
 * @description
 * @example
 */
KJUR.asn1.tsp.TSPUtil.newTimeStampToken = function(param) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_KJUR_asn1_cms = _KJUR_asn1.cms,
	_KJUR_asn1_tsp = _KJUR_asn1.tsp,
	_TSTInfo = _KJUR_asn1.tsp.TSTInfo;

    var sd = new _KJUR_asn1_cms.SignedData();

    var dTSTInfo = new _TSTInfo(param.tstInfo);
    var tstInfoHex = dTSTInfo.getEncodedHex();
    sd.dEncapContentInfo.setContentValue({hex: tstInfoHex});
    sd.dEncapContentInfo.setContentType('tstinfo');

    if (typeof param.certs == "object") {
        for (var i = 0; i < param.certs.length; i++) {
            sd.addCertificatesByPEM(param.certs[i]);
        }
    }

    var si = sd.signerInfoList[0];
    si.setSignerIdentifier(param.signerCert);
    si.setForContentAndHash({sdObj: sd,
                             eciObj: sd.dEncapContentInfo,
                             hashAlg: param.hashAlg});
    var signingCertificate = 
        new _KJUR_asn1_cms.SigningCertificate({array: [param.signerCert]});
    si.dSignedAttrs.add(signingCertificate);

    si.sign(param.signerPrvKey, param.sigAlg);

    return sd;
};

/**
 * parse hexadecimal string of TimeStampReq
 * @name parseTimeStampReq
 * @memberOf KJUR.asn1.tsp.TSPUtil
 * @function
 * @param {String} hexadecimal string of TimeStampReq
 * @return {Array} JSON object of parsed parameters
 * @description
 * This method parses a hexadecimal string of TimeStampReq
 * and returns parsed their fields:
 * @example
 * var json = KJUR.asn1.tsp.TSPUtil.parseTimeStampReq("302602...");
 * // resulted DUMP of above 'json':
 * {mi: {hashAlg: 'sha256',          // MessageImprint hashAlg
 *       hashValue: 'a1a2a3a4...'},  // MessageImprint hashValue
 *  policy: '1.2.3.4.5',             // tsaPolicy (OPTION)
 *  nonce: '9abcf318...',            // nonce (OPTION)
 *  certreq: true}                   // certReq (OPTION)
 */
KJUR.asn1.tsp.TSPUtil.parseTimeStampReq = function(reqHex) {
    var _ASN1HEX = ASN1HEX;
    var _getChildIdx = _ASN1HEX.getChildIdx;
    var _getV = _ASN1HEX.getV;
    var _getTLV = _ASN1HEX.getTLV;
    var json = {};
    json.certreq = false;

    var idxList = _getChildIdx(reqHex, 0);

    if (idxList.length < 2)
        throw "TimeStampReq must have at least 2 items";

    var miHex = _getTLV(reqHex, idxList[1]);
    json.mi = KJUR.asn1.tsp.TSPUtil.parseMessageImprint(miHex); 

    for (var i = 2; i < idxList.length; i++) {
        var idx = idxList[i];
        var tag = reqHex.substr(idx, 2);
        if (tag == "06") { // case OID
            var policyHex = _getV(reqHex, idx);
            json.policy = _ASN1HEX.hextooidstr(policyHex);
        }
        if (tag == "02") { // case INTEGER
            json.nonce = _getV(reqHex, idx);
        }
        if (tag == "01") { // case BOOLEAN
            json.certreq = true;
        }
    }

    return json;
};

/**
 * parse hexadecimal string of MessageImprint
 * @name parseMessageImprint
 * @memberOf KJUR.asn1.tsp.TSPUtil
 * @function
 * @param {String} hexadecimal string of MessageImprint
 * @return {Array} JSON object of parsed parameters
 * @description
 * This method parses a hexadecimal string of MessageImprint
 * and returns parsed their fields:
 * @example
 * var json = KJUR.asn1.tsp.TSPUtil.parseMessageImprint("302602...");
 * // resulted DUMP of above 'json':
 * {hashAlg: 'sha256',          // MessageImprint hashAlg
 *  hashValue: 'a1a2a3a4...'}   // MessageImprint hashValue
 */
KJUR.asn1.tsp.TSPUtil.parseMessageImprint = function(miHex) {
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

    json.hashAlg = hashAlg;
    json.hashValue = _getV(miHex, hashValueIdx); 

    return json;
};

