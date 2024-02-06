/* ecdsa-modified-1.2.2.js (c) Stephan Thomas, Kenji Urushima | github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE
 */
/*
 * ecdsa-modified.js - modified Bitcoin.ECDSA class
 * 
 * Copyright (c) 2013-2021 Stefan Thomas (github.com/justmoon)
 *                         Kenji Urushima (kenji.urushima@gmail.com)
 * LICENSE
 *   https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE
 */

/**
 * @fileOverview
 * @name ecdsa-modified-1.0.js
 * @author Stefan Thomas (github.com/justmoon) and Kenji Urushima (kenji.urushima@gmail.com)
 * @version jsrsasign 10.5.16 ecdsa-modified 1.2.2 (2022-Apr-08)
 * @since jsrsasign 4.0
 * @license <a href="https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * class for EC key generation,  ECDSA signing and verifcation
 * @name KJUR.crypto.ECDSA
 * @class class for EC key generation,  ECDSA signing and verifcation
 * @description
 * <p>
 * CAUTION: Most of the case, you don't need to use this class except
 * for generating an EC key pair. Please use {@link KJUR.crypto.Signature} class instead.
 * </p>
 * <p>
 * This class was originally developped by Stefan Thomas for Bitcoin JavaScript library.
 * (See {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/ecdsa.js})
 * Currently this class supports following named curves and their aliases.
 * <ul>
 * <li>secp192k1</li>
 * <li>secp256r1, NIST P-256, P-256, prime256v1 (*)</li>
 * <li>secp256k1 (*)</li>
 * <li>secp384r1, NIST P-384, P-384 (*)</li>
 * <li>secp521r1, NIST P-521, P-521 (*)</li>
 * </ul>
 * </p>
 */
KJUR.crypto.ECDSA = function(params) {
    var curveName = "secp256r1";	// curve name default
    var ecparams = null;
    var prvKeyHex = null;
    var pubKeyHex = null;
    var _Error = Error,
	_BigInteger = BigInteger,
	_ECPointFp = ECPointFp,
	_KJUR_crypto_ECDSA = KJUR.crypto.ECDSA,
	_KJUR_crypto_ECParameterDB = KJUR.crypto.ECParameterDB,
	_getName = _KJUR_crypto_ECDSA.getName,
	_ASN1HEX = ASN1HEX,
	_getVbyListEx = _ASN1HEX.getVbyListEx,
	_isASN1HEX = _ASN1HEX.isASN1HEX;

    var rng = new SecureRandom();

    var P_OVER_FOUR = null;

    this.type = "EC";
    this.isPrivate = false;
    this.isPublic = false;

    function implShamirsTrick(P, k, Q, l) {
	var m = Math.max(k.bitLength(), l.bitLength());
	var Z = P.add2D(Q);
	var R = P.curve.getInfinity();

	for (var i = m - 1; i >= 0; --i) {
	    R = R.twice2D();

	    R.z = _BigInteger.ONE;

	    if (k.testBit(i)) {
		if (l.testBit(i)) {
		    R = R.add2D(Z);
		} else {
		    R = R.add2D(P);
		}
	    } else {
		if (l.testBit(i)) {
		    R = R.add2D(Q);
		}
	    }
	}
	
	return R;
    };

    //===========================
    // PUBLIC METHODS
    //===========================
    this.getBigRandom = function (limit) {
	return new _BigInteger(limit.bitLength(), rng)
	.mod(limit.subtract(_BigInteger.ONE))
	.add(_BigInteger.ONE)
	;
    };

    this.setNamedCurve = function(curveName) {
	this.ecparams = _KJUR_crypto_ECParameterDB.getByName(curveName);
	this.prvKeyHex = null;
	this.pubKeyHex = null;
	this.curveName = curveName;
    };

    this.setPrivateKeyHex = function(prvKeyHex) {
        this.isPrivate = true;
	this.prvKeyHex = prvKeyHex;
    };

    this.setPublicKeyHex = function(pubKeyHex) {
        this.isPublic = true;
	this.pubKeyHex = pubKeyHex;
    };

    /**
     * get X and Y hexadecimal string value of public key
     * @name getPublicKeyXYHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @return {Array} associative array of x and y value of public key
     * @since ecdsa-modified 1.0.5 jsrsasign 5.0.14
     * @example
     * ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1', 'pub': pubHex});
     * ec.getPublicKeyXYHex() &rarr; { x: '01bacf...', y: 'c3bc22...' }
     */
    this.getPublicKeyXYHex = function() {
	var h = this.pubKeyHex;
	if (h.substr(0, 2) !== "04")
	    throw "this method supports uncompressed format(04) only";

	var charlen = this.ecparams.keycharlen;
	if (h.length !== 2 + charlen * 2)
	    throw "malformed public key hex length";

	var result = {};
	result.x = h.substr(2, charlen);
	result.y = h.substr(2 + charlen);
	return result;
    };

    /**
     * get NIST curve short name such as "P-256" or "P-384"
     * @name getShortNISTPCurveName
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @return {String} short NIST P curve name such as "P-256" or "P-384" if it's NIST P curve otherwise null;
     * @since ecdsa-modified 1.0.5 jsrsasign 5.0.14
     * @example
     * ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1', 'pub': pubHex});
     * ec.getShortPCurveName() &rarr; "P-256";
     */
    this.getShortNISTPCurveName = function() {
	var s = this.curveName;
	if (s === "secp256r1" || s === "NIST P-256" ||
	    s === "P-256" || s === "prime256v1")
	    return "P-256";
	if (s === "secp384r1" || s === "NIST P-384" || s === "P-384")
	    return "P-384";
	if (s === "secp521r1" || s === "NIST P-521" || s === "P-521")
	    return "P-521";
	if (s === "secp256k1")
		return "secp256k1";
	return null;
    };

    /**
     * generate a EC key pair
     * @name generateKeyPairHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @return {Array} associative array of hexadecimal string of private and public key
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
     * var keypair = ec.generateKeyPairHex();
     * var pubhex = keypair.ecpubhex; // hexadecimal string of EC public key
     * var prvhex = keypair.ecprvhex; // hexadecimal string of EC private key (=d)
     */
    this.generateKeyPairHex = function() {
	var biN = this.ecparams['n'];
	var biPrv = this.getBigRandom(biN);
	var charlen = this.ecparams.keycharlen;
	var hPrv = ("0000000000" + biPrv.toString(16)).slice(- charlen);
	this.setPrivateKeyHex(hPrv);
	var hPub = this.generatePublicKeyHex();
	return {'ecprvhex': hPrv, 'ecpubhex': hPub};
    };

	/**
     * generate public key for EC private key
     * @name generatePublicKeyHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @return {String} associative array of hexadecimal string of private and public key
     * @example
     * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1', 'prv': prvHex});
     * var pubhex = ec.generatePublicKeyHex(); // hexadecimal string of EC public key
     * var pub ec.getPublicKeyXYHex() &rarr; { x: '01bacf...', y: 'c3bc22...' }
     */
	this.generatePublicKeyHex = function() {
		var biPrv = new _BigInteger(this.prvKeyHex, 16);
		var epPub = this.ecparams['G'].multiply(biPrv);
		var biX = epPub.getX().toBigInteger();
		var biY = epPub.getY().toBigInteger();
		var charlen = this.ecparams.keycharlen;;
		var hX   = ("0000000000" + biX.toString(16)).slice(- charlen);
		var hY   = ("0000000000" + biY.toString(16)).slice(- charlen);
		var hPub = "04" + hX + hY;
		this.setPublicKeyHex(hPub);
		return hPub;
	}

    this.signWithMessageHash = function(hashHex) {
	return this.signHex(hashHex, this.prvKeyHex);
    };

    /**
     * signing to message hash
     * @name signHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @param {String} hashHex hexadecimal string of hash value of signing message
     * @param {String} privHex hexadecimal string of EC private key
     * @return {String} hexadecimal string of ECDSA signature
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
     * var sigValue = ec.signHex(hash, prvKey);
     */
    this.signHex = function (hashHex, privHex) {
	var d = new _BigInteger(privHex, 16);
	var n = this.ecparams['n'];

	// message hash is truncated with curve key length (FIPS 186-4 6.4)
        var e = new _BigInteger(hashHex.substring(0, this.ecparams.keycharlen), 16);

	do {
	    var k = this.getBigRandom(n);
	    var G = this.ecparams['G'];
	    var Q = G.multiply(k);
	    var r = Q.getX().toBigInteger().mod(n);
	} while (r.compareTo(_BigInteger.ZERO) <= 0);

	var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

	return _KJUR_crypto_ECDSA.biRSSigToASN1Sig(r, s);
    };

    this.sign = function (hash, priv) {
	var d = priv;
	var n = this.ecparams['n'];
	var e = _BigInteger.fromByteArrayUnsigned(hash);

	do {
	    var k = this.getBigRandom(n);
	    var G = this.ecparams['G'];
	    var Q = G.multiply(k);
	    var r = Q.getX().toBigInteger().mod(n);
	} while (r.compareTo(BigInteger.ZERO) <= 0);

	var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
	return this.serializeSig(r, s);
    };

    this.verifyWithMessageHash = function(hashHex, sigHex) {
	return this.verifyHex(hashHex, sigHex, this.pubKeyHex);
    };

    /**
     * verifying signature with message hash and public key
     * @name verifyHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @param {String} hashHex hexadecimal string of hash value of signing message
     * @param {String} sigHex hexadecimal string of signature value
     * @param {String} pubkeyHex hexadecimal string of public key
     * @return {Boolean} true if the signature is valid, otherwise false
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
     * var result = ec.verifyHex(msgHashHex, sigHex, pubkeyHex);
     */
    this.verifyHex = function(hashHex, sigHex, pubkeyHex) {
	try {
	    var r,s;

	    var obj = _KJUR_crypto_ECDSA.parseSigHex(sigHex);
	    r = obj.r;
	    s = obj.s;
	    
	    var Q = _ECPointFp.decodeFromHex(this.ecparams['curve'], pubkeyHex);

	    // message hash is truncated with curve key length (FIPS 186-4 6.4)
            var e = new _BigInteger(hashHex.substring(0, this.ecparams.keycharlen), 16);

	    return this.verifyRaw(e, r, s, Q);
	} catch (ex) {
	    return false;
	}
    };

    this.verify = function (hash, sig, pubkey) {
	var r,s;
	if (Bitcoin.Util.isArray(sig)) {
	    var obj = this.parseSig(sig);
	    r = obj.r;
	    s = obj.s;
	} else if ("object" === typeof sig && sig.r && sig.s) {
	    r = sig.r;
	    s = sig.s;
	} else {
	    throw "Invalid value for signature";
	}

	var Q;
	if (pubkey instanceof ECPointFp) {
	    Q = pubkey;
	} else if (Bitcoin.Util.isArray(pubkey)) {
	    Q = _ECPointFp.decodeFrom(this.ecparams['curve'], pubkey);
	} else {
	    throw "Invalid format for pubkey value, must be byte array or ECPointFp";
	}
	var e = _BigInteger.fromByteArrayUnsigned(hash);

	return this.verifyRaw(e, r, s, Q);
    };

    this.verifyRaw = function (e, r, s, Q) {
	var n = this.ecparams['n'];
	var G = this.ecparams['G'];

	if (r.compareTo(_BigInteger.ONE) < 0 ||
	    r.compareTo(n) >= 0)
	    return false;

	if (s.compareTo(_BigInteger.ONE) < 0 ||
	    s.compareTo(n) >= 0)
	    return false;

	var c = s.modInverse(n);

	var u1 = e.multiply(c).mod(n);
	var u2 = r.multiply(c).mod(n);

	// TODO(!!!): For some reason Shamir's trick isn't working with
	// signed message verification!? Probably an implementation
	// error!
	//var point = implShamirsTrick(G, u1, Q, u2);
	var point = G.multiply(u1).add(Q.multiply(u2));

	var v = point.getX().toBigInteger().mod(n);

	return v.equals(r);
    };

    /**
     * Serialize a signature into DER format.
     *
     * Takes two BigIntegers representing r and s and returns a byte array.
     */
    this.serializeSig = function (r, s) {
	var rBa = r.toByteArraySigned();
	var sBa = s.toByteArraySigned();

	var sequence = [];
	sequence.push(0x02); // INTEGER
	sequence.push(rBa.length);
	sequence = sequence.concat(rBa);

	sequence.push(0x02); // INTEGER
	sequence.push(sBa.length);
	sequence = sequence.concat(sBa);

	sequence.unshift(sequence.length);
	sequence.unshift(0x30); // SEQUENCE
	return sequence;
    };

    /**
     * Parses a byte array containing a DER-encoded signature.
     *
     * This function will return an object of the form:
     *
     * {
     *   r: BigInteger,
     *   s: BigInteger
     * }
     */
    this.parseSig = function (sig) {
	var cursor;
	if (sig[0] != 0x30)
	    throw new Error("Signature not a valid DERSequence");

	cursor = 2;
	if (sig[cursor] != 0x02)
	    throw new Error("First element in signature must be a DERInteger");;
	var rBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

	cursor += 2+sig[cursor+1];
	if (sig[cursor] != 0x02)
	    throw new Error("Second element in signature must be a DERInteger");
	var sBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

	cursor += 2+sig[cursor+1];

	//if (cursor != sig.length)
	//  throw new Error("Extra bytes in signature");

	var r = _BigInteger.fromByteArrayUnsigned(rBa);
	var s = _BigInteger.fromByteArrayUnsigned(sBa);

	return {r: r, s: s};
    };

    this.parseSigCompact = function (sig) {
	if (sig.length !== 65) {
	    throw "Signature has the wrong length";
	}

	// Signature is prefixed with a type byte storing three bits of
	// information.
	var i = sig[0] - 27;
	if (i < 0 || i > 7) {
	    throw "Invalid signature type";
	}

	var n = this.ecparams['n'];
	var r = _BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
	var s = _BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);

	return {r: r, s: s, i: i};
    };

    /**
     * read an ASN.1 hexadecimal string of PKCS#1/5 plain ECC private key<br/>
     * @name readPKCS5PrvKeyHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @param {String} h hexadecimal string of PKCS#1/5 ECC private key
     * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0
     */
    this.readPKCS5PrvKeyHex = function(h) {
	if (_isASN1HEX(h) === false)
	    throw new Error("not ASN.1 hex string");

	var hCurve, hPrv, hPub;
	try {
	    hCurve = _getVbyListEx(h, 0, ["[0]", 0], "06");
	    hPrv   = _getVbyListEx(h, 0, [1], "04");
	    try {
		hPub = _getVbyListEx(h, 0, ["[1]", 0], "03");
	    } catch(ex) {};
	} catch(ex) {
	    throw new Error("malformed PKCS#1/5 plain ECC private key");
	}

	this.curveName = _getName(hCurve);
	if (this.curveName === undefined) throw "unsupported curve name";

	this.setNamedCurve(this.curveName);
	this.setPublicKeyHex(hPub);
	this.setPrivateKeyHex(hPrv);
        this.isPublic = false;
    };

    /**
     * read an ASN.1 hexadecimal string of PKCS#8 plain ECC private key<br/>
     * @name readPKCS8PrvKeyHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @param {String} h hexadecimal string of PKCS#8 ECC private key
     * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0
     */
    this.readPKCS8PrvKeyHex = function(h) {
	if (_isASN1HEX(h) === false)
	    throw new _Error("not ASN.1 hex string");

	var hECOID, hCurve, hPrv, hPub;
	try {
	    hECOID = _getVbyListEx(h, 0, [1, 0], "06");
	    hCurve = _getVbyListEx(h, 0, [1, 1], "06");
	    hPrv   = _getVbyListEx(h, 0, [2, 0, 1], "04");
	    try {
		hPub = _getVbyListEx(h, 0, [2, 0, "[1]", 0], "03"); //.substr(2);
	    } catch(ex) {};
	} catch(ex) {
	    throw new _Error("malformed PKCS#8 plain ECC private key");
	}

	this.curveName = _getName(hCurve);
	if (this.curveName === undefined)
	    throw new _Error("unsupported curve name");

	this.setNamedCurve(this.curveName);
	this.setPublicKeyHex(hPub);
	this.setPrivateKeyHex(hPrv);
        this.isPublic = false;
    };

    /**
     * read an ASN.1 hexadecimal string of PKCS#8 ECC public key<br/>
     * @name readPKCS8PubKeyHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @param {String} h hexadecimal string of PKCS#8 ECC public key
     * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0
     */
    this.readPKCS8PubKeyHex = function(h) {
	if (_isASN1HEX(h) === false)
	    throw new _Error("not ASN.1 hex string");

	var hECOID, hCurve, hPub;
	try {
	    hECOID = _getVbyListEx(h, 0, [0, 0], "06");
	    hCurve = _getVbyListEx(h, 0, [0, 1], "06");
	    hPub = _getVbyListEx(h, 0, [1], "03"); //.substr(2); 
	} catch(ex) {
	    throw new _Error("malformed PKCS#8 ECC public key");
	}

	this.curveName = _getName(hCurve);
	if (this.curveName === null)
	    throw new _Error("unsupported curve name");

	this.setNamedCurve(this.curveName);
	this.setPublicKeyHex(hPub);
    };

    /**
     * read an ASN.1 hexadecimal string of X.509 ECC public key certificate<br/>
     * @name readCertPubKeyHex
     * @memberOf KJUR.crypto.ECDSA#
     * @function
     * @param {String} h hexadecimal string of X.509 ECC public key certificate
     * @param {Integer} nthPKI nth index of publicKeyInfo. (DEFAULT: 6 for X509v3)
     * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0
     */
    this.readCertPubKeyHex = function(h, nthPKI) {
	if (_isASN1HEX(h) === false)
	    throw new _Error("not ASN.1 hex string");

	var hCurve, hPub;
	try {
	    hCurve = _getVbyListEx(h, 0, [0, 5, 0, 1], "06");
	    hPub = _getVbyListEx(h, 0, [0, 5, 1], "03");
	} catch(ex) {
	    throw new _Error("malformed X.509 certificate ECC public key");
	}

	this.curveName = _getName(hCurve);
	if (this.curveName === null)
	    throw new _Error("unsupported curve name");

	this.setNamedCurve(this.curveName);
	this.setPublicKeyHex(hPub);
    };

    /*
     * Recover a public key from a signature.
     *
     * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
     * Key Recovery Operation".
     *
     * http://www.secg.org/download/aid-780/sec1-v2.pdf
     */
    /*
    recoverPubKey: function (r, s, hash, i) {
	// The recovery parameter i has two bits.
	i = i & 3;

	// The less significant bit specifies whether the y coordinate
	// of the compressed point is even or not.
	var isYEven = i & 1;

	// The more significant bit specifies whether we should use the
	// first or second candidate key.
	var isSecondKey = i >> 1;

	var n = this.ecparams['n'];
	var G = this.ecparams['G'];
	var curve = this.ecparams['curve'];
	var p = curve.getQ();
	var a = curve.getA().toBigInteger();
	var b = curve.getB().toBigInteger();

	// We precalculate (p + 1) / 4 where p is if the field order
	if (!P_OVER_FOUR) {
	    P_OVER_FOUR = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
	}

	// 1.1 Compute x
	var x = isSecondKey ? r.add(n) : r;

	// 1.3 Convert x to point
	var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
	var beta = alpha.modPow(P_OVER_FOUR, p);

	var xorOdd = beta.isEven() ? (i % 2) : ((i+1) % 2);
	// If beta is even, but y isn't or vice versa, then convert it,
	// otherwise we're done and y == beta.
	var y = (beta.isEven() ? !isYEven : isYEven) ? beta : p.subtract(beta);

	// 1.4 Check that nR is at infinity
	var R = new ECPointFp(curve,
			      curve.fromBigInteger(x),
			      curve.fromBigInteger(y));
	R.validate();

	// 1.5 Compute e from M
	var e = BigInteger.fromByteArrayUnsigned(hash);
	var eNeg = BigInteger.ZERO.subtract(e).mod(n);

	// 1.6 Compute Q = r^-1 (sR - eG)
	var rInv = r.modInverse(n);
	var Q = implShamirsTrick(R, s, G, eNeg).multiply(rInv);

	Q.validate();
	if (!this.verifyRaw(e, r, s, Q)) {
	    throw "Pubkey recovery unsuccessful";
	}

	var pubKey = new Bitcoin.ECKey();
	pubKey.pub = Q;
	return pubKey;
    },
    */

    /*
     * Calculate pubkey extraction parameter.
     *
     * When extracting a pubkey from a signature, we have to
     * distinguish four different cases. Rather than putting this
     * burden on the verifier, Bitcoin includes a 2-bit value with the
     * signature.
     *
     * This function simply tries all four cases and returns the value
     * that resulted in a successful pubkey recovery.
     */
    /*
    calcPubkeyRecoveryParam: function (address, r, s, hash) {
	for (var i = 0; i < 4; i++) {
	    try {
		var pubkey = Bitcoin.ECDSA.recoverPubKey(r, s, hash, i);
		if (pubkey.getBitcoinAddress().toString() == address) {
		    return i;
		}
	    } catch (e) {}
	}
	throw "Unable to find valid recovery factor";
    }
    */

    if (params !== undefined) {
	if (params['curve'] !== undefined) {
	    this.curveName = params['curve'];
	}
    }
    if (this.curveName === undefined) this.curveName = curveName;
    this.setNamedCurve(this.curveName);
    if (params !== undefined) {
	if (params.prv !== undefined) this.setPrivateKeyHex(params.prv);
	if (params.pub !== undefined) this.setPublicKeyHex(params.pub);
    }
};

/**
 * parse ASN.1 DER encoded ECDSA signature
 * @name parseSigHex
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} sigHex hexadecimal string of ECDSA signature value
 * @return {Array} associative array of signature field r and s of BigInteger
 * @since ecdsa-modified 1.0.1
 * @see {@link KJUR.crypto.ECDSA.parseSigHexInHexRS}
 * @see {@link ASN1HEX.checkStrictDER}
 * @throws Error when signature value is malformed.
 * @example
 * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
 * var sig = ec.parseSigHex('30...');
 * var biR = sig.r; // BigInteger object for 'r' field of signature.
 * var biS = sig.s; // BigInteger object for 's' field of signature.
 */
KJUR.crypto.ECDSA.parseSigHex = function(sigHex) {
    var p = KJUR.crypto.ECDSA.parseSigHexInHexRS(sigHex);
    var biR = new BigInteger(p.r, 16);
    var biS = new BigInteger(p.s, 16);
    
    return {'r': biR, 's': biS};
};

/**
 * parse ASN.1 DER encoded ECDSA signature
 * @name parseSigHexInHexRS
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} sigHex hexadecimal string of ECDSA signature value
 * @return {Array} associative array of signature field r and s in hexadecimal
 * @since ecdsa-modified 1.0.3
 * @see {@link KJUR.crypto.ECDSA.parseSigHex}
 * @see {@link ASN1HEX.checkStrictDER}
 * @throws Error when signature value is malformed.
 * @example
 * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
 * var sig = ec.parseSigHexInHexRS('30...');
 * var hR = sig.r; // hexadecimal string for 'r' field of signature.
 * var hS = sig.s; // hexadecimal string for 's' field of signature.
 */
KJUR.crypto.ECDSA.parseSigHexInHexRS = function(sigHex) {
    var _ASN1HEX = ASN1HEX,
	_getChildIdx = _ASN1HEX.getChildIdx,
	_getV = _ASN1HEX.getV;

    // 1. strict DER check
    _ASN1HEX.checkStrictDER(sigHex, 0);

    // 2. ASN.1 Sequence Check
    if (sigHex.substr(0, 2) != "30")
	throw new Error("signature is not a ASN.1 sequence");

    // 2. Items of ASN.1 Sequence Check
    var a = _getChildIdx(sigHex, 0);
    if (a.length != 2)
	throw new Error("signature shall have two elements");

    // 3. Integer tag check
    var iTLV1 = a[0];
    var iTLV2 = a[1];

    if (sigHex.substr(iTLV1, 2) != "02")
	throw new Error("1st item not ASN.1 integer");
    if (sigHex.substr(iTLV2, 2) != "02")
	throw new Error("2nd item not ASN.1 integer");

    // 4. getting value and least zero check for DER
    var hR = _getV(sigHex, iTLV1);
    var hS = _getV(sigHex, iTLV2);

    return {'r': hR, 's': hS};
};

/**
 * convert hexadecimal ASN.1 encoded signature to concatinated signature
 * @name asn1SigToConcatSig
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} asn1Hex hexadecimal string of ASN.1 encoded ECDSA signature value
 * @return {String} r-s concatinated format of ECDSA signature value
 * @throws Error when signature length is unsupported
 * @since ecdsa-modified 1.0.3
 */
KJUR.crypto.ECDSA.asn1SigToConcatSig = function(asn1Sig) {
    var pSig = KJUR.crypto.ECDSA.parseSigHexInHexRS(asn1Sig);
    var hR = pSig.r;
    var hS = pSig.s;

	// P-521 special case (65-66 bytes are allowed)
	if (hR.length >= 130 && hR.length <= 134) {
		if (hR.length % 2 != 0) {
			throw Error("unknown ECDSA sig r length error");
		}
		if (hS.length % 2 != 0) {
			throw Error("unknown ECDSA sig s length error");
		}
		if (hR.substr(0, 2) == "00") hR = hR.substr(2);
		if (hS.substr(0, 2) == "00") hS = hS.substr(2);

		// make sure they have the same length
		var length = Math.max(hR.length, hS.length);
		hR = ("000000" + hR).slice(- length);
		hS = ("000000" + hS).slice(- length);

		return hR + hS;
	}

    // R and S length is assumed multiple of 128bit(32chars in hex).
    // If leading is "00" and modulo of length is 2(chars) then
    // leading "00" is for two's complement and will be removed.
    if (hR.substr(0, 2) == "00" && (hR.length % 32) == 2)
	hR = hR.substr(2);

    if (hS.substr(0, 2) == "00" && (hS.length % 32) == 2)
	hS = hS.substr(2);

    // R and S length is assumed multiple of 128bit(32chars in hex).
    // If missing two chars then it will be padded by "00".
    if ((hR.length % 32) == 30) hR = "00" + hR;
    if ((hS.length % 32) == 30) hS = "00" + hS;

    // If R and S length is not still multiple of 128bit(32 chars),
    // then error
    if (hR.length % 32 != 0)
	throw Error("unknown ECDSA sig r length error");
    if (hS.length % 32 != 0)
	throw Error("unknown ECDSA sig s length error");

    return hR + hS;
};

/**
 * convert hexadecimal concatinated signature to ASN.1 encoded signature
 * @name concatSigToASN1Sig
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} concatSig r-s concatinated format of ECDSA signature value
 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
 * @throws Error when signature length is unsupported
 * @since ecdsa-modified 1.0.3
 */
KJUR.crypto.ECDSA.concatSigToASN1Sig = function(concatSig) {
	if (concatSig.length % 4 != 0) {
		throw Error("unknown ECDSA concatinated r-s sig length error");
	}

    var hR = concatSig.substr(0, concatSig.length / 2);
    var hS = concatSig.substr(concatSig.length / 2);
    return KJUR.crypto.ECDSA.hexRSSigToASN1Sig(hR, hS);
};

/**
 * convert hexadecimal R and S value of signature to ASN.1 encoded signature
 * @name hexRSSigToASN1Sig
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} hR hexadecimal string of R field of ECDSA signature value
 * @param {String} hS hexadecimal string of S field of ECDSA signature value
 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
 * @since ecdsa-modified 1.0.3
 */
KJUR.crypto.ECDSA.hexRSSigToASN1Sig = function(hR, hS) {
    var biR = new BigInteger(hR, 16);
    var biS = new BigInteger(hS, 16);
    return KJUR.crypto.ECDSA.biRSSigToASN1Sig(biR, biS);
};

/**
 * convert R and S BigInteger object of signature to ASN.1 encoded signature
 * @name biRSSigToASN1Sig
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {BigInteger} biR BigInteger object of R field of ECDSA signature value
 * @param {BigInteger} biS BIgInteger object of S field of ECDSA signature value
 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
 * @since ecdsa-modified 1.0.3
 */
KJUR.crypto.ECDSA.biRSSigToASN1Sig = function(biR, biS) {
    var _KJUR_asn1 = KJUR.asn1;
    var derR = new _KJUR_asn1.DERInteger({'bigint': biR});
    var derS = new _KJUR_asn1.DERInteger({'bigint': biS});
    var derSeq = new _KJUR_asn1.DERSequence({'array': [derR, derS]});
    return derSeq.tohex();
};

/**
 * static method to get normalized EC curve name from curve name or hexadecimal OID value
 * @name getName
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} s curve name (ex. P-256) or hexadecimal OID value (ex. 2a86...)
 * @return {String} normalized EC curve name (ex. secp256r1) 
 * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0 
 * @description
 * This static method returns normalized EC curve name 
 * which is supported in jsrsasign
 * from curve name or hexadecimal OID value.
 * When curve is not supported in jsrsasign, this method returns null.
 * Normalized name will be "secp*" in jsrsasign.
 * @example
 * KJUR.crypto.ECDSA.getName("2b8104000a") &rarr; "secp256k1"
 * KJUR.crypto.ECDSA.getName("NIST P-256") &rarr; "secp256r1"
 * KJUR.crypto.ECDSA.getName("P-521") &rarr; undefined // not supported
 */
KJUR.crypto.ECDSA.getName = function(s) {
    if (s === "2b8104001f") return "secp192k1"; // 1.3.132.0.31
    if (s === "2a8648ce3d030107") return "secp256r1"; // 1.2.840.10045.3.1.7
    if (s === "2b8104000a") return "secp256k1"; // 1.3.132.0.10
    if (s === "2b81040021") return "secp224r1"; // 1.3.132.0.33
    if (s === "2b81040022") return "secp384r1"; // 1.3.132.0.34
	if (s === "2b81040023") return "secp521r1"; // 1.3.132.0.35
    if ("|secp256r1|NIST P-256|P-256|prime256v1|".indexOf(s) !== -1) return "secp256r1";
    if ("|secp256k1|".indexOf(s) !== -1) return "secp256k1";
    if ("|secp224r1|NIST P-224|P-224|".indexOf(s) !== -1) return "secp224r1";
    if ("|secp384r1|NIST P-384|P-384|".indexOf(s) !== -1) return "secp384r1";
	if ("|secp521r1|NIST P-521|P-521|".indexOf(s) !== -1) return "secp521r1";
    return null;
};



