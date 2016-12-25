/*! crypto-1.1.11.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * crypto.js - Cryptographic Algorithm Provider class
 *
 * Copyright (c) 2013-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name crypto-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.1.11 (2016-Dec-25)
 * @since jsrsasign 2.2
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
/**
 * kjur's cryptographic algorithm provider library name space
 * <p>
 * This namespace privides following crytpgrahic classes.
 * <ul>
 * <li>{@link KJUR.crypto.MessageDigest} - Java JCE(cryptograhic extension) style MessageDigest class</li>
 * <li>{@link KJUR.crypto.Signature} - Java JCE(cryptograhic extension) style Signature class</li>
 * <li>{@link KJUR.crypto.Cipher} - class for encrypting and decrypting data</li>
 * <li>{@link KJUR.crypto.Util} - cryptographic utility functions and properties</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.crypto
 * @namespace
 */
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.Util
 * @class static object for cryptographic function utilities
 * @property {Array} DIGESTINFOHEAD PKCS#1 DigestInfo heading hexadecimal bytes for each hash algorithms
 * @property {Array} DEFAULTPROVIDER associative array of default provider name for each hash and signature algorithms
 * @description
 */
KJUR.crypto.Util = new function() {
    this.DIGESTINFOHEAD = {
	'sha1':      "3021300906052b0e03021a05000414",
        'sha224':    "302d300d06096086480165030402040500041c",
	'sha256':    "3031300d060960864801650304020105000420",
	'sha384':    "3041300d060960864801650304020205000430",
	'sha512':    "3051300d060960864801650304020305000440",
	'md2':       "3020300c06082a864886f70d020205000410",
	'md5':       "3020300c06082a864886f70d020505000410",
	'ripemd160': "3021300906052b2403020105000414",
    };

    /*
     * @since crypto 1.1.1
     */
    this.DEFAULTPROVIDER = {
	'md5':			'cryptojs',
	'sha1':			'cryptojs',
	'sha224':		'cryptojs',
	'sha256':		'cryptojs',
	'sha384':		'cryptojs',
	'sha512':		'cryptojs',
	'ripemd160':		'cryptojs',
	'hmacmd5':		'cryptojs',
	'hmacsha1':		'cryptojs',
	'hmacsha224':		'cryptojs',
	'hmacsha256':		'cryptojs',
	'hmacsha384':		'cryptojs',
	'hmacsha512':		'cryptojs',
	'hmacripemd160':	'cryptojs',

	'MD5withRSA':		'cryptojs/jsrsa',
	'SHA1withRSA':		'cryptojs/jsrsa',
	'SHA224withRSA':	'cryptojs/jsrsa',
	'SHA256withRSA':	'cryptojs/jsrsa',
	'SHA384withRSA':	'cryptojs/jsrsa',
	'SHA512withRSA':	'cryptojs/jsrsa',
	'RIPEMD160withRSA':	'cryptojs/jsrsa',

	'MD5withECDSA':		'cryptojs/jsrsa',
	'SHA1withECDSA':	'cryptojs/jsrsa',
	'SHA224withECDSA':	'cryptojs/jsrsa',
	'SHA256withECDSA':	'cryptojs/jsrsa',
	'SHA384withECDSA':	'cryptojs/jsrsa',
	'SHA512withECDSA':	'cryptojs/jsrsa',
	'RIPEMD160withECDSA':	'cryptojs/jsrsa',

	'SHA1withDSA':		'cryptojs/jsrsa',
	'SHA224withDSA':	'cryptojs/jsrsa',
	'SHA256withDSA':	'cryptojs/jsrsa',

	'MD5withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA1withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA224withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA256withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA384withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA512withRSAandMGF1':		'cryptojs/jsrsa',
	'RIPEMD160withRSAandMGF1':	'cryptojs/jsrsa',
    };

    /*
     * @since crypto 1.1.2
     */
    this.CRYPTOJSMESSAGEDIGESTNAME = {
	'md5':		CryptoJS.algo.MD5,
	'sha1':		CryptoJS.algo.SHA1,
	'sha224':	CryptoJS.algo.SHA224,
	'sha256':	CryptoJS.algo.SHA256,
	'sha384':	CryptoJS.algo.SHA384,
	'sha512':	CryptoJS.algo.SHA512,
	'ripemd160':	CryptoJS.algo.RIPEMD160
    };

    /**
     * get hexadecimal DigestInfo
     * @name getDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @return {String} hexadecimal string DigestInfo ASN.1 structure
     */
    this.getDigestInfoHex = function(hHash, alg) {
	if (typeof this.DIGESTINFOHEAD[alg] == "undefined")
	    throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
	return this.DIGESTINFOHEAD[alg] + hHash;
    };

    /**
     * get PKCS#1 padded hexadecimal DigestInfo
     * @name getPaddedDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value of message to be signed
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @param {Integer} keySize key bit length (ex. 1024)
     * @return {String} hexadecimal string of PKCS#1 padded DigestInfo
     */
    this.getPaddedDigestInfoHex = function(hHash, alg, keySize) {
	var hDigestInfo = this.getDigestInfoHex(hHash, alg);
	var pmStrLen = keySize / 4; // minimum PM length

	if (hDigestInfo.length + 22 > pmStrLen) // len(0001+ff(*8)+00+hDigestInfo)=22
	    throw "key is too short for SigAlg: keylen=" + keySize + "," + alg;

	var hHead = "0001";
	var hTail = "00" + hDigestInfo;
	var hMid = "";
	var fLen = pmStrLen - hHead.length - hTail.length;
	for (var i = 0; i < fLen; i += 2) {
	    hMid += "ff";
	}
	var hPaddedMessage = hHead + hMid + hTail;
	return hPaddedMessage;
    };

    /**
     * get hexadecimal hash of string with specified algorithm
     * @name hashString
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @param {String} alg hash algorithm name
     * @return {String} hexadecimal string of hash value
     * @since 1.1.1
     */
    this.hashString = function(s, alg) {
        var md = new KJUR.crypto.MessageDigest({'alg': alg});
        return md.digestString(s);
    };

    /**
     * get hexadecimal hash of hexadecimal string with specified algorithm
     * @name hashHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} sHex input hexadecimal string to be hashed
     * @param {String} alg hash algorithm name
     * @return {String} hexadecimal string of hash value
     * @since 1.1.1
     */
    this.hashHex = function(sHex, alg) {
        var md = new KJUR.crypto.MessageDigest({'alg': alg});
        return md.digestHex(sHex);
    };

    /**
     * get hexadecimal SHA1 hash of string
     * @name sha1
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha1 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha1', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal SHA256 hash of string
     * @name sha256
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha256 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    this.sha256Hex = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestHex(s);
    };

    /**
     * get hexadecimal SHA512 hash of string
     * @name sha512
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha512 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    this.sha512Hex = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestHex(s);
    };

};

/**
 * get hexadecimal MD5 hash of string
 * @name md5
 * @memberOf KJUR.crypto.Util
 * @function
 * @param {String} s input string to be hashed
 * @return {String} hexadecimal string of hash value
 * @since 1.0.3
 * @example
 * Util.md5('aaa') &rarr; 47bce5c74f589f4867dbd57e9ca9f808
 */
KJUR.crypto.Util.md5 = function(s) {
    var md = new KJUR.crypto.MessageDigest({'alg':'md5', 'prov':'cryptojs'});
    return md.digestString(s);
};

/**
 * get hexadecimal RIPEMD160 hash of string
 * @name ripemd160
 * @memberOf KJUR.crypto.Util
 * @function
 * @param {String} s input string to be hashed
 * @return {String} hexadecimal string of hash value
 * @since 1.0.3
 * @example
 * KJUR.crypto.Util.ripemd160("aaa") &rarr; 08889bd7b151aa174c21f33f59147fa65381edea
 */
KJUR.crypto.Util.ripemd160 = function(s) {
    var md = new KJUR.crypto.MessageDigest({'alg':'ripemd160', 'prov':'cryptojs'});
    return md.digestString(s);
};

// @since jsrsasign 7.0.0 crypto 1.1.11
KJUR.crypto.Util.SECURERANDOMGEN = new SecureRandom();

/**
 * get hexadecimal string of random value from with specified byte length<br/>
 * @name getRandomHexOfNbytes
 * @memberOf KJUR.crypto.Util
 * @function
 * @param {Integer} n length of bytes of random
 * @return {String} hexadecimal string of random
 * @since jsrsasign 7.0.0 crypto 1.1.11
 * @example
 * KJUR.crypto.Util.getRandomHexOfNbytes(3) &rarr; "6314af", "000000" or "001fb4"
 * KJUR.crypto.Util.getRandomHexOfNbytes(128) &rarr; "8fbc..." in 1024bits 
 */
KJUR.crypto.Util.getRandomHexOfNbytes = function(n) {
    var ba = new Array(n);
    KJUR.crypto.Util.SECURERANDOMGEN.nextBytes(ba);
    return BAtohex(ba);
};

/**
 * get BigInteger object of random value from with specified byte length<br/>
 * @name getRandomBigIntegerOfNbytes
 * @memberOf KJUR.crypto.Util
 * @function
 * @param {Integer} n length of bytes of random
 * @return {BigInteger} BigInteger object of specified random value
 * @since jsrsasign 7.0.0 crypto 1.1.11
 * @example
 * KJUR.crypto.Util.getRandomBigIntegerOfNbytes(3) &rarr; 6314af of BigInteger
 * KJUR.crypto.Util.getRandomBigIntegerOfNbytes(128) &rarr; 8fbc... of BigInteger
 */
KJUR.crypto.Util.getRandomBigIntegerOfNbytes = function(n) {
    return new BigInteger(KJUR.crypto.Util.getRandomHexOfNbytes(n), 16);
};

/**
 * get hexadecimal string of random value from with specified bit length<br/>
 * @name getRandomHexOfNbits
 * @memberOf KJUR.crypto.Util
 * @function
 * @param {Integer} n length of bits of random
 * @return {String} hexadecimal string of random
 * @since jsrsasign 7.0.0 crypto 1.1.11
 * @example
 * KJUR.crypto.Util.getRandomHexOfNbits(24) &rarr; "6314af", "000000" or "001fb4"
 * KJUR.crypto.Util.getRandomHexOfNbits(1024) &rarr; "8fbc..." in 1024bits 
 */
KJUR.crypto.Util.getRandomHexOfNbits = function(n) {
    var n_remainder = n % 8;
    var n_quotient = (n - n_remainder) / 8;
    var ba = new Array(n_quotient + 1);
    KJUR.crypto.Util.SECURERANDOMGEN.nextBytes(ba);
    ba[0] = (((255 << n_remainder) & 255) ^ 255) & ba[0];
    return BAtohex(ba);
};

/**
 * get BigInteger object of random value from with specified bit length<br/>
 * @name getRandomBigIntegerOfNbits
 * @memberOf KJUR.crypto.Util
 * @function
 * @param {Integer} n length of bits of random
 * @return {BigInteger} BigInteger object of specified random value
 * @since jsrsasign 7.0.0 crypto 1.1.11
 * @example
 * KJUR.crypto.Util.getRandomBigIntegerOfNbits(24) &rarr; 6314af of BigInteger
 * KJUR.crypto.Util.getRandomBigIntegerOfNbits(1024) &rarr; 8fbc... of BigInteger
 */
KJUR.crypto.Util.getRandomBigIntegerOfNbits = function(n) {
    return new BigInteger(KJUR.crypto.Util.getRandomHexOfNbits(n), 16);
};

/**
 * get BigInteger object of random value from zero to max value<br/>
 * @name getRandomBigIntegerZeroToMax
 * @memberOf KJUR.crypto.Util
 * @function
 * @param {BigInteger} biMax max value of BigInteger object for random value
 * @return {BigInteger} BigInteger object of specified random value
 * @since jsrsasign 7.0.0 crypto 1.1.11
 * @description
 * This static method generates a BigInteger object with random value
 * greater than or equal to zero and smaller than or equal to biMax
 * (i.e. 0 &le; result &le; biMax).
 * @example
 * biMax = new BigInteger("3fa411...", 16);
 * KJUR.crypto.Util.getRandomBigIntegerZeroToMax(biMax) &rarr; 8fbc... of BigInteger
 */
KJUR.crypto.Util.getRandomBigIntegerZeroToMax = function(biMax) {
    var bitLenMax = biMax.bitLength();
    while (1) {
	var biRand = KJUR.crypto.Util.getRandomBigIntegerOfNbits(bitLenMax);
	if (biMax.compareTo(biRand) != -1) return biRand;
    }
};

/**
 * get BigInteger object of random value from min value to max value<br/>
 * @name getRandomBigIntegerMinToMax
 * @memberOf KJUR.crypto.Util
 * @function
 * @param {BigInteger} biMin min value of BigInteger object for random value
 * @param {BigInteger} biMax max value of BigInteger object for random value
 * @return {BigInteger} BigInteger object of specified random value
 * @since jsrsasign 7.0.0 crypto 1.1.11
 * @description
 * This static method generates a BigInteger object with random value
 * greater than or equal to biMin and smaller than or equal to biMax
 * (i.e. biMin &le; result &le; biMax).
 * @example
 * biMin = new BigInteger("2fa411...", 16);
 * biMax = new BigInteger("3fa411...", 16);
 * KJUR.crypto.Util.getRandomBigIntegerMinToMax(biMin, biMax) &rarr; 32f1... of BigInteger
 */
KJUR.crypto.Util.getRandomBigIntegerMinToMax = function(biMin, biMax) {
    var flagCompare = biMin.compareTo(biMax);
    if (flagCompare == 1) throw "biMin is greater than biMax";
    if (flagCompare == 0) return biMin;

    var biDiff = biMax.subtract(biMin);
    var biRand = KJUR.crypto.Util.getRandomBigIntegerZeroToMax(biDiff);
    return biRand.add(biMin);
};

// === Mac ===============================================================

/**
 * MessageDigest class which is very similar to java.security.MessageDigest class<br/>
 * @name KJUR.crypto.MessageDigest
 * @class MessageDigest class which is very similar to java.security.MessageDigest class
 * @param {Array} params parameters for constructor
 * @property {Array} HASHLENGTH static Array of resulted byte length of hash (ex. HASHLENGTH["sha1"] == 20)
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>md5 - cryptojs</li>
 * <li>sha1 - cryptojs</li>
 * <li>sha224 - cryptojs</li>
 * <li>sha256 - cryptojs</li>
 * <li>sha384 - cryptojs</li>
 * <li>sha512 - cryptojs</li>
 * <li>ripemd160 - cryptojs</li>
 * <li>sha256 - sjcl (NEW from crypto.js 1.0.4)</li>
 * </ul>
 * @example
 * // CryptoJS provider sample
 * var md = new KJUR.crypto.MessageDigest({alg: "sha1", prov: "cryptojs"});
 * md.updateString('aaa')
 * var mdHex = md.digest()
 *
 * // SJCL(Stanford JavaScript Crypto Library) provider sample
 * var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "sjcl"}); // sjcl supports sha256 only
 * md.updateString('aaa')
 * var mdHex = md.digest()
 *
 * // HASHLENGTH property
 * KJUR.crypto.MessageDigest.HASHLENGTH['sha1'] &rarr 20
 * KJUR.crypto.MessageDigest.HASHLENGTH['sha512'] &rarr 64
 */
KJUR.crypto.MessageDigest = function(params) {
    var md = null;
    var algName = null;
    var provName = null;

    /**
     * set hash algorithm and provider<br/>
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.MessageDigest#
     * @function
     * @param {String} alg hash algorithm name
     * @param {String} prov provider name
     * @description
     * This methods set an algorithm and a cryptographic provider.<br/>
     * Here is acceptable algorithm names ignoring cases and hyphens:
     * <ul>
     * <li>MD5</li>
     * <li>SHA1</li>
     * <li>SHA224</li>
     * <li>SHA256</li>
     * <li>SHA384</li>
     * <li>SHA512</li>
     * <li>RIPEMD160</li>
     * </ul>
     * NOTE: Since jsrsasign 6.2.0 crypto 1.1.10, this method ignores
     * upper or lower cases. Also any hyphens (i.e. "-") will be ignored
     * so that "SHA1" or "SHA-1" will be acceptable.
     * @example
     * // for SHA1
     * md.setAlgAndProvider('sha1', 'cryptojs');
     * md.setAlgAndProvider('SHA1');
     * // for RIPEMD160
     * md.setAlgAndProvider('ripemd160', 'cryptojs');
     */
    this.setAlgAndProvider = function(alg, prov) {
	alg = KJUR.crypto.MessageDigest.getCanonicalAlgName(alg);

	if (alg !== null && prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];

	// for cryptojs
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(alg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		this.md = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[alg].create();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.md.update(wHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
	if (':sha256:'.indexOf(alg) != -1 &&
	    prov == 'sjcl') {
	    try {
		this.md = new sjcl.hash.sha256();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var baHex = sjcl.codec.hex.toBits(hex);
		this.md.update(baHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return sjcl.codec.hex.fromBits(hash);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
    };

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.MessageDigest#
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.MessageDigest#
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * completes hash calculation and returns hash result
     * @name digest
     * @memberOf KJUR.crypto.MessageDigest#
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.digest = function() {
	throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name digestString
     * @memberOf KJUR.crypto.MessageDigest#
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.digestString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using hexadecimal string, then completes the digest computation
     * @name digestHex
     * @memberOf KJUR.crypto.MessageDigest#
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
    this.digestHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    if (params !== undefined) {
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined)
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    this.setAlgAndProvider(this.algName, this.provName);
	}
    }
};

/**
 * get canonical hash algorithm name<br/>
 * @name getCanonicalAlgName
 * @memberOf KJUR.crypto.MessageDigest
 * @function
 * @param {String} alg hash algorithm name (ex. MD5, SHA-1, SHA1, SHA512 et.al.)
 * @return {String} canonical hash algorithm name
 * @since jsrsasign 6.2.0 crypto 1.1.10
 * @description
 * This static method normalizes from any hash algorithm name such as
 * "SHA-1", "SHA1", "MD5", "sha512" to lower case name without hyphens
 * such as "sha1".
 * @example
 * KJUR.crypto.MessageDigest.getCanonicalAlgName("SHA-1") &rarr "sha1"
 * KJUR.crypto.MessageDigest.getCanonicalAlgName("MD5")   &rarr "md5"
 */
KJUR.crypto.MessageDigest.getCanonicalAlgName = function(alg) {
    if (typeof alg === "string") {
	alg = alg.toLowerCase();
	alg = alg.replace(/-/, '');
    }
    return alg;
};

/**
 * get resulted hash byte length for specified algorithm name<br/>
 * @name getHashLength
 * @memberOf KJUR.crypto.MessageDigest
 * @function
 * @param {String} alg non-canonicalized hash algorithm name (ex. MD5, SHA-1, SHA1, SHA512 et.al.)
 * @return {Integer} resulted hash byte length
 * @since jsrsasign 6.2.0 crypto 1.1.10
 * @description
 * This static method returns resulted byte length for specified algorithm name such as "SHA-1".
 * @example
 * KJUR.crypto.MessageDigest.getHashLength("SHA-1") &rarr 20
 * KJUR.crypto.MessageDigest.getHashLength("sha1") &rarr 20
 */
KJUR.crypto.MessageDigest.getHashLength = function(alg) {
    var MD = KJUR.crypto.MessageDigest
    var alg2 = MD.getCanonicalAlgName(alg);
    if (MD.HASHLENGTH[alg2] === undefined)
	throw "not supported algorithm: " + alg;
    return MD.HASHLENGTH[alg2];
};

// described in KJUR.crypto.MessageDigest class (since jsrsasign 6.2.0 crypto 1.1.10)
KJUR.crypto.MessageDigest.HASHLENGTH = {
    'md5':		16,
    'sha1':		20,
    'sha224':		28,
    'sha256':		32,
    'sha384':		48,
    'sha512':		64,
    'ripemd160':	20
};

// === Mac ===============================================================

/**
 * Mac(Message Authentication Code) class which is very similar to java.security.Mac class 
 * @name KJUR.crypto.Mac
 * @class Mac class which is very similar to java.security.Mac class
 * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>hmacmd5 - cryptojs</li>
 * <li>hmacsha1 - cryptojs</li>
 * <li>hmacsha224 - cryptojs</li>
 * <li>hmacsha256 - cryptojs</li>
 * <li>hmacsha384 - cryptojs</li>
 * <li>hmacsha512 - cryptojs</li>
 * </ul>
 * NOTE: HmacSHA224 and HmacSHA384 issue was fixed since jsrsasign 4.1.4.
 * Please use 'ext/cryptojs-312-core-fix*.js' instead of 'core.js' of original CryptoJS
 * to avoid those issue.
 * <br/>
 * NOTE2: Hmac signature bug was fixed in jsrsasign 4.9.0 by providing CryptoJS
 * bug workaround.
 * <br/>
 * Please see {@link KJUR.crypto.Mac.setPassword}, how to provide password
 * in various ways in detail.
 * @example
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA1", "pass": "pass"});
 * mac.updateString('aaa')
 * var macHex = md.doFinal()
 *
 * // other password representation 
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"hex":  "6161"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"utf8": "aa"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"rstr": "\x61\x61"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"b64":  "Mi02/+...a=="}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"b64u": "Mi02_-...a"}});
 */
KJUR.crypto.Mac = function(params) {
    var mac = null;
    var pass = null;
    var algName = null;
    var provName = null;
    var algProv = null;

    this.setAlgAndProvider = function(alg, prov) {
	alg = alg.toLowerCase();

	if (alg == null) alg = "hmacsha1";

	alg = alg.toLowerCase();
        if (alg.substr(0, 4) != "hmac") {
	    throw "setAlgAndProvider unsupported HMAC alg: " + alg;
	}

	if (prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];
	this.algProv = alg + "/" + prov;

	var hashAlg = alg.substr(4);

	// for cryptojs
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(hashAlg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		var mdObj = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[hashAlg];
		this.mac = CryptoJS.algo.HMAC.create(mdObj, this.pass);
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail hashAlg=" + hashAlg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.mac.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.mac.update(wHex);
	    };
	    this.doFinal = function() {
		var hash = this.mac.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.doFinalString = function(str) {
		this.updateString(str);
		return this.doFinal();
	    };
	    this.doFinalHex = function(hex) {
		this.updateHex(hex);
		return this.doFinal();
	    };
	}
    };

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.Mac#
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Mac#
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * completes hash calculation and returns hash result
     * @name doFinal
     * @memberOf KJUR.crypto.Mac#
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.doFinal = function() {
	throw "digest() not supported for this alg/prov: " + this.algProv;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name doFinalString
     * @memberOf KJUR.crypto.Mac#
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.doFinalString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * performs final update on the digest using hexadecimal string, 
     * then completes the digest computation
     * @name doFinalHex
     * @memberOf KJUR.crypto.Mac#
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
    this.doFinalHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * set password for Mac
     * @name setPassword
     * @memberOf KJUR.crypto.Mac#
     * @function
     * @param {Object} pass password for Mac
     * @since crypto 1.1.7 jsrsasign 4.9.0
     * @description
     * This method will set password for (H)Mac internally.
     * Argument 'pass' can be specified as following:
     * <ul>
     * <li>even length string of 0..9, a..f or A-F: implicitly specified as hexadecimal string</li>
     * <li>not above string: implicitly specified as raw string</li>
     * <li>{rstr: "\x65\x70"}: explicitly specified as raw string</li>
     * <li>{hex: "6570"}: explicitly specified as hexacedimal string</li>
     * <li>{utf8: "秘密"}: explicitly specified as UTF8 string</li>
     * <li>{b64: "Mi78..=="}: explicitly specified as Base64 string</li>
     * <li>{b64u: "Mi7-_"}: explicitly specified as Base64URL string</li>
     * </ul>
     * It is *STRONGLY RECOMMENDED* that explicit representation of password argument
     * to avoid ambiguity. For example string  "6161" can mean a string "6161" or 
     * a hexadecimal string of "aa" (i.e. \x61\x61).
     * @example
     * mac = KJUR.crypto.Mac({'alg': 'hmacsha256'});
     * // set password by implicit raw string
     * mac.setPassword("\x65\x70\xb9\x0b");
     * mac.setPassword("password");
     * // set password by implicit hexadecimal string
     * mac.setPassword("6570b90b");
     * mac.setPassword("6570B90B");
     * // set password by explicit raw string
     * mac.setPassword({"rstr": "\x65\x70\xb9\x0b"});
     * // set password by explicit hexadecimal string
     * mac.setPassword({"hex": "6570b90b"});
     * // set password by explicit utf8 string
     * mac.setPassword({"utf8": "passwordパスワード");
     * // set password by explicit Base64 string
     * mac.setPassword({"b64": "Mb+c3f/=="});
     * // set password by explicit Base64URL string
     * mac.setPassword({"b64u": "Mb-c3f_"});
     */
    this.setPassword = function(pass) {
	// internal this.pass shall be CryptoJS DWord Object for CryptoJS bug
	// work around. CrytoJS HMac password can be passed by
	// raw string as described in the manual however it doesn't
	// work properly in some case. If password was passed
	// by CryptoJS DWord which is not described in the manual
	// it seems to work. (fixed since crypto 1.1.7)

	if (typeof pass == 'string') {
	    var hPass = pass;
	    if (pass.length % 2 == 1 || ! pass.match(/^[0-9A-Fa-f]+$/)) { // raw str
		hPass = rstrtohex(pass);
	    }
	    this.pass = CryptoJS.enc.Hex.parse(hPass);
	    return;
	}

	if (typeof pass != 'object')
	    throw "KJUR.crypto.Mac unsupported password type: " + pass;
	
	var hPass = null;
	if (pass.hex  !== undefined) {
	    if (pass.hex.length % 2 != 0 || ! pass.hex.match(/^[0-9A-Fa-f]+$/))
		throw "Mac: wrong hex password: " + pass.hex;
	    hPass = pass.hex;
	}
	if (pass.utf8 !== undefined) hPass = utf8tohex(pass.utf8);
	if (pass.rstr !== undefined) hPass = rstrtohex(pass.rstr);
	if (pass.b64  !== undefined) hPass = b64tohex(pass.b64);
	if (pass.b64u !== undefined) hPass = b64utohex(pass.b64u);

	if (hPass == null)
	    throw "KJUR.crypto.Mac unsupported password type: " + pass;

	this.pass = CryptoJS.enc.Hex.parse(hPass);
    };

    if (params !== undefined) {
	if (params.pass !== undefined) {
	    this.setPassword(params.pass);
	}
	if (params.alg !== undefined) {
	    this.algName = params.alg;
	    if (params['prov'] === undefined)
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    this.setAlgAndProvider(this.algName, this.provName);
	}
    }
};

// ====== Signature class =========================================================
/**
 * Signature class which is very similar to java.security.Signature class
 * @name KJUR.crypto.Signature
 * @class Signature class which is very similar to java.security.Signature class
 * @param {Array} params parameters for constructor
 * @property {String} state Current state of this signature object whether 'SIGN', 'VERIFY' or null
 * @description
 * <br/>
 * As for params of constructor's argument, it can be specify following attributes:
 * <ul>
 * <li>alg - signature algorithm name (ex. {MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD160}with{RSA,ECDSA,DSA})</li>
 * <li>provider - currently 'cryptojs/jsrsa' only</li>
 * </ul>
 * <h4>SUPPORTED ALGORITHMS AND PROVIDERS</h4>
 * This Signature class supports following signature algorithm and provider names:
 * <ul>
 * <li>MD5withRSA - cryptojs/jsrsa</li>
 * <li>SHA1withRSA - cryptojs/jsrsa</li>
 * <li>SHA224withRSA - cryptojs/jsrsa</li>
 * <li>SHA256withRSA - cryptojs/jsrsa</li>
 * <li>SHA384withRSA - cryptojs/jsrsa</li>
 * <li>SHA512withRSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSA - cryptojs/jsrsa</li>
 * <li>MD5withECDSA - cryptojs/jsrsa</li>
 * <li>SHA1withECDSA - cryptojs/jsrsa</li>
 * <li>SHA224withECDSA - cryptojs/jsrsa</li>
 * <li>SHA256withECDSA - cryptojs/jsrsa</li>
 * <li>SHA384withECDSA - cryptojs/jsrsa</li>
 * <li>SHA512withECDSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withECDSA - cryptojs/jsrsa</li>
 * <li>MD5withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA224withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA256withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA384withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA512withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withDSA - cryptojs/jsrsa</li>
 * <li>SHA224withDSA - cryptojs/jsrsa</li>
 * <li>SHA256withDSA - cryptojs/jsrsa</li>
 * </ul>
 * Here are supported elliptic cryptographic curve names and their aliases for ECDSA:
 * <ul>
 * <li>secp256k1</li>
 * <li>secp256r1, NIST P-256, P-256, prime256v1</li>
 * <li>secp384r1, NIST P-384, P-384</li>
 * </ul>
 * NOTE1: DSA signing algorithm is also supported since crypto 1.1.5.
 * <h4>EXAMPLES</h4>
 * @example
 * // RSA signature generation
 * var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * var hSigVal = sig.sign();
 *
 * // DSA signature validation
 * var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withDSA"});
 * sig2.init(certPEM);
 * sig.updateString('aaa');
 * var isValid = sig2.verify(hSigVal);
 * 
 * // ECDSA signing
 * var sig = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * var sigValueHex = sig.sign();
 *
 * // ECDSA verifying
 * var sig2 = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(certPEM);
 * sig.updateString('aaa');
 * var isValid = sig.verify(sigValueHex);
 */
KJUR.crypto.Signature = function(params) {
    var prvKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for signing
    var pubKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for verifying

    var md = null; // KJUR.crypto.MessageDigest object
    var sig = null;
    var algName = null;
    var provName = null;
    var algProvName = null;
    var mdAlgName = null;
    var pubkeyAlgName = null;	// rsa,ecdsa,rsaandmgf1(=rsapss)
    var state = null;
    var pssSaltLen = -1;
    var initParams = null;

    var sHashHex = null; // hex hash value for hex
    var hDigestInfo = null;
    var hPaddedDigestInfo = null;
    var hSign = null;

    this._setAlgNames = function() {
    var matchResult = this.algName.match(/^(.+)with(.+)$/);
	if (matchResult) {
	    this.mdAlgName = matchResult[1].toLowerCase();
	    this.pubkeyAlgName = matchResult[2].toLowerCase();
	}
    };

    this._zeroPaddingOfSignature = function(hex, bitLength) {
	var s = "";
	var nZero = bitLength / 4 - hex.length;
	for (var i = 0; i < nZero; i++) {
	    s = s + "0";
	}
	return s + hex;
    };

    /**
     * set signature algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {String} alg signature algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * md.setAlgAndProvider('SHA1withRSA', 'cryptojs/jsrsa');
     */
    this.setAlgAndProvider = function(alg, prov) {
	this._setAlgNames();
	if (prov != 'cryptojs/jsrsa')
	    throw "provider not supported: " + prov;

	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(this.mdAlgName) != -1) {
	    try {
		this.md = new KJUR.crypto.MessageDigest({'alg':this.mdAlgName});
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" +
                      this.mdAlgName + "/" + ex;
	    }

	    this.init = function(keyparam, pass) {
		var keyObj = null;
		try {
		    if (pass === undefined) {
			keyObj = KEYUTIL.getKey(keyparam);
		    } else {
			keyObj = KEYUTIL.getKey(keyparam, pass);
		    }
		} catch (ex) {
		    throw "init failed:" + ex;
		}

		if (keyObj.isPrivate === true) {
		    this.prvKey = keyObj;
		    this.state = "SIGN";
		} else if (keyObj.isPublic === true) {
		    this.pubKey = keyObj;
		    this.state = "VERIFY";
		} else {
		    throw "init failed.:" + keyObj;
		}
	    };

	    this.initSign = function(params) {
		if (typeof params['ecprvhex'] == 'string' &&
                    typeof params['eccurvename'] == 'string') {
		    this.ecprvhex = params['ecprvhex'];
		    this.eccurvename = params['eccurvename'];
		} else {
		    this.prvKey = params;
		}
		this.state = "SIGN";
	    };

	    this.initVerifyByPublicKey = function(params) {
		if (typeof params['ecpubhex'] == 'string' &&
		    typeof params['eccurvename'] == 'string') {
		    this.ecpubhex = params['ecpubhex'];
		    this.eccurvename = params['eccurvename'];
		} else if (params instanceof KJUR.crypto.ECDSA) {
		    this.pubKey = params;
		} else if (params instanceof RSAKey) {
		    this.pubKey = params;
		}
		this.state = "VERIFY";
	    };

	    this.initVerifyByCertificatePEM = function(certPEM) {
		var x509 = new X509();
		x509.readCertPEM(certPEM);
		this.pubKey = x509.subjectPublicKeyRSA;
		this.state = "VERIFY";
	    };

	    this.updateString = function(str) {
		this.md.updateString(str);
	    };

	    this.updateHex = function(hex) {
		this.md.updateHex(hex);
	    };

	    this.sign = function() {
		this.sHashHex = this.md.digest();
		if (typeof this.ecprvhex != "undefined" &&
		    typeof this.eccurvename != "undefined") {
		    var ec = new KJUR.crypto.ECDSA({'curve': this.eccurvename});
		    this.hSign = ec.signHex(this.sHashHex, this.ecprvhex);
		} else if (this.prvKey instanceof RSAKey &&
		           this.pubkeyAlgName == "rsaandmgf1") {
		    this.hSign = this.prvKey.signWithMessageHashPSS(this.sHashHex,
								    this.mdAlgName,
								    this.pssSaltLen);
		} else if (this.prvKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsa") {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex,
								 this.mdAlgName);
		} else if (this.prvKey instanceof KJUR.crypto.ECDSA) {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else if (this.prvKey instanceof KJUR.crypto.DSA) {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else {
		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
		return this.hSign;
	    };
	    this.signString = function(str) {
		this.updateString(str);
		return this.sign();
	    };
	    this.signHex = function(hex) {
		this.updateHex(hex);
		return this.sign();
	    };
	    this.verify = function(hSigVal) {
	        this.sHashHex = this.md.digest();
		if (typeof this.ecpubhex != "undefined" &&
		    typeof this.eccurvename != "undefined") {
		    var ec = new KJUR.crypto.ECDSA({curve: this.eccurvename});
		    return ec.verifyHex(this.sHashHex, hSigVal, this.ecpubhex);
		} else if (this.pubKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsaandmgf1") {
		    return this.pubKey.verifyWithMessageHashPSS(this.sHashHex, hSigVal, 
								this.mdAlgName,
								this.pssSaltLen);
		} else if (this.pubKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsa") {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (this.pubKey instanceof KJUR.crypto.ECDSA) {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (this.pubKey instanceof KJUR.crypto.DSA) {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else {
		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
	    };
	}
    };

    /**
     * Initialize this object for signing or verifying depends on key
     * @name init
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {Object} key specifying public or private key as plain/encrypted PKCS#5/8 PEM file, certificate PEM or {@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA} object
     * @param {String} pass (OPTION) passcode for encrypted private key
     * @since crypto 1.1.3
     * @description
     * This method is very useful initialize method for Signature class since
     * you just specify key then this method will automatically initialize it
     * using {@link KEYUTIL.getKey} method.
     * As for 'key',  following argument type are supported:
     * <h5>signing</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 encrypted RSA/ECDSA private key concluding "BEGIN ENCRYPTED PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 encrypted RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" and ",ENCRYPTED"</li>
     * <li>PEM formatted PKCS#8 plain RSA/ECDSA private key concluding "BEGIN PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 plain RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" without ",ENCRYPTED"</li>
     * <li>RSAKey object of private key</li>
     * <li>KJUR.crypto.ECDSA object of private key</li>
     * <li>KJUR.crypto.DSA object of private key</li>
     * </ul>
     * <h5>verification</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 RSA/EC/DSA public key concluding "BEGIN PUBLIC KEY"</li>
     * <li>PEM formatted X.509 certificate with RSA/EC/DSA public key concluding
     *     "BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE" or "BEGIN TRUSTED CERTIFICATE".</li>
     * <li>RSAKey object of public key</li>
     * <li>KJUR.crypto.ECDSA object of public key</li>
     * <li>KJUR.crypto.DSA object of public key</li>
     * </ul>
     * @example
     * sig.init(sCertPEM)
     */
    this.init = function(key, pass) {
	throw "init(key, pass) not supported for this alg:prov=" +
	      this.algProvName;
    };

    /**
     * Initialize this object for verifying with a public key
     * @name initVerifyByPublicKey
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {Object} param RSAKey object of public key or associative array for ECDSA
     * @since 1.0.2
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * Public key information will be provided as 'param' parameter and the value will be
     * following:
     * <ul>
     * <li>{@link RSAKey} object for RSA verification</li>
     * <li>associative array for ECDSA verification
     *     (ex. <code>{'ecpubhex': '041f..', 'eccurvename': 'secp256r1'}</code>)
     * </li>
     * </ul>
     * @example
     * sig.initVerifyByPublicKey(rsaPrvKey)
     */
    this.initVerifyByPublicKey = function(rsaPubKey) {
	throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" +
	      this.algProvName;
    };

    /**
     * Initialize this object for verifying with a certficate
     * @name initVerifyByCertificatePEM
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {String} certPEM PEM formatted string of certificate
     * @since 1.0.2
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * @example
     * sig.initVerifyByCertificatePEM(certPEM)
     */
    this.initVerifyByCertificatePEM = function(certPEM) {
	throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" +
	    this.algProvName;
    };

    /**
     * Initialize this object for signing
     * @name initSign
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {Object} param RSAKey object of public key or associative array for ECDSA
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * Private key information will be provided as 'param' parameter and the value will be
     * following:
     * <ul>
     * <li>{@link RSAKey} object for RSA signing</li>
     * <li>associative array for ECDSA signing
     *     (ex. <code>{'ecprvhex': '1d3f..', 'eccurvename': 'secp256r1'}</code>)</li>
     * </ul>
     * @example
     * sig.initSign(prvKey)
     */
    this.initSign = function(prvKey) {
	throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a string
     * @name updateString
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {String} str string to use for the update
     * @description
     * @example
     * sig.updateString('aaa')
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {String} hex hexadecimal string to use for the update
     * @description
     * @example
     * sig.updateHex('1f2f3f')
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Returns the signature bytes of all data updates as a hexadecimal string
     * @name sign
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @return the signature bytes as a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.sign()
     */
    this.sign = function() {
	throw "sign() not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signString
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {String} str string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signString('aaa')
     */
    this.signString = function(str) {
	throw "digestString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using hexadecimal string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signHex
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {String} hex hexadecimal string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signHex('1fdc33')
     */
    this.signHex = function(hex) {
	throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * verifies the passed-in signature.
     * @name verify
     * @memberOf KJUR.crypto.Signature#
     * @function
     * @param {String} str string to final update
     * @return {Boolean} true if the signature was verified, otherwise false
     * @description
     * @example
     * var isValid = sig.verify('1fbcefdca4823a7(snip)')
     */
    this.verify = function(hSigVal) {
	throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName;
    };

    this.initParams = params;

    if (params !== undefined) {
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined) {
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    } else {
		this.provName = params['prov'];
	    }
	    this.algProvName = this.algName + ":" + this.provName;
	    this.setAlgAndProvider(this.algName, this.provName);
	    this._setAlgNames();
	}

	if (params['psssaltlen'] !== undefined) this.pssSaltLen = params['psssaltlen'];

	if (params['prvkeypem'] !== undefined) {
	    if (params['prvkeypas'] !== undefined) {
		throw "both prvkeypem and prvkeypas parameters not supported";
	    } else {
		try {
		    var prvKey = new RSAKey();
		    prvKey.readPrivateKeyFromPEMString(params['prvkeypem']);
		    this.initSign(prvKey);
		} catch (ex) {
		    throw "fatal error to load pem private key: " + ex;
		}
	    }
	}
    }
};

// ====== Cipher class ============================================================
/**
 * Cipher class to encrypt and decrypt data<br/>
 * @name KJUR.crypto.Cipher
 * @class Cipher class to encrypt and decrypt data<br/>
 * @param {Array} params parameters for constructor
 * @since jsrsasign 6.2.0 crypto 1.1.10
 * @description
 * Here is supported canonicalized cipher algorithm names and its standard names:
 * <ul>
 * <li>RSA - RSA/ECB/PKCS1Padding (default for RSAKey)</li>
 * <li>RSAOAEP - RSA/ECB/OAEPWithSHA-1AndMGF1Padding</li>
 * <li>RSAOAEP224 - RSA/ECB/OAEPWithSHA-224AndMGF1Padding(*)</li>
 * <li>RSAOAEP256 - RSA/ECB/OAEPWithSHA-256AndMGF1Padding</li>
 * <li>RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding(*)</li>
 * <li>RSAOAEP512 - RSA/ECB/OAEPWithSHA-512AndMGF1Padding(*)</li>
 * </ul>
 * NOTE: (*) is not supported in Java JCE.<br/>
 * Currently this class supports only RSA encryption and decryption. 
 * However it is planning to implement also symmetric ciphers near in the future.
 * @example
 */
KJUR.crypto.Cipher = function(params) {
};

/**
 * encrypt raw string by specified key and algorithm<br/>
 * @name encrypt
 * @memberOf KJUR.crypto.Cipher
 * @function
 * @param {String} s input string to encrypt
 * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
 * @param {String} algName short/long algorithm name for encryption/decryption
 * @return {String} hexadecimal encrypted string
 * @since jsrsasign 6.2.0 crypto 1.1.10
 * @description
 * This static method encrypts raw string with specified key and algorithm.
 * @example 
 * KJUR.crypto.Cipher.encrypt("aaa", pubRSAKeyObj) &rarr; "1abc2d..."
 * KJUR.crypto.Cipher.encrypt("aaa", pubRSAKeyObj, "RSAOAEP) &rarr; "23ab02..."
 */
KJUR.crypto.Cipher.encrypt = function(s, keyObj, algName) {
    if (keyObj instanceof RSAKey && keyObj.isPublic) {
	var algName2 = KJUR.crypto.Cipher.getAlgByKeyAndName(keyObj, algName);
	if (algName2 === "RSA") return keyObj.encrypt(s);
	if (algName2 === "RSAOAEP") return keyObj.encryptOAEP(s, "sha1");

	var a = algName2.match(/^RSAOAEP(\d+)$/);
	if (a !== null) return keyObj.encryptOAEP(s, "sha" + a[1]);

	throw "Cipher.encrypt: unsupported algorithm for RSAKey: " + algName;
    } else {
	throw "Cipher.encrypt: unsupported key or algorithm";
    }
};

/**
 * decrypt encrypted hexadecimal string with specified key and algorithm<br/>
 * @name decrypt
 * @memberOf KJUR.crypto.Cipher
 * @function
 * @param {String} hex hexadecial string of encrypted message
 * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
 * @param {String} algName short/long algorithm name for encryption/decryption
 * @return {String} hexadecimal encrypted string
 * @since jsrsasign 6.2.0 crypto 1.1.10
 * @description
 * This static method decrypts encrypted hexadecimal string with specified key and algorithm.
 * @example 
 * KJUR.crypto.Cipher.decrypt("aaa", prvRSAKeyObj) &rarr; "1abc2d..."
 * KJUR.crypto.Cipher.decrypt("aaa", prvRSAKeyObj, "RSAOAEP) &rarr; "23ab02..."
 */
KJUR.crypto.Cipher.decrypt = function(hex, keyObj, algName) {
    if (keyObj instanceof RSAKey && keyObj.isPrivate) {
	var algName2 = KJUR.crypto.Cipher.getAlgByKeyAndName(keyObj, algName);
	if (algName2 === "RSA") return keyObj.decrypt(hex);
	if (algName2 === "RSAOAEP") return keyObj.decryptOAEP(hex, "sha1");

	var a = algName2.match(/^RSAOAEP(\d+)$/);
	if (a !== null) return keyObj.decryptOAEP(hex, "sha" + a[1]);

	throw "Cipher.decrypt: unsupported algorithm for RSAKey: " + algName;
    } else {
	throw "Cipher.decrypt: unsupported key or algorithm";
    }
};

/**
 * get canonicalized encrypt/decrypt algorithm name by key and short/long algorithm name<br/>
 * @name getAlgByKeyAndName
 * @memberOf KJUR.crypto.Cipher
 * @function
 * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
 * @param {String} algName short/long algorithm name for encryption/decryption
 * @return {String} canonicalized algorithm name for encryption/decryption
 * @since jsrsasign 6.2.0 crypto 1.1.10
 * @description
 * Here is supported canonicalized cipher algorithm names and its standard names:
 * <ul>
 * <li>RSA - RSA/ECB/PKCS1Padding (default for RSAKey)</li>
 * <li>RSAOAEP - RSA/ECB/OAEPWithSHA-1AndMGF1Padding</li>
 * <li>RSAOAEP224 - RSA/ECB/OAEPWithSHA-224AndMGF1Padding(*)</li>
 * <li>RSAOAEP256 - RSA/ECB/OAEPWithSHA-256AndMGF1Padding</li>
 * <li>RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding(*)</li>
 * <li>RSAOAEP512 - RSA/ECB/OAEPWithSHA-512AndMGF1Padding(*)</li>
 * </ul>
 * NOTE: (*) is not supported in Java JCE.
 * @example 
 * KJUR.crypto.Cipher.getAlgByKeyAndName(objRSAKey) &rarr; "RSA"
 * KJUR.crypto.Cipher.getAlgByKeyAndName(objRSAKey, "RSAOAEP") &rarr; "RSAOAEP"
 */
KJUR.crypto.Cipher.getAlgByKeyAndName = function(keyObj, algName) {
    if (keyObj instanceof RSAKey) {
	if (":RSA:RSAOAEP:RSAOAEP224:RSAOAEP256:RSAOAEP384:RSAOAEP512:".indexOf(algName) != -1)
	    return algName;
	if (algName === null || algName === undefined) return "RSA";
	throw "getAlgByKeyAndName: not supported algorithm name for RSAKey: " + algName;
    }
    throw "getAlgByKeyAndName: not supported algorithm name: " + algName;
}

// ====== Other Utility class =====================================================

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.OID
 * @class static object for cryptography related OIDs
 * @property {Array} oidhex2name key value of hexadecimal OID and its name
 *           (ex. '2a8648ce3d030107' and 'secp256r1')
 * @since crypto 1.1.3
 * @description
 */
KJUR.crypto.OID = new function() {
    this.oidhex2name = {
	'2a864886f70d010101': 'rsaEncryption',
	'2a8648ce3d0201': 'ecPublicKey',
	'2a8648ce380401': 'dsa',
	'2a8648ce3d030107': 'secp256r1',
	'2b8104001f': 'secp192k1',
	'2b81040021': 'secp224r1',
	'2b8104000a': 'secp256k1',
	'2b81040023': 'secp521r1',
	'2b81040022': 'secp384r1',
	'2a8648ce380403': 'SHA1withDSA', // 1.2.840.10040.4.3
	'608648016503040301': 'SHA224withDSA', // 2.16.840.1.101.3.4.3.1
	'608648016503040302': 'SHA256withDSA', // 2.16.840.1.101.3.4.3.2
    };
};
