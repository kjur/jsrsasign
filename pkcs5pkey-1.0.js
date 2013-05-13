/*! pkcs5pkey-1.0.1.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// pkcs5pkey.js - reading passcode protected PKCS#5 PEM formatted RSA private key
//
//
// version: 1.0.1 (13 May 2013)
//
// Copyright (c) 2013 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.

/**
 * @fileOverview
 * @name pkcs5pkey-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.0 (2013-Apr-14)
 * @since 2.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * @name PKCS5PKEY
 * @class class for reading passcode protected PKCS#5 private key.
 * @description 
 * passcode protected PKCS#5 private key reader class. 
 * Currently supports only RSA private key and
 * following symmetric key algorithms to protect private key.
 * <ul>
 * <li>DES-EDE3-CBC</li>
 * <li>AES-256-CBC</li>
 * <li>AES-192-CBC</li>
 * <li>AES-128-CBC</li>
 * </ul>
 * 
 */
var PKCS5PKEY = function() {
    // *****************************************************************
    // *** PRIVATE PROPERTIES AND METHODS *******************************
    // *****************************************************************
    var decryptAES = function(dataHex, keyHex, ivHex) {
	return decryptGeneral(CryptoJS.AES, dataHex, keyHex, ivHex);
    };

    var decrypt3DES = function(dataHex, keyHex, ivHex) {
	return decryptGeneral(CryptoJS.TripleDES, dataHex, keyHex, ivHex);
    };

    var decryptGeneral = function(f, dataHex, keyHex, ivHex) {
	var data = CryptoJS.enc.Hex.parse(dataHex);
	var key = CryptoJS.enc.Hex.parse(keyHex);
	var iv = CryptoJS.enc.Hex.parse(ivHex);
	var encrypted = {};
	encrypted.key = key;
	encrypted.iv = iv;
	encrypted.ciphertext = data;
	var decrypted = f.decrypt(encrypted, key, { iv: iv });
	return CryptoJS.enc.Hex.stringify(decrypted);
    };

    var getFuncByName = function(algName) {
	return ALGLIST[algName]['proc'];
    };

    var ALGLIST = {
	'AES-256-CBC': { 'proc': decryptAES, keylen: 32, ivlen: 16 },
	'AES-192-CBC': { 'proc': decryptAES, keylen: 24, ivlen: 16 },
	'AES-128-CBC': { 'proc': decryptAES, keylen: 16, ivlen: 16 },
	'DES-EDE3-CBC': { 'proc': decrypt3DES, keylen: 24, ivlen: 8 }
    };

    var _parsePKCS5PEM = function(sPKCS5PEM) {
	var info = {};
	if (sPKCS5PEM.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)", "m"))) {
	    info.cipher = RegExp.$1;
	    info.ivsalt = RegExp.$2;
	}
	if (sPKCS5PEM.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"))) {
	    info.type = RegExp.$1;
	}
	var i1 = -1;
	var lenNEWLINE = 0;
	if (sPKCS5PEM.indexOf("\r\n\r\n") != -1) {
	    i1 = sPKCS5PEM.indexOf("\r\n\r\n");
	    lenNEWLINE = 2;
	}
	if (sPKCS5PEM.indexOf("\n\n") != -1) {
	    i1 = sPKCS5PEM.indexOf("\n\n");
	    lenNEWLINE = 1;
	}
	var i2 = sPKCS5PEM.indexOf("-----END");
	if (i1 != -1 && i2 != -1) {
	    var s = sPKCS5PEM.substring(i1 + lenNEWLINE * 2, i2 - lenNEWLINE);
	    s = s.replace(/\s+/g, '');
	    info.data = s;
	}
	return info;
    };

    var _getKeyAndUnusedIvByPasscodeAndIvsalt = function(algName, passcode, ivsaltHex) {
	//alert("ivsaltHex(2) = " + ivsaltHex);
	var saltHex = ivsaltHex.substring(0, 16);
	//alert("salt = " + saltHex);
	    
	var salt = CryptoJS.enc.Hex.parse(saltHex);
	var data = CryptoJS.enc.Utf8.parse(passcode);
	//alert("salt = " + salt);
	//alert("data = " + data);

	var nRequiredBytes = ALGLIST[algName]['keylen'] + ALGLIST[algName]['ivlen'];
	var hHexValueJoined = '';
	var hLastValue = null;
	//alert("nRequiredBytes = " + nRequiredBytes);
	for (;;) {
	    var h = CryptoJS.algo.MD5.create();
	    if (hLastValue != null) {
		h.update(hLastValue);
	    }
	    h.update(data);
	    h.update(salt);
	    hLastValue = h.finalize();
	    hHexValueJoined = hHexValueJoined + CryptoJS.enc.Hex.stringify(hLastValue);
	    //alert("joined = " + hHexValueJoined);
	    if (hHexValueJoined.length >= nRequiredBytes * 2) {
		break;
	    }
	}
	var result = {};
	result.keyhex = hHexValueJoined.substr(0, ALGLIST[algName]['keylen'] * 2);
	result.ivhex = hHexValueJoined.substr(ALGLIST[algName]['keylen'] * 2, ALGLIST[algName]['ivlen'] * 2);
	return result;
    };

    var _decryptKeyB64 = function(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
	var privateKeyWA = CryptoJS.enc.Base64.parse(privateKeyB64);
	var privateKeyHex = CryptoJS.enc.Hex.stringify(privateKeyWA);
	var f = ALGLIST[sharedKeyAlgName]['proc'];
	var decryptedKey = f(privateKeyHex, sharedKeyHex, ivsaltHex);
	return decryptedKey;
    };
    
    // *****************************************************************
    // *** PUBLIC PROPERTIES AND METHODS *******************************
    // *****************************************************************
    return {
	/**
         * decrypt private key by shared key
	 * @name version
	 * @memberOf PKCS5PKEY
	 * @property {String} version
	 * @description version string of PKCS5PKEY class
	 */
	version: "1.0.0",
	/**
         * decrypt private key by shared key
	 * @name getDecryptedKeyHexByKeyIV
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} encryptedKeyHex hexadecimal string of encrypted private key
	 * @param {String} algName name of symmetric key algorithm (ex. 'DES-EBE3-CBC')
	 * @param {String} sharedKeyHex hexadecimal string of symmetric key
	 * @param {String} ivHex hexadecimal string of initial vector(IV).
	 * @return {String} hexadecimal string of decrypted privated key
	 */
	getDecryptedKeyHexByKeyIV: function(encryptedKeyHex, algName, sharedKeyHex, ivHex) {
	    var f1 = getFuncByName(algName);
	    return f1(encryptedKeyHex, sharedKeyHex, ivHex);
	},
	/**
         * parse PEM formatted passcode protected PKCS#5 private key
	 * @name parsePKCS5PEM
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} sEncryptedPEM PEM formatted protected passcode protected PKCS#5 private key
	 * @return {Hash} hash of key information
	 * @description
         * Resulted hash has following attributes.
	 * <ul>
	 * <li>cipher - symmetric key algorithm name (ex. 'DES-EBE3-CBC', 'AES-256-CBC')</li>
	 * <li>ivsalt - IV used for decrypt. Its heading 8 bytes will be used for passcode salt.</li>
	 * <li>type - asymmetric key algorithm name of private key described in PEM header.</li>
	 * <li>data - base64 encoded encrypted private key.</li>
	 * </ul>
         *
	 */
        parsePKCS5PEM: function(sPKCS5PEM) {
	    return _parsePKCS5PEM(sPKCS5PEM);
	},
	/**
         * the same function as OpenSSL EVP_BytsToKey to generate shared key and IV
	 * @name getKeyAndUnusedIvByPasscodeAndIvsalt
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} algName name of symmetric key algorithm (ex. 'DES-EBE3-CBC')
	 * @param {String} passcode passcode to decrypt private key (ex. 'password')
	 * @param {String} hexadecimal string of IV. heading 8 bytes will be used for passcode salt
	 * @return {Hash} hash of key and unused IV (ex. {keyhex:2fe3..., ivhex:3fad..})
	 */
	getKeyAndUnusedIvByPasscodeAndIvsalt: function(algName, passcode, ivsaltHex) {
	    return _getKeyAndUnusedIvByPasscodeAndIvsalt(algName, passcode, ivsaltHex);
	},
        decryptKeyB64: function(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
	    return _decryptKeyB64(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex);
        },

	/**
         * decrypt PEM formatted protected PKCS#5 private key with passcode
	 * @name getDecryptedKeyHex
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} sEncryptedPEM PEM formatted protected passcode protected PKCS#5 private key
	 * @param {String} passcode passcode to decrypt private key (ex. 'password')
	 * @return {String} hexadecimal string of decrypted RSA priavte key
	 */
	getDecryptedKeyHex: function(sEncryptedPEM, passcode) {
	    // 1. parse pem
	    var info = _parsePKCS5PEM(sEncryptedPEM);
	    var publicKeyAlgName = info.type;
	    var sharedKeyAlgName = info.cipher;
	    var ivsaltHex = info.ivsalt;
	    var privateKeyB64 = info.data;
	    //alert("ivsaltHex = " + ivsaltHex);

	    // 2. generate shared key
	    var sharedKeyInfo = _getKeyAndUnusedIvByPasscodeAndIvsalt(sharedKeyAlgName, passcode, ivsaltHex);
	    var sharedKeyHex = sharedKeyInfo.keyhex;
	    //alert("sharedKeyHex = " + sharedKeyHex);

	    // 3. decrypt private key
            var decryptedKey = _decryptKeyB64(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex);
	    return decryptedKey;
	},

	/**
         * read unencrypted PEM formatted protected PKCS#8 private key and returns RSAKey
	 * @name getRSAKeyFromPlainPKCS8PEM
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} PEM formatted plain PKCS#8 private key
	 * @return {RSAKey} RSA private key loaded
         * @since 1.0.1
	 */
        getRSAKeyFromPlainPKCS8PEM: function(pkcs8PEM) {
            if (pkcs8PEM.match(/ENCRYPTED/))
                throw "pem shall be not ENCRYPTED";
	    if (! pkcs8PEM.match(/BEGIN PRIVATE KEY/))
                throw "pkcs8PEM doesn't include 'BEGIN PRIVATE KEY'";
            var s = pkcs8PEM;
	    s = s.replace(/^-----BEGIN PRIVATE KEY-----/, '');
	    s = s.replace(/^-----END PRIVATE KEY-----/, '');
	    var sB64 = s.replace(/\s+/g, '');
	    var prvKeyWA = CryptoJS.enc.Base64.parse(sB64);
	    var prvKeyHex = CryptoJS.enc.Hex.stringify(prvKeyWA);
	    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(prvKeyHex, 0);
	    if (a1.length != 3)
		throw "outer DERSequence shall have 3 elements: " + a1.length;
            var algIdTLV =ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[1]);
	    if (algIdTLV != "300d06092a864886f70d0101010500") // AlgId rsaEncryption
		throw "PKCS8 AlgorithmIdentifier is not rsaEnc: " + algIdTLV;
            var algIdTLV = ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[1]);
	    var octetStr = ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[2]);
	    var p5KeyHex = ASN1HEX.getHexOfV_AtObj(octetStr, 0);
            //alert(p5KeyHex);
	    var rsaKey = new RSAKey();
	    rsaKey.readPrivateKeyFromASN1HexString(p5KeyHex);
	    return rsaKey;
        },

	addAlgorithm: function(functionObject, algName, keyLen, ivLen) {
	}
    };
}();
