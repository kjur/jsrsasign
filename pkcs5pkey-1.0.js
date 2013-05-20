/*! pkcs5pkey-1.0.2.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// pkcs5pkey.js - reading passcode protected PKCS#5 PEM formatted RSA private key
//
//
// version: 1.0.2 (20 May 2013)
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
 * @version pkcs5pkey 1.0.2 (2013-May-20)
 * @since jsrsasign 2.0.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * @name PKCS5PKEY
 * @class class for PKCS#5 and PKCS#8 private key 
 * @description 
 * <br/>
 * {@link PKCS5PKEY} class has following features:
 * <ul>
 * <li>read and parse PEM formatted encrypted PKCS#5 private key
 * <li>generate PEM formatted encrypted PKCS#5 private key
 * <li>read and parse PEM formatted plain PKCS#8 private key
 * </ul>
 * Currently supports only RSA private key and
 * following symmetric key algorithms to protect private key.
 * <ul>
 * <li>DES-EDE3-CBC</li>
 * <li>AES-256-CBC</li>
 * <li>AES-192-CBC</li>
 * <li>AES-128-CBC</li>
 * </ul>
 * 
 * @example
 * Here is an example of PEM formatted encrypted PKCS#5 private key.
 * -----BEGIN RSA PRIVATE KEY-----
 * Proc-Type: 4,ENCRYPTED
 * DEK-Info: AES-256-CBC,40555967F759530864FE022E257DE34E
 *
 * jV7uXajRw4cccDaliagcqiLOiQEUCe19l761pXRxzgQP+DH4rCi12T4puTdZyy6l
 *          ...(snip)...
 * qxLS+BASmyGm4DME6m+kltZ12LXwPgNU6+d+XQ4NXSA=
 *-----END RSA PRIVATE KEY-----
 */
var PKCS5PKEY = function() {
    // *****************************************************************
    // *** PRIVATE PROPERTIES AND METHODS *******************************
    // *****************************************************************

    // shared key decryption ------------------------------------------
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

    // shared key decryption ------------------------------------------
    var encryptAES = function(dataHex, keyHex, ivHex) {
	return encryptGeneral(CryptoJS.AES, dataHex, keyHex, ivHex);
    };

    var encrypt3DES = function(dataHex, keyHex, ivHex) {
	return encryptGeneral(CryptoJS.TripleDES, dataHex, keyHex, ivHex);
    };

    var encryptGeneral = function(f, dataHex, keyHex, ivHex) {
	var data = CryptoJS.enc.Hex.parse(dataHex);
	var key = CryptoJS.enc.Hex.parse(keyHex);
	var iv = CryptoJS.enc.Hex.parse(ivHex);
	var msg = {};
	var encryptedHex = f.encrypt(data, key, { iv: iv });
        var encryptedWA = CryptoJS.enc.Hex.parse(encryptedHex.toString());
        var encryptedB64 = CryptoJS.enc.Base64.stringify(encryptedWA);
	return encryptedB64;
    };

    // other methods --------------------------------------------------
    var getFuncByName = function(algName) {
	return ALGLIST[algName]['proc'];
    };

    var _generateIvSaltHex = function(numBytes) {
	var wa = CryptoJS.lib.WordArray.random(numBytes);
	var hex = CryptoJS.enc.Hex.stringify(wa);
	return hex;
    };

    var ALGLIST = {
	'AES-256-CBC': { 'proc': decryptAES, 'eproc': encryptAES, keylen: 32, ivlen: 16 },
	'AES-192-CBC': { 'proc': decryptAES, 'eproc': encryptAES, keylen: 24, ivlen: 16 },
	'AES-128-CBC': { 'proc': decryptAES, 'eproc': encryptAES, keylen: 16, ivlen: 16 },
	'DES-EDE3-CBC': { 'proc': decrypt3DES, 'eproc': encrypt3DES, keylen: 24, ivlen: 8 }
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

    /*
     * @param {String} privateKeyB64 base64 string of encrypted private key
     * @param {String} sharedKeyAlgName algorithm name of shared key encryption
     * @param {String} sharedKeyHex hexadecimal string of shared key to encrypt
     * @param {String} ivsaltHex hexadecimal string of IV and salt
     * @param {String} hexadecimal string of decrypted private key
     */
    var _decryptKeyB64 = function(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
	var privateKeyWA = CryptoJS.enc.Base64.parse(privateKeyB64);
	var privateKeyHex = CryptoJS.enc.Hex.stringify(privateKeyWA);
	var f = ALGLIST[sharedKeyAlgName]['proc'];
	var decryptedKeyHex = f(privateKeyHex, sharedKeyHex, ivsaltHex);
	return decryptedKeyHex;
    };
    
    /*
     * @param {String} privateKeyHex hexadecimal string of private key
     * @param {String} sharedKeyAlgName algorithm name of shared key encryption
     * @param {String} sharedKeyHex hexadecimal string of shared key to encrypt
     * @param {String} ivsaltHex hexadecimal string of IV and salt
     * @param {String} base64 string of encrypted private key
     */
    var _encryptKeyHex = function(privateKeyHex, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
	var f = ALGLIST[sharedKeyAlgName]['eproc'];
	var encryptedKeyB64 = f(privateKeyHex, sharedKeyHex, ivsaltHex);
	return encryptedKeyB64;
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
         * read PEM formatted encrypted PKCS#5 private key and returns RSAKey object
	 * @name getRSAKeyFromEncryptedPKCS5PEM
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} pkcs8PEM PEM formatted unencrypted PKCS#8 private key
	 * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.2
	 */
	getRSAKeyFromEncryptedPKCS5PEM: function(sEncryptedP5PEM, passcode) {
	    var hPKey = this.getDecryptedKeyHex(sEncryptedP5PEM, passcode);
	    var rsaKey = new RSAKey();
	    rsaKey.readPrivateKeyFromASN1HexString(hPKey);
	    return rsaKey;
	},

	/**
         * get PEM formatted encrypted PKCS#5 private key from hexadecimal string of plain private key
	 * @name getEryptedPKCS5PEMFromPrvKeyHex
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} hPrvKey hexadecimal string of plain private key
	 * @param {String} passcode pass code to protect private key (ex. password)
	 * @param {String} sharedKeyAlgName algorithm name to protect private key (ex. AES-256-CBC)
	 * @param {String} ivsaltHex hexadecimal string of IV and salt
	 * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
	 * @description
	 * <br/>
	 * generate PEM formatted encrypted PKCS#5 private key by hexadecimal string encoded
	 * ASN.1 object of plain RSA private key.
	 * Following arguments can be omitted.
	 * <ul>
	 * <li>alg - AES-256-CBC will be used if omitted.</li>
	 * <li>ivsaltHex - automatically generate IV and salt which length depends on algorithm</li>
	 * </ul>
	 * @example
	 * var pem = 
         *   PKCS5PKEY.getEryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password");
	 * var pem2 = 
         *   PKCS5PKEY.getEryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC");
	 * var pem3 = 
         *   PKCS5PKEY.getEryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC", "1f3d02...");
	 */
	getEryptedPKCS5PEMFromPrvKeyHex: function(hPrvKey, passcode, sharedKeyAlgName, ivsaltHex) {
	    var sPEM = "";

	    // 1. set sharedKeyAlgName if undefined (default AES-256-CBC)
	    if (typeof sharedKeyAlgName == "undefined" || sharedKeyAlgName == null) {
		sharedKeyAlgName = "AES-256-CBC";
	    }
	    if (typeof ALGLIST[sharedKeyAlgName] == "undefined")
		throw "PKCS5PKEY unsupported algorithm: " + sharedKeyAlgName;

	    // 2. set ivsaltHex if undefined
	    if (typeof ivsaltHex == "undefined" || ivsaltHex == null) {
		var ivlen = ALGLIST[sharedKeyAlgName]['ivlen'];
		var randIV = _generateIvSaltHex(ivlen);
		ivsaltHex = randIV.toUpperCase();
	    }

	    // 3. get shared key
            //alert("ivsalthex=" + ivsaltHex);
	    var sharedKeyInfo = _getKeyAndUnusedIvByPasscodeAndIvsalt(sharedKeyAlgName, passcode, ivsaltHex);
	    var sharedKeyHex = sharedKeyInfo.keyhex;
	    // alert("sharedKeyHex = " + sharedKeyHex);

            // 3. get encrypted Key in Base64
            var encryptedKeyB64 = _encryptKeyHex(hPrvKey, sharedKeyAlgName, sharedKeyHex, ivsaltHex);

	    var pemBody = encryptedKeyB64.replace(/(.{64})/g, "$1\r\n");
	    var sPEM = "-----BEGIN RSA PRIVATE KEY-----\r\n";
	    sPEM += "Proc-Type: 4,ENCRYPTED\r\n";
	    sPEM += "DEK-Info: " + sharedKeyAlgName + "," + ivsaltHex + "\r\n";
	    sPEM += "\r\n";
	    sPEM += pemBody;
	    sPEM += "\r\n-----END RSA PRIVATE KEY-----\r\n";

	    return sPEM;
        },

	/**
         * get PEM formatted encrypted PKCS#5 private key from RSAKey object of private key
	 * @name getEryptedPKCS5PEMFromRSAKey
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {RSAKey} pKey RSAKey object of private key
	 * @param {String} passcode pass code to protect private key (ex. password)
	 * @param {String} alg algorithm name to protect private key (default AES-256-CBC)
	 * @param {String} ivsaltHex hexadecimal string of IV and salt (default generated random IV)
	 * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
	 * @description
	 * <br/>
	 * generate PEM formatted encrypted PKCS#5 private key by
	 * {@link RSAKey} object of RSA private key and passcode.
	 * Following argument can be omitted.
	 * <ul>
	 * <li>alg - AES-256-CBC will be used if omitted.</li>
	 * <li>ivsaltHex - automatically generate IV and salt which length depends on algorithm</li>
	 * </ul>
	 * @example
	 * var pkey = new RSAKey();
	 * pkey.generate(1024, '10001'); // generate 1024bit RSA private key with public exponent 'x010001'
	 * var pem = PKCS5PKEY.getEryptedPKCS5PEMFromRSAKey(pkey, "password");
	 */
        getEryptedPKCS5PEMFromRSAKey: function(pKey, passcode, alg, ivsaltHex) {
	    var version = new KJUR.asn1.DERInteger({'int': 0});
	    var n = new KJUR.asn1.DERInteger({'bigint': pKey.n});
	    var e = new KJUR.asn1.DERInteger({'int': pKey.e});
	    var d = new KJUR.asn1.DERInteger({'bigint': pKey.d});
	    var p = new KJUR.asn1.DERInteger({'bigint': pKey.p});
	    var q = new KJUR.asn1.DERInteger({'bigint': pKey.q});
	    var dmp1 = new KJUR.asn1.DERInteger({'bigint': pKey.dmp1});
	    var dmq1 = new KJUR.asn1.DERInteger({'bigint': pKey.dmq1});
	    var coeff = new KJUR.asn1.DERInteger({'bigint': pKey.coeff});
	    var seq = new KJUR.asn1.DERSequence({'array': [version, n, e, d, p, q, dmp1, dmq1, coeff]});
	    var hex = seq.getEncodedHex();
	    return this.getEryptedPKCS5PEMFromPrvKeyHex(hex, passcode, alg, ivsaltHex);
        },

	/**
         * generate RSAKey and PEM formatted encrypted PKCS#5 private key
	 * @name newEryptedPKCS5PEM
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} passcode pass code to protect private key (ex. password)
	 * @param {Integer} keyLen key bit length of RSA key to be generated. (default 1024)
	 * @param {String} hPublicExponent hexadecimal string of public exponent (default 10001)
	 * @param {String} alg shared key algorithm to encrypt private key (default AES-258-CBC)
	 * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
	 * @example
	 * var pem1 = PKCS5PKEY.newEncryptedPKCS5PEM("password");           // RSA1024bit/10001/AES-256-CBC
	 * var pem2 = PKCS5PKEY.newEncryptedPKCS5PEM("password", 512);      // RSA 512bit/10001/AES-256-CBC
	 * var pem3 = PKCS5PKEY.newEncryptedPKCS5PEM("password", 512, '3'); // RSA 512bit/    3/AES-256-CBC
	 */
	newEryptedPKCS5PEM: function(passcode, keyLen, hPublicExponent, alg) {
	    if (typeof keyLen == "undefined" || keyLen == null) {
		keyLen = 1024;
	    }
	    if (typeof hPublicExponent == "undefined" || hPublicExponent == null) {
		hPublicExponent = '10001';
	    }
	    var pKey = new RSAKey();
	    pKey.generate(keyLen, hPublicExponent);
	    var pem = null;
	    if (typeof alg == "undefined" || alg == null) {
		pem = this.getEncryptedPKCS5PEMFromRSAKey(pkey, passcode);
	    } else {
		pem = this.getEncryptedPKCS5PEMFromRSAKey(pkey, passcode, alg);
	    }
	    return pem;
        },

	// === PKCS8 ===============================================================

	/**
         * read PEM formatted unencrypted PKCS#8 private key and returns RSAKey object
	 * @name getRSAKeyFromPlainPKCS8PEM
	 * @memberOf PKCS5PKEY
	 * @function
	 * @param {String} pkcs8PEM PEM formatted unencrypted PKCS#8 private key
	 * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.1
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
