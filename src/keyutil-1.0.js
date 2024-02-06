/* keyutil-1.3.0.js (c) 2013-2023 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * keyutil.js - key utility for PKCS#1/5/8 PEM, RSA/DSA/ECDSA key object
 *
 * Copyright (c) 2013-2023 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */
/**
 * @fileOverview
 * @name keyutil-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.9.0 keyutil 1.3.0 (2023-Nov-25)
 * @since jsrsasign 4.1.4
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * @name KEYUTIL
 * @class class for RSA/ECC/DSA key utility
 * @description 
 * <br/>
 * {@link KEYUTIL} class is an update of former {@link PKCS5PKEY} class.
 * {@link KEYUTIL} class has following features:
 * <dl>
 * <dt><b>key loading - {@link KEYUTIL.getKey}</b>
 * <dd>
 * <ul>
 * <li>supports RSAKey and KJUR.crypto.{ECDSA,DSA} key object</li>
 * <li>supports private key and public key</li>
 * <li>supports encrypted and plain private key</li>
 * <li>supports PKCS#1, PKCS#5 and PKCS#8 key</li>
 * <li>supports public key in X.509 certificate</li>
 * <li>key represented by JSON object</li>
 * </ul>
 * NOTE1: Encrypted PKCS#8 only supports PBKDF2/HmacSHA1/3DES <br/>
 * NOTE2: Encrypted PKCS#5 supports DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC <br/>
 *
 * <dt><b>exporting key - {@link KEYUTIL.getPEM}</b>
 * <dd>
 * {@link KEYUTIL.getPEM} method supports following formats:
 * <ul>
 * <li>supports RSA/EC/DSA keys</li>
 * <li>PKCS#1 plain RSA/EC/DSA private key</li>
 * <li>PKCS#5 encrypted RSA/EC/DSA private key with DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC</li>
 * <li>PKCS#8 plain RSA/EC/DSA private key</li>
 * <li>PKCS#8 encrypted RSA/EC/DSA private key with PBKDF2_HmacSHA1_3DES</li>
 * </ul>
 *
 * <dt><b>keypair generation - {@link KEYUTIL.generateKeypair}</b>
 * <ul>
 * <li>generate key pair of {@link RSAKey} or {@link KJUR.crypto.ECDSA}.</li>
 * <li>generate private key and convert it to PKCS#5 encrypted private key.</li>
 * </ul>
 * NOTE: {@link KJUR.crypto.DSA} is not yet supported.
 * </dl>
 * 
 * @example
 * // 1. loading PEM private key
 * var key = KEYUTIL.getKey(pemPKCS1PrivateKey);
 * var key = KEYUTIL.getKey(pemPKCS5EncryptedPrivateKey, "passcode");
 * var key = KEYUTIL.getKey(pemPKCS5PlainRsaDssEcPrivateKey);
 * var key = KEYUTIL.getKey(pemPKC85PlainPrivateKey);
 * var key = KEYUTIL.getKey(pemPKC85EncryptedPrivateKey, "passcode");
 * // 2. loading PEM public key
 * var key = KEYUTIL.getKey(pemPKCS8PublicKey);
 * var key = KEYUTIL.getKey(pemX509Certificate);
 * // 3. exporting private key
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS1PRV");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS5PRV", "passcode"); // DES-EDE3-CBC by default
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS5PRV", "passcode", "DES-CBC");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS8PRV");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS8PRV", "passcode");
 * // 4. exporting public key
 * var pem = KEYUTIL.getPEM(publicKeyObj);
 */
var KEYUTIL = function() {
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

    var decryptDES = function(dataHex, keyHex, ivHex) {
        return decryptGeneral(CryptoJS.DES, dataHex, keyHex, ivHex);
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

    var encryptDES = function(dataHex, keyHex, ivHex) {
        return encryptGeneral(CryptoJS.DES, dataHex, keyHex, ivHex);
    };

    var encryptGeneral = function(f, dataHex, keyHex, ivHex) {
        var data = CryptoJS.enc.Hex.parse(dataHex);
        var key = CryptoJS.enc.Hex.parse(keyHex);
        var iv = CryptoJS.enc.Hex.parse(ivHex);
        var encryptedHex = f.encrypt(data, key, { iv: iv });
        var encryptedWA = CryptoJS.enc.Hex.parse(encryptedHex.toString());
        var encryptedB64 = CryptoJS.enc.Base64.stringify(encryptedWA);
        return encryptedB64;
    };

    // other methods and properties ----------------------------------------
    var ALGLIST = {
        'AES-256-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 32, ivlen: 16 },
        'AES-192-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 24, ivlen: 16 },
        'AES-128-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 16, ivlen: 16 },
        'DES-EDE3-CBC': { 'proc': decrypt3DES, 'eproc': encrypt3DES, keylen: 24, ivlen: 8 },
        'DES-CBC':      { 'proc': decryptDES,  'eproc': encryptDES,  keylen: 8,  ivlen: 8 }
    };

    var getFuncByName = function(algName) {
        return ALGLIST[algName]['proc'];
    };

    var _generateIvSaltHex = function(numBytes) {
        var wa = CryptoJS.lib.WordArray.random(numBytes);
        var hex = CryptoJS.enc.Hex.stringify(wa);
        return hex;
    };

    var _parsePKCS5PEM = function(sPKCS5PEM) {
        var info = {};
        var matchResult1 = sPKCS5PEM.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)", "m"));
        if (matchResult1) {
            info.cipher = matchResult1[1];
            info.ivsalt = matchResult1[2];
        }
        var matchResult2 = sPKCS5PEM.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"));
        if (matchResult2) {
            info.type = matchResult2[1];
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
        // -- UTILITY METHODS ------------------------------------------------------------
        /**
         * decrypt private key by shared key
         * @name version
         * @memberOf KEYUTIL
         * @property {String} version
         * @description version string of KEYUTIL class
         */
        version: "1.0.0",

        /**
         * parse PEM formatted passcode protected PKCS#5 private key
         * @name parsePKCS5PEM
         * @memberOf KEYUTIL
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
         * @memberOf KEYUTIL
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
         * @memberOf KEYUTIL
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

        /*
         * get PEM formatted encrypted PKCS#5 private key from hexadecimal string of plain private key
         * @name getEncryptedPKCS5PEMFromPrvKeyHex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pemHeadAlg algorithm name in the pem header (i.e. RSA,EC or DSA)
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
         * NOTE1: DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC algorithm are supported.
         * @example
         * var pem = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password");
         * var pem2 = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC");
         * var pem3 = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC", "1f3d02...");
         */
        getEncryptedPKCS5PEMFromPrvKeyHex: function(pemHeadAlg, hPrvKey, passcode, sharedKeyAlgName, ivsaltHex) {
            var sPEM = "";

            // 1. set sharedKeyAlgName if undefined (default AES-256-CBC)
            if (typeof sharedKeyAlgName == "undefined" ||
		sharedKeyAlgName == null) {
                sharedKeyAlgName = "AES-256-CBC";
            }
            if (typeof ALGLIST[sharedKeyAlgName] == "undefined")
                throw new Error("KEYUTIL unsupported algorithm: " + 
				sharedKeyAlgName);

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
            var sPEM = "-----BEGIN " + pemHeadAlg + " PRIVATE KEY-----\r\n";
            sPEM += "Proc-Type: 4,ENCRYPTED\r\n";
            sPEM += "DEK-Info: " + sharedKeyAlgName + "," + ivsaltHex + "\r\n";
            sPEM += "\r\n";
            sPEM += pemBody;
            sPEM += "\r\n-----END " + pemHeadAlg + " PRIVATE KEY-----\r\n";

            return sPEM;
        },

        // === NEW ENCRYPTED PKCS8 GENERATOR =======================================
        /*
         * get Encrypted PKCS8 PEM private key by PEM string of plain priavte key
         * @name getEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {string} hPlainPKCS8Prv hexadecimal string of plain PKCS#8 private key
         * @param {string} passcode password string for encrytion
         * @param {object} param associative array object of parameters for encrypted PKCS#8 (OPITON)
         * @return {string} PEM string of encrypted PKCS#8 private key
         * @since jsrsasign 10.9.0 keyutil 1.3.0
         * @see KEYUTIL.getEncryptedPKCS8Hex
         *
         * @description
         * <br/>
         * generate hexadecimal string of encrypted PKCS#8 private key by a hexadecimal string of 
	 * plain PKCS#8 private key with encryption parameters.
	 * <pre>
	 * { // (OPTION) encryption algorithm (ex. des-EDE3-CBC,aes128-CBC) DEFAULT:aes256-CBC
         *   encalg: "aes128-CBC", 
	 *   // (OPTION) iteration count, DEFAULT:2048,
	 *   iter: 1024, 
	 *   // (OPTION) psudorandom function (ex. hmacWithSHA{1,224,256,384,512}) DEFAULT: hmacWithSHA256
	 *   prf: "hmacWithSHA512", 
	 *   // (OPTION) explicitly specifed 8 bytes hexadecimal salt string.
	 *   salt: "12ab...", 
	 *   // (OPTION) explicitly specified hexadecimal IV string.
	 *   enciv: "257c..." 
	 * </pre>
	 *
         * @example
	 * // generate with default parameters
	 * KEYUTIL.getEncryptedPKCS8PEM("3082...", "password")
	 *   &rarr; "-----BEGIN ENCRYPTED PRIVATE KEY..."
	 * // des-EDE3-CBC with 4096 iteration
	 * KEYUTIL.getEncryptedPKCS8PEM("3082...", "password", { encalg: "des-EDE3-CBC", iter: 4096 })
	 *   &rarr; "-----BEGIN ENCRYPTED PRIVATE KEY..."
         */
	getEncryptedPKCS8PEM: function(hPlainPKCS8Prv, passcode, param) {
	    var hP8E = this.getEncryptedPKCS8Hex(hPlainPKCS8Prv, passcode, param);
	    return hextopem(hP8E, "ENCRYPTED PRIVATE KEY");
	},

        /*
         * get Encrypted PKCS8 private key by PEM string of plain priavte key
         * @name 
         * @memberOf KEYUTIL
         * @function getEncryptedPKCS8Hex
         * @param {string} hPlainPKCS8Prv hexadecimal string of plain PKCS#8 private key
	 * @param {string} passcode password string for encrytion
	 * @param {object} param associative array object of parameters for encrypted PKCS#8 (OPTION)
         * @return {string} PEM string of encrypted PKCS#8 private key
         * @since jsrsasign 10.9.0 keyutil 1.3.0
	 * @see KEYUTIL.getEncryptedPKCS8PEM
	 *
         * @description
         * <br/>
         * generate PEM formatted encrypted PKCS#8 private key by a hexadecimal string of 
	 * plain PKCS#8 private key with encryption parameters.
	 * Regarding to "param", see {@link KEYUTIL.getEncryptedPKCS8PEM}.
	 *
         * @example
	 * // generate with default parameters
	 * KEYUTIL.getEncryptedPKCS8Hex("3082...", "password") &rarr; "3082..."
	 * // des-EDE3-CBC with 4096 iteration
	 * KEYUTIL.getEncryptedPKCS8PEM("3082...", "password", { encalg: "des-EDE3-CBC", iter: 4096 })  &rarr; "3082..."
         */
	getEncryptedPKCS8Hex: function(hPlainPKCS8Prv, passcode, param) {
	    var pParam2;
	    if (param == undefined || param == null) {
		pParam2 = {};
	    } else {
		pParam2 = JSON.parse(JSON.stringify(param));
	    }
	    pParam2.plain = hPlainPKCS8Prv;
	    
	    this.initPBES2Param(pParam2);
	    this.encryptPBES2Param(pParam2, passcode);
	    var pASN = this.generatePBES2ASN1Param(pParam2);
	    return KJUR.asn1.ASN1Util.newObject(pASN).tohex();
	},

        /*
         * set default PBES2 parameters if not specified
         * @name 
         * @memberOf KEYUTIL
         * @function initPBES2Param
	 * @param {object} param associative array object of parameters for encrypted PKCS#8
         * @since jsrsasign 10.9.0 keyutil 1.3.0
	 * @see KEYUTIL.getEncryptedPKCS8PEM
	 * @see KEYUTIL.getEncryptedPKCS8Hex
	 *
         * @description
         * <br/>
         * set default PBES2 parameters if not specified in the "param" associative array.
	 * Here is members:
	 * <ul>
	 * <li>encalg - set "aes256-CBC" encryption algorithm if not specified</li>
	 * <li>iter - set 2048 iteration count if not specified</li>
	 * <li>prf - set "hmacWithSHA256" psudorandom function if not specified</li>
	 * <li>salt - set 8 bytes random number hexadecimal string if not specified</li>
	 * <li>enciv - set random number hexadecimal string of initial vector if not specified.
	 * The length depends on encryption algorithm.</li>
	 * </ul>
         */
	initPBES2Param: function(pPBES2) {
	    if (aryval(pPBES2, "encalg") == undefined) pPBES2.encalg = "aes256-CBC";
	    if (aryval(pPBES2, "iter") == undefined) pPBES2.iter = 2048;
	    if (aryval(pPBES2, "prf") == undefined) pPBES2.prf = "hmacWithSHA256";
	    if (aryval(pPBES2, "salt") == undefined) pPBES2.salt = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(8));
	    if (aryval(pPBES2, "enciv") == undefined) {
		var nbytes;
		if (pPBES2.encalg == "des-EDE3-CBC") nbytes = 8;
		if (pPBES2.encalg == "aes128-CBC") nbytes = 16;
		if (pPBES2.encalg == "aes256-CBC") nbytes = 16;
		pPBES2.enciv = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(nbytes));
	    }
	},

        /*
         * encrypt plain private key with PBES2 paramters
         * @name 
         * @memberOf KEYUTIL
         * @function encryptPBES2Param
	 * @param {object} param associative array object of parameters for encrypted PKCS#8 private key
	 * @param {string} passcode password string for encrypted PKCS#8 private key.
         * @since jsrsasign 10.9.0 keyutil 1.3.0
	 * @see KEYUTIL.getEncryptedPKCS8PEM
	 * @see KEYUTIL.getEncryptedPKCS8Hex
	 *
         * @description
         * <br/>
         * encrypt plain private key with PBES2 parameters.
	 * Here is input members in PBES2 paramters.
	 * <ul>
	 * <li>plain - hexadecimal string of messages (i.e. plain private key) which will be encrypted</li>
	 * <li>encalg - encryption algorithm</li>
	 * <li>iter - iteration count</li>
	 * <li>prf - psudorandom function</li>
	 * <li>salt - salt</li>
	 * <li>enciv - initial vector</li>
	 * </ul>
	 * Encrypted result will be set as a new "enc" member of hexadecimal string in PBES2 parameters.
         */
	encryptPBES2Param: function(pPBES2, passcode) {
	    var hKey = KEYUTIL.getDKFromPBES2Param(pPBES2, passcode);
	    try {
		var hEnc = KJUR.crypto.Cipher.encrypt(pPBES2.plain, hKey, pPBES2.encalg, { iv: pPBES2.enciv });
	    } catch(ex) {
		throw new Error("encrypt error: " + pPBES2.plain + " " + hKey + " " + pPBES2.encalg + " " + pPBES2.enciv);
	    }
	    pPBES2.enc = hEnc;
	},

        /*
         * convert from PBES2 parameters to PKCS#8 encrypted private key ASN1 object
         * @name 
         * @memberOf KEYUTIL
         * @function generatePBES2ASN1Param
	 * @param {object} param associative array object of parameters for encrypted PKCS#8 private key
	 * @param {object} associative array object of ASN1 object
         * @since jsrsasign 10.9.0 keyutil 1.3.0
	 * @see KEYUTIL.getEncryptedPKCS8PEM
	 * @see KEYUTIL.getEncryptedPKCS8Hex
	 * @see KJUR.asn1.ASN1Util.newObject
	 *
         * @description
         * <br/>
	 * convert from PBES2 paramters to ASN1 object which can be
	 * passwd to {@link KJUR.asn1.ASN1Util.newObject}.
	 * Here is input members in PBES2 paramters.
	 * <ul>
	 * <li>encalg - encryption algorithm</li>
	 * <li>iter - iteration count</li>
	 * <li>prf - psudorandom function</li>
	 * <li>salt - salt</li>
	 * <li>enciv - initial vector</li>
	 * <li>enc - encrypted private key</li>
	 * </ul>
	 * Note that prf will be omitted when prf is a default "hmacWithSHA1".
         */
	generatePBES2ASN1Param: function(pPBES2) {
	    var pASN = 
		{ seq: [
		    { seq: [
			{ oid: "pkcs5PBES2" },
			{ seq: [
			    { seq: [
				{ oid: "pkcs5PBKDF2" },
				{ seq: [
				    { octstr: { hex: pPBES2.salt } },
				    { "int": { hex: inttohex(pPBES2.iter) } }
				] }
			    ] },
			    { seq: [
				{ oid: pPBES2.encalg },
				{ octstr: { hex: pPBES2.enciv } }
			    ] }
			] }
		    ] },
		    { octstr: { hex: pPBES2.enc } }
		] };
	    if (pPBES2.prf != "hmacWithSHA1") {
		pASN.seq[0].seq[1].seq[0].seq[1].seq.push({seq:[{oid:pPBES2.prf},{"null":""}]});
	    }
	    return pASN;
	},

        // === PKCS8 ===============================================================

        /**
         * generate PBKDF2 key hexstring with specified passcode and information (DEPRECATED)
         * @name parseHexOfEncryptedPKCS8
         * @memberOf KEYUTIL
         * @function
         * @param {String} passcode passcode to decrypto private key
         * @return {Array} info associative array of PKCS#8 parameters
         * @since pkcs5pkey 1.0.3
	 * @deprecated since jsrsasign 10.9.0 keyutil 1.3.0. Use {@link KEYUTIL.parsePBES2} instead.
	 *
         * @description
         * The associative array which is returned by this method has following properties:
         * <ul>
         * <li>info.pbkdf2Salt - hexadecimal string of PBKDF2 salt</li>
         * <li>info.pkbdf2Iter - iteration count</li>
         * <li>info.ciphertext - hexadecimal string of encrypted private key</li>
         * <li>info.encryptionSchemeAlg - encryption algorithm name (currently TripleDES only)</li>
         * <li>info.encryptionSchemeIV - initial vector for encryption algorithm</li>
         * </ul>
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        parseHexOfEncryptedPKCS8: function(sHEX) {
	    var _ASN1HEX = ASN1HEX;
	    var _getChildIdx = _ASN1HEX.getChildIdx;
	    var _getV = _ASN1HEX.getV;
            var info = {};
            
            var a0 = _getChildIdx(sHEX, 0);
            if (a0.length != 2)
                throw new Error("malformed format: SEQUENCE(0).items != 2: " +
				a0.length);

            // 1. ciphertext
            info.ciphertext = _getV(sHEX, a0[1]);

            // 2. pkcs5PBES2
            var a0_0 = _getChildIdx(sHEX, a0[0]); 
            if (a0_0.length != 2)
                throw new Error("malformed format: SEQUENCE(0.0).items != 2: "
				+ a0_0.length);

            // 2.1 check if pkcs5PBES2(1 2 840 113549 1 5 13)
            if (_getV(sHEX, a0_0[0]) != "2a864886f70d01050d")
                throw new Error("this only supports pkcs5PBES2");

            // 2.2 pkcs5PBES2 param
            var a0_0_1 = _getChildIdx(sHEX, a0_0[1]); 
            if (a0_0.length != 2)
                throw new Error("malformed format: SEQUENCE(0.0.1).items != 2: "
				+ a0_0_1.length);

            // 2.2.1 encryptionScheme
            var a0_0_1_1 = _getChildIdx(sHEX, a0_0_1[1]); 
            if (a0_0_1_1.length != 2)
                throw new Error("malformed format: " + 
				"SEQUENCE(0.0.1.1).items != 2: " +
				a0_0_1_1.length);
            if (_getV(sHEX, a0_0_1_1[0]) != "2a864886f70d0307")
                throw "this only supports TripleDES";
            info.encryptionSchemeAlg = "TripleDES";

            // 2.2.1.1 IV of encryptionScheme
            info.encryptionSchemeIV = _getV(sHEX, a0_0_1_1[1]);

            // 2.2.2 keyDerivationFunc
            var a0_0_1_0 = _getChildIdx(sHEX, a0_0_1[0]); 
            if (a0_0_1_0.length != 2)
                throw new Error("malformed format: " +
				"SEQUENCE(0.0.1.0).items != 2: "
				+ a0_0_1_0.length);
            if (_getV(sHEX, a0_0_1_0[0]) != "2a864886f70d01050c")
                throw new Error("this only supports pkcs5PBKDF2");

            // 2.2.2.1 pkcs5PBKDF2 param
            var a0_0_1_0_1 = _getChildIdx(sHEX, a0_0_1_0[1]); 
            if (a0_0_1_0_1.length < 2)
                throw new Error("malformed format: " +
				"SEQUENCE(0.0.1.0.1).items < 2: " + 
				a0_0_1_0_1.length);

            // 2.2.2.1.1 PBKDF2 salt
            info.pbkdf2Salt = _getV(sHEX, a0_0_1_0_1[0]);

            // 2.2.2.1.2 PBKDF2 iter
            var iterNumHex = _getV(sHEX, a0_0_1_0_1[1]);
            try {
                info.pbkdf2Iter = parseInt(iterNumHex, 16);
            } catch(ex) {
                throw new Error("malformed format pbkdf2Iter: " + iterNumHex);
            }

            return info;
        },

        /**
         * generate PBKDF2 key hexstring with specified passcode and information (DEPRECATED)
         * @name getPBKDF2KeyHexFromParam
         * @memberOf KEYUTIL
         * @function
         * @param {Array} info result of {@link parseHexOfEncryptedPKCS8} which has preference of PKCS#8 file
         * @param {String} passcode passcode to decrypto private key
         * @return {String} hexadecimal string of PBKDF2 key
         * @since pkcs5pkey 1.0.3
	 * @deprecated since jsrsasign 10.9.0 keyutil 1.3.0. Use {@link KEYUTIL.getDKFromPBES2Param} instead.
	 *
         * @description
         * As for info, this uses following properties:
         * <ul>
         * <li>info.pbkdf2Salt - hexadecimal string of PBKDF2 salt</li>
         * <li>info.pkbdf2Iter - iteration count</li>
         * </ul>
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 des3 -out encrypted_p8.pem
         */
        getPBKDF2KeyHexFromParam: function(info, passcode) {
            var pbkdf2SaltWS = CryptoJS.enc.Hex.parse(info.pbkdf2Salt);
            var pbkdf2Iter = info.pbkdf2Iter;
            var pbkdf2KeyWS = CryptoJS.PBKDF2(passcode, 
                                              pbkdf2SaltWS, 
                                              { keySize: 192/32, iterations: pbkdf2Iter });
            var pbkdf2KeyHex = CryptoJS.enc.Hex.stringify(pbkdf2KeyWS);
            return pbkdf2KeyHex;
        },

        /*
         * read PEM formatted encrypted PKCS#8 private key and returns hexadecimal string of plain PKCS#8 private key (DEPRECATED)
         * @name getPlainPKCS8HexFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM PEM formatted encrypted PKCS#8 private key
         * @param {String} passcode passcode to decrypto private key
         * @return {String} hexadecimal string of plain PKCS#8 private key
         * @since pkcs5pkey 1.0.3
	 * @deprecated since jsrsasign 10.9.0 keyutil 1.3.0. Use {@link KEYUTIL.getPlainHexFromEncryptedPKCS8PEM} instead.
	 * 
         * @description
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        _getPlainPKCS8HexFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            // 1. derHex - PKCS#8 private key encrypted by PBKDF2
            var derHex = pemtohex(pkcs8PEM, "ENCRYPTED PRIVATE KEY");
            // 2. info - PKCS#5 PBES info
            var info = this.parseHexOfEncryptedPKCS8(derHex);
            // 3. hKey - PBKDF2 key
            var pbkdf2KeyHex = KEYUTIL.getPBKDF2KeyHexFromParam(info, passcode);
            // 4. decrypt ciphertext by PBKDF2 key
            var encrypted = {};
            encrypted.ciphertext = CryptoJS.enc.Hex.parse(info.ciphertext);
            var pbkdf2KeyWS = CryptoJS.enc.Hex.parse(pbkdf2KeyHex);
            var des3IVWS = CryptoJS.enc.Hex.parse(info.encryptionSchemeIV);
            var decWS = CryptoJS.TripleDES.decrypt(encrypted, pbkdf2KeyWS, { iv: des3IVWS });
            var decHex = CryptoJS.enc.Hex.stringify(decWS);
            return decHex;
        },

	/**
         * parse ASN.1 hexadecimal encrypted PKCS#8 private key and return as JSON
         * @name parsePBES2
         * @memberOf KEYUTIL
         * @function
         * @param {string} hP8Prv hexadecimal encrypted PKCS#8 private key
	 * @return {object} parsed PBES2 parameters JSON object
         * @since jsrsasign 10.9.0 keyutil 1.3.0
         * @description
	 * This method parses ASN.1 hexadecimal encrypted PKCS#8 private key and returns as 
	 * JSON object based on 
	 * <a href="https://datatracker.ietf.org/doc/html/rfc8018" target="_blank">RFC 8018</a>.
	 * Currently following algorithms are supported:
	 * <ul>
	 * <li>prf(psudorandom function) - hmacWithSHA1,SHA224,SHA256,SHA384,SHA512</li>
	 * <li>encryptionScheme - des-EDE3-CBC,aes128-CBC,aes256-CBC</li>
	 * </ul>
	 * @see KEYUTIL.getDKFromPBES2Param
	 *
         * @example
	 * KEYUTIL.parsePBES2("3082...") &rarr;
	 * {
	 *   "prf": "hmacWithSHA256",
	 *   "salt": "1234567890abcdef",
	 *   "iter": 2048,
	 *   "encalg": "aes256-CBC",
	 *   "enciv": "12ab...",
	 *   "enc": "34cd..."
	 * }
	 *
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 des3 -out encrypted_p8.pem
	 */
	parsePBES2: function(hP8Prv) {
	    var pASN = ASN1HEX.parse(hP8Prv);
	    if (aryval(pASN, "seq.0.seq.0.oid") != "pkcs5PBES2" ||
		aryval(pASN, "seq.0.seq.1.seq.0.seq.0.oid") != "pkcs5PBKDF2") {
		throw new Error("not pkcs5PBES2 and pkcs5PBKDF2 used");
	    }
	    var pASNKDF = aryval(pASN, "seq.0.seq.1.seq.0.seq.1.seq");
	    if (pASNKDF == undefined) {
		throw new Error("PBKDF2 parameter not found");
	    }
	    var salt = aryval(pASNKDF, "0.octstr.hex");
	    var hIter = aryval(pASNKDF, "1.int.hex");
	    var prf = aryval(pASNKDF, "2.seq.0.oid", "hmacWithSHA1");
		
	    var iter = -1;
	    try {
		iter = parseInt(hIter, 16);
	    } catch(ex) {
		throw new Error("iter not proper value");
	    };

	    var encalg = aryval(pASN, "seq.0.seq.1.seq.1.seq.0.oid");
	    var enciv = aryval(pASN, "seq.0.seq.1.seq.1.seq.1.octstr.hex");
	    var enc = aryval(pASN, "seq.1.octstr.hex");
	    if (encalg == undefined || enciv == undefined || enc == undefined)
		throw new Error("encalg, enciv or enc is undefined");

	    var result = {
		salt: salt,
		iter: iter,
		prf: prf,
		encalg: encalg,
		enciv: enciv,
		enc: enc
	    };
	    return result;
	},

	/**
         * get derived key from PBES2 parameters and passcode
         * @name getDKFromPBES2Param
         * @memberOf KEYUTIL
         * @function
         * @param {object} pPBES2 parsed PBES2 parameter by {@link KEYUTIL.parsePBES2} method
	 * @param {string} passcode password to derive the key
	 * @return {string} hexadecimal string of derived key
         * @since jsrsasign 10.9.0 keyutil 1.3.0
	 * @see KEYUTIL.parsePBES2
	 *
         * @description
	 * This method derives a key from a passcode and a PBES2 parameter by 
	 * {@link KEYUTIL.parsePBES2}.
	 * Currently following algorithms are supported:
	 * <ul>
	 * <li>prf(psudorandom function) - hmacWithSHA1,SHA224,SHA256,SHA384,SHA512</li>
	 * <li>encryptionScheme - des-EDE3-CBC,aes128-CBC,aes256-CBC</li>
	 * </ul>
	 *
         * @example
	 * pPBES2 = {
	 *   "prf": "hmacWithSHA256",
	 *   "salt": "1234567890abcdef",
	 *   "iter": 2048,
	 *   "encalg": "aes256-CBC",
	 *   "enciv": "12ab...",
	 *   "enc": "34cd..."
	 * }
	 * KEYUTIL.getDKFromPBES2Param(pPBES2, "passwd") &rarr; "3ab10fd..."
	 */
	getDKFromPBES2Param: function(pPBES2, passcode) {
	    var pHasher = {
		"hmacWithSHA1":   CryptoJS.algo.SHA1,
		"hmacWithSHA224": CryptoJS.algo.SHA224,
		"hmacWithSHA256": CryptoJS.algo.SHA256,
		"hmacWithSHA384": CryptoJS.algo.SHA384,
		"hmacWithSHA512": CryptoJS.algo.SHA512
	    };
	    var pKeySize = {
		"des-EDE3-CBC": 192/32,
		"aes128-CBC": 128/32,
		"aes256-CBC": 256/32,
	    };

	    var hasher = pHasher[pPBES2.prf];
	    if (hasher == undefined)
		throw new Error("unsupported prf");

	    var keysize = pKeySize[pPBES2.encalg];
	    if (keysize == undefined)
		throw new Error("unsupported encalg");

	    var wSalt = CryptoJS.enc.Hex.parse(pPBES2.salt);
	    var iter = pPBES2.iter;
	    try {
		var wKey = CryptoJS.PBKDF2(passcode,
					   wSalt,
					   { keySize: keysize,
					     iterations: iter,
					     hasher: hasher }); 
		return CryptoJS.enc.Hex.stringify(wKey);
	    } catch(ex) {
		throw new Error("PBKDF2 error: " + ex + " " + JSON.stringify(pPBES2) + " " + passcode);
	    }
	},

	/**
         * get plaintext hexadecimal PKCS#8 private key from encrypted PKCS#8 PEM private key 
         * @name getPlainHexFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {string} pkcs8PEM PEM string of encrypted PKCS#8 private key
	 * @param {string} passcode passcode to decrypt the private key
	 * @return {string} hexadecimal string of decrypted plaintext PKCS#8 private key
         * @since jsrsasign 10.9.0 keyutil 1.3.0
	 * @see KEYUTIL.parsePBES2
	 *
         * @description
	 * This will get a plaintext hexadecimal PKCS#8 private key from a
	 * encrypted PKCS#8 PEM private key.
	 * Currently following algorithms are supported:
	 * <ul>
	 * <li>prf(psudorandom function) - hmacWithSHA1,SHA224,SHA256,SHA384,SHA512</li>
	 * <li>encryptionScheme - des-EDE3-CBC,aes128-CBC,aes256-CBC</li>
	 * </ul>
	 *
         * @example
	 * pem = "-----BEGIN ENCRYPTED PRIVATE KEY...";
	 * KEYUTIL.getPlainHexFromEncryptedPKCS8PEM(pem, "passwd") &rarr; "3082..."
	 */
	getPlainHexFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
	    if (pkcs8PEM.indexOf("BEGIN ENCRYPTED PRIVATE KEY") == -1)
		throw new Error("not Encrypted PKCS#8 PEM string");
	    var hPBES2 = pemtohex(pkcs8PEM);
	    var pPBES2;
	    try {
		pPBES2 = KEYUTIL.parsePBES2(hPBES2);
	    } catch(ex) {
		throw new Error("malformed PBES2 format: " + ex.message);
	    }
	    var hKey = KEYUTIL.getDKFromPBES2Param(pPBES2, passcode);
	    return KJUR.crypto.Cipher.decrypt(pPBES2.enc, hKey, pPBES2.encalg, { iv: pPBES2.enciv });
	},

        /**
         * get RSAKey/ECDSA private key object from encrypted PEM PKCS#8 private key
         * @name getKeyFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM string of PEM formatted PKCS#8 private key
         * @param {String} passcode passcode string to decrypt key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
	    var prvKeyHex = this.getPlainHexFromEncryptedPKCS8PEM(pkcs8PEM, passcode);
            var key = this.getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
            return key;
        },

        /**
         * parse hexadecimal string of plain PKCS#8 private key
         * @name parsePlainPrivatePKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 plain private key
         * @return {Array} associative array of parsed key
         * @since pkcs5pkey 1.0.5
         * @description
         * Resulted associative array has following properties:
         * <ul>
         * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
         * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
         * <li>keyidx - string starting index of key in pkcs8PrvHex</li>
         * </ul>
         */
        parsePlainPrivatePKCS8Hex: function(pkcs8PrvHex) {
	    var _ASN1HEX = ASN1HEX;
	    var _getChildIdx = _ASN1HEX.getChildIdx;
	    var _getV = _ASN1HEX.getV;
            var result = {};
            result.algparam = null;

            // 1. sequence
            if (pkcs8PrvHex.substr(0, 2) != "30")
                throw new Error("malformed plain PKCS8 private key(code:001)");
	        // not sequence

            var a1 = _getChildIdx(pkcs8PrvHex, 0);
            if (a1.length < 3)
                throw new Error("malformed plain PKCS8 private key(code:002)");
                // less elements

            // 2. AlgID
            if (pkcs8PrvHex.substr(a1[1], 2) != "30")
                throw new Error("malformed PKCS8 private key(code:003)");
                // AlgId not sequence

            var a2 = _getChildIdx(pkcs8PrvHex, a1[1]);
            if (a2.length != 2)
                throw new Error("malformed PKCS8 private key(code:004)");
                // AlgId not have two elements

            // 2.1. AlgID OID
            if (pkcs8PrvHex.substr(a2[0], 2) != "06")
                throw new Error("malformed PKCS8 private key(code:005)");
                // AlgId.oid is not OID

            result.algoid = _getV(pkcs8PrvHex, a2[0]);

            // 2.2. AlgID param
            if (pkcs8PrvHex.substr(a2[1], 2) == "06") {
                result.algparam = _getV(pkcs8PrvHex, a2[1]);
            }

            // 3. Key index
            if (pkcs8PrvHex.substr(a1[2], 2) != "04")
                throw new Error("malformed PKCS8 private key(code:006)");
                // not octet string

            result.keyidx = _ASN1HEX.getVidx(pkcs8PrvHex, a1[2]);

            return result;
        },

        /**
         * get RSAKey/ECDSA private key object from PEM plain PEM PKCS#8 private key
         * @name getKeyFromPlainPrivatePKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM string of plain PEM formatted PKCS#8 private key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPlainPrivatePKCS8PEM: function(prvKeyPEM) {
            var prvKeyHex = pemtohex(prvKeyPEM, "PRIVATE KEY");
            var key = this.getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
            return key;
        },

        /**
         * get RSAKey/DSA/ECDSA private key object from HEX plain PEM PKCS#8 private key
         * @name getKeyFromPlainPrivatePKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} prvKeyHex hexadecimal string of plain PKCS#8 private key
         * @return {Object} RSAKey or KJUR.crypto.{DSA,ECDSA} private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPlainPrivatePKCS8Hex: function(prvKeyHex) {
            var p8 = this.parsePlainPrivatePKCS8Hex(prvKeyHex);
	    var key;
            
            if (p8.algoid == "2a864886f70d010101") { // RSA
		key = new RSAKey();
	    } else if (p8.algoid == "2a8648ce380401") { // DSA
		key = new KJUR.crypto.DSA();
            } else if (p8.algoid == "2a8648ce3d0201") { // ECC
                key = new KJUR.crypto.ECDSA();
            } else {
                throw new Error("unsupported private key algorithm");
            }

	    key.readPKCS8PrvKeyHex(prvKeyHex);
	    return key;
        },

        // === PKCS8 RSA Public Key ================================================

        /*
         * get RSAKey/DSA/ECDSA public key object from hexadecimal string of PKCS#8 public key
         * @name _getKeyFromPublicPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcsPub8Hex hexadecimal string of PKCS#8 public key
         * @return {Object} RSAKey or KJUR.crypto.{ECDSA,DSA} private key object
         * @since pkcs5pkey 1.0.5
         */
        _getKeyFromPublicPKCS8Hex: function(h) {
	    var key;
	    var hOID = ASN1HEX.getVbyList(h, 0, [0, 0], "06");

	    if (hOID === "2a864886f70d010101") {    // oid=RSA
		key = new RSAKey();
	    } else if (hOID === "2a8648ce380401") { // oid=DSA
		key = new KJUR.crypto.DSA();
	    } else if (hOID === "2a8648ce3d0201") { // oid=ECPUB
		key = new KJUR.crypto.ECDSA();
	    } else {
		throw new Error("unsupported PKCS#8 public key hex");
	    }
	    key.readPKCS8PubKeyHex(h);
	    return key;
	},

        /**
         * parse hexadecimal string of plain PKCS#8 private key
         * @name parsePublicRawRSAKeyHex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pubRawRSAHex hexadecimal string of ASN.1 encoded PKCS#8 public key
         * @return {Array} associative array of parsed key
         * @since pkcs5pkey 1.0.5
         * @description
         * Resulted associative array has following properties:
         * <ul>
         * <li>n - hexadecimal string of public key
         * <li>e - hexadecimal string of public exponent
         * </ul>
         */
        parsePublicRawRSAKeyHex: function(pubRawRSAHex) {
	    var _ASN1HEX = ASN1HEX;
	    var _getChildIdx = _ASN1HEX.getChildIdx;
	    var _getV = _ASN1HEX.getV;
            var result = {};
            
            // 1. Sequence
            if (pubRawRSAHex.substr(0, 2) != "30")
                throw new Error("malformed RSA key(code:001)"); // not sequence
            
            var a1 = _getChildIdx(pubRawRSAHex, 0);
            if (a1.length != 2)
                throw new Error("malformed RSA key(code:002)"); // not 2 items in seq

            // 2. public key "N"
            if (pubRawRSAHex.substr(a1[0], 2) != "02")
                throw new Error("malformed RSA key(code:003)"); // 1st item is not integer

            result.n = _getV(pubRawRSAHex, a1[0]);

            // 3. public key "E"
            if (pubRawRSAHex.substr(a1[1], 2) != "02")
                throw new Error("malformed RSA key(code:004)"); // 2nd item is not integer

            result.e = _getV(pubRawRSAHex, a1[1]);

            return result;
        },

        /**
         * parse hexadecimal string of PKCS#8 RSA/EC/DSA public key
         * @name parsePublicPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PubHex hexadecimal string of PKCS#8 public key
         * @return {Hash} hash of key information
         * @description
         * Resulted hash has following attributes.
         * <ul>
         * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
         * <li>algparam - hexadecimal string of OID of ECC curve name, parameter SEQUENCE of DSA or null</li>
         * <li>key - hexadecimal string of public key</li>
         * </ul>
         */
        parsePublicPKCS8Hex: function(pkcs8PubHex) {
	    var _ASN1HEX = ASN1HEX;
	    var _getChildIdx = _ASN1HEX.getChildIdx;
	    var _getV = _ASN1HEX.getV;
            var result = {};
            result.algparam = null;

            // 1. AlgID and Key bit string
            var a1 = _getChildIdx(pkcs8PubHex, 0);
            if (a1.length != 2)
                throw new Error("outer DERSequence shall have 2 elements: " + a1.length);

            // 2. AlgID
            var idxAlgIdTLV = a1[0];
            if (pkcs8PubHex.substr(idxAlgIdTLV, 2) != "30")
                throw new Error("malformed PKCS8 public key(code:001)"); // AlgId not sequence

            var a2 = _getChildIdx(pkcs8PubHex, idxAlgIdTLV);
            if (a2.length != 2)
                throw new Error("malformed PKCS8 public key(code:002)"); // AlgId not have two elements

            // 2.1. AlgID OID
            if (pkcs8PubHex.substr(a2[0], 2) != "06")
                throw new Error("malformed PKCS8 public key(code:003)"); // AlgId.oid is not OID

            result.algoid = _getV(pkcs8PubHex, a2[0]);

            // 2.2. AlgID param
            if (pkcs8PubHex.substr(a2[1], 2) == "06") { // OID for EC
                result.algparam = _getV(pkcs8PubHex, a2[1]);
            } else if (pkcs8PubHex.substr(a2[1], 2) == "30") { // SEQ for DSA
                result.algparam = {};
                result.algparam.p = _ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [0], "02");
                result.algparam.q = _ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [1], "02");
                result.algparam.g = _ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [2], "02");
            }

            // 3. Key
            if (pkcs8PubHex.substr(a1[1], 2) != "03")
                throw new Error("malformed PKCS8 public key(code:004)"); // Key is not bit string

            result.key = _getV(pkcs8PubHex, a1[1]).substr(2);
            
            // 4. return result assoc array
            return result;
        },
    };
}();

// -- MAJOR PUBLIC METHODS ----------------------------------------------------
/**
 * get private or public key object from any arguments
 * @name getKey
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object} param parameter to get key object. see description in detail.
 * @param {String} passcode (OPTION) parameter to get key object. see description in detail.
 * @param {String} hextype (OPTOIN) parameter to get key object. see description in detail.
 * @return {Object} {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.ECDSA} object
 * @since keyutil 1.0.0
 * @description
 * This method gets private or public key object({@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA})
 * for RSA, DSA and ECC.
 * Arguments for this methods depends on a key format you specify.
 * Following key representations are supported.
 * <ul>
 * <li>ECC private/public key object(as is): param=KJUR.crypto.ECDSA</li>
 * <li>DSA private/public key object(as is): param=KJUR.crypto.DSA</li>
 * <li>RSA private/public key object(as is): param=RSAKey </li>
 * <li>ECC private key parameters: param={d: d, curve: curveName}</li>
 * <li>RSA private key parameters: param={n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, co: co}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>DSA private key parameters: param={p: p, q: q, g: g, y: y, x: x}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>ECC public key parameters: param={xy: xy, curve: curveName}<br/>
 * NOTE: ECC public key 'xy' shall be concatination of "04", x-bytes-hex and y-bytes-hex.</li>
 * <li>DSA public key parameters: param={p: p, q: q, g: g, y: y}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>RSA public key parameters: param={n: n, e: e} </li>
 * <li>X.509v1/v3 PEM certificate (RSA/DSA/ECC): param=pemString</li>
 * <li>PKCS#8 hexadecimal RSA/ECC public key: param=pemString, null, "pkcs8pub"</li>
 * <li>PKCS#8 PEM RSA/DSA/ECC public key: param=pemString</li>
 * <li>PKCS#5 plain hexadecimal RSA private key: param=hexString, null, "pkcs5prv"</li>
 * <li>PKCS#5 plain PEM RSA/DSA/EC private key: param=pemString</li>
 * <li>PKCS#8 plain PEM RSA/EC private key: param=pemString</li>
 * <li>PKCS#5 encrypted PEM RSA/DSA/EC private key: param=pemString, passcode</li>
 * <li>PKCS#8 encrypted PEM RSA/EC private key: param=pemString, passcode</li>
 * </ul>
 * Please note following limitation on encrypted keys:
 * <ul>
 * <li>Encrypted PKCS#8 only supports PBKDF2/HmacSHA1/3DES</li>
 * <li>Encrypted PKCS#5 supports DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC</li>
 * <li>JWT plain ECC private/public key</li>
 * <li>JWT plain RSA public key</li>
 * <li>JWT plain RSA private key with P/Q/DP/DQ/COEFF</li>
 * <li>JWT plain RSA private key without P/Q/DP/DQ/COEFF (since jsrsasign 5.0.0)</li>
 * </ul>
 * NOTE1: <a href="https://tools.ietf.org/html/rfc7517">RFC 7517 JSON Web Key(JWK)</a> support for RSA/ECC private/public key from jsrsasign 4.8.1.<br/>
 * NOTE2: X509v1 support is added since jsrsasign 5.0.11.
 * 
 * <h5>EXAMPLE</h5>
 * @example
 * // 1. loading private key from PEM string
 * keyObj = KEYUTIL.getKey("-----BEGIN RSA PRIVATE KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN RSA PRIVATE KEY..., "passcode");
 * keyObj = KEYUTIL.getKey("-----BEGIN PRIVATE KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN PRIVATE KEY...", "passcode");
 * keyObj = KEYUTIL.getKey("-----BEGIN EC PARAMETERS...-----BEGIN EC PRIVATE KEY...");
 * // 2. loading public key from PEM string
 * keyObj = KEYUTIL.getKey("-----BEGIN PUBLIC KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN X509 CERTIFICATE...");
 * // 3. loading hexadecimal PKCS#5/PKCS#8 key
 * keyObj = KEYUTIL.getKey("308205c1...", null, "pkcs8pub");
 * keyObj = KEYUTIL.getKey("3082048b...", null, "pkcs5prv");
 * // 4. loading JSON Web Key(JWK)
 * keyObj = KEYUTIL.getKey({kty: "RSA", n: "0vx7...", e: "AQAB"});
 * keyObj = KEYUTIL.getKey({kty: "EC", crv: "P-256", 
 *                          x: "MKBC...", y: "4Etl6...", d: "870Mb..."});
 * // 5. bare hexadecimal key
 * keyObj = KEYUTIL.getKey({n: "75ab..", e: "010001"});
 */
KEYUTIL.getKey = function(param, passcode, hextype) {
    var _ASN1HEX = ASN1HEX,
	_getChildIdx = _ASN1HEX.getChildIdx,
	_getV = _ASN1HEX.getV,
	_getVbyList = _ASN1HEX.getVbyList,
	_KJUR_crypto = KJUR.crypto,
	_KJUR_crypto_ECDSA = _KJUR_crypto.ECDSA,
	_KJUR_crypto_DSA = _KJUR_crypto.DSA,
	_RSAKey = RSAKey,
	_pemtohex = pemtohex,
	_KEYUTIL = KEYUTIL;

    // 1. by key RSAKey/KJUR.crypto.ECDSA/KJUR.crypto.DSA object
    if (typeof _RSAKey != 'undefined' && param instanceof _RSAKey)
        return param;
    if (typeof _KJUR_crypto_ECDSA != 'undefined' && param instanceof _KJUR_crypto_ECDSA)
        return param;
    if (typeof _KJUR_crypto_DSA != 'undefined' && param instanceof _KJUR_crypto_DSA)
        return param;

    // 2. by parameters of key

    // 2.1. bare ECC
    // 2.1.1. bare ECC public key by hex values
    if (param.curve !== undefined &&
	param.xy !== undefined && param.d === undefined) {
        return new _KJUR_crypto_ECDSA({pub: param.xy, curve: param.curve});
    }

    // 2.1.2. bare ECC private key by hex values
    if (param.curve !== undefined && param.d !== undefined) {
        return new _KJUR_crypto_ECDSA({prv: param.d, curve: param.curve});
    }

    // 2.2. bare RSA
    // 2.2.1. bare RSA public key by hex values
    if (param.kty === undefined &&
	param.n !== undefined && param.e !== undefined &&
        param.d === undefined) {
        var key = new _RSAKey();
        key.setPublic(param.n, param.e);
        return key;
    }

    // 2.2.2. bare RSA private key with P/Q/DP/DQ/COEFF by hex values
    if (param.kty === undefined &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
        param.p !== undefined &&
	param.q !== undefined &&
        param.dp !== undefined &&
	param.dq !== undefined &&
	param.co !== undefined &&
        param.qi === undefined) {
        var key = new _RSAKey();
        key.setPrivateEx(param.n, param.e, param.d, param.p, param.q,
                         param.dp, param.dq, param.co);
        return key;
    }

    // 2.2.3. bare RSA public key without P/Q/DP/DQ/COEFF by hex values
    if (param.kty === undefined &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
        param.p === undefined) {
        var key = new _RSAKey();
        key.setPrivate(param.n, param.e, param.d);
        return key;
    }

    // 2.3. bare DSA
    // 2.3.1. bare DSA public key by hex values
    if (param.p !== undefined && param.q !== undefined &&
	param.g !== undefined &&
        param.y !== undefined && param.x === undefined) {
        var key = new _KJUR_crypto_DSA();
        key.setPublic(param.p, param.q, param.g, param.y);
        return key;
    }

    // 2.3.2. bare DSA private key by hex values
    if (param.p !== undefined && param.q !== undefined &&
	param.g !== undefined &&
        param.y !== undefined && param.x !== undefined) {
        var key = new _KJUR_crypto_DSA();
        key.setPrivate(param.p, param.q, param.g, param.y, param.x);
        return key;
    }

    // 3. JWK
    // 3.1. JWK RSA
    // 3.1.1. JWK RSA public key by b64u values
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d === undefined) {
	var key = new _RSAKey();
	key.setPublic(b64utohex(param.n), b64utohex(param.e));
	return key;
    }

    // 3.1.2. JWK RSA private key with p/q/dp/dq/coeff by b64u values
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
	param.p !== undefined &&
	param.q !== undefined &&
	param.dp !== undefined &&
	param.dq !== undefined &&
	param.qi !== undefined) {
	var key = new _RSAKey();
        key.setPrivateEx(b64utohex(param.n),
			 b64utohex(param.e),
			 b64utohex(param.d),
			 b64utohex(param.p),
			 b64utohex(param.q),
                         b64utohex(param.dp),
			 b64utohex(param.dq),
			 b64utohex(param.qi));
	return key;
    }

    // 3.1.3. JWK RSA private key without p/q/dp/dq/coeff by b64u
    //        since jsrsasign 5.0.0 keyutil 1.0.11
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined) {
	var key = new _RSAKey();
        key.setPrivate(b64utohex(param.n),
		       b64utohex(param.e),
		       b64utohex(param.d));
	return key;
    }

    // 3.2. JWK ECC
    // 3.2.1. JWK ECC public key by b64u values
    if (param.kty === "EC" &&
	param.crv !== undefined &&
	param.x !== undefined &&
	param.y !== undefined &&
        param.d === undefined) {
	var ec = new _KJUR_crypto_ECDSA({"curve": param.crv});
	var charlen = ec.ecparams.keycharlen;
        var hX   = ("0000000000" + b64utohex(param.x)).slice(- charlen);
        var hY   = ("0000000000" + b64utohex(param.y)).slice(- charlen);
        var hPub = "04" + hX + hY;
	ec.setPublicKeyHex(hPub);
	return ec;
    }

    // 3.2.2. JWK ECC private key by b64u values
    if (param.kty === "EC" &&
	param.crv !== undefined &&
	param.x !== undefined &&
	param.y !== undefined &&
        param.d !== undefined) {
	var ec = new _KJUR_crypto_ECDSA({"curve": param.crv});
	var charlen = ec.ecparams.keycharlen;
        var hX   = ("0000000000" + b64utohex(param.x)).slice(- charlen);
        var hY   = ("0000000000" + b64utohex(param.y)).slice(- charlen);
        var hPub = "04" + hX + hY;
        var hPrv = ("0000000000" + b64utohex(param.d)).slice(- charlen);
	ec.setPublicKeyHex(hPub);
	ec.setPrivateKeyHex(hPrv);
	return ec;
    }
    
    // 4. (plain) hexadecimal data
    // 4.1. get private key by PKCS#5 plain RSA/DSA/ECDSA hexadecimal string
    if (hextype === "pkcs5prv") {
	var h = param, _ASN1HEX = ASN1HEX, a, key;
	a = _getChildIdx(h, 0);
	if (a.length === 9) {        // RSA (INT x 9)
	    key = new _RSAKey();
            key.readPKCS5PrvKeyHex(h);
	} else if (a.length === 6) { // DSA (INT x 6)
	    key = new _KJUR_crypto_DSA();
	    key.readPKCS5PrvKeyHex(h);
	} else if (a.length > 2 &&   // ECDSA (INT, OCT prv, [0] curve, [1] pub)
		   h.substr(a[1], 2) === "04") {
	    key = new _KJUR_crypto_ECDSA();
	    key.readPKCS5PrvKeyHex(h);
	} else {
	    throw new Error("unsupported PKCS#1/5 hexadecimal key");
	}

        return key;
    }

    // 4.2. get private key by PKCS#8 plain RSA/DSA/ECDSA hexadecimal string
    if (hextype === "pkcs8prv") {
	var key = _KEYUTIL.getKeyFromPlainPrivatePKCS8Hex(param);
        return key;
    }

    // 4.3. get public key by PKCS#8 RSA/DSA/ECDSA hexadecimal string
    if (hextype === "pkcs8pub") {
        return _KEYUTIL._getKeyFromPublicPKCS8Hex(param);
    }

    // 4.4. get public key by X.509 hexadecimal string for RSA/DSA/ECDSA
    if (hextype === "x509pub") {
        return X509.getPublicKeyFromCertHex(param);
    }

    // 5. by PEM certificate (-----BEGIN ... CERTIFICATE----)
    if (param.indexOf("-END CERTIFICATE-", 0) != -1 ||
        param.indexOf("-END X509 CERTIFICATE-", 0) != -1 ||
        param.indexOf("-END TRUSTED CERTIFICATE-", 0) != -1) {
        return X509.getPublicKeyFromCertPEM(param);
    }

    // 6. public key by PKCS#8 PEM string
    if (param.indexOf("-END PUBLIC KEY-") != -1) {
        var pubKeyHex = pemtohex(param, "PUBLIC KEY");
        return _KEYUTIL._getKeyFromPublicPKCS8Hex(pubKeyHex);
    }
    
    // 8.1 private key by plain PKCS#5 PEM RSA string 
    //    getKey("-----BEGIN RSA PRIVATE KEY-...")
    if (param.indexOf("-END RSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") == -1) {
        var hex = _pemtohex(param, "RSA PRIVATE KEY");
        return _KEYUTIL.getKey(hex, null, "pkcs5prv");
    }

    // 8.2. private key by plain PKCS#5 PEM DSA string
    if (param.indexOf("-END DSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") == -1) {

        var hKey = _pemtohex(param, "DSA PRIVATE KEY");
        var p = _getVbyList(hKey, 0, [1], "02");
        var q = _getVbyList(hKey, 0, [2], "02");
        var g = _getVbyList(hKey, 0, [3], "02");
        var y = _getVbyList(hKey, 0, [4], "02");
        var x = _getVbyList(hKey, 0, [5], "02");
        var key = new _KJUR_crypto_DSA();
        key.setPrivate(new BigInteger(p, 16),
                       new BigInteger(q, 16),
                       new BigInteger(g, 16),
                       new BigInteger(y, 16),
                       new BigInteger(x, 16));
        return key;
    }

    // 8.3. private key by plain PKCS#5 PEM EC string
    if (param.indexOf("-END EC PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") == -1) {
        var hex = _pemtohex(param, "EC PRIVATE KEY");
        return _KEYUTIL.getKey(hex, null, "pkcs5prv");
    }

    // 10. private key by plain PKCS#8 PEM ECC/RSA string
    if (param.indexOf("-END PRIVATE KEY-") != -1) {
        return _KEYUTIL.getKeyFromPlainPrivatePKCS8PEM(param);
    }

    // 11.1 private key by encrypted PKCS#5 PEM RSA string
    if (param.indexOf("-END RSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        var hPKey = _KEYUTIL.getDecryptedKeyHex(param, passcode);
        var rsaKey = new RSAKey();
        rsaKey.readPKCS5PrvKeyHex(hPKey);
        return rsaKey;
    }

    // 11.2. private key by encrypted PKCS#5 PEM ECDSA string
    if (param.indexOf("-END EC PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        var hKey = _KEYUTIL.getDecryptedKeyHex(param, passcode);

        var key = _getVbyList(hKey, 0, [1], "04");
        var curveNameOidHex = _getVbyList(hKey, 0, [2,0], "06");
        var pubkey = _getVbyList(hKey, 0, [3,0], "03").substr(2);
        var curveName = "";

        if (KJUR.crypto.OID.oidhex2name[curveNameOidHex] !== undefined) {
            curveName = KJUR.crypto.OID.oidhex2name[curveNameOidHex];
        } else {
            throw new Error("undefined OID(hex) in KJUR.crypto.OID: " + 
			    curveNameOidHex);
        }

        var ec = new _KJUR_crypto_ECDSA({'curve': curveName});
        ec.setPublicKeyHex(pubkey);
        ec.setPrivateKeyHex(key);
        ec.isPublic = false;
        return ec;
    }

    // 11.3. private key by encrypted PKCS#5 PEM DSA string
    if (param.indexOf("-END DSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        var hKey = _KEYUTIL.getDecryptedKeyHex(param, passcode);
        var p = _getVbyList(hKey, 0, [1], "02");
        var q = _getVbyList(hKey, 0, [2], "02");
        var g = _getVbyList(hKey, 0, [3], "02");
        var y = _getVbyList(hKey, 0, [4], "02");
        var x = _getVbyList(hKey, 0, [5], "02");
        var key = new _KJUR_crypto_DSA();
        key.setPrivate(new BigInteger(p, 16),
                       new BigInteger(q, 16),
                       new BigInteger(g, 16),
                       new BigInteger(y, 16),
                       new BigInteger(x, 16));
        return key;
    }

    // 11. private key by encrypted PKCS#8 hexadecimal RSA/ECDSA string
    if (param.indexOf("-END ENCRYPTED PRIVATE KEY-") != -1) {
        return _KEYUTIL.getKeyFromEncryptedPKCS8PEM(param, passcode);
    }

    throw new Error("not supported argument");
};

/**
 * @name generateKeypair
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {String} alg 'RSA' or 'EC'
 * @param {Object} keylenOrCurve key length for RSA or curve name for EC
 * @return {Array} associative array of keypair which has prvKeyObj and pubKeyObj parameters
 * @since keyutil 1.0.1
 * @description
 * This method generates a key pair of public key algorithm.
 * The result will be an associative array which has following
 * parameters:
 * <ul>
 * <li>prvKeyObj - RSAKey or ECDSA object of private key</li>
 * <li>pubKeyObj - RSAKey or ECDSA object of public key</li>
 * </ul>
 * NOTE1: As for RSA algoirthm, public exponent has fixed
 * value '0x10001'.
 * NOTE2: As for EC algorithm, supported names of curve are
 * secp256r1, secp256k1, secp384r1 and secp521r1.
 * NOTE3: DSA is not supported yet.
 * @example
 * var rsaKeypair = KEYUTIL.generateKeypair("RSA", 1024);
 * var ecKeypair = KEYUTIL.generateKeypair("EC", "secp256r1");
 *
 */
KEYUTIL.generateKeypair = function(alg, keylenOrCurve) {
    if (alg == "RSA") {
        var keylen = keylenOrCurve;
        var prvKey = new RSAKey();
        prvKey.generate(keylen, '10001');
        prvKey.isPrivate = true;
        prvKey.isPublic = true;
        
        var pubKey = new RSAKey();
        var hN = prvKey.n.toString(16);
        var hE = prvKey.e.toString(16);
        pubKey.setPublic(hN, hE);
        pubKey.isPrivate = false;
        pubKey.isPublic = true;
        
        var result = {};
        result.prvKeyObj = prvKey;
        result.pubKeyObj = pubKey;
        return result;
    } else if (alg == "EC") {
        var curve = keylenOrCurve;
        var ec = new KJUR.crypto.ECDSA({curve: curve});
        var keypairHex = ec.generateKeyPairHex();

        var prvKey = new KJUR.crypto.ECDSA({curve: curve});
        prvKey.setPublicKeyHex(keypairHex.ecpubhex);
        prvKey.setPrivateKeyHex(keypairHex.ecprvhex);
        prvKey.isPrivate = true;
        prvKey.isPublic = false;

        var pubKey = new KJUR.crypto.ECDSA({curve: curve});
        pubKey.setPublicKeyHex(keypairHex.ecpubhex);
        pubKey.isPrivate = false;
        pubKey.isPublic = true;

        var result = {};
        result.prvKeyObj = prvKey;
        result.pubKeyObj = pubKey;
        return result;
    } else {
        throw new Error("unknown algorithm: " + alg);
    }
};

/**
 * get PEM formatted private or public key file from a RSA/ECDSA/DSA key object
 * @name getPEM
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object} keyObjOrHex key object {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.DSA} to encode to
 * @param {String} formatType (OPTION) output format type of "PKCS1PRV", "PKCS5PRV" or "PKCS8PRV" for private key
 * @param {String} passwd (OPTION) password to protect private key
 * @param {String} encAlg (OPTION) encryption algorithm for PKCS#5. currently supports DES-CBC, DES-EDE3-CBC and AES-{128,192,256}-CBC
 * @param {String} hexType (OPTION) type of hex string (ex. pkcs5prv, pkcs8prv)
 * @param {String} ivsaltHex hexadecimal string of IV and salt (default generated random IV)
 * @since keyutil 1.0.4
 *
 * @description
 * <dl>
 * <dt><b>NOTE1:</b>
 * <dd>
 * PKCS#5 encrypted private key protection algorithm supports DES-CBC, 
 * DES-EDE3-CBC and AES-{128,192,256}-CBC
 * <dt><b>NOTE2:</b>
 * <dd>
 * OpenSSL supports
 * <dt><b>NOTE3:</b>
 * <dd>
 * Parameter "ivsaltHex" supported since jsrsasign 8.0.0 keyutil 1.2.0.
 * </dl>
 *
 * @example
 * KEUUTIL.getPEM(publicKey) &rarr; generates PEM PKCS#8 public key 
 * KEUUTIL.getPEM(privateKey) &rarr; generates PEM PKCS#8 plain private key by default
 * KEUUTIL.getPEM(privateKey, "PKCS1PRV") &rarr; generates PEM PKCS#1 plain private key
 * KEUUTIL.getPEM(privateKey, "PKCS5PRV", "pass") &rarr; generates PEM PKCS#5 encrypted private key 
 *                                                          with DES-EDE3-CBC (DEFAULT)
 * KEUUTIL.getPEM(privateKey, "PKCS5PRV", "pass", "DES-CBC") &rarr; generates PEM PKCS#5 encrypted 
 *                                                                 private key with DES-CBC
 * KEUUTIL.getPEM(privateKey, "PKCS8PRV") &rarr; generates PEM PKCS#8 plain private key
 * KEUUTIL.getPEM(privateKey, "PKCS8PRV", "pass") &rarr; generates PEM PKCS#8 encrypted private key
 *                                                      with PBKDF2_HmacSHA1_3DES
 */
KEYUTIL.getPEM = function(keyObjOrHex, formatType, passwd, encAlg, hexType, ivsaltHex) {
    var _KJUR = KJUR,
	_KJUR_asn1 = _KJUR.asn1,
	_DERObjectIdentifier = _KJUR_asn1.DERObjectIdentifier,
	_DERInteger = _KJUR_asn1.DERInteger,
	_newObject = _KJUR_asn1.ASN1Util.newObject,
	_KJUR_asn1_x509 = _KJUR_asn1.x509,
	_SubjectPublicKeyInfo = _KJUR_asn1_x509.SubjectPublicKeyInfo,
	_KJUR_crypto = _KJUR.crypto,
	_DSA = _KJUR_crypto.DSA,
	_ECDSA = _KJUR_crypto.ECDSA,
	_RSAKey = RSAKey;

    function _rsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj = _newObject({
            "seq": [
                {"int": 0 },
                {"int": {"bigint": keyObjOrHex.n}},
                {"int": keyObjOrHex.e},
                {"int": {"bigint": keyObjOrHex.d}},
                {"int": {"bigint": keyObjOrHex.p}},
                {"int": {"bigint": keyObjOrHex.q}},
                {"int": {"bigint": keyObjOrHex.dmp1}},
                {"int": {"bigint": keyObjOrHex.dmq1}},
                {"int": {"bigint": keyObjOrHex.coeff}}
            ]
        });
        return asn1Obj;
    };

    function _ecdsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj2 = _newObject({
            "seq": [
                {"int": 1 },
                {"octstr": {"hex": keyObjOrHex.prvKeyHex}},
                {"tag": ['a0', true, {'oid': {'name': keyObjOrHex.curveName}}]},
                {"tag": ['a1', true, {'bitstr': {'hex': '00' + keyObjOrHex.pubKeyHex}}]}
            ]
        });
        return asn1Obj2;
    };

    function _dsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj = _newObject({
            "seq": [
                {"int": 0 },
                {"int": {"bigint": keyObjOrHex.p}},
                {"int": {"bigint": keyObjOrHex.q}},
                {"int": {"bigint": keyObjOrHex.g}},
                {"int": {"bigint": keyObjOrHex.y}},
                {"int": {"bigint": keyObjOrHex.x}}
            ]
        });
        return asn1Obj;
    };

    // 1. public key

    // x. PEM PKCS#8 public key of RSA/ECDSA/DSA public key object
    if (((_RSAKey !== undefined && keyObjOrHex instanceof _RSAKey) ||
         (_DSA !== undefined    && keyObjOrHex instanceof _DSA) ||
         (_ECDSA !== undefined  && keyObjOrHex instanceof _ECDSA)) &&
        keyObjOrHex.isPublic == true &&
        (formatType === undefined || formatType == "PKCS8PUB")) {
        var asn1Obj = new _SubjectPublicKeyInfo(keyObjOrHex);
        var asn1Hex = asn1Obj.tohex();
        return hextopem(asn1Hex, "PUBLIC KEY");
    }
    
    // 2. private

    // x. PEM PKCS#1 plain private key of RSA private key object
    if (formatType == "PKCS1PRV" &&
        _RSAKey !== undefined &&
        keyObjOrHex instanceof _RSAKey &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _rsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.tohex();
        return hextopem(asn1Hex, "RSA PRIVATE KEY");
    }

    // x. PEM PKCS#1 plain private key of ECDSA private key object
    if (formatType == "PKCS1PRV" &&
        _ECDSA !== undefined &&
        keyObjOrHex instanceof _ECDSA &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj1 = 
	    new _DERObjectIdentifier({'name': keyObjOrHex.curveName});
        var asn1Hex1 = asn1Obj1.tohex();
        var asn1Obj2 = _ecdsaprv2asn1obj(keyObjOrHex);
        var asn1Hex2 = asn1Obj2.tohex();

        var s = "";
        s += hextopem(asn1Hex1, "EC PARAMETERS");
        s += hextopem(asn1Hex2, "EC PRIVATE KEY");
        return s;
    }

    // x. PEM PKCS#1 plain private key of DSA private key object
    if (formatType == "PKCS1PRV" &&
        _DSA !== undefined &&
        keyObjOrHex instanceof _DSA &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _dsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.tohex();
        return hextopem(asn1Hex, "DSA PRIVATE KEY");
    }

    // 3. private

    // x. PEM PKCS#5 encrypted private key of RSA private key object
    if (formatType == "PKCS5PRV" &&
        _RSAKey !== undefined &&
        keyObjOrHex instanceof _RSAKey &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _rsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.tohex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA", asn1Hex, passwd, encAlg, ivsaltHex);
    }

    // x. PEM PKCS#5 encrypted private key of ECDSA private key object
    if (formatType == "PKCS5PRV" &&
        _ECDSA !== undefined &&
        keyObjOrHex instanceof _ECDSA &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _ecdsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.tohex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("EC", asn1Hex, passwd, encAlg, ivsaltHex);
    }

    // x. PEM PKCS#5 encrypted private key of DSA private key object
    if (formatType == "PKCS5PRV" &&
        _DSA !== undefined &&
        keyObjOrHex instanceof _DSA &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _dsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.tohex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("DSA", asn1Hex, passwd, encAlg, ivsaltHex);
    }

    // x. ======================================================================
    
    var _getEncryptedPKCS8PEM = function(plainKeyHex, passcodeOrParam) {
	if (typeof passcodeOrParam == "string") {
	    return KEYUTIL.getEncryptedPKCS8PEM(plainKeyHex, passcodeOrParam);
	} else if (typeof passcodeOrParam == "object" && aryval(passcodeOrParam, "passcode") != undefined) {
	    var param = JSON.parse(JSON.stringify(passcodeOrParam));
	    var passcode = param.passcode;
	    delete param.passcode;
	    return KEYUTIL.getEncryptedPKCS8PEM(plainKeyHex, passcode, param);
	}
    };

    // x. PEM PKCS#8 plain private key of RSA private key object
    if (formatType == "PKCS8PRV" &&
        _RSAKey != undefined &&
        keyObjOrHex instanceof _RSAKey &&
        keyObjOrHex.isPrivate  == true) {

        var keyObj = _rsaprv2asn1obj(keyObjOrHex);
        var keyHex = keyObj.tohex();

        var asn1Obj = _newObject({
            "seq": [
                {"int": 0},
                {"seq": [{"oid": {"name": "rsaEncryption"}},{"null": true}]},
                {"octstr": {"hex": keyHex}}
            ]
        });
        var asn1Hex = asn1Obj.tohex();

        if (passwd === undefined || passwd == null) {
            return hextopem(asn1Hex, "PRIVATE KEY");
        } else {
            return _getEncryptedPKCS8PEM(asn1Hex, passwd);
        }
    }

    // x. PEM PKCS#8 plain private key of ECDSA private key object
    if (formatType == "PKCS8PRV" &&
        _ECDSA !== undefined &&
        keyObjOrHex instanceof _ECDSA &&
        keyObjOrHex.isPrivate  == true) {

	var pKeyObj = {
            "seq": [
                {"int": 1},
                {"octstr": {"hex": keyObjOrHex.prvKeyHex}}
            ]
        };
	if (typeof keyObjOrHex.pubKeyHex == "string") {
	    pKeyObj.seq.push({"tag": ['a1', true, {"bitstr": {"hex": "00" + keyObjOrHex.pubKeyHex}}]});
	}
        var keyObj = new _newObject(pKeyObj);
        var keyHex = keyObj.tohex();

        var asn1Obj = _newObject({
            "seq": [
                {"int": 0},
                {"seq": [
                    {"oid": {"name": "ecPublicKey"}},
                    {"oid": {"name": keyObjOrHex.curveName}}
                ]},
                {"octstr": {"hex": keyHex}}
            ]
        });

        var asn1Hex = asn1Obj.tohex();
        if (passwd === undefined || passwd == null) {
            return hextopem(asn1Hex, "PRIVATE KEY");
        } else {
            return _getEncryptedPKCS8PEM(asn1Hex, passwd);
        }
    }

    // x. PEM PKCS#8 plain private key of DSA private key object
    if (formatType == "PKCS8PRV" &&
        _DSA !== undefined &&
        keyObjOrHex instanceof _DSA &&
        keyObjOrHex.isPrivate  == true) {

        var keyObj = new _DERInteger({'bigint': keyObjOrHex.x});
        var keyHex = keyObj.tohex();

        var asn1Obj = _newObject({
            "seq": [
                {"int": 0},
                {"seq": [
                    {"oid": {"name": "dsa"}},
                    {"seq": [
                        {"int": {"bigint": keyObjOrHex.p}},
                        {"int": {"bigint": keyObjOrHex.q}},
                        {"int": {"bigint": keyObjOrHex.g}}
                    ]}
                ]},
                {"octstr": {"hex": keyHex}}
            ]
        });

        var asn1Hex = asn1Obj.tohex();
        if (passwd === undefined || passwd == null) {
            return hextopem(asn1Hex, "PRIVATE KEY");
        } else {
            return _getEncryptedPKCS8PEM(asn1Hex, passwd);
        }
    }

    throw new Error("unsupported object nor format");
};

// -- PUBLIC METHODS FOR CSR --------------------------------------------------

/**
 * get RSAKey/DSA/ECDSA public key object from PEM formatted PKCS#10 CSR string
 * @name getKeyFromCSRPEM
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrPEM PEM formatted PKCS#10 CSR string
 * @return {Object} RSAKey/DSA/ECDSA public key object
 * @since keyutil 1.0.5
 */
KEYUTIL.getKeyFromCSRPEM = function(csrPEM) {
    var csrHex = pemtohex(csrPEM, "CERTIFICATE REQUEST");
    var key = KEYUTIL.getKeyFromCSRHex(csrHex);
    return key;
};

/**
 * get RSAKey/DSA/ECDSA public key object from hexadecimal string of PKCS#10 CSR
 * @name getKeyFromCSRHex
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrHex hexadecimal string of PKCS#10 CSR
 * @return {Object} RSAKey/DSA/ECDSA public key object
 * @since keyutil 1.0.5
 */
KEYUTIL.getKeyFromCSRHex = function(csrHex) {
    var info = KEYUTIL.parseCSRHex(csrHex);
    var key = KEYUTIL.getKey(info.p8pubkeyhex, null, "pkcs8pub");
    return key;
};

/**
 * parse hexadecimal string of PKCS#10 CSR (certificate signing request)
 * @name parseCSRHex
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrHex hexadecimal string of PKCS#10 CSR
 * @return {Array} associative array of parsed CSR
 * @since keyutil 1.0.5
 * @description
 * Resulted associative array has following properties:
 * <ul>
 * <li>p8pubkeyhex - hexadecimal string of subject public key in PKCS#8</li>
 * </ul>
 */
KEYUTIL.parseCSRHex = function(csrHex) {
    var _ASN1HEX = ASN1HEX;
    var _getChildIdx = _ASN1HEX.getChildIdx;
    var _getTLV = _ASN1HEX.getTLV;
    var result = {};
    var h = csrHex;

    // 1. sequence
    if (h.substr(0, 2) != "30")
        throw new Error("malformed CSR(code:001)"); // not sequence

    var a1 = _getChildIdx(h, 0);
    if (a1.length < 1)
        throw new Error("malformed CSR(code:002)"); // short length

    // 2. 2nd sequence
    if (h.substr(a1[0], 2) != "30")
        throw new Error("malformed CSR(code:003)"); // not sequence

    var a2 = _getChildIdx(h, a1[0]);
    if (a2.length < 3)
        throw new Error("malformed CSR(code:004)"); // 2nd seq short elem

    result.p8pubkeyhex = _getTLV(h, a2[2]);

    return result;
};

// -- ENCRYPTED PKCS#8 PRIVATE KEY GENERATION METHODS  ------------------------

// -- OTHER STATIC PUBLIC METHODS  --------------------------------------------

/**
 * get key ID by public key object for subject or authority key identifier
 * @name getKeyID
 * @memberof KEYUTIL
 * @function
 * @static
 * @param {Object} obj RSAKey/KJUR.crypto.ECDSA,DSA public key object or public key PEM string
 * @return hexadecimal string of public key identifier
 * @since keyutil 1.2.2 jsrsasign 5.0.16
 * @description
 * This static method generates a key identifier from a public key
 * by the method described in 
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.2"
 * target="_blank">RFC 5280 4.2.1.2. Subject Key Identifier (1)</a>.
 * @example
 * pubkeyobj = KEYUTIL.getKey(...);
 * KEYTUTIL.getKey(pubkeyobj) &rarr; "a612..."
 */
KEYUTIL.getKeyID = function(obj) {
    var _KEYUTIL = KEYUTIL;
    var _ASN1HEX = ASN1HEX;

    if (typeof obj  === "string" && obj.indexOf("BEGIN ") != -1) {
	obj = _KEYUTIL.getKey(obj);
    }

    var p8hex = pemtohex(_KEYUTIL.getPEM(obj));
    var idx = _ASN1HEX.getIdxbyList(p8hex, 0, [1]); // BITSTRING
    var hV = _ASN1HEX.getV(p8hex, idx).substring(2); // value without unused bit
    return KJUR.crypto.Util.hashHex(hV, "sha1");
}

/**
 * convert from certificate, public/private key object to RFC 7517 JSON Web Key(JWK)<br/>
 * @name getJWK
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object or string} keyinfo public/private key object, PEM key or PEM certificate
 * @param {boolean} nokid set true if you don't need kid (OPTION, DEFAULT=undefined)
 * @param {boolean} nox5c set true if you don't need x5c of certificate (OPTION, DEFAULT=undefined)
 * @param {boolean} nox5t set true if you don't need x5t of certificate (OPTION, DEFAULT=undefined)
 * @param {boolean} nox5t2 set true if you don't need x5c#S256 of certificate (OPTION, DEFAULT=undefined)
 * @return {Object} JWK object
 * @since keyutil 1.2.5 jsrsasign 10.5.1
 * @see RSAKey
 * @see KJUR.crypto.ECDSA
 * @see KJUR.crypto.DSA
 *
 * @description
 * This static method provides 
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517">
 * RFC 7517 JSON Web Key(JWK) JSON</a>
 * object from following argument types:
 * <ul>
 * <li>
 * <b>JWK private key</b>
 * <ul>
 * <li>RSAKey or KJUR.crypto.{ECDSA,DSA} private key object</li>
 * <li>PKCS#5 or PKCS#8 plain PEM private key</li>
 * </ul>
 * </li>
 * <li>
 * <b>JWK public key</b>
 * <ul>
 * <li>RSAKey or KJUR.crypto.{ECDSA,DSA} public key object</li>
 * <li>PKCS#5 or PKCS#8 PEM public key</li>
 * <li>X509 certificate object</li>
 * <li>PEM certificate</li>
 * </ul>
 * </li>
 * </ul>
 * 
 * @example
 * kp1 = KEYUTIL.generateKeypair("EC", "P-256");
 * jwkPrv1 = KEYUTIL.getJWK(kp1.prvKeyObj);
 * jwkPub1 = KEYUTIL.getJWK(kp1.pubKeyObj);
 *
 * kp2 = KEYUTIL.generateKeypair("RSA", 2048);
 * jwkPrv2 = KEYUTIL.getJWK(kp2.prvKeyObj);
 * jwkPub2 = KEYUTIL.getJWK(kp2.pubKeyObj);
 *
 * // from PEM certificate
 * KEYUTIL.getJWK("-----BEGIN CERTIFICATE...") &rarr;
 * {
 *   kty: "EC", crv: "P-521", x: "...", y: "...",
 *   x5c: ["MI..."],
 *   x5t: "...",
 *   "x5t#S256": "...",
 *   kid: "..."
 * }
 *
 * // from X509 object
 * x509obj = new X509("-----BEGIN CERTIFICATE...");
 * KEYUTIL.getJWK(x509obj) &rarr;
 * {
 *   kty: "EC", crv: "P-521", x: "...", y: "...",
 *   ...
 * }
 *
 * // from PEM certificate without kid, x5t and x5t#S256 (i.e. only x5c)
 * KEYUTIL.getJWK("-----BEGIN CERTIFICATE...", true, false, true, true) &rarr;
 * {
 *   kty: "EC", crv: "P-521", x: "...", y: "...",
 *   x5c: ["MI..."]
 * }
 */
KEYUTIL.getJWK = function(keyinfo, nokid, nox5c, nox5t, nox5t2) {
    var keyObj;
    var jwk = {};
    var hCert;
    var _hashHex = KJUR.crypto.Util.hashHex;

    if (typeof keyinfo == "string") {
	keyObj = KEYUTIL.getKey(keyinfo);
	if (keyinfo.indexOf("CERTIFICATE") != -1) {
	    hCert = pemtohex(keyinfo)
	}
    } else if (typeof keyinfo == "object") {
	if (keyinfo instanceof X509) {
	    keyObj = keyinfo.getPublicKey();
	    hCert = keyinfo.hex;
	} else {
	    keyObj = keyinfo;
	}
    } else {
	throw new Error("unsupported keyinfo type");
    }

    if (keyObj instanceof RSAKey && keyObj.isPrivate) {
	jwk.kty = "RSA";
	jwk.n = hextob64u(keyObj.n.toString(16));
	jwk.e = hextob64u(keyObj.e.toString(16));
	jwk.d = hextob64u(keyObj.d.toString(16));
	jwk.p = hextob64u(keyObj.p.toString(16));
	jwk.q = hextob64u(keyObj.q.toString(16));
	jwk.dp = hextob64u(keyObj.dmp1.toString(16));
	jwk.dq = hextob64u(keyObj.dmq1.toString(16));
	jwk.qi = hextob64u(keyObj.coeff.toString(16));
    } else if (keyObj instanceof RSAKey && keyObj.isPublic) {
	jwk.kty = "RSA";
	jwk.n = hextob64u(keyObj.n.toString(16));
	jwk.e = hextob64u(keyObj.e.toString(16));
    } else if (keyObj instanceof KJUR.crypto.ECDSA && keyObj.isPrivate) {
	var name = keyObj.getShortNISTPCurveName();
	if (name !== "P-256" && name !== "P-384" && name !== "P-521" && name !== "secp256k1")
	    throw new Error("unsupported curve name for JWT: " + name);
	var xy = keyObj.getPublicKeyXYHex();
	jwk.kty = "EC";
	jwk.crv =  name;
	jwk.x = hextob64u(xy.x);
	jwk.y = hextob64u(xy.y);
	jwk.d = hextob64u(keyObj.prvKeyHex);
    } else if (keyObj instanceof KJUR.crypto.ECDSA && keyObj.isPublic) {
	var name = keyObj.getShortNISTPCurveName();
	if (name !== "P-256" && name !== "P-384" && name !== "P-521" && name !== "secp256k1")
	    throw new Error("unsupported curve name for JWT: " + name);
	var xy = keyObj.getPublicKeyXYHex();
	jwk.kty = "EC";
	jwk.crv =  name;
	jwk.x = hextob64u(xy.x);
	jwk.y = hextob64u(xy.y);
    }
    if (jwk.kty == undefined) throw new Error("unsupported keyinfo");

    if ((! keyObj.isPrivate) && nokid != true) {
	jwk.kid = KJUR.jws.JWS.getJWKthumbprint(jwk);
    }

    if (hCert != undefined && nox5c != true) {
	jwk.x5c = [hex2b64(hCert)];
    }

    if (hCert != undefined && nox5t != true) {
	jwk.x5t = b64tob64u(hex2b64(_hashHex(hCert, "sha1")));
    }

    if (hCert != undefined && nox5t2 != true) {
	jwk["x5t#S256"] = b64tob64u(hex2b64(_hashHex(hCert, "sha256")));
    }

    return jwk;
};

/**
 * convert from RSAKey/KJUR.crypto.ECDSA public/private key object to RFC 7517 JSON Web Key(JWK) (DEPRECATED)<br/>
 * @name getJWKFromKey
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object} RSAKey/KJUR.crypto.ECDSA public/private key object
 * @return {Object} JWK object
 * @since keyutil 1.0.13 jsrsasign 5.0.14
 * @deprecated since jsrsasign 10.5.1 keyutil 1.2.5 please use getJWK method
 * @see KEYUTIL.getJWK
 *
 * @description
 * This static method convert from RSAKey/KJUR.crypto.ECDSA public/private key object 
 * to RFC 7517 JSON Web Key(JWK)
 * 
 * @example
 * kp1 = KEYUTIL.generateKeypair("EC", "P-256");
 * jwkPrv1 = KEYUTIL.getJWKFromKey(kp1.prvKeyObj);
 * jwkPub1 = KEYUTIL.getJWKFromKey(kp1.pubKeyObj);
 *
 * kp2 = KEYUTIL.generateKeypair("RSA", 2048);
 * jwkPrv2 = KEYUTIL.getJWKFromKey(kp2.prvKeyObj);
 * jwkPub2 = KEYUTIL.getJWKFromKey(kp2.pubKeyObj);
 *
 * // if you need RFC 7638 JWK thumprint as kid do like this:
 * jwkPub2.kid = KJUR.jws.JWS.getJWKthumbprint(jwkPub2);
 */
KEYUTIL.getJWKFromKey = function(keyObj) {
    return KEYUTIL.getJWK(keyObj, true, true, true, true);
}
