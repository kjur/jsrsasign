/*! pkcs5pkey-1.0.7.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * pkcs5pkey.js - reading passcode protected PKCS#5 PEM formatted RSA private key
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
 * @name pkcs5pkey-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version pkcs5pkey 1.0.7 (2016-Oct-08)
 * @since jsrsasign 2.0.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * @name PKCS5PKEY
 * @class class for PKCS#5 and PKCS#8 private key 
 * @deprecated Since jsrsasign 4.1.3. Please use KEYUTIL class.
 * @description 
 * <br/>
 * {@link PKCS5PKEY} class has following features:
 * <ul>
 * <li>read and parse PEM formatted encrypted PKCS#5 private key
 * <li>generate PEM formatted encrypted PKCS#5 private key
 * <li>read and parse PEM formatted plain PKCS#8 private key
 * <li>read and parse PEM formatted encrypted PKCS#8 private key by PBKDF2/HmacSHA1/3DES
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
 * <h5>METHOD SUMMARY</h5>
 * <dl>
 * <dt><b>PKCS8 PRIVATE KEY METHODS</b><dd>
 * <ul>
 * <li>{@link PKCS5PKEY.getRSAKeyFromPlainPKCS8PEM} - convert plain PKCS8 PEM to RSAKey object</li>
 * <li>{@link PKCS5PKEY.getRSAKeyFromPlainPKCS8Hex} - convert plain PKCS8 hexadecimal data to RSAKey object</li>
 * <li>{@link PKCS5PKEY.getRSAKeyFromEncryptedPKCS8PEM} - convert encrypted PKCS8 PEM to RSAKey object</li>
 * <li>{@link PKCS5PKEY.getPlainPKCS8HexFromEncryptedPKCS8PEM} - convert encrypted PKCS8 PEM to plain PKCS8 Hex</li>
 * </ul>
 * <dt><b>PKCS5 PRIVATE KEY METHODS</b><dd>
 * <ul>
 * <li>{@link PKCS5PKEY.getRSAKeyFromEncryptedPKCS5PEM} - convert encrypted PKCS5 PEM to RSAKey object</li>
 * <li>{@link PKCS5PKEY.getEncryptedPKCS5PEMFromRSAKey} - convert RSAKey object to encryped PKCS5 PEM</li>
 * <li>{@link PKCS5PKEY.newEncryptedPKCS5PEM} - generate RSAKey and its encrypted PKCS5 PEM</li>
 * </ul>
 * <dt><b>PKCS8 PUBLIC KEY METHODS</b><dd>
 * <ul>
 * <li>{@link PKCS5PKEY.getKeyFromPublicPKCS8PEM} - convert encrypted PKCS8 PEM to RSAKey/ECDSA object</li>
 * <li>{@link PKCS5PKEY.getKeyFromPublicPKCS8Hex} - convert encrypted PKCS8 Hex to RSAKey/ECDSA object</li>
 * <li>{@link PKCS5PKEY.getRSAKeyFromPublicPKCS8PEM} - convert encrypted PKCS8 PEM to RSAKey object</li>
 * <li>{@link PKCS5PKEY.getRSAKeyFromPublicPKCS8Hex} - convert encrypted PKCS8 Hex to RSAKey object</li>
 * </ul>
 * <dt><b>UTITILIY METHODS</b><dd>
 * <ul>
 * <li>{@link PKCS5PKEY.getHexFromPEM} - convert PEM string to hexadecimal data</li>
 * <li>{@link PKCS5PKEY.getDecryptedKeyHexByKeyIV} - decrypt key by sharedKey and IV</li>
 * </ul>
 * </dl>
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

    // other methods and properties ----------------------------------------
    var ALGLIST = {
    'AES-256-CBC': { 'proc': decryptAES, 'eproc': encryptAES, keylen: 32, ivlen: 16 },
    'AES-192-CBC': { 'proc': decryptAES, 'eproc': encryptAES, keylen: 24, ivlen: 16 },
    'AES-128-CBC': { 'proc': decryptAES, 'eproc': encryptAES, keylen: 16, ivlen: 16 },
    'DES-EDE3-CBC': { 'proc': decrypt3DES, 'eproc': encrypt3DES, keylen: 24, ivlen: 8 }
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
        // -- UTILITY METHODS ------------------------------------------
        /**
         * decrypt private key by shared key
         * @name version
         * @memberOf PKCS5PKEY
         * @property {String} version
         * @description version string of PKCS5PKEY class
         */
        version: "1.0.5",

        /**
         * get hexacedimal string of PEM format
         * @name getHexFromPEM
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} sPEM PEM formatted string
         * @param {String} sHead PEM header string without BEGIN/END
         * @return {String} hexadecimal string data of PEM contents
         * @since pkcs5pkey 1.0.5
         */
        getHexFromPEM: function(sPEM, sHead) {
            var s = sPEM;
            if (s.indexOf("BEGIN " + sHead) == -1) {
                throw "can't find PEM header: " + sHead;
            }
            s = s.replace("-----BEGIN " + sHead + "-----", "");
            s = s.replace("-----END " + sHead + "-----", "");
            var sB64 = s.replace(/\s+/g, '');
            var dataHex = b64tohex(sB64);
            return dataHex;
        },

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
         * @param {String} sPKCS5PEM PEM formatted protected passcode protected PKCS#5 private key
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
         * @param {String} ivsaltHex hexadecimal string of IV. heading 8 bytes will be used for passcode salt
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
         * @param {String} sEncryptedP5PEM PEM formatted encrypted PKCS#5 private key
         * @param {String} passcode passcode to decrypt private key
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
         * @name getEncryptedPKCS5PEMFromPrvKeyHex
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
         *   PKCS5PKEY.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password");
         * var pem2 = 
         *   PKCS5PKEY.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC");
         * var pem3 = 
         *   PKCS5PKEY.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC", "1f3d02...");
         */
        getEncryptedPKCS5PEMFromPrvKeyHex: function(hPrvKey, passcode, sharedKeyAlgName, ivsaltHex) {
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
         * @name getEncryptedPKCS5PEMFromRSAKey
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
         * var pem = PKCS5PKEY.getEncryptedPKCS5PEMFromRSAKey(pkey, "password");
         */
        getEncryptedPKCS5PEMFromRSAKey: function(pKey, passcode, alg, ivsaltHex) {
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
            return this.getEncryptedPKCS5PEMFromPrvKeyHex(hex, passcode, alg, ivsaltHex);
        },

        /**
         * generate RSAKey and PEM formatted encrypted PKCS#5 private key
         * @name newEncryptedPKCS5PEM
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} passcode pass code to protect private key (ex. password)
         * @param {Integer} keyLen key bit length of RSA key to be generated. (default 1024)
         * @param {String} hPublicExponent hexadecimal string of public exponent (default 10001)
         * @param {String} alg shared key algorithm to encrypt private key (default AES-256-CBC)
         * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
         * @example
         * var pem1 = PKCS5PKEY.newEncryptedPKCS5PEM("password");           // RSA1024bit/10001/AES-256-CBC
         * var pem2 = PKCS5PKEY.newEncryptedPKCS5PEM("password", 512);      // RSA 512bit/10001/AES-256-CBC
         * var pem3 = PKCS5PKEY.newEncryptedPKCS5PEM("password", 512, '3'); // RSA 512bit/    3/AES-256-CBC
         */
        newEncryptedPKCS5PEM: function(passcode, keyLen, hPublicExponent, alg) {
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
            var prvKeyHex = this.getHexFromPEM(pkcs8PEM, "PRIVATE KEY");
            var rsaKey = this.getRSAKeyFromPlainPKCS8Hex(prvKeyHex);
            return rsaKey;
        },

        /**
         * provide hexadecimal string of unencrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromPlainPKCS8Hex
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} prvKeyHex hexadecimal string of unencrypted PKCS#8 private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.3
         */
        getRSAKeyFromPlainPKCS8Hex: function(prvKeyHex) {
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(prvKeyHex, 0);
            if (a1.length != 3)
                throw "outer DERSequence shall have 3 elements: " + a1.length;
            var algIdTLV =ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[1]);
            if (algIdTLV != "300d06092a864886f70d0101010500") // AlgId rsaEncryption
                throw "PKCS8 AlgorithmIdentifier is not rsaEnc: " + algIdTLV;
            var octetStr = ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[2]);
            var p5KeyHex = ASN1HEX.getHexOfV_AtObj(octetStr, 0);
            //alert(p5KeyHex);
            var rsaKey = new RSAKey();
            rsaKey.readPrivateKeyFromASN1HexString(p5KeyHex);
            return rsaKey;
        },

        /**
         * generate PBKDF2 key hexstring with specified passcode and information
         * @name parseHexOfEncryptedPKCS8
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} sHEX passcode to decrypto private key
         * @return {Array} info associative array of PKCS#8 parameters
         * @since pkcs5pkey 1.0.3
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
            var info = {};
        
            var a0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, 0);
            if (a0.length != 2)
                throw "malformed format: SEQUENCE(0).items != 2: " + a0.length;

            // 1. ciphertext
            info.ciphertext = ASN1HEX.getHexOfV_AtObj(sHEX, a0[1]);

            // 2. pkcs5PBES2
            var a0_0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0[0]); 
            if (a0_0.length != 2)
                throw "malformed format: SEQUENCE(0.0).items != 2: " + a0_0.length;

            // 2.1 check if pkcs5PBES2(1 2 840 113549 1 5 13)
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0[0]) != "2a864886f70d01050d")
                throw "this only supports pkcs5PBES2";

            // 2.2 pkcs5PBES2 param
            var a0_0_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0[1]); 
            if (a0_0.length != 2)
                throw "malformed format: SEQUENCE(0.0.1).items != 2: " + a0_0_1.length;

            // 2.2.1 encryptionScheme
            var a0_0_1_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1[1]); 
            if (a0_0_1_1.length != 2)
                throw "malformed format: SEQUENCE(0.0.1.1).items != 2: " + a0_0_1_1.length;
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1[0]) != "2a864886f70d0307")
                throw "this only supports TripleDES";
            info.encryptionSchemeAlg = "TripleDES";

            // 2.2.1.1 IV of encryptionScheme
            info.encryptionSchemeIV = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1[1]);

            // 2.2.2 keyDerivationFunc
            var a0_0_1_0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1[0]); 
            if (a0_0_1_0.length != 2)
                throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + a0_0_1_0.length;
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0[0]) != "2a864886f70d01050c")
                throw "this only supports pkcs5PBKDF2";
            
            // 2.2.2.1 pkcs5PBKDF2 param
            var a0_0_1_0_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1_0[1]); 
            if (a0_0_1_0_1.length < 2)
                throw "malformed format: SEQUENCE(0.0.1.0.1).items < 2: " + a0_0_1_0_1.length;

            // 2.2.2.1.1 PBKDF2 salt
            info.pbkdf2Salt = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[0]);

            // 2.2.2.1.2 PBKDF2 iter
            var iterNumHex = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[1]);
            try {
                info.pbkdf2Iter = parseInt(iterNumHex, 16);
            } catch(ex) {
                throw "malformed format pbkdf2Iter: " + iterNumHex;
            }

            return info;
        },

        /**
         * generate PBKDF2 key hexstring with specified passcode and information
         * @name getPBKDF2KeyHexFromParam
         * @memberOf PKCS5PKEY
         * @function
         * @param {Array} info result of {@link parseHexOfEncryptedPKCS8} which has preference of PKCS#8 file
         * @param {String} passcode passcode to decrypto private key
         * @return {String} hexadecimal string of PBKDF2 key
         * @since pkcs5pkey 1.0.3
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
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
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

        /**
         * read PEM formatted encrypted PKCS#8 private key and returns hexadecimal string of plain PKCS#8 private key
         * @name getPlainPKCS8HexFromEncryptedPKCS8PEM
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PEM PEM formatted encrypted PKCS#8 private key
         * @param {String} passcode passcode to decrypto private key
         * @return {String} hexadecimal string of plain PKCS#8 private key
         * @since pkcs5pkey 1.0.3
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
        getPlainPKCS8HexFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            // 1. derHex - PKCS#8 private key encrypted by PBKDF2
            var derHex = this.getHexFromPEM(pkcs8PEM, "ENCRYPTED PRIVATE KEY");
            // 2. info - PKCS#5 PBES info
            var info = this.parseHexOfEncryptedPKCS8(derHex);
            // 3. hKey - PBKDF2 key
            var pbkdf2KeyHex = PKCS5PKEY.getPBKDF2KeyHexFromParam(info, passcode);
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
         * read PEM formatted encrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromEncryptedPKCS8PEM
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PEM PEM formatted encrypted PKCS#8 private key
         * @param {String} passcode passcode to decrypto private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.3
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
        getRSAKeyFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            var prvKeyHex = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(pkcs8PEM, passcode);
            var rsaKey = this.getRSAKeyFromPlainPKCS8Hex(prvKeyHex);
            return rsaKey;
        },

        /**
         * get RSAKey/ECDSA private key object from encrypted PEM PKCS#8 private key
         * @name getKeyFromEncryptedPKCS8PEM
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PEM string of PEM formatted PKCS#8 private key
         * @param {String} passcode passcode string to decrypt key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            var prvKeyHex = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(pkcs8PEM, passcode);
            var key = this.getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
            return key;
        },

        /**
         * parse hexadecimal string of plain PKCS#8 private key
         * @name parsePlainPrivatePKCS8Hex
         * @memberOf PKCS5PKEY
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
            var result = {};
            result.algparam = null;

            // 1. sequence
            if (pkcs8PrvHex.substr(0, 2) != "30")
                throw "malformed plain PKCS8 private key(code:001)"; // not sequence

            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, 0);
            if (a1.length != 3)
                throw "malformed plain PKCS8 private key(code:002)";

            // 2. AlgID
            if (pkcs8PrvHex.substr(a1[1], 2) != "30")
                throw "malformed PKCS8 private key(code:003)"; // AlgId not sequence

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, a1[1]);
            if (a2.length != 2)
                throw "malformed PKCS8 private key(code:004)"; // AlgId not have two elements

            // 2.1. AlgID OID
            if (pkcs8PrvHex.substr(a2[0], 2) != "06")
                throw "malformed PKCS8 private key(code:005)"; // AlgId.oid is not OID

            result.algoid = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a2[0]);

            // 2.2. AlgID param
            if (pkcs8PrvHex.substr(a2[1], 2) == "06") {
                result.algparam = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a2[1]);
            }

            // 3. Key index
            if (pkcs8PrvHex.substr(a1[2], 2) != "04")
                throw "malformed PKCS8 private key(code:006)"; // not octet string

            result.keyidx = ASN1HEX.getStartPosOfV_AtObj(pkcs8PrvHex, a1[2]);

            return result;
        },

        /**
         * get RSAKey/ECDSA private key object from PEM plain PEM PKCS#8 private key
         * @name getKeyFromPlainPrivatePKCS8PEM
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} prvKeyPEM string of plain PEM formatted PKCS#8 private key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPlainPrivatePKCS8PEM: function(prvKeyPEM) {
            var prvKeyHex = this.getHexFromPEM(prvKeyPEM, "PRIVATE KEY");
            var key = this.getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
            return key;
        },

        /**
         * get RSAKey/ECDSA private key object from HEX plain PEM PKCS#8 private key
         * @name getKeyFromPlainPrivatePKCS8Hex
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} prvKeyHex hexadecimal string of plain PKCS#8 private key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPlainPrivatePKCS8Hex: function(prvKeyHex) {
            var p8 = this.parsePlainPrivatePKCS8Hex(prvKeyHex);
            
            if (p8.algoid == "2a864886f70d010101") { // RSA
                this.parsePrivateRawRSAKeyHexAtObj(prvKeyHex, p8);
                var k = p8.key;
                var key = new RSAKey();
                key.setPrivateEx(k.n, k.e, k.d, k.p, k.q, k.dp, k.dq, k.co);
                return key;
            } else if (p8.algoid == "2a8648ce3d0201") { // ECC
                this.parsePrivateRawECKeyHexAtObj(prvKeyHex, p8);
                if (KJUR.crypto.OID.oidhex2name[p8.algparam] === undefined)
                    throw "KJUR.crypto.OID.oidhex2name undefined: " + p8.algparam;
                var curveName = KJUR.crypto.OID.oidhex2name[p8.algparam];
                var key = new KJUR.crypto.ECDSA({'curve': curveName, 'prv': p8.key});
                return key;
            } else {
                throw "unsupported private key algorithm";
            }
        },

        // === PKCS8 RSA Public Key ================================================
        /**
         * read PEM formatted PKCS#8 public key and returns RSAKey object
         * @name getRSAKeyFromPublicPKCS8PEM
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PubPEM PEM formatted PKCS#8 public key
         * @return {RSAKey} loaded RSAKey object of RSA public key
         * @since pkcs5pkey 1.0.4
         */
        getRSAKeyFromPublicPKCS8PEM: function(pkcs8PubPEM) {
            var pubKeyHex = this.getHexFromPEM(pkcs8PubPEM, "PUBLIC KEY");
            var rsaKey = this.getRSAKeyFromPublicPKCS8Hex(pubKeyHex);
            return rsaKey;
        },

        /**
         * get RSAKey/ECDSA public key object from PEM PKCS#8 public key
         * @name getKeyFromPublicPKCS8PEM
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PubPEM string of PEM formatted PKCS#8 public key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPublicPKCS8PEM: function(pkcs8PubPEM) {
            var pubKeyHex = this.getHexFromPEM(pkcs8PubPEM, "PUBLIC KEY");
            var key = this.getKeyFromPublicPKCS8Hex(pubKeyHex);
            return key;
        },

        /**
         * get RSAKey/ECDSA public key object from hexadecimal string of PKCS#8 public key
         * @name getKeyFromPublicPKCS8Hex
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PubHex hexadecimal string of PKCS#8 public key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPublicPKCS8Hex: function(pkcs8PubHex) {
            var p8 = this.parsePublicPKCS8Hex(pkcs8PubHex);
            
            if (p8.algoid == "2a864886f70d010101") { // RSA
                var aRSA = this.parsePublicRawRSAKeyHex(p8.key);
                var key = new RSAKey();
                key.setPublic(aRSA.n, aRSA.e);
                return key;
            } else if (p8.algoid == "2a8648ce3d0201") { // ECC
                if (KJUR.crypto.OID.oidhex2name[p8.algparam] === undefined)
                    throw "KJUR.crypto.OID.oidhex2name undefined: " + p8.algparam;
                var curveName = KJUR.crypto.OID.oidhex2name[p8.algparam];
                var key = new KJUR.crypto.ECDSA({'curve': curveName, 'pub': p8.key});
                return key;
            } else {
                throw "unsupported public key algorithm";
            }
        },

        /**
         * parse hexadecimal string of plain PKCS#8 private key
         * @name parsePublicRawRSAKeyHex
         * @memberOf PKCS5PKEY
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
            var result = {};
            
            // 1. Sequence
            if (pubRawRSAHex.substr(0, 2) != "30")
                throw "malformed RSA key(code:001)"; // not sequence
            
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pubRawRSAHex, 0);
            if (a1.length != 2)
                throw "malformed RSA key(code:002)"; // not 2 items in seq

            // 2. public key "N"
            if (pubRawRSAHex.substr(a1[0], 2) != "02")
                throw "malformed RSA key(code:003)"; // 1st item is not integer

            result.n = ASN1HEX.getHexOfV_AtObj(pubRawRSAHex, a1[0]);

            // 3. public key "E"
            if (pubRawRSAHex.substr(a1[1], 2) != "02")
                throw "malformed RSA key(code:004)"; // 2nd item is not integer

            result.e = ASN1HEX.getHexOfV_AtObj(pubRawRSAHex, a1[1]);

            return result;
        },

        /**
         * parse hexadecimal string of RSA private key
         * @name parsePrivateRawRSAKeyHexAtObj
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 private key concluding RSA private key
         * @return {Array} info associative array to add parsed RSA private key information
         * @since pkcs5pkey 1.0.5
         * @description
         * Following properties are added to associative array 'info'
         * <ul>
         * <li>n - hexadecimal string of public key
         * <li>e - hexadecimal string of public exponent
         * <li>d - hexadecimal string of private key
         * <li>p - hexadecimal string
         * <li>q - hexadecimal string
         * <li>dp - hexadecimal string
         * <li>dq - hexadecimal string
         * <li>co - hexadecimal string
         * </ul>
         */
        parsePrivateRawRSAKeyHexAtObj: function(pkcs8PrvHex, info) {
            var keyIdx = info.keyidx;
            
            // 1. sequence
            if (pkcs8PrvHex.substr(keyIdx, 2) != "30")
                throw "malformed RSA private key(code:001)"; // not sequence

            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, keyIdx);
            if (a1.length != 9)
                throw "malformed RSA private key(code:002)"; // not sequence

            // 2. RSA key
            info.key = {};
            info.key.n = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[1]);
            info.key.e = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[2]);
            info.key.d = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[3]);
            info.key.p = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[4]);
            info.key.q = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[5]);
            info.key.dp = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[6]);
            info.key.dq = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[7]);
            info.key.co = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[8]);
        },

        /**
         * parse hexadecimal string of ECC private key
         * @name parsePrivateRawECKeyHexAtObj
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 private key concluding EC private key
         * @return {Array} info associative array to add parsed ECC private key information
         * @since pkcs5pkey 1.0.5
         * @description
         * Following properties are added to associative array 'info'
         * <ul>
         * <li>key - hexadecimal string of ECC private key
         * </ul>
         */
        parsePrivateRawECKeyHexAtObj: function(pkcs8PrvHex, info) {
            var keyIdx = info.keyidx;
            
            // 1. sequence
            if (pkcs8PrvHex.substr(keyIdx, 2) != "30")
                throw "malformed ECC private key(code:001)"; // not sequence

            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, keyIdx);
            if (a1.length != 3)
                throw "malformed ECC private key(code:002)"; // not sequence

            // 2. EC private key
            if (pkcs8PrvHex.substr(a1[1], 2) != "04")
                throw "malformed ECC private key(code:003)"; // not octetstring

            info.key = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[1]);
        },

        /**
         * parse hexadecimal string of PKCS#8 public key
         * @name parsePublicPKCS8Hex
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PubHex hexadecimal string of PKCS#8 public key
         * @return {Hash} hash of key information
         * @description
         * Resulted hash has following attributes.
         * <ul>
         * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
         * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
         * <li>key - hexadecimal string of public key</li>
         * </ul>
         */
        parsePublicPKCS8Hex: function(pkcs8PubHex) {
            var result = {};
            result.algparam = null;

            // 1. AlgID and Key bit string
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, 0);
            if (a1.length != 2)
                throw "outer DERSequence shall have 2 elements: " + a1.length;

            // 2. AlgID
            var idxAlgIdTLV = a1[0];
            if (pkcs8PubHex.substr(idxAlgIdTLV, 2) != "30")
                throw "malformed PKCS8 public key(code:001)"; // AlgId not sequence

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, idxAlgIdTLV);
            if (a2.length != 2)
                throw "malformed PKCS8 public key(code:002)"; // AlgId not have two elements

            // 2.1. AlgID OID
            if (pkcs8PubHex.substr(a2[0], 2) != "06")
                throw "malformed PKCS8 public key(code:003)"; // AlgId.oid is not OID

            result.algoid = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[0]);

            // 2.2. AlgID param
            if (pkcs8PubHex.substr(a2[1], 2) == "06") {
                result.algparam = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[1]);
            }

            // 3. Key
            if (pkcs8PubHex.substr(a1[1], 2) != "03")
                throw "malformed PKCS8 public key(code:004)"; // Key is not bit string

            result.key = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a1[1]).substr(2);
            
            // 4. return result assoc array
            return result;
        },

        /**
         * provide hexadecimal string of unencrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromPublicPKCS8Hex
         * @memberOf PKCS5PKEY
         * @function
         * @param {String} pkcs8PubHex hexadecimal string of unencrypted PKCS#8 public key
         * @return {RSAKey} loaded RSAKey object of RSA public key
         * @since pkcs5pkey 1.0.4
         */
        getRSAKeyFromPublicPKCS8Hex: function(pkcs8PubHex) {
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, 0);
            if (a1.length != 2)
                throw "outer DERSequence shall have 2 elements: " + a1.length;

            var algIdTLV =ASN1HEX.getHexOfTLV_AtObj(pkcs8PubHex, a1[0]);
            if (algIdTLV != "300d06092a864886f70d0101010500") // AlgId rsaEncryption
                throw "PKCS8 AlgorithmId is not rsaEncryption";
            
            if (pkcs8PubHex.substr(a1[1], 2) != "03")
                throw "PKCS8 Public Key is not BITSTRING encapslated.";

            var idxPub = ASN1HEX.getStartPosOfV_AtObj(pkcs8PubHex, a1[1]) + 2; // 2 for unused bit
            
            if (pkcs8PubHex.substr(idxPub, 2) != "30")
                throw "PKCS8 Public Key is not SEQUENCE.";

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, idxPub);
            if (a2.length != 2)
                throw "inner DERSequence shall have 2 elements: " + a2.length;

            if (pkcs8PubHex.substr(a2[0], 2) != "02") 
                throw "N is not ASN.1 INTEGER";
            if (pkcs8PubHex.substr(a2[1], 2) != "02") 
                throw "E is not ASN.1 INTEGER";
            
            var hN = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[0]);
            var hE = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[1]);

            var pubKey = new RSAKey();
            pubKey.setPublic(hN, hE);
            
            return pubKey;
        },
    };
}();
