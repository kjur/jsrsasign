/* ecparam-1.0.0.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * ecparam.js - Elliptic Curve Cryptography Curve Parameter Definition class
 *
 * Copyright (c) 2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name ecparam-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.0 (2013-Jul-17)
 * @since jsrsasign 4.0
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * static object for elliptic curve names and parameters
 * @name KJUR.crypto.ECParameterDB
 * @class static object for elliptic curve names and parameters
 * @description
 * This class provides parameters for named elliptic curves.
 * Currently it supoprts following curve names and aliases however 
 * the name marked (*) are available for {@link KJUR.crypto.ECDSA} and
 * {@link KJUR.crypto.Signature} classes.
 * <ul>
 * <li>secp128r1</li>
 * <li>secp160r1</li>
 * <li>secp160k1</li>
 * <li>secp192r1</li>
 * <li>secp192k1</li>
 * <li>secp224r1</li>
 * <li>secp256r1, NIST P-256, P-256, prime256v1 (*)</li>
 * <li>secp256k1 (*)</li>
 * <li>secp384r1, NIST P-384, P-384 (*)</li>
 * <li>secp521r1, NIST P-521, P-521</li>
 * </ul>
 * You can register new curves by using 'register' method.
 */
KJUR.crypto.ECParameterDB = new function() {
    var db = {};
    var aliasDB = {};

    function hex2bi(hex) {
        return new BigInteger(hex, 16);
    }
    
    /**
     * get curve inforamtion associative array for curve name or alias
     * @name getByName
     * @memberOf KJUR.crypto.ECParameterDB
     * @function
     * @param {String} nameOrAlias curve name or alias name
     * @return {Array} associative array of curve parameters
     * @example
     * var param = KJUR.crypto.ECParameterDB.getByName('prime256v1');
     * var keylen = param['keylen'];
     * var n = param['n'];
     */
    this.getByName = function(nameOrAlias) {
	var name = nameOrAlias;
	if (typeof aliasDB[name] != "undefined") {
	    name = aliasDB[nameOrAlias];
        }
	if (typeof db[name] != "undefined") {
	    return db[name];
	}
	throw "unregistered EC curve name: " + name;
    };

    /**
     * register new curve
     * @name regist
     * @memberOf KJUR.crypto.ECParameterDB
     * @function
     * @param {String} name name of curve
     * @param {Integer} keylen key length
     * @param {String} pHex hexadecimal value of p
     * @param {String} aHex hexadecimal value of a
     * @param {String} bHex hexadecimal value of b
     * @param {String} nHex hexadecimal value of n
     * @param {String} hHex hexadecimal value of h
     * @param {String} gxHex hexadecimal value of Gx
     * @param {String} gyHex hexadecimal value of Gy
     * @param {Array} aliasList array of string for curve names aliases
     * @param {String} oid Object Identifier for the curve
     * @param {String} info information string for the curve
     */
    this.regist = function(name, keylen, pHex, aHex, bHex, nHex, hHex, gxHex, gyHex, aliasList, oid, info) {
        db[name] = {};
	var p = hex2bi(pHex);
	var a = hex2bi(aHex);
	var b = hex2bi(bHex);
	var n = hex2bi(nHex);
	var h = hex2bi(hHex);
        var curve = new ECCurveFp(p, a, b);
        var G = curve.decodePointHex("04" + gxHex + gyHex);
	db[name]['name'] = name;
	db[name]['keylen'] = keylen;
        db[name]['curve'] = curve;
        db[name]['G'] = G;
        db[name]['n'] = n;
        db[name]['h'] = h;
        db[name]['oid'] = oid;
        db[name]['info'] = info;

        for (var i = 0; i < aliasList.length; i++) {
	    aliasDB[aliasList[i]] = name;
        }
    };
};

KJUR.crypto.ECParameterDB.regist(
  "secp128r1", // name / p = 2^128 - 2^97 - 1
  128,
  "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", // p
  "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", // a
  "E87579C11079F43DD824993C2CEE5ED3", // b
  "FFFFFFFE0000000075A30D1B9038A115", // n
  "1", // h
  "161FF7528B899B2D0C28607CA52C5B86", // gx
  "CF5AC8395BAFEB13C02DA292DDED7A83", // gy
  [], // alias
  "", // oid (underconstruction)
  "secp128r1 : SECG curve over a 128 bit prime field"); // info

KJUR.crypto.ECParameterDB.regist(
  "secp160k1", // name / p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
  160,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", // p
  "0", // a
  "7", // b
  "0100000000000000000001B8FA16DFAB9ACA16B6B3", // n
  "1", // h
  "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB", // gx
  "938CF935318FDCED6BC28286531733C3F03C4FEE", // gy
  [], // alias
  "", // oid
  "secp160k1 : SECG curve over a 160 bit prime field"); // info

KJUR.crypto.ECParameterDB.regist(
  "secp160r1", // name / p = 2^160 - 2^31 - 1
  160,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", // a
  "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", // b
  "0100000000000000000001F4C8F927AED3CA752257", // n
  "1", // h
  "4A96B5688EF573284664698968C38BB913CBFC82", // gx
  "23A628553168947D59DCC912042351377AC5FB32", // gy
  [], // alias
  "", // oid
  "secp160r1 : SECG curve over a 160 bit prime field"); // info

KJUR.crypto.ECParameterDB.regist(
  "secp192k1", // name / p = 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
  192,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", // p
  "0", // a
  "3", // b
  "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", // n
  "1", // h
  "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", // gx
  "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", // gy
  []); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp192r1", // name / p = 2^192 - 2^64 - 1
  192,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", // a
  "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", // b
  "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", // n
  "1", // h
  "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", // gx
  "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", // gy
  []); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp224r1", // name / p = 2^224 - 2^96 + 1
  224,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", // a
  "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", // b
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", // n
  "1", // h
  "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", // gx
  "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", // gy
  []); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp256k1", // name / p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
  256,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", // p
  "0", // a
  "7", // b
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", // n
  "1", // h
  "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", // gx
  "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", // gy
  []); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp256r1", // name / p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
  256,
  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", // p
  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", // a
  "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", // b
  "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", // n
  "1", // h
  "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", // gx
  "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", // gy
  ["NIST P-256", "P-256", "prime256v1"]); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp384r1", // name
  384,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", // a
  "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", // b
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", // n
  "1", // h
  "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", // gx
  "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", // gy
  ["NIST P-384", "P-384"]); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp521r1", // name
  521,
  "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // p
  "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", // a
  "051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", // b
  "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", // n
  "1", // h
  "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", // gx
  "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", // gy
  ["NIST P-521", "P-521"]); // alias

KJUR.crypto.ECParameterDB.regist(
  "brainpoolP160r1", // name
  160, 
  "E95E4A5F737059DC60DFC7AD95B3D8139515620F", // p
  "340E7BE2A280EB74E2BE61BADA745D97E8F7C300", // a
  "1E589A8595423412134FAA2DBDEC95C8D8675E58", // b
  "E95E4A5F737059DC60DF5991D45029409E60FC09", // n
  "1", // h
  "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3", // gx
  "1667CB477A1A8EC338F94741669C976316DA6321", // gy
  [], // alias
  "1.3.36.3.3.2.8.1.1.1", // OID
); 

KJUR.crypto.ECParameterDB.regist(
  "brainpoolP192r1", // name
  192, 
  "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297", // p
  "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF", // a
  "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9", // b
  "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1", // n
  "1", // h
  "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6", // gx
  "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F", // gy
  [], // alias
  "1.3.36.3.3.2.8.1.1.3", // OID
); 

KJUR.crypto.ECParameterDB.regist(
  "brainpoolP224r1", // name
  224, 
  "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF", // p
  "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43", // a
  "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B", // b
  "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", // n
  "1", // h
  "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D", // gx
  "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD", // gy
  [], // alias
  "1.3.36.3.3.2.8.1.1.5", // OID
); 

KJUR.crypto.ECParameterDB.regist(
  "brainpoolP256r1", // name
  256,
  "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", // p
  "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", // a
  "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", // b
  "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", // n
  "1", // h
  "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", // gx
  "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", // gy
  [], // alias
  "1.3.36.3.3.2.8.1.1.7", // OID
); 

KJUR.crypto.ECParameterDB.regist(
  "brainpoolP320r1", // name
  320, 
  "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27", // p
  "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4", // a
  "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6", // b
  "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311", // n
  "1", // h
  "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611", // gx
  "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1", // gy
  [], // alias
  "1.3.36.3.3.2.8.1.1.9", // OID
); 

KJUR.crypto.ECParameterDB.regist(
  "brainpoolP384r1", // name
  384, 
  "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", // p
  "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", // a
  "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", // b
  "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", // n
  "1", // h
  "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", // gx
  "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", // gy
  [], // alias
  "1.3.36.3.3.2.8.1.1.11", // OID
); 

KJUR.crypto.ECParameterDB.regist(
  "brainpoolP512r1", // name
  512, 
  "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", // p
  "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", // a
  "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", // b
  "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", // n
  "1", // h
  "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", // gx
  "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", // gy
  [], // alias
  "1.3.36.3.3.2.8.1.1.13", // OID
); 
