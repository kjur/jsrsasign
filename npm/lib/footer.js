
  exports.BigInteger = BigInteger;
  exports.RSAKey = RSAKey;
  exports.ECDSA = KJUR.crypto.ECDSA;
  exports.DSA = KJUR.crypto.DSA;
  exports.Signature = KJUR.crypto.Signature;
  exports.MessageDigest = KJUR.crypto.MessageDigest;
  exports.Mac = KJUR.crypto.Mac;
  exports.KEYUTIL = KEYUTIL;
  exports.ASN1HEX = ASN1HEX;
  exports.X509 = X509;
  
  // ext/base64.js
  exports.b64tohex = b64tohex;
  exports.b64toBA = b64toBA;
  
  // base64x.js
  exports.stoBA = stoBA;
  exports.BAtos = BAtos;
  exports.BAtohex = BAtohex;
  exports.stohex = stohex;
  exports.stob64 = stob64;
  exports.stob64u = stob64u;
  exports.b64utos = b64utos;
  exports.b64tob64u = b64tob64u;
  exports.b64utob64 = b64utob64;
  exports.hex2b64 = hex2b64;
  exports.hextob64u = hextob64u;
  exports.b64utohex = b64utohex;
  exports.b64tohex = b64tohex;
  exports.utf8tob64u = utf8tob64u;
  exports.b64utoutf8 = b64utoutf8;
  exports.utf8tob64 = utf8tob64;
  exports.b64toutf8 = b64toutf8;
  exports.utf8tohex = utf8tohex;
  exports.hextoutf8 = hextoutf8;
  exports.hextorstr = hextorstr;
  exports.rstrtohex = rstrtohex;
  exports.newline_toUnix = newline_toUnix;
  exports.newline_toDos = newline_toDos;
  exports.strdiffidx = strdiffidx;
  
  exports.crypto = KJUR.crypto;
  exports.asn1 = KJUR.asn1;
  exports.jws = KJUR.jws;
  
  if (typeof define == 'function' && typeof define.amd == 'object' && define.amd) {
     define('jsrsasign', function () {
        return exports;
     });
  } else if (typeof module == 'object') {
     module.exports = exports;
  } else {
     root.jsrsasign = exports;
  }
}(this));
