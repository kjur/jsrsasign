// 
// x509.js - X509 class to read subject public key from certificate.
//
// version: 1.0 (2010-Jun-03)
//
// Copyright (c) 2010 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://www.opensource.org/licenses/mit-license.php
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.
// 

// Depends:
//   base64.js
//   rsa.js

function _x509_pemToBase64(sCertPEM) {
  var s = sCertPEM;
  s = s.replace("-----BEGIN CERTIFICATE-----", "");
  s = s.replace("-----END CERTIFICATE-----", "");
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _x509_pemToHex(sCertPEM) {
  var b64Cert = _x509_pemToBase64(sCertPEM);
  var hCert = b64tohex(b64Cert);
  return hCert;
}

function _x509_getHexTbsCertificateFromCert(hCert) {
  var pTbsCert = _asnhex_getStartPosOfV_AtObj(hCert, 0);
  return pTbsCert;
}

// NOTE: privateKeyUsagePeriod field of X509v2 not supported.
// NOTE: v1 and v3 supported
function _x509_getSubjectPublicKeyInfoPosFromCertHex(hCert) {
  var pTbsCert = _asnhex_getStartPosOfV_AtObj(hCert, 0);
  var a = _asnhex_getPosArrayOfChildren_AtObj(hCert, pTbsCert); 
  if (a.length < 1) return -1;
  if (hCert.substring(a[0], a[0] + 10) == "a003020102") { // v3
    if (a.length < 6) return -1;
    return a[6];
  } else {
    if (a.length < 5) return -1;
    return a[5];
  }
}

// NOTE: Without BITSTRING encapsulation.
function _x509_getSubjectPublicKeyPosFromCertHex(hCert) {
  var pInfo = _x509_getSubjectPublicKeyInfoPosFromCertHex(hCert);
  if (pInfo == -1) return -1;    
  var a = _asnhex_getPosArrayOfChildren_AtObj(hCert, pInfo); 
  if (a.length != 2) return -1;
  var pBitString = a[1];
  if (hCert.substring(pBitString, pBitString + 2) != '03') return -1;
  var pBitStringV = _asnhex_getStartPosOfV_AtObj(hCert, pBitString);

  if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
  return pBitStringV + 2;
}

function _x509_getPublicKeyHexArrayFromCertHex(hCert) {
  var p = _x509_getSubjectPublicKeyPosFromCertHex(hCert);
  var a = _asnhex_getPosArrayOfChildren_AtObj(hCert, p); 
  if (a.length != 2) return [];
  var hN = _asnhex_getHexOfV_AtObj(hCert, a[0]);
  var hE = _asnhex_getHexOfV_AtObj(hCert, a[1]);
  if (hN != null && hE != null) {
    return [hN, hE];
  } else {
    return [];
  }
}

function _x509_getPublicKeyHexArrayFromCertPEM(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  return a;
}

function _x509_readCertPEM(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  var rsa = new RSAKey();
  rsa.setPublic(a[0], a[1]);
  this.subjectPublicKeyRSA = rsa;
  this.subjectPublicKeyRSA_hN = a[0];
  this.subjectPublicKeyRSA_hE = a[1];
}

function _x509_readCertPEMWithoutRSAInit(sCertPEM) {
  var hCert = _x509_pemToHex(sCertPEM);
  var a = _x509_getPublicKeyHexArrayFromCertHex(hCert);
  this.subjectPublicKeyRSA.setPublic(a[0], a[1]);
  this.subjectPublicKeyRSA_hN = a[0];
  this.subjectPublicKeyRSA_hE = a[1];
}

function X509() {
  this.subjectPublicKeyRSA = null;
  this.subjectPublicKeyRSA_hN = null;
  this.subjectPublicKeyRSA_hE = null;
}

X509.prototype.readCertPEM = _x509_readCertPEM;
X509.prototype.readCertPEMWithoutRSAInit = _x509_readCertPEMWithoutRSAInit;
