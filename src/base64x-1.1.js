/* base64x-1.1.30 (c) 2012-2022 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * base64x.js - Base64url and supplementary functions for Tom Wu's base64.js library
 *
 * Copyright (c) 2012-2022 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name base64x-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 10.5.25 base64x 1.1.30 (2022-Jun-23)
 * @since jsrsasign 2.1
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

var KJUR;
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.lang == "undefined" || !KJUR.lang) KJUR.lang = {};

/**
 * String and its utility class <br/>
 * This class provides some static utility methods for string.
 * @class String and its utility class
 * @author Kenji Urushima
 * @version 1.0 (2016-Aug-05)
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @description
 * <br/>
 * This class provides static methods for string utility.
 * <dl>
 * <dt><b>STRING TYPE CHECKERS</b>
 * <dd>
 * <ul>
 * <li>{@link KJUR.lang.String.isInteger} - check whether argument is an integer</li>
 * <li>{@link KJUR.lang.String.isHex} - check whether argument is a hexadecimal string</li>
 * <li>{@link KJUR.lang.String.isBase64} - check whether argument is a Base64 encoded string</li>
 * <li>{@link KJUR.lang.String.isBase64URL} - check whether argument is a Base64URL encoded string</li>
 * <li>{@link KJUR.lang.String.isIntegerArray} - check whether argument is an array of integers</li>
 * <li>{@link KJUR.lang.String.isPrintable} - check whether argument is PrintableString accepted characters</li>
 * <li>{@link KJUR.lang.String.isIA5} - check whether argument is IA5String accepted characters</li>
 * <li>{@link KJUR.lang.String.isMail} - check whether argument is RFC 822 e-mail address format</li>
 * </ul>
 * </dl>
 */
KJUR.lang.String = function() {};

/**
 * Base64URL and supplementary functions for Tom Wu's base64.js library.<br/>
 * This class is just provide information about global functions
 * defined in 'base64x.js'. The 'base64x.js' script file provides
 * global functions for converting following data each other.
 * <ul>
 * <li>(ASCII) String</li>
 * <li>UTF8 String including CJK, Latin and other characters</li>
 * <li>byte array</li>
 * <li>hexadecimal encoded String</li>
 * <li>Full URIComponent encoded String (such like "%69%94")</li>
 * <li>Base64 encoded String</li>
 * <li>Base64URL encoded String</li>
 * </ul>
 * All functions in 'base64x.js' are defined in {@link _global_} and not
 * in this class.
 * 
 * @class Base64URL and supplementary functions for Tom Wu's base64.js library
 * @author Kenji Urushima
 * @version 1.1 (07 May 2012)
 * @requires base64.js
 * @see <a href="https://kjur.github.io/jsjws/">'jwjws'(JWS JavaScript Library) home page https://kjur.github.io/jsjws/</a>
 * @see <a href="https://kjur.github.io/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page https://kjur.github.io/jsrsasign/</a>
 */
function Base64x() {
}

// ==== string / byte array ================================
/**
 * convert a string to an array of character codes
 * @name stoBA
 * @function
 * @param {String} s
 * @return {Array of Numbers} 
 */
function stoBA(s) {
    var a = new Array();
    for (var i = 0; i < s.length; i++) {
	a[i] = s.charCodeAt(i);
    }
    return a;
}

/**
 * convert an array of character codes to a string
 * @name BAtos
 * @function
 * @param {Array of Numbers} a array of character codes
 * @return {String} s
 */
function BAtos(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
	s = s + String.fromCharCode(a[i]);
    }
    return s;
}

// ==== byte array / hex ================================
/**
 * convert an array of bytes(Number) to hexadecimal string.<br/>
 * @name BAtohex
 * @function
 * @param {Array of Numbers} a array of bytes
 * @return {String} hexadecimal string
 */
function BAtohex(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
	var hex1 = a[i].toString(16);
	if (hex1.length == 1) hex1 = "0" + hex1;
	s = s + hex1;
    }
    return s;
}

// ==== string / hex ================================
/**
 * convert a ASCII string to a hexadecimal string of ASCII codes.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @name stohex
 * @function
 * @param {s} s ASCII string
 * @return {String} hexadecimal string
 */
function stohex(s) {
    return BAtohex(stoBA(s));
}

// ==== string / base64 ================================
/**
 * convert a ASCII string to a Base64 encoded string.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @name stob64
 * @function
 * @param {s} s ASCII string
 * @return {String} Base64 encoded string
 */
function stob64(s) {
    return hex2b64(stohex(s));
}

// ==== string / base64url ================================
/**
 * convert a ASCII string to a Base64URL encoded string.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @name stob64u
 * @function
 * @param {s} s ASCII string
 * @return {String} Base64URL encoded string
 */
function stob64u(s) {
    return b64tob64u(hex2b64(stohex(s)));
}

/**
 * convert a Base64URL encoded string to a ASCII string.<br/>
 * NOTE: This can't be used for Base64URL encoded non ASCII characters.
 * @name b64utos
 * @function
 * @param {s} s Base64URL encoded string
 * @return {String} ASCII string
 */
function b64utos(s) {
    return BAtos(b64toBA(b64utob64(s)));
}

// ==== base64 / base64url ================================
/**
 * convert a Base64 encoded string to a Base64URL encoded string.<br/>
 * @name b64tob64u
 * @function
 * @param {String} s Base64 encoded string
 * @return {String} Base64URL encoded string
 * @example
 * b64tob64u("ab+c3f/==") &rarr; "ab-c3f_"
 */
function b64tob64u(s) {
    s = s.replace(/\=/g, "");
    s = s.replace(/\+/g, "-");
    s = s.replace(/\//g, "_");
    return s;
}

/**
 * convert a Base64URL encoded string to a Base64 encoded string.<br/>
 * @name b64utob64
 * @function
 * @param {String} s Base64URL encoded string
 * @return {String} Base64 encoded string
 * @example
 * b64utob64("ab-c3f_") &rarr; "ab+c3f/=="
 */
function b64utob64(s) {
    if (s.length % 4 == 2) s = s + "==";
    else if (s.length % 4 == 3) s = s + "=";
    s = s.replace(/-/g, "+");
    s = s.replace(/_/g, "/");
    return s;
}

// ==== hex / base64url ================================
/**
 * convert a hexadecimal string to a Base64URL encoded string.<br/>
 * @name hextob64u
 * @function
 * @param {String} s hexadecimal string
 * @return {String} Base64URL encoded string
 * @description
 * convert a hexadecimal string to a Base64URL encoded string.
 * NOTE: If leading "0" is omitted and odd number length for
 * hexadecimal leading "0" is automatically added.
 */
function hextob64u(s) {
    if (s.length % 2 == 1) s = "0" + s;
    return b64tob64u(hex2b64(s));
}

/**
 * convert a Base64URL encoded string to a hexadecimal string.<br/>
 * @name b64utohex
 * @function
 * @param {String} s Base64URL encoded string
 * @return {String} hexadecimal string
 */
function b64utohex(s) {
    return b64tohex(b64utob64(s));
}

// ==== utf8 / base64url ================================

/**
 * convert a UTF-8 encoded string including CJK or Latin to a Base64URL encoded string.<br/>
 * @name utf8tob64u
 * @function
 * @param {String} s UTF-8 encoded string
 * @return {String} Base64URL encoded string
 * @since 1.1
 * @example
 * utf8tob64u("あ") &rarr; "44GC"
 * utf8tob64u("aaa") &rarr; "YWFh"
 */

/**
 * convert a Base64URL encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @name b64utoutf8
 * @function
 * @param {String} s Base64URL encoded string
 * @return {String} UTF-8 encoded string
 * @since 1.1
 * @example
 * b64utoutf8("44GC") &rarr; "あ"
 * b64utoutf8("YWFh") &rarr; "aaa"
 */

var utf8tob64u, b64utoutf8;

if (typeof Buffer === 'function') {
  utf8tob64u = function (s) {
    return b64tob64u(Buffer.from(s, 'utf8').toString('base64'));
  };

  b64utoutf8 = function (s) {
    return Buffer.from(b64utob64(s), 'base64').toString('utf8');
  };
} else {
  utf8tob64u = function (s) {
    return hextob64u(uricmptohex(encodeURIComponentAll(s)));
  };

  b64utoutf8 = function (s) {
    return decodeURIComponent(hextouricmp(b64utohex(s)));
  };
}

// ==== utf8 / base64url ================================
/**
 * convert a UTF-8 encoded string including CJK or Latin to a Base64 encoded string.<br/>
 * @name utf8tob64
 * @function
 * @param {String} s UTF-8 encoded string
 * @return {String} Base64 encoded string
 * @since 1.1.1
 */
function utf8tob64(s) {
  return hex2b64(uricmptohex(encodeURIComponentAll(s)));
}

/**
 * convert a Base64 encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @name b64toutf8
 * @function
 * @param {String} s Base64 encoded string
 * @return {String} UTF-8 encoded string
 * @since 1.1.1
 */
function b64toutf8(s) {
  return decodeURIComponent(hextouricmp(b64tohex(s)));
}

// ==== utf8 / hex ================================
/**
 * convert a UTF-8 encoded string including CJK or Latin to a hexadecimal encoded string.<br/>
 * @name utf8tohex
 * @function
 * @param {String} s UTF-8 encoded string
 * @return {String} hexadecimal encoded string
 * @since 1.1.1
 */
function utf8tohex(s) {
  return uricmptohex(encodeURIComponentAll(s)).toLowerCase();
}

/**
 * convert a hexadecimal encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * Note that when input is improper hexadecimal string as UTF-8 string, this function returns
 * 'null'.
 * @name hextoutf8
 * @function
 * @param {String} s hexadecimal encoded string
 * @return {String} UTF-8 encoded string or null
 * @since 1.1.1
 */
function hextoutf8(s) {
  try {
    return decodeURIComponent(hextouricmp(s));
  } catch(ex) {
    return null;
  }
}

// ==== iso8859-1 latin1 / utf8 ===================
/**
 * convert a hexadecimal ISO 8859-1 latin string to UTF-8 string<br/>
 * @name iso88591hextoutf8
 * @function
 * @param {String} h hexadecimal ISO 8859-1 latin string
 * @return {String} UTF-8 string
 * @since jsrsasign 10.5.12 base64x 1.1.25
 * @see utf8toiso88591hex
 *
 * @example
 * iso88591hextoutf8("41a9fa") &rarr; "A©ú"
 */
function iso88591hextoutf8(h) {
    return hextoutf8(iso88591hextoutf8hex(h));
}

/**
 * convert UTF-8 string to a hexadecimal ISO 8859-1 latin string<br/>
 * @name utf8toiso88591hex
 * @function
 * @param {String} s hexadecimal ISO 8859-1 latin string
 * @return {String} UTF-8 string
 * @since jsrsasign 10.5.12 base64x 1.1.25
 * @see iso88591hextoutf8
 *
 * @example
 * utf8toiso88591hex("A©ú") &rarr; "41a9fa"
 */
function utf8toiso88591hex(s) {
    return utf8hextoiso88591hex(utf8tohex(s));
}

/**
 * convert a hexadecimal ISO 8859-1 latin string to UTF-8 hexadecimal string<br/>
 * @name iso88591hextoutf8hex
 * @function
 * @param {String} h hexadecimal ISO 8859-1 latin string
 * @return {String} UTF-8 hexadecimal string
 * @since jsrsasign 10.5.12 base64x 1.1.25
 * @see iso88591hextoutf8
 * @see utf8hextoiso88591hex
 *
 * @example
 * iso88591hextoutf8hex("41a9fa") &rarr; "41c2a9c3ba"
 */
function iso88591hextoutf8hex(h) {
    var a = h.match(/.{1,2}/g);
    var a2 = [];
    for (var i = 0; i < a.length; i++) {
	var di = parseInt(a[i], 16);
	if (0xa1 <= di && di <= 0xbf) {
	    a2.push("c2");
	    a2.push(a[i]);
	} else if (0xc0 <= di && di <= 0xff) {
	    a2.push("c3");
	    a2.push((di - 64).toString(16));
	} else {
	    a2.push(a[i]);
	}
    }
    return a2.join('');
}

/**
 * convert UTF-8 string to a hexadecimal ISO 8859-1 latin string<br/>
 * @name utf8hextoiso88591hex
 * @function
 * @param {String} h hexadecimal UTF-8 string
 * @return {String} hexadecimal ISO 8859-1 latin string
 * @since jsrsasign 10.5.12 base64x 1.1.25
 * @see iso88591hextoutf8hex
 * @see utf8toiso88591hex
 *
 * @example
 * utf8hextoiso88591hex("41c2a9c3ba") &rarr; "41a9fa"
 */
function utf8hextoiso88591hex(h) {
    var a = h.match(/.{1,2}/g);
    var a2 = [];
    for (var i = 0; i < a.length; i++) {
	if (a[i] == 'c2') {
	    i++;
	    a2.push(a[i]);
	} else if (a[i] == 'c3') {
	    i++;
	    var ci = a[i];
	    var di = parseInt(a[i], 16) + 64;
	    a2.push(di.toString(16));
	} else {
	    a2.push(a[i]);
	}
    }
    return a2.join('');
}

// ==== rstr / hex ================================
/**
 * convert a hexadecimal encoded string to raw string including non printable characters.<br/>
 * @name hextorstr
 * @function
 * @param {String} s hexadecimal encoded string
 * @return {String} raw string
 * @since 1.1.2
 * @example
 * hextorstr("610061") &rarr; "a\x00a"
 */
function hextorstr(sHex) {
    var s = "";
    for (var i = 0; i < sHex.length - 1; i += 2) {
        s += String.fromCharCode(parseInt(sHex.substr(i, 2), 16));
    }
    return s;
}

/**
 * convert a raw string including non printable characters to hexadecimal encoded string.<br/>
 * @name rstrtohex
 * @function
 * @param {String} s raw string
 * @return {String} hexadecimal encoded string
 * @since 1.1.2
 * @example
 * rstrtohex("a\x00a") &rarr; "610061"
 */
function rstrtohex(s) {
    var result = "";
    for (var i = 0; i < s.length; i++) {
        result += ("0" + s.charCodeAt(i).toString(16)).slice(-2);
    }
    return result;
}

// ==== hex / b64nl =======================================

/**
 * convert a hexadecimal string to Base64 encoded string<br/>
 * @name hextob64
 * @function
 * @param {String} s hexadecimal string
 * @return {String} resulted Base64 encoded string
 * @since base64x 1.1.3
 * @description
 * This function converts from a hexadecimal string to Base64 encoded
 * string without new lines.
 * @example
 * hextob64("616161") &rarr; "YWFh"
 */
function hextob64(s) {
    return hex2b64(s);
}

/**
 * convert a hexadecimal string to Base64 encoded string with new lines<br/>
 * @name hextob64nl
 * @function
 * @param {String} s hexadecimal string
 * @return {String} resulted Base64 encoded string with new lines
 * @since base64x 1.1.3
 * @description
 * This function converts from a hexadecimal string to Base64 encoded
 * string with new lines for each 64 characters. This is useful for
 * PEM encoded file.
 * @example
 * hextob64nl("123456789012345678901234567890123456789012345678901234567890")
 * &rarr;
 * MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4 // new line
 * OTAxMjM0NTY3ODkwCg==
 */
function hextob64nl(s) {
    var b64 = hextob64(s);
    var b64nl = b64.replace(/(.{64})/g, "$1\r\n");
    b64nl = b64nl.replace(/\r\n$/, '');
    return b64nl;
}

/**
 * convert a Base64 encoded string with new lines to a hexadecimal string<br/>
 * @name b64nltohex
 * @function
 * @param {String} s Base64 encoded string with new lines
 * @return {String} hexadecimal string
 * @since base64x 1.1.3
 * @description
 * This function converts from a Base64 encoded
 * string with new lines to a hexadecimal string.
 * This is useful to handle PEM encoded file.
 * This function removes any non-Base64 characters (i.e. not 0-9,A-Z,a-z,\,+,=)
 * including new line.
 * @example
 * hextob64nl(
 * "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4\r\n" +
 * "OTAxMjM0NTY3ODkwCg==\r\n")
 * &rarr;
 * "123456789012345678901234567890123456789012345678901234567890"
 */
function b64nltohex(s) {
    var b64 = s.replace(/[^0-9A-Za-z\/+=]*/g, '');
    var hex = b64tohex(b64);
    return hex;
} 

// ==== hex / pem =========================================

/**
 * get PEM string from hexadecimal data and header string
 * @name hextopem
 * @function
 * @param {String} dataHex hexadecimal string of PEM body
 * @param {String} pemHeader PEM header string (ex. 'RSA PRIVATE KEY')
 * @return {String} PEM formatted string of input data
 * @since jsrasign 7.2.1 base64x 1.1.12
 * @description
 * This function converts a hexadecimal string to a PEM string with
 * a specified header. Its line break will be CRLF("\r\n").
 * @example
 * hextopem('616161', 'RSA PRIVATE KEY') &rarr;
 * -----BEGIN PRIVATE KEY-----
 * YWFh
 * -----END PRIVATE KEY-----
 */
function hextopem(dataHex, pemHeader) {
    var pemBody = hextob64nl(dataHex);
    return "-----BEGIN " + pemHeader + "-----\r\n" + 
        pemBody + 
        "\r\n-----END " + pemHeader + "-----\r\n";
}

/**
 * get hexacedimal string from PEM format data<br/>
 * @name pemtohex
 * @function
 * @param {String} s PEM formatted string
 * @param {String} sHead PEM header string without BEGIN/END(OPTION)
 * @return {String} hexadecimal string data of PEM contents
 * @since jsrsasign 7.2.1 base64x 1.1.12
 * @description
 * This static method gets a hexacedimal string of contents 
 * from PEM format data. You can explicitly specify PEM header 
 * by sHead argument. 
 * Any space characters such as white space or new line
 * will be omitted.<br/>
 * NOTE: Now {@link KEYUTIL.getHexFromPEM} and {@link X509.pemToHex}
 * have been deprecated since jsrsasign 7.2.1. 
 * Please use this method instead.
 * NOTE2: From jsrsasign 8.0.14 this can process multi
 * "BEGIN...END" section such as "EC PRIVATE KEY" with "EC PARAMETERS".
 * @example
 * pemtohex("-----BEGIN PUBLIC KEY...") &rarr; "3082..."
 * pemtohex("-----BEGIN CERTIFICATE...", "CERTIFICATE") &rarr; "3082..."
 * pemtohex(" \r\n-----BEGIN DSA PRIVATE KEY...") &rarr; "3082..."
 * pemtohex("-----BEGIN EC PARAMETERS...----BEGIN EC PRIVATE KEY...." &rarr; "3082..."
 */
function pemtohex(s, sHead) {
    if (s.indexOf("-----BEGIN ") == -1)
        throw "can't find PEM header: " + sHead;

    if (sHead !== undefined) {
        s = s.replace(new RegExp('^[^]*-----BEGIN ' + sHead + '-----'), '');
        s = s.replace(new RegExp('-----END ' + sHead + '-----[^]*$'), '');
    } else {
        s = s.replace(/^[^]*-----BEGIN [^-]+-----/, '');
        s = s.replace(/-----END [^-]+-----[^]*$/, '');
    }
    return b64nltohex(s);
}

// ==== hex / ArrayBuffer =================================

/**
 * convert a hexadecimal string to an ArrayBuffer<br/>
 * @name hextoArrayBuffer
 * @function
 * @param {String} hex hexadecimal string
 * @return {ArrayBuffer} ArrayBuffer
 * @since jsrsasign 6.1.4 base64x 1.1.8
 * @description
 * This function converts from a hexadecimal string to an ArrayBuffer.
 * @example
 * hextoArrayBuffer("fffa01") &rarr; ArrayBuffer of [255, 250, 1]
 */
function hextoArrayBuffer(hex) {
    if (hex.length % 2 != 0) throw "input is not even length";
    if (hex.match(/^[0-9A-Fa-f]+$/) == null) throw "input is not hexadecimal";

    var buffer = new ArrayBuffer(hex.length / 2);
    var view = new DataView(buffer);

    for (var i = 0; i < hex.length / 2; i++) {
	view.setUint8(i, parseInt(hex.substr(i * 2, 2), 16));
    }

    return buffer;
}

// ==== ArrayBuffer / hex =================================

/**
 * convert an ArrayBuffer to a hexadecimal string<br/>
 * @name ArrayBuffertohex
 * @function
 * @param {ArrayBuffer} buffer ArrayBuffer
 * @return {String} hexadecimal string
 * @since jsrsasign 6.1.4 base64x 1.1.8
 * @description
 * This function converts from an ArrayBuffer to a hexadecimal string.
 * @example
 * var buffer = new ArrayBuffer(3);
 * var view = new DataView(buffer);
 * view.setUint8(0, 0xfa);
 * view.setUint8(1, 0xfb);
 * view.setUint8(2, 0x01);
 * ArrayBuffertohex(buffer) &rarr; "fafb01"
 */
function ArrayBuffertohex(buffer) {
    var hex = "";
    var view = new DataView(buffer);

    for (var i = 0; i < buffer.byteLength; i++) {
	hex += ("00" + view.getUint8(i).toString(16)).slice(-2);
    }

    return hex;
}

// ==== zulu / int =================================
/**
 * GeneralizedTime or UTCTime string to milliseconds from Unix origin<br>
 * @name zulutomsec
 * @function
 * @param {String} s GeneralizedTime or UTCTime string (ex. 20170412235959.384Z)
 * @return {Number} milliseconds from Unix origin time (i.e. Jan 1, 1970 0:00:00 UTC)
 * @since jsrsasign 7.1.3 base64x 1.1.9
 * @description
 * This function converts from GeneralizedTime string (i.e. YYYYMMDDHHmmSSZ) or
 * UTCTime string (i.e. YYMMDDHHmmSSZ) to milliseconds from Unix origin time
 * (i.e. Jan 1 1970 0:00:00 UTC). 
 * Argument string may have fraction of seconds and
 * its length is one or more digits such as "20170410235959.1234567Z".
 * As for UTCTime, if year "YY" is equal or less than 49 then it is 20YY.
 * If year "YY" is equal or greater than 50 then it is 19YY.
 * @example
 * zulutomsec(  "071231235959Z")       &rarr; 1199145599000 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutomsec(  "071231235959.1Z")     &rarr; 1199145599100 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutomsec(  "071231235959.12345Z") &rarr; 1199145599123 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutomsec("20071231235959Z")       &rarr; 1199145599000 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutomsec(  "931231235959Z")       &rarr; -410227201000 #Mon, 31 Dec 1956 23:59:59 GMT
 */
function zulutomsec(s) {
    var year, month, day, hour, min, sec, msec, d;
    var sYear, sFrac, sMsec, matchResult;

    matchResult = s.match(/^(\d{2}|\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(|\.\d+)Z$/);

    if (matchResult) {
        sYear = matchResult[1];
	year = parseInt(sYear);
        if (sYear.length === 2) {
	    if (50 <= year && year < 100) {
		year = 1900 + year;
	    } else if (0 <= year && year < 50) {
		year = 2000 + year;
	    }
	}
	month = parseInt(matchResult[2]) - 1;
	day = parseInt(matchResult[3]);
	hour = parseInt(matchResult[4]);
	min = parseInt(matchResult[5]);
	sec = parseInt(matchResult[6]);
	msec = 0;

	sFrac = matchResult[7];
	if (sFrac !== "") {
	    sMsec = (sFrac.substr(1) + "00").substr(0, 3); // .12 -> 012
	    msec = parseInt(sMsec);
	}
	return Date.UTC(year, month, day, hour, min, sec, msec);
    }
    throw new Error("unsupported zulu format: " + s);
}

/**
 * GeneralizedTime or UTCTime string to seconds from Unix origin<br>
 * @name zulutosec
 * @function
 * @param {String} s GeneralizedTime or UTCTime string (ex. 20170412235959.384Z)
 * @return {Number} seconds from Unix origin time (i.e. Jan 1, 1970 0:00:00 UTC)
 * @since jsrsasign 7.1.3 base64x 1.1.9
 * @description
 * This function converts from GeneralizedTime string (i.e. YYYYMMDDHHmmSSZ) or
 * UTCTime string (i.e. YYMMDDHHmmSSZ) to seconds from Unix origin time
 * (i.e. Jan 1 1970 0:00:00 UTC). Argument string may have fraction of seconds 
 * however result value will be omitted.
 * As for UTCTime, if year "YY" is equal or less than 49 then it is 20YY.
 * If year "YY" is equal or greater than 50 then it is 19YY.
 * @example
 * zulutosec(  "071231235959Z")       &rarr; 1199145599 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutosec(  "071231235959.1Z")     &rarr; 1199145599 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutosec("20071231235959Z")       &rarr; 1199145599 #Mon, 31 Dec 2007 23:59:59 GMT
 */
function zulutosec(s) {
    return Math.round(zulutomsec(s) / 1000.0);
}

// ==== zulu / Date =================================

/**
 * GeneralizedTime or UTCTime string to Date object<br>
 * @name zulutodate
 * @function
 * @param {String} s GeneralizedTime or UTCTime string (ex. 20170412235959.384Z)
 * @return {Date} Date object for specified time
 * @since jsrsasign 7.1.3 base64x 1.1.9
 * @description
 * This function converts from GeneralizedTime string (i.e. YYYYMMDDHHmmSSZ) or
 * UTCTime string (i.e. YYMMDDHHmmSSZ) to Date object.
 * Argument string may have fraction of seconds and
 * its length is one or more digits such as "20170410235959.1234567Z".
 * As for UTCTime, if year "YY" is equal or less than 49 then it is 20YY.
 * If year "YY" is equal or greater than 50 then it is 19YY.
 * @example
 * zulutodate(  "071231235959Z").toUTCString()   &rarr; "Mon, 31 Dec 2007 23:59:59 GMT"
 * zulutodate(  "071231235959.1Z").toUTCString() &rarr; "Mon, 31 Dec 2007 23:59:59 GMT"
 * zulutodate("20071231235959Z").toUTCString()   &rarr; "Mon, 31 Dec 2007 23:59:59 GMT"
 * zulutodate(  "071231235959.34").getMilliseconds() &rarr; 340
 */
function zulutodate(s) {
    return new Date(zulutomsec(s));
}

// ==== Date / zulu =================================

/**
 * Date object to zulu time string<br>
 * @name datetozulu
 * @function
 * @param {Date} d Date object for specified time
 * @param {Boolean} flagUTCTime if this is true year will be YY otherwise YYYY
 * @param {Boolean} flagMilli if this is true result concludes milliseconds
 * @return {String} GeneralizedTime or UTCTime string (ex. 20170412235959.384Z)
 * @since jsrsasign 7.2.0 base64x 1.1.11
 * @description
 * This function converts from Date object to GeneralizedTime string (i.e. YYYYMMDDHHmmSSZ) or
 * UTCTime string (i.e. YYMMDDHHmmSSZ).
 * As for UTCTime, if year "YY" is equal or less than 49 then it is 20YY.
 * If year "YY" is equal or greater than 50 then it is 19YY.
 * If flagMilli is true its result concludes milliseconds such like
 * "20170520235959.42Z". 
 * @example
 * d = new Date(Date.UTC(2017,4,20,23,59,59,670));
 * datetozulu(d) &rarr; "20170520235959Z"
 * datetozulu(d, true) &rarr; "170520235959Z"
 * datetozulu(d, false, true) &rarr; "20170520235959.67Z"
 */
function datetozulu(d, flagUTCTime, flagMilli) {
    var s;
    var year = d.getUTCFullYear();
    if (flagUTCTime) {
	if (year < 1950 || 2049 < year) 
	    throw "not proper year for UTCTime: " + year;
	s = ("" + year).slice(-2);
    } else {
	s = ("000" + year).slice(-4);
    }
    s += ("0" + (d.getUTCMonth() + 1)).slice(-2);
    s += ("0" + d.getUTCDate()).slice(-2);
    s += ("0" + d.getUTCHours()).slice(-2);
    s += ("0" + d.getUTCMinutes()).slice(-2);
    s += ("0" + d.getUTCSeconds()).slice(-2);
    if (flagMilli) {
	var milli = d.getUTCMilliseconds();
	if (milli !== 0) {
	    milli = ("00" + milli).slice(-3);
	    milli = milli.replace(/0+$/g, "");
	    s += "." + milli;
	}
    }
    s += "Z";
    return s;
}

// ==== URIComponent / hex ================================
/**
 * convert a URLComponent string such like "%67%68" to a hexadecimal string.<br/>
 * @name uricmptohex
 * @function
 * @param {String} s URIComponent string such like "%67%68"
 * @return {String} hexadecimal string
 * @since 1.1
 */
function uricmptohex(s) {
  return s.replace(/%/g, "");
}

/**
 * convert a hexadecimal string to a URLComponent string such like "%67%68".<br/>
 * @name hextouricmp
 * @function
 * @param {String} s hexadecimal string
 * @return {String} URIComponent string such like "%67%68"
 * @since 1.1
 */
function hextouricmp(s) {
  return s.replace(/(..)/g, "%$1");
}

// ==== hex / ipv6 =================================

/**
 * convert any IPv6 address to a 16 byte hexadecimal string
 * @function
 * @param s string of IPv6 address
 * @return {String} 16 byte hexadecimal string of IPv6 address
 * @description
 * This function converts any IPv6 address representation string
 * to a 16 byte hexadecimal string of address.
 * @example
 * 
 */
function ipv6tohex(s) {
  var msgMalformedAddress = "malformed IPv6 address";
  if (! s.match(/^[0-9A-Fa-f:]+$/))
    throw msgMalformedAddress;

  // 1. downcase
  s = s.toLowerCase();

  // 2. expand ::
  var num_colon = s.split(':').length - 1;
  if (num_colon < 2) throw msgMalformedAddress;
  var colon_replacer = ':'.repeat(7 - num_colon + 2);
  s = s.replace('::', colon_replacer);

  // 3. fill zero
  var a = s.split(':');
  if (a.length != 8) throw msgMalformedAddress;
  for (var i = 0; i < 8; i++) {
    a[i] = ("0000" + a[i]).slice(-4);
  }
  return a.join('');
}

/**
 * convert a 16 byte hexadecimal string to RFC 5952 canonicalized IPv6 address<br/>
 * @name hextoipv6
 * @function
 * @param {String} s hexadecimal string of 16 byte IPv6 address
 * @return {String} IPv6 address string canonicalized by RFC 5952
 * @since jsrsasign 8.0.10 base64x 1.1.13
 * @description
 * This function converts a 16 byte hexadecimal string to 
 * <a href="https://tools.ietf.org/html/rfc5952">RFC 5952</a>
 * canonicalized IPv6 address string.
 * @example
 * hextoipv6("871020010db8000000000000000000000004") &rarr "2001:db8::4"
 * hextoipv6("871020010db8000000000000000000") &rarr raise exception
 * hextoipv6("xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz") &rarr raise exception
 */
function hextoipv6(s) {
    if (! s.match(/^[0-9A-Fa-f]{32}$/))
	throw new Error("malformed IPv6 address: " + s);

    // 1. downcase
    s = s.toLowerCase();

    // 2. split 4 > ["0123", "00a4", "0000", ..., "ffff"]
    var a = s.match(/.{1,4}/g);

    // 3. trim leading 0 for items and join > "123:a4:0:...:ffff"
    a = a.map(function(s){return s.replace(/^0+/, '')});
    a = a.map(function(s){return s == '' ? '0' : s});
    s = ':' + a.join(':') + ':';

    // 4. find shrinkable candidates :0:0:..:0:
    var aZero = s.match(/:(0:){2,}/g);

    // 5. no shrinkable
    if (aZero == null) return s.slice(1, -1);

    // 6. fix max length zero(:0:...:0:)
    var sMaxZero = aZero.sort().slice(-1)[0];

    // 7. replace shrinked
    s = s.replace(sMaxZero.substr(0, sMaxZero.length - 1), ':');

    // 8. trim leading ':' if not '::'
    if (s.substr(0, 2) != '::') s = s.substr(1);

    // 9. trim tail ':' if not '::'
    if (s.substr(-2, 2) != '::') s = s.substr(0, s.length - 1);

    return s;
}

// ==== hex / ip =================================

/**
 * convert a hexadecimal string to IP addresss<br/>
 * @name hextoip
 * @function
 * @param {String} s hexadecimal string of IP address
 * @return {String} IP address string
 * @since jsrsasign 8.0.10 base64x 1.1.13
 * @see hextoipv6
 * @see iptohex
 *
 * @description
 * This function converts a hexadecimal string of IPv4 or 
 * IPv6 address to IPv4 or IPv6 address string.
 * If byte length is not 4 nor 16, this returns a
 * hexadecimal string without conversion.
 * <br/>
 * NOTE: From jsrsasign 10.5.17, CIDR subnet mask notation also supported.
 *
 * @example
 * hextoip("c0a80101") &rarr; "192.168.1.1"
 * hextoip("871020010db8000000000000000000000004") &rarr "2001:db8::4"
 * hextoip("c0a80100ffffff00") &rarr; "192.168.1.0/24"
 * hextoip("c0a801010203") &rarr; "c0a801010203" // wrong 6 bytes
 * hextoip("zzz")) &rarr; raise exception because of not hexadecimal
 */
function hextoip(s) {
    var malformedErr = new Error("malformed hex value");
    if (! s.match(/^([0-9A-Fa-f][0-9A-Fa-f]){1,}$/))
	throw malformedErr;
    if (s.length == 8) { // ipv4
	var ip;
	try {
	    ip = parseInt(s.substr(0, 2), 16) + "." +
 		 parseInt(s.substr(2, 2), 16) + "." +
		 parseInt(s.substr(4, 2), 16) + "." +
		 parseInt(s.substr(6, 2), 16);
	    return ip;
	} catch (ex) {
	    throw malformedErr;
	}
  } else if (s.length == 16) {
      try {
	  return hextoip(s.substr(0, 8)) + "/" + ipprefixlen(s.substr(8));
      } catch (ex) {
	  throw malformedErr;
      }
  } else if (s.length == 32) {
      return hextoipv6(s);
  } else if (s.length == 64) {
      try {
	  return hextoipv6(s.substr(0, 32)) + "/" + ipprefixlen(s.substr(32));
      } catch (ex) {
	  throw malformedErr;
      }
      return 
  } else {
    return s;
  }
}

/*
 * convert subnet mask hex to ip address prefix length<br/>
 * @name ipprefixlen
 * @param {string} hMask hexadecimal string of ipv4/6 subnet mask (ex. "ffffff00" for v4 class C)
 * @return {nummber} ip address prefix length (ex. 24 for IPv4 class C)
 */
function ipprefixlen(hMask) {
    var malformedErr = new Error("malformed mask");
    var bMask;
    try {
	bMask = new BigInteger(hMask, 16).toString(2);
    } catch(ex) {
	throw malformedErr;
    }
    if (! bMask.match(/^1*0*$/)) throw malformedErr;
    return bMask.replace(/0+$/, '').length;
}

/**
 * convert IPv4/v6 addresss to a hexadecimal string<br/>
 * @name iptohex
 * @function
 * @param {String} s IPv4/v6 address string
 * @return {String} hexadecimal string of IP address
 * @since jsrsasign 8.0.12 base64x 1.1.14
 * @see hextoip
 * @see ipv6tohex
 *
 * @description
 * This function converts IPv4 or IPv6 address string to
 * a hexadecimal string of IPv4 or IPv6 address.
 * <br/>
 * NOTE: From jsrsasign 10.5.17, CIDR net mask notation also supported.
 *
 * @example
 * iptohex("192.168.1.1") &rarr; "c0a80101"
 * iptohex("2001:db8::4") &rarr; "871020010db8000000000000000000000004"
 * iptohex("192.168.1.1/24") &rarr; "c0a80101ffffff00"
 * iptohex("2001:db8::/120") &rarr; "871020010db8000000000000000000000000ffffffffffffffffffffffffffffffffff00"
 * iptohex("zzz")) &rarr; raise exception
 */
function iptohex(s) {
    var malformedErr = new Error("malformed IP address");
    s = s.toLowerCase(s);

    if (! s.match(/^[0-9a-f.:/]+$/) ) throw malformedErr;

    if (s.match(/^[0-9.]+$/)) {
	var a = s.split(".");
	if (a.length !== 4) throw malformedErr;
	var hex = "";
	try {
	    for (var i = 0; i < 4; i++) {
		var d = parseInt(a[i]);
		hex += ("0" + d.toString(16)).slice(-2);
	    }
	    return hex;
	} catch(ex) {
	    throw malformedErr;
	}
    } else if (s.match(/^[0-9.]+\/[0-9]+$/)) {
	var aItem = s.split("/");
	return iptohex(aItem[0]) + ipnetmask(parseInt(aItem[1]), 32);
    } else if (s.match(/^[0-9a-f:]+$/) && s.indexOf(":") !== -1) {
	return ipv6tohex(s);
    } else if (s.match(/^[0-9a-f:]+\/[0-9]+$/) && s.indexOf(":") !== -1) {
	var aItem = s.split("/");
	return ipv6tohex(aItem[0]) + ipnetmask(parseInt(aItem[1]), 128);
    } else {
	throw malformedErr;
    }
}

/*
 * convert ip prefix length to net mask octets<br/>
 * @param {number} prefixlen ip prefix length value (ex. 24 for IPv4 class C)
 * @param {number} len ip address length (ex. 32 for IPv4 and 128 for IPv6)
 * @return {string} hexadecimal string of net mask octets
 * @example
 * ipnetmask(24, 32) &rarr; "ffffff00" 
 * ipnetmask(120, 128) &rarr; "ffffffffffffffffffffffffffffff00"
 */
function ipnetmask(prefixlen, len) {
    if (len == 32 && prefixlen == 0) return "00000000"; // v4
    if (len == 128 && prefixlen == 0) return "00000000000000000000000000000000"; // v6
    var b = Array(prefixlen + 1).join("1") + Array(len - prefixlen + 1).join("0");
    return new BigInteger(b, 2).toString(16);
}

// ==== ucs2hex / utf8 ==============================

/**
 * convert UCS-2 hexadecimal stirng to UTF-8 string<br/>
 * @name ucs2hextoutf8
 * @function
 * @param {String} s hexadecimal string of UCS-2 string (ex. "0066")
 * @return {String} UTF-8 string
 * @since jsrsasign 10.1.13 base64x 1.1.20
 * @description
 * This function converts hexadecimal value of UCS-2 string to 
 * UTF-8 string.
 * @example
 * ucs2hextoutf8("006600fc0072") &rarr "für"
 */
/*
See: http://nomenclator.la.coocan.jp/unicode/ucs_utf.htm
UCS-2 to UTF-8
UCS-2 code point | UCS-2 bytes       | UTF-8 bytes
U+0000 .. U+007F | 00000000-0xxxxxxx | 0xxxxxxx (1 byte)
U+0080 .. U+07FF | 00000xxx-xxyyyyyy | 110xxxxx 10yyyyyy (2 byte)
U+0800 .. U+FFFF | xxxxyyyy-yyzzzzzz | 1110xxxx 10yyyyyy 10zzzzzz (3 byte)
 */
function ucs2hextoutf8(s) {
    function _conv(s) {
	var i1 = parseInt(s.substr(0, 2), 16);
	var i2 = parseInt(s.substr(2), 16);
	if (i1 == 0 & i2 < 0x80) { // 1 byte
	    return String.fromCharCode(i2);
	}
	if (i1 < 8) { // 2 bytes
	    var u1 = 0xc0 | ((i1 & 0x07) << 3) | ((i2 & 0xc0) >> 6);
	    var u2 = 0x80 | (i2 & 0x3f);
	    return hextoutf8(u1.toString(16) + u2.toString(16));
	}
	// 3 bytes
	var u1 = 0xe0 | ((i1 & 0xf0) >> 4);
	var u2 = 0x80 | ((i1 & 0x0f) << 2) | ((i2 & 0xc0) >> 6);
	var u3 = 0x80 | (i2 & 0x3f);
	return hextoutf8(u1.toString(16) + u2.toString(16) + u3.toString(16));
    }
    var a = s.match(/.{4}/g);
    var a2 = a.map(_conv);
    return a2.join("");
}

// ==== URIComponent ================================
/**
 * convert UTFa hexadecimal string to a URLComponent string such like "%67%68".<br/>
 * Note that these "<code>0-9A-Za-z!'()*-._~</code>" characters will not
 * converted to "%xx" format by builtin 'encodeURIComponent()' function.
 * However this 'encodeURIComponentAll()' function will convert 
 * all of characters into "%xx" format.
 * @name encodeURIComponentAll
 * @function
 * @param {String} s hexadecimal string
 * @return {String} URIComponent string such like "%67%68"
 * @since 1.1
 */
function encodeURIComponentAll(u8) {
  var s = encodeURIComponent(u8);
  var s2 = "";
  for (var i = 0; i < s.length; i++) {
    if (s[i] == "%") {
      s2 = s2 + s.substr(i, 3);
      i = i + 2;
    } else {
      s2 = s2 + "%" + stohex(s[i]);
    }
  }
  return s2;
}

// ==== new lines ================================
/**
 * convert all DOS new line("\r\n") to UNIX new line("\n") in 
 * a String "s".
 * @name newline_toUnix
 * @function
 * @param {String} s string 
 * @return {String} converted string
 */
function newline_toUnix(s) {
    s = s.replace(/\r\n/mg, "\n");
    return s;
}

/**
 * convert all UNIX new line("\r\n") to DOS new line("\n") in 
 * a String "s".
 * @name newline_toDos
 * @function
 * @param {String} s string 
 * @return {String} converted string
 */
function newline_toDos(s) {
    s = s.replace(/\r\n/mg, "\n");
    s = s.replace(/\n/mg, "\r\n");
    return s;
}

// ==== string type checker ===================

/**
 * check whether a string is an integer string or not<br/>
 * @name isInteger
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is an integer string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isInteger("12345") &rarr; true
 * KJUR.lang.String.isInteger("123ab") &rarr; false
 */
KJUR.lang.String.isInteger = function(s) {
    if (s.match(/^[0-9]+$/)) {
	return true;
    } else if (s.match(/^-[0-9]+$/)) {
	return true;
    } else {
	return false;
    }
};

/**
 * check whether a string is an hexadecimal string or not (DEPRECATED)<br/>
 * @name isHex
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is an hexadecimal string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @deprecated from 10.0.6. please use {@link ishex}
 * @see ishex
 * @example
 * KJUR.lang.String.isHex("1234") &rarr; true
 * KJUR.lang.String.isHex("12ab") &rarr; true
 * KJUR.lang.String.isHex("12AB") &rarr; true
 * KJUR.lang.String.isHex("12ZY") &rarr; false
 * KJUR.lang.String.isHex("121") &rarr; false -- odd length
 */
KJUR.lang.String.isHex = function(s) {
    return ishex(s);
};

/**
 * check whether a string is an hexadecimal string or not<br/>
 * @name ishex
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is an hexadecimal string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * ishex("1234") &rarr; true
 * ishex("12ab") &rarr; true
 * ishex("12AB") &rarr; true
 * ishex("12ZY") &rarr; false
 * ishex("121") &rarr; false -- odd length
 */
function ishex(s) {
    if (s.length % 2 == 0 &&
	(s.match(/^[0-9a-f]+$/) || s.match(/^[0-9A-F]+$/))) {
	return true;
    } else {
	return false;
    }
};

/**
 * check whether a string is a base64 encoded string or not<br/>
 * Input string can conclude new lines or space characters.
 * @name isBase64
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is a base64 encoded string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isBase64("YWE=") &rarr; true
 * KJUR.lang.String.isBase64("YW_=") &rarr; false
 * KJUR.lang.String.isBase64("YWE") &rarr; false -- length shall be multiples of 4
 */
KJUR.lang.String.isBase64 = function(s) {
    s = s.replace(/\s+/g, "");
    if (s.match(/^[0-9A-Za-z+\/]+={0,3}$/) && s.length % 4 == 0) {
	return true;
    } else {
	return false;
    }
};

/**
 * check whether a string is a base64url encoded string or not<br/>
 * Input string can conclude new lines or space characters.
 * @name isBase64URL
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is a base64url encoded string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isBase64URL("YWE") &rarr; true
 * KJUR.lang.String.isBase64URL("YW-") &rarr; true
 * KJUR.lang.String.isBase64URL("YW+") &rarr; false
 */
KJUR.lang.String.isBase64URL = function(s) {
    if (s.match(/[+/=]/)) return false;
    s = b64utob64(s);
    return KJUR.lang.String.isBase64(s);
};


/**
 * check whether a string is a base64url encoded string and dot or not<br/>
 * Input string can conclude new lines or space characters.
 * @name isBase64URLDot
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is a base64url encoded string and dot otherwise false
 * @since base64x 1.1.30 jsrsasign 10.5.25
 * @example
 * isBase64URLDot("YWE") &rarr; true
 * isBase64URLDot("YWE.YWE.YWE") &rarr; true
 * isBase64URLDot("YW-") &rarr; true
 * isBase64URLDot("YW+") &rarr; false
 */
function isBase64URLDot(s) {
    if (s.match(/^[0-9A-Za-z-_.]+$/)) return true;
    return false;
}

/**
 * check whether a string is a string of integer array or not<br/>
 * Input string can conclude new lines or space characters.
 * @name isIntegerArray
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is a string of integer array otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isIntegerArray("[1,2,3]") &rarr; true
 * KJUR.lang.String.isIntegerArray("  [1, 2, 3  ] ") &rarr; true
 * KJUR.lang.String.isIntegerArray("[a,2]") &rarr; false
 */
KJUR.lang.String.isIntegerArray = function(s) {
    s = s.replace(/\s+/g, "");
    if (s.match(/^\[[0-9,]+\]$/)) {
	return true;
    } else {
	return false;
    }
};

/**
 * check whether a string consists of PrintableString characters<br/>
 * @name isPrintable
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" consists of PrintableString characters
 * @since jsrsasign 9.0.0 base64x 1.1.16
 * A PrintableString consists of following characters
 * <pre>
 * 0-9A-Za-z '()+,-./:=?
 * </pre>
 * This method returns false when other characters than above.
 * Otherwise it returns true.
 * @example
 * KJUR.lang.String.isPrintable("abc") &rarr; true
 * KJUR.lang.String.isPrintable("abc@") &rarr; false
 * KJUR.lang.String.isPrintable("あいう") &rarr; false
 */
KJUR.lang.String.isPrintable = function(s) {
    if (s.match(/^[0-9A-Za-z '()+,-./:=?]*$/) !== null) return true;
    return false;
};

/**
 * check whether a string consists of IAString characters<br/>
 * @name isIA5
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" consists of IA5String characters
 * @since jsrsasign 9.0.0 base64x 1.1.16
 * A IA5String consists of following characters
 * <pre>
 * %x00-21/%x23-7F (i.e. ASCII characters excludes double quote(%x22)
 * </pre>
 * This method returns false when other characters than above.
 * Otherwise it returns true.
 * @example
 * KJUR.lang.String.isIA5("abc") &rarr; true
 * KJUR.lang.String.isIA5('"abc"') &rarr; false
 * KJUR.lang.String.isIA5("あいう") &rarr; false
 */
KJUR.lang.String.isIA5 = function(s) {
    if (s.match(/^[\x20-\x21\x23-\x7f]*$/) !== null) return true;
    return false;
};

/**
 * check whether a string is RFC 822 mail address<br/>
 * @name isMail
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" RFC 822 mail address
 * @since jsrsasign 9.0.0 base64x 1.1.16
 * This static method will check string s is RFC 822 compliant mail address.
 * @example
 * KJUR.lang.String.isMail("abc") &rarr; false
 * KJUR.lang.String.isMail("abc@example") &rarr; false
 * KJUR.lang.String.isMail("abc@example.com") &rarr; true
 */
KJUR.lang.String.isMail = function(s) {
    if (s.match(/^[A-Za-z0-9]{1}[A-Za-z0-9_.-]*@{1}[A-Za-z0-9_.-]{1,}\.[A-Za-z0-9]{1,}$/) !== null) return true;
    return false;
};

// ==== others ================================

/**
 * canonicalize hexadecimal string of positive integer<br/>
 * @name hextoposhex
 * @function
 * @param {String} s hexadecimal string 
 * @return {String} canonicalized hexadecimal string of positive integer
 * @since base64x 1.1.10 jsrsasign 7.1.4
 * @description
 * This method canonicalize a hexadecimal string of positive integer
 * for two's complement representation.
 * Canonicalized hexadecimal string of positive integer will be:
 * <ul>
 * <li>Its length is always even.</li>
 * <li>If odd length it will be padded with leading zero.<li>
 * <li>If it is even length and its first character is "8" or greater,
 * it will be padded with "00" to make it positive integer.</li>
 * </ul>
 * @example
 * hextoposhex("abcd") &rarr; "00abcd"
 * hextoposhex("1234") &rarr; "1234"
 * hextoposhex("12345") &rarr; "012345"
 */
function hextoposhex(s) {
    if (s.length % 2 == 1) return "0" + s;
    if (s.substr(0, 1) > "7") return "00" + s;
    return s;
}

/**
 * convert string of integer array to hexadecimal string.<br/>
 * @name intarystrtohex
 * @function
 * @param {String} s string of integer array
 * @return {String} hexadecimal string
 * @since base64x 1.1.6 jsrsasign 5.0.2
 * @throws "malformed integer array string: *" for wrong input
 * @description
 * This function converts a string of JavaScript integer array to
 * a hexadecimal string. Each integer value shall be in a range 
 * from 0 to 255 otherwise it raise exception. Input string can
 * have extra space or newline string so that they will be ignored.
 * 
 * @example
 * intarystrtohex(" [123, 34, 101, 34, 58] ")
 * &rarr; 7b2265223a (i.e. '{"e":' as string)
 */
function intarystrtohex(s) {
  s = s.replace(/^\s*\[\s*/, '');
  s = s.replace(/\s*\]\s*$/, '');
  s = s.replace(/\s*/g, '');
  try {
    var hex = s.split(/,/).map(function(element, index, array) {
      var i = parseInt(element);
      if (i < 0 || 255 < i) throw "integer not in range 0-255";
      var hI = ("00" + i.toString(16)).slice(-2);
      return hI;
    }).join('');
    return hex;
  } catch(ex) {
    throw "malformed integer array string: " + ex;
  }
}

/**
 * find index of string where two string differs
 * @name strdiffidx
 * @function
 * @param {String} s1 string to compare
 * @param {String} s2 string to compare
 * @return {Number} string index of where character differs. Return -1 if same.
 * @since jsrsasign 4.9.0 base64x 1.1.5
 * @example
 * strdiffidx("abcdefg", "abcd4fg") -> 4
 * strdiffidx("abcdefg", "abcdefg") -> -1
 * strdiffidx("abcdefg", "abcdef") -> 6
 * strdiffidx("abcdefgh", "abcdef") -> 6
 */
var strdiffidx = function(s1, s2) {
    var n = s1.length;
    if (s1.length > s2.length) n = s2.length;
    for (var i = 0; i < n; i++) {
	if (s1.charCodeAt(i) != s2.charCodeAt(i)) return i;
    }
    if (s1.length != s2.length) return n;
    return -1; // same
};

// ==== hex / oid =================================

/**
 * get hexadecimal value of object identifier from dot noted oid value
 * @name oidtohex
 * @function
 * @param {String} oidString dot noted string of object identifier
 * @return {String} hexadecimal value of object identifier
 * @since jsrsasign 10.1.0 base64x 1.1.18
 * @see hextooid
 * @see ASN1HEX.hextooidstr
 * @see KJUR.asn1.ASN1Util.oidIntToHex
 * @description
 * This static method converts from object identifier value string.
 * to hexadecimal string representation of it.
 * {@link hextooid} is a reverse function of this.
 * @example
 * oidtohex("2.5.4.6") &rarr; "550406"
 */
function oidtohex(oidString) {
    var itox = function(i) {
        var h = i.toString(16);
        if (h.length == 1) h = '0' + h;
        return h;
    };

    var roidtox = function(roid) {
        var h = '';
        var bi = parseInt(roid, 10);
        var b = bi.toString(2);

        var padLen = 7 - b.length % 7;
        if (padLen == 7) padLen = 0;
        var bPad = '';
        for (var i = 0; i < padLen; i++) bPad += '0';
        b = bPad + b;
        for (var i = 0; i < b.length - 1; i += 7) {
            var b8 = b.substr(i, 7);
            if (i != b.length - 7) b8 = '1' + b8;
            h += itox(parseInt(b8, 2));
        }
        return h;
    };
    
    try {
	if (! oidString.match(/^[0-9.]+$/)) return null;
    
	var h = '';
	var a = oidString.split('.');
	var i0 = parseInt(a[0], 10) * 40 + parseInt(a[1], 10);
	h += itox(i0);
	a.splice(0, 2);
	for (var i = 0; i < a.length; i++) {
            h += roidtox(a[i]);
	}
	return h;
    } catch(ex) {
	return null;
    }
};

/**
 * get oid string from hexadecimal value of object identifier<br/>
 * @name hextooid
 * @function
 * @param {String} h hexadecimal value of object identifier
 * @return {String} dot noted string of object identifier (ex. "1.2.3.4")
 * @since jsrsasign 10.1.0 base64x 1.1.18
 * @see oidtohex
 * @see ASN1HEX.hextooidstr
 * @see KJUR.asn1.ASN1Util.oidIntToHex
 * @description
 * This static method converts from hexadecimal object identifier value 
 * to dot noted OID value (ex. "1.2.3.4").
 * {@link oidtohex} is a reverse function of this.
 * @example
 * hextooid("550406") &rarr; "2.5.4.6"
 */
function hextooid(h) {
    if (! ishex(h)) return null;
    try {
	var a = [];

	// a[0], a[1]
	var hex0 = h.substr(0, 2);
	var i0 = parseInt(hex0, 16);
	a[0] = new String(Math.floor(i0 / 40));
	a[1] = new String(i0 % 40);

	// a[2]..a[n]
	var hex1 = h.substr(2);
	var b = [];
	for (var i = 0; i < hex1.length / 2; i++) {
	    b.push(parseInt(hex1.substr(i * 2, 2), 16));
	}
	var c = [];
	var cbin = "";
	for (var i = 0; i < b.length; i++) {
            if (b[i] & 0x80) {
		cbin = cbin + strpad((b[i] & 0x7f).toString(2), 7);
            } else {
		cbin = cbin + strpad((b[i] & 0x7f).toString(2), 7);
		c.push(new String(parseInt(cbin, 2)));
		cbin = "";
            }
	}

	var s = a.join(".");
	if (c.length > 0) s = s + "." + c.join(".");
	return s;
    } catch(ex) {
	return null;
    }
};

/**
 * string padding<br/>
 * @name strpad
 * @function
 * @param {String} s input string
 * @param {Number} len output string length
 * @param {String} padchar padding character (default is "0")
 * @return {String} padded string
 * @since jsrsasign 10.1.0 base64x 1.1.18
 * @example
 * strpad("1234", 10, "0") &rarr; "0000001234"
 * strpad("1234", 10, " ") &rarr; "      1234"
 * strpad("1234", 10)      &rarr; "0000001234"
 */
var strpad = function(s, len, padchar) {
    if (padchar == undefined) padchar = "0";
    if (s.length >= len) return s;
    return new Array(len - s.length + 1).join(padchar) + s;
};

// ==== bitstr hex / int =================================

/**
 * convert from hexadecimal string of ASN.1 BitString value with unused bit to integer value<br/>
 * @name bitstrtoint
 * @function
 * @param {String} h hexadecimal string of ASN.1 BitString value with unused bit
 * @return {Number} positive integer value of the BitString
 * @since jsrsasign 10.1.3 base64x 1.1.19
 * @see inttobitstr
 * @see KJUR.asn1.DERBitString
 * @see ASN1HEX.getInt
 * 
 * @description
 * This function converts from hexadecimal string of ASN.1 BitString
 * value with unused bit to its integer value. <br/>
 * When an improper hexadecimal string of BitString value
 * is applied, this returns -1.
 * 
 * @example
 * // "03c8" &rarr; 0xc8 unusedbit=03 &rarr; 11001000b unusedbit=03 &rarr; 11001b &rarr; 25
 * bitstrtoint("03c8") &rarr; 25
 * // "02fff8" &rarr; 0xfff8 unusedbit=02 &rarr; 1111111111111000b unusedbit=02
 * //   11111111111110b &rarr; 16382
 * bitstrtoint("02fff8") &rarr; 16382
 * bitstrtoint("05a0") &rarr; 5 (=101b)
 * bitstrtoint("ff00") &rarr; -1 // for improper BitString value
 * bitstrtoint("05a0").toString(2) &rarr; "101"
 * bitstrtoint("07a080").toString(2) &rarr; "101000001"
 */
function bitstrtoint(h) {
    if (h.length % 2 != 0) return -1; 
    h = h.toLowerCase();
    if (h.match(/^[0-9a-f]+$/) == null) return -1;
    try {
	var hUnusedbit = h.substr(0, 2);
	if (hUnusedbit == "00")
	    return parseInt(h.substr(2), 16);
	var iUnusedbit = parseInt(hUnusedbit, 16);
	if (iUnusedbit > 7) return -1;
	var hValue = h.substr(2);
	var bValue = parseInt(hValue, 16).toString(2);
	if (bValue == "0") bValue = "00000000";
	bValue = bValue.slice(0, 0 - iUnusedbit);
	var iValue = parseInt(bValue, 2);
	if (iValue == NaN) return -1;
	return iValue;
    } catch(ex) {
	return -1;
    }
};

/**
 * convert from integer value to hexadecimal string of ASN.1 BitString value with unused bit<br/>
 * @name inttobitstr
 * @function
 * @param {Number} n integer value of ASN.1 BitString
 * @return {String} hexadecimal string of ASN.1 BitString value with unused bit
 * @since jsrsasign 10.1.3 base64x 1.1.19
 * @see bitstrtoint
 * @see KJUR.asn1.DERBitString
 * @see ASN1HEX.getInt
 * 
 * @description
 * This function converts from an integer value to 
 * hexadecimal string of ASN.1 BitString value
 * with unused bit. <br/>
 * When "n" is not non-negative number, this returns null
 * 
 * @example
 * // 25 &rarr; 11001b &rarr; 11001000b unusedbit=03 &rarr; 0xc8 unusedbit=03 &rarr; "03c8"
 * inttobitstr(25) &rarr; "03c8"
 * inttobitstr(-3) &rarr; null
 * inttobitstr("abc") &rarr; null
 * inttobitstr(parseInt("11001", 2)) &rarr; "03c8"
 * inttobitstr(parseInt("101", 2)) &rarr; "05a0"
 * inttobitstr(parseInt("101000001", 2)) &rarr; "07a080"
 */
function inttobitstr(n) {
    if (typeof n != "number") return null;
    if (n < 0) return null;
    var bValue = Number(n).toString(2);
    var iUnusedbit = 8 - bValue.length % 8;
    if (iUnusedbit == 8) iUnusedbit = 0;
    bValue = bValue + strpad("", iUnusedbit, "0");
    var hValue = parseInt(bValue, 2).toString(16);
    if (hValue.length % 2 == 1) hValue = "0" + hValue;
    var hUnusedbit = "0" + iUnusedbit;
    return hUnusedbit + hValue;
};

// ==== bitstr hex / binary string =======================

/**
 * convert from hexadecimal string of ASN.1 BitString value with unused bit to binary string<br/>
 * @name bitstrtobinstr
 * @function
 * @param {string} h hexadecimal string of ASN.1 BitString value with unused bit
 * @return {string} binary string
 * @since jsrsasign 10.5.4 base64x 1.1.21
 * @see binstrtobitstr
 * @see inttobitstr
 * 
 * @description
 * This function converts from hexadecimal string of ASN.1 BitString
 * value with unused bit to its integer value. <br/>
 * When an improper hexadecimal string of BitString value
 * is applied, this returns null.
 * 
 * @example
 * bitstrtobinstr("05a0") &rarr; "101"
 * bitstrtobinstr("0520") &rarr; "001"
 * bitstrtobinstr("07a080") &rarr; "101000001"
 * bitstrtobinstr(502) &rarr; null // non ASN.1 BitString value
 * bitstrtobinstr("ff00") &rarr; null // for improper BitString value
 */
function bitstrtobinstr(h) {
    if (typeof h != "string") return null;
    if (h.length % 2 != 0) return null;
    if (! h.match(/^[0-9a-f]+$/)) return null;
    try {
	var unusedBits = parseInt(h.substr(0, 2), 16);
	if (unusedBits < 0 || 7 < unusedBits) return null

	var value = h.substr(2);
	var bin = "";
	for (var i = 0; i < value.length; i += 2) {
	    var hi = value.substr(i, 2);
	    var bi = parseInt(hi, 16).toString(2);
	    bi = ("0000000" + bi).slice(-8);
	    bin += bi;
	}
	return  bin.substr(0, bin.length - unusedBits);
    } catch(ex) {
	return null;
    }
}

/**
 * convert from binary string to hexadecimal string of ASN.1 BitString value with unused bit<br/>
 * @name binstrtobitstr
 * @function
 * @param {string} s binary string (ex. "101")
 * @return {string} hexadecimal string of ASN.1 BitString value with unused bit
 * @since jsrsasign 10.5.4 base64x 1.1.21
 * @see bitstrtobinstr
 * @see inttobitstr
 * @see KJUR.asn1.DERBitString
 * 
 * @description
 * This function converts from an binary string (ex. "101") to 
 * hexadecimal string of ASN.1 BitString value
 * with unused bit (ex. "05a0"). <br/>
 * When "s" is not binary string, this returns null.
 * 
 * @example
 * binstrtobitstr("101") &rarr; "05a0"
 * binstrtobitstr("001") &rarr; "0520"
 * binstrtobitstr("11001") &rarr; "03c8"
 * binstrtobitstr("101000001") &rarr; "07a080"
 * binstrtobitstr(101) &rarr; null // not number
 * binstrtobitstr("xyz") &rarr; null // not binary string
 */
function binstrtobitstr(s) {
    if (typeof s != "string") return null;
    if (s.match(/^[01]+$/) == null) return null;
    try {
	var n = parseInt(s, 2);
	return inttobitstr(n);
    } catch(ex) {
	return null;
    }
}

// =======================================================
/**
 * convert array of names to bit string<br/>
 * @name namearraytobinstr
 * @function
 * @param {array} namearray array of name string
 * @param {object} namedb associative array of name and value
 * @return {string} binary string (ex. "110001")
 * @since jsrsasign 10.5.21 base64x 1.1.27
 * @see KJUR.asn1.x509.KeyUsage
 * @see KJUR.asn1.tsp.PKIFailureInfo
 * 
 * @description
 * This function converts from an array of names to
 * a binary string. DB value bit will be set.
 * Note that ordering of namearray items
 * will be ignored.
 *
 * @example
 * db = { a: 0, b: 3, c: 8, d: 9, e: 17, f: 19 };
 * namearraytobinstr(['a', 'c', 'd'], db) &rarr: '1000000011'
 * namearraytobinstr(['c', 'b'], db) &rarr: '000100001'
 */
function namearraytobinstr (namearray, namedb) {
    var d = 0;
    for (var i = 0; i < namearray.length; i++) {
	d |= 1 << namedb[namearray[i]];
    }

    var s = d.toString(2);
    var r = "";
    for (var i = s.length - 1; i >=0; i--) {
	r += s[i];
    }
    return r;
}

// =======================================================
/**
 * set class inheritance<br/>
 * @name extendClass
 * @function
 * @param {Function} subClass sub class to set inheritance
 * @param {Function} superClass super class to inherit
 * @since jsrsasign 10.3.0 base64x 1.1.21
 *
 * @description
 * This function extends a class and set an inheritance
 * for member variables and methods.
 *
 * @example
 * var Animal = function() {
 *   this.hello = function(){console.log("Hello")};
 *   this.name="Ani";
 * };
 * var Dog = function() {
 *   Dog.superclass.constructor.call(this);
 *   this.vow = function(){console.log("Vow wow")};
 *   this.tail=true;
 * };
 * extendClass(Dog, Animal);
 */
function extendClass(subClass, superClass) {
    var F = function() {};
    F.prototype = superClass.prototype;
    subClass.prototype = new F();
    subClass.prototype.constructor = subClass;
    subClass.superclass = superClass.prototype;
     
    if (superClass.prototype.constructor == Object.prototype.constructor) {
        superClass.prototype.constructor = superClass;
    }
};

