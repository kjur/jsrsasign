/* base64x-1.1.14 (c) 2012-2018 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * base64x.js - Base64url and supplementary functions for Tom Wu's base64.js library
 *
 * version: 1.1.14 (2018-Apr-21)
 *
 * Copyright (c) 2012-2018 Kenji Urushima (kenji.urushima@gmail.com)
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
 * @version jsrsasign 8.0.12 base64x 1.1.14 (2018-Apr-22)
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
 */

/**
 * convert a Base64URL encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @name b64utoutf8
 * @function
 * @param {String} s Base64URL encoded string
 * @return {String} UTF-8 encoded string
 * @since 1.1
 */

var utf8tob64u, b64utoutf8;

if (typeof Buffer === 'function') {
  utf8tob64u = function (s) {
    return b64tob64u(new Buffer(s, 'utf8').toString('base64'));
  };

  b64utoutf8 = function (s) {
    return new Buffer(b64utob64(s), 'base64').toString('utf8');
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
  return uricmptohex(encodeURIComponentAll(s));
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
  return decodeURIComponent(hextouricmp(s));
}

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
 * @example
 * pemtohex("-----BEGIN PUBLIC KEY...") &rarr; "3082..."
 * pemtohex("-----BEGIN CERTIFICATE...", "CERTIFICATE") &rarr; "3082..."
 * pemtohex(" \r\n-----BEGIN DSA PRIVATE KEY...") &rarr; "3082..."
 */
function pemtohex(s, sHead) {
    if (s.indexOf("-----BEGIN ") == -1)
        throw "can't find PEM header: " + sHead;

    if (sHead !== undefined) {
        s = s.replace("-----BEGIN " + sHead + "-----", "");
        s = s.replace("-----END " + sHead + "-----", "");
    } else {
        s = s.replace(/-----BEGIN [^-]+-----/, '');
        s = s.replace(/-----END [^-]+-----/, '');
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
    throw "unsupported zulu format: " + s;
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
    var msec = zulutomsec(s);
    return ~~(msec / 1000);
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
 * hextoip("871020010db8000000000000000000000004") &rarr "2001:db8::4"
 * hextoip("871020010db8000000000000000000") &rarr raise exception
 * hextoip("xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz") &rarr raise exception
 */
function hextoipv6(s) {
  if (! s.match(/^[0-9A-Fa-f]{32}$/))
    throw "malformed IPv6 address octet";

  // 1. downcase
  s = s.toLowerCase();

  // 2. split 4
  var a = s.match(/.{1,4}/g);

  // 3. trim leading 0
  for (var i = 0; i < 8; i++) {
    a[i] = a[i].replace(/^0+/, "");
    if (a[i] == '') a[i] = '0';
  }
  s = ":" + a.join(":") + ":";

  // 4. find shrinkables :0:0:...
  var aZero = s.match(/:(0:){2,}/g);

  // 5. no shrinkable
  if (aZero === null) return s.slice(1, -1);

  // 6. find max length :0:0:...
  var item = '';
  for (var i = 0; i < aZero.length; i++) {
    if (aZero[i].length > item.length) item = aZero[i];
  }

  // 7. shrink
  s = s.replace(item, '::');
  return s.slice(1, -1);
}

// ==== hex / ip =================================

/**
 * convert a hexadecimal string to IP addresss<br/>
 * @name hextoip
 * @function
 * @param {String} s hexadecimal string of IP address
 * @return {String} IP address string
 * @since jsrsasign 8.0.10 base64x 1.1.13
 * @description
 * This function converts a hexadecimal string of IPv4 or 
 * IPv6 address to IPv4 or IPv6 address string.
 * If byte length is not 4 nor 16, this returns a
 * hexadecimal string without conversion.
 * @see {@link hextoipv6}
 * @example
 * hextoip("c0a80101") &rarr "192.168.1.1"
 * hextoip("871020010db8000000000000000000000004") &rarr "2001:db8::4"
 * hextoip("c0a801010203") &rarr "c0a801010203" // 6 bytes
 * hextoip("zzz")) &rarr raise exception because of not hexadecimal
 */
function hextoip(s) {
  var malformedMsg = "malformed hex value";
  if (! s.match(/^([0-9A-Fa-f][0-9A-Fa-f]){1,}$/))
    throw malformedMsg;
  if (s.length == 8) { // ipv4
    var ip;
    try {
      ip = parseInt(s.substr(0, 2), 16) + "." +
           parseInt(s.substr(2, 2), 16) + "." +
           parseInt(s.substr(4, 2), 16) + "." +
           parseInt(s.substr(6, 2), 16);
      return ip;
    } catch (ex) {
      throw malformedMsg;
    }
  } else if (s.length == 32) {
    return hextoipv6(s);
  } else {
    return s;
  }
}

/**
 * convert IPv4/v6 addresss to a hexadecimal string<br/>
 * @name iptohex
 * @function
 * @param {String} s IPv4/v6 address string
 * @return {String} hexadecimal string of IP address
 * @since jsrsasign 8.0.12 base64x 1.1.14
 * @description
 * This function converts IPv4 or IPv6 address string to
 * a hexadecimal string of IPv4 or IPv6 address.
 * @example
 * iptohex("192.168.1.1") &rarr "c0a80101"
 * iptohex("2001:db8::4") &rarr "871020010db8000000000000000000000004"
 * iptohex("zzz")) &rarr raise exception
 */
function iptohex(s) {
  var malformedMsg = "malformed IP address";
  s = s.toLowerCase(s);

  if (s.match(/^[0-9.]+$/)) {
    var a = s.split(".");
    if (a.length !== 4) throw malformedMsg;
    var hex = "";
    try {
      for (var i = 0; i < 4; i++) {
        var d = parseInt(a[i]);
        hex += ("0" + d.toString(16)).slice(-2);
      }
      return hex;
    } catch(ex) {
      throw malformedMsg;
    }
  } else if (s.match(/^[0-9a-f:]+$/) && s.indexOf(":") !== -1) {
    return ipv6tohex(s);
  } else {
    throw malformedMsg;
  }
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
 * check whether a string is an hexadecimal string or not<br/>
 * @name isHex
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is an hexadecimal string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isHex("1234") &rarr; true
 * KJUR.lang.String.isHex("12ab") &rarr; true
 * KJUR.lang.String.isHex("12AB") &rarr; true
 * KJUR.lang.String.isHex("12ZY") &rarr; false
 * KJUR.lang.String.isHex("121") &rarr; false -- odd length
 */
KJUR.lang.String.isHex = function(s) {
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


