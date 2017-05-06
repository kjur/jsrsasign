/*! nodeutil-1.0.0 (c) 2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * nodeutil.js - Utilities for Node
 *
 * version: 1.0.0 (2015 Nov 11)
 *
 * Copyright (c) 2015 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name nodeutil-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.0 (2015-Nov-11)
 * @since jsrsasign 5.0.2
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * read file and return file contents as utf-8 string
 * @param {String} utf8File file name to be read
 * @return {String} utf-8 string of file contents
 * @description
 * This function only works in Node.js.
 */
function readFileUTF8(utf8File) {
    return require('fs').readFileSync(utf8File, 'utf8');
}

/**
 * read binary file and return file contents as hexadecimal string
 * @param {String} binFile file name to be read
 * @return {String} hexadecimal string of file contents
 * @description
 * This function only works in Node.js.
 */
function readFileHexByBin(binFile) {
    var rs = require('jsrsasign');
    var fs = require('fs');
    return rs.rstrtohex(fs.readFileSync(binFile, 'binary'));
}

/**
 * read file and return file contents
 * @param {String} binFile file name to be read
 * @return {String} raw string of file contents
 * @description
 * This function only works in Node.js.
 */
function readFile(binFile) {
    var fs = require('fs');
    return fs.readFileSync(binFile, 'binary');
}

/**
 * save raw string to file
 * @param {String} binFile file name to save contents.
 * @param {String} rawString string contents to be saved.
 * @description
 * This function only works in Node.js.
 */
function saveFile(binFile, rawString) {
    var fs = require('fs');
    fs.writeFileSync(binFile, rawString, 'binary');
}

/**
 * save data represented by hexadecimal string to file
 * @param {String} binFile file name to save contents.
 * @param {String} hexString hexadecimal string to be saved.
 * @description
 * This function only works in Node.js.
 */
function saveFileBinByHex(binFile, hexString) {
    var fs = require('fs');
    var rs = require('jsrsasign');
    var rawString = rs.hextorstr(hexString);
    fs.writeFileSync(binFile, rawString, 'binary');
}
