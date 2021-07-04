/* nodeutil-1.0.2 (c) 2015-2021 Kenji Urushima | kjur.github.io/jsrsasign/license
 */
/*
 * nodeutil.js - Utilities for Node
 *
 * Copyright (c) 2015-2021 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name nodeutil-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign-util 1.0.3 nodeutil 1.0.2 (2021-Feb-15)
 * @since jsrsasign 5.0.2
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */
var fs = require("fs");
var JSONC = require("jsonc-parser");
var rs = require("jsrsasign");

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
 * save UTF-8 string to file
 * @param {String} binFile file name to save contents.
 * @param {String} utf8String string contents to be saved.
 * @description
 * This function only works in Node.js.
 */
function saveFileUTF8(binFile, utf8String) {
    var fs = require('fs');
    fs.writeFileSync(binFile, utf8String, 'utf8');
}

/**
 * save data represented by hexadecimal string to file
 * @param {String} binFile file name to save contents.
 * @param {String} hexString hexadecimal string to be saved.
 * @description
 * This function only works in Node.js.
 */
function saveFileBinByHex(binFile, hexString) {
    var rawString = rs.hextorstr(hexString);
    fs.writeFileSync(binFile, rawString, 'binary');
}

/**
 * read JSON file and return its JSON object
 * @param {String} JSON file name to be read
 * @return {Object} JSON object or array of file contents
 * @since jsrsasign-util 1.0.1 nodeutil 1.0.1
 *
 * @description
 * This function only works in Node.js.
 * @example
 * var rsu = require("jsrsasign-util");
 * rsu.readJSON("aaa.json") &rarr; JSON object
 */
function readJSON(jsonFile) {
    var jsonStr = fs.readFileSync(jsonFile, "utf8");
    var json = JSON.parse(jsonStr);
    return json;
}

/**
 * read JSONC file and return its JSON object
 * @param {String} JSONC file name to be read
 * @return {Object} JSON object or array of file contents
 * @since jsrsasign-util 1.0.1 nodeutil 1.0.1
 *
 * @description
 * This method read JSONC (i.e. JSON with comments) file
 * and returns JSON object.
 * This function only works in Node.js.
 * 
 * @example
 * var rsu = require("jsrsasign-util");
 * rsu.readJSONC("aaa.jsonc") &rarr; JSON object
 */
function readJSONC(jsonFile) {
    var jsonStr = fs.readFileSync(jsonFile, "utf8");
    var json = JSONC.parse(jsonStr);
    return json;
}

/**
 * save JSON object as file
 * @param {Object} jsonFile output JSON file name
 * @param {Object} json JSON object to save
 * @since jsrsasign-util 1.0.1 nodeutil 1.0.1
 *
 * @description
 * This method saves JSON object as a file.
 * This function only works in Node.js.
 * 
 * @example
 * var rsu = require("jsrsasign-util");
 * rsu.saveFileJSON("aaa.jsonc", json);
 */
function saveFileJSON(jsonFile, json) {
    var s = JSON.stringify(json, null, "  ");
    saveFileUTF8(jsonFile, s);
}

/**
 * output JSON object to console
 * @param {Object} json JSON object to print out
 * @param {Object} prefix prefix string (OPTION)
 * @since jsrsasign-util 1.0.1 nodeutil 1.0.1
 *
 * @description
 * This method writes JSON object to console.
 * This function only works in Node.js.
 * 
 * @example
 * var rsu = require("jsrsasign-util");
 * var obj = {aaa: "bbb", "ccc": 123};
 * rsu.printJSON(obj, "obj = ") &rarr;
 * obj = {
 *   "aaa": "bbb",
 *   "ccc": 123
 * }
 */
function printJSON(json, prefix) {
    var s = "";
    if (prefix != undefined) s = prefix;
    console.log(s + JSON.stringify(json, null, "  "));
}

