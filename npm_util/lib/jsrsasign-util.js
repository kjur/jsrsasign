/*! jsrsasign-util-1.0.1 (c) 2016-2020 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var fs=require("fs");var JSONC=require("jsonc-parser");var rs=require("jsrsasign");function readFileUTF8(a){return require("fs").readFileSync(a,"utf8")}function readFileHexByBin(a){return rs.rstrtohex(fs.readFileSync(a,"binary"))}function readFile(a){return fs.readFileSync(a,"binary")}function saveFile(c,b){var a=require("fs");a.writeFileSync(c,b,"binary")}function saveFileUTF8(c,b){var a=require("fs");a.writeFileSync(c,b,"utf8")}function saveFileBinByHex(c,a){var b=rs.hextorstr(a);fs.writeFileSync(c,b,"binary")}function readJSON(b){var a=fs.readFileSync(b,"utf8");var c=JSON.parse(a);return c}function readJSONC(b){var a=fs.readFileSync(b,"utf8");var c=JSONC.parse(a);return c}function saveFileJSON(a,b){var c=JSON.stringify(b,null,"  ");saveFileUTF8(a,c)}function printJSON(a,c){var b="";if(c!=undefined){b=c}console.log(b+JSON.stringify(a,null,"  "))};
exports.readFileUTF8 = readFileUTF8;
exports.readFileHexByBin = readFileHexByBin;
exports.readFile = readFile;
exports.saveFile = saveFile;
exports.saveFileUTF8 = saveFileUTF8;
exports.saveFileBinByHex = saveFileBinByHex;
exports.readJSON = readJSON;
exports.readJSONC = readJSONC;
exports.saveFileJSON = saveFileJSON;
exports.printJSON = printJSON;

