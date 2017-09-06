jsrsasign-util
=========

This package provides supplementary functions for 'jsrsasign' such like file I/O utilities.

Public page is https://kjur.github.io/jsrsasign .

[github TOP](https://kjur.github.io/jsrsasign/)|[API doc](https://kjur.github.io/jsrsasign/api/)|[Wiki](https://github.com/kjur/jsrsasign/wiki)|[Node sample](https://github.com/kjur/jsrsasign/tree/master/sample_node)

AVAILABLE FUNCTIONS
-----------------------------

- [readFile](https://kjur.github.io/jsrsasign/api/symbols/global__.html#readFile) : read file as binary string
- [readFileHexByBin](https://kjur.github.io/jsrsasign/api/symbols/global__.html#readFileHexByBin) : read file as binary then convert it to hexadecimal string
- [readFileUTF8](https://kjur.github.io/jsrsasign/api/symbols/global__.html#readFileUTF8) : read file as UTF-8 string
- [saveFile](https://kjur.github.io/jsrsasign/api/symbols/global__.html#saveFile) : save file as binary string
- [saveFileBinByHex](https://kjur.github.io/jsrsasign/api/symbols/global__.html#saveFileBinByHex) : convert a hexadecimal string to raw string then save it as file.

EXAMPLE(1) SIGNATURE
--------------------

    > var rsu = require('jsrsasign-util');
    > var rawString = rsu.readFile("bar.bin");
    > rsu.saveFileBinByHex("foo.bin", "30143abb...");


