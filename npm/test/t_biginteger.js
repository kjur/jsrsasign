var assert = require('assert');
var path = require('path');
var spawnSync = require('child_process').spawnSync;

describe("BigInteger", function() {
    it('modInverse(0, odd) should return 0 without hanging', function() {
        var childCode = [
            "var rs = require('./lib/jsrsasign.js');",
            "var a = new rs.BigInteger('0', 10);",
            "var m = new rs.BigInteger('9', 10);",
            "process.stdout.write(a.modInverse(m).toString(10));"
        ].join('\n');

        var result = spawnSync(process.execPath, ['-e', childCode], {
            cwd: path.resolve(__dirname, '..'),
            encoding: 'utf8',
            timeout: 1500
        });

        assert.notEqual(result.error && result.error.code, 'ETIMEDOUT');
        assert.equal(result.status, 0);
        assert.equal(result.stdout, '0');
    });
});
