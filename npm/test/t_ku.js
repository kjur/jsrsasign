var assert = require('assert');
var rs = require('../lib/jsrsasign.js');

var hex = "3081a2020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104204e1578f2b98424cc0e86e28ce2350f02e810454c7cc683d4ed442926537a9515a00a06082a8648ce3d030107a1440342000467df2be8010970b07d40d95bd921e6dd8f2c7ec5cd308ad73cd0917b87d5edf0d28894b124c4734c5f714280c3dc8d63d1003eb292bbdb0348672ff88a3f85eaa00d300b0603551d0f310403020080";

var p = {
    "algoid": "2a8648ce3d0201",
    "algparam": "2a8648ce3d030107",
    "keyidx": 58
};

describe("ggg", function() {
  describe("prv", function() {
    var info = rs.KEYUTIL.parsePlainPrivatePKCS8Hex(hex);
    it('load and sign properly', function() {
      assert.deepEqual(info, p);
    });
  });
});
