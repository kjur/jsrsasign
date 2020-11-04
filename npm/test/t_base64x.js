var assert = require('assert');
var rs = require('../lib/jsrsasign.js');

describe("base64x", function() {
    describe("hextorstr", function() {
	it('should return aaa', function() {
	    assert.equal("aaa", rs.hextorstr("616161"));
	});
    });
    describe("utf8tob64u, b64utoutf8", function() {
	it('utf8tob64u', function() {
	    assert.equal(rs.utf8tob64u("あ"), "44GC");
	    assert.equal(rs.utf8tob64u("aaa"), "YWFh");
	});
	it('b64utoutf8', function() {
	    assert.equal(rs.b64utoutf8("44GC"), "あ");
	    assert.equal(rs.b64utoutf8("YWFh"), "aaa");
	});
    });
});
