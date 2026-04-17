var assert = require('assert');
var rs = require('../lib/jsrsasign.js');

describe("JWS", function() {
    describe("verify HS256", function() {
	it('should verify valid and invalid HMAC signatures', function() {
	    var jwt = rs.KJUR.jws.JWS.sign(null,
					  {alg: "HS256", cty: "JWT"},
					  {age: 21},
					  "aaa");
	    assert.equal(rs.KJUR.jws.JWS.verify(jwt, "aaa"), true);
	    assert.equal(rs.KJUR.jws.JWS.verify(jwt, "aab"), false);
	});
    });
});
