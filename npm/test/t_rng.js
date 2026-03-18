var assert = require('assert');
var path = require('path');
var spawnSync = require('child_process').spawnSync;

function runChild(code) {
    return spawnSync(process.execPath, ['-e', code], {
	cwd: path.resolve(__dirname, '..'),
	encoding: 'utf8',
	timeout: 5000
    });
}

describe("SecureRandom", function() {
    it('should use crypto.randomBytes without seeding from Math.random in Node', function() {
	var childCode = [
	    "var Module = require('module');",
	    "var origLoad = Module._load;",
	    "var cryptoCalls = 0;",
	    "Module._load = function(request) {",
	    "  if (request === 'crypto') {",
	    "    return { randomBytes: function(size) { cryptoCalls++; return Buffer.alloc(size, 1); } };",
	    "  }",
	    "  return origLoad.apply(this, arguments);",
	    "};",
	    "var mathRandomCalls = 0;",
	    "var origRandom = Math.random;",
	    "Math.random = function() { mathRandomCalls++; return origRandom.call(Math); };",
	    "require('./lib/jsrsasign.js');",
	    "process.stdout.write(JSON.stringify({ cryptoCalls: cryptoCalls, mathRandomCalls: mathRandomCalls }));"
	].join('\n');

	var result = runChild(childCode);
	assert.equal(result.status, 0);

	var parsed = JSON.parse(result.stdout);
	assert.equal(parsed.cryptoCalls, 1);
	assert.equal(parsed.mathRandomCalls, 0);
    });

    it('should not become deterministic when Math.random and Date are controlled', function() {
	var childCode = [
	    "var _OrigDate = Date;",
	    "var seq = 0;",
	    "Math.random = function() { seq++; return ((seq * 7) % 65536) / 65536; };",
	    "var fixedTime = 1700000000000;",
	    "global.Date = class extends _OrigDate {",
	    "  constructor() {",
	    "    if (arguments.length === 0) super(fixedTime);",
	    "    else super(...arguments);",
	    "  }",
	    "  getTime() { return fixedTime; }",
	    "  static now() { return fixedTime; }",
	    "};",
	    "var rs = require('./lib/jsrsasign.js');",
	    "var out = new Array(32);",
	    "new rs.SecureRandom().nextBytes(out);",
	    "process.stdout.write(Buffer.from(out).toString('hex'));"
	].join('\n');

	var run1 = runChild(childCode);
	var run2 = runChild(childCode);

	assert.equal(run1.status, 0);
	assert.equal(run2.status, 0);
	assert.equal(run1.stdout.trim().length, 64);
	assert.equal(run2.stdout.trim().length, 64);
	assert.notEqual(run1.stdout.trim(), run2.stdout.trim());
    });
});
