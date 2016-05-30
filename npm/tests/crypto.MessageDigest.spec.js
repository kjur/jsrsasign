import test from "ava";
import * as KJUR from "../lib/jsrsasign.js";

test("md5 -- basic", (t) => {
  const hash = new KJUR.crypto.MessageDigest({ alg: "md5", prov: "cryptojs" });
  hash.updateString("test");
  const expected = "098f6bcd4621d373cade4e832627b4f6"; // md5("test")
  t.is(hash.digest(), expected);
});

test("md5 -- update twice", (t) => {
  const hash = new KJUR.crypto.MessageDigest({ alg: "md5", prov: "cryptojs" });
  hash.updateString("test");
  hash.updateString("test");
  const expected = "05a671c66aefea124cc08b76ea6d30bb"; // md5("testtest")
  t.is(hash.digest(), expected);
});

