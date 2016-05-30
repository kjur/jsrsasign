import test from "ava";
import { jws } from "../lib/jsrsasign";

test("JWS.parse HS256", (t) => {
  const {
    headerObj,
    payloadObj,
    headerPP,
    payloadPP,
    sigHex,
  } = jws.JWS.parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ");

  const expected = {
    headerObj: {
      alg: "HS256",
      typ: "JWT"
    },
    payloadObj: {
      sub: "1234567890",
      name: "John Doe",
      admin: true
    },
    sigHex: "4c9540f793ab33b13670169bdf444c1eb1c37047f18e861981e14e34587b1e04",
  };

  t.deepEqual(headerObj, expected.headerObj);
  t.deepEqual(payloadObj, expected.payloadObj);

  t.deepEqual(JSON.parse(headerPP), expected.headerObj);
  t.deepEqual(JSON.parse(payloadPP), expected.payloadObj);

  t.is(sigHex, expected.sigHex);
});

test("JWS.parse RS256", (t) => {
  const {
    headerObj,
    payloadObj,
    headerPP,
    payloadPP,
    sigHex,
  } = jws.JWS.parse("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE");

  const expected = {
    headerObj: {
      alg: "RS256",
      typ: "JWT"
    },
    payloadObj: {
      sub: "1234567890",
      name: "John Doe",
      admin: true
    },
    sigHex: "12437e0ceb27b2e46344ee81c577a69890e6dc76f1adb4735e095b3764b8b0e928a5d53822c0f14c8f233b5f56fc0e0af193c98a334b8ace0466c1de639e7d6b80c539de74fceaa01c6b84453a98672ba1b45dfdcb124f0235044b0c64d89e64ff8cccdcefafb5dd46872a3821ba8a292cba27d9939e26093de9e7e7e1c88ab1",
  };

  t.deepEqual(headerObj, expected.headerObj);
  t.deepEqual(payloadObj, expected.payloadObj);

  t.deepEqual(JSON.parse(headerPP), expected.headerObj);
  t.deepEqual(JSON.parse(payloadPP), expected.payloadObj);

  t.is(sigHex, expected.sigHex);
});

test("JWS.verify RS256", (t) => {
  const privateKey = `
    -----BEGIN RSA PRIVATE KEY-----
    MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUpa
    rCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1
    /xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGEl
    ESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1
    esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKw
    b4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf
    1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvB
    bzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLR
    i54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy+
    +GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw
    ==
    -----END RSA PRIVATE KEY-----  
  `;

  const publicKey = `
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1
    KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a0
    3GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
    -----END PUBLIC KEY-----  
  `;

  const token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE";
  const isValid = jws.JWS.verify(token, publicKey, ["RS256"]);
  t.true(isValid);
});

