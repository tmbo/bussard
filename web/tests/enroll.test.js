// The enrolment page's protocol core against dev/enroll/vectors-v1.json.
// Run: node --test web/tests/

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  EnrollError,
  aad,
  b64urlDecode,
  b64urlEncode,
  certificateMessage,
  checkCertificate,
  concatBytes,
  crc4itu,
  deriveSessionKey,
  doneMessage,
  extractFromQr,
  fingerprint,
  formatCertificate,
  fromHex,
  generatePhoneKey,
  normalizeCertificate,
  open,
  parseDown,
  parseLink,
  relayUrl,
  seal,
  sessionKeyBytes,
  sharedSecret,
  toHex,
} from "../enroll/enroll.js";

const subtle = globalThis.crypto.subtle;
const vectors = JSON.parse(
  await readFile(new URL("../../dev/enroll/vectors-v1.json", import.meta.url), "utf8"),
);
const S = vectors.session;

// PKCS#8 wrapper for a raw X25519 private key (RFC 8410), so the vector's
// fixed secret can be imported; WebCrypto has no raw private-key import.
const X25519_PKCS8_PREFIX = fromHex("302e020100300506032b656e04220420");

async function importPrivate(hex) {
  return subtle.importKey(
    "pkcs8",
    concatBytes(X25519_PKCS8_PREFIX, fromHex(hex)),
    { name: "X25519" },
    true,
    ["deriveBits"],
  );
}

async function publicOf(privateKey) {
  const jwk = await subtle.exportKey("jwk", privateKey);
  return b64urlDecode(jwk.x);
}

async function vectorKey() {
  const link = parseLink(S.link, "https://bussard.tmbo.dev");
  const phonePrivate = await importPrivate(S.phone_secret);
  return {
    link,
    key: await deriveSessionKey(subtle, phonePrivate, b64urlDecode(S.phone_public), link),
  };
}

test("test_publicOf_matches_vector_keys", async () => {
  assert.equal(b64urlEncode(await publicOf(await importPrivate(S.bussard_secret))), S.bussard_public);
  assert.equal(b64urlEncode(await publicOf(await importPrivate(S.phone_secret))), S.phone_public);
});

test("test_parseLink_vector", () => {
  const link = parseLink(S.link, "https://bussard.tmbo.dev");
  assert.equal(link.sidText, S.session_id);
  assert.equal(link.sid.length, 16);
  assert.equal(b64urlEncode(link.bussardPublic), S.bussard_public);
  assert.equal(link.relay, "https://relay.example");
  assert.equal(
    relayUrl(link.relay, link.sidText, "down", { after: 3, wait: 25 }),
    `https://relay.example/v1/sessions/${S.session_id}/down?after=3&wait=25`,
  );
});

test("test_parseLink_hash_only_and_local_mode", () => {
  const hash = `#v=1&s=${S.session_id}&k=${S.bussard_public}`;
  assert.equal(parseLink(hash, "http://127.0.0.1:8123").relay, "http://127.0.0.1:8123");
  assert.equal(parseLink(hash.slice(1), "http://localhost:9").relay, "http://localhost:9");
});

test("test_parseLink_rejects", () => {
  const ok = `v=1&s=${S.session_id}&k=${S.bussard_public}`;
  const cases = [
    ["", "link_missing"],
    ["#", "link_missing"],
    [`v=2&s=${S.session_id}&k=${S.bussard_public}`, "link_version"],
    [`s=${S.session_id}&k=${S.bussard_public}`, "link_version"],
    [`v=1&k=${S.bussard_public}`, "link_invalid"],
    [`v=1&s=${S.session_id}`, "link_invalid"],
    [`v=1&s=${S.session_id}AA&k=${S.bussard_public}`, "link_invalid"],
    [`v=1&s=${S.session_id}&k=${S.bussard_public}=`, "link_invalid"],
    [`v=1&s=${S.session_id}&k=${S.bussard_public.slice(0, -2)}`, "link_invalid"],
    [`${ok}&r=http%3A%2F%2Frelay.example`, "link_invalid"],
    [`${ok}&r=not%20a%20url`, "link_invalid"],
    [`${ok}&r=https%3A%2F%2Frelay.example%2F%3Fx%3D1`, "link_invalid"],
  ];
  for (const [hash, code] of cases) {
    assert.throws(
      () => parseLink(hash, "https://bussard.tmbo.dev"),
      (e) => e instanceof EnrollError && e.code === code,
      `${JSON.stringify(hash)} should fail with ${code}`,
    );
  }
  assert.throws(() => parseLink(ok, "null"), (e) => e.code === "link_invalid");
});

test("test_fingerprint_vector", async () => {
  assert.equal(await fingerprint(subtle, b64urlDecode(S.bussard_public)), S.fingerprint);
});

test("test_sharedSecret_and_key_vector", async () => {
  const link = parseLink(S.link, "https://bussard.tmbo.dev");
  const phonePrivate = await importPrivate(S.phone_secret);
  const shared = await sharedSecret(subtle, phonePrivate, link.bussardPublic);
  assert.equal(toHex(shared), S.shared_secret);
  // The other side of the exchange gives the same secret.
  const bussardPrivate = await importPrivate(S.bussard_secret);
  assert.equal(
    toHex(await sharedSecret(subtle, bussardPrivate, b64urlDecode(S.phone_public))),
    S.shared_secret,
  );
  const key = await sessionKeyBytes(
    subtle,
    shared,
    link.sid,
    link.bussardPublic,
    b64urlDecode(S.phone_public),
  );
  assert.equal(toHex(key), S.key);
});

test("test_sharedSecret_rejects_all_zero", async () => {
  // u = 0 is a small-order point: X25519 yields all zeros.
  const phonePrivate = await importPrivate(S.phone_secret);
  await assert.rejects(
    sharedSecret(subtle, phonePrivate, new Uint8Array(32)),
    (e) => e instanceof EnrollError && e.code === "crypto",
  );
});

test("test_aad_vectors", () => {
  for (const m of vectors.messages) {
    assert.equal(aad(m.direction, S.session_id), m.aad);
  }
});

test("test_seal_reproduces_up_vectors", async () => {
  const { link, key } = await vectorKey();
  for (const m of vectors.messages.filter((m) => m.direction === "up")) {
    const envelope = await seal(subtle, key, {
      dir: "up",
      sidText: link.sidText,
      phonePublicText: S.phone_public,
      plaintext: m.plaintext,
      nonce: b64urlDecode(m.envelope.n),
    });
    assert.deepEqual(envelope, m.envelope);
  }
});

test("test_messages_serialize_as_vectors", () => {
  const [cert, , done] = vectors.messages;
  const text = JSON.parse(cert.plaintext).text;
  assert.equal(certificateMessage(1, text), cert.plaintext);
  assert.equal(doneMessage(), done.plaintext);
});

test("test_open_every_vector", async () => {
  const { link, key } = await vectorKey();
  for (const m of vectors.messages) {
    const plain = await open(subtle, key, { dir: m.direction, sidText: link.sidText, envelope: m.envelope });
    assert.equal(plain, m.plaintext);
  }
});

test("test_open_rejects_wrong_direction_and_tamper", async () => {
  const { link, key } = await vectorKey();
  const down = vectors.messages[1].envelope;
  await assert.rejects(
    open(subtle, key, { dir: "up", sidText: link.sidText, envelope: down }),
    (e) => e.code === "crypto",
  );
  const c = b64urlDecode(down.c);
  c[0] ^= 1;
  await assert.rejects(
    open(subtle, key, { dir: "down", sidText: link.sidText, envelope: { ...down, c: b64urlEncode(c) } }),
    (e) => e.code === "crypto",
  );
});

test("test_parseDown_vector_result", () => {
  assert.deepEqual(parseDown(vectors.messages[1].plaintext), {
    type: "result",
    id: 1,
    status: "stored",
    serial: "00FA01020304",
    ia: "1.1.20",
    name: "Test actuator",
    message: undefined,
  });
  assert.deepEqual(parseDown('{"type":"closed","stored":2}'), { type: "closed", stored: 2 });
  assert.equal(parseDown('{"type":"result","id":1,"status":"weird"}'), null);
  assert.equal(parseDown("nope"), null);
});

test("test_generatePhoneKey_roundtrip_with_bussard_side", async () => {
  const phone = await generatePhoneKey(subtle);
  assert.equal(phone.publicRaw.length, 32);
  const link = parseLink(S.link, "https://bussard.tmbo.dev");
  const key = await deriveSessionKey(subtle, phone.privateKey, phone.publicRaw, link);
  const envelope = await seal(subtle, key, {
    dir: "up",
    sidText: link.sidText,
    phonePublicText: phone.publicText,
    plaintext: doneMessage(),
  });
  // bussard's side: its secret with the phone's public key.
  const bussardPrivate = await importPrivate(S.bussard_secret);
  const shared = await sharedSecret(subtle, bussardPrivate, b64urlDecode(envelope.pk));
  const raw = await sessionKeyBytes(subtle, shared, link.sid, link.bussardPublic, phone.publicRaw);
  const bussardKey = await subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  assert.equal(
    await open(subtle, bussardKey, { dir: "up", sidText: link.sidText, envelope }),
    doneMessage(),
  );
});

test("test_checkCertificate_valid_vectors", () => {
  for (const v of vectors.certificates.valid) {
    const r = checkCertificate(v.text);
    assert.equal(r.status, "ok", v.text);
    assert.equal(r.serial, v.serial);
    assert.equal(toHex(r.fdsk).toUpperCase(), v.fdsk);
    assert.equal(r.check, v.check);
    assert.equal(r.expectedCheck, v.check);
    assert.equal(formatCertificate(r.normalized), v.text);
  }
});

test("test_crc4itu_over_vector_bytes", () => {
  for (const v of vectors.certificates.valid) {
    assert.equal(crc4itu(fromHex(v.serial + v.fdsk)), v.check);
  }
});

test("test_normalizeCertificate_vectors", () => {
  for (const v of vectors.certificates.normalize) {
    assert.equal(normalizeCertificate(v.input), v.normalized);
    assert.equal(checkCertificate(v.input).status, "ok");
  }
  // 0 -> O, 1 -> I, 8 -> B.
  assert.equal(normalizeCertificate("a0-1 8"), "AOIB");
});

test("test_checkCertificate_bad_check_vectors", () => {
  for (const text of vectors.certificates.bad_check) {
    const r = checkCertificate(text);
    assert.equal(r.status, "bad_check", text);
    assert.notEqual(r.check, r.expectedCheck);
  }
});

test("test_checkCertificate_malformed_vectors", () => {
  for (const text of vectors.certificates.malformed) {
    assert.ok(["malformed", "incomplete"].includes(checkCertificate(text).status), text);
  }
  assert.equal(checkCertificate("ABC").status, "incomplete");
  assert.equal(checkCertificate("AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2X!").status, "malformed");
  assert.equal(checkCertificate("AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2X5A").status, "malformed");
  assert.equal(checkCertificate("  ").status, "empty");
});

test("test_extractFromQr", () => {
  const text = vectors.certificates.valid[0].text;
  const plain = text.replace(/-/g, "");
  assert.equal(extractFromQr(text), plain);
  assert.equal(extractFromQr(plain), plain);
  assert.equal(extractFromQr(`KNX:${text};X`), plain);
  assert.equal(extractFromQr(`serial 00fa ${plain.toLowerCase()}\n`), plain);
  assert.equal(extractFromQr(`${plain}A`), null);
  assert.equal(extractFromQr("nothing here"), null);
});
