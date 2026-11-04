// Generates dev/enroll/vectors-v2.json, the test vectors of
// dev/enroll-protocol.md (protocol v2), from fixed synthetic inputs: the key
// pairs, the session id, the nonces, the message plaintexts and the
// certificates' serials and FDSKs. Everything else (public keys, shared
// secrets, session keys, the session code, the AADs, the ciphertexts and the
// certificate texts and checks) is computed here.
//
//   node dev/enroll/regen-vectors.mjs          # rewrite vectors-v2.json
//   node dev/enroll/regen-vectors.mjs --check  # exit 1 if it is out of date
//
// Independent of web/enroll/enroll.js and the Rust code on purpose: the
// vectors check those two, so they must not be computed by them. Only
// node:crypto is used.

import {
  createCipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  pbkdf2Sync,
} from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const FILE = new URL("./vectors-v2.json", import.meta.url);
const LABEL = "bussard-enroll-v2";
const SESSION_CODE_LABEL = "bussard-enroll-v2 session code";
const SESSION_CODE_ITERATIONS = 1_000_000;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
// The hosted page is served by the relay Worker, on the relay's origin, so
// its link carries no `r`; a self-hosted page elsewhere names its relay.
const PAGE = "https://bussard-relay.tmbo.dev/enroll/";
const OTHER_PAGE = "https://page.example/enroll/";
const RELAY = "https://relay.example";

// ------------------------------------------------------------------ inputs

const BUSSARD_SECRET = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const PHONE_SECRET = "65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384";
const OTHER_PHONE_SECRET = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";
const SESSION_ID = "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7";

const CERTIFICATES = [
  { serial: "00FA01020304", fdsk: "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" },
  { serial: "0083A1B2C3D4", fdsk: "00000000000000000000000000000000" },
  { serial: "FFFFFFFFFFFF", fdsk: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" },
];

// ------------------------------------------------------------ certificates

function crc4(data) {
  let c = 0;
  for (const byte of data) {
    for (let bit = 7; bit >= 0; bit--) {
      const top = ((c >> 3) & 1) ^ ((byte >> bit) & 1);
      c = (c << 1) & 0xf;
      if (top) c ^= 0x3;
    }
  }
  return c;
}

function certificateText(serialHex, fdskHex) {
  const data = Buffer.from(serialHex + fdskHex, "hex");
  const check = crc4(data);
  let value = (BigInt("0x" + data.toString("hex")) << 4n) | BigInt(check);
  const chars = [];
  for (let i = 0; i < 36; i++) {
    chars.unshift(ALPHABET[Number(value & 31n)]);
    value >>= 5n;
  }
  const groups = [];
  for (let i = 0; i < 36; i += 6) groups.push(chars.slice(i, i + 6).join(""));
  return { text: groups.join("-"), check };
}

const valid = CERTIFICATES.map(({ serial, fdsk }) => {
  const { text, check } = certificateText(serial, fdsk);
  return { text, serial, fdsk, check };
});
const firstText = valid[0].text;
const first = firstText.replaceAll("-", "");
// The first certificate with its check flipped in the lowest bit.
const badCheck = first.slice(0, -1) + ALPHABET[ALPHABET.indexOf(first.at(-1)) ^ 1];

// ------------------------------------------------------------------ crypto

// PKCS#8 wrapper for a raw X25519 private key (RFC 8410).
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

function x25519(secretHex) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(secretHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  return { privateKey, publicRaw: Buffer.from(jwk.x, "base64url") };
}

function publicKeyOf(raw) {
  return createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

const bussard = x25519(BUSSARD_SECRET);
const phone = x25519(PHONE_SECRET);
const other = x25519(OTHER_PHONE_SECRET);
const sid = Buffer.from(SESSION_ID, "hex");
const sidText = sid.toString("base64url");

function sessionKey(phonePair) {
  const shared = diffieHellman({
    privateKey: phonePair.privateKey,
    publicKey: publicKeyOf(bussard.publicRaw),
  });
  const back = diffieHellman({
    privateKey: bussard.privateKey,
    publicKey: publicKeyOf(phonePair.publicRaw),
  });
  if (!shared.equals(back)) throw new Error("X25519 sides disagree");
  const info = Buffer.concat([Buffer.from(LABEL, "ascii"), bussard.publicRaw, phonePair.publicRaw]);
  const key = Buffer.from(hkdfSync("sha256", shared, sid, info, 32));
  return { shared, key };
}

const phoneSession = sessionKey(phone);
const otherSession = sessionKey(other);

const codeSalt = Buffer.concat([Buffer.from(SESSION_CODE_LABEL, "ascii"), sid]);
const codeHex = pbkdf2Sync(bussard.publicRaw, codeSalt, SESSION_CODE_ITERATIONS, 4, "sha256")
  .toString("hex")
  .toUpperCase();
const sessionCode = `${codeHex.slice(0, 4)}-${codeHex.slice(4)}`;

function aad(dir) {
  return `${LABEL}/${dir}/${sidText}`;
}

function message(direction, phonePair, key, nonceHex, plaintext) {
  const n = Buffer.from(nonceHex, "hex");
  const cipher = createCipheriv("aes-256-gcm", key, n);
  cipher.setAAD(Buffer.from(aad(direction), "ascii"));
  const c = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final(), cipher.getAuthTag()]);
  return {
    direction,
    aad: aad(direction),
    plaintext,
    envelope: {
      v: 2,
      pk: phonePair.publicRaw.toString("base64url"),
      n: n.toString("base64url"),
      c: c.toString("base64url"),
    },
  };
}

const json = JSON.stringify;
const key = phoneSession.key;
const result1 = {
  type: "result",
  id: 1,
  status: "stored",
  serial: "00FA01020304",
  ia: "1.1.20",
  name: "Test actuator",
};
// F7: an `invalid` result names no device.
const result2 = {
  type: "result",
  id: 2,
  status: "invalid",
  serial: "00FA01020304",
  message: "the label's check does not match; re-check the text (nothing was written)",
};

const vectors = {
  _comment:
    "Test vectors for dev/enroll-protocol.md (protocol v2). Synthetic keys only; never a real device's. Generated by dev/enroll/regen-vectors.mjs; node dev/enroll/regen-vectors.mjs --check verifies the file is current.",
  session: {
    bussard_secret: BUSSARD_SECRET,
    bussard_public: bussard.publicRaw.toString("base64url"),
    phone_secret: PHONE_SECRET,
    phone_public: phone.publicRaw.toString("base64url"),
    session_id: sidText,
    shared_secret: phoneSession.shared.toString("hex"),
    key: key.toString("hex"),
    session_code_salt: codeSalt.toString("hex"),
    session_code_iterations: SESSION_CODE_ITERATIONS,
    session_code: sessionCode,
    link: `${PAGE}#v=2&s=${sidText}&k=${bussard.publicRaw.toString("base64url")}`,
    link_other_relay: `${OTHER_PAGE}#v=2&s=${sidText}&k=${bussard.publicRaw.toString("base64url")}&r=${encodeURIComponent(RELAY)}`,
  },
  messages: [
    message("up", phone, key, "000102030405060708090a0b", json({ type: "hello" })),
    message("up", phone, key, "0c0d0e0f1011121314151617", json({ type: "certificate", id: 1, text: first })),
    message("down", phone, key, "32333435363738393a3b3c3d", json(result1)),
    message("up", phone, key, "18191a1b1c1d1e1f20212223", json({ type: "certificate", id: 2, text: badCheck })),
    message("down", phone, key, "3e3f40414243444546474849", json(result2)),
    message("up", phone, key, "2425262728292a2b2c2d2e2f", json({ type: "done" })),
    message("down", phone, key, "4a4b4c4d4e4f505152535455", json({ type: "closed", stored: 1, reason: "done" })),
  ],
  other_phone: {
    _comment:
      "A second phone in the same session. bussard derives its key, opens its hello, refuses it (one phone per session) and answers with refused.",
    phone_secret: OTHER_PHONE_SECRET,
    phone_public: other.publicRaw.toString("base64url"),
    shared_secret: otherSession.shared.toString("hex"),
    key: otherSession.key.toString("hex"),
    messages: [
      message("up", other, otherSession.key, "565758595a5b5c5d5e5f6061", json({ type: "hello" })),
      message("down", other, otherSession.key, "62636465666768696a6b6c6d", json({ type: "refused" })),
    ],
  },
  certificates: {
    valid,
    normalize: [{ input: firstText.toLowerCase().replaceAll("-", " - "), normalized: first }],
    bad_check: [badCheck],
    malformed: ["ABC", first + "A", first.slice(0, -1) + "!"],
  },
};

let original = "";
try {
  original = readFileSync(FILE, "utf8");
} catch {
  // First run: nothing to compare against.
}
const updated = JSON.stringify(vectors, null, 2) + "\n";
if (process.argv.includes("--check")) {
  if (updated !== original) {
    console.error("vectors-v2.json is out of date; run node dev/enroll/regen-vectors.mjs");
    process.exit(1);
  }
} else {
  writeFileSync(FILE, updated);
}
