// Regenerates the certificate parts of vectors-v1.json from their serial and
// FDSK: each `valid` vector's text and check, the `normalize` and `bad_check`
// vectors derived from the first, and every `up` certificate message's
// plaintext and ciphertext (same session key and nonce, so only `c` changes).
//
//   node dev/enroll/regen-certificates.mjs          # rewrite in place
//   node dev/enroll/regen-certificates.mjs --check  # exit 1 if out of date
//
// Independent of web/enroll/enroll.js and the Rust codec on purpose: the
// vectors check those two, so they must not be computed by them. The check is
// plain CRC-4 (x^4 + x + 1, init 0, MSB first, not reflected, no final XOR),
// see dev/enroll-protocol.md "Certificate text".

import { createCipheriv } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const FILE = new URL("./vectors-v1.json", import.meta.url);
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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

function b64urlDecode(s) {
  return Buffer.from(s, "base64url");
}

const original = readFileSync(FILE, "utf8");
const v = JSON.parse(original);

for (const vec of v.certificates.valid) {
  const { text, check } = certificateText(vec.serial, vec.fdsk);
  vec.text = text;
  vec.check = check;
}
const first = v.certificates.valid[0].text;
const firstNormalized = first.replaceAll("-", "");
v.certificates.normalize = [
  { input: first.toLowerCase().replaceAll("-", " - "), normalized: firstNormalized },
];
// The first vector with its check flipped in the lowest bit.
const last = ALPHABET.indexOf(firstNormalized.at(-1)) ^ 1;
v.certificates.bad_check = [firstNormalized.slice(0, -1) + ALPHABET[last]];
v.certificates.malformed = [
  "ABC",
  firstNormalized + "A",
  firstNormalized.slice(0, -1) + "!",
];

const key = Buffer.from(v.session.key, "hex");
for (const m of v.messages) {
  const plain = JSON.parse(m.plaintext);
  if (m.direction !== "up" || plain.type !== "certificate") continue;
  m.plaintext = JSON.stringify({ type: "certificate", id: plain.id, text: firstNormalized });
  const cipher = createCipheriv("aes-256-gcm", key, b64urlDecode(m.envelope.n));
  cipher.setAAD(Buffer.from(m.aad, "ascii"));
  const c = Buffer.concat([cipher.update(m.plaintext, "utf8"), cipher.final(), cipher.getAuthTag()]);
  m.envelope.c = c.toString("base64url");
}

const updated = JSON.stringify(v, null, 2) + "\n";
if (process.argv.includes("--check")) {
  if (updated !== original) {
    console.error("vectors-v1.json is out of date; run node dev/enroll/regen-certificates.mjs");
    process.exit(1);
  }
} else {
  writeFileSync(FILE, updated);
}
