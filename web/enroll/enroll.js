// Protocol core of the certificate enrolment page (dev/enroll-protocol.md, v2).
//
// Pure functions over WebCrypto and bytes, with no DOM access, so the same
// module runs in the browser and under `node --test` (web/tests/), where it is
// checked against dev/enroll/vectors-v2.json.

/** Protocol version carried in the link (`v=`) and in every envelope. */
export const PROTOCOL_VERSION = 2;
/** Largest serialized envelope the relay accepts, in bytes. */
export const MAX_ENVELOPE_BYTES = 4096;
/** Length of a normalized certificate text. */
export const CERTIFICATE_LENGTH = 36;

const LABEL = "bussard-enroll-v2";
const SESSION_CODE_LABEL = "bussard-enroll-v2 session code";
/** PBKDF2 iterations of the session code (dev/enroll-protocol.md, "Session code"). */
export const SESSION_CODE_ITERATIONS = 1_000_000;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** An error with a stable `code` the page maps to a message. */
export class EnrollError extends Error {
  /**
   * @param {string} code machine-readable reason
   * @param {string} message human-readable detail
   */
  constructor(code, message) {
    super(message);
    this.name = "EnrollError";
    this.code = code;
  }
}

// ---------------------------------------------------------------- encoding

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/** UTF-8 bytes of a string. */
export function utf8(text) {
  return encoder.encode(text);
}

/** Concatenate byte arrays. */
export function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Lowercase hex of bytes. */
export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Bytes of a hex string (either case); throws on odd length or bad digits. */
export function fromHex(hex) {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new EnrollError("encoding", "not a hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

/** base64url without padding. */
export function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decode base64url without padding. Strict: rejects padding, the standard
 * alphabet's `+` and `/`, and lengths no encoder produces.
 */
export function b64urlDecode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new EnrollError("encoding", "not base64url");
  }
  const std = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std + "=".repeat((4 - (std.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (b64urlEncode(out) !== text) {
    throw new EnrollError("encoding", "not canonical base64url");
  }
  return out;
}

// -------------------------------------------------------------------- link

/**
 * Parse the link fragment (`#v=2&s=<sid>&k=<b_pk>&r=<relay>`).
 *
 * @param {string} hash `location.hash`, with or without the leading `#`, or a
 *   whole link
 * @param {string} pageOrigin the page's own origin, the relay when `r` is
 *   omitted (local mode)
 * @returns {{sid: Uint8Array, sidText: string, bussardPublic: Uint8Array,
 *   bussardPublicText: string, relay: string}}
 */
export function parseLink(hash, pageOrigin) {
  let fragment = hash ?? "";
  const at = fragment.indexOf("#");
  if (at >= 0) fragment = fragment.slice(at + 1);
  if (fragment === "") throw new EnrollError("link_missing", "the link has no session");
  const params = new URLSearchParams(fragment);
  const version = params.get("v");
  if (version !== String(PROTOCOL_VERSION)) {
    throw new EnrollError(
      "link_version",
      version === null ? "the link has no version" : `link version ${version} is not supported`,
    );
  }
  const sidText = params.get("s") ?? "";
  const keyText = params.get("k") ?? "";
  let sid;
  let bussardPublic;
  try {
    sid = b64urlDecode(sidText);
    bussardPublic = b64urlDecode(keyText);
  } catch {
    throw new EnrollError("link_invalid", "the session or key in the link is damaged");
  }
  if (sid.length !== 16) throw new EnrollError("link_invalid", "the session id is not 16 bytes");
  if (bussardPublic.length !== 32) throw new EnrollError("link_invalid", "the key is not 32 bytes");
  const relay = parseRelay(params.get("r"), pageOrigin);
  return { sid, sidText, bussardPublic, bussardPublicText: keyText, relay };
}

function parseRelay(raw, pageOrigin) {
  if (raw === null || raw === "") {
    if (!pageOrigin || pageOrigin === "null") {
      throw new EnrollError("link_invalid", "the link names no relay");
    }
    return pageOrigin.replace(/\/+$/, "");
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new EnrollError("link_invalid", "the relay address is not a URL");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new EnrollError("link_invalid", "the relay must use https");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new EnrollError("link_invalid", "the relay address carries extra parts");
  }
  return (url.origin + url.pathname).replace(/\/+$/, "");
}

/** Relay URL of a session endpoint, `dir` = `up` | `down`. */
export function relayUrl(relay, sidText, dir, query) {
  const base = `${relay}/v1/sessions/${sidText}/${dir}`;
  if (!query) return base;
  return `${base}?${new URLSearchParams(query).toString()}`;
}

// ------------------------------------------------------------- session code

/**
 * The session code (`fingerprint`), `XXXX-XXXX`: 4 bytes of
 * PBKDF2-HMAC-SHA256(b_pk, label || sid, 1 000 000 iterations), uppercase
 * hex. Slow on purpose (about a second on a phone); derive it once.
 */
export async function fingerprint(subtle, sid, bussardPublic) {
  const key = await subtle.importKey("raw", bussardPublic, "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(
    await subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: concatBytes(utf8(SESSION_CODE_LABEL), sid),
        iterations: SESSION_CODE_ITERATIONS,
      },
      key,
      32,
    ),
  );
  const hex = toHex(bits).toUpperCase();
  return `${hex.slice(0, 4)}-${hex.slice(4)}`;
}

// ------------------------------------------------------------------- crypto

/** A fresh X25519 key pair for this page load; returns the raw public key. */
export async function generatePhoneKey(subtle) {
  const pair = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const publicRaw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicRaw, publicText: b64urlEncode(publicRaw) };
}

/** X25519(p_sk, b_pk); rejects the all-zero result. */
export async function sharedSecret(subtle, phonePrivate, bussardPublic) {
  const peer = await subtle.importKey("raw", bussardPublic, { name: "X25519" }, false, []);
  let bits;
  try {
    bits = new Uint8Array(
      await subtle.deriveBits({ name: "X25519", public: peer }, phonePrivate, 256),
    );
  } catch {
    // Some engines refuse a small-order point themselves.
    throw new EnrollError("crypto", "the key in the link is not usable");
  }
  if (bits.every((b) => b === 0)) throw new EnrollError("crypto", "the key in the link is not usable");
  return bits;
}

/** HKDF-SHA256(salt = sid, ikm = shared, info = label || b_pk || p_pk, L = 32). */
export async function sessionKeyBytes(subtle, shared, sid, bussardPublic, phonePublic) {
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const info = concatBytes(utf8(LABEL), bussardPublic, phonePublic);
  return new Uint8Array(
    await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: sid, info }, ikm, 256),
  );
}

/**
 * The AES-256-GCM session key for one (session, phone key). The raw bytes do
 * not leave this function; the returned key is not extractable.
 */
export async function deriveSessionKey(subtle, phonePrivate, phonePublic, link) {
  const shared = await sharedSecret(subtle, phonePrivate, link.bussardPublic);
  const raw = await sessionKeyBytes(subtle, shared, link.sid, link.bussardPublic, phonePublic);
  const key = await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  raw.fill(0);
  shared.fill(0);
  return key;
}

/** `bussard-enroll-v2/<dir>/<sid base64url>`. */
export function aad(dir, sidText) {
  return `${LABEL}/${dir}/${sidText}`;
}

/**
 * Encrypt one plaintext message into an envelope.
 *
 * @param {Uint8Array} [nonce] 12 bytes; random when omitted (tests pass one)
 */
export async function seal(subtle, key, { dir, sidText, phonePublicText, plaintext, nonce }) {
  const n = nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(12));
  if (n.length !== 12) throw new EnrollError("crypto", "nonce must be 12 bytes");
  const c = new Uint8Array(
    await subtle.encrypt(
      { name: "AES-GCM", iv: n, additionalData: utf8(aad(dir, sidText)), tagLength: 128 },
      key,
      utf8(plaintext),
    ),
  );
  const envelope = { v: PROTOCOL_VERSION, pk: phonePublicText, n: b64urlEncode(n), c: b64urlEncode(c) };
  if (utf8(JSON.stringify(envelope)).length > MAX_ENVELOPE_BYTES) {
    throw new EnrollError("too_large", "message is larger than the relay accepts");
  }
  return envelope;
}

/** Decrypt an envelope; throws `EnrollError("crypto")` when it does not open. */
export async function open(subtle, key, { dir, sidText, envelope }) {
  if (!envelope || envelope.v !== PROTOCOL_VERSION) {
    throw new EnrollError("crypto", "unknown envelope version");
  }
  let plain;
  try {
    const n = b64urlDecode(envelope.n);
    const c = b64urlDecode(envelope.c);
    if (n.length !== 12) throw new Error("nonce");
    plain = await subtle.decrypt(
      { name: "AES-GCM", iv: n, additionalData: utf8(aad(dir, sidText)), tagLength: 128 },
      key,
      c,
    );
    return decoder.decode(plain);
  } catch {
    throw new EnrollError("crypto", "message does not decrypt");
  }
}

/** Plaintext of an `up` certificate message. */
export function certificateMessage(id, text) {
  return JSON.stringify({ type: "certificate", id, text });
}

/** Plaintext of the `up` done message. */
export function doneMessage() {
  return JSON.stringify({ type: "done" });
}

/** Plaintext of the `up` hello message (page open, and the keep-alive). */
export function helloMessage() {
  return JSON.stringify({ type: "hello" });
}

const STATUSES = new Set(["stored", "unassigned", "already_stored", "conflict", "invalid", "error"]);

/**
 * Parse a `down` plaintext into `{type: "result", ...}`,
 * `{type: "closed", stored, reason}` or `{type: "refused"}`; anything else
 * yields `null`.
 */
export function parseDown(plaintext) {
  let msg;
  try {
    msg = JSON.parse(plaintext);
  } catch {
    return null;
  }
  if (!msg || typeof msg !== "object") return null;
  if (msg.type === "result" && Number.isInteger(msg.id) && STATUSES.has(msg.status)) {
    const str = (v) => (typeof v === "string" ? v : undefined);
    return {
      type: "result",
      id: msg.id,
      status: msg.status,
      serial: str(msg.serial),
      ia: str(msg.ia),
      name: str(msg.name),
      message: str(msg.message),
    };
  }
  if (msg.type === "closed") {
    return {
      type: "closed",
      stored: Number.isInteger(msg.stored) ? msg.stored : 0,
      reason: typeof msg.reason === "string" ? msg.reason : undefined,
    };
  }
  if (msg.type === "refused") {
    return { type: "refused" };
  }
  return null;
}

// -------------------------------------------------------------- certificate

/**
 * Normalize typed or scanned certificate text: drop whitespace and `-`,
 * uppercase, map `0`→`O`, `1`→`I`, `8`→`B`. The result is not yet validated.
 */
export function normalizeCertificate(input) {
  return String(input)
    .replace(/[\s-]+/g, "")
    .toUpperCase()
    .replace(/0/g, "O")
    .replace(/1/g, "I")
    .replace(/8/g, "B");
}

/**
 * The certificate check: plain CRC-4, x^4 + x + 1 (0x3), init 0, MSB first
 * (not reflected), no final xor, direct (not augmented). Confirmed on real
 * labels (#201); not CRC-4/ITU, the reflected variant.
 */
export function crc4(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    for (let bit = 7; bit >= 0; bit--) {
      const top = ((crc >> 3) & 1) ^ ((byte >> bit) & 1);
      crc = (crc << 1) & 0x0f;
      if (top) crc ^= 0x3;
    }
  }
  return crc;
}

/**
 * Normalize and check a certificate.
 *
 * `status` is one of
 * - `empty`: nothing typed
 * - `incomplete`: fewer than 36 valid characters so far
 * - `malformed`: a character outside base32, or more than 36
 * - `bad_check`: decodes, but the 4-bit check does not match (not sent)
 * - `ok`: decodes and the check matches
 *
 * `serial` (12 uppercase hex digits) and `check` are set for `bad_check` and
 * `ok`. The FDSK is returned only as bytes, for the caller to drop.
 */
export function checkCertificate(input) {
  const normalized = normalizeCertificate(input);
  if (normalized.length === 0) return { status: "empty", normalized };
  for (let i = 0; i < normalized.length; i++) {
    if (!BASE32_ALPHABET.includes(normalized[i])) {
      return { status: "malformed", normalized, position: i, char: normalized[i] };
    }
  }
  if (normalized.length < CERTIFICATE_LENGTH) return { status: "incomplete", normalized };
  if (normalized.length > CERTIFICATE_LENGTH) return { status: "malformed", normalized };

  // 36 * 5 = 180 bits, big-endian: 22 bytes (176 bits) then a 4-bit check.
  const bytes = new Uint8Array(23);
  let acc = 0;
  let bits = 0;
  let at = 0;
  for (const ch of normalized) {
    acc = (acc << 5) | BASE32_ALPHABET.indexOf(ch);
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes[at++] = (acc >>> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  // 180 = 22 * 8 + 4: the last 4 bits remain in `acc`.
  const data = bytes.slice(0, 22);
  const check = acc & 0x0f;
  const expected = crc4(data);
  const serial = toHex(data.slice(0, 6)).toUpperCase();
  const fdsk = data.slice(6, 22);
  return {
    status: check === expected ? "ok" : "bad_check",
    normalized,
    serial,
    fdsk,
    check,
    expectedCheck: expected,
  };
}

/** Group a normalized certificate as six groups of six, dash-separated. */
export function formatCertificate(normalized) {
  return normalized.match(/.{1,6}/g)?.join("-") ?? "";
}

/**
 * The first 36-character base32 run (dashes between characters allowed) in a
 * QR payload, normalized, or `null`. A longer run does not count.
 */
export function extractFromQr(payload) {
  if (typeof payload !== "string") return null;
  const upper = payload.toUpperCase();
  const re = /(?<![A-Z2-7])(?<![A-Z2-7]-)[A-Z2-7](?:-?[A-Z2-7]){35}(?![A-Z2-7]|-[A-Z2-7])/;
  const m = re.exec(upper);
  return m ? m[0].replace(/-/g, "") : null;
}
