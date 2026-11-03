# Certificate enrolment protocol (v1)

How a KNX Secure device certificate (the 36-character FDSK label) gets from a
phone camera into `bussard.keys` without passing through the chat, the MCP
client, the hosted page's server or the relay in readable form. Design and
decision: #201 ("Certificate entry"). Test vectors: `dev/enroll/vectors-v1.json`
(synthetic keys only). Every implementation (Rust session and local relay, the
web page, the hosted relay) checks itself against those vectors.

## Parties

| party | runs | sees |
|---|---|---|
| bussard | `bussard keys enroll`, or the MCP tool `knx_enroll_certificates` | plaintext, writes the key store |
| page | static HTML/JS at `https://bussard.tmbo.dev/enroll/` (or served by bussard on localhost) | plaintext, in the phone's browser only |
| relay | a mailbox service (hosted Worker, or bussard's in-process local relay) | ciphertext, session ids, timing |
| chat / MCP client | the link and the results | the link (public key only), serials, addresses; never a key |

## Flow

1. bussard generates a session: a 16-byte random session id `sid`, an X25519
   key pair `(b_sk, b_pk)` and a 32-byte random owner token. It creates the
   session on the relay (`PUT`, owner token as bearer).
2. bussard shows the link, as text and as a terminal QR code, and the
   fingerprint. Over MCP the tool returns the link and the fingerprint.
3. The phone opens the link. The page generates its own X25519 key pair
   `(p_sk, p_pk)` once per page load, derives the session key, shows the
   fingerprint, and opens the camera.
4. Each scanned or typed certificate is normalized and checked on the phone,
   then sent encrypted (`up`).
5. bussard long-polls `up`, decrypts, matches the serial against the model,
   stores the FDSK, and answers with a `result` (`down`, encrypted for that
   phone key). The page shows it per sticker.
6. The user ends the session on either side (`done` from the page, or
   bussard's own stop). bussard deletes the session on the relay. The relay
   also expires it 30 minutes after creation.

## Encoding

- All binary values in links, envelopes and JSON are base64url without padding.
- Link: `<page>#v=1&s=<sid>&k=<b_pk>&r=<relay base URL, percent-encoded>`.
  Everything after `#` stays in the browser; the page's server never sees it.
  `r` is omitted when the page and the relay share an origin (local mode).
- Fingerprint: the first 4 bytes of
  `SHA-256("bussard-enroll-v1 fingerprint" || b_pk)`, uppercase hex, as
  `XXXX-XXXX`. Both sides show it; a mismatch means the link was altered.

## Crypto

```
shared = X25519(p_sk, b_pk) = X25519(b_sk, p_pk)     reject all-zero
key    = HKDF-SHA256(salt = sid (16 raw bytes),
                     ikm  = shared,
                     info = "bussard-enroll-v1" || b_pk || p_pk,
                     L    = 32)
aad    = ASCII "bussard-enroll-v1/<dir>/<sid base64url>"   dir = up | down
c      = AES-256-GCM(key, nonce (12 random bytes), plaintext, aad)   tag appended
```

One key per (session, phone key). Several phones may join one session; each
has its own `p_pk` and key. Nonces are random per message.

Envelope (both directions, at most 4096 bytes serialized):

```json
{"v": 1, "pk": "<p_pk>", "n": "<nonce>", "c": "<ciphertext+tag>"}
```

`pk` is always the phone's key: it selects the key on bussard's side for `up`
and addresses the phone for `down`.

## Messages (plaintext, UTF-8 JSON)

Up (page to bussard):

| type | fields |
|---|---|
| `certificate` | `id` (page-local counter), `text` (36 normalized characters) |
| `done` | none: the user finished on the phone |

Down (bussard to page):

| type | fields |
|---|---|
| `result` | `id` (echoes the certificate), `status`, `serial` (12 hex digits), optional `ia`, `name`, `message` |
| `closed` | `stored` (count): bussard ended the session |

`status` is one of `stored` (matched to a device and saved), `unassigned`
(saved under its serial, no device in the model has it yet), `already_stored`
(the same FDSK is already in the store), `conflict` (the store holds a
different FDSK for this serial; nothing written), `invalid` (format or check
failed; the page should have caught it), `error` (`message` says why).

No down message ever carries an FDSK, a tool key or any other key.

## Relay API

JSON over HTTPS. CORS allows any origin on the phone-side endpoints
(`POST up`, `GET down`). Unknown or expired sessions answer `404`.

| method and path | auth | body / answer |
|---|---|---|
| `PUT /v1/sessions/{sid}` | owner | `{}` → `201`; `409` if it exists |
| `POST /v1/sessions/{sid}/up` | none | envelope → `202 {"seq": n}` |
| `GET /v1/sessions/{sid}/up?after=<seq>&wait=<s>` | owner | `{"messages": [{"seq": n, "body": envelope}], "closed": false}` |
| `POST /v1/sessions/{sid}/down` | owner | envelope → `202 {"seq": n}` |
| `GET /v1/sessions/{sid}/down?after=<seq>&wait=<s>` | none | same shape as `GET up` |
| `DELETE /v1/sessions/{sid}` | owner | `204`; later reads answer `{"messages": [], "closed": true}` until expiry |

- owner = `Authorization: Bearer <owner token>`; the relay stores
  SHA-256 of the token, set by the `PUT`.
- `wait` is a long poll, at most 25 seconds; `after` defaults to 0 and
  `seq` starts at 1 per direction.
- Limits: 30 minutes per session, 200 messages per direction, 4096 bytes per
  envelope, `429` beyond them. The relay keeps nothing after expiry.

Anyone who learns the link can post to `up`. That is accepted: they cannot
read anything, and a forged certificate fails the serial match, the check, or
the FDSK Sync that `--verify` runs on the bus.

## Certificate text

36 characters, RFC 4648 base32 (`A-Z`, `2-7`), printed as six groups of six
separated by dashes. Decoded as a 180-bit big-endian number: the upper 176
bits are the serial number (6 bytes) then the FDSK (16 bytes), the lower
4 bits a check.

Normalization, identical on the page and in bussard: drop whitespace and
`-`, uppercase, map `0` to `O`, `1` to `I` and `8` to `B` (base32 has none of
them), then require exactly 36 characters of the alphabet.

The check is CRC-4/ITU (x^4 + x + 1, reflected, init 0) over the 22 bytes in
the vectors. **Not yet confirmed on a real label** (#201): until it is, a
check mismatch is reported but the serial match and `--verify` decide.
Whether the label's QR code carries the same text is also unconfirmed; the
page extracts the first 36-character base32 run (dashes allowed) from a QR
payload.
