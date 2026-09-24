# KNX Secure specification (Data Secure + KNXnet/IP Secure)

> Implementation-grade spec for two independent implementers building in
> parallel from this document alone: (1) the bussard KNX Secure path
> (`bussard-project` keyring/FDSK ingest, `bussard-mgmt` Data Secure wrapping,
> `bussard-transport` IP Secure session), and (2) the knx-sim Secure device
> model. Both must converge on the same wire bytes. Grounded in
> `scratchpad/knx-secure-research.md` (clean-room, XKNX MIT + public spec + RFCs)
> and `scratchpad/knx-secure-corpus.md` (house/corpus/capture archaeology).
> Issue #71. Same discipline as `docs/system7-spec.md`.

## 0. Confidence discipline (read first)

Every byte-level claim below is tagged **CONFIRMED** (with source), **INFERRED**
(reasoned from an allowed source, residual risk noted), or **UNKNOWN** (needs a
live capture or the paid spec). Source shorthand: `[XKNX <file>]` (the MIT
`raw.githubusercontent.com/XKNX/xknx/main/xknx/...` files), `[ABB]` (the ABB
"KNX Secure Technical Details" V1.0 public overview), `[RFC 7748]` (X25519),
`[RFC 3610]`/`[SP 800-38C]` (CCM), `[corpus]` (bussard first-party evidence in
`knx-secure-corpus.md`), `[issue #71]`.

Rule for implementers: treat every UNKNOWN as "build the seam, pick the
best-evidence default, leave a calibration TODO tagged with the greppable marker
string `SEC-CAL:`". Do not hardcode an UNKNOWN as if it were CONFIRMED. There are
five load-bearing UNKNOWNs (all `SEC-CAL:`-tagged) that only a live ETS capture
settles - see §12 (test plan) and §13 (open questions). Until then, ship the
seam with the best-evidence default. The two Data Secure ones (Sync layout, MAC
length) are now settled by the secure-1-1-12 capture (2026-09-23), see §12.4;
the three IP Secure ones remain open.

The two research inputs disagree on exactly one point of substance: whether
Data Secure tool-access is *required* to flash the user's devices today. The
corpus proves it is NOT (§1.2); the research assumes it may be. This spec
resolves it by phasing (§1) - build the wrapper, keep plain the default, flip a
flag when a device is activated.

---

## 1. Scope, phasing, non-goals

### 1.1 The evidence that drives the phasing

From `knx-secure-corpus.md`, byte-scanned against the user's own house, corpus,
and captures:

- The house has **25 of 46 devices that are Data-Secure-capable** (per-app
  `IsSecureEnabled="true"`), and the gateway (Jung **IPS300SREG**, `1.1.200` /
  `1.1.201`) is Secure hardware. `[corpus §1]`
- **Security is NOT activated anywhere.** The decrypted `home_test.knxproj`
  carries 25 `<DeviceCertificate FDSK=…>` entries and 25 `<Security
  SequenceNumber SequenceNumberTimestamp>` elements, but NO `ToolKey`,
  `DeviceAuthenticationCode`, or `ManagementPassword`; `IPRoutingBackboneKey` is
  empty. ETS merely tracks Data-Secure sequence numbers and holds factory FDSKs.
  `[corpus §1, §4]`
- Every capture is **plaintext tunnelling** (UDP and TCP). A byte-scan of all 15
  pcapngs for service types `0x0950`-`0x0955` found **zero** frames - the gateway
  runs plain today. `[corpus §2]`
- `A_SecureData` (APCI `0x03F1`) appears in 6 captures as an **optional preamble**
  (a Sync_Req/Sync_Res + a few tool-access reads ETS does before every download),
  after which the **entire download proceeds plain**. Nine captures flash with no
  `0x3F1` at all. It is not a gate today. `[corpus §2]`
- Secure and plain devices have **byte-identical load procedures**; there is no
  secured-only load op. Flashing a secure-capable-but-unactivated device is
  identical to the plain case. `[corpus §3]`

### 1.2 Phase A (v1): KNX Data Secure, tool-access, for management

**Rationale.** The moment ETS (or the user) activates security on any of the 25
devices, *all* management access to that device goes behind `0x3F1` tool-access
and the entire current flash engine is locked out. The hardware ready to flip
that switch is the majority of the Jung installation. Load procedures are
structurally identical to plain, so this is a **management-layer wrapper, not a
new download engine** - a thin seam over the existing `bussard-mgmt`/`bussard-
download` path.

Phase A delivers:

1. **Importer stops dropping secure material** (`bussard-ets` / `bussard-prod`):
   preserve `IsSecureEnabled` and `MaxSecurity*` sizing attrs (currently
   dropped, zero references in any crate `[corpus §1]`); surface FDSK-certificate
   presence and `<Security>` seqnum state from the knxproj import. **Flags and
   structure only in committed YAML** - key values must NEVER touch `knx/` (a
   reviewable, committed tree). See §2 and §11.
2. **`.knxkeys` keyring parsing** (`bussard-project`, next to `password.rs`):
   fully decoded in research §keyring (§2, §3). Produces a typed `Keyring`.
3. **The A_SecureData ASDU** (`bussard-mgmt`): SCF layout, 6-byte sequence
   (ms since 2018-01-05), CCM-via-CBC-MAC+CTR, 4-byte MAC (§5).
4. **Tool-key derivation** (from the keyring `ToolKey`; FDSK is the factory tool
   key before commissioning) (§2).
5. **The sync preamble** (`S-A_Sync_Req`/`S-A_Sync_Res`): ETS runs it before
   the first S-A_Data of every secured connection, and so does bussard (§6.3).
6. **Plain-inside-secure coexistence rules** (§6.4): a device that is not
   security-activated stays plain; a wrapper is applied only per-device when the
   keyring/knxproj says the device is activated.

### 1.3 Phase B: KNXnet/IP Secure session layer

Fully specified here (§7-§9) because the research is byte-precise, but gated
separately: it is only needed to talk to a **secure-only** IP interface. The
user's gateway runs plain today, so Phase B is deferred behind its own gate
("talk to a secure-only interface"). Ship Phase A first.

Phase B delivers the session layer: `SESSION_REQUEST`/`_RESPONSE`/`_AUTHENTICATE`/
`_STATUS` (`0x0951`-`0x0954`), X25519 ECDH → session key, `SecureWrapper`
(`0x0950`), the monotonic sequence counter, replay/timeout handling, and the
`SEARCH_RESPONSE_EXTENDED` Secure DIB parser needed to *detect* a secure-only
gateway.

### 1.4 Non-goals (refuse cleanly, name the reason)

- **Secure ROUTING (multicast)**: backbone-key wrapper + `TIMER_NOTIFY`
  (`0x0955`). Specified in outline (§9.3) for completeness but deferred to a
  later phase (B2). bussard talks unicast tunnelling. `[issue #71]`
- **Commissioning a factory-fresh device from a scanned QR label**: the FDSK
  QR/label string encoding is UNKNOWN (§4.4) and unneeded - FDSK comes from the
  knxproj `<DeviceCertificate>` or a `.knxkeys` export, not a phone camera.
  `[corpus §4, research §2.6]`
- **Point-to-point connection-oriented secure** (secure T_CONNECT): unsupported
  in XKNX and out of scope; secure management is tool-access secure APDUs, not
  secure T_CONNECT. `[research §3.7]`

---

## 2. Key material model

### 2.1 The four key sources

| Key | Role | Source (Phase A) | Source (Phase B) |
|---|---|---|---|
| **FDSK** (Factory Default Setup Key) | 128-bit per-device factory key; is the tool key until IA is written | knxproj `<DeviceCertificate FDSK=…>` (25 present) `[corpus §1]` | n/a |
| **Tool key** | per-device management key after commissioning; replaces FDSK | keyring `Device/@ToolKey` (base64→16 raw) `[XKNX keyring.py]` | n/a |
| **Group key** | per-GA runtime encryption key for group comms | keyring top-level `GroupAddresses/GroupAddress/@Key` | n/a |
| **Backbone key** | multicast/routing key | keyring `Backbone/@Key` | routing only |
| **Device authentication code** | proves gateway identity in the IP handshake | keyring `Interface/@Authentication` (decrypted password → PBKDF2) | §7.4 |
| **User password** | authenticates a tunnel/mgmt user in the IP handshake | keyring `Interface/@Password` (decrypted → PBKDF2) | §7.5 |

**FDSK vs tool key lifecycle** `[research §2.6, ABB]`: FDSK is unique per device,
printed on a removable label and carried in the knxproj device certificate.
During first secure commissioning ETS uses the FDSK as the tool key, writes the
individual address (which **invalidates the FDSK**), then writes an ETS-generated
tool key that replaces it. From then on secure management uses the tool key.
bussard's Phase A treats "the device's tool key" as: keyring `ToolKey` if present,
else the FDSK from the certificate (a device not yet commissioned). It does NOT
perform the FDSK→tool-key rotation itself in v1 (that is ETS's job); it consumes
whichever key the project provides.

### 2.2 Where bussard stores key material

- **In memory only, for the duration of a run.** Keys are loaded from the
  `.knxkeys` file or the decrypted knxproj into a `Keyring` struct held by the
  session, never written to `knx/` and never to any other file.
- The keyring/knxproj **password** arrives the same way the project password
  already does: an env var (`BUSSARD_KEYRING_PASSWORD`, mirroring
  `BUSSARD_PROJECT_PASSWORD` `[corpus §4]`), never a CLI arg, never a config file.
- The committed YAML model (`knx/`) records **only flags**: `secure: true` on a
  device/app (from `IsSecureEnabled`), the `MaxSecurity*` sizing, and a boolean
  "has FDSK certificate" + the `<Security>` seqnum state. NEVER the FDSK, tool
  key, group key, or any password. See §11.

### 2.3 Key hygiene (mandatory)

- **Never print, log, or `Debug`-format a key.** Every key-bearing type MUST have
  a hand-written `Debug`/`Display` that redacts (e.g. `ToolKey(<redacted>)`).
  Derive `Debug` is FORBIDDEN on any struct holding raw key bytes.
- **Never serialize a key.** No `Serialize`/`Deserialize` on key types; the YAML
  model carries flags, not bytes (§2.2).
- **Zeroize where practical.** Wrap raw 16-byte keys in a type whose `Drop`
  zeroes the buffer (the `zeroize` crate, MIT/Apache - a candidate direct dep, or
  a hand-written `Drop` that overwrites with `0` under a `// SAFETY:`-free safe
  loop). At minimum, do not `clone()` keys casually; pass by reference.
- **Never commit anything derived from the user's real knxproj.** No test
  fixture, golden vector, or capture-derived byte may embed a real FDSK, tool
  key, group key, or password. Fixtures are synthetic (§12.3). This is a hard
  rule, on par with the license policy.
- The wire tracer (`bussard-transport/src/wire_trace.rs`) must redact secure
  payloads the same way it must never dump a key: trace the SCF and sequence, not
  the plaintext under a decrypted MAC+enc frame, unless a debug build explicitly
  opts in.

---

## 3. Crypto primitives (the decomposed CCM)

**KEY INSIGHT** `[research §KEY INSIGHT, XKNX util.py + security_primitives.py]`:
KNX Secure's AES-CCM is implemented (and MUST be reimplemented) as **AES-CBC-MAC**
(to make the tag) plus **AES-CTR** (to encrypt the payload and the tag), NOT via a
CCM library. This is exactly what CCM is under the hood `[RFC 3610, SP 800-38C]`.
Consequence: bussard needs `aes` + `cbc` + `ctr` and NO `ccm` crate, staying on
the RustCrypto cipher-0.4 generation already in tree (§10).

### 3.1 Building blocks `[XKNX util.py, CONFIRMED]`

```
bytes_xor(a, b)              # equal-length big-endian XOR
byte_pad(data, 16)          # ZERO-pad (0x00) to a multiple of 16. This is CBC-MAC
                            # formatting padding, NOT PKCS7. (The keyring code uses
                            # real PKCS7 separately - do not confuse them.)
sha256(data)
```

### 3.2 CBC-MAC (the tag) `[XKNX util.py, CONFIRMED]`

```
calculate_message_authentication_code_cbc(key, additional_data, payload=b"", block_0=16*0x00):
    buf = block_0
        + len(additional_data).to_bytes(2, "big")   # 2-byte AD length prefix
        + additional_data
        + payload
    buf = byte_pad(buf, 16)                           # zero-pad to 16
    ct  = AES_CBC_encrypt(key, iv=16*0x00, buf)       # AES-CBC, ZERO IV
    return ct[-16:]                                   # the CBC-MAC = last cipher block
```

### 3.3 CTR (encrypt tag + payload) `[XKNX util.py; CONFIRMED against ETS, secure-1-1-12 capture, 2026-09-23]`

```
encrypt_data_ctr(key, counter_0, mac, payload=b""):
    stream = AES_CTR(key, iv=counter_0)               # ONE continuous keystream
    encrypted_mac     = mac     XOR stream[0 : len(mac)]
    encrypted_payload = payload XOR stream[len(mac) : len(mac)+len(payload)]
    return (encrypted_payload, encrypted_mac)

decrypt_ctr(key, counter_0, mac, payload=b""):        # identical (CTR is symmetric)
```

The keystream is a single stream over `mac || payload`, and the MAC handed to
it is already truncated to its wire length. For Data Secure that is 4 bytes, so
the payload starts at **byte 4 of the first keystream block**, not at
`counter_0 + 1`. XKNX gets this for free because it truncates `mac_cbc[:4]`
before calling a streaming CTR encryptor. bussard's first implementation encrypted
the full 16-byte MAC first and started the payload at the second block: MACs
matched but the payload did not, and 0 of 210 ETS/device frames verified. With
the continuous stream all 210 verify (secure-1-1-12 capture, 2026-09-23). For IP
Secure the MAC is 16 bytes, so the payload starts at the second block and the
same rule holds. On the wire the transmitted MAC is the **encrypted** MAC.
Verification = recompute `mac_cbc`, CTR-encrypt it with `counter_0`, compare
constant-time against the received encrypted MAC (or decrypt the received MAC and
compare to the recomputed `mac_cbc`). Use a constant-time compare.

### 3.4 PBKDF2 parameter table `[XKNX security_primitives.py, CONFIRMED]`

All derivations are **PBKDF2-HMAC-SHA256, 65536 iterations, 16-byte output**.
Password input encoding differs: the IP-handshake passwords use **Latin-1**; the
existing ETS6 project password uses **UTF-16-LE** (already in `password.rs`).
Salts:

| Derived key | Salt (ASCII bytes) | Input encoding |
|---|---|---|
| device authentication code | `device-authentication-code.1.secure.ip.knx.org` | Latin-1 |
| user password | `user-password.1.secure.ip.knx.org` | Latin-1 |
| keyring password key | `1.keyring.ets.knx.org` | Latin-1 |
| `.knxproj` inner-zip password (ETS6, existing) | `21.project.ets.knx.org` | UTF-16-LE |

`password.rs::derive_zip_password` is the working template for the last row
(65536 iters, base64 out). The Secure derivations differ only in salt, output
handling (raw 16 bytes, not base64), and input encoding (Latin-1). Reuse the
`pbkdf2_hmac::<Sha256>` shape. `[research §1.6, §2.1]`

### 3.5 Worked example (for the unit vectors, §12.1)

Because the research captured no numeric XKNX test vectors, the implementers MUST
derive a shared set of worked vectors from these primitives and commit them as
synthetic fixtures. Recommended minimal set:

- A CBC-MAC over `additional_data = [0x11]`, `payload = b""`, `key = 16×0x00`,
  `block_0 = 16×0x00` → a fixed 16-byte tag both sides assert.
- A full A_SecureData round-trip (§5.7 worked example) with an all-zero tool key
  and a fixed sequence number.
- A `SecureWrapper` round-trip (§8.4) with a fixed session key.

Both implementers compute these independently from §3.1-§3.3 and diff. A mismatch
is the first signal one side's CCM decomposition diverged.

---

## 4. Keyring (`.knxkeys`) - byte-exact `[XKNX keyring.py; signature CONFIRMED against an ETS 6 export, #84]`

The layout comes from the public XKNX reference plus synthetic fixtures. The
signature scheme (§4.4) was confirmed against a genuine ETS 6 export of a project
with no Secure devices (root element only, so it isolates the root framing). That
file and its password stay outside the repo; the unit tests use synthetic
fixtures generated by an independent implementation of this section (§12.3).
The FDSK/seqnum material bussard needs for v1 already lives in the knxproj (§2.1),
so keyring parsing is the second credential source, not the only one.

### 4.1 Keyring password → key

`PBKDF2-HMAC-SHA256(password, salt=b"1.keyring.ets.knx.org", iter=65536,
dklen=16)` (§3.4). bussard feeds the password as Latin-1; ASCII passwords are
confirmed, non-ASCII encoding (Latin-1 vs UTF-8) is unverified.

### 4.2 Attribute decryption

- **AES-128-CBC**, key = the derived keyring key.
- **IV** = `sha256(created_timestamp_string.encode("utf-8"))[:16]`, where
  `created` is the keyring's `Created` attribute (ISO timestamp string).
- Encrypted attribute values are **base64** in the XML: decode → AES-CBC-decrypt.

### 4.3 Encrypted keys and passwords

Two kinds of encrypted attribute:

- **Keys** (`Device/@ToolKey`, `Backbone/@Key`, `GroupAddresses/Group/@Key`):
  base64 of exactly one 16-byte AES-CBC block. The decrypted block is the raw
  key; no prefix, no padding.
- **Passwords** (`Interface/@Password`, `Interface/@Authentication`,
  `Device/@ManagementPassword`, `Device/@Authentication`): the decrypted blob is
  an 8-byte prefix, the UTF-8 password, and PKCS#7 padding.
  `extract_password(data) = data[8:-data[-1]]`; bussard validates the padding
  (1..=16 bytes, all equal) so a wrong key surfaces as an error, not a garbage
  password.

### 4.4 Signature verify `[CONFIRMED against a real ETS 6 export, #84]`

The signature is `sha256(canonical)[:16]`, compared against
`base64_decode(@Signature)` on the root. The canonical byte string is built by a
document-order walk. Every *string* is framed as one length byte followed by its
UTF-8 bytes (strings over 255 bytes are rejected):

1. Element start: byte `0x01`, then the element name as a string, then for each
   attribute except `xmlns`, `xmlns:*` and `Signature`, **sorted by attribute
   name (ordinal)**: the name as a string, then the unescaped value as a string.
2. Element end: byte `0x02`. A self-closing element is a start plus an end.
3. After the walk: the base64 text of the 16-byte PBKDF2 keyring key (§4.1),
   framed as a string.

Text content, comments and the XML declaration are not signed. Because the key
is part of the hashed input, a well-formed file that fails the check means a
wrong password (or an edit after export); bussard reports it as "wrong keyring
password", while malformed XML and missing attributes are parse errors reported
before the check.

Worked layout for an empty keyring
`<Keyring Project="P" CreatedBy="C" Created="T" Signature=".." xmlns=".."/>`:
`01 07"Keyring" 07"Created" len(T)T 09"CreatedBy" len(C)C 07"Project" len(P)P 02
18<base64 of key>` (the base64 of 16 bytes is 24 = `0x18` characters).

What was wrong before #84: the serialization had no element names, no length
prefixes, unsorted attributes and an unframed key, and key attributes were read
as raw base64 instead of being decrypted.

### 4.5 Contents (element/attribute names) `[XKNX keyring.py, CONFIRMED]`

- **Backbone**: `Key` (encrypted key, multicast key), `MulticastAddress`,
  `Latency` (ms).
- **Interface** (tunnel/USB/backbone): `Type`, `IndividualAddress`, `Host`,
  `UserID`, `Password` (encrypted user password), `Authentication` (encrypted
  device auth password); both are absent on a USB interface. Child `Group`
  elements (`Address`, `Senders`) name the GAs the interface may send to.
- **GroupAddresses**: child `Group` elements with `Address` (raw 16-bit integer,
  e.g. `2563` = 1/2/3) and `Key` (encrypted group key).
- **Devices**: child `Device` elements with `IndividualAddress`, `ToolKey`
  (encrypted key), `ManagementPassword` (encrypted), `Authentication`
  (encrypted), `SequenceNumber` (int, default 0).

### 4.6 The typed result

```
Keyring {
    project: String,
    created: String,
    backbone: Option<Backbone { key: Key16, multicast: Ipv4Addr, latency_ms: u16 }>,
    interfaces: Vec<Interface { ia, host, user_id, user_key: Option<Key16>, device_auth: Option<Key16>, gas: [...] }>,
    devices: Vec<Device { ia, tool_key: Key16, seq: u48 }>,
    group_keys: HashMap<GroupAddress, Key16>,
}
```

`Key16` is the zeroizing, non-`Debug`, non-`Serialize` key wrapper (§2.3).

---

## 5. KNX Data Secure - wire format byte-exact

Source: `[XKNX data_secure_asdu.py, data_secure.py, CONFIRMED]`. This is the
Phase A hot path.

### 5.1 The service (APCI `0x03F1`)

`A_SecureData` / `S-A_Data`. `_APCI_SEC_HIGH = 0x03`, `_APCI_SEC_LOW = 0xF1` -
confirms the `0x3F1` seen in the house captures `[corpus §2]`. Standard extended
APCI (6-bit high field 0x03F… family).

### 5.2 Security Control Field (SCF) - one byte

| Bit(s) | Field | Meaning |
|---|---|---|
| 7 | `tool_access` | 1 = tool/management access (uses tool key) |
| 6-4 | `algorithm` (SecurityAlgorithmIdentifier) | `000` = CCM auth-only (MAC), `001` = CCM auth+encrypt |
| 3 | `system_broadcast` | 1 = system broadcast |
| 2-0 | `service` (SecurityALService) | S-A_Data service selector |

Serialize: `scf = (tool_access<<7) | (algorithm<<4) | (system_broadcast<<3) |
service`. Service selector values observed in captures `[corpus §2]`: SCF `0x90`
(tool-access secure **data**), `0x92` (tool-access **Sync_Req**), `0x93`
(**Sync_Res**). So `service` low bits: data = `0`, Sync_Req = `2`, Sync_Res = `3`
(`0x90 = 1001_0000`, `0x92 = 1001_0010`, `0x93 = 1001_0011`). `[CONFIRMED:
secure-1-1-12 capture, 2026-09-23, by decrypting the frames; each selector's
frames carry exactly the layout of §5.3 / §6.3]`. The `system_broadcast` bit is
clear on every frame in that capture, including the Sync_Req ETS sends to the
broadcast address `0/0/0`.

### 5.3 ASDU layout

After the SCF byte:

```
SCF(1) + sequence_number(6) + secured_apdu(variable) + MAC(4)
```

`len(SecureData) = 10 + len(secured_apdu)` (10 = 6-byte seq + 4-byte MAC). The
Data-Secure MAC for TP is **4 bytes**, truncated `mac[:4]`. `[research §3.3;
CONFIRMED on the tunnel management path, secure-1-1-12 capture, 2026-09-23]`.
The Sync services reuse this frame with a different body, see §6.3.

### 5.4 CCM nonce (block_0) for TP frames `[XKNX data_secure_asdu.py, CONFIRMED]`

```
block_0 = sequence_number(6)
        + address_fields_raw        # source_IA(2) + destination(2) = 4 bytes
        + [ 0x00,
            address_type | frame_format,   # Ctrl2-derived, form 'A000EEEE'
                                           #   A = address type bit, EEEE = ext frame format
            (tpci_int << 2) + 0x03,        # TPCI high bits + APCI-high 0x03
            0xF1,                          # APCI low
            0x00,
            payload_length ]               # 6 more bytes → 16 total
```

"Only Ctrl2 is protected, and only as `A000EEEEb`" (verbatim XKNX comment).

### 5.5 CCM counter_0 for TP frames `[XKNX, CONFIRMED]`

```
counter_0 = sequence_number(6) + address_fields_raw(4) + [0x00,0x00,0x00,0x00,0x01,0x00]
```

### 5.6 MAC-only vs MAC+encryption `[XKNX, CONFIRMED]`

- **CCM_AUTHENTICATION (`algorithm=0b000`)**: `additional_data = SCF(1) + apdu`;
  compute CBC-MAC (§3.2) with `block_0` from §5.4; the APDU is transmitted **in
  the clear** (`secured_apdu = apdu`), the 4-byte MAC appended after CTR.
- **CCM_ENCRYPTION (`algorithm=0b001`)**: `additional_data = SCF(1)` only;
  `payload = apdu`; CBC-MAC then `encrypt_data_ctr` (§3.3) encrypts BOTH the APDU
  and the MAC. `secured_apdu` = the encrypted APDU, MAC = the encrypted 4-byte
  tag. The CBC-MAC is truncated to 4 bytes before the CTR stage, so the APDU's
  keystream starts at byte 4 (§3.3).

### 5.7 Key selection

- **Tool access / management** (`tool_access=1`, individual-addressed): the target
  **device's tool key** (keyring `ToolKey`, else FDSK - §2.1). **This is the path
  bussard needs for secure management/flashing.** XKNX's *runtime* `data_secure.py`
  RAISES on `tool_access` (it only does group comms), so the send/verify path is
  built from the ASDU primitives (which support it) + the keyring ToolKey.
  `[research §3.7, CONFIRMED that XKNX ASDU supports it, runtime does not]`.
- **Group communication** (`tool_access=0`): key looked up by **destination group
  address** in the group-key table (keyring per-GA `Key`). Freshness: the received
  6-byte sequence must be strictly greater than the last seen for that source IA;
  update the per-source table only after a successful decrypt. Group comms is not
  on the Phase A flash hot path but the sim should model it for completeness.

### 5.7.1 Group communication (issue #172)

Implemented in `bussard-secure::group`, used by `monitor`, `capture`, `read`
and `write --keyring` (and MCP, viz), and modelled by the knx-sim Secure device.

| Element | Value | Status |
|---|---|---|
| Carrier | `T_Data_Group` (TPCI octet `0x00`) to the GA, APCI `0x03F1` | CONFIRMED for a group-addressed A_SecureData frame (the broadcast S-A_Sync to `0/0/0`, secure-1-1-12 capture) |
| B0 / Ctr0 addressing | `source(2) ‖ GA(2)`, Ctrl2 octet `0x80` (address-type bit set, standard frame), B0[12] = `0x03` | CONFIRMED: the capture's two group-addressed secured frames (S-A_Sync_Req and S-A_Sync_Res to `0/0/0`) verify through this exact path (`TpAddressing::group`, oracle test `test_group_addressed_capture_frames_verify`, 2026-09-24) |
| SCF | tool_access 0, system_broadcast 0, S-A_Data: `0x10` auth+encryption (bussard sends this), `0x00` auth only (accepted) | CONFIRMED (live, 2026-09-24): a real device (Jung F50 module, 1.1.12) sent a secured GroupValueWrite with SCF `0x10` on its secured GA; `bussard monitor --keyring` verified the MAC and decrypted it |
| Key | the group key of the destination GA (keyring `GroupAddresses/Group@Key`) | CONFIRMED (live, 2026-09-24): the frame verified under the keyring's key of the destination GA (`0/3/47`) |
| Inner APDU | the plain group APDU with TPCI bits zero: `00 00` GroupValueRead, `00 8v` small write, `00 40 …` large response | CONFIRMED (live, 2026-09-24) for the small/large GroupValueWrite form: the decrypted APDU decoded as a DPT 9.001 write of 22.12 °C |
| Sender sequence | ms since 2018-01-05, strictly above the last sent by the process (`SequenceHighWater`) | CONFIRMED rule (§5.8) |
| Receiver freshness | per sender IA; bussard's monitor only *warns* on a non-increasing sequence, it never drops | design choice |
| Sender admission | a device accepts a secured group telegram only from an IA in its security individual address table (PID 54) | INFERRED (ETS behaviour); the sim does not enforce it |

Known-answer vector (synthetic; bussard `group::tests` and knx-sim
`GROUP_KAT_ASDU` agree, and so does `tools/knxtrace/datasecure.py`): key
`000102…0F`, sequence 42, 1.1.1 → 1/2/3, inner `00 81`:

```
SCF 0x10: 10 000000 00002a df59 49899fd3
SCF 0x00: 00 000000 00002a 0081 2e51ca4a
```

The SCF, key and inner-APDU rows were promoted on 2026-09-24 from a live
`monitor --keyring` of the reference installation (one secured GroupValueWrite
from 1.1.12 on 0/3/47, MAC ok). Still to observe: a secured GroupValueRead and
its response on the wire, and the sender-admission behaviour (PID 54).

### 5.8 Sequence number = time since epoch `[XKNX, CONFIRMED]`

Sending sequence initialized to `int((now - epoch) * 1000)` where
`epoch = 2018-01-05T00:00:00Z` - **milliseconds since 2018-01-05 UTC** - then
`+1` per send. 48-bit (max `0xFFFFFFFFFFFF`). "The sequence need not increment by
exactly one; any higher value is acceptable" `[ABB]`. This is why ETS shows
per-device sequence numbers and why a device reset needs an ETS seqnum update.

### 5.9 Sequence persistence

- **Send side (per device):** persist the last-sent tool sequence per device so a
  new bussard run does not replay an old, lower value (which the device would
  reject as stale). Seed from the knxproj `<Security SequenceNumber>` if present,
  else from the epoch clock (§5.8). Store in a bussard state file (NOT in `knx/`;
  it is machine state, not model), keyed by device IA. The Sync exchange (§6.3)
  makes the seed self-correcting: the device's S-A_Sync_Res carries the sequence
  it accepts next from the tool, and the tool continues from
  `max(own seed, that value)`. ETS runs Sync on every secured connection
  `[CONFIRMED, secure-1-1-12 capture, 2026-09-23]`, and bussard now does too.
  Whether a device refuses S-A_Data that is not preceded by a Sync cannot be
  seen in a capture where ETS always syncs; it no longer matters for bussard.
- **Receive side (per source IA):** track last-seen sequence; refuse a received
  frame whose sequence is not strictly greater (replay protection). Update only
  after a successful MAC verify.

---

## 6. Tool-access management flow (Phase A)

### 6.1 The wrapping seam

The single seam is `DeviceConnection::send_data(apci, data)` in
`crates/bussard-mgmt/src/connection.rs:302` (and its `send_data_unacked` sibling
at `:387`), which today builds `CemiFrame::t_data_connected(target, source,
tpci, apci, data)`. Introduce a **`SecureLayer`** that, when the connection is
marked secure for this device, transforms `(apci, data)` into the A_SecureData
form **before** the cEMI is built:

```
fn wrap(&mut self, apci: u16, data: &[u8]) -> (u16 /* = 0x03F1 */, Vec<u8> /* SCF+seq+secured+MAC */)
```

and the inbound counterpart in `connection.rs:extract_apdu` / the receive loop:

```
fn unwrap(&mut self, apci: u16, asdu: &[u8]) -> Result<(u16, Vec<u8>)>   // verify MAC, decrypt, return the inner (apci, data)
```

Naming: `bussard_mgmt::secure::DataSecureSession` holds the per-device tool key,
the send sequence, and the per-source freshness table. `SecureLayer` is a thin
`Option<DataSecureSession>` on `DeviceConnection`: `None` → plain (today's
behaviour, unchanged); `Some` → every APDU is wrapped/unwrapped.

### 6.2 What changes in flash / describe / read paths

**Nothing structural.** `bussard-download`'s flash sequence (Unload →
StartLoading → AbsSegment writes → verify → LoadCompleted → Restart) and the
`describe`/`read` management reads are unchanged: each management APDU they emit
is transparently wrapped by `SecureLayer` when the device is activated. The
download engine does not know it is secure. `bussard-download` gains only a
**`secure` flag** that constructs the `DeviceConnection` with a
`Some(DataSecureSession)`. `[research §4 "What a Secure DOWNLOAD adds", corpus
§3 "no structurally different load procedure"]`.

Default `algorithm` for wrapped management APDUs = **CCM_ENCRYPTION (0b001)**
(the captures' `0x90` data frames; management content is sensitive). `tool_access
= 1`. The MAC is 4 bytes on the tunnel management path `[CONFIRMED,
secure-1-1-12 capture, 2026-09-23]`. In the same capture the activated device
still answers a plain `A_DeviceDescriptor_Read` and a plain
`A_PropertyValue_Read` of PID 56 (max APDU length) after `T_Connect`; ETS sends
those plain, then the Sync, then every further management APDU as S-A_Data
(including a second, secured descriptor read). bussard secures everything once
a tool key is given, which the device accepts.

### 6.3 The Sync preamble `[CONFIRMED: secure-1-1-12 capture, 2026-09-23; frames decrypted with the device tool key]`

ETS opens every secured tool-access connection like this (a System B device
that ETS 6.4.1 had security-activated):

1. `T_Connect`, plain `A_DeviceDescriptor_Read`, plain `A_PropertyValue_Read`
   (object 0, PID 56).
2. ETS -> device, connection-oriented (numbered data telegram to the device's
   individual address), SCF `0x92` **S-A_Sync_Req**.
3. Device -> ETS, numbered data telegram, SCF `0x93` **S-A_Sync_Res**.
4. ETS -> device, SCF `0x90` S-A_Data. Its sequence is **equal** to the
   Sync_Req's sequence; the Sync_Req does not consume a sequence number. Later
   S-A_Data frames count up by one. The device's first S-A_Data carries the
   device sequence from the Sync_Res.

**S-A_Sync_Req** (body after the SCF, 22 bytes including the MAC):

```
seq(6) || serial(6, clear) || challenge(6, encrypted) || MAC(4)
```

- CCM nonce: `block_0` / `counter_0` of §5.4 / §5.5 with the frame's own `seq`
  and addressing; `block_0` length octet = 6 (the challenge).
- additional data = `SCF || serial`; payload = the 6-byte random challenge,
  encrypted with the §3.3 stream (keystream bytes 4..10).
- `serial` is all zero on the connection-oriented form. On the broadcast form
  (unnumbered, to `0/0/0`, ETS used it once in the capture) it holds the
  target's KNX serial number, which the device checks.

**S-A_Sync_Res** (body after the SCF, 22 bytes including the MAC):

```
masked(6) || enc( responder_seq(6) || requester_seq(6) ) || MAC(4)
```

- The six bytes in the sequence slot are not a sequence: they are the CCM nonce
  sequence XOR the request's challenge. The receiver computes
  `nonce = masked XOR challenge` and uses it in `block_0` / `counter_0`; a
  response therefore verifies only against the request it answers.
- additional data = `SCF`; payload = 12 bytes, `block_0` length octet = 12.
- `responder_seq` = the device's own next send sequence (its next S-A_Data
  carries exactly this value, so the tool's freshness floor for the device is
  `responder_seq - 1`).
- `requester_seq` = the sequence the device accepts next from the tool. In all
  four exchanges of the capture it equals the Sync_Req's sequence, and ETS uses
  it as its next send sequence.

bussard: `DataSecureSession::sync_request` builds the request with a fresh
challenge; `unwrap` applies a verified Sync_Res (send sequence =
`max(current, requester_seq)`, freshness floor = `responder_seq - 1`);
`Layer4Connection` runs the exchange once, before the first wrapped APDU. A
device that T_ACKs the Sync_Req but never answers it (wrong tool key, or not
activated) surfaces as `AsduError::SyncUnanswered`. The earlier description of
this exchange as "system broadcast" was wrong: the SCF system-broadcast bit is
clear on every Sync frame, and the per-connection exchange is individually
addressed.

### 6.4 Plain-inside-secure coexistence

- A device with no keyring/knxproj secure activation → **plain**, `SecureLayer =
  None`. This is the state of all 25 house devices today `[corpus §1]`.
- Activation is per device: bussard decides `Some`/`None` from whether the
  keyring/knxproj marks that device secure-active (has a tool key / non-empty
  `<Security>` state indicating activation). A mixed installation (some activated,
  some not) is normal; the seam is per-`DeviceConnection`.
- A device that requires secure but is addressed plain will refuse (or ignore)
  the management APDU; bussard surfaces that as a "device requires KNX Data
  Secure" error, not a silent timeout.
- **The converse direction (decided by the A2 conformance loop, issue #71):** a
  secured APDU addressed to a device that is NOT security-activated is
  **refused**, not answered plain. A non-activated device holds no tool key and
  does not implement the secure application service, so it drops the frame the
  way it drops any unknown APCI. Both implementations model exactly that: the
  knx-sim logs the refusal (`SecureError::NotActivated`) rather than staying
  silent, and bussard turns the resulting silence into a message that names both
  possible causes (wrong tool key, or a device that is not activated). The
  spec had no wording for this direction; this is the best-evidence reading.

### 6.5 Send-sequence continuity across connections (A2 finding)

The send sequence is seeded from the clock (§5.8) but advances **once per APDU**,
so after a few hundred APDUs it is far ahead of the wall clock. A flash
reconnects (a master reset, a dropped L4 link), and a session rebuilt from the
clock therefore replays sequences the device has already accepted — the device
refuses every one as stale. **A new session for the same device must seed from
`max(clock, last_sent + 1)`**, i.e. the per-device high-water mark has to outlive
the connection (`bussard_secure::SequenceHighWater`). Cross-*process*
monotonicity still rests on the clock until either the state file of §5.9 or the
Sync preamble of §6.3 lands.

---

## 7. Phase B - KNXnet/IP Secure: keys and handshake

Source: `[XKNX ip_secure.py, secure_wrapper.py, knxip_enum.py, CONFIRMED]`.
Priority scope = **Secure Tunnelling (unicast)**.

### 7.1 Service type codes

Extend `ServiceType` in `crates/bussard-transport/src/knxnet.rs:32`:

| Service | Value |
|---|---|
| SEARCH_REQUEST_EXTENDED | 0x020B |
| SEARCH_RESPONSE_EXTENDED | 0x020C |
| SECURE_WRAPPER | 0x0950 |
| SESSION_REQUEST | 0x0951 |
| SESSION_RESPONSE | 0x0952 |
| SESSION_AUTHENTICATE | 0x0953 |
| SESSION_STATUS | 0x0954 |
| TIMER_NOTIFY | 0x0955 |

`SecureSessionStatusCode`: SUCCESS=0x00, AUTH_FAILED=0x01, UNAUTHENTICATED=0x02,
TIMEOUT=0x03, KEEPALIVE=0x04, CLOSE=0x05.

### 7.2 ECDH session-key derivation `[XKNX ip_secure.py, CONFIRMED]`

Curve **X25519 (RFC 7748)**. Public keys are 32 raw bytes.

```
ecdh_shared = X25519(client_private, server_public)   # 32 bytes
session_key = sha256(ecdh_shared)[:16]                # AES-128 session key (MSB128)
```

### 7.3 Handshake sequence

1. **SESSION_REQUEST (0x0951)** client→server: client control-endpoint HPAI +
   client ECDH public key (32). `[CONFIRMED key is sent; HPAI-then-key ordering
   INFERRED from standard layout]`.
2. **SESSION_RESPONSE (0x0952)** server→client:
   `secure_session_id(2 BE) + server ECDH public key(32) + MAC(16)`.
3. **SESSION_AUTHENTICATE (0x0953)** client→server: user id + auth MAC (§7.5).
4. **SESSION_STATUS (0x0954)** server→client: `0x00` on success.
5. **TIMER_NOTIFY (0x0955)**: secure ROUTING only (§9.3).

### 7.4 SESSION_RESPONSE MAC (device authentication) `[XKNX, CONFIRMED]`

The server proves it knows the **device authentication code**:

```
response_header = 06 10 09 52 00 38                       # 0x38 = 56 total len
pub_keys_xor    = client_pub XOR server_pub               # 32 bytes
additional_data = response_header + session_id(2 BE) + pub_keys_xor   # 6+2+32 = 40
block_0         = 16 * 0x00
counter_0       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF 00      # COUNTER_0_HANDSHAKE
mac_cbc = calculate_message_authentication_code_cbc(device_authentication_code, additional_data)
# verify: CTR-decrypt received MAC with counter_0, compare to mac_cbc[:16]
```

### 7.5 SESSION_AUTHENTICATE MAC (user authentication) `[XKNX, CONFIRMED]`

```
authenticate_header = 06 10 09 53 00 18                   # 0x18 = 24 total len
additional_data     = authenticate_header
                    + 0x00                                 # 1 reserved byte
                    + user_id(1)                           # user id
                    + pub_keys_xor(32)                     # 6+1+1+32 = 40
block_0  = 16 * 0x00
mac_cbc  = calculate_message_authentication_code_cbc(user_password, additional_data, block_0=0)
_, authenticate_mac = encrypt_data_ctr(user_password, counter_0=COUNTER_0_HANDSHAKE, mac_cbc)
```

Body = 1 reserved byte + 1 user-id byte + the 16-byte `authenticate_mac`.
`user_id` selects the tunnel/management user (id 1 = management, higher = tunnel
users). `[CONFIRMED code; user-id semantics INFERRED from keyring UserID]`.

---

## 8. Phase B - SecureWrapper (0x0950) byte-exact `[XKNX secure_wrapper.py, CONFIRMED]`

### 8.1 Framing

```
KNXnet/IP header    06 10 09 50 <total-len:2>   (6 bytes)
secure_session_id   2 bytes (BE)
sequence_information 6 bytes
serial_number       6 bytes  (KNX serial of sender)
message_tag         2 bytes
encrypted_data      variable (the wrapped KNXnet/IP frame)
message_authentication_code 16 bytes
```

`SECURITY_INFORMATION_LENGTH = 16` (session_id+seq+serial+tag),
`MESSAGE_AUTHENTICATION_CODE_LENGTH = 16`, minimum frame = 34 bytes; fixed
overhead beyond the wrapped payload = 32 bytes.

### 8.2 Crypto blocks

```
block_0   = sequence_information(6) + serial_number(6) + message_tag(2) + payload_len(2 BE)   # 16
counter_0 = sequence_information(6) + serial_number(6) + message_tag(2) + FF 00               # 16
additional_data = wrapper_header(6) + session_id(2)          # authenticated, not encrypted
mac_cbc   = calculate_message_authentication_code_cbc(session_key, additional_data, payload, block_0)
encrypted_data, encrypted_mac = encrypt_data_ctr(session_key, counter_0, mac_cbc, payload)
```

`[block_0/counter_0 + FF 00 CONFIRMED; additional_data = header + session_id
INFERRED from the ABB "Security Information authenticated" diagram + handshake
symmetry]`. `SEC-CAL: SecureWrapper additional_data exact bytes (header +
session_id, or + more) - one captured secure frame + the known session key
confirms the MAC input`.

### 8.3 Secure Tunnelling sequence model `[XKNX, CONFIRMED]`

- **Unicast (TCP or UDP)**: `sequence_information` is a **monotonic 6-byte
  counter** per session (increment-then-use). `secure_session_id` = the id from
  SESSION_RESPONSE. `message_tag` = 0 for tunnelling. Replay protection =
  strictly-increasing sequence.
- The wrapper sits at the `frame()`/`do_send` seam in
  `crates/bussard-transport/src/tunnel.rs:279` - the plain tunnelling frame is
  built as today, then wrapped in a SecureWrapper before the socket write, and
  every inbound SecureWrapper is unwrapped before `CemiFrame::decode`.
- `SEC-CAL: message_tag value for tunnelling (XKNX uses 0) and the keepalive /
  idle-timeout timers a real gateway enforces on a secure session`.

### 8.4 The wrapper seam and detection

- **Detection:** `parse_search_response` (`knxnet.rs:513`) today reads only the
  DEVICE_INFO DIB (0x01) and skips the rest `[corpus/research §5]`. Add a
  SEARCH_RESPONSE_EXTENDED (0x020C) path that parses the SUPP_SVC_FAMILIES DIB
  for a "Security" service family and the secured tunnel-slot DIB. `SEC-CAL:
  SEARCH_RESPONSE_EXTENDED Secure DIB type byte + layout (which DIB code
  advertises the Security family and secured tunnel slots)`.
- **Gate:** attempt a plain CONNECT_REQUEST; if the gateway rejects it (or
  advertises secure-only), fall to the Phase B handshake. `SEC-CAL: does the
  user's gateway require IP Secure (secure-only), and which user ids map to which
  tunnel slots - plain CONNECT + SEARCH_RESPONSE_EXTENDED capture`.

---

## 9. Phase B - session state, replay, routing (outline)

### 9.1 Session state machine

`Idle → SessionRequested → Authenticating → Established → Closing`. On
`Established`, the monotonic send sequence starts at 0 (or 1; increment-then-use).
A `SESSION_STATUS` with a non-SUCCESS code, an auth-MAC mismatch, or an idle
timeout tears the session down and (for tunnelling) the transport reconnects.

### 9.2 Replay / timeout

- Unicast: reject any inbound SecureWrapper whose `sequence_information` is not
  strictly greater than the last accepted (per session). Constant-time MAC
  compare before accepting.
- `KEEPALIVE` (SESSION_STATUS 0x04) keeps an idle session alive; honour the
  gateway's timeout (`SEC-CAL:` §8.3).

### 9.3 Secure ROUTING (deferred, B2)

`secure_session_id = 0`; `sequence_information` = the multicast timer value (ms),
synced via `TIMER_NOTIFY (0x0955)`; `message_tag` = random 2 bytes/frame; key =
backbone key; replay window = a time tolerance around the shared timer.
`TIMER_NOTIFY` blocks: header `06 10 09 55 00 24`; `block_0 = timer(6)+serial(6)+
tag(2)+00 00`; `counter_0 = timer(6)+serial(6)+tag(2)+FF 00`. Specified for
completeness, not built in Phase B. `[research §1.8, CONFIRMED]`.

---

## 10. Dependencies

Because CCM decomposes to CBC-MAC + CTR (§3), **no `ccm` crate is needed.** Stay
entirely on the RustCrypto **cipher-0.4 / digest-0.10 generation** already in
tree (`aes 0.8`, `sha2 0.10`, `hmac 0.12`, `pbkdf2 0.12`, `base64 0.22`). Add:

| Crate | Version | License | Why |
|---|---|---|---|
| `aes` | `0.8` | MIT/Apache-2.0 | AES-128 block cipher - **promote from transitive (via `zip`) to a direct workspace dep** |
| `cbc` | `0.1` | MIT/Apache-2.0 | CBC mode for CBC-MAC (cipher-0.4 gen; `0.2` is cipher-0.5 - AVOID) |
| `ctr` | `0.9` | MIT/Apache-2.0 | CTR mode for tag+payload (cipher-0.4 gen; `0.10` is cipher-0.5) |
| `x25519-dalek` | `2` | BSD-3-Clause | X25519 ECDH (Phase B only). v2 pairs with `rand_core 0.6` |
| `rand` / `rand_core` | `0.8` / `0.6` | MIT/Apache-2.0 | ephemeral X25519 keypair, message_tag/nonce randomness |
| `zeroize` (optional) | `1` | MIT/Apache-2.0 | zeroizing key wrapper (§2.3); may be replaced by a hand-written `Drop` |

License notes: BSD-3-Clause and MIT/Apache are all on the `deny.toml` allow-list
`[deny.toml]`, so `cargo deny check` stays green. Declare shared versions in the
root `[workspace.dependencies]` and reference with `dep.workspace = true`
(project convention). Phase A needs only `aes`, `cbc`, `ctr` (+ optional
`zeroize`); `x25519-dalek`/`rand` are Phase B.

**Version-generation rule (do not violate).** RustCrypto splits into two
incompatible generations: cipher-0.4 (`aes 0.8`/`cbc 0.1`/`ctr 0.9`) - what
bussard uses - and cipher-0.5 (`aes 0.9`/`cbc 0.2`/`ctr 0.10`/`ccm 0.6`). Pick
the version whose `rand_core` matches `rand`. Do NOT mix generations; if a future
maintainer wants the `ccm` crate for clarity, ALL crypto must move to 0.5
together (a bigger change). `[research §6.2, CONFIRMED crate licenses/versions]`.

---

## 11. Importer / model changes (Phase A, no crypto)

Cheap, independent of the crypto, do first `[corpus §5]`:

- `bussard-prod`/`bussard-ets`: preserve `ApplicationProgram/@IsSecureEnabled`
  and the `MaxSecurity{IndividualAddress,GroupKeyTable,P2PKey}Entries` sizing
  attrs (currently dropped). Surface them as a `secure` flag + sizing on the
  model.
- knxproj import: surface `<DeviceCertificate>` **presence** (a boolean "has
  FDSK") and the `<Security SequenceNumber SequenceNumberTimestamp>` state per
  device.
- **Committed YAML (`knx/`) carries flags + seqnum state ONLY** - never the FDSK,
  tool key, group key, or any password (§2.2, §2.3). `knx/` is reviewed and
  committed; key bytes must never enter it.

- Activation and per-object security `[CONFIRMED: two exports of the same
  project, before and after ETS activated 1.1.12, issue #156]`: the device's
  `<Security>` child gains `ToolKey` and `LoadedToolKey` on activation
  (`LoadedToolKey` present = `activated`; `ToolKey` alone = secure
  commissioning configured, not downloaded). A secured group address carries
  its encrypted group key as the `Key` attribute of its `<GroupAddress>`. No
  `ComObjectInstanceRef` and no `GroupAddress` carried a `Security` attribute,
  so a group object is secure when it links a keyed GA (ETS's `Auto`). The
  importer still honours an explicit `Security="On"|"Off"` should one appear.
  Only booleans reach the model.

### 11.1 The security interface object in a secured download `[CONFIRMED: secure-1-1-12 capture, decrypted; issue #156]`

Every full download of an activated device reprograms the security object
(object type 17, instance 1) with the extended property services:

| step | service | payload after the 5-octet header |
|---|---|---|
| after the other objects' Unload | `A_FunctionPropertyExt_Command` PID 5 | `04` + 9 × `00` (Unload); answer `rc=00 state=00` |
| after the tables and parameters | `A_FunctionPropertyExt_Command` PID 5 | `01` + 9 × `00` (StartLoading); answer `state=02` |
| | `A_PropertyExtValue_WriteCon` PID 54 | count 1, start 0, `00 00` (empty IA table) |
| | `A_PropertyExtValue_WriteCon` PID 53 | from start 1, 18-octet elements `[address-table index:16][group key:16]` |
| | `A_PropertyExtValue_WriteCon` PID 61 | from start 1, one flag octet per group object (element n = object n), all objects of the GO table, `0x03` for a secured object |
| before PID 13 and LoadCompleted | `A_FunctionPropertyExt_Command` PID 5 | `02` + 9 × `00` (LoadCompleted); answer `state=01` |

The header is `[object type:16][instance:12 | PID:12]`; the value services
follow with `[count:8][start:16]`, the write-con response with `[count][start]
[return code]`, the function state response with `[return code][data]`.
Chunks follow the inner APDU budget: `PID_MAX_APDU_LENGTH` minus 13 octets of
Data Secure overhead (ETS: 233 → 215-octet `A_MemoryExtended_Write` chunks,
211-element PID 61 chunks). The group key table and flags bussard builds from
the keyring and the tables equal ETS's bytes (`secure_capture_oracle.rs`,
`test_security_object_program_matches_ets`). INFERRED: the order and packing
of several PID 53 entries (the capture has one), the meaning of the flag bits
(bit 0/1 = authentication/confidentiality).

---

## 12. Test plan

### 12.1 Unit vectors

The research captured no numeric XKNX test vectors, so derive the shared worked
vectors from §3.5 and commit them as **synthetic** fixtures both implementers
compute independently: a CBC-MAC vector, an A_SecureData MAC+enc round-trip (§5),
and a SecureWrapper round-trip (§8). A mismatch is the primary "one side's CCM
diverged" signal. PBKDF2 vectors follow the `password.rs` pattern (a known
password → a known 16-byte key per salt in §3.4), computed independently in
Python and asserted.

### 12.2 Sim conformance loop

The knx-sim Secure device model is the executable spec (mirroring System 7).
bussard flashes a **security-ACTIVATED** sim device to `Loaded` via tool-access:
the sim is configured with a tool key + group keys + a freshness table + a
starting sequence, and asserts the exact A_SecureData wire bytes (SCF, 6-byte
seq, MAC, block_0/counter_0) for every wrapped management APDU, then that the
inner flash sequence (authorize, memory writes, load controls, restart) is
byte-identical to the plain path once unwrapped. Because the house has no
activated device to test against, the sim is the ONLY conformance peer for
Phase A. Run it in both `algorithm` modes (auth-only and auth+enc).

### 12.3 Fixtures - synthetic only (hard rule)

- Keyring fixtures: a synthetic `.knxkeys` generated by the test harness with
  known (fake) keys, exercising §4 (password→key, attr decrypt, extract_password,
  signature verify, all element types).
- knxproj fixtures: a synthetic minimal project with a fake `<DeviceCertificate
  FDSK=…>` and `<Security>` state.
- **FORBIDDEN:** committing anything derived from the user's real
  `home_test.knxproj`, any real FDSK/tool/group key, or any capture-derived
  plaintext-under-MAC. The 6 house captures' `0x3F1` frames may be decoded
  *offline for calibration* but their keys and plaintext MUST NOT be committed
  `[corpus §5]`.

### 12.4 M2 live-capture milestone

The five `SEC-CAL:` UNKNOWNs are settled by **activating security on ONE house
device via ETS and capturing it** (and, for Phase B, capturing a plain
CONNECT_REQUEST against the gateway + a SEARCH_RESPONSE_EXTENDED):

1. Sync_Req/Sync_Res ASDU byte layout + whether Sync is mandatory (§5.9, §6.3).
   **Settled** by the secure-1-1-12 capture (2026-09-23): layout in §6.3; ETS
   always syncs and bussard now does too.
2. Data-Secure MAC length (4 vs 16) and secured-vs-plain scope on the
   management path (§6.2). **Settled** by the same capture: 4 bytes; the device
   answers two plain reads before the Sync, everything after it is secured.
3. `SEC-CAL:` SecureWrapper `additional_data` exact bytes (§8.2).
4. `SEC-CAL:` SEARCH_RESPONSE_EXTENDED Secure DIB type/layout + gateway
   secure-only mode (§8.4).
5. `SEC-CAL:` `message_tag` for tunnelling + keepalive/idle timers (§8.3).

The `.knxkeys` signature canonicalization (§4.4) is settled (#84), confirmed
against a real ETS 6 export.

Until M2, ship every seam with the best-evidence default and keep every marker
greppable.

---

## 13. Ranked open questions a live capture would settle

1. **Does the gateway require IP Secure (secure-only), and which user ids map to
   which tunnel slots?** Decides whether Phase B is mandatory to talk to the house
   at all. (Capture a plain CONNECT_REQUEST; inspect SEARCH_RESPONSE_EXTENDED.)
2. **Do target devices require Data Secure for management once activated, or is
   plain management still allowed inside a secure tunnel?** Decides the Phase A
   default (§6.2).
3. **Sync_Req/Sync_Res byte layout and whether Sync is mandatory** to learn the
   device seqnum (§5.9, §6.3).
4. **SecureWrapper `additional_data` MAC input** (§8.2).
5. **FDSK QR/label string encoding** - only if commissioning from a scanned label
   (a non-goal, §1.4). `[research §2.6, UNKNOWN]`.

---

## 14. Milestones

- **A0** - importer preserves `IsSecureEnabled`/`MaxSecurity*` + FDSK-presence +
  seqnum state; flags-only in YAML. No crypto. (§11)
- **A1** - crypto primitives (`aes`+`cbc`+`ctr`), PBKDF2 salts, unit vectors
  (§3, §12.1). `.knxkeys` parser (§4).
- **A2** - A_SecureData ASDU + `DataSecureSession`/`SecureLayer` seam;
  tool-access wrap/unwrap; sequence persistence; sim conformance loop against an
  ACTIVATED sim device (§5, §6, §12.2). Phase A done.
- **B1** - IP Secure session layer: SESSION_* handshake, X25519, SecureWrapper,
  monotonic sequence, SEARCH_RESPONSE_EXTENDED detection; sim IP-Secure tunnel
  server (§7-§9). Gated on a secure-only interface.
- **B2** - Secure ROUTING (multicast + TIMER_NOTIFY), deferred (§9.3).
- **M2** - live ETS activation capture resolves the five `SEC-CAL:` markers; fix
  any default that was wrong. The Data Secure half is done (secure-1-1-12
  capture, 2026-09-23): it fixed the CTR payload offset (§3.3) and the Sync
  layout (§6.3).
