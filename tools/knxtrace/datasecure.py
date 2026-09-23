"""KNX Data Secure: the ETS keyring and A_SecureData verification/decryption.

A port of bussard's Rust implementation, which stays the reference:

- `crates/bussard-project/src/keyring.rs`: the `.knxkeys` keyring. PBKDF2-HMAC-
  SHA256 over the password with salt `1.keyring.ets.knx.org` and 65536
  iterations gives the 16-byte keyring key. Every encrypted key attribute
  (`ToolKey`, `FDSK`, group `Key`) is base64 of one AES-128-CBC block under
  that key, IV `sha256(Created)[:16]`, no padding. The root `Signature` is
  `sha256(canonical serialization)[:16]` and is what tells a wrong password
  from a right one.
- `crates/bussard-secure/src/{crypto,asdu}.rs`: the `A_SecureData` ASDU,
  `SCF(1) || seq(6) || secured APDU || MAC(4)`, protected with AES-128-CCM
  using the KNX TP `block_0` / `counter_0` layouts.

Everything is stdlib. AES-128 is implemented here in pure Python because the
tool has no third-party dependencies (see the README); it is slow, but a
capture holds at most a few thousand secure frames.

Key hygiene: key material lives only in `Keyring` objects, whose `repr` is
redacted, and nothing in this module prints or logs a key. Decrypted APDUs
are ordinary management traffic and are decoded like plain frames.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

BLOCK = 16
MAC_LEN = 4
A_SECURE_DATA = 0x3F1
KEYRING_SALT = b"1.keyring.ets.knx.org"
PBKDF2_ITERATIONS = 65536

# --------------------------------------------------------------------------
# AES-128 (FIPS-197), pure Python
# --------------------------------------------------------------------------


def _build_sbox() -> Tuple[List[int], List[int]]:
    sbox = [0] * 256
    inv = [0] * 256
    p = q = 1
    while True:
        # p walks the multiplicative group by 3, q by its inverse (1/3).
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        x = (x ^ 0x63) & 0xFF
        sbox[p] = x
        inv[x] = p
        if p == 1:
            break
    sbox[0] = 0x63
    inv[0x63] = 0
    return sbox, inv


def _rotl8(x: int, shift: int) -> int:
    return ((x << shift) | (x >> (8 - shift))) & 0xFF


SBOX, INV_SBOX = _build_sbox()


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out


_MUL9 = [_mul(i, 9) for i in range(256)]
_MUL11 = [_mul(i, 11) for i in range(256)]
_MUL13 = [_mul(i, 13) for i in range(256)]
_MUL14 = [_mul(i, 14) for i in range(256)]
_XT = [_xtime(i) for i in range(256)]


class Aes128:
    """AES-128 single-block encryption and decryption."""

    def __init__(self, key: bytes) -> None:
        if len(key) != BLOCK:
            raise ValueError("AES-128 needs a 16-byte key")
        words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
        rcon = 1
        for i in range(4, 44):
            t = list(words[i - 1])
            if i % 4 == 0:
                t = t[1:] + t[:1]
                t = [SBOX[b] for b in t]
                t[0] ^= rcon
                rcon = _xtime(rcon)
            words.append([a ^ b for a, b in zip(words[i - 4], t)])
        self._rk = [sum(words[r * 4 : r * 4 + 4], []) for r in range(11)]

    def __repr__(self) -> str:
        return "Aes128(<redacted>)"

    def encrypt_block(self, block: bytes) -> bytes:
        s = [b ^ k for b, k in zip(block, self._rk[0])]
        for rnd in range(1, 11):
            s = [SBOX[b] for b in s]
            # ShiftRows on the column-major state.
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
            if rnd != 10:
                t = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c : 4 * c + 4]
                    x = a0 ^ a1 ^ a2 ^ a3
                    t += [
                        a0 ^ x ^ _XT[a0 ^ a1],
                        a1 ^ x ^ _XT[a1 ^ a2],
                        a2 ^ x ^ _XT[a2 ^ a3],
                        a3 ^ x ^ _XT[a3 ^ a0],
                    ]
                s = t
            s = [b ^ k for b, k in zip(s, self._rk[rnd])]
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = [b ^ k for b, k in zip(block, self._rk[10])]
        for rnd in range(9, -1, -1):
            # InvShiftRows.
            s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]
            s = [INV_SBOX[b] for b in s]
            s = [b ^ k for b, k in zip(s, self._rk[rnd])]
            if rnd != 0:
                t = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c : 4 * c + 4]
                    t += [
                        _MUL14[a0] ^ _MUL11[a1] ^ _MUL13[a2] ^ _MUL9[a3],
                        _MUL9[a0] ^ _MUL14[a1] ^ _MUL11[a2] ^ _MUL13[a3],
                        _MUL13[a0] ^ _MUL9[a1] ^ _MUL14[a2] ^ _MUL11[a3],
                        _MUL11[a0] ^ _MUL13[a1] ^ _MUL9[a2] ^ _MUL14[a3],
                    ]
                s = t
        return bytes(s)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-128-CBC decryption without unpadding (crypto.rs `aes_cbc_decrypt`)."""
    if len(iv) != BLOCK or not ciphertext or len(ciphertext) % BLOCK:
        raise ValueError("AES-CBC needs a 16-byte IV and whole blocks")
    aes = Aes128(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK):
        blk = ciphertext[i : i + BLOCK]
        out += _xor(aes.decrypt_block(blk), prev)
        prev = blk
    return bytes(out)


def cbc_mac(aes: Aes128, additional_data: bytes, payload: bytes, block_0: bytes) -> bytes:
    """The CCM CBC-MAC as bussard builds it (crypto.rs `cbc_mac`).

    `block_0 || len(ad) as u16 BE || ad || payload`, zero-padded to a block
    multiple, CBC-encrypted under a zero IV; the MAC is the last block.
    """
    buf = block_0 + len(additional_data).to_bytes(2, "big") + additional_data + payload
    if len(buf) % BLOCK:
        buf += b"\x00" * (BLOCK - len(buf) % BLOCK)
    state = bytes(BLOCK)
    for i in range(0, len(buf), BLOCK):
        state = aes.encrypt_block(_xor(state, buf[i : i + BLOCK]))
    return state


def ctr_keystream(aes: Aes128, counter_0: bytes, n_bytes: int) -> bytes:
    """AES-CTR keystream from a 128-bit big-endian counter (crypto.rs CTR)."""
    ctr = int.from_bytes(counter_0, "big")
    out = bytearray()
    while len(out) < n_bytes:
        out += aes.encrypt_block(ctr.to_bytes(BLOCK, "big"))
        ctr = (ctr + 1) & ((1 << 128) - 1)
    return bytes(out[:n_bytes])


# --------------------------------------------------------------------------
# A_SecureData (asdu.rs)
# --------------------------------------------------------------------------


def tp_block_0(seq: int, src: int, dst: int, group: bool, ext_ff: int, tpci: int, payload_len: int) -> bytes:
    """`seq(6) || src(2) || dst(2) || 00 || A000EEEE || (tpci&FC)|03 || F1 || 00 || len`."""
    return (
        seq.to_bytes(6, "big")
        + src.to_bytes(2, "big")
        + dst.to_bytes(2, "big")
        + bytes([0x00, (0x80 if group else 0) | (ext_ff & 0x0F), (tpci & 0xFC) | 0x03, 0xF1, 0x00, payload_len & 0xFF])
    )


def tp_counter_0(seq: int, src: int, dst: int) -> bytes:
    """`seq(6) || src(2) || dst(2) || 00 00 00 00 01 00`."""
    return seq.to_bytes(6, "big") + src.to_bytes(2, "big") + dst.to_bytes(2, "big") + bytes([0, 0, 0, 0, 1, 0])


@dataclass
class Addressing:
    """The carrying frame's fields that the CCM nonce covers."""

    src: int
    dst: int
    group: bool = False
    ext_ff: int = 0
    tpci: int = 0x40


def encode(key: bytes, scf: int, seq: int, addr: Addressing, apdu: bytes) -> bytes:
    """Builds an A_SecureData ASDU around `apdu` (asdu.rs `encode`). Tests only."""
    aes = Aes128(key)
    encrypts = ((scf >> 4) & 0x07) == 0b001
    b0 = tp_block_0(seq, addr.src, addr.dst, addr.group, addr.ext_ff, addr.tpci, len(apdu) if encrypts else 0)
    c0 = tp_counter_0(seq, addr.src, addr.dst)
    if encrypts:
        mac = cbc_mac(aes, bytes([scf]), apdu, b0)
        ks = ctr_keystream(aes, c0, BLOCK + len(apdu))
        body = _xor(apdu, ks[BLOCK:])
    else:
        mac = cbc_mac(aes, bytes([scf]) + apdu, b"", b0)
        ks = ctr_keystream(aes, c0, BLOCK)
        body = apdu
    return bytes([scf]) + seq.to_bytes(6, "big") + body + _xor(mac, ks)[:MAC_LEN]


def decode(key: bytes, asdu: bytes, addr: Addressing) -> Tuple[bytes, bool]:
    """Recovers the inner APDU of an A_SecureData ASDU (asdu.rs `decode`).

    Returns `(apdu, mac_ok)`. Unlike the Rust decoder this does not reject a
    MAC mismatch: an analysis tool wants to report it. A failed MAC means the
    returned bytes are garbage (wrong key or wrong addressing).
    """
    if len(asdu) < 1 + 6 + MAC_LEN:
        raise ValueError("A_SecureData ASDU too short")
    scf = asdu[0]
    seq = int.from_bytes(asdu[1:7], "big")
    secured = asdu[7:-MAC_LEN]
    received = asdu[-MAC_LEN:]
    encrypts = ((scf >> 4) & 0x07) == 0b001
    aes = Aes128(key)
    b0 = tp_block_0(seq, addr.src, addr.dst, addr.group, addr.ext_ff, addr.tpci, len(secured) if encrypts else 0)
    c0 = tp_counter_0(seq, addr.src, addr.dst)
    ks = ctr_keystream(aes, c0, BLOCK + (len(secured) if encrypts else 0))
    if encrypts:
        apdu = _xor(secured, ks[BLOCK:])
        mac = cbc_mac(aes, bytes([scf]), apdu, b0)
    else:
        apdu = secured
        mac = cbc_mac(aes, bytes([scf]) + apdu, b"", b0)
    ok = hmac.compare_digest(_xor(mac, ks)[:MAC_LEN], received)
    return apdu, ok


# --------------------------------------------------------------------------
# Keyring (keyring.rs)
# --------------------------------------------------------------------------


class KeyringError(Exception):
    """The keyring could not be read, or the password is wrong."""


@dataclass
class Keyring:
    """Decrypted keys from a `.knxkeys` file, indexed by raw 16-bit address.

    `tool_keys` and `fdsks` are keyed by device individual address, `group_keys`
    by group address. The repr never shows key bytes.
    """

    project: str = ""
    tool_keys: Dict[int, bytes] = field(default_factory=dict, repr=False)
    fdsks: Dict[int, bytes] = field(default_factory=dict, repr=False)
    group_keys: Dict[int, bytes] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:
        return "Keyring(project=%r, %d tool key(s), %d FDSK(s), %d group key(s))" % (
            self.project,
            len(self.tool_keys),
            len(self.fdsks),
            len(self.group_keys),
        )

    def candidates(self, src: int, dst: int, group: bool, tool_access: bool) -> List[Tuple[str, bytes]]:
        """The keys worth trying for one frame, labelled, most likely first.

        Tool access (SCF bit 7) uses the device's tool key; during Secure
        activation ETS still talks under the device's FDSK, so that is tried
        next. The device is whichever end of the frame the keyring knows.
        Group traffic uses the group address's key.
        """
        out: List[Tuple[str, bytes]] = []
        if group and not tool_access:
            key = self.group_keys.get(dst)
            if key is not None:
                out.append(("group", key))
            return out
        ends = [dst, src] if not group else [src]
        for label, table in (("tool", self.tool_keys), ("fdsk", self.fdsks)):
            for ia in ends:
                key = table.get(ia)
                if key is not None and all(key != k for _, k in out):
                    out.append((label, key))
        return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _framed(data: bytes) -> bytes:
    if len(data) > 255:
        raise KeyringError("keyring string too long for the signature framing")
    return bytes([len(data)]) + data


def _canonical(root: ET.Element, keyring_key: bytes) -> bytes:
    """The byte string the root `Signature` is computed over (keyring.rs)."""
    out = bytearray()

    def walk(el: ET.Element) -> None:
        out.append(0x01)
        out.extend(_framed(_local(el.tag).encode("utf-8")))
        attrs = sorted(
            (k, v)
            for k, v in el.attrib.items()
            if k != "Signature" and k != "xmlns" and not k.startswith("xmlns:")
        )
        for k, v in sorted(attrs, key=lambda kv: kv[0].encode("utf-8")):
            out.extend(_framed(k.encode("utf-8")))
            out.extend(_framed(v.encode("utf-8")))
        for child in el:
            walk(child)
        out.append(0x02)

    walk(root)
    out.extend(_framed(base64.b64encode(keyring_key)))
    return bytes(out)


def _latin1(password: str) -> bytes:
    return bytes(ord(c) if ord(c) <= 0xFF else ord("?") for c in password)


def _parse_ia(text: str) -> int:
    parts = text.strip().split(".")
    if len(parts) != 3:
        raise KeyringError("not an individual address: %r" % text)
    a, l, d = (int(p) for p in parts)
    return (a << 12) | (l << 8) | d


def _parse_ga(text: str) -> int:
    text = text.strip()
    if text.isdigit():
        return int(text) & 0xFFFF
    parts = text.split("/")
    if len(parts) == 3:
        a, b, c = (int(p) for p in parts)
        return (a << 11) | (b << 8) | c
    if len(parts) == 2:
        a, b = (int(p) for p in parts)
        return (a << 11) | b
    raise KeyringError("not a group address: %r" % text)


def parse_keyring(xml_text: str, password: str) -> Keyring:
    """Parses and decrypts a `.knxkeys` document.

    Raises `KeyringError` on a malformed document or when the signature does
    not verify (a wrong password, or a file edited after export).
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise KeyringError("malformed keyring XML: %s" % exc)
    if _local(root.tag) != "Keyring":
        raise KeyringError("no <Keyring> root element")
    created = root.get("Created")
    signature = root.get("Signature")
    if created is None or signature is None:
        raise KeyringError("keyring root lacks Created or Signature")

    kk = hashlib.pbkdf2_hmac("sha256", _latin1(password), KEYRING_SALT, PBKDF2_ITERATIONS, BLOCK)
    digest = hashlib.sha256(_canonical(root, kk)).digest()[:BLOCK]
    try:
        expected = base64.b64decode(signature, validate=True)
    except ValueError:
        raise KeyringError("keyring Signature is not valid base64")
    if not hmac.compare_digest(digest, expected):
        raise KeyringError(
            "wrong keyring password: the .knxkeys signature does not verify "
            "(or the file was modified after export)"
        )
    iv = hashlib.sha256(created.encode("utf-8")).digest()[:BLOCK]

    def key_attr(el: ET.Element, name: str) -> Optional[bytes]:
        value = el.get(name)
        if value is None:
            return None
        try:
            ct = base64.b64decode(value, validate=True)
        except ValueError:
            raise KeyringError("%s is not valid base64" % name)
        if len(ct) != BLOCK:
            raise KeyringError("%s is %d bytes, expected one AES block" % (name, len(ct)))
        return aes_cbc_decrypt(kk, iv, ct)

    ring = Keyring(project=root.get("Project", ""))
    for el in root:
        tag = _local(el.tag)
        if tag == "GroupAddresses":
            for g in el:
                if _local(g.tag) == "Group" and g.get("Key") and g.get("Address"):
                    ring.group_keys[_parse_ga(g.get("Address", ""))] = key_attr(g, "Key") or b""
        elif tag == "Devices":
            for d in el:
                if _local(d.tag) != "Device" or not d.get("IndividualAddress"):
                    continue
                ia = _parse_ia(d.get("IndividualAddress", ""))
                tool = key_attr(d, "ToolKey")
                if tool is not None:
                    ring.tool_keys[ia] = tool
                fdsk = key_attr(d, "FDSK")
                if fdsk is not None:
                    ring.fdsks[ia] = fdsk
    return ring


def load_keyring(path: str, password: str) -> Keyring:
    """Reads and decrypts a `.knxkeys` file."""
    with open(path, "r", encoding="utf-8-sig") as fh:
        return parse_keyring(fh.read(), password)


# --------------------------------------------------------------------------
# Frame stream integration
# --------------------------------------------------------------------------


def unwrap_frames(frames: Iterable, ring: Keyring) -> None:
    """Verifies and decrypts every A_SecureData APDU in `frames`, in place.

    For each secure APDU whose key is in the keyring, the first candidate key
    whose MAC verifies wins; its label (`tool`, `fdsk`, `group`) lands in the
    `key` field, `mac` becomes `ok`, and the inner APDU is decoded with the
    plain decoder into `Apdu.inner`. If keys were tried and none verified,
    `mac` is `FAIL` and nothing is decoded. A frame with no candidate key is
    left exactly as the plain decoder produced it.

    Tunnelling clients often send `L_Data.req` with source `0.0.0` and let the
    interface fill in its own address, which is what the MAC actually covers.
    The source of the matching `L_Data.con` is therefore remembered per tunnel
    peer and tried as a fallback.
    """
    from knxip import decode_apdu  # local import: knxip imports nothing of ours

    tunnel_ia: Dict[str, int] = {}
    for frame in frames:
        cemi = frame.cemi
        if cemi is None or cemi.l4 is None:
            continue
        if cemi.mc == 0x2E and cemi.src_raw:  # L_Data.con: learn the real source
            tunnel_ia[frame.dst] = cemi.src_raw
        apdu = cemi.l4.apdu
        if apdu is None or apdu.apci != A_SECURE_DATA or len(apdu.payload) < 1 + 6 + MAC_LEN:
            continue
        scf = apdu.payload[0]
        cands = ring.candidates(cemi.src_raw, cemi.dst_raw, cemi.dst_is_group, bool(scf & 0x80))
        if not cands:
            continue
        sources = [cemi.src_raw]
        if cemi.src_raw == 0:
            learned = tunnel_ia.get(frame.src)
            if learned:
                sources.append(learned)
        result = None
        for label, key in cands:
            for src in sources:
                addr = Addressing(src, cemi.dst_raw, cemi.dst_is_group, cemi.ext_ff, cemi.l4.tpci)
                plain, ok = decode(key, apdu.payload, addr)
                if ok:
                    result = (label, plain)
                    break
            if result:
                break
        if result is None:
            apdu.fields["mac"] = "FAIL"
            continue
        label, plain = result
        apdu.fields["key"] = label
        apdu.fields["mac"] = "ok"
        service = scf & 0x07
        if service != 0:
            # S-A_Sync_Req/_Res carry a sequence and challenge, not an APDU.
            apdu.fields["sync_len"] = len(plain)
            continue
        if len(plain) < 2:
            apdu.fields["inner_truncated"] = True
            continue
        inner_apci = ((plain[0] & 0x03) << 8) | plain[1]
        apdu.inner = redact_keys(decode_apdu(inner_apci, plain[2:], plain[1] & 0x3F))


# Security interface object (type 17) properties that carry key material:
# PID_P2P_KEY_TABLE, PID_GRP_KEY_TABLE, PID_TOOL_KEY. (56 on the device object
# is PID_MAX_APDU_LENGTH, which is why object 0 is exempt.)
KEY_PIDS = frozenset({52, 53, 56})


def redact_keys(apdu):
    """Hides key material a decrypted management APDU may carry.

    Activation writes the new tool key, and a download may write the group key
    table, both as ordinary property values that the plain decoder would print
    as hex. Those, and any undecoded service with a payload of a key's size or
    more, are reduced to a length and a hash, the way `A_Authorize` keys are.
    """
    from knxip import sha8

    f = apdu.fields
    data = f.get("data")
    if not isinstance(data, str):
        return apdu
    secret = False
    if apdu.name.startswith("A_PropertyValue") and f.get("pid") in KEY_PIDS and f.get("obj") != 0:
        secret = True
    elif (apdu.name.startswith("APCI_0x") or "ExtValue" in apdu.name) and len(data) >= 32:
        secret = True
    if secret:
        f["data"] = "redacted:%s" % sha8(bytes.fromhex(data))
    return apdu


def sequence_problems(frames: Iterable) -> List[str]:
    """Reports every Data Secure sequence number that did not increase.

    Tracked per (sender, key): a receiver must see a strictly higher sequence
    from a sender than the last one it accepted. Only S-A_Data frames count:
    the sequence field of an S-A_Sync_Res is not a counter, and ETS reuses a
    Sync_Req's sequence for the first data frame after it. `L_Data.con`
    echoes and link-layer repeats are skipped, since they legitimately carry
    the same sequence again. The key is the verified key label when the frame
    decrypted, otherwise the SCF's `tool`/`group` class.
    """
    last: Dict[Tuple[str, str], Tuple[int, float]] = {}
    out: List[str] = []
    for frame in frames:
        cemi = frame.cemi
        if cemi is None or cemi.l4 is None or cemi.mc == 0x2E or cemi.repeated:
            continue
        apdu = cemi.l4.apdu
        if apdu is None or apdu.apci != A_SECURE_DATA or "seq" not in apdu.fields:
            continue
        if apdu.fields.get("service") != "S-A_Data":
            continue
        seq = int(apdu.fields["seq"])
        who = (cemi.src, key_class(apdu))
        prev = last.get(who)
        if prev is not None and seq <= prev[0]:
            out.append(
                "t=%.4f %s key=%s seq %d <= previous %d (at t=%.4f)"
                % (frame.ts, who[0], who[1], seq, prev[0], prev[1])
            )
        if prev is None or seq > prev[0]:
            last[who] = (seq, frame.ts)
    return out


def key_class(apdu) -> str:
    """The verified key label, or `tool`/`group` from the SCF when unverified."""
    if "key" in apdu.fields:
        return str(apdu.fields["key"])
    return "tool" if apdu.fields.get("tool_access") else "group"
