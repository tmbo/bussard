"""Capture-file reading: pcap and pcapng, link layers, IP, UDP and TCP.

Deliberately dependency-free. The campaign machine must be able to run the
decoder offline, and a hand-written reader keeps the failure modes ours: every
parse is bounds-checked and a malformed record is skipped, never fatal.

The public entry point is `packets(path)`, which yields `Packet` records in
capture order. Payload framing (KNXnet/IP) happens a layer up, in `knxip.py`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Optional

# Link types we understand (libpcap DLT numbers).
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_BSD = 12
DLT_RAW_OPENBSD = 14
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = (0x8100, 0x88A8, 0x9100)

IPPROTO_TCP = 6
IPPROTO_UDP = 17

# IPv6 extension headers we skip over when looking for TCP/UDP.
IPV6_SKIP = (0, 43, 44, 60)


@dataclass(frozen=True)
class Packet:
    """One transport-layer payload lifted out of a capture file."""

    ts: float
    proto: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes
    # TCP only; None for UDP.
    tcp_seq: Optional[int] = None
    tcp_fin: bool = False
    tcp_syn: bool = False

    @property
    def src(self) -> str:
        return "%s:%d" % (self.src_ip, self.src_port)

    @property
    def dst(self) -> str:
        return "%s:%d" % (self.dst_ip, self.dst_port)

    @property
    def flow(self) -> tuple:
        """The directional 4-tuple, used to key TCP reassembly."""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


class CaptureError(Exception):
    """The file is not a capture we can read at all (bad magic, empty)."""


# --------------------------------------------------------------------------
# File formats
# --------------------------------------------------------------------------


def _read_exact(fh, n: int) -> bytes:
    data = fh.read(n)
    return data or b""


def _raw_records(path: str) -> Iterator[tuple]:
    """Yields (ts, linktype, frame_bytes) from a pcap or pcapng file."""
    with open(path, "rb") as fh:
        magic = _read_exact(fh, 4)
        if len(magic) < 4:
            raise CaptureError("%s: too short to be a capture file" % path)
        fh.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            for rec in _pcapng_records(fh, path):
                yield rec
        elif magic in (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        ):
            for rec in _pcap_records(fh, path):
                yield rec
        else:
            raise CaptureError(
                "%s: unknown capture magic %s (expected pcap or pcapng)"
                % (path, magic.hex())
            )


def _pcap_records(fh, path: str) -> Iterator[tuple]:
    header = _read_exact(fh, 24)
    if len(header) < 24:
        raise CaptureError("%s: truncated pcap header" % path)
    magic = header[:4]
    endian = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
    nanos = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", header[20:24])[0]
    divisor = 1e9 if nanos else 1e6
    while True:
        rec = _read_exact(fh, 16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rec)
        if incl > 0x0400_0000:  # 64 MiB: a corrupt length, not a real packet
            return
        data = _read_exact(fh, incl)
        if len(data) < incl:
            return  # truncated final record: stop cleanly
        yield (ts_sec + ts_frac / divisor, linktype, data)


def _pcapng_records(fh, path: str) -> Iterator[tuple]:
    endian = "<"
    ifaces = {}  # iface id -> (linktype, timestamp divisor)
    while True:
        head = _read_exact(fh, 8)
        if len(head) < 8:
            return
        btype = struct.unpack(endian + "I", head[:4])[0]
        if btype == 0x0A0D0D0A:
            # Section header block: the byte-order magic sets the endianness for
            # everything that follows, including this block's own length field.
            raw_len = head[4:8]
            probe = _read_exact(fh, 4)
            if len(probe) < 4:
                return
            # The magic is the number 0x1A2B3C4D, so the octets 4d 3c 2b 1a on
            # the wire mean little-endian and 1a 2b 3c 4d mean big-endian.
            if probe == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif probe == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                return  # not a section header we can read
            blen = struct.unpack(endian + "I", raw_len)[0]
            if blen < 16 or blen > 0x0400_0000:
                return
            # head (8) + the byte-order magic (4) are already consumed; the
            # rest of the block, trailing total-length field included, is
            # blen - 12 octets.
            rest = _read_exact(fh, blen - 12)
            if len(rest) < blen - 12:
                return
            ifaces = {}
            continue
        blen = struct.unpack(endian + "I", head[4:8])[0]
        if blen < 12 or blen > 0x0400_0000:
            return
        body = _read_exact(fh, blen - 12)
        if len(body) < blen - 12:
            return
        if len(_read_exact(fh, 4)) < 4:
            return
        if btype == 0x00000001 and len(body) >= 8:  # interface description
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            ifaces[len(ifaces)] = (linktype, _if_tsresol(body[8:], endian))
        elif btype == 0x00000006 and len(body) >= 20:  # enhanced packet
            iface_id, ts_hi, ts_lo, cap_len = struct.unpack(endian + "IIII", body[0:16])
            linktype, divisor = ifaces.get(iface_id, (DLT_EN10MB, 1e6))
            yield (((ts_hi << 32) | ts_lo) / divisor, linktype, body[20 : 20 + cap_len])
        elif btype == 0x00000003 and len(body) >= 4:  # simple packet
            linktype, _div = ifaces.get(0, (DLT_EN10MB, 1e6))
            yield (0.0, linktype, body[4:])


def _if_tsresol(options: bytes, endian: str) -> float:
    """Reads the if_tsresol option (code 9) out of an IDB's option list."""
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[off : off + 4])
        val = options[off + 4 : off + 4 + length]
        if code == 0:
            break
        if code == 9 and val:
            raw = val[0]
            if raw & 0x80:
                return float(1 << (raw & 0x7F))
            return float(10**raw)
        off += 4 + ((length + 3) & ~3)
    return 1e6


# --------------------------------------------------------------------------
# Link and network layers
# --------------------------------------------------------------------------


def _strip_link(linktype: int, frame: bytes):
    """Returns (ethertype_or_None, ip_bytes) for the frame."""
    if linktype == DLT_EN10MB:
        if len(frame) < 14:
            return (None, b"")
        etype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        while etype in ETH_VLAN and len(frame) >= off + 4:
            etype = struct.unpack("!H", frame[off + 2 : off + 4])[0]
            off += 4
        return (etype, frame[off:])
    if linktype in (DLT_NULL, DLT_LOOP):
        if len(frame) < 4:
            return (None, b"")
        fam_le = struct.unpack("<I", frame[:4])[0]
        fam_be = struct.unpack(">I", frame[:4])[0]
        fam = fam_le if fam_le in (2, 24, 28, 30) else fam_be
        etype = ETH_IPV4 if fam == 2 else ETH_IPV6 if fam in (24, 28, 30) else None
        return (etype, frame[4:])
    if linktype == DLT_LINUX_SLL:
        if len(frame) < 16:
            return (None, b"")
        return (struct.unpack("!H", frame[14:16])[0], frame[16:])
    if linktype == DLT_LINUX_SLL2:
        if len(frame) < 20:
            return (None, b"")
        return (struct.unpack("!H", frame[0:2])[0], frame[20:])
    if linktype in (DLT_RAW, DLT_RAW_BSD, DLT_RAW_OPENBSD):
        if not frame:
            return (None, b"")
        version = frame[0] >> 4
        return (ETH_IPV4 if version == 4 else ETH_IPV6 if version == 6 else None, frame)
    if linktype == DLT_IPV4:
        return (ETH_IPV4, frame)
    if linktype == DLT_IPV6:
        return (ETH_IPV6, frame)
    return (None, b"")


def _ipv4(data: bytes):
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total = struct.unpack("!H", data[2:4])[0]
    frag = struct.unpack("!H", data[6:8])[0]
    if (frag & 0x1FFF) != 0:
        return None  # a non-first fragment carries no transport header
    proto = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    body = data[ihl:total] if 0 < total <= len(data) else data[ihl:]
    return (proto, src, dst, body)


def _ipv6(data: bytes):
    if len(data) < 40:
        return None
    plen = struct.unpack("!H", data[4:6])[0]
    nxt = data[6]
    src = _ipv6_str(data[8:24])
    dst = _ipv6_str(data[24:40])
    body = data[40 : 40 + plen] if plen and 40 + plen <= len(data) else data[40:]
    hops = 0
    while nxt in IPV6_SKIP and len(body) >= 8 and hops < 8:
        ext_len = 8 if nxt == 44 else (body[1] + 1) * 8
        nxt = body[0]
        body = body[ext_len:]
        hops += 1
    return (nxt, src, dst, body)


def _ipv6_str(raw: bytes) -> str:
    groups = ["%x" % struct.unpack("!H", raw[i : i + 2])[0] for i in range(0, 16, 2)]
    return "[" + ":".join(groups) + "]"


def packets(path: str) -> Iterator[Packet]:
    """Yields every UDP and TCP payload in the capture, in capture order."""
    for ts, linktype, frame in _raw_records(path):
        try:
            etype, ip_bytes = _strip_link(linktype, frame)
            if etype == ETH_IPV4:
                parsed = _ipv4(ip_bytes)
            elif etype == ETH_IPV6:
                parsed = _ipv6(ip_bytes)
            else:
                continue
            if parsed is None:
                continue
            proto, src, dst, body = parsed
            if proto == IPPROTO_UDP:
                if len(body) < 8:
                    continue
                sport, dport, ulen = struct.unpack("!HHH", body[0:6])
                payload = body[8:ulen] if 8 <= ulen <= len(body) else body[8:]
                if payload:
                    yield Packet(ts, proto, src, sport, dst, dport, payload)
            elif proto == IPPROTO_TCP:
                if len(body) < 20:
                    continue
                sport, dport, seq = struct.unpack("!HHI", body[0:8])
                offset = (body[12] >> 4) * 4
                if offset < 20 or len(body) < offset:
                    continue
                flags = body[13]
                yield Packet(
                    ts,
                    proto,
                    src,
                    sport,
                    dst,
                    dport,
                    body[offset:],
                    tcp_seq=seq,
                    tcp_fin=bool(flags & 0x01),
                    tcp_syn=bool(flags & 0x02),
                )
        except (struct.error, IndexError, ValueError):
            # Garbage in, nothing out: a malformed frame never stops the walk.
            continue


class TcpStream:
    """Reassembles one direction of one TCP flow into a byte stream.

    Segments arriving out of order are held until the gap fills; a retransmit
    that overlaps already-delivered data is trimmed. The stream never blocks
    forever: `flush_gap()` gives up on a missing segment and resyncs, which the
    KNXnet/IP framer recovers from by scanning for the next `06 10` header.
    """

    def __init__(self) -> None:
        self.next_seq: Optional[int] = None
        self.pending = {}

    def add(self, seq: int, data: bytes) -> bytes:
        """Adds one segment; returns the newly contiguous bytes (possibly b'')."""
        if not data:
            return b""
        if self.next_seq is None:
            self.next_seq = seq
        if _seq_lt(seq, self.next_seq):
            skip = (self.next_seq - seq) & 0xFFFF_FFFF
            if skip >= len(data):
                return b""  # a pure retransmit of already-delivered bytes
            seq, data = self.next_seq, data[skip:]
        self.pending[seq] = data
        out = bytearray()
        while True:
            seg = self.pending.pop(self.next_seq, None)
            if seg is None:
                break
            out += seg
            self.next_seq = (self.next_seq + len(seg)) & 0xFFFF_FFFF
        return bytes(out)

    def flush_gap(self) -> bytes:
        """Drops the wait for a missing segment and delivers what is buffered."""
        if not self.pending:
            return b""
        first = min(self.pending)
        self.next_seq = first
        return self.add(first, self.pending.pop(first))


def _seq_lt(a: int, b: int) -> bool:
    return a != b and ((b - a) & 0xFFFF_FFFF) < 0x8000_0000
