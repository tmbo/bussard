"""Normalization: turn a frame stream into a per-target-device operation sequence.

A chronological trace is what you read when something looks wrong. A *normalized*
sequence is what you diff. Normalizing throws away everything that legitimately
differs between two downloads of the same application:

  - timing, and the absolute order of frames belonging to different devices
  - the KNXnet/IP layer entirely (tunnel channel ids, sequence counters, ACKs)
  - Layer 4 sequence numbers and T_ACK/T_NAK traffic
  - L_Data.con echoes of an L_Data.req
  - repeats (the KNX repeat flag) and retransmissions of an identical TPDU

and keeps everything that is the actual programming of the device: load events
per interface object, allocation records, memory writes (as address / length /
content hash), verify reads, restarts, address writes and secure envelopes.

The same normalizer runs over a capture file and over the committed
`knx-sim/tests/fixtures/*_flash_requests.txt` TPDU streams, so a fixture can be
diffed against a live capture without a second code path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from knxip import (
    Apdu,
    KnxFrame,
    decode_npdu,
    ia_str,
    parse_ia,
    sha8,
)

# Op kinds, in the order a download uses them. The names are the diff's
# vocabulary: a report never mentions an APCI number where a kind will do.
KIND_CONNECT = "connect"
KIND_DISCONNECT = "disconnect"
KIND_DESCRIPTOR = "descriptor"
KIND_AUTHORIZE = "authorize"
KIND_LOAD_EVENT = "load-event"
KIND_ALLOC = "alloc-record"
KIND_PROP_WRITE = "prop-write"
KIND_PROP_READ = "prop-read"
KIND_PROP_DESC_READ = "prop-desc-read"
KIND_MEM_WRITE = "mem-write"
KIND_MEM_READ = "mem-read"
KIND_RESTART = "restart"
KIND_IA_WRITE = "ia-write"
KIND_GROUP = "group-value"
KIND_SECURE = "secure-data"
KIND_OTHER = "other"

# Kinds that are pure session plumbing: a difference in how many times these
# appear is connection cycling, never a programming difference.
LIFECYCLE_KINDS = frozenset({KIND_CONNECT, KIND_DISCONNECT})

# Kinds whose relative order carries no meaning (they are reads, or they address
# independent objects), so a reordering of them alone is benign.
COMMUTATIVE_KINDS = frozenset(
    {KIND_PROP_READ, KIND_PROP_DESC_READ, KIND_MEM_READ, KIND_DESCRIPTOR}
)

MEMORY_KINDS = frozenset({KIND_MEM_WRITE})


@dataclass
class Op:
    """One normalized operation aimed at (or answered by) one device."""

    kind: str
    key: str
    detail: Dict[str, object] = field(default_factory=dict)
    direction: str = "req"  # "req" (tool -> device) or "res" (device -> tool)
    ts: float = 0.0
    index: int = 0
    data: bytes = b""

    @property
    def signature(self) -> Tuple[str, str, str]:
        """What the differ compares: kind, identity, and a content fingerprint."""
        return (self.kind, self.key, self.content_sig())

    def content_sig(self) -> str:
        """A fingerprint of the payload that distinguishes two like ops."""
        if self.kind in (KIND_MEM_WRITE, KIND_PROP_WRITE, KIND_ALLOC, KIND_LOAD_EVENT):
            return "len=%d/%s" % (len(self.data), sha8(self.data)) if self.data else "-"
        if self.kind == KIND_SECURE:
            # The sequence number legitimately advances between two runs, so it
            # must not make every secure op look different. Length and the
            # security-control field are the comparable parts.
            return "scf=%s/len=%s" % (
                self.detail.get("scf", "?"),
                self.detail.get("protected_len", "?"),
            )
        if self.kind == KIND_RESTART:
            return str(self.detail.get("type", "basic"))
        if self.kind == KIND_MEM_READ:
            return "count=%s" % self.detail.get("count", "?")
        return "-"

    def describe(self) -> str:
        bits = []
        for k, v in self.detail.items():
            if k in ("data",):
                continue
            bits.append("%s=%s" % (k, v))
        return "%s %s%s" % (self.kind, self.key, (" " + " ".join(bits)) if bits else "")


@dataclass
class MemRegion:
    """A run of memory writes that ended up contiguous, however it was chunked."""

    start: int
    data: bytearray

    @property
    def end(self) -> int:
        return self.start + len(self.data)

    @property
    def sha(self) -> str:
        return sha8(bytes(self.data))

    def __str__(self) -> str:
        return "0x%06x..0x%06x len=%d sha=%s" % (
            self.start,
            self.end,
            len(self.data),
            self.sha,
        )


@dataclass
class DeviceOps:
    """The normalized operation sequence for one target device."""

    device: str
    ops: List[Op] = field(default_factory=list)
    dropped_repeats: int = 0
    dropped_confirms: int = 0
    dropped_acks: int = 0

    def requests(self) -> List[Op]:
        return [o for o in self.ops if o.direction == "req"]

    def signatures(self) -> List[Tuple[str, str, str]]:
        return [o.signature for o in self.requests()]

    def memory_image(self) -> List[MemRegion]:
        """Coalesces every memory write into contiguous regions.

        Two downloads that split the same image into different chunk sizes
        produce the same regions, which is exactly the benign case the diff must
        not report as a difference.
        """
        writes: List[Tuple[int, bytes]] = []
        for op in self.ops:
            if op.direction != "req" or op.kind != KIND_MEM_WRITE:
                continue
            addr = op.detail.get("addr_int")
            if isinstance(addr, int) and op.data:
                writes.append((addr, op.data))
        return coalesce(writes)

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for op in self.requests():
            out[op.kind] = out.get(op.kind, 0) + 1
        return out


def coalesce(writes: Iterable[Tuple[int, bytes]]) -> List[MemRegion]:
    """Merges (address, bytes) writes into contiguous regions.

    Later writes to the same address win, which mirrors the device: a rewritten
    octet holds what was written last.
    """
    flat: Dict[int, int] = {}
    for addr, data in writes:
        for i, b in enumerate(data):
            flat[addr + i] = b
    regions: List[MemRegion] = []
    current: Optional[MemRegion] = None
    for addr in sorted(flat):
        if current is not None and addr == current.end:
            current.data.append(flat[addr])
            continue
        current = MemRegion(addr, bytearray([flat[addr]]))
        regions.append(current)
    return regions


# --------------------------------------------------------------------------
# APDU -> Op
# --------------------------------------------------------------------------


def op_from_apdu(apdu: Apdu, direction: str, ts: float) -> Optional[Op]:
    """Maps one decoded APDU onto a normalized op, or None to drop it."""
    name = apdu.name
    f = apdu.fields

    if name.startswith("A_DeviceDescriptor"):
        return Op(KIND_DESCRIPTOR, "type%s" % f.get("type", "?"), dict(f), direction, ts)

    if name.startswith("A_Authorize") or name.startswith("A_Key"):
        return Op(KIND_AUTHORIZE, name.replace("A_", ""), dict(f), direction, ts)

    if name.startswith("A_PropertyValue"):
        obj = f.get("obj")
        pid = f.get("pid")
        key = "obj%s/%s" % (obj, f.get("pid_name", pid))
        data = bytes.fromhex(str(f.get("data", ""))) if f.get("data") else b""
        if name == "A_PropertyValue_Write" and pid == 5:  # PID_LOAD_STATE_CONTROL
            kind = KIND_ALLOC if "ld_ctrl" in f else KIND_LOAD_EVENT
            detail = {
                "event": f.get("load_event", "?"),
                "index": f.get("index", 1),
            }
            if "ld_ctrl" in f:
                detail["ctrl"] = f["ld_ctrl"]
                for extra in (
                    "seg_addr",
                    "seg_size",
                    "access",
                    "mem_type",
                    "fill",
                    "fill_byte",
                    "ld_ctrl_data",
                ):
                    if extra in f:
                        detail[extra] = f[extra]
            return Op(kind, key, detail, direction, ts, data=data)
        if name == "A_PropertyValue_Read":
            return Op(
                KIND_PROP_READ,
                key,
                {"count": f.get("count"), "index": f.get("index")},
                direction,
                ts,
            )
        detail = {"count": f.get("count"), "index": f.get("index")}
        if "load_state" in f:
            detail["load_state"] = f["load_state"]
        if "table_ref" in f:
            detail["table_ref"] = f["table_ref"]
        if data:
            detail["len"] = len(data)
            detail["sha"] = sha8(data)
        kind = KIND_PROP_WRITE if name == "A_PropertyValue_Write" else KIND_PROP_READ
        # A response carrying a value is the read-back, not a write.
        if name == "A_PropertyValue_Response":
            kind = KIND_PROP_READ
        return Op(kind, key, detail, direction, ts, data=data)

    if name.startswith("A_PropertyDescription"):
        key = "obj%s/%s" % (f.get("obj"), f.get("pid_name", f.get("pid")))
        return Op(KIND_PROP_DESC_READ, key, dict(f), direction, ts)

    if name in ("A_Memory_Write", "A_MemoryExtended_Write"):
        data = bytes.fromhex(str(f.get("data", ""))) if f.get("data") else b""
        addr = _addr_int(f.get("addr"))
        return Op(
            KIND_MEM_WRITE,
            "%s" % f.get("addr", "?"),
            {
                "addr_int": addr,
                "len": len(data),
                "sha": sha8(data) if data else "-",
                "extended": name.startswith("A_MemoryExtended"),
            },
            direction,
            ts,
            data=data,
        )

    if name in ("A_Memory_Read", "A_MemoryExtended_Read"):
        return Op(
            KIND_MEM_READ,
            "%s" % f.get("addr", "?"),
            {"addr_int": _addr_int(f.get("addr")), "count": f.get("count")},
            direction,
            ts,
        )

    if name in (
        "A_Memory_Response",
        "A_MemoryExtended_Read_Response",
        "A_MemoryExtended_Write_Response",
    ):
        data = bytes.fromhex(str(f.get("data", ""))) if f.get("data") else b""
        return Op(
            KIND_MEM_READ,
            "%s" % f.get("addr", "?"),
            {
                "addr_int": _addr_int(f.get("addr")),
                "len": len(data),
                "sha": sha8(data) if data else "-",
                "response": True,
            },
            direction,
            ts,
            data=data,
        )

    if name in ("A_Restart", "A_Restart_Response"):
        return Op(KIND_RESTART, name.replace("A_", ""), dict(f), direction, ts)

    if name.startswith("A_IndividualAddress"):
        return Op(KIND_IA_WRITE, name.replace("A_", ""), dict(f), direction, ts)

    if name.startswith("A_GroupValue"):
        return Op(KIND_GROUP, name.replace("A_GroupValue_", ""), dict(f), direction, ts)

    if name == "A_SecureData":
        return Op(KIND_SECURE, str(f.get("service", "S-A_Data")), dict(f), direction, ts)

    return Op(KIND_OTHER, name, dict(f), direction, ts, data=apdu.payload)


def _addr_int(text: object) -> Optional[int]:
    if isinstance(text, str) and text.startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------
# Frame stream -> DeviceOps
# --------------------------------------------------------------------------


def normalize(
    frames: Iterable[KnxFrame], device: Optional[str] = None
) -> Dict[str, DeviceOps]:
    """Groups a frame stream into one normalized sequence per target device.

    `device` restricts the walk to a single individual address. Without it every
    point-to-point peer in the capture gets its own sequence; group traffic is
    collected under the pseudo-device `group`.
    """
    out: Dict[str, DeviceOps] = {}
    last_npdu: Dict[str, bytes] = {}
    counter = 0

    for frame in frames:
        cemi = frame.cemi
        if cemi is None or cemi.l4 is None:
            continue
        l4 = cemi.l4

        if cemi.dst_is_group:
            target = "group"
            direction = "req"
        else:
            # The peer that is not the tool: a request names the device as
            # destination, a response names it as source.
            if cemi.mc == 0x29 or (cemi.mc != 0x11 and cemi.src not in ("0.0.0", "")):
                target, direction = cemi.src, "res"
            else:
                target, direction = cemi.dst, "req"
            if cemi.mc == 0x11:
                target, direction = cemi.dst, "req"

        if device is not None and target != device:
            continue

        bucket = out.get(target)
        if bucket is None:
            bucket = out[target] = DeviceOps(target)

        # L_Data.con is the gateway echoing back the L_Data.req we already have.
        if cemi.mc == 0x2E:
            bucket.dropped_confirms += 1
            continue
        # The repeat flag marks a link-layer retransmission of the same TPDU.
        if cemi.repeated and last_npdu.get(target + direction) == cemi.npdu:
            bucket.dropped_repeats += 1
            continue
        last_npdu[target + direction] = cemi.npdu

        counter += 1
        op = _op_from_l4(l4, direction, frame.ts)
        if op is None:
            bucket.dropped_acks += 1
            continue
        op.index = counter
        bucket.ops.append(op)

    return out


def _op_from_l4(l4, direction: str, ts: float) -> Optional[Op]:
    if l4.kind == "T_Connect":
        return Op(KIND_CONNECT, "T_Connect", {}, direction, ts)
    if l4.kind == "T_Disconnect":
        return Op(KIND_DISCONNECT, "T_Disconnect", {}, direction, ts)
    if l4.kind in ("T_ACK", "T_NAK"):
        return None  # L4 acknowledgement: plumbing, never a programming step
    if l4.apdu is None:
        return None
    return op_from_apdu(l4.apdu, direction, ts)


# --------------------------------------------------------------------------
# TPDU fixture streams
# --------------------------------------------------------------------------


def normalize_tpdu_file(path: str, device: Optional[str] = None) -> Dict[str, DeviceOps]:
    """Normalizes a `<src_hex> <dst_hex> <tpdu_hex>` fixture, as knx-sim ships.

    These files are request-direction only, which is why they make good
    normalizer fixtures: what comes out is exactly the request sequence a live
    capture of the same download must reduce to.
    """
    out: Dict[str, DeviceOps] = {}
    counter = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                dst = ia_str(int(parts[1], 16))
                tpdu = bytes.fromhex(parts[2])
            except ValueError:
                continue
            if device is not None and dst != device:
                continue
            l4 = decode_npdu(tpdu)
            if l4 is None:
                continue
            bucket = out.get(dst)
            if bucket is None:
                bucket = out[dst] = DeviceOps(dst)
            op = _op_from_l4(l4, "req", 0.0)
            if op is None:
                bucket.dropped_acks += 1
                continue
            counter += 1
            op.index = counter
            bucket.ops.append(op)
    return out


def resolve_device(buckets: Dict[str, DeviceOps], device: Optional[str]) -> DeviceOps:
    """Picks the sequence to work with, with a useful error when it is ambiguous."""
    if device is not None:
        if parse_ia(device) is None:
            raise SystemExit("not an individual address: %s" % device)
        found = buckets.get(device)
        if found is None:
            raise SystemExit(
                "no operations for %s (devices seen: %s)"
                % (device, ", ".join(sorted(buckets)) or "none")
            )
        return found
    real = {k: v for k, v in buckets.items() if k != "group" and parse_ia(k)}
    if len(real) == 1:
        return next(iter(real.values()))
    raise SystemExit(
        "several devices in this capture, pass --device: %s"
        % (", ".join(sorted(real)) or "none")
    )
