"""Memory images: what a download wrote, and how it compares to bussard's plan.

`compose` turns one device's normalized operation sequence into the memory it
wrote: one region per contiguous run of `A_Memory_Write`/`A_MemoryExtended_Write`
octets (later writes win, like the device), plus the segment allocation records
seen along the way. A System B `LdCtrlRelSegment` does not name an address; the
device picks the base and the tool reads it back as `PID_TABLE_REFERENCE`, so
the first table reference read for that object after the allocation is taken as
its base. An allocation with the fill flag set is fully determined even where
nothing was written (the device pre-fills it), so it is also composed as
fill + sparse writes.

`property_writes` lists the property writes of the same download
(`A_PropertyValue_Write`, `A_PropertyExtValue_WriteCon`/`_WriteUnCon`,
`A_FunctionPropertyExt_Command`), decrypted when the capture was read with a
keyring; `compose` writes them as `properties.json`. A value that may be key
material (see `datasecure.is_key_material`: the key PIDs or anything key-sized
on the security object, type 17) is reduced to `redacted:<sha256[:8]>` and its
length, so the file can be shared like the rest of the image directory.

`compare` diffs a `bussard flash --dry-run --dump-images` directory against a
composed image directory, one bussard image at a time: identical, differs (how
many octets, the first differing offset, both hex excerpts), or not comparable
(and why). It then aligns bussard's property-write steps with
`properties.json`: the same sequence of (object, PID, length), and equal
values where both sides carry one (bytes, or the hash when redacted). That
parity gets its own verdict next to the image verdict. This is the offline
conformance oracle of the physical campaign (issue #89).

Read-compare downloads (issue #384): a mask 0701 device that ETS already
programmed is not loaded again. ETS reads its memory, writes only the octets
that differ from its image, and restarts, so the capture holds few written
octets. Every octet ETS read (`A_Memory_Response`, a successful
`A_MemoryExtended_Read_Response`) and did not write anywhere in the capture is
*read-confirmed*: ETS's image equals what the device answered. `compose` writes
those as `confirmed/0x<addr>.bin` next to the written regions (the last read
wins), and `compare` checks bussard's planned octets against them separately
from the written ones, with its own coverage and verdict. An octet ETS wrote
is a written octet only, even when ETS read it before or after the write: the
written value is ETS's image, and a read-back may differ from it (the
Meteodata 1.1.202 clears its `0x4800+0` marker after ETS writes `0xAA`).

Load control (issue #419): `compose` also writes `load_controls.json`, every
record ETS sent a load-state machine, in order: the 10-octet
`PID_LOAD_STATE_CONTROL` value of an `A_PropertyValue_Write` on an
index-addressed object, and the 11-octet System 7 record an `A_Memory_Write`
puts at the LSM control address 0x0104. `compare` checks them against the
`load_controls` bussard's dry run lists per step and reports a third verdict
next to the memory and the property verdicts. The rule:

- Records are grouped per load-state object (the object index, which is the
  LSM index on System 7, in either form) and compared in order within it.
  How the objects interleave is not judged: ETS and bussard both drive one
  object at a time, but the pre-download unloads and the System B
  allocate-all-then-write template order the objects differently, and the
  device keeps one state machine per object.
- An immediate repeat of the same record on the same object counts once: the
  pre-download unload followed by the procedure's own unload, or a write the
  tool sent again, leaves the machine where one record does.
- Reads (a PID 5 read, a System 7 status read) are not records.
- Every octet counts, and the form too: a property record never matches a
  memory record.
- A bussard object index the plan leaves to the device (System B, no LsmIdx)
  pairs with the one ETS object no other bussard sequence claims.

The verdict is `identical`, `differs` (the first differing record of the
first differing object, both hex records, plus every difference), or
`not-comparable` (ETS sent no load-control record, or the dump predates the
`load_controls` field).

A diff is only as strong as what it compared. `compare` also reports the
coverage (issue #347): of the octets bussard places, how many the capture
holds a value for. A region's placed octets are the ones a parameter placement
wrote (the dump's `placed` record) when the image carries one, else every
octet bussard writes (all of a table or code image, or its `0xFF` mask
octets). Coverage is counted per region and per memory page (256 octets by
default). A row whose images match but whose coverage is below the threshold
(50 % of the placed octets by default), or that has a page with placed octets
and none compared, is "not comparable" (thin), never "identical": ETS
read-compared or skipped what the device already held, so the capture carries
no evidence for those octets.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import struct
from typing import Dict, List, Optional, Tuple

from datasecure import PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, SECURITY_OBJECT_TYPE, is_key_material
from normalize import KIND_ALLOC, KIND_MEM_WRITE, DeviceOps, coalesce

# LdCtrl subtypes of an `AdditionalLoadControls` (event 3) record.
SUB_S7_ALLOC = 0x00  # System 7 property-based AbsSegment: [3][0][start:2][len:2][acc][mem][cs][0]
SUB_ABS_SEGMENT = 0x01  # System B LdCtrlAbsSegment: [3][1][addr:4][len:2][acc][mem]...
SUB_REL_SEGMENT = 0x0B  # LdCtrlRelSegment: [3][0x0B][size:4][fill:1][fill_byte:1]

IDENTICAL = "identical"
DIFFERS = "differs"
NOT_COMPARABLE = "not-comparable"

EXCERPT = 8  # octets shown on each side of a first difference

# The coverage rule of issue #347: a matching row is "identical" only when at
# least this share of the placed octets was compared and no page with placed
# octets went uncompared.
DEFAULT_MIN_COVERAGE = 50.0
DEFAULT_PAGE_SIZE = 256

# Short region names, as the oracle summary and `--scope` spell them.
_SHORT = {
    "address table": "addr",
    "association table": "assoc",
    "group-object table": "gobj",
    "parameters": "par",
}


def region_short(name: str) -> str:
    """`addr`, `assoc`, `gobj`, `par`, `seg0x4800`, `app(obj4)`: a region's short name."""
    return _SHORT.get(
        name, name.replace("app segment ", "seg").replace("application ", "app")
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _obj_of(key: str) -> Optional[int]:
    """`obj4/PID_...` -> 4."""
    head = key.split("/", 1)[0]
    if head.startswith("obj"):
        try:
            return int(head[3:])
        except ValueError:
            return None
    return None


def _table_ref(op) -> Optional[int]:
    ref = op.detail.get("table_ref")
    if isinstance(ref, str):
        try:
            return int(ref, 16)
        except ValueError:
            return None
    return None


def allocations(ops: DeviceOps) -> List[Dict[str, object]]:
    """The segment allocation records of a download, in order, with bases."""
    out: List[Dict[str, object]] = []
    pending: Dict[int, Dict[str, object]] = {}  # object -> rel-segment awaiting its base
    for op in ops.ops:
        obj = _obj_of(op.key)
        if op.direction == "res" and "table_ref" in op.detail:
            if obj is not None and obj in pending:
                pending.pop(obj)["base"] = _table_ref(op)
            continue
        if op.direction != "req" or op.kind != KIND_ALLOC:
            continue
        data = op.data
        if len(data) < 2 or data[0] != 3:
            continue
        sub = data[1]
        if sub == SUB_REL_SEGMENT and len(data) >= 8:
            rec = {
                "kind": "rel-segment",
                "object": obj,
                "size": struct.unpack("!I", data[2:6])[0],
                "fill": bool(data[6]),
                "fill_byte": data[7],
                "base": None,
            }
            if obj is not None:
                pending[obj] = rec
            out.append(rec)
        elif sub == SUB_S7_ALLOC and len(data) >= 9:
            out.append(
                {
                    "kind": "abs-segment",
                    "lsm": obj,
                    "address": struct.unpack("!H", data[2:4])[0],
                    "size": struct.unpack("!H", data[4:6])[0],
                    "access": data[6],
                    "mem_type": data[7],
                    "checksum_ctrl": data[8],
                }
            )
        elif sub == SUB_ABS_SEGMENT and len(data) >= 10:
            out.append(
                {
                    "kind": "abs-segment",
                    "object": obj,
                    "address": struct.unpack("!I", data[2:6])[0],
                    "size": struct.unpack("!H", data[6:8])[0],
                    "access": data[8],
                    "mem_type": data[9],
                }
            )
    return out


def table_refs(ops: DeviceOps) -> Dict[int, int]:
    """The last `PID_TABLE_REFERENCE` read per object (object -> base)."""
    out: Dict[int, int] = {}
    for op in ops.ops:
        if op.direction == "res" and "table_ref" in op.detail:
            obj = _obj_of(op.key)
            ref = _table_ref(op)
            if obj is not None and ref is not None:
                out[obj] = ref
    return out


# Responses that carry memory the device holds (an extended write response
# carries a return code and maybe a CRC, never memory).
MEMORY_READ_RESPONSES = ("A_Memory_Response", "A_MemoryExtended_Read_Response")


def memory_reads(ops: DeviceOps) -> List[Tuple[int, bytes]]:
    """Every memory read response the device sent the tool, in order."""
    reads = []
    for op in ops.ops:
        apdu = op.apdu
        if op.direction != "res" or apdu is None or apdu.name not in MEMORY_READ_RESPONSES:
            continue
        if apdu.name == "A_MemoryExtended_Read_Response" and apdu.fields.get("rc") != "0x00":
            continue
        addr = op.detail.get("addr_int")
        if isinstance(addr, int) and op.data:
            reads.append((addr, op.data))
    return reads


def confirmed_octets(ops: DeviceOps) -> Dict[int, int]:
    """The read-confirmed octets (see the module doc): address -> the value
    the device answered last, for every octet read and never written."""
    written = {addr + i for addr, data in memory_writes(ops) for i in range(len(data))}
    out: Dict[int, int] = {}
    for addr, data in memory_reads(ops):
        for i, b in enumerate(data):
            if addr + i not in written:
                out[addr + i] = b
    return out


def _runs(octets: Dict[int, int]) -> List[Tuple[int, bytes]]:
    """Contiguous runs of an address -> octet map."""
    runs: List[Tuple[int, bytearray]] = []
    for addr in sorted(octets):
        if runs and runs[-1][0] + len(runs[-1][1]) == addr:
            runs[-1][1].append(octets[addr])
        else:
            runs.append((addr, bytearray([octets[addr]])))
    return [(start, bytes(data)) for start, data in runs]


def memory_writes(ops: DeviceOps) -> List[Tuple[int, bytes]]:
    writes = []
    for op in ops.ops:
        if op.direction != "req" or op.kind != KIND_MEM_WRITE:
            continue
        addr = op.detail.get("addr_int")
        if isinstance(addr, int) and op.data:
            writes.append((addr, op.data))
    return writes


# Property services whose request writes a value. Header octets before the
# value: plain (obj, pid, count/index:2), extended value (type:2, inst/pid:3,
# count, index:2), extended function property (type:2, inst/pid:3).
PROPERTY_WRITE_SERVICES = {
    "A_PropertyValue_Write": 4,
    "A_PropertyExtValue_WriteCon": 8,
    "A_PropertyExtValue_WriteUnCon": 8,
    "A_FunctionPropertyExt_Command": 5,
    # cEMI local device management on a KNXnet/IP device management
    # connection (issue #398): the body after the message code.
    "M_PropWrite.req": 6,
    "M_FuncPropCommand.req": 4,
}
PID_LOAD_STATE_CONTROL = 5


# The offline oracle's per-run salt (issue #378), shared with `bussard flash
# --dry-run --dump-images` through the environment and never written to disk.
ORACLE_SALT_ENV = "BUSSARD_ORACLE_SALT"
PID_GRP_KEY_TABLE = 53
GROUP_KEY_ENTRY_LEN = 18  # group address (2) + key (16)
SENDER_ENTRY_LEN = 8  # individual address (2) + sequence number (6)


def _ga_text(raw: int) -> str:
    return "%d/%d/%d" % ((raw >> 11) & 0x1F, (raw >> 8) & 0x07, raw & 0xFF)


def _ia_text(raw: int) -> str:
    return "%d.%d.%d" % (raw >> 12, (raw >> 8) & 0x0F, raw & 0xFF)


def group_key_entries(data: bytes, salt: str) -> List[Dict[str, object]]:
    """A group key table value as its entries: the address table index the
    entry names and the salted short hash `sha256(salt || key)[:8]` of its
    key, never the key.

    The same form `bussard flash --dump-images` writes under the same salt
    (bussard also adds the group address), so the two sides compare per group
    without either file holding a hash of a bare key. `compare` names the
    ETS entries' groups from the address table ETS wrote.
    """
    out: List[Dict[str, object]] = []
    for i in range(0, len(data) - GROUP_KEY_ENTRY_LEN + 1, GROUP_KEY_ENTRY_LEN):
        entry = data[i:i + GROUP_KEY_ENTRY_LEN]
        out.append(
            {
                "index": struct.unpack(">H", entry[:2])[0],
                "key": sha256(salt.encode() + entry[2:])[:8],
            }
        )
    return out


def _value_field(obj_type: Optional[int], obj_index: Optional[int], pid, data: bytes) -> str:
    if is_key_material(obj_type, obj_index, pid, len(data)):
        return "redacted:%s" % sha256(data)[:8]
    return data.hex()


def property_writes(ops: DeviceOps) -> List[Dict[str, object]]:
    """Every property write the tool sent the device, in order.

    Each entry names the object (`{"index": n}` for the plain services,
    `{"type": t, "instance": i}` for the extended ones), the PID, the element
    count and start index where the service has them, the value length and
    the value: hex, or `redacted:<sha256[:8]>` for possible key material.
    `secured` is the key a decrypted frame verified under, else null.
    """
    out: List[Dict[str, object]] = []
    for op in ops.ops:
        apdu = op.apdu
        if op.direction != "req" or apdu is None or apdu.name not in PROPERTY_WRITE_SERVICES:
            continue
        f = apdu.fields
        if f.get("truncated") or "pid" not in f:
            continue
        data = bytes(apdu.payload[PROPERTY_WRITE_SERVICES[apdu.name]:])
        if "obj_type" in f:
            obj_type, obj_index = int(f["obj_type"]), None
            obj: Dict[str, int] = {"type": obj_type, "instance": int(f.get("instance", 0))}
        else:
            obj_type, obj_index = None, int(f.get("obj", 0))
            obj = {"index": obj_index}
        record = {
            "seq": len(out) + 1,
            "service": apdu.name,
            "object": obj,
            "pid": f["pid"],
            "count": f.get("count"),
            "index": f.get("index"),
            "length": len(data),
            "data": _value_field(obj_type, obj_index, f["pid"], data),
            "secured": op.detail.get("secured"),
        }
        if "keyring" in f:
            # A credential write compared with the keyring (datasecure.
            # annotate_credentials): names only, never a value.
            record["keyring"] = f["keyring"]
        salt = os.environ.get(ORACLE_SALT_ENV)
        if (salt and f["pid"] == PID_GRP_KEY_TABLE
                and is_key_material(obj_type, obj_index, f["pid"], len(data))
                and data and len(data) % GROUP_KEY_ENTRY_LEN == 0):
            record["entries"] = group_key_entries(data, salt)
        out.append(record)
    return out


CONFIRMED_DIR = "confirmed"

# Load control (issue #419): the file `compose` writes, the System 7
# memory-mapped LSM control address and record width (bussard_mgmt
# SYS7_DEFAULT_CONTROL_ADDR, MEMORY_LSM_RECORD_SIZE).
LOAD_CONTROLS_FILE = "load_controls.json"
SYS7_LSM_CONTROL_ADDR = 0x0104
SYS7_LSM_RECORD_LEN = 11


def load_control_writes(ops: DeviceOps) -> List[Dict[str, object]]:
    """Every load-control record the tool sent, in order (see the module doc).

    A property record names its object index, a memory record its LSM (the
    high nibble of its first octet) and the address. `data` is the hex value.
    """
    out: List[Dict[str, object]] = []
    for op in ops.ops:
        apdu = op.apdu
        if op.direction != "req":
            continue
        if apdu is not None and apdu.name == "A_PropertyValue_Write":
            f = apdu.fields
            if f.get("truncated") or f.get("pid") != PID_LOAD_STATE_CONTROL or "obj_type" in f:
                continue
            data = bytes(apdu.payload[PROPERTY_WRITE_SERVICES[apdu.name]:])
            out.append({"seq": len(out) + 1, "form": "property", "object": int(f.get("obj", 0)),
                        "data": data.hex()})
        elif op.kind == KIND_MEM_WRITE and op.detail.get("addr_int") == SYS7_LSM_CONTROL_ADDR \
                and len(op.data) == SYS7_LSM_RECORD_LEN:
            out.append({"seq": len(out) + 1, "form": "memory", "lsm": op.data[0] >> 4,
                        "address": SYS7_LSM_CONTROL_ADDR, "data": op.data.hex()})
    return out


def compose(ops: DeviceOps, out_dir: str, source: str = "") -> Dict[str, object]:
    """Writes the composed image of one device's download into `out_dir`.

    Returns (and writes as `regions.json`) the index: one entry per contiguous
    written region, one per contiguous run of read-confirmed octets (under
    `confirmed/`), the allocation records, and the object bases read back.
    """
    os.makedirs(out_dir, exist_ok=True)
    writes = memory_writes(ops)
    flat: Dict[int, int] = {}
    for addr, data in writes:
        for i, b in enumerate(data):
            flat[addr + i] = b

    regions = []
    for region in coalesce(writes):
        name = "0x%06X.bin" % region.start
        data = bytes(region.data)
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)
        regions.append(
            {"start": region.start, "length": len(data), "sha256": sha256(data), "file": name}
        )

    allocs = allocations(ops)
    for rec in allocs:
        base = rec.get("base") if rec["kind"] == "rel-segment" else rec.get("address")
        if not isinstance(base, int):
            continue
        size = int(rec["size"])
        filled = rec.get("fill") is True
        buf = bytearray([int(rec.get("fill_byte", 0)) if filled else 0] * size)
        written = 0
        for i in range(size):
            b = flat.get(base + i)
            if b is not None:
                buf[i] = b
                written += 1
        rec["written_octets"] = written
        if filled:
            label = "obj%s" % rec.get("object")
            name = "alloc-%s-0x%06X.bin" % (label, base)
            with open(os.path.join(out_dir, name), "wb") as fh:
                fh.write(bytes(buf))
            rec["composed_file"] = name

    confirmed = []
    runs = _runs(confirmed_octets(ops))
    if runs:
        os.makedirs(os.path.join(out_dir, CONFIRMED_DIR), exist_ok=True)
    for start, data in runs:
        name = "%s/0x%06X.bin" % (CONFIRMED_DIR, start)
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)
        confirmed.append(
            {"start": start, "length": len(data), "sha256": sha256(data), "file": name}
        )

    with open(os.path.join(out_dir, LOAD_CONTROLS_FILE), "w", encoding="utf-8") as fh:
        json.dump(load_control_writes(ops), fh, indent=2)
        fh.write("\n")

    props = property_writes(ops)
    with open(os.path.join(out_dir, "properties.json"), "w", encoding="utf-8") as fh:
        json.dump(props, fh, indent=2)
        fh.write("\n")

    index = {
        "device": ops.device,
        "source": os.path.basename(source),
        "regions": regions,
        "confirmed": confirmed,
        "allocations": allocs,
        "table_refs": {str(k): v for k, v in sorted(table_refs(ops).items())},
        "property_writes": len(props),
    }
    with open(os.path.join(out_dir, "regions.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)
        fh.write("\n")
    return index


# --------------------------------------------------------------------------
# compare
# --------------------------------------------------------------------------


class EtsMemory:
    """What an ETS download is known to have left in device memory."""

    def __init__(self, image_dir: str):
        with open(os.path.join(image_dir, "regions.json"), encoding="utf-8") as fh:
            self.index = json.load(fh)
        self.written: Dict[int, int] = {}
        for region in self.index["regions"]:
            with open(os.path.join(image_dir, region["file"]), "rb") as fh:
                data = fh.read()
            for i, b in enumerate(data):
                self.written[region["start"] + i] = b
        # Octets a fill-flagged allocation determines without a write.
        self.filled: Dict[int, int] = {}
        for rec in self.index["allocations"]:
            if rec.get("kind") == "rel-segment" and rec.get("fill") and isinstance(
                rec.get("base"), int
            ):
                for i in range(int(rec["size"])):
                    self.filled[rec["base"] + i] = int(rec.get("fill_byte", 0))
        # Read-confirmed octets (never written in the capture).
        self.confirmed: Dict[int, int] = {}
        for region in self.index.get("confirmed", []):
            with open(os.path.join(image_dir, region["file"]), "rb") as fh:
                data = fh.read()
            for i, b in enumerate(data):
                if region["start"] + i not in self.written:
                    self.confirmed[region["start"] + i] = b
        self.bases = {int(k): v for k, v in self.index.get("table_refs", {}).items()}
        # The base read back right after each object's allocation wins over a
        # stale read taken before the download.
        for rec in self.index["allocations"]:
            if rec.get("kind") == "rel-segment" and isinstance(rec.get("base"), int):
                self.bases[int(rec["object"])] = rec["base"]

    def get(self, addr: int) -> Optional[int]:
        b = self.written.get(addr)
        return b if b is not None else self.filled.get(addr)


def _region_name(plan: dict, step: dict) -> str:
    """A human name for what a bussard image is (tables by object / LSM)."""
    image = step["image"]
    kind = image["image_kind"]
    if kind == "table":
        if plan.get("system") == "7":
            for t in plan.get("tables", []):
                if t.get("step") == step["index"]:
                    return {"lsm1": "address table", "lsm2": "association table"}.get(
                        t["name"], t["name"]
                    )
            return "table"
        return {1: "address table", 2: "association table", 3: "group-object table"}.get(
            image.get("object"), "table obj%s" % image.get("object")
        )
    if kind == "parameters":
        return "parameters"
    if plan.get("system") == "7":
        return "app segment 0x%04X" % image["address"]
    return "application (obj%s)" % image.get("object")


def _placed_offsets(image: dict, ours: bytes, mask: Optional[bytes]) -> List[int]:
    """The offsets of `image` the coverage counts (see the module doc)."""
    placed = image.get("placed")
    if placed and placed.get("ranges"):
        return [i for lo, hi in placed["ranges"] for i in range(lo, min(hi, len(ours)))]
    return [i for i in range(len(ours)) if mask is None or i >= len(mask) or mask[i] == 0xFF]


def _page_name(key) -> str:
    if isinstance(key, int):
        return "0x%04X" % key
    return "%s+0x%X" % key


def coverage(
    regions: List[Dict[str, object]],
    min_percent: float = DEFAULT_MIN_COVERAGE,
) -> Dict[str, object]:
    """The row's coverage from its regions' per-page counts."""
    placed = sum(int(r.get("placed", 0)) for r in regions)
    compared = sum(int(r.get("placed_compared", 0)) for r in regions)
    pages = []
    for r in regions:
        for page in r.get("pages", []):
            pages.append(dict(page, region=r["region"]))
    blind = [p for p in pages if p["placed"] and not p["compared"]]
    percent = 100.0 * compared / placed if placed else 0.0
    reasons = []
    if not placed:
        reasons.append("bussard places no octets")
    elif percent < min_percent:
        reasons.append(
            "%d of %d placed octets compared (%.1f %% < %.0f %%)"
            % (compared, placed, percent, min_percent)
        )
    if blind:
        reasons.append(
            "%d page(s) with placed octets and none compared: %s"
            % (len(blind), ", ".join(p["page"] for p in blind[:6]))
        )
    return {
        "placed": placed,
        "compared": compared,
        "percent": round(percent, 1),
        "min_percent": min_percent,
        "pages": len(pages),
        "blind_pages": [p["page"] for p in blind],
        "thin": bool(reasons),
        "reason": "; ".join(reasons),
    }


def compare(
    plan_dir: str,
    image_dir: str,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
    scope: Optional[List[str]] = None,
    phase: Optional[str] = None,
) -> Dict[str, object]:
    """Diffs bussard's dry-run images against the composed ETS image.

    `scope` names the regions (short names, see `region_short`) the verdict
    and the coverage are judged on, for a capture that by design downloads
    only part of the device (a security change rewrites the tables); every
    other region is still diffed and shown, as out of scope. `None` judges all.
    """
    with open(os.path.join(plan_dir, "plan.json"), encoding="utf-8") as fh:
        plan = json.load(fh)
    ets = EtsMemory(image_dir)
    results = []
    covered_addrs = set()
    for step in plan["steps"]:
        image = step.get("image")
        if not image:
            continue
        name = _region_name(plan, step)
        with open(os.path.join(plan_dir, image["file"]), "rb") as fh:
            ours = fh.read()
        mask = None
        if image.get("mask_file"):
            with open(os.path.join(plan_dir, image["mask_file"]), "rb") as fh:
                mask = fh.read()
        placed_offsets = _placed_offsets(image, ours, mask)
        addr = image.get("address")
        if addr is None:
            obj = image.get("object")
            base = ets.bases.get(obj) if obj is not None else None
            if base is None:
                rec = _result(step, name, ours, NOT_COMPARABLE, "no ETS base for object %s" % obj)
                rec["compared"] = 0
                _add_coverage(rec, placed_offsets, set(), None, "obj%s" % obj, page_size)
                results.append(rec)
                continue
            addr = base + int(image.get("offset") or 0)
        compared = diffs = fill_diffs = 0
        first = None
        fill_offsets: List[int] = []
        conf_compared = 0
        conf_mismatches: List[Dict[str, object]] = []
        for i, b in enumerate(ours):
            if mask is not None and i < len(mask) and mask[i] != 0xFF:
                continue
            covered_addrs.add(addr + i)
            read = ets.confirmed.get(addr + i)
            if read is not None:
                conf_compared += 1
                if read != b:
                    conf_mismatches.append(
                        {"address": addr + i, "offset": i, "bussard": "%02x" % b, "ets": "%02x" % read}
                    )
            theirs = ets.get(addr + i)
            if theirs is None:
                continue
            compared += 1
            if theirs != b:
                diffs += 1
                if first is None:
                    first = i
                if (addr + i) not in ets.written:
                    # ETS never wrote this octet: its value is the fill of
                    # the allocation, i.e. ETS's image held the fill there.
                    fill_diffs += 1
                    fill_offsets.append(i)
        rec = _result(step, name, ours, IDENTICAL, "")
        rec["address"] = addr
        rec["compared"] = compared
        known = {i for i in placed_offsets if ets.get(addr + i) is not None}
        _add_coverage(rec, placed_offsets, known, addr, None, page_size)
        conf_known = {i for i in placed_offsets if (addr + i) in ets.confirmed}
        conf_rec: Dict[str, object] = {}
        _add_coverage(conf_rec, placed_offsets, conf_known, addr, None, page_size)
        conf_rec.update(
            {
                "verdict": DIFFERS if conf_mismatches else IDENTICAL if conf_compared
                else NOT_COMPARABLE,
                "compared": conf_compared,
                "diff_octets": len(conf_mismatches),
                "mismatches": conf_mismatches[:MAX_MISMATCHES],
            }
        )
        rec["confirmed"] = conf_rec
        if compared == 0:
            rec["verdict"] = NOT_COMPARABLE
            rec["reason"] = "ETS wrote nothing in 0x%06X..0x%06X" % (addr, addr + len(ours))
        elif diffs:
            lo = max(0, first - EXCERPT)
            hi = min(len(ours), first + EXCERPT)
            theirs = bytes(
                (ets.get(addr + i) if ets.get(addr + i) is not None else 0) for i in range(lo, hi)
            )
            rec.update(
                {
                    "verdict": DIFFERS,
                    "diff_octets": diffs,
                    "first_offset": first,
                    "excerpt_offset": lo,
                    "bussard_hex": ours[lo:hi].hex(),
                    "ets_hex": theirs.hex(),
                    "fill_diff_octets": fill_diffs,
                    "fill_diff_offsets": fill_offsets[:20],
                }
            )
        results.append(rec)

    ets_only = sorted(a for a in ets.written if a not in covered_addrs)
    # The property parity has its own verdict: `verdict` stays the image
    # verdict the pre-flash gate reads, so a known extra property write does
    # not hide whether the memory images match.
    props = compare_properties(plan, image_dir, _ets_groups(plan, results, ets), phase=phase)
    load_controls = compare_load_controls(plan, image_dir)
    for r in results:
        r["in_scope"] = scope is None or region_short(r["region"]) in scope
    judged = [r for r in results if r["in_scope"]]
    verdicts = {r["verdict"] for r in judged}
    cov = coverage(judged, min_coverage)
    cov["scope"] = list(scope) if scope is not None else None
    confirmed = _confirmed_summary(judged, min_coverage, len(ets.confirmed))
    reason = ""
    if DIFFERS in verdicts:
        overall = DIFFERS
    elif IDENTICAL in verdicts and not cov["thin"]:
        overall = IDENTICAL
    else:
        # Matching octets from a thin capture are not evidence (issue #347).
        overall = NOT_COMPARABLE
        reason = "thin: " + cov["reason"] if IDENTICAL in verdicts else "nothing compared"
    if plan.get("system") == IP_SECURE_SYSTEM:
        # `bussard interface secure --dry-run` (issue #398) writes no memory:
        # the property parity is the verdict.
        overall = str(props.get("verdict", NOT_COMPARABLE))
        reason = str(props.get("reason") or "")
    return {
        "device": plan.get("device"),
        "application": plan.get("application", {}).get("id"),
        "system": plan.get("system"),
        "verdict": overall,
        "reason": reason,
        "coverage": cov,
        "confirmed": confirmed,
        "regions": results,
        "ets_only_octets": len(ets_only),
        "ets_only_ranges": _ranges(ets_only)[:20],
        "properties": props,
        "load_controls": load_controls,
    }


MAX_MISMATCHES = 256  # confirmed mismatches kept per region and per row


def _confirmed_summary(
    judged: List[dict], min_coverage: float, total: int
) -> Dict[str, object]:
    """The row's read-confirmed comparison: coverage, verdict and mismatches.

    The coverage is counted like the written one, on the placed octets that
    have a read-confirmed value. The verdict is `differs` on any mismatch,
    else `identical` when the confirmed coverage is not thin, else
    `not-comparable`.
    """
    regions = [dict(r["confirmed"], region=r["region"]) for r in judged if r.get("confirmed")]
    cov = coverage(regions, min_coverage)
    compared = sum(int(r["compared"]) for r in regions)
    diffs = sum(int(r["diff_octets"]) for r in regions)
    mismatches = []
    for r in regions:
        for m in r["mismatches"]:
            mismatches.append(dict(m, region=r["region"]))
    if diffs:
        verdict, reason = DIFFERS, ""
    elif compared and not cov["thin"]:
        verdict, reason = IDENTICAL, ""
    else:
        verdict = NOT_COMPARABLE
        reason = "thin: " + cov["reason"] if compared else "no read-confirmed octet in the images"
    return dict(
        cov,
        verdict=verdict,
        reason=reason,
        octets=compared,
        diff_octets=diffs,
        mismatches=mismatches[:MAX_MISMATCHES],
        capture_octets=total,
    )


def _ets_groups(plan: dict, results: List[dict], ets: "EtsMemory") -> Dict[int, str]:
    """Address table index to group address, read from the address table
    ETS wrote at the place bussard's address table goes (System B: a 2-octet
    count, then one 2-octet group address per entry, index 1 first). Empty
    when the plan is not System B or ETS did not write the table.
    """
    if plan.get("system") != "B":
        return {}
    for r in results:
        if r["region"] != "address table" or r.get("address") is None:
            continue
        addr = int(r["address"])

        def word(at: int) -> Optional[int]:
            hi, lo = ets.get(at), ets.get(at + 1)
            return None if hi is None or lo is None else (hi << 8) | lo

        count = word(addr)
        if count is None:
            return {}
        out: Dict[int, str] = {}
        for i in range(1, count + 1):
            raw = word(addr + 2 * i)
            if raw is not None:
                out[i] = _ga_text(raw)
        return out
    return {}


# `write property (object 4, type 0, PID 27, 10 byte(s) from element 1)`, the
# label bussard-download gives a `FlashStep::WriteProp`.
WRITE_PROP_LABEL = re.compile(
    r"write property \(object (\d+), type (\d+), PID (\d+), (\d+) byte\(s\) from element (\d+)\)"
)


PID_MCB_TABLE = 27
MCB_ENTRY_LEN = 8


def _wire_writes(entry: Dict[str, object]) -> List[Dict[str, object]]:
    """The writes one plan step becomes on the wire.

    Mirrors bussard-download's executor: a `PID_MCB_TABLE` value longer than
    one 8-octet entry (the vendor pads it to 10) is sent one entry per request
    from the start element, and a trailing partial entry (the padding) is
    dropped. Everything else goes out as one write.
    """
    length = int(entry["length"])
    if not (
        "index" in entry["object"] and entry["pid"] == PID_MCB_TABLE and length > MCB_ENTRY_LEN
    ):
        return [entry]
    out = []
    data = entry.get("data")
    start = int(entry.get("index") or 1)
    for i in range(length // MCB_ENTRY_LEN):
        chunk = dict(entry, index=start + i, length=MCB_ENTRY_LEN, sha256=None)
        if isinstance(data, str) and not data.startswith("redacted:"):
            chunk["data"] = data[i * 2 * MCB_ENTRY_LEN:(i + 1) * 2 * MCB_ENTRY_LEN]
        else:
            chunk["data"] = None
        out.append(chunk)
    return out


def plan_property_writes(plan: dict) -> List[Dict[str, object]]:
    """bussard's property writes, in plan order, as they go out on the wire.

    A step may carry a structured `property` record (`object` index, or
    `object_type` and `instance`; `pid`, `start_element`, `length` and either
    `data` hex or `sha256`); otherwise the step label is parsed, which gives
    the object, PID, length and start element but no value. Today's
    `plan.json` has labels only.
    """
    out: List[Dict[str, object]] = []
    for entry in _plan_property_steps(plan):
        out.extend(_wire_writes(entry))
    return out


def _plan_property_steps(plan: dict) -> List[Dict[str, object]]:
    out: List[Dict[str, object]] = []
    for step in plan.get("steps", []):
        # A step that goes out as several writes (the Data Secure security
        # object's chunked PID 61 flags) lists them under `properties`.
        records = step.get("properties")
        if isinstance(records, list) and records:
            for rec in records:
                if isinstance(rec, dict):
                    out.append(_structured_entry(step, rec))
            continue
        rec = step.get("property")
        if isinstance(rec, dict):
            if rec.get("object_type") is not None:
                obj: Dict[str, int] = {
                    "type": int(rec["object_type"]),
                    "instance": int(rec.get("instance", 1)),
                }
            else:
                obj = {"index": int(rec["object"])}
            data = rec.get("data")
            entry = {
                "step": step.get("index"),
                "object": obj,
                "pid": int(rec["pid"]),
                "index": rec.get("start_element"),
                "length": int(rec.get("length", len(data) // 2 if isinstance(data, str) else 0)),
                "data": data if isinstance(data, str) else None,
                "sha256": rec.get("sha256"),
            }
            out.append(entry)
            continue
        m = WRITE_PROP_LABEL.search(step.get("label", ""))
        if m:
            out.append(
                {
                    "step": step.get("index"),
                    "object": {"index": int(m.group(1))},
                    "pid": int(m.group(3)),
                    "index": int(m.group(5)),
                    "length": int(m.group(4)),
                    "data": None,
                    "sha256": None,
                }
            )
    return out


def _structured_entry(step: dict, rec: dict) -> Dict[str, object]:
    """One structured `property` record of a plan step as a comparable entry."""
    if rec.get("object_type") is not None:
        obj: Dict[str, int] = {
            "type": int(rec["object_type"]),
            "instance": int(rec.get("instance", 1)),
        }
    else:
        obj = {"index": int(rec["object"])}
    data = rec.get("data")
    return {
        "step": step.get("index"),
        "object": obj,
        "pid": int(rec["pid"]),
        "index": rec.get("start_element"),
        "length": int(rec.get("length", len(data) // 2 if isinstance(data, str) else 0)),
        "data": data if isinstance(data, str) else None,
        "sha256": rec.get("sha256"),
        "entries": rec.get("entries"),
        "phase": rec.get("phase"),
    }


def _obj_label(obj: Dict[str, int]) -> str:
    if "type" in obj:
        return "type%d.%d" % (obj["type"], obj.get("instance", 1))
    return "obj%d" % obj["index"]


def _key_object(key: list) -> Dict[str, int]:
    """The object a `_prop_key` label names (`type11.1` or `obj4`)."""
    label = str(key[0])
    if label.startswith("type"):
        t, _, inst = label[4:].partition(".")
        return {"type": int(t), "instance": int(inst or 1)}
    return {"index": int(label[3:])}


def _prop_key(entry: Dict[str, object]) -> Tuple[str, int, int]:
    return (_obj_label(entry["object"]), int(entry["pid"]), int(entry["length"]))


def _is_security_object(entry: Dict[str, object]) -> bool:
    return entry["object"].get("type") == SECURITY_OBJECT_TYPE


def _sender_check(ours_hex: str, ets_hex: str) -> Optional[Tuple[str, str]]:
    """PID 54 (security individual address table) by sender address.

    An entry is the individual address (2 octets) and the last sequence
    number received from it (6 octets). The sender list, set and order, is
    what admits a frame; the stored sequence number only has to be below the
    sender's next one, and bussard seeds it from the clock (#228), so it is a
    note, not a difference. None when the value is not a whole entry list.
    """
    n = SENDER_ENTRY_LEN * 2
    if not ours_hex or len(ours_hex) % n or len(ets_hex) % n:
        return None
    try:
        ours_b, ets_b = bytes.fromhex(ours_hex), bytes.fromhex(ets_hex)
    except ValueError:
        return None

    ours_ia, ours_seq = _senders(ours_b)
    ets_ia, ets_seq = _senders(ets_b)
    if ours_ia != ets_ia:
        what = "sender order differs" if sorted(ours_ia) == sorted(ets_ia) else "senders differ"
        return "differs", "%s: ETS %s; bussard %s" % (
            what, _sender_list(ets_ia, ets_seq), _sender_list(ours_ia, ours_seq))
    if ours_seq != ets_seq:
        return "equal", "sequence numbers differ: ETS %s; bussard %s" % (
            _sender_list(ets_ia, ets_seq), _sender_list(ours_ia, ours_seq))
    return "equal", ""


def _senders(b: bytes) -> Tuple[List[str], List[int]]:
    """A PID 54 value as its individual addresses and sequence numbers."""
    rows = [b[i:i + SENDER_ENTRY_LEN] for i in range(0, len(b), SENDER_ENTRY_LEN)]
    return (
        [_ia_text(struct.unpack(">H", r[:2])[0]) for r in rows],
        [int.from_bytes(r[2:], "big") for r in rows],
    )


def _sender_list(ias: List[str], seqs: List[int]) -> str:
    """`1.1.5 (seq 12345), 1.1.7 (seq 0)`, or `none`."""
    return ", ".join("%s (seq %d)" % (ia, seq) for ia, seq in zip(ias, seqs)) or "none"


def _sender_table(ours: list, ets: list) -> Optional[Dict[str, object]]:
    """The whole PID 54 sender table (every non-empty PID 54 write on the
    security object, in order) of each side, or None when a side has no such
    write or one without a readable value. Lists both sides' senders with
    their sequence numbers, so a difference names who ETS admitted, also when
    the two sides wrote tables of different lengths (which the per-write
    alignment shows only as one-sided writes).
    """
    def table(side: list) -> Optional[bytes]:
        writes = [e for e in side if _is_security_object(e)
                  and int(e["pid"]) == PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE
                  and int(e["length"]) > 0]
        out = b""
        for e in writes:
            data = e.get("data")
            if not isinstance(data, str) or data.startswith("redacted:"):
                return None
            try:
                out += bytes.fromhex(data)
            except ValueError:
                return None
        return out if writes and len(out) % SENDER_ENTRY_LEN == 0 else None

    ours_b, ets_b = table(ours), table(ets)
    if ours_b is None or ets_b is None:
        return None
    ours_ia, ours_seq = _senders(ours_b)
    ets_ia, ets_seq = _senders(ets_b)
    return {
        "value": "equal" if ours_ia == ets_ia else "differs",
        "bussard": _sender_list(ours_ia, ours_seq),
        "ets": _sender_list(ets_ia, ets_seq),
    }


def _group_key_check(ours: list, theirs: list) -> Tuple[str, str]:
    """PID 53 (group key table) per entry, from both sides' salted entries.

    Entries are matched by group address when both sides name one (bussard
    does; `compare` resolves ETS's address table index through the address
    table ETS wrote), else by address table index, named by bussard's group
    for that index. Names the groups whose key differs or that one side
    lacks; never a key or a hash of one.
    """
    by_ga = all(e.get("ga") for e in ours) and all(e.get("ga") for e in theirs)
    names: Dict[object, str] = {}

    def ident(e: dict) -> object:
        if by_ga:
            return e["ga"]
        idx = int(e["index"])
        if e.get("ga"):
            names.setdefault(idx, str(e["ga"]))
        return idx

    ours_ids = [ident(e) for e in ours]
    ets_ids = [ident(e) for e in theirs]
    ours_by = dict(zip(ours_ids, (e["key"] for e in ours)))
    ets_by = dict(zip(ets_ids, (e["key"] for e in theirs)))

    def name(i: object) -> str:
        if by_ga:
            return str(i)
        return names.get(i, "index %s" % i)

    problems = []
    for i in ours_ids + [i for i in ets_ids if i not in ours_by]:
        if i not in ets_by:
            problems.append("%s: missing in ETS" % name(i))
        elif i not in ours_by:
            problems.append("%s: missing in bussard" % name(i))
        elif ours_by[i] != ets_by[i]:
            problems.append("%s: key differs" % name(i))
    if problems:
        return "differs", "; ".join(problems)
    if ours_ids != ets_ids:
        return "differs", "entry order differs"
    return "hash-equal", ""


def _value_check(ours: Dict[str, object], theirs: Dict[str, object]) -> Tuple[str, str]:
    """(outcome, why): `equal`, `hash-equal`, `differs` or `no-value`.

    `why` says what differs; on `equal` it may carry a note (PID 54's
    sequence numbers).
    """
    if _is_security_object(ours) and _is_security_object(theirs):
        pid = int(ours["pid"])
        ours_entries, ets_entries = ours.get("entries"), theirs.get("entries")
        if pid == PID_GRP_KEY_TABLE and isinstance(ours_entries, list) \
                and isinstance(ets_entries, list):
            return _group_key_check(ours_entries, ets_entries)
        ours_data, ets_data = ours.get("data"), str(theirs.get("data") or "")
        if pid == PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE and isinstance(ours_data, str) \
                and not ours_data.startswith("redacted:") and not ets_data.startswith("redacted:"):
            sender = _sender_check(ours_data, ets_data)
            if sender is not None:
                return sender
    ets_value = str(theirs.get("data") or "")
    redacted = ets_value.startswith("redacted:")
    ours_hex = ours.get("data")
    ours_sha = ours.get("sha256")
    if isinstance(ours_hex, str) and ours_hex.startswith("redacted:"):
        ours_hash = ours_hex[len("redacted:"):]
    elif isinstance(ours_hex, str):
        ours_hash = sha256(bytes.fromhex(ours_hex))[:8]
    elif isinstance(ours_sha, str):
        ours_hash = ours_sha[:8]
    elif ours["object"].get("type") == SECURITY_OBJECT_TYPE and int(ours["pid"]) == 59:
        return "no-value", "the send sequence comes from the clock on both sides"
    else:
        return "no-value", "plan.json carries no value for this step"
    if redacted:
        same = ours_hash == ets_value[len("redacted:"):]
        return ("hash-equal", "") if same else ("differs", "hash differs")
    if isinstance(ours_hex, str) and not ours_hex.startswith("redacted:"):
        return ("equal", "") if ours_hex == ets_value else ("differs", "bytes differ")
    same = ours_hash == sha256(bytes.fromhex(ets_value))[:8]
    return ("hash-equal", "") if same else ("differs", "hash differs")


# The commissioning ETS writes to a KNX IP interface beside the application's
# load procedure (issue #390, the 1.1.200 capture of 2026-10-26): the security
# object's tool key and mode (type 17) and the KNXnet/IP parameter object's IP
# and tunnelling configuration (type 11), parts 2 and 3 of #389. On a
# property-only plan they are listed, not counted.
COMMISSIONING_OBJECT_TYPES = frozenset({11, 17})


def _is_commissioning(entry: Dict[str, object], ours_keys: set) -> bool:
    obj = entry["object"]
    return (
        obj.get("type") in COMMISSIONING_OBJECT_TYPES
        and (_obj_label(obj), int(entry["pid"])) not in ours_keys
    )


# The KNXnet/IP Secure properties `bussard interface secure on|off` writes
# (issue #398): the security object's mode, tool key and send sequence (type
# 17 PIDs 51, 56, 59) and the KNXnet/IP parameter object's PIDs 91 to 97. A
# plan with `system: "ip-secure"` is compared against these only: ETS also
# rewrites the `[knxnet]` table and may run the load procedure in the same
# capture, which `bussard apply` and `bussard flash` cover.
IP_SECURE_SYSTEM = "ip-secure"
IP_SECURE_PROPERTIES = frozenset(
    {("type17.1", 51), ("type17.1", 56), ("type17.1", 59)}
    | {("type11.1", pid) for pid in range(91, 98)}
)


def _ip_secure_entry(entry: Dict[str, object]) -> bool:
    return (_obj_label(entry["object"]), int(entry["pid"])) in IP_SECURE_PROPERTIES


def compare_properties(
    plan: dict,
    image_dir: str,
    ets_groups: Optional[Dict[int, str]] = None,
    phase: Optional[str] = None,
) -> Dict[str, object]:
    """Aligns bussard's property-write steps with ETS's `properties.json`.

    `ets_groups` maps an address table index to the group address in the
    address table ETS wrote; it names the entries of ETS's group key table
    (PID 53), which store the index, not the group.

    PID_LOAD_STATE_CONTROL writes on the plain services are left out on the
    ETS side: they are the load state machine (unload, allocate, complete),
    which the plan carries as its own step kinds, not as property writes.
    `compare_load_controls` judges them.
    """
    path = os.path.join(image_dir, "properties.json")
    if not os.path.exists(path):
        return {"verdict": NOT_COMPARABLE, "reason": "no properties.json (re-run `knxtrace image`)"}
    with open(path, encoding="utf-8") as fh:
        ets_all = json.load(fh)
    ets = [
        e
        for e in ets_all
        if not ("index" in e["object"] and e["pid"] == PID_LOAD_STATE_CONTROL
                and e["service"] == "A_PropertyValue_Write")
    ]
    if ets_groups:
        for e in ets:
            for entry in e.get("entries") or []:
                ga = ets_groups.get(int(entry.get("index", 0)))
                if ga:
                    entry["ga"] = ga
    ours = plan_property_writes(plan)
    ip_secure = plan.get("system") == IP_SECURE_SYSTEM
    if ip_secure:
        # Only the IP Secure properties, and with `phase` only the writes
        # bussard sends under that key (`fdsk` or `tool`): the decoded half of
        # a capture whose other half ran inside a KNXnet/IP Secure session.
        ets = [e for e in ets if _ip_secure_entry(e)]
        if phase:
            ours = [e for e in ours if e.get("phase") == phase]
    matcher = difflib.SequenceMatcher(
        None, [_prop_key(e) for e in ours], [_prop_key(e) for e in ets], autojunk=False
    )
    matched: List[Dict[str, object]] = []
    bussard_only: List[Dict[str, object]] = []
    ets_only: List[Dict[str, object]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for a, b in zip(ours[i1:i2], ets[j1:j2]):
                outcome, why = _value_check(a, b)
                if outcome != "differs" and a.get("index") is not None and b.get("index") is not None \
                        and a["index"] != b["index"]:
                    outcome, why = "differs", "start index %s vs %s" % (a["index"], b["index"])
                matched.append(
                    {"step": a["step"], "ets_seq": b["seq"], "key": list(_prop_key(a)),
                     "value": outcome, "why": why, "ets_data": b["data"]}
                )
            continue
        for a in ours[i1:i2]:
            bussard_only.append({"step": a["step"], "key": list(_prop_key(a))})
        for b in ets[j1:j2]:
            ets_only.append({"ets_seq": b["seq"], "service": b["service"], "key": list(_prop_key(b)),
                             "data": b["data"]})
    group_keys = _group_key_table(ours, ets)
    senders = _sender_table(ours, ets)
    counts: Dict[str, int] = {}
    for m in matched:
        counts[m["value"]] = counts.get(m["value"], 0) + 1
    # A property-only plan (issue #390): ETS's interface commissioning is
    # listed, not counted, and a capture in which ETS wrote none of the
    # properties the procedure writes did not run the procedure at all.
    commissioning: List[Dict[str, object]] = []
    reason = ""
    property_only = plan.get("system") == "properties"
    if property_only:
        ours_keys = {(_obj_label(e["object"]), int(e["pid"])) for e in ours}
        commissioning = [e for e in ets_only if _is_commissioning(
            {"object": _key_object(e["key"]), "pid": e["key"][1]}, ours_keys)]
        ets_only = [e for e in ets_only if e not in commissioning]
        ets_keys = {(_obj_label(e["object"]), int(e["pid"])) for e in ets}
    if bussard_only or ets_only or counts.get("differs"):
        verdict = DIFFERS
    elif not matched:
        verdict = NOT_COMPARABLE
    else:
        verdict = IDENTICAL
    if property_only and not matched and ours and not (ours_keys & ets_keys):
        verdict = NOT_COMPARABLE
        reason = (
            "ETS did not run the load procedure in this capture: none of bussard's %d "
            "property write(s) (%s) appears among ETS's %d"
            % (len(ours), ", ".join(_key_text(list(_prop_key(e))) for e in ours), len(ets))
        )
    out: Dict[str, object] = {
        "verdict": verdict,
        "bussard_writes": len(ours),
        "ets_writes": len(ets),
        "ets_load_controls_skipped": len(ets_all) - len(ets),
        "matched": matched,
        "value_counts": counts,
        "bussard_only": bussard_only,
        "ets_only": ets_only,
        "group_key_table": group_keys,
        "sender_table": senders,
    }
    if property_only:
        out["reason"] = reason
        out["commissioning"] = commissioning
    return out


LOAD_EVENTS = {1: "start-loading", 2: "load-completed", 4: "unload", 0: "no-operation"}
# `AdditionalLoadControls` subtypes. 0x01 is a System B LdCtrlAbsSegment or a
# System 7 stack segment, so it keeps its number.
LOAD_SUBTYPES = {0x00: "abs-segment", 0x02: "task-segment", 0x03: "task-ptr",
                 0x04: "task-ctrl1", 0x05: "task-ctrl2", 0x0B: "rel-segment"}
MAX_LOAD_DIFFERENCES = 64


def load_event_name(form: str, data_hex: str) -> str:
    """`unload`, `abs-segment`, `task-segment`, `sub0x01`, ... for a record."""
    try:
        data = bytes.fromhex(data_hex)
    except ValueError:
        return "?"
    if not data:
        return "empty"
    opcode = data[0] & 0x0F if form == "memory" else data[0]
    if opcode != 3:
        return LOAD_EVENTS.get(opcode, "event0x%02x" % opcode)
    if len(data) < 2:
        return "additional"
    return LOAD_SUBTYPES.get(data[1], "sub0x%02x" % data[1])


def _lc_object(rec: Dict[str, object]) -> Optional[int]:
    """The load-state object a record drives: the object index, or the LSM."""
    value = rec.get("lsm") if rec.get("form") == "memory" else rec.get("object")
    return None if value is None else int(value)


def _lc_text(rec: Optional[Dict[str, object]]) -> str:
    if rec is None:
        return "none"
    where = "@0x%04X" % int(rec.get("address") or 0) if rec["form"] == "memory" else "PID 5"
    return "%s %s %s" % (rec["event"], where, rec["data"])


def _lc_collapse(records: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Drops an immediate repeat of the same record (see the module doc)."""
    out: List[Dict[str, object]] = []
    for rec in records:
        if out and (out[-1]["form"], out[-1]["data"]) == (rec["form"], rec["data"]):
            out[-1]["repeats"] = int(out[-1].get("repeats", 1)) + 1
            continue
        out.append(dict(rec))
    return out


def plan_load_controls(plan: dict) -> Optional[List[Dict[str, object]]]:
    """bussard's load-control records in plan order, or None for a dump that
    predates the `load_controls` field."""
    if "load_control_records" not in plan:
        return None
    out: List[Dict[str, object]] = []
    for step in plan.get("steps", []):
        for rec in step.get("load_controls") or []:
            out.append(dict(rec, step=step.get("index"),
                            event=load_event_name(rec["form"], rec["data"])))
    return out


def compare_load_controls(plan: dict, image_dir: str) -> Dict[str, object]:
    """Compares bussard's load-control records with ETS's, per load-state
    object, by the rule in the module doc."""
    if plan.get("system") in (IP_SECURE_SYSTEM, "properties"):
        return {"verdict": NOT_COMPARABLE, "reason": "the plan drives no load-state machine"}
    ours_all = plan_load_controls(plan)
    if ours_all is None:
        return {"verdict": NOT_COMPARABLE,
                "reason": "plan.json lists no load_controls (rebuild bussard)"}
    path = os.path.join(image_dir, LOAD_CONTROLS_FILE)
    if not os.path.exists(path):
        return {"verdict": NOT_COMPARABLE,
                "reason": "no %s (re-run `knxtrace image`)" % LOAD_CONTROLS_FILE}
    with open(path, encoding="utf-8") as fh:
        ets_all = [dict(e, event=load_event_name(e["form"], e["data"])) for e in json.load(fh)]
    base = {"bussard_records": len(ours_all), "ets_records": len(ets_all)}
    if not ets_all:
        return dict(base, verdict=NOT_COMPARABLE, reason="ETS sent no load-control record",
                    objects=[], differences=[], first=None)

    def grouped(records: List[Dict[str, object]]) -> Dict[Optional[int], List[Dict[str, object]]]:
        out: Dict[Optional[int], List[Dict[str, object]]] = {}
        for rec in records:
            out.setdefault(_lc_object(rec), []).append(rec)
        return {k: _lc_collapse(v) for k, v in out.items()}

    ours, ets = grouped(ours_all), grouped(ets_all)
    notes: List[str] = []
    if None in ours:
        # The object the device resolves: the one ETS object no bussard
        # sequence names.
        free = [k for k in ets if k not in ours]
        if len(free) == 1:
            ours[free[0]] = ours.pop(None)
            notes.append("bussard's unresolved object paired with ETS object %d" % free[0])
    order: List[Optional[int]] = []
    for rec in ets_all + ours_all:
        key = _lc_object(rec)
        if key not in order and (key in ours or key in ets):
            order.append(key)
    for key in ours:
        if key not in order:
            order.append(key)
    differences: List[Dict[str, object]] = []
    objects: List[Dict[str, object]] = []
    for key in order:
        a, b = ours.get(key, []), ets.get(key, [])
        sig_a = [(r["form"], r["data"]) for r in a]
        sig_b = [(r["form"], r["data"]) for r in b]
        same = sig_a == sig_b
        objects.append({"object": key, "bussard": len(a), "ets": len(b),
                        "verdict": IDENTICAL if same else DIFFERS})
        if same:
            continue
        matcher = difflib.SequenceMatcher(None, sig_a, sig_b, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue
            for k in range(max(i2 - i1, j2 - j1)):
                x = a[i1 + k] if i1 + k < i2 else None
                y = b[j1 + k] if j1 + k < j2 else None
                differences.append({
                    "object": key,
                    "position": (i1 + k if x is not None else j1 + k) + 1,
                    "kind": "value" if x and y else "bussard-only" if x else "ets-only",
                    "event": (y or x or {}).get("event"),
                    "bussard_event": x["event"] if x else None,
                    "ets_event": y["event"] if y else None,
                    "step": x.get("step") if x else None,
                    "ets_seq": y.get("seq") if y else None,
                    "bussard": _lc_text(x),
                    "ets": _lc_text(y),
                    "bussard_hex": x["data"] if x else None,
                    "ets_hex": y["data"] if y else None,
                })
    verdict = DIFFERS if differences else IDENTICAL
    return dict(base, verdict=verdict, reason="", notes=notes, objects=objects,
                differences=differences[:MAX_LOAD_DIFFERENCES],
                difference_count=len(differences),
                first=differences[0] if differences else None)


def render_load_controls(lc: Optional[Dict[str, object]]) -> List[str]:
    if not lc:
        return []
    if lc["verdict"] == NOT_COMPARABLE:
        return ["  load control: not comparable: %s" % lc.get("reason", "")]
    head = "  load control: %s (bussard %d, ETS %d record(s) on %d object(s))" % (
        lc["verdict"], lc["bussard_records"], lc["ets_records"], len(lc["objects"]))
    lines = [head]
    for note in lc.get("notes") or []:
        lines.append("      note: %s" % note)
    for d in lc["differences"]:
        lines.append("      obj %s #%d %s: bussard %s" % (d["object"], d["position"], d["kind"], d["bussard"]))
        lines.append("      %s ETS     %s" % (" " * len("obj %s #%d %s:" % (
            d["object"], d["position"], d["kind"])), d["ets"]))
    if lc.get("difference_count", 0) > len(lc["differences"]):
        lines.append("      ... %d more" % (lc["difference_count"] - len(lc["differences"])))
    return lines


def _group_key_table(ours: list, ets: list) -> Optional[Dict[str, str]]:
    """The whole group key table (every PID 53 write on the security object,
    in order) compared per group address, or None when a side has no such
    write or one without salted entries.

    The per-write check names what differs within one chunk; a table written
    in chunks of different sizes shifts entries between them, so this is the
    line that says which groups really differ.
    """
    def entries(side: list) -> Optional[list]:
        writes = [e for e in side if _is_security_object(e) and int(e["pid"]) == PID_GRP_KEY_TABLE
                  and int(e["length"]) > 0]
        if not writes or not all(isinstance(e.get("entries"), list) for e in writes):
            return None
        return [x for e in writes for x in e["entries"]]

    ours_entries, ets_entries = entries(ours), entries(ets)
    if ours_entries is None or ets_entries is None:
        return None
    value, why = _group_key_check(ours_entries, ets_entries)
    return {"value": value, "why": why, "bussard_entries": len(ours_entries),
            "ets_entries": len(ets_entries)}


def _add_coverage(
    rec: dict,
    offsets: List[int],
    known: set,
    addr: Optional[int],
    label: Optional[str],
    page_size: int,
) -> None:
    """Adds the placed/compared counts of one region, per page, to `rec`."""
    pages: Dict[object, List[int]] = {}
    for i in offsets:
        if addr is not None:
            key = (addr + i) // page_size * page_size
        else:
            key = (label, i // page_size * page_size)
        counts = pages.setdefault(key, [0, 0])
        counts[0] += 1
        if i in known:
            counts[1] += 1
    rec["placed"] = len(offsets)
    rec["placed_compared"] = len(known)
    rec["pages"] = [
        {"page": _page_name(k), "placed": v[0], "compared": v[1]} for k, v in pages.items()
    ]


def _result(step: dict, name: str, ours: bytes, verdict: str, reason: str) -> dict:
    return {
        "step": step["index"],
        "region": name,
        "length": len(ours),
        "verdict": verdict,
        "reason": reason,
    }


def _ranges(addrs: List[int]) -> List[List[int]]:
    out: List[List[int]] = []
    for a in addrs:
        if out and out[-1][1] == a:
            out[-1][1] = a + 1
        else:
            out.append([a, a + 1])
    return out


def render(report: Dict[str, object]) -> List[str]:
    if report.get("system") == IP_SECURE_SYSTEM:
        # An `interface secure` plan writes properties only (issue #398).
        lines = ["%s KNXnet/IP Secure: %s" % (report["device"], report["verdict"])]
        lines.extend(render_properties(report.get("properties")))
        return lines
    lines = [
        "%s %s (System %s): %s"
        % (report["device"], report["application"], report["system"], report["verdict"])
    ]
    cov = report.get("coverage")
    if cov:
        blind = cov["blind_pages"]
        lines.append(
            "  coverage %.1f %% (%d of %d placed octets compared; %d of %d page(s) uncompared%s)%s"
            % (
                cov["percent"],
                cov["compared"],
                cov["placed"],
                len(blind),
                cov["pages"],
                ": " + ", ".join(blind[:8]) + (", ..." if len(blind) > 8 else "") if blind else "",
                ": THIN (needs %.0f %% and every page)" % cov["min_percent"] if cov["thin"] else "",
            )
        )
    conf = report.get("confirmed")
    if conf:
        lines.append("  " + confirmed_text(report))
        if conf["octets"]:
            blind = conf["blind_pages"]
            lines.append(
                "  confirmed coverage %.1f %% (%d of %d placed octets read-confirmed; %d of %d "
                "page(s) without one%s)%s"
                % (
                    conf["percent"],
                    conf["compared"],
                    conf["placed"],
                    len(blind),
                    conf["pages"],
                    ": " + ", ".join(blind[:8]) + (", ..." if len(blind) > 8 else "")
                    if blind else "",
                    ": THIN" if conf["thin"] else "",
                )
            )
        for m in conf["mismatches"]:
            lines.append(
                "      confirmed mismatch 0x%06X (%s+0x%X): bussard %s, device/ETS %s"
                % (m["address"], region_short(m["region"]), m["offset"], m["bussard"], m["ets"])
            )
    if cov and cov.get("scope") is not None:
        lines.append("  scope: %s (other regions are shown, not judged)" % ",".join(cov["scope"]))
    for r in report["regions"]:
        head = "  step %3d %-22s %6d octets  " % (r["step"], r["region"], r["length"])
        if not r.get("in_scope", True):
            head += "(out of scope) "
        if "placed" in r:
            head += "[%d/%d placed] " % (r["placed_compared"], r["placed"])
        conf = r.get("confirmed")
        if conf and conf["compared"]:
            head += "[%d confirmed%s] " % (
                conf["compared"],
                ", %d differ" % conf["diff_octets"] if conf["diff_octets"] else "")
        if r["verdict"] == IDENTICAL:
            lines.append(head + "identical (%d compared)" % r["compared"])
        elif r["verdict"] == DIFFERS:
            lines.append(
                head
                + "differs: %d of %d octets, first at +0x%X"
                % (r["diff_octets"], r["compared"], r["first_offset"])
            )
            lines.append("      bussard +0x%04X: %s" % (r["excerpt_offset"], r["bussard_hex"]))
            lines.append("      ets     +0x%04X: %s" % (r["excerpt_offset"], r["ets_hex"]))
            if r.get("fill_diff_octets"):
                lines.append(
                    "      %d of them ETS never wrote (they hold the allocation's fill): %s"
                    % (
                        r["fill_diff_octets"],
                        ", ".join("+0x%X" % o for o in r["fill_diff_offsets"][:8]),
                    )
                )
        else:
            lines.append(head + "not comparable: %s" % r["reason"])
    if report["ets_only_octets"]:
        lines.append(
            "  ETS also wrote %d octet(s) outside bussard's images: %s"
            % (
                report["ets_only_octets"],
                ", ".join("0x%06X+%d" % (a, b - a) for a, b in report["ets_only_ranges"][:6]),
            )
        )
    lines.extend(render_properties(report.get("properties")))
    lines.extend(render_load_controls(report.get("load_controls")))
    return lines


def confirmed_text(report: Dict[str, object]) -> str:
    """`written: identical, confirmed: 1 of 2328 octets differ at 0x4800+0`."""
    conf = report.get("confirmed") or {}
    head = "written: %s, confirmed: " % report["verdict"]
    if not conf.get("octets"):
        return head + "none (%d read-confirmed octet(s) in the capture)" % conf.get(
            "capture_octets", 0)
    if conf["diff_octets"]:
        first = conf["mismatches"][0]
        return head + "%d of %d octets differ at 0x%04X+%d" % (
            conf["diff_octets"], conf["octets"], first["address"] - first["offset"],
            first["offset"])
    if conf["verdict"] == IDENTICAL:
        return head + "identical (%d octets)" % conf["octets"]
    return head + "not comparable (%d octets; %s)" % (conf["octets"], conf["reason"])


def _key_text(key) -> str:
    return "%s PID %d (%d octets)" % (key[0], key[1], key[2])


def render_properties(props: Optional[Dict[str, object]]) -> List[str]:
    if not props:
        return []
    if props["verdict"] == NOT_COMPARABLE and props.get("reason") and "matched" not in props:
        return ["  property writes: not comparable: %s" % props["reason"]]
    if props["verdict"] == NOT_COMPARABLE and props.get("reason"):
        lines = ["  property writes: not comparable: %s" % props["reason"]]
        for b in props["bussard_only"]:
            lines.append("      bussard only: step %3s %s" % (b["step"], _key_text(b["key"])))
        lines.extend(_commissioning_lines(props))
        return lines
    if not (props["bussard_writes"] or props["ets_writes"]):
        return ["  property writes: none on either side"]
    counts = props["value_counts"]
    lines = [
        "  property writes: %s (bussard %d, ETS %d; %d matched: %s)"
        % (
            props["verdict"],
            props["bussard_writes"],
            props["ets_writes"],
            len(props["matched"]),
            ", ".join("%s %d" % kv for kv in sorted(counts.items())) or "none",
        )
    ]
    for m in props["matched"]:
        if m["value"] == "differs":
            lines.append("      step %3s %s: %s" % (m["step"], _key_text(m["key"]), m["why"]))
        elif m["value"] in ("equal", "hash-equal") and m["why"]:
            # A note on a match (PID 54's sequence numbers).
            lines.append(
                "      step %3s %s: %s (%s)" % (m["step"], _key_text(m["key"]), m["value"], m["why"])
            )
    gk = props.get("group_key_table")
    if gk and gk["value"] == "differs":
        lines.append(
            "      group key table (PID 53, bussard %d, ETS %d entries): %s"
            % (gk["bussard_entries"], gk["ets_entries"], gk["why"])
        )
    st = props.get("sender_table")
    if st and st["value"] == "differs":
        lines.append("      sender table (PID 54): ETS %s" % st["ets"])
        lines.append("      sender table (PID 54): bussard %s" % st["bussard"])
    for b in props["bussard_only"]:
        lines.append("      bussard only: step %3s %s" % (b["step"], _key_text(b["key"])))
    for e in props["ets_only"]:
        lines.append(
            "      ETS only:     #%-3s %s %s" % (e["ets_seq"], e["service"], _key_text(e["key"]))
        )
    lines.extend(_commissioning_lines(props))
    return lines


def _commissioning_lines(props: Dict[str, object]) -> List[str]:
    """ETS's interface commissioning on a property-only plan, not counted."""
    return [
        "      ETS commissioning (not counted): #%-3s %s %s"
        % (e["ets_seq"], e["service"], _key_text(e["key"]))
        for e in props.get("commissioning") or []
    ]
