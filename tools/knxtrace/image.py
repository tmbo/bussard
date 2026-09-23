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

`compare` diffs a `bussard flash --dry-run --dump-images` directory against a
composed image directory, one bussard image at a time: identical, differs (how
many octets, the first differing offset, both hex excerpts), or not comparable
(and why). This is the offline conformance oracle of the physical campaign
(issue #89).
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from typing import Dict, List, Optional, Tuple

from normalize import KIND_ALLOC, KIND_MEM_WRITE, DeviceOps, coalesce

# LdCtrl subtypes of an `AdditionalLoadControls` (event 3) record.
SUB_S7_ALLOC = 0x00  # System 7 property-based AbsSegment: [3][0][start:2][len:2][acc][mem][cs][0]
SUB_ABS_SEGMENT = 0x01  # System B LdCtrlAbsSegment: [3][1][addr:4][len:2][acc][mem]...
SUB_REL_SEGMENT = 0x0B  # LdCtrlRelSegment: [3][0x0B][size:4][fill:1][fill_byte:1]

IDENTICAL = "identical"
DIFFERS = "differs"
NOT_COMPARABLE = "not-comparable"

EXCERPT = 8  # octets shown on each side of a first difference


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


def memory_writes(ops: DeviceOps) -> List[Tuple[int, bytes]]:
    writes = []
    for op in ops.ops:
        if op.direction != "req" or op.kind != KIND_MEM_WRITE:
            continue
        addr = op.detail.get("addr_int")
        if isinstance(addr, int) and op.data:
            writes.append((addr, op.data))
    return writes


def compose(ops: DeviceOps, out_dir: str, source: str = "") -> Dict[str, object]:
    """Writes the composed image of one device's download into `out_dir`.

    Returns (and writes as `regions.json`) the index: one entry per contiguous
    written region, the allocation records, and the object bases read back.
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

    index = {
        "device": ops.device,
        "source": os.path.basename(source),
        "regions": regions,
        "allocations": allocs,
        "table_refs": {str(k): v for k, v in sorted(table_refs(ops).items())},
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


def compare(plan_dir: str, image_dir: str) -> Dict[str, object]:
    """Diffs bussard's dry-run images against the composed ETS image."""
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
        addr = image.get("address")
        if addr is None:
            obj = image.get("object")
            base = ets.bases.get(obj) if obj is not None else None
            if base is None:
                results.append(
                    _result(step, name, ours, NOT_COMPARABLE, "no ETS base for object %s" % obj)
                )
                continue
            addr = base + int(image.get("offset") or 0)
        compared = diffs = 0
        first = None
        for i, b in enumerate(ours):
            if mask is not None and i < len(mask) and mask[i] != 0xFF:
                continue
            covered_addrs.add(addr + i)
            theirs = ets.get(addr + i)
            if theirs is None:
                continue
            compared += 1
            if theirs != b:
                diffs += 1
                if first is None:
                    first = i
        rec = _result(step, name, ours, IDENTICAL, "")
        rec["address"] = addr
        rec["compared"] = compared
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
                }
            )
        results.append(rec)

    ets_only = sorted(a for a in ets.written if a not in covered_addrs)
    verdicts = {r["verdict"] for r in results}
    if DIFFERS in verdicts:
        overall = DIFFERS
    elif IDENTICAL in verdicts:
        overall = IDENTICAL
    else:
        overall = NOT_COMPARABLE
    return {
        "device": plan.get("device"),
        "application": plan.get("application", {}).get("id"),
        "system": plan.get("system"),
        "verdict": overall,
        "regions": results,
        "ets_only_octets": len(ets_only),
        "ets_only_ranges": _ranges(ets_only)[:20],
    }


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
    lines = [
        "%s %s (System %s): %s"
        % (report["device"], report["application"], report["system"], report["verdict"])
    ]
    for r in report["regions"]:
        head = "  step %3d %-22s %6d octets  " % (r["step"], r["region"], r["length"])
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
    return lines
