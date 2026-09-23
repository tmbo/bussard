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
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import struct
from typing import Dict, List, Optional, Tuple

from datasecure import is_key_material
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


# Property services whose request writes a value. Header octets before the
# value: plain (obj, pid, count/index:2), extended value (type:2, inst/pid:3,
# count, index:2), extended function property (type:2, inst/pid:3).
PROPERTY_WRITE_SERVICES = {
    "A_PropertyValue_Write": 4,
    "A_PropertyExtValue_WriteCon": 8,
    "A_PropertyExtValue_WriteUnCon": 8,
    "A_FunctionPropertyExt_Command": 5,
}
PID_LOAD_STATE_CONTROL = 5


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
        out.append(
            {
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
        )
    return out


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

    props = property_writes(ops)
    with open(os.path.join(out_dir, "properties.json"), "w", encoding="utf-8") as fh:
        json.dump(props, fh, indent=2)
        fh.write("\n")

    index = {
        "device": ops.device,
        "source": os.path.basename(source),
        "regions": regions,
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
        compared = diffs = fill_diffs = 0
        first = None
        fill_offsets: List[int] = []
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
                if (addr + i) not in ets.written:
                    # ETS never wrote this octet: its value is the fill of
                    # the allocation, i.e. ETS's image held the fill there.
                    fill_diffs += 1
                    fill_offsets.append(i)
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
                    "fill_diff_octets": fill_diffs,
                    "fill_diff_offsets": fill_offsets[:20],
                }
            )
        results.append(rec)

    ets_only = sorted(a for a in ets.written if a not in covered_addrs)
    # The property parity has its own verdict: `verdict` stays the image
    # verdict the pre-flash gate reads, so a known extra property write does
    # not hide whether the memory images match.
    props = compare_properties(plan, image_dir)
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
        "properties": props,
    }


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


def _obj_label(obj: Dict[str, int]) -> str:
    if "type" in obj:
        return "type%d.%d" % (obj["type"], obj.get("instance", 1))
    return "obj%d" % obj["index"]


def _prop_key(entry: Dict[str, object]) -> Tuple[str, int, int]:
    return (_obj_label(entry["object"]), int(entry["pid"]), int(entry["length"]))


def _value_check(ours: Dict[str, object], theirs: Dict[str, object]) -> Tuple[str, str]:
    """(outcome, why): `equal`, `hash-equal`, `differs` or `no-value`."""
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
    else:
        return "no-value", "plan.json carries no value for this step"
    if redacted:
        same = ours_hash == ets_value[len("redacted:"):]
        return ("hash-equal", "") if same else ("differs", "hash differs")
    if isinstance(ours_hex, str) and not ours_hex.startswith("redacted:"):
        return ("equal", "") if ours_hex == ets_value else ("differs", "bytes differ")
    same = ours_hash == sha256(bytes.fromhex(ets_value))[:8]
    return ("hash-equal", "") if same else ("differs", "hash differs")


def compare_properties(plan: dict, image_dir: str) -> Dict[str, object]:
    """Aligns bussard's property-write steps with ETS's `properties.json`.

    PID_LOAD_STATE_CONTROL writes on the plain services are left out on the
    ETS side: they are the load state machine (unload, allocate, complete),
    which the plan carries as its own step kinds, not as property writes.
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
    ours = plan_property_writes(plan)
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
    counts: Dict[str, int] = {}
    for m in matched:
        counts[m["value"]] = counts.get(m["value"], 0) + 1
    if bussard_only or ets_only or counts.get("differs"):
        verdict = DIFFERS
    elif not matched:
        verdict = NOT_COMPARABLE
    else:
        verdict = IDENTICAL
    return {
        "verdict": verdict,
        "bussard_writes": len(ours),
        "ets_writes": len(ets),
        "ets_load_controls_skipped": len(ets_all) - len(ets),
        "matched": matched,
        "value_counts": counts,
        "bussard_only": bussard_only,
        "ets_only": ets_only,
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
    return lines


def _key_text(key) -> str:
    return "%s PID %d (%d octets)" % (key[0], key[1], key[2])


def render_properties(props: Optional[Dict[str, object]]) -> List[str]:
    if not props:
        return []
    if props["verdict"] == NOT_COMPARABLE and "reason" in props:
        return ["  property writes: not comparable: %s" % props["reason"]]
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
    for b in props["bussard_only"]:
        lines.append("      bussard only: step %3s %s" % (b["step"], _key_text(b["key"])))
    for e in props["ets_only"]:
        lines.append(
            "      ETS only:     #%-3s %s %s" % (e["ets_seq"], e["service"], _key_text(e["key"]))
        )
    return lines
