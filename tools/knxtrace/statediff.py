"""The device state after a partial download: ETS's against bussard's.

`imgdiff` compares the images of one full download. A partial download
(`bussard apply`, ETS's "Partiell") writes into a device that already holds
a full download, and both tools may write different chunks of the same table:
ETS rewrites a whole group-object table in 12-octet chunks where bussard
writes one octet. What has to match is the memory the device ends with, and
the load-state sequence that got it there (bussard issues #469 and #478).

`compare_states` composes the final memory of each side from the captures
that led to the step (the `base` downloads, in order, later writes winning)
plus that side's own step capture, and compares it on every octet either side
wrote in the step. An octet one side wrote and the other never had a value
for (in the base or its step) differs: an unknown value is no match. The
octets are grouped by the load-state object whose segment holds them (the
`AbsSegment` records of the base and step captures: object 1 the address
table, 2 the association table, any other its application segment), and the
load-control records of the two steps are compared per object as `imgdiff`
does. The report has the shape of an `imgdiff` report, so the offline
oracle's summary reads it unchanged (system `apply`).

Property writes are compared the same way (issue #944: a System B program
whose parameters all live in interface-object properties writes no memory
in a parameter-only download): the final value of every property element
(object, PID, element index; a write of `count` elements at `index` sets
each) either side wrote in the step, over the base's writes. The load-state
machine's own PID 5 is left to the load-control comparison, function
property commands to the fcall comparison. Their verdict is reported apart
from the memory's (`properties`, the keys the oracle reads as `props=`),
as imgdiff reports it; the headline stays the memory's, except in a step
that writes no memory, where it is the properties' (issue #1074). The writes imgdiff
never compares (the security object's mode, tool key and send sequence,
PID_PROGMODE, the verify-mode switch) are listed, not compared, and the
security object's tables compare whole by imgdiff's value check. Objects
named by index meet those named by type through the object types the
captures read.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import image as memimage
import sequence
from normalize import DeviceOps

REGION_NAMES = {1: "address table", 2: "association table"}
EXCERPT = 8


def writes(ops: Optional[DeviceOps]) -> Dict[int, int]:
    """Every octet the tool wrote in one capture (the last write wins)."""
    out: Dict[int, int] = {}
    if ops is None:
        return out
    for addr, data in memimage.memory_writes(ops):
        for i, b in enumerate(data):
            out[addr + i] = b
    return out


def segments(ops_list: List[Optional[DeviceOps]]) -> Dict[int, Tuple[int, int]]:
    """Load-state object -> (start, length) of its absolute segment, from the
    `AbsSegment` records of the captures (a later record wins)."""
    out: Dict[int, Tuple[int, int]] = {}
    for ops in ops_list:
        if ops is None:
            continue
        for rec in memimage.load_control_writes(ops):
            data = bytes.fromhex(str(rec["data"]))
            event = data[0] & 0x0F if rec["form"] == "memory" else data[0]
            if event != 3 or len(data) < 6 or data[1] != memimage.SUB_ABS_DATA:
                continue
            obj = rec.get("lsm") if rec["form"] == "memory" else rec.get("object")
            if obj is None:
                continue
            start = int.from_bytes(data[2:4], "big")
            length = int.from_bytes(data[4:6], "big")
            out[int(obj)] = (start, length)
    return out


# PID_LOAD_STATE_CONTROL: compared as load-control records.
PID_LOAD_STATE_CONTROL = 5


# Function property commands are calls, not state: the fcall comparison
# (`image.compare_function_properties`) covers them.
FUNCTION_SERVICES = frozenset({"A_FunctionPropertyExt_Command", "M_FuncPropCommand.req"})


def object_labels(ops_list: List[Optional[DeviceOps]]) -> Dict[int, str]:
    """Each interface object index a capture resolved to its type, as the
    label `image` keys types by (`type17.1`): from every capture's reads of
    PID_OBJECT_TYPE and PID_IO_LIST (`image.object_types`)."""
    types: Dict[int, int] = {}
    for ops in ops_list:
        if ops is not None:
            types.update(memimage.object_types(ops))
    return {i: "type%d.%d" % ti for i, ti in memimage.type_instances(types).items()}


def property_elements(ops: Optional[DeviceOps], labels: Optional[Dict[int, str]] = None
                      ) -> Dict[Tuple[str, int, int], str]:
    """Every property element the tool wrote in one capture, as hex (the
    last write wins): (object, PID, element index) -> value. A write of
    `count` elements of `length` octets starting at `index` sets each. The
    object is its type label when `labels` resolves its index, so a write by
    index and one by type of the same object meet. Function property
    commands are left out (`FUNCTION_SERVICES`)."""
    out: Dict[Tuple[str, int, int], str] = {}
    if ops is None:
        return out
    for w in memimage.property_writes(ops):
        pid = w.get("pid")
        if not isinstance(pid, int) or pid == PID_LOAD_STATE_CONTROL or w.get("service") in FUNCTION_SERVICES:
            continue
        obj = w["object"]
        if "index" in obj:
            key = (labels or {}).get(int(obj["index"])) or "obj%d" % obj["index"]
        else:
            key = "type%d.%d" % (obj["type"], obj["instance"])
        data = str(w["data"])
        count = w.get("count") or 1
        start = w.get("index") or 0
        if data.startswith("redacted:") or count <= 1 or len(data) % (2 * count):
            out[(key, pid, int(start))] = data
            continue
        size = len(data) // count
        for i in range(count):
            out[(key, pid, int(start) + i)] = data[i * size:(i + 1) * size]
    return out


def _whole(elements: Dict[Tuple[str, int, int], str], label: str, pid: int) -> str:
    """A property's value from its elements, in element order."""
    return "".join(v for (k, p, _), v in sorted(elements.items(), key=lambda kv: kv[0][2])
                   if k == label and p == pid)


def compare_properties(base: List[DeviceOps], ets: Optional[DeviceOps],
                       bussard: Optional[DeviceOps]) -> Dict[str, object]:
    """The property elements either side wrote in the step, compared on
    their final values (see the module doc). The writes `image` never
    compares (`image.property_exemption`) are listed under `not_compared`;
    the security object's properties compare whole, by `image.value_check`
    (the group key table and the sender table by entry, the sender
    table's sequence numbers a note)."""
    labels = object_labels(list(base) + [ets, bussard])
    before: Dict[Tuple[str, int, int], str] = {}
    for ops in base:
        before.update(property_elements(ops, labels))
    ets_step, ours_step = property_elements(ets, labels), property_elements(bussard, labels)
    ets_final, ours_final = dict(before), dict(before)
    ets_final.update(ets_step)
    ours_final.update(ours_step)
    touched = sorted(set(ets_step) | set(ours_step))
    differences, notes = [], []
    matched, ets_only, bussard_only, value = [], [], [], 0
    not_compared: List[Dict[str, object]] = []
    whole_done = set()
    for key in touched:
        label, pid, _ = key
        name = "%s PID %d [%d]" % key
        reason = memimage.property_exemption(label, pid)
        if reason is not None:
            # imgdiff's shape, which the oracle summary prints.
            if not any(e["key"] == [label, pid] for e in not_compared):
                not_compared.append({"key": [label, pid], "reason": reason})
            continue
        if label.startswith("type%d." % memimage.SECURITY_OBJECT_TYPE):
            if (label, pid) in whole_done:
                continue
            whole_done.add((label, pid))
            name = "%s PID %d" % (label, pid)
            a, b = _whole(ours_final, label, pid), _whole(ets_final, label, pid)
            if not a or not b:
                (ets_only if not a else bussard_only).append(name)
                differences.append({"property": name, "bussard": a or "--", "ets": b or "--"})
                continue
            obj = {"type": memimage.SECURITY_OBJECT_TYPE, "instance": int(label.split(".")[1])}
            outcome, why = memimage.value_check({"object": obj, "pid": pid, "data": a},
                                                {"object": obj, "pid": pid, "data": b})
            if outcome in ("equal", "hash-equal"):
                matched.append(name)
                if why:
                    notes.append("%s: %s" % (name, why))
            else:
                value += 1
                differences.append({"property": name, "bussard": a, "ets": b, "why": why})
            continue
        a, b = ours_final.get(key), ets_final.get(key)
        if a is not None and a == b:
            matched.append(name)
            continue
        if a is None:
            ets_only.append(name)
        elif b is None:
            bussard_only.append(name)
        else:
            value += 1
        differences.append({"property": name, "bussard": a or "--", "ets": b or "--"})
    compared = len(matched) + len(differences)
    # The keys the offline oracle's summary reads (as for imgdiff's
    # property parity): props=ok(<matched>) or props=differs(...).
    return {
        "verdict": (memimage.NOT_COMPARABLE if not compared else memimage.DIFFERS if differences
                    else memimage.IDENTICAL),
        "compared": compared, "differing": len(differences),
        "ets_step": len(ets_step), "bussard_step": len(ours_step),
        "matched": matched, "ets_only": ets_only, "bussard_only": bussard_only,
        "value_counts": {"differs": value},
        "not_compared": not_compared, "notes": notes,
        "differences": differences[:64],
    }


def region_of(addr: int, segs: Dict[int, Tuple[int, int]]) -> Tuple[str, int]:
    """The region name and the region's start for an address."""
    for obj, (start, length) in sorted(segs.items()):
        if start <= addr < start + length:
            return REGION_NAMES.get(obj, "application (obj%d)" % obj), start
    return "memory 0x%04X" % (addr & ~0xFF), addr & ~0xFF


def _records(ops: Optional[DeviceOps]) -> List[Dict[str, object]]:
    if ops is None:
        return []
    return [dict(r, event=memimage.load_event_name(str(r["form"]), str(r["data"])))
            for r in memimage.load_control_writes(ops)]


def compare_states(
    base: List[DeviceOps],
    ets: Optional[DeviceOps],
    bussard: Optional[DeviceOps],
    device: str = "",
) -> Dict[str, object]:
    """ETS's and bussard's device state after one partial download (see the
    module doc). `ets` or `bussard` None: that side wrote nothing."""
    before: Dict[int, int] = {}
    for ops in base:
        before.update(writes(ops))
    ets_step, ours_step = writes(ets), writes(bussard)
    ets_final = dict(before)
    ets_final.update(ets_step)
    ours_final = dict(before)
    ours_final.update(ours_step)
    segs = segments(list(base) + [ets, bussard])
    touched = sorted(set(ets_step) | set(ours_step))
    regions: Dict[str, Dict[str, object]] = {}
    for addr in touched:
        name, start = region_of(addr, segs)
        reg = regions.setdefault(name, {"region": name, "start": start, "compared": 0, "diff_octets": 0,
                                        "unknown_octets": 0, "ets_written": 0, "bussard_written": 0,
                                        "first_offset": None, "differences": []})
        reg["compared"] = int(reg["compared"]) + 1
        reg["ets_written"] = int(reg["ets_written"]) + (addr in ets_step)
        reg["bussard_written"] = int(reg["bussard_written"]) + (addr in ours_step)
        a, b = ours_final.get(addr), ets_final.get(addr)
        if a is None or b is None or a != b:
            reg["diff_octets"] = int(reg["diff_octets"]) + 1
            # One side never had a value for it: a write the other tool
            # never makes (an unknown value is no match).
            reg["unknown_octets"] = int(reg["unknown_octets"]) + (a is None or b is None)
            if reg["first_offset"] is None:
                reg["first_offset"] = addr - start
            diffs = reg["differences"]
            if isinstance(diffs, list) and len(diffs) < 64:
                diffs.append({"address": addr,
                              "bussard": "--" if a is None else "%02x" % a,
                              "ets": "--" if b is None else "%02x" % b})
    out_regions = []
    for reg in sorted(regions.values(), key=lambda r: int(r["start"])):
        reg["verdict"] = memimage.DIFFERS if reg["diff_octets"] else memimage.IDENTICAL
        if reg["diff_octets"]:
            first = int(reg["start"]) + int(reg["first_offset"] or 0)
            lo = first - EXCERPT
            reg["bussard_hex"] = "".join("--" if ours_final.get(x) is None else "%02x" % ours_final[x]
                                         for x in range(lo, first + EXCERPT))
            reg["ets_hex"] = "".join("--" if ets_final.get(x) is None else "%02x" % ets_final[x]
                                     for x in range(lo, first + EXCERPT))
        out_regions.append(reg)
    compared = len(touched)
    differing = sum(int(r["diff_octets"]) for r in out_regions)
    # The headline is the memory's, as imgdiff's: the property writes have
    # their own verdict under `properties`, which a row pins with props=.
    # A step in which neither side wrote memory but the property elements
    # compared (a property-only program, issue #1074) takes their verdict,
    # as imgdiff does for a property-only plan (#1043).
    props = compare_properties(base, ets, bussard)
    if not compared and props.get("compared"):
        verdict = str(props["verdict"])
        reason = "no memory written in this step; the property elements are the verdict"
    elif not compared:
        verdict, reason = memimage.NOT_COMPARABLE, "neither side wrote memory in this step"
    elif differing:
        verdict, reason = memimage.DIFFERS, ""
    else:
        verdict, reason = memimage.IDENTICAL, ""
    lc = memimage.compare_load_control_records(_records(bussard), _records(ets))
    if not _records(ets) and not _records(bussard):
        lc = {"verdict": memimage.NOT_COMPARABLE, "reason": "no load-control record on either side",
              "bussard_records": 0, "ets_records": 0}
    # The order of the state-changing operations (issue #1055): its own
    # verdict, never the row's.
    order = sequence.compare_captures(ets, bussard)
    return {
        "device": device,
        "application": None,
        "system": "apply",
        "verdict": verdict,
        "reason": reason,
        "coverage": {"placed": compared, "compared": compared, "percent": 100.0 if compared else 0.0,
                     "min_percent": 0.0, "pages": 0, "blind_pages": [], "thin": False, "reason": ""},
        "regions": out_regions,
        "octets": {"ets_step": len(ets_step), "bussard_step": len(ours_step), "compared": compared,
                   "differing": differing},
        "properties": props,
        "ets_only_octets": 0,
        "ets_only_ranges": [],
        "load_controls": lc,
        "sequence": order,
    }


def render(report: Dict[str, object]) -> List[str]:
    octets = report["octets"]
    lines = ["%s partial download (apply): %s%s" % (
        report["device"], report["verdict"], " (%s)" % report["reason"] if report["reason"] else "")]
    lines.append("  octets written in the step: ETS %d, bussard %d; compared %d (final state), %d differ"
                 % (octets["ets_step"], octets["bussard_step"], octets["compared"], octets["differing"]))
    for reg in report["regions"]:
        unknown = int(reg.get("unknown_octets") or 0)
        line = "  %-22s @0x%04X  %4d compared (ETS wrote %d, bussard %d)  %s" % (
            reg["region"], reg["start"], reg["compared"], reg["ets_written"], reg["bussard_written"],
            reg["verdict"] if not reg["diff_octets"] else "differs: %d octet(s), first at +0x%X%s"
            % (reg["diff_octets"], reg["first_offset"],
               ", %d of them without a value on one side (`--`)" % unknown if unknown else ""))
        lines.append(line)
        if reg["diff_octets"]:
            lines.append("      bussard: %s" % reg["bussard_hex"])
            lines.append("      ets    : %s" % reg["ets_hex"])
    props = report.get("properties") or {}
    if props.get("compared"):
        lines.append("  property elements written in the step: ETS %d, bussard %d; compared %d (final state), %d differ"
                     % (props["ets_step"], props["bussard_step"], props["compared"], props["differing"]))
        for d in props.get("differences") or []:
            lines.append("      %-28s bussard %s  ets %s" % (d["property"], d["bussard"][:40], d["ets"][:40]))
    for e in props.get("not_compared") or []:
        lines.append("  not compared: %s PID %s (%s)" % (e["key"][0], e["key"][1], e["reason"]))
    for note in props.get("notes") or []:
        lines.append("  note: %s" % note)
    lines.extend(memimage.render_load_controls(report.get("load_controls")))
    lines.extend(sequence.render(report.get("sequence")))
    return lines
