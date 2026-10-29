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
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import image as memimage
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
    if not compared:
        verdict, reason = memimage.NOT_COMPARABLE, "neither side wrote memory in this step"
    elif differing:
        verdict, reason = memimage.DIFFERS, ""
    else:
        verdict, reason = memimage.IDENTICAL, ""
    lc = memimage.compare_load_control_records(_records(bussard), _records(ets))
    if not _records(ets) and not _records(bussard):
        lc = {"verdict": memimage.NOT_COMPARABLE, "reason": "no load-control record on either side",
              "bussard_records": 0, "ets_records": 0}
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
        "ets_only_octets": 0,
        "ets_only_ranges": [],
        "load_controls": lc,
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
    lines.extend(memimage.render_load_controls(report.get("load_controls")))
    return lines
