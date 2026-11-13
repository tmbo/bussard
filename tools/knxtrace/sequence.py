"""The order of a download's state-changing operations: ETS's against bussard's.

The state comparisons (`image.compare`, `statediff.compare_states`) judge the
device after the download: memory, property elements, load-control records.
Two downloads can end in the same state and still send their writes in a
different order relative to a load-state event or a restart, which a real
device may not forgive (bussard issue #1055). This module reports that order
as its own verdict, next to the state verdicts and never changing them.

`operations` lists the requests of one capture in order (`compose` writes
them as `sequence.json`); `plan_operations` lists the steps of a dry run's
`plan.json` the same way. Each entry is one of

- `load-control`: a record to a load-state machine (`image.load_control_writes`),
  by object (the LSM on System 7) and event (`image.load_event_name`);
- `mem-write`: a memory write, by target: `objN` for the relative segment
  of object N (System B: its allocation and the `PID_TABLE_REFERENCE` the
  tool read), `lsmN` for the absolute segment of LSM N (System 7, from the
  `AbsSegment` records in either form), else the
  256-octet page (`mem 0x4800`);
- `prop-write`: a property write (`image.property_writes`), by object and PID;
- `fcall`: a load procedure's function property call
  (`image.function_property_calls`), by object and PID;
- `restart`: an `A_Restart`, basic or master reset with its erase code;
- `read`: a property, memory or property description read;
- `connect` / `disconnect`: the transport connection, listed, not compared
  (a dry run plans no connection, and how often a tool cycles it is benign).

The kind-local `seq` of a load control, property write or function call is
its position in `load_controls.json`, `properties.json` or
`function_properties.json`, so the comparisons' own results apply.

`compare` turns both lists into tokens and compares them in order, after the
normalisations the state comparison applies:

- consecutive writes to one target are one token: the APDU chunking of one
  memory range, the element runs of one property, an immediate repeat of a
  load-control record;
- a property write counts only when the state comparison counted it
  (`image.compare_properties`: matched, bussard-only or ETS-only), under the
  object label it paired on. The writes it lists and does not count (ETS's
  commissioning writes, `NOT_COMPARED_ETS_WRITES`, the verify-mode switch
  ETS skipped, the writes outside an IP Secure plan) drop out. For two
  captures (`statediff`) the rule is `statediff.property_elements`':
  `image.property_exemption` drops out, the objects meet by type;
- the memory writes to a segment bussard streams by read-compare (mask
  0701) are no tokens on either side: the device's content decides which
  octets go out, and the state comparison judges them;
- reads, connects and disconnects are no tokens.

The verdict is `identical` (`seq=ok(n)`, n tokens), `differs` with the first
divergence, or `not-comparable` when a side has no operation list (an image
directory from before `sequence.json`). The reads are counted per side by
kind and key and listed as ETS-only and bussard-only counts, never judged;
the dry run lists only the reads it plans as steps (verify and MCB reads,
description reads), not its pre-flight probe.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, List, Optional, Tuple

import image as memimage
from normalize import (
    KIND_CONNECT,
    KIND_DISCONNECT,
    KIND_MEM_READ,
    KIND_PROP_DESC_READ,
    KIND_PROP_READ,
    KIND_RESTART,
    DeviceOps,
)

SEQUENCE_FILE = "sequence.json"
READ_KINDS = ("property", "memory", "description")
MAX_TOKENS = 400  # tokens kept per side in the report


# --------------------------------------------------------------------------
# operations
# --------------------------------------------------------------------------


def _segments(allocs: List[Dict[str, object]], refs: Dict[int, int]) -> List[Tuple[int, int, str]]:
    """(start, end, label) of every segment an allocation list names: an
    absolute segment by its LSM, a relative one by its object at the base the
    tool read (the last allocation's base wins, as in `image.EtsMemory`)."""
    bases = dict(refs)
    sizes: Dict[int, int] = {}
    out: List[Tuple[int, int, str]] = []
    for rec in allocs:
        if rec.get("kind") == "abs-segment" and isinstance(rec.get("address"), int):
            start = int(rec["address"])
            out.append((start, start + int(rec.get("size") or 0), "lsm%s" % rec.get("lsm")))
        elif rec.get("kind") == "rel-segment" and isinstance(rec.get("object"), int):
            sizes[int(rec["object"])] = int(rec.get("size") or 0)
            if isinstance(rec.get("base"), int):
                bases[int(rec["object"])] = int(rec["base"])
    for obj, size in sizes.items():
        if obj in bases:
            out.append((bases[obj], bases[obj] + size, "obj%d" % obj))
    return out


def abs_segment(rec: Dict[str, object]) -> Optional[Tuple[Optional[int], int, int]]:
    """(load-state object, start, length) of one `AbsSegment` load-control
    record, in either form: the property record `[3][sub][start:2][len:2]...`,
    the System 7 memory record at 0x0104 one octet later (`[lsm|3][sub][00]
    [start:2][len:2]...`); None for any other record. The one parser of the
    record (`abs_segments`, `statediff.segments`, issue #1080)."""
    try:
        data = bytes.fromhex(str(rec["data"]))
    except ValueError:
        return None
    memory = rec.get("form") == "memory"
    at = 3 if memory else 2
    event = data[0] & 0x0F if memory else data[0] if data else None
    if event != 3 or len(data) < at + 4 or data[1] != memimage.SUB_ABS_DATA:
        return None
    start = int.from_bytes(data[at:at + 2], "big")
    length = int.from_bytes(data[at + 2:at + 4], "big")
    return memimage._lc_object(rec), start, length


def abs_segments(records: List[Dict[str, object]]) -> List[Tuple[int, int, str]]:
    """(start, end, `lsmN`) of every `AbsSegment` load-control record
    (`abs_segment`), in order."""
    out: List[Tuple[int, int, str]] = []
    for rec in records:
        seg = abs_segment(rec)
        if seg is not None:
            obj, start, length = seg
            out.append((start, start + length, "lsm%s" % obj))
    return out


def memory_target(addr: int, segments: List[Tuple[int, int, str]]) -> str:
    """The target label of a memory address (see the module doc)."""
    for start, end, label in segments:
        if start <= addr < end:
            return label
    return "mem 0x%04X" % (addr & ~0xFF)


def _single(ops: DeviceOps, op) -> DeviceOps:
    return DeviceOps(ops.device, [op])


def _prop_label(f: Dict[str, object]) -> str:
    if "obj_type" in f:
        return "type%s.%s" % (f.get("obj_type"), f.get("instance", 0))
    return "obj%s" % f.get("obj", 0)


def operations(ops: DeviceOps) -> List[Dict[str, object]]:
    """Every request of one capture the sequence comparison reads, in order
    (see the module doc). The kind-local `seq` numbers follow the image
    files' (`load_control_writes`, `property_writes`,
    `function_property_calls`), which are computed op by op here, so the
    rules of those lists apply unchanged."""
    segs = _segments(memimage.allocations(ops), memimage.table_refs(ops))
    segs += abs_segments(memimage.load_control_writes(ops))
    out: List[Dict[str, object]] = []
    n_lc = n_pw = n_fc = 0
    for op in ops.ops:
        if op.direction != "req":
            continue
        one = _single(ops, op)
        lc = memimage.load_control_writes(one)
        pw = memimage.property_writes(one)
        fc = memimage.function_property_calls(one)
        n_lc += len(lc)
        n_pw += len(pw)
        n_fc += len(fc)
        entry: Optional[Dict[str, object]] = None
        if lc:
            rec = lc[0]
            entry = {"op": "load-control", "seq": n_lc, "object": memimage._lc_object(rec),
                     "event": memimage.load_event_name(str(rec["form"]), str(rec["data"]))}
        elif fc:
            entry = {"op": "fcall", "seq": n_fc, "object": fc[0]["object"], "pid": fc[0]["pid"]}
        elif pw:
            entry = {"op": "prop-write", "seq": n_pw, "object": pw[0]["object"], "pid": pw[0]["pid"],
                     "service": pw[0]["service"]}
        else:
            mw = memimage.memory_writes(one)
            apdu = op.apdu
            if mw:
                addr, data = mw[0]
                entry = {"op": "mem-write", "address": addr, "length": len(data),
                         "target": memory_target(addr, segs)}
            elif op.kind == KIND_RESTART and apdu is not None and apdu.name == "A_Restart":
                entry = {"op": "restart", "type": apdu.fields.get("type", "basic")}
                if apdu.fields.get("erase_code") is not None:
                    entry["erase_code"] = apdu.fields["erase_code"]
            elif op.kind == KIND_PROP_READ and apdu is not None and "pid" in apdu.fields:
                entry = {"op": "read", "read": "property",
                         "key": "%s PID %s" % (_prop_label(apdu.fields), apdu.fields["pid"])}
            elif op.kind == KIND_PROP_DESC_READ and apdu is not None and "pid" in apdu.fields:
                entry = {"op": "read", "read": "description",
                         "key": "%s PID %s" % (_prop_label(apdu.fields), apdu.fields["pid"])}
            elif op.kind == KIND_MEM_READ and isinstance(op.detail.get("addr_int"), int):
                entry = {"op": "read", "read": "memory",
                         "key": memory_target(int(op.detail["addr_int"]), segs)}
            elif op.kind in (KIND_CONNECT, KIND_DISCONNECT):
                entry = {"op": op.kind}
        if entry is not None:
            entry["pos"] = len(out) + 1
            out.append(entry)
    return out


def write_operations(ops: DeviceOps, out_dir: str) -> None:
    """Writes `operations(ops)` as `sequence.json` into an image directory."""
    with open(os.path.join(out_dir, SEQUENCE_FILE), "w", encoding="utf-8") as fh:
        json.dump(operations(ops), fh, indent=1)
        fh.write("\n")


def load_operations(image_dir: str) -> Optional[List[Dict[str, object]]]:
    """An image directory's `sequence.json`, or None when it has none."""
    try:
        with open(os.path.join(image_dir, SEQUENCE_FILE), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


ERASE_CODE = re.compile(r"erase code (\d+)")
PROP_READ_LABEL = re.compile(r"\((object(?: type)? \d+(?: #\d+)?), PID (\d+)")
MCB_READ_LABEL = re.compile(r"\(object (\d+), PID (\d+)")


def _label_object(text: str) -> str:
    """`object 4` -> obj4, `object type 17 #1` -> type17.1 (`PropObject`'s
    Display in bussard-download)."""
    m = re.match(r"object type (\d+)(?: #(\d+))?", text)
    if m:
        return "type%s.%s" % (m.group(1), m.group(2) or 1)
    return "obj%s" % text.split()[-1]


def _step_restart(label: str) -> Optional[Dict[str, object]]:
    """The restart a plan step sends, from its label (the dump has no
    structured record for it)."""
    low = label.lower()
    if "master reset" in low or "factory reset" in low:
        m = ERASE_CODE.search(label)
        out: Dict[str, object] = {"op": "restart", "type": "master-reset"}
        if m:
            out["erase_code"] = int(m.group(1))
        return out
    if "restart device" in low or "a_restart" in low:
        return {"op": "restart", "type": "basic"}
    return None


def _step_reads(label: str, step: dict, segs: List[Tuple[int, int, str]]) -> List[Dict[str, object]]:
    """The reads a plan step names (verify and MCB reads, read-compare)."""
    out: List[Dict[str, object]] = []
    if label.startswith("verify property") or label.startswith("verify image") \
            or label.startswith("read image MCB"):
        m = PROP_READ_LABEL.search(label)
        if m:
            out.append({"op": "read", "read": "property",
                        "key": "%s PID %s" % (_label_object(m.group(1)), m.group(2))})
    elif label.startswith("verify relative memory"):
        m = re.search(r"\(obj (\d+)\)", label)
        out.append({"op": "read", "read": "memory", "key": "obj%s" % m.group(1) if m else "obj?"})
    elif label.startswith("[S7] verify memory") or "read-compare" in label:
        m = re.search(r"(?:at|to) 0x([0-9A-Fa-f]+)", label)
        if m:
            out.append({"op": "read", "read": "memory",
                        "key": memory_target(int(m.group(1), 16), segs)})
    desc = step.get("property_description")
    if isinstance(desc, dict):
        if desc.get("object_type") is not None:
            obj = "type%s.%s" % (desc["object_type"], desc.get("instance", 1))
        else:
            obj = "obj%s" % desc.get("object")
        out.append({"op": "read", "read": "description", "key": "%s PID %s" % (obj, desc.get("pid"))})
    return out


def plan_operations(plan: dict) -> List[Dict[str, object]]:
    """bussard's operations from a dry run's `plan.json`, in plan order, in
    the form of `operations` (with the plan `step` instead of a kind-local
    `seq`). Within a step: its load-control records, its image, its property
    writes (`image.plan_property_writes`, split as they go on the wire), its
    function property call, its restart; its reads after them."""
    segs = _segments(list(plan.get("allocations") or []), {})
    props: Dict[object, List[Dict[str, object]]] = {}
    for w in memimage.plan_property_writes(plan):
        props.setdefault(w.get("step"), []).append(w)
    calls = {c["step"]: c for c in memimage.plan_function_calls(plan)}
    out: List[Dict[str, object]] = []
    # The verify-mode step only arms the switch: the executor writes
    # obj0 PID_DEVICE_CONTROL right before the next memory write, after that
    # step's load-control records (issues #705, #1076), so its write is held
    # until then. An armed switch with no later memory write is never sent.
    armed: List[Dict[str, object]] = []
    for step in plan.get("steps", []):
        n = step.get("index")
        label = re.sub(r"^\d+\.\s*", "", str(step.get("label") or ""))
        entries: List[Dict[str, object]] = []
        for rec in step.get("load_controls") or []:
            if isinstance(rec, dict):
                entries.append({"op": "load-control", "object": memimage._lc_object(rec),
                                "event": memimage.load_event_name(str(rec.get("form")),
                                                                  str(rec.get("data")))})
        img = step.get("image")
        # An image of nothing but its segment's pre-fill octet is no memory
        # write on the wire: the executor streams only octets that differ
        # from the fill, as ETS does (issue #1088, `fill_only` in plan.json).
        if isinstance(img, dict) and not img.get("fill_only"):
            if img.get("address") is not None:
                target = memory_target(int(img["address"]), segs)
            else:
                target = "obj%s" % img.get("object")
            entry = {"op": "mem-write", "target": target, "length": img.get("length")}
            if "read-compare" in label:
                # A read-compare stream (mask 0701) writes only the octets
                # the device does not already hold.
                entry["read_compare"] = True
            entries.extend(armed)
            armed = []
            entries.append(entry)
        for w in props.get(n, []):
            write = {"op": "prop-write", "object": w["object"], "pid": w["pid"]}
            if label.startswith("enable verify mode"):
                # Keeps its own step: the state comparison counted it there.
                write["step"] = n
                armed.append(write)
            else:
                entries.append(write)
        if n in calls:
            entries.append({"op": "fcall", "object": calls[n]["object"], "pid": calls[n]["pid"]})
        restart = _step_restart(label)
        if restart is not None:
            entries.append(restart)
        entries.extend(_step_reads(label, step, segs))
        for e in entries:
            e.setdefault("step", n)
            e["pos"] = len(out) + 1
            out.append(e)
    return out


# --------------------------------------------------------------------------
# tokens and the comparison
# --------------------------------------------------------------------------


def _obj_text(obj: object) -> str:
    if isinstance(obj, dict):
        return memimage._obj_label(obj)
    return "obj%s" % obj


def _token(e: Dict[str, object], prop_label: Optional[str] = None) -> Optional[str]:
    op = e.get("op")
    if op == "load-control":
        return "load-control obj%s %s" % (e.get("object"), e.get("event"))
    if op == "mem-write":
        return "mem-write %s" % e.get("target")
    if op == "prop-write":
        return "prop-write %s" % (prop_label or "%s PID %s" % (_obj_text(e.get("object")), e.get("pid")))
    if op == "fcall":
        return "fcall %s PID %s" % (_obj_text(e.get("object")), e.get("pid"))
    if op == "restart":
        if e.get("type") == "master-reset":
            return "restart master-reset erase %s" % e.get("erase_code", "?")
        return "restart"
    return None


def collapse(tokens: Iterable[str]) -> List[Tuple[str, int]]:
    """Consecutive equal tokens as one, with the count (see the module doc)."""
    out: List[Tuple[str, int]] = []
    for t in tokens:
        if out and out[-1][0] == t:
            out[-1] = (t, out[-1][1] + 1)
        else:
            out.append((t, 1))
    return out


def tokens(ops: List[Dict[str, object]], keep_prop=None) -> List[Tuple[str, int]]:
    """The collapsed tokens of an operation list. `keep_prop(entry)` returns
    the label a property write counts under, or None to drop it."""
    out: List[str] = []
    for e in ops:
        label = None
        if e.get("op") == "prop-write" and keep_prop is not None:
            label = keep_prop(e)
            if label is None:
                continue
        t = _token(e, label)
        if t is not None:
            out.append(t)
    return collapse(out)


def read_counts(ours: List[Dict[str, object]], ets: List[Dict[str, object]]) -> Dict[str, object]:
    """The reads of each side by kind, and how many of them only one side
    sends (by kind and key, a multiset difference). Never judged."""

    def counted(ops: List[Dict[str, object]]) -> Dict[Tuple[str, str], int]:
        out: Dict[Tuple[str, str], int] = {}
        for e in ops:
            if e.get("op") == "read":
                k = (str(e.get("read")), str(e.get("key")))
                out[k] = out.get(k, 0) + 1
        return out

    a, b = counted(ours), counted(ets)
    result: Dict[str, object] = {"bussard": {}, "ets": {}, "bussard_only": {}, "ets_only": {},
                                 "ets_only_keys": [], "bussard_only_keys": []}
    for kind in READ_KINDS:
        result["bussard"][kind] = sum(n for (k, _), n in a.items() if k == kind)
        result["ets"][kind] = sum(n for (k, _), n in b.items() if k == kind)
        result["bussard_only"][kind] = sum(max(0, n - b.get(key, 0)) for key, n in a.items() if key[0] == kind)
        result["ets_only"][kind] = sum(max(0, n - a.get(key, 0)) for key, n in b.items() if key[0] == kind)
    result["ets_only_keys"] = ["%s %s x%d" % (k, key, n - a.get((k, key), 0))
                               for (k, key), n in sorted(b.items()) if n > a.get((k, key), 0)][:40]
    result["bussard_only_keys"] = ["%s %s x%d" % (k, key, n - b.get((k, key), 0))
                                   for (k, key), n in sorted(a.items()) if n > b.get((k, key), 0)][:40]
    return result


def first_divergence(ours: List[str], ets: List[str]) -> Optional[Dict[str, object]]:
    """The first place two token lists part, or None when they are equal:
    the first position where they differ, as an `order` difference when
    each side's token there still comes later on the other side, else as the
    operation only one side sends from there on."""
    if ours == ets:
        return None
    k = 0
    while k < len(ours) and k < len(ets) and ours[k] == ets[k]:
        k += 1
    a = ours[k] if k < len(ours) else None
    b = ets[k] if k < len(ets) else None
    after = ours[k - 1] if k > 0 else None
    if a is not None and b is not None and a in ets[k:] and b in ours[k:]:
        kind, text = "order", "bussard %s where ETS %s" % (a, b)
    elif b is not None and (a is None or b not in ours[k:]):
        kind, text = "ets-only", "ETS-only %s" % b
    elif a is not None and (b is None or a not in ets[k:]):
        kind, text = "bussard-only", "bussard-only %s" % a
    else:
        kind, text = "replace", "bussard %s where ETS %s" % (a, b)
    if after is not None:
        text += " (after %s)" % after
    return {"kind": kind, "position": k + 1, "bussard": a, "ets": b, "after": after, "text": text}


def _result(ours_t: List[Tuple[str, int]], ets_t: List[Tuple[str, int]],
            ours_ops: List[Dict[str, object]], ets_ops: List[Dict[str, object]]) -> Dict[str, object]:
    a = [t for t, _ in ours_t]
    b = [t for t, _ in ets_t]
    first = first_divergence(a, b)
    return {
        "verdict": memimage.IDENTICAL if first is None else memimage.DIFFERS,
        "compared": len(b) if first is None else min(len(a), len(b)),
        "bussard_tokens": len(a), "ets_tokens": len(b),
        "first": first,
        "bussard": ["%s x%d" % (t, n) if n > 1 else t for t, n in ours_t][:MAX_TOKENS],
        "ets": ["%s x%d" % (t, n) if n > 1 else t for t, n in ets_t][:MAX_TOKENS],
        "reads": read_counts(ours_ops, ets_ops),
    }


def not_comparable(reason: str) -> Dict[str, object]:
    """The `seq=n/c` result, with why."""
    return {"verdict": memimage.NOT_COMPARABLE, "reason": reason}


def compare_plan(plan: dict, image_dir: str, props: Dict[str, object]) -> Dict[str, object]:
    """bussard's planned order against ETS's `sequence.json` (see the module
    doc). `props` is `image.compare_properties`' result for the same pair,
    which decides the property writes that count and their labels."""
    ets_ops = load_operations(image_dir)
    if ets_ops is None:
        return not_comparable("no %s (re-run `knxtrace image`)" % SEQUENCE_FILE)
    if "load_control_records" not in plan:
        return not_comparable("plan.json lists no load_controls (rebuild bussard)")
    if plan.get("system") == memimage.IP_SECURE_SYSTEM:
        return not_comparable("an IP Secure plan covers part of the capture only")
    ours_ops = plan_operations(plan)

    # The property writes the state comparison counted, under the label
    # they paired on: by ETS seq and by bussard step.
    ets_label: Dict[int, str] = {}
    ours_label: Dict[Tuple[object, str], str] = {}

    def text(key: list) -> str:
        return "%s PID %s" % (key[0], key[1])

    def note_ours(step: object, key: list) -> None:
        ours_label[(step, text(key))] = text(key)

    for m in props.get("matched") or []:
        parts_e = m.get("ets_parts") or [{"ets_seq": m.get("ets_seq")}]
        for p in parts_e:
            if p.get("ets_seq") is not None:
                ets_label[int(p["ets_seq"])] = text(m["key"])
        for p in m.get("bussard_parts") or [{"step": m.get("step")}]:
            note_ours(p.get("step"), m["key"])
    for e in props.get("ets_only") or []:
        for p in e.get("parts") or [{"ets_seq": e.get("ets_seq")}]:
            if p.get("ets_seq") is not None:
                ets_label[int(p["ets_seq"])] = text(e["key"])
    for e in props.get("bussard_only") or []:
        for p in e.get("parts") or [{"step": e.get("step")}]:
            note_ours(p.get("step"), e["key"])

    def keep_ets(e: Dict[str, object]) -> Optional[str]:
        return ets_label.get(int(e.get("seq") or 0))

    def keep_ours(e: Dict[str, object]) -> Optional[str]:
        own = "%s PID %s" % (_obj_text(e.get("object")), e.get("pid"))
        return ours_label.get((e.get("step"), own))

    # The segments bussard streams by read-compare: whether a write goes
    # out depends on what the device holds, so neither side's writes to
    # them are tokens (their octets are the state comparison's).
    compared_only = {e["target"] for e in ours_ops if e.get("op") == "mem-write" and e.get("read_compare")}
    if compared_only:
        ours_ops = [e for e in ours_ops if not (e.get("op") == "mem-write" and e["target"] in compared_only)]
        ets_ops = [e for e in ets_ops if not (e.get("op") == "mem-write" and e.get("target") in compared_only)]
    result = _result(tokens(ours_ops, keep_ours), tokens(ets_ops, keep_ets), ours_ops, ets_ops)
    if compared_only:
        result["read_compare_targets"] = sorted(compared_only)
    return result


def compare_captures(ets: Optional[DeviceOps], bussard: Optional[DeviceOps]) -> Dict[str, object]:
    """Two captures' order (a partial download against knx-sim, `statediff`):
    the property writes counted as `statediff.property_elements` counts them."""
    if ets is None or bussard is None:
        return not_comparable("%s side has no operation list" % ("ETS's" if ets is None else "bussard's"))
    import statediff

    labels = statediff.object_labels([ets, bussard])
    ets_ops, ours_ops = operations(ets), operations(bussard)

    def keep(e: Dict[str, object]) -> Optional[str]:
        pid = e.get("pid")
        obj = e.get("object") or {}
        if not isinstance(pid, int) or pid == statediff.PID_LOAD_STATE_CONTROL \
                or e.get("service") in statediff.FUNCTION_SERVICES:
            return None
        if "index" in obj:
            label = labels.get(int(obj["index"])) or "obj%d" % obj["index"]
        else:
            label = "type%d.%d" % (obj["type"], obj["instance"])
        if memimage.property_exemption(label, pid) is not None:
            return None
        return "%s PID %d" % (label, pid)

    return _result(tokens(ours_ops, keep), tokens(ets_ops, keep), ours_ops, ets_ops)


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def summary(seq: Optional[Dict[str, object]]) -> str:
    """The `seq=` column of the oracle's summary line."""
    if not seq:
        return "seq=n/c"
    if seq.get("verdict") == memimage.IDENTICAL:
        return "seq=ok(%d)" % seq.get("ets_tokens", 0)
    if seq.get("verdict") == memimage.DIFFERS:
        return "seq=differs(first: %s)" % (seq.get("first") or {}).get("text", "?")
    return "seq=n/c"


def _reads_text(counts: Dict[str, int]) -> str:
    return ", ".join("%s %d" % (k, counts.get(k, 0)) for k in READ_KINDS)


def render(seq: Optional[Dict[str, object]]) -> List[str]:
    """The text lines of the sequence comparison and the read counts."""
    if not seq:
        return []
    if seq.get("verdict") == memimage.NOT_COMPARABLE:
        return ["  operation order: not comparable: %s" % seq.get("reason", "")]
    lines = ["  operation order: %s (bussard %d, ETS %d state-changing operation(s) after "
             "normalisation; not part of the verdict)" % (
                 seq["verdict"], seq.get("bussard_tokens", 0), seq.get("ets_tokens", 0))]
    first = seq.get("first")
    if first:
        lines.append("      first divergence at #%s: %s" % (first["position"], first["text"]))
        pos = int(first["position"]) - 1
        for side in ("bussard", "ets"):
            window = seq.get(side, [])[max(0, pos - 2):pos + 3]
            lines.append("      %-7s ... %s ..." % ("ETS" if side == "ets" else side, " | ".join(window)))
    reads = seq.get("reads") or {}
    if reads:
        lines.append("  reads (not judged): bussard %s; ETS %s" % (
            _reads_text(reads.get("bussard", {})), _reads_text(reads.get("ets", {}))))
        lines.append("      ETS-only: %s; bussard-only: %s" % (
            _reads_text(reads.get("ets_only", {})), _reads_text(reads.get("bussard_only", {}))))
    return lines
