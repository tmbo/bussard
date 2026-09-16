#!/usr/bin/env python3
"""analyze-load-ops.py — tally LoadProcedure ``LdCtrl*`` ops across the extracted
product-corpus model YAMLs and rank the ops ``bussard flash`` does NOT execute.

This is a standalone analysis aid (no workspace deps). It reads the rendered
``load_procedure:`` block of every ``models/*.yaml`` under a corpus cache
directory, classifies each op against bussard's supported set (from
``crates/bussard-download/src/flash.rs``), and prints:

  * the support matrix (supported / refused op, corpus frequency),
  * the ranked unimplemented-op table (op, #apps, #manufacturers, examples,
    whether the app is otherwise fully executable),
  * whether any real vendor app uses ``LdCtrlMasterReset``.

The model YAMLs are derived from copyrighted vendor data and are gitignored;
only this script and the report it feeds are committed. Regenerate the corpus
with ``tests-support/product-corpus/fetch.sh`` (or by importing each index
entry), then run this over ``cache/``.

Usage:
    tests-support/product-corpus/analyze-load-ops.py [CACHE_DIR]

CACHE_DIR defaults to tests-support/product-corpus/cache.
"""

import json
import os
import re
import sys
from collections import defaultdict

# The set bussard's plan_flash lowers to an executable FlashStep (flash.rs).
# These are the rendered snake-case op tokens produced by import-product.
SUPPORTED = {
    "connect",
    "disconnect",
    "unload",
    "load",
    "load_completed",
    "rel_segment",
    "write_rel_mem",
    "write_mem",
    "write_prop",
    "compare_prop",
    "load_image_prop",
    "restart",
}

# Ops bussard refuses today, with the wire/mgmt work each would need.
# A "raw <Name>" op renders with the verbatim LdCtrl name; we key those by name.
REFUSED_NEED = {
    "abs_segment": "absolute-segment allocate (LdCtrlAbsSegment) + A_Memory placement; mgmt allocate is a stub",
    "task_segment": "task/segment descriptor write (LdCtrlTaskSegment)",
    "task_ctrl1": "task-control-1 write (LdCtrlTaskCtrl1)",
    "LdCtrlMasterReset": "A_Restart with the master-reset erase code (device wipe before load)",
    "LdCtrlCompareRelMem": "read-relative-memory + byte compare (issue #51)",
    "LdCtrlTaskPtr": "task-pointer table write (LdCtrlTaskPtr)",
    "LdCtrlTaskCtrl2": "task-control-2 write (LdCtrlTaskCtrl2)",
    "LdCtrlCompareMem": "read absolute memory (A_Memory_Read) + byte compare",
}


def op_key(line):
    """The classification key for one rendered load_procedure line.

    ``- raw LdCtrlFoo [..]`` -> ``LdCtrlFoo``; ``- foo bar=..`` -> ``foo``.
    """
    body = line[2:].strip() if line.startswith("- ") else line.strip()
    toks = body.split()
    if not toks:
        return None
    if toks[0] == "raw" and len(toks) > 1:
        return toks[1]
    return toks[0]


def load_procedures(path):
    """Yield each op line inside the ``load_procedure:`` block of a model YAML."""
    inside = False
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("load_procedure:"):
                inside = True
                continue
            if inside:
                if line.startswith("- "):
                    yield line.rstrip("\n")
                elif line.strip() == "" or line.startswith(" "):
                    continue  # blank / indented continuation — stay in block
                else:
                    inside = False


MODEL_RE = re.compile(r"^(M-[0-9A-Fa-f]{4})_")


def manufacturer_names(repo_root):
    """Map M-id -> vendor name from the product index (best effort)."""
    names = {}
    idx = os.path.join(repo_root, "data", "product-index.json")
    try:
        data = json.load(open(idx, encoding="utf-8"))
        for e in data.get("entries", []):
            names[e.get("manufacturer_id", "")] = e.get("manufacturer", "")
    except Exception:
        pass
    return names


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    default = os.path.join(repo_root, "tests-support", "product-corpus", "cache")
    cache = sys.argv[1] if len(sys.argv) > 1 else default
    models_dir = os.path.join(cache, "models")
    if not os.path.isdir(models_dir):
        sys.exit(f"no models/ under {cache}; run fetch.sh first")
    names = manufacturer_names(repo_root)

    files = sorted(f for f in os.listdir(models_dir) if f.endswith(".yaml"))
    total_op_count = defaultdict(int)
    apps_using = defaultdict(set)
    mfrs_using = defaultdict(set)
    app_ops = {}
    app_mfr = {}

    for f in files:
        mid_m = MODEL_RE.match(f)
        mid = mid_m.group(1) if mid_m else "?"
        app_mfr[f] = mid
        keys = set()
        for line in load_procedures(os.path.join(models_dir, f)):
            k = op_key(line)
            if k is None:
                continue
            total_op_count[k] += 1
            apps_using[k].add(f)
            mfrs_using[k].add(mid)
            keys.add(k)
        app_ops[f] = keys

    all_mfrs = sorted(set(app_mfr.values()))
    print(
        f"Corpus: {len(files)} application programs across "
        f"{len(all_mfrs)} manufacturers "
        f"({', '.join(names.get(m, m) for m in all_mfrs)})"
    )
    print()

    print("=== Support matrix (op -> supported?, occurrences, #apps, #mfrs) ===")
    for k in sorted(total_op_count, key=lambda x: -total_op_count[x]):
        sup = "SUPPORTED" if k in SUPPORTED else "REFUSED  "
        print(
            f"  {sup}  {k:<24} occ={total_op_count[k]:>4}  "
            f"apps={len(apps_using[k]):>3}  mfrs={len(mfrs_using[k])}"
        )
    print()

    refused = [k for k in total_op_count if k not in SUPPORTED]
    refused.sort(key=lambda k: (-len(apps_using[k]), -len(mfrs_using[k])))

    print("=== Ranked UNIMPLEMENTED ops ===")
    for k in refused:
        ex = ", ".join(sorted(names.get(m, m) for m in mfrs_using[k]))
        only_blocker = sum(
            1
            for a in apps_using[k]
            if not {o for o in app_ops[a] if o not in SUPPORTED and o != k}
        )
        need = REFUSED_NEED.get(k, "?")
        print(
            f"{k:<22} apps={len(apps_using[k]):>3} mfrs={len(mfrs_using[k])}  "
            f"[{ex}]"
        )
        print(f"    apps blocked ONLY by this op: {only_blocker}")
        print(f"    need: {need}")
    print()

    fully = [a for a in files if app_ops[a] <= SUPPORTED]
    print(f"Apps fully executable by bussard today: {len(fully)}/{len(files)}")

    mr = apps_using.get("LdCtrlMasterReset", set())
    print(
        f"LdCtrlMasterReset used by {len(mr)} app(s): "
        f"{sorted(mr) if mr else 'NONE'}"
    )


if __name__ == "__main__":
    main()
