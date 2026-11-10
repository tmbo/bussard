# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""The representative subset of the KNX Data Secure variant (#423).

    uv run tools/ets-sweep/secure_subset.py select [--products DIR] [--results DIR] [--out FILE]
    uv run tools/ets-sweep/secure_subset.py show

The owner chose a representative subset over every secure-capable
application (2026-11-10, as for the links variant #478), so
`secure.py run --representative` runs only the applications in
`secure-subset.json`: a greedy cover (`links_subset.greedy_cover`) over the
secure-capable applications (`IsSecureEnabled`) the defaults sweep captured
whose plain oracle row is identical, memory and load control both, so a
difference of the secure row is the secure download's. Each application
covers a set of labels:

    mask:<mask>                    the mask family
    iface:<mask>/tp | tunnelling   a plain TP device, or one with tunnelling
                                   addresses (AdditionalAddressesCount > 0);
    iface:<mask>/ip-interface      a tunnelling device without group objects
                                   (a KNX IP interface)
    tunnels:<n>                    the number of tunnelling addresses
    maker:<name>                   the manufacturer: every one the issue names, any
                                   other with at least MAKER_MIN candidates
    objects:<bucket>               how many group objects the application has
                                   (the security object's PID 61 has one flag each)
    group-keys:<bucket>            the group key table's capacity the product
                                   declares (SecurityCapacity), `undeclared` when none
    ia-table:<bucket>              the security individual address table's capacity
    secobj:<how>                   how the security object is reached: `ets` when
                                   the load procedure has no step on it (ETS
                                   addresses it by object type with the extended
                                   property services), `lp-index` when the load
                                   procedure writes PID 51 (security mode) of object
                                   index 9 itself
    tables:<iface>/<style>         how the tables load (links_subset.table_style), per
                                   TP device and tunnelling device
    modules, plugin                ModuleDefs instances, an EtsDownloadPlugin

`PINNED` applications come first whatever their plain verdict, with the
reason; the rest is the cover, ties to the shorter defaults run. The
labels an application added first are its reason. Re-derive with `select`
when the corpus grows.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import links_subset  # noqa: E402

HERE = Path(__file__).resolve().parent
SUBSET = HERE / "secure-subset.json"

# Manufacturer names for the labels, by KNX manufacturer id (the issue names
# the first nine); any other manufacturer with at least `MAKER_MIN`
# candidate applications gets a label under its id.
MAKERS = {"M-0001": "Siemens", "M-0002": "ABB", "M-0004": "Jung", "M-0007": "Busch-Jaeger", "M-0008": "Gira",
          "M-0009": "Hager", "M-0048": "Theben", "M-0071": "Zennio", "M-0083": "MDT", "M-0085": "GVS",
          "M-008E": "Steinel", "M-00A6": "Enertex", "M-00B6": "Ekinex", "M-00C5": "Weinzierl"}
MAKER_MIN = 3

# In the subset whatever their plain verdict.
PINNED = {
    "M-00A6_A-0014-10-2517": "the only secure-capable application of mask 0021 (Enertex IP Secure Interface); "
                             "its plain row is not comparable, so its secure row shows whether the sim and "
                             "ETS's secure commissioning work on that mask, not an attributable difference",
}


def secobj(model: dict) -> str:
    """`lp-index` when the load procedure writes PID 51 of object index 9,
    else `ets` (see the module doc)."""
    for lp in model.get("load_procedures") or []:
        for op in lp.get("ops") or []:
            if isinstance(op, dict):
                kind, v = next(iter(op.items()))
                if isinstance(v, dict) and v.get("prop_id") == 51 and v.get("obj_idx") == 9:
                    return "lp-index"
    return "ets"


def features(model: dict) -> set[str]:
    """The labels one secure-capable application covers (the module doc)."""
    bucket = links_subset.bucket
    mask = model.get("mask_version") or "?"
    n = len(model.get("com_objects") or {})
    tunnels = int(model.get("additional_addresses_count") or 0)
    iface = "tunnelling" if tunnels else "tp"
    out = {f"mask:{mask}", f"iface:{mask}/{iface}", f"secobj:{secobj(model)}",
           f"tables:{iface}/{links_subset.table_style(model)}",
           "objects:" + bucket(n, [(0, "none"), (10, "few <=10"), (50, "some 11-50"), (200, "many 51-200"),
                                   (1000, "very many 201-1000")], "huge >1000")}
    if tunnels:
        out.add(f"tunnels:{tunnels}")
        if not n:
            out.add(f"iface:{mask}/ip-interface")
    cap = model.get("security_capacity") or {}
    keys = cap.get("group_key_table_entries")
    out.add("group-keys:" + ("undeclared" if keys is None else
                             bucket(int(keys), [(255, "<=255"), (1100, "256-1100")], ">1100")))
    ias = cap.get("individual_address_entries")
    out.add("ia-table:" + ("undeclared" if ias is None else bucket(int(ias), [(100, "<=100"), (250, "101-250")], ">250")))
    m = re.match(r"M-[0-9A-F]{4}", model.get("id") or "")
    if m:
        out.add(f"maker:{MAKERS.get(m.group(0), m.group(0))}")
    if model.get("module_instances") or model.get("module_dynamics"):
        out.add("modules")
    if model.get("ets_download_plugin"):
        out.add("plugin")
    return out


def plain_identical(row: dict | None) -> bool:
    """Whether the plain oracle row is identical in memory and load control."""
    return bool(row) and row.get("verdict") == "identical" and (row.get("loadctl") or {}).get("verdict") == "identical"


def select(products: Path, results: Path) -> list[dict]:
    """The subset over the secure-capable applications the defaults sweep captured."""
    defaults = json.loads((results / "defaults.json").read_text())
    oracle = json.loads((results / "oracle.json").read_text())
    models = links_subset.product_models(products)
    apps: dict[str, set[str]] = {}
    for app, r in defaults.items():
        if r.get("outcome") != "captured" or app not in models:
            continue
        model = json.loads(models[app].read_text())
        if not model.get("is_secure_enabled"):
            continue
        if app in PINNED or plain_identical(oracle.get(app)):
            apps[app] = features(model)
    makers: dict[str, int] = {}
    for labels in apps.values():
        for label in labels:
            if label.startswith("maker:"):
                makers[label] = makers.get(label, 0) + 1
    for app, labels in apps.items():
        named = {f"maker:{n}" for n in list(MAKERS.values())[:9]}
        labels -= {label for label in labels if label.startswith("maker:") and label not in named
                   and makers[label] < MAKER_MIN and app not in PINNED}
    cost = {a: float(defaults[a].get("seconds") or 1e6) for a in apps}
    rows = []
    for app, gain in links_subset.greedy_cover(apps, cost, list(PINNED)):
        why = PINNED.get(app, "")
        cover = "first to cover " + ", ".join(gain) if gain else ""
        rows.append({"app": app, "mask": defaults[app].get("mask"), "name": defaults[app].get("name"),
                     "file": defaults[app].get("file"), "defaults_seconds": defaults[app].get("seconds"),
                     "plain": (oracle.get(app) or {}).get("verdict"),
                     "why": "; also ".join(w for w in (why, cover) if w), "covers": gain})
    return rows


def load(path: Path = SUBSET) -> list[dict]:
    """The committed subset (`secure-subset.json`): [{app, mask, name, why, ...}]."""
    return json.loads(path.read_text())["apps"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("select", help="derive the subset from the imported product models and the results")
    p.add_argument("--products", type=Path, default=links_subset.PRODUCTS)
    p.add_argument("--results", type=Path, default=links_subset.RESULTS)
    p.add_argument("--out", type=Path, default=SUBSET)
    sub.add_parser("show", help="print the committed subset")
    args = ap.parse_args()
    if args.cmd == "show":
        for r in load():
            print(f"{r['app']:32} {r['mask']} {r['name']!s:.40}  {r['why']}")
        return 0
    rows = select(args.products, args.results)
    args.out.write_text(json.dumps({"issue": 423, "derived_by": "tools/ets-sweep/secure_subset.py select",
                                    "apps": rows}, indent=1, ensure_ascii=False) + "\n")
    print(f"{len(rows)} applications -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
