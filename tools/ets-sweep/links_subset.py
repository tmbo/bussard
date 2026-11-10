# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""The representative subset of the links variant (#478).

    uv run tools/ets-sweep/links_subset.py select [--products DIR] [--results DIR] [--out FILE]
    uv run tools/ets-sweep/links_subset.py show

A links row costs minutes in ETS (371 s for the ise KNX Sonos, 2026-11-10),
so `defaults.py --variant links --representative` runs only the applications
in `links-subset.json`: a greedy cover of what matters for links, taken from
the applications the defaults sweep captured. Each application covers a set
of labels (`features`), each label naming one variation:

    mask:<mask>                      the mask family
    tables:<mask>/<style>            how the address and association tables load:
                                     prop-image (LdCtrlLoadImageProp on objects 1, 2),
                                     rel-segment (System B relative segments),
                                     abs-segment (LdCtrlAbsSegment, memory),
                                     ets-default (no table step: ETS's own procedure)
    go-table:<mask>/<where>          the group-object table: in its own segment,
                                     inside the application segment, or a property
                                     of the device (System B, no table in the model)
    assoc:<mask>/<bucket>            the association table segment's size
    secure:<mask>                    KNX Data Secure capable
    objects:<mask>/<bucket>          how many objects the application defines
    size:<mask>/<size>               an object of 1 bit, 1 byte, 2 bytes or 14 bytes
    size:<size>                      any other object size, once
    modules:<mask>                   ModuleDefs instances; module-objects:<mask> when
                                     modules define objects
    plugin:<manufacturer>            the manufacturer's EtsDownloadPlugin
    oracle:<mask>/<verdict>          the plain oracle's verdict differs or
                                     not-comparable now, or `was-differs` in an
                                     earlier nightly manifest

`select` takes the `PINNED` applications first (the partial-download series'
representatives and the first refused link), then picks greedily: each round
the application covering most labels not yet covered, ties to the shorter
defaults run. The labels it added first are
its reason. `links-subset.json` keeps the list with that reason; it is
re-derived with `select` when the corpus grows.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SUBSET = HERE / "links-subset.json"
PRODUCTS = REPO / "captures" / "ets-sweep" / ".oracle-products"
RESULTS = HERE / "results"

# The object sizes the issue names; any other size counts once, for any mask.
NAMED_SIZES = ("1 Bit", "1 Byte", "2 Bytes", "14 Bytes")
SIZE_RE = re.compile(r"^\d+ (Bit|Bytes?)$")

# Applications in the subset whatever the cover picks, with the reason: the
# partial-download series' representatives (`series.REPRESENTATIVES`, one per
# table layout; the KNX Virtual DA.tp is not in the corpus) and the first
# product whose link ETS refused (#478).
PINNED = {
    "M-0007_A-20BA-11-05A3-O000A": "series representative: 0705 with the tables loaded through properties "
                                   "(LdCtrlLoadImageProp, Busch-Jaeger 6173/11 U)",
    "M-0083_A-000E-23-2274": "series representative: 0705 with load control through memory (MDT AKK)",
    "M-00B6_A-4537-03-DE59": "series representative: 0705 with the group-object table in a segment of its own "
                             "(Ekinex EK-E72)",
    "M-0071_A-4131-32-17BF": "series representative: 0701, memory-mapped load-state machines (Zennio ACTinBOX MAX6)",
    "M-007C_A-0002-30-DC22": "ETS refused a link of another object size here (ise KNX Sonos, 2026-11-10): "
                             "the refusal path",
}


def bucket(n: int, edges: list[tuple[int, str]], top: str) -> str:
    """The label of the first edge `n` does not exceed, else `top`."""
    return next((name for edge, name in edges if n <= edge), top)


def table_style(model: dict) -> str:
    """How the address and association tables (interface objects and load
    state machines 1 and 2) are loaded, from the model's load procedures."""
    styles = set()
    for lp in model.get("load_procedures") or []:
        for op in lp.get("ops") or []:
            if not isinstance(op, dict):
                continue
            kind, v = next(iter(op.items()))
            if kind == "LoadImageProp" and v.get("obj_idx") in (1, 2):
                styles.add("prop-image")
            elif kind == "RelSegment" and v.get("lsm_idx") in (1, 2):
                styles.add("rel-segment")
            elif kind == "AbsSegment" and v.get("lsm_idx") in (1, 2):
                styles.add("abs-segment")
    for style in ("rel-segment", "prop-image", "abs-segment"):
        if style in styles:
            return style
    return "ets-default"


def assoc_size(model: dict) -> int | None:
    """The size in bytes of the association table's segment (state machine 2),
    when the load procedure gives one."""
    for lp in model.get("load_procedures") or []:
        for op in lp.get("ops") or []:
            if isinstance(op, dict):
                kind, v = next(iter(op.items()))
                if kind in ("AbsSegment", "RelSegment") and v.get("lsm_idx") == 2 and v.get("size"):
                    return int(v["size"])
    return None


def go_table(model: dict) -> str:
    """Where the group-object table lives: `own-segment` (at offset 0 of a
    segment), `in-app-segment` (inside another segment), or `property` (no
    table in the model: a System B device's object, written by ETS)."""
    cot = model.get("com_object_table")
    if not cot:
        return "property"
    return "own-segment" if not cot.get("offset") else "in-app-segment"


def object_sizes(model: dict) -> set[str]:
    """Every object size the application uses (a reference's size over its object's)."""
    objs = model.get("com_objects") or {}
    sizes = {o.get("object_size") for o in objs.values()}
    for ref in (model.get("com_object_refs") or {}).values():
        sizes.add(ref.get("object_size") or (objs.get(ref.get("ref_id")) or {}).get("object_size"))
    return {s for s in sizes if s}


def features(model: dict, verdicts: set[str] | None = None) -> set[str]:
    """The labels one application covers (see the module doc). `verdicts`,
    the plain oracle's verdicts of it: `differs`, `not-comparable` now, and
    `was-differs` for an earlier non-identical verdict."""
    mask = model.get("mask_version") or "?"
    out = {f"mask:{mask}", f"tables:{mask}/{table_style(model)}", f"go-table:{mask}/{go_table(model)}"}
    size = assoc_size(model)
    if size is not None:
        out.add(f"assoc:{mask}/" + bucket(size, [(127, "small <128 B"), (447, "medium <448 B"), (511, "standard 448-511 B")],
                                          "large >=512 B"))
    if model.get("is_secure_enabled"):
        out.add(f"secure:{mask}")
    n = len(model.get("com_objects") or {})
    out.add(f"objects:{mask}/" + bucket(n, [(10, "few <=10"), (50, "some 11-50"), (200, "many 51-200")], "very many >200"))
    for s in sorted(object_sizes(model)):
        if not SIZE_RE.match(s):
            continue
        out.add(f"size:{mask}/{s}" if s in NAMED_SIZES else f"size:{s}")
    if model.get("module_instances") or model.get("module_dynamics"):
        out.add(f"modules:{mask}")
        if any("_MD-" in k for k in model.get("com_objects") or {}):
            out.add(f"module-objects:{mask}")
    if model.get("ets_download_plugin"):
        m = re.match(r"M-[0-9A-F]{4}", model.get("id") or "")
        out.add(f"plugin:{m.group(0) if m else '?'}")
    for v in verdicts or ():
        out.add(f"oracle:{mask}/{v}")
    return out


def greedy_cover(apps: dict[str, set[str]], cost: dict[str, float] | None = None,
                 pinned: list[str] | tuple[str, ...] = ()) -> list[tuple[str, list[str]]]:
    """A greedy set cover of every label in `apps` (application -> labels):
    the `pinned` applications first (those in `apps`, in order), then each
    round the application adding most uncovered labels, ties to the lower
    `cost` (the defaults run's seconds), then the id. Returns
    [(application, the labels it added, sorted)] in pick order."""
    cost = cost or {}
    left = set().union(*apps.values()) if apps else set()
    picked: list[tuple[str, list[str]]] = []
    for app in pinned:
        if app in apps:
            picked.append((app, sorted(apps[app] & left)))
            left -= apps[app]
    while left:
        app = min(apps, key=lambda a: (-len(apps[a] & left), cost.get(a, float("inf")), a))
        gain = apps[app] & left
        if not gain:
            break
        picked.append((app, sorted(gain)))
        left -= gain
    return picked


def oracle_verdicts(results: Path) -> dict[str, set[str]]:
    """Per application the non-identical verdicts of the plain oracle: the
    current one (`oracle.json`) and `was-differs` from earlier nightly
    manifests (`history/manifest-*.json`)."""
    out: dict[str, set[str]] = {}
    try:
        current = json.loads((results / "oracle.json").read_text())
    except (OSError, ValueError):
        current = {}
    for app, r in current.items():
        if r.get("verdict") in ("differs", "not-comparable"):
            out.setdefault(app, set()).add(r["verdict"])
    for f in sorted((results / "history").glob("manifest-*.json")):
        try:
            apps = json.loads(f.read_text()).get("apps") or {}
        except (OSError, ValueError):
            continue
        for app, r in apps.items():
            if r.get("verdict") in ("differs", "not-comparable") and (current.get(app) or {}).get("verdict") == "identical":
                out.setdefault(app, set()).add("was-differs")
    return out


def product_models(products: Path) -> dict[str, Path]:
    """application id -> one imported product model (`<sha>/.bussard/products/<sha>/<app>@<lang>.json`)."""
    out: dict[str, Path] = {}
    for f in sorted(products.glob("*/.bussard/products/*/M-*@*.json")):
        out.setdefault(f.name.split("@", 1)[0], f)
    return out


def select(products: Path, results: Path) -> list[dict]:
    """The subset: the greedy cover over the applications the defaults sweep captured."""
    defaults = json.loads((results / "defaults.json").read_text())
    captured = {a: r for a, r in defaults.items() if r.get("outcome") == "captured"}
    verdicts = oracle_verdicts(results)
    models = product_models(products)
    apps: dict[str, set[str]] = {}
    for app in captured:
        if app in models:
            apps[app] = features(json.loads(models[app].read_text()), verdicts.get(app))
    cost = {a: float(captured[a].get("seconds") or 1e6) for a in apps}
    return [{"app": app, "mask": captured[app].get("mask"), "name": captured[app].get("name"),
             "file": captured[app].get("file"), "defaults_seconds": captured[app].get("seconds"),
             "why": why(app, gain), "covers": gain}
            for app, gain in greedy_cover(apps, cost, list(PINNED))]


def why(app: str, labels: list[str]) -> str:
    """A short reason: the pin's, else the labels the application added to the cover."""
    if app in PINNED:
        return PINNED[app] + ("; also first to cover " + ", ".join(labels) if labels else "")
    return "first to cover " + ", ".join(labels)


def load(path: Path = SUBSET) -> list[dict]:
    """The committed subset (`links-subset.json`): [{app, mask, name, why, ...}]."""
    return json.loads(path.read_text())["apps"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("select", help="derive the subset from the imported product models and the results")
    p.add_argument("--products", type=Path, default=PRODUCTS)
    p.add_argument("--results", type=Path, default=RESULTS)
    p.add_argument("--out", type=Path, default=SUBSET)
    sub.add_parser("show", help="print the committed subset")
    args = ap.parse_args()
    if args.cmd == "show":
        for r in load():
            print(f"{r['app']:32} {r['mask']} {r['name']!s:.40}  {r['why']}")
        return 0
    rows = select(args.products, args.results)
    args.out.write_text(json.dumps({"issue": 478, "derived_by": "tools/ets-sweep/links_subset.py select",
                                    "apps": rows}, indent=1, ensure_ascii=False) + "\n")
    print(f"{len(rows)} applications -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
