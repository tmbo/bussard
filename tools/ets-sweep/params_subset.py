# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""The representative subset of the parameter-set variant (#424).

    uv run tools/ets-sweep/params_subset.py select [--products DIR] [--results DIR] [--out FILE] [--max 15]
    uv run tools/ets-sweep/params_subset.py show

A parameter-set row costs minutes in ETS (the page survey, the changes, a
second survey, the download and the export), so `params.py run
--representative` runs only the applications in `params-subset.json`: a
greedy cover, as for the links variant (`links_subset.py`, #478), of what
matters for parameters, over the applications the defaults sweep captured.
Each application covers a set of labels:

    mask:<mask>                    the mask family
    placement:<mask>/<where>       parameters placed in memory, in interface-object
                                   properties, or both
    type:<kind>                    a parameter type: Enum, Int, Float, Text, Color, Other
    unions:<mask>                  parameters sharing memory in unions
    modules:<mask>                 ModuleDefs instances (module parameters)
    channels:<mask>                the Dynamic tree has channels (pages per channel)
    switches:<mask>/<bucket>       how many choose nodes (page switches) the
                                   Dynamic tree has: few <=20, some 21-200, many >200
    calculations:<mask>            parameter calculations (ParameterCalculation)
    oracle:<mask>/<verdict>        the plain oracle's verdict differs or
                                   not-comparable now, or was-differs earlier

`select` takes the `PINNED` applications first, then picks greedily (most
uncovered labels, ties to the shorter defaults run) until every label is
covered or `--max` applications are picked. The labels an application
added first are its reason.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import links_subset  # noqa: E402

HERE = Path(__file__).resolve().parent
SUBSET = HERE / "params-subset.json"

# In the subset whatever the cover picks, with the reason.
PINNED = {
    "M-0009_A-E804-10-98AD": "every parameter in an interface-object property (Hager TYMS616D, 07B0): the "
                             "parameter-only download of #572 A.4 / #944",
    "M-0009_A-E802-13-7620": "Hager TYMS646R (07B0), the third application of the 2026-11-08 attempt that set "
                             "nothing",
}


def bucket(n: int) -> str:
    return links_subset.bucket(n, [(20, "few <=20"), (200, "some 21-200")], "many >200")


def count_nodes(tree, key: str) -> int:
    """How many `key` nodes (`choose`, `channel`) a Dynamic tree holds."""
    if isinstance(tree, dict):
        return sum((k == key) + count_nodes(v, key) for k, v in tree.items())
    if isinstance(tree, list):
        return sum(count_nodes(v, key) for v in tree)
    return 0


def features(model: dict, verdicts: set[str] | None = None) -> set[str]:
    """The labels one application covers (see the module doc)."""
    mask = model.get("mask_version") or "?"
    out = {f"mask:{mask}"}
    params = model.get("parameters") or {}
    params = params.values() if isinstance(params, dict) else params
    memory = prop = False
    for p in params:
        memory |= bool(p.get("memory"))
        prop |= bool(p.get("property"))
    if memory or prop:
        out.add(f"placement:{mask}/" + ("both" if memory and prop else "memory" if memory else "property"))
    types = model.get("parameter_types") or {}
    for t in types.values() if isinstance(types, dict) else types:
        kind = t.get("kind")
        name = kind if isinstance(kind, str) else next(iter(kind), None) if kind else None
        if name and name != "None":
            out.add(f"type:{name}")
    if model.get("unions"):
        out.add(f"unions:{mask}")
    if model.get("module_instances") or model.get("module_dynamics"):
        out.add(f"modules:{mask}")
    dynamic = model.get("dynamic") or []
    if count_nodes(dynamic, "channel"):
        out.add(f"channels:{mask}")
    out.add(f"switches:{mask}/{bucket(count_nodes(dynamic, 'choose'))}")
    if model.get("calculations"):
        out.add(f"calculations:{mask}")
    for v in verdicts or ():
        out.add(f"oracle:{mask}/{v}")
    return out


def select(products: Path, results: Path, limit: int = 15) -> list[dict]:
    """The subset: the greedy cover over the applications the defaults sweep captured."""
    defaults = json.loads((results / "defaults.json").read_text())
    captured = {a: r for a, r in defaults.items() if r.get("outcome") == "captured"}
    verdicts = links_subset.oracle_verdicts(results)
    models = links_subset.product_models(products)
    apps: dict[str, set[str]] = {}
    for app in captured:
        if app in models:
            apps[app] = features(json.loads(models[app].read_text()), verdicts.get(app))
    cost = {a: float(captured[a].get("seconds") or 1e6) for a in apps}
    picked = links_subset.greedy_cover(apps, cost, list(PINNED))[:limit]
    return [{"app": app, "mask": captured[app].get("mask"), "name": captured[app].get("name"),
             "file": captured[app].get("file"), "defaults_seconds": captured[app].get("seconds"),
             "why": why(app, gain), "covers": gain}
            for app, gain in picked]


def why(app: str, labels: list[str]) -> str:
    if app in PINNED:
        return PINNED[app] + ("; also first to cover " + ", ".join(labels) if labels else "")
    return "first to cover " + ", ".join(labels)


def load(path: Path = SUBSET) -> list[dict]:
    """The committed subset (`params-subset.json`): [{app, mask, name, why, ...}]."""
    return json.loads(path.read_text())["apps"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("select", help="derive the subset from the imported product models and the results")
    p.add_argument("--products", type=Path, default=links_subset.PRODUCTS)
    p.add_argument("--results", type=Path, default=links_subset.RESULTS)
    p.add_argument("--out", type=Path, default=SUBSET)
    p.add_argument("--max", type=int, default=15)
    sub.add_parser("show", help="print the committed subset")
    args = ap.parse_args()
    if args.cmd == "show":
        for r in load():
            print(f"{r['app']:32} {r['mask']} {r['name']!s:.40}  {r['why']}")
        return 0
    rows = select(args.products, args.results, args.max)
    args.out.write_text(json.dumps({"issue": 424, "derived_by": "tools/ets-sweep/params_subset.py select",
                                    "apps": rows}, indent=1, ensure_ascii=False) + "\n")
    print(f"{len(rows)} applications -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
