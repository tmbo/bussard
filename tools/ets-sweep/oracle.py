# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Compare every captured ETS download of the defaults sweep with bussard
(epic #419, part 3 #422).

    uv run tools/ets-sweep/oracle.py [--filter SUBSTR,...] [--redo]
        [--captures DIR] [--work DIR] [--out FILE]

For each application with outcome `captured` in results/defaults.json: build
the scratch model (one device 1.1.1, the application at its defaults, no
links; oracle_model.py) and run scripts/campaign/95-offline-oracle.sh on the
row `1.1.1|<capture>|<product>|<application>`. The verdict, coverage and the
region summary land in results/oracle.json, keyed by application id, with the
load-control verdict and its differences under `loadctl` (issue #419). Nothing
touches a bus; the model and the oracle output live next to the capture under
captures/ (ignored), or under --work DIR/<application>/<variant> (a worktree
reads the main checkout's captures with --captures and writes nowhere under
them).

Each product file is imported once, into `.oracle-products/<sha>/` under
--work (else under the captures directory), and every row's model links that
import (`oracle_model.shared_import`): a row of the 152 MB ABB catalogue costs
seconds instead of minutes and 1.6 GB. --seed-models takes the model the
sweep imported next to a capture as that import.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import defaults  # noqa: E402
import apply_rows  # noqa: E402
import oracle_model  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ORACLE = REPO / "scripts" / "campaign" / "95-offline-oracle.sh"
OUT = HERE / "results" / "oracle.json"
CAPTURES = REPO / "captures" / "ets-sweep"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def load_control_summary(diff_json: Path) -> dict:
    """The load-control verdict of a row and its differences, from diff.json."""
    try:
        lc = json.loads(diff_json.read_text()).get("load_controls") or {}
    except (OSError, ValueError):
        return {"verdict": "missing"}
    out = {"verdict": lc.get("verdict", "missing")}
    if lc.get("reason"):
        out["reason"] = lc["reason"]
    for key in ("bussard_records", "ets_records", "difference_count", "notes"):
        if lc.get(key):
            out[key] = lc[key]
    if lc.get("differences"):
        out["differences"] = [{k: d.get(k) for k in ("object", "position", "kind", "event", "bussard_hex",
                                                     "ets_hex", "bussard_event", "ets_event")}
                              for d in lc["differences"]]
    return out


def catalog_row_name(run_dir: Path) -> str | None:
    """The catalog row ETS added the device from (its product text, the
    device's name in the project): ETS writes it as the friendly name of an
    IP-enabled device (bussard issue #455)."""
    try:
        driver = json.loads((run_dir / "driver.json").read_text())
    except (OSError, ValueError):
        return None
    row = (driver.get("driver") or {}).get("catalog_add", {}).get("row") or {}
    return row.get("name")


def variant_links(run_dir: Path) -> dict:
    """The links of a links-variant row: what ETS's object table showed after
    the driver linked the objects (objects.json in the run directory)."""
    try:
        return apply_rows.links_from_objects(json.loads((run_dir / "objects.json").read_text()))
    except (OSError, ValueError):
        return {}


def shared_root(captures: Path, work: Path | None) -> Path:
    """Where the per-product imports live: under --work, else next to the
    captures (both outside git)."""
    return (work or captures) / ".oracle-products"


def run_row(app: str, entry: dict, captures: Path, work: Path | None, seed: bool = False,
            variant: str = "plain-defaults", links: dict | None = None) -> dict:
    run_dir = captures / app / variant
    work_dir = work / app / variant if work else run_dir
    capture = run_dir / "ets.pcapng"
    product = defaults.product_path(entry["file"])
    # The product file is imported once and shared by every row of it; with
    # --seed-models the model the sweep imported for this row stands in for
    # the import.
    seed_dir = run_dir / "model" if seed else None
    shared = oracle_model.shared_import(shared_root(captures, work), product, seed=seed_dir)
    model = oracle_model.build(work_dir / "model", product, app, mask=entry.get("mask", ""),
                               friendly_name=catalog_row_name(run_dir), shared=shared, links=links)
    row = f"1.1.1|{capture}|{product}|{app}"
    r = subprocess.run(["bash", str(ORACLE), "--dir", str(model), "--out", str(work_dir / "oracle"), "--row", row],
                       capture_output=True, text=True, timeout=1800, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
    text = ANSI.sub("", r.stdout + r.stderr)
    summary = next((l for l in text.splitlines() if l.startswith("1.1.1 ")), "")
    m = re.match(r"1\.1\.1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)", summary)
    out = {"exit": r.returncode, "summary": summary.strip()}
    if m:
        out.update({"system": m.group(1), "verdict": m.group(2), "coverage": m.group(3), "confirmed": m.group(4),
                    "regions": m.group(5).strip()})
        # The oracle judges memory only unless a row asks for property parity;
        # an ETS-only property write (the KNXnet/IP object of an IP-enabled
        # device, ALLinBOX 1612) is a write bussard would miss: report it.
        if out["verdict"] == "identical" and "props=differs" in out["regions"]:
            out["verdict"] = "differs-props"
    else:
        out["verdict"] = "oracle-error"
        out["tail"] = text.strip().splitlines()[-6:]
    out["loadctl"] = load_control_summary(work_dir / "oracle" / "1.1.1" / "diff.json")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter", default="")
    ap.add_argument("--redo", action="store_true")
    ap.add_argument("--captures", type=Path, default=CAPTURES, help="the sweep captures (default %(default)s)")
    ap.add_argument("--work", type=Path, help="write the models and oracle output here, not next to the captures")
    ap.add_argument("--out", type=Path, help=f"the results file (default {OUT}, results/oracle-<variant>.json for a variant)")
    ap.add_argument("--seed-models", action="store_true",
                    help="take the model the sweep imported next to a capture as the product import instead of importing (once per product file)")
    ap.add_argument("--defaults", type=Path, help="the sweep results (default: the variant's, results/defaults.json)")
    ap.add_argument("--variant", default="plain-defaults", choices=sorted(defaults.VARIANTS),
                    help="links: the links variant (#478); each row's model gets the links ETS showed (objects.json)")
    args = ap.parse_args()
    args.defaults = args.defaults or defaults.results_path(args.variant)
    args.out = args.out or (OUT if args.variant == "plain-defaults" else OUT.with_name(f"oracle-{args.variant}.json"))
    res = json.loads(args.defaults.read_text())
    out = json.loads(args.out.read_text()) if args.out.exists() else {}
    wanted = [w.lower() for w in args.filter.split(",") if w]
    for app, entry in sorted(res.items()):
        if entry["outcome"] != "captured":
            continue
        if wanted and not any(w in (app + " " + (entry.get("name") or "")).lower() for w in wanted):
            continue
        if app in out and not args.redo and out[app].get("capture_when") == entry["when"]:
            continue
        try:
            v = run_row(app, entry, args.captures, args.work, args.seed_models, variant=args.variant,
                        links=variant_links(args.captures / app / args.variant) if args.variant != "plain-defaults" else None)
        except Exception as exc:  # noqa: BLE001 - recorded, the next row runs
            v = {"verdict": "oracle-error", "error": str(exc)[:400]}
        v.update({"name": entry.get("name"), "mask": entry.get("mask"), "capture_when": entry["when"],
                  "when": datetime.now(timezone.utc).isoformat()})
        out[app] = v
        args.out.write_text(json.dumps(dict(sorted(out.items())), indent=1, ensure_ascii=False) + "\n")
        lc = v.get("loadctl", {}).get("verdict", "-")
        print(f"{v['verdict']:14} {lc:14} {v.get('coverage', ''):>7} {entry.get('mask')} {app} "
              f"{v.get('regions', '')[:70]}", flush=True)
    counts: dict[str, int] = {}
    lc_counts: dict[str, int] = {}
    for v in out.values():
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
        lc = v.get("loadctl", {}).get("verdict", "missing")
        lc_counts[lc] = lc_counts.get(lc, 0) + 1
    print("oracle:", counts)
    print("load control:", lc_counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
