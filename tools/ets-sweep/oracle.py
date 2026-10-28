# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Compare every captured ETS download of the defaults sweep with bussard
(epic #419, part 3 #422).

    uv run tools/ets-sweep/oracle.py [--filter SUBSTR,...] [--redo]

For each application with outcome `captured` in results/defaults.json: build
the scratch model (one device 1.1.1, the application at its defaults, no
links; oracle_model.py) and run scripts/campaign/95-offline-oracle.sh on the
row `1.1.1|<capture>|<product>|<application>`. The verdict, coverage and the
region summary land in results/oracle.json, keyed by application id. Nothing
touches a bus; the model and the oracle output live under captures/ (ignored).
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
import oracle_model  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ORACLE = REPO / "scripts" / "campaign" / "95-offline-oracle.sh"
OUT = HERE / "results" / "oracle.json"
CAPTURES = REPO / "captures" / "ets-sweep"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run_row(app: str, entry: dict) -> dict:
    run_dir = CAPTURES / app / "plain-defaults"
    capture = run_dir / "ets.pcapng"
    product = defaults.product_path(entry["file"])
    model = oracle_model.build(run_dir / "model", product, app, mask=entry.get("mask", ""))
    row = f"1.1.1|{capture}|{product}|{app}"
    r = subprocess.run(["bash", str(ORACLE), "--dir", str(model), "--out", str(run_dir / "oracle"), "--row", row],
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
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter", default="")
    ap.add_argument("--redo", action="store_true")
    args = ap.parse_args()
    res = json.loads(defaults.RESULTS.read_text())
    out = json.loads(OUT.read_text()) if OUT.exists() else {}
    wanted = [w.lower() for w in args.filter.split(",") if w]
    for app, entry in sorted(res.items()):
        if entry["outcome"] != "captured":
            continue
        if wanted and not any(w in (app + " " + (entry.get("name") or "")).lower() for w in wanted):
            continue
        if app in out and not args.redo and out[app].get("capture_when") == entry["when"]:
            continue
        try:
            v = run_row(app, entry)
        except Exception as exc:  # noqa: BLE001 - recorded, the next row runs
            v = {"verdict": "oracle-error", "error": str(exc)[:400]}
        v.update({"name": entry.get("name"), "mask": entry.get("mask"), "capture_when": entry["when"],
                  "when": datetime.now(timezone.utc).isoformat()})
        out[app] = v
        OUT.write_text(json.dumps(dict(sorted(out.items())), indent=1, ensure_ascii=False) + "\n")
        print(f"{v['verdict']:14} {v.get('coverage', ''):>7} {entry.get('mask')} {app} {v.get('regions', '')[:90]}", flush=True)
    counts: dict[str, int] = {}
    for v in out.values():
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
    print("oracle:", counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
