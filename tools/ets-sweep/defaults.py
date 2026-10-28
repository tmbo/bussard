# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""The defaults sweep (epic #419, part 3 #422): ETS downloads every corpus
application at its vendor defaults into knx-sim, and the capture is kept.

    uv run tools/ets-sweep/defaults.py [--filter SUBSTR,...] [--mask 07B0,0705] [--limit N]
                                       [--shard k/n] [--redo] [--redo-failed]

Jobs come from tools/ets-sweep/catalog-apps.json (every corpus file's
applications, their mask and order numbers). One job per application id (the
first file that holds it). The first order number is ETS's catalog search
term; the application version picks the catalog row. Masks the simulator does
not play are recorded as `skipped-mask`. Outcomes go to
tools/ets-sweep/results/defaults.json, keyed by application id:

    captured        ETS reported the download done and the capture has operations
    ets-failed      ETS reported the download failed (its history line is kept)
    driver-error    the driver could not complete a step (the error is kept)
    sim-refused     knx-sim did not start with this product (its message is kept)
    unknown         neither: look at the run directory
    skipped-mask / skipped-no-order / skipped-not-in-catalog
    skipped-older-version   a newer version of the same application on the
                            same hardware runs instead (field `newer`)

The run directory per application is captures/ets-sweep/<app>/plain-defaults/
(gitignored): ets.pcapng, sim.log, driver.json, ops.txt.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sweep  # noqa: E402
import vm  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CORPUS = REPO / "tests-support" / "product-corpus" / "cache" / "vendor"
APPS = HERE / "catalog-apps.json"
CATALOG = HERE / "catalog.json"
RESULTS = HERE / "results" / "defaults.json"
SIM_MASKS = {"07B0", "0705", "0701", "0021"}


def product_path(file: str) -> Path:
    path = CORPUS / file
    if file.lower().endswith(".zip"):
        import zipfile

        with zipfile.ZipFile(path) as z:
            inner = [n for n in z.namelist() if n.lower().endswith(".knxprod")][0]
        return HERE / ".unpacked" / Path(inner).name.replace(" ", "_")
    return path


APP_ID = re.compile(r"(M-[0-9A-F]{4})_A-([0-9A-F]{4})-([0-9A-F]{2})-")


def jobs() -> list[dict]:
    """One job per application, and per hardware only the newest version of
    an application: the same order numbers and application number in several
    versions (ALLinBOX 1612 1.0 and 1.3) run once, as the newest. ETS's
    catalog offers only that one anyway. Older versions come back with
    `older: <newest id>` so the caller records them as skipped."""
    apps = json.loads(APPS.read_text())
    catalog = json.loads(CATALOG.read_text()) if CATALOG.exists() else {}
    seen: set[str] = set()
    out = []
    for file in sorted(apps):
        for app in apps[file]["apps"]:
            if app["id"] in seen:
                continue
            seen.add(app["id"])
            out.append({**app, "file": file, "in_catalog": catalog.get(file, {}).get("outcome") == "imported"})
    newest: dict[tuple, dict] = {}
    for j in out:
        m = APP_ID.match(j["id"])
        if not m:
            continue
        key = (m.group(1), m.group(2), tuple(j["order_numbers"]))
        cur = newest.get(key)
        if cur is None or int(m.group(3), 16) > int(APP_ID.match(cur["id"]).group(3), 16):
            newest[key] = j
    for j in out:
        m = APP_ID.match(j["id"])
        if m:
            top = newest[(m.group(1), m.group(2), tuple(j["order_numbers"]))]
            if top["id"] != j["id"]:
                j["older"] = top["id"]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter", default="", help="comma-separated substrings of the application id, name or file")
    ap.add_argument("--mask", default="", help="comma-separated masks to run (default: every mask the sim plays)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--shard", default="", help="k/n: run every n-th job starting at k (0-based)")
    ap.add_argument("--redo", action="store_true")
    ap.add_argument("--redo-failed", action="store_true", help="run again what is not `captured` or skipped")
    args = ap.parse_args()

    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    todo = jobs()
    wanted = [w.lower() for w in args.filter.split(",") if w]
    if wanted:
        todo = [j for j in todo if any(w in (j["id"] + " " + (j["name"] or "") + " " + j["file"]).lower() for w in wanted)]
    masks = {m.upper() for m in args.mask.split(",") if m} or SIM_MASKS
    if args.shard:
        k, n = (int(x) for x in args.shard.split("/"))
        todo = todo[k::n]

    def save() -> None:
        RESULTS.write_text(json.dumps(dict(sorted(results.items())), indent=1, ensure_ascii=False) + "\n")

    c = vm.connect()
    done = 0
    for job in todo:
        prev = results.get(job["id"])
        if prev and not args.redo and not (args.redo_failed and not prev["outcome"].startswith(("captured", "skipped"))):
            continue
        base = {"file": job["file"], "name": job["name"], "mask": job["mask"], "when": datetime.now(timezone.utc).isoformat()}
        if job.get("older"):
            if not prev or prev["outcome"] != "captured":
                results[job["id"]] = {**base, "outcome": "skipped-older-version", "newer": job["older"]}
                save()
            continue
        if job["mask"] not in SIM_MASKS:
            results[job["id"]] = {**base, "outcome": "skipped-mask"}
            save()
            continue
        if job["mask"] not in masks:
            continue
        if not job["order_numbers"]:
            results[job["id"]] = {**base, "outcome": "skipped-no-order"}
            save()
            continue
        if not job["in_catalog"]:
            results[job["id"]] = {**base, "outcome": "skipped-not-in-catalog"}
            save()
            continue
        try:
            r = sweep.run_learning(c, product_path(job["file"]), job["id"], str(job["order_numbers"][0]), mask=job["mask"])
        except Exception as exc:  # noqa: BLE001 - a lost ssh link: reconnect and go on
            r = {"outcome": "driver-error", "error": f"{type(exc).__name__}: {exc}"[:600]}
            c = vm.connect()
        results[job["id"]] = {
            **base,
            "outcome": r["outcome"],
            "ets": r.get("ets"),
            "ops": r.get("ops"),
            "loaded": r.get("loaded_objects"),
            "seconds": r.get("seconds"),
            "search": job["order_numbers"][0],
            "row": r.get("catalog_row"),
            "error": r.get("error"),
            "ets_history": [l for l in (r.get("history") or [])[:4]],
            "attempts": r.get("attempt"),
            "learned_properties": r.get("learned_properties"),
        }
        save()
        if any(k in (r.get("error") or "") for k in ("screen grab failed", "not the RDP layout")):
            # The VM's desktop session is not drawing (an RDP client went
            # away): every further job would fail the same way. Stop here;
            # `tscon <session> /dest:console` in the VM brings it back.
            print(f"stopping: the VM desktop is not usable: {r.get('error', '')[:160]}", flush=True)
            break
        print(f"{r['outcome']:13} {job['mask']} {r.get('seconds', 0):4}s ops={r.get('ops')} {job['id']} {job['name']!s:.40}"
              + (f"  {r.get('error', '')[:100]}" if r.get("error") else ""), flush=True)
        done += 1
        if args.limit and done >= args.limit:
            break
    counts: dict[str, int] = {}
    for e in results.values():
        counts[e["outcome"]] = counts.get(e["outcome"], 0) + 1
    print("results:", counts, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
