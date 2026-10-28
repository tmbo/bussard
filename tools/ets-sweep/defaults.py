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
import catalog  # noqa: E402
import sweep  # noqa: E402
import vm  # noqa: E402


def sweep_search_term(order: str) -> str:
    """The fixed part of an order number (no wildcard suffix)."""
    return re.sub(r"(?<=[0-9.\-])x+$", "", order.strip(), flags=re.IGNORECASE) or order

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


def guessed_identity(app: str) -> list[dict] | None:
    """The hardware type (PID 78) ETS requires, where a manufacturer's rule is
    known, so the first download does not fail just to learn it. The value is
    not in the product file. Zennio: manufacturer, 0000, the application
    number with its last digit 0 (23 of 23 learned values, 2026-10-28). A
    wrong guess costs nothing extra: ETS logs the mismatch and the sweep
    learns the real value as before."""
    m = re.match(r"M-0071_A-([0-9A-Fa-f]{3})[0-9A-Fa-f]-", app)
    if m:
        return [{"object": 0, "pid": 78, "value": f"00710000{m.group(1).lower()}0"}]
    return None


def catalog_sibling(job: dict, r: dict, everything: dict[str, dict]) -> dict | None:
    """When ETS's catalog shows another version of the same application for
    this product (a catalog version mismatch), the job of that version."""
    m = APP_ID.match(job["id"])
    if r.get("outcome") == "skipped-catalog-version":
        shown = re.findall(r"\('[^']*', '([^']*)'", r.get("error") or "")
    else:
        # The sole catalog row is taken without its version, so look at the
        # version it shows when OCR read one: another version means ETS
        # downloaded that application, not this one.
        shown = [((r.get("catalog_row") or {}).get("version") or "")]
        if not m or not shown[0] or re.sub(r"[^0-9a-z]", "", re.sub(r"^[^0-9]+", "", shown[0].lower())) == m.group(3).lower():
            return None
    if not m or not shown:
        return None
    wanted = {re.sub(r"[^0-9a-z]", "", re.sub(r"^[^0-9]+", "", v.lower())) for v in shown}
    for other in everything.values():
        o = APP_ID.match(other["id"])
        if (o and other["id"] != job["id"] and o.group(1) == m.group(1) and o.group(2) == m.group(2)
                and other["order_numbers"] == job["order_numbers"] and o.group(3).lower() in wanted):
            return other
    return None


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
    everything = {j["id"]: j for j in todo}
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
    stop = False

    def runnable(job: dict) -> bool:
        """Record the skips; True when the job needs ETS."""
        prev = results.get(job["id"])
        if prev and not args.redo and not (args.redo_failed and not prev["outcome"].startswith(("captured", "skipped"))):
            return False
        base = {"file": job["file"], "name": job["name"], "mask": job["mask"], "when": datetime.now(timezone.utc).isoformat()}
        if job.get("older"):
            if not prev or prev["outcome"] != "captured":
                results[job["id"]] = {**base, "outcome": "skipped-older-version", "newer": job["older"]}
                save()
            return False
        if job["mask"] not in SIM_MASKS:
            results[job["id"]] = {**base, "outcome": "skipped-mask"}
            save()
            return False
        if job["mask"] not in masks:
            return False
        if not job["order_numbers"]:
            results[job["id"]] = {**base, "outcome": "skipped-no-order"}
            save()
            return False
        return True

    # One product file at a time: import it into ETS's catalog, run its
    # applications, remove its products again. ETS slowed down and its product
    # store broke with the whole corpus imported at once (2026-10-28).
    by_file: dict[str, list[dict]] = {}
    for job in todo:
        if runnable(job):
            by_file.setdefault(job["file"], []).append(job)
    all_orders: dict[str, set[str]] = {}
    for job in jobs():
        all_orders.setdefault(job["file"], set()).update(str(o) for o in job["order_numbers"])
    for file, file_jobs in by_file.items():
        if stop:
            break
        path = product_path(file)
        if file.lower().endswith(".zip") and not path.exists():
            import zipfile

            with zipfile.ZipFile(CORPUS / file) as z:
                inner = [n for n in z.namelist() if n.lower().endswith(".knxprod")][0]
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(z.read(inner))
        imp: dict = {}
        try:
            remote = catalog.upload_if_missing(c, path)
            imp = vm.driver(c, "POST", "/ets/catalog_import", {"path": remote, "timeout": 3600, "project": "ets-sweep"}, timeout=3700)
        except Exception as exc:  # noqa: BLE001
            imp = {"outcome": "error", "error": str(exc)[:300]}
            c = vm.connect()
        print(f"import  {imp.get('outcome', imp.get('error'))!s:12} {file}", flush=True)
        if imp.get("outcome") not in ("imported", "done_unverified"):
            for job in file_jobs:
                results[job["id"]] = {"file": file, "name": job["name"], "mask": job["mask"],
                                      "when": datetime.now(timezone.utc).isoformat(),
                                      "outcome": "skipped-import-failed" if imp.get("outcome") == "refused" else "driver-error",
                                      "error": (imp.get("message") or imp.get("error") or "")[:300]}
            save()
            if any(k in (imp.get("error") or "") for k in ("screen grab failed", "not the RDP layout", "desktop in use")):
                print(f"stopping: the VM desktop is not usable: {imp.get('error', '')[:160]}", flush=True)
                break
            continue
        queue = list(file_jobs)
        while queue:
            job = queue.pop(0)
            prev = results.get(job["id"])
            base = {"file": job["file"], "name": job["name"], "mask": job["mask"], "when": datetime.now(timezone.utc).isoformat()}
            try:
                # The product name without its version suffix, for ETS's search
                # when the order number does not list the wanted version.
                fallback = re.sub(r"\s+v?\d+(\.\d+)*$", "", job["name"] or "").strip()
                # Start from the identity a previous run learned from ETS.
                r = sweep.run_learning(c, path, job["id"], str(job["order_numbers"][0]),
                                       mask=job["mask"], fallback_search=fallback,
                                       properties=(prev or {}).get("learned_properties") or guessed_identity(job["id"]))
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
                "end": r.get("end"),
                "learned_properties": r.get("learned_properties"),
            }
            save()
            print(f"{r['outcome']:13} {job['mask']} {r.get('seconds', 0):4}s ops={r.get('ops')} {job['id']} {job['name']!s:.40}"
                  + (f"  {r.get('error', '')[:100]}" if r.get("error") else ""), flush=True)
            if any(k in (r.get("error") or "") for k in ("screen grab failed", "not the RDP layout", "desktop in use")):
                print(f"stopping: the VM desktop is not usable: {r.get('error', '')[:160]}", flush=True)
                stop = True
                break
            sibling = catalog_sibling(job, r, everything)
            if sibling and r["outcome"] != "skipped-catalog-version":
                # Recorded as what it was: ETS ran the sibling's application.
                results[job["id"]].update(outcome="skipped-catalog-version",
                                          error=f"ETS's catalog row is version {(r.get('catalog_row') or {}).get('version')}, run as {sibling['id']}")
                save()
            if sibling and sibling["id"] not in [q["id"] for q in queue]:
                # One Hardware2Program maps several versions of the application
                # to the hardware (ABB BM/A4.11-13x: 8.2 and 8.3) and ETS's
                # catalog row offers only the first: run that one instead.
                print(f"sibling {sibling['id']} is the version ETS's catalog offers", flush=True)
                queue.insert(0, {**sibling, "older": None})
            done += 1
            if args.limit and done >= args.limit:
                stop = True
                break
        # Remove what the file put into the catalog: every product of every
        # application it holds (multi-product files import many).
        removed = []
        for order in sorted(all_orders.get(file, set())):
            try:
                rm = vm.driver(c, "POST", "/ets/catalog_remove", {"term": sweep_search_term(order), "project": "ets-sweep"}, timeout=900)
                removed += rm.get("removed", [])
                if not rm.get("ok", True):
                    print(f"remove  failed {order}: {rm.get('error', '')[:120]}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"remove  failed {order}: {exc}", flush=True)
                c = vm.connect()
        print(f"remove  {len(removed):3} rows  {file}", flush=True)
    counts: dict[str, int] = {}
    for e in results.values():
        counts[e["outcome"]] = counts.get(e["outcome"], 0) + 1
    print("results:", counts, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
