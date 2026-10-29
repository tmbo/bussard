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
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import catalog  # noqa: E402
import series  # noqa: E402
import sweep  # noqa: E402
import vm  # noqa: E402


def sweep_search_term(order: str) -> str:
    """The fixed part of an order number (no wildcard suffix)."""
    return re.sub(r"(?<=[0-9.\-])x+$", "", order.strip(), flags=re.IGNORECASE) or order

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
# The product corpus (vendor data, never committed): $BUSSARD_PRODUCT_CORPUS
# as the sim catalog loop takes it (a worktree points it at the main checkout's).
CORPUS = Path(os.environ.get("BUSSARD_PRODUCT_CORPUS", REPO / "tests-support" / "product-corpus")) / "cache" / "vendor"
APPS = HERE / "catalog-apps.json"
CATALOG = HERE / "catalog.json"
RESULTS = HERE / "results" / "defaults.json"
# The sweep variants: the run directory name and the results file.
VARIANTS = {"plain-defaults": "defaults.json", "links": "links.json"}


def results_path(variant: str) -> Path:
    """The outcome manifest of a sweep variant (`links` is #478's links
    variant: the defaults download plus a few links)."""
    return HERE / "results" / VARIANTS[variant]


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
    history = " ".join(r.get("history") or r.get("ets_history") or [])
    if m and r.get("outcome") == "ets-failed" and "association table format" in history:
        # ETS downloaded another application of this hardware than the sim
        # plays: one Hardware2Program lists several versions and ETS's
        # catalog row takes the first, while ABB's Version column shows the
        # name's suffix ('11.1' for both A-0806-B1 and -C1), so the row cannot
        # tell them apart. Run the next older sibling.
        older = [o for o in everything.values()
                 if (om := APP_ID.match(o["id"])) and o["id"] != job["id"]
                 and om.group(1) == m.group(1) and om.group(2) == m.group(2)
                 and o["order_numbers"] == job["order_numbers"]
                 and int(om.group(3), 16) < int(m.group(3), 16)]
        return max(older, key=lambda o: int(APP_ID.match(o["id"]).group(3), 16), default=None)
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


def shown_version(text: str) -> tuple[int, int] | None:
    """The application version a catalog row's Version cell shows, as
    (major, minor), or None when OCR read no clean version. ETS prints the
    version octet's nibbles in decimal: 0x1C is '1.12', 0xB1 is '11.1'.
    Leading noise goes ('. 11.1', '...1.13')."""
    m = re.search(r"(\d+)\.(\d+)[a-z]?\s*$", text.strip().lower())
    return (int(m.group(1)), int(m.group(2))) if m else None


def row_version_mismatch(app: str, row: dict | None) -> str | None:
    """Why the catalog row ETS added is not the job's application, or None.

    The driver takes the sole local row of an order number without reading
    its version (OCR truncates that cell), so ETS can download another
    version of the application than the sim plays: Busch-Jaeger
    `A-6109-50-71A0` ran against the row of version 1.1 and its capture was
    `A-6109-11` byte for byte (2026-10-29). A shown version that ends in the
    job's version passes (OCR adds a digit in front at times: '21.2' for
    1.2); an unreadable one passes too, the image comparison catches it."""
    m = APP_ID.match(app)
    shown = shown_version((row or {}).get("version") or "")
    if not m or shown is None:
        return None
    v = int(m.group(3), 16)
    want = f"{v >> 4}.{v & 0xF}"
    have = f"{shown[0]}.{shown[1]}"
    if have == want or have.endswith(want) and have[-len(want) - 1].isdigit():
        return None
    return f"catalog row shows version {have}, the job is {want}"


def relabel_wrong_rows(results: dict) -> list[str]:
    """Marks every `captured` result whose catalog row shows another
    application version as `skipped-catalog-version` (no VM needed);
    returns the application ids it changed."""
    changed = []
    for app, r in results.items():
        if r.get("outcome") != "captured":
            continue
        why = row_version_mismatch(app, r.get("row"))
        if why:
            r.update(outcome="skipped-catalog-version", error=why)
            changed.append(app)
    return changed


def seed_properties(path: Path, app: str, prev: dict | None) -> list[dict] | None:
    """The device properties the sim starts with: those the application binds
    parameters to (the hardware type ETS checks first, PID 78; 78 of 81
    learned values match), overridden by what a previous run learned from
    ETS's log, else Zennio's rule for PID 78."""
    # The device object only: its PIDs 78 and 25 are what ETS checks; a
    # property on an object the sim does not build would refuse the config.
    merged = {(p["object"], p["pid"]): p for p in sweep.product_properties(path, app) if p["object"] == 0}
    for p in (prev or {}).get("learned_properties") or []:
        merged[(p["object"], p["pid"])] = p
    if (0, 78) not in merged:
        for p in guessed_identity(app) or []:
            merged[(p["object"], p["pid"])] = p
    return list(merged.values()) or None


OFFERED = HERE / "results" / "offered.json"


def offered_apps(files: list[str]) -> dict[str, str]:
    """application id -> the application ETS's catalog offers for its
    hardware: the first ApplicationProgramRef of each Hardware2Program (one
    H2P can list several versions, ABB BM/A4.11-13x 8.2 and 8.3, and the
    catalog item adds the first). Read from each product's Hardware.xml and
    cached in results/offered.json."""
    import zipfile

    cache = json.loads(OFFERED.read_text()) if OFFERED.exists() else {}
    changed = False
    for file in files:
        if file in cache:
            continue
        mapping: dict[str, str] = {}
        try:
            z = zipfile.ZipFile(CORPUS / file)
            if file.lower().endswith(".zip"):
                import io

                inner = [n for n in z.namelist() if n.lower().endswith(".knxprod")][0]
                z = zipfile.ZipFile(io.BytesIO(z.read(inner)))
            for name in z.namelist():
                if name.endswith("Hardware.xml"):
                    xml = z.read(name).decode("utf-8", "replace")
                    for h2p in re.finditer(r"<Hardware2Program\b.*?</Hardware2Program>", xml, re.S):
                        refs = re.findall(r'<ApplicationProgramRef RefId="([^"]+)"', h2p.group(0))
                        for ref in refs:
                            mapping.setdefault(ref, refs[0])
        except (OSError, zipfile.BadZipFile, IndexError):
            pass
        cache[file] = mapping
        changed = True
    if changed:
        OFFERED.write_text(json.dumps(cache, indent=1, sort_keys=True))
    return {app: first for m in cache.values() for app, first in m.items()}


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
    # Only the application ETS's catalog offers for a hardware can run; the
    # others of the same Hardware2Program are recorded as skipped in its favour.
    offered = offered_apps(sorted(apps))
    for j in out:
        first = offered.get(j["id"])
        if first and first != j["id"]:
            j["older"] = first
    newest: dict[tuple, dict] = {}
    for j in out:
        if j.get("older"):
            continue
        m = APP_ID.match(j["id"])
        if not m:
            continue
        key = (m.group(1), m.group(2), tuple(j["order_numbers"]))
        cur = newest.get(key)
        if cur is None or int(m.group(3), 16) > int(APP_ID.match(cur["id"]).group(3), 16):
            newest[key] = j
    for j in out:
        m = APP_ID.match(j["id"])
        if m and not j.get("older"):
            top = newest.get((m.group(1), m.group(2), tuple(j["order_numbers"])))
            if top and top["id"] != j["id"]:
                j["older"] = top["id"]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter", default="", help="comma-separated substrings of the application id, name or file")
    ap.add_argument("--mask", default="", help="comma-separated masks to run (default: every mask the sim plays)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--shard", default="", help="k/n: run every n-th job starting at k (0-based)")
    ap.add_argument("--redo", action="store_true")
    ap.add_argument("--reset-every", type=int, default=200,
                    help="close ETS and clear its product store once this many products were imported")
    ap.add_argument("--in-catalog", type=int, default=0, help="products already in ETS's catalog at the start")
    ap.add_argument("--redo-failed", action="store_true", help="run again what is not `captured` or skipped")
    ap.add_argument("--relabel", action="store_true",
                    help="only mark captured results whose catalog row shows another version (no VM)")
    ap.add_argument("--variant", default="plain-defaults", choices=sorted(VARIANTS),
                    help="links: link a few objects before the download (#478), "
                         "for the applications the defaults sweep captured; results/links.json")
    args = ap.parse_args()

    results_file = results_path(args.variant)
    results = json.loads(results_file.read_text()) if results_file.exists() else {}
    # The links variant runs what the defaults sweep captured, from the
    # identity that run learned.
    captured = json.loads(RESULTS.read_text()) if args.variant != "plain-defaults" and RESULTS.exists() else {}
    hook = series.links_hook() if args.variant == "links" else None
    if args.relabel:
        changed = relabel_wrong_rows(results)
        if changed:
            results_file.write_text(json.dumps(dict(sorted(results.items())), indent=1, ensure_ascii=False) + "\n")
        print(f"relabelled {len(changed)}: {', '.join(changed)}")
        return 0
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
        results_file.write_text(json.dumps(dict(sorted(results.items())), indent=1, ensure_ascii=False) + "\n")

    c = vm.connect()
    done = 0
    stop = False

    def runnable(job: dict) -> bool:
        """Record the skips; True when the job needs ETS."""
        if args.variant != "plain-defaults" and (captured.get(job["id"]) or {}).get("outcome") != "captured":
            return False
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

    # One product file at a time: import it into ETS's catalog and run its
    # applications; every --reset-every products ETS's product store is
    # cleared. ETS slowed down and its product store broke with the whole
    # corpus imported at once (2026-10-28).
    by_file: dict[str, list[dict]] = {}
    for job in todo:
        if runnable(job):
            by_file.setdefault(job["file"], []).append(job)
    all_orders: dict[str, set[str]] = {}
    for job in jobs():
        all_orders.setdefault(job["file"], set()).update(str(o) for o in job["order_numbers"])
    in_catalog = args.in_catalog
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
        if in_catalog >= args.reset_every:
            # Clearing the whole store now and then is much faster than
            # removing each file's products row by row (user decision,
            # 2026-10-28); ETS slowed down and broke with the whole corpus in it.
            try:
                rs = vm.driver(c, "POST", "/ets/reset_catalog", {"project": "ets-sweep"}, timeout=900)
                print(f"reset   {rs.get('did', rs.get('error'))}", flush=True)
                if not rs.get("ok", True):
                    break
            except Exception as exc:  # noqa: BLE001
                print(f"reset   failed: {exc}", flush=True)
                break
            in_catalog = 0
        in_catalog += len(all_orders.get(file, ()))
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
                                       mask=job["mask"], fallback_search=fallback, variant=args.variant,
                                       before_download=hook,
                                       properties=seed_properties(path, job["id"], prev or captured.get(job["id"])))
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
                "links": (r.get("before") or {}).get("links"),
            }
            save()
            print(f"{r['outcome']:13} {job['mask']} {r.get('seconds', 0):4}s ops={r.get('ops')} {job['id']} {job['name']!s:.40}"
                  + (f"  {r.get('error', '')[:100]}" if r.get("error") else ""), flush=True)
            if any(k in (r.get("error") or "") for k in ("screen grab failed", "not the RDP layout", "desktop in use")):
                print(f"stopping: the VM desktop is not usable: {r.get('error', '')[:160]}", flush=True)
                stop = True
                break
            if "compatibility mode before project_tab" in (r.get("error") or "") and not job.get("retried"):
                # A compatibility prompt that keeps coming back for a device the
                # previous product left in the project: restart ETS (with a
                # cleared store) and run this product again once.
                try:
                    rs = vm.driver(c, "POST", "/ets/reset_catalog", {"project": "ets-sweep"}, timeout=900)
                    print(f"reset   after a stale compatibility prompt: {rs.get('did', rs.get('error'))}", flush=True)
                    in_catalog = 0
                    remote = catalog.upload_if_missing(c, path)
                    vm.driver(c, "POST", "/ets/catalog_import", {"path": remote, "timeout": 3600, "project": "ets-sweep"}, timeout=3700)
                    queue.insert(0, {**job, "retried": True})
                    continue
                except Exception as exc:  # noqa: BLE001 - a lost ssh link (EOFError after the ETS restart)
                    print(f"reset   failed: {type(exc).__name__}: {exc}", flush=True)
                    c = vm.connect()
                    queue.insert(0, {**job, "retried": True})
                    continue
            sibling = catalog_sibling(job, r, everything)
            wrong_row = row_version_mismatch(job["id"], r.get("catalog_row"))
            if not sibling and wrong_row and r["outcome"] == "captured":
                # ETS downloaded another version of the application than the
                # sim plays: the capture is not this job's.
                results[job["id"]].update(outcome="skipped-catalog-version", error=wrong_row)
                save()
                print(f"refused {job['id']}: {wrong_row}", flush=True)
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
    counts: dict[str, int] = {}
    for e in results.values():
        counts[e["outcome"]] = counts.get(e["outcome"], 0) + 1
    print("results:", counts, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
