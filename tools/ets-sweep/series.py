# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""ETS partial-download series and the links variant (epic #419, part 7 #478).

    uv run tools/ets-sweep/series.py partial [--only M-00B6,...] [--steps abcd] [--oracle]
    uv run tools/ets-sweep/series.py plan <objects.json>        # offline: the links a series would make

`partial` runs the series on each representative product (`REPRESENTATIVES`,
one per table layout), in ONE knx-sim process per product so ETS sees a
loaded device at every step:

    a-full-links          the application download after the initial links
    b-partial-add-<n>     a first link on an unlinked object, partial download
    c-partial-remove-<n>  that link removed, partial download
    d-partial-second-ga   a second address on a linked object, partial download
                          (control: no flag change)

Every step's run directory (`captures/ets-sweep/<app>/<step>/`) holds the
step's slice of the sim's pcap (`ets.pcapng`), `objects.json` (ETS's object
table after the link change, the driver's `objects` flow), `objects.png`,
`sim.yaml`, `sim.log`, `ops.txt` and `driver.json`. The outcome manifest is
`results/series.json`: per product why it was chosen and every step's
outcome. `--oracle` then writes and runs the `run=apply` rows of each series
(`apply_rows.py`, `bussard apply` plus a `line apply` row for step B, #478
item 3) on the Mac.

The objects are picked from what ETS shows at default parameters
(`plan_links`): the initial links go to objects with the transmit flag; the
step B object is a visible unlinked object; step D puts the address of the
second link on the first linked object. Hidden objects never appear (the
EK-E72's cooling setpoints, 30 to 36, are hidden; 31 stood in for 32 in the
hand-run series of #469).

The links variant of every product is `defaults.py --variant links`
(`links_hook` below links the objects before the download).
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULTS = HERE / "results" / "series.json"
TRANSMIT, WRITE = "Ü", "S"
# The group-object table of the driver's object view, for the screenshot.
GO_TABLE = (680, 260, 3400, 1240)

# One representative per table layout (#478). `file` is relative to the main
# corpus unless `path` names the product (extra corpus, knx-sim fixture).
REPRESENTATIVES = [
    {"app": "M-0004_A-A011-13-60BC-O000A", "search": "3361-1MWW", "mask": "0705",
     "why": "0705 with load control through properties (Jung 3361-1M)"},
    {"app": "M-0083_A-000E-23-2274", "search": "AKK-01UP.03", "mask": "0705",
     "why": "0705 with load control through memory (MDT AKK)"},
    {"app": "M-00B6_A-4537-03-DE59", "search": "EK-E72", "mask": "0705",
     "path": "tests-support/product-corpus-extra/cache/vendor/APEKE72TP03.knxprod",
     "why": "0705 with the group-object table in a segment of its own (Ekinex EK-E72)"},
    {"app": "M-0071_A-4131-32-17BF", "search": "ZN4131", "mask": "0701",
     "why": "0701, memory-mapped load-state machines (Zennio ACTinBOX MAX6; Theben 4940275 failed the defaults sweep)"},
    {"app": "M-00FA_A-2500-10-51CB", "search": "DA.tp", "mask": "07B0",
     "path": "knx-sim/tests/fixtures/KNX_Virtual_M-00FA.knxprod",
     "why": "07B0, System B relative segments (KNX Virtual DA.tp)"},
]


def has(flags: str | None, flag: str) -> bool:
    return flag in (flags or "")


def plan_links(objects: list[dict], n: int = 4) -> dict:
    """The links of a series, picked from ETS's object table (see the module
    doc): `initial` [(object, ga)] for step A, `add` (object, ga) for B and C,
    `second` (object, ga) for D. Addresses 1/0/1.. in order, 1/0/9 for B.
    None where the table offers no candidate."""
    rows = [o for o in objects if isinstance(o.get("number"), int)]
    # Objects already linked keep their links; the initial links go to free
    # transmitting objects first (the status outputs ETS shows K L Ü), then
    # to any other free object.
    free = [o for o in rows if not o.get("gas")]
    senders = [o for o in free if has(o.get("flags"), TRANSMIT)]
    others = [o for o in free if o not in senders]
    initial_objs = (senders + others)[:n]
    initial = [(o["number"], f"1/0/{i + 1}") for i, o in enumerate(initial_objs)]
    rest = [o for o in free if o not in initial_objs]
    # Step B: a free object, one that can be written or sent preferred.
    add_obj = next((o for o in rest if has(o.get("flags"), WRITE) or has(o.get("flags"), TRANSMIT)), None) \
        or (rest[0] if rest else None)
    add = (add_obj["number"], "1/0/9") if add_obj else None
    # Step D: another link's address on a linked object (the EK-E72 series
    # put 1/0/4 on object 1), one that can be written preferred: a second
    # address is one the object listens to.
    second = None
    if len(initial) >= 2:
        flags = {o["number"]: o.get("flags") for o in initial_objs}
        target = next((n for n, _ in initial if has(flags[n], WRITE)), initial[0][0])
        second = (target, next(ga for n, ga in initial if n != target))
    return {"initial": initial, "add": add, "second": second}


def pcap_slice(data: bytes, offset: int) -> tuple[bytes, int]:
    """A classic pcap of the records that start at byte `offset` of `data`
    (the sim's pcap, little-endian, as it records): the global header plus
    those records, and their count. A record cut off at the end is dropped."""
    out = bytearray(data[:24])
    pos, n = max(offset, 24), 0
    while pos + 16 <= len(data):
        incl = struct.unpack("<I", data[pos + 8:pos + 12])[0]
        if pos + 16 + incl > len(data):
            break
        out += data[pos:pos + 16 + incl]
        pos += 16 + incl
        n += 1
    return bytes(out), n


def links_hook(n: int = 3):
    """`sweep.run_one(before_download=...)` for the links variant: reads the
    object table, links `n` objects plus a second address on the first
    (`plan_links`), reads the table again into objects.json."""

    def hook(flow, out: Path) -> dict:
        objects = flow("objects", ia="1.1.1")["objects"]
        plan = plan_links(objects, n)
        done = []
        for number, ga in plan["initial"] + ([plan["second"]] if plan["second"] else []):
            flow("link", ia="1.1.1", number=number, ga=ga)
            done.append([number, ga])
        after = flow("objects", ia="1.1.1")["objects"]
        (out / "objects.json").write_text(json.dumps(after, indent=1, ensure_ascii=False))
        return {"links": done}

    return hook


def product_path(rep: dict) -> Path:
    import defaults

    if rep.get("path"):
        return REPO / rep["path"]
    apps = json.loads(defaults.APPS.read_text())
    for file, entry in apps.items():
        if any(a["id"] == rep["app"] for a in entry["apps"]):
            return defaults.product_path(file)
    raise SystemExit(f"{rep['app']}: not in catalog-apps.json; give `path`")


def say(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def run_series(c, rep: dict, only_steps: str = "abcd") -> dict:
    """The partial series of one product (see the module doc)."""
    import catalog
    import defaults
    import sweep
    import vm

    app, product = rep["app"], product_path(rep)
    series = sweep.CAPTURES / app
    result: dict = {"why": rep["why"], "product": product.name, "when": datetime.now(timezone.utc).isoformat(),
                    "steps": {}}

    def flow(name: str, /, **body) -> dict:
        r = vm.driver(c, "POST", f"/ets/{name}", {"project": "ets-sweep", **body}, timeout=900)
        if not r.get("ok", True):
            raise RuntimeError(f"{name}: {r.get('error')}")
        return r

    remote = catalog.upload_if_missing(c, product)
    imp = flow("catalog_import", path=remote, timeout=3600)
    result["import"] = imp.get("outcome")
    flow("project_tab", name="ets-sweep")
    for d in flow("devices")["devices"]:
        if not flow("delete_device", ia=d["ia"]).get("deleted"):
            raise RuntimeError(f"could not delete {d['ia']}")
    add = flow("catalog_add", search=rep["search"], version=sweep.app_version(app), fallback_search="",
               password_wait=12 if sweep.secure_enabled(product, app) else 2)
    if not add.get("added"):
        raise RuntimeError(f"catalog add added nothing: {add.get('row')}")
    result["row"] = add.get("row")
    why = defaults.row_version_mismatch(app, add.get("row"))
    if why:
        raise RuntimeError(why)
    prev = json.loads(defaults.RESULTS.read_text()).get(app) if defaults.RESULTS.exists() else None
    first = series / "a-full-links"
    first.mkdir(parents=True, exist_ok=True)
    sim = sweep.RemoteSim(c, product.resolve(), app, "1.1.1", 3672, None, first / "sim.log", mask=rep["mask"],
                          properties=defaults.seed_properties(product, app, prev))
    try:
        plan = plan_links(flow("objects", ia="1.1.1")["objects"])
        result["plan"] = plan
        if not plan["add"] or not plan["second"]:
            raise RuntimeError(f"the object table offers no series: {plan}")
        add_no = plan["add"][0]
        steps = [("a", "a-full-links", "application", [("link", n, g) for n, g in plan["initial"]]),
                 ("b", f"b-partial-add-{add_no}", "partial", [("link", *plan["add"])]),
                 ("c", f"c-partial-remove-{add_no}", "partial", [("unlink", *plan["add"])]),
                 ("d", "d-partial-second-ga", "partial", [("link", *plan["second"])])]
        for letter, name, mode, changes in steps:
            if letter not in only_steps:
                continue
            out = series / name
            out.mkdir(parents=True, exist_ok=True)
            for action, number, ga in changes:
                flow(action, ia="1.1.1", number=number, ga=ga)
            objects = flow("objects", ia="1.1.1")["objects"]
            (out / "objects.json").write_text(json.dumps(objects, indent=1, ensure_ascii=False))
            try:
                shot = vm.driver(c, "POST", "/screenshot", {"window": "desktop", "bbox": list(GO_TABLE)}, timeout=120)
                (out / "objects.png").write_bytes(base64.b64decode(shot["png_base64"]))
            except Exception as exc:  # noqa: BLE001 - a screenshot is evidence, not a step
                say(f"{name}: no screenshot: {exc}")
            flow("select_connection", name="knx-sim")
            offset = remote_size(c)
            since = sweep.vm_now(c)
            log_from = len(sim.lines())
            say(f"{app} {name}: download {mode}")
            r = flow("download", ia="1.1.1", mode=mode)
            end = wait_download(c, sim, since, log_from)
            hist: list[str] = []
            for _ in range(24):
                hist = vm.driver(c, "POST", "/ets/history", {}, timeout=120).get("lines") or []
                if sweep.ets_status(hist) != "unknown":
                    break
                time.sleep(5)
            full = out / "sim-full.pcap"
            sim.fetch_pcap(full)
            sliced, frames = pcap_slice(full.read_bytes(), offset)
            (out / "ets.pcapng").write_bytes(sliced)
            full.unlink()
            (out / "sim.log").write_text("\n".join(sim.lines()[log_from:]) + "\n")
            ops = subprocess.run(["uv", "run", "--quiet", str(sweep.KNXTRACE), "ops", str(out / "ets.pcapng"),
                                  "--device", "1.1.1"], capture_output=True, text=True)
            (out / "ops.txt").write_text(ops.stdout + ops.stderr)
            with c.open_sftp().open(f"{sweep.RemoteSim.DIR}/sim.yaml".replace("\\", "/")) as fh:
                (out / "sim.yaml").write_bytes(fh.read())
            step = {"mode": mode, "changes": changes, "download": r, "end": end, "ets": sweep.ets_status(hist),
                    "history": hist[:4], "frames": frames}
            (out / "driver.json").write_text(json.dumps({"app": app, "variant": name, **step}, indent=1,
                                                        ensure_ascii=False))
            result["steps"][name] = {"ets": step["ets"], "end": end, "frames": frames}
            say(f"{app} {name}: {end}, ETS {step['ets']}, {frames} frames")
            if step["ets"] != "ok":
                break
    finally:
        sim.stop()
    return result


def remote_size(c) -> int:
    import sweep

    try:
        return c.open_sftp().stat(f"{sweep.RemoteSim.DIR}/sim.pcap".replace("\\", "/")).st_size
    except OSError:
        return 24


def wait_download(c, sim, since: str, log_from: int, timeout: int = 900, quiet: int = 30) -> str:
    """The end of one download of the series, by the sim's log (see sweep.run_one)."""
    import sweep

    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(3)
        lines = sim.lines()[log_from:]
        if any("device restarted" in l and "master_reset=false" in l for l in lines):
            time.sleep(3)
            return "device restarted"
        if sweep.ets_failed_since(c, since):
            return "ets logged a failure"
        if any("direction=" in l for l in lines) and sim.last_telegram_age() > quiet:
            return "bus quiet"
    return "timeout"


def oracle(rep: dict, run: bool = True) -> int:
    """Writes the run=apply rows of a recorded series and runs them."""
    import sweep

    args = ["uv", "run", "--quiet", str(HERE / "apply_rows.py"), str(sweep.CAPTURES / rep["app"]),
            "--product", str(product_path(rep)), "--app", rep["app"], "--line-step", "b"]
    return subprocess.run(args + (["--run"] if run else [])).returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("partial", help="the partial-download series on the representative products")
    p.add_argument("--only", default="", help="comma-separated application id prefixes")
    p.add_argument("--steps", default="abcd")
    p.add_argument("--oracle", action="store_true", help="write and run the run=apply rows afterwards")
    p.add_argument("--no-ets", action="store_true", help="with --oracle: only the rows of recorded series")
    p = sub.add_parser("plan", help="print the links a series would make from an objects.json")
    p.add_argument("objects", type=Path)
    args = ap.parse_args()
    if args.cmd == "plan":
        print(json.dumps(plan_links(json.loads(args.objects.read_text())), indent=1))
        return 0
    reps = [r for r in REPRESENTATIVES if not args.only or any(r["app"].startswith(o) for o in args.only.split(","))]
    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    if not args.no_ets:
        import vm

        c = vm.connect()
        for rep in reps:
            try:
                results[rep["app"]] = run_series(c, rep, args.steps)
            except Exception as exc:  # noqa: BLE001 - recorded, the next product runs
                results[rep["app"]] = {"why": rep["why"], "error": f"{type(exc).__name__}: {exc}"[:600],
                                       "when": datetime.now(timezone.utc).isoformat()}
                c = vm.connect()
            RESULTS.parent.mkdir(exist_ok=True)
            RESULTS.write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n")
            say(f"{rep['app']}: {results[rep['app']].get('error') or results[rep['app']]['steps']}")
    status = 0
    if args.oracle:
        for rep in reps:
            status |= oracle(rep)
    return status


if __name__ == "__main__":
    sys.exit(main())
