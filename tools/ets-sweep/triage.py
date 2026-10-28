# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Triage the defaults sweep's failures while it runs (epic #419, part 3 #422).

    uv run tools/ets-sweep/triage.py [--watch] [--interval 120]

For every application in results/defaults.json whose outcome is ets-failed,
driver-error, sim-refused or unknown and that has no triage entry for that
attempt yet, collect the evidence:

  - ETS's history line (from the run's driver.json),
  - ETS's own WARN/ERROR log lines written during that run (its log names the
    failing load-procedure step or the identity it required),
  - what knx-sim rejected (sim.log), and the last operations on the wire,

and reduce it to a cause signature. results/triage.json keeps one entry per
application and results/triage.md the tally per signature with examples.

With --watch it polls and exits as soon as a signature appears that has not
been seen before (status 3), so whoever started it is woken for a new kind of
failure while known ones only add to the tally. Nothing here changes the sweep.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULTS = HERE / "results" / "defaults.json"
TRIAGE = HERE / "results" / "triage.json"
REPORT = HERE / "results" / "triage.md"
CAPTURES = REPO / "captures" / "ets-sweep"
KNXTRACE = REPO / "tools" / "knxtrace" / "knxtrace.py"
ETS_LOG = r"C:\Users\macremote\AppData\Local\KNX\ETS6\Log\ETS6.log"
FAILED = {"ets-failed", "driver-error", "sim-refused", "unknown"}
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def norm(text: str) -> str:
    """A cause signature: numbers, hex, quoted values and addresses folded."""
    t = re.sub(r"[\[{].*", "[…]", text)  # a dump of catalog rows or devices
    t = re.sub(r"\b(?:0x)?[0-9A-Fa-f]{4,}\b", "#", t)
    # Search terms and versions vary per product; keep the message around them.
    t = re.sub(r"(for|shows|wanted|term|search:?) '[^']*'", r"\1 '…'", t)
    t = re.sub(r"\b\d+(?:\.\d+)*\b", "N", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()[:160]


def ets_log_lines(c, start: datetime, end: datetime, offset: timedelta) -> list[str]:
    """ETS's WARN/ERROR lines between start and end (UTC), its log being in VM local time."""
    cmd = ("powershell -NoProfile -Command \"Get-Content -Path '" + ETS_LOG + "' -Tail 4000 | "
           "Select-String -Pattern ' (WARN|ERROR) ' | ForEach-Object { $_.Line }\"")
    out = []
    lo, hi = (start + offset).strftime("%Y-%m-%d %H:%M:%S"), (end + offset).strftime("%Y-%m-%d %H:%M:%S")
    for line in vm.run(c, cmd, 180)[1].splitlines():
        ts = line[:19]
        if lo <= ts <= hi:
            out.append(line.strip()[:400])
    return out


def ets_signature(lines: list[str]) -> str | None:
    for line in lines:
        m = re.search(r"Load Control <(LdCtrl\w+)([^>]*)/?> failed: (\w+)", line)
        if m:
            obj = re.search(r'ObjIdx="(\d+)"', m.group(2))
            pid = re.search(r'PropId="(\d+)"', m.group(2))
            where = f" obj {obj.group(1)}" if obj else ""
            where += f" pid {pid.group(1)}" if pid else ""
            return f"ets: {m.group(1)}{where} failed: {m.group(3)}"
        m = re.search(r"Required data mismatch at (\w+)\(([^)]*)\)", line)
        if m:
            return f"ets: required {m.group(1)}({m.group(2)}) still mismatching after learning"
    for line in lines:
        if " ERROR " in line:
            return "ets: " + norm(line.split(" - ", 1)[-1])
    return None


def sim_rejects(run: Path) -> list[str]:
    log = run / "sim.log"
    if not log.exists():
        return []
    text = ANSI.sub("", log.read_text(errors="replace"))
    return sorted({re.sub(r".*REJECTED by [0-9.]+: ", "", l).replace(" direction=ToBus", "")
                   for l in text.splitlines() if "REJECTED" in l})


def last_ops(run: Path, n: int = 8) -> list[str]:
    cap = run / "ets.pcapng"
    if not cap.exists() or cap.stat().st_size < 100:
        return []
    r = subprocess.run(["uv", "run", "--quiet", str(KNXTRACE), "trace", str(cap)], capture_output=True, text=True)
    ops = [l.strip()[len("L_Data."):][:180] for l in (x.strip() for x in r.stdout.splitlines())
           if l.startswith("L_Data.") and "T_ACK" not in l and "L_Data.con" not in l]
    return ops[-n:]


def triage_one(c, app: str, entry: dict, offset: timedelta) -> dict:
    run = CAPTURES / app / "plain-defaults"
    end = datetime.fromisoformat(entry["when"])
    start = end - timedelta(seconds=(entry.get("seconds") or 0) + 30)
    history = entry.get("ets_history") or []
    ets_lines = ets_log_lines(c, start, end + timedelta(seconds=30), offset) if entry["outcome"] == "ets-failed" else []
    rejects = sim_rejects(run)
    sig = None
    if entry["outcome"] == "driver-error":
        sig = "driver: " + norm((entry.get("error") or "")[:200])
    elif entry["outcome"] == "sim-refused":
        m = re.search(r"Caused by:\s*(.*)", entry.get("error") or "", re.S)
        sig = "sim refused: " + norm((m.group(1) if m else entry.get("error") or "")[:200])
    else:
        sig = ets_signature(ets_lines)
        if not sig and rejects:
            sig = "sim rejected: " + norm(rejects[0])
        if not sig:
            detail = next((h for h in history[3:] if h.strip()), "")
            sig = "ets: " + norm(detail or "failed, no detail")
    return {
        "signature": sig,
        "outcome": entry["outcome"],
        "mask": entry.get("mask"),
        "name": entry.get("name"),
        "when": entry["when"],
        "ets_history": history[1:5],
        "ets_log": ets_lines[-8:],
        "sim_rejects": rejects[:5],
        "last_ops": last_ops(run),
        "error": (entry.get("error") or "")[:300],
    }


def write_report(tri: dict) -> None:
    by: dict[str, list[str]] = {}
    for app, t in tri.items():
        by.setdefault(t["signature"], []).append(app)
    lines = ["# ETS sweep triage", "", f"{len(tri)} failures, {len(by)} causes.", "",
             "| failures | cause | examples |", "| ---: | --- | --- |"]
    for sig, apps in sorted(by.items(), key=lambda kv: -len(kv[1])):
        ex = ", ".join(f"{a} ({tri[a]['name']})"[:70] for a in apps[:3])
        lines.append(f"| {len(apps)} | {sig.replace('|', '/')} | {ex} |")
    REPORT.write_text("\n".join(lines) + "\n")


def run_once(c, tri: dict, offset: timedelta) -> list[str]:
    results = json.loads(RESULTS.read_text())
    known = {t["signature"] for t in tri.values()}
    new_sigs: list[str] = []
    for app, entry in sorted(results.items(), key=lambda kv: kv[1].get("when", "")):
        if entry["outcome"] not in FAILED:
            tri.pop(app, None)  # it passed on a later attempt
            continue
        if app in tri and tri[app]["when"] == entry["when"]:
            continue
        if "not the RDP layout" in (entry.get("error") or "") or "screen grab failed" in (entry.get("error") or ""):
            continue  # an interrupted session, not a product's failure; the sweep reruns it
        t = triage_one(c, app, entry, offset)
        tri[app] = t
        print(f"{t['signature'][:110]:110} {app}", flush=True)
        if t["signature"] not in known:
            known.add(t["signature"])
            new_sigs.append(t["signature"])
    TRIAGE.write_text(json.dumps(dict(sorted(tri.items())), indent=1, ensure_ascii=False) + "\n")
    write_report(tri)
    return new_sigs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--watch", action="store_true", help="poll; exit 3 on a cause not seen before")
    ap.add_argument("--interval", type=int, default=120)
    args = ap.parse_args()
    c = vm.connect()
    offset_h = vm.run(c, 'powershell -NoProfile -Command "[TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalHours"')[1].strip()
    offset = timedelta(hours=float(offset_h.replace(",", ".") or 0))
    tri = json.loads(TRIAGE.read_text()) if TRIAGE.exists() else {}
    first = True
    while True:
        try:
            new = run_once(c, tri, offset)
        except Exception as exc:  # noqa: BLE001 - a dropped ssh link: reconnect next round
            print(f"triage round failed: {exc}", flush=True)
            new = []
            c = vm.connect()
        if new and not first and args.watch:
            print("NEW CAUSE: " + " || ".join(new), flush=True)
            return 3
        first = False
        if not args.watch:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
