# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""The nightly ETS sweep run (epic #419, part 6 #425).

    uv run tools/ets-sweep/nightly.py [--shards 4] [--steps preflight,build,sweep,oracle,summary,followups]
                                      [--create-issues] [--dry-run]

Started by launchd (`schedule/dev.bussard.ets-sweep.nightly.plist`) or cron
(`schedule/crontab.txt`); README "Nightly run" has the install steps. One run:

  preflight  the driver answers in the VM and ETS is among its windows, else
             the run stops (the VM desktop is not ready; nothing is retried)
  build      `cargo build -p bussard-cli` and knx-sim, so the oracle runs this
             checkout's bussard
  sweep      every shard of `defaults.py --redo-failed`, one after the other
             (one VM, one ETS), then the links variant
  oracle     `oracle.py --redo` and the same for the links variant: every
             row again, so a bussard change shows as a verdict change
  summary    `summary.py`: manifest, parity summary, verdict changes
  followups  `followups.py`: an issue per identical -> differs change
             (printed only, unless --create-issues)

`results/run.json` names the run (UTC stamp), the ETS version and each step's
exit code and seconds; `summary.py` puts the ETS version and run id into the
manifest. The log of the run is `results/nightly/<stamp>.log`. A lock
(`results/nightly/lock`) keeps a second run from starting while one is busy.
Nothing is committed: the results stay untracked until the owner commits a
manifest.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULTS = HERE / "results"
NIGHTLY = RESULTS / "nightly"
STEPS = ("preflight", "build", "sweep", "oracle", "summary", "followups")


def uv(script: str, *args: str) -> list[str]:
    return ["uv", "run", "--quiet", str(HERE / script), *args]


def commands(step: str, shards: int, create_issues: bool) -> list[list[str]]:
    """The commands of one step, in order (see the module doc)."""
    if step == "preflight":
        return [uv("vm.py", "driver", "GET", "/health")]
    if step == "build":
        return [["cargo", "build", "-q", "-p", "bussard-cli"],
                ["cargo", "build", "-q", "--manifest-path", str(REPO / "knx-sim" / "Cargo.toml")]]
    if step == "sweep":
        return [uv("defaults.py", "--redo-failed", "--shard", f"{k}/{shards}") for k in range(shards)] \
            + [uv("defaults.py", "--variant", "links")]
    if step == "oracle":
        # Every row again: a verdict change comes from a new bussard as often
        # as from a new capture (seconds per row with the shared imports).
        return [uv("oracle.py", "--redo"), uv("oracle.py", "--redo", "--variant", "links")]
    if step == "summary":
        return [uv("summary.py")]
    if step == "followups":
        return [uv("followups.py", *(["--create"] if create_issues else []))]
    raise ValueError(step)


def preflight_ok(output: str) -> str | None:
    """None when the driver's /health shows ETS, else why not."""
    try:
        health = json.loads(output[output.index("{"):])
    except ValueError:
        return f"driver did not answer: {output.strip()[-200:]}"
    titles = [w.get("title", "") for w in health.get("windows") or []]
    if not any(t.startswith("ETS6") for t in titles):
        return f"ETS is not among the driver's windows: {titles[:6]}"
    return None


class Lock:
    """A directory lock; a stale one (older than `stale` seconds) is taken over."""

    def __init__(self, path: Path, stale: int = 20 * 3600):
        self.path, self.stale = path, stale

    def __enter__(self):
        try:
            self.path.mkdir(parents=True)
        except FileExistsError:
            if time.time() - self.path.stat().st_mtime < self.stale:
                raise SystemExit(f"another nightly run holds {self.path}")
            self.path.touch()
        return self

    def __exit__(self, *exc):
        try:
            self.path.rmdir()
        except OSError:
            pass


def ets_version() -> str | None:
    try:
        import sweep
        import vm

        return sweep.ets_version(vm.connect())
    except Exception:  # noqa: BLE001 - recorded as unknown
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--shards", type=int, default=int(os.environ.get("ETS_SWEEP_SHARDS", "4")))
    ap.add_argument("--steps", default=",".join(STEPS))
    ap.add_argument("--create-issues", action="store_true", help="open the follow-up issues (default: print them)")
    ap.add_argument("--dry-run", action="store_true", help="print the commands, run nothing")
    args = ap.parse_args()
    steps = [s for s in args.steps.split(",") if s]
    for s in steps:
        if s not in STEPS:
            raise SystemExit(f"unknown step {s}; steps: {', '.join(STEPS)}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.dry_run:
        for s in steps:
            for cmd in commands(s, args.shards, args.create_issues):
                print(f"{s:10} {' '.join(cmd)}")
        return 0
    sys.path.insert(0, str(HERE))
    NIGHTLY.mkdir(parents=True, exist_ok=True)
    log = (NIGHTLY / f"{stamp}.log").open("a")
    run = {"id": stamp, "started": datetime.now(timezone.utc).isoformat(), "steps": {}}
    status = 0
    with Lock(NIGHTLY / "lock"):
        for s in steps:
            for cmd in commands(s, args.shards, args.create_issues):
                t0 = time.time()
                log.write(f"\n== {s}: {' '.join(cmd)}\n")
                log.flush()
                p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
                log.write(p.stdout + p.stderr)
                log.flush()
                run["steps"].setdefault(s, []).append({"cmd": cmd[3:] if cmd[0] == "uv" else cmd, "exit": p.returncode,
                                                       "seconds": round(time.time() - t0)})
                if s == "preflight":
                    why = preflight_ok(p.stdout) if p.returncode == 0 else f"exit {p.returncode}: {p.stderr[-200:]}"
                    if why:
                        run["stopped"] = f"preflight: {why}"
                        break
                    run["ets_version"] = ets_version()
                elif p.returncode != 0 and s in ("build",):
                    run["stopped"] = f"{s} failed (exit {p.returncode})"
                    break
                elif p.returncode != 0:
                    status = 1
            run["ended"] = datetime.now(timezone.utc).isoformat()
            (RESULTS / "run.json").write_text(json.dumps(run, indent=1) + "\n")
            if run.get("stopped"):
                status = 2
                break
    print(f"nightly {stamp}: {run.get('stopped') or 'done'}; log {NIGHTLY / (stamp + '.log')}")
    return status


if __name__ == "__main__":
    sys.exit(main())
