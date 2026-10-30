# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Calibrate a synthetic product against ETS and, optionally, against the product it was cloned from (epic #596).

    uv run tools/ets-sweep/synthetic/calibrate.py --knxprod <file> --app <application id> --search <order number>
        [--reference-knxprod <file> --reference-app <id> --reference-search <order number>]
        [--no-ets] [--work DIR] [--json FILE]

Per product (the synthetic one, then the reference when given):
  1. the ETS download into knx-sim in the VM (`sweep.run_learning`, as `sweep.py`
     runs it): `captures/ets-sweep/<app>/plain-defaults/` gets `ets.pcapng`,
     `sim.log`, `driver.json` and `ops.txt`; `--no-ets` reuses that capture;
  2. the request fixture (`distil.py`): `requests.txt` in the same directory,
     the form `knx-sim/tests/ets_calibration.rs` replays;
  3. the offline oracle row of the defaults sweep (`oracle.run_row`: a scratch
     model with device 1.1.1 at defaults, `95-offline-oracle.sh` against
     `bussard flash --dry-run`), under `--work` (default
     `captures/ets-sweep/<app>/plain-defaults/`).

Then the verdict table: ETS outcome, operations, oracle verdict, coverage,
load-control verdict, and with a reference the comparisons step 2 of #596
asks for: the `ops.txt` sequences apart from PID_PROGRAM_VERSION, the
request streams apart from the application number, the oracle figures, and
the sim replay: `knx-sim/tests/ets_calibration.rs`
(`test_replay_spec_synthetic_matches_reference`) replays both request fixtures
into devices built from their products, each must reach Loaded without a
rejection and both must leave the same memory image (`--no-replay` skips it;
it runs `cargo test` in `knx-sim/`).

bussard must be built (`target/debug/bussard` or `BUSSARD_BIN`). Nothing here
is committed: the captures and models stay under the gitignored `captures/`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import distil  # noqa: E402
import oracle  # noqa: E402
import sweep  # noqa: E402

REPO = HERE.parents[2]
CAPTURES = REPO / "captures" / "ets-sweep"
VARIANT = "plain-defaults"
# ops.txt lines that carry the product's identity, not its behaviour.
IDENTITY_OPS = re.compile(r"PID_PROGRAM_VERSION|^normalized operation sequence")


def app_number(app: str) -> bytes:
    """The application number octets of an application id (A-2600 -> 26 00)."""
    m = re.match(r"M-[0-9A-F]{4}_A-([0-9A-F]{4})-", app)
    return bytes.fromhex(m.group(1)) if m else b""


def run_dir(app: str) -> Path:
    return CAPTURES / app / VARIANT


def calibrate_one(knxprod: Path, app: str, search: str, ets: bool, work: Path | None,
                  mask: str = "07B0") -> dict:
    """ETS download (unless `ets` is off), request fixture and oracle row of one product.

    `mask` picks the sim's load-state machine in the VM (memory-mapped on 0701,
    as `sweep.RemoteSim` does) and the oracle model's mask."""
    out: dict = {"app": app, "knxprod": str(knxprod)}
    if ets:
        c = sweep.vm.connect()
        r = sweep.run_learning(c, knxprod, app, search, mask=mask)
        out.update({k: r.get(k) for k in ("outcome", "ets", "ops", "loaded_objects", "seconds", "error")})
    else:
        try:
            r = json.loads((run_dir(app) / "driver.json").read_text())
        except (OSError, ValueError) as exc:
            raise SystemExit(f"--no-ets: no earlier run for {app}: {exc}") from exc
        out.update({k: r.get(k) for k in ("outcome", "ets", "ops", "loaded_objects")})
    capture = run_dir(app) / "ets.pcapng"
    if not capture.exists():
        out["oracle"] = {"verdict": "no-capture"}
        return out
    requests = distil.requests(capture)
    (run_dir(app) / "requests.txt").write_text(distil.render(requests, f"{app}/{VARIANT}/ets.pcapng"))
    out["requests"] = len(requests)
    out["oracle"] = oracle.run_row(app, {"file": str(knxprod.resolve()), "mask": mask}, CAPTURES, work)
    return out


def ops_lines(app: str) -> list[str]:
    try:
        return (run_dir(app) / "ops.txt").read_text().splitlines()
    except OSError:
        return []


def compare(cand: dict, ref: dict) -> dict:
    """The differences step 2 counts: operations apart from the identity, the
    request streams apart from the application number, the oracle figures."""
    a, b = ops_lines(cand["app"]), ops_lines(ref["app"])
    ops_diff = [f"{x.strip()}  |  {y.strip()}" for x, y in zip(a, b) if x != y and not IDENTITY_OPS.search(x)]
    if len(a) != len(b):
        ops_diff.append(f"length {len(a)} vs {len(b)}")
    ra = distil.requests(run_dir(cand["app"]) / "ets.pcapng") if cand.get("requests") is not None else []
    rb = distil.requests(run_dir(ref["app"]) / "ets.pcapng") if ref.get("requests") is not None else []
    na, nb = app_number(cand["app"]), app_number(ref["app"])
    req_diff = []
    for i, (x, y) in enumerate(zip(ra, rb)):
        if x != y and not (na and nb and x[2].replace(na, nb) == y[2] and x[:2] == y[:2]):
            req_diff.append(f"#{i + 1}: {x[2].hex()} vs {y[2].hex()}")
    if len(ra) != len(rb):
        req_diff.append(f"length {len(ra)} vs {len(rb)}")
    figures = {}
    for key in ("verdict", "coverage", "confirmed"):
        figures[key] = (cand["oracle"].get(key), ref["oracle"].get(key))
    figures["loadctl"] = (cand["oracle"].get("loadctl", {}).get("verdict"), ref["oracle"].get("loadctl", {}).get("verdict"))
    same = not ops_diff and not req_diff and all(x == y for x, y in figures.values())
    return {"ops": ops_diff, "requests": req_diff, "oracle": figures, "match": same}


def replay(cand: dict, ref: dict) -> dict:
    """Run knx-sim's calibration replay of both request fixtures."""
    spec = lambda r: f"{Path(r['knxprod']).resolve()}|{r['app']}|{run_dir(r['app']) / 'requests.txt'}"  # noqa: E731
    env = {**os.environ, "KNX_SIM_CALIBRATE": spec(cand), "KNX_SIM_CALIBRATE_REFERENCE": spec(ref)}
    r = subprocess.run(["cargo", "test", "--manifest-path", str(REPO / "knx-sim" / "Cargo.toml"), "--test",
                        "ets_calibration", "test_replay_spec", "--", "--nocapture"],
                       capture_output=True, text=True, env=env, timeout=1800)
    lines = [l for l in (r.stdout + r.stderr).splitlines() if ": object " in l or l.startswith("Error")]
    return {"ok": r.returncode == 0, "lines": lines}


def table(rows: list[dict]) -> str:
    head = f"{'application':24} {'ets':7} {'ops':>4} {'reqs':>5} {'oracle':10} {'coverage':>8} {'loadctl':10}"
    lines = [head]
    for r in rows:
        o = r.get("oracle", {})
        lines.append(f"{r['app']:24} {str(r.get('ets')):7} {str(r.get('ops')):>4} {str(r.get('requests')):>5} "
                     f"{str(o.get('verdict')):10} {str(o.get('coverage')):>8} {str(o.get('loadctl', {}).get('verdict')):10}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--knxprod", required=True, type=Path)
    ap.add_argument("--app", required=True)
    ap.add_argument("--search", required=True)
    ap.add_argument("--reference-knxprod", type=Path)
    ap.add_argument("--reference-app")
    ap.add_argument("--reference-search")
    ap.add_argument("--no-ets", action="store_true", help="reuse the captures of an earlier run")
    ap.add_argument("--work", type=Path, help="models and oracle output (default: next to the capture)")
    ap.add_argument("--no-replay", action="store_true", help="skip knx-sim's replay of the request fixtures")
    ap.add_argument("--json", type=Path, help="write the results here as well")
    args = ap.parse_args()
    rows = [calibrate_one(args.knxprod, args.app, args.search, not args.no_ets, args.work)]
    result: dict = {"products": rows}
    if args.reference_knxprod:
        if not (args.reference_app and args.reference_search):
            ap.error("--reference-knxprod needs --reference-app and --reference-search")
        rows.append(calibrate_one(args.reference_knxprod, args.reference_app, args.reference_search,
                                  not args.no_ets, args.work))
        result["comparison"] = compare(rows[0], rows[1])
        if not args.no_replay:
            result["comparison"]["replay"] = replay(rows[0], rows[1])
            result["comparison"]["match"] &= result["comparison"]["replay"]["ok"]
    print(table(rows))
    for r in rows:
        print(f"{r['app']}: {r.get('oracle', {}).get('summary', '')}")
    if "comparison" in result:
        cmp_ = result["comparison"]
        print(f"ops differences beyond the identity: {cmp_['ops'] or 'none'}")
        print(f"request differences beyond the application number: {cmp_['requests'] or 'none'}")
        print(f"oracle figures (synthetic, reference): {cmp_['oracle']}")
        if "replay" in cmp_:
            print("sim replay:", "ok" if cmp_["replay"]["ok"] else "FAILED")
            for line in cmp_["replay"]["lines"]:
                print("  " + line.replace(str(CAPTURES) + "/", ""))
        print("calibration:", "MATCH" if cmp_["match"] else "DIFFERS")
    if args.json:
        args.json.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    return 0 if result.get("comparison", {}).get("match", True) else 1


if __name__ == "__main__":
    sys.exit(main())
