# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""The outcome manifest and the parity summary of the ETS sweep (epic #419,
#422 and #425).

    uv run tools/ets-sweep/summary.py [--results DIR] [--no-history]

Reads the sweep's results (`defaults.json`, `oracle.json`, the optional
hand-kept `benign.json` and `run.json` of the nightly run) and writes, next to
them:

- `manifest.json`: per application its labels only (product file, mask,
  manufacturer, sweep outcome, oracle and load-control verdicts, coverage),
  plus the ETS version and when it was generated. No vendor data, no capture.
- `summary.md`: outcome counts, the parity table (identical / benign / differs
  / ...) per mask family and per manufacturer, and every application whose
  verdict changed since the previous manifest.
- `changes.json`: those changes, machine-readable (`followups.py` opens an
  issue for each identical -> differs).
- `history/manifest-<UTC stamp>.json`: this manifest, the previous one being
  the newest file there before it.

`benign.json` maps an application id to the reason its differences are known
and accepted (`{"M-...": "ETS writes the template tail, #..."}`); such a
`differs` counts as `benign`. The verdict of an application the oracle has not
compared since its last capture is `pending`; one the sweep did not capture
carries its outcome (`ets-failed`, `skipped-mask`, ...).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
# The order the parity columns are shown in; anything else is appended.
VERDICTS = ["identical", "benign", "differs", "differs-props", "not-comparable", "oracle-error", "pending"]
APP_ID = re.compile(r"(M-[0-9A-F]{4})_A-")


def load(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def manufacturer(app: str) -> str:
    m = APP_ID.match(app)
    return m.group(1) if m else "?"


def verdict_of(app: str, entry: dict, oracle: dict, benign: dict) -> str:
    """The application's parity verdict (see the module doc)."""
    if entry.get("outcome") != "captured":
        return entry.get("outcome") or "unknown"
    o = oracle.get(app)
    if not o or (o.get("capture_when") and o.get("capture_when") != entry.get("when")):
        return "pending"
    v = o.get("verdict") or "oracle-error"
    if v.startswith("differs") and app in benign:
        return "benign"
    return v


def build_manifest(defaults: dict, oracle: dict, benign: dict, run: dict, now: str) -> dict:
    apps = {}
    for app, e in sorted(defaults.items()):
        o = oracle.get(app) or {}
        rec = {
            "file": e.get("file"),
            "mask": e.get("mask"),
            "manufacturer": manufacturer(app),
            "outcome": e.get("outcome"),
            "verdict": verdict_of(app, e, oracle, benign),
        }
        if e.get("outcome") == "captured" and o:
            rec["loadctl"] = (o.get("loadctl") or {}).get("verdict")
            if o.get("coverage"):
                rec["coverage"] = o["coverage"]
        if app in benign:
            rec["benign"] = benign[app]
        apps[app] = rec
    return {"generated": now, "ets_version": run.get("ets_version"), "run": run.get("id"), "apps": apps}


def changes(prev: dict | None, cur: dict) -> list[dict]:
    """Every application whose verdict differs between two manifests (new
    and dropped applications included, as `-`)."""
    if not prev:
        return []
    before, after = prev.get("apps", {}), cur.get("apps", {})
    out = []
    for app in sorted(set(before) | set(after)):
        b = (before.get(app) or {}).get("verdict", "-")
        a = (after.get(app) or {}).get("verdict", "-")
        if a != b:
            out.append({"app": app, "before": b, "after": a, "mask": (after.get(app) or before.get(app) or {}).get("mask"),
                        "file": (after.get(app) or before.get(app) or {}).get("file"),
                        "regression": b == "identical" and a.startswith("differs")})
    return out


def table(rows: dict[str, dict[str, int]], key_name: str, hint: dict[str, str] | None = None) -> list[str]:
    cols = [v for v in VERDICTS if any(v in r for r in rows.values())]
    cols += sorted({v for r in rows.values() for v in r} - set(cols))
    head = [key_name] + (["product files"] if hint else []) + cols + ["total"]
    lines = ["| " + " | ".join(head) + " |", "| " + " | ".join(["---"] * (1 + bool(hint)) + ["---:"] * (len(cols) + 1)) + " |"]
    for key, r in sorted(rows.items(), key=lambda kv: (-sum(kv[1].values()), kv[0])):
        cells = [key] + ([hint.get(key, "")] if hint else []) + [str(r.get(c, "")) for c in cols] + [str(sum(r.values()))]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


COMPARED = set(VERDICTS)


def render(manifest: dict, delta: list[dict]) -> str:
    apps = manifest["apps"]
    outcomes: dict[str, int] = {}
    for r in apps.values():
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    per_mask: dict[str, dict[str, int]] = {}
    per_vendor: dict[str, dict[str, int]] = {}
    files: dict[str, dict[str, int]] = {}
    loadctl: dict[str, dict[str, int]] = {}
    for app, r in apps.items():
        if r["verdict"] not in COMPARED:
            continue
        for bucket, key in ((per_mask, r["mask"] or "?"), (per_vendor, r["manufacturer"])):
            row = bucket.setdefault(key, {})
            row[r["verdict"]] = row.get(r["verdict"], 0) + 1
        f = files.setdefault(r["manufacturer"], {})
        f[r["file"] or "?"] = f.get(r["file"] or "?", 0) + 1
        if r.get("loadctl"):
            row = loadctl.setdefault(r["mask"] or "?", {})
            row[r["loadctl"]] = row.get(r["loadctl"], 0) + 1
    hint = {m: ", ".join(sorted(fs, key=lambda k: -fs[k])[:2])[:60] for m, fs in files.items()}
    out = [
        "# ETS sweep parity summary",
        "",
        f"Generated {manifest['generated']}"
        + (f", ETS {manifest['ets_version']}" if manifest.get("ets_version") else "")
        + (f", run {manifest['run']}" if manifest.get("run") else "") + ".",
        "",
        "## Sweep outcomes",
        "",
        "| outcome | applications |",
        "| --- | ---: |",
    ]
    out += [f"| {k} | {v} |" for k, v in sorted(outcomes.items(), key=lambda kv: -kv[1])]
    out += ["", "## Parity per mask family", ""] + table(per_mask, "mask")
    out += ["", "## Load-control parity per mask family", ""] + table(loadctl, "mask")
    out += ["", "## Parity per manufacturer", ""] + table(per_vendor, "manufacturer", hint)
    out += ["", "## Verdict changes since the previous manifest", ""]
    if not delta:
        out.append("None.")
    else:
        out += ["| application | mask | before | after | |", "| --- | --- | --- | --- | --- |"]
        for d in delta:
            flag = "**regression**" if d["regression"] else ""
            out.append(f"| {d['app']} | {d.get('mask') or ''} | {d['before']} | {d['after']} | {flag} |")
    return "\n".join(out) + "\n"


def previous_manifest(history: Path) -> dict | None:
    files = sorted(history.glob("manifest-*.json"))
    return load(files[-1], None) if files else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=RESULTS)
    ap.add_argument("--no-history", action="store_true", help="do not record this manifest in history/")
    args = ap.parse_args()
    res = args.results
    defaults = load(res / "defaults.json", None)
    if defaults is None:
        print(f"no {res / 'defaults.json'}", file=sys.stderr)
        return 1
    now = datetime.now(timezone.utc)
    manifest = build_manifest(defaults, load(res / "oracle.json", {}), load(res / "benign.json", {}),
                              load(res / "run.json", {}), now.isoformat(timespec="seconds"))
    history = res / "history"
    delta = changes(previous_manifest(history), manifest)
    (res / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n")
    (res / "changes.json").write_text(json.dumps(delta, indent=1, ensure_ascii=False) + "\n")
    (res / "summary.md").write_text(render(manifest, delta))
    if not args.no_history:
        history.mkdir(exist_ok=True)
        shutil.copyfile(res / "manifest.json", history / f"manifest-{now.strftime('%Y%m%dT%H%M%SZ')}.json")
    regressions = [d for d in delta if d["regression"]]
    print(f"{len(manifest['apps'])} applications, {len(delta)} verdict changes, {len(regressions)} identical -> differs; "
          f"{res / 'summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
