# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""A follow-up issue for every application whose oracle verdict went from
identical to differs (epic #419, part 6 #425).

    uv run tools/ets-sweep/followups.py [--results DIR] [--captures DIR] [--work DIR] [--create]

Reads `changes.json` (written by `summary.py`) and, for each change flagged
`regression`, drafts an issue: the application id, mask and product file, the
capture path, the verdict before and after, the oracle's region summary and
an excerpt of its diff (`<oracle dir>/1.1.1/diff.txt`). Without `--create`
the drafts are printed and nothing leaves the machine. With `--create` each
is opened with `gh issue create` (labels `bug`, `ets-sweep`, `oracle`) unless
an open issue already names the application in its title, or an earlier run
opened one (`followups.json` keeps application -> issue number).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULTS = HERE / "results"
CAPTURES = REPO / "captures" / "ets-sweep"
LABELS = ("bug", "ets-sweep", "oracle")
EXCERPT_LINES = 30


def load(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def diff_excerpt(oracle_dir: Path, lines: int = EXCERPT_LINES) -> str:
    """The first lines of the row's knxtrace diff, or a note when absent."""
    try:
        text = (oracle_dir / "1.1.1" / "diff.txt").read_text().splitlines()
    except OSError:
        return f"(no diff.txt under {oracle_dir})"
    more = f"\n... {len(text) - lines} more lines" if len(text) > lines else ""
    return "\n".join(text[:lines]) + more


def draft(change: dict, oracle: dict, captures: Path, work: Path | None, run: dict) -> dict:
    """The title and body of one follow-up issue."""
    app = change["app"]
    o = oracle.get(app) or {}
    run_dir = captures / app / "plain-defaults"
    oracle_dir = (work / app / "plain-defaults" / "oracle") if work else run_dir / "oracle"
    title = f"ETS sweep: {app} went from identical to {change['after']} ({change.get('mask') or '?'})"
    body = "\n".join([
        f"Found by the nightly ETS sweep run {run.get('id') or '?'} (ETS {run.get('ets_version') or '?'}): "
        f"the offline-oracle verdict of `{app}` changed from `{change['before']}` to `{change['after']}`.",
        "",
        "## Evidence",
        "",
        f"- Product file: `{change.get('file') or '?'}`, mask {change.get('mask') or '?'}",
        f"- Capture: `{run_dir / 'ets.pcapng'}` (local, gitignored)",
        f"- Oracle summary: `{o.get('summary') or o.get('regions') or '?'}`",
        f"- Load control: `{(o.get('loadctl') or {}).get('verdict', '?')}`",
        "",
        "```",
        diff_excerpt(oracle_dir),
        "```",
        "",
        "## Done when",
        "",
        "The row is `identical` again, or the change is explained here and the application is listed in "
        "`tools/ets-sweep/results/benign.json`.",
        "",
        "## References",
        "",
        "#419, #422, #425",
    ])
    return {"app": app, "title": title, "body": body}


def open_issue_for(app: str) -> int | None:
    """An open issue whose title names `app`, if any."""
    r = subprocess.run(["gh", "issue", "list", "--state", "open", "--search", f"{app} in:title",
                        "--json", "number,title"], capture_output=True, text=True, cwd=REPO)
    try:
        hits = [i for i in json.loads(r.stdout or "[]") if app in i["title"]]
    except ValueError:
        return None
    return hits[0]["number"] if hits else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=RESULTS)
    ap.add_argument("--captures", type=Path, default=CAPTURES)
    ap.add_argument("--work", type=Path, help="the oracle's --work directory, if it ran with one")
    ap.add_argument("--create", action="store_true", help="open the issues (default: print the drafts)")
    args = ap.parse_args()
    changes = [c for c in load(args.results / "changes.json", []) if c.get("regression")]
    oracle = load(args.results / "oracle.json", {})
    run = load(args.results / "run.json", {})
    opened = load(args.results / "followups.json", {})
    for change in changes:
        d = draft(change, oracle, args.captures, args.work, run)
        if d["app"] in opened:
            print(f"{d['app']}: issue #{opened[d['app']]} opened earlier")
            continue
        if not args.create:
            print(f"--- draft (not opened; --create opens it)\n# {d['title']}\n\n{d['body']}\n")
            continue
        existing = open_issue_for(d["app"])
        if existing:
            print(f"{d['app']}: open issue #{existing} already names it")
            opened[d["app"]] = existing
            continue
        cmd = ["gh", "issue", "create", "--title", d["title"], "--body", d["body"]]
        for label in LABELS:
            cmd += ["--label", label]
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)
        url = r.stdout.strip()
        if r.returncode == 0 and url.rsplit("/", 1)[-1].isdigit():
            opened[d["app"]] = int(url.rsplit("/", 1)[-1])
            print(f"{d['app']}: opened {url}")
        else:
            print(f"{d['app']}: gh failed: {r.stderr.strip()[:200]}")
    (args.results / "followups.json").write_text(json.dumps(opened, indent=1, sort_keys=True) + "\n")
    print(f"{len(changes)} identical -> differs change(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
