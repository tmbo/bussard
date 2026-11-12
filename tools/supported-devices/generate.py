# /// script
# requires-python = ">=3.11"
# ///
"""Compute the generated half of bussard's device-support list (issue #1097).

    uv run tools/supported-devices/generate.py            # write the list
    uv run tools/supported-devices/generate.py --check    # fail if it is stale (CI)
    uv run tools/supported-devices/generate.py --stats    # print the counts

Reads committed files only:

- `crates/bussard-model/data/supported-devices.toml`, the hand-kept half:
  `proven` entries (which define the proven families) and the house `likely`
  entries. An application listed there is never generated.
- `tools/supported-devices/causes.toml`, hand-kept: the issue and cause of each
  application the sweep reports `differs`.
- `tools/ets-sweep/evidence/manifest.json`, the ETS sweep (#422).
- `tools/ets-sweep/catalog-apps.json`, for the product names.
- `captures/synthetic/manifest.json` and `tests-support/synthetic-products/`,
  the synthetic catalogue (#596): counted per family, not listed.

and writes `crates/bussard-model/data/supported-generated.toml`, which the
binary embeds next to the hand file.

The rule for `likely` (rule `sweep-1`), per application id (manufacturer,
application number, version; the sweep keys several builds of one id):

1. a sweep row has the oracle verdict `identical`;
2. its load-control verdict is `identical` (the sweep README names no case
   where an absent one is expected, so absent does not pass);
3. its coverage is at or above COVERAGE_FLOOR;
4. no sweep row of the id is `differs`;
5. its family has a proven device. The family key is the mask: the
   load-procedure shape cannot be derived from committed data yet.

Not checked by sweep-1 (open in #1097): the construct fingerprint of the
application against the synthetic catalogue, and branch coverage (a defaults
sweep reaches the default branches only).

An id with a `differs` row is generated as `unsupported`, with the cause from
causes.toml. The synthetic M-00FA applications are not listed: no real device
runs them, and the knx-sim loop runs on loopback, where nothing is refused.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
HAND = REPO / "crates/bussard-model/data/supported-devices.toml"
OUT = REPO / "crates/bussard-model/data/supported-generated.toml"
CAUSES = HERE / "causes.toml"
SWEEP = REPO / "tools/ets-sweep/evidence/manifest.json"
CATALOG = REPO / "tools/ets-sweep/catalog-apps.json"
SYNTHETIC = REPO / "captures/synthetic/manifest.json"
SYNTHETIC_PRODUCTS = REPO / "tests-support/synthetic-products"

# Coverage floor of rule sweep-1, percent. Of the 1414 identical rows of the
# 2026-11-10 manifest, 1411 cover 100.0 % and three (Zennio-built M-00C9, mask
# 0701) cover 97.7 %; nothing lies between 50 % (the oracle's own thin rule,
# below which a row is `not-comparable`) and 97.7 %. 95 % admits what the
# sweep shows today and keeps a future row that compares a fifth less out.
COVERAGE_FLOOR = 95.0
RULE = "sweep-1"
CHECKED = [
    "every captured build: sweep oracle verdict identical",
    "every captured build: sweep load-control verdict identical",
    f"every captured build: sweep coverage at or above {COVERAGE_FLOOR:.1f} %",
    "no sweep row of the application differs",
    "every mask a build of the application has: a proven device",
]
NOT_CHECKED = [
    "builds the sweep did not capture (skipped as an older catalog version or by the catalog "
    "check): counted in `uncompared`, neither for nor against the entry",
    "construct fingerprint against the synthetic catalogue (#1097)",
    "branch coverage beyond the default branches (#1097)",
    "real firmware behaviour (only a proven device shows it)",
]
DIFFERS_REASON = "differs from ETS in the sweep"

_KEY = re.compile(r"^M-([0-9A-F]{4})_A-([0-9A-F]{4})-([0-9A-F]{2})(?:-|$)")
_MASK = re.compile(r'MaskVersion="MV-([0-9A-F]{4})"')


def application_id(key: str) -> str | None:
    """The ten-digit application id of a sweep key (`M-0001_A-140B-11-3036-O0048`)."""
    m = _KEY.match(key)
    return "".join(m.groups()) if m else None


def coverage_of(row: dict) -> float | None:
    """A row's coverage as a number (`"100.0%"` is 100.0), None when absent."""
    text = (row.get("coverage") or "").rstrip("%")
    try:
        return float(text)
    except ValueError:
        return None


def passes(row: dict) -> bool:
    """Conditions 1 to 3 of sweep-1 on one sweep row."""
    cov = coverage_of(row)
    return (row.get("verdict") == "identical" and row.get("loadctl") == "identical"
            and cov is not None and cov >= COVERAGE_FLOOR)


def toml_str(text: str) -> str:
    """A TOML basic string."""
    out = text.replace("\\", "\\\\").replace('"', '\\"')
    out = "".join(c if c >= " " else f"\\u{ord(c):04x}" for c in out)
    return f'"{out}"'


def names() -> dict[str, str]:
    """Product name per application id from catalog-apps.json: the program's
    name and up to two order numbers."""
    out: dict[str, str] = {}
    for entry in json.loads(CATALOG.read_text()).values():
        for app in entry.get("apps") or []:
            aid = application_id(app.get("id", ""))
            if not aid or aid in out:
                continue
            name = " ".join((app.get("name") or "").split()) or app["id"]
            orders = sorted(set(app.get("order_numbers") or []))
            if orders:
                more = f", +{len(orders) - 2}" if len(orders) > 2 else ""
                name = f"{name} ({', '.join(orders[:2])}{more})"
            out[aid] = name
    return out


def synthetic_families() -> Counter:
    """Synthetic products whose every committed capture is identical, per mask."""
    caps = json.loads(SYNTHETIC.read_text())["captures"]
    verdicts: dict[str, set[str]] = defaultdict(set)
    for cap in caps:
        verdicts[cap["product"]].add((cap.get("oracle") or {}).get("verdict", ""))
    out: Counter = Counter()
    for product, seen in verdicts.items():
        if seen != {"identical"}:
            continue
        masks = set()
        for xml in (SYNTHETIC_PRODUCTS / product / "xml").rglob("*.xml"):
            masks.update(_MASK.findall(xml.read_text(encoding="utf-8")))
        for mask in masks:
            out[mask] += 1
    return out


def classify(group: list[dict], proven: set[str]) -> tuple[float, int] | list[str] | None:
    """Rule sweep-1 on the sweep rows of one application id (no row differs):
    `(coverage, uncompared builds)` when it is likely, the unproven masks when
    only the family rule holds it back, `None` otherwise."""
    captured = [r for r in group if r.get("outcome") == "captured"]
    if not captured or not all(passes(r) for r in captured):
        return None
    unproven = sorted({r.get("mask") or "?" for r in group} - proven)
    if unproven:
        return unproven
    return min(coverage_of(r) or 0.0 for r in captured), len(group) - len(captured)


class InputError(SystemExit):
    """A committed input the generator refuses; the message names the id."""


def check_hand(hand: list[dict], rows: dict[str, list[tuple[str, dict]]]) -> None:
    """Cross-checks the hand-kept entries against the sweep.

    - A hand entry's `mask` must be the mask of every sweep row of its id, so a
      typo cannot open a family; an id the sweep never saw needs `mask_source`
      saying where the mask comes from.
    - A hand entry that passes the gate (`proven`, `likely`) must not have a
      sweep row whose oracle or load-control verdict is `differs`, unless the
      entry says why in `sweep_differs`.
    """
    errors = []
    for d in hand:
        aid, mask = d["application_id"], d["mask"]
        group = rows.get(aid, [])
        masks = {r.get("mask") for _, r in group}
        if group and masks != {mask}:
            errors.append(f"{aid}: hand mask {mask}, the sweep has {', '.join(sorted(m or '?' for m in masks))}")
        if not group and not d.get("mask_source"):
            errors.append(f"{aid}: no sweep row; say where mask {mask} comes from in mask_source")
        if d["category"] in ("proven", "likely") and not d.get("sweep_differs"):
            bad = [k for k, r in group if "differs" in (r.get("verdict"), r.get("loadctl"))]
            if bad:
                errors.append(f"{aid}: {d['category']}, but the sweep reports differs for {', '.join(bad)} "
                              "(fix the entry, or say why in sweep_differs)")
    if errors:
        raise InputError(f"{HAND.relative_to(REPO)} contradicts the sweep:\n  " + "\n  ".join(errors))


def compute() -> tuple[str, dict]:
    """The generated file's text and the counts behind it."""
    hand = tomllib.loads(HAND.read_text())["device"]
    hand_ids = {d["application_id"] for d in hand}
    proven: dict[str, list[str]] = defaultdict(list)
    for d in hand:
        if d["category"] == "proven":
            proven[d["mask"]].append(d["application_id"])
    causes = tomllib.loads(CAUSES.read_text())["cause"]
    sweep = json.loads(SWEEP.read_text())
    label = names()

    rows: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for key, row in sweep["apps"].items():
        aid = application_id(key)
        if aid:
            rows[aid].append((key, row))
    check_hand(hand, rows)

    likely, differs = [], []
    blocked: Counter = Counter()
    for aid in sorted(rows):
        if aid in hand_ids or aid.startswith("00FA"):
            continue
        group = rows[aid]
        masks = sorted({r.get("mask") or "?" for _, r in group})
        name = label.get(aid) or group[0][1].get("file") or aid
        if any(r.get("verdict") == "differs" for _, r in group):
            cause = causes.get(aid)
            if cause is None:
                raise InputError(f"{aid} differs in the sweep but has no entry in {CAUSES.relative_to(REPO)}")
            differs.append((aid, name, masks, cause))
            continue
        verdict = classify([r for _, r in group], set(proven))
        if verdict is None:
            continue
        if isinstance(verdict, list):
            for m in verdict:
                blocked[m] += 1
            continue
        cov, uncompared = verdict
        likely.append((aid, name, masks, cov, uncompared))
    stale = sorted(set(causes) - {d[0] for d in differs})
    if stale:
        raise InputError(f"{CAUSES.relative_to(REPO)} names applications the sweep no longer reports differs: {', '.join(stale)}")

    synth = synthetic_families()
    masks = sorted(set(proven) | set(blocked) | set(synth))
    out = [
        "# Generated by tools/supported-devices/generate.py from committed files; do",
        "# not edit. Regenerate after a change to its inputs (CI runs --check). The",
        "# hand-kept half is supported-devices.toml; the rule is in the generator's",
        "# docstring and in docs/explanation/device-support.md.",
        "",
        "[source]",
        f"sweep_manifest = {toml_str(str(SWEEP.relative_to(REPO)))}",
        f"sweep_generated = {toml_str(sweep.get('generated') or '')}",
        f"synthetic_manifest = {toml_str(str(SYNTHETIC.relative_to(REPO)))}",
        f"coverage_floor = {COVERAGE_FLOOR:.1f}",
        "",
    ]
    for mask in masks:
        out += [
            "[[family]]",
            f"mask = {toml_str(mask)}",
            f"blocked = {blocked[mask]}",
            f"synthetic = {synth[mask]}",
            "",
        ]
    out += [
        "[[rule]]",
        f"id = {toml_str(RULE)}",
        f"checked = [{', '.join(toml_str(c) for c in CHECKED)}]",
        f"not_checked = [{', '.join(toml_str(c) for c in NOT_CHECKED)}]",
        "likely = [",
    ]
    def masks_str(masks: list[str]) -> str:
        return "[" + ", ".join(toml_str(m) for m in masks) + "]"

    out += [f"  {{ id = {toml_str(a)}, name = {toml_str(n)}, masks = {masks_str(m)}, coverage = {c:.1f}"
            + (f", uncompared = {u}" if u else "") + " },"
            for a, n, m, c, u in likely]
    out += ["]", "", "[differs]", f"reason = {toml_str(DIFFERS_REASON)}", "entries = ["]
    out += [f"  {{ id = {toml_str(a)}, name = {toml_str(n)}, masks = {masks_str(m)}, issue = {c['issue']}, "
            f"cause = {toml_str(c['cause'])} }},"
            for a, n, m, c in differs]
    out += ["]", ""]
    stats = {
        "likely": len(likely),
        "differs": len(differs),
        "blocked": dict(blocked),
        "likely_per_family": dict(Counter(m for _, _, ms, _, _ in likely for m in ms)),
        "proven_per_family": {m: len(v) for m, v in proven.items()},
        "uncompared_builds": sum(u for *_, u in likely),
        "synthetic_per_family": dict(synth),
    }
    return "\n".join(out), stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail when the committed list is stale")
    ap.add_argument("--stats", action="store_true", help="print the counts")
    args = ap.parse_args()
    text, stats = compute()
    if args.stats:
        print(json.dumps(stats, indent=1, sort_keys=True))
    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT.relative_to(REPO)} is stale: run python3 tools/supported-devices/generate.py",
                  file=sys.stderr)
            return 1
        return 0
    if not args.stats:
        OUT.write_text(text)
        print(f"wrote {OUT.relative_to(REPO)}: {stats['likely']} likely, {stats['differs']} differs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
