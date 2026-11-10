# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Compare every captured ETS download of the defaults sweep with bussard
(epic #419, part 3 #422).

    uv run tools/ets-sweep/oracle.py [--filter SUBSTR,...] [--redo]
        [--captures DIR] [--work DIR] [--out FILE]

For each application with outcome `captured` in results/defaults.json: build
the scratch model (one device 1.1.1, the application at its defaults, no
links; oracle_model.py) and run scripts/campaign/95-offline-oracle.sh on the
row `1.1.1|<capture>|<product>|<application>`, with `state=fresh` on a
System 7 mask (`device_state`: the sim starts factory-fresh, #640). The verdict, coverage and the
region summary land in results/oracle.json, keyed by application id, with the
load-control verdict and its differences under `loadctl` (issue #419) and the
property description read verdict under `desc` (issue #1014; shown, never part
of the verdict). Nothing
touches a bus; the model and the oracle output live next to the capture under
captures/ (ignored), or under --work DIR/<application>/<variant> (a worktree
reads the main checkout's captures with --captures and writes nowhere under
them).

Each product file is imported once, into `.oracle-products/<sha>/` under
--work (else under the captures directory), and every row's model links that
import (`oracle_model.shared_import`): a row of the 152 MB ABB catalogue costs
seconds instead of minutes and 1.6 GB. --seed-models takes the model the
sweep imported next to a capture as that import.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import defaults  # noqa: E402
import apply_rows  # noqa: E402
import oracle_model  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ORACLE = REPO / "scripts" / "campaign" / "95-offline-oracle.sh"
OUT = HERE / "results" / "oracle.json"
CAPTURES = REPO / "captures" / "ets-sweep"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def load_control_summary(diff_json: Path) -> dict:
    """The load-control verdict of a row and its differences, from diff.json."""
    try:
        lc = json.loads(diff_json.read_text()).get("load_controls") or {}
    except (OSError, ValueError):
        return {"verdict": "missing"}
    out = {"verdict": lc.get("verdict", "missing")}
    if lc.get("reason"):
        out["reason"] = lc["reason"]
    for key in ("bussard_records", "ets_records", "difference_count", "notes"):
        if lc.get(key):
            out[key] = lc[key]
    if lc.get("differences"):
        out["differences"] = [{k: d.get(k) for k in ("object", "position", "kind", "event", "bussard_hex",
                                                     "ets_hex", "bussard_event", "ets_event")}
                              for d in lc["differences"]]
    return out


def description_summary(diff_json: Path) -> dict:
    """The property description read verdict of a row and its counts, from
    diff.json (issue #1014). Shown next to the row's verdict, never part of
    it: a read changes nothing on the device."""
    try:
        desc = json.loads(diff_json.read_text()).get("property_descriptions") or {}
    except (OSError, ValueError):
        return {"verdict": "missing"}
    out = {"verdict": desc.get("verdict", "missing")}
    for key in ("bussard_reads", "ets_reads"):
        if desc.get(key) is not None:
            out[key] = desc[key]
    for key in ("bussard_only", "ets_only", "not_compared"):
        if desc.get(key):
            out[key] = len(desc[key])
    return out


def catalog_row(run_dir: Path) -> dict:
    """The catalog row ETS added the device from, as the driver read it."""
    try:
        driver = json.loads((run_dir / "driver.json").read_text())
    except (OSError, ValueError):
        return {}
    return (driver.get("driver") or {}).get("catalog_add", {}).get("row") or {}


def catalog_row_name(run_dir: Path) -> str | None:
    """The catalog row's name, as the driver read it off the screen."""
    return catalog_row(run_dir).get("name")


def device_name(run_dir: Path, product: Path, app: str) -> str | None:
    """The device's name in the sweep's ETS project, which ETS writes as the
    friendly name of an IP-enabled device (bussard issues #455, #1023): the
    product text of the catalog row's order number
    (`oracle_model.project_device_name`), else the row's name as read."""
    return (oracle_model.project_device_name(product, app, catalog_row(run_dir).get("order"))
            or catalog_row_name(run_dir))


def variant_links(run_dir: Path) -> dict:
    """The links of a links-variant row: what ETS's object table showed after
    the driver linked the objects (objects.json in the run directory)."""
    try:
        return apply_rows.links_from_objects(json.loads((run_dir / "objects.json").read_text()))
    except (OSError, ValueError):
        return {}


def shared_root(captures: Path, work: Path | None) -> Path:
    """Where the per-product imports live: under --work, else next to the
    captures (both outside git)."""
    return (work or captures) / ".oracle-products"


# The masks whose load state ETS never reads before its download (System 7,
# dev/system7-spec.md): their rows name the device state (#488, #640).
SYSTEM7_MASKS = frozenset({"0700", "0701", "0705"})
# The runs that download into a device a previous download of the same sim
# already programmed (the synthetic run variants of #604); every other run
# starts on a factory-fresh knx-sim.
LOADED_RUNS = frozenset({"reload", "other-app"})


def device_state(mask: str, variant: str) -> str:
    """The `state=` row option of a capture (95-offline-oracle.sh, issue #488):
    `state=loaded` for a System 7 run into a programmed device (`reload`,
    `other-app`), `state=fresh` for any other System 7 run (the sim starts
    factory-fresh and ETS reads no System 7 load state, so knxtrace records
    none), empty for other masks. The sweep's rows (`row`) and the synthetic
    captures' rows (`synthetic/capture.py`) both take it from here (#640)."""
    if str(mask).upper() not in SYSTEM7_MASKS:
        return ""
    return "state=loaded" if variant in LOADED_RUNS else "state=fresh"


DEFAULT_IA = "1.1.1"


def entry_ia(entry: dict) -> str:
    """The address ETS gave the row's device: the sweep records it (`ia`), a
    coupler gets the line's coupler address 1.1.0 (#876); 1.1.1 otherwise."""
    return str(entry.get("ia") or DEFAULT_IA)


def row(app: str, capture: Path, product: Path, mask: str, variant: str = "plain-defaults",
        ia: str = DEFAULT_IA, keyring: Path | None = None) -> str:
    """The oracle row of a sweep capture: the device at the address ETS gave
    it (1.1.1 unless `ia`), no note, no recorded coverage, the device state
    of a System 7 mask (`device_state`) and, for a Data Secure capture, the
    keyring that decodes it (`keyring=`, #423)."""
    options = " ".join(o for o in (device_state(mask, variant), f"keyring={keyring}" if keyring else "") if o)
    return "|".join([ia, str(capture), str(product), app, "", "", options]).rstrip("|")


# The oracle's variants beyond the sweep's (`defaults.VARIANTS`): the Data
# Secure variant (#423), whose captures secure.py writes under
# `<app>/secure-defaults/` and whose outcomes are results/secure.json.
SECURE = "secure"


def variant_run_dir(variant: str) -> str:
    """The run directory name of a variant under `<captures>/<app>/`."""
    import secure

    return secure.VARIANT if variant == SECURE else variant


def variant_results(variant: str) -> Path:
    """The outcome manifest the oracle reads for a variant."""
    import secure

    return secure.RESULTS if variant == SECURE else defaults.results_path(variant)


def keyring_password() -> str:
    """The password of a vendor secure run's keyring export: the sweep's
    project password (secure.py exports under it), from the environment."""
    import secure

    pw = os.environ.get(secure.PASSWORD_ENV, "")
    if not pw:
        raise RuntimeError(f"the secure variant needs ${secure.PASSWORD_ENV} (the keyring's password)")
    return pw


def import_key_store(model: Path, keyring: Path, password: str) -> None:
    """The model's key store `bussard.keys`, imported from the run's keyring,
    so bussard plans the security object's writes (PID 5, 54, 61) with the
    keys ETS used, as the syn-secure row does (#858, `synthetic/capture.py`
    `secure_model`)."""
    (model / "bussard.keys").unlink(missing_ok=True)
    env = {k: v for k, v in os.environ.items() if k not in ("BUSSARD_KEYRING", "BUSSARD_DIR")}
    r = subprocess.run([str(oracle_model.BUSSARD), "--dir", str(model), "keys", "import", str(keyring)],
                       capture_output=True, text=True, timeout=300,
                       env={**env, "BUSSARD_NO_DOTENV": "1", "BUSSARD_KEYRING_PASSWORD": password})
    if r.returncode:
        raise RuntimeError("keys import failed: " + ANSI.sub("", r.stderr + r.stdout).strip()[-300:])


def run_row(app: str, entry: dict, captures: Path, work: Path | None, seed: bool = False,
            variant: str = "plain-defaults", links: dict | None = None) -> dict:
    run_dir = captures / app / variant_run_dir(variant)
    work_dir = work / app / variant_run_dir(variant) if work else run_dir
    capture = run_dir / "ets.pcapng"
    product = defaults.product_path(entry["file"])
    # The product file is imported once and shared by every row of it; with
    # --seed-models the model the sweep imported for this row stands in for
    # the import.
    seed_dir = run_dir / "model" if seed else None
    shared = oracle_model.shared_import(shared_root(captures, work), product, seed=seed_dir)
    ia = entry_ia(entry)
    model = oracle_model.build(work_dir / "model", product, app, ia=ia, mask=entry.get("mask", ""),
                               friendly_name=device_name(run_dir, product, app), shared=shared, links=links)
    env = {**os.environ, "BUSSARD_NO_DOTENV": "1"}
    keyring = None
    if variant == SECURE:
        keyring = run_dir / "project.knxkeys"
        if not keyring.is_file():
            return {"verdict": "no-keyring", "ia": ia}
        pw = keyring_password()
        import_key_store(model, keyring, pw)
        env["BUSSARD_KEYRING_PASSWORD"] = pw
    r = subprocess.run(["bash", str(ORACLE), "--dir", str(model), "--out", str(work_dir / "oracle"),
                        "--row", row(app, capture, product, entry.get("mask", ""), variant, ia, keyring)],
                       capture_output=True, text=True, timeout=1800, env=env)
    text = ANSI.sub("", r.stdout + r.stderr)
    summary = next((l for l in text.splitlines() if l.startswith(ia + " ")), "")
    m = re.match(re.escape(ia) + r"\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)", summary)
    out = {"exit": r.returncode, "summary": summary.strip(), "ia": ia}
    if m:
        out.update({"system": m.group(1), "verdict": m.group(2), "coverage": m.group(3), "confirmed": m.group(4),
                    "regions": m.group(5).strip()})
        # The oracle judges memory only unless a row asks for property parity;
        # an ETS-only property write (the KNXnet/IP object of an IP-enabled
        # device, ALLinBOX 1612) is a write bussard would miss: report it.
        if out["verdict"] == "identical" and "props=differs" in out["regions"]:
            out["verdict"] = "differs-props"
    else:
        out["verdict"] = "oracle-error"
        out["tail"] = text.strip().splitlines()[-6:]
    out["loadctl"] = load_control_summary(work_dir / "oracle" / ia / "diff.json")
    out["desc"] = description_summary(work_dir / "oracle" / ia / "diff.json")
    return out


def desc_text(desc: dict | None) -> str:
    """The `desc=` column of the progress line (issue #1014): `desc=ok`,
    `desc=differs(+1/-2)` (bussard-only/ETS-only reads), `desc=none`."""
    if not desc:
        return "desc=-"
    v = desc.get("verdict", "missing")
    if v == "identical":
        return "desc=ok"
    if v == "differs":
        return "desc=differs(+%d/-%d)" % (desc.get("bussard_only", 0), desc.get("ets_only", 0))
    return "desc=" + v


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter", default="")
    ap.add_argument("--redo", action="store_true")
    ap.add_argument("--captures", type=Path, default=CAPTURES, help="the sweep captures (default %(default)s)")
    ap.add_argument("--work", type=Path, help="write the models and oracle output here, not next to the captures")
    ap.add_argument("--out", type=Path, help=f"the results file (default {OUT}, results/oracle-<variant>.json for a variant)")
    ap.add_argument("--seed-models", action="store_true",
                    help="take the model the sweep imported next to a capture as the product import instead of importing (once per product file)")
    ap.add_argument("--defaults", type=Path, help="the sweep results (default: the variant's, results/defaults.json)")
    ap.add_argument("--variant", default="plain-defaults", choices=sorted(defaults.VARIANTS) + [SECURE],
                    help="links: the links variant (#478); each row's model gets the links ETS showed (objects.json). "
                         "secure: the Data Secure variant (#423, results/secure.json); each row decodes with its "
                         "keyring and plans with a key store imported from it ($ETS_SWEEP_PROJECT_PASSWORD)")
    args = ap.parse_args()
    args.defaults = args.defaults or variant_results(args.variant)
    args.out = args.out or (OUT if args.variant == "plain-defaults" else OUT.with_name(f"oracle-{args.variant}.json"))
    res = json.loads(args.defaults.read_text())
    out = json.loads(args.out.read_text()) if args.out.exists() else {}
    wanted = [w.lower() for w in args.filter.split(",") if w]
    for app, entry in sorted(res.items()):
        if entry["outcome"] != "captured":
            continue
        if wanted and not any(w in (app + " " + (entry.get("name") or "")).lower() for w in wanted):
            continue
        if app in out and not args.redo and out[app].get("capture_when") == entry["when"]:
            continue
        try:
            v = run_row(app, entry, args.captures, args.work, args.seed_models, variant=args.variant,
                        links=variant_links(args.captures / app / args.variant) if args.variant == "links" else None)
        except Exception as exc:  # noqa: BLE001 - recorded, the next row runs
            v = {"verdict": "oracle-error", "error": str(exc)[:400]}
        v.update({"name": entry.get("name"), "mask": entry.get("mask"), "capture_when": entry["when"],
                  "when": datetime.now(timezone.utc).isoformat()})
        out[app] = v
        args.out.write_text(json.dumps(dict(sorted(out.items())), indent=1, ensure_ascii=False) + "\n")
        lc = v.get("loadctl", {}).get("verdict", "-")
        desc = desc_text(v.get("desc"))
        print(f"{v['verdict']:14} {lc:14} {desc:18} {v.get('coverage', ''):>7} {entry.get('mask')} {app} "
              f"{v.get('regions', '')[:70]}", flush=True)
    counts: dict[str, int] = {}
    lc_counts: dict[str, int] = {}
    desc_counts: dict[str, int] = {}
    for v in out.values():
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
        lc = v.get("loadctl", {}).get("verdict", "missing")
        lc_counts[lc] = lc_counts.get(lc, 0) + 1
        dv = (v.get("desc") or {}).get("verdict", "missing")
        desc_counts[dv] = desc_counts.get(dv, 0) + 1
    print("oracle:", counts)
    print("load control:", lc_counts)
    print("description reads (not part of the verdict):", desc_counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
