# /// script
# requires-python = ">=3.11"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Capture a synthetic product with ETS and commit-ready files (epic #596, step 5).

    uv run tools/ets-sweep/synthetic/capture.py <product> [--no-ets] [--sim-build SHA]

For `tests-support/synthetic-products/<product>/` it runs the whole flow:

  1. render and zip (`generate.py --zip`), sign in the VM (`sign.py`) and record
     the signed id (`generate.py --signed-id`);
  2. import the signed file into ETS's catalogue (`/ets/catalog_import`, as
     `catalog.py` does) and require `/ets/catalog_search <order number>` to
     list it;
  3. the `defaults` download into knx-sim in the VM (`calibrate.calibrate_one`,
     the sweep's run directory `captures/ets-sweep/<signed id>/plain-defaults/`);
  4. copies the capture to `captures/synthetic/<product>/defaults/`:
     `ets.pcapng`, `driver.json`, `ops.txt`, `requests.txt` (`distil.py`),
     `image.json` (`knxtrace image`: the segments and octets ETS wrote) and a
     `sim.yaml` for a loopback knx-sim with the stub-zipped product;
  5. the oracle row of the committed files (the product's `xml/`, zipped with
     the stub master by `95-offline-oracle.sh`), its verdict and coverage
     written into `captures/synthetic/rows.txt`, then `--check` over the file;
  6. the entry in `captures/synthetic/manifest.json`: ETS version, knx-sim
     build, the `xml/` digest (`generate.py`'s, as in `signed.toml`), the
     signed id, the date, the oracle verdict and coverage.

`--no-ets` skips steps 1 to 3 and reuses the sweep's run directory (the ETS
version, simulator build and date come from `--ets-version`, `--sim-build`
and `--captured`, else from the manifest entry it replaces). `--sim-build`
names the commit `winbuild-knx-sim.sh` built the VM's `knx-sim.exe` from;
the default is the sidecar `knx-sim.exe.git` that script writes. bussard must
be built (`target/debug/bussard` or `BUSSARD_BIN`). Nothing here talks to a
real gateway: ETS downloads into the sim inside the VM, and the oracle runs
`flash --dry-run`.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import calibrate  # noqa: E402
import distil  # noqa: E402

REPO = HERE.parents[2]
CATALOGUE = REPO / "tests-support" / "synthetic-products"
OUT = REPO / "captures" / "synthetic"
ROWS = OUT / "rows.txt"
MANIFEST = OUT / "manifest.json"
MODEL = OUT / "model"
ORACLE = REPO / "scripts" / "campaign" / "95-offline-oracle.sh"
SIM_EXE = REPO / "knx-sim" / "target-win" / "x86_64-pc-windows-gnu" / "release" / "knx-sim.exe"
ETS_EXE = r"C:\Program Files (x86)\ETS6\ETS6N.exe"
VARIANT = "defaults"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

sys.path.insert(0, str(CATALOGUE))
import generate  # noqa: E402


def run(cmd: list[str], **kw) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise SystemExit(f"{' '.join(cmd)} failed:\n{(r.stdout + r.stderr)[-1500:]}")
    return r.stdout


def xml_sha256(product: str) -> str:
    return generate.xml_digest(generate.committed(product))


def rendered_app(product: str) -> str:
    apps = sorted((CATALOGUE / product / "xml").glob("*/*_A-*.xml"))
    if len(apps) != 1:
        raise SystemExit(f"{product}: expected one application in xml/, found {len(apps)}")
    return apps[0].stem


def sign(product: str) -> tuple[Path, str]:
    """Render, zip, sign in the VM, record the signed id; returns the signed
    file under a content-addressed name (the sim and the VM's product folder
    cache files by name) and the signed application id."""
    gen = [sys.executable, str(CATALOGUE / "generate.py")]
    run(gen + ["--zip", product])
    build = CATALOGUE / product / "build"
    run(["uv", "run", str(HERE / "sign.py"), str(build / f"{product}.knxprod")])
    signed = build / f"{product}-signed.knxprod"
    run(gen + [product, "--signed-id", str(signed)])
    sid = tomllib.loads((CATALOGUE / product / "signed.toml").read_text())["application_id"]
    digest = hashlib.sha256(signed.read_bytes()).hexdigest()[:8]
    named = build / f"{product}-signed-{digest}.knxprod"
    shutil.copyfile(signed, named)
    return named, sid


def ets_import(c, signed: Path, order: str) -> dict:
    """Import into ETS's catalogue and find the order number."""
    import catalog
    import vm

    remote = f"{catalog.REMOTE_PRODUCTS}\\{signed.name}"
    c.open_sftp().put(str(signed), remote.replace("\\", "/"))
    r = vm.driver(c, "POST", "/ets/catalog_import", {"path": remote, "timeout": 600}, timeout=660)
    found = vm.driver(c, "POST", "/ets/catalog_search", {"term": order}, timeout=180)
    rows = [row for row in found.get("rows", []) if order in json.dumps(row, ensure_ascii=False)]
    if not rows:
        # The search flow OCRs the result pane magnified, which came back empty
        # on 2026-10-30 although the row was on screen; `catalog_rows` reads the
        # same pane (left filtered by the search) at native size.
        listed = vm.driver(c, "POST", "/ets/catalog_rows", {}, timeout=180)
        rows = [row for row in listed.get("rows", []) if row.get("order") == order]
    if not rows:
        raise SystemExit(f"ETS does not list {order} after the import: {json.dumps(r, ensure_ascii=False)[:600]}")
    return {"import": r.get("outcome"), "message": r.get("message"), "catalog_row": rows[0]}


def ets_version(c) -> str:
    import vm

    # ProductVersion reads "6.4.1 [<date>|<sha>|<branch>]", FileVersion "6.4.8718".
    info = "(Get-Item '" + ETS_EXE + "').VersionInfo"
    code, out = vm.run(c, f'powershell -NoProfile -Command "{info}.ProductVersion; {info}.FileVersion"')
    parts = out.split()
    if code != 0 or len(parts) < 2:
        return "unknown"
    return f"{parts[0]} build {parts[-1]}"


def sim_build(arg: str | None) -> str:
    if arg:
        return arg
    side = SIM_EXE.with_name("knx-sim.exe.git")
    try:
        return side.read_text().strip()
    except OSError:
        raise SystemExit(f"no {side}: pass --sim-build, or rebuild with tools/ets-sweep/winbuild-knx-sim.sh") from None


def sim_yaml(product: str, app: str) -> str:
    """A loopback knx-sim for the capture's device, on the stub-zipped product."""
    prod = os.path.relpath(CATALOGUE / product / "build" / f"{product}.knxprod", OUT / product / VARIANT)
    return (
        f"# knx-sim device of the ETS capture next to this file (epic #596), on loopback.\n"
        f"# The product is the committed xml/ zipped with the stub master:\n"
        f"#   uv run tests-support/synthetic-products/generate.py --zip {product}\n"
        f"# The application is the rendered id; the signed one ETS imported differs\n"
        f"# only in its fingerprint, which never reaches the wire.\n"
        f"gateway:\n  host: 127.0.0.1\n  port: 3672\n  tunnel_address: 1.1.254\n"
        f"devices:\n- address: 1.1.1\n  knxprod: {prod}\n  application: {app}\n"
        f"  initial_state: unloaded\n  lsm_access: property\n"
    )


def copy_capture(product: str, sid: str, app: str) -> Path:
    src = calibrate.run_dir(sid)
    dst = OUT / product / VARIANT
    dst.mkdir(parents=True, exist_ok=True)
    rel = dst.relative_to(REPO).as_posix()
    shutil.copyfile(src / "ets.pcapng", dst / "ets.pcapng")
    shutil.copyfile(src / "driver.json", dst / "driver.json")
    ops = (src / "ops.txt").read_text().replace(str(src / "ets.pcapng"), f"{rel}/ets.pcapng")
    (dst / "ops.txt").write_text(ops)
    reqs = distil.requests(dst / "ets.pcapng")
    (dst / "requests.txt").write_text(distil.render(reqs, f"{rel}/ets.pcapng"))
    (dst / "sim.yaml").write_text(sim_yaml(product, app))
    write_image(dst, rel)
    return dst


def write_image(dst: Path, rel: str) -> None:
    """`image.json`: the segments ETS allocated and the octets it wrote, as
    `knxtrace image` composes them from the capture. knx-sim's calibration
    replay (`knx-sim/tests/synthetic_calibration.rs`) compares the device it
    replayed `requests.txt` into against this, without running Python."""
    knxtrace = REPO / "tools" / "knxtrace" / "knxtrace.py"
    with tempfile.TemporaryDirectory() as tmp:
        run([sys.executable, str(knxtrace), "image", str(dst / "ets.pcapng"), "--device", "1.1.1", "--out", tmp])
        index = json.loads((Path(tmp) / "regions.json").read_text())
        regions = [{"start": r["start"], "hex": (Path(tmp) / r["file"]).read_bytes().hex()} for r in index["regions"]]
    segments = [{"object": a["object"], "base": a["base"], "size": a["size"]}
                for a in index["allocations"] if a.get("kind") == "rel-segment" and isinstance(a.get("base"), int)]
    lines = [
        "{",
        f'"about": "The memory ETS allocated and wrote in {rel}/ets.pcapng (knxtrace image), written by '
        'tools/ets-sweep/synthetic/capture.py for knx-sim/tests/synthetic_calibration.rs.",',
        '"segments": [',
        ",\n".join("  " + json.dumps(s) for s in sorted(segments, key=lambda s: s["object"])),
        "],",
        '"regions": [',
        ",\n".join("  " + json.dumps(r) for r in regions),
        "]",
        "}",
    ]
    (dst / "image.json").write_text("\n".join(lines) + "\n")


def oracle_row(product: str, app: str, coverage: str = "", options: str = "", why: str = "") -> str:
    rel = (OUT / product / VARIANT).relative_to(REPO).as_posix()
    xml = (CATALOGUE / product / "xml").relative_to(REPO).as_posix()
    note = f"{product} {VARIANT}{': ' + why if why else ''}"
    return f"1.1.1|{rel}/ets.pcapng|{xml}|{app}|{note}|{coverage}|{options}".rstrip("|")


def run_oracle(args: list[str]) -> tuple[int, str]:
    """The oracle script over a scratch copy of the committed model."""
    with tempfile.TemporaryDirectory() as tmp:
        model = Path(tmp) / "model"
        shutil.copytree(MODEL, model)
        r = subprocess.run(["bash", str(ORACLE), *args, "--dir", str(model), "--out", str(Path(tmp) / "out")],
                           capture_output=True, text=True, cwd=REPO, timeout=1800,
                           env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
        out = ANSI.sub("", r.stdout + r.stderr)
        diff = Path(tmp) / "out" / "1.1.1" / "diff.json"
        if diff.exists():
            out += "\n@loadctl " + json.dumps(calibrate.oracle.load_control_summary(diff))
        return r.returncode, out


def oracle_verdict(product: str, app: str) -> dict:
    code, text = run_oracle(["--row", oracle_row(product, app)])
    # The summary table is the last line that starts with the device.
    line = next((l for l in reversed(text.splitlines()) if l.startswith("1.1.1 ")), "")
    m = re.match(r"1\.1\.1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)", line)
    if not m:
        raise SystemExit(f"oracle row of {product} gave no summary:\n{text[-1500:]}")
    lc = next((json.loads(l[len("@loadctl "):]) for l in text.splitlines() if l.startswith("@loadctl ")), {})
    return {"verdict": m.group(2), "coverage": m.group(3), "regions": m.group(5).strip(),
            "loadctl": lc.get("verdict")}


def load_manifest() -> list[dict]:
    try:
        return json.loads(MANIFEST.read_text())["captures"]
    except (OSError, ValueError, KeyError):
        return []


def write_manifest(entries: list[dict]) -> None:
    entries = sorted(entries, key=lambda e: (e["product"], e["variant"]))
    lines = ",\n".join("  " + json.dumps(e, ensure_ascii=False) for e in entries)
    MANIFEST.write_text(
        "{\n"
        '"about": "ETS captures of the synthetic products (epic #596), one entry per product and variant. '
        'Written by tools/ets-sweep/synthetic/capture.py; xml_sha256 is generate.py\'s digest of the committed '
        'xml/ (as in signed.toml). A product whose xml/ no longer matches is re-captured '
        '(crates/bussard-cli/tests/it/synthetic_captures.rs fails until it is).",\n'
        f'"captures": [\n{lines}\n]\n}}\n'
    )


def row_options(oracle: dict) -> str:
    """The row's `expect=` and `loadctl=` from the recorded verdicts, so `--check`
    holds a product to what its capture showed: a `differs` row is the evidence
    of an open bug and stays green until the fix changes the verdict (#596
    step 4). `identical` is the script's default and is not written."""
    opts = []
    if oracle.get("verdict") in ("differs", "not-comparable"):
        opts.append(f"expect={oracle['verdict']}")
    if oracle.get("loadctl") in ("identical", "differs"):
        opts.append(f"loadctl={oracle['loadctl']}")
    return " ".join(opts)


def write_rows(entries: list[dict]) -> None:
    head = (
        "# Offline oracle rows of the synthetic captures (epic #596), for\n"
        "#   scripts/campaign/95-offline-oracle.sh --rows captures/synthetic/rows.txt --check\n"
        "# run from the repository root. Written by tools/ets-sweep/synthetic/capture.py\n"
        "# from manifest.json. The product field is the committed xml/ directory,\n"
        "# zipped with the stub master by the script; the application is the rendered\n"
        "# id (the signed fingerprint never reaches the wire).\n"
        "#@ --dir captures/synthetic/model\n"
    )
    rows = []
    for e in sorted(entries, key=lambda e: (e["product"], e["variant"])):
        coverage = e["oracle"]["coverage"].rstrip("%")
        # A not-comparable row (bussard refused the product) has no coverage.
        coverage = coverage if re.fullmatch(r"[0-9.]+", coverage) else ""
        why = ""
        if e["oracle"]["verdict"] == "not-comparable":
            issues = tomllib.loads((CATALOGUE / e["product"] / "product.toml").read_text())["doc"]["issues"]
            why = "bussard refuses the product, " + ", ".join(f"#{n}" for n in issues)
        rows.append(oracle_row(e["product"], e["application"], coverage, row_options(e["oracle"]), why))
    ROWS.write_text(head + "\n".join(rows) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("product")
    ap.add_argument("--no-ets", action="store_true", help="reuse the sweep's run directory")
    ap.add_argument("--sim-build", help="the commit knx-sim.exe in the VM was built from")
    ap.add_argument("--ets-version", help="with --no-ets: the ETS version of the reused capture")
    ap.add_argument("--captured", help="with --no-ets: the date of the reused capture (YYYY-MM-DD)")
    args = ap.parse_args()
    product = args.product
    spec = tomllib.loads((CATALOGUE / product / "product.toml").read_text())
    order = spec["product"]["order_number"]
    app = rendered_app(product)
    entries = [e for e in load_manifest() if not (e["product"] == product and e["variant"] == VARIANT)]
    previous = next((e for e in load_manifest() if e["product"] == product and e["variant"] == VARIANT), {})
    if args.no_ets:
        sid = tomllib.loads((CATALOGUE / product / "signed.toml").read_text())["application_id"]
        ets = args.ets_version or previous.get("ets", "unknown")
        build = args.sim_build or previous.get("knx_sim", "unknown")
        when = args.captured or previous.get("captured")
        result = json.loads((calibrate.run_dir(sid) / "driver.json").read_text())
    else:
        import vm

        build = sim_build(args.sim_build)
        signed, sid = sign(product)
        c = vm.connect()
        imported = ets_import(c, signed, order)
        print(f"ETS import: {imported['import']}, catalogue row {imported['catalog_row']}")
        ets = ets_version(c)
        result = calibrate.calibrate_one(signed, sid, order, True, Path(tempfile.mkdtemp()))
        print(f"ETS download: {result.get('outcome')} ets={result.get('ets')} ops={result.get('ops')} "
              f"loaded={result.get('loaded_objects')}; signed-product oracle: {result.get('oracle', {}).get('summary')}")
        when = datetime.date.today().isoformat()
        if result.get("outcome") != "captured":
            raise SystemExit(f"ETS did not complete the download: {result}")
    dst = copy_capture(product, sid, app)
    verdict = oracle_verdict(product, app)
    requests = sum(1 for l in (dst / "requests.txt").read_text().splitlines() if l and not l.startswith("#"))
    entry = {
        "product": product, "variant": VARIANT, "order_number": order, "application": app, "signed_id": sid,
        "xml_sha256": xml_sha256(product), "ets": ets, "knx_sim": build, "captured": when,
        "ops": result.get("ops"), "requests": requests,
        "oracle": {"verdict": verdict["verdict"], "coverage": verdict["coverage"], "loadctl": verdict["loadctl"]},
    }
    entries.append(entry)
    write_manifest(entries)
    write_rows(entries)
    code, text = run_oracle(["--rows", str(ROWS.relative_to(REPO)), "--check"])
    print(f"{product}/{VARIANT}: oracle {verdict['verdict']} coverage {verdict['coverage']} "
          f"loadctl {verdict['loadctl']} ({verdict['regions']}); rows --check: {'passed' if code == 0 else 'FAILED'}")
    if code != 0:
        print(text[-2000:])
    return code


if __name__ == "__main__":
    sys.exit(main())
