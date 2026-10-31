# /// script
# requires-python = ">=3.11"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Capture a synthetic product with ETS and commit-ready files (epic #596, step 5).

    uv run tools/ets-sweep/synthetic/capture.py <product> [--no-ets] [--sim-build SHA]
    uv run tools/ets-sweep/synthetic/capture.py <product> --variant <name> [--sim-build SHA]

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

Before signing, it refuses a product whose committed `xml/` differs from a
manifest entry of it unless `[application] version` is above the one in that
entry's signed id: ETS keeps the application it imported first under the
same order number and version (#650). After the download it checks that the
capture wrote the spec's program version and stops before copying otherwise.
A re-capture recomputes the entry's row options and keeps the hand-set ones
it cannot derive (`carried_options`).

`--variant <name>` captures a run variant instead of the `defaults` download
(#604, "Run variants"; `VARIANTS` below): the same product downloaded another
way, in one knx-sim process so ETS sees the device a step before left
(`no-ga`, `links`, `reload`, `other-app`, `partial`, `calc-input`). It
writes `captures/synthetic/<product>/<variant>/` with the capture of the
variant's last download, the earlier downloads as `base.pcapng` and
`base-requests.txt`, and the bussard model template the row plans with
(`model/`) where the variant links objects or changes a parameter; its own
row and manifest entry.

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
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import calibrate  # noqa: E402
import distil  # noqa: E402
import oracle  # noqa: E402

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


def lsm_access(mask: str) -> str:
    """The sim's load-state machine for a mask: memory-mapped on 0700 and 0701,
    where ETS drives the 11-octet record at 0x0104, property (PID 5) otherwise
    (dev/system7-spec.md section 5)."""
    return "memory" if mask in ("0700", "0701") else "property"


def sim_yaml(product: str, app: str, mask: str = "07B0", variant: str = VARIANT, base: bool = False) -> str:
    """A loopback knx-sim for the capture's device, on the stub-zipped product.
    With `base` the sim first replays `base.pcapng` next to it: the device as
    the variant's earlier downloads left it, before the captured one."""
    prod = os.path.relpath(CATALOGUE / product / "build" / f"{product}.knxprod", OUT / product / variant)
    replay = ("# The device starts as the variant's earlier downloads left it:\nreplay:\n- base.pcapng\n"
              if base else "")
    # The variant's own device options (VARIANTS "sim"), e.g. master_reset (#611).
    options = "".join(f"  {k}: {v}\n" for k, v in VARIANTS.get(variant, {}).get("sim", {}).items())
    return (
        f"# knx-sim device of the ETS capture next to this file (epic #596), on loopback.\n"
        f"# The product is the committed xml/ zipped with the stub master:\n"
        f"#   uv run tests-support/synthetic-products/generate.py --zip {product}\n"
        f"# The application is the rendered id; the signed one ETS imported differs\n"
        f"# only in its fingerprint, which never reaches the wire.\n"
        f"gateway:\n  host: 127.0.0.1\n  port: 3672\n  tunnel_address: 1.1.254\n"
        f"devices:\n- address: 1.1.1\n  knxprod: {prod}\n  application: {app}\n"
        f"  initial_state: unloaded\n  lsm_access: {lsm_access(mask)}\n{options}{knxnet_sim(product)}{replay}"
    )


# -------------------------------- IP-enabled TP hardware (#604 row 34, #455)
# A product whose hardware has a KNX IP interface built in (`[product]
# ip_enabled`, the application's AdditionalAddressesCount) gets the KNXnet/IP
# parameter object in its knx-sim device, as sweep.py gives one (ETS aborts
# without it), and its row plans against a model whose device file holds the
# `[knxnet]` table of the sweep project (oracle_model.knxnet_table: DHCP, the
# product text as the friendly name, the highest addresses of line 1.1), since
# bussard refuses to plan the download without one.

def tunnel_count(product: str) -> int:
    """The product's `additional_addresses_count`, 0 for a plain device."""
    return int(generate_spec(product)["application"].get("additional_addresses_count", 0))


def knxnet_sim(product: str) -> str:
    """The `knxnet:` block of the loopback sim device, room for 16 tunnels as
    in sweep.py; empty for a plain device."""
    return "  knxnet:\n    tunnel_slots: 16\n" if tunnel_count(product) else ""


def knxnet_model(product: str, dst: Path) -> str:
    """Writes `model/` next to an IP-enabled product's capture and returns the
    row option naming it (`dir=`); empty for a plain device."""
    count = tunnel_count(product)
    if not count:
        return ""
    import oracle_model

    model = dst / "model"
    (model / "devices").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(MODEL / "bussard.toml", model / "bussard.toml")
    name = generate_spec(product)["product"]["text"]
    (model / "devices" / "1.1.1.toml").write_text(
        f'# The device of {product}: the [knxnet] table of the sweep project (capture.py, #455).\n'
        f'address = "1.1.1"\nname = "{product}"\n' + oracle_model.knxnet_table("1.1.1", count, name))
    return f"dir={dst.relative_to(REPO).as_posix()}/model"


def copy_capture(product: str, sid: str, app: str, mask: str = "07B0") -> Path:
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
    (dst / "sim.yaml").write_text(sim_yaml(product, app, mask))
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


def device_state(product: str, variant: str = VARIANT) -> str:
    """The row's `state=` for a System 7 product (`oracle.device_state`, the
    function the sweep's rows use too, #640): `state=fresh` where the sim
    starts unloaded (`sim_yaml`), since ETS reads no load state before a
    System 7 download and the oracle must plan as on a fresh device (#488);
    `state=loaded` for the `reload` and `other-app` variants."""
    try:
        mask = tomllib.loads((CATALOGUE / product / "product.toml").read_text())["application"]["mask"]
    except (OSError, KeyError, ValueError):
        return ""
    return oracle.device_state(str(mask), variant)


def oracle_row(product: str, app: str, coverage: str = "", options: str = "", why: str = "",
               variant: str = VARIANT, extra: str = "") -> str:
    """The row of a capture. `extra` are the run variant's own options
    (`variant_options`); a variant that names the device state replaces the
    product's `state=fresh`."""
    rel = (OUT / product / variant).relative_to(REPO).as_posix()
    xml = (CATALOGUE / product / "xml").relative_to(REPO).as_posix()
    note = f"{product} {variant}{': ' + why if why else ''}"
    state = "" if "state=" in extra or "run=" in extra else device_state(product, variant)
    options = " ".join(o for o in (options, extra, state) if o)
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
            # The read-confirmed octets (a 0701 download into a device that
            # holds the image read-compares instead of writing, #384).
            try:
                conf = json.loads(diff.read_text()).get("confirmed") or {}
            except ValueError:
                conf = {}
            if conf.get("octets"):
                out += "\n@confirmed " + str(conf.get("verdict"))
        return r.returncode, out


def oracle_verdict(product: str, app: str, variant: str = VARIANT, extra: str = "") -> dict:
    code, text = run_oracle(["--row", oracle_row(product, app, variant=variant, extra=extra)])
    # The summary table is the last line that starts with the device.
    line = next((l for l in reversed(text.splitlines()) if l.startswith("1.1.1 ")), "")
    m = re.match(r"1\.1\.1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)", line)
    if not m:
        raise SystemExit(f"oracle row of {product} gave no summary:\n{text[-1500:]}")
    lc = next((json.loads(l[len("@loadctl "):]) for l in text.splitlines() if l.startswith("@loadctl ")), {})
    confirmed = next((l.split()[1] for l in text.splitlines() if l.startswith("@confirmed ")), None)
    out = {"verdict": m.group(2), "coverage": m.group(3), "regions": m.group(5).strip(),
           "loadctl": lc.get("verdict")}
    if confirmed:
        out["confirmed"] = confirmed
    props = props_verdict(out["regions"])
    if props:
        out["props"] = props
    return out


PROPS_REGION = re.compile(r"\bprops=(ok|differs|n/c)\b")


def props_verdict(regions: str) -> str | None:
    """The property-write parity of a row from the summary's regions
    (`props=ok(..)`, `props=differs(..)`, `props=n/c(..)`), as the `props=`
    row option names it; None when the row reports none."""
    m = PROPS_REGION.search(regions)
    return {"ok": "identical", "differs": "differs", "n/c": "not-comparable"}[m.group(1)] if m else None


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


def row_options(verdicts: dict) -> str:
    """The row's `expect=`, `confirmed=`, `loadctl=` and `props=` from the
    recorded verdicts, so `--check` holds a product to what its capture
    showed: a `differs` row is the evidence of an open bug and stays green
    until the fix changes the verdict (#596 step 4). An identical headline or
    property parity is the script's default and is not written."""
    opts = []
    if verdicts.get("verdict") in ("differs", "not-comparable"):
        opts.append(f"expect={verdicts['verdict']}")
    if verdicts.get("confirmed") in ("identical", "differs", "not-comparable"):
        opts.append(f"confirmed={verdicts['confirmed']}")
    if verdicts.get("loadctl") in ("identical", "differs"):
        opts.append(f"loadctl={verdicts['loadctl']}")
    if verdicts.get("props") in ("differs", "not-comparable"):
        opts.append(f"props={verdicts['props']}")
    return " ".join(opts)


# The row options capture.py derives on every capture: from the verdicts
# (`row_options`), the device state (`device_state`), the variant
# (`variant_options`) and an IP-enabled product's model (`knxnet_model`).
DERIVED_OPTIONS = frozenset({"expect", "confirmed", "loadctl", "props", "state", "dir", "run", "base", "lsm"})


def carried_options(derived: str, previous: str) -> str:
    """A re-captured entry's `row_options`: the ones this capture derived,
    then those of the entry it replaces that capture.py cannot derive (set by
    hand, e.g. `scope=` or `phase=`). A derived option of the old entry (a
    hand-set `props=differs`, say) is dropped: the new verdicts decide it."""
    kept = [w for w in previous.split() if w.split("=", 1)[0] not in DERIVED_OPTIONS]
    return " ".join(o for o in (derived, *kept) if o)


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
        if e["oracle"]["verdict"] == "not-comparable" and e["oracle"].get("confirmed"):
            why = "ETS read-compared the image the device held and wrote no memory, #384"
        elif e["oracle"]["verdict"] == "not-comparable":
            issues = tomllib.loads((CATALOGUE / e["product"] / "product.toml").read_text())["doc"]["issues"]
            why = "bussard refuses the product, " + ", ".join(f"#{n}" for n in issues)
        rows.append(oracle_row(e["product"], e["application"], coverage, row_options(e["oracle"]), why,
                               e["variant"], e.get("row_options", "")))
    ROWS.write_text(head + "\n".join(rows) + "\n")


# ---------------------------------------------------------------------------
# Stale catalogue imports (#650). ETS keeps the application it imported first
# under an order number and application version: importing changed XML under
# the same version reports "imported" and the download uses the old program.
# A re-capture after an XML change therefore needs `[application] version`
# above every version the product was captured with (the version octet of the
# manifest's signed id), and a capture is checked to carry the spec's version.
# ---------------------------------------------------------------------------

APP_ID = re.compile(r"_A-([0-9A-F]{4})-([0-9A-F]{2})-", re.IGNORECASE)


def app_version(app_id: str) -> int | None:
    """The application version octet of an application id
    (`M-00FA_A-280F-11-48D6` gives 0x11); None for no id."""
    m = APP_ID.search(app_id or "")
    return int(m.group(2), 16) if m else None


def recapture_refusal(product: str, digest: str, version: int, entries: list[dict]) -> str | None:
    """Why a capture of `product` at `digest` and application `version` would
    test a stale import, or None. Stale: a manifest entry of the product was
    captured from other XML under this version or a higher one, so ETS's
    catalogue may hold that XML under the version the spec names."""
    mine = [(e, app_version(e.get("signed_id", ""))) for e in entries if e.get("product") == product]
    recorded = [v for _, v in mine if v is not None]
    stale = [e for e, v in mine if v is not None and v >= version and e.get("xml_sha256") != digest]
    if not stale:
        return None
    newest = max(recorded)
    where = ", ".join(f"{e['variant']} ({e['signed_id']})" for e in stale)
    bump = (f"bump [application] version in tests-support/synthetic-products/{product}/product.toml "
            f"to 0x{newest + 1:02X}" if newest < 0xFF else
            f"give tests-support/synthetic-products/{product}/product.toml a new [application] number")
    return (f"{product}: the committed xml/ differs from the XML of its capture {where}, and "
            f"[application] version 0x{version:02X} is not above 0x{newest:02X}. ETS keeps the application "
            f"it imported first under the same order number and version and reports \"imported\" anyway, "
            f"so the download would test the old XML (#650): {bump}, run generate.py, then capture again.")


def check_recapture(product: str) -> None:
    """Refuses (SystemExit) a capture `recapture_refusal` calls stale."""
    version = int(generate_spec(product)["application"]["version"])
    why = recapture_refusal(product, xml_sha256(product), version, load_manifest())
    if why:
        raise SystemExit(why)


def expected_program_version(product: str) -> str:
    """The `PID_PROGRAM_VERSION` value of the spec, hex: manufacturer 00FA,
    the application number, the version."""
    a = generate_spec(product)["application"]
    return f"00fa{int(a['number']):04x}{int(a['version']):02x}"


PROGRAM_VERSION_WRITE = re.compile(r"prop-write \S+/PID_PROGRAM_VERSION .*\bsha=([0-9a-f]{8})")
TASK_SEGMENT_APP = re.compile(r"ctrl=LdCtrlTaskSegment .*\bapp_id=([0-9a-f]{10})")
LSM_RECORD = 0x0104  # the memory-mapped load-state records of 0700/0701
LD_CTRL_TASK_SEGMENT = 0x02


def downloaded_versions(run_dir: Path) -> list[tuple[str, str]]:
    """What the capture in `run_dir` wrote as the program version, as
    (`sha`, first 8 hex of the value's sha256) for a `PID_PROGRAM_VERSION`
    write in `ops.txt` (knxtrace prints its digest only) and (`app_id`, hex)
    for a LdCtrlTaskSegment record, from `ops.txt` on the property form
    (0705) and from `ets.pcapng` on the memory-mapped form (0700/0701, an
    11-octet record at 0x0104 whose last five octets are the id)."""
    ops = (run_dir / "ops.txt").read_text()
    found = [("sha", m.group(1)) for m in PROGRAM_VERSION_WRITE.finditer(ops)]
    found += [("app_id", m.group(1)) for m in TASK_SEGMENT_APP.finditer(ops)]
    if found or not (run_dir / "ets.pcapng").exists():
        return found
    sys.path.insert(0, str(REPO / "tools" / "knxtrace"))
    import knxtrace

    pcap = str(run_dir / "ets.pcapng")
    for op in knxtrace.resolve(knxtrace.load_ops(pcap, None), "1.1.1", pcap, None).requests():
        data = op.data or b""
        if (op.kind == "mem-write" and op.detail.get("addr_int") == LSM_RECORD and len(data) == 11
                and data[1] == LD_CTRL_TASK_SEGMENT):
            found.append(("app_id", data[-5:].hex()))
    return found


def version_mismatch(found: list[tuple[str, str]], expected: str) -> str | None:
    """Why the program versions a capture wrote are not `expected`, or None."""
    if not found:
        return ("the capture writes no program version (no PID_PROGRAM_VERSION, no LdCtrlTaskSegment); "
                f"expected {expected}")
    sha = hashlib.sha256(bytes.fromhex(expected)).hexdigest()[:8]
    wrong = [f"{kind}={value}" for kind, value in found if value != (sha if kind == "sha" else expected)]
    if wrong:
        return f"ETS downloaded another program version than the spec's {expected} (sha {sha}): {', '.join(wrong)}"
    return None


def check_downloaded_version(product: str, run_dir: Path) -> None:
    """Fails loudly (SystemExit) when the capture in `run_dir` did not
    download the spec's program version: ETS used a stale catalogue entry
    (#650). Runs before anything is copied under captures/synthetic/."""
    why = version_mismatch(downloaded_versions(run_dir), expected_program_version(product))
    if why:
        raise SystemExit(f"{product}: {why} in {run_dir}. ETS's catalogue holds a stale import; bump "
                         f"[application] version and capture again (#650).")


# ---------------------------------------------------------------------------
# Run variants (#604 "Run variants", epic #596 step 5). A variant is a driver
# option on an existing product: another download of it, captured into
# captures/synthetic/<product>/<variant>/ with its own row and manifest entry.
# All downloads of one variant run in ONE knx-sim process (series.py's way), so
# ETS sees the device the step before left; the last download is the capture,
# the earlier ones are its base.
# ---------------------------------------------------------------------------

# The variants and the products each one runs on. `doc` goes into the manifest
# entry. Steps are built by `variant_steps`.
VARIANTS: dict[str, dict] = {
    "no-ga": {"products": ("syn-minimal",),
              "doc": "the application download with no group address linked: empty address and "
                     "association tables (#542)"},
    "links": {"products": ("syn-minimal",),
              "doc": "the switch object linked to two group addresses and the status object to one "
                     "(driver `link`), then the application download (#478, #540)"},
    "reload": {"products": ("syn-s7-0705", "syn-s7-0701"),
               "doc": "a defaults download, then the same application again over the loaded device; "
                      "the capture is the second download (#488)"},
    "other-app": {"products": ("syn-s7-0705", "syn-s7-0701"),
                  "doc": "another synthetic application of the same mask downloaded first, then this one "
                         "over it; the capture is the second download (#488)"},
    "partial": {"products": ("syn-minimal",),
                "doc": "a defaults download, a parameter changed in ETS's parameter editor, then ETS's "
                       "partial download; the capture is the partial download (#543, #490)"},
    "calc-input": {"products": ("syn-param-calculation",),
                   "doc": "the input of the ParameterCalculation changed in ETS's parameter editor, then the "
                          "application download into a fresh device (#427)"},
    "bare-restart": {"products": ("syn-master-reset",),
                     "doc": "the application download into a device without the Master Reset: knx-sim "
                            "`master_reset: refuse` answers the confirmed A_Restart with error code 2 "
                            "(unsupported erase code); what ETS sends then (#611). Result 2026-10-31: ETS "
                            "6.4.1 disconnects and fails the download (UnsupportedEraseCode), no Basic "
                            "Restart, so the run raises and nothing is committed",
                     "sim": {"master_reset": "refuse"}},
}
# `other-app`: the application loaded first, a sibling of the same mask with
# the smallest delta.
OTHER_APP = {"syn-s7-0705": "syn-s7-hidden-default", "syn-s7-0701": "syn-s7-lsm5"}
# `links`: (object number, group address) in the order the driver links them.
# The first address of an object that transmits is its sending address.
LINKS = {"syn-minimal": [(0, "1/0/1"), (0, "1/0/2"), (1, "1/0/3")]}
# `partial` and `calc-input`: the parameter ETS's editor changes, as ETS shows
# it (`text`, `kind`, `value`), and the device file's key and value for it.
PARAMS = {
    "syn-minimal": [{"text": "Delay (s)", "kind": "int", "value": "500", "key": "delay-s", "model": 500}],
    "syn-param-calculation": [{"text": "Delay (s)", "kind": "int", "value": "500", "key": "delay-s",
                               "model": 500}],
}


def variant_steps(product: str, variant: str) -> list[dict]:
    """The downloads of a variant, in order: `product` (whose application ETS
    downloads), `mode` (the driver's download mode), `links`, `params`, and
    `capture` on the last one (the others are its base)."""
    if product not in VARIANTS[variant]["products"]:
        raise SystemExit(f"{variant} runs on {', '.join(VARIANTS[variant]['products'])}, not {product}")
    one = {"product": product, "mode": "application", "links": [], "params": []}
    steps = {
        "no-ga": [{**one, "objects": True}],
        "links": [{**one, "links": LINKS.get(product, []), "objects": True}],
        "reload": [dict(one), dict(one)],
        "other-app": [{**one, "product": OTHER_APP.get(product, "")}, dict(one)],
        "partial": [dict(one), {**one, "mode": "partial", "params": PARAMS.get(product, [])}],
        "calc-input": [{**one, "params": PARAMS.get(product, [])}],
        "bare-restart": [dict(one)],
    }[variant]
    for i, step in enumerate(steps):
        step["name"] = "capture" if i == len(steps) - 1 else f"base-{i + 1}" if len(steps) > 2 else "base"
    return steps


def variant_options(product: str, variant: str) -> str:
    """The oracle row options a variant needs beside `expect=` and `loadctl=`:
    the device state of a programmed System 7 device, the model template of a
    variant that links or changes a parameter, the `run=params` of a partial
    download replayed over its base."""
    rel = (OUT / product / variant).relative_to(REPO).as_posix()
    if variant in oracle.LOADED_RUNS:
        return device_state(product, variant)
    if variant in ("links", "calc-input"):
        return f"dir={rel}/model"
    if variant == "partial":
        mask = tomllib.loads((CATALOGUE / product / "product.toml").read_text())["application"]["mask"]
        return f"run=params base={rel}/base.pcapng dir={rel}/model lsm={lsm_access(str(mask))}"
    return ""


def model_template(product: str, variant: str, dst: Path) -> None:
    """`model/` of a variant whose row plans with links or a parameter value:
    bussard.toml as `captures/synthetic/model`, the device file and
    groups.toml. The oracle script imports the product into a copy and pins
    the device (`95-offline-oracle.sh`, `dir=`)."""
    links = {}
    for step in variant_steps(product, variant):
        for number, ga in step["links"]:
            links.setdefault(number, []).append(ga)
    params = [p for step in variant_steps(product, variant) for p in step["params"]]
    if not links and not params:
        return
    model = dst / "model"
    (model / "devices").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(MODEL / "bussard.toml", model / "bussard.toml")
    text = f'# The device of the {variant} variant of {product} (capture.py).\naddress = "1.1.1"\nname = "{product}"\n'
    if params:
        text += "\n[parameters]\n" + "".join(f'{p["key"]} = {json.dumps(p["model"])}\n' for p in params)
    if links:
        objects = {o["number"]: o for o in generate_spec(product).get("com_object", [])}
        text += "\n[links]\n"
        for number, gas in sorted(links.items()):
            if "T" in objects.get(number, {}).get("flags", []):
                text += f'{number}.send = "{gas[0]}"\n'
                if gas[1:]:
                    text += f"{number}.listen = [{', '.join(json.dumps(g) for g in gas[1:])}]\n"
            else:
                text += f"{number}.listen = [{', '.join(json.dumps(g) for g in gas)}]\n"
    (model / "devices" / "1.1.1.toml").write_text(text)
    groups = sorted({g for gas in links.values() for g in gas}, key=lambda g: tuple(int(x) for x in g.split("/")))
    entries = "".join(f'  {{ address = "{g}", name = "{variant} {g}" }},\n' for g in groups)
    (model / "groups.toml").write_text(f'project = "{product} {variant}"\n\ngroups = [\n{entries}]\n')


def generate_spec(product: str) -> dict:
    return tomllib.loads((CATALOGUE / product / "product.toml").read_text())


def run_variant(c, product: str, variant: str, signed: dict[str, tuple[Path, str]]) -> dict:
    """The variant's downloads in one sim inside the VM (see the block doc).
    Every step's slice of the sim's pcap goes to
    `captures/ets-sweep/<signed id>/<variant>/<step>/` with `ops.txt`,
    `sim.log`, `driver.json` and, where the step read it, `objects.json` /
    `params.json`. Raises when a step does not end "Abgeschlossen"."""
    import base64

    import series
    import sweep
    import vm

    target, sid = signed[product]
    mask = str(generate_spec(product)["application"]["mask"])
    run = sweep.CAPTURES / sid / variant
    shutil.rmtree(run, ignore_errors=True)
    run.mkdir(parents=True)
    steps = variant_steps(product, variant)
    result: dict = {"variant": variant, "product": product, "steps": []}

    def flow(name: str, /, **body) -> dict:
        r = vm.driver(c, "POST", f"/ets/{name}", {"project": "ets-sweep", **body}, timeout=900)
        if not r.get("ok", True):
            raise RuntimeError(f"{name}: {r.get('error')}")
        return r

    # The sim's device is the variant's product throughout: `other-app` loads
    # the sibling's application into it first.
    sim = sweep.RemoteSim(c, target.resolve(), sid, "1.1.1", 3672, None, run / "sim.log", mask=mask,
                          device_options=VARIANTS[variant].get("sim"))
    in_project = None
    try:
        for step in steps:
            out = run / step["name"]
            out.mkdir(parents=True, exist_ok=True)
            prod_file, prod_sid = signed[step["product"]]
            info: dict = {"step": step["name"], "product": step["product"], "signed_id": prod_sid,
                          "mode": step["mode"]}
            if in_project != step["product"]:
                flow("project_tab", name="ets-sweep")
                for d in flow("devices")["devices"]:
                    if not flow("delete_device", ia=d["ia"]).get("deleted"):
                        raise RuntimeError(f"could not delete {d['ia']} before the add")
                order = generate_spec(step["product"])["product"]["order_number"]
                add = flow("catalog_add", search=order, version=sweep.app_version(prod_sid), fallback_search="",
                           password_wait=2)
                if not add.get("added"):
                    raise RuntimeError(f"catalog add added nothing: {add.get('row')}")
                info["catalog_row"] = add.get("row")
                in_project = step["product"]
            # The object numbers the table lists, in order: OCR reads no lone
            # digit, so the driver takes them from here (`read_objects`).
            numbers = sorted(o["number"] for o in generate_spec(step["product"]).get("com_object", []))
            for number, ga in step["links"]:
                info.setdefault("links", []).append(
                    flow("link", ia="1.1.1", number=number, ga=ga, numbers=numbers).get("row"))
            if step["params"]:
                pages = flow("param_pages", ia="1.1.1").get("pages") or []
                done = []
                for p in step["params"]:
                    r = flow("set_param", ia="1.1.1", text=p["text"], kind=p["kind"], value=p["value"], pages=pages)
                    done.append({**p, "set": bool(r.get("set")), "page": r.get("page"), "row": r.get("row"),
                                 "seen": r.get("seen")})
                (out / "params.json").write_text(json.dumps({"pages": pages, "changes": done}, indent=1,
                                                            ensure_ascii=False) + "\n")
                info["params"] = done
                if not all(d["set"] for d in done):
                    raise RuntimeError(f"the parameter editor did not set {[d for d in done if not d['set']]}")
            if step.get("objects"):
                objects = flow("objects", ia="1.1.1", numbers=numbers)["objects"]
                (out / "objects.json").write_text(json.dumps(objects, indent=1, ensure_ascii=False) + "\n")
                info["objects"] = [{"number": o.get("number"), "gas": o.get("gas"), "flags": o.get("flags")}
                                   for o in objects]
                try:
                    shot = vm.driver(c, "POST", "/screenshot", {"window": "desktop", "bbox": list(series.GO_TABLE)},
                                     timeout=120)
                    (out / "objects.png").write_bytes(base64.b64decode(shot["png_base64"]))
                except Exception as exc:  # noqa: BLE001 - a screenshot is evidence, not a step
                    info["screenshot"] = f"failed: {exc}"[:200]
            flow("select_connection", name="knx-sim")
            offset = series.remote_size(c)
            since = sweep.vm_now(c)
            log_from = len(sim.lines())
            print(f"{product} {variant} {step['name']}: {step['product']} download {step['mode']}", flush=True)
            info["download"] = flow("download", ia="1.1.1", mode=step["mode"])
            info["end"] = series.wait_download(c, sim, since, log_from)
            hist: list[str] = []
            for _ in range(24):
                hist = vm.driver(c, "POST", "/ets/history", {}, timeout=120).get("lines") or []
                if sweep.ets_status(hist) != "unknown":
                    break
                time.sleep(5)
            info["ets"], info["history"] = sweep.ets_status(hist), hist[:4]
            full = out / "sim-full.pcap"
            sim.fetch_pcap(full)
            sliced, info["frames"] = series.pcap_slice(full.read_bytes(), offset)
            (out / "ets.pcapng").write_bytes(sliced)
            full.unlink()
            lines = sim.lines()
            (out / "sim.log").write_text("\n".join(lines[log_from:]) + "\n")
            info["loaded_objects"] = sorted({m.group(1) for l in lines[log_from:] if sweep.Sim.LOADED.search(l)
                                             for m in [re.search(r"object=(\d+)", l)] if m})
            ops = subprocess.run(["uv", "run", "--quiet", str(sweep.KNXTRACE), "ops", str(out / "ets.pcapng"),
                                  "--device", "1.1.1"], capture_output=True, text=True)
            (out / "ops.txt").write_text(ops.stdout + ops.stderr)
            info["ops"] = sum(1 for l in ops.stdout.splitlines() if re.match(r"\s+\d+\s", l))
            (out / "driver.json").write_text(json.dumps(info, indent=1, ensure_ascii=False) + "\n")
            result["steps"].append(info)
            print(f"  {info['end']}, ETS {info['ets']}, {info['ops']} ops, loaded {info['loaded_objects']}",
                  flush=True)
            if info["ets"] != "ok":
                raise RuntimeError(f"step {step['name']}: ETS {info['ets']}: {hist[:3]}")
    finally:
        sim.stop()
    (run / "driver.json").write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    return result


def merge_pcaps(parts: list[Path]) -> bytes:
    """Classic pcaps of one sim (one global header) joined in order."""
    out = bytearray()
    for i, part in enumerate(parts):
        data = part.read_bytes()
        out += data if i == 0 else data[24:]
    return bytes(out)


def copy_variant(product: str, variant: str, sid: str, app: str, mask: str) -> Path:
    """`captures/synthetic/<product>/<variant>/` from the run directory: the
    files of a defaults capture for the last download, `base.pcapng` and
    `base-requests.txt` for the earlier ones, `objects.json`/`params.json`
    where a step read them, the model template."""
    run = calibrate.CAPTURES / sid / variant
    steps = variant_steps(product, variant)
    dst = OUT / product / variant
    shutil.rmtree(dst, ignore_errors=True)
    dst.mkdir(parents=True)
    rel = dst.relative_to(REPO).as_posix()
    last = run / steps[-1]["name"]
    shutil.copyfile(last / "ets.pcapng", dst / "ets.pcapng")
    shutil.copyfile(run / "driver.json", dst / "driver.json")
    ops = (last / "ops.txt").read_text().replace(str(last / "ets.pcapng"), f"{rel}/ets.pcapng")
    (dst / "ops.txt").write_text(ops)
    for name in ("objects.json", "params.json"):
        if (last / name).exists():
            shutil.copyfile(last / name, dst / name)
    reqs = distil.requests(dst / "ets.pcapng")
    (dst / "requests.txt").write_text(distil.render(reqs, f"{rel}/ets.pcapng"))
    base = [run / s["name"] / "ets.pcapng" for s in steps[:-1]]
    if base:
        (dst / "base.pcapng").write_bytes(merge_pcaps(base))
        (dst / "base-requests.txt").write_text(
            distil.render(distil.requests(dst / "base.pcapng"), f"{rel}/base.pcapng"))
    (dst / "sim.yaml").write_text(sim_yaml(product, app, mask, variant, base=bool(base)))
    write_image(dst, rel)
    model_template(product, variant, dst)
    return dst


def capture_variant(product: str, variant: str, args) -> int:
    """`--variant`: sign and import every product the variant downloads, run
    it (`run_variant`), copy the capture, run its row, write the manifest and
    the rows (see the block doc)."""
    spec = generate_spec(product)
    order, mask = spec["product"]["order_number"], str(spec["application"]["mask"])
    app = rendered_app(product)
    steps = variant_steps(product, variant)
    involved = list(dict.fromkeys(s["product"] for s in steps))
    previous = next((e for e in load_manifest() if e["product"] == product and e["variant"] == variant), {})
    if args.no_ets:
        sid = tomllib.loads((CATALOGUE / product / "signed.toml").read_text())["application_id"]
        ets = args.ets_version or previous.get("ets", "unknown")
        build = args.sim_build or previous.get("knx_sim", "unknown")
        when = args.captured or previous.get("captured")
        result = json.loads((calibrate.CAPTURES / sid / variant / "driver.json").read_text())
    else:
        import vm

        build = sim_build(args.sim_build)
        for p in involved:
            check_recapture(p)
        signed = {p: sign(p) for p in involved}
        c = vm.connect()
        for p in involved:
            imported = ets_import(c, signed[p][0], generate_spec(p)["product"]["order_number"])
            print(f"ETS import of {p}: {imported['import']}, catalogue row {imported['catalog_row']}")
        ets = ets_version(c)
        sid = signed[product][1]
        result = run_variant(c, product, variant, signed)
        when = datetime.date.today().isoformat()
    check_downloaded_version(product, calibrate.CAPTURES / sid / variant / steps[-1]["name"])
    dst = copy_variant(product, variant, sid, app, mask)
    extra = carried_options(variant_options(product, variant), previous.get("row_options", ""))
    verdict = oracle_verdict(product, app, variant, extra)
    requests = sum(1 for l in (dst / "requests.txt").read_text().splitlines() if l and not l.startswith("#"))
    entry = {
        "product": product, "variant": variant, "order_number": order, "application": app, "signed_id": sid,
        "xml_sha256": xml_sha256(product), "ets": ets, "knx_sim": build, "captured": when,
        "ops": result["steps"][-1].get("ops"), "requests": requests,
        "about": VARIANTS[variant]["doc"],
        "steps": [{"product": s["product"], "mode": s["mode"], "ets": s.get("ets"), "ops": s.get("ops")}
                  for s in result["steps"]],
        "row_options": extra,
        "oracle": {k: verdict[k] for k in ("verdict", "coverage", "confirmed", "loadctl", "props") if k in verdict},
    }
    for p in involved:
        if p != product:
            entry.setdefault("base_xml_sha256", {})[p] = xml_sha256(p)
    entries = [e for e in load_manifest() if not (e["product"] == product and e["variant"] == variant)]
    entries.append({k: v for k, v in entry.items() if v not in ("", None)})
    write_manifest(entries)
    write_rows(entries)
    code, text = run_oracle(["--rows", str(ROWS.relative_to(REPO)), "--check"])
    print(f"{product}/{variant}: oracle {verdict['verdict']} coverage {verdict['coverage']} "
          f"loadctl {verdict['loadctl']} ({verdict['regions']}); rows --check: {'passed' if code == 0 else 'FAILED'}")
    if code != 0:
        print(text[-2000:])
    return code


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("product")
    ap.add_argument("--no-ets", action="store_true", help="reuse the sweep's run directory")
    ap.add_argument("--sim-build", help="the commit knx-sim.exe in the VM was built from")
    ap.add_argument("--ets-version", help="with --no-ets: the ETS version of the reused capture")
    ap.add_argument("--captured", help="with --no-ets: the date of the reused capture (YYYY-MM-DD)")
    ap.add_argument("--variant", default=VARIANT, choices=[VARIANT, *VARIANTS],
                    help="a run variant instead of the defaults download (see VARIANTS)")
    args = ap.parse_args()
    if args.variant != VARIANT:
        return capture_variant(args.product, args.variant, args)
    product = args.product
    spec = tomllib.loads((CATALOGUE / product / "product.toml").read_text())
    order = spec["product"]["order_number"]
    mask = spec["application"]["mask"]
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
        check_recapture(product)
        signed, sid = sign(product)
        c = vm.connect()
        imported = ets_import(c, signed, order)
        print(f"ETS import: {imported['import']}, catalogue row {imported['catalog_row']}")
        ets = ets_version(c)
        result = calibrate.calibrate_one(signed, sid, order, True, Path(tempfile.mkdtemp()), mask)
        print(f"ETS download: {result.get('outcome')} ets={result.get('ets')} ops={result.get('ops')} "
              f"loaded={result.get('loaded_objects')}; signed-product oracle: {result.get('oracle', {}).get('summary')}")
        when = datetime.date.today().isoformat()
        if result.get("outcome") != "captured":
            raise SystemExit(f"ETS did not complete the download: {result}")
    check_downloaded_version(product, calibrate.run_dir(sid))
    dst = copy_capture(product, sid, app, mask)
    extra = carried_options(knxnet_model(product, dst), previous.get("row_options", ""))
    verdict = oracle_verdict(product, app, extra=extra)
    requests = sum(1 for l in (dst / "requests.txt").read_text().splitlines() if l and not l.startswith("#"))
    entry = {
        "product": product, "variant": VARIANT, "order_number": order, "application": app, "signed_id": sid,
        "xml_sha256": xml_sha256(product), "ets": ets, "knx_sim": build, "captured": when,
        "ops": result.get("ops"), "requests": requests,
        "oracle": {k: verdict[k] for k in ("verdict", "coverage", "loadctl", "props") if k in verdict},
    }
    if extra:
        entry["row_options"] = extra
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
