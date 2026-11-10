# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""The KNX Data Secure variant of the ETS sweep (epic #419, part 4 #423).

    ETS_SWEEP_PROJECT_PASSWORD=... uv run tools/ets-sweep/secure.py run [--representative] [--filter ...] [--limit N] [--redo | --redo-failed]
    uv run tools/ets-sweep/secure.py cert --serial 00FA12345678 --fdsk <32 hex>   # print a label
    uv run tools/ets-sweep/secure.py cert --check "<36-character label>"          # calibrate the format
    uv run tools/ets-sweep/secure.py jobs                                         # list the secure-capable jobs

For every application the defaults sweep captured whose program declares
`IsSecureEnabled="true"`:

1. the sim device starts in factory state with a synthetic FDSK and serial
   number (`security: {status: factory, tool_key: <FDSK>}`, the serial as the
   device object's PID 11), both derived from the application id, never a
   real device's;
2. ETS adds the device in the sweep's secure project (`ets-sweep-secure`, set
   up once by hand: a copy of `ets-sweep` with the knx-sim connection), sets
   the project password when it asks, takes the device certificate (the FDSK
   label) when it asks for one at the download, commissions the device and
   downloads it;
3. the driver exports the project's keyring to the VM, it is fetched next to
   the capture (`project.knxkeys`, gitignored with every capture) and
   `knxtrace devices --keyring` decides whether the capture decodes end to
   end: every `A_SecureData` frame verified, none without a key.

`--representative` runs only the applications of `secure-subset.json`
(`secure_subset.py`, the owner's choice of 2026-11-10), in its order.

Outputs per application under `captures/ets-sweep/<app>/secure-defaults/`;
outcomes in `results/secure.json` (`captured` + `decoded` / `partial` /
`undecoded`, or the run's failure). The project and keyring password comes
from `$ETS_SWEEP_PROJECT_PASSWORD` (letters and digits only: the driver
types it), never the command line or a file in the repository.

The certificate format (`certificate_text`): 36 characters in six groups of
six, the RFC 4648 base32 of the serial number (6 octets) and the FDSK (16
octets) with a 4-bit check in the 4 spare bits: plain CRC-4 over the 22
octets (`crc4`), confirmed on two real labels (#201, 2026-11-03); the
contract is dev/enroll-protocol.md, "Certificate text". `cert --check` on a
label says whether its check matches.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results" / "secure.json"
PROJECT = "ets-sweep-secure"
VARIANT = "secure-defaults"
PASSWORD_ENV = "ETS_SWEEP_PROJECT_PASSWORD"
KNXTRACE = HERE.parents[1] / "tools" / "knxtrace" / "knxtrace.py"
PID_SERIAL_NUMBER = 11


def crc4(data: bytes) -> int:
    """The certificate check: plain CRC-4 over `data`, x^4 + x + 1 (0x3), init
    0, MSB first (not reflected), no final XOR, direct (not augmented). Not
    CRC-4/ITU, the reflected variant."""
    crc = 0
    for byte in data:
        for bit in range(7, -1, -1):
            top = ((crc >> 3) & 1) ^ ((byte >> bit) & 1)
            crc = (crc << 1) & 0xF
            if top:
                crc ^= 0x3
    return crc


def _bits_to_base32(value: int, bits: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(alphabet[(value >> (bits - 5 * (i + 1))) & 0x1F] for i in range(bits // 5))


def certificate_text(serial: bytes, fdsk: bytes) -> str:
    """The device certificate text ETS takes for a device (see the module
    doc): six groups of six base32 characters, dash-separated."""
    if len(serial) != 6 or len(fdsk) != 16:
        raise ValueError("a serial number is 6 octets and an FDSK 16")
    data = serial + fdsk
    raw = _bits_to_base32((int.from_bytes(data, "big") << 4) | crc4(data), 180)
    return "-".join(raw[i:i + 6] for i in range(0, 36, 6))


def parse_certificate(text: str) -> dict:
    """Serial, FDSK, the check nibble and whether it matches. The FDSK is
    returned for the sim config only; nothing here prints it."""
    clean = re.sub(r"[\s-]", "", text).upper()
    if not re.fullmatch(r"[A-Z2-7]{36}", clean):
        raise ValueError("a certificate is 36 base32 characters (A-Z, 2-7), dashes and spaces aside")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    value = 0
    for ch in clean:
        value = (value << 5) | alphabet.index(ch)
    data = (value >> 4).to_bytes(22, "big")
    tail = value & 0xF
    return {"serial": data[:6], "fdsk": data[6:], "check": tail,
            "check_ok": crc4(data) == tail}


def synthetic_identity(app: str) -> tuple[bytes, bytes]:
    """A synthetic serial number (the application's manufacturer id, then four
    octets of a hash) and FDSK for the sim device of `app`: deterministic, so
    a rerun keeps the certificate ETS already holds, and never a real one."""
    digest = hashlib.sha256(f"ets-sweep secure {app}".encode()).digest()
    m = re.match(r"M-([0-9A-F]{4})_", app)
    manufacturer = bytes.fromhex(m.group(1)) if m else b"\x00\xfa"
    return manufacturer + digest[:4], digest[8:24]


def sim_security(app: str) -> tuple[dict, list[dict]]:
    """The sim device's `security:` block and the serial-number property."""
    serial, fdsk = synthetic_identity(app)
    return ({"status": "factory", "tool_key": fdsk.hex()},
            [{"object": 0, "pid": PID_SERIAL_NUMBER, "value": serial.hex()}])


def secure_capable(product: Path, app: str) -> bool:
    """Whether the application program declares IsSecureEnabled="true"
    (strict: an unreadable product is not secure-capable)."""
    import zipfile

    try:
        z = zipfile.ZipFile(product)
        for name in z.namelist():
            if name.endswith(f"/{app}.xml"):
                return 'IsSecureEnabled="true"' in z.read(name)[:8192].decode("utf-8", "replace")
    except (OSError, zipfile.BadZipFile):
        return False
    return False


def decode_verdict(text: str) -> dict:
    """From `knxtrace devices --keyring` output: `decoded` when every
    A_SecureData frame verified, `partial` when some did, `undecoded` when
    none did, `plain` when there is none."""
    m = re.search(r"data secure: (\d+) A_SecureData frame", text)
    total = int(m.group(1)) if m else 0
    ok = sum(int(n) for n in re.findall(r"MAC ok \([^)]*\)\s+(\d+)", text))
    if not total:
        return {"verdict": "plain", "frames": 0, "verified": 0}
    verdict = "decoded" if ok == total else "partial" if ok else "undecoded"
    return {"verdict": verdict, "frames": total, "verified": ok}


def password() -> str:
    pw = os.environ.get(PASSWORD_ENV, "")
    # ETS 6.4.1 enables 'Passwort setzen' only for a password with a digit, an
    # upper and a lower case letter and a special character (2026-11-04); the
    # driver types it, so the special characters are ones send_keys takes
    # literally.
    if not (re.fullmatch(r"[A-Za-z0-9!#$*,.:;=?@_-]{8,64}", pw)
            and all(re.search(c, pw) for c in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[!#$*,.:;=?@_-]"))):
        raise SystemExit(f"${PASSWORD_ENV} must hold 8 to 64 letters, digits and at least one of "
                         "! # $ * , . : ; = ? @ _ -, with a digit, an upper and a lower case letter "
                         "(ETS's rule; the driver types it)")
    return pw


def export_hook(pw: str):
    """`sweep.run_one(after_download=...)`: the keyring export to the VM and
    its fetch next to the capture."""
    import vm

    def hook(flow, out: Path) -> dict:
        remote = f"{vm.REMOTE_DIR}\\keyrings\\{out.parent.name}.knxkeys"
        flow("export_keyring", path=remote, password=pw)
        return {"keyring_remote": remote, "keyring": str(out / "project.knxkeys")}

    return hook


def jobs() -> list[dict]:
    import defaults

    captured = json.loads(defaults.RESULTS.read_text()) if defaults.RESULTS.exists() else {}
    out = []
    for job in defaults.jobs():
        if (captured.get(job["id"]) or {}).get("outcome") != "captured":
            continue
        if secure_capable(defaults.product_path(job["file"]), job["id"]):
            out.append({**job, "prev": captured[job["id"]]})
    return out


# An import error that fails every row after it: stop the run (defaults.py's
# desktop checks, and ETS's 'not enough disk space').
STOP_ERRORS = ("screen grab failed", "not the RDP layout", "desktop in use", "Speicherplatz")


# Consecutive rows failed in the driver before the run stops.
MAX_DRIVER_ERRORS = 3


def save(results: dict) -> None:
    RESULTS.parent.mkdir(exist_ok=True)
    RESULTS.write_text(json.dumps(dict(sorted(results.items())), indent=1, ensure_ascii=False) + "\n")


def import_product(c, path: Path, pw: str) -> dict:
    """Imports the product file into ETS's catalog, as defaults.py does
    before a file's jobs: ETS adds a device only from its catalog, and the
    catalog is reset between sweeps (`reset_catalog`)."""
    import catalog
    import vm

    try:
        remote = catalog.upload_if_missing(c, path)
        return vm.driver(c, "POST", "/ets/catalog_import", {"path": remote, "timeout": 3600, "project": PROJECT,
                                                            "project_password": pw}, timeout=3700)
    except Exception as exc:  # noqa: BLE001 - recorded, the next job runs
        return {"outcome": "error", "error": str(exc)[:300]}


def run(args) -> int:
    import defaults
    import sweep
    import vm

    pw = password()
    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    todo = jobs()
    if args.representative:
        import secure_subset

        order = [r["app"] for r in secure_subset.load()]
        by_id = {j["id"]: j for j in todo}
        todo = [by_id[a] for a in order if a in by_id]
    wanted = [w.lower() for w in args.filter.split(",") if w]
    if wanted:
        todo = [j for j in todo if any(w in (j["id"] + " " + j["file"]).lower() for w in wanted)]
    c = vm.connect()
    vm.run(c, f'mkdir "{vm.REMOTE_DIR}\\keyrings"')
    done = 0
    import_errors = 0
    driver_errors = 0
    for job in todo:
        # A row whose import failed is run again (nothing of it reached ETS);
        # --redo-failed also runs again what is neither captured nor skipped,
        # as defaults.py's does.
        prev = results.get(job["id"])
        if prev and not args.redo and not prev.get("import_failed") and not (
                args.redo_failed and not str(prev.get("outcome", "")).startswith(("captured", "skipped"))):
            continue
        path = defaults.product_path(job["file"])
        imp = import_product(c, path, pw)
        if imp.get("outcome") not in ("imported", "done_unverified"):
            error = (imp.get("message") or imp.get("error") or "")[:300]
            results[job["id"]] = {"file": job["file"], "mask": job["mask"], "name": job["prev"].get("name"),
                                  "when": datetime.now(timezone.utc).isoformat(),
                                  "outcome": "skipped-import-failed" if imp.get("outcome") == "refused" else "driver-error",
                                  "error": error, "import_failed": imp.get("outcome") != "refused"}
            save(results)
            print(f"{results[job['id']]['outcome']:13} -          {job['id']}  import failed: {error[:120]}", flush=True)
            # defaults.py's stop rules: a desktop that cannot be used, or a
            # run of failed imports (a dialog ETS left open, a full disk:
            # 'nicht genug Speicherplatz', 2026-11-10) fails every row after it.
            if any(k in error for k in STOP_ERRORS):
                print(f"stopping: {error[:160]}", flush=True)
                break
            import_errors += imp.get("outcome") != "refused"
            if import_errors >= defaults.MAX_IMPORT_ERRORS:
                print(f"stopping: {import_errors} imports in a row failed", flush=True)
                break
            try:
                c = vm.connect()
            except Exception as exc:  # noqa: BLE001 - the VM is gone: stop, the rows stay to do
                print(f"stopping: ssh reconnect failed: {exc}", flush=True)
                break
            continue
        import_errors = 0
        secure, serial_prop = sim_security(job["id"])
        serial, fdsk = synthetic_identity(job["id"])
        props = (defaults.seed_properties(path, job["id"], job["prev"]) or []) + serial_prop
        r = sweep.run_one(c, path, job["id"], str(job["order_numbers"][0]), variant=VARIANT, project=PROJECT,
                          mask=job["mask"], properties=props, secure=secure,
                          flow_extra={"project_password": pw,
                                      "certificate": certificate_text(serial, fdsk)},
                          after_download=export_hook(pw))
        entry = {"file": job["file"], "mask": job["mask"], "name": job["prev"].get("name"), "ia": r.get("ia"),
                 "seconds": r.get("seconds"), "when": datetime.now(timezone.utc).isoformat(),
                 "outcome": r["outcome"], "error": r.get("error"), "ets": r.get("ets"), "ops": r.get("ops"),
                 "repair": (r.get("repair") or {}).get("dir")}
        out = sweep.CAPTURES / job["id"] / VARIANT
        remote = (r.get("after") or {}).get("keyring_remote")
        if remote:
            try:
                c.open_sftp().get(remote.replace("\\", "/"), str(out / "project.knxkeys"))
                d = subprocess.run(["uv", "run", "--quiet", str(KNXTRACE), "devices", str(out / "ets.pcapng"),
                                    "--keyring", str(out / "project.knxkeys")], capture_output=True, text=True,
                                   env={**os.environ, "BUSSARD_KEYRING_PASSWORD": pw})
                (out / "secure.txt").write_text(d.stdout + d.stderr)
                entry["decode"] = decode_verdict(d.stdout)
            except OSError as exc:
                entry["decode"] = {"verdict": "no-keyring", "error": str(exc)[:200]}
        results[job["id"]] = entry
        save(results)
        # A driver error in a row of its own is the row's; a run of them is
        # ETS stuck in a state the driver does not recover from (seven rows
        # in the Gebäude view, 2026-11-10): stop. The failed rows are saved;
        # `run --redo-failed` runs them again.
        driver_errors = driver_errors + 1 if entry["outcome"].startswith("driver-error") else 0
        print(f"{entry['outcome']:13} {(entry.get('decode') or {}).get('verdict', '-'):10} {job['id']}"
              + (f"  {entry['error'][:100]}" if entry.get("error") else ""), flush=True)
        done += 1
        if args.limit and done >= args.limit:
            break
        if driver_errors >= MAX_DRIVER_ERRORS:
            print(f"stopping: {driver_errors} rows in a row failed in the driver", flush=True)
            break
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run")
    p.add_argument("--filter", default="")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--redo", action="store_true")
    p.add_argument("--redo-failed", action="store_true",
                   help="run again what is neither captured nor skipped (a driver error, an ETS failure)")
    p.add_argument("--representative", action="store_true",
                   help="only the applications of secure-subset.json (secure_subset.py, #423)")
    p = sub.add_parser("cert")
    p.add_argument("--serial", help="12 hex digits")
    p.add_argument("--fdsk", help="32 hex digits")
    p.add_argument("--check", help="a real label: its serial and whether its check matches (the FDSK is not printed)")
    sub.add_parser("jobs")
    args = ap.parse_args()
    if args.cmd == "cert":
        if args.check:
            info = parse_certificate(args.check)
            print(f"serial {info['serial'].hex().upper()}, check nibble {info['check']:X}, "
                  f"{'matches' if info['check_ok'] else 'does NOT match'}")
            return 0 if info["check_ok"] else 1
        print(certificate_text(bytes.fromhex(args.serial), bytes.fromhex(args.fdsk)))
        return 0
    if args.cmd == "jobs":
        for j in jobs():
            print(j["id"], j["mask"], j["file"])
        return 0
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
