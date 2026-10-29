# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""The KNX Data Secure variant of the ETS sweep (epic #419, part 4 #423).

    ETS_SWEEP_PROJECT_PASSWORD=... uv run tools/ets-sweep/secure.py run [--filter ...] [--limit N] [--redo]
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

Outputs per application under `captures/ets-sweep/<app>/secure-defaults/`;
outcomes in `results/secure.json` (`captured` + `decoded` / `partial` /
`undecoded`, or the run's failure). The project and keyring password comes
from `$ETS_SWEEP_PROJECT_PASSWORD` (letters and digits only: the driver
types it), never the command line or a file in the repository.

The certificate format (`certificate_text`): 36 characters in six groups of
six, the RFC 4648 base32 of the serial number (6 octets) and the FDSK (16
octets) with a 4-bit check in the 4 spare bits. Which check ETS expects is
NOT verified yet (written offline, 2026-10-30): the default is CRC-4/ITU over
the 22 octets; `cert --check` on the label of a real device says which
variant matches, and `--check-variant` picks it for the run.
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


def crc4(data: bytes, poly: int = 0x3, init: int = 0x0, reflected: bool = True) -> int:
    """A 4-bit CRC over `data` (CRC-4/ITU by default: x^4 + x + 1, reflected)."""
    crc = init
    if reflected:
        rpoly = int(f"{poly:04b}"[::-1], 2)
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ rpoly if crc & 1 else crc >> 1
            crc &= 0xF
        return crc
    for byte in data:
        for bit in range(7, -1, -1):
            top = (crc >> 3) & 1
            crc = ((crc << 1) & 0xF) | ((byte >> bit) & 1)
            if top:
                crc ^= poly
    return crc & 0xF


# The 4-bit checks a label might carry; `cert --check` tells which one a real
# label uses.
CHECKS = {
    "crc4-itu": lambda d: crc4(d),
    "crc4-plain": lambda d: crc4(d, reflected=False),
    "none": lambda d: 0,
}


def _bits_to_base32(value: int, bits: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(alphabet[(value >> (bits - 5 * (i + 1))) & 0x1F] for i in range(bits // 5))


def certificate_text(serial: bytes, fdsk: bytes, check: str = "crc4-itu") -> str:
    """The device certificate text ETS takes for a device (see the module
    doc): six groups of six base32 characters, dash-separated."""
    if len(serial) != 6 or len(fdsk) != 16:
        raise ValueError("a serial number is 6 octets and an FDSK 16")
    data = serial + fdsk
    raw = _bits_to_base32((int.from_bytes(data, "big") << 4) | CHECKS[check](data), 180)
    return "-".join(raw[i:i + 6] for i in range(0, 36, 6))


def parse_certificate(text: str) -> dict:
    """Serial, FDSK and the check variants a label satisfies. The FDSK is
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
            "matches": [name for name, f in CHECKS.items() if f(data) == tail]}


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
    if not re.fullmatch(r"[A-Za-z0-9]{8,64}", pw):
        raise SystemExit(f"${PASSWORD_ENV} must hold 8 to 64 letters and digits (the driver types it)")
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


def run(args) -> int:
    import defaults
    import sweep
    import vm

    pw = password()
    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    todo = jobs()
    wanted = [w.lower() for w in args.filter.split(",") if w]
    if wanted:
        todo = [j for j in todo if any(w in (j["id"] + " " + j["file"]).lower() for w in wanted)]
    c = vm.connect()
    vm.run(c, f'mkdir "{vm.REMOTE_DIR}\\keyrings"')
    done = 0
    for job in todo:
        if job["id"] in results and not args.redo:
            continue
        path = defaults.product_path(job["file"])
        secure, serial_prop = sim_security(job["id"])
        serial, fdsk = synthetic_identity(job["id"])
        props = (defaults.seed_properties(path, job["id"], job["prev"]) or []) + serial_prop
        r = sweep.run_one(c, path, job["id"], str(job["order_numbers"][0]), variant=VARIANT, project=PROJECT,
                          mask=job["mask"], properties=props, secure=secure,
                          flow_extra={"project_password": pw,
                                      "certificate": certificate_text(serial, fdsk, args.check_variant)},
                          after_download=export_hook(pw))
        entry = {"file": job["file"], "mask": job["mask"], "when": datetime.now(timezone.utc).isoformat(),
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
        RESULTS.parent.mkdir(exist_ok=True)
        RESULTS.write_text(json.dumps(dict(sorted(results.items())), indent=1, ensure_ascii=False) + "\n")
        print(f"{entry['outcome']:13} {(entry.get('decode') or {}).get('verdict', '-'):10} {job['id']}"
              + (f"  {entry['error'][:100]}" if entry.get("error") else ""), flush=True)
        done += 1
        if args.limit and done >= args.limit:
            break
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run")
    p.add_argument("--filter", default="")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--redo", action="store_true")
    p.add_argument("--check-variant", default="crc4-itu", choices=sorted(CHECKS))
    p = sub.add_parser("cert")
    p.add_argument("--serial", help="12 hex digits")
    p.add_argument("--fdsk", help="32 hex digits")
    p.add_argument("--check-variant", default="crc4-itu", choices=sorted(CHECKS))
    p.add_argument("--check", help="a real label: which check variant it carries (the FDSK is not printed)")
    sub.add_parser("jobs")
    args = ap.parse_args()
    if args.cmd == "cert":
        if args.check:
            info = parse_certificate(args.check)
            print(f"serial {info['serial'].hex().upper()}, check nibble {info['check']:X}, "
                  f"matches: {', '.join(info['matches']) or 'none of ' + ', '.join(CHECKS)}")
            return 0 if info["matches"] else 1
        print(certificate_text(bytes.fromhex(args.serial), bytes.fromhex(args.fdsk), args.check_variant))
        return 0
    if args.cmd == "jobs":
        for j in jobs():
            print(j["id"], j["mask"], j["file"])
        return 0
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
