# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Build the scratch bussard model an oracle row of the ETS sweep compares against.

    uv run tools/ets-sweep/oracle_model.py <out-dir> <product.knxprod> <application-id> [--ia 1.1.1]

The model holds one device at `--ia` with the application at its vendor
defaults and no links, which is what the sweep has ETS download into the
simulator (a catalog device added to an empty line, nothing configured). It is
the same shape the sim catalog loop uses (bussard-cli tests/it/sim_catalog_loop.rs,
`write_model`): `bussard import-product`, then the device pinned in the lock.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUSSARD = Path(os.environ.get("BUSSARD_BIN", REPO / "target" / "debug" / "bussard"))


def build(out: Path, product: Path, app: str, ia: str = "1.1.1", mask: str = "") -> Path:
    out.mkdir(parents=True, exist_ok=True)
    (out / "bussard.toml").write_text('[connection]\ntransport = "tunnel"\ngateway = "127.0.0.1:3671"\n')
    r = subprocess.run([str(BUSSARD), "import-product", "--dir", str(out), str(product)],
                       capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
    if r.returncode != 0:
        raise RuntimeError(f"import-product failed: {(r.stderr or r.stdout)[-400:]}")
    sha = hashlib.sha256(product.read_bytes()).hexdigest()
    lock = (out / "bussard.lock").read_text()
    if "[[device]]" not in lock:
        mask_line = f'mask = "{mask}"\n' if mask else ""
        lock += f'\n[[device]]\naddress = "{ia}"\napplication = "{app}"\nproduct_sha256 = "{sha}"\n{mask_line}'
        (out / "bussard.lock").write_text(lock)
    (out / "devices").mkdir(exist_ok=True)
    (out / "devices" / f"{ia}.toml").write_text(f'address = "{ia}"\nname = "ets sweep"\n')
    (out / "groups.toml").write_text('project = "ets sweep"\n\ngroups = [\n]\n')
    return out


if __name__ == "__main__":
    args = sys.argv[1:]
    ia = "1.1.1"
    if "--ia" in args:
        i = args.index("--ia")
        ia = args[i + 1]
        del args[i : i + 2]
    print(build(Path(args[0]), Path(args[1]), args[2], ia))
