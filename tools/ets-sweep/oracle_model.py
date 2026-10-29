# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Build the scratch bussard model an oracle row of the ETS sweep compares against.

    uv run tools/ets-sweep/oracle_model.py <out-dir> <product.knxprod> <application-id> [--ia 1.1.1]

The model holds one device at `--ia` with the application at its vendor
defaults and no links (and, for a device with a KNX IP interface built in, the
`[knxnet]` table ETS's project gives it), which is what the sweep has ETS download into the
simulator (a catalog device added to an empty line, nothing configured). Its
import language is the sweep's ETS project language, de-DE: ETS starts a new
device's text parameters from the `InitialValue` translated into the project
language (issue #473, the Busch-Wächter PRO 2800's device name). It is
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
# The language of the sweep's ETS project (issue #473).
LANGUAGE = "de-DE"
BUSSARD = Path(os.environ.get("BUSSARD_BIN", REPO / "target" / "debug" / "bussard"))


def additional_addresses(product: Path, app: str) -> int:
    """The application's `AdditionalAddressesCount`: the tunnelling addresses of
    a KNX IP interface built into the device (5 on the ALLinBOX 1612), 0 when
    it declares none."""
    import re
    import zipfile

    try:
        z = zipfile.ZipFile(product)
        for name in z.namelist():
            if name.endswith(f"/{app}.xml"):
                head = z.read(name)[:8192].decode("utf-8", "replace")
                m = re.search(r'<ApplicationProgram [^>]*AdditionalAddressesCount="(\d+)"', head)
                return int(m.group(1)) if m else 0
    except (OSError, zipfile.BadZipFile):
        return 0
    return 0


def knxnet_table(ia: str, count: int, friendly_name: str | None) -> str:
    """The `[knxnet]` table the sweep's ETS project holds for an IP-enabled
    device (bussard issue #455): DHCP, the device's name in the project (the
    catalog row's product text) as the friendly name, and the tunnelling
    addresses ETS assigns on its own, the highest `count` on the device's line
    in ascending order (1.1.251 to 1.1.255 for 5, every sweep capture)."""
    area, line, _ = ia.split(".")
    tunnels = ", ".join(f'"{area}.{line}.{256 - count + i}"' for i in range(count))
    name = f'friendly_name = "{friendly_name}"\n' if friendly_name else ""
    return f'\n[knxnet]\nassignment = "dhcp"\n{name}tunnels = [{tunnels}]\n'


def ensure_knxnet(out: Path, product: Path, app: str, ia: str = "1.1.1",
                  friendly_name: str | None = None) -> None:
    """Adds the `[knxnet]` table to the device file of an IP-enabled device
    that has none (a model the sweep imported before issue #455)."""
    count = additional_addresses(product, app)
    path = out / "devices" / f"{ia}.toml"
    if count and path.exists() and "[knxnet]" not in path.read_text():
        with path.open("a") as fh:
            fh.write(knxnet_table(ia, count, friendly_name))


def build(out: Path, product: Path, app: str, ia: str = "1.1.1", mask: str = "",
          friendly_name: str | None = None) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    (out / "bussard.toml").write_text('[connection]\ntransport = "tunnel"\ngateway = "127.0.0.1:3671"\n'
                                      f'\n[import]\nlanguage = "{LANGUAGE}"\n')
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
    ensure_knxnet(out, product, app, ia, friendly_name)
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
