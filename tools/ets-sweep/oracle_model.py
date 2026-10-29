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

A product file is imported once (`shared_import`): every row of the same file
gets a small model of its own whose `products/` and the product caches under
`.bussard/` (`products`, `models`, `model-cache`) are links into the shared
import, and whose lock is the shared lock plus its device. The ABB and
Busch-Jaeger catalogue files (152 MB) cost about 3.5 minutes and 1.6 GB per
row when every row imported the file itself (2026-10-29).

`links` (the links variant and the partial-download series, #478) gives the
device's objects their group addresses: `{"31": {"send": "1/0/9", "listen":
[]}}`, and `groups.toml` lists every address used.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# The language of the sweep's ETS project (issue #473).
LANGUAGE = "de-DE"
BUSSARD = Path(os.environ.get("BUSSARD_BIN", REPO / "target" / "debug" / "bussard"))
# The caches under `.bussard/` that depend on the product data only. A row's
# history and device facts stay its own.
SHARED_CACHES = ("products", "models", "model-cache")
_SHA: dict[tuple, str] = {}


def additional_addresses(product: Path, app: str) -> int:
    """The application's `AdditionalAddressesCount`: the tunnelling addresses of
    a KNX IP interface built into the device (5 on the ALLinBOX 1612), 0 when
    it declares none."""
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


def product_sha(product: Path) -> str:
    """The sha256 of a product file, memoised by path, size and mtime."""
    st = product.stat()
    key = (str(product.resolve()), st.st_size, st.st_mtime_ns)
    if key not in _SHA:
        h = hashlib.sha256()
        with product.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        _SHA[key] = h.hexdigest()
    return _SHA[key]


def model_toml() -> str:
    return ('[connection]\ntransport = "tunnel"\ngateway = "127.0.0.1:3671"\n'
            f'\n[import]\nlanguage = "{LANGUAGE}"\n')


def strip_devices(lock: str) -> str:
    """The lock without its `[[device]]` entries (each runs to the next table
    header or the end of the file)."""
    out: list[str] = []
    skipping = False
    for line in lock.splitlines(keepends=True):
        head = line.strip()
        if head.startswith("["):
            skipping = head == "[[device]]"
        if not skipping:
            out.append(line)
    return "".join(out).rstrip("\n") + "\n"


def device_entry(ia: str, app: str, sha: str, mask: str = "") -> str:
    mask_line = f'mask = "{mask}"\n' if mask else ""
    return f'\n[[device]]\naddress = "{ia}"\napplication = "{app}"\nproduct_sha256 = "{sha}"\n{mask_line}'


def import_product(out: Path, product: Path) -> None:
    r = subprocess.run([str(BUSSARD), "import-product", "--dir", str(out), str(product)],
                       capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
    if r.returncode != 0:
        raise RuntimeError(f"import-product failed: {(r.stderr or r.stdout)[-400:]}")


def shared_dir(root: Path, product: Path) -> Path:
    """Where `shared_import` keeps the import of `product` under `root`."""
    return root / product_sha(product)[:16]


def shared_import(root: Path, product: Path, seed: Path | None = None) -> Path:
    """The model directory holding `product` imported once (no device), under
    `root`, keyed by the file's hash. `seed`, a model the sweep already
    imported the same file into, is copied instead of importing again."""
    out = shared_dir(root, product)
    sha = product_sha(product)
    lock = out / "bussard.lock"
    if lock.exists() and sha in lock.read_text():
        return out
    tmp = out.with_name(out.name + ".partial")
    shutil.rmtree(tmp, ignore_errors=True)
    seed_lock = seed / "bussard.lock" if seed else None
    if seed_lock and seed_lock.exists() and sha in seed_lock.read_text():
        shutil.copytree(seed, tmp, symlinks=True, ignore=shutil.ignore_patterns("history", "facts", "captures"))
    else:
        tmp.mkdir(parents=True)
        (tmp / "bussard.toml").write_text(model_toml())
        import_product(tmp, product)
    (tmp / "bussard.lock").write_text(strip_devices((tmp / "bussard.lock").read_text()))
    for name in SHARED_CACHES:
        (tmp / ".bussard" / name).mkdir(parents=True, exist_ok=True)
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
    return out


def link_shared(out: Path, shared: Path) -> None:
    """Points `out/products` and the product caches of `out/.bussard/` at the
    shared import, replacing what a previous build left there."""

    def relink(link: Path, target: Path) -> None:
        if link.is_symlink() or link.is_file():
            link.unlink()
        elif link.is_dir():
            shutil.rmtree(link)
        link.symlink_to(target.resolve(), target_is_directory=True)

    relink(out / "products", shared / "products")
    (out / ".bussard").mkdir(exist_ok=True)
    for name in SHARED_CACHES:
        relink(out / ".bussard" / name, shared / ".bussard" / name)


def ga_key(ga: str) -> tuple:
    return tuple(int(x) for x in ga.split("/"))


def device_toml(ia: str, links: dict | None = None) -> str:
    """The device file: the address, a name, and the `[links]` table."""
    text = f'address = "{ia}"\nname = "ets sweep"\n'
    if links:
        text += "\n[links]\n"
        for number in sorted(links, key=int):
            link = links[number]
            if link.get("send"):
                text += f'{number}.send = "{link["send"]}"\n'
            if link.get("listen"):
                gas = ", ".join(f'"{g}"' for g in link["listen"])
                text += f"{number}.listen = [{gas}]\n"
    return text


def groups_toml(groups: list[str] | None = None) -> str:
    entries = "".join(f'  {{ address = "{g}", name = "sweep {g}" }},\n'
                      for g in sorted(set(groups or []), key=ga_key))
    return f'project = "ets sweep"\n\ngroups = [\n{entries}]\n'


def build(out: Path, product: Path, app: str, ia: str = "1.1.1", mask: str = "",
          friendly_name: str | None = None, shared: Path | None = None,
          links: dict | None = None) -> Path:
    """The scratch model of one row. With `shared` (a `shared_import` of the
    product) nothing is imported: the model links the shared caches and pins
    its device in a copy of the shared lock."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "bussard.toml").write_text(model_toml())
    if shared is not None:
        link_shared(out, shared)
        lock = (shared / "bussard.lock").read_text()
    else:
        import_product(out, product)
        lock = (out / "bussard.lock").read_text()
    (out / "bussard.lock").write_text(strip_devices(lock) + device_entry(ia, app, product_sha(product), mask))
    (out / "devices").mkdir(exist_ok=True)
    (out / "devices" / f"{ia}.toml").write_text(device_toml(ia, links))
    ensure_knxnet(out, product, app, ia, friendly_name)
    groups = [g for link in (links or {}).values() for g in ([link.get("send")] + list(link.get("listen") or [])) if g]
    (out / "groups.toml").write_text(groups_toml(groups))
    return out


if __name__ == "__main__":
    args = sys.argv[1:]
    ia = "1.1.1"
    if "--ia" in args:
        i = args.index("--ia")
        ia = args[i + 1]
        del args[i : i + 2]
    print(build(Path(args[0]), Path(args[1]), args[2], ia))
