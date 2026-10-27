# /// script
# requires-python = ">=3.10"
# dependencies = ["pyyaml"]
# ///
"""Map every corpus product file to its application programs (epic #419, part 2 #421).

    uv run tools/ets-sweep/catalog_apps.py [--corpus DIR] [--filter a,b] [--bussard target/debug/bussard]

For each `.knxprod` in the corpus, `bussard import-product` into a scratch
directory generates the product models; their identity (application id, name,
mask) and order numbers go to `tools/ets-sweep/catalog-apps.json`:

    {"<file>": {"apps": [{"id": "M-0083_A-004F-11-8F33", "name": "Rain sensor",
                          "mask": "0701", "order_numbers": ["SCN-RS1R.01"]}, ...],
                "error": null}}

This is the join between a product file, the catalog entry ETS shows (the
order number is ETS's catalog search term) and the application the sweep
flashes. Labels only, no vendor data. Files with an entry are skipped.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


class _Loader(yaml.SafeLoader):
    """bussard's models tag parameter types (`type: !int`); keep the scalar."""


_Loader.add_multi_constructor("!", lambda loader, suffix, node: loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else loader.construct_mapping(node) if isinstance(node, yaml.MappingNode) else loader.construct_sequence(node))

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUT = HERE / "catalog-apps.json"


def apps_of(bussard: Path, product: Path) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="ets-apps-") as tmp:
        r = subprocess.run([str(bussard), "import-product", "--dir", tmp, str(product)], capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout).strip()[-400:])
        out = []
        for model in sorted(Path(tmp, ".bussard", "models").glob("*.yaml")):
            doc = yaml.load(model.read_text(), Loader=_Loader)  # noqa: S506 - our own models
            ident = doc.get("identity", {})
            out.append({
                "id": ident.get("id", model.stem),
                "name": ident.get("name"),
                "mask": str(ident.get("mask_version")),
                "order_numbers": doc.get("order_numbers") or [],
            })
        return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, default=REPO / "tests-support" / "product-corpus" / "cache" / "vendor")
    ap.add_argument("--bussard", type=Path, default=REPO / "target" / "debug" / "bussard")
    ap.add_argument("--filter", default="")
    ap.add_argument("--redo", action="store_true")
    args = ap.parse_args()
    data = json.loads(OUT.read_text()) if OUT.exists() else {}
    files = sorted(p for p in args.corpus.iterdir() if p.is_file() and ".knxprod" in p.name.lower())
    wanted = [s for s in args.filter.split(",") if s]
    if wanted:
        files = [p for p in files if any(w.lower() in p.name.lower() for w in wanted)]
    for i, path in enumerate(files, 1):
        if path.name in data and not args.redo:
            continue
        try:
            data[path.name] = {"apps": apps_of(args.bussard, path), "error": None}
        except Exception as exc:  # noqa: BLE001 - recorded, the sweep goes on
            data[path.name] = {"apps": [], "error": str(exc)[:400]}
        OUT.write_text(json.dumps(dict(sorted(data.items())), indent=1, ensure_ascii=False) + "\n")
        e = data[path.name]
        print(f"{i:4}/{len(files)} {len(e['apps']):3} apps {path.name[:60]}" + (f"  ERROR {e['error'][:80]}" if e["error"] else ""))
    n_apps = sum(len(e["apps"]) for e in data.values())
    print(f"{len(data)} files, {n_apps} applications, {sum(1 for e in data.values() if e['error'])} errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
