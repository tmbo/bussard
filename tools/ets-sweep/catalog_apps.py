# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Map every corpus product file to its application programs (epic #419, part 2 #421).

    uv run tools/ets-sweep/catalog_apps.py [--corpus DIR] [--filter a,b]

For each `.knxprod` in the corpus (and each `.knxprod` nested in it), the
application programs' identity (application id, the untranslated `Name`, mask)
and the order numbers `Hardware.xml` maps to them go to
`tools/ets-sweep/catalog-apps.json` (read from the archive: bussard's product
models carry neither name nor order numbers since #906):

    {"<file>": {"apps": [{"id": "M-0083_A-004F-11-8F33", "name": "Rain sensor",
                          "mask": "0701", "order_numbers": ["SCN-RS1R.01"]}, ...],
                "error": null}}

This is the join between a product file, the catalog entry ETS shows (the
order number is ETS's catalog search term) and the application the sweep
flashes. Labels only, no vendor data. Files with an entry are skipped.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUT = HERE / "catalog-apps.json"

_APP_FILE = re.compile(r"(^|/)(M-[0-9A-F]{4}_A-[^/]+)\.xml$")
_ATTR = re.compile(r'([A-Za-z]+)="([^"]*)"')


def _attrs(tag: str) -> dict[str, str]:
    return dict(_ATTR.findall(tag))


def _scan(z: zipfile.ZipFile, apps: dict[str, dict], orders: dict[str, set[str]]) -> None:
    """Collects the programs and the order-number mapping of one archive,
    descending into nested `.knxprod` files."""
    for name in z.namelist():
        lower = name.lower()
        if lower.endswith(".knxprod"):
            with zipfile.ZipFile(io.BytesIO(z.read(name))) as inner:
                _scan(inner, apps, orders)
        elif lower.endswith("/hardware.xml"):
            text = z.read(name).decode("utf-8", "replace")
            for hw in re.findall(r"<Hardware\b.*?</Hardware>", text, re.S):
                numbers = [_attrs(t).get("OrderNumber") for t in re.findall(r"<Product\b[^>]*>", hw)]
                refs = [_attrs(t).get("RefId") for t in re.findall(r"<ApplicationProgramRef\b[^>]*>", hw)]
                for ref in filter(None, refs):
                    orders.setdefault(ref, set()).update(n for n in numbers if n)
        elif _APP_FILE.search(name):
            with z.open(name) as f:
                head = f.read(1 << 16).decode("utf-8", "replace")
            tag = re.search(r"<ApplicationProgram\b[^>]*>", head)
            if tag:
                a = _attrs(tag.group(0))
                if a.get("Id"):
                    mask = a.get("MaskVersion") or ""
                    apps[a["Id"]] = {"id": a["Id"], "name": (a.get("Name") or "").strip() or None,
                                     "mask": (mask[3:] if mask.startswith("MV-") else mask) or None}


def apps_of(product: Path) -> list[dict]:
    apps: dict[str, dict] = {}
    orders: dict[str, set[str]] = {}
    with zipfile.ZipFile(product) as z:
        _scan(z, apps, orders)
    return [{**apps[i], "order_numbers": sorted(orders.get(i, ()))} for i in sorted(apps)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, default=REPO / "tests-support" / "product-corpus" / "cache" / "vendor")
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
            data[path.name] = {"apps": apps_of(path), "error": None}
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
