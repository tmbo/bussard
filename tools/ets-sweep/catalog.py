# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko"]
# ///
"""Import the product corpus into ETS's catalog through the driver (epic #419, part 2 #421).

    uv run tools/ets-sweep/catalog.py [--corpus tests-support/product-corpus/cache/vendor]
                                      [--filter SUBSTR[,SUBSTR]] [--limit N] [--redo]

For every `.knxprod` in the corpus directory (sorted by name): upload it to the
VM unless it is already there, have the driver run ETS's catalog import (file
dialog, "Alle Sprachen importieren", wait for the result panel), and record
the outcome in `tools/ets-sweep/catalog.json`:

    {"<file>": {"outcome": "imported" | "refused" | "error",
                "products": ["<order> <name>", ...], "message": "...",
                "seconds": n, "when": "<iso>"}}

The manifest holds outcome labels and the product names ETS printed, never
vendor data. A file with an outcome is skipped unless `--redo`; ETS refuses
nothing on a second import of the same file (it converts and reports success
again), so a resumed run is idempotent at the file level. `.knxprod.zip`
wrappers are recorded as `skipped` (ETS wants the inner file).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MANIFEST = HERE / "catalog.json"
REMOTE_PRODUCTS = vm.REMOTE_DIR + r"\products"


def load_manifest() -> dict:
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text())
    return {}


def save_manifest(m: dict) -> None:
    MANIFEST.write_text(json.dumps(dict(sorted(m.items())), indent=1, ensure_ascii=False) + "\n")


def upload_if_missing(c, local: Path) -> str:
    remote = f"{REMOTE_PRODUCTS}\\{local.name}"
    sftp = c.open_sftp()
    posix = remote.replace("\\", "/")
    try:
        if sftp.stat(posix).st_size == local.stat().st_size:
            return remote
    except OSError:
        pass
    sftp.put(str(local), posix)
    return remote


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, default=REPO / "tests-support" / "product-corpus" / "cache" / "vendor")
    ap.add_argument("--filter", default="", help="comma-separated substrings of the file name")
    ap.add_argument("--limit", type=int, default=0, help="stop after N imports (0 = all)")
    ap.add_argument("--redo", action="store_true", help="import files that already have an outcome")
    ap.add_argument("--timeout", type=int, default=3600, help="seconds to wait for one import (a multi-product ABB file converts for over 15 min)")
    args = ap.parse_args()

    files = sorted(p for p in args.corpus.iterdir() if p.is_file() and ".knxprod" in p.name.lower())
    wanted = [s for s in args.filter.split(",") if s]
    if wanted:
        files = [p for p in files if any(w.lower() in p.name.lower() for w in wanted)]
    manifest = load_manifest()
    vm.run(c := vm.connect(), f'mkdir "{REMOTE_PRODUCTS}"')
    done = 0
    for path in files:
        entry = manifest.get(path.name)
        if entry and not args.redo:
            continue
        if path.name.lower().endswith(".zip"):
            manifest[path.name] = {"outcome": "skipped", "message": "zip wrapper, ETS wants the inner .knxprod",
                                   "products": [], "seconds": 0, "when": datetime.now(timezone.utc).isoformat()}
            save_manifest(manifest)
            continue
        t0 = time.time()
        remote = upload_if_missing(c, path)
        r = vm.driver(c, "POST", "/ets/catalog_import", {"path": remote, "timeout": args.timeout}, timeout=args.timeout + 60)
        entry = {
            "outcome": r.get("outcome", "error"),
            "products": r.get("products", []),
            "message": r.get("message") or r.get("error", ""),
            "seconds": round(time.time() - t0),
            "when": datetime.now(timezone.utc).isoformat(),
        }
        if entry["products"]:
            # The catalog entry ETS shows: search for the first product's order number.
            order = entry["products"][0].split()[0]
            found = vm.driver(c, "POST", "/ets/catalog_search", {"term": order}, timeout=120)
            entry["verified"] = any(order.lower() in row["text"].lower() for row in found.get("rows", []))
        manifest[path.name] = entry
        save_manifest(manifest)
        print(f"{manifest[path.name]['outcome']:9} {path.name} {manifest[path.name]['seconds']}s {manifest[path.name]['products'][:2]}")
        done += 1
        if args.limit and done >= args.limit:
            break
    counts: dict[str, int] = {}
    for e in manifest.values():
        counts[e["outcome"]] = counts.get(e["outcome"], 0) + 1
    print("manifest:", counts, "of", len(files), "files in the corpus")
    return 0


if __name__ == "__main__":
    sys.exit(main())
