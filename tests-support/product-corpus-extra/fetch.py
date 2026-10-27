#!/usr/bin/env python3
"""fetch.py — re-download every entry of index.json into cache/vendor/.

This is the second, separate product-corpus (see README.md): vendor
.knxprod files found by crawling manufacturer websites, kept apart from
tests-support/product-corpus/ on purpose. Nothing under cache/ is committed;
index.json is the committed pointer list this script rebuilds the cache from.

Usage:
    python3 fetch.py            # or: uv run fetch.py
    python3 fetch.py --force    # re-download even if a verified file is cached

Stdlib only. For every entry it:
  1. skips a file already cached under cache/vendor/<file> whose SHA-256
     matches the index (idempotent re-run);
  2. otherwise downloads `url` with a plain User-Agent, one request at a
     time, with a short pause between requests;
  3. verifies the download's byte size and SHA-256 against the index entry;
  4. on a mismatch, leaves the bad download out of cache/vendor/ and reports
     it — vendors renumber or replace files over time, and a stale pointer
     should fail loudly rather than silently caching the wrong bytes.
"""
import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
INDEX_JSON = HERE / "index.json"
VENDOR_DIR = HERE / "cache" / "vendor"
UA = "Mozilla/5.0 (compatible; bussard-product-corpus-extra/1.0; +https://github.com/)"
PAUSE_SECONDS = 0.5


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_one(entry: dict, force: bool) -> str:
    dest = VENDOR_DIR / entry["file"]
    if dest.exists() and not force:
        if dest.stat().st_size == entry["size"] and sha256_of(dest) == entry["sha256"]:
            return "cached"
        print(f"  WARNING: {dest.name} exists but does not match the index; re-downloading", file=sys.stderr)

    req = urllib.request.Request(entry["url"], headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"  FAILED: {entry['url']}: {e}", file=sys.stderr)
        return "failed"

    size = len(data)
    sha = hashlib.sha256(data).hexdigest()
    if size != entry["size"] or sha != entry["sha256"]:
        print(
            f"  MISMATCH: {entry['file']}: got size={size} sha256={sha}, "
            f"index expects size={entry['size']} sha256={entry['sha256']}",
            file=sys.stderr,
        )
        return "mismatch"

    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return "downloaded"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-download even if already cached and verified")
    args = parser.parse_args()

    entries = json.loads(INDEX_JSON.read_text())
    print(f"{len(entries)} entries in {INDEX_JSON.name}")

    counts = {"cached": 0, "downloaded": 0, "failed": 0, "mismatch": 0}
    for i, entry in enumerate(entries, 1):
        print(f"[{i}/{len(entries)}] {entry['vendor']}: {entry['product']} ({entry['file']})")
        result = fetch_one(entry, args.force)
        counts[result] += 1
        if result == "downloaded":
            time.sleep(PAUSE_SECONDS)

    print()
    print(
        f"cached={counts['cached']} downloaded={counts['downloaded']} "
        f"failed={counts['failed']} mismatch={counts['mismatch']}"
    )
    return 1 if (counts["failed"] or counts["mismatch"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
