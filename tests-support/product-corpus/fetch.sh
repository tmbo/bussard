#!/usr/bin/env bash
#
# fetch.sh — populate the product-corpus cache by dogfooding `bussard
# import-product`.
#
# For every order number in corpus.txt this runs
#
#     bussard import-product --order-number <ORDER> --yes-download --dir <cache>
#
# which looks the number up in data/product-index.json, downloads the vendor
# .knxprod over the network, verifies its byte size and SHA-256 against the
# index, and caches it under <cache>/vendor/. That is the exact consent +
# checksum path a user hits, so this script exercises it end to end.
#
# Idempotent: a .knxprod already cached (byte-identical) is left in place, so a
# re-run only fetches what is missing. Copyrighted vendor data never enters git —
# the whole cache/ directory is .gitignored (see .gitignore and the README).
#
# Usage:
#     tests-support/product-corpus/fetch.sh            # build bussard if needed, fetch all
#     BUSSARD=/path/to/bussard tests-support/product-corpus/fetch.sh
#
# Then run the flashability sweep:
#     BUSSARD_PRODUCT_CORPUS=tests-support/product-corpus/cache \
#         cargo test -p bussard-download --test flash_corpus -- --nocapture
#
set -euo pipefail

# Resolve paths relative to this script so it works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORPUS_LIST="$SCRIPT_DIR/corpus.txt"
CACHE_DIR="$SCRIPT_DIR/cache"
INDEX_JSON="$REPO_ROOT/data/product-index.json"

# Maps an order number to the cache filename its index entry downloads to, so a
# re-run can skip an order whose file is already cached. Uses python3 (available
# on any machine that can build the toolchain); falls back to "always fetch" if
# python3 is missing, which is still correct (import-product re-verifies).
cached_filename_for() {
    local order="$1"
    command -v python3 >/dev/null 2>&1 || { echo ""; return; }
    python3 - "$INDEX_JSON" "$order" <<'PY' 2>/dev/null || echo ""
import json, sys
index, order = sys.argv[1], sys.argv[2].strip().upper()
try:
    data = json.load(open(index))
except Exception:
    sys.exit(0)
for e in data.get("entries", []):
    if any(o.strip().upper() == order for o in e.get("order_numbers", [])):
        print(e.get("filename", ""))
        break
PY
}

# Locate (or build) the bussard binary. Honour an explicit $BUSSARD override.
if [[ -n "${BUSSARD:-}" ]]; then
    BUSSARD_BIN="$BUSSARD"
else
    BUSSARD_BIN="$REPO_ROOT/target/debug/bussard"
    if [[ ! -x "$BUSSARD_BIN" ]]; then
        echo "bussard binary not found at $BUSSARD_BIN; building it…" >&2
        (cd "$REPO_ROOT" && cargo build --bin bussard)
    fi
fi

if [[ ! -x "$BUSSARD_BIN" ]]; then
    echo "error: bussard binary not executable: $BUSSARD_BIN" >&2
    exit 1
fi
if [[ ! -f "$CORPUS_LIST" ]]; then
    echo "error: corpus list not found: $CORPUS_LIST" >&2
    exit 1
fi

mkdir -p "$CACHE_DIR"

echo "Fetching product corpus into $CACHE_DIR/vendor/ using $BUSSARD_BIN"
echo

fetched=0
skipped=0
failed=0
# Read order numbers: strip trailing '# comment', trim whitespace, skip blanks.
while IFS= read -r raw || [[ -n "$raw" ]]; do
    line="${raw%%#*}"
    # Trim leading/trailing whitespace.
    order="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$order" ]] && continue

    echo "--- $order ---"
    # Idempotent skip: if this order's file is already cached, don't re-download.
    fname="$(cached_filename_for "$order")"
    if [[ -n "$fname" && -f "$CACHE_DIR/vendor/$fname" ]]; then
        echo "  already cached: vendor/$fname (skipping download)"
        skipped=$((skipped + 1))
        echo
        continue
    fi

    if "$BUSSARD_BIN" import-product \
        --order-number "$order" \
        --yes-download \
        --dir "$CACHE_DIR"; then
        fetched=$((fetched + 1))
    else
        echo "  WARNING: fetch failed for $order (continuing)" >&2
        failed=$((failed + 1))
    fi
    echo
done < "$CORPUS_LIST"

echo "======================================================================"
echo "Fetched $fetched, skipped (already cached) $skipped, failed $failed."
echo "Cached .knxprod files:"
ls -1 "$CACHE_DIR/vendor/"*.knxprod 2>/dev/null | sed 's/^/  /' || echo "  (none)"
echo
echo "Run the flashability sweep with:"
echo "  BUSSARD_PRODUCT_CORPUS=$CACHE_DIR \\"
echo "      cargo test -p bussard-download --test flash_corpus -- --nocapture"

if [[ "$failed" -gt 0 ]]; then
    exit 1
fi
