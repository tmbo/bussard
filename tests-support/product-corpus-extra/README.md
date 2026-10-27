# Product-corpus-extra: a second, separate vendor-file collection

This is a **second** corpus of real KNX `.knxprod` product databases, found
by crawling vendor websites directly (not `bussard import-product
--order-number`, not `data/product-index.json`). It exists to widen test
coverage beyond `tests-support/product-corpus/` without touching that corpus,
its pointer index, or anything under `data/`.

**Kept strictly separate from `tests-support/product-corpus/`:**

- Different directory, different pointer index (`index.json` here vs.
  `data/product-index.json`), different cache (`cache/vendor/` here vs.
  `tests-support/product-corpus/cache/vendor/`).
- No overlap: anything whose SHA-256 already appears in
  `data/product-index.json`, or whose file name already exists under
  `tests-support/product-corpus/cache/vendor/`, was left out and recorded in
  `skipped.json` instead of being downloaded here.
- Nothing here feeds `bussard`'s built-in index, the flashability sweep, or
  any crate. It is a raw materials shelf for whoever next wants to extend
  that sweep or the pointer index with new vendors.

**Nothing under `cache/` is committed.** Vendor product data is copyrighted,
exactly as for the main corpus; see the repo root `CLAUDE.md`. `cache/` is
git-ignored (see `.gitignore`). Only the pointers in `index.json` (and the
`skipped.json` dedup log) are checked in.

## Layout

| path            | what it is |
| --------------- | ---------- |
| `index.json`    | Committed pointer index: one entry per collected `.knxprod`, with vendor, product name, URL, source page, size, SHA-256 and local file name. Schema below. |
| `skipped.json`  | Files the crawl found but did not download because they duplicate something already in the main corpus (by SHA-256 or file name). Keeps the "no duplicates" rule auditable. |
| `fetch.py`      | Re-downloads every `index.json` entry into `cache/vendor/` and verifies size + SHA-256. Stdlib only. |
| `cache/vendor/` | The downloaded files (git-ignored). Created by `fetch.py`. |

## Index schema

`index.json` is a JSON array; each entry:

| Field            | Meaning |
| ---------------- | ------- |
| `vendor`         | Manufacturer name as the site calls itself, e.g. `"Ekinex"`. |
| `product`        | Product name/title as the vendor's page calls it (often the page `<title>`). |
| `order_numbers`  | Order numbers shown on the page, if any; `[]` when the page didn't give one. |
| `url`            | The direct download URL (a bare `.knxprod`, or the `.zip` it was extracted from). |
| `source_page`    | The product page the link was found on. |
| `size`           | Byte size of the **extracted `.knxprod`** (not the surrounding zip, when there was one). |
| `sha256`         | Lower-case hex SHA-256 of the extracted `.knxprod`. |
| `file`           | Local file name under `cache/vendor/`. |
| `fetched`        | ISO date the file was downloaded and verified. |

This mirrors `data/product-index.json`'s schema (see
`docs/reference/product-data.md`) minus the `bussard`-specific fields
(`manufacturer_id`, `application_ref`, `redistributable`) that only apply to
entries the CLI's built-in index resolves order numbers against.

## Refreshing the collection

```sh
cd tests-support/product-corpus-extra
python3 fetch.py          # or: uv run fetch.py
```

Idempotent: a file already cached with a matching size and SHA-256 is left in
place; only missing or mismatched files are re-downloaded. A SHA-256 mismatch
against the index is reported and left out of the cache rather than silently
accepted — it means the vendor replaced the file at that URL, so the index
entry needs a fresh look (same policy as the main corpus's
"Refreshing the index" section).

## How this was built

A one-off, polite, breadth-first crawl of vendor sites (sitemap or
download/product-listing page -> product pages -> `.knxprod` or
`.knxprod`-bearing `.zip` links), one request at a time with a short pause
between requests, respecting `robots.txt`, skipping anything behind a login
or JavaScript-only catalog. There is no standing crawler script committed
here (the per-vendor scraping logic was one-off and vendor-specific); re-running
the harvest means repeating that process by hand for whichever vendors are
still worth covering. `fetch.py` only replays the download half from
`index.json`.
