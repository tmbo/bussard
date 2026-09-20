# Product-corpus flashability test

A repeatable, network-backed check of one question across a shelf of real vendor
devices: **can bussard flash this today?**

It downloads ~20 real `.knxprod` product databases from a range of manufacturers
and device types, then dry-runs each application program through the flash
engine's planner (`plan_flash`, no device, no bus) and reports which ones lower
to an executable plan, which are refused, and — for the refused System B ones —
which load-procedure op blocked them. That op ranking is the roadmap for
finishing the download interpreter.

Nothing here is committed: vendor product data is copyrighted, so the whole
`cache/` directory is `.gitignored`. A clean machine reproduces the corpus by
running the fetch script, which re-downloads and re-verifies every file.

## Layout

| path              | what it is |
| ----------------- | ---------- |
| `corpus.txt`      | One order number per index entry, with a type/mask comment. The fetch driver. |
| `fetch.sh`        | Downloads each order number via `bussard import-product`, caching under `cache/vendor/`. |
| `cache/`          | Local-only download cache (git-ignored). Created by `fetch.sh`. |
| `fixture-conformance.json` / `.md` | Checked-in conformance baseline for the **committed fabricated fixtures** (`crates/bussard-download/tests/fixtures/corpus/`). Regenerated + diffed by `tests/sweep_fixtures.rs` in normal CI — no vendor data. |
| `conformance-manifest.json` / `.md` | Checked-in conformance baseline for the **full real corpus**, regenerated on a machine that holds the cache (see below). The env-gated sweep fails on a regression against it. Absent on a clean checkout. |
| (the tests)       | `crates/bussard-download/tests/flash_corpus.rs` (env-gated on `BUSSARD_PRODUCT_CORPUS`), `tests/sweep_fixtures.rs` + `tests/golden_images.rs` (always-on, fixture-based). The sweep engine is `bussard_download::sweep`. |

## Conformance sweep

The sweep runs every application in every product through the three stages a real
flash exercises — **parse** -> **image synthesis** -> **plan lowering** — and
buckets the outcome of each (parse-ok/fail/panic; image ok/refused/panicked;
plan executable/refused/not-supported-family/panicked). It emits a stable,
sorted [`SweepManifest`](../../crates/bussard-download/src/sweep.rs) that is
checked in and diffs over time, with refusal reasons ranked by application count
and per-mask-family coverage. A **new refusal or any panic** is a regression the
checked-in baseline catches; a panic is never acceptable and must be converted to
a proper refusal in the engine.

Two tiers, so CI without the big cache still passes:

* **Fixture tier (always on, no cache).** `sweep_fixtures.rs` assembles the
  committed fabricated fixtures into `.knxprod` ZIPs in a temp dir, runs the real
  `read_knxprod` + `sweep_corpus` pipeline, and fails if the buckets drift from
  `fixture-conformance.json`. `golden_images.rs` locks byte-exact images for the
  union / enum-leniency / extension-lie shapes.
* **Full-corpus tier (env-gated).** With `BUSSARD_PRODUCT_CORPUS` set to a
  populated cache, `flash_corpus.rs::corpus_flashability_sweep` sweeps all ~500
  products and fails on a regression vs `conformance-manifest.json`.

Regenerate either baseline by re-running its test with
`BUSSARD_UPDATE_SWEEP_MANIFEST=1` (the full-corpus one also needs
`BUSSARD_PRODUCT_CORPUS` set), then review and commit the diff.

The pointer index the corpus draws from is `data/product-index.json` (schema:
`docs/product-data.md`). `corpus.txt` and the index are kept in step: one order
number per entry is enough, because a single `.knxprod` usually serves a whole
product family.

## Clean-machine repro

From the repo root:

```sh
# 1. Build the bussard binary (fetch.sh will do this for you if needed).
cargo build --bin bussard

# 2. Download + verify the corpus. Idempotent: re-runs skip cached files.
#    Each download is consent-gated and checksum-verified against the index,
#    so this exercises the exact path a user hits with `import-product`.
tests-support/product-corpus/fetch.sh

# 3. Run the flashability sweep against the cache (absolute path).
BUSSARD_PRODUCT_CORPUS="$(pwd)/tests-support/product-corpus/cache" \
    cargo test -p bussard-download --test flash_corpus -- --nocapture
```

Point `BUSSARD_PRODUCT_CORPUS` at an **absolute** path: the test binary runs with
its crate directory as the working directory, so a relative path would resolve
against `crates/bussard-download/`, not the repo root.

`fetch.sh` accepts a `BUSSARD=/path/to/bussard` override if you built the binary
somewhere other than `target/debug/bussard`.

## What the sweep reports

For every `.knxprod` in the cache the test reads it (which must not error), and
for **every** application program it contains attempts a dry-run `plan_flash`
against that application's own declared mask. Each application lands in exactly
one bucket:

- **executable** — the whole load procedure lowered to a `FlashPlan`.
- **refused** — a System B (mask 07B0) app whose procedure carries an op the
  engine cannot execute yet, or an image it cannot resolve. The blocking op is
  recorded and ranked corpus-wide.
- **non-SB** — the app targets a non-07B0 mask (System 7 `0705`/`0701`, System 2
  `0021`, older BCUs). The engine refuses these up front by design; expected and
  common. Mixed-mask files are deliberate — one MDT switch-actuator `.knxprod`
  can carry both a 07B0 app and several 0705 ones.

The test prints a per-product table and a blocking-op ranking, then asserts only
invariants that must hold: `read_knxprod` never errors on a corpus file, every
application is classified, and at least a floor of applications lower to an
executable plan (so the sweep stays meaningful without being brittle).

## CI safety

With `BUSSARD_PRODUCT_CORPUS` unset the test **skips green** — it prints a note
and returns. CI never downloads copyrighted vendor data, so it is unaffected. The
sweep only runs when someone has deliberately populated a cache and pointed the
env var at it.

## Refreshing the index

If a vendor re-publishes a file under the same URL, its size/SHA-256 changes and
`import-product` fails the download with a checksum mismatch (by design — the
file is no longer the one the index vouches for). To refresh: re-download the
file, recompute its `sha256` (`shasum -a 256 <file>`) and `size`
(`wc -c <file>`), update the entry in `data/product-index.json`, and rebuild the
binary (the index is baked in via `include_str!`).
