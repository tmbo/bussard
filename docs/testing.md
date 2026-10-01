# Testing

The default suite needs nothing but the repository:

```console
$ cargo nextest run --workspace --profile ci
$ cargo test --workspace --doc
```

Some tests read data that is never committed: copyrighted vendor product
archives (`.knxprod`) and ETS project exports. They are gated on an
environment variable and skip green without it, so CI and a fresh clone pass
without the data. A gated test prints a `skipping` or `SKIP` line on stderr when
its data is missing; nextest shows that line only for a failing test, so a run
without the data looks the same as a run with it. Run these tests before a
release and after any change to the product parser, the image builder or the
download planner.

## The product corpus (`BUSSARD_PRODUCT_CORPUS`)

The corpus is the vendor archives `tests-support/product-corpus/fetch.sh`
downloads into `tests-support/product-corpus/cache/vendor/` (git-ignored; see
`tests-support/product-corpus/README.md`). Point `BUSSARD_PRODUCT_CORPUS` at an
absolute path: the product-corpus directory, its `cache/`, or the vendor
directory itself. Every gated test resolves all three to the vendor directory.

```console
$ export BUSSARD_PRODUCT_CORPUS="$PWD/tests-support/product-corpus"
$ cargo nextest run --profile corpus \
    -p bussard-download -p bussard-prod -p bussard-cli \
    -E 'binary(flash_corpus) | binary(flash_dryrun_system7) | binary(ets_golden)
        | binary(sys7_jung_m2_plan) | binary(param_readback_roundtrip)
        | binary(parameter_image) | binary(sys7_visible_parameters)
        | binary(selected) | binary(flash_dry_run)'
```

The `corpus` nextest profile (`.config/nextest.toml`) allows a test 20 minutes:
the three `flash_corpus` sweeps plan every application of ~500 archives and
take several minutes each in a debug build. Run one file while iterating, for
example `cargo nextest run --profile corpus -p bussard-download --test
sys7_jung_m2_plan`.

The gated tests:

| Crate | Test file | What it checks |
|---|---|---|
| bussard-download | `flash_corpus.rs` | the conformance sweep against `conformance-manifest.json`, no duplicate consecutive allocations, extended-memory applications lower to executable plans |
| bussard-download | `flash_dryrun_system7.rs` | System 7 plans for MDT `A-000E`, Theben FIX2 `M-0048_A-4947` (ends at the terminal restart), Zennio LUMENTO, Jung `A-A011`, and the Meteodata Hawk verify-mode profile |
| bussard-download | `sys7_jung_m2_plan.rs` | the Jung 3361-1M (0705) full plan against the M2 capture, and its parameter-only plan against `bad-eg-pm-1-1-18.pcapng` (1.1.32) |
| bussard-download | `ets_golden.rs` | group-object tables, parameter image and allocation of the F50 (`A-D142-21`), Jung `A-3030`, ABB `A-A0ED`, Helios `A-0003`, Jung `A-20DE` byte for byte against ETS |
| bussard-download | `param_readback_roundtrip.rs` | parameter read-back decodes what the image builder wrote, for a set of real products |
| bussard-prod | `parameter_image.rs` | the Zennio FIX2 union default byte, the ABB IEEE-754 single width |
| bussard-prod | `sys7_visible_parameters.rs` | Jung System 7 parameter images (3361, 2116, 3181) against ETS |
| bussard-prod | `selected.rs` | a selective archive read equals the full read, on the first archives of the corpus (`BUSSARD_SELECTED_CORPUS_LIMIT`, default 6) |
| bussard-cli | `flash_dry_run.rs` | `flash --dry-run --dump-images` of the Jung 3361-1M |

`BUSSARD_UPDATE_SWEEP_MANIFEST=1` regenerates the sweep baseline instead of
comparing against it; review and commit the diff.

## ETS project exports

| Variable | Tests |
|---|---|
| `BUSSARD_ETS_PROJECT` | `ets_golden.rs`: the `A-D141-22` inactive-channel fill and the `A-2088-11` plan that ends at the restart. The path of a `.knxproj` whose product XML is not encrypted. |

## CI

The `corpus-sweep` job runs the committed-fixture sweep on every push and pull
request. A `workflow_dispatch` run with the `product_corpus` input (or the
repository variable `BUSSARD_PRODUCT_CORPUS`) set to a corpus path on the runner
also runs every corpus-gated test above. A GitHub-hosted runner has no corpus
(CI never downloads vendor data), so that path is for a self-hosted runner; the
owner otherwise runs the command above locally before a release.
