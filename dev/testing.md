# Testing

The default suite needs nothing but the repository:

```console
$ cargo nextest run --workspace --profile ci
$ cargo test --workspace --doc
```

Each crate links its integration tests into one binary, `it`: the files live
in `tests/it/`, and `tests/it/main.rs` declares each one as a module. A test's
name starts with its file's module, so `test(/^flash_mock::/)` selects one file
and `cargo test -p bussard-download --test it flash_mock::` runs it. The
`virtual_device` and `virtual_device_flash` suites of `bussard-cli` stay
separate binaries, since CI runs them by name against an external device.

Some tests read data that is never committed: copyrighted vendor product
archives (`.knxprod`) and ETS project exports. They are gated on an
environment variable and skip green without it, so CI and a fresh clone pass
without the data. A gated test prints a `skipping` or `SKIP` line on stderr when
its data is missing; nextest shows that line only for a failing test, so a run
without the data looks the same as a run with it. Run these tests before a
release and after any change to the product parser, the image builder or the
download planner.

## ETS, bussard and knx-sim: the triangle

Three implementations meet on the wire, and each pair checks the other:

- **ETS** is the reference: what it writes to a device is what bussard must
  write. It runs only in the owner's Windows VM and has no scripting
  interface, so it is a capture tool, not a test runner.
- **knx-sim** is an independent strict device, built from the KNX Standard,
  the Wireshark dissector and ETS captures, never from bussard's code
  (`knx-sim/README.md`).
- **bussard** is the implementation under test.

| pair | how it is checked |
|---|---|
| ETS vs sim | calibration replays: knx-sim must accept the request stream ETS sent in a capture, reach `Loaded` and hold the same image (`knx-sim/tests/ets_calibration.rs`, the `*_replay.rs` tests). The ETS sweep (`tools/ets-sweep`) produces such captures by having ETS download into knx-sim. |
| bussard vs ETS | the offline oracle rows: a bussard dry run against the image an ETS capture holds, with a coverage figure ([rows](#the-offline-oracle-rows-bussard_oracle_rows), [coverage](#offline-oracle-coverage)). |
| bussard vs sim | the [flash-then-plan loop](#the-flash-then-plan-loop-against-knx-sim-scriptssim-catalog-loopsh), the `sim-conformance` CI job, the `bussard-testkit` mock device and the `virtual-device` interop job. |

The sim is calibrated against ETS, not against bussard, so a misreading of
the standard that both bussard and the sim share still shows up as a
difference to ETS.

Most of the ETS side is gated on data that cannot be committed:

- the house captures under `captures/` are the owner's installation;
- the vendor `.knxprod` corpus is copyrighted (the oracle rows, `ets_golden`,
  `flash_corpus` and the sim loop need it; even `ets_calibration.rs` skips
  without the KNX Virtual product file);
- the ETS sweep needs the VM and an ETS licence.

CI therefore runs the bussard-vs-sim leg and the committed request-stream
fixtures, but no oracle row: the only ungated oracle test checks that a row
without its capture is skipped. A corpus product also bundles hundreds of
constructs, so a sweep failure is hard to reduce to one regression test.

### The synthetic product catalogue (#596)

[Epic #596](https://github.com/tmbo/bussard/issues/596) plans to close the
triangle without vendor data: a catalogue of small fabricated `.knxprod`
files under the KNX test manufacturer `M-00FA`, one construct per product
(a little-endian float, a `<choose>` that writes part of a segment, a
master reset with an erase code, and so on, taken from the `needs-capture`
backlog). ETS downloads each one into knx-sim in the VM once; the capture is
ours and is committed with a manifest of the ETS version and the product
XML hash. CI then replays the captures: the oracle rows run `--check`
ungated, knx-sim replays each capture as a calibration test, and the sim
loop runs the catalogue. The epic's checklist tracks the captures and the
CI wiring that are still open.

The products live in `tests-support/synthetic-products/`: one TOML spec per
product, rendered by `generate.py` into committed product XML, which
`bussard-prod` and knx-sim read in an ungated test each. Its README holds the
spec schema, the id and master-data rules, the render, sign and capture flow
and the catalogue table.

The rule that holds now and after #596: ETS is a capture tool, CI runs on
captures. A question about what ETS writes is answered by a capture (house,
sweep or, once it exists, a synthetic product), never by reasoning about
what ETS probably does. A capture is retaken when the product XML or the ETS
version changes.

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
    -E 'binary(it) & test(/^(flash_corpus|flash_dryrun_system7|ets_golden|sys7_jung_m2_plan|param_readback_roundtrip|parameter_image|sys7_visible_parameters|selected|evaluator_conformance|flash_dry_run|offline_oracle)::/)'
```

The `corpus` nextest profile (`.config/nextest.toml`) allows a test 20 minutes:
the three `flash_corpus` sweeps plan every application of ~500 archives and
take several minutes each in a debug build. Run one file while iterating, for
example `cargo nextest run --profile corpus -p bussard-download --test it
sys7_jung_m2_plan::`.

The gated tests:

| Crate | Test file (`tests/it/`) | What it checks |
|---|---|---|
| bussard-download | `flash_corpus.rs` | the conformance sweep against `conformance-manifest.json`, no duplicate consecutive allocations, extended-memory applications lower to executable plans |
| bussard-download | `flash_dryrun_system7.rs` | System 7 plans for MDT `A-000E`, Theben FIX2 `M-0048_A-4947` (ends at the terminal restart), Zennio LUMENTO, Jung `A-A011`, the Meteodata Hawk verify-mode profile, and the Meteodata C4 page octets the write mask owns (#320) |
| bussard-download | `sys7_jung_m2_plan.rs` | the Jung 3361-1M (0705) full plan against the M2 capture, and its parameter-only plan against `bad-eg-pm-1-1-18.pcapng` (1.1.32) |
| bussard-download | `ets_golden.rs` | group-object tables, parameter image and allocation of the F50 (`A-D142-21`), Jung `A-3030`, ABB `A-A0ED`, Helios `A-0003`, Jung `A-20DE` byte for byte against ETS |
| bussard-download | `param_readback_roundtrip.rs` | parameter read-back decodes what the image builder wrote, for a set of real products |
| bussard-prod | `parameter_image.rs` | the Zennio FIX2 union default byte, the ABB IEEE-754 single width |
| bussard-prod | `sys7_visible_parameters.rs` | Jung System 7 parameter images (3361, 2116, 3181) against ETS |
| bussard-prod | `selected.rs` | a selective archive read equals the full read, on the first archives of the corpus (`BUSSARD_SELECTED_CORPUS_LIMIT`, default 6) |
| bussard-prod | `evaluator_conformance.rs` | the Dynamic evaluator over each program's product model gives the same modules, placements, containers and values as over its XML, at the vendor defaults and under 50 seeded random value sets (#345) |
| bussard-cli | `flash_dry_run.rs` | `flash --dry-run --dump-images` of the Jung 3361-1M |
| bussard-cli | `offline_oracle.rs` | the offline-oracle rows pass `--check` (needs `BUSSARD_ORACLE_ROWS`, see below) |

`BUSSARD_UPDATE_SWEEP_MANIFEST=1` regenerates the sweep baseline instead of
comparing against it; review and commit the diff.

## The offline oracle rows (`BUSSARD_ORACLE_ROWS`)

`offline_oracle.rs` (bussard-cli) runs `scripts/campaign/95-offline-oracle.sh
--check` over the campaign rows files with the build's `bussard` (issue #347).
Every row whose capture and product exist must give its expected verdict
(identical unless the row says `expect=...`) and at least the coverage recorded
in its `coverage` column; rows without a capture are skipped. Coverage is the
share of the octets bussard places that the capture holds, per segment and per
256-octet page; a matching row below 50 %, or with a page that has placed
octets and none compared, is "not comparable (thin)". The row format, the
`#@` per-file options and the coverage rule are documented in the script
header.

| Variable | Meaning |
|---|---|
| `BUSSARD_ORACLE_ROWS` | rows files, `:`-separated; relative to `BUSSARD_ORACLE_ROOT` |
| `BUSSARD_ORACLE_ROOT` | where the rows' relative capture and product paths resolve (default: the workspace root) |
| `BUSSARD_ORACLE_DIR` | the model directory for every file (`--dir`; else the file's `#@ --dir`, else `knx`). Use a copy. |

```console
$ BUSSARD_ORACLE_ROWS=captures/campaign/rows/rows-house-16.txt BUSSARD_ORACLE_ROOT=$PWD \
    BUSSARD_ORACLE_DIR=/tmp/knx-copy \
    cargo nextest run --profile corpus -p bussard-cli -E 'test(/^offline_oracle::/)'
```

The ungated `test_offline_oracle_check_skips_a_row_without_its_capture` runs
the script's `--check` path on every CI run (POSIX hosts with `python3`).

## The flash-then-plan loop against knx-sim (`scripts/sim-catalog-loop.sh`)

The loop (issue #346) runs every application of the corpus that bussard
flashes and knx-sim models (masks `07B0`, `0705`, `0701`) through the
programming cycle against a simulated device:

1. Configurations: the vendor defaults, plus N seeded generated ones. A
   generated one flips the parameters the product's pages are gated on (the
   enable switches `bussard device` lists for an inactive page) with
   probability 2/3 and gives any other shown parameter a random valid value
   with probability 1/4, over a few rounds so a switch a flipped one shows
   gets its turn. Each configuration links a few of the com-objects it shows.
2. Each configuration is flashed to a factory-fresh simulated device with
   `bussard flash`, and `bussard plan --json` must be a no-op: no change, no
   table or parameter write, and the parameters decoded.
3. On the last configuration: `bussard apply` of a partial change (up to
   three parameters that keep the object table, one link removed, one
   added), a plan (no-op), a full flash, a plan (no-op). Then the first
   configuration is flashed over it without `--force`, and planned.
4. Data Secure (the same cycle with security on, plus admission and
   unsecuring a group address) is not part of the loop yet: it waits for the
   secure group simulation (`feat/secure-group-sim`).

```console
$ export BUSSARD_PRODUCT_CORPUS="$PWD/tests-support/product-corpus"
$ scripts/sim-catalog-loop.sh                          # the whole corpus
$ scripts/sim-catalog-loop.sh --filter A-140C,A-A0ED   # some applications
$ scripts/sim-catalog-loop.sh --subset                 # the curated CI subset
```

The script reads the corpus and never downloads. To run the subset locally,
cache its archives once (the order numbers are the first field of `SUBSET` in
the script) and point the variable at the corpus:

```console
$ cargo build --bin bussard
$ printf '%s\n' '2CDG 110 283 R0011' 52921ST 1409207 SCN-P360D3.03 > /tmp/subset.txt
$ CORPUS_LIST=/tmp/subset.txt tests-support/product-corpus/fetch.sh
$ BUSSARD_PRODUCT_CORPUS="$PWD/tests-support/product-corpus" \
    scripts/sim-catalog-loop.sh --subset
```

An application whose archive is missing or unreadable is listed as
`skip ... archive not in corpus` in the summary and does not fail the run.

The script builds knx-sim's `serve` binary (release: it parses the archive at
every start, ten times faster than a debug build) and runs the corpus-gated test
`crates/bussard-cli/tests/it/sim_catalog_loop.rs` (gated on
`BUSSARD_PRODUCT_CORPUS` and `BUSSARD_KNX_SIM_BIN`). The simulator runs as a
separate process on a loopback port, one per configuration; no bussard crate
links it, and every `bussard` command gets an explicit `127.0.0.1` gateway.
The applications are split over eight test functions that nextest runs in
parallel, and over runners with `--shard <k>/<n>`. `--configs N` sets the
number of generated configurations (default 2), `--seed` the generator seed
(default 346), so a failure replays with the same values.

The summary lists every failing application with its first failing step and
what differs (the plan's changed parameters, octets and links, or the last
lines of a refused command). Each application's model, sim config, sim log and
the device file of every configuration are kept under the work directory when
`BUSSARD_SIM_LOOP_WORK` names one. Failures the loop knows about are listed
with their step (and the issue that tracks them) in
`tests-support/product-corpus/sim-loop-baseline.json`; an
application that fails at another step, or is not listed, fails the run.
`--update-baseline` rewrites the file from a run; review and commit the diff.
New corpus applications join the loop on their own.

## ETS project exports

| Variable | Tests |
|---|---|
| `BUSSARD_ETS_PROJECT` | `ets_golden.rs`: the `A-D141-22` inactive-channel fill and the `A-2088-11` plan that ends at the restart. The path of a `.knxproj` whose product XML is not encrypted. |
| `BUSSARD_ETS_PROJECTS` | `bussard-cli` `import_corpus_clean.rs` (issue #348): `bussard import` of every `.knxproj` in this directory (else the one `BUSSARD_ETS_PROJECT` names), then `bussard validate`, reports no error and no warning. `BUSSARD_PROJECT_PASSWORD` opens the exports; a `<stem>.knxkeys` next to an export is imported with `BUSSARD_KEYRING_PASSWORD`. A project with a genuine ETS-level problem lists its expected `CODE location` lines in `<stem>.expect` next to it or in `crates/bussard-cli/tests/fixtures/import-clean/`. Run it with `--profile corpus`; it takes a few minutes. |

## A model snapshot with the Meteodata (`BUSSARD_METEO_SNAPSHOT`)

Point `BUSSARD_METEO_SNAPSHOT` at a model snapshot directory that holds the
Theben Meteodata 1.1.202 (for example `knx/.bussard/history/20261023T190946Z-001`).
The archive `M-0048_A-140C-14-EB70.knxprod` is read from `BUSSARD_METEO_KNXPROD`,
else from `<snapshot>/../../../products/`. The tests copy what they need into a
temporary directory and never write to the snapshot.

| Crate | Test file (`tests/it/`) | What it checks |
|---|---|---|
| bussard-prod | `evaluator_conformance.rs` | the page evaluator and the download's Dynamic evaluator reach the same refs for the device's values, and every "ignored" value is one the image leaves out (#326) |
| bussard-mcp | `capabilities.rs` | `knx_set_parameter helligkeitsschwelle@P-7305_R-7305` is taken once C4's function is Helligkeitssensor, without "Wenn Temperatur" being set (#326) |

## Offline oracle coverage

`scripts/campaign/95-offline-oracle.sh` replays an ETS download capture
against a bussard dry run and compares the two images per row. An "identical"
verdict counts only as far as the row reaches: the coverage figure is the
number of compared octets over the placed octets, per segment and per page,
from `knxtrace imgdiff` and the summary table of the oracle script. A row
below the threshold, or with a placed page it never compares, is "not
comparable" rather than "identical". The figure, the threshold and the capture
plan for devices without a row are defined in
[#347](https://github.com/tmbo/bussard/issues/347). A PR that changes a device
write names its rows and their figures.

## CI

The `sim-conformance` job also runs the KNX IP interface loop
(`sim_interface_loop`, issue #391): it builds knx-sim's `serve`, starts a
simulated interface with no product file, applies a `[knxnet]` table to it
with `bussard apply` and requires the plan after it to be a no-op. Locally:
`cargo build --manifest-path knx-sim/Cargo.toml --bin serve`, then
`BUSSARD_KNX_SIM_BIN=$PWD/knx-sim/target/debug/serve cargo nextest run -p
bussard-cli -E 'test(/sim_interface_loop/)'`.

The same step runs `sim_interface_secure` (issue #398): a simulated interface
in factory state (`security: { status: factory, tool_key: <FDSK> }`, Data
Secure tool access under the FDSK, security mode off) whose gateway is its own
KNXnet/IP server (`gateway.interface_device: "1.1.200"`). `bussard interface
secure on` switches it on; at the master reset the sim's gateway turns to
secure-only tunnelling with the credentials the interface was given, and the
read-back runs over a KNXnet/IP Secure session with the key store's
credentials. `off` switches it back to plain. The sim also serves KNXnet/IP
device management for that interface (a type 3 CONNECT,
`DEVICE_CONFIGURATION_REQUEST` with cEMI `M_PropRead`/`M_PropWrite`/`M_Reset`
and `T_Data_Connected`, as ETS sends them; `knx-sim/tests/interface_device_management.rs`).

The `corpus-sweep` job runs the committed-fixture sweep on every push and pull
request. The `sim-catalog-loop` job runs the flash-then-plan loop over the
curated subset (`--subset`) and needs the corpus like the corpus-gated tests:
it runs only when the `product_corpus` input or the repository variable
`BUSSARD_PRODUCT_CORPUS` names a corpus on the runner, and is skipped (green)
otherwise. It never downloads from the vendor sites; a subset application
whose archive is not in the corpus is reported as `skipped: archive not in
corpus` and does not fail the run. The `sim-catalog-nightly` workflow
runs it over the whole corpus in 12 shards every night (and on demand), with
`--update-baseline`, and uploads each shard's baseline and reports as
artifacts; it is not a required check. A `workflow_dispatch` run with the `product_corpus` input (or the
repository variable `BUSSARD_PRODUCT_CORPUS`) set to a corpus path on the runner
also runs every corpus-gated test above. A GitHub-hosted runner has no corpus
(CI never downloads vendor data), so that path is for a self-hosted runner; the
owner otherwise runs the command above locally before a release.

## Test knobs

The CLI reads these environment variables only to shorten its waits in the
test suites and the simulator loops. They are not documented for users and
stay unset in normal use.

| Variable | Meaning |
|---|---|
| `BUSSARD_SECURE_ALGORITHM` | `auth` wraps KNX Data Secure management APDUs authentication-only (in the clear under a MAC) instead of the default authentication + encryption. For the conformance loop against the simulator; a real flash never sets it: the standard allows the tool key with authentication + confidentiality only (KNX 3/5/1 §6.3.10.4), even though TSS J §3.1.1 expects a device to accept the authentication-only form. |
| `BUSSARD_FLASH_SYS7_LSM` | `memory` or `property` overrides the product-driven System 7 load-state-machine realisation (memory-mapped record or PID 5). For conformance tests against knx-sim; unset in normal use. |
| `BUSSARD_ASSIGN_WAIT_MS` | shrinks the programming-mode wait budget of `assign` and `adopt`. Unset in normal use. |
| `BUSSARD_SCAN_DISCOVERY_MS` | shrinks the per-address probe timeout of `scan`, `reconstruct --line`, `commission`, `backup` and `replace`. Unset in normal use. |
| `BUSSARD_ADDRESS_PROBE_MS` | shrinks the per-attempt timeout of the source-address check (default 600 ms). Unset in normal use. |
| `BUSSARD_CONNECT_WAIT_MS` | shrinks how long a command waits for the first tunnel connect (default 10 s). Unset in normal use. |
| `BUSSARD_MGMT_TIMEOUT_MS` | shrinks the management ACK and response timeouts (default 3 s each) and caps the KNX Data Secure sync retry backoff (default 1 s doubling to 4 s, or 8 s after a restart). Repetitions and attempts are unchanged. Unset in normal use. |
| `BUSSARD_BUS_BACKOFF_MS` | shrinks the first reconnect backoff of the bus connection (default 1 s, doubling to 30 s). Unset in normal use. |
| `BUSSARD_READ_TIMEOUT_MS` | shrinks how long `read` waits for a group response (default 3 s). Unset in normal use. |
