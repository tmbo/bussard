# knx-sim

An independent, strict KNX device + bus **simulator**. It recreates the KNX
*device* side in software so a KNXnet/IP flashing/monitoring tool can be tested
against realistic devices without hardware.

`knx-sim` is a **second, independent implementation** of the KNX
device-management protocol, built from the published KNX spec, the Wireshark KNX
dissector, and real ETS captures — not from any tool's code. Two independent
implementations meeting on the wire is the cross-check: a misconception baked
into one will not be silently mirrored in the other. See `DESIGN.md` for the
architecture.

## What it does today (Phase 1)

- Independent KNXnet/IP tunnelling gateway + cEMI + management-APDU codec
  (`src/wire`, `src/net`).
- Independent `.knxprod` reader for the flash-relevant structure — memory map,
  `LoadProcedures`, load-state-machine layout (`src/prod`).
- Strict **System B** and **System 7** devices (`src/device`): authorize, the
  load-state machine(s), segment allocation, memory read/write bounded to
  allocated segments, `A_Restart` / master reset, device-descriptor read,
  property read/write. Strictness is deliberate — it rejects out-of-order load
  transitions, writes to the wrong object, out-of-range addresses, and
  unauthorized writes. A per-device profile (from the product mask or a `mask:`
  config override) selects the generation; `A_DeviceDescriptor_Read` reports the
  true mask. The System 7 model adds the three parallel absolute memory-mapped
  load-state machines, both LSM realisations (`lsm_access: memory | property`),
  the object-0/PID78 preflight, and System 7 wire strictness (standard frame
  only, ≤12 memory octets — the trap for a tool wrongly sending 63-byte chunks).
  See `DESIGN.md` and `docs/system7-spec.md`.
- A virtual bus with an **observable event stream** (`src/bus`) — the seam a
  future read-only HTML visualization will consume. Today a `TracingSink` logs
  every telegram + state change to stdout.
- File-driven config (`src/config`) that spins up a bus + devices from YAML.

## Run

```sh
cargo run -- examples/da_tp.yaml
# then point a KNXnet/IP tool at 127.0.0.1:3671
```

## Test

```sh
cargo test
```

The key test, `tests/ets_calibration.rs`, replays the **exact** management
sequence ETS captured while flashing the real KNX-Virtual DA.tp device and
asserts the simulator accepts it, reaches `Loaded` on all four objects, and
reproduces ETS's exact memory image — while rejecting deliberate deviations.

## Fixtures

The calibration target is the KNX-Virtual **DA.tp** demo product (application
`M-00FA_A-2500-10-51CB`, mask MV-07B0). Because vendor `.knxprod` files are not
committed (the repo git-ignores `*.knxprod`), place it yourself at:

```
tests/fixtures/KNX_Virtual_M-00FA.knxprod
```

The fixture-backed tests **skip cleanly** (printing `SKIP:`) when it is absent,
so `cargo test` is always green; drop the file in to actually exercise the
calibration. `tests/fixtures/ets_da_tp_flash_requests.txt` (the request-direction
TPDU stream distilled from the ETS capture) *is* committed — it is text, not
vendor product data.

## Independence & license

MIT. crates.io dependencies only; no GPL, no `bussard` crates. This project is a
standalone Cargo workspace (it has its own `[workspace]`), cleanly extractable to
its own repository.

That is enforced, not just asserted:

- `tests/independence.rs` reads `Cargo.toml` and `Cargo.lock` and fails on any
  `path`/`git` dependency, any `bussard` package, or a non-crates.io source.
- `knx-sim/deny.toml` carries the same licence allow-list as the root project.
  `cargo deny --manifest-path knx-sim/Cargo.toml check` runs in CI, so a copyleft
  dependency fails the build here too. `Cargo.lock` is committed for it to read.
- The `knx-sim` CI job runs `cargo fmt --check`, `cargo clippy --all-targets -D
  warnings` and `cargo test` against this manifest on every push.
