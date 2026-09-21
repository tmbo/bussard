# bussard

Open-source Rust CLI that programs, monitors, and decodes a KNX building bus.
The KNX configuration lives as YAML files in `knx/` (reviewable diffs, edited by
humans and LLMs); `bussard` pushes changes to devices over a KNXnet/IP gateway.
It exposes an MCP server so an LLM can drive it. See `README.md` for the
architecture overview.

## License Policy (most important rule)

bussard MUST NEVER take on a copyleft dependency
(GPL/LGPL/AGPL/EPL/MPL/CDDL). This is the whole point of the clean-room
reimplementation, so it is a hard constraint, not a preference.

- The allow-list of permitted licenses lives in `deny.toml` and is enforced by
  `cargo-deny` in CI (the `deny` job). A copyleft dep fails the build.
- Only crates.io is allowed. Git dependencies and alternative registries are
  forbidden (`deny.toml` `[sources]`), partly because a git dep is an easy way
  to smuggle in copyleft code past the license gate.
- The thelsing/knx interop device used in the `virtual-device` CI job IS GPL. It
  is only ever built and run as a SEPARATE external process and talked to over a
  socket. It is never linked into or vendored by any bussard crate.
- Run `cargo deny check` locally after changing dependencies.

## Workspace Layout

This is a Cargo **workspace** of 14 crates under `crates/`, not a single crate.
Shared settings (version, edition, license, MSRV, dependency versions) are
centralized in the root `Cargo.toml` under `[workspace.package]` and
`[workspace.dependencies]`; individual crates inherit them with
`x.workspace = true`.

Crates: `bussard-model` (KNX types, DPT codecs, YAML model), `bussard-project`,
`bussard-transport`, `bussard-monitor`, `bussard-bus`, `bussard-mcp` (MCP
server), `bussard-viz` (the `viz` web server), `bussard-mgmt`, `bussard-prod`,
`bussard-ets` (`.knxproj`/`.knxprod` import), `bussard-secure` (KNX Secure),
`bussard-ha` (Home Assistant), `bussard-download`, `bussard-cli` (the `bussard`
binary).

`knx-sim/` is a separate workspace, excluded from this one on purpose; it must
never gain a path dependency on a `crates/` member.

## Build & Test Commands

- Build: `cargo build`
- Fast type-check: `cargo check --workspace`
- Test (matches CI): `cargo nextest run --workspace --profile ci`
  - nextest does NOT run doc-tests; run them too: `cargo test --workspace --doc`
  - Local default profile fails fast; use `--profile ci` for the full picture.
  - Config and profiles live in `.config/nextest.toml`.
- Test a single crate: `cargo nextest run -p bussard-model`
- Lint (matches CI): `cargo clippy --workspace --all-targets -- -D warnings`
- Format check: `cargo fmt --all --check` (apply with `cargo fmt --all`)
- License / advisory gate: `cargo deny check`
- Documentation: `cargo doc --open`

Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
and the test commands before committing, not just before merging.

## Rust Edition and Toolchain

- Edition: **2024**, set once in `[workspace.package]` (do not set it per crate).
- MSRV: **1.85**, declared as `rust-version` in `[workspace.package]` and gated
  by the dedicated `msrv` CI job (`cargo check` on the 1.85 toolchain). Do not
  use std/lang features newer than 1.85.
- `rust-toolchain.toml` pins the local dev channel to `stable` (with `rustfmt`
  and `clippy`). It does NOT pin the MSRV; that floor lives in `Cargo.toml`.
- Do NOT use nightly features.

## Error Handling

- Libraries: use `thiserror` (v2) — derive `Error` for custom error types.
- Applications/binaries: use `anyhow` (v1) — propagate with `?`, add context
  with `.context()`.
- Never use `.unwrap()` or `.expect()` in library code.
- `.expect()` is acceptable in binary `main()` for setup failures.
- Never use `.unwrap()` in tests — return `Result` and use `?`.
- Propagate errors with `?` unless there is a documented reason to handle
  locally.

## Clippy Policy

- Treat all warnings as errors: `cargo clippy --workspace --all-targets -- -D warnings`.
- Run clippy before committing, not just before merging.
- Do not use `#[allow(clippy::...)]` without a comment explaining why.

## Code Style

- All public items (structs, enums, functions, traits, modules) must have doc
  comments (`///`).
- Private items: doc comments encouraged but not required.
- Prefer explicit type annotations on public function signatures.
- Do not use wildcard imports (`use foo::*`) except in test modules.

## Dependency Policy

- Prefer minimal dependencies — justify each new crate in the PR description.
- All third-party crates must be MIT and/or Apache-2.0 (or another entry on the
  `deny.toml` allow-list). Check with `cargo deny check` before adding one.
- Declare shared dependency versions in the root `[workspace.dependencies]` and
  reference them from crates with `dep.workspace = true`. Match the existing
  style: major-version constraints (`tokio = "1"`), not exact pins.
- crates.io only — no git or alternative-registry dependencies.
- Do not add a crate to solve a problem that can be solved with std in under 20
  lines.

## Testing

- Unit tests: `#[cfg(test)]` module at the bottom of each file.
- Integration tests: the crate's `tests/` directory.
- Test naming: `test_<function_name>_<scenario>` pattern.
- nextest runs each test in its own process; mock-gateway/device tests each bind
  their own `127.0.0.1:0` UDP socket and rely on that isolation.
- Real-import oracle tests decrypt and stream ~15 MB of XML; the crypto and
  parser crates are compiled optimized even in the test profile (see the
  `[profile.test.package.*]` blocks in the root `Cargo.toml`) to keep them fast.
- Mock external dependencies using trait objects, not concrete types.

## Memory Safety and Unsafe

- No `unsafe` blocks without a `// SAFETY:` comment explaining the invariants.
- If `unsafe` is required, isolate it in a dedicated module.
- Prefer `Arc<Mutex<T>>` over raw pointers for shared state across threads.
- Do not use `Rc<RefCell<T>>` in async code (not `Send`).
- If you need `unsafe`, ask before writing it — there may be a safe alternative.
