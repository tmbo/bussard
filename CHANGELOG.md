# Changelog

All notable changes to bussard are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release, planned as 0.1.0 (#92). This section describes what `main`
does today. A `0.1.0` tag from 2026-09-16 exists but was never released; this
entry supersedes it and is not a diff against it.

### Added

**The model and the ETS import**

- `bussard import` reads an ETS 4, 5 or 6 `.knxproj`, including
  password-protected exports, into a YAML model in `knx/`: `groups.yaml`,
  `links.yaml`, one file per device with its channels, com objects and a
  `parameters:` block. Re-imports are idempotent across renames, keep
  hand-authored edits, and report conflicts (`--mine`, `--theirs`,
  `--interactive`, exit code 3) (#4, #9, #18, #46).
- `bussard validate` checks the model with rule passes E001 to E012 plus
  topology and convention lints (#3, #102).
- `bussard init` starts an empty model from a discovered gateway and reports
  the interface's tunnel slots (#21, #105). `scaffold` writes a group-address
  plan from a room and function list (#103).
- Built-in history: every model-changing command takes a snapshot, and
  `status`, `history`, `show` and `undo` work without git. Pending changes
  render as plain sentences (#110, #112).
- `export` and `import` of a single-file `.bussard` bundle, and `diff` for a
  semantic comparison of two projects or bundles (#99, #111).
- `export-groups` writes group addresses as ETS-importable CSV and XML (#104).
  `doc` generates installation documentation (#97). `ha-config` derives a Home
  Assistant KNX configuration from the same model (#15).
- DPT codecs for the common datapoint types, shared by every surface (#2, #34).

**Programming devices**

- `plan` reads a device's live link tables and shows the diff against the
  model; `apply` writes them: confirm, back up, write, verify. Both run per
  device or over a whole line (`--line`). `apply --line --resume` continues a
  run after a tunnel drop, a killed process or Ctrl-C (#100).
- System B (masks `07B0`, `27B0`, `57B0`): tables are written the way ETS
  writes them, into segments the device allocates (`LdCtrlRelSegment`, then
  memory writes), because real devices refuse the `PID_TABLE` property path
  (#115).
- System 7 (masks `0705`, `0701`, `0700`): `plan`, `apply` and `reconstruct`
  read and write the memory-mapped tables. A link change reloads only the two
  table load-state machines, with no restart (#49, #91).
- `flash` downloads an application program without ETS by interpreting the
  product's load procedure, for System B and System 7 (#43, #49):
  - the parameter image is computed from vendor defaults, the model's
    `parameters:` block and the Dynamic section, including module instances,
    hidden parameter defaults, unions and ETS's DPT 9 rounding (#48, #89, #123,
    #126, #140, #159);
  - on System B, a sparse download starts with a confirmed factory reset
    (erase code 7) and ends with a confirmed restart, like an ETS initial
    download (#117, #129). `--no-factory-reset` leaves the reset out;
  - MCB (size and CRC) integrity checks, including the companion (PEI)
    programs that some ABB and Busch-Jaeger applications load from their
    own object (#145, #151);
  - differential download by default: an object whose resident image already
    matches is skipped; `--full` streams everything (#122);
  - on System 7 masks without `VerifyMode`, segments are read, compared and
    only the differing chunks written (#133);
  - a pre-flight refuses a device that is not factory-fresh unless `--force`
    is given (#79), and shows a parameter-level plan with old and new values
    (#109).
- `flash --parameters-only` rewrites only the parameter memory of a device
  that already runs the application, as the octets that differ, on System B
  and System 7 (#119, #146).
- Parameter read-back: `plan` and `reconstruct` decode a device's parameter
  memory as the exact inverse of the `flash` encoder and list what differs from
  the vendor defaults and from the model (#142).
- `assign` sets an individual address through programming mode, `adopt` runs
  the new-device flow, and `commission --line` walks a bench line: assign,
  check the order number, and optionally flash and apply (#22, #26, #100).
- `reconstruct` rebuilds a model from a live device or line (#23).
  `describe` walks a device's interface objects and property descriptions
  (#72). `scan` discovers devices, their masks and order numbers (#10).
- `backup` snapshots the whole installation read-only; `restore` writes one
  device's tables back through the `apply` path; `replace` guides a device
  swap (#96, #98).
- `audit` reports installation readiness and health, `learn` names and types
  group addresses from live traffic, and `test` runs scripted acceptance tests
  from `tests.yaml` (#93, #95, #101).

**Product data**

- `import-product` reads a vendor `.knxprod` with an MIT-licensed reader,
  including ZIP-wrapped and multi-product archives (`--inner`) (#8, #25).
- An ETS project export (`.knxproj`) also serves as product data: it carries
  the application of every device in the project.
- A product-data pointer index (`data/product-index.json`, 511 entries) maps an
  order number to the vendor's download URL and checksum. bussard never
  redistributes product files (#27).

**Observing the bus**

- `monitor` decodes live telegrams against the model; `capture` records them
  to SQLite; `read` and `write` read and write one group value, typed by the
  GA's DPT (#6, #12).
- KNXnet/IP tunnelling and routing with a cEMI codec, and a single bus-service
  actor that owns the connection (#5, #37).

**MCP server and viz**

- `bussard mcp` serves the model and the bus to an LLM over stdio, in three
  tiers: passive, read (default, rate-limited) and write (`--allow-writes`)
  (#7, #14). Model-edit tools (`knx_set_group`, `knx_add_link`,
  `knx_set_parameter`, `knx_undo` and more) change the YAML with a history
  snapshot, and the server follows the model on disk.
- `--allow-programming` adds `knx_plan_device` and `knx_apply_device`: the
  assistant writes one device's link tables only with the digest of a plan the
  human approved (#118).
- `bussard viz` serves the network as a live bus-spine diagram in the browser,
  with a problems panel, model reload and programming-mode highlighting
  (`--watch-prog`) (#65, #67).

**KNX Data Secure**

- `bussard keyring` inspects an ETS `.knxkeys` export: it verifies the
  signature and decrypts the tool and group keys (#84, #148). The password
  comes from `BUSSARD_KEYRING_PASSWORD`, never a flag.
- `flash`, `apply`, `describe`, `restore`, `plan` and `reconstruct` take
  `--keyring` (or `--tool-key` for a bench device) and run over KNX Data
  Secure. Every secured connection starts with the S-A_Sync handshake ETS uses
  (#71, #90, #153, #170).
- A secured `flash` or `apply` also programs the security object: the group
  key table and the group-object security flags, as the ETS secured download
  does (#156).
- After a restart, `flash` probes the device until its security layer is ready
  and retries an unanswered Sync request (#166).
- The crypto, the handshake and the security-object bytes match an ETS 6.4.1
  capture frame for frame, and a secured download was verified against a real
  installation on 2026-09-23 and 2026-09-24.
- Secured group communication: `monitor` and `capture --keyring` verify and
  decrypt secured group telegrams with the GA's group key and mark them
  `secured`; `read` and `write --keyring` (and MCP, viz) send a secured GA as
  `A_SecureData` and refuse one without a key; a keyless `flash` of an
  activated device names the missing key (#172).
- A secured `flash` or `apply` writes the security individual address table
  (PID 54) like ETS: one `[IA][sequence]` entry per device that sends on a
  secured group address the device listens to, with the sender's keyring
  sequence number. `--secure-sender <IA>` (off by default) adds bussard's own
  tunnel address, so the device accepts `write --keyring`; without it the
  device drops bussard's secured group telegrams. knx-sim enforces the table
  (#181).

**Live progress display**

- `flash`, `apply`, `reconstruct --line` and `scan` draw a live view on
  stderr: step, byte bar, elapsed time, ETA and the last bus event. Piped
  output, `--json`, `TERM=dumb` and `--no-progress` keep the plain text byte
  for byte (#147).

**Simulator and conformance tooling**

- `knx-sim`, a separate workspace, is a strict KNX device simulator for
  System B, System 7 and a Data Secure activated device. It rejects
  out-of-order and out-of-bounds operations the way real devices do.
- `tools/knxtrace` decodes KNXnet/IP captures, diffs downloads, rebuilds the
  memory images from an ETS capture (`image`, `imgdiff`) and verifies and
  decrypts Data Secure frames with a keyring (#124, #152).
- The offline oracle: `flash --dry-run --dump-images` writes the exact images a
  flash would stream, and `scripts/campaign/95-offline-oracle.sh` compares them
  with an ETS capture before any flash (#124).
- A corpus sweep plans every application in the product corpus and gates
  regressions in CI (#69).
- The physical test campaign: downloads for the whole installation are
  byte-identical to ETS, verified against ETS captures of 16 device types of a
  real installation.

**Distribution**

- Release builds for Linux x64 and arm64, macOS arm64 and x64, and Windows
  x64, each with a SHA-256 checksum; the tag must match the crate version
  (#75, #77). Installers `install.sh`, `install.ps1` and a Homebrew formula
  (#106).
- Documentation: README, `docs/SAFETY.md`, the command reference, how-to
  recipes, the owner's first-weekend guide, the handover checklist, the
  collaboration guide and a website (#76, #94, #108, #114).

### Changed

- The workspace is 16 crates on Rust edition 2024 with an MSRV of 1.88, checked
  in CI across all targets (#85, #87, #136).
- The gateway gate, the protected-GA check and the checked group write live
  once in `bussard-service`, which the CLI, the MCP server and viz all call
  (#86).
- One ETS-XML, ZIP and PBKDF2 primitive layer serves the project, product and
  ETS importers (#36, #83).
- `flash` and `apply` use one tunnel per command, negotiate the maximum APDU
  length, and poll for a device after a restart instead of sleeping (#122,
  #136).

### Fixed

- Group writes: DPT-blind 6-bit APCI packing corrupted values on the live bus
  (#59).
- Tunnelling: ACK handling outside the window, a tunnel-slot leak on abort,
  an inbound-burst deadlock, and management commands now use the
  tunnel-assigned source address (#30, #31, #60, #82).
- Management: A_Memory framing, folded-ACK desync, NAK handling, the layer-4
  sequence wrap, and table reads above `0xFFFF` (#33, #52, #57, #80).
- Honest completion: reads confirmed by echo, no phantom write success, and
  `LdCtrlWriteProp` no longer planned as supported but executed as a no-op
  (#32, #54).
- `flash` writes `PID_PROGRAM_VERSION` only to objects the plan loads (#160),
  and no longer emits duplicate segment allocations (#113).
- `describe` on a Data Secure device without a key fails with a hint instead
  of reporting zero objects (#155).
- DPT codec fixes: 5.003 scaling, NaN handling, a UTF-8 boundary panic, and
  the DPT 20 scope (#34).
- A lost KNXnet/IP tunnel (a pulled LAN cable on the IP interface) no longer
  aborts `flash` with "timed out waiting for TUNNELING_ACK". The tunnel
  re-establishes itself for up to 60 s (`BUSSARD_TUNNEL_RECONNECT_SECS`),
  re-sends the pending frame and reports the loss on the bus status; `flash`
  resumes like after a device connection drop, and its read-only pre-flight
  runs again. When the gateway stays away the error names it (#177, S2.6 of
  #90).

### Security

- Writes to a non-loopback gateway are refused unless the user opts in with
  `--allow-remote-gateway` or `BUSSARD_ALLOW_REAL_GATEWAY=1`, and every
  confirmation names the resolved gateway (#74).
- A `protected: true` group address needs `--force` on the CLI and cannot be
  written over MCP at all. The gate fails closed on a model parse error (#13,
  #55).
- Every device write is plan, confirm, back up, write, verify. Without a
  terminal a write needs `--yes`.
- Device commands refuse when another bus device answers at bussard's own
  source address (#120).
- viz binds loopback by default, answers `403` to writes unless armed, and
  refuses unknown `Host` headers against DNS rebinding.
- Untrusted input is bounded: zip bombs, address truncation, unbounded image
  allocation and overflow from vendor XML are refused (#39, #53). Decrypted
  project passwords are zeroized.
- Key material never appears in output: dry runs list secure steps without key
  bytes, and a keyring password is read only from the environment.
- `cargo-deny` gates licenses and sources in CI: no copyleft dependency, and
  crates.io only (#38).

### Known limitations

- KNXnet/IP Secure (encrypted tunnel sessions) is not implemented; a
  Secure-only interface refuses bussard (#71 Phase B).
- ETS3-era products shipped only as encrypted `.vd4` files cannot be flashed
  (#135).
- Some Data Secure memory layouts are still inferred rather than confirmed by
  a capture (#71).
- System 1 and System 2 masks are classified but not programmable; program
  them with ETS. bussard never activates or deactivates Data Secure on a
  device.
- Release binaries are not yet published.

[Unreleased]: https://github.com/tmbo/bussard/commits/main
