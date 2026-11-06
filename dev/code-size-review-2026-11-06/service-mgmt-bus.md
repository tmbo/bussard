# bussard-service, bussard-mgmt, bussard-bus review

Total product lines (loc.py rule): bussard-service 16 966, bussard-mgmt 6 625, bussard-bus 720.

Verdict up front: these three crates are not where 40 % comes from. The service
crate is already the "one copy" layer CLAUDE.md asks for, and most of its bulk is
orchestration and operator-facing sentences, not duplicated logic. What is
duplicated is (a) small helpers copied per module, (b) the same read/walk
skeleton written five times, and (c) report-row mirror types. Realistic savings
inside the three crates: ~1 700 lines (~7 %). The one finding that moves the
workspace needle (F1) removes ~700 lines from the surfaces, not from here.

## Module inventory (bussard-service, product lines, external callers)

| module | lines | callers | overlaps with |
|---|---|---|---|
| params.rs | 1325 | cli, mcp | bussard-download param rows (mirror structs), verify.rs |
| ip_secure.rs | 1069 | cli, mcp | bus.rs session skeleton; 4 `match Step` tables |
| verify.rs | 742 | cli, mcp | params.rs read-back prologue |
| admission.rs | 733 | cli, mcp | `_with` doubles |
| knxnet.rs | 713 | cli, mcp | verify.rs (own leftovers), chain() |
| line.rs | 671 | cli, mcp | **single-device apply in cli/apply_cmd.rs and mcp/tools_program.rs** |
| flash_flow.rs | 647 | cli, mcp | – |
| enroll_session/* | 939 | mcp, viz | – (feature-sized, keep) |
| assign.rs | 581 | cli, mcp | identity.rs, replace.rs, reconstruct_line.rs, backup.rs (identity reads) |
| adopt/flow.rs + adopt.rs | 706 | cli, mcp | – |
| secure.rs | 506 | all | – |
| setup/products.rs | 477 | cli, mcp | files/products.rs (order download) |
| reconstruct_line.rs | 446 | cli, mcp | scan.rs (sweep loop, discovery_timeouts, DISCOVERY_MS_ENV), identity reads |
| backup.rs | 432 | cli, mcp | parse_line, session_error_detail, identity reads |
| commission.rs | 373 | cli, mcp | line.rs (targets_on_line, Status) |
| scan.rs | 302 | cli, mcp | reconstruct_line.rs, line.rs (parse_line) |
| bus.rs | 251 | all | – |
| the rest (34 files) | ~5 000 | mixed | small |

bussard-mgmt: connection.rs 1329 (TL state machine + ~250 lines of property/descriptor helpers), load.rs 934, property_ext.rs 615, memory.rs 477, apci.rs 468, tables.rs 465, knxnet.rs 404, sys7.rs 378, profile.rs 243, ip_secure.rs 204, device.rs 201, error.rs 196, probe.rs 186, secure.rs 148, io_list.rs 135, broadcast.rs 116, lib.rs 74. Every public item has a caller in download/service except the responder-side codecs (F6).

bussard-bus: lib.rs 608 (actor) + ops.rs 112. Proportionate; nothing to cut beyond ~30 lines of process globals.

## Findings (largest first)

### F1. The single-device apply is written three times; the service has it once as the line visit: est. save: ~700 lines in cli + mcp, 0 here (confidence high)
- Where: `crates/bussard-service/src/line.rs:311-616` (`visit`, 262 lines) is a complete apply of one device: resolve product, read live tables + object-table check, plan, refuse unsupported mask, fingerprint, backup, lease, `write_sys7` / `write_system_b_seeded`, verify after restart, record PID 54. `crates/bussard-cli/src/apply_cmd.rs:560-1100` (452 lines, `write_tables_then_parameters` + helpers) and `crates/bussard-mcp/src/tools_program.rs:1950-2520` (515 lines) each do the same sequence again with `write_tables_seeded`, `download::write_parameters`, `verify::read_back`, their own `Expected` construction and their own `L4Options`. `write_system_b_seeded`/`write_sys7` have no caller outside line.rs; `write_tables_seeded` has none outside the two surfaces.
- What: this is exactly the #314 shape CLAUDE.md warns about. The MCP apply and the CLI apply can drift (and have: the MCP one carries its own `'write:` block with JSON merged at each step).
- Proposal: promote `line::visit` into `service::apply::apply_device(ctx, target, mode, observer) -> DeviceOutcome` with a structured outcome (tables result, parameter result, read-back, backup path, lock records) and a progress observer trait like `FlashObserver`. `visit_device` becomes a loop over it; the CLI prints the outcome, the MCP job serialises it. Then delete the two surface copies.
- Risk: write path change; needs the `95-offline-oracle.sh` plain and `--keyring` apply rows and the mock apply tests on both surfaces. No byte change on the wire is intended, so the oracle should stay identical.

### F2. Five copies of "read a device's identity", plus per-module copies of chain/hex/clean_ascii/one_line: est. save: ~190 (high)
- Where: `assign.rs:484-560,697-725` (identify + read_manufacturer/read_serial/read_order), `identity.rs:297-350` (identify), `replace.rs:291-340`, `reconstruct_line.rs:230-270`, `backup.rs:325-390`: each opens a session, reads the descriptor, best-effort authorizes, then reads PID_MANUFACTURER_ID / PID_SERIAL_NUMBER / PID_ORDER_INFO with the same `len() >= 2`, `filter(!is_empty)`, `clean_ascii` handling. `fn chain(err)` is defined in params.rs, verify.rs, line.rs, knxnet.rs (and mcp tools_program.rs); `fn hex` 6 times in the crate; `clean_ascii` 3 times (identity.rs pub, backup.rs, reconstruct_line.rs); `one_line` in line.rs, cli/commission_cmd.rs, model/device_view.rs; `session_error_detail` in line.rs and backup.rs.
- Proposal: one `identity::read_identity(dev) -> Identity` (mask, manufacturer, serial, order, hidden-mask short cut) used by all five; one `util.rs` with `chain`, `hex`, `clean_ascii`, `one_line`, `session_error_detail` (or put `chain` on `ServiceError` as `Display` with `{:#}`).
- Risk: none on the wire; wording of a few errors unifies.

### F3. Four line walkers with four observer styles and three line parsers: est. save: ~220 (medium)
- Where: `scan.rs:302-352` (`sweep`, `SweepEvent` enum), `reconstruct_line.rs:164-198` (`sweep_line`, `SweepObserver` trait), `backup.rs:196-220` (`capture_devices`, `BackupProgress` enum), `commission.rs:310-330` (`probe_line`, `FnMut`). Line parsing: `scan.rs:71-110` (`LineError` enum + `parse_line`), `line.rs:48-80` (`LineError(String)` + `parse_line`), `backup.rs:64-135` (`TargetError` + `parse_line`); `targets_on_line` in `line.rs:171` and `commission.rs:82`; `discovery_timeouts` + `DISCOVERY_MS_ENV` in `scan.rs:31-55` and `reconstruct_line.rs:46-62` byte for byte; `probe_options` (scan) vs `read_options` (line) vs the inline `L4Options` in reconstruct_line/backup (48 `L4Options {` literals across service+surfaces).
- Proposal: `line::parse_line` once (the `LineError` enum form, so `backup` can map it); `line::walk(service, addresses, |addr| async …, &mut on_event)` with one `WalkEvent {Probing, Probed}`; `commission::LineRun` (97 lines of cursor/verdict bookkeeping, `commission.rs:184-310`) replaced by the walk plus a verdict map; `L4Options::read_only(source)`, `L4Options::discovery(source)`, `L4Options::secured(source, key, hw)` constructors instead of 48 struct literals.
- Risk: none on the wire; the CLI's resume-state file for `apply --line` keeps its own loop.

### F4. params.rs re-states bussard-download's parameter rows as "JSON" mirror types: est. save: ~250 (medium)
- Where: `params.rs:414-560` (`ReadingJson`, `DifferenceJson`, `Readback`, `ParamDetail`, `ParamState`), `params.rs:846-900` (`reading_json`, `kept_rows`, `report` conversions), `params.rs:898-1060` (`ParameterChange`, `OctetAttribution`, `OctetParameter`, `octet_attributions`). `ParameterChange` has the same four fields as `DifferenceJson`; `ReadingJson` is `ParamReading` field for field; `OctetParameter` is `OctetOwner` with `file_key` applied; `FlashedParameters` (706-775) is a subset of `Readback` with its own `failure()`; `read_state` (559-705) and `read_flashed_parameters` (776-834) share a 40-line prologue (DynamicMemo, `plan_for_readback_with`, `read_parameter_regions`, `regions_memory`, `model_parameters`, `decode_parameters_with`).
- Proposal: derive `Serialize` on `bussard_download::{ParamReading, ParamChange, OctetRange, OctetOwner}` and have the decoder take the `Device` so keys are file keys at the source (`file_key` moves next to `decode_parameters_with`); drop the five mirror types and three converters; one `Readback` type with `FlashedParameters` as `Readback` plus `compared`; one `decode_on_session(l4, …) -> Decoded` prologue used by both reads.
- Risk: JSON field names are part of the MCP/CLI `--json` output; keep them via `#[serde(rename)]`. Oracle rows unaffected (read side).

### F5. ip_secure.rs: a private session skeleton, four `match Step` tables, a hand-rolled KeyStore clone: est. save: ~190 (medium)
- Where: `ip_secure.rs:1212-1295` (`open` + `connection`: open bus, checked_source, connect_l4, run, disconnect = `BusService::with_l4` again with one twist, the no-disconnect after master reset); `describe()` 353-392, `step_records()` 401-508, `step_property()` 1046-1060, `run_steps()` 932-978: four matches over the same eight `Step` variants; `store_clone` 900-912 and `same_credentials` 872-898 exist because `KeyStore` has no `Clone`/`PartialEq`; `SwitchError` 1125-1180 has three `{stage, source}` variants plus a private `BodyError` adapter.
- Proposal: `Step::wire(&self, plan) -> StepWire {object_type, pid, start, value}` once; `describe`, `records` and `run_steps` derive from it (run_steps still calls the typed `wire::*` writers, but picks them from one table); derive `Clone, PartialEq` on `KeyStore` (bussard-project); `SwitchError::At { stage, source: Box<dyn Error + Send + Sync> }`; `with_l4` grows a `keep_open_after: impl Fn(&T) -> bool` or the connection body returns the session, so ip_secure needs no private copy.
- Risk: `records()` feeds the `--dump-images` oracle (`tools/knxtrace`); keep its output byte-identical (it is a pure refactor of the table).

### F6. bussard-mgmt ships the device-side (responder) codecs that no product code calls: est. save: ~215 (high)
- Where: `apci.rs`: `encode_property_value_response`, `encode_memory_response`, `encode_property_description_response`, `decode_property_value_read`, `decode_memory_write`, `decode_memory_extended_request`, `encode_memory_extended_write_response`, `encode_memory_extended_read_response`, `decode_property_description_read`, `encode_user_memory_response`, `decode_restart_response_full` (124 fn lines) and the structs `PropertyValueRead`, `PropertyDescriptionRead`, `MemoryWrite`, `ExtendedMemoryRequest` (~21); `property_ext.rs`: `encode_property_ext_value_response`, `encode_property_ext_write_con_response`, `decode_property_ext_write_con_response`, `encode_property_ext_description_response`, `decode_function_property_ext`, `encode_function_property_ext_state_response` (57) and `FunctionPropertyExtCommand`, `PropertyExtWriteConResponse` (~10).
- What: verified by grep: no non-test use inside bussard-mgmt, none in any other crate's `src` (bussard-testkit included); knx-sim has its own copies by design. They exist for mgmt's own unit tests that script a fake device.
- Proposal: move them under `#[cfg(test)] mod responder` in mgmt (or into bussard-testkit if MockDevice wants them later). Zero behaviour change.

### F7. bussard-mgmt API doubles and the DeviceConnection wrapper: est. save: ~200 (medium)
- Where: `device.rs` (201 lines): `DeviceConnection` wraps `Layer4Connection` with three `connect*` constructors mirroring `Layer4Connection::connect/_with/_with_secure`, `read_property`/`write_property` (10-line shims over `property_request`/`property_write_request`), `read_memory` (delegates), a 70-line interactive `write_memory` with per-chunk read-back (callers: check `write-memory`-style commands only), `l4_mut`/`into_l4`/`from_l4` seams that exist only because the wrapper exists; in service `Device` alias, `with_device`, `connect_device` (bus.rs ~40 lines) duplicate `with_l4`/`connect_l4`. `broadcast.rs`: `devices_in_programming_mode` / `_within`, `read_individual_address_by_serial` / `_within` (default-arg doubles). `lib.rs`: `is_system_b`, `system_type` wrappers over `MaskProfile` kept "for history". `tables.rs:409-460`: private `read_property`, `read_memory`, `memory_error` adapters plus `TablesError` because the table reader has a third error enum next to `MgmtError` and `load::WriteError` (`memory_error` folding appears in tables.rs and device.rs).
- Proposal: make the typed procedures inherent methods (or an extension trait) on `Layer4Connection` and delete `DeviceConnection` and the service `with_device` path (callers switch `dev.device_descriptor()` to `read_device_descriptor(l4)`, mechanical); drop the `_within` doubles (take `window: Duration`); fold `TablesError::TableUnreadable` into `MgmtError::MalformedResponse { reason }` so tables.rs uses `MgmtError` and loses its adapters; one `Layer4Connection::connect(conn, target, source, ConnectOptions { timeouts, secure })`.
- Risk: mechanical; the TL state machine itself (connection.rs 467-2060) is untouched.

### F8. Result/verdict wrappers and `_with` doubles in service: est. save: ~150 (medium-low)
- Where: `admission.rs:348-515`: `receiver_verdict`/`_with`, `check_sender_admission`/`_with`, `check_tunnel_write`/`_with` (three thin doubles; every caller could pass `&LiveTables::new()`); `Admission` has four variants each repeating `sender, ga, receivers`; `verify.rs:369-400,440-520`: `Compared` with nine `Option` counters and a 50-line `summary()` that could be a `Vec<(LeftoverKind, usize)>` and one loop; five verdict wrappers with their own `verified()`/`failure()`: `WriteReadback`, `FlashedParameters`, `InterfaceApply` (knxnet.rs:787-820), `Flashed` (flash_flow.rs:690-717), `SwitchOutcome`; `knxnet.rs:822-890` pushes its own leftovers into a `WriteReadback` it then re-verifies.
- Proposal: drop the `_with`-less forms; `Admission { sender, ga, kind: AdmissionKind }`; `Compared = BTreeMap<LeftoverKind, usize>`; everything that reads back returns `WriteReadback` and the four wrappers hold one.

### F9. Nine `BUSSARD_*` env knobs, each with its own parser: est. save: ~60 (high)
- Where: `scan.rs:41`, `reconstruct_line.rs:49` (identical `discovery_timeouts`), `download.rs:32` (`flash_l4_timeouts`), `assign.rs:84` (`wait_ms_override`), mgmt `probe.rs:82` (`probe_timeouts_from_env`), mgmt `connection.rs:304` (`mgmt_timeout_override`), bus `lib.rs:80` (`backoff_start`): the same "read var, trim, parse u64 ms" and a `Timeouts {…}` literal each time.
- Proposal: `bussard_model::dotenv::duration_ms(var) -> Option<Duration>` and `Timeouts::uniform(ms, repetitions, absent_on_negative)`; one table of knobs in one place also makes the test hooks discoverable.

### F10. Two "download a product by order number" flows: est. save: ~70 (medium)
- Where: `setup/products.rs:516-636` (`fetch_missing`: index lookup, group by URL, prompt, `fetch_to_store`, `generate_models_pinned`) and `files/products.rs:210-282` (`import_product_order`: index lookup, prose, prompt, `fetch_entry`, `store_download`, `import_from_file`). Two store writers (`fetch_to_store` 133-157 vs `store_download` 158-188) for the same bytes.
- Proposal: `products::download(entries, dir, prompt, out) -> Vec<Result<PathBuf>>` used by both; one store writer.

### F11. Minor: `BusService::open`/`from_handle` (bus.rs:146-190) duplicate the constructor body; `bussard-bus` process globals `no_free_tunnel_seen`/`fatal_connect_error` (lib.rs:98-150) could live on `BusDiagnostics`: est. save: ~40 (low).

## Not duplication, but worth knowing
- About 2 000 lines of the service crate are operator-facing sentences (`decide_freshness`, `descriptor_read_message`, `load_reason`, `load_refusal`, `recovery_text`, `Admission::refusal/admit_hint/note`, `TunnelGap::message`, the octet notes in params.rs). They are not cuttable by refactoring; only a product decision to say less would shrink them. Leave them.
- `enroll_session/*` (939 lines) is one feature (phone certificate relay, E2E crypto). Keep or drop as a feature, not as a refactor.

## Do not touch
- `bussard-mgmt/src/connection.rs:467-2060`: the TL Style 3 state machine with its AN210 amendments, idle reconnect and Data Secure sync; every branch is a tested spec case.
- `load.rs`, `memory.rs`, `sys7.rs`, `property_ext.rs` request/response paths: these are the write path the oracle rows cover; their `_chunked`/`_echoed`/`_verified` variants differ on the wire (capture-derived), so they are not doubles.
- `verify.rs::read_back` and `Expected` (the #319/#349 read-back rule) and `flash_flow.rs` (the freshness gate): shape stays, only F8's bookkeeping changes.
- `ip_secure.rs::records()` output (the `--dump-images` oracle shape).

## Estimated total
- bussard-service: F2 190 + F3 220 + F4 250 + F5 190 + F8 150 + F9 40 + F10 70 + F11 40 ≈ 1 150 lines (~7 %).
- bussard-mgmt: F6 215 + F7 200 + F9 20 ≈ 435 lines (~7 %).
- bussard-bus: ≈ 30 lines (~4 %).
- Plus F1: ≈ 700 lines removed from bussard-cli and bussard-mcp by moving the single-device apply into this crate (the biggest #314-class risk in the workspace today).
