# bussard-download, bussard-prod, bussard-ets review

Total product lines (loc.py rule): bussard-download 15,752 · bussard-prod 3,802 · bussard-ets 3,074 · together 22,628.

Headline: these three crates are protocol and codec logic, not surface code. Refactoring alone yields roughly 3,000 lines (13 %). A 40 % cut here is only reachable through product decisions (see "Ceiling" at the end), not through de-duplication.

## Module inventory

| module | crate | product lines | role | overlaps with |
|---|---|---|---|---|
| flash/plan.rs | download | 1,220 | lower System B `LoadOp`s to `FlashStep`s, table images, kept octets, template splicing | plan_sys7.rs (shared Connect/Restart/Delay/WriteProp/CompareProp/LoadImageProp lowering) |
| flash/plan_sys7.rs | download | 1,405 | System 7 lowering: abs segments, task records, packed tables, group-object post-pass | plan.rs scaffolding only; the protocol content is distinct |
| flash/execute.rs | download | 1,048 | System B executor (step loop, resume, write_image, diff/fill regions) | execute_sys7.rs, execute_props.rs (same loop, same property/restart handlers) |
| flash/execute_sys7.rs | download | 671 | System 7 executor + verify_sys7 | execute.rs; load_records.rs re-encodes the same LSM events |
| flash/execute_props.rs | download | 130 | property-only executor | execute.rs step loop |
| flash/session.rs | download | 863 | `Session<C: Connector>`: authorize, reconnect, reboot probing, verify mode, resumable wrappers | plain vs secure reboot loops duplicate each other |
| flash/mod.rs | download | 806 | `FlashStep` (35 variants), `FlashPlan` (17 fields, ~40 accessors), `PlanError`, options | labels.rs (step_label overrides live here too) |
| flash/labels.rs | download | 306 | prose label per step + `trace` | FlashPlan::step_label, load_records.rs, product_model.rs load_op_summary |
| flash/load_records.rs | download | 164 | wire record per load-control step | execute_sys7.rs encodes the same events |
| flash/partial.rs, verify.rs, props.rs, plan_props.rs, knxnet_ip.rs, par_procedure.rs, restart_form.rs | download | 1,760 | partial plans, MCB verify, property services, property-only planning, KNXnet/IP block | fine; small items only |
| param_decode.rs | download | 909 | decode device memory into parameter values; attribute changed octets to parameters | **static placement duplicated in prod image.rs** |
| param_plan.rs | download | 490 | parameter diff, region read-back | planned_parameter_regions vs read_parameter_regions_with_objects duplicate the step walk |
| model_params.rs | download | 673 | glue: model → overrides/table images/plan, identity gate, sys7 identity, read-back verify | fine |
| program.rs, apply.rs, apply_sys7.rs, tables_sys7.rs, compute_sys7.rs, plan.rs (top-level) | download | 1,690 | the older **tables-only write engine** (`bussard plan/apply`, MCP restore_tables) | the flash engine writes the same three table objects |
| compute.rs | download | 441 | desired tables, group-object descriptors | fine |
| device_plan.rs | download | 459 | `DevicePlan` view-model, prose rendering, state hash | mcp tools_program.rs `live_digest` re-implements `state_hash_with` |
| backup.rs | download | 456 | JSON backups, manifest, hand-rolled hex/date | 4 identical read/write fns; hex and civil_from_days duplicated workspace-wide |
| preflight.rs, security.rs, security_diag.rs, object_table.rs, param_props.rs | download | 1,710 | resident probe, Data Secure object programming, diagnostics, object-table check | fine |
| sweep.rs | download | 409 | product-corpus conformance sweep + markdown report | **test tooling, no src caller** |
| image.rs | prod | 1,792 | parameter image: placement + codec + property values | static placement duplicated in download param_decode.rs |
| product_model.rs | prod | 952 | writes `.bussard/models/<app>.yaml` from `ApplicationProgram` | a Serialize-only mirror of ApplicationProgram; bussard-model param_model.rs holds the Deserialize-only mirror |
| lib.rs, container.rs, cache.rs, fetch.rs, extract.rs, index.rs | prod | 1,058 | archive reading, parsed-product JSON cache, download verification | fine |
| application.rs | ets | 2,083 | streaming XML parser → `ApplicationProgram` (189 `Option` fields) | every consumer `unwrap_or(0)`s the `Option<u32>` attributes |
| master.rs, hardware.rs, dynamic.rs, misc | ets | 991 | knx_master template + Hawk, Hardware.xml, DynamicSource impl | fine |

## Findings (ordered by lines saved)

### F1. Product-model pipeline: four struct families for one concept: est. save: 550 in prod, ~300 more in bussard-model (confidence medium)
- Where: `crates/bussard-prod/src/product_model.rs:248-1150` (`Model`, `Identity`, `ComObjectModel`, `ParameterModel`, `RefModel`, `ParamTypeModel`, `EnumValueModel`, `MemoryModel`, `build_model`, `parameters_for`, `param_type_model`, `load_op_summary` 207 lines, `unions_for`, `other_object_refs`, `serialize_model`); `crates/bussard-model/src/param_model.rs:230-640` (`RawModel`, `RawParam`, `RawRef`, `RawType`, `RawComObject`, `from_yaml` 103 lines).
- What: `ApplicationProgram` (ets) is re-shaped into a Serialize-only `Model` tree, written as YAML, read back through a Deserialize-only `Raw*` tree, then converted into `ProductModel`/`ParamDef`/`ParamKind`. prod `cache.rs` already caches the parsed `ApplicationProgram` as JSON, so the project carries two product caches and two mirrors. The perf baseline memory (2026-10-24) names the YAML parse as the dominant cost of every command.
- Proposal: build `ProductModel` directly from the cached `ApplicationProgram` with one `impl From<&ApplicationProgram> for ProductModel` (placed in bussard-prod, where both types are visible; `bussard_model::param_model::load` gains a hook or the surfaces call `bussard_prod::product_model::load`). Keep `ProductModel`/`ParamDef`/`ObjectDef` as the model-crate API so device_view/checklist/change/doc are untouched. Delete `Model*`, `load_op_summary`, `write_models`, `model_yaml`, the `Raw*` tree and `from_yaml`; `complete_models`/`models_incomplete`/`model_is_current` collapse to "is the parsed-product cache current". `TableCapacity::for_device` (security.rs:220) then reads `app.security_capacity` directly (−20).
- Risk / constraints: `.bussard/models/*.yaml` is documented (docs/reference/product-data.md, dev/product-model-format.md) as a generated, never-edited, disposable directory, so dropping it is a docs change, not a compatibility break (memory: no backwards compat pre-release). Tests that read YAML fixtures under `crates/bussard-model/tests` need the JSON form instead. No bytes written to a device change; the oracle is unaffected because flash plans from `ApplicationProgram`, never from the YAML.

### F2. Static parameter placement implemented twice: est. save: 300 (150 download, 150 prod) (confidence medium-high)
- Where: `crates/bussard-prod/src/image.rs:259-520` (static branch of `compute_parameter_image_placed_with`: parameters loop, unions loop, overrides loop with module base offsets; `resolve_override_key`, `split_module_instance`, `union_member_memory`) and `crates/bussard-download/src/param_decode.rs:770-1100` (`static_placements`, `static_location_with`, `UnionMembers`, `resolve_key`, `application_placements`).
- What: both compute "parameter → (segment, offset, bit_offset)" for non-Dynamic products: defaults from `initial_value`/`ParameterRef.value`/`default`, union default members, overrides with `_M-<m>_MI-<n>` selectors and per-instance base offsets. The dynamic path already shares this through `dynamic_parameter_slots` → `ParameterSlot`; the static path does not.
- Proposal: add `static_parameter_slots(app, overrides, base_offsets) -> Result<Vec<ParameterSlot>>` in prod image.rs returning the same `ParameterSlot` (plus `value`/`source`). The image writer becomes one loop over slots through the existing `write_slot` (as the dynamic branch is), and param_decode's `placements_of` maps slots to `Placed` for both product kinds. `resolve_key`/`resolve_override_key` become one function.
- Risk / oracle: this is the exact code that produces the parameter image for every non-Dynamic product, so the plain rows of `scripts/campaign/95-offline-oracle.sh` (the house rows and the synthetic `syn-*` static products) must stay `identical` with unchanged coverage figures; unit tests in image.rs and param_decode.rs pin the placement rules.

### F3. Three flash executors share one loop: est. save: 300 (confidence medium-high)
- Where: `flash/execute.rs:311-980` (`flash_steps`), `flash/execute_sys7.rs:29-520` (`flash_sys7`), `flash/execute_props.rs:24-150` (`flash_properties`).
- What: each has its own `for (i, step)` loop with progress reporting, `cycle_l4` threshold, the `'resume` loop with the `resumable_death` / link-loss repeat rules, and its own copies of the `DescribeProp`, `CompareProp`, `WriteProp`, `LoadImageProp`, `KnxnetIpParameters`, `Delay`, `Restart` arms and the verify-after-restart branching. `image_part` exists twice (execute.rs:1497, execute_sys7.rs:515). The property-only executor's final read-back loop is a third verify path.
- Proposal: one driver `run_steps(session, plan, options, progress, exec: impl StepExecutor)` owning the loop, progress, reconnect threshold and resume policy; the three families become `match` arms in one `execute_step` (family-specific arms stay in their files as helpers). Shared property/restart arms exist once.
- Risk: executor code is covered by the mock campaigns (`crates/bussard-download/tests/it/flash_mock.rs`, `flash_mock_system7.rs`, `property_procedure.rs`, cli `virtual_device_flash.rs`), not by the offline oracle (which stops at the plan). The two restart policies (System B confirmed/master reset vs System 7 plain restart) and the System 7 "after the final restart, failures are warnings" rule must survive as explicit branches.

### F4. Test tooling in the product crate: sweep.rs: est. save: 409 (confidence high)
- Where: `crates/bussard-download/src/sweep.rs` (whole file), lib.rs re-exports.
- What: the product-corpus conformance sweep (`catch_unwind`, JSON manifest, markdown report, refusal rankings). Zero callers in any `src/`; used only by `tests/it/flash_corpus.rs` and `tests/it/sweep_fixtures.rs`.
- Proposal: move to `crates/bussard-download/tests/it/support/sweep.rs` (or `bussard-testkit`). Nothing in the binary changes.
- Risk: none for devices; CI sweep job keeps working from the test path.

### F5. Wrapper ladders and `_with` doubles: est. save: 250 (confidence high)
- Where: program.rs `write_tables → write_tables_secured → write_tables_seeded`, `write_system_b → _secured → _seeded`; apply.rs `apply_tables → _secured → _with`; plan.rs `plan_flash → _with_object_flags → _with_memo`; `decode_parameters/_with`, `attribute_octets/_with`, `build_table_images/_with`, `plan_for_readback/_with`, `group_object_change/_with`, `dynamic_group_object_table/_with`, `read_current_parameter_memory/_with_objects`, `read_parameter_regions/_with_objects`, `compute_parameter_image/_placed/_placed_with`, `Session::open/open_with_key/open_with_facts`, `read_live_tables/_at`, `read_sys7_tables/_at`, `probe_resident_state/_full` (21 wrappers in the three crates, each 8-20 lines with its own doc block).
- What: every "memo" wrapper only constructs `DynamicMemo::new(app)`; every "secured/seeded" wrapper only fills a `SystemBLoad`. External callers use the longest form in most cases (service calls `plan_flash_with_object_flags`, `write_system_b_seeded`, `write_tables_seeded`); the short forms survive for tests.
- Proposal: keep one function per operation taking the full input struct (`SystemBLoad`, the memo, `Sys7TableBases`); tests build the struct with `..Default::default()`. Prune the 280-item `pub use` list in lib.rs: 112 items have no external `src/` caller (callers.py), a third of those are internal-only helpers that should be `pub(crate)`.
- Risk: mechanical; the 81 internal `plan_flash(` call sites are tests.

### F6. Tables-only write engine next to the flash engine: est. save: 400 now, up to 1,700 with a product decision (confidence low-medium; needs capture evidence)
- Where: `program.rs` (304 fn-lines), `apply.rs` (203), `plan.rs` (50) for System B; `apply_sys7.rs` (358), `tables_sys7.rs` (286), `compute_sys7.rs` (210) for System 7.
- What: `bussard plan/apply` and MCP `restore_tables` write the address and association tables (and on System 7 the group-object flags) with a hand-sequenced StartLoading → allocate → write → LoadCompleted per table and a read-back, written before the flash engine existed. The flash engine plans and executes the same three table objects from `table_images` (plan.rs `RelSegment`/`WriteRelMem` with `table_object_name`), already has partial plans (`parameters_only`, `restoring`, `use_par_procedure`), the security-program block, kept octets, MCB verification and the resumable session. CLAUDE.md "Device Writes" asks for one write path per kind of write; this is two.
- Proposal: add `FlashPlan::tables_only(&self)` beside `parameters_only` (keep only the steps that touch objects 1/2 and their load-state transitions), and let `apply`/`restore_tables` run it through `Session` + `flash`. The System B apply path (apply.rs, most of program.rs, plan.rs) then goes; `PlanReport` stays as the diff view. System 7 apply stays until the sys7 flash path gains a "keep LSM 3, rewrite LSM 1/2" mode, so the sys7 trio is a second step.
- Risk / oracle: `apply` has ETS-parity rules of its own (an empty table set is refused, the association PDT check, the own-IA slot on System 7). Before merging, a capture of an ETS "partial download: group addresses" on a System B device must show the same op sequence the tables-only FlashPlan emits (dev/testing.md: parity by capture, never by guess); the `20-per-device.sh` campaign covers the live side. Keep this behind the oracle, not a code-only PR.

### F7. Step rendering and record encoding triplicated: est. save: 100 (confidence medium)
- Where: `flash/labels.rs:15-310` (`step_label`), `flash/mod.rs:1245-1310` (`FlashPlan::step_label` overrides), `flash/load_records.rs:101-182` (`sys7_events` re-encoding `encode_alloc_segment`/`encode_task_*` that `execute_sys7.rs:70-200` encodes again), plus `product_model.rs:935-1142` `load_op_summary` (goes with F1).
- Proposal: `FlashStep::sys7_event(&self) -> Option<(lsm, name, [u8; N])>` used by both the executor and `load_records`; `step_label(step, ctx: &LabelCtx)` with the plan facts (`parameters_only`, `confirmed_restart`, `sys7_read_compare`, baseline address) instead of a second match in mod.rs.
- Risk: labels are not an oracle input (the oracle compares `--dump-images`), and only 4 test files assert on label text.

### F8. Hand-rolled hex, dates and JSON file I/O: est. save: 80 here, ~150 workspace-wide (confidence high)
- Where: `backup.rs:400-456` (`encode_hex`, `decode_hex`, `rfc3339_utc`, `timestamp_dir_name`, `civil_from_days`), `backup.rs:258-350` (four identical `write_*`/`read_*` JSON functions), `param_props.rs:50`, `knxnet_ip.rs`, `plan_sys7.rs` `decode_hex`, `product_model.rs` `hex`, ets `decode_hex_bytes`; `civil_from_days` also in bussard-model history.rs, bussard-monitor timefmt.rs, bussard-project keystore.rs; 24 private `hex()` helpers across the workspace.
- Proposal: `bussard_model::text::{hex, from_hex}` and `bussard_model::timefmt::{rfc3339_utc, compact_utc}` (model is the leaf crate every other crate already depends on); one generic `read_json<T>(path)`/`write_json(path, &T)` pair in backup.rs.
- Risk: none; pure helpers with unit tests.

### F9. param_plan.rs duplicates its own step walk: est. save: 90 (confidence medium)
- Where: `param_plan.rs:436-520` (`planned_parameter_regions`) and `:560-720` (`read_parameter_regions_with_objects`) both derive "last allocation per object, readable segments" from the steps; `param_plan.rs:154-230` (`param_plan` no-memory branch) re-derives kept octets by hand instead of through `placements_of`.
- Proposal: `read_parameter_regions_with_objects` iterates `planned_parameter_regions(plan)` and only adds the base read and the memory read; `param_plan` without memory uses the same `Placed` list as with memory (decode returns `None`).
- Risk: read-back only; covered by `flash_parameters_mock.rs`.

### F10. session.rs reboot probing and resumable wrappers: est. save: 70 (confidence high)
- Where: `session.rs:1041-1230` (`reconnect_after_plain_reboot`, `reconnect_after_secure_reboot`, `measure_readiness_until` share the probe-until-deadline loop; the plain and secure probes differ only in the descriptor read and in keeping the connection), `session.rs:1570-1610` (`read_load_state_resumable`, `read_memory_resumable` spelled out instead of using the `resume!` macro three lines above).
- Proposal: one `probe_until(deadline, |l4| probe)` loop with a `Secure`/`Plain` probe enum; the two hand-written resumable readers use `resume!`.
- Risk: the evidence-based waits (`REBOOT_PROBE_MIN_WAIT`, `SECURE_REBOOT_WAIT`, `FACTORY_RESET_PROBE_FROM`) stay as constants; no timing changes (CLAUDE.md "Speed Changes").

### F11. `Option<u32>` on every LoadOp attribute: est. save: 60 downstream (confidence low-medium)
- Where: `crates/bussard-ets/src/application.rs:524-840` (`LoadOp`), consumers in `flash/plan.rs` and `flash/plan_sys7.rs` (`lsm_idx.unwrap_or(0)`, `prop_id.unwrap_or(0)`, `obj_idx.unwrap_or(0)`, `count.unwrap_or(1).max(1)` at ~40 sites).
- What: the parser keeps every attribute optional; each consumer re-decides the default. The defaults are the same everywhere (0, 1 for counts, `PID_MCB_TABLE` for LoadImageProp).
- Proposal: apply the defaults once in `push_load_op` (field becomes `u32`), keep `Option` only where absence is meaningful (`size`, `address`, `inline_data`, `applies_to`).
- Risk: a parse-time default is a semantic choice; verify against the ETS sweep fixtures (`tests/fixtures/corpus`) that no product relies on the "absent" distinction the planner currently reads (`RelSegment.size: None` does).

### F12. Surface duplicates of download logic (for the mcp/service reviewers): est. save: 50 in bussard-mcp
- `crates/bussard-mcp/src/tools_program.rs:3543-3590` `live_digest` re-implements `bussard_download::state_hash_with` (device_plan.rs:565) byte for byte with a different domain tag; the MCP flash fingerprint should call the download function (CLAUDE.md #314 pattern).

## Do not touch
- `flash/plan.rs` `plan_flash_with_memo` (652 lines) and `flash/plan_sys7.rs` `plan_flash_sys7` (408): the op-to-step semantics (MapError over Unload, table images for objects 1-3, kept octets from untaken `<choose>` branches, packed System 7 tables, task identity) are the oracle-proven core. Shrinking them by a strategy trait saves under 100 lines and risks parity.
- `flash/verify.rs` (MCB skip gate, spot checks), `execute.rs` `write_image` (echo verify mode, resume by confirmed bytes), `diff_regions`/`fill_regions`/`merge_runs` (request-count-aware merging, the speed rules).
- `security.rs` (Data Secure object programming order), `knxnet_ip.rs`, `preflight.rs` (System B decisive probe vs System 7 LSM probe).
- `bussard-ets/src/application.rs` streaming parser: the 15 MB inputs make a serde-derive rewrite a performance regression; the `handle_start`/`handle_empty` dispatch is proportionate.
- `bussard-prod/src/image.rs` codec (`encode_value`/`decode_value`/`encode_int_bits`/`encode_float`): byte-exact, little-endian and DPT-9 edge cases pinned by tests.

## Estimated total
| crate | lines saved | share |
|---|---|---|
| bussard-download | F3 300 + F2 150 + F4 409 + F5 200 + F7 100 + F8 80 + F9 90 + F10 70 = ~1,400; +400 with F6 (System B apply) | 9 % (12 % with F6) |
| bussard-prod | F1 550 + F2 150 + F5 30 = ~730 | 19 % |
| bussard-ets | F11 ~20 at the source, the rest lands downstream | 1 % |
| together | ~2,150, ~2,550 with F6 | 10-11 % |

Ceiling: beyond refactoring, the only large blocks are product scope. System 7 support (plan_sys7, execute_sys7, apply_sys7, tables_sys7, compute_sys7, load_records, the sys7 halves of partial/preflight/model_params) is ~3,300 lines (15 %); the full tables-only engine is ~1,700 (7.5 %); the Data Secure object programming + diagnostics ~1,000 (4.5 %). Reaching 40 % in these crates means dropping one of those, which is the owner's call, not a review finding.
