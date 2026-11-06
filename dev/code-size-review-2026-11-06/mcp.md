# bussard-mcp review

Total product lines: 22,439 (loc.py rule; 45 files). Biggest: tools_program.rs 3,016,
tools_model.rs 1,712, server.rs 1,199, tools_program/{add_device 1,120, replace_device 937,
commission 888}, tools_enroll.rs 860, jobs.rs 743, everyday.rs 719, flash.rs 718.

Central answer: roughly 40 % of the crate is domain orchestration that has a second copy in
bussard-cli and no home in bussard-service. The service crate exposes vocabulary (targets,
outcomes, plans, `write_tables_seeded`, `flash_and_verify`, `visit_device`,
`capture_devices`) but, for apply/plan, describe, adopt/replace/commission and the
flash decision, no runner. Each surface then sequences the steps itself, in its own
result shape (JSON here, printed text there). This is the #314 failure class
institutionalised. Where the service does own the flow (backup, line, enrol session,
import) the MCP side is a thin adapter and the file is 150-600 lines instead of 1,000-3,000.

## Tool inventory

| tool(s) | file | lines | adapter / logic | CLI twin | service fn used |
|---|---|---|---|---|---|
| knx_project_summary, model_lookup, get_group, get_device, show_device, recent_telegrams, wait_for_telegram, validate, bus_status, bus_reconnect | server.rs + tools.rs | ~1,000 | mostly adapter; model_lookup (150) and validate_filtered (80) are logic | status_cmd, validate_cmd, device_cmd | ModelHandle, TelegramRing |
| knx_read_group, knx_write_group | server.rs 823-1322 | ~280 | logic: keys, admission resolve, refusal JSON | read_cmd 221, write_cmd 231 | group::read_group, write::prepare_group_write/send_prepared, admission::* |
| knx_describe_device | server.rs 982-1170 + 1401 | ~220 | logic: key resolution, warm reuse, factory-key probe, refusal | describe_cmd 528 | describe::walk_objects, identity::refused_walk_answers_under_factory_key |
| knx_plan_device, knx_apply_device, knx_apply_status, knx_last_apply | tools_program.rs | ~2,600 | logic: read_device, plan, security inputs, digests, write sequence, read-back | plan_cmd 515, apply_cmd 813 | download::plan, write_tables_seeded, verify::read_back_on, restart::wait_until_back (pieces, not a flow) |
| (flash half of apply) | tools_program/flash.rs | 718 | logic: load_need, flash/load image, gate refusal | flash_cmd 1,066 | download::flash_session, flash_flow::flash_and_verify |
| knx_add_device | add_device.rs | 1,120 | logic: identify, product fetch, assign, read-back, device file, prose | adopt_cmd 777 | adopt::flow pieces |
| knx_replace_device | replace_device.rs | 937 | logic: identify, backup, flash+apply, assign, record, prose | replace_cmd 337 | replace::* pieces |
| knx_commission_line | commission.rs | 888 | logic: probe, per-device pause/answer state machine, prose | commission_cmd 484 | commission::LineRun, probe_line, identify_pressed |
| plan/apply `line` form | line.rs | 580 | adapter + digests + JSON | line_cmd 500 | line::visit_device (good: service owns the flow) |
| knx_restore_parameters | restore.rs | 429 | adapter + plan table + backup + write | restore_cmd 249 | restore::build_restore_plan, download::write_parameters |
| knx_restore_tables | restore_tables.rs | 502 | logic: tables-only plan, digest, write | restore_cmd (apply_desired) | write_tables_seeded |
| knx_restart_device | restart.rs | 230 | adapter | restart_cmd 119 | restart::restart_device |
| interface plan/apply, knx_interface_secure, knx_clear_security_log | interface.rs, ip_secure.rs, secure_diag.rs | 679 | adapter + hand-rolled session | interface_cmd 390, interface_secure_cmd 285, secure_diag_cmd 99 | knxnet::*, ip_secure::* |
| 12 edit tools, describe_change, history, undo, discard_edits | tools_model.rs + session_edits.rs + param_keys.rs | 2,560 | logic: edit_with_hook (good), session-edit ledger, parameter-key resolver, set_interface | none (edits are MCP-first by design) | model::change, History |
| knx_import_file, knx_export | tools_files.rs | 701 | adapter + JSON/prose | import_cmd 88, export_cmd 52, keys_cmd | setup::import, files::* (service owns the flow) |
| knx_backup_device, knx_reconstruct_device, knx_find_devices | tools_device.rs + tools_find.rs | 1,014 | adapter (backup), logic (reconstruct line job, scan result JSON) | backup_cmd 144, reconstruct_cmd 327, scan_cmd 409 | backup::capture_devices, reconstruct::build_report, scan::sweep |
| knx_enroll_certificates, knx_enroll_status | tools_enroll.rs + password_form.rs + browser.rs | 1,263 | adapter + elicitation + prose | enroll_cmd 273 | enroll_session::EnrollSession (service owns the flow) |
| knx_audit | tools_audit.rs | 451 | report builder lives HERE; CLI imports bussard_mcp::tools_audit | audit_cmd 673 (depends on mcp crate) | none |
| HA status/plan/apply + automation plan/apply/remove | tools_ha.rs, tools_ha_automation.rs | 1,063 | logic (no service module) | ha_config_cmd 18 | bussard_ha |
| scaffold/reserve groups, infer_group, run_tests, viz, job_status, diff/export_bundle | tools_groups, tools_learn, tools_viz, tools_jobs, tools_diff | 859 | adapter | groups_cmd, learn_cmd, test_cmd, viz_cmd, diff_cmd | model/project fns |
| knx_setup (onboarding server) | onboarding.rs | 565 | second ServerHandler + hooks | init_cmd 314 | setup::run (service owns the flow) |
| infrastructure | jobs 743, everyday 719, guidance 430, state 231, run 157, http 128, args 128, tier_help 119, warm 99, lib 246 | 3,000 | | | |

## Findings (ordered by lines saved, largest first)

### F1. The plan/apply engine exists twice: here and in the CLI: est. save: 1,400 here (+ ~900 in bussard-cli) (confidence high)
- Where: tools_program.rs `plan_body` 1132-1530, `apply_preflight` 1826-2128, `apply_write` 2128-2597, `read_device`/`read_on`/`read_property_rows` 3073-3330, `security_inputs`/`built_plan`/`admit_in_plan`/`security_change_in_plan`/`refuse_drift`/`refuse_protected` 2892-3414, digests 3537-3712. CLI: `plan_cmd.rs::read_device` 237-330, `apply_cmd.rs::apply_desired` 260-760, `write_tables_then_parameters` 763-938, `write_parameters` 938-1007.
- What: both sides perform the identical sequence: resolve keys and admitted tunnel, read identity + live tables + parameter memory + PID 54 + PID 61 on one session, `desired_tables_for_app`, `plan`, build `SecurityInputs`, refuse drift/protected, decide tables vs parameters vs flash, back up, `write_tables_seeded`, `wait_until_back` after a System 7 restart, `record_secure_senders`, `record_security_flags`, `write_parameters`, build `verify::Expected` the same way, `read_back_on`, record the lock. The MCP copy additionally hand-rolls the session (`checked_source` + `lease` + `Layer4Connection::connect_with_secure` + authorize) three times (3106-3185, 3212-3249, interface.rs 62-98) while `BusService::with_l4`/`connect_l4` (bus.rs 258, 360) already do that for the CLI.
- Proposal: `bussard_service::apply` with `read_device(service, target, Inputs) -> DeviceRead`, `plan_device(..) -> DevicePlanOutcome` and `apply_device(prepared, &mut dyn ApplyObserver) -> ApplyOutcome`, both outcomes `Serialize` with the keys the MCP JSON uses today (`verified`, `address_state`, `parameters`, `restarted`, `secure_senders_recorded`, …). MCP becomes: parse args → claim job → `serde_json::to_value(outcome)` → summary. The CLI prints the same struct. The observer trait already exists (`download::FlashObserver`); extend it with `step()` and `progress()` so `JobObserver` and the CLI progress bar are its two impls.
- Risk / constraints: this is the write path CLAUDE.md wants shared ("the CLI and the MCP server call the same function"); oracle rows 95-offline-oracle cover the images, not the sequence, so the sequence tests in `bussard-mcp/tests/it/mcp_flash*.rs` and `bussard-cli/tests/it/apply_*` must both pass against the one implementation. Keep `state_hash`/`plan_hash` semantics (F2 folds the two hash schemes).

### F2. Nine bespoke plan→confirm→job scaffolds: est. save: 650 (confidence medium)
- Where: `PendingPlan` (tools_program.rs 280), `PendingLinePlan` (line.rs 42), `PendingRestore` (restore.rs 34), `PendingTables` (restore_tables.rs 44), `PendingRestart` (restart.rs 30), `PendingAdd` (add_device.rs 55), `PendingReplace` (replace_device.rs 85), `PendingAutomation` (tools_ha_automation.rs 41), HA `plans` map (tools_ha.rs 122); 13 `*_digest` functions (listed by `grep "fn [a-z_]*digest("`); five `MutexGuard<HashMap<String, Pending*>>` accessors on `ProgrammingTier` (241-279); seven `*_preflight` and eight `*_job` methods that each re-implement "retain within TTL, get by digest, refuse with the 'no fresh plan … single use' sentence, check target binding, remove".
- What: the same contract (digest, TTL, single use, bound to a device/line/file) written nine times with nine messages. `live_digest` (3544-3622) is a line-for-line copy of `bussard_download::state_hash_with` (device_plan.rs 565) with a different salt, so a plan carries two incompatible hashes (`state_hash` and `plan_digest`) of the same read; `model_digest` (3623) and `tables_digest` (restore_tables.rs 138) repeat the address/association serialisation loop a third and fourth time.
- Proposal: one `confirm::Store<P>` (TTL, single use, `bind: Subject`) on `ProgrammingTier`/`HomeAssistantTier`, one `Digest` builder in bussard-download (`DesiredTables::digest_into`, `LiveTables` already has `state_hash_with`) and one `run_job(kind, subject, fut)` on `BussardMcp` (today `run_job` 1551, `watch_job` 1113, `job_started` 1609, `line_job_started` 445, `tables_job`, `restore_job`, `restart_job`, `add_identify_job`, `replace_identify_job`, `spawn_commission`).
- Risk: digests are compared in tests by value in a few places (`mcp_flash.rs`); keep the salts stable or update the tests.

### F3. Three flows that have no service runner: add, replace, commission: est. save: 1,650 (confidence medium)
- Where: add_device.rs (1,120), replace_device.rs (937), commission.rs (888). Shared blocks the scanner found: `identified_detail` (add 987 / replace 871), `done_result` (add 1122 / replace 1009), `who` ×3, `Consented` download hook ×2, `PRESS_BUTTON` ×2, product fetch (`import_add_product`/`download_product` 786-864 vs `replace_source`/`pinned_source` 733-792).
- What: each tool re-implements, from `checked_source` down: find the device in programming mode, identify it, verify the order number, resolve product data (store, download or `--product` file), probe the target address for an occupant, write the address, read back, write the device file and lock entry; replace adds backup+flash+apply (calling F1's apply engine), commission adds a pause/answer state machine (`commission_segment` 614-893). The CLI does the same in adopt_cmd (777), replace_cmd (337) and commission_cmd (484) over the same `adopt::flow`, `replace`, `commission` building blocks.
- Proposal: `bussard_service::adopt::run(service, AdoptRequest, &mut dyn Hooks) -> AdoptOutcome` (identify → product → assign → verify → record), with replace = backup + adopt::run + apply::run and commission = `LineRun` + adopt::run per device. The MCP files keep the job/pause bookkeeping and the question texts (~300-450 lines each).
- Risk: `dev/chat-parity.md` fixes the three-step chat contract (job, identified, yes) and the result keys; keep those at the MCP layer. Touches the address-write path: the mock tests `mcp_add_device.rs`, `mcp_commission.rs`, `adopt_mock.rs`, `assign_mock.rs` are the gate.

### F4. Tool descriptions and guidance prose are Rust source: est. save: 800 (confidence high; text moves, it does not vanish)
- Where: 809 lines inside `#[tool(description = …)]` attributes (tools_program.rs 271, tools_model.rs 133, server.rs 107, tools_device.rs 55, tools_enroll.rs 47 …); `guidance.rs::instructions` 276-400 (~130 lines of string), `HOW_TO_TALK`, `HA_INSTRUCTIONS`, `tier_help.rs` (119).
- What: the assistant's manual is compiled into the binary as string literals that rustfmt cannot wrap and that nobody can read without the code. loc.py counts every continuation line as code.
- Proposal: `tools/<name>.md` + `include_str!` in the attribute (rmcp accepts any `&'static str` expression), `guidance/*.md` for the tier paragraphs. Zero behaviour change; docs become reviewable and the files can be linted for length.
- Risk: none beyond keeping `tests/it/guidance.rs` string assertions in sync.

### F5. Hand-built JSON plus a second layer that parses it back: est. save: 500 (confidence medium)
- Where: ~440 `json!(` sites; everyday.rs 719 (`result_summary` 465, `job_summary` 490, `finished_summary` 569, `backup_summary` 607, `reconstruct_summary`, `ha_*_summary`, `plain_view` 765, `plain_group`, `plain_lookup`); jobs.rs `next_step`/`add_next_step`/`replace_next_step`/`commission_next_step` 821-1000 (180 lines keyed on `status["kind"] == "add"`); server.rs `with_summary` 224-245.
- What: tools build `serde_json::Value` by hand, then `everyday` and `jobs` re-read string keys (`value["started"] == true && value["done"] == false`) to derive the homeowner summary and the next step. Every key name exists twice and the summary logic cannot see types.
- Proposal: per tool a `#[derive(Serialize)]` result struct (the F1/F3 service outcomes already are) with `fn summary(&self, model) -> String` and `fn next_step(&self) -> String` implemented on the struct; `everyday.rs` shrinks to `device_phrase`, `room_of`, `join_and`, `PlanFacts` (~250). The post-hoc `with_summary` hook and `SUMMARIZED_TOOLS` list go.
- Risk: the JSON keys are the chat contract and are asserted in ~40 integration tests; derive with `#[serde(rename)]` to keep them byte-identical.

### F6. `knx_describe_device` re-implements `bussard describe`: est. save: 150 (+ ~150 in the CLI) (confidence high)
- Where: server.rs 982-1170, `describe_over_l4` 1401-1432; CLI describe_cmd.rs 177-370.
- What: both resolve tool/factory keys, open the session, walk objects, decide "refused walk" (empty walk after descriptor read, System 1 exempt), run `refused_walk_answers_under_factory_key`, and shape the result; the CLI adds the identity check and serial learning, the MCP adds the warm-connection reuse. Service has only `describe::walk_objects` (67 lines).
- Proposal: `bussard_service::describe::run(service, target, keys, Reuse) -> DescribeOutcome { report, plain, secured, on_factory_key, identity }` and make the warm connection a `BusService` concern (today `warm.rs` is MCP-only; the CLI reconnects per command).

### F7. `knx_read_group` and `knx_write_group` duplicate each other and the CLI read/write: est. save: 150 (confidence high)
- Where: server.rs 823-965 and 1182-1322; `admission_refusal_json`, `write_refusal_json` 1331-1400; read_cmd.rs 221, write_cmd.rs 231.
- What: the keys load, the "bus wired / connected" checks, the admission resolve with PID 54 read, the refusal JSON and the `note` are the same in both tools; the CLI has the same two again with text output.
- Proposal: `bussard_service::group::{read, write}(service, model, ga, GroupOp) -> GroupOutcome` that owns keys + admission + rate limit; both tools and both commands format `GroupOutcome`.

### F8. Flash decision duplicated and already divergent: est. save: 350 (confidence medium)
- Where: tools_program/flash.rs `load_need` 212, `load_image` 267, `flash_image` 99, `shape` 456, `gate_refusal` 844; service flash_flow.rs `probe` 130, `decide_freshness` 501, `parameter_plan` 653, `load_refusal` 860; CLI flash_cmd.rs 327-630.
- What: the MCP computes "does the device need its application loaded, and with which image" with its own code; the CLI uses `flash_flow::probe` + `decide_freshness`. `gate_refusal` is a fork of `load_refusal` that answers differently for `Freshness::Resident { reason: Some(_) }` (MCP refuses, service does not): a parity bug waiting for a device.
- Proposal: route the MCP plan through `flash_flow::probe`/`decide_freshness`/`parameter_plan`; delete `shape`/`gate_refusal`/`resident_line`. Keep `FlashJob` + `flash_write` as the job adapter (~200 lines).
- Risk: the oracle rows for flash (`95-offline-oracle.sh` plain and `--keyring`) stay the gate for the image; the decision change needs the `mcp_flash_sys7.rs` and `flash_mock.rs` resident-application cases.

### F9. The session-edit ledger duplicates History: est. save: 350 (confidence low-medium)
- Where: session_edits.rs 204, tools_model.rs `knx_discard_edits` 947-1165, `knx_undo` 824-947, `created_in_session` 1168, `refresh_device_facts` 1457-1535, `set_interface` 1962-2100.
- What: every edit snapshots with reason `mcp <tool>` and args; `SessionEdits` then keeps a second in-memory ledger per device/GA to answer "what is pending on this device" and to implement discard by replaying snapshots. History already has the snapshot list, its reasons, `undo_target`, and `describe(before, after)`.
- Proposal: `History::since(snapshot).for_subject(ia|ga)` computed from snapshots; discard = restore the subject's files from the snapshot before its first edit. `set_interface` (140 lines of field-by-field `[knxnet]` editing) belongs next to `knxnet::interface_config` in the service.

### F10. Parameter-key resolver lives in the MCP crate: est. save: 644 moved (≈100 net after merging) (confidence medium)
- Where: param_keys.rs (644): `KeyContext`, `resolve_parameter_key`, `unreached_refusal`, `closest` + hand-written `edit_distance` 796-858, `index_parameter`, `replace_parameter`.
- What: resolving a human key (`ch1.led_brightness`) against the product model's dynamic tree, with branch conditions and sibling disambiguation, is model logic (bussard-model `device_view.rs` already enumerates the shown keys per channel). Only `knx_set_parameter` and `guidance.rs` use it.
- Proposal: move to `bussard_model::device_view::resolve_key`, reuse the view's key enumeration, drop the private edit-distance (or use the one bussard-model must already have for `model_lookup`-style suggestions; if none, keep one copy there).

### F11. The audit report builder is in the wrong crate: est. 330 moved (confidence high)
- Where: tools_audit.rs 65-415 (`static_report`, `capability_json`, `SecureProbe`, `secure_live_report`, `gateway_report`, `traffic_report`); bussard-cli/src/audit_cmd.rs imports `bussard_mcp::tools_audit`. The CLI also takes `tier_help`, `READ_MIN_INTERVAL`, `args::redact_strings` from this crate.
- Proposal: `bussard_service::audit` with a typed `AuditReport: Serialize`; the CLI's 330-line `render_text` over `Value` (audit_cmd.rs 398-730) then renders the struct. Drops the cli→mcp dependency for everything but `run_*` and `McpConfig`.

### F12. Eleven copies of the reply helpers and the bus-ready check: est. save: 150 (confidence high)
- Where: `fn ok` ×9, `fn refusal/refused` ×7, `fn invalid` ×2, `fn hex` ×3, `fn who` ×3, `fn merge/merge_into` ×2, `fn chain/error_chain` ×2 (list from `grep "^fn ok(\|^fn refusal…"`); the "passive / bus not wired / not connected" ladder inline three times in server.rs (831-880, 993-1015, 1252-1270), `device_read_bus` (tools_device.rs 225), `programming_preflight` (tools_program.rs 996), tools_audit 530.
- Proposal: `crate::reply::{ok, refusal, invalid}`, `SharedState::live_service(Need) -> Result<&BusService, String>`, `bussard_model::hex`.

### F13. Enrolment and password form share one elicitation pattern: est. save: 250 (confidence medium)
- Where: tools_enroll.rs 860 (`EnrollJobs`, `new_elicitation_id`, `shows_urls`, `lock`, `end_reason` 374, `status_json` 420-560 with ~120 lines of `next_step` prose), password_form.rs 328 (`PendingForm`, `new_id`, `shows_urls`, `lock`, `collect`).
- What: `end_reason` re-describes `EnrollEnd::describe` (service enroll_session 371); the id/lock/`shows_urls` helpers are duplicated; the long `next_step` strings are F4/F5 material.
- Proposal: one `elicit.rs` (id, lifetime, `shows_urls`, `collect`) used by both; status prose into the typed outcome.

### F14. Job table: seven `claim_*` variants and string-keyed prose: est. save: 250 (confidence medium)
- Where: jobs.rs 266-360 (`claim`, `claim_scan`, `claim_plan`, `claim_read`, `claim_add`, `claim_replace`, `claim_commission`), 821-1000 (`next_step` family).
- Proposal: `claim(JobKind, Subject)` with the per-kind retention rule as a match; `next_step` on the typed job status (F5).

### F15. Tier membership is written three times: est. save: 120 (confidence high)
- Where: lib.rs `tool_names`/`tool_names_for`/`tool_names_with_ha` (three nested fns, ~80 lines), server.rs `new` 76-150 (`remove_route` per tier), the `*_TOOLS` consts in eight modules, tier_help.rs 119.
- Proposal: one `const TOOLS: &[(&str, Tier)]`; `tool_names(tiers)` filters it, `new` removes what the filter rejects, tier_help derives its lists.

### F16. Onboarding is a second server: est. save: 150 (confidence low)
- Where: onboarding.rs 565: `SetupMcp` with its own `call_tool`/`list_tools`/`get_tool`/`get_info`, `Chat` hooks, `activate`, `finish_setup`.
- Proposal: register `knx_setup` on `BussardMcp` behind a `RwLock<Option<SharedState>>` and swap the router after setup; rmcp's `ToolRouter` is already mutable in `new`. Needs a spike against rmcp 3.x's handler lifetime.

### F17. HA tools carry the same scaffolding without a service module: est. save: 200 (confidence medium)
- Where: tools_ha.rs 528, tools_ha_automation.rs 535: own `ok`/`refusal`, plan tables, digests, `ha_status` building JSON by inserting into a serialised struct's map (233-275).
- Proposal: F2's store, F5's typed results; `bussard_ha` gets `Status`/`Plan` structs that serialise directly.

### F18. Smaller: tools.rs `model_lookup` 98-275 (two variants, 180 lines) and `validate_filtered` 643-720 (diagnostic "mentions" parsing by splitting address strings) belong on `Model`/`Diagnostic`; tools_find.rs `scan_result`/`device_row`/`summary` (296-418) re-shape `scan::ScanReport` that is already `Serialize`.: est. save: 150 (confidence medium)

## Do not touch
- `args.rs` (128): the lenient argument deserialiser and the redaction are MCP-specific and small.
- `warm.rs` (99), `state.rs::ReadLimiter`, `instances.rs`, `http.rs`, `run.rs`: transport plumbing, no duplication.
- `tools_model.rs::edit_with_hook` (1223-1324) is the right shape (one path for all 12 edits); keep it, shrink around it.
- `line.rs`, `tools_device.rs::backup_devices`, `tools_files.rs`: already adapters over service flows; they shrink only through F2/F5/F12.
- The refusal messages and the three-step chat contracts (job → identified → yes) in `dev/chat-parity.md` are product decisions, not code to cut.

## Estimated total
Deleted outright: F1 1,400 + F2 650 + F3 1,650 + F5 500 + F6 150 + F7 150 + F8 350 + F9 350 + F12 150 + F13 250 + F14 250 + F15 120 + F16 150 + F17 200 + F18 150 ≈ 6,500 lines (≈29 % of the crate).
Moved to a better home (not deleted, but out of bussard-mcp and de-duplicated with the CLI on the way): F4 800 (to .md), F10 644, F11 330 ≈ 1,800.
Crate after: ≈ 14,100 lines (−37 %). The same service extraction removes an estimated 2,000-2,500 lines from bussard-cli (apply_cmd, plan_cmd, describe_cmd, adopt_cmd, replace_cmd, commission_cmd, read/write_cmd, audit render), which the CLI reviewer should count once.

Order of work: F1 first (it is also the CLAUDE.md write-path rule and the parity risk in F8 lives on it), then F3, F2, F5; F4/F11/F12/F15 are mechanical and can go in parallel.
