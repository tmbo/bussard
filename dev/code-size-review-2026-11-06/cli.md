# bussard-cli review

Total product lines: 18,133 (65 files; code lines excluding blanks, comments and `#[cfg(test)]`).

## Shape of the crate

`bussard-service` is a toolbox of primitives (`assign::write_address`, `flash_flow::probe`,
`flash_flow::flash_and_verify`, `verify::read_back_on`, `commission::identify_pressed`,
`adopt::flow::record_secured`, `line::visit_device`, ...). The CLI composes them into the
actual command flows with prints interleaved, and `bussard-mcp` composes the same primitives
a second time into its tools. The CLI uses 124 distinct `bussard_service::` items, MCP 112,
and 68 are shared: the two surfaces drive the same primitives in the same order. The
"flow" (preflight, identity gate, plan, confirm, snapshot, backup, write, read-back,
record lock) is where the duplicated code lives, not in literal copy-paste.

Secondary pattern: flat parameter passing. 19 functions take 8 or more parameters and there
are 23 `#[allow(clippy::too_many_arguments)]`; `main::run` destructures every clap variant
and re-packs it into those signatures (465 product lines for the dispatch alone).

Only 2 campaign greps look at CLI text (`refus`, `gateway listening`); 5 scripts use `--json`.
The text output is not a contract for the campaign; the JSON schemas (`output::schema::*`) are.

## Command inventory

| command | file | prod lines | adapter vs logic | MCP twin | service used |
|---|---|---|---|---|---|
| flash | flash_cmd.rs + flash_params.rs + flash_dump.rs + flash_handover.rs + flash_resident.rs | 1066+503+498+56+110 | **logic**: the whole pre-flight/gate/shape/write/verify flow | tools_program/flash.rs (718) + tools_program.rs apply_job | flash_flow::probe, flash_and_verify, record_lock, flash::FlashInputs, download::FlashRun |
| apply (+restore) | apply_cmd.rs, restore_cmd.rs | 813+249 | **logic**: read device, plan, admission, security change, confirm, backup, write, read-back | tools_program.rs plan_body/apply_preflight/apply_write (~1,150), restore.rs, restore_tables.rs | verify::read_back_on, security_change, admission, download::write_parameters |
| plan | plan_cmd.rs, plan_view.rs, device_plan.rs | 515+72+1 | **logic**: `read_device` (identify+tables+params+PID54+PID61) | tools_program.rs read_device/read_on (identical sequence) | params::read_state, identify |
| adopt | adopt_cmd.rs | 777 | **logic**: wait, target, write address, verify, read secured, knxnet, write file | tools_program/add_device.rs (1120) | adopt::flow::{adopt_target, record_secured, read_knxnet_settings}, assign::* |
| assign | assign_cmd.rs | 360 | logic: wait/confirm/write/verify/stub file; shared helpers used by adopt, replace, commission | add_device.rs | assign::* |
| commission | commission_cmd.rs | 484 | logic: probe line, per device assign + flash + apply by calling the other `*_cmd::run`s | tools_program/commission.rs (888) | commission::* |
| replace | replace_cmd.rs | 337 | logic: `swap_flow` step machine | tools_program/replace_device.rs (937) | replace::*, assign::* |
| line (plan/apply --line) | line_cmd.rs | 500 | half: state file, resume, visit loop, json | tools_program/line.rs | line::visit_device |
| interface (plan/apply) | interface_cmd.rs, interface_session.rs | 390+197 | logic: read_and_plan, apply, backup | tools_program/interface.rs (492) | knxnet::{read_interface, plan_interface, apply_interface} |
| interface secure | interface_secure_cmd.rs | 285 | adapter (service `ip_secure::run_switch` holds the flow) | ip_secure.rs (150) | ip_secure |
| scan | scan_cmd.rs | 409 | adapter + 267 lines of stats/table rendering | tools_find.rs | scan::{sweep, cross_reference} |
| describe | describe_cmd.rs | 528 | logic: own Report structs + secure classification + 127 lines text | tools_device.rs | describe::walk_objects |
| audit | audit_cmd.rs | 673 | adapter over `bussard_mcp::tools_audit` (CLI depends on the MCP crate) + 345 lines text renderer | tools_audit.rs | none (goes through mcp) |
| keys import/export/show/add-certificate | keys_cmd.rs, certificate_view.rs | 683+75 | adapter + 263 lines of report/table text | tools_files.rs, tools_enroll.rs | files::keyring, CertificateEnrolment |
| keys enroll | enroll_cmd.rs | 273 | adapter | tools_enroll.rs (860) | enroll_session |
| learn | learn_cmd.rs | 494 | logic: learn loop, decisions, linking | tools_learn.rs knx_infer_group | none (bussard_monitor::infer) |
| history/status/show/undo | history_cmd.rs | 427 | logic: undo flow incl. key store restore (copied in MCP) | tools_model.rs knx_history/knx_undo | group_security::restore_group_keys |
| mcp | mcp_cmd.rs | 509 | adapter + 273 lines of connect-hint rendering | onboarding.rs |: |
| init / import / import-product / export | init_cmd.rs, import_cmd.rs, import_product_cmd.rs, export_cmd.rs, product_fetch.rs, product_store.rs, product_cache.rs | 314+88+99+52+37+65+12 | adapter | tools_files.rs | setup::*, files::* |
| conn / globals | conn_cmd.rs, main.rs, secure_key.rs, device_facts.rs, lock_pin.rs, param_readback.rs | 495+1712+127+43+136+144 | config resolution; thin wrappers adding anyhow context | server.rs/state.rs | secure::*, params::*, status::* |
| output | progress.rs, style.rs, output.rs, confirm.rs, console.rs, timing.rs | 492+242+61+59+29+55 | presentation |: |: |
| rest (backup, restart, read, write, test, monitor, capture, viz, groups, validate, diff, doc, export-groups, ha-config, device, secure diag) | | ~2,000 | mostly adapters | | |

## Findings (ordered by lines saved, largest first)

### F1. Move the device-programming flows (flash, apply, plan, parameters-only) into `bussard-service` once: est. save: 2,600 lines in the CLI (plus ~2,000 in bussard-mcp) (confidence high)

- Where: `flash_cmd.rs:59-775` (532 lines of `run`), `flash_cmd.rs:776-1015` (dry run and errors, 187), `flash_params.rs:104-321` (180), `apply_cmd.rs:260-1004` (`apply_desired` + `write_tables_then_parameters` + `write_parameters`, 609), `plan_cmd.rs:79-568` (readers + `run`, 394), `restore_cmd.rs` (249), `flash_handover.rs`, `device_facts.rs`, `secure_key.rs`.
- What: the CLI `flash` is a 530-line function that calls, in order, `load_model_required`, `secure_key::resolve_material`, `admitted_tunnel`, product resolution (`product_store`, `product_cache`, `select_application`), `FlashInputs::from_model`, `lock_pin::enforce_override`, `BusSession::open`, `flash_flow::probe`, `assess_freshness`, `inputs.finish`, `security_change::from_flash_plan`, `flash_gate`, `decide_freshness`, confirm, `history::snapshot`, `flash_and_verify`, `record_lock`, and prints between every step. `bussard-mcp/src/tools_program/flash.rs` (718 lines) plus `apply_job` in `tools_program.rs` call the same functions in the same order with their own `gate_refusal`/`resident_line` text instead of `decide_freshness`. `apply_cmd::apply_desired` (385 lines) and MCP `plan_body` (400) + `apply_preflight` (300) + `apply_write` (470) are the same story for the table write: both build `L4Options`, run identify + `read_live_tables_at` + `params::read_state` + `read_security_sender_table` + `read_security_flags` (CLI `plan_cmd::read_device` at `plan_cmd.rs:237-330` vs MCP `read_on` at `tools_program.rs:3249-3329`, line for line), build `TunnelAdmission` and `SecurityObjectChange`, compute `Expected`, write, then `verify::read_back_on`. `plan_cmd::table_bases`, `read_admission_table`, `read_security_flags`, `tunnel_admission`, `security_change` (`plan_cmd.rs:79-172`) are pure service helpers that only live in the CLI because the CLI was written first.
- Proposal: one `bussard_service::program` module with `FlashFlow`, `ApplyFlow` (also serving `restore` and `--parameters-only`) and `read_device` returning typed stage results (`Planned { plan, params, gate, security_change, question }`, `Written { verify, readback, lock_record }`), driven through a small `FlowObserver` trait (`fn step`, `fn note`, `fn confirm(&Question) -> bool`). The CLI implements the observer with `eprintln!`/`confirm::confirm`/`FlashDisplay`; MCP implements it with `jobs.step` and the plan-digest hand-shake. Each surface keeps only argument parsing and one `render_text`/`to_json` of the typed results. `flash_cmd.rs` + `flash_params.rs` + `apply_cmd.rs` + `plan_cmd.rs` + `restore_cmd.rs` (3,146 lines) become roughly 550 lines of adapters; the service gains roughly 1,100 (most of it moved, not new). MCP loses a similar amount.
- Risk / constraints: this is exactly what CLAUDE.md "Device Writes" asks for (one write path; #314 happened because there were two). The bytes written do not change, so `scripts/campaign/95-offline-oracle.sh` rows must stay byte-identical before and after (the dry run and `flash_dump::write_dump` stay, moved with the flow). Every step keeps its read-back. The CLI `--json` shapes (`output::schema::FLASH`, `PLAN`, `APPLY`) and the campaign's two text greps must be kept; the MCP plan digest (`plan_digest`, `live_digest`) must come out of the shared `Planned` so it cannot drift.

### F2. Move the addressing flows (assign, adopt, replace, commission) into `bussard-service` once: est. save: 1,100 lines in the CLI (confidence high)

- Where: `assign_cmd.rs:170-330` (`assign_flow`, 111), `adopt_cmd.rs:325-560` (`adopt_flow`, 182) and `adopt_cmd.rs:198-325` (product selection, 90), `replace_cmd.rs:232-351` (`swap_flow`, 112) and `replace_cmd.rs:53-232`, `commission_cmd.rs:290-460` (`commission_one`, `assign_on_bus`, 149) and `102-290`.
- What: four commands each re-run "wait for the one device in programming mode, check the target is free, confirm, `write_address`, `verify_assignment_with`, warn if still in programming mode, write the device file, attach serial". `wait_for_single_device_as`, `target_is_free`, `warn_if_still_in_programming_mode` are defined in `assign_cmd.rs` and used by the other three; `bussard-mcp/src/tools_program/add_device.rs` (1,120 lines), `replace_device.rs` (937) and `commission.rs` (888) re-compose the same service primitives again. `commission_one` runs `flash` and `apply` by calling `flash_cmd::run` and `apply_cmd::run` with 16 positional arguments, which is why those signatures cannot shrink. `replace_cmd::swap_flow` is a hand-rolled step machine over `bussard_service::replace::Step` whose only CLI-specific content is the message text per step.
- Proposal: `bussard_service::assign::AssignFlow` (wait, target, free check, write, verify, record) with the three programming-mode helpers moved to the service, used by `adopt`, `replace` and `commission` as a sub-step; `commission` then composes `AssignFlow` + `FlashFlow` + `ApplyFlow` from F1 instead of recursing into CLI commands. The CLI keeps the wizard text (`step(n, ...)`, `print_links_snippet`, `print_summary`, `print_secure_summary`: 276 lines in adopt, worth a separate trim, see F6).
- Risk / constraints: the address write and the verify read-back stay the same functions; `adopt` of a Data Secure device must keep reading under the tool key (#201). MCP `add_device`/`replace_device`/`commission` are the bigger beneficiaries and must switch in the same PR series so the flow exists once.

### F3. Make each subcommand an `Args` struct that runs itself; replace `main::run` and the `Role`/`supports_json`/`has_tool_key`/`early_consent` tables: est. save: 700 lines (confidence high)

- Where: `main.rs:1869-2340` (dispatch, 465 lines), `main.rs:200-420` (`Role`, `has_tool_key`, `early_consent`, `supports_json`, `Resolved`, 165 lines), the `Command` enum (`main.rs:820-1725`): `tool_key: Option<String>` declared 12 times with the same three-line doc, `yes: bool` 15 times, `product: Option<PathBuf>` 7 times.
- What: every variant is destructured in `run` and re-packed into a `*_cmd::run(a, b, c, ..., 16 args)` or an ad-hoc `XOptions` struct; four separate `match self` tables describe per-command traits (bus or files, consent text, JSON support, tool key); the shared arg groups are copy-pasted into each variant.
- Proposal: `#[derive(Args)] struct FlashArgs { #[command(flatten)] target: TargetArgs, #[command(flatten)] consent: Consent, ... }` per command in its own module, with `impl Run for FlashArgs { const ROLE: Role; const JSON: bool; fn consent(&self) -> Option<String>; fn run(self, g: &Resolved) -> Result<ExitCode> }`; `Command` becomes `enum Command { Flash(FlashArgs), ... }` and `run` is `match self { Command::Flash(a) => a.run(g), ... }` (one line per command). `ToolKey`, `Consent { yes }`, `ProductSelection { product, application }`, `LineRange { from, to }` are flattened arg structs. The four trait tables collapse into the impl. Also removes the 23 `too_many_arguments` allows and `cli_name`'s Debug-string parsing (clap knows the name).
- Risk / constraints: `--help` text must stay (same doc comments, now on the arg structs); flag names and `conflicts_with`/`requires` move with them. Mechanical, no bus behaviour.

### F4. Text renderers from JSON values and hand-built `json!` blocks: one typed report per command: est. save: 900 lines (confidence medium)

- Where: `audit_cmd.rs:398-760` (`render_text` over a `serde_json::Value`, 345 lines), `audit_cmd.rs:96-398` (`products_report`, `live_report`, `scan_model_devices` building `Value` by hand, 258), `scan_cmd.rs:221-520` (267), `describe_cmd.rs` (own `Report`/`ObjectReport`/`PropertyReport`/`SecureReport` structs + 127 lines text), `keys_cmd.rs:99-212` and `327-486` (263), `flash_cmd.rs:1121-1420` (`print_plan`, `plan_json`, `kept_memory_*`, 264), `history_cmd.rs` (`change_json`, `print_raw_diff`), `line_cmd.rs`/`commission_cmd.rs` (`DeviceJson`/`LineJson`/`CommissionJson` + `to_json` + `print_summary`, ~120 each).
- What: the audit report is computed in `bussard_mcp::tools_audit` as untyped JSON and the CLI then walks that JSON with `text_or`/`array`/`n` helpers to print it; the CLI is the only crate that depends on `bussard-mcp` for domain logic (wrong direction: `audit_cmd.rs:21`, `364`). `flash` builds its `--json` by hand from `FlashPlan`/`ParamPlan` while `bussard_download::PlanReport` and `DevicePlan` already derive `Serialize` and have a shared renderer (`plan_view::render`). `scan`'s `SweepStats` recomputes counts the service `Sweep` already has (`Sweep::count`, `Sweep::summary`). `describe` keeps its own report structs although `bussard_service::describe::ObjectDescription` exists.
- Proposal: the computation of audit, scan, describe, keys-show, flash-plan reports becomes a `#[derive(Serialize)]` struct in `bussard-service` (audit moves out of `bussard-mcp` into `bussard_service::audit`); `--json` is `output::print(schema, &report)` with no `json!`; the text view is one `impl Display`/`render_text` per report in the CLI, written against typed fields instead of `Value` lookups. `bussard-cli` drops its dependency on `bussard-mcp` except for `mcp_cmd` and `tier_help`.
- Risk / constraints: JSON field names are a contract for scripts and docs (`docs/reference`); derive with the same names. Keep the schema line.

### F5. Delete the thin wrapper modules that only add `anyhow` context around service calls: est. save: 450 lines (confidence high)

- Where: `secure_key.rs` (127: `resolve`, `resolve_session_keys`, `resolve_material`, `admitted_tunnel`, `secure_hint`, `group_keys` wrap `bussard_service::secure::*`), `device_facts.rs` (43), `product_cache.rs` (`read`, `by_application`, re-exports), `product_store.rs` (65, wraps `files::products::prepare`, `setup::products::complete_models`, `device_archive` already in `params`), `product_fetch.rs` (37), `lock_pin.rs` (136: `enforce_override`/`override_conflict`, the lock-pin rule, which MCP has no twin for and therefore does not enforce), `param_readback.rs` (144: `resolve` wraps `params::resolve_product`, plus a `ParamState` display), `flash_handover.rs` (56), `interface_session.rs` (197, a second `BusSession`).
- What: the pattern is `pub fn x(args) -> anyhow::Result<T> { bussard_service::x(args).context("...") }`, sometimes with an `Error` newtype so `main` can downcast; `admitted_tunnel` has a copy in `tools_program.rs:1040`; `lock_pin` is a policy that belongs next to the lock in the service (so MCP enforces it too).
- Proposal: callers use `bussard_service::secure::*` directly with `.context()` at the call site; `admitted_tunnel`, `enforce_override`, `read_only_authorize`-with-cache and `ProductSource::resolve` live in the service once; `interface_session` folds into `conn_cmd::BusSession` (one `open` with an optional device-management keyring hook).
- Risk / constraints: `secure_hint` wording is user-facing guidance; keep the strings, move them into `bussard_service::guidance` where the other hints already are.

### F6. Trim wizard prose and repeated `confirm`/`recovery_notice`/`snapshot` boilerplate: est. save: 500 lines (confidence medium)

- Where: `adopt_cmd.rs:616-940` (`print_links_snippet`, `print_summary`, `print_secure_summary`, `import_product`, `prompt_index`: 276), `assign_cmd.rs` "next steps" prints, per-command `fn confirm(...)` in `flash_cmd.rs:1375`, `apply_cmd.rs:1029`, `flash_params.rs:600`, `line_cmd.rs:545`, `commission_cmd.rs:525`, `replace_cmd.rs:371`, `test_cmd.rs:319` (each builds a question string and calls `confirm::confirm`), `recovery_notice` in `flash_cmd.rs:1405`, `apply_cmd.rs:1070`, `flash_params.rs:620`, `history_cmd::snapshot(... SnapshotReason::new(verb).with_args(..).with_gateway(..).with_result(..))` repeated in nine commands, `mcp_cmd.rs:372-700` (`ConnectHint` builder, JSON pretty-printer by string concatenation, shell quoting: 273 lines).
- What: the `Question`/`Recovery` text comes out of the flow in F1 (`Planned.question`, `DevicePlan::question()` already exists in `bussard_download`), so the seven `confirm` wrappers collapse into one `confirm::ask(&question)`; the snapshot call becomes `history::snapshot(dir, verb, target, gateway)`; the `ConnectHint` JSON can be a `serde_json::json!` value printed with `to_string_pretty` instead of a hand-built string, and the `claude mcp add` command one `format!`.
- Risk / constraints: wording is covered by `tests/it` snapshots in places; update them with the PR.

### F7. `history_cmd::run_undo` and `knx_undo` are the same 100 lines: move the undo flow into `bussard-service`: est. save: 150 lines in the CLI (confidence high)

- Where: `history_cmd.rs:258-383` vs `bussard-mcp/src/tools_model.rs:824-900`.
- What: list snapshots, resolve target, load, `describe`, `history.restore`, `group_security::restore_group_keys` with the same error sentence, same JSON shape. `run_show` and `knx_history` likewise.
- Proposal: `bussard_service::history::{undo, show, list}` returning a typed `UndoOutcome`; both surfaces render it.
- Risk: none on the bus; model-file only.

### F8. `learn_cmd` decision loop: split the interactive prompt from the model edit: est. save: 150 lines (confidence medium)

- Where: `learn_cmd.rs:225-540` (271 lines: `learn_loop`, `consider`, `maybe_link`, `print_observation`).
- What: `consider` mixes the inference (`bussard_monitor::infer`), the model edit (`model.groups.groups.entry(ga)`), the link edit and an inline readline menu. MCP `knx_infer_group` does the inference half again against the ring buffer.
- Proposal: `bussard_service::learn::{observe, accept}`: `observe(model, telegram, earlier) -> Observation { candidates, proposed_name, object }` shared with `knx_infer_group`; `accept(model, ga, Decision)` applies the edit. The CLI keeps the menu (~60 lines).

### F9. `progress.rs`: three display types with the same live/plain split: est. save: 150 lines (confidence medium)

- Where: `progress.rs:262-409` (`FlashEta`, 106 lines of ETA smoothing), `409-700` (`FlashDisplay`, `SweepDisplay`, `TaskDisplay`, each with `new`/`finish`/`Drop` and the `live(json)` gate).
- Proposal: one `Display { bar: Option<ProgressBar>, plain: fn }` with three template constants; drop `FlashEta` in favour of indicatif's built-in `eta`/`per_sec` keys on a bytes-length bar (the plan's `estimated_duration()` already exists for the first estimate).
- Risk: cosmetic only.

### F10. Smaller items: est. save: 300 lines (confidence medium)

- `describe_cmd.rs:152-176` `PlainManagement`/`SecuredManagement` enums and the five-way match: fold into `bussard_service::identity::SecureStatus`, which already names the same states.
- `commission_cmd.rs:472-525` `append_labels`/`csv_field`: a 50-line CSV writer; `bussard_service::commission::label_line` exists, so the CLI writes lines.
- `line_cmd.rs:489-545` resume state file (`open_state`, `write_state`, `is_done`) is a CLI-only feature MCP solves with jobs; move the state type next to `LineOutcome` in the service so `--resume` and the MCP job share one record (removes `DeviceRecord`/`LineState` duplication with `LineOutcome`).
- `conn_cmd.rs:272-304` `checked_source` / `checked_source_or_close`: fold into `BusSession::open` (every command calls them right after opening).
- `test_cmd.rs:124-206` `run_secure_idle` (idle-session probe, a #197 diagnostic): if still needed, it belongs under `secure diag`, else delete.
- `output.rs::with_schema_line` and `style.rs::count`/`summary` are fine; `console.rs` and `timing.rs` are fine.

## Do not touch

- `flash_dump.rs` (498): writes the images the offline oracle compares (`95-offline-oracle.sh` uses `flash --dry-run --dump-images`). Moves with the flow in F1 but its records must stay byte-identical.
- `conn_cmd.rs` keyring/.env/gateway resolution (`resolve_model_dir`, `apply_dotenv`, `resolve_keyring`, `resolve_config`, `attach_keyring_tunnel`): the documented precedence rules (#228, #251, #287); only the two `checked_source` helpers are redundant.
- `style.rs` `Table`/`Cell`/`Tone`: the one table renderer, used by scan, keys, describe.
- `init_cmd.rs` `Terminal` hooks: the service already owns the setup flow (`setup::run<H: SetupHooks>`); this is the right shape and the model for F1/F2.
- `interface_secure_cmd.rs` is likewise already thin over `ip_secure::run_switch` (MCP's `ip_secure.rs` is 150 lines); keep as the example of the target shape.

## Estimated total

| finding | lines saved in bussard-cli |
|---|---|
| F1 programming flows to service | 2,600 |
| F2 addressing flows to service | 1,100 |
| F3 Args-per-command dispatch | 700 |
| F4 typed reports, audit out of bussard-mcp | 900 |
| F5 wrapper modules | 450 |
| F6 prose and boilerplate | 500 |
| F7 undo/show to service | 150 |
| F8 learn split | 150 |
| F9 progress displays | 150 |
| F10 smaller items | 300 |
| **total** | **~7,000 (39% of the crate)** |

Net for the workspace is larger: F1, F2 and F7 remove a second copy of the same flows from `bussard-mcp` (roughly 2,500 more lines there, since `add_device.rs`, `replace_device.rs`, `commission.rs`, `flash.rs` and `apply_*` in `tools_program.rs` are the longer copies), against roughly 1,500 lines that move into `bussard-service`.

Suggested order: F3 first (mechanical, unblocks the narrower signatures), then F1 behind the oracle gate, then F2, F4, F5 together, then the rest.
