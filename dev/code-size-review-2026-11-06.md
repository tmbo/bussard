# Code size review, 2026-11-06

Goal set by the owner: cut the product code (not tests, not sweep or download
tooling) by 40 % through simplification, de-duplication and a better division of
responsibility. Seven reviewers read the 16 crates; their per-crate reports with
file and line ranges are in `dev/code-size-review-2026-11-06/`. This document is
the synthesis: what the code base is made of, where the size comes from, what a
pure refactor can remove, and what only a product decision can.

## 1. Baseline

Measure: code lines in `crates/*/src`, excluding blank lines, comment lines and
`#[cfg(test)]` modules (`dev/code-size-review-2026-11-06/loc.py`). The 56k
comment lines and the 128k test lines are not counted.

| crate | product lines | role |
|---|---|---|
| bussard-model | 26,246 | types, DPT codec, Dynamic evaluator, TOML files, lock, history |
| bussard-mcp | 22,439 | MCP server, 60 tools |
| bussard-cli | 18,133 | 60 commands |
| bussard-service | 16,966 | the layer between surfaces and domain |
| bussard-download | 15,752 | flash planning and execution, parameter image decode |
| bussard-mgmt | 6,625 | layer-4 connection, APCI, load procedures |
| bussard-transport | 5,355 | KNXnet/IP tunnel, cEMI |
| bussard-project | 5,222 | .knxproj import, key store, keyring |
| bussard-testkit | 3,978 | mock gateway and device (dev-dependency) |
| bussard-prod | 3,802 | .knxprod reading, parameter image |
| bussard-ets | 3,074 | application program XML parser |
| bussard-viz | 2,596 | web UI server |
| bussard-ha | 2,338 | Home Assistant export |
| bussard-monitor | 2,225 | bus monitor, capture |
| bussard-secure | 2,137 | KNX Secure crypto |
| bussard-bus | 720 | bus actor |
| total | 137,608 | |

40 % is 55,000 lines. Literal copy-paste is rare: a 10-line duplicate-block
scan over product code finds under 1,000 duplicated lines. Dead code is under
1,000 lines (17 uncalled public functions, 83 test-only ones). The size comes
from structure, so the savings come from structure.

## 2. Verdict

| tier | lines | share | behaviour change |
|---|---|---|---|
| A. refactor only (section 5) | ~27,000 | ~20 % | none: same bytes on the bus, same JSON keys |
| B. plus small product decisions (section 6.1) | +1,400 | ~21 % | drops four minor conveniences |
| C. plus feature-scope cuts (section 6.2) | up to +14,000 | up to ~31 % | drops whole capabilities |

Reaching 40 % by refactoring is not possible: the three reviewers of the
protocol crates (download, mgmt, transport, secure) each conclude their code is
spec-sized, and the model crate reaches 14 % by refactoring and 29 % only with
feature removals. The 40 % line is crossed only by dropping a major capability
(System 7 support, 3,300 lines, or certificate enrolment, 4,200 lines) on top of
tier C. That is the owner's decision, not a review finding.

Tier A is still worth doing in full. Most of it removes the second and third
copies of the write path, which is the #314 bug class CLAUDE.md names as the
most expensive process failure. Section 3 lists one such divergence found today.

## 3. Bugs found on the way (fix before or with the refactor)

1. **MCP flash gate diverges from the service gate.** `tools_program/flash.rs`
   `gate_refusal` refuses a device that runs an identified other application;
   `flash_flow::load_refusal` allows it (the plan names the replaced
   application and the yes covers it). Same `Freshness` input, different
   answer. Whichever is intended, there must be one function.
2. **Two incompatible fingerprints of one device read.** `tools_program.rs`
   `live_digest` is a copy of `bussard_download::state_hash_with` with a
   different salt, so a plan carries two hashes of the same state.
3. **Lock-pin override policy enforced only in the CLI.** `cli/lock_pin.rs`
   has no MCP twin, so the assistant does not enforce it.
4. **Dependency inversion.** `bussard-cli` imports `bussard_mcp::tools_audit`
   for the audit report. Domain logic in a surface crate, consumed by another
   surface.
5. **Responder-side codecs shipped in the product.** 17 `encode_*_response` /
   `decode_*_read` functions in `bussard-mgmt` have no non-test caller.

## 4. Diagnosis: three patterns account for most of the size

**4.1 The service is a toolbox, not a set of flows.** `bussard-service`
exposes primitives (`write_tables_seeded`, `flash_and_verify`, `read_back_on`,
`identify`, `adopt::flow::*`) but no runner for apply, plan, flash decision,
adopt, replace, commission, describe, group read/write or undo. The CLI
composes the primitives into flows with prints between the steps; the MCP
composes the same primitives again with JSON between the steps. The CLI uses
124 service items, the MCP 112, 68 shared. Verified today: `plan_cmd::read_device`
and `tools_program::read_on` run the same nine steps in the same order; the
single-device apply exists in `service/line.rs::visit` (262 lines),
`cli/apply_cmd.rs` (452) and `mcp/tools_program.rs` (515). Where the service
does own the flow (setup, import, line, backup, enrol session, interface
secure) the surface file is 150 to 600 lines instead of 1,000 to 3,000.
The CLI makes 104 direct calls into `bussard_download`/`bussard_mgmt` from
five flash files, the MCP 38 from `tools_program.rs`; these are the places a
surface does the service's job.

**4.2 One concept, several models along a pipeline.** The application program
has four in-memory forms and two on-disk caches: `ApplicationProgram` (ets),
the parsed-product JSON cache (prod), a Serialize-only `Model*` tree written as
YAML (prod), a Deserialize-only `Raw*` tree read back and converted into
`ProductModel` (model), plus a second serde form of the Dynamic tree
(`dynamic_compact.rs`, 523 lines) just for that YAML. Downstream, parameter
rows exist four times (`ParamRow`, `ParameterDoc`, `ParameterFact`,
`ParamDetail`). The same shape repeats for key material (`Keyring` and
`KeyStore` with parallel XML parsers and converters), device facts (three
structs named `DeviceFacts`), progress reporting (12 observer and prompt
shapes adapted separately by `cli/progress.rs` and `mcp/jobs.rs`), errors (19
per-flow enums in service that only wrap callee errors; 179 functions return
`Result<_, String>`), and line walking (four walkers, three `parse_line`).

**4.3 Surfaces shape output by hand and then read it back.** 488 `json!` sites
in the MCP crate, 115 in the CLI (`flash_dump.rs` alone is 498 lines of it),
`--json` handled by hand in 30 CLI files, while the service and download
crates already return `Serialize` reports. `mcp/everyday.rs` (719 lines) and
`jobs.rs` then parse string keys out of the hand-built values to produce the
homeowner summary and the next step. The CLI audit command walks an untyped
`Value` with `text_or`/`array`/`n` helpers to print it.

## 5. Tier A: the refactor plan

Lines are product lines removed from the workspace after the moved code lands
in its new home. Overlaps between reviewers were removed; the sum carries an
uncertainty of roughly 15 %. Gates name the test or oracle that proves no
behaviour change. Details with file and line ranges are in the per-crate
reports (abbreviated `cli F1` and so on).

| # | work package | lines | gate | detail |
|---|---|---|---|---|
| 1 | Programming flow once: `service::program` with `FlashFlow`, `ApplyFlow` (also restore and parameters-only), `read_device`, typed `Planned`/`Written` outcomes, one observer trait. CLI flash/plan/apply/restore files and MCP `tools_program.rs` apply/plan plus `flash.rs` become adapters. Fixes bugs 1 and 2. | 3,800 | every `95-offline-oracle.sh` flash and apply row identical; `mcp_flash*.rs`, `apply_*`, `flash_parameters_mock.rs` | cli F1, mcp F1 F8, service F1, xcut A |
| 2 | Addressing flow once: `service::adopt::run` (identify, product, assign, verify, record); replace = backup + adopt + apply; commission = line walk + adopt per device. MCP `add_device`, `replace_device`, `commission` and CLI adopt/assign/replace/commission keep only questions and rendering. | 2,200 | `adopt_mock.rs`, `assign_mock.rs`, `mcp_add_device.rs`, `mcp_commission.rs`; chat contract in `dev/chat-parity.md` unchanged | cli F2, mcp F3 |
| 3 | Remaining duplicated flows: describe, group read/write, undo/history, learn observe/accept, interface read-and-plan. | 550 | mock suites per command | cli F7 F8, mcp F6 F7 |
| 4 | Typed reports: every service entry returns `Serialize` plus one `render_text`; surfaces never build `json!`; audit report moves from MCP to service (bug 4); `everyday.rs` summaries become methods on the result types. | 2,500 | JSON keys kept with `serde(rename)`; the ~40 MCP integration tests that assert keys; `output::schema::*` | cli F4, mcp F5 F11 F18, xcut B |
| 5 | MCP scaffolding: one plan-confirm store (nine today, 13 digest functions), one job claim, one reply helper set, one elicitation module, one tool/tier table, onboarding as a route not a second server, HA tools on the same scaffold. | 2,100 | `mcp_*` suites, `guidance.rs` | mcp F2 F9 F12 F13 F14 F15 F16 F17 |
| 6 | CLI scaffolding: one `Args` struct per command that runs itself (removes the 465-line dispatch, four trait tables, 23 `too_many_arguments` allows), delete the anyhow wrapper modules, one `confirm::ask(&Question)`, one snapshot call, one progress display. Move `lock_pin` into the service (bug 3). | 2,100 | `--help` snapshot, `tests/it` | cli F3 F5 F6 F9 F10 |
| 7 | One application-program model: build `ProductModel` from the cached `ApplicationProgram`, delete the YAML round trip (`Model*`, `Raw*`, `from_yaml`, `load_op_summary`, `dynamic_compact.rs`), one static parameter placement shared by prod `image.rs` and download `param_decode.rs`, one parameter row type. Also removes the YAML parse the perf baseline names as the dominant cost. | 2,450 | every plain oracle row identical with unchanged coverage figures (image bytes); model and prod suites | model F1 F2, download F1 F2, service F4, xcut C |
| 8 | bussard-model internals: one Dynamic-tree visitor (four walkers today, plus a gate text round trip), one `DeviceAnalysis` (nine entry points today, checklist evaluates each device five times), lock written by derive instead of 214 hand lines, device file with one reader and one recursive merge, field descriptor table for diff/merge/reconcile/checklist, numeric DPT descriptor shared by decode/parse/encode, analysis from diagnostics, one-line scaffold tables, one memo cache. | 2,330 | model suites; `knx_show_device` JSON contract in `guidance.rs`; lock fingerprint test; device-file edit tests | model F3 to F8, F10, F12, F14, F16 |
| 9 | Key material: `KeyStore` is the one model (delete the `Keyring` structs and parallel parser, keep its crypto half), one `KeyringExport`, one `resolve_keys` in service replacing `conn_cmd`'s and `secure.rs`'s paths, key-store rules and type in one crate. | 900 | signed `.knxkeys` export byte-identical (ETS accepts it, #349); secure mock suites | small F1, xcut D |
| 10 | One `ServiceError` with `Refused(String)` replacing the 19 flow enums; no `Result<_, String>`; MCP maps once. | 900 | error text asserted in tests stays | xcut E |
| 11 | One `ProgressSink` and one `Prompt` (one `Event` enum) in service; CLI, MCP job table and viz hub implement them. | 400 | cosmetic | xcut F, cli F9 |
| 12 | Enrolment in one place: service owns session and relay client; viz has one loopback `LocalServer` (three verbatim copies today) and one page template; MCP and CLI thin. | 800 | `enroll_e2e.rs`, `mcp_enroll.rs`, `dev/enroll/vectors-v2.json` | small F12, mcp F13, xcut G |
| 13 | One `DeviceFacts` record (model) extended with the pre-flight fields; project's becomes `LockKeys`; `DeviceCapture` folds into `DeviceBackup`. | 600 | facts cache tests | xcut H |
| 14 | bussard-download internals: one step-loop driver for the three executors, `sweep.rs` to tests, 21 wrapper ladders to one function each, 112 unused re-exports pruned, step labels and sys7 records once, hex/date/JSON helpers once, `param_plan` step walk once, reboot probe loop once, LoadOp defaults applied at parse time. | 1,360 | mock campaigns `flash_mock*.rs`, `property_procedure.rs`, `virtual_device_flash.rs`; no timing constant changes | download F3 F4 F5 F7 to F11 |
| 15 | service, mgmt, bus internals: one `read_identity` (five copies), one line walker and `parse_line`, `L4Options` constructors (48 literals), `ip_secure` step table and `with_l4` reuse, verdict wrappers, env knob parser, one product download flow; mgmt responder codecs to tests (bug 5), `DeviceConnection` wrapper removed, `_within` doubles, `TablesError` folded. | 1,365 | mgmt and service suites; `ip_secure::records()` byte-identical | service F2 F3 F5 to F11 |
| 16 | Small crates: transport `devmgmt::Task` reuses the tunnel task machine, unused config knobs, secure `random_bytes` and X25519 pair once, monitor `run_stream` ladder to one options struct, viz `ModelHandle` wrapper, project `slugify` and dead API. | 525 | `mock_gateway.rs`, `device_mgmt.rs` unchanged | small F3 F4 F6 F7 F9 F10 F11 F13 F14 |
| 17 | Workspace helpers once in bussard-model: `hex` (24 copies), civil date/RFC 3339 (5), `escape_html` (3), `slug`, `edit_distance`, `join_and`. | 350 | unit tests | model F15, download F8, small C1 |
| 18 | Guidance and tool-description prose as markdown files loaded with `include_str!`. The text stays; it stops being code. | 750 | `guidance.rs` string assertions | mcp F4, xcut I |
| 19 | Crate merges, 16 to 11: bus into transport; ets, prod, the import half of project and `facts.rs` into `bussard-product`; key store into model (project disappears); surfaces depend on service and model only, enforced by Cargo. | 600 | `cargo deny`, workspace build | xcut, small F5 |
| | **total** | **~27,000** | | |

Package 19 removes little by itself but is what makes 1, 2, 4 and 7 stick:
once `bussard-cli` and `bussard-mcp` cannot import `bussard_download` or
`bussard_mgmt`, a third copy of a flow cannot be written.

### Sequencing

- 6 (Args per command) first: mechanical, unblocks the narrower signatures
  that 1 and 2 need, no bus behaviour.
- 1, then 2, then 3: the write path, one package at a time, each behind the
  offline oracle and the mock suites on both surfaces. 11 (observer) lands with
  1 since the flow needs it.
- 4 and 5 after 1 and 2, because the typed outcomes come from the flows.
- 7 and 8 are independent of the surface work and can run in parallel in their
  own worktrees; 7 before 8 inside the model crate (both touch
  `param_model.rs`).
- 9, 10, 12, 13, 14, 15, 16, 17, 18 are independent of each other; 19 last.
- Conflict hot-spots, one agent at a time: `mcp/tools_program.rs`,
  `cli/main.rs`, `cli/flash_cmd.rs`, `service/params.rs`,
  `model/param_model.rs`.

### Do not touch (every reviewer's list, merged)

The Dynamic evaluator core (`model/dynamic.rs`), `files.rs` mem-key
resolution, history, the validation rules; the two plan lowerings
(`flash/plan.rs`, `plan_sys7.rs`), `verify.rs`, `write_image`, region
merging, `security.rs` ordering, `preflight.rs`; the streaming ETS parser and
the `image.rs` codec; the TL state machine (`mgmt/connection.rs`), the
`load`/`memory`/`sys7` write variants (wire-different, capture-derived);
`tunnel.rs` connect planning, cemi and knxnet codecs, secure asdu/session;
`conn_cmd` precedence rules, `flash_dump.rs` records, `ip_secure::records()`;
`testkit/device.rs` (knx-sim is deliberately an independent second
implementation); `warm.rs`, `args.rs`, `edit_with_hook`.

## 6. Tiers B and C: product decisions

### 6.1 Small conveniences (tier B, ~1,400 lines)

| item | lines | what goes |
|---|---|---|
| `doc.rs` Markdown-to-HTML renderer | 210 | `bussard doc --format html`; Markdown stays | YES REMOVE
| `toml_io.rs` fix-it hint heuristics | 200 | typo hints for hand-edited TOML; keep the snippet and the unknown-field suggestion | KEEP
| VBScript interpreter | 664 | `ParameterCalculation` in VBScript (check the corpus: if only the Ekinex thermostat uses it, refuse with `ScriptError::Unsupported`); the alternative is sharing the tokenizer and Pratt parser with JS for ~300 |
| xknxproject JSON import | 320 | `bussard import --from-json`; keep the dump as test data | IF THIS IS NOT NEEDED FOR TESTING, REMOVE import only from knxproj

### 6.2 Capabilities (tier C, up to ~14,000 lines)

Listed so the 40 % target can be discussed with numbers. None is recommended
on technical grounds.

| capability | lines | notes |
|---|---|---|
| certificate enrolment (secure, service, viz, mcp, cli) | 4,200 | package 12 keeps it and trims 800 |
| System 7 programming (plan, execute, apply, tables, compute, load records, sys7 halves of partial/preflight/model_params, mgmt sys7) | 3,300 | the one capability whose removal would reach 40 % together with everything else |
| model optional features: `doc` 983, `checklist` 828, `scaffold` 612, `capabilities` 545, `bundle` 511, `lint` 332 (runs only with a `lint:` table), `reconcile` 276, `tests_schema` 200, `ets_export` 159 | 3,300 beyond tier B | one or two callers each |
| tables-only write engine (System B `apply`/`restore_tables` beside the flash engine) | 1,300 beyond package 14 | needs an ETS "partial download: group addresses" capture to prove `FlashPlan::tables_only` emits the same op sequence |
| Data Secure object programming and diagnostics | 1,000 | `security.rs`, `security_diag.rs` |
| MCP session-edit ledger | 350 | History already holds the snapshots |

One further option fits the LLM-first direction in the owner's notes
(assistant over MCP is the primary operator, bus programming stays CLI):
after packages 1 to 6 the CLI is ~9,000 lines of adapters, of which the
model-query and reporting commands (describe, audit, scan tables, learn,
history, doc, export, ha-config) are 2,000 to 3,000 lines that the MCP serves
better. Dropping them is a product decision of the same kind as the table
above.

## 7. What the review did not count

- 56k comment lines (41 % of the source) and 128k test lines. If the 40 % is
  measured on raw `wc -l`, doc-comment density is a separate lever; not
  recommended.
- `knx-sim/` (separate workspace, 24k lines), `tools/`, `scripts/`.
- About 2,000 lines of operator-facing sentences in the service crate
  (refusals, hints, recovery text). They shrink only if bussard says less.
