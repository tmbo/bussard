# bussard-model review
Total product lines: 26,246 (loc.py rule: code lines, no blanks/comments/#[cfg(test)]).

Context that frames every finding: the crate has almost no dead code (one pub fn,
`device_view::shown_objects`, has zero callers). Its size comes from (a) the same
concept modelled two or three times along a pipeline, (b) the same tree walked by
several bespoke walkers, (c) five hand-written passes over the DPT table, and (d)
~4.4k lines of optional features with one or two callers each. Refactoring (a)-(c)
yields about 14 % of the crate; the 40 % target is reachable only with (d).

## Findings (ordered by lines saved, largest first)

### F1. The Dynamic tree has two serde forms: est. save: 450 lines (confidence high)
- Where: `dynamic_compact.rs` (523 lines, whole file); `dynamic.rs:455-540` (`DynamicNode` derive); `bussard-prod/src/cache.rs` (the only consumer of the verbose derive form, JSON cache keyed by `FORMAT = "bussard-parsed-product-v9"`).
- What: `DynamicNode` derives the externally tagged serde form (used only by prod's parsed-product JSON cache), and `dynamic_compact.rs` mirrors every node variant twice more (`NodeOut`/`RepeatOut`/`ChooseOut`/`WhenOut`/`BlockOut`/`ChannelOut`/`ModuleOut`/`AssignOut`, then `NodeIn`…`AssignIn`) plus `node_out`/`into_node` conversions and three `with = ` modules, so the product-model YAML gets short keys (`p:`, `o:`, `choose:`).
- Proposal: put the compact shape on `DynamicNode` itself with serde attributes (`#[serde(rename = "p")]` on `ParameterRefRef`, `rename = "ref"` on `param_ref_id`, `with = "test_text"` on `WhenTest`), delete `dynamic_compact.rs` except `test_text` (used by device_view), bump prod's cache `FORMAT`. The compact form is an externally tagged enum of one-key maps, which is exactly serde's default encoding after renames.
- Risk / constraints: product-model YAML byte layout (`model_format` 13) changes only if attribute order differs; the offline oracle does not read model YAML, the sim and MCP read it through `ProductModel::from_yaml`. Round-trip test `test_nodes_round_trip_every_shape` already exists and transfers.

### F2. Three models of the product model: prod writes one struct set, model reads another, then converts: est. save: 220 lines in model, ~200 in prod (confidence high)
- Where: `param_model.rs:285-420` (`RawModel`, `RawIdentity`, `RawComObject`, `RawParam`, `RawRef`, `RawType`, `RawEnumValue`, 127 lines) and `:420-547` (`from_yaml` + `RawType::into_kind`, 113 lines); `bussard-prod/src/product_model.rs:399-606` (`Model`, `Identity`, `ComObjectModel`, `ParameterModel`, `RefModel`, `ParamTypeModel`, `EnumValueModel`, `MemoryModel`, Serialize-only mirrors, ~200 lines); `param_model.rs:879-1139` (JSON cache of the *third* form, `ProductModel`'s own derive).
- What: the same YAML document has a write-side struct set in prod (Serialize), a read-side struct set in model (Deserialize) and an in-memory third form (`ProductModel`/`ParamDef`) with a JSON cache of its own derive. `into_kind` and `from_yaml` exist only to bridge form 2 to form 3, and `ParamDef.labels`/`enum_values` are two projections of the same enum list.
- Proposal: one `ProductModelFile` struct set in `bussard-model` with `Serialize + Deserialize`, written by prod and read by model. Keep `ProductModel` as a thin view over it (indices built in `OnceLock`, as `pages`/`ref_index` already are) or make `ParamDef` the on-disk shape. The JSON cache then stores the same struct, so `CacheFileIn/Out` stay but the conversion goes.
- Risk / constraints: `MODEL_FORMAT` bump; `ets::application::ColorSpace` vs `color_codec::ColorSpace` (prod uses the ets one, model its own; unify on model's). The prod side is counted in the prod reviewer's scope.

### F3. Four walkers of the Dynamic tree, and a text round-trip between two of their gate types: est. save: 350 lines (confidence medium-high)
- Where: `blocks.rs` (311 lines: `PageWalk`, `app_modules`, `ModuleInstance`, `for_each_when`); `dynamic.rs:2937-3150` (`RefIndex`/`IndexWalk`, 160); `dynamic.rs:2017-2300` (`placed_parameters`, `assigned_parameters`, `module_ordinals`, `for_each_node`, 217); `dynamic.rs:600-640` (`flatten_containers`); `device_view.rs:631-680` (`ref_gate`, `words_gate`, `enabling_code`: convert `blocks::Gate{test: String}` back to `RefGate{test: WhenTest}` by re-parsing the text that `blocks::test_string` produced).
- What: each walker re-implements the same recursion (Channel/ParameterBlock push a container, Choose/When push a gate, Repeat recurses, Module instantiates) with its own context struct. `BlockDef.when` stores gates as *strings* so `device_view` parses them back, and `Pages::new` then rebuilds a `RefIndex` to get the typed ones.
- Proposal: one `walk(nodes, &mut Visitor)` in `dynamic.rs` that carries `(container path, gates: &[RefGate], module_def)` and calls `visit_ref`, `enter_container`, `leave_container`. `pages_of`, `module_channels_of`, `RefIndex::new`, `placed_parameters`, `assigned_parameters`, `module_ordinals` become 10-30-line visitors. `BlockDef.when: Vec<RefGate>` (derive serde on `RefGate`/`WhenTest`), delete `Gate`, `test_string`, `ref_gate`, `words_gate`.
- Risk / constraints: `BlockDef` is serialised in the MCP `knx_show_device` output (`blocks` field) and in `bussard-viz`; keep the JSON shape by a `Serialize` impl on `RefGate` that prints the text. ETS page order must stay document order (test `pages_of` coverage exists in `tests/it/device_blocks.rs`).

### F4. `device_view` exposes nine entry points that each rebuild the same analysis: est. save: 350 lines (confidence medium-high)
- Where: `device_view.rs:1899-2700` (`device_view`, `device_view_for_blocks`, `parameter_pages`, `unindexed_parameters`, `parameter_visibility`, `show_reached_hidden`, `shown_objects` (dead), `ignored_overrides`, `Evaluated`); `checklist.rs:572-760` (`DeviceContext::new` calls `device_view`, `parameter_pages`, `unindexed_parameters`, `parameter_visibility` and then `RefIndex::new` again: five evaluations of the same device); duplicated helpers `same_value` (`device_view.rs:537`, `checklist.rs:736`, `dynamic.rs:1859`), `display_value`/`value_text` (`device_view.rs:527`, `checklist.rs:716`), `toml_key`/`toml_string` (`device_view.rs:2772-2805` vs `emit.rs:29-65` `basic_string`/`toml_key`), `table()` (`device_view.rs:2728`, also `bussard-mcp/src/session_edits.rs`).
- What: every public function repeats 20-40 lines of setup (`device`, `product`, `parameter_entries`, `device_overrides`, `Evaluated::new`, `Pages::new`) and the callers (`checklist`, MCP `tools.rs`, `service/params.rs`, `download/model_params.rs`) combine several of them.
- Proposal: one `DeviceAnalysis::new(model, products, ia) -> Result<Self>` holding `Pages` + `Evaluated`, with methods `view(channel)`, `pages()`, `unindexed()`, `visibility()`, `ignored_overrides()`; checklist's `DeviceContext` becomes a field. Delete `shown_objects`. Move `same_value`/`display_value` to `param_model.rs` next to `enum_label`/`enum_code` and use them from checklist/change/dynamic. Use `emit::{basic_string, toml_key}` in `render_toml`.
- Risk / constraints: the MCP JSON of `knx_show_device` is a contract tested in `bussard-mcp/tests/it/guidance.rs`; keep the `DeviceView` struct unchanged.

### F5. The lock is read with serde but written by hand: est. save: 180 lines (confidence high)
- Where: `emit.rs:483-700` (`render_product`, `render_lock`, `push_array`, `string_array`, 214 lines); readers in `files.rs:137-252` (`LockFile`, `LockDevice`, `LockChannel`, `LockObject`, `LockParameter`, `LockHidden` all `Deserialize`).
- What: `render_lock` re-states every field of `LockDevice` as `format!("{k} = {}", basic_string(v))`, one `if let Some` per field, and builds the inline tables of `channels`/`objects`/`parameters` by string concatenation.
- Proposal: derive `Serialize` on the lock structs (`skip_serializing_if` for the options, `#[serde(serialize_with)]` for `Dpt`/`Flags` already `Display`), render with `toml_edit::ser::to_document`, then set `ArrayOfTables`→inline-table-per-line formatting once (a 15-line pass that puts each `channels`/`objects`/`parameters` element on its own line keeps the current diff-friendly layout). `LOCK_HEADER` stays a prefix.
- Risk / constraints: the lock is generated, pre-release (no backwards compat), but a byte change rewrites every user's `bussard.lock` once; the `test_lock_schema_fingerprint_matches_the_version` test pins the field set and keeps working.

### F6. The device file has a serde reader, a hand-written toml_edit reader, a hand-built desired document and five merge functions: est. save: 300 lines (confidence medium)
- Where: `files.rs:252-600` (`DeviceFileTop` serde struct plus `scope_entries`, `kind_of`, `classify_table`, `object_value`: 221 lines walking the same document again with `toml_edit` for `parameters`/`links`/`channel.*`/pages); `emit.rs:770-920` (`desired_device`, 134 lines building a `DocumentMut` field by field); `emit.rs:1007-1320` (`merge_device`, `merge_plain_slot`, `merge_scope_slot`, `merge_scope_like`, `merge_entries`, `prune_scope_like`, `order_like`, `number_tables`: 284 lines).
- What: the second reader exists for spans (E020-E023 in `file_checks.rs`) and for the dynamic key set; the desired document is built by hand although the same fields have a `DeviceFileTop`; the merge is specialised per table level although the rule is the same at each level ("keep bytes of unchanged entries, replace changed, append new, drop absent").
- Proposal: (1) a `DeviceFileBody` serde shape with `#[serde(flatten)] entries: BTreeMap<String, Entry>` where `Entry` is an untagged enum `String | ObjectTable | PageTable`; keep one `toml_edit` pass only for spans in `file_checks`. (2) `toml_edit::ser::to_document(&DeviceFileTop{..})` for the desired document. (3) one recursive `merge_table(have: &mut dyn TableLike, want: &dyn TableLike, keep: impl Fn(path) -> bool)` replacing the five merge functions; the only special case left is the channel-scope pruning rule, passed as the `keep` closure.
- Risk / constraints: the comment-preserving edit is a documented contract (`docs/reference/files/`); `bussard-cli/tests/it/*edit*` and `bussard-model/tests/it/files.rs` cover it. Do this after F5.

### F7. Device and group fields are enumerated by hand in four modules: est. save: 400 lines (confidence medium-low)
- Where: `change.rs:1055-1870` (`describe_connection`, `describe_groups`, `group_field_changes`, `describe_devices`, `device_field_changes`, `describe_knxnet`, `describe_object_security`, `describe_channels`, `describe_parameters`, `describe_links`: 722 lines); `merge.rs:498-810` (`overlay_device`, `overlay_parameter_values`, `overlay_product`, `report_opt`: 241); `reconcile.rs:60-340` (`take_theirs` re-parses the `path`/`field` strings that `merge` produced and matches field names again: 260); `checklist.rs:329-570` (`group_item`, `object_item`, `security_items` re-derive wording from `Change.kind`).
- What: each hand-authored field (group `name`/`dpt`/`description`/`secure`/`protected`; device `name`/`description`/`location.floor`/`location.room`/`product.*`/`knxnet.*`/channel name/parameter value) appears in a diff arm, an overlay arm, a take-theirs arm and a checklist arm, each with its own sentence.
- Proposal: a `FIELDS: &[FieldSpec]` table per entity (`name`, `get: fn(&T) -> Option<String>`, `set: fn(&mut T, Option<String>)`, `noun`, `ChangeKind`). `describe` iterates it for the plain fields (keeping bespoke arms only for links, parameters and knxnet), `merge::overlay_*` reports conflicts by iterating it, and `reconcile::take_theirs` becomes `spec.set(mine, spec.get(theirs))`. Checklist keeps its ETS-step wording but reads `Change.field` instead of re-matching kinds.
- Risk / constraints: the sentences are quoted by the assistant and tested (`change.rs` tests, `bussard-mcp/tests/it/diff_tools.rs`); keep the templates in the table so the text is unchanged. This is the largest-risk item; do it last or split per entity.

### F8. `codec.rs` makes five hand-written passes over the DPT table: est. save: 350 lines (confidence medium)
- Where: `codec.rs:1316-1780` decode (345 lines), `:1780-2553` `parse_value` (670), `:2575-2900` `encode` (305), `:1141-1316` `validity_problems` (150), `:394-520` `Display` (122); plus the unit/label tables (`int_unit`, `float16_unit`, `float32_unit`, `bool_labels`, `bool_aliases`, `step_labels`, `scaling`, `count_range`, `writable_range`).
- What: the numeric families (5, 6, 7, 8, 12, 13, 14, the scaled 7/8/12/13 sub-types) each get an arm in decode, parse, encode and (for 7/8/12/13) `writable_range`, with the same range check and the same `EncodeError::OutOfRange { dpt, value }` literal repeated (the `out_of_range` closure at `:2583` is defined and then not used for most arms). `validity_problems` re-extracts the same bit fields that `decode_inner` extracts ten lines later (10/11/19/232/251).
- Proposal: a `Numeric { width, signed, scale, unit, range }` descriptor returned by one `numeric(dpt)` fn that decode/parse/encode share (one arm each instead of seven); fold `validity_problems` into `decode_inner` by returning `(TypedValue, Vec<String>)` from the arms that already hold the fields; use the error closures. The compound types (10, 11, 19, 232, 251, 3, 18, 20.102) stay bespoke.
- Risk / constraints: DPT decoding is covered by the reference-vector tests in this file and by `bussard-monitor`; keep the vectors. No oracle row covers codecs (model-side only).

### F9. A hand-written Markdown-to-HTML renderer lives in `doc.rs`: est. save: 210 lines (confidence high, product decision)
- Where: `doc.rs:1015-1254` (`html_page`, `STYLE`, `markdown_to_html`, `is_table_row`, `table_cells`, `inline`, `find_char`, `find_pair`, `escape_char`, `escape_html`: 213 lines).
- What: `bussard doc` writes Markdown and, via `DocFormat::Html`, the same content as HTML through a private line-based Markdown parser (headings, lists, tables, inline code/links).
- Proposal: drop the HTML flavour (Markdown renders on GitHub, in MkDocs and in every viewer the owner uses; `docs/` itself is MkDocs). If HTML must stay, `pulldown-cmark` (MIT) is a one-line replacement, but the dependency policy prefers deletion.
- Risk / constraints: `DocFormat` is a CLI flag (`doc_cmd.rs`) and an MCP argument (`tools_files.rs`); remove the variant in both. Changelog fragment needed.

### F10. `analysis.rs` recomputes what `validate.rs` already reports: est. save: 120 lines (confidence medium)
- Where: `analysis.rs:100-340` (189 lines: unnamed groups, groups without DPT, links to unknown devices/objects, unlinked objects, unused group addresses, devices without name/location); `validate.rs:352-506` (`check_links`: E001, E003, E013) and `:699-730` (`check_orphans_and_unlinked`: the same unlinked/unused rule).
- What: `bussard audit` and the viz Problems panel get their findings from `analyze`, which re-walks links and groups with its own endpoint index while `validate` walks them again for the same conditions with different wording.
- Proposal: `ModelAnalysis::from(&[Diagnostic], &Model)`: the findings list is the diagnostics filtered by code; the counts (`devices_per_line`, `secure_devices`, totals) are 40 lines of iteration. Keep the JSON shape of `GET /api/model.analysis`.
- Risk / constraints: `bussard-viz/tests/it` asserts the analysis JSON; MCP `knx_audit` quotes the messages. Wording unification is a visible change.

### F11. Two script interpreters with parallel tokenizer, parser, value and interpreter: est. save: 300 lines (confidence low-medium); alternatively drop VBScript: 664 lines (product decision)
- Where: `script/js.rs` (1,295 lines) and `script/vbscript.rs` (664): `Tok`/`tokenize`, `Expr`/`Stmt`, `Parser` (JS: Pratt `binary(min)`; VBScript: a seven-level precedence chain `and_expr`→`not_expr`→`comparison`→`concat`→`additive`→`modulo`→`int_div`→`term`), `Value`, `Interp`.
- What: both languages are expression languages over numbers/strings/booleans with `if`, assignment and a built-in whitelist; the differences are precedence/operator tables, truthiness (`True = -1`), integer division and string conversion. ~40 % of each file is the shared shape.
- Proposal: one tokenizer parameterised by an operator/keyword table, one Pratt expression parser taking a precedence table, one `Interp` over a shared `Value` with a `Semantics` trait (`truthy`, `to_number`, `to_string`, `arith`, `compare`). JS keeps its statement parser (`for`, `while`, `switch`); VBScript keeps `If/ElseIf/End If`.
- Risk / constraints: `ParameterCalculation` results feed the parameter image, which the offline oracle checks (`95-offline-oracle.sh` rows for the Jung LED dimmer, Zennio dimmer, Ekinex thermostat per the module docs). Any change here needs those rows identical. If the Ekinex thermostat is the only VBScript product in the corpus, refusing VBScript (`ScriptError::Unsupported`) and deleting the file is the cheaper cut; the owner decides.

### F12. Scaffold role/trade tables are multi-line struct literals: est. save: 150 lines (confidence high)
- Where: `scaffold.rs:130-400` (`LIGHT_ROLES`, the other `*_ROLES`, `TRADES`, `FUNCTIONS`: 239 lines of `Role { offset: 0, label: "Switch", dpt_main: 1, dpt_sub: 1, status_of: None }` six lines each).
- Proposal: `const fn role(offset: u8, label: &'static str, main: u16, sub: u16) -> Role` and `role_status(...)`; each row becomes one line. Same for `TradeSpec`/`FunctionSpec`.
- Risk / constraints: none (data only); `scaffold` tests cover the addresses.

### F13. Fix-it hint heuristics in `toml_io.rs`: est. save: 200 lines (confidence high, product decision)
- Where: `toml_io.rs:186-460` (`Hint`, `hint_for`, `invalid_type_hint`, `unknown_field_hint`, `edit_distance`, `key_before_equals`, `scan_brackets`, `unclosed_brace_line`, `unclosed_array`, `duplicate_key_hint`: 252 lines).
- What: pattern-matches the `toml` crate's error message and the text around the caret to add a `help:` line for human typos (YAML `-` markers, curly quotes, unclosed inline tables, misspelled keys).
- Proposal: keep the snippet renderer (`snippet`, `line_col`, `clamp_span`, ~60 lines) and the `unknown_field` did-you-mean (the one hint an assistant benefits from, ~40 lines); drop the rest. With the assistant as primary editor (LLM-first direction) the human-typo hints have little use.
- Risk / constraints: `docs/reference/files/` Errors section documents the hints; `bussard-model/tests/it/toml_errors.rs` tests them. Owner decision.

### F14. Three stamped-file memo caches: est. save: 80 lines (confidence medium)
- Where: `param_model.rs:904-1000` (`Stamp`, `MEMO`, `memo_get`/`memo_put`), `lock_products.rs:87-128` (`HashMemo`, `FileStamp`), `loader.rs:311-416` (`models_fingerprint`, `memo` module with `PARSES`/`THREAD_PARSES` counters).
- Proposal: one `StampedMemo<T>` (`Mutex<HashMap<PathBuf, (Stamp, Arc<T>)>>` with `get_or_insert_with`) used by all three; the test-only parse counters move into it.
- Risk / constraints: none beyond the perf tests in `param_model.rs` (`test_load_apps_memo_hit_and_miss`) that read the counters.

### F15. Workspace-wide small duplicates (model's share): est. save: 30 lines in model, ~200 across the workspace (confidence high)
- Where: `fn hex(` defined in 18 crates/files (model `bundle.rs:708`, prod, mgmt, service ×5, download ×2, mcp ×3, cli, monitor ×2, secure, transport), `sha256_hex` ×5, `escape_html` ×3 (`doc.rs`, viz ×2), `capitalize`/`join_and` (`change.rs`, `mcp/everyday.rs`), `edit_distance` (`toml_io.rs`, `mcp/param_keys.rs`), `rfc3339` (`history.rs`, `download/backup.rs`), `slug` (`doc.rs`, `files.rs`).
- Proposal: `bussard_model::text` (or `util`) exporting `hex`, `sha256_hex`, `escape_html`, `capitalize`, `join_and`, `edit_distance`, `rfc3339`, `slug`; every crate already depends on model.

### F16. `DynamicSource` forwarding impl: est. save: 50 lines (confidence high)
- Where: `dynamic.rs:193-250` (`impl<T: DynamicSource + ?Sized> DynamicSource for &T` restating 16 methods).
- Proposal: make the evaluator entry points take `&S` once (they already do: `evaluate_dynamic<S: DynamicSource + ?Sized>(app: &S, ..)`) and drop the blanket impl; grep shows the callers pass `&ProductModel`/`&ApplicationProgram` directly.

## Feature weight (owner decisions, not code quality)
Each of these is an optional feature with one or two callers. Together 4,443 lines (17 % of the crate). Listed so the 40 % target can be discussed honestly; none is recommended for deletion on technical grounds alone.
- `doc.rs` 983: handover documentation (`bussard doc`, MCP `knx_export_docs`). F9 covers 210 of it.
- `checklist.rs` 828: ETS redo-checklist (`bussard diff --checklist`, CLI only).
- `scaffold.rs` 612: group-address scaffold (`groups reserve`, MCP `knx_reserve_groups`); F12 trims 150.
- `capabilities.rs` 545: "could this device…" search (one MCP tool).
- `bundle.rs` 511: `.bussard` zip export/import.
- `lint.rs` 332: opt-in topology/convention lints (no caller outside `validate`; zero references from cli/mcp/service, it runs only when `bussard.toml` has a `lint:` table).
- `reconcile.rs` 276: `import --theirs/--interactive` conflict resolution (F7 shrinks it).
- `tests_schema.rs` 200: `tests.toml` acceptance tests (`bussard test`).
- `ets_export.rs` 159: ETS CSV/XML group export (CLI only).

## Do not touch
- `dynamic.rs` evaluator core (`Walk`, `ActiveModule`, `CalcRuns`, `UnionIndex`, `DynamicMemo`, `value_of`, `scope_of`, ~1,400 lines): the ETS Dynamic semantics the CLAUDE.md rule says every other crate must call; it is already the single implementation (`bussard-ets` and `bussard-prod` implement `DynamicSource` and call in). Correct by oracle, not by size.
- `files.rs` mem-key resolution (`Resolver`, `join_device`'s spelling/label logic): encodes the device-file contract (`docs/reference/files/`) and lock v4; F6 only replaces the mechanics around it.
- `history.rs` (507): snapshot/undo with atomic writes; the civil-time code (~40 lines) is cheaper than a `time` dependency.
- `validate.rs` rules E0xx/W0xx, `file_checks.rs`, `secure_links.rs`, `secure_invariants.rs`, `keyring_checks.rs`: each rule is a documented code; F10 reuses them rather than editing them.
- `dpt_tables.rs` (423), `knxnet.rs` (374), `facts.rs`, `identity.rs`, `serials.rs`, `manufacturer_names.rs`, `color_codec.rs`, `text_codec.rs`: data or thin, already minimal.
- `param_model.rs` JSON cache (183): it is the fix for the "YAML parse dominates every command" perf baseline; F2 keeps it on the unified struct.

## Estimated total
| Group | Lines | Share of crate |
|---|---|---|
| Refactoring findings F1-F8, F10-F12 (excluding product decisions), F14-F16 | ~3,300 | 12.6 % |
| Product-decision cuts F9, F13, VBScript (F11 alt) | ~1,070 | 4.1 % |
| Feature removals (section above, owner's call) | up to ~3,300 beyond the rows already counted | 12.6 % |
| **Reachable by refactoring alone** | **~3,300-3,700** | **13-14 %** |
| **Reachable with product decisions** | **~7,500** | **~29 %** |

Order of execution (dependencies): F1 → F2 (both touch the product-model file), F3 → F4 (walker first, then entry points), F5 → F6 (lock, then device file), F12/F15/F16 any time, F7 last. Every one of F1-F7 needs `cargo nextest run -p bussard-model -p bussard-prod -p bussard-mcp -p bussard-cli` and, for F11, the offline oracle rows that carry calculations.
