# Changelog

All notable changes to bussard are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes that have merged but are not yet folded into this file live as
fragments under `changelog.d/`; `scripts/changelog.py render` prints the
Unreleased section with them included.

## [Unreleased]

## [0.10.0] - 2026-11-06

The same code as 0.9.0 with the release pipeline repaired: the Windows asset
builds again (the build step ran under PowerShell), the release notes are capped
at GitHub's body limit with a link to the full entry, and the Homebrew tap
updates. 0.9.0 stays published without a Windows asset; see its entry for what
this release contains.

### Fixed

- knx-sim takes the last `Count` octets of a longer `LdCtrlCompareProp`
  `InlineData` as the compared value (the leading octets are padding), and the
  ETS sweep seeds a device property a parameter names by `ObjectType="0"`:
  the Gira IR-Gateway's hardware type is `00 00 00 20 00 03` (#422).
- knx-sim sizes a property a product declares with `LdCtrlDeclarePropDesc` as
  an array of the declared type as far as its writes reach, so ETS can read
  the Gira Eco's PID 69 in chunks, and it answers `A_FunctionPropertyExt_Command`
  on a function property a product calls by object type (the Gira
  IR-Gateway's PID 208 of type 65281) (#422).
- knx-sim answers a load event on a vendor object addressed by type with the
  next transport sequence number: the answer skipped one, ETS refused it with
  T_NAK, and the Gira Eco download ended with "Connection closed by remote
  device" (#422).

## [0.9.0] - 2026-11-06

The first public release (#92). This entry describes what bussard does at the
tag; it is not a diff against the unreleased `0.1.0` draft of 2026-09-16, which
was never published.

### Breaking changes

bussard is pre-release and keeps no compatibility shims. What a model
directory or a script from before these changes needs:

- **Lock version 3 only** (#228, #276): a `bussard.lock` of another version
  is refused with the fix, `bussard import <export> --dir <dir>`, which
  regenerates it. Version 3 indexes the parameters at their vendor default
  and records a ref's `default` and the `written_by` build. The version is
  read before the rest of the lock, so a mismatch is always the version
  message (quoting `written_by` when present), never an unknown-field error;
  any later schema change bumps the version again (a schema fingerprint test
  enforces it).
- **Product data moved** (#228): archives live in `<dir>/products/` (retained,
  pinned in the lock, no longer git-ignored by bussard); the first command
  moves an old `vendor/` there. Product models live in `.bussard/models/` and
  regenerate; the old `<dir>/models/` is not read.
- **The model is TOML**: the YAML model files are not read; re-import the ETS
  project into an empty directory.
- **Global options** (#228): `--dir`, `--gateway`, `--routing`, `--keyring`,
  `--json`, `--allow-remote-gateway`, `--skip-address-check` and
  `--refresh-facts` are one global group. Existing command lines keep
  working; `--json` on a command without JSON output is now refused.
- **`keyring` subcommand removed** (#241): `bussard keys show` summarizes
  the key store, `bussard keys import` brings an ETS export into it and
  `bussard keys export` writes one back. Keys resolve from an explicit
  `--keyring` / `BUSSARD_KEYRING` file, else `bussard.keys`, else the
  deprecated `connection.keyring`.
- **`validate --format` removed** (#228): use the global `--json`; the
  document is `{"schema", "diagnostics": [...]}` instead of a bare array.
- **Download consent is `--yes-download`** (#228) on `init`, `import`,
  `import-product` and `adopt`; `--yes` only skips the confirmation prompt,
  on every command.
- **`adopt [ADDRESS]`** (#228): the target address is an optional argument
  (default: the next free one); `BUSSARD_ADOPT_ADDRESS` is gone. A
  non-interactive `adopt` needs `--yes` and nothing else.
- **JSON documents carry a schema** (#228): every `--json` document is an
  object whose first field is `"schema": <n>` (each `monitor --json` line
  too); `history --json` is `{"schema", "snapshots": [...]}`.
- **One non-TTY refusal** (#228): `refusing to <action> without a terminal to
  confirm on; pass --yes to confirm non-interactively`.
- **`replace --product` is optional** (#228): the archive the lock pins is the
  default. A `--product` or `--application` that contradicts the lock is
  refused by `flash`, `apply` and `replace` unless `--force`.
- **`knx_add_link` / `knx_remove_link` take `address` only** (#285): the
  `device` alias is gone, and a call that names the device `device` is
  refused with "expected fields: address, com_object, ga, role". The Claude
  remote-devices bridge strips a key named `device`, so it never worked
  there; both descriptions say the device's individual address goes in
  `address`.

### Added

- `knx_plan_device` runs as a job when the device read is slow (#332). A
  Data Secure System B device reads its whole parameter memory over a secured
  session, which outlasted the client bridge's 60 s call cap. The plan still
  comes inline when the read ends within about 20 s; otherwise the call
  answers `started: true` with a `job` id, and `knx_apply_status` (now for
  plan jobs too, `kind: plan`) returns the plan as its `result`, digest
  included, exactly as the inline answer would. A second plan of the same
  device joins the running job. Plan and apply jobs share the one slot, so a
  plan never reads a device while a write runs, and the other way round.
  `knx_apply_device` also answers `started` when its pre-flight read outlasts
  the same wait; a pre-flight that refuses after that ends the job with
  `result.refused: true` and nothing written.
- Validation errors E035 and E036 for links that cannot work under KNX Data
  Secure (#330). E035: a device without Data Secure sends on a group address
  that a Secure receiver takes secured, so the receiver drops every telegram.
  E036: the reverse, a Secure sender on a group address a plain device listens
  to. The message names the devices, the group address and the ways out (make
  the address plain, or route through a plain address into a logic input).
  `bussard validate` and `knx_validate` list them, `knx_add_link` refuses such
  a link, and `knx_plan_device` refuses to plan the plain device.

- Switch KNX Data Secure off (or on) for one group address end to end
  (#331). `bussard groups secure <GA> on|off` and `knx_set_group` with
  `secure` change the three signals together: the group key in the key
  store, the group's `secure` flag and every linked com-object's flag, in one
  snapshot that keeps a copy of the encrypted key store, so `undo` restores
  the very key. `on` generates a random group key as ETS does when the store
  has none. `plan`/`apply` (and `knx_plan_device`/`knx_apply_device`) on a
  Secure System B device read its group-object security flags (PID 61) and
  list one security-object change naming the group address and the objects;
  the apply rewrites the security object as a full ETS download does (group
  key table without the entry, the objects' flags `0x00`) and records the
  flags in the lock. `flash` prints the same line. The result tells Home
  Assistant users to load a new `bussard keys export`. The write is oracle
  pending: an ETS capture of 1.1.5 with 1/0/4 set to security Off must
  compare identical before it runs on a real device (SAFETY.md).

- `knx_remove_group` and `knx_discard_edits` (#305). `knx_remove_group`
  removes a group address from `groups.toml`; it is refused while a link uses
  the address (the reason lists the links and names `knx_remove_link`) and for
  a protected address, and `knx_undo` restores it. `knx_discard_edits` takes a
  device `address` or a `group` and drops only that subject's unapplied edits
  from this session, so reverting one device no longer means undoing the
  edits made on other devices since. It returns the dropped sentences and
  snapshots first, so `knx_undo` brings them back. A removed group address now
  reads "Group address 1/0/22 (Kitchen door light) removed."
- `knx_plan_device` and `knx_apply_device` push a parameter that shows or
  hides com-objects (#303). Such a change rewrites the group-object table,
  which only a full application download writes, so the plan used to refuse
  it with "needs `bussard flash`". The plan now says `method: "flash"`
  (`"apply"` otherwise) and lists, under `flash`, the com-objects that appear
  or disappear with their text, DPT and the parameter behind them, the
  address, association and group-object table sizes before and after, that
  the device restarts and is offline for 30 to 50 s, that its parameter
  memory is backed up first, and the archive it writes with its
  `product_sha256` from the lock. Its question asks to flash the device.
  `knx_apply_device` with that plan's digest runs the flash as the usual job
  (`knx_apply_status`, `knx_last_apply`, one at a time, the plan hash check):
  the parameter backup under `captures/backups/parameters/`, then the same
  image `bussard flash <ia> --yes` writes (both now build it with the same
  code from the same inputs), the restart and the verify, then the lock
  update `flash` makes. It refuses what `flash` refuses: no archive pinned in
  the lock, an identity that drifted, another or an unreadable resident
  application, a stale plan. `bussard flash` is unchanged. The server
  instructions and the `knx_set_parameter` note say so at the programming
  tier.
- `[connection] admit_tunnel_senders = true` (#297): `plan`, `apply`,
  `flash`, `apply --line`, `knx_plan_device` and `knx_apply_device` on a KNX
  Data Secure device add every tunnelling address of the key store to its
  security individual address table (PID 54) with sequence 0. `plan` reads
  PID 54 and lists the missing addresses as one change (`subject: security`,
  `writes.security_object`); the security-object summary names them. ETS does
  the same when group addresses are assigned to the interface's tunnelling
  addresses. Off by default; off, the security object is byte-identical to
  before. Every verified secured `apply`, `apply --line`, `flash` and
  `knx_apply_device` records the PID 54 table it wrote as the device's
  `secure_senders` in `bussard.lock`, so the next secured write is checked
  against it without an `adopt`.
- Validation warning W034 (#297): a secured group address no device sends
  on (only tunnel clients can write it) whose linked Secure device does not
  admit the key store's tunnelling addresses. ETS does not admit them by
  default, so `admit_tunnel_senders` stays off; the warning says when it
  matters. `knx_plan_device` adds the same sentence as a note for that
  device while the option is off.
- What a device can do (#298). `bussard device` and `knx_show_device` list an
  application without channels of its own (a Theben Meteodata's one
  `generic-0` channel) by ETS parameter page, in ETS order, and mark a page
  the configuration does not show as `inactive`, with the parameters that
  enable it, the objects it would show and whether that needs `bussard
  flash <ia>`; a device with channels lists its inactive channels the same
  way, and a `summary` line counts what is inactive ("7 Universalkanal C4:
  Funktion .. Universalkanal C10: Funktion"). A page handle details one page.
  `knx_model_lookup` gains `capabilities`: the parameter and enum choice texts
  of the installed devices' product models, ranked `provides` first, then
  `could provide` on inactive pages, cached under `.bussard/lookup/`. The
  `knx_get_device` and `knx_show_device` descriptions say which answers
  "what can this device do", and the server instructions how to find a
  device that can provide a function. Product models gain `model_format: 2`
  and the `blocks` of the Dynamic section; an older model regenerates from
  its archive.
- `bussard restore --parameters <backup.json> <ADDRESS>` and the MCP tool
  `knx_restore_parameters` (#290) replay a parameter backup from
  `captures/backups/parameters/` with the parameter-only download `apply`
  uses: refused for a backup of another device, application or mask; only
  placed octets written, device-managed ones kept; the current memory backed
  up first; verified by read-back. The MCP tool is at the programming tier
  with a plan, a single-use digest and an explicit yes, and runs the write as
  a job like `knx_apply_device`.

**The model and the ETS import**

- `bussard import` reads an ETS 4, 5 or 6 `.knxproj`, including
  password-protected exports, into a TOML model in `knx/`: `groups.toml` for
  the group-address plan, one `devices/<address>.toml` per device with its
  parameters and links, and the generated `bussard.lock`. Re-imports are
  idempotent across renames, keep hand-authored edits, and report conflicts
  (`--mine`, `--theirs`, `--interactive`, exit code 3) (#4, #9, #18, #46).
- The model files are TOML, written with `toml_edit` so comments and untouched
  lines survive a save. Strings are always quoted and numbers never are, so a
  DPT or an address cannot turn into a number by accident. Parse errors keep
  the caret and add a `help:` line with the fix where the raw message
  misleads. `docs/model-format.md` specifies every file.
- `bussard.lock` holds the vendor facts for every device (program, mask,
  channel ids, the com-object table, parameter refs, module offsets), the way
  `Cargo.lock` holds resolved dependencies. `import` and `adopt` write it and
  nobody edits it. Every other file is user-owned in full. Because the lock is
  committed, a checkout without product data still validates, plans and
  decodes telegrams.
- Device files read like the ETS dialog: one table per channel with its
  parameters and links, keyed by the vendor's texts (`[channel.a-1]`,
  `betriebsart = "Jalousie"`, `langzeitbetrieb.listen = ["0/1/3"]`). A
  parameter is stored once, however many refs point at its memory cell. A
  device without product data shows vendor channel ids and object numbers
  instead.
- `bussard validate` checks the model with rule passes E001 to E026 plus
  topology and convention lints (#3, #102). E020 to E026 cover the files and
  the lock: duplicate addresses, a missing or stale lock entry, unknown keys,
  a DPT mismatch between an object and its GA, `send` or `listen` against the
  object's flags, and parameters that cannot be checked without product
  data.
- `bussard init` starts an empty model from a discovered gateway and reports
  the interface's tunnel slots (#21, #105). `groups reserve` allocates a
  group-address plan from a room and function list (#103).
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
  from `tests.toml` (#93, #95, #101).

- Device facts (#209): the mask, max APDU, interface-object table, property
  descriptions and authorize verdict of each device are stored in
  `knx/.bussard/facts/<ia>.toml` and reused while the device's mask and
  application id match. `describe` of a Data Secure device drops from about
  110 requests (24 s at 200 ms per request) to 4 (0.9 s) on the second run;
  `reconstruct`, `plan`, `apply` and the flash pre-flight skip the
  `PID_OBJECT_TYPE` walk and the max-APDU read. The object table is read from
  `PID_IO_LIST` where a System B device offers it, with a fallback to the
  walk. `describe --full` walks the property descriptions again;
  `--refresh-facts` re-reads everything.
- A device whose facts record that it never answers `A_Authorize` (1.1.30,
  1.1.39, 1.1.45, 1.1.51, 1.1.202 in the reference installation) is no longer
  asked in the `flash` pre-flight or in either phase of `apply`, which saves
  the 3 s response timeout per session (mock: `apply` 2 authorize requests to
  0). A device that answers, granted or asking for a key, is always asked;
  stale facts present the key on the same connection (#215).
- `PID_MAX_APDU_LENGTH` is read once per connection, its absence included:
  a device without the property was asked again by the facts, the table
  reader, the parameter read-back and the flash pre-flight (mock: 3 calls on
  one connection, 3 reads to 1). A read the device acknowledges and never
  answers re-opens the connection instead of leaving it closed, so the next
  request no longer fails with "disconnected". The flash write phase reuses
  the pre-flight's answered absence instead of reading it again (#215).
- `bussard_mgmt::write_table`, a `PID_TABLE` property-array writer with fixed
  8-octet chunks, is removed. Nothing called it since `apply` writes tables
  into device-allocated segments with memory writes, as ETS does; the ETS
  table downloads of 1.1.47 and 1.1.5 contain no `PID_TABLE` property write
  (#215).
- `flash --parameters-only` reads the parameter memory on the pre-flight
  connection and reads it back after the restart on the write session's
  post-restart connection, instead of opening a read-only session before
  the prompt and another after the download. The written octets and the
  verification are unchanged (mock: 6 to 4 `T_Connect`, 44 to 34 requests)
  (#215).
- The `flash` pre-flight reads what decides the factory-freshness verdict:
  on System B the load state and application id of the application objects,
  instead of the load state of every interface object. The other objects are
  read only when no application object answers, so the verdict is the one
  the full read gives (a test runs both against the same mock). Under
  `--yes` the write phase takes over the pre-flight's connection instead of
  disconnecting and connecting again: one `T_Connect`, `S-A_Sync` and
  `A_Authorize_Request` fewer, the same frames written. A connection idle for
  more than 3 s or closed by the device is replaced by a fresh one, and
  `BUSSARD_FLASH_NO_HANDOVER=1` always reconnects. Without `--yes` the
  prompt sits between the phases and the write phase reconnects as before,
  seeded with the pre-flight's facts. Mock, 1.1.12-like Data Secure device at
  200 ms per request: pre-flight 19 to 12 requests (3.9 s to 2.5 s) with
  facts, 25 to 18 without; `flash --yes` 4 to 3 `T_Connect` on the System B
  mock, 6 to 5 on the DA.tp and System 7 mocks (#213).
- `bussard reconstruct --no-parameters` reads the links and tables only: no
  product parse and no parameter read-back (mock: 18 to 14 requests, no
  memory read) (#215).
- The MCP server keeps a device's management connection for 3 s after
  `knx_describe_device`, so a following call to the same device reuses it
  instead of connecting again (mock, two consecutive calls at 200 ms per
  answer: 46 to 44 requests, 9.35 s to 8.97 s; a Data Secure device also
  skips the second `S-A_Sync`). One device at a time: a call to another
  device, a programming-tier call or a lost gateway link closes it first,
  the idle close runs before the device's own 6 s timeout, and a call that
  fails on the kept connection is repeated on a fresh one (#215).
- `BUSSARD_WIRE_TRACE=1` encodes each frame once and writes each line with a
  single write to stderr; a 215-octet write's line takes 1.3 µs instead of
  17 µs (release). With the trace off nothing is encoded or formatted: a
  counting allocator sees zero allocations over 200,000 calls (#215).
- System B table read-back reads the address and association tables from
  memory at the negotiated chunk when that takes fewer requests than
  `PID_TABLE` property reads (#223). A 400-address, 1,333-association table
  set on a Data Secure mock drops from 125 requests (25.7 s at 200 ms per
  request) to 40 (8.4 s). Small tables keep the property reads, so the frames
  are unchanged for them. The memory read falls back to `PID_TABLE` on a
  missing reference, a refused or unanswered read, or a count mismatch.
  `reconstruct`, `plan`, `apply`, `backup`, `line` and the MCP plan tool
  share the reader.

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
  `knx_set_parameter`, `knx_undo` and more) change the model files with a history
  snapshot, and the server follows the model on disk.
- `--allow-programming` adds `knx_plan_device` and `knx_apply_device`: the
  assistant writes one device's link tables only with the digest of a plan the
  human approved (#118).
- `--allow-home-assistant` with a `[home_assistant]` table in `bussard.toml`
  adds the Home Assistant tier (#280): `knx_ha_status` reads Home Assistant's
  REST API (version, KNX integration, entity counts, the state of the KNX
  YAML file); `knx_ha_plan` says per entity what writing the YAML generated
  from the model would add, change or remove, with a digest; `knx_ha_apply`
  takes that digest after the human's yes, backs the file up under
  `captures/backups/ha/`, replaces it atomically and calls `knx.reload`. The
  token comes from `BUSSARD_HA_TOKEN` (or the variable `token_env` names) and
  is never printed. `next_step` after an edit to a group address Home
  Assistant uses names `knx_ha_plan`.
- The Home Assistant tier manages bussard's own automations (#280):
  `knx_ha_automation_plan` renders a small rule (`when` a group address
  receives a value, `then` send group values) into a `knx.telegram` trigger
  and `knx.send` actions with the raw payload of the group address's DPT;
  `knx_ha_automation_apply` writes it through the config API after the
  human's yes and reloads automations; `knx_ha_automation_remove` deletes one.
  Only `bussard_` ids with bussard's marker line are touched, every address
  must be in `groups.toml` with a matching DPT, and the previous JSON is kept
  under `captures/backups/ha/`.
- `bussard mcp` started from a terminal prints how to register it: the
  `claude mcp add` command and the `mcpServers` JSON entry for Claude Desktop
  and other clients, built from the running binary, the resolved model
  directory and the flags given, with where a password must come from (never
  the password itself). A client that spawns the server with pipes gets only
  the `mcp: serving on stdio` log line (`-v`).
- `bussard viz` serves the network as a live bus-spine diagram in the browser,
  with a problems panel, model reload and programming-mode highlighting
  (`--watch-prog`) (#65, #67).
- viz: the inspector opens wide enough for a device's channel tables (780 px),
  resizes with a drag handle between the diagram and the panel (360 px minimum,
  the diagram keeps 480 px), remembers the width in the browser, and wraps long
  labels instead of scrolling sideways. A help panel (`?`) explains the header
  actions; the reload tooltip and help describe what a reload does instead of
  naming the HTTP endpoint (#252).
- viz: the inspector shows each channel's parameter values under its header,
  after the com objects, with the vendor label, the choice label and a marker
  for values that differ from the vendor default (from the product model in
  `.bussard/models/`). The same rows are in the model projection the page
  loads (#259).

**KNX Data Secure**

- The `.knxkeys` reader verifies an ETS export's signature and decrypts the
  tool and group keys (#84, #148). The password comes from
  `BUSSARD_KEYRING_PASSWORD`, never a flag.
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
- `learn` decrypts secured group telegrams the same way (`--keyring`, else
  `connection.keyring`): the inner value feeds the DPT inference, the learned
  group gets `secure = true`, and a replayed sequence number is shown as a
  warning. Without a key a secured telegram is reported and skipped (#204).
- A secured `flash` or `apply` writes the security individual address table
  (PID 54) like ETS: one `[IA][sequence]` entry per device that sends on a
  secured group address the device listens to, with the sender's keyring
  sequence number when the sender is activated (else 0). `--secure-sender <IA>` (off by default) adds bussard's own
  tunnel address, so the device accepts `write --keyring`; without it the
  device drops bussard's secured group telegrams. knx-sim enforces the table
  (#181).
- `adopt` of a Data Secure-activated device whose tool key is in the keyring
  (`--keyring`, `BUSSARD_KEYRING` or `connection.keyring`) (#201 tier 1). adopt keeps the device at its address,
  verifies it and reads its link tables, parameters and security object (the
  group-object security flags, PID 61, and the security individual address
  table, PID 54) over `A_SecureData`, and writes nothing to the device. The
  model records the links, the non-default parameters, `[security] activated
  = true, secure_commissioning = true`, `secure` on the flagged objects and on
  the linked group addresses the keyring has a key for, and, in the lock,
  `secure_capable`, the keyring sequence and the PID 54 table as
  `secure_senders`, which a later secured download writes back. `plan` right
  after reports no change. An activated device the keyring does not list fails
  with the "no tool key" message and a hint to re-export the keyring, and no
  device file is written. Activation from the FDSK certificate (tier 2) stays
  open.
- MCP `knx_apply_device` programs a device the server's keyring lists, as
  `bussard apply --keyring` does: the tables over `A_SecureData` plus the
  security object (PID 54, 53, 61). `knx_plan_device` returns what the
  security object receives as `security_object` (addresses and object
  numbers, never a key), refuses a secure GA without a group key, and binds
  it into the plan digest. The write gate, the digest and the human approval
  are unchanged (#205).
- MCP `knx_wait_for_telegram`, `knx_recent_telegrams` and `knx_infer_group`
  see secured group telegrams decrypted with the server's keyring; the
  inference leaves out telegrams that did not verify and counts them (#205).
- `validate` checks the configured keyring (`BUSSARD_KEYRING` or
  `connection.keyring`): E027 for a missing file, W028 for a
  security-activated device without a tool key (re-export the keyring from
  ETS), W029 for a group whose `secure` flag disagrees with the keyring's
  group keys, W030 for a keyring that does not decrypt. Without
  `BUSSARD_KEYRING_PASSWORD` it prints one I031 line and skips the key checks;
  it never prompts. `knx_validate` runs the same rules with the server's
  keyring (#205).
- `init` records a `.knxkeys` exported next to the project as
  `connection.keyring` and prints the `BUSSARD_KEYRING_PASSWORD` reminder
  (#205).
- viz shows the model's Data Secure state read-only: a device's `security`
  block, the groups' and com objects' `secure` flags, and `[secured]` on
  secured telegrams in the traffic view (#205).

- The key store `knx/bussard.keys` (#241 items 1 and 3): bussard's own copy of
  the KNX Secure key material (backbone, interfaces, tool keys, serial
  numbers, FDSKs, management passwords, authentication codes, group keys),
  encrypted and signed exactly like an ETS `.knxkeys` with
  `BUSSARD_KEYRING_PASSWORD`, and git-tracked by design. Writes are atomic and
  keep `bussard.keys.bak`; an unchanged entry keeps its ciphertext, so a diff
  shows only what moved. `bussard keys import <file.knxkeys>` merges an ETS
  export and reports new devices, rotated keys and group keys (an FDSK is
  never dropped); `bussard keys export <file.knxkeys>` writes a signed export
  for ETS; `bussard keys show [--json]` prints a redaction-safe summary. The
  keyring reader now also reads the `FDSK` and `SerialNumber` an ETS 6 export
  carries per device. `init` writes `*.knxkeys` into the model's
  `.gitignore`.
- Store-first key resolution (#241 items 2 and 4): every bus command takes
  its tunnelling users, tool keys and group keys from `bussard.keys` unless
  `--keyring` or `BUSSARD_KEYRING` names an explicit file; `connection.keyring`
  is the fallback for a model without a store (deprecated, kept for one
  release, ignored with a warning when a store exists). `import` and `init`
  merge the one `.knxkeys` next to the project into the store when the
  password is set (without it `init` records `connection.keyring` and prints
  the `keys import` command). `validate` runs E027 to I031 against the same
  source, the store included.
- Data Secure send sequences are clock-seeded without persistence (#241 item
  3): 48-bit milliseconds since 2018-01-05, issued by a process-wide monotonic
  guard that never repeats or goes below a value already issued or sent, even
  within one millisecond or across a clock step back. The S-A_Sync handshake
  still moves a session up when a device expects more.

**KNXnet/IP Secure**

- Secure tunnelling to a KNXnet/IP Secure interface over TCP: X25519 session
  handshake, the interface's device authentication verified, the user password
  authenticated, every frame in a SECURE_WRAPPER, session keepalive, and the
  #180 reconnect opening a new secure session (#71 Phase B). The credentials
  come from `--keyring` (the keyring's tunnelling users, picked automatically
  for the gateway reached) or from `--secure-user <id> --secure-password-env
  <VAR>`.
- A secure-only interface without credentials fails at once with a message
  that names KNXnet/IP Secure, instead of retrying a refused CONNECT (#182).
  `init` and discovery report an interface as KNXnet/IP Secure capable or
  secure-only from the extended search.
- `bussard keyring` lists the tunnelling users per interface
  (`user <id> -> <tunnel IA> (host <IA>)`) and which devices carry KNXnet/IP
  Secure credentials, never the passwords; the keyring parser decrypts
  `Device@ManagementPassword` and `@Authentication` too (#188).
- A keyring without a `Device` entry for the target serves the secure tunnel
  alone: the device is managed in the clear through it, so the plain devices
  behind a secure-only interface stay reachable. A device the keyring lists
  keeps secured management; a device the model marks `security.activated` but
  the keyring lacks is refused as before. `describe`, `reconstruct`, `plan`,
  `flash`, `apply`, `commission`, `replace`, `backup`, `restore`, the line
  walks and the MCP device tools follow this rule; `scan` and `assign` take
  `--keyring` for the tunnel (#189).
- Identity reads of Data Secure devices (#203). A Data Secure-activated device
  answers a plain descriptor read with mask `FFFF`. `scan --keyring` reads a
  keyring-listed device over `A_SecureData` and shows its real mask
  (`secure: activated` in `--json`); an activated device without a tool key is
  labelled "Data Secure activated (mask hidden), no tool key in the keyring"
  (`secure: activated_no_key`). Plain devices see the same frames as before.
  `assign` verifies a Secure device over `A_SecureData` with the tool key of
  the new address, or of the old one with a note to re-export the keyring, or
  `--tool-key`; without a key it reports the hidden mask instead of "verified:
  mask 0xffff". `audit --live` and MCP `knx_audit` probe each Secure device
  with its tool key and report `activated`, `reachable_secured`,
  `plain_reads_refused` and `in_keyring` (`live.secure`).
- `connection.keyring` in `bussard.toml` is the default for `--keyring` on
  every bus command (the flag overrides it; the password stays in
  `BUSSARD_KEYRING_PASSWORD`). The campaign wrapper passes
  `--keyring "$BUSSARD_KEYRING"` to its probes and the step when that variable
  is set (#189).
- KNXnet/IP Secure over UDP for an interface without a TCP endpoint, as an
  explicit opt-in: `--secure-transport udp`. The default `auto` stays on TCP,
  the only carrier tested against a real interface; an interface that refuses
  TCP but advertises Secure fails with a message naming the opt-in instead of
  switching to UDP on its own. A secure UDP handshake skips an authenticated
  frame that arrives before the CONNECT_RESPONSE, as the TCP one does. The
  session keepalive is configurable (`BUSSARD_SECURE_KEEPALIVE_SECS`), and
  `bussard test --secure-idle <secs>` measures the interface's idle timeout
  read-only. It measured 60 s on the Jung interface (alive at 45 s, dropped at
  59.97 s), so the 30 s default keepalive is confirmed; an interval of 60 s or
  more prints a warning at connect. `write --keyring` prints a note on sender admission (PID 54,
  `--secure-sender`) after a secured write (#197).
- The frame shapes, the Secure DIBs and the interface's SESSION_RESPONSE MAC
  are checked against an ETS capture of a Jung interface by an ignored oracle
  test; knx-sim gained a secure-only interface mode; knxtrace decodes the
  Secure DIBs, the search parameters and the wrapper headers.

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
- `bussard mcp --listen [<ADDR>]` serves the MCP tools over the streamable
  HTTP transport at `http://<ADDR>/mcp`, for clients that take a server URL
  (#265). It binds `127.0.0.1:0` by default and prints the URL; the tiers and
  the real-gateway write gate are the same as over stdio. A non-loopback
  address needs `--allow-remote-clients` and a bearer token
  (`BUSSARD_MCP_TOKEN`, or one generated and printed once); `--allow-host`
  admits a reverse proxy's host name. bussard does not terminate TLS: Claude
  Desktop's custom connectors reach it through a proxy or tunnel you run.
- The MCP server talks to a homeowner (#306). The server instructions say who
  reads the replies and how to name things (rooms, device, channel and group
  names; ids only in tool calls). Every edit, undo, discard, pending change,
  plan, apply, restore, restart, backup, read-back and Home Assistant result
  carries a `summary` in names, and an edit's `validation` a `for_the_human`
  line. `knx_plan_device` adds `what_you_will_notice`: the device and room,
  how long the write takes, what keeps working, the changes in plain words and
  what to test afterwards. `knx_show_device`, `knx_get_group` and
  `knx_model_lookup` take `technical` like `knx_get_device`: by default they
  leave out the ETS ids and wire detail, and `technical: true` returns the
  payload as before. `next_step` names devices by name and room.
- `scripts/sim-catalog-loop.sh` and the corpus-gated `sim-catalog-loop` CI job
  flash every corpus application bussard and knx-sim support to a simulated
  device, with its defaults and seeded generated configurations, and require
  every plan after a flash, a partial `apply` and a re-flash to be a no-op
  (#346). knx-sim now keeps every segment a System 7 load-state machine
  allocates, accepts an in-place partial download of a loaded one, serves the
  device-object values a program's `LdCtrlCompareProp` expects, accepts a
  `PID_MCB_TABLE` seeding write while loading, accepts the property writes of a
  program's `LdCtrlWriteProp` steps, and places a relative segment that would
  cover a table's base above 0xFFFF.
- The offline oracle reports coverage (#347): of the octets bussard places, the
  share the ETS capture holds, per segment and per 256-octet page
  (`knxtrace imgdiff`, a coverage column in the `95-offline-oracle.sh`
  summary). A matching row below 50 %, or with a page that has placed octets
  and none compared, is "not comparable (thin)", never "identical".
  `flash --dry-run --dump-images` records the placed octets of each image in
  `plan.json`. Rows take a recorded `coverage` and `expect=`/`scope=` options,
  `--check` gates on them, and the corpus-gated `offline_oracle` test runs it
  (`BUSSARD_ORACLE_ROWS`). The script now plans the bussard side with the
  model's key store (`--keyring` only decodes the capture) and offers
  `--no-admit`.
- The KNX Data Secure invariants are validation codes (#348): W037 (a device
  on a secured group address is not activated), W039 (a Secure sender has no
  sequence number in the lock), W041 (the group flag and the object flags
  disagree; with W029 it names `bussard groups secure <ga> on|off` as the
  fix), W040 (a keyring export, or Home Assistant's keyring, is older than
  the key store's last change, recorded in `bussard.keys.meta.toml`), E038
  (a secured write to a tunnel-only group address whose devices admit no
  tunnelling address is refused while `admit_tunnel_senders` is off) and
  W042 (`bussard import` or `bussard keys import` secures a group address
  the model ran plain again, naming the devices that need an apply). Each
  code has a mutation test on a fixture project, and a corpus-gated test
  (`BUSSARD_ETS_PROJECTS`) checks that a clean ETS import validates without
  errors or warnings.
- `bussard diff <A> <B> --checklist` prints a per-device Markdown checklist of
  the changes to redo by hand in ETS: group addresses first, then one section
  per device with its parameters on their ETS pages (an enabling parameter
  before the one it reveals, old values as ETS shows them), its objects and
  links and its security, then plain notes for what ETS cannot take by hand.
  `--checklist --json` emits the same structure. Link sentences of `diff`,
  `status` and the MCP tools now carry the device address (#372).
- `bussard flash` executes the property operations of a load procedure
  (#390): `LdCtrlWriteProp` with its `Count` and `Verify` (a read-back right
  after the write), with the value from `InlineData` or, when the op carries
  none, from the program's property-located parameters as ETS composes it;
  `LdCtrlCompareProp` on an object named by type; and the `<choose>` blocks of
  a load procedure, decided under the device's parameters. An object named by
  type is written with the extended property services, as ETS does, and by
  its index when the device refuses them. The 99 System 7 programs refused on
  `LdCtrlWriteProp` now plan, and a property-only procedure on mask 0021 (the
  Jung IPS 300 SREG KNX IP interface) plans and runs without a load-state
  machine, a factory reset or a security-object step, ending with a read-back
  of every property it wrote. The post-write read-back compares those
  properties too.
- The offline oracle and knx-sim follow the property load procedures (#390):
  `knxtrace ops` names the extended property services (`prop-write
  type11.1/PID205`, `function-prop`), the KNXnet/IP Secure keys (PIDs 91 to
  93 of object type 11) are redacted like the Data Secure ones, and a
  property-only row lists ETS's KNX IP interface commissioning (objects 11 and
  17) without counting it and says when ETS did not run the load procedure.
  knx-sim serves a property-only device on mask 0021, the compares a
  procedure runs on objects other than the device object, writes by object
  type through the extended services, and the label objects a System 7
  procedure writes; the sim catalog loop runs the 0021 program. A
  type-addressed write that the device leaves unanswered falls back to the
  object index from `PID_IO_LIST`. Masks 0020, 0021 and 0025 are now labelled
  System 2 (BCU2), not System 1.
- `plan` and `apply` write a KNX IP interface's `[knxnet]` table (#391): the
  friendly name, the tunnel addresses, the static address set and the IP
  assignment become property writes on its KNXnet/IP parameter object (object
  type 11, by type as ETS writes the IPS 300 SREG), each read back and the
  object read again before `apply` says verified. The tunnel count changes
  only as far as the device's description of PID 53 allows. A change of the IP
  settings or the tunnel addresses (PID 53) of the interface bussard tunnels
  through is refused unless
  `apply --allow-self-reconfigure`. Over MCP, `knx_set_interface` edits the
  table with validation (E043 to E046, W047) and `knx_plan_device` /
  `knx_apply_device` write it through the same service functions. knx-sim's
  simulated interface takes the writes and needs no product file.
- KNX IP interfaces carry their KNXnet/IP settings as a `[knxnet]` table in the
  device file (IP assignment, static address, netmask and gateway, friendly name,
  tunnel addresses), imported from the project's `IPConfig` and
  `AdditionalAddresses` and written by `adopt` from the device (#391).
  `bussard status <ADDRESS>` reads a device live and shows an interface's IP
  address, assignment, MAC address, tunnels and state; `describe` and
  `knx_show_device` show them too, the read values are kept with the device
  facts, `diff` describes table changes in sentences, and `validate` checks the
  table (E043 to E046) and its tunnels against the key store (W047). Writing the
  settings to the device follows separately.
- `bussard interface secure on|off <ia>` and the MCP tool `knx_interface_secure`
  switch KNXnet/IP Secure of a KNX IP interface without ETS (#398), in the
  sequence the ETS captures of 1.1.200 show: under the FDSK the security mode
  and the tool key, under the tool key the device authentication code, the
  password hashes, the tunnelling users and the secured service families, a
  master reset; `off` undoes it. Credentials come from and go to the key store
  only (missing ones generated and saved before the first write), every switch
  ends with a read-back after the restart, and `--dry-run --dump-images` feeds
  the offline oracle (`run=secure-on|secure-off` rows: identical against the
  ETS activation, 11 of 11 writes, and the decoded half of the deactivation).
  knx-sim models the interface's Secure properties, the tool-key switch, the
  gateway's switch to secure-only tunnelling at the master reset, and
  KNXnet/IP device management.
- The offline oracle compares load control with ETS (#419): every record bussard
  sends a load-state machine (Unload, StartLoading, LoadCompleted, the segment,
  TaskSegment and TaskCtrl records, as `PID_LOAD_STATE_CONTROL` or as the System 7
  memory-mapped record at 0x0104) against the capture, per object in order, as
  its own verdict next to the memory and property verdicts. `flash --dry-run
  --dump-images` lists the records per step in `plan.json`, and a rows file pins
  the expected verdict with `loadctl=`.
- `tools/ets-sweep`: ETS 6 downloads a product into knx-sim without a hand on
  the VM (epic #419, part 1 #420): a UI Automation plus OCR driver inside the
  Windows VM, a sweep script that runs the sim in the VM and keeps the capture,
  and the knx-sim behaviour ETS needs that bussard never asked for (tunnelling
  feature services, L_Data.con, a T_ACK before every answer, the request's
  sequence number in the answer, verify-mode memory echo, a PID_TABLE
  description, plain SEARCH_REQUEST, a configurable tunnel address, a pcap of
  the gateway's own datagrams).
- `tools/ets-sweep/catalog.py` imports the product corpus into ETS's catalog
  through the driver and records each file's outcome in
  `tools/ets-sweep/catalog.json` (epic #419, part 2 #421).
- The ETS defaults sweep (`tools/ets-sweep/defaults.py`, `oracle.py`) has ETS
  download every corpus application into knx-sim and compares each capture
  with bussard's dry-run flash (epic #419, part 3 #422). knx-sim answers
  connectionless descriptor and property reads, and takes per-device property
  overrides (`properties:`) for the identity ETS checks before a download.
- knx-sim creates the application interface objects a product's load procedure
  addresses by index beyond the system objects (the MDT Glass Touch Smart's
  object 7): written properties are writable and described with the PDT of
  their length, compared ones hold the value the parameter defaults select,
  so ETS can describe and write them during a download (#422).
- ETS sweep: `oracle.py` imports each product file once and shares it across
  its rows (seconds instead of minutes and 1.6 GB per row of a catalogue file),
  `defaults.py` refuses a capture from a catalog row of another application
  version (`--relabel` for recorded results), and `summary.py` writes the
  labels-only outcome manifest and the parity summary per mask family and
  manufacturer with the verdict changes since the previous run (#422).
- ETS sweep part 4, not yet run live: `secure.py` runs the secure-capable
  applications against a factory-state sim device with a synthetic FDSK and
  serial number, has the driver set the project password, enter the device
  certificate and export the keyring, and checks that knxtrace decodes the
  capture end to end; `secure.py cert` writes and checks certificate labels
  (#423).
- ETS capture of a KNX Data Secure download: ETS 6.4.1 commissions the
  synthetic product syn-secure in knx-sim (FDSK session, tool key, security
  mode, then the download under the tool key). The ETS sweep driver now
  handles ETS's Data Secure dialogs: the project password, the device
  certificate when the device is added, and the keyring export with
  certificates. Synthetic keyrings are exported under a public password and
  committed next to the capture. The offline oracle takes a per-row keyring
  (`keyring=`) to decode the secured frames. The syn-secure row is compared:
  the memory and load control are identical to ETS. The security object's
  writes differ until the keyring imports into a key store (#858) (#423).
- ETS sweep part 5, not yet run live: `params.py` draws seeded parameter
  configurations (page switches bussard's `device --json` names first, then
  enumeration and integer parameters off their defaults), has the driver set
  them on ETS's parameter pages, download and export the project, and compares
  each capture with `bussard import` of that export (#424).
- ETS sweep part 6: `nightly.py` runs the sweep shards, the links variant, the
  oracle over every row, the parity summary and the follow-up drafts in one
  locked run that records the ETS version (launchd agent and cron entry under
  `tools/ets-sweep/schedule/`, install steps in the README); `followups.py`
  drafts, and with `--create` opens, an issue for every identical -> differs
  verdict; a failed run keeps a screenshot, the control trees and the
  driver's trace under `repair/` next to the outcome (#425).
- Parameter calculations: values a program computes with a `<ParameterCalculation>`
  script (VBScript or JavaScript), such as an Ekinex EK-E72's fan block or a
  Jung LED dimmer's dimming curve, are now computed in the Dynamic evaluation
  and written instead of their vendor defaults (#427). As in ETS, a script
  runs only once one of its inputs differs from its default. Verified byte for
  byte against ETS downloads of the EK-E72, a Jung LED dimmer and the synthetic
  product that changes a calculation's input. A script outside the supported subset, calculations that do not
  settle, and a model value a calculation would replace refuse the device's
  write, naming the calculation, instead of writing a value the script did not
  compute.
- `bussard restart <ADDRESS>` restarts one device (nothing erased) behind the
  usual confirmation and real-gateway gate, in the form ETS's *Restart device*
  uses for it (#435, #452): the confirmed restart (master reset, erase code 1)
  for a secure-capable System B application, verified only by its
  `A_Restart_Response` with error code 0, else a bare `A_Restart`, reported as
  sent and not verified. Either way it then waits until the device answers
  again with the same mask. `--json` carries `form` and `confirmed`.
- The offline oracle compares partial downloads: a `run=apply` row starts
  knx-sim from ETS's state before the step (the earlier captures replayed with
  the new `replay:` config key), runs `bussard apply` against it and compares
  the device memory after it and the load-control records with ETS's partial
  download (`knxtrace statediff`); `tools/ets-sweep/apply_rows.py` writes the
  rows of a recorded series (#469).
- ETS sweep part 7: `defaults.py --variant links` links a few objects before
  each download and `oracle.py --variant links` compares those captures with a
  model carrying the same links; `series.py partial` runs the partial-download
  series (full download with links, a link added, removed, a second address)
  on one representative product per table layout in one sim process, and
  `--oracle` compares each step with `bussard apply` and, for the first
  partial step, `apply --line` (`run=apply-line`) (#478).
- `write`, the MCP `knx_write_group` tool, `viz` and HA automations can send
  text (`16.000` ASCII, `16.001` Latin-1, `28.001` UTF-8), a time (`10.001`,
  `Mon 07:30`), a date (`11.001`, `2026-10-29`) and a date-time (`19.001`,
  `2026-10-29 12:30:00 summer`) (#503). A `16.x` value now decodes the whole
  14 octets and trims only the trailing padding; `monitor` notes a byte above
  7Fh on `16.000` and a `28.001` string without its terminating NUL.
- `write`, the MCP tools and HA automations take a colour: `#RRGGBB` or
  `rgb(r, g, b)` on `232.600`, `#RRGGBBWW`, `#RRGGBB` or `rgbw(r, g, b, w)`
  with `-` for a channel to mark invalid on `251.600` (#504). `read` and
  `monitor` decode `242.600` (x, y, brightness and the validity bits),
  `249.600`, `250.600`, `252.600` and `254.600` instead of showing raw hex.
- The tunnel reads the interface's max APDU length (tunnelling feature 07)
  right after CONNECT, as ETS does, when the interface's extended description
  shows it serves feature services; `Tunnel::feature_get` reads any feature.
  Inbound TUNNELLING_FEATURE frames are now ACKed and sequence-counted like a
  TUNNELLING_REQUEST, so a FEATURE_INFO no longer knocks the inbound sequence
  out of step (KNXnet/IP Tunnelling 3/8/4 §3, #514).
- bussard can manage a KNX IP interface over a KNXnet/IP device management
  connection (connection type 03h), plain over UDP or inside a KNXnet/IP
  Secure session of the management user (#523). `--device-management` asks
  for it on `plan`/`apply` of an interface, `describe` and `interface secure`;
  without the flag these commands fall back to it when the interface is the
  gateway and has no free tunnel slot or a duplicated tunnel address.
  Property reads and writes go as `M_PropRead`/`M_PropWrite`, the rest as
  cEMI transport-layer frames; the tunnel stays the default.
- System 7 downloads lower `LdCtrlTaskPtr` (the Task Pointer Record) and
  `LdCtrlTaskCtrl2` (Task Control Record 2) to their Additional Load Controls
  records (segment types 03h and 05h, 11 octets memory mapped, 10 by
  property) instead of refusing the procedure, and knx-sim accepts both while
  Loading (#527).
- `bussard secure diag <ia> [--clear]` reads a Data Secure device's security
  failures log (PID 55: sequence, cryptographic and access counts, the latest
  failure), its security report (PID 57) and report control (PID 58) with the
  tool key; `--clear` resets them and reads them back. `status <ia>` and
  `knx_describe_device` show the same for a Secure device, the note of a
  secured write without admission evidence points at it, `monitor` names a
  device's broadcast security report, and knx-sim counts the failures as the
  standard says (#533).
- The System B flash pre-flight reads the device's `PID_MANUFACTURER_ID`
  (object 0, PID 12) before anything is unloaded and refuses, naming both
  manufacturers, when it is neither the application's manufacturer nor its
  `OriginalManufacturer`; `--force` overrides as for a resident application.
  This is step 04 of the KNX download procedure and adds one read to a
  flash (#547).
- `knx_describe_device` takes the FDSK fallback of `bussard describe` through the
  same service function: a device without a tool key that refuses the plain walk
  and answers under its factory key is reported `factory_key: true` (#571).
  `knx_clear_security_log` clears the security failures log (PID 55) and resets
  the report over MCP, in two calls behind the question `secure diag --clear`
  asks (#571).
- The CLI and the MCP server are checked to write the same requests for the
  same change over the synthetic catalogue (epic #596, step 8, the #314
  class): `bussard plan` and `apply` (or `flash`) against `knx_plan_device`
  and `knx_apply_device`, on knx-sim from the same flashed state, for every
  product's apply and for the flash of the products whose switches show or
  hide a com-object. All 46 simulated products write identically.
- Golden request streams over the synthetic product catalogue (epic #596,
  step 7): bussard's flash of every synthetic product into knx-sim, and its
  apply where the catalogue has a `links` or `partial` variant, normalized by
  `knxtrace ops`, is committed under
  `tests-support/synthetic-products/<product>/requests/` and compared in the
  `sim-conformance` CI job, so a change to a write path is a reviewable diff;
  `BUSSARD_UPDATE_GOLDENS=1` regenerates them.
- The synthetic product `syn-assign` ("Chore assigner", `NEST-CHORE`, #604
  row 31) has an `<Assign>` from the reached delay parameter onto a placed
  parameter no block shows, captured with ETS: ETS writes the assigned value,
  not the target's default, as bussard does (row identical). The generator
  gained `<Assign>` in a `<when>`.
- The synthetic product `syn-choose-never-shown` ("Ghost-mouse detector",
  `NEST-GHOST`, #604 row 14) has a `<choose>` on a memoryless parameter no
  block shows, with only a default branch, captured with ETS for #474: ETS
  takes no branch, bussard does (row `expect=differs`). The generator gained
  virtual parameters and a `<choose>` in the Dynamic tree.
- Synthetic product `syn-choose-partial-segment` ("Half-egg warmer",
  `NEST-HALF`): a `<choose>` in the load procedure on a keep-data parameter
  whose taken branch writes half the parameter segment, with its ETS capture
  (ETS writes only that half) and a not-comparable oracle row, since bussard
  refuses the product (#604 row 8, #411). The generator renders a `choose`
  load op.
- The synthetic product `syn-choose-per-ref` ("Twin-perch selector",
  `NEST-TWIN`, #604 row 25) chooses on the unreached second `ParameterRef`
  of a reached parameter, captured with ETS as the regression row of #563:
  ETS selects no branch and leaves the object behind it out of the
  group-object table, as bussard does (row identical). The generator gained
  further `ParameterRef`s of a parameter and `<when test>` branches in the
  Dynamic tree.
- Synthetic product `syn-color-param-hsv2` (`NEST-COLHSV2`): the HSV twin of
  `syn-color-param` with two non-primary defaults (`#FC35C7`, `#90F32C`),
  captured with ETS. ETS writes `DF C9 FC` and `3F D0 F3`: hue times
  255/360, saturation times 255, both truncated, and value the largest RGB
  component. The row is `expect=differs` until #616 is fixed.
- Synthetic products `syn-color-param` (Plumage colour lamp, `NEST-COLOUR`)
  and its twin `syn-color-param-hsv` (`NEST-COLHSV`): `syn-minimal` with a
  reached `TypeColor` parameter in memory, default `#FF0000`, in the RGB and
  the HSV space, captured with ETS (#604 row 40). RGB: ETS writes `FF 00 00`,
  as bussard does. HSV: ETS converts the RGB value and writes `00 FF FF`,
  bussard `FF 00 00`; the row is `expect=differs` until #616 is fixed. The
  generator renders the `color` type kind.
- The synthetic product `syn-com-objects` ("Chirp switchboard",
  `NEST-CHIRP`, #604 row 27) has one com object per size from 1 bit to 14
  bytes, every combination of the C, R, W, T and U flags, priorities Low,
  High and Alert and a read-on-init object, captured with ETS as the
  regression row of the group-object descriptors (#541, #545, #540). It
  differs in one descriptor: an unlinked object with no flags, which ETS
  writes and bussard leaves at `00 00` (#686, row `expect=differs`).
- The synthetic product `syn-dynamic-tests` ("Worm-movement detector",
  `NEST-WORM`, #604 row 28) has a `<Channel>` whose block holds three
  `<choose>`s with single-value, value-list, comparison and default `<when>`
  tests, one com object per branch, captured with ETS as a regression row of
  the Dynamic evaluator (#345): ETS takes the same branches as bussard (row
  identical). The generator gained channels and chooses inside a block.
- The synthetic product `syn-hidden-default` ("Egg heater", `NEST-EGGHEAT`,
  #604 row 12) has a parameter no block shows whose default differs from the
  segment template, with no download options, captured with ETS for #448.
- The synthetic product `syn-ip-57b0` ("Thermal-updraft sensor",
  `NEST-THERMAL`, #604 row 35) is `syn-minimal` on mask 57B0 with
  `MediumTypes="MT-5"`. bussard plans it, and knx-sim now models mask 57B0 as
  System B, so the synthetic sim loop flashes it. ETS imports it but will not
  add a KNX IP device to the sweep project's TP line, so it has no capture
  (#389).
- Synthetic product `syn-ip-address-param` (Homing beacon, `NEST-HOMING`):
  `syn-minimal` with a reached `TypeIPAddress` parameter in memory, default
  192.168.27.21, captured with ETS (#604 row 21): ETS writes `C0 A8 1B 15`,
  and so does bussard (regression row for #457). The generator renders the
  `ip_address` type kind.
- The synthetic product `syn-ip-enabled-tp` ("Treetop uplink", `NEST-UPLINK`,
  #604 row 34) is `syn-minimal` on hardware with a KNX IP interface built in
  (`IsIPEnabled`, `AdditionalAddressesCount="2"`), captured with ETS for
  #455. After the application ETS writes the KNXnet/IP parameter object
  (PIDs 51, 66, 67, 76 in two writes, 55, 53), and bussard writes the same
  block: the row is identical with `props=ok(8)`. The generator gained
  `ip_enabled` and `additional_addresses_count`. `capture.py` gives such a
  product's sim the KNXnet/IP object and plans its row with the sweep
  project's `[knxnet]` table, and the knx-sim replay reads `knxnet` from
  `sim.yaml`.
- The synthetic product `syn-le-order` ("Tree-altitude meter", `NEST-ALTI`,
  #604 row 4) declares `ParameterByteOrder="LittleEndian"` with signed 16- and
  32-bit numbers, a DPT 9 float and an IEEE-754 Single float at asymmetric
  defaults, captured with ETS for #403. The generator renders the `float`
  parameter type kind and the `ParameterByteOrder` option; its rendering paths
  have unit tests (`test_generate.py`).
- Synthetic product `syn-legacy-patch-always` (Twig patcher, `NEST-PATCH`):
  `syn-minimal` with a hidden `LegacyPatchAlways` parameter whose default
  differs from the template, in a `DownloadInvisibleParameters="Background"`
  application, captured with ETS (#604 row 20): ETS writes the default, and so
  does bussard (regression row for #450).
- The synthetic product `syn-map-error` ("False-alarm filter", `NEST-FALSE`,
  #604 row 38) wraps an `LdCtrlUnload LsmIdx="5"` of `syn-product-07b0` in
  `LdCtrlMapError` (`0xC0042B08` to 0 and back), the Siemens shape of #614,
  captured with ETS: ETS sends the unload to object 5 ahead of the other
  unloads, as bussard does, and the row is identical. The generator gained
  `LdCtrlMapError` in the 07B0 product procedure.
- Synthetic product `syn-master-reset-code4` ("Deep-cleaning switch",
  `NEST-RESET4`): the `syn-master-reset` twin with erase code 4, the KNX
  Virtual DA.tp sequence, with its ETS capture and oracle row (#604 row 10,
  #600, #611). The synthetic sim loop reads known failures from
  `tests-support/synthetic-products/sim-loop-baseline.json`; this product is
  listed there until #623 is fixed.
- Synthetic product `syn-master-reset` ("Spring-cleaning switch",
  `NEST-RESET`): `LdCtrlMasterReset EraseCode="1"` after the segment
  allocation in the application's procedure, with its ETS capture and oracle
  row (#604 row 10, #546, #611). The generator renders `LdCtrlMasterReset`.
- The synthetic product `syn-module-repeat` ("Triple chick feeder",
  `NEST-TRIFEED`, #604 row 19) instantiates a `ModuleDef` three times by a
  `<Repeat>`, each instance's parameter and com-object base drawn from an
  `<Allocator>`, captured with ETS as the regression row of #449: ETS writes
  the three module parameters at +0x10, +0x14 and +0x18 and objects 2 to 4,
  as bussard does (row identical). The generator gained allocators, module
  definitions and `<Repeat>`.
- The synthetic product `syn-param-calculation` ("Prey calculator",
  `NEST-CALC`, #604 row 11) has an inline JavaScript `<ParameterCalculation>`
  with two placed outputs, one of them a hidden `LegacyPatchAlways`
  parameter, captured with ETS for #427 and #450: at defaults ETS writes both
  outputs at their defaults without running the script, and writes the hidden
  `LegacyPatchAlways` output, as bussard does. The generator gained
  calculations and `legacy_patch_always`.
- The synthetic product `syn-product-07b0` ("Nest-building planner",
  `NEST-PLAN`, #604 row 37) spells out a 07B0 download as one
  `ProductProcedure` with the tables as relative segments on LSM 1 to 3, the
  Siemens shape of #614, captured with ETS: ETS allocates and writes each
  table at its length, not at the op's `Size`, adds no unload of object 5 and
  no restart, and the row is identical. The generator gained the 07B0 product
  procedure, and the synthetic sim loop's flashability gate passes the empty
  tables `bussard flash` would.
- Synthetic product `syn-property-param` (Territory marker, `NEST-TERR`):
  `syn-minimal` with a parameter placed by `<Property>` in object 4 PID 201
  and an `LdCtrlWriteProp` without `InlineData` that writes it, captured with
  ETS (#604 row 30): ETS writes `5A` to the property, bussard nothing (#669);
  the row holds `props=differs`. The generator renders `property` placement
  and `LdCtrlWriteProp`; `capture.py` records a property difference in the
  manifest and the row.
- Synthetic product `syn-relseg-fill` ("Feather filler", `NEST-FILL`): the
  parameter segment allocated by `LdCtrlRelSegment Mode="0" Fill="255"`, with
  its ETS capture and oracle row (#604 row 7, #480). `capture.py` writes a
  row's `expect=` and `loadctl=` from the recorded verdicts.
- The synthetic product `syn-rf-27b0` ("Radio chick monitor", `NEST-RADIO`,
  #604 row 36) is `syn-minimal` on mask 27B0 with `MediumTypes="MT-2"`.
  bussard imports and plans it. knx-sim has no RF model, so the sim loop
  skips it (`sim-loop-refusals.json`). ETS imports the product but will not
  add an RF device to the sweep project's TP line, so it has no capture.
- Synthetic product `syn-s7-0701` (Back-door actuator, `NEST-BKDOOR`): the
  System 7 baseline on mask 0701, `syn-s7-0705` with the memory-mapped load
  state machine and no stack segment, captured with ETS (#604 row 3).
  knx-sim's calibration replay builds a captured System 7 device with the
  load state machine its mask requires and skips the load-control records.
- Synthetic product `syn-s7-0705` (Twig-door actuator, `NEST-DOOR`): the
  System 7 baseline on mask 0705, a full `ProductProcedure` over absolute
  segments with a SegType 1 stack segment, TaskSegment, TaskCtrl1 and the
  property load state machine, captured with ETS (#604 row 2). The generator
  renders System 7 masks, absolute segments and the System 7 load ops, and
  `capture.py` drives a memory-mapped sim for mask 0701.
- Synthetic product `syn-s7-choose-split` (Split-branch perch, `NEST-SPLIT`):
  `syn-s7-0705` with a load-procedure `<choose>` whose taken branch allocates
  the parameter AbsSegment in two parts around a placed parameter, captured
  with ETS (#604 row 9). ETS allocates and writes the two parts only and never
  touches the gap; bussard refuses the product (#411).
- The synthetic product `syn-s7-delay` ("Slow-hatch timer", `NEST-HATCH`,
  #604 row 39) adds `LdCtrlDelay MilliSeconds="200"` before the restart of
  `syn-s7-0701`, captured with ETS for #615: ETS pauses 211 ms after the last
  LoadCompleted and before `A_Restart`, where bussard pauses too; the row is
  identical. The generator gained `LdCtrlDelay` on System 7.
- The synthetic product `syn-s7-hidden-default-ets4` ("Vintage egg heater",
  `NEST-EGGV4`) is `syn-s7-hidden-default` with `MinEtsVersion="4.0"` in
  schema project/23, captured with ETS for #448: ETS keeps the hidden
  parameter's template, so on System 7 `MinEtsVersion` decides, not the schema
  bussard keys on (row `expect=differs`). The generator gained
  `min_ets_version`.
- The synthetic product `syn-s7-hidden-default-p11` ("Heirloom egg heater",
  `NEST-EGGOLD`) is `syn-s7-hidden-default` in schema project/11, the schema
  of the #448 vendor applications. ETS keeps the segment template for its
  hidden parameter where the project/23 twin gets the default, so the
  schema, not the System 7 mask, decides (#448; row identical). The generator
  gained `[application] schema = 11`, and the signer signs a product in its
  own schema (`signer.exe --schema`).
- The synthetic product `syn-s7-hidden-default` ("Backup egg heater",
  `NEST-EGGBAK`, #604 row 13) is the System 7 twin of `syn-hidden-default`,
  captured with ETS for #448: ETS writes the hidden parameter at its default
  on this 0705 product too, where bussard keeps the template (row
  `expect=differs`).
- The synthetic product `syn-s7-lsm5-0705` ("Fifth-twig gauge",
  `NEST-TWIG5G`, #604 row 32) adds a TaskSegment on LsmIdx 5 to
  `syn-s7-0705`, captured with ETS for #489: ETS sends no LSM 5 record on 0705
  either, while bussard still does there (row `loadctl=differs`, sim-loop
  baseline entry, fix in #680).
- Synthetic product `syn-s7-lsm5` (Fifth-twig sensor, `NEST-TWIG5`):
  `syn-s7-0701` with a TaskSegment on LsmIdx 5 inside LSM 3's load, captured
  with ETS (#604 row 15). ETS sends no LSM 5 record; bussard sends the
  TaskSegment and fails against knx-sim, which the sim-loop baseline lists
  under #489.
- The synthetic product `syn-s7-no-comobjects` ("Silent perch", `NEST-SILENT`,
  #604 row 26) puts the com objects of `syn-s7-0701` only in a block the
  defaults do not reach, the shape of #562, captured with ETS: ETS writes the
  group-object descriptors as the template with the communication flag
  cleared, as bussard does; the row is identical. The synthetic sim loop now
  flashes a product with no linkable com object instead of skipping it.
- Synthetic product `syn-s7-pei80` (Claw connector, `NEST-CLAW`):
  `syn-s7-0701` with `PeiType="128"`, captured with ETS (#604 row 16). ETS
  writes PEI type 0x80 and segment ID 0 into each memory-mapped TaskSegment
  record, as bussard does (#483).
- The synthetic product `syn-s7-pid204` ("Plumage programmer", `NEST-PLUME`,
  #604 row 33) adds `LdCtrlWriteProp ObjIdx="3" PropId="204" Count="2"` with
  10 octets of `InlineData` to `syn-s7-0701`, captured with ETS. knx-sim
  describes the property as one `PDT_GENERIC_10` element and ETS skips the
  write, which bussard makes; the row is `expect=differs props=differs` until
  the sim describes `Count` elements (#692).
- Synthetic product `syn-s7-static-split` ("Fixed-fork perch",
  `NEST-FORK`): `syn-s7-choose-split` with the split of the parameter
  AbsSegment outside any `<choose>` and a placed parameter in the gap, with
  its ETS capture (#657). ETS allocates and writes the two parts and never
  touches the gap, as in the `<choose>` case; the row is
  `expect=not-comparable` while bussard refuses the product.
- Synthetic product `syn-s7-taskptr` (Hunt scheduler, `NEST-HUNT`):
  `syn-s7-0705` with `LdCtrlTaskPtr` and `LdCtrlTaskCtrl2` on LSM 3, captured
  with ETS (#604 row 17): the first ETS capture of both records, which
  bussard sends octet for octet (#527). The generator renders the two ops.
- Synthetic product `syn-text-initialvalue` (Nest nameplate, `NEST-NAME`):
  `syn-minimal` with `TextParameterEncoding="utf-8"` and a text parameter
  whose de-DE `InitialValue` translation differs from its default, captured
  with ETS in the sweep's German project (#604 row 24): ETS writes the
  translated text in UTF-8, and so does bussard (regression row for #473).
  The generator renders `InitialValue` and its translations.
- The synthetic product `syn-text-undeclared` ("Squawk display",
  `NEST-SQUAWK`, #604 row 6) has a text parameter with the default "Störung"
  and no `TextParameterEncoding`, captured with ETS for #416. The generator
  renders the `text` parameter type kind; the synthetic sim loop accepts a
  refusal listed in `tests-support/synthetic-products/sim-loop-refusals.json`.
- Synthetic product `syn-union-bitfields` (Feather-bit packer, `NEST-BITS`):
  `syn-minimal` with a 16-bit union of two member types and three sub-octet
  parameters packed into one octet by `BitOffset`, captured with ETS (#604
  row 29): ETS writes `0A 0B` and `56`, and so does bussard (regression row
  for the packing). The generator checks that a `bit_offset` lies in 0..7.
- The synthetic product `syn-union-default-range` ("Stray-egg counter",
  `NEST-STRAY`, #604 row 5) has a hidden union member whose default (1) lies
  outside its type (129..129), captured with ETS for #405. The generator
  renders `[[union]]` with member parameters and the parameter `access`.
- The synthetic products `syn-user-memory` ("Big prey larder", `NEST-LARDER`,
  #604 row 22) and its twin `syn-user-memory-extmem` (`NEST-LARDERX`) carry an
  8448-octet parameter segment that knx-sim places at 0x10000, without and
  with `SupportsExtendedMemoryServices`, captured with ETS: ETS writes it with
  `A_UserMemory_Write` without the option and `A_MemoryExtended_Write` with
  it, as bussard does since #472; both rows are identical.
- The synthetic product `syn-writerelmem-size` ("Short quill writer",
  `NEST-QUILL`, #604 row 23) allocates and writes 128 octets of a 256-octet
  parameter segment (`LdCtrlRelSegment` and `LdCtrlWriteRelMem Size` 128),
  the shape of #564, captured with ETS: ETS writes 128 octets and the row is
  identical, a regression row for the #564 fix.
- `tools/ets-sweep/synthetic/calibrate.py` runs a synthetic product and the
  product it was cloned from through the ETS sweep, distils each capture into
  a knx-sim request fixture (`synthetic/distil.py`), runs the offline oracle row
  of each, replays both fixtures in knx-sim and prints whether ETS, the oracle
  and the sim treat the two alike (#596). knx-sim's `ets_calibration.rs` gains
  an environment-gated replay of such fixtures.
- The synthetic product `syn-minimal` ("Nest-side light switch",
  `NEST-LIGHT`) is captured once with ETS 6.4.1 into knx-sim and committed
  under `captures/synthetic/` with its oracle row (`rows.txt`, identical at
  100.0 % coverage) and a manifest of the ETS version, simulator build and
  product XML digest (#596). `tools/ets-sweep/synthetic/capture.py` runs the
  whole flow; `95-offline-oracle.sh` accepts a product XML directory in a row
  and zips it with the stub master; an ungated test fails when a product's XML
  changed since its capture. The synthetic product generator now escapes `-`
  in ids as ETS does (`NEST.2DLIGHT`).
- CI replays the synthetic products' committed ETS captures on every push,
  with no vendor data (#596): the offline oracle `--check` over
  `captures/synthetic/rows.txt`, knx-sim's calibration replay of each capture
  against the memory image ETS wrote (`image.json`), and the flash-then-plan
  sim loop over the synthetic catalogue in the `sim-conformance` job.
- `tests-support/synthetic-products/`: fabricated `M-00FA` products for
  checking bussard, knx-sim and ETS against each other without vendor data
  (#596). A TOML spec per product renders deterministically into committed
  product XML (`generate.py`, stdlib Python), zipped on demand with a stub
  `knx_master.xml`; `bussard-prod` and knx-sim read every product in an
  ungated test. The first product, `syn-minimal` (07B0, merged procedure, two
  parameters, two objects), is the baseline the others derive from. The VM
  signer (`tools/ets-sweep/synthetic/sign.py`) now puts ETS's own master data
  in place of the stub, which ETS 6.4 refuses on import.
- `tools/ets-sweep/synthetic/` clones the KNX Virtual DA.tp into a renamed
  `M-00FA` product and signs a fabricated `.knxprod` in the ETS VM with ETS's
  own signing library (`sign.py` plus our `signer.cs`, compiled there), so ETS
  can import products of the synthetic catalogue (#596).
- The `calc-input` run variant of `syn-param-calculation`: with the
  calculation's input changed in ETS, ETS downloads the computed outputs;
  bussard does not run calculations yet (row `expect=differs`, #427).
- The `links` run variant of `syn-minimal`: two addresses on the switch
  object, one on the status object. bussard's tables and descriptors match
  ETS's (#478, #540).
- The `no-ga` run variant of `syn-minimal`: with no group address linked ETS
  loads both tables with a count of 0 and completes them, as `bussard flash`
  does (#542). The ETS driver's object table, link and parameter editor flows
  now work on the synthetic products.
- The `other-app` run variant of `syn-s7-0705` and `syn-s7-0701`: another
  synthetic application of the same mask loaded first. ETS runs no
  pre-download unload pass there either (#488).
- The `partial` run variant of `syn-minimal`: a parameter changed in ETS and
  ETS's partial download, compared with `bussard flash --parameters-only` in a
  knx-sim that replayed the first download; identical, load control included
  (#543, #490).
- Run variants of the synthetic products (#604): `capture.py --variant` runs
  several ETS downloads in one knx-sim session and commits the last one with
  its base. The `reload` variant of `syn-s7-0705` and `syn-s7-0701` shows that
  ETS runs no pre-download unload pass on a device that holds the same
  application (#488). The offline oracle gained `state=loaded`, a per-row
  model template (`dir=`) and `run=params`; knx-sim's calibration replays a
  variant's base first.
- The synthetic product `syn-secure` ("Nest-guard lock", `NEST-GUARD`, #604
  row 18) is `syn-minimal` made KNX Data Secure capable: `IsSecureEnabled`
  with room for 4 group keys and 4 sender addresses. bussard imports it with
  those capacities, and knx-sim builds it as a factory-fresh secure device
  with a synthetic FDSK and serial number. A factory-state sim device now
  keeps the security table sizes its product declares. `capture.py` captures
  a secure product through the sweep's secure project (#423); the capture
  itself is still pending.
- The product-data index covers 413 more product databases from Siemens,
  Elsner, Ekinex, Weinzierl, Dinuy, ABB, Busch-Jaeger, Enertex, Arcus-EDS,
  Intesis, Jung and Theben (#608). An entry served inside a ZIP names the
  `.knxprod` in it (`inner`), and `import-product --order-number` stores that
  file instead of the ZIP.
- The safety net around an apply is in chat (#717): `knx_backup_device` and
  `knx_reconstruct_device` (default tier, read-only on the bus, not in
  `--passive`) back devices up and diff a device's tables against the model;
  `knx_restore_tables` and `knx_restart_device` (programming tier) write a
  backup's link tables back with `knx_apply_device`'s write and read-back, and
  restart a device in the form ETS uses, each after the human's yes. They call
  the `bussard-service` functions `bussard backup`, `reconstruct`, `restore`
  and `restart` use.
- `bussard keys add-certificate` enters device certificates (the 36-character
  FDSK labels) into the key store, from the terminal without echo or with
  `--stdin`. The label's serial number selects the device; a serial no device
  has yet is kept and attached when `bussard assign` reads it off a device. A
  different key already held for a serial is a conflict and is never
  overwritten. `keys show` lists the unassigned certificates and the
  secure-capable devices without a factory key. Every surface enters labels
  through `bussard_service::enroll_certificate` (#728).
- `bussard keys enroll` takes KNX Secure device certificates from a phone
  (#729): it prints a link, its QR code and a fingerprint, and one line per
  label the phone scans. The label travels end to end encrypted (X25519,
  HKDF-SHA256, AES-256-GCM, `dev/enroll-protocol.md`) through a mailbox relay
  named by `--relay` or `[enroll] relay` in `bussard.toml`; the page's server
  and the relay see only ciphertext, and no key reaches the output. bussard
  also carries an in-process relay with the same API for tests and local
  mode. Each label is stored as `keys add-certificate` stores it (#728).
- The certificate enrolment page for the phone, `https://bussard-relay.tmbo.dev/enroll/`
  (#730): it opens the link `bussard keys enroll` shows, displays the session
  code, scans certificate QR codes with the camera (`BarcodeDetector`, or the
  vendored jsQR on iOS) or takes the typed 36 characters with the same
  normalization and check as bussard, sends each certificate encrypted to the
  relay, and shows bussard's result per label. Serials stay visible, keys are
  never shown again after sending.
- `services/enroll-relay/`: the hosted relay for certificate enrolment as a
  Cloudflare Worker with one Durable Object per session, implementing the
  Relay API of `dev/enroll-protocol.md` (#731). Its API cases
  (`test/cases.json`) are shared with bussard's local relay. Not deployed yet.
- Certificate enrolment over MCP and in local mode (#732): the tools
  `knx_enroll_certificates` (returns the link and the fingerprint) and
  `knx_enroll_status` (serial, address, name and status per label) run the
  `bussard keys enroll` session in the server process; no tool input or
  output carries a label or a key. `bussard keys enroll --local` and
  `local: true` serve the enrolment page and the relay on 127.0.0.1, one
  origin, for a browser on the same computer without a hosted relay.
- `bussard keys enroll` defaults to the hosted relay
  `https://bussard-relay.tmbo.dev` (`--relay`, then `[enroll] relay`, then
  the default); `--relay` is no longer required (#732).
- `knx_import_file` imports from chat what `bussard import`, `import-product`
  and `keys import` import at the terminal, chosen by the file type: a
  `.knxproj`, `.bussard` bundle or `.json` dump into the model, a `.knxprod`
  into the product store, a `.knxkeys` into the key store, or vendor product
  data by order number (#743). Downloading vendor data needs `download: true`;
  a `password` argument is never echoed, and no result or log line carries key
  material. Withheld by `--no-model-edits`.
- `knx_export` writes the bundle, the group plan for ETS, the keyring or the
  handover documentation, as `export`, `export-groups`, `keys export` and `doc`
  do (#744). `knx_export_bundle` stays as the bundle form under its old name.
- `bussard mcp --dir <empty folder>` starts in an onboarding state with `knx_setup` and `knx_bus_status`: `knx_setup` finds the gateway, writes the model and imports the ETS export as `bussard init` does (product data downloads only with `download: true`, the project password from `.env` or an argument it never repeats), then the server registers its full tool set and tells the client the tool list changed. `init` and `knx_setup` share one setup in `bussard-service` (#745).
- The MCP server keeps one job table for every tier, and `knx_job_status {job}`
  (registered in every tier, `--passive` included) reads any job: its `step`,
  the `question` it waits on, `done` and `result`. `knx_apply_status` keeps
  its name and payload (#746).
- `knx_find_devices` scans a line from chat, as `bussard scan` does, and runs
  as a job of the server's job table: mask, manufacturer and order number per
  device, names first, with a one-sentence summary and the devices found so
  far while it runs. `knx_show_device` with `live: true` adds what `bussard
  status <ia>` reads over the bus: identity, and for an IP interface its IP
  settings, tunnelling addresses and state. Both only read and are omitted or
  refused in `--passive` mode (#747).
- `knx_plan_device`, `knx_apply_device` and `knx_reconstruct_device` take
  `line: "1.1"`, the MCP form of `plan --line`, `apply --line` and
  `reconstruct --line` (#748). Each runs through the function the CLI calls,
  now in `bussard-service` (`line`, `reconstruct_line`). A line apply is one
  job with one plan digest over the line; every device is backed up, written
  and verified by its own read-back, and the result lists each device.
- `knx_add_device` adds a new device from chat, the flow of `bussard adopt`
  (#749): it asks the human to press the programming button, identifies the
  device (serial, mask, order number), names the address and the product data
  it would fetch and returns a `plan_digest`; after the human's yes (and a
  separate `download: true` for vendor product data) it writes the address,
  reads the device back at the new address and writes the device file and its
  lock entry. The assign and adopt flows moved into `bussard-service`, so
  `bussard assign`, `bussard adopt` and the tool run the same steps.
- `knx_apply_device` loads the application program `bussard.lock` pins when a
  device runs another one or none (#750). `knx_plan_device` says in its
  sentences that the application must be loaded and what it replaces, and one
  yes to its digest runs the load, the read-back and the lock update as one
  job. The flash flow (pre-flight, freshness decision, download with its
  read-back, lock update) moved from the CLI into `bussard-service`, and
  `bussard flash` and the tool both run it.
- `knx_replace_device` replaces a dead device from chat, as `bussard replace`
  does (#751): a backup snapshot of the device file and its lock record, the
  press-the-button question, the identity check against the device file and
  the lock, then after one yes the address, the application, the model's
  parameters and links with their read-back, and the record. The flow moved
  into `bussard-service` as a step machine both surfaces run.
- `bussard.lock` records each device's serial number (`serial_number`, lock
  version 4) when `adopt`, `assign`, `scan` or `describe` reads it, so
  `bussard keys add-certificate` and the phone enrolment session match a
  certificate to a device ETS never saw and report its address and name. A
  certificate entered before its device was read is attached to it in the key
  store as soon as one of those commands reads the serial. `describe` shows
  the serial. A lock without serial numbers is still written as version 3
  (#752).
- `knx_commission_line` commissions a line from chat, the flow of
  `bussard commission` (#753): one yes for the line, then per device it names
  the device to press, checks the pressed device's order number against the
  model, writes the address, reads the device back and returns the label text.
  A different product, no device or several devices pause the job for the
  human's retry, skip or stop. The commission flow moved into
  `bussard-service`, so the CLI and the tool run the same steps; the read-back
  now also fails a device whose serial or mask differs from the one identified.
- `knx_add_device` takes `product`, a path to the device's `.knxprod`, as
  `bussard adopt --product` does: imported into the product store first and
  used as the device's product data (#779).
- `bussard keys enroll` explains how the labels travel (phone, relay, key
  store; in `--local` mode nothing leaves the machine) with a link to the
  docs, highlights the session code to compare with the phone, and ends with a
  summary and the next steps that apply. `knx_enroll_status` returns the same
  `summary`, `tally` and `next_steps` (#784).
- `import` and `import-product` keep the manufacturer list of the ETS master
  data in `products/manufacturers.toml`; `scan`, the other commands and the MCP
  tools name every manufacturer ETS knows, and an id no list knows reads
  `unknown manufacturer (0x0048)` (#788).
- The enrolment page comes back as the same phone after a reload or a
  network switch: it keeps its phone key for the session in IndexedDB as a
  non-extractable key (deleted when the session ends or after 4 hours),
  shows the earlier results again, and shows "Reconnecting…" while it
  retries (#796).
- `knx_setup` and `knx_import_file` take the ETS project password from a
  form bussard serves on this computer when the chat app supports URL
  elicitation, so the password never passes through the chat. bussard
  stores it as `BUSSARD_PROJECT_PASSWORD` in the `.env` next to the project
  folder, creating the file with mode 0600, and asks again on the page when
  it is wrong (#818).
- `knx_viz` opens the `bussard viz` page from chat (#821): the MCP server
  serves the page itself and returns its URL. The page reads the server's
  own project and its one bus connection, so it takes no extra tunnelling
  slot, and it is read-only in every tier, `--passive` included.
  `bussard mcp --viz-listen <ADDR>` fixes its address.
- Docs: diagrams on How bussard works, The assistant, KNX Secure, Exchange
  with ETS and Work with an integrator; screenshots of the password form,
  the phone page and the viz page (#852).
- The product-data pointer index grows by 761 entries found by diffing baccata's
  product list against it: Hager, Berker, Gira, Schneider Electric (Merten),
  GVS, Hugo Müller, IPAS, ise, TAPKO and a long tail of smaller vendors are new,
  and Zennio, B.E.G., MDT, Jung, Weinzierl, STEINEL, Siemens, EAE, Theben and
  Lingg & Janke fill their gaps (#865).

### Changed

- Smaller and more forgiving MCP answers about parameters (#304).
  `knx_set_parameter` takes a parameter key in every shape
  `knx_show_device` shows: the bare key, the key behind its page or channel
  handle (`universalkanal-c4-funktion.helligkeitsschwelle`), `key@reference`
  and the bare reference. Its `channel` takes a page handle as
  `knx_show_device` does, and an unknown key is refused with the three
  closest keys on the device and the page each sits on. A scoped
  `knx_show_device` lists the other pages one line each, leaves out
  `how_to_change`, and returns the enable detail of the inactive pages only
  with `inactive: true` (about 30 KB down to under 8 KB on a Meteodata).
  Unscoped, a page whose enable chain repeats an earlier page's lists only
  its own switch plus `also_needs`. `knx_validate` returns errors and
  warnings by default, infos with `severity: "info"`, takes `address` and
  `group` filters, and always counts every severity.
- The partial parameter write does what ETS's download does (#290, owner
  decision, option b): `apply`, `flash --parameters-only` and
  `knx_apply_device` compare and write only the octets a parameter is placed
  in under the current configuration (reached by the Dynamic section, or a
  hidden parameter the application downloads), plus device-managed octets
  alongside another write. An octet no reached parameter covers keeps the
  device's value; when it differs from the model's image the plan lists it in
  `octet_ranges` with `written: false` and the "ETS does not write this octet
  in a download" sentence, and it is not counted in `parameter_octets`. On
  1.1.18 the stale extension-module selectors `_AppInstanz 51/52` (offsets 165
  and 168, gated by `P-388`) are now listed and left alone, as the 2026-09-18
  ETS capture shows ETS skipping them. The full `flash` is unchanged (it
  allocates with fill); the 16-row offline oracle is byte-identical to main.
- `knx_apply_device` runs the write as a job (#289): the pre-flight (gates,
  digest, identity, snapshot, backups) runs in the call, the write in the
  server. A write that ends within 20 s still returns the full result
  (`started: false, done: true`); a longer one returns `started: true` with a
  `job` id, and `knx_apply_status {job}` reports progress and the final
  result. `knx_last_apply {address}` returns a device's latest job, also from
  the record kept in `.bussard/history/<snapshot>/apply-result.json`, so a
  reply lost to the client's 60 s call budget or a server restart is
  recoverable. One apply per server at a time; a second call is refused with
  the running job's id. The CLI `apply` is unchanged.
- Device-managed parameter octets (`Access="None"` runtime values such as a
  Download-Flag) no longer make a plan non-empty (#289): a plan whose only
  difference is such octets is `noop` / "nothing to write" in `bussard plan`,
  `bussard apply` and `knx_plan_device`, and they are not written on their
  own. They are still written alongside a table or parameter write and still
  listed in `octet_ranges` with their role.
- An octet attributed to a parameter the download does not place (the
  Dynamic does not reach it, the image keeps the segment fill) is explained
  as one ETS does not write: "ETS does not write this octet in a download; a
  full download leaves the segment fill (0x00) there; the device holds
  <value> from an earlier state" (#289, from an ETS capture of 1.1.18). The
  "project changed" note stays for a selector the download writes.
- `knx_plan_device` and `knx_apply_device` push parameter values too (#274),
  so a change made in a chat reaches the device without a terminal step. The
  plan reads the parameter memory with the product data `bussard.lock` pins,
  lists each differing parameter by key, vendor text, device value and model
  value with one sentence, and its digest covers the parameter image; the
  apply writes only the differing octets after the tables and reads them
  back, over KNX Data Secure for a device the keyring lists. The gates are
  the link write's, plus the identity verdict (a drifted device needs
  `bussard flash`). Without the product data the plan says why, with the
  recovery line, and writes the links only. The parameter engine (product
  resolution, read-back, plan builder, parameter-only download) moved from
  the CLI into `bussard-service` and `bussard-download`, so `bussard apply`
  and the MCP tier run one implementation. The guidance, the tool
  descriptions and the docs no longer send parameter writes to the CLI.
- The MCP server's guidance follows its tiers (#272). The server
  instructions describe what it does at its tier, which tools push, and what
  still needs the CLI (`flash`, `adopt`, `replace`, `commission`) or ETS
  (Secure activation, settings the product model does not expose). A model
  edit's `next_step` names the device and, with `--allow-programming`, says to
  push the links with `knx_plan_device` and `knx_apply_device` instead of
  "a human runs `bussard plan`". `knx_project_summary`
  gains `server` and `capabilities`, `knx_show_device` gains `how_to_change`.
- `knx_add_link` and `knx_remove_link` take the device's individual address
  as `address`, like every other MCP tool, instead of `device`. The Claude
  remote-devices bridge reserves `device` for its own routing and strips it
  from forwarded calls, so those calls arrived without the field. (The
  `device` alias was removed later, see Breaking changes.)
- Product data is resolved from the lock and the store everywhere (#228):
  `replace` no longer requires `--product`, `flash --product <export>` needs
  no `--application` when the lock pins the program, and `adopt` stores an
  export it is given. A `--product` / `--application` that contradicts the
  lock (another archive hash, another application) is refused by `flash`,
  `apply` (new `--force`) and `replace` unless `--force`, which pins the
  archive; `plan`, `reconstruct` and `flash --dry-run` warn.
- One identity verdict across the management commands (#228): `describe`,
  `plan`, `reconstruct`, `apply`, `restore`, `backup` (manifest `identity`),
  `replace`, the `flash` pre-flight, `scan`, `assign` and `audit --live` print
  the same `identity of <ia>: …` line (and JSON object) against the lock.
  `apply` refuses a drifted device, `replace --no-flash` refuses a
  replacement with another application, and `commission --apply` refuses
  through `apply`.
- All management commands read or refresh the device facts through one
  helper: `backup` now seeds its connection from them, `commission` and
  `replace` drop the facts of the address they re-assign, and `scan`,
  `assign` and `audit --live` drop facts stored under another mask (#228).
- Product data is retained model data in `<dir>/products/` (#228): vendor
  `.knxprod` files as downloaded or supplied, and each application program
  `import` and `import-product` extract once from an ETS export into
  `<application-id>.knxprod` (new `bussard_prod::extract_from_project`; the
  flash image is byte-identical to reading the export). `bussard.lock` pins
  each archive and every use verifies its SHA-256. bussard no longer
  git-ignores product data: committing `products/` is the owner's decision.
- A missing or changed pinned archive refuses `flash`, `apply` (parameters)
  and `commission --flash` before any bus access, naming the recovery step
  for its origin; `plan` and `reconstruct` warn and read the links only.
  `flash --product <file> --force` makes the file the device's pinned
  product data (#228).
- The product models moved to `.bussard/models/` and regenerate from
  `products/` whenever the directory is missing; `.bussard/` now holds only
  regenerable data. The old `<dir>/models/` is not read. The first command on
  an older model directory moves `vendor/*.knxprod` into `products/` and pins
  them (#228).
- The lookups that opened every cached archive to find an order number
  (`commission`, `flash`, `plan`, `apply`, `adopt`) and the models-based
  "is it cached" check now read the lock's `[[product]]` entries (#228).
- bussard is pre-release: a lock of another version than 2 is refused with
  the fix (`bussard import <export> --dir <dir>`) instead of being upgraded.
- `bussard.lock` is now version 2 (#228). It records every product-data
  archive the model depends on as a `[[product]]` entry (content hash, file,
  size, origin, applications, order numbers), and each device's
  `product_sha256`, `application_id` (the `PID_PROGRAM_VERSION` it must
  report) and `application_version`. `import`, `import-product`, the
  product-data download and `adopt` pin what they read. bussard is
  pre-release: a lock of another version is refused, and `bussard import`
  regenerates it.
- Device identity is compared with the lock: `describe` and `reconstruct`
  report an `identity` verdict (`match`, `drift`, `unmodelled`), `plan` warns
  on drift, `apply` refuses a device whose application id or mask differs
  from the lock before any write, and `audit` gains a product-data section
  (unpinned devices, missing or changed archives, drifted facts). `flash`
  refuses a cached archive whose hash differs from the pinned one;
  `--product` stays the explicit override (#228).
- New validation warnings E032 (a product link without a `[[product]]`
  entry) and E033 (a pinned archive missing from the model) (#228).
- One global option group (#228): `--dir`, `--gateway`, `--routing`,
  `--keyring`, `--json`, `--allow-remote-gateway`, `--skip-address-check` and
  `--refresh-facts` are declared once, print once under "Global options" in
  every `--help`, and go before or after the subcommand. They replace the
  per-command copies (`--dir` alone was declared 39 times). `--yes`, `--force`,
  `--dry-run` and `--plan` stay per command. A command without JSON output now
  refuses `--json` with a message instead of a clap error; read-only commands
  accept and ignore `--allow-remote-gateway`.
- One confirmation rule and one output contract (#228): see Breaking changes
  above. `read`, `write`, `assign`, `show` and `undo` gain `--json`; the
  missing-keyring, missing-password and real-gateway opt-in messages have one
  wording each, shared by the CLI, the MCP server, `viz` and the libraries
  (`bussard_service::guidance`); the `--force` and `--full` help texts name
  the refusal they override.
- Without `--dir`, a command finds the model directory itself: `.` when it
  holds `bussard.toml`, else `./knx`, else the nearest parent holding
  `bussard.toml` or `knx/bussard.toml`. Commands now work from inside the
  model and its subdirectories. `init` and `import` never search upward
  (#228).
- Breaking: the default model directory is the current directory, not `knx`.
  When discovery finds nothing, every command works in `.`, and a directory
  without a model file reports `no model in the current directory <path>`
  with `bussard init`, `bussard import <export>` or `--dir` as the way out.
  `init` and `import` write into `.` without `--dir`; in a non-empty
  directory that holds no model they ask first (naming the entry count and a
  model in `knx/` below), `--yes` answers, and without a terminal they refuse
  with the standard sentence. `init` there keeps existing files and extends an
  existing `.gitignore`. Pass `--dir knx` (or `cd knx`) for the old layout.
- New environment variables `BUSSARD_DIR`, `BUSSARD_GATEWAY` and
  `BUSSARD_KEYRING`, with the precedence flag, then environment, then
  `bussard.toml`, then discovery. They only select; none of them can permit a
  write, and `BUSSARD_ALLOW_REAL_GATEWAY` is unchanged (#228).
- bussard reads its `BUSSARD_*` variables from a `.env` file too, so the
  passwords and the gateway no longer have to be exported before every
  command, the MCP server included (#251). The first of `<model dir>/.env`,
  the `.env` next to the model directory and `./.env` is read, never merged;
  `BUSSARD_DIR` alone comes from `./.env` before the model directory is known.
  An exported variable wins, even when empty. Only `BUSSARD_*` keys are read,
  no value is printed (`-vv` and `--timing` name the file), and
  `BUSSARD_NO_DOTENV=1` skips it. The campaign scripts apply the same file,
  so `set -a; . ./.env` is no longer needed before them.
- `--keyring` is now accepted by `adopt` and `test` (tunnel only, as
  `connection.keyring` already was), and `assign --keyring --tool-key` opens
  the secure tunnel with the given keyring as documented.
- The model moved from YAML (`bussard.yaml`, `groups.yaml`, `links.yaml`,
  `devices/*.yaml`) to TOML plus the generated `bussard.lock`. Links now live
  in the device files. The YAML files are not read any more: bussard refuses a
  directory that holds only them and asks for a re-import. Product models
  under `models/` keep their YAML format.
- On top of the new format: `apply` is the one write verb, writing whatever
  differs (tables, parameters or both) after one plan and one confirmation,
  and refusing to run when `--plan <hash>` no longer matches the device's live
  state; `import` and `apply` run validation first; `adopt` and `import` fetch
  missing product data by order number through the pointer index; a group
  address a device file uses that `groups.toml` does not define is declared
  on first use, by `import`, `apply` and the MCP edit tools; `groups reserve`
  allocates group addresses for a room and function without a plan file,
  replacing `scaffold`; `bussard device` shows what a device offers, in its
  device file's words; and `init` accepts a project file (`init [PROJECT]`).
  `docs/reference.md` describes each of them.
- The workspace is 16 crates on Rust edition 2024 with an MSRV of 1.88, checked
  in CI across all targets (#85, #87, #136).
- The gateway gate, the protected-GA check and the checked group write live
  once in `bussard-service`, which the CLI, the MCP server and viz all call
  (#86).
- Every device command (`apply`, `assign`, `adopt`, `backup`, `commission`,
  `flash`, `line`, `plan`, `reconstruct`, `replace`, `scan`, `audit`) opens
  its management sessions through `BusService::with_l4` / `with_device`, so the
  tunnel-reconnect wait, the connect retry on a gateway link loss and the Data
  Secure layer apply to all of them. The frames on the bus are unchanged (#86).
- One ETS-XML, ZIP and PBKDF2 primitive layer serves the project, product and
  ETS importers (#36, #83).
- `flash` and `apply` use one tunnel per command, negotiate the maximum APDU
  length, and poll for a device after a restart instead of sleeping (#122,
  #136).
- `scan` rules out an absent address from the interface's negative
  `L_Data.con` (22 to 45 ms) instead of waiting out 2 × 1.5 s of ACK timeout. A
  gateway that sends no negative confirmation keeps the timeout path. A mock
  line of 256 addresses with 5 devices drops from about 12.5 minutes to 8 s.
  Present devices see the same frames. `scan --json` gains a `timing` object
  with per-address probe times and outcomes, and stderr ends with a summary
  of how each absent address was classified (#45).

- A load-state change (`Unload`, `StartLoading`, the `LdCtrlRelSegment`
  allocation, `LoadCompleted`) on System B and on System 7 `0705` is
  confirmed by the one-octet state the device returns in its answer to the
  PID 5 write, as ETS does, instead of a separate PID 5 read. A device that
  answers without a state octet, with the event echoed back or with another
  state (KNX Virtual's `Loaded` after `StartLoading`) is read back as before;
  `0701` keeps its per-event status reads. The written frames are unchanged.
  A System B object costs 5 requests instead of 10 for unload, open,
  allocate and complete (about 1 s less per object at 200 ms per request)
  (#211).

- The sparse writer of a filled System B segment (and of a parameters-only
  download) joins two runs across a gap of up to 100 octets when that saves a
  memory-write request (`BUSSARD_SPARSE_MERGE_GAP`, was a fixed 4). The
  joined gap is written with the octets the device already holds, so the
  image is unchanged. The 1.1.5 parameter image (19155 octets) goes from 71
  to 22 writes and the 1.1.12 image from 23 to 6 at the 215-octet Data
  Secure chunk; ETS writes 197 and 38 (#210).

- `flash` polls a rebooting device every 500 ms with a 2 s answer window
  instead of a fixed 1.5 s wait, a 400 ms window and a 1, 2, 4, 8 s backoff
  on Data Secure devices. After a confirmed restart the first probe goes out
  0.5 s after the reported process time; a bare `A_Restart` keeps the 1.5 s
  quiet period. A negative `L_Data.con` counts as "not up yet". After the
  factory reset the device is probed from +3 s to measure its readiness, the
  8 s process time is still waited out. `flash -v` appends the readiness per
  restart to its timing line. On the mock with the 1.1.5 reboot pattern the
  restart phase ends at +3.0 s instead of +9.7 s (#212).

- Start-up before the first bus frame is cheaper (#214, #215). `flash`,
  `plan`, `reconstruct` and `adopt` read the product archive's table of
  contents and parse only the selected ApplicationProgram (by
  `--application`, the model's application reference or the order number)
  instead of every program in it; the order-number match against `vendor/`
  parses none. The table of contents and each parsed program are cached
  under `.bussard/products/`, keyed by the archive's SHA-256 and the bussard
  build (`BUSSARD_PRODUCT_CACHE=off` bypasses it). The model is parsed once
  per command, and a keyring is decrypted once per process or MCP server
  (previously once per MCP tool call); an edited file is read again in both
  cases. `--timing` lists the start-up phases (model load, product parse,
  keyring, time to the tunnel request, tunnel) and the parse and decrypt
  counts. The images and property writes are unchanged (offline oracle on
  both row sets). On the mock with the 15 MB house export (30 programs, dev
  build, best of 5): `flash --dry-run` 5.8 s to 0.74 s (0.43 s with the
  cache), `reconstruct --product` start to first frame 5.6 s to 0.65 s
  (0.34 s with the cache); `describe` is unchanged at 0.08 s.

- The verification after the terminal restart reads what decides: the
  application object's type and its load state. The other objects keep the
  `Loaded` their `LoadCompleted` confirmed before the restart, and a written
  segment's memory sample is skipped when its MCB check (`PID_MCB_TABLE` CRC
  over the streamed image) passed before the restart. A segment without a
  passed MCB check, such as an absolute `WriteMem` or an advisory check, is
  still sampled, and an application that is not `Loaded` after the reboot
  gets the full verification as before. On a 4-object System B flash with
  MCB checks this is 2 reads instead of 9. On System 7 `0701` the LSM status
  octets are read with one memory read instead of one per LSM, falling back
  to per-LSM reads when the device refuses it (#215).

- Every workspace crate now opts into the workspace lints, so
  `clippy::unwrap_used` is denied everywhere. The tests of `bussard-project`,
  `bussard-ets` and `bussard-prod` return `Result` and use `?` instead of
  `.unwrap()` and `.expect()`; `Option`s and expected errors fail with a named
  message (#208).
- The `A_PropertyExtDescription_Response` layout and the ascending order of a
  multi-entry security individual address table (PID 54) are now confirmed by
  the standard (KNX 3/3/7 §3.4.3.2, KNX 3/5/1 §6.3.8.3 and §6.3.8.5); the
  description's maximum element count is decoded as the two full octets the
  standard gives (#197).
- Change sentences (`bussard status`, `history`, `show`, `undo`, `diff` and
  the MCP edit results) name a group address or device by its name alone; the
  address follows only when the name is not unique or the group address is
  protected, and an unnamed one still reads as its address (#306). A com
  object without a name of its own is called by its vendor text, and a
  channel without a name or vendor text is left out. The Home Assistant
  automation sentence and its default alias use group-address names. The
  technical restart line of `knx_restart_device` moved from `summary` to
  `outcome`.
- `knx_model_lookup` lists a capability repeated on several channels of a
  device once, with `channels`, and one repeated on devices of one
  application once, with `also_on`; a device whose com-objects send the
  measured value the query names (DPT 9.004 for "Helligkeit") comes first,
  with those objects in `sends`. `knx_get_device` returns the keyed
  parameters only and counts the ETS-internal `hidden@`/`label@` values in
  `hidden_parameters` (`technical: true` includes them; 16.7 KB to 10.3 KB on
  a 16-fold binary input) (#311).
- Each product model is parsed once per process and cached as JSON under
  `.bussard/model-cache/`, kept in sync with its YAML by length and mtime
  (#339). On the reference house a debug `validate` drops from 16.3 s to
  about 2.3 s once the cache is warm, `status` from 11.2 s to about 2 s. The
  capability lookup uses the same cache; `.bussard/lookup/` is no longer
  written and can be deleted.
- `bussard history`, `history --json` and MCP `knx_history` read each
  snapshot's one-line summary from its manifest instead of loading two models
  per snapshot (#340). The summary is computed when the snapshot is taken; a
  snapshot from before this change gets it computed once on the first listing
  and written back.
- The MCP server runs the source-address probe once per tunnel instead of on
  every `knx_plan_device`, `knx_apply_device` and `knx_restore_parameters`
  call (#341). The second plan on one connection no longer waits the 600 ms
  probe window; a reconnect or a re-established tunnel probes again, and an
  occupied address still refuses every call. CLI commands open a fresh tunnel
  each time and still probe once per command.
- Product models are format 6: they no longer carry `blocks`, `parameter_when`
  and `ref_values`, and a parameter's `default` is its own value (a ref's value
  sits on the ref). The ETS pages are derived from the Dynamic tree when the
  model loads, with the same titles; models regenerate from their archive on
  the next command. The plan no longer calls a stored value "ignored" when the
  flash writes it as the source of an `<Assign>` (#345).
- The Dynamic evaluator (`evaluate_dynamic`) and its tree types moved from
  `bussard-ets` into `bussard-model` behind a `DynamicSource` trait, which the
  parsed product XML implements (#345). `bussard_ets::dynamic` re-exports it,
  so download, flash and plan behave exactly as before: the parameter images
  of every fixture application are byte-identical. The evaluation also lists
  every reached channel and parameter block, and a new value-free `RefIndex`
  records where each parameter and object ref sits and behind which `<when>`
  gates; nothing reads either yet.
- Product models are format 5 (#345): each one carries its program's Dynamic
  tree (`dynamic`, `module_dynamics`), its unions, every parameter ref with its
  value and `Access="None"` mark, and the parameters' `base_value` and integer
  width, so the Dynamic evaluator runs over the model as it runs over the XML.
  Models of an older format regenerate from their archive at the next command;
  the device view is unchanged for now.
- `bussard device`, `knx_show_device`, the parameter key resolver, the
  `set_parameter` refusal and the plan's "ignored" notes now take page and
  channel activity, parameter and object placement, values and conditions
  from the one Dynamic evaluator the flash uses, with the same values (#345).
  The view no longer marks a page active because the lock indexes a
  parameter on it. Internal parameters (`Access="None"`) are no longer
  offered as keys.
- More than one sending object on a group address is info I006, no longer
  warning W006 (#348): it is normal in KNX and ETS does not warn about it.
- Verified means read back and compared, for every write (#349). `apply` (CLI
  and the MCP job) ends with a fresh read of the tables, the written
  parameters and, on a secured write, the security object (the PID 53 entry
  count, PID 54 and PID 61), compared with the model; anything left is
  `verified: false` with `readback.leftovers` naming each item, and the CLI
  exits non-zero. A flash's read-back now also compares the links, both table
  sizes and the group-object count, and runs after an unverified flash too,
  so the failure names what differs. `bussard keys export` reads the written
  file back, decrypts it, compares its keys with the store and prints the
  group addresses it carries and the ones it omits. One routine,
  `bussard_service::verify`, serves every surface.
- Regenerating `.bussard/models/` writes only the models of the applications the
  lock's devices pin, parsing each archive once for them (#356). The first command
  in a one-device model of the ABB i-bus archive (407 programs, 159 MB) took 223 s
  and wrote 407 models; it now takes 6 s and writes one. `import` still writes every
  program of the archives it pins.
- `bussard plan` on a large program is faster (#367). The parameter read-back
  evaluates the application's Dynamic section once per set of values and
  shares it between the read-back plan, the decode, the group-object check and
  the octet attribution; a pinned archive is hashed once per process (keyed by
  path, size and mtime); the parsed-product cache is decoded from memory with
  the JSON parser optimized in debug builds; and a plan with nothing to write
  skips the octet attribution. On a one-device model of the ABB
  `M-0002_A-A0ED-10-9B4E` program against knx-sim, a debug `plan` with
  nothing to write drops from about 6.0 s to 2.4 s with the 159 MB vendor
  archive. `plan --timing` shows the new `parameter read` phase. Nothing
  written to a device changes. Old `.bussard/products/` entries are no longer read and are
  pruned as usual.
- The offline oracle compares PID 54 (the security individual address table)
  by sender address and reports differing sequence numbers as a note
  (`equal (sequence numbers differ: ETS …, bussard …)`), and compares PID 53
  (the group key table) per entry, naming the group whose key differs or is
  missing (`0/0/6: key differs`). Both sides hash each key with a salt drawn
  per run, so no output holds a key or a hash of a bare key (#378).
- The offline oracle compares read-compare downloads (mask 0701) against the
  octets ETS read and did not write (`confirmed/` in `knxtrace image`),
  reports their coverage and every mismatch next to the written figure, and a
  row can require a verdict on them with `confirmed=`. PID 54 is no longer
  redacted, and a sender difference prints both sender lists with their
  sequence numbers (#384).
- knxtrace decodes KNXnet/IP device management connections (#398): the cEMI
  `T_Data_Connected` / `T_Data_Individual` frames ETS sends there and the local
  `M_PropRead` / `M_PropWrite` / `M_FuncProp*` / `M_Reset` services, filed under
  the interface that answered the description, so `ops`, `diff` and `image`
  record a device management write like a bus-level one. The IP Secure
  function properties (`PID_SECURED_SERVICE_FAMILIES`, `PID_SECURITY_MODE`)
  and the type 11 and 17 PIDs are named. `--keyring` is repeatable (the
  exports before and after a key rotation), credential writes (tool key,
  device authentication code, password hashes) are compared with the keyring
  by name only, and each KNXnet/IP Secure session is listed with its verified
  device authentication code and connection type: a secure session itself
  cannot be decrypted from a capture (ephemeral X25519 key). The offline
  oracle rows take `props=VERDICT` to gate the property-write parity of a
  property-only plan.
- The offline oracle counts read-confirmed octets that equal bussard's toward a
  row's coverage when none of the row's read-confirmed octets differs: a mask
  0701 read-compare row whose association-table page ETS only read is compared
  instead of thin (#422).
- `apply` on a System 7 device now loads the tables in the order ETS 6.4.1
  uses for a table-only download and ends with a basic restart, as ETS does
  (#433). It waits for the device to answer again before the parameter write
  and the read-back, so the read-back also shows the write survived the
  restart. The plan's `writes` line says `then a restart`.
- The pre-flight of a loaded System 7 device now reads the resident
  application's id, `PID_PROGRAM_VERSION` of the application object (KNX 6
  Profiles Annex A.2.6), within one second (#481). An id that names another
  application refuses `flash`, `apply` and `plan` by that id; a matching id,
  or a device that does not answer, leaves the decision to the code sample as
  before. The read writes nothing and changes no image.
- A System 7 `flash` of a device that holds no loaded application no longer
  runs the pre-download pass (unload of LSMs 1 to 4, restart, reconnect)
  ahead of the vendor procedure: ETS runs none on a factory-fresh device in
  all 31 System 7 downloads of its sweep (#488). A device with an application
  keeps the pass until a capture series settles ETS's rule there.
- `bussard flash` onto a System B device that already holds the same
  application runs the product's `AppliesTo="par"` load procedure, as ETS
  does: the application segment is allocated without the fill flag (Mode 0),
  an object that reads Unloaded and is not loaded gets no unload, and no
  factory reset opens the download; the group-object table stays when its
  MCB already matches. A device holding another application, or none, keeps
  the `full` procedure (#490). `flash --dry-run --resident FILE` plans
  against a recorded device state, and the offline oracle passes it the
  state ETS read from the capture, so the house rows compare
  `loadctl=identical`.
- Scene numbers (DPT 17.001, 18.001 and the scenes A/B of 1.022) count from 1,
  as ETS and Home Assistant show them (#495, KNX 03_07_02 §3.19 NOTE 9).
  `write 1/0/7 "scene 3"`, `knx_write_group`, the viz and Home Assistant rules
  send the field 2, where they sent 3; `raw 2` sends the field directly.
  `read` and `monitor` print both, `activate scene 3 (raw 2)`.
- knx-sim's devices run a Style 3 transport layer (03_03_04 §5.4.3 with
  AN210) (#511): an out-of-window numbered telegram draws a `T_NAK`, a
  repeated `T_Connect` from the connected client is ignored with the
  sequences kept, one from another client is refused with `T_Disconnect`, a
  connection idle for 6 s closes with a `T_Disconnect`, an unacknowledged
  response is repeated every 3 s up to three times, and `T_ACK`/`T_NAK` from
  the client are honoured. Transport control frames go out at system
  priority. The `l4_strict_drop` device option (or
  `Device::with_strict_l4_drop`) keeps the old silent drop for desync tests.
- A KNXnet/IP Secure tunnelling session runs over TCP only, as the KNX
  standard requires (KNX IP Secure 3/8/9 §2.2.3.3, §2.2.3.6.4). The opt-in
  `--secure-transport udp` is gone (`auto` and `tcp` stay), and an interface
  that advertises Secure but refuses the TCP connect is reported with the
  likely causes instead of a hint to try UDP. knx-sim and the testkit mock
  discard a SESSION_REQUEST over UDP, as TSSK test 2.2.25 expects (#513).
- The refusal of an empty table set in `apply` says that `bussard flash` loads
  empty System B tables, as ETS does, and the docs say what such a device does:
  it reacts to no group telegram (#542).
- `dev/testing.md` explains how ETS, bussard and knx-sim check each other,
  which of those checks need uncommitted data, and the planned synthetic
  product catalogue that would run them in CI (#596).
- The synthetic `M-00FA` products are the appliances of a buzzard's nest: the
  README's Theme section sets the naming rule (`NEST-` order numbers, the
  catalogue section titled "The buzzard's nest"), and `syn-minimal` is now the
  "Nest-side light switch", `NEST-LIGHT`, with every technical value unchanged
  (#596, #604).
- The synthetic catalogue's CI tests scale with the catalogue: the oracle
  rows test checks the rows on four workers and names each failing row with
  its time, the knx-sim flash-then-plan loop runs as four shards, and the
  oracle test passes the resolved Python interpreter to the script (a pyenv
  shim made a row take 18 s instead of 2 s). CI now also runs the synthetic
  product generator's unit tests and `generate.py --check` (#596).
- knx-sim: the `master_reset` device option models a device without the
  Master Reset: `refuse` answers every erase code with error code 2 and runs
  nothing, `basic` runs the request as a Basic Restart without an answer
  (default `supported`). The synthetic capture tooling has a `bare-restart`
  run variant of `syn-master-reset` that uses `refuse`; ETS 6.4.1 fails that
  download with "UnsupportedEraseCode" (#611).
- The synthetic product `syn-s7-pid204` is re-captured (application version
  0x11) against knx-sim with the fixed property description: ETS now writes
  PID 204 on the application object as two 5-octet elements, the same write
  bussard plans, and its oracle row is identical (#692).
- The user documentation matches main before the first release (#702): device
  support lists the current limits (computed parameters, undeclared text
  encodings, System 1 and System 2, Data Secure activation) and states that
  KNXnet/IP Secure tunnelling runs on real interfaces; the reference covers
  the System B manufacturer check, the typed load controls, `reconstruct` on
  System 7, the `describe` factory-key fallback and colour parameters; the MCP
  tool counts and tiers are corrected; the README install section names the
  five release binaries and links the safety page.
- The re-import merge, `import-product` and the keyring export moved from the
  CLI into `bussard-service` (`files`), next to the setup pieces they build on,
  so the CLI and the MCP tools run the same functions; the CLI's output is
  unchanged (#743, #744). The MCP SDK's own log events stop at `info` whatever
  `RUST_LOG` says, because at `debug` it logged each request with its raw
  arguments; bussard's own `tools/call` line still logs every call with string
  values redacted.
- `bussard replace` records the new device's serial number in its
  `bussard.lock` entry, in place of the old one's (#751).
- `knx_apply_device` reuses the device facts its digest check read for the
  table write, the parameter write and the read-back, as `bussard apply`
  does, instead of reading the device descriptor, the maximum APDU length and
  the interface objects again on each connection; an apply over MCP now sends
  the same requests as the CLI (#761).
- `knx_plan_device` no longer refuses to load a self-contained application
  whose links would differ from the project (#779). The plan says the
  application is loaded and then the links are written, one yes covers both,
  and `knx_apply_device` writes the links after the verified download as
  `bussard apply` does, with its own read-back (`links` in the result). The
  result is verified only when that read-back matches the project. The same
  holds for a parameter change that needs a full download.
- The certificate enrolment page is laid out for the phone (#783): the session
  code is confirmed once ("Matches" / "Doesn't match") and then sits as a chip
  in the header; Scan and Type are tabs (the camera runs only in Scan, the
  choice is remembered); a bar at the bottom, kept above the iOS toolbar and
  keyboard, shows a running count and Finish. A new scan flashes green with
  its serial and beeps (mute toggle, remembered); a label scanned again shows
  "already in this session", a bad check flashes red. A flashlight button
  appears where the camera offers a torch (Android Chrome). Rows read
  `saved`, `waiting for device`, `already known`, `conflict`, `invalid`.
- The enrolment page titles each certificate by its printed code
  (`AAFDHW … X4VCNL`) with the serial number below, uses the glossary's
  badges and summary ("6 sent · 1 added · 4 already known · 1 no device
  yet"), ends with "Finished. You can close this page." and the page's own
  count, and checks that the session exists before it asks for the camera
  (#791).
- The shared CLI output style (#792) now covers `status`, `describe`, `plan`, `apply`, `validate`, `audit` and `adopt`: bold headings, aligned tables, plan marks coloured (`+` green, `-` red, `~` yellow), `warning:`/`error:` labels instead of `WARNING`/`ERROR`, a "Next steps" block where a command suggests the next one, and the glossary's words ("your project" instead of "the model", counts such as "4 devices"). `--json` is unchanged.
- One output style for the CLI (#792): `scan`, `keys enroll`, `keys add-certificate` and `keys show` print aligned tables with a dim header, colour by state (`NO_COLOR` and pipes turn it off), one summary line such as `46 devices found · 256 addresses in 52 s · 202 did not answer within 3 s`, and a "Next steps" block. Wording follows the glossary: certificate states read **added**, **no device yet**, **already known**, **conflict**, **invalid**, **failed**; scan shows Product, Serial number, Secure (a lock) and In project, and marks serial numbers saved to your project instead of printing a line per device. `--json` is unchanged except for the human `summary` text of `keys enroll`.
- The sentences the CLI shares with the MCP server follow the glossary (#804):
  validation messages, the identity line ("matches your project", "differs
  from your project"), the KNXnet/IP drift lines, the plan's "matches your
  project; nothing to write", the flash and apply read-back ("compared with
  your project: 2 group addresses, 2 associations") and the adopt Secure
  summary. Diagnostic codes and JSON fields are unchanged.
- The user docs use the glossary's words: project instead of model, certificate,
  factory key, key store, supports Secure and address (#805).
- `knx_enroll_certificates` opens a pairing page in your browser (#809): served
  by the MCP server on 127.0.0.1 under a random path, it shows the session
  code, a QR code of the phone link and the certificates as they arrive. Chat
  apps without URL elicitation can now enrol certificates; the link, the code
  and the page's address never appear in a tool result. Over SSH or without a
  display the tool refuses and points at `bussard keys enroll`.
- Getting-started docs: the install page has one download tab per OS, the
  assistant page registers the server through config files and shows chat
  examples only, the first weekend is half as long, and the watch-the-bus
  page shows the viz page (#819).
- The pairing page is one column of numbered steps, with the QR code and
  the whole phone link (wrapped, with Copy) in step 1. Once the phone joined,
  the first two steps fold into one line and the certificate list leads. The
  assistant only says the page is open and to follow it there;
  `knx_enroll_status` returns counts while the session runs and the list of
  certificates on request (`details: true`) or at the end (#820).
- The landing page shows the everyday workflow as five steps with an example
  chat each (import, watch the bus, change the project, program the device,
  keep it safe), naming the real MCP tools. Its claims now match the docs: four
  MCP tiers including `--allow-programming`, the six write steps, the supported
  masks, and links to the assistant and device support pages (#824).
- Landing page: the "Import your ETS project" step shows the setup in chat,
  with the password form and the product-data question, instead of a
  terminal session (#844).
- The user documentation is rewritten page by page for the owner and the
  integrator: one topic per page, the command first, short sections, a
  "Next steps" footer, and wire-level detail folded into collapsed blocks. The
  command reference is split by command group, the model format into one
  page per file, and Safety into the rules plus separate pages on write
  commands, KNX Secure, the assistant and device support. `dev/docs-guide.md`
  records the style.
- The documentation is split in two: `docs/` holds only user documentation,
  arranged as tutorials, how-to guides, reference and explanation (the Divio
  system), with a new "How bussard works" page; design notes, specs, test
  runbooks and the agent brief moved to `dev/`. Page URLs on the site changed
  accordingly.
- Issue and label conventions documented in `dev/agent-brief.md` and `CLAUDE.md` (type labels, area labels, `needs-capture`, `needs-decision`).
- The design notes cite the KNX Standard 3.0.0 clauses behind the cEMI codec,
  the transport-layer timings and state machine, and the application-layer
  services, and no longer claim a per-chunk read-back on the plain memory write
  path (spec review A, #506, #507, #508, #509, #511).
- The KNXnet/IP and IP Secure developer notes cite the KNX Standard 3.0.0 clauses they rest on and correct three statements: unicast secure sessions are TCP-only (no UDP carrier exists in the standard), the smallest SECURE_WRAPPER is 44 octets, and a tunnelling slot's "authorised" bit read outside a session means "no authorisation required" (#513, #518, #522).
- The Data Secure notes in `dev/knx-secure-spec.md` cite KNX Standard 3.0.0 for
  the SCF, CCM block and MAC layout, the sequence-number rules, the S-A_Sync
  arithmetic, the access policies, the security object's table layouts and
  sort orders (PID 53, 54, 61 now confirmed by the standard, not inferred),
  the load-state dependency and the master-reset effects; the FDSK lifecycle
  and the "secure T_CONNECT" non-goal are corrected (spec review C).
- The maintainer notes on the System B download (`dev/flash-op-coverage.md`,
  `dev/DESIGN.md`, `dev/testing-campaign.md`, `dev/product-model-format.md`)
  now cite the clauses of the KNX Standard 3.0.0 they describe and name the
  findings of the spec review (#540 to #547).
- The System 7 maintainer notes (`dev/system7-spec.md`, the System 7 rows of
  `dev/flash-op-coverage.md`, `dev/DESIGN.md`) are corrected against the KNX
  Standard 3.0.0 text, with the section cited next to each statement: the load
  state machine realisation per mask, the 11-octet record fields, the
  TaskSegment identity, the group-object CONFIG octet, the LSM status octets
  and the verify-mode rules (#524 to #530).
- Design notes and the command, diagnostics and Home Assistant references now cite KNX
  03_07_02 Datapoint Types for the small-APDU rule, the DPT size and sub-type rules behind
  E004 and W005, the 2-octet float and scene-number conventions, and the 1.009/1.019 and
  7.x mappings (#492 to #505).
- The website's top navigation links "Docs" to the documentation site instead of the docs section of the landing page.

### Fixed

- The plan no longer calls a value "ignored" that the flash writes, and
  `knx_set_parameter` no longer refuses a parameter the configuration shows
  (#326). Some conditions in ETS hold through a value the vendor sets on the
  parameter reference itself, not on the parameter. On the Meteodata, C1's
  wind threshold sits behind "Wenn Temperatur" = Windsensor, which only that
  reference value satisfies: `knx_plan_device` said the 8 m/s threshold was
  ignored while the image carried it, and the C4 brightness threshold was
  refused until "Wenn Temperatur" was set by hand, a value ETS never stores.
  The same shape hid values on 1.1.30 and 1.1.39. The product model now
  records these reference values (`ref_values`, model format 4; older models
  regenerate from their archive on the next command), and the device view,
  the plan notes and `knx_set_parameter` read a value in the order the
  download does. A row `knx_set_parameter` adds to the lock carries the
  reference value as its `default`, as an import writes it.
- A plan that needs a full download (`method: flash`) said `writes: nothing`
  and "nothing to do, the device tables already match the model" when only
  parameters changed (#326). It now names the download: `writes: full image
  (segments AS-4800, ...), tables rewritten (unchanged: 12 addresses, 15
  associations)`.
- `knx_set_parameter` refusals no longer carry runs of spaces in the middle
  of a sentence.
- `knx_set_parameter` stored a value on a parameter ref the configuration
  does not show, and nothing ever wrote it (#321). On a Meteodata, a value
  set on the XOR-branch ref of "Eingangsgröße für Eingang 1" while the logic
  channel was at UND was saved, indexed and listed by `knx_show_device` next
  to the shown ref, but the image holds one slot per shown ref, so neither
  the plan nor the flash carried it. Such a set is now refused with the
  branch condition in words, the current value it tests, and the shown ref
  to use instead. A bare parameter id (`P-6823`) or the vendor text names
  the shown ref. `force: true` still stores the value for a branch you switch
  to later; `knx_show_device` marks it `ignored`, and `knx_plan_device`,
  `bussard plan`, `bussard apply` and `bussard flash` list it as "ignored:
  not shown under the current values (needs ...)".
- A System 7 flash now writes every parameter the plan places (#320). The
  writer skipped any octet whose product `<Mask>` byte is `0x00`, even when a
  parameter sat there, so on the Theben Meteodata 140 S the whole C4 page
  (14 of 19 changes in one flash) never reached the device. An octet is now
  written when the mask owns it or a parameter is placed in it; this adds
  exactly the octets ETS writes (on the Meteodata's `AS-4800`, 655 writable
  octets instead of 625) and changes nothing else: the image, the write order
  and the timing are the same, and a masked run that holds no parameter (the
  `0x4000` table region, the tail of `AS-4C00`) is still left alone. The
  parameter-only download and its read-back use the same rule. The job's
  `octets` progress now counts the octets written, not how far the segment
  walk got (that is `segment`).
- `verified` after a flash now means the device matches the model (#319).
  `bussard flash` and the MCP flash job read the parameter memory back on the
  flash's own connection and compare it with the model the way a plan does.
  A parameter that still differs makes the job end `verified: false` with
  the parameter named in `reason` and listed in `parameters.differences`, and
  makes `bussard flash` print it and exit non-zero. Before, `verified` only
  said the load-state machines were Loaded. A plan also says when the model
  sets a parameter the device's configuration does not show ("ignored: not
  shown under the current values"), instead of dropping it silently.

- `knx_set_parameter` refused `universalkanal-c4-funktion.helligkeitsschwelle`
  on a Theben weather station with the same key listed twice as the choice.
  The page holds the threshold twice, once per branch of "Funktion des
  Kanals", and only one of them shows under the current function. Product
  models now record the conditions inside a page for each parameter
  (`parameter_when`, model format 3; older models regenerate from their
  archive), and the key resolver picks the ref the current values show, so
  the page-qualified and the bare key work again and follow a change of the
  function. Only two or more shown refs are ambiguous, and the refusal then
  lists each one once, as `key@reference` with its branch condition in words
  where the page-qualified keys would repeat (#315).
- A healthy System 7 device (mask 0701/0705, such as the Meteodata 140 S)
  could not be flashed without `--force`. `knx_plan_device` refused the
  flash plan with "carries another application (unidentified)", and
  `bussard flash` refused with "an application bussard could not identify",
  while `bussard describe` said the device matches bussard.lock. System 7
  exposes no readable application id, so both gates now judge the device the
  way the parameter read-back already did: every load-state machine the
  application loads must be Loaded and the first octets of each code segment
  must match the product. A device that passes is the same application and
  flashes without `--force` on both surfaces; the CLI says "already runs
  this application" and the MCP flash plan carries the `identity` line and a
  `resident` verdict. Code that differs is refused with the segment and the
  first differing offset, and only then does the message name `bussard
  flash --force`. `--force` still replaces a different or unreadable
  application. The written image is unchanged.
- `knx_set_parameter` refused a parameter on a page that was inactive at
  import, even though `knx_show_device` listed it: after switching on
  "Universalkanal C4", its brightness threshold was "no parameter" in every
  key shape. The lock indexes only what the configuration showed at import,
  and the key resolver looked nowhere else. It now also resolves against the
  product model's pages, so every key `knx_show_device` prints works as the
  bare key, page-qualified, `key@reference` or the bare reference. A bare
  key that several pages share is refused with the page-qualified keys to
  pick from, instead of silently taking the indexed one. Setting such a
  parameter adds its lock entry, so the device file names it like its
  neighbours. An unknown reference is refused as "no parameter with
  reference ... in its application" instead of a list of unrelated near
  matches, and a near match on a page the lock does not index says it is at
  its default.
- The inactive-page hint of `knx_show_device` and `knx_model_lookup` said
  "needs `bussard flash <ia>`" even on a server that flashes through
  `knx_plan_device` and `knx_apply_device`. The model now says what kind of
  push it is, and the server and the CLI each say how at their end (#310).
  Scoped page lines read "1 parameter, 1 object" instead of "1 parameters,
  1 objects", the "an apply is running" refusal lost a run of spaces, and the
  how-to no longer says plan, apply and flash are CLI-only.

- A secured group write the actuator discarded was reported as confirmed
  (#297). `write`, `read`, `knx_write_group` and `knx_read_group` on a secured
  GA now check whether the devices on it admit bussard's tunnel address (the
  lock's `secure_senders`, the key store's interface `Group`/`Senders`): a
  write or read the recorded tables say would be discarded is refused before
  sending ("1.1.5 does not list the tunnel address 1.1.25 as a secure sender
  of 1/0/4; …"), and one without evidence is sent with a note that delivery
  is not confirmed. A write result says only what KNX confirms ("the interface
  acknowledged the telegram (L_Data.con); KNX reports no application-level
  result"), and a secured read that times out names sender admission as the
  usual cause. The key store import keeps the interface `Senders` as
  admission evidence.
- A DPT 9 parameter whose type spans the full raw range is written like ETS
  writes it (#294). The Zennio Flat 55 Display (`M-0071_A-5261-10`) types
  `ctrl[n].uCtrl.b2.float16.maxValue` as `float16_t (-671088.64, 670760.96)`
  with `maxInclusive="670760.96"` and that value as the default. It encodes
  to `7F FF`, the group-value "invalid data" marker, so the image builder
  refused the whole parameter image. The pattern is now written when the
  type's own `maxInclusive` reaches it and stays refused otherwise. The
  product-corpus sweep baseline is regenerated: the Flat 55 Display is
  executable again, and seven archives added to the corpus are tracked.
- The corpus-gated tests run again and are listed (#293). They read vendor
  archives that are never committed and skip green without
  `BUSSARD_PRODUCT_CORPUS`, so three had gone stale unseen: the Jung 3361-1M
  parameter-only plan test now expects ETS's prelude (a restart with no
  unload, then verify mode) that #186 added, as the 1.1.32 capture
  `bad-eg-pm-1-1-18.pcapng` shows; the Theben FIX2 plan test expects the plan
  to end at the terminal restart (#178); the ABB IEEE-754 test checks the
  4-octet encoding and the image only where the configuration reaches the
  parameters (#159). No product code changed. Every gated test now accepts
  the product-corpus directory, its `cache/` or the vendor directory (before,
  each wanted one of them and quietly skipped with the others).
  `docs/testing.md` lists them and how to run them locally with the new
  `corpus` nextest profile, and a `workflow_dispatch` run of `corpus-sweep`
  with a corpus path runs all of them, not only the sweep.
  The full sweep itself still fails against its baseline on one Zennio
  application (#294).
- A bus stuck reconnecting says why and can be told to reconnect (#287).
  `bus` in `knx_project_summary` and the new read-only `knx_bus_status`
  carry the interface, the tunnelling user, the exact last transport error
  and when it happened, the failed attempts and the seconds to the next one;
  a bus tool refused while the bus is down quotes that error. A socket error
  in the KNXnet/IP Secure handshake names the step it happened at.
  `knx_bus_reconnect` (read tier, not a write) drops the connection and
  connects afresh with the backoff reset.
- Two bussard processes on one host no longer share a tunnelling user
  (#287). The tunnel marks the user it holds in
  `<dir>/.bussard/tunnel-users/` (stale pids ignored) and a second process
  picks another; a user the interface refuses (authentication, no tunnel,
  or a hang-up in the handshake) hands over to the next keyring user before
  the bus backs off. `bussard mcp` warns at start when another server for
  the same model directory runs, and lists it in `knx_bus_status`.
- A lost KNXnet/IP Secure tunnel closes its stale session before it opens
  the new one (#287). Before, the re-establish authenticated as the same
  user while the old session was still open, which an interface holding one
  session per user refuses for the whole budget.
- A connect error that is fatal at startup (a refused password, a TCP
  endpoint that refuses while UDP still answers) no longer stops a bus that
  was connected before: it is retried, since the same configuration worked
  (#287).

- `knx_model_lookup` searches com-object and channel texts (#276): every
  object a device has, linked or not, matches on its vendor text, function
  and key besides the link name, and a new `channels` list matches channel
  texts, names and handles. Each hit names the device, channel handle and
  object number, so "Mapper" finds the IPS300SREG mapper objects 15..34 that
  have no links, and "Logik" finds a push-button's logic inputs once its LED
  function shows them. The tool description no longer claims more than it
  searches.
- Parameters at their vendor default are visible and settable (#276).
  `bussard.lock` indexes every parameter the device's configuration shows,
  not only the ones ETS stored, so `bussard device`, its `--toml` (as
  commented default lines), `knx_show_device` and `knx_set_parameter` see
  them: the IPS300SREG mapper's channel enables and data lengths, the
  52921ST's "Objekt-Polarität", a key's function parameters. A parameter
  ref's `Value` override counts as the default (lock field `default`). A
  channel with nothing to configure (only `Access="None"` parameters, no
  objects, such as "Applikationsinstanzen") is no longer emitted; other
  handles do not move. After `knx_set_parameter` the device's channels,
  objects and parameter index are re-derived under the new value when the
  lock pins the archive, so dependent parameters and objects appear in
  `knx_show_device` at once, and the result's `note` names objects the value
  shows or hides. Such a change needs a full download: `bussard flash <ia>`,
  which the `apply` refusal names, or the flash `knx_plan_device` plans
  (#303). The lock format is now
  version 3 (see Breaking changes).
- An MCP tool call without arguments no longer fails with serde's "missing
  field `device`", which read as a server bug. The error says the call
  reached bussard without any arguments (or with an empty object), lists the
  fields the tool expects and asks for a retry; a mistyped field keeps
  serde's text, names the field and lists the expected ones. Every
  `tools/call` is logged at info with the tool name, whether `arguments` was
  present and the field names (never values); `-vv` adds the raw request with
  string values redacted (#269).
- MCP payloads carry only what the edit did (#279). A history snapshot holds
  no product models, so its enum labels stayed text while the working model
  held codes: `knx_undo`, `knx_describe_change` and the plan's pending list
  reported every labelled parameter of the house as changed ("Fußbodenheizung
  to 8"). Snapshots now translate labels through the working directory's
  models, and a parameter change whose two sides name the same enum member
  is dropped. Parameter sentences print the label with the code after it
  ("Funktion … is set to Kurzer und langer Tastendruck (5)").
  `knx_plan_device`'s `pending_model_changes` lists this session's
  unapplied edits of that device only (`[{snapshot, tool, sentences}]`),
  cleared by a successful `knx_apply_device`, a plan with nothing to write,
  or `knx_undo` of the edit. Edit and undo results return `validation:
  {ok, errors, error_count, new_warnings, warning_count}` with only the
  warnings the edit introduced (the full list stays in `knx_validate`), and
  cap their lists with a `truncated` or `note` field. A plan names the
  parameters behind every written parameter octet (`parameters.
  octet_ranges`), and a plan that writes octets while no shown parameter
  changes says why in its notes (device memory that differs from the model's
  image outside any parameter, a hidden or runtime-owned parameter). W005 no
  longer fires for a main-type-only DPT (`1`) next to a subtype of it
  (`1.017`).
- Written parameter octets are attributed to every parameter placed there
  (#285), not only the shown ones: a parameter the configuration hides
  (`hidden`) and an `Access="None"` internal ETS value the configuration
  does not reach (`internal`, such as the `_AppInstanz <n>` function-block
  selectors of a Jung push-button) next to `changed`, `same_value` and
  `device_managed`. Each parameter in `octet_ranges` carries `device` and
  `model`, the values the device's octets and the model's image hold
  (enumeration text where the value is a member, else the number), and the
  sentence reads "1 octet at offset 165 of segment RS-04-00000: _AppInstanz
  51 (internal ETS selector, P-643), device 3, model no application". A
  differing internal selector adds one note on what it means (the device's
  function assignment differs from the project; writing makes the device
  match the model). `reconstruct` and `plan -v` print the differing internal
  values too (`parameters.internal` in `--json`).
- Product models regenerate when `.bussard/models/` exists but is empty or
  lacks the model of a pinned application, not only when the directory is
  absent. Before, an empty directory left every consumer, the MCP server
  included, reporting "no product data" for devices whose archives sit in
  `products/`. Every command checks one file per pinned application and
  writes only the missing models; the MCP and `viz` servers do the same at
  start and on every model reload. E026 and the `device` note name
  `bussard import-product` only when no stored archive carries the
  application (#267).
- The `.gitignore` that `init` writes lists `.env`, and `init` adds the line
  to an existing `.gitignore` that lacks it, so the passwords bussard reads
  from `.env` are not committed by accident. An `import` into a directory
  without a model writes or merges the same `.gitignore`.
- The product models a command regenerates from `products/` are parsed in
  the lock's `language`, so a German model no longer reports E017 ("enum
  value ... is not an integer") on every German label after a fresh import.
  `import` writes `.bussard/models/` itself, and `device` writes a missing
  model on demand (#255).
- A re-import with `--theirs` writes the files a fresh import of the same
  project writes. Link keys the project dropped (a link that moved to another
  channel, an object that went away with its parameter) no longer survive in
  the device files and fail `validate` with E023. A send or listen address
  only the local model has is now a conflict (`--theirs` removes it, `--mine`
  keeps it), and so is a stored parameter value the project changed, which a
  re-import used to keep silently. Sections, entries and escape-key
  spellings follow the fresh import's order and keys (#235).
- Enum labels in the project language resolve on the flash path: `flash`,
  `plan`, `apply`, `reconstruct` and `replace` read the product in the lock's
  `language`, so a German model's `Heizen und Kühlen` no longer fails with
  "neither an enum code nor exactly one of its labels". A label matches the
  lock's language first, then the default text, then any translation; the
  Dynamic section evaluates a labelled value as its code, so the branch it
  selects is the one ETS takes. `import-product` writes `models/` in the
  same language (#231).
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
- A tunnel loss while `flash` reconnects to a device it restarted (after the
  factory reset, an `LdCtrlMasterReset`, the final restart, or a System 7
  restart) no longer fails with "connection to <ia> was disconnected" and
  leaves a reset, unloaded device. The readiness probe, Data Secure sync and
  authorize run again once the tunnel is back, and the flash continues with
  the same step, within the 60 s tunnel and 30 s readiness budgets. An
  authorize lost with the link is no longer cached as "device has no
  authorize". A KNXnet/IP Secure (TCP) tunnel now notices a pulled cable
  after about 7 s instead of about 37 s: after 5 s without traffic it probes
  the link (`BUSSARD_TCP_READ_DEADLINE_MS`) (#192, S2.6 of #90).
- A tunnel that connected before anything waited for it no longer makes
  the next wait sit out its whole timeout: 10 s in `learn`, `audit`,
  `assign`, `test` and `commission`, 60 s for each MCP device tool call.
  The bus now records every connection-state change even while no one is
  listening, and a wait returns at once when the bus is already connected
  (#207).
- The KNX Secure device certificate check is plain CRC-4 (x^4 + x + 1, not
  reflected), confirmed on real labels, instead of CRC-4/ITU. Real labels no
  longer show a check mismatch. A label whose check does not match is now
  `invalid` in `keys add-certificate`, `keys enroll` and the enrolment page,
  which no longer offers "Send anyway" (#201).
- `knx_show_device`, `bussard device` and `knx_model_lookup` list the channels
  of a module instance the configuration does not reach (a Jung actuator's
  switch outputs while it runs blinds) as inactive, with the parameters that
  enable them. An enable step no longer names an internal (`Access="None"`)
  parameter: it names the parameter that sets it, or says "enabled by ETS
  only". A capability lookup evaluates only the pages holding a match and
  builds each application's condition index once, about half the CPU time on
  a 47-device installation (#302).
- A secured group write or read whose sender admission the lock and the
  keyring cannot tell now reads the receivers' security individual address
  table (PID 54) with their tool keys first, records it in `bussard.lock`
  and refuses with the remedy when it does not list the tunnel address;
  when the read fails it sends as before and the note says why (CLI and MCP,
  once per device per server lifetime) (#316).
- `knx_discard_edits` on a group address whose Data Secure state the session
  flipped restores the key store as `knx_undo` does (#336). A plan of a Secure
  System B device reads PID 61 only when a security change is pending or no
  earlier read is cached; `apply` and `flash` always read it (#336).
  `flash --json` carries the "Data Secure off for <GA>" line as
  `security_object` (#336).
- The `sim-catalog-loop` CI job no longer downloads vendor archives (#346
  follow-up): it runs only when `BUSSARD_PRODUCT_CORPUS` names a corpus, like
  the other corpus-gated jobs, and is skipped otherwise. A subset application
  whose archive is not in the corpus is reported as skipped, not failed.
- knx-sim serves what the 24 unclassified sim-loop applications need from a
  real device: the properties and segment of a paired ABB/Busch-Jaeger PEI
  program (object 5 PID 16 and 13), a load completed without a TaskSegment
  when the vendor procedure has none (IRSC/Zennio 0701), and the factory
  memory a `CompareMem` checks. The baseline lists none of them (#346).
- W005 follows ETS (#348): subtypes of one main type on one group address
  (`1.001`, `1.005`, `1.019`) no longer warn; only different main types of
  the same size do. A clean ETS import no longer reports dozens of W005.
- `bussard flash` no longer refuses a System 7 configuration flashed over
  another configuration of the same application (#355). The identity check
  sampled the group-object descriptor table as code, whose CONFIG octets
  follow the links, so the Theben Meteodata 140 S and 13 MDT 0705 programs
  read as "another application". It now samples only the segments streamed
  verbatim from the product; a product with none (the Meteodata) is judged by
  its load-state machines alone, and the pre-flight says so.
- `scripts/dev/wait-pr.sh` reports a failed check within a minute instead of
  waiting out its deadline: `gh pr checks` exits 8 once a check has failed, which
  the "no checks yet" loop took for "no checks".
- `plan`, `apply` and the read-back after `flash` read a System 7 device's
  link tables where its product puts them when the device does not answer
  `PID_TABLE_REFERENCE`, not at the fixed `0x4000` / `0x4201`. Products with
  the association table at `0x41FF` (Jung, Siemens), `0x41D5` or `0x4041`
  read back as missing every link, and `apply` would have written there (#369).
- A System 7 `LdCtrlCompareMem` pre-flight compares its `Size` octets, not the
  whole padded `InlineData`, so the Zennio 0701 programs pass it (#370).
- `diff` and `diff --checklist` compare parameters by ref, so one ref keyed
  differently on the two sides (`label@R`, `page-label@R`, `hidden@R`) is no
  change, or one change, instead of a set and an unset (#375). A `hidden[]`
  value of a ref the lock indexes is read under the visible key and written
  into the device file on the next save, and `knx_set_parameter` updates it
  instead of adding a second key for the ref.
- A System B relative segment that carries no `<Data>` now reads `0xFF` in
  every octet no parameter writes, as ETS writes it, instead of `0x00` (#377).
  The flash, the dry-run images and the read-back compare all see the same
  image; the Jung IP interface additional function (`A-0024-22`) is now
  byte-identical to its ETS download.
- A hidden value ETS stored for a parameter the current configuration does not
  reach (the Meteodata's C4 temperature refs while C4 is a brightness sensor)
  is no longer reported as an ignored override, listed in the device view or
  offered as a key; the flash still writes it (#380). Whether such a value
  counts as a visible setting is now decided by the Dynamic evaluation, not by
  the lock's parameter index.
- A System 7 flash of a program with `DynamicTableManagement` (the Jung
  Schaltaktor `A-2088`, the Theben Meteodata `A-140C`) lays out its tables as
  ETS does (#383): the address-table segment is sized to the table, and the
  association table sits directly behind it, up to the end of the product's
  LSM 2 segment. `plan`, `apply`, the flash read-back and the MCP tools read
  and write the association table there when the device does not report its
  table reference.
- A System 7 flash now matches ETS on the ABB 6119/20 (`A-A002`, mask 0701)
  (#386): a program that declares `ParameterByteOrder="LittleEndian"` gets its
  multi-octet integer parameters least significant octet first, and the
  group-object descriptor table is taken from the program's
  `<ComObjectTable CodeSegment Offset>` declaration, so its CONFIG octets get
  the project's flags (C cleared on unlinked objects) even when the
  descriptors point into controller RAM the plan does not allocate.
- `bussard plan`, `apply` and the MCP plan and apply no longer refuse a device
  without links when its application has no group objects (#390): the Jung
  IPS 300 SREG KNX IP interface's empty table set is its correct state. `plan`
  then reads the properties its property-only load procedure writes and says
  which differ from the model; `apply` names `flash` as the command that
  writes them. A program with group objects keeps the empty-table refusal.
- `status`, `describe` and `adopt` find the KNXnet/IP parameter object of an IP
  interface whose object-index walk does not list it, such as the Jung IPS 300
  SREG at mask 0021 (#391). They look in `PID_IO_LIST`, then probe object type
  11 by type and instance with one short extended-property read, which keeps
  the connection when the device leaves it unanswered. A device found without
  the object is recorded in its device facts, so later commands skip the probe.
- The sim loop names every program it does not run, with the reason: an
  application id a second archive carries again (two MDT push-button programs,
  which is why the property-procedure run counted 97 of 99), an archive it
  cannot read, or a program the parse did not return. Its configuration
  generator draws integers only between a type's declared bounds, also over a
  full 64-bit range (#399).
- knx-sim seeds a device property that a load procedure compares under a
  `<choose>` from the branch the product's own parameter defaults select, not
  from the first compare in the file: the MDT central operation unit
  `M-0083_A-0054-14-0D63` reports hardware revision R2.0 (object 0 PID 19
  `01000000`) and its vendor defaults flash on the simulator (#400).
- A text parameter is written in the code page its application program
  declares in `<Options TextParameterEncoding>` (#401): MDT's ISO 8859-15
  labels such as the eight-character `Scènario` now fit their eight-octet
  field instead of being refused as nine UTF-8 bytes. A character the code
  page cannot represent, or a text longer than the field, is refused; a
  program that declares no encoding takes ASCII text only. `validate` measures
  text the same way, and the product model records the encoding
  (`model_format: 7`, regenerated on the next command).
- A System B load procedure now runs only the `<choose>` branches the device's
  parameters take, as the System 7 path already did, instead of every branch
  (#402). The MDT 07B0 programs that pick their hardware variant by parameter
  (`A-047A`, `A-04C0`, `A-018C`) planned one PID 78 or PID 162 compare per
  variant and could not pass the second; they now plan the chosen variant's
  compare. Nested `<choose>` blocks are decided recursively with the Dynamic
  evaluator's branch rules, and a self-closed `<when …/>` keeps its test.
- A `<choose>` whose taken branches write only part of a segment (the MDT
  JTA-01 `A-00A2` with its keep-data parameter set) is refused at plan time:
  ETS keeps the device's octets there, which neither the MCB check nor the
  read-back can verify (#402).
- A product with `ParameterByteOrder="LittleEndian"` gets its float
  parameters (DPT 9, IEEE-754 Single and Double) written least significant
  octet first, as ETS writes them, and `bussard device` and the read-back
  decode them in that order. Before, bussard wrote these floats big-endian
  and the device held different values than ETS would have written. The
  ETS capture of the synthetic `syn-le-order` is the regression test
  (#403).
- A flash writes a vendor default that lies outside its parameter type's range
  as declared, as ETS does, with a warning naming the parameter, instead of
  refusing the image. The ABB/Busch-Jaeger ventilation programs `A-A074` and
  `A-A075` ("Vent Dummy Prio Ende", default 1, type 129..129) flash again. A
  value set in the model outside its type is still refused (#405).
- The sim loop's configuration generator leaves a parameter at its vendor
  default when a `<choose>` of the load procedure tested on it holds a device
  compare (`LdCtrlCompareProp`, `LdCtrlCompareRelMem`, `LdCtrlCompareMem`):
  such a parameter states which hardware the project expects, and flipping it
  made the simulated device refuse the download like real hardware (#407).
- `bussard flash` plans a System B load procedure whose `<choose>` branch
  writes only part of a segment (a keep-data branch, as on the MDT JTA-01
  `A-00A2`) instead of refusing it. As in ETS's download, the taken branch's
  octets are written and the rest of the allocation is kept on the device:
  the plan and `--dump-images` name the gap (`object 4 octets 128..256
  kept`), the MCB CRC over that segment is read but not compared, and the
  parameters placed in the gap are listed as kept on the device by `flash`,
  `plan` and the post-flash read-back, never as a difference (#411).
- `bussard flash` plans a System 7 load procedure whose `<choose>` branch
  allocates an absolute segment in parts with a parameter placed in the gap
  (the MDT `A-0054-14` and `A-0255-21` with switching times in the device)
  instead of refusing it. As in ETS's download, each part is streamed into
  its allocation and the gap is kept on the device: the plan names it
  (`LSM 3 segment 0x4440 octets 1..3 kept`), and the parameters placed there
  are listed as kept on the device by `flash`, `plan` and the read-back,
  never as a difference (#411).
- `bussard apply` and `bussard flash --parameters-only` refuse a System 7
  parameter change that makes the load procedure allocate the segments
  differently, and ask for a full `bussard flash`: a parameter-only download
  sends no allocation record (#411).
- A System 7 load procedure whose `<choose>` branch allocates an absolute
  segment in parts now streams each allocation the part of the image it holds
  (#413). The MDT central operation unit `A-0054` with `Switching times in the
  device` = 1 allocates `0x47E4` as 899, 2966 and 578 octets of its 5406;
  bussard streamed the whole image into the first allocation and retried until
  the timeout. The octets no allocation holds are the device's and are never
  written. Where the configuration places a parameter in them, the plan
  refuses, as it does for a System B `<choose>` that writes a segment in part
  (#402).
- A text parameter of a program that declares no `TextParameterEncoding` is
  written in ISO 8859-1, NUL-padded to its field, as ETS 6 writes it (the
  capture of the synthetic product `syn-text-undeclared`: "Störung" as
  `53 74 F6 72 75 6E 67 00 ...`). Such programs with accented defaults, ABB
  `M-0002_A-A016-22` among them, plan again instead of being refused. A
  character whose octet is not settled by the capture (the euro sign, the
  eight ISO 8859-15 replacements, anything beyond U+00FF) is still refused
  (#416).
- knx-sim compares only the first `Count` octets of an `LdCtrlCompareProp`
  whose `InlineData` is longer than `Count` elements can hold: the Gira
  IR-Gateway's PID 78 compare carries a seventh padding octet, the sim served
  it, and ETS reported a hardware type mismatch (#422).
- knx-sim merges the `LdCtrlCompareProp` steps that check single elements of
  one property (`StartElement`, `Count`) into that property's element array:
  the Siemens 07B0 actuators compare object 4's PID 246 element by element and
  the sim answered every element with the first compare's value, so ETS
  refused the download with "Das Schreiben in den Speicherbereich ist
  fehlgeschlagen" (#422).
- knx-sim answers an extended property read that names an indexed object by
  type, the device object as type 0 among them: ETS reads the manufacturer id
  of the ABB Modbus RTU gateway that way (#422).
- knx-sim answers `A_FunctionPropertyCommand` and
  `A_FunctionPropertyState_Read` (KNX 3/3/7 §3.4.7) and declares the function
  properties a product's `LdCtrlInvokeFunctionProp` steps call as
  `PDT_FUNCTION`: the Siemens 0701 programs call object 5's PID 52 before the
  download, the sim stayed silent, and ETS reported "Das Gerät antwortet
  nicht" (#422).
- knx-sim's System B IP interface keeps the manufacturer properties its
  product writes on the KNXnet/IP parameter object (the Siemens IP Interface
  Secure's PID 236), so ETS can describe and write them; the ETS sweep reads
  `IsIPEnabled="1"` of older product files as IP-enabled, so the Jung Sonos
  gateway's sim has the KNXnet/IP object ETS looks for (#422).
- knx-sim places a simulated IP interface's KNXnet/IP parameter object at the
  lowest free object index, where ETS's object walk finds it, not after the
  last object: the ise smart connect devices have application object 8, the
  parameter object went to 9, and ETS stopped at the absent object 6 (#422).
- knx-sim's KNXnet/IP parameter object takes the writes ETS sends to a
  device with a built-in IP router (Zennio ALLinBOX 1612): the project
  installation id (PID 51), the routing multicast address and TTL (66, 67),
  and it describes the IP capabilities, DHCP server and routing capabilities
  (56, 63, 70) (#422).
- knx-sim fills the manufacturer and version into a masked program-id compare
  (object 3 PID 13, `Mask="0000FFFF00"`): ETS refused the ABB 0701 programs as
  "a device of another manufacturer" when the sim reported 0000 there (#422).
- knx-sim keeps the program version (PID 13) writable when a load-procedure
  compare seeds it: ETS stamps it at the end of the download, and the sim
  refused the write on an Enertex IP system device (#422).
- knx-sim's System 7 application object reports a program id (PID 13) from
  the product even when no load-procedure step compares it: ETS reads it
  before a download and failed the ABB Room Master Premium without it (#422).
- knx-sim's System B device always has the load-state machines of objects 1
  to 5, gives an application object the procedure drives through PID 5 load
  events its own load-state machine, and places the vendor objects a
  procedure names by type at the indices past the system objects, where ETS
  looks for them with the standard property services. ETS stopped on the
  Siemens IP Interface Secure, the Jung Sonos gateway and the Siemens 983901
  dimmer (#422).
- knx-sim gives a vendor object that a product loads by object type
  (`LdCtrlUnload ObjType="40960"`) a load-state machine and answers ETS's
  `A_FunctionPropertyExt_Command` on its PID 5 with the new state: the Gira
  Eco download stopped at "Das Gerät antwortet nicht" (#422).
- knx-sim answers `A_UserMemory_Write` and `A_UserMemory_Read` (20-bit
  addresses, read-back response in verify mode): ETS writes a segment above
  0xFFFF with them on devices without the extended memory service (Zennio
  DALIBOX, a 418 kB object at 0x10000) (#422).
- knx-sim seeds the vendor interface objects a load procedure reaches by type
  on System B and System 7 devices too, and describes them over the extended
  property service (the ABB Modbus RTU gateway's type 65281) (#422).
- The ETS sweep finds the catalog's add bar at the window's bottom edge
  whatever the catalog splitter's position, and stops after eight jobs in a
  row end in driver errors (#422).
- The ETS sweep drags the Topologie/Katalog splitter back to its layout when
  ETS restored another position, so line 1.1 stays visible (#422).
- The ETS sweep declines a compatibility-mode warning with its Abbrechen
  button instead of a word of the warning's text (#422).
- The ETS sweep's guarded delete reads a device row three ways (full row,
  from the address column, the address column magnified), so OCR noise from
  a secure device's shield icon no longer blocks it (#422).
- The ETS sweep deletes a secure device's row: the shield icon before its
  address no longer reads as part of the address (#422).
- The ETS sweep keeps the `ETS6.log` lines that end a run as "ets logged a
  failure" (`ets_log` in `driver.json` and `defaults.json`), and the newest
  entry of ETS's history pane instead of its first four lines, which for some
  runs were only the pane's header and `1.1.1` (#422).
- The ETS sweep clicks the delete confirmation's Ja and Nein only on an
  exact match and waits up to 30 s for the dialog (#422).
- The ETS defaults sweep recovers from a compatibility-mode prompt that ETS
  raises before any of the sweep's own flows (not only before the project
  tab): a prompt before the catalog import failed ten products in a row (#422).
- The ETS sweep closes a product file dialog a failed import left open
  before the next import (#422).
- The ETS sweep confirms a device delete whose dialog grew with a two-line
  device name, and stops after five failed imports in a row instead of
  marking the rest of the corpus as driver errors (#422).
- The ETS defaults sweep records a failure on a catalog row that shows another
  application version as `skipped-catalog-version`, as it already did for a
  capture: the Theben MIX 2 secure ran its 0701 sibling's row and ETS refused
  the mask (#422).
- knx-sim answers the KNX Data Secure S-A_Sync_Req that ETS 6 sends connectionless
  before it connects, and secured property services without a connection, each
  in the requesting frame's transport mode (#423).
- knx-sim answers the security-mode read (PID 51) with the return code, the
  ReadServiceID and the mode, as ETS 6 expects before a secure download, and
  sends no state after a negative load-control return code (#423).
- `apply` on a System 7 device writes the address table alone, bounded by its
  segment, and no longer moves the octets behind it as if they were the
  group-object table (#431). The group-object table is read where the
  product declares it, its descriptors numbered from 0 as on the device. A
  device that refuses that read keeps its plain table read. Without product
  data and a reported association table, the address table is not grown.
- `apply` on a System 7 device switches on the communication flag of an
  object that gains its first link, and off for one that loses its last (#432).
  Before, the device ignored a new link on an object whose flag ETS had left
  off. Like ETS, it rewrites the group-object table inside an LSM 3 load
  bracket. `plan` lists each switch, and without product data names the new
  links whose flag it could not check. `apply --line` reads each device with
  its pinned product data, so the line walk switches the flags too.
- knx-sim's System 7 devices take ETS's partial download: the load-status
  bytes at 0xB6EA+ answer whichever way load control is driven, and each
  object reports the program id its TaskSegment record carried as PID 13
  (the `ApplicationId` ETS reads back first) (#433).
- On System 7 the parameters the configuration does not show are written at
  their defaults by the application's `MinEtsVersion` (5 or later), not by its
  schema version, as ETS does: a project/23 application with
  `MinEtsVersion` 4.0 keeps the segment template (synthetic twins
  `syn-s7-hidden-default` and `syn-s7-hidden-default-ets4`) (#448).
- `flash` writes the parameters the configuration does not show at their
  defaults on a System 7 application of schema project/21 or later without
  `DownloadInvisibleParameters`, as ETS 6 does; older System 7 applications
  keep the segment template, System B ones are unchanged. Established by the
  synthetic twins `syn-s7-hidden-default` (project/23, defaults written) and
  `syn-s7-hidden-default-p11` (project/11, template kept) and the sweep's
  Busch-Jaeger `A-FF11-15` (project/20, template kept) (#448).
- Hidden parameters are written at their defaults only by a System B program
  that declares neither `DownloadInvisibleParameters` nor a preferred partial
  download, as ETS does (#448); a System 7 program keeps the segment template for
  them whatever its schema version. The Steinel HPD 2 and TruePresence, ekinex,
  B.E.G. DIM, Zennio Sensato, Elsner and Busch-Jaeger `A-FF11-15` images no longer
  carry hidden defaults.
- The Dynamic evaluator models ETS module allocation (#449): a `<Repeat>`
  instantiates its modules as often as its parameter says, and a module argument
  fed by an `<Allocator>` takes the allocator's next value (submodules count from
  their parent's allocators, plus a `BaseValue`). The Zennio DALI BOX v3 channel,
  the DALI BOX Broadcast and X2 channels, the AmbianceBOX and the ABB Modbus RTU
  Gateway's signals are now written, and the MDT AKR-IO logic module no longer
  lands on the application's own parameters; all match ETS. A module argument
  without a value now refuses the image instead of resolving to 0.
- A hidden parameter declaring `LegacyPatchAlways="true"` is written at its default,
  as ETS does whatever `DownloadInvisibleParameters` says (#450): the Zennio
  DALI-BOX group limits, the Flat and Flat Display brightness and LED night
  settings, and the ABB Data Logging and Busch-Jaeger Dim Slave hidden values now
  match ETS. A `LegacyPatchAlways` parameter that is also computed by a
  `<ParameterCalculation>` gets its default, not the computed value, until #427.
- `flash` picks the restart form ETS uses from the product data (#452): only
  a System B application that declares `IsSecureEnabled` opens with the
  factory reset (erase code 7) and ends with the confirmed restart (erase
  code 1). Every other application, such as the KWL-KNX Connect (1.1.45) and
  the Steinel Control Pro (1.1.51), gets no master reset and ends with a bare
  `A_Restart`, as in ETS's captures. Before, every download with a filled
  segment got both.
- A full `flash` of a bus device with a KNX IP interface built in (an
  application that declares tunnelling addresses, such as the Zennio ALLinBOX
  family or the COMIP2) now writes its KNXnet/IP parameter object after the
  application, as ETS does: installation id, routing multicast address and
  TTL, friendly name, assignment method and tunnel addresses from the device
  file's `[knxnet]` table, each read back (#455). A device file without the
  table, or without one of the values, is refused before anything is written;
  a static assignment is refused until a capture shows what ETS writes for
  one. The ETS sweep rows of the five ALLinBOX and the COMIP2 captures compare
  their property writes `props=identical`.
- A `TypeIPAddress` parameter stored in memory (the Zennio ALLinBOX DNS
  servers) is written as the address's four octets and read back as the
  dotted quad, where the flash kept the template octets without a word. A
  parameter of an unknown type that has a value but no width now refuses
  (#457).
- An application that does not announce `SupportsExtendedMemoryServices`
  (Zennio DIMinBOX and DALIBOX, ABB Caldion and RoomTouch, Busch-Jaeger Split
  Unit Gateway) has its memory above `0xFFFF` written and read with
  `A_UserMemory_Write`/`A_UserMemory_Read` as ETS does, in `flash`, `apply`,
  `backup` and the MCP tools, instead of `A_MemoryExtended_*`, a service
  such a device does not offer. `knxtrace` decodes the user-memory services,
  so the oracle compares these downloads (#472).
- A text parameter starts from its `InitialValue`, translated into the model's
  language, as ETS starts a new device (#473): the Busch-Wächter PRO 2800's device
  name is "Busch-Wächter Pro" in a German project, not the English "Busch-Watchdog
  Pro". A value set in the model still wins. The ETS sweep's oracle models import
  in de-DE, the sweep project's language.
- On a System B application, a `<choose>` whose only branch is the default
  one, on a parameter that has no memory and that no page shows, now selects
  no branch, as ETS does: the com objects behind it get no group-object
  descriptor and its parameters are not reached. The synthetic
  `syn-choose-never-shown` capture now compares identical. System 7
  programs keep taking such branches, as ETS does there. Product models move
  to format 12 (`virtual: true` on such parameters) and regenerate on the
  next command (#474).
- The group-object table leaves out a reached, unlinked object whose flags are all
  disabled, as ETS does (#474): the Zennio Flat push buttons no longer enable the
  4 or 5 "dummy" objects behind `Flat_AlwaysFALSE`. The `<choose>` that reaches them
  still takes its default branch, as ETS does on the ABB and Busch-Jaeger steering
  parameters of the same shape.
- A System 7 flash of an application that declares no group object (COMIP2
  KNX IP-Interface) writes the descriptor table as the template has it and
  keeps the communication flag, as ETS does, instead of clearing it on every
  descriptor (#475).
- A load-state machine that answers `Unloading` (4) or `LoadCompleting` (5)
  no longer fails the flash: bussard names both states and re-reads every 3 s
  for up to 30 s (KNX 3/5/1 §4.23.2.4.1, 3/5/2 §3.31.4.1) on System B and on
  both System 7 forms (0705 property, 0701 memory-mapped), then fails with
  the last state. knx-sim's `intermediate_load_states` device option reports
  them (#479).
- `flash` sends a relative allocation (`LdCtrlRelSegment`) with the product's
  `Mode` and `Fill` octets as given, as ETS does: a `Mode="0" Fill="255"`
  record now carries `00 ff` instead of `00 00`. The device behaviour is the
  same (Mode 0 keeps the memory); the load-control records are now identical
  to ETS's capture of `syn-relseg-fill` (#480).
- Load-control names and docs match the KNX Standard: the sim's PID 13
  constant is `PID_PROGRAM_VERSION`, the 0701 LSM record's octet 2 is the
  segment ID, the System 7 AbsSegment fields are `access` and `seg_flags`
  (they were swapped), `PID_MCB_TABLE` is documented as seeded by many
  procedures with the product's access octet, and the System 7 notes describe
  `0xB6EC` as the application program's load state (#482).
- A System 7 flash or table write now puts the application's PEI type, manufacturer, number and version into each TaskSegment record, as ETS does (#485). bussard guessed the manufacturer octet from the mask family, which was right only for Jung and Theben products. A table write without the device's product data now refuses instead of writing a zeroed application id.
- A System 7 `LdCtrlAbsSegment SegType="1"` now goes out as a stack-segment
  allocation (Additional Load Controls subtype 01) as ETS sends it, not as a
  data segment; any other `SegType` refuses the plan (#487).
- A System 7 `flash` of a device that already holds an application no longer
  unloads load-state machines 1 to 4 and restarts the device before the
  download, as ETS's application download does neither, whatever the device
  holds; `--parameters-only` and the MCP flash drop that restart too. `flash
  --full` keeps the pass, as ETS runs it only after its own Unload command.
  The offline oracle plans a capture with ETS's Unload with `--full` (#488).
- A System 7 flash runs the pre-download unload of LSMs 1 to 4 and the restart
  only when the device's probed state calls for it: an LSM in Loaded, Loading
  or Error, or a resident application id. A device whose every LSM answers
  Unloaded gets none, as ETS gives none to a factory-fresh device. A device
  left mid-load (Loading) now keeps the pass. `flash --dry-run --resident`
  takes System 7 LSM states, and the offline oracle's `state=fresh` row option
  plans a capture of a fresh device that way (#488).
- A System 7 flash of a 0701 application whose load procedure names a task
  segment on load state machine 5 (Busch-Jaeger applications such as the
  binary input `A002-13`) no longer sends that record. The memory-mapped form
  has machines 1 to 4 only, ETS sends no record for 5, and the record failed
  the flash on a device that leaves the machine Unloaded (#489).
- Scaled DPT sub-types are decoded and written in their unit (#492): 8.010
  percent in 0.01 % (7FFFh is invalid), 7.003/7.004 and 8.003/8.004 time
  periods in 10 ms / 100 ms steps, 13.002 flow rate in 0.0001 m³/h. The
  monitor shows `50.00 %` instead of `5000`, and `bussard write <ga> 50` on
  an 8.010 address sends `13 88` instead of 0.50 %. Home Assistant maps
  7.003, 7.004 and 13.002 to their own sensor types.
- A DPT 9 (2-octet float) group value is encoded as the nearest
  representable code (#493). The encoder rounded the mantissa once per
  exponent step and could land up to two resolution steps off: 50.01 went out
  as 50.04, -2621.45 as -2624.00. Group values and `<TypeFloat Encoding="DPT 9">`
  parameter images now share one rounding rule (smallest exponent, ties to
  even, as ETS writes).
- Relative dimming and blind steps (DPT 3.007, 3.008) can be written and
  inferred (#494). `write`, `knx_write_group`, the viz and Home Assistant rules
  take `increase 25%`, `down 50%`, `up` or `break`; `read` and `monitor` print
  the step size (`Increase 25 %`) where they printed the code as if it were a
  count of steps (`Increase step 3`); `knx_infer_group` proposes 3.007 for a
  4-bit payload.
- `bussard ha-config` emits `invert: true` for a 1.009 Open/Close contact
  mapped to a `window`, `door`, `opening` or `garage_door` binary_sensor
  (#496). 1.009 is 0 = open (KNX 03_07_02 §3.1), the inverse of 1.019, and
  Home Assistant showed such a window as closed while it was open.
- The 1-bit controlled values (DPT 2.001-2.012, forced operation) decode,
  encode and parse (#497). `monitor` and `read` show `Control: On` or
  `No control` where they showed `0x03`, and `write <ga> "control on"`,
  `"control down"` (2.008) or `release` is accepted.
- Every fixed-width DPT main type of the KNX 03_07_02 overview has a size
  (#498): E004, the monitor's size note and the raw-payload check of `write`
  now cover 15.x, 21.x, 22.x, 26.x, 27.x, 29.x and the 2xx structured types
  (a one-octet payload to a 245.600 GA is refused). The 2-bit 23.x and 3-bit
  31.x values are packed into the APCI, where a raw `write --payload` sent
  them as a separate data octet.
- `read`, `monitor`, `write` and the MCP group tools know the word pair of every
  `1.xxx` sub-type of KNX 03_07_02 §3.1 and `1.100` (#499): a `1.018` presence
  object shows `Occupied`, a `1.019` contact `Closed`, and `write <ga> night`
  works on a `1.024` address. `1.009` now reads `Close` (was `Closed`), the
  spec's word.
- The 20.xxx enumerations of KNX 03_07_02 §3.21, §4.3 and §6.3 decode to their
  label (`20.105` `03` is `Cool`, reserved codes `Unknown(n)`) and `write`
  takes the label (`cool`); the 21.xxx and 22.xxx bit sets decode to the names
  of their set bits (`21.001` `0A` is `Fault, InAlarm`); `6.020` shows its five
  status fields and the one-hot mode instead of a signed byte (#500).
- `read`, `monitor` and the MCP tools show the unit of every integer and float
  sub-type of KNX 03_07_02 §3.5-§3.15 (#501): `7.600` reads `6500 K`, `13.100`
  `3600 s`, `9.002` `20 K`, `5.004` `50 %`, counters `pulses`, and `write`
  accepts the same suffix (`write <ga> "6500 K"`). A `5.003` angle decodes to
  one decimal (`180.7 °`) instead of truncating to whole degrees.
- `monitor` notes a telegram that every conforming receiver drops (KNX
  03_07_01 §2.4): reserved bits set (`18.001` `45`, `17.001` `C1`), fields out
  of range (hour 24 on `10.001`, month 0 on `11.001`, `19.001` hour 24 with
  non-zero seconds), `5.006` tariff 255 and reserved `20.xxx` codes. The value
  still decodes; the note says the devices will not act on it (#502).
- `bussard ha` gives a sensor the Home Assistant KNX `type` of its exact
  sub-type for `7.x`, `9.x`, `12.x`, `13.x` and `14.x` (#505): `7.600` is
  `color_temperature`, `7.005` `time_period_sec`, `13.100`
  `long_delta_timesec`, `13.011`-`13.016` the apparent, reactive and MWh energy
  types, so HA shows kelvin and seconds with a device class instead of pulses.
  An unknown `12.x` now uses `4byte_unsigned` instead of the signed
  `pulse_4byte`, and an unknown `7.x` `2byte_unsigned`.
- `T_Connect`, `T_ACK`, `T_NAK`, `T_Disconnect`, the numbered management
  telegrams and the `A_IndividualAddress_*` broadcasts now go out at system
  priority, as the transport and application layer specify and ETS sends them
  (#506). `Layer4Connection::set_data_priority` changes the priority of the
  numbered data telegrams; group telegrams keep theirs.
- The management connection follows the Style 3 transport layer
  (03_03_04 §5.4.3 with AN210) on its error paths (#507): an out-of-window
  numbered telegram draws a `T_NAK` with its sequence instead of a `T_ACK`,
  only a `T_NAK` for the pending sequence triggers a repeat, giving up after
  the acknowledge timeout, a `T_NAK` or a broken channel sends one
  `T_Disconnect` to a device that holds the connection open, and a negative
  `L_Data.con` for the `T_Connect` fails the connection at once on every
  budget instead of after 4 x 3 s. A wrong-sequence `T_ACK` stays ignored, as
  AN210 amends the table. Healthy sessions send the same frames as before.
- cEMI control field 1 bit 4 is now read with its wire meaning: a cleared bit
  is a system broadcast, a set bit an ordinary broadcast (#508). The field is
  `Control1::broadcast: BroadcastKind` instead of the inverted
  `system_broadcast: bool`; the bytes bussard sends are unchanged.
- Defined negative answers of the application layer are reported as what
  they are (#509): an `A_Memory_Response` with number 0 is a named refusal
  (`MemoryRefused`) where a caller needs the data, an extended-memory return
  code is named (`E_ACCESS_DENIED`, `E_LENGTH_EXCEEDS_MAX_APDU_LENGTH`, ...)
  instead of a verify mismatch or a raw code, a device descriptor answer of
  type 3Fh is "type not supported" and one of another type is no longer read
  as the mask, and an `A_Authorize` level between 0 and the minimum (3 or 15)
  is a grant; only the minimum level is an access denial.
- knxtrace names APCI `0x3D0` `A_MemoryBit_Write` instead of `A_ADC_Read`,
  decodes `A_ADC_Read`/`A_ADC_Response` (`0x180`/`0x1C0`, channel in the low
  six bits) and knows the remaining services of the 03_03_07 APCI table (#510).
- A plain UDP tunnel now sends its TUNNELLING_REQUESTs and ACKs to the data
  endpoint the gateway names in its CONNECT_RESPONSE, and receives them from
  there, while CONNECTIONSTATE and DISCONNECT stay on the control endpoint
  (#512, KNXnet/IP Core §5.2, §8.6.3). A gateway that serves a tunnel on its
  own data port no longer times out every frame after a successful CONNECT;
  one that uses a single port, as most do, sees no change. knx-sim can serve
  that split with `gateway.data_port`, and the testkit `MockGateway` and
  `RawGateway` with `data_port()` and `bind_with_data_port()`.
- A TUNNELLING_ACK with an error status now makes the tunnel repeat the
  request once and then treat the link as lost, as a missing ACK does; the
  send failed at once before. Only an inbound frame one behind the expected
  sequence is ACKed as a repeat; one two or more behind is dropped without an
  ACK (KNXnet/IP Tunnelling 3/8/4 §2.6.1, #516).
- An unanswered heartbeat is now repeated three times before the tunnel counts
  as lost, four CONNECTIONSTATE_REQUESTs in all, as KNXnet/IP Core §5.4 asks;
  it gave up after three in total before (#516).
- A gateway status error names the KNXnet/IP code and its meaning, e.g.
  `E_NO_MORE_UNIQUE_CONNECTIONS` or `E_KNX_CONNECTION`, instead of a bare hex
  value (#517). `E_NO_MORE_UNIQUE_CONNECTIONS` (0x25) points at the duplicated
  tunnelling address (PID 53) to fix.
- The tunnelling-slot status bit 1, read outside a KNXnet/IP Secure session,
  means "no authorisation required" (KNXnet/IP Core 3/8/2 §7.5.4.8), not
  "this client is authorised". `TunnelSlot::authorized` is now
  `authorisation_required`, and the live `knx_audit` reports each slot's
  `authorisation_required` with an `access` of `needs tunnelling credentials`
  or `open`, instead of `authorized: false` on every slot of a secure
  interface (#518).
- Routing now paces its ROUTING_INDICATIONs as the standard requires: at
  most 50 per second with at least 5 ms between two, and after a
  ROUTING_BUSY a random extra wait of up to N x 50 ms on top of the busy
  time, with the busy counter N (KNX IP 3/2/6 §2.1, Routing 3/8/5 §2.3.5).
  Routing datagrams leave with a multicast TTL of 16, PID_TTL's default
  (3/8/3 §2.5.18), instead of the OS default of 1 that never crosses an IP
  router (#519).
- `interface secure on` now reads the interface's tunnelling addresses
  (PID_TUNNELLING_ADDRESSES, PID 79) before it writes the tunnelling users,
  and points each user's index into that table, as KNX IP Secure 3/8/9
  §2.3.1.8.3 requires; it wrote the `[knxnet] tunnels` slot instead, which is
  only right when PID 79 lists the slots in order. A tunnel address the
  interface does not use for tunnelling is refused before any write, and an
  interface without PID 79 keeps the slot order with a note. knx-sim serves
  PID 78 and PID 79 and resolves the users through them (#520).
- knx-sim's KNXnet/IP Secure server follows the session state machine of KNX
  IP Secure 3/8/9 §2.2.3.5.2: an unauthenticated session ends after 10 s and
  an idle authenticated one after 60 s (both configurable), a wrapper that
  fails to verify is ignored instead of closing the connection, a wrapped
  keepalive or other frame before authentication gets
  STATUS_UNAUTHENTICATED and a wrapped close gets STATUS_CLOSE, session ids
  are unique and never 0, and a SESSION_REQUEST or SESSION_AUTHENTICATE of
  the wrong length, HPAI or reserved octet is discarded (#521).
- A plain (unwrapped) SESSION_STATUS no longer decides a KNXnet/IP Secure
  handshake or ends a session: it is logged and dropped, since only a wrapped
  one is valid (KNX IP Secure 3/8/9 §2.2.3.9.2). A SECURE_WRAPPER shorter
  than 44 octets is discarded before the MAC check, and SESSION_RESPONSE and
  SESSION_AUTHENTICATE must be exactly 56 and 24 octets (#522).
- A System 7 download in verify mode compares every `A_Memory_Response` echo
  with the octets it wrote and fails the step on a difference, naming the
  address and both values (#524). The session sets verify mode again on every
  new connection before its next write, `flash -v` reports the echoes compared,
  and knx-sim clears verify mode with the connection, as the standard says.
- A System 7 device on mask `0700` is now driven through the memory-mapped load
  state machine, the realisation the KNX profile makes mandatory there, instead
  of the optional property one; knx-sim picks the same realisation per mask
  when a device's config omits `lsm_access` (#526).
- The public System 7 CONFIG octet helper `sys7_config_byte` now follows Group
  Object Table Realisation Type 2 like the flash post-pass (bit 7 is the U
  flag, the segment selector and priority come from the product's template)
  and is the one definition both use; the unused `sys7_group_objects` and
  `SYS7_DEFAULT_RAM_FLAGS_PTR` are removed (#528).
- knx-sim no longer opens Loading on a System 7 Task allocation record that
  arrives in Unloaded: per the load state machine transition table
  (Resources Table 94) a record or a LoadCompleted in Unloaded leaves the LSM
  Unloaded, so a tool that sends a record before StartLoading no longer passes
  the conformance loop (#529).
- `assign` and `adopt` check on the bus that the target address is free before
  writing it (a connect and a descriptor read, step 1 of the standard's
  `NM_IndividualAddress_Write`), refuse when a device answers there, naming
  its mask, manufacturer and order number, and take `--force` to proceed
  (#530). `commission` counts an answering address as commissioned only when
  the device there reports the model's order number; any other answer refuses
  that device as an address in use. `replace` names the same details.
- A Data Secure device that was reset to default is recognised: when the
  S-A_Sync under the tool key goes unanswered and the key store holds the
  device's FDSK, bussard tries one Sync under the FDSK and, if it verifies,
  `describe`, `plan`, `apply`, `flash` and `status` (CLI and MCP) say the
  device is back on its factory key and what to do, instead of a generic key
  error; nothing is written under the factory key. `describe` also tries the
  FDSK on a device that refuses plain access before asking for a keyring
  (#532).
- `apply` and `flash` of a Data Secure device read the security object's load
  state (PID 5) back and are not verified unless it is Loaded; a write that
  stops between the security object's Unload and LoadCompleted says that the
  device now drops every secured group telegram and that `bussard apply <ia>`
  again is the remedy (#534).
- The `PID_SEQUENCE_NUMBER_SENDING` write of `ip-secure on` writes the clock or
  the device's own counter, whichever is higher, and accepts the confirmation
  the device already protects with the new value; a device whose counter ran
  ahead of the clock no longer fails the step as a stale sequence (#535).
- A secured frame with one of the six reserved bits above the inner APCI set
  is refused by bussard's Data Secure decoder and dropped by knx-sim without
  a failure count, its sequence still counted as received (#535).
- knx-sim's Data Secure device follows the standard where it was more lenient
  or stricter (#536): a Sync_Req raises the stored tool-access counter (as
  does bussard's mock device role), a Sync_Req within 1 s of the last
  Sync_Res is ignored, a Sync_Req carrying the device's own serial number is
  answered, PID 61 octets with reserved bits set are accepted and the bits
  ignored, and a secured group telegram is checked in the standard's order,
  a tool-access flag on it counting an access error.
- A secured download checks the group key table (PID 53) and the security
  individual address table (PID 54) against the device's capacity before it
  opens anything, and refuses with the counts instead of failing after the
  `Unload` (#537). The capacity comes from the application's
  `MaxSecurityGroupKeyTableEntries` and `MaxSecurityIndividualAddressEntries`,
  which the importer now keeps (product model format 9, `data_secure:`;
  `describe` shows them), else from the property description's maximum element
  count read from the device. knx-sim takes the capacities from its product
  and reports them in the description.
- `apply` on a System B device reloads the group-object table when it differs
  from the one a full flash writes (#540). Before, a link to an object the
  last flash left unlinked was written and verified, but the object's
  communication flag stayed off and the device ignored the link. `plan` reads
  the table with the device's product data and names each descriptor that
  changes; `apply`, `apply --line` and the MCP apply reload the table before
  the link tables and read it back. Without product data `plan` names the
  newly linked objects whose flag it could not check.
- A com-object's transmission priority now reaches the device (#541). The
  product's `Priority` (`High`, `Alert`, `System`; a ref overrides its base
  object) is written into bits 9-8 of a System B group-object descriptor and
  bits 1-0 of a System 7 CONFIG octet; before, every descriptor went out Low.
  The product model carries it as `priority:` (model format 8).
- The System B parameter-only download, and the parameter part of `apply`, run
  the partial download of Configuration Procedures §3.5.3 as ETS runs the
  product's `par` procedure: Unload, Load, the relative allocation in Mode 0,
  the writes at the base the device reports after the allocation,
  LoadCompleted (#543). It refuses an object that is not `Loaded` before the
  Unload, writes the whole image where the device moved the segment, and stops
  where the reference reads zero. The MCB check stays.
- knx-sim follows the load state machine transition table (Resources Table
  94): StartLoading in Loading stays Loading, LoadCompleted or an allocation
  in Unloaded stays Unloaded; it refuses PID 5 writes shorter than 10 octets,
  zeroes `PID_TABLE_REFERENCE` on Unload and on a failed allocation (new
  `max_allocation` device option), executes master-reset erase codes 2 to 6
  and 8, and answers error code 3 for a channel number other than 0 (#544).
- The association table's entry format is now read from the device (the
  property description of `PID_TABLE`) by `describe`, `adopt`, `apply` and the
  flash pre-flight, which refuse a format-0 table (one-octet TSAP and ASAP)
  instead of misreading or overwriting it; the flash records the format in its
  device facts. Com-object sizes follow the full value field type table
  (Resources Table 88, up to 252 octets), and a System B plan refuses an
  `ObjectSize` without a code instead of writing it as 1 bit (#545).
- A load procedure's `LdCtrlMasterReset` now goes out as the confirmed Master
  Reset with the op's erase code and channel number on every device but KNX
  Virtual (which keeps the bare `A_Restart` its capture shows); an
  "unsupported erase code" answer falls back to a basic restart, as the
  standard asks of a client that finds no support. The restart process time a
  device announces is waited out in full, with a warning above 60 s, instead
  of being capped at 60 s (#546).
- System 7: when the configuration shows none of the group objects the
  Dynamic section declares, the flash keeps each descriptor at the template
  with the communication flag cleared, as ETS does, instead of writing the
  product refs' flags (20 ABB and Busch-Jaeger applications, #562).
- A `<choose>` on a `ParameterRef` that is not itself shown selects no branch,
  even when another ref of the same parameter or a `<Union>` sibling is shown, as
  in ETS (#563). The ABB / Busch-Jaeger Switching Inputs 2.2 no longer writes a
  hidden "send group feedback" default, and the Busch-Jaeger fan coil, valve drive
  and ABB Caldion programs no longer enable the objects ETS leaves out.
- `LdCtrlWriteRelMem Size` bounds what a System B flash streams: an
  application whose `RelativeSegment` is larger than its allocation (ABB
  Caldion, eight corpus applications) no longer writes past the allocation,
  and its MCB check runs over the written length. A parameter value past the
  written size refuses the plan (#564).
- A System B program that declares an ETS download plugin
  (`<Extension EtsDownloadPlugin>`, the Busch-Jaeger DALI gateways) gets the
  group-object table ETS writes: the communication flag on every declared
  object, `04 00` for an object the configuration does not show (#565).
- A management connection that idled past the device's 6 s transport-layer
  timeout reconnects at the next request (drain, `T_Disconnect`, `T_Connect`,
  the authorize key presented again) instead of meeting the device's
  `T_Disconnect` (#575). The S-A_Sync retry backs off at most 2 s, so no pause
  outlasts that timeout; after a restart it makes seven attempts over about
  32 s (was five over 30 s) (#575). An `A_MemoryExtended_Write` confirmed with
  `E_SUCCESS_WITH_CRC` (01h) is a success whose CRC is compared with the one
  over the written request (#575).
- knx-sim honours the `Mode`/`Fill` octets of a relative allocation
  (Configuration Procedures §3.5.1.2): a filled download over a previous image
  no longer leaves that image's octets where the new one equals the fill byte,
  which failed the MCB check of the ALLinBOX 1612 sim-loop runs (#581).
- `bussard apply` on a System 7 device now writes what ETS's partial download
  writes (#588): it no longer writes the address table's first entry (the
  device's own address), it sends the product's own allocation record for each
  table segment (the whole segment with the product's access octet, as `flash`
  does, instead of the written length with access `f2`), and it rewrites the
  group-object table on LSM 3 also when no communication flag changes. The
  EK-E72 partial-download oracle rows are identical on memory and load control.
- `tools/ets-sweep/synthetic/sign.py` writes a directory signature ETS 6.4
  accepts (the signer signed from a relative path before, and ETS refused the
  file with "Projektdatei hat keine gültige Signatur"); the signed DA.tp clone
  imports into ETS's catalogue. `--dir-only` signs without rehashing (#596).
- knx-sim keeps an object that is in `Loading`, with its allocated segment,
  across a master reset with erase code 4, 5 or 6, so ETS's KNX Virtual DA.tp
  download (StartLoading, RelSegment, master reset erase code 4, parameter
  writes) completes again. Outside a load procedure the reset still unloads
  (#600).
- `bussard flash` and the MCP flash detect KNX Virtual by its `M-00FA_A-25xx`
  application ids (the "KNX Virtual" catalogue section 25), not by
  manufacturer `0x00FA` alone. Other `M-00FA` applications (OpenKNX, the
  synthetic catalogue) now get the confirmed Master Reset and hold one
  connection for the download, like every other device (#605).
- `bussard flash` of a product without `knx_master.xml` (or with a `<KNX/>`
  stub, as the synthetic product catalogue ships) plans the full download of a
  `MergedProcedure` application: bussard carries the complete-download
  load-procedure template of the System B masks 07B0, 27B0 and 57B0 and uses it
  when the product's master data has none for the mask. A product's own master
  data still wins, so vendor downloads are unchanged (#607).
- `tests-support/product-corpus/fetch.sh` fills `cache/vendor/` again instead
  of letting `import-product` move it into `cache/products/` (#608).
- `bussard flash` sends a load procedure's `LdCtrlMasterReset` as the
  confirmed Master Reset (`A_Restart` restart type 1 with the erase code and
  channel) to every device, KNX Virtual included, as ETS does. The KNX Virtual
  DA.tp capture shows ETS sending that form and the device answering it; the
  bare `A_Restart` bussard sent there was a misreading of the capture's other
  restarts. A device that refuses it (error code 2, "unsupported erase code")
  now fails the flash, as it fails ETS's download, instead of getting a Basic
  Restart ETS never sends (#611).
- `bussard flash` plans the 27 Siemens 07B0 applications whose product
  procedure wraps the unload of object 5 in `LdCtrlMapError` (#614). The op is
  typed: the unload goes to object 5 and a device without that object (count 0
  answer) completes it; any other failure still fails the step. A procedure
  that lists its `par` and `grp` downloads after the complete one runs only
  the complete one, its table segments on LSM 1 to 3 take the table images,
  and `LdCtrlCompareProp` reads the element its `StartElement` names.
- `flash` runs `LdCtrlDelay`: the op pauses the download for its
  `MilliSeconds` on System B and System 7, shows as a step in the plan and in
  the `-v` log, and no longer refuses the 16 System 7 (0701) applications that
  put a 200 ms delay before the restart (#615).
- An `HSV` colour parameter (`TypeColor Space="HSV"`) is written as ETS
  writes it: the `#RRGGBB` value is converted to hue, saturation and value
  octets (`#FF0000` is `00 FF FF`) instead of being placed as the RGB octets.
  Read-back and `bussard device` show the held octets as an RGB value that
  converts to the same octets. Pinned by three synthetic ETS captures (#616).
- A `TypeColor` parameter (`Space` `RGB`, `RGBW` or `HSV`) has its own type:
  its value `#FF0000` is written as one octet per component in the written
  order, read back and shown by `bussard device` the same way, and checked
  when set. The flash refused it as a non-integer, so four Ekinex
  applications could not be programmed at their defaults. Product models move
  to format 11 and regenerate on the next command (#616).
- A re-flash of a device that already holds the application no longer skips
  an object the product's own `LdCtrlMasterReset` then erases (erase code 4
  and every other code that resets a loaded object). Such a plan takes no
  resident-MCB skip and re-downloads every object, so the read-back verifies
  instead of finding the application unloaded (#623).
- knx-sim reports the original manufacturer of an OEM application (`-O0002`
  on Busch-Jaeger's ABB programs) in the program id, as a real device does;
  ETS copies it into the TaskSegment records, and 40 Busch-Jaeger captures
  differed from the house device because the sim reported 0007 (#640).
- `tools/ets-sweep/synthetic/capture.py` refuses to re-capture a synthetic
  product whose XML changed without an `[application] version` bump (ETS keeps
  the application it imported first under the same version and reports
  "imported" anyway), names the version to bump to, and fails when the
  captured download carries another program version than the spec's. A
  re-capture recomputes the row options from the new verdicts and keeps
  hand-set ones. The ETS sweep's `oracle.py` writes `state=fresh` on System 7
  rows, from the same function the synthetic rows use (#650, #640).
- A System 7 load procedure that allocates an absolute segment in parts
  outside any `<choose>`, with a parameter placed in the gap (the Jung
  `A-5015-13`), is planned as ETS downloads it instead of refused: the parts
  are allocated and written, the gap is kept on the device and its parameters
  are reported as kept, matching the synthetic `syn-s7-static-split` capture
  (#657).
- `bussard flash` writes a parameter that lives in an interface-object
  property (`<Parameter><Property …/>`) on System B devices, as ETS does: an
  `LdCtrlWriteProp` without `InlineData` writes the value the parameters
  compose, and the read-back after the flash or an apply compares it. Before,
  the write was skipped and the flash reported success while the device did
  not hold the parameter. A write that no parameter supplies a value for is
  refused. The offline oracle's headline verdict now reads `differs` when the
  memory is identical but the property writes differ (#669).
- A System 7 flash of a 0705 device no longer sends the procedure's
  `LdCtrlTaskSegment` on LSM 5, as on 0701: ETS sends no record for an LSM
  outside 1 to 4 on either realisation (capture `syn-s7-lsm5-0705`), and
  sending it failed the flash with a T_NAK (#680).
- The offline oracle no longer fails rows on ETS-only writes it cannot compare
  (the security object's tool key, send sequence and activation mode command,
  and `PID_PROGMODE` from the address assignment): they are listed as not
  compared. A row that pins `props=` is judged on its memory verdict, with the
  property verdict checked by the pin, so a known property difference no longer
  hides a memory difference (#683).
- A System B group-object table now carries the descriptor of a shown,
  unlinked com object with no flags at all: its priority and size code
  (`03 00` for a Low 1-bit object), as ETS writes it. bussard wrote `00 00`
  (#686).
- knx-sim describes a property a product's load procedure writes with
  `Count` > 1 as `Count` elements of the generic PDT of their size, and takes
  and reads it element by element, so ETS writes it as it would to a real
  device instead of skipping the write (#692).
- `bussard mcp --help` builds the tier flags' tool lists and the tool counts per tier from the server's registration tables, so they always match what the server registers. `--help` texts no longer cite issue numbers. The mask table in the device-support page marks `flash` on `0021` as `property-only` (#704).
- A System B download (07B0, 27B0, 57B0) of an application written over the
  plain memory services switches the device's verify mode on before its first
  `Verify="true"` memory write, as ETS does: it reads `PID_DEVICE_CONTROL`,
  writes bit 2 only when it is clear, and compares the `A_Memory_Response`
  echo of every later write with the octets written. A Data Secure or
  extended-memory application is left alone, as ETS leaves it. The offline
  oracle records ETS's read of the property and does not count the planned
  write where ETS found the bit already set (#705).
- `bussard apply`, `bussard plan`, `bussard flash --parameters-only` and the
  MCP apply compare the interface-object properties a product places
  parameters in (#669) with what the device holds, so a change to such a
  parameter alone is planned and written with its read-back instead of
  ending as "nothing to do". The plan names it (`territory-mark (object 4
  PID 201) = 07, was 5A`; `writes: parameter property (object 4 PID 201)`)
  (#706).
- `import-product --order-number` accepts a vendor download served as a ZIP
  that bundles several products when the index entry's size and SHA-256
  describe one inner `.knxprod` (Ekinex EK-E72): the matching inner file is
  stored and the others are ignored. No match still fails, naming the URL,
  the served ZIP and how many inner products were tried (#711).
- `knx_get_device` lists the parameters a `<ParameterCalculation>` computes in
  `computed_parameters`, with the value a download writes and the
  calculation's id, and `knx_set_parameter` refuses a calculation output (also
  with `force`), naming the inputs to set instead, as ETS shows outputs
  read-only (#712).
- `bussard device`, `bussard doc`, `bussard diff`, `viz` and the MCP model
  tools show a parameter a `<ParameterCalculation>` computes with the value a
  download writes, marked as computed by its calculation, instead of the
  stored value. A `diff` names an output that changes because one of its
  inputs did. The product model carries the calculations (format 13; models
  regenerate from their archives) (#712).
- `apply` on a System 7 device refuses a model whose address count, TSAP or
  ASAP does not fit the one-octet tables, instead of writing the low octet and
  linking the wrong object (#739, #482).
- `knx_apply_device`, with `address` and with `line`, declares the group
  addresses the device files use but `groups.toml` does not define before it
  writes, as `bussard apply` and `apply --line` do, through the same function;
  the result lists them in `declared` (#779).
- After `knx_setup` imports a keyring into the key store, the MCP server
  opens its KNXnet/IP Secure tunnel with the keyring's tunnelling users
  right away; before, they took effect only after a server restart (#779).
  The setup summary names the users the tunnel offers, or, when the keyring
  does not open, says the tunnel is plain until the server restarts with
  `BUSSARD_KEYRING_PASSWORD` set.
- `keys enroll` and `keys add-certificate` load the key store afresh for every
  certificate, so a tool key or group key another command or the MCP server
  saved during the session is kept instead of overwritten. `keys enroll`,
  `keys add-certificate` and `interface secure` (CLI and MCP) refuse to save
  the key store when the file changed since they loaded it, with an error
  that says so, rather than overwrite it (#793).
- Certificate enrolment from chat continues by itself when the phone taps
  Finish: `knx_enroll_certificates` keeps the call open until the session
  ends and returns the summary, with progress notifications while it waits
  (`knx_enroll_status` gains `until_end`). The pairing page then says "Done.
  You can close this tab and go back to your chat." and tries to close
  itself.
- A colour parameter declared as text with a `(?# TypeColor:RGB)` or `(?# TypeColor:HSV)`
  pattern (ekinex, MDT) is written as its 3 colour octets, as ETS does, instead of 7
  ASCII characters over the parameters that follow it. A colour space bussard does not
  encode is refused (#833).
- In a parameter segment without vendor data, the octets no parameter writes now hold
  the fill byte of the full download's `LdCtrlRelSegment` when it pre-fills the
  segment (`00` on Enertex MeTa², MDT and ekinex DALI gateways), as ETS leaves them,
  instead of `0xFF` (#834).
- A download that writes hidden parameters at their defaults now writes those
  of every module instance too, at the instance's base, instead of leaving
  them at the segment fill (#835: MDT and ekinex DALI gateways).
- System 7 flash: a group object whose project data declares no transmission
  priority gets `Low`, as ETS writes it, instead of keeping the priority of
  the product's descriptor template (ekinex 0705 `A-4741-01`).
- System 7 flash: a group object the program declares without any reference
  (a placeholder such as the ekinex `Dummy` object) now has its communication
  flag cleared, as ETS does, instead of keeping the template's.
- A System B download writes the parameters the configuration does not show
  at their defaults only when the program's `MinEtsVersion` is 5 or later, as
  on System 7, and keeps the segment template below 5;
  `PreferPartialDownloadIfApplicationLoaded` no longer keeps it (#838: 40
  sweep rows of Elsner, ekinex, MDT and ABB / Busch-Jaeger programs now match
  ETS).
- On System B, a `<choose>` on a never-shown parameter without memory that no
  `<Assign>` sets selects no `test` branch, as ETS does (#839: Enertex MeTa²
  `b_ParameterAusblenden`).
- `flash` of a System B program without group objects (the ekinex KNX IP
  interface secure) no longer refuses with "no table image was supplied":
  like ETS it allocates the empty address, association and group-object
  tables and writes none of them, and reads each table's own load check.
- knx-sim keeps a `PID_MCB_TABLE` entry a tool writes while the object is
  Loading and reads back its size, CRC control byte and access as written,
  with the CRC it computes over that many octets of the segment (Resources
  §4.2.27). It answered access `0xFF` and the written span's size instead
  (ekinex A-4945, #840).
- The ETS sweep's oracle model gives an IP device whose application declares
  `<BusInterfaces>` its tunnelling addresses in the order ETS assigns them,
  descending from `.255` (1.1.255 to 1.1.248 for eight), and keeps the
  ascending order for one with only `AdditionalAddressesCount` (#840).
- `flash` no longer refuses a load procedure whose property write carries no
  data and writes a property no parameter of the application is stored in
  (the Enertex ViTa presence detector, object type 50001 PID 211). As ETS
  does, it reads that property's description and writes nothing. A write
  whose property a parameter is stored in still needs that value or is
  refused (#841).
- knx-sim describes a property a product's load procedure writes as the
  product declares it: its size from the step's `InlineData`, else from the
  parameters the product stores in the property, else `Count`; a scalar PDT
  where those parameters give one (`PDT_UNSIGNED_CHAR` for the Enertex PID 211
  of object type 50001), else the generic PDT of the element size; write
  level 2. It described the Enertex property as `PDT_VARIABLE_LENGTH` with
  write level 0, under a constant misnamed `PDT_GENERIC_01` (#841).
- Docs: the copy button on a terminal example copies the commands only, not
  the prompt and the output (#849).
- `tests-support/product-corpus/fetch.sh` no longer reports every fetch after
  the first as failed: `import-product` stores `products/manufacturers.toml`
  next to the archives, and the copy into the cache now skips it (#865).
- A DPT 9 value reads as its decimal (`21.54 °C`), not with float noise
  (`21.539999 °C`), in `read`, the monitor and every other decoded view.
- When the operating system refuses bussard access to the local network
  (macOS Local Network privacy, also after a rebuild or update of bussard),
  the bus status, `knx_bus_status` and the bus tools' refusals now say so and
  name the setting to change, instead of `socket error: Broken pipe` or
  `No route to host`. A KNXnet/IP Secure probe that fails with a socket
  error no longer falls back to a plain tunnel, and `knx_bus_status` reports
  no tunnelling user while the bus is down.

### Security

- Writes to a non-loopback gateway are refused unless the user opts in with
  `--allow-remote-gateway` or `BUSSARD_ALLOW_REAL_GATEWAY=1`, and every
  confirmation names the resolved gateway (#74). `BUSSARD_ALLOW_REAL_GATEWAY`
  in a `.env` is ignored with a warning: only the flag or an exported
  variable opens the gate (#251).
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
- Dependencies moved past the RustSec advisories of 2026-10-22: rustls
  0.23.46 (RUSTSEC-2026-0346 to 0349), rustls-webpki 0.103.16
  (RUSTSEC-2026-0382) and webpki-roots 1.0.10 (RUSTSEC-2026-0381) for the
  HTTPS client, and zip 9 (RUSTSEC-2026-0367 to 0369). bussard never called
  the affected `extract` APIs; it reads entries by name. zip keeps the
  miniz_oxide deflate backend, so extracted product archives and `.bussard`
  bundles are byte-identical to before.
- The enrolment page's CSP connects only to its own origin and the hosted
  relay `https://bussard-relay.tmbo.dev`, not to any https or loopback
  host; a self-hosted relay needs a self-hosted copy of the page set as
  `[enroll] page` (#732).
- The enrolment page removes the link from the address bar and the history
  once read (a reload in the same tab still works), and its typed-entry field
  turns off keyboard learning and autofill as far as browsers allow (#791).
- Certificate enrolment speaks protocol v2: one phone per session (another
  phone that opens the link is refused and reported), a slow session code
  (PBKDF2, 10^6 iterations), a session ends when no phone joins within 10
  minutes, 15 minutes after the phone's last sign of life (the open page
  sends one every 5) or after 4 hours, an `invalid` result names no device,
  the relay must be https (plain http only on loopback), and a page or relay
  other than the default gets a warning (#796).
- The relays expire a session 15 minutes after its last write (at most 4
  hours), keep at most 4 long polls per direction, allow 500 messages per
  direction, and the hosted relay allows 10 new sessions per client IP and
  minute (#796).
- The certificate enrolment page moved to `https://bussard-relay.tmbo.dev/enroll/`,
  served by the relay's Worker on the relay's origin with a CSP header
  (`connect-src 'self'`, `frame-ancestors 'none'`), HSTS, `nosniff` and
  `Referrer-Policy: no-referrer` (#797). It is no longer part of the docs
  site; `https://bussard.tmbo.dev/enroll/` shows a notice. This is the new
  default `[enroll] page`. The CI workflows pin every action to a commit SHA,
  the docs toolchain installs with `--require-hashes`, and the vendored jsQR
  1.4.0 has its sha256 recorded and checked.
- `knx_enroll_certificates` shows the certificate page link and its session
  code to you through your chat app (MCP URL elicitation), never through the
  assistant, so a prompt injection cannot hand you another link (#798). No
  tool result carries the link or the code any more. A chat app that cannot
  show a link that way gets a refusal pointing at `bussard keys enroll`.

### Known limitations

- KNXnet/IP Secure over UDP is implemented from the KNX specification and
  verified against knx-sim and the testkit mock only; no real interface has
  been tested, so it runs only with `--secure-transport udp` (#197).
- ETS3-era products shipped only as encrypted `.vd4` files need the ETS
  project export as product source (#135).
- Some Data Secure memory layouts are still inferred rather than confirmed by
  a capture (#71): the order of several entries in the security individual
  address table (PID 54; every capture holds at most one), the meaning of the
  group-object flag bits beyond the two values ETS writes (`0x00`, `0x03`),
  and the `A_PropertyExtDescription_Response` layout (#197). `adopt` notes a
  flag value other than those two.
- System 1 and System 2 masks are classified but not programmable; program
  them with ETS. bussard never activates or deactivates Data Secure on a
  device.
- Release binaries are not yet published.

[Unreleased]: https://github.com/tmbo/bussard/commits/main
