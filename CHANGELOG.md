# Changelog

All notable changes to bussard are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release, planned as 0.1.0 (#92). This section describes what `main`
does today. A `0.1.0` tag from 2026-09-16 exists but was never released; this
entry supersedes it and is not a diff against it.

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

### Changed

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

### Fixed

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
  shows or hides. Such a change still needs `bussard flash <ia>`, which the
  `apply` refusal and the MCP instructions now say. The lock format is now
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
