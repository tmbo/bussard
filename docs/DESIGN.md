# bussard design

> Living design document: what bussard is, why it is feasible, the architecture, and the
> roadmap. Updated as decisions are taken. For a hands-on introduction read the
> [README](../README.md) and [howto.md](howto.md); the complete command
> reference is [reference.md](reference.md), and the file format is specified in
> [model-format.md](model-format.md).

## 1. What we're building

`bussard`: an open-source (MIT), cross-platform CLI for KNX. No GUI.

The goal is to use a configuration-first approach for managing KNX:

- Configuration lives in TOML files in a git repo (group addresses, links, device
  parameters), so changes, including LLM-proposed ones, are reviewable diffs.
- `bussard` compiles those files and pushes them to the devices over the bus.
- `bussard` also observes the bus: live monitor, telegram capture, decode against the
  same model, device introspection.
- An MCP server exposes those read/write operations as tools.

Non-goals: replacing ETS for certification, planning, or documentation. Supporting every
KNX device ever made.

### Design goals (north star)

- Easy and quick to install: a single static binary, no runtime.
- Primary target: home owners and small installations; larger ones later.
- Speed matters for every operation: flushing configurations, validating, getting
  feedback from the bus.
- All configuration is file based.
- Fail fast and fail gracefully; never leave the KNX system or its components in an
  inconsistent, non-functional state.

### Why this is possible at all

The `.knxprod` product-data format is known to the public, the download
procedure is described inside the product data itself (`LoadProcedures`), and open-source
implementations exist for both ends of the problem, just not for the download side.

## 2. The layer cake

A KNX device's configuration is three separable things with very different difficulty:

| Layer | What | Difficulty |
|---|---|---|
| (a) Individual address | `1.1.4` | Standardised management procedure. Trivial. |
| (b) Links | group address table, association table, com-object table | Standardised loadable parts; on System B / mask 07B0+ property-based and writable through documented interface objects. Moderate. |
| (c) Parameters | channel mode, runtime, wind-alarm behaviour, ... | Device-specific memory layout described only in the `.knxprod`. Hard. |

Most day-to-day changes are (b), but all three layers are in scope: the goal is the
entire installation lifecycle in files, from `init` to a running house. `assign` does (a);
`plan`/`apply` do (b) for System B devices. For (c), the loop is closed on System B:
device files carry parameter values per channel (imported from the ETS project,
validated against the product model, #46), and `flash` computes the parameter memory image from
vendor defaults plus those overrides and streams it, using per-module-instance base
offsets (recorded in `bussard.lock`, #48) to place per-channel parameters. Which path links take
(properties on System B vs. memory writes on older System 1/2) depends on the mask
version each device reports; `bussard scan` reports this.

## 3. What's inside a `.knxprod`

A ZIP containing XML (`Catalog.xml`, `Hardware.xml`, ApplicationProgram XML) plus an
RSA-1024 signature. The ApplicationProgram XML contains:

- `ParameterTypes`: enums with value/text pairs, ints with min/max, strings
- `Parameters` with `Offset` / `BitOffset` into the parameter memory block
- `ParameterRefs`, `ComObjects` (DPT + flags), `ComObjectRefs`
- `LoadProcedures`: a declarative download script (`LdCtrlWriteRelMem`,
  `LdCtrlTaskSegment`, `LdCtrlLoadCompleted`, ...) telling the tool exactly how to
  download into this device

The flashing mechanics are literally described in the file. Building a downloader means
writing an interpreter for that little language plus the parameter-to-memory allocator.
XML namespaces differ across ETS 4 / 5.x / 6.x; budget several parser variants.

The signature is authentication, not access control: it stops third parties from making
files ETS accepts; it doesn't stop reading legitimately downloaded files. Vendor
application XML is copyrighted: bussard never bundles extracted product data; users supply
their own `.knxprod` files (available free from manufacturer service sites and the MyKNX
catalogue). The EU interoperability exception (Software Directive 2009/24/EC Art. 6)
covers making an independently created program interoperable, the same footing as Samba
and Wine. Handling details live in [product-data.md](product-data.md).

## 4. Ecosystem survey and licensing constraints

Surveyed 2026-09. Key constraint: bussard is MIT, so GPL code cannot be depended on,
forked, or ported.

| Project | Language | License | Use for bussard |
|---|---|---|---|
| `knx-rs`, `knx-rs-prod` (metaneutrons) | Rust | GPL-3.0-only | Behavioral reference only, clean-room rules. Cannot depend/fork/port. |
| `calimero` | Java | GPL-2.0 + Classpath exception | Reference documentation for management procedures; clean-room rules (read behavior, write a spec, implement from the spec). |
| `knx-go` (vapourismo) | Go | MIT | Primary design reference for KNXnet/IP: parallel Tunnel/Router transports behind one interface. Unmaintained, so reference not dependency. |
| `xknxproject` | Python | MIT | Test oracle for the .knxproj importer (its JSON output vs. ours). |
| `thelsing/knx` | C++ | see repo | Device side of the download protocol; shows what the receiver expects. |
| `OpenKNXproducer` | .NET | see repo | Reference for per-ETS-version XML namespace handling. |
| `knxkit` | Rust | EPL-2.0/GPL-3.0 | Stalled, no routing, pre-production. Not used. |
| `knx-ip` / KNXyz | Rust | MIT | Too new/unaudited for the core. Watching. |

Consequence: the transport + cEMI layer is written from scratch (MIT). The wire surface
is small (~1-2 KLOC): KNXnet/IP framing, tunneling (CONNECT / CONNECTIONSTATE heartbeat /
TUNNELING_REQUEST+ACK sequence counters / DISCONNECT), routing (multicast
224.0.23.12:3671, ROUTING_INDICATION / LOST_MESSAGE / BUSY), and cEMI `L_Data` decode
including 6-bit small APDUs. The `.knxprod` reader (`bussard-prod`) is likewise written
from scratch: parsing XML from a ZIP; signing is never needed since bussard only reads
vendor files.

## 5. Architecture

### 5.1 Crate layout (Rust workspace)

```
crates/
  bussard-model/      # GA/IA/DPT/flags types, DPT codecs, TOML files, loader, validation
  bussard-ets/        # shared ETS-XML primitives: streaming parsers, DPT/flag helpers, zip guard
  bussard-project/    # .knxproj import: AES zip + PBKDF2, streaming XML → model
  bussard-prod/       # .knxprod reading (import-product)
  bussard-transport/  # trait BusConnection; Tunnel + Router impls; cEMI codec
  bussard-bus/        # bus-service actor: one Transport owner, frame subscriptions, L4 leases
  bussard-monitor/    # decode pipeline, SQLite capture, formatters
  bussard-mgmt/       # layer-4 connection-oriented transport, management procedures, table read
  bussard-download/   # LoadProcedure interpreter, table/memory image builder, plan/apply/flash
  bussard-ha/         # Home Assistant config generation (ha-config)
  bussard-secure/     # KNX Secure primitives: .knxkeys keyring, Data Secure session
  bussard-service/    # the layer the surfaces call: gated BusService, L4 sessions, checked write
  bussard-mcp/        # MCP stdio server
  bussard-viz/        # the `bussard viz` web server and its embedded frontend
  bussard-testkit/    # test-only mock KNXnet/IP gateways and devices
  bussard-cli/        # clap binary
```

The separation that matters most: `bussard-mgmt` is fiddly and protocol-correct, heavily
tested against real devices; `bussard-download` is pure-ish computation (model + product
data → byte image), unit-testable without a bus. `bussard-bus` owns the single transport
connection and hands out exclusive layer-4 leases so a management session and live group
traffic share one gateway tunnel slot. `bussard-ets` factors the streaming-XML primitives
shared by the `.knxproj` and `.knxprod` importers.

#### Surfaces and the service layer

bussard has three surfaces: the CLI (`bussard-cli`), the MCP server (`bussard-mcp`) and
the viz server (`bussard-viz`). None of them orchestrates the domain crates for a bus
operation on its own; they go through `bussard-service` (issue #86), which holds the one
copy of each safety rule:

```
  bussard-cli    bussard-mcp    bussard-viz        parse input, render output
        \             |             /
         +------ bussard-service ---+               policy: gate, protected GAs, sessions
        /        |          |        \
  bussard-bus  bussard-mgmt  bussard-model  bussard-secure    domain
```

- `BusService::open(config, WritePolicy)` applies the non-loopback write gate (§8,
  issue #74) before the bus actor is spawned. A transmitting surface cannot obtain a bus
  without it, so a new surface inherits the gate by construction.
- `with_l4` / `connect_l4` run the management-session skeleton (source-address check,
  lease, `T_Connect`, the KNX Data Secure layer from a keyring or tool key, authorize,
  disconnect) that device commands used to copy; `with_device` hands the body the typed
  `DeviceConnection` instead. Every CLI device command opens its sessions this way. A
  command that must authorize at a specific point in its frame sequence (after the
  descriptor read, as `scan` and `assign` do) passes `Authorize::Skip` and authorizes in
  the body. The download engine opens its own connections, so `flash` and `apply` hand
  it a channel from `lease_channel` (or, for the flash connector, a `connect_l4`
  session) rather than a body.
- `prepare_group_write` and `write_group_checked` implement the group-write policy once:
  protected-GA check, DPT resolution, encode (or raw-payload size check), one send. The
  result is a typed `WriteRefusal`; the CLI renders it with a `--force` hint, MCP as a
  hard refusal with no override, viz as an HTTP status.
- `ModelHandle` is the live model the long-running servers share: it reloads when the
  files under `knx/` change and keeps the previous model when a reload fails. The CLI
  loads the model once per invocation.

The crate never prints; prompts, JSON shapes and status codes stay with the surfaces.

### 5.2 The model files

The user's KNX-as-code repository is a directory of TOML files: `bussard.toml`
(connection and lint settings), `groups.toml` (the GA plan), one
`devices/<address>.toml` per device, and the generated `bussard.lock`.
[model-format.md](model-format.md) is the normative contract for every file, key and
error; this section keeps only the decisions behind it.

- **TOML, because the writer is often an LLM.** YAML types a scalar by its spelling:
  `0` is an integer, `1.010` becomes the float `1.01`, `07B0` is a string and `0705` is
  not. Every edit had to get the quoting right. In TOML a string is always quoted and a
  number never is, duplicate keys are a parse error by the spec, and `toml_edit` keeps
  comments and untouched lines byte-identical across a save. A float in a string field
  is rejected, not coerced, because the trailing zero is already gone after parsing.
- **A file is user-owned or generated, never both.** `bussard.lock` is the only
  generated file, and only `import` and `adopt` write it. Every other file belongs to
  the user in full, so there is no hand-editable zone behind a marker.
- **The lock follows `Cargo.lock`.** An `@generated` first line (which GitHub also uses
  to fold the diff), a flat `[[device]]` list sorted by address, one file per model,
  and regenerate rather than hand-merge on a conflict. It holds the vendor facts:
  program, mask, channel ids, the com-object table, parameter refs, module base offsets.
  It is committed because `models/` is not: a checkout without product data must still
  validate, plan, decode telegrams and derive Home Assistant entities.
- **Identity is a value, never a key.** An address in key position needs quotes in
  TOML. `groups.toml` is therefore a list of inline tables, one line per entry, each
  with `address = "0/0/1"`, and a device's identity is its `address` field, which must
  match the file name. Uniqueness moves from the parser to validation (E020), next to
  the other cross-file rules.
- **Device files are channel-centric.** A channel in ETS is one screen with its
  parameters and its objects, and `[channel.<handle>]` is the same. Links live in the
  device file. An entry's shape says what it is: a scalar is a parameter, a table of
  `send`, `listen` and `name` is an object, any other table is a parameter page.
- **Keys come from vendor texts.** ETS never shows a ref id or an object number as the
  primary label, and neither does the file. Import derives the channel handle from the
  channel name and number (`a-1`), object keys from the object function
  (`langzeitbetrieb`) and parameter keys from the parameter text (`betriebsart`), and
  records each mapping in the lock. Values are what the user means: `"Jalousie"`,
  `"21 °C"`. The reader also accepts the vendor forms (object number, enum code). The
  channel's label parameter (ETS `Bezeichnung`) becomes the channel `name`.
- **One parameter per memory cell.** Vendors often point several parameter refs at one
  memory location and show whichever is visible. The file stores one value per
  parameter, the lock records the visible ref, and nine `konfiguration-rtr@R-…` lines
  on a heating actuator become one. Only values that differ from the vendor default are
  stored.
- **Product data is a prerequisite for a readable device.** Parameter texts, enum
  labels and the memory map come from the `.knxprod`, not from the ETS project. Without
  it a device file holds identity, location and links, with vendor channel ids and
  object numbers as keys (`[channel.CH-1]`, `0.send = "0/0/0"`), and its parameters can
  be neither checked nor flashed.
- **Deterministic, minimal diffs.** Sorted, column-aligned emission; bussard re-formats
  only the entries it changes, so re-imports and hand edits produce small diffs.
- **Strict parsing with fix-it hints.** Unknown fields and duplicate keys are errors, so
  a typo never becomes a silent no-op. Parse errors keep the `toml` crate's caret and
  add a `help:` line where the raw message misleads.
- `protected = true` on a GA is the safety gate: the CLI requires `--force`, MCP
  refuses outright.

**The plan is the consent surface.** The loop stays Terraform-shaped:
`import → validate → plan → apply`. The plan is the read-only half of `apply`: bussard
reads the device's live state, diffs it against the files and shows the result before
writing anything. It serves three purposes. It detects drift,
so an empty plan proves the model matches the house. It gives the minimum write, so a
re-run is a no-op. And it is what a human says yes to: a device write cannot be undone
with `git revert`. An agent may compute plans as often as it likes; the agent proposes,
the human reads the final plan, the tool executes.

### 5.3 Validation

Strict parsing, then rule passes with rustc-style diagnostics and `--format json`. The
diagnostic table lives in [reference.md](reference.md#validation-diagnostics); the
rules tied to the file format (E020 to E026) are in
[model-format.md](model-format.md#errors).

### 5.4 Monitor and capture

cEMI → `{timestamp, source, destination GA, APCI, payload}` → resolve GA to name + DPT →
typed value; source resolves to device name, and (source, GA) to the sending com object's
name (from the device file). Unknown GAs/DPTs degrade gracefully to raw hex, never a
failure; decode-size mismatches are shown inline as a debugging signal. `capture` stores
raw cEMI bytes plus a decoded snapshot in SQLite so telegrams can be re-decoded after
model fixes. The JSON Lines contract shared by `monitor --json` and the MCP telegram
tools is specified in [reference.md](reference.md#telegram-json-contract).

### 5.5 MCP server

Stdio server holding the loaded model and a live bus connection feeding a bounded ring
buffer. The tool list, parameters and tiers are in
[reference.md](reference.md#the-mcp-server). The design stance:

- Read-only by default; `--passive` for a server that never transmits; `knx_write_group`
  only with `--allow-writes`, and it hard-refuses `protected: true` GAs with no MCP
  override. The LLM must ask a human, who can run `bussard write ... --force` from the
  CLI. The write tool's description states the consequences plainly for LLM callers
  (actuators move; prefer asking the human when uncertain).
- Programming and download (`plan`, `apply`, `flash`) stay CLI-only and out of the MCP
  surface: they run through a plan/confirm/backup/verify ladder a human drives.
- **Model edits over MCP are first-class.** The primary operator is an assistant working
  for an owner who does not read the model files, so the model is edited through structured tools
  (`knx_set_group`, `knx_add_link`, `knx_remove_link`, `knx_set_device`,
  `knx_set_parameter`, `knx_undo`), never by the assistant hand-writing files. Every edit
  snapshots the model first (§ history, issue #110), applies one well-defined change,
  saves, validates, and returns the change as plain-language sentences (issue #112) the
  assistant quotes to the human. The edit tools write files only, so they are available in
  every tier including `--passive`; `--no-model-edits` withholds them (and `knx_scaffold_groups`, which writes `groups.toml`). Protected GAs are
  refused exactly as `knx_write_group` refuses them, and no tool parameter can set or clear
  `protected`.
- The line is therefore not read versus write, it is **files versus bus**. Files are
  reversible without git (`bussard undo`) and reach nothing physical; the bus is where a
  human confirms.

## 6. Roadmap

**Phase 0, read-only and zero risk. Shipped.** Import an existing `.knxproj` (ETS 6,
including password-protected exports) into the model files. `monitor` + `capture` +
decode. Read-only MCP. This alone delivers LLM-assisted debugging.

**Phase 1, runtime writes. Shipped.** Group value read/write from the CLI, the opt-in
MCP write tool, and Home Assistant KNX config generation from the same model: one source
of truth.

**Phase 2, links. Shipped.** `scan` (device discovery with mask/manufacturer/order
report), `import-product` (`.knxprod` reading with an order-number pointer index, see
[product-data.md](product-data.md)), `assign` (programming-mode address assignment),
`adopt` (the guided new-device wizard), and `reconstruct` (read a System B device's tables
back and diff, plus a `--line` sweep that synthesizes a fresh ETS-less model). The link
downloader itself shipped as `plan` (read-only table diff) and `apply` (backup, write,
verify) for System B devices. The workflows are documented in [howto.md](howto.md).

**Phase 3, parameters and application download. Shipped for System B.** `flash` does the
ETS-free application download from a `.knxprod` into a System B device: pre-flight plan
(mask gate and unsupported-op refusal before any write), progress, `Loaded` + spot-check
verification. The parameter image is computed from vendor defaults plus the device file's
`parameters:` overrides, with `module_bases:` resolving per-channel placement. Hardening
shipped along the way: A_Authorize on every management connect (`flash --bcu-key` for
keyed devices, free access otherwise, #52), per-chunk read-back verification, and strict
load-state checking that fails fast when a device does not honour a segment allocation.
The download runs over a single management connection for its whole duration, exactly as
ETS does; a genuinely dead connection fails cleanly, and re-running `flash` is safe
because the download is idempotent.

**The frontier.** System 7 (mask `0705`, plus `0701`/`0700`) is flashable: its
absolute-addressed procedures (`LdCtrlAbsSegment` allocation and streaming,
`LdCtrlTaskSegment`, `LdCtrlTaskCtrl1`, the obj0/PID78 compare, `LdCtrlCompareMem`) run on
their own lowering, driven by the per-mask profile (see
[system7-spec.md](system7-spec.md)). The System B family covers `07B0` and its `57B0`
(KNX-IP) and `27B0` (RF) variants. The per-mask support table lives in one place,
`MaskProfile::capabilities`, and is rendered into
[SAFETY.md](SAFETY.md#supported-device-masks). Unrecognized ops (notably
`LdCtrlCompareRelMem`, a read-and-compare that blocks two otherwise-executable MDT apps)
are refused whole before any write; `LdCtrlCompareRelMem` is the top roadmap op. System 1
and System 2 masks remain ETS-only.

### The interop wall

The management stack is validated against thelsing/knx as an independent foreign peer,
built and run as a separate process over KNXnet/IP routing by the virtual-device test
harness (see [`tests-support/virtual-device/README.md`](../tests-support/virtual-device/README.md)):
`assign` and `scan` clear it. But the only thelsing binary that speaks KNXnet/IP routing
multicast reports mask `57B0` (KNXnet/IP System B), while `reconstruct`/`apply`/`flash`
gate on `07B0` (TP System B). There is no stock thelsing binary that both speaks IP
multicast and reports `07B0`, so the table-level rungs cannot be reached over routing
without either relaxing the mask gate to also accept `57B0` (they share the same
`BauSystemBDevice` table stack), a modified thelsing variant, or driving `knx-linux-tp`
over a TP-UART. The full table cycle against a foreign peer is therefore still pending;
validating it needs a `07B0`-reporting device (a spare TP actuator, or a TP-UART
variant).

### KNX Virtual notes

KNX Virtual (Windows) is useful for discovery and assign, but is not a faithful flash
target and is not what `flash` is tuned for:

- It reports `Loaded` immediately after StartLoading instead of the conformant `Loading`,
  and it wedges and drops the L4 connection when a too-large foreign vendor application is
  written onto a device that cannot hold it. Earlier releases carried KV-specific flags
  (`--tolerate-nonconformant-load-states`, `--pace`, `--verify batched`, windowed
  `--reconnect-every` reconnect downloads) to work around this. Those were later proven to
  be papering over an over-sized-application mistake, not a real protocol issue: real
  KNXnet/IP gateways and real devices hold one stable connection for the whole download
  and report conformant load states, exactly as ETS does. The workarounds were removed;
  load-state handling is now strict, so a device that cannot hold an application fails
  fast instead of being silently overrun.
- Management reads need a loaded application, so `reconstruct` against a fresh KV device
  has nothing to read until after a first flash.

### Verification strategy (phase 2 onward)

1. Program a device with ETS.
2. Dump its memory over the bus.
3. Store the byte image as a golden fixture.
4. bussard's job is to reproduce it byte-for-byte from the model files.

This turns "did I understand the allocator?" into a failing test. Additionally, run an
independent implementation (Calimero) against the same device and diff the frames.

### The flashability corpus and sweep findings

`tests-support/product-corpus/` turns the product-data pointer index into a repeatable
"can bussard flash this today?" check. `fetch.sh` reads `corpus.txt` (one order number
per index entry) and runs `bussard import-product --order-number … --yes-download` for
each, downloading and checksum-verifying every file into a git-ignored `cache/`. The
env-gated test `crates/bussard-download/tests/flash_corpus.rs` then dry-runs `plan_flash`
over every application program in the cache and reports which lower to an executable
plan, which are refused, and, for the refused System B apps, which load-procedure op
blocked them. With `BUSSARD_PRODUCT_CORPUS` unset the test skips green, so CI never
downloads vendor data. See `tests-support/product-corpus/README.md` for the
clean-machine repro.

A wider one-off sweep read a much larger corpus through the same library code: 220
`.knxprod` files across 8 manufacturers (MDT, Zennio, Theben, Elsner, Lingg & Janke,
Steinel, EAE Technology, Arcus-EDS). The full pointer list (URL, SHA-256, size, vendor)
lives in `tests-support/product-corpus/sweep-manifest.json`; like the index it holds
pointers only, never vendor bytes. The sweep script may unzip a zip-of-`.knxprod`
locally, which the committed index deliberately does not.

Headline numbers: 384 application programs, 83 executable, 4 refused, 0 parse failures.
`read_knxprod` parsed every one of the 220 files without error, over schema versions
`/11`, `/13`, `/14`, `/20`, `/21`, `/23` and 13 distinct mask families, including
BCU1/BCU2, KNX-RF and coupler masks. Only the 82 System B (`07B0`) apps are flash
candidates, and 78 of those lower to an executable plan.

What blocked the four refusals:

- **`LdCtrlCompareRelMem` (2 apps).** A masked, inverted relative-memory verify op the
  parser keeps as `LoadOp::Raw` and the planner refuses (MDT BE-GTSx6Tx, MDT JTA blind
  push button). The top roadmap op: it is a read-and-compare sitting inside
  otherwise-complete procedures.
- **Enum default not a declared member (2 apps).** The Zennio Z40 and Z70 v2 panels
  declare a parameter whose own default `Value` is not one of its enumeration's members,
  so `compute_parameter_image` refuses the whole download (`UnresolvableImage`). The
  strict membership check has real user cost here: it blocks two otherwise fully
  executable panels over a vendor data-quality quirk.

Other unhandled load ops the sweep surfaced (all kept as `LoadOp::Raw`, none yet blocking
an executable procedure): `LdCtrlTaskCtrl2`, `LdCtrlTaskPtr`, `LdCtrlDeclarePropDesc`,
`LdCtrlDelay`, `LdCtrlCompareMem`. Load-op use splits cleanly by mask family: System B
(`07B0`) procedures are property-and-MCB based (`RelSegment`, `WriteRelMem`,
`LoadImageProp`, `CompareProp`), System 7/2 (`0705`/`0701`/`0021`) procedures are segment
based (`AbsSegment`, `WriteMem`), and the RF/coupler masks are where the
`TaskCtrl2`/`TaskPtr`/`DeclarePropDesc` ops appear.

Parameter-type coverage: the four encodable shapes dominate (Int, Enum, Text, Float).
Six type elements fall through to `ParameterType::Other` and are preserved by name but
encoded only as a byte-multiple fallback: `TypeColor`, `TypeTime`, `TypeIPAddress`,
`TypePicture`, `TypeRawData`, and stray `TypeRestriction`. None is silently dropped.

Each new construct has a fabricated regression fixture (fake data reproducing the
structural shape, never vendor content) under `crates/bussard-ets/tests/fixtures/` and
`crates/bussard-prod/tests/fixtures/`; see those directories' `README.md` for the
intended test per fixture. The sweep is a point-in-time study, not a CI job; the
committed corpus (`corpus.txt` + `flash_corpus.rs`) is the ongoing check.

## 7. Performance

Be precise about what's winnable. TP1 is 9600 baud (roughly 30-50 telegrams/s), so the
frame count of a big download is fixed. Winnable: startup overhead (sub-second to first
frame vs. ETS project-open latency), pipelining independent device operations, extended
frames/larger APDUs where the mask supports them, and differential downloads by default.
Expect a large multiple on multi-device operations, near-parity on a single big download;
the everyday win is a group-address change in ~2 seconds instead of a minute.

## 8. Constraints and guardrails

- **Tunnel contention.** Cheap KNXnet/IP interfaces allow few tunnel connections, and a
  home-automation system may hold one. Routing (multicast) is a first-class transport,
  decided in the transport crate's API from day one.
- **Bus flooding.** Rate-limit writes; an agent in a retry loop must not brown out TP1.
- **MCP safety.** Read-only by default; writes only through an approved plan; denylist
  for safety-critical objects.
- **Failed download leaves a device unloaded.** `apply` writes a pre-state table backup
  under `captures/backups/` before any write; a re-apply is idempotent. `flash` has no
  backup (a factory-fresh device has no prior application to save), so recovery there is
  a re-flash or an ETS download. Keep a fresh `.knxproj` backup as the last resort.

## 9. The hard residue

- **ETS DCA plugin devices**: configured by compiled .NET, no XML to interpret. These
  stay ETS-only, permanently. Audit target installations for them early.
- **KNX Data Secure**: secure commissioning with the FDSK is additional work where
  enabled.
- Per-manufacturer quirks that ETS handles by special-casing.
