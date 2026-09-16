# bussard design

> Living design document: what bussard is, why it is feasible, the architecture, and the
> roadmap. Updated as decisions are taken. For a hands-on introduction read the
> [README](../README.md) and [howto.md](howto.md); the complete command and schema
> reference is [reference.md](reference.md).

## 1. What we're building

`bussard`: an open-source (MIT), cross-platform CLI for KNX. No GUI.

The goal is to use a configuration-first approach for managing KNX:

- Configuration lives in YAML files in a git repo (group addresses, links, device
  parameters), so changes, including LLM-proposed ones, are reviewable diffs.
- `bussard` compiles that YAML and pushes it to the devices over the bus.
- `bussard` also observes the bus: live monitor, telegram capture, decode against the
  same YAML model, device introspection.
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
implementations exist for both ends of the problem, just not for the
the download side.

## 2. The layer cake

A KNX device's configuration is three separable things with very different difficulty:

| Layer | What | Difficulty |
|---|---|---|
| (a) Individual address | `1.1.4` | Standardised management procedure. Trivial. |
| (b) Links | group address table, association table, com-object table | Standardised loadable parts; on System B / mask 07B0+ property-based and writable through documented interface objects. Moderate. |
| (c) Parameters | channel mode, runtime, wind-alarm behaviour, ... | Device-specific memory layout described only in the `.knxprod`. Hard. |

Most day-to-day changes are (b). bussard ships (a) + (b) first: that's real commissioning,
genuinely useful, and needs no reverse engineering of manufacturer memory layouts. `assign`
does (a); `plan`/`apply` do (c) for System B devices. Which path links take (properties on
System B vs. memory writes on older System 1/2) depends on the mask version each device
reports; `bussard scan` reports this. Layer (b), parameters, is the phase-3 residue.

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
  bussard-model/      # GA/IA/DPT/flags types, DPT codecs, YAML schema, loader, validation
  bussard-ets/        # shared ETS-XML primitives: streaming parsers, DPT/flag helpers, zip guard
  bussard-project/    # .knxproj import: AES zip + PBKDF2, streaming XML → model
  bussard-prod/       # .knxprod reading (import-product)
  bussard-transport/  # trait BusConnection; Tunnel + Router impls; cEMI codec
  bussard-bus/        # bus-service actor: one Transport owner, frame subscriptions, L4 leases
  bussard-monitor/    # decode pipeline, SQLite capture, formatters
  bussard-mgmt/       # layer-4 connection-oriented transport, management procedures, table read
  bussard-download/   # LoadProcedure interpreter, table/memory image builder, plan/apply/flash
  bussard-ha/         # Home Assistant config generation (ha-config)
  bussard-mcp/        # MCP stdio server
  bussard-cli/        # clap binary
```

The separation that matters most: `bussard-mgmt` is fiddly and protocol-correct, heavily
tested against real devices; `bussard-download` is pure-ish computation (YAML + product
data → byte image), unit-testable without a bus. `bussard-bus` owns the single transport
connection and hands out exclusive layer-4 leases so a management session and live group
traffic share one gateway tunnel slot. `bussard-ets` factors the streaming-XML primitives
shared by the `.knxproj` and `.knxprod` importers.

### 5.2 The YAML model

The user's KNX-as-code repo: `bussard.yaml` (connection), `groups.yaml` (the GA plan),
`links.yaml` (com-object → GA assignments), `devices/*.yaml`. The full layout and every
field are specified in [reference.md](reference.md#the-model-directory); this section
keeps only the design decisions behind the schema.

- Deterministic, sorted emission, so re-imports and hand edits produce minimal diffs.
- Strict parsing everywhere: unknown fields and duplicate keys are rejected, so a typo is
  an error, not a silent no-op.
- Every generated file carries a banner naming what generated it and what is
  hand-editable; regenerated sections carry an explicit marker.
- `address:` is a device's identity; the filename slug is cosmetic. Re-import is
  idempotent: pruned devices leave, renamed devices replace their old file.
- The informational com-object `name` lives only in `links.yaml`; device files carry no
  duplicate. Payload `size` is derived from the DPT and serialized only when no DPT
  exists.
- `protected: true` on a GA is the safety gate: the CLI requires `--force`, MCP refuses
  outright.

The loop is deliberately Terraform-shaped: `import → validate → plan → apply`, with
`plan` producing a reviewable diff. That's what makes the LLM workflow safe: the model
edits YAML, a human approves a diff, the tool executes.

### 5.3 Validation

Strict parsing, then rule passes with rustc-style diagnostics and `--format json`. The
diagnostic table (E001-E012) lives in
[reference.md](reference.md#validation-diagnostics).

### 5.4 Monitor and capture

cEMI → `{timestamp, source, destination GA, APCI, payload}` → resolve GA to name + DPT →
typed value; source resolves to device name, and (source, GA) to the sending com object's
name (from `links.yaml`). Unknown GAs/DPTs degrade gracefully to raw hex, never a
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

## 6. Roadmap

**Phase 0, read-only and zero risk. Shipped.** Import an existing `.knxproj` (ETS 6,
including password-protected exports) into the YAML model. `monitor` + `capture` +
decode. Read-only MCP. This alone delivers LLM-assisted debugging.

**Phase 1, runtime writes. Shipped.** Group value read/write from the CLI, the opt-in
MCP write tool, and Home Assistant KNX config generation from the same YAML: one source
of truth.

**Phase 2, links. Shipped.** `scan` (device discovery with mask/manufacturer/order
report), `import-product` (`.knxprod` reading with an order-number pointer index, see
[product-data.md](product-data.md)), `assign` (programming-mode address assignment),
`adopt` (the guided new-device wizard), and `reconstruct` (read a System B device's tables
back and diff, plus a `--line` sweep that synthesizes a fresh ETS-less model). The link
downloader itself shipped as `plan` (read-only table diff) and `apply` (backup, write,
verify) for System B devices. The workflows are documented in [howto.md](howto.md).

**Phase 3, parameters and application download. Engine shipped.** `flash` does the first
ETS-free application download from a `.knxprod` into a factory-fresh System B device:
pre-flight plan (mask gate and unsupported-op refusal before any write), progress,
`Loaded` + spot-check verification. Known gap: load procedures using `LdCtrlAbsSegment`
(absolute segments), `LdCtrlTaskSegment`/`LdCtrlTaskCtrl1`, or vendor ops like
`LdCtrlLoadImageProp` are refused at pre-flight rather than executed; those remain
ETS-only and are a documented follow-up. Per-parameter memory placement (the hard,
device-specific allocator) is next, validated byte-wise against ETS dumps.

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
over a TP-UART. KNX Virtual (Windows) works for discovery and assign, but management
reads need a loaded application. The full table cycle against a foreign peer is therefore
still pending; validating it needs a `07B0`-reporting device (a spare TP actuator, or a
TP-UART variant).

### Verification strategy (phase 2 onward)

1. Program a device with ETS.
2. Dump its memory over the bus.
3. Store the byte image as a golden fixture.
4. bussard's job is to reproduce it byte-for-byte from the YAML.

This turns "did I understand the allocator?" into a failing test. Additionally, run an
independent implementation (Calimero) against the same device and diff the frames.

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
