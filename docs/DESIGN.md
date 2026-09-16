# bussard design

> Living design document: what bussard is, why it is feasible, the architecture, the
> YAML model reference, and the roadmap. Updated as decisions are taken. For a hands-on
> introduction read [getting-started.md](getting-started.md) first.

## 1. What we're building

`bussard`: an open-source (MIT), cross-platform CLI for KNX. No GUI, ever.

The goal is to replace ETS for day-to-day work on an existing KNX installation:

- Configuration lives in YAML files in a git repo (group addresses, links, device
  parameters), so changes, including LLM-proposed ones, are reviewable diffs.
- `bussard` compiles that YAML and pushes it to the devices over the bus.
- `bussard` also observes the bus: live monitor, telegram capture, decode against the
  same YAML model, device introspection.
- An MCP server exposes those read/write operations as tools.

Non-goals: replacing ETS for certification, planning, or documentation. Supporting every
KNX device ever made. Any graphical interface.

### Design goals (north star)

- Easy and quick to install.
- Primary target: home owners and small installations; larger ones later.
- Speed matters for every operation: flushing configurations, validating, getting
  feedback from the bus.
- All configuration is file based.
- Fail fast and fail gracefully; never leave the KNX system or its components in an
  inconsistent, non-functional state.

### Why this is possible at all

The `.knxprod` product-data format is already reverse engineered in public, the download
procedure is described inside the product data itself (`LoadProcedures`), and open-source
implementations exist for both ends of the problem, just not the middle. Nobody has built
the ETS-side downloader. That's the contribution.

## 2. The layer cake

A KNX device's configuration is three separable things with very different difficulty:

| Layer | What | Difficulty |
|---|---|---|
| (a) Individual address | `1.1.4` | Standardised management procedure. Trivial. |
| (c) Links | group address table, association table, com-object table | Standardised loadable parts; on System B / mask 07B0+ property-based and writable through documented interface objects. Moderate. |
| (b) Parameters | channel mode, runtime, wind-alarm behaviour, … | Device-specific memory layout described only in the `.knxprod`. Hard. |

Most day-to-day changes are (c). bussard ships (a) + (c) first: that's real commissioning,
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
  `LdCtrlTaskSegment`, `LdCtrlLoadCompleted`, …) telling the tool exactly how to download
  into this device

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
| `thelsing/knx` | C++ | — | Device side of the download protocol; shows what the receiver expects. |
| `OpenKNXproducer` | .NET | — | Reference for per-ETS-version XML namespace handling. |
| `knxkit` | Rust | EPL-2.0/GPL-3.0 | Stalled, no routing, pre-production. Not used. |
| `knx-ip` / KNXyz | Rust | MIT | Too new/unaudited for the core. Watching. |

Consequence: the transport + cEMI layer is written from scratch (MIT). The wire surface
is small (~1–2 KLOC): KNXnet/IP framing, tunneling (CONNECT / CONNECTIONSTATE heartbeat /
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

### 5.2 The YAML model (the user's KNX-as-code repo)

```
knx/
  bussard.yaml      # connection config: transport (tunnel|routing), gateway, multicast
  groups.yaml       # group address plan
  links.yaml        # com-object → GA assignments
  devices/1.1.4-jalousieaktor-wohnen.yaml
  captures/         # gitignored
```

Conventions: GAs as 3-level strings (`"3/0/4"`), DPTs as `"1.001"`, individual addresses
as `"1.1.4"`, com-object flags as a compact `CRWTUI` string. Emission is deterministic and
sorted so re-imports and hand edits produce minimal diffs. Every generated file carries a
top banner comment saying what generated it, what is hand-editable, and where the docs
live; regenerated sections carry an explicit marker. `bussard import` writes the model
directory via `--dir` (default `knx`), aligned with every other command. Re-import is
idempotent: device files whose address left the project are pruned, and a renamed device
(same `address:`, new name, new filename slug) replaces its old file instead of
duplicating it. `address:` is the device identity; the filename slug is cosmetic.

`groups.yaml` is a map keyed by GA. Names, DPTs, descriptions and `protected:` flags are
hand-editable and survive re-import merges where the address is unchanged. The header
documents the `ranges` key convention (`"3"` = main group, `"3/2"` = middle group):

```yaml
# groups.yaml — the group-address plan (generated by `bussard import`).
#
# Hand-editable: names, DPTs, descriptions and `protected:` flags are yours to
# refine and survive re-import merges where the address is unchanged.
#
# `ranges:` keys name main/middle group ranges: "3" is a main group,
# "3/2" a middle group. Group addresses are keyed as 3-level strings ("3/2/0").
# Docs: https://github.com/tmbo/bussard/blob/main/docs/DESIGN.md#52-the-yaml-model
groups:
  "3/0/4":
    name: "Jalousie Wohnen Süd — Auf/Ab"
    dpt: "1.008"
  "3/2/0":
    name: "Windalarm"
    dpt: "1.005"
    description: "Wetterstation → alle Raffstore-Kanäle; Sperrobjekt"
    protected: true   # safety-critical: CLI needs --force, MCP refuses outright
```

`links.yaml` is keyed by device address; entries reference com objects by their ETS
com-object number (the stable, user-visible handle), with at most one `send` GA and any
number of `listen` GAs, mirroring KNX association semantics. This file is the single home
for the informational com-object `name` (it appears nowhere else):

```yaml
links:
  "1.1.4":
    - object: 12
      name: "A: Behang Auf/Ab"     # informational; refreshed on import
      listen: ["3/0/4"]
  "1.1.30":
    - object: 3
      name: "Windalarm 1"
      send: "3/2/0"
```

`devices/*.yaml` holds hand-edited identity/naming plus a clearly-marked generated
section. The com-object entries carry no `name` (it lives in `links.yaml`) and no `size`
(the payload size is a pure function of the DPT and is computed on demand); a lowercase
`size: "1 bit"` appears only in the rare case where an object has no DPT at all. The
`channels:` block is emitted only when real human channel labels are known; a block that
merely echoes raw channel ids is omitted:

```yaml
# Device file (generated by `bussard import`).
#
# `address:` is the device identity; the filename slug is cosmetic. The identity,
# name, location, product and channel names above `com_objects:` are hand-editable.
# Docs: https://github.com/tmbo/bussard/blob/main/docs/DESIGN.md#52-the-yaml-model
address: "1.1.4"
name: "Jalousieaktor Wohnen"
location: { floor: "EG", room: "Wohnzimmer" }
product:
  manufacturer: "Albrecht Jung"
  order_number: "23024 1S R"
  application_ref: "M-0004_A-20D6-25-D965"   # matches the .knxprod in later phases
  mask: "07B0"                               # decides property- vs memory-based links
channels:
  A: { name: "Raffstore Wohnen Süd 1" }
# --- GENERATED: regenerated on re-import; hand edits here are lost. ---
com_objects:
  12: { dpt: "1.008", flags: "CW", channel: "A" }
```

The loop is deliberately Terraform-shaped: `import → validate → plan → apply`, with
`plan` producing a reviewable diff. That's what makes the LLM workflow safe: the model
edits YAML, a human approves a diff, the tool executes.

### 5.3 Validation rules

Strict parsing (unknown fields and duplicate keys rejected), then rule passes with
rustc-style diagnostics and `--format json`:

| Code | Rule | Severity |
|---|---|---|
| E001 | link references a GA not defined in groups.yaml | error |
| E002 | duplicate individual address | error |
| E003 | link references a com object the device doesn't have | error |
| E004 | conflicting object/DPT sizes on one GA | error |
| W005 | same size but different DPT subtypes on one GA | warning |
| W006 | more than one sending object on a GA | warning |
| E007 | impossible flags (no C flag; `send` without T) | error |
| W008 | listening object with neither W nor U | warning |
| I009 | orphaned com object (T or W, never linked) | info |
| I010 | GA defined but never linked | info |
| W011 | GA without a DPT (monitor can't decode it) | warning |
| E012 | invalid GA (out of bounds, or 0/0/0) | error |

### 5.4 Monitor and capture

cEMI → `{timestamp, source, destination GA, APCI, payload}` → resolve GA to name + DPT →
typed value; source resolves to device name, and (source, GA) to the sending com object's
name (from `links.yaml`). Unknown GAs/DPTs degrade gracefully to raw hex, never a
failure; decode-size mismatches are shown inline as a debugging signal. `capture` stores
raw cEMI bytes plus a decoded snapshot in SQLite so telegrams can be re-decoded after
model fixes.

The JSON Lines contract (used by `monitor --json` and mirrored by the MCP telegram
tools): `ts_utc` (RFC3339 UTC, the same name as the SQLite capture column), `source`,
`source_name`, `destination`, `destination_name`, `dest_type`, `apci`, `payload` (hex),
`value`, `dpt`, `object_name` (the sending com-object's informational name), `note`.
Absent fields are `null` so the schema is uniform.

### 5.5 MCP server

Stdio server holding the loaded model and a live bus connection feeding a bounded ring
buffer. Read tools: `knx_project_summary`, `knx_model_lookup`, `knx_get_device`,
`knx_get_group`, `knx_recent_telegrams`, `knx_wait_for_telegram` (enables
"press the button now" debugging loops), `knx_validate`, and `knx_read_group`
(a GroupValueRead: transmits on the bus, rate-limited, dropped under `--passive`).
`--capture-db` extends `knx_recent_telegrams` history beyond the in-memory ring using a
`bussard capture` database.

One opt-in write tool exists: `knx_write_group` (a GroupValueWrite with human-typed
values, sharing the read rate limiter). It is registered only when the server is started
with `--allow-writes` (mutually exclusive with `--passive`), so the default remains
read-only. It hard-refuses any GA marked `protected: true`; there is no override via MCP.
That stance is deliberate: the LLM must ask a human, who can then run
`bussard write … --force` from the CLI. Its tool description states the consequences
plainly for LLM callers (it writes to the physical bus, actuators move, protected GAs are
refused, prefer asking the human when uncertain). Programming and download (`plan`,
`apply`, `flash`) stay CLI-only and out of the MCP surface: they run through a
plan/confirm/backup/verify ladder a human drives, with the same denylist for
safety-critical objects (wind alarm, central functions).

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
verify) for System B devices. The whole flow is documented in
[commissioning.md](commissioning.md).

**Phase 3, parameters and application download. Engine shipped.** `flash` does the first
ETS-free application download from a `.knxprod` into a factory-fresh System B device:
pre-flight plan (mask gate and unsupported-op refusal before any write), progress,
`Loaded` + spot-check verification. Known gap: load procedures using `LdCtrlAbsSegment`
(absolute segments), `LdCtrlTaskSegment`/`LdCtrlTaskCtrl1`, or vendor ops like
`LdCtrlLoadImageProp` are refused at pre-flight rather than executed; those remain
ETS-only and are a documented follow-up. Per-parameter memory placement (the hard,
device-specific allocator) is next, validated byte-wise against ETS dumps.

### The interop wall

The management stack is validated against thelsing/knx as an independent foreign peer (see
[`tests-support/virtual-device/README.md`](../tests-support/virtual-device/README.md)):
`assign` and `scan` clear it. But the only thelsing binary that speaks KNXnet/IP routing
multicast reports mask `57B0` (KNXnet/IP System B), while `reconstruct`/`apply`/`flash`
gate on `07B0` (TP System B). There is no stock thelsing binary that both speaks IP
multicast and reports `07B0`, so the table-level rungs cannot be reached over routing
without either relaxing the mask gate to also accept `57B0` (they share the same
`BauSystemBDevice` table stack), a modified thelsing variant, or driving `knx-linux-tp`
over a TP-UART. The full table cycle against a foreign peer is therefore still pending.

### Verification strategy (phase 2 onward)

1. Program a device with ETS.
2. Dump its memory over the bus.
3. Store the byte image as a golden fixture.
4. bussard's job is to reproduce it byte-for-byte from the YAML.

This turns "did I understand the allocator?" into a failing test. Additionally, run an
independent implementation (Calimero) against the same device and diff the frames.

## 7. Performance

Be precise about what's winnable. TP1 is 9600 baud (roughly 30–50 telegrams/s), so the
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
  backup (a factory-fresh device has no prior application to save), so recovery there is a
  re-flash or an ETS download. Keep a fresh `.knxproj` backup as the last resort.

## 9. The hard residue

- **ETS DCA plugin devices**: configured by compiled .NET, no XML to interpret. These
  stay ETS-only, permanently. Audit target installations for them early.
- **KNX Data Secure**: secure commissioning with the FDSK is additional work where
  enabled.
- Per-manufacturer quirks that ETS handles by special-casing.
