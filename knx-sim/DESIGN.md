# knx-sim — an independent KNX device + bus simulator

`knx-sim` recreates the KNX *device* side in software so a flashing/monitoring
tool (bussard) can be exercised against realistic devices without hardware. It
is an **independent second implementation** of the KNX device-management
protocol: it shares no code with the tool under test, so a shared misconception
cannot hide in both. Two independent implementations meeting on the wire is the
cross-check. The only contract with the tool is the KNXnet/IP wire.

## Why independence matters

If the simulator were built from the same assumptions as the tool, a bug baked
into both would pass every test while both are wrong. So `knx-sim` is built from
the published KNX device-management spec, real ETS captures, and the `.knxprod`
product-data format — not from the tool's source. It is deliberately **strict**:
it rejects out-of-order load-state transitions, writes to the wrong object,
wrong segment sizes, unauthorized writes, and malformed frames. Leniency is what
lets a tool's bug slip through; strictness is what catches it.

## Architecture

```
                KNXnet/IP (UDP)
  tool  <───────────────────────────►  KnxnetIpServer  (net/)
  (bussard)   CONNECT / TUNNELING_REQ         │  wraps/unwraps cEMI
                                              ▼
                                            Bus  (bus/)
                                      routes cEMI L_Data
                                     ┌────────┼────────┐
                                     ▼        ▼        ▼
                                  Device   Device   Device   (device/)
                                   1.1.2    1.1.3    ...
                                   each: memory map + interface objects
                                         + load-state machines
                                              │
                                        emits every telegram +
                                        state change on an
                                     ┌──► observable EventSink ◄── (future HTML viz)
```

### Layers

- **`wire/`** — an independent KNXnet/IP + cEMI codec. Encodes/decodes
  KNXnet/IP frames (CONNECT / CONNECTIONSTATE / TUNNELING_REQUEST + ACK /
  DISCONNECT), cEMI `L_Data`, the TPCI/APCI transport+application layer, and the
  management APDUs (`A_Authorize`, `A_PropertyValue_Read/Write`,
  `A_Memory_Read/Write`, `A_Restart`, `A_DeviceDescriptor_Read`). No dependency
  on the tool's codec.

- **`prod/`** — an independent `.knxprod` reader. The `.knxprod` is a plain ZIP
  of product XML. This reader extracts only the flash-relevant bits: the
  `RelativeSegment` application image (base64 `<Data>`), the `LoadProcedures`
  (`LdCtrlRelSegment` / `LdCtrlWriteRelMem` / `LdCtrlMasterReset`), and the
  interface-object / load-state-machine structure (which LSM indices exist:
  address table = 1, association table = 2, com-object table = 3, application =
  4). It does not reuse the tool's importer.

- **`device/`** — one strict device. Holds a sparse memory map, a set of
  interface objects (each with its properties), and one load-state machine per
  loadable object. Implements the device-side management protocol: authorize,
  the load-state machine (`Unloaded → Loading → Loaded`, driven by
  `PID_LOAD_STATE_CONTROL` load events and sub-commands), segment allocation
  (`AdditionalLoadControls`/`RelSegment`), memory read/write bounded to an
  allocated segment, `A_Restart` master reset, device-descriptor read, and
  property read/write.

- **`bus/`** — the virtual bus. Carries cEMI `L_Data` telegrams. A
  connection-oriented (management) telegram is delivered to the addressed
  device; a group telegram is broadcast to every device and each device reply is
  fanned back onto the bus and returned to the tunnel client. A tool-originated
  group write is also echoed back to the sender as an `L_Data.con` — a real
  gateway confirms every request it puts on the bus, and the connected
  monitor/viz relies on that echo to see its own writes (issue #64). Every
  telegram and every device state change is published to an `EventSink` — the
  seam the HTML visualization consumes. The bus only observes; it never mutates
  device state directly.

- **`net/`** — the KNXnet/IP tunneling *frontend*. Presents a gateway endpoint
  so the tool connects exactly as it would to a real KNXnet/IP interface. It
  terminates the tunnel, unwraps cEMI, hands it to the bus, and wraps device
  responses back into `TUNNELING_REQUEST` frames toward the tool. Routing /
  multicast is a later addition; the seam is a `Frontend` boundary.

- **`config/`** — file-driven configuration (YAML), mirroring the tool's
  file-first philosophy. A config declares the bus (gateway `host:port`) and a
  list of devices (individual address, path to a `.knxprod`, application ref,
  initial load state). Loading a config spins up that virtual installation.

## The observable event stream (the viz seam)

`bus::EventSink` is a trait with one method, `emit(&self, Event)`. `Event`
covers every telegram (`Telegram { direction, cemi }`) and every device state
change (`LoadStateChanged`, `MemoryWritten`, `PropertyWritten`, `Restarted`,
`AuthChanged`). Phase 1 ships two sinks: a `TracingSink` that logs each event to
stdout as a placeholder, and a `FanoutSink` for composing several. A future HTML
visualization is just another `EventSink` that renders device tiles (load state,
memory, authorization) and a live telegram log. Because the bus emits, never
queries, the viz is strictly read-only.

## How the future vision slots in

- **Multi-device installs.** The `Bus` already holds a map of devices keyed by
  individual address and dispatches management telegrams by destination IA. Add
  more `[[devices]]` entries and the same dispatch serves them. No structural
  change needed; group-telegram broadcast is the main missing piece.
- **HTML visualization.** A new `EventSink` implementation subscribes to the
  same event stream the `TracingSink` uses today and serves a read-only page.
  Nothing in the device/bus needs to change.
- **Routing / multicast.** Add a `RoutingServer` alongside `KnxnetIpServer`
  behind the same `Frontend` seam; both feed the one `Bus`.
- **Product-corpus generalization.** The `prod/` reader targets the
  flash-relevant subset today. Broadening it to more masks/products is additive:
  more `LdCtrl*` ops and mask-specific memory layouts, same `Device` model.

## Calibration against the real device

The DA.tp product (`M-00FA_A-2500-10-51CB`, mask MV-07B0 = System B) is the
calibration target. The simulator, loaded with the DA.tp `.knxprod`, must
**accept** the exact management sequence ETS sends to flash the real KNX-Virtual
device (captured in `dumpfile.pcap`) and reach `Loaded` on all four loadable
objects, and must **reject** deliberate deviations (e.g. a memory write to the
wrong object or an out-of-range address). The captured sequence, distilled to
management APDUs, is the oracle encoded in `tests/`.

### The System B flash sequence (from the ETS→KNX-Virtual capture)

1. Connect; `A_Authorize(FF FF FF FF)` → level 0.
2. `PID_LOAD_STATE_CONTROL` (PID 5) load event `Unload (04)` on objects 1..5.
3. `A_Restart` master reset — bare APCI `0x380`, no payload. Device reboots.
4. Reconnect; per loadable object: `StartLoading (01)`, then allocate with the
   `RelSegment` sub-command `03 0b <size big-endian>`.
5. Per object: read `PID_TABLE_REFERENCE` (PID 7) to learn the segment base,
   then `A_MemoryWrite` the segment bytes at that base.
6. `LoadCompleted (02)` on each object; write the app-id property; final
   `A_Restart`.

Observed bases and sizes for DA.tp: object 4 (application) → base `0x6000`,
size 256; object 3 (com-object table) → `0x8000`, size 148; object 2
(association table) → `0xC000`, size 22; object 1 (address table) → `0xA000`,
size 12. The device reports these bases via PID 7; the simulator assigns them
deterministically so a tool that reads PID 7 gets a stable, real-looking map.

## System 7 devices (mask 0705 / 0701)

Alongside System B the simulator models a **System 7** device, the conformance
peer for the System 7 download path. A per-device **profile**
(`device/profile.rs`) selects the generation: it comes from the product's
`MaskVersion` (`MV-0705` / `MV-0701` → System 7, `MV-07B0` → System B) or a
`mask:` override in `sim.yaml`. `A_DeviceDescriptor_Read` type 0 reports the true
mask, so a tool classifies the device correctly. An unmodelled mask is refused —
the simulator will not pretend to be a generation it does not implement.

System 7 differs from System B in four ways the device model reproduces strictly
(built from `docs/system7-spec.md`, not from any tool):

- **Absolute, memory-mapped download.** No `RelSegment`/`WriteRelMem`. The whole
  download is absolute `A_Memory_Write`s at fixed 16-bit addresses (0x4000
  table region, 0x4201 association/group-object, 0x4400 params, 0x0700 RAM). Each
  `AbsSegment` allocation is validated against the device's memory map and its
  bytes retained per segment; writes outside an open segment are refused.
- **Three parallel load-state machines** (`device/sys7_lsm.rs`,
  `Sys7LoadStateMachine`) instead of one. LSM 1/2/3 are torn down and reloaded in
  order; a `TaskSegment` finalize is a precondition for each `LoadCompleted`.
- **Two `LsmAccess` realisations, both implemented device-side**, selectable per
  device (`lsm_access: memory | property`, default `memory`):
  - **memory-mapped** — a 12-octet load-event record written by `A_Memory_Write`
    to the LSM control address (default 0x0104), with the LSM state polled back
    at the status address (default 0xB6EA+);
  - **property-based** — the 10-octet load event over
    `PID_LOAD_STATE_CONTROL` (PID 5). A memory-mapped device refuses a PID 5 load
    write and vice-versa, so a tool that used the wrong realisation is caught.
- **Wire strictness.** A memory op to a System 7 device must ride a *standard*
  frame and carry at most 12 data octets. An extended cEMI frame or a >12-octet
  memory op is refused — the trap that catches a tool wrongly sending 63-byte
  chunks. Max-APDU is reported as 15; `A_Authorize` (free-access key, or a
  configured `bcu_key:`) gates memory access.

After Loaded, the System 7 device self-parses its own written address /
association / group-object tables in the System 7 byte formats
(`device/sys7_group_comm.rs`, spec §7: 1-byte counts, own-IA slot, 4-byte
group-object descriptors with the on-device CONFIG byte) and participates on the
bus through the same `GroupComm` runtime the System B path uses.

The one property the System 7 download touches, object-0 PID 78
(`PID_HARDWARE_TYPE`), is served as the 10-octet preflight value the MDT
`CompareProp` matches. Per-loadable-object `PID_MCB_TABLE` (PID 27) reads are
also served (some System 7 apps, e.g. Jung `A-A011`, verify via
`LoadImageProp`), reusing the same integrity-block computation as System B.

Calibration constants the spec marks UNKNOWN (the LSM control/status addresses,
the 12-octet record layout, the alloc access/mem_type octets, the CONFIG
synthesis rule) are implemented as the spec's best-evidence defaults and tagged
with the greppable `S7-CAL:` marker for the M2 live-capture pass.

`tests/sys7_calibration.rs` is the System 7 analogue of `ets_calibration.rs`: it
drives the canonical MDT `M-0083_A-000E` op sequence (encoded as raw TPDUs by the
test) to `Loaded` on all three LSMs, for *both* `LsmAccess` variants, and asserts
the strictness refusals.

## Non-goals (Phase 1)

- No HTML viz yet (event stream exposed; `TracingSink` is the placeholder).
- No routing/multicast (tunneling only; seam left).
- Single tunnel client (the viz use case). The frontend tracks one connected
  peer; there is no multi-peer mirroring. Group-telegram runtime behavior —
  broadcast, device replies, write-echo confirmation, and scripted stimulus — is
  implemented and fully visible to that one client.
- System B and System 7 management models and the flash-relevant `LdCtrl*` ops.
  System 7 second-phase ops (`TaskCtrl1`, Zennio `CompareMem`, the post-restart
  LSM-5 dance) are refused cleanly with a named reason (M2).
- Only one device per config is exercised end-to-end, though the bus already
  supports many.
