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
  property read/write. The interface objects are indexed without gaps (KNX
  3/5/2 §3.28.2, 3/5/1 §4.3.22): an index the product data leaves free below
  the highest object holds a placeholder that answers only
  `PID_OBJECT_TYPE`, since the product data does not say what a real device
  keeps there (bussard issue #1073).

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
3. On object 4: `StartLoading`, the 256-octet `RelSegment`, then the `A_Restart`
   master reset `0x381` with erase code 4, channel 0, answered by
   `A_Restart_Response` error 0, process time 0 (`43 81 04 00`). Device reboots.
   (The bare `0x380`s in the capture are the restart after the address
   assignment and the final restart; bussard issue #611.)
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

The load state machine follows Resources Table 94 with the recommended
transition where the table offers one: StartLoading in Loading stays Loading,
LoadCompleted or an allocation in Unloaded stays Unloaded, LoadCompleted in
Loaded stays Loaded; an allocation in Loaded and anything but Unload in Error
is Error. A PID 5 write value is always 10 octets; a shorter one is refused.
An Unload frees the object's allocation (the octets stay, as the partial
download relies on) and zeroes PID 7, an allocation sets it
again, and a device configured with `max_allocation` fails a larger
allocation (Error, PID 7 zero; Configuration Procedures §3.5.1.2). A device
configured with `intermediate_load_states: n` reports the optional
intermediate states of Table 92 `n` times before the settled one (each write
answer, PID 5 read or memory-mapped status read is one report):
LoadCompleting (5) after a LoadCompleted from Loading, Unloading (4) after an
Unload of a machine that held something. A load event in either state is
ignored and answered with it (Table 94). A master
reset executes erase codes 2 to 8 (KNX 3/5/2 Table 4) and answers error code 3
for any channel number other than 0, since the sim models no channels. The
`master_reset` device option models a device without the Master Reset:
`refuse` answers every erase code with error code 2 ("unsupported erase
code") and runs nothing, `basic` runs the request as a Basic Restart without
an answer (bussard issue #611; ETS 6.4.1 fails a download into a `refuse`
device at the procedure's Master Reset).

A table only ever arrives this way. An `A_PropertyValue_Write` to `PID_TABLE`
(PID 23) is **refused** with a zero-count `A_PropertyValue_Response`, exactly as
a Jung F50 52911ST refused it on the physical campaign (issue #89). ETS never
attempts that path either; only the lenient KNX Virtual stack accepts it, so a
tool validated against KNX Virtual alone can ship a download no real device
performs. The simulator takes the real device's side, with no opt-out.

## System 7 devices (mask 0705 / 0701)

Alongside System B the simulator models a **System 7** device, the conformance
peer for the System 7 download path. A per-device **profile**
(`device/profile.rs`) selects the generation: it comes from the product's
`MaskVersion` (`MV-0705` / `MV-0701` → System 7, `MV-07B0` → System B) or a
`mask:` override in `sim.yaml`. `A_DeviceDescriptor_Read` type 0 reports the true
mask, so a tool classifies the device correctly. An unmodelled mask is refused —
the simulator will not pretend to be a generation it does not implement.

System 7 differs from System B in four ways the device model reproduces strictly
(built from `dev/system7-spec.md`, not from any tool):

- **Absolute, memory-mapped download.** No `RelSegment`/`WriteRelMem`. The whole
  download is absolute `A_Memory_Write`s at fixed 16-bit addresses (0x4000
  table region, 0x4201 association/group-object, 0x4400 params, 0x0700 RAM). Each
  `AbsSegment` allocation is validated against the device's memory map and its
  bytes retained per segment; writes outside an open segment are refused.
- **Three parallel load-state machines** (`device/sys7_lsm.rs`,
  `Sys7LoadStateMachine`) instead of one. LSM 1/2/3 are torn down and reloaded in
  order; a `TaskSegment` finalize is a precondition for each `LoadCompleted`.
- **Two `LsmAccess` realisations, both implemented device-side**, selectable per
  device (`lsm_access: memory | property`). When omitted the mask picks the
  realisation the profile makes mandatory (KNX 6 Profiles §4.2 row 7): memory
  mapped on 0700 and 0701 (both mandatory on 0701, where ETS drives memory),
  property on 0705:
  - **memory-mapped** — an 11-octet load-event record written by `A_Memory_Write`
    to the LSM control address (default 0x0104), with the LSM index folded into
    the high nibble of octet 0 and the state polled back at the status address
    (default 0xB6EA + (lsm - 1)) — the Theben 0701 Meteodata form;
  - **property-based** — the 10-octet load event over
    `PID_LOAD_STATE_CONTROL` (PID 5). A memory-mapped device refuses a PID 5 load
    write and vice-versa, so a tool that used the wrong realisation is caught.
- **Wire strictness.** A memory op to a System 7 device must ride a *standard*
  frame and carry at most 12 data octets. An extended cEMI frame or a >12-octet
  memory op is refused — the trap that catches a tool wrongly sending 63-byte
  chunks. The device object has no `PID_MAX_APDU_LENGTH`, as the house's
  Jung 0705 and 0701 devices; a product whose procedure writes a property
  element longer than a standard frame carries gets the APDU that element
  needs, and its memory ops may then fill that APDU (#996). `A_Authorize`
  (free-access key, or a configured `bcu_key:`) gates memory access.

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

Remaining calibration constants the spec still marks UNKNOWN (the TaskSegment
marker lead/version octets, the residual alloc `seg_flags 0xF3` and last-EEPROM
`checksum_ctrl 0x00`, the CONFIG synthesis rule) are implemented as the analysis'
best-evidence defaults and tagged with the greppable `S7-CAL:` marker. The LSM
realisation, the 11-octet memory record layout and the control/status addresses
are now CONFIRMED by the real-ETS captures (Jung 0705 property, Theben 0701
memory-mapped).

`tests/sys7_calibration.rs` is the System 7 analogue of `ets_calibration.rs`: it
drives the canonical MDT `M-0083_A-000E` op sequence (encoded as raw TPDUs by the
test) to `Loaded` on all three LSMs, for *both* `LsmAccess` variants, and asserts
the strictness refusals.

## System 2 devices (BCU 2, masks 0020 / 0021 / 0025)

A product on mask `MV-0020`, `MV-0021` or `MV-0025` builds a BCU 2
(`Profile::System2`, `device/bcu2.rs`, bussard issue #525). A 0021 product
whose procedure only touches properties still builds the property-only device
of #390. The model follows the KNX Standard 3.0.0 and the mask's own resource
list in `knx_master.xml` (`MaskVersion/HawkConfigurationData/Resources`, which
is how ETS addresses each resource); the clauses are cited by document,
section and page.

**Descriptor and system memory.** `A_DeviceDescriptor_Read` type 0 answers the
mask. A fresh device holds (KNX 9/4/1 §5.1.2.12, pp. 43-47): mask type 00h
and the mask version at 004Eh-004Fh, OptionReg FFh at 0100h, the product
manufacturer at 0101h (also object 0 PID 12), this application's id
(manufacturer, number, version) at 0103h and object 3 PID 13, its PEI type at
0109h, RunError FFh (no error) at 010Dh, and the address table length 1 with
the own address at 0116h. 0117h follows an address change. The system status
at 0060h answers the programming mode in bit 0 and takes it on a write (the
mask's `ProgrammingMode` resource).

**Interface objects** (Profiles Annex A.2.2 to A.2.6; 9/4/1 §5.1.2.13):

| object | type | properties the sim serves |
|---|---|---|
| 0 device | 0 | 1, 12 manufacturer, 14 device control (bit 2 Verify Mode, mandatory, Profiles §4.2 row 3), 15 order info, 16 PEI type (the product's `PeiType`), 54 programming mode, and what the product's compares and writes name |
| 1 address table | 1 | 1, 5 load control, 7 = 0116h on 0020/0021 (fixed, 3/5/1 §4.16.4 p. 226); on 0025 set by the record |
| 2 association table | 2 | 1, 5, 7 from the Segment Control Record (3/5/1 §4.17.4 pp. 247-248), also 0111h |
| 3 application | 3 | 1, 5, 6 run state (read only), 7 group object table from Task Control Record 2 (also 0112h), 13 application id, 16 required PEI type |

There is no object 4 or higher: the mask's `FirstAppObjectIdx` is 4 and the
application interface objects a Task Control Record 1 announces are not
served.

**Load state machines.** Realisation Type 1, property based: Profiles §4.2
row 7 (p. 37) makes it mandatory on BCU 2 and rules out the memory-mapped
Type 2 (Realisation Type 2 applies to the tables, not the LSMs). The 10-octet
records are those of KNX 3/5/2 §3.31.3 (pp. 138-141) on PID 5 of objects 1
to 3; Annex A.2.4.1 Table 7 lists the sub-controls a BCU 2 takes. The device
reuses the System 7 machines (a TaskSegment before each LoadCompleted where
the product's procedure sends one) and adds:

| record | effect |
|---|---|
| `03 00` absolute code/data allocation | must lie in one region of its memory type and not overlap another LSM's segment; the segment opens for memory writes with its access attributes. Otherwise the LSM goes to Error |
| `03 01` stack allocation | refused, Error (not required on BCU 2, Table 7) |
| `03 02` Segment Control Record | allocates nothing. LSM 3: the id to 0103h-0107h and object 3 PID 13, the PEI type to 0109h and object 3 PID 16. LSM 2: the association table pointer. LSM 1: ignored on 0020/0021, the table pointer on 0025 |
| `03 03` TaskPtr, `03 04` TaskCtrl1, `03 05` TaskCtrl2 | LSM 3 only (3/5/2 §3.31.1 table, p. 134); TaskCtrl2 sets the group object table pointer |
| `03 0A`, `03 0B` relative allocation | refused, Error |

The memory regions (9/4/1 §5.1.2.12; Profiles §4.2.9 and §4.2.10): page 0
RAM 00BDh-00DFh (type 1), RAM 2 0972h-09BBh (type 2, UserRAM2 and the PEI
buffers an application may use), EEPROM 0100h-046Fh (type 3, the mask's
880-octet `MemorySegment`), plus every range the product's own procedure
allocates (a device of that hardware has memory there: three Busch-Jaeger
0021 programs reach 07A4h, the 0025 programs allocate above 1C00h).

**Access levels** (9/4/1 §5.1.2.14, p. 54): four levels. `A_Authorize` grants
the level of the matching key, else 3 (free access); all keys are FFFFFFFFh on
a fresh device (§5.1.2.6.1). PID 5 of objects 1 and 2 needs level 1, every
other property write level 0, a memory write the segment's write level (the
low nibble of the record's access attributes, 3/5/2 §3.31.3.4).

**Memory services.** Tables, parameters and the system table arrive by
`A_Memory_Write` on standard frames of at most 12 octets (no
`PID_MAX_APDU_LENGTH`, a 15-octet APDU), inside a segment whose LSM is
Loading. On 0020/0021 a write over 0101h-0102h is refused: the product
manufacturer is never overwritten (9/4/1 §5.1.2.12.5.1, p. 46). RunError and
the system status take a one-octet write outside any segment. With Verify
Mode set every write is echoed as an `A_Memory_Response`.

**Restart and run state.** A basic restart closes the connection; LSM states
and memory stay (EEPROM). The Master Reset (optional, Profiles §4.2 row 11c)
runs as a basic restart without an answer (`master_reset: basic`). Object 3
PID 6 reads Running (1) when the three LSMs are Loaded, RunError is FFh and
the required PEI type equals the connected one (9/4/1 §5.1.2.6.3, p. 41),
else Halted (0).

**Choices an ETS capture must confirm** (the sweep and `syn-bcu2-0021`):

- which octets ETS writes after an allocation: the corpus calibration writes
  the octets the code segment's `<Mask>` defines (the address table mask
  leaves out the own address, the system table mask leaves out 0101h-0109h,
  010Dh and 0111h-0115h), in runs of at most 12;
- the Segment Control Record ETS sends: the program's own id or the id the
  image declares (some 0025 images name a sibling program), and zeros on
  the table LSMs (Cookbook 2/3/1 §3);
- that controls on LSM 5 (`AbsCObjSeg`, Cookbook 2/3/1 §2.3) never reach the
  bus;
- that ETS reads object 0 PID 12 and object 3 PID 13 (and perhaps 0115h,
  the mask's `ManagementStyle`, which the sim answers from memory) and
  writes Verify Mode before the download;
- that an Unload keeps the segments (a partial download, `M-0004_A-9019`,
  writes LSM 3 without allocating);
- the Master Reset answer.

**Not modelled** (refused, or absent with the message saying so): group
communication on the Realisation Type 2 tables (the device stays silent on
the group side), application interface objects, `A_Key_Write`, the
memory-mapped LSM, stack and relative allocation, a BCU 1 application in
compatibility mode (the mask's own procedure writes the system table without
an allocation), checksum control and MCBs, the RAM clear of Profiles §4.2.9,
the user program and PEI.

**Calibration.** No ETS capture of a BCU 2 download exists yet.
`tests/bcu2_corpus.rs` runs each corpus BCU 2 program's own load procedure
through a test-only executor and checks Loaded and the declared image: 90 of
94 load (3 on 0020, 63 on 0021, 24 on 0025), 3 are property-only (#390), and
`M-0004_A-9019` is refused as expected (it writes without an allocation). It
skips without the corpus cache; the same executor runs `syn-bcu2-0021` in CI.

## KNX Data Secure device model

The secure device (`src/secure/`, `src/device/data_secure.rs`,
`src/device/secure_group.rs`, `src/device/security_object/`) is bussard's
conformance peer for Data Secure, so it follows the clauses rather than the
lenient reading. The rules it enforces and where they come from (KNX Standard
3.0.0; TSS J v1.11 test names as the oracle):

- S-A_Sync_Req (KNX 3/3/7 §5.3.2): a request within 1 s of the last
  Sync_Res is ignored unevaluated (step 1); the serial field must be 0 on
  point-to-point or the device's own serial (PID 11), only the own serial on
  a broadcast, checked before the security (step 2; TSS J §3.3.10 to
  §3.3.12); the stored tool-access counter becomes `max(stored, SeqNrlocal -
  1)` and the answer is `stored + 1` (KNX 3/5/1 §6.2 NOTE 94; TSS J §3.3.1).
- S-A_Data: the sequence must exceed the last valid one (§5.3; TSS J
  §3.1.9); after a positive MAC check the six reserved bits above the inner
  APCI must be zero, else the frame is dropped without a count and its
  sequence still counts (§5.2.1.4; TSS J §3.1.12).
- Group reception (§5.5.3.2, §5.2.1.1): the group address's key, the
  tool-access flag (set: an attack, access error 04h), the sender table
  (PID 54, unlisted: dropped without a count), the sequence, the MAC, then the
  group-object flags (KNX 3/5/1 Table 108; TSS J §3.2.3, §3.2.18). Each
  counted failure lands in PID 55.
- PID 61 (KNX 3/5/1 §6.3.15.2 Figure 81): any octet is taken, bits b7..b2
  are reserved and ignored.

## Non-goals (Phase 1)

- No HTML viz yet (event stream exposed; `TracingSink` is the placeholder).
- No routing/multicast (tunneling only; seam left).
- Single tunnel client (the viz use case). The frontend tracks one connected
  peer; there is no multi-peer mirroring. Group-telegram runtime behavior —
  broadcast, device replies, write-echo confirmation, and scripted stimulus — is
  implemented and fully visible to that one client.
- System B, System 7 and System 2 (BCU 2) management models and the
  flash-relevant `LdCtrl*` ops.
  System 7 second-phase ops (`TaskCtrl1`, Zennio `CompareMem`, the post-restart
  LSM-5 dance) are refused cleanly with a named reason (M2).
- Only one device per config is exercised end-to-end, though the bus already
  supports many.
