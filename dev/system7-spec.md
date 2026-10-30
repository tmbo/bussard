# System 7 download specification (mask 0705 / 0701)

> Implementation-grade spec for two independent implementers building in
> parallel from this document alone: (1) the bussard System 7 download path
> (`bussard-download` lowering + `bussard-mgmt` primitives), and (2) the
> knx-sim System 7 device model. Both must converge on the same wire bytes.
> Grounded in a standards research pass and an archaeology of the 49 System 7
> applications of the product corpus (issue #49); their notes were working
> files and are not in the repository, so the claims below cite the KNX
> Standard, the corpus counts and the captures directly (#482).

## 0. Confidence discipline (read first)

Every byte-level claim below is tagged **CONFIRMED** (with source), **INFERRED**
(reasoned from an allowed source, residual risk noted), or **UNKNOWN** (needs a
live capture). The two research inputs disagree on exactly one load-bearing
point (the LSM realisation, section 5); this spec resolves it by requiring a
seam and a default, not by picking a winner on paper.

Rule for implementers: treat every UNKNOWN as "build the seam, pick the
best-evidence default, and leave a calibration TODO tagged with the greppable
marker string `S7-CAL:`". Do not hardcode an UNKNOWN as if it were CONFIRMED.
At M2 (section 9) a single ETS capture against a real Jung 0705 device settles
the UNKNOWNs; every `S7-CAL:` marker names precisely which constant that
capture must confirm.

Source shorthand: `[XKNX PR#NNNN]`, `[Res §X]` (KNX 3/5/1 Resources
v01.10.01), `[MP §X]` (3/5/2 Management Procedures v02.01.02), `[Prof §X]`
(Volume 6 Profiles v02.01.01), `[BCU §X]` (9/4/1 BCUs v01.02.01), `[TSSG §X]`
(Volume 8 Load State Machines Tests v01.02.01), `[AL 03.03.07 §X]`,
`[corpus: N/49]`, `[Selfbus]`, `[endrekatona]`, `[Kögler SDK]`, `[issue #49]`
(bussard first-party evidence). The research and corpus notes this spec grew
from are not in the repository (#482).

**Checked against the standard (2026-10-28).** This spec was written before
the KNX Standard 3.0.0 text was available under `dev/knx-standard-3.0.0/`
(read-only, licensed: cite sections, never paste). The review of the System 7
and System 2 clauses corrected the statements marked `[Res §…]`, `[MP §…]`,
`[Prof §…]` below; the findings that need code are #524 to #530 and the older
#479, #481, #482, #487, #488, #489. In the standard's words masks 0700, 0701
and 0705 are the "BIM M112" device profile `[Res §4.1.2.2, Table 7]`; the
memory-mapped load procedure is restricted to mask 070nh `[MP §3.31.2]`.

---

## 1. Scope

**In scope:** masks `0x0705` and `0x0701` on TP1 (`MaskFamily::System7` in
`crates/bussard-mgmt/src/profile.rs`). The download path: link tables (address,
association, group-object) and the application/parameter image, driven by the
`.knxprod` LoadProcedure. `A_Authorize`, absolute `A_Memory_Write`/`_Read` in
standard frames, the three parallel load-state machines, verify by read-back.

**Out of scope (refuse cleanly, name the reason):**
- BCU1-era System 1 masks `0x0012` / `0x002x` and System 2 `0x03xx` [issue #49
  non-goal].
- RF and KNX-IP media. High-nibble `0x2…` / `0x5…` System 7 masks are not
  expected in the corpus; classify but do not drive [research 5.3].
- KNX Secure / Data Secure [issue #49 non-goal].
- Extended-frame long downloads: System 7 has no extended-frame guarantee;
  standard frame only (section 6) [research 5.3, CONFIRMED substance].

0701 and 0705 share the resource model and op set, but the **LSM realisation
differs per mask**; they are NOT identical at the wire level. The profile
`[Prof §4.2 row 7, p. 37]` requires the property realisation (Realisation Type
1, PID 5) on 0701 and 0705 and the memory-mapped one (Realisation Type 2,
0104h / B6EAh) on 0700 and 0701; memory-mapped is optional on 0705, property
optional on 0700. Both are standard; ETS picks memory on 0701 and property on
0705, which two real-ETS download captures show (superseding the earlier
"0701==0705" claim). bussard drives 0700 memory-mapped, the mandatory
realisation there (#526; no 0700 capture exists).

- **Jung `0705`** (M2 issue #70, plus the binaereingang / automitschalter /
  schaltaktor 0705 analysis captures) drives load control **property-based** over
  `PID_LOAD_STATE_CONTROL` (PID 5); see §5.
- **Theben `0701`** (Meteodata 1409207, IA 1.1.202) drives load control
  **memory-mapped**: 11-octet records written by `A_Memory_Write` to `0x0104`,
  status read at `0xB6EA + (lsm - 1)`, with ZERO PID-5 traffic; see §5.

So the download-path realisation branches on the mask (0705 → property,
0700 and 0701 → memory-mapped) via `Sys7Profile::corpus_default_for_mask`. The status
octets of the memory-mapped form are the load states of object types 1 to 4:
B6EAh address table, B6EBh association table, B6ECh application program, B6EDh
PEI program `[MP §3.31.2, p. 134]`, so the "0xB6EC read" in the ETS captures is
the application program's load state, not a generic status octet (#482).

---

## 2. Resource model

System 7 is **memory-mapped and absolute-addressed**: the whole download is a
sequence of absolute segment writes at fixed 16-bit addresses. `[corpus: 49/49]`
There is **no `RelSegment`, `WriteRelMem`, `WriteMem`, or `WriteProp`** anywhere
in the System 7 corpus.

> **Amendment (2026-09-17, Jung 3361-1M):** the freshly fetched Jung
> `M-0004_A-A011` (0705, the reference installation's presence detector) DOES
> use `LdCtrlLoadImageProp` with `prop_id = 27` (`PID_MCB_TABLE`) on objects
> 1-3. MCB verification on System 7 is therefore **app-dependent, not absent**:
> the 49 MDT/Theben/Zennio corpus apps omit it, Jung requires it. Both sides
> must support it: bussard executes `LoadImageProp` on System 7 exactly as the
> procedure demands (per-object MCB, as on System B); the sim's System 7 device
> serves `PID_MCB_TABLE` reads. Read-back compare remains the baseline verify
> for procedures without it. Supersedes the two "no MCB on System 7" claims
> below (section 6).

> **Amendment (2026-09-22, Jung 3361-1MWW, physical campaign, issue #89):** the
> MCB entries are read **one per request**. `LdCtrlLoadImageProp ObjIdx="3"
> PropId="27" Count="6"` does not mean one `A_PropertyValue_Read` with
> `count=6`. Sent that way, the real device answered count 0 with no data: six
> 8-octet entries are 48 octets of value, far past a standard-frame APDU, and a
> real device refuses the whole read rather than answering part of it. The
> 1.1.31 ETS capture reads index 1..=6 with `count=1` each. bussard's
> `read_mcb_table` loops one element per request, and the simulator refuses
> `count > 1` on PID 27 the way the Jung did.

### 2.1 Interface objects

The standard object-type numbers still exist as identifiers even though the
System 7 profile does not serve tables through property arrays [research 1.3,
XKNX `profile/const.py`, CONFIRMED]:

| Object | Type |
|---|---|
| Device | 0x0000 |
| AddressTable | 0x0001 |
| AssociationTable | 0x0002 |
| ApplicationProgram | 0x0003 |
| GroupObjectTable | 0x0009 |

Standard PIDs referenced: `PID_TABLE_REFERENCE` = 7, `PID_DEVICE_DESCRIPTOR` =
83, and `PID_HARDWARE_TYPE` = 78 (the object-0 preflight target, section 4.6).
On 0701 and 0705 the device, address table, association table and application
program objects are mandatory and the group object table object is optional
`[Prof Annex A.2.2]`; `PID_PROGRAM_VERSION` (13) of the application program
object is readable there `[Prof Annex A.2.6]` and carries manufacturer id,
device type and version `[Res §4.2.13]`, the five octets the TaskSegment record
writes (section 4.3, #481).

### 2.2 PID_TABLE_REFERENCE usage

On System B the association table is located via object-2 `PID_TABLE_REFERENCE`
(PID 7). Research states the same *may* hold on System 7 for the association
table [research 1.1, INFERRED-strong from issue #49]. **The corpus contradicts
this for the download path:** there is zero `PID_TABLE_REFERENCE` usage and zero
property-array table access in any of the 49 System 7 apps `[corpus: 49/49,
§5]`. Tables are addressed only by absolute memory (0x4000 / 0x4201).

Resolution: the System 7 **download** takes its addresses from the segment
`Address` attribute (or packs the tables itself under `DynamicTableManagement`,
#383) and never reads PID 7. The **readers** (`plan`, `apply`, `reconstruct`)
ask the device's PID 7 of objects 1 and 2 first and fall back to the product's
bases (#369): the standard has the device set PID 7 to the segment start when
the client allocates and to zero when the resource is unloaded `[Res §4.2.7,
p. 31]`, and the Jung 0705 devices answer it. A zero answer therefore means
"unloaded", not "no such property".

### 2.3 Absolute code segments

Every corpus segment is an `AbsoluteSegment` (`SegmentKind::Absolute`) with a
fixed `Address`; the parser already carries `AbsSegment{lsm_idx, address, size}`
plus the decoded `<Data>` and `<Mask>` payloads (see
`crates/bussard-ets/src/application.rs`, `CodeSegment` / `LoadOp::AbsSegment`).
The segment **`<Data>` IS the payload** to stream to `Address`; there is no
separate write op (section 4.2). Address families `[corpus §3]`:

| Address | Role | Data |
|---|---|---|
| 0x4000 (16384) | LSM 1 table region (address / com-object descriptors). Carries a per-byte `<Mask>`; some products mask their parameter segments too (section 4.2, issue #320). ~511–513 B | present + mask |
| 0x4201 (16897) | LSM 2 table region: the association table. ~511 B | present |
| 0x4400 (17408) | LSM 3 parameter image start; the group-object table lives in an LSM 3 EEPROM segment where `<ComObjectTable>` declares it (#431, #386) | present |
| 0x0700 (1792), 0x0730 | LSM 3 low-RAM working region: the "RAM cleared" area of BIM M112 starts at 0700h `[Prof §4.2.9, p. 40]`; user EEPROM is 4000h to CFFFh `[Prof §4.2.10, p. 41]` | **allocate only, NO `<Data>`** |
| 0x1C00, 0x4800, 0x4C00, 0x8710, 0xB800 | vendor code/param regions (Theben/Zennio) | present |

A segment with `<Data>` == `None` (e.g. 0x0700) is an **allocation-only** record:
the LSM reserves/zeroes device-initialised RAM; no memory write is streamed.

### 2.4 HawkConfigurationData: the load-bearing architecture decision

Do **not** hardcode per-mask addresses in Rust. Every `.knxprod`'s
`knx_master.xml` carries a `HawkConfigurationData` block: the per-mask
programming config (resource/LSM realisation, table locations, memory map,
authorize levels). Parse it at import time (`bussard-ets`) into a data-driven
mask profile, resolved per product [research 1.3, CONFIRMED as the right source;
issue #49 architecture conclusion].

Extract, per mask version:
- **LSM realisation** (property-based vs memory-mapped; see section 5) and, if
  memory-mapped, the LSM control address and status-poll address.
- **Table locations / RealisationType** for address, association, group-object
  segments (or confirmation they come straight from segment `Address`).
- **Authorize levels** required for memory access.
- **Memory map anchors** used for verification.

**Fallback when `HawkConfigurationData` is absent or unparsable:** fall back to
the corpus-derived defaults hardcoded as a *named default profile* (not scattered
constants): LSM realisation = property (section 5 default, M2 CONFIRMED),
addresses from segment `Address`, authorize with the free-access key. The download
must still be attemptable on a device whose product data lacks the block, because
the corpus shape is uniform enough to drive blind.

**M2 caveat on the Hawk block itself.** The Jung MV-0705 `HawkConfigurationData`
carries a `LoadControl_M112 @ StandardMemory 0x0104` block, which pre-M2 was read
as "this device's LSM is a 12-octet memory record". The M2 capture disproved that
reading (control is property; see section 5). So bussard's normal flash path does
**not** feed a parsed Hawk config to the planner; it plans with the property
corpus default. `sys7_profile_from_hawk` stays for the memory-mapped conformance
harness only.

For M1 the sim and bussard MAY share a single hand-written default profile
matching `M-0083_A-000E`; `HawkConfigurationData` parsing is the M1.5 hardening
step. Ship the seam first.

---

## 3. The three parallel load-state machines

System 7 runs **three** LSMs in parallel (System B uses one) `[corpus: 49/49]`:

The LSM index is the object type of the loadable part `[MP §3.31.2, p. 134]`:

- **LSM 1**: the address table, region at 0x4000 (state at B6EAh).
- **LSM 2**: the association table, region at 0x4201 (state at B6EBh).
- **LSM 3**: the application program: parameters, code and the group-object
  table (0x0700 RAM alloc + 0x4400 param image; state at B6ECh).
- **LSM 4**: the PEI program (state at B6EDh); ETS unloads it in its
  pre-download pass, no corpus procedure loads it.
- **LSM 5**: no object type `[MP §3.31.2]`; named only by a tail some converted (pre-ETS4) procedures carry
  *after* the restart (Theben FIX2 `M-0048_A-4947`, Jung 2308.16REGHM
  `M-0004_A-2088-11`: `LdCtrlRestart`, `LdCtrlTaskSegment LsmIdx="5"`,
  `LdCtrlLoad LsmIdx="5"`). ETS sends nothing after the restart (captures
  `meteodata-1-1-202-new.pcapng`, `schaltaktor-8fach-1-1-49.pcapng`), and the
  2308.16REGHM has no object 5 (its `PID_LOAD_STATE_CONTROL` read answers count
  0). bussard cuts the procedure after the terminal restart (issue #178).
  Some procedures name LSM 5 before the restart too: 98 corpus 0701
  applications (Busch-Jaeger, such as `M-0002_A-A002-13`, and the house binary
  input 1.1.44) carry an `LdCtrlTaskSegment LsmIdx="5"` inside LSM 3's load,
  with no `Load` of LSM 5.
  ETS sends no record for it: its download of the synthetic `syn-s7-lsm5`
  (`captures/synthetic/syn-s7-lsm5/defaults/`, ETS 6.4.1) writes 18 records to
  `0x0104`, none with high nibble 5, and 1.1.44's capture has none either. A
  product variant that also loaded and completed LSM 5 failed inside ETS
  ("System.ArgumentException: lsm"). **Rule (issue #489):** under the
  memory-mapped realisation the planner sends no `TaskSegment` record for an
  LSM outside 1 to 4 (`SYS7_MEMORY_MAPPED_LSMS` in `plan_sys7.rs`); knx-sim
  leaves an unopened machine Unloaded on such a record (#529), which failed
  bussard's flash. The property realisation (0705) keeps the record until
  `syn-s7-lsm5-0705` (#604 row 32) shows what ETS does there.

**Two ETS differences bussard keeps (issue #178, 2308.16REGHM `A-2088-11`).**
The application declares `DynamicTableManagement="1"`, and ETS places the
tables itself instead of following the procedure's `LdCtrlAbsSegment`s: it
allocates the address table at `0x4000` with its real length (31 octets) and
the association table right behind it (`0x401F`, 991 octets up to `0x43FE`),
where the procedure says `0x4000`/511 and `0x41FF`/511. bussard follows the
procedure. The table octets are identical, the device reports either placement
through `PID_TABLE_REFERENCE`, and the live flash of 1.1.49 read back 14 of 14
links. The capture's `Unload` of objects 1 to 4 and restart before the
download run on their own connection, ahead of the procedure: an ETS unload
pass, not a procedure step. The procedure unloads 1 to 3 only. bussard
reproduces the pass as a step of its own (section 3.1).

Each LSM is torn down (`Unload`) up front, then loaded in order. The LSM index on
`Load`/`LoadCompleted`/`AbsSegment` names the machine, not an object index. The
mapping LSM-index → memory region is per-mask (from `HawkConfigurationData`;
default per the table above).

### 3.1 ETS prelude and session discipline (issue #116)

Diffing bussard's download of 1.1.36 against the ETS captures left three
differences that change nothing the device stores. This section records what
ETS does around the vendor procedure and what bussard reproduces. Captures:
`schaltaktor-8fach-1-1-49`, `pm-mini-1-1-52`, `bad-eg-pm-1-1-18(-new)`,
`jung-1131`, `binaereingang-6fach`, `automitschalter-standard-110` (0705);
`meteodata-1-1-202(-new)`, `meteodata-140-s` (0701).

**What ETS sends before the procedure.** In order, each on its own L4
connection:

1. *Unload pass* (full downloads only: 1.1.49, 1.1.31, 1.1.1, 1.1.46,
   Meteodata new and 140 S; absent from 1.1.52, 1.1.32 and the Meteodata
   parameter download): `A_Authorize`, `Unload` of LSMs 1, 2, 3 and 4, a
   one-octet `A_Memory_Read` of `0x0060` (answer `00`), disconnect. On 0705
   each unload's `A_PropertyValue_Response` carries the new state (`00`); on
   0701 each record write to `0x0104` is followed by a status read at
   `0xB6EA + lsm - 1`.
2. *Restart pass* (every capture): a connect/descriptor/disconnect probe,
   then connect, descriptor, `PID_MAX_APDU_LENGTH`, `PID_SERIAL_NUMBER`, basic
   `A_Restart`. The device reboots and answers again on a fresh connection.
3. *Procedure connection*: a second probe, then descriptor,
   `PID_MAX_APDU_LENGTH`, `A_Authorize`, `PID_SERIAL_NUMBER`, a one-octet read
   of `0xB6EC`, the load state of the application program (object type 3,
   `[MP §3.31.2, p. 134]`; answer `00`, Unloaded after the unload pass; on
   0701 the reads of `0xB6EA..0xB6ED` are the load states of object types 1
   to 4), `PID_MANUFACTURER_ID`, `PID_HARDWARE_TYPE`, then the procedure.

**Verify mode (`PID_DEVICE_CONTROL`).** On every 0705 download ETS reads
`obj0/PID_DEVICE_CONTROL` (PID 14, answer `00`) right after the first
allocation record and writes `04`. The property is the device-control bit
field of the device object: bit 0 user application stopped, bit 1 own
individual address duplicated, bit 2 verify mode, bit 3 safe state. ETS sets
verify mode only: from then on the device answers every `A_Memory_Write` with
an `A_Memory_Response` carrying the octets it stored (1.1.49: `A_Memory_Write
0x47CA` answered by `A_Memory_Response 0x47CA` with the same 12 octets). The
bit lives in RAM; the device clears it whenever the TL connection closes, and
a client shall set it again on every connection it opens `[Res §4.2.14.7.3,
§4.2.14.7.4, p. 36]`. With it on, every `A_Memory_Write` is answered by an
`A_Memory_Response` and the client treats a different or missing answer as an
error `[MP §3.16.3 DMP_MemWrite_RCoV, p. 101-102]`. bussard compares every
echo with the chunk it wrote and sets the bit again on every new connection
before its next write (#524). Verify Mode is
mandatory on 0700, 0701 and 0705 alike `[Prof §4.2 row 3]`; that the 0701
Meteodata gets no PID 14 access is ETS following the Hawk `VerifyMode` flag of
MV-0701, not a device limitation, and ETS read-compare-writes it instead
(section 4.2 amendment).

**What bussard reproduces.**

- `Sys7PreDownloadRestart`: unload LSMs 1 to 4, basic restart, wait for the
  reboot, reconnect and re-authorize. It goes in front of the procedure's
  first state-changing step, after the vendor's read-only preconditions
  (`CompareProp`, `CompareMem`), so a device that fails them is refused before
  its application is unloaded. The pass follows the device's resident state
  (issue #488, `FlashPlan::fit_sys7_prelude`): a device whose every LSM the
  pre-flight probe reads answers Unloaded, with no application id, gets no
  pass at all; an LSM in Loaded, Loading or Error, a resident
  `PID_PROGRAM_VERSION`, or a probe that read nothing keeps it. Evidence for
  the fresh device: ETS runs no pass in all 31 System 7 sweep downloads and in
  the synthetic captures `syn-s7-0705` and `syn-s7-0701` (`defaults`, a
  factory-fresh knx-sim; after the connect come the identity reads and the
  procedure's own unloads of LSMs 1 to 3, no unload of LSM 4, no restart). On
  a programmed device the captures disagree, so the pass stays as before:
  1.1.31 and 1.1.46 (`jung-1131`, `automitschalter-standard-110`) run the
  full pass, 1.1.32 (`bad-eg-pm-1-1-18-new`, same application as 1.1.31) only
  the restart, and the EK-E72 partial downloads on the sim
  (`captures/ets-sweep/M-00B6_A-4537-03-DE59/b-*` to `d-*`) none; ETS decides
  before reading anything from the device, so the trigger is project state.
  The offline dry run has no device and keeps the pass, unless `--resident`
  records the LSM states; the oracle's `state=fresh` row option records a
  fresh device for a capture that reads none (the synthetic System 7 rows). A
  parameter-only flash restarts without unloading, like the Meteodata
  parameter capture. An LSM the device lacks (count 0) or that answers Error
  is skipped with a warning; the procedure's own unloads stay strict.
- `Sys7EnableVerifyMode` on masks with `VerifyMode` (0705): read PID 14 and
  write it back with bit 2 set, only when the bit is clear, keeping the other
  bits. It goes right after the first `StartLoading`, one record earlier than
  ETS (the allocation and its stream are one step in bussard; nothing depends
  on the order). Each segment write waits for its echo, which must name the
  chunk's address and carry the octets written, or the step fails with both
  values (#524); a missing echo is a silence the resume path retries on a new
  connection. The session sets verify mode again on every connection it
  opens after the step, before the next write; a device that refuses or lacks
  PID 14 streams blind with a warning. An LSM record write (0701, memory-mapped)
  is not echo-checked; its echo, if any, is drained, and `read_memory` skips a
  late echo whose address is not the one it asked for.
- **State read-backs follow the realisation.** On the property realisation
  (0705) the state comes from each PID 5 write's answer, as for ETS, including
  the verdict after `LoadCompleted` when the answer is `01` (Loaded, issue
  #211); an answer without a state octet, or with another state after
  `LoadCompleted`, is confirmed by a separate read. The post-restart verify
  reads each LSM once. On the memory-mapped realisation (0701) the status
  octet is read after every event, as ETS does.
- **One connection.** ETS holds a single L4 connection for the whole
  procedure. bussard cycles the connection proactively only for KNX Virtual
  (manufacturer `0x00FA`, the device class that drops long connections,
  issue #80); `BUSSARD_FLASH_RECONNECT_EXCHANGES` overrides it either way.
  Resume-on-drop still reconnects after an unexpected drop.

**What bussard skips on purpose.** All of these are reads or connection
bookkeeping that change no device state:

- the connect/descriptor/disconnect probes and the separate connections per
  pass (bussard's session already probed the device in the pre-flight);
- `PID_MAX_APDU_LENGTH` re-reads (negotiated once per session and re-seeded
  across reconnects, issue #58);
- `PID_SERIAL_NUMBER`, `PID_MANUFACTURER_ID`, `PID_HARDWARE_TYPE` (identity
  checks the pre-flight covers; a vendor `CompareProp` on PID 78 still runs);
- the `0x0060` read after the unload pass (the programming-mode octet,
  `[Res §4.26.3.4.2]`) and the `0xB6EC` read on the procedure connection (the
  application program's load state `[MP §3.31.2]`; ETS reads it before a
  partial download and refuses on 00, see #481). Neither changes device state.

The effect on the 1.1.49 download (Jung 2308.16REGHM, 184 segment writes),
counted from the plan: the numbered requests bussard sends drop from about 236
to 222 (17 fewer state reads, no re-authorize per cycle) and the L4
connections before the terminal restart from 6 to 2. The telegram count rises,
because each segment write now draws a verify echo and its `T_ACK`, as it does
for ETS: roughly 580 to 890 L_Data frames, against 939 in the ETS capture of
the same download (which adds its probe connections and identity reads).

### Canonical op sequence (MDT `M-0083_A-000E`, smallest 0705, first target)

```
connect
compare_prop obj=0 pid=78 data=00000000031200000000   # preflight (§4.6)
unload lsm=1 ; unload lsm=2 ; unload lsm=3             # tear down all three
load lsm=1
  abs_segment lsm=1 addr=0x4000 size=513               # table region + <Mask>
  task_segment lsm=1 addr=0x4000                        # finalize LSM 1
load_completed lsm=1
load lsm=2
  abs_segment lsm=2 addr=0x4201 size=511
  task_segment lsm=2 addr=0x4201
load_completed lsm=2
load lsm=3
  abs_segment lsm=3 addr=0x0700 size=48                 # alloc only, no data
  abs_segment lsm=3 addr=0x0730 size=1                  # alloc only
  abs_segment lsm=3 addr=0x4400 size=92                 # param image
  abs_segment lsm=3 addr=0x445C size=88                 # param image
  task_segment lsm=3 addr=0x4400
load_completed lsm=3
restart
disconnect
```

The `A_Authorize` handshake and the absolute `A_Memory_Write` streaming are not
named by any op token; they are implied by the `connect` gate and each
`abs_segment`'s `<Data>` (sections 4, 6).

---

## 4. Load-procedure op semantics

The wire realisation of Unload / Load / LoadCompleted (the LSM events) is
section 5. This section is the per-op content semantics.

### 4.1 Ordering / state rules

Abstract LSM states (1 octet, read back to poll) `[Res §4.23.2.3.1, Table 92,
p. 294; CONFIRMED]`; the PID 5 read value is always one octet, the write value
always ten `[Res §4.2.5, p. 30]`:

| State | Value |
|---|---|
| Unloaded | 0 |
| Loaded | 1 |
| Loading | 2 |
| Error | 3 |
| Unloading | 4 (optional) |
| LoadCompleting | 5 (optional) |

Abstract load events (10-octet record, first octet = event, rest zero-padded
unless the sub-command below fills them) `[XKNX `LOAD_EVENT_SIZE=10`]`:

| Event | Opcode |
|---|---|
| NoOperation | 0x00 |
| StartLoading | 0x01 |
| LoadCompleted | 0x02 |
| AdditionalLoadControls | 0x03 |
| Unload | 0x04 |

State transitions the sim MUST enforce, and bussard MUST drive in order
`[Res §4.23.2.3.3, Table 94, p. 296]`: `Unloaded --StartLoading--> Loading
--(AdditionalLoadControls*)--> Loading --LoadCompleted--> Loaded`; `Unload`
from any state → Unloaded, through the optional intermediate Unloading (4);
`LoadCompleted` may pass through LoadCompleting (5) when the commit takes more
than 2 s, and the client then polls PID 5 at most every 3 s and keeps the
connection alive `[Res §4.23.2.4.1]` (#479). A record in Unloaded leaves the
machine Unloaded (recommended) or Error (optional), never Loading (#529); a
record in Loaded, or a `LoadCompleted` outside Loading, is Error. On the
memory-mapped form the client re-reads the status octet up to three times
until it shows the expected state `[MP §3.31.2, p. 135]`.

The **load event record** is the 10-octet form (`[Resources 03.05.01 §4.23.2]`).
`AdditionalLoadControls` (0x03) uses octet 1 as the sub-command selector, big-
endian, total 10 octets `[XKNX, CONFIRMED]`:

| Sub-command (segment type) `[MP §3.31.2, p. 136-137]` | Code | Layout (after `[0x03][type][segment ID = 00]`) |
|---|---|---|
| AllocAbsDataSeg | 0x00 | `[start:2][length:2][access attributes:1][memory type:1][memory attributes:1]` |
| AllocAbsStackSeg | 0x01 | same as 0x00 (#487: send the product's `SegType`) |
| AllocAbsTaskSeg ("Segment Control Record") | 0x02 | `[start:2][PEI type:1][manufacturer:2][application id:2][version:1]` (§4.3) |
| TaskPtr | 0x03 | `[init address:2][save address:2][PEI handler:2][reserved:2]` |
| TaskCtrl1 | 0x04 | `[interface object table address:2][object count:1]` (§4.4) |
| TaskCtrl2 | 0x05 | `[callback address:2][com-object pointer:2][com-object segment pointer 1:2][pointer 2:2]` |

The property form is the same record without the leading state-machine octet
(10 octets); the segment ID octet is 00 in every capture. Access attributes:
bits 0–3 write level, bits 4–7 read level (16 levels on BIM M112, `[Prof §4.2
row 12]`). Memory type bits 0–2: 1 = zero-page RAM, 2 = RAM, 3 = EEPROM.
Memory attributes bit 7 = checksum control. The profile requires types 00, 02,
03, 04 and 05 on 0701 and 0705 `[Prof Annex A.2.4.1, Table 7]`; bussard
lowers all five (`encode_task_ptr` and `encode_task_ctrl2` for 03 and 05, #527;
`LdCtrlTaskPtr` `InitPtr`/`SavePtr`/`SerialPtr` are the init, save and PEI
handler addresses, `LdCtrlTaskCtrl2` `Callback`/`Address`/`Seg0`/`Seg1` the
callback, group-object pointer and the two segment pointers). In the local
corpus the two ops appear only on masks 0020, 0021 and 0025 (and the
knx_master procedures of 0020/0021), which bussard does not flash; no ETS
capture of either record exists yet.

### 4.2 AbsSegment: allocation record + payload

`AbsSegment{lsm_idx, address, size}` lowers to two device actions:

1. **Allocate:** an `AdditionalLoadControls` "Alloc absolute Data segment"
   (subtype 0x00) record for the LSM, filled
   `[event=3][subtype=0][start:2 BE][length:2 BE][access][mem_type][seg_flags][reserved]`
   (`access`, `mem_type` and `seg_flags` are the op's `Access`, `MemType` and
   `SegFlags`; `seg_flags` is the memory-attributes octet, bit 7 checksum control).
   **M2 CONFIRMED** (cross-checked against the Jung app M-0004_A-A011's declared
   AbsSegment addresses/sizes): the opcode/subtype, the big-endian `start` and
   `length` (= the declared segment size in octets), and `mem_type` at octet 7,
   `2` (RAM) for the `0x0700` low-RAM region, `3` (EEPROM) for the `0x4xxx`
   table/param regions. Every captured record's length equals the product's
   declared size (e.g. `0x43FF` size 811 = `0x032B`; `0x4743` size 260 = `0x0104`).
   Octets 6 to 8 are the op's `Access`, `MemType` and `SegFlags` verbatim (172
   of 172 ETS sweep records): the record's access attributes, memory type and
   memory attributes `[MP §3.31.2]`. `0xF2` is read level 15, write level 2;
   `0x80` is checksum control on. bussard's field names are swapped (#482).
2. **Stream payload:** if the segment carries `<Data>`, write those bytes to
   `address` via absolute `A_Memory_Write` in 12-octet chunks (section 6). **The
   segment `<Data>` IS the payload**; there is no separate `WriteMem` op
   `[corpus §2]`. A segment with no `<Data>` is allocate-only; skip the write.

The 0x4000 segment carries a per-byte `<Mask>`: `0xFF` = this byte belongs to the
image, other = device-owned, leave untouched. Under the mask, bussard streams
only owned bytes (still in 12-octet chunks by address run). The sim, on receiving
a write into a masked region, must accept the owned bytes and preserve the rest.

**Parameter segments with a `<Mask>` (issue #320).** Some products mask their
parameter segments as well. The Theben Meteodata 140 S (`M-0048_A-140C-14-EB70`)
masks `AS-4800` with `0x00` runs at offsets 17..31, 64..351 and 528..623, and
`AS-4C00` from 32 to the end. Its C4 page (`P-2238` at offset 128 and the
parameters under it) lives in such a run. ETS does not treat those octets as
device-owned: in `meteodata-1-1-202-new.pcapng` it read-compares the 12-octet
chunks at `0x4844`, `0x4860`, `0x4880` and others inside the masked runs, and the
device holds C2/C3 active at `0x4840`/`0x4860`, which only ETS wrote. In
`AS-4C00` ETS reads only the 32 octets that carry parameters and leaves the other
992 alone (the device holds `0xFF` there). The rule: an octet of a segment is
written when the product's `<Mask>` marks it `0xFF` **or** the plan placed a
parameter in it (`FlashPlan::placed`, the octets the image builder laid a
reached parameter's bits into). A masked run with no placed parameter stays
untouched, so the 0x4000 table region and the tail of `AS-4C00` behave as
before. The planner folds this into the write mask once, so the blind writer,
the read-compare writer, the parameter-only diff and its read-back verify all
use the same set.

**A segment allocated in parts (issues #413, #411).** A `<choose>` branch can
allocate one absolute segment with several `LdCtrlAbsSegment` records that
leave gaps: the MDT `A-0054-14` and `A-0255-21` with `P-203` (switching times
in the device) = 1 allocate `0x47E4` and `0x4770` in three and two parts.
`CONFIRMED` against the synthetic `syn-s7-choose-split` (`captures/synthetic/
syn-s7-choose-split/defaults/ops.txt`, ETS 6.4.1, 2026-10-30): with `mode` = 1
the branch allocates the 64-octet `AS-4440` as `0x4440` length 1 and `0x4443`
length 61; ETS sends both records as declared, streams `0x4440` (1 octet)
after the first and `0x4443..0x447F` after the second, and never writes or
reads `0x4441..0x4442`, where the 16-bit parameter `delay` is placed. The
download completes. The rule bussard follows (`plan_sys7.rs`,
`sys7_kept_octets`): each record is sent as declared, each part of the image
is streamed into the allocation that holds it, and the octets no allocation
holds are kept on the device: masked off (so the read-compare, the
parameter-only download and the diff never touch them), not placed, and named
in the plan (`LSM 3 segment 0x4440 octets 1..3 kept`). A parameter placed in
a gap is reported as kept on the device (the device's value and the model's,
no verdict), never as a difference, by `flash`, `plan` and the read-back.
System B has the same rule for a `<choose>` branch that writes part of a
relative segment (`KeptOctets`, PR #647).

**Amendment (issue #133): read-compare-write on masks without `VerifyMode`.**
`CONFIRMED` against `meteodata-1-1-202-new.pcapng` (Theben Meteodata 140 S,
1.1.202, mask 0701, full ETS download after a device reset). ETS does not stream
the 0701 segments blind: it reads the device memory back in the chunk size it
would write (12 octets), compares each chunk with its image, and writes only the
chunks that differ, then reads a written chunk back. The capture holds 194
12-octet `A_Memory_Read`s across `0x4000`, `0x4400`, `0x4800` and `0x4C00`, and
only 21 writes: the load-state records at `0x0104` and single octets at `0x4000`
and `0x4800`. The switch is the Hawk `VerifyMode` feature in `knx_master.xml`:
MV-0705 declares `VerifyMode=1` (and `DownloadStamp=1`) and is written blind and
verified through the MCB entries; MV-0700 and MV-0701 declare none.

bussard follows the same rule. `Sys7Profile::verify_mode` comes from the Hawk
block when the planner has one, else from the mask default (0700/0701 none,
0705 `1`). With no verify mode, each AbsSegment image is walked in negotiated
memory chunks: read the owned span of the chunk, skip it when it matches, else
write its owned runs and read it back (a mismatch fails the flash). Because every
octet was compared, those segments get no post-restart spot check. The plan text
reads `stream segment (read-compare, N octets)`, and `plan.json` marks each
segment image `write_mode: read-compare` (or `blind`). A re-flash of an unchanged
device writes nothing but the load-state records.

### 4.3 TaskSegment: per-LSM finalize

`TaskSegment{lsm_idx, address}` `[corpus: 47/49]` writes a task/segment
descriptor pointing at the segment base, issued once per LSM immediately before
`LoadCompleted`. Realisation: an AllocAbsTaskSegment record (subtype 0x02)
carrying the address and the application's identity:

```
[03][02][address:2 BE][PEI type][manufacturer:2 BE][application number:2 BE][application version]
```

This is the AllocAbsTaskSeg record of `[MP §3.31.2, p. 136-137]`: start
address, the PEI type the application needs, then the application id
(manufacturer, manufacturer-specific id, version) that the device exposes as
PID 13 of the application program object (`[Res §4.2.13]`; the BCU2 lineage
stores the same five octets at 0103h-0107h and the PEI type at 0109h, `[BCU
§5.1.2.12.5, p. 45-47]`). A device starts its application only when the
requested PEI type equals the physical one `[BCU §5.1.2.6.3, p. 41]`.

**CONFIRMED** against ETS 6. The EK-E72 (`M-00B6_A-4537-03-DE59`, `PeiType="1"`,
number 17719 = `0x4537`, version 3) wrote `03 02 40 00 01 00 b6 45 37 03` and
`03 02 40 ed 01 00 b6 45 37 03`; the Jung `00 00 04 a0 11 13` and Theben
`00 00 48 14 0c 14` tails, once read as a "zero length plus marker", are PEI type
0 and manufacturer `0x0004` / `0x0048`. The ETS sweep captures of 30
applications (nine manufacturers, 0705 and 0701, property and memory-mapped) and
the house captures all match. The manufacturer is the one in the application id,
except with `<Options LegacyPatchManufacturerIdInTaskSegment="true">`, where it
is the `OriginalManufacturer` (Busch-Jaeger `M-0007_A-A002-13-…-O0002`, PEI type
`0x80`: `80 00 02 a0 02 13`). The planner takes every octet from the product
(`sys7_task_identity`) and refuses when one is missing; a table-only `apply`
without product data refuses for the same reason.

The sim must accept a TaskSegment in `Loading` state and treat it as "segment
descriptor committed"; it is a precondition for the following `LoadCompleted`.

### 4.4 TaskCtrl1

`TaskCtrl1{lsm_idx, address, count}` `[corpus: 3/49; Theben, Steinel, Elsner;
plus Jung M-0004_A-A011]` is `AdditionalLoadControls` subtype 0x04, the Task
Control Record 1: the address of the application's interface-object table and
the number of objects in it `[MP §3.31.2, p. 137]`.

**Implemented (2026-09-18):** the Jung `M-0004_A-A011` (0705) download issues a
TaskCtrl1 on LSM 3, so it is on the conformance hot path, not a second-phase op.
bussard plans and executes it; the sim decodes subtype 0x04 into `TaskCtrl1
{address, count}` and accepts it while `Loading` with no memory side effect in
the M1 model (like TaskSegment). **M2 CONFIRMED** the `03 04` opcode is on the
Jung download hot path (a single TaskCtrl1 on LSM 3), but the captured record was
`03 04` then all-zero (address 0, count 0), so the product's declared
address/count are not carried on the wire the way this encoder lays them out; the
sim's no-side-effect accept still reaches Loaded. Resolved: the all-zero record
is that product's own `Address="0" Count="0"` (#482); the schaltaktor and
Meteodata captures carry non-zero values the encoder reproduces.

### 4.5 CompareMem

Raw `LdCtrlCompareMem{Address, InlineData, Size}` `[corpus: 1/49; Zennio
LUMENTO]`: an absolute `A_Memory_Read(Address, Size)` + byte-compare against
`InlineData`; mismatch fails the flash. No LSM interaction. Second-phase op.

### 4.6 CompareProp obj0 / PID78: the MDT preflight

`CompareProp{obj_idx=0, prop_id=78, inline_data}` `[corpus: 44/49; all MDT]`
runs **before** any Unload: read object-0 property 78 (`PID_HARDWARE_TYPE`,
`[Res §4.3.28]`; "Identification of the hardware" is mandatory on 0705 and
optional on 0700/0701, `[Prof §4.3 row 7, p. 42]`, via `DM_Identify_RCo2`
`[MP §3.4.3]`) and byte-compare against the 10-octet `InlineData`, e.g.
`00000000 03 12 00000000`. Mismatch fails the flash (it guards against flashing
the wrong app onto a device). Absent on Theben/Zennio/Steinel/Elsner.

The 6th octet (`0x12` above) does **not** cleanly equal the application number
across the corpus (app 14 → 0x12, app 8 → 0x11, app 9 → 0x09, app 10 → 0x0A):
it is a hardware-type / app-family marker, not the app id. Treat the whole 10
octets as opaque expected bytes from `InlineData`; do not synthesize it. The sim
must serve object-0 PID78 as a readable 10-octet value that a correctly-targeted
flash matches. `S7-CAL: PID78 value semantics and how the sim seeds it`.

There is **no `WriteProp`** of the app id anywhere in System 7; the device
derives run-state from the loaded tables, ETS only checks `[corpus §5]`.

### 4.7 Parameters the configuration does not show (#448)

A parameter the Dynamic walk does not reach is written at its default, or its
octets keep the segment template, by
`ApplicationProgram::downloads_invisible_parameters` (`bussard-ets`), the one
predicate the image builder and the read-back decoder use on both systems.
With `DownloadInvisibleParameters` (`None`, `Background`) or
`PreferPartialDownloadIfApplicationLoaded="true"` the template stays. Without
either, the schema version of the application file
(`http://knx.org/xml/project/<N>`) decides on System 7:

| capture | system | schema | `MinEtsVersion` | ETS at the hidden parameter |
|---|---|---|---|---|
| `syn-s7-hidden-default-p11` | 0705 | 11 | 4.0 | template |
| sweep rows of #448 (Steinel, ekinex, B.E.G., Zennio, MDT, Elsner) | 0705/0701 | 11 | 4.0, 3.0d, none | template |
| Busch-Jaeger `A-FF11-15` (sweep) | 0705 | 20 | 3.0d | template (14 octets differ when written) |
| `syn-s7-hidden-default` | 0705 | 23 | 6.0 | default |
| `syn-hidden-default` | 07B0 | 23 | 6.0 | default |
| Busch-Wächter PRO 280 `A-6179-82` (sweep, #89) | 07B0 | 20 | 5.0 | default |

The two synthetic System 7 products differ only in the namespace and
`MinEtsVersion`. So System 7 writes the defaults from project/21 on and keeps
the template through project/20; System B writes them at every schema. The
schema alone does not decide (project/20 writes on the PRO 280 and keeps on
`A-FF11-15`). Open: the System 7 boundary within 21 to 23 (no System 7 program
in the corpus has project/21 or /22, so it changes no vendor product), System B
below project/20 (no capture separates it), and whether ETS keys on
`MinEtsVersion` instead (every capture that writes has 5.0 or later, every one
that keeps has 4.0 or earlier, or none). `syn-s7-hidden-default` rendered in project/23
with `MinEtsVersion="4.0"` would tell the two apart.

---

## 5. LSM realisation, resolved: fixed per mask by the profile

**This was the single most important open question. The profile answers it
`[Prof §4.2 row 7, p. 37]`: Realisation Type 1 (property) is mandatory on 0701
and 0705 and optional on 0700; Realisation Type 2 (memory mapped, `[MP
§3.31.2]`, "shall only be used with mask 070nh" and "not for further
developments") is mandatory on 0700 and 0701 and optional on 0705. Two
real-ETS download captures show which one ETS picks where both are available.**

**Verdict (both captures CONFIRMED):**

- **Jung `0705`: property-based.** The M2 live capture (issue #70, a real ETS 6
  download to a Jung 3361-1M) and the 0705 analysis captures (binaereingang,
  automitschalter, schaltaktor) drive their LSMs **property-based**: every Unload
  / StartLoading / AbsSegment / TaskSegment / LoadCompleted is an
  `A_PropertyValue_Write(objN, PID 5, 10-octet load event, one element at index
  1)`, state read back via `A_PropertyValue_Read(objN, PID 5)`. There is **no
  `A_Memory_Write` to `0x0104`** anywhere; the only `0xB6EA+` touch is a single
  readable-status `A_Memory_Read`. So [`LsmAccess::Property`] is the `0705`
  default.
- **Theben `0701`: memory-mapped.** The Theben Meteodata 1409207 (IA 1.1.202)
  capture drives its LSMs **memory-mapped**: **11-octet** records written by
  `A_Memory_Write` to `0x0104`, status read at `0xB6EA + (lsm - 1)` (returning
  `02` Loading … `01` Loaded), with **zero PID-5 traffic**. So
  [`LsmAccess::MemoryMapped`] is the `0701` default.

The download path selects the realisation by mask family
(`Sys7Profile::corpus_default_for_mask`: `0700` and `0701` → memory-mapped,
`0705` → property), overridable by `HawkConfigurationData` when a product carries a
usable block. This corrects the earlier claim that property was the default for
ALL System 7; that regressed the memory-mapped Theben 0701.

The two research inputs that disagreed before M2:

- **Standards/clean-room research** (the issue #49 research pass): System 7 is a
  BCU2 descendant; the KNX LSM is property-based; load events written to
  `PID_LOAD_STATE_CONTROL` (PID 5) via `A_PropertyValue_Write`, state read back
  via `A_PropertyValue_Read`. **M2 confirmed this is correct for 0705.**
- **First-party evidence** (`[issue #49]`, from `.knxprod` HawkConfigurationData
  + ETS analysis): the `.knxprod` `HawkConfigurationData` carries a
  `LoadControl_M112 @ StandardMemory 0x0104` block with status at `0xB6EA+`, read
  as evidence the LSM is a **12-octet memory record**. **M2 disproved this
  reading:** the `LoadControl_M112 @ 0x0104` Hawk block did NOT predict the wire,
  control is property; `0xB6EA..0xB6ED` hold the load states of object types 1
  to 4 (`0xB6EA + OT - 1`, `[MP §3.31.2, p. 134]`; the single read at `0xB6EC`
  is the application program's), not a control-write target. `sys7_profile_from_hawk` no longer feeds
  the normal CLI flash path (it plans with the property corpus default); the
  helper stays only for the memory-mapped conformance harness.

**Both realisations stay behind an `LsmAccess` seam**, selected per mask family:

```
trait LsmAccess {
    fn send_event(lsm, event_record: [u8; 10]) -> Result<()>;  // 10-octet abstract event
    fn read_state(lsm) -> Result<u8>;   // 0..5 per §4.1
}
```

- **`LsmAccess::Property`** (the `0705` default): `A_PropertyValue_Write(obj, PID
  5, 10-octet event)` / `A_PropertyValue_Read(obj, PID 5) -> 1 octet`. Confirmed
  by the M2 Jung 0705 capture.
- **`LsmAccess::MemoryMapped`** (the `0701` default): write the **11-octet**
  record to the LSM control address (default 0x0104), poll status at
  `0xB6EA + (lsm - 1)`, both via `A_Memory_Write`/`_Read`. Confirmed by the Theben
  0701 Meteodata capture.

The memory-mapped variant's **11-octet** record (`[MP §3.31.2, p. 135-137]`;
Theben 0701 CONFIRMED; `[TSSG §2.1]` shows `14h`, `24h`, `34h`, `44h` as the
first octet of the four unloads) carries the object type in the high nibble of
the first octet and the event in the low nibble, then the segment type and a
segment ID octet (00); there is NO `[lsm][00]` prefix and no widened address
(#482):
```
[0] (object type << 4) | event_opcode   [1] segment type   [2] segment ID (0x00)
[3..5] start:2 BE   [5..11] the event's octets 4..10 (alloc attrs or task identity)
```
e.g. `13 00 00 40 00 00 1d f2 03 80 00` (LSM1 alloc 0x4000 len 0x1D EEPROM),
`13 02 00 40 00 00 00 48 14 0c 14` (LSM1 task, identity `00 00 48 14 0c 14`),
`33 04 00 46 eb 01 00 00 00 00 00` (LSM3 taskctrl1 0x46EB count 1). Built by
`bussard_mgmt::wrap_memory_lsm_record`, decoded by the sim's
`decode_memory_lsm_record`.

**Default:** the realisation the profile makes mandatory for the mask
(`Sys7Profile::corpus_default_for_mask`): `0700` and `0701` →
`MemoryMapped { control 0x0104, status 0xB6EA }`; `0705` → `Property`. knx-sim
picks the same per mask when a device's config omits `lsm_access`. A `HawkConfigurationData` block may still select `MemoryMapped`
for a product that carries a `StandardMemory` LoadControl (the 0701 Hawk block
does; the 0705 Jung block also resolves there but is a pre-M2 false positive, so
the normal Jung flash plans with the property default and does not feed a Hawk
config). `BUSSARD_FLASH_SYS7_LSM=memory|property` overrides the realisation for
conformance testing.

**The sim implements the device side of BOTH variants** (PID-5 property
writes/reads, plus 11-octet memory writes to 0x0104 with `0xB6EA + (lsm-1)`
status) and selects by a construction-time flag, so bussard can be
conformance-tested against either realisation without a second sim.

Calibration constants now CONFIRMED (were `S7-CAL:`): LSM realisation is
mask-family dependent (0705 property PID 5 / 0701 memory-mapped 11-octet @0x0104);
free-access authorize with `0xFFFFFFFF` → level 0; max-APDU absent → 15-octet
floor → 12-octet chunks; MCB via `A_PropertyValue_Read(PID 27)`; bare-0x380
fire-and-forget restart; the TaskSegment identity (§4.3); the allocation
record's octets 6 to 8 are the op's `Access`, `MemType` and `SegFlags` verbatim
(172 of 172 sweep records).

---

## 6. Wire constraints

- **12-octet memory chunks on standard frames.** A server without
  `L_Data_Extended` takes at most 12 data octets per `A_Memory_Write`/`_Read`
  `[MP §3.16.2, p. 100]`; treat max APDU as 15 → 12 data octets (3-octet
  header: APCI+count, addr-hi, addr-lo) `[research 5.1/5.3, XKNX PR#1938; M2
  Jung 0705 capture CONFIRMED]`. The M2 capture is byte-exact on this: every
  segment `A_Memory_Write` carried exactly 12 data octets on a standard frame
  (only the trailing partial chunks were shorter), across the whole 0x4000–0x4916
  span, with no extended frames. This is exactly `CONSERVATIVE_MEMORY_CHUNK = 12`
  in `apci.rs`. Do **not** use the 63-octet `MAX_MEMORY_*_LEN` ceiling (that is
  the System B extended-frame path). Fallback max-APDU when unreadable = 15
  `[XKNX PR#1834; M2 CONFIRMED]`. In the M2 capture, `PropRead(obj0, PID 56)`
  returned count 0 (`47 d6 00 38 00 01`) (max-APDU absent) and ETS fell back to
  the 15-octet standard-frame floor exactly as bussard does.
- **APDU byte layouts** `[research 5.2, CONFIRMED]`:
  - `A_Memory_Read` APCI 0x0200: `[TPCI|APCI-hi][APCI-lo|count&0x3F][addr-hi][addr-lo]`.
  - `A_Memory_Response` APCI 0x0240: same header + `count` data octets.
  - `A_Memory_Write` APCI 0x0280: same header + `count` data octets. No
    application-layer ack; verify by read-back.
- **`A_Authorize` before memory access.** Sequence: `T_Connect → A_Authorize_Request
  → memory/load writes → A_Restart` `[corpus §5, research 5.4]`. APCIs
  (CONFIRMED, match `apci.rs`): Authorize_Request 0x3D1, Authorize_Response 0x3D2,
  Key_Write 0x3D3, Key_Response 0x3D4. Key-then-level model: device compares the
  4-octet key against its per-level table and returns the granted level
  (0 = highest privilege … 15 = failed). Unkeyed device → free-access key
  `0xFFFFFFFF` (`FREE_ACCESS_KEY`). Field layout (INFERRED; verify against raw
  XKNX before wire use, `S7-CAL:`):
  ```
  Authorize_Request:  [APCI][reserved=0x00][key:4 BE]
  Authorize_Response: [APCI][level:1]
  Key_Write:          [APCI][level:1][key:4 BE]
  Key_Response:       [APCI][level:1]
  ```
  **M2 CONFIRMED:** the Jung 0705 download authorized with the free-access key,
  `Authorize_Request [d1 00 ff ff ff ff]` → `Authorize_Response [d2 00]` (level 0)
 ; exactly the `[APCI][reserved=0x00][key:4 BE]` / `[APCI][level:1]` layout above,
  so `0xFFFFFFFF` suffices on an unkeyed device. BIM M112 has 16 access levels
  `[Prof §4.2 row 12]`; a device without protected areas grants level 0 to any
  key `[Prof §4.2 footnote 10]`, a keyed one may grant a lower level that still
  covers the segments' write level (`0xF2` = level 2), which bussard treats as
  a denial today (reviewer A, #509). The sim must accept the free-access
  key and grant a usable level, and (optionally) reject memory writes issued before
  a successful authorize so bussard's ordering is tested.
- **Verification.** `A_Memory_Write` is unconfirmed. The standard verifies a
  stream either by a read-back after each block (`DMP_MemWrite_RCo` with verify,
  `[MP §3.16.2]`, the 0701 read-compare-write) or by the echo Verify Mode
  produces for each write (`DMP_MemWrite_RCoV`, `[MP §3.16.3]`, the 0705 path,
  where bussard compares each echo since #524); a short or different answer is an
  error `[research 3.1, AL 03.03.07 §3.5, CONFIRMED]`. MCB is
  app-dependent on System 7: absent from the MDT-era corpus but demanded by
  Jung `A-A011` via `LoadImageProp` PID 27; see the section 2 amendment. **M2
  CONFIRMED:** ETS verified the Jung MCB by *reading* `PID 27 (0x1B)` per object
  (`PropRead [d5 03 1b 10 01]` on objects 1/2/3, object 3 across start indices
  1..6), never writing it; exactly `A_PropertyValue_Read(PID_MCB_TABLE)`. Note
  the `10` in that header: **one element per request**. A single `count=6` read
  is refused by the real device (see the section 2 amendment of 2026-09-22).
  Segment checksums (last byte of a checksum-enabled segment) exist on
  the BCU2 lineage but are not required for M1.
- **Restart semantics** `[research 6.3; M2 Jung 0705 capture CONFIRMED]`. Basic
  Restart APCI 0x380, no payload, fire-and-forget, breaks the management
  connection; bussard reconnects after the device reboots. The client may
  reconnect from 1 s after the restart and the device shall answer again by 5 s
  `[MP §3.7.1.1.2, p. 78-79]`; bussard's 1.5 s quiet and 30 s bound sit inside
  that. The M2 capture shows
  exactly this: bare `[4f 80]` / `[6f 80]` restarts with no payload and no
  `RestartResponse`, no master-reset (0x381/0x3A1) variant anywhere in a normal
  download. Every load procedure ends with a restart `[corpus: 47/49]`.
  Master-reset request/response caveats are errata (section 8), unaffected by M2.

---

## 7. Table formats (byte-exact)

These are the on-memory forms bussard writes into the 0x4000 / 0x4201 segments
and the sim must accept. ETS synthesizes the CONFIG/TYPE bytes itself (not from
`.knxprod`); only the data pointers come from product data `[Selfbus, CONFIRMED]`.

### 7.1 Address table (GrAT) at 0x4000 `[Res §4.16.3.1, p. 223; endrekatona, knx-stack, CONFIRMED]`

```
[CNT:1][own-IA:2 BE][GA1:2 BE][GA2:2 BE]...
```
- `CNT` = number of 2-byte entries **including** the own-IA slot (= 1 + number of
  group addresses).
- Entry 0 = the device's own individual address, big-endian (TSAP 0 = own IA).
- Each GA = 2 bytes big-endian (15 significant bits, D15 reserved). TSAP 1..N map
  to GAs in order; the GAs are sorted ascending and the implementation-specific
  maximum length "shall be checked" `[Res §4.16.3.1]` (the segment-size check).

### 7.2 Association table (GrOAT) `[Res §4.17.3.1, p. 245; endrekatona, knx-stack, CONFIRMED]`

```
[CNT:1][TSAP0:1][ASAP0:1][TSAP1:1][ASAP1:1]...
```
- `CNT` = number of `(TSAP, ASAP)` pairs.
- `TSAP` = 1-byte index into the address table; `ASAP` = 1-byte group-object
  number (lowest = 0). m:n allowed. On System 7 (and System B) the sending
  association of an object is the first entry with its ASAP `[Res §4.17.5.2.5,
  p. 250]`, so `compute_tables` puts the send link first; on BCU2 the sending
  association is the one whose number equals the ASAP `[Res §4.17.4.3.1,
  p. 248]`, a different build (#525).
- Index width: 1 byte confirmed on small devices; 0705 allows ~254 GAs, which
  still fits u8. `S7-CAL: confirm no 2-byte TSAP/ASAP variant in the corpus`.

### 7.3 Group-object table + descriptors `[Selfbus BIM112 dump, CONFIRMED; Res §4.18.3/§4.18.4 for the octets]`

The standard text has the BCU1/BCU2 layout only (one-octet pointers, 3-octet
descriptors, `[Res §4.18.3.1, p. 261]`); the BIM M112 widens the pointers to
two octets, which the dump and the ETS captures confirm. The CONFIG and TYPE
octets keep the standard's coding.

```
[CNT:1][RAM-flags ptr:2 BE] then per object a 4-byte descriptor:
[data-ptr:2 BE][CONFIG:1][TYPE:1]
```
Real BIM112 dump: `5C` (92 objects), `07 00` (RAM-flags table at 0x0700), then
descriptors like `07 5C DF 03`.

- **data-ptr** = 2 bytes BE into user RAM (live value location).
- **CONFIG** (worked example 0xDF), Realisation Type 2 `[Res §4.18.4.1,
  p. 265]`, the BCU2 form the 0705 captures follow (1.1.46: `df` → `5f`):
  ```
  bit 7   Update enable (U); "shall be 1" only in the BCU1 form [Res §4.18.3.1.2.1]
  bit 6   Transmit enable (T)
  bit 5   Segment selector (which segment a one-octet pointer names on BCU1/2;
          meaning on the two-octet BIM M112 pointers not in the text: keep the template)
  bit 4   Write enable (W)
  bit 3   Read enable (R)
  bit 2   Communication enable (C)
  bits 1-0 transmission priority: 00 system, 01 normal (ETS "high"), 10 urgent
          (ETS "alarm"), 11 low [Res §4.18.3.1.2.1, p. 263]
  ```
  This on-device order differs from the ETS UI "C R W T U I"; I is not in this
  byte, U is bit 7. `compute_sys7::sys7_config_byte(template, flags)` is the one
  definition, used by the flash post-pass: the flag bits from the project,
  bits 5, 1 and 0 from the product's template octet (#528).
- **TYPE** = object size code `[Res §4.18.3.1.2.1, p. 264-265]`: 0..6 = 1..7
  bits, 7 = 1 octet, 8 = 2, 9 = 3, 10 = 4, 11 = 6, 12 = 8, 13 = 10, 14 = 14
  octets; bits 7-6 reserved 0. `compute::object_size_code` matches and goes on
  with Table 88 (`[Res §4.18.6.2.4.1.4]`, codes 15 to 255) for System B; a size
  with no code refuses the plan (#545).
- **RAM-flags table** `[Res §4.18.3.1.1.1, p. 262]`: four bits per object, two
  objects per octet (object 0 in the low nibble): bits 1-0 transmission status
  (00 idle/OK, 01 idle/error, 10 transmitting, 11 transmit request), bit 2
  data request, bit 3 update. That is the BCU1/2 text; the BIM M112 layout is
  not in the standard and bussard never writes the table.

Both implementers compute these from the same model (GAs, links, com-object
flags/DPT) so a golden-byte test (section 9) can lock them without a device.

---

## 8. Errata found during research (re-verify before changing)

Two constants in the existing bussard tree disagree with XKNX. Both are for
services **not on the System 7 download hot path** (System 7 uses only basic
Restart 0x380), so neither blocks M1; but they are latent bugs to fix.
**Re-verify against the existing DA.tp captures before changing them**, because
bussard's master-reset encoding was validated against a real capture, not GPL
source, and the DA.tp captures are the tie-breaker.

1. **`A_RESTART_RESPONSE`.** `crates/bussard-mgmt/src/apci.rs:106` defines
   `A_RESTART_RESPONSE = 0x381` (shared with the master-reset request
   `A_RESTART_MASTER_RESET = 0x381`). XKNX gives the master-reset **response**
   APCI as **0x3A1** `[research 6.3]`. If XKNX is right, bussard cannot currently
   distinguish a master-reset request from its response by APCI (it relies on
   frame flow direction). `S7-CAL: A_Restart master-reset response APCI 0x381 vs
   0x3A1 against DA.tp`.

2. **`master_reset_error_reason`.** `crates/bussard-mgmt/src/load.rs:496`
   maps `2` = access denied, `3` = unsupported erase code, `4` = invalid channel.
   XKNX's table is **`0x01` = access denied, `0x02` = unsupported erase code,
   `0x03` = invalid channel** (`0x00` = success) `[research 6.3]`; bussard is
   off by one. The `apci.rs:104` doc comment carries the same off-by-one.
   `S7-CAL: master-reset error-code mapping against DA.tp`.

Not errata but adjacent unknowns to resolve at capture: process-time unit
(seconds, GPL-corroborated only) and erase-code names 0x02–0x08.

---

## 9. Test plan

**Corpus targets, in order:**
1. **MDT `M-0083_A-000E`** (AKK-01UP.03, Switching 1-fold): smallest canonical
   0705, 6 segments, ~740 B, no TaskCtrl1. Brings up AbsSegment + TaskSegment +
   multi-LSM + the object-0/PID78 preflight. First conformance target.
2. **MDT `M-0083_A-0008`** (Switching 2-fold): same shape, sanity-check the
   engine generalizes across sizes.
3. **Theben `M-0048_A-4947`** (FIX2 DM 4 T, 0701): exercises `TaskCtrl1` and the
   converted post-restart LSM-5 tail (§3, dropped since issue #178). Also
   surfaces the orthogonal wide-integer parameter-image bug in `bussard-prod` (472-bit field); track separately.
4. **Jung `M-0004_A-A011`** (Präsenzmelder Mini Universal, 3361-1MWW): 11 of the
   user's 17 real System 7 devices; **not yet in the corpus, fetch this
   `.knxprod` first**. Expected to match the MDT canonical LSM 1/2/3 shape.

**Conformance loop (sim as oracle):** the knx-sim System 7 device model is the
executable spec. bussard flashes the sim; the sim asserts the exact wire byte
sequence (authorize, 12-octet chunks, LSM records, segment payloads, read-back)
against a recorded expectation. Run the sim in **both** LsmAccess variants
(section 5) so bussard's realisation switch is exercised against each. Because
both implementers build from this doc, a sim-vs-bussard mismatch is the primary
signal that one diverged.

**Golden-byte table tests:** for `M-0083_A-000E`, lock the 0x4000 address table,
0x4201 association table, and group-object descriptors as byte-exact fixtures
computed from the model (section 7). These need no device and catch
CONFIG/TYPE-synthesis and endianness regressions.

**M2 live-capture milestone.** Capture an ETS re-download of a real Jung 0705
device (the `.knxprod` from target 4). The plaintext memory-write frames resolve,
in priority order, every `S7-CAL:` marker: (1) LSM realisation; memory vs
property, the 0x0104 / 0xB6EA+ addresses, the 12-octet record layout and status
protocol; (2) whether `A_Authorize` is mandatory on unkeyed 0705 and the request
field order; (3) the AbsSegment alloc-record access/mem_type/mem_attr octets and
the TaskSegment sub-command; (4) address-table base 0x4000 by read-back; (5) the
CONFIG/TYPE synthesis rule and TYPE length table; (6) the two errata APCIs. Until
M2, ship the seams with the best-evidence defaults above and keep every marker
greppable.

---

## 10. Milestones

- **M1**: MDT canonical shape against the sim: AbsSegment + TaskSegment +
  3 parallel LSMs + object-0/PID78 preflight + `A_Authorize` + 12-octet absolute
  memory streaming + read-back verify. Default `LsmAccess::MemoryMapped`, hand-
  written default profile. Covers all 43 MDT apps and (by structure) the Jung
  sensors. Refuse TaskCtrl1 / CompareMem cleanly with a named message.
- **M1.5**: parse `HawkConfigurationData` into the data-driven mask profile;
  drop the hand-written default to a fallback.
- **M2**: live Jung capture resolves the `S7-CAL:` markers; fix any default that
  was wrong; add `TaskCtrl1` + post-restart LSM-5 (Theben) and Zennio
  `CompareMem`; fix the two errata against DA.tp.
```
