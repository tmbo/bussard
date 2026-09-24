# System 7 download specification (mask 0705 / 0701)

> Implementation-grade spec for two independent implementers building in
> parallel from this document alone: (1) the bussard System 7 download path
> (`bussard-download` lowering + `bussard-mgmt` primitives), and (2) the
> knx-sim System 7 device model. Both must converge on the same wire bytes.
> Grounded in `system7-research.md` (standards/clean-room research) and
> `system7-corpus.md` + `system7-corpus.json` (49-app corpus archaeology).
> Issue #49.

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

Source shorthand: `[XKNX PR#NNNN]`, `[Resources 03.05.01 §X]`, `[AL 03.03.07 §X]`,
`[MP 03.05.02 §X]`, `[corpus: N/49]`, `[Selfbus]`, `[endrekatona]`,
`[Kögler SDK]`, `[issue #49]` (bussard first-party evidence). Full URLs in
`system7-research.md`.

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

0701 and 0705 share the resource model and op set, but the **LSM realisation is
vendor / mask-family dependent** — they are NOT identical at the wire level. Two
real-ETS download captures settle it (superseding the earlier "0701==0705"
claim):

- **Jung `0705`** (M2 issue #70, plus the binaereingang / automitschalter /
  schaltaktor 0705 analysis captures) drives load control **property-based** over
  `PID_LOAD_STATE_CONTROL` (PID 5) — see §5.
- **Theben `0701`** (Meteodata 1409207, IA 1.1.202) drives load control
  **memory-mapped**: 11-octet records written by `A_Memory_Write` to `0x0104`,
  status read at `0xB6EA + (lsm - 1)`, with ZERO PID-5 traffic — see §5.

So the download-path realisation branches on the mask family (0705 → property,
0701 → memory-mapped) via `Sys7Profile::corpus_default_for_mask`. Any further
divergence found in capture gets an `S7-CAL:` marker.

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

### 2.2 PID_TABLE_REFERENCE usage

On System B the association table is located via object-2 `PID_TABLE_REFERENCE`
(PID 7). Research states the same *may* hold on System 7 for the association
table [research 1.1, INFERRED-strong from issue #49]. **The corpus contradicts
this for the download path:** there is zero `PID_TABLE_REFERENCE` usage and zero
property-array table access in any of the 49 System 7 apps `[corpus: 49/49,
§5]`. Tables are addressed only by absolute memory (0x4000 / 0x4201).

Resolution: the System 7 download path **does not resolve any table base via
PID_TABLE_REFERENCE**. Addresses come from the segment `Address` attribute
directly. The sim need not implement a functional PID_TABLE_REFERENCE for the
download to work; it MAY expose PID 7 as a best-effort probe returning the
segment base, but bussard must not depend on it. `S7-CAL: confirm no live 0705
download issues an A_PropertyValue_Read(obj2, PID7)`.

### 2.3 Absolute code segments

Every corpus segment is an `AbsoluteSegment` (`SegmentKind::Absolute`) with a
fixed `Address`; the parser already carries `AbsSegment{lsm_idx, address, size}`
plus the decoded `<Data>` and `<Mask>` payloads (see
`crates/bussard-ets/src/application.rs`, `CodeSegment` / `LoadOp::AbsSegment`).
The segment **`<Data>` IS the payload** to stream to `Address`; there is no
separate write op (section 4.2). Address families `[corpus §3]`:

| Address | Role | Data |
|---|---|---|
| 0x4000 (16384) | LSM 1 table region (address / com-object descriptors). The **only** segment carrying a per-byte `<Mask>`. ~511–513 B | present + mask |
| 0x4201 (16897) | LSM 2 table region (association / group-object). ~511 B | present |
| 0x4400 (17408) | LSM 3 parameter image start | present |
| 0x0700 (1792), 0x0730 | LSM 3 low-RAM working region | **allocate only, NO `<Data>`** |
| 0x1C00, 0x4800, 0x4C00, 0x8710, 0xB800 | vendor code/param regions (Theben/Zennio) | present |

A segment with `<Data>` == `None` (e.g. 0x0700) is an **allocation-only** record:
the LSM reserves/zeroes device-initialised RAM; no memory write is streamed.

### 2.4 HawkConfigurationData — the load-bearing architecture decision

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
**not** feed a parsed Hawk config to the planner — it plans with the property
corpus default. `sys7_profile_from_hawk` stays for the memory-mapped conformance
harness only.

For M1 the sim and bussard MAY share a single hand-written default profile
matching `M-0083_A-000E`; `HawkConfigurationData` parsing is the M1.5 hardening
step. Ship the seam first.

---

## 3. The three parallel load-state machines

System 7 runs **three** LSMs in parallel (System B uses one) `[corpus: 49/49]`:

- **LSM 1** — table region at 0x4000 (address table + com-object descriptors).
- **LSM 2** — table region at 0x4201 (association + group-object).
- **LSM 3** — parameters (0x0700 RAM alloc + 0x4400 param image).
- **LSM 5** — named only by a tail some converted (pre-ETS4) procedures carry
  *after* the restart (Theben FIX2 `M-0048_A-4947`, Jung 2308.16REGHM
  `M-0004_A-2088-11`: `LdCtrlRestart`, `LdCtrlTaskSegment LsmIdx="5"`,
  `LdCtrlLoad LsmIdx="5"`). ETS sends nothing after the restart (captures
  `meteodata-1-1-202-new.pcapng`, `schaltaktor-8fach-1-1-49.pcapng`), and the
  2308.16REGHM has no object 5 (its `PID_LOAD_STATE_CONTROL` read answers count
  0). bussard cuts the procedure after the terminal restart (issue #178).

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
pass, not a procedure step. The procedure unloads 1 to 3 only, as bussard does.

Each LSM is torn down (`Unload`) up front, then loaded in order. The LSM index on
`Load`/`LoadCompleted`/`AbsSegment` names the machine, not an object index. The
mapping LSM-index → memory region is per-mask (from `HawkConfigurationData`;
default per the table above).

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

Abstract LSM states (1 octet, read back to poll) `[XKNX, Resources 03.05.01
§4.23.2, CONFIRMED]`:

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

State transitions the sim MUST enforce, and bussard MUST drive in order:
`Unloaded --StartLoading--> Loading --(AdditionalLoadControls*)--> Loading
--LoadCompleted--> Loaded`; `Unload` from any state → Unloaded; any illegal
event or a failed segment → Error (state 3), which must fail the flash.

The **load event record** is the 10-octet form (`[Resources 03.05.01 §4.23.2]`).
`AdditionalLoadControls` (0x03) uses octet 1 as the sub-command selector, big-
endian, total 10 octets `[XKNX, CONFIRMED]`:

| Sub-command | Code | Layout (after `[0x03][subtype]`) |
|---|---|---|
| Alloc absolute Data segment | 0x00 | `[start:2][length:2][access:1][mem_type:1][mem_attr:1]` |
| Alloc absolute Stack segment | 0x01 | same as 0x00 |
| Alloc absolute Task segment | 0x02 | same as 0x00 |
| Task pointer | 0x03 | (not in corpus) |
| Task control 1 | 0x04 | `[address:2][count:…]` (§4.4) |
| Task control 2 | 0x05 | (not in corpus) |

`access`: bits 0–3 write level, bits 4–7 read level. `mem_type` bits 0–2: 1 =
zero-page RAM, 2 = RAM, 3 = EEPROM. `mem_attr` bit 7 = checksum-control enable.

### 4.2 AbsSegment — allocation record + payload

`AbsSegment{lsm_idx, address, size}` lowers to two device actions:

1. **Allocate:** an `AdditionalLoadControls` "Alloc absolute Data segment"
   (subtype 0x00) record for the LSM, filled
   `[event=3][subtype=0][start:2 BE][length:2 BE][seg_flags][mem_type][checksum_ctrl][reserved]`.
   **M2 CONFIRMED** (cross-checked against the Jung app M-0004_A-A011's declared
   AbsSegment addresses/sizes): the opcode/subtype, the big-endian `start` and
   `length` (= the declared segment size in octets), and `mem_type` at octet 7 —
   `2` (RAM) for the `0x0700` low-RAM region, `3` (EEPROM) for the `0x4xxx`
   table/param regions. Every captured record's length equals the product's
   declared size (e.g. `0x43FF` size 811 = `0x032B`; `0x4743` size 260 = `0x0104`).
   Two attribute octets are shown by the capture but not yet derivable from
   product data, so bussard emits `0`: `seg_flags` (octet 6, observed `0xF2`/`0xF3`)
   and `checksum_ctrl` (octet 8, observed `0x80`/`0x00`). A 0705 device keys the
   allocation on subtype + start + length, so a zero attribute tail still drives it
   to `Loaded`. `S7-CAL: derive the alloc-record seg_flags (0xF2/0xF3) and
   checksum_ctrl (0x80/0x00) octets from product data`.
2. **Stream payload:** if the segment carries `<Data>`, write those bytes to
   `address` via absolute `A_Memory_Write` in 12-octet chunks (section 6). **The
   segment `<Data>` IS the payload** — there is no separate `WriteMem` op
   `[corpus §2]`. A segment with no `<Data>` is allocate-only; skip the write.

The 0x4000 segment carries a per-byte `<Mask>`: `0xFF` = this byte belongs to the
image, other = device-owned, leave untouched. Under the mask, bussard streams
only owned bytes (still in 12-octet chunks by address run). The sim, on receiving
a write into a masked region, must accept the owned bytes and preserve the rest.

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

### 4.3 TaskSegment — per-LSM finalize

`TaskSegment{lsm_idx, address}` `[corpus: 47/49]` writes a task/segment
descriptor pointing at the segment base, issued once per LSM immediately before
`LoadCompleted`. Realisation: an `AdditionalLoadControls` record carrying the
address. Default: encode as AllocAbsTaskSegment (subtype 0x02) with
`start=address`, `length` = the LSM's total loaded span. **M2 CONFIRMED** the
`[03][02][address:2 BE]` prefix (LSM1 `0x4000`, LSM2 `0x41FF`, LSM3 `0x4722`); in
the capture the length field was `0x0000` and the four trailing octets a fixed
`04 a0 11 13` marker. bussard's `length=span` form still drives the sim to Loaded
(it keys the finalize on subtype + address). `S7-CAL: confirm the TaskSegment
length field (0x0000 vs span) and the trailing 04 a0 11 13 marker`.

The sim must accept a TaskSegment in `Loading` state and treat it as "segment
descriptor committed"; it is a precondition for the following `LoadCompleted`.

### 4.4 TaskCtrl1

`TaskCtrl1{lsm_idx, address, count}` `[corpus: 3/49 — Theben, Steinel, Elsner;
plus Jung M-0004_A-A011]` is `AdditionalLoadControls` subtype 0x04,
`[address:2][count]`. It writes a task-control table entry `count` times.

**Implemented (2026-09-18):** the Jung `M-0004_A-A011` (0705) download issues a
TaskCtrl1 on LSM 3, so it is on the conformance hot path, not a second-phase op.
bussard plans and executes it; the sim decodes subtype 0x04 into `TaskCtrl1
{address, count}` and accepts it while `Loading` with no memory side effect in
the M1 model (like TaskSegment). **M2 CONFIRMED** the `03 04` opcode is on the
Jung download hot path (a single TaskCtrl1 on LSM 3), but the captured record was
`03 04` then all-zero (address 0, count 0), so the product's declared
address/count are not carried on the wire the way this encoder lays them out; the
sim's no-side-effect accept still reaches Loaded. `S7-CAL: reconcile the TaskCtrl1
address/count fields with the captured all-zero record.`

### 4.5 CompareMem

Raw `LdCtrlCompareMem{Address, InlineData, Size}` `[corpus: 1/49 — Zennio
LUMENTO]`: an absolute `A_Memory_Read(Address, Size)` + byte-compare against
`InlineData`; mismatch fails the flash. No LSM interaction. Second-phase op.

### 4.6 CompareProp obj0 / PID78 — the MDT preflight

`CompareProp{obj_idx=0, prop_id=78, inline_data}` `[corpus: 44/49 — all MDT]`
runs **before** any Unload: read object-0 property 78 (`PID_HARDWARE_TYPE` in
`apci.rs`) and byte-compare against the 10-octet `InlineData`, e.g.
`00000000 03 12 00000000`. Mismatch fails the flash (it guards against flashing
the wrong app onto a device). Absent on Theben/Zennio/Steinel/Elsner.

The 6th octet (`0x12` above) does **not** cleanly equal the application number
across the corpus (app 14 → 0x12, app 8 → 0x11, app 9 → 0x09, app 10 → 0x0A):
it is a hardware-type / app-family marker, not the app id. Treat the whole 10
octets as opaque expected bytes from `InlineData`; do not synthesize it. The sim
must serve object-0 PID78 as a readable 10-octet value that a correctly-targeted
flash matches. `S7-CAL: PID78 value semantics and how the sim seeds it`.

There is **no `WriteProp`** of the app id anywhere in System 7 — the device
derives run-state from the loaded tables, ETS only checks `[corpus §5]`.

---

## 5. LSM realisation — RESOLVED: vendor / mask-family dependent

**This was the single most important open question. Two real-ETS download
captures settle it — and the answer is that the realisation depends on the mask
family, NOT a single global default.**

**Verdict (both captures CONFIRMED):**

- **Jung `0705` — property-based.** The M2 live capture (issue #70, a real ETS 6
  download to a Jung 3361-1M) and the 0705 analysis captures (binaereingang,
  automitschalter, schaltaktor) drive their LSMs **property-based**: every Unload
  / StartLoading / AbsSegment / TaskSegment / LoadCompleted is an
  `A_PropertyValue_Write(objN, PID 5, 10-octet load event, one element at index
  1)`, state read back via `A_PropertyValue_Read(objN, PID 5)`. There is **no
  `A_Memory_Write` to `0x0104`** anywhere; the only `0xB6EA+` touch is a single
  readable-status `A_Memory_Read`. So [`LsmAccess::Property`] is the `0705`
  default.
- **Theben `0701` — memory-mapped.** The Theben Meteodata 1409207 (IA 1.1.202)
  capture drives its LSMs **memory-mapped**: **11-octet** records written by
  `A_Memory_Write` to `0x0104`, status read at `0xB6EA + (lsm - 1)` (returning
  `02` Loading … `01` Loaded), with **zero PID-5 traffic**. So
  [`LsmAccess::MemoryMapped`] is the `0701` default.

The download path selects the realisation by mask family
(`Sys7Profile::corpus_default_for_mask`: `0701` → memory-mapped, everything else
→ property), overridable by `HawkConfigurationData` when a product carries a
usable block. This corrects the earlier claim that property was the default for
ALL System 7 — that regressed the memory-mapped Theben 0701.

The two research inputs that disagreed before M2:

- **Standards/clean-room research** (`system7-research.md` 2.1): System 7 is a
  BCU2 descendant; the KNX LSM is property-based — load events written to
  `PID_LOAD_STATE_CONTROL` (PID 5) via `A_PropertyValue_Write`, state read back
  via `A_PropertyValue_Read`. **M2 confirmed this is correct for 0705.**
- **First-party evidence** (`[issue #49]`, from `.knxprod` HawkConfigurationData
  + ETS analysis): the `.knxprod` `HawkConfigurationData` carries a
  `LoadControl_M112 @ StandardMemory 0x0104` block with status at `0xB6EA+`, read
  as evidence the LSM is a **12-octet memory record**. **M2 disproved this
  reading:** the `LoadControl_M112 @ 0x0104` Hawk block did NOT predict the wire —
  control is property; `0xB6EA+` is a readable status region (the single read at
  `0xB6EC`), not a control-write target. `sys7_profile_from_hawk` no longer feeds
  the normal CLI flash path (it plans with the property corpus default); the
  helper stays only for the memory-mapped conformance harness.

**Both realisations stay behind an `LsmAccess` seam**, selected per mask family:

```
trait LsmAccess {
    fn send_event(lsm, event_record: [u8; 10]) -> Result<()>;  // 10-octet abstract event
    fn read_state(lsm) -> Result<u8>;   // 0..5 per §4.1
}
```

- **`LsmAccess::Property`** (the `0705` default) — `A_PropertyValue_Write(obj, PID
  5, 10-octet event)` / `A_PropertyValue_Read(obj, PID 5) -> 1 octet`. Confirmed
  by the M2 Jung 0705 capture.
- **`LsmAccess::MemoryMapped`** (the `0701` default) — write the **11-octet**
  record to the LSM control address (default 0x0104), poll status at
  `0xB6EA + (lsm - 1)`, both via `A_Memory_Write`/`_Read`. Confirmed by the Theben
  0701 Meteodata capture.

The memory-mapped variant's **11-octet** record (Theben 0701 CONFIRMED) folds the
LSM index into the high nibble of the event opcode byte and widens the address to
3 octets — there is NO `[lsm][00]` prefix:
```
[0] (lsm << 4) | event_opcode   [1] subtype   [2] 0x00 (addr high octet)
[3..5] start:2 BE   [5..7] length:2 BE   [7..11] tail (alloc attrs or task marker)
```
e.g. `13 00 00 40 00 00 1d f2 03 80 00` (LSM1 alloc 0x4000 len 0x1D EEPROM),
`13 02 00 40 00 00 00 48 14 0c 14` (LSM1 task, marker `48 14 0c 14`),
`33 04 00 46 eb 01 00 00 00 00 00` (LSM3 taskctrl1 0x46EB count 1). Built by
`bussard_mgmt::wrap_memory_lsm_record`, decoded by the sim's
`decode_memory_lsm_record`.

**Default:** mask-family dependent (`Sys7Profile::corpus_default_for_mask`):
`0701` → `MemoryMapped { control 0x0104, status 0xB6EA }`; every other System 7
mask → `Property`. A `HawkConfigurationData` block may still select `MemoryMapped`
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
fire-and-forget restart. Remaining `S7-CAL:` on the memory-mapped path: the
TaskSegment marker lead/version octets and the residual alloc `seg_flags 0xF3` /
last-EEPROM `checksum_ctrl 0x00`.

---

## 6. Wire constraints

- **12-octet memory chunks on standard frames.** System 7 has no extended-frame
  guarantee; treat max APDU as 15 → 12 data octets per `A_Memory_Write`/`_Read`
  (3-octet header: APCI+count, addr-hi, addr-lo) `[research 5.1/5.3, XKNX PR#1938;
  M2 Jung 0705 capture CONFIRMED]`. The M2 capture is byte-exact on this: every
  segment `A_Memory_Write` carried exactly 12 data octets on a standard frame
  (only the trailing partial chunks were shorter), across the whole 0x4000–0x4916
  span, with no extended frames. This is exactly `CONSERVATIVE_MEMORY_CHUNK = 12`
  in `apci.rs`. Do **not** use the 63-octet `MAX_MEMORY_*_LEN` ceiling (that is
  the System B extended-frame path). Fallback max-APDU when unreadable = 15
  `[XKNX PR#1834; M2 CONFIRMED]`. In the M2 capture, `PropRead(obj0, PID 56)`
  returned count 0 (`47 d6 00 38 00 01`) — max-APDU absent — and ETS fell back to
  the 15-octet standard-frame floor exactly as bussard does.
- **APDU byte layouts** `[research 5.2, CONFIRMED]`:
  - `A_Memory_Read` APCI 0x0200: `[TPCI|APCI-hi][APCI-lo|count&0x3F][addr-hi][addr-lo]`.
  - `A_Memory_Response` APCI 0x0240: same header + `count` data octets.
  - `A_Memory_Write` APCI 0x0280: same header + `count` data octets. No
    application-layer ack — verify by read-back.
- **`A_Authorize` before memory access.** Sequence: `T_Connect → A_Authorize_Request
  → memory/load writes → A_Restart` `[corpus §5, research 5.4]`. APCIs
  (CONFIRMED, match `apci.rs`): Authorize_Request 0x3D1, Authorize_Response 0x3D2,
  Key_Write 0x3D3, Key_Response 0x3D4. Key-then-level model: device compares the
  4-octet key against its per-level table and returns the granted level
  (0 = highest privilege … 15 = failed). Unkeyed device → free-access key
  `0xFFFFFFFF` (`FREE_ACCESS_KEY`). Field layout (INFERRED — verify against raw
  XKNX before wire use, `S7-CAL:`):
  ```
  Authorize_Request:  [APCI][reserved=0x00][key:4 BE]
  Authorize_Response: [APCI][level:1]
  Key_Write:          [APCI][level:1][key:4 BE]
  Key_Response:       [APCI][level:1]
  ```
  **M2 CONFIRMED:** the Jung 0705 download authorized with the free-access key —
  `Authorize_Request [d1 00 ff ff ff ff]` → `Authorize_Response [d2 00]` (level 0)
  — exactly the `[APCI][reserved=0x00][key:4 BE]` / `[APCI][level:1]` layout above,
  so `0xFFFFFFFF` suffices on an unkeyed device. The sim must accept the free-access
  key and grant a usable level, and (optionally) reject memory writes issued before
  a successful authorize so bussard's ordering is tested.
- **Verification = read-back compare.** `A_Memory_Write` is unconfirmed; verify
  by `A_Memory_Read` + compare of echoed address, length, and bytes; a short
  response is an error `[research 3.1, AL 03.03.07 §3.5, CONFIRMED]`. MCB is
  app-dependent on System 7: absent from the MDT-era corpus but demanded by
  Jung `A-A011` via `LoadImageProp` PID 27 — see the section 2 amendment. **M2
  CONFIRMED:** ETS verified the Jung MCB by *reading* `PID 27 (0x1B)` per object
  (`PropRead [d5 03 1b 10 01]` on objects 1/2/3, object 3 across start indices
  1..6), never writing it — exactly `A_PropertyValue_Read(PID_MCB_TABLE)`. Note
  the `10` in that header: **one element per request**. A single `count=6` read
  is refused by the real device (see the section 2 amendment of 2026-09-22).
  Segment checksums (last byte of a checksum-enabled segment) exist on
  the BCU2 lineage but are not required for M1.
- **Restart semantics** `[research 6.3; M2 Jung 0705 capture CONFIRMED]`. Basic
  Restart APCI 0x380, no payload, fire-and-forget, breaks the management
  connection — bussard reconnects after the device reboots. The M2 capture shows
  exactly this: bare `[4f 80]` / `[6f 80]` restarts with no payload and no
  `RestartResponse`, no master-reset (0x381/0x3A1) variant anywhere in a normal
  download. Every load procedure ends with a restart `[corpus: 47/49]`.
  Master-reset request/response caveats are errata (section 8), unaffected by M2.

---

## 7. Table formats (byte-exact)

These are the on-memory forms bussard writes into the 0x4000 / 0x4201 segments
and the sim must accept. ETS synthesizes the CONFIG/TYPE bytes itself (not from
`.knxprod`); only the data pointers come from product data `[Selfbus, CONFIRMED]`.

### 7.1 Address table (GrAT) at 0x4000 `[endrekatona, knx-stack, CONFIRMED]`

```
[CNT:1][own-IA:2 BE][GA1:2 BE][GA2:2 BE]...
```
- `CNT` = number of 2-byte entries **including** the own-IA slot (= 1 + number of
  group addresses).
- Entry 0 = the device's own individual address, big-endian (TSAP 0 = own IA).
- Each GA = 2 bytes big-endian (15 significant bits, D15 reserved). TSAP 1..N map
  to GAs in order.

### 7.2 Association table (GrOAT) `[endrekatona, knx-stack, CONFIRMED]`

```
[CNT:1][TSAP0:1][ASAP0:1][TSAP1:1][ASAP1:1]...
```
- `CNT` = number of `(TSAP, ASAP)` pairs.
- `TSAP` = 1-byte index into the address table; `ASAP` = 1-byte group-object
  number (lowest = 0). Ordered as links were created in ETS. m:n allowed.
- Index width: 1 byte confirmed on small devices; 0705 allows ~254 GAs, which
  still fits u8. `S7-CAL: confirm no 2-byte TSAP/ASAP variant in the corpus`.

### 7.3 Group-object table + descriptors `[Selfbus BIM112 dump, CONFIRMED]`

```
[CNT:1][RAM-flags ptr:2 BE] then per object a 4-byte descriptor:
[data-ptr:2 BE][CONFIG:1][TYPE:1]
```
Real BIM112 dump: `5C` (92 objects), `07 00` (RAM-flags table at 0x0700), then
descriptors like `07 5C DF 03`.

- **data-ptr** = 2 bytes BE into user RAM (live value location).
- **CONFIG** (worked example 0xDF):
  ```
  bit 7   reserved, must be 1
  bit 6   Transmit enable (T)
  bit 5   Segment selector type (0 = value in user RAM segment)
  bit 4   Write enable (W)
  bit 3   Read enable (R)
  bit 2   Communication enable (C)
  bits 1-0 transmission priority (11 = low CONFIRMED; other codes INFERRED)
  ```
  This on-device order differs from the ETS UI "C R W T U I"; U/I are not in this
  byte. Synthesize CONFIG from com-object flags + DPT (bussard already parses
  `flags`/`dpt`). `S7-CAL: exact CONFIG synthesis rule + priority codes for
  bits 1-0 other than 11=low`.
- **TYPE** = object size code. CONFIRMED anchors: `0x00` = 1 bit, `0x03` = 4 bit.
  **INFERRED** proposed full mapping (standard KNX length code, verify vs
  03.05.01 §4.11): `0x00..0x05` = 1..6 bit, `0x06` = 7 bit, `0x07` = 1 byte,
  `0x08` = 2 byte, `0x09` = 3 byte, `0x0A` = 4 byte, … up to 14 byte. `S7-CAL:
  confirm TYPE-byte length table beyond 0x00/0x03`.
- **RAM-flags table**: 1 byte per com-object (live status). Confirmed 2-bit
  codes: `0x00` Idle/OK, `0x01` Idle/Error, `0x02` Transmitting, `0x03`
  Transmit-request. Remaining bits not fully sourced.

Both implementers compute these from the same YAML model (GAs, links, com-object
flags/DPT) so a golden-byte test (section 9) can lock them without a device.

---

## 8. Errata found during research (re-verify before changing)

Two constants in the existing bussard tree disagree with XKNX. Both are for
services **not on the System 7 download hot path** (System 7 uses only basic
Restart 0x380), so neither blocks M1 — but they are latent bugs to fix.
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
   `0x03` = invalid channel** (`0x00` = success) `[research 6.3]` — bussard is
   off by one. The `apci.rs:104` doc comment carries the same off-by-one.
   `S7-CAL: master-reset error-code mapping against DA.tp`.

Not errata but adjacent unknowns to resolve at capture: process-time unit
(seconds, GPL-corroborated only) and erase-code names 0x02–0x08.

---

## 9. Test plan

**Corpus targets, in order:**
1. **MDT `M-0083_A-000E`** (AKK-01UP.03, Switching 1-fold) — smallest canonical
   0705, 6 segments, ~740 B, no TaskCtrl1. Brings up AbsSegment + TaskSegment +
   multi-LSM + the object-0/PID78 preflight. First conformance target.
2. **MDT `M-0083_A-0008`** (Switching 2-fold) — same shape, sanity-check the
   engine generalizes across sizes.
3. **Theben `M-0048_A-4947`** (FIX2 DM 4 T, 0701) — exercises `TaskCtrl1` and the
   converted post-restart LSM-5 tail (§3, dropped since issue #178). Also
   surfaces the orthogonal wide-integer parameter-image bug in `bussard-prod` (472-bit field) — track separately.
4. **Jung `M-0004_A-A011`** (Präsenzmelder Mini Universal, 3361-1MWW) — 11 of the
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
computed from the YAML model (section 7). These need no device and catch
CONFIG/TYPE-synthesis and endianness regressions.

**M2 live-capture milestone.** Capture an ETS re-download of a real Jung 0705
device (the `.knxprod` from target 4). The plaintext memory-write frames resolve,
in priority order, every `S7-CAL:` marker: (1) LSM realisation — memory vs
property, the 0x0104 / 0xB6EA+ addresses, the 12-octet record layout and status
protocol; (2) whether `A_Authorize` is mandatory on unkeyed 0705 and the request
field order; (3) the AbsSegment alloc-record access/mem_type/mem_attr octets and
the TaskSegment sub-command; (4) address-table base 0x4000 by read-back; (5) the
CONFIG/TYPE synthesis rule and TYPE length table; (6) the two errata APCIs. Until
M2, ship the seams with the best-evidence defaults above and keep every marker
greppable.

---

## 10. Milestones

- **M1** — MDT canonical shape against the sim: AbsSegment + TaskSegment +
  3 parallel LSMs + object-0/PID78 preflight + `A_Authorize` + 12-octet absolute
  memory streaming + read-back verify. Default `LsmAccess::MemoryMapped`, hand-
  written default profile. Covers all 43 MDT apps and (by structure) the Jung
  sensors. Refuse TaskCtrl1 / CompareMem cleanly with a named message.
- **M1.5** — parse `HawkConfigurationData` into the data-driven mask profile;
  drop the hand-written default to a fallback.
- **M2** — live Jung capture resolves the `S7-CAL:` markers; fix any default that
  was wrong; add `TaskCtrl1` + post-restart LSM-5 (Theben) and Zennio
  `CompareMem`; fix the two errata against DA.tp.
```
