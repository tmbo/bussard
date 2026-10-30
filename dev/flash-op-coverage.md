# `bussard flash` LoadProcedure op coverage

Which `LdCtrl*` ops the product corpus uses, which ones `bussard flash`
executes on System B, and the clause of the KNX Standard 3.0.0 each op
realises. It answers two questions: can bussard run a given product's
download, and does each step do what the standard says. The System 7 lowering
(masks 0705, 0701, 0700) has its own spec in [system7-spec.md](system7-spec.md).

Spec references use the chapter numbers of the standard: Resources is 3/5/1
(`03_05_01 Resources v01.10.01`), Management Procedures 3/5/2
(`03_05_02 v02.01.02`), Configuration Procedures 3/5/3 (`03_05_03 v02.01.01`),
and the 27B0 profile is Volume 6 `06_01_35`. The text lives under
`dev/knx-standard-3.0.0/_txt/` (read-only).

## Corpus

The local cache `tests-support/product-corpus/cache/vendor/` holds 502
`.knxprod` files, 1353 application programs. The System B family is 885 of
them (scan of the `<LdCtrl*>` elements of each application XML, 2026-10-28;
`analyze-load-ops.py` tallies the same from the rendered models):

| mask | apps | load ops that appear | flash |
|---|---:|---|---|
| 07B0 | 850 | RelSegment, WriteRelMem, LoadImageProp (770), WriteProp (416), CompareProp (183), CompareRelMem (2); Connect/Unload/Load/LoadCompleted/Restart/Disconnect in the 26 that carry a full procedure, the rest come from the mask template (see below) | yes |
| 27B0 (RF) | 6 | RelSegment, WriteRelMem, LoadImageProp | gated with 07B0 |
| 57B0 (IP) | 1 | RelSegment, WriteRelMem, LoadImageProp, WriteProp | gated with 07B0 |
| 2705 (RF) | 26 | AbsSegment, TaskSegment, Load, Unload, LoadCompleted, CompareProp, Restart | no: System 7 shaped, not gated |
| 2920 (RF) | 2 | DeclarePropDesc, WriteProp, CompareProp | no: property-only, not gated |

The `.knxprod` files and the extracted models are vendor data and gitignored;
`tests-support/product-corpus/fetch.sh` regenerates the cache.

## The System B op set

What the load state machine accepts is Resources §4.23 (Table 93 events, Table
94 transitions) and Management Procedures §3.31.3
(`DMP_LoadStateMachineWrite_RCo_IO`: a 10-octet write to
`PID_LOAD_STATE_CONTROL`, the first octet the event). Configuration Procedures
§3.5.1.2 Table 4 names the controls a System B device supports: Start Loading
(01h), Load Completed (02h), Additional Load Controls 03h with subtype 0Bh Data
Relative Allocation, and Unload (04h). The 27B0 profile (06_01_35 §6.3.1,
Table 1) lists the same four as mandatory and the absolute and task records
(subtypes 00h to 05h) as optional.

| op | standard | bussard (`crates/bussard-download/src/flash/plan.rs` unless noted) | status |
|---|---|---|---|
| `LdCtrlConnect`, `LdCtrlDisconnect` | DM_Connect 3/5/2 §3.2, steps 01 and 12 of 3/5/3 §3.5.2 | one connection for the whole procedure, no step | supported |
| `LdCtrlUnload` | event 04h, 3/5/2 §3.31.3.1; step 05 of §3.5.2 | `FlashStep::Unload` | supported |
| `LdCtrlLoad` | event 01h, §3.31.3.2 | `FlashStep::StartLoading`, skipped for an object that gets no segment | supported |
| `LdCtrlLoadCompleted` | event 02h, §3.31.3.3; the device computes the MCB CRC on this transition (3/5/1 §4.2.27.1.2) | `FlashStep::LoadCompleted` | supported |
| `LdCtrlRelSegment` | 03h/0Bh Data Relative Allocation, §3.31.3.4; 3/5/3 §3.5.1.2 (Mode, Fill, same base on re-allocation) | `FlashStep::AllocateSegment`, then `PID_TABLE_REFERENCE` read (`bussard-mgmt/src/load.rs` `allocate_segment`); `@Mode` and `@Fill` copied verbatim as ETS does, also a Mode 0 Fill (#480, `syn-relseg-fill`); table objects always `00 00` | supported |
| `LdCtrlWriteRelMem` | memory write at base + offset; 3/5/3 §3.5.1.4 Table 5 (`A_Memory_Write` up to 64k, `A_UserMemory_Write` above); DM_MemWrite §3.16.2 chunks sized to `PID_MAX_APDU_LENGTH` (3/5/1 §4.3.7, 12 octets without it) | `FlashStep::WriteRelMem`, the image cut to the op's `Size` (#564); above 0xFFFF `A_MemoryExtended_Write` when `<Options SupportsExtendedMemoryServices>` is set, else `A_UserMemory_Write` (03_03_07 §3.5.6.3, 15 octets per request, #472) | supported |
| `LdCtrlWriteMem` | absolute `A_Memory_Write` | `FlashStep::WriteMem` | supported |
| `LdCtrlWriteProp` | DM_InterfaceObjectWrite §3.25; PID 13 is `PID_PROGRAM_VERSION`, 5 octets manufacturer, device type, version (3/5/1 §4.2.13), written before `LoadCompleted` (§3.5.2 step 06); PID 27 one 8-octet element per write (§4.2.27) | `FlashStep::WriteProp`; the zero placeholder for PID 13 is replaced by the application id | supported |
| `LdCtrlLoadImageProp` | read `PID_MCB_TABLE` and compare the CRC16-CCITT (init FFFFh, check value E5CCh) with the image (§4.2.27, §4.18.6.2.5); the "read and save CRC" step of §3.5.2 | `FlashStep::LoadImageProp`, `read_mcb_table` | supported |
| `LdCtrlCompareProp` | DM_InterfaceObjectRead §3.27 plus compare | `FlashStep::CompareProp` (mask honoured, `Range` kept as a no-op) | supported |
| `LdCtrlCompareRelMem` | memory read at base + offset plus compare | `FlashStep::CompareRelMem` (mask, invert) | supported (2 MDT apps) |
| `LdCtrlRestart` | Basic Restart §3.7.1.1 (unconfirmed `A_Restart`); the confirmed restart is the Master Reset with erase code 01h (§3.7.1.2 Table 4) | `FlashStep::Restart`; confirmed form for secure-capable applications, bare otherwise | supported |
| `LdCtrlMasterReset` | Master Reset §3.7.1.2: restart type 1, erase code, channel, confirmed by `A_Restart_Response` | `FlashStep::MasterReset`: the confirmed form with the op's erase code and channel; a bare `A_Restart` on KNX Virtual only (its ETS capture); error code 2 falls back to a basic restart | no vendor capture; capture plan in `testing-campaign.md` (#546) |
| `LdCtrlMerge` | none: the mask template's splice marker | spliced | supported |
| `LdCtrlAbsSegment`, `LdCtrlTaskSegment`, `LdCtrlTaskCtrl1`, `LdCtrlTaskPtr`, `LdCtrlTaskCtrl2` | Additional Load Controls subtypes 00h to 05h, §3.31.3.4; optional in the 27B0 profile | System 7 lowering only; refused on System B | by design | All five lowered (TaskPtr and TaskCtrl2 since #527) with the KNX 3/5/2 §3.31.2 layout, mandatory on 0701/0705 per Profiles Annex A.2.4.1; in the local corpus TaskPtr/TaskCtrl2 occur only on masks 0020/0021/0025, so no flashable application uses them yet and no capture exists. A `LdCtrlTaskSegment` on an LSM the memory-mapped form has no machine for (LsmIdx 5 on the Busch-Jaeger 0701 applications; 3/5/2 §3.31.2 names LSMs 1 to 4) is not sent, as ETS sends none (`captures/synthetic/syn-s7-lsm5`, #489); the property realisation (0705) keeps it until `syn-s7-lsm5-0705` (#604) is captured.
| `LdCtrlDeclarePropDesc`, `LdCtrlDelay`, other `Raw` | | refused before any write | 2920 only in the corpus |

The factory reset that opens a download of a secure-capable application
(erase code 07h, Master Reset §3.7.1.2 Table 4, AN194 for what it resets) is
not an op: `plan_flash` inserts it from the restart form.

## Where the frame ops come from

A `MergedProcedure` application carries only its own `<LoadProcedure
MergeId="N">` blocks. The frame around them (Connect, the Unload of every
load state machine, Load, the table allocations and writes, the
`PID_PROGRAM_VERSION` write, LoadCompleted, Restart) is the mask's
complete-download `Load` procedure (`ProcedureSubType="all"`), the per-mask
form of 3/5/3 §3.5.2, and `plan_flash` splices the application's blocks in
at its `LdCtrlMerge` markers.

- The product file's `knx_master.xml`, when it declares the mask: parsed by
  `crates/bussard-ets/src/master.rs` (`parse_master_template`).
- Otherwise bussard's built-in template (`MasterTemplate::builtin_for_mask`,
  same file, #607) for 07B0, 27B0 and 57B0. `bussard-prod` fills it in where
  it attaches the product's templates, so `flash`, `plan` and the MCP tools
  see the same ops. A product without master data (the synthetic catalogue's
  `<KNX/>` stub) therefore plans the same download as one with it.

The built-in ops are those of every master-data version in the corpus
(schemas 10 to 23; the three masks are identical).
`test_builtin_for_mask_matches_corpus_master` (bussard-prod, gated on
`BUSSARD_PRODUCT_CORPUS`) compares them with each corpus file's master. The
System 7 masks declare no `Load` procedure in the master data and their
lowering takes nothing from a template; the PL110 mask 17B0 has a template
of its own that bussard does not carry (no corpus application uses it).

## Steps of the standard's procedure with no op

Configuration Procedures §3.5.2 (complete download) and §3.5.3 (partial
downloads) have steps a product procedure never spells out:

| step | bussard |
|---|---|
| 02 descriptor type 0, 03 authorize | done at connect |
| 04 manufacturer id equals `PID_MANUFACTURER_ID` | not done (#547) |
| read `PID_TABLE_REFERENCE` after every allocation, zero means failure | done |
| read and save the CRC after each `LoadCompleted` | the application's `LoadImageProp` ops, else the template's |
| 11 modify access keys | not done (no product in the corpus sets keys) |
| partial download: `Unload`, `Load`, Mode 0 allocation around a parameter write | parameters-only download skips the first two (#543) |
| LoadCompleting (5) and Unloading (4): poll `PID_LOAD_STATE_CONTROL` every 3 s for up to 30 s (3/5/1 §4.23.2.4.1) | not done (#479) |

## Table images

The images the table ops stream are built in `crates/bussard-download/src/compute.rs`:

- Group address table, realisation type 7 (3/5/1 §4.16.8, Table 78): count
  word, then the addresses in ascending order; TSAP is the 1-based index. No
  own-address slot (that is the System 1/2/7 layout).
- Association table, realisation type 6 (§4.17.5, Table 82): count word, then
  format 1 entries of TSAP and ASAP, two octets each, the sending association
  first per object. Format 0 (one octet each) is never checked for (#545).
- Group object table, realisation type 7 (§4.18.6, Tables 86 to 88): count
  word, then one descriptor word per ASAP: bit 15 update, 14 transmit, 13 read
  on init, 12 write, 11 read, 10 communication, 9 to 8 priority, 7 to 0 value
  field type. Priority is always written Low (#541); value field types above
  14 fall back to 0 (#545). An unlinked object gets communication cleared,
  which is why `apply` has to rewrite this table when a link set changes
  (#540).

## Master reset

No vendor device in the corpus uses `LdCtrlMasterReset`; its only user is KNX
Virtual. The factory reset bussard sends itself (erase code 7) and the
confirmed restart (erase code 1) are the Master Reset of 3/5/2 §3.7.1.2 with
the process time of §3.7.1.2.2 honoured as a minimum wait; above 60 s bussard
logs a warning and still waits it out (#546).

## Recommendation

The System B op set is complete for every 07B0, 27B0 and 57B0 application in
the corpus. The open items are the issues above: the group-object table on
`apply` (#540, P1), the descriptor priority (#541, P1), the parameters-only
procedure (#543), the format checks (#545), the restart details (#546) and the
manufacturer check (#547). The RF masks 2705 and 2920 need their own lowering
before their ops matter.
