//! The application-download engine: interpret an [`ApplicationProgram`]'s typed
//! [`LoadProcedure`]s against a live (or mock) System B device.
//!
//! This is the write side of the first ETS-free application download (issue
//! #43). Where [`crate::apply`] rewrites the two link tables of an
//! already-programmed device, this module drives the full **application
//! download**: it opens the application-program interface object, allocates its
//! backing segments, streams the code image and the computed parameter image
//! into device memory, completes the load, and restarts the device — all by
//! interpreting the vendor's declared `LdCtrl*` op sequence rather than a
//! hand-coded one.
//!
//! # The op → primitive mapping (evidence)
//!
//! Each [`LoadOp`] maps to one management primitive. The mapping is derived from
//! the published KNX standard: the load-state machine and interface-object
//! property definitions in KNX Spec 3/5/1 (management interface-object
//! properties) and the download/management procedures in KNX Spec 3/5/2
//! (Management Procedures), with the transport framing from KNX Spec 3/3/4
//! (Transport Layer) and 3/3/7 (Application Layer):
//!
//! | `LoadOp`            | primitive                                            | notes |
//! |---------------------|------------------------------------------------------|-------|
//! | `Connect`           | (session boundary)                                   | the engine already holds one open `T_Connect`; a no-op per-op |
//! | `Disconnect`        | (session boundary)                                   | the engine disconnects once, at the end |
//! | `Unload{lsm}`       | [`write_load_control`]`(obj, Unload)`                | drops the app object to `Unloaded` — the factory-fresh start |
//! | `Load{lsm}`         | [`write_load_control`]`(obj, StartLoading)`          | opens the app object for writing → `Loading` |
//! | `LoadCompleted{lsm}`| [`write_load_control`]`(obj, LoadCompleted)`         | persists + activates → `Loaded`; `Error` surfaces loudly |
//! | `RelSegment{lsm,sz}`| [`allocate_segment`]`(obj, sz, None)`                | device places the segment; its base address is captured for the writes that follow |
//! | `WriteRelMem{off,sz}`| [`write_memory`]`(base+off, image)`                 | `image` is the code segment `.data` (`AppliesTo=full`) or the computed parameter image (`AppliesTo=par`) |
//! | `WriteMem{addr,sz}` | [`write_memory`]`(addr, image)`                      | absolute placement (an absolute segment's data) |
//! | `WriteProp{ot,pid}` | [`write_property`]                                   | a property write, echo-validated |
//! | `CompareProp{oi,pid}`| [`compare_property`]                                | reads the property and byte-compares it (under `Mask`) against the op's `InlineData`; a mismatch fails the flash |
//! | `CompareRelMem{oi,off}`| [`compare_rel_mem`]                              | reads relative memory at `base+off` and byte-compares it (under `Mask`, optionally `Invert`ed) against the op's `InlineData`; a mismatch fails the flash |
//! | `LoadImageProp{oi,pid}`| [`read_mcb_table`]                                | reads the object's `PID_MCB_TABLE` one element per request and checks the device CRC over the stored segment against the written image |
//! | `Restart`           | `restart`                                            | last op; fire-and-forget |
//!
//! # `lsm_idx` → interface-object index
//!
//! The ops carry a `LsmIdx` (load-state-machine index), not a device object
//! index. On a System B device the application program is a single loadable
//! interface object (`OT_APPLICATION_PROGRAM`, type 3), discovered by probing
//! `PID_OBJECT_TYPE` exactly as [`crate::apply::discover_table_objects`] does for
//! the table objects. Every relative-segment load-state-machine in a
//! single-application device is that one object, so all `lsm`-bearing ops resolve
//! to the discovered application-program object index. Multi-LSM devices (BCU2,
//! multiple applications) are out of scope and refused at pre-flight — see
//! [`plan_flash`].
//!
//! # Pre-flight, then execute — never die mid-flash
//!
//! [`plan_flash`] validates the **whole** selected procedure up front: it refuses
//! a mask mismatch, an unsupported op (`AbsSegment`, `TaskSegment`, `TaskCtrl1`,
//! and any `Raw`), and a procedure whose segment references it cannot resolve.
//! `LoadImageProp` is executable: it lowers to an MCB-table integrity read that
//! validates the device's CRC over the segment it stored against the bytes
//! bussard wrote. Only a fully-executable [`FlashPlan`] reaches [`flash`], so
//! the engine never begins writing a procedure it cannot finish. Every
//! property/load-control write is confirmed by the device's echo, and memory
//! content is confirmed after the load by the device's own MCB CRC
//! (`LdCtrlLoadImageProp`) plus the end-of-segment spot check — the segment stream
//! itself is not read back chunk by chunk, exactly as ETS streams it (see
//! [`bussard_mgmt::write_memory_chunked`]).

use std::collections::{BTreeMap, BTreeSet};

use bussard_mgmt::MgmtError;
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{
    self, LoadControl, LoadState, WriteError, allocate_segment, compare_property, compare_rel_mem,
    is_connection_death, master_reset_via_basic_restart, read_load_state, read_mcb_table,
    read_memory, read_table_reference, write_load_control, write_property,
};
use bussard_mgmt::tables::OT_APPLICATION_PROGRAM;
use bussard_prod::application::{ApplicationProgram, LoadOp, LoadProcedure, SegmentKind};

/// A step of a validated flash, ready to render for the pre-flight display and
/// to execute in order. Each corresponds to one supported [`LoadOp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashStep {
    /// Drop a loadable object to `Unloaded` (`LdCtrlUnload`).
    Unload {
        /// The op's `LsmIdx`, resolved to a device object index at execute time
        /// (see [`resolve_object_target_opt`]). `None` (op carried no `LsmIdx`) or an
        /// index the device does not expose falls back to the discovered
        /// application-program object — preserving the single-object behaviour a
        /// conformant ProductDefault procedure (thelsing) relies on.
        target: Option<u32>,
    },
    /// Open a loadable object for writing (`LdCtrlLoad`).
    StartLoading {
        /// The op's `LsmIdx`, resolved like [`FlashStep::Unload::target`].
        target: Option<u32>,
    },
    /// Allocate a relative segment; the device places it (`LdCtrlRelSegment`).
    /// Carries the source of the image the following `WriteRelMem` streams and
    /// the byte count, resolved at plan time.
    AllocateSegment {
        /// Requested segment size in octets.
        size: u32,
        /// The op's `LsmIdx`, resolved like [`FlashStep::Unload::target`]. The
        /// allocation runs against — and reads `PID_TABLE_REFERENCE` (PID7,
        /// the per-object base) from — this object.
        target: Option<u32>,
        /// The device-side pre-fill the allocation requests, from the source
        /// `LdCtrlRelSegment`'s fill (`Mode`/`Fill`) (see
        /// [`bussard_ets::LoadOp::RelSegment::fill`]). `Some(b)` sets the
        /// relative-segment structure's fill flag with byte `b`; `None` (the
        /// DA.tp default) leaves it clear, byte-identical to the historical
        /// no-fill allocation. Threaded into
        /// [`bussard_mgmt::encode_rel_segment`]'s `fill_byte` argument.
        fill: Option<u8>,
    },
    /// Write a relative-memory image at `segment base + offset` (`LdCtrlWriteRelMem`).
    WriteRelMem {
        /// Offset within the just-allocated segment.
        offset: u32,
        /// Which image this streams and how many octets it is.
        image: ImageRef,
        /// The op's `ObjIdx`, resolved to a device object index at execute time.
        /// ETS→KNX-Virtual writes the app segment to `ObjIdx=4` (device object 4,
        /// base `0x6000`) — **not** the type-discovered application-program object
        /// (index 3, base `0x8000`). Resolving by this index, not by object type,
        /// is the divergence-#2 fix. `ObjIdx=0` / an absent index falls back to the
        /// discovered app object (the conformant thelsing shape).
        target: Option<u32>,
    },
    /// Write an absolute-memory image at a fixed address (`LdCtrlWriteMem`).
    WriteMem {
        /// Absolute device memory address.
        address: u32,
        /// Which image this streams.
        image: ImageRef,
    },
    /// Write an interface-object property (`LdCtrlWriteProp`). Carries the value
    /// to write (from the op's `InlineData`) and the object index the write
    /// targets, resolved at plan time. A value-less op is refused at plan time
    /// (see [`PlanError::UnsupportedWriteProp`]) rather than lowering to a step
    /// that would execute as a silent no-op.
    WriteProp {
        /// The interface-object index (`ObjIdx`) the property write targets.
        obj_idx: u32,
        /// The interface-object type (`ObjType`), kept for the trace/label.
        obj_type: u32,
        /// The property id.
        prop_id: u32,
        /// The value bytes to write (decoded `InlineData`), echo-validated.
        value: Vec<u8>,
        /// The 1-based element the value is written from (`StartElement`, default 1).
        start_element: u16,
    },
    /// Verify an interface-object property against expected data
    /// (`LdCtrlCompareProp`) — the read-only precondition check that is the twin
    /// of [`FlashStep::WriteProp`]. Reads the property and byte-compares it
    /// (under the optional mask) against the op's `InlineData`; a mismatch fails
    /// the flash. A `Range`-only compare (no `InlineData`) carries no `expected`
    /// bytes and is a no-op confirm, kept so the procedure still lowers whole.
    CompareProp {
        /// The interface-object index (`ObjIdx`) whose property to read.
        obj_idx: u32,
        /// The property id (`PropId`) to compare.
        prop_id: u32,
        /// The expected property bytes (decoded `InlineData`), or `None` for a
        /// `Range`-only op with no literal expectation to byte-compare.
        expected: Option<Vec<u8>>,
        /// The comparison mask (decoded `Mask`); `None` compares every byte.
        mask: Option<Vec<u8>>,
    },
    /// Verify relative (segment-relative) memory against expected data
    /// (`LdCtrlCompareRelMem`) — the read-only precondition check that is the
    /// memory twin of [`FlashStep::CompareProp`] and the verify counterpart of
    /// [`FlashStep::WriteRelMem`]. Reads `expected.len()` octets at the target
    /// object's `segment base + offset` and byte-compares them (under the optional
    /// mask, with the sense inverted when `invert` is set) against the op's
    /// `InlineData`; a failing compare fails the flash. An op with no `InlineData`
    /// carries no `expected` bytes and is a no-op confirm, kept so the procedure
    /// still lowers whole.
    CompareRelMem {
        /// The op's `ObjIdx`, resolved to a device object index at execute time —
        /// the object whose `PID_TABLE_REFERENCE` supplies the read base, exactly
        /// as [`FlashStep::WriteRelMem::target`] resolves its write base.
        target: Option<u32>,
        /// The byte offset within the object's segment (`Offset`); the read starts
        /// at `segment base + offset`.
        offset: u32,
        /// The expected memory bytes (decoded `InlineData`), or `None` for an op
        /// with no literal expectation to byte-compare.
        expected: Option<Vec<u8>>,
        /// The comparison mask (decoded `Mask`); `None` compares every byte.
        mask: Option<Vec<u8>>,
        /// Whether the comparison sense is inverted (`Invert="true"`): the device
        /// memory must *differ* from `expected` under the mask when set.
        invert: bool,
    },
    /// Validate a loadable object's image via its memory-control-block table
    /// (`LdCtrlLoadImageProp`). After the object is `Loaded`, read its
    /// `PID_MCB_TABLE` (PID 27) and, where this engine wrote the object's image,
    /// confirm the device's CRC16-CCITT over the stored segment matches the CRC
    /// over the bytes bussard streamed.
    LoadImageProp {
        /// The target object index (`ObjIdx`), resolved at plan time. For an op
        /// that targets the single application-program object bussard flashes,
        /// this is that object; other indices are read but not our own image.
        obj_idx: u32,
        /// The property id to read (27 = `PID_MCB_TABLE`).
        prop_id: u32,
        /// How many MCB elements to read (`Count`), at least 1. They are read
        /// **one per request**: a real Jung 3361-1MWW refused a single
        /// `count=6` read with a zero-count response (issue #89 campaign), and
        /// the ETS capture of the same application reads index 1..=6 one at a
        /// time. See [`read_mcb_table`].
        count: u32,
        /// The segment image whose CRC to check against the device's MCB, when
        /// this engine wrote the target object's image; `None` when the op
        /// targets an object bussard did not itself write (read-only confirm).
        image: Option<ImageRef>,
    },
    /// Persist and activate the load (`LdCtrlLoadCompleted`).
    LoadCompleted {
        /// The op's `LsmIdx`, resolved like [`FlashStep::Unload::target`].
        target: Option<u32>,
    },
    /// Restart the device (`LdCtrlRestart`).
    ///
    /// Sent as a bare `A_Restart` (APCI `0x380`), or, when the plan
    /// [`uses_confirmed_restart`](FlashPlan::uses_confirmed_restart), as the
    /// confirmed master reset with erase code 1 that ETS ends a System B download
    /// with (issue #117 captures).
    Restart,
    /// Factory-reset the device before the download (issue #117, #89).
    ///
    /// A confirmed master-reset `A_Restart` (APCI `0x381`, `[erase_code, 0]`)
    /// sent as a numbered request. With erase code 7 ("factory reset without
    /// individual address") the device erases its application program,
    /// parameters, group addresses and links, keeps its individual address,
    /// answers `A_Restart_Response` with a process time, and reboots. The engine
    /// waits out the process time and reconnects before the next step.
    ///
    /// Not a load-procedure op: the planner inserts it before the first
    /// `Unload` when the download allocates a filled segment and writes only the
    /// octets that differ from the fill (a re-flash would otherwise inherit the
    /// previous image's octets wherever the new one writes nothing), and the CLI
    /// adds it when a device that is not factory-fresh is flashed. ETS opens an
    /// initial System B download the same way (`4f 81 07 00`, answered
    /// `4f a1 00 00 08`).
    FactoryReset {
        /// The master-reset erase code (7 = factory reset keeping the individual
        /// address).
        erase_code: u8,
    },
    /// Master-reset the device mid-procedure (`LdCtrlMasterReset`).
    ///
    /// Sends a master-reset `A_Restart`, waits for the device to reboot and come
    /// back, re-establishes the L4 connection, re-authorizes it, and resumes the
    /// remaining steps. This is the single spec-required reconnect-after-restart
    /// a master reset entails; memory writes are absolute/relative-addressed and
    /// stateless, so resuming is just continuing the op list on the fresh
    /// connection.
    MasterReset {
        /// The erase code from the op's `EraseCode` attribute (defaulting to `1`,
        /// "Confirmed Restart", when absent).
        erase_code: u8,
        /// The channel number from the op's `ChannelNumber` attribute (`0` = the
        /// whole device).
        channel_number: u8,
    },

    // --- System 7 (mask 0705 / 0701) steps -----------------------------------
    //
    // System 7 is memory-mapped and absolute-addressed (`[system7-spec §2/§3]`):
    // the LSM index names a load-state machine (a memory region), NOT a device
    // object, so these steps carry the raw `lsm` index and are driven through the
    // [`bussard_mgmt::LsmAccess`] seam (memory-mapped 11-octet record by default,
    // property-based alternative) rather than System B's `PID_LOAD_STATE_CONTROL`
    // property on a resolved object index. Kept distinct from the System B steps
    // above so B semantics are never overloaded.
    /// Tear down System 7 load-state machine `lsm` to `Unloaded`
    /// (`LdCtrlUnload`, `[system7-spec §3]`).
    Sys7Unload {
        /// The 1-based LSM index (a memory-mapped load-state machine).
        lsm: u32,
    },
    /// Open System 7 load-state machine `lsm` for loading (`LdCtrlLoad`).
    Sys7StartLoading {
        /// The 1-based LSM index.
        lsm: u32,
    },
    /// Allocate an absolute segment on `lsm` at `address` and, when the segment
    /// carries `<Data>`, stream that image to `address` in negotiated-max-APDU chunks
    /// (`LdCtrlAbsSegment`, `[system7-spec §4.2]`). A data-less segment (e.g. the
    /// `0x0700` RAM region) is an allocate-only record — no memory write.
    Sys7AbsSegment {
        /// The 1-based LSM index the segment belongs to.
        lsm: u32,
        /// The absolute 16-bit memory address the segment is placed at.
        address: u32,
        /// The declared segment size in octets (the allocation length).
        size: u32,
        /// The memory type for the allocation (`3` = EEPROM, `2` = RAM): the op's
        /// `MemType`, or derived from the address via the mask profile.
        mem_type: u8,
        /// The allocation record's access-attribute octet: the op's `Access`
        /// (`0xF2`/`0xF3` on the Jung System 7 apps), else `0xF2`.
        seg_flags: u8,
        /// The allocation record's checksum-control octet: the op's `SegFlags`
        /// (`0x80` checksum-controlled, `0x00` runtime-writable), else derived
        /// from `mem_type`. A `0x00` segment is not spot-checked after the
        /// restart: the application rewrites it (issue #89, 1.1.36 `0x4916`).
        checksum_ctrl: u8,
        /// The segment image to stream, when the segment carries `<Data>` (or a
        /// computed table image replaces it); `None` for an allocate-only record.
        image: Option<ImageRef>,
    },
    /// Finalize System 7 load-state machine `lsm` with a task/segment descriptor
    /// pointing at `address` (`LdCtrlTaskSegment`, `[system7-spec §4.3]`), issued
    /// immediately before `Sys7LoadCompleted`.
    Sys7TaskSegment {
        /// The 1-based LSM index.
        lsm: u32,
        /// The segment base address the task descriptor points at.
        address: u32,
        /// The 4-octet trailing marker `[lead][AppNumber:2 BE][ver]` ETS writes
        /// after the zero-length field (`[system7-spec §4.3]`). Derived at plan
        /// time from the mask family + application number (see
        /// [`bussard_mgmt::task_segment_marker`]). The real captures show the
        /// length field is `0x0000`, NOT the loaded span.
        marker: [u8; 4],
    },
    /// Write a task-control-table entry `count` times on `lsm` (`LdCtrlTaskCtrl1`,
    /// `[system7-spec §4.4]`) — the Theben/Steinel/Elsner second-phase op.
    Sys7TaskCtrl1 {
        /// The 1-based LSM index.
        lsm: u32,
        /// The task-control-table address.
        address: u32,
        /// The repeat count.
        count: u32,
    },
    /// Persist and activate System 7 load-state machine `lsm` → `Loaded`
    /// (`LdCtrlLoadCompleted`).
    Sys7LoadCompleted {
        /// The 1-based LSM index.
        lsm: u32,
    },
    /// Verify an absolute-memory range against expected inline data
    /// (`LdCtrlCompareMem`, `[system7-spec §4.5]`) — the Zennio second-phase op.
    /// Reads `expected.len()` octets at `address` and byte-compares; a mismatch
    /// fails the flash. No LSM interaction.
    Sys7CompareMem {
        /// The absolute address to read.
        address: u32,
        /// The expected bytes (the op's `InlineData`).
        expected: Vec<u8>,
    },
}

/// The origin of the bytes a memory-write step streams, resolved at plan time so
/// the pre-flight can report byte counts without re-deriving images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// The code-segment id the bytes belong to.
    pub segment_id: String,
    /// Where the bytes come from.
    pub kind: ImageKind,
    /// The image length in octets.
    pub len: usize,
}

/// Whether a memory image is the vendor code image, the computed parameters, or
/// a computed loadable table (address / association / group-object).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    /// The code segment's `<Data>` image (`AppliesTo=full`).
    Code,
    /// The computed parameter image (`AppliesTo=par`).
    Parameters,
    /// A computed loadable table image (obj1 address table, obj2 association
    /// table, or obj3 group-object table) streamed to a table object the master
    /// template's `WriteRelMem` targets by index.
    Table,
}

impl std::fmt::Display for ImageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageKind::Code => write!(f, "code"),
            ImageKind::Parameters => write!(f, "parameters"),
            ImageKind::Table => write!(f, "table"),
        }
    }
}

/// Why a procedure cannot be flashed. Every variant is a *pre-flight* refusal:
/// none of these can occur mid-write, because [`plan_flash`] returns one of them
/// instead of a [`FlashPlan`], and only a plan reaches [`flash`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum PlanError {
    /// No application program matched the requested id / order number.
    #[error("no application program {0:?} in the product data")]
    NoApplication(String),

    /// The product data holds several candidate applications and none was named.
    #[error(
        "the product data has {count} candidate application programs; \
         pass --application to choose one of: {ids}"
    )]
    AmbiguousApplication {
        /// How many candidates matched.
        count: usize,
        /// The candidate ids, comma-joined.
        ids: String,
    },

    /// The application's mask version does not match the device descriptor.
    #[error(
        "application program targets mask {app_mask} but device {device:?} reports mask \
         {device_mask:04X} — refusing to flash a mismatched application"
    )]
    MaskMismatch {
        /// The device's individual address (for the message).
        device: String,
        /// The mask the device reports.
        device_mask: u16,
        /// The mask the application declares.
        app_mask: String,
    },

    /// The device is not System B; only the 07B0 family is supported for now.
    #[error(
        "device {device:?} reports mask {device_mask:04X} ({system}) — `bussard flash` \
         supports System B (mask 07B0) only for now"
    )]
    NotSystemB {
        /// The device's individual address.
        device: String,
        /// The mask the device reports.
        device_mask: u16,
        /// The human-readable system classification.
        system: &'static str,
    },

    /// The application declares no mask version at all.
    #[error("application program {0:?} declares no mask version; cannot check compatibility")]
    MissingAppMask(String),

    /// The application has no load procedure to execute.
    #[error("application program {0:?} has no load procedures")]
    NoProcedure(String),

    /// The procedure contains an op this engine cannot execute. The whole
    /// procedure is refused so the device is never left half-flashed.
    #[error(
        "load procedure contains the unsupported operation {op} — \
         `bussard flash` cannot execute it and refuses the procedure rather than \
         leaving the device partially flashed (supported: Unload/Load/LoadCompleted/\
         RelSegment/WriteRelMem/WriteMem/WriteProp/CompareProp/CompareRelMem/LoadImageProp/Restart \
         on a single-LSM System B device)"
    )]
    UnsupportedOp {
        /// A human description of the offending op.
        op: String,
    },

    /// A `WriteRelMem`/`WriteMem` op names an image bussard cannot resolve.
    #[error(
        "load procedure step {step} references a segment or image that cannot be resolved: {reason}"
    )]
    UnresolvableImage {
        /// The 1-based op index in the procedure.
        step: usize,
        /// What could not be resolved.
        reason: String,
    },

    /// A write step's target range runs past the 24-bit extended-memory address
    /// space ([`MAX_MEMORY_END`]), or one of its component u32s is absurdly large
    /// ([`MAX_WRITE_SPAN`]). Refused at pre-flight so the device is never streamed
    /// a write at a truncated (wrong) address.
    #[error(
        "load procedure step {step} writes {size} octet(s) ending at {end} which exceeds the \
         24-bit memory address space (max {max:#08X}); {detail} — refusing to flash rather \
         than truncating the address and writing to the wrong device memory",
        max = MAX_MEMORY_END - 1
    )]
    AddressOutOfRange {
        /// The 1-based op index in the procedure.
        step: usize,
        /// The write length in octets.
        size: u64,
        /// The exclusive end address the write would reach.
        end: u64,
        /// Which component (base/offset/address) drove it out of range.
        detail: String,
    },

    /// A `WriteProp` op carries a value shape this engine cannot safely execute.
    /// Refused at pre-flight rather than silently dropped so the device is never
    /// left `Loaded`-but-misconfigured.
    #[error(
        "load procedure step {step} is an LdCtrlWriteProp this engine cannot execute: {reason} — \
         refusing the procedure rather than reporting a skipped property write as done"
    )]
    UnsupportedWriteProp {
        /// The 1-based op index in the procedure.
        step: usize,
        /// Why the op's shape cannot be executed.
        reason: String,
    },

    /// A spliced master-template op programs a standard table object (obj1
    /// address, obj2 association, obj3 group-object) but no table image was
    /// supplied for it. Refused at pre-flight — writing the app segment (or
    /// nothing) to a table object would leave the device misconfigured, so the
    /// caller must supply the computed table image (from the model links) for
    /// every table object the template writes.
    #[error(
        "load procedure step {step} programs table object {obj_idx} \
         ({table}) but no table image was supplied for it — a merged flash must \
         compute the address/association/group-object tables from the device's \
         links; refusing rather than writing a wrong image to the table object"
    )]
    MissingTableImage {
        /// The 1-based op index in the procedure.
        step: usize,
        /// The table object index (1/2/3).
        obj_idx: u32,
        /// A human name for the table object.
        table: &'static str,
    },

    /// A System 7 step's address, size or count does not fit the field the
    /// `AdditionalLoadControls` record carries for it. Refused at plan time: the
    /// executor used to truncate with `as u16`, which puts a **wrong frame on the
    /// bus** (an allocation at a truncated address) before the following write
    /// refuses.
    #[error(
        "load procedure step {step} has a System 7 {field} of {value:#X}, which does not fit \
         the {max:#X} ceiling the AdditionalLoadControls record carries — refusing to flash \
         rather than truncating it and allocating the wrong memory"
    )]
    Sys7FieldOutOfRange {
        /// The 1-based op index in the procedure.
        step: usize,
        /// Which field is out of range ("segment address", "segment size", …).
        field: &'static str,
        /// The value the product data asked for.
        value: u64,
        /// The largest value the record's field can carry.
        max: u64,
    },

    /// A System 7 op names a load-state machine index outside `1..=15`. The index
    /// rides in the **high nibble** of the record's opcode octet, so anything
    /// larger silently wraps into a different LSM (or into index 0) and anything
    /// smaller names no machine at all.
    #[error(
        "load procedure step {step} names System 7 load-state machine {lsm}, which is outside \
         the 1..=15 range the record's opcode nibble can carry — refusing to flash rather than \
         driving a different LSM than the product data asks for"
    )]
    Sys7LsmOutOfRange {
        /// The 1-based op index in the procedure.
        step: usize,
        /// The LSM index the product data named.
        lsm: u32,
    },
}

/// The largest System 7 memory address (and segment size) the 2-octet fields of
/// an `AdditionalLoadControls` record can carry. System 7 is a 16-bit,
/// absolute-addressed memory map (`[system7-spec §2]`).
const SYS7_MAX_ADDRESS: u32 = 0xFFFF;

/// The LSM index range a memory-mapped record can name: the index occupies the
/// high nibble of the opcode octet ([`bussard_mgmt::sys7::wrap_memory_lsm_record`]),
/// and `0` names no machine.
const SYS7_LSM_RANGE: std::ops::RangeInclusive<u32> = 1..=15;

/// Validates a System 7 LSM index at plan time, so the executor never folds an
/// out-of-range index into the record's opcode nibble.
fn check_sys7_lsm(step: usize, lsm: u32) -> std::result::Result<u32, PlanError> {
    if SYS7_LSM_RANGE.contains(&lsm) {
        Ok(lsm)
    } else {
        Err(PlanError::Sys7LsmOutOfRange { step, lsm })
    }
}

/// Validates one 16-bit System 7 record field (an address, a size) at plan time.
fn check_sys7_u16(
    step: usize,
    field: &'static str,
    value: u32,
) -> std::result::Result<u32, PlanError> {
    if value <= SYS7_MAX_ADDRESS {
        Ok(value)
    } else {
        Err(PlanError::Sys7FieldOutOfRange {
            step,
            field,
            value: u64::from(value),
            max: u64::from(SYS7_MAX_ADDRESS),
        })
    }
}

/// The standard System B table object indices a master template programs, and
/// their human names. Used to refuse a spliced template that writes one of these
/// objects without a supplied table image.
fn table_object_name(idx: u32) -> Option<&'static str> {
    match idx {
        1 => Some("address table"),
        2 => Some("association table"),
        3 => Some("group-object table"),
        _ => None,
    }
}

/// `PID_PROGRAM_VERSION` (PID 13) — the application object's app-id / run-state
/// property. The master template writes it with an all-zero placeholder that the
/// flash replaces with the synthesized [`app_program_version`] value.
const PID_PROGRAM_VERSION: u32 = 13;

/// The 5-octet placeholder the master template ships for the PID-13 write; ETS
/// (and this engine) overwrite it with the real application id.
const APP_ID_PLACEHOLDER: [u8; 5] = [0, 0, 0, 0, 0];

/// Extracts the 2-octet KNX manufacturer id from an application-program id.
///
/// Application ids begin with the manufacturer prefix `M-XXXX` (four hex
/// digits), e.g. `M-00FA_A-2500-10-51CB` → `0x00FA`. Returns `None` when the id
/// does not start with a parseable `M-XXXX` prefix.
fn manufacturer_from_app_id(id: &str) -> Option<u16> {
    let hex = id.strip_prefix("M-")?.get(..4)?;
    u16::from_str_radix(hex, 16).ok()
}

/// Synthesizes the app object's `PID_PROGRAM_VERSION` (app-id) value for an
/// application, or `None` when the identity is too incomplete to build one.
///
/// Needs the manufacturer (from the id prefix), the application number, and the
/// application version; any missing piece yields `None`, leaving a placeholder
/// PID-13 write untouched rather than writing a partly-zero id.
fn app_program_version_value(app: &ApplicationProgram) -> Option<[u8; 5]> {
    let manufacturer = manufacturer_from_app_id(&app.id)?;
    let application_number = app.application_number?;
    let application_version = app.application_version?;
    Some(crate::compute::app_program_version(
        manufacturer,
        application_number as u16,
        application_version as u8,
    ))
}

/// Replaces the master template's all-zero PID-13 placeholder with the
/// synthesized app-id, leaving every other property write (and any non-zero
/// PID-13 value) unchanged.
///
/// Substitutes only when the op targets `PID_PROGRAM_VERSION`, an app-id value is
/// available, and the op's inline data is the exact 5-octet zero placeholder — so
/// a template that already carries a concrete PID-13 value is honoured verbatim.
fn maybe_substitute_app_id(
    prop_id: u32,
    inline_data: Option<&[u8]>,
    app_id_value: Option<&[u8; 5]>,
) -> Option<Vec<u8>> {
    if prop_id == PID_PROGRAM_VERSION && inline_data == Some(&APP_ID_PLACEHOLDER[..]) {
        if let Some(app_id) = app_id_value {
            return Some(app_id.to_vec());
        }
    }
    inline_data.map(<[u8]>::to_vec)
}

/// The largest byte length or u32 component a single flash write step may carry.
/// Real System B segments are tens of KiB; a value beyond this in the vendor XML
/// (or a device-supplied base) is treated as corrupt input and refused at plan
/// time rather than driving an allocation or an out-of-range address.
const MAX_WRITE_SPAN: u64 = 1024 * 1024;

/// The exclusive upper bound of the memory address space a flash write may reach:
/// the 24-bit extended-memory space, `0x100_0000`. A write whose end address
/// exceeds this is refused at plan time. This replaces the old 16-bit ceiling
/// (`0x1_0000`): the System B extended memory service reaches 24-bit addresses,
/// which the real 07B0 actuators require (segment bases at `0xf000..0x16000`,
/// writes running to `0x1aad3`). The per-chunk selection between the plain and
/// extended service happens at flash time from the resolved absolute address (see
/// [`bussard_mgmt::select_extended_memory`]).
const MAX_MEMORY_END: u64 = 0x100_0000;

/// The **upper bound** on how long to wait for a device to come back after a
/// restart (a master-reset `A_Restart` or the terminal one) before giving up on
/// the reboot. A real ETS→KNX-Virtual capture showed ~6.5s of silence while the
/// device rebooted; real devices vary, so the bound is deliberately generous.
///
/// It is a *bound*, not a fixed sleep: after
/// [`REBOOT_PROBE_MIN_WAIT`] of silence the session polls the device with a cheap
/// liveness probe every [`REBOOT_PROBE_INTERVAL`] (see
/// [`Session::reconnect_after_reboot`]), so a device that is back after 6.5 s is
/// picked up then instead of costing the full bound. Only a device that never
/// answers pays it.
const MASTER_RESET_REBOOT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the post-restart poll stays quiet before its first probe.
///
/// A device that is still shutting down can answer for a few hundred
/// milliseconds after it acknowledged the restart; probing immediately would
/// mistake that dying stack for a rebooted one and resume the procedure against
/// a device that is about to go away. Waiting a short minimum first makes the
/// first probe meaningful. Capped by the overall bound (see
/// [`reboot_wait_bound`]) so a test that shrinks the bound stays fast.
const REBOOT_PROBE_MIN_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// How long to wait between post-restart liveness probes.
const REBOOT_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// The tight L4 budget one post-restart liveness probe runs on: a device that is
/// still rebooting must be ruled out in a fraction of a second, not in the
/// standard 3 s ACK wait times four attempts.
const REBOOT_PROBE_TIMEOUTS: bussard_mgmt::Timeouts = bussard_mgmt::Timeouts {
    ack_timeout: std::time::Duration::from_millis(400),
    max_repetitions: 0,
    response_timeout: std::time::Duration::from_millis(400),
};

/// Environment variable that overrides [`MASTER_RESET_REBOOT_WAIT`] with a
/// millisecond value. Set by the mock-device restart tests so the reboot wait
/// does not stall them; unset in normal use, so the full generous bound applies.
/// It caps the minimum quiet period too, so a tiny value really is a tiny wait.
const REBOOT_WAIT_MS_ENV: &str = "BUSSARD_FLASH_REBOOT_WAIT_MS";

/// The upper bound on the post-restart wait, honouring [`REBOOT_WAIT_MS_ENV`].
fn reboot_wait_bound() -> std::time::Duration {
    std::env::var(REBOOT_WAIT_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_millis)
        .unwrap_or(MASTER_RESET_REBOOT_WAIT)
}

/// The numbered-exchange count at which the flash proactively cycles the L4
/// connection (a graceful `T_Disconnect`/`T_Connect` + re-authorize) *between*
/// steps, to stay under the device's per-connection budget.
///
/// A real connection-oriented device drops a long-held L4 connection after a
/// bounded number of numbered exchanges — the KNX Virtual DA.tp device was
/// observed to drop at ~35, and a whole post-master-reset flow on one connection
/// sits right at that edge, failing ~50% of the time. ETS reconnects the L4
/// connection periodically within a download (its capture shows repeated
/// T_Disconnect/T_Connect cycles at 2–65-exchange intervals) to stay well clear.
///
/// 10 is deliberately well under the observed drop point (16–35, historically as
/// low as ~7 on the live KV DA.tp) so a proactive cycle usually lands before the
/// device drops: the check runs *before* each step, and a single step (a chunked
/// memory write) can add several exchanges, so the effective peak before a cycle
/// is `THRESHOLD` + one step's exchanges. The threshold is intentionally
/// conservative rather than tuned to the mean because the drop is
/// non-deterministic; whatever it misses is caught by resume-on-drop (see
/// [`flash`]), which reconnects and re-runs the step when the connection dies
/// unexpectedly mid-flow. Only sessions that
/// [`can_reconnect`](Session::can_reconnect) cycle; a single-connection session
/// ([`Session::from_connection`], mocks) keeps the one-connection path.
const RECONNECT_EXCHANGE_THRESHOLD: u32 = 10;

/// Environment variable that overrides [`RECONNECT_EXCHANGE_THRESHOLD`] with a
/// numeric value. Set by the flash-mock periodic-reconnect test so it can drive
/// the cycle at a low, deterministic exchange count against a small procedure;
/// unset in normal use, so the default 20 applies. Behaviour is otherwise
/// unchanged (a value of 0 disables proactive cycling entirely).
const RECONNECT_THRESHOLD_ENV: &str = "BUSSARD_FLASH_RECONNECT_EXCHANGES";

/// The proactive-reconnect exchange threshold, honouring [`RECONNECT_THRESHOLD_ENV`]
/// for tests. A value of 0 disables proactive cycling.
fn reconnect_exchange_threshold() -> u32 {
    std::env::var(RECONNECT_THRESHOLD_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(RECONNECT_EXCHANGE_THRESHOLD)
}

/// Environment variable that overrides the System 7 LSM realisation the product
/// data selected (`memory` for [`LsmRealisation::MemoryMapped`], `property` for
/// [`LsmRealisation::Property`]).
///
/// The spec (`[system7-spec §5]`) resolves the memory-vs-property disagreement by
/// building a seam with a best-evidence default (memory-mapped) and notes that
/// "flipping the profile bit is a one-line change". This env var is that switch:
/// it lets bussard's `LsmAccess` realisation be conformance-tested against a
/// property-based device side (the knx-sim `lsm_access: property` device) without
/// a second product carrying a property `HawkConfigurationData`. Unset in normal
/// use, so a flash uses exactly the product-driven realisation.
const SYS7_LSM_OVERRIDE_ENV: &str = "BUSSARD_FLASH_SYS7_LSM";

/// The System 7 LSM-realisation override from [`SYS7_LSM_OVERRIDE_ENV`], or `None`
/// to keep the product-driven realisation. `memory` keeps the memory-mapped record
/// at the profile's control/status addresses; `property` drives PID 5.
pub(crate) fn sys7_lsm_override() -> Option<bussard_mgmt::LsmRealisation> {
    match std::env::var(SYS7_LSM_OVERRIDE_ENV)
        .ok()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "property" | "prop" => Some(bussard_mgmt::LsmRealisation::Property),
        "memory" | "mem" | "memory-mapped" | "memorymapped" => {
            Some(bussard_mgmt::LsmRealisation::MemoryMapped {
                control_addr: 0x0104,
                status_addr: 0xB6EA,
            })
        }
        _ => None,
    }
}

/// How many times a single flash step is retried after an *unexpected* mid-flow
/// connection death before the flash gives up on it.
///
/// This is the resume-on-drop bound (see [`flash`]). A connection-oriented device
/// (KNX Virtual DA.tp) drops the L4 connection at a non-deterministic exchange
/// count that no fixed proactive threshold can reliably stay under; when a step
/// fails with a connection-death error and the session can reconnect, the engine
/// cycles the L4 connection and re-runs the step. Load state and allocated
/// segments are persistent device state that survive the drop, so re-running the
/// step on the fresh connection is safe (memory writes are absolute/relative
/// addressed; a re-issued StartLoading/allocate on an already-open object is
/// idempotent enough).
///
/// The bound is *per step*, but **any forward progress resets it** (each step that
/// completes starts the next step with a full budget): a healthy flash that simply
/// needs a reconnect every few steps is unbounded, while a genuinely dead device
/// that never completes a single step fails cleanly after this many reconnect
/// attempts rather than looping forever.
const MAX_RESUME_RECONNECTS: u32 = 5;

/// Identity of the application being flashed, for the pre-flight display and the
/// verify report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIdentity {
    /// The application-program id.
    pub id: String,
    /// The display name, if the program carried one.
    pub name: Option<String>,
    /// The KNX application number.
    pub application_number: Option<u32>,
    /// The application version.
    pub application_version: Option<u32>,
    /// The mask version, e.g. `"07B0"`.
    pub mask_version: String,
}

impl AppIdentity {
    /// The 5-octet `PID_PROGRAM_VERSION` value a completed flash of this
    /// application stamps on the device (`[manufacturer:2][number:2][version:1]`),
    /// or `None` when the identity is too incomplete to build one.
    ///
    /// This is the id the pre-flight compares against what a device already
    /// carries, to tell a re-flash of the *same* application (allowed) from a
    /// flash over a *different* one (refused without `--force`) — issue #79.
    pub fn program_version(&self) -> Option<[u8; 5]> {
        Some(crate::compute::app_program_version(
            manufacturer_from_app_id(&self.id)?,
            u16::try_from(self.application_number? & 0xFFFF).ok()?,
            u8::try_from(self.application_version? & 0xFF).ok()?,
        ))
    }
}

/// A validated, executable flash: the application identity, the device mask it
/// was checked against, and the ordered [`FlashStep`]s with their byte counts.
///
/// Produced by [`plan_flash`] only when the whole procedure is executable, so it
/// is the pre-flight the CLI shows before confirming, and the exact program
/// [`flash`] runs.
#[derive(Debug, Clone)]
pub struct FlashPlan {
    /// What is being flashed.
    pub identity: AppIdentity,
    /// The device mask the plan was validated against.
    pub device_mask: u16,
    /// The ordered steps.
    pub steps: Vec<FlashStep>,
    /// The per-segment images resolved at plan time (segment id → bytes), keyed
    /// so [`flash`] streams the very bytes the plan counted.
    images: BTreeMap<String, Vec<u8>>,
    /// The computed parameter images (segment id → bytes), retained so a caller
    /// can inspect what parameter values the flash will write.
    pub param_images: BTreeMap<String, Vec<u8>>,
    /// Whether the op sequence was spliced from a master template (a merged
    /// multi-object download). When true, a load-control op naming an object
    /// index the device does not expose (a template LSM5 op on a device without
    /// obj5) is **skipped** at execute time rather than redirected onto the app
    /// object — the master template targets objects that may not all exist on a
    /// given device. When false (a self-contained single-object procedure), an
    /// absent index falls back to the app object, preserving the conformant
    /// thelsing ProductDefault shape (`LsmIdx=4` on a device whose app object
    /// sits at a lower index).
    spliced_from_template: bool,
    /// The System 7 execution context when this is a System 7 (mask 0705/0701)
    /// plan, or `None` for a System B plan. Carries the data-driven mask profile
    /// (LSM realisation, authorize level, mem-types) and the per-segment `<Mask>`
    /// payloads the executor honours on masked writes (`[system7-spec §5]`).
    sys7: Option<Sys7Context>,
    /// Whether the terminal [`FlashStep::Restart`] is sent as the confirmed
    /// master reset with erase code 1 (the ETS form on System B devices whose
    /// download allocates filled segments) instead of a bare `A_Restart`.
    confirmed_restart: bool,
}

/// The System 7 execution context attached to a [`FlashPlan`] for a mask
/// 0705/0701 download (`[system7-spec §2.4/§5]`).
#[derive(Debug, Clone)]
pub struct Sys7Context {
    /// The data-driven mask profile: LSM realisation (memory-mapped vs property),
    /// authorize level, and the EEPROM/RAM mem-types for segment allocation.
    pub profile: bussard_mgmt::Sys7Profile,
    /// Per-segment `<Mask>` payloads (segment id → mask bytes), where a segment
    /// declares one (only the `0x4000` table region does in the corpus). A `0xFF`
    /// mask byte means "this byte belongs to the image, write it"; any other value
    /// means "device-owned, leave untouched" (`[system7-spec §4.2]`).
    pub segment_masks: BTreeMap<String, Vec<u8>>,
}

impl FlashPlan {
    /// Whether the plan starts with a [`FlashStep::FactoryReset`].
    pub fn has_factory_reset(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s, FlashStep::FactoryReset { .. }))
    }

    /// Adds a [`FlashStep::FactoryReset`] (erase code 7) before the first
    /// `Unload`, unless the plan already has one. The CLI calls this when the
    /// device is not factory-fresh. A no-op on a System 7 plan, whose download
    /// rewrites every region in full.
    pub fn require_factory_reset(&mut self) {
        if self.sys7.is_none() && !self.has_factory_reset() {
            insert_factory_reset(&mut self.steps);
        }
    }

    /// Removes the [`FlashStep::FactoryReset`] step (`flash --no-factory-reset`).
    /// Only safe when the device is known to hold no stale image.
    pub fn skip_factory_reset(&mut self) {
        self.steps
            .retain(|s| !matches!(s, FlashStep::FactoryReset { .. }));
    }

    /// Whether the terminal restart is sent as the confirmed master reset with
    /// erase code 1 rather than a bare `A_Restart`. True for a System B plan that
    /// allocates a filled segment, the download shape ETS ends with a confirmed
    /// restart in the issue #117 captures; false for the KNX Virtual DA.tp and
    /// thelsing shapes, which end with the bare restart.
    pub fn uses_confirmed_restart(&self) -> bool {
        self.confirmed_restart
    }

    /// The human label of one of this plan's steps, as the dry-run trace and the
    /// progress line print it.
    pub fn step_label(&self, step: &FlashStep) -> String {
        match step {
            FlashStep::Restart if self.confirmed_restart => {
                "restart device (confirmed: A_Restart master reset, erase code 1)".to_string()
            }
            _ => step_label(step),
        }
    }

    /// Whether this is a System 7 (mask 0705/0701) plan.
    pub fn is_sys7(&self) -> bool {
        self.sys7.is_some()
    }

    /// The System 7 LSM realisation this plan will drive (property-based vs
    /// memory-mapped), or `None` for a System B plan. Property is the default
    /// (M2 Jung 0705 capture, `[system7-spec §5]`).
    pub fn sys7_lsm(&self) -> Option<bussard_mgmt::LsmRealisation> {
        self.sys7.as_ref().map(|s| s.profile.lsm)
    }

    /// The System 7 LSM access seam this plan will drive, or `None` for a System
    /// B plan.
    ///
    /// The pre-flight state probe ([`crate::preflight`]) reads the device's
    /// load-state machines through exactly this realisation, so what it reads is
    /// what the flash would overwrite.
    pub fn sys7_lsm_access(&self) -> Option<bussard_mgmt::LsmAccess> {
        self.sys7
            .as_ref()
            .map(|s| bussard_mgmt::lsm_access_from_profile(&s.profile))
    }

    /// The exact bytes a memory-write step streams for `segment_id` (the
    /// [`ImageRef::segment_id`] a step carries), as resolved at plan time.
    ///
    /// This is what the executor sends, so an offline dump of it (`bussard
    /// flash --dry-run --dump-images`) can be diffed against a capture of what
    /// ETS wrote to the same device.
    pub fn image_bytes(&self, segment_id: &str) -> Option<&[u8]> {
        self.images.get(segment_id).map(Vec::as_slice)
    }

    /// The System 7 per-octet write mask for `segment_id`, when the segment
    /// carries one (`0xFF` = written, anything else = device-owned, skipped).
    /// Always `None` for a System B plan.
    pub fn segment_mask(&self, segment_id: &str) -> Option<&[u8]> {
        self.sys7
            .as_ref()
            .and_then(|s| s.segment_masks.get(segment_id))
            .map(Vec::as_slice)
    }

    /// Total octets written to device memory across all memory-write steps.
    pub fn total_write_bytes(&self) -> usize {
        self.steps
            .iter()
            .map(|s| match s {
                FlashStep::WriteRelMem { image, .. } | FlashStep::WriteMem { image, .. } => {
                    image.len
                }
                FlashStep::Sys7AbsSegment {
                    image: Some(image), ..
                } => image.len,
                _ => 0,
            })
            .sum()
    }

    /// A rough estimate of the number of `A_Memory_Write` telegrams the flash
    /// sends (one per [`bussard_mgmt::apci::MAX_MEMORY_WRITE_LEN`] octets). Each
    /// write also does a read-back, so on-bus frames are ~2× this.
    pub fn estimated_write_frames(&self) -> usize {
        let chunk = usize::from(bussard_mgmt::apci::MAX_MEMORY_WRITE_LEN);
        self.steps
            .iter()
            .map(|s| match s {
                FlashStep::WriteRelMem { image, .. } | FlashStep::WriteMem { image, .. } => {
                    image.len.div_ceil(chunk)
                }
                FlashStep::Sys7AbsSegment {
                    image: Some(image), ..
                } => image.len.div_ceil(chunk),
                _ => 0,
            })
            .sum()
    }

    /// A conservative TP1 time estimate for the memory writes: each frame plus
    /// its read-back is roughly two ~20 ms TP1 telegrams, so ~40 ms per chunk.
    pub fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis((self.estimated_write_frames() as u64) * 40)
    }
}

/// Runtime options for [`flash`] that do not belong in the offline [`FlashPlan`].
///
/// Currently just the authorization key. The download runs over a single L4
/// connection like ETS; real gateways hold one stable connection for the whole
/// download and real devices report conformant load states, so no simulator
/// escape hatches are needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlashOptions {
    /// The access key presented with `A_Authorize_Request` on the management
    /// connect (issue #52 finding #1).
    ///
    /// ETS authorizes a management session before any configuration access;
    /// bussard does the same, so an unauthorized connection-oriented session is
    /// not why a keyed device drops us. `None` means present the
    /// [`FREE_ACCESS_KEY`](bussard_mgmt::apci::FREE_ACCESS_KEY) (the unkeyed /
    /// full-access default — what the capture used); `Some(k)` presents the
    /// project BCU key (the `--bcu-key <hex>` flag) for a keyed device. The policy
    /// is tolerate-absence (a device that does not implement authorize continues)
    /// and fail-on-denied (a non-zero granted level is a hard
    /// [`MgmtError`](bussard_mgmt::MgmtError)`::AccessDenied`).
    pub bcu_key: Option<u32>,

    /// Whether to verify the flash *after* the terminal restart rather than
    /// before it.
    ///
    /// A device only truly holds a flash if the load survives the reboot the
    /// terminal `LdCtrlRestart` triggers. KNX Virtual reports a transient
    /// `Loaded` while the device is still up and then reverts the application
    /// object to `Unloaded` after the restart when the written image is
    /// content-incomplete — so verifying before the restart reports a
    /// non-persisting flash as a success (a false positive).
    ///
    /// When `true` (the real `bussard flash`), the terminal restart is fired,
    /// the reboot is waited out, the connection is re-opened and re-authorized,
    /// and the load state is re-read on the fresh connection — success is
    /// reported only if the object is *genuinely* `Loaded` afterwards. It
    /// requires a session that [`can_reconnect`](Session::can_reconnect); a
    /// session built from a single already-open connection ignores it and
    /// verifies before the restart regardless.
    ///
    /// When `false` (the default, used by the mock-device tests whose devices
    /// do not reboot-and-return), the load state is read over the still-open
    /// connection before the restart, as before.
    pub verify_after_restart: bool,

    /// Skip re-downloading an object whose resident image already matches
    /// (issue #73 item 2 — the MCB-CRC re-download skip).
    ///
    /// ETS's group-B re-download captures streamed ZERO body bytes: before
    /// touching an object, ETS read its `PID_MCB_TABLE` (PID 27), saw the
    /// resident image's size and CRC already matched the image it was about to
    /// stream, and skipped the object's whole re-load (an app-unload flips load
    /// state without erasing flash, so the resident image is intact). When this
    /// is `true`, bussard does the same: a pre-pass reads each to-be-written
    /// object's resident MCB and, on a size+CRC match, skips that object's
    /// `Unload`/`StartLoading`/`AllocateSegment`/`WriteRelMem`/`LoadCompleted`
    /// steps — leaving the intact resident load untouched — while still running
    /// its `LoadImageProp` MCB re-verify.
    ///
    /// It NEVER skips a genuinely-needed write: a fresh/blank device (no MCB
    /// entry), any object whose resident size or CRC differs, and any object that
    /// does not currently report `Loaded` full-streams exactly as before. When `false` (the conservative default, and every
    /// path validated byte-for-byte against DA.tp, which was a fresh flash whose
    /// blank device never matches) every object is always full-streamed.
    pub skip_matching_mcb: bool,
}

/// A progress event emitted as [`flash`] executes, for the CLI to render.
#[derive(Debug, Clone)]
pub enum Progress {
    /// A step is starting (1-based index, total count).
    Step {
        /// The 1-based step index.
        index: usize,
        /// The total number of steps.
        total: usize,
        /// A human label for the step.
        label: String,
    },
    /// Bytes written so far within the current memory-write step.
    Bytes {
        /// Octets written of the current step.
        written: usize,
        /// Total octets in the current step.
        total: usize,
    },
}

/// The result of a completed flash: the final load state and whether the
/// spot-check read-back of written segments matched.
#[derive(Debug, Clone)]
pub struct FlashOutcome {
    /// The application-program object's final load state (must be `Loaded`).
    pub load_state: LoadState,
    /// The final load state of every object the flash programmed (each object
    /// that received a `LoadCompleted`, plus the application object). Every entry
    /// must be `Loaded` for the flash to have verified — this catches a
    /// multi-object flash where a table object silently failed to load.
    pub object_states: Vec<(u8, LoadState)>,
    /// Whether the sampled read-backs of written memory matched what was written.
    pub spot_checks_match: bool,
}

impl FlashOutcome {
    /// The flash verified: every programmed object reached `Loaded` and every
    /// spot check matched.
    pub fn ok(&self) -> bool {
        self.object_states
            .iter()
            .all(|(_, state)| *state == LoadState::Loaded)
            && self.load_state == LoadState::Loaded
            && self.spot_checks_match
    }
}

/// Opens the [`Layer4Connection`] to the flash target.
///
/// A [`Session`] uses this to establish the single L4 connection the whole
/// download runs over — like ETS, one stable connection for the entire flash. The
/// CLI's implementation leases the bus and builds a `LeaseChannel`; tests script
/// one directly. Kept as an async trait (rather than a bare closure) so the
/// returned connection's channel type `Ch` is named and the future is nameable
/// without boxing.
#[allow(async_fn_in_trait)]
pub trait Connector {
    /// The channel the produced connection drives.
    type Channel: L4Channel;

    /// Opens the connection to the flash target.
    async fn connect(&mut self) -> Result<Layer4Connection<Self::Channel>, WriteError>;
}

/// The [`Connector`] type of a [`Session`] built from an already-open connection
/// via [`Session::from_connection`].
///
/// It only names the channel type `Ch` so `Session<SingleConnector<Ch>>` is a
/// concrete type; it is never actually connected through (the session already
/// holds its connection), so [`connect`](Connector::connect) is unreachable.
pub struct SingleConnector<Ch: L4Channel>(std::marker::PhantomData<Ch>);

impl<Ch: L4Channel> Connector for SingleConnector<Ch> {
    type Channel = Ch;

    async fn connect(&mut self) -> Result<Layer4Connection<Ch>, WriteError> {
        // Unreachable: a session built from an already-open connection never
        // opens another. Present only to satisfy the `Connector` bound.
        Err(WriteError::Mgmt(MgmtError::Transport(
            bussard_transport::TransportError::Closed,
        )))
    }
}

impl<Ch: L4Channel> Session<SingleConnector<Ch>> {
    /// Wraps one already-open [`Layer4Connection`] as a session.
    ///
    /// The returned session flashes over exactly this connection. This is the
    /// drop-in for callers and tests that open the connection themselves.
    pub fn from_connection(l4: Layer4Connection<Ch>) -> Session<SingleConnector<Ch>> {
        Session {
            l4: Some(l4),
            connector: None,
            bcu_key: None,
            authorize_outcomes: BTreeMap::new(),
            facts: DeviceFacts::default(),
            max_apdu: None,
        }
    }
}

/// What the read-only pre-flight already learned about the device, carried into
/// the write phase so the flash does not pay for discovering it a second time.
///
/// `bussard flash` runs a read-only probe before it shows the plan (issue #79):
/// it walks `PID_OBJECT_TYPE` over every interface object, presents
/// `A_Authorize_Request`, and reads each object's load state. All three are
/// device-stable facts, but the write phase used to rediscover them on its own
/// connection: another full object-table walk, another authorize (a device that
/// does not implement authorize burns a full `RESPONSE_TIMEOUT` answering
/// nothing), and another `PID_MAX_APDU_LENGTH` read.
///
/// Handing the pre-flight's findings to [`Session::open_with_facts`] removes
/// that duplication. Every field is optional/empty-tolerant: an empty
/// [`DeviceFacts`] (or [`Session::open_with_key`], which supplies none) restores
/// the rediscover-everything behaviour byte-for-byte, which is what the mock and
/// oracle tests pin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceFacts {
    /// The interface-object table (`index → PID_OBJECT_TYPE`) the pre-flight
    /// walked, in index order. Empty when it could not be read, in which case
    /// the flash walks it itself.
    pub object_table: Vec<(u8, u16)>,
    /// The authorize outcome the pre-flight observed on its own connection.
    ///
    /// Only an [`Unsupported`](bussard_mgmt::AuthorizeOutcome::Unsupported)
    /// outcome changes what the write phase does — it stops re-presenting a key
    /// to a device that answers nothing, saving a full `RESPONSE_TIMEOUT` per
    /// connection window. A `Granted` is per-connection state that a fresh
    /// `T_Connect` clears, so it is recorded but still re-presented.
    pub authorize: Option<bussard_mgmt::AuthorizeOutcome>,
    /// The device's `PID_MAX_APDU_LENGTH`, when the pre-flight negotiated it.
    /// Device-stable, so the session seeds it instead of spending an exchange
    /// re-reading it.
    pub max_apdu: Option<u16>,
}

impl DeviceFacts {
    /// The application-program object index this table names, if any.
    ///
    /// `None` when the pre-flight read no table, or read one that carries no
    /// interface-object of type 3 — either way the flash falls back to its own
    /// discovery walk rather than guessing.
    pub fn application_object(&self) -> Option<u8> {
        self.object_table
            .iter()
            .find(|(_, ot)| *ot == OT_APPLICATION_PROGRAM)
            .map(|(index, _)| *index)
    }
}

/// An L4 session to the flash target: it owns the open [`Layer4Connection`] the
/// whole download runs over.
///
/// Like ETS, the download runs over a single stable connection for its entire
/// duration; the engine borrows `session.l4()` for each step. `apply`/`reconstruct`
/// keep borrowing a plain `Layer4Connection` and are untouched.
///
/// The session also retains the [`Connector`] it was opened from and the
/// authorization key, so it can re-establish the connection **once** after a
/// spec-required device restart (an `LdCtrlMasterReset`): the device reboots and
/// drops the L4 link, and the procedure must continue on a fresh, re-authorized
/// connection. This is the single reconnect-after-restart the KNX spec mandates
/// for a master reset — not general connection cycling.
///
/// The type parameter `C` names the [`Connector`] the session was opened from, so
/// the connection's channel type stays nameable without boxing.
pub struct Session<C: Connector> {
    /// The open connection the download runs over.
    l4: Option<Layer4Connection<C::Channel>>,
    /// The connector the session was opened from, retained so a master-reset
    /// step can re-open the connection after the device reboots. `None` for a
    /// session built from an already-open connection ([`Session::from_connection`]),
    /// which cannot reconnect on its own.
    connector: Option<C>,
    /// The authorization key to re-present on a reconnect (the free-access key
    /// when `None`), so the resumed connection is authorized exactly as the
    /// original was.
    bcu_key: Option<u32>,
    /// The first successful [`AuthorizeOutcome`] observed per target device
    /// (keyed by its raw individual address), cached for the life of the session.
    ///
    /// Only an [`Unsupported`](bussard_mgmt::AuthorizeOutcome::Unsupported)
    /// outcome causes a later re-authorize to be *skipped*: such a device does
    /// not implement authorize and answers the request with silence — a full
    /// `RESPONSE_TIMEOUT` burned on every reconnect/cycle window (issue #58).
    /// Once we know a target is unsupported we stop paying that wait.
    ///
    /// A [`Granted`](bussard_mgmt::AuthorizeOutcome::Granted) outcome is cached
    /// for observability but does NOT skip re-authorize: authorization is
    /// per-connection state that a `T_Disconnect`/reboot clears, so a device with
    /// a real write gate must re-present the key on every fresh connection. A
    /// `Denied` never reaches the cache — it fails the open before insertion.
    authorize_outcomes: BTreeMap<u16, bussard_mgmt::AuthorizeOutcome>,
    /// What the CLI's read-only pre-flight already learned about this device
    /// ([`DeviceFacts`]), so the flash does not rediscover it. Empty for a
    /// session opened without facts (the library default and every mock test),
    /// which keeps the rediscover-everything wire sequence.
    facts: DeviceFacts,
    /// The device's `PID_MAX_APDU_LENGTH`, negotiated once on the first connection
    /// and re-seeded (not re-read) onto every later window's connection.
    ///
    /// The value is device-stable, so re-reading it each window would only burn a
    /// numbered exchange against the tight per-connection budget and shift where a
    /// mid-step drop lands (issue #58). Caching it at the session level keeps every
    /// window's exchange sequence identical to an un-negotiated flash after the
    /// first, while still scaling chunks to the device.
    max_apdu: Option<u16>,
}

impl<C: Connector> Session<C> {
    /// Opens the connection and wraps it in a session, authorizing it with the
    /// free-access key.
    ///
    /// Equivalent to [`open_with_key`](Session::open_with_key) with `None` — the
    /// connection presents [`FREE_ACCESS_KEY`](bussard_mgmt::apci::FREE_ACCESS_KEY)
    /// right after connect (issue #52 finding #1). A device that does not implement
    /// authorize is tolerated; a non-zero granted level fails with
    /// `MgmtError::AccessDenied`.
    pub async fn open(connector: C) -> Result<Session<C>, WriteError> {
        Session::open_with_key(connector, None).await
    }

    /// Opens the connection and authorizes it with `bcu_key` (or the free-access
    /// key when `None`).
    ///
    /// Equivalent to [`open_with_facts`](Session::open_with_facts) with an empty
    /// [`DeviceFacts`]: the session discovers everything itself, which is the
    /// standalone-library behaviour the mock and oracle wire traces pin.
    pub async fn open_with_key(
        connector: C,
        bcu_key: Option<u32>,
    ) -> Result<Session<C>, WriteError> {
        Session::open_with_facts(connector, bcu_key, DeviceFacts::default()).await
    }

    /// Opens the connection with what a read-only pre-flight already learned
    /// about the device ([`DeviceFacts`]).
    ///
    /// Two of the three facts change what this open costs on the wire:
    ///
    /// * an [`Unsupported`](bussard_mgmt::AuthorizeOutcome::Unsupported)
    ///   authorize outcome seeds the per-target cache, so no key is presented to
    ///   a device that answers nothing — saving one `RESPONSE_TIMEOUT` here and
    ///   one on every later reconnect/cycle;
    /// * a known `PID_MAX_APDU_LENGTH` is seeded instead of re-read, saving a
    ///   numbered exchange against the tight per-connection budget.
    ///
    /// The object table is not used here; it is consumed by [`flash`] in place of
    /// its own discovery walk.
    pub async fn open_with_facts(
        mut connector: C,
        bcu_key: Option<u32>,
        facts: DeviceFacts,
    ) -> Result<Session<C>, WriteError> {
        let mut l4 = connector.connect().await?;
        let mut authorize_outcomes = BTreeMap::new();
        // Seed the pre-flight's verdict BEFORE authorizing: an "this device does
        // not implement authorize" finding is what makes `authorize` skip the
        // request entirely. A `Granted`/`Denied` verdict is per-connection state
        // and is deliberately not seeded — this fresh connection must earn it.
        if let Some(outcome @ bussard_mgmt::AuthorizeOutcome::Unsupported { .. }) = &facts.authorize
        {
            authorize_outcomes.insert(l4.target().raw(), outcome.clone());
        }
        Self::authorize(&mut l4, bcu_key, &mut authorize_outcomes).await?;
        // Read PID_MAX_APDU_LENGTH once so memory/property chunks scale to the
        // device (issue #58). Best-effort: a failure leaves the conservative
        // standard-frame caps and never aborts the open. Cached at the session
        // level and re-seeded (not re-read) on later windows so it costs exactly
        // one exchange for the whole flash — or none, when the pre-flight already
        // negotiated it.
        let max_apdu = match facts.max_apdu {
            Some(known) => {
                l4.set_max_apdu(Some(known));
                Some(known)
            }
            None => l4.negotiate_max_apdu().await.ok().flatten(),
        };
        Ok(Session {
            l4: Some(l4),
            connector: Some(connector),
            bcu_key,
            authorize_outcomes,
            facts,
            max_apdu,
        })
    }

    /// Presents the free-access-or-`bcu_key` authorization on the connection,
    /// applying the tolerate-absence / fail-on-denied policy, consulting and
    /// populating the per-target [`authorize_outcomes`](Session::authorize_outcomes)
    /// cache.
    ///
    /// If a previous window on this target already found the device does not
    /// implement authorize ([`Unsupported`](bussard_mgmt::AuthorizeOutcome::Unsupported)),
    /// the request is skipped entirely — it would only burn another
    /// `RESPONSE_TIMEOUT` waiting for an answer the device never sends (issue
    /// #58). Otherwise the real authorize is presented (a `Granted` gate is
    /// per-connection and must be re-opened on every fresh connection), and the
    /// outcome recorded for the next window's decision.
    async fn authorize(
        l4: &mut Layer4Connection<C::Channel>,
        bcu_key: Option<u32>,
        cache: &mut BTreeMap<u16, bussard_mgmt::AuthorizeOutcome>,
    ) -> Result<(), WriteError> {
        let target = l4.target().raw();
        if let Some(bussard_mgmt::AuthorizeOutcome::Unsupported { .. }) = cache.get(&target) {
            // This device does not implement authorize (seen in an earlier
            // window): re-presenting the key only stalls a full RESPONSE_TIMEOUT
            // on a device that will not answer. Skip it (issue #58).
            tracing::debug!(
                target = %l4.target(),
                "device previously found not to implement authorize; skipping re-authorize"
            );
            return Ok(());
        }
        let key = bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY);
        let outcome = l4.authorize_or_fail(key).await.map_err(WriteError::Mgmt)?;
        cache.insert(target, outcome);
        Ok(())
    }

    /// The open connection, for a step to drive.
    pub fn l4(&mut self) -> &mut Layer4Connection<C::Channel> {
        self.l4
            .as_mut()
            .expect("session always holds its open connection")
    }

    /// Whether this session can re-open its connection after a device restart.
    ///
    /// True when the session was opened from a [`Connector`] it can call again
    /// ([`Session::open`]/[`open_with_key`](Session::open_with_key)); false when it
    /// wraps a single already-open connection ([`Session::from_connection`]), which
    /// has no way to reconnect. The terminal-restart verify uses this to decide
    /// whether to re-read the load state *after* the reboot (a real device) or
    /// *before* it (a mock with no reconnect).
    pub fn can_reconnect(&self) -> bool {
        self.connector.is_some()
    }

    /// The pre-flight's interface-object table and the application-object index
    /// it names, when both are known.
    ///
    /// `None` when the session was opened without [`DeviceFacts`], or with facts
    /// whose table is empty or carries no application-program object — in which
    /// case the caller walks the table itself.
    fn known_object_table(&self) -> Option<(u8, Vec<(u8, u16)>)> {
        let app_obj = self.facts.application_object()?;
        Some((app_obj, self.facts.object_table.clone()))
    }

    /// Re-establishes the L4 connection after a device restart, re-authorizing it.
    ///
    /// Used by the master-reset step and the terminal-restart verify: the device
    /// rebooted and dropped the
    /// connection, so the old `Layer4Connection` is dead. This drops it, opens a
    /// fresh connection via the retained [`Connector`], and re-presents the same
    /// authorization the original connection used, so the remaining procedure
    /// steps continue transparently. A session built from an already-open
    /// connection ([`Session::from_connection`]) has no connector to reconnect
    /// with and fails with [`MgmtError::Transport`]`(Closed)`.
    async fn reconnect(&mut self) -> Result<(), WriteError> {
        // Drop the dead connection outright (do NOT try to T_Disconnect — the
        // device is mid-reboot and will not answer).
        self.l4 = None;
        let connector =
            self.connector
                .as_mut()
                .ok_or(WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                    bussard_transport::TransportError::Closed,
                )))?;
        let mut l4 = connector.connect().await?;
        Self::authorize(&mut l4, self.bcu_key, &mut self.authorize_outcomes).await?;
        // Re-seed the device-stable max APDU onto the fresh connection without a
        // round-trip, so scaling persists across the cycle without spending an
        // exchange against the tight per-connection budget (issue #58).
        l4.set_max_apdu(self.max_apdu);
        self.l4 = Some(l4);
        Ok(())
    }

    /// Waits out a device reboot with a **bounded poll**, then re-establishes the
    /// authorized connection.
    ///
    /// Used after a master-reset `A_Restart` and after the terminal restart. The
    /// device is unreachable while it reboots, but how long that takes varies by
    /// device (~6.5 s on KNX Virtual, less on others), so this does not burn a
    /// fixed [`MASTER_RESET_REBOOT_WAIT`]:
    ///
    /// 1. stay quiet for [`REBOOT_PROBE_MIN_WAIT`] (capped by the overall bound)
    ///    so a device that is still *shutting down* is not mistaken for one that
    ///    has come back;
    /// 2. then, every [`REBOOT_PROBE_INTERVAL`], run a cheap liveness probe — a
    ///    throwaway `T_Connect` + `A_DeviceDescriptor_Read` + `T_Disconnect` on a
    ///    tight [`REBOOT_PROBE_TIMEOUTS`] budget — until it answers or the bound
    ///    from [`reboot_wait_bound`] elapses;
    /// 3. either way, finish with the ordinary [`reconnect`](Session::reconnect),
    ///    so the session connection is established exactly as before and a device
    ///    that never came back surfaces that reconnect's error unchanged.
    ///
    /// The probe deliberately runs on its **own** connection rather than on the
    /// session's: it must not touch the session's authorize cache (a still-booting
    /// device answers nothing, which an authorize would record as "does not
    /// implement authorize" and never retry) and it must not shift the session
    /// connection's numbered-exchange sequence.
    async fn reconnect_after_reboot(&mut self) -> Result<(), WriteError> {
        // Drop the dead connection up front: on the real path it holds the bus
        // lease, and the probes below need it. Dropping (rather than
        // disconnecting) is right — the peer is mid-reboot and will not answer.
        self.l4 = None;
        let bound = reboot_wait_bound();
        let started = tokio::time::Instant::now();
        tokio::time::sleep(REBOOT_PROBE_MIN_WAIT.min(bound)).await;
        // Only a session that owns a connector can probe; one built from a single
        // open connection falls straight through to `reconnect`'s error.
        if self.connector.is_some() {
            let deadline = started + bound;
            loop {
                if self.probe_rebooted_device().await {
                    break;
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    tracing::debug!(
                        "device did not answer a liveness probe within the reboot bound; \
                         reconnecting anyway"
                    );
                    break;
                }
                tokio::time::sleep(REBOOT_PROBE_INTERVAL.min(deadline - now)).await;
            }
        }
        self.reconnect().await
    }

    /// One post-reboot liveness probe: is the device answering management again?
    ///
    /// Opens a throwaway connection through the retained [`Connector`], asks for
    /// the device descriptor on the tight [`REBOOT_PROBE_TIMEOUTS`] budget, and
    /// tears it down again. Every failure path — no connector, a connector error,
    /// a silent device — is just `false`, so a failed probe leaves no state
    /// behind: the throwaway connection (and, on the real path, its bus lease) is
    /// released before returning, and the session still holds no connection of its
    /// own.
    async fn probe_rebooted_device(&mut self) -> bool {
        let Some(connector) = self.connector.as_mut() else {
            return false;
        };
        let mut l4 = match connector.connect().await {
            Ok(l4) => l4,
            Err(_) => return false,
        };
        l4.set_timeouts(REBOOT_PROBE_TIMEOUTS);
        let alive = bussard_mgmt::read_device_descriptor(&mut l4).await.is_ok();
        // Close the probe connection either way: a clean `T_Disconnect` when it
        // answered (so the device frees the slot immediately), a no-op when the
        // probe already tore it down.
        let _ = l4.disconnect().await;
        alive
    }

    /// Waits out a confirmed master reset (factory reset or confirmed restart)
    /// and re-establishes the authorized connection.
    ///
    /// The device answered the `A_Restart_Response` and is rebooting, so the old
    /// connection is dropped without a `T_Disconnect` (the ETS capture sends none
    /// after the factory reset either), then the session sleeps for `process_wait`
    /// (the device's own process time, already capped by
    /// [`bussard_mgmt::restart_process_wait`]) and finishes with the bounded
    /// liveness poll and reconnect of
    /// [`reconnect_after_reboot`](Session::reconnect_after_reboot).
    ///
    /// A session built from an already-open connection cannot reconnect and fails
    /// with [`MgmtError::Transport`]`(Closed)` before sleeping.
    async fn reconnect_after_master_reset(
        &mut self,
        process_wait: std::time::Duration,
    ) -> Result<(), WriteError> {
        if !self.can_reconnect() {
            return Err(WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            )));
        }
        self.l4 = None;
        tokio::time::sleep(process_wait).await;
        self.reconnect_after_reboot().await
    }

    /// Proactively cycles the L4 connection **between** flash steps to stay under
    /// the device's per-connection numbered-exchange budget.
    ///
    /// Real connection-oriented devices (KNX Virtual, and the couplers ETS drives)
    /// drop a long-held L4 connection after a bounded number of numbered exchanges
    /// — the DA.tp device drops at ~35. ETS avoids that by reconnecting the L4
    /// connection periodically within a download; bussard does the same here.
    ///
    /// Unlike [`reconnect`](Session::reconnect) (used after a device *restart*,
    /// where the peer is mid-reboot and the old connection is already dead), this
    /// is a **graceful** cycle of a live connection: it sends a `T_Disconnect` to
    /// close the old connection cleanly, opens a fresh one via the retained
    /// [`Connector`], and re-presents the same authorization. The objects' load
    /// states — and their allocated segments — are *persistent device state*, not
    /// connection state, so they survive the `T_Disconnect`/`T_Connect` and the
    /// procedure resumes seamlessly on the fresh, zero-exchange connection.
    ///
    /// A session built from an already-open connection
    /// ([`Session::from_connection`]) has no connector and returns
    /// [`MgmtError::Transport`]`(Closed)` — but such a session never calls this
    /// (the flash loop only cycles when [`can_reconnect`](Session::can_reconnect)).
    async fn cycle_l4(&mut self) -> Result<(), WriteError> {
        // Gracefully close the live connection with a T_Disconnect so the device
        // frees the old connection immediately (best-effort: a send error here is
        // irrelevant, the fresh T_Connect below re-establishes state regardless).
        if let Some(l4) = self.l4.take() {
            let _ = l4.disconnect().await;
        }
        let connector =
            self.connector
                .as_mut()
                .ok_or(WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                    bussard_transport::TransportError::Closed,
                )))?;
        let mut l4 = connector.connect().await?;
        Self::authorize(&mut l4, self.bcu_key, &mut self.authorize_outcomes).await?;
        // Re-seed the device-stable max APDU onto the fresh connection without a
        // round-trip, so scaling persists across the cycle without spending an
        // exchange against the tight per-connection budget (issue #58).
        l4.set_max_apdu(self.max_apdu);
        self.l4 = Some(l4);
        Ok(())
    }

    /// The current L4 connection's numbered-exchange count, or 0 when the session
    /// holds no connection.
    fn numbered_exchanges(&self) -> u32 {
        self.l4
            .as_ref()
            .map_or(0, Layer4Connection::numbered_exchanges)
    }

    /// Consumes the session and gracefully disconnects the open connection.
    pub async fn into_disconnect(self) -> bussard_mgmt::Result<()> {
        match self.l4 {
            Some(l4) => l4.disconnect().await,
            None => Ok(()),
        }
    }
}

/// Chooses the application program to flash from a product's candidates.
///
/// `wanted` is the optional `--application` id. With `None`, a single candidate
/// is used and several is [`PlanError::AmbiguousApplication`].
pub fn select_application<'a>(
    candidates: &[&'a ApplicationProgram],
    wanted: Option<&str>,
) -> std::result::Result<&'a ApplicationProgram, PlanError> {
    if let Some(id) = wanted {
        return candidates
            .iter()
            .find(|a| a.id == id)
            .copied()
            .ok_or_else(|| PlanError::NoApplication(id.to_string()));
    }
    match candidates {
        [only] => Ok(only),
        [] => Err(PlanError::NoApplication("<none>".to_string())),
        many => Err(PlanError::AmbiguousApplication {
            count: many.len(),
            ids: many
                .iter()
                .map(|a| a.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

/// Validates the application against the device and builds an executable
/// [`FlashPlan`], or returns the pre-flight [`PlanError`] that refuses it.
///
/// Steps:
/// 1. **System B gate** — refuse a non-07B0 device mask.
/// 2. **Mask match** — the app's declared mask must equal the device mask.
/// 3. **Procedure choice** — the merged/first procedure with the most ops.
/// 4. **Op validation** — every op must be a supported one; the segment each
///    memory write references must resolve to a code or parameter image.
///
/// `device` is the individual address (for error messages), `device_mask` the
/// descriptor read live, `overrides` the parameter values.
///
/// `template_ops` is the master-template `Load` procedure for the device mask
/// (from `knx_master.xml`), or `None` for a self-contained application whose own
/// procedures already carry the whole download (the conformant thelsing
/// ProductDefault shape). When present and the app is merged-style, the app's
/// `<LoadProcedure MergeId="N">` blocks are spliced into the template at its
/// `LdCtrlMerge` markers — the only way a merged app programs the table objects
/// (obj1/obj2/obj3), whose load-control ops live in the master template.
///
/// `table_images` supplies the memory image for each table object the template
/// writes, keyed by device object index: `1` = address table, `2` = association
/// table, `3` = group-object table (each including its big-endian count word).
/// A `WriteRelMem`/`RelSegment` naming one of these indices streams and sizes
/// itself from the supplied bytes instead of the app's code segments; an index
/// with no entry is left to the normal code/parameter resolution (obj4, the app
/// segment). Empty for a single-object flash.
pub fn plan_flash(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    template_ops: Option<&[LoadOp]>,
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> std::result::Result<FlashPlan, PlanError> {
    plan_flash_with_object_flags(
        app,
        device,
        device_mask,
        overrides,
        base_offsets,
        template_ops,
        table_images,
        &BTreeMap::new(),
    )
}

/// [`plan_flash`] with the project's flags of the linked com-objects, keyed by
/// object number.
///
/// Only a System 7 plan reads them (the CONFIG octet of a linked descriptor).
/// They take precedence over the flags decoded from the System B group-object
/// table image, which cannot carry object 0: that table is 1-based, word 0 is
/// its count (1.1.1, 2116REG: object 0 is linked with the project's T W R C,
/// ETS wrote `5f`, the ref's own T W C gave `57`).
#[allow(clippy::too_many_arguments)] // plan_flash's inputs plus one map.
pub fn plan_flash_with_object_flags(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    template_ops: Option<&[LoadOp]>,
    table_images: &BTreeMap<u32, Vec<u8>>,
    object_flags: &BTreeMap<u16, bussard_model::Flags>,
) -> std::result::Result<FlashPlan, PlanError> {
    // 1. Family gate. System B and System 7 (mask 0705/0701, issue #49) are the
    //    two supported families; every other mask refuses cleanly. System 7 is
    //    dispatched to its own lowering below (after the shared mask-match check).
    let profile = bussard_mgmt::MaskProfile::from_mask(device_mask);
    if !profile.capabilities().flash {
        return Err(PlanError::NotSystemB {
            device: device.to_string(),
            device_mask,
            system: bussard_mgmt::system_type(device_mask),
        });
    }

    // 2. Mask match: compare the app's declared mask (hex string) to the device.
    let app_mask = app
        .mask_version
        .clone()
        .ok_or_else(|| PlanError::MissingAppMask(app.id.clone()))?;
    let app_mask_num = u16::from_str_radix(app_mask.trim(), 16).ok();
    if app_mask_num != Some(device_mask) {
        return Err(PlanError::MaskMismatch {
            device: device.to_string(),
            device_mask,
            app_mask,
        });
    }

    // System 7 has its own memory-mapped, absolute-addressed lowering: the LSM
    // events, AbsSegment allocation + streaming, TaskSegment finalize, and the
    // obj0/PID78 preflight all differ from System B, so it is a separate path
    // rather than a branchy overload of the System B lowering below.
    if profile.is_system_7() {
        let mut tables = Sys7PlanTables::from_system_b(table_images);
        tables.linked_flags.extend(object_flags);
        return plan_flash_sys7(
            app,
            device_mask,
            overrides,
            base_offsets,
            profile,
            None,
            &tables,
        );
    }

    // 3. Assemble the op sequence to execute. A `MergedProcedure` app splits one
    //    logical download across several `<LoadProcedure MergeId=…>` blocks
    //    (e.g. Jung 23024: MergeId 2 allocates + seeds the MCB, 4 writes the
    //    segment, 7 runs the LoadImageProp integrity checks); those blocks are
    //    concatenated in MergeId order so the whole download lowers, not just the
    //    richest single block. A single-style app has one block, used as-is.
    //    Empty apps are refused.
    let (ops, spliced_from_template) = assemble_ops(app, template_ops);
    if ops.is_empty() {
        return Err(PlanError::NoProcedure(app.id.clone()));
    }

    // Resolve the parameter images once, up front (used by AppliesTo=par writes).
    // `overrides` is keyed by app-relative ParameterRef id (the #46 contract);
    // the caller re-keys the device file's `parameters:` block before calling.
    // No per-instance base offsets are supplied here (they live in the project,
    // not in the product data): a module-instance override therefore refuses at
    // pre-flight rather than misplacing a byte — see `compute_parameter_image`.
    let param_images = bussard_prod::compute_parameter_image(app, overrides, base_offsets)
        .map_err(|e| PlanError::UnresolvableImage {
            step: 0,
            reason: format!("computing the parameter image: {e}"),
        })?;

    // The 5-octet application-program-version (app-id / run-state) value ETS
    // writes to the app object's PID 13 on LoadCompleted, synthesized from the
    // app's manufacturer + number + version. `None` when the identity is
    // incomplete (no application number/version), in which case a placeholder
    // PID-13 write is left as-is. Computed once, applied in the WriteProp branch.
    let app_id_value: Option<[u8; 5]> = app_program_version_value(app);

    // 4. Validate + lower each op into a FlashStep.
    let mut steps = Vec::new();
    let mut images: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // Track the segment id most-recently allocated so a following WriteRelMem
    // resolves to it when its own AppliesTo does not pin one.
    let mut last_rel_segment: Option<String> = None;
    // Track the image most-recently streamed into device memory so a following
    // LoadImageProp with no matching per-object image checks the device's MCB CRC
    // against the very bytes we wrote.
    let mut last_written_image: Option<ImageRef> = None;
    // Track the image streamed into each object index, so a `LoadImageProp{obj}`
    // that targets a table object verifies that object's own MCB against the
    // bytes written to it — not the last object written. Real multi-object System
    // B procedures (the MDT actuators) write obj1/obj2/obj3 each with its own
    // segment and then check each object's MCB in turn.
    let mut written_image_by_object: std::collections::HashMap<u32, ImageRef> =
        std::collections::HashMap::new();

    // The objects worth loading are exactly the ones that receive a segment
    // (a `RelSegment` allocation). A master template also opens/completes
    // contentless objects — e.g. an unused "application program 2" at object
    // index 5 — which some devices (KNX Virtual) refuse to open (StartLoading
    // leaves them Unloaded). ETS only loads the objects it writes, so skip the
    // Load/LoadCompleted of any object with no allocation. The Unload still runs
    // (ETS unloads them too); a `None` index is kept rather than silently dropped.
    let loadable: std::collections::HashSet<u32> = ops
        .iter()
        .filter_map(|op| match op {
            LoadOp::RelSegment {
                lsm_idx: Some(idx), ..
            } => Some(*idx),
            _ => None,
        })
        .collect();
    let is_loadable = |idx: &Option<u32>| idx.is_none_or(|i| loadable.contains(&i));

    for (i, op) in ops.iter().enumerate() {
        let step_no = i + 1;
        match op {
            // Session boundaries: the engine holds one connection open across the
            // whole procedure, so these carry no per-op device action.
            LoadOp::Connect | LoadOp::Disconnect => {}

            LoadOp::Unload { lsm_idx } => steps.push(FlashStep::Unload { target: *lsm_idx }),
            LoadOp::Load { lsm_idx } if is_loadable(lsm_idx) => {
                steps.push(FlashStep::StartLoading { target: *lsm_idx })
            }
            LoadOp::Load { .. } => {}
            LoadOp::LoadCompleted { lsm_idx } if is_loadable(lsm_idx) => {
                steps.push(FlashStep::LoadCompleted { target: *lsm_idx })
            }
            LoadOp::LoadCompleted { .. } => {}
            LoadOp::Restart => steps.push(FlashStep::Restart),
            LoadOp::MasterReset {
                erase_code,
                channel_number,
            } => {
                // The EraseCode/ChannelNumber are single octets on the wire; a
                // value beyond a u8 is corrupt vendor input. Default the erase
                // code to 1 ("Confirmed Restart") and the channel to 0 (the whole
                // device) when the attribute is absent, and clamp to u8.
                steps.push(FlashStep::MasterReset {
                    erase_code: erase_code.unwrap_or(1).min(u32::from(u8::MAX)) as u8,
                    channel_number: channel_number.unwrap_or(0).min(u32::from(u8::MAX)) as u8,
                });
            }

            // A master-template merge marker that survived (no matching app
            // block): a no-op. After splicing this should not appear, but a bare
            // marker in an app procedure is tolerated rather than refused.
            LoadOp::Merge { .. } => {}

            // A spliced template allocates a standard table object (obj1/2/3) but
            // no table image was supplied: refuse rather than allocate a
            // placeholder-sized (or app-segment-sized) segment for it.
            LoadOp::RelSegment {
                lsm_idx: Some(idx), ..
            } if spliced_from_template
                && !table_images.contains_key(idx)
                && table_object_name(*idx).is_some() =>
            {
                return Err(PlanError::MissingTableImage {
                    step: step_no,
                    obj_idx: *idx,
                    table: table_object_name(*idx).unwrap_or("table"),
                });
            }

            // A relative-segment allocation for a table object (obj1/obj2/obj3):
            // its size is the supplied table image's length, not a code segment.
            // The template carries a placeholder `Size` (2 or the 1 MiB
            // sentinel); the real size is the computed table body.
            LoadOp::RelSegment {
                lsm_idx: Some(idx), ..
            } if table_images.contains_key(idx) => {
                let size = table_images[idx].len() as u32;
                if u64::from(size) > MAX_WRITE_SPAN {
                    return Err(PlanError::AddressOutOfRange {
                        step: step_no,
                        size: u64::from(size),
                        end: u64::from(size),
                        detail: format!("table object {idx} allocation size {size}"),
                    });
                }
                // Table objects always allocate no-fill (`Fill=0` in every
                // observed procedure, including the products that set `Fill=1`
                // on the code segment). Preserve that unconditionally so the
                // fill flag never leaks onto a table allocation.
                steps.push(FlashStep::AllocateSegment {
                    size,
                    target: Some(*idx),
                    fill: None,
                });
            }

            LoadOp::RelSegment {
                size,
                applies_to,
                lsm_idx,
                fill,
                ..
            } => {
                // Bind this allocation to the segment whose code image we will
                // stream. The op does not name the segment id directly; we pair
                // it with the application's relative segments in document-ish
                // order using the applies_to hint and remaining unallocated
                // segments.
                let seg = resolve_rel_segment(app, *lsm_idx, applies_to.as_deref(), &images);
                let size = size
                    .or_else(|| seg.as_ref().and_then(|(_, s)| *s))
                    .unwrap_or(0);
                // The requested segment size drives the device allocation; an
                // absurd vendor `Size` is corrupt input, refused before it can
                // become a huge allocation request.
                if u64::from(size) > MAX_WRITE_SPAN {
                    return Err(PlanError::AddressOutOfRange {
                        step: step_no,
                        size: u64::from(size),
                        end: u64::from(size),
                        detail: format!("relative segment allocation size {size}"),
                    });
                }
                // The segment the PREVIOUS allocation bound, before this op
                // updates the binding — the dedupe below must compare against
                // this, not against its own freshly-written value.
                let prev_rel_segment = last_rel_segment.clone();
                if let Some((seg_id, _)) = &seg {
                    last_rel_segment = Some(seg_id.clone());
                    // Record the code image so total-byte accounting is correct.
                    if let Some(data) = app.code_segments.get(seg_id).and_then(|s| s.data.clone()) {
                        images.entry(seg_id.clone()).or_insert(data);
                    }
                }

                // Dedupe an identical consecutive allocation of the SAME segment.
                //
                // Evidence (MDT A-0007 / AKK-0216.03, corpus `M-0083_A-0007`): the
                // vendor's `MergeId=2` block carries TWO `<LdCtrlRelSegment>` ops
                // for one segment — `AppliesTo="full" LsmIdx=4 Size=1936` and
                // `AppliesTo="par" LsmIdx=4 Size=1936` — differing only in
                // AppliesTo/Mode. Both target the same LSM index and the same
                // size, i.e. the same relative segment allocated twice; the single
                // following `<LdCtrlWriteRelMem AppliesTo="full,par" Size=1936>`
                // then writes the whole segment once.
                //
                // Per the KNX load-state machine (KNX Spec 3/5/2 Management
                // Procedures, `LdCtrlRelSegment`), a relative-segment allocation
                // frees any prior backing store and re-allocates `size` octets, so a
                // second relative allocation on an already-`Loading` object is
                // *legal* and lands in the same state — but it is redundant work,
                // and re-issuing the
                // 10-octet AdditionalLoadControls against an object that has just
                // been (re)allocated is exactly the step KNX Virtual was observed
                // to choke on. Emitting one allocation of the identical size
                // reaches the same device state the vendor procedure intends (one
                // 1936-octet segment for the combined full,par write), so we drop
                // the immediately-repeated identical allocation. A *different* size
                // or a *newly resolved* segment is never deduped.
                // Duplicate = the immediately preceding step allocated the same
                // size AND this op resolves to the same segment (or resolves no
                // new segment at all). The DALI-gateway corpus app resolves its
                // segment on BOTH ops of the repeated pair, so resolution alone
                // must not defeat the dedupe; only a genuinely NEW segment does.
                // "Same segment" is decided by `resolve_rel_segment`, which binds
                // an op to the segment on its own `LsmIdx` — an app that declares
                // segments on several LSMs (the ABB/BJE shape of issue #113) would
                // otherwise bind the restated pair to two different segments and
                // slip past this check.
                let same_segment = match &seg {
                    None => true,
                    Some((seg_id, _)) => prev_rel_segment.as_deref() == Some(seg_id.as_str()),
                };
                let is_duplicate = same_segment
                    && matches!(steps.last(), Some(FlashStep::AllocateSegment { size: prev, .. }) if *prev == size);
                if !is_duplicate {
                    // Thread the source procedure's fill (`Mode`/`Fill`) through:
                    // `None` (the DA.tp default) keeps the historical no-fill
                    // allocation byte-identical; `Some(b)` requests the device
                    // pre-fill the segment (the code-segment behaviour on
                    // products like Jung LED A-3030).
                    steps.push(FlashStep::AllocateSegment {
                        size,
                        target: *lsm_idx,
                        fill: *fill,
                    });
                }
            }

            // A spliced template writes a standard table object (obj1/2/3) but no
            // table image was supplied: refuse rather than stream the app segment
            // (or nothing) to a table object.
            LoadOp::WriteRelMem {
                obj_idx: Some(idx), ..
            } if spliced_from_template
                && !table_images.contains_key(idx)
                && table_object_name(*idx).is_some() =>
            {
                return Err(PlanError::MissingTableImage {
                    step: step_no,
                    obj_idx: *idx,
                    table: table_object_name(*idx).unwrap_or("table"),
                });
            }

            // A relative-memory write into a table object (obj1/obj2/obj3):
            // stream the supplied table image, not an app code/parameter image.
            // The template carries a placeholder `Size` (the 1 MiB sentinel);
            // the real length is the table body.
            LoadOp::WriteRelMem {
                offset,
                obj_idx: Some(idx),
                ..
            } if table_images.contains_key(idx) => {
                let bytes = table_images[idx].clone();
                let len = bytes.len();
                let offset = offset.unwrap_or(0);
                let end = u64::from(offset).saturating_add(len as u64);
                if len as u64 > MAX_WRITE_SPAN
                    || u64::from(offset) > MAX_WRITE_SPAN
                    || end > MAX_MEMORY_END
                {
                    return Err(PlanError::AddressOutOfRange {
                        step: step_no,
                        size: len as u64,
                        end,
                        detail: format!("table object {idx} relative offset {offset}"),
                    });
                }
                // A synthetic, unique segment id so `FlashPlan.images` keys stay
                // distinct from the app's real code segments.
                let segment_id = format!("obj-table-{idx}");
                images.insert(segment_id.clone(), bytes);
                let image = ImageRef {
                    segment_id,
                    kind: ImageKind::Table,
                    len,
                };
                last_written_image = Some(image.clone());
                written_image_by_object.insert(*idx, image.clone());
                steps.push(FlashStep::WriteRelMem {
                    offset,
                    image,
                    target: Some(*idx),
                });
            }

            LoadOp::WriteRelMem {
                offset,
                applies_to,
                obj_idx,
                ..
            } => {
                let (segment_id, kind, bytes) = resolve_write_image(
                    app,
                    applies_to.as_deref(),
                    last_rel_segment.as_deref(),
                    &param_images,
                )
                .map_err(|reason| PlanError::UnresolvableImage {
                    step: step_no,
                    reason,
                })?;
                let len = bytes.len();
                let offset = offset.unwrap_or(0);
                // The segment base is device-supplied at execute time (>= 0), so a
                // relative write already exceeds the 16-bit A_Memory space if
                // offset+len does. Refuse here rather than truncate later. Also
                // reject an absurd offset/len before any allocation.
                let end = u64::from(offset).saturating_add(len as u64);
                if len as u64 > MAX_WRITE_SPAN
                    || u64::from(offset) > MAX_WRITE_SPAN
                    || end > MAX_MEMORY_END
                {
                    return Err(PlanError::AddressOutOfRange {
                        step: step_no,
                        size: len as u64,
                        end,
                        detail: format!(
                            "relative offset {offset} (segment base added at flash time)"
                        ),
                    });
                }
                images.insert(segment_id.clone(), bytes);
                let image = ImageRef {
                    segment_id,
                    kind,
                    len,
                };
                last_written_image = Some(image.clone());
                if let Some(oi) = obj_idx {
                    written_image_by_object.insert(*oi, image.clone());
                }
                steps.push(FlashStep::WriteRelMem {
                    offset,
                    image,
                    target: *obj_idx,
                });
            }

            LoadOp::WriteMem { address, .. } => {
                // Absolute write: the bytes are an absolute segment's data at the
                // named address.
                let (segment_id, bytes) = resolve_abs_image(app, *address).map_err(|reason| {
                    PlanError::UnresolvableImage {
                        step: step_no,
                        reason,
                    }
                })?;
                let len = bytes.len();
                let address = address.unwrap_or(0);
                // Absolute write: the full [address, address+len) range must fit
                // the 16-bit A_Memory space, checked before any allocation.
                let end = u64::from(address).saturating_add(len as u64);
                if len as u64 > MAX_WRITE_SPAN || end > MAX_MEMORY_END {
                    return Err(PlanError::AddressOutOfRange {
                        step: step_no,
                        size: len as u64,
                        end,
                        detail: format!("absolute address {address:#06X}"),
                    });
                }
                images.insert(segment_id.clone(), bytes);
                let image = ImageRef {
                    segment_id,
                    kind: ImageKind::Code,
                    len,
                };
                last_written_image = Some(image.clone());
                steps.push(FlashStep::WriteMem { address, image });
            }

            LoadOp::WriteProp {
                obj_idx,
                obj_type,
                prop_id,
                inline_data,
                start_element,
            } => {
                let obj_type = obj_type.unwrap_or(0);
                let start_element = start_element
                    .and_then(|e| u16::try_from(e).ok())
                    .unwrap_or(1)
                    .max(1);
                let prop_id = prop_id.unwrap_or(0);
                // The property write targets an object index. When the op names
                // one directly (`ObjIdx`) use it; otherwise it is object 0 (the
                // device object, as the observed vendor procedures write). The
                // A_PropertyValue_Write primitive addresses by a u8 object index
                // and u8 PID.
                let obj_idx = obj_idx.unwrap_or(0);
                // The master template carries a placeholder
                // `LdCtrlWriteProp ObjIdx=4 PropId=13 InlineData="0000000000"`
                // for the application object's PID_PROGRAM_VERSION (the app-id /
                // run-state). ETS replaces the zeros with the real 5-octet app id
                // (manufacturer + application number + version); a device left
                // with zeros does not record which program it runs. Substitute the
                // synthesized value here (see `app_id_value`) so the flash writes
                // the same bytes ETS does. Only the all-zero placeholder of the
                // right width is substituted — a template that already carries a
                // concrete value is written verbatim.
                let inline_data =
                    maybe_substitute_app_id(prop_id, inline_data.as_deref(), app_id_value.as_ref());

                match &inline_data {
                    Some(value) if !value.is_empty() => {
                        // A value-carrying WriteProp must be executable to keep the
                        // "only a fully-executable FlashPlan reaches flash" invariant.
                        // Refuse a shape the write primitive cannot address rather
                        // than dropping the value at execute time.
                        if obj_idx > u32::from(u8::MAX) {
                            return Err(PlanError::UnsupportedWriteProp {
                                step: step_no,
                                reason: format!(
                                    "object index {obj_idx} exceeds the 8-bit object-index space \
                                     the property-write primitive addresses"
                                ),
                            });
                        }
                        if prop_id > u32::from(u8::MAX) {
                            return Err(PlanError::UnsupportedWriteProp {
                                step: step_no,
                                reason: format!(
                                    "property id {prop_id} exceeds the 8-bit PID space the \
                                     property-write primitive addresses"
                                ),
                            });
                        }
                        steps.push(FlashStep::WriteProp {
                            obj_idx,
                            obj_type,
                            prop_id,
                            value: value.clone(),
                            start_element,
                        });
                    }
                    _ => {
                        // A bare LdCtrlWriteProp carries no value: the device seeds
                        // the standard interface-object properties itself on
                        // LoadCompleted, so there is genuinely nothing to write. It
                        // is intentionally NOT lowered to a step, so it can never be
                        // rendered in the plan/trace as an executed write.
                    }
                }
            }

            LoadOp::CompareProp {
                obj_idx,
                prop_id,
                inline_data,
                mask,
                range,
                ..
            } => {
                // A property-verify precondition. The expected bytes come from the
                // op's own `InlineData` (resolved at parse time), so this lowers
                // with no device access — a fully-executable read-and-compare.
                // A `Range`-only op carries no literal bytes; keep it as a
                // no-expectation confirm so the whole procedure still lowers
                // rather than refusing (its numeric-range semantics are not
                // needed to complete the download).
                let _ = range;
                steps.push(FlashStep::CompareProp {
                    obj_idx: obj_idx.unwrap_or(0),
                    prop_id: prop_id.unwrap_or(0),
                    expected: inline_data.clone(),
                    mask: mask.clone(),
                });
            }

            LoadOp::CompareRelMem {
                obj_idx,
                offset,
                size,
                inline_data,
                mask,
                invert,
            } => {
                // A relative-memory verify precondition — the memory twin of
                // CompareProp. The expected bytes come from the op's own
                // `InlineData` (resolved at parse time), so this lowers with no
                // device access; the read base is resolved from the object's
                // PID_TABLE_REFERENCE at execute time. An op carrying no
                // `InlineData` (only a `Size`/`Range`-style expectation) keeps a
                // `None` expectation — a no-op confirm — so the whole procedure
                // still lowers rather than refusing.
                let offset = offset.unwrap_or(0);
                // The read span (offset + the compared length) must fit the 16-bit
                // A_Memory space once the device-supplied base (>= 0) is added.
                // Refuse here rather than truncate at execute time. Use the
                // InlineData length when present, else the declared `Size`.
                let read_len = inline_data
                    .as_ref()
                    .map(|d| d.len() as u64)
                    .unwrap_or_else(|| u64::from(size.unwrap_or(0)));
                let end = u64::from(offset).saturating_add(read_len);
                if read_len > MAX_WRITE_SPAN
                    || u64::from(offset) > MAX_WRITE_SPAN
                    || end > MAX_MEMORY_END
                {
                    return Err(PlanError::AddressOutOfRange {
                        step: step_no,
                        size: read_len,
                        end,
                        detail: format!(
                            "relative compare offset {offset} (segment base added at flash time)"
                        ),
                    });
                }
                steps.push(FlashStep::CompareRelMem {
                    target: *obj_idx,
                    offset,
                    expected: inline_data.clone(),
                    mask: mask.clone(),
                    invert: *invert,
                });
            }

            LoadOp::LoadImageProp {
                obj_idx,
                prop_id,
                count,
                ..
            } => {
                // The MCB integrity check for a loadable object. Resolve the
                // segment image whose CRC the device's PID_MCB_TABLE should
                // match: the most-recently written relative-memory image (the
                // procedures observed write one `full,par` image per object, then
                // check each object's MCB). Where no image was written into this
                // procedure the op still executes as a read-only confirm.
                let obj_idx = obj_idx.unwrap_or(0);
                let prop_id = prop_id.unwrap_or(u32::from(bussard_mgmt::PID_MCB_TABLE));
                let count = count.unwrap_or(1).max(1);
                // A table object (obj1/obj2/obj3) is checked against the image
                // written to *that* object; any other check verifies the
                // last-written (application) image, whose MCB lives on the
                // discovered application-program object.
                let image = written_image_by_object
                    .get(&obj_idx)
                    .cloned()
                    .or_else(|| last_written_image.clone());
                steps.push(FlashStep::LoadImageProp {
                    obj_idx,
                    prop_id,
                    count,
                    image,
                });
            }

            // Unsupported: refuse the whole procedure at pre-flight. These need
            // device-side behaviour bussard cannot yet verify (absolute segment
            // allocation is an unverified stub in bussard-mgmt; task segments have
            // no clean-room-verified execution).
            LoadOp::AbsSegment { .. } => {
                return Err(PlanError::UnsupportedOp {
                    op: "LdCtrlAbsSegment (absolute segment allocation is unverified)".to_string(),
                });
            }
            LoadOp::TaskSegment { .. } => {
                return Err(PlanError::UnsupportedOp {
                    op: "LdCtrlTaskSegment".to_string(),
                });
            }
            LoadOp::TaskCtrl1 { .. } => {
                return Err(PlanError::UnsupportedOp {
                    op: "LdCtrlTaskCtrl1".to_string(),
                });
            }
            LoadOp::Raw { name, .. } => {
                return Err(PlanError::UnsupportedOp { op: name.clone() });
            }
        }
    }

    // A filled segment is written sparsely (only the octets that differ from
    // the fill, issue #123). The device's fill is bookkeeping, not an erase, so
    // on a re-flash every octet the new image leaves out keeps whatever the
    // previous image put there (issue #117: a Jung F50 kept a blinking status
    // LED). ETS opens such a download with a factory reset (erase code 7) and
    // ends it with a confirmed restart (erase code 1); do the same.
    let sparse = steps
        .iter()
        .any(|s| matches!(s, FlashStep::AllocateSegment { fill: Some(_), .. }));
    if sparse {
        insert_factory_reset(&mut steps);
    }

    Ok(FlashPlan {
        identity: AppIdentity {
            id: app.id.clone(),
            name: app.name.clone(),
            application_number: app.application_number,
            application_version: app.application_version,
            mask_version: app_mask,
        },
        device_mask,
        steps,
        images,
        param_images,
        spliced_from_template,
        sys7: None,
        confirmed_restart: sparse,
    })
}

/// Inserts a [`FlashStep::FactoryReset`] with erase code 7 right before the
/// first `Unload` (or at the start when the procedure has none), so read-only
/// preconditions that precede the first state change still run on the intact
/// device, and the reset lands before anything is torn down or written.
fn insert_factory_reset(steps: &mut Vec<FlashStep>) {
    let at = steps
        .iter()
        .position(|s| {
            !matches!(
                s,
                FlashStep::CompareProp { .. } | FlashStep::CompareRelMem { .. }
            )
        })
        .unwrap_or(steps.len());
    steps.insert(
        at,
        FlashStep::FactoryReset {
            erase_code: bussard_mgmt::apci::ERASE_CODE_FACTORY_RESET_KEEP_IA,
        },
    );
}

/// Lowers a System 7 (mask 0705 / 0701) application into an executable
/// [`FlashPlan`] (`[system7-spec §3/§4]`).
///
/// System 7 is memory-mapped and absolute-addressed: the download is a sequence
/// of absolute-segment allocations + streams driven by three parallel load-state
/// machines, with no `PID_TABLE_REFERENCE` resolution and no relative segments.
/// The op → step mapping:
///
/// | `LoadOp`                | `FlashStep`                                    |
/// |-------------------------|------------------------------------------------|
/// | `Unload{lsm}`           | [`FlashStep::Sys7Unload`]                       |
/// | `Load{lsm}`             | [`FlashStep::Sys7StartLoading`]                 |
/// | `AbsSegment{lsm,a,sz}`  | [`FlashStep::Sys7AbsSegment`] (alloc + stream)  |
/// | `TaskSegment{lsm,a}`    | [`FlashStep::Sys7TaskSegment`]                  |
/// | `TaskCtrl1{lsm,a,c}`    | [`FlashStep::Sys7TaskCtrl1`]                    |
/// | `LoadCompleted{lsm}`    | [`FlashStep::Sys7LoadCompleted`]                |
/// | `CompareProp{0,78,d}`   | [`FlashStep::CompareProp`] (obj0/PID78 preflight)|
/// | `CompareMem{a,d,sz}` (Raw)| [`FlashStep::Sys7CompareMem`]                 |
/// | `LoadImageProp{oi,pid}` | [`FlashStep::LoadImageProp`] (Jung A-A011 MCB)  |
/// | `Restart`               | [`FlashStep::Restart`]                          |
///
/// The mask profile ([`bussard_mgmt::Sys7Profile`]) supplies the LSM realisation,
/// authorize level and mem-types; absent `HawkConfigurationData`, the
/// corpus-default profile drives blind (`[system7-spec §2.4]`).
fn plan_flash_sys7(
    app: &ApplicationProgram,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    profile: bussard_mgmt::MaskProfile,
    hawk: Option<&bussard_prod::HawkConfig>,
    tables: &Sys7PlanTables,
) -> std::result::Result<FlashPlan, PlanError> {
    let sys7_tables = &tables.tables;
    let linked_flags = &tables.linked_flags;
    let app_mask = app
        .mask_version
        .clone()
        .ok_or_else(|| PlanError::MissingAppMask(app.id.clone()))?;

    // System 7 apps carry their whole download in their own load procedures
    // (ProductProcedure style — no master-template splice; `[corpus 49/49]`).
    let (ops, _spliced) = assemble_ops(app, None);
    if ops.is_empty() {
        return Err(PlanError::NoProcedure(app.id.clone()));
    }

    // Resolve parameter images up front: each parameter segment's <Data> is only
    // the vendor's template, and the image streamed for it is that template with
    // the parameters laid over it.
    let param_images = bussard_prod::compute_parameter_image(app, overrides, base_offsets)
        .map_err(|e| PlanError::UnresolvableImage {
            step: 0,
            reason: format!("computing the parameter image: {e}"),
        })?;

    // The data-driven mask profile: from `HawkConfigurationData` when the import
    // path supplied one, else the corpus-default fallback (`[system7-spec §2.4]`).
    let mut s7_profile = hawk
        .and_then(sys7_profile_from_hawk)
        .or_else(|| profile.sys7_default_profile())
        .unwrap_or_else(bussard_mgmt::Sys7Profile::corpus_default);
    // Realisation override (`[system7-spec §5]`: "flipping the profile bit is a
    // one-line change"). The product data selects the realisation (default
    // memory-mapped); this env var flips it so bussard's `LsmAccess` switch can be
    // conformance-tested against a property-based device side without a second
    // product. It never changes what a normal, product-driven flash does.
    if let Some(lsm) = sys7_lsm_override() {
        s7_profile.lsm = lsm;
    }

    // Index the app's absolute code segments by address so each AbsSegment op can
    // find its <Data>/<Mask> payload. System 7 segments are all absolute.
    let mut seg_by_addr: BTreeMap<u32, &bussard_prod::CodeSegment> = BTreeMap::new();
    for seg in app.code_segments.values() {
        if seg.kind == SegmentKind::Absolute
            && let Some(addr) = seg.address_or_offset
        {
            seg_by_addr.insert(addr, seg);
        }
    }

    let mut steps: Vec<FlashStep> = Vec::new();
    let mut images: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut segment_masks: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    // The TaskSegment trailing marker `[lead][AppNumber:2][ver]` is per-app: the
    // lead byte tracks the mask family (0x04 on 0705, 0x48 on 0701), the middle two
    // octets are the application number, the trailing octet the app version's low
    // byte (`[system7-spec §4.3]`; the lead/version octets are best-effort — see
    // `bussard_mgmt::task_segment_marker`).
    let task_marker = bussard_mgmt::task_segment_marker(
        device_mask,
        app.application_number.unwrap_or(0) as u16,
        app.application_version.unwrap_or(0) as u8,
    );

    for (i, op) in ops.iter().enumerate() {
        let step_no = i + 1;
        match op {
            LoadOp::Connect | LoadOp::Disconnect => {}
            LoadOp::Restart => steps.push(FlashStep::Restart),
            LoadOp::Unload { lsm_idx } => steps.push(FlashStep::Sys7Unload {
                lsm: check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?,
            }),
            LoadOp::Load { lsm_idx } => steps.push(FlashStep::Sys7StartLoading {
                lsm: check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?,
            }),
            LoadOp::LoadCompleted { lsm_idx } => steps.push(FlashStep::Sys7LoadCompleted {
                lsm: check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?,
            }),
            LoadOp::AbsSegment {
                lsm_idx,
                address,
                size,
                access,
                mem_type,
                seg_flags,
            } => {
                // Validate before anything is bound: the executor folds the LSM
                // index into the record's opcode nibble and the address/size into
                // its 2-octet fields, so an out-of-range value used to go out as a
                // *wrong frame* on the bus (issue #81).
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                let addr = address.ok_or_else(|| PlanError::UnresolvableImage {
                    step: step_no,
                    reason: "LdCtrlAbsSegment has no Address".to_string(),
                })?;
                let addr = check_sys7_u16(step_no, "segment address", addr)?;
                let size = check_sys7_u16(step_no, "segment size", size.unwrap_or(0))?;
                // The allocation must also *fit* the 16-bit space: a segment that
                // starts inside it but runs past 0xFFFF cannot be placed.
                check_sys7_u16(step_no, "segment end", addr + size.saturating_sub(1))?;
                // The allocation record's attribute octets come from the op itself
                // when the product declares them (`Access`/`MemType`/`SegFlags`,
                // which the ETS captures reproduce verbatim: `f2 03 80`,
                // `f3 03 80`, `f3 03 00`), else from the address-derived defaults.
                let mem_type = mem_type
                    .and_then(|m| u8::try_from(m).ok())
                    .unwrap_or_else(|| mem_type_for_addr(addr, &s7_profile));
                let (default_flags, default_checksum) = bussard_mgmt::alloc_attr_octets(mem_type);
                let op_seg_flags: Option<u32> = seg_flags.to_owned();
                let checksum_ctrl = seg_flags_octet(op_seg_flags).unwrap_or(default_checksum);
                let seg_flags = access
                    .and_then(|a| u8::try_from(a).ok())
                    .unwrap_or(default_flags);
                // A table LSM (1 = group addresses, 2 = associations) streams the
                // table computed from the model, never the product's `<Data>`
                // template: the Jung 3361-1MWW ships a 255-entry placeholder table
                // (`FF 00 00 00 01 00 02 …`) which, written verbatim, linked the
                // device to 254 group addresses (issue #89, 1.1.36). ETS writes
                // the count octet and the group addresses only, skipping the
                // device-owned individual-address slot — the table mask does the
                // same here.
                let image = if let Some(table) = sys7_tables.get(&lsm) {
                    if table.image.len() > size as usize {
                        return Err(PlanError::UnresolvableImage {
                            step: step_no,
                            reason: format!(
                                "LSM {lsm} table image is {} octets but the segment at {addr:#06X} holds {size}",
                                table.image.len()
                            ),
                        });
                    }
                    let id = seg_by_addr
                        .get(&addr)
                        .map(|seg| seg.id.clone())
                        .unwrap_or_else(|| format!("lsm{lsm}-table-{addr:#06X}"));
                    images.insert(id.clone(), table.image.clone());
                    if let Some(mask) = &table.mask {
                        segment_masks.insert(id.clone(), mask.clone());
                    }
                    Some(ImageRef {
                        segment_id: id,
                        kind: ImageKind::Table,
                        len: table.image.len(),
                    })
                } else {
                    // Bind the segment's parameter image: its <Data> with every
                    // parameter's resolved value (vendor default, ParameterRef
                    // override, model override) laid over it. Streaming the raw
                    // <Data> template instead wrote the vendor's placeholder
                    // bytes, which are not the parameter defaults, and dropped
                    // every model override (issue #117: the 3361-1MWW and 3181
                    // parameter segments). A segment with no <Data> that no
                    // parameter targets is an allocate-only record (e.g. the
                    // 0x0700 RAM region), with no stream.
                    seg_by_addr.get(&addr).and_then(|seg| {
                        let bytes = param_images
                            .get(&seg.id)
                            .filter(|b| !b.is_empty())
                            .or(seg.data.as_ref());
                        bytes.map(|data| {
                            images.insert(seg.id.clone(), data.clone());
                            if let Some(mask) = &seg.mask {
                                segment_masks.insert(seg.id.clone(), mask.clone());
                            }
                            ImageRef {
                                segment_id: seg.id.clone(),
                                kind: ImageKind::Code,
                                len: data.len(),
                            }
                        })
                    })
                };
                steps.push(FlashStep::Sys7AbsSegment {
                    lsm,
                    address: addr,
                    size,
                    mem_type,
                    seg_flags,
                    checksum_ctrl,
                    image,
                });
            }
            LoadOp::TaskSegment { lsm_idx, address } => {
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                let addr = address.ok_or_else(|| PlanError::UnresolvableImage {
                    step: step_no,
                    reason: "LdCtrlTaskSegment has no Address".to_string(),
                })?;
                let addr = check_sys7_u16(step_no, "task segment address", addr)?;
                // ETS writes a zero-length field + a `[lead][AppNumber:2][ver]`
                // marker, not the loaded span. Derive the marker from the mask
                // family + application number (`[system7-spec §4.3]`).
                steps.push(FlashStep::Sys7TaskSegment {
                    lsm,
                    address: addr,
                    marker: task_marker,
                });
            }
            LoadOp::TaskCtrl1 {
                lsm_idx,
                address,
                count,
            } => {
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                let addr = address.ok_or_else(|| PlanError::UnresolvableImage {
                    step: step_no,
                    reason: "LdCtrlTaskCtrl1 has no Address".to_string(),
                })?;
                let addr = check_sys7_u16(step_no, "task control address", addr)?;
                // The count is a single octet of the record.
                let count = count.unwrap_or(1);
                if count > u32::from(u8::MAX) {
                    return Err(PlanError::Sys7FieldOutOfRange {
                        step: step_no,
                        field: "task control count",
                        value: u64::from(count),
                        max: u64::from(u8::MAX),
                    });
                }
                steps.push(FlashStep::Sys7TaskCtrl1 {
                    lsm,
                    address: addr,
                    count,
                });
            }
            LoadOp::CompareProp {
                obj_idx,
                prop_id,
                inline_data,
                mask,
                ..
            } => {
                // The obj0/PID78 preflight (44/49 MDT apps). Reuses the System B
                // CompareProp step: an interface-object property read + compare,
                // which is identical on System 7 (`[system7-spec §4.6]`).
                steps.push(FlashStep::CompareProp {
                    obj_idx: obj_idx.unwrap_or(0),
                    prop_id: prop_id.unwrap_or(0),
                    expected: inline_data.clone(),
                    mask: mask.clone(),
                });
            }
            LoadOp::LoadImageProp {
                obj_idx,
                prop_id,
                count,
                ..
            } => {
                // Jung M-0004_A-A011 requires per-object MCB verification via
                // LoadImageProp PID 27 (`[system7-spec §2 amendment]`). Reuses the
                // System B LoadImageProp step (an MCB-table read + CRC compare).
                steps.push(FlashStep::LoadImageProp {
                    obj_idx: obj_idx.unwrap_or(0),
                    prop_id: prop_id.unwrap_or(bussard_mgmt::PID_MCB_TABLE.into()),
                    count: count.unwrap_or(1).max(1),
                    // System 7 read-back verify is the baseline; the MCB check is a
                    // read-only confirm against the device's own CRC, so no
                    // tool-side image is bound here.
                    image: None,
                });
            }
            LoadOp::Raw { name, attrs } if name == "LdCtrlCompareMem" => {
                let (address, expected) =
                    parse_compare_mem(attrs).ok_or_else(|| PlanError::UnresolvableImage {
                        step: step_no,
                        reason: "LdCtrlCompareMem missing Address or InlineData".to_string(),
                    })?;
                let address = check_sys7_u16(step_no, "compare address", address)?;
                steps.push(FlashStep::Sys7CompareMem { address, expected });
            }
            // System 7 never carries these (`[corpus §2]`); a Raw op we do not
            // recognise refuses cleanly rather than silently skipping.
            other => {
                return Err(PlanError::UnsupportedOp {
                    op: sys7_op_label(other),
                });
            }
        }
    }

    // The group-object descriptors live inside the application's own EEPROM
    // segment on these devices (`GroupObjectTable AddressSpace="None"` in the
    // mask's Hawk data), with the vendor template's communication flag set on
    // every object. ETS enables the flag only on linked objects (captures
    // 1.1.31 with no links: none set; 1.1.46 with four links: exactly the four
    // association ASAPs). Mirror that here (issue #89, 1.1.32).
    let linked: BTreeSet<u16> = sys7_tables
        .get(&2)
        .map(|assoc| sys7_linked_asaps(&assoc.image))
        .unwrap_or_default();
    // Every unlinked object's CONFIG (and TYPE) comes from the ComObjectRef the
    // device's parameter values make visible, as in ETS (issue #117).
    let config = bussard_prod::dynamic::evaluate_dynamic(app, overrides);
    let default_flags = sys7_object_defaults(app, &config);
    // Module instances shift numbers past the declared ones: count those too.
    let last_object = app
        .resolved_com_objects()
        .iter()
        .map(|c| c.number())
        .chain(default_flags.keys().copied())
        .chain(linked.iter().copied())
        .max();
    apply_sys7_group_object_links(
        &steps,
        &mut images,
        &linked,
        linked_flags,
        &default_flags,
        last_object,
    );

    Ok(FlashPlan {
        identity: AppIdentity {
            id: app.id.clone(),
            name: app.name.clone(),
            application_number: app.application_number,
            application_version: app.application_version,
            mask_version: app_mask,
        },
        device_mask,
        steps,
        images,
        param_images,
        spliced_from_template: false,
        sys7: Some(Sys7Context {
            profile: s7_profile,
            segment_masks,
        }),
        confirmed_restart: false,
    })
}

/// What the System 7 post-pass writes for one object that the project does not
/// link: the flags of its ComObjectRef and, when known, its TYPE octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sys7ObjectDefault {
    /// The ref's flags (ref merged onto the base object).
    flags: bussard_model::Flags,
    /// The TYPE octet (the size code of the ref's object size), `None` to keep
    /// the template's.
    type_code: Option<u8>,
}

/// The per-ASAP defaults the System 7 post-pass writes, from the Dynamic walk.
///
/// ETS writes, for every object the device's parameter values make visible,
/// the flags of the visible ComObjectRef (the 3361-1MWW and 3181 captures of
/// issue #117: the same object `Number` has refs with different flags under
/// different `<when>` branches), and leaves an object no branch shows at the
/// template (C cleared). An application without a Dynamic section (the walk
/// reaches no com-object) falls back to the flat product defaults: every
/// declared ref's flags, with the template's TYPE.
fn sys7_object_defaults(
    app: &ApplicationProgram,
    config: &bussard_prod::dynamic::DynamicConfig,
) -> BTreeMap<u16, Sys7ObjectDefault> {
    if config.com_objects.is_empty() {
        return app
            .resolved_com_objects()
            .iter()
            .map(|c| {
                (
                    c.number(),
                    Sys7ObjectDefault {
                        flags: c.flags(),
                        type_code: None,
                    },
                )
            })
            .collect();
    }
    let mut out = BTreeMap::new();
    for active in &config.com_objects {
        let Some((base, cref)) = app.resolve(&active.com_object_ref_id) else {
            continue;
        };
        let offset = base
            .base_number_ref
            .as_deref()
            .map(|arg| arg.strip_prefix(&format!("{}_", app.id)).unwrap_or(arg))
            .and_then(|arg| config.module_args(active.module)?.get(arg).copied())
            .unwrap_or(0);
        let Ok(asap) = u16::try_from(i64::from(base.number) + offset) else {
            continue;
        };
        let size = cref.object_size.as_deref().or(base.object_size.as_deref());
        out.insert(
            asap,
            Sys7ObjectDefault {
                flags: base.flags.merge(cref.flags).to_flags(),
                type_code: size.and_then(sys7_type_code),
            },
        );
    }
    out
}

/// The System 7 TYPE octet for an `ObjectSize` (the KNX size code: `1 Bit` is
/// 0, `1 Byte` 7, `2 Bytes` 8), `None` for a size the table does not know.
fn sys7_type_code(object_size: &str) -> Option<u8> {
    let code = crate::compute::size_code_from_object_size(Some(object_size));
    let one_bit = object_size.trim().eq_ignore_ascii_case("1 bit");
    (code != 0 || one_bit).then_some(code)
}

/// The System 7 CONFIG octet for a linked object: the project's flags in bits
/// 7 (U), 6 (T), 4 (W), 3 (R) and 2 (C), the template's bits 5, 1 and 0 kept.
fn sys7_config_from_flags(template: u8, flags: bussard_model::Flags) -> u8 {
    use bussard_model::Flags;
    let mut c = template & 0b0010_0011;
    for (bit, flag) in [
        (7, Flags::UPDATE),
        (6, Flags::TRANSMIT),
        (4, Flags::WRITE),
        (3, Flags::READ),
        (2, Flags::COMMUNICATION),
    ] {
        if flags.contains(flag) {
            c |= 1 << bit;
        }
    }
    c
}

/// The ASAPs a System 7 association-table image (`[CNT][TSAP ASAP]…`) links.
fn sys7_linked_asaps(assoc_image: &[u8]) -> BTreeSet<u16> {
    let Some((&count, pairs)) = assoc_image.split_first() else {
        return BTreeSet::new();
    };
    pairs
        .chunks_exact(2)
        .take(usize::from(count))
        .map(|p| u16::from(p[1]))
        .collect()
}

/// Rewrites the CONFIG octet of the group-object descriptors inside the LSM 3
/// segment image that carries the descriptor table, the way ETS does. Bits 7
/// (U), 6 (T), 4 (W), 3 (R) and 2 (C) come from the object's flags, bits 5, 1
/// and 0 stay as the template has them:
///
/// - a linked ASAP takes the model's flags (`linked_flags`), else its default
///   flags with C set, else the template with C set;
/// - every other ASAP takes its default flags (`default_flags`, see
///   [`sys7_object_defaults`]) with C cleared, else the template with C
///   cleared.
///
/// An ASAP whose default carries a TYPE octet (the visible ref's object size)
/// takes that too.
///
/// `last_object` is the highest com-object `Number` the application declares:
/// ETS rewrites the descriptors up to it (numbering gaps included) and leaves
/// the template slots past it alone (1.1.1, 2116REG: the template declares 129
/// descriptors, the application objects up to 126, and ETS keeps the `17` of
/// descriptors 127 and 128 while it clears C on the gaps 6, 7, 14, …). `None`
/// rewrites every descriptor.
///
/// Captures: 1.1.31 (no links: template `db` became `4b`, `17` became `13`),
/// 1.1.46 (four links: `df` became `4f`/`17`/`47`, the project's T R C / W C /
/// T C), 1.1.1 (`47` became `5f`); objects no `<when>` branch shows keep the
/// template (`db`) on the 3361-1MWW and 3181 captures (issue #117).
///
/// The table is found by shape, since the mask declares no address for it:
/// `[CNT:1][RAM-flags ptr:2]` followed by `CNT` 4-octet descriptors
/// `[data ptr:2 BE][CONFIG][TYPE]`, where every data pointer and the RAM-flags
/// pointer fall inside a RAM (`mem_type` 2) segment the same plan allocates.
/// Descriptor `i` is ASAP `i` (the 1.1.46 capture: association ASAPs 1, 5, 7,
/// 13 are exactly the descriptors ETS enabled). A plan without such a segment
/// is left untouched.
fn apply_sys7_group_object_links(
    steps: &[FlashStep],
    images: &mut BTreeMap<String, Vec<u8>>,
    linked: &BTreeSet<u16>,
    linked_flags: &BTreeMap<u16, bussard_model::Flags>,
    default_flags: &BTreeMap<u16, Sys7ObjectDefault>,
    last_object: Option<u16>,
) {
    let ram: Vec<(u32, u32)> = steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::Sys7AbsSegment {
                address,
                size,
                mem_type: 2,
                ..
            } => Some((*address, *address + *size)),
            _ => None,
        })
        .collect();
    if ram.is_empty() {
        return;
    }
    // An unused descriptor slot carries a zero data pointer (the 3361 image
    // declares 200 slots and uses 125), so zero passes the shape check.
    let in_ram = |p: u16| {
        p == 0
            || ram
                .iter()
                .any(|(lo, hi)| (*lo..*hi).contains(&u32::from(p)))
    };
    for step in steps {
        let FlashStep::Sys7AbsSegment {
            lsm: 3,
            mem_type: 3,
            image: Some(img),
            ..
        } = step
        else {
            continue;
        };
        let Some(bytes) = images.get_mut(&img.segment_id) else {
            continue;
        };
        let Some((&count, rest)) = bytes.split_first() else {
            continue;
        };
        let count = usize::from(count);
        if count == 0 || rest.len() < 2 + 4 * count {
            continue;
        }
        let ram_flags = u16::from_be_bytes([rest[0], rest[1]]);
        let descriptors = &rest[2..2 + 4 * count];
        let shaped = in_ram(ram_flags)
            && descriptors
                .chunks_exact(4)
                .all(|d| in_ram(u16::from_be_bytes([d[0], d[1]])));
        if !shaped {
            continue;
        }
        use bussard_model::Flags;
        for (asap, d) in bytes[3..3 + 4 * count].chunks_exact_mut(4).enumerate() {
            let asap = asap as u16;
            if last_object.is_some_and(|last| asap > last) {
                break;
            }
            let default = default_flags.get(&asap);
            if linked.contains(&asap) {
                match linked_flags
                    .get(&asap)
                    .copied()
                    .or_else(|| default.map(|o| o.flags | Flags::COMMUNICATION))
                {
                    Some(flags) => d[2] = sys7_config_from_flags(d[2], flags),
                    None => d[2] |= 0x04,
                }
            } else {
                match default {
                    Some(o) => d[2] = sys7_config_from_flags(d[2], o.flags - Flags::COMMUNICATION),
                    None => d[2] &= !0x04,
                }
            }
            if let Some(t) = default.and_then(|o| o.type_code) {
                d[3] = t;
            }
        }
        return;
    }
}

/// Plans a System 7 flash using a `.knxprod`'s parsed `HawkConfigurationData` to
/// resolve the LSM realisation and addresses, falling back to the corpus default
/// when the block is absent (`[system7-spec §2.4]`).
///
/// This is the data-driven entry the CLI uses when it has the master template's
/// Hawk config for the device mask; [`plan_flash`] itself (which does not receive
/// the full template) uses the corpus default. Refuses a non-System-7 mask with
/// [`PlanError::NotSystemB`].
pub fn plan_flash_sys7_with_hawk(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    hawk: Option<&bussard_prod::HawkConfig>,
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> std::result::Result<FlashPlan, PlanError> {
    let profile = bussard_mgmt::MaskProfile::from_mask(device_mask);
    if !profile.is_system_7() {
        return Err(PlanError::NotSystemB {
            device: device.to_string(),
            device_mask,
            system: bussard_mgmt::system_type(device_mask),
        });
    }
    let app_mask = app
        .mask_version
        .clone()
        .ok_or_else(|| PlanError::MissingAppMask(app.id.clone()))?;
    if u16::from_str_radix(app_mask.trim(), 16).ok() != Some(device_mask) {
        return Err(PlanError::MaskMismatch {
            device: device.to_string(),
            device_mask,
            app_mask,
        });
    }
    let tables = Sys7PlanTables::from_system_b(table_images);
    plan_flash_sys7(
        app,
        device_mask,
        overrides,
        base_offsets,
        profile,
        hawk,
        &tables,
    )
}

/// The model-derived inputs of a System 7 plan: the table images for LSM 1/2
/// and the flags of every linked com-object (for the descriptor CONFIG octets).
#[derive(Debug, Clone, Default)]
pub struct Sys7PlanTables {
    /// Computed table images keyed by LSM index (1 = addresses, 2 = associations).
    pub tables: BTreeMap<u32, Sys7TableImage>,
    /// The linked objects' flags, keyed by ASAP.
    pub linked_flags: BTreeMap<u16, bussard_model::Flags>,
}

impl Sys7PlanTables {
    /// Derives both from the System B table images [`plan_flash`] receives.
    pub fn from_system_b(table_images: &BTreeMap<u32, Vec<u8>>) -> Self {
        Self {
            tables: sys7_tables_from_system_b(table_images),
            linked_flags: linked_flags_from_system_b(table_images),
        }
    }
}

/// The com-object flags of every linked object, decoded from the System B
/// group-object table image (`[count:2][word per ASAP]`, see
/// `compute::group_object_word`: bit 10 C, 11 R, 12 W, 13 I, 14 T, 15 U).
/// A zero word is an unlinked ASAP and is left out.
pub fn linked_flags_from_system_b(
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> BTreeMap<u16, bussard_model::Flags> {
    use bussard_model::Flags;
    let mut out = BTreeMap::new();
    let Some(img) = table_images.get(&3).filter(|img| img.len() >= 2) else {
        return out;
    };
    for (i, w) in img[2..].chunks_exact(2).enumerate() {
        let word = u16::from_be_bytes([w[0], w[1]]);
        if word == 0 {
            continue;
        }
        let mut flags = Flags::empty();
        for (bit, flag) in [
            (10, Flags::COMMUNICATION),
            (11, Flags::READ),
            (12, Flags::WRITE),
            (13, Flags::INIT),
            (14, Flags::TRANSMIT),
            (15, Flags::UPDATE),
        ] {
            if word & (1 << bit) != 0 {
                flags |= flag;
            }
        }
        out.insert((i + 1) as u16, flags);
    }
    out
}

/// A computed System 7 table image bound to a table LSM's absolute segment in
/// place of the product's `<Data>` template.
///
/// `mask` (same length as `image`, `0xFF` = write, `0x00` = leave the device's
/// octet alone) skips the individual-address slot of the group-address table,
/// exactly as ETS does: it writes the count octet at the segment start and the
/// group addresses from offset 3, never the two octets in between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sys7TableImage {
    /// The table octets, from the segment start.
    pub image: Vec<u8>,
    /// Per-octet write mask, when part of the span is device-owned.
    pub mask: Option<Vec<u8>>,
}

/// Derives the System 7 table images (keyed by LSM index: 1 = group-address
/// table, 2 = association table) from the System B table images
/// [`plan_flash`] receives (keyed by object index, `[count:2 BE][elements]`
/// with 2-octet address and 4-octet `[TSAP:2][ASAP:2]` association elements).
///
/// System 7 layouts (`[system7-spec §7]`, ETS captures for 1.1.31 and 1.1.46):
///
/// ```text
/// group addresses  [CNT:1][own IA:2, device-owned][GA1:2 BE]…   CNT = 1 + n
/// associations     [CNT:1][TSAP:1][ASAP:1]…                     CNT = n
/// ```
///
/// A table that does not fit the one-octet count is left out, and the
/// lowering then keeps the product's `<Data>`; the segment-size check there
/// refuses an image longer than its segment.
pub fn sys7_tables_from_system_b(
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> BTreeMap<u32, Sys7TableImage> {
    let mut out = BTreeMap::new();
    if let Some(addr) = table_images.get(&1).filter(|img| img.len() >= 2) {
        let elements = &addr[2..];
        let n = elements.len() / 2;
        if n < usize::from(u8::MAX) {
            let mut image = Vec::with_capacity(3 + elements.len());
            image.push((n + 1) as u8);
            image.extend_from_slice(&[0, 0]);
            image.extend_from_slice(&elements[..n * 2]);
            let mut mask = vec![0xFF; image.len()];
            mask[1] = 0;
            mask[2] = 0;
            out.insert(
                1,
                Sys7TableImage {
                    image,
                    mask: Some(mask),
                },
            );
        }
    }
    if let Some(assoc) = table_images.get(&2).filter(|img| img.len() >= 2) {
        let elements = &assoc[2..];
        let n = elements.len() / 4;
        let fits =
            n <= usize::from(u8::MAX) && elements.chunks_exact(4).all(|e| e[0] == 0 && e[2] == 0);
        if fits {
            let mut image = Vec::with_capacity(1 + n * 2);
            image.push(n as u8);
            for e in elements.chunks_exact(4) {
                image.push(e[1]);
                image.push(e[3]);
            }
            out.insert(2, Sys7TableImage { image, mask: None });
        }
    }
    out
}

/// Maps an `LdCtrlAbsSegment` `SegFlags` attribute to the allocation record's
/// checksum-control octet: `128` → `0x80` (checksum-controlled), `0` → `0x00`
/// (runtime-writable). Any other value is passed through when it fits an octet.
fn seg_flags_octet(seg_flags: Option<u32>) -> Option<u8> {
    seg_flags.and_then(|f| u8::try_from(f).ok())
}

/// Derives a [`bussard_mgmt::Sys7Profile`] from a mask's parsed
/// `HawkConfigurationData` (`[system7-spec §2.4/§5]`).
///
/// Reads the `GroupAddressTableLoadControl` (the LSM control address + record
/// length) and `GroupAddressTableLoadStatus` (the status base) resources. A
/// `Flavour="LoadControl_M112"` LoadControl in `StandardMemory` selects
/// [`bussard_mgmt::LsmRealisation::MemoryMapped`] with the resolved addresses;
/// absent that, `None` (the caller falls back to the corpus default — property).
///
/// **M2 caveat (issue #70).** The Jung MV-0705 block resolves to control `0x0104`
/// / status `0xB6EA`, but the M2 live capture proved the Jung device does NOT
/// drive its LSM there: load control is property-based (`A_PropertyValue_Write`
/// PID 5), and the only `0xB6EA+` touch is a single `A_Memory_Read` at `0xB6EC`
/// (a *readable* status region). So the `LoadControl_M112 @ 0x0104` block did not
/// predict the wire for Jung. The normal CLI flash path therefore does NOT feed a
/// Hawk config here (it plans with the property corpus default); this helper stays
/// for the data-driven memory-mapped conformance harness and for any 0705 silicon
/// a future capture proves genuinely memory-mapped.
pub fn sys7_profile_from_hawk(
    hawk: &bussard_prod::HawkConfig,
) -> Option<bussard_mgmt::Sys7Profile> {
    let control = hawk.resource("GroupAddressTableLoadControl")?;
    // Only the memory-mapped M112 LoadControl is data-driven here; a property
    // realisation would carry a SystemProperty address space instead.
    let control_addr = match (control.address_space.as_deref(), control.start_address) {
        (Some("StandardMemory"), Some(addr)) => u16::try_from(addr).ok()?,
        _ => return None,
    };
    let status_addr = hawk
        .resource("GroupAddressTableLoadStatus")
        .and_then(|s| s.start_address)
        .and_then(|a| u16::try_from(a).ok())
        .unwrap_or(0xB6EA);
    let mut profile = bussard_mgmt::Sys7Profile::corpus_default();
    profile.lsm = bussard_mgmt::LsmRealisation::MemoryMapped {
        control_addr,
        status_addr,
    };
    Some(profile)
}

/// The mem-type for a System 7 absolute-segment allocation at `addr`: RAM (`2`)
/// for the low-RAM working region (`0x0700`/`0x0730` ≤ addr < `0x4000`), EEPROM
/// (`3`) for the table/param regions (`[system7-spec §4.2]`).
fn mem_type_for_addr(addr: u32, profile: &bussard_mgmt::Sys7Profile) -> u8 {
    if addr < 0x4000 {
        profile.ram_mem_type
    } else {
        profile.eeprom_mem_type
    }
}

/// A human label for a System 7 op that this engine cannot lower.
fn sys7_op_label(op: &LoadOp) -> String {
    match op {
        LoadOp::Raw { name, .. } => name.clone(),
        LoadOp::WriteMem { .. } => "LdCtrlWriteMem (not in the System 7 corpus)".to_string(),
        LoadOp::RelSegment { .. } => {
            "LdCtrlRelSegment (System 7 is absolute-addressed)".to_string()
        }
        LoadOp::WriteRelMem { .. } => {
            "LdCtrlWriteRelMem (System 7 is absolute-addressed)".to_string()
        }
        LoadOp::WriteProp { .. } => "LdCtrlWriteProp (not in the System 7 corpus)".to_string(),
        LoadOp::MasterReset { .. } => "LdCtrlMasterReset (not in the System 7 corpus)".to_string(),
        other => format!("{other:?}"),
    }
}

/// Parses an `LdCtrlCompareMem` raw op's `Address` and `InlineData` attributes
/// (`[system7-spec §4.5]`). Returns `(address, expected_bytes)`.
fn parse_compare_mem(attrs: &[(String, String)]) -> Option<(u32, Vec<u8>)> {
    let mut address: Option<u32> = None;
    let mut inline: Option<Vec<u8>> = None;
    for (k, v) in attrs {
        match k.as_str() {
            "Address" => address = v.trim().parse().ok(),
            "InlineData" => inline = decode_hex(v),
            _ => {}
        }
    }
    Some((address?, inline?))
}

/// Decodes an even-length hex string (e.g. an `InlineData` attribute) into bytes;
/// `None` on odd length or a non-hex digit.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Assembles the op sequence to execute from an app's load procedures, splicing
/// against the master template when one is supplied.
///
/// A `MergedProcedure` app carries only its own per-object `<LoadProcedure
/// MergeId="N">` blocks (e.g. DA.tp: MergeId 2 = allocate the app segment +
/// MasterReset, MergeId 4 = write it). The Unload/Load/allocate/write/complete
/// ops for the **table** objects (obj1/obj2/obj3) live in `knx_master.xml`'s
/// `Load` procedure for the device mask, which threads the app's blocks in at
/// `<LdCtrlMerge MergeId="N"/>` markers. So, when `template_ops` is present and
/// the app is merged-style, the assembled sequence is the template with each
/// `Merge` marker replaced by its matching app block (an unmatched marker — ids
/// the app supplies nothing for, e.g. 1/3/5/6/7 — is dropped). This is the only
/// way a merged app programs all four objects the way ETS does.
///
/// Without a template (`None`), or for a self-contained app whose blocks are not
/// all `MergeId`-tagged (the conformant thelsing ProductDefault shape), there is
/// no splicing: the blocks are concatenated by ascending `MergeId`, or the
/// single richest block is used — preserving the previous single-object
/// behaviour exactly. This keeps the `virtual-device-flash` CI path green.
fn assemble_ops(app: &ApplicationProgram, template_ops: Option<&[LoadOp]>) -> (Vec<LoadOp>, bool) {
    let non_empty: Vec<&LoadProcedure> = app
        .load_procedures
        .iter()
        .filter(|p| !p.ops.is_empty())
        .collect();
    if non_empty.is_empty() {
        return (Vec::new(), false);
    }
    let all_merged = non_empty.iter().all(|p| p.merge_id.is_some());

    // Splice against the master template: only when a template is available AND
    // the app is merged-style (every block is MergeId-tagged). This is the
    // DA.tp / MV-07B0 case; anything else stays on the self-contained path.
    if all_merged {
        if let Some(template) = template_ops {
            // App blocks keyed by parsed MergeId. A block whose id is not numeric
            // cannot match a numeric `<LdCtrlMerge MergeId=N>` and is ignored.
            let mut blocks: BTreeMap<u32, Vec<LoadOp>> = BTreeMap::new();
            for p in &non_empty {
                if let Some(id) = p.merge_id.as_deref().and_then(|m| m.parse::<u32>().ok()) {
                    blocks.entry(id).or_default().extend(p.ops.clone());
                }
            }
            let mut out = Vec::new();
            for op in template {
                match op {
                    LoadOp::Merge { merge_id } => {
                        if let Some(ops) = merge_id
                            .as_deref()
                            .and_then(|m| m.parse::<u32>().ok())
                            .and_then(|id| blocks.get(&id))
                        {
                            out.extend(ops.iter().cloned());
                        }
                        // Unmatched or id-less marker: drop it.
                    }
                    other => out.push(other.clone()),
                }
            }
            return (out, true);
        }
    }

    // Self-contained: no template splice. Merged-style (all MergeId) → concat in
    // ascending MergeId order; else the richest single block.
    if all_merged && non_empty.len() > 1 {
        let mut blocks = non_empty.clone();
        blocks.sort_by(|a, b| {
            let key = |p: &&LoadProcedure| {
                p.merge_id
                    .as_deref()
                    .and_then(|m| m.parse::<u32>().ok())
                    .map(|n| (0u8, n, String::new()))
                    .unwrap_or_else(|| (1u8, 0, p.merge_id.clone().unwrap_or_default()))
            };
            key(a).cmp(&key(b))
        });
        return (
            blocks.into_iter().flat_map(|p| p.ops.clone()).collect(),
            false,
        );
    }
    (
        non_empty
            .into_iter()
            .max_by_key(|p| p.ops.len())
            .map(|p| p.ops.clone())
            .unwrap_or_default(),
        false,
    )
}

/// Resolves which relative segment a `RelSegment` op allocates. Returns
/// `(segment_id, declared_size)`.
///
/// The op names the load state machine it allocates on (`LsmIdx`), and a
/// `<RelativeSegment>` declares the LSM it belongs to (`LoadStateMachine`), so
/// that pair — not document order — is the segment's identity. When the op names
/// an LSM that some relative segment declares, the candidates are narrowed to
/// that LSM: the first one not already allocated, or, when they are all
/// allocated, the first one again (a **restated** allocation of a segment this
/// procedure has already opened, which the caller's dedupe then collapses).
///
/// Evidence (ABB/Busch-Jaeger i-bus, `M-0002_A-0806-71-AD30-O0007`, issue #113):
/// the app declares `RS-03-00000` (`LoadStateMachine="3"`, the group-object-table
/// segment) *and* `RS-04-00000` (`LoadStateMachine="4"`, the app segment), while
/// its `MergeId=2` block restates one LSM-4 allocation twice (`AppliesTo="full"`
/// then `="par"`, both `LsmIdx="4" Size="232"`). Handing segments out in id order
/// bound the first op to `RS-03` and the second to `RS-04`, so the two ops looked
/// like two different segments and the dedupe below declined — lowering two
/// identical `AllocateSegment { size: 232, target: 4 }` steps, i.e. a repeated
/// relative allocation on one object, the shape that broke a device during the KV
/// work. Matching on the LSM binds both ops to `RS-04` and the restatement
/// collapses. 153 of the 865 System B applications in the product corpus (every
/// one of them an ABB `M-0002` or Busch-Jaeger `M-0007` app with this
/// two-segment shape) were affected.
///
/// An op with no `LsmIdx`, or one naming an LSM no segment declares, keeps the
/// historical document-order fallback, so a single-segment app and the
/// multi-segment fixtures whose segments share one LSM lower exactly as before.
fn resolve_rel_segment(
    app: &ApplicationProgram,
    lsm_idx: Option<u32>,
    _applies_to: Option<&str>,
    already: &BTreeMap<String, Vec<u8>>,
) -> Option<(String, Option<u32>)> {
    let mut segs: Vec<_> = app
        .code_segments
        .values()
        .filter(|s| s.kind == SegmentKind::Relative)
        .collect();
    segs.sort_by(|a, b| a.id.cmp(&b.id));

    // Narrow to the op's own load state machine when it names one that some
    // segment declares; otherwise keep every relative segment as a candidate.
    let on_lsm: Vec<_> = match lsm_idx {
        Some(idx) => segs
            .iter()
            .copied()
            .filter(|s| s.load_state_machine == Some(idx))
            .collect(),
        None => Vec::new(),
    };
    let candidates = if on_lsm.is_empty() { &segs } else { &on_lsm };

    candidates
        .iter()
        .find(|s| !already.contains_key(&s.id))
        // Every segment on this LSM is already allocated: the op restates one.
        .or_else(|| {
            if on_lsm.is_empty() {
                None
            } else {
                on_lsm.first()
            }
        })
        .map(|s| (s.id.clone(), s.size))
}

/// Resolves the bytes a `WriteRelMem` streams from its `AppliesTo` hint. `full`
/// (or unset) streams the current relative segment's code `<Data>`; `par`
/// streams the computed parameter image for that segment; the combined
/// `full,par` (the real MDT / Jung shape, one write covering the whole segment)
/// streams the parameter image when parameters target the segment, else the
/// code `<Data>` — either way the segment's own bytes, so a following
/// `LoadImageProp` MCB check runs over a real image.
fn resolve_write_image(
    app: &ApplicationProgram,
    applies_to: Option<&str>,
    current_segment: Option<&str>,
    param_images: &BTreeMap<String, Vec<u8>>,
) -> std::result::Result<(String, ImageKind, Vec<u8>), String> {
    let seg_id = current_segment
        .map(str::to_string)
        .or_else(|| {
            // No allocation preceded this write: fall back to the first relative
            // segment that has data or a parameter image.
            let mut segs: Vec<_> = app
                .code_segments
                .values()
                .filter(|s| s.kind == SegmentKind::Relative)
                .collect();
            segs.sort_by(|a, b| a.id.cmp(&b.id));
            segs.first().map(|s| s.id.clone())
        })
        .ok_or_else(|| "no relative segment to write into".to_string())?;

    let wants_params = applies_to
        .map(|a| a.split(',').any(|t| t.trim().eq_ignore_ascii_case("par")))
        .unwrap_or(false);

    // A segment that any parameter targets has a computed parameter image, and
    // that image already *is* the segment's full content: `compute_parameter_image`
    // seeds it from the segment's `<Data>` base and lays the parameter values over
    // it. So whenever a non-empty parameter image exists for this segment, stream
    // it — even for an `AppliesTo="full"` or attribute-less `WriteRelMem`.
    //
    // Evidence (KNX Virtual DA.tp, M-00FA_A-2500-10-51CB): the app-segment write is
    // `<LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="256">` with NO `AppliesTo`,
    // yet ETS writes the *computed* parameter image (`05 05 ff … 05 04 …`), not the
    // raw 256×0xFF `<Data>` base. Resolving the code `<Data>` here would stream the
    // all-0xFF base and the load would be content-incomplete (the device discards
    // it on restart). A segment that no parameter targets has no `param_images`
    // entry, so a pure code segment still streams its `<Data>` below — this only
    // changes parameter-bearing segments.
    if let Some(bytes) = param_images.get(&seg_id).filter(|b| !b.is_empty()) {
        return Ok((seg_id, ImageKind::Parameters, bytes.clone()));
    }

    if wants_params {
        // The write wanted parameters but this segment carries none: a combined
        // `full,par` write (or a pure `par` write with no params) still owns the
        // segment's code `<Data>`. Fall back to that so the streamed image is never
        // spuriously empty.
        if let Some(data) = app.code_segments.get(&seg_id).and_then(|s| s.data.clone()) {
            return Ok((seg_id, ImageKind::Code, data));
        }
        return Ok((seg_id, ImageKind::Parameters, Vec::new()));
    }

    // Code image: the segment's `<Data>`.
    let bytes = app
        .code_segments
        .get(&seg_id)
        .and_then(|s| s.data.clone())
        .ok_or_else(|| format!("segment {seg_id} carries no code image (<Data>)"))?;
    Ok((seg_id, ImageKind::Code, bytes))
}

/// Resolves an absolute segment's bytes for a `WriteMem` op by matching its
/// declared address to `address`.
fn resolve_abs_image(
    app: &ApplicationProgram,
    address: Option<u32>,
) -> std::result::Result<(String, Vec<u8>), String> {
    let addr = address.ok_or_else(|| "LdCtrlWriteMem has no Address".to_string())?;
    let mut segs: Vec<_> = app
        .code_segments
        .values()
        .filter(|s| s.kind == SegmentKind::Absolute)
        .collect();
    segs.sort_by(|a, b| a.id.cmp(&b.id));
    let seg = segs
        .into_iter()
        .find(|s| s.address_or_offset == Some(addr))
        .ok_or_else(|| format!("no absolute segment declares address {addr:#010X}"))?;
    let data = seg
        .data
        .clone()
        .ok_or_else(|| format!("absolute segment {} carries no <Data>", seg.id))?;
    Ok((seg.id.clone(), data))
}

/// Discovers the application-program interface object's index by probing
/// `PID_OBJECT_TYPE` (as [`crate::apply::discover_table_objects`] does for the
/// table objects). All `lsm`-bearing ops resolve to this single object on a
/// single-application System B device.
///
/// Returns just the index for callers that need it; [`flash`] uses
/// [`discover_object_table`] instead so it can fold the whole discovered table
/// into a load-state error for diagnosis.
pub async fn discover_application_object<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<u8, WriteError> {
    let (index, _table) = discover_object_table(l4).await?;
    Ok(index)
}

/// Discovers the application-program object index **and** the full interface-object
/// table (`index → object type`), probing `PID_OBJECT_TYPE` from index 0 until the
/// first empty read. The table is used to enrich a load-state error so a failure
/// names not just "object N" but what every discovered object is.
async fn discover_object_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<(u8, Vec<(u8, u16)>), WriteError> {
    let table = probe_object_types(l4).await?;
    match table
        .iter()
        .find(|(_, ot)| *ot == OT_APPLICATION_PROGRAM)
        .map(|(index, _)| *index)
    {
        Some(index) => Ok((index, table)),
        None => Err(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: l4.target(),
                reason: "device is missing the application-program interface object".to_string(),
            },
        )),
    }
}

/// Walks `PID_OBJECT_TYPE` from index 0 and returns the `(index, object type)`
/// table the device exposes, in this crate's error type.
///
/// The walk itself is [`bussard_mgmt::probe_object_types`] — the crate-wide
/// interface-object discovery the table read side and `apply` use too, so all of
/// them see the same device picture. Its tolerance at the end of the object list
/// (an off-service, undecodable, empty or short answer means "no object here")
/// came from this walk: it is what lets it run against real devices, KNX Virtual
/// and the thelsing demo included, whose answer for an out-of-range object index
/// is not uniform.
pub(crate) async fn probe_object_types<Ch: bussard_mgmt::L4Channel>(
    l4: &mut bussard_mgmt::Layer4Connection<Ch>,
) -> Result<Vec<(u8, u16)>, WriteError> {
    Ok(bussard_mgmt::probe_object_types(l4).await?)
}

/// Discovers the object table like [`discover_object_table`], but **resumable at
/// probe granularity** over the session so it survives a connection death mid-walk.
///
/// It probes `PID_OBJECT_TYPE` at each interface-object index in turn; on an
/// unexpected connection death it reconnects and continues from the next
/// unprobed index (object types are stable device state, so the indices already
/// read stay valid). This matters on a device whose per-connection exchange budget
/// is smaller than the number of objects: a single-shot discovery could never
/// finish in one window, but accumulating one probe of forward progress per window
/// does. Bounded by [`MAX_RESUME_RECONNECTS`] *reconnects without any new probe*, so
/// a device that answers nothing still fails cleanly; every successful probe resets
/// the bound.
async fn discover_object_table_resumable<C: Connector>(
    session: &mut Session<C>,
) -> Result<(u8, Vec<(u8, u16)>), WriteError> {
    let mut table: Vec<(u8, u16)> = Vec::new();
    let mut app_obj: Option<u8> = None;
    let mut index: u8 = 0;
    let mut stalled_reconnects = 0u32;
    while index < bussard_mgmt::MAX_OBJECT_INDEX {
        // One index at a time through the shared, tolerant probe, so the resumable
        // walk and the one-shot `probe_object_types` terminate identically.
        match bussard_mgmt::probe_object_type(session.l4(), index)
            .await
            .map_err(WriteError::Mgmt)
        {
            Ok(None) => break,
            Ok(Some(ot)) => {
                stalled_reconnects = 0;
                table.push((index, ot));
                if ot == OT_APPLICATION_PROGRAM && app_obj.is_none() {
                    app_obj = Some(index);
                }
                index += 1;
            }
            // Unexpected connection death mid-walk: reconnect and RETRY this same
            // index (no progress was made on it). Bounded by consecutive stalls so a
            // genuinely dead device fails cleanly.
            Err(e)
                if resumable_death(&e, session) && stalled_reconnects < MAX_RESUME_RECONNECTS =>
            {
                stalled_reconnects += 1;
                session.reconnect().await?;
            }
            Err(e) => return Err(e),
        }
    }
    let target = session.l4().target();
    match app_obj {
        Some(index) => Ok((index, table)),
        None => Err(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: target,
                reason: "device is missing the application-program interface object".to_string(),
            },
        )),
    }
}

/// Re-confirms the application-program object index on a fresh post-restart
/// connection with a **single** `PID_OBJECT_TYPE` probe.
///
/// The interface-object table is device state that survives a reboot, so the
/// index discovered before the terminal restart is still the right one; the only
/// thing worth checking is that the device really is back and still reports that
/// index as an application-program object. A probe that answers anything else —
/// a different type, no object, or a read error — means the picture is not what
/// was assumed, so the full resumable walk runs and decides (it also reconnects
/// if the probe killed the connection).
async fn confirm_app_object<C: Connector>(
    session: &mut Session<C>,
    app_obj: u8,
) -> Result<u8, WriteError> {
    match bussard_mgmt::probe_object_type(session.l4(), app_obj).await {
        Ok(Some(OT_APPLICATION_PROGRAM)) => Ok(app_obj),
        _ => discover_object_table_resumable(session)
            .await
            .map(|(index, _table)| index),
    }
}

/// Resolves the op-carried `LsmIdx`/`ObjIdx` to the device interface-object index
/// the step should act on, by **index**, not by object type — the divergence-#2 fix.
///
/// On KNX Virtual the load procedure's `LsmIdx`/`ObjIdx` **are** device object
/// indices (the app segment is `ObjIdx=4` → device object 4 → base `0x6000`,
/// while the object of *type* application-program is index 3 → base `0x8000`). So
/// a valid, non-zero `target` that names an object the device actually exposes is
/// used literally.
///
/// It falls back to the discovered application-program object (`app_obj`) when the
/// op carried no index, named index 0 (the device object — the conformant
/// thelsing `WriteRelMem ObjIdx="0"` shape, which means "the app object" not "the
/// device object"), or named an index beyond the discovered object table (e.g. a
/// `LsmIdx=4` on a device whose app object sits at index 3 and that has no object
/// 4). This keeps a simple single-segment ProductDefault procedure targeting the
/// one app object exactly as before.
/// Resolves an op's `LsmIdx`/`ObjIdx` to a device object index, returning `None`
/// only when the step should be **skipped**.
///
/// `spliced` selects the two behaviours for an explicit, non-zero index the
/// device does not expose:
///
/// - `spliced = true` (a master-template multi-object download): return `None`
///   so the executor skips it. The `Load/all` template carries load-control ops
///   for LSM5 (the PEI program) that a device without an obj5 does not have;
///   redirecting those onto the app object would spuriously Unload / StartLoading
///   / LoadCompleted it out of sequence.
/// - `spliced = false` (a self-contained single-object procedure): fall back to
///   the discovered app object — the conformant thelsing shape, whose `LsmIdx=4`
///   ops address the app object even on a device whose app object sits at a
///   lower index and has no object 4.
///
/// A `None`/`0` target always resolves to the app object (the thelsing
/// `ObjIdx="0"` shape means "the app object", not "device object 0").
fn resolve_object_target_opt(
    target: Option<u32>,
    object_table: &[(u8, u16)],
    app_obj: u8,
    spliced: bool,
) -> Option<u8> {
    match target {
        Some(idx) if idx != 0 && idx <= u32::from(u8::MAX) => {
            let idx = idx as u8;
            if object_table.iter().any(|(i, _)| *i == idx) {
                Some(idx)
            } else if spliced {
                None
            } else {
                Some(app_obj)
            }
        }
        // None / 0: the app object (the conformant single-object shape).
        _ => Some(app_obj),
    }
}

/// The device object index whose re-load a step belongs to, for the MCB-skip
/// gate (issue #73 item 2) — or `None` if the step is not part of a per-object
/// re-load that a resident-MCB match may skip.
///
/// Only the load-state and segment-write steps of a single object are skippable:
/// `Unload`/`StartLoading`/`AllocateSegment`/`WriteRelMem`/`LoadCompleted`. The
/// `LoadImageProp` verify is deliberately excluded (it is a read-only confirm
/// that must still run against the skipped object's resident MCB), as is every
/// non-per-object step (`WriteMem`, `CompareProp`, `Restart`, `MasterReset`, all
/// System 7 steps). Resolution uses the same index rules as execution.
fn mcb_skip_target(
    step: &FlashStep,
    object_table: &[(u8, u16)],
    app_obj: u8,
    plan: &FlashPlan,
) -> Option<u8> {
    let target = match step {
        FlashStep::Unload { target }
        | FlashStep::StartLoading { target }
        | FlashStep::AllocateSegment { target, .. }
        | FlashStep::LoadCompleted { target } => *target,
        FlashStep::WriteRelMem { target, .. } => *target,
        _ => return None,
    };
    resolve_object_target_opt(target, object_table, app_obj, plan.spliced_from_template)
}

/// The single whole-segment image a `WriteRelMem` streams into `obj`, if the
/// object has exactly one such write and it starts at offset 0.
///
/// The MCB CRC the device reports covers the whole stored segment, so a skip is
/// only sound when a single write covers that segment from its base. An object
/// with several writes (e.g. a `full` then a `par` write at different offsets),
/// or a write at a non-zero offset, is treated as *uncertain* and never skipped
/// — the conservative choice the issue mandates ("never skip a write on an
/// uncertain match"). Returns the streamed bytes, or `None` when no single
/// offset-0 write resolves onto `obj`. Resolution uses the same object-index
/// rules as execution, so `obj` must be the executor-resolved index.
fn sole_object_image<'a>(
    plan: &'a FlashPlan,
    obj: u8,
    app_obj: u8,
    object_table: &[(u8, u16)],
) -> Option<&'a [u8]> {
    let mut found: Option<&str> = None;
    for step in &plan.steps {
        if let FlashStep::WriteRelMem {
            offset,
            image,
            target,
        } = step
        {
            let resolved = resolve_object_target_opt(
                *target,
                object_table,
                app_obj,
                plan.spliced_from_template,
            );
            if resolved != Some(obj) {
                continue;
            }
            if *offset != 0 || found.is_some() {
                // A non-zero-offset write, or a second write into this object:
                // uncertain, so never skip it.
                return None;
            }
            found = Some(&image.segment_id);
        }
    }
    let segment_id = found?;
    plan.images.get(segment_id).map(|v| v.as_slice())
}

/// Reads each to-be-written object's resident `PID_MCB_TABLE` and returns the
/// set of object indices whose resident image already matches what bussard would
/// stream — the objects whose re-load the executor may skip (issue #73 item 2).
///
/// For every object that a single offset-0 `WriteRelMem` would fill (see
/// [`sole_object_image`]), this reads the object's MCB *before* any step touches
/// it. A match requires the device to report an entry whose `segment_size`
/// equals the image length AND whose `crc16` equals the CRC over the image
/// bytes. A device that answers no MCB entry (a fresh/blank object), a differing
/// size, or a differing CRC is NOT added — that object full-streams. Any read
/// error is treated as "cannot confirm a match" and the object full-streams,
/// so an unreadable MCB never causes a needed write to be skipped.
async fn resident_match_objects<C: Connector>(
    session: &mut Session<C>,
    plan: &FlashPlan,
    app_obj: u8,
    object_table: &[(u8, u16)],
) -> Result<BTreeSet<u8>, WriteError> {
    // The candidate objects: those the executor would resolve a WriteRelMem onto.
    let mut candidates: BTreeSet<u8> = BTreeSet::new();
    for step in &plan.steps {
        if let FlashStep::WriteRelMem { target, .. } = step {
            if let Some(obj) = resolve_object_target_opt(
                *target,
                object_table,
                app_obj,
                plan.spliced_from_template,
            ) {
                candidates.insert(obj);
            }
        }
    }

    let mut matches = BTreeSet::new();
    for obj in candidates {
        let Some(image) = sole_object_image(plan, obj, app_obj, object_table) else {
            // Several writes / a non-zero offset: uncertain, never skip.
            continue;
        };
        // Read the resident MCB WITHOUT asserting (expected = None), so a
        // mismatch is a value to compare, not an error. Any read failure means
        // we cannot confirm a match — leave the object out (it full-streams).
        let entries = match read_mcb_table(session.l4(), obj, 0, 1, None).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        let Some(entry) = entries.first() else {
            continue;
        };
        let want_size = image.len() as u32;
        let want_crc = bussard_mgmt::crc16_ccitt(image);
        if entry.segment_size != want_size || entry.crc16 != want_crc {
            continue;
        }
        // A matching MCB alone is not enough: an object left `Unloaded`,
        // `Loading` or `Error` (an interrupted flash, an app-unload) can still
        // describe an intact segment, but skipping its re-load would skip the
        // `StartLoading`/`LoadCompleted` that bring it back to `Loaded`. Only an
        // object that reports `Loaded` right now is skipped; an unreadable state
        // full-streams, like an unreadable MCB.
        if matches!(
            read_load_state(session.l4(), obj).await,
            Ok(LoadState::Loaded)
        ) {
            matches.insert(obj);
        }
    }
    Ok(matches)
}

/// Drives a `StartLoading` on the application object, enriching a non-conformant
/// load-state failure with discovery context.
///
/// A conformant device lands in `Loading`; [`write_load_control`] confirms that.
/// Load-state handling is strict: a device that does not report `Loading` (e.g.
/// reports `Loaded` instead) fails with [`WriteError::UnexpectedLoadState`], now
/// carrying the targeted object's discovered type and the full discovered object
/// table so the failure is actionable rather than a bare "object N did not reach
/// Loading". This strictness is intentional — it catches a device that cannot
/// hold this application before its memory is overrun.
async fn start_loading<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    object_table: &[(u8, u16)],
) -> Result<(), WriteError> {
    match write_load_control(l4, app_obj, LoadControl::StartLoading).await {
        Ok(_) => Ok(()),
        Err(WriteError::UnexpectedLoadState {
            address,
            object_index,
            control,
            expected,
            actual,
            ..
        }) => {
            // Re-emit with the discovered object context folded in.
            let context = bussard_mgmt::LoadStateContext {
                object_type: object_table
                    .iter()
                    .find(|(idx, _)| *idx == object_index)
                    .map(|(_, ot)| *ot),
                object_table: object_table.to_vec(),
            };
            Err(WriteError::UnexpectedLoadState {
                address,
                object_index,
                control,
                expected,
                actual,
                context,
            })
        }
        Err(other) => Err(other),
    }
}

/// Allocates a relative segment, enriching a non-conformant load-state failure
/// with the discovered object context — like [`start_loading`].
///
/// [`allocate_segment`] raises [`WriteError::UnexpectedLoadState`] with an empty
/// context when the object is not `Loading` (its precondition, or the re-read
/// after the `AdditionalLoadControls` write) — a device that did not honour the
/// segment allocation (e.g. it reports `Loaded`, meaning it lacks memory for this
/// application). This folds the targeted object's discovered interface-object type
/// and the full discovered object table into any such failure so it is actionable.
///
/// `fill` mirrors the source `LdCtrlRelSegment`'s fill (`Mode`/`Fill`): `None` (the
/// DA.tp default) asks for a no-fill allocation, byte-identical to before;
/// `Some(b)` requests the device pre-fill the segment with `b`.
async fn allocate_with_context<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    size: u32,
    fill: Option<u8>,
    object_table: &[(u8, u16)],
) -> Result<bussard_mgmt::SegmentAllocation, WriteError> {
    match allocate_segment(l4, app_obj, size, fill).await {
        Err(WriteError::UnexpectedLoadState {
            address,
            object_index,
            control,
            expected,
            actual,
            ..
        }) => {
            let context = bussard_mgmt::LoadStateContext {
                object_type: object_table
                    .iter()
                    .find(|(idx, _)| *idx == object_index)
                    .map(|(_, ot)| *ot),
                object_table: object_table.to_vec(),
            };
            Err(WriteError::UnexpectedLoadState {
                address,
                object_index,
                control,
                expected,
                actual,
                context,
            })
        }
        other => other,
    }
}

/// Retries a resumable flash primitive over the session across an *unexpected*
/// connection death, reconnecting and re-running it.
///
/// This is a `macro_rules!` (not a generic higher-order fn) because the retried
/// primitives borrow `session.l4()` for the duration of their future, a lifetime a
/// single closure type cannot express without boxing. It expands to a bounded
/// reconnect loop around the given expression, which it re-evaluates after each
/// reconnect — so the primitive must be idempotent (load state and allocated
/// segments are persistent device state, so re-issuing StartLoading / allocate /
/// LoadCompleted / a state read is safe). Bounded by [`MAX_RESUME_RECONNECTS`]
/// consecutive reconnects; each success is forward progress. A session that cannot
/// reconnect surfaces the death unchanged (the mock single-connection path).
///
/// Making each *primitive* resumable — rather than only whole steps — is what lets
/// a flash survive a per-connection exchange budget *smaller than a single step's
/// exchange count*: the step's constituent writes/reads each make forward progress
/// across windows, where a whole-step replay would straddle the same budget
/// boundary forever.
macro_rules! resume {
    ($session:expr, $op:expr) => {{
        let mut reconnects = 0u32;
        loop {
            match $op {
                Ok(value) => break Ok(value),
                Err(e) if resumable_death(&e, $session) && reconnects < MAX_RESUME_RECONNECTS => {
                    reconnects += 1;
                    $session.reconnect().await?;
                }
                Err(e) => break Err(e),
            }
        }
    }};
}

/// Session-aware, resume-on-drop [`write_load_control`].
async fn write_load_control_resumable<C: Connector>(
    session: &mut Session<C>,
    obj: u8,
    control: LoadControl,
) -> Result<LoadState, WriteError> {
    resume!(
        session,
        write_load_control(session.l4(), obj, control).await
    )
}

/// Session-aware, resume-on-drop [`start_loading`].
async fn start_loading_resumable<C: Connector>(
    session: &mut Session<C>,
    obj: u8,
    object_table: &[(u8, u16)],
) -> Result<(), WriteError> {
    resume!(
        session,
        start_loading(session.l4(), obj, object_table).await
    )
}

/// Session-aware, resume-on-drop [`allocate_with_context`].
async fn allocate_with_context_resumable<C: Connector>(
    session: &mut Session<C>,
    obj: u8,
    size: u32,
    fill: Option<u8>,
    object_table: &[(u8, u16)],
) -> Result<bussard_mgmt::SegmentAllocation, WriteError> {
    resume!(
        session,
        allocate_with_context(session.l4(), obj, size, fill, object_table).await
    )
}

/// Whether an error from a resumable flash operation is an *unexpected* connection
/// death this session can recover from by reconnecting: a connection-death (see
/// [`is_connection_death`]) on a session that [`can_reconnect`](Session::can_reconnect).
///
/// This is the shared predicate behind resume-on-drop: the initial discovery probe,
/// each plan step, and the final verify each retry on it (bounded by
/// [`MAX_RESUME_RECONNECTS`]). It is a free function rather than a generic
/// retry-a-closure helper because the retried operations borrow the session's
/// connection mutably for the duration of their future, which a single closure type
/// cannot express without boxing; each call site owns its own small retry loop
/// instead.
fn resumable_death<C: Connector>(err: &WriteError, session: &Session<C>) -> bool {
    is_connection_death(err) && session.can_reconnect()
}

/// Executes a validated [`FlashPlan`] against the device over the session's
/// connection, reporting progress through `progress`, then verifies the result.
///
/// The application-program object index is discovered live; the plan's steps run
/// in order, streaming the plan's resolved images into device memory (chunked by
/// [`write_memory`], which does not read each chunk back — see the module docs).
/// After the sequence, the object's
/// load state is re-read and a sample of each written segment is read back for a
/// spot check. Returns the [`FlashOutcome`]; the caller treats `!ok()` as a hard
/// failure. Any op error surfaces immediately with the failing primitive.
///
/// This is the only function here that mutates the device, and only ever runs
/// from `bussard flash` after the plan is shown, confirmed, and the factory-fresh
/// assumption stated.
pub async fn flash<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    plan: &FlashPlan,
    options: FlashOptions,
    mut progress: F,
) -> Result<FlashOutcome, WriteError> {
    // System 7 has its own memory-mapped, absolute-addressed executor: the LSM
    // control, absolute streaming and read-back verify all differ from System B.
    if plan.sys7.is_some() {
        return flash_sys7(session, plan, options, progress).await;
    }
    // `options.bcu_key` was consumed at connect time (the session was opened with
    // it); only `verify_after_restart` is read below, in the terminal-restart arm.
    let verify_after_restart = options.verify_after_restart;
    // The initial object-type discovery is itself several numbered exchanges — more
    // than a very tight per-connection budget allows in one window — so on such a
    // device the drop lands here, before the first step. Discovery resumes at
    // **probe granularity**: it walks object indices, and on a connection death it
    // reconnects and CONTINUES from the next index, keeping the indices already
    // probed. Whole-operation replay alone could not recover a discovery that needs
    // more exchanges than the budget; per-probe forward progress can.
    //
    // A session opened with [`DeviceFacts`] (the CLI: its read-only pre-flight
    // already walked `PID_OBJECT_TYPE` over every object) skips the walk entirely
    // — the table is device-stable, so re-reading it would only repeat one
    // `A_PropertyValue_Read` per interface object. Without facts (the library
    // API, every mock and oracle test) the walk runs exactly as before.
    let (app_obj, object_table) = match session.known_object_table() {
        Some(known) => known,
        None => discover_object_table_resumable(session).await?,
    };
    let total = plan.steps.len();

    // The base address of the most-recently allocated relative segment, used by
    // the following `WriteRelMem` when it does not resolve a per-object base.
    let mut segment_base: Option<u32> = None;
    // Per-object segment base addresses, keyed by device object index, filled as
    // each `AllocateSegment` returns the object's `PID_TABLE_REFERENCE` base.
    // The master-template sequence allocates every object (obj4/obj3/obj1/obj2)
    // BEFORE writing any of them, so a single `segment_base` would be clobbered;
    // each `WriteRelMem` looks its own object's base up here. Matches ETS reading
    // PID7 per object before its write.
    let mut segment_bases: BTreeMap<u8, u32> = BTreeMap::new();
    // The set of object indices that received a `LoadCompleted`, in order, so the
    // post-flash verify checks every programmed object reached `Loaded` — not
    // only the app object (the verify_outcome bug fix).
    let mut completed_objects: Vec<u8> = Vec::new();
    // The size of the most-recently allocated relative segment, remembered so a
    // `MasterReset` step (which reboots the device and, on KNX Virtual, wipes the
    // app object's load state back to `Unloaded` and drops the segment allocated
    // before it) can re-open the object and re-allocate the same-sized segment on
    // the fresh connection — updating `segment_base` to the freshly-returned
    // address — before the resumed `WriteRelMem` targets it. `None` until the
    // first `AllocateSegment`.
    let mut last_alloc_size: Option<u32> = None;
    // The pre-fill (`Mode`/`Fill`) the most-recent `AllocateSegment`
    // requested, so a `MasterReset` re-allocation reproduces the same fill flag
    // as the original op rather than silently dropping it. `None` = no-fill (the
    // DA.tp default).
    let mut last_alloc_fill: Option<u8> = None;
    // The pre-fill each object's segment was allocated with, so its
    // `WriteRelMem` streams only what differs from the fill (issue #123).
    let mut segment_fills: BTreeMap<u8, Option<u8>> = BTreeMap::new();
    // The object index the most-recent `AllocateSegment` targeted, so a
    // `MasterReset` re-opens and re-allocates *that* object (the one whose segment
    // the reset dropped) rather than the type-discovered application object. On
    // KNX Virtual DA.tp the app segment is obj4 (allocated right before the reset)
    // while the type-discovered app object is obj3 — re-opening obj3 here would
    // double-`StartLoading` it (the template re-opens obj3 itself after the reset)
    // and drive it to `Error`. `None` until the first `AllocateSegment`.
    let mut last_alloc_target: Option<u8> = None;
    // Track (address, sample_len) of writes for the post-flash spot check. The
    // address is 24-bit: an extended-memory segment (07B0 actuators) lives above
    // 0xFFFF, and the spot-check read picks plain vs extended from it.
    let mut written_samples: Vec<(u32, Vec<u8>)> = Vec::new();
    // The verified outcome, captured just before a terminal restart reboots the
    // device (after which it is unreachable and cannot be verified). `None` until
    // then; the post-loop verify runs only if it is still `None`.
    let mut verified: Option<FlashOutcome> = None;

    // The proactive-reconnect exchange threshold (0 = disabled), read once.
    let reconnect_threshold = reconnect_exchange_threshold();

    // Item 2 (issue #73): the MCB-CRC re-download skip. When enabled, read each
    // to-be-written object's resident `PID_MCB_TABLE` *before* any step touches
    // it and, on a size+CRC match against the image bussard would stream, mark
    // that object skippable. The skip drops the object's re-load steps (so no
    // body bytes stream and the intact resident load is left untouched) but is
    // NEVER taken on a fresh/blank device (no MCB entry) or a size/CRC mismatch —
    // those full-stream exactly as before. Disabled by default, so DA.tp and
    // every mock path are byte-identical.
    //
    // A plan that factory-resets the device first erases every object, so no
    // resident image can survive to be matched: the pre-pass is skipped and every
    // object streams in full.
    let skip_objects: BTreeSet<u8> = if options.skip_matching_mcb && !plan.has_factory_reset() {
        resident_match_objects(session, plan, app_obj, &object_table).await?
    } else {
        BTreeSet::new()
    };

    for (i, step) in plan.steps.iter().enumerate() {
        // A resident-match object (its MCB already matched the image bussard
        // would stream) skips its whole re-load: the `Unload`/`StartLoading`/
        // `AllocateSegment`/`WriteRelMem`/`LoadCompleted` for it are dropped so
        // the intact resident load is untouched and ZERO body bytes stream
        // (matching ETS's group-B captures). Its `LoadImageProp` MCB re-verify is
        // kept (a read-only confirm that passes by construction). The object is
        // still recorded as completed so the post-flash verify covers it.
        if let Some(skip_obj) = mcb_skip_target(step, &object_table, app_obj, plan) {
            if skip_objects.contains(&skip_obj) {
                if let FlashStep::LoadCompleted { .. } = step {
                    if !completed_objects.contains(&skip_obj) {
                        completed_objects.push(skip_obj);
                    }
                }
                progress(Progress::Step {
                    index: i + 1,
                    total,
                    label: format!(
                        "skip {} (unchanged: resident MCB size+CRC match the image, object Loaded)",
                        step_label(step)
                    ),
                });
                continue;
            }
        }
        // Proactive periodic L4 reconnection (the ETS pattern): before starting a
        // step, if this connection's numbered-exchange count has reached the
        // threshold, cycle the connection (graceful T_Disconnect / T_Connect +
        // re-authorize) so it never approaches the device's per-connection budget
        // (~35 on KNX Virtual). The objects' load states and their allocated
        // segments are persistent device state, not connection state, so they
        // survive the cycle and the step resumes on a fresh, zero-exchange
        // connection. The check is *between* steps — never mid memory-write — so a
        // chunked write is never split across a reconnect.
        //
        // Steps that reboot the device and re-establish the connection themselves
        // (`MasterReset`, terminal `Restart`) are skipped here: cycling right
        // before them would be a wasted reconnect (they drop and re-open the
        // connection anyway). A single-connection session (mocks,
        // `from_connection`) cannot reconnect, so it keeps the one-connection path.
        let self_reconnecting_step = matches!(
            step,
            FlashStep::MasterReset { .. } | FlashStep::Restart | FlashStep::FactoryReset { .. }
        );
        if reconnect_threshold > 0
            && session.can_reconnect()
            && !self_reconnecting_step
            && session.numbered_exchanges() >= reconnect_threshold
        {
            session.cycle_l4().await?;
        }
        progress(Progress::Step {
            index: i + 1,
            total,
            label: plan.step_label(step),
        });

        // Resume-on-drop: run the step, and if it dies from an *unexpected* mid-flow
        // connection death (the device dropped the L4 connection at a
        // non-deterministic exchange count — see [`is_connection_death`]) and the
        // session can reconnect, cycle the L4 connection and re-run the whole step.
        // Load state and allocated segments are persistent device state that survive
        // the drop, so re-running the step on the fresh connection is safe: memory
        // writes are absolute/relative-addressed, and a re-issued StartLoading /
        // allocate on an already-open object lands in the same state. Bounded by
        // [`MAX_RESUME_RECONNECTS`] per step so a genuinely dead device that never
        // makes progress fails cleanly instead of looping forever; any step that
        // completes starts the next with a full budget (forward progress resets it).
        //
        // `MasterReset` and the terminal `Restart` reboot the device and reconnect
        // themselves, so they are excluded from resume-on-drop — their own silence
        // is expected, not a death to recover from.
        let mut resume_reconnects = 0u32;
        'resume: loop {
            let step_result: Result<(), WriteError> = async {
                match step {
                    FlashStep::Unload { target } => {
                        // Skip a load-control op that names an object index the device
                        // does not expose (a template LSM5 op on a device without obj5).
                        let Some(obj) = resolve_object_target_opt(
                            *target,
                            &object_table,
                            app_obj,
                            plan.spliced_from_template,
                        ) else {
                            return Ok(());
                        };
                        write_load_control_resumable(session, obj, LoadControl::Unload).await?;
                    }
                    FlashStep::StartLoading { target } => {
                        let Some(obj) = resolve_object_target_opt(
                            *target,
                            &object_table,
                            app_obj,
                            plan.spliced_from_template,
                        ) else {
                            return Ok(());
                        };
                        start_loading_resumable(session, obj, &object_table).await?;
                    }
                    FlashStep::AllocateSegment { size, target, fill } => {
                        // Allocate against — and read PID7 (the per-object base) from — the
                        // object the op names by index. On KNX Virtual this is the ObjIdx
                        // (e.g. obj4 → base 0x6000); allocate_segment reads that object's
                        // PID_TABLE_REFERENCE, so the base the following WriteRelMem uses is
                        // this object's own. An index the device lacks is skipped.
                        let Some(obj) = resolve_object_target_opt(
                            *target,
                            &object_table,
                            app_obj,
                            plan.spliced_from_template,
                        ) else {
                            return Ok(());
                        };
                        let alloc = allocate_with_context_resumable(
                            session,
                            obj,
                            *size,
                            *fill,
                            &object_table,
                        )
                        .await?;
                        segment_base = Some(alloc.address);
                        segment_bases.insert(obj, alloc.address);
                        segment_fills.insert(obj, *fill);
                        last_alloc_size = Some(*size);
                        last_alloc_fill = *fill;
                        last_alloc_target = Some(obj);
                    }
                    FlashStep::WriteRelMem {
                        offset,
                        image,
                        target,
                    } => {
                        // Prefer this object's own allocated base (the multi-object
                        // template allocates every object before writing any, so the
                        // shared `segment_base` may belong to a later allocation). Fall
                        // back to the most-recent allocation for the single-object shape.
                        let obj = resolve_object_target_opt(
                            *target,
                            &object_table,
                            app_obj,
                            plan.spliced_from_template,
                        );
                        let base = obj
                            .and_then(|obj| segment_bases.get(&obj).copied())
                            .or(segment_base)
                            .unwrap_or(0);
                        // The fill the target segment was allocated with (the
                        // most-recent allocation's for the single-object shape).
                        let fill = match obj.and_then(|obj| segment_fills.get(&obj).copied()) {
                            Some(fill) => fill,
                            None => last_alloc_fill,
                        };
                        // The device-supplied segment base plus the vendor offset must fit
                        // the 24-bit extended-memory space. `write_image` picks the plain
                        // A_Memory_Write (≤0xFFFF, byte-identical to before) or the
                        // A_MemoryExtended_Write service from the resolved address, so a
                        // base above 0xFFFF (the Jung/ABB 07B0 actuators) streams via the
                        // extended service instead of being refused.
                        let addr = base
                            .checked_add(*offset)
                            .filter(|&a| a <= bussard_mgmt::apci::MAX_MEMORY_ADDRESS)
                            .ok_or_else(|| WriteError::AddressOutOfRange {
                                address: session.l4().target(),
                                detail: format!("segment base {base:#X} + offset {offset:#X}"),
                            })?;
                        let bytes = plan
                            .images
                            .get(&image.segment_id)
                            .cloned()
                            .unwrap_or_default();
                        match fill {
                            // A pre-filled segment already holds the fill byte
                            // everywhere: write only the runs that differ, as ETS
                            // does (the F50 obj4 image is 276 of 6152 octets).
                            Some(fill) => {
                                for (start, run) in fill_regions(&bytes, fill) {
                                    write_image(session, addr + start as u32, run, &mut progress)
                                        .await?;
                                }
                            }
                            None => write_image(session, addr, &bytes, &mut progress).await?,
                        }
                        if let Some(sample) = bytes.first().map(|_| take_sample(&bytes)) {
                            written_samples.push((addr, sample));
                        }
                    }
                    FlashStep::WriteMem { address, image } => {
                        // The absolute address must fit the 24-bit extended-memory space;
                        // `write_image` picks plain vs extended from the address (≤0xFFFF
                        // stays byte-identical to the historical plain path).
                        let addr = *address;
                        if addr > bussard_mgmt::apci::MAX_MEMORY_ADDRESS {
                            return Err(WriteError::AddressOutOfRange {
                                address: session.l4().target(),
                                detail: format!("absolute address {address:#X}"),
                            });
                        }
                        let bytes = plan
                            .images
                            .get(&image.segment_id)
                            .cloned()
                            .unwrap_or_default();
                        write_image(session, addr, &bytes, &mut progress).await?;
                        if !bytes.is_empty() {
                            written_samples.push((addr, take_sample(&bytes)));
                        }
                    }
                    FlashStep::WriteProp {
                        obj_idx,
                        obj_type,
                        prop_id,
                        value,
                        start_element,
                    } => {
                        // A spliced template writes properties on obj4 and obj5 (the app
                        // id, PID 13). Skip a write to an object index the device does not
                        // expose (obj5 on a device without a PEI program), exactly like
                        // the load-control steps — otherwise the device NAKs the write to
                        // the absent object and fails the flash. A `u32::MAX`-bounded index
                        // is compared against the discovered table.
                        let _ = obj_type;
                        if plan.spliced_from_template
                            && !object_table.iter().any(|(i, _)| u32::from(*i) == *obj_idx)
                        {
                            return Ok(());
                        }
                        let obj = (*obj_idx).min(u32::from(u8::MAX)) as u8;
                        let pid = (*prop_id).min(u32::from(u8::MAX)) as u8;
                        // PID_MCB_TABLE is an array of 8-octet entries and the vendor
                        // InlineData is padded to 10: ETS writes one 8-octet element per
                        // request from `StartElement` (1.1.18 capture: `count=1 index=1
                        // len=8`, then `index=2`). The Jung F50 refuses the padded
                        // 10-octet write with a zero-count response (issue #89).
                        if pid == bussard_mgmt::PID_MCB_TABLE
                            && value.len() > bussard_mgmt::MCB_ENTRY_LEN
                        {
                            for (i, entry) in value.chunks(bussard_mgmt::MCB_ENTRY_LEN).enumerate()
                            {
                                if entry.len() < bussard_mgmt::MCB_ENTRY_LEN {
                                    break; // the vendor's zero padding, never an entry
                                }
                                let index = start_element.saturating_add(i as u16);
                                write_property(session.l4(), obj, pid, 1, index, entry, None)
                                    .await?;
                            }
                        } else {
                            write_property(session.l4(), obj, pid, 1, *start_element, value, None)
                                .await?;
                        }
                    }
                    FlashStep::CompareProp {
                        obj_idx,
                        prop_id,
                        expected,
                        mask,
                    } => {
                        // Read the named interface object's property and compare it
                        // against the vendor's expected data. A `Range`-only op has no
                        // literal expectation (`expected` is None) and is skipped. The op
                        // names the object by its own index (e.g. 0 = the device object),
                        // read directly — not the discovered app object.
                        if let Some(expected) = expected {
                            compare_property(
                                session.l4(),
                                (*obj_idx).min(u32::from(u8::MAX)) as u8,
                                (*prop_id).min(u32::from(u8::MAX)) as u8,
                                expected,
                                mask.as_deref(),
                            )
                            .await?;
                        }
                    }
                    FlashStep::CompareRelMem {
                        target,
                        offset,
                        expected,
                        mask,
                        invert,
                    } => {
                        // Read this object's relative memory and compare it against the
                        // vendor's expected data — the memory twin of CompareProp. An op
                        // with no literal expectation (`expected` is None) is skipped.
                        if let Some(expected) = expected {
                            // Resolve the object index the op names. A `spliced`
                            // template naming an index the device lacks is skipped
                            // (nothing to compare against).
                            let Some(obj) = resolve_object_target_opt(
                                *target,
                                &object_table,
                                app_obj,
                                plan.spliced_from_template,
                            ) else {
                                return Ok(());
                            };
                            // The read base is this object's segment address. Prefer the
                            // base allocated earlier in this procedure; otherwise read the
                            // object's PID_TABLE_REFERENCE fresh (a compare against an
                            // object this procedure did not itself allocate). The u32 base
                            // may exceed 0xFFFF (07B0 actuators); `compare_rel_mem` reads
                            // via the extended service in that case and refuses only if
                            // base + offset exceeds the 24-bit space.
                            let base = match segment_bases.get(&obj).copied().or(segment_base) {
                                Some(b) => b,
                                None => read_table_reference(session.l4(), obj).await?,
                            };
                            compare_rel_mem(
                                session.l4(),
                                obj,
                                base,
                                *offset,
                                expected,
                                mask.as_deref(),
                                *invert,
                            )
                            .await?;
                        }
                    }
                    FlashStep::LoadImageProp {
                        obj_idx,
                        prop_id,
                        count,
                        image,
                    } => {
                        // Read the loaded object's PID_MCB_TABLE and, where we wrote the
                        // object's image, validate the device's CRC over the stored
                        // segment against the bytes we streamed. The op names a vendor
                        // object index in the app's own numbering; the image bussard
                        // wrote lives on the single application-program object it
                        // discovered and loaded, so the MCB check targets `app_obj`.
                        // `read_mcb_table` compares the device's CRC16-CCITT to the CRC
                        // over `expected`; a mismatch surfaces `ImagePropMismatch`.
                        if *prop_id == u32::from(bussard_mgmt::PID_MCB_TABLE) {
                            let expected = image
                                .as_ref()
                                .and_then(|img| plan.images.get(&img.segment_id))
                                .map(Vec::as_slice);
                            // Read the MCB on the object that holds the checked
                            // segment. A *table* image (obj1/obj2/obj3) lives on its
                            // own table interface object, named by its own index. A
                            // code/parameter image is a segment of the one
                            // application-program object bussard discovered
                            // (`app_obj`) — including a single-segment procedure that
                            // names several object indices which all verify that one
                            // application image (the DA.tp / mock shape). Reading
                            // `app_obj` for every check (the previous behaviour) made
                            // each table-object check read the application segment's
                            // MCB, so the CRC never matched on a multi-object System B
                            // procedure (the MDT actuators).
                            let read_obj = match image.as_ref().map(|i| i.kind) {
                                Some(ImageKind::Table) => (*obj_idx).min(u32::from(u8::MAX)) as u8,
                                _ => app_obj,
                            };
                            read_mcb_table(
                                session.l4(),
                                read_obj,
                                1,
                                (*count).min(255) as u8,
                                expected,
                            )
                            .await?;
                        }
                    }
                    FlashStep::LoadCompleted { target } => {
                        // Skip a completion for an object the device does not expose (a
                        // template LSM5 completion on a device without obj5).
                        let Some(obj) = resolve_object_target_opt(
                            *target,
                            &object_table,
                            app_obj,
                            plan.spliced_from_template,
                        ) else {
                            return Ok(());
                        };
                        write_load_control_resumable(session, obj, LoadControl::LoadCompleted)
                            .await?;
                        if !completed_objects.contains(&obj) {
                            completed_objects.push(obj);
                        }
                    }
                    FlashStep::MasterReset {
                        erase_code,
                        channel_number,
                    } => {
                        // Send the master reset as a BARE A_Restart (0x380), exactly as
                        // ETS→KNX-Virtual does on the wire for an LdCtrlMasterReset — NOT
                        // the confirmed master-reset A_Restart (0x381 + erase/channel).
                        // The device T_ACKs it at the transport layer and then reboots,
                        // dropping the L4 connection — the SPEC-REQUIRED single reconnect:
                        // wait out the reboot, re-establish the connection and re-authorize.
                        master_reset_via_basic_restart(session.l4(), *erase_code, *channel_number)
                            .await?;
                        // Wait out the reboot with a bounded poll (not a fixed
                        // sleep) and re-establish the authorized connection.
                        session.reconnect_after_reboot().await?;

                        // The master reset ERASES the app object's load state (back to
                        // `Unloaded`) and drops the segment allocated before it (erase
                        // code 4, KNX Virtual). A resumed `WriteRelMem` would then target
                        // the now-stale pre-reset `segment_base` while the object is
                        // `Unloaded`, which the device rejects (it drops the connection
                        // after the first chunk). ETS re-runs the load-control sequence
                        // AFTER the reset before writing (real ETS→KV capture): re-open
                        // the object, then re-establish its segment and read back the
                        // (possibly relocated) base. Mirror that here so the resumed write
                        // targets valid, open memory:
                        //
                        //   1. If the object is not still open (reset wiped it to
                        //      `Unloaded`), re-open it with `StartLoading`. A lenient stack
                        //      that kept it open needs no re-open, so only drive
                        //      `StartLoading` when it actually fell out of the loading
                        //      state.
                        //   2. If a segment was allocated before the reset, re-allocate the
                        //      same size and UPDATE `segment_base` to the freshly-returned
                        //      address — the reset dropped the old placement, so the base
                        //      the following `WriteRelMem` uses must come from this fresh
                        //      allocation, not the stale pre-reset value.
                        //
                        // Re-open the object whose segment the reset dropped — the one the
                        // most-recent `AllocateSegment` targeted (`last_alloc_target`), not
                        // the type-discovered application object. On KNX Virtual DA.tp the
                        // reset sits right after obj4's allocate, so obj4 is what must be
                        // re-opened; the type-discovered app object is obj3, which the
                        // spliced template re-opens itself later — re-opening it here too
                        // would double-`StartLoading` it into `Error`. Fall back to
                        // `app_obj` for a self-contained procedure that allocated nothing
                        // through a distinct index.
                        let reset_obj = last_alloc_target.unwrap_or(app_obj);
                        // Re-establish the object on the fresh post-reboot connection,
                        // resume-on-drop at block granularity: this whole re-open +
                        // re-allocate is several exchanges and can itself outrun a tight
                        // per-connection budget, but the MasterReset step is excluded from
                        // the outer step-retry (it reconnects itself). Each sub-primitive is
                        // therefore individually resume-on-drop (per-primitive forward
                        // progress), so the re-establishment survives a budget smaller than
                        // its total exchange count. Re-reading the load state and re-issuing
                        // StartLoading / allocate are idempotent.
                        let state = read_load_state_resumable(session, reset_obj).await?;
                        if !matches!(state, LoadState::Loading | LoadState::Loaded) {
                            start_loading_resumable(session, reset_obj, &object_table).await?;
                        }
                        if let Some(size) = last_alloc_size {
                            let alloc = allocate_with_context_resumable(
                                session,
                                reset_obj,
                                size,
                                last_alloc_fill,
                                &object_table,
                            )
                            .await?;
                            segment_base = Some(alloc.address);
                            // Update the per-object base too: the resumed `WriteRelMem` for
                            // this object prefers its per-object base, which must be the
                            // freshly-returned one, not the dropped pre-reset value.
                            segment_bases.insert(reset_obj, alloc.address);
                            segment_fills.insert(reset_obj, last_alloc_fill);
                        }
                    }
                    FlashStep::FactoryReset { erase_code } => {
                        // The confirmed master reset ETS opens an initial System B
                        // download with (issue #117): numbered A_Restart 0x381
                        // [erase_code, channel 0], answered by A_Restart_Response
                        // [error, process time]. A refusal (non-zero error) or silence
                        // fails the flash before anything is written: the device may
                        // still hold a stale image, and `--no-factory-reset` is the
                        // explicit way past that.
                        // Refuse before erasing anything when the session could not
                        // reconnect to the rebooted device afterwards.
                        if !session.can_reconnect() {
                            return Err(WriteError::Mgmt(MgmtError::Transport(
                                bussard_transport::TransportError::Closed,
                            )));
                        }
                        let response =
                            bussard_mgmt::master_reset(session.l4(), *erase_code, 0).await?;
                        tracing::debug!(
                            erase_code,
                            process_time_s = response.process_time_s,
                            "factory reset accepted; waiting out the reboot"
                        );
                        // Erase code 7 leaves the individual address and the
                        // interface-object table alone, so the discovered table stays
                        // valid; the objects are back to `Unloaded` and the following
                        // Unload/StartLoading steps run as on a fresh device.
                        session
                            .reconnect_after_master_reset(bussard_mgmt::restart_process_wait(
                                &response,
                            ))
                            .await?;
                    }
                    FlashStep::Restart => {
                        // The terminal restart reboots the device, and the flash is only a
                        // real success if the load *persists* across that reboot. KNX
                        // Virtual reports a transient `Loaded` while the device is still up,
                        // then reverts the application object to `Unloaded` after the restart
                        // when the written image is content-incomplete. Verifying *before*
                        // the restart therefore reads that transient `Loaded` and reports a
                        // non-persisting flash as a success — the false-positive this fixes.
                        //
                        // So, when the session can re-open its own connection, verify AFTER
                        // the restart: fire the restart, wait out the reboot, reconnect and
                        // re-authorize, then re-read the load state. Success is reported only
                        // if the application object is *genuinely* `Loaded` once the device
                        // is back; a load that did not persist now fails loudly.
                        //
                        // A session built from an already-open connection
                        // ([`Session::from_connection`], used by the mock-device tests) has
                        // no connector to reconnect with, and the mock does not reboot — so
                        // fall back to verifying over the still-open connection before the
                        // restart, preserving those tests' behaviour.
                        // A plan that allocates filled segments ends with the confirmed
                        // form ETS uses on those devices (issue #117): A_Restart master
                        // reset, erase code 1, answered by A_Restart_Response. Every
                        // other plan (KNX Virtual DA.tp, thelsing) keeps the bare
                        // A_Restart its captures show.
                        let (apci, payload) = if plan.confirmed_restart {
                            bussard_mgmt::apci::encode_master_reset(
                                bussard_mgmt::apci::ERASE_CODE_CONFIRMED_RESTART,
                                0,
                            )
                        } else {
                            bussard_mgmt::apci::encode_restart(0)
                        };
                        if verify_after_restart && session.can_reconnect() {
                            if plan.confirmed_restart {
                                // Wait the device's process time when it answered; a
                                // device that reboots without answering is still
                                // judged by the post-restart verify below.
                                match bussard_mgmt::master_reset(
                                    session.l4(),
                                    bussard_mgmt::apci::ERASE_CODE_CONFIRMED_RESTART,
                                    0,
                                )
                                .await
                                {
                                    Ok(response) => {
                                        session
                                            .reconnect_after_master_reset(
                                                bussard_mgmt::restart_process_wait(&response),
                                            )
                                            .await?;
                                    }
                                    Err(err) => {
                                        tracing::debug!(
                                            %err,
                                            "confirmed restart not answered; polling for the reboot"
                                        );
                                        session.reconnect_after_reboot().await?;
                                    }
                                }
                            } else {
                                let _ = session.l4().send_data_unacked(apci, &payload).await;
                                // The device is unreachable while it reboots; poll for it
                                // (bounded), then re-establish the authorized connection.
                                session.reconnect_after_reboot().await?;
                            }
                            // Re-confirm the application object on the fresh connection. The
                            // index is stable across the reboot, so a single `PID_OBJECT_TYPE`
                            // probe of the known index is enough; only if the device answers
                            // something else (or does not answer) is the full walk re-run.
                            // Re-walking every object unconditionally — the previous behaviour
                            // — cost one exchange per interface object on the tightest
                            // connection of the whole flash.
                            let post_app_obj = confirm_app_object(session, app_obj).await?;
                            verified = Some(
                                verify_outcome(
                                    session,
                                    post_app_obj,
                                    &completed_objects,
                                    &written_samples,
                                )
                                .await?,
                            );
                        } else {
                            // No connector to reconnect with: verify over the still-open
                            // connection, then fire-and-forget the restart.
                            verified = Some(
                                verify_outcome(
                                    session,
                                    app_obj,
                                    &completed_objects,
                                    &written_samples,
                                )
                                .await?,
                            );
                            let _ = session.l4().send_data_unacked(apci, &payload).await;
                        }
                    }
                    // System 7 steps are executed by `flash_sys7` (dispatched at the
                    // top of `flash`); a System B plan never carries them.
                    FlashStep::Sys7Unload { .. }
                    | FlashStep::Sys7StartLoading { .. }
                    | FlashStep::Sys7AbsSegment { .. }
                    | FlashStep::Sys7TaskSegment { .. }
                    | FlashStep::Sys7TaskCtrl1 { .. }
                    | FlashStep::Sys7LoadCompleted { .. }
                    | FlashStep::Sys7CompareMem { .. } => {}
                }
                Ok(())
            }
            .await;

            match step_result {
                Ok(()) => break 'resume,
                // An unexpected mid-flow connection death on a resumable step: cycle the
                // L4 connection and re-run the step, up to the per-step bound. This
                // composes with the proactive `cycle_l4` above (which reduces how often
                // we get here) and with `write_image`'s chunk-granular resume (which
                // continues a segment stream from the last confirmed offset instead of
                // replaying the whole image); resume-on-drop is the outer net that
                // reconnects a *dead* connection and replays the whole step.
                Err(e)
                    if resumable_death(&e, session)
                        && !self_reconnecting_step
                        && resume_reconnects < MAX_RESUME_RECONNECTS =>
                {
                    resume_reconnects += 1;
                    // The old connection is dead (the device stopped answering); re-open
                    // a fresh one and re-authorize, then replay the step. `reconnect`
                    // drops the dead connection outright rather than trying a graceful
                    // T_Disconnect the dead peer would not answer.
                    session.reconnect().await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // If no terminal restart captured the outcome (a procedure with no final
    // Restart), verify now over the still-open connection. `verify_outcome` is
    // internally resume-on-drop (each read reconnects and retries), so a connection
    // death here — after all the writes landed — is recovered rather than reported
    // as a flash failure.
    match verified {
        Some(outcome) => Ok(outcome),
        None => verify_outcome(session, app_obj, &completed_objects, &written_samples).await,
    }
}

/// Executes a validated **System 7** [`FlashPlan`] (`[system7-spec §3/§4]`).
///
/// System 7 is memory-mapped and absolute-addressed: it drives the three parallel
/// load-state machines through the [`bussard_mgmt::LsmAccess`] seam (memory-mapped
/// 11-octet record by default), allocates each absolute segment and streams its
/// `<Data>` to the segment's fixed address in negotiated-max-APDU chunks (honouring the
/// `0x4000` region's per-byte `<Mask>`), finalizes each LSM with a TaskSegment,
/// and verifies by read-back compare. The obj0/PID78 preflight, `LdCtrlCompareMem`
/// and per-object `LdCtrlLoadImageProp` MCB checks reuse the System B primitives.
///
/// The session was already authorized at connect time (System 7 requires
/// `A_Authorize` before memory access; the free-access key is presented by
/// [`Session::open`]). It shares the same resume-on-drop and proactive-L4-cycling
/// discipline as [`flash`] via the session, but has its own step loop because the
/// LSM control and absolute streaming differ from System B.
async fn flash_sys7<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    plan: &FlashPlan,
    options: FlashOptions,
    mut progress: F,
) -> Result<FlashOutcome, WriteError> {
    let ctx = plan
        .sys7
        .as_ref()
        .expect("flash_sys7 called on a non-System-7 plan");
    let lsm = bussard_mgmt::lsm_access_from_profile(&ctx.profile);
    // Whether to verify after the terminal restart (real device) or before it (a
    // mock that does not reboot-and-return). Read once, then consumed in the
    // terminal-restart arm — same discipline as the System B path.
    let verify_after_restart = options.verify_after_restart;
    // The final outcome, captured either by the terminal-restart arm (verify AFTER
    // reconnect) or by the post-loop fallback (a procedure with no final Restart).
    let mut verified: Option<FlashOutcome> = None;
    let total = plan.steps.len();
    // Read-back spot-check samples of the segment writes (address, first octets).
    let mut written_samples: Vec<(u16, Vec<u8>)> = Vec::new();
    // The LSMs that reached LoadCompleted, in order, for the post-flash verify.
    let mut completed_lsms: Vec<u32> = Vec::new();

    // The proactive-reconnect exchange threshold (0 = disabled), read once — the
    // same ETS-pattern L4 cycling the System B path uses.
    let reconnect_threshold = reconnect_exchange_threshold();

    for (i, step) in plan.steps.iter().enumerate() {
        // Proactive periodic L4 reconnection between steps (never mid memory
        // write). The LSM states and allocated segments are persistent device
        // state, so they survive a graceful cycle. The terminal Restart reboots
        // the device itself, so it is excluded.
        let self_reconnecting = matches!(step, FlashStep::Restart);
        if reconnect_threshold > 0
            && session.can_reconnect()
            && !self_reconnecting
            && session.numbered_exchanges() >= reconnect_threshold
        {
            session.cycle_l4().await?;
        }
        progress(Progress::Step {
            index: i + 1,
            total,
            label: step_label(step),
        });

        // Resume-on-drop: run the step, and if it dies from an unexpected mid-flow
        // connection death and the session can reconnect, cycle the connection and
        // re-run the whole step. LSM state and allocated segments are persistent
        // device state that survive the drop, and every System 7 memory write is
        // absolute-addressed and idempotent, so replaying the step is safe. The
        // terminal Restart reboots the device and is excluded (its silence is
        // expected). Bounded by MAX_RESUME_RECONNECTS per step.
        let mut resume_reconnects = 0u32;
        'resume: loop {
            let step_result: Result<(), WriteError> = async {
                match step {
                    FlashStep::Sys7Unload { lsm: idx } => {
                        let octet = lsm_octet(session.l4().target(), *idx)?;
                        lsm.drive(session.l4(), octet, LoadControl::Unload).await?;
                    }
                    FlashStep::Sys7StartLoading { lsm: idx } => {
                        let octet = lsm_octet(session.l4().target(), *idx)?;
                        lsm.drive(session.l4(), octet, LoadControl::StartLoading)
                            .await?;
                    }
                    FlashStep::Sys7AbsSegment {
                        lsm: idx,
                        address,
                        size,
                        mem_type,
                        seg_flags,
                        checksum_ctrl,
                        image,
                    } => {
                        // 1. Allocate the absolute segment on the LSM. The captures pin
                        //    opcode/subtype, big-endian start+length, `mem_type` and the
                        //    per-segment attribute octets, which the plan takes from the
                        //    op's `Access`/`MemType`/`SegFlags` (ETS reproduces them
                        //    verbatim) or derives from the address when absent.
                        let (seg_flags, checksum_ctrl) = (*seg_flags, *checksum_ctrl);
                        // Checked, not truncated: an out-of-range address used to go out as
                        // a wrong allocation frame before the following write refused.
                        let target = session.l4().target();
                        let seg_addr = sys7_u16(target, "segment address", *address)?;
                        let seg_size = sys7_u16(target, "segment size", *size)?;
                        let event = bussard_mgmt::encode_alloc_segment(
                            bussard_mgmt::sys7::S7_SUB_ALLOC_DATA,
                            seg_addr,
                            seg_size,
                            seg_flags,
                            *mem_type,
                            checksum_ctrl,
                        );
                        let octet = lsm_octet(target, *idx)?;
                        lsm.send_control(session.l4(), octet, &event).await?;
                        // 2. Stream the segment's <Data>, if any, to its absolute address.
                        //    A data-less segment (0x0700 RAM region) is allocate-only.
                        if let Some(img) = image {
                            let bytes = plan
                                .images
                                .get(&img.segment_id)
                                .expect("System 7 segment image resolved at plan time");
                            let addr = seg_addr;
                            let mask = ctx.segment_masks.get(&img.segment_id);
                            write_sys7_segment(
                                session,
                                addr,
                                bytes,
                                mask.map(Vec::as_slice),
                                &mut progress,
                            )
                            .await?;
                            // Spot-check only unmasked, checksum-controlled segments: a
                            // masked segment leaves device-owned bytes untouched, so the
                            // image's leading octets do not equal the device's memory;
                            // a `checksum_ctrl == 0` segment is rewritten by the running
                            // application after the restart (1.1.36 `0x4916`: written
                            // `0c`, read back `00`), so its sample proves nothing.
                            if mask.is_none() && checksum_ctrl != 0 {
                                written_samples.push((addr, take_sample(bytes)));
                            }
                        }
                    }
                    FlashStep::Sys7TaskSegment {
                        lsm: idx,
                        address,
                        marker,
                    } => {
                        let target = session.l4().target();
                        let task_addr = sys7_u16(target, "task segment address", *address)?;
                        let event = bussard_mgmt::encode_task_segment(task_addr, *marker);
                        let octet = lsm_octet(target, *idx)?;
                        lsm.send_control(session.l4(), octet, &event).await?;
                    }
                    FlashStep::Sys7TaskCtrl1 {
                        lsm: idx,
                        address,
                        count,
                    } => {
                        let target = session.l4().target();
                        let ctrl_addr = sys7_u16(target, "task control address", *address)?;
                        let ctrl_count =
                            u8::try_from(*count).map_err(|_| WriteError::AddressOutOfRange {
                                address: target,
                                detail: format!(
                                    "System 7 task control count {count} does not fit the record's \
                             single count octet"
                                ),
                            })?;
                        let event = bussard_mgmt::encode_task_ctrl1(ctrl_addr, ctrl_count);
                        let octet = lsm_octet(target, *idx)?;
                        lsm.send_control(session.l4(), octet, &event).await?;
                    }
                    FlashStep::Sys7LoadCompleted { lsm: idx } => {
                        let octet = lsm_octet(session.l4().target(), *idx)?;
                        lsm.drive(session.l4(), octet, LoadControl::LoadCompleted)
                            .await?;
                        completed_lsms.push(*idx);
                    }
                    FlashStep::Sys7CompareMem { address, expected } => {
                        let addr = sys7_u16(session.l4().target(), "compare address", *address)?;
                        let got = read_sys7_memory(session, addr, expected.len()).await?;
                        if &got != expected {
                            return Err(WriteError::Mgmt(
                                bussard_mgmt::MgmtError::MemoryVerifyFailed {
                                    address: session.l4().target(),
                                    addr: u32::from(addr),
                                    expected: expected.clone(),
                                    got,
                                },
                            ));
                        }
                    }
                    FlashStep::CompareProp {
                        obj_idx,
                        prop_id,
                        expected,
                        mask,
                    } => {
                        // The obj0/PID78 preflight and any other property compare: identical
                        // to System B (an interface-object property read + compare).
                        if let Some(expected) = expected {
                            compare_property(
                                session.l4(),
                                (*obj_idx).min(u8::MAX.into()) as u8,
                                (*prop_id).min(u8::MAX.into()) as u8,
                                expected,
                                mask.as_deref(),
                            )
                            .await?;
                        }
                    }
                    FlashStep::LoadImageProp {
                        obj_idx,
                        prop_id,
                        count,
                        ..
                    } => {
                        // Jung A-A011 per-object MCB verification (`[system7-spec §2
                        // amendment]`): read the object's PID_MCB_TABLE. Read-back compare is
                        // the baseline verify, so a read-only MCB confirm here (no tool-side
                        // CRC) simply asserts the object serves a readable MCB entry.
                        if *prop_id == u32::from(bussard_mgmt::PID_MCB_TABLE) {
                            read_mcb_table(
                                session.l4(),
                                (*obj_idx).min(u8::MAX.into()) as u8,
                                1,
                                (*count).max(1).min(u8::MAX.into()) as u8,
                                None,
                            )
                            .await?;
                        }
                    }
                    FlashStep::Restart => {
                        // The terminal restart reboots the device and drops the L4
                        // connection, and the flash is only a real success if the load
                        // *persists* across that reboot (System B taught us a bad image
                        // silently reverts to Unloaded — the same rigor applies here). So
                        // when the session can re-open its own connection, verify AFTER the
                        // restart: fire the restart, wait out the reboot, reconnect and
                        // re-authorize (the retained connector), then re-read the LSM states
                        // and run the segment spot checks on the *fresh* connection. Reading
                        // the LSM status or a segment on the now-closed pre-restart
                        // connection is exactly the "management telegram with no open
                        // connection" rejection a real device (and the sim) issues.
                        //
                        // A session built from an already-open connection
                        // ([`Session::from_connection`], the mock-device tests) has no
                        // connector to reconnect with and its mock does not reboot — so fall
                        // back to verifying over the still-open connection *before* the
                        // restart, preserving those tests' behaviour.
                        let (apci, payload) = bussard_mgmt::apci::encode_restart(0);
                        if verify_after_restart && session.can_reconnect() {
                            let _ = session.l4().send_data_unacked(apci, &payload).await;
                            // The device is unreachable while it reboots; poll for it
                            // (bounded), then re-establish the authorized connection and
                            // verify honestly on it.
                            session.reconnect_after_reboot().await?;
                            verified = Some(
                                verify_sys7(session, &lsm, &completed_lsms, &written_samples)
                                    .await?,
                            );
                        } else {
                            // No connector to reconnect with (mock): verify over the
                            // still-open connection, then fire-and-forget the restart.
                            verified = Some(
                                verify_sys7(session, &lsm, &completed_lsms, &written_samples)
                                    .await?,
                            );
                            let _ = session.l4().send_data_unacked(apci, &payload).await;
                        }
                    }
                    // System B steps never appear in a System 7 plan.
                    other => {
                        return Err(WriteError::Mgmt(
                            bussard_mgmt::MgmtError::MalformedResponse {
                                address: session.l4().target(),
                                reason: format!(
                                    "System 7 executor met a non-System-7 step: {other:?}"
                                ),
                            },
                        ));
                    }
                }
                Ok(())
            }
            .await;

            match step_result {
                Ok(()) => break 'resume,
                Err(e)
                    if resumable_death(&e, session)
                        && !self_reconnecting
                        && resume_reconnects < MAX_RESUME_RECONNECTS =>
                {
                    resume_reconnects += 1;
                    session.reconnect().await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // The terminal restart captured the outcome (verify AFTER reboot). A procedure
    // with no final Restart falls back to verifying now over the still-open
    // connection.
    match verified {
        Some(outcome) => Ok(outcome),
        None => verify_sys7(session, &lsm, &completed_lsms, &written_samples).await,
    }
}

/// Verifies a completed System 7 download by read-back: every LSM that reached
/// `LoadCompleted` must report `Loaded`, and each recorded segment spot check must
/// still match device memory.
///
/// Called AFTER the terminal restart+reconnect (a real device) so the load is
/// checked as it *persists* across the reboot, or over the still-open connection
/// when there is no restart / no connector (the mock-device tests). The LSM-state
/// reads tolerate a single resumable connection death by re-reading, because a
/// freshly-rebooted device can drop the first probe on the newly-opened
/// connection; the segment spot checks stay best-effort (a transient read miss on
/// a just-rebooted device is not a mismatch — the LSM states are the load's real
/// verdict).
async fn verify_sys7<C: Connector>(
    session: &mut Session<C>,
    lsm: &bussard_mgmt::LsmAccess,
    completed_lsms: &[u32],
    written_samples: &[(u16, Vec<u8>)],
) -> Result<FlashOutcome, WriteError> {
    let mut object_states: Vec<(u8, LoadState)> = Vec::new();
    let mut all_loaded = true;
    for idx in completed_lsms {
        let octet = lsm_octet(session.l4().target(), *idx)?;
        // Re-read once through a resumable death: a just-rebooted device can drop
        // the first probe on the fresh connection before it is fully back.
        let state = match lsm.read_state(session.l4(), octet).await {
            Ok(state) => state,
            Err(e) if resumable_death(&e, session) && session.can_reconnect() => {
                session.reconnect().await?;
                lsm.read_state(session.l4(), octet).await?
            }
            Err(e) => return Err(e),
        };
        if state != LoadState::Loaded {
            all_loaded = false;
        }
        object_states.push((octet, state));
    }
    // Spot-check the written segments (best-effort: a read failure is not treated
    // as a mismatch here — the per-chunk read-back during the write already
    // verified each byte).
    let mut spot_checks_match = true;
    for (addr, expected) in written_samples {
        match read_sys7_memory(session, *addr, expected.len()).await {
            Ok(got) if &got != expected => spot_checks_match = false,
            _ => {}
        }
    }

    Ok(FlashOutcome {
        load_state: if all_loaded {
            LoadState::Loaded
        } else {
            LoadState::Other(0xFF)
        },
        object_states,
        spot_checks_match,
    })
}

/// One 16-bit System 7 record field (an address, a size) as the `u16` the wire
/// carries, refusing anything larger instead of truncating it.
///
/// [`plan_flash_sys7`] already validates these at plan time
/// ([`PlanError::Sys7FieldOutOfRange`]); this is the executor's own guard, so a
/// hand-built or deserialized plan cannot put an allocation at a wrapped address
/// on the bus either (issue #81).
fn sys7_u16(
    address: bussard_model::IndividualAddress,
    field: &str,
    value: u32,
) -> Result<u16, WriteError> {
    u16::try_from(value).map_err(|_| WriteError::AddressOutOfRange {
        address,
        detail: format!("System 7 {field} {value:#X} exceeds the 16-bit A_Memory space"),
    })
}

/// The 1-based LSM index as the octet the record carries, refusing anything
/// outside `1..=15`.
///
/// The index rides in the **high nibble** of the record's opcode octet
/// ([`bussard_mgmt::sys7::wrap_memory_lsm_record`]), so a larger value wraps into
/// a different machine and `0` names none. The executor's guard next to
/// [`PlanError::Sys7LsmOutOfRange`] at plan time.
fn lsm_octet(address: bussard_model::IndividualAddress, lsm: u32) -> Result<u8, WriteError> {
    u8::try_from(lsm)
        .ok()
        .filter(|idx| (1..=15).contains(idx))
        .ok_or_else(|| WriteError::AddressOutOfRange {
            address,
            detail: format!(
                "System 7 LSM index {lsm} is outside 1..=15 and cannot be folded into the \
                 record's opcode nibble"
            ),
        })
}

/// Reads `len` octets of System 7 device memory at `addr`, looping over the
/// device's max-chunk cap. Used by the `CompareMem` op and the post-flash spot
/// checks.
async fn read_sys7_memory<C: Connector>(
    session: &mut Session<C>,
    addr: u16,
    len: usize,
) -> Result<Vec<u8>, WriteError> {
    let mut out = Vec::with_capacity(len);
    let chunk = usize::from(session.l4().max_memory_chunk());
    let mut offset = 0usize;
    while offset < len {
        let take = chunk.min(len - offset);
        let piece_addr = addr.saturating_add(offset as u16);
        let piece = read_memory(session.l4(), u32::from(piece_addr), take as u8).await?;
        out.extend_from_slice(&piece);
        offset += take;
    }
    Ok(out)
}

/// Streams a System 7 segment image to `addr`, honouring an optional per-byte
/// `<Mask>` (`[system7-spec §4.2]`): a `0xFF` mask byte means the byte belongs to
/// the image and is written; any other value marks a device-owned byte the write
/// must leave untouched. Owned bytes are streamed in maximal contiguous runs
/// (streamed in negotiated-max-APDU chunks by [`write_image`]). With no mask,
/// the whole image is streamed.
async fn write_sys7_segment<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    addr: u16,
    bytes: &[u8],
    mask: Option<&[u8]>,
    progress: &mut F,
) -> Result<(), WriteError> {
    let Some(mask) = mask else {
        return write_image(session, u32::from(addr), bytes, progress).await;
    };
    // Walk the mask, writing each maximal run of owned (0xFF) bytes at its address.
    let mut i = 0usize;
    while i < bytes.len() {
        let owned = mask.get(i).copied() == Some(0xFF);
        if !owned {
            i += 1;
            continue;
        }
        let run_start = i;
        while i < bytes.len() && mask.get(i).copied() == Some(0xFF) {
            i += 1;
        }
        let run_addr = addr.saturating_add(run_start as u16);
        write_image(session, u32::from(run_addr), &bytes[run_start..i], progress).await?;
    }
    Ok(())
}

/// Reads one object's load state, **resuming at read granularity** over the
/// session across an unexpected connection death: on a connection-death it
/// reconnects and re-reads (the load state is persistent, so the read is
/// idempotent). Bounded by [`MAX_RESUME_RECONNECTS`] consecutive reconnects.
async fn read_load_state_resumable<C: Connector>(
    session: &mut Session<C>,
    obj: u8,
) -> Result<LoadState, WriteError> {
    let mut reconnects = 0u32;
    loop {
        match read_load_state(session.l4(), obj).await {
            Ok(state) => return Ok(state),
            Err(e) if resumable_death(&e, session) && reconnects < MAX_RESUME_RECONNECTS => {
                reconnects += 1;
                session.reconnect().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Reads `len` octets at `addr`, resuming at read granularity over the session
/// across an unexpected connection death (like [`read_load_state_resumable`]).
async fn read_memory_resumable<C: Connector>(
    session: &mut Session<C>,
    addr: u32,
    len: u8,
) -> Result<Vec<u8>, WriteError> {
    let mut reconnects = 0u32;
    loop {
        match load::read_memory(session.l4(), addr, len).await {
            Ok(got) => return Ok(got),
            Err(e) if resumable_death(&e, session) && reconnects < MAX_RESUME_RECONNECTS => {
                reconnects += 1;
                session.reconnect().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Verifies a completed flash over the session's connection: re-reads the load
/// state of **every object that was programmed** (each that received a
/// `LoadCompleted`, plus the application object) and spot-checks a sample of each
/// written segment against what was streamed.
///
/// Verifying every completed object — not just the type-discovered application
/// object — is the divergence-#3 fix: a multi-object flash (obj1/obj2/obj3/obj4)
/// must confirm the table objects reached `Loaded` too, or a device that
/// silently failed to load a table would be reported as a success.
///
/// Every read is individually resume-on-drop (see [`read_load_state_resumable`] /
/// [`read_memory_resumable`]): the verify is many exchanges — more than a tight
/// per-connection budget allows in one window — so a whole-verify replay could
/// never finish; per-read forward progress can, and every read is idempotent.
///
/// Called with the device still up — either just before a terminal restart
/// reboots it, or (for a procedure without a final restart) after the last step.
async fn verify_outcome<C: Connector>(
    session: &mut Session<C>,
    app_obj: u8,
    completed_objects: &[u8],
    written_samples: &[(u32, Vec<u8>)],
) -> Result<FlashOutcome, WriteError> {
    // The application object's own state (kept as the headline `load_state`).
    let load_state = read_load_state_resumable(session, app_obj).await?;

    // Every programmed object's state: the completed set, plus the app object if
    // the procedure did not itself complete it (a bare app segment write). Read
    // each once, de-duplicated, preserving order for a deterministic report.
    let mut object_states: Vec<(u8, LoadState)> = Vec::new();
    let mut seen: Vec<u8> = Vec::new();
    for &obj in completed_objects.iter().chain(std::iter::once(&app_obj)) {
        if seen.contains(&obj) {
            continue;
        }
        seen.push(obj);
        let state = if obj == app_obj {
            load_state
        } else {
            read_load_state_resumable(session, obj).await?
        };
        object_states.push((obj, state));
    }

    let mut spot_checks_match = true;
    for (addr, expected) in written_samples {
        let got = read_memory_resumable(session, *addr, expected.len() as u8).await?;
        if &got != expected {
            spot_checks_match = false;
        }
    }
    Ok(FlashOutcome {
        load_state,
        object_states,
        spot_checks_match,
    })
}

/// Gaps of up to this many fill octets between two differing runs are written
/// through rather than split: a new memory-write telegram costs more than a few
/// payload octets.
const FILL_MERGE_GAP: usize = 4;

/// The regions of `image` that differ from a segment pre-filled with `fill`, as
/// `(offset, bytes)` pairs in ascending order. Runs separated by at most
/// [`FILL_MERGE_GAP`] fill octets are merged. Writing only these regions over
/// the pre-filled segment leaves the same memory as writing the whole image.
fn fill_regions(image: &[u8], fill: u8) -> Vec<(usize, &[u8])> {
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < image.len() {
        if image[i] == fill {
            i += 1;
            continue;
        }
        let start = i;
        while i < image.len() && image[i] != fill {
            i += 1;
        }
        match regions.last_mut() {
            Some((_, end)) if start - *end <= FILL_MERGE_GAP => *end = i,
            _ => regions.push((start, i)),
        }
    }
    regions
        .into_iter()
        .map(|(start, end)| (start, &image[start..end]))
        .collect()
}

/// Streams `bytes` to `addr` over the session's connection, emitting a
/// byte-progress event per confirmed chunk, and **resuming at chunk granularity**
/// across an unexpected connection death.
///
/// The write is chunked by [`bussard_mgmt::write_memory_chunked`], which sizes each
/// chunk from the negotiated max-APDU and propagates a connection death on the first
/// failure — recovering from one needs a *new* connection, which only this call site
/// can open. When the connection dies mid-way
/// (the device dropped it), this reconnects and continues streaming from the last
/// **confirmed** offset rather than restarting the image — essential on a device
/// whose per-connection exchange budget is smaller than the whole image (a
/// whole-image replay would drop at the same offset forever and never finish). The
/// confirmed offset is tracked from the `on_written` cumulative callback, so no byte
/// is re-sent unnecessarily and none is skipped. Bounded by [`MAX_RESUME_RECONNECTS`]
/// consecutive reconnects that make no further progress; each confirmed chunk resets
/// the bound. A session that cannot reconnect (mocks, `from_connection`) surfaces the
/// death unchanged, exactly as before.
async fn write_image<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    addr: u32,
    bytes: &[u8],
    progress: &mut F,
) -> Result<(), WriteError> {
    let total = bytes.len();
    // Bytes confirmed written so far (cumulative), so a resume continues from here.
    let mut confirmed = 0usize;
    let mut stalled_reconnects = 0u32;
    loop {
        // Stream the remaining tail from the last confirmed offset. `on_written`
        // reports the offset *within this call*; add the already-confirmed base to
        // get the cumulative image offset (for the progress event and the resume
        // cursor). `made_progress` distinguishes a death that advanced the cursor
        // (reset the stall bound) from one that did not.
        let base = confirmed;
        let mut call_confirmed = confirmed;
        let mut on_written = |written_in_call: usize| {
            call_confirmed = base + written_in_call;
            progress(Progress::Bytes {
                written: call_confirmed,
                total,
            });
        };
        let tail_addr = addr.saturating_add(confirmed as u32);
        let result = bussard_mgmt::write_memory_chunked(
            session.l4(),
            tail_addr,
            &bytes[confirmed..],
            &mut on_written,
        )
        .await;
        let made_progress = call_confirmed > confirmed;
        confirmed = call_confirmed;
        match result {
            Ok(()) => return Ok(()),
            Err(e)
                if resumable_death(&e, session)
                    && (made_progress || stalled_reconnects < MAX_RESUME_RECONNECTS) =>
            {
                if made_progress {
                    stalled_reconnects = 0;
                } else {
                    stalled_reconnects += 1;
                }
                session.reconnect().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// The first up-to-4 octets of an image, used as the post-flash read-back sample.
fn take_sample(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len().min(4)].to_vec()
}

/// A `" (LsmIdx/ObjIdx N)"` suffix for a step label, naming the object index the
/// op targets, or empty when it targets the discovered application object.
fn target_suffix(target: Option<u32>) -> String {
    match target {
        Some(idx) if idx != 0 => format!(" (obj {idx})"),
        _ => " (app object)".to_string(),
    }
}

/// A short human label for a step, for the progress line and the dry-run trace.
fn step_label(step: &FlashStep) -> String {
    match step {
        FlashStep::Unload { target } => format!("unload{}", target_suffix(*target)),
        FlashStep::StartLoading { target } => {
            format!("open for loading{}", target_suffix(*target))
        }
        FlashStep::AllocateSegment { size, target, fill } => {
            let fill_note = match fill {
                Some(b) => format!(", fill 0x{b:02X}"),
                None => String::new(),
            };
            format!(
                "allocate segment ({size} bytes{fill_note}){}",
                target_suffix(*target)
            )
        }
        FlashStep::WriteRelMem {
            offset,
            image,
            target,
        } => {
            format!(
                "write {} image ({} bytes) at segment+{offset}{}",
                image.kind,
                image.len,
                target_suffix(*target)
            )
        }
        FlashStep::WriteMem { address, image } => {
            format!(
                "write {} image ({} bytes) at {address:#010X}",
                image.kind, image.len
            )
        }
        FlashStep::WriteProp {
            obj_idx,
            obj_type,
            prop_id,
            value,
            start_element,
        } => {
            format!(
                "write property (object {obj_idx}, type {obj_type}, PID {prop_id}, {} byte(s) from element {start_element})",
                value.len()
            )
        }
        FlashStep::CompareProp {
            obj_idx,
            prop_id,
            expected,
            ..
        } => match expected {
            Some(bytes) => format!(
                "verify property (object {obj_idx}, PID {prop_id} == {} byte(s))",
                bytes.len()
            ),
            None => format!("verify property (object {obj_idx}, PID {prop_id}, range — skipped)"),
        },
        FlashStep::CompareRelMem {
            target,
            offset,
            expected,
            invert,
            ..
        } => match expected {
            Some(bytes) => format!(
                "verify relative memory (segment+{offset}{} {} {} byte(s))",
                target_suffix(*target),
                if *invert { "!=" } else { "==" },
                bytes.len()
            ),
            None => format!(
                "verify relative memory (segment+{offset}{}, no data — skipped)",
                target_suffix(*target)
            ),
        },
        FlashStep::LoadImageProp {
            obj_idx,
            prop_id,
            image,
            ..
        } => match image {
            Some(img) => format!(
                "verify image (object {obj_idx}, PID {prop_id} MCB CRC over {} bytes)",
                img.len
            ),
            None => format!("read image MCB (object {obj_idx}, PID {prop_id})"),
        },
        FlashStep::LoadCompleted { target } => {
            format!("complete load{}", target_suffix(*target))
        }
        FlashStep::Restart => "restart device".to_string(),
        FlashStep::FactoryReset { erase_code } => format!(
            "factory reset (A_Restart master reset, erase code {erase_code}): erase application, \
             parameters and links, keep the individual address; reconnect"
        ),
        FlashStep::MasterReset {
            erase_code,
            channel_number,
        } => format!(
            "master reset (erase code {erase_code}, channel {channel_number}) — reconnect and resume"
        ),
        FlashStep::Sys7Unload { lsm } => format!("[S7] unload LSM {lsm}"),
        FlashStep::Sys7StartLoading { lsm } => format!("[S7] open LSM {lsm} for loading"),
        FlashStep::Sys7AbsSegment {
            lsm,
            address,
            size,
            image,
            ..
        } => match image {
            Some(img) => format!(
                "[S7] alloc + stream segment ({} bytes) to {address:#06X} on LSM {lsm}",
                img.len
            ),
            None => format!("[S7] alloc segment ({size} bytes) at {address:#06X} on LSM {lsm}"),
        },
        FlashStep::Sys7TaskSegment {
            lsm,
            address,
            marker,
        } => {
            format!("[S7] finalize LSM {lsm} task segment at {address:#06X} (marker {marker:02X?})")
        }
        FlashStep::Sys7TaskCtrl1 {
            lsm,
            address,
            count,
        } => format!("[S7] task control 1 at {address:#06X} x{count} on LSM {lsm}"),
        FlashStep::Sys7LoadCompleted { lsm } => format!("[S7] complete load of LSM {lsm}"),
        FlashStep::Sys7CompareMem { address, expected } => format!(
            "[S7] verify memory at {address:#06X} == {} byte(s)",
            expected.len()
        ),
    }
}

/// Renders a plan's step list as a dry-run trace: one line per step, in order.
/// Used by the CLI pre-flight and the env-gated golden trace test to prove the
/// interpreter digests a real vendor procedure without touching a device.
pub fn trace(plan: &FlashPlan) -> Vec<String> {
    plan.steps
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{:>3}. {}", i + 1, plan.step_label(s)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The System 7 group-object post-pass: the communication flag follows the
    /// association table (1.1.31: no links, none set; 1.1.46: exactly the
    /// linked ASAPs), everything else in the descriptor is left alone.
    #[test]
    fn test_apply_sys7_group_object_links_follows_the_association_table() {
        let seg_id = "M-0004_A-A011-13-60BC-O000A_AS-43FF".to_string();
        let steps = vec![
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x0700,
                size: 450,
                mem_type: 2,
                seg_flags: 0xF2,
                checksum_ctrl: 0x00,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FF,
                size: 811,
                mem_type: 3,
                seg_flags: 0xF2,
                checksum_ctrl: 0x80,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
                }),
            },
        ];
        // [CNT=3][RAM flags 0x07F9] then three descriptors with the vendor
        // template's communication flag set on every one.
        let template = vec![
            0x03, 0x07, 0xF9, 0x07, 0x00, 0x17, 0x00, 0x07, 0x01, 0x4F, 0x08, 0x07, 0x03, 0x17,
            0x08,
        ];
        let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);

        // No links: ETS clears the flag everywhere (the 1.1.31 capture).
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        );
        assert_eq!(
            images[&seg_id],
            vec![
                0x03, 0x07, 0xF9, 0x07, 0x00, 0x13, 0x00, 0x07, 0x01, 0x4B, 0x08, 0x07, 0x03, 0x13,
                0x08
            ]
        );

        // ASAP 1 linked: only descriptor 1 carries the flag.
        let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);
        let linked = sys7_linked_asaps(&[0x01, 0x02, 0x01]);
        assert_eq!(linked, BTreeSet::from([1]));
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            &linked,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        );
        assert_eq!(images[&seg_id][5], 0x13);
        assert_eq!(images[&seg_id][9], 0x4F);
        assert_eq!(images[&seg_id][13], 0x13);

        // With the project's flags known, the linked descriptor takes them
        // (1.1.46: template `df` became `4f` = T R C, low priority kept).
        let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);
        let mut flags = BTreeMap::new();
        flags.insert(
            1u16,
            bussard_model::Flags::COMMUNICATION
                | bussard_model::Flags::READ
                | bussard_model::Flags::TRANSMIT,
        );
        let mut tmpl = template.clone();
        tmpl[9] = 0xDF;
        let mut images_df = BTreeMap::from([(seg_id.clone(), tmpl)]);
        apply_sys7_group_object_links(
            &steps,
            &mut images_df,
            &linked,
            &flags,
            &BTreeMap::new(),
            None,
        );
        assert_eq!(images_df[&seg_id][9], 0x4F);
        apply_sys7_group_object_links(&steps, &mut images, &linked, &flags, &BTreeMap::new(), None);
        assert_eq!(images[&seg_id][9], 0x4F);

        // A segment that does not look like the descriptor table is untouched.
        let odd = vec![0xFF; 15];
        let mut images = BTreeMap::from([(seg_id.clone(), odd.clone())]);
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            &BTreeSet::from([1]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        );
        assert_eq!(images[&seg_id], odd);
    }

    /// Issue #126, 1.1.1 (2116REG): object 0 is linked and takes the
    /// project's T W R C (`47` became `5f`), and the template slots past the
    /// highest declared object keep their `17` (ETS only rewrites descriptors up
    /// to the last com-object `Number`).
    #[test]
    fn test_apply_sys7_group_object_links_object_zero_and_trailing_slots() {
        use bussard_model::Flags;
        let seg_id = "M-0004_A-7066-11-94AD-O000A_AS-43FE".to_string();
        let steps = vec![
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x0700,
                size: 450,
                mem_type: 2,
                seg_flags: 0xF2,
                checksum_ctrl: 0x00,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FE,
                size: 883,
                mem_type: 3,
                seg_flags: 0xF2,
                checksum_ctrl: 0x80,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
                }),
            },
        ];
        // The 2116REG template head: [CNT][RAM flags 0x0835], descriptor 0
        // `0702 47 00`, then two `17` slots standing in for 127 and 128.
        let template = vec![
            0x03, 0x08, 0x35, 0x07, 0x02, 0x47, 0x00, 0x08, 0x18, 0x17, 0x00, 0x08, 0x19, 0x17,
            0x00,
        ];
        let mut images = BTreeMap::from([(seg_id.clone(), template)]);
        let flags = BTreeMap::from([(
            0u16,
            Flags::COMMUNICATION | Flags::READ | Flags::WRITE | Flags::TRANSMIT,
        )]);
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            &BTreeSet::from([0]),
            &flags,
            &BTreeMap::new(),
            Some(0),
        );
        assert_eq!(
            images[&seg_id],
            vec![
                0x03, 0x08, 0x35, 0x07, 0x02, 0x5F, 0x00, 0x08, 0x18, 0x17, 0x00, 0x08, 0x19, 0x17,
                0x00
            ]
        );
    }

    /// Issue #117: the unlinked System 7 descriptors take the ComObjectRef the
    /// parameter values make visible. Object 0 has two refs behind a
    /// `<choose>` (T R, 1 bit / W, 2 bytes), object 1 is always shown, object
    /// 2 only under a branch that is not taken, so it keeps the template with C
    /// cleared. The bytes follow the 3361-1MWW capture (`df`/`0b` became
    /// `4b`, `13` or `db`).
    #[test]
    fn test_apply_sys7_group_object_links_takes_the_visible_ref()
    -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="A" MaskVersion="MV-0705" Name="s7dyn">
          <Static>
           <Parameters><Parameter Id="A_P-1" Name="type" Value="0" /></Parameters>
           <ParameterRefs><ParameterRef Id="A_P-1_R-1" RefId="A_P-1" /></ParameterRefs>
           <ComObjects>
            <ComObject Id="A_O-0" Number="0" ObjectSize="1 Bit" />
            <ComObject Id="A_O-1" Number="1" ObjectSize="1 Byte" />
            <ComObject Id="A_O-2" Number="2" ObjectSize="1 Bit" />
           </ComObjects>
           <ComObjectRefs>
            <ComObjectRef Id="A_O-0_R-1" RefId="A_O-0" TransmitFlag="Enabled" ReadFlag="Enabled" CommunicationFlag="Enabled" />
            <ComObjectRef Id="A_O-0_R-2" RefId="A_O-0" ObjectSize="2 Bytes" WriteFlag="Enabled" CommunicationFlag="Enabled" />
            <ComObjectRef Id="A_O-1_R-3" RefId="A_O-1" WriteFlag="Enabled" CommunicationFlag="Enabled" />
            <ComObjectRef Id="A_O-2_R-4" RefId="A_O-2" TransmitFlag="Enabled" CommunicationFlag="Enabled" />
           </ComObjectRefs>
          </Static>
          <Dynamic>
           <ChannelIndependentBlock>
            <ParameterBlock Id="A_PB-1" Name="main">
             <ParameterRefRef RefId="A_P-1_R-1" />
             <ComObjectRefRef RefId="A_O-1_R-3" />
             <choose ParamRefId="A_P-1_R-1">
              <when test="0"><ComObjectRefRef RefId="A_O-0_R-1" /></when>
              <when test="1"><ComObjectRefRef RefId="A_O-0_R-2" /></when>
              <when test="2"><ComObjectRefRef RefId="A_O-2_R-4" /></when>
             </choose>
            </ParameterBlock>
           </ChannelIndependentBlock>
          </Dynamic>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("A", xml.as_bytes())?;
        let seg_id = "A_AS-43FF".to_string();
        let steps = vec![
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x0700,
                size: 16,
                mem_type: 2,
                seg_flags: 0xF2,
                checksum_ctrl: 0x00,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FF,
                size: 15,
                mem_type: 3,
                seg_flags: 0xF2,
                checksum_ctrl: 0x80,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
                }),
            },
        ];
        // [CNT=3][RAM flags 0x070F][ptr CONFIG TYPE] x3, the template's C set.
        let template = vec![
            0x03, 0x07, 0x0F, 0x07, 0x00, 0xDF, 0x00, 0x07, 0x01, 0xDF, 0x07, 0x07, 0x02, 0xDF,
            0x00,
        ];
        let run = |value: &str| {
            let overrides = BTreeMap::from([("P-1_R-1".to_string(), value.to_string())]);
            let config = bussard_prod::dynamic::evaluate_dynamic(&app, &overrides);
            let defaults = sys7_object_defaults(&app, &config);
            let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);
            apply_sys7_group_object_links(
                &steps,
                &mut images,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &defaults,
                None,
            );
            images.remove(&seg_id).unwrap_or_default()
        };
        // Type 0: object 0 shows R-1 (T R), object 2 is hidden.
        assert_eq!(
            run("0"),
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0x4B, 0x00, 0x07, 0x01, 0x13, 0x07, 0x07, 0x02, 0xDB,
                0x00
            ]
        );
        // Type 1: object 0 shows R-2 (W, 2 bytes: TYPE 8).
        assert_eq!(
            run("1"),
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0x13, 0x08, 0x07, 0x01, 0x13, 0x07, 0x07, 0x02, 0xDB,
                0x00
            ]
        );
        // Type 2: object 0 is hidden, object 2 shows R-4 (T).
        assert_eq!(
            run("2"),
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0xDB, 0x00, 0x07, 0x01, 0x13, 0x07, 0x07, 0x02, 0x43,
                0x00
            ]
        );
        Ok(())
    }
    use bussard_prod::application::parse_application_program;

    /// A minimal single-application System B app: two relative segments (code +
    /// parameters) with a straightforward relative-segment procedure.
    fn fabricated_app() -> ApplicationProgram {
        // Code segment RS-1 carries a 6-byte code image (base64 of 00..05).
        // Parameter segment RS-2 has an 8-bit param at offset 0 default 7, over a
        // 1-byte zero base.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
          <Static>
           <Code>
            <RelativeSegment Id="M-1_A-1_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
            <RelativeSegment Id="M-1_A-1_RS-2" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
           </Code>
           <ParameterTypes><ParameterType Id="M-1_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
           <Parameters><Parameter Id="M-1_A-1_P-0" Name="thr" ParameterType="M-1_A-1_PT-0" Value="7"><Memory CodeSegment="M-1_A-1_RS-2" Offset="0" BitOffset="0" /></Parameter></Parameters>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
             <LdCtrlRelSegment LsmIdx="4" Size="1" AppliesTo="par" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="1" AppliesTo="par" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        parse_application_program("M-1_A-1", xml.as_bytes()).unwrap()
    }

    fn no_overrides() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    /// A fabricated System 7 (mask 0705) app in the MDT canonical LSM 1/2/3 shape
    /// (`[system7-spec §3]`): obj0/PID78 preflight, three LSMs, an AbsSegment with
    /// a per-byte `<Mask>` on LSM 1, an allocate-only RAM segment on LSM 3, a
    /// TaskSegment per LSM, a restart.
    fn fabricated_sys7_app() -> ApplicationProgram {
        // Segment images (base64): AS-1 = 4 bytes of table data at 0x4000 (mask
        // FF FF 00 FF -> byte 2 is device-owned); AS-3 = 2 bytes of param at
        // 0x4400; AS-2 (0x0700) is allocate-only (no <Data>).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-83_A-E" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-83_A-E_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data><Mask>//8A/w==</Mask></AbsoluteSegment>
            <AbsoluteSegment Id="M-83_A-E_AS-2" Size="8" Address="1792" />
            <AbsoluteSegment Id="M-83_A-E_AS-3" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlCompareProp ObjIdx="0" PropId="78" InlineData="00000000031200000000" />
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlUnload LsmIdx="2" />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="4" />
             <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="1792" Size="8" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
             <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        parse_application_program("M-83_A-E", xml.as_bytes()).unwrap()
    }

    /// A minimal System 7 app whose single `LdCtrlAbsSegment` carries the given
    /// LSM index, address and size — the knobs issue #81's range checks guard.
    fn sys7_app_with(lsm: u32, address: u32, size: u32) -> ApplicationProgram {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-83_A-F" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7Range" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code />
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlLoad LsmIdx="{lsm}" />
             <LdCtrlAbsSegment LsmIdx="{lsm}" Address="{address}" Size="{size}" />
             <LdCtrlLoadCompleted LsmIdx="{lsm}" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        parse_application_program("M-83_A-F", xml.as_bytes()).unwrap()
    }

    fn plan_sys7_range(
        lsm: u32,
        address: u32,
        size: u32,
    ) -> std::result::Result<FlashPlan, PlanError> {
        plan_flash(
            &sys7_app_with(lsm, address, size),
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
    }

    /// The top of the System 7 address space still plans: the record's 2-octet
    /// address field carries `0xFFFF` exactly.
    #[test]
    fn plan_sys7_accepts_the_last_16_bit_address() {
        let plan = plan_sys7_range(1, 0xFFFF, 1).expect("0xFFFF is the last addressable octet");
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7AbsSegment {
                address: 0xFFFF,
                size: 1,
                ..
            }
        )));
    }

    /// One past it is refused at plan time. Before issue #81 the executor
    /// truncated it with `as u16` and allocated at `0x0000` — a wrong frame on the
    /// bus before the following write refused.
    #[test]
    fn plan_sys7_refuses_an_address_past_16_bits() {
        match plan_sys7_range(1, 0x1_0000, 1) {
            Err(PlanError::Sys7FieldOutOfRange { field, value, .. }) => {
                assert_eq!(field, "segment address");
                assert_eq!(value, 0x1_0000);
            }
            other => panic!("expected Sys7FieldOutOfRange, got {other:?}"),
        }
    }

    /// A segment that starts inside the 16-bit space but runs past its end cannot
    /// be placed either.
    #[test]
    fn plan_sys7_refuses_a_segment_that_runs_past_the_top() {
        match plan_sys7_range(1, 0xFFF0, 0x20) {
            Err(PlanError::Sys7FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "segment end");
            }
            other => panic!("expected Sys7FieldOutOfRange, got {other:?}"),
        }
    }

    /// LSM 15 is the last index the record's opcode nibble can carry.
    #[test]
    fn plan_sys7_accepts_lsm_15() {
        let plan = plan_sys7_range(15, 0x4000, 4).expect("LSM 15 fits the opcode nibble");
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::Sys7StartLoading { lsm: 15 }))
        );
    }

    /// LSM 16 would wrap into index 0 (`16 << 4` truncates to `0x00`) and drive a
    /// different machine, so the plan is refused instead.
    #[test]
    fn plan_sys7_refuses_lsm_16() {
        match plan_sys7_range(16, 0x4000, 4) {
            Err(PlanError::Sys7LsmOutOfRange { lsm, .. }) => assert_eq!(lsm, 16),
            other => panic!("expected Sys7LsmOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn plan_lowers_system_7() {
        let app = fabricated_sys7_app();
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");
        assert!(plan.is_sys7(), "should be a System 7 plan");

        // The obj0/PID78 preflight lowers to a CompareProp.
        assert!(
            matches!(
                plan.steps.first(),
                Some(FlashStep::CompareProp {
                    obj_idx: 0,
                    prop_id: 78,
                    expected: Some(_),
                    ..
                })
            ),
            "first step is the obj0/PID78 preflight, got {:?}",
            plan.steps.first()
        );

        // Three unloads, one per LSM.
        let unloads: Vec<u32> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Sys7Unload { lsm } => Some(*lsm),
                _ => None,
            })
            .collect();
        assert_eq!(unloads, vec![1, 2, 3]);

        // The 0x4000 AbsSegment carries an image AND a mask (streamed under mask).
        let s7 = plan.sys7.as_ref().unwrap();
        let table_seg = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::Sys7AbsSegment {
                    address: 16384,
                    image: Some(img),
                    mem_type,
                    ..
                } => Some((img.clone(), *mem_type)),
                _ => None,
            })
            .expect("the 0x4000 AbsSegment with an image");
        assert_eq!(table_seg.1, 3, "0x4000 is EEPROM (mem_type 3)");
        assert!(
            s7.segment_masks.contains_key(&table_seg.0.segment_id),
            "the 0x4000 segment carries a <Mask>"
        );

        // The 0x0700 RAM region is allocate-only (no image) and RAM mem-type.
        let ram_seg = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::Sys7AbsSegment {
                    address: 1792,
                    image,
                    mem_type,
                    ..
                } => Some((image.is_none(), *mem_type)),
                _ => None,
            })
            .expect("the 0x0700 AbsSegment");
        assert!(ram_seg.0, "0x0700 is allocate-only (no <Data>)");
        assert_eq!(ram_seg.1, 2, "0x0700 is RAM (mem_type 2)");

        // TaskSegment finalizes LSM 1 and LSM 3; the last step is the restart.
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7TaskSegment {
                lsm: 1,
                address: 16384,
                ..
            }
        )));
        assert!(matches!(plan.steps.last(), Some(FlashStep::Restart)));
    }

    /// The System 7 parameter segment streams its `<Data>` with the
    /// parameters laid over it, not the raw template (issue #117): the Jung
    /// 3361-1MWW and 3181 segments went out as the vendor placeholder bytes,
    /// with every model override dropped.
    #[test]
    fn test_plan_flash_sys7_streams_the_parameter_image() -> Result<(), Box<dyn std::error::Error>>
    {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/11">
         <ApplicationProgram Id="M-83_A-F" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7P" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-83_A-F_AS-3" Size="3" Address="17408"><Data>BAUG</Data></AbsoluteSegment>
           </Code>
           <ParameterTypes>
            <ParameterType Id="M-83_A-F_PT-8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-83_A-F_P-1" Name="delay" ParameterType="M-83_A-F_PT-8" Value="17"><Memory CodeSegment="M-83_A-F_AS-3" Offset="0" BitOffset="0" /></Parameter>
            <Parameter Id="M-83_A-F_P-2" Name="level" ParameterType="M-83_A-F_PT-8" Value="1"><Memory CodeSegment="M-83_A-F_AS-3" Offset="1" BitOffset="0" /></Parameter>
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-83_A-F_P-1_R-1" RefId="M-83_A-F_P-1" />
            <ParameterRef Id="M-83_A-F_P-2_R-2" RefId="M-83_A-F_P-2" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="3" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="M-83_A-F_PB-1">
           <ParameterRefRef RefId="M-83_A-F_P-1_R-1" />
           <ParameterRefRef RefId="M-83_A-F_P-2_R-2" />
          </ParameterBlock></ChannelIndependentBlock></Dynamic>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-83_A-F", xml.as_bytes())?;
        let overrides: BTreeMap<String, String> =
            [("P-2_R-2".to_string(), "200".to_string())].into();
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0705,
            &overrides,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        // Byte 0: P-1's default 17 over the template's 04. Byte 1: the
        // override. Byte 2: no parameter, the template's 06.
        assert_eq!(plan.images.get("M-83_A-F_AS-3"), Some(&vec![17, 200, 6]));
        Ok(())
    }

    #[test]
    fn plan_lowers_system_7_task_ctrl1_and_post_restart_lsm5() {
        // The Theben FIX2 shape (§4.4/§4.7): a TaskCtrl1 on LSM 3, then a restart
        // followed by a post-restart TaskSegment + Load on LSM 5.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-48_A-4947" ApplicationNumber="18759" ApplicationVersion="16"
            MaskVersion="MV-0701" Name="FIX2" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-48_A-4947_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="16384" Size="4" />
             <LdCtrlTaskSegment LsmIdx="3" Address="18486" />
             <LdCtrlTaskCtrl1 LsmIdx="3" Address="18425" Count="1" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlTaskSegment LsmIdx="5" Address="17406" />
             <LdCtrlLoad LsmIdx="5" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-48_A-4947", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0701,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");

        // The TaskCtrl1 lowers to its own step.
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7TaskCtrl1 {
                lsm: 3,
                address: 18425,
                count: 1
            }
        )));
        // A post-restart LSM-5 TaskSegment + Load appears after the Restart.
        let restart_pos = plan
            .steps
            .iter()
            .position(|s| matches!(s, FlashStep::Restart))
            .expect("a restart");
        assert!(
            plan.steps[restart_pos + 1..]
                .iter()
                .any(|s| matches!(s, FlashStep::Sys7TaskSegment { lsm: 5, .. }))
        );
        assert!(
            plan.steps[restart_pos + 1..]
                .iter()
                .any(|s| matches!(s, FlashStep::Sys7StartLoading { lsm: 5 }))
        );
    }

    #[test]
    fn plan_lowers_system_7_compare_mem() {
        // The Zennio LUMENTO shape (§4.5): a raw LdCtrlCompareMem before the LSMs.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-71_A-3211" ApplicationNumber="12817" ApplicationVersion="18"
            MaskVersion="MV-0701" Name="LUMENTO" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-71_A-3211_AS-1" Size="2" Address="16384"><Data>AAE=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlCompareMem Address="46609" InlineData="3210" Size="2" />
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="2" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-71_A-3211", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0701,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7CompareMem { address: 46609, expected } if expected == &[0x32, 0x10]
        )));
    }

    #[test]
    fn sys7_profile_from_hawk_resolves_memory_mapped_addresses() {
        use bussard_prod::{HawkConfig, HawkResource};
        let mut resources = std::collections::HashMap::new();
        resources.insert(
            "GroupAddressTableLoadControl".to_string(),
            HawkResource {
                name: "GroupAddressTableLoadControl".to_string(),
                address_space: Some("StandardMemory".to_string()),
                start_address: Some(260), // 0x0104
                length: Some(12),
                flavour: Some("LoadControl_M112".to_string()),
            },
        );
        resources.insert(
            "GroupAddressTableLoadStatus".to_string(),
            HawkResource {
                name: "GroupAddressTableLoadStatus".to_string(),
                address_space: Some("StandardMemory".to_string()),
                start_address: Some(46826), // 0xB6EA
                length: Some(1),
                flavour: Some("LoadControl_M112".to_string()),
            },
        );
        let hawk = HawkConfig { resources };
        let profile = sys7_profile_from_hawk(&hawk).expect("a resolved profile");
        // A LoadControl_M112 @ StandardMemory Hawk block still resolves to the
        // memory-mapped realisation with the block's addresses (the data-driven
        // memory-mapped conformance path).
        assert_eq!(
            profile.lsm,
            bussard_mgmt::LsmRealisation::MemoryMapped {
                control_addr: 0x0104,
                status_addr: 0xB6EA,
            }
        );
        // It differs from the corpus default only in `lsm`: the M2 Jung 0705
        // capture proved the real default is property-based (issue #70), so the
        // corpus default is Property while this Hawk block selects MemoryMapped.
        assert_ne!(profile, bussard_mgmt::Sys7Profile::corpus_default());
        assert_eq!(
            bussard_mgmt::Sys7Profile::corpus_default().lsm,
            bussard_mgmt::LsmRealisation::Property
        );
        assert_eq!(profile.authorize_level, 0);
        assert_eq!(profile.eeprom_mem_type, 3);
        assert_eq!(profile.ram_mem_type, 2);

        // plan_flash_sys7_with_hawk lowers the same app with the Hawk profile.
        let app = fabricated_sys7_app();
        let plan = plan_flash_sys7_with_hawk(
            &app,
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            Some(&hawk),
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");
        assert!(plan.is_sys7());
    }

    #[test]
    fn plan_lowers_supported_procedure() {
        let app = fabricated_app();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(plan.identity.mask_version, "07B0");
        // Connect/Disconnect are session-boundary no-ops; 8 device steps remain.
        assert_eq!(
            plan.steps,
            vec![
                FlashStep::Unload { target: Some(4) },
                FlashStep::StartLoading { target: Some(4) },
                FlashStep::AllocateSegment {
                    size: 6,
                    target: Some(4),
                    fill: None,
                },
                FlashStep::WriteRelMem {
                    offset: 0,
                    image: ImageRef {
                        segment_id: "M-1_A-1_RS-1".to_string(),
                        kind: ImageKind::Code,
                        len: 6,
                    },
                    target: Some(0),
                },
                FlashStep::AllocateSegment {
                    size: 1,
                    target: Some(4),
                    fill: None,
                },
                FlashStep::WriteRelMem {
                    offset: 0,
                    image: ImageRef {
                        segment_id: "M-1_A-1_RS-2".to_string(),
                        kind: ImageKind::Parameters,
                        len: 1,
                    },
                    target: Some(0),
                },
                FlashStep::LoadCompleted { target: Some(4) },
                FlashStep::Restart,
            ]
        );
        // 6 code bytes + 1 param byte written.
        assert_eq!(plan.total_write_bytes(), 7);
        // The parameter image reflects the default 7.
        assert_eq!(plan.param_images["M-1_A-1_RS-2"], vec![7]);
    }

    #[test]
    fn write_rel_mem_without_applies_to_streams_the_parameter_image() {
        // The KNX-Virtual DA.tp shape: a single 256-byte relative segment whose
        // `<Data>` base is all 0xFF, a parameter placing a non-0xFF value into it,
        // and an app-segment `LdCtrlWriteRelMem` with NO `AppliesTo`. ETS writes the
        // *computed* parameter image (base + parameters), not the raw 0xFF `<Data>`.
        // The lowered write must therefore resolve to the parameter image, or the
        // device is streamed a content-incomplete all-0xFF image and discards the
        // load on restart.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-P" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="Par" LoadProcedureStyle="ProductDefault">
          <Static>
           <Code>
            <RelativeSegment Id="M-1_A-P_RS-04" Size="4" LoadStateMachine="4" Offset="0"><Data>/////w==</Data></RelativeSegment>
           </Code>
           <ParameterTypes><ParameterType Id="M-1_A-P_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
           <Parameters><Parameter Id="M-1_A-P_P-0" Name="speed" ParameterType="M-1_A-P_PT-0" Value="5"><Memory CodeSegment="M-1_A-P_RS-04" Offset="0" BitOffset="0" /></Parameter></Parameters>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="4" />
             <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="4" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-P", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();

        // The (only) relative-memory write must stream the PARAMETER image.
        let write = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::WriteRelMem { image, .. } => Some(image),
                _ => None,
            })
            .expect("the procedure lowers a WriteRelMem");
        assert_eq!(
            write.kind,
            ImageKind::Parameters,
            "an attribute-less WriteRelMem into a parameter-bearing segment must stream \
             the computed parameter image, not the raw <Data> base"
        );
        // The computed image is the 0xFF base with the parameter's default (5) laid
        // over byte 0 — NOT the raw all-0xFF <Data>.
        assert_eq!(
            plan.param_images["M-1_A-P_RS-04"],
            vec![5, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn plan_lowers_master_reset() {
        // An LdCtrlMasterReset mid-procedure (KNX-Virtual shape) lowers to a
        // MasterReset step carrying the op's EraseCode/ChannelNumber, between the
        // allocate and the write. It is NOT refused as an unsupported op.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-MR" MaskVersion="MV-07B0" Name="MR"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code><RelativeSegment Id="M-1_A-MR_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlMasterReset EraseCode="4" ChannelNumber="0" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-MR", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        // The master reset sits between the allocation and the write.
        let mr_pos = plan
            .steps
            .iter()
            .position(|s| matches!(s, FlashStep::MasterReset { .. }))
            .expect("the master reset lowers to a step");
        assert!(matches!(
            plan.steps[mr_pos],
            FlashStep::MasterReset {
                erase_code: 4,
                channel_number: 0
            }
        ));
        let alloc_pos = plan
            .steps
            .iter()
            .position(|s| matches!(s, FlashStep::AllocateSegment { .. }))
            .unwrap();
        let write_pos = plan
            .steps
            .iter()
            .position(|s| matches!(s, FlashStep::WriteRelMem { .. }))
            .unwrap();
        assert!(
            alloc_pos < mr_pos && mr_pos < write_pos,
            "steps {:?}",
            plan.steps
        );
        // The trace names the reconnect-and-resume master-reset step.
        assert!(trace(&plan).iter().any(|l| l.contains("master reset")));
    }

    #[test]
    fn test_fill_regions_skips_fill_and_merges_small_gaps() {
        let image = [0, 0, 1, 2, 0, 3, 0, 0, 0, 0, 0, 0, 4, 0];
        let regions = fill_regions(&image, 0);
        assert_eq!(
            regions,
            vec![(2usize, &image[2..6]), (12usize, &image[12..13])]
        );
        // All fill: nothing to write.
        assert!(fill_regions(&[0xFF; 8], 0xFF).is_empty());
        // Composing the regions over the fill reproduces the image.
        let mut composed = vec![0u8; image.len()];
        for (start, run) in fill_regions(&image, 0) {
            composed[start..start + run.len()].copy_from_slice(run);
        }
        assert_eq!(composed, image);
    }

    #[test]
    fn plan_threads_rel_segment_fill_flag_data_driven() {
        // Item 1 (issue #73): the `LdCtrlRelSegment` `Fill`/`FillByte` is
        // per-product, not a blanket rule. A procedure that sets `Fill="1"` on the
        // code segment (the Jung LED A-3030 shape, obj4 alloc
        // `030b000028c1 01 00 0000`) must lower to `AllocateSegment { fill:
        // Some(0) }`; a DA.tp-shape procedure with no `Fill` attribute must stay
        // `fill: None` so its allocation is byte-identical to before.
        let fill_xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-FILL" MaskVersion="MV-07B0" Name="Fill"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code><RelativeSegment Id="M-1_A-FILL_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" Fill="1" />
             <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-FILL", fill_xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        let fill = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::AllocateSegment { fill, .. } => Some(*fill),
                _ => None,
            })
            .expect("the procedure lowers an AllocateSegment");
        assert_eq!(
            fill,
            Some(0),
            "a Fill=\"1\" code-segment allocation must carry the pre-fill flag"
        );

        // The DA.tp shape (no `Fill`) must keep the historical no-fill allocation.
        let da_tp_xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-DATP" MaskVersion="MV-07B0" Name="DaTp"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code><RelativeSegment Id="M-1_A-DATP_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-DATP", da_tp_xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        let fill = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::AllocateSegment { fill, .. } => Some(*fill),
                _ => None,
            })
            .expect("the procedure lowers an AllocateSegment");
        assert_eq!(
            fill, None,
            "a DA.tp-shape allocation (no Fill) must stay no-fill (byte-identical)"
        );
    }

    #[test]
    fn plan_defaults_master_reset_erase_code() {
        // An LdCtrlMasterReset with no attributes defaults EraseCode to 1
        // ("Confirmed Restart") and ChannelNumber to 0.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-MR2" MaskVersion="MV-07B0" Name="MR2">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlMasterReset />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-MR2", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::MasterReset {
                erase_code: 1,
                channel_number: 0
            }
        )));
    }

    #[test]
    fn plan_refuses_non_system_b() {
        // System 2 (0x0300): neither System B nor System 7, refused at the gate.
        // (System 7 masks 0705/0701 are now supported — issue #49 — so they no
        // longer hit this gate; see `plan_lowers_system_7`.)
        let app = fabricated_app();
        let err = plan_flash(
            &app,
            "1.1.4",
            0x0300,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(matches!(err, PlanError::NotSystemB { .. }), "{err:?}");
    }

    #[test]
    fn plan_refuses_mask_mismatch() {
        // App declares MV-07B0 but the device is a different System B medium
        // (0x57B0 IP): the exact-mask compare refuses it.
        let app = fabricated_app();
        let err = plan_flash(
            &app,
            "1.1.4",
            0x57B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(matches!(err, PlanError::MaskMismatch { .. }), "{err:?}");
    }

    #[test]
    fn plan_refuses_unsupported_op() {
        // An app whose procedure carries a task-segment op (device-side
        // behaviour bussard cannot yet verify) is refused whole, at pre-flight.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-2" MaskVersion="MV-07B0" Name="Merged">
          <Static>
           <Code><RelativeSegment Id="M-1_A-2_RS-1" Size="4" LoadStateMachine="4" Offset="0"><Data>AAECAw==</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure MergeId="1">
             <LdCtrlTaskSegment LsmIdx="4" Address="16384" />
             <LdCtrlRelSegment LsmIdx="4" Size="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-2", xml.as_bytes()).unwrap();
        let err = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap_err();
        match err {
            PlanError::UnsupportedOp { op } => assert!(op.contains("TaskSegment"), "{op}"),
            other => panic!("expected UnsupportedOp, got {other:?}"),
        }
    }

    #[test]
    fn plan_lowers_load_image_prop() {
        // A procedure in the real MDT A-0007 / Jung 23024 shape: allocate +
        // write a combined full,par segment, then LoadImageProp x4 for the MCB
        // integrity check. Every LoadImageProp lowers (none is refused); the
        // ones following the write carry the written image for CRC validation.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-3" ApplicationNumber="7" ApplicationVersion="35"
            MaskVersion="MV-07B0" Name="AKK" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code><RelativeSegment Id="M-1_A-3_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure MergeId="1">
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" />
             <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="6" Verify="true" />
             <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />
             <LdCtrlLoadImageProp ObjIdx="2" PropId="27" />
             <LdCtrlLoadImageProp ObjIdx="3" PropId="27" />
             <LdCtrlLoadImageProp ObjIdx="4" PropId="27" Count="2" />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-3", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();

        let image_props: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::LoadImageProp { .. }))
            .collect();
        assert_eq!(image_props.len(), 4, "all four LoadImageProp ops lower");
        // Each carries the written image (the full,par segment) for CRC checking.
        for step in &image_props {
            match step {
                FlashStep::LoadImageProp {
                    prop_id,
                    image,
                    count,
                    ..
                } => {
                    assert_eq!(*prop_id, 27);
                    assert!(*count >= 1);
                    let img = image.as_ref().expect("image resolved after the write");
                    assert_eq!(img.segment_id, "M-1_A-3_RS-1");
                    assert_eq!(img.len, 6);
                }
                other => panic!("expected LoadImageProp, got {other:?}"),
            }
        }
        // The last op carries Count=2.
        assert!(matches!(
            image_props[3],
            FlashStep::LoadImageProp { count: 2, .. }
        ));
        // The trace names the verify step.
        assert!(trace(&plan).iter().any(|l| l.contains("verify image")));
    }

    #[test]
    fn plan_dedupes_identical_consecutive_allocations() {
        // The real MDT A-0007 shape: the MergeId=2 block carries TWO
        // <LdCtrlRelSegment> ops for one segment — AppliesTo="full" and
        // AppliesTo="par", both LsmIdx=4 Size=6 — followed by a single combined
        // full,par WriteRelMem. The two identical allocations of the same segment
        // must collapse to ONE AllocateSegment step (the second is redundant and
        // is the step KV chokes on), while the write still runs once.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-83_A-7" ApplicationNumber="7" ApplicationVersion="35"
            MaskVersion="MV-07B0" Name="AKK" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code><RelativeSegment Id="M-83_A-7_RS-4" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure MergeId="2">
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" />
             <LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="6" Mode="0" Fill="0" />
            </LoadProcedure>
            <LoadProcedure MergeId="4">
             <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="6" Verify="true" />
            </LoadProcedure>
            <LoadProcedure MergeId="7">
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-83_A-7", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();

        let allocs = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::AllocateSegment { .. }))
            .count();
        assert_eq!(
            allocs, 1,
            "two identical consecutive allocations of the same segment must \
             collapse to one, got steps {:?}",
            plan.steps
        );
        // The single write still runs.
        assert_eq!(
            plan.steps
                .iter()
                .filter(|s| matches!(s, FlashStep::WriteRelMem { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn plan_dedupes_a_restated_allocation_when_segments_span_several_lsms() {
        // The real ABB/BJE i-bus shape (M-0002_A-0806-71-AD30-O0007, issue #113):
        // the app declares TWO relative segments on DIFFERENT load state machines
        // — RS-03 (LSM 3, the group-object-table segment) and RS-04 (LSM 4, the
        // app segment) — and its MergeId=2 block restates one LSM-4 allocation
        // twice (AppliesTo="full" then ="par", both LsmIdx=4 Size=6). Binding the
        // ops in document order pinned the first to RS-03 and the second to RS-04,
        // so the restatement looked like two distinct segments and lowered two
        // identical AllocateSegment steps. Both ops name LSM 4, so both must bind
        // RS-04 and collapse to one allocation — and the write must stream RS-04.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-2_A-806" ApplicationNumber="2054" ApplicationVersion="113"
            MaskVersion="MV-07B0" Name="ABB" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code>
            <RelativeSegment Id="M-2_A-806_RS-04-00000" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
            <RelativeSegment Id="M-2_A-806_RS-03-00000" Size="3" LoadStateMachine="3" Offset="0"><Data>AAEC</Data></RelativeSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure MergeId="2">
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" />
             <LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="6" Mode="0" Fill="0" />
            </LoadProcedure>
            <LoadProcedure MergeId="4">
             <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="6" Verify="true" />
            </LoadProcedure>
            <LoadProcedure MergeId="7">
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-2_A-806", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();

        let allocs: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::AllocateSegment { .. }))
            .collect();
        assert_eq!(
            allocs.len(),
            1,
            "a restated LSM-4 allocation must collapse even when the app declares \
             another relative segment on a different LSM, got steps {:?}",
            plan.steps
        );
        assert!(matches!(
            allocs[0],
            FlashStep::AllocateSegment {
                size: 6,
                target: Some(4),
                ..
            }
        ));
        // The write binds the LSM-4 segment, and the LSM-3 segment (which this
        // procedure never allocates) is not pulled into the plan's images.
        let writes: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::WriteRelMem { .. }))
            .collect();
        assert_eq!(writes.len(), 1);
        match writes[0] {
            FlashStep::WriteRelMem { image, .. } => {
                assert_eq!(image.segment_id, "M-2_A-806_RS-04-00000");
                assert_eq!(image.len, 6);
            }
            other => panic!("expected WriteRelMem, got {other:?}"),
        }
        assert!(
            !plan.images.contains_key("M-2_A-806_RS-03-00000"),
            "the LSM-3 segment is never allocated by this procedure"
        );
    }

    #[test]
    fn plan_keeps_distinct_allocations() {
        // Two RelSegment ops for DIFFERENT segments (different sizes) must NOT be
        // deduped — the fabricated app allocates a 6-byte code segment and a
        // 1-byte parameter segment.
        let app = fabricated_app();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        let allocs = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::AllocateSegment { .. }))
            .count();
        assert_eq!(allocs, 2, "distinct segments keep distinct allocations");
    }

    #[test]
    fn plan_lowers_compare_prop() {
        // The MDT SCN-DA64x DALI-gateway shape: a CompareProp precondition (with
        // InlineData + OnError child) before the download proper. It must lower to
        // an executable CompareProp step carrying the expected bytes, not refuse.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-4" ApplicationNumber="8" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="DALI" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code><RelativeSegment Id="M-1_A-4_RS-1" Size="4" LoadStateMachine="4" Offset="0"><Data>AAECAw==</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure MergeId="1">
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlCompareProp InlineData="00000001620100000000" ObjIdx="0" PropId="78">
              <OnError Cause="CompareMismatch" MessageRef="M-1_A-4_M-1" />
             </LdCtrlCompareProp>
             <LdCtrlCompareProp InlineData="00010000" Mask="00FF0000" ObjIdx="0" PropId="19" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="4" />
             <LdCtrlWriteRelMem AppliesTo="full" ObjIdx="0" Offset="0" Size="4" />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-4", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();

        let compares: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::CompareProp { .. }))
            .collect();
        assert_eq!(compares.len(), 2, "both CompareProp ops lower");
        match compares[0] {
            FlashStep::CompareProp {
                obj_idx,
                prop_id,
                expected,
                mask,
            } => {
                assert_eq!(*obj_idx, 0);
                assert_eq!(*prop_id, 78);
                assert_eq!(
                    expected.as_deref(),
                    Some([0x00, 0x00, 0x00, 0x01, 0x62, 0x01, 0x00, 0x00, 0x00, 0x00].as_slice())
                );
                assert!(mask.is_none());
            }
            other => panic!("expected CompareProp, got {other:?}"),
        }
        // The masked compare carries its mask.
        assert!(matches!(
            compares[1],
            FlashStep::CompareProp {
                mask: Some(_),
                prop_id: 19,
                ..
            }
        ));
        // The trace names the verify-property step.
        assert!(trace(&plan).iter().any(|l| l.contains("verify property")));
    }

    #[test]
    fn plan_refuses_unknown_parameter_override_key() {
        // A parameter override naming a ref-id this application does not define is
        // a pre-flight refusal that names the offending key — the device is never
        // touched with an unresolvable parameter image.
        let app = fabricated_app();
        let mut ov = BTreeMap::new();
        ov.insert("P-999_R-1".to_string(), "1".to_string());
        let err = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &ov,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap_err();
        match err {
            PlanError::UnresolvableImage { reason, .. } => {
                assert!(reason.contains("P-999"), "must name the key: {reason}");
            }
            other => panic!("expected UnresolvableImage, got {other:?}"),
        }
    }

    #[test]
    fn plan_applies_parameter_override_to_image() {
        // A valid ref-id override changes the computed parameter image the plan
        // carries (proving the re-keyed override flows into plan_flash).
        let app = fabricated_app();
        let mut ov = BTreeMap::new();
        ov.insert("P-0_R-1".to_string(), "99".to_string());
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &ov,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(plan.param_images["M-1_A-1_RS-2"], vec![99]);
    }

    #[test]
    fn select_application_disambiguates() {
        let a = fabricated_app();
        let b = {
            let mut b = fabricated_app();
            b.id = "M-1_A-9".to_string();
            b
        };
        let cands: Vec<&ApplicationProgram> = vec![&a, &b];
        // No selection with two candidates is ambiguous.
        assert!(matches!(
            select_application(&cands, None),
            Err(PlanError::AmbiguousApplication { .. })
        ));
        // Naming one selects it.
        assert_eq!(
            select_application(&cands, Some("M-1_A-9")).unwrap().id,
            "M-1_A-9"
        );
        // A single candidate needs no name.
        assert_eq!(select_application(&[&a], None).unwrap().id, "M-1_A-1");
    }

    #[test]
    fn trace_renders_every_step() {
        let app = fabricated_app();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        let lines = trace(&plan);
        assert_eq!(lines.len(), plan.steps.len());
        assert!(lines[0].contains("unload"));
        assert!(lines.last().unwrap().contains("restart"));
    }

    #[test]
    fn estimates_are_sane() {
        let app = fabricated_app();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        // 7 bytes fit in one conservative 12-octet chunk each write → 2 frames.
        assert_eq!(plan.estimated_write_frames(), 2);
        assert!(plan.estimated_duration().as_millis() >= 40);
    }

    // ---------------------------------------------------------------------
    // Issue #53: address-arithmetic bounds at plan pre-flight.
    // ---------------------------------------------------------------------

    #[test]
    fn plan_refuses_write_rel_mem_offset_past_24bit_space() {
        // A WriteRelMem whose offset alone lands the write past the 24-bit
        // extended-memory space (0xFF_FFFF) must be refused at plan time (the
        // segment base is added at flash time and is >= 0, so the range already
        // exceeds the addressable space). This is the raised ceiling: an offset
        // past 0xFFFF but within 24 bits is now valid (the extended service
        // reaches it), so only an offset past the 24-bit space is refused.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-7" MaskVersion="MV-07B0" Name="Overflow">
          <Static>
           <Code><RelativeSegment Id="M-1_A-7_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="16777215" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-7", xml.as_bytes()).unwrap();
        let err = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap_err();
        match err {
            PlanError::AddressOutOfRange { end, .. } => {
                assert!(
                    end > MAX_MEMORY_END,
                    "end {end} must exceed the 24-bit space"
                );
            }
            other => panic!("expected AddressOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn plan_accepts_write_rel_mem_offset_above_16bit_space() {
        // A WriteRelMem at an offset past 0xFFFF but inside the 24-bit space is now
        // planned (the extended service reaches it) — the old 16-bit refusal is
        // gone. The plain-vs-extended selection is deferred to flash time from the
        // device-supplied base + offset.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-7b" MaskVersion="MV-07B0" Name="ExtOffset">
          <Static>
           <Code><RelativeSegment Id="M-1_A-7b_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="65540" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-7b", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .expect("an offset above 0xFFFF but within 24 bits must plan via the extended service");
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::WriteRelMem { offset, .. } if *offset == 65540)),
            "the WriteRelMem step must survive lowering"
        );
    }

    #[test]
    fn plan_refuses_write_mem_address_past_24bit_space() {
        // An absolute WriteMem at an address past the 24-bit space (0xFF_FFFF) is
        // refused (a cast would silently truncate and stream to the wrong memory).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-8" MaskVersion="MV-07B0" Name="AbsOverflow">
          <Static>
           <Code><AbsoluteSegment Id="M-1_A-8_AS-1" Address="16777214" Size="4"><Data>AAECAw==</Data></AbsoluteSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="0" />
             <LdCtrlWriteMem Address="16777214" Size="4" />
             <LdCtrlLoadCompleted LsmIdx="0" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-8", xml.as_bytes()).unwrap();
        let err = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PlanError::AddressOutOfRange { .. }),
            "expected AddressOutOfRange, got {err:?}"
        );
    }

    #[test]
    fn plan_refuses_absurd_segment_allocation_size() {
        // A RelSegment declaring a multi-gigabyte size is corrupt input; refuse
        // it before it becomes a huge allocation request.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-A" MaskVersion="MV-07B0" Name="HugeAlloc">
          <Static>
           <Code><RelativeSegment Id="M-1_A-A_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="4000000000" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-A", xml.as_bytes()).unwrap();
        let err = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PlanError::AddressOutOfRange { .. }),
            "expected AddressOutOfRange, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------
    // Issue #54: LdCtrlWriteProp value parse, lowering and refusal.
    // ---------------------------------------------------------------------

    /// An app whose procedure carries a single value-carrying WriteProp.
    fn app_with_write_prop(inline_data: &str, obj_idx: &str, prop_id: &str) -> ApplicationProgram {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-W" MaskVersion="MV-07B0" Name="WriteProp">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="0" />
             <LdCtrlWriteProp ObjIdx="{obj_idx}" ObjType="11" PropId="{prop_id}" InlineData="{inline_data}" />
             <LdCtrlLoadCompleted LsmIdx="0" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        parse_application_program("M-1_A-W", xml.as_bytes()).unwrap()
    }

    #[test]
    fn plan_lowers_value_carrying_write_prop_as_real_write() {
        // A WriteProp carrying InlineData lowers to an executable WriteProp step
        // with the decoded value — a real write in the plan, not a skipped no-op.
        let app = app_with_write_prop("0102", "0", "204");
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        let write_props: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::WriteProp { .. }))
            .collect();
        assert_eq!(write_props.len(), 1, "the value-carrying WriteProp lowers");
        match write_props[0] {
            FlashStep::WriteProp {
                obj_idx,
                prop_id,
                value,
                ..
            } => {
                assert_eq!(*obj_idx, 0);
                assert_eq!(*prop_id, 204);
                assert_eq!(value, &vec![0x01, 0x02]);
            }
            other => panic!("expected WriteProp, got {other:?}"),
        }
        // The trace renders it as a real property write, not "skipped".
        let line = trace(&plan)
            .into_iter()
            .find(|l| l.contains("write property"))
            .expect("a write-property line is rendered");
        assert!(line.contains("2 byte"), "renders the value length: {line}");
    }

    #[test]
    fn plan_skips_bare_write_prop_without_emitting_a_step() {
        // A bare WriteProp (no InlineData) carries no value: the device seeds the
        // property on LoadCompleted. It must NOT lower to a WriteProp step, so it
        // can never be rendered as an executed write.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-B" MaskVersion="MV-07B0" Name="BareWriteProp">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="0" />
             <LdCtrlWriteProp ObjType="11" PropId="204" />
             <LdCtrlLoadCompleted LsmIdx="0" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-B", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| matches!(s, FlashStep::WriteProp { .. })),
            "a bare WriteProp must not lower to an executed step: {:?}",
            plan.steps
        );
    }

    #[test]
    fn plan_refuses_write_prop_shape_it_cannot_execute() {
        // A value-carrying WriteProp whose object index exceeds the 8-bit space
        // the property-write primitive addresses is refused at pre-flight rather
        // than dropped at execute time.
        let app = app_with_write_prop("01", "9999", "204");
        let err = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap_err();
        match err {
            PlanError::UnsupportedWriteProp { reason, .. } => {
                assert!(reason.contains("object index"), "{reason}");
            }
            other => panic!("expected UnsupportedWriteProp, got {other:?}"),
        }
    }

    #[test]
    fn resolve_object_target_uses_the_lsm_index_when_the_device_exposes_it() {
        // KNX-Virtual shape: obj0=device, obj1=address, obj2=association,
        // obj3=application-program (the type-discovered app object), obj4=app
        // segment. The app segment write names ObjIdx=4 → device object 4, NOT the
        // type-discovered obj3 (the divergence-#2 fix). Present indices resolve
        // literally regardless of the splice mode.
        let table = vec![(0u8, 0u16), (1, 1), (2, 2), (3, 3), (4, 4)];
        let app_obj = 3; // discovered by type OT_APPLICATION_PROGRAM
        assert_eq!(
            resolve_object_target_opt(Some(4), &table, app_obj, false),
            Some(4)
        );
        assert_eq!(
            resolve_object_target_opt(Some(1), &table, app_obj, false),
            Some(1)
        );
        assert_eq!(
            resolve_object_target_opt(Some(4), &table, app_obj, true),
            Some(4)
        );
    }

    #[test]
    fn resolve_object_target_falls_back_to_the_app_object_when_not_spliced() {
        // A conformant thelsing device: only obj0..obj3, app object at index 3, and
        // the procedure writes with ObjIdx=0 / LsmIdx=4. Index 0 (device object) and
        // index 4 (absent) both fall back to the discovered app object, preserving
        // the single-object ProductDefault behaviour — but only for a
        // non-spliced (self-contained) procedure.
        let table = vec![(0u8, 0u16), (1, 1), (2, 2), (3, 3)];
        let app_obj = 3;
        assert_eq!(
            resolve_object_target_opt(Some(0), &table, app_obj, false),
            Some(app_obj)
        );
        assert_eq!(
            resolve_object_target_opt(Some(4), &table, app_obj, false),
            Some(app_obj)
        );
        assert_eq!(
            resolve_object_target_opt(None, &table, app_obj, false),
            Some(app_obj)
        );
    }

    #[test]
    fn resolve_object_target_skips_absent_index_when_spliced() {
        // A master-template multi-object download against a device without obj5:
        // the template's LSM5 ops must be SKIPPED (None), not redirected onto the
        // app object. A None/0 target still resolves to the app object.
        let table = vec![(0u8, 0u16), (1, 1), (2, 2), (3, 3), (4, 4)];
        let app_obj = 4;
        assert_eq!(
            resolve_object_target_opt(Some(5), &table, app_obj, true),
            None
        );
        assert_eq!(
            resolve_object_target_opt(Some(0), &table, app_obj, true),
            Some(app_obj)
        );
        assert_eq!(
            resolve_object_target_opt(None, &table, app_obj, true),
            Some(app_obj)
        );
    }

    #[test]
    fn plan_targets_the_obj_idx_of_the_write_not_the_type() {
        // A DA.tp-shaped write: RelSegment LsmIdx=4, then WriteRelMem ObjIdx=4. The
        // lowered steps carry those indices verbatim so the executor resolves the
        // write to device object 4 (base 0x6000), not the type-discovered object.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-DA" MaskVersion="MV-07B0" Name="DA"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code><RelativeSegment Id="M-1_A-DA_RS-04" Size="256" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="256" />
             <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="256" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-DA", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        // The allocate targets LsmIdx=4; the write targets ObjIdx=4.
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::AllocateSegment {
                target: Some(4),
                ..
            }
        )));
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::WriteRelMem {
                target: Some(4),
                ..
            }
        )));
    }

    #[test]
    fn test_manufacturer_from_app_id_parses_prefix() {
        assert_eq!(
            manufacturer_from_app_id("M-00FA_A-2500-10-51CB"),
            Some(0x00FA)
        );
        assert_eq!(manufacturer_from_app_id("M-0083_A-0007"), Some(0x0083));
        assert_eq!(manufacturer_from_app_id("not-a-manufacturer-id"), None);
        assert_eq!(manufacturer_from_app_id("M-XZ"), None);
    }

    #[test]
    fn test_app_program_version_value_synthesizes_da_tp_id() {
        // A DA.tp-shaped app: M-00FA, ApplicationNumber 9472 (0x2500), version
        // 16 (0x10). ETS wrote `00 fa 25 00 10` to obj4 PID 13.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-00FA_A-2500-10-51CB" ApplicationNumber="9472"
            ApplicationVersion="16" MaskVersion="MV-07B0" Name="Dimming"
            LoadProcedureStyle="MergedProcedure"><Static /></ApplicationProgram></KNX>"#;
        let app =
            parse_application_program("M-00FA_A-2500-10-51CB", xml.as_bytes()).expect("parse");
        assert_eq!(
            app_program_version_value(&app),
            Some([0x00, 0xFA, 0x25, 0x00, 0x10])
        );
    }

    #[test]
    fn test_maybe_substitute_app_id_replaces_only_the_placeholder() {
        let app_id = [0x00u8, 0xFA, 0x25, 0x00, 0x10];
        // PID 13 + the all-zero placeholder → substituted with the app id.
        assert_eq!(
            maybe_substitute_app_id(13, Some(&[0, 0, 0, 0, 0]), Some(&app_id)),
            Some(app_id.to_vec())
        );
        // PID 13 but a concrete (non-placeholder) value → left verbatim.
        assert_eq!(
            maybe_substitute_app_id(13, Some(&[1, 2, 3, 4, 5]), Some(&app_id)),
            Some(vec![1, 2, 3, 4, 5])
        );
        // A different PID → never substituted, even for a zero value.
        assert_eq!(
            maybe_substitute_app_id(5, Some(&[0, 0, 0, 0, 0]), Some(&app_id)),
            Some(vec![0, 0, 0, 0, 0])
        );
        // No app id available → placeholder left as-is (a partly-zero id is worse).
        assert_eq!(
            maybe_substitute_app_id(13, Some(&[0, 0, 0, 0, 0]), None),
            Some(vec![0, 0, 0, 0, 0])
        );
    }
}
