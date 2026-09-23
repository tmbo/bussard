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
//!
//! # Module layout
//!
//! The engine is split by phase (issue #81). This file holds the public surface:
//! the validated [`FlashPlan`] and its [`FlashStep`]s, [`PlanError`], the options
//! and progress types, and [`FlashOutcome`].
//!
//! - `plan`: System B planning ([`plan_flash`], template splicing, RelSegment
//!   binding, table images).
//! - `plan_sys7`: System 7 planning ([`plan_flash_sys7_with_hawk`], the table
//!   synthesis from a System B model, the group-object descriptor post-pass).
//! - `session`: the [`Session`] over a [`Connector`], reconnect and resume.
//! - `execute`: the System B executor loop ([`flash`]), object discovery and the
//!   factory reset step.
//! - `execute_sys7`: the System 7 executor and its post-load verification.
//! - `verify`: the resident-MCB skip gate and the post-load MCB and spot-check
//!   verification.
//! - `labels`: step labels and the dry-run [`trace`].
//!
//! [`ApplicationProgram`]: bussard_prod::application::ApplicationProgram
//! [`LoadProcedure`]: bussard_prod::application::LoadProcedure
//! [`LoadOp`]: bussard_prod::application::LoadOp
//! [`write_load_control`]: bussard_mgmt::load::write_load_control
//! [`allocate_segment`]: bussard_mgmt::load::allocate_segment
//! [`write_property`]: bussard_mgmt::load::write_property
//! [`compare_property`]: bussard_mgmt::load::compare_property
//! [`compare_rel_mem`]: bussard_mgmt::load::compare_rel_mem
//! [`read_mcb_table`]: bussard_mgmt::load::read_mcb_table

use bussard_mgmt::load::LoadState;
use std::collections::BTreeMap;

mod execute;
mod execute_sys7;
mod labels;
mod plan;
mod plan_sys7;
mod session;
#[cfg(test)]
mod test_support;
mod verify;

pub(crate) use execute::probe_object_types;
pub use execute::{discover_application_object, flash};
use labels::step_label;
pub use labels::trace;
use plan::{MAX_MEMORY_END, insert_factory_reset, manufacturer_from_app_id};
pub use plan::{plan_flash, plan_flash_with_object_flags, select_application};
pub(crate) use plan_sys7::sys7_lsm_override;
pub use plan_sys7::{
    Sys7PlanTables, Sys7TableImage, linked_flags_from_system_b, plan_flash_sys7_with_hawk,
    sys7_profile_from_hawk, sys7_tables_from_system_b,
};
pub use session::{Connector, DeviceFacts, Session, SingleConnector};

/// A step of a validated flash, ready to render for the pre-flight display and
/// to execute in order. Each corresponds to one supported [`LoadOp`](bussard_prod::application::LoadOp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashStep {
    /// Drop a loadable object to `Unloaded` (`LdCtrlUnload`).
    Unload {
        /// The op's `LsmIdx`, resolved to a device object index at execute time
        /// (see [`resolve_object_target_opt`](execute::resolve_object_target_opt)). `None` (op carried no `LsmIdx`) or an
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
        /// time. See [`read_mcb_table`](bussard_mgmt::load::read_mcb_table).
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
    /// ([`MAX_WRITE_SPAN`](plan::MAX_WRITE_SPAN)). Refused at pre-flight so the device is never streamed
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

#[cfg(test)]
mod tests {

    use crate::flash::plan::plan_flash;
    use crate::flash::test_support::{fabricated_app, no_overrides};
    use std::collections::BTreeMap;

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
}
