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
//! the KNX load-state machine and the System B device-side realisation in
//! thelsing/knx (`bau_systemB.cpp`, `table_object.cpp`,
//! `application_program_object.cpp` — a permitted, non-GPL behavioural reference;
//! semantics only, no code copied):
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
//! | `LoadImageProp{oi,pid}`| [`read_mcb_table`]                                | reads the object's `PID_MCB_TABLE` and checks the device CRC over the stored segment against the written image |
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
//! the engine never begins writing a procedure it cannot finish. Every memory
//! write is read-back-verified and every property/load-control write is
//! confirmed, so a device that drops or refuses a write fails loudly at that op.

use std::collections::BTreeMap;

use bussard_mgmt::MgmtError;
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{
    self, LoadControl, LoadState, WriteError, allocate_segment, compare_property,
    master_reset_via_basic_restart, read_load_state, read_mcb_table, write_load_control,
    write_property,
};
use bussard_mgmt::tables::{OT_APPLICATION_PROGRAM, PID_OBJECT_TYPE};
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
        /// How many MCB elements to read (`Count`), at least 1.
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
    Restart,
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
         RelSegment/WriteRelMem/WriteMem/WriteProp/CompareProp/LoadImageProp/Restart on a \
         single-LSM System B device)"
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

    /// A write step's target range exceeds the 16-bit A_Memory address space, or
    /// one of its component u32s is absurdly large. Refused at pre-flight so the
    /// device is never streamed a write at a truncated (wrong) address.
    #[error(
        "load procedure step {step} writes {size} octet(s) ending at {end} which exceeds the \
         16-bit A_Memory address space (max {max:#06X}); {detail} — refusing to flash rather \
         than truncating the address and writing to the wrong device memory",
        max = 0xFFFF_u32
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

/// How long to wait for a device to come back after a master-reset `A_Restart`
/// before attempting to reconnect. A real ETS→KNX-Virtual capture showed ~6.5s of
/// silence while the device rebooted; this is deliberately generous so a slower
/// real device still comes back in time. The wait is a single bounded sleep — not
/// a poll loop — because the device is unreachable while it reboots.
const MASTER_RESET_REBOOT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Environment variable that overrides [`MASTER_RESET_REBOOT_WAIT`] with a
/// millisecond value. Set by the mock-device master-reset test so the reboot wait
/// does not stall the test; unset in normal use, so the full generous wait
/// applies. Behaviour is otherwise unchanged.
const REBOOT_WAIT_MS_ENV: &str = "BUSSARD_FLASH_REBOOT_WAIT_MS";

/// The master-reset reboot wait, honouring [`REBOOT_WAIT_MS_ENV`] for tests.
fn master_reset_reboot_wait() -> std::time::Duration {
    std::env::var(REBOOT_WAIT_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_millis)
        .unwrap_or(MASTER_RESET_REBOOT_WAIT)
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
}

impl FlashPlan {
    /// Total octets written to device memory across all memory-write steps.
    pub fn total_write_bytes(&self) -> usize {
        self.steps
            .iter()
            .map(|s| match s {
                FlashStep::WriteRelMem { image, .. } | FlashStep::WriteMem { image, .. } => {
                    image.len
                }
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
        }
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
    pub async fn open_with_key(
        mut connector: C,
        bcu_key: Option<u32>,
    ) -> Result<Session<C>, WriteError> {
        let mut l4 = connector.connect().await?;
        Self::authorize(&mut l4, bcu_key).await?;
        Ok(Session {
            l4: Some(l4),
            connector: Some(connector),
            bcu_key,
        })
    }

    /// Presents the free-access-or-`bcu_key` authorization on the connection,
    /// applying the tolerate-absence / fail-on-denied policy.
    async fn authorize(
        l4: &mut Layer4Connection<C::Channel>,
        bcu_key: Option<u32>,
    ) -> Result<(), WriteError> {
        let key = bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY);
        l4.authorize_or_fail(key).await.map_err(WriteError::Mgmt)?;
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
        Self::authorize(&mut l4, self.bcu_key).await?;
        self.l4 = Some(l4);
        Ok(())
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
    // 1. System B gate.
    if !bussard_mgmt::is_system_b(device_mask) {
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
    // LoadImageProp checks the device's MCB CRC against the very bytes we wrote.
    let mut last_written_image: Option<ImageRef> = None;

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
                steps.push(FlashStep::AllocateSegment {
                    size,
                    target: Some(*idx),
                });
            }

            LoadOp::RelSegment {
                size,
                applies_to,
                lsm_idx,
                ..
            } => {
                // Bind this allocation to the segment whose code image we will
                // stream. The op does not name the segment id directly; we pair
                // it with the application's relative segments in document-ish
                // order using the applies_to hint and remaining unallocated
                // segments.
                let seg = resolve_rel_segment(app, applies_to.as_deref(), &images);
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
                // Per thelsing `table_object.cpp` (`allocTable` frees any prior
                // backing store and re-allocates `size` octets) a second relative
                // allocation on an already-`Loading` object is *legal* and lands in
                // the same state — but it is redundant work, and re-issuing the
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
                let same_segment = match &seg {
                    None => true,
                    Some((seg_id, _)) => prev_rel_segment.as_deref() == Some(seg_id.as_str()),
                };
                let is_duplicate = same_segment
                    && matches!(steps.last(), Some(FlashStep::AllocateSegment { size: prev, .. }) if *prev == size);
                if !is_duplicate {
                    steps.push(FlashStep::AllocateSegment {
                        size,
                        target: *lsm_idx,
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
                if len as u64 > MAX_WRITE_SPAN || u64::from(offset) > MAX_WRITE_SPAN || end > 0xFFFF
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
                if len as u64 > MAX_WRITE_SPAN || u64::from(offset) > MAX_WRITE_SPAN || end > 0xFFFF
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
                if len as u64 > MAX_WRITE_SPAN || end > 0xFFFF {
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
            } => {
                let obj_type = obj_type.unwrap_or(0);
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
                let image = last_written_image.clone();
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
    })
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

/// Resolves which relative segment a `RelSegment` op allocates, preferring one
/// not already allocated. Returns `(segment_id, declared_size)`.
fn resolve_rel_segment(
    app: &ApplicationProgram,
    _applies_to: Option<&str>,
    already: &BTreeMap<String, Vec<u8>>,
) -> Option<(String, Option<u32>)> {
    let mut segs: Vec<_> = app
        .code_segments
        .values()
        .filter(|s| s.kind == SegmentKind::Relative)
        .collect();
    segs.sort_by(|a, b| a.id.cmp(&b.id));
    segs.into_iter()
        .find(|s| !already.contains_key(&s.id))
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
    let mut table: Vec<(u8, u16)> = Vec::new();
    let mut app_obj: Option<u8> = None;
    for index in 0..16u8 {
        let payload = bussard_mgmt::apci::encode_property_value_read(index, PID_OBJECT_TYPE, 1, 1);
        let (resp_apci, data) = l4
            .request(bussard_mgmt::apci::A_PROPERTY_VALUE_READ, &payload)
            .await?;
        if resp_apci != bussard_mgmt::apci::A_PROPERTY_VALUE_RESPONSE {
            break;
        }
        let Some(resp) = bussard_mgmt::apci::decode_property_value_response(&data) else {
            break;
        };
        if resp.count == 0 || resp.data.len() < 2 {
            break;
        }
        let ot = u16::from_be_bytes([resp.data[0], resp.data[1]]);
        table.push((index, ot));
        if ot == OT_APPLICATION_PROGRAM && app_obj.is_none() {
            app_obj = Some(index);
        }
    }
    match app_obj {
        Some(index) => Ok((index, table)),
        None => Err(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: l4.target(),
                reason: "device is missing the application-program interface object".to_string(),
            },
        )),
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
async fn allocate_with_context<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    size: u32,
    object_table: &[(u8, u16)],
) -> Result<bussard_mgmt::SegmentAllocation, WriteError> {
    match allocate_segment(l4, app_obj, size, None).await {
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

/// Executes a validated [`FlashPlan`] against the device over the session's
/// connection, reporting progress through `progress`, then verifies the result.
///
/// The application-program object index is discovered live; the plan's steps run
/// in order, streaming the plan's resolved images into device memory (each write
/// read-back-verified by [`write_memory`]). After the sequence, the object's
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
    // `options.bcu_key` was consumed at connect time (the session was opened with
    // it); only `verify_after_restart` is read below, in the terminal-restart arm.
    let verify_after_restart = options.verify_after_restart;
    let (app_obj, object_table) = discover_object_table(session.l4()).await?;
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
    // The object index the most-recent `AllocateSegment` targeted, so a
    // `MasterReset` re-opens and re-allocates *that* object (the one whose segment
    // the reset dropped) rather than the type-discovered application object. On
    // KNX Virtual DA.tp the app segment is obj4 (allocated right before the reset)
    // while the type-discovered app object is obj3 — re-opening obj3 here would
    // double-`StartLoading` it (the template re-opens obj3 itself after the reset)
    // and drive it to `Error`. `None` until the first `AllocateSegment`.
    let mut last_alloc_target: Option<u8> = None;
    // Track (address, sample_len) of writes for the post-flash spot check.
    let mut written_samples: Vec<(u16, Vec<u8>)> = Vec::new();
    // The verified outcome, captured just before a terminal restart reboots the
    // device (after which it is unreachable and cannot be verified). `None` until
    // then; the post-loop verify runs only if it is still `None`.
    let mut verified: Option<FlashOutcome> = None;

    for (i, step) in plan.steps.iter().enumerate() {
        progress(Progress::Step {
            index: i + 1,
            total,
            label: step_label(step),
        });
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
                    continue;
                };
                write_load_control(session.l4(), obj, LoadControl::Unload).await?;
            }
            FlashStep::StartLoading { target } => {
                let Some(obj) = resolve_object_target_opt(
                    *target,
                    &object_table,
                    app_obj,
                    plan.spliced_from_template,
                ) else {
                    continue;
                };
                start_loading(session.l4(), obj, &object_table).await?;
            }
            FlashStep::AllocateSegment { size, target } => {
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
                    continue;
                };
                let alloc = allocate_with_context(session.l4(), obj, *size, &object_table).await?;
                segment_base = Some(alloc.address);
                segment_bases.insert(obj, alloc.address);
                last_alloc_size = Some(*size);
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
                let base = resolve_object_target_opt(
                    *target,
                    &object_table,
                    app_obj,
                    plan.spliced_from_template,
                )
                .and_then(|obj| segment_bases.get(&obj).copied())
                .or(segment_base)
                .unwrap_or(0);
                // The device-supplied segment base plus the vendor offset must fit
                // the 16-bit A_Memory space. A `u16` cast of the sum would silently
                // wrap and stream the image to the wrong address; refuse instead.
                let addr = base
                    .checked_add(*offset)
                    .and_then(|a| u16::try_from(a).ok())
                    .ok_or_else(|| WriteError::AddressOutOfRange {
                        address: session.l4().target(),
                        detail: format!("segment base {base:#X} + offset {offset:#X}"),
                    })?;
                let bytes = plan
                    .images
                    .get(&image.segment_id)
                    .cloned()
                    .unwrap_or_default();
                write_image(session.l4(), addr, &bytes, &mut progress).await?;
                if let Some(sample) = bytes.first().map(|_| take_sample(&bytes)) {
                    written_samples.push((addr, sample));
                }
            }
            FlashStep::WriteMem { address, image } => {
                // The absolute address must fit the 16-bit A_Memory space; a `u16`
                // cast would silently truncate a too-large vendor address.
                let addr = u16::try_from(*address).map_err(|_| WriteError::AddressOutOfRange {
                    address: session.l4().target(),
                    detail: format!("absolute address {address:#X}"),
                })?;
                let bytes = plan
                    .images
                    .get(&image.segment_id)
                    .cloned()
                    .unwrap_or_default();
                write_image(session.l4(), addr, &bytes, &mut progress).await?;
                if !bytes.is_empty() {
                    written_samples.push((addr, take_sample(&bytes)));
                }
            }
            FlashStep::WriteProp {
                obj_idx,
                obj_type,
                prop_id,
                value,
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
                    continue;
                }
                write_property(
                    session.l4(),
                    (*obj_idx).min(u32::from(u8::MAX)) as u8,
                    (*prop_id).min(u32::from(u8::MAX)) as u8,
                    1,
                    1,
                    value,
                    None,
                )
                .await?;
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
            FlashStep::LoadImageProp {
                prop_id,
                count,
                image,
                ..
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
                    read_mcb_table(session.l4(), app_obj, 1, (*count).min(255) as u8, expected)
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
                    continue;
                };
                write_load_control(session.l4(), obj, LoadControl::LoadCompleted).await?;
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
                master_reset_via_basic_restart(session.l4(), *erase_code, *channel_number).await?;
                tokio::time::sleep(master_reset_reboot_wait()).await;
                session.reconnect().await?;

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
                let state = read_load_state(session.l4(), reset_obj).await?;
                if !matches!(state, LoadState::Loading | LoadState::Loaded) {
                    start_loading(session.l4(), reset_obj, &object_table).await?;
                }
                if let Some(size) = last_alloc_size {
                    let alloc =
                        allocate_with_context(session.l4(), reset_obj, size, &object_table).await?;
                    segment_base = Some(alloc.address);
                    // Update the per-object base too: the resumed `WriteRelMem` for
                    // this object prefers its per-object base, which must be the
                    // freshly-returned one, not the dropped pre-reset value.
                    segment_bases.insert(reset_obj, alloc.address);
                }
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
                let (apci, payload) = bussard_mgmt::apci::encode_restart(0);
                if verify_after_restart && session.can_reconnect() {
                    let _ = session.l4().send_data_unacked(apci, &payload).await;
                    // The device is unreachable while it reboots; wait it out (a
                    // single bounded sleep, not a poll loop), then re-establish the
                    // authorized connection.
                    tokio::time::sleep(master_reset_reboot_wait()).await;
                    session.reconnect().await?;
                    // Re-discover the application object on the fresh connection: the
                    // object index is stable across the reboot, but the L4 connection
                    // is new, so probe it again rather than trusting the pre-restart
                    // handle.
                    let (post_app_obj, _post_table) = discover_object_table(session.l4()).await?;
                    verified = Some(
                        verify_outcome(
                            session.l4(),
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
                        verify_outcome(session.l4(), app_obj, &completed_objects, &written_samples)
                            .await?,
                    );
                    let _ = session.l4().send_data_unacked(apci, &payload).await;
                }
            }
        }
    }

    // If no terminal restart captured the outcome (a procedure with no final
    // Restart), verify now over the still-open connection.
    match verified {
        Some(outcome) => Ok(outcome),
        None => verify_outcome(session.l4(), app_obj, &completed_objects, &written_samples).await,
    }
}

/// Verifies a completed flash over the open connection: re-reads the load state
/// of **every object that was programmed** (each that received a
/// `LoadCompleted`, plus the application object) and spot-checks a sample of each
/// written segment against what was streamed.
///
/// Verifying every completed object — not just the type-discovered application
/// object — is the divergence-#3 fix: a multi-object flash (obj1/obj2/obj3/obj4)
/// must confirm the table objects reached `Loaded` too, or a device that
/// silently failed to load a table would be reported as a success.
///
/// Called with the device still up — either just before a terminal restart
/// reboots it, or (for a procedure without a final restart) after the last step.
async fn verify_outcome<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    completed_objects: &[u8],
    written_samples: &[(u16, Vec<u8>)],
) -> Result<FlashOutcome, WriteError> {
    // The application object's own state (kept as the headline `load_state`).
    let load_state = read_load_state(l4, app_obj).await?;

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
            read_load_state(l4, obj).await?
        };
        object_states.push((obj, state));
    }

    let mut spot_checks_match = true;
    for (addr, expected) in written_samples {
        let got = load::read_memory(l4, *addr, expected.len() as u8).await?;
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

/// Streams `bytes` to `addr` over the connection, emitting a byte-progress event
/// per confirmed write chunk. Each chunk is read-back-verified; a transient
/// connection blip on an individual exchange is retried a bounded number of times
/// on the same connection by [`bussard_mgmt::write_memory_verified`].
async fn write_image<Ch: L4Channel, F: FnMut(Progress)>(
    l4: &mut Layer4Connection<Ch>,
    addr: u16,
    bytes: &[u8],
    progress: &mut F,
) -> Result<(), WriteError> {
    let total = bytes.len();
    let mut on_written = |written| progress(Progress::Bytes { written, total });
    bussard_mgmt::write_memory_verified(l4, addr, bytes, &mut on_written).await
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
        FlashStep::AllocateSegment { size, target } => {
            format!("allocate segment ({size} bytes){}", target_suffix(*target))
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
        } => {
            format!(
                "write property (object {obj_idx}, type {obj_type}, PID {prop_id}, {} byte(s))",
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
        FlashStep::MasterReset {
            erase_code,
            channel_number,
        } => format!(
            "master reset (erase code {erase_code}, channel {channel_number}) — reconnect and resume"
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
        .map(|(i, s)| format!("{:>3}. {}", i + 1, step_label(s)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let app = fabricated_app();
        let err = plan_flash(
            &app,
            "1.1.4",
            0x0705,
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
        // 7 bytes fit in one 12-octet chunk each write → 2 frames.
        assert_eq!(plan.estimated_write_frames(), 2);
        assert!(plan.estimated_duration().as_millis() >= 40);
    }

    // ---------------------------------------------------------------------
    // Issue #53: address-arithmetic bounds at plan pre-flight.
    // ---------------------------------------------------------------------

    #[test]
    fn plan_refuses_write_rel_mem_offset_past_16bit_space() {
        // A WriteRelMem whose offset alone lands the write past 0xFFFF must be
        // refused at plan time (the segment base is added at flash time and is
        // >= 0, so the range already exceeds the 16-bit A_Memory space). This is
        // rejected in the plan, before any allocation or write happens.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-7" MaskVersion="MV-07B0" Name="Overflow">
          <Static>
           <Code><RelativeSegment Id="M-1_A-7_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="65535" Size="6" AppliesTo="full" />
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
                assert!(end > 0xFFFF, "end {end} must exceed the 16-bit space");
            }
            other => panic!("expected AddressOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn plan_refuses_write_mem_address_past_16bit_space() {
        // An absolute WriteMem at an address past 0xFFFF is refused (a u16 cast
        // would silently truncate and stream to the wrong memory).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-8" MaskVersion="MV-07B0" Name="AbsOverflow">
          <Static>
           <Code><AbsoluteSegment Id="M-1_A-8_AS-1" Address="70000" Size="4"><Data>AAECAw==</Data></AbsoluteSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="0" />
             <LdCtrlWriteMem Address="70000" Size="4" />
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
