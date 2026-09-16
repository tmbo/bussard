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
    self, LoadControl, LoadState, WriteError, allocate_segment, compare_property, read_load_state,
    read_mcb_table, write_load_control, write_property,
};
use bussard_mgmt::tables::{OT_APPLICATION_PROGRAM, PID_OBJECT_TYPE};
use bussard_prod::application::{ApplicationProgram, LoadOp, LoadProcedure, SegmentKind};

/// A step of a validated flash, ready to render for the pre-flight display and
/// to execute in order. Each corresponds to one supported [`LoadOp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashStep {
    /// Drop the application-program object to `Unloaded` (`LdCtrlUnload`).
    Unload,
    /// Open the application-program object for writing (`LdCtrlLoad`).
    StartLoading,
    /// Allocate a relative segment; the device places it (`LdCtrlRelSegment`).
    /// Carries the source of the image the following `WriteRelMem` streams and
    /// the byte count, resolved at plan time.
    AllocateSegment {
        /// Requested segment size in octets.
        size: u32,
    },
    /// Write a relative-memory image at `segment base + offset` (`LdCtrlWriteRelMem`).
    WriteRelMem {
        /// Offset within the just-allocated segment.
        offset: u32,
        /// Which image this streams and how many octets it is.
        image: ImageRef,
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
    LoadCompleted,
    /// Restart the device (`LdCtrlRestart`).
    Restart,
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

/// Whether a memory image is the vendor code image or the computed parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    /// The code segment's `<Data>` image (`AppliesTo=full`).
    Code,
    /// The computed parameter image (`AppliesTo=par`).
    Parameters,
}

impl std::fmt::Display for ImageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageKind::Code => write!(f, "code"),
            ImageKind::Parameters => write!(f, "parameters"),
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
}

/// The largest byte length or u32 component a single flash write step may carry.
/// Real System B segments are tens of KiB; a value beyond this in the vendor XML
/// (or a device-supplied base) is treated as corrupt input and refused at plan
/// time rather than driving an allocation or an out-of-range address.
const MAX_WRITE_SPAN: u64 = 1024 * 1024;

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
/// Currently just the KNX-Virtual escape hatch. Defaults keep real-device
/// behaviour strict.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlashOptions {
    /// Accept a device that reports [`bussard_mgmt::LoadState::Loaded`] rather
    /// than the conformant `Loading` right after a `StartLoading`.
    ///
    /// A conformant System B device exposes the `Loading` intermediate state
    /// after `StartLoading` (bussard's clean-room model of thelsing
    /// `table_object.cpp`, and the KNX load-state machine). KNX Virtual 2.6.1 was
    /// observed to snap straight to `Loaded`, tripping the strict check on the
    /// very first allocate. This flag (off by default, surfaced as
    /// `--tolerate-nonconformant-load-states`) lets the owner retry against KV
    /// without weakening the guard on real hardware.
    pub tolerate_nonconformant_load_states: bool,

    /// How memory writes verify their read-back — see
    /// [`bussard_mgmt::VerifyMode`]. Default [`bussard_mgmt::VerifyMode::PerChunk`]
    /// is the conservative real-device behaviour (each chunk confirmed before the
    /// next). [`bussard_mgmt::VerifyMode::Batched`] writes the whole segment first
    /// and verifies once, roughly halving the flash's memory round-trips (the
    /// `--verify batched` flag) and doubling as the #50 KV stall discriminator.
    pub verify: bussard_mgmt::VerifyMode,

    /// Optional inter-frame pace for memory writes (`--pace <ms>`). Real
    /// gateways throttle the tool to TP1 speed by ACK flow control; simulators
    /// like KNX Virtual ACK at loopback speed and were observed to wedge under
    /// the unpaced burst (#50). Pacing to TP1-like rates (25-50 ms) keeps such
    /// peers alive; unnecessary but harmless on real hardware.
    pub pace: Option<std::time::Duration>,

    /// Chunk the download across multiple graceful connection windows: after
    /// roughly every N numbered exchanges, gracefully `T_Disconnect`,
    /// re-establish a fresh L4 connection to the same target (a fresh sequence
    /// window), and resume where the procedure left off (`--reconnect-every <N>`,
    /// off by default).
    ///
    /// KNX Virtual drops the L4 connection after a varying number of exchanges
    /// (7-200+ across runs, no deterministic wall, issue #52). Load states are
    /// persistent *object* state, not connection state — they change only via load
    /// controls — so a download split across several graceful windows lands in the
    /// same device state as one unbroken run, and is spec-legal (vendor procedures
    /// themselves carry Connect/Disconnect ops).
    ///
    /// Windowing runs at two granularities. **Between steps**: after the current
    /// window's exchange budget is spent, the engine cycles at the next step
    /// boundary. **Inside a memory write**: a single vendor "write image" step can
    /// be far more frames than the budget, so the write path itself cycles between
    /// chunks (never mid-frame) and resumes at the current offset on the fresh
    /// connection — memory writes are absolute-addressed and stateless, so this
    /// lands the same bytes. After each reconnect the engine re-verifies the target
    /// still answers (a descriptor read) and — cheap paranoia — that the in-progress
    /// object is still `Loading` (honouring the tolerance flag), and re-reads the
    /// last-written chunk before continuing.
    ///
    /// Setting this also arms **window-retry on unexpected death**: if the peer
    /// drops *before* the planned boundary (KV's random early drop), the write path
    /// reconnects and resumes from the last-confirmed offset rather than failing,
    /// bounded by [`max_window_retries`](FlashOptions::max_window_retries)
    /// consecutive no-progress retries. A bare run without this flag keeps today's
    /// fail-fast + `--reconnect-every` hint behaviour.
    pub reconnect_every: Option<u32>,

    /// How many *consecutive* window-retries without forward progress to allow on
    /// an unexpected mid-write connection death before giving up (default
    /// [`DEFAULT_MAX_WINDOW_RETRIES`]). Any newly-confirmed byte resets the count,
    /// so a peer that makes progress between drops can be retried indefinitely; a
    /// peer that drops every time before a single byte lands fails after this many
    /// tries with a "gave up at offset X" error rather than looping forever. Only
    /// consulted when [`reconnect_every`](FlashOptions::reconnect_every) is set.
    /// `0` falls back to the crate default.
    pub max_window_retries: u32,

    /// The access key presented with `A_Authorize_Request` after every
    /// (re)connect (issue #52 finding #1).
    ///
    /// ETS authorizes a management session before any configuration access;
    /// bussard does the same, so an unauthorized connection-oriented session is
    /// no longer why a keyed device drops us. `None` means present the
    /// [`FREE_ACCESS_KEY`](bussard_mgmt::apci::FREE_ACCESS_KEY) (the unkeyed /
    /// full-access default — what the capture used); `Some(k)` presents the
    /// project BCU key (the `--bcu-key <hex>` flag) for a keyed device. The policy
    /// is tolerate-absence (a device that does not implement authorize continues)
    /// and fail-on-denied (a non-zero granted level is a hard
    /// [`MgmtError`](bussard_mgmt::MgmtError)`::AccessDenied`).
    pub bcu_key: Option<u32>,
}

/// The default [`FlashOptions::max_window_retries`]: eight consecutive
/// no-progress reconnects. Generous enough to ride out a burst of early drops on
/// a very fragile peer, bounded enough that a peer which can never land a byte
/// fails promptly instead of looping forever.
pub const DEFAULT_MAX_WINDOW_RETRIES: u32 = 8;

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
    /// A windowed download crossed a connection-window boundary: the L4
    /// connection was gracefully cycled and the procedure resumed.
    Reconnect {
        /// The window just opened (1 = the second connection, after the first
        /// window closed).
        window: u32,
        /// Total numbered exchanges across every window up to the cycle.
        exchanges: u32,
    },
}

/// The result of a completed flash: the final load state and whether the
/// spot-check read-back of written segments matched.
#[derive(Debug, Clone)]
pub struct FlashOutcome {
    /// The application-program object's final load state (must be `Loaded`).
    pub load_state: LoadState,
    /// Whether the sampled read-backs of written memory matched what was written.
    pub spot_checks_match: bool,
}

impl FlashOutcome {
    /// The flash verified: object `Loaded` and every spot check matched.
    pub fn ok(&self) -> bool {
        self.load_state == LoadState::Loaded && self.spot_checks_match
    }
}

/// Opens a fresh [`Layer4Connection`] to the flash target on demand.
///
/// A [`Session`] uses this to (re)establish the L4 connection at each window
/// boundary of a windowed download: every call must hand back a *new* connection
/// to the same device with fresh sequence counters (a `T_Connect` resets them).
/// The CLI's implementation leases the bus and builds a `LeaseChannel` per call;
/// tests script one directly. Kept as an async trait (rather than a bare closure)
/// so the returned connection's channel type `Ch` is named and the future is
/// nameable without boxing.
#[allow(async_fn_in_trait)]
pub trait Connector {
    /// The channel the produced connection drives.
    type Channel: L4Channel;

    /// Opens a fresh connection to the flash target.
    async fn connect(&mut self) -> Result<Layer4Connection<Self::Channel>, WriteError>;
}

/// A [`Connector`] that hands back one already-open connection and then refuses.
///
/// This adapts a plain [`Layer4Connection`] into a [`Session`] for a
/// non-windowed flash (`--reconnect-every` off): the session opens with the given
/// connection, and any attempt to [`cycle`](Session::cycle) it — which only
/// happens when windowing is enabled — fails, since there is no factory to open a
/// fresh window. Used by callers and tests that flash over a single connection.
pub struct SingleConnector<Ch: L4Channel> {
    l4: Option<Layer4Connection<Ch>>,
    target: bussard_model::IndividualAddress,
}

impl<Ch: L4Channel> Connector for SingleConnector<Ch> {
    type Channel = Ch;

    async fn connect(&mut self) -> Result<Layer4Connection<Ch>, WriteError> {
        self.l4.take().ok_or_else(|| {
            WriteError::Mgmt(MgmtError::MalformedResponse {
                address: self.target,
                reason: "windowed reconnect needs a reconnectable session, but this flash was \
                         opened over a single fixed connection (no --reconnect-every)"
                    .to_string(),
            })
        })
    }
}

impl<Ch: L4Channel> Session<SingleConnector<Ch>> {
    /// Wraps one already-open [`Layer4Connection`] as a non-reconnectable session.
    ///
    /// The returned session flashes over exactly this connection; it cannot
    /// `cycle`, so it is only valid for a run with `reconnect_every` unset. This
    /// is the drop-in for callers and tests that flash over a single connection.
    pub fn from_connection(l4: Layer4Connection<Ch>) -> Session<SingleConnector<Ch>> {
        let target = l4.target();
        Session {
            connector: SingleConnector { l4: None, target },
            l4: Some(l4),
            retired_exchanges: 0,
            windows: 0,
            // A pre-opened connection is authorized (or not) at its own connect
            // site; the session does not re-authorize it (it cannot cycle anyway).
            bcu_key: None,
        }
    }
}

/// A reconnectable L4 session to the flash target: it owns a [`Connector`] and the
/// currently-open [`Layer4Connection`], and can [`cycle`](Session::cycle) itself —
/// gracefully `T_Disconnect` the current connection and open a fresh one — between
/// procedure steps.
///
/// This is the seam that lets [`flash`] window a download across several graceful
/// connection windows (issue #52) while the per-step device logic stays unchanged:
/// the engine borrows `session.l4()` for each step exactly as it borrowed a single
/// `Layer4Connection` before, and asks the session to `cycle()` only at safe step
/// boundaries. `apply`/`reconstruct` keep borrowing a plain `Layer4Connection` and
/// are untouched.
pub struct Session<C: Connector> {
    connector: C,
    /// The currently-open connection. `Some` for the whole lifetime of a healthy
    /// session; briefly `None` only *inside* [`cycle`](Session::cycle), between
    /// releasing the old connection and opening the fresh one (so the old lease is
    /// dropped before the new one is requested).
    l4: Option<Layer4Connection<C::Channel>>,
    /// Numbered exchanges completed on connections *before* the current one, so
    /// [`total_exchanges`](Session::total_exchanges) reports the whole download's
    /// count across every window (each `cycle` folds the closing connection's
    /// count in here before it is dropped).
    retired_exchanges: u32,
    /// How many times the connection has been cycled (windows beyond the first).
    windows: u32,
    /// The access key presented with `A_Authorize_Request` after every
    /// (re)connect (issue #52 finding #1). Every fresh connection is a fresh
    /// authorization context — ETS re-authorizes on each new connection, and the
    /// capture's per-connection `T_Connect` pattern matches — so the session
    /// authorizes right after `open`, `cycle` and `reconnect_after_death`.
    /// [`None`] presents the [`FREE_ACCESS_KEY`](bussard_mgmt::apci::FREE_ACCESS_KEY)
    /// default (what the capture used); [`Some`] presents a project BCU key.
    /// Policy: tolerate a device that does not implement authorize, fail on a
    /// non-zero granted level (`MgmtError::AccessDenied`). `None` on a session
    /// built from a pre-opened connection ([`from_connection`](Session::from_connection)),
    /// which authorizes at its own connect site instead.
    bcu_key: Option<u32>,
}

impl<C: Connector> Session<C> {
    /// Opens the first connection and wraps it in a session, authorizing it with
    /// the free-access key.
    ///
    /// Equivalent to [`open_with_key`](Session::open_with_key) with `None` — every
    /// fresh connection presents
    /// [`FREE_ACCESS_KEY`](bussard_mgmt::apci::FREE_ACCESS_KEY) right after connect
    /// (issue #52 finding #1). A device that does not implement authorize is
    /// tolerated; a non-zero granted level fails with `MgmtError::AccessDenied`.
    pub async fn open(connector: C) -> Result<Session<C>, WriteError> {
        Session::open_with_key(connector, None).await
    }

    /// Opens the first connection and authorizes it with `bcu_key` (or the
    /// free-access key when `None`).
    ///
    /// The key is retained so every window boundary ([`cycle`](Session::cycle)) and
    /// unexpected-death reconnect ([`reconnect_after_death`](Session::reconnect_after_death))
    /// re-authorizes the fresh connection — a fresh connection is a fresh
    /// authorization context, matching ETS's per-`T_Connect` re-authorize.
    pub async fn open_with_key(
        mut connector: C,
        bcu_key: Option<u32>,
    ) -> Result<Session<C>, WriteError> {
        let mut l4 = connector.connect().await?;
        Self::authorize(&mut l4, bcu_key).await?;
        Ok(Session {
            connector,
            l4: Some(l4),
            retired_exchanges: 0,
            windows: 0,
            bcu_key,
        })
    }

    /// Presents the free-access-or-`bcu_key` authorization on a fresh connection,
    /// applying the tolerate-absence / fail-on-denied policy.
    async fn authorize(
        l4: &mut Layer4Connection<C::Channel>,
        bcu_key: Option<u32>,
    ) -> Result<(), WriteError> {
        let key = bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY);
        l4.authorize_or_fail(key).await.map_err(WriteError::Mgmt)?;
        Ok(())
    }

    /// The currently-open connection, for a step to drive.
    ///
    /// Panics only if called while a `cycle` is mid-flight, which never happens:
    /// `cycle` holds `&mut self` exclusively and always restores the connection
    /// before returning (or propagates an error and the session is abandoned).
    pub fn l4(&mut self) -> &mut Layer4Connection<C::Channel> {
        self.l4
            .as_mut()
            .expect("session connection is only absent inside cycle()")
    }

    /// Numbered exchanges on the *current* connection (resets each `cycle`).
    pub fn window_exchanges(&self) -> u32 {
        self.l4.as_ref().map_or(0, |l4| l4.numbered_exchanges())
    }

    /// Numbered exchanges across every window of this download so far.
    pub fn total_exchanges(&self) -> u32 {
        self.retired_exchanges
            .saturating_add(self.window_exchanges())
    }

    /// How many additional windows have been opened (0 before the first cycle).
    pub fn windows(&self) -> u32 {
        self.windows
    }

    /// Gracefully tears down the current connection and opens a fresh one to the
    /// same target — a new sequence window. Only ever called at a safe step
    /// boundary, so it never splits a write/verify.
    ///
    /// The old connection is disconnected **and dropped first**, then the fresh
    /// one is opened. That order matters: a bus-lease channel holds an exclusive
    /// lease, and opening the fresh connection before releasing the old one would
    /// deadlock waiting for a second lease. The retired connection's exchange count
    /// is folded into the running total before it is dropped.
    pub async fn cycle(&mut self) -> Result<(), WriteError> {
        if let Some(old) = self.l4.take() {
            self.retired_exchanges = self
                .retired_exchanges
                .saturating_add(old.numbered_exchanges());
            // Disconnect + drop, releasing any exclusive channel resource (e.g. a
            // bus lease) before we reconnect. A fragile peer that has already
            // dropped makes the T_Disconnect a no-op; the reconnect is what matters.
            let _ = old.disconnect().await;
        }
        // Now that the old connection (and its lease) is gone, open a fresh one and
        // re-authorize it — a fresh connection is a fresh authorization context.
        let mut fresh = self.connector.connect().await?;
        Self::authorize(&mut fresh, self.bcu_key).await?;
        self.l4 = Some(fresh);
        self.windows = self.windows.saturating_add(1);
        Ok(())
    }

    /// Reconnects after an *unexpected* connection death: the current connection
    /// already dropped, so this opens a fresh one directly (no graceful
    /// disconnect first, unlike [`cycle`](Session::cycle)) and folds the dead
    /// connection's exchange count into the running total.
    ///
    /// Used by the intra-write window-retry: when a memory write dies before the
    /// planned window boundary, the write path reconnects here and resumes.
    pub async fn reconnect_after_death(&mut self) -> Result<(), WriteError> {
        if let Some(dead) = self.l4.take() {
            self.retired_exchanges = self
                .retired_exchanges
                .saturating_add(dead.numbered_exchanges());
            // The peer already dropped; a T_Disconnect is a best-effort no-op but
            // still releases any exclusive channel resource (e.g. the bus lease)
            // before we reconnect.
            let _ = dead.disconnect().await;
        }
        let mut fresh = self.connector.connect().await?;
        Self::authorize(&mut fresh, self.bcu_key).await?;
        self.l4 = Some(fresh);
        self.windows = self.windows.saturating_add(1);
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

/// A [`bussard_mgmt::WindowCtl`] over a live [`Session`] that lets a memory write
/// cycle the L4 connection *during* the write (issue #52).
///
/// It borrows the session and carries the resume context ([`resume_recheck`]
/// needs the app object index, the discovered object table, and the flash
/// options) so a cycle — planned or after an unexpected death — reconnects **and**
/// re-verifies the fresh connection can safely resume (target answers + the
/// in-progress object is still `Loading`) before the write continues. This is the
/// seam that threads reconnect into `write_memory`: `flash` builds one of these
/// around the session for each windowed `Write{Rel}Mem` step.
struct SessionWindow<'a, C: Connector> {
    session: &'a mut Session<C>,
    app_obj: u8,
    object_table: &'a [(u8, u16)],
    options: &'a FlashOptions,
    /// The planned window size, or `None` for a non-windowed write.
    reconnect_every: Option<u32>,
    /// A sink for the [`Progress::Reconnect`] events the cycles emit, so the CLI
    /// renders a reconnect line for an intra-write cycle exactly as for a
    /// between-steps one.
    on_reconnect: &'a mut dyn FnMut(u32, u32),
}

impl<C: Connector> bussard_mgmt::WindowCtl for SessionWindow<'_, C> {
    type Channel = C::Channel;

    fn l4(&mut self) -> &mut Layer4Connection<C::Channel> {
        self.session.l4()
    }

    fn window_exchanges(&self) -> u32 {
        self.session.window_exchanges()
    }

    fn reconnect_every(&self) -> Option<u32> {
        self.reconnect_every
    }

    fn max_window_retries(&self) -> u32 {
        let n = self.options.max_window_retries;
        if n == 0 {
            DEFAULT_MAX_WINDOW_RETRIES
        } else {
            n
        }
    }

    async fn cycle(&mut self) -> Result<(), WriteError> {
        self.session.cycle().await?;
        (self.on_reconnect)(self.session.windows(), self.session.total_exchanges());
        // A write only ever cycles inside the loading window, so require Loading.
        resume_recheck(
            self.session.l4(),
            self.app_obj,
            self.object_table,
            self.options,
            true,
        )
        .await
    }

    async fn resume_after_death(&mut self) -> Result<(), WriteError> {
        self.session.reconnect_after_death().await?;
        (self.on_reconnect)(self.session.windows(), self.session.total_exchanges());
        resume_recheck(
            self.session.l4(),
            self.app_obj,
            self.object_table,
            self.options,
            true,
        )
        .await
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
pub fn plan_flash(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
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
    let ops = assemble_ops(app);
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

    // 4. Validate + lower each op into a FlashStep.
    let mut steps = Vec::new();
    let mut images: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // Track the segment id most-recently allocated so a following WriteRelMem
    // resolves to it when its own AppliesTo does not pin one.
    let mut last_rel_segment: Option<String> = None;
    // Track the image most-recently streamed into device memory so a following
    // LoadImageProp checks the device's MCB CRC against the very bytes we wrote.
    let mut last_written_image: Option<ImageRef> = None;

    for (i, op) in ops.iter().enumerate() {
        let step_no = i + 1;
        match op {
            // Session boundaries: the engine holds one connection open across the
            // whole procedure, so these carry no per-op device action.
            LoadOp::Connect | LoadOp::Disconnect => {}

            LoadOp::Unload { .. } => steps.push(FlashStep::Unload),
            LoadOp::Load { .. } => steps.push(FlashStep::StartLoading),
            LoadOp::LoadCompleted { .. } => steps.push(FlashStep::LoadCompleted),
            LoadOp::Restart => steps.push(FlashStep::Restart),

            LoadOp::RelSegment {
                size, applies_to, ..
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
                    && matches!(steps.last(), Some(FlashStep::AllocateSegment { size: prev }) if *prev == size);
                if !is_duplicate {
                    steps.push(FlashStep::AllocateSegment { size });
                }
            }

            LoadOp::WriteRelMem {
                offset, applies_to, ..
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
                steps.push(FlashStep::WriteRelMem { offset, image });
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
                match inline_data {
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
    })
}

/// Assembles the op sequence to execute from an app's load procedures.
///
/// A `MergedProcedure` app spreads one logical download across several
/// `<LoadProcedure MergeId=…>` blocks that ETS splices into the master template
/// at ordered merge points; at the app-local level the correct execution order is
/// the blocks concatenated by ascending `MergeId` (e.g. allocate → write →
/// image-prop). When every block carries a `MergeId`, they are concatenated in
/// that order. A single-style app (one block, or blocks without a `MergeId`) has
/// no merge ordering to honour, so the single richest non-empty block is used —
/// preserving the previous behaviour for those apps.
fn assemble_ops(app: &ApplicationProgram) -> Vec<LoadOp> {
    let non_empty: Vec<&LoadProcedure> = app
        .load_procedures
        .iter()
        .filter(|p| !p.ops.is_empty())
        .collect();
    if non_empty.is_empty() {
        return Vec::new();
    }
    // Merged style: every block is tagged with a MergeId. Concatenate all blocks
    // in ascending MergeId order (numeric where the ids parse, else lexical).
    if non_empty.iter().all(|p| p.merge_id.is_some()) && non_empty.len() > 1 {
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
        return blocks.into_iter().flat_map(|p| p.ops.clone()).collect();
    }
    // Single style: the richest block is the download proper.
    non_empty
        .into_iter()
        .max_by_key(|p| p.ops.len())
        .map(|p| p.ops.clone())
        .unwrap_or_default()
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

    if wants_params {
        // A non-empty parameter image is the intended content; but a combined
        // `full,par` write whose segment carries no parameters (or a pure `par`
        // write with none) still owns the segment's code `<Data>`. Fall back to
        // that so the streamed image is never spuriously empty.
        if let Some(bytes) = param_images.get(&seg_id).filter(|b| !b.is_empty()) {
            return Ok((seg_id, ImageKind::Parameters, bytes.clone()));
        }
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

/// Drives a `StartLoading` on the application object, applying the tolerance
/// policy and enriching a non-conformant load-state failure with discovery
/// context.
///
/// A conformant device lands in `Loading`; [`write_load_control`] confirms that.
/// When a device instead snaps to `Loaded` (the KNX Virtual behaviour):
/// - with `tolerate_nonconformant_load_states` set, the `Loaded` is accepted and
///   the flash proceeds (the subsequent allocate is likewise tolerant);
/// - otherwise the strict [`WriteError::UnexpectedLoadState`] is re-emitted, now
///   carrying the targeted object's discovered type and the full discovered
///   object table so the failure is actionable rather than a bare "object N did
///   not reach Loading".
async fn start_loading<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    object_table: &[(u8, u16)],
    options: &FlashOptions,
) -> Result<(), WriteError> {
    match write_load_control(l4, app_obj, LoadControl::StartLoading).await {
        Ok(_) => Ok(()),
        Err(WriteError::UnexpectedLoadState {
            actual: bussard_mgmt::LoadState::Loaded,
            control: LoadControl::StartLoading,
            ..
        }) if options.tolerate_nonconformant_load_states => {
            // KV snapped straight to Loaded; the owner opted to accept it.
            Ok(())
        }
        Err(WriteError::UnexpectedLoadState {
            address,
            object_index,
            control,
            expected,
            actual,
            ..
        }) => {
            // Strict path: re-emit with the discovered object context folded in.
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

/// Allocates a relative segment, applying the tolerance policy and — like
/// [`start_loading`] — enriching a non-conformant load-state failure with the
/// discovered object context.
///
/// [`allocate_segment`] raises [`WriteError::UnexpectedLoadState`] with an empty
/// context when the object is not `Loading` (its precondition, or the re-read
/// after the `AdditionalLoadControls` write). That bare "object N did not reach
/// Loading" is exactly as unactionable on the allocate path as it was on the
/// StartLoading path fixed in 9a0668a — the KV transcript (#50) shows the
/// allocate path still lacked it. This folds the targeted object's discovered
/// interface-object type and the full discovered object table into any such
/// failure so both paths render the same rich detail.
async fn allocate_with_context<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    size: u32,
    object_table: &[(u8, u16)],
    options: &FlashOptions,
) -> Result<bussard_mgmt::SegmentAllocation, WriteError> {
    match allocate_segment(
        l4,
        app_obj,
        size,
        None,
        options.tolerate_nonconformant_load_states,
    )
    .await
    {
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

/// After a windowed reconnect, confirms the fresh connection can resume the
/// download safely: the target still answers a cheap read, and the in-progress
/// application object is still `Loading` (its load state is persistent object
/// state that survives a graceful `T_Disconnect`, so a fresh window must find it
/// exactly where the previous window left it).
///
/// The load-state paranoia only applies when the download is inside the loading
/// window — after `StartLoading` and before `LoadCompleted` — signalled by
/// `require_loading`. A cycle that lands *before* `StartLoading` (e.g. right after
/// `Unload`, when the object is legitimately `Unloaded`) only checks liveness, not
/// the load state.
///
/// When `require_loading` is set, a device that has dropped out of `Loading` on
/// reconnect (KV was observed to drop the intermediate state on some reconnects)
/// fails here with a clear [`WriteError::UnexpectedLoadState`] carrying the
/// discovered object context — rather than silently writing into an object that is
/// no longer open for loading. The `tolerate_nonconformant_load_states` flag is
/// honoured: a peer that reports `Loaded` after `StartLoading` (KV's non-conformant
/// snap) is also accepted here, since with tolerance on that *is* the in-progress
/// state.
async fn resume_recheck<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    object_table: &[(u8, u16)],
    options: &FlashOptions,
    require_loading: bool,
) -> Result<(), WriteError> {
    // 1. Cheap liveness: a descriptor read proves the fresh connection reached
    //    the same device before we resume writing into it.
    let (req_apci, payload) = bussard_mgmt::apci::encode_device_descriptor_read(0);
    let (resp_apci, data) = l4.request(req_apci, &payload).await?;
    if resp_apci & bussard_mgmt::apci::APCI_SELECTOR_MASK
        != bussard_mgmt::apci::A_DEVICE_DESCRIPTOR_RESPONSE
    {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "device did not answer a descriptor read on the reconnected window \
                 (got APCI {resp_apci:#06X}, {} payload octet(s)) — cannot safely resume",
                data.len()
            ),
        }));
    }

    // 2. Load-state paranoia: only while inside the loading window. The object we
    //    are mid-download on must still be Loading. With tolerance on, a Loaded
    //    snap is also acceptable.
    if !require_loading {
        return Ok(());
    }
    let state = read_load_state(l4, app_obj).await?;
    let acceptable = state == LoadState::Loading
        || (options.tolerate_nonconformant_load_states && state == LoadState::Loaded);
    if !acceptable {
        let context = bussard_mgmt::LoadStateContext {
            object_type: object_table
                .iter()
                .find(|(idx, _)| *idx == app_obj)
                .map(|(_, ot)| *ot),
            object_table: object_table.to_vec(),
        };
        return Err(WriteError::UnexpectedLoadState {
            address: l4.target(),
            object_index: app_obj,
            control: LoadControl::StartLoading,
            expected: LoadState::Loading,
            actual: state,
            context,
        });
    }
    Ok(())
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
    let (app_obj, object_table) = discover_object_table(session.l4()).await?;
    let total = plan.steps.len();

    // Segment base addresses, filled as RelSegment allocations return them.
    let mut segment_base: Option<u32> = None;
    // Track (address, sample_len) of writes for the post-flash spot check.
    let mut written_samples: Vec<(u16, Vec<u8>)> = Vec::new();

    // Windowing: the exchange count on the current connection at which the last
    // window opened (0 for the first window). When `--reconnect-every N` is set
    // and the current window has run N exchanges, cycle the connection *between*
    // steps — never inside a write/verify. Cycling is followed by a resume
    // re-check (target answers + object still Loading).
    let reconnect_every = options.reconnect_every.filter(|&n| n > 0);
    // Whether the download is inside the loading window — after StartLoading has
    // run and before LoadCompleted. Only then must a reconnect re-check that the
    // object is still Loading; a cycle before StartLoading (e.g. right after
    // Unload) legitimately finds it Unloaded.
    let mut loading_active = false;

    for (i, step) in plan.steps.iter().enumerate() {
        // Window boundary check — runs only *between* steps, so a cycle can never
        // split a single write/verify frame. Skip a cycle right before a Restart
        // (fire-and-forget on the current connection; a fresh window would just be
        // torn down) and never before the very first step (nothing done yet).
        if let Some(n) = reconnect_every {
            let due = i > 0 && session.window_exchanges() >= n;
            let is_restart = matches!(step, FlashStep::Restart);
            if due && !is_restart {
                session.cycle().await?;
                progress(Progress::Reconnect {
                    window: session.windows(),
                    exchanges: session.total_exchanges(),
                });
                // Resume-safety: the fresh connection must reach the same device,
                // and — while inside the loading window — the in-progress object
                // must still be Loading before we write more into it (KV drops
                // Loading on some reconnects → clear error).
                resume_recheck(
                    session.l4(),
                    app_obj,
                    &object_table,
                    &options,
                    loading_active,
                )
                .await?;
            }
        }

        progress(Progress::Step {
            index: i + 1,
            total,
            label: step_label(step),
        });
        match step {
            FlashStep::Unload => {
                write_load_control(session.l4(), app_obj, LoadControl::Unload).await?;
            }
            FlashStep::StartLoading => {
                start_loading(session.l4(), app_obj, &object_table, &options).await?;
                loading_active = true;
            }
            FlashStep::AllocateSegment { size } => {
                let alloc =
                    allocate_with_context(session.l4(), app_obj, *size, &object_table, &options)
                        .await?;
                segment_base = Some(alloc.address);
            }
            FlashStep::WriteRelMem { offset, image } => {
                let base = segment_base.unwrap_or(0);
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
                // The write path itself windows: it cycles the connection at the
                // planned boundary AND auto-retries an unexpected mid-write death,
                // resuming at the current offset on the fresh connection.
                write_windowed_with_progress(
                    session,
                    app_obj,
                    &object_table,
                    &options,
                    reconnect_every,
                    addr,
                    &bytes,
                    &mut progress,
                )
                .await?;
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
                write_windowed_with_progress(
                    session,
                    app_obj,
                    &object_table,
                    &options,
                    reconnect_every,
                    addr,
                    &bytes,
                    &mut progress,
                )
                .await?;
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
                // Write the property value to the named object index / PID and
                // echo-validate it via the property-write primitive. Only
                // value-carrying ops reach here (a bare WriteProp is not lowered),
                // so this always performs a real, verified write. The object index
                // and PID were bounded to u8 at plan time.
                let _ = obj_type;
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
            FlashStep::LoadCompleted => {
                write_load_control(session.l4(), app_obj, LoadControl::LoadCompleted).await?;
                loading_active = false;
            }
            FlashStep::Restart => {
                // Fire-and-forget restart on the raw connection.
                let (apci, payload) = bussard_mgmt::apci::encode_restart(0);
                let _ = session.l4().send_data(apci, &payload).await;
            }
        }
    }

    // Verify: re-read the application-program object's load state and spot-check
    // a sample of each written segment. Uses whatever connection the session
    // currently holds (a windowed download may have cycled it several times).
    let l4 = session.l4();
    let load_state = read_load_state(l4, app_obj).await?;
    let mut spot_checks_match = true;
    for (addr, expected) in &written_samples {
        let got = load::read_memory(l4, *addr, expected.len() as u8).await?;
        if &got != expected {
            spot_checks_match = false;
        }
    }

    Ok(FlashOutcome {
        load_state,
        spot_checks_match,
    })
}

/// Streams `bytes` to `addr` through the session, windowing the write itself:
/// it cycles the L4 connection at the planned boundary and auto-retries an
/// unexpected mid-write death, resuming at the current offset on the fresh
/// connection (issue #52). Emits a byte-progress event per write chunk and a
/// [`Progress::Reconnect`] per intra-write cycle.
///
/// The single `progress` callback is shared between the byte-progress and
/// reconnect closures via a [`RefCell`], so each borrows it only at call time —
/// the windowed write holds one closure (byte progress) and the [`SessionWindow`]
/// holds the other (reconnect) simultaneously, which a plain `&mut` capture would
/// forbid.
#[allow(clippy::too_many_arguments)]
async fn write_windowed_with_progress<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    app_obj: u8,
    object_table: &[(u8, u16)],
    options: &FlashOptions,
    reconnect_every: Option<u32>,
    addr: u16,
    bytes: &[u8],
    progress: &mut F,
) -> Result<(), WriteError> {
    let total = bytes.len();
    let progress = std::cell::RefCell::new(progress);
    let mut on_reconnect = |window, exchanges| {
        (progress.borrow_mut())(Progress::Reconnect { window, exchanges });
    };
    let mut window = SessionWindow {
        session,
        app_obj,
        object_table,
        options,
        reconnect_every,
        on_reconnect: &mut on_reconnect,
    };
    let mut on_written = |written| {
        (progress.borrow_mut())(Progress::Bytes { written, total });
    };
    bussard_mgmt::write_memory_windowed(
        &mut window,
        addr,
        bytes,
        options.verify,
        options.pace,
        &mut on_written,
    )
    .await
}

/// The first up-to-4 octets of an image, used as the post-flash read-back sample.
fn take_sample(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len().min(4)].to_vec()
}

/// A short human label for a step, for the progress line and the dry-run trace.
fn step_label(step: &FlashStep) -> String {
    match step {
        FlashStep::Unload => "unload application".to_string(),
        FlashStep::StartLoading => "open application for loading".to_string(),
        FlashStep::AllocateSegment { size } => format!("allocate segment ({size} bytes)"),
        FlashStep::WriteRelMem { offset, image } => {
            format!(
                "write {} image ({} bytes) at segment+{offset}",
                image.kind, image.len
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
        FlashStep::LoadCompleted => "complete load".to_string(),
        FlashStep::Restart => "restart device".to_string(),
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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
        assert_eq!(plan.identity.mask_version, "07B0");
        // Connect/Disconnect are session-boundary no-ops; 8 device steps remain.
        assert_eq!(
            plan.steps,
            vec![
                FlashStep::Unload,
                FlashStep::StartLoading,
                FlashStep::AllocateSegment { size: 6 },
                FlashStep::WriteRelMem {
                    offset: 0,
                    image: ImageRef {
                        segment_id: "M-1_A-1_RS-1".to_string(),
                        kind: ImageKind::Code,
                        len: 6,
                    },
                },
                FlashStep::AllocateSegment { size: 1 },
                FlashStep::WriteRelMem {
                    offset: 0,
                    image: ImageRef {
                        segment_id: "M-1_A-1_RS-2".to_string(),
                        kind: ImageKind::Parameters,
                        len: 1,
                    },
                },
                FlashStep::LoadCompleted,
                FlashStep::Restart,
            ]
        );
        // 6 code bytes + 1 param byte written.
        assert_eq!(plan.total_write_bytes(), 7);
        // The parameter image reflects the default 7.
        assert_eq!(plan.param_images["M-1_A-1_RS-2"], vec![7]);
    }

    #[test]
    fn plan_refuses_non_system_b() {
        let app = fabricated_app();
        let err = plan_flash(&app, "1.1.4", 0x0705, &no_overrides(), &BTreeMap::new()).unwrap_err();
        assert!(matches!(err, PlanError::NotSystemB { .. }), "{err:?}");
    }

    #[test]
    fn plan_refuses_mask_mismatch() {
        // App declares MV-07B0 but the device is a different System B medium
        // (0x57B0 IP): the exact-mask compare refuses it.
        let app = fabricated_app();
        let err = plan_flash(&app, "1.1.4", 0x57B0, &no_overrides(), &BTreeMap::new()).unwrap_err();
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
        let err = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap_err();
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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

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
        let err = plan_flash(&app, "1.1.4", 0x07B0, &ov, &BTreeMap::new()).unwrap_err();
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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &ov, &BTreeMap::new()).unwrap();
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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
        let lines = trace(&plan);
        assert_eq!(lines.len(), plan.steps.len());
        assert!(lines[0].contains("unload"));
        assert!(lines.last().unwrap().contains("restart"));
    }

    #[test]
    fn estimates_are_sane() {
        let app = fabricated_app();
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
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
        let err = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap_err();
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
        let err = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap_err();
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
        let err = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap_err();
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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
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
        let err = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap_err();
        match err {
            PlanError::UnsupportedWriteProp { reason, .. } => {
                assert!(reason.contains("object index"), "{reason}");
            }
            other => panic!("expected UnsupportedWriteProp, got {other:?}"),
        }
    }
}
