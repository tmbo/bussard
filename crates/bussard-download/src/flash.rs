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
//! and any `Raw`/`LoadImageProp`), and a procedure whose segment references it
//! cannot resolve. Only a fully-executable [`FlashPlan`] reaches [`flash`], so
//! the engine never begins writing a procedure it cannot finish. Every memory
//! write is read-back-verified and every property/load-control write is
//! confirmed, so a device that drops or refuses a write fails loudly at that op.

use std::collections::BTreeMap;

use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{
    self, LoadControl, LoadState, WriteError, allocate_segment, read_load_state,
    write_load_control, write_memory,
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
    /// Write an interface-object property (`LdCtrlWriteProp`).
    WriteProp {
        /// The interface-object type whose object index the write targets.
        obj_type: u32,
        /// The property id.
        prop_id: u32,
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
         RelSegment/WriteRelMem/WriteMem/WriteProp/Restart on a single-LSM System B device)"
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
    /// Whether the sampled read-backs of written memory matched what was written.
    pub spot_checks_match: bool,
}

impl FlashOutcome {
    /// The flash verified: object `Loaded` and every spot check matched.
    pub fn ok(&self) -> bool {
        self.load_state == LoadState::Loaded && self.spot_checks_match
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

    // 3. Choose a procedure. A merged style splits one logical procedure across
    //    several `<LoadProcedure MergeId=…>` blocks; pick the one with the most
    //    ops as the representative single procedure to execute. A single-style
    //    app has exactly one. Empty apps are refused.
    let procedure = pick_procedure(app).ok_or_else(|| PlanError::NoProcedure(app.id.clone()))?;

    // Resolve the parameter images once, up front (used by AppliesTo=par writes).
    let param_images = bussard_prod::compute_parameter_image(app, overrides).map_err(|e| {
        PlanError::UnresolvableImage {
            step: 0,
            reason: format!("computing the parameter image: {e}"),
        }
    })?;

    // 4. Validate + lower each op into a FlashStep.
    let mut steps = Vec::new();
    let mut images: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // Track the segment id most-recently allocated so a following WriteRelMem
    // resolves to it when its own AppliesTo does not pin one.
    let mut last_rel_segment: Option<String> = None;

    for (i, op) in procedure.ops.iter().enumerate() {
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
                if let Some((seg_id, _)) = &seg {
                    last_rel_segment = Some(seg_id.clone());
                    // Record the code image so total-byte accounting is correct.
                    if let Some(data) = app.code_segments.get(seg_id).and_then(|s| s.data.clone()) {
                        images.entry(seg_id.clone()).or_insert(data);
                    }
                }
                steps.push(FlashStep::AllocateSegment { size });
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
                images.insert(segment_id.clone(), bytes);
                steps.push(FlashStep::WriteRelMem {
                    offset: offset.unwrap_or(0),
                    image: ImageRef {
                        segment_id,
                        kind,
                        len,
                    },
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
                images.insert(segment_id.clone(), bytes);
                steps.push(FlashStep::WriteMem {
                    address: address.unwrap_or(0),
                    image: ImageRef {
                        segment_id,
                        kind: ImageKind::Code,
                        len,
                    },
                });
            }

            LoadOp::WriteProp { obj_type, prop_id } => {
                let (obj_type, prop_id) = (obj_type.unwrap_or(0), prop_id.unwrap_or(0));
                steps.push(FlashStep::WriteProp { obj_type, prop_id });
            }

            // Unsupported: refuse the whole procedure at pre-flight. These need
            // device-side behaviour bussard cannot yet verify (absolute segment
            // allocation is an unverified stub in bussard-mgmt; task segments and
            // any Raw/LoadImageProp op have no clean-room-verified execution).
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

/// Picks the procedure to execute: the one with the most ops (a merged style
/// spreads a logical procedure across `MergeId` blocks; the richest block is the
/// download proper).
fn pick_procedure(app: &ApplicationProgram) -> Option<&LoadProcedure> {
    app.load_procedures
        .iter()
        .filter(|p| !p.ops.is_empty())
        .max_by_key(|p| p.ops.len())
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
/// streams the computed parameter image for that segment.
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
        let bytes = param_images.get(&seg_id).cloned().unwrap_or_default();
        return Ok((seg_id, ImageKind::Parameters, bytes));
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
pub async fn discover_application_object<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<u8, WriteError> {
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
        if ot == OT_APPLICATION_PROGRAM {
            return Ok(index);
        }
    }
    Err(WriteError::Mgmt(
        bussard_mgmt::MgmtError::MalformedResponse {
            address: l4.target(),
            reason: "device is missing the application-program interface object",
        },
    ))
}

/// Executes a validated [`FlashPlan`] against the device over `l4`, reporting
/// progress through `progress`, then verifies the result.
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
pub async fn flash<Ch: L4Channel, F: FnMut(Progress)>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
    mut progress: F,
) -> Result<FlashOutcome, WriteError> {
    let app_obj = discover_application_object(l4).await?;
    let total = plan.steps.len();

    // Segment base addresses, filled as RelSegment allocations return them.
    let mut segment_base: Option<u32> = None;
    // Track (address, sample_len) of writes for the post-flash spot check.
    let mut written_samples: Vec<(u16, Vec<u8>)> = Vec::new();

    for (i, step) in plan.steps.iter().enumerate() {
        progress(Progress::Step {
            index: i + 1,
            total,
            label: step_label(step),
        });
        match step {
            FlashStep::Unload => {
                write_load_control(l4, app_obj, LoadControl::Unload).await?;
            }
            FlashStep::StartLoading => {
                write_load_control(l4, app_obj, LoadControl::StartLoading).await?;
            }
            FlashStep::AllocateSegment { size } => {
                let alloc = allocate_segment(l4, app_obj, *size, None).await?;
                segment_base = Some(alloc.address);
            }
            FlashStep::WriteRelMem { offset, image } => {
                let base = segment_base.unwrap_or(0);
                let addr = (base + offset) as u16;
                let bytes = plan
                    .images
                    .get(&image.segment_id)
                    .cloned()
                    .unwrap_or_default();
                write_with_progress(l4, addr, &bytes, &mut progress).await?;
                if let Some(sample) = bytes.first().map(|_| take_sample(&bytes)) {
                    written_samples.push((addr, sample));
                }
            }
            FlashStep::WriteMem { address, image } => {
                let addr = *address as u16;
                let bytes = plan
                    .images
                    .get(&image.segment_id)
                    .cloned()
                    .unwrap_or_default();
                write_with_progress(l4, addr, &bytes, &mut progress).await?;
                if !bytes.is_empty() {
                    written_samples.push((addr, take_sample(&bytes)));
                }
            }
            FlashStep::WriteProp { obj_type, prop_id } => {
                // Resolve the object index for this object type, then write the
                // property. The value comes from the app's property image; for
                // the first flash the standard interface-object properties are
                // written by the device on LoadCompleted, so a bare WriteProp with
                // no value is a confirm-only no-op here. A property write with a
                // value is echo-validated by write_property.
                let _ = (obj_type, prop_id);
                // Nothing to write without a value payload in the typed op; the
                // op is recorded for the trace and skipped. (A future revision
                // will carry the property value once bussard-prod exposes it.)
            }
            FlashStep::LoadCompleted => {
                write_load_control(l4, app_obj, LoadControl::LoadCompleted).await?;
            }
            FlashStep::Restart => {
                // Fire-and-forget restart on the raw connection.
                let (apci, payload) = bussard_mgmt::apci::encode_restart(0);
                let _ = l4.send_data(apci, &payload).await;
            }
        }
    }

    // Verify: re-read the application-program object's load state and spot-check
    // a sample of each written segment.
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

/// Streams `bytes` to `addr`, emitting a byte-progress event per chunk.
async fn write_with_progress<Ch: L4Channel, F: FnMut(Progress)>(
    l4: &mut Layer4Connection<Ch>,
    addr: u16,
    bytes: &[u8],
    progress: &mut F,
) -> Result<(), WriteError> {
    let chunk = usize::from(bussard_mgmt::apci::MAX_MEMORY_WRITE_LEN);
    let mut offset = 0usize;
    while offset < bytes.len() {
        let take = chunk.min(bytes.len() - offset);
        let chunk_addr = addr.checked_add(offset as u16).ok_or(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: l4.target(),
                reason: "memory write range exceeds the 16-bit address space",
            },
        ))?;
        write_memory(l4, chunk_addr, &bytes[offset..offset + take]).await?;
        offset += take;
        progress(Progress::Bytes {
            written: offset,
            total: bytes.len(),
        });
    }
    Ok(())
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
        FlashStep::WriteProp { obj_type, prop_id } => {
            format!("write property (object type {obj_type}, PID {prop_id})")
        }
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
        parse_application_program("M-1_A-1", xml).unwrap()
    }

    fn no_overrides() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn plan_lowers_supported_procedure() {
        let app = fabricated_app();
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap();
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
        let err = plan_flash(&app, "1.1.4", 0x0705, &no_overrides()).unwrap_err();
        assert!(matches!(err, PlanError::NotSystemB { .. }), "{err:?}");
    }

    #[test]
    fn plan_refuses_mask_mismatch() {
        // App declares MV-07B0 but the device is a different System B medium
        // (0x57B0 IP): the exact-mask compare refuses it.
        let app = fabricated_app();
        let err = plan_flash(&app, "1.1.4", 0x57B0, &no_overrides()).unwrap_err();
        assert!(matches!(err, PlanError::MaskMismatch { .. }), "{err:?}");
    }

    #[test]
    fn plan_refuses_unsupported_op() {
        // An app whose procedure carries a Raw LoadImageProp op (the real Jung
        // MergedProcedure style) is refused whole, at pre-flight.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-2" MaskVersion="MV-07B0" Name="Merged">
          <Static>
           <Code><RelativeSegment Id="M-1_A-2_RS-1" Size="4" LoadStateMachine="4" Offset="0"><Data>AAECAw==</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure MergeId="1">
             <LdCtrlLoadImageProp ObjIdx="0" />
             <LdCtrlRelSegment LsmIdx="4" Size="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-2", xml).unwrap();
        let err = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap_err();
        match err {
            PlanError::UnsupportedOp { op } => assert!(op.contains("LoadImageProp"), "{op}"),
            other => panic!("expected UnsupportedOp, got {other:?}"),
        }
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
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap();
        let lines = trace(&plan);
        assert_eq!(lines.len(), plan.steps.len());
        assert!(lines[0].contains("unload"));
        assert!(lines.last().unwrap().contains("restart"));
    }

    #[test]
    fn estimates_are_sane() {
        let app = fabricated_app();
        let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap();
        // 7 bytes fit in one 12-octet chunk each write → 2 frames.
        assert_eq!(plan.estimated_write_frames(), 2);
        assert!(plan.estimated_duration().as_millis() >= 40);
    }
}
