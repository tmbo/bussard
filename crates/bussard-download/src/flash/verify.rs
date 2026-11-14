//! Post-load verification and the resident-image check.
//!
//! Before a download, the executor may find that the device already holds
//! everything the plan writes ([`FlashPlan::resident_check`],
//! [`resident_matches`]); it then writes nothing and goes straight to the
//! read-back. After the load, [`FlashOutcome`] records the load state and an
//! end-of-segment spot check.

use super::execute::resolve_object_target_opt;
use super::session::{
    Connector, Session, read_load_state_ext_resumable, read_load_state_resumable,
    read_mcb_entries_resumable, read_memory_range_resumable, read_memory_resumable,
    read_property_value_resumable,
};
use super::{FlashOutcome, FlashPlan, FlashStep, ImageRef, PropObject};
use bussard_mgmt::load::{LoadState, WriteError};
use std::collections::{BTreeMap, BTreeSet};

/// The single whole-segment image a `WriteRelMem` streams into `obj`, if the
/// object has exactly one such write and it starts at offset 0.
///
/// The MCB CRC the device reports covers the whole stored segment, so a match
/// is only sound when a single write covers that segment from its base. An
/// object with several writes (e.g. a `full` then a `par` write at different
/// offsets), or a write at a non-zero offset, is treated as *uncertain* and
/// never matched. Returns the streamed bytes, or `None` when no single
/// offset-0 write resolves onto `obj`. Resolution uses the same object-index
/// rules as execution, so `obj` must be the executor-resolved index.
pub(super) fn sole_object_image<'a>(
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
                // uncertain, so never matched.
                return None;
            }
            found = Some(&image.segment_id);
        }
    }
    let segment_id = found?;
    // A segment the device keeps octets of (issue #411): its CRC says nothing
    // about what bussard writes, so the match is uncertain.
    if plan.kept.iter().any(|k| k.segment == segment_id) {
        return None;
    }
    plan.images.get(segment_id).map(|v| v.as_slice())
}

/// A property value a plan writes to an object named by index: what the
/// resident check reads back instead of writing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedValue<'a> {
    /// The object index the write names.
    pub object: u8,
    /// The property.
    pub prop_id: u32,
    /// The first element written.
    pub start: u16,
    /// The number of elements written.
    pub count: u16,
    /// The octets written.
    pub value: &'a [u8],
}

/// Everything a download would leave on the device, in the terms the device
/// can be asked about before anything is written (issue #1127): the image
/// each loaded object ends with, the objects left unloaded, and the property
/// values written. [`resident_matches`] compares it with the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResidentCheck<'a> {
    /// Each object the plan loads, with the image one offset-0 write
    /// streams into it ([`sole_object_image`]).
    pub loaded: BTreeMap<u8, &'a [u8]>,
    /// Each object the plan unloads and does not load again (object 5 of
    /// the synthetic System B products: ETS unloads 5 to 1 and loads 4 to 1).
    pub unloaded: BTreeSet<u8>,
    /// Each property value the plan writes (the `PID_PROGRAM_VERSION` of
    /// the application object on every System B product).
    pub values: Vec<PlannedValue<'a>>,
}

impl FlashPlan {
    /// What the resident check compares before this plan runs (issue
    /// #1127), or why the plan always runs in full.
    ///
    /// The check takes only a plan made of loads it can compare entry by
    /// entry: `Unload`, `StartLoading`, `AllocateSegment`, `WriteRelMem`,
    /// `LoadCompleted`, property writes to an object named by index (read
    /// back and compared octet for octet; not a load-state control and not
    /// `PID_MCB_TABLE`, whose CRC the device computes), and the steps that
    /// change nothing (`CompareProp`, `DescribeProp`, `LoadImageProp`,
    /// `Delay`, the verify-mode switch) or only reboot (`Restart`). Any
    /// other step (a memory write outside a segment, a reset, a Data Secure
    /// table, a function property, an object named by type) writes state
    /// the check does not read, so the plan runs in full. So does a loaded
    /// object without one whole-segment image. `app_obj` and `object_table`
    /// resolve object indices as the executor does.
    ///
    /// # Errors
    ///
    /// The reason the plan always runs in full, for the plan text.
    pub(super) fn resident_check(
        &self,
        app_obj: u8,
        object_table: &[(u8, u16)],
    ) -> Result<ResidentCheck<'_>, String> {
        let spliced = self.spliced_from_template;
        let mut loads: BTreeSet<u8> = BTreeSet::new();
        let mut unloads: BTreeSet<u8> = BTreeSet::new();
        let mut values = Vec::new();
        for step in &self.steps {
            match step {
                // The executor sends a mapped unload to the object it names
                // (issue #614), else the application object.
                FlashStep::Unload {
                    target,
                    absent_ok: true,
                } => {
                    unloads.insert(
                        target
                            .and_then(|idx| u8::try_from(idx).ok())
                            .filter(|idx| *idx != 0)
                            .unwrap_or(app_obj),
                    );
                }
                FlashStep::Unload { target, .. } => {
                    if let Some(obj) =
                        resolve_object_target_opt(*target, object_table, app_obj, spliced)
                    {
                        unloads.insert(obj);
                    }
                }
                FlashStep::StartLoading { target }
                | FlashStep::AllocateSegment { target, .. }
                | FlashStep::LoadCompleted { target }
                | FlashStep::WriteRelMem { target, .. } => {
                    if let Some(obj) =
                        resolve_object_target_opt(*target, object_table, app_obj, spliced)
                    {
                        loads.insert(obj);
                    }
                }
                FlashStep::WriteProp {
                    object: PropObject::Index(index),
                    prop_id,
                    value,
                    start_element,
                    count,
                    ..
                } if step.load_state_control().is_none()
                    && *prop_id != u32::from(bussard_mgmt::PID_MCB_TABLE)
                    && *prop_id <= u32::from(u8::MAX)
                    && *count > 0
                    && !value.is_empty()
                    && value.len() % usize::from(*count) == 0 =>
                {
                    let Ok(object) = u8::try_from(*index) else {
                        return Err(format!("object index {index} past 8 bits"));
                    };
                    values.push(PlannedValue {
                        object,
                        prop_id: *prop_id,
                        start: *start_element,
                        count: *count,
                        value,
                    });
                }
                FlashStep::CompareProp { .. }
                | FlashStep::DescribeProp { .. }
                | FlashStep::LoadImageProp { .. }
                | FlashStep::Delay { .. }
                | FlashStep::EnableVerifyMode
                | FlashStep::Restart => {}
                other => {
                    return Err(format!(
                        "`{}` writes state the resident check does not read",
                        self.step_label(other)
                    ));
                }
            }
        }
        if loads.is_empty() {
            return Err("the plan loads no object".to_string());
        }
        let mut loaded = BTreeMap::new();
        for obj in loads {
            let Some(image) = sole_object_image(self, obj, app_obj, object_table) else {
                return Err(format!(
                    "object {obj} is not loaded with one whole-segment image"
                ));
            };
            loaded.insert(obj, image);
        }
        let unloaded = unloads
            .into_iter()
            .filter(|obj| !loaded.contains_key(obj))
            .collect();
        Ok(ResidentCheck {
            loaded,
            unloaded,
            values,
        })
    }

    /// The offline counterpart of the executor's resident check (issue
    /// #490), for a dry run planned against a recorded device state: when
    /// every object the plan loads has an MCB in `mcbs` (object index to
    /// segment size and CRC, one entry) that matches its image and
    /// `state_of` reports it `Loaded`, and every object the plan only
    /// unloads is reported `Unloaded`, the plan is emptied, as the executor
    /// writes nothing then; returns the objects that matched. The recorded
    /// state holds no property values and no MCB table past entry 1, so the
    /// executor reads those live; the dry run says so. An object whose
    /// state was not recorded counts as matching (`state_of` returns
    /// `None`). Every object the plan names counts as present; `app_obj` is
    /// the object an op without an index resolves to. The caller gates it
    /// the way the executor's check is gated (`skip_unchanged` in
    /// `bussard-service`).
    pub fn skip_resident_matches(
        &mut self,
        mcbs: &BTreeMap<u8, (u32, u16)>,
        app_obj: u8,
        state_of: impl Fn(u8) -> Option<LoadState>,
    ) -> BTreeSet<u8> {
        let table: Vec<(u8, u16)> = self
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Unload { target, .. }
                | FlashStep::StartLoading { target }
                | FlashStep::AllocateSegment { target, .. }
                | FlashStep::LoadCompleted { target }
                | FlashStep::WriteRelMem { target, .. } => *target,
                _ => None,
            })
            .filter_map(|t| u8::try_from(t).ok())
            .chain(std::iter::once(app_obj))
            .collect::<BTreeSet<u8>>()
            .into_iter()
            .map(|idx| (idx, 0))
            .collect();
        let Ok(check) = self.resident_check(app_obj, &table) else {
            return BTreeSet::new();
        };
        let all_match = check.loaded.iter().all(|(&obj, image)| {
            mcbs.get(&obj).is_some_and(|&(size, crc)| {
                let entry = bussard_mgmt::McbEntry {
                    segment_size: size,
                    crc_control: 0,
                    access: 0,
                    crc16: crc,
                };
                bussard_mgmt::mcb_entries_match(image, &[entry])
            }) && state_of(obj).is_none_or(|s| s == LoadState::Loaded)
        }) && check
            .unloaded
            .iter()
            .all(|&obj| state_of(obj).is_none_or(|s| s == LoadState::Unloaded));
        if !all_match {
            return BTreeSet::new();
        }
        let matched = check.loaded.keys().copied().collect();
        self.steps.clear();
        matched
    }
}

/// How the device compares with a [`ResidentCheck`]: `Ok` when every loaded
/// object's `PID_MCB_TABLE` entries describe its image
/// ([`bussard_mgmt::mcb_entries_match`]) and it reads `Loaded`, every object
/// the plan leaves unloaded reads `Unloaded`, and every planned property
/// value reads back octet for octet; otherwise the first difference.
///
/// Reads only, each resumed across a connection death. A read the device
/// refuses or does not answer is a difference: the full procedure runs, as
/// before this check existed (CLAUDE.md "Speed Changes").
///
/// The MCB entries are read from entry 1, one element per request, as ETS
/// reads them (issue #1128); element 0 is the number of entries
/// (Application Layer 03_03_07 §3.4.4.1) and is not read. The CRC is
/// valid in `Loaded` only (Resources 03_05_01 §4.2.27.1.2), so the load
/// state is read after it, on the same object.
pub(super) async fn resident_matches<C: Connector>(
    session: &mut Session<C>,
    check: &ResidentCheck<'_>,
) -> Result<(), String> {
    for (&obj, image) in &check.loaded {
        let entries = read_mcb_entries_resumable(session, obj, image.len())
            .await
            .map_err(|e| format!("object {obj}: PID_MCB_TABLE not read ({e})"))?;
        if !bussard_mgmt::mcb_entries_match(image, &entries) {
            return Err(format!(
                "object {obj}: the resident MCB does not describe the image"
            ));
        }
        let state = read_load_state_resumable(session, obj)
            .await
            .map_err(|e| format!("object {obj}: load state not read ({e})"))?;
        if state != LoadState::Loaded {
            return Err(format!("object {obj} is {state}, not Loaded"));
        }
    }
    for &obj in &check.unloaded {
        let state = read_load_state_resumable(session, obj)
            .await
            .map_err(|e| format!("object {obj}: load state not read ({e})"))?;
        if state != LoadState::Unloaded {
            return Err(format!("object {obj} is {state}, not Unloaded"));
        }
    }
    for v in &check.values {
        let elem = v.value.len() / usize::from(v.count);
        let read = read_property_value_resumable(session, v.object, v.prop_id, v.start, v.count, elem)
            .await
            .map_err(|e| format!("object {} PID {}: not read ({e})", v.object, v.prop_id))?;
        if read != v.value {
            return Err(format!(
                "object {} PID {} holds another value",
                v.object, v.prop_id
            ));
        }
    }
    Ok(())
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
pub(super) async fn verify_outcome<C: Connector>(
    session: &mut Session<C>,
    app_obj: u8,
    completed_objects: &[u8],
    completed_typed: &[(u16, u16)],
    written_samples: &[WrittenSample],
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

    let typed_object_states = read_typed_states(session, completed_typed).await?;
    let spot_checks_match = spot_check(session, written_samples.iter()).await?;
    Ok(FlashOutcome {
        load_state,
        object_states,
        typed_object_states,
        spot_checks_match,
        warnings: Vec::new(),
        reboot_readiness: Vec::new(),
        verify_echoes: None,
        property_only: false,
    })
}

/// Reads back the load state of every object the flash completed by type
/// (issue #961) with `A_FunctionPropertyExt_State_Read` PID 5, falling back to
/// the extended property read; each read is resume-on-drop.
async fn read_typed_states<C: Connector>(
    session: &mut Session<C>,
    completed_typed: &[(u16, u16)],
) -> Result<Vec<(u16, u16, LoadState)>, WriteError> {
    let mut states = Vec::with_capacity(completed_typed.len());
    for &(object_type, occurrence) in completed_typed {
        let addr = super::function_prop::typed_load_state_address(
            session.l4().target(),
            object_type,
            occurrence,
        )?;
        let state = read_load_state_ext_resumable(session, addr).await?;
        states.push((object_type, occurrence, state));
    }
    Ok(states)
}

/// A post-flash read-back sample: the first octets streamed to `address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WrittenSample {
    /// The 24-bit memory address the sample starts at.
    pub(super) address: u32,
    /// The octets written there (up to 4, see [`take_sample`]).
    pub(super) bytes: Vec<u8>,
    /// The device object and image segment a `WriteRelMem` streamed the sample
    /// into, so a passed MCB check of that very segment can stand in for the
    /// sample (issue #215). `None` for an absolute `WriteMem`, which no MCB
    /// covers.
    pub(super) segment: Option<(u8, String)>,
    /// Which of [`Self::bytes`] were written (`0xFF`) when the sample spans
    /// a whole write with octets the device keeps between its runs (issue
    /// #1084): only those are compared. `None`: every octet.
    pub(super) mask: Option<Vec<u8>>,
}

/// Reads every sample back; `false` as soon as one differs from what was
/// written. Each read is resume-on-drop.
async fn spot_check<'a, C: Connector>(
    session: &mut Session<C>,
    samples: impl Iterator<Item = &'a WrittenSample>,
) -> Result<bool, WriteError> {
    let mut all_match = true;
    for sample in samples {
        let matches = match &sample.mask {
            None => {
                read_memory_resumable(session, sample.address, sample.bytes.len() as u8).await?
                    == sample.bytes
            }
            Some(mask) => {
                let got = read_memory_range_resumable(session, sample.address, sample.bytes.len())
                    .await?;
                sample
                    .bytes
                    .iter()
                    .zip(mask)
                    .enumerate()
                    .all(|(i, (want, m))| *m != 0xFF || got.get(i) == Some(want))
            }
        };
        if !matches {
            all_match = false;
        }
    }
    Ok(all_match)
}

/// The post-restart verification (issue #215): the reads that decide, instead
/// of re-reading everything [`verify_outcome`] reads.
///
/// Called on the fresh connection after the terminal restart, once
/// [`super::execute::confirm_app_object`] re-confirmed the application object
/// (one `PID_OBJECT_TYPE` read). It then reads:
///
/// - the application object's load state (one `PID_LOAD_STATE` read), the
///   state the device decides on after its reboot (KNX Virtual reverts a
///   content-incomplete load to `Unloaded` here, #47);
/// - a memory sample only for a segment no passed MCB check covers
///   (`mcb_verified`, the `(object, segment)` pairs whose device CRC matched
///   the streamed image before the restart). An absolute `WriteMem` or a
///   segment with an advisory, missing or mismatching check keeps its sample.
///
/// The other programmed objects are reported with the `Loaded` state their
/// own `LoadCompleted` (or the MCB skip's load-state read) confirmed before
/// the restart; a completion that did not reach `Loaded` already failed the
/// flash. When the application object is not `Loaded` after the reboot, this
/// falls back to the full [`verify_outcome`], so a failed flash reports every
/// object's state and every sample as before.
///
/// On the 2026-09-24 1.1.12 flash the full verify was 9 reads (one
/// `PID_OBJECT_TYPE`, four `PID_LOAD_STATE`, four samples); this is 2.
pub(super) async fn verify_after_reboot<C: Connector>(
    session: &mut Session<C>,
    app_obj: u8,
    completed_objects: &[u8],
    completed_typed: &[(u16, u16)],
    written_samples: &[WrittenSample],
    mcb_verified: &BTreeSet<(u8, String)>,
) -> Result<FlashOutcome, WriteError> {
    let load_state = read_load_state_resumable(session, app_obj).await?;
    if load_state != LoadState::Loaded {
        return verify_outcome(
            session,
            app_obj,
            completed_objects,
            completed_typed,
            written_samples,
        )
        .await;
    }
    let mut object_states: Vec<(u8, LoadState)> = Vec::new();
    for &obj in completed_objects.iter().chain(std::iter::once(&app_obj)) {
        if !object_states.iter().any(|(seen, _)| *seen == obj) {
            object_states.push((obj, LoadState::Loaded));
        }
    }
    let uncovered = written_samples.iter().filter(|sample| {
        !sample
            .segment
            .as_ref()
            .is_some_and(|segment| mcb_verified.contains(segment))
    });
    // An object loaded by type is read back after the reboot: its
    // completion's own answer is not the independent read-back (issue #961).
    let typed_object_states = read_typed_states(session, completed_typed).await?;
    let spot_checks_match = spot_check(session, uncovered).await?;
    Ok(FlashOutcome {
        load_state,
        object_states,
        typed_object_states,
        spot_checks_match,
        warnings: Vec::new(),
        reboot_readiness: Vec::new(),
        verify_echoes: None,
        property_only: false,
    })
}

/// The object whose `PID_MCB_TABLE` covers a code or parameter `image` checked
/// by a `LoadImageProp` naming `obj_idx`.
///
/// When the plan wrote `image` to that very object (a companion program's
/// segment on object 5 of the ABB BE/S16), the MCB lives there, resolved the
/// way the write resolved its target. Otherwise the check names an object whose
/// image bussard streamed elsewhere (the single-segment DA.tp and mock shapes,
/// where several indices verify one application image) and the MCB is the
/// discovered application object's.
pub(super) fn mcb_read_object(
    steps: &[FlashStep],
    spliced: bool,
    image: &ImageRef,
    obj_idx: u32,
    object_table: &[(u8, u16)],
    app_obj: u8,
) -> u8 {
    let written_to_checked_object = steps.iter().any(|s| {
        matches!(
            s,
            FlashStep::WriteRelMem { image: w, target: Some(t), .. }
                if *t == obj_idx && w.segment_id == image.segment_id
        )
    });
    if !written_to_checked_object {
        return app_obj;
    }
    resolve_object_target_opt(Some(obj_idx), object_table, app_obj, spliced).unwrap_or(app_obj)
}

/// The outcome text for an advisory MCB check that did not match (issue #145):
/// what differed, and why it does not fail the flash.
pub(super) fn advisory_mcb_warning(obj_idx: u32, err: &WriteError) -> String {
    let detail = match err {
        WriteError::ImagePropMismatch {
            object_index,
            expected_crc,
            device_crc,
            ..
        } => format!(
            "device PID_MCB_TABLE CRC {device_crc:#06X} on object {object_index}, \
             written image CRC {expected_crc:#06X}"
        ),
        other => other.to_string(),
    };
    format!(
        "warning: MCB check of object {obj_idx} did not match ({detail}); advisory only, \
         the application's own load procedure does not verify this object (ETS reads it \
         without failing), so the download continued through its restart"
    )
}

/// The read-back sample of the octets a sparse write over a filled segment
/// skipped (issue #1081): up to 4 octets at the start of the first gap
/// between the written `regions` of a `len`-octet image at `addr`, expected
/// to hold `fill`. `None` when the write left no octet out, or when
/// `written`, the step's own read-back sample, already reads an octet of
/// that gap (it samples the image's first octets, written or not).
///
/// The sparse write is right only when the device filled the segment on the
/// allocation (Management Procedures 03_05_02 §3.31.3.4, Mode bit 0). A
/// passed MCB check of the segment proves that for every octet (its CRC runs
/// over the whole image, fill included) and stands in for this sample; where
/// no such check runs (3 of the 56 sweep programs that used to carry the
/// factory reset), this one read catches a device that kept other contents
/// at the sampled octets. It is a sample, not proof: a device that ignores
/// the fill flag and happens to hold the fill byte there passes.
pub(super) fn fill_sample(
    addr: u32,
    len: usize,
    regions: &[(usize, usize)],
    fill: u8,
    segment: Option<(u8, String)>,
    written: Option<&WrittenSample>,
) -> Option<WrittenSample> {
    let mut at = 0usize;
    let mut gap = None;
    for &(start, end) in regions {
        if start > at {
            gap = Some((at, start));
            break;
        }
        at = at.max(end);
    }
    let (start, end) = gap.or((at < len).then_some((at, len)))?;
    let (gap_start, gap_end) = (addr + start as u32, addr + end as u32);
    if written.is_some_and(|w| w.address < gap_end && gap_start < w.address + w.bytes.len() as u32)
    {
        return None;
    }
    Some(WrittenSample {
        address: addr + start as u32,
        bytes: vec![fill; (end - start).min(4)],
        segment,
        mask: None,
    })
}

/// The first up-to-4 octets of an image, used as the post-flash read-back sample.
pub(super) fn take_sample(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len().min(4)].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::ImageKind;

    fn image(segment_id: &str) -> ImageRef {
        ImageRef {
            segment_id: segment_id.to_string(),
            kind: ImageKind::Code,
            len: 4,
            offset: 0,
        }
    }

    fn write(segment_id: &str, target: u32) -> FlashStep {
        FlashStep::WriteRelMem {
            offset: 0,
            image: image(segment_id),
            target: Some(target),
        }
    }

    /// The ABB BE/S16 / Busch-Wächter PRO 280 shape (issue #145): the
    /// application image on object 4, a companion program's on object 5.
    const TABLE: [(u8, u16); 5] = [(1, 1), (2, 2), (3, 9), (4, 3), (5, 3)];

    #[test]
    fn test_fill_sample_takes_the_first_skipped_octets() -> Result<(), Box<dyn std::error::Error>> {
        let sample = fill_sample(0x4000, 6, &[(1, 2), (3, 4), (5, 6)], 0xFF, None, None)
            .ok_or("a gap at octet 0")?;
        assert_eq!(sample.address, 0x4000);
        assert_eq!(sample.bytes, vec![0xFF]);
        let sample = fill_sample(0x4000, 16, &[(0, 4)], 0x00, None, None).ok_or("a tail gap")?;
        assert_eq!(sample.address, 0x4004);
        assert_eq!(sample.bytes, vec![0; 4]);
        assert_eq!(fill_sample(0x4000, 4, &[(0, 4)], 0x00, None, None), None);
        // The step's own sample of octets 0 to 3 already reads the gap at 0.
        let own = WrittenSample {
            address: 0x4000,
            bytes: vec![0, 1, 0, 3],
            segment: None,
            mask: None,
        };
        assert_eq!(
            fill_sample(0x4000, 6, &[(1, 2), (3, 4)], 0x00, None, Some(&own)),
            None
        );
        Ok(())
    }

    #[test]
    fn test_mcb_read_object_reads_the_companion_object_it_wrote() {
        let steps = [write("app", 4), write("pei", 5)];
        assert_eq!(
            mcb_read_object(&steps, true, &image("pei"), 5, &TABLE, 4),
            5,
            "object 5's check reads object 5's MCB, not the application object's"
        );
        assert_eq!(
            mcb_read_object(&steps, true, &image("app"), 4, &TABLE, 4),
            4
        );
    }

    #[test]
    fn test_mcb_read_object_falls_back_to_the_app_object() {
        // A check naming an object the image was not written to (the DA.tp
        // shape: several indices verify the one application image).
        let steps = [write("app", 4)];
        assert_eq!(
            mcb_read_object(&steps, true, &image("app"), 2, &TABLE, 4),
            4
        );
        // Written to an index the device does not expose: the app object.
        let steps = [write("app", 7)];
        assert_eq!(
            mcb_read_object(&steps, true, &image("app"), 7, &TABLE, 4),
            4
        );
    }

    #[test]
    fn test_advisory_mcb_warning_names_both_crcs_and_why() -> Result<(), Box<dyn std::error::Error>>
    {
        let err = WriteError::ImagePropMismatch {
            address: "1.1.30".parse()?,
            object_index: 5,
            expected_crc: 0x62E5,
            device_crc: 0xB0DA,
        };
        let text = advisory_mcb_warning(5, &err);
        assert!(text.starts_with("warning: MCB check of object 5"), "{text}");
        assert!(text.contains("0xB0DA") && text.contains("0x62E5"), "{text}");
        assert!(text.contains("advisory only"), "{text}");
        Ok(())
    }

    /// The image the plan streams into object 4.
    fn object_4_image(plan: &FlashPlan) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::WriteRelMem { image, .. } => plan.image_bytes(&image.segment_id),
                _ => None,
            })
            .ok_or("no write")?
            .to_vec())
    }

    /// Issues #490 and #1127: the offline resident check empties the plan
    /// when every loaded object's recorded MCB matches and its state is
    /// Loaded, and leaves the whole plan otherwise: never a part of it.
    #[test]
    fn test_skip_resident_matches_is_all_or_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let plan = super::super::test_support::full_only_plan()?;
        let check = plan
            .resident_check(4, &[(4, 0)])
            .map_err(|e| format!("the plan is checkable: {e}"))?;
        assert_eq!(check.loaded.keys().copied().collect::<Vec<_>>(), vec![4]);
        let image = object_4_image(&plan)?;
        let crc = bussard_mgmt::crc16_ccitt(&image);
        let len = image.len() as u32;
        // Object 4 Loaded; the objects the plan only unloads unrecorded.
        let loaded = |obj: u8| (obj == 4).then_some(LoadState::Loaded);

        let mut differs = plan.clone();
        let wrong = BTreeMap::from([(4u8, (len, crc ^ 1))]);
        assert!(differs.skip_resident_matches(&wrong, 4, loaded).is_empty());
        assert_eq!(differs.steps, plan.steps, "a different image: the full plan");

        let matching = BTreeMap::from([(4u8, (len, crc))]);
        let mut unloaded = plan.clone();
        assert!(
            unloaded
                .skip_resident_matches(&matching, 4, |_| Some(LoadState::Unloaded))
                .is_empty()
        );
        assert_eq!(unloaded.steps, plan.steps, "not Loaded: the full plan");

        let mut skipped = plan.clone();
        assert_eq!(
            skipped.skip_resident_matches(&matching, 4, loaded),
            BTreeSet::from([4u8])
        );
        assert!(skipped.steps.is_empty(), "{:?}", skipped.steps);
        Ok(())
    }
}
