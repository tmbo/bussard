//! Post-load verification and the resident-image keep.
//!
//! Before a download, the executor keeps an object whose resident image
//! already matches, where ETS keeps it ([`keep_candidates`],
//! [`resident_keep`]). After the load, [`FlashOutcome`] records the load
//! state and an end-of-segment spot check.

use super::execute::resolve_object_target_opt;
use super::session::{
    Connector, Session, read_load_state_ext_resumable, read_load_state_resumable,
    read_mcb_entries_resumable, read_memory_range_resumable, read_memory_resumable,
};
use super::{FlashOutcome, FlashPlan, FlashStep, ImageRef};
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

/// The segment id the System B planner gives the group-object table image
/// (`obj-table-3`, `plan.rs` `table_object_name`).
const GROUP_OBJECT_TABLE_IMAGE: &str = "obj-table-3";

/// The objects of `plan` the keep may leave alone, with the image the
/// plan streams into each: the rule the house captures show ETS following
/// (issue #1127). In a download onto a device that already holds the same
/// application, ETS reads `PID_MCB_TABLE` of the group-object table and of
/// the application object before the first unload, with the count of the
/// product's `LdCtrlLoadImageProp`, and leaves the group-object table alone
/// when it matches: no unload, no load, no write, while the application
/// object and the address and association tables are reloaded as the
/// procedure says (`1-1-5-no-secure-ga`, `secure-1-1-47`, `secure-1-1-48`,
/// `taster-1-1-12-unsecure-0-0-6`: objects 4, 2, 1 unloaded and loaded,
/// object 3 untouched). Where the product declares no MCB check ETS reads no
/// MCB and runs the whole procedure (every synthetic `reload` capture).
///
/// So an object is a candidate when the plan writes the group-object table
/// image into it with one offset-0 write ([`sole_object_image`]), it is not
/// the application object, and the plan carries an `LdCtrlLoadImageProp` of
/// it (the product declares its MCB). `object_types` gives the device's type
/// of an object when known; a known type other than the group-object table
/// excludes it.
pub(super) fn keep_candidates<'a>(
    plan: &'a FlashPlan,
    app_obj: u8,
    object_table: &[(u8, u16)],
) -> BTreeMap<u8, &'a [u8]> {
    let spliced = plan.spliced_from_template;
    let mut out = BTreeMap::new();
    for step in &plan.steps {
        let FlashStep::WriteRelMem { image, target, .. } = step else {
            continue;
        };
        if image.segment_id != GROUP_OBJECT_TABLE_IMAGE {
            continue;
        }
        let Some(obj) = resolve_object_target_opt(*target, object_table, app_obj, spliced) else {
            continue;
        };
        let typed_otherwise = object_table
            .iter()
            .any(|&(i, t)| i == obj && t != 0 && t != bussard_mgmt::tables::OT_GROUP_OBJECT_TABLE);
        let declared = plan.steps.iter().any(|s| {
            matches!(s, FlashStep::LoadImageProp { obj_idx, prop_id, .. }
                if *obj_idx == u32::from(obj) && *prop_id == u32::from(bussard_mgmt::PID_MCB_TABLE))
        });
        if obj == app_obj || typed_otherwise || !declared {
            continue;
        }
        if let Some(bytes) = sole_object_image(plan, obj, app_obj, object_table) {
            out.insert(obj, bytes);
        }
    }
    out
}

/// The device object index whose re-load a step belongs to, for the keep
/// (issue #73 item 2), or `None` for a step that is not part of one
/// object's re-load: only `Unload`, `StartLoading`, `AllocateSegment`,
/// `WriteRelMem` and `LoadCompleted` are. The `LoadImageProp` check still
/// runs on a kept object, as ETS reads its MCB after the load too.
pub(super) fn mcb_skip_target(
    step: &FlashStep,
    object_table: &[(u8, u16)],
    app_obj: u8,
    plan: &FlashPlan,
) -> Option<u8> {
    let target = match step {
        FlashStep::Unload { target, .. }
        | FlashStep::StartLoading { target }
        | FlashStep::AllocateSegment { target, .. }
        | FlashStep::LoadCompleted { target }
        | FlashStep::WriteRelMem { target, .. } => *target,
        _ => return None,
    };
    resolve_object_target_opt(target, object_table, app_obj, plan.spliced_from_template)
}

/// Whether an object's resident state lets it be kept: its MCB entries
/// describe `image` ([`bussard_mgmt::mcb_entries_match`]: from entry 1,
/// entry by entry, CRC control bit 0 clear) and it is `Loaded` (the CRC is
/// valid only there, Resources 03_05_01 §4.2.27.1.2). The one rule the live
/// check ([`resident_keep`]) and the dry run against a recorded state
/// ([`FlashPlan::skip_resident_matches`]) apply.
pub(super) fn keeps(image: &[u8], entries: &[bussard_mgmt::McbEntry], state: LoadState) -> bool {
    state == LoadState::Loaded && bussard_mgmt::mcb_entries_match(image, entries)
}

impl FlashPlan {
    /// Drops the re-load steps ([`mcb_skip_target`]) of each object in `keep`.
    fn drop_reloads(&mut self, keep: &BTreeSet<u8>, app_obj: u8, object_table: &[(u8, u16)]) {
        let retain: Vec<bool> = self
            .steps
            .iter()
            .map(|s| {
                mcb_skip_target(s, object_table, app_obj, self).is_none_or(|o| !keep.contains(&o))
            })
            .collect();
        let mut retain = retain.into_iter();
        self.steps.retain(|_| retain.next().unwrap_or(true));
    }

    /// The offline counterpart of the executor's keep (issue #490), for a
    /// dry run planned against a recorded device state: drops the re-load
    /// of each candidate ([`keep_candidates`]) whose recorded MCB entries
    /// (`mcbs`, by object index, as ETS read them) and load state pass
    /// [`keeps`], the rule the executor applies live. `state_of` returns the
    /// recorded load state; an object whose state was not recorded counts as
    /// `Loaded`, as ETS reads the MCB of the object it keeps and not its
    /// state. Every object the plan names counts as present; `app_obj` is
    /// the object an op without an index resolves to. Returns the objects
    /// kept. The caller gates it as the executor's keep is gated
    /// (`skip_unchanged` in `bussard-service`).
    pub fn skip_resident_matches(
        &mut self,
        mcbs: &BTreeMap<u8, Vec<bussard_mgmt::McbEntry>>,
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
        let keep: BTreeSet<u8> = keep_candidates(self, app_obj, &table)
            .into_iter()
            .filter(|(obj, image)| {
                mcbs.get(obj).is_some_and(|entries| {
                    keeps(image, entries, state_of(*obj).unwrap_or(LoadState::Loaded))
                })
            })
            .map(|(obj, _)| obj)
            .collect();
        if !keep.is_empty() {
            self.drop_reloads(&keep, app_obj, &table);
        }
        keep
    }
}

/// The objects the device already holds as the plan would leave them: each
/// candidate ([`keep_candidates`]) that passes [`keeps`]. Reads only, each
/// resumed across a connection death; a read the device refuses or does not
/// answer keeps nothing for that object, so it is reloaded as before this
/// check existed (CLAUDE.md "Speed Changes").
///
/// The MCB entries are read from entry 1, one element per request, as ETS
/// reads them (issue #1128); element 0 is the number of entries (Application
/// Layer 03_03_07 §3.4.4.1) and is not read.
pub(super) async fn resident_keep<C: Connector>(
    session: &mut Session<C>,
    plan: &FlashPlan,
    app_obj: u8,
    object_table: &[(u8, u16)],
) -> BTreeSet<u8> {
    let mut keep = BTreeSet::new();
    for (obj, image) in keep_candidates(plan, app_obj, object_table) {
        let Ok(entries) = read_mcb_entries_resumable(session, obj, image.len()).await else {
            continue;
        };
        if !bussard_mgmt::mcb_entries_match(image, &entries) {
            continue;
        }
        if let Ok(state) = read_load_state_resumable(session, obj).await
            && keeps(image, &entries, state)
        {
            keep.insert(obj);
        }
    }
    keep
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

    /// `plan` with a group-object table loaded into object 3 (the planner's
    /// `obj-table-3` image) and, with `declared`, its MCB check.
    fn with_group_object_table(mut plan: FlashPlan, table: &[u8], declared: bool) -> FlashPlan {
        let image = ImageRef {
            segment_id: GROUP_OBJECT_TABLE_IMAGE.to_string(),
            kind: ImageKind::Table,
            len: table.len(),
            offset: 0,
        };
        plan.images
            .insert(GROUP_OBJECT_TABLE_IMAGE.to_string(), table.to_vec());
        let mut steps = vec![
            FlashStep::Unload {
                target: Some(3),
                absent_ok: false,
            },
            FlashStep::StartLoading { target: Some(3) },
            FlashStep::AllocateSegment {
                size: table.len() as u32,
                target: Some(3),
                fill: super::super::SegmentFill::NONE,
            },
            FlashStep::WriteRelMem {
                offset: 0,
                image,
                target: Some(3),
            },
            FlashStep::LoadCompleted { target: Some(3) },
        ];
        if declared {
            steps.push(FlashStep::LoadImageProp {
                obj_idx: 3,
                prop_id: 27,
                count: 1,
                image: None,
                advisory: false,
            });
        }
        plan.steps.splice(0..0, steps);
        plan
    }

    /// The one MCB entry a device reports for `bytes`.
    fn entry(bytes: &[u8], crc_control: u8) -> Vec<bussard_mgmt::McbEntry> {
        vec![bussard_mgmt::McbEntry {
            segment_size: bytes.len() as u32,
            crc_control,
            access: 0x33,
            crc16: bussard_mgmt::crc16_ccitt(bytes),
        }]
    }

    /// Issues #490, #1127: the dry run against a recorded state keeps the
    /// group-object table when its recorded MCB matches, under the rule
    /// the executor applies ([`keeps`]): another image, CRC control bit 0,
    /// a state other than Loaded or an undeclared MCB check keep nothing.
    /// The application object is never kept.
    #[test]
    fn test_skip_resident_matches_keeps_the_group_object_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = [0x01u8, 0x02, 0x03];
        let base = super::super::test_support::full_only_plan()?;
        let plan = with_group_object_table(base.clone(), &table, true);
        let loaded = |_: u8| None;
        let reloads_3 = |p: &FlashPlan| {
            p.steps
                .iter()
                .any(|s| matches!(s, FlashStep::StartLoading { target: Some(3) }))
        };

        let mut kept = plan.clone();
        assert_eq!(
            kept.skip_resident_matches(&BTreeMap::from([(3u8, entry(&table, 0))]), 4, loaded),
            BTreeSet::from([3u8])
        );
        assert!(!reloads_3(&kept), "{:?}", kept.steps);
        assert!(
            kept.steps
                .iter()
                .any(|s| matches!(s, FlashStep::LoadImageProp { obj_idx: 3, .. })),
            "the MCB check of the kept object stays"
        );
        assert_eq!(kept.steps.len(), plan.steps.len() - 5);

        for (mcbs, state, why) in [
            (
                BTreeMap::from([(3u8, entry(&[9, 9, 9], 0))]),
                None,
                "another image",
            ),
            (
                BTreeMap::from([(3u8, entry(&table, 1))]),
                None,
                "CRC control bit 0",
            ),
            (
                BTreeMap::from([(3u8, entry(&table, 0))]),
                Some(LoadState::Unloaded),
                "not Loaded",
            ),
        ] {
            let mut p = plan.clone();
            assert!(
                p.skip_resident_matches(&mcbs, 4, |_| state).is_empty(),
                "{why}"
            );
            assert_eq!(p.steps, plan.steps, "{why}");
        }

        let mut undeclared = with_group_object_table(base.clone(), &table, false);
        assert!(
            undeclared
                .skip_resident_matches(&BTreeMap::from([(3u8, entry(&table, 0))]), 4, loaded)
                .is_empty(),
            "no MCB check declared: ETS reads no MCB"
        );
        let app = base
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::WriteRelMem { image, .. } => base.image_bytes(&image.segment_id),
                _ => None,
            })
            .ok_or("no write")?
            .to_vec();
        let mut app_plan = base.clone();
        assert!(
            app_plan
                .skip_resident_matches(&BTreeMap::from([(4u8, entry(&app, 0))]), 4, loaded)
                .is_empty(),
            "the application object is never kept"
        );
        Ok(())
    }
}
