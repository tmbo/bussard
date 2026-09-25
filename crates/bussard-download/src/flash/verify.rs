//! Post-load verification and the resident-MCB skip gate.
//!
//! Before a re-load, the executor compares each object's resident MCB (memory
//! control block) against the image it is about to write and skips an object
//! that already matches. After the load, [`FlashOutcome`] records the load state
//! and an end-of-segment spot check.

use super::execute::resolve_object_target_opt;
use super::session::{Connector, Session, read_load_state_resumable, read_memory_resumable};
use super::{FlashOutcome, FlashPlan, FlashStep, ImageRef};
use bussard_mgmt::load::{LoadState, WriteError, read_load_state, read_mcb_table};
use std::collections::BTreeSet;

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
pub(super) fn mcb_skip_target(
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
pub(super) async fn resident_match_objects<C: Connector>(
    session: &mut Session<C>,
    plan: &FlashPlan,
    app_obj: u8,
    object_table: &[(u8, u16)],
) -> Result<BTreeSet<u8>, WriteError> {
    // The candidate objects: those the executor would resolve a WriteRelMem onto.
    let mut candidates: BTreeSet<u8> = BTreeSet::new();
    for step in &plan.steps {
        if let FlashStep::WriteRelMem { target, .. } = step
            && let Some(obj) = resolve_object_target_opt(
                *target,
                object_table,
                app_obj,
                plan.spliced_from_template,
            )
        {
            candidates.insert(obj);
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

    let spot_checks_match = spot_check(session, written_samples.iter()).await?;
    Ok(FlashOutcome {
        load_state,
        object_states,
        spot_checks_match,
        warnings: Vec::new(),
        reboot_readiness: Vec::new(),
    })
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
}

/// Reads every sample back; `false` as soon as one differs from what was
/// written. Each read is resume-on-drop.
async fn spot_check<'a, C: Connector>(
    session: &mut Session<C>,
    samples: impl Iterator<Item = &'a WrittenSample>,
) -> Result<bool, WriteError> {
    let mut all_match = true;
    for sample in samples {
        let got = read_memory_resumable(session, sample.address, sample.bytes.len() as u8).await?;
        if got != sample.bytes {
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
    written_samples: &[WrittenSample],
    mcb_verified: &BTreeSet<(u8, String)>,
) -> Result<FlashOutcome, WriteError> {
    let load_state = read_load_state_resumable(session, app_obj).await?;
    if load_state != LoadState::Loaded {
        return verify_outcome(session, app_obj, completed_objects, written_samples).await;
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
    let spot_checks_match = spot_check(session, uncovered).await?;
    Ok(FlashOutcome {
        load_state,
        object_states,
        spot_checks_match,
        warnings: Vec::new(),
        reboot_readiness: Vec::new(),
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
}
