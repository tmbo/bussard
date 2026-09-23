//! Post-load verification and the resident-MCB skip gate.
//!
//! Before a re-load, the executor compares each object's resident MCB (memory
//! control block) against the image it is about to write and skips an object
//! that already matches. After the load, [`FlashOutcome`] records the load state
//! and an end-of-segment spot check.

use super::execute::resolve_object_target_opt;
use super::session::{Connector, Session, read_load_state_resumable, read_memory_resumable};
use super::{FlashOutcome, FlashPlan, FlashStep};
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

/// The first up-to-4 octets of an image, used as the post-flash read-back sample.
pub(super) fn take_sample(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len().min(4)].to_vec()
}
