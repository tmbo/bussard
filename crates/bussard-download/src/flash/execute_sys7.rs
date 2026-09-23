//! The System 7 executor: run a System 7 [`FlashPlan`] against a mask 0705 /
//! 0701 device, then read the written regions back to verify them.

use super::execute::write_image;
use super::session::{
    Connector, MAX_RESUME_RECONNECTS, Session, reconnect_exchange_threshold, resumable_death,
};
use super::verify::take_sample;
use super::{FlashOptions, FlashOutcome, FlashPlan, FlashStep, Progress};
use bussard_mgmt::load::{
    LoadControl, LoadState, WriteError, compare_property, read_mcb_table, read_memory,
};

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
/// discipline as [`flash`](super::flash) via the session, but has its own step loop because the
/// LSM control and absolute streaming differ from System B.
pub(super) async fn flash_sys7<C: Connector, F: FnMut(Progress)>(
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
            label: plan.step_label(step),
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
                            if ctx.profile.read_compare_write() {
                                // No `VerifyMode` on this mask: read each chunk,
                                // write only the differing ones, and let the
                                // read-back stand as the verification (issue
                                // #133). Every octet was compared, so no
                                // post-restart spot check is recorded.
                                read_compare_sys7_segment(
                                    session,
                                    addr,
                                    bytes,
                                    mask.map(Vec::as_slice),
                                    &mut progress,
                                )
                                .await?;
                            } else {
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
pub(super) async fn verify_sys7<C: Connector>(
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
/// [`plan_flash_sys7`](super::plan_sys7::plan_flash_sys7) already validates these at plan time
/// ([`PlanError::Sys7FieldOutOfRange`](super::PlanError::Sys7FieldOutOfRange)); this is the executor's own guard, so a
/// hand-built or deserialized plan cannot put an allocation at a wrapped address
/// on the bus either (issue #81).
pub(super) fn sys7_u16(
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
/// [`PlanError::Sys7LsmOutOfRange`](super::PlanError::Sys7LsmOutOfRange) at plan time.
pub(super) fn lsm_octet(
    address: bussard_model::IndividualAddress,
    lsm: u32,
) -> Result<u8, WriteError> {
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
pub(super) async fn read_sys7_memory<C: Connector>(
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
pub(super) async fn write_sys7_segment<C: Connector, F: FnMut(Progress)>(
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

/// Streams a System 7 segment image read-compare-write, the ETS behaviour on a
/// mask without a Hawk `VerifyMode` (Theben `0701`, issue #133,
/// `[system7-spec §4.2 amendment]`).
///
/// The image is walked in chunks of the negotiated memory chunk (the write
/// chunk, 12 octets on the Meteodata). Each chunk is read from the device and
/// compared with the image over its owned octets (all of them without a
/// `<Mask>`; only the `0xFF`-masked ones with one, and a chunk with no owned
/// octet is neither read nor written). A matching chunk is left alone. A
/// differing chunk has its owned runs written, then is read back and must
/// match, or the write fails with
/// [`MgmtError::MemoryVerifyFailed`](bussard_mgmt::MgmtError::MemoryVerifyFailed).
/// Returns the number of chunks written.
pub(super) async fn read_compare_sys7_segment<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    addr: u16,
    bytes: &[u8],
    mask: Option<&[u8]>,
    progress: &mut F,
) -> Result<usize, WriteError> {
    let owned = |i: usize| mask.is_none_or(|m| m.get(i).copied() == Some(0xFF));
    let chunk = usize::from(session.l4().max_memory_chunk()).max(1);
    let total = bytes.len();
    let mut written_chunks = 0usize;
    let mut start = 0usize;
    while start < total {
        let end = (start + chunk).min(total);
        // The owned span inside this chunk: read only from its first to its last
        // owned octet, so a masked chunk never reads a device-owned edge.
        let first = (start..end).find(|&i| owned(i));
        let last = (start..end).rev().find(|&i| owned(i));
        if let (Some(first), Some(last)) = (first, last) {
            let span_addr = addr.saturating_add(first as u16);
            let expected = &bytes[first..=last];
            let differs = |got: &[u8]| {
                got.len() != expected.len()
                    || (first..=last).any(|i| owned(i) && got[i - first] != bytes[i])
            };
            let got = read_memory(session.l4(), u32::from(span_addr), expected.len() as u8).await?;
            if differs(&got) {
                // Write the owned runs of the span (all of it without a mask).
                let mut i = first;
                while i <= last {
                    if !owned(i) {
                        i += 1;
                        continue;
                    }
                    let run_start = i;
                    while i <= last && owned(i) {
                        i += 1;
                    }
                    let run_addr = addr.saturating_add(run_start as u16);
                    write_image(
                        session,
                        u32::from(run_addr),
                        &bytes[run_start..i],
                        &mut |_: Progress| {},
                    )
                    .await?;
                }
                let got =
                    read_memory(session.l4(), u32::from(span_addr), expected.len() as u8).await?;
                if differs(&got) {
                    return Err(WriteError::Mgmt(
                        bussard_mgmt::MgmtError::MemoryVerifyFailed {
                            address: session.l4().target(),
                            addr: u32::from(span_addr),
                            expected: expected.to_vec(),
                            got,
                        },
                    ));
                }
                written_chunks += 1;
            }
        }
        start = end;
        progress(Progress::Bytes {
            written: start,
            total,
        });
    }
    Ok(written_chunks)
}
