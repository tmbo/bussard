//! The System 7 executor: run a System 7 [`FlashPlan`] against a mask 0705 /
//! 0701 device, then read the written regions back to verify them.

use super::execute::{image_part, write_image};
use super::session::{
    Connector, MAX_RESUME_RECONNECTS, Session, reconnect_exchange_threshold, resumable_death,
};
use super::steps::{Reboot, StepExecutor, run_shared_step, run_steps, send_restart};
use super::verify::take_sample;
use super::{FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageRef, Progress};
use bussard_mgmt::load::{
    IntermediatePoll, LoadControl, LoadState, WriteError, read_mcb_table, read_memory,
};

/// The System 7 step semantics: the LSM records, absolute segment streaming
/// and the plain terminal restart, with the verify state they build up.
struct System7<'a> {
    plan: &'a FlashPlan,
    ctx: &'a super::Sys7Context,
    lsm: bussard_mgmt::LsmAccess,
    /// Whether to verify after the terminal restart (real device) or before it
    /// (a mock that does not reboot-and-return).
    verify_after_restart: bool,
    /// The final outcome, captured by the terminal-restart arm (verify AFTER
    /// reconnect); `None` until then.
    verified: Option<FlashOutcome>,
    /// Read-back spot-check samples of the segment writes (address, first octets).
    written_samples: Vec<(u16, Vec<u8>)>,
    /// The LSMs that reached LoadCompleted, in order, for the post-flash verify.
    completed_lsms: Vec<u32>,
    /// Findings that do not fail the flash (a skipped step, see below).
    warnings: Vec<String>,
}

impl StepExecutor for System7<'_> {
    /// The terminal restart reboots the device itself and is repeated only
    /// after a link loss. The pre-download pass reboots and reconnects too,
    /// so no cycle runs before it, but it stays resumable (its unloads are
    /// idempotent).
    fn reboot(&self, step: &FlashStep) -> Reboot {
        match step {
            FlashStep::Restart => Reboot::SelfReconnecting,
            FlashStep::Sys7PreDownloadRestart { .. } => Reboot::Replayed,
            _ => Reboot::No,
        }
    }

    fn restart_verified(&self) -> bool {
        self.verified.is_some()
    }

    async fn run<C: Connector, F: FnMut(Progress)>(
        &mut self,
        session: &mut Session<C>,
        progress: &mut F,
        index: usize,
        step: &FlashStep,
    ) -> Result<(), WriteError> {
        let plan = self.plan;
        match step {
            FlashStep::Sys7Unload { lsm: idx } => {
                let octet = lsm_octet(session.l4().target(), *idx)?;
                self.lsm
                    .drive(session.l4(), octet, LoadControl::Unload)
                    .await?;
            }
            FlashStep::Sys7StartLoading { lsm: idx } => {
                let octet = lsm_octet(session.l4().target(), *idx)?;
                // A parameter-only download writes into the resident
                // application (issue #146): the machine must hold it,
                // or nothing is written.
                if plan.is_parameters_only() {
                    // A machine still completing an earlier load
                    // (LoadCompleting) is waited out (issue #479).
                    let actual = self
                        .lsm
                        .read_settled_state(session.l4(), octet, IntermediatePoll::STANDARD)
                        .await?;
                    if actual != LoadState::Loaded {
                        return Err(WriteError::NotLoaded {
                            address: session.l4().target(),
                            object_index: octet,
                            actual,
                        });
                    }
                }
                self.lsm
                    .drive(session.l4(), octet, LoadControl::StartLoading)
                    .await?;
            }
            FlashStep::Sys7AbsSegment {
                lsm: idx,
                address,
                size,
                mem_type,
                access,
                seg_flags,
                seg_type,
                image,
            } => {
                // 1. Allocate the absolute segment on the LSM. The captures pin
                //    opcode/subtype, big-endian start+length, `mem_type` and the
                //    per-segment attribute octets, which the plan takes from the
                //    op's `Access`/`MemType`/`SegFlags` (ETS reproduces them
                //    verbatim) or derives from the address when absent.
                let (access, seg_flags) = (*access, *seg_flags);
                // Checked, not truncated: an out-of-range address used to go out as
                // a wrong allocation frame before the following write refused.
                let target = session.l4().target();
                let seg_addr = sys7_u16(target, "segment address", *address)?;
                let seg_size = sys7_u16(target, "segment size", *size)?;
                let event = bussard_mgmt::encode_alloc_segment(
                    *seg_type, seg_addr, seg_size, access, *mem_type, seg_flags,
                );
                let octet = lsm_octet(target, *idx)?;
                self.lsm.send_control(session.l4(), octet, &event).await?;
                // 2. Stream the segment's <Data>, if any, to its absolute address.
                //    A data-less segment (0x0700 RAM region) is allocate-only.
                if let Some(img) = image {
                    let blind =
                        stream_sys7_image(session, plan, seg_addr, img, &mut *progress).await?;
                    // Spot-check only unmasked, checksum-controlled segments
                    // written blind: a masked segment leaves device-owned
                    // bytes untouched, so the image's leading octets do not
                    // equal the device's memory; a `seg_flags == 0`
                    // segment is rewritten by the running application after
                    // the restart (1.1.36 `0x4916`: written `0c`, read back
                    // `00`), so its sample proves nothing. A read-compare
                    // write compared every octet already.
                    if blind
                        && !self.ctx.segment_masks.contains_key(&img.segment_id)
                        && seg_flags != 0
                        && let Some(bytes) = plan.images.get(&img.segment_id)
                    {
                        let part = image_part(bytes, img);
                        self.written_samples.push((seg_addr, take_sample(part)));
                    }
                }
            }
            // A parameter segment written in place, with no allocation
            // record: the System 7 parameter-only download (issue #146).
            FlashStep::WriteMem { address, image } => {
                let addr = sys7_u16(session.l4().target(), "write address", *address)?;
                stream_sys7_image(session, plan, addr, image, &mut *progress).await?;
            }
            FlashStep::Sys7TaskSegment {
                lsm: idx,
                address,
                identity,
            } => {
                let target = session.l4().target();
                let task_addr = sys7_u16(target, "task segment address", *address)?;
                let event = bussard_mgmt::encode_task_segment(task_addr, identity);
                let octet = lsm_octet(target, *idx)?;
                self.lsm.send_control(session.l4(), octet, &event).await?;
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
                self.lsm.send_control(session.l4(), octet, &event).await?;
            }
            FlashStep::Sys7TaskPtr {
                lsm: idx,
                init,
                save,
                pei_handler,
            } => {
                let event = bussard_mgmt::encode_task_ptr(*init, *save, *pei_handler);
                let octet = lsm_octet(session.l4().target(), *idx)?;
                self.lsm.send_control(session.l4(), octet, &event).await?;
            }
            FlashStep::Sys7TaskCtrl2 {
                lsm: idx,
                callback,
                com_objects,
                segment_1,
                segment_2,
            } => {
                let event = bussard_mgmt::encode_task_ctrl2(
                    *callback,
                    *com_objects,
                    *segment_1,
                    *segment_2,
                );
                let octet = lsm_octet(session.l4().target(), *idx)?;
                self.lsm.send_control(session.l4(), octet, &event).await?;
            }
            FlashStep::Sys7LoadCompleted { lsm: idx } => {
                let octet = lsm_octet(session.l4().target(), *idx)?;
                self.lsm
                    .drive(session.l4(), octet, LoadControl::LoadCompleted)
                    .await?;
                self.completed_lsms.push(*idx);
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
                if self.verify_after_restart && session.can_reconnect() {
                    send_restart(session).await;
                    // The device is unreachable while it reboots; poll for it
                    // (bounded), then re-establish the authorized connection and
                    // verify honestly on it.
                    session.reconnect_after_reboot().await?;
                    self.verified = Some(
                        verify_sys7(
                            session,
                            &self.lsm,
                            &self.completed_lsms,
                            &self.written_samples,
                        )
                        .await?,
                    );
                } else {
                    // No connector to reconnect with (mock): verify over the
                    // still-open connection, then fire-and-forget the restart.
                    self.verified = Some(
                        verify_sys7(
                            session,
                            &self.lsm,
                            &self.completed_lsms,
                            &self.written_samples,
                        )
                        .await?,
                    );
                    send_restart(session).await;
                }
            }
            FlashStep::Sys7PreDownloadRestart { unload } => {
                for idx in unload {
                    let octet = lsm_octet(session.l4().target(), *idx)?;
                    match self
                        .lsm
                        .drive(session.l4(), octet, LoadControl::Unload)
                        .await
                    {
                        Ok(_) => {}
                        // ETS unloads LSMs 1 to 4 whatever the procedure
                        // loads; a machine the device lacks, or one that
                        // refuses, is no reason to stop before anything
                        // was written. The procedure's own unloads stay
                        // strict.
                        Err(
                            e @ (WriteError::ObjectAbsent { .. } | WriteError::LoadError { .. }),
                        ) => {
                            self.warnings.push(format!(
                                "step {}: pre-download unload of LSM {idx} skipped: {e}",
                                index + 1
                            ));
                        }
                        Err(e) => return Err(e),
                    }
                }
                // Reboot the device into its unloaded state and start the
                // download on a fresh connection, as ETS does. Without a
                // connector (a mock built from one open connection) the
                // session could not come back, so the restart is skipped.
                if session.can_reconnect() {
                    send_restart(session).await;
                    session.reconnect_after_reboot().await?;
                }
            }
            FlashStep::EnableVerifyMode => {
                // From here every segment write's echo is compared
                // with the chunk (DMP_MemWrite_RCoV, Management
                // Procedures 03_05_02 §3.16.3), and the session sets
                // the mode again on every later connection (issue
                // #524). A device without it streams as before.
                match session.enable_verify_mode().await? {
                    bussard_mgmt::VerifyModeOutcome::Refused { previous } => {
                        self.warnings.push(format!(
                            "step {}: the device refused verify mode \
                             (PID_DEVICE_CONTROL stays {previous:#04X}); the segment \
                             writes were not self.verified by echo",
                            index + 1
                        ));
                    }
                    bussard_mgmt::VerifyModeOutcome::Unsupported => {
                        self.warnings.push(format!(
                            "step {}: the device has no readable PID_DEVICE_CONTROL; \
                             the segment writes were not self.verified by echo",
                            index + 1
                        ));
                    }
                    _ => {}
                }
            }
            other => match run_shared_step(session, other).await {
                Some(result) => result?,
                // System B steps never appear in a System 7 plan.
                None => {
                    return Err(WriteError::Mgmt(
                        bussard_mgmt::MgmtError::MalformedResponse {
                            address: session.l4().target(),
                            reason: format!("System 7 executor met a non-System-7 step: {other:?}"),
                        },
                    ));
                }
            },
        }
        Ok(())
    }

    fn recover(
        &mut self,
        index: usize,
        step: &FlashStep,
        err: WriteError,
    ) -> Result<(), WriteError> {
        match err {
            // Unloading an object the device does not have leaves nothing
            // loaded on it: the goal of the step already holds.
            WriteError::ObjectAbsent { object_index, .. }
                if matches!(step, FlashStep::Sys7Unload { .. }) =>
            {
                self.warnings.push(format!(
                    "step {}: object {object_index} absent on the device, nothing to unload",
                    index + 1
                ));
                Ok(())
            }
            // The terminal restart already ran and verified the download
            // (issue #178): a step after it cannot undo that, so its failure
            // is reported, not turned into a failed, "partially written"
            // flash. The planner emits no such step; a hand-built plan can.
            e if self.verified.is_some() => {
                self.warnings.push(format!(
                    "step {} ({}) after the final restart failed and was skipped: {e}",
                    index + 1,
                    self.plan.step_label(step)
                ));
                Ok(())
            }
            e => Err(e),
        }
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
/// [`Session::open`]). The step loop, proactive L4 cycling and resume-on-drop
/// are [`run_steps`], shared with [`flash`](super::flash). ETS holds one
/// connection for the whole System 7 download, so the cycle is off unless the
/// plan targets KNX Virtual or the environment asks for it (issue #116).
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
    let mut exec = System7 {
        plan,
        ctx,
        lsm: bussard_mgmt::lsm_access_from_profile(&ctx.profile),
        verify_after_restart: options.verify_after_restart,
        verified: None,
        written_samples: Vec::new(),
        completed_lsms: Vec::new(),
        warnings: Vec::new(),
    };
    let threshold = reconnect_exchange_threshold(plan);
    run_steps(session, plan, threshold, &mut progress, &mut exec).await?;

    // The terminal restart captured the outcome (verify AFTER reboot). A procedure
    // with no final Restart falls back to verifying now over the still-open
    // connection.
    let mut outcome = match exec.verified {
        Some(outcome) => outcome,
        None => {
            verify_sys7(
                session,
                &exec.lsm,
                &exec.completed_lsms,
                &exec.written_samples,
            )
            .await?
        }
    };
    outcome.warnings.extend(exec.warnings);
    Ok(outcome)
}

/// Streams the plan's image for `segment_id` to `addr` and reports whether it
/// was written blind (`true`) or read-compare-written (`false`).
///
/// A parameter-only download (issue #119) narrows the write to the octets that
/// differ from the resident memory read before planning: the mask owns only
/// those runs, so read-compare reads and compares just the chunks that hold
/// them, and the plain writer writes just them. A mask with no `VerifyMode`
/// reads each chunk, writes only the differing ones, and lets the read-back
/// stand as the verification (issue #133).
async fn stream_sys7_image<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    plan: &FlashPlan,
    addr: u16,
    image: &ImageRef,
    progress: &mut F,
) -> Result<bool, WriteError> {
    let ctx = plan
        .sys7
        .as_ref()
        .expect("stream_sys7_image called on a non-System-7 plan");
    let whole = plan
        .images
        .get(&image.segment_id)
        .expect("System 7 segment image resolved at plan time");
    // The part of the image this step's allocation holds (issue #413): the
    // whole image unless the procedure allocates the segment in parts. The
    // mask and the baseline are indexed like the image, so they are cut the
    // same way.
    let bytes = image_part(whole, image);
    let mask = ctx
        .segment_masks
        .get(&image.segment_id)
        .map(|m| image_part(m, image));
    let diff_mask = plan.baseline.get(&image.segment_id).map(|current| {
        let current = image_part(current, image);
        let mut owned = vec![0u8; bytes.len()];
        // The historic gap on System 7 (see `LEGACY_MERGE_GAP`): any join
        // within it counts as saving a request, as before issue #210.
        let regions = super::execute::diff_regions(
            bytes,
            current,
            mask,
            super::execute::LEGACY_MERGE_GAP,
            &|_, _| usize::MAX,
        );
        for (start, end) in regions {
            owned[start..end].fill(0xFF);
        }
        owned
    });
    let mask_slice = diff_mask.as_deref().or(mask);
    if ctx.profile.read_compare_write() {
        read_compare_sys7_segment(session, addr, bytes, mask_slice, progress).await?;
        Ok(false)
    } else {
        write_sys7_segment(session, addr, bytes, mask_slice, progress).await?;
        Ok(true)
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
    let octets = completed_lsms
        .iter()
        .map(|idx| lsm_octet(session.l4().target(), *idx))
        .collect::<Result<Vec<u8>, WriteError>>()?;
    // One read for every memory-mapped status octet (issue #215); the
    // per-LSM reads below stay the fallback.
    if let Some(states) = read_lsm_states_at_once(session, lsm, &octets).await {
        for (octet, state) in octets.iter().copied().zip(states) {
            if state != LoadState::Loaded {
                all_loaded = false;
            }
            object_states.push((octet, state));
        }
    }
    let per_lsm: &[u32] = if object_states.is_empty() {
        completed_lsms
    } else {
        &[]
    };
    for idx in per_lsm {
        let octet = lsm_octet(session.l4().target(), *idx)?;
        // Re-read through a resumable death: a just-rebooted device can drop the
        // first probe on the fresh connection before it is fully back, and a
        // gateway link loss can hit the read too (issue #192). Bounded by
        // MAX_RESUME_RECONNECTS consecutive reconnects.
        let mut reconnects = 0u32;
        let state = loop {
            match lsm.read_state(session.l4(), octet).await {
                Ok(state) => break state,
                Err(e) if resumable_death(&e, session) && reconnects < MAX_RESUME_RECONNECTS => {
                    reconnects += 1;
                    session.reconnect().await?;
                }
                Err(e) => return Err(e),
            }
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
        warnings: Vec::new(),
        reboot_readiness: Vec::new(),
        verify_echoes: None,
        property_only: false,
    })
}

/// Reads the status octets of several memory-mapped LSMs (the 0701
/// realisation, status of LSM `n` at `status_addr + n - 1`) with a single
/// `A_Memory_Read` over the contiguous span that holds them (issue #215).
///
/// The octets are the ones the per-LSM reads would read, decoded the same
/// way, so the verdict is unchanged. Returns `None`, and the caller reads each
/// LSM on its own as before, for a property-based realisation (one object per
/// LSM), fewer than two LSMs, a span wider than the connection's memory chunk,
/// or any failure or short answer of the combined read.
async fn read_lsm_states_at_once<C: Connector>(
    session: &mut Session<C>,
    lsm: &bussard_mgmt::LsmAccess,
    octets: &[u8],
) -> Option<Vec<LoadState>> {
    let bussard_mgmt::LsmAccess::MemoryMapped { status_addr, .. } = lsm else {
        return None;
    };
    let (first, last) = (*octets.iter().min()?, *octets.iter().max()?);
    if octets.len() < 2 || first == 0 {
        return None;
    }
    let span = last - first + 1;
    if span > session.l4().max_memory_chunk() {
        return None;
    }
    let addr = status_addr.checked_add(u16::from(first - 1))?;
    let data = read_memory(session.l4(), u32::from(addr), span)
        .await
        .ok()?;
    if data.len() != usize::from(span) {
        return None;
    }
    octets
        .iter()
        .map(|octet| {
            data.get(usize::from(octet - first))
                .map(|b| LoadState::from_octet(*b))
        })
        .collect()
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
/// write mask (`[system7-spec §4.2]`, the product's `<Mask>` with the placed
/// parameter octets added, issue #320): a `0xFF` mask byte means the byte
/// belongs to the image and is written; any other value marks a device-owned
/// byte the write must leave untouched. Owned bytes are streamed in maximal contiguous runs
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
        write_image(session, u32::from(addr), bytes, progress).await?;
        progress(Progress::Written {
            written: bytes.len(),
            writable: bytes.len(),
        });
        return Ok(());
    };
    // Walk the mask, writing each maximal run of owned (0xFF) bytes at its address.
    let mut written = 0usize;
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
        written += i - run_start;
    }
    progress(Progress::Written {
        written,
        writable: written,
    });
    Ok(())
}

/// Streams a System 7 segment image read-compare-write, the ETS behaviour on a
/// mask without a Hawk `VerifyMode` (Theben `0701`, issue #133,
/// `[system7-spec §4.2 amendment]`).
///
/// The image is walked in chunks of the negotiated memory chunk (the write
/// chunk, 12 octets on the Meteodata). Each chunk is read from the device and
/// compared with the image over its owned octets (all of them without a
/// mask; only the `0xFF`-masked ones with one, a placed parameter octet under
/// a `0x00` product `<Mask>` byte included (issue #320), and a chunk with no
/// owned octet is neither read nor written). A matching chunk is left alone. A
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
    let writable = (0..total).filter(|&i| owned(i)).count();
    let mut written_chunks = 0usize;
    let mut written_octets = 0usize;
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
                    written_octets += i - run_start;
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
        // The walk position, for a progress bar; `Written` below reports what
        // was written (issue #320).
        progress(Progress::Bytes {
            written: start,
            total,
        });
    }
    progress(Progress::Written {
        written: written_octets,
        writable,
    });
    Ok(written_chunks)
}
