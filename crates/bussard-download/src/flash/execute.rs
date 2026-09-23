//! The System B executor: run a validated [`FlashPlan`] against a device.
//!
//! [`flash`] walks the plan step by step over a [`Session`]: it discovers the
//! application-program object, drives the load-state machine, streams the
//! segment images, performs the factory reset step when the plan asks for one
//! and verifies the result.

use super::execute_sys7::flash_sys7;
use super::labels::step_label;
use super::session::{
    Connector, MAX_RESUME_RECONNECTS, Session, allocate_with_context_resumable,
    read_load_state_resumable, reconnect_exchange_threshold, resumable_death,
    start_loading_resumable, write_load_control_resumable,
};
use super::verify::{
    advisory_mcb_warning, mcb_read_object, mcb_skip_target, resident_match_objects, take_sample,
    verify_outcome,
};
use super::{FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageKind, Progress};
use bussard_mgmt::MgmtError;
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{
    LoadControl, LoadState, WriteError, compare_property, compare_rel_mem,
    master_reset_via_basic_restart, read_mcb_table, read_table_reference, write_property,
};
use bussard_mgmt::tables::OT_APPLICATION_PROGRAM;
use std::collections::{BTreeMap, BTreeSet};

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
pub(super) async fn discover_object_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<(u8, Vec<(u8, u16)>), WriteError> {
    let table = probe_object_types(l4).await?;
    match table
        .iter()
        .find(|(_, ot)| *ot == OT_APPLICATION_PROGRAM)
        .map(|(index, _)| *index)
    {
        Some(index) => Ok((index, table)),
        None => Err(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: l4.target(),
                reason: "device is missing the application-program interface object".to_string(),
            },
        )),
    }
}

/// Walks `PID_OBJECT_TYPE` from index 0 and returns the `(index, object type)`
/// table the device exposes, in this crate's error type.
///
/// The walk itself is [`bussard_mgmt::probe_object_types`] — the crate-wide
/// interface-object discovery the table read side and `apply` use too, so all of
/// them see the same device picture. Its tolerance at the end of the object list
/// (an off-service, undecodable, empty or short answer means "no object here")
/// came from this walk: it is what lets it run against real devices, KNX Virtual
/// and the thelsing demo included, whose answer for an out-of-range object index
/// is not uniform.
pub(crate) async fn probe_object_types<Ch: bussard_mgmt::L4Channel>(
    l4: &mut bussard_mgmt::Layer4Connection<Ch>,
) -> Result<Vec<(u8, u16)>, WriteError> {
    Ok(bussard_mgmt::probe_object_types(l4).await?)
}

/// Discovers the object table like [`discover_object_table`], but **resumable at
/// probe granularity** over the session so it survives a connection death mid-walk.
///
/// It probes `PID_OBJECT_TYPE` at each interface-object index in turn; on an
/// unexpected connection death it reconnects and continues from the next
/// unprobed index (object types are stable device state, so the indices already
/// read stay valid). This matters on a device whose per-connection exchange budget
/// is smaller than the number of objects: a single-shot discovery could never
/// finish in one window, but accumulating one probe of forward progress per window
/// does. Bounded by [`MAX_RESUME_RECONNECTS`] *reconnects without any new probe*, so
/// a device that answers nothing still fails cleanly; every successful probe resets
/// the bound.
pub(super) async fn discover_object_table_resumable<C: Connector>(
    session: &mut Session<C>,
) -> Result<(u8, Vec<(u8, u16)>), WriteError> {
    let mut table: Vec<(u8, u16)> = Vec::new();
    let mut app_obj: Option<u8> = None;
    let mut index: u8 = 0;
    let mut stalled_reconnects = 0u32;
    while index < bussard_mgmt::MAX_OBJECT_INDEX {
        // One index at a time through the shared, tolerant probe, so the resumable
        // walk and the one-shot `probe_object_types` terminate identically.
        match bussard_mgmt::probe_object_type(session.l4(), index)
            .await
            .map_err(WriteError::Mgmt)
        {
            Ok(None) => break,
            Ok(Some(ot)) => {
                stalled_reconnects = 0;
                table.push((index, ot));
                if ot == OT_APPLICATION_PROGRAM && app_obj.is_none() {
                    app_obj = Some(index);
                }
                index += 1;
            }
            // Unexpected connection death mid-walk: reconnect and RETRY this same
            // index (no progress was made on it). Bounded by consecutive stalls so a
            // genuinely dead device fails cleanly.
            Err(e)
                if resumable_death(&e, session) && stalled_reconnects < MAX_RESUME_RECONNECTS =>
            {
                stalled_reconnects += 1;
                session.reconnect().await?;
            }
            Err(e) => return Err(e),
        }
    }
    let target = session.l4().target();
    match app_obj {
        Some(index) => Ok((index, table)),
        None => Err(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: target,
                reason: "device is missing the application-program interface object".to_string(),
            },
        )),
    }
}

/// Re-confirms the application-program object index on a fresh post-restart
/// connection with a **single** `PID_OBJECT_TYPE` probe.
///
/// The interface-object table is device state that survives a reboot, so the
/// index discovered before the terminal restart is still the right one; the only
/// thing worth checking is that the device really is back and still reports that
/// index as an application-program object. A probe that answers anything else —
/// a different type, no object, or a read error — means the picture is not what
/// was assumed, so the full resumable walk runs and decides (it also reconnects
/// if the probe killed the connection).
pub(super) async fn confirm_app_object<C: Connector>(
    session: &mut Session<C>,
    app_obj: u8,
) -> Result<u8, WriteError> {
    match bussard_mgmt::probe_object_type(session.l4(), app_obj).await {
        Ok(Some(OT_APPLICATION_PROGRAM)) => Ok(app_obj),
        _ => discover_object_table_resumable(session)
            .await
            .map(|(index, _table)| index),
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
pub(super) fn resolve_object_target_opt(
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

/// Executes a validated [`FlashPlan`] against the device over the session's
/// connection, reporting progress through `progress`, then verifies the result.
///
/// The application-program object index is discovered live; the plan's steps run
/// in order, streaming the plan's resolved images into device memory (chunked by
/// [`write_memory`], which does not read each chunk back — see the module docs).
/// After the sequence, the object's
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
    // System 7 has its own memory-mapped, absolute-addressed executor: the LSM
    // control, absolute streaming and read-back verify all differ from System B.
    if plan.sys7.is_some() {
        return flash_sys7(session, plan, options, progress).await;
    }
    // `options.bcu_key` was consumed at connect time (the session was opened with
    // it); only `verify_after_restart` is read below, in the terminal-restart arm.
    let verify_after_restart = options.verify_after_restart;
    // The initial object-type discovery is itself several numbered exchanges — more
    // than a very tight per-connection budget allows in one window — so on such a
    // device the drop lands here, before the first step. Discovery resumes at
    // **probe granularity**: it walks object indices, and on a connection death it
    // reconnects and CONTINUES from the next index, keeping the indices already
    // probed. Whole-operation replay alone could not recover a discovery that needs
    // more exchanges than the budget; per-probe forward progress can.
    //
    // A session opened with [`DeviceFacts`] (the CLI: its read-only pre-flight
    // already walked `PID_OBJECT_TYPE` over every object) skips the walk entirely
    // — the table is device-stable, so re-reading it would only repeat one
    // `A_PropertyValue_Read` per interface object. Without facts (the library
    // API, every mock and oracle test) the walk runs exactly as before.
    let (app_obj, object_table) = match session.known_object_table() {
        Some(known) => known,
        None => discover_object_table_resumable(session).await?,
    };
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
    // Advisory findings (an MCB check the application's procedure does not
    // declare that did not match), carried into the outcome.
    let mut warnings: Vec<String> = Vec::new();
    // The size of the most-recently allocated relative segment, remembered so a
    // `MasterReset` step (which reboots the device and, on KNX Virtual, wipes the
    // app object's load state back to `Unloaded` and drops the segment allocated
    // before it) can re-open the object and re-allocate the same-sized segment on
    // the fresh connection — updating `segment_base` to the freshly-returned
    // address — before the resumed `WriteRelMem` targets it. `None` until the
    // first `AllocateSegment`.
    let mut last_alloc_size: Option<u32> = None;
    // The pre-fill (`Mode`/`Fill`) the most-recent `AllocateSegment`
    // requested, so a `MasterReset` re-allocation reproduces the same fill flag
    // as the original op rather than silently dropping it. `None` = no-fill (the
    // DA.tp default).
    let mut last_alloc_fill: Option<u8> = None;
    // The pre-fill each object's segment was allocated with, so its
    // `WriteRelMem` streams only what differs from the fill (issue #123).
    let mut segment_fills: BTreeMap<u8, Option<u8>> = BTreeMap::new();
    // The object index the most-recent `AllocateSegment` targeted, so a
    // `MasterReset` re-opens and re-allocates *that* object (the one whose segment
    // the reset dropped) rather than the type-discovered application object. On
    // KNX Virtual DA.tp the app segment is obj4 (allocated right before the reset)
    // while the type-discovered app object is obj3 — re-opening obj3 here would
    // double-`StartLoading` it (the template re-opens obj3 itself after the reset)
    // and drive it to `Error`. `None` until the first `AllocateSegment`.
    let mut last_alloc_target: Option<u8> = None;
    // Track (address, sample_len) of writes for the post-flash spot check. The
    // address is 24-bit: an extended-memory segment (07B0 actuators) lives above
    // 0xFFFF, and the spot-check read picks plain vs extended from it.
    let mut written_samples: Vec<(u32, Vec<u8>)> = Vec::new();
    // The verified outcome, captured just before a terminal restart reboots the
    // device (after which it is unreachable and cannot be verified). `None` until
    // then; the post-loop verify runs only if it is still `None`.
    let mut verified: Option<FlashOutcome> = None;

    // The proactive-reconnect exchange threshold (0 = disabled), read once.
    let reconnect_threshold = reconnect_exchange_threshold();

    // Item 2 (issue #73): the MCB-CRC re-download skip. When enabled, read each
    // to-be-written object's resident `PID_MCB_TABLE` *before* any step touches
    // it and, on a size+CRC match against the image bussard would stream, mark
    // that object skippable. The skip drops the object's re-load steps (so no
    // body bytes stream and the intact resident load is left untouched) but is
    // NEVER taken on a fresh/blank device (no MCB entry) or a size/CRC mismatch —
    // those full-stream exactly as before. Disabled by default, so DA.tp and
    // every mock path are byte-identical.
    //
    // A plan that factory-resets the device first erases every object, so no
    // resident image can survive to be matched: the pre-pass is skipped and every
    // object streams in full.
    let skip_objects: BTreeSet<u8> = if options.skip_matching_mcb && !plan.has_factory_reset() {
        resident_match_objects(session, plan, app_obj, &object_table).await?
    } else {
        BTreeSet::new()
    };

    for (i, step) in plan.steps.iter().enumerate() {
        // A resident-match object (its MCB already matched the image bussard
        // would stream) skips its whole re-load: the `Unload`/`StartLoading`/
        // `AllocateSegment`/`WriteRelMem`/`LoadCompleted` for it are dropped so
        // the intact resident load is untouched and ZERO body bytes stream
        // (matching ETS's group-B captures). Its `LoadImageProp` MCB re-verify is
        // kept (a read-only confirm that passes by construction). The object is
        // still recorded as completed so the post-flash verify covers it.
        if let Some(skip_obj) = mcb_skip_target(step, &object_table, app_obj, plan) {
            if skip_objects.contains(&skip_obj) {
                if let FlashStep::LoadCompleted { .. } = step {
                    if !completed_objects.contains(&skip_obj) {
                        completed_objects.push(skip_obj);
                    }
                }
                progress(Progress::Step {
                    index: i + 1,
                    total,
                    label: format!(
                        "skip {} (unchanged: resident MCB size+CRC match the image, object Loaded)",
                        step_label(step)
                    ),
                });
                continue;
            }
        }
        // Proactive periodic L4 reconnection (the ETS pattern): before starting a
        // step, if this connection's numbered-exchange count has reached the
        // threshold, cycle the connection (graceful T_Disconnect / T_Connect +
        // re-authorize) so it never approaches the device's per-connection budget
        // (~35 on KNX Virtual). The objects' load states and their allocated
        // segments are persistent device state, not connection state, so they
        // survive the cycle and the step resumes on a fresh, zero-exchange
        // connection. The check is *between* steps — never mid memory-write — so a
        // chunked write is never split across a reconnect.
        //
        // Steps that reboot the device and re-establish the connection themselves
        // (`MasterReset`, terminal `Restart`) are skipped here: cycling right
        // before them would be a wasted reconnect (they drop and re-open the
        // connection anyway). A single-connection session (mocks,
        // `from_connection`) cannot reconnect, so it keeps the one-connection path.
        let self_reconnecting_step = matches!(
            step,
            FlashStep::MasterReset { .. } | FlashStep::Restart | FlashStep::FactoryReset { .. }
        );
        if reconnect_threshold > 0
            && session.can_reconnect()
            && !self_reconnecting_step
            && session.numbered_exchanges() >= reconnect_threshold
        {
            session.cycle_l4().await?;
        }
        progress(Progress::Step {
            index: i + 1,
            total,
            label: plan.step_label(step),
        });

        // Resume-on-drop: run the step, and if it dies from an *unexpected* mid-flow
        // connection death (the device dropped the L4 connection at a
        // non-deterministic exchange count — see [`is_connection_death`]) and the
        // session can reconnect, cycle the L4 connection and re-run the whole step.
        // Load state and allocated segments are persistent device state that survive
        // the drop, so re-running the step on the fresh connection is safe: memory
        // writes are absolute/relative-addressed, and a re-issued StartLoading /
        // allocate on an already-open object lands in the same state. Bounded by
        // [`MAX_RESUME_RECONNECTS`] per step so a genuinely dead device that never
        // makes progress fails cleanly instead of looping forever; any step that
        // completes starts the next with a full budget (forward progress resets it).
        //
        // `MasterReset` and the terminal `Restart` reboot the device and reconnect
        // themselves, so they are excluded from resume-on-drop — their own silence
        // is expected, not a death to recover from.
        let mut resume_reconnects = 0u32;
        'resume: loop {
            let step_result: Result<(), WriteError> = async {
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
                            return Ok(());
                        };
                        write_load_control_resumable(session, obj, LoadControl::Unload).await?;
                    }
                    FlashStep::StartLoading { target } => {
                        let Some(obj) = resolve_object_target_opt(
                            *target,
                            &object_table,
                            app_obj,
                            plan.spliced_from_template,
                        ) else {
                            return Ok(());
                        };
                        start_loading_resumable(session, obj, &object_table).await?;
                    }
                    FlashStep::AllocateSegment { size, target, fill } => {
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
                            return Ok(());
                        };
                        let alloc = allocate_with_context_resumable(
                            session,
                            obj,
                            *size,
                            *fill,
                            &object_table,
                        )
                        .await?;
                        segment_base = Some(alloc.address);
                        segment_bases.insert(obj, alloc.address);
                        segment_fills.insert(obj, *fill);
                        last_alloc_size = Some(*size);
                        last_alloc_fill = *fill;
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
                        let obj = resolve_object_target_opt(
                            *target,
                            &object_table,
                            app_obj,
                            plan.spliced_from_template,
                        );
                        let base = obj
                            .and_then(|obj| segment_bases.get(&obj).copied())
                            .or(segment_base)
                            .unwrap_or(0);
                        // The fill the target segment was allocated with (the
                        // most-recent allocation's for the single-object shape).
                        let fill = match obj.and_then(|obj| segment_fills.get(&obj).copied()) {
                            Some(fill) => fill,
                            None => last_alloc_fill,
                        };
                        // The device-supplied segment base plus the vendor offset must fit
                        // the 24-bit extended-memory space. `write_image` picks the plain
                        // A_Memory_Write (≤0xFFFF, byte-identical to before) or the
                        // A_MemoryExtended_Write service from the resolved address, so a
                        // base above 0xFFFF (the Jung/ABB 07B0 actuators) streams via the
                        // extended service instead of being refused.
                        let addr = base
                            .checked_add(*offset)
                            .filter(|&a| a <= bussard_mgmt::apci::MAX_MEMORY_ADDRESS)
                            .ok_or_else(|| WriteError::AddressOutOfRange {
                                address: session.l4().target(),
                                detail: format!("segment base {base:#X} + offset {offset:#X}"),
                            })?;
                        let bytes = plan
                            .images
                            .get(&image.segment_id)
                            .cloned()
                            .unwrap_or_default();
                        match fill {
                            // A pre-filled segment already holds the fill byte
                            // everywhere: write only the runs that differ, as ETS
                            // does (the F50 obj4 image is 276 of 6152 octets).
                            Some(fill) => {
                                for (start, run) in fill_regions(&bytes, fill) {
                                    write_image(session, addr + start as u32, run, &mut progress)
                                        .await?;
                                }
                            }
                            None => write_image(session, addr, &bytes, &mut progress).await?,
                        }
                        if let Some(sample) = bytes.first().map(|_| take_sample(&bytes)) {
                            written_samples.push((addr, sample));
                        }
                    }
                    FlashStep::WriteMem { address, image } => {
                        // The absolute address must fit the 24-bit extended-memory space;
                        // `write_image` picks plain vs extended from the address (≤0xFFFF
                        // stays byte-identical to the historical plain path).
                        let addr = *address;
                        if addr > bussard_mgmt::apci::MAX_MEMORY_ADDRESS {
                            return Err(WriteError::AddressOutOfRange {
                                address: session.l4().target(),
                                detail: format!("absolute address {address:#X}"),
                            });
                        }
                        let bytes = plan
                            .images
                            .get(&image.segment_id)
                            .cloned()
                            .unwrap_or_default();
                        match plan.baseline.get(&image.segment_id) {
                            // A parameter-only download (issue #119): write only
                            // the octets that differ from what the device holds.
                            Some(current) => {
                                for (start, end) in diff_regions(&bytes, current, None) {
                                    write_image(
                                        session,
                                        addr + start as u32,
                                        &bytes[start..end],
                                        &mut progress,
                                    )
                                    .await?;
                                }
                            }
                            None => write_image(session, addr, &bytes, &mut progress).await?,
                        }
                        if !bytes.is_empty() {
                            written_samples.push((addr, take_sample(&bytes)));
                        }
                    }
                    FlashStep::WriteProp {
                        obj_idx,
                        obj_type,
                        prop_id,
                        value,
                        start_element,
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
                            return Ok(());
                        }
                        let obj = (*obj_idx).min(u32::from(u8::MAX)) as u8;
                        let pid = (*prop_id).min(u32::from(u8::MAX)) as u8;
                        // PID_MCB_TABLE is an array of 8-octet entries and the vendor
                        // InlineData is padded to 10: ETS writes one 8-octet element per
                        // request from `StartElement` (1.1.18 capture: `count=1 index=1
                        // len=8`, then `index=2`). The Jung F50 refuses the padded
                        // 10-octet write with a zero-count response (issue #89).
                        if pid == bussard_mgmt::PID_MCB_TABLE
                            && value.len() > bussard_mgmt::MCB_ENTRY_LEN
                        {
                            for (i, entry) in value.chunks(bussard_mgmt::MCB_ENTRY_LEN).enumerate()
                            {
                                if entry.len() < bussard_mgmt::MCB_ENTRY_LEN {
                                    break; // the vendor's zero padding, never an entry
                                }
                                let index = start_element.saturating_add(i as u16);
                                write_property(session.l4(), obj, pid, 1, index, entry, None)
                                    .await?;
                            }
                        } else {
                            write_property(session.l4(), obj, pid, 1, *start_element, value, None)
                                .await?;
                        }
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
                    FlashStep::CompareRelMem {
                        target,
                        offset,
                        expected,
                        mask,
                        invert,
                    } => {
                        // Read this object's relative memory and compare it against the
                        // vendor's expected data — the memory twin of CompareProp. An op
                        // with no literal expectation (`expected` is None) is skipped.
                        if let Some(expected) = expected {
                            // Resolve the object index the op names. A `spliced`
                            // template naming an index the device lacks is skipped
                            // (nothing to compare against).
                            let Some(obj) = resolve_object_target_opt(
                                *target,
                                &object_table,
                                app_obj,
                                plan.spliced_from_template,
                            ) else {
                                return Ok(());
                            };
                            // The read base is this object's segment address. Prefer the
                            // base allocated earlier in this procedure; otherwise read the
                            // object's PID_TABLE_REFERENCE fresh (a compare against an
                            // object this procedure did not itself allocate). The u32 base
                            // may exceed 0xFFFF (07B0 actuators); `compare_rel_mem` reads
                            // via the extended service in that case and refuses only if
                            // base + offset exceeds the 24-bit space.
                            let base = match segment_bases.get(&obj).copied().or(segment_base) {
                                Some(b) => b,
                                None => read_table_reference(session.l4(), obj).await?,
                            };
                            compare_rel_mem(
                                session.l4(),
                                obj,
                                base,
                                *offset,
                                expected,
                                mask.as_deref(),
                                *invert,
                            )
                            .await?;
                        }
                    }
                    FlashStep::LoadImageProp {
                        obj_idx,
                        prop_id,
                        count,
                        image,
                        advisory,
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
                            // Read the MCB on the object that holds the checked
                            // segment. A *table* image (obj1/obj2/obj3) lives on its
                            // own table interface object, named by its own index. A
                            // code/parameter image is a segment of the one
                            // application-program object bussard discovered
                            // (`app_obj`) — including a single-segment procedure that
                            // names several object indices which all verify that one
                            // application image (the DA.tp / mock shape). Reading
                            // `app_obj` for every check (the previous behaviour) made
                            // each table-object check read the application segment's
                            // MCB, so the CRC never matched on a multi-object System B
                            // procedure (the MDT actuators).
                            //
                            // A code image the plan wrote to the very object the
                            // check names (a companion program's segment on object
                            // 5) lives on that object, not on `app_obj`: reading
                            // `app_obj` there compared object 4's CRC with object
                            // 5's image (issue #145, 1.1.30 and 1.1.39).
                            let read_obj = match image.as_ref() {
                                Some(img) if img.kind == ImageKind::Table => {
                                    (*obj_idx).min(u32::from(u8::MAX)) as u8
                                }
                                Some(img) => mcb_read_object(
                                    &plan.steps,
                                    plan.spliced_from_template,
                                    img,
                                    *obj_idx,
                                    &object_table,
                                    app_obj,
                                ),
                                None => app_obj,
                            };
                            match read_mcb_table(
                                session.l4(),
                                read_obj,
                                1,
                                (*count).min(255) as u8,
                                expected,
                            )
                            .await
                            {
                                Ok(_) => {}
                                // A check the application's own procedure does not
                                // declare warns instead of aborting (issue #145), so
                                // the download still reaches its restart.
                                Err(err @ WriteError::ImagePropMismatch { .. }) if *advisory => {
                                    tracing::warn!(%err, "advisory MCB check did not match");
                                    warnings.push(advisory_mcb_warning(*obj_idx, &err));
                                }
                                Err(err) => return Err(err),
                            }
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
                            return Ok(());
                        };
                        write_load_control_resumable(session, obj, LoadControl::LoadCompleted)
                            .await?;
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
                        master_reset_via_basic_restart(session.l4(), *erase_code, *channel_number)
                            .await?;
                        // Wait out the reboot with a bounded poll (not a fixed
                        // sleep) and re-establish the authorized connection.
                        session.reconnect_after_reboot().await?;

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
                        // Re-establish the object on the fresh post-reboot connection,
                        // resume-on-drop at block granularity: this whole re-open +
                        // re-allocate is several exchanges and can itself outrun a tight
                        // per-connection budget, but the MasterReset step is excluded from
                        // the outer step-retry (it reconnects itself). Each sub-primitive is
                        // therefore individually resume-on-drop (per-primitive forward
                        // progress), so the re-establishment survives a budget smaller than
                        // its total exchange count. Re-reading the load state and re-issuing
                        // StartLoading / allocate are idempotent.
                        let state = read_load_state_resumable(session, reset_obj).await?;
                        if !matches!(state, LoadState::Loading | LoadState::Loaded) {
                            start_loading_resumable(session, reset_obj, &object_table).await?;
                        }
                        if let Some(size) = last_alloc_size {
                            let alloc = allocate_with_context_resumable(
                                session,
                                reset_obj,
                                size,
                                last_alloc_fill,
                                &object_table,
                            )
                            .await?;
                            segment_base = Some(alloc.address);
                            // Update the per-object base too: the resumed `WriteRelMem` for
                            // this object prefers its per-object base, which must be the
                            // freshly-returned one, not the dropped pre-reset value.
                            segment_bases.insert(reset_obj, alloc.address);
                            segment_fills.insert(reset_obj, last_alloc_fill);
                        }
                    }
                    FlashStep::FactoryReset { erase_code } => {
                        // The confirmed master reset ETS opens an initial System B
                        // download with (issue #117): numbered A_Restart 0x381
                        // [erase_code, channel 0], answered by A_Restart_Response
                        // [error, process time]. A refusal (non-zero error) or silence
                        // fails the flash before anything is written: the device may
                        // still hold a stale image, and `--no-factory-reset` is the
                        // explicit way past that.
                        // Refuse before erasing anything when the session could not
                        // reconnect to the rebooted device afterwards.
                        if !session.can_reconnect() {
                            return Err(WriteError::Mgmt(MgmtError::Transport(
                                bussard_transport::TransportError::Closed,
                            )));
                        }
                        let response =
                            bussard_mgmt::master_reset(session.l4(), *erase_code, 0).await?;
                        tracing::debug!(
                            erase_code,
                            process_time_s = response.process_time_s,
                            "factory reset accepted; waiting out the reboot"
                        );
                        // Erase code 7 leaves the individual address and the
                        // interface-object table alone, so the discovered table stays
                        // valid; the objects are back to `Unloaded` and the following
                        // Unload/StartLoading steps run as on a fresh device.
                        session
                            .reconnect_after_master_reset(bussard_mgmt::restart_process_wait(
                                &response,
                            ))
                            .await?;
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
                        // A plan that allocates filled segments ends with the confirmed
                        // form ETS uses on those devices (issue #117): A_Restart master
                        // reset, erase code 1, answered by A_Restart_Response. Every
                        // other plan (KNX Virtual DA.tp, thelsing) keeps the bare
                        // A_Restart its captures show.
                        let (apci, payload) = if plan.confirmed_restart {
                            bussard_mgmt::apci::encode_master_reset(
                                bussard_mgmt::apci::ERASE_CODE_CONFIRMED_RESTART,
                                0,
                            )
                        } else {
                            bussard_mgmt::apci::encode_restart(0)
                        };
                        if verify_after_restart && session.can_reconnect() {
                            if plan.confirmed_restart {
                                // Wait the device's process time when it answered; a
                                // device that reboots without answering is still
                                // judged by the post-restart verify below.
                                match bussard_mgmt::master_reset(
                                    session.l4(),
                                    bussard_mgmt::apci::ERASE_CODE_CONFIRMED_RESTART,
                                    0,
                                )
                                .await
                                {
                                    Ok(response) => {
                                        session
                                            .reconnect_after_master_reset(
                                                bussard_mgmt::restart_process_wait(&response),
                                            )
                                            .await?;
                                    }
                                    Err(err) => {
                                        tracing::debug!(
                                            %err,
                                            "confirmed restart not answered; polling for the reboot"
                                        );
                                        session.reconnect_after_reboot().await?;
                                    }
                                }
                            } else {
                                let _ = session.l4().send_data_unacked(apci, &payload).await;
                                // The device is unreachable while it reboots; poll for it
                                // (bounded), then re-establish the authorized connection.
                                session.reconnect_after_reboot().await?;
                            }
                            // Re-confirm the application object on the fresh connection. The
                            // index is stable across the reboot, so a single `PID_OBJECT_TYPE`
                            // probe of the known index is enough; only if the device answers
                            // something else (or does not answer) is the full walk re-run.
                            // Re-walking every object unconditionally — the previous behaviour
                            // — cost one exchange per interface object on the tightest
                            // connection of the whole flash.
                            let post_app_obj = confirm_app_object(session, app_obj).await?;
                            verified = Some(
                                verify_outcome(
                                    session,
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
                                verify_outcome(
                                    session,
                                    app_obj,
                                    &completed_objects,
                                    &written_samples,
                                )
                                .await?,
                            );
                            let _ = session.l4().send_data_unacked(apci, &payload).await;
                        }
                    }
                    // System 7 steps are executed by `flash_sys7` (dispatched at the
                    // top of `flash`); a System B plan never carries them.
                    FlashStep::Sys7Unload { .. }
                    | FlashStep::Sys7StartLoading { .. }
                    | FlashStep::Sys7AbsSegment { .. }
                    | FlashStep::Sys7TaskSegment { .. }
                    | FlashStep::Sys7TaskCtrl1 { .. }
                    | FlashStep::Sys7LoadCompleted { .. }
                    | FlashStep::Sys7CompareMem { .. } => {}
                }
                Ok(())
            }
            .await;

            match step_result {
                Ok(()) => break 'resume,
                // An unexpected mid-flow connection death on a resumable step: cycle the
                // L4 connection and re-run the step, up to the per-step bound. This
                // composes with the proactive `cycle_l4` above (which reduces how often
                // we get here) and with `write_image`'s chunk-granular resume (which
                // continues a segment stream from the last confirmed offset instead of
                // replaying the whole image); resume-on-drop is the outer net that
                // reconnects a *dead* connection and replays the whole step.
                Err(e)
                    if resumable_death(&e, session)
                        && !self_reconnecting_step
                        && resume_reconnects < MAX_RESUME_RECONNECTS =>
                {
                    resume_reconnects += 1;
                    // The old connection is dead (the device stopped answering); re-open
                    // a fresh one and re-authorize, then replay the step. `reconnect`
                    // drops the dead connection outright rather than trying a graceful
                    // T_Disconnect the dead peer would not answer.
                    session.reconnect().await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // If no terminal restart captured the outcome (a procedure with no final
    // Restart), verify now over the still-open connection. `verify_outcome` is
    // internally resume-on-drop (each read reconnects and retries), so a connection
    // death here — after all the writes landed — is recovered rather than reported
    // as a flash failure.
    let mut outcome = match verified {
        Some(outcome) => outcome,
        None => verify_outcome(session, app_obj, &completed_objects, &written_samples).await?,
    };
    outcome.warnings = warnings;
    Ok(outcome)
}

/// Gaps of up to this many fill octets between two differing runs are written
/// through rather than split: a new memory-write telegram costs more than a few
/// payload octets.
pub(super) const FILL_MERGE_GAP: usize = 4;

/// The regions of `image` that differ from a segment pre-filled with `fill`, as
/// `(offset, bytes)` pairs in ascending order. Runs separated by at most
/// [`FILL_MERGE_GAP`] fill octets are merged. Writing only these regions over
/// the pre-filled segment leaves the same memory as writing the whole image.
pub(super) fn fill_regions(image: &[u8], fill: u8) -> Vec<(usize, &[u8])> {
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < image.len() {
        if image[i] == fill {
            i += 1;
            continue;
        }
        let start = i;
        while i < image.len() && image[i] != fill {
            i += 1;
        }
        match regions.last_mut() {
            Some((_, end)) if start - *end <= FILL_MERGE_GAP => *end = i,
            _ => regions.push((start, i)),
        }
    }
    regions
        .into_iter()
        .map(|(start, end)| (start, &image[start..end]))
        .collect()
}

/// The octet ranges `[start, end)` of `image` that differ from `current`, the
/// memory the device holds today, in ascending order (issue #119). With a
/// `mask`, only octets whose mask byte is `0xFF` are considered. Ranges
/// separated by at most [`FILL_MERGE_GAP`] unchanged (and writable) octets are
/// merged, since rewriting an octet with its own value is cheaper than another
/// telegram. An octet past the end of `current` counts as different.
pub(super) fn diff_regions(
    image: &[u8],
    current: &[u8],
    mask: Option<&[u8]>,
) -> Vec<(usize, usize)> {
    let writable = |i: usize| mask.is_none_or(|m| m.get(i) == Some(&0xFF));
    let differs = |i: usize| writable(i) && current.get(i) != Some(&image[i]);
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < image.len() {
        if !differs(i) {
            i += 1;
            continue;
        }
        let start = i;
        while i < image.len() && differs(i) {
            i += 1;
        }
        match regions.last_mut() {
            Some((_, end)) if start - *end <= FILL_MERGE_GAP && (*end..start).all(writable) => {
                *end = i;
            }
            _ => regions.push((start, i)),
        }
    }
    regions
}

/// Streams `bytes` to `addr` over the session's connection, emitting a
/// byte-progress event per confirmed chunk, and **resuming at chunk granularity**
/// across an unexpected connection death.
///
/// The write is chunked by [`bussard_mgmt::write_memory_chunked`], which sizes each
/// chunk from the negotiated max-APDU and propagates a connection death on the first
/// failure — recovering from one needs a *new* connection, which only this call site
/// can open. When the connection dies mid-way
/// (the device dropped it), this reconnects and continues streaming from the last
/// **confirmed** offset rather than restarting the image — essential on a device
/// whose per-connection exchange budget is smaller than the whole image (a
/// whole-image replay would drop at the same offset forever and never finish). The
/// confirmed offset is tracked from the `on_written` cumulative callback, so no byte
/// is re-sent unnecessarily and none is skipped. Bounded by [`MAX_RESUME_RECONNECTS`]
/// consecutive reconnects that make no further progress; each confirmed chunk resets
/// the bound. A session that cannot reconnect (mocks, `from_connection`) surfaces the
/// death unchanged, exactly as before.
pub(super) async fn write_image<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    addr: u32,
    bytes: &[u8],
    progress: &mut F,
) -> Result<(), WriteError> {
    let total = bytes.len();
    // Bytes confirmed written so far (cumulative), so a resume continues from here.
    let mut confirmed = 0usize;
    let mut stalled_reconnects = 0u32;
    loop {
        // Stream the remaining tail from the last confirmed offset. `on_written`
        // reports the offset *within this call*; add the already-confirmed base to
        // get the cumulative image offset (for the progress event and the resume
        // cursor). `made_progress` distinguishes a death that advanced the cursor
        // (reset the stall bound) from one that did not.
        let base = confirmed;
        let mut call_confirmed = confirmed;
        let mut on_written = |written_in_call: usize| {
            call_confirmed = base + written_in_call;
            progress(Progress::Bytes {
                written: call_confirmed,
                total,
            });
        };
        let tail_addr = addr.saturating_add(confirmed as u32);
        let result = bussard_mgmt::write_memory_chunked(
            session.l4(),
            tail_addr,
            &bytes[confirmed..],
            &mut on_written,
        )
        .await;
        let made_progress = call_confirmed > confirmed;
        confirmed = call_confirmed;
        match result {
            Ok(()) => return Ok(()),
            Err(e)
                if resumable_death(&e, session)
                    && (made_progress || stalled_reconnects < MAX_RESUME_RECONNECTS) =>
            {
                if made_progress {
                    stalled_reconnects = 0;
                } else {
                    stalled_reconnects += 1;
                }
                session.reconnect().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_regions_writes_only_changed_octets() {
        let current = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let mut image = current;
        image[1] = 0xAA;
        image[10] = 0xBB;
        assert_eq!(diff_regions(&image, &current, None), vec![(1, 2), (10, 11)]);
        // Two changes two octets apart merge into one write.
        image[4] = 0xCC;
        assert_eq!(diff_regions(&image, &current, None), vec![(1, 5), (10, 11)]);
        // A device-owned octet (mask 0x00) is never written nor merged across.
        let mut mask = [0xFFu8; 12];
        mask[3] = 0x00;
        assert_eq!(
            diff_regions(&image, &current, Some(&mask)),
            vec![(1, 2), (4, 5), (10, 11)]
        );
        assert!(diff_regions(&current, &current, None).is_empty());
    }

    #[test]
    fn test_fill_regions_skips_fill_and_merges_small_gaps() {
        let image = [0, 0, 1, 2, 0, 3, 0, 0, 0, 0, 0, 0, 4, 0];
        let regions = fill_regions(&image, 0);
        assert_eq!(
            regions,
            vec![(2usize, &image[2..6]), (12usize, &image[12..13])]
        );
        // All fill: nothing to write.
        assert!(fill_regions(&[0xFF; 8], 0xFF).is_empty());
        // Composing the regions over the fill reproduces the image.
        let mut composed = vec![0u8; image.len()];
        for (start, run) in fill_regions(&image, 0) {
            composed[start..start + run.len()].copy_from_slice(run);
        }
        assert_eq!(composed, image);
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
}
