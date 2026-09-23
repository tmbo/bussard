//! System B planning: lower an application's typed [`LoadProcedure`] into a
//! validated [`FlashPlan`].
//!
//! [`plan_flash`] validates the whole selected procedure up front: it splices a
//! vendor template, binds each `RelSegment` to its code segment, resolves every
//! write image (code, parameters, link tables) and refuses anything the executor
//! could not finish. Only a fully-executable plan leaves this module.

use super::plan_sys7::{Sys7PlanTables, plan_flash_sys7};
use super::{AppIdentity, FlashPlan, FlashStep, ImageKind, ImageRef, PlanError};
use bussard_prod::application::{
    ApplicationProgram, CodeSegment, LoadOp, LoadProcedure, SegmentKind,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The standard System B table object indices a master template programs, and
/// their human names. Used to refuse a spliced template that writes one of these
/// objects without a supplied table image.
pub(super) fn table_object_name(idx: u32) -> Option<&'static str> {
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
pub(super) const PID_PROGRAM_VERSION: u32 = 13;

/// The 5-octet placeholder the master template ships for the PID-13 write; ETS
/// (and this engine) overwrite it with the real application id.
pub(super) const APP_ID_PLACEHOLDER: [u8; 5] = [0, 0, 0, 0, 0];

/// Extracts the 2-octet KNX manufacturer id from an application-program id.
///
/// Application ids begin with the manufacturer prefix `M-XXXX` (four hex
/// digits), e.g. `M-00FA_A-2500-10-51CB` → `0x00FA`. Returns `None` when the id
/// does not start with a parseable `M-XXXX` prefix.
pub(super) fn manufacturer_from_app_id(id: &str) -> Option<u16> {
    let hex = id.strip_prefix("M-")?.get(..4)?;
    u16::from_str_radix(hex, 16).ok()
}

/// Synthesizes the app object's `PID_PROGRAM_VERSION` (app-id) value for an
/// application, or `None` when the identity is too incomplete to build one.
///
/// Needs the manufacturer (from the id prefix), the application number, and the
/// application version; any missing piece yields `None`, leaving a placeholder
/// PID-13 write untouched rather than writing a partly-zero id.
pub(super) fn app_program_version_value(app: &ApplicationProgram) -> Option<[u8; 5]> {
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
pub(super) fn maybe_substitute_app_id(
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
pub(super) const MAX_WRITE_SPAN: u64 = 1024 * 1024;

/// The exclusive upper bound of the memory address space a flash write may reach:
/// the 24-bit extended-memory space, `0x100_0000`. A write whose end address
/// exceeds this is refused at plan time. This replaces the old 16-bit ceiling
/// (`0x1_0000`): the System B extended memory service reaches 24-bit addresses,
/// which the real 07B0 actuators require (segment bases at `0xf000..0x16000`,
/// writes running to `0x1aad3`). The per-chunk selection between the plain and
/// extended service happens at flash time from the resolved absolute address (see
/// [`bussard_mgmt::select_extended_memory`]).
pub(super) const MAX_MEMORY_END: u64 = 0x100_0000;

/// Chooses the application program to flash from a product's candidates.
///
/// `wanted` is the optional `--application` id. With `None`, a single candidate
/// is used and several is [`PlanError::AmbiguousApplication`].
pub fn select_application<'a>(
    candidates: &[&'a ApplicationProgram],
    wanted: Option<&str>,
) -> std::result::Result<&'a ApplicationProgram, PlanError> {
    if let Some(id) = wanted {
        if let Some(app) = candidates.iter().find(|a| a.id == id) {
            return Ok(app);
        }
        // The same program (manufacturer, number, version) under another
        // build hash: a project names it with the hash of the product it was
        // imported from (issue #142).
        let same: Vec<&&ApplicationProgram> = candidates
            .iter()
            .filter(|a| same_program(&a.id, id))
            .collect();
        return match same.as_slice() {
            [only] => Ok(only),
            _ => Err(PlanError::NoApplication(id.to_string())),
        };
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

/// Whether two application-program ids name the same program: the same
/// manufacturer, application number and version, whatever the build hash and
/// suffix (`M-0004_A-A011-13-400D-O000A` and `M-0004_A-A011-13-60BC-O000A`).
///
/// That triple is also all a device's `PID_PROGRAM_VERSION` records, so it is
/// the identity every resident-application check compares; the hash only
/// tells product-file builds apart (issue #142).
pub fn same_program(a: &str, b: &str) -> bool {
    fn program(id: &str) -> Option<(&str, &str, &str)> {
        let (mfr, rest) = id.split_once("_A-")?;
        let mut parts = rest.split('-');
        Some((mfr, parts.next()?, parts.next()?))
    }
    match (program(a), program(b)) {
        (Some(x), Some(y)) => {
            x.0.eq_ignore_ascii_case(y.0)
                && x.1.eq_ignore_ascii_case(y.1)
                && x.2.eq_ignore_ascii_case(y.2)
        }
        _ => a == b,
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
    plan_flash_with_object_flags(
        app,
        device,
        device_mask,
        overrides,
        base_offsets,
        template_ops,
        table_images,
        &BTreeMap::new(),
    )
}

/// [`plan_flash`] with the project's flags of the linked com-objects, keyed by
/// object number.
///
/// Only a System 7 plan reads them (the CONFIG octet of a linked descriptor).
/// They take precedence over the flags decoded from the System B group-object
/// table image, which cannot carry object 0: that table is 1-based, word 0 is
/// its count (1.1.1, 2116REG: object 0 is linked with the project's T W R C,
/// ETS wrote `5f`, the ref's own T W C gave `57`).
#[allow(clippy::too_many_arguments)] // plan_flash's inputs plus one map.
pub fn plan_flash_with_object_flags(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    template_ops: Option<&[LoadOp]>,
    table_images: &BTreeMap<u32, Vec<u8>>,
    object_flags: &BTreeMap<u16, bussard_model::Flags>,
) -> std::result::Result<FlashPlan, PlanError> {
    // 1. Family gate. System B and System 7 (mask 0705/0701, issue #49) are the
    //    two supported families; every other mask refuses cleanly. System 7 is
    //    dispatched to its own lowering below (after the shared mask-match check).
    let profile = bussard_mgmt::MaskProfile::from_mask(device_mask);
    if !profile.capabilities().flash {
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

    // System 7 has its own memory-mapped, absolute-addressed lowering: the LSM
    // events, AbsSegment allocation + streaming, TaskSegment finalize, and the
    // obj0/PID78 preflight all differ from System B, so it is a separate path
    // rather than a branchy overload of the System B lowering below.
    if profile.is_system_7() {
        let mut tables = Sys7PlanTables::from_system_b(table_images);
        tables.linked_flags.extend(object_flags);
        return plan_flash_sys7(
            app,
            device_mask,
            overrides,
            base_offsets,
            profile,
            None,
            &tables,
        );
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
    // A companion program (a PeiProgram, see
    // `ApplicationProgram::companion_programs`) owns the objects its segments
    // load into; its own id replaces the PID-13 placeholder on those (ETS wrote
    // `0002A0ED20` to object 5 of the ABB BE/S16, `0002A0ED10` to object 4).
    let companion_ids: BTreeMap<u32, [u8; 5]> = app
        .companion_programs
        .iter()
        .filter_map(|c| Some((c, app_program_version_value(c)?)))
        .flat_map(|(c, id)| {
            c.code_segments
                .values()
                .filter_map(|seg| seg.load_state_machine)
                .map(move |lsm| (lsm, id))
        })
        .collect();
    let segments = plan_segments(app);
    let image_checks = DeclaredImageChecks::of(app);

    // 4. Validate + lower each op into a FlashStep.
    let mut steps = Vec::new();
    let mut images: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // Track the segment id most-recently allocated so a following WriteRelMem
    // resolves to it when its own AppliesTo does not pin one.
    let mut last_rel_segment: Option<String> = None;
    // The segment each object's allocation bound, so a write naming its object
    // (`ObjIdx`) streams that object's segment even when another object was
    // allocated in between (the ABB PEI program: object 5 is allocated before
    // object 4, and written after it was allocated).
    let mut rel_segment_by_object: BTreeMap<u32, String> = BTreeMap::new();
    // Track the image most-recently streamed into device memory so a following
    // LoadImageProp with no matching per-object image checks the device's MCB CRC
    // against the very bytes we wrote.
    let mut last_written_image: Option<ImageRef> = None;
    // Track the image streamed into each object index, so a `LoadImageProp{obj}`
    // that targets a table object verifies that object's own MCB against the
    // bytes written to it — not the last object written. Real multi-object System
    // B procedures (the MDT actuators) write obj1/obj2/obj3 each with its own
    // segment and then check each object's MCB in turn.
    let mut written_image_by_object: std::collections::HashMap<u32, ImageRef> =
        std::collections::HashMap::new();

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
    // The objects the procedure would open but this plan skips (a `Load` with no
    // allocation, see above). ETS writes an object's PID 13 program version
    // only when it loads that object: the 07B0 template's
    // `LdCtrlWriteProp ObjIdx=5 PropId=13` runs on the ABB BE/S16 and the
    // Busch-Waechter PRO 280, whose object 5 receives a segment, and is skipped
    // on the Jung actuators, whose object 5 stays unloaded (issue #160).
    let skipped_objects: std::collections::HashSet<u32> = ops
        .iter()
        .filter_map(|op| match op {
            LoadOp::Load { lsm_idx: Some(idx) } if !loadable.contains(idx) => Some(*idx),
            _ => None,
        })
        .collect();

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
                // Table objects always allocate no-fill (`Fill=0` in every
                // observed procedure, including the products that set `Fill=1`
                // on the code segment). Preserve that unconditionally so the
                // fill flag never leaks onto a table allocation.
                steps.push(FlashStep::AllocateSegment {
                    size,
                    target: Some(*idx),
                    fill: None,
                });
            }

            LoadOp::RelSegment {
                size,
                applies_to,
                lsm_idx,
                fill,
                ..
            } => {
                // Bind this allocation to the segment whose code image we will
                // stream. The op does not name the segment id directly; we pair
                // it with the application's relative segments in document-ish
                // order using the applies_to hint and remaining unallocated
                // segments.
                let seg = resolve_rel_segment(&segments, *lsm_idx, applies_to.as_deref(), &images);
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
                    if let Some(idx) = lsm_idx {
                        rel_segment_by_object.insert(*idx, seg_id.clone());
                    }
                    // Record the code image so total-byte accounting is correct.
                    if let Some(data) = segments.get(seg_id).and_then(|s| s.data.clone()) {
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
                // Per the KNX load-state machine (KNX Spec 3/5/2 Management
                // Procedures, `LdCtrlRelSegment`), a relative-segment allocation
                // frees any prior backing store and re-allocates `size` octets, so a
                // second relative allocation on an already-`Loading` object is
                // *legal* and lands in the same state — but it is redundant work,
                // and re-issuing the
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
                // "Same segment" is decided by `resolve_rel_segment`, which binds
                // an op to the segment on its own `LsmIdx` — an app that declares
                // segments on several LSMs (the ABB/BJE shape of issue #113) would
                // otherwise bind the restated pair to two different segments and
                // slip past this check.
                let same_segment = match &seg {
                    None => true,
                    Some((seg_id, _)) => prev_rel_segment.as_deref() == Some(seg_id.as_str()),
                };
                let is_duplicate = same_segment
                    && matches!(steps.last(), Some(FlashStep::AllocateSegment { size: prev, .. }) if *prev == size);
                if !is_duplicate {
                    // Thread the source procedure's fill (`Mode`/`Fill`) through:
                    // `None` (the DA.tp default) keeps the historical no-fill
                    // allocation byte-identical; `Some(b)` requests the device
                    // pre-fill the segment (the code-segment behaviour on
                    // products like Jung LED A-3030).
                    steps.push(FlashStep::AllocateSegment {
                        size,
                        target: *lsm_idx,
                        fill: *fill,
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
                if len as u64 > MAX_WRITE_SPAN
                    || u64::from(offset) > MAX_WRITE_SPAN
                    || end > MAX_MEMORY_END
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
                written_image_by_object.insert(*idx, image.clone());
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
                let current = obj_idx
                    .and_then(|idx| rel_segment_by_object.get(&idx))
                    .or(last_rel_segment.as_ref());
                let (segment_id, kind, bytes) = resolve_write_image(
                    &segments,
                    applies_to.as_deref(),
                    current.map(String::as_str),
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
                if len as u64 > MAX_WRITE_SPAN
                    || u64::from(offset) > MAX_WRITE_SPAN
                    || end > MAX_MEMORY_END
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
                if let Some(oi) = obj_idx {
                    written_image_by_object.insert(*oi, image.clone());
                }
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
                if len as u64 > MAX_WRITE_SPAN || end > MAX_MEMORY_END {
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

            // The program version of an object this plan never loads: ETS does
            // not write it (see `skipped_objects`).
            LoadOp::WriteProp {
                obj_idx: Some(idx),
                prop_id: Some(prop_id),
                ..
            } if *prop_id == PID_PROGRAM_VERSION && skipped_objects.contains(idx) => {}

            LoadOp::WriteProp {
                obj_idx,
                obj_type,
                prop_id,
                inline_data,
                start_element,
            } => {
                let obj_type = obj_type.unwrap_or(0);
                let start_element = start_element
                    .and_then(|e| u16::try_from(e).ok())
                    .unwrap_or(1)
                    .max(1);
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
                let inline_data = maybe_substitute_app_id(
                    prop_id,
                    inline_data.as_deref(),
                    companion_ids.get(&obj_idx).or(app_id_value.as_ref()),
                );

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
                            start_element,
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

            LoadOp::CompareRelMem {
                obj_idx,
                offset,
                size,
                inline_data,
                mask,
                invert,
            } => {
                // A relative-memory verify precondition — the memory twin of
                // CompareProp. The expected bytes come from the op's own
                // `InlineData` (resolved at parse time), so this lowers with no
                // device access; the read base is resolved from the object's
                // PID_TABLE_REFERENCE at execute time. An op carrying no
                // `InlineData` (only a `Size`/`Range`-style expectation) keeps a
                // `None` expectation — a no-op confirm — so the whole procedure
                // still lowers rather than refusing.
                let offset = offset.unwrap_or(0);
                // The read span (offset + the compared length) must fit the 16-bit
                // A_Memory space once the device-supplied base (>= 0) is added.
                // Refuse here rather than truncate at execute time. Use the
                // InlineData length when present, else the declared `Size`.
                let read_len = inline_data
                    .as_ref()
                    .map(|d| d.len() as u64)
                    .unwrap_or_else(|| u64::from(size.unwrap_or(0)));
                let end = u64::from(offset).saturating_add(read_len);
                if read_len > MAX_WRITE_SPAN
                    || u64::from(offset) > MAX_WRITE_SPAN
                    || end > MAX_MEMORY_END
                {
                    return Err(PlanError::AddressOutOfRange {
                        step: step_no,
                        size: read_len,
                        end,
                        detail: format!(
                            "relative compare offset {offset} (segment base added at flash time)"
                        ),
                    });
                }
                steps.push(FlashStep::CompareRelMem {
                    target: *obj_idx,
                    offset,
                    expected: inline_data.clone(),
                    mask: mask.clone(),
                    invert: *invert,
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
                // Check what ETS checks (issue #145): the objects the
                // application's own procedure names, plus a companion program's.
                // A template check for an object neither names is only taken for
                // an app that declares no check of its own (KNX Virtual DA.tp).
                let Some(advisory) = image_checks.classify(obj_idx) else {
                    continue;
                };
                let prop_id = prop_id.unwrap_or(u32::from(bussard_mgmt::PID_MCB_TABLE));
                let count = count.unwrap_or(1).max(1);
                // A table object (obj1/obj2/obj3) is checked against the image
                // written to *that* object; any other check verifies the
                // last-written (application) image, whose MCB lives on the
                // discovered application-program object.
                let image = written_image_by_object
                    .get(&obj_idx)
                    .cloned()
                    .or_else(|| last_written_image.clone());
                steps.push(FlashStep::LoadImageProp {
                    obj_idx,
                    prop_id,
                    count,
                    image,
                    advisory,
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

    // A filled segment is written sparsely (only the octets that differ from
    // the fill, issue #123). The device's fill is bookkeeping, not an erase, so
    // on a re-flash every octet the new image leaves out keeps whatever the
    // previous image put there (issue #117: a Jung F50 kept a blinking status
    // LED). ETS opens such a download with a factory reset (erase code 7) and
    // ends it with a confirmed restart (erase code 1); do the same.
    let sparse = steps
        .iter()
        .any(|s| matches!(s, FlashStep::AllocateSegment { fill: Some(_), .. }));
    if sparse {
        insert_factory_reset(&mut steps);
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
        sys7: None,
        confirmed_restart: sparse,
        baseline: BTreeMap::new(),
    })
}

/// Inserts a [`FlashStep::FactoryReset`] with erase code 7 right before the
/// first `Unload` (or at the start when the procedure has none), so read-only
/// preconditions that precede the first state change still run on the intact
/// device, and the reset lands before anything is torn down or written.
pub(super) fn insert_factory_reset(steps: &mut Vec<FlashStep>) {
    let at = steps
        .iter()
        .position(|s| {
            !matches!(
                s,
                FlashStep::CompareProp { .. } | FlashStep::CompareRelMem { .. }
            )
        })
        .unwrap_or(steps.len());
    steps.insert(
        at,
        FlashStep::FactoryReset {
            erase_code: bussard_mgmt::apci::ERASE_CODE_FACTORY_RESET_KEEP_IA,
        },
    );
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
/// The objects whose `LdCtrlLoadImageProp` MCB check the application's own
/// load procedures declare, and those its companion programs' procedures add
/// (issue #145).
///
/// ETS runs the checks of the procedure it assembles, but the master template's
/// merge splice is not the application's word on which objects to verify. The
/// application's own checks are authoritative and fail the download on a
/// mismatch. A companion program's check (object 5 on the ABB BE/S16 and the
/// Busch-Wächter PRO 280) is advisory: ETS reads that MCB and carries on,
/// because those devices answer it with object 2's entry. A check only the
/// template carries is kept (as authoritative) solely for an application that
/// declares no check at all, the pure template-driven shape of KNX Virtual
/// DA.tp; otherwise it is dropped and the post-restart spot check verifies.
#[derive(Debug, Default)]
struct DeclaredImageChecks {
    /// Objects the application's own procedures check.
    app: BTreeSet<u32>,
    /// Objects only a companion program's procedures check.
    companion: BTreeSet<u32>,
}

impl DeclaredImageChecks {
    fn of(app: &ApplicationProgram) -> Self {
        fn objects<'a>(procs: impl Iterator<Item = &'a LoadProcedure>) -> BTreeSet<u32> {
            procs
                .flat_map(|p| p.ops.iter())
                .filter_map(|op| match op {
                    LoadOp::LoadImageProp { obj_idx, .. } => Some(obj_idx.unwrap_or(0)),
                    _ => None,
                })
                .collect()
        }
        let own = objects(app.load_procedures.iter());
        let companion = objects(
            app.companion_programs
                .iter()
                .flat_map(|c| c.load_procedures.iter()),
        )
        .difference(&own)
        .copied()
        .collect();
        Self {
            app: own,
            companion,
        }
    }

    /// Whether a check of `obj_idx` is lowered, and if so whether it is advisory:
    /// `Some(false)` fails the flash on a mismatch, `Some(true)` only warns,
    /// `None` drops a template check the application does not ask for.
    fn classify(&self, obj_idx: u32) -> Option<bool> {
        if self.app.contains(&obj_idx) {
            Some(false)
        } else if self.companion.contains(&obj_idx) {
            Some(true)
        } else if self.app.is_empty() {
            Some(false)
        } else {
            None
        }
    }
}

/// The code segments a System B plan streams from: the application's own and
/// those of its companion programs (a PeiProgram's segment on object 5). A
/// companion never shadows a segment id of the application.
pub(super) fn plan_segments(
    app: &ApplicationProgram,
) -> std::borrow::Cow<'_, HashMap<String, CodeSegment>> {
    if app.companion_programs.is_empty() {
        return std::borrow::Cow::Borrowed(&app.code_segments);
    }
    let mut all = app.code_segments.clone();
    for companion in &app.companion_programs {
        for (id, seg) in &companion.code_segments {
            all.entry(id.clone()).or_insert_with(|| seg.clone());
        }
    }
    std::borrow::Cow::Owned(all)
}

pub(super) fn assemble_ops(
    app: &ApplicationProgram,
    template_ops: Option<&[LoadOp]>,
) -> (Vec<LoadOp>, bool) {
    let non_empty: Vec<&LoadProcedure> = app
        .load_procedures
        .iter()
        .filter(|p| !p.ops.is_empty())
        .collect();
    // A companion program's merged blocks join the application's under the
    // same MergeId, after them (the ABB PEI program fills MergeId 3 and 5 of
    // the 07B0 template and adds object 5's LoadImageProp to MergeId 7).
    let companion_blocks: Vec<&LoadProcedure> = app
        .companion_programs
        .iter()
        .flat_map(|c| c.load_procedures.iter())
        .filter(|p| !p.ops.is_empty() && p.merge_id.is_some())
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
            for p in non_empty.iter().chain(companion_blocks.iter()) {
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

/// Resolves which relative segment a `RelSegment` op allocates. Returns
/// `(segment_id, declared_size)`.
///
/// The op names the load state machine it allocates on (`LsmIdx`), and a
/// `<RelativeSegment>` declares the LSM it belongs to (`LoadStateMachine`), so
/// that pair — not document order — is the segment's identity. When the op names
/// an LSM that some relative segment declares, the candidates are narrowed to
/// that LSM: the first one not already allocated, or, when they are all
/// allocated, the first one again (a **restated** allocation of a segment this
/// procedure has already opened, which the caller's dedupe then collapses).
///
/// Evidence (ABB/Busch-Jaeger i-bus, `M-0002_A-0806-71-AD30-O0007`, issue #113):
/// the app declares `RS-03-00000` (`LoadStateMachine="3"`, the group-object-table
/// segment) *and* `RS-04-00000` (`LoadStateMachine="4"`, the app segment), while
/// its `MergeId=2` block restates one LSM-4 allocation twice (`AppliesTo="full"`
/// then `="par"`, both `LsmIdx="4" Size="232"`). Handing segments out in id order
/// bound the first op to `RS-03` and the second to `RS-04`, so the two ops looked
/// like two different segments and the dedupe below declined — lowering two
/// identical `AllocateSegment { size: 232, target: 4 }` steps, i.e. a repeated
/// relative allocation on one object, the shape that broke a device during the KV
/// work. Matching on the LSM binds both ops to `RS-04` and the restatement
/// collapses. 153 of the 865 System B applications in the product corpus (every
/// one of them an ABB `M-0002` or Busch-Jaeger `M-0007` app with this
/// two-segment shape) were affected.
///
/// An op with no `LsmIdx`, or one naming an LSM no segment declares, keeps the
/// historical document-order fallback, so a single-segment app and the
/// multi-segment fixtures whose segments share one LSM lower exactly as before.
pub(super) fn resolve_rel_segment(
    segments: &HashMap<String, CodeSegment>,
    lsm_idx: Option<u32>,
    _applies_to: Option<&str>,
    already: &BTreeMap<String, Vec<u8>>,
) -> Option<(String, Option<u32>)> {
    let mut segs: Vec<_> = segments
        .values()
        .filter(|s| s.kind == SegmentKind::Relative)
        .collect();
    segs.sort_by(|a, b| a.id.cmp(&b.id));

    // Narrow to the op's own load state machine when it names one that some
    // segment declares; otherwise keep every relative segment as a candidate.
    let on_lsm: Vec<_> = match lsm_idx {
        Some(idx) => segs
            .iter()
            .copied()
            .filter(|s| s.load_state_machine == Some(idx))
            .collect(),
        None => Vec::new(),
    };
    let candidates = if on_lsm.is_empty() { &segs } else { &on_lsm };

    candidates
        .iter()
        .find(|s| !already.contains_key(&s.id))
        // Every segment on this LSM is already allocated: the op restates one.
        .or_else(|| {
            if on_lsm.is_empty() {
                None
            } else {
                on_lsm.first()
            }
        })
        .map(|s| (s.id.clone(), s.size))
}

/// Resolves the bytes a `WriteRelMem` streams from its `AppliesTo` hint. `full`
/// (or unset) streams the current relative segment's code `<Data>`; `par`
/// streams the computed parameter image for that segment; the combined
/// `full,par` (the real MDT / Jung shape, one write covering the whole segment)
/// streams the parameter image when parameters target the segment, else the
/// code `<Data>` — either way the segment's own bytes, so a following
/// `LoadImageProp` MCB check runs over a real image.
pub(super) fn resolve_write_image(
    segments: &HashMap<String, CodeSegment>,
    applies_to: Option<&str>,
    current_segment: Option<&str>,
    param_images: &BTreeMap<String, Vec<u8>>,
) -> std::result::Result<(String, ImageKind, Vec<u8>), String> {
    let seg_id = current_segment
        .map(str::to_string)
        .or_else(|| {
            // No allocation preceded this write: fall back to the first relative
            // segment that has data or a parameter image.
            let mut segs: Vec<_> = segments
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
        if let Some(data) = segments.get(&seg_id).and_then(|s| s.data.clone()) {
            return Ok((seg_id, ImageKind::Code, data));
        }
        return Ok((seg_id, ImageKind::Parameters, Vec::new()));
    }

    // Code image: the segment's `<Data>`.
    let bytes = segments
        .get(&seg_id)
        .and_then(|s| s.data.clone())
        .ok_or_else(|| format!("segment {seg_id} carries no code image (<Data>)"))?;
    Ok((seg_id, ImageKind::Code, bytes))
}

/// Resolves an absolute segment's bytes for a `WriteMem` op by matching its
/// declared address to `address`.
pub(super) fn resolve_abs_image(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::test_support::{fabricated_app, no_overrides};
    use bussard_prod::application::parse_application_program;

    use crate::flash::labels::trace;
    use bussard_prod::application::ApplicationProgram;
    use std::collections::BTreeMap;

    #[test]
    fn test_same_program_ignores_the_build_hash() {
        assert!(same_program(
            "M-0004_A-A011-13-400D-O000A",
            "M-0004_A-A011-13-60BC-O000A"
        ));
        assert!(!same_program(
            "M-0004_A-A011-12-400D-O000A",
            "M-0004_A-A011-13-60BC-O000A"
        ));
        assert!(!same_program(
            "M-0004_A-A011-13-60BC",
            "M-0002_A-A011-13-60BC"
        ));
    }

    #[test]
    fn test_select_application_accepts_another_build_of_the_same_program() {
        let mut other = fabricated_app();
        other.id = "M-0004_A-A011-13-60BC-O000A".to_string();
        let candidates = [&other];
        let picked = select_application(&candidates, Some("M-0004_A-A011-13-400D-O000A"));
        assert_eq!(picked.map(|a| a.id.as_str()).ok(), Some(other.id.as_str()));
        assert!(select_application(&candidates, Some("M-0004_A-A011-14-400D-O000A")).is_err());
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
                    fill: None,
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
                    fill: None,
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
    fn plan_threads_rel_segment_fill_flag_data_driven() {
        // Item 1 (issue #73): the `LdCtrlRelSegment` `Fill`/`FillByte` is
        // per-product, not a blanket rule. A procedure that sets `Fill="1"` on the
        // code segment (the Jung LED A-3030 shape, obj4 alloc
        // `030b000028c1 01 00 0000`) must lower to `AllocateSegment { fill:
        // Some(0) }`; a DA.tp-shape procedure with no `Fill` attribute must stay
        // `fill: None` so its allocation is byte-identical to before.
        let fill_xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-FILL" MaskVersion="MV-07B0" Name="Fill"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code><RelativeSegment Id="M-1_A-FILL_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" Fill="1" />
             <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-FILL", fill_xml.as_bytes()).unwrap();
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
        let fill = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::AllocateSegment { fill, .. } => Some(*fill),
                _ => None,
            })
            .expect("the procedure lowers an AllocateSegment");
        assert_eq!(
            fill,
            Some(0),
            "a Fill=\"1\" code-segment allocation must carry the pre-fill flag"
        );

        // The DA.tp shape (no `Fill`) must keep the historical no-fill allocation.
        let da_tp_xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-DATP" MaskVersion="MV-07B0" Name="DaTp"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code><RelativeSegment Id="M-1_A-DATP_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-DATP", da_tp_xml.as_bytes()).unwrap();
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
        let fill = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::AllocateSegment { fill, .. } => Some(*fill),
                _ => None,
            })
            .expect("the procedure lowers an AllocateSegment");
        assert_eq!(
            fill, None,
            "a DA.tp-shape allocation (no Fill) must stay no-fill (byte-identical)"
        );
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
        // System 2 (0x0300): neither System B nor System 7, refused at the gate.
        // (System 7 masks 0705/0701 are now supported — issue #49 — so they no
        // longer hit this gate; see `plan_lowers_system_7`.)
        let app = fabricated_app();
        let err = plan_flash(
            &app,
            "1.1.4",
            0x0300,
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
    fn plan_dedupes_a_restated_allocation_when_segments_span_several_lsms() {
        // The real ABB/BJE i-bus shape (M-0002_A-0806-71-AD30-O0007, issue #113):
        // the app declares TWO relative segments on DIFFERENT load state machines
        // — RS-03 (LSM 3, the group-object-table segment) and RS-04 (LSM 4, the
        // app segment) — and its MergeId=2 block restates one LSM-4 allocation
        // twice (AppliesTo="full" then ="par", both LsmIdx=4 Size=6). Binding the
        // ops in document order pinned the first to RS-03 and the second to RS-04,
        // so the restatement looked like two distinct segments and lowered two
        // identical AllocateSegment steps. Both ops name LSM 4, so both must bind
        // RS-04 and collapse to one allocation — and the write must stream RS-04.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-2_A-806" ApplicationNumber="2054" ApplicationVersion="113"
            MaskVersion="MV-07B0" Name="ABB" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code>
            <RelativeSegment Id="M-2_A-806_RS-04-00000" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
            <RelativeSegment Id="M-2_A-806_RS-03-00000" Size="3" LoadStateMachine="3" Offset="0"><Data>AAEC</Data></RelativeSegment>
           </Code>
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
        let app = parse_application_program("M-2_A-806", xml.as_bytes()).unwrap();
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

        let allocs: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::AllocateSegment { .. }))
            .collect();
        assert_eq!(
            allocs.len(),
            1,
            "a restated LSM-4 allocation must collapse even when the app declares \
             another relative segment on a different LSM, got steps {:?}",
            plan.steps
        );
        assert!(matches!(
            allocs[0],
            FlashStep::AllocateSegment {
                size: 6,
                target: Some(4),
                ..
            }
        ));
        // The write binds the LSM-4 segment, and the LSM-3 segment (which this
        // procedure never allocates) is not pulled into the plan's images.
        let writes: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::WriteRelMem { .. }))
            .collect();
        assert_eq!(writes.len(), 1);
        match writes[0] {
            FlashStep::WriteRelMem { image, .. } => {
                assert_eq!(image.segment_id, "M-2_A-806_RS-04-00000");
                assert_eq!(image.len, 6);
            }
            other => panic!("expected WriteRelMem, got {other:?}"),
        }
        assert!(
            !plan.images.contains_key("M-2_A-806_RS-03-00000"),
            "the LSM-3 segment is never allocated by this procedure"
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
    fn plan_refuses_write_rel_mem_offset_past_24bit_space() {
        // A WriteRelMem whose offset alone lands the write past the 24-bit
        // extended-memory space (0xFF_FFFF) must be refused at plan time (the
        // segment base is added at flash time and is >= 0, so the range already
        // exceeds the addressable space). This is the raised ceiling: an offset
        // past 0xFFFF but within 24 bits is now valid (the extended service
        // reaches it), so only an offset past the 24-bit space is refused.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-7" MaskVersion="MV-07B0" Name="Overflow">
          <Static>
           <Code><RelativeSegment Id="M-1_A-7_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="16777215" Size="6" AppliesTo="full" />
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
                assert!(
                    end > MAX_MEMORY_END,
                    "end {end} must exceed the 24-bit space"
                );
            }
            other => panic!("expected AddressOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn plan_accepts_write_rel_mem_offset_above_16bit_space() {
        // A WriteRelMem at an offset past 0xFFFF but inside the 24-bit space is now
        // planned (the extended service reaches it) — the old 16-bit refusal is
        // gone. The plain-vs-extended selection is deferred to flash time from the
        // device-supplied base + offset.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-7b" MaskVersion="MV-07B0" Name="ExtOffset">
          <Static>
           <Code><RelativeSegment Id="M-1_A-7b_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="65540" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-7b", xml.as_bytes()).unwrap();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .expect("an offset above 0xFFFF but within 24 bits must plan via the extended service");
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::WriteRelMem { offset, .. } if *offset == 65540)),
            "the WriteRelMem step must survive lowering"
        );
    }

    #[test]
    fn plan_refuses_write_mem_address_past_24bit_space() {
        // An absolute WriteMem at an address past the 24-bit space (0xFF_FFFF) is
        // refused (a cast would silently truncate and stream to the wrong memory).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-8" MaskVersion="MV-07B0" Name="AbsOverflow">
          <Static>
           <Code><AbsoluteSegment Id="M-1_A-8_AS-1" Address="16777214" Size="4"><Data>AAECAw==</Data></AbsoluteSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="0" />
             <LdCtrlWriteMem Address="16777214" Size="4" />
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
