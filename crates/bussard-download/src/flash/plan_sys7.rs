//! System 7 planning (mask 0705 / 0701): lower a System 7 procedure into a
//! validated [`FlashPlan`].
//!
//! Holds [`plan_flash_sys7_with_hawk`] and its range checks, the table images
//! synthesized from a System B model ([`Sys7PlanTables`],
//! [`sys7_tables_from_system_b`], [`linked_flags_from_system_b`]) and the
//! group-object descriptor post-pass that sets each object's communication flag
//! from the association table.

use super::{
    AppIdentity, FlashPlan, FlashStep, ImageKind, ImageRef, KeptOctets, PlanError, Sys7Context,
};
use bussard_prod::application::{ApplicationProgram, LoadOp, SegmentKind, TableLocation};
use std::collections::{BTreeMap, BTreeSet};

/// The largest System 7 memory address (and segment size) the 2-octet fields of
/// an `AdditionalLoadControls` record can carry. System 7 is a 16-bit,
/// absolute-addressed memory map (`[system7-spec §2]`).
pub(super) const SYS7_MAX_ADDRESS: u32 = 0xFFFF;

/// The LSM index range a memory-mapped record can name: the index occupies the
/// high nibble of the opcode octet ([`bussard_mgmt::sys7::wrap_memory_lsm_record`]),
/// and `0` names no machine.
pub(super) const SYS7_LSM_RANGE: std::ops::RangeInclusive<u32> = 1..=15;

/// Validates a System 7 LSM index at plan time, so the executor never folds an
/// out-of-range index into the record's opcode nibble.
pub(super) fn check_sys7_lsm(step: usize, lsm: u32) -> std::result::Result<u32, PlanError> {
    if SYS7_LSM_RANGE.contains(&lsm) {
        Ok(lsm)
    } else {
        Err(PlanError::Sys7LsmOutOfRange { step, lsm })
    }
}

/// Validates one 16-bit System 7 record field (an address, a size) at plan time.
pub(super) fn check_sys7_u16(
    step: usize,
    field: &'static str,
    value: u32,
) -> std::result::Result<u32, PlanError> {
    if value <= SYS7_MAX_ADDRESS {
        Ok(value)
    } else {
        Err(PlanError::Sys7FieldOutOfRange {
            step,
            field,
            value: u64::from(value),
            max: u64::from(SYS7_MAX_ADDRESS),
        })
    }
}

/// [`check_sys7_u16`] for a field the record carries as a `u16`.
fn sys7_u16_field(
    step: usize,
    field: &'static str,
    value: u32,
) -> std::result::Result<u16, PlanError> {
    let value = check_sys7_u16(step, field, value)?;
    u16::try_from(value).map_err(|_| PlanError::Sys7FieldOutOfRange {
        step,
        field,
        value: u64::from(value),
        max: u64::from(u16::MAX),
    })
}

/// Environment variable that overrides the System 7 LSM realisation the product
/// data selected (`memory` for [`LsmRealisation::MemoryMapped`], `property` for
/// [`LsmRealisation::Property`]).
///
/// The spec (`[system7-spec §5]`) resolves the memory-vs-property disagreement by
/// building a seam with a best-evidence default (memory-mapped) and notes that
/// "flipping the profile bit is a one-line change". This env var is that switch:
/// it lets bussard's `LsmAccess` realisation be conformance-tested against a
/// property-based device side (the knx-sim `lsm_access: property` device) without
/// a second product carrying a property `HawkConfigurationData`. Unset in normal
/// use, so a flash uses exactly the product-driven realisation.
pub(super) const SYS7_LSM_OVERRIDE_ENV: &str = "BUSSARD_FLASH_SYS7_LSM";

/// The System 7 LSM-realisation override from [`SYS7_LSM_OVERRIDE_ENV`], or `None`
/// to keep the product-driven realisation. `memory` keeps the memory-mapped record
/// at the profile's control/status addresses; `property` drives PID 5.
pub(crate) fn sys7_lsm_override() -> Option<bussard_mgmt::LsmRealisation> {
    match bussard_model::dotenv::var(SYS7_LSM_OVERRIDE_ENV)
        .ok()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "property" | "prop" => Some(bussard_mgmt::LsmRealisation::Property),
        "memory" | "mem" | "memory-mapped" | "memorymapped" => {
            Some(bussard_mgmt::LsmRealisation::MemoryMapped {
                control_addr: 0x0104,
                status_addr: 0xB6EA,
            })
        }
        _ => None,
    }
}

/// The length of the System 7 procedure bussard lowers: everything up to and
/// including the terminal `LdCtrlRestart`, or the whole procedure when it has
/// no restart.
///
/// The restart ends the download: the device reboots into the loaded
/// application, and ETS sends nothing after it. Some procedures converted from
/// pre-ETS4 product data carry a tail past the restart anyway: the Jung
/// 2308.16REGHM application `M-0004_A-2088-11-C937-O000A`
/// (`ConvertedFromPreEts4Data="1"`) ends with `<LdCtrlRestart/>`,
/// `<LdCtrlTaskSegment LsmIdx="5" Address="17407"/>`, `<LdCtrlLoad LsmIdx="5"/>`,
/// `<LdCtrlDisconnect/>`. The device has no interface object 5 (its
/// `PID_LOAD_STATE_CONTROL` read answers count 0), and ETS's download of it
/// (capture `schaltaktor-8fach-1-1-49.pcapng`) ends with the restart. Lowering
/// the tail failed the flash of 1.1.49 after a complete download (issue #178).
/// A trailing `LdCtrlDisconnect` lowers to nothing, so cutting it changes no
/// step.
pub(super) fn sys7_procedure_end(ops: &[LoadOp]) -> usize {
    ops.iter()
        .rposition(|op| matches!(op, LoadOp::Restart))
        .map_or(ops.len(), |i| i + 1)
}

/// The load-state machines a System 7 device has: one per object type, the
/// address table (1), the association table (2), the application program (3)
/// and the PEI program (4). The memory-mapped form keeps their states at
/// `B6EAh` to `B6EDh` (KNX 3/5/2 §3.31.2, which supports "only one state
/// machine of each type"); the property form addresses them as interface
/// objects 1 to 4 by `PID_LOAD_STATE_CONTROL`.
///
/// A record on another index names no machine, and ETS sends none on either
/// realisation:
///
/// - 0701 (memory-mapped, issue #489): ETS's full download of the synthetic
///   `syn-s7-lsm5` (an `LdCtrlTaskSegment LsmIdx="5"` inside LSM 3's load, the
///   shape of the Busch-Jaeger 0701 applications such as `M-0002_A-A002-13`)
///   executes no LSM 5 op and writes no record with high nibble 5 to `0x0104`
///   (`captures/synthetic/syn-s7-lsm5/defaults/requests.txt`: its 18 records
///   name LSMs 1 to 3 only), and on the house binary input 1.1.44
///   (`binaereingang-1-1-44.pcapng`) none of ETS's 23 records names LSM 5.
/// - 0705 (property, issue #680): ETS's full download of `syn-s7-lsm5-0705`
///   (`syn-s7-0705` plus the same TaskSegment on LsmIdx 5) runs 44 operations
///   and none on object 5 (`captures/synthetic/syn-s7-lsm5-0705/defaults/ops.txt`);
///   the sequence equals `syn-s7-0705`'s apart from the application number.
///
/// 0700 shares the memory-mapped lowering with 0701. knx-sim leaves an
/// unopened machine Unloaded on such a record (#529) and refuses the property
/// write with a T_NAK, so sending it fails the flash.
pub(super) const SYS7_LSMS: std::ops::RangeInclusive<u32> = 1..=4;

/// Whether a System 7 Additional Load Controls record on `lsm` is sent: only
/// for an LSM in [`SYS7_LSMS`], on every realisation (issues #489, #680).
pub(super) fn sys7_lsm_record_sent(lsm: u32) -> bool {
    SYS7_LSMS.contains(&lsm)
}

/// The load-state machines ETS unloads before a full System 7 download: LSMs 1
/// to 4, on both mask families (`schaltaktor-8fach-1-1-49`, `jung-1131`,
/// `binaereingang-6fach`, `automitschalter-standard-110` on 0705;
/// `meteodata-1-1-202-new`, `meteodata-140-s` on 0701).
pub(super) const SYS7_PRELUDE_UNLOAD_LSMS: [u32; 4] = [1, 2, 3, 4];

/// Adds ETS's System 7 prelude to a lowered procedure (issue #116):
///
/// - [`FlashStep::Sys7PreDownloadRestart`] (unload LSMs 1 to 4, basic restart,
///   reconnect) before the procedure's first step that changes device state.
///   ETS runs it before anything else; the vendor's read-only preconditions
///   (`CompareProp`, `CompareMem`) stay ahead of it here, so a device that
///   fails them is refused before its application is unloaded.
/// - [`FlashStep::Sys7EnableVerifyMode`] right after the first `StartLoading`,
///   when the mask declares the Hawk `VerifyMode` feature and streams blind.
///   ETS writes `obj0/PID_DEVICE_CONTROL` after the first allocation record;
///   the allocation and its stream are one step here, so the write goes out
///   just before that record. Nothing depends on the order: the bit only makes
///   the device echo memory writes.
///
/// ETS's read-only prelude traffic (`PID_SERIAL_NUMBER`, `PID_MANUFACTURER_ID`,
/// `PID_HARDWARE_TYPE`, the `0xB6EC` and `0x0060` memory reads) is not
/// reproduced; `dev/system7-spec.md` §3 lists why.
fn add_ets_prelude(steps: &mut Vec<FlashStep>, profile: &bussard_mgmt::Sys7Profile) {
    if !profile.read_compare_write()
        && let Some(first_load) = steps
            .iter()
            .position(|s| matches!(s, FlashStep::Sys7StartLoading { .. }))
    {
        steps.insert(first_load + 1, FlashStep::Sys7EnableVerifyMode);
    }
    // A procedure that loads nothing (a bare restart) gets no prelude.
    let loads = steps.iter().any(|s| {
        matches!(
            s,
            FlashStep::Sys7Unload { .. } | FlashStep::Sys7StartLoading { .. }
        )
    });
    if !loads {
        return;
    }
    let first_change = steps
        .iter()
        .position(|s| {
            !matches!(
                s,
                FlashStep::CompareProp { .. } | FlashStep::Sys7CompareMem { .. }
            )
        })
        .unwrap_or(steps.len());
    steps.insert(
        first_change,
        FlashStep::Sys7PreDownloadRestart {
            unload: SYS7_PRELUDE_UNLOAD_LSMS.to_vec(),
        },
    );
}

/// Lowers a System 7 (mask 0705 / 0701) application into an executable
/// [`FlashPlan`] (`[system7-spec §3/§4]`).
///
/// System 7 is memory-mapped and absolute-addressed: the download is a sequence
/// of absolute-segment allocations + streams driven by three parallel load-state
/// machines, with no `PID_TABLE_REFERENCE` resolution and no relative segments.
/// The op → step mapping:
///
/// | `LoadOp`                | `FlashStep`                                    |
/// |-------------------------|------------------------------------------------|
/// | `Unload{lsm}`           | [`FlashStep::Sys7Unload`]                       |
/// | `Load{lsm}`             | [`FlashStep::Sys7StartLoading`]                 |
/// | `AbsSegment{lsm,a,sz}`  | [`FlashStep::Sys7AbsSegment`] (alloc + stream)  |
/// | `TaskSegment{lsm,a}`    | [`FlashStep::Sys7TaskSegment`]                  |
/// | `TaskCtrl1{lsm,a,c}`    | [`FlashStep::Sys7TaskCtrl1`]                    |
/// | `LoadCompleted{lsm}`    | [`FlashStep::Sys7LoadCompleted`]                |
/// | `CompareProp{0,78,d}`   | [`FlashStep::CompareProp`] (obj0/PID78 preflight)|
/// | `CompareMem{a,d,sz}` (Raw)| [`FlashStep::Sys7CompareMem`]                 |
/// | `LoadImageProp{oi,pid}` | [`FlashStep::LoadImageProp`] (Jung A-A011 MCB)  |
/// | `Restart`               | [`FlashStep::Restart`]                          |
/// | `Delay{ms}`             | [`FlashStep::Delay`] (a pause, nothing sent)    |
///
/// [`add_ets_prelude`] then adds ETS's pre-download restart pass and, on a
/// `VerifyMode` mask, the verify-mode switch.
///
/// The mask profile ([`bussard_mgmt::Sys7Profile`]) supplies the LSM realisation,
/// authorize level and mem-types; absent `HawkConfigurationData`, the
/// corpus-default profile drives blind (`[system7-spec §2.4]`).
#[allow(clippy::too_many_arguments)] // the plan inputs plus the shared Dynamic memo (issue #367).
pub(super) fn plan_flash_sys7(
    app: &ApplicationProgram,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    profile: bussard_mgmt::MaskProfile,
    hawk: Option<&bussard_prod::HawkConfig>,
    tables: &Sys7PlanTables,
    memo: &bussard_prod::dynamic::DynamicMemo<'_, ApplicationProgram>,
) -> std::result::Result<FlashPlan, PlanError> {
    let sys7_tables = &tables.tables;
    let linked_flags = &tables.linked_flags;
    let app_mask = app
        .mask_version
        .clone()
        .ok_or_else(|| PlanError::MissingAppMask(app.id.clone()))?;

    // System 7 apps carry their whole download in their own load procedures
    // (ProductProcedure style — no master-template splice; `[corpus 49/49]`).
    // Each `<choose>` of the procedure is decided under the device's
    // parameters (issue #390: the MDT 0705 label writes and PID 19 compare).
    let config = memo.evaluate_for(app, overrides);
    let mut ops = super::plan_props::guarded_ops(app, &config)?;
    if ops.is_empty() {
        return Err(PlanError::NoProcedure(app.id.clone()));
    }
    ops.truncate(sys7_procedure_end(&ops));
    // The values the program's property-located parameters compose, for a
    // property write without `InlineData`.
    let property_values = bussard_prod::compute_property_values(app, &config).map_err(|e| {
        PlanError::UnsupportedWriteProp {
            step: 0,
            reason: format!("composing the property values from the parameters: {e}"),
        }
    })?;

    // Resolve parameter images up front: each parameter segment's <Data> is only
    // the vendor's template, and the image streamed for it is that template with
    // the parameters laid over it.
    let (param_images, mut placed) =
        bussard_prod::compute_parameter_image_placed_with(app, overrides, base_offsets, memo)
            .map_err(|e| PlanError::UnresolvableImage {
                step: 0,
                reason: format!("computing the parameter image: {e}"),
            })?;

    // The data-driven mask profile: from `HawkConfigurationData` when the import
    // path supplied one, else the corpus-default fallback (`[system7-spec §2.4]`).
    let mut s7_profile = hawk
        .and_then(sys7_profile_from_hawk)
        .or_else(|| profile.sys7_default_profile())
        .unwrap_or_else(bussard_mgmt::Sys7Profile::corpus_default);
    // Realisation override (`[system7-spec §5]`: "flipping the profile bit is a
    // one-line change"). The product data selects the realisation (default
    // memory-mapped); this env var flips it so bussard's `LsmAccess` switch can be
    // conformance-tested against a property-based device side without a second
    // product. It never changes what a normal, product-driven flash does.
    if let Some(lsm) = sys7_lsm_override() {
        s7_profile.lsm = lsm;
    }
    // The Hawk `VerifyMode` feature decides blind vs read-compare-write segment
    // streaming (issue #133), even when the block selects no memory-mapped LSM.
    if let Some(h) = hawk {
        s7_profile.verify_mode = h.verify_mode();
    }

    // Index the app's absolute code segments by address so each AbsSegment op can
    // find its <Data>/<Mask> payload. System 7 segments are all absolute.
    let mut seg_by_addr: BTreeMap<u32, &bussard_prod::CodeSegment> = BTreeMap::new();
    for seg in app.code_segments.values() {
        if seg.kind == SegmentKind::Absolute
            && let Some(addr) = seg.address_or_offset
        {
            seg_by_addr.insert(addr, seg);
        }
    }

    let mut steps: Vec<FlashStep> = Vec::new();
    let mut images: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut segment_masks: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    // A segment the taken branches allocate in parts (issue #413: the MDT
    // `A-0054` with `Switching times in the device` = 1 allocates `0x47E4` as
    // 899 + 2966 + 578 octets of its 5406): each allocation streams the part
    // of the image it holds, never the whole image into the first one. The
    // octets between and after the parts are kept on the device, as ETS
    // keeps them (issue #411, [`sys7_kept_octets`]).
    let splits = sys7_segment_splits(app, &ops, |seg| {
        param_images
            .get(&seg.id)
            .filter(|b| !b.is_empty())
            .or(seg.data.as_ref())
            .map_or(0, Vec::len)
    });
    let mut part_at: BTreeMap<u32, (&bussard_prod::CodeSegment, usize, usize)> = BTreeMap::new();
    let mut gaps_of: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    for split in &splits {
        for &(addr, offset, part_len) in &split.parts.parts {
            part_at.entry(addr).or_insert((split.seg, offset, part_len));
        }
        gaps_of.insert(split.seg.id.clone(), split.parts.gaps.clone());
    }
    let kept: Vec<KeptOctets> = splits.iter().filter_map(SegmentSplit::kept).collect();
    // A split no `<choose>` makes has no capture: a parameter placed in its
    // gap refuses, as before issue #411.
    for split in splits.iter().filter(|s| !s.by_choose) {
        let placed_here = placed.get(&split.seg.id);
        if let Some(&(start, end)) =
            split.parts.gaps.iter().find(|(start, end)| {
                placed_here.is_some_and(|p| p.range(start..end).next().is_some())
            })
        {
            return Err(PlanError::UnsupportedOp {
                op: format!(
                    "LdCtrlAbsSegment allocations outside any <choose> that leave octets \
                     {start}..{end} of segment {} unallocated while the configuration places \
                     a parameter there (no ETS capture shows what ETS writes there)",
                    split.seg.id
                ),
            });
        }
    }

    // With `DynamicTableManagement` ETS sizes the address-table segment to the
    // table and moves the association table directly behind it (issue #383).
    // Only when both tables are computed: a table left to the product's
    // `<Data>` keeps the product's segments.
    let packed = match (sys7_tables.get(&1), sys7_tables.get(&2)) {
        (Some(address), Some(_)) => sys7_packed_tables(app, address.image.len()),
        _ => None,
    };

    // Every TaskSegment record carries the application's identity: PEI type,
    // manufacturer, application number and version, all from the product
    // ([`sys7_task_identity`]). A product that lacks one refuses at the first
    // TaskSegment op rather than writing a guessed identity.
    let task_identity = sys7_task_identity(app);

    for (i, op) in ops.iter().enumerate() {
        let step_no = i + 1;
        match op {
            LoadOp::Connect | LoadOp::Disconnect => {}
            LoadOp::Restart => steps.push(FlashStep::Restart),
            LoadOp::Delay { milliseconds } => steps.push(super::plan::lower_delay(*milliseconds)?),
            LoadOp::Unload { lsm_idx } => steps.push(FlashStep::Sys7Unload {
                lsm: check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?,
            }),
            LoadOp::Load { lsm_idx } => steps.push(FlashStep::Sys7StartLoading {
                lsm: check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?,
            }),
            LoadOp::LoadCompleted { lsm_idx } => steps.push(FlashStep::Sys7LoadCompleted {
                lsm: check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?,
            }),
            LoadOp::AbsSegment {
                lsm_idx,
                address,
                size,
                access,
                mem_type,
                seg_flags,
                seg_type,
            } => {
                // Validate before anything is bound: the executor folds the LSM
                // index into the record's opcode nibble and the address/size into
                // its 2-octet fields, so an out-of-range value used to go out as a
                // *wrong frame* on the bus (issue #81).
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                let addr = address.ok_or_else(|| PlanError::UnresolvableImage {
                    step: step_no,
                    reason: "LdCtrlAbsSegment has no Address".to_string(),
                })?;
                let addr = check_sys7_u16(step_no, "segment address", addr)?;
                let size = check_sys7_u16(step_no, "segment size", size.unwrap_or(0))?;
                let (addr, size) = match packed {
                    Some(p) if lsm == 1 && addr == p.address => (addr, p.address_size),
                    Some(p) if lsm == 2 && addr == p.static_association => {
                        (p.association, p.association_size)
                    }
                    _ => (addr, size),
                };
                // The allocation must also *fit* the 16-bit space: a segment that
                // starts inside it but runs past 0xFFFF cannot be placed.
                check_sys7_u16(step_no, "segment end", addr + size.saturating_sub(1))?;
                // The allocation record's attribute octets come from the op itself
                // when the product declares them (`Access`/`MemType`/`SegFlags`,
                // which the ETS captures reproduce verbatim: `f2 03 80`,
                // `f3 03 80`, `f3 03 00`), else from the address-derived defaults.
                let mem_type = mem_type
                    .and_then(|m| u8::try_from(m).ok())
                    .unwrap_or_else(|| mem_type_for_addr(addr, &s7_profile));
                let (default_access, default_seg_flags) = bussard_mgmt::alloc_attr_octets(mem_type);
                let seg_flags = seg_flags_octet(*seg_flags).unwrap_or(default_seg_flags);
                let access = access
                    .and_then(|a| u8::try_from(a).ok())
                    .unwrap_or(default_access);
                // A table LSM (1 = group addresses, 2 = associations) streams the
                // table computed from the model, never the product's `<Data>`
                // template: the Jung 3361-1MWW ships a 255-entry placeholder table
                // (`FF 00 00 00 01 00 02 …`) which, written verbatim, linked the
                // device to 254 group addresses (issue #89, 1.1.36). ETS writes
                // the count octet and the group addresses only, skipping the
                // device-owned individual-address slot — the table mask does the
                // same here.
                let image = if let Some(table) = sys7_tables.get(&lsm) {
                    if table.image.len() > size as usize {
                        return Err(PlanError::UnresolvableImage {
                            step: step_no,
                            reason: format!(
                                "LSM {lsm} table image is {} octets but the segment at {addr:#06X} holds {size}",
                                table.image.len()
                            ),
                        });
                    }
                    let id = seg_by_addr
                        .get(&addr)
                        .map(|seg| seg.id.clone())
                        .unwrap_or_else(|| format!("lsm{lsm}-table-{addr:#06X}"));
                    images.insert(id.clone(), table.image.clone());
                    if let Some(mask) = &table.mask {
                        segment_masks.insert(id.clone(), mask.clone());
                    }
                    Some(ImageRef {
                        segment_id: id,
                        kind: ImageKind::Table,
                        len: table.image.len(),
                        offset: 0,
                    })
                } else {
                    // Bind the segment's parameter image: its <Data> with every
                    // parameter's resolved value (vendor default, ParameterRef
                    // override, model override) laid over it. Streaming the raw
                    // <Data> template instead wrote the vendor's placeholder
                    // bytes, which are not the parameter defaults, and dropped
                    // every model override (issue #117: the 3361-1MWW and 3181
                    // parameter segments). A segment with no <Data> that no
                    // parameter targets is an allocate-only record (e.g. the
                    // 0x0700 RAM region), with no stream.
                    if let Some(&(seg, offset, len)) = part_at.get(&addr) {
                        bind_segment_part(
                            seg,
                            offset,
                            len,
                            &param_images,
                            &placed,
                            gaps_of.get(&seg.id).map(Vec::as_slice).unwrap_or(&[]),
                            &mut images,
                            &mut segment_masks,
                        )
                    } else {
                        seg_by_addr.get(&addr).and_then(|seg| {
                            let bytes = param_images
                                .get(&seg.id)
                                .filter(|b| !b.is_empty())
                                .or(seg.data.as_ref());
                            bytes.map(|data| {
                                images.insert(seg.id.clone(), data.clone());
                                if let Some(mask) = &seg.mask {
                                    segment_masks.insert(
                                        seg.id.clone(),
                                        effective_mask(mask, placed.get(&seg.id)),
                                    );
                                }
                                ImageRef {
                                    segment_id: seg.id.clone(),
                                    kind: ImageKind::Code,
                                    len: data.len(),
                                    offset: 0,
                                }
                            })
                        })
                    }
                };
                // `SegType="1"` allocates a stack segment: ETS sends it as
                // AllocAbsStackSeg (subtype 01), every other octet as for a
                // data segment (issue #487, MDT `A-0222` LSM 3 record 4).
                let seg_type = match seg_type.unwrap_or(0) {
                    0 => bussard_mgmt::sys7::S7_SUB_ALLOC_DATA,
                    1 => bussard_mgmt::sys7::S7_SUB_ALLOC_STACK,
                    other => {
                        return Err(PlanError::UnresolvableImage {
                            step: step_no,
                            reason: format!(
                                "LdCtrlAbsSegment SegType {other} is not a data (0) or stack (1) segment"
                            ),
                        });
                    }
                };
                steps.push(FlashStep::Sys7AbsSegment {
                    lsm,
                    address: addr,
                    size,
                    mem_type,
                    access,
                    seg_flags,
                    seg_type,
                    image,
                });
            }
            LoadOp::TaskSegment { lsm_idx, address } => {
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                // A TaskSegment on an LSM outside 1 to 4 (LsmIdx 5 on the
                // Busch-Jaeger 0701 applications and on 0705 products) is not
                // sent: ETS sends no record for it on either realisation
                // (captures/synthetic/syn-s7-lsm5 and syn-s7-lsm5-0705,
                // issues #489 and #680).
                if !sys7_lsm_record_sent(lsm) {
                    continue;
                }
                let addr = address.ok_or_else(|| PlanError::UnresolvableImage {
                    step: step_no,
                    reason: "LdCtrlTaskSegment has no Address".to_string(),
                })?;
                let addr = check_sys7_u16(step_no, "task segment address", addr)?;
                // The association table's descriptor names its packed base, as
                // ETS's does (`03 02 401F …` on the A-2088).
                let addr = match packed {
                    Some(p) if lsm == 2 && addr == p.static_association => p.association,
                    _ => addr,
                };
                let identity =
                    task_identity
                        .clone()
                        .map_err(|reason| PlanError::UnresolvableImage {
                            step: step_no,
                            reason,
                        })?;
                steps.push(FlashStep::Sys7TaskSegment {
                    lsm,
                    address: addr,
                    identity,
                });
            }
            LoadOp::TaskCtrl1 {
                lsm_idx,
                address,
                count,
            } => {
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                let addr = address.ok_or_else(|| PlanError::UnresolvableImage {
                    step: step_no,
                    reason: "LdCtrlTaskCtrl1 has no Address".to_string(),
                })?;
                let addr = check_sys7_u16(step_no, "task control address", addr)?;
                // The count is a single octet of the record.
                let count = count.unwrap_or(1);
                if count > u32::from(u8::MAX) {
                    return Err(PlanError::Sys7FieldOutOfRange {
                        step: step_no,
                        field: "task control count",
                        value: u64::from(count),
                        max: u64::from(u8::MAX),
                    });
                }
                steps.push(FlashStep::Sys7TaskCtrl1 {
                    lsm,
                    address: addr,
                    count,
                });
            }
            LoadOp::TaskPtr {
                lsm_idx,
                init_ptr,
                save_ptr,
                serial_ptr,
            } => {
                // The Task Pointer Record, mandatory on 0701/0705 (Profiles
                // Annex A.2.4.1 Table 7), laid out per KNX 3/5/2 §3.31.2.
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                steps.push(FlashStep::Sys7TaskPtr {
                    lsm,
                    init: sys7_u16_field(step_no, "task pointer init", init_ptr.unwrap_or(0))?,
                    save: sys7_u16_field(step_no, "task pointer save", save_ptr.unwrap_or(0))?,
                    pei_handler: sys7_u16_field(
                        step_no,
                        "task pointer PEI handler",
                        serial_ptr.unwrap_or(0),
                    )?,
                });
            }
            LoadOp::TaskCtrl2 {
                lsm_idx,
                callback,
                address,
                seg0,
                seg1,
            } => {
                // Task Control Record 2, mandatory on 0701/0705 (Profiles
                // Annex A.2.4.1 Table 7), laid out per KNX 3/5/2 §3.31.2.
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                steps.push(FlashStep::Sys7TaskCtrl2 {
                    lsm,
                    callback: sys7_u16_field(
                        step_no,
                        "task control 2 callback",
                        callback.unwrap_or(0),
                    )?,
                    com_objects: sys7_u16_field(
                        step_no,
                        "task control 2 group-object pointer",
                        address.unwrap_or(0),
                    )?,
                    segment_1: sys7_u16_field(
                        step_no,
                        "task control 2 segment 1",
                        seg0.unwrap_or(0),
                    )?,
                    segment_2: sys7_u16_field(
                        step_no,
                        "task control 2 segment 2",
                        seg1.unwrap_or(0),
                    )?,
                });
            }
            LoadOp::CompareProp { .. } => {
                // The obj0/PID78 preflight (44/49 MDT apps). Reuses the System B
                // CompareProp step: an interface-object property read + compare,
                // which is identical on System 7 (`[system7-spec §4.6]`).
                steps.push(super::plan_props::lower_compare_prop(step_no, op)?);
            }
            LoadOp::WriteProp { .. } => {
                // A property write with its Count and Verify (issue #390): the
                // 0701 programs' `ObjIdx=3 PropId=204 Count=2` and the MDT 0705
                // label properties their parameters compose.
                steps.push(super::plan_props::lower_write_prop(
                    step_no,
                    op,
                    &property_values,
                )?);
            }
            LoadOp::LoadImageProp {
                obj_idx,
                prop_id,
                count,
                ..
            } => {
                // Jung M-0004_A-A011 requires per-object MCB verification via
                // LoadImageProp PID 27 (`[system7-spec §2 amendment]`). Reuses the
                // System B LoadImageProp step (an MCB-table read + CRC compare).
                steps.push(FlashStep::LoadImageProp {
                    obj_idx: obj_idx.unwrap_or(0),
                    prop_id: prop_id.unwrap_or(bussard_mgmt::PID_MCB_TABLE.into()),
                    count: count.unwrap_or(1).max(1),
                    // System 7 read-back verify is the baseline; the MCB check is a
                    // read-only confirm against the device's own CRC, so no
                    // tool-side image is bound here.
                    image: None,
                    advisory: false,
                });
            }
            LoadOp::Raw { name, attrs } if name == "LdCtrlCompareMem" => {
                let (address, expected) =
                    parse_compare_mem(attrs).ok_or_else(|| PlanError::UnresolvableImage {
                        step: step_no,
                        reason: "LdCtrlCompareMem missing Address or InlineData".to_string(),
                    })?;
                let address = check_sys7_u16(step_no, "compare address", address)?;
                steps.push(FlashStep::Sys7CompareMem { address, expected });
            }
            // System 7 never carries these (`[corpus §2]`); a Raw op we do not
            // recognise refuses cleanly rather than silently skipping.
            other => {
                return Err(PlanError::UnsupportedOp {
                    op: sys7_op_label(other),
                });
            }
        }
    }

    add_ets_prelude(&mut steps, &s7_profile);

    // The group-object descriptors live inside the application's own EEPROM
    // segment on these devices (`GroupObjectTable AddressSpace="None"` in the
    // mask's Hawk data), with the vendor template's communication flag set on
    // every object. ETS enables the flag only on linked objects (captures
    // 1.1.31 with no links: none set; 1.1.46 with four links: exactly the four
    // association ASAPs). Mirror that here (issue #89, 1.1.32).
    let linked: BTreeSet<u16> = sys7_tables
        .get(&2)
        .map(|assoc| sys7_linked_asaps(&assoc.image))
        .unwrap_or_default();
    // Every unlinked object's CONFIG (and TYPE) comes from the ComObjectRef the
    // device's parameter values make visible, as in ETS (issue #117).
    let default_flags = sys7_object_defaults(app, &config);
    // Module instances shift numbers past the declared ones: count those too.
    let last_object = app
        .resolved_com_objects()
        .iter()
        .map(|c| c.number())
        .chain(default_flags.keys().copied())
        .chain(linked.iter().copied())
        .max();
    let declared = app.com_object_table.as_ref();
    // An application that declares no com-object, no module object and no
    // link has every descriptor past its last declared object: ETS writes the
    // template unchanged (issue #475, COMIP2 `M-00E1_A-A00D-10-12FB-O00C5`,
    // all 8 CONFIG octets kept at `df`). Only a declaration rewrites.
    if let Some(last_object) = last_object {
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            declared,
            &linked,
            linked_flags,
            &default_flags,
            Some(last_object),
        );
    }
    // A kept octet is written by no step, so it is not placed: the dump's
    // coverage, the parameter-only download and the restore leave it alone,
    // and the read-back reports a parameter there as kept (issue #411).
    for k in &kept {
        if let Some(octets) = placed.get_mut(&k.segment) {
            octets.retain(|&i| !k.contains(i));
        }
    }
    let code_segments = sys7_code_segments(&steps, &images, declared, &param_images, &placed);

    Ok(FlashPlan {
        identity: AppIdentity {
            id: app.id.clone(),
            name: app.name.clone(),
            application_number: app.application_number,
            application_version: app.application_version,
            mask_version: app_mask,
            original_manufacturer: app.original_manufacturer.clone(),
        },
        device_mask,
        steps,
        images,
        param_images,
        spliced_from_template: false,
        sys7: Some(Sys7Context {
            profile: s7_profile,
            segment_masks,
            code_segments,
        }),
        confirmed_restart: false,
        baseline: BTreeMap::new(),
        placed,
        unwritten: BTreeMap::new(),
        baseline_address: BTreeMap::new(),
        security_capacity: Default::default(),
        user_memory_above_64k: false,
        par_allocations: BTreeMap::new(),
        par_procedure: false,
        kept,
    })
}

/// The segments of a System 7 plan that hold the application's code, which
/// the identity check samples (issue #355): the segments streamed verbatim
/// from the product's `<Data>`. Left out are a table load-state machine's
/// segment (its image is computed from the model), a RAM segment (the
/// running application rewrites it), one with no checksum control (the
/// product does not treat it as fixed content), one a parameter is placed in
/// (parameter memory), and the group-object descriptor table (the planner
/// rewrites its CONFIG and TYPE octets from the model: the Theben Meteodata's
/// `AS-4400` and the MDT `A-00xx` programs').
fn sys7_code_segments(
    steps: &[FlashStep],
    images: &BTreeMap<String, Vec<u8>>,
    declared: Option<&TableLocation>,
    param_images: &BTreeMap<String, Vec<u8>>,
    placed: &bussard_prod::PlacedOctets,
) -> BTreeSet<String> {
    let object_table = sys7_object_table_location(steps, images, declared).map(|(id, _)| id);
    steps
        .iter()
        .filter_map(|step| match step {
            FlashStep::Sys7AbsSegment {
                image: Some(image),
                mem_type,
                seg_flags,
                ..
            } if image.kind == ImageKind::Code && *mem_type != 2 && *seg_flags != 0 => {
                Some(&image.segment_id)
            }
            _ => None,
        })
        .filter(|id| !param_images.get(*id).is_some_and(|b| !b.is_empty()))
        .filter(|id| !placed.get(*id).is_some_and(|o| !o.is_empty()))
        .filter(|id| object_table.as_ref() != Some(*id))
        .filter(|id| images.contains_key(*id))
        .cloned()
        .collect()
}

/// How the allocations of a load procedure hold one absolute segment's image
/// when no single allocation holds all of it (issue #413).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SegmentParts {
    /// Per allocation that starts inside the image, in address order: the
    /// allocation's address, and the offset and length of the part of the
    /// image it holds (never more than the allocation's size).
    pub parts: Vec<(u32, usize, usize)>,
    /// The octet ranges of the image that no allocation holds, as
    /// `(start, end)` offsets.
    pub gaps: Vec<(usize, usize)>,
}

/// Splits the `image_len`-octet image of the absolute segment at `base` over
/// the `(address, size)` allocations the procedure's taken branches make.
///
/// `None` when the image needs no split: one allocation at `base` holds all
/// of it (the plain case, where the image is streamed whole), or no
/// allocation starts inside it. Otherwise every allocation that starts inside
/// the image holds the octets from its address up to its size, and the
/// octets no allocation holds are the gaps: memory the download does not
/// allocate, so it never writes it. ETS's download of the MDT `A-0054` with
/// `Switching times in the device` = 1 leaves the switching times the device
/// keeps there ("The switch time settings are not transmitted").
pub(super) fn sys7_segment_parts(
    allocations: &[(u32, u32)],
    base: u32,
    image_len: usize,
) -> Option<SegmentParts> {
    let end = u64::from(base) + image_len as u64;
    let mut inside: Vec<(u32, u32)> = allocations
        .iter()
        .copied()
        .filter(|&(a, s)| s > 0 && a >= base && u64::from(a) < end)
        .collect();
    inside.sort_unstable();
    inside.dedup();
    if inside.is_empty()
        || inside
            .iter()
            .any(|&(a, s)| a == base && s as usize >= image_len)
    {
        return None;
    }
    let mut parts = Vec::with_capacity(inside.len());
    let mut gaps = Vec::new();
    let mut covered = 0usize;
    for (addr, size) in inside {
        let offset = (addr - base) as usize;
        let len = (size as usize).min(image_len - offset);
        if offset > covered {
            gaps.push((covered, offset));
        }
        covered = covered.max(offset + len);
        parts.push((addr, offset, len));
    }
    if covered < image_len {
        gaps.push((covered, image_len));
    }
    Some(SegmentParts { parts, gaps })
}

/// One absolute segment of a System 7 application the taken branches of its
/// load procedure allocate in parts (issue #413), with the load-state
/// machine of its first part.
pub(super) struct SegmentSplit<'a> {
    /// The segment.
    seg: &'a bussard_prod::CodeSegment,
    /// Its absolute base address.
    base: u32,
    /// The octets of its image.
    len: usize,
    /// The LSM the first part is allocated on.
    lsm: Option<u32>,
    /// The parts and the gaps.
    parts: SegmentParts,
    /// Whether a `<choose>` branch makes the split: the allocations outside
    /// every `<choose>` do not split the segment. Only such a split is
    /// planned as the `syn-s7-choose-split` capture shows (issue #411); a
    /// procedure that always allocates a segment in part (the Jung
    /// `M-0004_A-5015-13-7E56-O00F4`, `AS-5DAF`: 4 of 14 octets) has no
    /// capture, and a parameter placed in its gap still refuses.
    by_choose: bool,
}

impl SegmentSplit<'_> {
    /// The octets of the segment no allocation holds, as [`KeptOctets`]
    /// (issue #411); `None` when the parts cover the whole image.
    fn kept(&self) -> Option<KeptOctets> {
        (self.by_choose && !self.parts.gaps.is_empty()).then(|| KeptOctets {
            object: self.lsm.unwrap_or(0),
            segment: self.seg.id.clone(),
            allocated: self.len,
            ranges: self.parts.gaps.clone(),
            address: Some(self.base),
        })
    }
}

/// The absolute segments of `app` the `LdCtrlAbsSegment` records of `ops`
/// (the taken branches) allocate in parts ([`sys7_segment_parts`]), the
/// image of each `image_len(segment)` octets long. A segment at an address
/// another segment also declares is taken once, the last by id.
pub(super) fn sys7_segment_splits<'a>(
    app: &'a ApplicationProgram,
    ops: &[LoadOp],
    image_len: impl Fn(&bussard_prod::CodeSegment) -> usize,
) -> Vec<SegmentSplit<'a>> {
    let mut seg_by_addr: BTreeMap<u32, &bussard_prod::CodeSegment> = BTreeMap::new();
    for seg in app.code_segments.values() {
        if seg.kind == SegmentKind::Absolute
            && let Some(addr) = seg.address_or_offset
        {
            seg_by_addr.insert(addr, seg);
        }
    }
    let records: Vec<(Option<u32>, u32, u32)> = ops
        .iter()
        .filter_map(|op| match op {
            LoadOp::AbsSegment {
                lsm_idx,
                address: Some(a),
                size,
                ..
            } => Some((*lsm_idx, *a, size.unwrap_or(0))),
            _ => None,
        })
        .collect();
    let allocations: Vec<(u32, u32)> = records.iter().map(|&(_, a, s)| (a, s)).collect();
    // The allocations no `<choose>` guards: a segment they split already is
    // split by the procedure itself, not by a branch.
    let unguarded: Vec<(u32, u32)> = super::plan::self_contained_blocks(app)
        .into_iter()
        .flat_map(|p| {
            p.ops
                .iter()
                .enumerate()
                .filter(|(i, _)| p.guards_of(*i).is_empty())
                .filter_map(|(_, op)| match op {
                    LoadOp::AbsSegment {
                        address: Some(a),
                        size,
                        ..
                    } => Some((*a, size.unwrap_or(0))),
                    _ => None,
                })
        })
        .collect();
    seg_by_addr
        .into_iter()
        .filter_map(|(base, seg)| {
            let len = image_len(seg);
            let parts = sys7_segment_parts(&allocations, base, len)?;
            let first = parts.parts.first().map(|&(addr, _, _)| addr);
            let lsm = records
                .iter()
                .find(|&&(_, a, _)| Some(a) == first)
                .and_then(|&(lsm, _, _)| lsm);
            let by_choose = sys7_segment_parts(&unguarded, base, len).is_none();
            Some(SegmentSplit {
                seg,
                base,
                len,
                lsm,
                parts,
                by_choose,
            })
        })
        .collect()
}

/// The octets of each absolute segment a System 7 download leaves as the
/// device holds them (issue #411): the gaps the taken branches' allocations
/// leave in a segment they allocate in parts, each segment's image
/// `image_len(segment)` octets long.
///
/// The rule, from ETS: a branch that allocates a segment in parts is planned
/// as ETS downloads it. Each `LdCtrlAbsSegment` record is sent as the
/// product declares it, each part of the image is streamed into the
/// allocation that holds it, and the octets no allocation holds are neither
/// written nor read back; a parameter placed there is kept on the device,
/// reported as kept (not written, no verdict). ETS's download of the
/// synthetic `syn-s7-choose-split`
/// (`captures/synthetic/syn-s7-choose-split/defaults/ops.txt`, ops 33 to 41)
/// allocates `0x4440` (1 octet) and `0x4443` (61 octets), streams `0x4440`
/// and `0x4443..0x447F`, and never writes or reads `0x4441..0x4442`, where
/// the 16-bit parameter `delay` sits; the download completes. The MDT
/// `A-0054-14` and `A-0255-21` with `P-203` = 1 have the same shape.
pub(super) fn sys7_kept_octets(
    app: &ApplicationProgram,
    ops: &[LoadOp],
    image_len: impl Fn(&bussard_prod::CodeSegment) -> usize,
) -> Vec<KeptOctets> {
    sys7_segment_splits(app, ops, image_len)
        .iter()
        .filter_map(SegmentSplit::kept)
        .collect()
}

/// The `(LSM, address, size)` of every `LdCtrlAbsSegment` record a System 7
/// download of `app` under `values` sends, `None` when the procedure cannot
/// be decided (the planner refuses such a plan on its own).
fn sys7_allocation_records(
    app: &ApplicationProgram,
    values: &BTreeMap<String, String>,
    memo: &bussard_prod::dynamic::DynamicMemo<'_, ApplicationProgram>,
) -> Option<BTreeSet<(u32, u32, u32)>> {
    let config = memo.evaluate_for(app, values);
    let mut ops = super::plan_props::guarded_ops(app, &config).ok()?;
    ops.truncate(sys7_procedure_end(&ops));
    Some(
        ops.iter()
            .filter_map(|op| match op {
                LoadOp::AbsSegment {
                    lsm_idx,
                    address: Some(a),
                    size,
                    ..
                } => Some((lsm_idx.unwrap_or(0), *a, size.unwrap_or(0))),
                _ => None,
            })
            .collect(),
    )
}

/// Why a parameter-only download cannot take a System 7 device from the
/// parameter values `before` (decoded off the device) to `after` (the
/// model's): a load-procedure `<choose>` on a changed parameter allocates
/// the absolute segments differently (issue #411), `None` when it does not,
/// for an application that is not System 7, or when either side cannot be
/// decided.
///
/// A parameter-only download sends no allocation record, so the device keeps
/// the allocations of its last full download: writing the new layout's
/// octets into memory the device never allocated is refused by the device
/// (knx-sim answers `T_NAK`), and octets the new layout keeps would carry
/// the old values. Only a full download allocates the new layout. The
/// synthetic `syn-s7-choose-split` shows it: `mode` 1 allocates `0x4440` in
/// two parts around `delay`, any other value all 64 octets.
pub fn allocation_change(
    app: &ApplicationProgram,
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    memo: &bussard_prod::dynamic::DynamicMemo<'_, ApplicationProgram>,
) -> Option<String> {
    let is_sys7 = app
        .mask_version
        .as_deref()
        .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())
        .map(bussard_mgmt::MaskProfile::from_mask)
        .is_some_and(|p| p.is_system_7());
    if !is_sys7 || app.load_procedures.iter().all(|p| p.chooses.is_empty()) {
        return None;
    }
    let old = sys7_allocation_records(app, before, memo)?;
    let new = sys7_allocation_records(app, after, memo)?;
    if old == new {
        return None;
    }
    let text = |records: Vec<&(u32, u32, u32)>| -> String {
        records
            .iter()
            .map(|(lsm, addr, size)| format!("LSM {lsm} {addr:#06X} ({size} octets)"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Some(format!(
        "the load procedure allocates {} instead of {}",
        text(new.difference(&old).collect()),
        text(old.difference(&new).collect())
    ))
}

/// Binds the part `offset..offset + len` of `seg`'s image to the allocation
/// that holds it (issue #413), registering the whole image and its write mask
/// the first time the segment is met.
///
/// The octets of the segment no allocation holds (`gaps`) are the device's:
/// the mask marks them unwritten, so the read-compare, a parameter-only
/// download and the diff against the device leave them alone, as ETS does. A
/// parameter placed there is kept on the device (issue #411,
/// [`sys7_kept_octets`]), the octets it occupies masked off like the rest of
/// the gap.
#[allow(clippy::too_many_arguments)] // the segment, its part, and the plan's image tables.
fn bind_segment_part(
    seg: &bussard_prod::CodeSegment,
    offset: usize,
    len: usize,
    param_images: &BTreeMap<String, Vec<u8>>,
    placed: &bussard_prod::PlacedOctets,
    gaps: &[(usize, usize)],
    images: &mut BTreeMap<String, Vec<u8>>,
    segment_masks: &mut BTreeMap<String, Vec<u8>>,
) -> Option<ImageRef> {
    let data = param_images
        .get(&seg.id)
        .filter(|b| !b.is_empty())
        .or(seg.data.as_ref())?;
    if !images.contains_key(&seg.id) {
        let mut mask = seg
            .mask
            .as_ref()
            .map(|m| effective_mask(m, placed.get(&seg.id)))
            .unwrap_or_else(|| vec![0xFF; data.len()]);
        for &(start, end) in gaps {
            for byte in mask.iter_mut().take(end).skip(start) {
                *byte = 0x00;
            }
        }
        images.insert(seg.id.clone(), data.clone());
        segment_masks.insert(seg.id.clone(), mask);
    }
    Some(ImageRef {
        segment_id: seg.id.clone(),
        kind: ImageKind::Code,
        len,
        offset,
    })
}

/// The write mask of a parameter segment (issue #320): an octet is written
/// when the product's `<Mask>` marks it `0xFF` or when the plan placed a
/// parameter in it. ETS writes and read-compares the octets its placed
/// parameters occupy whatever the `<Mask>` says (the Meteodata's C4 page sits
/// in a `0x00` run of `AS-4800`), and leaves a masked run that no parameter
/// occupies alone (the 992 octets of its `AS-4C00` the device holds as
/// `0xFF`). A table segment has no placed octets and keeps its mask as is.
fn effective_mask(mask: &[u8], placed: Option<&std::collections::BTreeSet<usize>>) -> Vec<u8> {
    let mut out = mask.to_vec();
    for &i in placed.into_iter().flatten() {
        if let Some(byte) = out.get_mut(i) {
            *byte = 0xFF;
        }
    }
    out
}

/// What the System 7 post-pass writes for one object that the project does not
/// link: the flags of its ComObjectRef and, when known, its TYPE octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sys7ObjectDefault {
    /// The ref's flags (ref merged onto the base object).
    flags: bussard_model::Flags,
    /// The TYPE octet (the size code of the ref's object size), `None` to keep
    /// the template's.
    type_code: Option<u8>,
    /// The transmission priority the ref (else its base object) declares,
    /// for CONFIG bits 1-0; `None` keeps the template's (issue #541).
    priority: Option<bussard_model::Priority>,
}

/// The per-ASAP defaults the System 7 post-pass writes, from the Dynamic walk.
///
/// ETS writes, for every object the device's parameter values make visible,
/// the flags of the visible ComObjectRef (the 3361-1MWW and 3181 captures of
/// issue #117: the same object `Number` has refs with different flags under
/// different `<when>` branches), and leaves an object no branch shows at the
/// template (C cleared). Only an application whose Dynamic section (module
/// bodies included) holds no `<ComObjectRefRef>` at all falls back to the
/// flat product defaults: every declared ref's flags, with the template's
/// TYPE. One that has them but whose walk reaches none at these values gets
/// no defaults, so every object keeps the template with C cleared (issue
/// #562, ABB `A-A04C-13`: every object behind `Eingang_freigeben = 1`,
/// default 0; ETS wrote `template & !C` on all 20 sweep rows).
pub(super) fn sys7_object_defaults(
    app: &ApplicationProgram,
    config: &bussard_prod::dynamic::DynamicConfig,
) -> BTreeMap<u16, Sys7ObjectDefault> {
    if config.com_objects.is_empty() {
        if dynamic_declares_com_objects(app) {
            return BTreeMap::new();
        }
        return app
            .resolved_com_objects()
            .iter()
            .map(|c| {
                (
                    c.number(),
                    Sys7ObjectDefault {
                        flags: c.flags(),
                        type_code: None,
                        priority: c.declared_priority(),
                    },
                )
            })
            .collect();
    }
    let mut out = BTreeMap::new();
    for active in &config.com_objects {
        let Some((base, cref)) = app.resolve(&active.com_object_ref_id) else {
            continue;
        };
        // A `BaseNumber` its instance has no value for (issue #449) gets no
        // entry here; the parameter image refuses the configuration.
        let offset = match base.base_number_ref.as_deref() {
            Some(arg) => match bussard_prod::module_argument(app, config, active.module, arg) {
                Some(v) => v,
                None => continue,
            },
            None => 0,
        };
        let Ok(asap) = u16::try_from(i64::from(base.number) + offset) else {
            continue;
        };
        let size = cref.object_size.as_deref().or(base.object_size.as_deref());
        out.insert(
            asap,
            Sys7ObjectDefault {
                flags: base.flags.merge(cref.flags).to_flags(),
                type_code: size.and_then(sys7_type_code),
                priority: cref.priority.or(base.priority),
            },
        );
    }
    out
}

/// Whether the program's Dynamic section or any module body holds a
/// `<ComObjectRefRef>` on any branch.
fn dynamic_declares_com_objects(app: &ApplicationProgram) -> bool {
    use bussard_model::dynamic::DynamicNode;
    let mut stack: Vec<&[DynamicNode]> = vec![app.dynamic.as_slice()];
    stack.extend(app.module_dynamics.values().map(Vec::as_slice));
    while let Some(nodes) = stack.pop() {
        for node in nodes {
            match node {
                DynamicNode::ComObjectRefRef(_) => return true,
                DynamicNode::Channel { children, .. }
                | DynamicNode::ParameterBlock { children, .. }
                | DynamicNode::Repeat { children, .. } => stack.push(children),
                DynamicNode::Choose { whens, .. } => {
                    stack.extend(whens.iter().map(|w| w.children.as_slice()));
                }
                DynamicNode::ParameterRefRef(_)
                | DynamicNode::Module { .. }
                | DynamicNode::Assign { .. } => {}
            }
        }
    }
    false
}

/// The System 7 TYPE octet for an `ObjectSize` (the KNX size code: `1 Bit` is
/// 0, `1 Byte` 7, `2 Bytes` 8), `None` for a size the table does not know; the
/// descriptor then keeps the product's template octet.
pub(super) fn sys7_type_code(object_size: &str) -> Option<u8> {
    crate::compute::object_size_code(object_size)
}

/// The ASAPs a System 7 association-table image (`[CNT][TSAP ASAP]…`) links.
pub(super) fn sys7_linked_asaps(assoc_image: &[u8]) -> BTreeSet<u16> {
    let Some((&count, pairs)) = assoc_image.split_first() else {
        return BTreeSet::new();
    };
    pairs
        .as_chunks::<2>()
        .0
        .iter()
        .take(usize::from(count))
        .map(|p| u16::from(p[1]))
        .collect()
}

/// Rewrites the CONFIG octet of the group-object descriptors inside the LSM 3
/// segment image that carries the descriptor table, the way ETS does. Bits 7
/// (U), 6 (T), 4 (W), 3 (R) and 2 (C) come from the object's flags, bits 5, 1
/// and 0 stay as the template has them:
///
/// - a linked ASAP takes the model's flags (`linked_flags`), else its default
///   flags with C set, else the template with C set;
/// - every other ASAP takes its default flags (`default_flags`, see
///   [`sys7_object_defaults`]) with C cleared, else the template with C
///   cleared.
///
/// An ASAP whose default carries a TYPE octet (the visible ref's object size)
/// takes that too, and one whose visible ref (else base object) declares a
/// `Priority` takes it into bits 1-0 (Resources 3/5/1 §4.18.3.1.2.1, issue
/// #541); without a declaration the template's priority stays.
///
/// `last_object` is the highest com-object `Number` the application declares:
/// ETS rewrites the descriptors up to it (numbering gaps included) and leaves
/// the template slots past it alone (1.1.1, 2116REG: the template declares 129
/// descriptors, the application objects up to 126, and ETS keeps the `17` of
/// descriptors 127 and 128 while it clears C on the gaps 6, 7, 14, …). `None`
/// rewrites every descriptor.
///
/// Captures: 1.1.31 (no links: template `db` became `4b`, `17` became `13`),
/// 1.1.46 (four links: `df` became `4f`/`17`/`47`, the project's T R C / W C /
/// T C), 1.1.1 (`47` became `5f`); objects no `<when>` branch shows keep the
/// template (`db`) on the 3361-1MWW and 3181 captures (issue #117).
///
/// The table is where the program's `<ComObjectTable CodeSegment Offset>`
/// declares it, else found by shape (see [`sys7_object_table_location`]):
/// `[CNT:1][RAM-flags ptr:2]` followed by `CNT` 4-octet descriptors
/// `[data ptr:2][CONFIG][TYPE]`. Descriptor `i` is ASAP `i` (the 1.1.46
/// capture: association ASAPs 1, 5, 7, 13 are exactly the descriptors ETS
/// enabled). A plan without such a segment is left untouched.
///
/// Issue #386, 1.1.44 (ABB 6119/20, `A-A002`, no links): the declared table
/// at `AS-43FE` holds 30 descriptors whose little-endian pointers name the
/// controller's own RAM, which the plan does not allocate. ETS wrote `13`
/// and `53` (the visible refs' W / T W, C cleared) to objects 0 and 1 and
/// `db` (template `df`, C cleared) to the other 28.
pub(super) fn apply_sys7_group_object_links(
    steps: &[FlashStep],
    images: &mut BTreeMap<String, Vec<u8>>,
    declared: Option<&TableLocation>,
    linked: &BTreeSet<u16>,
    linked_flags: &BTreeMap<u16, bussard_model::Flags>,
    default_flags: &BTreeMap<u16, Sys7ObjectDefault>,
    last_object: Option<u16>,
) {
    let Some((segment, at)) = sys7_object_table_location(steps, images, declared) else {
        return;
    };
    let Some(bytes) = images.get_mut(&segment) else {
        return;
    };
    let count = bytes.get(at).map_or(0, |&c| usize::from(c));
    // The finder checked the image holds `count` descriptors.
    let Some(descriptors) = bytes.get_mut(at + 3..at + 3 + 4 * count) else {
        return;
    };
    use bussard_model::Flags;
    for (asap, d) in descriptors.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let asap = asap as u16;
        if last_object.is_some_and(|last| asap > last) {
            break;
        }
        let default = default_flags.get(&asap);
        if linked.contains(&asap) {
            match linked_flags
                .get(&asap)
                .copied()
                .or_else(|| default.map(|o| o.flags | Flags::COMMUNICATION))
            {
                Some(flags) => d[2] = crate::compute_sys7::sys7_config_byte(d[2], flags),
                None => d[2] |= 0x04,
            }
        } else {
            match default {
                Some(o) => {
                    d[2] =
                        crate::compute_sys7::sys7_config_byte(d[2], o.flags - Flags::COMMUNICATION)
                }
                None => d[2] &= !0x04,
            }
        }
        if let Some(t) = default.and_then(|o| o.type_code) {
            d[3] = t;
        }
        if let Some(p) = default.and_then(|o| o.priority) {
            d[2] = (d[2] & !0b11) | (p.code() as u8 & 0b11);
        }
    }
}

/// Where the group-object descriptor table sits in a System 7 plan: the
/// segment id and the table's offset in its image.
///
/// The program's `<ComObjectTable CodeSegment Offset>` declaration wins when
/// it names an LSM 3 EEPROM segment of the plan whose image holds the
/// `[CNT:1][RAM-flags ptr:2]` header and `CNT` 4-octet descriptors there.
/// Every System 7 program of the product corpus declares it (336
/// applications); the declaration is what finds the table of a program whose
/// descriptors point into controller RAM the plan does not allocate, or
/// whose pointers are little-endian (101 corpus applications declare
/// `ParameterByteOrder="LittleEndian"`, the ABB 6119/20 among them, issue
/// #386). Without a usable declaration the table is found by shape
/// ([`sys7_group_object_table`]) at offset 0.
pub(super) fn sys7_object_table_location(
    steps: &[FlashStep],
    images: &BTreeMap<String, Vec<u8>>,
    declared: Option<&TableLocation>,
) -> Option<(String, usize)> {
    let from_declaration = declared.and_then(|table| {
        let lsm3_eeprom = steps.iter().any(|step| {
            matches!(
                step,
                FlashStep::Sys7AbsSegment {
                    lsm: 3,
                    mem_type: 3,
                    image: Some(img),
                    ..
                } if img.segment_id == table.code_segment
            )
        });
        let at = usize::try_from(table.offset).ok()?;
        let bytes = images.get(&table.code_segment)?;
        let count = usize::from(*bytes.get(at)?);
        (lsm3_eeprom && count > 0 && bytes.len() >= at + 3 + 4 * count)
            .then(|| (table.code_segment.clone(), at))
    });
    from_declaration.or_else(|| sys7_group_object_table(steps, images).map(|id| (id, 0)))
}

/// The LSM 3 EEPROM segment whose image carries the group-object descriptor
/// table, found by shape (see [`apply_sys7_group_object_links`]):
/// `[CNT:1][RAM-flags ptr:2]` followed by `CNT` 4-octet descriptors
/// `[data ptr:2 BE][CONFIG][TYPE]`, every pointer inside a RAM (`mem_type` 2)
/// segment the plan allocates. The planner rewrites its CONFIG and TYPE
/// octets from the model, so it is configuration, not code (issue #355).
/// `None` when no segment has that shape.
pub(super) fn sys7_group_object_table(
    steps: &[FlashStep],
    images: &BTreeMap<String, Vec<u8>>,
) -> Option<String> {
    let ram: Vec<(u32, u32)> = steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::Sys7AbsSegment {
                address,
                size,
                mem_type: 2,
                ..
            } => Some((*address, *address + *size)),
            _ => None,
        })
        .collect();
    if ram.is_empty() {
        return None;
    }
    // An unused descriptor slot carries a zero data pointer (the 3361 image
    // declares 200 slots and uses 125), so zero passes the shape check.
    let in_ram = |p: u16| {
        p == 0
            || ram
                .iter()
                .any(|(lo, hi)| (*lo..*hi).contains(&u32::from(p)))
    };
    for step in steps {
        let FlashStep::Sys7AbsSegment {
            lsm: 3,
            mem_type: 3,
            image: Some(img),
            ..
        } = step
        else {
            continue;
        };
        let Some(bytes) = images.get(&img.segment_id) else {
            continue;
        };
        let Some((&count, rest)) = bytes.split_first() else {
            continue;
        };
        let count = usize::from(count);
        if count == 0 || rest.len() < 2 + 4 * count {
            continue;
        }
        let ram_flags = u16::from_be_bytes([rest[0], rest[1]]);
        let descriptors = &rest[2..2 + 4 * count];
        let shaped = in_ram(ram_flags)
            && descriptors
                .as_chunks::<4>()
                .0
                .iter()
                .all(|d| in_ram(u16::from_be_bytes([d[0], d[1]])));
        if shaped {
            return Some(img.segment_id.clone());
        }
    }
    None
}

/// Plans a System 7 flash using a `.knxprod`'s parsed `HawkConfigurationData` to
/// resolve the LSM realisation and addresses, falling back to the corpus default
/// when the block is absent (`[system7-spec §2.4]`).
///
/// This is the data-driven entry the CLI uses when it has the master template's
/// Hawk config for the device mask; [`plan_flash`](super::plan_flash) itself (which does not receive
/// the full template) uses the corpus default. Refuses a non-System-7 mask with
/// [`PlanError::NotSystemB`].
pub fn plan_flash_sys7_with_hawk(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    hawk: Option<&bussard_prod::HawkConfig>,
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> std::result::Result<FlashPlan, PlanError> {
    let profile = bussard_mgmt::MaskProfile::from_mask(device_mask);
    if !profile.is_system_7() {
        return Err(PlanError::NotSystemB {
            device: device.to_string(),
            device_mask,
            system: bussard_mgmt::system_type(device_mask),
        });
    }
    let app_mask = app
        .mask_version
        .clone()
        .ok_or_else(|| PlanError::MissingAppMask(app.id.clone()))?;
    if u16::from_str_radix(app_mask.trim(), 16).ok() != Some(device_mask) {
        return Err(PlanError::MaskMismatch {
            device: device.to_string(),
            device_mask,
            app_mask,
        });
    }
    let tables = Sys7PlanTables::from_system_b(table_images);
    plan_flash_sys7(
        app,
        device_mask,
        overrides,
        base_offsets,
        profile,
        hawk,
        &tables,
        &bussard_prod::dynamic::DynamicMemo::new(app),
    )
}

/// The model-derived inputs of a System 7 plan: the table images for LSM 1/2
/// and the flags of every linked com-object (for the descriptor CONFIG octets).
#[derive(Debug, Clone, Default)]
pub struct Sys7PlanTables {
    /// Computed table images keyed by LSM index (1 = addresses, 2 = associations).
    pub tables: BTreeMap<u32, Sys7TableImage>,
    /// The linked objects' flags, keyed by ASAP.
    pub linked_flags: BTreeMap<u16, bussard_model::Flags>,
}

impl Sys7PlanTables {
    /// Derives both from the System B table images [`plan_flash`](super::plan_flash) receives.
    pub fn from_system_b(table_images: &BTreeMap<u32, Vec<u8>>) -> Self {
        Self {
            tables: sys7_tables_from_system_b(table_images),
            linked_flags: linked_flags_from_system_b(table_images),
        }
    }
}

/// The com-object flags of every linked object, decoded from the System B
/// group-object table image (`[count:2][word per ASAP]`, see
/// `compute::group_object_word`: bit 10 C, 11 R, 12 W, 13 I, 14 T, 15 U).
/// A zero word is an unlinked ASAP and is left out.
pub fn linked_flags_from_system_b(
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> BTreeMap<u16, bussard_model::Flags> {
    use bussard_model::Flags;
    let mut out = BTreeMap::new();
    let Some(img) = table_images.get(&3).filter(|img| img.len() >= 2) else {
        return out;
    };
    for (i, w) in img[2..].as_chunks::<2>().0.iter().enumerate() {
        let word = u16::from_be_bytes([w[0], w[1]]);
        if word == 0 {
            continue;
        }
        let mut flags = Flags::empty();
        for (bit, flag) in [
            (10, Flags::COMMUNICATION),
            (11, Flags::READ),
            (12, Flags::WRITE),
            (13, Flags::INIT),
            (14, Flags::TRANSMIT),
            (15, Flags::UPDATE),
        ] {
            if word & (1 << bit) != 0 {
                flags |= flag;
            }
        }
        out.insert((i + 1) as u16, flags);
    }
    out
}

/// A computed System 7 table image bound to a table LSM's absolute segment in
/// place of the product's `<Data>` template.
///
/// `mask` (same length as `image`, `0xFF` = write, `0x00` = leave the device's
/// octet alone) skips the individual-address slot of the group-address table,
/// exactly as ETS does: it writes the count octet at the segment start and the
/// group addresses from offset 3, never the two octets in between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sys7TableImage {
    /// The table octets, from the segment start.
    pub image: Vec<u8>,
    /// Per-octet write mask, when part of the span is device-owned.
    pub mask: Option<Vec<u8>>,
}

/// Derives the System 7 table images (keyed by LSM index: 1 = group-address
/// table, 2 = association table) from the System B table images
/// [`plan_flash`](super::plan_flash) receives (keyed by object index, `[count:2 BE][elements]`
/// with 2-octet address and 4-octet `[TSAP:2][ASAP:2]` association elements).
///
/// System 7 layouts (`[system7-spec §7]`, ETS captures for 1.1.31 and 1.1.46):
///
/// ```text
/// group addresses  [CNT:1][own IA:2, device-owned][GA1:2 BE]…   CNT = 1 + n
/// associations     [CNT:1][TSAP:1][ASAP:1]…                     CNT = n
/// ```
///
/// A table that does not fit the one-octet count is left out, and the
/// lowering then keeps the product's `<Data>`; the segment-size check there
/// refuses an image longer than its segment.
pub fn sys7_tables_from_system_b(
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> BTreeMap<u32, Sys7TableImage> {
    let mut out = BTreeMap::new();
    if let Some(addr) = table_images.get(&1).filter(|img| img.len() >= 2) {
        let elements = &addr[2..];
        let n = elements.len() / 2;
        if n < usize::from(u8::MAX) {
            let mut image = Vec::with_capacity(3 + elements.len());
            image.push((n + 1) as u8);
            image.extend_from_slice(&[0, 0]);
            image.extend_from_slice(&elements[..n * 2]);
            let mut mask = vec![0xFF; image.len()];
            mask[1] = 0;
            mask[2] = 0;
            out.insert(
                1,
                Sys7TableImage {
                    image,
                    mask: Some(mask),
                },
            );
        }
    }
    if let Some(assoc) = table_images.get(&2).filter(|img| img.len() >= 2) {
        let elements = &assoc[2..];
        let n = elements.len() / 4;
        let fits = n <= usize::from(u8::MAX)
            && elements
                .as_chunks::<4>()
                .0
                .iter()
                .all(|e| e[0] == 0 && e[2] == 0);
        if fits {
            let mut image = Vec::with_capacity(1 + n * 2);
            image.push(n as u8);
            for e in elements.as_chunks::<4>().0 {
                image.push(e[1]);
                image.push(e[3]);
            }
            out.insert(2, Sys7TableImage { image, mask: None });
        }
    }
    out
}

/// The application identity every System 7 TaskSegment record carries
/// ([`bussard_mgmt::encode_task_segment`]), from `app`:
///
/// - the PEI type is `PeiType`;
/// - the manufacturer is the one in the application id (`M-00B6_A-…` gives
///   `0x00B6`), or `OriginalManufacturer` when the application declares
///   `LegacyPatchManufacturerIdInTaskSegment`;
/// - the application number and version are `ApplicationNumber` and
///   `ApplicationVersion`.
///
/// The ETS 6 captures confirm each part: the Ekinex EK-E72 (`PeiType="1"`)
/// writes `01 00 b6 45 37 03`, the Busch-Jaeger `M-0007_A-A002-13-…-O0002`
/// (`PeiType="128"`, `OriginalManufacturer="M-0002"`, the legacy option set)
/// `80 00 02 a0 02 13`, and an OEM application without the option (Zennio
/// `M-0071_A-4411-…-O00C9`) its own manufacturer, `00 00 71 44 11 10`.
///
/// An error names what is missing or out of range. The caller refuses: a
/// TaskSegment with a guessed identity can leave the device's application
/// marked as some other program.
pub fn sys7_task_identity(
    app: &ApplicationProgram,
) -> Result<bussard_mgmt::Sys7TaskIdentity, String> {
    let missing = |what: &str| {
        format!(
            "the application {} declares no {what}, which every System 7 TaskSegment record carries",
            app.id
        )
    };
    let pei_type = app.pei_type.ok_or_else(|| missing("PeiType"))?;
    let manufacturer_id = if app.legacy_patch_manufacturer_in_task_segment {
        app.original_manufacturer.as_deref().unwrap_or(&app.id)
    } else {
        &app.id
    };
    let manufacturer = super::plan::manufacturer_from_app_id(manufacturer_id)
        .ok_or_else(|| missing("manufacturer id"))?;
    let application_number = app
        .application_number
        .ok_or_else(|| missing("ApplicationNumber"))?;
    let application_number = u16::try_from(application_number).map_err(|_| {
        format!(
            "the application {} declares ApplicationNumber {application_number}, more than the TaskSegment record's two octets hold",
            app.id
        )
    })?;
    let application_version = app
        .application_version
        .ok_or_else(|| missing("ApplicationVersion"))?;
    let application_version = u8::try_from(application_version).map_err(|_| {
        format!(
            "the application {} declares ApplicationVersion {application_version}, more than the TaskSegment record's octet holds",
            app.id
        )
    })?;
    Ok(bussard_mgmt::Sys7TaskIdentity {
        pei_type,
        manufacturer,
        application_number,
        application_version,
    })
}

/// Maps an `LdCtrlAbsSegment` `SegFlags` attribute to the allocation record's
/// memory-attributes octet (bit 7 checksum control): `128` → `0x80`
/// (checksum-controlled), `0` → `0x00` (runtime-writable). Any other value is
/// passed through when it fits an octet.
pub(super) fn seg_flags_octet(seg_flags: Option<u32>) -> Option<u8> {
    seg_flags.and_then(|f| u8::try_from(f).ok())
}

/// Derives a [`bussard_mgmt::Sys7Profile`] from a mask's parsed
/// `HawkConfigurationData` (`[system7-spec §2.4/§5]`).
///
/// Reads the `GroupAddressTableLoadControl` (the LSM control address + record
/// length) and `GroupAddressTableLoadStatus` (the status base) resources, and
/// the `VerifyMode` feature ([`bussard_mgmt::Sys7Profile::verify_mode`]). A
/// `Flavour="LoadControl_M112"` LoadControl in `StandardMemory` selects
/// [`bussard_mgmt::LsmRealisation::MemoryMapped`] with the resolved addresses;
/// absent that, `None` (the caller falls back to the corpus default — property).
///
/// **M2 caveat (issue #70).** The Jung MV-0705 block resolves to control `0x0104`
/// / status `0xB6EA`, but the M2 live capture proved the Jung device does NOT
/// drive its LSM there: load control is property-based (`A_PropertyValue_Write`
/// PID 5), and the only `0xB6EA+` touch is a single `A_Memory_Read` at `0xB6EC`
/// (a *readable* status region). So the `LoadControl_M112 @ 0x0104` block did not
/// predict the wire for Jung. The normal CLI flash path therefore does NOT feed a
/// Hawk config here (it plans with the property corpus default); this helper stays
/// for the data-driven memory-mapped conformance harness and for any 0705 silicon
/// a future capture proves genuinely memory-mapped.
pub fn sys7_profile_from_hawk(
    hawk: &bussard_prod::HawkConfig,
) -> Option<bussard_mgmt::Sys7Profile> {
    let control = hawk.resource("GroupAddressTableLoadControl")?;
    // Only the memory-mapped M112 LoadControl is data-driven here; a property
    // realisation would carry a SystemProperty address space instead.
    let control_addr = match (control.address_space.as_deref(), control.start_address) {
        (Some("StandardMemory"), Some(addr)) => u16::try_from(addr).ok()?,
        _ => return None,
    };
    let status_addr = hawk
        .resource("GroupAddressTableLoadStatus")
        .and_then(|s| s.start_address)
        .and_then(|a| u16::try_from(a).ok())
        .unwrap_or(0xB6EA);
    let mut profile = bussard_mgmt::Sys7Profile::corpus_default();
    profile.lsm = bussard_mgmt::LsmRealisation::MemoryMapped {
        control_addr,
        status_addr,
    };
    profile.verify_mode = hawk.verify_mode();
    Some(profile)
}

/// The mem-type for a System 7 absolute-segment allocation at `addr`: RAM (`2`)
/// for the low-RAM working region (`0x0700`/`0x0730` ≤ addr < `0x4000`), EEPROM
/// (`3`) for the table/param regions (`[system7-spec §4.2]`).
pub(super) fn mem_type_for_addr(addr: u32, profile: &bussard_mgmt::Sys7Profile) -> u8 {
    if addr < 0x4000 {
        profile.ram_mem_type
    } else {
        profile.eeprom_mem_type
    }
}

/// A human label for a System 7 op that this engine cannot lower.
pub(super) fn sys7_op_label(op: &LoadOp) -> String {
    match op {
        LoadOp::Raw { name, .. } => name.clone(),
        LoadOp::WriteMem { .. } => "LdCtrlWriteMem (not in the System 7 corpus)".to_string(),
        LoadOp::RelSegment { .. } => {
            "LdCtrlRelSegment (System 7 is absolute-addressed)".to_string()
        }
        LoadOp::WriteRelMem { .. } => {
            "LdCtrlWriteRelMem (System 7 is absolute-addressed)".to_string()
        }
        LoadOp::WriteProp { .. } => "LdCtrlWriteProp (not in the System 7 corpus)".to_string(),
        LoadOp::MasterReset { .. } => "LdCtrlMasterReset (not in the System 7 corpus)".to_string(),
        LoadOp::MapError { .. } => "LdCtrlMapError (not in the System 7 corpus)".to_string(),
        other => format!("{other:?}"),
    }
}

/// Where a System 7 product places its link tables: the address the
/// application's own procedure allocates for LSM 1 (address table, followed by
/// the group-object table) and LSM 2 (association table). `None` where the
/// procedure allocates no absolute segment on that LSM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sys7TableBases {
    /// The LSM 1 region (the address table).
    pub address: Option<u16>,
    /// The LSM 2 region (the association table) as the product declares it.
    /// When [`Self::packed_end`] is set, the association table is not here
    /// but directly behind the address table.
    pub association: Option<u16>,
    /// Set when the product declares `DynamicTableManagement` and its two
    /// table segments are contiguous: ETS allocates the address table at its
    /// own length and the association table right behind it (issue #383), so
    /// the association table's base follows from the address table's length.
    /// The value is where the product's LSM 2 segment ends (exclusive), the
    /// end of both tables. `None` for static table segments.
    pub packed_end: Option<u16>,
    /// The application identity a table write's TaskSegment records carry
    /// ([`sys7_task_identity`]); `None` without product data, or when the
    /// product lacks part of it.
    pub task_identity: Option<bussard_mgmt::Sys7TaskIdentity>,
    /// The size of the LSM 1 segment the procedure allocates: the most octets
    /// the address table may take. The Ekinex EK-E72 (`M-00B6_A-4537-03`)
    /// allocates 237 octets at `0x4000` and puts its association table at
    /// `0x40ED`, right behind.
    pub address_size: Option<u16>,
    /// The size of the LSM 2 segment the procedure allocates: the most octets
    /// the association table may take (the EK-E72: 235 at `0x40ED`).
    pub association_size: Option<u16>,
    /// The absolute address of the group-object table the program declares
    /// (`<ComObjectTable CodeSegment Offset>` in an absolute segment). A System 7
    /// program keeps it in its own application segment, never behind the
    /// address table: the EK-E72 at `0x41D8`, the Jung `A-2088` at `0x43FF`.
    pub object_table: Option<u16>,
}

/// The first `LdCtrlAbsSegment` (address, size) `app`'s procedure allocates on
/// LSM 1 and on LSM 2.
fn table_allocations(app: &ApplicationProgram) -> [Option<(u32, u32)>; 2] {
    // Every branch of every block, read without a configuration: no corpus
    // program allocates inside a `<choose>` (issue #402).
    let ops = super::plan::self_contained_blocks(app)
        .into_iter()
        .flat_map(|p| p.ops.iter());
    let alloc = |lsm: u32| {
        ops.clone().find_map(|op| match op {
            LoadOp::AbsSegment {
                lsm_idx: Some(l),
                address: Some(a),
                size,
                ..
            } if *l == lsm => Some((*a, size.unwrap_or(0))),
            _ => None,
        })
    };
    [alloc(1), alloc(2)]
}

/// A table segment's size as a bound: unknown when the procedure gives none
/// (a missing `Size` reads as 0) or one past 16 bits.
fn segment_size(alloc: Option<(u32, u32)>) -> Option<u16> {
    alloc
        .and_then(|(_, size)| u16::try_from(size).ok())
        .filter(|size| *size > 0)
}

/// Whether ETS packs `app`'s tables (see [`Sys7TableBases::packed_end`]): the
/// application declares `DynamicTableManagement` and its LSM 2 segment starts
/// where its LSM 1 segment ends. The corpus holds 29 System 7 programs with
/// the attribute (of 332); the 28 that allocate both table segments all have
/// that contiguous shape. A non-contiguous one keeps the product's addresses,
/// as no capture shows what ETS does with it.
fn packs_tables(app: &ApplicationProgram, allocs: &[Option<(u32, u32)>; 2]) -> bool {
    match allocs {
        [Some((a1, s1)), Some((a2, _))] => app.dynamic_table_management && a1 + s1 == *a2,
        _ => false,
    }
}

/// The table bases `app`'s System 7 load procedure allocates
/// (`LdCtrlAbsSegment` on LSM 1 and 2, the first of each). The corpus default
/// `0x4000` / `0x4201` is common but not universal: the Jung and Siemens 0705
/// programs put the association table at `0x41FF`, the Elsner
/// `M-00B6_A-4548-01` at `0x41D5`, the MDT `M-0083_A-0041-14` (0701) at
/// `0x4041`, the Zennio 0701 programs at `0x4200`. The table reader falls back
/// to these when the device does not answer `PID_TABLE_REFERENCE`, as ETS
/// takes them from the product. With `DynamicTableManagement` the association
/// table follows the address table instead ([`Sys7TableBases::packed_end`]).
pub fn sys7_table_bases(app: &ApplicationProgram) -> Sys7TableBases {
    let allocs = table_allocations(app);
    let base = |i: usize| allocs[i].and_then(|(a, _)| u16::try_from(a).ok());
    let packed_end = match allocs {
        [_, Some((a2, s2))] if packs_tables(app, &allocs) => {
            a2.checked_add(s2).and_then(|end| u16::try_from(end).ok())
        }
        _ => None,
    };
    Sys7TableBases {
        address: base(0),
        association: base(1),
        packed_end,
        task_identity: sys7_task_identity(app).ok(),
        address_size: segment_size(allocs[0]),
        association_size: segment_size(allocs[1]),
        object_table: declared_object_table(app),
    }
}

/// The absolute address of the group-object table `app` declares, when its
/// `<ComObjectTable>` names an absolute segment.
fn declared_object_table(app: &ApplicationProgram) -> Option<u16> {
    let table = app.com_object_table.as_ref()?;
    let segment = app.code_segments.get(&table.code_segment)?;
    if segment.kind != SegmentKind::Absolute {
        return None;
    }
    let at = segment.address_or_offset?.checked_add(table.offset)?;
    u16::try_from(at).ok()
}

/// The two table segments ETS allocates for a System 7 product with
/// `DynamicTableManagement` (issue #383).
///
/// The rule, from the ETS 6.4 download of the Jung `M-0004_A-2088-11`
/// (product: LSM 1 `0x4000`/511, LSM 2 `0x41FF`/511, next segment `0x43FF`):
/// ETS allocated LSM 1 at `0x4000` with size 31, the address table's length
/// with its count octet and own-address slot (15 entries), and LSM 2 at
/// `0x401F` with size 991, so the association table ends at `0x43FE`, where
/// the product's LSM 2 segment ends (not at the next segment, `0x43FF`). The
/// two segments together keep the product's span; the address table gives
/// up what it does not use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sys7PackedTables {
    /// The address table's base: the product's LSM 1 address.
    pub address: u32,
    /// The address table's segment size: the table's own length.
    pub address_size: u32,
    /// The product's LSM 2 address, which the association table leaves.
    pub static_association: u32,
    /// The association table's base: right behind the address table.
    pub association: u32,
    /// Its segment size: up to the end of the product's LSM 2 segment.
    pub association_size: u32,
}

/// The packed table layout of `app` for an address table of
/// `address_table_len` octets, or `None` when ETS uses the product's static
/// segments (no `DynamicTableManagement`, non-contiguous segments) or the
/// table does not leave room for the association table.
pub(crate) fn sys7_packed_tables(
    app: &ApplicationProgram,
    address_table_len: usize,
) -> Option<Sys7PackedTables> {
    let allocs = table_allocations(app);
    if !packs_tables(app, &allocs) {
        return None;
    }
    let [Some((a1, _)), Some((a2, s2))] = allocs else {
        return None;
    };
    let end = a2.checked_add(s2)?;
    let len = u32::try_from(address_table_len).ok().filter(|l| *l > 0)?;
    let association = a1.checked_add(len).filter(|b| *b < end)?;
    Some(Sys7PackedTables {
        address: a1,
        address_size: len,
        static_association: a2,
        association,
        association_size: end - association,
    })
}

/// Parses an `LdCtrlCompareMem` raw op's `Address`, `InlineData` and `Size`
/// attributes (`[system7-spec §4.5]`). Returns `(address, expected_bytes)`.
///
/// `Size` is the number of octets compared: the Zennio 0701 programs
/// (`M-0071_A-1231-22`, `M-0071_A-3222-11`) pad `InlineData` to 11 octets with
/// zeros behind a `Size` of 3 or 2, and the device holds other data past the
/// compared octets. A `Size` larger than `InlineData` is not shortened.
pub(super) fn parse_compare_mem(attrs: &[(String, String)]) -> Option<(u32, Vec<u8>)> {
    let mut address: Option<u32> = None;
    let mut inline: Option<Vec<u8>> = None;
    let mut size: Option<usize> = None;
    for (k, v) in attrs {
        match k.as_str() {
            "Address" => address = v.trim().parse().ok(),
            "InlineData" => inline = decode_hex(v),
            "Size" => size = v.trim().parse().ok(),
            _ => {}
        }
    }
    let mut expected = inline?;
    if let Some(size) = size
        && size < expected.len()
    {
        expected.truncate(size);
    }
    Some((address?, expected))
}

/// Decodes an even-length hex string (e.g. an `InlineData` attribute) into bytes;
/// `None` on odd length or a non-hex digit.
pub(super) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::plan::plan_flash;

    #[test]
    fn test_parse_compare_mem_compares_size_octets() -> Result<(), Box<dyn std::error::Error>> {
        let attrs = |size: &str| {
            vec![
                ("Address".to_string(), "46608".to_string()),
                ("Size".to_string(), size.to_string()),
                (
                    "InlineData".to_string(),
                    "5212300000000000000000".to_string(),
                ),
            ]
        };
        let (address, expected) = parse_compare_mem(&attrs("3")).ok_or("not parsed")?;
        assert_eq!(address, 0xB610);
        assert_eq!(expected, vec![0x52, 0x12, 0x30]);
        // A Size past the inline data keeps what is there.
        let (_, expected) = parse_compare_mem(&attrs("20")).ok_or("not parsed")?;
        assert_eq!(expected.len(), 11);
        Ok(())
    }
    use crate::flash::test_support::no_overrides;
    use bussard_prod::application::parse_application_program;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use bussard_prod::application::ApplicationProgram;

    /// Issue #386, 1.1.44 (ABB 6119/20, `A-A002`, mask 0701): the program
    /// declares its descriptor table at `AS-43FE` + 0, the pointers are
    /// little-endian and name controller RAM the plan does not allocate, so
    /// only the declaration finds it. With no links, ETS wrote the visible
    /// objects 0 and 1 with their refs' flags and C cleared (`13`, `53`) and
    /// cleared C on the template of the rest (`df` became `db`).
    #[test]
    fn test_apply_sys7_group_object_links_uses_the_declared_table() {
        use bussard_model::Flags;
        let seg_id = "M-0007_A-A002-13-73C8-O0002_AS-43FE".to_string();
        let steps = vec![FlashStep::Sys7AbsSegment {
            lsm: 3,
            address: 0x43FE,
            size: 123,
            mem_type: 3,
            access: 0x80,
            seg_flags: 0x00,
            seg_type: 0,
            image: Some(ImageRef {
                segment_id: seg_id.clone(),
                kind: ImageKind::Code,
                len: 15,
                offset: 0,
            }),
        }];
        // The product's first three descriptors, CNT cut to 3.
        let template = vec![
            0x03, 0x60, 0x04, 0x7E, 0x04, 0xDF, 0x00, 0x7F, 0x04, 0xDF, 0x00, 0x83, 0x04, 0xDF,
            0x00,
        ];
        let defaults = BTreeMap::from([
            (
                0,
                Sys7ObjectDefault {
                    flags: Flags::WRITE | Flags::COMMUNICATION,
                    type_code: None,
                    priority: None,
                },
            ),
            (
                1,
                Sys7ObjectDefault {
                    flags: Flags::TRANSMIT | Flags::WRITE | Flags::COMMUNICATION,
                    type_code: None,
                    priority: None,
                },
            ),
        ]);
        let run_with = |declared: Option<&TableLocation>,
                        defaults: &BTreeMap<u16, Sys7ObjectDefault>| {
            let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);
            apply_sys7_group_object_links(
                &steps,
                &mut images,
                declared,
                &BTreeSet::new(),
                &BTreeMap::new(),
                defaults,
                None,
            );
            images.remove(&seg_id).unwrap_or_default()
        };
        let run = |declared: Option<&TableLocation>| run_with(declared, &defaults);
        // The shape finder alone does not see it: no RAM segment in the plan.
        assert_eq!(sys7_group_object_table(&steps, &BTreeMap::new()), None);
        assert_eq!(run(None), template);
        let declared = TableLocation {
            code_segment: seg_id.clone(),
            offset: 0,
        };
        assert_eq!(
            run(Some(&declared)),
            vec![
                0x03, 0x60, 0x04, 0x7E, 0x04, 0x13, 0x00, 0x7F, 0x04, 0x53, 0x00, 0x83, 0x04, 0xDB,
                0x00
            ]
        );
        // A declared priority replaces the template's in bits 1-0 (issue
        // #541): `High` is the standard's normal (`01`), `Alert` urgent
        // (`10`); a declared `Low` keeps `11`.
        let mut prioritised = defaults.clone();
        for (asap, priority) in [
            (0, bussard_model::Priority::Low),
            (1, bussard_model::Priority::High),
        ] {
            if let Some(d) = prioritised.get_mut(&asap) {
                d.priority = Some(priority);
            }
        }
        prioritised.insert(
            2,
            Sys7ObjectDefault {
                flags: Flags::TRANSMIT,
                type_code: None,
                priority: Some(bussard_model::Priority::Alarm),
            },
        );
        assert_eq!(
            run_with(Some(&declared), &prioritised),
            vec![
                0x03, 0x60, 0x04, 0x7E, 0x04, 0x13, 0x00, 0x7F, 0x04, 0x51, 0x00, 0x83, 0x04, 0x42,
                0x00
            ]
        );
        // A declaration the image cannot hold falls back to the shape finder.
        let past_end = TableLocation {
            code_segment: seg_id.clone(),
            offset: 4,
        };
        assert_eq!(run(Some(&past_end)), template);
    }

    /// The System 7 group-object post-pass: the communication flag follows the
    /// association table (1.1.31: no links, none set; 1.1.46: exactly the
    /// linked ASAPs), everything else in the descriptor is left alone.
    #[test]
    fn test_apply_sys7_group_object_links_follows_the_association_table() {
        let seg_id = "M-0004_A-A011-13-60BC-O000A_AS-43FF".to_string();
        let steps = vec![
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x0700,
                size: 450,
                mem_type: 2,
                access: 0xF2,
                seg_flags: 0x00,
                seg_type: 0,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FF,
                size: 811,
                mem_type: 3,
                access: 0xF2,
                seg_flags: 0x80,
                seg_type: 0,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
                    offset: 0,
                }),
            },
        ];
        // [CNT=3][RAM flags 0x07F9] then three descriptors with the vendor
        // template's communication flag set on every one.
        let template = vec![
            0x03, 0x07, 0xF9, 0x07, 0x00, 0x17, 0x00, 0x07, 0x01, 0x4F, 0x08, 0x07, 0x03, 0x17,
            0x08,
        ];
        let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);

        // No links: ETS clears the flag everywhere (the 1.1.31 capture).
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        );
        assert_eq!(
            images[&seg_id],
            vec![
                0x03, 0x07, 0xF9, 0x07, 0x00, 0x13, 0x00, 0x07, 0x01, 0x4B, 0x08, 0x07, 0x03, 0x13,
                0x08
            ]
        );

        // ASAP 1 linked: only descriptor 1 carries the flag.
        let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);
        let linked = sys7_linked_asaps(&[0x01, 0x02, 0x01]);
        assert_eq!(linked, BTreeSet::from([1]));
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            None,
            &linked,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        );
        assert_eq!(images[&seg_id][5], 0x13);
        assert_eq!(images[&seg_id][9], 0x4F);
        assert_eq!(images[&seg_id][13], 0x13);

        // With the project's flags known, the linked descriptor takes them
        // (1.1.46: template `df` became `4f` = T R C, low priority kept).
        let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);
        let mut flags = BTreeMap::new();
        flags.insert(
            1u16,
            bussard_model::Flags::COMMUNICATION
                | bussard_model::Flags::READ
                | bussard_model::Flags::TRANSMIT,
        );
        let mut tmpl = template.clone();
        tmpl[9] = 0xDF;
        let mut images_df = BTreeMap::from([(seg_id.clone(), tmpl)]);
        apply_sys7_group_object_links(
            &steps,
            &mut images_df,
            None,
            &linked,
            &flags,
            &BTreeMap::new(),
            None,
        );
        assert_eq!(images_df[&seg_id][9], 0x4F);
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            None,
            &linked,
            &flags,
            &BTreeMap::new(),
            None,
        );
        assert_eq!(images[&seg_id][9], 0x4F);

        // A segment that does not look like the descriptor table is untouched.
        let odd = vec![0xFF; 15];
        let mut images = BTreeMap::from([(seg_id.clone(), odd.clone())]);
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            None,
            &BTreeSet::from([1]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        );
        assert_eq!(images[&seg_id], odd);
    }

    /// Issue #126, 1.1.1 (2116REG): object 0 is linked and takes the
    /// project's T W R C (`47` became `5f`), and the template slots past the
    /// highest declared object keep their `17` (ETS only rewrites descriptors up
    /// to the last com-object `Number`).
    /// Issue #355: the identity sample's segments are the code alone, never a
    /// link table, RAM, parameter memory or the group-object descriptor
    /// table (the Meteodata's `AS-4400`, whose CONFIG octets follow the
    /// configuration).
    #[test]
    fn test_sys7_code_segments_never_picks_a_table_or_parameter_segment() {
        let seg = |lsm: u32, address: u32, mem_type: u8, seg_flags: u8, id: &str, kind| {
            FlashStep::Sys7AbsSegment {
                lsm,
                address,
                size: 16,
                mem_type,
                access: 0xF2,
                seg_flags,
                seg_type: 0,
                image: Some(ImageRef {
                    segment_id: id.to_string(),
                    kind,
                    len: 16,
                    offset: 0,
                }),
            }
        };
        let steps = vec![
            seg(1, 0x4000, 3, 0x80, "AS-4000", ImageKind::Table),
            seg(2, 0x4201, 3, 0x80, "AS-4201", ImageKind::Table),
            // The RAM the descriptors point into (the Meteodata's AS-1C00).
            seg(3, 0x1C00, 2, 0x00, "AS-1C00", ImageKind::Code),
            seg(3, 0x4400, 3, 0x80, "AS-4400", ImageKind::Code),
            seg(3, 0x4800, 3, 0x00, "AS-4800", ImageKind::Code),
            seg(3, 0x4C00, 3, 0x80, "AS-4C00", ImageKind::Code),
            seg(3, 0x5000, 3, 0x80, "AS-5000", ImageKind::Code),
            seg(3, 0x5400, 3, 0x80, "AS-5400", ImageKind::Code),
        ];
        // [CNT=2][RAM flags 0x1C00] and two descriptors pointing into RAM.
        let object_table = vec![
            0x02, 0x1C, 0x00, 0x1C, 0x01, 0x4F, 0x00, 0x1C, 0x02, 0x4B, 0x00,
        ];
        let images: BTreeMap<String, Vec<u8>> = [
            "AS-4000", "AS-4201", "AS-1C00", "AS-4800", "AS-4C00", "AS-5000", "AS-5400",
        ]
        .iter()
        .map(|id| ((*id).to_string(), vec![0xAA; 16]))
        .chain([("AS-4400".to_string(), object_table)])
        .collect();
        assert_eq!(
            sys7_group_object_table(&steps, &images).as_deref(),
            Some("AS-4400")
        );
        // AS-4C00 carries a parameter image, AS-5000 a placed parameter only.
        let param_images = BTreeMap::from([("AS-4C00".to_string(), vec![1u8; 16])]);
        let placed = BTreeMap::from([("AS-5000".to_string(), BTreeSet::from([3usize]))]);
        let code = sys7_code_segments(&steps, &images, None, &param_images, &placed);
        assert_eq!(code, BTreeSet::from(["AS-5400".to_string()]));

        // Without AS-5400 nothing is code: the gate falls back to the load
        // state (the Meteodata 140 S).
        let code = sys7_code_segments(&steps[..7], &images, None, &param_images, &placed);
        assert!(code.is_empty(), "{code:?}");
    }

    #[test]
    fn test_apply_sys7_group_object_links_object_zero_and_trailing_slots() {
        use bussard_model::Flags;
        let seg_id = "M-0004_A-7066-11-94AD-O000A_AS-43FE".to_string();
        let steps = vec![
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x0700,
                size: 450,
                mem_type: 2,
                access: 0xF2,
                seg_flags: 0x00,
                seg_type: 0,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FE,
                size: 883,
                mem_type: 3,
                access: 0xF2,
                seg_flags: 0x80,
                seg_type: 0,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
                    offset: 0,
                }),
            },
        ];
        // The 2116REG template head: [CNT][RAM flags 0x0835], descriptor 0
        // `0702 47 00`, then two `17` slots standing in for 127 and 128.
        let template = vec![
            0x03, 0x08, 0x35, 0x07, 0x02, 0x47, 0x00, 0x08, 0x18, 0x17, 0x00, 0x08, 0x19, 0x17,
            0x00,
        ];
        let mut images = BTreeMap::from([(seg_id.clone(), template)]);
        let flags = BTreeMap::from([(
            0u16,
            Flags::COMMUNICATION | Flags::READ | Flags::WRITE | Flags::TRANSMIT,
        )]);
        apply_sys7_group_object_links(
            &steps,
            &mut images,
            None,
            &BTreeSet::from([0]),
            &flags,
            &BTreeMap::new(),
            Some(0),
        );
        assert_eq!(
            images[&seg_id],
            vec![
                0x03, 0x08, 0x35, 0x07, 0x02, 0x5F, 0x00, 0x08, 0x18, 0x17, 0x00, 0x08, 0x19, 0x17,
                0x00
            ]
        );
    }

    /// Issue #117: the unlinked System 7 descriptors take the ComObjectRef the
    /// parameter values make visible. Object 0 has two refs behind a
    /// `<choose>` (T R, 1 bit / W, 2 bytes), object 1 is always shown, object
    /// 2 only under a branch that is not taken, so it keeps the template with C
    /// cleared. The bytes follow the 3361-1MWW capture (`df`/`0b` became
    /// `4b`, `13` or `db`).
    #[test]
    fn test_apply_sys7_group_object_links_takes_the_visible_ref()
    -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram PeiType="0" Id="A" MaskVersion="MV-0705" Name="s7dyn">
          <Static>
           <Parameters><Parameter Id="A_P-1" Name="type" Value="0" /></Parameters>
           <ParameterRefs><ParameterRef Id="A_P-1_R-1" RefId="A_P-1" /></ParameterRefs>
           <ComObjects>
            <ComObject Id="A_O-0" Number="0" ObjectSize="1 Bit" />
            <ComObject Id="A_O-1" Number="1" ObjectSize="1 Byte" />
            <ComObject Id="A_O-2" Number="2" ObjectSize="1 Bit" />
           </ComObjects>
           <ComObjectRefs>
            <ComObjectRef Id="A_O-0_R-1" RefId="A_O-0" TransmitFlag="Enabled" ReadFlag="Enabled" CommunicationFlag="Enabled" />
            <ComObjectRef Id="A_O-0_R-2" RefId="A_O-0" ObjectSize="2 Bytes" WriteFlag="Enabled" CommunicationFlag="Enabled" />
            <ComObjectRef Id="A_O-1_R-3" RefId="A_O-1" WriteFlag="Enabled" CommunicationFlag="Enabled" />
            <ComObjectRef Id="A_O-2_R-4" RefId="A_O-2" TransmitFlag="Enabled" CommunicationFlag="Enabled" />
           </ComObjectRefs>
          </Static>
          <Dynamic>
           <ChannelIndependentBlock>
            <ParameterBlock Id="A_PB-1" Name="main">
             <ParameterRefRef RefId="A_P-1_R-1" />
             <ComObjectRefRef RefId="A_O-1_R-3" />
             <choose ParamRefId="A_P-1_R-1">
              <when test="0"><ComObjectRefRef RefId="A_O-0_R-1" /></when>
              <when test="1"><ComObjectRefRef RefId="A_O-0_R-2" /></when>
              <when test="2"><ComObjectRefRef RefId="A_O-2_R-4" /></when>
             </choose>
            </ParameterBlock>
           </ChannelIndependentBlock>
          </Dynamic>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("A", xml.as_bytes())?;
        let seg_id = "A_AS-43FF".to_string();
        let steps = vec![
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x0700,
                size: 16,
                mem_type: 2,
                access: 0xF2,
                seg_flags: 0x00,
                seg_type: 0,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FF,
                size: 15,
                mem_type: 3,
                access: 0xF2,
                seg_flags: 0x80,
                seg_type: 0,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
                    offset: 0,
                }),
            },
        ];
        // [CNT=3][RAM flags 0x070F][ptr CONFIG TYPE] x3, the template's C set.
        let template = vec![
            0x03, 0x07, 0x0F, 0x07, 0x00, 0xDF, 0x00, 0x07, 0x01, 0xDF, 0x07, 0x07, 0x02, 0xDF,
            0x00,
        ];
        let run = |value: &str| {
            let overrides = BTreeMap::from([("P-1_R-1".to_string(), value.to_string())]);
            let config = bussard_prod::dynamic::evaluate_dynamic(&app, &overrides);
            let defaults = sys7_object_defaults(&app, &config);
            let mut images = BTreeMap::from([(seg_id.clone(), template.clone())]);
            apply_sys7_group_object_links(
                &steps,
                &mut images,
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &defaults,
                None,
            );
            images.remove(&seg_id).unwrap_or_default()
        };
        // Type 0: object 0 shows R-1 (T R), object 2 is hidden.
        assert_eq!(
            run("0"),
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0x4B, 0x00, 0x07, 0x01, 0x13, 0x07, 0x07, 0x02, 0xDB,
                0x00
            ]
        );
        // Type 1: object 0 shows R-2 (W, 2 bytes: TYPE 8).
        assert_eq!(
            run("1"),
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0x13, 0x08, 0x07, 0x01, 0x13, 0x07, 0x07, 0x02, 0xDB,
                0x00
            ]
        );
        // Type 2: object 0 is hidden, object 2 shows R-4 (T).
        assert_eq!(
            run("2"),
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0xDB, 0x00, 0x07, 0x01, 0x13, 0x07, 0x07, 0x02, 0x43,
                0x00
            ]
        );
        Ok(())
    }
    /// A System 7 (0701) app whose LSM 3 segment `AS-43FF` carries a three-slot
    /// descriptor table (template C set, `df`) that `<ComObjectTable>` names;
    /// `objects` goes into `<Static>` and `dynamic` is the Dynamic section.
    fn sys7_descriptor_app(
        objects: &str,
        dynamic: &str,
    ) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="A" ApplicationNumber="1" ApplicationVersion="16"
            MaskVersion="MV-0701" Name="Descriptors" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="A_AS-43FF" Size="15" Address="17407"><Data>AwcPBwDfAAcB3wcHAt8A</Data></AbsoluteSegment>
           </Code>
           <ParameterTypes><ParameterType Id="A_PT-1" Name="t"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="1" /></ParameterType></ParameterTypes>
           <Parameters><Parameter Id="A_P-1" Name="enable" ParameterType="A_PT-1" Value="0" /></Parameters>
           <ParameterRefs><ParameterRef Id="A_P-1_R-1" RefId="A_P-1" /></ParameterRefs>
           {objects}
           <ComObjectTable CodeSegment="A_AS-43FF" Offset="0" />
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17407" Size="15" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
          {dynamic}
         </ApplicationProgram></KNX>"#
        );
        Ok(parse_application_program("A", xml.as_bytes())?)
    }

    fn plan_descriptor_table(
        app: &ApplicationProgram,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let plan = plan_flash(
            app,
            "1.1.99",
            0x0701,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        Ok(plan
            .image_bytes("A_AS-43FF")
            .map(<[u8]>::to_vec)
            .unwrap_or_default())
    }

    /// Issue #475 (COMIP2 `M-00E1_A-A00D-10-12FB-O00C5`): an application that
    /// declares no com-object, no module object and no link writes the
    /// descriptor table as the template has it, C kept on every slot.
    #[test]
    fn test_plan_flash_sys7_template_only_table_keeps_the_template()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = sys7_descriptor_app("", "")?;
        assert_eq!(
            plan_descriptor_table(&app)?,
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0xDF, 0x00, 0x07, 0x01, 0xDF, 0x07, 0x07, 0x02, 0xDF,
                0x00
            ]
        );
        Ok(())
    }

    /// Issue #562 (ABB `A-A04C-13-0D6B`): the Dynamic section declares the
    /// objects, but at the defaults the walk reaches none. ETS writes every
    /// descriptor as the template with C cleared, not the refs' flags.
    #[test]
    fn test_plan_flash_sys7_unreached_objects_keep_the_template_without_c()
    -> Result<(), Box<dyn std::error::Error>> {
        let objects = r#"<ComObjects>
            <ComObject Id="A_O-0" Number="0" ObjectSize="1 Bit" TransmitFlag="Enabled" ReadFlag="Enabled" CommunicationFlag="Enabled" />
            <ComObject Id="A_O-1" Number="1" ObjectSize="1 Bit" WriteFlag="Enabled" CommunicationFlag="Enabled" />
           </ComObjects>
           <ComObjectRefs>
            <ComObjectRef Id="A_O-0_R-1" RefId="A_O-0" />
            <ComObjectRef Id="A_O-1_R-2" RefId="A_O-1" />
           </ComObjectRefs>"#;
        let dynamic = r#"<Dynamic>
           <ChannelIndependentBlock>
            <ParameterBlock Id="A_PB-1" Name="main">
             <ParameterRefRef RefId="A_P-1_R-1" />
             <choose ParamRefId="A_P-1_R-1">
              <when test="1"><ComObjectRefRef RefId="A_O-0_R-1" /><ComObjectRefRef RefId="A_O-1_R-2" /></when>
             </choose>
            </ParameterBlock>
           </ChannelIndependentBlock>
          </Dynamic>"#;
        let app = sys7_descriptor_app(objects, dynamic)?;
        // Objects 0 and 1 are declared: `df & !C` = `db`; slot 2 lies past
        // the last declared object and keeps the template.
        assert_eq!(
            plan_descriptor_table(&app)?,
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0xDB, 0x00, 0x07, 0x01, 0xDB, 0x07, 0x07, 0x02, 0xDF,
                0x00
            ]
        );
        // Without a Dynamic section the flat defaults still apply: the refs'
        // flags (T R, W) with C cleared.
        let flat = sys7_descriptor_app(objects, "")?;
        assert_eq!(
            plan_descriptor_table(&flat)?,
            vec![
                0x03, 0x07, 0x0F, 0x07, 0x00, 0x4B, 0x00, 0x07, 0x01, 0x13, 0x07, 0x07, 0x02, 0xDF,
                0x00
            ]
        );
        Ok(())
    }

    /// A fabricated System 7 (mask 0705) app in the MDT canonical LSM 1/2/3 shape
    /// (`[system7-spec §3]`): obj0/PID78 preflight, three LSMs, an AbsSegment with
    /// a per-byte `<Mask>` on LSM 1, an allocate-only RAM segment on LSM 3, a
    /// TaskSegment per LSM, a restart.
    fn fabricated_sys7_app() -> ApplicationProgram {
        // Segment images (base64): AS-1 = 4 bytes of table data at 0x4000 (mask
        // FF FF 00 FF -> byte 2 is device-owned); AS-3 = 2 bytes of param at
        // 0x4400; AS-2 (0x0700) is allocate-only (no <Data>).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0083_A-E" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0083_A-E_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data><Mask>//8A/w==</Mask></AbsoluteSegment>
            <AbsoluteSegment Id="M-0083_A-E_AS-2" Size="8" Address="1792" />
            <AbsoluteSegment Id="M-0083_A-E_AS-3" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlCompareProp ObjIdx="0" PropId="78" InlineData="00000000031200000000" />
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlUnload LsmIdx="2" />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="4" />
             <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="1792" Size="8" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
             <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        parse_application_program("M-0083_A-E", xml.as_bytes()).expect("the fixture app parses")
    }

    /// A minimal System 7 app whose single `LdCtrlAbsSegment` carries the given
    /// LSM index, address and size — the knobs issue #81's range checks guard.
    fn sys7_app_with(lsm: u32, address: u32, size: u32) -> ApplicationProgram {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0083_A-F" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7Range" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code />
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlLoad LsmIdx="{lsm}" />
             <LdCtrlAbsSegment LsmIdx="{lsm}" Address="{address}" Size="{size}" />
             <LdCtrlLoadCompleted LsmIdx="{lsm}" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        parse_application_program("M-0083_A-F", xml.as_bytes()).expect("the fixture app parses")
    }

    /// A minimal System 7 app with a data segment and a stack segment on LSM 3,
    /// the second carrying `SegType="{seg_type}"` (issue #487).
    fn sys7_app_with_seg_type(
        seg_type: &str,
    ) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0083_A-G" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7Stack" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code />
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="1792" Size="8" MemType="2" />
             <LdCtrlAbsSegment LsmIdx="3" Address="2038" Size="1" Access="0" MemType="2" SegFlags="0" SegType="{seg_type}" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        Ok(parse_application_program("M-0083_A-G", xml.as_bytes())?)
    }

    #[test]
    fn test_plan_flash_sys7_stack_segment_keeps_seg_type() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = plan_flash(
            &sys7_app_with_seg_type("1")?,
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let seg_types: Vec<(u32, u8)> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Sys7AbsSegment {
                    address, seg_type, ..
                } => Some((*address, *seg_type)),
                _ => None,
            })
            .collect();
        assert_eq!(
            seg_types,
            vec![
                (0x0700, bussard_mgmt::sys7::S7_SUB_ALLOC_DATA),
                (0x07F6, bussard_mgmt::sys7::S7_SUB_ALLOC_STACK)
            ]
        );
        Ok(())
    }

    #[test]
    fn test_plan_flash_sys7_unknown_seg_type_refuses() -> Result<(), Box<dyn std::error::Error>> {
        let err = plan_flash(
            &sys7_app_with_seg_type("2")?,
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        );
        assert!(
            matches!(&err, Err(PlanError::UnresolvableImage { reason, .. }) if reason.contains("SegType 2")),
            "{err:?}"
        );
        Ok(())
    }

    fn plan_sys7_range(
        lsm: u32,
        address: u32,
        size: u32,
    ) -> std::result::Result<FlashPlan, PlanError> {
        plan_flash(
            &sys7_app_with(lsm, address, size),
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
    }

    /// The top of the System 7 address space still plans: the record's 2-octet
    /// address field carries `0xFFFF` exactly.
    #[test]
    fn plan_sys7_accepts_the_last_16_bit_address() {
        let plan = plan_sys7_range(1, 0xFFFF, 1).expect("0xFFFF is the last addressable octet");
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7AbsSegment {
                address: 0xFFFF,
                size: 1,
                ..
            }
        )));
    }

    /// One past it is refused at plan time. Before issue #81 the executor
    /// truncated it with `as u16` and allocated at `0x0000` — a wrong frame on the
    /// bus before the following write refused.
    #[test]
    fn plan_sys7_refuses_an_address_past_16_bits() {
        match plan_sys7_range(1, 0x1_0000, 1) {
            Err(PlanError::Sys7FieldOutOfRange { field, value, .. }) => {
                assert_eq!(field, "segment address");
                assert_eq!(value, 0x1_0000);
            }
            other => panic!("expected Sys7FieldOutOfRange, got {other:?}"),
        }
    }

    /// A segment that starts inside the 16-bit space but runs past its end cannot
    /// be placed either.
    #[test]
    fn plan_sys7_refuses_a_segment_that_runs_past_the_top() {
        match plan_sys7_range(1, 0xFFF0, 0x20) {
            Err(PlanError::Sys7FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "segment end");
            }
            other => panic!("expected Sys7FieldOutOfRange, got {other:?}"),
        }
    }

    /// LSM 15 is the last index the record's opcode nibble can carry.
    #[test]
    fn plan_sys7_accepts_lsm_15() {
        let plan = plan_sys7_range(15, 0x4000, 4).expect("LSM 15 fits the opcode nibble");
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::Sys7StartLoading { lsm: 15 }))
        );
    }

    /// LSM 16 would wrap into index 0 (`16 << 4` truncates to `0x00`) and drive a
    /// different machine, so the plan is refused instead.
    #[test]
    fn plan_sys7_refuses_lsm_16() {
        match plan_sys7_range(16, 0x4000, 4) {
            Err(PlanError::Sys7LsmOutOfRange { lsm, .. }) => assert_eq!(lsm, 16),
            other => panic!("expected Sys7LsmOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn plan_lowers_system_7() -> Result<(), Box<dyn std::error::Error>> {
        let app = fabricated_sys7_app();
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");
        assert!(plan.is_sys7(), "should be a System 7 plan");

        // The obj0/PID78 preflight lowers to a CompareProp.
        assert!(
            matches!(
                plan.steps.first(),
                Some(FlashStep::CompareProp {
                    object: crate::flash::PropObject::Index(0),
                    prop_id: 78,
                    expected: Some(_),
                    ..
                })
            ),
            "first step is the obj0/PID78 preflight, got {:?}",
            plan.steps.first()
        );

        // Three unloads, one per LSM.
        let unloads: Vec<u32> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Sys7Unload { lsm } => Some(*lsm),
                _ => None,
            })
            .collect();
        assert_eq!(unloads, vec![1, 2, 3]);

        // The 0x4000 AbsSegment carries an image AND a mask (streamed under mask).
        let s7 = plan.sys7.as_ref().ok_or("a System 7 plan")?;
        let table_seg = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::Sys7AbsSegment {
                    address: 16384,
                    image: Some(img),
                    mem_type,
                    ..
                } => Some((img.clone(), *mem_type)),
                _ => None,
            })
            .expect("the 0x4000 AbsSegment with an image");
        assert_eq!(table_seg.1, 3, "0x4000 is EEPROM (mem_type 3)");
        assert!(
            s7.segment_masks.contains_key(&table_seg.0.segment_id),
            "the 0x4000 segment carries a <Mask>"
        );

        // The 0x0700 RAM region is allocate-only (no image) and RAM mem-type.
        let ram_seg = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::Sys7AbsSegment {
                    address: 1792,
                    image,
                    mem_type,
                    ..
                } => Some((image.is_none(), *mem_type)),
                _ => None,
            })
            .expect("the 0x0700 AbsSegment");
        assert!(ram_seg.0, "0x0700 is allocate-only (no <Data>)");
        assert_eq!(ram_seg.1, 2, "0x0700 is RAM (mem_type 2)");

        // TaskSegment finalizes LSM 1 and LSM 3; the last step is the restart.
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7TaskSegment {
                lsm: 1,
                address: 16384,
                ..
            }
        )));
        assert!(matches!(plan.steps.last(), Some(FlashStep::Restart)));
        Ok(())
    }

    #[test]
    fn test_add_ets_prelude_orders_restart_and_verify_mode() {
        let procedure = || {
            vec![
                FlashStep::CompareProp {
                    object: crate::flash::PropObject::Index(0),
                    prop_id: 78,
                    expected: Some(vec![0]),
                    mask: None,
                    start_element: 1,
                },
                FlashStep::Sys7Unload { lsm: 1 },
                FlashStep::Sys7StartLoading { lsm: 1 },
                FlashStep::Sys7LoadCompleted { lsm: 1 },
                FlashStep::Restart,
            ]
        };
        // 0705 declares VerifyMode: the restart pass goes after the read-only
        // precondition, verify mode right after the first StartLoading.
        let mut steps = procedure();
        add_ets_prelude(
            &mut steps,
            &bussard_mgmt::Sys7Profile::corpus_default_for_mask(0x0705),
        );
        let mut expected = procedure();
        expected.insert(3, FlashStep::Sys7EnableVerifyMode);
        expected.insert(
            1,
            FlashStep::Sys7PreDownloadRestart {
                unload: vec![1, 2, 3, 4],
            },
        );
        assert_eq!(steps, expected);

        // 0701 has no VerifyMode (read-compare-write): the restart pass only.
        let mut steps = procedure();
        add_ets_prelude(
            &mut steps,
            &bussard_mgmt::Sys7Profile::corpus_default_for_mask(0x0701),
        );
        assert!(!steps.contains(&FlashStep::Sys7EnableVerifyMode));
        assert!(matches!(
            steps.get(1),
            Some(FlashStep::Sys7PreDownloadRestart { .. })
        ));

        // A procedure that loads nothing gets no prelude.
        let mut steps = vec![FlashStep::Restart];
        add_ets_prelude(
            &mut steps,
            &bussard_mgmt::Sys7Profile::corpus_default_for_mask(0x0705),
        );
        assert_eq!(steps, vec![FlashStep::Restart]);
    }

    /// Issue #488: the pre-download pass follows the device's resident state.
    /// Every LSM `Unloaded` (a factory-fresh device, the ETS sweep and
    /// `captures/synthetic/syn-s7-0705/defaults`): no pass. An LSM `Loaded` or
    /// `Loading`, a resident application id, or a probe that read nothing:
    /// the pass stays, unloads and all.
    #[test]
    fn test_fit_sys7_prelude_follows_the_resident_state() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::preflight::{ResidentObject, ResidentState};
        use bussard_mgmt::load::LoadState;
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/11">
         <ApplicationProgram PeiType="0" Id="M-0083_A-E" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0083_A-E_AS-3" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0083_A-E", xml.as_bytes())?;
        let planned = plan_flash(
            &app,
            "1.1.99",
            0x0705,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let prelude = |plan: &FlashPlan| {
            plan.steps.iter().find_map(|s| match s {
                FlashStep::Sys7PreDownloadRestart { unload } => Some(unload.clone()),
                _ => None,
            })
        };
        assert_eq!(prelude(&planned), Some(vec![1, 2, 3, 4]));
        let lsms = |states: [LoadState; 4]| ResidentState {
            objects: (1u8..)
                .zip(states)
                .map(|(index, state)| ResidentObject {
                    index,
                    object_type: None,
                    state,
                })
                .collect(),
            ..Default::default()
        };
        let fresh = lsms([LoadState::Unloaded; 4]);
        let loaded = lsms([
            LoadState::Loaded,
            LoadState::Loaded,
            LoadState::Loaded,
            LoadState::Unloaded,
        ]);
        let loading = lsms([
            LoadState::Unloaded,
            LoadState::Unloaded,
            LoadState::Loading,
            LoadState::Unloaded,
        ]);
        let with_id = ResidentState {
            app_id: Some(vec![0x00, 0x83, 0x00, 0x0E, 0x23]),
            ..lsms([LoadState::Unloaded; 4])
        };
        let unreadable = ResidentState {
            unreadable: Some("no load-state machine answered".to_string()),
            ..Default::default()
        };
        for (name, resident, kept) in [
            ("fresh", &fresh, false),
            ("loaded", &loaded, true),
            ("loading", &loading, true),
            ("resident id", &with_id, true),
            ("unreadable", &unreadable, true),
            ("nothing read", &ResidentState::default(), true),
        ] {
            let mut plan = planned.clone();
            plan.fit_sys7_prelude(resident);
            let expected = kept.then(|| vec![1, 2, 3, 4]);
            assert_eq!(prelude(&plan), expected, "{name}");
            // The procedure's own unload of LSM 3 stays either way.
            assert!(
                plan.steps.contains(&FlashStep::Sys7Unload { lsm: 3 }),
                "{name}"
            );
        }
        Ok(())
    }

    /// The System 7 parameter segment streams its `<Data>` with the
    /// parameters laid over it, not the raw template (issue #117): the Jung
    /// 3361-1MWW and 3181 segments went out as the vendor placeholder bytes,
    /// with every model override dropped.
    #[test]
    fn test_plan_flash_sys7_streams_the_parameter_image() -> Result<(), Box<dyn std::error::Error>>
    {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/11">
         <ApplicationProgram PeiType="0" Id="M-0083_A-F" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7P" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0083_A-F_AS-3" Size="3" Address="17408"><Data>BAUG</Data></AbsoluteSegment>
           </Code>
           <ParameterTypes>
            <ParameterType Id="M-0083_A-F_PT-8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-0083_A-F_P-1" Name="delay" ParameterType="M-0083_A-F_PT-8" Value="17"><Memory CodeSegment="M-0083_A-F_AS-3" Offset="0" BitOffset="0" /></Parameter>
            <Parameter Id="M-0083_A-F_P-2" Name="level" ParameterType="M-0083_A-F_PT-8" Value="1"><Memory CodeSegment="M-0083_A-F_AS-3" Offset="1" BitOffset="0" /></Parameter>
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-0083_A-F_P-1_R-1" RefId="M-0083_A-F_P-1" />
            <ParameterRef Id="M-0083_A-F_P-2_R-2" RefId="M-0083_A-F_P-2" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="3" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="M-0083_A-F_PB-1">
           <ParameterRefRef RefId="M-0083_A-F_P-1_R-1" />
           <ParameterRefRef RefId="M-0083_A-F_P-2_R-2" />
          </ParameterBlock></ChannelIndependentBlock></Dynamic>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0083_A-F", xml.as_bytes())?;
        let overrides: BTreeMap<String, String> =
            [("P-2_R-2".to_string(), "200".to_string())].into();
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0705,
            &overrides,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        // Byte 0: P-1's default 17 over the template's 04. Byte 1: the
        // override. Byte 2: no parameter, the template's 06.
        assert_eq!(plan.images.get("M-0083_A-F_AS-3"), Some(&vec![17, 200, 6]));
        Ok(())
    }

    #[test]
    fn plan_lowers_system_7_task_ctrl1_and_ends_at_the_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        // The Theben FIX2 shape (§4.4): a TaskCtrl1 on LSM 3, then a restart
        // followed by a converted TaskSegment + Load on LSM 5, which ETS never
        // sends and the plan drops (issue #178).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0048_A-4947" ApplicationNumber="18759" ApplicationVersion="16"
            MaskVersion="MV-0701" Name="FIX2" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0048_A-4947_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="16384" Size="4" />
             <LdCtrlTaskSegment LsmIdx="3" Address="18486" />
             <LdCtrlTaskCtrl1 LsmIdx="3" Address="18425" Count="1" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlTaskSegment LsmIdx="5" Address="17406" />
             <LdCtrlLoad LsmIdx="5" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0048_A-4947", xml.as_bytes())?;
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0701,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");

        // The TaskCtrl1 lowers to its own step.
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7TaskCtrl1 {
                lsm: 3,
                address: 18425,
                count: 1
            }
        )));
        // Nothing follows the restart, and LSM 5 is never touched.
        assert!(matches!(plan.steps.last(), Some(FlashStep::Restart)));
        assert!(!plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7TaskSegment { lsm: 5, .. } | FlashStep::Sys7StartLoading { lsm: 5 }
        )));
        Ok(())
    }

    #[test]
    fn test_plan_flash_sys7_lowers_task_ptr_and_task_ctrl2()
    -> Result<(), Box<dyn std::error::Error>> {
        // The Task Pointer Record and Task Control Record 2 (KNX 3/5/2
        // §3.31.2), with the attribute values of the knx_master MV-0021
        // procedure (issue #527).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0048_A-4947" ApplicationNumber="18759" ApplicationVersion="16"
            MaskVersion="MV-0701" Name="FIX2" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0048_A-4947_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="16384" Size="4" />
             <LdCtrlTaskSegment LsmIdx="3" Address="16384" />
             <LdCtrlTaskPtr LsmIdx="3" InitPtr="284" SavePtr="285" SerialPtr="0" />
             <LdCtrlTaskCtrl2 LsmIdx="3" Callback="20609" Address="282" Seg0="208" Seg1="208" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0048_A-4947", xml.as_bytes())?;
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0701,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        assert!(plan.steps.contains(&FlashStep::Sys7TaskPtr {
            lsm: 3,
            init: 284,
            save: 285,
            pei_handler: 0,
        }));
        assert!(plan.steps.contains(&FlashStep::Sys7TaskCtrl2 {
            lsm: 3,
            callback: 20609,
            com_objects: 282,
            segment_1: 208,
            segment_2: 208,
        }));
        Ok(())
    }

    #[test]
    fn test_sys7_u16_field_out_of_range_is_refused() {
        assert!(matches!(
            sys7_u16_field(1, "task pointer init", 0x1_0000),
            Err(PlanError::Sys7FieldOutOfRange { .. })
        ));
        assert!(matches!(
            sys7_u16_field(1, "task pointer init", 284),
            Ok(284)
        ));
    }

    /// `LdCtrlDelay MilliSeconds="200"` before the restart (16 corpus 0701
    /// programs, e.g. `M-0076_A-0022-15-D6FE`) lowers to a 200 ms pause right
    /// before the terminal restart instead of refusing the plan (issue #615).
    #[test]
    fn test_plan_flash_sys7_lowers_delay_before_restart() -> Result<(), Box<dyn std::error::Error>>
    {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-00FA_A-0615" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-0701" Name="Delay" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-00FA_A-0615_AS-1" Size="2" Address="16384"><Data>AAE=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="2" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlDelay MilliSeconds="200" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-00FA_A-0615", xml.as_bytes())?;
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0701,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let n = plan.steps.len();
        assert!(n >= 2);
        assert_eq!(
            plan.steps[n - 2..],
            [FlashStep::Delay { milliseconds: 200 }, FlashStep::Restart]
        );
        assert_eq!(
            plan.step_label(&plan.steps[n - 2]),
            "wait 200 ms (LdCtrlDelay), nothing sent"
        );
        Ok(())
    }

    #[test]
    fn test_sys7_procedure_end_cuts_after_the_last_restart() {
        let load5 = LoadOp::Load { lsm_idx: Some(5) };
        let ops = [
            LoadOp::Connect,
            LoadOp::Restart,
            load5.clone(),
            LoadOp::Disconnect,
        ];
        assert_eq!(sys7_procedure_end(&ops), 2);
        let ops = [
            LoadOp::Restart,
            load5.clone(),
            LoadOp::Restart,
            load5.clone(),
        ];
        assert_eq!(sys7_procedure_end(&ops), 3);
        // No restart: the whole procedure.
        let ops = [LoadOp::Connect, load5, LoadOp::Disconnect];
        assert_eq!(sys7_procedure_end(&ops), 3);
    }

    #[test]
    fn plan_lowers_system_7_compare_mem() -> Result<(), Box<dyn std::error::Error>> {
        // The Zennio LUMENTO shape (§4.5): a raw LdCtrlCompareMem before the LSMs.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0071_A-3211" ApplicationNumber="12817" ApplicationVersion="18"
            MaskVersion="MV-0701" Name="LUMENTO" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0071_A-3211_AS-1" Size="2" Address="16384"><Data>AAE=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlCompareMem Address="46609" InlineData="3210" Size="2" />
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="2" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0071_A-3211", xml.as_bytes())?;
        let plan = plan_flash(
            &app,
            "1.1.99",
            0x0701,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7CompareMem { address: 46609, expected } if expected == &[0x32, 0x10]
        )));
        Ok(())
    }

    /// A System 7 application with the given `<ApplicationProgram>` attributes
    /// and `<Options>`, and one TaskSegment in its procedure.
    fn identity_app(
        id: &str,
        attrs: &str,
        options: &str,
    ) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="{id}" {attrs} MaskVersion="MV-0705" Name="I"
            LoadProcedureStyle="ProductProcedure">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="16384" Size="16" />
             <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
             <LdCtrlLoadCompleted LsmIdx="1" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
          {options}
         </ApplicationProgram></KNX>"#
        );
        Ok(parse_application_program(id, xml.as_bytes())?)
    }

    #[test]
    fn test_sys7_task_identity_ekinex_e72() -> Result<(), Box<dyn std::error::Error>> {
        // ETS wrote `01 00 b6 45 37 03` for M-00B6_A-4537-03-DE59.
        let app = identity_app(
            "M-00B6_A-4537-03-DE59",
            r#"ApplicationNumber="17719" ApplicationVersion="3" PeiType="1""#,
            "",
        )?;
        let identity = sys7_task_identity(&app)?;
        assert_eq!(identity.octets(), [0x01, 0x00, 0xB6, 0x45, 0x37, 0x03]);
        let plan = plan_flash(
            &app,
            "1.1.1",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let planned: Vec<_> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Sys7TaskSegment { identity, .. } => Some(*identity),
                _ => None,
            })
            .collect();
        assert_eq!(planned, vec![identity]);
        Ok(())
    }

    #[test]
    fn test_sys7_task_identity_legacy_patch_takes_the_original_manufacturer()
    -> Result<(), Box<dyn std::error::Error>> {
        // ETS wrote `80 00 02 a0 02 13` for the Busch-Jaeger A-A002 (house 1.1.44).
        let app = identity_app(
            "M-0007_A-A002-13-73C8-O0002",
            r#"ApplicationNumber="40962" ApplicationVersion="19" PeiType="128" OriginalManufacturer="M-0002""#,
            r#"<Options LegacyPatchManufacturerIdInTaskSegment="true" />"#,
        )?;
        assert_eq!(
            sys7_task_identity(&app)?.octets(),
            [0x80, 0x00, 0x02, 0xA0, 0x02, 0x13]
        );
        Ok(())
    }

    #[test]
    fn test_sys7_task_identity_oem_without_the_option_keeps_its_manufacturer()
    -> Result<(), Box<dyn std::error::Error>> {
        // ETS wrote `00 00 71 44 11 10` for M-0071_A-4411-10-C69D-O00C9.
        let app = identity_app(
            "M-0071_A-4411-10-C69D-O00C9",
            r#"ApplicationNumber="17425" ApplicationVersion="16" PeiType="0" OriginalManufacturer="M-00C9""#,
            "",
        )?;
        assert_eq!(
            sys7_task_identity(&app)?.octets(),
            [0x00, 0x00, 0x71, 0x44, 0x11, 0x10]
        );
        Ok(())
    }

    #[test]
    fn test_sys7_task_identity_without_pei_type_refuses_the_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = identity_app(
            "M-00B6_A-4537-03-DE59",
            r#"ApplicationNumber="17719" ApplicationVersion="3""#,
            "",
        )?;
        let reason = sys7_task_identity(&app)
            .err()
            .ok_or("no PeiType must refuse")?;
        assert!(reason.contains("PeiType"), "{reason}");
        let err = plan_flash(
            &app,
            "1.1.1",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("the plan must refuse")?;
        assert!(err.to_string().contains("PeiType"), "{err}");
        Ok(())
    }

    #[test]
    fn test_sys7_task_identity_version_past_an_octet_refuses()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = identity_app(
            "M-00B6_A-4537-03-DE59",
            r#"ApplicationNumber="17719" ApplicationVersion="256" PeiType="1""#,
            "",
        )?;
        assert!(sys7_task_identity(&app).is_err());
        Ok(())
    }

    #[test]
    fn test_sys7_table_bases_reads_the_procedure_allocations()
    -> Result<(), Box<dyn std::error::Error>> {
        // The Jung 0705 shape: the association table at 0x41FF, not 0x4201.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0004_A-7066" ApplicationNumber="28774" ApplicationVersion="17"
            MaskVersion="MV-0705" Name="Eingang" LoadProcedureStyle="ProductProcedure">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="16384" Size="511" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlLoad LsmIdx="2" />
             <LdCtrlAbsSegment LsmIdx="2" SegType="0" Address="16895" Size="255" />
             <LdCtrlLoadCompleted LsmIdx="2" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0004_A-7066", xml.as_bytes())?;
        assert_eq!(
            sys7_table_bases(&app),
            Sys7TableBases {
                address: Some(0x4000),
                association: Some(0x41FF),
                packed_end: None,
                task_identity: Some(bussard_mgmt::Sys7TaskIdentity {
                    pei_type: 0,
                    manufacturer: 0x0004,
                    application_number: 0x7066,
                    application_version: 0x11,
                }),
                address_size: Some(511),
                association_size: Some(255),
                object_table: None,
            }
        );
        Ok(())
    }

    /// The Ekinex EK-E72-TP (`M-00B6_A-4537-03`) shape: a 237-octet address
    /// segment, the association table right behind it at `0x40ED`, and the
    /// group-object table declared in its own segment at `0x41D8`.
    #[test]
    fn test_segment_size_treats_a_missing_size_as_unknown() {
        assert_eq!(segment_size(Some((0x4000, 0))), None);
        assert_eq!(segment_size(Some((0x4000, 0x1_0000))), None);
        assert_eq!(segment_size(Some((0x4000, 237))), Some(237));
        assert_eq!(segment_size(None), None);
    }

    #[test]
    fn test_sys7_table_bases_reads_the_declared_object_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-00B6_A-4537-03-9C38" PeiType="1" ApplicationNumber="17719"
            ApplicationVersion="3" MaskVersion="MV-0705" Name="EK-E72"
            LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-00B6_A-4537-03-9C38_AS-4000" Address="16384" Size="237" />
            <AbsoluteSegment Id="M-00B6_A-4537-03-9C38_AS-40ED" Address="16621" Size="235" />
            <AbsoluteSegment Id="M-00B6_A-4537-03-9C38_AS-41D8" Address="16856" Size="472" />
           </Code>
           <AddressTable CodeSegment="M-00B6_A-4537-03-9C38_AS-4000" Offset="0" MaxEntries="114" />
           <AssociationTable CodeSegment="M-00B6_A-4537-03-9C38_AS-40ED" Offset="0" MaxEntries="114" />
           <ComObjectTable CodeSegment="M-00B6_A-4537-03-9C38_AS-41D8" Offset="0" />
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="16384" Size="237" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlLoad LsmIdx="2" />
             <LdCtrlAbsSegment LsmIdx="2" SegType="0" Address="16621" Size="235" />
             <LdCtrlLoadCompleted LsmIdx="2" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="16856" Size="472" />
             <LdCtrlLoadCompleted LsmIdx="3" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-00B6_A-4537-03-9C38", xml.as_bytes())?;
        assert_eq!(
            sys7_table_bases(&app),
            Sys7TableBases {
                address: Some(0x4000),
                association: Some(0x40ED),
                packed_end: None,
                address_size: Some(237),
                association_size: Some(235),
                object_table: Some(0x41D8),
                task_identity: Some(bussard_mgmt::Sys7TaskIdentity {
                    pei_type: 1,
                    manufacturer: 0x00B6,
                    application_number: 0x4537,
                    application_version: 3,
                }),
            }
        );
        Ok(())
    }

    /// A System 7 app with two table segments (LSM 1 at `lsm1`, LSM 2 at
    /// `lsm2`, each `(address, size)`) and the given `DynamicTableManagement`
    /// attribute (`None`: not declared).
    fn sys7_table_app(
        lsm1: (u32, u32),
        lsm2: (u32, u32),
        dynamic: Option<&str>,
    ) -> std::result::Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let dtm = dynamic
            .map(|v| format!(r#" DynamicTableManagement="{v}""#))
            .unwrap_or_default();
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0083_A-D" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7Dyn" LoadProcedureStyle="ProductProcedure"{dtm}>
          <Static>
           <Code />
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlUnload LsmIdx="2" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="{a1}" Size="{s1}" Access="242" MemType="3" SegFlags="128" />
             <LdCtrlTaskSegment LsmIdx="1" Address="{a1}" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlLoad LsmIdx="2" />
             <LdCtrlAbsSegment LsmIdx="2" SegType="0" Address="{a2}" Size="{s2}" Access="242" MemType="3" SegFlags="128" />
             <LdCtrlTaskSegment LsmIdx="2" Address="{a2}" />
             <LdCtrlLoadCompleted LsmIdx="2" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#,
            a1 = lsm1.0,
            s1 = lsm1.1,
            a2 = lsm2.0,
            s2 = lsm2.1,
        );
        Ok(parse_application_program("M-0083_A-D", xml.as_bytes())?)
    }

    /// The System B table images for `n` group addresses, each linked to its
    /// own object: the 1.1.49 capture's 14 GAs and 14 associations.
    fn system_b_tables(n: u16) -> BTreeMap<u32, Vec<u8>> {
        let mut addr = n.to_be_bytes().to_vec();
        let mut assoc = n.to_be_bytes().to_vec();
        for i in 0..n {
            addr.extend_from_slice(&(0x0800 + i).to_be_bytes());
            assoc.extend_from_slice(&(i + 1).to_be_bytes());
            assoc.extend_from_slice(&(i + 1).to_be_bytes());
        }
        BTreeMap::from([(1, addr), (2, assoc)])
    }

    /// The (LSM, address, size) of every table allocation and the (LSM,
    /// address) of every table descriptor commit of `plan`.
    #[allow(clippy::type_complexity)] // a test helper's two plain lists
    fn table_layout(plan: &FlashPlan) -> (Vec<(u32, u32, u32)>, Vec<(u32, u32)>) {
        let allocs = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Sys7AbsSegment {
                    lsm, address, size, ..
                } if *lsm <= 2 => Some((*lsm, *address, *size)),
                _ => None,
            })
            .collect();
        let tasks = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Sys7TaskSegment { lsm, address, .. } if *lsm <= 2 => {
                    Some((*lsm, *address))
                }
                _ => None,
            })
            .collect();
        (allocs, tasks)
    }

    fn plan_tables(
        app: &ApplicationProgram,
        n: u16,
    ) -> std::result::Result<FlashPlan, Box<dyn std::error::Error>> {
        Ok(plan_flash(
            app,
            "1.1.49",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &system_b_tables(n),
        )?)
    }

    /// The Jung `M-0004_A-2088-11` (`DynamicTableManagement="1"`): ETS
    /// allocated LSM 1 at 0x4000 with the address table's 31 octets and LSM 2
    /// at 0x401F with 991 octets, up to where the product's LSM 2 segment
    /// ends (0x43FE), and committed the association table's descriptor at
    /// 0x401F (capture `schaltaktor-1-1-49.pcapng`, issue #383).
    #[test]
    fn test_plan_flash_sys7_packs_the_jung_a2088_tables() -> Result<(), Box<dyn std::error::Error>>
    {
        let app = sys7_table_app((0x4000, 511), (0x41FF, 511), Some("1"))?;
        let plan = plan_tables(&app, 14)?;
        let (allocs, tasks) = table_layout(&plan);
        assert_eq!(allocs, vec![(1, 0x4000, 31), (2, 0x401F, 991)]);
        assert_eq!(tasks, vec![(1, 0x4000), (2, 0x401F)]);
        let assoc = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::Sys7AbsSegment {
                    lsm: 2,
                    image: Some(image),
                    ..
                } => Some(image.len),
                _ => None,
            })
            .ok_or("the association table is streamed")?;
        assert_eq!(assoc, 29);
        assert_eq!(
            sys7_table_bases(&app),
            Sys7TableBases {
                address: Some(0x4000),
                association: Some(0x41FF),
                packed_end: Some(0x43FE),
                task_identity: Some(bussard_mgmt::Sys7TaskIdentity {
                    pei_type: 0,
                    manufacturer: 0x0083,
                    application_number: 14,
                    application_version: 35,
                }),
                address_size: Some(511),
                association_size: Some(511),
                object_table: None,
            }
        );
        Ok(())
    }

    /// The Theben Meteodata `M-0048_A-140C-14` (`DynamicTableManagement="true"`,
    /// LSM 1 0x4000/513, LSM 2 0x4201/511). Its capture has no load procedure
    /// (ETS read-compares a mask 0701 device), so the layout follows the
    /// A-2088 rule: the address table at its own length, the association
    /// table behind it up to 0x4400.
    #[test]
    fn test_plan_flash_sys7_packs_the_meteodata_tables() -> Result<(), Box<dyn std::error::Error>> {
        let app = sys7_table_app((0x4000, 513), (0x4201, 511), Some("true"))?;
        let plan = plan_tables(&app, 3)?;
        let (allocs, tasks) = table_layout(&plan);
        // 1 + 2 × (own IA + 3 GAs) = 9 octets.
        assert_eq!(allocs, vec![(1, 0x4000, 9), (2, 0x4009, 0x4400 - 0x4009)]);
        assert_eq!(tasks, vec![(1, 0x4000), (2, 0x4009)]);
        Ok(())
    }

    /// Without `DynamicTableManagement` (`0`, `false`, or absent) and for
    /// non-contiguous segments, the product's segments stay as declared:
    /// 1.1.52's `A-A012` is identical to ETS that way.
    #[test]
    fn test_plan_flash_sys7_keeps_static_tables() -> Result<(), Box<dyn std::error::Error>> {
        for dynamic in [Some("0"), Some("false"), None] {
            let app = sys7_table_app((0x4000, 511), (0x41FF, 511), dynamic)?;
            let (allocs, tasks) = table_layout(&plan_tables(&app, 14)?);
            assert_eq!(
                allocs,
                vec![(1, 0x4000, 511), (2, 0x41FF, 511)],
                "{dynamic:?}"
            );
            assert_eq!(tasks, vec![(1, 0x4000), (2, 0x41FF)], "{dynamic:?}");
            assert_eq!(sys7_table_bases(&app).packed_end, None, "{dynamic:?}");
        }
        let gap = sys7_table_app((0x4000, 500), (0x41FF, 511), Some("1"))?;
        let (allocs, _) = table_layout(&plan_tables(&gap, 14)?);
        assert_eq!(allocs, vec![(1, 0x4000, 500), (2, 0x41FF, 511)]);
        assert_eq!(sys7_table_bases(&gap).packed_end, None);
        Ok(())
    }

    #[test]
    fn sys7_profile_from_hawk_resolves_memory_mapped_addresses() {
        use bussard_prod::{HawkConfig, HawkResource};
        let mut resources = std::collections::HashMap::new();
        resources.insert(
            "GroupAddressTableLoadControl".to_string(),
            HawkResource {
                name: "GroupAddressTableLoadControl".to_string(),
                address_space: Some("StandardMemory".to_string()),
                start_address: Some(260), // 0x0104
                length: Some(12),
                flavour: Some("LoadControl_M112".to_string()),
            },
        );
        resources.insert(
            "GroupAddressTableLoadStatus".to_string(),
            HawkResource {
                name: "GroupAddressTableLoadStatus".to_string(),
                address_space: Some("StandardMemory".to_string()),
                start_address: Some(46826), // 0xB6EA
                length: Some(1),
                flavour: Some("LoadControl_M112".to_string()),
            },
        );
        let hawk = HawkConfig {
            resources,
            ..HawkConfig::default()
        };
        let profile = sys7_profile_from_hawk(&hawk).expect("a resolved profile");
        // A LoadControl_M112 @ StandardMemory Hawk block still resolves to the
        // memory-mapped realisation with the block's addresses (the data-driven
        // memory-mapped conformance path).
        assert_eq!(
            profile.lsm,
            bussard_mgmt::LsmRealisation::MemoryMapped {
                control_addr: 0x0104,
                status_addr: 0xB6EA,
            }
        );
        // It differs from the corpus default only in `lsm`: the M2 Jung 0705
        // capture proved the real default is property-based (issue #70), so the
        // corpus default is Property while this Hawk block selects MemoryMapped.
        assert_ne!(profile, bussard_mgmt::Sys7Profile::corpus_default());
        assert_eq!(
            bussard_mgmt::Sys7Profile::corpus_default().lsm,
            bussard_mgmt::LsmRealisation::Property
        );
        assert_eq!(profile.authorize_level, 0);
        assert_eq!(profile.eeprom_mem_type, 3);
        assert_eq!(profile.ram_mem_type, 2);

        // plan_flash_sys7_with_hawk lowers the same app with the Hawk profile.
        let app = fabricated_sys7_app();
        let plan = plan_flash_sys7_with_hawk(
            &app,
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            Some(&hawk),
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");
        assert!(plan.is_sys7());
        // This Hawk block declares no VerifyMode feature: read-compare-write
        // (issue #133), even on 0705 whose corpus default is VerifyMode=1.
        assert_eq!(profile.verify_mode, None);
        assert!(plan.sys7_read_compare());

        // With `VerifyMode=1` the same block selects the blind write.
        let mut verified = hawk.clone();
        verified
            .features
            .insert("VerifyMode".to_string(), "1".to_string());
        assert_eq!(
            sys7_profile_from_hawk(&verified).map(|p| p.verify_mode),
            Some(Some(1))
        );
        let plan = plan_flash_sys7_with_hawk(
            &app,
            "1.1.99",
            0x0705,
            &no_overrides(),
            &BTreeMap::new(),
            Some(&verified),
            &BTreeMap::new(),
        )
        .expect("a System 7 plan");
        assert!(!plan.sys7_read_compare());
    }

    /// A System 7 program whose procedure allocates its parameter segment
    /// `AS-48` (16 octets at `0x4800`) whole when `P-1` is 0 and in two parts
    /// when it is 1 (`0x4800` 6 octets, `0x4808` 4 octets), the shape of the
    /// MDT `A-0054` with `Switching times in the device` = 1 (issue #413).
    /// `P-2` (offset 0) and `P-4` (offset 9) sit in the parts, `P-3` (offset
    /// 13) in the second gap, shown only when `P-1` is 0 (and, as on the MDT
    /// programs, a hidden parameter is not downloaded); `gap_param` adds a
    /// `P-5` at offset 14 that is always shown.
    ///
    /// With `unconditional`, the procedure allocates the two parts outside
    /// any `<choose>` (the Jung `A-5015` shape, no capture).
    fn split_segment_app(
        gap_param: bool,
        unconditional: bool,
    ) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let parts = r#"<LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="18432" Size="6" Access="255" MemType="3" SegFlags="128" />
               <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="18440" Size="4" Access="255" MemType="3" SegFlags="128" />"#;
        let allocation = if unconditional {
            parts.to_string()
        } else {
            format!(
                r#"<choose ParamRefId="M-0083_A-S_P-1_R-1">
              <when test="0">
               <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="18432" Size="16" Access="255" MemType="3" SegFlags="128" />
              </when>
              <when test="1">
               {parts}
              </when>
             </choose>"#
            )
        };
        let (p5, p5_ref, p5_rr) = if gap_param {
            (
                r#"<Parameter Id="M-0083_A-S_P-5" Name="kept" ParameterType="M-0083_A-S_PT-8" Value="5"><Memory CodeSegment="M-0083_A-S_AS-48" Offset="14" BitOffset="0" /></Parameter>"#,
                r#"<ParameterRef Id="M-0083_A-S_P-5_R-5" RefId="M-0083_A-S_P-5" />"#,
                r#"<ParameterRefRef RefId="M-0083_A-S_P-5_R-5" />"#,
            )
        } else {
            ("", "", "")
        };
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram PeiType="0" Id="M-0083_A-S" ApplicationNumber="84" ApplicationVersion="20"
            MaskVersion="MV-0705" Name="Split" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Options DownloadInvisibleParameters="Background" PreferPartialDownloadIfApplicationLoaded="true" />
           <Code>
            <AbsoluteSegment Id="M-0083_A-S_AS-48" Size="16" Address="18432"><Data>AAECAwQFBgcICQoLDA0ODw==</Data></AbsoluteSegment>
           </Code>
           <ParameterTypes>
            <ParameterType Id="M-0083_A-S_PT-8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-0083_A-S_P-1" Name="kept by the device" ParameterType="M-0083_A-S_PT-8" Value="0" />
            <Parameter Id="M-0083_A-S_P-2" Name="delay" ParameterType="M-0083_A-S_PT-8" Value="17"><Memory CodeSegment="M-0083_A-S_AS-48" Offset="0" BitOffset="0" /></Parameter>
            <Parameter Id="M-0083_A-S_P-3" Name="switch time" ParameterType="M-0083_A-S_PT-8" Value="33"><Memory CodeSegment="M-0083_A-S_AS-48" Offset="13" BitOffset="0" /></Parameter>
            <Parameter Id="M-0083_A-S_P-4" Name="level" ParameterType="M-0083_A-S_PT-8" Value="44"><Memory CodeSegment="M-0083_A-S_AS-48" Offset="9" BitOffset="0" /></Parameter>
            {p5}
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-0083_A-S_P-1_R-1" RefId="M-0083_A-S_P-1" />
            <ParameterRef Id="M-0083_A-S_P-2_R-2" RefId="M-0083_A-S_P-2" />
            <ParameterRef Id="M-0083_A-S_P-3_R-3" RefId="M-0083_A-S_P-3" />
            <ParameterRef Id="M-0083_A-S_P-4_R-4" RefId="M-0083_A-S_P-4" />
            {p5_ref}
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="3" />
             {allocation}
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="M-0083_A-S_PB-1">
           <ParameterRefRef RefId="M-0083_A-S_P-1_R-1" />
           <ParameterRefRef RefId="M-0083_A-S_P-2_R-2" />
           <ParameterRefRef RefId="M-0083_A-S_P-4_R-4" />
           {p5_rr}
           <choose ParamRefId="M-0083_A-S_P-1_R-1">
            <when test="0"><ParameterRefRef RefId="M-0083_A-S_P-3_R-3" /></when>
           </choose>
          </ParameterBlock></ChannelIndependentBlock></Dynamic>
         </ApplicationProgram></KNX>"#
        );
        Ok(parse_application_program("M-0083_A-S", xml.as_bytes())?)
    }

    /// Plans [`split_segment_app`] with `P-1` at `kept`.
    fn plan_split(
        app: &ApplicationProgram,
        kept: &str,
    ) -> std::result::Result<FlashPlan, PlanError> {
        let overrides: BTreeMap<String, String> =
            [("P-1_R-1".to_string(), kept.to_string())].into();
        plan_flash(
            app,
            "1.1.99",
            0x0705,
            &overrides,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
    }

    /// The `(address, allocated size, image offset, streamed length)` of
    /// every allocation of `AS-48`.
    fn split_layout(plan: &FlashPlan) -> Vec<(u32, u32, usize, usize)> {
        plan.steps
            .iter()
            .filter_map(|step| match step {
                FlashStep::Sys7AbsSegment {
                    address,
                    size,
                    image: Some(image),
                    ..
                } if image.segment_id == "M-0083_A-S_AS-48" => {
                    Some((*address, *size, image.offset, image.len))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_plan_flash_sys7_streams_each_allocation_its_part()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = split_segment_app(false, false)?;
        // P-1 = 0: one allocation holds the whole image, streamed whole.
        let whole = plan_split(&app, "0")?;
        assert_eq!(split_layout(&whole), vec![(0x4800, 16, 0, 16)]);
        assert_eq!(whole.segment_mask("M-0083_A-S_AS-48"), None);
        // P-1 = 1: each allocation streams the part it holds, so what is
        // streamed into an allocation equals its size.
        let split = plan_split(&app, "1")?;
        let layout = split_layout(&split);
        assert_eq!(layout, vec![(0x4800, 6, 0, 6), (0x4808, 4, 8, 4)]);
        assert!(layout.iter().all(|&(_, size, _, len)| size as usize == len));
        // The image is the whole segment's; the octets no allocation holds
        // are the device's: masked off, so no diff or partial download
        // writes them.
        let image = split.image_bytes("M-0083_A-S_AS-48").ok_or("the image")?;
        assert_eq!(image.len(), 16);
        assert_eq!((image[0], image[9]), (17, 44));
        let mask = split.segment_mask("M-0083_A-S_AS-48").ok_or("a mask")?;
        let owned: Vec<usize> = (0..16).filter(|&i| mask[i] == 0xFF).collect();
        assert_eq!(owned, vec![0, 1, 2, 3, 4, 5, 8, 9, 10, 11]);
        Ok(())
    }

    #[test]
    fn test_plan_flash_sys7_keeps_a_parameter_no_allocation_holds()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = split_segment_app(true, false)?;
        // Allocated whole, P-5 is written as before.
        let whole = plan_split(&app, "0")?;
        assert_eq!(split_layout(&whole), vec![(0x4800, 16, 0, 16)]);
        assert!(whole.kept().is_empty());
        // Allocated in parts, P-5 (offset 14) is in no allocation: as in
        // ETS's download (issue #411), the parts are written and the gaps
        // kept on the device, P-5's octet among them.
        let split = plan_split(&app, "1")?;
        assert_eq!(
            split_layout(&split),
            vec![(0x4800, 6, 0, 6), (0x4808, 4, 8, 4)]
        );
        let kept = split.kept();
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(kept[0].object, 3);
        assert_eq!(kept[0].ranges, vec![(6, 8), (12, 16)]);
        assert_eq!(
            kept[0].label(),
            "LSM 3 segment 0x4800 octets 6..8, 12..16 kept"
        );
        let placed = split
            .placed_octets("M-0083_A-S_AS-48")
            .ok_or("placed octets")?;
        assert!(!placed.contains(&14) && placed.contains(&0) && placed.contains(&9));
        let mask = split.segment_mask("M-0083_A-S_AS-48").ok_or("a mask")?;
        assert_eq!(mask[14], 0x00);
        Ok(())
    }

    #[test]
    fn test_plan_flash_sys7_refuses_a_parameter_in_an_unconditional_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        // Split outside any `<choose>`: no capture says what ETS writes, so a
        // placed parameter in the gap (P-5 at 14) still refuses.
        match plan_split(&split_segment_app(true, true)?, "1") {
            Err(PlanError::UnsupportedOp { op }) => {
                assert!(
                    op.contains("outside any <choose>")
                        && op.contains("octets 12..16 of segment M-0083_A-S_AS-48"),
                    "{op}"
                );
            }
            other => return Err(format!("expected the refusal, got {other:?}").into()),
        }
        // Without a parameter in the gap it plans as in #413, nothing kept.
        let plan = plan_split(&split_segment_app(false, true)?, "1")?;
        assert_eq!(
            split_layout(&plan),
            vec![(0x4800, 6, 0, 6), (0x4808, 4, 8, 4)]
        );
        assert!(plan.kept().is_empty());
        Ok(())
    }

    #[test]
    fn test_sys7_segment_parts_splits_and_finds_the_gaps() {
        // One allocation that holds the image: no split.
        assert_eq!(sys7_segment_parts(&[(0x4800, 16)], 0x4800, 16), None);
        assert_eq!(sys7_segment_parts(&[(0x4800, 32)], 0x4800, 16), None);
        // No allocation inside the image: nothing to bind.
        assert_eq!(sys7_segment_parts(&[(0x0700, 16)], 0x4800, 16), None);
        // The A-0054 shape: three parts, a 2-octet and a 961-octet gap.
        let parts = sys7_segment_parts(
            &[(16384, 513), (18404, 899), (19305, 2966), (23232, 578)],
            18404,
            5406,
        );
        assert_eq!(
            parts,
            Some(SegmentParts {
                parts: vec![(18404, 0, 899), (19305, 901, 2966), (23232, 4828, 578)],
                gaps: vec![(899, 901), (3867, 4828)],
            })
        );
        // An allocation smaller than the image leaves the tail unheld.
        assert_eq!(
            sys7_segment_parts(&[(0x4800, 10)], 0x4800, 16),
            Some(SegmentParts {
                parts: vec![(0x4800, 0, 10)],
                gaps: vec![(10, 16)],
            })
        );
    }

    /// Corpus count for issue #413 (env-gated on `BUSSARD_PRODUCT_CORPUS`):
    /// the programs whose load procedure has a `<choose>` branch that
    /// allocates an absolute segment in parts (System 7) or writes a segment
    /// only in part (System B, the #402 refusal), each decided one choose and
    /// one branch at a time. Prints one `SPLIT-SEGMENT` line per such program
    /// and a `SPLIT-SEGMENT-SUMMARY`, and asserts that no System 7 procedure
    /// but the known Jung `A-5015-13` splits a segment outside a `<choose>`:
    /// the layout of every other System 7 plan is the one before #413.
    #[test]
    fn test_sys7_segment_parts_on_the_corpus() -> Result<(), Box<dyn std::error::Error>> {
        use bussard_prod::application::LoadProcedure;
        let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
            return Ok(());
        };
        let dir = std::path::PathBuf::from(dir);
        let dir = [dir.join("cache/vendor"), dir.join("vendor")]
            .into_iter()
            .find(|d| d.is_dir())
            .unwrap_or(dir);
        // The ops of `blocks` with branch `branch` of choose `choose` (of
        // block `block`) taken and every other branch of it left out; the
        // other chooses keep all their branches.
        fn with_branch<'a>(
            blocks: &[&'a LoadProcedure],
            block: usize,
            choose: usize,
            branch: usize,
        ) -> Vec<&'a LoadOp> {
            blocks
                .iter()
                .enumerate()
                .flat_map(|(bi, p)| {
                    p.ops.iter().enumerate().filter_map(move |(i, op)| {
                        let other = bi == block
                            && p.guards_of(i)
                                .iter()
                                .any(|g| g.choose == choose && g.branch != branch);
                        (!other).then_some(op)
                    })
                })
                .collect()
        }
        let mut seen = BTreeSet::new();
        let (mut sys7, mut sys_b, mut sys7_choose, mut sys_b_choose) = (0, 0, 0, 0);
        let mut default_splits = Vec::new();
        for path in crate::sweep::knxprod_files(&dir) {
            let Ok(product) = bussard_prod::read_knxprod(&path) else {
                continue;
            };
            for app in &product.applications {
                if !seen.insert(app.id.clone()) {
                    continue;
                }
                let mask = app.mask_version.as_deref().unwrap_or("");
                let device_mask = u16::from_str_radix(mask.trim(), 16).unwrap_or(0);
                let profile = bussard_mgmt::MaskProfile::from_mask(device_mask);
                let is_sys7 = profile.is_system_7();
                let is_sys_b = profile.capabilities().flash && !is_sys7;
                let blocks = super::super::plan::self_contained_blocks(app);
                let segments: Vec<(u32, usize, &str)> = app
                    .code_segments
                    .values()
                    .filter(|seg| seg.kind == SegmentKind::Absolute)
                    .filter_map(|seg| {
                        let len = seg
                            .data
                            .as_ref()
                            .map(Vec::len)
                            .or(seg.size.map(|s| s as usize))?;
                        Some((seg.address_or_offset?, len, seg.id.as_str()))
                    })
                    .collect();
                let allocations = |ops: &[&LoadOp]| -> Vec<(u32, u32)> {
                    ops.iter()
                        .filter_map(|op| match op {
                            LoadOp::AbsSegment {
                                address: Some(a),
                                size,
                                ..
                            } => Some((*a, size.unwrap_or(0))),
                            _ => None,
                        })
                        .collect()
                };
                // Outside a `<choose>`, no System 7 procedure splits a
                // segment: the layout of every other plan is the one before
                // #413.
                if is_sys7 {
                    let unguarded: Vec<&LoadOp> = blocks
                        .iter()
                        .flat_map(|p| {
                            p.ops
                                .iter()
                                .enumerate()
                                .filter(|(i, _)| p.guards_of(*i).is_empty())
                                .map(|(_, op)| op)
                        })
                        .collect();
                    let allocs = allocations(&unguarded);
                    if segments
                        .iter()
                        .any(|&(base, len, _)| sys7_segment_parts(&allocs, base, len).is_some())
                    {
                        default_splits.push(app.id.clone());
                    }
                }
                if blocks.iter().all(|p| p.chooses.is_empty()) {
                    continue;
                }
                if is_sys7 {
                    sys7_choose += 1;
                } else if is_sys_b {
                    sys_b_choose += 1;
                }
                let mut found: Vec<String> = Vec::new();
                for (bi, p) in blocks.iter().enumerate() {
                    for (ci, choose) in p.chooses.iter().enumerate() {
                        for branch in 0..choose.tests.len() {
                            let ops = with_branch(&blocks, bi, ci, branch);
                            if is_sys7 {
                                let allocations = allocations(&ops);
                                for &(base, len, id) in &segments {
                                    if let Some(split) = sys7_segment_parts(&allocations, base, len)
                                    {
                                        found.push(format!(
                                            "{} branch {branch}: {id} in {} parts, gaps {:?}",
                                            choose.param_ref_id,
                                            split.parts.len(),
                                            split.gaps
                                        ));
                                    }
                                }
                            } else if is_sys_b {
                                let taken: Vec<LoadOp> =
                                    ops.iter().map(|op| (*op).clone()).collect();
                                let every = blocks.iter().flat_map(|p| p.ops.iter());
                                if let Err(e) =
                                    super::super::plan_props::refuse_partial_rel_mem(every, &taken)
                                {
                                    found.push(format!(
                                        "{} branch {branch}: {e}",
                                        choose.param_ref_id
                                    ));
                                }
                            }
                        }
                    }
                }
                found.sort();
                found.dedup();
                if found.is_empty() {
                    continue;
                }
                if is_sys7 {
                    sys7 += 1;
                } else {
                    sys_b += 1;
                }
                println!(
                    "SPLIT-SEGMENT|{}|{mask}|{}|{}",
                    app.id,
                    if is_sys7 { "System 7" } else { "System B" },
                    found.first().map(String::as_str).unwrap_or("")
                );
            }
        }
        println!(
            "SPLIT-SEGMENT-SUMMARY|System 7 {sys7} of {sys7_choose} with a load <choose>|System B {sys_b} of {sys_b_choose} with a load <choose>|splits outside a choose {}",
            default_splits.len()
        );
        // The one known split outside a `<choose>`, in the corpus since the
        // crawled vendor archives were folded in (#613, 2026-10-30): the Jung
        // `A-5015-13` allocates 4 of the 14 octets of `AS-5DAF` and places
        // parameters at octets 12 and 13. No capture shows what ETS writes
        // there, so the planner refuses it (issue #411 keeps only a gap a
        // `<choose>` makes); a new one is reported here.
        const KNOWN: &[&str] = &["M-0004_A-5015-13-7E56-O00F4"];
        default_splits.retain(|id| !KNOWN.contains(&id.as_str()));
        assert!(default_splits.is_empty(), "{default_splits:#?}");
        Ok(())
    }
}
