//! System 7 planning (mask 0705 / 0701): lower a System 7 procedure into a
//! validated [`FlashPlan`].
//!
//! Holds [`plan_flash_sys7_with_hawk`] and its range checks, the table images
//! synthesized from a System B model ([`Sys7PlanTables`],
//! [`sys7_tables_from_system_b`], [`linked_flags_from_system_b`]) and the
//! group-object descriptor post-pass that sets each object's communication flag
//! from the association table.

use super::plan::assemble_ops;
use super::{AppIdentity, FlashPlan, FlashStep, ImageKind, ImageRef, PlanError, Sys7Context};
use bussard_prod::application::{ApplicationProgram, LoadOp, SegmentKind};
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
    match std::env::var(SYS7_LSM_OVERRIDE_ENV)
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
///
/// The mask profile ([`bussard_mgmt::Sys7Profile`]) supplies the LSM realisation,
/// authorize level and mem-types; absent `HawkConfigurationData`, the
/// corpus-default profile drives blind (`[system7-spec §2.4]`).
pub(super) fn plan_flash_sys7(
    app: &ApplicationProgram,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    profile: bussard_mgmt::MaskProfile,
    hawk: Option<&bussard_prod::HawkConfig>,
    tables: &Sys7PlanTables,
) -> std::result::Result<FlashPlan, PlanError> {
    let sys7_tables = &tables.tables;
    let linked_flags = &tables.linked_flags;
    let app_mask = app
        .mask_version
        .clone()
        .ok_or_else(|| PlanError::MissingAppMask(app.id.clone()))?;

    // System 7 apps carry their whole download in their own load procedures
    // (ProductProcedure style — no master-template splice; `[corpus 49/49]`).
    let (ops, _spliced) = assemble_ops(app, None);
    if ops.is_empty() {
        return Err(PlanError::NoProcedure(app.id.clone()));
    }

    // Resolve parameter images up front: each parameter segment's <Data> is only
    // the vendor's template, and the image streamed for it is that template with
    // the parameters laid over it.
    let param_images = bussard_prod::compute_parameter_image(app, overrides, base_offsets)
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

    // The TaskSegment trailing marker `[lead][AppNumber:2][ver]` is per-app: the
    // lead byte tracks the mask family (0x04 on 0705, 0x48 on 0701), the middle two
    // octets are the application number, the trailing octet the app version's low
    // byte (`[system7-spec §4.3]`; the lead/version octets are best-effort — see
    // `bussard_mgmt::task_segment_marker`).
    let task_marker = bussard_mgmt::task_segment_marker(
        device_mask,
        app.application_number.unwrap_or(0) as u16,
        app.application_version.unwrap_or(0) as u8,
    );

    for (i, op) in ops.iter().enumerate() {
        let step_no = i + 1;
        match op {
            LoadOp::Connect | LoadOp::Disconnect => {}
            LoadOp::Restart => steps.push(FlashStep::Restart),
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
                let (default_flags, default_checksum) = bussard_mgmt::alloc_attr_octets(mem_type);
                let op_seg_flags: Option<u32> = seg_flags.to_owned();
                let checksum_ctrl = seg_flags_octet(op_seg_flags).unwrap_or(default_checksum);
                let seg_flags = access
                    .and_then(|a| u8::try_from(a).ok())
                    .unwrap_or(default_flags);
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
                    seg_by_addr.get(&addr).and_then(|seg| {
                        let bytes = param_images
                            .get(&seg.id)
                            .filter(|b| !b.is_empty())
                            .or(seg.data.as_ref());
                        bytes.map(|data| {
                            images.insert(seg.id.clone(), data.clone());
                            if let Some(mask) = &seg.mask {
                                segment_masks.insert(seg.id.clone(), mask.clone());
                            }
                            ImageRef {
                                segment_id: seg.id.clone(),
                                kind: ImageKind::Code,
                                len: data.len(),
                            }
                        })
                    })
                };
                steps.push(FlashStep::Sys7AbsSegment {
                    lsm,
                    address: addr,
                    size,
                    mem_type,
                    seg_flags,
                    checksum_ctrl,
                    image,
                });
            }
            LoadOp::TaskSegment { lsm_idx, address } => {
                let lsm = check_sys7_lsm(step_no, lsm_idx.unwrap_or(0))?;
                let addr = address.ok_or_else(|| PlanError::UnresolvableImage {
                    step: step_no,
                    reason: "LdCtrlTaskSegment has no Address".to_string(),
                })?;
                let addr = check_sys7_u16(step_no, "task segment address", addr)?;
                // ETS writes a zero-length field + a `[lead][AppNumber:2][ver]`
                // marker, not the loaded span. Derive the marker from the mask
                // family + application number (`[system7-spec §4.3]`).
                steps.push(FlashStep::Sys7TaskSegment {
                    lsm,
                    address: addr,
                    marker: task_marker,
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
            LoadOp::CompareProp {
                obj_idx,
                prop_id,
                inline_data,
                mask,
                ..
            } => {
                // The obj0/PID78 preflight (44/49 MDT apps). Reuses the System B
                // CompareProp step: an interface-object property read + compare,
                // which is identical on System 7 (`[system7-spec §4.6]`).
                steps.push(FlashStep::CompareProp {
                    obj_idx: obj_idx.unwrap_or(0),
                    prop_id: prop_id.unwrap_or(0),
                    expected: inline_data.clone(),
                    mask: mask.clone(),
                });
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
    let config = bussard_prod::dynamic::evaluate_dynamic(app, overrides);
    let default_flags = sys7_object_defaults(app, &config);
    // Module instances shift numbers past the declared ones: count those too.
    let last_object = app
        .resolved_com_objects()
        .iter()
        .map(|c| c.number())
        .chain(default_flags.keys().copied())
        .chain(linked.iter().copied())
        .max();
    apply_sys7_group_object_links(
        &steps,
        &mut images,
        &linked,
        linked_flags,
        &default_flags,
        last_object,
    );

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
        spliced_from_template: false,
        sys7: Some(Sys7Context {
            profile: s7_profile,
            segment_masks,
        }),
        confirmed_restart: false,
        baseline: BTreeMap::new(),
    })
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
}

/// The per-ASAP defaults the System 7 post-pass writes, from the Dynamic walk.
///
/// ETS writes, for every object the device's parameter values make visible,
/// the flags of the visible ComObjectRef (the 3361-1MWW and 3181 captures of
/// issue #117: the same object `Number` has refs with different flags under
/// different `<when>` branches), and leaves an object no branch shows at the
/// template (C cleared). An application without a Dynamic section (the walk
/// reaches no com-object) falls back to the flat product defaults: every
/// declared ref's flags, with the template's TYPE.
pub(super) fn sys7_object_defaults(
    app: &ApplicationProgram,
    config: &bussard_prod::dynamic::DynamicConfig,
) -> BTreeMap<u16, Sys7ObjectDefault> {
    if config.com_objects.is_empty() {
        return app
            .resolved_com_objects()
            .iter()
            .map(|c| {
                (
                    c.number(),
                    Sys7ObjectDefault {
                        flags: c.flags(),
                        type_code: None,
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
        let offset = base
            .base_number_ref
            .as_deref()
            .map(|arg| arg.strip_prefix(&format!("{}_", app.id)).unwrap_or(arg))
            .and_then(|arg| config.module_args(active.module)?.get(arg).copied())
            .unwrap_or(0);
        let Ok(asap) = u16::try_from(i64::from(base.number) + offset) else {
            continue;
        };
        let size = cref.object_size.as_deref().or(base.object_size.as_deref());
        out.insert(
            asap,
            Sys7ObjectDefault {
                flags: base.flags.merge(cref.flags).to_flags(),
                type_code: size.and_then(sys7_type_code),
            },
        );
    }
    out
}

/// The System 7 TYPE octet for an `ObjectSize` (the KNX size code: `1 Bit` is
/// 0, `1 Byte` 7, `2 Bytes` 8), `None` for a size the table does not know.
pub(super) fn sys7_type_code(object_size: &str) -> Option<u8> {
    let code = crate::compute::size_code_from_object_size(Some(object_size));
    let one_bit = object_size.trim().eq_ignore_ascii_case("1 bit");
    (code != 0 || one_bit).then_some(code)
}

/// The System 7 CONFIG octet for a linked object: the project's flags in bits
/// 7 (U), 6 (T), 4 (W), 3 (R) and 2 (C), the template's bits 5, 1 and 0 kept.
pub(super) fn sys7_config_from_flags(template: u8, flags: bussard_model::Flags) -> u8 {
    use bussard_model::Flags;
    let mut c = template & 0b0010_0011;
    for (bit, flag) in [
        (7, Flags::UPDATE),
        (6, Flags::TRANSMIT),
        (4, Flags::WRITE),
        (3, Flags::READ),
        (2, Flags::COMMUNICATION),
    ] {
        if flags.contains(flag) {
            c |= 1 << bit;
        }
    }
    c
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
/// takes that too.
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
/// The table is found by shape, since the mask declares no address for it:
/// `[CNT:1][RAM-flags ptr:2]` followed by `CNT` 4-octet descriptors
/// `[data ptr:2 BE][CONFIG][TYPE]`, where every data pointer and the RAM-flags
/// pointer fall inside a RAM (`mem_type` 2) segment the same plan allocates.
/// Descriptor `i` is ASAP `i` (the 1.1.46 capture: association ASAPs 1, 5, 7,
/// 13 are exactly the descriptors ETS enabled). A plan without such a segment
/// is left untouched.
pub(super) fn apply_sys7_group_object_links(
    steps: &[FlashStep],
    images: &mut BTreeMap<String, Vec<u8>>,
    linked: &BTreeSet<u16>,
    linked_flags: &BTreeMap<u16, bussard_model::Flags>,
    default_flags: &BTreeMap<u16, Sys7ObjectDefault>,
    last_object: Option<u16>,
) {
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
        return;
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
        let Some(bytes) = images.get_mut(&img.segment_id) else {
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
        if !shaped {
            continue;
        }
        use bussard_model::Flags;
        for (asap, d) in bytes[3..3 + 4 * count]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .enumerate()
        {
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
                    Some(flags) => d[2] = sys7_config_from_flags(d[2], flags),
                    None => d[2] |= 0x04,
                }
            } else {
                match default {
                    Some(o) => d[2] = sys7_config_from_flags(d[2], o.flags - Flags::COMMUNICATION),
                    None => d[2] &= !0x04,
                }
            }
            if let Some(t) = default.and_then(|o| o.type_code) {
                d[3] = t;
            }
        }
        return;
    }
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

/// Maps an `LdCtrlAbsSegment` `SegFlags` attribute to the allocation record's
/// checksum-control octet: `128` → `0x80` (checksum-controlled), `0` → `0x00`
/// (runtime-writable). Any other value is passed through when it fits an octet.
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
        other => format!("{other:?}"),
    }
}

/// Parses an `LdCtrlCompareMem` raw op's `Address` and `InlineData` attributes
/// (`[system7-spec §4.5]`). Returns `(address, expected_bytes)`.
pub(super) fn parse_compare_mem(attrs: &[(String, String)]) -> Option<(u32, Vec<u8>)> {
    let mut address: Option<u32> = None;
    let mut inline: Option<Vec<u8>> = None;
    for (k, v) in attrs {
        match k.as_str() {
            "Address" => address = v.trim().parse().ok(),
            "InlineData" => inline = decode_hex(v),
            _ => {}
        }
    }
    Some((address?, inline?))
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
    use crate::flash::test_support::no_overrides;
    use bussard_prod::application::parse_application_program;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use bussard_prod::application::ApplicationProgram;

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
                seg_flags: 0xF2,
                checksum_ctrl: 0x00,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FF,
                size: 811,
                mem_type: 3,
                seg_flags: 0xF2,
                checksum_ctrl: 0x80,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
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
            &linked,
            &flags,
            &BTreeMap::new(),
            None,
        );
        assert_eq!(images_df[&seg_id][9], 0x4F);
        apply_sys7_group_object_links(&steps, &mut images, &linked, &flags, &BTreeMap::new(), None);
        assert_eq!(images[&seg_id][9], 0x4F);

        // A segment that does not look like the descriptor table is untouched.
        let odd = vec![0xFF; 15];
        let mut images = BTreeMap::from([(seg_id.clone(), odd.clone())]);
        apply_sys7_group_object_links(
            &steps,
            &mut images,
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
                seg_flags: 0xF2,
                checksum_ctrl: 0x00,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FE,
                size: 883,
                mem_type: 3,
                seg_flags: 0xF2,
                checksum_ctrl: 0x80,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
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
         <ApplicationProgram Id="A" MaskVersion="MV-0705" Name="s7dyn">
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
                seg_flags: 0xF2,
                checksum_ctrl: 0x00,
                image: None,
            },
            FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x43FF,
                size: 15,
                mem_type: 3,
                seg_flags: 0xF2,
                checksum_ctrl: 0x80,
                image: Some(ImageRef {
                    segment_id: seg_id.clone(),
                    kind: ImageKind::Code,
                    len: 15,
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
    /// A fabricated System 7 (mask 0705) app in the MDT canonical LSM 1/2/3 shape
    /// (`[system7-spec §3]`): obj0/PID78 preflight, three LSMs, an AbsSegment with
    /// a per-byte `<Mask>` on LSM 1, an allocate-only RAM segment on LSM 3, a
    /// TaskSegment per LSM, a restart.
    fn fabricated_sys7_app() -> ApplicationProgram {
        // Segment images (base64): AS-1 = 4 bytes of table data at 0x4000 (mask
        // FF FF 00 FF -> byte 2 is device-owned); AS-3 = 2 bytes of param at
        // 0x4400; AS-2 (0x0700) is allocate-only (no <Data>).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-83_A-E" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-83_A-E_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data><Mask>//8A/w==</Mask></AbsoluteSegment>
            <AbsoluteSegment Id="M-83_A-E_AS-2" Size="8" Address="1792" />
            <AbsoluteSegment Id="M-83_A-E_AS-3" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
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
        parse_application_program("M-83_A-E", xml.as_bytes()).unwrap()
    }

    /// A minimal System 7 app whose single `LdCtrlAbsSegment` carries the given
    /// LSM index, address and size — the knobs issue #81's range checks guard.
    fn sys7_app_with(lsm: u32, address: u32, size: u32) -> ApplicationProgram {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-83_A-F" ApplicationNumber="14" ApplicationVersion="35"
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
        parse_application_program("M-83_A-F", xml.as_bytes()).unwrap()
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
    fn plan_lowers_system_7() {
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
                    obj_idx: 0,
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
        let s7 = plan.sys7.as_ref().unwrap();
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
    }

    /// The System 7 parameter segment streams its `<Data>` with the
    /// parameters laid over it, not the raw template (issue #117): the Jung
    /// 3361-1MWW and 3181 segments went out as the vendor placeholder bytes,
    /// with every model override dropped.
    #[test]
    fn test_plan_flash_sys7_streams_the_parameter_image() -> Result<(), Box<dyn std::error::Error>>
    {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/11">
         <ApplicationProgram Id="M-83_A-F" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="FabS7P" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-83_A-F_AS-3" Size="3" Address="17408"><Data>BAUG</Data></AbsoluteSegment>
           </Code>
           <ParameterTypes>
            <ParameterType Id="M-83_A-F_PT-8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-83_A-F_P-1" Name="delay" ParameterType="M-83_A-F_PT-8" Value="17"><Memory CodeSegment="M-83_A-F_AS-3" Offset="0" BitOffset="0" /></Parameter>
            <Parameter Id="M-83_A-F_P-2" Name="level" ParameterType="M-83_A-F_PT-8" Value="1"><Memory CodeSegment="M-83_A-F_AS-3" Offset="1" BitOffset="0" /></Parameter>
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-83_A-F_P-1_R-1" RefId="M-83_A-F_P-1" />
            <ParameterRef Id="M-83_A-F_P-2_R-2" RefId="M-83_A-F_P-2" />
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
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="M-83_A-F_PB-1">
           <ParameterRefRef RefId="M-83_A-F_P-1_R-1" />
           <ParameterRefRef RefId="M-83_A-F_P-2_R-2" />
          </ParameterBlock></ChannelIndependentBlock></Dynamic>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-83_A-F", xml.as_bytes())?;
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
        assert_eq!(plan.images.get("M-83_A-F_AS-3"), Some(&vec![17, 200, 6]));
        Ok(())
    }

    #[test]
    fn plan_lowers_system_7_task_ctrl1_and_post_restart_lsm5() {
        // The Theben FIX2 shape (§4.4/§4.7): a TaskCtrl1 on LSM 3, then a restart
        // followed by a post-restart TaskSegment + Load on LSM 5.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-48_A-4947" ApplicationNumber="18759" ApplicationVersion="16"
            MaskVersion="MV-0701" Name="FIX2" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-48_A-4947_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data></AbsoluteSegment>
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
        let app = parse_application_program("M-48_A-4947", xml.as_bytes()).unwrap();
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
        // A post-restart LSM-5 TaskSegment + Load appears after the Restart.
        let restart_pos = plan
            .steps
            .iter()
            .position(|s| matches!(s, FlashStep::Restart))
            .expect("a restart");
        assert!(
            plan.steps[restart_pos + 1..]
                .iter()
                .any(|s| matches!(s, FlashStep::Sys7TaskSegment { lsm: 5, .. }))
        );
        assert!(
            plan.steps[restart_pos + 1..]
                .iter()
                .any(|s| matches!(s, FlashStep::Sys7StartLoading { lsm: 5 }))
        );
    }

    #[test]
    fn plan_lowers_system_7_compare_mem() {
        // The Zennio LUMENTO shape (§4.5): a raw LdCtrlCompareMem before the LSMs.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-71_A-3211" ApplicationNumber="12817" ApplicationVersion="18"
            MaskVersion="MV-0701" Name="LUMENTO" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-71_A-3211_AS-1" Size="2" Address="16384"><Data>AAE=</Data></AbsoluteSegment>
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
        let app = parse_application_program("M-71_A-3211", xml.as_bytes()).unwrap();
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
}
