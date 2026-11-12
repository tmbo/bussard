//! System B planning: lower an application's typed [`LoadProcedure`] into a
//! validated [`FlashPlan`].
//!
//! [`plan_flash`] validates the whole selected procedure up front: it splices a
//! vendor template, binds each `RelSegment` to its code segment, resolves every
//! write image (code, parameters, link tables) and refuses anything the executor
//! could not finish. Only a fully-executable plan leaves this module.

use super::plan_sys7::{Sys7PlanTables, plan_flash_sys7};
use super::{
    AppIdentity, FlashPlan, FlashStep, ImageKind, ImageRef, KeptOctets, PlanError, PropObject,
    SegmentFill,
};
use bussard_product::application::{
    ApplicationProgram, CodeSegment, LoadOp, LoadProcedure, SegmentKind,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Lowers an `LdCtrlDelay` to a [`FlashStep::Delay`] of its `MilliSeconds`
/// (issue #615), in the System B and the System 7 planner. An op without a
/// readable `MilliSeconds` is refused: the length of the pause is not guessed.
pub(super) fn lower_delay(milliseconds: Option<u32>) -> Result<FlashStep, PlanError> {
    milliseconds
        .map(|milliseconds| FlashStep::Delay { milliseconds })
        .ok_or_else(|| PlanError::UnsupportedOp {
            op: "LdCtrlDelay without a MilliSeconds value".to_string(),
        })
}

/// The values the program's property-located parameters compose, computed
/// on first use and kept in `cache` (issue #669), from the parameter values
/// the plan resolved once (issue #945).
fn composed_property_values<'a>(
    cache: &'a mut Option<bussard_product::PropertyValues>,
    params: &bussard_product::PropertyParameters<'_>,
    step: usize,
) -> Result<&'a bussard_product::PropertyValues, PlanError> {
    match cache {
        Some(values) => Ok(values),
        None => Ok(cache.insert(
            params
                .values()
                .map_err(|e| PlanError::UnsupportedWriteProp {
                    step,
                    reason: format!("composing the property values from the parameters: {e}"),
                })?,
        )),
    }
}

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

/// Whether a merged download of `app` leaves its empty tables unwritten.
///
/// A program that declares no group object (`<ComObjectTable />`, no
/// `<ComObject>`) can hold no link: ETS allocates each table object its
/// 2-octet empty table (`LdCtrlRelSegment` without fill) and writes no octet
/// of any of them (issue #840, ekinex `M-00B6_A-4945-10-C905-O00C5`, KNX IP
/// interface secure, sweep capture of 2026-11-04). Every program with group
/// objects gets its empty address and association tables written (issue
/// #542).
fn writes_no_empty_table(app: &ApplicationProgram) -> bool {
    app.com_objects.is_empty()
}

/// Whether a table image is the empty table: the count word 0 and nothing
/// after it.
fn is_empty_table(image: &[u8]) -> bool {
    image == [0, 0]
}

/// `PID_PROGRAM_VERSION` (PID 13) — the application object's app-id / run-state
/// property. The master template writes it with an all-zero placeholder that the
/// flash replaces with the synthesized [`app_program_version`] value.
pub(super) const PID_PROGRAM_VERSION: u32 = 13;

/// The 5-octet placeholder the master template ships for the PID-13 write; ETS
/// (and this engine) overwrite it with the real application id.
pub(super) const APP_ID_PLACEHOLDER: [u8; 5] = [0, 0, 0, 0, 0];

/// Refuses an application that declares an `ObjectSize` with no value field
/// type code (issue #545): its descriptor would otherwise go out as 1 bit.
pub(super) fn check_object_sizes(app: &ApplicationProgram) -> Result<(), PlanError> {
    let unknown = crate::compute::unknown_object_sizes(app);
    if unknown.is_empty() {
        return Ok(());
    }
    Err(PlanError::UnknownObjectSize {
        sizes: unknown
            .iter()
            .map(|(id, size)| format!("{id}: {size:?}"))
            .collect::<Vec<_>>()
            .join(", "),
    })
}

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

/// The interface object type of a PEI program: the interface program object
/// (KNX 3/7/3, object type 4), where a companion `PeiProgram` loads.
const OT_INTERFACE_PROGRAM: u16 = 4;

/// The application ids a plan writes to `PID_PROGRAM_VERSION`, by the object
/// each program loads (issue #964: the object is resolved before the id is
/// picked, never taken for object 0).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ProgramIds {
    /// The main program's id ([`app_program_version_value`]).
    main: Option<[u8; 5]>,
    /// A companion program's (a `PeiProgram`, see
    /// `ApplicationProgram::companion_programs`) own id, by the object index
    /// its segments load into: ETS wrote `0002A0ED20` to object 5 of the ABB
    /// BE/S16, `0002A0ED10` to object 4.
    by_index: BTreeMap<u32, [u8; 5]>,
    /// The object index each program object named by type is:
    /// `(object type, occurrence)` to index. The main program's objects
    /// (its segments' load-state machines from 4, past the System B table
    /// objects 1 to 3) are application-program objects (type 3), a
    /// `PeiProgram`'s an interface program object (type 4), another
    /// companion's an application-program object; each type's occurrences
    /// count in index order.
    typed: BTreeMap<(u16, u16), u32>,
}

impl ProgramIds {
    /// The ids of `app` and its companion programs.
    pub(super) fn of(app: &ApplicationProgram) -> Self {
        let lsms = |p: &ApplicationProgram| -> BTreeSet<u32> {
            p.code_segments
                .values()
                .filter_map(|seg| seg.load_state_machine)
                .collect()
        };
        let mut by_index = BTreeMap::new();
        let mut objects: BTreeMap<u32, u16> = lsms(app)
            .into_iter()
            .filter(|lsm| *lsm >= 4)
            .map(|lsm| (lsm, bussard_mgmt::tables::OT_APPLICATION_PROGRAM))
            .collect();
        for c in &app.companion_programs {
            let object_type = if c.is_pei_program() {
                OT_INTERFACE_PROGRAM
            } else {
                bussard_mgmt::tables::OT_APPLICATION_PROGRAM
            };
            let id = app_program_version_value(c);
            for lsm in lsms(c) {
                objects.insert(lsm, object_type);
                if let Some(id) = id {
                    by_index.insert(lsm, id);
                }
            }
        }
        let mut seen: BTreeMap<u16, u16> = BTreeMap::new();
        let typed = objects
            .into_iter()
            .map(|(index, object_type)| {
                let occurrence = seen.entry(object_type).or_insert(0);
                let key = (object_type, *occurrence);
                *occurrence = occurrence.saturating_add(1);
                (key, index)
            })
            .collect();
        ProgramIds {
            main: app_program_version_value(app),
            by_index,
            typed,
        }
    }

    /// The id the `PID_PROGRAM_VERSION` of `object` takes: a companion's for
    /// an object its segments load, else the main program's for an object
    /// named by index or for a program object named by type, resolved to its
    /// index first. Another object named by type is one the plan cannot tie
    /// to a program, so it takes none.
    pub(super) fn for_object(&self, object: PropObject) -> Option<&[u8; 5]> {
        let index = match object {
            PropObject::Index(index) => index,
            PropObject::Type {
                object_type,
                occurrence,
            } => match self.typed.get(&(object_type, occurrence)) {
                Some(index) => *index,
                None if object_type == bussard_mgmt::tables::OT_APPLICATION_PROGRAM
                    && occurrence == 0 =>
                {
                    return self.main.as_ref();
                }
                None => return None,
            },
        };
        self.by_index.get(&index).or(self.main.as_ref())
    }
}

/// Whether `inline_data` of a write to `prop_id` is the master template's
/// all-zero application-id placeholder of `PID_PROGRAM_VERSION`.
pub(super) fn is_app_id_placeholder(prop_id: u32, inline_data: Option<&[u8]>) -> bool {
    prop_id == PID_PROGRAM_VERSION && inline_data == Some(&APP_ID_PLACEHOLDER[..])
}

/// The template a property write's parameters are composed over, by the one
/// rule for the master template's all-zero PID 13 placeholder (issues #945,
/// #957, #964), on the declared and the undeclared arm alike.
///
/// Only the placeholder ([`is_app_id_placeholder`]) is replaced; any other
/// write (and any non-zero PID 13 value) is honoured verbatim. The
/// placeholder takes the application id (`app_id_value`, see
/// [`ProgramIds::for_object`]), and the parameters placed in the property are
/// laid over it by the caller, once. Without an id it stays zeros when a
/// parameter is placed in the property (`placed`, asked only then) and the
/// parameters supply the value; with neither it is refused: zeros name no
/// program, and the read-back would compare them.
///
/// # Errors
///
/// The refusal reason, naming `name`, for a placeholder nothing supplies,
/// and the reason `placed` gives.
pub(super) fn maybe_substitute_app_id(
    name: &str,
    prop_id: u32,
    inline_data: Option<&[u8]>,
    app_id_value: Option<&[u8; 5]>,
    placed: impl FnOnce() -> Result<bool, String>,
) -> Result<Option<Vec<u8>>, String> {
    if !is_app_id_placeholder(prop_id, inline_data) {
        return Ok(inline_data.map(<[u8]>::to_vec));
    }
    if let Some(app_id) = app_id_value {
        return Ok(Some(app_id.to_vec()));
    }
    if placed()? {
        return Ok(Some(APP_ID_PLACEHOLDER.to_vec()));
    }
    Err(format!(
        "the write to {name} is the all-zero application-id placeholder, and neither an \
         application number and version of the program nor a parameter placed in the \
         property supplies the value to put in its place"
    ))
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
///
/// `object_flags` are the project's flags of the linked com-objects, keyed by
/// object number. Only a System 7 plan reads them (the CONFIG octet of a
/// linked descriptor). They take precedence over the flags decoded from the
/// System B group-object table image, which cannot carry object 0: that table
/// is 1-based, word 0 is its count (1.1.1, 2116REG: object 0 is linked with
/// the project's T W R C, ETS wrote `5f`, the ref's own T W C gave `57`).
///
/// The Dynamic section is evaluated through `memo` (issue #367), so a caller
/// that evaluates the same overrides for other reasons (the group-object table
/// image, a parameter decode) shares the evaluation.
#[allow(clippy::too_many_arguments)] // the plan's inputs; a struct would only rename them
pub fn plan_flash(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    template_ops: Option<&[LoadOp]>,
    table_images: &BTreeMap<u32, Vec<u8>>,
    object_flags: &BTreeMap<u16, bussard_model::Flags>,
    memo: &bussard_product::dynamic::DynamicMemo<'_, ApplicationProgram>,
) -> std::result::Result<FlashPlan, PlanError> {
    plan_flash_as(
        app,
        device,
        device_mask,
        overrides,
        base_offsets,
        template_ops,
        table_images,
        object_flags,
        memo,
        Download::Full,
    )
}

/// Adds to `plan` (a [`plan_flash`] of the same inputs) the lowering of the
/// mask's parameter-only procedure `par_ops` (issue #1052): what
/// [`FlashPlan::parameters_only`] then runs for a System B program spliced
/// into the master template whose parameters all live in properties. The
/// application's blocks are filtered to the ops whose `AppliesTo` includes
/// `par` (KNX 3/5/3 §3.9.3.6; the E802 and E804 sweep captures). A no-op for
/// any other plan, and without `par_ops` (a mask whose master data and
/// bussard declare no such procedure): that plan keeps the cut of the
/// complete download. Only a caller that plans a parameter-only download
/// asks for it: the second lowering costs as much as the first.
#[allow(clippy::too_many_arguments)] // the plan's inputs; a struct would only rename them
pub fn add_par_procedure(
    plan: &mut FlashPlan,
    app: &ApplicationProgram,
    device: &str,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    par_ops: Option<&[LoadOp]>,
    table_images: &BTreeMap<u32, Vec<u8>>,
    object_flags: &BTreeMap<u16, bussard_model::Flags>,
    memo: &bussard_product::dynamic::DynamicMemo<'_, ApplicationProgram>,
) {
    let Some(par_ops) = par_ops else {
        return;
    };
    if plan.par_steps.is_some() || !plan.takes_par_procedure() {
        return;
    }
    plan.par_steps = Some(
        plan_flash_as(
            app,
            device,
            plan.device_mask,
            overrides,
            base_offsets,
            Some(par_ops),
            table_images,
            object_flags,
            memo,
            Download::Par,
        )
        .map(|p| p.steps)
        .map_err(|e| e.to_string()),
    );
}

/// Which download a lowering builds (issue #1052): the complete one, or the
/// mask's parameter-only (`par`) procedure with the application's ops
/// filtered by `AppliesTo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Download {
    /// The complete download.
    Full,
    /// The parameter-only download.
    Par,
}

/// [`plan_flash`] for one `download`.
#[allow(clippy::too_many_arguments)] // the plan's inputs; a struct would only rename them
fn plan_flash_as(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    template_ops: Option<&[LoadOp]>,
    table_images: &BTreeMap<u32, Vec<u8>>,
    object_flags: &BTreeMap<u16, bussard_model::Flags>,
    memo: &bussard_product::dynamic::DynamicMemo<'_, ApplicationProgram>,
    download: Download,
) -> std::result::Result<FlashPlan, PlanError> {
    // 1. Family gate. System B and System 7 (mask 0705/0701, issue #49) are the
    //    two supported families; every other mask refuses cleanly. System 7 is
    //    dispatched to its own lowering below (after the shared mask-match check).
    // A security-activated device answers a plain descriptor read with FFFF
    // (Jung F50, 1.1.12) and refuses the rest unsecured: name the cause.
    if device_mask == 0xFFFF {
        return Err(PlanError::SecurityActivated {
            device: device.to_string(),
        });
    }
    let profile = bussard_mgmt::MaskProfile::from_mask(device_mask);
    // A procedure of property operations only on mask 0021 (the Jung IPS 300
    // SREG, issue #390) loads nothing: the family gate opens for it, and only
    // the mask match below applies. Every other family keeps its refusal.
    let property_only = device_mask == super::plan_props::PROPERTY_ONLY_MASK
        && super::plan_props::is_property_only(app);
    if !profile.capabilities().flash && !property_only {
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

    // The module definitions' load procedures run once per module instance
    // the configuration reaches, resolved to that instance's objects and
    // elements (issue #959); every lowering below sees the resolved ops.
    let resolved = resolve_module_procedures(app, overrides, memo, template_ops)?;
    let resolved_memo;
    let (app, memo) = match &resolved {
        None => (app, memo),
        Some(r) => {
            resolved_memo = r.memo();
            (&r.app, &resolved_memo)
        }
    };

    if property_only && !profile.capabilities().flash {
        return super::plan_props::plan_flash_properties(app, device_mask, overrides, memo);
    }

    // System 7 has its own memory-mapped, absolute-addressed lowering: the LSM
    // events, AbsSegment allocation + streaming, TaskSegment finalize, and the
    // obj0/PID78 preflight all differ from System B, so it is a separate path
    // rather than a branchy overload of the System B lowering below.
    if profile.is_system_7() {
        let mut tables = Sys7PlanTables::from_system_b(table_images)?;
        tables.linked_flags.extend(object_flags);
        return plan_flash_sys7(
            app,
            device_mask,
            overrides,
            base_offsets,
            profile,
            None,
            &tables,
            memo,
        );
    }

    // A System B plan writes every descriptor's size code from the product's
    // `ObjectSize`, so a size without a code refuses here. A System 7 plan
    // keeps the product's own TYPE octet for such an object (the Berker
    // 0701 `LegacyVarData` object, issue #545), so it is not refused there.
    check_object_sizes(app)?;

    // 3. Assemble the op sequence to execute. A `MergedProcedure` app splits one
    //    logical download across several `<LoadProcedure MergeId=…>` blocks
    //    (e.g. Jung 23024: MergeId 2 allocates + seeds the MCB, 4 writes the
    //    segment, 7 runs the LoadImageProp integrity checks); those blocks are
    //    concatenated in MergeId order so the whole download lowers, not just the
    //    richest single block. A single-style app has one block, used as-is.
    //    Empty apps are refused.
    let config = memo.evaluate_for(app, overrides);
    let (ops, spliced_from_template, branch_gaps) =
        assemble_ops(app, template_ops, &config, download)?;
    if ops.is_empty() {
        return Err(PlanError::NoProcedure(app.id.clone()));
    }
    // The octets a `<choose>` branch leaves unwritten stay as the device holds
    // them, as in ETS's download (issue #411, [`KeptOctets`]).
    let kept = kept_from(app, &ops, &branch_gaps);

    // Resolve the parameter images once, up front (used by AppliesTo=par writes).
    // `overrides` is keyed by app-relative ParameterRef id (the #46 contract);
    // the caller re-keys the device file's `parameters:` block before calling.
    // No per-instance base offsets are supplied here (they live in the project,
    // not in the product data): a module-instance override therefore refuses at
    // pre-flight rather than misplacing a byte — see `compute_parameter_image`.
    let (param_images, mut placed) =
        bussard_product::compute_parameter_image_placed_with(app, overrides, base_offsets, memo)
            .map_err(|e| PlanError::UnresolvableImage {
                step: 0,
                reason: format!("computing the parameter image: {e}"),
            })?;

    // A program that is not Data Secure enabled has its objects named by
    // type written at the index the device's object list gives them, on the
    // plain services (issue #948); the plan holds their PID to 8 bits (issue
    // #964).
    let typed_objects_by_list = !app.is_secure_enabled;
    // The application id each program object's PID 13 placeholder takes.
    let program_ids = ProgramIds::of(app);
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
    // The fill byte and size of each object's lowered allocation that asks
    // the device to pre-fill it (`Mode` bit 0), so a write into a segment that
    // has no image of its own streams that fill (issue #1026). Keyed by the
    // object the allocation names: a write takes the fill of its own object's
    // allocation only.
    let mut prefill_by_object: BTreeMap<u32, (u8, u32)> = BTreeMap::new();
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
    // The table objects allocated but deliberately not written (see
    // [`writes_no_empty_table`]); their MCB check reads the device's entry
    // without comparing it with another object's image.
    let mut unwritten_tables: BTreeSet<u32> = BTreeSet::new();
    let writes_no_tables = writes_no_empty_table(app);
    // The allocations of the product's `AppliesTo="par"` procedure (issue
    // #490): the planner lowers the `full` one, and a download onto a device
    // that already holds this application swaps in these.
    let mut par_allocations: BTreeMap<Option<u32>, (u32, SegmentFill)> = BTreeMap::new();

    // The `LdCtrlMapError` rules in force, original code to mapped code (issue
    // #614). Only `MAPPED_UNLOAD_ERROR` to success is lowered, and only over
    // an `Unload`.
    let mut error_maps: BTreeMap<u32, u32> = BTreeMap::new();
    // The values of the properties the program's parameters live in, composed
    // on the first `LdCtrlWriteProp` without `InlineData` (issue #669).
    let mut property_values: Option<bussard_product::PropertyValues> = None;
    // The property-located parameters' values, resolved once for every
    // property write of the plan, declared or not (issue #945).
    let property_params = bussard_product::PropertyParameters::resolve(app, &config);
    // The properties an `LdCtrlDeclarePropDesc` declared so far (issue #938).
    let mut declared: Vec<super::declare::PropDecl> = Vec::new();
    // What the procedure has left in the device's properties so far: after
    // a reset of every channel's parameters the catalogue's `LoadedImage`
    // values, until a write touches them (issue #951).
    let mut device_image = super::factory::DeviceImage::default();

    // ETS switches verify mode on before the first `Verify="true"` relative
    // memory write it sends over the plain memory services (issue #705).
    let verify_mode_at = system_b_verify_mode(app, device_mask)
        .then(|| {
            ops.iter().position(|op| {
                matches!(
                    op,
                    LoadOp::WriteRelMem {
                        verify: Some(true),
                        ..
                    }
                )
            })
        })
        .flatten();

    for (i, op) in ops.iter().enumerate() {
        let step_no = i + 1;
        if verify_mode_at == Some(i) {
            steps.push(FlashStep::EnableVerifyMode);
        }
        if let Some(code) = error_maps.keys().next()
            && !matches!(
                op,
                LoadOp::Unload { .. }
                    | LoadOp::MapError { .. }
                    | LoadOp::Connect
                    | LoadOp::Disconnect
            )
        {
            return Err(PlanError::UnsupportedOp {
                op: format!(
                    "LdCtrlMapError OriginalError={code:#010X} in force over {op:?} (step \
                     {step_no}); bussard maps it over an LdCtrlUnload only"
                ),
            });
        }
        // The declaration a write to a declared property follows, looked up
        // once (issue #945).
        let declared_write = super::declare::declaration_for(&declared, step_no, op).cloned();
        let lowered_from = steps.len();
        let declared_target = declared_write.is_some();
        match op {
            // Session boundaries: the engine holds one connection open across the
            // whole procedure, so these carry no per-op device action.
            LoadOp::Connect | LoadOp::Disconnect => {}

            LoadOp::MapError {
                original_error,
                mapped_error,
            } => lower_map_error(&mut error_maps, *original_error, *mapped_error)?,

            // A load-state control naming its object by type goes to that
            // object as ETS sends it (issue #961).
            LoadOp::Unload {
                obj_type: Some(_), ..
            }
            | LoadOp::Load {
                obj_type: Some(_), ..
            }
            | LoadOp::LoadCompleted {
                obj_type: Some(_), ..
            } => steps.push(lower_typed_load_control(
                step_no,
                op,
                !error_maps.is_empty(),
            )?),
            LoadOp::Unload { lsm_idx, .. } => {
                let absent_ok = error_maps.get(&MAPPED_UNLOAD_ERROR) == Some(&0);
                // A mapped unload goes to the object it names, so it must name
                // one (1..=255), not the application object by default.
                if absent_ok && !lsm_idx.is_some_and(|i| (1..=u32::from(u8::MAX)).contains(&i)) {
                    return Err(PlanError::UnsupportedOp {
                        op: format!(
                            "LdCtrlMapError over an LdCtrlUnload without an object index 1 to \
                             255 (step {step_no})"
                        ),
                    });
                }
                steps.push(FlashStep::Unload {
                    target: *lsm_idx,
                    absent_ok,
                });
            }
            // Every object the procedure opens is opened, allocated or not
            // (issue #942): which objects ETS loads is the template variant's
            // choice ([`application_program_1_only`]) and the application's
            // own blocks', never an allocation's. The Gira
            // `M-0008_A-0004-75-0A9A-O007C` loads object 5 from its MergeId 6
            // block without allocating it, and ETS sends both controls
            // (`ops.txt` ops 60, 61).
            LoadOp::Load {
                lsm_idx,
                obj_type: None,
                ..
            } => steps.push(FlashStep::StartLoading { target: *lsm_idx }),
            LoadOp::LoadCompleted {
                lsm_idx,
                obj_type: None,
                ..
            } => steps.push(FlashStep::LoadCompleted { target: *lsm_idx }),
            LoadOp::Restart => steps.push(FlashStep::Restart),
            LoadOp::Delay { milliseconds } => steps.push(lower_delay(*milliseconds)?),
            // A function property call, its return code checked (issue #946).
            LoadOp::InvokeFunctionProp { .. } => {
                steps.push(super::function_prop::lower_invoke_function_prop(
                    step_no, op,
                )?);
            }
            // A declaration sends nothing; it sizes the writes to its property
            // that follow (issue #938).
            LoadOp::DeclarePropDesc { .. } => {
                let decl = super::declare::lower_declare_prop(step_no, op)?;
                steps.push(decl.step());
                declared.push(decl);
            }
            LoadOp::MasterReset {
                erase_code,
                channel_number,
            } => {
                // The EraseCode/ChannelNumber are single octets on the wire; a
                // value beyond a u8 is corrupt vendor input. Default the erase
                // code to 1 ("Confirmed Restart") and the channel to 0 (the whole
                // device) when the attribute is absent, and clamp to u8.
                let erase_code = erase_code.unwrap_or(1).min(u32::from(u8::MAX)) as u8;
                let channel_number = channel_number.unwrap_or(0).min(u32::from(u8::MAX)) as u8;
                device_image.master_reset(erase_code, channel_number);
                steps.push(FlashStep::MasterReset {
                    erase_code,
                    channel_number,
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
                // Table objects always allocate with `Mode` 0 and `Fill` 0
                // (`00 00` in every observed capture, e.g. the house's 1.1.7 and
                // 1.1.8 obj1-3, including the products that set `Mode=1` on the
                // code segment). Preserve that unconditionally so the code
                // segment's fill never leaks onto a table allocation.
                steps.push(FlashStep::AllocateSegment {
                    size,
                    target: Some(*idx),
                    fill: SegmentFill::NONE,
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
                if applies_to
                    .as_deref()
                    .is_some_and(super::par_procedure::is_par_only)
                {
                    par_allocations.insert(*lsm_idx, (size, *fill));
                }
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
                    if let Some(idx) = lsm_idx {
                        match (fill.prefill(), &seg) {
                            (Some(byte), Some(_)) => prefill_by_object.insert(*idx, (byte, size)),
                            _ => prefill_by_object.remove(idx),
                        };
                    }
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
            // A product procedure (issue #614: the Siemens 07B0 applications)
            // writes a table object it declares no segment for: the same.
            LoadOp::WriteRelMem {
                obj_idx: Some(idx), ..
            } if !table_images.contains_key(idx)
                && table_object_name(*idx).is_some()
                && (spliced_from_template || !declares_segment_on(&segments, *idx)) =>
            {
                return Err(PlanError::MissingTableImage {
                    step: step_no,
                    obj_idx: *idx,
                    table: table_object_name(*idx).unwrap_or("table"),
                });
            }

            // A program without group objects: ETS allocates the empty table
            // and writes none of its octets (issue #840).
            LoadOp::WriteRelMem {
                obj_idx: Some(idx), ..
            } if writes_no_tables
                && table_object_name(*idx).is_some()
                && table_images.get(idx).is_some_and(|t| is_empty_table(t)) =>
            {
                unwritten_tables.insert(*idx);
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
                    offset: 0,
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
                size,
                applies_to,
                obj_idx,
                ..
            } => {
                let current = obj_idx
                    .and_then(|idx| rel_segment_by_object.get(&idx))
                    .or(last_rel_segment.as_ref());
                // Only the write's own object's allocation decides the fill: a
                // write whose object has no allocation of its own keeps the
                // refusal below rather than borrow another object's fill.
                let prefill = obj_idx
                    .filter(|idx| rel_segment_by_object.contains_key(idx))
                    .and_then(|idx| prefill_by_object.get(&idx).copied());
                let (segment_id, kind, bytes) = resolve_write_image(
                    &segments,
                    applies_to.as_deref(),
                    current.map(String::as_str),
                    &param_images,
                    prefill,
                )
                .map_err(|reason| PlanError::UnresolvableImage {
                    step: step_no,
                    reason,
                })?;
                // The op's `Size` bounds what is streamed: the write covers the
                // allocation, not the whole `RelativeSegment` (issue #564).
                //
                // A segment a `<choose>` branch writes only in part (issue #411)
                // keeps its image bounded by the allocation, and the step streams
                // the op's own `[Offset, Offset + Size)` of it; the rest of the
                // allocation is kept on the device ([`KeptOctets`]).
                let kept_here = kept.iter().find(|k| k.segment == segment_id);
                let bound = match kept_here {
                    Some(k) => u32::try_from(k.allocated).ok(),
                    None => *size,
                };
                let bytes = bound_write_rel_mem(&segment_id, bytes, bound, placed.get(&segment_id))
                    .map_err(|reason| PlanError::UnresolvableImage {
                        step: step_no,
                        reason,
                    })?;
                let (part_start, len) = match kept_here {
                    Some(_) => {
                        let start = usize::try_from(offset.unwrap_or(0))
                            .unwrap_or(usize::MAX)
                            .min(bytes.len());
                        let end = size
                            .and_then(|s| usize::try_from(s).ok())
                            .map_or(bytes.len(), |s| start.saturating_add(s))
                            .min(bytes.len());
                        (start, end - start)
                    }
                    None => (0, bytes.len()),
                };
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
                    offset: part_start,
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
                    offset: 0,
                };
                last_written_image = Some(image.clone());
                steps.push(FlashStep::WriteMem { address, image });
            }

            // A write to a declared property: `Count` elements of the declared
            // type, the value the parameters compose (issue #938), the
            // template's application-id placeholder replaced by the one rule
            // for it (issues #945, #957, #964).
            LoadOp::WriteProp {
                prop_id,
                inline_data,
                ..
            } if declared_write.is_some() => {
                let Some(decl) = declared_write else { continue };
                let prop = prop_id.unwrap_or(decl.prop_id);
                let name = format!("the declared {} PID {prop}", decl.object);
                // The template; `lower_declared_write_prop` lays the
                // parameters placed in the property over it, once.
                let substituted = maybe_substitute_app_id(
                    &name,
                    prop,
                    inline_data.as_deref(),
                    program_ids.for_object(decl.object),
                    || super::declare::is_placed(&name, decl.object, prop, &property_params, app),
                )
                .map_err(|reason| PlanError::UnsupportedWriteProp {
                    step: step_no,
                    reason,
                })?;
                steps.extend(super::declare::lower_declared_write_prop(
                    step_no,
                    op,
                    &decl,
                    substituted.as_deref(),
                    &property_params,
                    app,
                    typed_objects_by_list,
                )?);
            }

            LoadOp::WriteProp {
                obj_idx,
                obj_type,
                occurrence,
                prop_id,
                inline_data,
                start_element,
                count,
                ..
            } => {
                let prop_id = prop_id.unwrap_or(0);
                // The object the write names: `ObjIdx`, else `ObjType` (the
                // device object for type 0), else the device object, as the
                // observed vendor procedures write. An object named by type is
                // found on the device, never taken for object 0 (issue #948:
                // the Siemens dimmer `M-0001_A-9839-01-38C4` writes PID 205 of
                // type 50215, which ETS found at object 6).
                let object =
                    super::plan_props::prop_object(step_no, *obj_idx, *obj_type, *occurrence)?;
                // The master template carries a placeholder
                // `LdCtrlWriteProp ObjIdx=4 PropId=13 InlineData="0000000000"`
                // for the application object's PID_PROGRAM_VERSION (the app-id /
                // run-state). ETS replaces the zeros with the real 5-octet app id
                // (manufacturer + application number + version); a device left
                // with zeros does not record which program it runs. The one rule
                // for it (`maybe_substitute_app_id`) writes the same bytes ETS
                // does; a template that already carries a concrete value is
                // written verbatim.
                let name = format!("{object} PID {prop_id}");
                let placeholder = is_app_id_placeholder(prop_id, inline_data.as_deref());
                let inline_data = maybe_substitute_app_id(
                    &name,
                    prop_id,
                    inline_data.as_deref(),
                    program_ids.for_object(object),
                    || super::declare::is_placed(&name, object, prop_id, &property_params, app),
                )
                .map_err(|reason| PlanError::UnsupportedWriteProp {
                    step: step_no,
                    reason,
                })?;

                match inline_data {
                    Some(value) if !value.is_empty() => {
                        // The PID 13 placeholder's parameters are laid over its
                        // template as on the declared arm (the one rule,
                        // `maybe_substitute_app_id`), and the step says the
                        // value is theirs, so the executor never skips it as a
                        // template write to an unlisted object (issue #669).
                        let (value, from_parameters) = if placeholder {
                            match super::declare::placed_value(
                                &name,
                                object,
                                prop_id,
                                &property_params,
                                app,
                                &value,
                            )
                            .map_err(|reason| {
                                PlanError::UnsupportedWriteProp {
                                    step: step_no,
                                    reason,
                                }
                            })? {
                                Some(composed) => (composed, true),
                                None => (value, false),
                            }
                        } else {
                            (value, false)
                        };
                        // A value-carrying WriteProp must be executable to keep the
                        // "only a fully-executable FlashPlan reaches flash" invariant:
                        // the one rule of an undeclared write (its `Count`, the
                        // services' reach, issue #964) refuses a shape the executor
                        // cannot address rather than dropping the value at execute
                        // time. Without `Count` it is one element; with it, `Count`
                        // elements in requests of at most 15, as ETS writes the
                        // undeclared `ObjIdx="9" PropId="208" Count="124"` with
                        // 124 octets of InlineData of `M-0009_A-E802-13-7620`
                        // (`count=15 index=1` to `count=4 index=121`, ops 46 to
                        // 54), where the old one-element shape sent 124 octets
                        // in one request.
                        steps.push(super::plan_props::write_prop_step(
                            step_no,
                            super::plan_props::WriteTarget {
                                object,
                                prop_id,
                                start_element: *start_element,
                                count: *count,
                            },
                            value,
                            from_parameters,
                            // `Verify` is not honoured on this arm: the master
                            // template's PID 13 writes carry `Verify="true"`, and
                            // ETS echo-validates them with no extra read-back,
                            // the historical System B shape the offline oracle
                            // confirms (issue #390).
                            false,
                            typed_objects_by_list,
                        )?);
                    }
                    _ => {
                        // A write without `InlineData` writes the value the
                        // program's property-located parameters compose, as ETS
                        // does (issue #669: `syn-property-param`, `5A` to object
                        // 4 PID 201), with the op's `Count` and `Verify`. On a
                        // property no parameter is stored in it is a description
                        // read and no write, as ETS (issue #841); a stored
                        // property without a composed value is refused.
                        let values = composed_property_values(
                            &mut property_values,
                            &property_params,
                            step_no,
                        )?;
                        steps.push(super::plan_props::lower_write_prop(
                            step_no,
                            op,
                            values,
                            app,
                            typed_objects_by_list,
                        )?);
                    }
                }
            }

            // The parameter-only procedure's base pointer checks (KNX 3/5/3
            // §3.9.3.6 steps 02, 03, 08, 11): `PID_TABLE_REFERENCE` read before
            // the unload and compared after the load, where the master's
            // `InlineData` stands for the value read before (issue #1052).
            LoadOp::LoadImageProp {
                obj_idx: Some(obj_idx),
                obj_type: None,
                prop_id: Some(TABLE_REFERENCE),
                ..
            } if download == Download::Par => {
                steps.push(FlashStep::ReadTableReference { obj_idx: *obj_idx });
            }
            LoadOp::CompareProp {
                obj_idx: Some(obj_idx),
                obj_type: None,
                prop_id: Some(TABLE_REFERENCE),
                ..
            } if download == Download::Par => {
                steps.push(FlashStep::CompareTableReference { obj_idx: *obj_idx });
            }

            LoadOp::CompareProp { .. } => {
                // A property-verify precondition. The expected bytes come from
                // the op's own `InlineData` (resolved at parse time), so this
                // lowers with no device access. A `Range`-only op carries no
                // literal bytes and stays a no-expectation confirm. An op
                // naming its object by `ObjType` keeps the type, resolved on
                // the device as a by-type write is, never object 0 (issue
                // #1021: the Gira `M-0008_A-E000-10-89B0-O0077` compares PID
                // 207 of type 65281).
                steps.push(super::plan_props::lower_compare_prop(step_no, op)?);
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
                // The parameter-only procedure writes no table: a table
                // object's check compares the device's MCB with the table the
                // complete download writes there (`obj-table-<n>`, the same
                // image the parameter-only plan carries), which the
                // parameter-only download requires unchanged; it never
                // borrows another object's image (issue #1052).
                let image = written_image_by_object
                    .get(&obj_idx)
                    .cloned()
                    .or_else(|| {
                        (download == Download::Par)
                            .then(|| table_images.get(&obj_idx))
                            .flatten()
                            .filter(|t| table_object_name(obj_idx).is_some() && !t.is_empty())
                            .map(|t| ImageRef {
                                segment_id: format!("obj-table-{obj_idx}"),
                                kind: ImageKind::Table,
                                len: t.len(),
                                offset: 0,
                            })
                    })
                    .or_else(|| {
                        (!unwritten_tables.contains(&obj_idx) && download == Download::Full)
                            .then(|| last_written_image.clone())
                            .flatten()
                    })
                    // The device's CRC covers octets it keeps (issue #411):
                    // the MCB is read, as ETS reads it, but not compared.
                    .filter(|img| !kept.iter().any(|k| k.segment == img.segment_id));
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
            LoadOp::TaskPtr { .. } => {
                return Err(PlanError::UnsupportedOp {
                    op: "LdCtrlTaskPtr".to_string(),
                });
            }
            LoadOp::TaskCtrl2 { .. } => {
                return Err(PlanError::UnsupportedOp {
                    op: "LdCtrlTaskCtrl2".to_string(),
                });
            }
            LoadOp::Raw { name, .. } => {
                return Err(PlanError::UnsupportedOp { op: name.clone() });
            }
        }
        // A write whose value the device holds after the reset of its
        // parameters is not sent; every other write marks its elements
        // (issue #951).
        if matches!(op, LoadOp::WriteProp { .. }) {
            for step in &mut steps[lowered_from..] {
                device_image.settle(step, app, declared_target);
            }
        }
    }

    // A filled segment is written sparsely (only the octets that differ from
    // the fill, issue #123). The device's fill is bookkeeping, not an erase, so
    // on a re-flash every octet the new image leaves out keeps whatever the
    // previous image put there (issue #117: a Jung F50 kept a blinking status
    // LED). ETS opens an unload + download of a secure-capable application
    // with a factory reset (erase code 7) and ends every download of one with
    // a confirmed restart (erase code 1); do the same. An application that is
    // not secure-capable gets neither (issue #452: 1.1.45 and 1.1.51 allocate
    // a filled segment too, and ETS unloads them with load controls and ends
    // with a bare A_Restart).
    // A kept octet is written by no step, so it is not placed: the dump's
    // coverage, the parameter-only download and the restore leave it alone.
    for k in &kept {
        if let Some(octets) = placed.get_mut(&k.segment) {
            octets.retain(|&i| !k.contains(i));
        }
    }

    let form = super::restart_form(app);
    let sparse = steps
        .iter()
        .any(|s| matches!(s, FlashStep::AllocateSegment { fill, .. } if fill.prefill().is_some()));
    if sparse && form.is_confirmed() && download == Download::Full {
        insert_factory_reset(&mut steps);
    }
    // The description reads ETS makes before it first touches a property it
    // has no type for (issue #1014).
    let steps = super::describe::describe_untyped_properties(steps);

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
        spliced_from_template,
        sys7: None,
        confirmed_restart: form.is_confirmed(),
        baseline: BTreeMap::new(),
        placed,
        unwritten: BTreeMap::new(),
        baseline_address: BTreeMap::new(),
        security_capacity: Default::default(),
        user_memory_above_64k: crate::apply::uses_user_memory(Some(app)),
        typed_objects_by_list,
        par_allocations,
        par_procedure: false,
        par_steps: None,
        from_par_procedure: false,
        parameters_only: false,
        kept,
    })
}

/// Whether a System B download of `app` on `device_mask` switches the
/// device's verify mode on before its first `Verify="true"` memory write, as
/// ETS does (issue #705).
///
/// Every System B mask bussard flashes (`07B0`, `17B0`, `27B0`, `57B0`)
/// declares the Hawk `VerifyMode` feature in `knx_master.xml`. ETS reads
/// `obj0/PID_DEVICE_CONTROL` and writes bit 2 when it is clear before the
/// first plain `A_Memory_Write` of such a load control (the house captures of
/// 1.1.45 and 1.1.51, the DA.tp sweep and the synthetic System B captures).
/// An application that is Data Secure enabled or declares
/// `SupportsExtendedMemoryServices` is written with `A_MemoryExtended_Write`,
/// which a response confirms already: ETS never touches the property there
/// (the Jung, ABB and Siemens secure applications of the house,
/// `syn-user-memory-extmem`).
pub(super) fn system_b_verify_mode(app: &ApplicationProgram, device_mask: u16) -> bool {
    device_mask & 0x0FFF == 0x07B0
        && !app.is_secure_enabled
        && !app.supports_extended_memory_services
}

/// The one ETS error code the product corpus maps (`LdCtrlMapError
/// OriginalError="3221498632"`, 27 Siemens 07B0 applications, issue #614): to
/// success, around the `LdCtrlUnload LsmIdx="5"` of a device that may have no
/// object 5. bussard reads it as the device's refusal of that load control
/// with element count 0, the answer of a device without the object (issue
/// #178). The ETS captures of the synthetic products `syn-map-error` and
/// `syn-product-07b0` are to confirm what ETS sends there.
pub const MAPPED_UNLOAD_ERROR: u32 = 0xC004_2B08;

/// Applies one `LdCtrlMapError` to the rules in force: a code mapped to 0 is
/// reported as success from here on, a code mapped to itself ends its rule.
///
/// # Errors
///
/// [`PlanError::UnsupportedOp`] for a rule bussard cannot honour: a code other
/// than [`MAPPED_UNLOAD_ERROR`] (bussard cannot tell which of its failures it
/// names), a mapping to another error, or a missing attribute.
fn lower_map_error(
    error_maps: &mut BTreeMap<u32, u32>,
    original: Option<u32>,
    mapped: Option<u32>,
) -> std::result::Result<(), PlanError> {
    let refuse = |why: &str| PlanError::UnsupportedOp {
        op: format!(
            "LdCtrlMapError OriginalError={} MappedError={}: {why}",
            original.map_or_else(|| "-".to_string(), |c| format!("{c:#010X}")),
            mapped.map_or_else(|| "-".to_string(), |c| format!("{c:#010X}")),
        ),
    };
    let (Some(original), Some(mapped)) = (original, mapped) else {
        return Err(refuse("an attribute is missing"));
    };
    if original != MAPPED_UNLOAD_ERROR {
        return Err(refuse(
            "bussard knows no device failure this ETS error code stands for",
        ));
    }
    if mapped == original {
        error_maps.remove(&original);
    } else if mapped == 0 {
        error_maps.insert(original, 0);
    } else {
        return Err(refuse("only a mapping to success (0) is supported"));
    }
    Ok(())
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

/// The op sequence a download of `app` runs, with every `<choose>` of its
/// load procedures decided under `config`, whether it was spliced into
/// the master template (`template_ops`), and the octets of each object some
/// branch writes and the taken branches do not
/// ([`super::plan_props::partial_rel_mem_gaps`], issue #411).
///
/// Only the branches `config` takes contribute their ops
/// ([`super::plan_props::taken_ops`]), on every path: the System B lowering
/// used to concatenate every branch, so a program choosing its hardware
/// variant by parameter (the MDT 07B0 programs: one `LdCtrlCompareProp` on
/// PID 78 per variant) planned every variant's check and could not pass
/// the second one (issue #402).
///
/// # Errors
///
/// [`PlanError::UndecidableCondition`] when a `<choose>` cannot be decided,
/// or when a companion program's block holds one (its parameters are not
/// the application's).
pub(super) fn assemble_ops(
    app: &ApplicationProgram,
    template_ops: Option<&[LoadOp]>,
    config: &bussard_product::dynamic::DynamicConfig,
    download: Download,
) -> std::result::Result<AssembledOps, PlanError> {
    use super::plan_props::taken_ops;
    // The parameter-only procedure runs an application op whose `AppliesTo`
    // names `par`, or that has none (issue #1052): MergeId 7's no-`AppliesTo`
    // checks and write run in ETS's partial download of `M-0009_A-E804-10-98AD`
    // (#1038), its `full`-only allocation does not.
    //
    // The complete download runs every op, except that a procedure listing
    // its partial downloads after the complete one
    // ([`LoadProcedure::lists_partial_downloads`], the Siemens 07B0 product
    // procedures of issue #614) runs none of their ops
    // ([`LoadProcedure::is_partial_only`]). Any other procedure keeps its
    // `AppliesTo="par"` ops in the complete download, as before: there they
    // restate the complete download's allocation (issue #490) or write the
    // parameter segment.
    let in_download = |lp: &LoadProcedure, i: usize| match download {
        Download::Full => !(lp.lists_partial_downloads() && lp.is_partial_only(i)),
        Download::Par => lp
            .applies_to_of(i)
            .is_none_or(|a| bussard_product::application::applies_to_includes(a, "par")),
    };
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
        return Ok((Vec::new(), false, BTreeMap::new()));
    }
    if let Some(p) = companion_blocks.iter().find(|p| !p.chooses.is_empty()) {
        return Err(PlanError::UndecidableCondition {
            step: 0,
            reason: format!(
                "a companion program's load procedure (MergeId {}) holds a <choose>; \
                 its parameters are not the application's",
                p.merge_id.as_deref().unwrap_or("?")
            ),
        });
    }
    let all_merged = non_empty.iter().all(|p| p.merge_id.is_some());

    // Splice against the master template: only when a template is available AND
    // the app is merged-style (every block is MergeId-tagged). This is the
    // DA.tp / MV-07B0 case; anything else stays on the self-contained path.
    if all_merged && let Some(template) = template_ops {
        // App blocks keyed by parsed MergeId. A block whose id is not numeric
        // cannot match a numeric `<LdCtrlMerge MergeId=N>` and is ignored.
        let mut blocks: BTreeMap<u32, Vec<LoadOp>> = BTreeMap::new();
        let (mut every_branch, mut taken) = (Vec::new(), Vec::new());
        for p in &non_empty {
            if let Some(id) = p.merge_id.as_deref().and_then(|m| m.parse::<u32>().ok()) {
                let ops = taken_ops(app, p, config, &in_download)?;
                every_branch.extend(p.ops.iter());
                taken.extend(ops.iter().cloned());
                blocks.entry(id).or_default().extend(ops);
            }
        }
        let gaps = super::plan_props::partial_rel_mem_gaps(every_branch.into_iter(), &taken);
        for p in &companion_blocks {
            if let Some(id) = p.merge_id.as_deref().and_then(|m| m.parse::<u32>().ok()) {
                let ops = p.ops.iter().enumerate().filter(|(i, _)| in_download(p, *i));
                blocks
                    .entry(id)
                    .or_default()
                    .extend(ops.map(|(_, op)| op.clone()));
            }
        }
        let template = if loads_application_program_2(&blocks) {
            template.to_vec()
        } else if download == Download::Par {
            par_program_1_only(template)
        } else {
            application_program_1_only(template)
        };
        let mut out = Vec::new();
        for op in &template {
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
        return Ok((out, true, gaps));
    }

    let blocks = self_contained_blocks(app);
    let mut out = Vec::new();
    for p in &blocks {
        out.extend(taken_ops(app, p, config, &in_download)?);
    }
    let gaps =
        super::plan_props::partial_rel_mem_gaps(blocks.iter().flat_map(|p| p.ops.iter()), &out);
    Ok((out, false, gaps))
}

/// Lowers a load-state control naming its object by type (`ObjType`) to
/// [`FlashStep::TypedLoadControl`] (issue #961).
///
/// KNX 3/5/3 §3.9.3.2 addresses every System B load control by object index;
/// a vendor procedure that names its object by type is outside it, so the
/// rule is ETS's, from the Gira Eco capture `M-0008_A-C02A-21-B6D8-O007C`
/// (2026-11-07, `ops.txt` ops 61, 62 and 117): `LdCtrlUnload`, `LdCtrlLoad`
/// and `LdCtrlLoadCompleted ObjType="40960"` go out as
/// `A_FunctionPropertyExt_Command` type 40960 instance 1 PID 5 with the
/// 10-octet control value (KNX 3/3/7 §3.4.8.1), and the device answers the
/// new load state.
///
/// # Errors
///
/// [`PlanError::UnsupportedOp`] for a control that names both an index and a
/// type, a type or occurrence [`super::plan_props::prop_object`] refuses, the
/// device object (type 0), or one an `LdCtrlMapError` is in force over
/// (`mapped`), which bussard maps over an indexed `LdCtrlUnload` only.
fn lower_typed_load_control(
    step: usize,
    op: &LoadOp,
    mapped: bool,
) -> std::result::Result<FlashStep, PlanError> {
    let (name, control, lsm_idx, obj_type, occurrence) = match op {
        LoadOp::Unload {
            lsm_idx,
            obj_type,
            occurrence,
        } => (
            "LdCtrlUnload",
            bussard_mgmt::LoadControl::Unload,
            lsm_idx,
            obj_type,
            occurrence,
        ),
        LoadOp::Load {
            lsm_idx,
            obj_type,
            occurrence,
        } => (
            "LdCtrlLoad",
            bussard_mgmt::LoadControl::StartLoading,
            lsm_idx,
            obj_type,
            occurrence,
        ),
        LoadOp::LoadCompleted {
            lsm_idx,
            obj_type,
            occurrence,
        } => (
            "LdCtrlLoadCompleted",
            bussard_mgmt::LoadControl::LoadCompleted,
            lsm_idx,
            obj_type,
            occurrence,
        ),
        other => {
            return Err(PlanError::UnsupportedOp {
                op: format!("{other:?} as a load-state control (step {step})"),
            });
        }
    };
    let refuse = |why: String| PlanError::UnsupportedOp {
        op: format!("{name} {why} (step {step})"),
    };
    if let Some(idx) = lsm_idx {
        return Err(refuse(format!(
            "naming both LsmIdx {idx} and ObjType {}",
            obj_type.unwrap_or_default()
        )));
    }
    if mapped {
        return Err(refuse(
            "by ObjType under an LdCtrlMapError; bussard maps over an indexed LdCtrlUnload only"
                .to_string(),
        ));
    }
    // The object by type and occurrence, by the one rule every op naming an
    // object follows; the device object (type 0) holds no load-state machine.
    let (object_type, occurrence) =
        match super::plan_props::prop_object(step, None, *obj_type, *occurrence)
            .map_err(|e| refuse(e.to_string()))?
        {
            PropObject::Type {
                object_type,
                occurrence,
            } => (object_type, occurrence),
            PropObject::Index(index) => {
                return Err(refuse(format!(
                    "naming the device object (ObjType {}, object {index}), which has no \
                     load-state machine",
                    obj_type.unwrap_or_default()
                )));
            }
        };
    Ok(FlashStep::TypedLoadControl {
        object_type,
        occurrence,
        control,
    })
}

/// The interface object index of Application Program 2 on a System B device
/// (KNX 3/5/3 §3.9.3.3, `OIDX_APPLICATION_PROGRAM_2`).
const OIDX_APPLICATION_PROGRAM_2: u32 = 5;

/// The merge points that carry Application Program 2's allocation (3) and
/// image (5) in the System B complete download (KNX 3/5/3 §3.9.3.1).
const AP2_MERGE_IDS: [u32; 2] = [3, 5];

/// Whether the download loads Application Program 2: the application or its
/// companion program fills one of its merge points (issue #942).
///
/// The 07B0 complete download marks the object 5 rows (`LdCtrlLoad LsmIdx=5`,
/// `MergeId=3`, its `PID_PROGRAM_VERSION`, its `LdCtrlLoadCompleted`) as not
/// executed "if only AP 1 shall be loaded", and ignores errors on its unload
/// (KNX 3/5/3 §3.9.3.4, rows 03, 08, 09, 24, 26). The sweep captures of
/// 2026-11-07 show ETS doing exactly that: the Hager `M-0009_A-E807-10-0EAB`
/// (no block for MergeId 3 or 5) unloads object 5 and loads only object 4
/// (`ops.txt` ops 26, 31, 270, 271), the ABB `M-0002_A-0806-71-AD30-O0007`,
/// whose companion program fills MergeId 3 and 5, loads both.
fn loads_application_program_2(blocks: &BTreeMap<u32, Vec<LoadOp>>) -> bool {
    AP2_MERGE_IDS
        .iter()
        .any(|id| blocks.get(id).is_some_and(|ops| !ops.is_empty()))
}

/// Whether any load procedure of `app` or its companion program carries a
/// non-empty block for an Application Program 2 merge point (MergeId 3 or
/// 5) before the `<choose>` branches are taken: the procedure choice of
/// [`crate::master_template_ops`]. The planner decides again on the blocks
/// it takes ([`loads_application_program_2`]).
pub(crate) fn fills_application_program_2(app: &ApplicationProgram) -> bool {
    app.load_procedures
        .iter()
        .chain(
            app.companion_programs
                .iter()
                .flat_map(|c| c.load_procedures.iter()),
        )
        .any(|p| {
            !p.ops.is_empty()
                && p.merge_id
                    .as_deref()
                    .and_then(|m| m.parse::<u32>().ok())
                    .is_some_and(|id| AP2_MERGE_IDS.contains(&id))
        })
}

/// The complete-download template as ETS runs it when only Application
/// Program 1 is loaded (the master data's `ProcedureSubType="ap1"`): object
/// 5's start, allocation and image merge points, program version and
/// completion are dropped, and its unload is wrapped in the `LdCtrlMapError`
/// pair the `ap1` procedure carries, so a device without object 5 completes
/// it (KNX 3/5/3 §3.9.3.4 remarks: errors accessing the AP2 object are
/// ignored when the product has no AP2). A template without object 5's rows
/// (an `ap1` procedure already) comes back unchanged.
fn application_program_1_only(template: &[LoadOp]) -> Vec<LoadOp> {
    let ap2 = Some(OIDX_APPLICATION_PROGRAM_2);
    let names_ap2 = |op: &LoadOp| match op {
        LoadOp::Load { lsm_idx, .. } | LoadOp::LoadCompleted { lsm_idx, .. } => *lsm_idx == ap2,
        LoadOp::WriteProp {
            obj_idx, prop_id, ..
        } => *obj_idx == ap2 && *prop_id == Some(PID_PROGRAM_VERSION),
        LoadOp::Merge { merge_id } => merge_id
            .as_deref()
            .and_then(|m| m.parse::<u32>().ok())
            .is_some_and(|id| AP2_MERGE_IDS.contains(&id)),
        _ => false,
    };
    if !template
        .iter()
        .any(|op| matches!(op, LoadOp::Load { lsm_idx, .. } if *lsm_idx == ap2))
    {
        return template.to_vec();
    }
    let map = |mapped_error: u32| LoadOp::MapError {
        original_error: Some(MAPPED_UNLOAD_ERROR),
        mapped_error: Some(mapped_error),
    };
    let mut out = Vec::with_capacity(template.len());
    for op in template {
        match op {
            LoadOp::Unload { lsm_idx, .. } if *lsm_idx == ap2 => {
                out.push(map(0));
                out.push(op.clone());
                out.push(map(MAPPED_UNLOAD_ERROR));
            }
            op if names_ap2(op) => {}
            op => out.push(op.clone()),
        }
    }
    out
}

/// The parameter-only procedure as ETS runs it when only Application
/// Program 1 is loaded: every row of object 5 (its table reference reads
/// and checks, unload, load, merge points 3 and 5, program version and
/// completion) is left out, as KNX 3/5/3 §3.9.3.6 marks them "not executed
/// if only AP 1" and ETS's partial download of `M-0009_A-E802-13-7620` sends
/// nothing to object 5 (issue #1052).
fn par_program_1_only(template: &[LoadOp]) -> Vec<LoadOp> {
    let ap2 = Some(OIDX_APPLICATION_PROGRAM_2);
    template
        .iter()
        .filter(|op| match op {
            LoadOp::Unload { lsm_idx, .. }
            | LoadOp::Load { lsm_idx, .. }
            | LoadOp::LoadCompleted { lsm_idx, .. } => *lsm_idx != ap2,
            LoadOp::WriteProp { obj_idx, .. }
            | LoadOp::LoadImageProp { obj_idx, .. }
            | LoadOp::CompareProp { obj_idx, .. } => *obj_idx != ap2,
            LoadOp::Merge { merge_id } => !merge_id
                .as_deref()
                .and_then(|m| m.parse::<u32>().ok())
                .is_some_and(|id| AP2_MERGE_IDS.contains(&id)),
            _ => true,
        })
        .cloned()
        .collect()
}

/// `PID_TABLE_REFERENCE` as a load procedure names it (KNX 3/5/3 §3.9.3.6).
const TABLE_REFERENCE: u32 = bussard_mgmt::tables::PID_TABLE_REFERENCE as u32;

/// What [`assemble_ops`] returns: the ops, whether they were spliced into
/// the master template, and the branch gaps by object index.
pub(super) type AssembledOps = (Vec<LoadOp>, bool, BTreeMap<u32, Vec<(u32, u32)>>);

/// The [`KeptOctets`] of a System B download of `app`: each branch gap of
/// [`assemble_ops`] bound to the relative segment its object allocates
/// (the segment on that load-state machine, [`resolve_rel_segment`]) and cut
/// to the allocation the taken ops make there (the segment's declared size
/// when they make none).
///
/// The rule (issue #411): a `<choose>` branch that writes only part of a
/// segment is planned as ETS downloads it, with the taken branch's writes
/// alone and the rest of the allocation left as the device holds it. ETS's
/// download of `syn-choose-partial-segment`
/// (`captures/synthetic/syn-choose-partial-segment/defaults/ops.txt`, ops
/// 17 and 25 to 27) allocates 256 octets, writes 0..128 and neither reads
/// nor checks 128..256. The MCB check of such a segment reads the device's
/// CRC without comparing it (it covers the kept octets), and the parameter
/// read-back leaves the parameters placed in the gap out of its verdict.
fn kept_from(
    app: &ApplicationProgram,
    ops: &[LoadOp],
    gaps: &BTreeMap<u32, Vec<(u32, u32)>>,
) -> Vec<KeptOctets> {
    if gaps.is_empty() {
        return Vec::new();
    }
    let segments = plan_segments(app);
    gaps.iter()
        .filter_map(|(&object, ranges)| {
            let (segment, declared) =
                resolve_rel_segment(&segments, Some(object), None, &BTreeMap::new())?;
            let allocated = ops
                .iter()
                .rev()
                .find_map(|op| match op {
                    LoadOp::RelSegment {
                        lsm_idx: Some(idx),
                        size,
                        ..
                    } if *idx == object => Some(*size),
                    _ => None,
                })
                .flatten()
                .or(declared)
                .and_then(|a| usize::try_from(a).ok())?;
            let ranges: Vec<(usize, usize)> = ranges
                .iter()
                .filter_map(|&(start, end)| {
                    let start = usize::try_from(start).ok()?;
                    let end = usize::try_from(end).ok()?.min(allocated);
                    (start < end).then_some((start, end))
                })
                .collect();
            (!ranges.is_empty()).then_some(KeptOctets {
                object,
                segment,
                allocated,
                ranges,
                address: None,
            })
        })
        .collect()
}

/// The octets a download of `app` under `overrides` leaves as the device
/// holds them (issue #411, [`KeptOctets`]): what the planner keeps, for the
/// read-back and the plan, which decode a device's parameters without a
/// [`FlashPlan`] at hand. System B: the octets of a segment the taken
/// `<choose>` branch writes in part; System 7: the octets of a segment the
/// procedure allocates in parts (in a taken branch or outside any
/// `<choose>`) and leaves between or after them
/// ([`super::plan_sys7::sys7_kept_octets`]). Empty for a property-only
/// application, for a System B procedure without a `<choose>`, and when the load
/// procedure cannot be decided (the planner refuses such a plan on its own).
///
/// # Errors
///
/// [`PlanError::ModuleProcedure`] when a module definition's load procedure
/// cannot be resolved for the reached instances (issue #959): which octets
/// the download keeps is then not known, and an empty list would read as
/// "every octet written".
pub fn kept_octets(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
    memo: &bussard_product::dynamic::DynamicMemo<'_, ApplicationProgram>,
) -> Result<Vec<KeptOctets>, PlanError> {
    let Some(profile) = app
        .mask_version
        .as_deref()
        .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())
        .map(bussard_mgmt::MaskProfile::from_mask)
    else {
        return Ok(Vec::new());
    };
    let system_7 = profile.is_system_7();
    if !system_7
        && (!profile.capabilities().flash
            || app.load_procedures.iter().all(|p| p.chooses.is_empty()))
    {
        return Ok(Vec::new());
    }
    // The procedures the planner runs, module instances resolved.
    let resolved = resolve_module_procedures(app, overrides, memo, None)?;
    let resolved_memo;
    let (app, memo) = match &resolved {
        None => (app, memo),
        Some(r) => {
            resolved_memo = r.memo();
            (&r.app, &resolved_memo)
        }
    };
    let config = memo.evaluate_for(app, overrides);
    // System 7: a procedure may split a segment outside any `<choose>` too
    // (issue #657, the Jung `A-5015-13`), so the check runs without one.
    if system_7 {
        return Ok(match super::plan_props::guarded_ops(app, &config) {
            Ok(mut ops) => {
                ops.truncate(super::plan_sys7::sys7_procedure_end(&ops));
                super::plan_sys7::sys7_kept_octets(app, &ops, |seg| {
                    let data = seg.data.as_ref().map_or(0, Vec::len);
                    let size = seg.size.and_then(|s| usize::try_from(s).ok()).unwrap_or(0);
                    data.max(size)
                })
            }
            Err(_) => Vec::new(),
        });
    }
    Ok(match assemble_ops(app, None, &config, Download::Full) {
        Ok((ops, _, gaps)) => kept_from(app, &ops, &gaps),
        Err(_) => Vec::new(),
    })
}

/// A program with its module definitions' load procedures resolved for one
/// set of parameter values (issue #959), and the Dynamic evaluation they
/// were resolved under.
pub(super) struct ModuleResolved {
    /// The program, its load procedures the resolved ones.
    pub(super) app: ApplicationProgram,
    /// The values the evaluation was made for.
    overrides: BTreeMap<String, String>,
    /// The caller's evaluation of them.
    config: std::sync::Arc<bussard_product::dynamic::DynamicConfig>,
}

impl ModuleResolved {
    /// A memo for the resolved program holding the caller's evaluation, so
    /// the Dynamic section is not evaluated again for the same values: the
    /// program's Dynamic section is the original's.
    pub(super) fn memo(&self) -> bussard_product::dynamic::DynamicMemo<'_, ApplicationProgram> {
        bussard_product::dynamic::DynamicMemo::seeded(
            &self.app,
            &self.overrides,
            std::sync::Arc::clone(&self.config),
        )
    }
}

/// `app` with its module definitions' load procedures resolved for the
/// module instances `overrides` reach
/// ([`ApplicationProgram::resolved_load_procedures`], issue #959), `None`
/// for a program without one: the one resolution both [`plan_flash`] and
/// [`kept_octets`] run. The evaluation is the caller's `memo`'s.
///
/// A block no application marker takes is spliced at the master template's
/// marker of its `MergeId`, as an application block is; with a template
/// (`template_ops`) and every block merged, a block the template has no
/// marker for is refused rather than dropped.
///
/// # Errors
///
/// [`PlanError::ModuleProcedure`] when the procedures cannot be resolved, or
/// such a block has no marker in the template.
pub(super) fn resolve_module_procedures(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
    memo: &bussard_product::dynamic::DynamicMemo<'_, ApplicationProgram>,
    template_ops: Option<&[LoadOp]>,
) -> Result<Option<ModuleResolved>, PlanError> {
    if app.module_load_procedures.is_empty()
        && app
            .companion_programs
            .iter()
            .all(|c| c.module_load_procedures.is_empty())
    {
        return Ok(None);
    }
    let config = memo.evaluate_for(app, overrides);
    let Some(resolved) = app.resolved_load_procedures(&config)? else {
        return Ok(None);
    };
    let all_merged = resolved
        .load_procedures
        .iter()
        .filter(|p| !p.ops.is_empty())
        .all(|p| p.merge_id.is_some());
    if let Some(template) = template_ops.filter(|_| all_merged) {
        for (merge, module) in &resolved.unspliced {
            let marked = template.iter().any(|op| {
                matches!(op, LoadOp::Merge { merge_id: Some(id) }
                    if id.parse::<u32>().ok().is_some_and(|n| merge.parse::<u32>().ok() == Some(n)))
            });
            if !marked {
                return Err(PlanError::ModuleProcedure(
                    bussard_product::application::ModuleProcedureError {
                        module: module.clone(),
                        reason: format!(
                            "neither the application's procedures nor the master template \
                             have the <LdCtrlMerge MergeId=\"{merge}\"> its MergeId names, so \
                             bussard does not know where it runs"
                        ),
                    },
                ));
            }
        }
    }
    let mut resolved_app = app.clone();
    resolved_app.load_procedures = resolved.load_procedures;
    Ok(Some(ModuleResolved {
        app: resolved_app,
        overrides: overrides.clone(),
        config,
    }))
}

/// The blocks a self-contained download (no master-template splice) runs, in
/// order: merged-style (every block MergeId-tagged) → all blocks in ascending
/// MergeId order; else the richest single block. Empty blocks never count.
pub(super) fn self_contained_blocks(app: &ApplicationProgram) -> Vec<&LoadProcedure> {
    let non_empty: Vec<&LoadProcedure> = app
        .load_procedures
        .iter()
        .filter(|p| !p.ops.is_empty())
        .collect();
    let all_merged = non_empty.iter().all(|p| p.merge_id.is_some());
    if all_merged && non_empty.len() > 1 {
        let mut blocks = non_empty;
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
        return blocks;
    }
    non_empty
        .into_iter()
        .max_by_key(|p| p.ops.len())
        .into_iter()
        .collect()
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

/// Whether the application declares a relative segment of its own on load
/// state machine `lsm` (the ABB i-bus group-object table, issue #113).
fn declares_segment_on(segments: &HashMap<String, CodeSegment>, lsm: u32) -> bool {
    segments
        .values()
        .any(|s| s.kind == SegmentKind::Relative && s.load_state_machine == Some(lsm))
}

/// Cuts a `WriteRelMem` image to the op's `Size` (issue #564).
///
/// ABB Caldion `M-0002_A-4980-17-A22E-O01EC` declares a 135168-octet
/// `RelativeSegment`, allocates 128444 octets (`LdCtrlRelSegment Size`) and
/// writes 128444 (`LdCtrlWriteRelMem Size`); ETS wrote 128444 octets. The
/// streamed image, the MCB check that follows (`LoadImageProp`) and the
/// read-back all use the cut image, so they agree on the length. A `Size`
/// at or above the image length, or none, keeps the image as it is.
///
/// A parameter value placed at or past `Size` refuses: cutting it would drop
/// a configured value without a word.
pub(super) fn bound_write_rel_mem(
    segment_id: &str,
    mut bytes: Vec<u8>,
    size: Option<u32>,
    placed: Option<&std::collections::BTreeSet<usize>>,
) -> std::result::Result<Vec<u8>, String> {
    let Some(size) = size.and_then(|s| usize::try_from(s).ok()) else {
        return Ok(bytes);
    };
    if size >= bytes.len() {
        return Ok(bytes);
    }
    if let Some(&octet) = placed.and_then(|p| p.range(size..).next()) {
        return Err(format!(
            "segment {segment_id} image is {} octets, its LdCtrlWriteRelMem writes {size}, \
             but a parameter value sits at octet {octet}",
            bytes.len()
        ));
    }
    bytes.truncate(size);
    Ok(bytes)
}

/// Resolves the bytes a `WriteRelMem` streams from its `AppliesTo` hint. `full`
/// (or unset) streams the current relative segment's code `<Data>`; `par`
/// streams the computed parameter image for that segment; the combined
/// `full,par` (the real MDT / Jung shape, one write covering the whole segment)
/// streams the parameter image when parameters target the segment, else the
/// code `<Data>` — either way the segment's own bytes, so a following
/// `LoadImageProp` MCB check runs over a real image.
///
/// A segment with neither a parameter image nor a code `<Data>` that its
/// allocation pre-fills (`prefill`: the fill byte and the allocated size,
/// `Mode` bit 0) holds the fill byte throughout, and that is its image (issue
/// #1026). ETS writes none of it (the Gira `M-0008_A-6010-20-4D55`: a
/// 256-octet segment allocated with fill `00`, no memory parameter, no memory
/// write); the executor streams only what differs from the fill, so nothing,
/// and an MCB check of the object runs over the octets the device holds.
pub(super) fn resolve_write_image(
    segments: &HashMap<String, CodeSegment>,
    applies_to: Option<&str>,
    current_segment: Option<&str>,
    param_images: &BTreeMap<String, Vec<u8>>,
    prefill: Option<(u8, u32)>,
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

    let wants_params =
        applies_to.is_some_and(|a| bussard_product::application::applies_to_names(a, "par"));

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
    match segments.get(&seg_id).and_then(|s| s.data.clone()) {
        Some(bytes) => Ok((seg_id, ImageKind::Code, bytes)),
        None => match prefill.and_then(|(fill, size)| Some((fill, usize::try_from(size).ok()?))) {
            Some((fill, size)) => Ok((seg_id, ImageKind::Parameters, vec![fill; size])),
            None => Err(format!("segment {seg_id} carries no code image (<Data>)")),
        },
    }
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
    use crate::flash::test_support::plan_flash_default;
    use crate::flash::test_support::{fabricated_app, no_overrides};
    use bussard_product::application::parse_application_program;

    use crate::flash::labels::trace;
    use bussard_product::application::ApplicationProgram;
    use std::collections::BTreeMap;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    fn plan_lowers_supported_procedure() -> Result<(), Box<dyn std::error::Error>> {
        let app = fabricated_app();
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        assert_eq!(plan.identity.mask_version, "07B0");
        // Connect/Disconnect are session-boundary no-ops; 8 device steps remain.
        assert_eq!(
            plan.steps,
            vec![
                FlashStep::Unload {
                    target: Some(4),
                    absent_ok: false
                },
                FlashStep::StartLoading { target: Some(4) },
                FlashStep::AllocateSegment {
                    size: 6,
                    target: Some(4),
                    fill: SegmentFill::NONE,
                },
                FlashStep::WriteRelMem {
                    offset: 0,
                    image: ImageRef {
                        segment_id: "M-1_A-1_RS-1".to_string(),
                        kind: ImageKind::Code,
                        len: 6,
                        offset: 0,
                    },
                    target: Some(0),
                },
                FlashStep::AllocateSegment {
                    size: 1,
                    target: Some(4),
                    fill: SegmentFill::NONE,
                },
                FlashStep::WriteRelMem {
                    offset: 0,
                    image: ImageRef {
                        segment_id: "M-1_A-1_RS-2".to_string(),
                        kind: ImageKind::Parameters,
                        len: 1,
                        offset: 0,
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
        Ok(())
    }

    #[test]
    fn write_rel_mem_without_applies_to_streams_the_parameter_image()
    -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-P", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;

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
        Ok(())
    }

    #[test]
    fn plan_lowers_master_reset() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-MR", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
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
                channel_number: 0,
                ..
            }
        ));
        let alloc_pos = plan
            .steps
            .iter()
            .position(|s| matches!(s, FlashStep::AllocateSegment { .. }))
            .ok_or("the plan allocates a segment")?;
        let write_pos = plan
            .steps
            .iter()
            .position(|s| matches!(s, FlashStep::WriteRelMem { .. }))
            .ok_or("the plan writes relative memory")?;
        assert!(
            alloc_pos < mr_pos && mr_pos < write_pos,
            "steps {:?}",
            plan.steps
        );
        // The trace names the reconnect-and-resume master-reset step.
        assert!(trace(&plan).iter().any(|l| l.contains("master reset")));
        Ok(())
    }

    /// A System B procedure with `LdCtrlDelay` (issue #615): the given
    /// milliseconds lower to a pause step in procedure order, and the trace
    /// names it. An op without `MilliSeconds` refuses the plan.
    #[test]
    fn test_plan_flash_lowers_delay() -> Result<(), Box<dyn std::error::Error>> {
        let app_xml = |delay: &str| {
            format!(
                r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-DL" MaskVersion="MV-07B0" Name="DL"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code><RelativeSegment Id="M-1_A-DL_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             {delay}
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
            )
        };
        let plan_for =
            |delay: &str| -> Result<Result<FlashPlan, PlanError>, Box<dyn std::error::Error>> {
                let app = parse_application_program("M-1_A-DL", app_xml(delay).as_bytes())?;
                Ok(plan_flash_default(
                    &app,
                    "1.1.4",
                    0x07B0,
                    &no_overrides(),
                    &BTreeMap::new(),
                    None,
                    &BTreeMap::new(),
                ))
            };
        let plan = plan_for(r#"<LdCtrlDelay MilliSeconds="200" />"#)??;
        let n = plan.steps.len();
        assert!(n >= 2);
        assert_eq!(
            plan.steps[n - 2..],
            [FlashStep::Delay { milliseconds: 200 }, FlashStep::Restart]
        );
        assert!(trace(&plan).iter().any(|l| l.contains("wait 200 ms")));
        assert!(matches!(
            plan_for("<LdCtrlDelay />")?,
            Err(PlanError::UnsupportedOp { op }) if op.contains("LdCtrlDelay")
        ));
        Ok(())
    }

    /// Plans a 07B0 program whose relative segments (one per LSM in `lsms`)
    /// carry no `<Data>` and no parameter, around the procedure `body`.
    fn plan_dataless(
        lsms: &[u32],
        body: &str,
    ) -> Result<Result<FlashPlan, PlanError>, Box<dyn std::error::Error>> {
        let segments: String = lsms
            .iter()
            .map(|lsm| {
                format!(
                    r#"<RelativeSegment Id="M-1_A-EMPTY_RS-{lsm:02}-00000" Size="256" LoadStateMachine="{lsm}" Offset="0" />"#
                )
            })
            .collect();
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-EMPTY" MaskVersion="MV-07B0" Name="Empty"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code>{segments}</Code>
           <LoadProcedures><LoadProcedure>{body}<LdCtrlRestart /></LoadProcedure></LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        let app = parse_application_program("M-1_A-EMPTY", xml.as_bytes())?;
        Ok(plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        ))
    }

    /// Issue #1026: a write into a segment with neither `<Data>` nor a memory
    /// parameter streams the fill when its allocation pre-fills it (the Gira
    /// `M-0008_A-6010-20-4D55`: ETS allocates 256 octets with fill `00` and
    /// writes none; the executor streams only what differs from the fill).
    /// The image is the allocation's fill octets, so an MCB check of the
    /// object compares the device's CRC over what it holds.
    #[test]
    fn test_plan_flash_prefilled_segment_without_image_streams_the_fill() -> TestResult {
        let plan = plan_dataless(
            &[4],
            r#"<LdCtrlUnload LsmIdx="4" /><LdCtrlLoad LsmIdx="4" />
               <LdCtrlRelSegment LsmIdx="4" Size="200" Mode="1" Fill="170" />
               <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="200" Verify="true" />
               <LdCtrlLoadCompleted LsmIdx="4" />
               <LdCtrlLoadImageProp ObjIdx="4" PropId="27" />"#,
        )??;
        let written: Vec<&ImageRef> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::WriteRelMem { image, .. } => Some(image),
                _ => None,
            })
            .collect();
        let [image] = written[..] else {
            return Err(format!("one WriteRelMem expected, got {}", written.len()).into());
        };
        assert_eq!(image.len, 200);
        assert_eq!(plan.image_bytes(&image.segment_id), Some(&[0xAA; 200][..]));
        let checked = plan.steps.iter().find_map(|s| match s {
            FlashStep::LoadImageProp { image, .. } => Some(image.clone()),
            _ => None,
        });
        assert_eq!(checked.flatten().as_ref(), Some(image));
        Ok(())
    }

    /// Issue #1026: an allocation that keeps the memory (`Mode` 0) leaves a
    /// segment without an image refused, also when another object's
    /// allocation pre-fills: a write takes only its own object's fill, and a
    /// write whose object has no allocation of its own borrows none.
    #[test]
    fn test_plan_flash_dataless_segment_without_its_own_prefill_refuses() -> TestResult {
        let no_image = |plan: Result<FlashPlan, PlanError>| matches!(plan, Err(PlanError::UnresolvableImage { reason, .. }) if reason.contains("no code image"));
        // Mode 0 on the written object.
        assert!(no_image(plan_dataless(
            &[4],
            r#"<LdCtrlLoad LsmIdx="4" />
               <LdCtrlRelSegment LsmIdx="4" Size="256" Mode="0" Fill="0" />
               <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="256" />
               <LdCtrlLoadCompleted LsmIdx="4" />"#,
        )?));
        // Object 4 pre-filled, object 5 allocated with Mode 0, object 5 written.
        assert!(no_image(plan_dataless(
            &[4, 5],
            r#"<LdCtrlLoad LsmIdx="4" /><LdCtrlLoad LsmIdx="5" />
               <LdCtrlRelSegment LsmIdx="4" Size="256" Mode="1" Fill="0" />
               <LdCtrlRelSegment LsmIdx="5" Size="128" Mode="0" Fill="0" />
               <LdCtrlWriteRelMem ObjIdx="5" Offset="0" Size="128" />
               <LdCtrlLoadCompleted LsmIdx="5" /><LdCtrlLoadCompleted LsmIdx="4" />"#,
        )?));
        // The same where only object 4 declares a segment.
        assert!(no_image(plan_dataless(
            &[4],
            r#"<LdCtrlLoad LsmIdx="4" /><LdCtrlLoad LsmIdx="5" />
               <LdCtrlRelSegment LsmIdx="4" Size="256" Mode="1" Fill="0" />
               <LdCtrlRelSegment LsmIdx="5" Size="128" Mode="0" Fill="0" />
               <LdCtrlWriteRelMem ObjIdx="5" Offset="0" Size="128" />
               <LdCtrlLoadCompleted LsmIdx="5" /><LdCtrlLoadCompleted LsmIdx="4" />"#,
        )?));
        // Object 4 pre-filled, object 5 written without an allocation of its own.
        assert!(no_image(plan_dataless(
            &[4],
            r#"<LdCtrlLoad LsmIdx="4" />
               <LdCtrlRelSegment LsmIdx="4" Size="256" Mode="1" Fill="0" />
               <LdCtrlWriteRelMem ObjIdx="5" Offset="0" Size="256" />
               <LdCtrlLoadCompleted LsmIdx="4" />"#,
        )?));
        Ok(())
    }

    #[test]
    fn plan_threads_rel_segment_fill_flag_data_driven() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-FILL", fill_xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
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
            SegmentFill::filled(0),
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
        let app = parse_application_program("M-1_A-DATP", da_tp_xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
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
            SegmentFill::NONE,
            "a DA.tp-shape allocation (no Fill) must stay no-fill (byte-identical)"
        );
        Ok(())
    }

    /// Issue #623: the plan of a re-download onto a device that already holds
    /// the application (the `par` procedure of a same-application device),
    /// for a product whose procedure has a Master Reset with erase code 4,
    /// erases resident objects, so the executor takes no resident-MCB skip.
    /// The confirmed restart (1) and the address reset (3) erase no object.
    #[test]
    fn test_erases_resident_objects_master_reset_erase_code_4_over_same_application()
    -> Result<(), Box<dyn std::error::Error>> {
        for (code, erases) in [(4u8, true), (2, true), (6, true), (1, false), (3, false)] {
            let xml = format!(
                r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-MR" MaskVersion="MV-07B0" Name="MR"
            LoadProcedureStyle="ProductDefault">
          <Static>
           <Code><RelativeSegment Id="M-1_A-MR_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="6" Mode="0" Fill="0" />
             <LdCtrlMasterReset EraseCode="{code}" ChannelNumber="0" />
             <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="6" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
            );
            let app = parse_application_program("M-1_A-MR", xml.as_bytes())?;
            let mut plan = plan_flash_default(
                &app,
                "1.1.4",
                0x07B0,
                &no_overrides(),
                &BTreeMap::new(),
                None,
                &BTreeMap::new(),
            )?;
            // The device already runs this application: the `par` procedure.
            plan.use_par_procedure(None);
            assert!(!plan.has_factory_reset(), "erase code {code}");
            assert_eq!(plan.erases_resident_objects(), erases, "erase code {code}");
        }
        Ok(())
    }

    #[test]
    fn plan_defaults_master_reset_erase_code() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-MR2", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::MasterReset {
                erase_code: 1,
                channel_number: 0,
                ..
            }
        )));
        Ok(())
    }

    #[test]
    fn plan_refuses_non_system_b() -> Result<(), Box<dyn std::error::Error>> {
        // System 2 (0x0300): neither System B nor System 7, refused at the gate.
        // (System 7 masks 0705/0701 are now supported — issue #49 — so they no
        // longer hit this gate; see `plan_lowers_system_7`.)
        let app = fabricated_app();
        let err = plan_flash_default(
            &app,
            "1.1.4",
            0x0300,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        assert!(matches!(err, PlanError::NotSystemB { .. }), "{err:?}");
        Ok(())
    }

    #[test]
    fn test_plan_flash_mask_ffff_names_security_activation()
    -> Result<(), Box<dyn std::error::Error>> {
        // A security-activated device answers a plain descriptor read with FFFF.
        let app = fabricated_app();
        match plan_flash_default(
            &app,
            "1.1.2",
            0xFFFF,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        ) {
            Err(err @ PlanError::SecurityActivated { .. }) => {
                assert!(err.to_string().contains("--keyring"), "{err}");
                Ok(())
            }
            other => Err(format!("expected SecurityActivated, got {other:?}").into()),
        }
    }

    #[test]
    fn plan_refuses_mask_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        // App declares MV-07B0 but the device is a different System B medium
        // (0x57B0 IP): the exact-mask compare refuses it.
        let app = fabricated_app();
        let err = plan_flash_default(
            &app,
            "1.1.4",
            0x57B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        assert!(matches!(err, PlanError::MaskMismatch { .. }), "{err:?}");
        Ok(())
    }

    #[test]
    fn plan_refuses_unsupported_op() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-2", xml.as_bytes())?;
        let err = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        match err {
            PlanError::UnsupportedOp { op } => assert!(op.contains("TaskSegment"), "{op}"),
            other => panic!("expected UnsupportedOp, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn plan_lowers_load_image_prop() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-3", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;

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
        Ok(())
    }

    #[test]
    fn plan_dedupes_identical_consecutive_allocations() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-83_A-7", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;

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
        Ok(())
    }

    /// Issue #840 (ekinex `A-4945-10`, KNX IP interface secure): a merged
    /// 07B0 program without group objects allocates the 2-octet empty table
    /// on objects 1 to 3, writes none of them, and checks each table's MCB on
    /// its own object without an image; the parameters are still written.
    #[test]
    fn test_plan_flash_program_without_group_objects_writes_no_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-0002_A-2" ApplicationNumber="2" ApplicationVersion="16"
            MaskVersion="MV-07B0" Name="IP" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code>
            <RelativeSegment Id="M-0002_A-2_RS-04-00000" Size="4" LoadStateMachine="4" Offset="0"><Data>AQIDBA==</Data></RelativeSegment>
           </Code>
           <AddressTable MaxEntries="200" />
           <AssociationTable MaxEntries="200" />
           <ComObjectTable />
           <LoadProcedures>
            <LoadProcedure MergeId="2">
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="4" Mode="1" Fill="0" />
            </LoadProcedure>
            <LoadProcedure MergeId="7">
             <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />
             <LdCtrlLoadImageProp ObjIdx="2" PropId="27" />
             <LdCtrlLoadImageProp ObjIdx="3" PropId="27" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0002_A-2", xml.as_bytes())?;
        let template = bussard_product::MasterTemplate::builtin_for_mask("07B0")
            .ok_or("a built-in 07B0 template")?;
        let tables = crate::build_table_images(
            None,
            "1.1.1".parse()?,
            &app,
            &no_overrides(),
            &bussard_product::dynamic::DynamicMemo::new(&app),
        );
        assert_eq!(tables.get(&3), Some(&vec![0, 0]));
        let plan = plan_flash_default(
            &app,
            "1.1.1",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            Some(&template.ops),
            &tables,
        )?;
        for idx in 1..=3 {
            assert!(
                plan.steps.iter().any(|s| matches!(s,
                    FlashStep::AllocateSegment { size: 2, target: Some(t), fill }
                        if *t == idx && *fill == SegmentFill::NONE)),
                "object {idx} allocated 2 octets without fill"
            );
            assert!(
                !plan.steps.iter().any(|s| matches!(s,
                    FlashStep::WriteRelMem { target: Some(t), .. } if *t == idx)),
                "object {idx} written"
            );
            assert!(
                plan.steps.iter().any(|s| matches!(s,
                    FlashStep::LoadImageProp { obj_idx, image: None, .. } if *obj_idx == idx)),
                "object {idx}'s MCB read without an image: {:?}",
                plan.steps
            );
        }
        Ok(())
    }

    /// A System B app whose 16-octet `RelativeSegment` is allocated and written
    /// with `Size="8"` (the ABB Caldion shape of issue #564), with one 8-bit
    /// parameter at `param_offset`.
    fn write_size_app(param_offset: u32) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-2_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="Caldion" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code>
            <RelativeSegment Id="M-2_A-1_RS-04-00000" Size="16" LoadStateMachine="4" Offset="0"><Data>AAECAwQFBgcICQoLDA0ODw==</Data></RelativeSegment>
           </Code>
           <ParameterTypes><ParameterType Id="M-2_A-1_PT-1" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType></ParameterTypes>
           <Parameters><Parameter Id="M-2_A-1_P-1" Name="p" ParameterType="M-2_A-1_PT-1" Value="170"><Memory CodeSegment="M-2_A-1_RS-04-00000" Offset="{param_offset}" BitOffset="0" /></Parameter></Parameters>
           <ParameterRefs><ParameterRef Id="M-2_A-1_P-1_R-1" RefId="M-2_A-1_P-1" /></ParameterRefs>
           <LoadProcedures>
            <LoadProcedure MergeId="2">
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="8" Mode="1" Fill="0" />
            </LoadProcedure>
            <LoadProcedure MergeId="4">
             <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="8" Verify="true" />
            </LoadProcedure>
            <LoadProcedure MergeId="7">
             <LdCtrlLoadImageProp ObjIdx="4" PropId="27" />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        Ok(parse_application_program("M-2_A-1", xml.as_bytes())?)
    }

    /// Issue #564: `LdCtrlWriteRelMem Size` bounds the streamed image; the
    /// MCB check and the plan image use the same length.
    #[test]
    fn test_plan_flash_write_rel_mem_honours_size() -> Result<(), Box<dyn std::error::Error>> {
        let plan = plan_flash_default(
            &write_size_app(2)?,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let seg = "M-2_A-1_RS-04-00000";
        let write = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::WriteRelMem { image, .. } => Some(image),
                _ => None,
            })
            .ok_or("no write")?;
        assert_eq!((write.segment_id.as_str(), write.len), (seg, 8));
        assert_eq!(
            plan.image_bytes(seg),
            Some(&[0x00, 0x01, 0xAA, 0x03, 0x04, 0x05, 0x06, 0x07][..])
        );
        let check = plan
            .steps
            .iter()
            .find_map(|s| match s {
                FlashStep::LoadImageProp { image, .. } => image.as_ref(),
                _ => None,
            })
            .ok_or("no MCB check")?;
        assert_eq!((check.segment_id.as_str(), check.len), (seg, 8));
        Ok(())
    }

    /// Issue #564: a parameter value past the written `Size` refuses, naming
    /// the segment and both sizes, instead of being cut off.
    #[test]
    fn test_plan_flash_write_rel_mem_refuses_a_parameter_past_size()
    -> Result<(), Box<dyn std::error::Error>> {
        let err = plan_flash_default(
            &write_size_app(10)?,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        );
        assert!(
            matches!(&err, Err(PlanError::UnresolvableImage { reason, .. })
                if reason.contains("M-2_A-1_RS-04-00000")
                    && reason.contains("16 octets")
                    && reason.contains("writes 8")
                    && reason.contains("octet 10")),
            "{err:?}"
        );
        Ok(())
    }

    #[test]
    fn plan_dedupes_a_restated_allocation_when_segments_span_several_lsms()
    -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-2_A-806", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;

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
        Ok(())
    }

    #[test]
    fn plan_keeps_distinct_allocations() -> Result<(), Box<dyn std::error::Error>> {
        // Two RelSegment ops for DIFFERENT segments (different sizes) must NOT be
        // deduped — the fabricated app allocates a 6-byte code segment and a
        // 1-byte parameter segment.
        let app = fabricated_app();
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let allocs = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::AllocateSegment { .. }))
            .count();
        assert_eq!(allocs, 2, "distinct segments keep distinct allocations");
        Ok(())
    }

    #[test]
    fn test_plan_flash_compare_prop_by_object_type() -> Result<(), Box<dyn std::error::Error>> {
        // Issue #1021: the Gira `M-0008_A-E000-10-89B0-O0077` compares PID
        // 207 of the object of type 65281 (no `ObjIdx`); ETS describes and
        // reads that object, so the step keeps the type, never object 0, and
        // the description read before it names the type too. `ObjType="0"`
        // is the device object.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-4" ApplicationNumber="8" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="Typed" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code><RelativeSegment Id="M-1_A-4_RS-1" Size="4" LoadStateMachine="4" Offset="0"><Data>AAECAw==</Data></RelativeSegment></Code>
           <LoadProcedures>
            <LoadProcedure MergeId="1">
             <LdCtrlCompareProp InlineData="0008" ObjType="0" PropId="12" />
             <LdCtrlCompareProp InlineData="01" ObjType="65281" PropId="207" />
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="4" />
             <LdCtrlWriteRelMem AppliesTo="full" ObjIdx="0" Offset="0" Size="4" />
             <LdCtrlLoadCompleted LsmIdx="4" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-4", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let typed = crate::flash::PropObject::Type {
            object_type: 65281,
            occurrence: 0,
        };
        let objects: Vec<(crate::flash::PropObject, u32)> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::CompareProp {
                    object, prop_id, ..
                } => Some((*object, *prop_id)),
                _ => None,
            })
            .collect();
        assert_eq!(
            objects,
            vec![(crate::flash::PropObject::Index(0), 12), (typed, 207)]
        );
        assert!(
            plan.steps.iter().any(|s| *s
                == FlashStep::DescribeProp {
                    object: typed,
                    prop_id: 207,
                    unwritten: None,
                }),
            "the description read names the type: {:?}",
            plan.steps
        );
        assert!(!plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::DescribeProp {
                object: crate::flash::PropObject::Index(0),
                prop_id: 207,
                unwritten: None,
            }
        )));
        Ok(())
    }

    #[test]
    fn plan_lowers_compare_prop() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-4", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;

        let compares: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::CompareProp { .. }))
            .collect();
        assert_eq!(compares.len(), 2, "both CompareProp ops lower");
        match compares[0] {
            FlashStep::CompareProp {
                object,
                prop_id,
                expected,
                mask,
                start_element,
            } => {
                assert_eq!(*start_element, 1);
                assert_eq!(*object, crate::flash::PropObject::Index(0));
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
        Ok(())
    }

    /// The MDT 07B0 shape (BWM-xxxxx-03S, `M-0083_A-047A-11-B6E0`): the
    /// hardware variant is a parameter, and a `<choose>` on it picks the one
    /// PID 78 compare that variant must pass.
    fn hardware_variant_app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-5" ApplicationNumber="9" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="BWM" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code><RelativeSegment Id="M-1_A-5_RS-1" Size="4" LoadStateMachine="4" Offset="0"><Data>AAECAw==</Data></RelativeSegment></Code>
           <ParameterTypes>
            <ParameterType Id="M-1_A-5_PT-v" Name="v"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="3" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-1_A-5_P-579" Name="variant" ParameterType="M-1_A-5_PT-v" Value="0" />
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-1_A-5_P-579_R-1032" RefId="M-1_A-5_P-579" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure MergeId="2">
             <choose ParamRefId="M-1_A-5_P-579_R-1032">
              <when test="0"><LdCtrlCompareProp InlineData="008300000000" ObjIdx="0" PropId="78" /></when>
              <when test="1"><LdCtrlCompareProp InlineData="008300000407" ObjIdx="0" PropId="78" /></when>
              <when test="2"><LdCtrlCompareProp InlineData="008300000406" ObjIdx="0" PropId="78" /></when>
             </choose>
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="4" Mode="1" Fill="0" />
            </LoadProcedure>
            <LoadProcedure MergeId="4">
             <LdCtrlWriteRelMem AppliesTo="full" ObjIdx="4" Offset="0" Size="4" Verify="true" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        Ok(parse_application_program("M-1_A-5", xml.as_bytes())?)
    }

    /// The PID 78 compares a System B plan of [`hardware_variant_app`] runs
    /// for `variant`, as their expected bytes.
    fn variant_compares(variant: Option<&str>) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let app = hardware_variant_app()?;
        let mut overrides = BTreeMap::new();
        if let Some(v) = variant {
            overrides.insert("P-579_R-1032".to_string(), v.to_string());
        }
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &overrides,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        Ok(plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::CompareProp {
                    prop_id: 78,
                    expected,
                    ..
                } => expected.clone(),
                _ => None,
            })
            .collect())
    }

    #[test]
    fn test_plan_flash_runs_only_the_taken_hardware_variant_compare() -> TestResult {
        // Issue #402: the System B lowering used to concatenate every branch,
        // planning three mutually exclusive PID 78 compares.
        assert_eq!(
            variant_compares(Some("2"))?,
            vec![vec![0x00, 0x83, 0x00, 0x00, 0x04, 0x06]]
        );
        assert_eq!(
            variant_compares(None)?,
            vec![vec![0x00, 0x83, 0x00, 0x00, 0x00, 0x00]]
        );
        // A value no branch tests (and no default branch): no compare at all.
        assert!(variant_compares(Some("3"))?.is_empty());
        Ok(())
    }

    #[test]
    fn test_plan_flash_splices_only_the_taken_branch_into_the_template() -> TestResult {
        let app = hardware_variant_app()?;
        let template = [
            LoadOp::Connect,
            LoadOp::Merge {
                merge_id: Some("2".to_string()),
            },
            LoadOp::Merge {
                merge_id: Some("4".to_string()),
            },
            LoadOp::Disconnect,
        ];
        let memo = bussard_product::dynamic::DynamicMemo::new(&app);
        let overrides = BTreeMap::from([("P-579_R-1032".to_string(), "1".to_string())]);
        let (ops, spliced, _) = assemble_ops(
            &app,
            Some(&template),
            &memo.evaluate_for(&app, &overrides),
            Download::Full,
        )?;
        assert!(spliced);
        let compares: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                LoadOp::CompareProp { inline_data, .. } => inline_data.clone(),
                _ => None,
            })
            .collect();
        assert_eq!(compares, vec![vec![0x00, 0x83, 0x00, 0x00, 0x04, 0x07]]);
        Ok(())
    }

    #[test]
    fn test_plan_flash_keeps_the_octets_a_choose_leaves_unwritten() -> TestResult {
        // The MDT JTA-01 shape (`M-0083_A-00A2-10-6169`): parameter P-324
        // picks a full write of the segment or one that skips octets 4..6,
        // which ETS leaves as the device holds them (issue #411).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-6" ApplicationNumber="9" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="JTA" LoadProcedureStyle="MergedProcedure">
          <Static>
           <Code><RelativeSegment Id="M-1_A-6_RS-1" Size="8" LoadStateMachine="4" Offset="0"><Data>AAECAwQFBgc=</Data></RelativeSegment></Code>
           <ParameterTypes>
            <ParameterType Id="M-1_A-6_PT-v" Name="v"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="1" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-1_A-6_P-324" Name="keep" ParameterType="M-1_A-6_PT-v" Value="0" />
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-1_A-6_P-324_R-1539" RefId="M-1_A-6_P-324" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure MergeId="2">
             <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="8" Mode="0" Fill="0" />
            </LoadProcedure>
            <LoadProcedure MergeId="4">
             <choose ParamRefId="M-1_A-6_P-324_R-1539">
              <when test="0">
               <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="8" Verify="true" />
              </when>
              <when test="1">
               <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="4" Verify="true" />
               <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="6" Size="2" Verify="true" />
              </when>
             </choose>
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-6", xml.as_bytes())?;
        let plan_for = |keep: &str| {
            plan_flash_default(
                &app,
                "1.1.4",
                0x07B0,
                &BTreeMap::from([("P-324_R-1539".to_string(), keep.to_string())]),
                &BTreeMap::new(),
                None,
                &BTreeMap::new(),
            )
        };
        let full = plan_for("0")?;
        let writes = full
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::WriteRelMem { .. }))
            .count();
        assert_eq!(writes, 1, "one full write, not three");
        assert!(full.kept().is_empty());
        // Issue #411: the keep branch writes its two parts and keeps 4..6.
        let keep = plan_for("1")?;
        let parts: Vec<(u32, usize, usize)> = keep
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::WriteRelMem { offset, image, .. } => {
                    Some((*offset, image.offset, image.len))
                }
                _ => None,
            })
            .collect();
        assert_eq!(parts, vec![(0, 0, 4), (6, 6, 2)]);
        assert_eq!(keep.kept().len(), 1);
        assert_eq!(keep.kept()[0].label(), "object 4 octets 4..6 kept");
        assert_eq!(
            keep.image_bytes("M-1_A-6_RS-1"),
            Some(&[0, 1, 2, 3, 4, 5, 6, 7][..])
        );
        assert_eq!(keep.total_write_bytes(), 6);
        Ok(())
    }

    #[test]
    fn plan_refuses_unknown_parameter_override_key() -> Result<(), Box<dyn std::error::Error>> {
        // A parameter override naming a ref-id this application does not define is
        // a pre-flight refusal that names the offending key — the device is never
        // touched with an unresolvable parameter image.
        let app = fabricated_app();
        let mut ov = BTreeMap::new();
        ov.insert("P-999_R-1".to_string(), "1".to_string());
        let err = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &ov,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        match err {
            PlanError::UnresolvableImage { reason, .. } => {
                assert!(reason.contains("P-999"), "must name the key: {reason}");
            }
            other => panic!("expected UnresolvableImage, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn plan_applies_parameter_override_to_image() -> Result<(), Box<dyn std::error::Error>> {
        // A valid ref-id override changes the computed parameter image the plan
        // carries (proving the re-keyed override flows into plan_flash).
        let app = fabricated_app();
        let mut ov = BTreeMap::new();
        ov.insert("P-0_R-1".to_string(), "99".to_string());
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &ov,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        assert_eq!(plan.param_images["M-1_A-1_RS-2"], vec![99]);
        Ok(())
    }

    #[test]
    fn select_application_disambiguates() -> Result<(), Box<dyn std::error::Error>> {
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
        assert_eq!(select_application(&cands, Some("M-1_A-9"))?.id, "M-1_A-9");
        // A single candidate needs no name.
        assert_eq!(select_application(&[&a], None)?.id, "M-1_A-1");
        Ok(())
    }

    #[test]
    fn plan_refuses_write_rel_mem_offset_past_24bit_space() -> Result<(), Box<dyn std::error::Error>>
    {
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
        let app = parse_application_program("M-1_A-7", xml.as_bytes())?;
        let err = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        match err {
            PlanError::AddressOutOfRange { end, .. } => {
                assert!(
                    end > MAX_MEMORY_END,
                    "end {end} must exceed the 24-bit space"
                );
            }
            other => panic!("expected AddressOutOfRange, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn plan_accepts_write_rel_mem_offset_above_16bit_space()
    -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-7b", xml.as_bytes())?;
        let plan = plan_flash_default(
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
        Ok(())
    }

    #[test]
    fn plan_refuses_write_mem_address_past_24bit_space() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-8", xml.as_bytes())?;
        let err = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        assert!(
            matches!(err, PlanError::AddressOutOfRange { .. }),
            "expected AddressOutOfRange, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn plan_refuses_absurd_segment_allocation_size() -> Result<(), Box<dyn std::error::Error>> {
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
        let app = parse_application_program("M-1_A-A", xml.as_bytes())?;
        let err = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        assert!(
            matches!(err, PlanError::AddressOutOfRange { .. }),
            "expected AddressOutOfRange, got {err:?}"
        );
        Ok(())
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
        parse_application_program("M-1_A-W", xml.as_bytes()).expect("the fixture app parses")
    }

    #[test]
    fn plan_lowers_value_carrying_write_prop_as_real_write()
    -> Result<(), Box<dyn std::error::Error>> {
        // A WriteProp carrying InlineData lowers to an executable WriteProp step
        // with the decoded value — a real write in the plan, not a skipped no-op.
        let app = app_with_write_prop("0102", "0", "204");
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let write_props: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::WriteProp { .. }))
            .collect();
        assert_eq!(write_props.len(), 1, "the value-carrying WriteProp lowers");
        match write_props[0] {
            FlashStep::WriteProp {
                object,
                prop_id,
                value,
                ..
            } => {
                assert_eq!(*object, crate::flash::PropObject::Index(0));
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
        Ok(())
    }

    #[test]
    fn test_plan_flash_describes_a_bare_write_prop_no_parameter_supplies()
    -> Result<(), Box<dyn std::error::Error>> {
        // A bare WriteProp (no InlineData) writes the value the property-located
        // parameters compose (issue #669). With no parameter stored in the
        // property there is nothing to write: ETS reads the property's
        // description and goes on (issue #841, `M-00A6_A-0033-20-BFA6`), and so
        // does the plan.
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
        let app = parse_application_program("M-1_A-B", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let props: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    FlashStep::WriteProp { .. } | FlashStep::DescribeProp { .. }
                )
            })
            .collect();
        assert_eq!(
            props,
            vec![&FlashStep::DescribeProp {
                object: crate::flash::PropObject::Type {
                    object_type: 11,
                    occurrence: 0,
                },
                prop_id: 204,
                unwritten: None,
            }]
        );
        Ok(())
    }

    #[test]
    fn plan_refuses_write_prop_shape_it_cannot_execute() -> Result<(), Box<dyn std::error::Error>> {
        // A value-carrying WriteProp whose object index exceeds the 8-bit space
        // the property-write primitive addresses is refused at pre-flight rather
        // than dropped at execute time.
        let app = app_with_write_prop("01", "9999", "204");
        let err = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        match err {
            PlanError::UnsupportedWriteProp { reason, .. } => {
                assert!(reason.contains("object index"), "{reason}");
            }
            other => panic!("expected UnsupportedWriteProp, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn plan_targets_the_obj_idx_of_the_write_not_the_type() -> Result<(), Box<dyn std::error::Error>>
    {
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
        let app = parse_application_program("M-1_A-DA", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
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
        Ok(())
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

    /// The property steps of a System B plan of a procedure that writes
    /// object 6 (undeclared) and object 7 (declared, two writes) PID 208,
    /// after `reset` (an `LdCtrlMasterReset` line or nothing), with the
    /// `LoadedImage` holding `01 02` at object 6, `03 04` at object 7 element
    /// 1 and `05 07` at element 3 (issue #951).
    fn factory_plan(reset: &str) -> Result<Vec<FlashStep>, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-00FA_A-2501-10-0000" ApplicationNumber="9473"
            ApplicationVersion="16" MaskVersion="MV-07B0" Name="Held">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             {reset}
             <LdCtrlWriteProp ObjIdx="6" PropId="208" Count="2" InlineData="0102" />
             <LdCtrlDeclarePropDesc ObjIdx="7" PropId="208" PropType="PDT_UNSIGNED_CHAR" MaxElements="4" Writable="true" />
             <LdCtrlWriteProp ObjIdx="7" PropId="208" Count="2" InlineData="0304" />
             <LdCtrlWriteProp ObjIdx="7" PropId="208" StartElement="3" Count="2" InlineData="0506" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        let mut app = parse_application_program("M-00FA_A-2501-10-0000", xml.as_bytes())?;
        let held = |object: u32, start: u32, data: &[u8]| bussard_product::FactoryProperty {
            object,
            prop_id: 208,
            start,
            data: data.to_vec(),
            mask: Vec::new(),
        };
        app.factory_properties = vec![
            held(6, 0, &[1, 2]),
            held(7, 0, &[3, 4]),
            held(7, 2, &[5, 7]),
        ];
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        Ok(plan
            .steps
            .into_iter()
            .filter(|s| {
                matches!(
                    s,
                    FlashStep::WriteProp { prop_id: 208, .. }
                        | FlashStep::FactoryHeldProp { prop_id: 208, .. }
                )
            })
            .collect())
    }

    #[test]
    fn test_plan_flash_leaves_out_a_write_the_factory_image_holds() -> TestResult {
        // Issue #951: after the parameter reset, ETS sends none of the writes
        // whose value the `LoadedImage` holds (`M-0009_A-E0D0-11-434F`) and
        // the others whole (`M-0009_A-E0D1-11-99AD`, element 97 of objects
        // 13 to 24); the undeclared one still has its description read.
        let held = |object: u32, value: &[u8], start_element: u16, describe: bool| {
            FlashStep::FactoryHeldProp {
                object: crate::flash::PropObject::Index(object),
                prop_id: 208,
                value: value.to_vec(),
                start_element,
                count: 2,
                verify: false,
                from_parameters: false,
                describe,
            }
        };
        let write = |object: u32, value: &[u8], start_element: u16| FlashStep::WriteProp {
            object: crate::flash::PropObject::Index(object),
            prop_id: 208,
            value: value.to_vec(),
            start_element,
            count: 2,
            verify: false,
            from_parameters: false,
        };
        assert_eq!(
            factory_plan(r#"<LdCtrlMasterReset EraseCode="5" ChannelNumber="0" />"#)?,
            vec![
                held(6, &[1, 2], 1, true),
                held(7, &[3, 4], 1, false),
                write(7, &[5, 6], 3),
            ]
        );
        // Without a reset of every channel's parameters the device holds
        // what an earlier download left: every write is sent.
        for reset in [
            "",
            r#"<LdCtrlMasterReset EraseCode="6" ChannelNumber="0" />"#,
            r#"<LdCtrlMasterReset EraseCode="5" ChannelNumber="2" />"#,
        ] {
            assert_eq!(
                factory_plan(reset)?,
                vec![
                    write(6, &[1, 2], 1),
                    write(7, &[3, 4], 1),
                    write(7, &[5, 6], 3),
                ],
                "{reset}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_plan_flash_holds_a_zero_placeholder_only_where_the_image_records_it() -> TestResult {
        // Review of #1011: a declared all-zero `InlineData` write to a
        // property no parameter is placed in is written as before, unless
        // the `LoadedImage` records the zeros after the reset; then it is held
        // and still read back (`FactoryHeldProp`).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-00FA_A-2502-10-0000" ApplicationNumber="9474"
            ApplicationVersion="16" MaskVersion="MV-07B0" Name="Zero">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlMasterReset EraseCode="5" ChannelNumber="0" />
             <LdCtrlDeclarePropDesc ObjIdx="10" PropId="52" PropType="PDT_UNSIGNED_CHAR" MaxElements="11" Writable="true" />
             <LdCtrlWriteProp ObjIdx="10" PropId="52" Count="11" InlineData="00000000000000000000" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let mut app = parse_application_program("M-00FA_A-2502-10-0000", xml.as_bytes())?;
        let plan = |app: &ApplicationProgram| {
            plan_flash_default(
                app,
                "1.1.4",
                0x07B0,
                &no_overrides(),
                &BTreeMap::new(),
                None,
                &BTreeMap::new(),
            )
        };
        let property_steps = |plan: FlashPlan| -> Vec<FlashStep> {
            plan.steps
                .into_iter()
                .filter(|s| s.property_write().is_some())
                .collect()
        };
        assert_eq!(
            property_steps(plan(&app)?),
            vec![FlashStep::WriteProp {
                object: crate::flash::PropObject::Index(10),
                prop_id: 52,
                value: vec![0; 11],
                start_element: 1,
                count: 11,
                verify: false,
                from_parameters: false,
            }]
        );
        app.factory_properties = vec![bussard_product::FactoryProperty {
            object: 10,
            prop_id: 52,
            start: 0,
            data: vec![0; 11],
            mask: Vec::new(),
        }];
        assert!(matches!(
            property_steps(plan(&app)?).as_slice(),
            [FlashStep::FactoryHeldProp {
                prop_id: 52,
                describe: false,
                ..
            }]
        ));
        Ok(())
    }

    #[test]
    fn test_plan_flash_substitutes_the_app_id_in_a_declared_pid_13_write()
    -> Result<(), Box<dyn std::error::Error>> {
        // Issue #945: a procedure that declares object 4 PID 13 before the
        // placeholder write still writes the synthesized application id, not
        // the zeros.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-00FA_A-2500-10-51CB" ApplicationNumber="9472"
            ApplicationVersion="16" MaskVersion="MV-07B0" Name="Declared">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlDeclarePropDesc ObjIdx="4" PropId="13" PropType="PDT_GENERIC_05" MaxElements="1" Writable="true" />
             <LdCtrlWriteProp ObjIdx="4" PropId="13" Count="1" InlineData="0000000000" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-00FA_A-2500-10-51CB", xml.as_bytes())?;
        let plan = plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let writes: Vec<&FlashStep> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::WriteProp { prop_id: 13, .. }))
            .collect();
        assert_eq!(
            writes,
            vec![&FlashStep::WriteProp {
                object: crate::flash::PropObject::Index(4),
                prop_id: 13,
                value: vec![0x00, 0xFA, 0x25, 0x00, 0x10],
                start_element: 1,
                count: 1,
                verify: false,
                from_parameters: false,
            }]
        );
        Ok(())
    }

    #[test]
    fn test_plan_flash_refuses_a_declared_pid_13_placeholder_without_an_app_id()
    -> Result<(), Box<dyn std::error::Error>> {
        // Issue #957: without an application number and version there is no
        // id for the placeholder; zeros would name no program and the
        // read-back of the declared write would compare them.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-00FA_A-2500-10-51CB" MaskVersion="MV-07B0" Name="Declared">
          <Static>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlDeclarePropDesc ObjIdx="4" PropId="13" PropType="PDT_GENERIC_05" MaxElements="1" Writable="true" />
             <LdCtrlWriteProp ObjIdx="4" PropId="13" Count="1" InlineData="0000000000" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-00FA_A-2500-10-51CB", xml.as_bytes())?;
        match plan_flash_default(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        ) {
            Err(PlanError::UnsupportedWriteProp { reason, .. }) => {
                assert!(reason.contains("application-id placeholder"), "{reason}");
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn test_maybe_substitute_app_id_replaces_only_the_placeholder() {
        let app_id = [0x00u8, 0xFA, 0x25, 0x00, 0x10];
        let none = || Ok(false);
        // PID 13 + the all-zero placeholder → substituted with the app id.
        assert_eq!(
            maybe_substitute_app_id("x", 13, Some(&[0, 0, 0, 0, 0]), Some(&app_id), none),
            Ok(Some(app_id.to_vec()))
        );
        // PID 13 but a concrete (non-placeholder) value → left verbatim.
        assert_eq!(
            maybe_substitute_app_id("x", 13, Some(&[1, 2, 3, 4, 5]), Some(&app_id), none),
            Ok(Some(vec![1, 2, 3, 4, 5]))
        );
        // A different PID → never substituted, even for a zero value.
        assert_eq!(
            maybe_substitute_app_id("x", 5, Some(&[0, 0, 0, 0, 0]), None, none),
            Ok(Some(vec![0, 0, 0, 0, 0]))
        );
    }

    #[test]
    fn test_maybe_substitute_app_id_lets_a_parameter_supply_the_placeholder() {
        // Issue #964: without an application id a parameter placed in PID 13
        // keeps the zero template for the parameters to be laid over; with
        // neither the placeholder is refused, never written as zeros.
        assert_eq!(
            maybe_substitute_app_id("x", 13, Some(&[0; 5]), None, || Ok(true)),
            Ok(Some(vec![0; 5]))
        );
        let refused =
            maybe_substitute_app_id("object 4 PID 13", 13, Some(&[0; 5]), None, || Ok(false));
        assert!(
            refused
                .as_ref()
                .is_err_and(|r| r.contains("object 4 PID 13") && r.contains("placeholder")),
            "{refused:?}"
        );
    }

    #[test]
    fn test_program_ids_resolve_the_object_before_the_id() {
        // Issue #964: a PID 13 write naming its object by type takes the id
        // of the program that object is, never object 0's; a companion
        // `PeiProgram` named by type (interface program object, type 4)
        // takes its own id.
        let main = [1u8, 2, 3, 4, 5];
        let companion = [9u8, 9, 9, 9, 9];
        let ids = ProgramIds {
            main: Some(main),
            by_index: BTreeMap::from([(5u32, companion)]),
            typed: BTreeMap::from([
                ((bussard_mgmt::tables::OT_APPLICATION_PROGRAM, 0), 4u32),
                ((OT_INTERFACE_PROGRAM, 0), 5u32),
            ]),
        };
        assert_eq!(ids.for_object(PropObject::Index(5)), Some(&companion));
        assert_eq!(ids.for_object(PropObject::Index(4)), Some(&main));
        let typed = |object_type: u16| PropObject::Type {
            object_type,
            occurrence: 0,
        };
        assert_eq!(
            ids.for_object(typed(bussard_mgmt::tables::OT_APPLICATION_PROGRAM)),
            Some(&main)
        );
        assert_eq!(
            ids.for_object(typed(OT_INTERFACE_PROGRAM)),
            Some(&companion)
        );
        assert_eq!(ids.for_object(typed(11)), None);
    }

    #[test]
    fn test_program_ids_of_types_a_pei_companion_by_its_object() -> TestResult {
        // Issue #964: the ABB BE/S16 shape, a `PeiProgram` companion loading
        // object 5: named by type 4 it resolves to object 5 and its own id.
        let xml = |id: &str, number: &str, lsm: &str, kind: &str| {
            format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20">
             <ApplicationProgram Id="{id}" ApplicationNumber="{number}" ApplicationVersion="16"
                MaskVersion="MV-07B0" Name="P" ProgramType="{kind}">
              <Static><Code>
               <RelativeSegment Id="{id}_RS-0{lsm}-00000" Size="4" LoadStateMachine="{lsm}" Offset="0"><Data>AQIDBA==</Data></RelativeSegment>
              </Code></Static>
             </ApplicationProgram></KNX>"#
            )
        };
        let mut app = parse_application_program(
            "M-0002_A-A0ED-10-0001",
            xml("M-0002_A-A0ED-10-0001", "41197", "4", "ApplicationProgram").as_bytes(),
        )?;
        let pei = parse_application_program(
            "M-0002_A-A0ED-20-0002",
            xml("M-0002_A-A0ED-20-0002", "41198", "5", "PeiProgram").as_bytes(),
        )?;
        let pei_id = app_program_version_value(&pei).ok_or("a companion id")?;
        let main_id = app_program_version_value(&app).ok_or("a main id")?;
        app.companion_programs.push(pei);
        let ids = ProgramIds::of(&app);
        let typed = |object_type: u16| PropObject::Type {
            object_type,
            occurrence: 0,
        };
        assert_eq!(ids.for_object(typed(OT_INTERFACE_PROGRAM)), Some(&pei_id));
        assert_eq!(ids.for_object(PropObject::Index(5)), Some(&pei_id));
        assert_eq!(
            ids.for_object(typed(bussard_mgmt::tables::OT_APPLICATION_PROGRAM)),
            Some(&main_id)
        );
        Ok(())
    }

    /// A non-secure 07B0 program running `ops` in its one load procedure,
    /// with `params` (`<Parameter>` elements over the `u8` type) and, with
    /// `identity`, an application number and version.
    fn ops_app(
        ops: &str,
        params: &str,
        identity: bool,
    ) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        ops_app_showing(ops, params, &[], identity)
    }

    /// [`ops_app`] with a `ParameterRef` `P-<n>_R-<n>` for each of `shown`,
    /// each shown in the Dynamic section.
    fn ops_app_showing(
        ops: &str,
        params: &str,
        shown: &[u32],
        identity: bool,
    ) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let refs: String = shown
            .iter()
            .map(|n| format!(r#"<ParameterRef Id="M-00FA_A-2500-10-51CB_P-{n}_R-{n}" RefId="M-00FA_A-2500-10-51CB_P-{n}" />"#))
            .collect();
        let refrefs: String = shown
            .iter()
            .map(|n| format!(r#"<ParameterRefRef RefId="M-00FA_A-2500-10-51CB_P-{n}_R-{n}" />"#))
            .collect();
        let identity = if identity {
            r#"ApplicationNumber="9472" ApplicationVersion="16""#
        } else {
            ""
        };
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-00FA_A-2500-10-51CB" {identity} MaskVersion="MV-07B0" Name="Ops">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-00FA_A-2500-10-51CB_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
           </ParameterTypes>
           <Parameters>{params}</Parameters>
           <ParameterRefs>{refs}</ParameterRefs>
           <LoadProcedures><LoadProcedure>{ops}</LoadProcedure></LoadProcedures>
          </Static>
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="M-00FA_A-2500-10-51CB_PB-1">{refrefs}</ParameterBlock></ChannelIndependentBlock></Dynamic>
         </ApplicationProgram></KNX>"#
        );
        Ok(parse_application_program(
            "M-00FA_A-2500-10-51CB",
            xml.as_bytes(),
        )?)
    }

    /// The plan of [`ops_app`].
    fn plan_ops(app: &ApplicationProgram) -> Result<FlashPlan, PlanError> {
        plan_flash_default(
            app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
    }

    /// The `UnsupportedWriteProp` reason of `result`.
    fn write_refusal(
        result: Result<FlashPlan, PlanError>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match result {
            Err(PlanError::UnsupportedWriteProp { reason, .. }) => Ok(reason),
            other => Err(format!("expected a refusal, got {other:?}").into()),
        }
    }

    /// The `WriteProp` steps of `plan` to `prop_id`.
    fn writes_to(plan: &FlashPlan, prop_id: u32) -> Vec<FlashStep> {
        plan.steps
            .iter()
            .filter(|s| matches!(s, FlashStep::WriteProp { prop_id: p, .. } if *p == prop_id))
            .cloned()
            .collect()
    }

    #[test]
    fn test_plan_flash_refuses_an_undeclared_pid_13_placeholder_without_an_app_id() -> TestResult {
        // Issue #964: the undeclared arm wrote the zeros; the one rule
        // refuses them as the declared arm does.
        let app = ops_app(
            r#"<LdCtrlWriteProp ObjIdx="4" PropId="13" InlineData="0000000000" />"#,
            "",
            false,
        )?;
        let reason = write_refusal(plan_ops(&app))?;
        assert!(reason.contains("application-id placeholder"), "{reason}");
        Ok(())
    }

    #[test]
    fn test_plan_flash_takes_a_pid_13_placeholder_value_from_a_parameter() -> TestResult {
        // Issue #964: one rule on both arms. A parameter placed in PID 13 is
        // laid over the application id when there is one, and supplies the
        // value over zeros when there is none; the step is marked as the
        // parameters' value either way, so the executor never skips it.
        let param = r#"<Parameter Id="M-00FA_A-2500-10-51CB_P-1" Name="v" ParameterType="M-00FA_A-2500-10-51CB_PT-u8" Value="7"><Property ObjectIndex="4" PropertyId="13" Offset="4" BitOffset="0" /></Parameter>"#;
        for (identity, expected) in [
            (false, vec![0, 0, 0, 0, 7]),
            (true, vec![0x00, 0xFA, 0x25, 0x00, 0x07]),
        ] {
            for ops in [
                r#"<LdCtrlWriteProp ObjIdx="4" PropId="13" InlineData="0000000000" />"#,
                r#"<LdCtrlDeclarePropDesc ObjIdx="4" PropId="13" PropType="PDT_GENERIC_05" MaxElements="1" Writable="true" />
                   <LdCtrlWriteProp ObjIdx="4" PropId="13" Count="1" InlineData="0000000000" />"#,
            ] {
                let plan = plan_ops(&ops_app_showing(ops, param, &[1], identity)?)?;
                let writes: Vec<(Vec<u8>, bool)> = writes_to(&plan, 13)
                    .into_iter()
                    .filter_map(|s| match s {
                        FlashStep::WriteProp {
                            value,
                            from_parameters,
                            ..
                        } => Some((value, from_parameters)),
                        _ => None,
                    })
                    .collect();
                assert_eq!(writes, vec![(expected.clone(), true)], "{ops}");
            }
        }
        Ok(())
    }

    #[test]
    fn test_plan_flash_picks_the_app_id_of_a_typed_pid_13_write_by_its_object() -> TestResult {
        // Issue #964: a declared PID 13 placeholder naming the application
        // object by type takes the main id; one naming another type has no
        // id to take and is refused, never given object 0's.
        let typed = |object_type: u32| {
            format!(
                r#"<LdCtrlDeclarePropDesc ObjType="{object_type}" PropId="13" PropType="PDT_GENERIC_05" MaxElements="1" Writable="true" />
                   <LdCtrlWriteProp ObjType="{object_type}" PropId="13" Count="1" InlineData="0000000000" />"#
            )
        };
        let plan = plan_ops(&ops_app(&typed(3), "", true)?)?;
        assert!(matches!(
            writes_to(&plan, 13).as_slice(),
            [FlashStep::WriteProp { value, .. }] if value == &[0x00, 0xFA, 0x25, 0x00, 0x10]
        ));
        let reason = write_refusal(plan_ops(&ops_app(&typed(60001), "", true)?))?;
        assert!(reason.contains("application-id placeholder"), "{reason}");
        Ok(())
    }

    #[test]
    fn test_plan_flash_lowers_the_enertex_data_less_write_by_its_placement() -> TestResult {
        // Issue #841, the Enertex shape `LdCtrlWriteProp ObjType="50001"
        // PropId="211"` without InlineData or Count: with no parameter placed
        // in the property ETS reads its description and writes nothing
        // (`M-00A6_A-0033-20-BFA6`); with one placed it writes the parameter
        // (`M-00A6_A-0014-10-2517` re-swept on knx-sim with #843, one octet).
        let op = r#"<LdCtrlWriteProp ObjType="50001" PropId="211" Verify="false" />"#;
        let typed = PropObject::Type {
            object_type: 50001,
            occurrence: 0,
        };
        let plan = plan_ops(&ops_app(op, "", true)?)?;
        assert!(plan.steps.contains(&FlashStep::DescribeProp {
            object: typed,
            prop_id: 211,
            unwritten: None,
        }));
        assert!(writes_to(&plan, 211).is_empty());
        let param = r#"<Parameter Id="M-00FA_A-2500-10-51CB_P-1" Name="limit" ParameterType="M-00FA_A-2500-10-51CB_PT-u8" Value="50"><Property ObjectType="50001" PropertyId="211" Offset="0" BitOffset="0" /></Parameter>"#;
        let plan = plan_ops(&ops_app(op, param, true)?)?;
        assert_eq!(
            writes_to(&plan, 211),
            vec![FlashStep::WriteProp {
                object: typed,
                prop_id: 211,
                value: vec![50],
                start_element: 1,
                count: 1,
                verify: false,
                from_parameters: true,
            }]
        );
        Ok(())
    }

    #[test]
    fn test_plan_flash_refuses_a_typed_write_past_an_8_bit_pid_by_list() -> TestResult {
        // Issue #964: on a program that is not Data Secure enabled an
        // object named by type is written on the plain services at its
        // listed index, so a PID past 8 bits is refused at plan time, before
        // the unload, on the InlineData, declared and parameter arms.
        let param = r#"<Parameter Id="M-00FA_A-2500-10-51CB_P-1" Name="v" ParameterType="M-00FA_A-2500-10-51CB_PT-u8" Value="7"><Property ObjectType="60001" PropertyId="300" Offset="0" BitOffset="0" /></Parameter>"#;
        for (ops, params) in [
            (
                r#"<LdCtrlWriteProp ObjType="60001" PropId="300" InlineData="5A" />"#,
                "",
            ),
            (
                r#"<LdCtrlDeclarePropDesc ObjType="60001" PropId="300" PropType="PDT_UNSIGNED_CHAR" MaxElements="1" Writable="true" />
                   <LdCtrlWriteProp ObjType="60001" PropId="300" Count="1" InlineData="5A" />"#,
                "",
            ),
            (r#"<LdCtrlWriteProp ObjType="60001" PropId="300" />"#, param),
        ] {
            let reason = write_refusal(plan_ops(&ops_app(ops, params, true)?))?;
            assert!(reason.contains("8-bit PID"), "{ops}: {reason}");
        }
        Ok(())
    }

    #[test]
    fn test_plan_flash_takes_the_count_of_an_inline_data_write() -> TestResult {
        // Issue #964: the one Count rule holds on the System B InlineData
        // arm: `ObjType="50215" PropId="205" Count="2" InlineData="5A5A"` is
        // two one-octet elements, not one two-octet element. `Verify` stays
        // the echo validation ETS does on that arm (issue #390).
        let app = ops_app(
            r#"<LdCtrlWriteProp ObjType="50215" PropId="205" Count="2" Verify="true" InlineData="5A5A" />"#,
            "",
            true,
        )?;
        let plan = plan_ops(&app)?;
        assert_eq!(
            writes_to(&plan, 205),
            vec![FlashStep::WriteProp {
                object: PropObject::Type {
                    object_type: 50215,
                    occurrence: 0,
                },
                prop_id: 205,
                value: vec![0x5A, 0x5A],
                start_element: 1,
                count: 2,
                verify: false,
                from_parameters: false,
            }]
        );
        Ok(())
    }

    /// The fabricated Siemens-shaped product procedure (issue #614).
    fn map_error_app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml =
            include_bytes!("../../../bussard-product/tests/fixtures/ldctrl_map_error.app.xml");
        Ok(parse_application_program("M-00FA_A-0614-01-ABCD", xml)?)
    }

    fn plan_map_error(app: &ApplicationProgram) -> std::result::Result<FlashPlan, PlanError> {
        let tables = crate::build_table_images(
            None,
            bussard_model::IndividualAddress::from_raw(0x1101),
            app,
            &BTreeMap::new(),
            &bussard_product::dynamic::DynamicMemo::new(app),
        );
        plan_flash_default(
            app,
            "1.1.1",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &tables,
        )
    }

    #[test]
    fn test_plan_flash_map_error_maps_only_the_wrapped_unload()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = plan_map_error(&map_error_app()?)?;
        let unloads: Vec<(Option<u32>, bool)> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Unload { target, absent_ok } => Some((*target, *absent_ok)),
                _ => None,
            })
            .collect();
        // The second LdCtrlMapError (mapped to itself) ends the rule, and the
        // par/grp unloads after the complete download are left out.
        assert_eq!(
            unloads,
            [
                (Some(5), true),
                (Some(4), false),
                (Some(3), false),
                (Some(2), false),
                (Some(1), false)
            ]
        );
        Ok(())
    }

    #[test]
    fn test_plan_flash_product_procedure_runs_the_complete_download_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = plan_map_error(&map_error_app()?)?;
        let allocations: Vec<Option<u32>> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::AllocateSegment { target, .. } => Some(*target),
                _ => None,
            })
            .collect();
        assert_eq!(allocations, [Some(4), Some(3), Some(1), Some(2)]);
        let writes: Vec<(Option<u32>, ImageKind)> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::WriteRelMem { target, image, .. } => Some((*target, image.kind)),
                _ => None,
            })
            .collect();
        // The tables on LSM 1 to 3 stream the table images, as every System B
        // download does.
        assert_eq!(
            writes,
            [
                (Some(4), ImageKind::Code),
                (Some(3), ImageKind::Table),
                (Some(2), ImageKind::Table),
                (Some(1), ImageKind::Table)
            ]
        );
        let completed = plan
            .steps
            .iter()
            .filter(|s| matches!(s, FlashStep::LoadCompleted { .. }))
            .count();
        assert_eq!(completed, 4);
        let elements: Vec<u16> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::CompareProp { start_element, .. } => Some(*start_element),
                _ => None,
            })
            .collect();
        assert_eq!(elements, [1, 3]);
        assert!(
            trace(&plan)
                .iter()
                .any(|l| l.contains("absent object is no error"))
        );
        Ok(())
    }

    #[test]
    fn test_plan_flash_product_procedure_without_table_images_refuses()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = map_error_app()?;
        match plan_flash_default(
            &app,
            "1.1.1",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        ) {
            Err(PlanError::MissingTableImage { obj_idx: 3, .. }) => Ok(()),
            other => Err(format!("expected MissingTableImage for object 3, got {other:?}").into()),
        }
    }

    #[test]
    fn test_lower_map_error_refuses_what_it_cannot_honour() {
        let mut maps = BTreeMap::new();
        assert!(lower_map_error(&mut maps, Some(MAPPED_UNLOAD_ERROR), Some(0)).is_ok());
        assert_eq!(maps.get(&MAPPED_UNLOAD_ERROR), Some(&0));
        assert!(
            lower_map_error(
                &mut maps,
                Some(MAPPED_UNLOAD_ERROR),
                Some(MAPPED_UNLOAD_ERROR)
            )
            .is_ok()
        );
        assert!(maps.is_empty());
        for (original, mapped) in [
            (Some(0xC004_0001), Some(0)),
            (Some(MAPPED_UNLOAD_ERROR), Some(5)),
            (None, Some(0)),
            (Some(MAPPED_UNLOAD_ERROR), None),
        ] {
            assert!(
                matches!(
                    lower_map_error(&mut maps, original, mapped),
                    Err(PlanError::UnsupportedOp { .. })
                ),
                "{original:?} -> {mapped:?}"
            );
        }
    }

    #[test]
    fn test_plan_flash_map_error_over_another_op_refuses() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut app = map_error_app()?;
        // Drop the closing LdCtrlMapError: the rule stays in force over the
        // unload of object 4 (fine) and then over a Load (refused).
        let lp = app.load_procedures.first_mut().ok_or("procedure")?;
        let closing = lp
            .ops
            .iter()
            .rposition(|op| matches!(op, LoadOp::MapError { .. }))
            .ok_or("closing map")?;
        lp.ops.remove(closing);
        lp.applies_to.remove(closing);
        match plan_map_error(&app) {
            Err(PlanError::UnsupportedOp { op }) => {
                assert!(op.contains("LdCtrlMapError"), "{op}");
                Ok(())
            }
            other => Err(format!("expected UnsupportedOp, got {other:?}").into()),
        }
    }

    /// A merged 07B0 program `M-0002_A-2` with the given `LoadProcedure`
    /// blocks and no code segment, planned against the built-in template.
    fn plan_merged_blocks(blocks: &str) -> Result<FlashPlan, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-0002_A-2" ApplicationNumber="2" ApplicationVersion="16"
            MaskVersion="MV-07B0" Name="AP1" LoadProcedureStyle="MergedProcedure">
          <Static>
           <AddressTable MaxEntries="200" />
           <AssociationTable MaxEntries="200" />
           <ComObjectTable />
           <LoadProcedures>{blocks}</LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        let app = parse_application_program("M-0002_A-2", xml.as_bytes())?;
        let template = bussard_product::MasterTemplate::builtin_for_mask("07B0")
            .ok_or("a built-in 07B0 template")?;
        let tables = BTreeMap::from([(1, vec![0, 0]), (2, vec![0, 0]), (3, vec![0, 0])]);
        Ok(plan_flash_default(
            &app,
            "1.1.1",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            Some(&template.ops),
            &tables,
        )?)
    }

    /// The load-state steps of `plan` on index-addressed objects, in order.
    fn load_steps(plan: &FlashPlan) -> Vec<(&'static str, Option<u32>)> {
        plan.steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::Unload {
                    target,
                    absent_ok: true,
                } => Some(("unload-absent-ok", *target)),
                FlashStep::Unload { target, .. } => Some(("unload", *target)),
                FlashStep::StartLoading { target } => Some(("start", *target)),
                FlashStep::LoadCompleted { target } => Some(("complete", *target)),
                _ => None,
            })
            .collect()
    }

    /// The objects `plan` writes `PID_PROGRAM_VERSION` to, with the value.
    fn program_versions(plan: &FlashPlan) -> Vec<(u32, Vec<u8>)> {
        plan.steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::WriteProp {
                    object: PropObject::Index(idx),
                    prop_id: PID_PROGRAM_VERSION,
                    value,
                    ..
                } => Some((*idx, value.clone())),
                _ => None,
            })
            .collect()
    }

    /// Issue #942: the built-in `all` template without Application Program
    /// 2 is the master data's `ap1` procedure, op for op (the 07B0 `ap1`
    /// block of every corpus `knx_master.xml`).
    #[test]
    fn test_application_program_1_only_is_the_ap1_procedure() -> TestResult {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-1_A-1" Name="x">
          <LoadProcedures><LoadProcedure>
           <LdCtrlConnect />
           <LdCtrlMerge MergeId="1" />
           <LdCtrlMapError OriginalError="3221498632" MappedError="0" />
           <LdCtrlUnload LsmIdx="5" />
           <LdCtrlMapError OriginalError="3221498632" MappedError="3221498632" />
           <LdCtrlUnload LsmIdx="4" />
           <LdCtrlUnload LsmIdx="3" />
           <LdCtrlUnload LsmIdx="2" />
           <LdCtrlUnload LsmIdx="1" />
           <LdCtrlLoad LsmIdx="4" />
           <LdCtrlMerge MergeId="2" />
           <LdCtrlLoad LsmIdx="3" />
           <LdCtrlRelSegment LsmIdx="3" Size="2" Mode="0" Fill="0" />
           <LdCtrlLoad LsmIdx="1" />
           <LdCtrlRelSegment LsmIdx="1" Size="2" Mode="0" Fill="0" />
           <LdCtrlLoad LsmIdx="2" />
           <LdCtrlRelSegment LsmIdx="2" Size="2" Mode="0" Fill="0" />
           <LdCtrlMerge MergeId="4" />
           <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="1048576" Verify="true" />
           <LdCtrlWriteRelMem ObjIdx="2" Offset="0" Size="1048576" Verify="true" />
           <LdCtrlWriteRelMem ObjIdx="1" Offset="0" Size="1048576" Verify="true" />
           <LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />
           <LdCtrlLoadCompleted LsmIdx="4" />
           <LdCtrlLoadCompleted LsmIdx="3" />
           <LdCtrlLoadCompleted LsmIdx="2" />
           <LdCtrlLoadCompleted LsmIdx="1" />
           <LdCtrlMerge MergeId="6" />
           <LdCtrlMerge MergeId="7" />
           <LdCtrlRestart />
          </LoadProcedure></LoadProcedures>
         </ApplicationProgram></KNX>"#;
        let ap1 = parse_application_program("M-1_A-1", xml.as_bytes())?;
        let all = bussard_product::MasterTemplate::builtin_for_mask("07B0")
            .ok_or("a built-in 07B0 template")?;
        assert_eq!(
            application_program_1_only(&all.ops),
            ap1.load_procedures[0].ops
        );
        // An `ap1` procedure already has no object 5 rows to drop.
        assert_eq!(
            application_program_1_only(&ap1.load_procedures[0].ops),
            ap1.load_procedures[0].ops
        );
        Ok(())
    }

    /// Issue #942: a master that ships its own `ap1` is run as shipped for a
    /// program without Application Program 2, not derived from `all`; a
    /// program that fills MergeId 3 gets the `all` procedure.
    #[test]
    fn test_master_template_ops_selects_the_masters_ap1() -> TestResult {
        let master_xml = r#"<KNX><ManufacturerData><Manufacturer><MaskVersions>
          <MaskVersion Id="MV-07B0" MaskVersion="1968">
           <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="ap1">
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlDelay MilliSeconds="7" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </Procedure>
            <Procedure ProcedureType="Load" ProcedureSubType="all">
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="5" />
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="5" />
             <LdCtrlMerge MergeId="3" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlLoadCompleted LsmIdx="5" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </Procedure>
           </Procedures>
          </MaskVersion>
        </MaskVersions></Manufacturer></ManufacturerData></KNX>"#;
        let master = bussard_product::parse_master_template(master_xml.as_bytes(), "test")?;
        let app_xml = |blocks: &str| {
            format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20">
             <ApplicationProgram Id="M-0002_A-2" ApplicationNumber="2" ApplicationVersion="16"
                MaskVersion="MV-07B0" Name="AP1" LoadProcedureStyle="MergedProcedure">
              <Static><LoadProcedures>{blocks}</LoadProcedures></Static>
             </ApplicationProgram></KNX>"#
            )
        };
        let ap1_only = parse_application_program(
            "M-0002_A-2",
            app_xml(r#"<LoadProcedure MergeId="7"><LdCtrlLoadImageProp ObjIdx="4" PropId="27" /></LoadProcedure>"#)
                .as_bytes(),
        )?;
        let ops = crate::master_template_ops(&master, "07B0", &ap1_only).ok_or("a template")?;
        assert!(
            ops.contains(&LoadOp::Delay {
                milliseconds: Some(7)
            }),
            "the master's own ap1: {ops:?}"
        );
        let with_ap2 = parse_application_program(
            "M-0002_A-2",
            app_xml(r#"<LoadProcedure MergeId="3"><LdCtrlRelSegment LsmIdx="5" Size="2" Mode="0" Fill="0" /></LoadProcedure>"#)
                .as_bytes(),
        )?;
        let ops = crate::master_template_ops(&master, "07B0", &with_ap2).ok_or("a template")?;
        assert!(
            ops.contains(&LoadOp::Load {
                lsm_idx: Some(5),
                obj_type: None,
                occurrence: None,
            }),
            "the all procedure: {ops:?}"
        );
        // The planner runs the shipped ap1 as is: its delay, and no object 5.
        let plan = plan_flash_default(
            &ap1_only,
            "1.1.1",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            Some(&crate::master_template_ops(&master, "07B0", &ap1_only).ok_or("a template")?),
            &BTreeMap::new(),
        )?;
        assert!(plan.steps.contains(&FlashStep::Delay { milliseconds: 7 }));
        assert!(!load_steps(&plan).iter().any(|(_, t)| *t == Some(5)));
        Ok(())
    }

    /// Issue #942, the Hager `M-0009_A-E807-10-0EAB` shape: no block for
    /// MergeId 2, 3 or 5. ETS unloads object 5 and loads object 4 without an
    /// allocation, writing its program version (`ops.txt` ops 26, 31, 270,
    /// 271); object 5 is never opened.
    #[test]
    fn test_plan_flash_loads_object_4_without_an_allocation() -> TestResult {
        let plan = plan_merged_blocks(
            r#"<LoadProcedure MergeId="7"><LdCtrlLoadImageProp ObjIdx="1" PropId="27" /></LoadProcedure>"#,
        )?;
        assert_eq!(
            load_steps(&plan),
            [
                ("unload-absent-ok", Some(5)),
                ("unload", Some(4)),
                ("unload", Some(3)),
                ("unload", Some(2)),
                ("unload", Some(1)),
                ("start", Some(4)),
                ("start", Some(3)),
                ("start", Some(1)),
                ("start", Some(2)),
                ("complete", Some(4)),
                ("complete", Some(3)),
                ("complete", Some(2)),
                ("complete", Some(1)),
            ]
        );
        assert_eq!(
            program_versions(&plan),
            [(4, vec![0x00, 0x02, 0x00, 0x02, 0x10])]
        );
        Ok(())
    }

    /// Issue #942, the Gira `M-0008_A-0004-75-0A9A-O007C` shape: the
    /// application's own MergeId 6 block loads object 5 without allocating
    /// it, and ETS sends both controls (`ops.txt` ops 60, 61). It is not
    /// Application Program 2, so the template still runs as `ap1`.
    #[test]
    fn test_plan_flash_loads_an_object_the_application_opens() -> TestResult {
        let plan = plan_merged_blocks(
            r#"<LoadProcedure MergeId="6"><LdCtrlLoad LsmIdx="5" /><LdCtrlLoadCompleted LsmIdx="5" /></LoadProcedure>"#,
        )?;
        let steps = load_steps(&plan);
        assert_eq!(steps.first(), Some(&("unload-absent-ok", Some(5))));
        assert_eq!(
            &steps[steps.len() - 2..],
            [("start", Some(5)), ("complete", Some(5))]
        );
        assert_eq!(program_versions(&plan).len(), 1);
        Ok(())
    }

    /// Issue #942: Application Program 2 is loaded when a non-empty block
    /// fills MergeId 3 or 5 (the ABB PEI companion's), and only then.
    #[test]
    fn test_loads_application_program_2_needs_a_filled_ap2_block() {
        for id in [3, 5] {
            assert!(loads_application_program_2(&BTreeMap::from([(
                id,
                vec![LoadOp::Restart]
            )])));
        }
        assert!(!loads_application_program_2(&BTreeMap::from([(
            3,
            Vec::new()
        )])));
        assert!(!loads_application_program_2(&BTreeMap::from([(
            6,
            vec![LoadOp::Restart]
        )])));
    }

    /// Issue #961: load-state controls naming their object by type become
    /// typed controls on that object, in place, never controls to no object.
    #[test]
    fn test_plan_flash_sends_load_controls_by_object_type() -> TestResult {
        let plan = plan_merged_blocks(
            r#"<LoadProcedure MergeId="6">
                 <LdCtrlUnload AppliesTo="all" ObjType="40960" />
                 <LdCtrlLoad AppliesTo="all" ObjType="40960" />
                 <LdCtrlLoadCompleted AppliesTo="all" ObjType="40960" />
               </LoadProcedure>"#,
        )?;
        let typed: Vec<(u16, u16, bussard_mgmt::LoadControl)> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::TypedLoadControl {
                    object_type,
                    occurrence,
                    control,
                } => Some((*object_type, *occurrence, *control)),
                _ => None,
            })
            .collect();
        assert_eq!(
            typed,
            [
                (40960, 0, bussard_mgmt::LoadControl::Unload),
                (40960, 0, bussard_mgmt::LoadControl::StartLoading),
                (40960, 0, bussard_mgmt::LoadControl::LoadCompleted),
            ]
        );
        assert!(
            !load_steps(&plan).iter().any(|(_, target)| target.is_none()),
            "no load control to no object"
        );
        // The typed controls send no indexed load-control record.
        for step in &plan.steps {
            if matches!(step, FlashStep::TypedLoadControl { .. }) {
                assert!(plan.load_control_records(step).is_empty());
            }
        }
        Ok(())
    }

    /// Issue #961: a typed control naming an index too, or under an
    /// `LdCtrlMapError`, is refused.
    #[test]
    fn test_lower_typed_load_control_refuses_what_it_cannot_send() {
        let both = LoadOp::Unload {
            lsm_idx: Some(4),
            obj_type: Some(40960),
            occurrence: None,
        };
        assert!(lower_typed_load_control(1, &both, false).is_err());
        let typed = LoadOp::Unload {
            lsm_idx: None,
            obj_type: Some(40960),
            occurrence: None,
        };
        assert!(lower_typed_load_control(1, &typed, true).is_err());
        let wide = LoadOp::Load {
            lsm_idx: None,
            obj_type: Some(0x1_0000),
            occurrence: None,
        };
        assert!(lower_typed_load_control(1, &wide, false).is_err());
        let device = LoadOp::LoadCompleted {
            lsm_idx: None,
            obj_type: Some(0),
            occurrence: None,
        };
        assert!(lower_typed_load_control(1, &device, false).is_err());
        assert!(matches!(
            lower_typed_load_control(1, &typed, false),
            Ok(FlashStep::TypedLoadControl {
                object_type: 40960,
                occurrence: 0,
                control: bussard_mgmt::LoadControl::Unload,
            })
        ));
    }
}
