//! Property operations in load procedures (issue #390): the lowering of
//! `LdCtrlWriteProp` and `LdCtrlCompareProp` shared by the System 7 planner and
//! the property-only planner, the `<choose>` guards of a load procedure, and
//! the planner for a procedure that holds nothing but property operations (the
//! Jung IPS 300 SREG, mask 0021).
//!
//! The value an `LdCtrlWriteProp` writes is its `InlineData` when it carries
//! one, else the value the program's property-located parameters compose
//! ([`bussard_product::compute_property_values`]), as ETS resolves it from the
//! project. A write without `InlineData` on a property no parameter of the
//! program is stored in reads the property's description and writes nothing,
//! as ETS does (issue #841). Any other write whose value neither source
//! supplies is refused; nothing is guessed.

use super::{AppIdentity, FlashPlan, FlashStep, PlanError, PropObject};
use bussard_product::application::{ApplicationProgram, LoadGuard, LoadOp, LoadProcedure};
use bussard_product::dynamic::{DynamicConfig, WhenTest, taken_branches};
use bussard_product::{PropertyObjectRef, PropertyValues};
use std::collections::BTreeMap;

/// The mask whose property-only procedures bussard plans although it does
/// not download the family (0021, the BCU2-family mask of the Jung IPS 300
/// SREG KNX IP interface, issue #390).
pub(super) const PROPERTY_ONLY_MASK: u16 = bussard_mgmt::PROPERTY_ONLY_FLASH_MASK;

/// The interface object type of the device object: always interface object
/// 0 (KNX 3/5/1), so an op naming it by type is addressed by index.
const OT_DEVICE: u32 = 0;

/// Whether `op` decides nothing but property access or the session around it,
/// the operations a property-only procedure may hold.
fn is_property_op(op: &LoadOp) -> bool {
    matches!(
        op,
        LoadOp::Connect
            | LoadOp::Disconnect
            | LoadOp::Restart
            | LoadOp::WriteProp { .. }
            | LoadOp::CompareProp { .. }
    )
}

/// Whether `app`'s load procedure is property-only: every op of every block
/// is a property operation (or a session boundary or restart) and at least one
/// writes or compares a property. The mask gate opens for such a procedure on
/// a family bussard does not otherwise download (mask 0021, issue #390): it
/// touches no memory and no load-state machine.
pub(crate) fn is_property_only(app: &ApplicationProgram) -> bool {
    let ops = || app.load_procedures.iter().flat_map(|p| p.ops.iter());
    ops().next().is_some()
        && ops().all(is_property_op)
        && ops().any(|op| matches!(op, LoadOp::WriteProp { .. } | LoadOp::CompareProp { .. }))
}

/// Whether the branch `guard` names is taken under `config`, by the Dynamic
/// evaluator's `<choose>` semantics ([`taken_branches`]): every `<when>`
/// whose test matches the controlling parameter's value, else the
/// `<when default="true">` branches. A load procedure is a device write, so
/// where the Dynamic walk would quietly fall back to the default branch this
/// refuses instead: a controlling parameter without a value, a value that is
/// not a number, a test bussard does not understand, and an `=`-spelled
/// test ([`WhenTest::Spelled`]).
fn branch_taken(
    app: &ApplicationProgram,
    lp: &LoadProcedure,
    guard: &LoadGuard,
    config: &DynamicConfig,
    step: usize,
) -> Result<bool, PlanError> {
    let choose = lp
        .chooses
        .get(guard.choose)
        .ok_or_else(|| PlanError::UndecidableCondition {
            step,
            reason: "the op names a <choose> the procedure does not hold".to_string(),
        })?;
    let raw = config
        .value(app, None, &choose.param_ref_id)
        .ok_or_else(|| PlanError::UndecidableCondition {
            step,
            reason: format!("parameter ref {} has no value", choose.param_ref_id),
        })?;
    let value: f64 = raw
        .trim()
        .parse()
        .map_err(|_| PlanError::UndecidableCondition {
            step,
            reason: format!(
                "parameter ref {} holds `{raw}`, not a number a <when> test can compare",
                choose.param_ref_id
            ),
        })?;
    // An `=`-spelled test (`=417`, issue #949) is decided by the Dynamic walk
    // only: no capture shows ETS deciding a load-procedure `<choose>` with
    // one, so the planner keeps refusing it.
    if let Some(test) = choose
        .tests
        .iter()
        .find(|t| matches!(t, WhenTest::Unknown(_) | WhenTest::Spelled { .. }))
        .and_then(WhenTest::text)
    {
        return Err(PlanError::UndecidableCondition {
            step,
            reason: format!(
                "the <choose> on {} has a <when test=\"{test}\"> bussard does not understand",
                choose.param_ref_id
            ),
        });
    }
    Ok(taken_branches(&choose.tests, Some(value)).contains(&guard.branch))
}

/// The ops of `lp` whose `<choose>` branches `config` takes, in order. A
/// procedure without `<choose>` returns all of its ops.
///
/// `in_download` says which ops the download runs at all
/// ([`super::plan::assemble_ops`] decides it from `AppliesTo`).
///
/// The evaluation is recursive, as the Dynamic walk's: an op inside nested
/// `<choose>` blocks carries its branches outermost first
/// ([`LoadProcedure::guards_of`]), and runs only when every one of them is
/// taken. An inner `<choose>` is decided only once its enclosing branch is
/// taken, so an inner one behind a branch not taken never refuses (issue
/// #402).
///
/// # Errors
///
/// [`PlanError::UndecidableCondition`] when a `<choose>` the op depends on
/// cannot be decided.
pub(super) fn taken_ops(
    app: &ApplicationProgram,
    lp: &LoadProcedure,
    config: &DynamicConfig,
    in_download: &dyn Fn(&LoadProcedure, usize) -> bool,
) -> Result<Vec<LoadOp>, PlanError> {
    let mut out = Vec::with_capacity(lp.ops.len());
    for (i, op) in lp.ops.iter().enumerate() {
        if !in_download(lp, i) {
            continue;
        }
        let mut taken = true;
        for guard in lp.guards_of(i) {
            if !branch_taken(app, lp, guard, config, i + 1)? {
                taken = false;
                break;
            }
        }
        if taken {
            out.push(op.clone());
        }
    }
    Ok(out)
}

/// The octet ranges each object's `LdCtrlWriteRelMem` ops write, merged and
/// sorted, keyed by object index.
fn rel_mem_coverage<'a>(ops: impl Iterator<Item = &'a LoadOp>) -> BTreeMap<u32, Vec<(u32, u32)>> {
    let mut out: BTreeMap<u32, Vec<(u32, u32)>> = BTreeMap::new();
    for op in ops {
        if let LoadOp::WriteRelMem {
            obj_idx,
            offset,
            size,
            ..
        } = op
        {
            let start = offset.unwrap_or(0);
            let end = start.saturating_add(size.unwrap_or(0));
            if end > start {
                out.entry(obj_idx.unwrap_or(0))
                    .or_default()
                    .push((start, end));
            }
        }
    }
    for ranges in out.values_mut() {
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for &(start, end) in ranges.iter() {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        *ranges = merged;
    }
    out
}

/// The octet ranges `every` covers and `taken` does not (both merged and
/// sorted), in order.
fn gaps(every: &[(u32, u32)], taken: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for &(start, end) in every {
        let mut at = start;
        for &(t_start, t_end) in taken {
            if t_end <= at || t_start >= end {
                continue;
            }
            if t_start > at {
                out.push((at, t_start));
            }
            at = at.max(t_end);
        }
        if at < end {
            out.push((at, end));
        }
    }
    out
}

/// The octets of each object's memory that some branch of the procedure
/// writes (`LdCtrlWriteRelMem`) and the taken branches do not, keyed by
/// object index: the gap a `<choose>` whose taken branch writes part of a
/// segment leaves (issue #411). Empty when the taken branches write every
/// octet any branch writes.
pub(super) fn partial_rel_mem_gaps<'a>(
    every_branch: impl Iterator<Item = &'a LoadOp>,
    taken: &[LoadOp],
) -> BTreeMap<u32, Vec<(u32, u32)>> {
    let taken_cov = rel_mem_coverage(taken.iter());
    rel_mem_coverage(every_branch)
        .into_iter()
        .filter_map(|(obj, every)| {
            let taken = taken_cov.get(&obj).map(Vec::as_slice).unwrap_or(&[]);
            let found = gaps(&every, taken);
            (!found.is_empty()).then_some((obj, found))
        })
        .collect()
}

/// The refusal of a partial segment write on the paths that do not keep the
/// gap on the device: the System 7 and the property-only planners (issue
/// #411 decided only System B, from a capture).
pub(super) fn partial_rel_mem_refusal(gaps: &BTreeMap<u32, Vec<(u32, u32)>>) -> Option<PlanError> {
    let (obj, ranges) = gaps.iter().next()?;
    let &(start, end) = ranges.first()?;
    Some(PlanError::UnsupportedOp {
        op: format!(
            "LdCtrlWriteRelMem in a <choose> whose taken branches leave octets \
             {start}..{end} of object {obj} unwritten (ETS keeps the device's octets \
             there; bussard cannot verify a segment it writes only in part)"
        ),
    })
}

/// Refuses a procedure whose `<choose>` leaves part of an object's memory
/// unwritten: the octets some branch of the procedure writes and the taken
/// branches do not ([`partial_rel_mem_gaps`]).
///
/// The System B planner keeps such a gap on the device instead, as ETS does
/// (issue #411, see `kept_octets`); the System 7 planner still refuses it
/// through [`guarded_ops`]. The corpus survey uses this to find them.
///
/// # Errors
///
/// [`PlanError::UnsupportedOp`] naming the object and the first octet range.
#[cfg(test)]
pub(super) fn refuse_partial_rel_mem<'a>(
    every_branch: impl Iterator<Item = &'a LoadOp>,
    taken: &[LoadOp],
) -> Result<(), PlanError> {
    match partial_rel_mem_refusal(&partial_rel_mem_gaps(every_branch, taken)) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// The self-contained op sequence of `app` (no master-template splice) with
/// each `<choose>` decided under `config`: [`super::plan::assemble_ops`]'s
/// block selection (merged blocks in `MergeId` order, else the richest block),
/// each block filtered to the branches taken.
///
/// # Errors
///
/// [`PlanError::UndecidableCondition`] when a `<choose>` cannot be decided,
/// and [`PlanError::UnsupportedOp`] when the taken branches write only part
/// of what another branch writes (a gap only the System B planner keeps,
/// issue #411).
pub(super) fn guarded_ops(
    app: &ApplicationProgram,
    config: &DynamicConfig,
) -> Result<Vec<LoadOp>, PlanError> {
    let (ops, _, gaps) = super::plan::assemble_ops(app, None, config, super::plan::Download::Full)?;
    match partial_rel_mem_refusal(&gaps) {
        Some(err) => Err(err),
        None => Ok(ops),
    }
}

/// The largest value of the 12-bit fields of the property services (KNX
/// 3/3/7): the start index of `A_PropertyValue_Write`/`_Read` (element 4095),
/// and the property id and object instance of the extended services. An object
/// named by type is written on the extended service (a 16-bit start index) but
/// falls back to the plain one, so the start-index bound holds for it too.
const MAX_12_BIT: u16 = 0x0FFF;

/// How an op names its object: by index when it carries `ObjIdx`, else by
/// `ObjType` and `Occurrence`, the device object by index 0.
pub(super) fn prop_object(
    step: usize,
    obj_idx: Option<u32>,
    obj_type: Option<u32>,
    occurrence: Option<u32>,
) -> Result<PropObject, PlanError> {
    match (obj_idx, obj_type) {
        (Some(index), _) => Ok(PropObject::Index(index)),
        (None, Some(OT_DEVICE)) if occurrence.unwrap_or(0) == 0 => Ok(PropObject::Index(0)),
        (None, Some(object_type)) => {
            let object_type =
                u16::try_from(object_type).map_err(|_| PlanError::UnsupportedWriteProp {
                    step,
                    reason: format!("object type {object_type} exceeds 16 bits"),
                })?;
            let occurrence = u16::try_from(occurrence.unwrap_or(0))
                .ok()
                .filter(|o| *o < MAX_12_BIT)
                .ok_or_else(|| PlanError::UnsupportedWriteProp {
                    step,
                    reason: format!(
                        "occurrence {} of object type {object_type} exceeds the 12-bit \
                         instance the extended property services carry",
                        occurrence.unwrap_or(0)
                    ),
                })?;
            Ok(PropObject::Type {
                object_type,
                occurrence,
            })
        }
        // Neither: the device object, as the System B lowering has always
        // read an op without an object.
        (None, None) => Ok(PropObject::Index(0)),
    }
}

/// The parameter-composed value of the property `object`/`prop_id` names,
/// from `values` ([`bussard_product::compute_property_values`]).
pub(super) fn parameter_value(
    values: &PropertyValues,
    obj_idx: Option<u32>,
    obj_type: Option<u32>,
    occurrence: Option<u32>,
    prop_id: u32,
) -> Option<&Vec<u8>> {
    let by_index = obj_idx.and_then(|i| values.get(&(PropertyObjectRef::Index(i), prop_id)));
    let by_type = obj_type.and_then(|t| {
        values.get(&(
            PropertyObjectRef::Type {
                object_type: t,
                occurrence: occurrence.unwrap_or(0),
            },
            prop_id,
        ))
    });
    by_index.or(by_type)
}

/// Whether a parameter located at `loc` may be stored in the property `prop_id`
/// of `object`. An object named by index on one side and by type on the other
/// cannot be told apart at plan time, and a location naming no object is
/// unplaceable: both count as the same object, so the caller refuses rather
/// than skips.
pub(super) fn may_hold(
    loc: &bussard_product::application::PropertyLocation,
    object: PropObject,
    prop_id: u32,
) -> bool {
    if loc.property_id != prop_id {
        return false;
    }
    match (object, loc.object_index, loc.object_type) {
        (PropObject::Index(index), Some(at), _) => index == at,
        (PropObject::Index(index), None, Some(OT_DEVICE)) => index == 0,
        (
            PropObject::Type {
                object_type,
                occurrence,
            },
            None,
            Some(at),
        ) => u32::from(object_type) == at && u32::from(occurrence) == loc.occurrence.unwrap_or(0),
        _ => true,
    }
}

/// Lowers an `LdCtrlWriteProp` with its `Count` and `Verify` (the System 7
/// and property-only planners, and the System B planner for a write without
/// `InlineData`, issue #669; a System B write with `InlineData` keeps its own
/// lowering).
///
/// A write without `InlineData` on a property no parameter of `app` is stored
/// in lowers to [`FlashStep::DescribeProp`]: ETS reads the property's
/// description and writes nothing (issue #841, `M-00A6_A-0033-20-BFA6`). One
/// from element 1 to an undeclared property the parameters compose a value
/// for is sized as ETS sizes it by the description ([`DescribedSize`], issue
/// #947): `Count` elements, one element, or the description read alone.
///
/// `typed_by_list` is the plan's [`FlashPlan::typed_objects_by_list`]: an
/// object named by type is then written at a listed index on the plain
/// services, so its PID is held to 8 bits ([`check_addressable`]).
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] when a parameter is stored in the
/// property but its value has no source, and the refusals of
/// [`write_prop_step`].
pub(super) fn lower_write_prop(
    step: usize,
    op: &LoadOp,
    values: &PropertyValues,
    app: &ApplicationProgram,
    typed_by_list: bool,
) -> Result<FlashStep, PlanError> {
    let LoadOp::WriteProp {
        obj_idx,
        obj_type,
        prop_id,
        inline_data,
        start_element,
        count,
        verify,
        occurrence,
    } = op
    else {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: "not an LdCtrlWriteProp".to_string(),
        });
    };
    let prop_id = prop_id.ok_or_else(|| PlanError::UnsupportedWriteProp {
        step,
        reason: "the op names no PropId".to_string(),
    })?;
    let object = prop_object(step, *obj_idx, *obj_type, *occurrence)?;
    let name = format!("{object} PID {prop_id}");
    let mut count = *count;
    let (value, from_parameters) = match inline_data.as_ref().filter(|d| !d.is_empty()) {
        Some(data) => (data.clone(), false),
        None => match parameter_value(values, *obj_idx, *obj_type, *occurrence, prop_id) {
            Some(value) if start_element.unwrap_or(1) <= 1 && !declared(app, object, prop_id) => {
                match sized_by_description(count, value.len()) {
                    DescribedSize::Elements(elements) => {
                        count = Some(elements);
                        (value.to_vec(), true)
                    }
                    DescribedSize::VariableLength => {
                        check_addressable(step, object, prop_id, typed_by_list)?;
                        return Ok(FlashStep::DescribeProp {
                            object,
                            prop_id,
                            unwritten: Some(value.len()),
                        });
                    }
                }
            }
            Some(value) => {
                let target = WriteTarget {
                    object,
                    prop_id,
                    start_element: *start_element,
                    count,
                };
                (elements_of_property(step, &name, value, app, target)?, true)
            }
            None if !app.parameters.values().any(|p| {
                p.property
                    .as_ref()
                    .is_some_and(|loc| may_hold(loc, object, prop_id))
            }) =>
            {
                // Nothing in the program decides the property: ETS reads its
                // description and writes nothing (issue #841).
                if let PropObject::Index(index) = object
                    && index > u32::from(u8::MAX)
                {
                    return Err(PlanError::UnsupportedWriteProp {
                        step,
                        reason: format!(
                            "object index {index} exceeds the 8-bit index the services address"
                        ),
                    });
                }
                return Ok(FlashStep::DescribeProp {
                    object,
                    prop_id,
                    unwritten: None,
                });
            }
            None => {
                return Err(PlanError::UnsupportedWriteProp {
                    step,
                    reason: format!(
                        "the write to {name} carries no InlineData and the value the program's \
                         parameters store in that property could not be composed, so bussard \
                         has no value to write"
                    ),
                });
            }
        },
    };
    write_prop_step(
        step,
        WriteTarget {
            object,
            prop_id,
            start_element: *start_element,
            count,
        },
        value,
        from_parameters,
        verify.unwrap_or(false),
        typed_by_list,
    )
}

/// How ETS sizes an undeclared `LdCtrlWriteProp` without `InlineData` from
/// element 1: by the property's description, which it reads first (issue
/// #947). A device holding what the product implies describes the property
/// from the `len` octets the parameters placed in it compose and the op's
/// `Count` (knx-sim `Property::product_written`, #983):
///
/// - `Count` elements of `len / Count` octets when `Count` divides `len`:
///   ETS writes the `Count` elements (`M-007C_A-0002-30-DC22` object 8 PID
///   64, `Count="988"`, 3952 octets: 988 elements of 4 in 66 requests);
/// - else one element of the whole value, `PDT_GENERIC_01` to `_20`, when
///   `len` is 1 to 20 octets: ETS writes it as `count=1` (DC22 PID 69,
///   `Count="64"`, 4 octets; `M-007C_A-0003-43-4813` PID 68, the 4-octet IP
///   address under `Count="64"`);
/// - else one element of `PDT_VARIABLE_LENGTH`: ETS reads the description and
///   writes nothing (`M-007C_A-0001-10-2A85` PIDs 64 and 66, `Count="500"`,
///   256 octets; PIDs 68 and 69, 40 octets under `Count="64"`; DC22 PID 68,
///   240 octets under `Count="100"`; 4813 PID 69, 108 octets).
///
/// All ten such writes of the sweep's captures, and the 29 whose `Count`
/// divides the value, follow it (issue #947, 2026-11-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescribedSize {
    /// Written as this many elements from element 1.
    Elements(u32),
    /// Described as variable-length: not written.
    VariableLength,
}

/// The largest element a generic PDT describes: `PDT_GENERIC_20`.
const MAX_GENERIC_OCTETS: usize = 20;

/// The size ETS writes a composed value of `len` octets in under the op's
/// `count` ([`DescribedSize`]).
fn sized_by_description(count: Option<u32>, len: usize) -> DescribedSize {
    let count = super::declare::undeclared_element_count(count);
    let divides = usize::try_from(count).is_ok_and(|c| len.is_multiple_of(c));
    if len > 0 && divides {
        DescribedSize::Elements(count)
    } else if (1..=MAX_GENERIC_OCTETS).contains(&len) {
        DescribedSize::Elements(1)
    } else {
        DescribedSize::VariableLength
    }
}

/// Whether an `LdCtrlDeclarePropDesc` of `app`'s procedures declares
/// `object`/`prop_id`: its description is then the declared one, which
/// [`elements_of_property`] and `flash/declare.rs` size by.
fn declared(app: &ApplicationProgram, object: PropObject, prop_id: u32) -> bool {
    app.load_procedures
        .iter()
        .flat_map(|p| p.ops.iter())
        .any(|op| match op {
            LoadOp::DeclarePropDesc {
                obj_idx,
                obj_type,
                occurrence,
                prop_id: Some(declared),
                ..
            } => {
                *declared == prop_id
                    && prop_object(0, *obj_idx, *obj_type, *occurrence).ok() == Some(object)
            }
            _ => false,
        })
}

/// The octets of `property`, the value the parameters compose for the
/// whole property from element 1, that the write to `target` sends. From element 1 the value as it stands (the shape
/// every capture before issue #951 shows: `M-0009_A-E801-13-F381` writes the
/// 124 octets of object 9 PID 208 as `Count="124"`). From a later element
/// the write's own elements: ETS writes `count=1 index=16 len=1` for the
/// count-less `ObjIdx="12" PropId="208" StartElement="16"` of
/// `M-0009_A-E0EE-10-ADF8` (op 34), not the property's 48 octets. Their
/// size is the one an `LdCtrlDeclarePropDesc` of the procedure gives the
/// property (`PDT_GENERIC_01` there, declared after the write).
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] for a write past element 1 to a
/// property no declaration of the procedure sizes.
fn elements_of_property(
    step: usize,
    name: &str,
    property: &[u8],
    app: &ApplicationProgram,
    target: WriteTarget,
) -> Result<Vec<u8>, PlanError> {
    let WriteTarget {
        object,
        prop_id,
        start_element,
        count,
    } = target;
    let start = start_element.unwrap_or(1).max(1);
    if start == 1 {
        return Ok(property.to_vec());
    }
    let elem = app
        .load_procedures
        .iter()
        .flat_map(|p| p.ops.iter())
        .find_map(|op| match op {
            LoadOp::DeclarePropDesc {
                obj_idx,
                obj_type,
                occurrence,
                prop_id: Some(declared),
                prop_type: Some(prop_type),
                ..
            } if *declared == prop_id
                && prop_object(step, *obj_idx, *obj_type, *occurrence).ok() == Some(object) =>
            {
                super::declare::pdt_element_size(prop_type)
            }
            _ => None,
        })
        .ok_or_else(|| PlanError::UnsupportedWriteProp {
            step,
            reason: format!(
                "the write to {name} starts at element {start} with the value the parameters \
                 compose for the whole property, and no LdCtrlDeclarePropDesc of the procedure \
                 gives the size of its elements; bussard does not guess which octets it sends"
            ),
        })?;
    let count = super::declare::undeclared_element_count(count) as usize;
    let from = (start as usize - 1).saturating_mul(elem);
    let len = count.saturating_mul(elem);
    // The parameters' value never gains octets they do not compose, as the
    // write from element 1 does not.
    property
        .get(from..from.saturating_add(len))
        .map(<[u8]>::to_vec)
        .ok_or_else(|| PlanError::UnsupportedWriteProp {
            step,
            reason: format!(
                "the write to {name} sends elements {start} to {} ({len} octets from octet \
                 {from}), past the {} octets the parameters compose for the property; bussard \
                 does not make up the missing octets",
                start as usize + count - 1,
                property.len()
            ),
        })
}

/// What an undeclared `LdCtrlWriteProp` writes to: the object, the PID, and
/// the op's `StartElement` and `Count` as the procedure gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WriteTarget {
    /// The object the op names ([`prop_object`]).
    pub(super) object: PropObject,
    /// The property id.
    pub(super) prop_id: u32,
    /// `StartElement`, 1 when absent or 0.
    pub(super) start_element: Option<u32>,
    /// `Count`, one element when absent
    /// ([`undeclared_element_count`](super::declare::undeclared_element_count)).
    pub(super) count: Option<u32>,
}

/// Whether the services reach `object`/`prop_id`: an index and its PID go
/// out on the plain services (8 bits each); an object named by type on the
/// extended ones (a 12-bit PID), unless `typed_by_list`, where the System B
/// executor writes it at the index the device's object list gives it on the
/// plain services (issue #948), so the PID is held to 8 bits at plan time
/// rather than refused at execute time after the unload (issue #964).
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] naming the index or PID out of reach.
pub(super) fn check_addressable(
    step: usize,
    object: PropObject,
    prop_id: u32,
    typed_by_list: bool,
) -> Result<(), PlanError> {
    if let PropObject::Index(index) = object
        && index > u32::from(u8::MAX)
    {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: format!("object index {index} exceeds the 8-bit index the services address"),
        });
    }
    let (pid_limit, services) = match object {
        PropObject::Index(_) => (u32::from(u8::MAX), "the plain property services"),
        PropObject::Type { .. } if typed_by_list => (
            u32::from(u8::MAX),
            "the plain property services, which write an object named by type at the index \
             the device's object list gives it on a program that is not Data Secure enabled",
        ),
        PropObject::Type { .. } => (u32::from(MAX_12_BIT), "the extended property services"),
    };
    if prop_id > pid_limit {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: format!(
                "property id {prop_id} of {object} exceeds the {}-bit PID {services} address",
                if pid_limit == u32::from(u8::MAX) {
                    8
                } else {
                    12
                }
            ),
        });
    }
    Ok(())
}

/// The [`FlashStep::WriteProp`] of `value` to `target` an undeclared
/// `LdCtrlWriteProp` lowers to, with `verify` as the caller decides it: the
/// one rule of the System B planner's writes with and without `InlineData`
/// and of the System 7 and property-only planners (issues #957, #964).
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] when the write reaches past the
/// 12-bit start index, the value does not split into `Count` whole elements,
/// or the object or property id does not fit the services that address it
/// ([`check_addressable`]).
pub(super) fn write_prop_step(
    step: usize,
    target: WriteTarget,
    value: Vec<u8>,
    from_parameters: bool,
    verify: bool,
    typed_by_list: bool,
) -> Result<FlashStep, PlanError> {
    let WriteTarget {
        object,
        prop_id,
        start_element,
        count,
    } = target;
    let name = format!("{object} PID {prop_id}");
    let start_element = start_element.unwrap_or(1).max(1);
    // `Count` is a 16-bit element count in the procedure; only the per-request
    // count is a nibble, and the executor splits the write into requests of at
    // most 15 elements on the plain service (ETS writes `Count="500"` to object
    // 8 PID 64 of the Jung Sonos-Gateway as 34 requests from element 1 to 496,
    // issue #947). What bounds the write is the 12-bit start index of its last
    // request: element 4095.
    // The one Count rule of both System B planners (issue #957).
    let count = super::declare::undeclared_element_count(count);
    let last_element = u64::from(start_element) + u64::from(count) - 1;
    if last_element > u64::from(MAX_12_BIT) {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: format!(
                "the write to {name} has Count {count} from element {start_element}, past \
                 element {MAX_12_BIT}, the last the 12-bit start index addresses"
            ),
        });
    }
    // Both fit 12 bits: the last element, their sum, does.
    let (start_element, count) = (start_element as u16, count as u16);
    if !value.len().is_multiple_of(usize::from(count)) {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: format!(
                "the {}-octet value for {name} does not split into Count {count} whole elements",
                value.len()
            ),
        });
    }
    check_addressable(step, object, prop_id, typed_by_list)?;
    Ok(FlashStep::WriteProp {
        object,
        prop_id,
        value,
        start_element,
        count,
        verify,
        from_parameters,
    })
}

/// The element an `LdCtrlCompareProp` reads: its `StartElement`, 1 when
/// absent or 0.
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] for an element past the 12-bit start
/// index of `A_PropertyValue_Read`.
pub(super) fn compare_start_element(
    step: usize,
    start_element: Option<u32>,
) -> Result<u16, PlanError> {
    let start = start_element.unwrap_or(1).max(1);
    u16::try_from(start)
        .ok()
        .filter(|s| *s <= MAX_12_BIT)
        .ok_or_else(|| PlanError::UnsupportedWriteProp {
            step,
            reason: format!("compare start element {start} exceeds the 12-bit start index"),
        })
}

/// Lowers an `LdCtrlCompareProp`.
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] when the op names an object the
/// services cannot address.
pub(super) fn lower_compare_prop(step: usize, op: &LoadOp) -> Result<FlashStep, PlanError> {
    let LoadOp::CompareProp {
        obj_idx,
        obj_type,
        prop_id,
        inline_data,
        mask,
        occurrence,
        start_element,
        ..
    } = op
    else {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: "not an LdCtrlCompareProp".to_string(),
        });
    };
    Ok(FlashStep::CompareProp {
        object: prop_object(step, *obj_idx, *obj_type, *occurrence)?,
        prop_id: prop_id.unwrap_or(0),
        expected: inline_data.clone(),
        mask: mask.clone(),
        start_element: compare_start_element(step, *start_element)?,
    })
}

/// Plans a property-only procedure ([`is_property_only`]): its compares and
/// writes, in order, and a restart when the procedure asks for one. Nothing
/// is loaded, so the plan carries no images.
///
/// # Errors
///
/// [`PlanError::NoProcedure`] for an empty procedure, and the lowering errors
/// of [`lower_write_prop`] and [`lower_compare_prop`].
pub(super) fn plan_flash_properties(
    app: &ApplicationProgram,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    memo: &bussard_product::dynamic::DynamicMemo<'_, ApplicationProgram>,
) -> Result<FlashPlan, PlanError> {
    let app_mask = app
        .mask_version
        .clone()
        .ok_or_else(|| PlanError::MissingAppMask(app.id.clone()))?;
    let config = memo.evaluate_for(app, overrides);
    let ops = guarded_ops(app, &config)?;
    if ops.is_empty() {
        return Err(PlanError::NoProcedure(app.id.clone()));
    }
    let values = bussard_product::compute_property_values(app, &config).map_err(|e| {
        PlanError::UnsupportedWriteProp {
            step: 0,
            reason: format!("composing the property values from the parameters: {e}"),
        }
    })?;
    let mut steps = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let step = i + 1;
        match op {
            LoadOp::Connect | LoadOp::Disconnect => {}
            LoadOp::Restart => steps.push(FlashStep::Restart),
            LoadOp::WriteProp { .. } => {
                steps.push(lower_write_prop(step, op, &values, app, false)?)
            }
            LoadOp::CompareProp { .. } => steps.push(lower_compare_prop(step, op)?),
            other => {
                return Err(PlanError::UnsupportedOp {
                    op: format!("{other:?}"),
                });
            }
        }
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
        images: BTreeMap::new(),
        param_images: BTreeMap::new(),
        spliced_from_template: false,
        sys7: None,
        confirmed_restart: false,
        baseline: BTreeMap::new(),
        placed: BTreeMap::new(),
        unwritten: BTreeMap::new(),
        baseline_address: BTreeMap::new(),
        security_capacity: Default::default(),
        user_memory_above_64k: false,
        typed_objects_by_list: false,
        par_allocations: BTreeMap::new(),
        par_procedure: false,
        par_steps: None,
        parameters_only: false,
        kept: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::test_support::plan_flash_default;
    use bussard_product::application::LoadGuard;
    use bussard_product::application::parse_application_program;
    use bussard_product::dynamic::DynamicMemo;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// An MDT 0705-shaped procedure: a label write guarded by `P-18 >= 3`, a
    /// default branch, and a 0701-shaped inline `Count="2"` write.
    fn guarded_app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram PeiType="0" Id="M-0083_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-0705" Name="G">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-0083_A-1_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="9" /></ParameterType>
            <ParameterType Id="M-0083_A-1_PT-t" Name="t"><TypeText SizeInBit="32" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-0083_A-1_P-18" Name="mode" ParameterType="M-0083_A-1_PT-u8" Value="1" />
            <Parameter Id="M-0083_A-1_P-36" Name="label" ParameterType="M-0083_A-1_PT-t" Value="Off">
             <Property ObjectIndex="6" PropertyId="60" Offset="0" BitOffset="0" />
            </Parameter>
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-0083_A-1_P-18_R-8" RefId="M-0083_A-1_P-18" />
            <ParameterRef Id="M-0083_A-1_P-36_R-36" RefId="M-0083_A-1_P-36" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <choose ParamRefId="M-0083_A-1_P-18_R-8">
              <when test="&gt;=3">
               <LdCtrlWriteProp ObjIdx="6" PropId="60" Verify="false" />
              </when>
              <when default="true">
               <LdCtrlCompareProp InlineData="01" ObjIdx="0" PropId="19" />
              </when>
             </choose>
             <LdCtrlWriteProp ObjIdx="3" PropId="204" Count="2" Verify="false" InlineData="00004000000076FF0000" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="M-0083_A-1_PB-1">
           <ParameterRefRef RefId="M-0083_A-1_P-18_R-8" />
           <ParameterRefRef RefId="M-0083_A-1_P-36_R-36" />
          </ParameterBlock></ChannelIndependentBlock></Dynamic>
         </ApplicationProgram></KNX>"#;
        Ok(parse_application_program("M-0083_A-1", xml.as_bytes())?)
    }

    fn ops_for(app: &ApplicationProgram, mode: &str) -> Result<Vec<LoadOp>, PlanError> {
        let memo = DynamicMemo::new(app);
        let overrides = BTreeMap::from([("P-18_R-8".to_string(), mode.to_string())]);
        guarded_ops(app, &memo.evaluate_for(app, &overrides))
    }

    #[test]
    fn test_guarded_ops_takes_the_matching_branch() -> TestResult {
        let app = guarded_app()?;
        let taken = ops_for(&app, "3")?;
        assert!(taken.iter().any(|op| matches!(
            op,
            LoadOp::WriteProp {
                prop_id: Some(60),
                ..
            }
        )));
        assert!(
            !taken
                .iter()
                .any(|op| matches!(op, LoadOp::CompareProp { .. }))
        );
        Ok(())
    }

    #[test]
    fn test_guarded_ops_takes_the_default_branch() -> TestResult {
        let app = guarded_app()?;
        let taken = ops_for(&app, "1")?;
        assert!(!taken.iter().any(|op| matches!(
            op,
            LoadOp::WriteProp {
                prop_id: Some(60),
                ..
            }
        )));
        assert!(
            taken
                .iter()
                .any(|op| matches!(op, LoadOp::CompareProp { .. }))
        );
        // The unguarded ops always run.
        assert_eq!(taken.len(), 4);
        Ok(())
    }

    #[test]
    fn test_guarded_ops_refuses_a_value_it_cannot_compare() -> TestResult {
        let app = guarded_app()?;
        assert!(matches!(
            ops_for(&app, "three"),
            Err(PlanError::UndecidableCondition { .. })
        ));
        Ok(())
    }

    /// An application placing `9` at octet 0 and `1` at octet 15 of object
    /// 12 PID 208, writing it from element 16 without `Count`, then
    /// `declaration` (issue #951, the shape of `M-0009_A-E0EE-10-ADF8`).
    fn element_app(declaration: &str) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-0009_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="E">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-0009_A-1_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="9" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-0009_A-1_P-1" Name="a" ParameterType="M-0009_A-1_PT-u8" Value="9">
             <Property ObjectIndex="12" PropertyId="208" Offset="0" BitOffset="0" />
            </Parameter>
            <Parameter Id="M-0009_A-1_P-2" Name="b" ParameterType="M-0009_A-1_PT-u8" Value="1">
             <Property ObjectIndex="12" PropertyId="208" Offset="15" BitOffset="0" />
            </Parameter>
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-0009_A-1_P-1_R-1" RefId="M-0009_A-1_P-1" />
            <ParameterRef Id="M-0009_A-1_P-2_R-2" RefId="M-0009_A-1_P-2" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlWriteProp ObjIdx="12" PropId="208" StartElement="16" Verify="false" />
             {declaration}
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        Ok(parse_application_program("M-0009_A-1", xml.as_bytes())?)
    }

    #[test]
    fn test_lower_write_prop_writes_the_elements_from_its_start() -> TestResult {
        // Issue #951: ETS writes `count=1 index=16 len=1` for the count-less
        // `StartElement="16"` write of `M-0009_A-E0EE-10-ADF8`, the element
        // the later `PDT_GENERIC_01` declaration sizes, not the property.
        let app = element_app(
            r#"<LdCtrlDeclarePropDesc ObjIdx="12" PropId="208" PropType="PDT_GENERIC_01" MaxElements="46" Writable="true" />"#,
        )?;
        let config = DynamicMemo::new(&app).evaluate_for(&app, &BTreeMap::new());
        let values = bussard_product::compute_property_values(&app, &config)?;
        let op = &app.load_procedures[0].ops[0];
        assert_eq!(
            lower_write_prop(1, op, &values, &app, false)?,
            FlashStep::WriteProp {
                object: PropObject::Index(12),
                prop_id: 208,
                value: vec![1],
                start_element: 16,
                count: 1,
                verify: false,
                from_parameters: true,
            }
        );
        // A write past the octets the parameters compose is refused, not
        // padded (review of #1011).
        let app = element_app(
            r#"<LdCtrlDeclarePropDesc ObjIdx="12" PropId="208" PropType="PDT_GENERIC_02" MaxElements="46" Writable="true" />"#,
        )?;
        let config = DynamicMemo::new(&app).evaluate_for(&app, &BTreeMap::new());
        let values = bussard_product::compute_property_values(&app, &config)?;
        let op = &app.load_procedures[0].ops[0];
        match lower_write_prop(1, op, &values, &app, false) {
            Err(PlanError::UnsupportedWriteProp { reason, .. }) => {
                assert!(reason.contains("does not make up"), "{reason}");
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }
        // Without a declaration the element size is unknown: refused.
        let app = element_app("")?;
        let config = DynamicMemo::new(&app).evaluate_for(&app, &BTreeMap::new());
        let values = bussard_product::compute_property_values(&app, &config)?;
        let op = &app.load_procedures[0].ops[0];
        match lower_write_prop(1, op, &values, &app, false) {
            Err(PlanError::UnsupportedWriteProp { reason, .. }) => {
                assert!(reason.contains("size of its elements"), "{reason}");
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_takes_the_parameter_value_and_the_count() -> TestResult {
        let app = guarded_app()?;
        let memo = DynamicMemo::new(&app);
        let config = memo.evaluate_for(&app, &BTreeMap::new());
        let values = bussard_product::compute_property_values(&app, &config)?;
        let ops = ops_for(&app, "3")?;
        let label = ops
            .iter()
            .find(|op| {
                matches!(
                    op,
                    LoadOp::WriteProp {
                        prop_id: Some(60),
                        ..
                    }
                )
            })
            .ok_or("the label write is taken")?;
        assert_eq!(
            lower_write_prop(2, label, &values, &app, false)?,
            FlashStep::WriteProp {
                object: PropObject::Index(6),
                prop_id: 60,
                value: b"Off\0".to_vec(),
                start_element: 1,
                count: 1,
                verify: false,
                from_parameters: true,
            }
        );
        let inline = ops
            .iter()
            .find(|op| {
                matches!(
                    op,
                    LoadOp::WriteProp {
                        prop_id: Some(204),
                        ..
                    }
                )
            })
            .ok_or("the inline write is unguarded")?;
        match lower_write_prop(3, inline, &values, &app, false)? {
            FlashStep::WriteProp {
                count,
                value,
                from_parameters,
                ..
            } => {
                assert_eq!(count, 2);
                assert_eq!(value.len(), 10);
                assert!(
                    !from_parameters,
                    "an InlineData value is not your project's"
                );
            }
            other => return Err(format!("expected WriteProp, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_refuses_a_value_that_does_not_split_into_count() -> TestResult {
        let op = LoadOp::WriteProp {
            obj_idx: Some(3),
            obj_type: None,
            prop_id: Some(204),
            inline_data: Some(vec![0; 9]),
            start_element: None,
            count: Some(2),
            verify: None,
            occurrence: None,
        };
        assert!(matches!(
            lower_write_prop(1, &op, &PropertyValues::new(), &guarded_app()?, false),
            Err(PlanError::UnsupportedWriteProp { .. })
        ));
        Ok(())
    }

    /// The ise smart connect's count-only write to object 8 (issue #947).
    fn ise_write(prop_id: u32, count: u32) -> LoadOp {
        LoadOp::WriteProp {
            obj_idx: Some(8),
            obj_type: None,
            prop_id: Some(prop_id),
            inline_data: None,
            start_element: None,
            count: Some(count),
            verify: Some(false),
            occurrence: None,
        }
    }

    #[test]
    fn test_sized_by_description_follows_the_captures() {
        // DC22 PID 64: 988 elements of 4 octets.
        assert_eq!(
            sized_by_description(Some(988), 3952),
            DescribedSize::Elements(988)
        );
        // DC22 PID 69 and 4813 PID 68: 4 octets under Count 64, one element.
        assert_eq!(
            sized_by_description(Some(64), 4),
            DescribedSize::Elements(1)
        );
        assert_eq!(
            sized_by_description(Some(64), 20),
            DescribedSize::Elements(1)
        );
        // 2A85 PID 64 (256 octets, Count 500), 4813 PID 69 (108, Count 64),
        // and 2A85 PID 68 (40, Count 64): variable-length, not written.
        assert_eq!(
            sized_by_description(Some(500), 256),
            DescribedSize::VariableLength
        );
        assert_eq!(
            sized_by_description(Some(64), 108),
            DescribedSize::VariableLength
        );
        assert_eq!(
            sized_by_description(Some(64), 21),
            DescribedSize::VariableLength
        );
        // No Count: one element, as before.
        assert_eq!(sized_by_description(None, 300), DescribedSize::Elements(1));
    }

    #[test]
    fn test_lower_write_prop_leaves_out_a_variable_length_property() -> TestResult {
        // `M-007C_A-0001-10-2A85` step 31: 64 parameters of 4 octets in
        // object 8 PID 64 under `Count="500"`; ETS reads the description and
        // writes nothing (ops 43, 44).
        let mut values = PropertyValues::new();
        values.insert((PropertyObjectRef::Index(8), 64), vec![0; 256]);
        assert_eq!(
            lower_write_prop(31, &ise_write(64, 500), &values, &guarded_app()?, false)?,
            FlashStep::DescribeProp {
                object: PropObject::Index(8),
                prop_id: 64,
                unwritten: Some(256),
            }
        );
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_writes_a_short_value_as_one_element() -> TestResult {
        // `M-007C_A-0002-30-DC22` op 210: one 32-bit parameter in object 8
        // PID 69 under `Count="64"`, written `count=1 index=1 len=4`.
        let mut values = PropertyValues::new();
        values.insert((PropertyObjectRef::Index(8), 69), vec![0, 0, 0, 1]);
        assert_eq!(
            lower_write_prop(35, &ise_write(69, 64), &values, &guarded_app()?, false)?,
            FlashStep::WriteProp {
                object: PropObject::Index(8),
                prop_id: 69,
                value: vec![0, 0, 0, 1],
                start_element: 1,
                count: 1,
                verify: false,
                from_parameters: true,
            }
        );
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_writes_count_elements_that_split() -> TestResult {
        // DC22 op 75: 988 elements of 4 octets.
        let mut values = PropertyValues::new();
        values.insert((PropertyObjectRef::Index(8), 64), vec![7; 3952]);
        match lower_write_prop(31, &ise_write(64, 988), &values, &guarded_app()?, false)? {
            FlashStep::WriteProp {
                count,
                value,
                start_element,
                ..
            } => {
                assert_eq!((start_element, count, value.len()), (1, 988, 3952));
            }
            other => return Err(format!("expected WriteProp, got {other:?}").into()),
        }
        Ok(())
    }

    /// A data-less write on a property no parameter is stored in.
    fn dataless_write(obj_idx: Option<u32>, obj_type: Option<u32>, prop_id: u32) -> LoadOp {
        LoadOp::WriteProp {
            obj_idx,
            obj_type,
            prop_id: Some(prop_id),
            inline_data: None,
            start_element: None,
            count: None,
            verify: Some(false),
            occurrence: None,
        }
    }

    #[test]
    fn test_lower_write_prop_describes_a_property_no_parameter_is_stored_in() -> TestResult {
        // The Enertex `PID_ENX_TELEGRAMMRATE_LIMIT` step of
        // `M-00A6_A-0033-20-BFA6` (issue #841): ETS reads the description of
        // 50001/211 and writes nothing.
        let app = guarded_app()?;
        let op = dataless_write(None, Some(50001), 211);
        assert_eq!(
            lower_write_prop(21, &op, &PropertyValues::new(), &app, false)?,
            FlashStep::DescribeProp {
                object: PropObject::Type {
                    object_type: 50001,
                    occurrence: 0,
                },
                prop_id: 211,
                unwritten: None,
            }
        );
        let op = dataless_write(Some(6), None, 61);
        assert_eq!(
            lower_write_prop(1, &op, &PropertyValues::new(), &app, false)?,
            FlashStep::DescribeProp {
                object: PropObject::Index(6),
                prop_id: 61,
                unwritten: None,
            }
        );
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_refuses_a_stored_property_without_a_value() -> TestResult {
        // The label parameter lives in object 6 PID 60: without its composed
        // value the write is refused, never turned into a description read.
        let app = guarded_app()?;
        let op = dataless_write(Some(6), None, 60);
        assert!(matches!(
            lower_write_prop(1, &op, &PropertyValues::new(), &app, false),
            Err(PlanError::UnsupportedWriteProp { .. })
        ));
        // Named by type, the object cannot be told apart from index 6: refused.
        let op = dataless_write(None, Some(17), 60);
        assert!(matches!(
            lower_write_prop(1, &op, &PropertyValues::new(), &app, false),
            Err(PlanError::UnsupportedWriteProp { .. })
        ));
        Ok(())
    }

    /// A write of `count` elements without `InlineData` to object 8 `prop_id`,
    /// as the ise smart connect and Jung Sonos procedures carry it.
    fn count_write(prop_id: u32, count: u32) -> LoadOp {
        LoadOp::WriteProp {
            obj_idx: Some(8),
            obj_type: None,
            prop_id: Some(prop_id),
            inline_data: None,
            start_element: None,
            count: Some(count),
            verify: Some(false),
            occurrence: None,
        }
    }

    #[test]
    fn test_lower_write_prop_takes_a_count_of_500() -> TestResult {
        // `M-0004_A-B015-21-F7AD-O007C` (issue #947): `Count="500"` on object 8
        // PID 64, four-octet elements composed from the parameters. ETS writes
        // them in 34 requests from element 1 to 496 (ops 59 to 92).
        let app = guarded_app()?;
        let value: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let values = PropertyValues::from([((PropertyObjectRef::Index(8), 64), value.clone())]);
        assert_eq!(
            lower_write_prop(32, &count_write(64, 500), &values, &app, false)?,
            FlashStep::WriteProp {
                object: PropObject::Index(8),
                prop_id: 64,
                value,
                start_element: 1,
                count: 500,
                verify: false,
                from_parameters: true,
            }
        );
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_refuses_a_count_past_the_start_index() -> TestResult {
        // Element 4096 is past the 12-bit start index of the last request.
        let app = guarded_app()?;
        let values = PropertyValues::from([((PropertyObjectRef::Index(8), 64), vec![0; 4096])]);
        match lower_write_prop(7, &count_write(64, 4096), &values, &app, false) {
            Err(PlanError::UnsupportedWriteProp { step: 7, reason }) => {
                assert!(reason.contains("Count 4096"), "{reason}");
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }
        // 4095 elements end on the last addressable element.
        let values = PropertyValues::from([((PropertyObjectRef::Index(8), 64), vec![0; 4095])]);
        assert!(matches!(
            lower_write_prop(7, &count_write(64, 4095), &values, &app, false)?,
            FlashStep::WriteProp { count: 4095, .. }
        ));
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_count_without_inline_data() -> TestResult {
        // `M-007C_A-0006-20-C776` (issue #947): `Count="237"` on object 8 PID
        // 64 without `InlineData` writes the 237 elements the parameters
        // compose.
        let app = guarded_app()?;
        let values = PropertyValues::from([((PropertyObjectRef::Index(8), 64), vec![7; 948])]);
        assert!(matches!(
            lower_write_prop(28, &count_write(64, 237), &values, &app, false)?,
            FlashStep::WriteProp {
                count: 237,
                from_parameters: true,
                ..
            }
        ));
        // `Count="64"` on object 8 PID 68, which no parameter is stored in:
        // ETS reads the description and writes nothing
        // (`M-007C_A-000E-20-E64D` op 130, `M-007C_A-0010-20-5E04` op 130).
        assert_eq!(
            lower_write_prop(30, &count_write(68, 64), &values, &app, false)?,
            FlashStep::DescribeProp {
                object: PropObject::Index(8),
                prop_id: 68,
                unwritten: None,
            }
        );
        Ok(())
    }

    #[test]
    fn test_is_property_only_needs_a_property_op() -> TestResult {
        let app = guarded_app()?;
        assert!(is_property_only(&app));
        let mut connect_only = app.clone();
        for lp in &mut connect_only.load_procedures {
            lp.ops
                .retain(|op| matches!(op, LoadOp::Connect | LoadOp::Disconnect));
        }
        assert!(!is_property_only(&connect_only));
        Ok(())
    }

    /// A procedure with a `<choose>` nested in a `<when>`: the outer one on
    /// `P-18` (`>=3` or default), the inner one on `P-20` inside the `>=3`
    /// branch (`0` writes PID 60, `1` PID 61, default PID 62; a self-closed `<when test="2"/>` takes no op).
    fn nested_app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        nested_app_with(r#"<when test="0">"#)
    }

    /// [`nested_app`] with the inner choose's first `<when>` written as
    /// `inner_when`.
    fn nested_app_with(inner_when: &str) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram PeiType="0" Id="M-0083_A-2" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-0705" Name="N">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-0083_A-2_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="9" /></ParameterType>
            <ParameterType Id="M-0083_A-2_PT-t" Name="t"><TypeText SizeInBit="32" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-0083_A-2_P-18" Name="mode" ParameterType="M-0083_A-2_PT-u8" Value="1" />
            <Parameter Id="M-0083_A-2_P-20" Name="label" ParameterType="M-0083_A-2_PT-u8" Value="0" />
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-0083_A-2_P-18_R-8" RefId="M-0083_A-2_P-18" />
            <ParameterRef Id="M-0083_A-2_P-20_R-9" RefId="M-0083_A-2_P-20" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <choose ParamRefId="M-0083_A-2_P-18_R-8">
              <when test="&gt;=3">
               <LdCtrlWriteProp ObjIdx="6" PropId="59" InlineData="01" Verify="false" />
               <choose ParamRefId="M-0083_A-2_P-20_R-9">
                INNER_WHEN
                 <LdCtrlWriteProp ObjIdx="6" PropId="60" InlineData="00" Verify="false" />
                </when>
                <when test="1">
                 <LdCtrlWriteProp ObjIdx="6" PropId="61" InlineData="01" Verify="false" />
                </when>
                <when test="2" />
                <when default="true">
                 <LdCtrlWriteProp ObjIdx="6" PropId="62" InlineData="02" Verify="false" />
                </when>
               </choose>
               <LdCtrlWriteProp ObjIdx="6" PropId="63" InlineData="03" Verify="false" />
              </when>
              <when default="true">
               <LdCtrlCompareProp InlineData="01" ObjIdx="0" PropId="19" />
              </when>
             </choose>
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#
            .replace("INNER_WHEN", inner_when);
        Ok(parse_application_program("M-0083_A-2", xml.as_bytes())?)
    }

    #[test]
    fn test_guarded_ops_refuses_an_equals_spelled_test() -> TestResult {
        // `test="=0"` is decided by the Dynamic walk (issue #949), but no
        // capture shows ETS deciding a load-procedure choose with it: the
        // planner refuses, naming the test as written.
        let app = nested_app_with(r#"<when test="=0">"#)?;
        let memo = DynamicMemo::new(&app);
        let overrides = BTreeMap::from([
            ("P-18_R-8".to_string(), "3".to_string()),
            ("P-20_R-9".to_string(), "0".to_string()),
        ]);
        match guarded_ops(&app, &memo.evaluate_for(&app, &overrides)) {
            Err(PlanError::UndecidableCondition { reason, .. }) => {
                assert!(reason.contains(r#"test="=0""#), "{reason}");
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }
        Ok(())
    }

    /// The property ids the taken ops of [`nested_app`] write or compare.
    fn nested_props(mode: &str, label: &str) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
        let app = nested_app()?;
        let memo = DynamicMemo::new(&app);
        let overrides = BTreeMap::from([
            ("P-18_R-8".to_string(), mode.to_string()),
            ("P-20_R-9".to_string(), label.to_string()),
        ]);
        Ok(guarded_ops(&app, &memo.evaluate_for(&app, &overrides))?
            .iter()
            .filter_map(|op| match op {
                LoadOp::WriteProp { prop_id, .. } | LoadOp::CompareProp { prop_id, .. } => *prop_id,
                _ => None,
            })
            .collect())
    }

    #[test]
    fn test_guarded_ops_decides_a_nested_choose_by_the_inner_parameter() -> TestResult {
        // Outer branch taken: the inner choose picks by P-20, the ops around
        // it run in document order.
        assert_eq!(nested_props("3", "0")?, vec![59, 60, 63]);
        assert_eq!(nested_props("4", "1")?, vec![59, 61, 63]);
        // No inner test matches: the inner default branch.
        assert_eq!(nested_props("3", "7")?, vec![59, 62, 63]);
        // A self-closed `<when>` matches and holds nothing, so the default
        // branch is not taken.
        assert_eq!(nested_props("3", "2")?, vec![59, 63]);
        Ok(())
    }

    #[test]
    fn test_guarded_ops_skips_a_nested_choose_behind_a_branch_not_taken() -> TestResult {
        assert_eq!(nested_props("1", "1")?, vec![19]);
        // The inner choose is never decided, so its undecidable value does
        // not refuse.
        assert_eq!(nested_props("1", "x")?, vec![19]);
        // Behind the taken branch it does.
        let app = nested_app()?;
        let memo = DynamicMemo::new(&app);
        let overrides = BTreeMap::from([
            ("P-18_R-8".to_string(), "3".to_string()),
            ("P-20_R-9".to_string(), "x".to_string()),
        ]);
        assert!(matches!(
            guarded_ops(&app, &memo.evaluate_for(&app, &overrides)),
            Err(PlanError::UndecidableCondition { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_parse_records_nested_load_guards_outermost_first() -> TestResult {
        let app = nested_app()?;
        let lp = app.load_procedures.first().ok_or("one procedure")?;
        assert_eq!(lp.chooses.len(), 2);
        // The self-closed `<when test="2"/>` keeps its place among the tests.
        assert_eq!(lp.chooses[1].tests.len(), 4);
        let inner = lp.guards_of(3);
        assert_eq!(
            inner,
            [
                LoadGuard {
                    choose: 0,
                    branch: 0
                },
                LoadGuard {
                    choose: 1,
                    branch: 1
                }
            ]
        );
        Ok(())
    }

    /// Corpus conformance for load-procedure `<choose>` blocks (issue #402,
    /// env-gated on `BUSSARD_PRODUCT_CORPUS`): every program whose load
    /// procedure holds a `<choose>` decides it under the product defaults and
    /// plans without an undecidable-condition refusal. Prints one
    /// `LOAD-CHOOSE` line per program (mask, family, nesting depth, op count
    /// with every branch and with the taken ones) and marks with `changed`
    /// the System B programs, whose lowering concatenated every branch
    /// before #402.
    #[test]
    fn test_guarded_ops_decides_every_load_procedure_choose_on_the_corpus() -> TestResult {
        let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
            return Ok(());
        };
        let dir = std::path::PathBuf::from(dir);
        let dir = [dir.join("cache/vendor"), dir.join("vendor")]
            .into_iter()
            .find(|d| d.is_dir())
            .unwrap_or(dir);
        let mut seen = std::collections::BTreeSet::new();
        let mut failures = Vec::new();
        let (mut with_choose, mut nested, mut changed) = (0, 0, 0);
        for path in crate::corpus::knxprod_files(&dir) {
            let Ok(product) = bussard_product::read_knxprod(&path) else {
                continue;
            };
            for app in &product.applications {
                if !seen.insert(app.id.clone())
                    || app.load_procedures.iter().all(|p| p.chooses.is_empty())
                {
                    continue;
                }
                with_choose += 1;
                let depth = app
                    .load_procedures
                    .iter()
                    .flat_map(|p| (0..p.ops.len()).map(move |i| p.guards_of(i).len()))
                    .max()
                    .unwrap_or(0);
                if depth > 1 {
                    nested += 1;
                }
                let mask = app.mask_version.as_deref().unwrap_or("");
                let device_mask = u16::from_str_radix(mask.trim(), 16).unwrap_or(0);
                let profile = bussard_mgmt::MaskProfile::from_mask(device_mask);
                let every_branch = super::super::plan::self_contained_blocks(app)
                    .iter()
                    .map(|p| p.ops.len())
                    .sum::<usize>();
                let memo = DynamicMemo::new(app);
                let taken = match guarded_ops(app, &memo.evaluate_for(app, &BTreeMap::new())) {
                    Ok(ops) => ops.len(),
                    Err(e) => {
                        failures.push(format!("{}: {e}", app.id));
                        continue;
                    }
                };
                let plan = plan_flash_default(
                    app,
                    "1.1.1",
                    device_mask,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    None,
                    &BTreeMap::new(),
                );
                let plan = match plan {
                    Ok(plan) => format!("plan {} steps", plan.steps.len()),
                    Err(e @ PlanError::UndecidableCondition { .. }) => {
                        failures.push(format!("{}: {e}", app.id));
                        continue;
                    }
                    Err(e) => format!("refused {}", e.to_string().split(':').next().unwrap_or("")),
                };
                let system_b = profile.capabilities().flash && !profile.is_system_7();
                let differs = taken != every_branch;
                if system_b && differs {
                    changed += 1;
                }
                println!(
                    "LOAD-CHOOSE|{}|{mask}|{}|depth {depth}|ops {every_branch}->{taken}|{plan}|{}",
                    app.id,
                    bussard_mgmt::system_type(device_mask),
                    if system_b && differs {
                        "changed"
                    } else {
                        "unchanged"
                    },
                );
            }
        }
        println!(
            "LOAD-CHOOSE-SUMMARY|programs {with_choose}|nested {nested}|System B changed {changed}"
        );
        assert!(failures.is_empty(), "undecidable: {failures:#?}");
        Ok(())
    }
}
