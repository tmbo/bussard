//! Declared properties in a System B load procedure (issue #938).
//!
//! `LdCtrlDeclarePropDesc` describes an interface-object property on the tool
//! side: its datatype, how many elements it holds, and whether it may be
//! written. The tool needs the description before it writes a property (KNX
//! Cookbook 2/3/1 §1.1, Example 3); a declaration supplies it so the tool does
//! not read it from the device. The KNX Standard defines no such load control.
//!
//! What ETS does with one, from the sweep captures of 2026-11-07 of five Hager
//! 07B0 actuators (`M-0009_A-E807-10-0EAB` and four siblings, under
//! `captures/ets-sweep/<application>/plain-defaults/ops.txt`):
//!
//! - nothing on the wire for the declaration: no `A_PropertyDescription_Read`
//!   of a declared property;
//! - the `LdCtrlWriteProp` that follows writes `Count` elements of the
//!   declared type with plain `A_PropertyValue_Write`, at most 15 elements per
//!   request (`count=15 index=1`, `15@16`, ..., `8@61` for obj10 PID 55);
//! - the value is the one the program's property-located parameters compose,
//!   not the op's `InlineData`: the Hager writes carry a 10-octet all-zero
//!   `InlineData` placeholder, and ETS writes 1 to 328 octets of parameter
//!   values instead;
//! - a write without `Count` to a property declared with `MaxElements="1"`
//!   writes that one element (`count=1 index=1 len=1` for obj10 PID 52 of
//!   `M-0009_A-E804-10-98AD`, and for obj6 PID 52 of
//!   `M-0006_A-E01C-01-DC47-O0009` over a 10-octet `InlineData`). Neither the
//!   KNX Standard nor a schema in the repository gives `Count` a default, so
//!   a count-less write that could mean more than one element is refused
//!   (issue #945).
//!
//! From the sweep captures of three Gira 07B0 programs (issue #948):
//!
//! - a declaration and its writes may name the object by type: ETS writes
//!   `type60001.1/PID51` to `PID56` and `type11.1/PID201` with
//!   `A_PropertyExtValue_WriteCon` (`M-0008_A-0004-75-0A9A-O007C`, ops 46 to
//!   53), `type40960.1/PID69` and on (`M-0008_A-C02A-21-B6D8-O007C`, ops 65
//!   and on);
//! - `MaxElements` does not bound the write: `M-0008_A-C02A-21-B6D8-O007C`
//!   declares PID 69 with `MaxElements="1"` and ETS writes the 25 elements of
//!   `Count="25"` (`count=14 index=1`, `count=11 index=15`, ops 65 to 66);
//! - nor does `Writable="false"`: ETS writes the 4-octet `type11.1/PID201`
//!   and `PID202` of `M-0008_A-0004-75-0A9A-O007C` declared so (ops 52, 53);
//! - a write with neither `InlineData` nor a parameter placed in the
//!   property sends nothing, not even a description read
//!   (`M-0008_A-F060-10-5848`, the declared object 4 PID 201: no frame for it).

use super::plan_props::{check_addressable, may_hold, prop_object};
use super::{FlashStep, PlanError, PropObject};
use bussard_product::application::{ApplicationProgram, LoadOp};
use bussard_product::{PropertyObjectRef, PropertyParameters};

/// The highest element index the plain property services address (a 12-bit
/// start index).
const MAX_ELEMENT_INDEX: u32 = 0x0FFF;

/// The octets one element of the property datatype `name` takes, `None` for
/// a datatype without a fixed element size. KNX 3/7/3 §4.1, Table 6.
/// `PDT_BINARY_INFORMATION` (32h) is one bit held in the least significant
/// position of an octet, its alternative type `PDT_UNSIGNED_CHAR` (§4.2).
pub(super) fn pdt_element_size(name: &str) -> Option<usize> {
    let size = match name {
        "PDT_CHAR"
        | "PDT_UNSIGNED_CHAR"
        | "PDT_BITSET8"
        | "PDT_ENUM8"
        | "PDT_SCALING"
        | "PDT_BINARY_INFORMATION" => 1,
        "PDT_INT" | "PDT_UNSIGNED_INT" | "PDT_KNX_FLOAT" | "PDT_BITSET16" | "PDT_VERSION" => 2,
        "PDT_DATE" | "PDT_TIME" | "PDT_POLL_GROUP_SETTINGS" => 3,
        "PDT_LONG" | "PDT_UNSIGNED_LONG" | "PDT_FLOAT" => 4,
        "PDT_SHORT_CHAR_BLOCK" => 5,
        "PDT_ALARM_INFO" => 6,
        "PDT_DOUBLE" | "PDT_DATE_TIME" | "PDT_REFERENCE" => 8,
        "PDT_CHAR_BLOCK" => 10,
        other => {
            let n: usize = other.strip_prefix("PDT_GENERIC_")?.parse().ok()?;
            return (1..=20).contains(&n).then_some(n);
        }
    };
    Some(size)
}

/// A property an `LdCtrlDeclarePropDesc` declared, in force for the writes
/// to that property that follow it in the procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PropDecl {
    /// The interface object the declaration names.
    pub(super) object: PropObject,
    /// The property id.
    pub(super) prop_id: u32,
    /// The declared datatype (`PropType`).
    pub(super) prop_type: String,
    /// Octets per element of `prop_type`.
    pub(super) element_size: usize,
    /// `MaxElements`: the size the declaration describes, which does not
    /// bound the write (see the module docs). `Writable` is not kept: ETS
    /// writes a property declared not writable all the same.
    pub(super) max_elements: u32,
}

impl PropDecl {
    /// The plan step that keeps the declaration visible; it sends nothing.
    pub(super) fn step(&self) -> FlashStep {
        FlashStep::DeclareProp {
            object: self.object,
            prop_id: self.prop_id,
            prop_type: self.prop_type.clone(),
            max_elements: self.max_elements,
        }
    }
}

/// The declaration `op` (an `LdCtrlDeclarePropDesc`) makes.
///
/// # Errors
///
/// [`PlanError::UnsupportedOp`] for a declaration without a `PropId`, a
/// `PropType` with a fixed element size, or a `MaxElements`; the size of the
/// write that follows is not guessed.
pub(super) fn lower_declare_prop(step: usize, op: &LoadOp) -> Result<PropDecl, PlanError> {
    let refuse = |what: &str| PlanError::UnsupportedOp {
        op: format!("LdCtrlDeclarePropDesc {what} (step {step})"),
    };
    let LoadOp::DeclarePropDesc {
        obj_idx,
        obj_type,
        occurrence,
        prop_id,
        prop_type,
        max_elements,
        ..
    } = op
    else {
        return Err(refuse("expected"));
    };
    let prop_id = prop_id.ok_or_else(|| refuse("without a PropId"))?;
    let prop_type = prop_type
        .clone()
        .ok_or_else(|| refuse("without a PropType"))?;
    let element_size = pdt_element_size(&prop_type).ok_or_else(|| {
        refuse(&format!(
            "with PropType {prop_type}, which has no fixed element size"
        ))
    })?;
    let max_elements = max_elements
        .filter(|m| *m >= 1)
        .ok_or_else(|| refuse("without a MaxElements of at least 1"))?;
    let object = prop_object(step, *obj_idx, *obj_type, *occurrence)?;
    Ok(PropDecl {
        object,
        prop_id,
        prop_type,
        element_size,
        max_elements,
    })
}

/// The declaration in `declared` the write `op` targets, the latest first.
pub(super) fn declaration_for<'a>(
    declared: &'a [PropDecl],
    step: usize,
    op: &LoadOp,
) -> Option<&'a PropDecl> {
    let LoadOp::WriteProp {
        obj_idx,
        obj_type,
        occurrence,
        prop_id: Some(prop_id),
        ..
    } = op
    else {
        return None;
    };
    let object = prop_object(step, *obj_idx, *obj_type, *occurrence).ok()?;
    declared
        .iter()
        .rev()
        .find(|d| d.object == object && d.prop_id == *prop_id)
}

/// How many elements an `LdCtrlWriteProp` to an undeclared property writes:
/// its `Count`, else one ([`element_count`] with no declaration, which cannot
/// refuse).
pub(super) fn undeclared_element_count(count: Option<u32>) -> u32 {
    count.map_or(1, |count| count.max(1))
}

/// How many elements an `LdCtrlWriteProp` writes from `start`: its `Count`,
/// or, without one, one element where the evidence says so. The one rule both
/// System B planners use (issue #957).
///
/// - A write to an undeclared property (`declared_max` `None`) without
///   `Count` writes one element: ETS wrote `count=1 index=16 len=1` for the
///   count-less `ObjIdx="12" PropId="208" StartElement="16"` of
///   `M-0009_A-E0EE-10-ADF8` although the device described 48 elements, and
///   `count=1 len=1` for the count-less `ObjType="50215" PropId="205"` of
///   `M-0001_A-9839-01-38C4` (ETS sweep, `plain-defaults`, 2026-11-05).
/// - A write to a declared property without `Count` writes one element only
///   where the declaration leaves room for no more (`MaxElements` equal to
///   `StartElement`): obj10 PID 52 of `M-0009_A-E804-10-98AD` and obj6 PID 52
///   of `M-0006_A-E01C-01-DC47-O0009` (see the module docs). Any other
///   count-less declared write is refused.
///
/// # Errors
///
/// The refusal reason, naming `name`, for a count-less declared write that
/// could mean more than one element or starts past `MaxElements`.
pub(super) fn element_count(
    name: &str,
    count: Option<u32>,
    start: u32,
    declared_max: Option<u32>,
) -> Result<u32, String> {
    match (count, declared_max) {
        (_, None) => Ok(undeclared_element_count(count)),
        (Some(count), Some(_)) => Ok(count.max(1)),
        (None, Some(max)) if max == start => Ok(1),
        (None, Some(max)) if start > max => Err(format!(
            "the LdCtrlWriteProp to the declared {name} has no Count and starts at element \
             {start}, past the declared MaxElements of {max}"
        )),
        (None, Some(max)) => Err(format!(
            "the LdCtrlWriteProp to the declared {name} has no Count, and the declaration \
             (MaxElements {max}, StartElement {start}) leaves room for more than one element; \
             neither the KNX Standard nor the schema says how many it writes, so bussard does \
             not guess"
        )),
    }
}

/// The `len` octets of an `LdCtrlWriteProp`'s `InlineData` the write sends,
/// elements of `elem` octets (issue #957).
///
/// ETS cuts the Hager 10-octet all-zero placeholder to the `Count` elements it
/// writes (`count=1 index=1 len=1`), so a tail past `Count` elements is
/// dropped only when it is all zero. A shorter `InlineData` is padded with
/// zeros when it is all zero, or when parameters are placed in the property
/// (`placed`) and it holds whole elements: ETS lays the parameters over the
/// placeholder. A non-zero value is never cut, never ends in part of an
/// element, and is never extended on a property no parameter decides.
///
/// # Errors
///
/// The refusal reason, naming `name`, for a non-zero tail past `Count`
/// elements, a non-zero `InlineData` that ends in part of an element, or a
/// non-zero one shorter than `Count` elements on a property no parameter is
/// placed in.
fn inline_template(
    name: &str,
    inline: &[u8],
    len: usize,
    elem: usize,
    placed: bool,
) -> Result<Vec<u8>, String> {
    if inline.len() >= len {
        if inline[len..].iter().any(|b| *b != 0) {
            return Err(format!(
                "the {}-octet InlineData of the write to {name} runs past its {len} octets \
                 (Count elements of the declared type) with non-zero octets; bussard does not \
                 drop them",
                inline.len()
            ));
        }
        return Ok(inline[..len].to_vec());
    }
    let zero = inline.iter().all(|b| *b == 0);
    if !zero && !inline.len().is_multiple_of(elem) {
        return Err(format!(
            "the {}-octet InlineData of the write to {name} ends in part of a {elem}-octet \
             element",
            inline.len()
        ));
    }
    if !zero && !placed {
        return Err(format!(
            "the {}-octet InlineData of the write to {name} is shorter than its {len} octets \
             (Count elements of the declared type) and no parameter is placed in the property; \
             bussard does not make up the missing elements",
            inline.len()
        ));
    }
    let mut out = inline.to_vec();
    out.resize(len, 0);
    Ok(out)
}

/// Whether the parameter location `loc` names `object` for certain, the
/// equivalence [`may_hold`] encodes: the same index, the same type and
/// occurrence, or the device object by type (`ObjectType="0"`) for object 0,
/// always interface object 0 (KNX 3/5/1). An index against any other type is
/// a name that may or may not be `object`, which bussard does not resolve.
fn same_object(loc: &bussard_product::application::PropertyLocation, object: PropObject) -> bool {
    match (PropertyObjectRef::of(loc), object) {
        (Some(PropertyObjectRef::Index(at)), PropObject::Index(index)) => at == index,
        (
            Some(PropertyObjectRef::Type {
                object_type: 0,
                occurrence: 0,
            }),
            PropObject::Index(0),
        ) => true,
        (
            Some(PropertyObjectRef::Type {
                object_type,
                occurrence,
            }),
            PropObject::Type {
                object_type: t,
                occurrence: o,
            },
        ) => object_type == u32::from(t) && occurrence == u32::from(o),
        _ => false,
    }
}

/// The parameters of `app` that decide `object`/`prop_id`: the names they
/// give the object ([`same_object`]), and whether another parameter
/// [`may_hold`] the property under a name bussard does not resolve.
fn placements(
    app: &ApplicationProgram,
    object: PropObject,
    prop_id: u32,
) -> (Vec<PropertyObjectRef>, bool) {
    let mut names: Vec<PropertyObjectRef> = Vec::new();
    let mut unresolved = false;
    for loc in app.parameters.values().filter_map(|p| p.property.as_ref()) {
        if !may_hold(loc, object, prop_id) {
            continue;
        }
        match PropertyObjectRef::of(loc) {
            Some(name) if same_object(loc, object) => {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            _ => unresolved = true,
        }
    }
    (names, unresolved)
}

/// The value the parameters placed in `prop_id` under `names` compose over
/// `template`, the octets the write sends from octet `from` of the property
/// (element `StartElement`): the base vector from element 1 (zeros before
/// `from`, then the template), each name's parameters laid over it, and the
/// slice of the write's extent, `template.len()` octets. The one composition
/// of a declared write on System B and System 7 (issue #946), and of a PID 13
/// placeholder a parameter supplies (issue #964).
///
/// # Errors
///
/// The reason, naming `name`, when a parameter's value cannot be composed.
pub(super) fn compose_over(
    name: &str,
    names: &[PropertyObjectRef],
    prop_id: u32,
    params: &PropertyParameters<'_>,
    template: &[u8],
    from: usize,
) -> Result<Vec<u8>, String> {
    let len = template.len();
    let mut composed = vec![0u8; from];
    composed.extend_from_slice(template);
    for n in names {
        if let Some(next) = params
            .compose(*n, prop_id, composed.clone())
            .map_err(|e| format!("composing the value of {name} from the parameters: {e}"))?
        {
            composed = next;
        }
    }
    let mut value: Vec<u8> = composed.into_iter().skip(from).take(len).collect();
    value.resize(len, 0);
    Ok(value)
}

/// The value the parameters placed in `object`/`prop_id` compose over
/// `template` from element 1 ([`compose_over`]), `None` when no parameter is
/// placed in the property under a name of `object`.
///
/// # Errors
///
/// The reason, naming `name`, when a parameter may be stored in the property
/// under a name bussard does not resolve to `object` (see
/// [`lower_declared_write_prop`]), or its value cannot be composed.
pub(super) fn placed_value(
    name: &str,
    object: PropObject,
    prop_id: u32,
    params: &PropertyParameters<'_>,
    app: &ApplicationProgram,
    template: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let (names, unresolved) = placements(app, object, prop_id);
    if unresolved {
        return Err(unresolved_reason(name));
    }
    if !names.iter().any(|n| params.places(*n, prop_id)) {
        return Ok(None);
    }
    compose_over(name, &names, prop_id, params, template, 0).map(Some)
}

/// Whether a parameter is placed in `object`/`prop_id` under a name of
/// `object`: what the PID 13 placeholder rule asks before it refuses a
/// placeholder without an application id (issue #964).
///
/// # Errors
///
/// The reason, naming `name`, when a parameter may be stored in the property
/// under a name bussard does not resolve to `object`.
pub(super) fn is_placed(
    name: &str,
    object: PropObject,
    prop_id: u32,
    params: &PropertyParameters<'_>,
    app: &ApplicationProgram,
) -> Result<bool, String> {
    let (names, unresolved) = placements(app, object, prop_id);
    if unresolved {
        return Err(unresolved_reason(name));
    }
    Ok(names.iter().any(|n| params.places(*n, prop_id)))
}

/// Why a write is refused when a parameter may be stored in its property
/// under another name of the object.
fn unresolved_reason(name: &str) -> String {
    format!(
        "a parameter is placed in a property that may be {name}, but it names the object by \
         type where the load procedure names it by index (or the other way round, or names \
         no object); bussard does not resolve one to the other, so it does not know the \
         value to write"
    )
}

/// Lowers an `LdCtrlWriteProp` to a property `decl` declared: `Count` elements
/// of the declared size from `StartElement` ([`element_count`]), whether or
/// not a parameter is placed in the property. `inline` is the op's
/// `InlineData` after the planner's application-id substitution (the one rule
/// for a PID 13 placeholder, issue #945); it is the template
/// ([`inline_template`]) the parameters placed in the property (`params`)
/// replace the bits of. The object may be named by index or by type, and
/// neither `MaxElements` nor `Writable` bounds the write (issue #948, see the
/// module docs). `typed_by_list` is the plan's
/// [`super::FlashPlan::typed_objects_by_list`], which holds the PID of an
/// object named by type to 8 bits ([`check_addressable`]). `None` for a
/// write with neither `InlineData` nor a parameter placed in the property:
/// ETS sends nothing for it.
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] when the write has no `Count` and
/// could mean more than one element, reaches past the 12-bit element index,
/// names an object or PID the property services cannot address, carries an
/// `InlineData` that does not fit `Count` elements, a parameter may be stored
/// in the property under another name of its object (an index against a
/// type, refused even when another parameter is placed under the write's own
/// name: leaving it out would be a partial write, issue #964), or its value
/// cannot be composed.
pub(super) fn lower_declared_write_prop(
    step: usize,
    op: &LoadOp,
    decl: &PropDecl,
    inline: Option<&[u8]>,
    params: &PropertyParameters<'_>,
    app: &ApplicationProgram,
    typed_by_list: bool,
) -> Result<Option<FlashStep>, PlanError> {
    let refuse = |reason: String| PlanError::UnsupportedWriteProp { step, reason };
    let LoadOp::WriteProp {
        prop_id,
        start_element,
        count,
        verify,
        ..
    } = op
    else {
        return Err(refuse("not an LdCtrlWriteProp".to_string()));
    };
    let prop_id = prop_id.unwrap_or(decl.prop_id);
    let name = format!("{} PID {prop_id}", decl.object);
    check_addressable(step, decl.object, prop_id, typed_by_list)?;
    let elem = decl.element_size;
    let inline = inline.filter(|d| !d.is_empty());
    let start = start_element.unwrap_or(1).max(1);
    let count = element_count(&name, *count, start, Some(decl.max_elements)).map_err(refuse)?;
    let last = start.saturating_add(count).saturating_sub(1);
    if last > MAX_ELEMENT_INDEX {
        return Err(refuse(format!(
            "the write to {name} reaches element {last}, past the 12-bit element index"
        )));
    }
    // Bounded by the extent check: at most 4095 elements of 20 octets.
    let from = ((start - 1) as usize).saturating_mul(elem);
    let len = (count as usize).saturating_mul(elem);
    let (names, unresolved) = placements(app, decl.object, prop_id);
    // Any placement under a name bussard does not resolve is refused, also
    // beside one it does: composing only the resolved ones would leave the
    // other parameter's bits out of the value (issue #964).
    if unresolved {
        return Err(refuse(unresolved_reason(&name)));
    }
    let placed = names.iter().any(|n| params.places(*n, prop_id));
    let template =
        inline_template(&name, inline.unwrap_or_default(), len, elem, placed).map_err(refuse)?;
    let (value, from_parameters) = if placed {
        let value =
            compose_over(&name, &names, prop_id, params, &template, from).map_err(refuse)?;
        (value, true)
    } else if inline.is_some() {
        (template, false)
    } else {
        // Nothing decides the value: ETS sends nothing (issue #948).
        return Ok(None);
    };
    Ok(Some(FlashStep::WriteProp {
        object: decl.object,
        prop_id,
        value,
        // Both fit the 12-bit element index checked above.
        start_element: start as u16,
        count: count as u16,
        verify: verify.unwrap_or(false),
        from_parameters,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn declare(prop_type: &str, max_elements: u32) -> LoadOp {
        LoadOp::DeclarePropDesc {
            obj_idx: Some(10),
            obj_type: None,
            occurrence: None,
            prop_id: Some(55),
            prop_type: Some(prop_type.to_string()),
            max_elements: Some(max_elements),
            writable: Some(true),
            read_access: Some(0),
            write_access: Some(0),
        }
    }

    fn write(inline: Option<Vec<u8>>, count: Option<u32>) -> LoadOp {
        LoadOp::WriteProp {
            obj_idx: Some(10),
            obj_type: None,
            prop_id: Some(55),
            inline_data: inline,
            start_element: None,
            count,
            verify: Some(false),
            occurrence: None,
        }
    }

    /// An application whose parameters are the `<Property …/>` elements
    /// `locations`, each an 8-bit parameter with the paired value.
    fn app_placing(
        locations: &[(&str, u8)],
    ) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let params: String = locations
            .iter()
            .enumerate()
            .map(|(i, (loc, value))| {
                format!(
                    r#"<Parameter Id="M-1_A-1_P-{i}" Name="p{i}" ParameterType="M-1_A-1_PT-u8" Value="{value}">{loc}</Parameter>"#
                )
            })
            .collect();
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-1_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="D">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-1_A-1_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
           </ParameterTypes>
           <Parameters>{params}</Parameters>
          </Static>
         </ApplicationProgram></KNX>"#
        );
        Ok(bussard_product::application::parse_application_program(
            "M-1_A-1",
            xml.as_bytes(),
        )?)
    }

    /// An application with parameters placed in object 10 PID 55 at
    /// `(offset, value)`.
    fn app_with(placed: &[(usize, u8)]) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let locations: Vec<(String, u8)> = placed
            .iter()
            .map(|(at, v)| {
                (
                    format!(r#"<Property ObjectIndex="10" PropertyId="55" Offset="{at}" BitOffset="0" />"#),
                    *v,
                )
            })
            .collect();
        let refs: Vec<(&str, u8)> = locations.iter().map(|(l, v)| (l.as_str(), *v)).collect();
        app_placing(&refs)
    }

    /// An application with no property-located parameter.
    fn app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        app_with(&[])
    }

    /// Lowers `op` against `decl` with the planner's own values for `app`.
    fn lower_opt(
        op: &LoadOp,
        decl: &PropDecl,
        app: &ApplicationProgram,
    ) -> Result<Option<FlashStep>, PlanError> {
        let config = bussard_product::dynamic::DynamicMemo::new(app)
            .evaluate_for(app, &std::collections::BTreeMap::new());
        let params = PropertyParameters::resolve(app, &config);
        let inline = match op {
            LoadOp::WriteProp { inline_data, .. } => inline_data.clone(),
            _ => None,
        };
        lower_declared_write_prop(2, op, decl, inline.as_deref(), &params, app, false)
    }

    /// [`lower_opt`] for a write that sends something.
    fn lower(
        op: &LoadOp,
        decl: &PropDecl,
        app: &ApplicationProgram,
    ) -> Result<FlashStep, PlanError> {
        lower_opt(op, decl, app)?.ok_or_else(|| PlanError::UnsupportedOp {
            op: "the write lowered to nothing".to_string(),
        })
    }

    fn refusal(result: Result<FlashStep, PlanError>) -> Result<String, Box<dyn std::error::Error>> {
        match result {
            Err(PlanError::UnsupportedWriteProp { step: 2, reason }) => Ok(reason),
            other => Err(format!("expected a refusal, got {other:?}").into()),
        }
    }

    #[test]
    fn test_pdt_element_size_follows_table_6() {
        assert_eq!(pdt_element_size("PDT_UNSIGNED_CHAR"), Some(1));
        assert_eq!(pdt_element_size("PDT_BINARY_INFORMATION"), Some(1));
        assert_eq!(pdt_element_size("PDT_UNSIGNED_INT"), Some(2));
        assert_eq!(pdt_element_size("PDT_GENERIC_04"), Some(4));
        assert_eq!(pdt_element_size("PDT_GENERIC_20"), Some(20));
        assert_eq!(pdt_element_size("PDT_GENERIC_21"), None);
        assert_eq!(pdt_element_size("PDT_VARIABLE_LENGTH"), None);
        assert_eq!(pdt_element_size("PDT_UTF-8"), None);
    }

    #[test]
    fn test_lower_declare_prop_reads_the_declaration() -> TestResult {
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 328))?;
        assert_eq!(decl.object, PropObject::Index(10));
        assert_eq!(
            (decl.prop_id, decl.element_size, decl.max_elements),
            (55, 1, 328)
        );
        assert!(matches!(
            decl.step(),
            FlashStep::DeclareProp {
                max_elements: 328,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn test_lower_declare_prop_refuses_a_variable_type() {
        assert!(matches!(
            lower_declare_prop(1, &declare("PDT_VARIABLE_LENGTH", 4)),
            Err(PlanError::UnsupportedOp { .. })
        ));
    }

    #[test]
    fn test_lower_declared_write_prop_writes_count_elements_over_the_placeholder() -> TestResult {
        // The Hager shape: a 10-octet zero placeholder, Count 20, the
        // parameters covering octets 0 and 19.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 20))?;
        let step = lower(
            &write(Some(vec![0; 10]), Some(20)),
            &decl,
            &app_with(&[(0, 7), (19, 9)])?,
        )?;
        let mut expected = vec![0u8; 20];
        expected[0] = 7;
        expected[19] = 9;
        assert_eq!(
            step,
            FlashStep::WriteProp {
                object: PropObject::Index(10),
                prop_id: 55,
                value: expected,
                start_element: 1,
                count: 20,
                verify: false,
                from_parameters: true,
            }
        );
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_cuts_the_placeholder_to_count() -> TestResult {
        // Count absent on a one-element declaration: ETS writes one octet,
        // not the 10-octet placeholder (obj10 PID 52 of E804).
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 1))?;
        let step = lower(
            &write(Some(vec![0; 10]), None),
            &decl,
            &app_with(&[(0, 7)])?,
        )?;
        assert!(matches!(step, FlashStep::WriteProp { ref value, count: 1, .. } if value == &[7]));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_keeps_the_inline_data_the_parameters_leave() -> TestResult {
        // `StartElement="3" Count="3"` with InlineData `AA BB CC`: a parameter
        // at octet 3 (element 4) replaces BB, the rest is the InlineData, as
        // ETS writes object 16 PID 208 of `M-0009_A-E802-13-7620`.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 8))?;
        let mut op = write(Some(vec![0xAA, 0xBB, 0xCC]), Some(3));
        if let LoadOp::WriteProp { start_element, .. } = &mut op {
            *start_element = Some(3);
        }
        let step = lower(&op, &decl, &app_with(&[(3, 0x11), (7, 0x22)])?)?;
        assert!(matches!(
            step,
            FlashStep::WriteProp { ref value, start_element: 3, count: 3, .. }
                if value == &[0xAA, 0x11, 0xCC]
        ));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_uses_the_declared_element_size() -> TestResult {
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_INT", 4))?;
        let step = lower(
            &write(Some(vec![1, 2, 3, 4, 5, 6]), Some(3)),
            &decl,
            &app()?,
        )?;
        assert!(matches!(
            step,
            FlashStep::WriteProp {
                count: 3,
                from_parameters: false,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_refuses_a_partial_element() -> TestResult {
        // Issue #957: 3 octets for two 2-octet elements end in half an
        // element; bussard neither pads nor guesses it.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_INT", 4))?;
        let reason = refusal(lower(&write(Some(vec![1, 2, 3]), Some(2)), &decl, &app()?))?;
        assert!(reason.contains("part of a 2-octet element"), "{reason}");
        // With a parameter placed in the property, too.
        let reason = refusal(lower(
            &write(Some(vec![1, 2, 3]), Some(2)),
            &decl,
            &app_with(&[(0, 7)])?,
        ))?;
        assert!(reason.contains("part of a 2-octet element"), "{reason}");
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_refuses_a_non_zero_tail_past_count() -> TestResult {
        // Issue #957: the all-zero tail is cut (the Hager placeholder), a
        // non-zero one is not dropped.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 4))?;
        let reason = refusal(lower(&write(Some(vec![1, 2, 3]), Some(2)), &decl, &app()?))?;
        assert!(reason.contains("non-zero octets"), "{reason}");
        let step = lower(&write(Some(vec![1, 2, 0, 0]), Some(2)), &decl, &app()?)?;
        assert!(matches!(step, FlashStep::WriteProp { ref value, .. } if value == &[1, 2]));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_refuses_to_extend_an_unplaced_value() -> TestResult {
        // Issue #957: one element of InlineData for Count 2 with no parameter
        // placed in the property; a zero placeholder is padded.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 4))?;
        let reason = refusal(lower(&write(Some(vec![5]), Some(2)), &decl, &app()?))?;
        assert!(reason.contains("shorter than"), "{reason}");
        let step = lower(&write(Some(vec![0]), Some(2)), &decl, &app()?)?;
        assert!(matches!(step, FlashStep::WriteProp { ref value, .. } if value == &[0, 0]));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_writes_past_max_elements() -> TestResult {
        // Issue #948: ETS writes the 25 elements of `Count="25"` to PID 69
        // declared `MaxElements="1"` (`M-0008_A-C02A-21-B6D8-O007C`); only the
        // 12-bit element index bounds the write.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 2))?;
        let step = lower(&write(Some(vec![1, 2, 3]), Some(3)), &decl, &app()?)?;
        assert!(
            matches!(step, FlashStep::WriteProp { count: 3, ref value, .. } if value == &[1, 2, 3])
        );
        let mut op = write(None, Some(3));
        if let LoadOp::WriteProp { start_element, .. } = &mut op {
            *start_element = Some(4094);
        }
        let reason = refusal(lower(&op, &decl, &app_with(&[(0, 1)])?))?;
        assert!(reason.contains("12-bit element index"), "{reason}");
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_writes_an_object_named_by_type() -> TestResult {
        // Issue #948: the Gira declarations name the object by type, and ETS
        // writes `type60001.1/PID51` (`M-0008_A-0004-75-0A9A-O007C`).
        let mut decl_op = declare("PDT_UNSIGNED_CHAR", 1);
        if let LoadOp::DeclarePropDesc {
            obj_idx, obj_type, ..
        } = &mut decl_op
        {
            *obj_idx = None;
            *obj_type = Some(60001);
        }
        let decl = lower_declare_prop(1, &decl_op)?;
        let app = app_placing(&[(
            r#"<Property ObjectType="60001" PropertyId="55" Offset="0" BitOffset="0" />"#,
            3,
        )])?;
        let mut op = write(None, None);
        if let LoadOp::WriteProp {
            obj_idx, obj_type, ..
        } = &mut op
        {
            *obj_idx = None;
            *obj_type = Some(60001);
        }
        let step = lower(&op, &decl, &app)?;
        assert_eq!(
            step,
            FlashStep::WriteProp {
                object: PropObject::Type {
                    object_type: 60001,
                    occurrence: 0,
                },
                prop_id: 55,
                value: vec![3],
                start_element: 1,
                count: 1,
                verify: false,
                from_parameters: true,
            }
        );
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_writes_a_property_declared_not_writable() -> TestResult {
        // Issue #948: ETS writes `type11.1/PID201` and `PID202`, declared
        // `Writable="false"` (`M-0008_A-0004-75-0A9A-O007C`, ops 52 and 53).
        let mut decl_op = declare("PDT_UNSIGNED_CHAR", 1);
        if let LoadOp::DeclarePropDesc { writable, .. } = &mut decl_op {
            *writable = Some(false);
        }
        let decl = lower_declare_prop(1, &decl_op)?;
        let step = lower(&write(None, Some(1)), &decl, &app_with(&[(0, 7)])?)?;
        assert!(matches!(step, FlashStep::WriteProp { ref value, .. } if value == &[7]));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_sends_nothing_without_a_value() -> TestResult {
        // Issue #948: no InlineData and no parameter placed in the declared
        // property: ETS sends nothing for it (`M-0008_A-F060-10-5848`,
        // object 4 PID 201).
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 1))?;
        assert_eq!(lower_opt(&write(None, None), &decl, &app()?)?, None);
        Ok(())
    }

    #[test]
    fn test_lower_declare_prop_accepts_binary_information() -> TestResult {
        // Issue #945: one octet per element, as PDT_UNSIGNED_CHAR.
        let decl = lower_declare_prop(1, &declare("PDT_BINARY_INFORMATION", 1))?;
        assert_eq!(decl.element_size, 1);
        let step = lower(&write(Some(vec![1]), Some(1)), &decl, &app()?)?;
        assert!(matches!(step, FlashStep::WriteProp { ref value, count: 1, .. } if value == &[1]));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_sizes_an_unplaced_placeholder_by_count() -> TestResult {
        // Issue #945: the Hager 10-octet zero placeholder with Count 1 on a
        // one-element declaration writes one zero element (`count=1 index=1
        // len=1`), where sizing by the InlineData refused it.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 1))?;
        for count in [Some(1), None] {
            let step = lower(&write(Some(vec![0; 10]), count), &decl, &app()?)?;
            assert_eq!(
                step,
                FlashStep::WriteProp {
                    object: PropObject::Index(10),
                    prop_id: 55,
                    value: vec![0],
                    start_element: 1,
                    count: 1,
                    verify: false,
                    from_parameters: false,
                }
            );
        }
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_refuses_a_count_less_write_of_several_elements() -> TestResult
    {
        // Issue #945: without Count and with room for more than one element,
        // neither branch guesses.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 10))?;
        for app in [app()?, app_with(&[(0, 7)])?] {
            let reason = refusal(lower(&write(Some(vec![0; 10]), None), &decl, &app))?;
            assert!(reason.contains("no Count"), "{reason}");
            assert!(reason.contains("object 10 PID 55"), "{reason}");
        }
        Ok(())
    }

    #[test]
    fn test_element_count_names_a_start_past_max_elements() {
        // Issue #957: a count-less write starting past MaxElements says so.
        let reason = element_count("object 10 PID 55", None, 3, Some(1)).err();
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("past the declared MaxElements of 1")),
            "{reason:?}"
        );
        assert_eq!(element_count("x", None, 1, Some(1)), Ok(1));
        assert_eq!(element_count("x", Some(4), 1, Some(1)), Ok(4));
        // An undeclared property: one element (E0EE obj12 PID 208, Siemens
        // 983901 PID 205).
        assert_eq!(element_count("x", None, 16, None), Ok(1));
    }

    #[test]
    fn test_lower_declared_write_prop_composes_from_the_resolved_parameters() -> TestResult {
        // The planner's own values: the parameter's 7 over the placeholder.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 4))?;
        let step = lower(
            &write(Some(vec![0; 10]), Some(4)),
            &decl,
            &app_with(&[(0, 7)])?,
        )?;
        assert!(matches!(
            step,
            FlashStep::WriteProp { ref value, from_parameters: true, .. } if value == &[7, 0, 0, 0]
        ));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_names_an_index_type_mismatch() -> TestResult {
        // Issue #945: a parameter placed by object type where the procedure
        // names an index is refused for that reason, not as a value that
        // "could not be found".
        let app = app_placing(&[(
            r#"<Property ObjectType="11" PropertyId="55" Offset="0" BitOffset="0" />"#,
            7,
        )])?;
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 1))?;
        let reason = refusal(lower(&write(Some(vec![0]), Some(1)), &decl, &app))?;
        assert!(reason.contains("by type"), "{reason}");
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_refuses_a_mixed_placement() -> TestResult {
        // Issue #964: one parameter placed by index, another by type on the
        // same PID; composing the first alone would leave the second's bits
        // out of the value (a partial write), so the write is refused.
        let app = app_placing(&[
            (
                r#"<Property ObjectIndex="10" PropertyId="55" Offset="0" BitOffset="0" />"#,
                7,
            ),
            (
                r#"<Property ObjectType="11" PropertyId="55" Offset="1" BitOffset="0" />"#,
                9,
            ),
        ])?;
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 2))?;
        let reason = refusal(lower(&write(Some(vec![0, 0]), Some(2)), &decl, &app))?;
        assert!(reason.contains("by type"), "{reason}");
        Ok(())
    }

    #[test]
    fn test_compose_over_lays_the_parameters_over_the_template_slice() -> TestResult {
        // Issue #946: the one composition both planners use; the base vector
        // runs from element 1, the slice is the write's extent.
        let app = app_with(&[(1, 0x11), (3, 0x22)])?;
        let config = bussard_product::dynamic::DynamicMemo::new(&app)
            .evaluate_for(&app, &std::collections::BTreeMap::new());
        let params = PropertyParameters::resolve(&app, &config);
        let names = [PropertyObjectRef::Index(10)];
        let value = compose_over("x", &names, 55, &params, &[0xAA, 0xBB, 0xCC], 2)?;
        assert_eq!(value, vec![0xAA, 0x22, 0xCC]);
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_takes_the_device_object_by_type() -> TestResult {
        // Issue #957: `<Property ObjectType="0">` is object 0 (KNX 3/5/1), the
        // equivalence `may_hold` encodes; a procedure that declares and writes
        // `ObjIdx="0"` composes it instead of refusing.
        let app = app_placing(&[(
            r#"<Property ObjectType="0" PropertyId="55" Offset="0" BitOffset="0" />"#,
            7,
        )])?;
        let mut decl_op = declare("PDT_UNSIGNED_CHAR", 1);
        if let LoadOp::DeclarePropDesc { obj_idx, .. } = &mut decl_op {
            *obj_idx = Some(0);
        }
        let decl = lower_declare_prop(1, &decl_op)?;
        let mut op = write(Some(vec![0]), Some(1));
        if let LoadOp::WriteProp { obj_idx, .. } = &mut op {
            *obj_idx = Some(0);
        }
        let step = lower(&op, &decl, &app)?;
        assert!(matches!(
            step,
            FlashStep::WriteProp { object: PropObject::Index(0), ref value, from_parameters: true, .. }
                if value == &[7]
        ));
        Ok(())
    }
}
