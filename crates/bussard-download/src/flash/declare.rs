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
//!   values instead.

use super::plan_props::{may_hold, prop_object};
use super::{FlashStep, PlanError, PropObject};
use bussard_prod::application::{ApplicationProgram, LoadOp};

/// The highest element index the plain property services address (a 12-bit
/// start index).
const MAX_ELEMENT_INDEX: u32 = 0x0FFF;

/// The octets one element of the property datatype `name` takes, `None` for
/// a datatype without a fixed element size. KNX 3/7/3 §4.1, Table 6.
pub(super) fn pdt_element_size(name: &str) -> Option<usize> {
    let size = match name {
        "PDT_CHAR" | "PDT_UNSIGNED_CHAR" | "PDT_BITSET8" | "PDT_ENUM8" | "PDT_SCALING" => 1,
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
    /// `MaxElements`.
    pub(super) max_elements: u32,
    /// `Writable`; absent counts as writable.
    pub(super) writable: bool,
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
        writable,
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
        writable: writable.unwrap_or(true),
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

/// Composes a declared property's value over a base: the octets of the
/// whole property from element 1, the op's `InlineData` placed at its
/// `StartElement`. Returns `None` when no parameter is placed in the property.
/// The System B planner passes [`bussard_prod::compose_property_value`] under
/// the evaluated configuration.
pub(super) type ComposeOver<'a> = dyn Fn(Vec<u8>) -> Result<Option<Vec<u8>>, PlanError> + 'a;

/// Lowers an `LdCtrlWriteProp` to a property `decl` declared: `Count` elements
/// of the declared size from `StartElement`. The op's `InlineData` is the
/// template; the parameters placed in the property replace the bits they
/// cover (`compose`), and the elements the op names are written. A property
/// no parameter is placed in writes its `InlineData` as it is, which must then
/// be whole elements and match `Count`.
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] when the property is declared not
/// writable, the value is not a whole number of declared elements, the write
/// reaches past `MaxElements` or the 12-bit element index, a parameter may be
/// stored in the property but its value cannot be composed, or there is no
/// value at all.
pub(super) fn lower_declared_write_prop(
    step: usize,
    op: &LoadOp,
    decl: &PropDecl,
    compose: &ComposeOver<'_>,
    app: &ApplicationProgram,
) -> Result<FlashStep, PlanError> {
    let refuse = |reason: String| PlanError::UnsupportedWriteProp { step, reason };
    let LoadOp::WriteProp {
        prop_id,
        inline_data,
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
    if !decl.writable {
        return Err(refuse(format!(
            "the load procedure declares {name} not writable and then writes it"
        )));
    }
    let PropObject::Index(index) = decl.object else {
        return Err(refuse(format!(
            "{name} is named by type; bussard writes a declared property by index only"
        )));
    };
    if index > u32::from(u8::MAX) || prop_id > u32::from(u8::MAX) {
        return Err(refuse(format!(
            "{name} exceeds the 8-bit object index or PID the property services address"
        )));
    }
    let elem = decl.element_size;
    let inline = inline_data.as_deref().filter(|d| !d.is_empty());
    let start = start_element.unwrap_or(1).max(1);
    let check_extent = |elements: u32| -> Result<(), PlanError> {
        let last = start.saturating_add(elements).saturating_sub(1);
        if last > decl.max_elements {
            return Err(refuse(format!(
                "the write to {name} reaches element {last}, past the declared MaxElements of {}",
                decl.max_elements
            )));
        }
        if last > MAX_ELEMENT_INDEX {
            return Err(refuse(format!(
                "the write to {name} reaches element {last}, past the 12-bit element index"
            )));
        }
        Ok(())
    };
    let placed = app.parameters.values().any(|p| {
        p.property
            .as_ref()
            .is_some_and(|loc| may_hold(loc, decl.object, prop_id))
    });
    let (value, from_parameters) = if placed {
        let count = count.unwrap_or(1).max(1);
        // Bounded by the extent check: at most 4095 elements of 20 octets.
        check_extent(count)?;
        let from = ((start - 1) as usize).saturating_mul(elem);
        let len = (count as usize).saturating_mul(elem);
        let mut template = inline.map(<[u8]>::to_vec).unwrap_or_default();
        template.resize(len, 0);
        let mut base = vec![0u8; from];
        base.extend_from_slice(&template);
        let composed = compose(base)?.ok_or_else(|| {
            refuse(format!(
                "a parameter may be stored in {name} but the value the parameters compose \
                 could not be found, so bussard has no value to write"
            ))
        })?;
        let mut value: Vec<u8> = composed.iter().skip(from).take(len).copied().collect();
        value.resize(len, 0);
        (value, true)
    } else {
        let data = inline.ok_or_else(|| {
            refuse(format!(
                "the write to the declared {name} carries no InlineData and no parameter is \
                 stored in it"
            ))
        })?;
        if !data.len().is_multiple_of(elem) {
            return Err(refuse(format!(
                "the {}-octet InlineData for {name} is not a whole number of {} elements \
                 ({elem} octets each)",
                data.len(),
                decl.prop_type
            )));
        }
        let elements = u32::try_from(data.len() / elem).unwrap_or(u32::MAX);
        if let Some(count) = count
            && *count != elements
        {
            return Err(refuse(format!(
                "the {}-octet InlineData for {name} holds {elements} {} elements, not its \
                 Count of {count}",
                data.len(),
                decl.prop_type
            )));
        }
        check_extent(elements)?;
        (data.to_vec(), false)
    };
    // Both fit the 12-bit element index checked above.
    let elements = (value.len() / elem) as u16;
    Ok(FlashStep::WriteProp {
        object: decl.object,
        prop_id,
        value,
        start_element: start as u16,
        count: elements,
        verify: verify.unwrap_or(false),
        from_parameters,
    })
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

    fn app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-1_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="D"><Static /></ApplicationProgram></KNX>"#;
        Ok(bussard_prod::application::parse_application_program(
            "M-1_A-1",
            xml.as_bytes(),
        )?)
    }

    #[test]
    fn test_pdt_element_size_follows_table_6() {
        assert_eq!(pdt_element_size("PDT_UNSIGNED_CHAR"), Some(1));
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

    /// A composer that places `placed` (offset, octet) over the base, as the
    /// parameters of a program would.
    fn placing(placed: &[(usize, u8)]) -> impl Fn(Vec<u8>) -> Result<Option<Vec<u8>>, PlanError> {
        let placed = placed.to_vec();
        move |mut base: Vec<u8>| {
            for (at, octet) in &placed {
                if base.len() <= *at {
                    base.resize(at + 1, 0);
                }
                base[*at] = *octet;
            }
            Ok(Some(base))
        }
    }

    /// An application with one parameter placed in object 10 PID 55.
    fn app_with_parameter() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-1_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="D">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-1_A-1_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-1_A-1_P-1" Name="p" ParameterType="M-1_A-1_PT-u8" Value="7">
             <Property ObjectIndex="10" PropertyId="55" Offset="0" BitOffset="0" />
            </Parameter>
           </Parameters>
          </Static>
         </ApplicationProgram></KNX>"#;
        Ok(bussard_prod::application::parse_application_program(
            "M-1_A-1",
            xml.as_bytes(),
        )?)
    }

    fn none(_: Vec<u8>) -> Result<Option<Vec<u8>>, PlanError> {
        Ok(None)
    }

    #[test]
    fn test_lower_declared_write_prop_writes_count_elements_over_the_placeholder() -> TestResult {
        // The Hager shape: a 10-octet zero placeholder, Count 20, the
        // parameters covering octets 0 and 19.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 20))?;
        let step = lower_declared_write_prop(
            2,
            &write(Some(vec![0; 10]), Some(20)),
            &decl,
            &placing(&[(0, 7), (19, 9)]),
            &app_with_parameter()?,
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
        // Count absent (1 element): ETS writes one octet, not the 10-octet
        // placeholder.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 1))?;
        let step = lower_declared_write_prop(
            2,
            &write(Some(vec![0; 10]), None),
            &decl,
            &placing(&[(0, 7)]),
            &app_with_parameter()?,
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
        let step = lower_declared_write_prop(
            2,
            &op,
            &decl,
            &placing(&[(3, 0x11), (7, 0x22)]),
            &app_with_parameter()?,
        )?;
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
        let step = lower_declared_write_prop(
            2,
            &write(Some(vec![1, 2, 3, 4, 5, 6]), Some(3)),
            &decl,
            &none,
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
    fn test_lower_declared_write_prop_refuses_partial_elements() -> TestResult {
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_INT", 4))?;
        let result =
            lower_declared_write_prop(2, &write(Some(vec![1, 2, 3]), None), &decl, &none, &app()?);
        assert!(matches!(
            result,
            Err(PlanError::UnsupportedWriteProp { step: 2, .. })
        ));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_refuses_past_max_elements() -> TestResult {
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 2))?;
        let result =
            lower_declared_write_prop(2, &write(Some(vec![1, 2, 3]), None), &decl, &none, &app()?);
        assert!(matches!(
            result,
            Err(PlanError::UnsupportedWriteProp { .. })
        ));
        let result = lower_declared_write_prop(
            2,
            &write(None, Some(3)),
            &decl,
            &placing(&[(0, 1)]),
            &app_with_parameter()?,
        );
        assert!(matches!(
            result,
            Err(PlanError::UnsupportedWriteProp { .. })
        ));
        Ok(())
    }
}
