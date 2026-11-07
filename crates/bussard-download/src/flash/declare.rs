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

use super::plan_props::{may_hold, prop_object};
use super::{FlashStep, PlanError, PropObject};
use bussard_prod::application::{ApplicationProgram, LoadOp};
use bussard_prod::{PropertyObjectRef, PropertyParameters};

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

/// The values of the properties a program's parameters are placed in, as
/// the System B planner composes a declared property: resolved once per plan
/// ([`PropertyParameters`]); a test supplies its own.
pub(super) trait DeclaredValues {
    /// Whether a parameter is placed in `object`/`prop_id`, the object named
    /// exactly as the parameter names it. The one test of "the parameters
    /// decide this property" a declared write uses (issue #945).
    fn places(&self, object: PropObject, prop_id: u32) -> bool;

    /// The value of `object`/`prop_id` composed over `base`: the octets of
    /// the whole property from element 1, the parameters placed in it
    /// replacing the bits they cover. `None` when no parameter is placed in
    /// it.
    fn compose(
        &self,
        object: PropObject,
        prop_id: u32,
        base: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String>;
}

/// The object `object` names, as a property-located parameter names it.
fn object_ref(object: PropObject) -> PropertyObjectRef {
    match object {
        PropObject::Index(index) => PropertyObjectRef::Index(index),
        PropObject::Type {
            object_type,
            occurrence,
        } => PropertyObjectRef::Type {
            object_type: u32::from(object_type),
            occurrence: u32::from(occurrence),
        },
    }
}

impl DeclaredValues for PropertyParameters<'_> {
    fn places(&self, object: PropObject, prop_id: u32) -> bool {
        PropertyParameters::places(self, object_ref(object), prop_id)
    }

    fn compose(
        &self,
        object: PropObject,
        prop_id: u32,
        base: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        PropertyParameters::compose(self, object_ref(object), prop_id, base)
            .map_err(|e| e.to_string())
    }
}

/// Lowers an `LdCtrlWriteProp` to a property `decl` declared: `Count` elements
/// of the declared size from `StartElement`, whether or not a parameter is
/// placed in the property. The op's `InlineData` is the template, cut or
/// zero-padded to `Count` elements; the parameters placed in the property
/// replace the bits they cover (`values`). A write without `Count` is taken as
/// one element only where the declaration leaves room for no more
/// (`MaxElements` equal to `StartElement`, as captured); otherwise it is
/// refused.
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] when the property is declared not
/// writable, the write has no `Count` and could mean more than one element,
/// the write reaches past `MaxElements` or the 12-bit element index, a
/// parameter may be stored in the property under another name of its object
/// (an index against a type), its value cannot be composed, or there is no
/// value at all.
pub(super) fn lower_declared_write_prop(
    step: usize,
    op: &LoadOp,
    decl: &PropDecl,
    values: &dyn DeclaredValues,
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
    let count = match count {
        Some(count) => (*count).max(1),
        // ETS writes the one element (see the module docs).
        None if decl.max_elements == start => 1,
        None => {
            return Err(refuse(format!(
                "the LdCtrlWriteProp to the declared {name} has no Count, and the declaration \
                 (MaxElements {}, StartElement {start}) leaves room for more than one element; \
                 neither the KNX Standard nor the schema says how many it writes, so bussard \
                 does not guess",
                decl.max_elements
            )));
        }
    };
    let last = start.saturating_add(count).saturating_sub(1);
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
    // Bounded by the extent check: at most 4095 elements of 20 octets.
    let from = ((start - 1) as usize).saturating_mul(elem);
    let len = (count as usize).saturating_mul(elem);
    let mut template = inline.map(<[u8]>::to_vec).unwrap_or_default();
    template.resize(len, 0);
    let (value, from_parameters) = if values.places(decl.object, prop_id) {
        let mut base = vec![0u8; from];
        base.extend_from_slice(&template);
        let composed = values
            .compose(decl.object, prop_id, base)
            .map_err(|e| {
                refuse(format!(
                    "composing the value of {name} from the parameters: {e}"
                ))
            })?
            .ok_or_else(|| {
                refuse(format!(
                    "a parameter is placed in {name} but composed no value for it"
                ))
            })?;
        let mut value: Vec<u8> = composed.iter().skip(from).take(len).copied().collect();
        value.resize(len, 0);
        (value, true)
    } else if app.parameters.values().any(|p| {
        p.property
            .as_ref()
            .is_some_and(|loc| may_hold(loc, decl.object, prop_id))
    }) {
        return Err(refuse(format!(
            "a parameter is placed in a property that may be {name}, but it names the object \
             by type where the load procedure names it by index (or names no object); bussard \
             does not resolve one to the other, so it has no value to write"
        )));
    } else if inline.is_some() {
        (template, false)
    } else {
        return Err(refuse(format!(
            "the write to the declared {name} carries no InlineData and no parameter is \
             stored in it"
        )));
    };
    Ok(FlashStep::WriteProp {
        object: decl.object,
        prop_id,
        value,
        // Both fit the 12-bit element index checked above.
        start_element: start as u16,
        count: count as u16,
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

    /// Values with parameters placed in object 10 PID 55 at `(offset, octet)`,
    /// as the parameters of a program would compose them.
    struct Placing(Vec<(usize, u8)>);

    impl DeclaredValues for Placing {
        fn places(&self, object: PropObject, prop_id: u32) -> bool {
            object == PropObject::Index(10) && prop_id == 55
        }

        fn compose(
            &self,
            object: PropObject,
            prop_id: u32,
            mut base: Vec<u8>,
        ) -> Result<Option<Vec<u8>>, String> {
            if !self.places(object, prop_id) {
                return Ok(None);
            }
            for (at, octet) in &self.0 {
                if base.len() <= *at {
                    base.resize(at + 1, 0);
                }
                base[*at] = *octet;
            }
            Ok(Some(base))
        }
    }

    fn placing(placed: &[(usize, u8)]) -> Placing {
        Placing(placed.to_vec())
    }

    /// Values with no parameter placed in any property.
    struct NotPlaced;

    impl DeclaredValues for NotPlaced {
        fn places(&self, _: PropObject, _: u32) -> bool {
            false
        }

        fn compose(&self, _: PropObject, _: u32, _: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
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
        // Count absent on a one-element declaration: ETS writes one octet,
        // not the 10-octet placeholder (obj10 PID 52 of E804).
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
            &NotPlaced,
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
    fn test_lower_declared_write_prop_pads_the_inline_data_to_count() -> TestResult {
        // Sized by Count, not by the InlineData length: 3 octets for two
        // 2-octet elements are zero-padded.
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_INT", 4))?;
        let step = lower_declared_write_prop(
            2,
            &write(Some(vec![1, 2, 3]), Some(2)),
            &decl,
            &NotPlaced,
            &app()?,
        )?;
        assert!(matches!(
            step,
            FlashStep::WriteProp { ref value, count: 2, from_parameters: false, .. }
                if value == &[1, 2, 3, 0]
        ));
        Ok(())
    }

    #[test]
    fn test_lower_declared_write_prop_refuses_past_max_elements() -> TestResult {
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 2))?;
        let result = lower_declared_write_prop(
            2,
            &write(Some(vec![1, 2, 3]), Some(3)),
            &decl,
            &NotPlaced,
            &app()?,
        );
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

    #[test]
    fn test_lower_declare_prop_accepts_binary_information() -> TestResult {
        // Issue #945: one octet per element, as PDT_UNSIGNED_CHAR.
        let decl = lower_declare_prop(1, &declare("PDT_BINARY_INFORMATION", 1))?;
        assert_eq!(decl.element_size, 1);
        let step = lower_declared_write_prop(
            2,
            &write(Some(vec![1]), Some(1)),
            &decl,
            &NotPlaced,
            &app()?,
        )?;
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
            let step = lower_declared_write_prop(
                2,
                &write(Some(vec![0; 10]), count),
                &decl,
                &NotPlaced,
                &app()?,
            )?;
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
        let cases: [(&dyn DeclaredValues, ApplicationProgram); 2] = [
            (&NotPlaced, app()?),
            (&Placing(vec![(0, 7)]), app_with_parameter()?),
        ];
        for (values, app) in cases {
            match lower_declared_write_prop(2, &write(Some(vec![0; 10]), None), &decl, values, &app)
            {
                Err(PlanError::UnsupportedWriteProp { step: 2, reason }) => {
                    assert!(reason.contains("no Count"), "{reason}");
                    assert!(reason.contains("object 10 PID 55") || reason.contains("PID 55"));
                }
                other => return Err(format!("expected a refusal, got {other:?}").into()),
            }
        }
        Ok(())
    }

    /// The evaluated configuration of `app` with no overrides.
    fn config_of(app: &ApplicationProgram) -> std::sync::Arc<bussard_prod::dynamic::DynamicConfig> {
        bussard_prod::dynamic::DynamicMemo::new(app)
            .evaluate_for(app, &std::collections::BTreeMap::new())
    }

    #[test]
    fn test_lower_declared_write_prop_composes_from_the_resolved_parameters() -> TestResult {
        // The planner's own values: the parameter's 7 over the placeholder.
        let app = app_with_parameter()?;
        let config = config_of(&app);
        let values = PropertyParameters::resolve(&app, &config);
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 4))?;
        let step =
            lower_declared_write_prop(2, &write(Some(vec![0; 10]), Some(4)), &decl, &values, &app)?;
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
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-1_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="D">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-1_A-1_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-1_A-1_P-1" Name="p" ParameterType="M-1_A-1_PT-u8" Value="7">
             <Property ObjectType="11" PropertyId="55" Offset="0" BitOffset="0" />
            </Parameter>
           </Parameters>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = bussard_prod::application::parse_application_program("M-1_A-1", xml.as_bytes())?;
        let config = config_of(&app);
        let values = PropertyParameters::resolve(&app, &config);
        let decl = lower_declare_prop(1, &declare("PDT_UNSIGNED_CHAR", 1))?;
        match lower_declared_write_prop(2, &write(Some(vec![0]), Some(1)), &decl, &values, &app) {
            Err(PlanError::UnsupportedWriteProp { reason, .. }) => {
                assert!(reason.contains("by type"), "{reason}");
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }
        Ok(())
    }
}
