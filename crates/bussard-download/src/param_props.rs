//! Property-placed parameters in the parameter download (issue #706).
//!
//! A parameter the product places in an interface-object property
//! (`<Parameter><Property ObjectIndex PropertyId …/></Parameter>`, issue
//! #669) has no octet in the parameter memory, so the memory diff of a
//! parameter-only download ([`FlashPlan::changed_octets`]) never sees a change
//! to it. The plan's `LdCtrlWriteProp` steps whose value the parameters
//! compose ([`FlashStep::WriteProp`] with `from_parameters`) name where the
//! value lives; this module reads what the device holds there and says which
//! of them differ from the model, so `flash --parameters-only` and `apply`
//! (CLI and MCP) count such a change as one to write.

use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_prod::application::ApplicationProgram;

use crate::flash::{FlashPlan, FlashStep, PropObject, read_property_value};

/// One property the program's parameters compose, with the model's value and
/// what the device holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamProperty {
    /// The interface object.
    pub object: PropObject,
    /// The property id.
    pub prop_id: u32,
    /// The 1-based element the value starts at.
    pub start_element: u16,
    /// How many elements the value spans.
    pub count: u16,
    /// The value the model composes (what the plan writes).
    pub model: Vec<u8>,
    /// What the device holds, `None` when it was not read or the read failed.
    pub device: Option<Vec<u8>>,
    /// The display names of the parameters placed in the property
    /// ([`ParamProperty::parameter_names`]), filled by
    /// [`read_parameter_properties`]; empty until then.
    pub parameters: Vec<String>,
}

impl ParamProperty {
    /// Whether the device does not hold the model's value: it differs, or it
    /// could not be read (a value bussard cannot confirm is written).
    pub fn differs(&self) -> bool {
        self.device.as_deref() != Some(self.model.as_slice())
    }

    /// `object 4 PID 201`.
    pub fn label(&self) -> String {
        format!("{} PID {}", self.object, self.prop_id)
    }

    /// `object 4 PID 201: 07, the device holds 5A` (or `could not be read`).
    pub fn sentence(&self) -> String {
        let device = self
            .device
            .as_deref()
            .map_or_else(|| "could not be read".to_string(), hex);
        format!("{}: {} (device: {device})", self.label(), hex(&self.model))
    }

    /// Whether `location` places a parameter in this property.
    pub fn holds(&self, location: &bussard_prod::application::PropertyLocation) -> bool {
        if location.property_id != self.prop_id {
            return false;
        }
        match self.object {
            PropObject::Index(index) => location.object_index == Some(index),
            PropObject::Type {
                object_type,
                occurrence,
            } => {
                location.object_type == Some(u32::from(object_type))
                    && location.occurrence.unwrap_or(0) == u32::from(occurrence)
            }
        }
    }

    /// The display names of the parameters `app` places in this property, in
    /// id order (the parameter's `Text`, else its `Name`, else its id).
    pub fn parameter_names(&self, app: &ApplicationProgram) -> Vec<String> {
        app.parameters
            .values()
            .filter(|p| p.property.as_ref().is_some_and(|loc| self.holds(loc)))
            .map(|p| {
                p.text
                    .clone()
                    .or_else(|| p.name.clone())
                    .unwrap_or_else(|| p.id.clone())
            })
            .collect()
    }
}

/// Upper-case hex, no separator.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

impl FlashPlan {
    /// The property writes of the plan whose value the program's parameters
    /// compose (issue #669), in plan order, each once; the device side unset.
    pub fn parameter_properties(&self) -> Vec<ParamProperty> {
        let mut out: Vec<ParamProperty> = Vec::new();
        for step in &self.steps {
            let FlashStep::WriteProp {
                object,
                prop_id,
                value,
                start_element,
                count,
                from_parameters: true,
                ..
            } = step
            else {
                continue;
            };
            let property = ParamProperty {
                object: *object,
                prop_id: *prop_id,
                start_element: *start_element,
                count: (*count).max(1),
                model: value.clone(),
                device: None,
                parameters: Vec::new(),
            };
            if !out.iter().any(|p| {
                (p.object, p.prop_id, p.start_element)
                    == (property.object, property.prop_id, property.start_element)
            }) {
                out.push(property);
            }
        }
        out
    }
}

/// Reads what the device holds in each of `plan`'s parameter properties
/// ([`FlashPlan::parameter_properties`]) of `app`: one property read each, on
/// the connection the parameter memory is read on, so the parameter read
/// costs one request more per property and nothing when the program places
/// no parameter in a property. A read that fails leaves the device side
/// `None`, which [`ParamProperty::differs`] counts as a difference.
pub async fn read_parameter_properties<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
    app: &ApplicationProgram,
) -> Vec<ParamProperty> {
    let mut out = plan.parameter_properties();
    for property in &mut out {
        property.parameters = property.parameter_names(app);
        let elem = (property.model.len() / usize::from(property.count)).max(1);
        match read_property_value(
            l4,
            property.object,
            property.prop_id,
            property.start_element,
            property.count,
            elem,
        )
        .await
        {
            Ok(value) => property.device = Some(value),
            Err(err) => {
                tracing::debug!(property = %property.label(), %err, "parameter property not read");
            }
        }
    }
    out
}

/// The properties of `properties` whose device value differs from the model.
pub fn changed_properties(properties: &[ParamProperty]) -> Vec<&ParamProperty> {
    properties.iter().filter(|p| p.differs()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn property(model: &[u8], device: Option<&[u8]>) -> ParamProperty {
        ParamProperty {
            object: PropObject::Index(4),
            prop_id: 201,
            start_element: 1,
            count: 1,
            model: model.to_vec(),
            device: device.map(<[u8]>::to_vec),
            parameters: Vec::new(),
        }
    }

    #[test]
    fn test_param_property_differs_on_value_and_on_an_unread_device() {
        assert!(!property(&[0x5A], Some(&[0x5A])).differs());
        assert!(property(&[0x07], Some(&[0x5A])).differs());
        assert!(property(&[0x07], None).differs());
        assert_eq!(
            property(&[0x07], Some(&[0x5A])).sentence(),
            "object 4 PID 201: 07 (device: 5A)"
        );
    }

    #[test]
    fn test_changed_properties_keeps_only_the_differing_ones() {
        let props = [
            property(&[0x5A], Some(&[0x5A])),
            property(&[0x07], Some(&[0x5A])),
        ];
        let changed = changed_properties(&props);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].model, vec![0x07]);
    }
}
