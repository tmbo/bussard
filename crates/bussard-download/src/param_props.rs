//! Property-placed parameters in the parameter download (issue #706).
//!
//! A parameter the product places in an interface-object property
//! (`<Parameter><Property ObjectIndex PropertyId …/></Parameter>`, issue
//! #669) has no octet in the parameter memory, so the memory diff of a
//! parameter-only download ([`FlashPlan::changed_octets`]) never sees a change
//! to it. The plan's `LdCtrlWriteProp` steps whose value the parameters
//! compose ([`crate::flash::FlashStep::WriteProp`] with `from_parameters`) name where the
//! value lives; this module reads what the device holds there and says which
//! of them differ from the model, so `flash --parameters-only` and `apply`
//! (CLI and MCP) count such a change as one to write.

use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_model::text::hex_upper;
use bussard_product::application::ApplicationProgram;

use crate::flash::{FlashPlan, PropObject, PropertyWrite, read_property_value};

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
            .map_or_else(|| "could not be read".to_string(), hex_upper);
        format!(
            "{}: {} (device: {device})",
            self.label(),
            hex_upper(&self.model)
        )
    }

    /// Whether `location` places a parameter in this property.
    pub fn holds(&self, location: &bussard_product::application::PropertyLocation) -> bool {
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

impl FlashPlan {
    /// The property writes of the plan whose value the program's parameters
    /// compose (issue #669), in plan order, each once; the device side unset.
    pub fn parameter_properties(&self) -> Vec<ParamProperty> {
        let mut out: Vec<ParamProperty> = Vec::new();
        for step in &self.steps {
            // A write the full flash leaves out as held after the parameter
            // reset (issue #951) is still a property the parameters decide.
            let Some(PropertyWrite {
                object,
                prop_id,
                value,
                start_element,
                count,
                from_parameters: true,
                ..
            }) = step.property_write()
            else {
                continue;
            };
            let property = ParamProperty {
                object,
                prop_id,
                start_element,
                count: count.max(1),
                model: value.to_vec(),
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

/// A run of property elements a procedure writes: what a read-back must
/// find there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyRange {
    /// The interface object, as the plan addresses it.
    pub object: PropObject,
    /// The property id.
    pub prop_id: u32,
    /// The first element.
    pub start: u16,
    /// How many elements.
    pub count: u16,
    /// The octets.
    pub value: Vec<u8>,
}

/// What `writes` (in procedure order) leave on the device: each write on the
/// runs of its elements no later write to the same object and property
/// covers (issue #946). A write whose value is not whole elements is kept as
/// it is. The one rule every read-back of property writes uses.
pub fn held_after(writes: &[PropertyRange]) -> Vec<PropertyRange> {
    writes
        .iter()
        .enumerate()
        .flat_map(|(i, w)| still_held(w, writes.get(i + 1..).unwrap_or_default()))
        .collect()
}

/// The parts of `write` the device still holds after `later`.
fn still_held(write: &PropertyRange, later: &[PropertyRange]) -> Vec<PropertyRange> {
    let count = usize::from(write.count.max(1));
    if !write.value.len().is_multiple_of(count) {
        return vec![write.clone()];
    }
    let elem = write.value.len() / count;
    let covered = |element: u32| {
        later.iter().any(|l| {
            l.object == write.object
                && l.prop_id == write.prop_id
                && (u32::from(l.start)..u32::from(l.start) + u32::from(l.count.max(1)))
                    .contains(&element)
        })
    };
    let mut out = Vec::new();
    let mut run: Option<(usize, usize)> = None;
    for i in 0..=count {
        let held = i < count && !covered(u32::from(write.start) + i as u32);
        match (held, run) {
            (true, None) => run = Some((i, i + 1)),
            (true, Some((from, _))) => run = Some((from, i + 1)),
            (false, Some((from, to))) => {
                out.push(PropertyRange {
                    object: write.object,
                    prop_id: write.prop_id,
                    // Within the write's own u16 extent.
                    start: write.start + from as u16,
                    count: (to - from) as u16,
                    value: write
                        .value
                        .get(from * elem..to * elem)
                        .unwrap_or_default()
                        .to_vec(),
                });
                run = None;
            }
            (false, None) => {}
        }
    }
    out
}

impl FlashPlan {
    /// The steps of the parameter-only procedure behind this plan (issue
    /// #1052): its own steps for a parameter-only plan built from it, the
    /// lowering it carries for a full plan, `None` otherwise.
    fn par_procedure_writes(&self) -> Option<&[crate::flash::FlashStep]> {
        if self.is_built_from_par_procedure() {
            Some(&self.steps)
        } else {
            self.par_procedure()
        }
    }

    /// The properties a parameter-only download of this plan writes and
    /// reads back (issue #1052). For a plan run by the mask's parameter-only
    /// procedure ([`FlashPlan::parameters_only`]): every property that
    /// procedure writes, each on the elements it leaves written
    /// ([`held_after`]), so a read-back of a correct device finds exactly
    /// these. Read before the download (the backup must hold each, or nothing
    /// is written) and after it (each must read back as written), so a write
    /// the device did not take, or a value a parameter reset changed and
    /// nothing wrote back, fails the download instead of passing unnoticed.
    /// For any other plan: [`FlashPlan::parameter_properties`].
    pub fn checked_properties(&self) -> Vec<ParamProperty> {
        let Some(steps) = self.par_procedure_writes() else {
            return self.parameter_properties();
        };
        let writes: Vec<PropertyRange> = steps
            .iter()
            .filter(|s| s.load_state_control().is_none())
            .filter_map(crate::flash::FlashStep::property_write)
            .map(|w| PropertyRange {
                object: w.object,
                prop_id: w.prop_id,
                start: w.start_element,
                count: w.count.max(1),
                value: w.value.to_vec(),
            })
            .collect();
        held_after(&writes)
            .into_iter()
            .map(|r| ParamProperty {
                object: r.object,
                prop_id: r.prop_id,
                start_element: r.start,
                count: r.count,
                model: r.value,
                device: None,
                parameters: Vec::new(),
            })
            .collect()
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
    read_properties(l4, plan.parameter_properties(), app).await
}

/// [`read_parameter_properties`] of [`FlashPlan::checked_properties`]: what
/// a parameter-only download backs up before it writes and compares after
/// (issue #1052).
pub async fn read_checked_properties<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
    app: &ApplicationProgram,
) -> Vec<ParamProperty> {
    read_properties(l4, plan.checked_properties(), app).await
}

/// Reads the device side of each of `out`.
async fn read_properties<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    mut out: Vec<ParamProperty>,
    app: &ApplicationProgram,
) -> Vec<ParamProperty> {
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
