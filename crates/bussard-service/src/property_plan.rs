//! `plan` for a device whose application is a property-only load procedure
//! (issue #390): the Jung IPS 300 SREG KNX IP interface (mask 0021) has no
//! group objects and no table reader, so its plan is the properties its
//! procedure writes, each read from the device and compared with the value
//! the model asks for. Shared by `bussard plan` and the MCP plan tool.

use std::collections::BTreeMap;

use bussard_download::{FlashPlan, FlashStep, PropObject, parameter_overrides, plan_flash};
use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_model::{IndividualAddress, Model};
use bussard_prod::ApplicationProgram;

/// The property-only download of `app` for `target` under the model's
/// parameters, or `None` when `app` is not a property-only procedure bussard
/// plans (see `bussard_download::FlashPlan::is_property_only`).
pub fn property_plan(
    app: &ApplicationProgram,
    model: Option<&Model>,
    target: IndividualAddress,
) -> Option<FlashPlan> {
    let mask = app
        .mask_version
        .as_deref()
        .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())?;
    let (overrides, _) = parameter_overrides(model, target);
    let plan = plan_flash(
        app,
        &target.to_string(),
        mask,
        &overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &bussard_prod::dynamic::DynamicMemo::new(app),
    )
    .ok()?;
    plan.is_property_only().then_some(plan)
}

/// One property of a property-only plan: what the model asks for and what
/// the device holds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PropertyRow {
    /// The object and property, in words (`object type 11 PID 205`).
    pub property: String,
    /// The octets the download writes, hex.
    pub planned: String,
    /// The octets the device holds, hex, when it answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Why the property could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PropertyRow {
    /// Whether the device does not (or may not) hold the planned value.
    pub fn differs(&self) -> bool {
        self.device.as_deref() != Some(self.planned.as_str())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Reads every property `plan` writes from the device on `l4`.
pub async fn read_property_rows<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
) -> Vec<PropertyRow> {
    let mut rows = Vec::new();
    for step in &plan.steps {
        let FlashStep::WriteProp {
            object,
            prop_id,
            value,
            start_element,
            count,
            ..
        } = step
        else {
            continue;
        };
        let elem = (value.len() / usize::from((*count).max(1))).max(1);
        let read = bussard_download::read_property_value(
            l4,
            *object,
            *prop_id,
            *start_element,
            (*count).max(1),
            elem,
        )
        .await;
        rows.push(row(*object, *prop_id, value, read));
    }
    rows
}

fn row(
    object: PropObject,
    prop_id: u32,
    planned: &[u8],
    read: Result<Vec<u8>, bussard_mgmt::load::WriteError>,
) -> PropertyRow {
    let (device, error) = match read {
        Ok(held) => (Some(hex(&held)), None),
        Err(err) => (None, Some(err.to_string())),
    };
    PropertyRow {
        property: format!("{object} PID {prop_id}"),
        planned: hex(planned),
        device,
        error,
    }
}

/// The plan in sentences: one line per property, then what to run.
pub fn render_text(target: IndividualAddress, app_id: &str, rows: &[PropertyRow]) -> String {
    let mut out = format!(
        "{target} runs {app_id}, a property-only load procedure (no group objects, no tables)\n"
    );
    for r in rows {
        let state = match (&r.device, &r.error) {
            (Some(held), _) if !r.differs() => format!("holds {held}, as the model asks"),
            (Some(held), _) => format!("holds {held}, the model asks for {}", r.planned),
            (None, Some(err)) => format!("not readable ({err}), the model asks for {}", r.planned),
            (None, None) => format!("not read, the model asks for {}", r.planned),
        };
        out.push_str(&format!("  {}: {state}\n", r.property));
    }
    if rows.iter().any(PropertyRow::differs) {
        out.push_str(&format!(
            "`bussard flash {target}` writes these properties and reads them back.\n"
        ));
    } else {
        out.push_str("nothing to do: the device holds every property the model asks for.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_text_names_what_differs() {
        let ip = PropObject::Type {
            object_type: 11,
            occurrence: 0,
        };
        let rows = vec![
            row(ip, 204, &[10], Ok(vec![10])),
            row(ip, 211, &[50], Ok(vec![5])),
        ];
        let text = render_text(IndividualAddress::from_raw(0x11C8), "A", &rows);
        assert!(text.contains("object type 11 PID 204: holds 0A, as the model asks"));
        assert!(text.contains("object type 11 PID 211: holds 05, the model asks for 32"));
        assert!(text.contains("bussard flash 1.1.200"));
        assert!(!rows[0].differs());
        assert!(rows[1].differs());
    }
}
