//! Building the [`DevicePlan`] `plan` and `apply` print, from what one read of
//! the device returned: its live tables and, when product data is at hand,
//! its parameter memory.
//!
//! The rendering and the state fingerprint live in
//! [`bussard_download::device_plan`], shared with the MCP programming tier;
//! this module adds the parameter half, which only the CLI reads.

use std::collections::BTreeMap;
use std::path::Path;

use bussard_download::backup::backups_root;
use bussard_download::{
    ChangeMark, ChangeSubject, DevicePlan, FlashPlan, LiveTables, ParamValue, PlanChange,
    PlanReport, PlanWrites, object_changes, sort_changes, state_hash,
};
use bussard_model::{IndividualAddress, Model};

use crate::param_readback::ParamState;

/// A plan, and what executing its parameter half needs.
pub(crate) struct Built {
    /// The plan to print and confirm.
    pub plan: DevicePlan,
    /// The parameter-only download that writes the differing octets, when
    /// any differ.
    pub partial: Option<FlashPlan>,
    /// Why this device cannot be written by `apply` (a parameter change that
    /// shows or hides a com-object needs a full `flash`).
    pub refusal: Option<String>,
}

/// Builds the plan of writing the model to `target`.
///
/// `params` is the parameter read-back, `None` when no product data was at
/// hand. The parameter half is left out of the write (with a note) when the
/// read-back could not decode the memory.
pub(crate) fn build(
    model: &Model,
    target: IndividualAddress,
    gateway: &str,
    dir: &Path,
    live: &LiveTables,
    report: &PlanReport,
    params: Option<&ParamState>,
) -> Built {
    let device = model.devices.get(&target).map(|d| &d.device);
    let (mut changes, unchanged_objects) = object_changes(model, target, report);
    let mut notes = Vec::new();
    let mut unchanged_parameters = None;
    let mut partial = None;
    let mut refusal = None;
    let mut parameter_octets = 0;

    match params {
        None => {
            if device.is_some_and(|d| !d.parameters.is_empty()) {
                let order = device
                    .and_then(|d| d.product.as_ref())
                    .and_then(|p| p.order_number.clone());
                notes.push(match order {
                    Some(order) => format!(
                        "parameters not compared: no product data for {order} under {} (run \
                         `bussard import-product --order-number {order}`, or pass --product)",
                        dir.join("vendor").display()
                    ),
                    None => "parameters not compared: the device file names no product (order \
                             number), so no product data can be found"
                        .to_string(),
                });
            }
        }
        Some(state) => match &state.detail {
            None => {
                if let Some(note) = &state.readback.note {
                    notes.push(format!("parameters not compared: {note}"));
                }
            }
            Some(detail) => {
                let differences = &detail.decoded.differences;
                unchanged_parameters = Some(
                    detail
                        .decoded
                        .values
                        .len()
                        .saturating_sub(differences.len()),
                );
                for c in differences {
                    let place = device.and_then(|d| d.parameter_place(&c.key));
                    let channel = place
                        .as_ref()
                        .and_then(|(ch, _)| ch.as_deref())
                        .and_then(|id| device.map(|d| d.channel_handle(id)));
                    let key = place
                        .map(|(_, key)| key)
                        .unwrap_or_else(|| bussard_model::slug(&c.name));
                    let unit = match &c.unit {
                        Some(u) if !u.is_empty() => format!(" {u}"),
                        _ => String::new(),
                    };
                    let was = match &c.old {
                        ParamValue::Known(v) => format!("{v}{unit}"),
                        ParamValue::Unknown => "unreadable".to_string(),
                    };
                    changes.push(PlanChange {
                        mark: ChangeMark::Changed,
                        subject: ChangeSubject::Parameter,
                        channel,
                        key: key.clone(),
                        object: None,
                        sentence: format!("{key} = {}{unit}, was {was}", c.new),
                    });
                }
                if let Some(why) = &detail.needs_flash {
                    refusal = Some(format!(
                        "the model's parameter values change the group-object table ({why}); \
                         `apply` rewrites parameters in place and cannot do that. Run a full \
                         `bussard flash {target}`."
                    ));
                } else {
                    match detail.plan.parameters_only(&detail.regions) {
                        Ok(p) => {
                            parameter_octets = p.changed_octets();
                            if parameter_octets > 0 {
                                partial = Some(p);
                            }
                        }
                        Err(err) => notes.push(format!(
                            "parameters not written: {err} (a full `bussard flash {target}` \
                             writes them)"
                        )),
                    }
                }
            }
        },
    }
    sort_changes(&mut changes);

    let tables_change = !report.is_noop();
    let writes = PlanWrites {
        address_table: tables_change.then_some(report.resulting_address_count),
        association_table: tables_change.then_some(report.resulting_association_count),
        parameter_octets,
    };
    let root = backups_root(dir);
    let backup_dir = if parameter_octets > 0 {
        format!(
            "{} (tables) and {} (parameter memory)",
            root.display(),
            bussard_download::backup::parameter_backups_dir(dir).display()
        )
    } else {
        root.display().to_string()
    };
    let channels: BTreeMap<String, String> = device
        .map(|d| {
            d.channels
                .iter()
                .map(|(id, ch)| (d.channel_handle(id), ch.name.clone()))
                .collect()
        })
        .unwrap_or_default();
    let regions = params.and_then(|s| s.detail.as_ref()).map(|d| &d.regions);
    Built {
        plan: DevicePlan {
            address: target.to_string(),
            name: device.map(|d| d.name.clone()).unwrap_or_default(),
            gateway: gateway.to_string(),
            changes,
            channels,
            unchanged_objects,
            unchanged_parameters,
            writes,
            backup_dir,
            notes,
            state_hash: state_hash(live, regions),
        },
        partial,
        refusal,
    }
}
