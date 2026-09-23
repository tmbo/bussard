//! Parameter read-back for `bussard plan` and `bussard reconstruct` (issue #119).
//!
//! Both commands read the link tables. With the device's product file (the
//! explicit `--product`, or the archive in `<dir>/vendor/` whose hardware
//! catalogue carries the model's order number) they also read the parameter
//! memory the application's load procedure writes, decode it through the
//! product's parameter types, and report:
//!
//! - the parameters whose value differs from the vendor default, and
//! - the differences to the model's `parameters:` block (what
//!   `bussard flash --parameters-only` would write).
//!
//! The read is refused (with a note, never an error) when the device does not
//! run the application the product file describes, since its memory would then
//! decode to nonsense. Everything here is read-only on the bus.

use std::path::Path;

use bussard_download::{
    Freshness, ParamValue, assess_freshness, non_default_parameters, param_plan,
    probe_resident_state, read_parameter_regions, regions_memory,
};
use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_model::{IndividualAddress, Model};
use bussard_prod::{ApplicationProgram, ProductData};

/// The `--product` / `--application` flags of `plan` and `reconstruct`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Selection<'a> {
    /// `--product`: the vendor `.knxprod`.
    pub product: Option<&'a Path>,
    /// `--application`: the application program id.
    pub application: Option<&'a str>,
}

/// The product file and application a read-back decodes with.
pub(crate) struct ProductSource {
    /// The parsed product archive.
    product: ProductData,
    /// The selected application program id.
    app_id: String,
}

impl ProductSource {
    fn app(&self) -> Option<&ApplicationProgram> {
        self.product.application_by_id(&self.app_id)
    }
}

/// Resolves the product file and application for `target`.
///
/// `explicit` is `--product`; without it the vendor cache is searched by the
/// model device's order number. Returns `Ok(None)` when there is nothing to
/// decode with and none was asked for (no `--product`, no cached archive).
/// An explicit `--product` that cannot be read or holds no matching
/// application is an error.
pub(crate) fn resolve(
    dir: &Path,
    selection: Selection<'_>,
    model: Option<&Model>,
    target: IndividualAddress,
) -> anyhow::Result<Option<ProductSource>> {
    let (explicit, application) = (selection.product, selection.application);
    let device_product = model
        .and_then(|m| m.devices.get(&target))
        .and_then(|d| d.device.product.as_ref());
    let order = device_product.and_then(|p| p.order_number.clone());
    let path = match (explicit, &order) {
        (Some(path), _) => path.to_path_buf(),
        (None, Some(order)) => {
            match crate::commission_cmd::resolve_product_file(dir, None, order) {
                Ok(path) => path,
                Err(err) => {
                    tracing::debug!(%err, "no cached product file for the parameter read-back");
                    return Ok(None);
                }
            }
        }
        (None, None) => return Ok(None),
    };
    let product = bussard_prod::read_knxprod(&path)
        .map_err(|e| anyhow::anyhow!("reading product data from {}: {e}", path.display()))?;
    let app_id = select_app(&product, application, device_product, order.as_deref())
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(Some(ProductSource { product, app_id }))
}

/// Picks the application: `--application`, else the model's `application_ref`
/// when the archive has it, else the order number, else the sole application.
fn select_app(
    product: &ProductData,
    application: Option<&str>,
    device_product: Option<&bussard_model::schema::Product>,
    order: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(id) = application {
        return product
            .application_by_id(id)
            .map(|a| a.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no application program {id:?} in the product data"));
    }
    if let Some(app) = device_product
        .and_then(|p| p.application_ref.as_deref())
        .and_then(|r| product.application_by_id(r))
    {
        return Ok(app.id.clone());
    }
    if let Some(order) = order {
        if let Ok(app) = crate::flash_cmd::resolve_by_order_number(product, order) {
            return Ok(app.id.clone());
        }
    }
    match product.applications.as_slice() {
        [only] => Ok(only.id.clone()),
        apps => anyhow::bail!(
            "the product data has {} application programs; pass --application to choose one",
            apps.len()
        ),
    }
}

/// One non-default parameter, for the JSON report.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ReadingJson {
    key: String,
    name: String,
    value: String,
    default: String,
    unit: Option<String>,
}

/// One difference between the device and the model, for the JSON report.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DifferenceJson {
    key: String,
    name: String,
    /// What the device holds; `None` when it could not be read.
    device: Option<String>,
    /// What the model asks for (its override, else the vendor default).
    model: String,
    unit: Option<String>,
}

/// The parameter read-back of one device.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub(crate) struct Readback {
    /// The application the memory was decoded with.
    application: String,
    /// The parameters whose device value differs from the vendor default.
    non_default: Vec<ReadingJson>,
    /// The parameters whose device value differs from the model.
    differences: Vec<DifferenceJson>,
    /// Why the read-back is partial or absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

impl Readback {
    fn noted(application: &str, note: String) -> Readback {
        Readback {
            application: application.to_string(),
            note: Some(note),
            ..Readback::default()
        }
    }
}

/// Reads and decodes the parameter memory over an open, authorized session.
pub(crate) async fn read<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    source: &ProductSource,
    model: Option<&Model>,
    target: IndividualAddress,
    device_mask: u16,
) -> Readback {
    let Some(app) = source.app() else {
        return Readback::noted(
            &source.app_id,
            "the application is not in the product data".into(),
        );
    };
    let plan =
        match crate::flash_cmd::plan_for_readback(&source.product, app, model, target, device_mask)
        {
            Ok(plan) => plan,
            Err(err) => {
                return Readback::noted(
                    &app.id,
                    format!("the parameter memory cannot be located: {err}"),
                );
            }
        };
    let access = plan.sys7_lsm_access();
    let resident = probe_resident_state(l4, device_mask, access.as_ref()).await;
    let runs_app = match assess_freshness(&resident, &plan.identity) {
        Freshness::SameApplication { .. } => Ok(()),
        // System 7 has no readable application id: accept a fully Loaded device.
        Freshness::Resident { resident: None, .. }
            if plan.is_sys7()
                && resident
                    .objects
                    .iter()
                    .all(|o| o.state == bussard_mgmt::load::LoadState::Loaded) =>
        {
            Ok(())
        }
        Freshness::Fresh => Err("the device holds no loaded application".to_string()),
        Freshness::Resident {
            resident: Some(id), ..
        } => Err(format!("the device runs {id}")),
        Freshness::Resident { resident: None, .. } => {
            Err("the device's application id cannot be read".to_string())
        }
        Freshness::Unknown { reason } => Err(format!("its load state is unreadable ({reason})")),
    };
    if let Err(why) = runs_app {
        return Readback::noted(
            &app.id,
            format!("parameters not decoded: {why}, not {}", app.id),
        );
    }
    let regions = read_parameter_regions(l4, &plan).await;
    if regions.is_empty() {
        return Readback::noted(&app.id, "the parameter memory could not be read".into());
    }
    let current = regions_memory(&regions);
    let (overrides, bases) = crate::flash_cmd::model_parameters(model, target);
    let non_default = non_default_parameters(app, &current)
        .into_iter()
        .map(|r| ReadingJson {
            key: r.key,
            name: r.name,
            value: r.value,
            default: r.default,
            unit: r.unit,
        })
        .collect();
    let plan = param_plan(app, &overrides, &bases, &current);
    let differences = plan
        .changes
        .into_iter()
        .map(|c| DifferenceJson {
            key: c.key,
            name: c.name,
            device: match c.old {
                ParamValue::Known(v) => Some(v),
                ParamValue::Unknown => None,
            },
            model: c.new.to_string(),
            unit: c.unit,
        })
        .collect();
    Readback {
        application: app.id.clone(),
        non_default,
        differences,
        note: plan.note,
    }
}

/// Appends the unit, when there is one.
fn with_unit(value: &str, unit: &Option<String>) -> String {
    match unit {
        Some(u) if !u.is_empty() => format!("{value} {u}"),
        _ => value.to_string(),
    }
}

/// Prints the read-back section of a text report.
pub(crate) fn print_text(readback: &Readback, target: IndividualAddress) {
    println!("\nparameters (application {}):", readback.application);
    if let Some(note) = &readback.note {
        println!("  note: {note}");
    }
    if readback.non_default.is_empty() && readback.differences.is_empty() {
        if readback.note.is_none() {
            println!("  every parameter holds its vendor default and matches the model");
        }
        return;
    }
    println!(
        "  {} parameter(s) differ from the vendor default:",
        readback.non_default.len()
    );
    for r in &readback.non_default {
        println!(
            "      {}: {} (default {})",
            r.name,
            with_unit(&r.value, &r.unit),
            with_unit(&r.default, &r.unit)
        );
    }
    if readback.differences.is_empty() {
        println!("  the device matches the model's parameters: block");
        return;
    }
    println!(
        "  {} parameter(s) differ from the model:",
        readback.differences.len()
    );
    for d in &readback.differences {
        let device = d
            .device
            .as_deref()
            .map(|v| with_unit(v, &d.unit))
            .unwrap_or_else(|| "unreadable".to_string());
        println!(
            "      {}: device {device}, model {}",
            d.name,
            with_unit(&d.model, &d.unit)
        );
    }
    println!(
        "  run `bussard flash --parameters-only {target} --product <FILE>` to write the model's \
         values (a value that shows or hides a com-object needs a full `bussard flash`)"
    );
}

/// The note printed when the model has parameters for a device but no product
/// file was found to decode them with.
pub(crate) fn print_missing_product_note(model: Option<&Model>, target: IndividualAddress) {
    let has_params = model
        .and_then(|m| m.devices.get(&target))
        .is_some_and(|d| !d.device.parameters.is_empty());
    if has_params {
        println!(
            "\nparameters: not read back (no product file; pass --product <FILE> or run \
             `bussard import-product` to cache it)"
        );
    }
}
