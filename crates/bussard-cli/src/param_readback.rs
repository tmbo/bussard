//! Parameter read-back for `bussard plan` and `bussard reconstruct` (issue #119).
//!
//! Both commands read the link tables. With the device's product file (the
//! explicit `--product`, or the archive in `<dir>/vendor/` whose hardware
//! catalogue carries the model's order number) they also read the parameter
//! memory the application's load procedure writes, decode it through the
//! product's parameter types, and report:
//!
//! - the parameters whose value differs from the vendor default, and
//! - the differences to the model's parameter values (what
//!   `bussard flash --parameters-only` would write).
//!
//! The read is refused (with a note, never an error) when the device does not
//! run the application the product file describes, since its memory would then
//! decode to nonsense. Everything here is read-only on the bus.

use std::path::Path;

use bussard_download::{
    DecodedParameters, FlashPlan, ParamRegions, ParamValue, ResidentState, decode_parameters,
    group_object_change, probe_resident_state, read_parameter_regions, regions_memory,
};
use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_model::{IndividualAddress, Model};
use bussard_prod::{AppSelection, ApplicationProgram, ProductData};

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
    /// The selected application program, when the archive has it.
    pub(crate) fn app(&self) -> Option<&ApplicationProgram> {
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
    // Parse only the program `select_app` will pick (issue #214), judged on
    // the catalogue's ids. The narrowed read is used only when `select_app`
    // picks that very program from it; otherwise the full read decides, so
    // every choice and every refusal reads as before.
    let app_ref = device_product.and_then(|p| p.application_ref.as_deref());
    let read_error = |e: bussard_prod::ProdError| {
        anyhow::anyhow!("reading product data from {}: {e}", path.display())
    };
    // Texts in the lock's language, so the device file's enum labels resolve
    // and read-back values render as `import` wrote them (issue #231).
    let language = crate::product_cache::model_language(model, dir);
    let mut expected: Option<String> = None;
    let narrowed = crate::product_cache::read(&path, None, dir, language.as_deref(), |catalog| {
        expected = expected_app(catalog, application, app_ref, order.as_deref());
        match &expected {
            Some(id) => AppSelection::Only(vec![id.clone()]),
            None => AppSelection::All,
        }
    })
    .map_err(read_error)?;
    let picked = select_app(&narrowed, application, device_product, order.as_deref());
    if let (Ok(app_id), Some(want)) = (&picked, &expected)
        && app_id == want
    {
        return Ok(Some(ProductSource {
            product: narrowed,
            app_id: app_id.clone(),
        }));
    }
    if expected.is_none() {
        // The narrowed read already parsed every program.
        let app_id = picked.map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        return Ok(Some(ProductSource {
            product: narrowed,
            app_id,
        }));
    }
    let product =
        crate::product_cache::read(&path, None, dir, language.as_deref(), |_| AppSelection::All)
            .map_err(read_error)?;
    let app_id = select_app(&product, application, device_product, order.as_deref())
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(Some(ProductSource { product, app_id }))
}

/// The program [`select_app`] picks under its first three rules, judged on
/// the catalogue's ids alone: the `--application` match, else the model's
/// `application_ref` match, else the one program the order number maps to.
/// `None` when those rules do not settle it.
fn expected_app(
    catalog: &bussard_prod::ProductCatalog,
    application: Option<&str>,
    app_ref: Option<&str>,
    order: Option<&str>,
) -> Option<String> {
    if let Some(wanted) = application {
        return crate::product_cache::select_id(catalog, wanted);
    }
    if let Some(id) = app_ref.and_then(|wanted| crate::product_cache::select_id(catalog, wanted)) {
        return Some(id);
    }
    let held: Vec<String> = crate::product_cache::order_refs(catalog, order?)
        .into_iter()
        .filter(|id| catalog.application_ids.contains(id))
        .collect();
    match held.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    }
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
        let candidates: Vec<&ApplicationProgram> = product.applications.iter().collect();
        return bussard_download::select_application(&candidates, Some(id))
            .map(|a| a.id.clone())
            .map_err(|_| anyhow::anyhow!("no application program {id:?} in the product data"));
    }
    if let Some(wanted) = device_product.and_then(|p| p.application_ref.as_deref()) {
        let candidates: Vec<&ApplicationProgram> = product.applications.iter().collect();
        if let Ok(app) = bussard_download::select_application(&candidates, Some(wanted)) {
            return Ok(app.id.clone());
        }
    }
    if let Some(order) = order
        && let Ok(app) = crate::flash_cmd::resolve_by_order_number(product, order)
    {
        return Ok(app.id.clone());
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
    /// The runtime-owned parameters (`Access="None"`, e.g. a download flag the
    /// application resets after the restart): what the device holds, with no
    /// verdict against the default or the model.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    device_managed: Vec<ReadingJson>,
    /// Why the read-back is partial or absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
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

/// Everything a parameter read-back learned that a parameter write needs: the
/// full flash plan (which locates the memory), the regions as read, the
/// decoded values and the resident state the identity gate checked.
pub(crate) struct ParamDetail {
    /// The full flash plan for the device's mask.
    pub plan: FlashPlan,
    /// The parameter regions as the device holds them.
    pub regions: ParamRegions,
    /// The decoded memory against the model's overrides.
    pub decoded: DecodedParameters,
    /// What the probe found resident.
    pub resident: ResidentState,
    /// Why writing the model's values needs a full flash: they show or hide
    /// a com-object (the group-object table changes). `None` when they do not.
    pub needs_flash: Option<String>,
}

/// A parameter read-back: the report, and the detail when the memory was
/// read and decoded.
pub(crate) struct ParamState {
    /// The report `plan` and `reconstruct` print.
    pub readback: Readback,
    /// The memory and its decoding; `None` when the read was refused (see
    /// the report's note).
    pub detail: Option<ParamDetail>,
}

impl ParamState {
    fn noted(application: &str, note: String) -> ParamState {
        ParamState {
            readback: Readback::noted(application, note),
            detail: None,
        }
    }
}

/// Reads and decodes the parameter memory over an open, authorized session,
/// keeping the memory and its decoding for a parameter write.
pub(crate) async fn read_state<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    source: &ProductSource,
    model: Option<&Model>,
    target: IndividualAddress,
    device_mask: u16,
) -> ParamState {
    let Some(app) = source.app() else {
        return ParamState::noted(
            &source.app_id,
            "the application is not in the product data".into(),
        );
    };
    let plan =
        match crate::flash_cmd::plan_for_readback(&source.product, app, model, target, device_mask)
        {
            Ok(plan) => plan,
            Err(err) => {
                return ParamState::noted(
                    &app.id,
                    format!("the parameter memory cannot be located: {err}"),
                );
            }
        };
    let access = plan.sys7_lsm_access();
    let resident = probe_resident_state(l4, device_mask, access.as_ref()).await;
    // The parameter-only download's rule: the same program (any build hash)
    // on System B, every driven LSM Loaded and the product's code on System 7.
    if let Err(why) = crate::flash_params::identity_gate(&plan, Some(&resident)) {
        return ParamState::noted(&app.id, format!("parameters not decoded: {why}"));
    }
    if plan.is_sys7()
        && let Some(why) = crate::flash_params::sys7_code_mismatch(l4, &plan).await
    {
        return ParamState::noted(&app.id, format!("parameters not decoded: {why}"));
    }
    let regions = read_parameter_regions(l4, &plan).await;
    if regions.is_empty() {
        return ParamState::noted(&app.id, "the parameter memory could not be read".into());
    }
    let current = regions_memory(&regions);
    let (overrides, bases) = crate::flash_cmd::model_parameters(model, target);
    let decoded = decode_parameters(app, &overrides, &bases, &current);
    let change = group_object_change(app, &decoded.values, &overrides);
    let needs_flash =
        (!change.is_empty()).then(|| crate::flash_params::describe_group_object_change(&change));
    let device_managed = decoded
        .device_managed
        .iter()
        .cloned()
        .map(reading_json)
        .collect();
    let (non_default, differences) = report(decoded.clone());
    ParamState {
        readback: Readback {
            application: app.id.clone(),
            non_default,
            differences,
            device_managed,
            note: None,
        },
        detail: Some(ParamDetail {
            plan,
            regions,
            decoded,
            resident,
            needs_flash,
        }),
    }
}

/// One decoded value as a JSON report row.
fn reading_json(r: bussard_download::ParamReading) -> ReadingJson {
    ReadingJson {
        key: r.key,
        name: r.name,
        value: r.value,
        default: r.default,
        unit: r.unit,
    }
}

/// The JSON report rows of a decoded parameter memory.
fn report(decoded: DecodedParameters) -> (Vec<ReadingJson>, Vec<DifferenceJson>) {
    let non_default = decoded.non_default.into_iter().map(reading_json).collect();
    let differences = decoded
        .differences
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
    (non_default, differences)
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
    if !readback.device_managed.is_empty() {
        println!("  device-managed (written by a download, owned by the application; no verdict):");
        for r in &readback.device_managed {
            println!("      {}: {}", r.name, with_unit(&r.value, &r.unit));
        }
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
        "  run `bussard apply {target}` to write the model's values (a value that shows or \
         hides a com-object needs a full `bussard flash`)"
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
            "\nparameters: not read back (no product data under vendor/ for this device; pass \
             --product <FILE> or run `bussard import-product` to cache it)"
        );
    }
}
