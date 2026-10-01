//! The parameter half of a device write, shared by `bussard plan`, `bussard
//! apply`, `bussard reconstruct` and the MCP programming tier (issues #119,
//! #274).
//!
//! 1. **The product data** ([`resolve_product`]): the archive `bussard.lock`
//!    pins for the device (or an explicit `--product`), verified, and the
//!    application program the device runs.
//! 2. **The read-back** ([`read_state`]): on an open, authorized session, the
//!    parameter memory the application's load procedure writes, decoded
//!    through the product's parameter types and compared with the model.
//! 3. **The plan** ([`build_device_plan`]): the object and parameter changes in
//!    the model's words, and the parameter-only download that writes the
//!    differing octets.
//! 4. **The write** ([`crate::download::write_parameters`]): that download,
//!    verified by reading the memory back.
//!
//! One implementation for every surface, so the image the MCP tier writes is
//! the CLI's, octet for octet.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bussard_download::backup::backups_root;
use bussard_download::{
    ChangeMark, ChangeSubject, DecodedParameters, DevicePlan, FlashPlan, LiveTables, OctetRange,
    OctetRole, ParamRegions, ParamValue, PlanChange, PlanReport, PlanWrites, ResidentState,
    decode_parameters, group_object_change, object_changes, probe_resident_state,
    read_parameter_regions, regions_memory, select_application, sort_changes, state_hash,
};
use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_model::schema::{Device, ProductEntry};
use bussard_model::{IndividualAddress, Model};
use bussard_prod::{AppSelection, ApplicationProgram, ProductCatalog, ProductData};

/// The retained product store under a model directory (issue #228).
pub const PRODUCTS_DIR: &str = "products";

/// Why the product data for a device could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ProductError(pub String);

/// An error and its sources, joined with `": "` (the `{:#}` rendering).
fn chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut next = err.source();
    while let Some(cause) = next {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        next = cause.source();
    }
    out
}

/// The `--product` / `--application` selection of a command.
#[derive(Debug, Clone, Copy, Default)]
pub struct Selection<'a> {
    /// `--product`: the vendor `.knxprod`.
    pub product: Option<&'a Path>,
    /// `--application`: the application program id.
    pub application: Option<&'a str>,
}

/// What [`resolve_product`] does when the lock pins an archive that is
/// missing or whose content changed (issue #228).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingProduct {
    /// Refuse (a command about to write the parameters: `apply`).
    Refuse,
    /// Warn and go on without parameters (`plan`, `reconstruct`, the MCP
    /// tier's links-only plan).
    Warn,
}

/// The product file and application a read-back decodes with.
pub struct ProductSource {
    /// The parsed product archive.
    pub product: ProductData,
    /// The selected application program id.
    pub app_id: String,
}

impl ProductSource {
    /// The selected application program, when the archive has it.
    pub fn app(&self) -> Option<&ApplicationProgram> {
        self.product.application_by_id(&self.app_id)
    }
}

/// What [`resolve_product`] found.
#[derive(Default)]
pub struct ProductLookup {
    /// The product data, when there is any to decode with.
    pub source: Option<ProductSource>,
    /// Under [`MissingProduct::Warn`], why a pinned archive could not be used
    /// (its recovery step included). `None` when nothing went wrong.
    pub warning: Option<String>,
}

/// Called with how long each product parse took and a one-line detail
/// (the CLI's `--timing` phase).
pub type ParseHook = fn(Duration, String);

/// Reads `path` (a `.knxprod`, a wrapper with `inner`, or a `.knxproj`),
/// parsing only what `select` picks, through the parsed-product cache of the
/// model at `dir` (issue #214). `language` is the lock's language, so enum
/// labels resolve as `import` wrote them.
///
/// # Errors
///
/// As [`bussard_prod::read_knxprod`].
pub fn read_product(
    path: &Path,
    inner: Option<&str>,
    dir: &Path,
    language: Option<&str>,
    select: impl FnOnce(&ProductCatalog) -> AppSelection,
    on_parse: Option<ParseHook>,
) -> bussard_prod::Result<ProductData> {
    let started = std::time::Instant::now();
    let cache = bussard_prod::product_model::cache_dir(dir);
    let product =
        bussard_prod::read_knxprod_selected_in(path, inner, cache.as_deref(), language, select);
    if let Some(hook) = on_parse {
        let detail = match &product {
            Ok(p) => format!(
                "{} program(s), {}",
                p.applications.len(),
                if cache.is_some() {
                    "cache on"
                } else {
                    "no cache"
                }
            ),
            Err(_) => "failed".to_string(),
        };
        hook(started.elapsed(), detail);
    }
    product
}

/// The language a model's device files carry their texts and enum labels in:
/// the `language` the loaded `model`'s lock records, else the language
/// `bussard import` would use for `dir`. `None` when nothing says.
pub fn model_language(model: Option<&Model>, dir: &Path) -> Option<String> {
    model
        .and_then(|m| m.lock_language().map(str::to_string))
        .or_else(|| bussard_model::import_language(dir))
}

/// The id [`select_application`] picks for `wanted` among the catalogue's
/// programs, judged on the ids alone (all the rule reads).
pub fn select_id(catalog: &ProductCatalog, wanted: &str) -> Option<String> {
    let stubs: Vec<ApplicationProgram> = catalog
        .application_ids
        .iter()
        .map(|id| ApplicationProgram {
            id: id.clone(),
            ..ApplicationProgram::default()
        })
        .collect();
    let refs: Vec<&ApplicationProgram> = stubs.iter().collect();
    select_application(&refs, Some(wanted))
        .ok()
        .map(|a| a.id.clone())
}

/// Every program the hardware catalogue maps an order number to that
/// normalizes to `order` (what `resolve_by_order_number` considers).
pub fn order_refs(catalog: &ProductCatalog, order: &str) -> Vec<String> {
    let want = bussard_prod::normalize_order_number(order);
    let mut refs: Vec<String> = Vec::new();
    for (o, apps) in &catalog.hardware.order_to_apps {
        if bussard_prod::normalize_order_number(o) == want {
            for r in apps {
                if !refs.contains(r) {
                    refs.push(r.clone());
                }
            }
        }
    }
    refs
}

/// The archive `entry` pins, verified: its path when the file is there and
/// its SHA-256 is the pinned one.
///
/// # Errors
///
/// The file is missing (or the entry names none), or its content changed;
/// the message names the recovery step.
pub fn verified_path(
    dir: &Path,
    what: &str,
    entry: &ProductEntry,
) -> Result<PathBuf, ProductError> {
    bussard_prod::product_model::verified_archive(dir, what, entry)
        .map_err(|e| ProductError(chain(&e)))
}

/// The archive a model device's product data comes from: the entry its lock
/// link names, verified. `Ok(None)` when the lock pins nothing for it.
///
/// # Errors
///
/// The pinned archive is missing or its content changed.
pub fn device_archive(dir: &Path, device: &Device) -> Result<Option<PathBuf>, ProductError> {
    let Some(entry) = &device.lock.product_entry else {
        return Ok(None);
    };
    verified_path(dir, &device.address.to_string(), entry).map(Some)
}

/// The archive the lock pins for an order number (the first entry holding
/// an archive whose catalogue carries it), verified. `Ok(None)` when no
/// entry carries it.
///
/// # Errors
///
/// A matching entry's archive is missing or changed.
pub fn archive_for_order(dir: &Path, order: &str) -> Result<Option<PathBuf>, ProductError> {
    let want = bussard_prod::normalize_order_number(order);
    let entries = bussard_model::lock_products::lock_entries(dir);
    let mut matching = entries.iter().filter(|e| {
        e.file.is_some()
            && e.order_numbers
                .iter()
                .any(|o| bussard_prod::normalize_order_number(o) == want)
    });
    match matching.next() {
        Some(entry) => verified_path(dir, order, entry).map(Some),
        None => Ok(None),
    }
}

/// Resolves the product file and application for `target`.
///
/// `selection.product` is `--product`; without it the archive the lock pins
/// for the device (else for its order number) is used. The lookup holds no
/// source when there is nothing to decode with and none was asked for.
///
/// # Errors
///
/// An explicit `--product` that cannot be read or holds no matching
/// application, and under [`MissingProduct::Refuse`] a pinned archive that
/// is missing or changed.
pub fn resolve_product(
    dir: &Path,
    selection: Selection<'_>,
    model: Option<&Model>,
    target: IndividualAddress,
    missing: MissingProduct,
    on_parse: Option<ParseHook>,
) -> Result<ProductLookup, ProductError> {
    let (explicit, application) = (selection.product, selection.application);
    let model_device = model
        .and_then(|m| m.devices.get(&target))
        .map(|d| &d.device);
    let device_product = model_device.and_then(|d| d.product.as_ref());
    let order = device_product.and_then(|p| p.order_number.clone());
    let refused = |err: ProductError| match missing {
        MissingProduct::Refuse => Err(err),
        MissingProduct::Warn => Ok(ProductLookup {
            source: None,
            warning: Some(err.0),
        }),
    };
    // The archive bussard.lock pins for the device (issue #228), verified; a
    // pinned archive that is missing or changed is refused or warned about
    // per `missing`, an unpinned device decodes nothing.
    let pinned = match (explicit, model_device) {
        (None, Some(device)) => device_archive(dir, device),
        _ => Ok(None),
    };
    let pinned = match pinned {
        Ok(pinned) => pinned,
        Err(err) => return refused(err),
    };
    let path = match (explicit, pinned, &order) {
        (Some(path), _, _) => path.to_path_buf(),
        (None, Some(path), _) => path,
        (None, None, Some(order)) => match archive_for_order(dir, order) {
            Ok(Some(path)) => path,
            Ok(None) => return Ok(ProductLookup::default()),
            Err(err) => return refused(err),
        },
        (None, None, None) => return Ok(ProductLookup::default()),
    };
    // Parse only the program `select_app` will pick (issue #214), judged on
    // the catalogue's ids. The narrowed read is used only when `select_app`
    // picks that very program from it; otherwise the full read decides, so
    // every choice and every refusal reads as before.
    let app_ref = device_product.and_then(|p| p.application_ref.as_deref());
    let read_error = |e: bussard_prod::ProdError| {
        ProductError(format!("reading product data from {}: {e}", path.display()))
    };
    let app_error = |e: ProductError| ProductError(format!("{}: {e}", path.display()));
    let found = |product, app_id| {
        Ok(ProductLookup {
            source: Some(ProductSource { product, app_id }),
            warning: None,
        })
    };
    // Texts in the lock's language, so the device file's enum labels resolve
    // and read-back values render as `import` wrote them (issue #231).
    let language = model_language(model, dir);
    let mut expected: Option<String> = None;
    let narrowed = read_product(
        &path,
        None,
        dir,
        language.as_deref(),
        |catalog| {
            expected = expected_app(catalog, application, app_ref, order.as_deref());
            match &expected {
                Some(id) => AppSelection::Only(vec![id.clone()]),
                None => AppSelection::All,
            }
        },
        on_parse,
    )
    .map_err(read_error)?;
    let picked = select_app(&narrowed, application, device_product, order.as_deref());
    if let (Ok(app_id), Some(want)) = (&picked, &expected)
        && app_id == want
    {
        let app_id = app_id.clone();
        return found(narrowed, app_id);
    }
    if expected.is_none() {
        // The narrowed read already parsed every program.
        let app_id = picked.map_err(app_error)?;
        return found(narrowed, app_id);
    }
    let product = read_product(
        &path,
        None,
        dir,
        language.as_deref(),
        |_| AppSelection::All,
        on_parse,
    )
    .map_err(read_error)?;
    let app_id =
        select_app(&product, application, device_product, order.as_deref()).map_err(app_error)?;
    found(product, app_id)
}

/// The program [`select_app`] picks under its first three rules, judged on
/// the catalogue's ids alone: the `--application` match, else the model's
/// `application_ref` match, else the one program the order number maps to.
/// `None` when those rules do not settle it.
fn expected_app(
    catalog: &ProductCatalog,
    application: Option<&str>,
    app_ref: Option<&str>,
    order: Option<&str>,
) -> Option<String> {
    if let Some(wanted) = application {
        return select_id(catalog, wanted);
    }
    if let Some(id) = app_ref.and_then(|wanted| select_id(catalog, wanted)) {
        return Some(id);
    }
    let held: Vec<String> = order_refs(catalog, order?)
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
) -> Result<String, ProductError> {
    if let Some(id) = application {
        let candidates: Vec<&ApplicationProgram> = product.applications.iter().collect();
        return select_application(&candidates, Some(id))
            .map(|a| a.id.clone())
            .map_err(|_| {
                ProductError(format!("no application program {id:?} in the product data"))
            });
    }
    if let Some(wanted) = device_product.and_then(|p| p.application_ref.as_deref()) {
        let candidates: Vec<&ApplicationProgram> = product.applications.iter().collect();
        if let Ok(app) = select_application(&candidates, Some(wanted)) {
            return Ok(app.id.clone());
        }
    }
    if let Some(order) = order
        && let Ok(app) = bussard_download::resolve_by_order_number(product, order)
    {
        return Ok(app.id.clone());
    }
    match product.applications.as_slice() {
        [only] => Ok(only.id.clone()),
        apps => Err(ProductError(format!(
            "the product data has {} application programs; pass --application to choose one",
            apps.len()
        ))),
    }
}

/// One non-default parameter, for the JSON report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReadingJson {
    /// The parameter's key.
    pub key: String,
    /// The vendor text.
    pub name: String,
    /// What the device holds.
    pub value: String,
    /// The vendor default.
    pub default: String,
    /// The unit, when the parameter type has one.
    pub unit: Option<String>,
}

/// One difference between the device and the model, for the JSON report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DifferenceJson {
    /// The parameter's key.
    pub key: String,
    /// The vendor text.
    pub name: String,
    /// What the device holds; `None` when it could not be read.
    pub device: Option<String>,
    /// What the model asks for (its override, else the vendor default).
    pub model: String,
    /// The unit, when the parameter type has one.
    pub unit: Option<String>,
}

/// The parameter read-back of one device.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Readback {
    /// The application the memory was decoded with.
    pub application: String,
    /// The parameters whose device value differs from the vendor default.
    pub non_default: Vec<ReadingJson>,
    /// The parameters whose device value differs from the model.
    pub differences: Vec<DifferenceJson>,
    /// The runtime-owned parameters (`Access="None"`, e.g. a download flag the
    /// application resets after the restart): what the device holds, with no
    /// verdict against the default or the model.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub device_managed: Vec<ReadingJson>,
    /// The written octet runs that hold an internal ETS value (`Access="None"`,
    /// never shown, e.g. a function-block selector) differing from the
    /// model's image, with both values (issue #285).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub internal: Vec<OctetAttribution>,
    /// Why the read-back is partial or absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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
pub struct ParamDetail {
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
    /// The octets a parameter-only download of the model writes, with the
    /// parameters behind each run (issue #279). Empty when nothing differs
    /// or the download cannot be cut.
    pub octets: Vec<OctetRange>,
    /// The octets that differ from the model's image where no parameter the
    /// configuration reaches is placed (issue #290): ETS's download does not
    /// write them, so neither does the parameter-only download. Listed, never
    /// written or counted.
    pub unwritten: Vec<OctetRange>,
}

/// A parameter read-back: the report, and the detail when the memory was
/// read and decoded.
pub struct ParamState {
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
pub async fn read_state<Ch: L4Channel>(
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
        match bussard_download::plan_for_readback(&source.product, app, model, target, device_mask)
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
    if let Err(why) = bussard_download::identity_gate(&plan, Some(&resident)) {
        return ParamState::noted(&app.id, format!("parameters not decoded: {why}"));
    }
    if plan.is_sys7()
        && let Some(why) = bussard_download::sys7_code_mismatch(l4, &plan).await
    {
        return ParamState::noted(&app.id, format!("parameters not decoded: {why}"));
    }
    let regions = read_parameter_regions(l4, &plan).await;
    if regions.is_empty() {
        return ParamState::noted(&app.id, "the parameter memory could not be read".into());
    }
    let current = regions_memory(&regions);
    let (overrides, bases) = bussard_download::model_parameters(model, target);
    let decoded = decode_parameters(app, &overrides, &bases, &current);
    let change = group_object_change(app, &decoded.values, &overrides);
    let needs_flash =
        (!change.is_empty()).then(|| bussard_download::describe_group_object_change(&change));
    let device_managed = decoded
        .device_managed
        .iter()
        .cloned()
        .map(reading_json)
        .collect();
    let (non_default, differences) = report(decoded.clone());
    let (octets, unwritten) = plan
        .parameters_only(&regions)
        .map(|partial| {
            let attribute = |changed: &BTreeMap<String, Vec<(usize, u8)>>| {
                bussard_download::attribute_octets(
                    app,
                    &overrides,
                    &bases,
                    &current,
                    &model_images(&partial, changed),
                    changed,
                )
            };
            (
                attribute(&partial.changed_bits()),
                attribute(&partial.unwritten_bits()),
            )
        })
        .unwrap_or_default();
    let device = model
        .and_then(|m| m.devices.get(&target))
        .map(|d| &d.device);
    let internal = octet_ranges(device, &octets, &unwritten, TargetLabel::Model)
        .into_iter()
        .filter(|r| r.parameters.iter().any(|p| p.role == OctetRole::Internal))
        .collect();
    ParamState {
        readback: Readback {
            application: app.id.clone(),
            non_default,
            differences,
            device_managed,
            internal,
            note: None,
        },
        detail: Some(ParamDetail {
            plan,
            regions,
            decoded,
            resident,
            needs_flash,
            octets,
            unwritten,
        }),
    }
}

/// The model's image of each segment `changed` names (the octets a full
/// download writes there), for attributing octets of `partial`.
pub(crate) fn model_images(
    partial: &FlashPlan,
    changed: &BTreeMap<String, Vec<(usize, u8)>>,
) -> BTreeMap<String, Vec<u8>> {
    changed
        .keys()
        .filter_map(|segment| Some((segment.clone(), partial.model_image(segment)?)))
        .collect()
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

/// One parameter the plan writes, in the model's words and the vendor's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ParameterChange {
    /// The device-file key (`<channel>.<slug>` when the parameter belongs to a
    /// channel, else the slug).
    pub key: String,
    /// The vendor text of the parameter.
    pub name: String,
    /// What the device holds (`None`: unreadable), with the unit.
    pub device: Option<String>,
    /// What the model asks for, with the unit.
    pub model: String,
}

/// A plan, and what executing its parameter half needs.
pub struct BuiltPlan {
    /// The plan to print and confirm.
    pub plan: DevicePlan,
    /// The parameter-only download that writes the differing octets, when
    /// any differ.
    pub partial: Option<FlashPlan>,
    /// The parameters that differ, one row each (empty when they were not
    /// compared).
    pub parameters: Vec<ParameterChange>,
    /// Why this device cannot be written by `apply` (a parameter change that
    /// shows or hides a com-object needs a full `flash`).
    pub refusal: Option<String>,
    /// Why the parameters were not compared or cannot be written, when they
    /// were not (also in the plan's notes).
    pub parameters_skipped: Option<String>,
    /// Every run of parameter octets the plan writes, with the parameters
    /// behind it (issue #279). Empty when no parameter octet is written.
    pub octet_ranges: Vec<OctetAttribution>,
}

/// A run of parameter octets a plan writes, in the model's words (issue
/// #279).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OctetAttribution {
    /// The code segment, as the product names it after the application id
    /// (`RS-2`).
    pub segment: String,
    /// The first octet's offset in the segment.
    pub offset: usize,
    /// How many octets.
    pub length: usize,
    /// The parameters whose bits in the run differ, by device-file key.
    pub parameters: Vec<OctetParameter>,
    /// The run in one line, ready to quote.
    pub sentence: String,
    /// What the run means, when it holds an internal ETS selector whose
    /// device value differs from the model's ([`INTERNAL_SELECTOR_NOTE`]),
    /// or when the run is not written (the "ETS does not write this octet"
    /// sentence, issue #290).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Whether the plan writes the run. `false` for octets that differ where
    /// no parameter the configuration reaches is placed (issue #290): ETS's
    /// download leaves them as the device holds them, and so does bussard's
    /// parameter-only download. They are never counted in
    /// `parameter_octets`.
    pub written: bool,
}

/// Whose bytes the `model` side of an octet run shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLabel {
    /// The model's image (`plan`, `apply`).
    Model,
    /// A parameter backup's memory (`restore --parameters`).
    Backup,
}

impl TargetLabel {
    /// The word a run's sentence uses for the side.
    fn word(self) -> &'static str {
        match self {
            TargetLabel::Model => "model",
            TargetLabel::Backup => "backup",
        }
    }
}

/// What an internal ETS selector that differs means (issue #285).
pub const INTERNAL_SELECTOR_NOTE: &str = "an internal ETS selector differs: the device's \
     function assignment differs from the project (the project changed after the device's \
     last download, or the device was downloaded from another project state); writing makes \
     the device match the model";

/// What an octet a download of the model does not place means, when the
/// device holds another value there (issue #289, 1.1.18): ETS skips such an
/// octet in a download (a capture of ETS showed it skipping exactly those),
/// so the device's value is left from an earlier state, not a project change.
fn unwritten_note(owner: &bussard_download::OctetOwner) -> String {
    format!(
        "ETS does not write this octet in a download; a full download leaves the segment fill \
         (0x{:02X}) there; the device holds {} from an earlier state",
        owner.segment_fill.unwrap_or(0),
        owner.device.as_deref().unwrap_or("an unreadable value")
    )
}

/// What an unwritten run means when no unreached parameter of the
/// application names it (vendor data, a module parameter the configuration
/// does not instantiate there): the same rule, without a value to quote.
pub const UNWRITTEN_NOTE: &str = "ETS does not write this octet in a download: no parameter the \
     configuration reaches is placed there, so the device keeps its value; a full download \
     writes the segment's fill or vendor data there";

/// The sentence a plan prefixes to a run it does not write (issue #290).
const UNWRITTEN_PREFIX: &str = "not written (ETS does not write this octet in a download)";

/// The prefix of a device-managed run a restore leaves alone (issue #290).
const DEVICE_MANAGED_PREFIX: &str = "not written (owned by the application at runtime)";

/// What a device-managed run a restore leaves alone means (issue #290).
pub const DEVICE_MANAGED_SKIP_NOTE: &str = "the application owns this value at runtime (an \
     `Access=\"None\"` parameter such as a download flag); a restore leaves the device's value";

/// A parameter behind written octets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OctetParameter {
    /// The device-file key (`<channel>.<key>` in a channel), or the ref id
    /// when the device file does not place the parameter.
    pub key: String,
    /// The vendor text.
    pub name: String,
    /// Why it is or is not in the changed list.
    pub role: OctetRole,
    /// What the device holds there (enumeration member text, else the
    /// number, with the unit); `None` when it cannot be decoded.
    pub device: Option<String>,
    /// What the model's image holds there, in the same form.
    pub model: Option<String>,
}

/// How many octet runs a plan's notes spell out before pointing at the
/// structured list.
const OCTET_NOTE_RANGES: usize = 8;

/// The model-side key of a parameter ref on `device`: `<channel>.<key>` or
/// `<key>` where the device file places it, else the ref id.
fn file_key(device: Option<&Device>, reference: &str) -> String {
    let Some(d) = device else {
        return reference.to_string();
    };
    match d.parameter_place(reference) {
        Some((channel, key)) => match channel.map(|id| d.channel_handle(&id)) {
            Some(handle) => format!("{handle}.{key}"),
            None => key,
        },
        None => reference.to_string(),
    }
}

/// The written runs and the unwritten ones (issue #290) in the model's
/// words, in segment and offset order.
pub fn octet_ranges(
    device: Option<&Device>,
    written: &[OctetRange],
    unwritten: &[OctetRange],
    label: TargetLabel,
) -> Vec<OctetAttribution> {
    let mut out = octet_attributions(device, written, true, label);
    out.extend(octet_attributions(device, unwritten, false, label));
    out.sort_by(|a, b| (&a.segment, a.offset).cmp(&(&b.segment, b.offset)));
    out
}

/// The octet runs of `ranges` in the model's words; `written` says whether
/// the plan writes them.
fn octet_attributions(
    device: Option<&Device>,
    ranges: &[OctetRange],
    written: bool,
    label: TargetLabel,
) -> Vec<OctetAttribution> {
    ranges
        .iter()
        .map(|r| {
            let segment = r
                .segment
                .rsplit_once('_')
                .map_or(r.segment.as_str(), |(_, tail)| tail)
                .to_string();
            let parameters: Vec<OctetParameter> = r
                .owners
                .iter()
                .map(|o| OctetParameter {
                    key: file_key(device, &o.key),
                    name: o.name.clone(),
                    role: o.role,
                    device: o.device.clone(),
                    model: o.model.clone(),
                })
                .collect();
            let place = format!(
                "{} at offset {} of segment {segment}",
                if r.length == 1 {
                    "1 octet".to_string()
                } else {
                    format!("{} octets", r.length)
                },
                r.offset
            );
            let managed =
                !r.owners.is_empty() && r.owners.iter().all(|o| o.role == OctetRole::DeviceManaged);
            let place = match (written, managed) {
                (true, _) => place,
                (false, true) => format!("{place}, {DEVICE_MANAGED_PREFIX}"),
                (false, false) => format!("{place}, {UNWRITTEN_PREFIX}"),
            };
            let sentence = if parameters.is_empty() {
                format!(
                    "{place}: device memory differs from the {}'s {} there, not covered by a \
                     shown parameter",
                    label.word(),
                    if label == TargetLabel::Model {
                        "defaults"
                    } else {
                        "bytes"
                    }
                )
            } else {
                let names: Vec<String> = r
                    .owners
                    .iter()
                    .zip(&parameters)
                    .map(|(o, p)| {
                        let named = format!("{} ({}, {})", p.name, o.role_text(), p.key);
                        match (&p.device, &p.model) {
                            (None, None) => named,
                            (device, model) => format!(
                                "{named}, device {}, {} {}",
                                device.as_deref().unwrap_or("unreadable"),
                                label.word(),
                                model.as_deref().unwrap_or("unreadable")
                            ),
                        }
                    })
                    .collect();
                format!("{place}: {}", names.join("; "))
            };
            let explanation = r
                .owners
                .iter()
                .find(|o| o.unwritten_differs())
                .map(unwritten_note)
                .or_else(|| {
                    r.owners
                        .iter()
                        .any(bussard_download::OctetOwner::internal_selector_differs)
                        .then(|| INTERNAL_SELECTOR_NOTE.to_string())
                })
                .or_else(|| match (written, managed) {
                    (true, _) => None,
                    (false, true) => Some(DEVICE_MANAGED_SKIP_NOTE.to_string()),
                    (false, false) => Some(UNWRITTEN_NOTE.to_string()),
                });
            OctetAttribution {
                segment,
                offset: r.offset,
                length: r.length,
                parameters,
                sentence,
                explanation,
                written,
            }
        })
        .collect()
}

/// The plan notes that explain the written octets no changed parameter
/// accounts for: every run when no parameter changes, else the runs that
/// are not all changed parameters. Empty when nothing needs explaining.
fn octet_notes(octets: usize, changed: usize, ranges: &[OctetAttribution]) -> Vec<String> {
    let ranges: Vec<OctetAttribution> = ranges.iter().filter(|r| r.written).cloned().collect();
    let ranges = ranges.as_slice();
    let unexplained: Vec<&OctetAttribution> = ranges
        .iter()
        .filter(|r| {
            r.parameters.is_empty() || r.parameters.iter().any(|p| p.role != OctetRole::Changed)
        })
        .collect();
    if octets == 0 || unexplained.is_empty() {
        return Vec::new();
    }
    let mut notes = vec![if changed == 0 {
        format!(
            "the {octets} parameter octet{} this plan writes change{} no parameter the device \
             file shows; writing the model's image puts back what follows",
            if octets == 1 { "" } else { "s" },
            if octets == 1 { "s" } else { "" }
        )
    } else {
        "parameter octets written besides the changed parameters:".to_string()
    }];
    notes.extend(
        unexplained
            .iter()
            .take(OCTET_NOTE_RANGES)
            .map(|r| r.sentence.clone()),
    );
    if unexplained.len() > OCTET_NOTE_RANGES {
        notes.push(format!(
            "and {} more octet runs (the plan's parameter octet list names them all)",
            unexplained.len() - OCTET_NOTE_RANGES
        ));
    }
    let mut explained: Vec<&str> = Vec::new();
    for explanation in ranges.iter().filter_map(|r| r.explanation.as_deref()) {
        if !explained.contains(&explanation) {
            explained.push(explanation);
        }
    }
    notes.extend(explained.into_iter().map(str::to_string));
    notes
}

/// The written and unwritten octet runs of `detail` in the model's words.
fn octet_ranges_of(
    device: Option<&Device>,
    detail: &ParamDetail,
    label: TargetLabel,
) -> Vec<OctetAttribution> {
    octet_ranges(device, &detail.octets, &detail.unwritten, label)
}

/// Whether every written octet run is owned only by device-managed
/// parameters ([`OctetRole::DeviceManaged`]: `Access="None"` runtime values
/// such as a download flag). A run no parameter covers, or one with any
/// other owner, is a real difference.
pub fn device_managed_only(ranges: &[OctetAttribution]) -> bool {
    let mut ranges = ranges.iter().filter(|r| r.written).peekable();
    ranges.peek().is_some()
        && ranges.all(|r| {
            !r.parameters.is_empty()
                && r.parameters
                    .iter()
                    .all(|p| p.role == OctetRole::DeviceManaged)
        })
}

/// The plan note for parameter octets that differ only where the
/// application owns the value at runtime (issue #289): not written on their
/// own, written with the next table or parameter write as ETS does at a
/// download.
fn device_managed_note(octets: usize, ranges: &[OctetAttribution]) -> String {
    let runs: Vec<&str> = ranges
        .iter()
        .filter(|r| r.written)
        .map(|r| r.sentence.as_str())
        .collect();
    format!(
        "{octets} device-managed parameter octet{s} differ{v} from the model's image and {is} \
         not written on {its} own (the application owns {them} at runtime; the next table or \
         parameter write puts back the model's value, as ETS does at a download): {}",
        runs.join("; "),
        s = if octets == 1 { "" } else { "s" },
        v = if octets == 1 { "s" } else { "" },
        is = if octets == 1 { "is" } else { "are" },
        its = if octets == 1 { "its" } else { "their" },
        them = if octets == 1 { "it" } else { "them" },
    )
}

/// The plan note for the octets a parameter-only download leaves alone
/// although the device differs from the model's image there (issue #290):
/// `None` when there are none.
pub fn unwritten_note_for(ranges: &[OctetAttribution]) -> Option<String> {
    let runs: Vec<&OctetAttribution> = ranges.iter().filter(|r| !r.written).collect();
    if runs.is_empty() {
        return None;
    }
    let octets: usize = runs.iter().map(|r| r.length).sum();
    let mut sentences: Vec<&str> = runs
        .iter()
        .take(OCTET_NOTE_RANGES)
        .map(|r| r.sentence.as_str())
        .collect();
    let more = runs.len().saturating_sub(OCTET_NOTE_RANGES);
    let tail = if more > 0 {
        format!(" (and {more} more runs in the plan's parameter octet list)")
    } else {
        String::new()
    };
    sentences.dedup();
    Some(format!(
        "{octets} parameter octet{s} differ{v} from the model's image where no parameter the \
         configuration reaches is placed; ETS does not write {them} in a download, so this plan \
         leaves the device's value{s} (a full `bussard flash` writes the segment fill): {}{tail}",
        sentences.join("; "),
        s = if octets == 1 { "" } else { "s" },
        v = if octets == 1 { "s" } else { "" },
        them = if octets == 1 { "it" } else { "them" },
    ))
}

/// The refusal of a parameter write whose values show, hide or reshape a
/// com-object (`why` names them): `apply` and `knx_apply_device` rewrite
/// parameters in place, so only a full `bussard flash <ia>` writes the new
/// group-object table.
pub fn group_object_refusal(target: IndividualAddress, why: &str) -> String {
    format!(
        "the model's parameter values change the group-object table ({why}); `apply` rewrites \
         parameters in place and cannot do that. A parameter that shows or hides com-objects \
         needs a full `bussard flash {target}`."
    )
}

/// Builds the plan of writing the model to `target`.
///
/// `params` is the parameter read-back, `None` when no product data was at
/// hand. The parameter half is left out of the write (with a note) when the
/// read-back could not decode the memory.
pub fn build_device_plan(
    model: &Model,
    target: IndividualAddress,
    gateway: &str,
    dir: &Path,
    live: &LiveTables,
    report: &PlanReport,
    params: Option<&ParamState>,
) -> BuiltPlan {
    let device = model.devices.get(&target).map(|d| &d.device);
    let (mut changes, unchanged_objects) = object_changes(model, target, report);
    let mut notes = Vec::new();
    let mut unchanged_parameters = None;
    let mut partial = None;
    let mut refusal = None;
    let mut parameter_octets = 0;
    let mut parameters = Vec::new();
    let mut octet_ranges = Vec::new();

    match params {
        None => {
            if device.is_some_and(|d| !d.parameters.is_empty()) {
                let order = device
                    .and_then(|d| d.product.as_ref())
                    .and_then(|p| p.order_number.clone());
                notes.push(match order {
                    Some(order) => format!(
                        "parameters not compared: bussard.lock pins no product data for {order} \
                         in {} (run `bussard import-product --order-number {order}`, or pass \
                         --product)",
                        dir.join(PRODUCTS_DIR).display()
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
                    parameters.push(ParameterChange {
                        key: match &channel {
                            Some(ch) => format!("{ch}.{key}"),
                            None => key.clone(),
                        },
                        name: c.name.clone(),
                        device: match &c.old {
                            ParamValue::Known(v) => Some(format!("{v}{unit}")),
                            ParamValue::Unknown => None,
                        },
                        model: format!("{}{unit}", c.new),
                    });
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
                    refusal = Some(group_object_refusal(target, why));
                } else {
                    match detail.plan.parameters_only(&detail.regions) {
                        Ok(p) => {
                            let octets = p.changed_octets();
                            octet_ranges = octet_ranges_of(device, detail, TargetLabel::Model);
                            if let Some(note) = unwritten_note_for(&octet_ranges) {
                                notes.push(note);
                            }
                            if octets > 0 {
                                if report.is_noop()
                                    && parameters.is_empty()
                                    && device_managed_only(&octet_ranges)
                                {
                                    // Issue #289: octets the application owns
                                    // at runtime (a download flag) always
                                    // differ from the model's image. They are
                                    // listed, but never written on their own.
                                    notes.push(device_managed_note(octets, &octet_ranges));
                                } else {
                                    parameter_octets = octets;
                                    partial = Some(p);
                                    notes.extend(octet_notes(
                                        parameter_octets,
                                        parameters.len(),
                                        &octet_ranges,
                                    ));
                                }
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
    let parameters_skipped = notes
        .iter()
        .find(|n| n.starts_with("parameters not"))
        .cloned();

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
    BuiltPlan {
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
        parameters,
        refusal,
        parameters_skipped,
        octet_ranges,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(ids: &[&str]) -> ProductCatalog {
        ProductCatalog {
            application_ids: ids.iter().map(|s| s.to_string()).collect(),
            ..ProductCatalog::default()
        }
    }

    /// Issue #279: the written octets are named per run, and a plan that
    /// changes no shown parameter says why it writes octets at all.
    #[test]
    fn test_octet_notes_explain_unattributed_octets() {
        let owner = |key: &str, role: OctetRole| bussard_download::OctetOwner {
            key: key.to_string(),
            name: format!("{key} text"),
            role,
            device: None,
            model: None,
            enumerated: false,
            segment_fill: None,
        };
        let range =
            |offset: usize, length: usize, owners: Vec<bussard_download::OctetOwner>| OctetRange {
                segment: "M-00FA_A-0002_RS-2".to_string(),
                offset,
                length,
                owners,
            };
        let uncovered = octet_attributions(None, &[range(1, 2, vec![])], true, TargetLabel::Model);
        assert_eq!(uncovered[0].segment, "RS-2");
        assert_eq!(
            uncovered[0].sentence,
            "2 octets at offset 1 of segment RS-2: device memory differs from the model's \
             defaults there, not covered by a shown parameter"
        );
        let hidden = octet_attributions(
            None,
            &[range(
                4,
                1,
                vec![owner("P-8_R-8", OctetRole::DeviceManaged)],
            )],
            true,
            TargetLabel::Model,
        );
        let changed = octet_attributions(
            None,
            &[range(0, 1, vec![owner("P-0_R-1", OctetRole::Changed)])],
            true,
            TargetLabel::Model,
        );

        // (octets, changed parameters, runs, the notes' first line or None)
        let cases: Vec<(usize, usize, Vec<OctetAttribution>, Option<&str>)> = vec![
            (
                2,
                0,
                uncovered.clone(),
                Some(
                    "the 2 parameter octets this plan writes change no parameter the device \
                     file shows; writing the model's image puts back what follows",
                ),
            ),
            (
                1,
                0,
                hidden.clone(),
                Some(
                    "the 1 parameter octet this plan writes changes no parameter the device \
                     file shows; writing the model's image puts back what follows",
                ),
            ),
            (1, 1, changed.clone(), None),
            (
                2,
                1,
                [changed, hidden].concat(),
                Some("parameter octets written besides the changed parameters:"),
            ),
            (0, 0, Vec::new(), None),
        ];
        for (octets, n_changed, runs, want) in cases {
            let notes = octet_notes(octets, n_changed, &runs);
            assert_eq!(notes.first().map(String::as_str), want, "{notes:?}");
            if want.is_some() {
                assert_eq!(notes.len(), 2, "{notes:?}");
            }
        }
    }

    /// Issue #289: runs owned only by device-managed parameters are not a
    /// difference on their own; any other owner, or a run no parameter
    /// covers, is.
    #[test]
    fn test_device_managed_only_needs_every_owner_device_managed() {
        let owner = |key: &str, role: OctetRole| bussard_download::OctetOwner {
            key: key.to_string(),
            name: key.to_string(),
            role,
            device: Some("1".to_string()),
            model: Some("0".to_string()),
            enumerated: false,
            segment_fill: None,
        };
        let run = |owners: Vec<bussard_download::OctetOwner>| OctetRange {
            segment: "M-00FA_A-0002_RS-2".to_string(),
            offset: 1,
            length: 1,
            owners,
        };
        let flag = || owner("P-1_R-2", OctetRole::DeviceManaged);
        let cases = [
            (vec![run(vec![flag()])], true),
            (vec![run(vec![flag()]), run(vec![flag()])], true),
            (
                vec![run(vec![flag(), owner("P-0_R-1", OctetRole::Changed)])],
                false,
            ),
            (vec![run(vec![flag()]), run(vec![])], false),
            (vec![run(vec![owner("P-3", OctetRole::Internal)])], false),
            (vec![], false),
        ];
        for (runs, want) in cases {
            let ranges = octet_attributions(None, &runs, true, TargetLabel::Model);
            assert_eq!(device_managed_only(&ranges), want, "{ranges:?}");
        }
        let note = device_managed_note(
            1,
            &octet_attributions(None, &[run(vec![flag()])], true, TargetLabel::Model),
        );
        assert!(
            note.starts_with("1 device-managed parameter octet differs from the model's image"),
            "{note}"
        );
        assert!(!note.starts_with("parameters not"), "{note}");
    }

    /// Issue #285: an internal ETS selector is named with its role and both
    /// values, and the plan says once what a differing selector means.
    #[test]
    fn test_octet_attributions_name_internal_selectors() {
        let selector = bussard_download::OctetOwner {
            key: "P-643".to_string(),
            name: "_AppInstanz 51".to_string(),
            role: OctetRole::Internal,
            device: Some("3".to_string()),
            model: Some("no application".to_string()),
            enumerated: true,
            segment_fill: None,
        };
        let runs = octet_attributions(
            None,
            &[OctetRange {
                segment: "M-0004_A-D142-21-8848-O000A_RS-04-00000".to_string(),
                offset: 165,
                length: 1,
                owners: vec![selector],
            }],
            true,
            TargetLabel::Model,
        );
        assert_eq!(
            runs[0].sentence,
            "1 octet at offset 165 of segment RS-04-00000: _AppInstanz 51 (internal ETS \
             selector, P-643), device 3, model no application"
        );
        assert_eq!(runs[0].explanation.as_deref(), Some(INTERNAL_SELECTOR_NOTE));
        assert_eq!(runs[0].parameters[0].role, OctetRole::Internal);
        let notes = octet_notes(1, 0, &runs);
        assert_eq!(notes.len(), 3, "{notes:?}");
        assert_eq!(notes[1], runs[0].sentence);
        assert_eq!(notes[2], INTERNAL_SELECTOR_NOTE);
    }

    /// Issues #289, #290 (1.1.18): a selector the Dynamic does not reach is
    /// an octet ETS does not write, and the plan does not write it either:
    /// the run is listed with `written: false`, its sentence and explanation
    /// say ETS does not write it and the device's value is left from an
    /// earlier state, and only the unwritten note names it.
    #[test]
    fn test_octet_attributions_explain_an_unreached_selector() {
        let selector = bussard_download::OctetOwner {
            key: "P-643".to_string(),
            name: "_AppInstanz 51".to_string(),
            role: OctetRole::Internal,
            device: Some("3".to_string()),
            model: Some("no application".to_string()),
            enumerated: true,
            segment_fill: Some(0x00),
        };
        assert!(!selector.internal_selector_differs());
        assert!(selector.unwritten_differs());
        let runs = octet_attributions(
            None,
            &[OctetRange {
                segment: "M-0004_A-D142-21-8848-O000A_RS-04-00000".to_string(),
                offset: 165,
                length: 1,
                owners: vec![selector],
            }],
            false,
            TargetLabel::Model,
        );
        let want = "ETS does not write this octet in a download; a full download leaves the \
                    segment fill (0x00) there; the device holds 3 from an earlier state";
        assert!(!runs[0].written);
        assert_eq!(runs[0].explanation.as_deref(), Some(want));
        assert_eq!(
            runs[0].sentence,
            "1 octet at offset 165 of segment RS-04-00000, not written (ETS does not write this \
             octet in a download): _AppInstanz 51 (internal ETS selector, P-643), device 3, model \
             no application"
        );
        assert!(octet_notes(1, 0, &runs).is_empty());
        assert!(!device_managed_only(&runs));
        let note = unwritten_note_for(&runs).unwrap_or_default();
        assert!(
            note.starts_with(
                "1 parameter octet differs from the model's image where no parameter the \
                 configuration reaches is placed; ETS does not write it in a download"
            ),
            "{note}"
        );
        assert!(note.contains(&runs[0].sentence), "{note}");
    }

    #[test]
    fn test_order_refs_normalizes() {
        let mut cat = catalog(&["M-0083_A-0001-10-0000"]);
        cat.hardware.order_to_apps.insert(
            "AKK-0216.03".to_string(),
            vec!["M-0083_A-0001-10-0000".to_string()],
        );
        assert_eq!(
            order_refs(&cat, " akk-0216.03 "),
            vec!["M-0083_A-0001-10-0000".to_string()]
        );
        assert!(order_refs(&cat, "OTHER").is_empty());
    }

    #[test]
    fn test_select_id_same_program_other_hash() {
        let cat = catalog(&["M-0004_A-A011-13-400D-O000A"]);
        assert_eq!(
            select_id(&cat, "M-0004_A-A011-13-60BC-O000A"),
            Some("M-0004_A-A011-13-400D-O000A".to_string())
        );
    }

    #[test]
    fn test_group_object_refusal_names_the_flash() -> Result<(), Box<dyn std::error::Error>> {
        let text = group_object_refusal("1.1.201".parse()?, "shows object(s) 35, 36");
        assert!(text.contains("(shows object(s) 35, 36)"), "{text}");
        assert!(
            text.contains(
                "A parameter that shows or hides com-objects needs a full `bussard flash 1.1.201`."
            ),
            "{text}"
        );
        Ok(())
    }
}
