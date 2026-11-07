//! The product models under `<model dir>/.bussard/model-cache/` (issues #228,
//! #906): one JSON file per application program, built from the archives
//! `bussard.lock` pins under `products/`.
//!
//! [`product_model`] builds the model of one parsed application program;
//! [`write_product_models`] writes them for parsed product data (what
//! `import-product` and `import` do). [`complete_models`] fills in the ones
//! the lock's devices pin that are missing or outdated, from the pinned
//! archives through the parsed-product cache. Every surface runs it before
//! it reads the model: the CLI before each command, the MCP and `viz`
//! servers at start and on every model reload (issue #267). An empty or
//! partly deleted `.bussard/` therefore heals on its own; only an
//! application no stored archive carries needs `bussard import-product`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bussard_model::dynamic::EnumValue;
use bussard_model::lock_products::{LockPins, lock_pins};
use bussard_model::param_model::{
    DataSecureCapacity, ObjectDef, ParamDef, ParamKind, ProductModel, RefDef,
    product_model_is_current,
};
use bussard_model::schema::ProductEntry;

use crate::dynamic::{DynamicNode, DynamicSource, Union, UnionMember};
use crate::{AppSelection, ApplicationProgram, ParameterType, ProductData, ResolvedComObject};

/// The environment variable that disables the parsed-product cache (`off`,
/// `0` or `false`).
pub const CACHE_ENV: &str = "BUSSARD_PRODUCT_CACHE";

/// An error writing or regenerating product models.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    /// A pinned archive is not in the model directory.
    #[error("{0}")]
    Missing(String),
    /// A pinned archive's content is not the one the lock pins.
    #[error("{0}")]
    Changed(String),
    /// Reading or writing a file failed.
    #[error("{what} {path}: {source}")]
    Io {
        /// What was being done (`writing`, `hashing`, ...).
        what: &'static str,
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The archive could not be parsed.
    #[error("reading product data from {path}: {source}")]
    Read {
        /// The archive.
        path: PathBuf,
        /// The underlying error.
        source: crate::ProductError,
    },
}

/// The parsed-product cache directory for the model at `dir`, or `None` when
/// there is no model directory or [`CACHE_ENV`] disables the cache.
pub fn cache_dir(dir: &Path) -> Option<PathBuf> {
    let disabled = bussard_model::dotenv::var(CACHE_ENV).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false"
        )
    });
    (!disabled && dir.is_dir()).then(|| dir.join(".bussard").join("products"))
}

/// The refusal for a pinned archive that is missing, with the lock's record
/// and the way to get it back.
pub fn missing_archive_message(what: &str, entry: &ProductEntry) -> String {
    let order = entry.order_numbers.first().map(String::as_str);
    let file = entry.file.as_deref().unwrap_or("(not extracted yet)");
    let label = match order {
        Some(order) => format!("{order}, {file}"),
        None => file.to_string(),
    };
    format!(
        "product data for {what} ({label}, sha256 {}) is missing; {}",
        short(&entry.sha256),
        bussard_model::lock_products::recovery_hint(entry)
    )
}

/// The refusal for an archive whose SHA-256 (`found`) is not the one the
/// lock pins for it.
pub fn archive_changed_message(archive: &Path, found: &str, entry: &ProductEntry) -> String {
    format!(
        "{} has sha256 {found} but bussard.lock pins {} for it: the product data \
         changed since it was pinned. Re-pin it with `bussard import-product {}` (a \
         reviewable lock change), or pass --product <FILE> to use a file explicitly",
        archive.display(),
        entry.sha256,
        archive.display()
    )
}

/// The first 12 hex digits of a hash, for messages.
fn short(sha: &str) -> String {
    if sha.len() > 12 {
        format!("{}…", &sha[..12])
    } else {
        sha.to_string()
    }
}

/// Refuses an archive whose content is not the one `entry` pins. An entry
/// for an ETS export pins no archive in the model, so there is nothing to
/// compare.
///
/// # Errors
///
/// [`ModelError::Changed`], or [`ModelError::Io`] when hashing fails.
pub fn verify_archive(archive: &Path, entry: &ProductEntry) -> Result<(), ModelError> {
    if entry.file.is_none() {
        return Ok(());
    }
    let (sha256, _) =
        bussard_model::sha256_file_cached(archive).map_err(|source| ModelError::Io {
            what: "hashing",
            path: archive.to_path_buf(),
            source,
        })?;
    if !sha256.eq_ignore_ascii_case(&entry.sha256) {
        return Err(ModelError::Changed(archive_changed_message(
            archive, &sha256, entry,
        )));
    }
    Ok(())
}

/// The archive `entry` pins, verified: its path when the file is in `dir`
/// and its SHA-256 is the pinned one. `what` names the device or product in
/// the refusal.
///
/// # Errors
///
/// [`ModelError::Missing`] (the file is absent or the entry names none),
/// [`ModelError::Changed`] (its content changed), or [`ModelError::Io`].
pub fn verified_archive(
    dir: &Path,
    what: &str,
    entry: &ProductEntry,
) -> Result<PathBuf, ModelError> {
    let Some(file) = entry.file.as_deref() else {
        return Err(ModelError::Missing(missing_archive_message(what, entry)));
    };
    let path = dir.join(file);
    if !path.is_file() {
        return Err(ModelError::Missing(missing_archive_message(what, entry)));
    }
    verify_archive(&path, entry)?;
    Ok(path)
}

/// Whether an application a device in the lock pins lacks its model, or has
/// one of an older [`bussard_model::param_model::MODEL_FORMAT`]: the head of
/// each pinned application's model file is read, no archive. Only the
/// applications [`complete_models`] writes count, so the two agree. `false`
/// when there is no lock.
pub fn models_incomplete(dir: &Path) -> bool {
    if !dir.join(bussard_model::loader::LOCK_FILE).is_file() {
        return false;
    }
    let pins = lock_pins(dir);
    pins.products.iter().filter(|e| e.file.is_some()).any(|e| {
        pinned_in(e, &pins)
            .iter()
            .any(|app| !product_model_is_current(dir, app))
    })
}

/// Whether the archive of `entry` carries `app` as far as the lock knows: an
/// entry that lists its applications carries those, one that lists none
/// carries what the devices linked to it pin.
fn carries(entry: &ProductEntry, pins: &LockPins, app: &str) -> bool {
    if entry.applications.is_empty() {
        let sha = entry.sha256.to_ascii_lowercase();
        pins.devices
            .iter()
            .any(|d| d.application == app && d.product_sha256.as_deref() == Some(sha.as_str()))
    } else {
        entry.applications.iter().any(|a| a == app)
    }
}

/// The applications of `entry`'s archive a device in the lock pins: the
/// product models the model directory needs from it (issue #356). The model
/// load reads no other.
fn pinned_in(entry: &ProductEntry, pins: &LockPins) -> BTreeSet<String> {
    pins.devices
        .iter()
        .filter(|d| carries(entry, pins, &d.application))
        .map(|d| d.application.clone())
        .collect()
}

/// Which models [`complete`] writes.
#[derive(Clone, Copy)]
enum Wanted<'a> {
    /// The pinned applications, or only this one.
    Pinned(Option<&'a str>),
    /// Every application of every pinned archive.
    All,
}

/// Writes the product model of every application a device in the lock pins
/// that `.bussard/model-cache/` lacks or holds in an older format, or only of
/// `only` when given (an application a pinned archive carries, pinned by a
/// device or not). Each archive is parsed once, and only for the programs it
/// has to write (with their `Hardware2Program` companions, see
/// [`AppSelection::Exact`]); an archive whose pinned applications all have a
/// current model is not read. Applications no device pins get no model
/// (issue #356): a 159 MB archive with 407 programs costs one program parse,
/// not 407. [`complete_all_models`] writes every application.
///
/// Returns one message per archive that could not be used (missing, changed,
/// unreadable). The caller reports them as warnings, since the command
/// itself says what it cannot do without the model.
///
/// The archives are parsed in the language the model's device files carry
/// their enum labels in ([`bussard_model::import_language`]: the lock's
/// `language`), as `import-product` reads them; a model written in another
/// language would not know those labels (E017, issue #255). The
/// parsed-product cache keys programs by that language.
pub fn complete_models(dir: &Path, only: Option<&str>) -> Vec<String> {
    complete(dir, Wanted::Pinned(only))
}

/// [`complete_models`] for every application program of every archive the
/// lock pins that lacks a current model, pinned by a device or not: the
/// behaviour before issue #356, for a caller that needs the whole product
/// family. An archive whose listed applications all have a current model is
/// not read.
pub fn complete_all_models(dir: &Path) -> Vec<String> {
    complete(dir, Wanted::All)
}

/// [`complete_models`] and [`complete_all_models`].
fn complete(dir: &Path, wanted: Wanted<'_>) -> Vec<String> {
    // A model of an older format regenerates too (issue #298).
    let has_current = |app: &str| product_model_is_current(dir, app);
    let language = bussard_model::import_language(dir);
    let cache = cache_dir(dir);
    let pins = lock_pins(dir);
    // Applications written from an earlier entry: two archives that carry
    // the same application write its model once.
    let mut done: BTreeSet<String> = BTreeSet::new();
    let mut warnings = Vec::new();
    for entry in pins.products.iter().filter(|e| e.file.is_some()) {
        // The models to write (`None`: every program the archive holds).
        let needed = match wanted {
            Wanted::Pinned(only) => {
                let apps: BTreeSet<String> = match only {
                    Some(app) if carries(entry, &pins, app) => BTreeSet::from([app.to_string()]),
                    Some(_) => BTreeSet::new(),
                    None => pinned_in(entry, &pins),
                };
                let needed: Vec<String> = apps
                    .into_iter()
                    .filter(|a| !done.contains(a) && !has_current(a))
                    .collect();
                if needed.is_empty() {
                    continue;
                }
                Some(needed)
            }
            Wanted::All => {
                let apps = &entry.applications;
                if !apps.is_empty() && apps.iter().all(|a| has_current(a)) {
                    continue;
                }
                None
            }
        };
        let what = entry
            .filename
            .clone()
            .unwrap_or_else(|| entry.sha256.clone());
        let written = verified_archive(dir, &what, entry).and_then(|path| {
            let selection = match &needed {
                Some(ids) => AppSelection::Exact(ids.clone()),
                None => AppSelection::All,
            };
            let product = crate::read_knxprod_selected_in(
                &path,
                None,
                cache.as_deref(),
                language.as_deref(),
                |_| selection,
            )
            .map_err(|source| ModelError::Read {
                path: path.clone(),
                source,
            })?;
            match &needed {
                // The companion programs the selection parsed along are
                // attached to their application, not written as models.
                Some(ids) => write_models(&product, dir, |id| ids.iter().any(|a| a == id)),
                None => write_product_models(&product, dir),
            }
        });
        match written {
            Ok(files) => {
                let ids: BTreeSet<String> = files
                    .iter()
                    .filter_map(|f| f.strip_suffix(".json"))
                    .map(str::to_string)
                    .collect();
                // An application the lock says the archive carries, which it
                // does not: no model, and the next command would try again.
                for id in needed.iter().flatten() {
                    if !ids.contains(id) {
                        warnings.push(format!("{what} carries no application program {id}"));
                    }
                }
                done.extend(ids);
            }
            Err(err) => warnings.push(err.to_string()),
        }
    }
    warnings
}

/// Writes the product model of each application program of `product` under
/// `<dir>/.bussard/model-cache/` and returns the file names, sorted.
///
/// # Errors
///
/// A file cannot be written.
pub fn write_product_models(product: &ProductData, dir: &Path) -> Result<Vec<String>, ModelError> {
    write_models(product, dir, |_| true)
}

/// [`write_product_models`] for the programs whose id `keep` accepts.
fn write_models(
    product: &ProductData,
    dir: &Path,
    keep: impl Fn(&str) -> bool,
) -> Result<Vec<String>, ModelError> {
    let mut written: Vec<String> = Vec::new();
    for app in product.applications.iter().filter(|a| keep(&a.id)) {
        let path = bussard_model::param_model::model_cache_path(dir, &app.id);
        bussard_model::param_model::write_product_model(dir, product_model(app, product)).map_err(
            |source| ModelError::Io {
                what: "writing",
                path: path.clone(),
                source,
            },
        )?;
        written.push(format!("{}.json", app.id));
    }
    written.sort();
    Ok(written)
}

/// The product model of `app` (one of `product`'s applications): its
/// parameters and refs, com-objects and Dynamic section with app-relative
/// ids, what the views, the validator and the Dynamic evaluator read.
pub fn product_model(app: &ApplicationProgram, product: &ProductData) -> ProductModel {
    let prefix = format!("{}_", app.id);
    let relative = |id: &str| id.strip_prefix(&prefix).unwrap_or(id).to_string();
    let (parameters, parameter_refs) = parameters_for(app, &relative);
    let com_objects = com_objects_for(app);
    let com_object_refs = other_object_refs(app, &com_objects)
        .into_iter()
        .map(|(r, rc)| (r, object_def(&rc)))
        .collect();
    let mut model = ProductModel::default();
    model.bus_current_ma = bus_current_for(app, product);
    model.parameters = parameters;
    model.com_objects = com_objects
        .iter()
        .map(|(n, rc)| (*n, object_def(rc)))
        .collect();
    model.com_object_refs = com_object_refs;
    model.program_id = app.id.clone();
    model.data_secure = app.is_secure_enabled.then_some(DataSecureCapacity {
        group_key_table_entries: app.security_capacity.group_key_table_entries,
        individual_address_entries: app.security_capacity.individual_address_entries,
        p2p_key_table_entries: app.security_capacity.p2p_key_table_entries,
    });
    model.dynamic = app.dynamic.clone();
    model.module_dynamics = app
        .module_dynamics
        .iter()
        .map(|(def, body)| (def.clone(), body.clone()))
        .collect();
    model.unions = app
        .unions
        .iter()
        .map(|u| Union {
            size_bits: u.size_bits,
            memory: None,
            members: u
                .members
                .iter()
                .map(|m| UnionMember {
                    parameter: relative(&m.parameter),
                    offset: m.offset,
                    bit_offset: m.bit_offset,
                    is_default: m.is_default,
                })
                .collect(),
        })
        .collect();
    model.parameter_refs = parameter_refs;
    model.allocators = app
        .allocators
        .iter()
        .map(|(id, a)| (id.clone(), *a))
        .collect();
    model.argument_allocates = app
        .argument_allocates
        .iter()
        .map(|(id, n)| (id.clone(), *n))
        .collect();
    model.system_b = app
        .mask_version
        .as_deref()
        .is_some_and(bussard_model::param_model::is_system_b_mask);
    model.calculations = app.calculations.clone();
    model
}

/// The order numbers that map to this application program, sorted.
pub fn order_numbers_for(app: &ApplicationProgram, product: &ProductData) -> Vec<String> {
    let mut orders: Vec<String> = product
        .hardware
        .order_to_apps
        .iter()
        .filter(|(_, apps)| apps.iter().any(|a| a == &app.id))
        .map(|(order, _)| order.clone())
        .collect();
    orders.sort();
    orders.dedup();
    orders
}

/// The highest bus current declared for any order number that maps to this
/// application program, in mA.
///
/// One application can be served by several catalogue parts; taking the maximum
/// keeps the topology lint from under-reporting a line's draw.
fn bus_current_for(app: &ApplicationProgram, product: &ProductData) -> Option<u32> {
    order_numbers_for(app, product)
        .iter()
        .filter_map(|order| product.hardware.order_to_bus_current.get(order).copied())
        .max()
}

/// The resolved com-objects keyed by number. When two refs share a number, the
/// one with the lexicographically smallest ref id wins (deterministic).
fn com_objects_for(app: &ApplicationProgram) -> BTreeMap<u16, ResolvedComObject<'_>> {
    let mut map: BTreeMap<u16, ResolvedComObject<'_>> = BTreeMap::new();
    for rc in app.resolved_com_objects() {
        match map.get(&rc.number()) {
            Some(existing) if existing.cref.id <= rc.cref.id => {}
            _ => {
                map.insert(rc.number(), rc);
            }
        }
    }
    map
}

/// The com-object refs of the application's own Dynamic section whose
/// number `com_objects` describes through another ref, keyed by
/// app-relative ref id.
fn other_object_refs<'a>(
    app: &'a ApplicationProgram,
    com_objects: &BTreeMap<u16, ResolvedComObject<'_>>,
) -> BTreeMap<String, ResolvedComObject<'a>> {
    let mut out = BTreeMap::new();
    let prefix = format!("{}_", app.id);
    for reference in &dynamic_object_refs(&app.dynamic) {
        if out.contains_key(reference) {
            continue;
        }
        let full = format!("{prefix}{reference}");
        let Some(cref) = app.com_object_refs.get(&full) else {
            continue;
        };
        let Some(base) = app.com_objects.get(&cref.ref_id) else {
            continue;
        };
        let rc = ResolvedComObject { base, cref };
        if com_objects
            .get(&rc.number())
            .is_some_and(|m| m.cref.id == full)
        {
            continue;
        }
        out.insert(reference.clone(), rc);
    }
    out
}

/// The `<ComObjectRefRef>`s of `nodes` and everything nested in them, on
/// every branch (module bodies excluded: they are not walked from here).
fn dynamic_object_refs(nodes: &[DynamicNode]) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<&[DynamicNode]> = vec![nodes];
    while let Some(nodes) = stack.pop() {
        for node in nodes {
            match node {
                DynamicNode::ComObjectRefRef(reference) => out.push(reference.clone()),
                DynamicNode::Channel { children, .. }
                | DynamicNode::ParameterBlock { children, .. }
                | DynamicNode::Repeat { children, .. } => stack.push(children),
                DynamicNode::Choose { whens, .. } => {
                    stack.extend(whens.iter().map(|w| w.children.as_slice()));
                }
                DynamicNode::ParameterRefRef(_)
                | DynamicNode::Module { .. }
                | DynamicNode::Assign { .. } => {}
            }
        }
    }
    out
}

/// A com-object as a view shows it: the priority only where it is not Low,
/// the default of an object that declares none (issue #541).
fn object_def(rc: &ResolvedComObject<'_>) -> ObjectDef {
    ObjectDef {
        text: rc.text().map(str::to_string),
        function: rc
            .function_text()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        dpt: rc.dpt().map(|d| d.to_string()),
        flags: Some(rc.flags().to_string()),
        priority: Some(rc.priority()).filter(|p| *p != bussard_model::Priority::Low),
    }
}

/// The parameters by app-relative id, each with its own default and its
/// refs, and every ref by app-relative id (a ref's `Value` lives on the ref,
/// issue #345).
fn parameters_for(
    app: &ApplicationProgram,
    relative: &dyn Fn(&str) -> String,
) -> (BTreeMap<String, ParamDef>, BTreeMap<String, RefDef>) {
    let mut refs_by_param: BTreeMap<&str, Vec<&crate::ParameterRef>> = BTreeMap::new();
    for pref in app.parameter_refs.values() {
        refs_by_param
            .entry(pref.ref_id.as_str())
            .or_default()
            .push(pref);
    }
    let mut parameters = BTreeMap::new();
    let mut parameter_refs = BTreeMap::new();
    for param in app.parameters.values() {
        let id = relative(&param.id);
        let default = param.default.clone().filter(|s| !s.is_empty());
        let mut refs: Vec<String> = Vec::new();
        for pref in refs_by_param.get(param.id.as_str()).into_iter().flatten() {
            let reference = relative(&pref.id);
            refs.push(reference.clone());
            parameter_refs.insert(reference, ref_def(&id, param, pref, default.as_deref()));
        }
        refs.sort();
        let kind = param_type(app, param.parameter_type.as_deref());
        let enum_values: Vec<EnumValue> = match &kind {
            Some(ParameterType::Enum { values, .. }) => values
                .iter()
                .map(|v| EnumValue {
                    value: v.value,
                    text: v.text.clone(),
                    default_text: v.text.clone(),
                    translations: BTreeMap::new(),
                    id: None,
                    binary_value: None,
                })
                .collect(),
            _ => Vec::new(),
        };
        let def = ParamDef {
            kind: param_kind(app, kind),
            default,
            text: param.text.clone().filter(|t| !t.trim().is_empty()),
            labels: enum_values
                .iter()
                .map(|v| (v.value, v.text.clone()))
                .collect(),
            name: param.name.clone().filter(|n| !n.trim().is_empty()),
            refs,
            base_value: param.base_value.as_deref().map(relative),
            integer_width: DynamicSource::integer_width(app, &param.id),
            enum_values,
            initial_value: param.initial_value.clone(),
            is_virtual: DynamicSource::is_virtual(app, &param.id),
        };
        parameters.insert(id, def);
    }
    (parameters, parameter_refs)
}

/// The model entry of `pref`, a ref of `param` (app-relative `param_id`),
/// where the model gives `default` as the parameter's default: the ref's
/// `Value` where it differs from the parameter's own, and wherever the
/// model's `default` would not give the value the ref has (an empty `Value`
/// the model leaves out), so the evaluator reads every ref's value as the
/// XML gives it (issue #345).
fn ref_def(
    param_id: &str,
    param: &crate::Parameter,
    pref: &crate::ParameterRef,
    default: Option<&str>,
) -> RefDef {
    let effective = pref.value.as_deref().or(param.default.as_deref());
    let differs = pref.value.is_some() && pref.value != param.default;
    RefDef {
        parameter: param_id.to_string(),
        value: (differs || effective != default)
            .then(|| effective.map(str::to_string))
            .flatten(),
        internal: pref.access.as_deref().or(param.access.as_deref()) == Some("None"),
        text: pref.text.clone().filter(|_| pref.text != param.text),
    }
}

/// The declared shape of a parameter's `ParameterType`, if it resolves.
fn param_type<'a>(app: &'a ApplicationProgram, type_id: Option<&str>) -> Option<&'a ParameterType> {
    type_id
        .and_then(|id| app.parameter_types.get(id))
        .map(|decl| &decl.kind)
}

/// A parameter type as the model checks values against it; an unresolved
/// type is [`ParamKind::None`].
fn param_kind(app: &ApplicationProgram, kind: Option<&ParameterType>) -> ParamKind {
    match kind {
        None | Some(ParameterType::None) => ParamKind::None,
        Some(ParameterType::Int {
            min, max, signed, ..
        }) => ParamKind::Int {
            min: *min,
            max: *max,
            signed: *signed,
        },
        Some(ParameterType::Enum { values, .. }) => ParamKind::Enum {
            values: values.iter().map(|v| v.value).collect(),
        },
        Some(ParameterType::Text { size_bits }) => ParamKind::Text {
            len: size_bits.map(|b| (b / 8) as usize),
            encoding: app.text_parameter_encoding.clone(),
        },
        Some(ParameterType::Float { .. }) => ParamKind::Float,
        Some(ParameterType::Color { space }) => ParamKind::Color { space: *space },
        Some(ParameterType::Other { .. }) => ParamKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::schema::ProductOrigin;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn scratch(tag: &str) -> Result<PathBuf, std::io::Error> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-product-model-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// A model of application `app` without anything in it.
    fn empty_model(app: &str) -> ProductModel {
        let mut model = ProductModel::default();
        model.program_id = app.to_string();
        model
    }

    fn entry(sha256: &str, file: Option<&str>) -> ProductEntry {
        ProductEntry {
            sha256: sha256.to_string(),
            file: file.map(str::to_string),
            filename: None,
            size: None,
            origin: ProductOrigin::File {
                path: "x.knxprod".to_string(),
            },
            applications: Vec::new(),
            order_numbers: Vec::new(),
        }
    }

    /// Issue #537: a Data-Secure-capable application's model carries its
    /// table capacities; any other carries none.
    #[test]
    fn test_product_model_data_secure_capacity() {
        let mut app = ApplicationProgram {
            id: "M-00FA_A-0001-01-0000".to_string(),
            is_secure_enabled: true,
            ..ApplicationProgram::default()
        };
        app.security_capacity.group_key_table_entries = Some(1500);
        app.security_capacity.individual_address_entries = Some(64);
        let product = ProductData::default();
        assert_eq!(
            product_model(&app, &product).data_secure,
            Some(DataSecureCapacity {
                group_key_table_entries: Some(1500),
                individual_address_entries: Some(64),
                p2p_key_table_entries: None,
            })
        );
        app.is_secure_enabled = false;
        assert_eq!(product_model(&app, &product).data_secure, None);
    }

    #[test]
    fn test_verify_archive_refuses_a_changed_archive() -> TestResult {
        let dir = scratch("verify")?;
        let path = dir.join("x.knxprod");
        std::fs::write(&path, b"abc")?;
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify_archive(&path, &entry(abc, Some("products/x.knxprod"))).is_ok());
        let err = verify_archive(&path, &entry("00ff", Some("products/x.knxprod")))
            .err()
            .ok_or("a changed archive must be refused")?;
        let text = err.to_string();
        assert!(text.contains(abc) && text.contains("00ff"), "{text}");
        // An entry for an ETS export pins no archive in the model.
        assert!(verify_archive(&path, &entry("00ff", None)).is_ok());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_complete_models_warns_without_the_archive() -> TestResult {
        let dir = scratch("outdated")?;
        std::fs::write(
            dir.join(bussard_model::loader::LOCK_FILE),
            "version = 3\n\n[[product]]\nsha256 = \"00\"\nfile = \"products/a.knxprod\"\n\
             origin = { kind = \"file\", path = \"a.knxprod\" }\napplications = [\"M-1\"]\n\n\
             [[device]]\naddress = \"1.1.1\"\napplication = \"M-1\"\n",
        )?;
        // Missing: the absent archive is worth a warning.
        assert_eq!(complete_models(&dir, None).len(), 1);
        // Outdated: an old model is not read, so the same warning.
        let file = bussard_model::param_model::model_cache_path(&dir, "M-1");
        std::fs::create_dir_all(file.parent().ok_or("no parent")?)?;
        std::fs::write(&file, "{\"header\":{\"schema\":1}}")?;
        assert_eq!(complete_models(&dir, Some("M-1")).len(), 1);
        // Current: nothing to do.
        bussard_model::param_model::write_product_model(&dir, empty_model("M-1"))?;
        assert!(complete_models(&dir, None).is_empty());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_models_incomplete_checks_every_pinned_application() -> TestResult {
        let dir = scratch("incomplete")?;
        assert!(!models_incomplete(&dir), "no lock, nothing to complete");
        std::fs::write(
            dir.join(bussard_model::loader::LOCK_FILE),
            "version = 3\n\n[[product]]\nsha256 = \"00\"\nfile = \"products/a.knxprod\"\n\
             origin = { kind = \"file\", path = \"a.knxprod\" }\n\
             applications = [\"M-1\", \"M-2\", \"M-3\"]\n\n\
             [[device]]\naddress = \"1.1.1\"\napplication = \"M-1\"\n\n\
             [[device]]\naddress = \"1.1.2\"\napplication = \"M-2\"\n",
        )?;
        assert!(models_incomplete(&dir), "no models");
        let write =
            |app: &str| bussard_model::param_model::write_product_model(&dir, empty_model(app));
        write("M-1")?;
        assert!(models_incomplete(&dir), "one model of two");
        let m2 = bussard_model::param_model::model_cache_path(&dir, "M-2");
        std::fs::write(&m2, "{\"header\":{\"schema\":1}}")?;
        assert!(models_incomplete(&dir), "a model of an older format");
        write("M-2")?;
        // M-3 is in the archive, but no device pins it (issue #356).
        assert!(
            !models_incomplete(&dir),
            "every pinned application has its model"
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
