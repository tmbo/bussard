//! The product models under `<model dir>/.bussard/models/` (issue #228): one
//! machine-generated YAML file per application program, derived from the
//! archives `bussard.lock` pins under `products/`.
//!
//! [`write_product_models`] writes them from parsed product data (what
//! `import-product` and `import` do). [`complete_models`] fills in the ones
//! the lock's devices pin that are missing, from the pinned archives. Every surface runs it before it
//! reads the model: the CLI before each command, the MCP and `viz` servers at
//! start and on every model reload (issue #267). An empty or partly deleted
//! `.bussard/models/` therefore heals on its own; only an application no
//! stored archive carries needs `bussard import-product`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bussard_model::lock_products::{LockPins, lock_pins};
use bussard_model::schema::ProductEntry;
use serde::Serialize;

use crate::dynamic::{DynamicNode, DynamicSource, Union, UnionMember};
use crate::{
    AppSelection, ApplicationProgram, LoadOp, LoadProcedure, ParameterType, ProductData,
    ResolvedComObject,
};

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
        source: crate::ProdError,
    },
    /// A model did not serialize to YAML.
    #[error("serializing model to YAML: {0}")]
    Serialize(String),
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

/// Whether an application a device in the lock pins lacks its model file, or
/// has one of an older [`bussard_model::param_model::MODEL_FORMAT`]: the first
/// 4 KiB of each pinned application's model are read, no archive. Only the
/// applications [`complete_models`] writes count, so the two agree. `false`
/// when there is no lock.
pub fn models_incomplete(dir: &Path) -> bool {
    if !dir.join(bussard_model::loader::LOCK_FILE).is_file() {
        return false;
    }
    let models_dir = dir.join(bussard_model::param_model::MODELS_DIR);
    let pins = lock_pins(dir);
    pins.products.iter().filter(|e| e.file.is_some()).any(|e| {
        pinned_in(e, &pins).iter().any(|app| {
            !bussard_model::param_model::model_is_current(&models_dir.join(format!("{app}.yaml")))
        })
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
/// that `.bussard/models/` lacks or holds in an older format, or only of
/// `only` when given (an application a pinned archive carries, pinned by a
/// device or not). Each archive is parsed once, and only for the programs it
/// has to write (with their `Hardware2Program` companions, see
/// [`AppSelection::Exact`]); an archive whose pinned applications all have a
/// current model is not read. Applications no device pins get no model
/// (issue #356): a 159 MB archive with 407 programs costs one program parse,
/// not 407. [`complete_all_models`] writes every application.
///
/// Returns one message per archive that could not be used (missing, changed,
/// unreadable) for a model that is missing; an outdated model whose archive
/// cannot be read stays as it is, silently. The caller reports them as
/// warnings, since the command itself says what it cannot do without the
/// model.
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
    let models_dir = dir.join(bussard_model::param_model::MODELS_DIR);
    let _ = std::fs::create_dir_all(&models_dir);
    let has_model = |app: &str| models_dir.join(format!("{app}.yaml")).is_file();
    // A model of an older format regenerates too (issue #298), quietly when
    // its archive cannot be read: the old model still serves.
    let has_current = |app: &str| {
        bussard_model::param_model::model_is_current(&models_dir.join(format!("{app}.yaml")))
    };
    let language = bussard_model::import_language(dir);
    let cache = cache_dir(dir);
    let pins = lock_pins(dir);
    // Applications written from an earlier entry: two archives that carry
    // the same application write its model once.
    let mut done: BTreeSet<String> = BTreeSet::new();
    let mut warnings = Vec::new();
    for entry in pins.products.iter().filter(|e| e.file.is_some()) {
        // `needed`: the models to write (`None`: every program the archive
        // holds); `only_outdated`: each of them exists in an older format.
        let (needed, only_outdated) = match wanted {
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
                let outdated = needed.iter().all(|a| has_model(a));
                (Some(needed), outdated)
            }
            Wanted::All => {
                let apps = &entry.applications;
                if !apps.is_empty() && apps.iter().all(|a| has_current(a)) {
                    continue;
                }
                (None, !apps.is_empty() && apps.iter().all(|a| has_model(a)))
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
                    .filter_map(|f| f.strip_suffix(".yaml"))
                    .map(str::to_string)
                    .collect();
                // An application the lock says the archive carries, which it
                // does not: no model, and the next command would try again.
                for id in needed.iter().flatten() {
                    if !ids.contains(id) && !has_model(id) {
                        warnings.push(format!("{what} carries no application program {id}"));
                    }
                }
                done.extend(ids);
            }
            Err(err) if !only_outdated => warnings.push(err.to_string()),
            Err(_) => {}
        }
    }
    warnings
}

/// Writes one model file per application program under
/// `<dir>/.bussard/models/`, with each converted model's JSON cache under
/// `.bussard/model-cache/`, and returns the file names, sorted.
///
/// # Errors
///
/// A model does not serialize, or a file cannot be written.
pub fn write_product_models(product: &ProductData, dir: &Path) -> Result<Vec<String>, ModelError> {
    write_models(product, dir, |_| true)
}

/// [`write_product_models`] for the programs whose id `keep` accepts.
fn write_models(
    product: &ProductData,
    dir: &Path,
    keep: impl Fn(&str) -> bool,
) -> Result<Vec<String>, ModelError> {
    let models_dir = dir.join(bussard_model::param_model::MODELS_DIR);
    std::fs::create_dir_all(&models_dir).map_err(|source| ModelError::Io {
        what: "creating",
        path: models_dir.clone(),
        source,
    })?;
    let mut written: Vec<String> = Vec::new();
    for app in product.applications.iter().filter(|a| keep(&a.id)) {
        let yaml = model_yaml(app, product)?;
        let file_name = format!("{}.yaml", app.id);
        let path = models_dir.join(&file_name);
        std::fs::write(&path, &yaml).map_err(|source| ModelError::Io {
            what: "writing",
            path: path.clone(),
            source,
        })?;
        // The converted model's JSON cache, so the first load after an
        // import reads it instead of parsing the YAML (issue #339).
        bussard_model::param_model::cache_written_model(dir, &app.id, &yaml);
        written.push(file_name);
    }
    written.sort();
    Ok(written)
}

// The model YAML shape
// ---------------------------------------------------------------------------

/// The product model YAML of `app` (one of `product`'s applications), as
/// [`write_product_models`] writes it, banner included.
///
/// # Errors
///
/// The model does not serialize.
pub fn model_yaml(app: &ApplicationProgram, product: &ProductData) -> Result<String, ModelError> {
    serialize_model(&build_model(app, product))
}

/// The top-level model file for one application program.
#[derive(Debug, Serialize)]
struct Model<'a> {
    /// [`bussard_model::param_model::MODEL_FORMAT`]: a model of an older
    /// format regenerates.
    model_format: u32,
    identity: Identity,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    order_numbers: Vec<String>,
    /// The hardware's declared bus current in mA (`Hardware.xml` `BusCurrent`),
    /// read by the `L002` topology lint to total a line's draw.
    #[serde(skip_serializing_if = "Option::is_none")]
    bus_current_ma: Option<u32>,
    /// The Data Secure table capacities of a Data-Secure-capable application
    /// (issue #537); absent for any other.
    #[serde(skip_serializing_if = "Option::is_none")]
    data_secure: Option<bussard_model::param_model::DataSecureCapacity>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    com_objects: BTreeMap<u16, ComObjectModel>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parameters: Vec<ParameterModel>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    load_procedure: Vec<String>,
    /// The com-object refs of the Dynamic section that `com_objects` does
    /// not describe (a number's other refs, with their own text, function
    /// and DPT), keyed by app-relative ref id.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    com_object_refs: BTreeMap<String, ComObjectModel>,
    /// The `<Union>`s: size and member positions (issue #345).
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "bussard_model::dynamic_compact::unions::serialize"
    )]
    unions: Vec<Union>,
    /// The `<Allocator>`s by app-relative id (issue #449).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    allocators: BTreeMap<&'a str, bussard_model::dynamic::Allocator>,
    /// The module arguments' `Allocates` by app-relative id (issue #449).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    argument_allocates: BTreeMap<&'a str, i64>,
    /// The application's Dynamic section (issue #345), appended by
    /// [`serialize_model`] one flow-style node per line.
    #[serde(skip)]
    dynamic: &'a [DynamicNode],
    /// The module definitions' Dynamic sections by app-relative id, written
    /// the same way.
    #[serde(skip)]
    module_dynamics: BTreeMap<&'a str, &'a [DynamicNode]>,
}

/// The identity block.
#[derive(Debug, Serialize)]
struct Identity {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mask_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    load_procedure_style: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_version: Option<String>,
}

/// One com-object, keyed by number, in the same field style as the device
/// schema (dpt / flags / size-when-no-dpt).
#[derive(Debug, Serialize)]
struct ComObjectModel {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpt: Option<String>,
    flags: String,
    /// The object size, carried when there is no DPT to imply it.
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<String>,
    /// The transmission priority (ref overrides base), carried only when it
    /// is not Low, the default of an object that declares none (issue #541).
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<bussard_model::Priority>,
    /// The application ref id this com-object resolves through (stable handle).
    ref_id: String,
}

/// One parameter definition.
#[derive(Debug, Serialize)]
struct ParameterModel {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(rename = "type")]
    param_type: ParamTypeModel,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<MemoryModel>,
    /// A text parameter's `InitialValue`, translated (issue #473).
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_value: Option<String>,
    /// The `BaseValue` argument, app-relative (issue #126).
    #[serde(skip_serializing_if = "Option::is_none")]
    base_value: Option<String>,
    /// Width in bits of an integer or plain enumeration parameter: what a
    /// shared union memory is read back with.
    #[serde(skip_serializing_if = "Option::is_none")]
    bits: Option<u32>,
    /// Whether that integer is signed.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    signed: bool,
    /// The refs that point at this parameter, app-relative.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    refs: BTreeMap<String, RefModel>,
}

/// One `ParameterRef` of a parameter.
#[derive(Debug, Default, Serialize)]
struct RefModel {
    /// The ref's `Value`, where it differs from the parameter's `Value`, or
    /// where the model's `default` would not give it.
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    /// The effective `Access` is `None`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    internal: bool,
    /// The ref's own `Text`, where it differs from the parameter's: the
    /// title of a page the ref names (`ParamRefId`).
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

/// A parameter's type, tagged by shape.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ParamTypeModel {
    Int {
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u32>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        signed: bool,
    },
    Enum {
        values: Vec<EnumValueModel>,
    },
    Text {
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u32>,
        /// The program's `TextParameterEncoding` (issue #401).
        #[serde(skip_serializing_if = "Option::is_none")]
        encoding: Option<String>,
    },
    Float {
        #[serde(skip_serializing_if = "Option::is_none")]
        encoding: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
    },
    None,
    /// A `<TypeColor>` of a known space (format 11, issue #616).
    Color {
        space: bussard_ets::application::ColorSpace,
    },
    Other {
        kind: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u32>,
    },
}

/// One enum value/text pair.
#[derive(Debug, Serialize)]
struct EnumValueModel {
    value: i64,
    text: String,
}

/// A parameter's memory location.
#[derive(Debug, Serialize)]
struct MemoryModel {
    #[serde(skip_serializing_if = "Option::is_none")]
    segment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bit_offset: Option<u8>,
}

/// Builds the model for one application program.
fn build_model<'a>(app: &'a ApplicationProgram, product: &ProductData) -> Model<'a> {
    let com_objects = com_objects_for(app);
    let com_object_refs = other_object_refs(app, &com_objects);
    Model {
        model_format: bussard_model::param_model::MODEL_FORMAT,
        identity: Identity {
            id: app.id.clone(),
            name: app.name.clone(),
            application_number: app.application_number,
            application_version: app.application_version,
            mask_version: app.mask_version.clone(),
            load_procedure_style: app.load_procedure_style.clone(),
            schema_version: app.schema_version.clone(),
        },
        order_numbers: order_numbers_for(app, product),
        bus_current_ma: bus_current_for(app, product),
        data_secure: app.is_secure_enabled.then_some(
            bussard_model::param_model::DataSecureCapacity {
                group_key_table_entries: app.security_capacity.group_key_table_entries,
                individual_address_entries: app.security_capacity.individual_address_entries,
                p2p_key_table_entries: app.security_capacity.p2p_key_table_entries,
            },
        ),
        com_objects,
        parameters: parameters_for(app),
        load_procedure: load_procedure_summary(&app.load_procedures),
        com_object_refs,
        unions: unions_for(app),
        allocators: app
            .allocators
            .iter()
            .map(|(id, a)| (id.as_str(), *a))
            .collect(),
        argument_allocates: app
            .argument_allocates
            .iter()
            .map(|(id, n)| (id.as_str(), *n))
            .collect(),
        dynamic: &app.dynamic,
        module_dynamics: app
            .module_dynamics
            .iter()
            .map(|(def, body)| (def.as_str(), body.as_slice()))
            .collect(),
    }
}

/// The application's unions with app-relative member ids.
fn unions_for(app: &ApplicationProgram) -> Vec<Union> {
    let prefix = format!("{}_", app.id);
    app.unions
        .iter()
        .map(|u| Union {
            size_bits: u.size_bits,
            memory: None,
            members: u
                .members
                .iter()
                .map(|m| UnionMember {
                    parameter: m
                        .parameter
                        .strip_prefix(&prefix)
                        .unwrap_or(&m.parameter)
                        .to_string(),
                    offset: m.offset,
                    bit_offset: m.bit_offset,
                    is_default: m.is_default,
                })
                .collect(),
        })
        .collect()
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
/// one with the lexicographically smallest ref id wins (deterministic); this is
/// rare and the ref id disambiguates in the output.
fn com_objects_for(app: &ApplicationProgram) -> BTreeMap<u16, ComObjectModel> {
    let mut map: BTreeMap<u16, ComObjectModel> = BTreeMap::new();
    for rc in app.resolved_com_objects() {
        let number = rc.number();
        let candidate = com_object_model(&rc);
        match map.get(&number) {
            Some(existing) if existing.ref_id <= candidate.ref_id => {}
            _ => {
                map.insert(number, candidate);
            }
        }
    }
    map
}

/// The com-object refs of the application's own Dynamic section whose
/// number `com_objects` describes through another ref, keyed by
/// app-relative ref id.
fn other_object_refs(
    app: &ApplicationProgram,
    com_objects: &BTreeMap<u16, ComObjectModel>,
) -> BTreeMap<String, ComObjectModel> {
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
            .is_some_and(|m| m.ref_id == full)
        {
            continue;
        }
        out.insert(reference.clone(), com_object_model(&rc));
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

fn com_object_model(rc: &ResolvedComObject<'_>) -> ComObjectModel {
    let dpt = rc.dpt().map(|d| d.to_string());
    ComObjectModel {
        text: rc.text().map(str::to_string),
        function_text: rc
            .function_text()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        dpt: dpt.clone(),
        flags: rc.flags().to_string(),
        // Carry size only when no DPT implies it, matching the device schema.
        size: if dpt.is_none() {
            rc.object_size().map(str::to_string)
        } else {
            None
        },
        priority: Some(rc.priority()).filter(|p| *p != bussard_model::Priority::Low),
        ref_id: rc.cref.id.clone(),
    }
}

/// The parameters, sorted by id, each with its own default and its refs
/// (a ref's `Value` lives on the ref, issue #345).
fn parameters_for(app: &ApplicationProgram) -> Vec<ParameterModel> {
    // Index refs by the parameter they point at.
    let mut refs_by_param: BTreeMap<&str, Vec<&crate::ParameterRef>> = BTreeMap::new();
    for pref in app.parameter_refs.values() {
        refs_by_param
            .entry(pref.ref_id.as_str())
            .or_default()
            .push(pref);
    }

    let prefix = format!("{}_", app.id);
    let mut out: Vec<ParameterModel> = app
        .parameters
        .values()
        .map(|param| {
            let default = param.default.clone().filter(|s| !s.is_empty());
            let width = DynamicSource::integer_width(app, &param.id);
            let refs = refs_by_param
                .get(param.id.as_str())
                .into_iter()
                .flatten()
                .map(|pref| {
                    let id = pref.id.strip_prefix(&prefix).unwrap_or(&pref.id);
                    (id.to_string(), ref_model(param, pref, default.as_deref()))
                })
                .collect();
            ParameterModel {
                id: param.id.clone(),
                name: param.name.clone().filter(|s| !s.is_empty()),
                text: param.text.clone().filter(|s| !s.is_empty()),
                param_type: param_type_model(app, param.parameter_type.as_deref()),
                default,
                memory: param.memory.as_ref().map(|m| MemoryModel {
                    segment: m.code_segment.clone(),
                    offset: m.offset,
                    bit_offset: m.bit_offset,
                }),
                initial_value: param.initial_value.clone(),
                base_value: param
                    .base_value
                    .as_deref()
                    .map(|b| b.strip_prefix(&prefix).unwrap_or(b).to_string()),
                bits: width.map(|(bits, _)| bits),
                signed: width.is_some_and(|(_, signed)| signed),
                refs,
            }
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// The model entry of `pref`, a ref of `param`, where the model writes
/// `default` as the parameter's default: the ref's `Value` where it differs
/// from the parameter's own, and wherever the model's `default` would not
/// give the value the ref has (an empty `Value` the model leaves out), so
/// the evaluator reads every ref's value as the XML gives it (issue #345).
fn ref_model(
    param: &crate::Parameter,
    pref: &crate::ParameterRef,
    default: Option<&str>,
) -> RefModel {
    let effective = pref.value.as_deref().or(param.default.as_deref());
    let differs = pref.value.is_some() && pref.value != param.default;
    RefModel {
        value: (differs || effective != default)
            .then(|| effective.map(str::to_string))
            .flatten(),
        internal: pref.access.as_deref().or(param.access.as_deref()) == Some("None"),
        text: pref.text.clone().filter(|_| pref.text != param.text),
    }
}

/// Resolves a parameter's `ParameterType` ref to its model shape.
fn param_type_model(app: &ApplicationProgram, type_id: Option<&str>) -> ParamTypeModel {
    let Some(decl) = type_id.and_then(|id| app.parameter_types.get(id)) else {
        return ParamTypeModel::None;
    };
    match &decl.kind {
        ParameterType::Int {
            size_bits,
            min,
            max,
            signed,
        } => ParamTypeModel::Int {
            min: *min,
            max: *max,
            size: *size_bits,
            signed: *signed,
        },
        ParameterType::Enum { values, .. } => ParamTypeModel::Enum {
            values: values
                .iter()
                .map(|v| EnumValueModel {
                    value: v.value,
                    text: v.text.clone(),
                })
                .collect(),
        },
        ParameterType::Text { size_bits } => ParamTypeModel::Text {
            size: *size_bits,
            encoding: app.text_parameter_encoding.clone(),
        },
        ParameterType::Float { encoding, min, max } => ParamTypeModel::Float {
            encoding: encoding.clone(),
            min: *min,
            max: *max,
        },
        ParameterType::None => ParamTypeModel::None,
        ParameterType::Color { space } => ParamTypeModel::Color { space: *space },
        ParameterType::Other {
            kind, size_bits, ..
        } => ParamTypeModel::Other {
            kind: kind.clone(),
            size: *size_bits,
        },
    }
}

/// A flat, ordered op-list summary of the load procedures.
fn load_procedure_summary(procedures: &[LoadProcedure]) -> Vec<String> {
    let mut out = Vec::new();
    for lp in procedures {
        for op in &lp.ops {
            out.push(load_op_summary(op));
        }
    }
    out
}

/// A stable one-line summary of a load op, faithful to the parsed variant.
fn load_op_summary(op: &LoadOp) -> String {
    match op {
        LoadOp::Connect => "connect".to_string(),
        LoadOp::Disconnect => "disconnect".to_string(),
        LoadOp::Restart => "restart".to_string(),
        LoadOp::Delay { milliseconds } => format!("delay ms={}", opt(milliseconds)),
        LoadOp::Merge { merge_id } => {
            format!("merge id={}", merge_id.as_deref().unwrap_or("?"))
        }
        LoadOp::MasterReset {
            erase_code,
            channel_number,
        } => format!(
            "master_reset erase_code={} channel={}",
            opt(erase_code),
            opt(channel_number)
        ),
        LoadOp::Unload { lsm_idx } => format!("unload lsm={}", opt(lsm_idx)),
        LoadOp::Load { lsm_idx } => format!("load lsm={}", opt(lsm_idx)),
        LoadOp::LoadCompleted { lsm_idx } => format!("load_completed lsm={}", opt(lsm_idx)),
        LoadOp::TaskSegment { lsm_idx, address } => {
            format!("task_segment lsm={} addr={}", opt(lsm_idx), opt(address))
        }
        LoadOp::TaskCtrl1 {
            lsm_idx,
            address,
            count,
        } => format!(
            "task_ctrl1 lsm={} addr={} count={}",
            opt(lsm_idx),
            opt(address),
            opt(count)
        ),
        LoadOp::TaskPtr {
            lsm_idx,
            init_ptr,
            save_ptr,
            serial_ptr,
        } => format!(
            "task_ptr lsm={} init={} save={} serial={}",
            opt(lsm_idx),
            opt(init_ptr),
            opt(save_ptr),
            opt(serial_ptr)
        ),
        LoadOp::TaskCtrl2 {
            lsm_idx,
            callback,
            address,
            seg0,
            seg1,
        } => format!(
            "task_ctrl2 lsm={} callback={} addr={} seg0={} seg1={}",
            opt(lsm_idx),
            opt(callback),
            opt(address),
            opt(seg0),
            opt(seg1)
        ),
        LoadOp::RelSegment {
            lsm_idx,
            size,
            applies_to,
            fill,
        } => format!(
            "rel_segment lsm={} size={} applies_to={} fill={}",
            opt(lsm_idx),
            opt(size),
            applies_to.as_deref().unwrap_or("-"),
            match (fill.mode, fill.fill) {
                (0, 0) => "-".to_string(),
                (1, b) => format!("0x{b:02X}"),
                (m, b) => format!("mode={m}:0x{b:02X}"),
            }
        ),
        LoadOp::AbsSegment {
            lsm_idx,
            address,
            size,
            access,
            mem_type,
            seg_flags,
            ..
        } => format!(
            "abs_segment lsm={} addr={} size={} access={} mem_type={} seg_flags={}",
            opt(lsm_idx),
            opt(address),
            opt(size),
            opt(access),
            opt(mem_type),
            opt(seg_flags)
        ),
        LoadOp::WriteRelMem {
            obj_idx,
            offset,
            size,
            applies_to,
        } => format!(
            "write_rel_mem obj={} offset={} size={} applies_to={}",
            opt(obj_idx),
            opt(offset),
            opt(size),
            applies_to.as_deref().unwrap_or("-")
        ),
        LoadOp::WriteMem { address, size } => {
            format!("write_mem addr={} size={}", opt(address), opt(size))
        }
        LoadOp::WriteProp {
            obj_idx,
            obj_type,
            prop_id,
            inline_data,
            ..
        } => {
            let data = inline_data
                .as_ref()
                .map(|d| format!(" data={}", hex(d)))
                .unwrap_or_default();
            format!(
                "write_prop obj_idx={} obj_type={} prop_id={}{data}",
                opt(obj_idx),
                opt(obj_type),
                opt(prop_id),
            )
        }
        LoadOp::CompareProp {
            obj_idx,
            obj_type,
            prop_id,
            inline_data,
            mask,
            range,
            ..
        } => {
            let expected = match (inline_data, range) {
                (Some(d), _) => format!("data={}", hex(d)),
                (None, Some(r)) => format!("range={r}"),
                (None, None) => "-".to_string(),
            };
            let mask = mask
                .as_ref()
                .map(|m| format!(" mask={}", hex(m)))
                .unwrap_or_default();
            format!(
                "compare_prop obj_idx={} obj_type={} prop_id={} {expected}{mask}",
                opt(obj_idx),
                opt(obj_type),
                opt(prop_id),
            )
        }
        LoadOp::CompareRelMem {
            obj_idx,
            offset,
            size,
            inline_data,
            mask,
            invert,
        } => {
            let expected = inline_data
                .as_ref()
                .map(|d| format!("data={}", hex(d)))
                .unwrap_or_else(|| "-".to_string());
            let mask = mask
                .as_ref()
                .map(|m| format!(" mask={}", hex(m)))
                .unwrap_or_default();
            let invert = if *invert { " invert=true" } else { "" };
            format!(
                "compare_rel_mem obj_idx={} offset={} size={} {expected}{mask}{invert}",
                opt(obj_idx),
                opt(offset),
                opt(size),
            )
        }
        LoadOp::LoadImageProp {
            obj_idx,
            obj_type,
            occurrence,
            prop_id,
            count,
        } => format!(
            "load_image_prop obj_idx={} obj_type={} occurrence={} prop_id={} count={}",
            opt(obj_idx),
            opt(obj_type),
            opt(occurrence),
            opt(prop_id),
            opt(count)
        ),
        LoadOp::MapError {
            original_error,
            mapped_error,
        } => {
            let code =
                |c: &Option<u32>| c.map_or_else(|| "-".to_string(), |c| format!("{c:#010X}"));
            format!(
                "map_error original={} mapped={}",
                code(original_error),
                code(mapped_error)
            )
        }
        LoadOp::Raw { name, attrs } => {
            let joined: Vec<String> = attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("raw {name} [{}]", joined.join(" "))
        }
    }
}

/// Renders bytes as a lower-case hex string for a load-procedure trace line.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    v.as_ref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// Serializes a model to YAML, prefixed with the generated-file banner. The
/// Dynamic trees come last, each node of their top level on a line of its
/// own in flow style (see
/// [`bussard_model::dynamic_compact::write_flow_lines`]).
fn serialize_model(model: &Model) -> Result<String, ModelError> {
    let body = serde_norway::to_string(model).map_err(|e| ModelError::Serialize(e.to_string()))?;
    let mut out = format!("{MODEL_BANNER}{body}");
    let flow = |e: serde_json::Error| ModelError::Serialize(e.to_string());
    if !model.dynamic.is_empty() {
        out.push_str("dynamic:\n");
        bussard_model::dynamic_compact::write_flow_lines(model.dynamic, "", &mut out)
            .map_err(flow)?;
    }
    if !model.module_dynamics.is_empty() {
        out.push_str("module_dynamics:\n");
        for (def, body) in &model.module_dynamics {
            if body.is_empty() {
                out.push_str(&format!("  {def}: []\n"));
                continue;
            }
            out.push_str(&format!("  {def}:\n"));
            bussard_model::dynamic_compact::write_flow_lines(body, "  ", &mut out).map_err(flow)?;
        }
    }
    Ok(out)
}

/// The banner prefixed to each generated model file (same voice as the
/// `bussard-model` loader banners).
const MODEL_BANNER: &str = "\
# Product model (generated by `bussard import-product`).
#
# Machine-generated from vendor `.knxprod` product data — do not hand-edit; it
# is regenerated on the next import and edits are lost. This describes one
# application program: its identity, com-objects, parameters and the load
# procedure used to download it. Regenerated data under .bussard/: derived from
# the archive under products/, rebuilt whenever it is missing.
# Docs: https://github.com/tmbo/bussard/blob/main/dev/product-model-format.md
";

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
    /// table capacities and reads them back; any other carries none.
    #[test]
    fn test_model_yaml_data_secure_capacity_round_trip() -> TestResult {
        let mut app = ApplicationProgram {
            id: "M-00FA_A-0001-01-0000".to_string(),
            is_secure_enabled: true,
            ..ApplicationProgram::default()
        };
        app.security_capacity.group_key_table_entries = Some(1500);
        app.security_capacity.individual_address_entries = Some(64);
        let product = ProductData::default();
        let yaml = model_yaml(&app, &product)?;
        assert!(yaml.contains("data_secure:"), "{yaml}");
        let model = bussard_model::param_model::ProductModel::from_yaml(&yaml, &app.id)?;
        assert_eq!(
            model.data_secure,
            Some(bussard_model::param_model::DataSecureCapacity {
                group_key_table_entries: Some(1500),
                individual_address_entries: Some(64),
                p2p_key_table_entries: None,
            })
        );
        app.is_secure_enabled = false;
        let plain = model_yaml(&app, &product)?;
        assert!(!plain.contains("data_secure"));
        let model = bussard_model::param_model::ProductModel::from_yaml(&plain, &app.id)?;
        assert_eq!(model.data_secure, None);
        Ok(())
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
    fn test_complete_models_keeps_an_outdated_model_quietly_without_its_archive() -> TestResult {
        let dir = scratch("outdated")?;
        std::fs::write(
            dir.join(bussard_model::loader::LOCK_FILE),
            "version = 3\n\n[[product]]\nsha256 = \"00\"\nfile = \"products/a.knxprod\"\n\
             origin = { kind = \"file\", path = \"a.knxprod\" }\napplications = [\"M-1\"]\n\n\
             [[device]]\naddress = \"1.1.1\"\napplication = \"M-1\"\n",
        )?;
        let models = dir.join(bussard_model::param_model::MODELS_DIR);
        std::fs::create_dir_all(&models)?;
        // Missing: the absent archive is worth a warning.
        assert_eq!(complete_models(&dir, None).len(), 1);
        // Outdated: the old model still serves, so no warning, and it stays.
        std::fs::write(models.join("M-1.yaml"), "identity:\n  id: M-1\n")?;
        assert!(complete_models(&dir, None).is_empty());
        assert!(complete_models(&dir, Some("M-1")).is_empty());
        assert_eq!(
            std::fs::read_to_string(models.join("M-1.yaml"))?,
            "identity:\n  id: M-1\n"
        );
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
        assert!(models_incomplete(&dir), "no models directory");
        let models = dir.join(bussard_model::param_model::MODELS_DIR);
        std::fs::create_dir_all(&models)?;
        assert!(models_incomplete(&dir), "an empty models directory");
        let current = format!(
            "# banner\nmodel_format: {}\n",
            bussard_model::param_model::MODEL_FORMAT
        );
        std::fs::write(models.join("M-1.yaml"), &current)?;
        assert!(models_incomplete(&dir), "one model of two");
        std::fs::write(models.join("M-2.yaml"), "identity:\n  id: M-2\n")?;
        assert!(models_incomplete(&dir), "a model of an older format");
        std::fs::write(models.join("M-2.yaml"), &current)?;
        // M-3 is in the archive, but no device pins it (issue #356).
        assert!(
            !models_incomplete(&dir),
            "every pinned application has its model"
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
