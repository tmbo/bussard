//! The product models under `<model dir>/.bussard/models/` (issue #228): one
//! machine-generated YAML file per application program, derived from the
//! archives `bussard.lock` pins under `products/`.
//!
//! [`write_product_models`] writes them from parsed product data (what
//! `import-product` and `import` do). [`complete_models`] fills in the ones
//! that are missing from the pinned archives. Every surface runs it before it
//! reads the model: the CLI before each command, the MCP and `viz` servers at
//! start and on every model reload (issue #267). An empty or partly deleted
//! `.bussard/models/` therefore heals on its own; only an application no
//! stored archive carries needs `bussard import-product`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_model::schema::ProductEntry;
use serde::Serialize;

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
    let (sha256, _) = bussard_model::sha256_file(archive).map_err(|source| ModelError::Io {
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

/// Whether an application an archive in the lock pins lacks its model file:
/// one `stat` per pinned application, no archive read. `false` when there is
/// no lock.
pub fn models_incomplete(dir: &Path) -> bool {
    if !dir.join(bussard_model::loader::LOCK_FILE).is_file() {
        return false;
    }
    let models_dir = dir.join(bussard_model::param_model::MODELS_DIR);
    if !models_dir.is_dir() {
        return true;
    }
    bussard_model::lock_products::lock_entries(dir)
        .iter()
        .filter(|e| e.file.is_some())
        .any(|e| {
            e.applications.is_empty()
                || e.applications
                    .iter()
                    .any(|app| !models_dir.join(format!("{app}.yaml")).is_file())
        })
}

/// Writes the product model of every application a pinned archive carries
/// that `.bussard/models/` lacks, or only of `only` when given. An archive
/// whose applications all have a model is not read. Returns one message per
/// archive that could not be used (missing, changed, unreadable); the caller
/// reports them as warnings, since the command itself says what it cannot do
/// without the model.
///
/// The archives are parsed in the language the model's device files carry
/// their enum labels in ([`bussard_model::import_language`]: the lock's
/// `language`), as `import-product` reads them; a model written in another
/// language would not know those labels (E017, issue #255). The
/// parsed-product cache keys programs by that language.
pub fn complete_models(dir: &Path, only: Option<&str>) -> Vec<String> {
    let models_dir = dir.join(bussard_model::param_model::MODELS_DIR);
    let _ = std::fs::create_dir_all(&models_dir);
    let has_model = |app: &str| models_dir.join(format!("{app}.yaml")).is_file();
    let language = bussard_model::import_language(dir);
    let cache = cache_dir(dir);
    let mut warnings = Vec::new();
    for entry in bussard_model::lock_products::lock_entries(dir) {
        if entry.file.is_none() {
            continue;
        }
        let wanted = match only {
            Some(app) => entry.applications.iter().any(|a| a == app) && !has_model(app),
            None => {
                entry.applications.is_empty() || !entry.applications.iter().all(|a| has_model(a))
            }
        };
        if !wanted {
            continue;
        }
        let what = entry
            .filename
            .clone()
            .unwrap_or_else(|| entry.sha256.clone());
        let written = verified_archive(dir, &what, &entry).and_then(|path| {
            let product = crate::read_knxprod_selected_in(
                &path,
                None,
                cache.as_deref(),
                language.as_deref(),
                |_| AppSelection::All,
            )
            .map_err(|source| ModelError::Read {
                path: path.clone(),
                source,
            })?;
            write_product_models(&product, dir)
        });
        if let Err(err) = written {
            warnings.push(err.to_string());
        }
    }
    warnings
}

/// Writes one model file per application program under
/// `<dir>/.bussard/models/` and returns the file names, sorted.
///
/// # Errors
///
/// A model does not serialize, or a file cannot be written.
pub fn write_product_models(product: &ProductData, dir: &Path) -> Result<Vec<String>, ModelError> {
    let models_dir = dir.join(bussard_model::param_model::MODELS_DIR);
    std::fs::create_dir_all(&models_dir).map_err(|source| ModelError::Io {
        what: "creating",
        path: models_dir.clone(),
        source,
    })?;
    let mut written: Vec<String> = Vec::new();
    for app in &product.applications {
        let model = build_model(app, product);
        let yaml = serialize_model(&model)?;
        let file_name = format!("{}.yaml", app.id);
        let path = models_dir.join(&file_name);
        std::fs::write(&path, yaml).map_err(|source| ModelError::Io {
            what: "writing",
            path: path.clone(),
            source,
        })?;
        written.push(file_name);
    }
    written.sort();
    Ok(written)
}

// The model YAML shape
// ---------------------------------------------------------------------------

/// The top-level model file for one application program.
#[derive(Debug, Serialize)]
struct Model {
    identity: Identity,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    order_numbers: Vec<String>,
    /// The hardware's declared bus current in mA (`Hardware.xml` `BusCurrent`),
    /// read by the `L002` topology lint to total a line's draw.
    #[serde(skip_serializing_if = "Option::is_none")]
    bus_current_ma: Option<u32>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    com_objects: BTreeMap<u16, ComObjectModel>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parameters: Vec<ParameterModel>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    load_procedure: Vec<String>,
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
fn build_model(app: &ApplicationProgram, product: &ProductData) -> Model {
    Model {
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
        com_objects: com_objects_for(app),
        parameters: parameters_for(app),
        load_procedure: load_procedure_summary(&app.load_procedures),
    }
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
        ref_id: rc.cref.id.clone(),
    }
}

/// The parameters, sorted by id, resolving each parameter's own default and
/// applying any single owning parameter-ref override.
fn parameters_for(app: &ApplicationProgram) -> Vec<ParameterModel> {
    // Index refs by the parameter they point at, so a parameter with exactly
    // one ref inherits that ref's Value/Access override.
    let mut refs_by_param: BTreeMap<&str, Vec<&crate::ParameterRef>> = BTreeMap::new();
    for pref in app.parameter_refs.values() {
        refs_by_param
            .entry(pref.ref_id.as_str())
            .or_default()
            .push(pref);
    }

    let mut out: Vec<ParameterModel> = app
        .parameters
        .values()
        .map(|param| {
            // Apply an override only when a single ref owns this parameter; with
            // multiple refs the base default is kept (refs differ per instance).
            let effective_default = match refs_by_param.get(param.id.as_str()) {
                Some(refs) if refs.len() == 1 => {
                    refs[0].value.clone().or_else(|| param.default.clone())
                }
                _ => param.default.clone(),
            };
            ParameterModel {
                id: param.id.clone(),
                name: param.name.clone().filter(|s| !s.is_empty()),
                text: param.text.clone().filter(|s| !s.is_empty()),
                param_type: param_type_model(app, param.parameter_type.as_deref()),
                default: effective_default.filter(|s| !s.is_empty()),
                memory: param.memory.as_ref().map(|m| MemoryModel {
                    segment: m.code_segment.clone(),
                    offset: m.offset,
                    bit_offset: m.bit_offset,
                }),
            }
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
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
        ParameterType::Text { size_bits } => ParamTypeModel::Text { size: *size_bits },
        ParameterType::Float { encoding, min, max } => ParamTypeModel::Float {
            encoding: encoding.clone(),
            min: *min,
            max: *max,
        },
        ParameterType::None => ParamTypeModel::None,
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
            fill.map(|b| format!("0x{b:02X}"))
                .unwrap_or_else(|| "-".to_string())
        ),
        LoadOp::AbsSegment {
            lsm_idx,
            address,
            size,
            access,
            mem_type,
            seg_flags,
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

/// Serializes a model to YAML, prefixed with the generated-file banner.
fn serialize_model(model: &Model) -> Result<String, ModelError> {
    let body = serde_norway::to_string(model).map_err(|e| ModelError::Serialize(e.to_string()))?;
    Ok(format!("{MODEL_BANNER}{body}"))
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
# Docs: https://github.com/tmbo/bussard/blob/main/docs/product-data.md
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
    fn test_models_incomplete_checks_every_pinned_application() -> TestResult {
        let dir = scratch("incomplete")?;
        assert!(!models_incomplete(&dir), "no lock, nothing to complete");
        std::fs::write(
            dir.join(bussard_model::loader::LOCK_FILE),
            "version = 2\n\n[[product]]\nsha256 = \"00\"\nfile = \"products/a.knxprod\"\n\
             origin = { kind = \"file\", path = \"a.knxprod\" }\napplications = [\"M-1\", \"M-2\"]\n",
        )?;
        assert!(models_incomplete(&dir), "no models directory");
        let models = dir.join(bussard_model::param_model::MODELS_DIR);
        std::fs::create_dir_all(&models)?;
        assert!(models_incomplete(&dir), "an empty models directory");
        std::fs::write(models.join("M-1.yaml"), "")?;
        assert!(models_incomplete(&dir), "one model of two");
        std::fs::write(models.join("M-2.yaml"), "")?;
        assert!(
            !models_incomplete(&dir),
            "every pinned application has its model"
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
