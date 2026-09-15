//! The `bussard import-product` subcommand — generate device models from
//! vendor `.knxprod` product data.
//!
//! Reads a `.knxprod` (see `bussard-prod`), caches the original byte-identical
//! under `<dir>/vendor/`, and writes one machine-generated-but-human-skimmable
//! model YAML per ApplicationProgram under `<dir>/models/`. Both directories are
//! local-only: vendor XML is copyrighted and the models are derived from it, so
//! a `vendor/.gitignore` of `*` is planted to keep them out of git.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_prod::{
    ApplicationProgram, LoadOp, LoadProcedure, ParameterType, ProductData, ResolvedComObject,
};
use serde::Serialize;

/// Imports a `.knxprod`: caches it under `<dir>/vendor/` and generates a device
/// model under `<dir>/models/` for each application program it contains.
pub fn run(file: &Path, dir: &Path) -> anyhow::Result<ExitCode> {
    if !file.exists() {
        bail!("product file not found: {}", file.display());
    }

    let product = bussard_prod::read_knxprod(file)
        .with_context(|| format!("reading product data from {}", file.display()))?;

    if product.applications.is_empty() {
        bail!(
            "no application programs found in {} (is it a valid .knxprod?)",
            file.display()
        );
    }

    // Cache the source file verbatim under <dir>/vendor/.
    let vendor_dir = dir.join("vendor");
    let vendor_created = !vendor_dir.exists();
    std::fs::create_dir_all(&vendor_dir)
        .with_context(|| format!("creating {}", vendor_dir.display()))?;
    if vendor_created {
        // Self-protecting: a fresh vendor/ ignores everything (copyrighted).
        std::fs::write(vendor_dir.join(".gitignore"), VENDOR_GITIGNORE)
            .with_context(|| format!("writing {}", vendor_dir.join(".gitignore").display()))?;
    }

    let original_name = file
        .file_name()
        .context("product file has no file name")?
        .to_owned();
    let vendor_target = vendor_dir.join(&original_name);
    let cached_note = cache_vendor_file(file, &vendor_target)?;

    // Generate one model YAML per application program.
    let models_dir = dir.join("models");
    std::fs::create_dir_all(&models_dir)
        .with_context(|| format!("creating {}", models_dir.display()))?;

    let mut written: Vec<String> = Vec::new();
    for app in &product.applications {
        let model = build_model(app, &product);
        let yaml = serialize_model(&model)?;
        let file_name = format!("{}.yaml", app.id);
        let path = models_dir.join(&file_name);
        std::fs::write(&path, yaml).with_context(|| format!("writing {}", path.display()))?;
        written.push(file_name);
    }
    written.sort();

    // Report.
    println!("{cached_note}");
    println!(
        "Generated {} model file{} in {}:",
        written.len(),
        if written.len() == 1 { "" } else { "s" },
        models_dir.display()
    );
    for name in &written {
        println!("  models/{name}");
    }
    println!();
    println!(
        "Reminder: {} and {} are local-only — vendor product data is copyrighted",
        vendor_dir.display(),
        models_dir.display()
    );
    println!("and the models are derived from it. Keep both out of git; cloners regenerate");
    println!("their models from their own vendor downloads.");

    Ok(ExitCode::SUCCESS)
}

/// Copies `src` to `dst` byte-identically, skipping the copy (with a note) if an
/// identical file is already cached.
fn cache_vendor_file(src: &Path, dst: &Path) -> anyhow::Result<String> {
    let src_bytes = std::fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    if dst.exists() {
        let existing = std::fs::read(dst).with_context(|| format!("reading {}", dst.display()))?;
        if existing == src_bytes {
            return Ok(format!(
                "Vendor file already cached (identical): {}",
                dst.display()
            ));
        }
    }
    std::fs::write(dst, &src_bytes).with_context(|| format!("writing {}", dst.display()))?;
    Ok(format!("Cached vendor file: {}", dst.display()))
}

// ---------------------------------------------------------------------------
// The model YAML shape
// ---------------------------------------------------------------------------

/// The top-level model file for one application program.
#[derive(Debug, Serialize)]
struct Model {
    identity: Identity,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    order_numbers: Vec<String>,
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
        com_objects: com_objects_for(app),
        parameters: parameters_for(app),
        load_procedure: load_procedure_summary(&app.load_procedures),
    }
}

/// The order numbers that map to this application program, sorted.
fn order_numbers_for(app: &ApplicationProgram, product: &ProductData) -> Vec<String> {
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
    let mut refs_by_param: BTreeMap<&str, Vec<&bussard_prod::ParameterRef>> = BTreeMap::new();
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
        ParameterType::Other { kind, size_bits } => ParamTypeModel::Other {
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
        } => format!(
            "rel_segment lsm={} size={} applies_to={}",
            opt(lsm_idx),
            opt(size),
            applies_to.as_deref().unwrap_or("-")
        ),
        LoadOp::AbsSegment {
            lsm_idx,
            address,
            size,
        } => format!(
            "abs_segment lsm={} addr={} size={}",
            opt(lsm_idx),
            opt(address),
            opt(size)
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
        LoadOp::WriteProp { obj_type, prop_id } => {
            format!(
                "write_prop obj_type={} prop_id={}",
                opt(obj_type),
                opt(prop_id)
            )
        }
        LoadOp::Raw { name, attrs } => {
            let joined: Vec<String> = attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("raw {name} [{}]", joined.join(" "))
        }
    }
}

fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    v.as_ref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// Serializes a model to YAML, prefixed with the generated-file banner.
fn serialize_model(model: &Model) -> anyhow::Result<String> {
    let body = serde_norway::to_string(model).context("serializing model to YAML")?;
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
# procedure used to download it. Local-only: derived from copyrighted vendor
# data, never committed.
# Docs: https://github.com/tmbo/bussard/blob/main/docs/product-data.md
";

/// `vendor/.gitignore`: ignore everything, since vendor product data is
/// copyrighted and must never be committed.
const VENDOR_GITIGNORE: &str = "\
# Vendor `.knxprod` product data is copyrighted — never commit it. Each user
# supplies their own downloads; models under ../models/ are regenerated from them.
*
";
