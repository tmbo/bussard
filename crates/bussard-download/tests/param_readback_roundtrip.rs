//! The parameter read-back round trip on real products (issue #142).
//!
//! For each product: build the full flash plan from a set of parameter values,
//! take the parameter regions the live read-back would read off a device that
//! ran that plan ([`planned_parameter_regions`]: the same segments, bases and
//! lengths, holding the bytes the plan streams), decode them, and require the
//! decoder to give back exactly those values: no difference to the values the
//! plan was built from, and `non_default` naming exactly the keys that differ
//! from the vendor default.
//!
//! Value sets per application: the vendor defaults, and a deterministic set of
//! changed values (every third shown enumeration or number, moved off its
//! default, kept only where the changed configuration still shows it). With
//! `BUSSARD_ROUNDTRIP_MODEL=<model dir>` set, also the `parameters:` block of
//! every model device that runs one of the applications.
//! `BUSSARD_ROUNDTRIP_ONLY=<text>` limits the run to the product files whose
//! name contains the text.
//!
//! The vendor products are not committed: the test is gated on
//! `BUSSARD_PRODUCT_CORPUS` like the other corpus tests and skips a product
//! that is not in the cache. Nothing here touches a bus.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use bussard_download::{
    decode_parameters, group_object_change, plan_flash_with_object_flags,
    planned_parameter_regions, regions_memory,
};
use bussard_prod::application::ParameterType;
use bussard_prod::dynamic::evaluate_dynamic;
use bussard_prod::{
    ApplicationProgram, MasterTemplate, parse_application_program, parse_master_template,
};

type Error = Box<dyn std::error::Error>;

/// A product file in the corpus cache (`outer.zip!inner.knxprod` for a
/// wrapper) and the id prefix of the application(s) to check (`None`: all).
const PRODUCTS: &[(&str, Option<&str>)] = &[
    (
        "de_3361-1m_V1.3_2020-05.knxprod",
        Some("M-0004_A-A011-13-60BC"),
    ),
    (
        "Tastsensoren_Universal_F50_Secure_2v1_Jung_DE_EN_FR_NL_ES_RU_IT.knxprod",
        Some("M-0004_A-D142-21-8848"),
    ),
    (
        "all_230021SU_v2v_20210930.knxprod",
        Some("M-0004_A-20DE-22-C7D8-O000A"),
    ),
    ("all_390041SR_20230313.knxprod", None),
    (
        "IBUS_ETS5_ABB_XX_V24-12-20_*Rev_P.knxprod",
        Some("M-0002_A-A0ED-10-9B4E"),
    ),
    (
        "BM_A4_11_13X_V8-2_9AKK108471A0162.knxprod",
        Some("M-0007_A-6179-82-036E"),
    ),
    (
        "89637_ControlPro_KNX_Hochfrequenz.zip!ControlPro_KNX_V3.1.knxprod",
        Some("M-008E_A-7188-31-1BFA"),
    ),
    ("de_3x81_24112017.knxprod", None),
    (
        "all_360061SR_20230811.knxprod",
        Some("M-0004_A-20E0-21-5B9E-O000A"),
    ),
    ("MV_KNX-Bus-Einheit_OEM_2020-11-17_cert.knxprod", None),
    (
        "o5646v53_KNX_DB_Meteodata_140_S_KNX_KNXDatenbank.zip!KNX_DB_D_GB_E_F_I_NL_METEODATA_140_S_V1_4_knxprod_2206.knxprod",
        None,
    ),
];

/// The vendor directory of the corpus, or `None` (skip).
fn vendor_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("BUSSARD_PRODUCT_CORPUS")?);
    [dir.join("cache/vendor"), dir.join("vendor"), dir]
        .into_iter()
        .find(|d| d.is_dir())
}

/// Resolves a file name with at most one `*` in `dir`.
fn find(dir: &Path, pattern: &str) -> Option<PathBuf> {
    match pattern.split_once('*') {
        None => Some(dir.join(pattern)).filter(|p| p.is_file()),
        Some((head, tail)) => std::fs::read_dir(dir)
            .ok()?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(head) && n.ends_with(tail))
            })
            .min(),
    }
}

/// The applications (matching the id prefix) and master template of one
/// product. Only those application files are parsed: some product files hold
/// hundreds.
struct Product {
    applications: Vec<ApplicationProgram>,
    master: Option<MasterTemplate>,
}

/// Reads a product, `None` when it is not in the cache.
fn product(dir: &Path, spec: &str, app_prefix: Option<&str>) -> Result<Option<Product>, Error> {
    let (file, inner) = match spec.split_once('!') {
        Some((outer, inner)) => (outer, Some(inner)),
        None => (spec, None),
    };
    let Some(path) = find(dir, file) else {
        eprintln!("{file} not in the corpus cache; skipping.");
        return Ok(None);
    };
    let mut bytes = std::fs::read(path)?;
    if let Some(inner) = inner {
        bytes = entry(&bytes, inner)?;
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(&bytes))?;
    let names: Vec<String> = archive.file_names().map(str::to_string).collect();
    let mut applications = Vec::new();
    for name in &names {
        let Some((folder, file)) = name.split_once('/') else {
            continue;
        };
        let Some(id) = file.strip_suffix(".xml") else {
            continue;
        };
        if !id.starts_with(&format!("{folder}_A-"))
            || app_prefix.is_some_and(|p| !id.starts_with(p))
        {
            continue;
        }
        let xml = entry(&bytes, name)?;
        let app = parse_application_program(id, &xml)?;
        if !app.is_pei_program() {
            applications.push(app);
        }
    }
    let master = match archive.by_name("knx_master.xml") {
        Ok(mut f) => {
            let mut xml = Vec::new();
            f.read_to_end(&mut xml)?;
            Some(parse_master_template(&xml, "knx_master.xml")?)
        }
        Err(_) => None,
    };
    Ok(Some(Product {
        applications,
        master,
    }))
}

/// One entry of a zip archive.
fn entry(bytes: &[u8], name: &str) -> Result<Vec<u8>, Error> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let mut file = archive.by_name(name)?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

/// The result of one round trip.
struct Outcome {
    /// Differences the decoder reported (should be none).
    differences: Vec<String>,
    /// Keys expected in `non_default` but missing.
    missing: Vec<String>,
    /// Keys in `non_default` that were not expected.
    extra: Vec<String>,
    /// How many values the decoder read back as non-default.
    non_default: usize,
}

impl Outcome {
    fn ok(&self) -> bool {
        self.differences.is_empty() && self.missing.is_empty() && self.extra.is_empty()
    }
}

/// Plans a flash of `values`, reads the planned regions back and decodes them.
/// `expected` is the set of keys `non_default` must list.
fn round_trip(
    data: &Product,
    app: &ApplicationProgram,
    values: &BTreeMap<String, String>,
    bases: &BTreeMap<String, u32>,
    expected: &BTreeSet<String>,
) -> Result<Outcome, Error> {
    let mask_text = app.mask_version.as_deref().ok_or("no mask version")?;
    let mask = u16::from_str_radix(mask_text.trim(), 16)?;
    let template = data
        .master
        .as_ref()
        .and_then(|m| m.full_load_procedure(mask_text))
        .map(|p| p.ops.clone());
    // The table contents do not matter here; the plan only needs one per
    // table object a master template writes.
    let tables: BTreeMap<u32, Vec<u8>> = [(1, vec![0, 0]), (2, vec![0]), (3, vec![0])].into();
    let plan = plan_flash_with_object_flags(
        app,
        "1.1.250",
        mask,
        values,
        bases,
        template.as_deref(),
        &tables,
        &BTreeMap::new(),
    )?;
    let regions = planned_parameter_regions(&plan);
    if regions.is_empty() {
        return Err("the plan writes no readable parameter region".into());
    }
    let decoded = decode_parameters(app, values, bases, &regions_memory(&regions));
    let listed: BTreeSet<String> = decoded.non_default.iter().map(|r| r.key.clone()).collect();
    // The parameter-only download's refusal compares the group-object table
    // of the decoded values with the model's: it must see no change here.
    let mut differences: Vec<String> = decoded.differences.iter().map(|c| c.line()).collect();
    let objects = group_object_change(app, &decoded.values, values);
    if !objects.is_empty() {
        differences.push(format!("group-object table would change: {objects:?}"));
    }
    Ok(Outcome {
        differences,
        missing: expected.difference(&listed).cloned().collect(),
        extra: listed.difference(expected).cloned().collect(),
        non_default: listed.len(),
    })
}

/// The keys of `values` that land in memory, that the configuration shows as
/// the user's (no `<Assign>` sets them, not `Access="None"`) and whose value
/// is not the vendor default: what `non_default` must list.
fn memory_keys(app: &ApplicationProgram, values: &BTreeMap<String, String>) -> BTreeSet<String> {
    let config = evaluate_dynamic(app, values);
    let shown: BTreeSet<(Option<String>, String)> = config
        .parameters
        .iter()
        .map(|p| {
            (
                config.module_instance_id(p.module).map(str::to_string),
                p.param_ref_id.clone(),
            )
        })
        .collect();
    values
        .keys()
        .filter(|key| {
            let (instance, param_ref) = bussard_prod::dynamic::split_selector(key);
            let Some(param) = app
                .parameter_refs
                .get(&format!("{}_{param_ref}", app.id))
                .and_then(|r| app.parameters.get(&r.ref_id))
            else {
                return false;
            };
            let in_union = app
                .unions
                .iter()
                .any(|u| u.members.iter().any(|m| m.parameter == param.id));
            let placed = param.memory.is_some() || in_union;
            let module = config
                .modules
                .iter()
                .position(|m| Some(m.id.as_str()) == instance.as_deref());
            let canonical =
                |v: Option<&str>| bussard_prod::canonical_parameter_value(app, param, v);
            let default = match app.dynamic.is_empty() {
                true => app
                    .parameter_refs
                    .get(&format!("{}_{param_ref}", app.id))
                    .and_then(|r| r.value.clone())
                    .or_else(|| param.default.clone()),
                false => config.vendor_default(app, module, &param_ref),
            };
            let differs =
                canonical(values.get(*key).map(String::as_str)) != canonical(default.as_deref());
            let ref_access = app
                .parameter_refs
                .get(&format!("{}_{param_ref}", app.id))
                .and_then(|r| r.access.as_deref());
            let device_managed = ref_access
                .or(param.access.as_deref())
                .is_some_and(|a| a.eq_ignore_ascii_case("none"));
            placed
                && differs
                && !device_managed
                && (app.dynamic.is_empty()
                    || shown.contains(&(instance.clone(), param_ref.clone())))
                && !config.is_assigned(module, &param_ref)
        })
        .cloned()
        .collect()
}

/// A deterministic set of non-default values: every third shown enumeration
/// or number moved off its default, dropping values the changed
/// configuration no longer shows.
fn changed_values(app: &ApplicationProgram) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let config = evaluate_dynamic(app, &values);
    for (i, active) in config.parameters.iter().enumerate() {
        if i % 3 != 0 {
            continue;
        }
        let Some(pref) = app
            .parameter_refs
            .get(&format!("{}_{}", app.id, active.param_ref_id))
        else {
            continue;
        };
        let access = pref.access.as_deref().or(app
            .parameters
            .get(&pref.ref_id)
            .and_then(|p| p.access.as_deref()));
        if matches!(access, Some("None") | Some("Read")) {
            continue;
        }
        let Some(param) = app.parameters.get(&pref.ref_id) else {
            continue;
        };
        let Some(ptype) = param
            .parameter_type
            .as_deref()
            .and_then(|t| app.parameter_types.get(t))
        else {
            continue;
        };
        let Some(default) = config.vendor_default(app, active.module, &active.param_ref_id) else {
            continue;
        };
        let Ok(default) = default.trim().parse::<i64>() else {
            continue;
        };
        let new = match &ptype.kind {
            ParameterType::Enum { values, .. } => {
                values.iter().map(|v| v.value).find(|v| *v != default)
            }
            ParameterType::Int { min, max, .. } => {
                let (lo, hi) = (min.unwrap_or(0), max.unwrap_or(default + 1));
                [default + 1, default - 1]
                    .into_iter()
                    .find(|v| (lo..=hi).contains(v))
            }
            _ => None,
        };
        let Some(new) = new else { continue };
        let key = match config.module_instance_id(active.module) {
            Some(instance) => {
                let md = instance.split_once("_M-").map_or(instance, |(md, _)| md);
                let rest = active
                    .param_ref_id
                    .strip_prefix(&format!("{md}_"))
                    .unwrap_or(&active.param_ref_id);
                format!("{instance}_MI-1_{rest}")
            }
            None => active.param_ref_id.clone(),
        };
        values.insert(key, new.to_string());
    }
    // Keep only what the changed configuration still shows as the user's.
    for _ in 0..4 {
        let keep = memory_keys(app, &values);
        let before = values.len();
        values.retain(|k, _| keep.contains(k));
        if values.len() == before {
            break;
        }
    }
    values
}

/// An application id without its hash and suffix (`M-0004_A-A011-13`): a
/// project names the same program version with another hash than the
/// product file does.
fn program(id: &str) -> String {
    match id.split_once("_A-") {
        Some((mfr, rest)) => {
            let parts: Vec<&str> = rest.splitn(3, '-').take(2).collect();
            format!("{mfr}_A-{}", parts.join("-"))
        }
        None => id.to_string(),
    }
}

/// A labelled value set: (label or address, values, module bases).
type ModelDevice = (String, BTreeMap<String, String>, BTreeMap<String, u32>);

/// The model devices that run `app`, with their values and module bases.
fn model_devices(
    model: Option<&bussard_model::Model>,
    app: &ApplicationProgram,
) -> Vec<ModelDevice> {
    let Some(model) = model else {
        return Vec::new();
    };
    model
        .devices
        .iter()
        .filter(|(_, d)| {
            d.device
                .product
                .as_ref()
                .and_then(|p| p.application_ref.as_deref())
                .map(program)
                == Some(program(&app.id))
        })
        .map(|(address, d)| {
            let values = d
                .device
                .parameters
                .iter()
                .filter_map(|(k, v)| Some((k.split_once('@')?.1.to_string(), v.clone())))
                .collect();
            (address.to_string(), values, d.device.module_bases.clone())
        })
        .collect()
}

#[test]
fn test_parameter_readback_round_trips_real_products() -> Result<(), Error> {
    let Some(dir) = vendor_dir() else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping the read-back round trip.");
        return Ok(());
    };
    let model = match std::env::var_os("BUSSARD_ROUNDTRIP_MODEL") {
        Some(path) => Some(bussard_model::Model::load(Path::new(&path))?),
        None => None,
    };
    let mut failures = Vec::new();
    let mut checked = 0usize;
    let only = std::env::var("BUSSARD_ROUNDTRIP_ONLY").ok();
    for (spec, app_prefix) in PRODUCTS {
        if only.as_deref().is_some_and(|o| !spec.contains(o)) {
            continue;
        }
        let Some(data) = product(&dir, spec, *app_prefix)? else {
            continue;
        };
        for app in &data.applications {
            let changed = changed_values(app);
            let mut cases: Vec<ModelDevice> = vec![
                ("defaults".into(), BTreeMap::new(), BTreeMap::new()),
                (
                    format!("{} changed values", changed.len()),
                    changed,
                    BTreeMap::new(),
                ),
            ];
            for (address, values, bases) in model_devices(model.as_ref(), app) {
                cases.push((format!("model {address}"), values, bases));
            }
            for (label, values, bases) in cases {
                let expected = memory_keys(app, &values);
                let unplaced: Vec<&String> =
                    values.keys().filter(|k| !expected.contains(*k)).collect();
                if !unplaced.is_empty() && label.starts_with("model") {
                    eprintln!(
                        "{} [{label}]: not expected as non-default (display-only, hidden, \
                         assigned or at the default): {unplaced:?}",
                        app.id
                    );
                }
                match round_trip(&data, app, &values, &bases, &expected) {
                    Ok(outcome) => {
                        checked += 1;
                        eprintln!(
                            "{} [{label}]: {} non-default, {} difference(s), {} missing, {} extra",
                            app.id,
                            outcome.non_default,
                            outcome.differences.len(),
                            outcome.missing.len(),
                            outcome.extra.len()
                        );
                        if !outcome.ok() {
                            failures.push(format!(
                                "{} [{label}]: differences {:?}; missing {:?}; extra {:?}",
                                app.id,
                                &outcome.differences[..outcome.differences.len().min(5)],
                                &outcome.missing[..outcome.missing.len().min(5)],
                                &outcome.extra[..outcome.extra.len().min(5)],
                            ));
                        }
                    }
                    Err(err) => eprintln!("{} [{label}]: not planned ({err})", app.id),
                }
            }
        }
    }
    eprintln!("{checked} round trip(s) checked");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}
