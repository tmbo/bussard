//! The two evaluators of an application's Dynamic section agree (issue
//! #326): the model side (`bussard_model::device_view`, over the product
//! model's `blocks:` and `ref_values:`) and the download side
//! (`bussard_ets::dynamic::evaluate_dynamic`, over the application XML)
//! reach the same parameter refs for the same values. The model side
//! decides the plan's "ignored" notes and `knx_set_parameter`'s refusals,
//! the download side what an image holds; a disagreement is a false note or
//! a false refusal.
//!
//! Every fixture application in the repository is checked at the vendor
//! defaults and with each condition's tested value set on its own. With
//! `BUSSARD_METEO_SNAPSHOT` set to a model snapshot directory holding the
//! Theben Meteodata 1.1.202 (`knx/.bussard/history/20261023T190946Z-001`),
//! the device's own values are checked against its archive too (found at
//! `BUSSARD_METEO_KNXPROD`, else `<snapshot>/../../../products/`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};
use bussard_prod::product_model::write_product_models;
use bussard_prod::{ApplicationProgram, ProductData, parse_application_program};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The fixture applications: (application id, XML).
const FIXTURES: &[(&str, &[u8])] = &[
    (
        "M-00FA_A-0298-10-0000",
        include_bytes!("fixtures/blocks_app.xml"),
    ),
    (
        "A",
        include_bytes!("../../bussard-download/tests/fixtures/param-readback/app.xml"),
    ),
    (
        "M-00FA_A-00D1-10-0001",
        include_bytes!("../../bussard-project/tests/fixtures/dynamic_tree.app.xml"),
    ),
    (
        "M-00FA_A-00D2-10-0001",
        include_bytes!("../../bussard-project/tests/fixtures/default_params.app.xml"),
    ),
    (
        "M-00FA_A-00D1-10-0001",
        include_bytes!("../../bussard-ets/tests/fixtures/dynamic_tree.app.xml"),
    ),
];

/// The product model the importer writes for `app`.
fn product_model(app: &ApplicationProgram) -> Result<ProductModel, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let product = ProductData {
        applications: vec![app.clone()],
        ..ProductData::default()
    };
    write_product_models(&product, dir.path())?;
    let path = dir
        .path()
        .join(".bussard/models")
        .join(format!("{}.yaml", app.id));
    let text = std::fs::read_to_string(&path)?;
    Ok(ProductModel::from_yaml(&text, &app.id)?)
}

/// The refs the download side reaches at the application level with
/// `values`, among `held` (the refs the model's pages hold).
fn download_reached(
    app: &ApplicationProgram,
    values: &BTreeMap<String, String>,
    held: &BTreeSet<String>,
) -> BTreeSet<String> {
    let config = bussard_prod::dynamic::evaluate_dynamic(app, values);
    config
        .parameters
        .iter()
        .zip(&config.parameter_placements)
        .filter(|(p, place)| p.module.is_none() && place.module.is_none() && place.shown)
        .map(|(p, _)| p.param_ref_id.clone())
        .filter(|r| held.contains(r))
        .collect()
}

/// The refs the model side shows for device `address` of `model`.
fn model_reached(
    model: &Model,
    products: &ProductModels,
    address: IndividualAddress,
) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    Ok(
        bussard_model::device_view::parameter_visibility(model, products, address)?
            .into_iter()
            .filter(|(_, v)| v.shown)
            .map(|(r, _)| r)
            .collect(),
    )
}

/// A one-device model running `app`, with `values` stored as values ETS
/// keeps outside the device file (the lock's `hidden[]`): the model side
/// reads them as it reads any stored value, and the flash writes them.
fn one_device(
    app: &str,
    values: &BTreeMap<String, String>,
) -> Result<Model, Box<dyn std::error::Error>> {
    let hidden: String = values
        .iter()
        .map(|(r, v)| format!("  {{ ref = \"{r}\", value = \"{v}\" }},\n"))
        .collect();
    let lock = format!(
        "version = 3\n\n[[device]]\naddress = \"1.1.1\"\nproduct = \"P-1\"\napplication = \
         \"{app}\"\nmask = \"0701\"\nhidden = [\n{hidden}]\n"
    );
    let files: BTreeMap<String, String> = [
        ("bussard.lock", lock),
        (
            "devices/1.1.1.toml",
            "address = \"1.1.1\"\nname = \"Device\"\nproduct = \"P-1\"\n".to_string(),
        ),
        ("groups.toml", "groups = []\n".to_string()),
        (
            "bussard.toml",
            "[connection]\ntransport = \"tunnel\"\n".to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    Ok(Model::from_texts(&files)?)
}

/// The vendor default of app-relative ref `reference` as the download side
/// takes it: the ref's `Value`, else the parameter's.
fn vendor_default(app: &ApplicationProgram, reference: &str) -> Option<f64> {
    let pref = app.parameter_ref(reference)?;
    let raw = pref.value.clone().or_else(|| {
        app.parameters
            .get(&pref.ref_id)
            .and_then(|p| p.default.clone())
    })?;
    raw.trim().parse().ok()
}

/// The value sets to compare under: none; each condition's tested value on
/// its own; and per ref the pages hold, the values that open the way to it
/// (every condition of its enclosing pages and of its branch), set only
/// where the vendor default does not already satisfy the condition, so a
/// condition the defaults hold (a ref value among them) is left to the
/// evaluators to resolve.
fn scenarios(app: &ApplicationProgram, product: &ProductModel) -> Vec<BTreeMap<String, String>> {
    let mut out = vec![BTreeMap::new()];
    let mut push = |values: BTreeMap<String, String>| {
        if !out.contains(&values) {
            out.push(values);
        }
    };
    for b in &product.blocks {
        for g in b.when.iter().chain(b.parameter_when.values().flatten()) {
            if let Some(v) = g.first_value() {
                push(BTreeMap::from([(g.reference.clone(), v.to_string())]));
            }
        }
    }
    let parents = bussard_model::blocks::parent_indexes(&product.blocks);
    for (i, b) in product.blocks.iter().enumerate() {
        let mut enclosing: Vec<&bussard_model::blocks::Gate> = Vec::new();
        let mut at = Some(i);
        while let Some(j) = at {
            enclosing.extend(product.blocks[j].when.iter());
            at = parents[j];
        }
        for reference in &b.parameters {
            let mut values = BTreeMap::new();
            let own = b.parameter_when.get(reference).into_iter().flatten();
            for g in enclosing.iter().copied().chain(own) {
                if g.holds(vendor_default(app, &g.reference)) {
                    continue;
                }
                if let Some(v) = g.first_value() {
                    values
                        .entry(g.reference.clone())
                        .or_insert_with(|| v.to_string());
                }
            }
            push(values);
        }
    }
    out
}

#[test]
fn test_model_and_download_evaluators_reach_the_same_refs_on_every_fixture() -> TestResult {
    let address: IndividualAddress = "1.1.1".parse()?;
    let mut compared = 0;
    for (id, xml) in FIXTURES {
        let app = parse_application_program(id, xml)?;
        let product = product_model(&app)?;
        if product.blocks.is_empty() {
            continue;
        }
        let held: BTreeSet<String> = product
            .blocks
            .iter()
            .flat_map(|b| b.parameters.iter().cloned())
            .collect();
        let mut products = ProductModels::default();
        products.by_app_ref.insert(id.to_string(), product.clone());
        let scenarios = scenarios(&app, &product);
        compared += scenarios.len();
        for values in scenarios {
            let model = one_device(id, &values)?;
            let model_side = model_reached(&model, &products, address)?;
            let download_side = download_reached(&app, &values, &held);
            assert_eq!(
                model_side, download_side,
                "{id} with {values:?}: the model side and the download side reach different refs"
            );
        }
    }
    assert!(compared > 20, "only {compared} value sets compared");
    Ok(())
}

/// The snapshot directory and the Meteodata archive, when the corpus is at
/// hand.
fn meteo_corpus() -> Option<(PathBuf, PathBuf)> {
    let Some(snapshot) = std::env::var_os("BUSSARD_METEO_SNAPSHOT").map(PathBuf::from) else {
        eprintln!("skipping: BUSSARD_METEO_SNAPSHOT is not set");
        return None;
    };
    let archive = std::env::var_os("BUSSARD_METEO_KNXPROD")
        .map(PathBuf::from)
        .unwrap_or_else(|| snapshot.join("../../../products/M-0048_A-140C-14-EB70.knxprod"));
    if !snapshot.join("bussard.lock").is_file() || !archive.is_file() {
        eprintln!(
            "skipping: no snapshot at {} or no archive at {}",
            snapshot.display(),
            archive.display()
        );
        return None;
    }
    Some((snapshot, archive))
}

const METEO_APP: &str = "M-0048_A-140C-14-EB70";

/// The Meteodata 1.1.202 of the snapshot, its product model and its
/// application.
fn meteo(
    snapshot: &Path,
    archive: &Path,
) -> Result<(Model, ProductModels, ApplicationProgram), Box<dyn std::error::Error>> {
    let model = Model::load(snapshot)?;
    // The device file names enum members in the lock's language.
    let language = bussard_model::import_language(snapshot);
    let product =
        bussard_prod::read_knxprod_selected_in(archive, None, None, language.as_deref(), |_| {
            bussard_prod::AppSelection::Only(vec![METEO_APP.to_string()])
        })?;
    let app = product
        .application_by_id(METEO_APP)
        .ok_or("the archive carries no Meteodata application")?
        .clone();
    let mut products = ProductModels::default();
    products
        .by_app_ref
        .insert(METEO_APP.to_string(), product_model(&app)?);
    Ok((model, products, app))
}

/// Corpus-gated (issue #326): on the owner's Meteodata the two evaluators
/// agree, so the plan carries no "ignored" note for the wind thresholds of
/// C1 the image writes, and every note it does carry names a value the
/// image leaves out.
#[test]
fn test_meteodata_snapshot_evaluators_agree_and_ignore_only_unwritten_values() -> TestResult {
    let Some((snapshot, archive)) = meteo_corpus() else {
        return Ok(());
    };
    let (model, products, app) = meteo(&snapshot, &archive)?;
    let address: IndividualAddress = "1.1.202".parse()?;
    let product = products.get(METEO_APP).ok_or("no product model")?;
    assert_eq!(
        product.ref_values.get("UP-2248_R-2262").map(String::as_str),
        Some("4")
    );
    let held: BTreeSet<String> = product
        .blocks
        .iter()
        .flat_map(|b| b.parameters.iter().cloned())
        .collect();
    let (values, malformed) = bussard_download_overrides(&model, address);
    assert!(malformed.is_empty(), "{malformed:?}");
    let model_side = model_reached(&model, &products, address)?;
    let download_side = download_reached(&app, &values, &held);
    assert!(model_side.contains("P-613_R-2263"), "C1 wind threshold");
    assert_eq!(model_side, download_side);
    // Every value the plan calls ignored is one the image does not hold:
    // its ref is unreached on the download side too. None of C1's wind
    // values is among them. The two that are: ETS keeps a value for the C18
    // logic inputs' XOR refs (`@P-6823_R-6823`, `@P-6824_R-6824`), while the
    // channel runs UND and shows the inputs through other refs of the same
    // parameters, which the image writes at their defaults.
    let ignored = bussard_model::device_view::ignored_overrides(&model, &products, address)?;
    let refs: BTreeSet<&str> = ignored.iter().map(|o| o.reference.as_str()).collect();
    for r in &refs {
        assert!(
            !download_side.contains(*r),
            "{r} is written but called ignored"
        );
    }
    assert_eq!(
        refs,
        BTreeSet::from(["P-6823_R-6823", "P-6824_R-6824"]),
        "{ignored:?}"
    );
    Ok(())
}

/// The device's values keyed by ref, as the flash reads them (the part of
/// each in-memory key after `@`).
fn bussard_download_overrides(
    model: &Model,
    address: IndividualAddress,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut out = BTreeMap::new();
    let mut malformed = Vec::new();
    if let Some(d) = model.devices.get(&address) {
        for (key, value) in &d.device.parameters {
            match key.split_once('@') {
                Some((_, r)) if !r.is_empty() => {
                    out.insert(r.to_string(), value.clone());
                }
                _ => malformed.push(key.clone()),
            }
        }
    }
    (out, malformed)
}
