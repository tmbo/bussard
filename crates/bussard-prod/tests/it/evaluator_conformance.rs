//! The two evaluators of an application's Dynamic section agree (issue
//! #326): the model side (`bussard_model::device_view`, over the product
//! model's pages and Dynamic tree) and the download side
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
//!
//! The round trip (issue #345): the Dynamic evaluator over a program's
//! product model (format 5, which carries the tree) gives the same modules,
//! placements, containers and values as over its XML, on every fixture and,
//! with `BUSSARD_PRODUCT_CORPUS` set, on every program of the corpus.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};
use bussard_prod::product_model::write_product_models;
use bussard_prod::{ApplicationProgram, ProductData, parse_application_program};

use crate::value_sets::{
    FIXTURES, RANDOM_SETS, Rng, candidates, corpus_vendor, knxprod_files, random_values, seed,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    let first_value = |g: &bussard_model::dynamic::RefGate| match &g.test {
        bussard_model::dynamic::WhenTest::Values(values) => values.first().copied(),
        _ => None,
    };
    let index = bussard_model::dynamic::RefIndex::new(product);
    let occurrences = || {
        index
            .parameters()
            .flat_map(|(r, occ)| occ.iter().map(move |o| (r, o)))
            .filter(|(_, o)| o.module_def.is_none())
    };
    for (_, o) in occurrences() {
        for g in &o.gates {
            if let Some(v) = first_value(g) {
                push(BTreeMap::from([(g.param_ref_id.clone(), v.to_string())]));
            }
        }
    }
    for (_, o) in occurrences() {
        let mut values = BTreeMap::new();
        for g in &o.gates {
            if g.holds(vendor_default(app, &g.param_ref_id)) {
                continue;
            }
            if let Some(v) = first_value(g) {
                values
                    .entry(g.param_ref_id.clone())
                    .or_insert_with(|| v.to_string());
            }
        }
        push(values);
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
        if product.blocks().is_empty() {
            continue;
        }
        let held: BTreeSet<String> = product
            .blocks()
            .iter()
            .flat_map(|b| b.parameters.iter().cloned())
            .collect();
        let mut products = ProductModels::default();
        products.insert(id.to_string(), product.clone());
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
    products.insert(METEO_APP.to_string(), product_model(&app)?);
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
    assert_eq!(product.ref_default("UP-2248_R-2262"), Some("4"));
    let held: BTreeSet<String> = product
        .blocks()
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

// ---------------------------------------------------------------------------
// The lossless round trip (issue #345): the product model carries the
// Dynamic tree, so the evaluator gives the same answer over the model as
// over the application XML.
// ---------------------------------------------------------------------------

/// The first index at which two lists differ, as a message.
fn first_difference<T: PartialEq + std::fmt::Debug>(
    what: &str,
    a: &[T],
    b: &[T],
) -> Option<String> {
    if let Some(i) = (0..a.len().min(b.len())).find(|&i| a[i] != b[i]) {
        return Some(format!("{what}[{i}]: XML {:?}, model {:?}", a[i], b[i]));
    }
    (a.len() != b.len()).then(|| format!("{what}: XML has {}, model {}", a.len(), b.len()))
}

/// `None` when the evaluator gives the same answer over `app` and over
/// `model` with `values`, else the first difference.
fn round_trip_difference(
    app: &ApplicationProgram,
    model: &ProductModel,
    values: &BTreeMap<String, String>,
) -> Result<bussard_model::dynamic::DynamicConfig, String> {
    use bussard_model::dynamic::evaluate_dynamic;
    let xml = evaluate_dynamic(app, values);
    let yaml = evaluate_dynamic(model, values);
    let found = first_difference("modules", &xml.modules, &yaml.modules)
        .or_else(|| first_difference("parameters", &xml.parameters, &yaml.parameters))
        .or_else(|| {
            first_difference(
                "parameter_placements",
                &xml.parameter_placements,
                &yaml.parameter_placements,
            )
        })
        .or_else(|| first_difference("com_objects", &xml.com_objects, &yaml.com_objects))
        .or_else(|| {
            first_difference(
                "com_object_placements",
                &xml.com_object_placements,
                &yaml.com_object_placements,
            )
        })
        .or_else(|| first_difference("containers", &xml.containers, &yaml.containers))
        .or_else(|| {
            first_difference(
                "unresolved_overrides",
                &xml.unresolved_overrides,
                &yaml.unresolved_overrides,
            )
        });
    if let Some(found) = found {
        return Err(found);
    }
    let value = xml.parameters.iter().find_map(|p| {
        let r = p.param_ref_id.as_str();
        let a = (
            xml.value(app, p.module, r),
            xml.vendor_default(app, p.module, r),
            xml.is_assigned(p.module, r),
        );
        let b = (
            yaml.value(model, p.module, r),
            yaml.vendor_default(model, p.module, r),
            yaml.is_assigned(p.module, r),
        );
        (a != b).then(|| format!("value of {r} in {:?}: XML {a:?}, model {b:?}", p.module))
    });
    match value {
        Some(found) => Err(found),
        None => Ok(xml),
    }
}

/// Compares the evaluator over `app` and over its product model under the
/// vendor defaults and [`RANDOM_SETS`] random value sets seeded by the
/// application id. Returns how many sets were compared and how many reached
/// a configuration other than the defaults'.
fn check_round_trip(
    app: &ApplicationProgram,
    product: &ProductData,
) -> Result<(usize, usize), String> {
    let yaml = bussard_prod::product_model::model_yaml(app, product).map_err(|e| e.to_string())?;
    let model = ProductModel::from_yaml(&yaml, &app.id).map_err(|e| e.to_string())?;
    if bussard_model::dynamic::RefIndex::new(app) != bussard_model::dynamic::RefIndex::new(&model) {
        return Err("the ref index differs".to_string());
    }
    let defaults = BTreeMap::new();
    let base = round_trip_difference(app, &model, &defaults)
        .map_err(|diff| format!("vendor defaults: {diff}"))?
        .parameters;
    let candidates = candidates(app);
    let mut rng = Rng(seed(app));
    let mut other = 0;
    for set in 0..RANDOM_SETS {
        let values = random_values(&candidates, &mut rng);
        let config = round_trip_difference(app, &model, &values)
            .map_err(|diff| format!("set {set} ({} values): {diff}", values.len()))?;
        if config.parameters != base {
            other += 1;
        }
    }
    Ok((RANDOM_SETS as usize + 1, other))
}

#[test]
fn test_product_model_round_trips_the_dynamic_tree_on_every_fixture() -> TestResult {
    let mut compared = 0;
    let mut other = 0;
    for (id, xml) in FIXTURES {
        let app = parse_application_program(id, xml)?;
        let product = ProductData {
            applications: vec![app.clone()],
            ..ProductData::default()
        };
        let (sets, moved) = check_round_trip(&app, &product).map_err(|e| format!("{id}: {e}"))?;
        compared += sets;
        other += moved;
    }
    assert_eq!(compared, FIXTURES.len() * (RANDOM_SETS as usize + 1));
    assert!(
        other > 50,
        "only {other} random sets reached another configuration than the defaults"
    );
    Ok(())
}

/// Corpus-gated (`BUSSARD_PRODUCT_CORPUS`, dev/testing.md): the round trip
/// over every application program of every archive in the corpus.
#[test]
fn test_product_model_round_trips_the_dynamic_tree_on_the_corpus() -> TestResult {
    let Some(vendor) = corpus_vendor() else {
        return Ok(());
    };
    let files = knxprod_files(&vendor);
    let started = std::time::Instant::now();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = std::sync::Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 10));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(file) = files.get(i) else { break };
                    let name = file.file_name().map(|n| n.to_string_lossy().into_owned());
                    let name = name.unwrap_or_default();
                    let outcome = match bussard_prod::read_knxprod(file) {
                        Err(_) => vec![(name, None, Ok((0, 0)))],
                        Ok(product) => product
                            .applications
                            .iter()
                            .map(|app| {
                                (
                                    name.clone(),
                                    Some(app.id.clone()),
                                    check_round_trip(app, &product),
                                )
                            })
                            .collect(),
                    };
                    if let Ok(mut all) = results.lock() {
                        all.extend(outcome);
                    }
                }
            });
        }
    });
    let results = results
        .into_inner()
        .map_err(|_| "a sweep thread panicked")?;
    let mut programs = 0;
    let mut sets = 0;
    let mut other = 0;
    let mut unreadable = 0;
    let mut failures = Vec::new();
    for (archive, app, outcome) in results {
        match (app, outcome) {
            (None, _) => unreadable += 1,
            (Some(app), Ok((n, moved))) => {
                programs += 1;
                sets += n;
                other += moved;
                let _ = app;
            }
            (Some(app), Err(e)) => failures.push(format!("{archive} {app}: {e}")),
        }
    }
    eprintln!(
        "round trip: {} archives ({unreadable} unreadable), {programs} programs, {sets} value \
         sets ({other} off the defaults), {} failed, {:.0?}",
        files.len(),
        failures.len(),
        started.elapsed()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(programs > 0, "no program compared");
    Ok(())
}

/// The issue #449 fixture: allocator-fed module arguments and `<Repeat>`.
const ALLOCATORS: &[u8] = include_bytes!("../fixtures/allocators.app.xml");
/// Its program id.
const ALLOCATORS_ID: &str = "M-00FA_A-0449-10-0000";

/// The octets at `offsets` of the fixture's one parameter segment.
fn segment_octets(
    image: &BTreeMap<String, Vec<u8>>,
    offsets: &[usize],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let seg = image
        .get(&format!("{ALLOCATORS_ID}_RS-04-00000"))
        .ok_or("no parameter segment")?;
    offsets
        .iter()
        .map(|&o| seg.get(o).copied().ok_or_else(|| "offset outside".into()))
        .collect()
}

#[test]
fn test_evaluate_dynamic_repeat_instantiates_allocator_fed_modules() -> TestResult {
    let app = parse_application_program(ALLOCATORS_ID, ALLOCATORS)?;
    let config = bussard_prod::dynamic::evaluate_dynamic(&app, &BTreeMap::new());
    let modules: Vec<(&str, Option<i64>, Option<i64>)> = config
        .modules
        .iter()
        .map(|m| {
            let arg = |a: &str| m.args.get(a).copied();
            (
                m.id.as_str(),
                arg("MD-1_A-1").or(arg("MD-1_SM-1_A-1")),
                arg("MD-1_A-2"),
            )
        })
        .collect();
    // Two channels from L-1 (16, then 16 + 16) and L-2 (2, then 4); two
    // scenes in each, from the channel's own MD-1_L-1 (4, 5) plus the
    // channel's base (BaseValue).
    assert_eq!(
        modules,
        vec![
            ("MD-1_M-1", Some(16), Some(2)),
            ("MD-1_M-1_MI-1_SM-1_M-1_MI-1", Some(20), None),
            ("MD-1_M-1_MI-1_SM-1_M-1_MI-2", Some(21), None),
            ("MD-1_M-1_MI-2", Some(32), Some(4)),
            ("MD-1_M-1_MI-2_SM-1_M-1_MI-1", Some(36), None),
            ("MD-1_M-1_MI-2_SM-1_M-1_MI-2", Some(37), None),
        ]
    );
    let image = bussard_prod::compute_dynamic_parameter_image(&app, &BTreeMap::new())?;
    assert_eq!(
        segment_octets(&image, &[0, 1, 16, 17, 20, 21, 32, 33, 36, 37])?,
        vec![0xFF, 7, 5, 2, 9, 9, 5, 2, 9, 9]
    );
    // The objects: the application's 1, each channel's 0 and 1 on its base.
    let mut numbers = Vec::new();
    for active in &config.com_objects {
        let (base, _) = app
            .resolve(&active.com_object_ref_id)
            .ok_or("unresolved object")?;
        let offset = match base.base_number_ref.as_deref() {
            Some(arg) => bussard_prod::module_argument(&app, &config, active.module, arg)
                .ok_or("no object base")?,
            None => 0,
        };
        numbers.push(i64::from(base.number) + offset);
    }
    numbers.sort_unstable();
    assert_eq!(numbers, vec![1, 2, 3, 4, 5]);
    Ok(())
}

#[test]
fn test_evaluate_dynamic_repeat_values_are_keyed_per_instance() -> TestResult {
    let app = parse_application_program(ALLOCATORS_ID, ALLOCATORS)?;
    // The second channel's level and its first scene; the first channel
    // keeps its defaults.
    let values: BTreeMap<String, String> = [
        ("MD-1_M-1_MI-2_P-1_R-1", "33"),
        ("MD-1_M-1_MI-2_SM-1_M-1_MI-1_P-1_R-1", "44"),
        ("MD-1_M-1_MI-1_P-2_R-2", "1"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let image = bussard_prod::compute_dynamic_parameter_image(&app, &values)?;
    // Channel 1 now has one scene (at 20; 21 keeps the erased fill).
    assert_eq!(
        segment_octets(&image, &[16, 17, 20, 21, 32, 36, 37])?,
        vec![5, 1, 9, 0xFF, 33, 44, 9]
    );
    Ok(())
}

#[test]
fn test_compute_dynamic_parameter_image_refuses_an_exhausted_allocator() -> TestResult {
    let app = parse_application_program(ALLOCATORS_ID, ALLOCATORS)?;
    // A third channel would start at 48, past L-1's maxInclusive 47: its
    // base has no value, and the image refuses instead of writing the
    // channel at base 0 over the application's parameters.
    let values = BTreeMap::from([("P-1_R-1".to_string(), "3".to_string())]);
    let err = bussard_prod::compute_dynamic_parameter_image(&app, &values)
        .err()
        .ok_or("expected a refusal")?;
    assert!(err.to_string().contains("BaseOffset"), "{err}");
    Ok(())
}
