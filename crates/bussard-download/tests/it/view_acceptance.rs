//! The device view and the download agree (issue #345, the acceptance test
//! of the one Dynamic evaluator): for every fixture application, and with
//! `BUSSARD_PRODUCT_CORPUS` set every program of every archive in the
//! corpus, under the vendor defaults and 50 seeded random valid value sets
//! stored in the device file,
//!
//! - the refs the view shows ([`DeviceAnalysis::visibility`], `shown`) are the
//!   refs the image writes at the application level
//!   ([`dynamic_parameter_slots`] with a `param_ref_id`), the internal ones
//!   (`Access="None"`, which the view never lists) left out on both sides;
//! - the objects the view shows ([`shown_objects`]) are the ones the object
//!   table gets a descriptor for ([`dynamic_group_object_descriptors`]);
//! - [`DeviceAnalysis::ignored_overrides`] names exactly the stored values the image does
//!   not carry: on refs without a slot (and, for a ref without memory, that
//!   the evaluation does not reach), or replaced by an `<Assign>`; and on a
//!   module instance's refs the evaluation does not reach (issue #1050).
//!
//! The view runs over the product model, the download over the application
//! XML. The test sits here, not in `bussard-prod`, because the object table
//! is `bussard-download`'s; it draws its value sets from the generator of
//! `bussard-prod`'s evaluator conformance test.
//!
//! Two sides of the comparison are restricted to what both can name: a ref
//! whose parameter has no memory (a display-only switch) steers the
//! evaluation but gets no slot, so the view's shown refs count only those
//! with a memory location; and a ref the evaluation reaches without showing
//! it (an `<Assign>` target or source) gets a slot the view does not list,
//! so the written refs count only those the evaluation places as shown.

use std::collections::{BTreeMap, BTreeSet};

use bussard_download::compute::dynamic_group_object_descriptors;
use bussard_download::model_params::parameter_overrides;

use bussard_model::dynamic::{
    DynamicConfig, DynamicNode, evaluate_dynamic, selector_key, split_selector,
    vendor_default_with_args, walk_all,
};
use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};
use bussard_product::image::dynamic_parameter_slots;
use bussard_product::{
    ApplicationProgram, ProductData, compute_parameter_image, parse_application_program,
};

use crate::value_sets::{
    FIXTURES, RANDOM_SETS, Rng, candidates, corpus_vendor, knxprod_files, random_values, seed,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ADDRESS: &str = "1.1.1";

/// A one-device model running `app` with nothing stored.
fn one_device(app: &str) -> Result<Model, String> {
    let lock = format!(
        "version = 3\n\n[[device]]\naddress = \"{ADDRESS}\"\nproduct = \"P-1\"\napplication = \
         \"{app}\"\nmask = \"0701\"\n"
    );
    let files: BTreeMap<String, String> = [
        ("bussard.lock", lock),
        (
            "devices/1.1.1.toml",
            format!("address = \"{ADDRESS}\"\nname = \"Device\"\nproduct = \"P-1\"\n"),
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
    Model::from_texts(&files).map_err(|e| e.to_string())
}

/// The app-relative refs whose parameter has a memory location: those the
/// image writes once reached.
fn located(app: &ApplicationProgram) -> BTreeSet<String> {
    let prefix = format!("{}_", app.id);
    let in_union: BTreeSet<&str> = app
        .unions
        .iter()
        .filter(|u| u.memory.is_some())
        .flat_map(|u| u.members.iter().map(|m| m.parameter.as_str()))
        .collect();
    app.parameter_refs
        .values()
        .filter(|pref| {
            app.parameters.get(&pref.ref_id).is_some_and(|p| {
                p.memory
                    .as_ref()
                    .is_some_and(|m| m.code_segment.is_some() && m.offset.is_some())
                    || in_union.contains(p.id.as_str())
            })
        })
        .filter_map(|pref| pref.id.strip_prefix(&prefix).map(str::to_string))
        .collect()
}

/// The vendor default of a device-form ref (`P-1_R-1`, or a module ref by
/// its selector key) in `config`: in a reached instance with its arguments;
/// in an unreached one with the arguments its `<Module>` in the application
/// XML gives, literal and computed from a literal `Value` (issue #1050).
/// `None` when the XML alone does not tell the default: an unreached
/// repetition or submodule, or an argument from an allocator or a parent's
/// `BaseValue`, whose value depends on the instances reached before it.
fn default_in(
    app: &ApplicationProgram,
    config: &DynamicConfig,
    key: &str,
) -> Option<Option<String>> {
    let (instance, reference) = split_selector(key);
    let Some(instance) = instance else {
        return Some(config.vendor_default(app, None, key));
    };
    if let Some(m) = config.modules.iter().position(|m| m.id == instance) {
        return Some(config.vendor_default(app, Some(m), &reference));
    }
    if instance.contains("_MI-") {
        return None;
    }
    let mut site = None;
    walk_all(app, &mut |node, _| {
        if let DynamicNode::Module {
            id,
            args,
            computed_args,
            ..
        } = node
            && *id == instance
        {
            site = Some((args.clone(), computed_args.clone()));
        }
        true
    });
    let (mut args, computed) = site?;
    for c in computed {
        match (c.allocator, c.value, c.base) {
            (None, Some(value), None) => {
                args.insert(c.arg, value);
            }
            _ => return None,
        }
    }
    Some(vendor_default_with_args(app, Some(&args), &reference))
}

/// Sorted lists of what only one side has, as a message.
fn difference<T: Ord + std::fmt::Debug>(
    what: &str,
    view: &BTreeSet<T>,
    download: &BTreeSet<T>,
) -> Option<String> {
    let only_view: Vec<&T> = view.difference(download).collect();
    let only_download: Vec<&T> = download.difference(view).collect();
    (!only_view.is_empty() || !only_download.is_empty()).then(|| {
        format!("{what}: only the view {only_view:?}, only the download {only_download:?}")
    })
}

/// `None` when the view and the download agree on `app` with `values`
/// stored, else the first disagreement.
fn compare(
    app: &ApplicationProgram,
    products: &ProductModels,
    product: &ProductModel,
    located: &BTreeSet<String>,
    values: &BTreeMap<String, String>,
    tally: &mut Tally,
) -> Result<Option<String>, String> {
    let address: IndividualAddress = ADDRESS.parse().map_err(|e| format!("{e:?}"))?;
    let mut model = one_device(&app.id)?;
    let device = &mut model.devices.get_mut(&address).ok_or("no device")?.device;
    for (key, value) in values {
        device.parameters.insert(format!("v@{key}"), value.clone());
    }
    let internal = |r: &str| product.parameter_refs.get(r).is_some_and(|d| d.internal);

    // The download side, as the flash evaluates and writes.
    let (overrides, _) = parameter_overrides(Some(&model), address);
    let config = evaluate_dynamic(app, &overrides);
    let slots = dynamic_parameter_slots(app, &config).map_err(|e| e.to_string())?;
    let placed_shown: BTreeSet<&str> = config
        .parameters
        .iter()
        .zip(&config.parameter_placements)
        .filter(|(p, place)| p.module.is_none() && place.module.is_none() && place.shown)
        .map(|(p, _)| p.param_ref_id.as_str())
        .collect();
    let slotted: BTreeSet<String> = slots
        .iter()
        .filter(|s| s.module.is_none())
        .filter_map(|s| s.param_ref_id.clone())
        .collect();
    let written: BTreeSet<String> = slotted
        .iter()
        .filter(|r| placed_shown.contains(r.as_str()) && !internal(r))
        .cloned()
        .collect();

    // The view side: one analysis (one evaluation) answers all three
    // questions, as the view itself asks them (issue #1087).
    let analysis = bussard_model::device_view::DeviceAnalysis::new(&model, products, address)
        .map_err(|e| e.to_string())?;
    // The shown refs alone: [`DeviceAnalysis::visibility`] would word what
    // every other ref needs, most of a set's time on a large program.
    let shown: BTreeSet<String> = analysis
        .shown_refs()
        .into_iter()
        .filter(|r| located.contains(r) && !internal(r))
        .collect();
    // The pages hold the refs of the application's own containers; the
    // image writes the ones outside every container too.
    let held: BTreeSet<&str> = product
        .blocks()
        .iter()
        .flat_map(|b| b.parameters.iter().map(String::as_str))
        .collect();
    let written_held: BTreeSet<String> = written
        .iter()
        .filter(|r| held.contains(r.as_str()))
        .cloned()
        .collect();
    tally.shown += shown.len();
    if let Some(d) = difference("shown refs", &shown, &written_held) {
        return Ok(Some(d));
    }

    // Objects: the view's shown objects by number, the table's descriptors
    // of the application-level objects.
    let mut app_level = config.clone();
    app_level.com_objects.retain(|c| c.module.is_none());
    let table: BTreeSet<u16> = dynamic_group_object_descriptors(app, &app_level, &BTreeMap::new())
        .iter()
        .map(|d| d.asap)
        .collect();
    let view_objects: BTreeSet<u16> = analysis
        .shown_objects()
        .iter()
        // Every shown object gets a descriptor, one with every flag disabled
        // too (issue #686).
        .filter_map(|r| app.resolve(r))
        .map(|(base, _)| base.number)
        .filter(|n| *n != 0)
        .collect();
    tally.objects += view_objects.len();
    if let Some(d) = difference("shown objects", &view_objects, &table) {
        return Ok(Some(d));
    }

    // Ignored: the stored values on application refs the pages hold that
    // the image does not carry, and that differ from the ref's default. A
    // ref without memory never has a slot; its value is ignored when the
    // evaluation does not reach it (reached, it steers the evaluation).
    let reached: BTreeSet<&str> = config
        .parameters
        .iter()
        .filter(|p| p.module.is_none())
        .map(|p| p.param_ref_id.as_str())
        .collect();
    let ignored: BTreeSet<String> = analysis
        .ignored_overrides()
        .into_iter()
        .map(|o| o.reference)
        // A default the XML alone does not tell is left out of the
        // comparison (see [`default_in`]).
        .filter(|r| default_in(app, &config, r).is_some())
        .collect();
    // A module instance's ref (issue #1050), by its selector key: in effect
    // when the image carries it in its instance (a slot of that instance),
    // or, for a ref without memory, when the evaluation reaches it, unless
    // an `<Assign>` replaces it; only a ref a module body places counts, as
    // the application's refs count only on a page.
    let instance_key = |m: Option<usize>, r: &str| {
        m.and_then(|m| config.modules.get(m))
            .map(|i| selector_key(Some(&i.id), r))
    };
    let carried: BTreeSet<String> = slots
        .iter()
        .filter_map(|s| instance_key(s.module, s.param_ref_id.as_deref()?))
        .collect();
    let module_reached: BTreeSet<String> = config
        .parameters
        .iter()
        .filter_map(|p| instance_key(p.module, &p.param_ref_id))
        .collect();
    let module_shown: BTreeSet<String> = config
        .parameters
        .iter()
        .zip(&config.parameter_placements)
        .filter(|(_, place)| place.shown)
        .filter_map(|(p, _)| instance_key(p.module, &p.param_ref_id))
        .collect();
    let module_in_effect = |key: &str, reference: &str, module: Option<usize>| {
        let written = if located.contains(reference) {
            carried.contains(key)
        } else {
            module_reached.contains(key)
        };
        written && (module_shown.contains(key) || !config.is_assigned(module, reference))
    };
    let expected: BTreeSet<String> = values
        .iter()
        .filter(|(r, _)| {
            let (instance, reference) = split_selector(r);
            match instance {
                Some(instance) => {
                    let module = config.modules.iter().position(|m| m.id == instance);
                    let placed = product
                        .ref_index()
                        .parameter(&reference)
                        .iter()
                        .any(|o| o.module_def.is_some());
                    placed && !module_in_effect(r, &reference, module)
                }
                None => {
                    // The image carries the stored value of a ref the
                    // evaluation reaches (as its slot, or as the source of
                    // an `<Assign>`), unless an `<Assign>` replaces it.
                    let in_effect = reached.contains(r.as_str())
                        && (placed_shown.contains(r.as_str()) || !config.is_assigned(None, r));
                    held.contains(r.as_str()) && !in_effect
                }
            }
        })
        .filter(|(r, v)| {
            default_in(app, &config, r).is_some_and(|d| d.as_deref() != Some(v.as_str()))
        })
        .map(|(r, _)| r.clone())
        .collect();
    tally.ignored += ignored.len();
    Ok(difference("ignored overrides", &ignored, &expected).map(|d| {
        let why: Vec<String> = ignored
            .symmetric_difference(&expected)
            .map(|r| {
                format!(
                    "{r}: stored {:?}, value {:?}, assigned {}, default {:?}, slot {}, reached {}, shown {}",
                    values.get(r),
                    config.value(app, None, r),
                    config.is_assigned(None, r),
                    config.vendor_default(app, None, r),
                    slotted.contains(r),
                    reached.contains(r.as_str()),
                    placed_shown.contains(r.as_str()),
                )
            })
            .collect();
        format!("{d} ({})", why.join("; "))
    }))
}

/// What the comparisons covered, summed over the value sets: shown refs,
/// shown objects and ignored values (each compared equal).
#[derive(Debug, Default)]
struct Tally {
    sets: usize,
    shown: usize,
    objects: usize,
    ignored: usize,
}

/// Compares the view and the download on `app` under the vendor defaults
/// and [`RANDOM_SETS`] random value sets, adding what it compared to
/// `tally` (nothing for an application without pages).
fn check(app: &ApplicationProgram, product: &ProductData, tally: &mut Tally) -> Result<(), String> {
    let model = bussard_product::product_model::product_model(app, product);
    if model.blocks().is_empty() {
        return Ok(());
    }
    let mut products = ProductModels::default();
    products.insert(app.id.clone(), model.clone());
    let located = located(app);
    let candidates = candidates(app);
    let mut rng = Rng(seed(app));
    let mut sets = vec![BTreeMap::new()];
    sets.extend((0..RANDOM_SETS).map(|_| random_values(&candidates, &mut rng)));
    for (i, values) in sets.iter().enumerate() {
        if let Some(diff) = compare(app, &products, &model, &located, values, tally)? {
            return Err(format!("set {i} {values:?}: {diff}"));
        }
        tally.sets += 1;
    }
    Ok(())
}

#[test]
fn test_view_shows_what_the_download_writes_on_every_fixture() -> TestResult {
    let mut tally = Tally::default();
    for (id, xml) in FIXTURES {
        let app = parse_application_program(id, xml)?;
        let product = ProductData {
            applications: vec![app.clone()],
            ..ProductData::default()
        };
        check(&app, &product, &mut tally).map_err(|e| format!("{id}: {e}"))?;
    }
    eprintln!("{tally:?}");
    assert!(tally.sets > RANDOM_SETS as usize, "{tally:?}");
    assert!(
        tally.shown > 0 && tally.objects > 0 && tally.ignored > 0,
        "every comparison must have something to compare: {tally:?}"
    );
    Ok(())
}

/// Issue #1087: [`DeviceAnalysis::shown_refs`], which the comparison reads
/// instead of the whole visibility map, names exactly the refs
/// [`DeviceAnalysis::visibility`] marks shown, on every fixture under the
/// vendor defaults and the random value sets.
#[test]
fn test_shown_refs_is_what_visibility_shows_on_every_fixture() -> TestResult {
    let address: IndividualAddress = ADDRESS.parse()?;
    let mut compared = 0;
    for (id, xml) in FIXTURES {
        let app = parse_application_program(id, xml)?;
        let product = ProductData {
            applications: vec![app.clone()],
            ..ProductData::default()
        };
        let model = bussard_product::product_model::product_model(&app, &product);
        let mut products = ProductModels::default();
        products.insert(app.id.clone(), model);
        let candidates = candidates(&app);
        let mut rng = Rng(seed(&app));
        let mut sets = vec![BTreeMap::new()];
        sets.extend((0..RANDOM_SETS).map(|_| random_values(&candidates, &mut rng)));
        for values in &sets {
            let mut device_model = one_device(&app.id)?;
            let device = &mut device_model
                .devices
                .get_mut(&address)
                .ok_or("no device")?
                .device;
            for (key, value) in values {
                device.parameters.insert(format!("v@{key}"), value.clone());
            }
            let analysis =
                bussard_model::device_view::DeviceAnalysis::new(&device_model, &products, address)?;
            let from_map: BTreeSet<String> = analysis
                .visibility()
                .into_iter()
                .filter(|(_, v)| v.shown)
                .map(|(r, _)| r)
                .collect();
            assert_eq!(analysis.shown_refs(), from_map, "{id} {values:?}");
            compared += from_map.len();
        }
    }
    assert!(compared > 0);
    Ok(())
}

/// How many test functions split the corpus sweep (issue #1087): nextest runs
/// them side by side, and each prints a line per program, so a slow program
/// shows by name instead of stalling one test for hours.
const CORPUS_SHARDS: usize = 16;

/// Whether archive `name` falls in shard `slot` of [`CORPUS_SHARDS`]: by the
/// first octet of the SHA-256 of its file name, stable across hosts.
fn in_shard(name: &str, slot: usize) -> bool {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(name.as_bytes());
    usize::from(digest[0]) % CORPUS_SHARDS == slot
}

macro_rules! corpus_shards {
    ($($name:ident = $slot:expr),* $(,)?) => {
        $(
            /// Corpus-gated (`BUSSARD_PRODUCT_CORPUS`, dev/testing.md): the
            /// fixture comparison over every application program of the
            /// archives that hash to this shard.
            #[test]
            fn $name() -> TestResult {
                corpus_shard($slot)
            }
        )*
    };
}

corpus_shards!(
    test_view_shows_what_the_download_writes_on_the_corpus_shard_0 = 0,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_1 = 1,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_2 = 2,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_3 = 3,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_4 = 4,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_5 = 5,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_6 = 6,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_7 = 7,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_8 = 8,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_9 = 9,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_10 = 10,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_11 = 11,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_12 = 12,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_13 = 13,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_14 = 14,
    test_view_shows_what_the_download_writes_on_the_corpus_shard_15 = 15,
);

/// Compares the view and the download on every program of the corpus
/// archives in shard `slot`, printing one line per program (its tally and
/// time) as it goes.
fn corpus_shard(slot: usize) -> TestResult {
    let Some(vendor) = corpus_vendor() else {
        return Ok(());
    };
    let files: Vec<_> = knxprod_files(&vendor)
        .into_iter()
        .filter(|f| {
            f.file_name()
                .is_some_and(|n| in_shard(&n.to_string_lossy(), slot))
        })
        .collect();
    let started = std::time::Instant::now();
    let (mut programs, mut with_pages, mut unreadable) = (0, 0, 0);
    let mut total = Tally::default();
    let mut failures = Vec::new();
    for file in &files {
        let archive = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Ok(product) = bussard_product::read_knxprod(file) else {
            unreadable += 1;
            eprintln!("view acceptance: {archive} unreadable");
            continue;
        };
        for app in &product.applications {
            let at = std::time::Instant::now();
            let mut t = Tally::default();
            let outcome = check(app, &product, &mut t);
            eprintln!(
                "view acceptance: {archive} {} {t:?} {} {:.1?}",
                app.id,
                if outcome.is_ok() { "ok" } else { "FAILED" },
                at.elapsed()
            );
            match outcome {
                Ok(()) => {
                    programs += 1;
                    with_pages += usize::from(t.sets > 0);
                    total.sets += t.sets;
                    total.shown += t.shown;
                    total.objects += t.objects;
                    total.ignored += t.ignored;
                }
                Err(e) => failures.push(format!("{archive} {}: {e}", app.id)),
            }
        }
    }
    eprintln!(
        "view acceptance shard {slot}/{CORPUS_SHARDS}: {} archives ({unreadable} unreadable), \
         {programs} programs ({with_pages} with pages), {total:?}, {} failed, {:.0?}",
        files.len(),
        failures.len(),
        started.elapsed()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// Issue #375: the flash takes every stored value by ref, so the parameter
/// image is the same whether a value is keyed `hidden@<ref>` (the lock's
/// `hidden[]`) or `<label>@<ref>` (the device file), in memory and after a
/// save and reload, and once the evaluation moved the reached values to the
/// lock's keys (issue #380). Re-keying a value never changes what a download
/// writes.
#[test]
fn test_parameter_image_is_the_same_under_hidden_and_visible_keys() -> TestResult {
    let address: IndividualAddress = ADDRESS.parse()?;
    let (mut compared, mut moved, mut kept) = (0, 0, 0);
    for (id, xml) in FIXTURES {
        let app = parse_application_program(id, xml)?;
        let candidates = candidates(&app);
        let mut rng = Rng(seed(&app));
        for _ in 0..5 {
            let values = random_values(&candidates, &mut rng);
            if values.is_empty() {
                continue;
            }
            let keyed = |prefix: &str| -> Result<Model, String> {
                let mut model = one_device(&app.id)?;
                let device = &mut model.devices.get_mut(&address).ok_or("no device")?.device;
                for (reference, value) in &values {
                    device
                        .parameters
                        .insert(format!("{prefix}@{reference}"), value.clone());
                }
                Ok(model)
            };
            let visible = keyed("v")?;
            let hidden = keyed("hidden")?;
            let reloaded = Model::from_texts(&hidden.to_texts()?)?;
            // The lock indexes every ref: the save moves the values into the
            // device file under the lock's keys.
            let mut indexed = hidden.clone();
            let device = &mut indexed.devices.get_mut(&address).ok_or("no device")?.device;
            for (n, reference) in values.keys().enumerate() {
                device.lock.parameters.insert(
                    reference.clone(),
                    bussard_model::schema::LockedParameter {
                        key: format!("p-{n}"),
                        channel: None,
                        param: None,
                        default: None,
                    },
                );
            }
            // The evaluation moves the reached values to the lock's keys
            // (issue #380: the lock's index alone is not reachability); the
            // unreached ones stay hidden, and the save writes the moved ones
            // into the device file.
            let product = bussard_product::ProductData {
                applications: vec![app.clone()],
                ..ProductData::default()
            };
            let product = bussard_product::product_model::product_model(&app, &product);
            let mut products = ProductModels::default();
            products.insert(app.id.clone(), product.clone());
            let visibility =
                bussard_model::device_view::DeviceAnalysis::new(&indexed, &products, address)?
                    .visibility();
            let device = &mut indexed.devices.get_mut(&address).ok_or("no device")?.device;
            moved += bussard_model::device_view::show_reached_hidden(device, &product);
            for reference in values.keys() {
                let shown = visibility.get(reference).is_some_and(|v| v.shown);
                kept += usize::from(!shown);
                assert_eq!(
                    device
                        .parameters
                        .contains_key(&format!("hidden@{reference}")),
                    !shown,
                    "{id} {reference}"
                );
            }
            let texts = indexed.to_texts()?;
            let moved = Model::from_texts(&texts)?;
            let (expected, _) = parameter_overrides(Some(&visible), address);
            let image = compute_parameter_image(&app, &expected, &BTreeMap::new())?;
            for model in [&hidden, &reloaded, &moved] {
                let (overrides, _) = parameter_overrides(Some(model), address);
                assert_eq!(overrides, expected, "{id}");
                assert_eq!(
                    compute_parameter_image(&app, &overrides, &BTreeMap::new())?,
                    image,
                    "{id}"
                );
            }
            compared += 1;
        }
    }
    assert!(compared > 0);
    assert!(moved > 0 && kept > 0, "moved {moved}, kept {kept}");
    Ok(())
}

/// Issue #686: a reached, unlinked com-object whose flags are all disabled
/// gets its descriptor's type octet (priority and size code) with no flags,
/// as ETS writes it (`syn-com-objects`, object 2: `03 00`). The fixture's
/// object 4 is one; objects 5 to 9 are reached the same way, with flags.
/// The fixture is System B, where the default-only `<choose>`s in front of
/// objects 4, 5 and 8 select no branch (the Dynamic walk, issue #474), so the
/// test rewrites the mask to a System 7 one, where they are taken.
#[test]
fn test_dynamic_group_object_descriptors_keep_flagless_objects() -> TestResult {
    let (id, xml) = FIXTURES
        .iter()
        .find(|(id, _)| *id == "M-00FA_A-0563-10-0000")
        .ok_or("choose activity fixture")?;
    let xml = std::str::from_utf8(xml)?.replace("MV-07B0", "MV-0701");
    let app = parse_application_program(id, xml.as_bytes())?;
    let config = evaluate_dynamic(&app, &BTreeMap::new());
    let descriptors = dynamic_group_object_descriptors(&app, &config, &BTreeMap::new());
    let asaps: BTreeSet<u16> = descriptors.iter().map(|d| d.asap).collect();
    assert_eq!(asaps, BTreeSet::from([1, 4, 5, 6, 7, 8, 9]));
    let four = descriptors
        .iter()
        .find(|d| d.asap == 4)
        .ok_or("a descriptor for object 4")?;
    assert!(four.flags.is_empty(), "{:?}", four.flags);
    let linked = BTreeMap::from([(4u16, bussard_download::compute::LinkedObject::default())]);
    let linked_four = dynamic_group_object_descriptors(&app, &config, &linked)
        .into_iter()
        .find(|d| d.asap == 4)
        .ok_or("a descriptor for linked object 4")?;
    assert!(
        linked_four
            .flags
            .contains(bussard_model::Flags::COMMUNICATION)
    );
    Ok(())
}
