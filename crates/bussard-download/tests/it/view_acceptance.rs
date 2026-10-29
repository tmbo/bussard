//! The device view and the download agree (issue #345, the acceptance test
//! of the one Dynamic evaluator): for every fixture application, and with
//! `BUSSARD_PRODUCT_CORPUS` set every program of every archive in the
//! corpus, under the vendor defaults and 50 seeded random valid value sets
//! stored in the device file,
//!
//! - the refs the view shows ([`parameter_visibility`], `shown`) are the
//!   refs the image writes at the application level
//!   ([`dynamic_parameter_slots`] with a `param_ref_id`), the internal ones
//!   (`Access="None"`, which the view never lists) left out on both sides;
//! - the objects the view shows ([`shown_objects`]) are the ones the object
//!   table gets a descriptor for ([`dynamic_group_object_descriptors`]);
//! - [`ignored_overrides`] names exactly the stored values the image does
//!   not carry: on refs without a slot (and, for a ref without memory, that
//!   the evaluation does not reach), or replaced by an `<Assign>`.
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
use bussard_model::device_view::{ignored_overrides, parameter_visibility, shown_objects};
use bussard_model::dynamic::evaluate_dynamic;
use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};
use bussard_prod::image::dynamic_parameter_slots;
use bussard_prod::{
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

    // The view side.
    let visibility = parameter_visibility(&model, products, address).map_err(|e| e.to_string())?;
    let shown: BTreeSet<String> = visibility
        .iter()
        .filter(|(r, v)| v.shown && located.contains(*r) && !internal(r))
        .map(|(r, _)| r.clone())
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
    let view_objects: BTreeSet<u16> = shown_objects(&model, products, address)
        .map_err(|e| e.to_string())?
        .iter()
        // An object with every flag disabled is shown but gets no
        // descriptor (issue #474).
        .filter_map(|r| app.resolve(r))
        .filter(|(base, cref)| !base.flags.merge(cref.flags).to_flags().is_empty())
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
    let ignored: BTreeSet<String> = ignored_overrides(&model, products, address)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|o| o.reference)
        .collect();
    let expected: BTreeSet<String> = values
        .iter()
        .filter(|(r, _)| !r.starts_with("MD-") && held.contains(r.as_str()))
        .filter(|(r, _)| {
            // The image carries the stored value of a ref the evaluation
            // reaches (as its slot, or as the source of an `<Assign>`),
            // unless an `<Assign>` replaces it.
            let in_effect = reached.contains(r.as_str())
                && (placed_shown.contains(r.as_str()) || !config.is_assigned(None, r));
            !in_effect
        })
        .filter(|(r, v)| {
            let module = None;
            config.vendor_default(app, module, r).as_deref() != Some(v.as_str())
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
    let yaml = bussard_prod::product_model::model_yaml(app, product).map_err(|e| e.to_string())?;
    let model = ProductModel::from_yaml(&yaml, &app.id).map_err(|e| e.to_string())?;
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

/// Corpus-gated (`BUSSARD_PRODUCT_CORPUS`, dev/testing.md): the same over
/// every application program of every archive in the corpus.
#[test]
fn test_view_shows_what_the_download_writes_on_the_corpus() -> TestResult {
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
                    let outcome: Vec<(String, Option<String>, Result<Tally, String>)> =
                        match bussard_prod::read_knxprod(file) {
                            Err(_) => vec![(name, None, Ok(Tally::default()))],
                            Ok(product) => product
                                .applications
                                .iter()
                                .map(|app| {
                                    let mut tally = Tally::default();
                                    let result = check(app, &product, &mut tally).map(|()| tally);
                                    (name.clone(), Some(app.id.clone()), result)
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
    let (mut programs, mut with_pages, mut unreadable) = (0, 0, 0);
    let mut total = Tally::default();
    let mut failures = Vec::new();
    for (archive, app, outcome) in results {
        match (app, outcome) {
            (None, _) => unreadable += 1,
            (Some(_), Ok(t)) => {
                programs += 1;
                with_pages += usize::from(t.sets > 0);
                total.sets += t.sets;
                total.shown += t.shown;
                total.objects += t.objects;
                total.ignored += t.ignored;
            }
            (Some(app), Err(e)) => failures.push(format!("{archive} {app}: {e}")),
        }
    }
    eprintln!(
        "view acceptance: {} archives ({unreadable} unreadable), {programs} programs \
         ({with_pages} with pages), {total:?}, {} failed, {:.0?}",
        files.len(),
        failures.len(),
        started.elapsed()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(programs > 0, "no program compared");
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
            let product = bussard_prod::ProductData {
                applications: vec![app.clone()],
                ..ProductData::default()
            };
            let yaml = bussard_prod::product_model::model_yaml(&app, &product)?;
            let product = ProductModel::from_yaml(&yaml, &app.id)?;
            let mut products = ProductModels::default();
            products.insert(app.id.clone(), product.clone());
            let visibility = parameter_visibility(&indexed, &products, address)?;
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

/// Issue #474: a reached, unlinked com-object whose flags are all disabled
/// gets no group-object descriptor, as ETS leaves the Zennio Flat "dummy"
/// objects out of the table; the fixture's object 4 is one, objects 5 to 8
/// (reached the same way, with flags) keep theirs. Linked, it gets one.
#[test]
fn test_dynamic_group_object_descriptors_leave_out_flagless_objects() -> TestResult {
    let (id, xml) = FIXTURES
        .iter()
        .find(|(id, _)| *id == "M-00FA_A-0563-10-0000")
        .ok_or("choose activity fixture")?;
    let app = parse_application_program(id, xml)?;
    let config = evaluate_dynamic(&app, &BTreeMap::new());
    let asaps: BTreeSet<u16> = dynamic_group_object_descriptors(&app, &config, &BTreeMap::new())
        .iter()
        .map(|d| d.asap)
        .collect();
    assert_eq!(asaps, BTreeSet::from([1, 5, 6, 7, 8]));
    let linked = BTreeMap::from([(4u16, bussard_download::compute::LinkedObject::default())]);
    let asaps: BTreeSet<u16> = dynamic_group_object_descriptors(&app, &config, &linked)
        .iter()
        .map(|d| d.asap)
        .collect();
    assert!(asaps.contains(&4), "{asaps:?}");
    Ok(())
}
