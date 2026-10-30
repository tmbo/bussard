//! The flash-then-plan loop against knx-sim over the product catalog (issue
//! #346).
//!
//! For every application of the product corpus that bussard can flash and
//! knx-sim can simulate (masks `07B0`, `0705`, `0701`), the loop:
//!
//! 1. builds configurations: the vendor defaults, plus N seeded generated ones
//!    that flip the parameters a `<choose>` of the Dynamic section tests (the
//!    enable switches of inactive pages and channels) and pick random valid
//!    values for other shown parameters, each with a few links on the
//!    com-objects that configuration shows;
//! 2. flashes each to a fresh knx-sim device with `bussard flash`, then
//!    `bussard plan --json` must be a no-op: no change, no table write, no
//!    parameter octet, and the parameters decoded;
//! 3. applies a partial change set to the last configuration (a few
//!    parameters that keep the object table, a link added, a link removed)
//!    with `bussard apply`, plans (no-op), flashes again and plans (no-op).
//!
//! A property-only application on mask `0021` (the Jung IPS 300 SREG, issue
//! #390) has no com-objects and no `plan`: each configuration is flashed to a
//! fresh device and the flash must end with its property read-back verified.
//!
//! Step 4 of the issue (the same with Data Secure on) waits for the secure
//! group simulation; see `dev/testing.md`.
//!
//! The simulator is the separate `knx-sim` workspace. It runs as its own
//! process (`BUSSARD_KNX_SIM_BIN`, the `serve` binary) on a loopback port and
//! is reached over KNXnet/IP only, so no bussard crate links it. The `bussard`
//! binary always gets an explicit `127.0.0.1` gateway.
//!
//! Gated on `BUSSARD_PRODUCT_CORPUS` and `BUSSARD_KNX_SIM_BIN`; without
//! either the shards skip green. The synthetic source
//! (`test_sim_catalog_loop_synthetic_catalogue_shard_*`, epic #596) runs the same loop
//! over `tests-support/synthetic-products/` and needs only
//! `BUSSARD_KNX_SIM_BIN`. `scripts/sim-catalog-loop.sh` builds both
//! binaries and runs the shards. The applications are split over
//! [`SHARDS`] test functions that nextest runs in parallel, and further over
//! runners with `BUSSARD_SIM_LOOP_SHARD=<k>/<n>`. Known failures live in
//! `tests-support/product-corpus/sim-loop-baseline.json`; any other failure
//! fails the shard.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bussard_download::sweep::knxprod_files;
use bussard_download::{GroupObjectDescriptor, dynamic_group_object_descriptors, plan_flash};
use bussard_model::Flags;
use bussard_model::text_codec::TextCodec;
use bussard_prod::application::LoadOp;
use bussard_prod::dynamic::{DynamicConfig, evaluate_dynamic, visible_parameter_refs};
use bussard_prod::{AppSelection, ApplicationProgram, ParameterType};
use sha2::{Digest as _, Sha256};

type BoxError = Box<dyn std::error::Error>;
type TestResult = Result<(), BoxError>;

/// How many test functions split the applications of one runner.
const SHARDS: usize = 8;

/// The device's individual address on the simulated bus.
const DEVICE: &str = "1.1.10";

/// The masks knx-sim models and bussard flashes.
const SIM_MASKS: [&str; 3] = ["07B0", "0705", "0701"];

/// How long one `bussard` command may run before it counts as hung.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);

/// How long the simulator may take to load the product and listen.
const SIM_START_TIMEOUT: Duration = Duration::from_secs(60);

macro_rules! shard_tests {
    ($($name:ident = $index:expr),* $(,)?) => {
        $(
            /// One shard of the loop: the applications whose id hashes to it.
            #[test]
            fn $name() -> TestResult {
                run_shard($index)
            }
        )*
    };
}

shard_tests!(
    test_sim_catalog_loop_shard_0 = 0,
    test_sim_catalog_loop_shard_1 = 1,
    test_sim_catalog_loop_shard_2 = 2,
    test_sim_catalog_loop_shard_3 = 3,
    test_sim_catalog_loop_shard_4 = 4,
    test_sim_catalog_loop_shard_5 = 5,
    test_sim_catalog_loop_shard_6 = 6,
    test_sim_catalog_loop_shard_7 = 7,
);

/// The loop over the synthetic product catalogue (epic #596): every product
/// under `tests-support/synthetic-products/`, its committed `xml/` zipped
/// with the stub `knx_master.xml`, through the same flash, plan, seeded
/// configuration and apply steps as the corpus shards. Gated only on
/// `BUSSARD_KNX_SIM_BIN` (the `sim-conformance` CI job sets it), not on the
/// corpus; every product must run and pass, except a refusal listed in
/// `tests-support/synthetic-products/sim-loop-refusals.json` (the finding a
/// product exists for, #604) and a failure listed with the step it fails at
/// in `tests-support/synthetic-products/sim-loop-baseline.json` (the evidence
/// of an open bussard bug, like an `expect=differs` oracle row).
///
/// The catalogue grows to about forty products at roughly 10 s each, so the
/// products are split over [`SYNTHETIC_SHARDS`] test functions by the hash of
/// their application id, as the corpus shards are; nextest runs them side by
/// side. A shard that draws no product passes.
fn run_synthetic_shard(slot: usize) -> TestResult {
    let Some(sim) = std::env::var_os("BUSSARD_KNX_SIM_BIN").map(PathBuf::from) else {
        eprintln!("BUSSARD_KNX_SIM_BIN unset; skipping the synthetic sim loop.");
        return Ok(());
    };
    if !sim.is_file() {
        return Err(format!("BUSSARD_KNX_SIM_BIN={} is not a file", sim.display()).into());
    }
    let dir = std::env::temp_dir().join(format!(
        "bussard-sim-loop-synthetic-{}-{slot}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let products = synthetic_knxprods(&dir)?;
    assert!(
        products.iter().any(|p| p == "syn-minimal"),
        "the baseline product is missing: {products:?}"
    );
    let settings = Settings {
        corpus: dir.canonicalize()?,
        sim,
        configs: 2,
        seed: 346,
        filter: Vec::new(),
        runner: (0, 1),
        report: None,
        cache: None,
        work: None,
    };
    let reports = run_files(
        &settings,
        SYNTHETIC_SHARDS,
        slot,
        &read_baseline_at("../../tests-support/synthetic-products/sim-loop-baseline.json")?,
    );
    let _ = std::fs::remove_dir_all(&dir);
    let reports = reports?;
    let refusals = read_synthetic_refusals()?;
    let not_run: Vec<String> = reports
        .iter()
        .filter(|r| r.outcome == "skip")
        .filter(|r| {
            // A product whose refusal is the finding it exists for (#604).
            let detail = r.detail.as_deref().unwrap_or("");
            !refusals
                .get(&r.application)
                .is_some_and(|needle| detail.contains(needle.as_str()))
        })
        .map(|r| format!("{}: {}", r.application, r.detail.as_deref().unwrap_or("")))
        .collect();
    assert!(
        not_run.is_empty(),
        "synthetic products the loop skipped:\n{}",
        not_run.join("\n")
    );
    let now_run: Vec<&String> = refusals
        .keys()
        .filter(|app| {
            reports
                .iter()
                .any(|r| &r.application == *app && r.outcome != "skip")
        })
        .collect();
    assert!(
        now_run.is_empty(),
        "synthetic products bussard flashes now; drop them from sim-loop-refusals.json: {now_run:?}"
    );
    judge(&reports)
}

/// How many test functions split the synthetic catalogue.
const SYNTHETIC_SHARDS: usize = 4;

macro_rules! synthetic_shard_tests {
    ($($name:ident = $index:expr),* $(,)?) => {
        $(
            /// One shard of the synthetic catalogue loop
            /// ([`run_synthetic_shard`]).
            #[test]
            fn $name() -> TestResult {
                run_synthetic_shard($index)
            }
        )*
    };
}

synthetic_shard_tests!(
    test_sim_catalog_loop_synthetic_catalogue_shard_0 = 0,
    test_sim_catalog_loop_synthetic_catalogue_shard_1 = 1,
    test_sim_catalog_loop_synthetic_catalogue_shard_2 = 2,
    test_sim_catalog_loop_synthetic_catalogue_shard_3 = 3,
);

/// The synthetic products bussard is known to refuse, from
/// `tests-support/synthetic-products/sim-loop-refusals.json`: application id
/// to a phrase the refusal must contain. Each one is the finding its product
/// exists for, and names the open issue.
fn read_synthetic_refusals() -> Result<BTreeMap<String, String>, BoxError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products/sim-loop-refusals.json");
    let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let mut out = BTreeMap::new();
    if let Some(map) = value.get("refusals").and_then(|v| v.as_object()) {
        for (app, entry) in map {
            let needle = entry
                .get("contains")
                .and_then(|s| s.as_str())
                .ok_or_else(|| format!("sim-loop-refusals.json: {app} has no `contains`"))?;
            out.insert(app.clone(), needle.to_string());
        }
    }
    Ok(out)
}

/// Zips every synthetic product's `xml/` with the stub master into `dir` as
/// `<product>.knxprod`; returns the product names.
fn synthetic_knxprods(dir: &Path) -> Result<Vec<String>, BoxError> {
    use std::io::Write as _;
    let catalogue =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests-support/synthetic-products");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&catalogue)? {
        let product = entry?.path();
        let xml = product.join("xml");
        let Some(name) = product
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
        else {
            continue;
        };
        if !product.join("product.toml").is_file() || !xml.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        for manufacturer in std::fs::read_dir(&xml)? {
            let manufacturer = manufacturer?.path();
            let Some(m) = manufacturer
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
            else {
                continue;
            };
            for file in std::fs::read_dir(&manufacturer)? {
                let file = file?.path();
                if let Some(f) = file.file_name().map(|n| n.to_string_lossy().into_owned()) {
                    files.push((format!("{m}/{f}"), std::fs::read(&file)?));
                }
            }
        }
        files.sort();
        let mut zip =
            zip::ZipWriter::new(std::fs::File::create(dir.join(format!("{name}.knxprod")))?);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("knx_master.xml", opts)?;
        zip.write_all(b"<KNX/>")?;
        for (path, data) in files {
            zip.start_file(path, opts)?;
            zip.write_all(&data)?;
        }
        zip.finish()?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// What the environment asks for.
struct Settings {
    /// The directory holding the `.knxprod` files.
    corpus: PathBuf,
    /// The knx-sim `serve` binary.
    sim: PathBuf,
    /// Generated configurations per application, besides the defaults.
    configs: usize,
    /// The seed of the generator.
    seed: u64,
    /// Substrings of an application id or archive name to restrict the run.
    filter: Vec<String>,
    /// This runner's shard and the runner count.
    runner: (usize, usize),
    /// Where the per-shard JSON reports go.
    report: Option<PathBuf>,
    /// The parsed-product cache shared by the shards.
    cache: Option<PathBuf>,
    /// Where each application's work directory goes; kept after the run.
    work: Option<PathBuf>,
}

impl Settings {
    /// Reads the settings, `None` when the loop is not enabled.
    fn from_env() -> Result<Option<Settings>, BoxError> {
        let Some(corpus) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
            eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping the knx-sim catalog loop.");
            return Ok(None);
        };
        let Some(sim) = std::env::var_os("BUSSARD_KNX_SIM_BIN") else {
            eprintln!(
                "BUSSARD_KNX_SIM_BIN unset; skipping the knx-sim catalog loop \
                 (scripts/sim-catalog-loop.sh builds knx-sim and sets it)."
            );
            return Ok(None);
        };
        let sim = PathBuf::from(sim);
        if !sim.is_file() {
            return Err(format!("BUSSARD_KNX_SIM_BIN={} is not a file", sim.display()).into());
        }
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let configs = match var("BUSSARD_SIM_LOOP_CONFIGS") {
            Some(v) => v.trim().parse()?,
            None => 2,
        };
        let seed = match var("BUSSARD_SIM_LOOP_SEED") {
            Some(v) => v.trim().parse()?,
            None => 346,
        };
        let filter = var("BUSSARD_SIM_LOOP_FILTER")
            .map(|f| {
                f.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let runner = match var("BUSSARD_SIM_LOOP_SHARD") {
            Some(v) => {
                let (k, n) = v
                    .split_once('/')
                    .ok_or("BUSSARD_SIM_LOOP_SHARD must read <k>/<n>, e.g. 0/4")?;
                let (k, n): (usize, usize) = (k.trim().parse()?, n.trim().parse()?);
                if n == 0 || k >= n {
                    return Err(format!("BUSSARD_SIM_LOOP_SHARD={v}: need 0 <= k < n").into());
                }
                (k, n)
            }
            None => (0, 1),
        };
        // Absolute paths: the work directories symlink into both.
        let corpus = vendor_dir(PathBuf::from(corpus)).canonicalize()?;
        let cache = match var("BUSSARD_SIM_LOOP_CACHE").map(PathBuf::from) {
            Some(dir) => {
                std::fs::create_dir_all(&dir)?;
                Some(dir.canonicalize()?)
            }
            None => None,
        };
        Ok(Some(Settings {
            corpus,
            sim,
            configs,
            seed,
            filter,
            runner,
            report: var("BUSSARD_SIM_LOOP_REPORT").map(PathBuf::from),
            cache,
            work: var("BUSSARD_SIM_LOOP_WORK").map(PathBuf::from),
        }))
    }
}

/// The corpus variable may name the product-corpus directory, its `cache/`,
/// or the vendor directory (dev/testing.md).
fn vendor_dir(dir: PathBuf) -> PathBuf {
    [dir.join("cache/vendor"), dir.join("vendor")]
        .into_iter()
        .find(|d| d.is_dir())
        .unwrap_or(dir)
}

/// FNV-1a: a stable hash for assigning an application to a shard.
fn fnv1a(text: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// The shard
// ---------------------------------------------------------------------------

/// What happened to one application.
#[derive(Debug, Clone, serde::Serialize)]
struct AppReport {
    /// The application program id.
    application: String,
    /// The archive it came from.
    archive: String,
    /// The mask.
    mask: String,
    /// `pass`, `fail` or `skip`.
    outcome: &'static str,
    /// How many configurations were flashed.
    configurations: usize,
    /// The first failing step (`flash[1]`, `plan after apply`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<String>,
    /// What differs, or why it was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    /// Whether the baseline lists it, failing at this step.
    known: bool,
    /// Wall-clock seconds.
    seconds: f64,
}

/// Runs the applications of in-process shard `index`.
fn run_shard(index: usize) -> TestResult {
    let Some(settings) = Settings::from_env()? else {
        return Ok(());
    };
    let total = settings.runner.1 * SHARDS;
    let slot = settings.runner.0 * SHARDS + index;
    let baseline = read_baseline()?;
    let reports = run_files(&settings, total, slot, &baseline)?;
    judge(&reports)
}

/// Runs every application of the `.knxprod` files in `settings.corpus` whose
/// id hashes to `slot` of `total`; returns one report per application.
fn run_files(
    settings: &Settings,
    total: usize,
    slot: usize,
    baseline: &BTreeMap<String, String>,
) -> Result<Vec<AppReport>, BoxError> {
    let files = knxprod_files(&settings.corpus);
    if files.is_empty() {
        return Err(format!("{} holds no .knxprod files", settings.corpus.display()).into());
    }
    let started = Instant::now();
    // Application id to the archive it ran from: an id that two archives
    // carry (an MDT push-button database ships the same program under two
    // product files) runs once and is reported as skipped the second time.
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut reports: Vec<AppReport> = Vec::new();
    for file in &files {
        let archive = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let mut mine: Vec<String> = Vec::new();
        let product =
            bussard_prod::read_knxprod_selected(file, None, settings.cache.as_deref(), |catalog| {
                mine = catalog
                    .application_ids
                    .iter()
                    .filter(|id| fnv1a(id) % total as u64 == slot as u64)
                    .filter(|id| {
                        settings.filter.is_empty()
                            || settings
                                .filter
                                .iter()
                                .any(|f| id.contains(f.as_str()) || archive.contains(f.as_str()))
                    })
                    .cloned()
                    .collect();
                AppSelection::Exact(mine.clone())
            });
        let product = match product {
            Ok(p) => p,
            // The corpus sweep reports parse failures; say so only when this
            // shard wanted something from the archive.
            Err(e) => {
                for id in &mine {
                    reports.push(skipped(id, &archive, format!("archive not read: {e}")));
                }
                continue;
            }
        };
        // Each work model gets its program's model file from the parse
        // above, written when the program runs, so no command parses every
        // program of the archive to complete the models (the ABB i-bus
        // database holds hundreds).
        let mut product = product;
        let apps = std::mem::take(&mut product.applications);
        let mut seed = |app: &ApplicationProgram, dir: &Path| -> Result<(), String> {
            product.applications = vec![app.clone()];
            let written = bussard_prod::product_model::write_product_models(&product, dir);
            product.applications.clear();
            written.map(|_| ()).map_err(|e| e.to_string())
        };
        for id in mine.iter().filter(|id| !apps.iter().any(|a| &a.id == *id)) {
            reports.push(skipped(
                id,
                &archive,
                "not in the parsed archive: the catalog lists it, the parse returned no program"
                    .to_string(),
            ));
        }
        for app in &apps {
            if !mine.contains(&app.id) {
                continue;
            }
            if let Some(first) = seen.get(&app.id) {
                reports.push(skipped(
                    &app.id,
                    &archive,
                    format!("duplicate application id: already run from {first}"),
                ));
                continue;
            }
            seen.insert(app.id.clone(), archive.clone());
            let report = run_application(settings, file, &archive, app, &mut seed, baseline);
            eprintln!(
                "sim-loop {:<44} {:<4} {:<5} {:>2} cfg {:>6.1}s {}{}",
                report.application,
                report.mask,
                report.outcome,
                report.configurations,
                report.seconds,
                report.step.as_deref().unwrap_or(""),
                report
                    .detail
                    .as_deref()
                    .map(|d| format!(": {}", first_line(d)))
                    .unwrap_or_default(),
            );
            reports.push(report);
        }
    }
    if let Some(dir) = &settings.report {
        std::fs::create_dir_all(dir)?;
        let name = format!("shard-{slot:03}-of-{total:03}.json");
        std::fs::write(dir.join(name), serde_json::to_string_pretty(&reports)?)?;
    }
    let count = |o: &str| reports.iter().filter(|r| r.outcome == o).count();
    eprintln!(
        "sim-loop shard {slot}/{total}: {} applications, {} pass, {} fail ({} known), {} skip in {:.0}s",
        reports.len(),
        count("pass"),
        count("fail"),
        reports.iter().filter(|r| r.known).count(),
        count("skip"),
        started.elapsed().as_secs_f64()
    );
    Ok(reports)
}

/// Fails on any failure the baseline does not list.
fn judge(reports: &[AppReport]) -> TestResult {
    let new: Vec<String> = reports
        .iter()
        .filter(|r| r.outcome == "fail" && !r.known)
        .map(|r| {
            format!(
                "{} ({}): {}: {}",
                r.application,
                r.archive,
                r.step.as_deref().unwrap_or("?"),
                r.detail.as_deref().unwrap_or("")
            )
        })
        .collect();
    for r in reports.iter().filter(|r| r.outcome == "pass" && r.known) {
        eprintln!(
            "sim-loop: {} passes now; drop it from sim-loop-baseline.json",
            r.application
        );
    }
    if new.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} application(s) failed the flash-then-plan loop:\n{}",
            new.len(),
            new.join("\n\n")
        )
        .into())
    }
}

/// The report of an application the loop did not run, with the reason.
fn skipped(id: &str, archive: &str, why: String) -> AppReport {
    eprintln!("sim-loop {id:<44} skip ({archive}): {why}");
    AppReport {
        application: id.to_string(),
        archive: archive.to_string(),
        mask: String::new(),
        outcome: "skip",
        configurations: 0,
        step: None,
        detail: Some(why),
        known: false,
        seconds: 0.0,
    }
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

/// The checked-in known failures: application id to the step that fails.
/// A known application that fails at another step is a regression.
fn read_baseline() -> Result<BTreeMap<String, String>, BoxError> {
    read_baseline_at("../../tests-support/product-corpus/sim-loop-baseline.json")
}

/// The known failures of a baseline file, relative to this crate's manifest
/// directory; a missing file lists none.
fn read_baseline_at(relative: &str) -> Result<BTreeMap<String, String>, BoxError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(BTreeMap::new());
    };
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let mut out = BTreeMap::new();
    if let Some(map) = value.get("known_failures").and_then(|v| v.as_object()) {
        for (app, entry) in map {
            let step = entry
                .get("step")
                .and_then(|s| s.as_str())
                .ok_or_else(|| format!("{relative}: {app} has no step"))?;
            out.insert(app.clone(), step.to_string());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// One application
// ---------------------------------------------------------------------------

/// Writes the product model of a program into a model directory.
type Seed<'a> = dyn FnMut(&ApplicationProgram, &Path) -> Result<(), String> + 'a;

/// Why an application stopped.
enum Stop {
    /// Not something this loop can run.
    Skip(String),
    /// A step failed.
    Fail(String, String),
}

fn run_application(
    settings: &Settings,
    file: &Path,
    archive: &str,
    app: &ApplicationProgram,
    seed: &mut Seed<'_>,
    baseline: &BTreeMap<String, String>,
) -> AppReport {
    let started = Instant::now();
    let mask = app
        .mask_version
        .as_deref()
        .map(|m| m.trim().trim_start_matches("MV-").to_ascii_uppercase())
        .unwrap_or_default();
    let mut report = AppReport {
        application: app.id.clone(),
        archive: archive.to_string(),
        mask: mask.clone(),
        outcome: "pass",
        configurations: 0,
        step: None,
        detail: None,
        known: false,
        seconds: 0.0,
    };
    let result = run_loop(settings, file, app, seed, &mask, &mut report.configurations);
    match result {
        Ok(()) => {}
        Err(Stop::Skip(why)) => {
            report.outcome = "skip";
            report.detail = Some(why);
        }
        Err(Stop::Fail(step, detail)) => {
            report.outcome = "fail";
            report.step = Some(step);
            report.detail = Some(detail);
        }
    }
    report.known = match (&report.step, baseline.get(&app.id)) {
        (Some(step), Some(known)) => step == known,
        (None, Some(_)) => true,
        _ => false,
    };
    report.seconds = started.elapsed().as_secs_f64();
    report
}

/// Maps an infrastructure error (a file write, a spawn) to a failure of `step`.
fn infra<E: std::fmt::Display>(step: &str) -> impl FnOnce(E) -> Stop + '_ {
    move |e| Stop::Fail(step.to_string(), format!("harness: {e}"))
}

fn run_loop(
    settings: &Settings,
    file: &Path,
    app: &ApplicationProgram,
    seed: &mut Seed<'_>,
    mask: &str,
    flashed: &mut usize,
) -> Result<(), Stop> {
    if mask == PROPERTY_ONLY_MASK {
        return run_property_loop(settings, file, app, seed, flashed);
    }
    if !SIM_MASKS.contains(&mask) {
        return Err(Stop::Skip(format!("mask {mask} is not simulated")));
    }
    let mask_word =
        u16::from_str_radix(mask, 16).map_err(|e| Stop::Skip(format!("mask {mask}: {e}")))?;
    // The corpus sweep's verdict: an application whose plan lowers.
    if let Err(e) = plan_flash(
        app,
        DEVICE,
        mask_word,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    ) {
        return Err(Stop::Skip(format!("bussard does not flash it: {e}")));
    }

    let mut rng = SplitMix64::new(settings.seed ^ fnv1a(&app.id));
    let mut configs = vec![Configuration::defaults(app, &mut rng)];
    for k in 1..=settings.configs {
        configs.push(Configuration::generated(app, &mut rng, k));
    }
    if configs.iter().all(|c| c.links.is_empty()) {
        return Err(Stop::Skip(
            "no configuration shows a com-object to link (plan needs links)".to_string(),
        ));
    }

    let work = Work::create(settings, app, file).map_err(infra("setup"))?;
    seed(app, &work.model).map_err(infra("write the product model"))?;
    let mut bench = Bench {
        settings,
        work: &work,
        app,
        mask,
        sim: None,
        gateway: String::new(),
    };

    // Each configuration goes to a factory-fresh device: flash, then plan.
    let mut last: Option<Configuration> = None;
    for (k, config) in configs.iter().enumerate() {
        if config.links.is_empty() {
            continue;
        }
        bench.fresh_device(k == 0)?;
        bench.write_device(config).map_err(infra("setup"))?;
        bench.flash(&format!("flash[{k}] ({})", config.label))?;
        *flashed += 1;
        bench.plan_noop(&format!("plan after flash[{k}] ({})", config.label))?;
        last = Some(config.clone());
    }
    let Some(last) = last else {
        return Ok(());
    };

    // The everyday edit on the last one: apply a partial change, plan, then
    // a full flash of the same model must change nothing the plan sees.
    let partial = last.partial_change(app, &mut rng);
    bench.write_device(&partial).map_err(infra("setup"))?;
    // Issue #540: a link to an object the flash left unlinked changes the
    // group-object table on System B. The plan names the reload, `apply`
    // runs it, and the plan after it (which compares the table) is a no-op.
    let reload = bench.object_table_reload("plan before apply")?;
    eprintln!(
        "sim-loop: {}: the partial change reloads the group-object table: {reload}",
        app.id
    );
    bench.apply("apply partial change", reload)?;
    bench.plan_noop("plan after apply")?;
    bench.flash("flash after apply")?;
    bench.plan_noop("plan after flash after apply")?;

    // A configuration flashed over another one (what `apply` asks for when a
    // parameter change reshapes the object table): the first configuration
    // with links, without --force.
    if let Some((k, first)) = configs
        .iter()
        .enumerate()
        .find(|(_, c)| !c.links.is_empty())
        .filter(|_| configs.iter().filter(|c| !c.links.is_empty()).count() > 1)
    {
        bench.write_device(first).map_err(infra("setup"))?;
        bench.flash(&format!("flash[{k}] ({}) over the last", first.label))?;
        bench.plan_noop(&format!(
            "plan after flash[{k}] ({}) over the last",
            first.label
        ))?;
    }
    drop(bench);
    if settings.work.is_none() {
        let _ = std::fs::remove_dir_all(&work.root);
    }
    Ok(())
}

/// The mask of a property-only application knx-sim simulates (issue #390).
const PROPERTY_ONLY_MASK: &str = "0021";

/// The loop for a property-only application (issue #390): the defaults and
/// the generated configurations, each flashed to a fresh device; the flash
/// must report its property read-back verified. There is nothing to link and
/// no `plan` for the family.
fn run_property_loop(
    settings: &Settings,
    file: &Path,
    app: &ApplicationProgram,
    seed: &mut Seed<'_>,
    flashed: &mut usize,
) -> Result<(), Stop> {
    let plan = plan_flash(
        app,
        DEVICE,
        0x0021,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )
    .map_err(|e| Stop::Skip(format!("bussard does not flash it: {e}")))?;
    if !plan.is_property_only() {
        return Err(Stop::Skip("not a property-only procedure".to_string()));
    }
    let mut rng = SplitMix64::new(settings.seed ^ fnv1a(&app.id));
    let mut configs = vec![Configuration::defaults(app, &mut rng)];
    for k in 1..=settings.configs {
        configs.push(Configuration::generated(app, &mut rng, k));
    }
    let work = Work::create(settings, app, file).map_err(infra("setup"))?;
    seed(app, &work.model).map_err(infra("write the product model"))?;
    let mut bench = Bench {
        settings,
        work: &work,
        app,
        mask: PROPERTY_ONLY_MASK,
        sim: None,
        gateway: String::new(),
    };
    for (k, config) in configs.iter().enumerate() {
        bench.fresh_device(k == 0)?;
        bench.write_device(config).map_err(infra("setup"))?;
        bench.flash_properties(&format!("flash[{k}] ({})", config.label))?;
        *flashed += 1;
    }
    drop(bench);
    if settings.work.is_none() {
        let _ = std::fs::remove_dir_all(&work.root);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Configurations
// ---------------------------------------------------------------------------

/// A device configuration: parameter values by device-file ref key, and links
/// by com-object number.
#[derive(Debug, Clone)]
struct Configuration {
    /// `defaults`, `generated 1`, ...
    label: String,
    /// Ref key (`P-12_R-3`, `MD-1_M-2_MI-1_P-3_R-4`) to value.
    values: BTreeMap<String, String>,
    /// Com-object number to its links.
    links: BTreeMap<u16, Link>,
    /// The next free group address number.
    next_ga: u32,
}

/// The links of one com-object.
#[derive(Debug, Clone, Default)]
struct Link {
    send: Option<String>,
    listen: Vec<String>,
}

/// The shown com-objects of a configuration, by number.
fn shown_objects(app: &ApplicationProgram, config: &DynamicConfig) -> Vec<GroupObjectDescriptor> {
    dynamic_group_object_descriptors(app, config, &BTreeMap::new())
}

/// The object table shape a configuration gives: what a parameter change
/// must keep for `apply` to write it as a parameter download.
fn object_shape(app: &ApplicationProgram, values: &BTreeMap<String, String>) -> Vec<(u16, u8, u8)> {
    let config = evaluate_dynamic(app, values);
    shown_objects(app, &config)
        .iter()
        .map(|d| (d.asap, d.flags.bits(), d.size_code))
        .collect()
}

/// The parameter refs a `<when>` in the application's own Dynamic section
/// tests on the way to a parameter or object (the conditions `bussard
/// device` lists as what enables an inactive page, and those that gate a
/// single ref inside a page): the enable switches. Conditions inside a
/// `<ModuleDef>` are not counted; their switches take their turn with the
/// other parameters.
fn switches(app: &ApplicationProgram) -> HashSet<String> {
    let index = bussard_model::dynamic::RefIndex::new(app);
    index
        .parameters()
        .chain(index.com_objects())
        .flat_map(|(_, occurrences)| occurrences)
        .filter(|o| o.module_def.is_none())
        .flat_map(|o| o.gates.iter().map(|g| g.param_ref_id.clone()))
        .collect()
}

/// Whether a load-procedure op reads the device and refuses the download on a
/// mismatch: `LdCtrlCompareProp`, `LdCtrlCompareRelMem` or `LdCtrlCompareMem`
/// (kept raw by the parser).
fn is_device_compare(op: &LoadOp) -> bool {
    match op {
        LoadOp::CompareProp { .. } | LoadOp::CompareRelMem { .. } => true,
        LoadOp::Raw { name, .. } => name == "LdCtrlCompareMem",
        _ => false,
    }
}

/// The full `Parameter` ids that state the device identity: a `<choose>` of
/// the application's parsed load procedure, the one `bussard-download`
/// lowers, tests one of their refs and one of its branches holds a device
/// compare. A real device has one fixed identity (and knx-sim seeds the one
/// the vendor defaults select, #400), so the parameter only says which
/// hardware the project expects; flipping it makes the device refuse the
/// download at the compare, as ETS would (#407). The generator leaves such a
/// parameter at its vendor default.
fn identity_parameters(app: &ApplicationProgram) -> HashSet<String> {
    let mut out = HashSet::new();
    for lp in &app.load_procedures {
        for (i, op) in lp.ops.iter().enumerate() {
            if !is_device_compare(op) {
                continue;
            }
            for guard in lp.guards_of(i) {
                let Some(choose) = lp.chooses.get(guard.choose) else {
                    continue;
                };
                let full = format!("{}_{}", app.id, choose.param_ref_id);
                if let Some(pref) = app.parameter_refs.get(&full) {
                    out.insert(pref.ref_id.clone());
                }
            }
        }
    }
    out
}

/// A random valid value for an app-relative parameter ref, `None` for one
/// the user cannot set, whose type has no value to draw, or that states the
/// device identity ([`identity_parameters`]).
fn random_value(app: &ApplicationProgram, param_ref: &str, rng: &mut SplitMix64) -> Option<String> {
    let pref = app.parameter_refs.get(&format!("{}_{param_ref}", app.id))?;
    if identity_parameters(app).contains(&pref.ref_id) {
        return None;
    }
    let param = app.parameters.get(&pref.ref_id)?;
    let access = pref.access.as_deref().or(param.access.as_deref());
    if matches!(access, Some("None") | Some("Read")) {
        return None;
    }
    let kind = &app
        .parameter_types
        .get(param.parameter_type.as_deref()?)?
        .kind;
    let codec = TextCodec::from_declaration(app.text_parameter_encoding.as_deref());
    draw_value(kind, codec, rng)
}

/// A random value inside a parameter type's declared range: an enumeration
/// member, an integer between the type's `minInclusive` and `maxInclusive`
/// (both bounds declared, the span computed wide so a full 64-bit signed
/// range cannot overflow), or a text that fits its field in the program's
/// code page (`codec`, #401). `None` for a type with no declared range to
/// draw from (float, time, an integer missing a bound): the parameter keeps
/// its vendor default. A vendor default outside its own type is the
/// vendor's, not the generator's (#399).
fn draw_value(kind: &ParameterType, codec: TextCodec, rng: &mut SplitMix64) -> Option<String> {
    match kind {
        ParameterType::Text {
            size_bits: Some(bits),
        } => draw_text((*bits / 8) as usize, codec, rng),
        ParameterType::Enum { values, .. } if !values.is_empty() => {
            let i = usize::try_from(rng.below(values.len() as u64)).ok()?;
            values.get(i).map(|v| v.value.to_string())
        }
        ParameterType::Int {
            min: Some(min),
            max: Some(max),
            ..
        } if max >= min => {
            let span = i128::from(*max) - i128::from(*min) + 1;
            let pick = match u64::try_from(span) {
                Ok(span) => i128::from(rng.below(span)),
                // The whole 64-bit range: any draw is inside it.
                Err(_) => i128::from(rng.next()),
            };
            let value = i64::try_from(i128::from(*min) + pick).ok()?;
            (*min..=*max).contains(&value).then(|| value.to_string())
        }
        _ => None,
    }
}

/// A label of 1 to 12 characters that fits `len` octets in `codec`: ASCII
/// letters and digits, plus accented letters when the code page holds them
/// (#401). `None` for a field with no octets.
fn draw_text(len: usize, codec: TextCodec, rng: &mut SplitMix64) -> Option<String> {
    const ASCII: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const ACCENTED: &str = "äöüÄÖÜßéèçñ";
    if len == 0 {
        return None;
    }
    let mut pool: Vec<char> = ASCII.chars().collect();
    pool.extend(
        ACCENTED
            .chars()
            .filter(|c| codec.encode(&c.to_string(), 4).is_ok()),
    );
    let want = 1 + rng.below(12);
    let mut text = String::new();
    for _ in 0..want {
        let i = usize::try_from(rng.below(pool.len() as u64)).ok()?;
        let mut next = text.clone();
        next.push(*pool.get(i)?);
        // A character that would overflow the field is skipped.
        if codec.encode(&next, len).is_ok() {
            text = next;
        }
    }
    if text.is_empty() {
        // Every draw overflowed (an accented letter in one UTF-8 octet): one
        // ASCII letter fits any field.
        let i = usize::try_from(rng.below(26)).ok()?;
        text.push(*pool.get(i)?);
    }
    Some(text)
}

impl Configuration {
    /// The vendor defaults with a few links.
    fn defaults(app: &ApplicationProgram, rng: &mut SplitMix64) -> Configuration {
        let mut config = Configuration {
            label: "defaults".to_string(),
            values: BTreeMap::new(),
            links: BTreeMap::new(),
            next_ga: 1,
        };
        config.add_links(app, rng, 4);
        config
    }

    /// A seeded configuration: each shown enable switch is flipped with
    /// probability 2/3 and each other shown parameter with 1/4, for a few
    /// rounds so a switch a flipped one shows gets its turn too.
    fn generated(app: &ApplicationProgram, rng: &mut SplitMix64, k: usize) -> Configuration {
        let switches = switches(app);
        let mut values: BTreeMap<String, String> = BTreeMap::new();
        let mut decided: HashSet<String> = HashSet::new();
        for _round in 0..4 {
            let config = evaluate_dynamic(app, &values);
            let mut changed = false;
            for v in visible_parameter_refs(app, &config) {
                let shown = config
                    .parameter_placements
                    .get(v.index)
                    .is_some_and(|p| p.shown);
                if !shown || !decided.insert(v.ref_key.clone()) {
                    continue;
                }
                let odds = if switches.contains(&v.param_ref_id) {
                    (2, 3)
                } else {
                    (1, 4)
                };
                if rng.below(odds.1) < odds.0
                    && let Some(value) = random_value(app, &v.param_ref_id, rng)
                {
                    values.insert(v.ref_key, value);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        // Keep only what the final configuration shows: a value it does not
        // reach is never written (#321) and would only be noise in the file.
        let config = evaluate_dynamic(app, &values);
        let reached: HashSet<String> = visible_parameter_refs(app, &config)
            .into_iter()
            .map(|v| v.ref_key)
            .collect();
        values.retain(|k, _| reached.contains(k));
        let mut out = Configuration {
            label: format!("generated {k}"),
            values,
            links: BTreeMap::new(),
            next_ga: 1,
        };
        out.add_links(app, rng, 6);
        out
    }

    /// Links up to `count` shown com-objects: a sending object gets a send
    /// address, a writable one a listening address.
    fn add_links(&mut self, app: &ApplicationProgram, rng: &mut SplitMix64, count: usize) {
        let config = evaluate_dynamic(app, &self.values);
        let mut candidates: Vec<GroupObjectDescriptor> = shown_objects(app, &config)
            .into_iter()
            .filter(|d| !self.links.contains_key(&d.asap))
            .filter(|d| d.flags.intersects(Flags::WRITE | Flags::TRANSMIT))
            .collect();
        for _ in 0..count {
            if candidates.is_empty() {
                break;
            }
            let i = rng.below(candidates.len() as u64) as usize;
            let d = candidates.swap_remove(i);
            let mut link = Link::default();
            if d.flags.contains(Flags::TRANSMIT) {
                link.send = Some(self.take_ga());
            }
            if d.flags.contains(Flags::WRITE) && (link.send.is_none() || rng.below(2) == 0) {
                link.listen.push(self.take_ga());
            }
            self.links.insert(d.asap, link);
        }
    }

    fn take_ga(&mut self) -> String {
        let n = self.next_ga;
        self.next_ga += 1;
        format!("1/{}/{}", n / 256, n % 256)
    }

    /// The partial change set: up to three shown parameters take another
    /// value that keeps the object table, one link is added on an object
    /// that had none and one removed.
    fn partial_change(&self, app: &ApplicationProgram, rng: &mut SplitMix64) -> Configuration {
        let mut out = self.clone();
        out.label = format!("{} + partial change", self.label);
        let shape = object_shape(app, &self.values);
        let config = evaluate_dynamic(app, &self.values);
        let mut refs: Vec<(String, String)> = visible_parameter_refs(app, &config)
            .into_iter()
            .filter(|v| {
                config
                    .parameter_placements
                    .get(v.index)
                    .is_some_and(|p| p.shown)
            })
            .map(|v| (v.ref_key, v.param_ref_id))
            .collect();
        let mut changed = 0;
        while changed < 3 && !refs.is_empty() {
            let i = rng.below(refs.len() as u64) as usize;
            let (key, param_ref) = refs.swap_remove(i);
            let Some(value) = random_value(app, &param_ref, rng) else {
                continue;
            };
            if out.values.get(&key) == Some(&value) {
                continue;
            }
            let mut trial = out.values.clone();
            trial.insert(key, value);
            if object_shape(app, &trial) == shape {
                out.values = trial;
                changed += 1;
            }
        }
        // One link in, on an object the flashed configuration leaves
        // unlinked (issue #540: the flash cleared its communication flag, so
        // `apply` must reload the group-object table), then one of the old
        // links out (when another stays).
        let old: Vec<u16> = out.links.keys().copied().collect();
        out.add_links(app, rng, 1);
        if old.len() > 1 {
            let i = rng.below(old.len() as u64) as usize;
            if let Some(k) = old.get(i) {
                out.links.remove(k);
            }
        }
        out
    }

    /// The device file.
    fn device_toml(&self) -> String {
        let mut s = format!(
            "address = \"{DEVICE}\"\nname = \"sim loop ({})\"\n",
            self.label
        );
        if !self.values.is_empty() {
            s.push_str("\n[parameters]\n");
            for (key, value) in &self.values {
                s.push_str(&format!("\"p@{key}\" = \"{value}\"\n"));
            }
        }
        if !self.links.is_empty() {
            s.push_str("\n[links]\n");
            for (number, link) in &self.links {
                if let Some(send) = &link.send {
                    s.push_str(&format!("{number}.send = \"{send}\"\n"));
                }
                if !link.listen.is_empty() {
                    let list: Vec<String> =
                        link.listen.iter().map(|g| format!("\"{g}\"")).collect();
                    s.push_str(&format!("{number}.listen = [{}]\n", list.join(", ")));
                }
            }
        }
        s
    }

    /// `groups.toml` declaring every address the links use.
    fn groups_toml(&self) -> String {
        let mut gas: BTreeSet<&str> = BTreeSet::new();
        for link in self.links.values() {
            gas.extend(link.send.as_deref());
            gas.extend(link.listen.iter().map(String::as_str));
        }
        let mut s = String::from("project = \"sim loop\"\n\ngroups = [\n");
        for ga in gas {
            s.push_str(&format!(
                "  {{ address = \"{ga}\", name = \"ga {ga}\" }},\n"
            ));
        }
        s.push_str("]\n");
        s
    }
}

/// SplitMix64: a small seeded generator, so a run is reproducible.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> SplitMix64 {
        SplitMix64(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (`0` for `n == 0`).
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

// ---------------------------------------------------------------------------
// The work directory, the simulator and the bussard commands
// ---------------------------------------------------------------------------

/// One application's work directory: the model, the archive, the sim config.
struct Work {
    root: PathBuf,
    model: PathBuf,
    archive: PathBuf,
}

impl Work {
    fn create(settings: &Settings, app: &ApplicationProgram, file: &Path) -> std::io::Result<Work> {
        let base = settings
            .work
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("bussard-sim-loop"));
        let root = base.join(format!("{}-{}", app.id, std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let model = root.join("model");
        std::fs::create_dir_all(model.join("products"))?;
        std::fs::create_dir_all(model.join("devices"))?;
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "product.knxprod".to_string());
        let archive = model.join("products").join(name);
        link_or_copy(file, &archive)?;
        // The shards share one parsed-product cache, so an archive with many
        // applications (the ABB i-bus database holds hundreds) is parsed once
        // per run, not once per application.
        if let Some(cache) = &settings.cache {
            std::fs::create_dir_all(cache)?;
            std::fs::create_dir_all(model.join(".bussard"))?;
            link_or_copy(cache, &model.join(".bussard").join("products"))?;
        }
        Ok(Work {
            root,
            model,
            archive,
        })
    }
}

/// Symlinks `target` at `link` (an archive can be 150 MB); copies a file
/// where symlinks are unavailable.
fn link_or_copy(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(not(unix))]
    {
        std::fs::copy(target, link).map(|_| ())
    }
}

/// How many tunnelling addresses the download of `app` writes to the
/// device's KNXnet/IP parameter object (issue #455): its
/// `AdditionalAddressesCount`, except on a property-only procedure (mask
/// 0021), which writes the object itself.
fn knxnet_tunnels(app: &ApplicationProgram, mask: &str) -> u16 {
    if mask == "0021" {
        return 0;
    }
    app.additional_addresses_count.unwrap_or(0)
}

/// The `[knxnet]` table ETS's project gives a device with a KNX IP interface
/// built in (the ETS sweep, issue #455): DHCP, a friendly name, and the
/// highest tunnelling addresses of the device's line. Empty for any other.
fn knxnet_table(app: &ApplicationProgram, mask: &str) -> String {
    let n = knxnet_tunnels(app, mask);
    if n == 0 {
        return String::new();
    }
    let tunnels: Vec<String> = (0..n)
        .map(|i| format!("\"1.1.{}\"", 256 - u32::from(n) + u32::from(i)))
        .collect();
    format!(
        "\n[knxnet]\nassignment = \"dhcp\"\nfriendly_name = \"sim loop\"\ntunnels = [{}]\n",
        tunnels.join(", ")
    )
}

/// A running knx-sim, killed on drop.
struct Sim {
    child: Child,
    port: u16,
}

impl Sim {
    fn start(
        settings: &Settings,
        work: &Work,
        app: &ApplicationProgram,
        mask: &str,
    ) -> Result<Sim, BoxError> {
        let port = free_udp_port()?;
        // Theben's 0701 family drives its load-state machines memory-mapped;
        // bussard picks that from the mask, and the sim must match.
        let lsm = if mask == "0701" { "memory" } else { "property" };
        let mut yaml = format!(
            "gateway:\n  host: \"127.0.0.1\"\n  port: {port}\n\ndevices:\n  - address: \"{DEVICE}\"\n    \
             knxprod: \"{}\"\n    application: \"{}\"\n    initial_state: unloaded\n    lsm_access: {lsm}\n",
            work.archive.display(),
            app.id
        );
        // A device with a KNX IP interface built in has the KNXnet/IP
        // parameter object the download writes (issue #455), as the ETS sweep
        // configures it.
        if knxnet_tunnels(app, mask) > 0 {
            yaml.push_str("    knxnet:\n      tunnel_slots: 16\n");
        }
        let config = work.root.join("sim.yaml");
        std::fs::write(&config, yaml)?;
        let log = work.root.join("sim.log");
        let child = Command::new(&settings.sim)
            .arg(&config)
            .env(
                "RUST_LOG",
                std::env::var("BUSSARD_SIM_LOOP_SIM_LOG")
                    .unwrap_or_else(|_| "knx_sim::run=info,warn".to_string()),
            )
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&log)?)
            .stderr(Stdio::from(std::fs::File::create(
                work.root.join("sim.err"),
            )?))
            .spawn()?;
        let mut sim = Sim { child, port };
        let started = Instant::now();
        loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if text.contains("listening") {
                return Ok(sim);
            }
            if let Some(status) = sim.child.try_wait()? {
                let err = std::fs::read_to_string(work.root.join("sim.err")).unwrap_or_default();
                let tail: Vec<&str> = text.lines().chain(err.lines()).rev().take(3).collect();
                return Err(
                    format!("knx-sim did not start ({status}): {}", tail.join(" | ")).into(),
                );
            }
            if started.elapsed() > SIM_START_TIMEOUT {
                return Err("knx-sim did not listen within 60 s".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Sim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A loopback UDP port nothing holds right now.
fn free_udp_port() -> std::io::Result<u16> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?.port())
}

/// The bussard side: the simulator, the model files and the commands.
struct Bench<'a> {
    settings: &'a Settings,
    work: &'a Work,
    app: &'a ApplicationProgram,
    mask: &'a str,
    /// The running simulator, replaced by [`Bench::fresh_device`].
    sim: Option<Sim>,
    /// `127.0.0.1:<port>` of the running simulator.
    gateway: String,
}

/// The captured result of one command.
struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Run {
    /// The last lines of the output, for a failure report.
    fn tail(&self) -> String {
        let all: Vec<&str> = self
            .stdout
            .lines()
            .chain(self.stderr.lines())
            .filter(|l| {
                // Drop blank lines and the streaming progress (`12/1024 bytes`).
                let t = l.trim_start();
                !t.is_empty()
                    && !(t.starts_with(|c: char| c.is_ascii_digit()) && t.contains(" bytes"))
            })
            .collect();
        let start = all.len().saturating_sub(8);
        // The pre-flight verdict says why a flash refuses; keep it.
        let mut out: Vec<&str> = all[..start]
            .iter()
            .copied()
            .filter(|l| l.starts_with("pre-flight") || l.contains("differs"))
            .collect();
        out.extend_from_slice(&all[start..]);
        out.join("\n")
    }
}

impl Bench<'_> {
    /// Replaces the simulator with a new one whose device is unloaded, and
    /// points the model at it. A simulator that cannot load the product on
    /// the `first` start skips the application; later it fails the step.
    fn fresh_device(&mut self, first: bool) -> Result<(), Stop> {
        self.sim = None;
        let sim = Sim::start(self.settings, self.work, self.app, self.mask).map_err(|e| {
            if first {
                Stop::Skip(e.to_string())
            } else {
                Stop::Fail("restart knx-sim".to_string(), e.to_string())
            }
        })?;
        self.gateway = format!("127.0.0.1:{}", sim.port);
        self.sim = Some(sim);
        self.write_model(self.app).map_err(infra("setup"))
    }

    fn write_model(&self, app: &ApplicationProgram) -> std::io::Result<()> {
        let model = &self.work.model;
        std::fs::write(
            model.join("bussard.toml"),
            format!(
                "[connection]\ntransport = \"tunnel\"\ngateway = \"{}\"\n",
                self.gateway
            ),
        )?;
        let bytes = std::fs::read(&self.work.archive)?;
        let sha: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let name = self
            .work
            .archive
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mask = app
            .mask_version
            .as_deref()
            .map(|m| m.trim().trim_start_matches("MV-").to_ascii_uppercase())
            .unwrap_or_default();
        std::fs::write(
            model.join("bussard.lock"),
            format!(
                "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \"products/{name}\"\n\
                 filename = \"{name}\"\nsize = {}\n\
                 origin = {{ kind = \"file\", path = \"{name}\" }}\napplications = [\"{}\"]\n\n\
                 [[device]]\naddress = \"{DEVICE}\"\napplication = \"{}\"\n\
                 product_sha256 = \"{sha}\"\nmask = \"{mask}\"\n",
                bytes.len(),
                app.id,
                app.id
            ),
        )
    }

    fn write_device(&self, config: &Configuration) -> std::io::Result<()> {
        // Kept next to the model so a failure can be replayed by hand.
        let keep = config.label.replace([' ', '+'], "-").replace("--", "-");
        let mut toml = config.device_toml();
        toml.push_str(&knxnet_table(self.app, self.mask));
        std::fs::write(self.work.root.join(format!("device-{keep}.toml")), &toml)?;
        std::fs::write(
            self.work
                .model
                .join("devices")
                .join(format!("{DEVICE}.toml")),
            toml,
        )?;
        std::fs::write(self.work.model.join("groups.toml"), config.groups_toml())
    }

    /// Runs `bussard <args> --dir <model> --gateway <sim>`.
    fn bussard(&self, args: &[&str]) -> Result<Run, BoxError> {
        let model = self.work.model.to_str().ok_or("non-UTF-8 work path")?;
        let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(args)
            .args(["--dir", model, "--gateway", &self.gateway])
            .env("BUSSARD_NO_DOTENV", "1")
            .env("BUSSARD_FLASH_REBOOT_WAIT_MS", "200")
            .env("NO_COLOR", "1")
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .env_remove("BUSSARD_FLASH_SYS7_LSM")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Drain both pipes on threads so a chatty command never blocks.
        let mut out = child.stdout.take().ok_or("no stdout pipe")?;
        let mut err = child.stderr.take().ok_or("no stderr pipe")?;
        let out = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            s
        });
        let err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s);
            s
        });
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if started.elapsed() > COMMAND_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = out.join().map_err(|_| "stdout reader panicked")?;
        let mut stderr = err.join().map_err(|_| "stderr reader panicked")?;
        if status.is_none() {
            stderr.push_str("\n(timed out)");
        }
        Ok(Run {
            ok: status.is_some_and(|s| s.success()),
            stdout,
            stderr,
        })
    }

    fn flash(&self, step: &str) -> Result<(), Stop> {
        let run = self
            .bussard(&["flash", DEVICE, "--yes"])
            .map_err(infra(step))?;
        if run.ok && run.stdout.contains("is Loaded on") {
            Ok(())
        } else {
            Err(Stop::Fail(step.to_string(), run.tail()))
        }
    }

    /// A property-only flash (issue #390): it must succeed and report every
    /// written property read back.
    fn flash_properties(&self, step: &str) -> Result<(), Stop> {
        let run = self
            .bussard(&["flash", DEVICE, "--yes"])
            .map_err(infra(step))?;
        if run.ok
            && run
                .stdout
                .contains("every property it wrote reads back as written")
        {
            Ok(())
        } else {
            Err(Stop::Fail(step.to_string(), run.tail()))
        }
    }

    /// `apply`; with `reload`, its output must report the group-object
    /// table reloaded and read back (issue #540).
    fn apply(&self, step: &str, reload: bool) -> Result<(), Stop> {
        let run = self
            .bussard(&["apply", DEVICE, "--yes"])
            .map_err(infra(step))?;
        if !run.ok {
            return Err(Stop::Fail(step.to_string(), run.tail()));
        }
        if reload && !run.stdout.contains("group-object table reloaded") {
            return Err(Stop::Fail(
                step.to_string(),
                format!(
                    "the plan named a group-object table reload, apply did not report one\n{}",
                    run.tail()
                ),
            ));
        }
        Ok(())
    }

    /// `plan --json` before an `apply`: whether it reloads the System B
    /// group-object table (issue #540). A plan that left a newly linked
    /// object's communication flag unchecked fails the step: the loop has
    /// product data, so the table must have been compared.
    fn object_table_reload(&self, step: &str) -> Result<bool, Stop> {
        let run = self
            .bussard(&["plan", DEVICE, "--json"])
            .map_err(infra(step))?;
        if !run.ok {
            return Err(Stop::Fail(step.to_string(), run.tail()));
        }
        let plan: serde_json::Value = serde_json::from_str(&run.stdout).map_err(|e| {
            Stop::Fail(
                step.to_string(),
                format!("plan --json: {e}\n{}", run.tail()),
            )
        })?;
        let unchecked = plan
            .get("notes")
            .and_then(|n| n.as_array())
            .into_iter()
            .flatten()
            .filter_map(|n| n.as_str())
            .find(|n| n.contains("communication flag not checked"));
        if let Some(note) = unchecked {
            return Err(Stop::Fail(step.to_string(), note.to_string()));
        }
        Ok(plan
            .get("writes")
            .and_then(|w| w.get("group_object_table"))
            .is_some_and(|t| t.is_object()))
    }

    /// `plan --json` must be a no-op with the parameters decoded.
    fn plan_noop(&self, step: &str) -> Result<(), Stop> {
        let run = self
            .bussard(&["plan", DEVICE, "--json"])
            .map_err(infra(step))?;
        if !run.ok {
            return Err(Stop::Fail(step.to_string(), run.tail()));
        }
        let plan: serde_json::Value = serde_json::from_str(&run.stdout).map_err(|e| {
            Stop::Fail(
                step.to_string(),
                format!("plan --json: {e}\n{}", run.tail()),
            )
        })?;
        let mut problems: Vec<String> = Vec::new();
        if let Some(changes) = plan.get("changes").and_then(|c| c.as_array()) {
            for c in changes {
                problems.push(
                    c.get("sentence")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string(),
                );
            }
        }
        if let Some(writes) = plan.get("writes").and_then(|w| w.as_object()) {
            for (what, n) in writes {
                // A count, a flag, or a write described by an object or a
                // list (the group-object table reload of issue #540, the
                // System 7 communication flags, a full image).
                if n.as_u64().is_some_and(|n| n > 0)
                    || n.as_bool() == Some(true)
                    || n.is_object()
                    || n.as_array().is_some_and(|a| !a.is_empty())
                {
                    problems.push(format!("writes {what}: {n}"));
                }
            }
        }
        if plan.get("noop").and_then(|n| n.as_bool()) == Some(false) {
            problems.push("noop: false".to_string());
        }
        if let Some(params) = plan.get("parameters") {
            if let Some(diffs) = params.get("differences").and_then(|d| d.as_array()) {
                for d in diffs {
                    problems.push(format!("parameter differs: {d}"));
                }
            }
            if let Some(note) = params.get("note").and_then(|n| n.as_str()) {
                problems.push(format!("parameters: {note}"));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            let n = problems.len();
            problems.truncate(12);
            if n > 12 {
                problems.push(format!("... {} more", n - 12));
            }
            Err(Stop::Fail(step.to_string(), problems.join("\n")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_mix_64_is_reproducible() {
        let mut a = SplitMix64::new(346);
        let mut b = SplitMix64::new(346);
        let xs: Vec<u64> = (0..4).map(|_| a.below(1000)).collect();
        let ys: Vec<u64> = (0..4).map(|_| b.below(1000)).collect();
        assert_eq!(xs, ys);
        assert_eq!(a.below(0), 0);
    }

    #[test]
    fn test_configuration_device_toml_quotes_escape_keys() {
        let mut links = BTreeMap::new();
        links.insert(
            3,
            Link {
                send: Some("1/0/1".to_string()),
                listen: vec!["1/0/2".to_string()],
            },
        );
        let config = Configuration {
            label: "generated 1".to_string(),
            values: BTreeMap::from([("MD-1_M-2_MI-1_P-3_R-4".to_string(), "2".to_string())]),
            links,
            next_ga: 3,
        };
        let toml = config.device_toml();
        assert!(toml.contains("\"p@MD-1_M-2_MI-1_P-3_R-4\" = \"2\""));
        assert!(toml.contains("3.send = \"1/0/1\""));
        assert!(toml.contains("3.listen = [\"1/0/2\"]"));
        assert!(config.groups_toml().contains("address = \"1/0/2\""));
    }

    /// A synthetic MDT-style application: `P-1` ("Hardware revision") picks
    /// one of two `LdCtrlCompareProp`s of the load procedure, `P-2` only
    /// guards a property write, `P-3` guards nothing.
    fn identity_app() -> ApplicationProgram {
        use bussard_model::dynamic::WhenTest;
        use bussard_prod::application::{
            LoadChoose, LoadGuard, LoadProcedure, Parameter, ParameterRef, ParameterTypeDecl,
        };
        let id = "M-0083_A-0054-14-0D63".to_string();
        let mut app = ApplicationProgram {
            id: id.clone(),
            ..ApplicationProgram::default()
        };
        let type_id = format!("{id}_PT-1");
        app.parameter_types.insert(
            type_id.clone(),
            ParameterTypeDecl {
                id: type_id.clone(),
                name: None,
                kind: ParameterType::Int {
                    size_bits: Some(8),
                    min: Some(0),
                    max: Some(1),
                    signed: false,
                },
            },
        );
        for n in 1..=3 {
            let param = format!("{id}_P-{n}");
            app.parameters.insert(
                param.clone(),
                Parameter {
                    id: param.clone(),
                    parameter_type: Some(type_id.clone()),
                    default: Some("1".to_string()),
                    ..Parameter::default()
                },
            );
            let pref = format!("{param}_R-{n}");
            app.parameter_refs.insert(
                pref.clone(),
                ParameterRef {
                    id: pref,
                    ref_id: param,
                    ..ParameterRef::default()
                },
            );
        }
        let compare = |data: u8| LoadOp::CompareProp {
            obj_idx: Some(0),
            obj_type: None,
            prop_id: Some(19),
            inline_data: Some(vec![data, 0, 0, 0]),
            mask: None,
            range: None,
            occurrence: None,
            start_element: None,
        };
        let branches = vec![WhenTest::Values(vec![0]), WhenTest::Values(vec![1])];
        app.load_procedures.push(LoadProcedure {
            merge_id: None,
            ops: vec![
                LoadOp::Connect,
                compare(0),
                compare(1),
                LoadOp::Restart,
                LoadOp::Disconnect,
            ],
            chooses: vec![
                LoadChoose {
                    param_ref_id: "P-1_R-1".to_string(),
                    tests: branches.clone(),
                },
                LoadChoose {
                    param_ref_id: "P-2_R-2".to_string(),
                    tests: branches,
                },
            ],
            guards: vec![
                vec![],
                vec![LoadGuard {
                    choose: 0,
                    branch: 0,
                }],
                vec![LoadGuard {
                    choose: 0,
                    branch: 1,
                }],
                vec![LoadGuard {
                    choose: 1,
                    branch: 0,
                }],
                vec![],
            ],
            applies_to: Vec::new(),
        });
        app
    }

    #[test]
    fn test_identity_parameters_finds_a_choose_guarding_a_compare() {
        let app = identity_app();
        let found = identity_parameters(&app);
        assert_eq!(
            found,
            HashSet::from(["M-0083_A-0054-14-0D63_P-1".to_string()]),
            "only the parameter whose branch holds a compare states the identity"
        );
    }

    #[test]
    fn test_random_value_leaves_an_identity_parameter_at_its_default() -> TestResult {
        let app = identity_app();
        let mut rng = SplitMix64::new(407);
        for _ in 0..50 {
            assert_eq!(random_value(&app, "P-1_R-1", &mut rng), None);
            random_value(&app, "P-2_R-2", &mut rng).ok_or("P-2 draws a value")?;
            random_value(&app, "P-3_R-3", &mut rng).ok_or("P-3 draws a value")?;
        }
        Ok(())
    }

    #[test]
    fn test_draw_value_stays_inside_a_range_above_zero() -> TestResult {
        // The ABB/BJE `Dummy_Prio_ENDE` type: minInclusive = maxInclusive = 129.
        let pinned = ParameterType::Int {
            size_bits: Some(8),
            min: Some(129),
            max: Some(129),
            signed: false,
        };
        let range = ParameterType::Int {
            size_bits: Some(8),
            min: Some(129),
            max: Some(140),
            signed: false,
        };
        let mut rng = SplitMix64::new(346);
        for _ in 0..500 {
            assert_eq!(
                draw_value(&pinned, TextCodec::Utf8, &mut rng).as_deref(),
                Some("129")
            );
            let v: i64 = draw_value(&range, TextCodec::Utf8, &mut rng)
                .ok_or("no value")?
                .parse()?;
            assert!((129..=140).contains(&v), "{v} outside 129..=140");
        }
        Ok(())
    }

    #[test]
    fn test_draw_value_full_signed_range_and_undrawable_types() -> TestResult {
        let full = ParameterType::Int {
            size_bits: Some(64),
            min: Some(i64::MIN),
            max: Some(i64::MAX),
            signed: true,
        };
        let mut rng = SplitMix64::new(7);
        for _ in 0..100 {
            draw_value(&full, TextCodec::Utf8, &mut rng)
                .ok_or("no value")?
                .parse::<i64>()?;
        }
        let open = ParameterType::Int {
            size_bits: Some(8),
            min: Some(10),
            max: None,
            signed: false,
        };
        assert_eq!(draw_value(&open, TextCodec::Utf8, &mut rng), None);
        assert_eq!(
            draw_value(
                &ParameterType::Text { size_bits: Some(0) },
                TextCodec::Utf8,
                &mut rng
            ),
            None
        );
        Ok(())
    }

    /// A drawn text fits its field in the program's code page (#401): MDT's
    /// eight-octet labels in ISO 8859-15, UTF-8, ISO 8859-1 when undeclared
    /// (#416), and ASCII for a declared name bussard does not know.
    #[test]
    fn test_draw_value_text_fits_the_field_and_the_code_page() -> TestResult {
        let mut rng = SplitMix64::new(401);
        let mut accented = 0;
        for codec in [
            TextCodec::Latin9,
            TextCodec::Utf8,
            TextCodec::Undeclared,
            TextCodec::Unknown,
        ] {
            for bits in [8, 64, 160] {
                let kind = ParameterType::Text {
                    size_bits: Some(bits),
                };
                for _ in 0..300 {
                    let text = draw_value(&kind, codec, &mut rng).ok_or("no text")?;
                    let octets = codec.encode(&text, (bits / 8) as usize)?;
                    assert_eq!(codec.decode(&octets), text, "{codec:?}");
                    accented += usize::from(!text.is_ascii());
                    if codec == TextCodec::Unknown {
                        assert!(text.is_ascii(), "{text}");
                    }
                }
            }
        }
        assert!(accented > 0, "no accented text drawn");
        Ok(())
    }
}
