//! Env-gated full-corpus conformance sweep over a downloaded product corpus.
//!
//! Given a directory of real vendor `.knxprod` files (set
//! `BUSSARD_PRODUCT_CORPUS=<dir>`), [`corpus_flashability_sweep`] runs every
//! application in every product through the shared [`bussard_download::sweep`]
//! engine — parse -> image-synthesis -> plan-lowering — bucketing and ranking the
//! outcomes into a [`SweepManifest`]. No device is touched: everything is a pure
//! function of the product data and each app's own declared mask, so this answers
//! "can bussard flash this today?" for a whole shelf of vendor products at once.
//!
//! The manifest's ranked refusal tables are the roadmap of the next real gaps.
//! The test prints them, then enforces the invariants that must always hold —
//! **nothing panics** anywhere in the pipeline (a panic breaks the gate and must
//! be converted to a proper refusal), and a floor of applications still lower to
//! an executable plan — and, when the checked-in real-corpus baseline
//! (`tests-support/product-corpus/conformance-manifest.json`) is present, fails on
//! a **regression** (a new refusal or a new panic) rather than on the
//! pre-existing known-unsupported items that make up the baseline. Regenerate the
//! baseline with `BUSSARD_UPDATE_SWEEP_MANIFEST=1`.
//!
//! When `BUSSARD_PRODUCT_CORPUS` is unset the test skips cleanly, so CI — which
//! never downloads copyrighted vendor data — is unaffected. The always-on,
//! fixture-based half of the gate lives in `sweep_fixtures.rs` +
//! `golden_images.rs`. See `tests-support/product-corpus/README.md` for the
//! clean-machine repro.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_download::sweep::knxprod_files;
use bussard_download::{FlashStep, SweepManifest, plan_flash, sweep_corpus};

/// The minimum number of applications across the corpus that must lower to an
/// executable plan. The seeded corpus yields 12 (all the Zennio 07B0 devices,
/// the MDT AKH heating actuator's three apps, and one System B app each from the
/// mixed-mask MDT AKK/AKS files). A floor of 8 leaves headroom for a vendor to
/// re-publish or drop a file without breaking CI, while still catching a real
/// interpreter regression or an empty/broken corpus. Only enforced when a corpus
/// is actually present.
const MIN_EXECUTABLE: usize = 8;

/// The checked-in real-corpus conformance baseline, regenerated on a machine
/// that holds the (git-ignored) vendor cache. Absent on a clean checkout, so the
/// diff below is skipped unless the file exists.
fn real_corpus_baseline() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests-support/product-corpus/conformance-manifest.json")
}

/// Full-corpus conformance sweep: parse -> image-synthesis -> plan-lowering for
/// every application in every cached product, bucketed and ranked. Builds the
/// [`SweepManifest`], prints the ranked tables, and (when the checked-in
/// real-corpus baseline exists) fails on a **regression** — a new refusal or a
/// new panic — rather than on pre-existing known-unsupported items.
///
/// Env-gated on `BUSSARD_PRODUCT_CORPUS`; skips green when unset so CI (which
/// never downloads copyrighted vendor data) is unaffected. Regenerate the
/// baseline with `BUSSARD_UPDATE_SWEEP_MANIFEST=1`.
#[test]
fn corpus_flashability_sweep() {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!(
            "BUSSARD_PRODUCT_CORPUS unset; skipping the product-corpus flashability sweep. \
             See tests-support/product-corpus/README.md to populate a cache and run it."
        );
        return;
    };
    let dir = PathBuf::from(dir);
    if knxprod_files(&dir).is_empty() {
        eprintln!(
            "BUSSARD_PRODUCT_CORPUS={} holds no .knxprod files; skipping (nothing to sweep). \
             Run tests-support/product-corpus/fetch.sh first.",
            dir.display()
        );
        return;
    }

    let manifest = sweep_corpus(&dir);
    let t = &manifest.totals;

    // Print the ranked tables (the roadmap of the next real gaps).
    eprint!("{}", manifest.to_markdown());

    // Regenerate the real-corpus baseline on demand.
    if std::env::var_os("BUSSARD_UPDATE_SWEEP_MANIFEST").is_some() {
        let base = real_corpus_baseline();
        std::fs::write(&base, manifest.to_json().expect("the manifest serializes"))
            .expect("write real-corpus baseline");
        std::fs::write(base.with_extension("md"), manifest.to_markdown())
            .expect("write real-corpus baseline md");
        eprintln!("real-corpus baseline regenerated at {}", base.display());
        return;
    }

    // Invariants that must always hold.
    // 1. A panic anywhere is never acceptable — it breaks the gate.
    assert_eq!(
        t.parse_panicked + t.image_panicked + t.plan_panicked,
        0,
        "the sweep hit {} panic(s) (parse {}, image {}, plan {}); \
         a panic must be converted to a proper refusal in the engine",
        t.parse_panicked + t.image_panicked + t.plan_panicked,
        t.parse_panicked,
        t.image_panicked,
        t.plan_panicked,
    );
    // 2. A meaningful floor of executable plans across the corpus.
    assert!(
        t.plan_executable >= MIN_EXECUTABLE,
        "only {} executable plans across the corpus; expected at least {MIN_EXECUTABLE} \
         (is the corpus populated and the interpreter healthy?)",
        t.plan_executable,
    );

    // 3. Regression gate against the checked-in baseline (when present): no NEW
    //    refusal reason, no growth in an existing refusal/panic bucket, no new
    //    parse failure. Pre-existing known-unsupported items are the baseline, so
    //    only a regression fails; an *improvement* (fewer refusals) is reported
    //    and the baseline should be regenerated.
    let base = real_corpus_baseline();
    if let Ok(text) = std::fs::read_to_string(&base) {
        let baseline = SweepManifest::from_json(&text).expect("parse real-corpus baseline");
        assert_no_regression(&baseline, &manifest);
    } else {
        eprintln!(
            "no checked-in real-corpus baseline at {} — regenerate with \
             BUSSARD_UPDATE_SWEEP_MANIFEST=1 to lock this corpus's conformance.",
            base.display()
        );
    }
}

/// Fails on a conformance regression from `baseline` to `current`: a new or
/// larger plan-refusal bucket, a new or larger image-refusal bucket, more
/// parse failures, or any panic. An improvement (a bucket shrinking or vanishing)
/// is reported, not failed — regenerate the baseline to lock it in.
fn assert_no_regression(baseline: &SweepManifest, current: &SweepManifest) {
    let base_plan: BTreeMap<&str, usize> = baseline
        .plan_refusal_ranking
        .iter()
        .map(|r| (r.reason.as_str(), r.count))
        .collect();
    let mut regressions: Vec<String> = Vec::new();
    for r in &current.plan_refusal_ranking {
        let was = base_plan.get(r.reason.as_str()).copied().unwrap_or(0);
        if r.count > was {
            regressions.push(format!(
                "plan-refusal '{}' grew {was} -> {} app(s)",
                r.reason, r.count
            ));
        }
    }
    let base_img: BTreeMap<&str, usize> = baseline
        .image_refusal_ranking
        .iter()
        .map(|r| (r.reason.as_str(), r.count))
        .collect();
    for r in &current.image_refusal_ranking {
        let was = base_img.get(r.reason.as_str()).copied().unwrap_or(0);
        if r.count > was {
            regressions.push(format!(
                "image-refusal '{}' grew {was} -> {} app(s)",
                r.reason, r.count
            ));
        }
    }
    if current.totals.parse_failed > baseline.totals.parse_failed {
        regressions.push(format!(
            "parse failures grew {} -> {}",
            baseline.totals.parse_failed, current.totals.parse_failed
        ));
    }
    let panics = current.totals.parse_panicked
        + current.totals.image_panicked
        + current.totals.plan_panicked;
    if panics > 0 {
        regressions.push(format!("{panics} panic(s) (never acceptable)"));
    }

    assert!(
        regressions.is_empty(),
        "conformance regressed vs the checked-in baseline:\n  {}\n\
         If intended, regenerate with BUSSARD_UPDATE_SWEEP_MANIFEST=1 and review the diff.",
        regressions.join("\n  ")
    );

    if current.totals.plan_executable > baseline.totals.plan_executable {
        eprintln!(
            "conformance IMPROVED: {} -> {} executable plans; regenerate the baseline to lock it in.",
            baseline.totals.plan_executable, current.totals.plan_executable
        );
    }
}

/// Finding 1b regression guard, run against the real corpus when present.
///
/// The MDT AKK switch actuator (A-0007) declares TWO identical `LdCtrlRelSegment`
/// ops for its single 1936-octet segment (`AppliesTo="full"` and `="par"`, both
/// `LsmIdx=4 Size=1936`) inside one MergeId block. The lowering must dedupe the
/// identical consecutive allocation, so no plan in the corpus ever emits two
/// back-to-back `AllocateSegment` steps of the same size. (Re-allocation on an
/// already-Loading object is legal per the KNX load-state machine — KNX Spec 3/5/2
/// `LdCtrlRelSegment` frees any prior backing store and re-allocates — but the
/// second allocation is redundant and is the step KNX Virtual was observed to
/// choke on, so we drop it.)
///
/// Env-gated exactly like the sweep: absent corpus skips cleanly (CI never holds
/// copyrighted vendor data), so this is a local/opt-in regression check.
#[test]
fn corpus_never_emits_duplicate_consecutive_allocations() {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping the duplicate-allocation guard.");
        return;
    };
    let dir = PathBuf::from(dir);
    let files = knxprod_files(&dir);
    if files.is_empty() {
        eprintln!("corpus empty; skipping the duplicate-allocation guard.");
        return;
    }

    let mut checked_plans = 0usize;
    for file in &files {
        let Ok(product) = bussard_prod::read_knxprod(file) else {
            continue;
        };
        for app in &product.applications {
            let Some(mask_str) = app.mask_version.as_deref() else {
                continue;
            };
            let Ok(mask) = u16::from_str_radix(mask_str.trim(), 16) else {
                continue;
            };
            let Ok(plan) = plan_flash(
                app,
                "1.1.1",
                mask,
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
                &BTreeMap::new(),
            ) else {
                continue;
            };
            checked_plans += 1;
            // No two consecutive AllocateSegment steps of the same size.
            for pair in plan.steps.windows(2) {
                if let (
                    FlashStep::AllocateSegment { size: a, .. },
                    FlashStep::AllocateSegment { size: b, .. },
                ) = (&pair[0], &pair[1])
                {
                    assert_ne!(
                        a,
                        b,
                        "app {} in {} lowered two identical consecutive allocations \
                         ({a} bytes) — the dedupe regressed",
                        app.id,
                        file.display()
                    );
                }
            }
        }
    }
    eprintln!("duplicate-allocation guard checked {checked_plans} executable plan(s).");
}

/// Extended-memory regression guard, run against the real corpus when present.
///
/// The four real ETS6 downloads analysed in `scratchpad/ets-analysis/sysb-{a,c}.md`
/// place their loadable segments **above 0x10000** (the Jung Schaltaktor-24
/// `A-20D7` at `0xf000..0x1aad3`, the Heizungsaktor-6 `A-20E0` at
/// `0xf000..0x17d89`, the Tastsensor `A-D142` at `0xf000..0x17805`, the ABB
/// BE/S16 `A-A0ED` at `0x18000..0x19242`). Before the extended-memory work
/// `plan_flash` refused these at pre-flight with `AddressOutOfRange` (the 16-bit
/// guard). Now each must lower to an **executable** plan — the address width is
/// 24-bit and the flash engine selects `A_MemoryExtended_Write` at flash time from
/// the device-supplied base. The plan does not itself pick the service (the base
/// is device-supplied), so the assertion is that these known >64K-segment apps are
/// no longer refused.
///
/// Env-gated exactly like the sweep: an absent corpus skips cleanly, so CI never
/// needs the copyrighted vendor data. The apps are matched by app-id substring, so
/// a corpus missing a given product simply skips it (reported), never fails.
#[test]
fn corpus_extended_memory_apps_lower_to_executable_plans() {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping the extended-memory guard.");
        return;
    };
    let dir = PathBuf::from(dir);
    let files = knxprod_files(&dir);
    if files.is_empty() {
        eprintln!("corpus empty; skipping the extended-memory guard.");
        return;
    }

    // App-id prefixes of the four capture devices whose segments exceed 0xFFFF.
    const EXTENDED_APP_PREFIXES: &[&str] = &[
        "M-0004_A-20D7", // Jung Schaltaktor-24 / Jalousie-12
        "M-0004_A-20E0", // Jung Heizungsaktor-6 (capture version + sibling)
        "M-0004_A-D142", // Jung Tastsensor Universal 2f
        "M-0002_A-A0ED", // ABB BE/S16 binary input
    ];

    let mut found = 0usize;
    for file in &files {
        let Ok(product) = bussard_prod::read_knxprod(file) else {
            continue;
        };
        for app in &product.applications {
            if !EXTENDED_APP_PREFIXES.iter().any(|p| app.id.starts_with(p)) {
                continue;
            }
            found += 1;
            let mask = app
                .mask_version
                .as_deref()
                .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())
                .expect("a capture 07B0 app must declare a hex mask");
            match plan_flash(
                app,
                "1.1.1",
                mask,
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
                &BTreeMap::new(),
            ) {
                Ok(plan) => {
                    assert!(
                        plan.steps
                            .iter()
                            .any(|s| matches!(s, FlashStep::WriteRelMem { .. })),
                        "app {} must stream a relative segment",
                        app.id
                    );
                    eprintln!(
                        "extended-memory: {} lowered to an executable plan ({} step(s), {} write byte(s))",
                        app.id,
                        plan.steps.len(),
                        plan.total_write_bytes(),
                    );
                }
                Err(e) => panic!(
                    "app {} (a >64K-segment capture device) must lower to an executable \
                     plan now that the extended memory service is supported, but was \
                     refused: {e}",
                    app.id
                ),
            }
        }
    }

    if found == 0 {
        eprintln!(
            "extended-memory guard: none of the four capture products \
             ({EXTENDED_APP_PREFIXES:?}) are in this corpus; nothing to assert."
        );
    } else {
        eprintln!("extended-memory guard checked {found} capture app(s).");
    }
}
