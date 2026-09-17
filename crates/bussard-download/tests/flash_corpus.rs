//! Env-gated flashability sweep over a downloaded product corpus.
//!
//! Given a directory of real vendor `.knxprod` files (set
//! `BUSSARD_PRODUCT_CORPUS=<dir>`), this reads every one, and for **every**
//! application program it contains attempts a dry-run [`plan_flash`] lowering
//! against that application's own declared mask. No device is touched: a plan is
//! a pure function of the product data and the app's mask, so this answers "can
//! bussard flash this today?" for a whole shelf of vendor products at once.
//!
//! Each application is classified into exactly one bucket:
//!
//! * **executable** — [`plan_flash`] produced a [`FlashPlan`]; the whole
//!   procedure lowered.
//! * **refused(op)** — a supported-family (System B) app whose procedure carries
//!   an op the engine cannot execute yet ([`PlanError::UnsupportedOp`]) or an
//!   image it cannot resolve; the blocking op is recorded for the roadmap.
//! * **not-System-B-family** — the app targets a non-07B0 mask (System 7 / older
//!   BCUs), which the engine refuses up front. Expected and common.
//!
//! A `.knxprod` whose XML would not parse never reaches classification: the test
//! asserts [`read_knxprod`](bussard_prod::read_knxprod) itself does not error on
//! any corpus file, so a malformed archive is a hard, up-front failure.
//!
//! The test prints a per-product table and a corpus-wide blocking-op ranking,
//! then asserts only invariants that must hold: nothing panics, every app is
//! classified, and at least a floor of applications across the corpus lower to an
//! executable plan (so the sweep stays meaningful without being brittle).
//!
//! When `BUSSARD_PRODUCT_CORPUS` is unset the test skips cleanly, so CI — which
//! never downloads copyrighted vendor data — is unaffected. See
//! `tests-support/product-corpus/README.md` for the clean-machine repro.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_download::{FlashStep, PlanError, plan_flash};

/// The minimum number of applications across the corpus that must lower to an
/// executable plan. The seeded corpus yields 12 (all the Zennio 07B0 devices,
/// the MDT AKH heating actuator's three apps, and one System B app each from the
/// mixed-mask MDT AKK/AKS files). A floor of 8 leaves headroom for a vendor to
/// re-publish or drop a file without breaking CI, while still catching a real
/// interpreter regression or an empty/broken corpus. Only enforced when a corpus
/// is actually present.
const MIN_EXECUTABLE: usize = 8;

/// One application's flashability classification. Every application in the
/// corpus lands in exactly one of these buckets.
#[derive(Debug)]
enum Class {
    /// Lowered to an executable plan.
    Executable,
    /// A System B app refused at pre-flight; carries the blocking reason.
    Refused { reason: String },
    /// The app targets a non-System-B mask (refused up front).
    NotSystemB,
}

/// A per-product roll-up for the summary table.
struct ProductReport {
    file: String,
    apps: usize,
    executable: usize,
    refused: usize,
    not_system_b: usize,
    /// Blocking reasons for the refused (System B) apps, for the per-product line.
    blocking: Vec<String>,
}

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
    let files = knxprod_files(&dir);
    if files.is_empty() {
        eprintln!(
            "BUSSARD_PRODUCT_CORPUS={} holds no .knxprod files; skipping (nothing to sweep). \
             Run tests-support/product-corpus/fetch.sh first.",
            dir.display()
        );
        return;
    }

    let mut products: Vec<ProductReport> = Vec::new();
    // Corpus-wide blocking-op ranking: normalized op label -> count.
    let mut blocking_rank: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_apps = 0usize;
    let mut total_executable = 0usize;

    for file in &files {
        // read_knxprod must not panic or error on a real vendor file.
        let product = match bussard_prod::read_knxprod(file) {
            Ok(p) => p,
            Err(e) => panic!(
                "read_knxprod failed on {}: {e} — a corpus file must parse",
                file.display()
            ),
        };

        let mut report = ProductReport {
            file: file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            apps: 0,
            executable: 0,
            refused: 0,
            not_system_b: 0,
            blocking: Vec::new(),
        };

        for app in &product.applications {
            report.apps += 1;
            total_apps += 1;
            let class = classify(app);
            match class {
                Class::Executable => {
                    report.executable += 1;
                    total_executable += 1;
                }
                Class::Refused { reason } => {
                    report.refused += 1;
                    *blocking_rank.entry(reason.clone()).or_insert(0) += 1;
                    report.blocking.push(reason);
                }
                Class::NotSystemB => report.not_system_b += 1,
            }
        }
        products.push(report);
    }

    print_summary(&products, &blocking_rank, total_apps, total_executable);

    // Invariants that must hold.
    // 1. Every app was classified into exactly one bucket (counts add up). A
    //    malformed archive never reaches here: read_knxprod above panics first,
    //    so a corpus file that will not parse is a hard, up-front failure.
    for p in &products {
        assert_eq!(
            p.executable + p.refused + p.not_system_b,
            p.apps,
            "product {} left an app unclassified",
            p.file
        );
    }
    // 2. A meaningful floor of executable plans across the corpus.
    assert!(
        total_executable >= MIN_EXECUTABLE,
        "only {total_executable} executable plans across the corpus; \
         expected at least {MIN_EXECUTABLE} (is the corpus populated and the \
         interpreter healthy?)"
    );
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

/// Classifies one application by attempting a dry-run plan against its own mask.
fn classify(app: &bussard_prod::ApplicationProgram) -> Class {
    // Plan against the app's OWN declared mask so the System B gate and the mask
    // compare pass for System B apps and we exercise the op lowering itself.
    let Some(mask_str) = app.mask_version.as_deref() else {
        // No mask: cannot be checked for System B compatibility. Treat as
        // not-System-B (it is certainly not a flashable 07B0 target here).
        return Class::NotSystemB;
    };
    let Ok(device_mask) = u16::from_str_radix(mask_str.trim(), 16) else {
        return Class::NotSystemB;
    };

    match plan_flash(
        app,
        "1.1.1",
        device_mask,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    ) {
        Ok(_plan) => Class::Executable,
        Err(PlanError::NotSystemB { .. }) => Class::NotSystemB,
        Err(PlanError::UnsupportedOp { op }) => Class::Refused {
            reason: normalize_op(&op),
        },
        Err(PlanError::UnresolvableImage { reason, .. }) => Class::Refused {
            reason: format!("UnresolvableImage: {}", short(&reason)),
        },
        Err(PlanError::MissingAppMask(_)) => Class::Refused {
            reason: "MissingAppMask".to_string(),
        },
        Err(PlanError::NoProcedure(_)) => Class::Refused {
            reason: "NoProcedure".to_string(),
        },
        // Mask mismatch cannot happen here (we plan against the app's own mask),
        // but the match is total; record it if it ever surfaces.
        Err(PlanError::MaskMismatch { .. }) => Class::Refused {
            reason: "MaskMismatch".to_string(),
        },
        Err(PlanError::NoApplication(_) | PlanError::AmbiguousApplication { .. }) => {
            Class::Refused {
                reason: "SelectionError".to_string(),
            }
        }
        Err(PlanError::AddressOutOfRange { .. }) => Class::Refused {
            reason: "AddressOutOfRange".to_string(),
        },
        Err(PlanError::UnsupportedWriteProp { .. }) => Class::Refused {
            reason: "UnsupportedWriteProp".to_string(),
        },
        // Cannot happen here (no master template is passed, so nothing splices a
        // table-object write), but the match must be total.
        Err(PlanError::MissingTableImage { .. }) => Class::Refused {
            reason: "MissingTableImage".to_string(),
        },
    }
}

/// Normalizes an `UnsupportedOp` message to the bare op family for ranking, so
/// `LdCtrlAbsSegment (…)` and `LdCtrlTaskSegment` rank by op, not by full text.
fn normalize_op(op: &str) -> String {
    let head = op.split_whitespace().next().unwrap_or(op);
    format!("UnsupportedOp: {head}")
}

/// Trims a long reason to its first clause for the table.
fn short(s: &str) -> String {
    let s = s.split(':').next().unwrap_or(s).trim();
    s.chars().take(48).collect()
}

/// Collects the `.knxprod` files at or under `dir` (one level of nesting is
/// enough: `bussard import-product` caches downloads under `<dir>/vendor/`, so a
/// corpus dir may point either at the flat cache or at the parent that holds
/// `vendor/`). Sorted for stable output.
fn knxprod_files(dir: &Path) -> Vec<PathBuf> {
    fn is_knxprod(p: &Path) -> bool {
        p.extension().and_then(|e| e.to_str()) == Some("knxprod")
    }
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // One level deeper (e.g. the vendor/ cache subdirectory).
                if let Ok(sub) = std::fs::read_dir(&path) {
                    for e2 in sub.flatten() {
                        let p2 = e2.path();
                        if is_knxprod(&p2) {
                            out.push(p2);
                        }
                    }
                }
            } else if is_knxprod(&path) {
                out.push(path);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Prints the per-product flashability table and the corpus-wide blocking-op
/// ranking.
fn print_summary(
    products: &[ProductReport],
    blocking_rank: &BTreeMap<String, usize>,
    total_apps: usize,
    total_executable: usize,
) {
    eprintln!("\n=== Product-corpus flashability sweep ===");
    eprintln!(
        "{} product file(s), {} application program(s), {} executable\n",
        products.len(),
        total_apps,
        total_executable
    );
    eprintln!(
        "{:<48} {:>4} {:>5} {:>4} {:>7}",
        "product", "apps", "exec", "ref", "non-SB"
    );
    eprintln!("{}", "-".repeat(72));
    for p in products {
        eprintln!(
            "{:<48} {:>4} {:>5} {:>4} {:>7}",
            truncate(&p.file, 48),
            p.apps,
            p.executable,
            p.refused,
            p.not_system_b,
        );
        // Show the distinct blocking ops for this product, if any.
        if !p.blocking.is_empty() {
            let mut per: BTreeMap<&str, usize> = BTreeMap::new();
            for b in &p.blocking {
                *per.entry(b.as_str()).or_insert(0) += 1;
            }
            let joined: Vec<String> = per.iter().map(|(op, n)| format!("{op} x{n}")).collect();
            eprintln!("    blocking: {}", joined.join(", "));
        }
    }

    eprintln!("\n=== Blocking-op ranking (System B apps refused at pre-flight) ===");
    if blocking_rank.is_empty() {
        eprintln!("(none — every System B app lowered)");
    } else {
        // Rank by frequency, descending, then by name for stability.
        let mut ranked: Vec<(&String, &usize)> = blocking_rank.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (op, count) in ranked {
            eprintln!("  {count:>4}  {op}");
        }
    }
    eprintln!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
