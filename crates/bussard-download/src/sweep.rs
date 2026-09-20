//! Corpus-driven conformance sweep: run every application in every product
//! through the three stages a real flash exercises — **parse**, **image
//! synthesis**, and **plan lowering** — and bucket the outcome of each.
//!
//! This is a *measurement* tool, not a fixer. Its job is to answer, across a
//! whole shelf of real vendor products at once:
//!
//! * which `.knxprod` files parse and which do not,
//! * for each application program, whether its parameter memory image can be
//!   synthesized or is refused (and why),
//! * whether its load procedure lowers to an executable [`FlashPlan`] or is
//!   refused (and why), ranked corpus-wide by product count.
//!
//! The result serializes to a stable, sorted [`SweepManifest`] that is checked
//! in and diffs over time: a new refusal or a new panic shows up as a manifest
//! change in review, which is the regression gate (see the env-gated corpus test
//! in `tests/flash_corpus.rs`).
//!
//! # Panics are contained, never silent
//!
//! A panic anywhere in the pipeline (parse, image, or plan) breaks the gate, so
//! each application is classified inside [`std::panic::catch_unwind`]. A caught
//! panic becomes a [`PlanClass::Panicked`] bucket — recorded, ranked, and
//! visible — rather than aborting the whole sweep. A panic is never an acceptable
//! outcome: it must be converted to a proper refusal in the engine. The bucket
//! exists so the sweep *survives* to report the rest of the corpus while the
//! panic is being fixed, not to bless it.
//!
//! # No device, no network
//!
//! Everything here is a pure function of the product data and each application's
//! own declared mask. No gateway is touched; a plan is offline analysis.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use bussard_prod::ApplicationProgram;
use serde::{Deserialize, Serialize};

use crate::flash::{PlanError, plan_flash};

/// Outcome of reading a single `.knxprod` container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "parse", rename_all = "snake_case")]
pub enum ParseClass {
    /// The container parsed; the count of application programs it yielded.
    Ok {
        /// How many application programs the file yielded.
        apps: usize,
    },
    /// Reading the container failed; carries the normalized error family.
    Failed {
        /// A short, stable reason label (see [`normalize_parse_error`]).
        reason: String,
    },
    /// Reading the container panicked (never acceptable — must be fixed).
    Panicked,
}

/// Outcome of synthesizing an application's parameter memory image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "image", rename_all = "snake_case")]
pub enum ImageClass {
    /// The image built; the number of segment images produced.
    Ok {
        /// How many segment images were produced.
        segments: usize,
    },
    /// The image build was refused; carries the normalized reason.
    Refused {
        /// A short, stable reason label.
        reason: String,
    },
    /// The image build panicked (never acceptable — must be fixed).
    Panicked,
}

/// Outcome of lowering an application's load procedure to a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "plan", rename_all = "snake_case")]
pub enum PlanClass {
    /// The whole procedure lowered to an executable plan; the step count.
    Executable {
        /// How many flash steps the plan holds.
        steps: usize,
    },
    /// A supported-family app whose plan was refused; carries the reason.
    Refused {
        /// A short, stable reason label (see [`normalize_plan_error`]).
        reason: String,
    },
    /// The app targets an unsupported mask family (refused up front by design).
    NotSupportedFamily {
        /// The human system classification (e.g. `System 7`, `System 1`).
        system: String,
    },
    /// The plan lowering panicked (never acceptable — must be fixed).
    Panicked,
}

/// One application's full conformance classification across the three stages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSweep {
    /// The application-program id (e.g. `M-0083_A-0007-23-…`).
    pub id: String,
    /// The declared mask version (hex string, `MV-` already stripped), if any.
    pub mask: Option<String>,
    /// Image-synthesis outcome.
    pub image: ImageClass,
    /// Plan-lowering outcome.
    pub plan: PlanClass,
}

/// One product file's roll-up: the parse outcome and each application's sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductSweep {
    /// The `.knxprod` file name (not the full path — paths are machine-local).
    pub file: String,
    /// The parse outcome for the container.
    pub parse: ParseClass,
    /// One entry per application program (empty if parse failed/panicked).
    pub apps: Vec<AppSweep>,
}

/// Corpus-wide bucket totals, for the manifest header and quick diffs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepTotals {
    /// Product files read.
    pub products: usize,
    /// Product files that parsed.
    pub parse_ok: usize,
    /// Product files whose parse failed.
    pub parse_failed: usize,
    /// Product files whose parse panicked.
    pub parse_panicked: usize,
    /// Application programs classified (across all parsed files).
    pub apps: usize,
    /// Apps whose image synthesized.
    pub image_ok: usize,
    /// Apps whose image was refused.
    pub image_refused: usize,
    /// Apps whose image build panicked.
    pub image_panicked: usize,
    /// Apps whose plan is executable.
    pub plan_executable: usize,
    /// Apps whose plan was refused (supported family).
    pub plan_refused: usize,
    /// Apps on an unsupported mask family (refused up front).
    pub plan_not_supported_family: usize,
    /// Apps whose plan lowering panicked.
    pub plan_panicked: usize,
}

/// A ranked (reason, product-count) row. Product count = how many application
/// programs across the corpus landed on this reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankedReason {
    /// The normalized reason label.
    pub reason: String,
    /// How many applications carried it.
    pub count: usize,
}

/// Per-mask-family coverage: how a family's apps split across plan buckets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCoverage {
    /// Total apps declaring this mask.
    pub apps: usize,
    /// Apps that lowered to an executable plan.
    pub executable: usize,
    /// Apps refused within a supported family.
    pub refused: usize,
    /// Apps refused up front as an unsupported family.
    pub not_supported_family: usize,
    /// Apps that panicked somewhere in the pipeline.
    pub panicked: usize,
}

/// The checked-in, diffable conformance manifest: the whole corpus's outcome.
///
/// Everything is sorted deterministically so a re-run of the same corpus yields
/// byte-identical JSON, and any real change (a new refusal, a new panic, a
/// vendor-file drift) shows up as a reviewable diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepManifest {
    /// A human note describing what this file is.
    pub note: String,
    /// Corpus-wide bucket totals.
    pub totals: SweepTotals,
    /// Plan-refusal reasons ranked by application count, descending.
    pub plan_refusal_ranking: Vec<RankedReason>,
    /// Image-refusal reasons ranked by application count, descending.
    pub image_refusal_ranking: Vec<RankedReason>,
    /// Parse-failure reasons ranked by product-file count, descending.
    pub parse_failure_ranking: Vec<RankedReason>,
    /// Mask-family coverage, keyed by the human system label (`System B`, …).
    pub family_coverage: BTreeMap<String, FamilyCoverage>,
    /// One entry per product file, sorted by file name.
    pub products: Vec<ProductSweep>,
}

impl SweepManifest {
    /// Serializes the manifest to pretty, stable JSON (trailing newline).
    pub fn to_json(&self) -> String {
        // serde_json's pretty printer is deterministic for our sorted data.
        let mut s = serde_json::to_string_pretty(self).unwrap_or_default();
        s.push('\n');
        s
    }

    /// Parses a manifest from JSON.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] if the text is not a valid
    /// manifest.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Renders a compact markdown report (buckets + ranked tables + coverage),
    /// suitable for a checked-in `*.md` artifact next to the JSON.
    pub fn to_markdown(&self) -> String {
        let t = &self.totals;
        let mut out = String::new();
        out.push_str("# Product-corpus conformance sweep\n\n");
        out.push_str(&self.note);
        out.push_str("\n\n## Buckets\n\n");
        out.push_str(&format!(
            "- Product files: **{}** ({} parsed, {} parse-failed, {} parse-panicked)\n",
            t.products, t.parse_ok, t.parse_failed, t.parse_panicked
        ));
        out.push_str(&format!("- Application programs: **{}**\n", t.apps));
        out.push_str(&format!(
            "  - Image: {} ok, {} refused, {} panicked\n",
            t.image_ok, t.image_refused, t.image_panicked
        ));
        out.push_str(&format!(
            "  - Plan: {} executable, {} refused, {} unsupported-family, {} panicked\n\n",
            t.plan_executable, t.plan_refused, t.plan_not_supported_family, t.plan_panicked
        ));

        push_ranking(
            &mut out,
            "Plan-refusal reasons (ranked by app count)",
            &self.plan_refusal_ranking,
        );
        push_ranking(
            &mut out,
            "Image-refusal reasons (ranked by app count)",
            &self.image_refusal_ranking,
        );
        push_ranking(
            &mut out,
            "Parse-failure reasons (ranked by file count)",
            &self.parse_failure_ranking,
        );

        out.push_str("## Mask-family coverage\n\n");
        out.push_str("| family | apps | exec | refused | unsupported | panicked |\n");
        out.push_str("| --- | ---: | ---: | ---: | ---: | ---: |\n");
        for (family, c) in &self.family_coverage {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                family, c.apps, c.executable, c.refused, c.not_supported_family, c.panicked
            ));
        }
        out.push('\n');
        out
    }
}

/// Appends a markdown ranking table (skipped when the ranking is empty).
fn push_ranking(out: &mut String, title: &str, rows: &[RankedReason]) {
    out.push_str(&format!("## {title}\n\n"));
    if rows.is_empty() {
        out.push_str("_(none)_\n\n");
        return;
    }
    out.push_str("| count | reason |\n| ---: | --- |\n");
    for r in rows {
        out.push_str(&format!("| {} | {} |\n", r.count, r.reason));
    }
    out.push('\n');
}

/// Classifies a single application through image synthesis and plan lowering.
///
/// The parse has already succeeded (the caller holds an [`ApplicationProgram`]).
/// Both stages run inside [`catch_unwind`] so a panic in either becomes a
/// `Panicked` bucket rather than aborting the sweep — a panic is never an
/// acceptable outcome and must be fixed, but the sweep must survive to report the
/// rest of the corpus.
pub fn classify_application(app: &ApplicationProgram) -> AppSweep {
    let mask = app.mask_version.clone();

    // Stage 2: image synthesis (no overrides, no per-instance base offsets — the
    // pure product-default image, exactly what the sweep measures).
    let image = match catch_unwind(AssertUnwindSafe(|| {
        bussard_prod::compute_parameter_image(app, &BTreeMap::new(), &BTreeMap::new())
    })) {
        Ok(Ok(images)) => ImageClass::Ok {
            segments: images.len(),
        },
        Ok(Err(e)) => ImageClass::Refused {
            reason: normalize_image_error(&e.to_string()),
        },
        Err(_) => ImageClass::Panicked,
    };

    // Stage 3: plan lowering against the app's OWN declared mask, so the family
    // gate and mask-match pass and we exercise the op lowering itself.
    let plan = match app
        .mask_version
        .as_deref()
        .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())
    {
        None => PlanClass::Refused {
            reason: "MissingAppMask".to_string(),
        },
        Some(device_mask) => {
            match catch_unwind(AssertUnwindSafe(|| {
                plan_flash(
                    app,
                    "1.1.1",
                    device_mask,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    None,
                    &BTreeMap::new(),
                )
            })) {
                Ok(Ok(plan)) => PlanClass::Executable {
                    steps: plan.steps.len(),
                },
                Ok(Err(PlanError::NotSystemB { system, .. })) => PlanClass::NotSupportedFamily {
                    system: system.to_string(),
                },
                Ok(Err(e)) => PlanClass::Refused {
                    reason: normalize_plan_error(&e),
                },
                Err(_) => PlanClass::Panicked,
            }
        }
    };

    AppSweep {
        id: app.id.clone(),
        mask,
        image,
        plan,
    }
}

/// Reads and classifies a single product file. Reading is wrapped in
/// [`catch_unwind`] so a parser panic is a contained `Panicked` parse bucket.
pub fn sweep_file(path: &Path) -> ProductSweep {
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let read = catch_unwind(AssertUnwindSafe(|| bussard_prod::read_knxprod(path)));
    match read {
        Ok(Ok(product)) => {
            let apps: Vec<AppSweep> = product
                .applications
                .iter()
                .map(classify_application)
                .collect();
            ProductSweep {
                file,
                parse: ParseClass::Ok { apps: apps.len() },
                apps,
            }
        }
        Ok(Err(e)) => ProductSweep {
            file,
            parse: ParseClass::Failed {
                reason: normalize_parse_error(&e.to_string()),
            },
            apps: Vec::new(),
        },
        Err(_) => ProductSweep {
            file,
            parse: ParseClass::Panicked,
            apps: Vec::new(),
        },
    }
}

/// Sweeps every `.knxprod` under `dir` (one level of nesting, to cover the
/// `<dir>/vendor/` download cache) and assembles the manifest.
pub fn sweep_corpus(dir: &Path) -> SweepManifest {
    let files = knxprod_files(dir);
    let products: Vec<ProductSweep> = files.iter().map(|p| sweep_file(p)).collect();
    manifest_from_products(products)
}

/// Assembles a [`SweepManifest`] from already-classified product sweeps. Split
/// out so tooling can feed committed fixtures (not just a `.knxprod` cache).
pub fn manifest_from_products(mut products: Vec<ProductSweep>) -> SweepManifest {
    products.sort_by(|a, b| a.file.cmp(&b.file));

    let mut totals = SweepTotals::default();
    let mut plan_reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut image_reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut parse_reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut family: BTreeMap<String, FamilyCoverage> = BTreeMap::new();

    for p in &products {
        totals.products += 1;
        match &p.parse {
            ParseClass::Ok { .. } => totals.parse_ok += 1,
            ParseClass::Failed { reason } => {
                totals.parse_failed += 1;
                *parse_reasons.entry(reason.clone()).or_insert(0) += 1;
            }
            ParseClass::Panicked => totals.parse_panicked += 1,
        }

        for a in &p.apps {
            totals.apps += 1;
            let fam = family.entry(family_label(a.mask.as_deref())).or_default();
            fam.apps += 1;

            match &a.image {
                ImageClass::Ok { .. } => totals.image_ok += 1,
                ImageClass::Refused { reason } => {
                    totals.image_refused += 1;
                    *image_reasons.entry(reason.clone()).or_insert(0) += 1;
                }
                ImageClass::Panicked => totals.image_panicked += 1,
            }

            match &a.plan {
                PlanClass::Executable { .. } => {
                    totals.plan_executable += 1;
                    fam.executable += 1;
                }
                PlanClass::Refused { reason } => {
                    totals.plan_refused += 1;
                    fam.refused += 1;
                    *plan_reasons.entry(reason.clone()).or_insert(0) += 1;
                }
                PlanClass::NotSupportedFamily { .. } => {
                    totals.plan_not_supported_family += 1;
                    fam.not_supported_family += 1;
                }
                PlanClass::Panicked => {
                    totals.plan_panicked += 1;
                    fam.panicked += 1;
                }
            }
        }
    }

    SweepManifest {
        note: MANIFEST_NOTE.to_string(),
        totals,
        plan_refusal_ranking: rank(plan_reasons),
        image_refusal_ranking: rank(image_reasons),
        parse_failure_ranking: rank(parse_reasons),
        family_coverage: family,
        products,
    }
}

/// The manifest header note (kept in one place so re-runs stay byte-stable).
const MANIFEST_NOTE: &str = "Corpus-driven conformance sweep. Buckets every application \
in every product through parse -> image-synthesis -> plan-lowering, ranked by refusal reason \
and mask family. A new refusal or panic is a regression the checked-in baseline catches. \
Regenerate with the env-gated corpus test (BUSSARD_PRODUCT_CORPUS set, BUSSARD_UPDATE_SWEEP_MANIFEST=1). \
No vendor product data is committed here — only outcome labels and file names.";

/// Ranks a reason -> count map by count descending, then reason ascending.
fn rank(map: BTreeMap<String, usize>) -> Vec<RankedReason> {
    let mut v: Vec<RankedReason> = map
        .into_iter()
        .map(|(reason, count)| RankedReason { reason, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    v
}

/// The human mask-family label for coverage bucketing. Uses the shared
/// [`bussard_mgmt::system_type`] classifier so labels match the rest of bussard;
/// an app with no parseable mask is `"(no mask)"`.
pub fn family_label(mask: Option<&str>) -> String {
    match mask.and_then(|m| u16::from_str_radix(m.trim(), 16).ok()) {
        Some(m) => bussard_mgmt::system_type(m).to_string(),
        None => "(no mask)".to_string(),
    }
}

/// Normalizes a [`PlanError`] to a short, stable label for ranking. Op-carrying
/// variants keep only the op family (so `LdCtrlAbsSegment (…)` and
/// `LdCtrlTaskSegment` rank by op, not by full free text).
pub fn normalize_plan_error(e: &PlanError) -> String {
    match e {
        PlanError::UnsupportedOp { op } => {
            let head = op.split_whitespace().next().unwrap_or(op);
            format!("UnsupportedOp: {head}")
        }
        PlanError::UnresolvableImage { reason, .. } => {
            format!("UnresolvableImage: {}", first_clause(reason))
        }
        PlanError::MissingAppMask(_) => "MissingAppMask".to_string(),
        PlanError::NoProcedure(_) => "NoProcedure".to_string(),
        PlanError::MaskMismatch { .. } => "MaskMismatch".to_string(),
        PlanError::NoApplication(_) | PlanError::AmbiguousApplication { .. } => {
            "SelectionError".to_string()
        }
        PlanError::AddressOutOfRange { .. } => "AddressOutOfRange".to_string(),
        PlanError::UnsupportedWriteProp { .. } => "UnsupportedWriteProp".to_string(),
        PlanError::MissingTableImage { .. } => "MissingTableImage".to_string(),
        // NotSystemB is bucketed as NotSupportedFamily before reaching here.
        PlanError::NotSystemB { .. } => "NotSupportedFamily".to_string(),
    }
}

/// Normalizes an image-synthesis error message to a short, stable label.
pub fn normalize_image_error(msg: &str) -> String {
    // ProdError::ParameterImage renders as "... : <reason>"; keep the first
    // clause of the reason so distinct data traps rank apart but free-form ids
    // (parameter names) do not explode the ranking.
    format!("ParameterImage: {}", first_clause(msg))
}

/// Normalizes a parse (read_knxprod) error message to a short, stable label.
pub fn normalize_parse_error(msg: &str) -> String {
    first_clause(msg)
}

/// Trims a message to its first colon-delimited clause, capped to a sane length,
/// so rankings group by cause and stay stable across vendor id churn.
fn first_clause(s: &str) -> String {
    let head = s.split(':').next().unwrap_or(s).trim();
    head.chars().take(64).collect()
}

/// Collects the `.knxprod` files at or under `dir` (one level of nesting is
/// enough: `bussard import-product` caches downloads under `<dir>/vendor/`).
/// Sorted and de-duplicated for stable output.
pub fn knxprod_files(dir: &Path) -> Vec<PathBuf> {
    fn is_knxprod(p: &Path) -> bool {
        p.extension().and_then(|e| e.to_str()) == Some("knxprod")
    }
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_family_label_classifies_masks() {
        assert_eq!(family_label(Some("07B0")), "System B");
        assert_eq!(family_label(Some("0705")), "System 7");
        assert_eq!(family_label(Some(" 0012 ")), "System 1");
        assert_eq!(family_label(None), "(no mask)");
        assert_eq!(family_label(Some("zzzz")), "(no mask)");
    }

    #[test]
    fn test_normalize_plan_error_keeps_op_family_only() {
        let e = PlanError::UnsupportedOp {
            op: "LdCtrlAbsSegment (LsmIdx=4 Size=1936)".to_string(),
        };
        assert_eq!(normalize_plan_error(&e), "UnsupportedOp: LdCtrlAbsSegment");
    }

    #[test]
    fn test_rank_orders_by_count_then_name() {
        let mut m = BTreeMap::new();
        m.insert("b".to_string(), 2);
        m.insert("a".to_string(), 2);
        m.insert("c".to_string(), 5);
        let ranked = rank(m);
        assert_eq!(ranked[0].reason, "c");
        assert_eq!(ranked[1].reason, "a"); // tie broken by name
        assert_eq!(ranked[2].reason, "b");
    }

    #[test]
    fn test_manifest_json_roundtrips() {
        let products = vec![ProductSweep {
            file: "x.knxprod".to_string(),
            parse: ParseClass::Ok { apps: 1 },
            apps: vec![AppSweep {
                id: "M-0001_A-0001".to_string(),
                mask: Some("07B0".to_string()),
                image: ImageClass::Ok { segments: 1 },
                plan: PlanClass::Executable { steps: 5 },
            }],
        }];
        let manifest = manifest_from_products(products);
        let json = manifest.to_json();
        let back = SweepManifest::from_json(&json).expect("roundtrip");
        assert_eq!(manifest, back);
        assert_eq!(back.totals.plan_executable, 1);
        assert_eq!(back.family_coverage["System B"].executable, 1);
    }

    #[test]
    fn test_manifest_json_is_byte_stable() {
        // Same input twice must serialize identically (sorted, deterministic).
        let mk = || {
            manifest_from_products(vec![
                ProductSweep {
                    file: "b.knxprod".to_string(),
                    parse: ParseClass::Failed {
                        reason: "boom".to_string(),
                    },
                    apps: vec![],
                },
                ProductSweep {
                    file: "a.knxprod".to_string(),
                    parse: ParseClass::Ok { apps: 1 },
                    apps: vec![AppSweep {
                        id: "M-1_A-1".to_string(),
                        mask: Some("0705".to_string()),
                        image: ImageClass::Ok { segments: 0 },
                        plan: PlanClass::NotSupportedFamily {
                            system: "System 7".to_string(),
                        },
                    }],
                },
            ])
        };
        assert_eq!(mk().to_json(), mk().to_json());
        // Products are sorted by file name regardless of input order.
        assert_eq!(mk().products[0].file, "a.knxprod");
    }
}
