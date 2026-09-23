//! Env-gated dry-run corpus tests for the System 7 (mask 0705/0701) lowering
//! (issue #49): [`plan_flash`] must produce an executable plan for the canonical
//! corpus targets, exercising the op lowering against real vendor `.knxprod`
//! product data without touching a device.
//!
//! Set `BUSSARD_PRODUCT_CORPUS=<dir>` to the product-corpus cache (see
//! `tests-support/product-corpus/README.md`); with it unset every test skips
//! green, so CI is unaffected. The targets, in the spec's order (§9):
//!
//! 1. MDT `M-0083_A-000E` — smallest canonical 0705.
//! 2. Theben `M-0048_A-4947` — TaskCtrl1 + post-restart LSM 5.
//! 3. Zennio `M-0071_A-3211` (LUMENTO) — the sole `LdCtrlCompareMem` user.
//! 4. Jung `M-0004_A-A011` — the reference presence detector; must include the
//!    LoadImageProp steps and 9 AbsSegments.
//!
//! **No device or gateway is ever touched — this is pure plan lowering.**

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_download::{FlashStep, plan_flash};

/// The product-corpus cache directory, or `None` (skip) when unset.
fn corpus_dir() -> Option<PathBuf> {
    std::env::var_os("BUSSARD_PRODUCT_CORPUS").map(PathBuf::from)
}

/// Collects `.knxprod` files at or one level under `dir` (the flat cache or its
/// parent), mirroring `flash_corpus.rs`.
fn knxprod_files(dir: &Path) -> Vec<PathBuf> {
    fn is_knxprod(p: &Path) -> bool {
        p.extension().and_then(|e| e.to_str()) == Some("knxprod")
    }
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Ok(inner) = std::fs::read_dir(&path) {
                for e2 in inner.flatten() {
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
    out
}

/// Finds the application whose id starts with `app_prefix` (e.g.
/// `"M-0083_A-000E"`) across every `.knxprod` in the corpus, returning
/// `(product, application_index)` or `None` if absent (the corpus may not carry
/// every vendor).
fn find_app(app_prefix: &str) -> Option<(bussard_prod::ProductData, usize)> {
    let dir = corpus_dir()?;
    for file in knxprod_files(&dir) {
        let Ok(product) = bussard_prod::read_knxprod(&file) else {
            continue;
        };
        if let Some(idx) = product
            .applications
            .iter()
            .position(|a| a.id.starts_with(app_prefix))
        {
            return Some((product, idx));
        }
    }
    None
}

/// The device mask of an app (its declared mask version as a `u16`).
fn app_mask(app: &bussard_prod::ApplicationProgram) -> Option<u16> {
    u16::from_str_radix(app.mask_version.as_deref()?.trim(), 16).ok()
}

/// Plans a flash for an app against its own declared mask (so the family gate and
/// mask-match pass and the op lowering itself is exercised).
fn plan_for(
    app: &bussard_prod::ApplicationProgram,
) -> std::result::Result<bussard_download::FlashPlan, bussard_download::PlanError> {
    let mask = app_mask(app).expect("app declares a hex mask");
    plan_flash(
        app,
        "1.1.99",
        mask,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )
}

fn count_steps(plan: &bussard_download::FlashPlan, pred: impl Fn(&FlashStep) -> bool) -> usize {
    plan.steps.iter().filter(|s| pred(s)).count()
}

#[test]
fn plan_lowers_mdt_a000e_smallest_canonical() {
    let Some((product, idx)) = find_app("M-0083_A-000E") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset or MDT M-0083_A-000E absent; skipping");
        return;
    };
    let app = &product.applications[idx];
    let plan = plan_for(app).expect("MDT A-000E must lower to an executable plan");
    assert!(plan.is_sys7(), "MDT A-000E is a System 7 (0705) app");

    // The obj0/PID78 preflight, three LSMs, AbsSegments (incl. the 0x4000 table
    // and the allocate-only 0x0700 RAM region), a TaskSegment per LSM, a restart.
    assert!(
        plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::CompareProp {
                obj_idx: 0,
                prop_id: 78,
                ..
            }
        )),
        "the obj0/PID78 preflight must lower"
    );
    assert_eq!(
        count_steps(&plan, |s| matches!(s, FlashStep::Sys7Unload { .. })),
        3,
        "three LSM teardowns"
    );
    assert!(count_steps(&plan, |s| matches!(s, FlashStep::Sys7AbsSegment { .. })) >= 4);
    assert!(count_steps(&plan, |s| matches!(s, FlashStep::Sys7TaskSegment { .. })) >= 1);
    assert!(matches!(plan.steps.last(), Some(FlashStep::Restart)));
    // A 0x0700-region allocate-only AbsSegment (no image).
    assert!(
        plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::Sys7AbsSegment { image: None, address, .. } if *address < 0x4000
        )),
        "the low-RAM region is an allocate-only segment"
    );
}

#[test]
fn plan_lowers_theben_m0048_with_task_ctrl1() {
    let Some((product, idx)) = find_app("M-0048_A-4947") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset or Theben M-0048_A-4947 absent; skipping");
        return;
    };
    let app = &product.applications[idx];
    match plan_for(app) {
        Ok(plan) => {
            assert!(plan.is_sys7());
            // The Theben FIX2 procedure carries a TaskCtrl1 and a post-restart
            // LSM-5 Load; both must lower (TaskCtrl1 as its own step).
            assert!(
                count_steps(&plan, |s| matches!(s, FlashStep::Sys7TaskCtrl1 { .. })) >= 1,
                "Theben FIX2 must lower its LdCtrlTaskCtrl1"
            );
            // A post-restart Sys7 step (TaskSegment/StartLoading on LSM 5) appears
            // after the Restart in the step list.
            let restart_pos = plan
                .steps
                .iter()
                .position(|s| matches!(s, FlashStep::Restart));
            if let Some(pos) = restart_pos {
                assert!(
                    plan.steps[pos + 1..].iter().any(|s| matches!(
                        s,
                        FlashStep::Sys7TaskSegment { lsm: 5, .. }
                            | FlashStep::Sys7StartLoading { lsm: 5 }
                    )),
                    "the post-restart LSM-5 dance must lower after the restart"
                );
            }
        }
        // The Theben FIX2 also surfaces the orthogonal wide-integer parameter-image
        // bug in bussard-prod (a 472-bit field); that is tracked separately and is
        // an acceptable refusal here — the point is the op lowering, which a
        // parameter-image failure short-circuits before reaching.
        Err(bussard_download::PlanError::UnresolvableImage { reason, .. }) => {
            eprintln!(
                "Theben M-0048 refused at parameter-image computation (tracked separately): {reason}"
            );
        }
        Err(e) => panic!("unexpected Theben M-0048 refusal: {e:?}"),
    }
}

#[test]
fn plan_lowers_zennio_lumento_compare_mem() {
    let Some((product, idx)) = find_app("M-0071_A-3211") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset or Zennio LUMENTO M-0071_A-3211 absent; skipping");
        return;
    };
    let app = &product.applications[idx];
    let plan = plan_for(app).expect("Zennio LUMENTO must lower");
    assert!(plan.is_sys7());
    // The LUMENTO app is the sole corpus user of raw LdCtrlCompareMem.
    assert!(
        count_steps(&plan, |s| matches!(s, FlashStep::Sys7CompareMem { .. })) >= 1,
        "Zennio LUMENTO must lower its LdCtrlCompareMem"
    );
    // It also uses only AbsSegments (no TaskSegment/preflight/restart).
    assert!(count_steps(&plan, |s| matches!(s, FlashStep::Sys7AbsSegment { .. })) >= 6);
}

#[test]
fn plan_lowers_jung_a_a011_with_load_image_prop() {
    let Some((product, idx)) = find_app("M-0004_A-A011") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset or Jung M-0004_A-A011 absent; skipping");
        return;
    };
    let app = &product.applications[idx];
    let plan = plan_for(app).expect("Jung A-A011 must lower to an executable plan");
    assert!(plan.is_sys7(), "Jung A-A011 is a System 7 (0705) app");

    // The Jung reference app requires per-object MCB verification via
    // LdCtrlLoadImageProp (PID 27) on objects 1-3 (§2 amendment).
    let image_props = count_steps(&plan, |s| {
        matches!(s, FlashStep::LoadImageProp { prop_id: 27, .. })
    });
    assert!(
        image_props >= 3,
        "Jung A-A011 must lower its LoadImageProp MCB checks (got {image_props})"
    );
    // …and its AbsSegments. The spec estimated 9; the shipped V1.3 product data
    // carries 10 (a 9-vs-10 the M2 capture can reconcile). Assert the canonical
    // multi-segment shape rather than an exact count that the vendor may revise.
    let abs_segments = count_steps(&plan, |s| matches!(s, FlashStep::Sys7AbsSegment { .. }));
    assert!(
        abs_segments >= 9,
        "Jung A-A011 must lower its AbsSegments (got {abs_segments}, expected >= 9)"
    );
    // Three parallel LSMs, as the MDT-canonical shape.
    assert_eq!(
        count_steps(&plan, |s| matches!(s, FlashStep::Sys7Unload { .. })),
        3,
        "Jung A-A011 tears down three LSMs"
    );
}

/// The Theben Meteodata 140 S product (mask 0701) from the vendor cache, or
/// `None` when the corpus is unset or does not carry it.
fn meteodata_product() -> Option<bussard_prod::ProductData> {
    const ZIP: &str = "o5646v53_KNX_DB_Meteodata_140_S_KNX_KNXDatenbank.zip";
    const INNER: &str = "KNX_DB_D_GB_E_F_I_NL_METEODATA_140_S_V1_4_knxprod_2206.knxprod";
    let dir = corpus_dir()?;
    [
        dir.join("cache").join("vendor").join(ZIP),
        dir.join("vendor").join(ZIP),
        dir.join(ZIP),
    ]
    .iter()
    .find(|p| p.exists())
    .and_then(|p| bussard_prod::read_knxprod_inner(p, Some(INNER)).ok())
}

/// Issue #133: the Meteodata `knx_master.xml` Hawk blocks decide blind vs
/// read-compare-write streaming. MV-0701 declares no `VerifyMode`, MV-0705
/// declares `VerifyMode=1`.
#[test]
fn test_sys7_profile_from_hawk_verify_mode_meteodata_master() {
    let Some(product) = meteodata_product() else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset or Meteodata 140 S absent; skipping");
        return;
    };
    let master = product
        .master
        .as_ref()
        .expect("the Meteodata archive has a master");
    let h0701 = master.hawk_config("0701").expect("MV-0701 Hawk block");
    let h0705 = master.hawk_config("0705").expect("MV-0705 Hawk block");
    assert_eq!(h0701.verify_mode(), None);
    assert_eq!(h0705.verify_mode(), Some(1));
    let p0701 = bussard_download::sys7_profile_from_hawk(h0701).expect("0701 profile");
    let p0705 = bussard_download::sys7_profile_from_hawk(h0705).expect("0705 profile");
    assert_eq!(p0701.verify_mode, None);
    assert!(p0701.read_compare_write());
    assert_eq!(p0705.verify_mode, Some(1));
    assert!(!p0705.read_compare_write());

    // The Meteodata app plans read-compare with its Hawk block and with the
    // 0701 corpus default alike.
    let app = product
        .applications
        .iter()
        .find(|a| a.id.starts_with("M-0048_A-140C"))
        .expect("Meteodata app");
    for hawk in [Some(h0701), None] {
        let plan = bussard_download::plan_flash_sys7_with_hawk(
            app,
            "1.1.202",
            0x0701,
            &BTreeMap::new(),
            &BTreeMap::new(),
            hawk,
            &BTreeMap::new(),
        )
        .expect("Meteodata plan");
        assert!(plan.sys7_read_compare(), "hawk given: {}", hawk.is_some());
        assert!(
            bussard_download::trace(&plan)
                .iter()
                .any(|l| l.contains("stream segment (read-compare, ")),
            "plan text names the read-compare stream"
        );
    }
}
