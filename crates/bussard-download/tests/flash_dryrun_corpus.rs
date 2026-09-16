//! Env-gated dry-run trace of real vendor load procedures.
//!
//! Reads the developer's local `home_test.knxproj` (not committed; the test
//! skips when absent so CI is unaffected), builds a [`bussard_download::FlashPlan`]
//! for each application program **in dry-run** (no device — the plan is a pure
//! function of the product data and the app's own declared mask), and reports the
//! op-execution trace. This proves the interpreter digests real vendor
//! procedures — including the Jung 23024 — and, where a procedure carries an op
//! the engine cannot yet execute (e.g. `LoadImageProp`), reports the exact
//! pre-flight refusal rather than crashing.
//!
//! Nothing here touches a bus.

use std::collections::BTreeMap;

use bussard_download::{PlanError, plan_flash, trace};

#[test]
fn dry_run_trace_of_real_vendor_procedures() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../home_test.knxproj");
    if !path.exists() {
        eprintln!("home_test.knxproj absent; skipping real-data dry-run trace test");
        return;
    }

    let file = std::fs::File::open(&path).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let names: Vec<String> = zip.file_names().map(str::to_string).collect();
    let app_entries: Vec<String> = names
        .iter()
        .filter(|n| {
            n.split_once('/').is_some_and(|(dir, file)| {
                dir.starts_with("M-") && file.contains("_A-") && n.ends_with(".xml")
            })
        })
        .cloned()
        .collect();

    let mut planned = 0usize;
    let mut refused = 0usize;
    let mut with_image_prop = 0usize;
    let mut jung_seen = false;
    let mut jung_plan_write_bytes: Option<usize> = None;
    let mut jung_image_prop_steps = 0usize;

    for entry in &app_entries {
        let mut f = zip.by_name(entry).unwrap();
        let mut xml = String::new();
        use std::io::Read as _;
        if f.read_to_string(&mut xml).is_err() {
            continue;
        }
        drop(f);

        let id = entry
            .rsplit('/')
            .next()
            .unwrap()
            .strip_suffix(".xml")
            .unwrap();
        let app = bussard_prod::parse_application_program(id, xml.as_bytes()).unwrap();

        // Build the plan in dry-run against the app's OWN declared mask, so the
        // System B gate and the mask compare pass and we exercise the op lowering
        // itself. A missing/non-hex mask is skipped.
        let Some(mask_str) = app.mask_version.as_deref() else {
            continue;
        };
        let Ok(device_mask) = u16::from_str_radix(mask_str.trim(), 16) else {
            continue;
        };

        if xml.contains("LdCtrlLoadImageProp") {
            with_image_prop += 1;
        }

        let is_jung = id.contains("A-20D7-26-");
        if is_jung {
            jung_seen = true;
        }

        match plan_flash(
            &app,
            "1.1.4",
            device_mask,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        ) {
            Ok(plan) => {
                planned += 1;
                if is_jung {
                    jung_plan_write_bytes = Some(plan.total_write_bytes());
                    jung_image_prop_steps = plan
                        .steps
                        .iter()
                        .filter(|s| matches!(s, bussard_download::FlashStep::LoadImageProp { .. }))
                        .count();
                    eprintln!(
                        "\nJung 23024 ({id}): DRY-RUN plan — {} step(s), {} write byte(s), \
                         ~{} frame(s), est. {:.1}s",
                        plan.steps.len(),
                        plan.total_write_bytes(),
                        plan.estimated_write_frames(),
                        plan.estimated_duration().as_secs_f64(),
                    );
                    for line in trace(&plan) {
                        eprintln!("  {line}");
                    }
                }
            }
            Err(PlanError::NotSystemB { .. }) => {
                // App mask is not System B — expected for many corpus apps.
            }
            Err(err) => {
                refused += 1;
                if is_jung {
                    eprintln!("\nJung 23024 ({id}): DRY-RUN refused at pre-flight — {err}");
                }
            }
        }
    }

    eprintln!(
        "\ndry-run: {} application program(s) scanned; {with_image_prop} carry LdCtrlLoadImageProp; \
         {planned} produced an executable plan, {refused} refused at pre-flight \
         (unsupported ops / unresolvable images)",
        app_entries.len()
    );

    assert!(
        jung_seen,
        "Jung 23024 application not found in home_test.knxproj"
    );
    // With LoadImageProp now executable, the Jung 23024 MergedProcedure lowers to
    // a COMPLETE plan: its MergeId blocks (allocate → write → image-prop) are
    // concatenated, so it both writes its segment and runs the MCB integrity
    // checks. This is the headline result of the LoadImageProp work — the Jung
    // 23024 (and the same-shape MDT A-0007) go from refused to fully executable.
    assert_eq!(
        jung_image_prop_steps, 4,
        "the Jung 23024 must lower its four LdCtrlLoadImageProp MCB checks"
    );
    assert_eq!(
        jung_plan_write_bytes,
        Some(19155),
        "the Jung 23024 must stream its 19155-octet segment image in the same plan"
    );
    assert!(
        planned + refused > 0,
        "expected at least one System B app to be planned or explicitly refused"
    );
}
