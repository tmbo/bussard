//! A System 7 product's `LdCtrlTaskSegment LsmIdx="5"` plans no record, on
//! 0701 (issue #489) and on 0705 (issue #680).
//!
//! The synthetic product `syn-s7-lsm5` (`M-00FA_A-280F-11`) is `syn-s7-0701`
//! plus a TaskSegment on LSM 5 inside LSM 3's load, the shape of the
//! Busch-Jaeger 0701 applications. ETS's full download of it into knx-sim
//! (`captures/synthetic/syn-s7-lsm5/defaults/`) writes no record with high
//! nibble 5 to `0x0104`. The memory-mapped form has state machines 1 to 4
//! only (KNX 3/5/2 §3.31.2). The plan must carry the records of LSMs 1 to 3
//! exactly as before and none for LSM 5.
//!
//! `syn-s7-lsm5-0705` (`M-00FA_A-2820-10`) is `syn-s7-0705` plus the same
//! TaskSegment on LSM 5. ETS's download of it
//! (`captures/synthetic/syn-s7-lsm5-0705/defaults/`) runs no operation on
//! object 5 and equals `syn-s7-0705`'s apart from the application number.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_download::{FlashStep, plan_flash_sys7_with_hawk};
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `tests-support/synthetic-products/<product>/xml/`.
fn synthetic_xml(product: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products")
        .join(product)
        .join("xml")
}

/// Zips the synthetic `product`'s committed XML with the stub master into
/// `out`.
fn zip_synthetic(product: &str, out: &Path) -> TestResult {
    let root = synthetic_xml(product);
    let mut zip = zip::ZipWriter::new(std::fs::File::create(out)?);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root.join("M-00FA"))? {
        files.push(entry?.path());
    }
    files.sort();
    for path in files {
        let name = path.file_name().ok_or("a file name")?.to_string_lossy();
        zip.start_file(format!("M-00FA/{name}"), opts)?;
        zip.write_all(&std::fs::read(&path)?)?;
    }
    zip.finish()?;
    Ok(())
}

/// Plans the synthetic `product`'s application `app_id` for `mask` at
/// defaults.
fn plan_synthetic(
    product: &str,
    app_id: &str,
    mask: u16,
) -> Result<bussard_download::FlashPlan, Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join(format!("{product}.knxprod"));
    zip_synthetic(product, &path)?;
    let product_data = bussard_prod::read_knxprod(&path)?;
    let app = product_data
        .application_by_id(app_id)
        .ok_or_else(|| format!("the {product} application"))?;
    assert_eq!(
        app.mask_version.as_deref(),
        Some(format!("{mask:04X}").as_str())
    );
    Ok(plan_flash_sys7_with_hawk(
        app,
        "1.1.1",
        mask,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?)
}

/// One load-state-machine step of a System 7 plan, reduced to what the
/// record carries: the kind, the LSM and the address where there is one.
fn lsm_records(steps: &[FlashStep]) -> Vec<(&'static str, u32, Option<u32>)> {
    steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::Sys7Unload { lsm } => Some(("unload", *lsm, None)),
            FlashStep::Sys7StartLoading { lsm } => Some(("load", *lsm, None)),
            FlashStep::Sys7AbsSegment { lsm, address, .. } => Some(("alloc", *lsm, Some(*address))),
            FlashStep::Sys7TaskSegment { lsm, address, .. } => Some(("task", *lsm, Some(*address))),
            FlashStep::Sys7TaskCtrl1 { lsm, address, .. } => {
                Some(("taskctrl1", *lsm, Some(*address)))
            }
            FlashStep::Sys7LoadCompleted { lsm } => Some(("completed", *lsm, None)),
            _ => None,
        })
        .collect()
}

#[test]
fn test_plan_flash_sys7_with_hawk_skips_task_segment_on_lsm5() -> TestResult {
    let plan = plan_synthetic("syn-s7-lsm5", "M-00FA_A-280F-11-0000", 0x0701)?;
    assert!(matches!(
        plan.sys7_lsm(),
        Some(bussard_mgmt::LsmRealisation::MemoryMapped { .. })
    ));

    let records = lsm_records(&plan.steps);
    assert!(
        records.iter().all(|&(_, lsm, _)| lsm != 5),
        "no LSM 5 record is planned: {records:?}"
    );
    // The procedure's records for LSMs 1 to 3, in order, as syn-s7-0701 plans
    // them; the procedure loads nothing on LSM 4.
    let expected: Vec<(&'static str, u32, Option<u32>)> = vec![
        ("unload", 1, None),
        ("unload", 2, None),
        ("unload", 3, None),
        ("load", 1, None),
        ("alloc", 1, Some(0x4000)),
        ("task", 1, Some(0x4000)),
        ("completed", 1, None),
        ("load", 2, None),
        ("alloc", 2, Some(0x4201)),
        ("task", 2, Some(0x4201)),
        ("completed", 2, None),
        ("load", 3, None),
        ("alloc", 3, Some(0x0700)),
        ("alloc", 3, Some(0x4400)),
        ("alloc", 3, Some(0x4440)),
        ("task", 3, Some(0x4400)),
        ("taskctrl1", 3, Some(0x4430)),
        ("completed", 3, None),
    ];
    assert_eq!(records, expected);
    // The pre-download pass still unloads LSMs 1 to 4 (#488 is separate).
    assert!(plan.steps.iter().any(|s| matches!(
        s,
        FlashStep::Sys7PreDownloadRestart { unload } if unload == &[1, 2, 3, 4]
    )));
    Ok(())
}

#[test]
fn test_plan_flash_sys7_with_hawk_skips_task_segment_on_lsm5_on_0705() -> TestResult {
    let plan = plan_synthetic("syn-s7-lsm5-0705", "M-00FA_A-2820-10-0000", 0x0705)?;
    assert!(matches!(
        plan.sys7_lsm(),
        Some(bussard_mgmt::LsmRealisation::Property)
    ));
    let records = lsm_records(&plan.steps);
    assert!(
        records.iter().all(|&(_, lsm, _)| lsm != 5),
        "no LSM 5 record is planned: {records:?}"
    );
    // The records equal syn-s7-0705's, the product without the LSM 5
    // TaskSegment, as ETS's two captures do.
    let base = plan_synthetic("syn-s7-0705", "M-00FA_A-2800-10-0000", 0x0705)?;
    assert_eq!(records, lsm_records(&base.steps));
    assert!(records.contains(&("task", 3, Some(0x4400))));
    Ok(())
}
