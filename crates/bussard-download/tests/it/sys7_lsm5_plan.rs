//! A 0701 product's `LdCtrlTaskSegment LsmIdx="5"` plans no record (issue
//! #489).
//!
//! The synthetic product `syn-s7-lsm5` (`M-00FA_A-280F-11`) is `syn-s7-0701`
//! plus a TaskSegment on LSM 5 inside LSM 3's load, the shape of the
//! Busch-Jaeger 0701 applications. ETS's full download of it into knx-sim
//! (`captures/synthetic/syn-s7-lsm5/defaults/`) writes no record with high
//! nibble 5 to `0x0104`. The memory-mapped form has state machines 1 to 4
//! only (KNX 3/5/2 §3.31.2). The plan must carry the records of LSMs 1 to 3
//! exactly as before and none for LSM 5.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_download::{FlashStep, plan_flash_sys7_with_hawk};
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `tests-support/synthetic-products/syn-s7-lsm5/xml/`.
fn syn_s7_lsm5_xml() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products/syn-s7-lsm5/xml")
}

/// Zips `syn-s7-lsm5`'s committed XML with the stub master into `out`.
fn zip_syn_s7_lsm5(out: &Path) -> TestResult {
    let root = syn_s7_lsm5_xml();
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
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-s7-lsm5.knxprod");
    zip_syn_s7_lsm5(&path)?;
    let product = bussard_prod::read_knxprod(&path)?;
    let app = product
        .application_by_id("M-00FA_A-280F-11-0000")
        .ok_or("the syn-s7-lsm5 application")?;
    assert_eq!(app.mask_version.as_deref(), Some("0701"));

    let plan = plan_flash_sys7_with_hawk(
        app,
        "1.1.1",
        0x0701,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
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
