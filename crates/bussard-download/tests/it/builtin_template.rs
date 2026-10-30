//! A product whose `knx_master.xml` is the `<KNX/>` stub still plans the full
//! download of a `MergedProcedure` application (issue #607).
//!
//! The synthetic product `syn-minimal` (07B0, two `MergeId` blocks) is zipped
//! with the stub master, the way the synthetic catalogue ships it. The plan
//! must carry the frame of the mask's complete-download template (unload of
//! every load state machine, the table allocations and writes, the program
//! version, `LoadCompleted` of every object, restart) around the
//! application's own blocks, from bussard's built-in template.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_download::{FlashStep, build_table_images, plan_flash, template_ops_for};
use bussard_prod::MasterTemplate;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `tests-support/synthetic-products/syn-minimal/xml/`.
fn syn_minimal_xml() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products/syn-minimal/xml")
}

/// Zips `syn-minimal`'s XML with the stub master into `out`.
fn zip_syn_minimal(out: &Path) -> TestResult {
    let root = syn_minimal_xml();
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

#[test]
fn test_template_ops_for_stub_master_uses_builtin() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-minimal.knxprod");
    zip_syn_minimal(&path)?;
    let product = bussard_prod::read_knxprod(&path)?;
    let app = product.applications.first().ok_or("one application")?;
    assert_eq!(app.mask_version.as_deref(), Some("07B0"));

    let template = template_ops_for(&product, app).ok_or("a template for 07B0")?;
    let builtin = MasterTemplate::builtin_for_mask("07B0").ok_or("a built-in 07B0")?;
    assert_eq!(template, builtin.ops);

    let target: bussard_model::IndividualAddress = "1.1.1".parse()?;
    let overrides = BTreeMap::new();
    let tables = build_table_images(None, target, app, &overrides);
    let plan = plan_flash(
        app,
        "1.1.1",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?;
    let unloads: Vec<Option<u32>> = plan
        .steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::Unload { target, .. } => Some(*target),
            _ => None,
        })
        .collect();
    assert_eq!(
        unloads,
        vec![Some(5), Some(4), Some(3), Some(2), Some(1)],
        "the template unloads every load state machine"
    );
    let completed: Vec<Option<u32>> = plan
        .steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::LoadCompleted { target } => Some(*target),
            _ => None,
        })
        .collect();
    // LSM 5 gets no segment from syn-minimal and is skipped with its Load.
    assert!(
        [Some(4), Some(3), Some(2), Some(1)]
            .iter()
            .all(|t| completed.contains(t)),
        "LoadCompleted for the application and the three tables: {completed:?}"
    );
    let allocations: Vec<Option<u32>> = plan
        .steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::AllocateSegment { target, .. } => Some(*target),
            _ => None,
        })
        .collect();
    for lsm in [4, 3, 1, 2] {
        assert!(
            allocations.contains(&Some(lsm)),
            "an allocation of object {lsm}: {allocations:?}"
        );
    }
    assert!(
        plan.steps
            .iter()
            .any(|s| matches!(s, FlashStep::WriteProp { .. })),
        "the PID_PROGRAM_VERSION write"
    );
    assert!(matches!(plan.steps.last(), Some(FlashStep::Restart)));
    Ok(())
}
