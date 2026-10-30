//! A load-procedure `<choose>` whose taken branch writes part of a segment
//! (issue #411) plans as ETS downloads it: the taken branch's writes only,
//! the rest of the allocation kept on the device.
//!
//! The synthetic product `syn-choose-partial-segment` (#604 row 8) is
//! `syn-minimal` with a keep-data parameter (`P-3_R-3`, default 1) and its
//! segment write as a `<choose>` on it: `keep` writes octets 0..128 of the
//! 256-octet segment, `overwrite` all of it. ETS's download of it
//! (`captures/synthetic/syn-choose-partial-segment/defaults/ops.txt`)
//! allocates 256 octets and writes 128.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_download::{
    FlashPlan, FlashStep, build_table_images, kept_octets, plan_flash, template_ops_for,
};
use bussard_prod::ProductData;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The keep-data parameter's `ParameterRef`, app-relative.
const KEEP: &str = "P-3_R-3";

/// `tests-support/synthetic-products/syn-choose-partial-segment/xml/`.
fn product_xml() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products/syn-choose-partial-segment/xml")
}

/// The product, zipped with the stub master the way the catalogue ships it.
fn product(dir: &Path) -> Result<ProductData, Box<dyn std::error::Error>> {
    let out = dir.join("syn-choose-partial-segment.knxprod");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&out)?);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(product_xml().join("M-00FA"))? {
        files.push(entry?.path());
    }
    files.sort();
    for path in files {
        let name = path.file_name().ok_or("a file name")?.to_string_lossy();
        zip.start_file(format!("M-00FA/{name}"), opts)?;
        zip.write_all(&std::fs::read(&path)?)?;
    }
    zip.finish()?;
    Ok(bussard_prod::read_knxprod(&out)?)
}

/// The full download plan of the product under `overrides`.
fn plan(
    product: &ProductData,
    overrides: &BTreeMap<String, String>,
) -> Result<FlashPlan, Box<dyn std::error::Error>> {
    let app = product.applications.first().ok_or("one application")?;
    let template = template_ops_for(product, app).ok_or("a template for 07B0")?;
    let target: bussard_model::IndividualAddress = "1.1.1".parse()?;
    let tables = build_table_images(None, target, app, overrides);
    Ok(plan_flash(
        app,
        "1.1.1",
        0x07B0,
        overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?)
}

/// The application segment writes (object 4): offset, image offset, length.
fn app_writes(plan: &FlashPlan) -> Vec<(u32, usize, usize)> {
    plan.steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::WriteRelMem {
                offset,
                image,
                target: Some(4),
            } => Some((*offset, image.offset, image.len)),
            _ => None,
        })
        .collect()
}

#[test]
fn test_plan_flash_partial_segment_writes_the_taken_half() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let product = product(tmp.path())?;
    let plan = plan(&product, &BTreeMap::new())?;
    assert_eq!(
        app_writes(&plan),
        vec![(0, 0, 128)],
        "one write of 128 octets"
    );
    assert!(
        plan.steps.iter().any(|s| matches!(
            s,
            FlashStep::AllocateSegment {
                size: 256,
                target: Some(4),
                ..
            }
        )),
        "the whole segment is allocated, as ETS does (op 17)"
    );
    let kept = plan.kept();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(kept[0].object, 4);
    assert_eq!(kept[0].allocated, 256);
    assert_eq!(kept[0].ranges, vec![(128, 256)]);
    assert_eq!(kept[0].label(), "object 4 octets 128..256 kept");
    let segment = &kept[0].segment;
    assert!(
        plan.placed_octets(segment)
            .is_some_and(|p| p.iter().all(|&i| i < 128)),
        "no kept octet counts as placed"
    );
    assert_eq!(plan.total_write_bytes() - table_bytes(&plan), 128);
    // The read-back and the plan locate the same gap without a plan at hand.
    let app = product.applications.first().ok_or("one application")?;
    let memo = bussard_prod::dynamic::DynamicMemo::new(app);
    assert_eq!(kept_octets(app, &BTreeMap::new(), &memo), kept.to_vec());
    Ok(())
}

#[test]
fn test_plan_flash_partial_segment_other_branch_writes_the_whole_segment() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let product = product(tmp.path())?;
    let overrides = BTreeMap::from([(KEEP.to_string(), "0".to_string())]);
    let plan = plan(&product, &overrides)?;
    assert_eq!(app_writes(&plan), vec![(0, 0, 256)]);
    assert!(plan.kept().is_empty());
    let app = product.applications.first().ok_or("one application")?;
    let memo = bussard_prod::dynamic::DynamicMemo::new(app);
    assert!(kept_octets(app, &overrides, &memo).is_empty());
    Ok(())
}

/// The octets the table writes stream (objects 1 to 3).
fn table_bytes(plan: &FlashPlan) -> usize {
    plan.steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::WriteRelMem { image, target, .. } if *target != Some(4) => Some(image.len),
            _ => None,
        })
        .sum()
}
