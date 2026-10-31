//! A System 7 load-procedure `<choose>` whose taken branch allocates an
//! absolute segment in parts (issue #411, System 7 half) plans as ETS
//! downloads it: each `LdCtrlAbsSegment` record as declared, each part of
//! the image streamed into its allocation, the gap kept on the device.
//!
//! The synthetic product `syn-s7-choose-split` (#604 row 9) is `syn-s7-0705`
//! with a `<choose>` on `mode` (`P-1_R-1`, default 1): `1` allocates the
//! 64-octet parameter segment `AS-4440` as `0x4440` (1 octet) and `0x4443`
//! (61 octets), any other value all 64. The 16-bit parameter `delay` sits at
//! octets 1..3, in the gap. ETS's download of it
//! (`captures/synthetic/syn-s7-choose-split/defaults/ops.txt`, ops 33 to 41)
//! sends the two records, writes `0x4440` and `0x4443..0x447F`, and never
//! writes or reads `0x4441..0x4442`.
//!
//! `syn-s7-static-split` (issue #657) is the same product with the
//! `<choose>` removed: the procedure always allocates the two parts. ETS
//! downloads it alike (`captures/synthetic/syn-s7-static-split/defaults/ops.txt`,
//! the same sequence and image), so the planner does too.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_download::{
    FlashPlan, FlashStep, allocation_change, decode_parameters, kept_octets, plan_flash,
    planned_parameter_regions, regions_memory,
};
use bussard_prod::ProductData;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The `mode` parameter's `ParameterRef`, app-relative.
const MODE: &str = "P-1_R-1";
/// The parameter segment.
const SEGMENT: &str = "M-00FA_A-2809-10-0000_AS-4440";

/// The static split's parameter segment.
const STATIC_SEGMENT: &str = "M-00FA_A-2889-10-0000_AS-4440";

/// `tests-support/synthetic-products/<name>/xml/`.
fn product_xml(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products")
        .join(name)
        .join("xml")
}

/// `syn-s7-choose-split`, zipped with the stub master.
fn product(dir: &Path) -> Result<ProductData, Box<dyn std::error::Error>> {
    synthetic(dir, "syn-s7-choose-split")
}

/// The synthetic product `name`, zipped with the stub master the way the
/// catalogue ships it.
fn synthetic(dir: &Path, name: &str) -> Result<ProductData, Box<dyn std::error::Error>> {
    let out = dir.join(format!("{name}.knxprod"));
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&out)?);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(product_xml(name).join("M-00FA"))? {
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
    Ok(plan_flash(
        app,
        "1.1.1",
        0x0705,
        overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?)
}

/// Every allocation of the parameter segment: address, allocated size,
/// image offset, streamed length.
fn segment_records(plan: &FlashPlan) -> Vec<(u32, u32, usize, usize)> {
    records_of(plan, SEGMENT)
}

/// Every allocation of `segment`: address, allocated size, image offset,
/// streamed length.
fn records_of(plan: &FlashPlan, segment: &str) -> Vec<(u32, u32, usize, usize)> {
    plan.steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::Sys7AbsSegment {
                address,
                size,
                image: Some(image),
                ..
            } if image.segment_id == segment => Some((*address, *size, image.offset, image.len)),
            _ => None,
        })
        .collect()
}

#[test]
fn test_plan_flash_sys7_split_segment_writes_the_two_parts() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let product = product(tmp.path())?;
    let plan = plan(&product, &BTreeMap::new())?;
    // The two allocation records of the taken branch, each streaming exactly
    // the octets it allocates (ETS ops 33 to 41).
    assert_eq!(
        segment_records(&plan),
        vec![(0x4440, 1, 0, 1), (0x4443, 61, 3, 61)]
    );
    let image = plan.image_bytes(SEGMENT).ok_or("the parameter image")?;
    assert_eq!(image.len(), 64);
    assert_eq!(image[0], 1, "mode = 1 at 0x4440");
    // The gap is masked off: no read-compare, diff or parameter-only
    // download writes it.
    let mask = plan.segment_mask(SEGMENT).ok_or("a mask")?;
    let unwritten: Vec<usize> = (0..64).filter(|&i| mask[i] != 0xFF).collect();
    assert_eq!(unwritten, vec![1, 2]);
    // The gap is kept on the device, and the octets of `delay` are not placed.
    let kept = plan.kept();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(kept[0].object, 3);
    assert_eq!(kept[0].segment, SEGMENT);
    assert_eq!(kept[0].ranges, vec![(1, 3)]);
    assert_eq!(kept[0].address, Some(0x4440));
    assert_eq!(kept[0].label(), "LSM 3 segment 0x4440 octets 1..3 kept");
    assert!(
        plan.placed_octets(SEGMENT)
            .is_some_and(|p| !p.contains(&1) && !p.contains(&2) && p.contains(&0)),
        "no kept octet counts as placed"
    );
    // The read-back and the plan locate the same gap without a plan at hand.
    let app = product.applications.first().ok_or("one application")?;
    let memo = bussard_prod::dynamic::DynamicMemo::new(app);
    assert_eq!(kept_octets(app, &BTreeMap::new(), &memo), kept.to_vec());
    // A device that holds something else in the gap: `delay` is reported as
    // kept with the device's value, never as a difference.
    let mut current = regions_memory(&planned_parameter_regions(&plan));
    let held = current.get_mut(SEGMENT).ok_or("the parameter region")?;
    held[1] = 0x00;
    held[2] = 0x0A;
    let decoded = decode_parameters(app, &BTreeMap::new(), &BTreeMap::new(), &current);
    assert!(decoded.differences.is_empty(), "{:?}", decoded.differences);
    let names: Vec<String> = decoded.kept.iter().map(|k| k.kept_line()).collect();
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(
        names[0].contains("the device holds 10") && names[0].contains("model says 300"),
        "{names:?}"
    );
    Ok(())
}

#[test]
fn test_plan_flash_sys7_split_segment_other_branch_allocates_the_whole_segment() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let product = product(tmp.path())?;
    let overrides = BTreeMap::from([(MODE.to_string(), "0".to_string())]);
    let plan = plan(&product, &overrides)?;
    assert_eq!(segment_records(&plan), vec![(0x4440, 64, 0, 64)]);
    assert!(plan.kept().is_empty());
    assert!(
        plan.placed_octets(SEGMENT)
            .is_some_and(|p| p.contains(&1) && p.contains(&2)),
        "delay is written with the whole segment"
    );
    let app = product.applications.first().ok_or("one application")?;
    let memo = bussard_prod::dynamic::DynamicMemo::new(app);
    assert!(kept_octets(app, &overrides, &memo).is_empty());
    Ok(())
}

/// A parameter-only download sends no allocation record, so a change of
/// `mode` (which picks the allocation layout) needs a full download; a
/// change of `delay` alone does not.
#[test]
fn test_allocation_change_names_a_new_layout() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let product = product(tmp.path())?;
    let app = product.applications.first().ok_or("one application")?;
    let memo = bussard_prod::dynamic::DynamicMemo::new(app);
    let split = BTreeMap::from([(MODE.to_string(), "1".to_string())]);
    let whole = BTreeMap::from([(MODE.to_string(), "2".to_string())]);
    let why = allocation_change(app, &split, &whole, &memo).ok_or("a layout change")?;
    assert_eq!(
        why,
        "the load procedure allocates LSM 3 0x4440 (64 octets) instead of \
         LSM 3 0x4440 (1 octets), LSM 3 0x4443 (61 octets)"
    );
    let delay = BTreeMap::from([
        (MODE.to_string(), "1".to_string()),
        ("P-2_R-2".to_string(), "17".to_string()),
    ]);
    assert_eq!(allocation_change(app, &split, &delay, &memo), None);
    assert_eq!(
        allocation_change(
            app,
            &whole,
            &BTreeMap::from([(MODE.to_string(), "0".to_string())]),
            &memo
        ),
        None
    );
    Ok(())
}

/// The memory writes of a plan's parameter-segment streams, as
/// `(first address, octets)`: what goes on the wire for the segment.
fn written_ranges(plan: &FlashPlan, segment: &str) -> Vec<(u32, usize)> {
    records_of(plan, segment)
        .into_iter()
        .map(|(address, _, _, len)| (address, len))
        .collect()
}

#[test]
fn test_plan_flash_sys7_static_split_keeps_the_gap() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let product = synthetic(tmp.path(), "syn-s7-static-split")?;
    // No refusal: the procedure's two records outside any `<choose>`, each
    // streaming exactly the octets it allocates, as ETS does.
    let plan = plan(&product, &BTreeMap::new())?;
    assert_eq!(
        records_of(&plan, STATIC_SEGMENT),
        vec![(0x4440, 1, 0, 1), (0x4443, 61, 3, 61)]
    );
    assert_eq!(
        written_ranges(&plan, STATIC_SEGMENT),
        vec![(0x4440, 1), (0x4443, 61)]
    );
    // The gap (`delay` at 0x4441..0x4442) is neither written nor verified.
    let mask = plan.segment_mask(STATIC_SEGMENT).ok_or("a mask")?;
    let unwritten: Vec<usize> = (0..64).filter(|&i| mask[i] != 0xFF).collect();
    assert_eq!(unwritten, vec![1, 2]);
    let kept = plan.kept();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(kept[0].segment, STATIC_SEGMENT);
    assert_eq!(kept[0].ranges, vec![(1, 3)]);
    assert_eq!(kept[0].label(), "LSM 3 segment 0x4440 octets 1..3 kept");
    assert!(
        plan.placed_octets(STATIC_SEGMENT)
            .is_some_and(|p| !p.contains(&1) && !p.contains(&2) && p.contains(&0)),
        "no kept octet counts as placed"
    );
    let app = product.applications.first().ok_or("one application")?;
    let memo = bussard_prod::dynamic::DynamicMemo::new(app);
    assert_eq!(kept_octets(app, &BTreeMap::new(), &memo), kept.to_vec());
    // A changed `delay` is reported as kept, never as a difference.
    let mut current = regions_memory(&planned_parameter_regions(&plan));
    let held = current
        .get_mut(STATIC_SEGMENT)
        .ok_or("the parameter region")?;
    held[1] = 0x00;
    held[2] = 0x0A;
    let decoded = decode_parameters(app, &BTreeMap::new(), &BTreeMap::new(), &current);
    assert!(decoded.differences.is_empty(), "{:?}", decoded.differences);
    assert_eq!(decoded.kept.len(), 1, "{:?}", decoded.kept);
    Ok(())
}
