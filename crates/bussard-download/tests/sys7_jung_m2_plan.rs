//! M2 calibration: bussard's property-mode System 7 plan for the Jung 3361-1M
//! (`M-0004_A-A011`, mask 0705) reproduces the load-control + memory shape the
//! real ETS 6 download put on the wire (issue #70).
//!
//! This is the tool-side twin of the sim replay test
//! (`knx-sim/tests/sys7_jung_m2_replay.rs`): the sim proves it *accepts* the
//! captured request stream; this proves bussard *emits* the same shape. It plans
//! (offline, no device) a property-mode flash of the Jung app and asserts:
//!   - the plan is System 7 and drives the property (PID-5) LSM (the M2 default);
//!   - its absolute-segment steps carry the captured addresses/sizes/mem-types
//!     (0x4000, 0x0700 RAM alloc-only, 0x43FF EEPROM, …);
//!   - the AbsSegment encoder produces the exact octets the capture pinned;
//!   - memory streaming is chunked to <=12 octets (standard-frame floor).
//!
//! The Jung `.knxprod` is copyrighted vendor data and is NOT committed; it is read
//! at runtime from the product-corpus cache and the test skips cleanly when absent
//! (run `tests-support/product-corpus/fetch.sh` to populate it).

use std::collections::BTreeMap;
use std::path::PathBuf;

use bussard_download::{FlashStep, plan_flash_sys7_with_hawk, select_application};

const JUNG_APP: &str = "M-0004_A-A011-13-60BC-O000A";
const MASK_0705: u16 = 0x0705;

/// Resolve the Jung 3361-1M product from the corpus cache, or `None` to skip.
fn jung_knxprod_path() -> PathBuf {
    std::env::var_os("BUSSARD_PRODUCT_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("tests-support")
                .join("product-corpus")
        })
        .join("cache")
        .join("vendor")
        .join("de_3361-1m_V1.3_2020-05.knxprod")
}

#[test]
fn test_bussard_property_plan_matches_m2_jung_shape() {
    let path = jung_knxprod_path();
    let Ok(product) = bussard_prod::read_knxprod(&path) else {
        eprintln!(
            "SKIP: Jung 3361-1M .knxprod not in the product-corpus cache at {}; \
             run tests-support/product-corpus/fetch.sh to enable this test",
            path.display()
        );
        return;
    };

    let app = select_application(
        &[product
            .application_by_id(JUNG_APP)
            .expect("Jung app present")],
        None,
    )
    .expect("select Jung app");

    // Property-mode plan: hawk = None so the planner uses the property corpus
    // default (the M2 verdict). Empty overrides / base offsets: a vendor-default
    // flash with no group addresses, which is all the load-control shape needs.
    let plan = plan_flash_sys7_with_hawk(
        app,
        "1.1.5",
        MASK_0705,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )
    .expect("Jung property-mode plan builds");

    // 1. It is a System 7 plan driving the property (PID-5) LSM.
    assert!(plan.is_sys7(), "Jung 0705 plan must be System 7");
    assert_eq!(
        plan.sys7_lsm(),
        Some(bussard_mgmt::LsmRealisation::Property),
        "the M2 default LSM realisation is property-based (PID 5)"
    );

    // 2. The absolute-segment allocations match the product's declared segments,
    //    which the M2 capture's PID-5 event-03 records reproduced exactly. Collect
    //    (address, size, mem_type, is_alloc_only) per AbsSegment step.
    let mut segs: BTreeMap<u32, (u32, u8, bool)> = BTreeMap::new();
    for step in &plan.steps {
        if let FlashStep::Sys7AbsSegment {
            address,
            size,
            mem_type,
            image,
            ..
        } = step
        {
            segs.insert(*address, (*size, *mem_type, image.is_none()));
        }
    }

    // The low-RAM working region at 0x0700 is a RAM (mem_type 2) alloc-only record
    // (no <Data>) — capture `03 00 07 00 01 c2 f2 02 00 00`, declared size 450.
    let (size, mem_type, alloc_only) = segs.get(&0x0700).expect("0x0700 segment planned");
    assert_eq!(*size, 450, "0x0700 declared size");
    assert_eq!(*mem_type, 2, "0x0700 is RAM (mem_type 2)");
    assert!(alloc_only, "0x0700 is allocate-only (no memory write)");

    // The LSM 1 table region at 0x4000 is EEPROM (mem_type 3), carries <Data>.
    let (_size, mem_type, alloc_only) = segs.get(&0x4000).expect("0x4000 segment planned");
    assert_eq!(*mem_type, 3, "0x4000 is EEPROM (mem_type 3)");
    assert!(!alloc_only, "0x4000 carries an image to stream");

    // The LSM 3 EEPROM param image at 0x43FF: size 811 (= 0x032B in the capture).
    let (size, mem_type, _alloc) = segs.get(&0x43FF).expect("0x43FF segment planned");
    assert_eq!(*size, 811, "0x43FF declared size = capture length 0x032B");
    assert_eq!(*mem_type, 3, "0x43FF is EEPROM (mem_type 3)");

    // 3. The AbsSegment encoder produces the exact octets the M2 capture pinned
    //    for 0x43FF (opcode/subtype, start, length, mem_type at octet 7):
    //    `03 00 43 ff 03 2b .. 03 .. ..`.
    let event = bussard_mgmt::encode_alloc_segment(
        bussard_mgmt::sys7::S7_SUB_ALLOC_DATA,
        0x43FF,
        811,
        0x00,
        3,
        0x00,
    );
    assert_eq!(
        &event[0..2],
        &[0x03, 0x00],
        "event = AdditionalLoadControls, alloc Data"
    );
    assert_eq!(&event[2..4], &[0x43, 0xFF], "start 0x43FF big-endian");
    assert_eq!(
        &event[4..6],
        &[0x03, 0x2B],
        "length 0x032B = declared size 811"
    );
    assert_eq!(event[7], 0x03, "mem_type EEPROM at octet 7");

    // 4. The plan streams the app's data-bearing segments (the 12-octet chunking
    //    itself is enforced at execute time by the device's 15-octet max-APDU
    //    floor and is asserted on the wire by the sim replay test). The 0x0700 RAM
    //    region contributes nothing (alloc-only); the EEPROM data segments do.
    assert!(
        plan.total_write_bytes() > 0,
        "the Jung app streams segment images"
    );
    let data_bearing = segs
        .values()
        .filter(|(_, _, alloc_only)| !*alloc_only)
        .count();
    assert!(
        data_bearing >= 3,
        "the Jung app has multiple data-bearing EEPROM segments, got {data_bearing}"
    );

    // Sanity: the plan drives all three parallel LSMs to LoadCompleted.
    for lsm in [1u32, 2, 3] {
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::Sys7LoadCompleted { lsm: l } if *l == lsm)),
            "LSM {lsm} must be driven to LoadCompleted"
        );
    }
}

/// Issue #146: the parameter-only download of the Jung 3361-1MWW (1.1.32,
/// capture `bad-eg-pm-1-1-18.pcapng`) opens and completes LSM 3 around plain
/// memory writes. It sends no allocation record (the `0x0700` RAM region put
/// the real device into load state Error), no task segment and no task
/// control, keeps the MCB reads of objects 1 to 3, and ends with the restart.
#[test]
fn test_parameters_only_jung_plan_writes_in_place() -> Result<(), Box<dyn std::error::Error>> {
    let path = jung_knxprod_path();
    let Ok(product) = bussard_prod::read_knxprod(&path) else {
        eprintln!("SKIP: Jung 3361-1M .knxprod not in the product-corpus cache");
        return Ok(());
    };
    let app = select_application(
        &[product
            .application_by_id(JUNG_APP)
            .ok_or("Jung app present")?],
        None,
    )?;
    let full = plan_flash_sys7_with_hawk(
        app,
        "1.1.32",
        MASK_0705,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let regions = bussard_download::planned_parameter_regions(&full);
    let partial = full.parameters_only(&regions)?;
    let shape: Vec<String> = partial
        .steps
        .iter()
        .map(|step| match step {
            FlashStep::Sys7StartLoading { lsm } => format!("start {lsm}"),
            FlashStep::Sys7LoadCompleted { lsm } => format!("complete {lsm}"),
            FlashStep::WriteMem { address, .. } => format!("write {address:#06X}"),
            FlashStep::LoadImageProp { obj_idx, .. } => format!("mcb {obj_idx}"),
            FlashStep::CompareProp { .. } => "compare".to_string(),
            FlashStep::Restart => "restart".to_string(),
            other => format!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        shape.first().map(String::as_str),
        Some("start 3"),
        "{shape:?}"
    );
    assert!(
        shape.iter().all(|s| !s.starts_with("unexpected")),
        "{shape:?}"
    );
    assert!(shape.iter().any(|s| s.starts_with("write ")), "{shape:?}");
    assert!(!shape.iter().any(|s| s == "write 0x0700"), "{shape:?}");
    let tail: Vec<&str> = shape
        .iter()
        .rev()
        .take(5)
        .rev()
        .map(String::as_str)
        .collect();
    assert_eq!(
        tail,
        ["complete 3", "mcb 1", "mcb 2", "mcb 3", "restart"],
        "{shape:?}"
    );
    // No write lands in the table regions of LSM 1 and 2.
    assert!(
        partial.steps.iter().all(|s| !matches!(
            s,
            FlashStep::WriteMem { address, .. } if *address < 0x43FF
        )),
        "{shape:?}"
    );
    Ok(())
}
