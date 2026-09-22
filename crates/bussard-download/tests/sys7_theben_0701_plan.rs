//! Theben 0701 memory-mapped System 7 plan: bussard's default flash of the
//! Theben FIX2 Dimmaktor (`M-0048_A-4947`, mask 0701) drives load control
//! **memory-mapped** (11-octet records to `0x0104`), NOT property-based.
//!
//! This locks the regression the earlier "Property for all System 7" M2 default
//! caused: the real Theben 0701 Meteodata capture is memory-mapped, and the 0701
//! family (this FIX2 shares it) must default to `LsmRealisation::MemoryMapped`.
//! The test plans (offline, no device) a mask-family-default flash and asserts:
//!   - the plan is System 7 and drives the memory-mapped LSM;
//!   - its absolute-segment steps carry the product's addresses/mem-types;
//!   - the memory-mapped LSM control record is the 11-octet Theben form with the
//!     LSM index folded into the high nibble and the derived alloc attr octets.
//!
//! The Theben `.knxprod` is copyrighted vendor data and is NOT committed; it is
//! read at runtime from the product-corpus cache and the test skips cleanly when
//! absent (run `tests-support/product-corpus/fetch.sh` to populate it).

use std::collections::BTreeMap;
use std::path::PathBuf;

use bussard_download::{FlashStep, plan_flash_sys7_with_hawk, select_application};

const THEBEN_APP: &str = "M-0048_A-4947-10-4918";
const MASK_0701: u16 = 0x0701;

/// Resolve the Theben FIX2 Dimmaktor product from the corpus cache.
fn theben_knxprod_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests-support")
        .join("product-corpus")
        .join("cache")
        .join("vendor")
        .join("T4940275_KNX_FIX2_Dimmaktor_V1.0_ETS4.knxprod")
}

#[test]
fn test_bussard_theben_0701_plan_is_memory_mapped() {
    let path = theben_knxprod_path();
    let Ok(product) = bussard_prod::read_knxprod(&path) else {
        eprintln!(
            "SKIP: Theben FIX2 .knxprod not in the product-corpus cache at {}; \
             run tests-support/product-corpus/fetch.sh to enable this test",
            path.display()
        );
        return;
    };

    let app = select_application(
        &[product
            .application_by_id(THEBEN_APP)
            .expect("Theben app present")],
        None,
    )
    .expect("select Theben app");

    // Mask-family default: hawk = None so the planner uses the 0701 corpus default
    // (memory-mapped). (The 0701 Hawk block would independently select
    // memory-mapped too, but the family default is the load-bearing fix here.)
    let plan = plan_flash_sys7_with_hawk(
        app,
        "1.1.202",
        MASK_0701,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )
    .expect("Theben 0701 plan builds");

    // 1. It is a System 7 plan driving the MEMORY-MAPPED LSM (the 0701 default).
    assert!(plan.is_sys7(), "Theben 0701 plan must be System 7");
    assert_eq!(
        plan.sys7_lsm(),
        Some(bussard_mgmt::LsmRealisation::MemoryMapped {
            control_addr: 0x0104,
            status_addr: 0xB6EA,
        }),
        "the Theben 0701 family drives load control memory-mapped (Meteodata capture)"
    );

    // 2. The absolute-segment allocations carry the product's addresses/mem-types:
    //    the sub-0x4000 RAM region is mem_type 2, the 0x4xxx table/param EEPROM 3.
    let mut segs: BTreeMap<u32, (u32, u8)> = BTreeMap::new();
    for step in &plan.steps {
        if let FlashStep::Sys7AbsSegment {
            address,
            size,
            mem_type,
            ..
        } = step
        {
            segs.insert(*address, (*size, *mem_type));
        }
    }
    assert!(
        !segs.is_empty(),
        "the Theben app declares absolute segments"
    );
    // Every sub-0x4000 segment is RAM (2); every 0x4xxx segment is EEPROM (3).
    for (&addr, &(_, mem_type)) in &segs {
        if addr < 0x4000 {
            assert_eq!(mem_type, 2, "segment {addr:#06X} below 0x4000 is RAM");
        } else {
            assert_eq!(mem_type, 3, "segment {addr:#06X} at/above 0x4000 is EEPROM");
        }
    }

    // 3. The memory-mapped LSM control record is the 11-octet Theben form: the LSM
    //    index in the high nibble of octet 0, a derived (0xF2, mem_type, checksum)
    //    tail, and a 3-octet start address. Take an EEPROM segment (mem_type 3) and
    //    reproduce its wrapped record.
    let (&addr, &(size, mem_type)) = segs
        .iter()
        .find(|&(&a, _)| a >= 0x4000)
        .expect("an EEPROM segment");
    let (seg_flags, checksum_ctrl) = bussard_mgmt::alloc_attr_octets(mem_type);
    assert_eq!(
        (seg_flags, checksum_ctrl),
        (0xF2, 0x80),
        "EEPROM attr octets"
    );
    let event = bussard_mgmt::encode_alloc_segment(
        bussard_mgmt::sys7::S7_SUB_ALLOC_DATA,
        (addr & 0xFFFF) as u16,
        (size & 0xFFFF) as u16,
        seg_flags,
        mem_type,
        checksum_ctrl,
    );
    // Property-form 10-octet event -> 11-octet memory record for LSM 3.
    let record = bussard_mgmt::sys7::wrap_memory_lsm_record(3, &event);
    assert_eq!(record.len(), 11, "the memory-mapped record is 11 octets");
    assert_eq!(record[0], 0x33, "LSM3 (3<<4) | AdditionalLoadControls (3)");
    assert_eq!(record[1], 0x00, "alloc Data subtype");
    assert_eq!(record[2], 0x00, "high octet of the widened 3-octet address");
    assert_eq!(
        &record[3..5],
        &(addr as u16).to_be_bytes(),
        "start (low 16 bits)"
    );
    assert_eq!(record[7], 0xF2, "seg_flags");
    assert_eq!(record[8], 3, "mem_type EEPROM");
    assert_eq!(record[9], 0x80, "checksum_ctrl EEPROM");

    // 4. The plan drives LSM 1/2/3 to LoadCompleted.
    for lsm in [1u32, 2, 3] {
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::Sys7LoadCompleted { lsm: l } if *l == lsm)),
            "LSM {lsm} must be driven to LoadCompleted"
        );
    }
}
