//! Runtime access to calibration fixtures.
//!
//! The DA.tp `.knxprod` is a vendor product file and is **not committed** to the
//! repository (the project git-ignores `*.knxprod` as vendor data). Tests that
//! need it read it at runtime from `tests/fixtures/` and **skip cleanly** when
//! it is absent, rather than embedding it with `include_bytes!` (which would
//! break compilation on a clean checkout).
//!
//! Place the KNX-Virtual DA.tp product at
//! `tests/fixtures/KNX_Virtual_M-00FA.knxprod` to enable the calibration tests.

use std::path::PathBuf;

/// The path where the DA.tp calibration `.knxprod` is expected.
pub fn da_tp_knxprod_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("KNX_Virtual_M-00FA.knxprod")
}

/// Load the DA.tp calibration `.knxprod` bytes, or `None` if the (un-committed)
/// fixture is not present.
pub fn da_tp_knxprod() -> Option<Vec<u8>> {
    std::fs::read(da_tp_knxprod_path()).ok()
}

/// The path where the Jung 3361-1M (`M-0004_A-A011`, mask 0705) calibration
/// `.knxprod` is expected: the product-corpus cache the repo's `fetch.sh`
/// populates (`tests-support/product-corpus/cache/vendor/`). Vendor data is
/// copyrighted and git-ignored, so tests read it at runtime and skip when absent.
pub fn jung_3361_knxprod_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests-support")
        .join("product-corpus")
        .join("cache")
        .join("vendor")
        .join("de_3361-1m_V1.3_2020-05.knxprod")
}

/// Load the Jung 3361-1M calibration `.knxprod` bytes, or `None` if the
/// (un-committed, copyrighted) vendor file is not present in the corpus cache.
pub fn jung_3361_knxprod() -> Option<Vec<u8>> {
    std::fs::read(jung_3361_knxprod_path()).ok()
}

/// A synthetic MDT-canonical System 7 product (`M-0083_A-000E`, mask 0705),
/// built in memory so the System 7 conformance tests need no vendor fixture.
///
/// It carries the three loadable objects (address = 1, association = 2,
/// application = 3) and mask `MV-0705`; the load procedure is not needed by the
/// sim (the sim is the device side, driven by raw TPDUs), so it is left empty.
/// The application number (14) seeds the object-0 PID 78 preflight value the
/// canonical MDT sequence compares against.
pub fn synthetic_mdt_sys7_product() -> crate::prod::ProductData {
    use crate::prod::{LoadableObject, ProductData};
    let objects = vec![
        LoadableObject {
            lsm_index: 1,
            name: "address table".into(),
            max_size: None,
            image: Vec::new(),
        },
        LoadableObject {
            lsm_index: 2,
            name: "association table".into(),
            max_size: None,
            image: Vec::new(),
        },
        LoadableObject {
            lsm_index: 3,
            name: "application".into(),
            max_size: None,
            image: Vec::new(),
        },
    ];
    ProductData {
        application_id: "M-0083_A-000E-23-2274".into(),
        application_number: 14,
        application_version: 35,
        mask_version: "MV-0705".into(),
        objects,
        load_procedures: Vec::new(),
        segments: Vec::new(),
        // The marker the synthetic app's CompareProp preflight would expect;
        // byte 5 matches the derived default for application number 14.
        hardware_type_marker: Some(vec![0, 0, 0, 0, 0x03, 0x0E, 0, 0, 0, 0]),
    }
}

/// Skip the current test (return early) if the DA.tp fixture is absent, printing
/// a note. Use as: `let bytes = match knx_sim::testfixtures::da_tp_knxprod() { ... }`.
#[macro_export]
macro_rules! knxprod_or_skip {
    () => {{
        match $crate::testfixtures::da_tp_knxprod() {
            Some(bytes) => bytes,
            None => {
                eprintln!(
                    "SKIP: DA.tp fixture not found at {}; \
                     place the KNX-Virtual .knxprod there to run this test",
                    $crate::testfixtures::da_tp_knxprod_path().display()
                );
                return;
            }
        }
    }};
}
