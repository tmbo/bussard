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
