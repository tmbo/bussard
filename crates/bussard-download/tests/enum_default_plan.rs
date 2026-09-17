//! Dry-run plan regression for the vendor enum-default leniency rule.
//!
//! The Zennio Z40/Z70 v2 panels shipped an enum parameter whose default is not a
//! declared member, which used to surface from `plan_flash` as
//! `PlanError::UnresolvableImage`. With the leniency fix a vendor default outside
//! its own enum is passed through, so the fabricated fixture (fake ids/values, no
//! vendor content) now lowers to an executable plan.
//!
//! Nothing here touches a bus.

use std::collections::BTreeMap;

use bussard_download::plan_flash;

/// The enum-default fixture must now produce a `FlashPlan` rather than refusing at
/// pre-flight with an `UnresolvableImage` naming the non-member value.
#[test]
fn test_plan_flash_vendor_enum_default_no_longer_refused() -> Result<(), Box<dyn std::error::Error>>
{
    let xml = include_bytes!("../../bussard-prod/tests/fixtures/enum_default_not_a_member.app.xml");
    let app = bussard_prod::parse_application_program("M-00FA_A-0006-11-ABCD-O000A", xml)?;

    plan_flash(
        &app,
        "1.1.1",
        0x07B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )
    .expect("a vendor's own out-of-enum default must no longer refuse the flash");
    Ok(())
}
