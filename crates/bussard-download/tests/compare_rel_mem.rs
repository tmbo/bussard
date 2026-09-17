//! Dry-run plan regression for the `<LdCtrlCompareRelMem>` op.
//!
//! The MDT BE-GTSx6Tx and MDT JTA System B devices (mask 07B0) carry a relative
//! memory verify op in their download procedure. Before it was typed, the planner
//! refused the whole procedure with `PlanError::UnsupportedOp`. This test pins the
//! fix: the fabricated fixture (fake ids/offsets/data, no vendor content) now
//! lowers to an executable plan carrying a `CompareRelMem` step.
//!
//! Nothing here touches a bus — the plan is a pure function of the app data.

use std::collections::BTreeMap;

use bussard_download::{FlashStep, plan_flash};

/// The fixture procedure ends with an `LdCtrlCompareRelMem`; `plan_flash` must
/// now produce a `FlashPlan` (not refuse) and lower that op to a `CompareRelMem`
/// step preserving its offset, expected `InlineData`, mask, and inverted sense.
#[test]
fn test_plan_flash_compare_rel_mem_lowers_to_step() -> Result<(), Box<dyn std::error::Error>> {
    let xml = include_bytes!("../../bussard-ets/tests/fixtures/ldctrl_compare_rel_mem.app.xml");
    let app = bussard_prod::parse_application_program("M-00FA_A-0001-11-ABCD-O000A", xml)?;

    // Plan against the app's own declared System B mask (07B0) so the System B
    // gate and the mask compare pass and the op lowering is exercised.
    let plan = plan_flash(
        &app,
        "1.1.1",
        0x07B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )
    .expect("a procedure whose only previously-unsupported op is CompareRelMem must now plan");

    let compare = plan
        .steps
        .iter()
        .find_map(|s| match s {
            FlashStep::CompareRelMem {
                offset,
                expected,
                mask,
                invert,
                ..
            } => Some((offset, expected, mask, invert)),
            _ => None,
        })
        .expect("the plan must carry a CompareRelMem step");

    let (offset, expected, mask, invert) = compare;
    assert_eq!(*offset, 1234);
    assert_eq!(expected.as_deref(), Some(&[0xFFu8][..]));
    assert_eq!(mask.as_deref(), Some(&[0xFFu8][..]));
    assert!(*invert, "the fixture sets Invert=\"true\"");
    Ok(())
}
