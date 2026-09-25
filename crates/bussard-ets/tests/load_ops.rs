//! Parse-side regression for load-procedure ops that the deep-testing sweep
//! found in real vendor `.knxprod` files. Each test parses a fabricated fixture
//! (fake ids/offsets/data, no vendor content) and pins the typed [`LoadOp`] the
//! parser must produce.

use bussard_ets::application::{LoadOp, parse_application_program};

/// The `<LdCtrlCompareRelMem>` fixture (MDT BE-GTSx6Tx / JTA shape, mask 07B0)
/// must parse into the typed [`LoadOp::CompareRelMem`], preserving its
/// `InlineData`/`Mask`/`Invert`/`ObjIdx`/`Offset` attributes — not fall back to
/// `LoadOp::Raw`, which would refuse the whole download procedure at pre-flight.
#[test]
fn test_parse_application_program_compare_rel_mem() -> Result<(), Box<dyn std::error::Error>> {
    let xml = include_bytes!("fixtures/ldctrl_compare_rel_mem.app.xml");
    let app = parse_application_program("M-00FA_A-0001-11-ABCD-O000A", xml)?;

    let ops: Vec<&LoadOp> = app
        .load_procedures
        .iter()
        .flat_map(|lp| lp.ops.iter())
        .collect();

    let compare = ops
        .iter()
        .find_map(|op| match op {
            LoadOp::CompareRelMem {
                obj_idx,
                offset,
                size,
                inline_data,
                mask,
                invert,
            } => Some((obj_idx, offset, size, inline_data, mask, invert)),
            _ => None,
        })
        .ok_or("the fixture's LdCtrlCompareRelMem must parse as a typed CompareRelMem, not Raw")?;

    let (obj_idx, offset, size, inline_data, mask, invert) = compare;
    assert_eq!(*obj_idx, Some(4));
    assert_eq!(*offset, Some(1234));
    assert_eq!(*size, Some(1));
    assert_eq!(inline_data.as_deref(), Some(&[0xFFu8][..]));
    assert_eq!(mask.as_deref(), Some(&[0xFFu8][..]));
    assert!(*invert, "Invert=\"true\" must decode to true");

    // No op fell back to Raw — the whole procedure is now typed.
    assert!(
        !ops.iter().any(|op| matches!(op, LoadOp::Raw { .. })),
        "no op should remain a Raw fallback"
    );
    Ok(())
}
