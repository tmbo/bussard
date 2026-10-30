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
    let xml = include_bytes!("../fixtures/ldctrl_compare_rel_mem.app.xml");
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

/// `<LdCtrlMapError>` (issue #614) parses into the typed [`LoadOp::MapError`]
/// with its decimal codes, every op keeps its `AppliesTo`, the `par` and `grp`
/// ops count as partial-only, and `LdCtrlCompareProp` keeps its
/// `StartElement`.
#[test]
fn test_parse_application_program_map_error() -> Result<(), Box<dyn std::error::Error>> {
    let xml = include_bytes!("../fixtures/ldctrl_map_error.app.xml");
    let app = parse_application_program("M-00FA_A-0614-01-ABCD", xml)?;
    let lp = app.load_procedures.first().ok_or("one load procedure")?;

    let maps: Vec<&LoadOp> = lp
        .ops
        .iter()
        .filter(|op| matches!(op, LoadOp::MapError { .. }))
        .collect();
    assert_eq!(
        maps,
        [
            &LoadOp::MapError {
                original_error: Some(0xC004_2B08),
                mapped_error: Some(0),
            },
            &LoadOp::MapError {
                original_error: Some(0xC004_2B08),
                mapped_error: Some(0xC004_2B08),
            },
        ]
    );
    assert!(!lp.ops.iter().any(|op| matches!(op, LoadOp::Raw { .. })));

    // Every op carries its scope, parallel to the ops.
    assert_eq!(lp.applies_to.len(), lp.ops.len());
    assert_eq!(lp.applies_to_of(0), Some("all"));
    let partial = (0..lp.ops.len()).filter(|i| lp.is_partial_only(*i)).count();
    assert_eq!(partial, 11, "the par and grp ops");
    assert!(!lp.is_partial_only(0), "AppliesTo=all");
    assert!(!lp.is_partial_only(3), "AppliesTo=full");
    assert!(
        lp.lists_partial_downloads(),
        "the procedure lists a grp download"
    );

    let elements: Vec<Option<u32>> = lp
        .ops
        .iter()
        .filter_map(|op| match op {
            LoadOp::CompareProp { start_element, .. } => Some(*start_element),
            _ => None,
        })
        .collect();
    assert_eq!(elements, [None, Some(3)]);
    Ok(())
}

/// `AppliesTo` scopes: only `par` and `grp` are partial-only; `full`, `all`,
/// `auto`, a mixed list and an empty value are not.
#[test]
fn test_applies_to_partial_only_scopes() {
    use bussard_ets::application::applies_to_partial_only;
    assert!(applies_to_partial_only("par"));
    assert!(applies_to_partial_only("grp"));
    assert!(applies_to_partial_only("par, grp"));
    assert!(!applies_to_partial_only("full"));
    assert!(!applies_to_partial_only("full,par"));
    assert!(!applies_to_partial_only("all"));
    assert!(!applies_to_partial_only("auto"));
    assert!(!applies_to_partial_only(""));
}
