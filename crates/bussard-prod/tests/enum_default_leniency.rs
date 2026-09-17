//! Regression for the vendor enum-default leniency rule.
//!
//! The Zennio Z40 and Z70 v2 panels ship an enum parameter whose declared default
//! `Value` is not one of the enumeration's declared members. The strict membership
//! check used to refuse the whole flash. The fix: a value that comes from the
//! VENDOR DEFAULT is passed through verbatim (a default the vendor shipped is what
//! the device expects); only a USER OVERRIDE outside the enum stays strict.
//!
//! The fixture (fake ids/offsets/values, no vendor content) declares members
//! `{1, 2}` and a default of `3`.

use std::collections::BTreeMap;

use bussard_prod::{compute_parameter_image, parse_application_program};

/// `compute_parameter_image` must now accept the vendor's out-of-enum default and
/// encode the raw byte (3), rather than returning an Err.
#[test]
fn test_compute_parameter_image_vendor_enum_default_passes_through()
-> Result<(), Box<dyn std::error::Error>> {
    let xml = include_bytes!("fixtures/enum_default_not_a_member.app.xml");
    let app = parse_application_program("M-00FA_A-0006-11-ABCD-O000A", xml)?;

    let images = compute_parameter_image(&app, &BTreeMap::new(), &BTreeMap::new())
        .expect("a vendor's own out-of-enum default must not refuse the image build");

    // The `Mode` parameter sits at offset 0 of the RS-4 segment; its raw default 3
    // is encoded verbatim.
    let seg = images
        .get("M-00FA_A-0006-11-ABCD-O000A_RS-4")
        .expect("the segment image must be built");
    assert_eq!(seg[0], 3, "the raw vendor default byte is passed through");
    Ok(())
}
