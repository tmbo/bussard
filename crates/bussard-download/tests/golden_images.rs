//! Golden-image stability: lock the byte-exact parameter memory image the
//! builder produces for a representative set of application shapes, spanning
//! families and features, so an image-builder change cannot silently drift the
//! bytes that would be flashed onto a device.
//!
//! System B DA.tp is already golden byte-for-byte in `bussard-prod`'s
//! `image.rs` unit tests (against a real ETS→KNX-Virtual capture). This test
//! adds the *committed-fixture* half of the coverage — a union-using shape, a
//! vendor-out-of-enum-default shape, and a schema/version-lie shape — so those
//! feature paths are pinned in normal CI without any vendor `.knxprod`.
//!
//! The fixtures are fabricated (fake ids/offsets/values, no vendor content); see
//! `tests/fixtures/corpus/README.md`.

use std::collections::BTreeMap;

use bussard_prod::{compute_parameter_image, parse_application_program};

/// Computes the single-segment image for a fabricated fixture app and returns it.
fn fixture_image(file: &str, id: &str, seg: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/corpus/{file}");
    let xml = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let app = parse_application_program(id, &xml).expect("parse fixture app");
    let images =
        compute_parameter_image(&app, &BTreeMap::new(), &BTreeMap::new()).expect("compute image");
    images
        .get(seg)
        .unwrap_or_else(|| panic!("segment {seg} missing"))
        .clone()
}

/// A `<Union>` overlaying two members onto one shared region: the mode member
/// (value 1) lands at union base + 0 and the default byte member (value 42) at
/// union base + 1. The exact 2-byte image is locked so a union-lowering change
/// cannot silently move or drop a member's byte.
#[test]
fn golden_union_image_is_byte_stable() {
    let img = fixture_image(
        "zennio_union.app.xml",
        "M-0071_A-7001-10-FADE-O000A",
        "M-0071_A-7001-10-FADE-O000A_RS-4",
    );
    assert_eq!(img, vec![0x01, 0x2A], "union image drifted");
}

/// A vendor default that sits outside its own enum ({1,2}, default 3) is passed
/// through verbatim by the leniency rule: the raw byte 3 is encoded. Locked so a
/// change to enum handling cannot silently alter the byte or start refusing.
#[test]
fn golden_enum_leniency_image_is_byte_stable() {
    let img = fixture_image(
        "enum_default_out_of_range.app.xml",
        "M-0071_A-7002-10-BEEF-O000A",
        "M-0071_A-7002-10-BEEF-O000A_RS-4",
    );
    assert_eq!(img, vec![0x03], "enum-leniency image drifted");
}

/// The schema/version-lie shape still builds its one-byte image (level = 7)
/// despite the declared-vs-actual namespace disagreement. Locked to guard the
/// tolerant-parse path.
#[test]
fn golden_extension_lie_image_is_byte_stable() {
    let img = fixture_image(
        "interra_extension_lie.app.xml",
        "M-00C8_A-00C8-14-C0DE-O000A",
        "M-00C8_A-00C8-14-C0DE-O000A_RS-4",
    );
    assert_eq!(img, vec![0x07], "extension-lie image drifted");
}
