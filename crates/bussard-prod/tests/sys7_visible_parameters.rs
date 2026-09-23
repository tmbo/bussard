//! Real-product regression for issue #117: on the Jung System 7 (mask 0705)
//! applications, `compute_parameter_image` must reproduce the parameter
//! segments ETS writes, byte for byte.
//!
//! These applications put many parameters on one octet in different
//! `<choose>/<when>` branches, give one parameter several refs with different
//! `Value`s, and place `<Union>`s at a non-zero `BitOffset`. ETS writes only
//! the reached refs; the expected bytes in
//! `fixtures/sys7_ets_parameter_segments.txt` were composed from ETS download
//! captures of three devices.
//!
//! Set `BUSSARD_PRODUCT_CORPUS=<vendor-dir>` to run it; skipped when unset (the
//! vendor product data is copyrighted and never committed).

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;

use bussard_prod::compute_parameter_image;

/// A test result carrying any error.
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// One fixture segment: case, segment id suffix, ETS bytes (`None` where ETS
/// wrote nothing).
type EtsSegment = (String, String, Vec<Option<u8>>);

/// The ETS segment fixture, parsed into `(case, segment suffix, bytes)`.
fn ets_segments() -> TestResult<Vec<EtsSegment>> {
    let text = include_str!("fixtures/sys7_ets_parameter_segments.txt");
    let mut out = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let mut parts = line.split_whitespace();
        let (Some(case), Some(_app), Some(seg), Some(hex)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("malformed fixture line: {line}").into());
        };
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| match &hex[i..i + 2] {
                ".." => Ok(None),
                octet => u8::from_str_radix(octet, 16).map(Some),
            })
            .collect::<Result<Vec<Option<u8>>, _>>()?;
        out.push((case.to_string(), seg.to_string(), bytes));
    }
    Ok(out)
}

/// Reads one application program out of a corpus `.knxprod`, or `None` when
/// the corpus or the product is absent.
fn corpus_app(product: &str, app_id: &str) -> TestResult<Option<bussard_prod::ApplicationProgram>> {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping {app_id}.");
        return Ok(None);
    };
    let path = PathBuf::from(dir).join("cache/vendor").join(product);
    if !path.exists() {
        eprintln!("{product} not in the corpus; skipping {app_id}.");
        return Ok(None);
    }
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&path)?)?;
    let mut xml = Vec::new();
    zip.by_name(&format!("M-0004/{app_id}.xml"))?
        .read_to_end(&mut xml)?;
    Ok(Some(bussard_prod::parse_application_program(app_id, &xml)?))
}

/// Builds the image for `app_id` with `overrides` and compares every fixture
/// segment of `case` against it, octet by octet where ETS wrote one.
fn check(product: &str, app_id: &str, case: &str, overrides: &[(&str, &str)]) -> TestResult<()> {
    let Some(app) = corpus_app(product, app_id)? else {
        return Ok(());
    };
    let overrides: BTreeMap<String, String> = overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let images = compute_parameter_image(&app, &overrides, &BTreeMap::new())?;
    let mut compared = 0;
    for (fixture_case, seg, expected) in ets_segments()? {
        if fixture_case != case {
            continue;
        }
        let seg_id = format!("{app_id}_{seg}");
        // A segment no parameter targets streams its `<Data>` unchanged.
        let image = images
            .get(&seg_id)
            .or_else(|| app.code_segments.get(&seg_id)?.data.as_ref())
            .ok_or_else(|| format!("no image for {seg_id}"))?;
        assert_eq!(image.len(), expected.len(), "{seg_id} length");
        let differing: Vec<String> = expected
            .iter()
            .zip(image.iter())
            .enumerate()
            .filter_map(|(i, (e, b))| match e {
                Some(e) if e != b => Some(format!("+{i:#04x} ets {e:02x} bussard {b:02x}")),
                _ => None,
            })
            .collect();
        assert!(
            differing.is_empty(),
            "{case} {seg_id}: {}",
            differing.join(", ")
        );
        compared += 1;
    }
    assert!(compared > 0, "no fixture segments for {case}");
    Ok(())
}

/// The 3361-1MWW presence detector, one parameter changed from the default.
#[test]
fn test_compute_parameter_image_jung_3361_one_override_matches_ets() -> TestResult<()> {
    check(
        "de_3361-1m_V1.3_2020-05.knxprod",
        "M-0004_A-A011-13-60BC-O000A",
        "3361-one-override",
        &[("P-86_R-565", "1")],
    )
}

/// The 3361-1MWW set to application type 1. The send-delay values were set
/// through refs that type 1 hides; type 1 shows other refs of the same
/// parameters, and ETS writes those refs' defaults (values are per ref).
#[test]
fn test_compute_parameter_image_jung_3361_application_type_1_matches_ets() -> TestResult<()> {
    check(
        "de_3361-1m_V1.3_2020-05.knxprod",
        "M-0004_A-A011-13-60BC-O000A",
        "3361-type-1",
        &[
            ("UP-39_R-92", "1"),
            ("P-7_R-8", "1"),
            ("P-86_R-565", "1"),
            ("P-93_R-2108", "3"),
            ("P-94_R-2109", "0"),
        ],
    )
}

/// The 3181 automatic switch with four links and eight changed parameters.
#[test]
fn test_compute_parameter_image_jung_3181_automatic_switch_matches_ets() -> TestResult<()> {
    check(
        "de_3x81_24112017.knxprod",
        "M-0004_A-A033-12-6E08-O000A",
        "3181",
        &[
            ("P-39_R-46", "2"),
            // Memory-less: selects which refs of the three sensor sensitivity
            // bits are shown, and so which `Value` ETS writes.
            ("P-735_R-9353", "1"),
            ("P-272_R-2082", "0"),
            ("P-56_R-182", "1"),
            ("P-55_R-183", "200"),
            ("P-5_R-6", "0"),
            ("P-6_R-7", "2"),
            ("P-8_R-9", "0"),
        ],
    )
}

/// The 2116 binary input with every parameter at its default.
#[test]
fn test_compute_parameter_image_jung_2116_binary_input_matches_ets() -> TestResult<()> {
    check(
        "de_2116REG_2128REG_14062016.knxprod",
        "M-0004_A-7066-11-94AD-O000A",
        "2116-defaults",
        &[],
    )
}
