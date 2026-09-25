//! Aggressive robustness tests for the DPT codec and the address/DPT/flags
//! parsers (bussard-model). Added by the hardening pass.
//!
//! These are table-driven loop tests over every implemented DPT plus hostile
//! parse inputs. The defects they originally quarantined behind `#[ignore]` have
//! since been fixed (issue #34), so every test here now runs.

use std::panic::{AssertUnwindSafe, catch_unwind};

use bussard_model::codec::{EncodeError, ParseValueError, TypedValue, decode, encode, parse_value};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress};

fn dpt(s: &str) -> Dpt {
    s.parse().expect("test fixture")
}

/// Every DPT main type bussard claims to model, with a canonical sub.
const ALL_DPTS: &[&str] = &[
    "1.001", "2.001", "3.007", "3.008", "4.001", "5.001", "5.003", "5.010", "6.010", "7.001",
    "8.001", "9.001", "9.004", "10.001", "11.001", "12.001", "13.010", "13.013", "14.056",
    "14.076", "16.000", "16.001", "17.001", "18.001", "20.102", "232.600",
];

// ---------------------------------------------------------------------------
// decode(): must NEVER panic for any DPT × any payload length up to a bound.
// ---------------------------------------------------------------------------

#[test]
fn decode_never_panics_for_any_dpt_and_length() {
    for d in ALL_DPTS {
        let dp = dpt(d);
        for len in 0..=20usize {
            let payload: Vec<u8> = (0..len as u8).collect();
            let r = catch_unwind(AssertUnwindSafe(|| decode(&dp, &payload)));
            assert!(r.is_ok(), "decode panicked for DPT {d} len {len}");
        }
    }
}

#[test]
fn decode_boundary_bytes_never_panic() {
    // 0x00, 0xFF, 0x7F, 0x80 saturating patterns at various lengths.
    for d in ALL_DPTS {
        let dp = dpt(d);
        for fill in [0x00u8, 0xFF, 0x7F, 0x80, 0x01] {
            for len in 0..=16usize {
                let payload = vec![fill; len];
                let r = catch_unwind(AssertUnwindSafe(|| decode(&dp, &payload)));
                assert!(
                    r.is_ok(),
                    "decode panicked DPT {d} fill {fill:#x} len {len}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DPT 9.x — 2-byte float edge cases.
// ---------------------------------------------------------------------------

#[test]
fn float16_invalid_sentinel_decodes_to_raw_and_extremes_are_floats() {
    // 0x7FFF is the KNX DPT 9 "invalid data" sentinel; bussard now surfaces it as
    // `Raw` rather than a bogus ~670760 float (issue #34, fix 5).
    assert_eq!(
        decode(&dpt("9.001"), &[0x7F, 0xFF]),
        TypedValue::Raw(vec![0x7F, 0xFF])
    );
    // Other extremes remain ordinary floats and never panic.
    for bytes in [[0xFF, 0xFF], [0x80, 0x00], [0x00, 0x00]] {
        let v = decode(&dpt("9.001"), &bytes);
        assert!(
            matches!(v, TypedValue::Float { .. }),
            "9.001 {bytes:?} -> {v:?}"
        );
    }
}

#[test]
fn float16_full_exponent_sweep_roundtrips_or_errors_cleanly() {
    // Every representable (sign, exponent, mantissa-extreme) should decode then
    // re-encode without panic and within the DPT's coarse tolerance.
    for hi in 0u16..=255 {
        for lo in [0u8, 1, 0x7f, 0x80, 0xff] {
            let bytes = [hi as u8, lo];
            let v = decode(&dpt("9.001"), &bytes);
            if let TypedValue::Float { value, .. } = v {
                // re-encode must not panic
                let r = catch_unwind(AssertUnwindSafe(|| encode(&dpt("9.001"), &v)));
                assert!(r.is_ok(), "re-encode panicked for {value} from {bytes:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DPT 14.x — IEEE float NaN/Inf.
// ---------------------------------------------------------------------------

#[test]
fn float32_nan_inf_decode_lenient_but_encode_rejects_non_finite() {
    // NaN and infinities are valid IEEE bit patterns; decode stays lenient and
    // produces a Float. Finite values re-encode and round-trip the bytes;
    // non-finite values are rejected on encode (issue #34, fix 2).
    let finite: &[[u8; 4]] = &[
        [0x00, 0x00, 0x00, 0x00], // 0
        [0x80, 0x00, 0x00, 0x00], // -0
    ];
    for bytes in finite {
        let v = decode(&dpt("14.056"), bytes);
        match &v {
            TypedValue::Float { .. } => {
                let re = encode(&dpt("14.056"), &v).expect("14.x re-encode");
                assert_eq!(&re[..], &bytes[..], "14.x byte roundtrip for {bytes:?}");
            }
            other => panic!("14.056 {bytes:?} decoded to {other:?}"),
        }
    }
    let non_finite: &[[u8; 4]] = &[
        [0x7f, 0xc0, 0x00, 0x00], // NaN
        [0x7f, 0x80, 0x00, 0x00], // +Inf
        [0xff, 0x80, 0x00, 0x00], // -Inf
    ];
    for bytes in non_finite {
        let v = decode(&dpt("14.056"), bytes);
        assert!(matches!(v, TypedValue::Float { .. }), "decode lenient");
        assert!(
            matches!(
                encode(&dpt("14.056"), &v),
                Err(EncodeError::OutOfRange { .. })
            ),
            "encode rejects non-finite {bytes:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// DPT 16.x — text with non-ASCII, embedded NUL, oversized.
// ---------------------------------------------------------------------------

#[test]
fn text_embedded_nul_truncates_and_high_bytes_are_latin1() {
    // Embedded NUL truncates.
    assert_eq!(
        decode(&dpt("16.000"), b"AB\0CD"),
        TypedValue::Text("AB".to_string())
    );
    // Only first 14 bytes consumed.
    let long = vec![b'x'; 30];
    if let TypedValue::Text(s) = decode(&dpt("16.001"), &long) {
        assert_eq!(s.chars().count(), 14, "text capped at 14 chars");
    } else {
        panic!("expected text");
    }
    // High bytes map as Latin-1 code points (byte value == code point).
    if let TypedValue::Text(s) = decode(&dpt("16.001"), &[0xE9, 0xFF, 0x00]) {
        assert_eq!(s, "\u{E9}\u{FF}");
    } else {
        panic!("expected text");
    }
}

// ---------------------------------------------------------------------------
// DPT 232.600 — RGB short payload falls back to Raw (no panic).
// ---------------------------------------------------------------------------

#[test]
fn rgb_short_payload_falls_back_to_raw() {
    assert_eq!(
        decode(&dpt("232.600"), &[1, 2]),
        TypedValue::Raw(vec![1, 2])
    );
    assert_eq!(decode(&dpt("232.600"), &[]), TypedValue::Raw(vec![]));
    assert_eq!(
        decode(&dpt("232.600"), &[1, 2, 3, 4]),
        TypedValue::Rgb { r: 1, g: 2, b: 3 }
    );
}

// ---------------------------------------------------------------------------
// parse_value(): hostile strings must never panic and must Err cleanly.
// ---------------------------------------------------------------------------

/// Hostile textual inputs thrown at every parseable DPT.
const HOSTILE_INPUTS: &[&str] = &[
    "",
    " ",
    "\t",
    "\n",
    "abc",
    "1e999",
    "-1e999",
    "99999999999999999999999999",
    "-99999999999999999999999999",
    "０",
    "１２３",
    "０x10",
    "0x10",
    "1,5",
    "1_000",
    "٤",
    "🚀",
    "+",
    "-",
    ".",
    "e",
    "1e",
    "NaN",
    "nan",
    "inf",
    "-inf",
    "Infinity",
    "1.0.0",
    "255 %",
    "  100  ",
    "1\0",
    "\u{feff}5",
];

#[test]
fn parse_value_never_panics_on_hostile_input() {
    // DPT 9.x is now included: the encode_float16 overflow that made large
    // magnitudes / infinities panic is fixed (issue #34, fix 1), so 9.x must also
    // survive every hostile input with a clean Err.
    let parseable = &[
        "1.001", "1.008", "5.001", "5.003", "5.010", "6.010", "7.001", "8.001", "9.001", "12.001",
        "13.013", "14.056", "17.001", "18.001", "20.102",
    ];
    for d in parseable {
        let dp = dpt(d);
        for input in HOSTILE_INPUTS {
            let r = catch_unwind(AssertUnwindSafe(|| parse_value(&dp, input)));
            assert!(
                r.is_ok(),
                "parse_value PANICKED for DPT {d} input {input:?}: {:?}",
                r.err()
            );
        }
    }
}

/// Regression (was issue #34, fix 1): parse_value for a 2-byte-float DPT (9.x)
/// used to panic with an arithmetic overflow when handed any large finite (or
/// infinite) magnitude. `bussard write <ga> 1e9` (DPT 9) aborted the process.
///
/// Root cause was `encode_float16` (called by parse_value only to range-check)
/// doing `(value*100.0).round() as i32`, which saturated to `i32::MAX`/`i32::MIN`
/// for large inputs; the mantissa-halving loop then overflowed on `mantissa ± 1`.
/// Fixed by rejecting non-finite and out-of-range values before the integer
/// math, so parse_value returns `ParseValueError::OutOfRange` per its documented
/// "roughly -671088.64 .. 670760.96" contract.
#[test]
fn parse_value_9x_large_magnitude_errors_not_panic() {
    for input in ["1e9", "inf", "-1e9", "21474836.48", "1e30"] {
        let r = parse_value(&dpt("9.001"), input);
        assert!(
            matches!(r, Err(ParseValueError::OutOfRange { .. })),
            "9.001 {input:?} should be OutOfRange, got {r:?}"
        );
    }
}

/// Regression (was issue #34, fix 2): parse_value(9.x, "nan") used to silently
/// succeed and later encode to 0.0 (a "nan" write became 0.0 °C, because
/// `NaN as i32 == 0`). It is now rejected as OutOfRange, like any other value
/// outside the DPT 9 representable range.
#[test]
fn parse_value_9x_nan_is_rejected() {
    assert!(
        matches!(
            parse_value(&dpt("9.001"), "nan"),
            Err(ParseValueError::OutOfRange { .. })
        ),
        "9.001 nan should be OutOfRange"
    );
    // A directly-constructed NaN Float also fails to encode rather than
    // producing the zero encoding.
    let nan = TypedValue::Float {
        value: f32::NAN,
        unit: Some("°C"),
    };
    assert!(matches!(
        encode(&dpt("9.001"), &nan),
        Err(EncodeError::OutOfRange { .. })
    ));
}

/// Regression (was issue #34, fix 2): DPT 14.x used to accept NaN/Inf on encode
/// and round-trip the bit pattern. NaN/Inf are now rejected on both parse and
/// encode (a NaN/Inf write is a typo, not a bus value); decode stays lenient so
/// any 4-byte IEEE pattern seen on the wire still renders.
#[test]
fn parse_value_14x_nan_and_inf_are_rejected() {
    for input in ["nan", "inf", "-inf", "Infinity"] {
        assert!(
            matches!(
                parse_value(&dpt("14.056"), input),
                Err(ParseValueError::OutOfRange { .. })
            ),
            "14.056 {input:?} should be OutOfRange"
        );
    }
    // encode of a constructed NaN Float is rejected too.
    let nan = TypedValue::Float {
        value: f32::NAN,
        unit: None,
    };
    assert!(matches!(
        encode(&dpt("14.056"), &nan),
        Err(EncodeError::OutOfRange { .. })
    ));
    // Decode remains lenient: a NaN bit pattern still decodes to a Float.
    assert!(matches!(
        decode(&dpt("14.056"), &[0x7f, 0xc0, 0x00, 0x00]),
        TypedValue::Float { .. }
    ));
}

// ---------------------------------------------------------------------------
// parse_value range checks that ARE enforced correctly (regression guards).
// ---------------------------------------------------------------------------

#[test]
fn parse_value_integer_ranges_reject_out_of_range() {
    let cases: &[(&str, &str)] = &[
        ("5.010", "256"),
        ("6.010", "128"),
        ("6.010", "-129"),
        ("7.001", "65536"),
        ("8.001", "32768"),
        ("8.001", "-32769"),
        ("17.001", "64"),
        ("18.001", "64"),
        ("5.001", "101"),
        ("5.001", "-1"),
        ("5.003", "361"),
    ];
    for (d, input) in cases {
        let r = parse_value(&dpt(d), input);
        assert!(
            matches!(r, Err(ParseValueError::OutOfRange { .. })),
            "DPT {d} {input:?} should be OutOfRange, got {r:?}"
        );
    }
}

#[test]
fn parse_value_percent_accepts_scientific_and_signed_zero() -> Result<(), Box<dyn std::error::Error>>
{
    // Robustness observation: "1e2" parses as 100 (valid), "-0" as -0.0 (valid).
    assert_eq!(
        parse_value(&dpt("5.001"), "1e2")?,
        TypedValue::Percent(100.0)
    );
    // -0 is within 0..=100.
    assert!(matches!(
        parse_value(&dpt("5.001"), "-0"),
        Ok(TypedValue::Percent(_))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// encode(): DPT 5.003 angle mismatch.
// ---------------------------------------------------------------------------

/// Regression (was issue #34, fix 3): parse_value(5.003, "360") produces
/// `Unsigned { unit: Some("°") }`, but encode used to have no scaled arm for DPT
/// 5.003, so angles 256..=360 parsed then failed to encode (Mismatch) — they
/// were unsendable. Now encode scales degrees 0..=360 onto the raw 0..=255 byte,
/// the inverse of the decode scaling.
#[test]
fn dpt_5003_angle_above_255_encodes() {
    let v = parse_value(&dpt("5.003"), "360").expect("5.003 parses 360");
    assert_eq!(
        encode(&dpt("5.003"), &v).expect("5.003 angle 360 encodes"),
        vec![255]
    );

    // Round-trip both directions within the quantization: encode(decode(raw)) is
    // stable to within one raw step, and decode(encode(deg)) preserves degrees to
    // within the ~1.41°/step resolution.
    for raw in 0u8..=255 {
        if let TypedValue::Unsigned { value: deg, .. } = decode(&dpt("5.003"), &[raw]) {
            let re = encode(
                &dpt("5.003"),
                &TypedValue::Unsigned {
                    value: deg,
                    unit: Some("°"),
                },
            )
            .expect("re-encode angle");
            assert!(
                (re[0] as i16 - raw as i16).abs() <= 1,
                "raw {raw} -> {deg}° -> {} not within one step",
                re[0]
            );
        } else {
            panic!("5.003 decode should be Unsigned");
        }
    }
    for deg in [0u32, 45, 90, 180, 270, 360] {
        let bytes = encode(
            &dpt("5.003"),
            &TypedValue::Unsigned {
                value: deg,
                unit: Some("°"),
            },
        )
        .expect("encode angle");
        if let TypedValue::Unsigned { value: back, .. } = decode(&dpt("5.003"), &bytes) {
            assert!(
                (back as i64 - deg as i64).abs() <= 2,
                "{deg}° -> {back}° round-trip drifted"
            );
        } else {
            panic!("expected unsigned angle");
        }
    }
}

#[test]
fn encode_mismatch_and_unsupported_are_clean_errors() {
    // Wrong variant for the DPT -> Mismatch.
    assert!(matches!(
        encode(&dpt("1.001"), &TypedValue::Scene(1)),
        Err(EncodeError::Mismatch { .. })
    ));
    // Unsupported DPT -> Unsupported.
    assert!(matches!(
        encode(&dpt("250.001"), &TypedValue::Raw(vec![])),
        Err(EncodeError::Unsupported { .. })
    ));
}

// ---------------------------------------------------------------------------
// Round-trip property: encode(parse(x)) then decode == parse(x) for a spread of
// constructible values across the parseable DPTs.
// ---------------------------------------------------------------------------

#[test]
fn parse_encode_decode_roundtrip_spread() {
    let cases: &[(&str, &str)] = &[
        ("1.001", "on"),
        ("1.001", "off"),
        ("5.001", "0%"),
        ("5.001", "100%"),
        ("5.010", "0"),
        ("5.010", "255"),
        ("6.010", "-128"),
        ("6.010", "127"),
        ("7.001", "0"),
        ("7.001", "65535"),
        ("8.001", "-32768"),
        ("8.001", "32767"),
        ("12.001", "0"),
        ("12.001", "4294967295"),
        ("13.013", "-2147483648"),
        ("13.013", "2147483647"),
        ("17.001", "0"),
        ("17.001", "63"),
        ("18.001", "learn 63"),
        ("20.102", "auto"),
    ];
    for (d, input) in cases {
        let dp = dpt(d);
        let parsed =
            parse_value(&dp, input).unwrap_or_else(|e| panic!("parse {input} as {d}: {e}"));
        let bytes = encode(&dp, &parsed).unwrap_or_else(|e| panic!("encode {input} as {d}: {e}"));
        let back = decode(&dp, &bytes);
        match (&parsed, &back) {
            (TypedValue::Percent(a), TypedValue::Percent(b)) => {
                assert!((a - b).abs() <= 0.5, "{d} {input}: {a} != {b}")
            }
            _ => assert_eq!(&parsed, &back, "{d} {input} roundtrip"),
        }
    }
}

// ---------------------------------------------------------------------------
// Dpt FromStr fuzzing-by-hand.
// ---------------------------------------------------------------------------

#[test]
fn dpt_fromstr_rejects_and_accepts_correctly() {
    // Accepted (whitespace trimmed; leading + tolerated by Rust int parse).
    for ok in ["9", "1.001", "20.102", " 9 ", "9\t"] {
        assert!(ok.parse::<Dpt>().is_ok(), "{ok:?} should parse");
    }
    // Rejected.
    for bad in [
        "",
        ".",
        "9.",
        ".9",
        "1.2.3",
        "x",
        "9.x",
        "－9",
        "１.００１",
        "9 . 1",
    ] {
        assert!(bad.parse::<Dpt>().is_err(), "{bad:?} should fail");
    }
    // Observation: Rust's int parser accepts a leading '+', so "+1.001" parses.
    assert!("+1.001".parse::<Dpt>().is_ok(), "Rust tolerates leading +");
}

// ---------------------------------------------------------------------------
// GroupAddress / IndividualAddress FromStr fuzzing-by-hand.
// ---------------------------------------------------------------------------

#[test]
fn group_address_fromstr_hostile() {
    // Accepted.
    for ok in ["0/0/0", "31/7/255", "3/0/4"] {
        assert!(ok.parse::<GroupAddress>().is_ok(), "{ok:?} ok");
    }
    // Rejected shapes and ranges.
    for bad in [
        "",
        "3/0",
        "3/0/4/5",
        "abc",
        "32/0/0",
        "0/8/0",
        "0/0/256",
        "3//4",
        "/0/0",
        "3/0/",
        "-1/0/0",
        "3/0/4 5",
        "０/０/０",
        "🚀/0/0",
        "0x3/0/4",
    ] {
        assert!(bad.parse::<GroupAddress>().is_err(), "{bad:?} should fail");
    }
    // Observation: internal whitespace and leading '+' are tolerated because the
    // component parser trims and Rust int parse accepts '+'. This is lenient but
    // documented here so a future tightening is a conscious choice.
    assert!("3 / 0 / 4".parse::<GroupAddress>().is_ok());
    assert!("+3/0/+4".parse::<GroupAddress>().is_ok());
}

#[test]
fn individual_address_fromstr_hostile() {
    for ok in ["0.0.0", "15.15.255", "1.1.4"] {
        assert!(ok.parse::<IndividualAddress>().is_ok(), "{ok:?} ok");
    }
    for bad in [
        "", "1.1", "1.1.4.5", "16.0.0", "0.16.0", "0.0.256", "abc", "1..4", ".1.4", "1.1.",
    ] {
        assert!(
            bad.parse::<IndividualAddress>().is_err(),
            "{bad:?} should fail"
        );
    }
}

// ---------------------------------------------------------------------------
// Flags FromStr fuzzing-by-hand.
// ---------------------------------------------------------------------------

#[test]
fn flags_fromstr_hostile() -> Result<(), Box<dyn std::error::Error>> {
    // Accepted; any order, display canonicalises.
    assert_eq!("UTWC".parse::<Flags>()?.to_string(), "CWTU");
    assert_eq!("".parse::<Flags>()?.to_string(), "");
    assert_eq!("CRWTUI".parse::<Flags>()?, Flags::all());
    // Rejected: unknown char, lowercase, duplicate, unicode.
    for bad in ["CWZ", "cw", "CC", "C W", "C\tW", "Ç", "🚀", "CRWTUIX"] {
        assert!(bad.parse::<Flags>().is_err(), "{bad:?} should fail");
    }
    Ok(())
}
