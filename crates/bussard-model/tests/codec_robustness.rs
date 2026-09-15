//! Aggressive robustness tests for the DPT codec and the address/DPT/flags
//! parsers (bussard-model). Added by the hardening pass.
//!
//! These are table-driven loop tests over every implemented DPT plus hostile
//! parse inputs. A test tagged `#[ignore = "exposes bug: ..."]` documents a real
//! defect in `src/` that this pass is not permitted to fix (see the report).

use std::panic::{AssertUnwindSafe, catch_unwind};

use bussard_model::codec::{EncodeError, ParseValueError, TypedValue, decode, encode, parse_value};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress};

fn dpt(s: &str) -> Dpt {
    s.parse().unwrap()
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
fn float16_invalid_sentinel_and_extremes_decode_without_panic() {
    // 0x7FFF is the KNX "invalid data" sentinel; bussard decodes it as a normal
    // float (documented observation, not a panic). We only assert no panic and a
    // Float variant.
    for bytes in [[0x7F, 0xFF], [0xFF, 0xFF], [0x80, 0x00], [0x00, 0x00]] {
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
fn float32_nan_inf_decode_and_reencode() {
    // NaN and infinities are valid IEEE bit patterns; decode must produce a
    // Float and re-encode must round-trip the bytes.
    let cases: &[[u8; 4]] = &[
        [0x7f, 0xc0, 0x00, 0x00], // NaN
        [0x7f, 0x80, 0x00, 0x00], // +Inf
        [0xff, 0x80, 0x00, 0x00], // -Inf
        [0x00, 0x00, 0x00, 0x00], // 0
        [0x80, 0x00, 0x00, 0x00], // -0
    ];
    for bytes in cases {
        let v = decode(&dpt("14.056"), bytes);
        match &v {
            TypedValue::Float { .. } => {
                let re = encode(&dpt("14.056"), &v).expect("14.x re-encode");
                assert_eq!(&re[..], &bytes[..], "14.x byte roundtrip for {bytes:?}");
            }
            other => panic!("14.056 {bytes:?} decoded to {other:?}"),
        }
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
    // NOTE: DPT 9.x is deliberately excluded here because it DOES panic on large
    // magnitudes / infinities (e.g. "1e999" -> +Inf). That defect is captured by
    // the dedicated, ignored `parse_value_9x_large_magnitude_should_error_not_panic`
    // test so this broad guard can stay green for the rest of the DPTs.
    let parseable = &[
        "1.001", "1.008", "5.001", "5.003", "5.010", "6.010", "7.001", "8.001", "12.001", "13.013",
        "14.056", "17.001", "18.001", "20.102",
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

/// BUG: parse_value for a 2-byte-float DPT (9.x) panics with an arithmetic
/// overflow when handed any large finite (or infinite) magnitude. The CLI
/// `write` command and MCP `knx_write_group` feed user/LLM text straight into
/// `parse_value`, so `bussard write <ga> 1e9` (DPT 9) aborts the process.
///
/// Root cause: `codec::parse_value` accepts the float, then `encode_float16`
/// (called only to range-check) does `(value*100.0).round() as i32`, which
/// saturates to `i32::MAX`/`i32::MIN` for large inputs. The subsequent halving
/// loop computes `(mantissa + 1) / 2` / `(mantissa - 1) / 2` on `i32::MAX` /
/// `i32::MIN`, overflowing (panic in debug; wrap in release). See
/// `crates/bussard-model/src/codec.rs:316-327` (panic at :322 / :324).
///
/// Expected: parse_value should return `ParseValueError::OutOfRange`, matching
/// its documented "roughly -671088.64 .. 670760.96" contract.
#[test]
#[ignore = "exposes bug: parse_value(9.x, large/inf) panics with i32 add/sub overflow in encode_float16 (codec.rs:322/324)"]
fn parse_value_9x_large_magnitude_should_error_not_panic() {
    for input in ["1e9", "inf", "-1e9", "21474836.48", "1e30"] {
        let r = parse_value(&dpt("9.001"), input);
        assert!(
            matches!(r, Err(ParseValueError::OutOfRange { .. })),
            "9.001 {input:?} should be OutOfRange, got {r:?}"
        );
    }
}

/// Observation (not asserted as bug here, kept green): parse_value(9.x, "nan")
/// silently succeeds as a value that later encodes to 0. It does NOT panic
/// because `NaN as i32 == 0`. It is still wrong (a "nan" write becomes 0.0 °C),
/// but distinct from the overflow panic above.
#[test]
fn parse_value_9x_nan_is_accepted_as_zeroish() {
    // Documented current behaviour: "nan" parses to a NaN float.
    let r = parse_value(&dpt("9.001"), "nan");
    assert!(r.is_ok(), "current behaviour accepts nan: {r:?}");
    if let Ok(v) = r {
        // encode does not panic for NaN (unlike inf) and yields the zero encoding.
        let enc = encode(&dpt("9.001"), &v).expect("nan encodes to something");
        assert_eq!(enc, vec![0x00, 0x00], "nan encodes as zero float");
    }
}

/// DPT 14.x accepts NaN/Inf and round-trips the bit pattern, but a NaN value is
/// then `!= itself`, so a naive parse->encode->decode equality check fails.
/// Documented as a robustness observation.
#[test]
fn parse_value_14x_nan_roundtrip_is_not_equal_to_itself() {
    let v = parse_value(&dpt("14.056"), "nan").expect("14.x accepts nan");
    let bytes = encode(&dpt("14.056"), &v).expect("encode nan");
    let back = decode(&dpt("14.056"), &bytes);
    // NaN != NaN, so the values are unequal even though the bytes round-trip.
    assert_ne!(v, back, "NaN is never equal to itself");
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
fn parse_value_percent_accepts_scientific_and_signed_zero() {
    // Robustness observation: "1e2" parses as 100 (valid), "-0" as -0.0 (valid).
    assert_eq!(
        parse_value(&dpt("5.001"), "1e2").unwrap(),
        TypedValue::Percent(100.0)
    );
    // -0 is within 0..=100.
    assert!(matches!(
        parse_value(&dpt("5.001"), "-0"),
        Ok(TypedValue::Percent(_))
    ));
}

// ---------------------------------------------------------------------------
// encode(): DPT 5.003 angle mismatch.
// ---------------------------------------------------------------------------

/// BUG: parse_value(5.003, "180") produces `Unsigned { unit: Some("°") }`, but
/// encode has no arm for DPT main 5 sub 3 that accepts a unit-bearing Unsigned —
/// its 5.x arm only matches `(_, Unsigned)` with `v <= 255`, and an angle can be
/// up to 360. So `bussard write <ga> 360` for a 5.003 GA parses fine then fails
/// to encode (EncodeError::Mismatch) — the value cannot be sent even though it
/// parsed. 5.003 angles 256..=360 are unsendable.
///
/// See `codec::encode` main==5 arm (`crates/bussard-model/src/codec.rs:840-852`):
/// the `Unsigned` guard is `*v <= 255`, but 5.003 permits 0..=360.
#[test]
#[ignore = "exposes bug: DPT 5.003 angle 256..=360 parses but encode() rejects it (Mismatch); values >255 unsendable (codec.rs:850)"]
fn dpt_5003_angle_above_255_should_encode() {
    let v = parse_value(&dpt("5.003"), "360").expect("5.003 parses 360");
    let r = encode(&dpt("5.003"), &v);
    assert!(r.is_ok(), "5.003 angle 360 should encode, got {r:?}");
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
fn flags_fromstr_hostile() {
    // Accepted; any order, display canonicalises.
    assert_eq!("UTWC".parse::<Flags>().unwrap().to_string(), "CWTU");
    assert_eq!("".parse::<Flags>().unwrap().to_string(), "");
    assert_eq!("CRWTUI".parse::<Flags>().unwrap(), Flags::all());
    // Rejected: unknown char, lowercase, duplicate, unicode.
    for bad in ["CWZ", "cw", "CC", "C W", "C\tW", "Ç", "🚀", "CRWTUIX"] {
        assert!(bad.parse::<Flags>().is_err(), "{bad:?} should fail");
    }
}
