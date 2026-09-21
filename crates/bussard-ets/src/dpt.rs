//! Mapping ETS DatapointType strings to the model's [`Dpt`] type.
//!
//! ETS writes DPTs in two forms:
//!
//! * `"DPST-1-8"` — a fully-qualified sub-type: main 1, sub 8.
//! * `"DPT-9"` — a main type only (no sub): main 9, sub `None`.
//!
//! Some attributes carry *multiple* space-separated DPTs (e.g. a com-object ref
//! that accepts several); ETS/xknxproject takes the first, so we do too.

use bussard_model::Dpt;

/// Parses an ETS `DatapointType` attribute value into a [`Dpt`].
///
/// Accepts `"DPST-<main>-<sub>"`, `"DPT-<main>"`, and space-separated lists of
/// those (the first entry wins). Returns `None` if the string is empty or does
/// not match either shape.
pub fn parse_ets_dpt(raw: &str) -> Option<Dpt> {
    let first = raw.split_whitespace().next()?;
    parse_single(first)
}

/// Derives a fallback DPT main number from an ETS `ObjectSize` string, for
/// com-objects that declare no `DatapointType`.
///
/// Every entry maps a size to a main type whose payload is **exactly** that
/// wide (KNX 03/07/02 "Datapoint Types"), because the derived DPT is what the
/// rest of bussard sizes the object by: a main type of the wrong width shows up
/// as a spurious E004 size conflict and decodes payloads under the wrong layout.
/// Where several main types share a width the most common com-object type wins;
/// the result is always a main-only DPT (no sub).
///
/// | ObjectSize | DPT | Name | Width |
/// |---|---|---|---|
/// | 1 bit | 1 | boolean | 1 bit |
/// | 2 bit | 2 | 1-bit controlled | 2 bit |
/// | 4 bit | 3 | 3-bit controlled | 4 bit |
/// | 1 byte | 5 | 8-bit unsigned | 1 byte |
/// | 2 bytes | 9 | 2-byte float | 2 bytes |
/// | 3 bytes | 10 | time of day | 3 bytes |
/// | 4 bytes | 12 | 4-byte unsigned | 4 bytes |
/// | 6 bytes | 251 | RGBW colour | 6 bytes |
/// | 8 bytes | 19 | date + time | 8 bytes |
/// | 14 bytes | 16 | character string | 14 bytes |
///
/// Sizes with no main type of that exact width (notably `"10 bytes"`) return
/// `None`, leaving the com-object's declared `size` in the model rather than
/// inventing a DPT. `"6 bytes"` and `"8 bytes"` used to map to DPT 232, which is
/// 3 bytes wide — the source of exactly those bogus E004 conflicts.
pub fn dpt_from_object_size(size: &str) -> Option<Dpt> {
    let normalized = size.trim().to_ascii_lowercase();
    let main: u16 = match normalized.as_str() {
        "1 bit" => 1,
        "2 bit" => 2,
        "4 bit" => 3,
        "1 byte" => 5,
        "2 bytes" => 9,
        "3 bytes" => 10,
        "4 bytes" => 12,
        "6 bytes" => 251,
        "8 bytes" => 19,
        "14 bytes" => 16,
        _ => return None,
    };
    Some(Dpt::new(main, None))
}

fn parse_single(token: &str) -> Option<Dpt> {
    if let Some(rest) = token.strip_prefix("DPST-") {
        let mut parts = rest.splitn(2, '-');
        let main: u16 = parts.next()?.parse().ok()?;
        let sub: u16 = parts.next()?.parse().ok()?;
        Some(Dpt::new(main, Some(sub)))
    } else if let Some(rest) = token.strip_prefix("DPT-") {
        let main: u16 = rest.parse().ok()?;
        Some(Dpt::new(main, None))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::ApduSize;

    #[test]
    fn parses_dpst() {
        let d = parse_ets_dpt("DPST-1-8").unwrap();
        assert_eq!(d, Dpt::new(1, Some(8)));
        assert_eq!(d.to_string(), "1.008");
    }

    #[test]
    fn parses_dpt_no_sub() {
        let d = parse_ets_dpt("DPT-9").unwrap();
        assert_eq!(d, Dpt::new(9, None));
        assert_eq!(d.to_string(), "9");
    }

    #[test]
    fn parses_large_numbers() {
        assert_eq!(
            parse_ets_dpt("DPST-20-102").unwrap(),
            Dpt::new(20, Some(102))
        );
    }

    #[test]
    fn takes_first_of_list() {
        assert_eq!(
            parse_ets_dpt("DPST-1-1 DPST-1-2").unwrap(),
            Dpt::new(1, Some(1))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_ets_dpt(""), None);
        assert_eq!(parse_ets_dpt("nonsense"), None);
        assert_eq!(parse_ets_dpt("DPST-1"), None);
    }

    #[test]
    fn object_size_fallback() {
        assert_eq!(dpt_from_object_size("1 Bit"), Some(Dpt::new(1, None)));
        assert_eq!(dpt_from_object_size("2 Bytes"), Some(Dpt::new(9, None)));
        // Case-insensitive and trimmed.
        assert_eq!(dpt_from_object_size(" 1 bit "), Some(Dpt::new(1, None)));
        assert_eq!(dpt_from_object_size("42 Bytes"), None);
    }

    /// Regression: `"6 bytes"` and `"8 bytes"` both fell back to DPT 232, which
    /// is 3 bytes wide (`Dpt::expected_size`). A 6- or 8-byte com-object without
    /// a `DatapointType` imported as RGB, so every size check flagged a bogus
    /// E004 conflict and payloads decoded under a 3-byte layout.
    #[test]
    fn test_dpt_from_object_size_matches_the_declared_width() {
        for (size, dpt) in [
            ("1 Bit", Dpt::new(1, None)),
            ("2 Bit", Dpt::new(2, None)),
            ("4 Bit", Dpt::new(3, None)),
            ("1 Byte", Dpt::new(5, None)),
            ("2 Bytes", Dpt::new(9, None)),
            ("3 Bytes", Dpt::new(10, None)),
            ("4 Bytes", Dpt::new(12, None)),
            ("6 Bytes", Dpt::new(251, None)),
            ("8 Bytes", Dpt::new(19, None)),
            ("14 Bytes", Dpt::new(16, None)),
        ] {
            let derived = dpt_from_object_size(size).unwrap_or_else(|| panic!("{size} maps"));
            assert_eq!(derived, dpt, "{size}");
            // The whole point: the derived DPT is exactly as wide as the object.
            let lower = size.to_ascii_lowercase();
            let (count, unit) = lower.split_once(' ').unwrap_or_else(|| panic!("{size}"));
            let count: u8 = count.parse().unwrap_or_else(|_| panic!("{size}"));
            let width = match unit {
                "bit" => ApduSize::Bits(count),
                "byte" | "bytes" => ApduSize::Bytes(count),
                other => panic!("unexpected unit {other}"),
            };
            assert_eq!(
                derived.expected_size(),
                Some(width),
                "{size} -> {derived} must be {width} wide"
            );
        }
    }

    /// No KNX main type is exactly 10 octets wide, so the com-object keeps its
    /// declared size rather than being given an invented (14-byte) DPT 16.
    #[test]
    fn test_dpt_from_object_size_unknown_width_yields_none() {
        assert_eq!(dpt_from_object_size("10 Bytes"), None);
        assert_eq!(dpt_from_object_size("42 Bytes"), None);
        assert_eq!(dpt_from_object_size(""), None);
    }
}
