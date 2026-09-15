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

/// Derives a fallback DPT main number from an ETS `ObjectSize` string, matching
/// xknxproject's behaviour for com-objects that declare no `DatapointType`.
///
/// The mapping keys off the standard KNX object sizes: a 1-bit object defaults
/// to DPT main 1 (boolean), a 2-byte object to main 9 (2-byte float), and so on
/// for the sizes ETS emits. The result is always a main-only DPT (no sub).
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
        "6 bytes" => 232,
        "8 bytes" => 232,
        "10 bytes" => 16,
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
}
