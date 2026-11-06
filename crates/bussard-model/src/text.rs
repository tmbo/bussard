//! Small text helpers every crate shares: hex, HTML escaping, slugs, edit
//! distance and English list joining.
//!
//! The model crate sits below every other bussard crate, so these live here
//! once instead of as private copies in each crate.

use std::fmt::Write as _;

/// Lower-case hex of `bytes`, no separators (`[0x0c, 0x1a]` is `"0c1a"`).
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Upper-case hex of `bytes`, no separators (`[0x0c, 0x1a]` is `"0C1A"`).
pub fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Why [`from_hex`] refused a string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    /// The string has an odd number of characters.
    #[error("odd length ({0} chars); hex must be byte-aligned")]
    OddLength(usize),
    /// A character is not a hex digit.
    #[error("non-hex character {0:?}")]
    InvalidDigit(char),
}

/// Decodes an even-length hex string, upper- or lower-case, with no
/// separators or prefix. The empty string is no bytes.
pub fn from_hex(text: &str) -> Result<Vec<u8>, HexError> {
    if !text.len().is_multiple_of(2) {
        return Err(HexError::OddLength(text.len()));
    }
    let digit = |b: u8| {
        (b as char)
            .to_digit(16)
            .ok_or(HexError::InvalidDigit(b as char))
    };
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[hi, lo]| Ok((digit(*hi)? * 16 + digit(*lo)?) as u8))
        .collect()
}

/// `text` safe inside an HTML element or a double- or single-quoted attribute.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The contract's slug: lowercase, `ä ö ü ß` to `ae oe ue ss`, every run of
/// characters outside `[a-z0-9]` collapsed to `-`, trimmed; empty becomes `x`.
pub fn slug(text: &str) -> String {
    slug_or(text, "x")
}

/// [`slug`] with `fallback` for a text that leaves nothing.
pub fn slug_or(text: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in text.chars().flat_map(char::to_lowercase) {
        let mapped: &str = match c {
            'ä' => "ae",
            'ö' => "oe",
            'ü' => "ue",
            'ß' => "ss",
            _ => "",
        };
        if !mapped.is_empty() {
            out.push_str(mapped);
            dash = false;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

/// The Levenshtein distance between `a` and `b`, by characters.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diagonal = i;
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = (diagonal + usize::from(ca != *cb))
                .min(row[j] + 1)
                .min(above + 1);
            diagonal = above;
        }
    }
    row[b.len()]
}

/// `text` with its first letter in upper case.
pub fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// `a`, `a and b`, `a, b and c`.
pub fn join_and(items: &[String]) -> String {
    join_list(items, ", ", " and ")
}

/// `items` joined by `sep`, with `last` before the final item.
pub fn join_list(items: &[String], sep: &str, last: &str) -> String {
    match items.split_last() {
        None => String::new(),
        Some((only, [])) => only.clone(),
        Some((tail, rest)) => format!("{}{last}{tail}", rest.join(sep)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_lower_and_upper() {
        assert_eq!(hex(&[0x0c, 0x1a, 0xff]), "0c1aff");
        assert_eq!(hex_upper(&[0x0c, 0x1a, 0xff]), "0C1AFF");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn test_from_hex_roundtrip_and_errors() -> Result<(), HexError> {
        assert_eq!(from_hex("0c1AfF")?, vec![0x0c, 0x1a, 0xff]);
        assert_eq!(from_hex("")?, Vec::<u8>::new());
        assert_eq!(from_hex("abc"), Err(HexError::OddLength(3)));
        assert_eq!(from_hex("0g"), Err(HexError::InvalidDigit('g')));
        assert_eq!(from_hex("+1"), Err(HexError::InvalidDigit('+')));
        assert!(from_hex("ü0").is_err());
        assert_eq!(
            HexError::OddLength(3).to_string(),
            "odd length (3 chars); hex must be byte-aligned"
        );
        Ok(())
    }

    #[test]
    fn test_escape_html_escapes_markup() {
        assert_eq!(
            escape_html("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn test_slug_folds_umlauts_and_collapses() {
        assert_eq!(slug("Zuordnung Regen"), "zuordnung-regen");
        assert_eq!(slug("Größe / Maß"), "groesse-mass");
        assert_eq!(slug("  --  "), "x");
        assert_eq!(slug("Übersicht (1)"), "uebersicht-1");
        assert_eq!(slug_or("", "device"), "device");
    }

    #[test]
    fn test_edit_distance_counts_edits() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("projekt", "project"), 1);
        assert_eq!(edit_distance("dtp", "dpt"), 2);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("same", "same"), 0);
    }

    #[test]
    fn test_join_and_and_capitalize() {
        let items = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(join_and(&items(&[])), "");
        assert_eq!(join_and(&items(&["a"])), "a");
        assert_eq!(join_and(&items(&["a", "b", "c"])), "a, b and c");
        assert_eq!(join_list(&items(&["a", "b"]), "; ", "; and "), "a; and b");
        assert_eq!(capitalize("über"), "Über");
        assert_eq!(capitalize(""), "");
    }
}
