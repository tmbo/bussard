//! Small text helpers the service modules share: an error chain on one line,
//! a property value as printable ASCII, a multi-line message as one table
//! cell, and a session error as a per-device row reads it.

use crate::error::ServiceError;

/// An error and its sources, joined with `": "` (anyhow's `{:#}`).
pub fn chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut next = err.source();
    while let Some(cause) = next {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        next = cause.source();
    }
    out
}

/// The printable ASCII of a raw property value up to its first NUL, trimmed.
pub fn clean_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| char::from(*b))
        .collect();
    s.trim().to_string()
}

/// Flattens a multi-line error into one summary-table cell.
pub fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// A management session that could not be opened, as a per-device row reads
/// it: `leasing the bus: <cause>` or `connecting: <cause>`.
pub fn session_error_detail(err: &ServiceError) -> String {
    match err {
        ServiceError::Lease(cause) => format!("leasing the bus: {cause}"),
        other => format!("connecting: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_ascii_strips_nul_and_control() {
        assert_eq!(clean_ascii(b"ABB/S 1.1\0\0"), "ABB/S 1.1");
        assert_eq!(clean_ascii(&[0x01, 0x02]), "");
        assert_eq!(clean_ascii(b" 2CHANG.01\0junk"), "2CHANG.01");
    }

    #[test]
    fn test_one_line_flattens_multiline_errors() {
        assert_eq!(one_line("a\n\n  b  \nc"), "a; b; c");
    }
}
