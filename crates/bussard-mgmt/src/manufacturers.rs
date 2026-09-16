//! A small built-in table of common KNX manufacturer ids.
//!
//! KNX assigns each manufacturer a numeric id (the value behind
//! `PID_MANUFACTURER_ID`). This table maps the handful of common ones to names
//! so `bussard scan` can print "Jung" instead of `0x0004`. It is deliberately
//! small; unknown ids are rendered as hex by the caller.
//!
//! Ids are the public KNX manufacturer numbers.

/// Common KNX manufacturer ids and their display names.
pub const MANUFACTURERS: &[(u16, &str)] = &[
    (0x0001, "Siemens"),
    (0x0002, "ABB"),
    (0x0004, "Jung"),
    (0x0006, "Berker"),
    (0x0009, "GIRA"),
    (0x000C, "Merten"),
    (0x0016, "Legrand"),
    (0x0018, "Busch-Jaeger"),
    (0x0021, "Hager"),
    (0x0025, "Steinel"),
    (0x0028, "Theben"),
    (0x0069, "Helios"),
    // 0x00FA is the KNX Association itself; KNX Virtual's simulated devices
    // report it (observed live 2026-09-16).
    (0x00FA, "KNX Association"),
    (0x0083, "MDT"),
];

/// Looks up a manufacturer name by id, returning `None` if unknown.
pub fn name(id: u16) -> Option<&'static str> {
    MANUFACTURERS
        .iter()
        .find_map(|(k, v)| (*k == id).then_some(*v))
}

/// Formats a manufacturer id as its name, or `0xXXXX` if unknown.
pub fn display(id: u16) -> String {
    match name(id) {
        Some(n) => n.to_string(),
        None => format!("0x{id:04X}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_map_to_names() {
        assert_eq!(name(0x0004), Some("Jung"));
        assert_eq!(name(0x0083), Some("MDT"));
        assert_eq!(display(0x0002), "ABB");
    }

    #[test]
    fn unknown_id_is_hex() {
        assert_eq!(name(0xABCD), None);
        assert_eq!(display(0xABCD), "0xABCD");
    }
}
