//! The product-data pointer index: a committed JSON file mapping order numbers
//! to vendor-hosted `.knxprod` downloads.
//!
//! The index ships pointers only — never payloads. Vendor application programs
//! are copyrighted and large, so bussard stores just enough to fetch and verify
//! them on demand: the download URL, a SHA-256 checksum, the byte size, and the
//! filename to cache under. See [`fetch`](crate::fetch) for the download side
//! and `docs/product-data.md` for the schema.
//!
//! Order numbers are matched with [`normalize_order_number`], which strips
//! surrounding whitespace and upper-cases so that a scanned `akk-0216.03` finds
//! the index entry written `AKK-0216.03`. The interior form is preserved
//! otherwise: separators like `-` and `.` are meaningful in KNX order numbers
//! and are not stripped.

use serde::{Deserialize, Serialize};

use crate::error::ProdError;

/// One index entry: a pointer to a vendor-hosted `.knxprod` download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Human-readable manufacturer name, e.g. `"MDT"`.
    pub manufacturer: String,
    /// KNX manufacturer id as it appears inside the `.knxprod`, e.g. `"M-0083"`.
    pub manufacturer_id: String,
    /// Every order number this download serves, verbatim as in `Hardware.xml`
    /// (e.g. `"AKK-0216.03"`). A single MDT `.knxprod` commonly bundles a whole
    /// product family, so one entry lists many order numbers.
    pub order_numbers: Vec<String>,
    /// A human-readable product/family name for display.
    pub name: String,
    /// The vendor-hosted download URL for the `.knxprod` file.
    pub url: String,
    /// Lower-case hex SHA-256 of the downloaded file, for integrity + tamper
    /// detection.
    pub sha256: String,
    /// The exact byte size of the download, checked before and after fetching.
    pub size: u64,
    /// The filename to cache the download under (also the original vendor name).
    pub filename: String,
    /// Optional: the application-program ref an order number resolves to, for
    /// documentation. Not required for fetching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_ref: Option<String>,
    /// Whether bussard may itself mirror this file. Always `false` for
    /// vendor-hosted copyrighted data; `true` only for explicitly
    /// redistributable sources.
    #[serde(default)]
    pub redistributable: bool,
    /// Free-form notes (version, date verified, caveats).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// The parsed product-data pointer index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProductIndex {
    /// Every pointer entry, in file order.
    pub entries: Vec<IndexEntry>,
}

impl ProductIndex {
    /// Parses the index from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ProdError> {
        serde_json::from_slice(bytes).map_err(|e| ProdError::Index {
            reason: format!("parsing product index JSON: {e}"),
        })
    }

    /// Parses the index from a JSON string.
    pub fn from_json_str(s: &str) -> Result<Self, ProdError> {
        Self::from_json_bytes(s.as_bytes())
    }

    /// Looks up the entry serving a given order number, normalizing both sides
    /// so case and surrounding whitespace do not matter.
    ///
    /// Returns the first entry that lists a matching order number (entries are
    /// kept in file order; order numbers are unique across the seeded index).
    pub fn lookup(&self, order_number: &str) -> Option<&IndexEntry> {
        let want = normalize_order_number(order_number);
        self.entries.iter().find(|e| {
            e.order_numbers
                .iter()
                .any(|o| normalize_order_number(o) == want)
        })
    }
}

/// Normalizes an order number for matching: trims surrounding whitespace and
/// upper-cases. Interior separators (`-`, `.`, spaces inside the string) are
/// preserved, since they distinguish KNX order numbers.
pub fn normalize_order_number(order: &str) -> String {
    order.trim().to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "entries": [
        {
          "manufacturer": "MDT",
          "manufacturer_id": "M-0083",
          "order_numbers": ["AKK-0216.03", "AKK-0416.03"],
          "name": "MDT Switch Actuator AKK compact",
          "url": "https://example.test/akk.knxprod",
          "sha256": "05b20395667510c16b83c47d46935a69f52b4534d71371f848f96141b74ca1b9",
          "size": 334088,
          "filename": "MDT_KP_AKK.knxprod",
          "redistributable": false
        }
      ]
    }"#;

    #[test]
    fn parses_entries() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let idx = ProductIndex::from_json_str(SAMPLE)?;
        assert_eq!(idx.entries.len(), 1);
        let e = &idx.entries[0];
        assert_eq!(e.manufacturer_id, "M-0083");
        assert_eq!(e.size, 334088);
        assert!(!e.redistributable);
        assert_eq!(e.order_numbers.len(), 2);
        Ok(())
    }

    #[test]
    fn lookup_exact() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let idx = ProductIndex::from_json_str(SAMPLE)?;
        let e = idx
            .lookup("AKK-0216.03")
            .ok_or("idx.lookup(\"AKK-0216.03\") missing")?;
        assert_eq!(e.name, "MDT Switch Actuator AKK compact");
        Ok(())
    }

    #[test]
    fn lookup_normalizes_case_and_whitespace() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let idx = ProductIndex::from_json_str(SAMPLE)?;
        assert!(idx.lookup("  akk-0216.03 ").is_some());
        assert!(idx.lookup("AKK-0416.03").is_some());
        Ok(())
    }

    #[test]
    fn lookup_preserves_interior_separators() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let idx = ProductIndex::from_json_str(SAMPLE)?;
        // Stripping the dot/dash would be wrong: these are distinct order numbers.
        assert!(idx.lookup("AKK021603").is_none());
        assert!(idx.lookup("AKK-021603").is_none());
        Ok(())
    }

    #[test]
    fn lookup_miss_returns_none() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let idx = ProductIndex::from_json_str(SAMPLE)?;
        assert!(idx.lookup("NOPE-1").is_none());
        Ok(())
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(ProductIndex::from_json_str("{ not json").is_err());
    }

    #[test]
    fn normalize_examples() {
        assert_eq!(normalize_order_number(" akk-0216.03 "), "AKK-0216.03");
        assert_eq!(normalize_order_number("2116REG"), "2116REG");
    }
}
