//! bussard's list of supported devices (issue #1089): the application programs
//! it has checked against ETS, embedded in the binary from
//! `data/supported-devices.toml`.
//!
//! The list only says which applications are known good. The verdict a write
//! acts on, and the refusal, live in `bussard-service` (`support`), so the CLI
//! and the MCP server decide the same way.

use std::fmt;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// The list as shipped, the text the binary embeds.
pub const SUPPORTED_DEVICES_TOML: &str = include_str!("../data/supported-devices.toml");

/// Why an application is on the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// Flashed by bussard on a real device and read back.
    Live,
    /// The offline oracle is identical against an ETS capture at a meaningful
    /// coverage.
    Capture,
    /// A fabricated product of the synthetic catalogue (#596), identical
    /// against its committed ETS capture.
    Synthetic,
}

impl Evidence {
    /// The word the list file and every surface use.
    pub fn as_str(self) -> &'static str {
        match self {
            Evidence::Live => "live",
            Evidence::Capture => "capture",
            Evidence::Synthetic => "synthetic",
        }
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One supported application program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportedEntry {
    /// The application id: manufacturer, application number and version as
    /// ten upper-case hex digits (`000420DE22`).
    pub application_id: String,
    /// Manufacturer and product, for messages.
    pub name: String,
    /// Why the application is on the list.
    pub evidence: Evidence,
    /// Where the evidence is: an issue, or committed material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl SupportedEntry {
    /// The application ref prefix the id stands for (`M-0004_A-20DE-22`).
    pub fn application(&self) -> String {
        application_ref_of(&self.application_id)
    }
}

/// The application ref prefix of a ten-digit application id: `000420DE22`
/// is `M-0004_A-20DE-22`. An id of another shape is returned as it is.
pub fn application_ref_of(application_id: &str) -> String {
    match (
        application_id.get(..4),
        application_id.get(4..8),
        application_id.get(8..),
    ) {
        (Some(m), Some(n), Some(v)) if is_application_id(application_id) => {
            format!("M-{m}_A-{n}-{v}")
        }
        _ => application_id.to_string(),
    }
}

/// Whether `id` has the shape of an application id: ten hex digits.
pub fn is_application_id(id: &str) -> bool {
    id.len() == 10 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// The file's shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListFile {
    /// The entries.
    #[serde(default)]
    device: Vec<SupportedEntry>,
}

/// Why a list did not parse.
#[derive(Debug, thiserror::Error)]
pub enum SupportedListError {
    /// The TOML did not parse.
    #[error("supported-device list: {0}")]
    Toml(#[from] toml::de::Error),
    /// An entry is malformed.
    #[error("supported-device list, entry {index} ({application_id}): {reason}")]
    Entry {
        /// The entry's position, from zero.
        index: usize,
        /// The entry's application id as written.
        application_id: String,
        /// What is wrong with it.
        reason: String,
    },
}

/// The supported-device list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SupportedList {
    /// The entries, sorted by application id.
    entries: Vec<SupportedEntry>,
}

impl SupportedList {
    /// Parses a list file: every id ten upper-case hex digits and unique,
    /// every name non-empty.
    ///
    /// # Errors
    ///
    /// The TOML does not parse, or an entry is malformed or repeated.
    pub fn parse(text: &str) -> Result<SupportedList, SupportedListError> {
        let file: ListFile = toml::from_str(text)?;
        let mut entries = file.device;
        for (index, entry) in entries.iter().enumerate() {
            let bad = |reason: &str| SupportedListError::Entry {
                index,
                application_id: entry.application_id.clone(),
                reason: reason.to_string(),
            };
            if !is_application_id(&entry.application_id)
                || entry.application_id.to_ascii_uppercase() != entry.application_id
            {
                return Err(bad("application_id must be ten upper-case hex digits"));
            }
            if entry.name.trim().is_empty() {
                return Err(bad("name is empty"));
            }
        }
        entries.sort_by(|a, b| a.application_id.cmp(&b.application_id));
        if let Some(pair) = entries
            .windows(2)
            .find(|w| w[0].application_id == w[1].application_id)
        {
            return Err(SupportedListError::Entry {
                index: 0,
                application_id: pair[1].application_id.clone(),
                reason: "listed twice".to_string(),
            });
        }
        Ok(SupportedList { entries })
    }

    /// The list the binary ships. An embedded file that does not parse is
    /// an empty list (every write then needs the override); the unit test
    /// of this module keeps that from shipping.
    pub fn embedded() -> &'static SupportedList {
        static LIST: OnceLock<SupportedList> = OnceLock::new();
        LIST.get_or_init(|| SupportedList::parse(SUPPORTED_DEVICES_TOML).unwrap_or_default())
    }

    /// The entry for `application_id` (case-insensitive), if listed.
    pub fn lookup(&self, application_id: &str) -> Option<&SupportedEntry> {
        let id = application_id.to_ascii_uppercase();
        self.entries
            .binary_search_by(|e| e.application_id.as_str().cmp(id.as_str()))
            .ok()
            .and_then(|i| self.entries.get(i))
    }

    /// Every entry, sorted by application id.
    pub fn entries(&self) -> &[SupportedEntry] {
        &self.entries
    }

    /// The Markdown table `docs/explanation/device-support.md` carries
    /// between its `supported-table` markers.
    pub fn markdown_table(&self) -> String {
        let mut out =
            String::from("| Application | Id | Product | Evidence |\n|---|---|---|---|\n");
        for entry in &self.entries {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} |\n",
                entry.application(),
                entry.application_id,
                entry.name,
                entry.evidence
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_embedded_list_parses_and_is_seeded() -> TestResult {
        let list = SupportedList::parse(SUPPORTED_DEVICES_TOML)?;
        assert!(list.entries().len() > 10, "the seed entries are present");
        assert_eq!(SupportedList::embedded(), &list);
        for entry in list.entries() {
            assert!(
                entry.note.as_deref().is_some_and(|n| !n.trim().is_empty()),
                "{} cites no evidence",
                entry.application_id
            );
        }
        Ok(())
    }

    #[test]
    fn test_lookup_finds_by_id_case_insensitive() -> TestResult {
        let list = SupportedList::parse(
            "[[device]]\napplication_id = \"000420DE22\"\nname = \"Jung 230021SU\"\n\
             evidence = \"capture\"\nnote = \"#126\"\n",
        )?;
        let entry = list.lookup("000420de22").ok_or("not found")?;
        assert_eq!(entry.evidence, Evidence::Capture);
        assert_eq!(entry.application(), "M-0004_A-20DE-22");
        assert!(list.lookup("0083012010").is_none());
        Ok(())
    }

    #[test]
    fn test_parse_refuses_bad_id_duplicate_and_unknown_evidence() {
        let entry = |id: &str, evidence: &str| {
            format!(
                "[[device]]\napplication_id = \"{id}\"\nname = \"x\"\nevidence = \"{evidence}\"\n"
            )
        };
        assert!(SupportedList::parse(&entry("M-0004_A-20DE", "capture")).is_err());
        assert!(SupportedList::parse(&entry("000420de22", "capture")).is_err());
        assert!(SupportedList::parse(&entry("000420DE22", "guess")).is_err());
        let twice = format!(
            "{}{}",
            entry("000420DE22", "capture"),
            entry("000420DE22", "live")
        );
        assert!(SupportedList::parse(&twice).is_err());
    }

    #[test]
    fn test_application_ref_of_formats_the_prefix() {
        assert_eq!(application_ref_of("0002A0ED10"), "M-0002_A-A0ED-10");
        assert_eq!(application_ref_of("short"), "short");
    }
}
