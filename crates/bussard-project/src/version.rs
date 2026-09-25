//! ETS schema-version detection and the release family it maps to.
//!
//! Every ETS export declares its schema version as the trailing integer of the
//! project XML namespace on the root `KNX` element, e.g.
//! `http://knx.org/xml/project/21`. The version decides two things bussard
//! cares about: how the inner project archive is password-protected (see
//! [`crate::password`]) and how com-object group-address links are encoded in
//! `0.xml` (see [`crate::project`]).
//!
//! The version→release map (documented by ETS exports and the `xknxproject`
//! project's schema constants — reimplemented here from those format facts, not
//! copied):
//!
//! | schema version | ETS release          |
//! |----------------|----------------------|
//! | 11, 12         | ETS 4                |
//! | 13, 14         | ETS 5 (through 5.6)  |
//! | 20             | ETS 5.7              |
//! | 21, 22, 23     | ETS 6                |
//!
//! bussard treats the two decision boundaries by *range*, not by exact match,
//! so a future ETS 6 point release that bumps the trailing integer (e.g. 24) is
//! still handled as ETS 6 rather than rejected. A version below the earliest
//! known (< 11) or an unparseable namespace yields a clear diagnostic naming
//! what was found.

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::ImportError;

/// The lowest schema version bussard recognises (ETS 4.1/4.2).
const MIN_KNOWN_VERSION: u32 = 11;

/// The schema version at which the com-object `Links` attribute replaced the
/// `Connectors/Send`+`Receive` child elements (ETS 5.7).
const LINKS_ATTRIBUTE_VERSION: u32 = 20;

/// The schema version at which the ETS 6 WinZip-AES + PBKDF2 password scheme
/// replaced the ETS 4/5 traditional-ZipCrypto scheme.
const ETS6_VERSION: u32 = 21;

/// The ETS release family an export belongs to, derived from its schema version.
///
/// The family selects the password-derivation scheme and the com-object link
/// encoding; the exact integer is retained on [`SchemaVersion`] for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtsFamily {
    /// ETS 4 (schema 11–12): traditional ZipCrypto, `Connectors/Send`+`Receive`
    /// links, `Project.xml` (capital P) project-info filename.
    Ets4,
    /// ETS 5 up to 5.6 (schema 13–14): traditional ZipCrypto,
    /// `Connectors/Send`+`Receive` links, `project.xml` project-info filename.
    Ets5,
    /// ETS 5.7 (schema 20): traditional ZipCrypto, but the newer space-separated
    /// `Links` attribute for com-object links.
    Ets57,
    /// ETS 6 (schema ≥ 21): WinZip-AES with a PBKDF2-derived password, and the
    /// `Links` attribute for com-object links.
    Ets6,
}

/// A parsed, recognised ETS schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaVersion {
    /// The trailing integer of the project namespace (e.g. `21`).
    version: u32,
    /// The release family it maps to.
    family: EtsFamily,
}

impl SchemaVersion {
    /// Classifies a schema-version integer into its [`EtsFamily`], or errors if
    /// it is below the earliest version bussard knows how to read.
    ///
    /// Versions at or above [`ETS6_VERSION`] are all treated as ETS 6 (a future
    /// point release that bumps the integer stays supported rather than being
    /// rejected).
    pub fn from_version(version: u32) -> Result<Self, ImportError> {
        let family = match version {
            v if v < MIN_KNOWN_VERSION => {
                return Err(ImportError::UnsupportedSchemaVersion {
                    version: version.to_string(),
                });
            }
            11 | 12 => EtsFamily::Ets4,
            13 | 14 => EtsFamily::Ets5,
            v if v < LINKS_ATTRIBUTE_VERSION => EtsFamily::Ets5,
            v if v < ETS6_VERSION => EtsFamily::Ets57,
            _ => EtsFamily::Ets6,
        };
        Ok(Self { version, family })
    }

    /// Parses the schema version from a project XML namespace URI such as
    /// `http://knx.org/xml/project/21`.
    ///
    /// The version is the trailing path segment after the final `/`. A namespace
    /// that does not end in a `knx.org/xml/project/<int>` integer yields
    /// [`ImportError::UnsupportedSchemaVersion`] naming the offending URI.
    pub fn from_namespace(namespace: &str) -> Result<Self, ImportError> {
        let trailing = namespace.rsplit('/').next().unwrap_or(namespace);
        match trailing.parse::<u32>() {
            Ok(v) => Self::from_version(v),
            Err(_) => Err(ImportError::UnsupportedSchemaVersion {
                version: namespace.to_string(),
            }),
        }
    }

    /// The raw schema-version integer.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The release family this version maps to.
    pub fn family(&self) -> EtsFamily {
        self.family
    }

    /// Whether com-object group-address links are encoded as the newer
    /// space-separated `Links` attribute (ETS 5.7 and ETS 6) rather than the
    /// older `Connectors/Send`+`Receive` child elements (ETS 4 and ETS 5≤5.6).
    pub fn uses_links_attribute(&self) -> bool {
        self.version >= LINKS_ATTRIBUTE_VERSION
    }

    /// Whether the inner project archive is protected with the ETS 6 scheme
    /// (WinZip-AES + PBKDF2-derived password) rather than the ETS 4/5 scheme
    /// (traditional ZipCrypto with the raw password).
    pub fn uses_ets6_encryption(&self) -> bool {
        self.version >= ETS6_VERSION
    }

    /// The project-info filename ETS writes: `Project.xml` (capital P) for ETS 4,
    /// `project.xml` (lowercase) for ETS 5 and ETS 6.
    pub fn project_info_filename(&self) -> &'static str {
        match self.family {
            EtsFamily::Ets4 => "Project.xml",
            _ => "project.xml",
        }
    }
}

impl Default for SchemaVersion {
    /// Absent a namespace to detect from, assume ETS 6 (the format bussard has
    /// always read). This is the fallback when `knx_master.xml` cannot be parsed.
    fn default() -> Self {
        Self {
            version: ETS6_VERSION,
            family: EtsFamily::Ets6,
        }
    }
}

/// How much of `knx_master.xml` is scanned for the root element's namespace.
///
/// The root `<KNX>` element is the first element in the document, so a generous
/// 64 KiB window always contains it (leading comments, processing instructions
/// and a DOCTYPE included) while keeping the scan bounded for a huge file.
const MAX_HEADER_SCAN: usize = 64 * 1024;

/// Extracts the schema version from a `knx_master.xml` document by finding the
/// `xmlns` (default namespace) on the root `KNX` element.
///
/// The root element is read with quick-xml from the head of the document, so the
/// namespace is found wherever the exporter put it: ETS 4.1 writes it on the
/// first line, newer versions on the second, and pretty-printed or
/// comment-prefixed exports push it further down still. (This used to look at
/// the first four *lines* only, so anything below silently fell through to the
/// ETS 6 default — the wrong password scheme and the wrong link encoding for an
/// ETS 4/5 file, surfacing as `WrongPassword` or zero links.)
///
/// Returns:
/// * `Ok(Some(version))` when a recognised `knx.org/xml/project/<int>` namespace
///   is found;
/// * `Ok(None)` when no such namespace is present at all — an unusual but
///   tolerated case (e.g. a stripped-down fixture), logged as a warning, where
///   the caller falls back to the ETS 6 default rather than refusing the whole
///   import;
/// * `Err(UnsupportedSchemaVersion)` when a namespace *is* present but names a
///   version below the earliest bussard reads (< 11), so the user gets a clear
///   diagnostic instead of a silent mis-parse.
pub fn detect_schema_version(knx_master_xml: &str) -> Result<Option<SchemaVersion>, ImportError> {
    let head = header(knx_master_xml);
    match root_project_namespace(head) {
        Some(ns) => SchemaVersion::from_namespace(&ns).map(Some),
        None => {
            tracing::warn!(
                "knx_master.xml declares no http://knx.org/xml/project/<version> namespace; \
                 assuming ETS 6 (schema {}). If this is an ETS 4/5 export the password scheme \
                 and com-object link encoding will be wrong.",
                SchemaVersion::default().version()
            );
            Ok(None)
        }
    }
}

/// The leading [`MAX_HEADER_SCAN`] bytes of `xml`, trimmed back to a character
/// boundary so the slice is always valid UTF-8.
fn header(xml: &str) -> &str {
    let mut cap = MAX_HEADER_SCAN.min(xml.len());
    while !xml.is_char_boundary(cap) {
        cap -= 1;
    }
    &xml[..cap]
}

/// Finds the project namespace on the first element of `head`.
///
/// Uses quick-xml so an `xmlns` spread across lines, re-ordered among other
/// attributes, or preceded by comments is still found. If the (possibly
/// truncated) head cannot be parsed as far as the first element, falls back to a
/// plain text scan for an `xmlns="…knx.org/xml/project/…"` attribute.
fn root_project_namespace(head: &str) -> Option<String> {
    let mut reader = Reader::from_str(head);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                for a in e.attributes().flatten() {
                    if a.key.as_ref() != b"xmlns" {
                        continue;
                    }
                    let value = String::from_utf8_lossy(&a.value).into_owned();
                    if value.contains(PROJECT_NAMESPACE_PREFIX) {
                        return Some(value);
                    }
                }
                // The root element carried no project namespace; nothing below
                // it can be the root, so stop.
                return None;
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    // Truncated or malformed head: fall back to a raw scan.
    text_scan_xmlns(head)
}

/// The marker that identifies a project namespace among any other `xmlns`.
const PROJECT_NAMESPACE_PREFIX: &str = "knx.org/xml/project/";

/// Scans raw text for the first `xmlns="…knx.org/xml/project/…"` value.
fn text_scan_xmlns(head: &str) -> Option<String> {
    let mut rest = head;
    while let Some(start) = rest.find("xmlns=\"") {
        let after = &rest[start + "xmlns=\"".len()..];
        let end = after.find('"')?;
        let value = &after[..end];
        if value.contains(PROJECT_NAMESPACE_PREFIX) {
            return Some(value.to_string());
        }
        rest = &after[end..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_version_maps_families() -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert_eq!(SchemaVersion::from_version(11)?.family(), EtsFamily::Ets4);
        assert_eq!(SchemaVersion::from_version(12)?.family(), EtsFamily::Ets4);
        assert_eq!(SchemaVersion::from_version(13)?.family(), EtsFamily::Ets5);
        assert_eq!(SchemaVersion::from_version(14)?.family(), EtsFamily::Ets5);
        assert_eq!(SchemaVersion::from_version(20)?.family(), EtsFamily::Ets57);
        assert_eq!(SchemaVersion::from_version(21)?.family(), EtsFamily::Ets6);
        assert_eq!(SchemaVersion::from_version(23)?.family(), EtsFamily::Ets6);
        // Future ETS 6 bump stays ETS 6.
        assert_eq!(SchemaVersion::from_version(30)?.family(), EtsFamily::Ets6);
        Ok(())
    }

    #[test]
    fn test_from_version_rejects_below_floor() {
        assert!(SchemaVersion::from_version(10).is_err());
        assert!(SchemaVersion::from_version(0).is_err());
    }

    #[test]
    fn test_encryption_and_link_forks() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let ets4 = SchemaVersion::from_version(11)?;
        assert!(!ets4.uses_ets6_encryption());
        assert!(!ets4.uses_links_attribute());
        assert_eq!(ets4.project_info_filename(), "Project.xml");

        let ets5 = SchemaVersion::from_version(14)?;
        assert!(!ets5.uses_ets6_encryption());
        assert!(!ets5.uses_links_attribute());
        assert_eq!(ets5.project_info_filename(), "project.xml");

        let ets57 = SchemaVersion::from_version(20)?;
        assert!(!ets57.uses_ets6_encryption());
        assert!(ets57.uses_links_attribute());

        let ets6 = SchemaVersion::from_version(21)?;
        assert!(ets6.uses_ets6_encryption());
        assert!(ets6.uses_links_attribute());
        assert_eq!(ets6.project_info_filename(), "project.xml");
        Ok(())
    }

    #[test]
    fn test_from_namespace_parses_trailing_integer()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            SchemaVersion::from_namespace("http://knx.org/xml/project/21")?.version(),
            21
        );
        assert_eq!(
            SchemaVersion::from_namespace("http://knx.org/xml/project/11")?.family(),
            EtsFamily::Ets4
        );
        assert!(SchemaVersion::from_namespace("http://knx.org/xml/project/junk").is_err());
        Ok(())
    }

    #[test]
    fn test_detect_schema_version_from_master()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let ets6 = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/21"><MasterData/></KNX>"#;
        let v = detect_schema_version(ets6)?.ok_or("version present")?;
        assert_eq!(v.version(), 21);
        assert_eq!(v.family(), EtsFamily::Ets6);

        // ETS 4.1 style: xmlns on the very first line.
        let ets4 = r#"<KNX xmlns="http://knx.org/xml/project/11"><MasterData/></KNX>"#;
        let v = detect_schema_version(ets4)?.ok_or("version present")?;
        assert_eq!(v.family(), EtsFamily::Ets4);
        Ok(())
    }

    /// Regression: the scan read only the first four lines, so a namespace on
    /// line 5+ (pretty-printed, comment-prefixed, or attribute-per-line exports)
    /// went undetected and the import silently used the ETS 6 password scheme
    /// and link encoding for an ETS 4/5 file.
    #[test]
    fn test_detect_schema_version_scans_past_the_first_lines()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let padded = format!(
            "{}\n<KNX xmlns=\"http://knx.org/xml/project/14\"><MasterData/></KNX>",
            "<!-- an exporter comment line -->\n".repeat(12)
        );
        let v = detect_schema_version(&padded)?
            .ok_or("the namespace is found however far down it sits")?;
        assert_eq!(v.version(), 14);
        assert_eq!(v.family(), EtsFamily::Ets5);

        // An attribute-per-line root element: the xmlns is not even on the same
        // line as the element name.
        let split = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    CreatedBy="ETS5"
    ToolVersion="5.7.1234"
    xmlns="http://knx.org/xml/project/20">
  <MasterData/>
</KNX>"#;
        let v =
            detect_schema_version(split)?.ok_or("the namespace is found among other attributes")?;
        assert_eq!(v.version(), 20);
        assert_eq!(v.family(), EtsFamily::Ets57);
        Ok(())
    }

    /// A truncated head (the root element runs past the scan window, or the
    /// document is malformed) still yields the namespace through the text-scan
    /// fallback.
    #[test]
    fn test_detect_schema_version_survives_a_malformed_header()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let truncated = r#"<KNX xmlns="http://knx.org/xml/project/11" Unclosed="#;
        let v = detect_schema_version(truncated)?.ok_or("found by the text-scan fallback")?;
        assert_eq!(v.family(), EtsFamily::Ets4);
        Ok(())
    }

    #[test]
    fn test_detect_schema_version_missing_namespace_is_tolerated()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // No project namespace at all: tolerated as `None` (caller defaults to
        // ETS 6), not an error, so stripped-down archives still import.
        let no_ns = r#"<?xml version="1.0"?><KNX><MasterData/></KNX>"#;
        assert_eq!(detect_schema_version(no_ns)?, None);

        // But a *present* namespace with an unsupported (too-low) version errors.
        let too_low = r#"<KNX xmlns="http://knx.org/xml/project/9"><MasterData/></KNX>"#;
        assert!(detect_schema_version(too_low).is_err());
        Ok(())
    }
}
