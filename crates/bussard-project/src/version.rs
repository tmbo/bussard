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

/// Extracts the schema version from a `knx_master.xml` document by finding the
/// `xmlns` (default namespace) on the root `KNX` element.
///
/// ETS 4.1 puts the namespace on the first line; newer versions on the second.
/// This scans for the first `xmlns="…knx.org/xml/project/N…"` in the document
/// header without a full parse.
///
/// Returns:
/// * `Ok(Some(version))` when a recognised `knx.org/xml/project/<int>` namespace
///   is found;
/// * `Ok(None)` when no such namespace is present at all — an unusual but
///   tolerated case (e.g. a stripped-down fixture), where the caller falls back
///   to the ETS 6 default rather than refusing the whole import;
/// * `Err(UnsupportedSchemaVersion)` when a namespace *is* present but names a
///   version below the earliest bussard reads (< 11), so the user gets a clear
///   diagnostic instead of a silent mis-parse.
pub fn detect_schema_version(
    knx_master_xml: &str,
) -> Result<Option<SchemaVersion>, ImportError> {
    // Look at the document head only; the root element and its xmlns are always
    // near the top. Scanning line by line avoids depending on a specific parser.
    for line in knx_master_xml.lines().take(4) {
        if let Some(ns) = extract_xmlns(line) {
            if ns.contains("knx.org/xml/project/") {
                return SchemaVersion::from_namespace(ns).map(Some);
            }
        }
    }
    // No project namespace at all: tolerate and let the caller default.
    Ok(None)
}

/// Returns the value of the first `xmlns="…"` attribute in a line, if any.
fn extract_xmlns(line: &str) -> Option<&str> {
    let start = line.find("xmlns=\"")? + "xmlns=\"".len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_version_maps_families() {
        assert_eq!(
            SchemaVersion::from_version(11).unwrap().family(),
            EtsFamily::Ets4
        );
        assert_eq!(
            SchemaVersion::from_version(12).unwrap().family(),
            EtsFamily::Ets4
        );
        assert_eq!(
            SchemaVersion::from_version(13).unwrap().family(),
            EtsFamily::Ets5
        );
        assert_eq!(
            SchemaVersion::from_version(14).unwrap().family(),
            EtsFamily::Ets5
        );
        assert_eq!(
            SchemaVersion::from_version(20).unwrap().family(),
            EtsFamily::Ets57
        );
        assert_eq!(
            SchemaVersion::from_version(21).unwrap().family(),
            EtsFamily::Ets6
        );
        assert_eq!(
            SchemaVersion::from_version(23).unwrap().family(),
            EtsFamily::Ets6
        );
        // Future ETS 6 bump stays ETS 6.
        assert_eq!(
            SchemaVersion::from_version(30).unwrap().family(),
            EtsFamily::Ets6
        );
    }

    #[test]
    fn test_from_version_rejects_below_floor() {
        assert!(SchemaVersion::from_version(10).is_err());
        assert!(SchemaVersion::from_version(0).is_err());
    }

    #[test]
    fn test_encryption_and_link_forks() {
        let ets4 = SchemaVersion::from_version(11).unwrap();
        assert!(!ets4.uses_ets6_encryption());
        assert!(!ets4.uses_links_attribute());
        assert_eq!(ets4.project_info_filename(), "Project.xml");

        let ets5 = SchemaVersion::from_version(14).unwrap();
        assert!(!ets5.uses_ets6_encryption());
        assert!(!ets5.uses_links_attribute());
        assert_eq!(ets5.project_info_filename(), "project.xml");

        let ets57 = SchemaVersion::from_version(20).unwrap();
        assert!(!ets57.uses_ets6_encryption());
        assert!(ets57.uses_links_attribute());

        let ets6 = SchemaVersion::from_version(21).unwrap();
        assert!(ets6.uses_ets6_encryption());
        assert!(ets6.uses_links_attribute());
        assert_eq!(ets6.project_info_filename(), "project.xml");
    }

    #[test]
    fn test_from_namespace_parses_trailing_integer() {
        assert_eq!(
            SchemaVersion::from_namespace("http://knx.org/xml/project/21")
                .unwrap()
                .version(),
            21
        );
        assert_eq!(
            SchemaVersion::from_namespace("http://knx.org/xml/project/11")
                .unwrap()
                .family(),
            EtsFamily::Ets4
        );
        assert!(SchemaVersion::from_namespace("http://knx.org/xml/project/junk").is_err());
    }

    #[test]
    fn test_detect_schema_version_from_master() {
        let ets6 = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/21"><MasterData/></KNX>"#;
        let v = detect_schema_version(ets6).unwrap().expect("version present");
        assert_eq!(v.version(), 21);
        assert_eq!(v.family(), EtsFamily::Ets6);

        // ETS 4.1 style: xmlns on the very first line.
        let ets4 = r#"<KNX xmlns="http://knx.org/xml/project/11"><MasterData/></KNX>"#;
        let v = detect_schema_version(ets4).unwrap().expect("version present");
        assert_eq!(v.family(), EtsFamily::Ets4);
    }

    #[test]
    fn test_detect_schema_version_missing_namespace_is_tolerated() {
        // No project namespace at all: tolerated as `None` (caller defaults to
        // ETS 6), not an error, so stripped-down archives still import.
        let no_ns = r#"<?xml version="1.0"?><KNX><MasterData/></KNX>"#;
        assert_eq!(detect_schema_version(no_ns).unwrap(), None);

        // But a *present* namespace with an unsupported (too-low) version errors.
        let too_low = r#"<KNX xmlns="http://knx.org/xml/project/9"><MasterData/></KNX>"#;
        assert!(detect_schema_version(too_low).is_err());
    }
}
