//! The manufacturer names of the imported ETS master data (issue #788).
//!
//! Every `.knxproj` and `.knxprod` carries ETS's full manufacturer list in its
//! `knx_master.xml`. `import` and `import-product` keep that list next to the
//! product archives, in `products/manufacturers.toml`, so a device on the bus
//! is named by the list the owner's own ETS data provides:
//!
//! ```toml
//! [manufacturers]
//! M-0004 = "Albrecht Jung"
//! ```
//!
//! Each import merges its list into the file; an id it names again takes the
//! newer name.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file's name inside the product store `products/`.
pub const MANUFACTURERS_FILE: &str = "manufacturers.toml";

/// The product store directory under a model directory.
const PRODUCTS_DIR: &str = "products";

/// The header comment of the file.
const HEADER: &str = "# Manufacturer names from the knx_master.xml of the imported ETS data.\n\
# Written by `bussard import` and `bussard import-product`.\n\n";

/// The file's content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamesFile {
    /// ETS manufacturer reference (`M-0004`) to name.
    #[serde(default)]
    manufacturers: BTreeMap<String, String>,
}

/// Why the file could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum ManufacturerNamesError {
    /// Reading or writing the file failed.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The file is not a valid manufacturer list.
    #[error("{path}: {source}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// The TOML error.
        source: toml::de::Error,
    },
    /// The list did not serialize.
    #[error("serializing {path}: {source}")]
    Serialize {
        /// The file.
        path: PathBuf,
        /// The TOML error.
        source: toml::ser::Error,
    },
}

/// The manufacturer list of the model in `dir`.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(PRODUCTS_DIR).join(MANUFACTURERS_FILE)
}

/// Parses an ETS manufacturer reference (`M-0004`) to its numeric id.
pub fn parse_ref(reference: &str) -> Option<u16> {
    let hex = reference.strip_prefix("M-")?;
    if hex.len() != 4 {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

/// Reads the manufacturer list of the model in `dir`, by numeric id; empty
/// when there is none. Entries whose key is not an `M-XXXX` reference are
/// skipped.
///
/// # Errors
///
/// The file exists but does not read or parse.
pub fn load(dir: &Path) -> Result<BTreeMap<u16, String>, ManufacturerNamesError> {
    Ok(by_id(&load_file(dir)?))
}

/// Merges `names` (ETS reference to name, as `knx_master.xml` lists them) into
/// the list of the model in `dir`, writes it when it changed, and returns the
/// merged list by numeric id. An id already listed takes the name in `names`.
///
/// # Errors
///
/// The existing file does not read or parse, or the merged one does not write.
pub fn merge<I, K, V>(dir: &Path, names: I) -> Result<BTreeMap<u16, String>, ManufacturerNamesError>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let path = path(dir);
    let before = load_file(dir)?;
    let mut merged = before.clone();
    for (reference, name) in names {
        let reference = reference.into();
        if parse_ref(&reference).is_some() {
            merged.manufacturers.insert(reference, name.into());
        }
    }
    if merged != before {
        let body =
            toml::to_string(&merged).map_err(|source| ManufacturerNamesError::Serialize {
                path: path.clone(),
                source,
            })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ManufacturerNamesError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        std::fs::write(&path, format!("{HEADER}{body}"))
            .map_err(|source| ManufacturerNamesError::Io { path, source })?;
    }
    Ok(by_id(&merged))
}

/// Reads the file; the empty list when it does not exist.
fn load_file(dir: &Path) -> Result<NamesFile, ManufacturerNamesError> {
    let path = path(dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(NamesFile::default()),
        Err(source) => return Err(ManufacturerNamesError::Io { path, source }),
    };
    toml::from_str(&text).map_err(|source| ManufacturerNamesError::Parse { path, source })
}

/// The list keyed by numeric id.
fn by_id(file: &NamesFile) -> BTreeMap<u16, String> {
    file.manufacturers
        .iter()
        .filter_map(|(reference, name)| Some((parse_ref(reference)?, name.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn tempdir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-manufacturer-names-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn test_parse_ref_accepts_ets_references() {
        assert_eq!(parse_ref("M-0004"), Some(0x0004));
        assert_eq!(parse_ref("M-00FA"), Some(0x00FA));
        assert_eq!(parse_ref("M-04"), None);
        assert_eq!(parse_ref("0004"), None);
        assert_eq!(parse_ref("M-XYZW"), None);
    }

    #[test]
    fn test_load_missing_file_is_empty() -> TestResult {
        let dir = tempdir("missing")?;
        assert!(load(&dir)?.is_empty());
        Ok(())
    }

    #[test]
    fn test_merge_writes_and_updates() -> TestResult {
        let dir = tempdir("merge")?;
        let merged = merge(
            &dir,
            [("M-0004", "Albrecht Jung"), ("M-0048", "Example Maker")],
        )?;
        assert_eq!(
            merged.get(&0x0048).map(String::as_str),
            Some("Example Maker")
        );
        let text = std::fs::read_to_string(path(&dir))?;
        assert!(text.contains("M-0004 = \"Albrecht Jung\""), "{text}");

        let merged = merge(&dir, [("M-0048", "Example Maker GmbH"), ("bad", "x")])?;
        assert_eq!(merged.len(), 2);
        assert_eq!(
            load(&dir)?.get(&0x0048).map(String::as_str),
            Some("Example Maker GmbH")
        );
        Ok(())
    }
}
