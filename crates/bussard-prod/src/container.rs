//! The `.knxprod` container: a plain ZIP holding `knx_master.xml`, one or more
//! `M-XXXX/` manufacturer folders (each with `Hardware.xml`, `Catalog.xml`, and
//! the ApplicationProgram XML files), and — for files produced by ETS — RSA
//! signature entries that bussard simply ignores (they authenticate the file to
//! ETS; they are not access control and are irrelevant to reading).
//!
//! Unlike a `.knxproj`, a `.knxprod` is never password-protected, so this is a
//! straight ZIP reader. Big application-program entries (20+ MB) are read into a
//! single owned `String` and then handed to the streaming XML parser; we never
//! hold more than one entry's bytes at a time.

use std::fs::File;
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use crate::error::{ProdError, Result};

/// An opened `.knxprod` container.
pub struct Container {
    path: PathBuf,
    archive: ZipArchive<File>,
}

/// A manufacturer application-program entry located in the archive: the
/// manufacturer folder (`M-XXXX`) and the full entry name.
#[derive(Debug, Clone)]
pub struct AppEntry {
    /// The manufacturer id, e.g. `M-0004`.
    pub manufacturer: String,
    /// The application-program id, e.g. `M-0004_A-20D7-26-053C-O000A`.
    pub application_id: String,
    /// The full ZIP entry name, e.g. `M-0004/M-0004_A-20D7-26-053C-O000A.xml`.
    pub entry: String,
}

impl Container {
    /// Opens a `.knxprod` ZIP.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|source| ProdError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let archive = ZipArchive::new(file).map_err(|source| ProdError::Zip {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            archive,
        })
    }

    /// Lists every manufacturer folder id (`M-XXXX`) present in the archive.
    pub fn manufacturer_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .archive
            .file_names()
            .filter_map(|name| name.split_once('/').map(|(dir, _)| dir))
            .filter(|dir| is_manufacturer_dir(dir))
            .map(str::to_string)
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Lists all ApplicationProgram entries across every manufacturer folder,
    /// sorted by entry name for deterministic iteration.
    ///
    /// An ApplicationProgram file is `M-XXXX/M-XXXX_A-….xml`; this deliberately
    /// excludes `Hardware.xml`, `Catalog.xml`, `Baggages.xml` and signatures.
    pub fn application_entries(&self) -> Vec<AppEntry> {
        let mut entries: Vec<AppEntry> = self
            .archive
            .file_names()
            .filter_map(|name| {
                let (dir, file) = name.split_once('/')?;
                if !is_manufacturer_dir(dir) {
                    return None;
                }
                let stem = file.strip_suffix(".xml")?;
                // Application-program files are named `<M-XXXX>_A-…`; the id
                // therefore starts with the manufacturer id + `_A-`.
                if !stem.starts_with(&format!("{dir}_A-")) {
                    return None;
                }
                Some(AppEntry {
                    manufacturer: dir.to_string(),
                    application_id: stem.to_string(),
                    entry: name.to_string(),
                })
            })
            .collect();
        entries.sort_by(|a, b| a.entry.cmp(&b.entry));
        entries
    }

    /// Reads a manufacturer's `Hardware.xml`, or `None` if absent.
    pub fn hardware_xml(&mut self, manufacturer: &str) -> Result<Option<String>> {
        let entry = format!("{manufacturer}/Hardware.xml");
        Ok(self.read_entry_opt(&entry)?.map(strip_bom))
    }

    /// Reads the archive's top-level `knx_master.xml`, or `None` if absent.
    ///
    /// The master file carries the per-mask `Load` procedure templates a merged
    /// application splices into (`knx_master.xml` → [`crate::MasterTemplate`]). A
    /// self-contained `.knxprod` (or one produced without the master) has no such
    /// entry; `None` then leaves the flash on the single-object path.
    pub fn master_xml(&mut self) -> Result<Option<String>> {
        Ok(self.read_entry_opt("knx_master.xml")?.map(strip_bom))
    }

    /// Reads a named archive entry to a UTF-8 string (BOM stripped), erroring if
    /// the entry is absent.
    pub fn read_to_string(&mut self, entry: &str) -> Result<String> {
        match self.read_entry_opt(entry)? {
            Some(bytes) => Ok(strip_bom(bytes)),
            None => Err(ProdError::MissingEntry {
                path: self.path.clone(),
                entry: entry.to_string(),
            }),
        }
    }

    /// Reads a named entry as raw bytes, or `None` if absent. The decompressed
    /// size is capped (a zip-bomb guard); an oversized entry errors rather than
    /// exhausting memory.
    fn read_entry_opt(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(bussard_ets::read_entry_opt(&mut self.archive, name)?)
    }
}

/// Is `dir` a manufacturer folder id like `M-0004`?
fn is_manufacturer_dir(dir: &str) -> bool {
    dir.strip_prefix("M-")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Converts bytes to a `String`, dropping a leading UTF-8 BOM if present.
fn strip_bom(bytes: Vec<u8>) -> String {
    let s = String::from_utf8_lossy(&bytes).into_owned();
    s.strip_prefix('\u{feff}').map(str::to_string).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_manufacturer_dirs() {
        assert!(is_manufacturer_dir("M-0004"));
        assert!(is_manufacturer_dir("M-00FA"));
        assert!(!is_manufacturer_dir("M-"));
        assert!(!is_manufacturer_dir("knx_master"));
        assert!(!is_manufacturer_dir("P-05E7"));
    }
}
