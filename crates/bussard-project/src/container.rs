//! The ETS 6 `.knxproj` container: a ZIP holding `knx_master.xml`, a
//! (possibly password-protected) inner project archive, and manufacturer
//! folders with application-program XML.
//!
//! This module hides the on-disk layout behind lookups the rest of the crate
//! needs: the project `0.xml`, `knx_master.xml`, and a manufacturer
//! application-program file by its id.

use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use crate::error::{ImportError, Result};
use crate::password::archive_password;
use crate::version::{SchemaVersion, detect_schema_version};

/// An opened `.knxproj` container.
pub struct Container {
    path: PathBuf,
    archive: ZipArchive<File>,
    /// The decrypted (or plain) project `0.xml`, held in memory.
    project_xml: String,
    /// The decrypted (or plain) `project.xml`, if present. It carries the
    /// project name and group-address style; `0.xml` does not.
    project_info_xml: Option<String>,
    /// The detected ETS schema version, which selects the com-object link
    /// encoding downstream in [`crate::project`].
    schema: SchemaVersion,
}

impl Container {
    /// Opens a `.knxproj`, locating and decrypting the inner project as needed.
    ///
    /// `password` is the user's project password; it is only consulted if the
    /// inner project archive is encrypted.
    pub fn open(path: &Path, password: Option<&str>) -> Result<Self> {
        let file = File::open(path).map_err(|source| ImportError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut archive = ZipArchive::new(file).map_err(|source| ImportError::Zip {
            path: path.to_path_buf(),
            source,
        })?;

        // Detect the ETS schema version from `knx_master.xml` (always in the
        // unencrypted outer archive). This selects the password scheme for the
        // inner archive and the com-object link encoding. If it can't be read,
        // fall back to the ETS 6 assumption bussard has always used.
        let schema = match read_entry_opt(&mut archive, "knx_master.xml")? {
            // `detect_schema_version` warns when it finds no namespace at all.
            Some(bytes) => detect_schema_version(&strip_bom(bytes))?.unwrap_or_default(),
            None => {
                tracing::warn!(
                    path = %path.display(),
                    "the .knxproj has no knx_master.xml; assuming an ETS 6 export (schema {})",
                    SchemaVersion::default().version()
                );
                SchemaVersion::default()
            }
        };

        let project_id = find_project_id(&archive, path)?;
        let project_xml = read_inner_project_entry(
            &mut archive,
            &project_id,
            password,
            path,
            &["0.xml"],
            schema,
            true,
        )?
        .ok_or(ImportError::MissingEntry {
            path: path.to_path_buf(),
            entry: "0.xml".to_string(),
        })?;
        // `project.xml` carries the name and group-address style. ETS 4 names it
        // `Project.xml` (capital P); ETS 5/6 use lowercase. Try the version's
        // preferred name first, then the other casing as a fallback. Older/leaner
        // exports may omit it, so its absence is tolerated (None), not an error.
        let info_names: &[&str] = if schema.project_info_filename() == "Project.xml" {
            &["Project.xml", "project.xml"]
        } else {
            &["project.xml", "Project.xml"]
        };
        let project_info_xml = read_inner_project_entry(
            &mut archive,
            &project_id,
            password,
            path,
            info_names,
            schema,
            false,
        )?;

        Ok(Self {
            path: path.to_path_buf(),
            archive,
            project_xml,
            project_info_xml,
            schema,
        })
    }

    /// The detected ETS schema version of this project.
    pub fn schema(&self) -> SchemaVersion {
        self.schema
    }

    /// The project `0.xml` contents.
    pub fn project_xml(&self) -> &str {
        &self.project_xml
    }

    /// The `project.xml` contents, if the archive contained it.
    pub fn project_info_xml(&self) -> Option<&str> {
        self.project_info_xml.as_deref()
    }

    /// Reads `knx_master.xml` from the outer archive.
    pub fn knx_master_xml(&mut self) -> Result<String> {
        read_entry_to_string(&mut self.archive, "knx_master.xml", &self.path)
    }

    /// Reads a named entry from the outer archive as a UTF-8 string, returning
    /// `None` if it is absent.
    pub fn raw_entry(&mut self, name: &str) -> Result<Option<String>> {
        Ok(read_entry_opt(&mut self.archive, name)?.map(strip_bom))
    }

    /// Reads a manufacturer application-program file by its id, e.g.
    /// `M-0004_A-7066-11-7A9E-O000A`, returning its raw (inflated, BOM-stripped)
    /// XML bytes.
    ///
    /// The file lives at `M-XXXX/<id>.xml` where `M-XXXX` is the leading
    /// manufacturer segment of the id.
    ///
    /// The import path reads every referenced entry serially from the shared
    /// archive (inflate is a small fraction of the cost) and hands the bytes to
    /// [`bussard_ets::parse_application_program`], which reads UTF-8 event by
    /// event and so needs no eager whole-file `String` validation.
    pub fn application_raw(&mut self, application_id: &str, device: &str) -> Result<Vec<u8>> {
        let manufacturer = application_id.split('_').next().unwrap_or(application_id);
        let entry = format!("{manufacturer}/{application_id}.xml");
        match read_entry_opt(&mut self.archive, &entry)? {
            Some(bytes) => Ok(strip_bom_bytes(bytes)),
            None => Err(ImportError::MissingApplication {
                application: application_id.to_string(),
                device: device.to_string(),
            }),
        }
    }
}

/// Drops a leading UTF-8 BOM from raw bytes, if present.
fn strip_bom_bytes(bytes: Vec<u8>) -> Vec<u8> {
    match bytes.strip_prefix(b"\xEF\xBB\xBF") {
        Some(rest) => rest.to_vec(),
        None => bytes,
    }
}

/// Finds the project folder id (`P-XXXX`) by looking for a `P-XXXX.zip`,
/// `P-XXXX/0.xml`, or `P-XXXX/project.xml` entry.
fn find_project_id<R: Read + Seek>(archive: &ZipArchive<R>, path: &Path) -> Result<String> {
    for name in archive.file_names() {
        // Inner encrypted archive form: `P-XXXX.zip`.
        if let Some(stem) = name.strip_suffix(".zip") {
            if stem.starts_with("P-") && !stem.contains('/') {
                return Ok(stem.to_string());
            }
        }
    }
    // Unencrypted form: `P-XXXX/0.xml` (or `project.xml`/`Project.xml` for ETS 4).
    for name in archive.file_names() {
        for suffix in ["/0.xml", "/project.xml", "/Project.xml"] {
            if let Some(prefix) = name.strip_suffix(suffix) {
                if prefix.starts_with("P-") {
                    return Ok(prefix.to_string());
                }
            }
        }
    }
    Err(ImportError::MissingEntry {
        path: path.to_path_buf(),
        entry: "P-XXXX.zip or P-XXXX/0.xml".to_string(),
    })
}

/// Reads a project entry (e.g. `0.xml`, or `project.xml`/`Project.xml`),
/// decrypting the inner archive if it is stored as `P-XXXX.zip`.
///
/// `entries` lists acceptable filenames in preference order (used to try both
/// `project.xml` casings across ETS versions); the first one found is returned.
/// `schema` selects the archive-password scheme (ETS 6 PBKDF2 vs ETS 4/5 raw).
///
/// `required` controls the "not found" behaviour: a required entry that is
/// absent is an [`ImportError::MissingEntry`]; an optional one returns `None`.
/// Note that if the whole project is delivered *encrypted* and no password is
/// supplied, this errors [`ImportError::PasswordRequired`] even for optional
/// entries (the inner archive cannot be opened at all).
fn read_inner_project_entry(
    archive: &mut ZipArchive<File>,
    project_id: &str,
    password: Option<&str>,
    path: &Path,
    entries: &[&str],
    schema: SchemaVersion,
    required: bool,
) -> Result<Option<String>> {
    // Case 1: unencrypted `P-XXXX/<entry>` directly in the outer archive.
    for entry in entries {
        let direct = format!("{project_id}/{entry}");
        if let Some(bytes) = read_entry_opt(archive, &direct)? {
            return Ok(Some(strip_bom(bytes)));
        }
    }

    // Case 2: inner archive `P-XXXX.zip`, possibly password-protected.
    let inner_name = format!("{project_id}.zip");
    let inner_bytes = match read_entry_opt(archive, &inner_name)? {
        Some(b) => b,
        None => {
            // No inner archive and no direct entry: the entry is simply absent.
            return missing_entry(required, path, entries[0]);
        }
    };

    let cursor = std::io::Cursor::new(inner_bytes);
    let mut inner = ZipArchive::new(cursor).map_err(|source| ImportError::Zip {
        path: PathBuf::from(&inner_name),
        source,
    })?;

    // Determine the index of the first acceptable entry inside the inner archive.
    let found = (0..inner.len()).find_map(|i| {
        let name = inner.by_index_raw(i).ok().map(|f| f.name().to_string())?;
        entries.iter().any(|e| *e == name).then_some((i, name))
    });
    let (idx, entry) = match found {
        Some(v) => v,
        None => return missing_entry(required, &PathBuf::from(&inner_name), entries[0]),
    };

    // Is the inner entry encrypted?
    let encrypted = inner
        .by_index_raw(idx)
        .map(|f| f.encrypted())
        .unwrap_or(false);

    let bytes = if encrypted {
        let pw = password.ok_or(ImportError::PasswordRequired)?;
        // ETS 6 derives a WinZip-AES password; ETS 4/5 use the raw password with
        // traditional ZipCrypto. `by_index_decrypt` handles both cipher kinds.
        let zip_pw = archive_password(pw, schema);
        let file = inner
            .by_index_decrypt(idx, &zip_pw)
            .map_err(|_| ImportError::WrongPassword)?;
        // Cap the decrypted stream too: a hostile inner archive is untrusted.
        // The cap being hit is a zip-bomb signal, not a bad password, so it
        // propagates as itself; anything else is a read failure on an entry the
        // cipher already accepted (see `ImportError::DecryptedEntry`).
        bussard_ets::read_capped(file, &entry)
            .map_err(|source| decrypted_read_error(&entry, source))?
    } else {
        let file = inner.by_index(idx).map_err(|source| ImportError::Zip {
            path: PathBuf::from(&inner_name),
            source,
        })?;
        bussard_ets::read_capped(file, &entry)?
    };

    Ok(Some(strip_bom(bytes)))
}

/// Classifies a failure to read an entry out of the *decrypted* inner project
/// archive.
///
/// The cipher has already accepted the password by this point, so blaming the
/// password for everything hid two unrelated failures: the zip-bomb cap
/// ([`bussard_ets::EtsError::EntryTooLarge`]) and plain I/O errors both used to
/// surface as "wrong password". The cap propagates as itself; anything else
/// becomes [`ImportError::DecryptedEntry`], whose message still explains that an
/// ETS 4/5 (traditional ZipCrypto) export fails this way on a wrong password
/// because that cipher has no authentication tag.
fn decrypted_read_error(entry: &str, source: bussard_ets::EtsError) -> ImportError {
    match source {
        e @ bussard_ets::EtsError::EntryTooLarge { .. } => ImportError::Ets(e),
        source => ImportError::DecryptedEntry {
            entry: entry.to_string(),
            source: Box::new(source),
        },
    }
}

/// Helper: turn a missing entry into an error (if required) or `None`.
fn missing_entry(required: bool, path: &Path, entry: &str) -> Result<Option<String>> {
    if required {
        Err(ImportError::MissingEntry {
            path: path.to_path_buf(),
            entry: entry.to_string(),
        })
    } else {
        Ok(None)
    }
}

/// Reads a named entry from an archive as raw bytes (capped, a zip-bomb guard),
/// or `None` if absent.
fn read_entry_opt<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    Ok(bussard_ets::read_entry_opt(archive, name)?)
}

/// Reads a named entry as a UTF-8 string, erroring if absent.
fn read_entry_to_string<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    path: &Path,
) -> Result<String> {
    match read_entry_opt(archive, name)? {
        Some(bytes) => Ok(strip_bom(bytes)),
        None => Err(ImportError::MissingEntry {
            path: path.to_path_buf(),
            entry: name.to_string(),
        }),
    }
}

/// Converts bytes to a `String`, dropping a leading UTF-8 BOM if present.
fn strip_bom(bytes: Vec<u8>) -> String {
    bussard_ets::strip_bom(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: `EntryTooLarge` (the zip-bomb cap) and I/O errors on the
    /// decrypted inner entry were both reported as `WrongPassword`, so a hostile
    /// archive and a broken file both read as "you typed the wrong password".
    #[test]
    fn test_decrypted_read_error_keeps_the_cap_and_io_apart() {
        let too_large = bussard_ets::EtsError::EntryTooLarge {
            entry: "0.xml".to_string(),
            cap: 1024,
        };
        assert!(
            matches!(
                decrypted_read_error("0.xml", too_large),
                ImportError::Ets(bussard_ets::EtsError::EntryTooLarge { .. })
            ),
            "the decompression cap is a zip-bomb signal, not a bad password"
        );

        let io = bussard_ets::EtsError::Io {
            entry: "0.xml".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "crc mismatch"),
        };
        match decrypted_read_error("0.xml", io) {
            ImportError::DecryptedEntry { entry, source } => {
                assert_eq!(entry, "0.xml");
                assert!(source.to_string().contains("crc mismatch"), "{source}");
            }
            other => panic!("expected DecryptedEntry, got {other:?}"),
        }
    }
}
