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
use crate::password::derive_zip_password;

/// An opened `.knxproj` container.
pub struct Container {
    path: PathBuf,
    archive: ZipArchive<File>,
    /// The decrypted (or plain) project `0.xml`, held in memory.
    project_xml: String,
    /// The decrypted (or plain) `project.xml`, if present. It carries the
    /// project name and group-address style; `0.xml` does not.
    project_info_xml: Option<String>,
    /// The id of the project folder, e.g. `P-05E7`.
    #[allow(dead_code)]
    project_id: String,
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

        let project_id = find_project_id(&archive, path)?;
        let project_xml =
            read_inner_project_entry(&mut archive, &project_id, password, path, "0.xml", true)?
                .ok_or(ImportError::MissingEntry {
                    path: path.to_path_buf(),
                    entry: "0.xml".to_string(),
                })?;
        // `project.xml` carries the name and group-address style. Older/leaner
        // exports may omit it, so its absence is tolerated (None), not an error.
        let project_info_xml = read_inner_project_entry(
            &mut archive,
            &project_id,
            password,
            path,
            "project.xml",
            false,
        )?;

        Ok(Self {
            path: path.to_path_buf(),
            archive,
            project_xml,
            project_info_xml,
            project_id,
        })
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
    // Unencrypted form: `P-XXXX/0.xml`.
    for name in archive.file_names() {
        if let Some(prefix) = name.strip_suffix("/0.xml") {
            if prefix.starts_with("P-") {
                return Ok(prefix.to_string());
            }
        }
        if let Some(prefix) = name.strip_suffix("/project.xml") {
            if prefix.starts_with("P-") {
                return Ok(prefix.to_string());
            }
        }
    }
    Err(ImportError::MissingEntry {
        path: path.to_path_buf(),
        entry: "P-XXXX.zip or P-XXXX/0.xml".to_string(),
    })
}

/// Reads a named project entry (`0.xml` or `project.xml`), decrypting the inner
/// archive if it is stored as `P-XXXX.zip`.
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
    entry: &str,
    required: bool,
) -> Result<Option<String>> {
    // Case 1: unencrypted `P-XXXX/<entry>` directly in the outer archive.
    let direct = format!("{project_id}/{entry}");
    if let Some(bytes) = read_entry_opt(archive, &direct)? {
        return Ok(Some(strip_bom(bytes)));
    }

    // Case 2: inner archive `P-XXXX.zip`, possibly password-protected.
    let inner_name = format!("{project_id}.zip");
    let inner_bytes = match read_entry_opt(archive, &inner_name)? {
        Some(b) => b,
        None => {
            // No inner archive and no direct entry: the entry is simply absent.
            return missing_entry(required, path, entry);
        }
    };

    let cursor = std::io::Cursor::new(inner_bytes);
    let mut inner = ZipArchive::new(cursor).map_err(|source| ImportError::Zip {
        path: PathBuf::from(&inner_name),
        source,
    })?;

    // Determine the index of `<entry>` inside the inner archive.
    let idx = (0..inner.len()).find(|&i| {
        inner
            .by_index_raw(i)
            .map(|f| f.name() == entry)
            .unwrap_or(false)
    });
    let idx = match idx {
        Some(i) => i,
        None => return missing_entry(required, &PathBuf::from(&inner_name), entry),
    };

    // Is the inner entry encrypted?
    let encrypted = inner
        .by_index_raw(idx)
        .map(|f| f.encrypted())
        .unwrap_or(false);

    let bytes = if encrypted {
        let pw = password.ok_or(ImportError::PasswordRequired)?;
        let zip_pw = derive_zip_password(pw);
        let file = inner
            .by_index_decrypt(idx, zip_pw.as_bytes())
            .map_err(|_| ImportError::WrongPassword)?;
        // Cap the decrypted stream too: a hostile inner archive is untrusted.
        bussard_ets::read_capped(file, entry).map_err(|_| ImportError::WrongPassword)?
    } else {
        let file = inner.by_index(idx).map_err(|source| ImportError::Zip {
            path: PathBuf::from(&inner_name),
            source,
        })?;
        bussard_ets::read_capped(file, entry)?
    };

    Ok(Some(strip_bom(bytes)))
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
