//! The `.knxprod` container: a plain ZIP holding `knx_master.xml`, one or more
//! `M-XXXX/` manufacturer folders (each with `Hardware.xml`, `Catalog.xml`, and
//! the ApplicationProgram XML files), and — for files produced by ETS — RSA
//! signature entries that bussard simply ignores (they authenticate the file to
//! ETS; they are not access control and are irrelevant to reading).
//!
//! Unlike a `.knxproj`, a `.knxprod` is never password-protected, so this is a
//! straight ZIP reader. Big application-program entries (20+ MB) are inflated
//! into one byte buffer and handed as `&[u8]` to the streaming XML parser, with
//! no `String` copy; we never hold more than one entry's bytes at a time.
//!
//! # ZIP-served wrappers
//!
//! Many vendors publish their product data as a ZIP that *contains* a
//! `.knxprod` (often alongside a readme/PDF, or nested one folder deep). Since a
//! `.knxprod` is itself a ZIP, such a wrapper looks like a `.knxprod` with the
//! wrong entries. [`Container::open`] transparently unwraps one level: when the
//! opened archive has no `M-XXXX/` manufacturer folders but does hold exactly
//! one `*.knxprod` entry, that inner file is extracted (in memory, bounded by
//! [`MAX_INNER_KNXPROD_SIZE`]) and read in its place. Multiple inner `.knxprod`
//! entries are ambiguous and error with the list so the caller can pick one;
//! unwrapping recurses at most once (a wrapped wrapper is rejected).

use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use bussard_ets::{CappedReadError, ZipOpenError, strip_bom, strip_bom_bytes};
use zip::ZipArchive;

use crate::error::{ProdError, Result};

/// The cap on how many entries of a candidate wrapper are inspected while
/// looking for inner `.knxprod` files. A legitimate wrapper has a handful of
/// entries (the payload plus a readme/changelog); a much larger count is a sign
/// of a hostile or malformed archive, so we stop scanning past this bound.
const MAX_WRAPPER_ENTRIES: usize = 4096;

/// The decompression cap applied to an inner `.knxprod` extracted from a
/// ZIP-served wrapper: ~100 MiB. Application programs reach ~28 MB, so this
/// leaves generous headroom while refusing to buffer a zip-bomb payload.
pub const MAX_INNER_KNXPROD_SIZE: u64 = 100 * 1024 * 1024;

/// The backing store for an opened container: either the file on disk (the
/// common case) or an in-memory buffer holding an inner `.knxprod` extracted
/// from a ZIP-served wrapper. Both are `Read + Seek`, which is all
/// [`ZipArchive`] requires.
enum Source {
    /// The `.knxprod` file, read directly from disk.
    File(File),
    /// An inner `.knxprod` extracted from a wrapper ZIP, held in memory.
    Memory(Cursor<Vec<u8>>),
}

impl Read for Source {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Source::File(f) => f.read(buf),
            Source::Memory(c) => c.read(buf),
        }
    }
}

impl Seek for Source {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            Source::File(f) => f.seek(pos),
            Source::Memory(c) => c.seek(pos),
        }
    }
}

/// An opened `.knxprod` container.
pub struct Container {
    path: PathBuf,
    archive: ZipArchive<Source>,
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
    /// Opens a `.knxprod` ZIP, transparently unwrapping a ZIP-served wrapper.
    ///
    /// The common case is a plain `.knxprod`; that opens directly. If the
    /// archive is instead a *wrapper* (no `M-XXXX/` manufacturer folders, but one
    /// or more `*.knxprod` entries inside — see the module docs), exactly one
    /// inner `.knxprod` is extracted in memory and read in its place. Multiple
    /// inner `.knxprod` entries error with the list; a doubly wrapped archive
    /// (inner `.knxprod` that is itself a wrapper) is rejected, so unwrapping
    /// happens at most once.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_inner(path, None)
    }

    /// Opens a `.knxprod`, selecting a specific inner `.knxprod` when the file is
    /// a ZIP-served wrapper holding several.
    ///
    /// `inner` names the entry to read (matched by its full entry name or its
    /// bare file name); it is only honoured when the archive is a wrapper. For a
    /// plain `.knxprod`, or a wrapper with a single inner, `inner` is ignored and
    /// this behaves like [`Container::open`].
    pub fn open_with_inner(path: &Path, inner: Option<&str>) -> Result<Self> {
        let archive = bussard_ets::open_zip(path, Source::File).map_err(|e| match e {
            ZipOpenError::Io(source) => ProdError::Io {
                path: path.to_path_buf(),
                source,
            },
            ZipOpenError::Zip(source) => ProdError::Zip {
                path: path.to_path_buf(),
                source,
            },
        })?;
        Self::from_archive(path.to_path_buf(), archive, inner)
    }

    /// Builds a container from an opened archive, applying the wrapper-unwrap
    /// logic and honouring an explicit inner selection when present.
    fn from_archive(
        path: PathBuf,
        archive: ZipArchive<Source>,
        inner: Option<&str>,
    ) -> Result<Self> {
        let mut container = Self { path, archive };
        // An explicit inner selection only applies to a wrapper (no
        // manufacturer folders of its own).
        if let Some(sel) = inner
            && container.manufacturer_ids().is_empty()
        {
            let target = container.resolve_inner_selection(sel)?;
            container.replace_with_inner(&target)?;
            return Ok(container);
        }
        if let Some(target) = container.unwrap_target()? {
            container.replace_with_inner(&target)?;
        }
        Ok(container)
    }

    /// Resolves a user-supplied `--inner` selection to a concrete inner
    /// `.knxprod` entry name, matching either the full entry path or its bare
    /// file name. Errors (listing the candidates) if it matches none.
    fn resolve_inner_selection(&self, selection: &str) -> Result<String> {
        let inners: Vec<String> = self
            .archive
            .file_names()
            .take(MAX_WRAPPER_ENTRIES)
            .filter(|name| is_knxprod_entry(name))
            .map(str::to_string)
            .collect();
        if let Some(hit) = inners.iter().find(|name| {
            name.as_str() == selection
                || std::path::Path::new(name)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .is_some_and(|f| f == selection)
        }) {
            return Ok(hit.clone());
        }
        let mut listed = inners;
        listed.sort();
        Err(ProdError::AmbiguousWrapper {
            path: self.path.clone(),
            entries: listed,
        })
    }

    /// If the opened archive is a ZIP-served wrapper rather than a real
    /// `.knxprod`, returns the name of the single inner `.knxprod` entry to read
    /// instead. Returns `None` for a normal `.knxprod` (one that carries its own
    /// `M-XXXX/` manufacturer folders).
    fn unwrap_target(&self) -> Result<Option<String>> {
        // A real `.knxprod` has manufacturer folders; leave it alone.
        if !self.manufacturer_ids().is_empty() {
            return Ok(None);
        }

        // Otherwise, look for inner `.knxprod` entries (capped scan).
        let inners: Vec<String> = self
            .archive
            .file_names()
            .take(MAX_WRAPPER_ENTRIES)
            .filter(|name| is_knxprod_entry(name))
            .map(str::to_string)
            .collect();

        match <[String; 1]>::try_from(inners) {
            // Exactly one inner `.knxprod`: unwrap it transparently.
            Ok([only]) => Ok(Some(only)),
            // Zero or many: `Err` carries the original vec back.
            Err(inners) if inners.is_empty() => Ok(None),
            Err(mut listed) => {
                listed.sort();
                Err(ProdError::AmbiguousWrapper {
                    path: self.path.clone(),
                    entries: listed,
                })
            }
        }
    }

    /// Extracts `entry` (an inner `.knxprod`) in memory and reopens this
    /// container against it. Rejects a nested wrapper: the extracted archive must
    /// be a real `.knxprod`, not another wrapper.
    fn replace_with_inner(&mut self, entry: &str) -> Result<()> {
        let idx = self
            .archive
            .index_for_name(entry)
            .ok_or_else(|| ProdError::MissingEntry {
                path: self.path.clone(),
                entry: entry.to_string(),
            })?;
        let file = self
            .archive
            .by_index(idx)
            .map_err(|source| ProdError::Zip {
                path: self.path.clone(),
                source,
            })?;
        // Bounded read: refuse to buffer a zip-bomb inner payload.
        let bytes = read_capped(file, entry, MAX_INNER_KNXPROD_SIZE, &self.path)?;

        let archive = ZipArchive::new(Source::Memory(Cursor::new(bytes))).map_err(|source| {
            ProdError::Zip {
                path: self.path.clone(),
                source,
            }
        })?;
        self.archive = archive;

        // Recurse exactly once: a wrapped wrapper is rejected rather than peeled
        // again. If the inner archive is itself a wrapper (or empty of
        // manufacturers and inner `.knxprod`s), that surfaces later as "no
        // application programs"; a nested `.knxprod` is an explicit error.
        if let Some(nested) = self.unwrap_target()? {
            return Err(ProdError::NestedWrapper {
                path: self.path.clone(),
                outer: entry.to_string(),
                inner: nested,
            });
        }
        Ok(())
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

    /// Whether the archive is an ETS project export: it has a top-level
    /// `P-XXXX/` project folder, or a `P-XXXX.zip` (encrypted) or
    /// `P-XXXX.signature` entry. A `.knxprod` has only `M-XXXX/` folders.
    pub fn has_project_folder(&self) -> bool {
        self.archive
            .file_names()
            .take(MAX_WRAPPER_ENTRIES)
            .any(is_project_entry)
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

    /// Reads a named archive entry as raw bytes (BOM stripped in place),
    /// erroring if the entry is absent.
    ///
    /// This is the application-program path: the byte parser reads UTF-8 event
    /// by event, so the ~28 MB entry goes straight from the inflater's buffer to
    /// the parser with no `String` copy or eager whole-file UTF-8 validation.
    pub fn read_raw(&mut self, entry: &str) -> Result<Vec<u8>> {
        match self.read_entry_opt(entry)? {
            Some(bytes) => Ok(strip_bom_bytes(bytes)),
            None => Err(ProdError::MissingEntry {
                path: self.path.clone(),
                entry: entry.to_string(),
            }),
        }
    }

    /// Reads a named entry exactly as stored (no BOM stripping), or `None`
    /// if absent; size-capped like every other read.
    pub fn entry_bytes(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        self.read_entry_opt(name)
    }

    /// Reads a named entry as raw bytes, or `None` if absent. The decompressed
    /// size is capped (a zip-bomb guard); an oversized entry errors rather than
    /// exhausting memory.
    fn read_entry_opt(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(bussard_ets::read_entry_opt(&mut self.archive, name)?)
    }
}

/// Whether a ZIP entry name belongs to an ETS project folder: `P-XXXX/…`,
/// `P-XXXX.zip` or `P-XXXX.signature` at the archive root.
fn is_project_entry(name: &str) -> bool {
    let top = match name.split_once('/') {
        Some((dir, _)) => Some(dir),
        None => name
            .strip_suffix(".zip")
            .or_else(|| name.strip_suffix(".signature")),
    };
    top.and_then(|t| t.strip_prefix("P-"))
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Is `dir` a manufacturer folder id like `M-0004`?
fn is_manufacturer_dir(dir: &str) -> bool {
    dir.strip_prefix("M-")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Reads a wrapper's inner `.knxprod` entry into a buffer, capped at `cap`
/// bytes. Errors ([`ProdError::InnerTooLarge`]) if the entry decompresses past
/// the cap, so a zip-bomb payload is never fully buffered.
fn read_capped<R: Read>(reader: R, entry: &str, cap: u64, path: &Path) -> Result<Vec<u8>> {
    bussard_ets::read_to_cap(reader, cap).map_err(|e| match e {
        CappedReadError::Io(source) => ProdError::Io {
            path: path.to_path_buf(),
            source,
        },
        CappedReadError::TooLarge { cap } => ProdError::InnerTooLarge {
            path: path.to_path_buf(),
            entry: entry.to_string(),
            cap,
        },
    })
}

/// Is `name` a `.knxprod` entry (case-insensitive extension, and a real file —
/// not a directory placeholder)? Used to spot the payload inside a ZIP-served
/// wrapper, which may sit at the root or one folder deep.
fn is_knxprod_entry(name: &str) -> bool {
    !name.ends_with('/')
        && std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("knxprod"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_project_entry_matches_project_folders_only() {
        assert!(is_project_entry("P-048B/0.xml"));
        assert!(is_project_entry("P-048B.zip"));
        assert!(is_project_entry("P-048B.signature"));
        assert!(!is_project_entry("M-0083/Hardware.xml"));
        assert!(!is_project_entry("knx_master.xml"));
        assert!(!is_project_entry("P-.zip"));
        assert!(!is_project_entry("nested/P-048B/0.xml"));
        assert!(!is_project_entry("P-048B"));
    }

    #[test]
    fn recognizes_manufacturer_dirs() {
        assert!(is_manufacturer_dir("M-0004"));
        assert!(is_manufacturer_dir("M-00FA"));
        assert!(!is_manufacturer_dir("M-"));
        assert!(!is_manufacturer_dir("knx_master"));
        assert!(!is_manufacturer_dir("P-05E7"));
    }

    #[test]
    fn recognizes_knxprod_entries() {
        assert!(is_knxprod_entry("Fixture.knxprod"));
        assert!(is_knxprod_entry("pkg/Fixture.knxprod"));
        // Extension match is case-insensitive.
        assert!(is_knxprod_entry("FIXTURE.KNXPROD"));
        // Directory placeholders and non-payload files are not entries.
        assert!(!is_knxprod_entry("pkg/"));
        assert!(!is_knxprod_entry("Readme.txt"));
        assert!(!is_knxprod_entry("notes.pdf"));
        assert!(!is_knxprod_entry("knx_master.xml"));
    }
}
