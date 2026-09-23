//! Capped zip-entry reading.
//!
//! ETS containers (`.knxproj`, `.knxprod`) are untrusted input: a hostile
//! archive could declare a tiny compressed entry that inflates to gigabytes (a
//! "zip bomb"), OOM-ing the process. Every entry read here is bounded by
//! [`MAX_ENTRY_SIZE`]: we read at most `cap + 1` bytes via [`std::io::Read::take`]
//! and error out the moment the stream exceeds the cap, so decompression can
//! never run away.

use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

use zip::ZipArchive;
use zip::result::ZipError;

use crate::error::{EtsError, Result};

/// The per-entry decompression cap: 256 MiB. The largest real ETS
/// application-program XML seen in practice is ~28 MB, so this leaves ample
/// headroom while still bounding a hostile archive.
pub const MAX_ENTRY_SIZE: u64 = 256 * 1024 * 1024;

/// Reads a named entry from an archive as raw bytes, or `None` if it is absent.
///
/// The read is capped at [`MAX_ENTRY_SIZE`]; an entry that decompresses larger
/// yields [`EtsError::EntryTooLarge`] rather than exhausting memory.
pub fn read_entry_opt<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    let idx = match archive.index_for_name(name) {
        Some(i) => i,
        None => return Ok(None),
    };
    let file = archive.by_index(idx).map_err(|source| EtsError::Zip {
        entry: name.to_string(),
        source,
    })?;
    read_capped(file, name).map(Some)
}

/// Reads an already-opened zip entry (or any reader) into a `Vec`, capped at
/// [`MAX_ENTRY_SIZE`]. Errors with [`EtsError::EntryTooLarge`] if the source
/// produces more than the cap.
///
/// Callers that open the entry themselves (e.g. the encrypted-inner-archive
/// path in `bussard-project`) use this directly.
pub fn read_capped<R: Read>(reader: R, entry: &str) -> Result<Vec<u8>> {
    read_capped_with(reader, entry, MAX_ENTRY_SIZE)
}

/// [`read_capped`] with an explicit cap, exposed for tests.
pub fn read_capped_with<R: Read>(reader: R, entry: &str, cap: u64) -> Result<Vec<u8>> {
    read_to_cap(reader, cap).map_err(|e| match e {
        CappedReadError::Io(source) => EtsError::Io {
            entry: entry.to_string(),
            source,
        },
        CappedReadError::TooLarge { cap } => EtsError::EntryTooLarge {
            entry: entry.to_string(),
            cap,
        },
    })
}

/// Why a [`read_to_cap`] call failed, kept free of any caller context so each
/// crate can map it onto its own error type (zip entry, wrapper payload, HTTP
/// body) without re-implementing the bounded read.
#[derive(Debug, thiserror::Error)]
pub enum CappedReadError {
    /// The underlying reader failed.
    #[error("{0}")]
    Io(#[source] std::io::Error),
    /// The source produced more than `cap` bytes.
    #[error("exceeds the {cap}-byte cap")]
    TooLarge {
        /// The cap that was exceeded, in bytes.
        cap: u64,
    },
}

/// Reads `reader` to the end into a `Vec`, refusing to buffer more than `cap`
/// bytes.
///
/// At most `cap + 1` bytes are pulled through [`Read::take`]; getting `cap + 1`
/// means the source is over the cap and yields [`CappedReadError::TooLarge`]
/// rather than a truncated buffer. Exactly `cap` bytes is accepted. This is the
/// single bounded-read implementation behind every zip-entry, wrapper and
/// download read in bussard.
pub fn read_to_cap<R: Read>(reader: R, cap: u64) -> std::result::Result<Vec<u8>, CappedReadError> {
    let mut buf = Vec::new();
    let mut limited = reader.take(cap.saturating_add(1));
    limited.read_to_end(&mut buf).map_err(CappedReadError::Io)?;
    if buf.len() as u64 > cap {
        return Err(CappedReadError::TooLarge { cap });
    }
    Ok(buf)
}

/// Why [`open_zip`] failed: the file could not be opened, or it is not a
/// readable ZIP.
#[derive(Debug, thiserror::Error)]
pub enum ZipOpenError {
    /// Opening the file failed.
    #[error("{0}")]
    Io(#[source] std::io::Error),
    /// The file is not a readable ZIP archive.
    #[error("{0}")]
    Zip(#[source] ZipError),
}

/// Opens the file at `path` as a ZIP archive, wrapping the [`File`] with `wrap`
/// first (identity for most callers; `bussard-prod` wraps it in its
/// file-or-memory source enum).
///
/// Callers map [`ZipOpenError`] onto their own path-carrying error variants.
pub fn open_zip<R, F>(path: &Path, wrap: F) -> std::result::Result<ZipArchive<R>, ZipOpenError>
where
    R: Read + Seek,
    F: FnOnce(File) -> R,
{
    let file = File::open(path).map_err(ZipOpenError::Io)?;
    ZipArchive::new(wrap(file)).map_err(ZipOpenError::Zip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_capped_with_within_cap() -> Result<()> {
        let data = [b'x'; 100];
        let out = read_capped_with(&data[..], "e", 1000)?;
        assert_eq!(out.len(), 100);
        Ok(())
    }

    #[test]
    fn test_read_capped_with_exactly_at_cap() -> Result<()> {
        let data = [b'x'; 100];
        let out = read_capped_with(&data[..], "e", 100)?;
        assert_eq!(out.len(), 100);
        Ok(())
    }

    #[test]
    fn test_read_capped_with_errors_over_cap() {
        let data = [b'x'; 101];
        let err = read_capped_with(&data[..], "bomb", 100);
        assert!(matches!(err, Err(EtsError::EntryTooLarge { cap: 100, .. })));
    }

    #[test]
    fn test_read_to_cap_reports_the_cap() {
        let data = [b'x'; 11];
        let err = read_to_cap(&data[..], 10);
        assert!(matches!(err, Err(CappedReadError::TooLarge { cap: 10 })));
    }

    #[test]
    fn test_open_zip_missing_file_is_io() {
        let err = open_zip(Path::new("/nonexistent/bussard/none.zip"), |f| f);
        assert!(matches!(err, Err(ZipOpenError::Io(_))));
    }
}
