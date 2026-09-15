//! Capped zip-entry reading.
//!
//! ETS containers (`.knxproj`, `.knxprod`) are untrusted input: a hostile
//! archive could declare a tiny compressed entry that inflates to gigabytes (a
//! "zip bomb"), OOM-ing the process. Every entry read here is bounded by
//! [`MAX_ENTRY_SIZE`]: we read at most `cap + 1` bytes via [`std::io::Read::take`]
//! and error out the moment the stream exceeds the cap, so decompression can
//! never run away.

use std::io::{Read, Seek};

use zip::ZipArchive;

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
    // Read at most cap + 1 bytes: if we get cap + 1, the entry is over the cap.
    let mut buf = Vec::new();
    let mut limited = reader.take(cap.saturating_add(1));
    limited
        .read_to_end(&mut buf)
        .map_err(|source| EtsError::Io {
            entry: entry.to_string(),
            source,
        })?;
    if buf.len() as u64 > cap {
        return Err(EtsError::EntryTooLarge {
            entry: entry.to_string(),
            cap,
        });
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_within_cap() {
        let data = [b'x'; 100];
        let out = read_capped_with(&data[..], "e", 1000).unwrap();
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn reads_exactly_at_cap() {
        let data = [b'x'; 100];
        let out = read_capped_with(&data[..], "e", 100).unwrap();
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn errors_over_cap() {
        let data = [b'x'; 101];
        let err = read_capped_with(&data[..], "bomb", 100).unwrap_err();
        assert!(matches!(err, EtsError::EntryTooLarge { cap: 100, .. }));
    }
}
