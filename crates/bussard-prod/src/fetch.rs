//! Fetching a vendor-hosted `.knxprod` for an index entry: download to a temp
//! file, verify size and SHA-256 against the pointer, and hand back the bytes.
//!
//! Downloading vendor product data requires explicit consent from the caller
//! (the CLI passes it after a TTY prompt or `--yes-download`). This keeps a
//! network fetch of copyrighted third-party data from ever happening silently.
//!
//! Integrity is enforced in two directions: an oversize response is aborted
//! mid-stream (never buffered past the cap), and the completed download must
//! match the index's exact byte size and SHA-256. A checksum mismatch is a hard
//! error — the file the vendor served is not the one the index vouches for.

use std::io::Read;

use sha2::{Digest, Sha256};

use crate::error::ProdError;
use crate::index::IndexEntry;

/// The hard cap on a single download, regardless of the index's declared size.
/// Application programs reach ~28 MB; 100 MiB leaves generous headroom while
/// bounding a hostile or misconfigured response.
pub const MAX_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;

/// Caller consent to perform a network download of vendor product data. The CLI
/// constructs this only after a TTY confirmation or an explicit `--yes-download`.
///
/// It carries no data; its existence is the consent. This makes it impossible
/// to reach [`fetch_entry`] without a deliberate opt-in at a call site.
#[derive(Debug, Clone, Copy)]
pub struct DownloadConsent(());

impl DownloadConsent {
    /// Grants consent to download. Call this only after the user has agreed.
    pub fn granted() -> Self {
        DownloadConsent(())
    }
}

/// Fetches the `.knxprod` for `entry`, verifying size and checksum.
///
/// Returns the verified file bytes. Requires [`DownloadConsent`]. Downloads via
/// HTTP GET to a bounded in-memory buffer (capped at the smaller of
/// [`MAX_DOWNLOAD_BYTES`] and a small margin over the declared size), then
/// checks the byte length and SHA-256 against the index entry.
pub fn fetch_entry(entry: &IndexEntry, _consent: DownloadConsent) -> Result<Vec<u8>, ProdError> {
    let cap = download_cap(entry.size);
    let reader = http_get(&entry.url)?;
    let bytes = read_capped(reader, cap, &entry.url)?;
    verify(entry, &bytes)?;
    Ok(bytes)
}

/// Verifies already-downloaded bytes against an index entry's size and SHA-256.
/// Exposed so tests (and future on-disk cache checks) can validate without a
/// network round-trip.
pub fn verify(entry: &IndexEntry, bytes: &[u8]) -> Result<(), ProdError> {
    if bytes.len() as u64 != entry.size {
        return Err(ProdError::Fetch {
            reason: format!(
                "size mismatch for {}: index expects {} bytes, download is {} bytes. \
                 The vendor may have updated the file; please report this at \
                 https://github.com/tmbo/bussard/issues so the index can be refreshed.",
                entry.filename,
                entry.size,
                bytes.len()
            ),
        });
    }
    let got = sha256_hex(bytes);
    let want = entry.sha256.trim().to_lowercase();
    if got != want {
        return Err(ProdError::Fetch {
            reason: format!(
                "SHA-256 mismatch for {}: index expects {want}, download is {got}. \
                 The vendor may have re-published this product database under the same \
                 URL. Do NOT trust the downloaded file. Please report this at \
                 https://github.com/tmbo/bussard/issues so the index can be verified \
                 and refreshed.",
                entry.filename
            ),
        });
    }
    Ok(())
}

/// The lowercase-hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The read cap for a download: a small margin over the declared size so an
/// oversize (mismatched) response is caught early, but never above the absolute
/// [`MAX_DOWNLOAD_BYTES`] ceiling.
fn download_cap(declared: u64) -> u64 {
    // One extra byte past the declared size is enough to detect "too big": we
    // only need to know the response exceeds the expected length. Clamp to the
    // absolute ceiling regardless of what the index claims.
    declared.saturating_add(1).min(MAX_DOWNLOAD_BYTES)
}

/// Performs the HTTP GET, returning a reader over the response body.
fn http_get(url: &str) -> Result<Box<dyn Read + Send + Sync>, ProdError> {
    let resp = ureq::get(url).call().map_err(|e| ProdError::Fetch {
        reason: format!("downloading {url}: {e}"),
    })?;
    Ok(resp.into_reader())
}

/// Reads at most `cap` bytes; errors (rather than truncating) if the source has
/// more, so an oversize response is a hard failure.
fn read_capped<R: Read>(reader: R, cap: u64, url: &str) -> Result<Vec<u8>, ProdError> {
    bussard_ets::read_to_cap(reader, cap).map_err(|e| match e {
        bussard_ets::CappedReadError::Io(e) => ProdError::Fetch {
            reason: format!("reading response body from {url}: {e}"),
        },
        bussard_ets::CappedReadError::TooLarge { cap } => ProdError::Fetch {
            reason: format!(
                "download from {url} exceeds the expected size (> {cap} bytes); \
                 refusing to buffer it. If the vendor legitimately grew the file, \
                 the index needs refreshing — please report it."
            ),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_for(bytes: &[u8]) -> IndexEntry {
        IndexEntry {
            manufacturer: "Test".into(),
            manufacturer_id: "M-0000".into(),
            order_numbers: vec!["X-1".into()],
            name: "Test".into(),
            url: "https://example.test/x.knxprod".into(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
            filename: "x.knxprod".into(),
            application_ref: None,
            redistributable: false,
            notes: None,
        }
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") known digest.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn verify_accepts_matching() {
        let bytes = b"hello knxprod";
        let e = entry_for(bytes);
        assert!(verify(&e, bytes).is_ok());
    }

    #[test]
    fn verify_rejects_size_mismatch() {
        let bytes = b"hello knxprod";
        let mut e = entry_for(bytes);
        e.size += 1;
        let err = verify(&e, bytes).unwrap_err().to_string();
        assert!(err.contains("size mismatch"), "{err}");
    }

    #[test]
    fn verify_rejects_sha_mismatch() {
        let bytes = b"hello knxprod";
        let mut e = entry_for(bytes);
        e.sha256 = "0".repeat(64);
        let err = verify(&e, bytes).unwrap_err().to_string();
        assert!(err.contains("SHA-256 mismatch"), "{err}");
    }

    #[test]
    fn read_capped_accepts_at_limit() {
        let data = vec![7u8; 100];
        let out = read_capped(&data[..], 100, "u").unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn read_capped_rejects_over_limit() {
        let data = [7u8; 101];
        let err = read_capped(&data[..], 100, "u").unwrap_err().to_string();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn download_cap_clamps_to_ceiling() {
        assert_eq!(download_cap(10), 11);
        assert_eq!(download_cap(u64::MAX), MAX_DOWNLOAD_BYTES);
    }
}
