//! Fetching a vendor-hosted `.knxprod` for an index entry: download to a temp
//! file, verify size and SHA-256 against the pointer, and hand back the bytes.
//! A served ZIP that bundles several products is opened and the inner
//! `.knxprod` matching the pointer is handed back instead (#711).
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

/// How much larger than the index entry's declared size a download may be.
///
/// A vendor may serve a ZIP that bundles several products while the index
/// entry's size and SHA-256 describe one inner `.knxprod` (Ekinex EK-E72,
/// #711: four products, the entry's one about a quarter of the bundle). The
/// read cap leaves room for such a bundle and still aborts a response that is
/// out of all proportion to the declared size.
pub const BUNDLE_SIZE_FACTOR: u64 = 64;

/// The bytes a download was verified as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// The download itself matches the index entry: a plain `.knxprod`, or a
    /// ZIP wrapper whose own checksum the entry records (see
    /// [`IndexEntry::inner`]). Byte for byte what was served.
    Download(Vec<u8>),
    /// The download is a ZIP bundling several products and the entry's size
    /// and SHA-256 match this inner `.knxprod`; the other inner files are
    /// ignored.
    Inner {
        /// The matching entry's name inside the ZIP.
        name: String,
        /// The matching inner `.knxprod`'s bytes.
        bytes: Vec<u8>,
    },
}

impl Verified {
    /// The verified bytes: the download, or the matching inner `.knxprod`.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Verified::Download(bytes) | Verified::Inner { bytes, .. } => bytes,
        }
    }
}

/// Fetches the `.knxprod` for `entry`, verifying size and checksum.
///
/// Returns the verified bytes (see [`verify`]). Requires [`DownloadConsent`].
/// Downloads via HTTP GET to a bounded in-memory buffer (capped at the smaller
/// of [`MAX_DOWNLOAD_BYTES`] and [`BUNDLE_SIZE_FACTOR`] times the declared
/// size), then checks the byte length and SHA-256 against the index entry.
pub fn fetch_entry(entry: &IndexEntry, _consent: DownloadConsent) -> Result<Verified, ProdError> {
    let cap = download_cap(entry.size);
    let reader = http_get(&entry.url)?;
    let bytes = read_capped(reader, cap, &entry.url)?;
    verify(entry, bytes)
}

/// Verifies already-downloaded bytes against an index entry's size and SHA-256.
///
/// A download that matches is returned as [`Verified::Download`], unchanged.
/// Otherwise, when the download is a ZIP holding `.knxprod` files, each inner
/// `.knxprod` of the entry's size is hashed and the one matching the entry is
/// returned as [`Verified::Inner`]; no match is an error naming what was
/// served and how many inner products were tried. Exposed so tests (and future
/// on-disk cache checks) can validate without a network round-trip.
pub fn verify(entry: &IndexEntry, bytes: Vec<u8>) -> Result<Verified, ProdError> {
    let want = entry.sha256.trim().to_lowercase();
    if bytes.len() as u64 == entry.size && sha256_hex(&bytes) == want {
        return Ok(Verified::Download(bytes));
    }
    let label = std::path::Path::new(&entry.filename);
    // A download that is not a ZIP, or a ZIP without inner `.knxprod` files
    // (a plain `.knxprod` is itself a ZIP of XML), keeps the plain errors.
    let inner = crate::container::inner_knxprod_entries(&bytes, label).unwrap_or_default();
    if inner.is_empty() {
        return Err(plain_mismatch(entry, &bytes, &want));
    }
    for (name, size) in &inner {
        if *size != entry.size {
            continue;
        }
        let candidate = crate::container::inner_knxprod_bytes(&bytes, name, label)?;
        if candidate.len() as u64 == entry.size && sha256_hex(&candidate) == want {
            return Ok(Verified::Inner {
                name: name.clone(),
                bytes: candidate,
            });
        }
    }
    Err(ProdError::Fetch {
        reason: format!(
            "no product in the download matches the index entry for {}: {} served a \
             {}-byte ZIP (sha256 {}) holding {} .knxprod file(s) ({}), and none is {} bytes \
             with sha256 {want}. The vendor may have re-published this product database. \
             Do NOT trust the downloaded file. Please report this at \
             https://github.com/tmbo/bussard/issues so the index can be refreshed.",
            entry.filename,
            entry.url,
            bytes.len(),
            sha256_hex(&bytes),
            inner.len(),
            inner
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            entry.size,
        ),
    })
}

/// The error for a download that is neither the entry's file nor a ZIP of
/// `.knxprod` files: the size mismatch first, else the checksum mismatch.
fn plain_mismatch(entry: &IndexEntry, bytes: &[u8], want: &str) -> ProdError {
    if bytes.len() as u64 != entry.size {
        return ProdError::Fetch {
            reason: format!(
                "size mismatch for {}: index expects {} bytes, download is {} bytes. \
                 The vendor may have updated the file; please report this at \
                 https://github.com/tmbo/bussard/issues so the index can be refreshed.",
                entry.filename,
                entry.size,
                bytes.len()
            ),
        };
    }
    let got = sha256_hex(bytes);
    ProdError::Fetch {
        reason: format!(
            "SHA-256 mismatch for {}: index expects {want}, download is {got}. \
             The vendor may have re-published this product database under the same \
             URL. Do NOT trust the downloaded file. Please report this at \
             https://github.com/tmbo/bussard/issues so the index can be verified \
             and refreshed.",
            entry.filename
        ),
    }
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

/// The read cap for a download: room for a ZIP bundle around the declared
/// `.knxprod` ([`BUNDLE_SIZE_FACTOR`]), so a response out of all proportion is
/// caught early, but never above the absolute [`MAX_DOWNLOAD_BYTES`] ceiling.
fn download_cap(declared: u64) -> u64 {
    // One extra byte past the allowance is enough to detect "too big". Clamp to
    // the absolute ceiling regardless of what the index claims.
    declared
        .saturating_mul(BUNDLE_SIZE_FACTOR)
        .saturating_add(1)
        .min(MAX_DOWNLOAD_BYTES)
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
            inner: None,
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
        assert_eq!(
            verify(&e, bytes.to_vec()).ok(),
            Some(Verified::Download(bytes.to_vec()))
        );
    }

    #[test]
    fn verify_rejects_size_mismatch() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = b"hello knxprod";
        let mut e = entry_for(bytes);
        e.size += 1;
        let err = verify(&e, bytes.to_vec())
            .err()
            .ok_or("expected an error")?
            .to_string();
        assert!(err.contains("size mismatch"), "{err}");
        Ok(())
    }

    #[test]
    fn verify_rejects_sha_mismatch() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = b"hello knxprod";
        let mut e = entry_for(bytes);
        e.sha256 = "0".repeat(64);
        let err = verify(&e, bytes.to_vec())
            .err()
            .ok_or("expected an error")?
            .to_string();
        assert!(err.contains("SHA-256 mismatch"), "{err}");
        Ok(())
    }

    #[test]
    fn read_capped_accepts_at_limit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let data = vec![7u8; 100];
        let out = read_capped(&data[..], 100, "u")?;
        assert_eq!(out, data);
        Ok(())
    }

    #[test]
    fn read_capped_rejects_over_limit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let data = [7u8; 101];
        let err = read_capped(&data[..], 100, "u")
            .err()
            .ok_or("expected an error")?
            .to_string();
        assert!(err.contains("exceeds"), "{err}");
        Ok(())
    }

    #[test]
    fn download_cap_clamps_to_ceiling() {
        assert_eq!(download_cap(10), 10 * BUNDLE_SIZE_FACTOR + 1);
        assert_eq!(download_cap(u64::MAX), MAX_DOWNLOAD_BYTES);
    }

    /// A ZIP holding `entries` (name, bytes), stored uncompressed.
    fn zip_of(
        entries: &[(&str, &[u8])],
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in entries {
            writer.start_file(*name, options)?;
            writer.write_all(bytes)?;
        }
        Ok(writer.finish()?.into_inner())
    }

    /// Four products and a readme, the shape of Ekinex's EK-E72/E73 download.
    fn bundle() -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        zip_of(&[
            ("APEKE72TP01.knxprod", b"product one, version 01"),
            ("APEKE72TP02.knxprod", b"product one, version 02"),
            ("APEKE72TP03.knxprod", b"product one, version 03!"),
            ("APEKE73TP03.knxprod", b"product two, version 03"),
            ("readme.txt", b"product one, version 03!"),
        ])
    }

    #[test]
    fn test_verify_bundle_accepts_matching_inner()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let wanted: &[u8] = b"product one, version 03!";
        let mut e = entry_for(wanted);
        e.filename = "APEKE72TP03.knxprod".into();
        match verify(&e, bundle()?)? {
            Verified::Inner { name, bytes } => {
                assert_eq!(name, "APEKE72TP03.knxprod");
                assert_eq!(bytes, wanted);
            }
            other => return Err(format!("expected the inner product, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn test_verify_bundle_rejects_no_match() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let mut e = entry_for(b"a product not in the bundle");
        e.url = "https://example.test/bundle.zip".into();
        let bundle = bundle()?;
        let served = bundle.len();
        let err = verify(&e, bundle)
            .err()
            .ok_or("expected an error")?
            .to_string();
        assert!(err.contains("https://example.test/bundle.zip"), "{err}");
        assert!(err.contains(&format!("{served}-byte ZIP")), "{err}");
        assert!(err.contains("4 .knxprod file(s)"), "{err}");
        Ok(())
    }

    #[test]
    fn test_verify_plain_knxprod_keeps_bytes() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // A `.knxprod` is a ZIP of XML: it matches as a whole, unchanged.
        let plain = zip_of(&[("M-00B6/Hardware.xml", b"<KNX/>")])?;
        let e = entry_for(&plain);
        assert_eq!(
            verify(&e, plain.clone())?,
            Verified::Download(plain.clone())
        );
        // A mismatching one keeps the plain checksum error.
        let mut e = entry_for(&plain);
        e.sha256 = "0".repeat(64);
        let err = verify(&e, plain)
            .err()
            .ok_or("expected an error")?
            .to_string();
        assert!(err.contains("SHA-256 mismatch"), "{err}");
        Ok(())
    }

    #[test]
    fn test_verify_wrapper_hashed_as_whole_is_kept()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The index entry records the wrapper's own checksum (with `inner`): the
        // whole download is the verified file, for `store_download` to unpack.
        let bundle = bundle()?;
        let mut e = entry_for(&bundle);
        e.inner = Some("APEKE72TP03.knxprod".into());
        assert_eq!(verify(&e, bundle.clone())?, Verified::Download(bundle));
        Ok(())
    }
}
