//! Pinning product-data archives in `bussard.lock` (lock v2, issue #228).
//!
//! `import`, `import-product` and `adopt` read a product archive (a vendor
//! `.knxprod` or an ETS project export) and record it here: one `[[product]]`
//! entry per archive, identified by its SHA-256, and a `product_sha256` link on
//! every device whose order number and application the archive carries.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::address::IndividualAddress;
use crate::emit;
use crate::files::LockFile;
use crate::loader::{LOCK_FILE, LoadError, parse_lock};
use crate::schema::{ProductEntry, ProductOrigin};

/// Why [`pin_products`] failed.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// The existing lock does not parse.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// The lock could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// What [`pin_products`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinReport {
    /// The devices now linked to one of the pinned entries.
    pub linked: Vec<IndividualAddress>,
    /// Whether `bussard.lock` was rewritten.
    pub written: bool,
}

/// The SHA-256 (lowercase hex) and size of a file.
///
/// # Errors
///
/// The file cannot be read.
pub fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((hex_lower(&hasher.finalize()), size))
}

/// Lowercase hex of `bytes`.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Whether an entry names an archive the model holds.
fn holds_archive(entry: &ProductEntry) -> bool {
    entry.file.is_some()
}

/// Records `entries` in `<dir>/bussard.lock` and links the devices whose
/// order number an entry's catalogue carries (and whose application it lists,
/// when it lists any).
///
/// An entry replaces an existing one with the same hash or the same `file`. A
/// device already linked keeps its link unless the new entry holds an archive
/// in the model and the old one does not (an ETS export, a device read-back),
/// or the old one named the same file. A missing lock is created. The lock is
/// written as v2, and only when its text changes.
///
/// # Errors
///
/// The lock does not parse, or cannot be read or written.
pub fn pin_products(dir: &Path, entries: &[ProductEntry]) -> Result<PinReport, PinError> {
    let path = dir.join(LOCK_FILE);
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => return Err(PinError::Io { path, source }),
    };
    let mut lock = match &existing {
        Some(text) => parse_lock(&path, text)?,
        None => LockFile::default(),
    };
    let report = pin_into(&mut lock, entries);
    let text = emit::render_lock(
        lock.source.as_deref(),
        lock.language.as_deref(),
        &lock.products,
        &lock.devices,
    );
    let written = existing.as_deref() != Some(text.as_str());
    if written {
        std::fs::write(&path, &text).map_err(|source| PinError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(PinReport { written, ..report })
}

/// Records `entry` in `<dir>/bussard.lock` and links `address` to it,
/// replacing whatever link the device had: the explicit override of `flash
/// --product <file> --force`. Returns whether the lock changed.
///
/// # Errors
///
/// As [`pin_products`].
pub fn pin_device(
    dir: &Path,
    address: IndividualAddress,
    entry: &ProductEntry,
) -> Result<bool, PinError> {
    let report = pin_products(dir, std::slice::from_ref(entry))?;
    let path = dir.join(LOCK_FILE);
    let text = std::fs::read_to_string(&path).map_err(|source| PinError::Io {
        path: path.clone(),
        source,
    })?;
    let mut lock = parse_lock(&path, &text)?;
    let sha = entry.sha256.to_ascii_lowercase();
    let mut changed = false;
    for device in lock.devices.iter_mut().filter(|d| d.address == address) {
        if device.product_sha256.as_deref() != Some(sha.as_str()) {
            device.product_sha256 = Some(sha.clone());
            changed = true;
        }
    }
    if changed {
        let text = emit::render_lock(
            lock.source.as_deref(),
            lock.language.as_deref(),
            &lock.products,
            &lock.devices,
        );
        std::fs::write(&path, text).map_err(|source| PinError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(changed || report.written)
}

/// [`pin_products`] on a parsed lock.
pub(crate) fn pin_into(lock: &mut LockFile, entries: &[ProductEntry]) -> PinReport {
    let mut linked = BTreeSet::new();
    for entry in entries {
        let sha = entry.sha256.to_ascii_lowercase();
        let replaced: Vec<ProductEntry> = lock
            .products
            .iter()
            .filter(|p| {
                p.sha256.eq_ignore_ascii_case(&sha) || (p.file.is_some() && p.file == entry.file)
            })
            .cloned()
            .collect();
        lock.products.retain(|p| !replaced.contains(p));
        let mut entry = entry.clone();
        entry.sha256.clone_from(&sha);
        lock.products.push(entry.clone());

        for device in &mut lock.devices {
            let Some(order) = device.product.as_deref() else {
                continue;
            };
            if !entry
                .order_numbers
                .iter()
                .any(|o| o.trim().eq_ignore_ascii_case(order.trim()))
            {
                continue;
            }
            if let Some(app) = device.application.as_deref()
                && !entry.applications.is_empty()
                && !entry.applications.iter().any(|a| a == app)
            {
                continue;
            }
            let current = device.product_sha256.as_deref().map(|cur| {
                replaced
                    .iter()
                    .chain(lock.products.iter())
                    .find(|p| p.sha256.eq_ignore_ascii_case(cur))
            });
            let relink = match current {
                None => true,
                // A dangling link, or one to an entry being replaced.
                Some(None) => true,
                Some(Some(old)) => {
                    replaced.contains(old) || (!holds_archive(old) && holds_archive(&entry))
                }
            };
            if relink {
                device.product_sha256 = Some(sha.clone());
                linked.insert(device.address);
            }
        }
    }
    // Drop entries nothing links any more that hold no archive either (an
    // earlier import of an ETS export that a newer one superseded).
    let used: BTreeSet<String> = lock
        .devices
        .iter()
        .filter_map(|d| d.product_sha256.as_deref().map(str::to_ascii_lowercase))
        .collect();
    let pinned: BTreeSet<String> = entries
        .iter()
        .map(|e| e.sha256.to_ascii_lowercase())
        .collect();
    lock.products.retain(|p| {
        let sha = p.sha256.to_ascii_lowercase();
        holds_archive(p) || used.contains(&sha) || pinned.contains(&sha)
    });
    lock.products.sort_by(|a, b| {
        (a.filename.as_deref(), a.sha256.as_str()).cmp(&(b.filename.as_deref(), b.sha256.as_str()))
    });
    lock.version = crate::files::LOCK_VERSION;
    PinReport {
        linked: linked.into_iter().collect(),
        written: false,
    }
}

/// Every `[[product]]` entry of `<dir>/bussard.lock` (empty when there is no
/// lock or it does not parse).
pub fn lock_entries(dir: &Path) -> Vec<ProductEntry> {
    let path = dir.join(LOCK_FILE);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| parse_lock(&path, &text).ok())
        .map(|lock| lock.products)
        .unwrap_or_default()
}

/// How to get a pinned archive back, from its origin: the command to run.
pub fn recovery_hint(entry: &ProductEntry) -> String {
    const RESTORE: &str = "restore it from your backup or version control";
    match &entry.origin {
        ProductOrigin::Index { order_number, .. } => match order_number
            .as_deref()
            .or_else(|| entry.order_numbers.first().map(String::as_str))
        {
            Some(order) => format!(
                "{RESTORE}, or re-download it: bussard import-product --order-number {order}"
            ),
            None => RESTORE.to_string(),
        },
        ProductOrigin::File { path } => {
            format!("{RESTORE}, or re-import the file: bussard import-product {path}")
        }
        ProductOrigin::Knxproj { path, .. } => {
            format!("{RESTORE}, or re-import the ETS export: bussard import {path}")
        }
        ProductOrigin::Device => format!("{RESTORE}, or read it back: bussard reconstruct --line"),
    }
}

/// The entry for an ETS project export read in place: its hash stands for
/// the products until they are extracted into the model.
pub fn knxproj_entry(
    project: &Path,
    sha256: String,
    size: u64,
    applications: Vec<String>,
    order_numbers: Vec<String>,
) -> ProductEntry {
    ProductEntry {
        sha256: sha256.clone(),
        file: None,
        filename: project
            .file_name()
            .map(|n| n.to_string_lossy().into_owned()),
        size: Some(size),
        origin: ProductOrigin::Knxproj {
            path: project.display().to_string(),
            project_hash: Some(sha256),
        },
        applications,
        order_numbers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(text: &str) -> Result<LockFile, Box<dyn std::error::Error>> {
        Ok(parse_lock(Path::new("bussard.lock"), text)?)
    }

    const LOCK: &str = r#"version = 2
source = "house.knxproj"

[[device]]
address = "1.1.4"
product = "AKK-0216.03"
application = "M-0083_A-00FA-25-001A"

[[device]]
address = "1.1.5"
product = "OTHER-1"
"#;

    fn vendor_entry(sha: &str) -> ProductEntry {
        ProductEntry {
            sha256: sha.to_string(),
            file: Some("vendor/MDT_AKK.knxprod".to_string()),
            filename: Some("MDT_AKK.knxprod".to_string()),
            size: Some(10),
            origin: ProductOrigin::Index {
                order_number: Some("AKK-0216.03".to_string()),
                url: None,
            },
            applications: vec!["M-0083_A-00FA-25-001A".to_string()],
            order_numbers: vec!["AKK-0216.03".to_string()],
        }
    }

    #[test]
    fn test_pin_into_links_matching_devices_only() -> Result<(), Box<dyn std::error::Error>> {
        let mut lock = lock(LOCK)?;
        let report = pin_into(&mut lock, &[vendor_entry("AB12")]);
        assert_eq!(report.linked, vec!["1.1.4".parse()?]);
        assert_eq!(lock.version, 2);
        assert_eq!(lock.devices[0].product_sha256.as_deref(), Some("ab12"));
        assert_eq!(lock.devices[1].product_sha256, None);
        Ok(())
    }

    #[test]
    fn test_pin_into_prefers_an_archive_over_a_project_export()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut lock = lock(LOCK)?;
        let project = knxproj_entry(
            Path::new("../house.knxproj"),
            "ff00".to_string(),
            5,
            vec!["M-0083_A-00FA-25-001A".to_string()],
            vec!["AKK-0216.03".to_string(), "OTHER-1".to_string()],
        );
        pin_into(&mut lock, std::slice::from_ref(&project));
        assert_eq!(lock.devices[0].product_sha256.as_deref(), Some("ff00"));
        assert_eq!(lock.devices[1].product_sha256.as_deref(), Some("ff00"));
        pin_into(&mut lock, &[vendor_entry("ab12")]);
        assert_eq!(lock.devices[0].product_sha256.as_deref(), Some("ab12"));
        assert_eq!(lock.devices[1].product_sha256.as_deref(), Some("ff00"));
        // The project export stays: a device still links it.
        assert_eq!(lock.products.len(), 2);
        // Pinning the export again does not take the archive's device back.
        pin_into(&mut lock, &[project]);
        assert_eq!(lock.devices[0].product_sha256.as_deref(), Some("ab12"));
        Ok(())
    }

    #[test]
    fn test_pin_into_replaces_a_redownloaded_file() -> Result<(), Box<dyn std::error::Error>> {
        let mut lock = lock(LOCK)?;
        pin_into(&mut lock, &[vendor_entry("ab12")]);
        pin_into(&mut lock, &[vendor_entry("cd34")]);
        assert_eq!(lock.products.len(), 1);
        assert_eq!(lock.products[0].sha256, "cd34");
        assert_eq!(lock.devices[0].product_sha256.as_deref(), Some("cd34"));
        Ok(())
    }

    #[test]
    fn test_sha256_file_hashes_contents() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!("bussard-sha-{}", std::process::id()));
        std::fs::write(&path, b"abc")?;
        let (sha, size) = sha256_file(&path)?;
        std::fs::remove_file(&path)?;
        assert_eq!(size, 3);
        assert_eq!(
            sha,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        Ok(())
    }
}
