//! The retained product store `<dir>/products/` (issue #228, item 3).
//!
//! Every product archive the model depends on lives in `products/`: vendor
//! `.knxprod` files as downloaded or supplied, and archives extracted once from
//! an ETS project export. It is retained data, not a cache: vendor downloads
//! may disappear and the export is used once, so nothing here regenerates.
//! `bussard.lock` holds each archive's identity (`[[product]]`: `file`,
//! `sha256`, `origin`), and every use verifies the SHA-256 first.
//!
//! What regenerates lives under `.bussard/`: the product models
//! (`.bussard/models/<app>.yaml`) are rebuilt from the archives here when they
//! are missing.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use bussard_model::schema::{Device, ProductEntry, ProductOrigin};

/// The product store under a model directory.
pub(crate) const PRODUCTS_DIR: &str = "products";

/// The directory earlier versions cached vendor archives in; its archives
/// move to [`PRODUCTS_DIR`] on the first command after the upgrade.
const LEGACY_VENDOR_DIR: &str = "vendor";

/// Writes `bytes` into `<dir>/products/` under `name` and returns the path.
/// An identical file there is kept; a different file of that name is never
/// overwritten (the store is retained data): the new one gets the first
/// eight hex digits of its hash appended to the stem.
pub(crate) fn store_bytes(dir: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    let store = dir.join(PRODUCTS_DIR);
    std::fs::create_dir_all(&store).with_context(|| format!("creating {}", store.display()))?;
    let mut target = store.join(name);
    if let Ok(existing) = std::fs::read(&target) {
        if existing == bytes {
            return Ok(target);
        }
        let sha = sha256_hex(bytes);
        let path = Path::new(name);
        let stem = path
            .file_stem()
            .map_or_else(|| name.to_string(), |s| s.to_string_lossy().into_owned());
        let ext = path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        target = store.join(format!("{stem}-{}{ext}", &sha[..8]));
    }
    std::fs::write(&target, bytes).with_context(|| format!("writing {}", target.display()))?;
    Ok(target)
}

/// Copies `src` into the store under its own file name (see
/// [`store_bytes`]). A file already in the store is returned as it is.
pub(crate) fn store_file(dir: &Path, src: &Path) -> anyhow::Result<PathBuf> {
    let store = dir.join(PRODUCTS_DIR);
    if src.parent().is_some_and(|p| same_dir(p, &store)) {
        return Ok(src.to_path_buf());
    }
    let name = src
        .file_name()
        .context("product file has no file name")?
        .to_string_lossy()
        .into_owned();
    let bytes = std::fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    store_bytes(dir, &name, &bytes)
}

/// Whether two directories are the same (canonical paths when they exist).
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The refusal for a pinned archive that is missing, with the lock's record
/// and the way to get it back.
pub(crate) fn missing_message(what: &str, entry: &ProductEntry) -> String {
    let order = entry.order_numbers.first().map(String::as_str);
    let file = entry.file.as_deref().unwrap_or("(not extracted yet)");
    let label = match order {
        Some(order) => format!("{order}, {file}"),
        None => file.to_string(),
    };
    format!(
        "product data for {what} ({label}, sha256 {}) is missing; {}",
        short(&entry.sha256),
        bussard_model::lock_products::recovery_hint(entry)
    )
}

/// The first 12 hex digits of a hash, for messages.
fn short(sha: &str) -> String {
    if sha.len() > 12 {
        format!("{}…", &sha[..12])
    } else {
        sha.to_string()
    }
}

/// The archive `entry` pins, verified: its path when the file is there and
/// its SHA-256 is the pinned one.
///
/// # Errors
///
/// The file is missing (or the entry names none), or its content changed.
pub(crate) fn verified_path(
    dir: &Path,
    what: &str,
    entry: &ProductEntry,
) -> anyhow::Result<PathBuf> {
    let Some(file) = entry.file.as_deref() else {
        bail!("{}", missing_message(what, entry));
    };
    let path = dir.join(file);
    if !path.is_file() {
        bail!("{}", missing_message(what, entry));
    }
    crate::lock_pin::verify_archive(&path, entry)?;
    Ok(path)
}

/// The archive a model device's product data comes from: the entry its lock
/// link names, verified. `Ok(None)` when the lock pins nothing for it.
///
/// # Errors
///
/// The pinned archive is missing or its content changed (the refusal names
/// the recovery step).
pub(crate) fn device_archive(dir: &Path, device: &Device) -> anyhow::Result<Option<PathBuf>> {
    let Some(entry) = &device.lock.product_entry else {
        return Ok(None);
    };
    verified_path(dir, &device.address.to_string(), entry).map(Some)
}

/// The archive the lock pins for an order number (the first entry holding
/// an archive whose catalogue carries it), verified. `Ok(None)` when no
/// entry carries it.
///
/// # Errors
///
/// A matching entry's archive is missing or changed.
pub(crate) fn archive_for_order(dir: &Path, order: &str) -> anyhow::Result<Option<PathBuf>> {
    let want = bussard_prod::normalize_order_number(order);
    let entries = bussard_model::lock_products::lock_entries(dir);
    let mut matching = entries.iter().filter(|e| {
        e.file.is_some()
            && e.order_numbers
                .iter()
                .any(|o| bussard_prod::normalize_order_number(o) == want)
    });
    match matching.next() {
        Some(entry) => verified_path(dir, order, entry).map(Some),
        None => Ok(None),
    }
}

/// The product archive for `order` on a device of the model (`device`, when
/// the model has it): `explicit` (`--product`) when given, else the device's
/// pinned archive, else the archive the lock pins for the order number.
///
/// # Errors
///
/// Nothing pinned serves the device, or the pinned archive is missing or
/// changed.
pub(crate) fn resolve(
    dir: &Path,
    explicit: Option<&Path>,
    device: Option<&Device>,
    order: &str,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = device
        .map(|d| device_archive(dir, d))
        .transpose()?
        .flatten()
    {
        return Ok(path);
    }
    match archive_for_order(dir, order)? {
        Some(path) => Ok(path),
        None => bail!(
            "bussard.lock pins no product data for order number {order:?}; run `bussard \
             import-product --order-number {order}` (or `bussard import-product <file>`), or \
             pass --product <FILE>"
        ),
    }
}

/// The application program `app_ref` from an archive the lock pins, if one
/// carries it.
pub(crate) fn pinned_application(
    dir: &Path,
    app_ref: &str,
) -> Option<bussard_prod::ApplicationProgram> {
    let entry = bussard_model::lock_products::lock_entries(dir)
        .into_iter()
        .find(|e| e.file.is_some() && e.applications.iter().any(|a| a == app_ref))?;
    let path = verified_path(dir, app_ref, &entry).ok()?;
    let language = crate::product_cache::model_language(None, dir);
    let product = crate::product_cache::read(&path, None, dir, language.as_deref(), |_| {
        bussard_prod::AppSelection::Exact(vec![app_ref.to_string()])
    })
    .ok()?;
    product.applications.into_iter().find(|a| a.id == app_ref)
}

/// The one-shot migration from earlier layouts, and the regeneration of the
/// product models. Runs before a command that reads an existing model, and
/// in `import` and `import-product`. Cheap when there is nothing to do: one
/// directory listing and one `stat`.
///
/// - Every `vendor/*.knxprod` moves to `products/` and is pinned in the lock
///   (origin `index` when the pointer index knows its hash, else `file`),
///   linking the devices whose order number its catalogue carries; an empty
///   `vendor/` (apart from its old `.gitignore`) is removed.
/// - When `.bussard/models/` is missing, it is regenerated from every
///   archive the lock pins.
///
/// Failures are warnings: the command itself reports what it cannot do.
pub(crate) fn prepare(dir: &Path) {
    if let Err(err) = migrate_vendor(dir) {
        eprintln!("warning: moving vendor/ into products/: {err:#}");
    }
    if !dir.join(bussard_model::param_model::MODELS_DIR).is_dir()
        && dir.join(bussard_model::loader::LOCK_FILE).is_file()
    {
        regenerate_models(dir);
    }
}

/// Moves `vendor/*.knxprod` into `products/` and pins each one.
fn migrate_vendor(dir: &Path) -> anyhow::Result<()> {
    let vendor = dir.join(LEGACY_VENDOR_DIR);
    let Ok(read) = std::fs::read_dir(&vendor) else {
        return Ok(());
    };
    let mut archives: Vec<PathBuf> = read
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("knxprod"))
        })
        .collect();
    archives.sort();
    let index = crate::import_product_cmd::load_index().ok();
    let mut entries = Vec::new();
    for old in &archives {
        let moved = store_file(dir, old)?;
        std::fs::remove_file(old).with_context(|| format!("removing {}", old.display()))?;
        eprintln!(
            "moved {} to {} (product data is retained model data now)",
            old.display(),
            moved.display()
        );
        let product = bussard_prod::read_knxprod(&moved)
            .with_context(|| format!("reading product data from {}", moved.display()))?;
        let (sha, _) = bussard_model::sha256_file(&moved)?;
        let known = index.as_ref().and_then(|i| {
            i.entries
                .iter()
                .find(|e| e.sha256.eq_ignore_ascii_case(&sha))
        });
        let origin = match known {
            Some(e) => ProductOrigin::Index {
                order_number: e.order_numbers.first().cloned(),
                url: Some(e.url.clone()),
            },
            None => ProductOrigin::File {
                path: old.display().to_string(),
            },
        };
        entries.push(crate::lock_pin::archive_entry(
            &moved, dir, &product, origin,
        )?);
        crate::import_product_cmd::write_product_models(&product, dir)?;
    }
    if !entries.is_empty() {
        bussard_model::pin_products(dir, &entries)?;
    }
    // The old self-protecting .gitignore goes with the directory.
    let leftover: Vec<PathBuf> = std::fs::read_dir(&vendor)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    if leftover
        .iter()
        .all(|p| p.file_name().is_some_and(|n| n == ".gitignore"))
    {
        for p in &leftover {
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_dir(&vendor);
    }
    Ok(())
}

/// Rebuilds `.bussard/models/` from every archive the lock pins. The
/// directory is created even when nothing is pinned, so the next command
/// does not parse the lock again for nothing.
fn regenerate_models(dir: &Path) {
    let _ = std::fs::create_dir_all(dir.join(bussard_model::param_model::MODELS_DIR));
    for entry in bussard_model::lock_products::lock_entries(dir) {
        if entry.file.is_none() {
            continue;
        }
        let what = entry
            .filename
            .clone()
            .unwrap_or_else(|| entry.sha256.clone());
        match verified_path(dir, &what, &entry).and_then(|path| {
            let product = bussard_prod::read_knxprod(&path)
                .with_context(|| format!("reading product data from {}", path.display()))?;
            crate::import_product_cmd::write_product_models(&product, dir)
        }) {
            Ok(_) => {}
            Err(err) => eprintln!("warning: regenerating the product models: {err:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> anyhow::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("bussard-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn entry(sha256: String, file: &str) -> ProductEntry {
        ProductEntry {
            sha256,
            file: Some(file.to_string()),
            filename: Some("a.knxprod".to_string()),
            size: None,
            origin: ProductOrigin::Index {
                order_number: Some("AKK-0216.03".to_string()),
                url: None,
            },
            applications: Vec::new(),
            order_numbers: vec!["AKK-0216.03".to_string()],
        }
    }

    #[test]
    fn test_store_bytes_keeps_identical_and_never_overwrites() -> anyhow::Result<()> {
        let dir = scratch("put")?;
        let a = store_bytes(&dir, "a.knxprod", b"one")?;
        assert_eq!(a, dir.join("products/a.knxprod"));
        assert_eq!(store_bytes(&dir, "a.knxprod", b"one")?, a);
        let b = store_bytes(&dir, "a.knxprod", b"two")?;
        assert_ne!(a, b);
        assert_eq!(std::fs::read(&a)?, b"one");
        assert_eq!(std::fs::read(&b)?, b"two");
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_verified_path_accepts_refuses_missing_and_changed() -> anyhow::Result<()> {
        let dir = scratch("verify")?;
        let path = store_bytes(&dir, "a.knxprod", b"abc")?;
        let good = entry(sha256_hex(b"abc"), "products/a.knxprod");
        assert_eq!(verified_path(&dir, "1.1.4", &good)?, path);

        let changed = entry("00ff".to_string(), "products/a.knxprod");
        let err = format!(
            "{:#}",
            verified_path(&dir, "1.1.4", &changed)
                .err()
                .ok_or_else(|| anyhow::anyhow!("changed"))?
        );
        assert!(
            err.contains("00ff") && err.contains(&sha256_hex(b"abc")),
            "{err}"
        );

        let missing = entry(sha256_hex(b"abc"), "products/gone.knxprod");
        let err = format!(
            "{:#}",
            verified_path(&dir, "1.1.4", &missing)
                .err()
                .ok_or_else(|| anyhow::anyhow!("missing"))?
        );
        assert!(
            err.contains("product data for 1.1.4 (AKK-0216.03, products/gone.knxprod"),
            "{err}"
        );
        assert!(
            err.contains("bussard import-product --order-number AKK-0216.03"),
            "{err}"
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
