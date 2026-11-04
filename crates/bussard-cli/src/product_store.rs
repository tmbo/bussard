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

use anyhow::bail;
use bussard_model::schema::{Device, ProductEntry};

/// Writes `bytes` into `<dir>/products/` under `name` and returns the path
/// ([`bussard_service::setup::products::store_bytes`]): an identical file is
/// kept, a different one of that name never overwritten.
#[cfg(test)]
pub(crate) fn store_bytes(dir: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    Ok(bussard_service::setup::products::store_bytes(
        dir, name, bytes,
    )?)
}

/// Copies `src` into the store under its own file name
/// ([`bussard_service::files::products::store_file`]). A file already in the
/// store is returned as it is.
pub(crate) fn store_file(dir: &Path, src: &Path) -> anyhow::Result<PathBuf> {
    Ok(bussard_service::files::products::store_file(dir, src)?)
}

/// Lowercase hex SHA-256 of `bytes`.
#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The archive `entry` pins, verified
/// ([`bussard_service::params::verified_path`]).
///
/// # Errors
///
/// The file is missing (or the entry names none), or its content changed.
pub(crate) fn verified_path(
    dir: &Path,
    what: &str,
    entry: &ProductEntry,
) -> anyhow::Result<PathBuf> {
    Ok(bussard_service::params::verified_path(dir, what, entry)?)
}

/// The archive a model device's product data comes from
/// ([`bussard_service::params::device_archive`]).
///
/// # Errors
///
/// The pinned archive is missing or its content changed.
pub(crate) fn device_archive(dir: &Path, device: &Device) -> anyhow::Result<Option<PathBuf>> {
    Ok(bussard_service::params::device_archive(dir, device)?)
}

/// The archive the lock pins for an order number
/// ([`bussard_service::params::archive_for_order`]).
///
/// # Errors
///
/// A matching entry's archive is missing or changed.
pub(crate) fn archive_for_order(dir: &Path, order: &str) -> anyhow::Result<Option<PathBuf>> {
    Ok(bussard_service::params::archive_for_order(dir, order)?)
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
/// product models ([`bussard_service::files::products::prepare`]). Runs
/// before a command that reads an existing model, and in `import` and
/// `import-product`. Failures are warnings.
pub(crate) fn prepare(dir: &Path) {
    bussard_service::files::products::prepare(dir, &mut crate::console::Console);
}

/// Writes the product model of every application a device in the lock pins
/// that `.bussard/models/` lacks, or only of `only` when given (see
/// [`bussard_prod::product_model::complete_models`], which the MCP and `viz`
/// servers run on their model reload too).
///
/// Failures are warnings: the command itself reports what it cannot do.
pub(crate) fn complete_models(dir: &Path, only: Option<&str>) {
    bussard_service::setup::products::complete_models(dir, only, &mut crate::console::Console);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::schema::ProductOrigin;

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
