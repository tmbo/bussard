//! Recording the product-data archives a command read in `bussard.lock`
//! (lock v2, issue #228): `import`, `import-product` and the product-data
//! download hash the archive and pin it, linking the devices it serves.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context as _;
use bussard_model::Model;
use bussard_model::schema::{ProductEntry, ProductOrigin};
use bussard_prod::ProductData;

/// The `[[product]]` entry for an archive `import-product` or a download
/// read: its hash, where it lies in the model (when it does), the
/// applications it carries and every order number its catalogue maps to one.
pub(crate) fn archive_entry(
    archive: &Path,
    dir: &Path,
    product: &ProductData,
    origin: ProductOrigin,
) -> anyhow::Result<ProductEntry> {
    let (sha256, size) = bussard_model::sha256_file(archive)
        .with_context(|| format!("hashing {}", archive.display()))?;
    let file = archive
        .strip_prefix(dir)
        .ok()
        .filter(|_| !matches!(origin, ProductOrigin::Knxproj { .. }))
        .map(|rel| rel.to_string_lossy().replace('\\', "/"));
    let mut applications: Vec<String> = product.applications.iter().map(|a| a.id.clone()).collect();
    applications.sort();
    applications.dedup();
    let order_numbers: BTreeSet<String> = product
        .hardware
        .order_to_apps
        .iter()
        .filter(|(_, apps)| !apps.is_empty())
        .map(|(order, _)| order.clone())
        .collect();
    Ok(ProductEntry {
        sha256,
        file,
        filename: archive
            .file_name()
            .map(|n| n.to_string_lossy().into_owned()),
        size: Some(size),
        origin,
        applications,
        order_numbers: order_numbers.into_iter().collect(),
    })
}

/// Pins `entries` in `<dir>/bussard.lock` and says which devices now point at
/// them. A failure is a warning: the archive is cached either way.
pub(crate) fn pin(dir: &Path, entries: &[ProductEntry]) {
    match bussard_model::pin_products(dir, entries) {
        Ok(report) if !report.linked.is_empty() => {
            let list: Vec<String> = report.linked.iter().map(ToString::to_string).collect();
            println!(
                "pinned the product data of {} device(s) in bussard.lock: {}",
                list.len(),
                list.join(", ")
            );
        }
        Ok(_) => {}
        Err(err) => eprintln!("warning: could not record the product data in bussard.lock: {err}"),
    }
}

/// Pins an ETS project export `import` read: one entry for the export,
/// listing the applications and order numbers of the imported devices, then
/// every archive the lock already pins again, so a device served by a cached
/// vendor archive keeps (or regains) its link to it.
pub(crate) fn pin_import(dir: &Path, project: Option<&Path>, model: &Model) {
    let mut entries = Vec::new();
    if let Some(project) = project {
        match bussard_model::sha256_file(project) {
            Ok((sha256, size)) => {
                let applications: BTreeSet<String> = model
                    .devices
                    .values()
                    .filter_map(|d| d.device.product.as_ref()?.application_ref.clone())
                    .collect();
                let orders: BTreeSet<String> = model
                    .devices
                    .values()
                    .filter_map(|d| d.device.product.as_ref()?.order_number.clone())
                    .collect();
                entries.push(bussard_model::lock_products::knxproj_entry(
                    project,
                    sha256,
                    size,
                    applications.into_iter().collect(),
                    orders.into_iter().collect(),
                ));
            }
            Err(err) => eprintln!("warning: could not hash {}: {err}", project.display()),
        }
    }
    entries.extend(pinned_archives(dir));
    if !entries.is_empty() {
        pin(dir, &entries);
    }
}

/// The lock's entries that name an archive the model holds.
fn pinned_archives(dir: &Path) -> Vec<ProductEntry> {
    bussard_model::lock_products::lock_entries(dir)
        .into_iter()
        .filter(|e| e.file.is_some())
        .collect()
}

/// Refuses an archive whose content is not the one `bussard.lock` pins for it
/// (an entry naming an archive the model holds). An entry for an ETS export
/// pins no archive in the model, so there is nothing to compare.
pub(crate) fn verify_archive(archive: &Path, entry: &ProductEntry) -> anyhow::Result<()> {
    if entry.file.is_none() {
        return Ok(());
    }
    let (sha256, _) = bussard_model::sha256_file(archive)
        .with_context(|| format!("hashing {}", archive.display()))?;
    if !sha256.eq_ignore_ascii_case(&entry.sha256) {
        anyhow::bail!(
            "{} has sha256 {sha256} but bussard.lock pins {} for it: the product data \
             changed since it was pinned. Re-pin it with `bussard import-product {}` (a \
             reviewable lock change), or pass --product <FILE> to use a file explicitly",
            archive.display(),
            entry.sha256,
            archive.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sha256: &str, file: Option<&str>) -> ProductEntry {
        ProductEntry {
            sha256: sha256.to_string(),
            file: file.map(str::to_string),
            filename: None,
            size: None,
            origin: ProductOrigin::File {
                path: "x.knxprod".to_string(),
            },
            applications: Vec::new(),
            order_numbers: Vec::new(),
        }
    }

    #[test]
    fn test_verify_archive_refuses_a_changed_archive() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!("bussard-verify-{}", std::process::id()));
        std::fs::write(&path, b"abc")?;
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify_archive(&path, &entry(abc, Some("vendor/x.knxprod"))).is_ok());
        let err = verify_archive(&path, &entry("00ff", Some("vendor/x.knxprod")))
            .err()
            .ok_or_else(|| anyhow::anyhow!("a changed archive must be refused"))?;
        let text = format!("{err:#}");
        assert!(text.contains(abc) && text.contains("00ff"), "{text}");
        // An entry for an ETS export pins no archive in the model.
        assert!(verify_archive(&path, &entry("00ff", None)).is_ok());
        std::fs::remove_file(&path)?;
        Ok(())
    }
}
