//! Recording the product-data archives a command read in `bussard.lock`
//! (lock v2, issue #228): `import`, `import-product` and the product-data
//! download hash the archive and pin it, linking the devices it serves.

use std::path::Path;

use anyhow::Context as _;
use bussard_model::IndividualAddress;
use bussard_model::schema::{ProductEntry, ProductOrigin};
use bussard_prod::ProductData;
use bussard_service::setup::products;

use crate::console::Console;

/// The `[[product]]` entry for an archive `import-product` or a download
/// read ([`bussard_service::setup::products::archive_entry`]).
pub(crate) fn archive_entry(
    archive: &Path,
    dir: &Path,
    product: &ProductData,
    origin: ProductOrigin,
) -> anyhow::Result<ProductEntry> {
    Ok(products::archive_entry(archive, dir, product, origin)?)
}

/// Extracts each of `applications` from the ETS project export `project`
/// into its own archive under `<dir>/products/` and returns the
/// `[[product]]` entries to pin
/// ([`bussard_service::setup::products::extract_and_entries`]).
pub(crate) fn extract_and_entries(
    dir: &Path,
    project: &Path,
    product: &ProductData,
    applications: &[String],
) -> anyhow::Result<Vec<ProductEntry>> {
    Ok(products::extract_and_entries(
        dir,
        project,
        product,
        applications,
        &mut Console,
    )?)
}

/// Pins `entries` in `<dir>/bussard.lock` and says which devices now point at
/// them. A failure is a warning: the archive is cached either way.
pub(crate) fn pin(dir: &Path, entries: &[ProductEntry]) {
    products::pin(dir, entries, &mut Console);
}

/// `flash --product <file> --force`: stores `file` in `<dir>/products/` (an
/// ETS export is refused: extract it with `import-product`) and makes it the
/// pinned product data of `target`.
pub(crate) fn pin_explicit(
    dir: &Path,
    target: IndividualAddress,
    file: &Path,
) -> anyhow::Result<()> {
    let product = bussard_prod::read_knxprod(file)
        .with_context(|| format!("reading product data from {}", file.display()))?;
    if crate::import_product_cmd::is_project_export(file, &product) {
        anyhow::bail!(
            "--force with an ETS project export: run `bussard import-product {}` to extract \
             its programs into products/ first",
            file.display()
        );
    }
    let stored = crate::product_store::store_file(dir, file)?;
    let entry = archive_entry(
        &stored,
        dir,
        &product,
        ProductOrigin::File {
            path: file.display().to_string(),
        },
    )?;
    if bussard_model::lock_products::pin_device(dir, target, &entry)? {
        println!(
            "pinned {} as the product data of {target} in bussard.lock",
            stored.display()
        );
    }
    Ok(())
}

/// How an explicit `--product` / `--application` contradicts what
/// `bussard.lock` pins for `device` (issue #228, item 4): a product archive
/// with another SHA-256 than the pinned one, or another application than the
/// lock's. `None` when the override agrees, or the lock pins nothing to
/// contradict. An ETS project export is compared by application only: its
/// own hash is never the pinned archive's.
pub(crate) fn override_conflict(
    device: &bussard_model::schema::Device,
    product: Option<&Path>,
    application: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let target = device.address;
    if let (Some(file), Some(entry)) = (product, device.lock.product_entry.as_ref()) {
        let export = file
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("knxproj"));
        if !export && entry.file.is_some() {
            let (sha256, _) = bussard_model::sha256_file(file)
                .with_context(|| format!("hashing {}", file.display()))?;
            if !sha256.eq_ignore_ascii_case(&entry.sha256) {
                return Ok(Some(format!(
                    "--product {} has sha256 {sha256}, but bussard.lock pins {} ({}) as the \
                     product data of {target}",
                    file.display(),
                    entry.sha256,
                    entry.file.as_deref().unwrap_or("?")
                )));
            }
        }
    }
    if let Some(wanted) = application {
        let pinned = bussard_model::identity::LockIdentity::of(device).application;
        if let Some(pinned) = pinned
            && pinned != wanted
        {
            return Ok(Some(format!(
                "--application {wanted} is not the application bussard.lock pins for {target} \
                 ({pinned})"
            )));
        }
    }
    Ok(None)
}

/// Refuses an override that contradicts the lock unless `force`; with
/// `force` an explicit product archive is pinned for the device (a reviewable
/// lock change). `verb` names the command for the refusal.
pub(crate) fn enforce_override(
    dir: &Path,
    device: &bussard_model::schema::Device,
    product: Option<&Path>,
    application: Option<&str>,
    force: bool,
    verb: &str,
) -> anyhow::Result<()> {
    let Some(conflict) = override_conflict(device, product, application)? else {
        return Ok(());
    };
    if !force {
        anyhow::bail!(
            "refusing to {verb} {}: {conflict}. Pass --force to use it anyway (the product \
             archive is then pinned for the device in bussard.lock), or drop the override to \
             use what the lock pins",
            device.address
        );
    }
    eprintln!("warning: {conflict}; --force given, using the override");
    if let Some(file) = product
        && !file
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("knxproj"))
    {
        pin_explicit(dir, device.address, file)?;
    }
    if application.is_some() {
        eprintln!(
            "note: bussard.lock still names its application for {}; re-import the project (or \
             adopt the device again) so the model follows the application you load",
            device.address
        );
    }
    Ok(())
}
