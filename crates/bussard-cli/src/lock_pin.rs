//! Recording the product-data archives a command read in `bussard.lock`
//! (lock v2, issue #228): `import`, `import-product` and the product-data
//! download hash the archive and pin it, linking the devices it serves.

use std::path::Path;

use anyhow::Context as _;
use bussard_model::IndividualAddress;
use bussard_model::schema::{ProductEntry, ProductOrigin};
use bussard_prod::ProductData;
use bussard_service::params::Selection;
use bussard_service::setup::products;

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
/// `bussard.lock` pins for `device`
/// ([`bussard_service::setup::products::override_conflict`]).
pub(crate) fn override_conflict(
    device: &bussard_model::schema::Device,
    product: Option<&Path>,
    application: Option<&str>,
) -> anyhow::Result<Option<String>> {
    Ok(products::override_conflict(
        device,
        Selection {
            product,
            application,
        },
    )?)
}

/// Refuses an override that contradicts the lock unless `force`
/// ([`bussard_service::setup::products::enforce_override`], the rule the MCP
/// tier shares); with `force` an explicit product archive is pinned for the
/// device (a reviewable lock change). `verb` names the command for the
/// refusal.
pub(crate) fn enforce_override(
    dir: &Path,
    device: &bussard_model::schema::Device,
    product: Option<&Path>,
    application: Option<&str>,
    force: bool,
    verb: &str,
) -> anyhow::Result<()> {
    let selection = Selection {
        product,
        application,
    };
    let Some(conflict) = products::enforce_override(device, selection, force, verb)? else {
        return Ok(());
    };
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
