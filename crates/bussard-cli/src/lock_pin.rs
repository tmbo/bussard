//! Recording the product-data archives a command read in `bussard.lock`
//! (lock v2, issue #228): `import`, `import-product` and the product-data
//! download hash the archive and pin it, linking the devices it serves.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context as _;
use bussard_model::schema::{ProductEntry, ProductOrigin};
use bussard_model::{IndividualAddress, Model};
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
    let order_numbers = orders_for(product, &applications);
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

/// Every order number the catalogue maps to one of `applications`.
fn orders_for(product: &ProductData, applications: &[String]) -> Vec<String> {
    let orders: BTreeSet<String> = product
        .hardware
        .order_to_apps
        .iter()
        .filter(|(_, apps)| apps.iter().any(|a| applications.contains(a)))
        .map(|(order, _)| order.clone())
        .collect();
    orders.into_iter().collect()
}

/// Extracts each of `applications` from the ETS project export `project`
/// into its own archive under `<dir>/products/` (once: an identical archive
/// already there is kept) and returns the `[[product]]` entries to pin,
/// origin `knxproj` with the export's hash. `product` is the export's
/// catalogue (for the order numbers).
pub(crate) fn extract_and_entries(
    dir: &Path,
    project: &Path,
    product: &ProductData,
    applications: &[String],
) -> anyhow::Result<Vec<ProductEntry>> {
    let (project_hash, _) = bussard_model::sha256_file(project)
        .with_context(|| format!("hashing {}", project.display()))?;
    let mut entries = Vec::new();
    for app in applications {
        let extracted = match bussard_prod::extract_from_project(project, app) {
            Ok(extracted) => extracted,
            // An application the export does not carry stays unpinned.
            Err(bussard_prod::ProdError::MissingEntry { .. }) => {
                eprintln!("warning: {} carries no program {app}", project.display());
                continue;
            }
            Err(err) => {
                return Err(anyhow::Error::from(err)
                    .context(format!("extracting {app} from {}", project.display())));
            }
        };
        let stored =
            crate::product_store::store_bytes(dir, &extracted.file_name, &extracted.bytes)?;
        let (sha256, size) = bussard_model::sha256_file(&stored)
            .with_context(|| format!("hashing {}", stored.display()))?;
        let file = stored
            .strip_prefix(dir)
            .ok()
            .map(|rel| rel.to_string_lossy().replace('\\', "/"));
        entries.push(ProductEntry {
            sha256,
            file,
            filename: stored.file_name().map(|n| n.to_string_lossy().into_owned()),
            size: Some(size),
            origin: ProductOrigin::Knxproj {
                path: project.display().to_string(),
                project_hash: Some(project_hash.clone()),
            },
            order_numbers: orders_for(product, &extracted.applications),
            applications: extracted.applications,
        });
    }
    Ok(entries)
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

/// Pins the product data of an ETS project export `import` read: every
/// archive the lock already pins is pinned again (so a device served by a
/// stored vendor archive keeps, or regains, its link), and each application
/// the imported devices use that no stored archive carries is extracted once
/// from the export into `products/` (see [`extract_and_entries`]).
pub(crate) fn pin_import(dir: &Path, project: Option<&Path>, model: &Model) {
    let mut entries = pinned_archives(dir);
    if let Some(project) = project {
        let served: BTreeSet<&String> =
            entries.iter().flat_map(|e| e.applications.iter()).collect();
        let missing: BTreeSet<String> = model
            .devices
            .values()
            .filter_map(|d| d.device.product.as_ref()?.application_ref.clone())
            .filter(|app| !served.contains(app))
            .collect();
        if !missing.is_empty() {
            let catalog = bussard_prod::read_knxprod_selected(project, None, None, |_| {
                bussard_prod::AppSelection::Exact(Vec::new())
            });
            match catalog.map_err(anyhow::Error::from).and_then(|catalog| {
                let apps: Vec<String> = missing.into_iter().collect();
                extract_and_entries(dir, project, &catalog, &apps)
            }) {
                Ok(extracted) => {
                    if !extracted.is_empty() {
                        println!(
                            "extracted {} application program(s) from {} into {}",
                            extracted.len(),
                            project.display(),
                            dir.join(crate::product_store::PRODUCTS_DIR).display()
                        );
                    }
                    entries.extend(extracted);
                }
                Err(err) => eprintln!(
                    "warning: could not extract the product data from {}: {err:#}",
                    project.display()
                ),
            }
        }
    }
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
