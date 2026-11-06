//! `bussard import-product` and the product form of `knx_import_file`
//! (issue #743): vendor product data into the retained store
//! `<dir>/products/`, pinned in `bussard.lock`, with one product model per
//! application program under `<dir>/.bussard/model-cache/`. The store, the index
//! and the download are [`crate::setup::products`].
//!
//! An ETS project export (`.knxproj`) also carries the product data of every
//! device in the project. Each application program is extracted from it once
//! into its own archive under `products/` (`<application-id>.knxprod`, see
//! [`bussard_prod::extract_from_project`]); the export itself is never
//! copied.

use std::path::{Path, PathBuf};

use bussard_model::schema::ProductOrigin;
use bussard_prod::{DownloadConsent, ProductData};

use crate::setup::products::{self as store, PRODUCTS_DIR};
use crate::setup::{Context as _, DownloadAnswer, DownloadPrompt, Output, SetupError};

/// The directory earlier versions cached vendor archives in; its archives
/// move to [`PRODUCTS_DIR`] on the first command after the upgrade.
const LEGACY_VENDOR_DIR: &str = "vendor";

/// Copies `src` into the store under its own file name (see
/// [`store::store_bytes`]). A file already in the store is returned as it is.
///
/// # Errors
///
/// `src` cannot be read or the copy written.
pub fn store_file(dir: &Path, src: &Path) -> Result<PathBuf, SetupError> {
    let store_dir = dir.join(PRODUCTS_DIR);
    if src.parent().is_some_and(|p| same_dir(p, &store_dir)) {
        store::record_manufacturers(dir, src);
        return Ok(src.to_path_buf());
    }
    let name = src
        .file_name()
        .ok_or_else(|| SetupError::Message("product file has no file name".to_string()))?
        .to_string_lossy()
        .into_owned();
    let bytes = std::fs::read(src).ctx(|| format!("reading {}", src.display()))?;
    store::store_bytes(dir, &name, &bytes)
}

/// Whether two directories are the same (canonical paths when they exist).
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
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
/// - When an application a device in the lock pins has no
///   `.bussard/model-cache/<app>.json` (the directory is absent, empty or partly
///   deleted), the missing models are regenerated from the archives that
///   carry them (issues #267, #356). Checking costs one `stat` per pinned
///   application.
///
/// Failures are warnings: the command itself reports what it cannot do.
pub fn prepare(dir: &Path, out: &mut dyn Output) {
    if let Err(err) = migrate_vendor(dir, out) {
        out.warn(&format!(
            "warning: moving vendor/ into products/: {}",
            store::error_chain(&err)
        ));
    }
    if bussard_prod::product_model::models_incomplete(dir) {
        store::complete_models(dir, None, out);
    }
}

/// Moves `vendor/*.knxprod` into `products/` and pins each one.
fn migrate_vendor(dir: &Path, out: &mut dyn Output) -> Result<(), SetupError> {
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
    let index = store::load_index().ok();
    let mut entries = Vec::new();
    for old in &archives {
        let moved = store_file(dir, old)?;
        std::fs::remove_file(old).ctx(|| format!("removing {}", old.display()))?;
        out.warn(&format!(
            "moved {} to {} (product data is retained model data now)",
            old.display(),
            moved.display()
        ));
        let product = bussard_prod::read_knxprod(&moved)
            .ctx(|| format!("reading product data from {}", moved.display()))?;
        let (sha, _) = bussard_model::sha256_file(&moved).map_err(SetupError::source)?;
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
        entries.push(store::archive_entry(&moved, dir, &product, origin)?);
        store::write_product_models(&product, dir)?;
    }
    if !entries.is_empty() {
        bussard_model::pin_products(dir, &entries).map_err(SetupError::source)?;
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

/// Whether `file` is an ETS project export (`.knxproj`) rather than vendor
/// product data: by its extension (case-insensitive) or by the `P-XXXX`
/// project folder the reader found in the archive.
pub fn is_project_export(file: &Path, product: &ProductData) -> bool {
    product.is_project_export
        || file
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("knxproj"))
}

/// What an `import-product` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductImport {
    /// Where the archive went (or what was extracted from an export), as the
    /// sentence the command says.
    pub stored: String,
    /// The product model files written, by name.
    pub models: Vec<String>,
    /// The archive in the store, for vendor product data; `None` for an ETS
    /// project export, whose programs were extracted into archives of their
    /// own (found by order number through the lock).
    pub archive: Option<PathBuf>,
}

/// How an `import-product --order-number` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderImport {
    /// The operator declined the download; nothing was fetched.
    Declined,
    /// Downloaded, verified and imported.
    Imported(ProductImport),
}

/// Imports a local `.knxprod` (or a `.knxproj`, whose programs are
/// extracted): `import-product <file>`.
///
/// # Errors
///
/// The file is missing or unreadable, carries no application program, or
/// the store, lock or models cannot be written.
pub fn import_product_file(
    file: &Path,
    dir: &Path,
    inner: Option<&str>,
    out: &mut dyn Output,
) -> Result<ProductImport, SetupError> {
    if !file.exists() {
        return Err(SetupError::Message(format!(
            "product file not found: {}",
            file.display()
        )));
    }
    import_from_file(file, dir, inner, DownloadNote::Local, out)
}

/// `import-product --order-number`: looks the order number up in the index,
/// says what and where from, asks `prompt` (the one question, for one file),
/// downloads and verifies the `.knxprod`, then imports it.
///
/// # Errors
///
/// No entry for `order`, nobody to ask (the prompt's refusal sentence), a
/// failed download, or the import itself.
pub fn import_product_order(
    order: &str,
    dir: &Path,
    inner: Option<&str>,
    prompt: &mut dyn DownloadPrompt,
    out: &mut dyn Output,
) -> Result<OrderImport, SetupError> {
    let index = store::load_index()?;
    let entry = index.lookup(order).ok_or_else(|| {
        SetupError::Message(format!(
            "no product-data entry for order number `{order}` in the index. \
             Run `bussard import-product --list` to see what's available, or \
             pass the .knxprod file directly if you already have it."
        ))
    })?;

    // Say what and where-from before any network access.
    out.say("Found in the product-data index:");
    out.say(&format!("  {} — {}", entry.manufacturer, entry.name));
    out.say(&format!("  order number: {order}"));
    out.say(&format!("  download:     {}", entry.url));
    out.say(&format!(
        "  file:         {} ({} bytes)",
        entry.filename, entry.size
    ));
    out.say(&format!("  sha256:       {}", entry.sha256));
    out.say("");
    out.say(&format!(
        "This downloads copyrighted vendor product data over the network. It is \
         stored under {}/products/; whether that directory is committed is your \
         decision (see docs/reference/product-data.md).",
        dir.display()
    ));

    match prompt.download("Download this file?", 1)? {
        DownloadAnswer::Yes => {}
        DownloadAnswer::No => {
            out.say("Aborted; nothing downloaded.");
            return Ok(OrderImport::Declined);
        }
        DownloadAnswer::Refused(line) => return Err(SetupError::Message(line)),
    }

    out.say("Downloading…");
    let verified = bussard_prod::fetch_entry(entry, DownloadConsent::granted())
        .ctx(|| "downloading product data".to_string())?;
    match &verified {
        bussard_prod::Verified::Download(bytes) => {
            out.say(&format!("Downloaded and verified {} bytes.", bytes.len()));
        }
        bussard_prod::Verified::Inner { name, bytes } => out.say(&format!(
            "Downloaded a ZIP of several products; verified {name} ({} bytes) inside it.",
            bytes.len()
        )),
    }

    // Store the download under <dir>/products/, then import from there.
    let cached = store::store_download(entry, dir, verified)?;
    import_from_file(
        &cached,
        dir,
        inner,
        DownloadNote::Downloaded(ProductOrigin::Index {
            order_number: Some(order.to_string()),
            url: Some(entry.url.clone()),
        }),
        out,
    )
    .map(OrderImport::Imported)
}

/// Where a to-be-imported file came from, for the report line.
enum DownloadNote {
    /// A local positional file (copied into the product store).
    Local,
    /// Downloaded from the index and already stored under `products/`
    /// (verified against the index checksum); carries the lock's origin
    /// record.
    Downloaded(ProductOrigin),
}

/// Imports product data: stores the archive under `<dir>/products/`, pins it
/// in `bussard.lock` and generates a product model under
/// `<dir>/.bussard/model-cache/` for each application program it contains.
///
/// A downloaded file is already in the store. An ETS project export (see
/// [`is_project_export`]) is not copied: each of its application programs is
/// extracted once into its own archive in the store.
fn import_from_file(
    file: &Path,
    dir: &Path,
    inner: Option<&str>,
    note: DownloadNote,
    out: &mut dyn Output,
) -> Result<ProductImport, SetupError> {
    let product = store::read_in_model_language(file, dir, inner)?;

    if product.applications.is_empty() {
        return Err(SetupError::Message(format!(
            "no application programs found in {} (is it a valid .knxprod?)",
            file.display()
        )));
    }
    prepare(dir, out);

    // Only a local file can be an export; an index download is vendor data.
    let project_export = matches!(note, DownloadNote::Local) && is_project_export(file, &product);
    let (stored_note, entries, archive) = if project_export {
        let apps: Vec<String> = product
            .applications
            .iter()
            .filter(|a| !a.is_pei_program())
            .map(|a| a.id.clone())
            .collect();
        let entries = store::extract_and_entries(dir, file, &product, &apps, out)?;
        (
            format!(
                "Extracted {} application program(s) from the ETS project export {} into {}",
                entries.len(),
                file.display(),
                dir.join(PRODUCTS_DIR).display()
            ),
            entries,
            None,
        )
    } else {
        let (stored, origin, what) = match note {
            DownloadNote::Downloaded(origin) => (file.to_path_buf(), origin, "downloaded"),
            DownloadNote::Local => (
                store_file(dir, file)?,
                ProductOrigin::File {
                    path: file.display().to_string(),
                },
                "supplied",
            ),
        };
        let entry = store::archive_entry(&stored, dir, &product, origin)?;
        (
            format!("Stored vendor file ({what}): {}", stored.display()),
            vec![entry],
            Some(stored),
        )
    };

    let models_dir = dir.join(bussard_model::param_model::MODEL_CACHE_DIR);
    let written = store::write_product_models(&product, dir)?;
    store::pin(dir, &entries, out);

    out.say(&stored_note);
    out.say(&format!(
        "Generated {} product model{} in {}:",
        written.len(),
        if written.len() == 1 { "" } else { "s" },
        models_dir.display()
    ));
    for name in &written {
        out.say(&format!(
            "  {}/{name}",
            bussard_model::param_model::MODEL_CACHE_DIR
        ));
    }
    out.say("");
    out.say(&format!(
        "{} holds copyrighted vendor product data and is retained model data: bussard never \
         regenerates it. Whether it is committed is your decision (a private repository is \
         the usual case); the product models under .bussard/ regenerate from it.",
        dir.join(PRODUCTS_DIR).display()
    ));

    Ok(ProductImport {
        stored: stored_note,
        models: written,
        archive,
    })
}
