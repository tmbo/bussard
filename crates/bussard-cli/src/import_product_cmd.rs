//! The `bussard import-product` subcommand: record vendor product data in the
//! model's product store and generate its product models.
//!
//! Reads a `.knxprod` (see `bussard-prod`), stores the original byte-identical
//! under `<dir>/products/` (retained model data, see
//! [`crate::product_store`]), pins it in `bussard.lock`, and writes one
//! machine-generated product model per ApplicationProgram under
//! `<dir>/.bussard/models/` (regenerated from the archive whenever it is
//! missing).
//!
//! An ETS project export (`.knxproj`) also carries the product data of every
//! device in the project. Each application program is extracted from it once
//! into its own archive under `products/` (`<application-id>.knxprod`,
//! see [`bussard_prod::extract_from_project`]); the export itself is never
//! copied.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_prod::{DownloadConsent, ProductData, ProductIndex};

/// The committed pointer index, baked into the binary. Points order numbers at
/// vendor-hosted `.knxprod` downloads (never the payloads themselves).
const PRODUCT_INDEX_JSON: &str = include_str!("../../../data/product-index.json");

/// Dispatches the three `import-product` modes:
///
/// * `--list`: print the pointer index and exit.
/// * `--order-number`: look the file up in the index, confirm, download,
///   verify, then run the normal import on the downloaded file.
/// * positional FILE: run the normal import on a local `.knxprod`.
pub fn run(
    file: Option<&Path>,
    dir: &Path,
    order_number: Option<&str>,
    yes_download: bool,
    inner: Option<&str>,
    list: bool,
) -> anyhow::Result<ExitCode> {
    if list {
        return run_list();
    }
    if let Some(order) = order_number {
        return run_order_number(order, dir, yes_download, inner);
    }
    match file {
        Some(f) => run_file(f, dir, inner),
        None => bail!(
            "nothing to import: give a .knxprod FILE, --order-number <ORDER> to \
             download from the index, or --list to show the index"
        ),
    }
}

/// Prints the pointer index in a compact table.
fn run_list() -> anyhow::Result<ExitCode> {
    let index = load_index()?;
    if index.entries.is_empty() {
        println!("The product-data pointer index is empty.");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "Product-data pointer index ({} entr{}):",
        index.entries.len(),
        if index.entries.len() == 1 { "y" } else { "ies" }
    );
    println!();
    for e in &index.entries {
        println!("{} — {}", e.manufacturer, e.name);
        println!("  order numbers: {}", e.order_numbers.join(", "));
        println!("  file: {} ({} bytes)", e.filename, e.size);
        println!("  from: {}", e.url);
        if let Some(notes) = &e.notes {
            println!("  notes: {notes}");
        }
        println!();
    }
    println!("Import one with:  bussard import-product --order-number <ORDER> [--yes-download]");
    Ok(ExitCode::SUCCESS)
}

/// Looks an order number up in the index, confirms, downloads and verifies the
/// `.knxprod`, then runs the normal import on the cached file.
fn run_order_number(
    order: &str,
    dir: &Path,
    yes_download: bool,
    inner: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let index = load_index()?;
    let entry = index.lookup(order).with_context(|| {
        format!(
            "no product-data entry for order number `{order}` in the index. \
             Run `bussard import-product --list` to see what's available, or \
             pass the .knxprod file directly if you already have it."
        )
    })?;

    // Show what and where-from before any network access.
    println!("Found in the product-data index:");
    println!("  {} — {}", entry.manufacturer, entry.name);
    println!("  order number: {order}");
    println!("  download:     {}", entry.url);
    println!("  file:         {} ({} bytes)", entry.filename, entry.size);
    println!("  sha256:       {}", entry.sha256);
    println!();
    println!(
        "This downloads copyrighted vendor product data over the network. It is \
         stored under {}/products/; whether that directory is committed is your \
         decision (see docs/product-data.md).",
        dir.display()
    );

    if !confirm_download(yes_download)? {
        println!("Aborted; nothing downloaded.");
        return Ok(ExitCode::FAILURE);
    }

    println!("Downloading…");
    let bytes = bussard_prod::fetch_entry(entry, DownloadConsent::granted())
        .context("downloading product data")?;
    println!("Downloaded and verified {} bytes.", bytes.len());

    // Store the download under <dir>/products/, then import from there.
    let cached = crate::product_store::store_bytes(dir, &entry.filename, &bytes)?;

    import_from_file(
        &cached,
        dir,
        inner,
        DownloadNote::Downloaded(bussard_model::schema::ProductOrigin::Index {
            order_number: Some(order.to_string()),
            url: Some(entry.url.clone()),
        }),
    )
}

/// Asks the download question on a TTY; without one it needs
/// `--yes-download` (the one download-consent flag, `crate::confirm`).
fn confirm_download(yes_download: bool) -> anyhow::Result<bool> {
    match crate::confirm::download(yes_download, "Download this file?")? {
        crate::confirm::Download::Yes => Ok(true),
        crate::confirm::Download::No => Ok(false),
        crate::confirm::Download::NoTerminal => {
            bail!("{}", crate::confirm::download_refusal("this file"))
        }
    }
}

/// The environment variable that points bussard at another pointer index (a
/// JSON file of the same shape), for a private mirror or a test. Unset uses
/// the index baked into the binary.
pub(crate) const PRODUCT_INDEX_ENV: &str = "BUSSARD_PRODUCT_INDEX";

/// Loads and parses the pointer index: the file [`PRODUCT_INDEX_ENV`] names,
/// else the committed one.
pub(crate) fn load_index() -> anyhow::Result<ProductIndex> {
    if let Some(path) = bussard_model::dotenv::var_os(PRODUCT_INDEX_ENV).filter(|p| !p.is_empty()) {
        let path = std::path::PathBuf::from(path);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading the product index {}", path.display()))?;
        return ProductIndex::from_json_bytes(&bytes)
            .with_context(|| format!("parsing the product index {}", path.display()));
    }
    ProductIndex::from_json_str(PRODUCT_INDEX_JSON).context("parsing the product-data index")
}

/// Downloads (or, for a `file://` pointer, reads) the `.knxprod` an index
/// entry names, verifies its size and SHA-256 against the entry, and stores
/// it under `<dir>/products/`. Returns the stored path.
///
/// `consent` is the caller's proof that the human agreed to the download.
pub(crate) fn fetch_to_store(
    entry: &bussard_prod::IndexEntry,
    dir: &Path,
    consent: DownloadConsent,
) -> anyhow::Result<std::path::PathBuf> {
    let bytes = match entry.url.strip_prefix("file://") {
        Some(local) => {
            let bytes = std::fs::read(local).with_context(|| format!("reading {}", entry.url))?;
            bussard_prod::fetch::verify(entry, &bytes)?;
            bytes
        }
        None => bussard_prod::fetch_entry(entry, consent)
            .with_context(|| format!("downloading {}", entry.url))?,
    };
    crate::product_store::store_bytes(dir, &entry.filename, &bytes)
}

/// Generates the product models of a `.knxprod` already stored under
/// `<dir>/products/`, quietly, then pins the archive in `bussard.lock` under
/// `origin` when one is given (lock v2, issue #228). Returns the model file
/// names written.
pub(crate) fn generate_models_pinned(
    file: &Path,
    dir: &Path,
    origin: Option<bussard_model::schema::ProductOrigin>,
) -> anyhow::Result<Vec<String>> {
    let product = read_in_model_language(file, dir, None)?;
    if product.applications.is_empty() {
        bail!(
            "no application programs found in {} (is it a valid .knxprod?)",
            file.display()
        );
    }
    let written = write_product_models(&product, dir)?;
    if let Some(origin) = origin {
        let entry = crate::lock_pin::archive_entry(file, dir, &product, origin)?;
        crate::lock_pin::pin(dir, &[entry]);
    }
    Ok(written)
}

/// Reads every application program of `file` with its texts in the model's
/// language (see [`crate::product_cache::model_language`]), so the generated
/// models label enum members as the device files do and a label checked
/// against them (MCP `knx_set_parameter`) resolves in that language (issue
/// #231). Without a recorded language, en-US.
fn read_in_model_language(
    file: &Path,
    dir: &Path,
    inner: Option<&str>,
) -> anyhow::Result<ProductData> {
    let language = crate::product_cache::model_language(None, dir);
    bussard_prod::read_knxprod_selected_in(file, inner, None, language.as_deref(), |_| {
        bussard_prod::AppSelection::All
    })
    .with_context(|| format!("reading product data from {}", file.display()))
}

/// Writes one model file per application program under
/// `<dir>/.bussard/models/` (see [`bussard_prod::product_model`]).
pub(crate) fn write_product_models(
    product: &ProductData,
    dir: &Path,
) -> anyhow::Result<Vec<String>> {
    Ok(bussard_prod::product_model::write_product_models(
        product, dir,
    )?)
}

/// Where a to-be-imported file came from, for the report line.
enum DownloadNote {
    /// A local positional file (copied into the product store).
    Local,
    /// Downloaded from the index and already stored under `products/`
    /// (verified against the index checksum); carries the lock's origin
    /// record.
    Downloaded(bussard_model::schema::ProductOrigin),
}

/// Runs the normal import on a local `.knxprod` file (positional mode).
fn run_file(file: &Path, dir: &Path, inner: Option<&str>) -> anyhow::Result<ExitCode> {
    if !file.exists() {
        bail!("product file not found: {}", file.display());
    }
    import_from_file(file, dir, inner, DownloadNote::Local)
}

/// Imports product data: stores the archive under `<dir>/products/`, pins it
/// in `bussard.lock` and generates a product model under
/// `<dir>/.bussard/models/` for each application program it contains.
///
/// A downloaded file is already in the store. An ETS project export (see
/// [`is_project_export`]) is not copied: each of its application programs is
/// extracted once into its own archive in the store.
fn import_from_file(
    file: &Path,
    dir: &Path,
    inner: Option<&str>,
    note: DownloadNote,
) -> anyhow::Result<ExitCode> {
    let product = read_in_model_language(file, dir, inner)?;

    if product.applications.is_empty() {
        bail!(
            "no application programs found in {} (is it a valid .knxprod?)",
            file.display()
        );
    }
    crate::product_store::prepare(dir);

    // Only a local file can be an export; an index download is vendor data.
    let project_export = matches!(note, DownloadNote::Local) && is_project_export(file, &product);
    let (stored_note, entries) = if project_export {
        let apps: Vec<String> = product
            .applications
            .iter()
            .filter(|a| !a.is_pei_program())
            .map(|a| a.id.clone())
            .collect();
        let entries = crate::lock_pin::extract_and_entries(dir, file, &product, &apps)?;
        (
            format!(
                "Extracted {} application program(s) from the ETS project export {} into {}",
                entries.len(),
                file.display(),
                dir.join(crate::product_store::PRODUCTS_DIR).display()
            ),
            entries,
        )
    } else {
        let (stored, origin, what) = match note {
            DownloadNote::Downloaded(origin) => (file.to_path_buf(), origin, "downloaded"),
            DownloadNote::Local => (
                crate::product_store::store_file(dir, file)?,
                bussard_model::schema::ProductOrigin::File {
                    path: file.display().to_string(),
                },
                "supplied",
            ),
        };
        let entry = crate::lock_pin::archive_entry(&stored, dir, &product, origin)?;
        (
            format!("Stored vendor file ({what}): {}", stored.display()),
            vec![entry],
        )
    };

    let models_dir = dir.join(bussard_model::param_model::MODELS_DIR);
    let written = write_product_models(&product, dir)?;
    crate::lock_pin::pin(dir, &entries);

    // Report.
    println!("{stored_note}");
    println!(
        "Generated {} product model{} in {}:",
        written.len(),
        if written.len() == 1 { "" } else { "s" },
        models_dir.display()
    );
    for name in &written {
        println!("  {}/{name}", bussard_model::param_model::MODELS_DIR);
    }
    println!();
    println!(
        "{} holds copyrighted vendor product data and is retained model data: bussard never \
         regenerates it. Whether it is committed is your decision (a private repository is \
         the usual case); the product models under .bussard/ regenerate from it.",
        dir.join(crate::product_store::PRODUCTS_DIR).display()
    );

    Ok(ExitCode::SUCCESS)
}

/// Whether `file` is an ETS project export (`.knxproj`) rather than vendor
/// product data: by its extension (case-insensitive) or by the `P-XXXX`
/// project folder the reader found in the archive.
pub(crate) fn is_project_export(file: &Path, product: &ProductData) -> bool {
    product.is_project_export
        || file
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("knxproj"))
}
