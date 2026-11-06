//! The product data of a model: the retained store `<dir>/products/` (issue
//! #228), the pointer index of vendor downloads, the download step of
//! `import`, `adopt` and the setup, and the `bussard.lock` pins.
//!
//! `apply` and `flash` need the vendor's `.knxprod` for a device's order
//! number, and `validate` reads the product models under
//! `.bussard/models/`. `import` and `adopt` know the order numbers, so they
//! look every one without product data up in the pointer index, ask once for
//! the whole list, download, verify, cache and generate the models, and name
//! what they could not find with the sentence that says where to get it.
//!
//! The download is injectable for tests: `BUSSARD_PRODUCT_INDEX` points at
//! another index, whose entries may use `file://` URLs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use bussard_model::Model;
use bussard_model::schema::{ProductEntry, ProductOrigin};
use bussard_prod::{DownloadConsent, ProductData, ProductIndex, normalize_order_number};

use super::{Context as _, DownloadAnswer, DownloadPrompt, Output, SetupError};

/// The product store under a model directory.
pub const PRODUCTS_DIR: &str = crate::params::PRODUCTS_DIR;

/// The committed pointer index, baked into the binary. Points order numbers at
/// vendor-hosted `.knxprod` downloads (never the payloads themselves).
const PRODUCT_INDEX_JSON: &str = include_str!("../../../../data/product-index.json");

/// The environment variable that points bussard at another pointer index (a
/// JSON file of the same shape), for a private mirror or a test. Unset uses
/// the index baked into the binary.
pub const PRODUCT_INDEX_ENV: &str = "BUSSARD_PRODUCT_INDEX";

/// Loads and parses the pointer index: the file [`PRODUCT_INDEX_ENV`] names,
/// else the committed one.
///
/// # Errors
///
/// The named file cannot be read, or an index does not parse.
pub fn load_index() -> Result<ProductIndex, SetupError> {
    if let Some(path) = bussard_model::dotenv::var_os(PRODUCT_INDEX_ENV).filter(|p| !p.is_empty()) {
        let path = PathBuf::from(path);
        let bytes =
            std::fs::read(&path).ctx(|| format!("reading the product index {}", path.display()))?;
        return ProductIndex::from_json_bytes(&bytes)
            .ctx(|| format!("parsing the product index {}", path.display()));
    }
    ProductIndex::from_json_str(PRODUCT_INDEX_JSON)
        .ctx(|| "parsing the product-data index".to_string())
}

/// Writes `bytes` into `<dir>/products/` under `name` and returns the path.
/// An identical file there is kept; a different file of that name is never
/// overwritten (the store is retained data): the new one gets the first
/// eight hex digits of its hash appended to the stem.
///
/// # Errors
///
/// The store or the file cannot be written.
pub fn store_bytes(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, SetupError> {
    let store = dir.join(PRODUCTS_DIR);
    std::fs::create_dir_all(&store).ctx(|| format!("creating {}", store.display()))?;
    let mut target = store.join(name);
    if let Ok(existing) = std::fs::read(&target) {
        if existing == bytes {
            record_manufacturers(dir, &target);
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
    std::fs::write(&target, bytes).ctx(|| format!("writing {}", target.display()))?;
    record_manufacturers(dir, &target);
    Ok(target)
}

/// Keeps the manufacturer list of the `knx_master.xml` in `archive` (a stored
/// product archive or the ETS project export) in
/// `<dir>/products/manufacturers.toml` and installs the merged list for this
/// process, so every place that names a manufacturer uses it (issue #788).
///
/// Best effort: an archive without a master file adds nothing, and one that
/// does not read is logged and skipped. The archive itself is checked by the
/// command that stores or reads it.
pub fn record_manufacturers(dir: &Path, archive: &Path) {
    let names = match bussard_prod::read_manufacturer_names(archive) {
        Ok(names) => names,
        Err(err) => {
            tracing::warn!(
                "no manufacturer names read from {}: {err}",
                archive.display()
            );
            return;
        }
    };
    if names.is_empty() {
        return;
    }
    match bussard_model::manufacturer_names::merge(dir, names) {
        Ok(merged) => bussard_mgmt::manufacturers::install(merged),
        Err(err) => tracing::warn!("could not keep the manufacturer names: {err}"),
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

/// Downloads (or, for a `file://` pointer, reads) the `.knxprod` an index
/// entry names, verifies its size and SHA-256 against the entry, and stores
/// it under `<dir>/products/`. Returns the stored path.
///
/// `consent` is the caller's proof that the human agreed to the download.
///
/// # Errors
///
/// The download, the verification or the store failed.
pub fn fetch_to_store(
    entry: &bussard_prod::IndexEntry,
    dir: &Path,
    consent: DownloadConsent,
) -> Result<PathBuf, SetupError> {
    let verified = match entry.url.strip_prefix("file://") {
        Some(local) => {
            let bytes = std::fs::read(local).ctx(|| format!("reading {}", entry.url))?;
            bussard_prod::fetch::verify(entry, bytes).map_err(SetupError::source)?
        }
        None => bussard_prod::fetch_entry(entry, consent)
            .ctx(|| format!("downloading {}", entry.url))?,
    };
    store_download(entry, dir, verified)
}

/// Stores a verified download under `<dir>/products/` and returns the path.
///
/// An entry that names an inner `.knxprod` of a ZIP-served download
/// ([`bussard_prod::IndexEntry::inner`]) stores that file under its own name
/// instead of the wrapper: the download's SHA-256 covers it, and the store
/// then holds a plain archive every later command reads without a selection.
/// A download verified by one of its inner `.knxprod` files
/// ([`bussard_prod::Verified::Inner`], a bundle of several products, #711) is
/// stored the same way, as that inner file under its own name.
pub fn store_download(
    entry: &bussard_prod::IndexEntry,
    dir: &Path,
    verified: bussard_prod::Verified,
) -> Result<PathBuf, SetupError> {
    let (name, inner) = match verified {
        bussard_prod::Verified::Inner { name, bytes } => (name, bytes),
        bussard_prod::Verified::Download(bytes) => {
            let Some(name) = &entry.inner else {
                return store_bytes(dir, &entry.filename, &bytes);
            };
            let inner = bussard_prod::inner_knxprod_bytes(&bytes, name, Path::new(&entry.filename))
                .ctx(|| format!("extracting {name} from {}", entry.filename))?;
            (name.clone(), inner)
        }
    };
    let stored = Path::new(&name)
        .file_name()
        .map_or_else(|| name.clone(), |n| n.to_string_lossy().into_owned());
    store_bytes(dir, &stored, &inner)
}

/// Generates the product models of a `.knxprod` already stored under
/// `<dir>/products/`, quietly, then pins the archive in `bussard.lock` under
/// `origin` when one is given (lock v2, issue #228). Returns the model file
/// names written.
///
/// # Errors
///
/// The archive does not read or carries no application program, or a model
/// cannot be written.
pub fn generate_models_pinned(
    file: &Path,
    dir: &Path,
    origin: Option<ProductOrigin>,
    out: &mut dyn Output,
) -> Result<Vec<String>, SetupError> {
    let product = read_in_model_language(file, dir, None)?;
    if product.applications.is_empty() {
        return Err(SetupError::Message(format!(
            "no application programs found in {} (is it a valid .knxprod?)",
            file.display()
        )));
    }
    let written = write_product_models(&product, dir)?;
    if let Some(origin) = origin {
        let entry = archive_entry(file, dir, &product, origin)?;
        pin(dir, &[entry], out);
    }
    Ok(written)
}

/// Reads every application program of `file` with its texts in the model's
/// language (see [`crate::params::model_language`]), so the generated
/// models label enum members as the device files do and a label checked
/// against them (MCP `knx_set_parameter`) resolves in that language (issue
/// #231). Without a recorded language, en-US.
///
/// # Errors
///
/// The archive does not read.
pub fn read_in_model_language(
    file: &Path,
    dir: &Path,
    inner: Option<&str>,
) -> Result<ProductData, SetupError> {
    let language = crate::params::model_language(None, dir);
    bussard_prod::read_knxprod_selected_in(file, inner, None, language.as_deref(), |_| {
        bussard_prod::AppSelection::All
    })
    .ctx(|| format!("reading product data from {}", file.display()))
}

/// Writes one model file per application program under
/// `<dir>/.bussard/models/` (see [`bussard_prod::product_model`]).
///
/// # Errors
///
/// A model file cannot be written.
pub fn write_product_models(product: &ProductData, dir: &Path) -> Result<Vec<String>, SetupError> {
    bussard_prod::product_model::write_product_models(product, dir).map_err(SetupError::source)
}

/// The `[[product]]` entry for an archive `import-product` or a download
/// read: its hash, where it lies in the model (when it does), the
/// applications it carries and every order number its catalogue maps to one.
///
/// # Errors
///
/// The archive cannot be hashed.
pub fn archive_entry(
    archive: &Path,
    dir: &Path,
    product: &ProductData,
    origin: ProductOrigin,
) -> Result<ProductEntry, SetupError> {
    let (sha256, size) =
        bussard_model::sha256_file(archive).ctx(|| format!("hashing {}", archive.display()))?;
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
///
/// # Errors
///
/// The export cannot be hashed or read, or an archive cannot be stored.
pub fn extract_and_entries(
    dir: &Path,
    project: &Path,
    product: &ProductData,
    applications: &[String],
    out: &mut dyn Output,
) -> Result<Vec<ProductEntry>, SetupError> {
    let (project_hash, _) =
        bussard_model::sha256_file(project).ctx(|| format!("hashing {}", project.display()))?;
    let mut entries = Vec::new();
    for app in applications {
        let extracted = match bussard_prod::extract_from_project(project, app) {
            Ok(extracted) => extracted,
            // An application the export does not carry stays unpinned.
            Err(bussard_prod::ProdError::MissingEntry { .. }) => {
                out.warn(&format!(
                    "warning: {} carries no program {app}",
                    project.display()
                ));
                continue;
            }
            Err(err) => {
                return Err(SetupError::Failed {
                    context: format!("extracting {app} from {}", project.display()),
                    source: Box::new(err),
                });
            }
        };
        let stored = store_bytes(dir, &extracted.file_name, &extracted.bytes)?;
        let (sha256, size) =
            bussard_model::sha256_file(&stored).ctx(|| format!("hashing {}", stored.display()))?;
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

/// How an explicit `--product` / `--application` contradicts what
/// `bussard.lock` pins for `device` (issue #228, item 4): a product archive
/// with another SHA-256 than the pinned one, or another application than the
/// lock's. `None` when the override agrees, or the lock pins nothing to
/// contradict. An ETS project export is compared by application only: its
/// own hash is never the pinned archive's.
///
/// # Errors
///
/// The override archive cannot be hashed.
pub fn override_conflict(
    device: &bussard_model::schema::Device,
    selection: crate::params::Selection<'_>,
) -> Result<Option<String>, SetupError> {
    let target = device.address;
    if let (Some(file), Some(entry)) = (selection.product, device.lock.product_entry.as_ref()) {
        let export = file
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("knxproj"));
        if !export && entry.file.is_some() {
            let (sha256, _) =
                bussard_model::sha256_file(file).ctx(|| format!("hashing {}", file.display()))?;
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
    if let Some(wanted) = selection.application {
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

/// The lock-pin rule of a command that writes a device (issue #228, item 4):
/// an override that contradicts the lock ([`override_conflict`]) is refused
/// unless `force`. `Ok(None)` when nothing contradicts the lock;
/// `Ok(Some(conflict))` when `force` lets it through (the caller says so, and
/// pins an explicit product archive for the device). `verb` names the
/// command in the refusal.
///
/// # Errors
///
/// [`SetupError::Message`] with the refusal; the override archive cannot be
/// hashed.
pub fn enforce_override(
    device: &bussard_model::schema::Device,
    selection: crate::params::Selection<'_>,
    force: bool,
    verb: &str,
) -> Result<Option<String>, SetupError> {
    let Some(conflict) = override_conflict(device, selection)? else {
        return Ok(None);
    };
    if !force {
        return Err(SetupError::Message(format!(
            "refusing to {verb} {}: {conflict}. Pass --force to use it anyway (the product \
             archive is then pinned for the device in bussard.lock), or drop the override to \
             use what the lock pins",
            device.address
        )));
    }
    Ok(Some(conflict))
}

/// Pins `entries` in `<dir>/bussard.lock` and says which devices now point at
/// them. A failure is a warning: the archive is cached either way.
pub fn pin(dir: &Path, entries: &[ProductEntry], out: &mut dyn Output) {
    match bussard_model::pin_products(dir, entries) {
        Ok(report) if !report.linked.is_empty() => {
            let list: Vec<String> = report.linked.iter().map(ToString::to_string).collect();
            out.say(&format!(
                "pinned the product data of {} device(s) in bussard.lock: {}",
                list.len(),
                list.join(", ")
            ));
        }
        Ok(_) => {}
        Err(err) => out.warn(&format!(
            "warning: could not record the product data in bussard.lock: {err}"
        )),
    }
}

/// Pins the product data of an ETS project export `import` read: every
/// archive the lock already pins is pinned again (so a device served by a
/// stored vendor archive keeps, or regains, its link), and each application
/// the imported devices use that no stored archive carries is extracted once
/// from the export into `products/` (see [`extract_and_entries`]).
pub fn pin_import(dir: &Path, project: Option<&Path>, model: &Model, out: &mut dyn Output) {
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
            match catalog.map_err(SetupError::source).and_then(|catalog| {
                let apps: Vec<String> = missing.into_iter().collect();
                extract_and_entries(dir, project, &catalog, &apps, out)
            }) {
                Ok(extracted) => {
                    if !extracted.is_empty() {
                        out.say(&format!(
                            "extracted {} application program(s) from {} into {}",
                            extracted.len(),
                            project.display(),
                            dir.join(PRODUCTS_DIR).display()
                        ));
                    }
                    entries.extend(extracted);
                }
                Err(err) => out.warn(&format!(
                    "warning: could not extract the product data from {}: {}",
                    project.display(),
                    error_chain(&err)
                )),
            }
        }
    }
    if !entries.is_empty() {
        pin(dir, &entries, out);
    }
}

/// `err` and its sources joined by `: `, as anyhow's `{:#}` renders a chain.
pub fn error_chain(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// The lock's entries that name an archive the model holds.
fn pinned_archives(dir: &Path) -> Vec<ProductEntry> {
    bussard_model::lock_products::lock_entries(dir)
        .into_iter()
        .filter(|e| e.file.is_some())
        .collect()
}

/// Writes the product model of every application a device in the lock pins
/// that `.bussard/models/` lacks, or only of `only` when given (see
/// [`bussard_prod::product_model::complete_models`]). Failures are warnings.
pub fn complete_models(dir: &Path, only: Option<&str>, out: &mut dyn Output) {
    warn_models(bussard_prod::product_model::complete_models(dir, only), out);
}

/// Writes the product model of every application of every archive the lock
/// pins that `.bussard/models/` lacks, pinned by a device or not (see
/// [`bussard_prod::product_model::complete_all_models`]): what `import` has
/// always written. Failures are warnings.
pub fn complete_all_models(dir: &Path, out: &mut dyn Output) {
    warn_models(bussard_prod::product_model::complete_all_models(dir), out);
}

/// Says the warnings of a model completion.
fn warn_models(warnings: Vec<String>, out: &mut dyn Output) {
    for warning in warnings {
        out.warn(&format!(
            "warning: regenerating the product models: {warning}"
        ));
    }
}

/// What the download step did.
#[derive(Debug, Default)]
pub struct Outcome {
    /// The order numbers now backed by a cached archive, with its path.
    pub fetched: Vec<(String, PathBuf)>,
    /// Order numbers the index does not know.
    pub not_found: Vec<String>,
    /// Order numbers the index knows but that were not downloaded (declined,
    /// skipped, no terminal to ask on, or the download failed), with why.
    pub not_fetched: Vec<(String, String)>,
}

impl Outcome {
    /// Every order number that still has no product data.
    pub fn missing(&self) -> BTreeSet<String> {
        self.not_found
            .iter()
            .cloned()
            .chain(self.not_fetched.iter().map(|(o, _)| o.clone()))
            .collect()
    }
}

/// The normalized order numbers the archives `bussard.lock` pins cover,
/// where the archive is in the model's product store.
pub fn cached_orders(dir: &Path) -> BTreeSet<String> {
    bussard_model::lock_products::lock_entries(dir)
        .into_iter()
        .filter(|e| e.file.as_deref().is_some_and(|f| dir.join(f).is_file()))
        .flat_map(|e| e.order_numbers)
        .map(|o| normalize_order_number(&o))
        .collect()
}

/// The sentence for an order number bussard could not find product data for.
pub fn not_found_sentence(order: &str, dir: &Path) -> String {
    format!(
        "{order}: not in bussard's product index. Download the product data (.knxprod) from \
         the manufacturer's website (or export it from ETS's catalog), then run `bussard \
         import-product <file> --dir {}`.",
        dir.display()
    )
}

/// Looks every order number in `orders` without product data up in the
/// index, asks `prompt` once for the whole list, downloads, caches under
/// `<dir>/products/` and generates the models.
///
/// Never fails the caller's command over a download: a refusal or a failed
/// download is reported in the [`Outcome`] and the command continues without
/// that product's data.
///
/// # Errors
///
/// The index does not load, or the question could not be asked.
pub fn fetch_missing(
    dir: &Path,
    orders: &[String],
    prompt: &mut dyn DownloadPrompt,
    out: &mut dyn Output,
) -> Result<Outcome, SetupError> {
    let cached = cached_orders(dir);
    let mut seen = BTreeSet::new();
    let missing: Vec<String> = orders
        .iter()
        .map(|o| o.trim().to_string())
        .filter(|o| !o.is_empty())
        .filter(|o| !cached.contains(&normalize_order_number(o)))
        .filter(|o| seen.insert(normalize_order_number(o)))
        .collect();
    let mut outcome = Outcome::default();
    if missing.is_empty() {
        return Ok(outcome);
    }
    let index = load_index()?;
    // Group the order numbers by the archive that serves them: one download
    // often covers a whole product family.
    let mut downloads: Vec<(&bussard_prod::IndexEntry, Vec<String>)> = Vec::new();
    for order in &missing {
        match index.lookup(order) {
            Some(entry) => match downloads.iter_mut().find(|(e, _)| e.url == entry.url) {
                Some((_, list)) => list.push(order.clone()),
                None => downloads.push((entry, vec![order.clone()])),
            },
            None => outcome.not_found.push(order.clone()),
        }
    }
    if downloads.is_empty() {
        return Ok(outcome);
    }
    let not_fetched = |why: &str, outcome: &mut Outcome, downloads: &[(_, Vec<String>)]| {
        for (_, list) in downloads {
            for order in list {
                outcome.not_fetched.push((order.clone(), why.to_string()));
            }
        }
    };
    if let Some(why) = prompt.skip_downloads() {
        not_fetched(&why, &mut outcome, &downloads);
        return Ok(outcome);
    }

    let total: u64 = downloads.iter().map(|(e, _)| e.size).sum();
    out.say(&format!(
        "product data missing for {} order number(s); bussard's product index has {} \
         download(s) for them:",
        missing.len(),
        downloads.len()
    ));
    for (entry, list) in &downloads {
        out.say(&format!(
            "  {}: {} {} ({} bytes from {})",
            list.join(", "),
            entry.manufacturer,
            entry.name,
            entry.size,
            entry.url
        ));
    }
    out.say(&format!(
        "These are copyrighted vendor files; they are stored under {} (committing them is \
         your decision).",
        dir.join(PRODUCTS_DIR).display()
    ));
    let question = format!(
        "download {} file(s) ({:.1} MB) now?",
        downloads.len(),
        total as f64 / 1_000_000.0
    );
    let agreed = match prompt.download(&question, downloads.len())? {
        DownloadAnswer::Yes => true,
        DownloadAnswer::No => false,
        DownloadAnswer::Refused(line) => {
            out.say(&line);
            false
        }
    };
    if !agreed {
        not_fetched("not downloaded", &mut outcome, &downloads);
        return Ok(outcome);
    }
    for (entry, list) in downloads {
        let result = fetch_to_store(entry, dir, DownloadConsent::granted()).and_then(|path| {
            let origin = ProductOrigin::Index {
                order_number: list.first().cloned(),
                url: Some(entry.url.clone()),
            };
            generate_models_pinned(&path, dir, Some(origin), out).map(|models| (path, models))
        });
        match result {
            Ok((path, models)) => {
                out.say(&format!(
                    "  cached {} ({} model(s))",
                    path.display(),
                    models.len()
                ));
                for order in list {
                    outcome.fetched.push((order, path.clone()));
                }
            }
            Err(err) => {
                let why = error_chain(&err);
                out.warn(&format!("  download of {} failed: {why}", entry.filename));
                for order in list {
                    outcome
                        .not_fetched
                        .push((order, format!("the download failed: {why}")));
                }
            }
        }
    }
    Ok(outcome)
}

/// Says the end-of-command report: one sentence per order number without
/// product data.
pub fn report_missing(outcome: &Outcome, dir: &Path, out: &mut dyn Output) {
    if outcome.not_found.is_empty() && outcome.not_fetched.is_empty() {
        return;
    }
    out.say("product data still missing:");
    for order in &outcome.not_found {
        out.say(&format!("  {}", not_found_sentence(order, dir)));
    }
    for (order, why) in &outcome.not_fetched {
        out.say(&format!(
            "  {order}: in bussard's product index but {why}; run `bussard import-product \
             --order-number {order} --dir {}` to fetch it.",
            dir.display()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Selection;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn pinned_to(
        application: &str,
    ) -> Result<bussard_model::schema::Device, Box<dyn std::error::Error>> {
        Ok(bussard_model::schema::Device {
            address: "1.1.4".parse()?,
            name: "d".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: Default::default(),
            parameters: Default::default(),
            module_bases: Default::default(),
            com_objects: Default::default(),
            security: None,
            application_override: None,
            knxnet: None,
            lock: bussard_model::schema::DeviceLock {
                application: Some(application.to_string()),
                ..Default::default()
            },
        })
    }

    #[test]
    fn test_enforce_override_refuses_another_application_unless_force() -> TestResult {
        let device = pinned_to("M-00FA_A-0002-01-0000")?;
        let other = Selection {
            product: None,
            application: Some("M-00FA_A-0003-01-0000"),
        };
        let refused = enforce_override(&device, other, false, "flash");
        let Err(SetupError::Message(text)) = refused else {
            return Err(format!("not refused: {refused:?}").into());
        };
        assert!(
            text.starts_with("refusing to flash 1.1.4: --application"),
            "{text}"
        );
        assert!(text.contains("Pass --force"), "{text}");
        let forced = enforce_override(&device, other, true, "flash")?;
        assert!(forced.is_some_and(|c| c.contains("M-00FA_A-0002-01-0000")));
        Ok(())
    }

    #[test]
    fn test_enforce_override_passes_what_the_lock_pins() -> TestResult {
        let device = pinned_to("M-00FA_A-0002-01-0000")?;
        let same = Selection {
            product: None,
            application: Some("M-00FA_A-0002-01-0000"),
        };
        assert!(enforce_override(&device, same, false, "flash")?.is_none());
        assert!(enforce_override(&device, Selection::default(), false, "apply to")?.is_none());
        Ok(())
    }
}
