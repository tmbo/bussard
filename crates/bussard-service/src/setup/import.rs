//! The fresh import of an ETS export into a model directory: the history
//! snapshot before, the model files, the product data (extracted from the
//! export, downloaded with consent), the keyring next to the project, and the
//! validation summary after. `bussard import` into a fresh directory, `init`
//! and the MCP tool `knx_setup` run it.

use std::path::Path;

use bussard_model::history::{History, SnapshotId, SnapshotReason};
use bussard_model::{Model, Severity};
use bussard_project::keystore::{ImportReport, KeyStore, SaveOutcome};

use super::products::{self, error_chain};
use super::skeleton::{self, KEYRING_PASSWORD_ENV};
use super::{Context as _, DownloadPrompt, Output, SetupError};

/// The environment variable the project password is read from.
pub const PROJECT_PASSWORD_ENV: &str = "BUSSARD_PROJECT_PASSWORD";

/// The project password: `given`, else [`PROJECT_PASSWORD_ENV`] (from the
/// environment or the `.env` bussard reads); an empty value is none.
pub fn resolve_password(given: Option<String>) -> Option<String> {
    given
        .or_else(|| bussard_model::dotenv::var(PROJECT_PASSWORD_ENV).ok())
        .filter(|s| !s.is_empty())
}

/// Loads the project at `path` (a `.knxproj`, or an xknxproject `.json`
/// dump) as a model for `dir`. A password-protected `.knxproj` uses
/// `password` (see [`resolve_password`]); without one, `ask` is asked once.
///
/// # Errors
///
/// [`SetupError::PasswordRequired`] when the project needs a password nobody
/// gave, else the import's own error (wrong password, not an export).
pub fn load_project(
    path: &Path,
    dir: &Path,
    password: Option<String>,
    mut ask: impl FnMut() -> Result<Option<String>, SetupError>,
) -> Result<Model, SetupError> {
    if super::is_json(path) {
        return bussard_project::import_from_json(path).map_err(SetupError::source);
    }
    let password = resolve_password(password);
    let options = bussard_project::ImportOptions::for_dir(dir);
    match bussard_project::import_with(path, password.as_deref(), &options) {
        Ok(model) => Ok(model),
        Err(bussard_project::ImportError::PasswordRequired) => {
            // If we have no password yet and the caller can ask, ask once.
            match password.is_none().then(&mut ask).transpose()?.flatten() {
                Some(pw) => bussard_project::import_with(path, Some(&pw), &options)
                    .map_err(SetupError::source),
                None => Err(SetupError::PasswordRequired),
            }
        }
        Err(e) => Err(SetupError::source(e)),
    }
}

/// Records a snapshot of `dir` before a command writes, warning (never failing)
/// if the history cannot be written.
///
/// Returns the new snapshot's id when one was taken.
pub fn snapshot(dir: &Path, reason: SnapshotReason, out: &mut dyn Output) -> Option<SnapshotId> {
    let history = History::open(dir);
    // An empty or absent directory has no state worth keeping, and snapshotting
    // it would create a model directory where there was none.
    if !history.has_model_files() {
        return None;
    }
    match history.snapshot(reason) {
        Ok(id) => Some(id),
        Err(err) => {
            out.warn(&format!(
                "warning: could not record a history snapshot: {err}"
            ));
            None
        }
    }
}

/// Records an `external edit` snapshot when the working model differs from the
/// latest one, warning (never failing) if the history cannot be written.
pub fn capture_external_edit(dir: &Path, out: &mut dyn Output) {
    match History::open(dir).snapshot_if_changed_externally() {
        Ok(Some(id)) => out.warn(&format!(
            "recorded the current model as history snapshot {id} (external edit)"
        )),
        Ok(None) => {}
        Err(err) => out.warn(&format!(
            "warning: could not record a history snapshot: {err}"
        )),
    }
}

/// What comes before an import writes `dir`: the product models a pinned
/// archive lacks, an `external edit` snapshot of hand edits, and the
/// `before writing the imported model` snapshot `bussard undo` returns to.
pub fn prepare_write(dir: &Path, out: &mut dyn Output) {
    if dir.is_dir() && bussard_prod::product_model::models_incomplete(dir) {
        products::complete_models(dir, None, out);
    }
    before_write(dir, out);
}

/// The two history snapshots of [`prepare_write`].
pub fn before_write(dir: &Path, out: &mut dyn Output) {
    // History (issue #110): record an edit made outside bussard before the
    // import overwrites it, then snapshot the pre-import state so `bussard undo`
    // can put it back.
    capture_external_edit(dir, out);
    snapshot(
        dir,
        SnapshotReason::new("import").with_result("before writing the imported model"),
        out,
    );
}

/// What a fresh import wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    /// Group addresses in `groups.toml`.
    pub groups: usize,
    /// Device files.
    pub devices: usize,
    /// Link entries (com object to group address).
    pub links: usize,
    /// Validation errors of the written model.
    pub errors: usize,
    /// Validation warnings of the written model.
    pub warnings: usize,
}

/// Writes the freshly imported `model` into `dir`, which holds no model
/// content yet, then the product data and the validation summary.
///
/// `project` is the ETS export read, which `bussard.lock` pins as the
/// devices' product source until a vendor archive serves them (lock v2,
/// issue #228). `fetch` runs the product-data download step for the devices'
/// order numbers; `None` skips it (and the pins).
///
/// # Errors
///
/// The model files cannot be written, or the download question failed.
pub fn write_fresh(
    model: Model,
    dir: &Path,
    project: Option<&Path>,
    fetch: Option<&mut dyn DownloadPrompt>,
    out: &mut dyn Output,
) -> Result<Written, SetupError> {
    let mut to_save = model;
    // A group address a device file uses but the plan does not define is
    // declared in groups.toml, named after the object that uses it first.
    let declared = bussard_model::declare_used_groups(&mut to_save);

    // An import writes the files a fresh import would, in the same order,
    // even over a model an older writer laid out differently (issue #235).
    let report = to_save
        .save_pruning_as_import(dir)
        .map_err(SetupError::source)?;
    // A fresh import writes the same `.gitignore` as `init`, so the `.env`
    // with the project password is not committed by accident.
    skeleton::merge_gitignore(&dir.join(".gitignore"), out)?;
    let links = to_save.links.links.values().map(Vec::len).sum::<usize>();
    out.say(&format!(
        "imported {} group addresses, {} devices, {} link entries → {}",
        to_save.groups.groups.len(),
        to_save.devices.len(),
        links,
        skeleton::describe_dir(dir)
    ));
    for d in &declared {
        out.say(&d.sentence());
    }
    knxnet_summary(&to_save, out);
    if !report.renamed.is_empty() {
        out.say(&format!("renamed {} device file(s)", report.renamed.len()));
    }
    if !report.pruned.is_empty() {
        out.say(&format!(
            "pruned {} stale device file(s)",
            report.pruned.len()
        ));
    }

    let (errors, warnings) = after_write(dir, &to_save, project, fetch, out)?;
    Ok(Written {
        groups: to_save.groups.groups.len(),
        devices: to_save.devices.len(),
        links,
        errors,
        warnings,
    })
}

/// The steps after an import wrote (or found unchanged) the model files: the
/// lock pins, the download step, the product models, the validation summary.
/// Returns the error and warning counts of the summary.
///
/// # Errors
///
/// The download question failed.
pub fn after_write(
    dir: &Path,
    model: &Model,
    project: Option<&Path>,
    fetch: Option<&mut dyn DownloadPrompt>,
    out: &mut dyn Output,
) -> Result<(usize, usize), SetupError> {
    // The lock pins where each device's product data comes from.
    if fetch.is_some() {
        products::pin_import(dir, project, model, out);
    }
    // Product data fetches itself: every order number without it is looked up
    // in the pointer index, with one question for the whole list.
    fetch_product_data(dir, model, fetch, out)?;
    // The product models of every pinned archive, in the lock's language, so
    // the first command after an import finds them written (issue #255).
    products::complete_all_models(dir, out);
    // Validation is part of import: the summary says what to fix next.
    Ok(validation_summary(dir, out))
}

/// One line per IP interface whose `[knxnet]` table the model holds (issue
/// #391): the assignment and the tunnel addresses. The project states the
/// assignment only when it is not ETS's default, so a `dhcp` line says it is
/// that default, and every line names the command that reads what the
/// project does not carry (the address in use, the MAC address).
pub fn knxnet_summary(model: &Model, out: &mut dyn Output) {
    for (ia, loaded) in &model.devices {
        let Some(k) = &loaded.device.knxnet else {
            continue;
        };
        let how = match k.assignment {
            bussard_model::knxnet::IpAssignment::Dhcp => {
                "IP assignment dhcp (ETS's default; the project names no other)".to_string()
            }
            bussard_model::knxnet::IpAssignment::Static => format!(
                "static IP address {}",
                k.address.map_or("(none)".to_string(), |a| a.to_string())
            ),
        };
        let tunnels = if k.tunnels.is_empty() {
            "no tunnel addresses".to_string()
        } else {
            format!(
                "tunnel addresses {}",
                bussard_model::knxnet::join_addresses(&k.tunnels)
            )
        };
        out.say(&format!(
            "{ia}: KNXnet/IP settings: {how}, {tunnels}; `bussard status {ia}` reads the \
             address in use and the MAC address from the device"
        ));
    }
}

/// The download step of an import: fetch what is missing, then say how many
/// devices are written without product data and where to get it.
///
/// # Errors
///
/// The index does not load, or the question could not be asked.
pub fn fetch_product_data(
    dir: &Path,
    model: &Model,
    fetch: Option<&mut dyn DownloadPrompt>,
    out: &mut dyn Output,
) -> Result<(), SetupError> {
    let Some(prompt) = fetch else {
        return Ok(());
    };
    let orders: Vec<String> = model
        .devices
        .values()
        .filter_map(|d| d.device.product.as_ref()?.order_number.clone())
        .collect();
    let outcome = products::fetch_missing(dir, &orders, prompt, out)?;
    let missing: std::collections::BTreeSet<String> = outcome
        .missing()
        .iter()
        .map(|o| bussard_prod::normalize_order_number(o))
        .collect();
    let without = model
        .devices
        .values()
        .filter(|d| {
            match d
                .device
                .product
                .as_ref()
                .and_then(|p| p.order_number.as_deref())
            {
                Some(order) => missing.contains(&bussard_prod::normalize_order_number(order)),
                None => true,
            }
        })
        .count();
    if without > 0 {
        out.say(&format!(
            "{without} device(s) written without product data: their files carry identity, \
             location and links by number; `apply` writes their links, not their parameters"
        ));
    }
    products::report_missing(&outcome, dir, out);
    Ok(())
}

/// The one-line validation summary an import says after writing:
/// `validation: 0 error(s), 2 warning(s)`, followed by each error. Returns
/// the error and warning counts.
///
/// Errors never undo the import (the files are what the project says); they
/// are what the owner fixes next, so they are listed with their location.
pub fn validation_summary(dir: &Path, out: &mut dyn Output) -> (usize, usize) {
    let model = match Model::load(dir) {
        Ok(model) => model,
        Err(err) => {
            out.say(&format!(
                "validation: the written model does not load: {err}"
            ));
            return (1, 0);
        }
    };
    let diagnostics = bussard_model::validate_in_dir(&model, dir);
    let count = |s: Severity| diagnostics.iter().filter(|d| d.severity == s).count();
    let (errors, warnings) = (count(Severity::Error), count(Severity::Warning));
    out.say(&format!(
        "validation: {errors} error(s), {warnings} warning(s)"
    ));
    for d in diagnostics.iter().filter(|d| d.severity == Severity::Error) {
        out.say(&format!(
            "  error[{}]: {} ({})",
            d.code, d.message, d.location
        ));
    }
    if errors + warnings > 0 {
        out.say(&format!(
            "  run `bussard validate --dir {}` for the details",
            dir.display()
        ));
    }
    (errors, warnings)
}

/// Whether the key store password is set (a store can be written).
pub fn keyring_password_available() -> bool {
    bussard_model::dotenv::var_os(KEYRING_PASSWORD_ENV).is_some()
}

/// Reads the keyring password from the environment.
fn keyring_password() -> Result<String, SetupError> {
    // The one missing-password wording (issue #228).
    bussard_model::dotenv::var(KEYRING_PASSWORD_ENV)
        .map_err(|_| SetupError::source(crate::secure::SecureKeyError::MissingPassword))
}

/// Merges the ETS keyring `file` into the key store in `dir` and saves it.
///
/// # Errors
///
/// No password, a keyring that does not open with it, or a store that does
/// not load or save.
pub fn import_keyring(dir: &Path, file: &Path) -> Result<(ImportReport, SaveOutcome), SetupError> {
    let password = keyring_password()?;
    let xml =
        std::fs::read_to_string(file).ctx(|| format!("reading keyring {}", file.display()))?;
    let keyring = bussard_project::parse_keyring(&xml, &password).ctx(|| {
        format!(
            "loading keyring {} (the store and the export share {KEYRING_PASSWORD_ENV})",
            file.display()
        )
    })?;
    let path = KeyStore::path(dir);
    let mut store = KeyStore::load(dir, &password)
        .ctx(|| format!("loading the key store {}", path.display()))?
        .unwrap_or_else(|| KeyStore::new(&keyring.project));
    let report = store.merge_keyring(&keyring);
    let outcome = store
        .save(dir, &password)
        .ctx(|| format!("writing the key store {}", path.display()))?;
    Ok((report, outcome))
}

/// W042 (issue #348): the group keys an import added for group addresses the
/// model in `dir` runs plain, each naming the devices the next apply would
/// secure again. Empty without a loadable model.
pub fn rekeyed_warnings(dir: &Path, report: &ImportReport) -> Vec<bussard_model::Diagnostic> {
    let Ok(model) = Model::load(dir) else {
        return Vec::new();
    };
    let added: Vec<bussard_model::GroupAddress> = report
        .group_keys_added
        .iter()
        .filter_map(|ga| ga.parse().ok())
        .collect();
    bussard_model::rekeyed_by_keys_import(&model, &added)
}

/// Says warnings as `warning[CODE]: message`.
pub fn warn_diagnostics(diags: &[bussard_model::Diagnostic], out: &mut dyn Output) {
    for d in diags {
        out.warn(&format!("warning[{}]: {}", d.code, d.message));
    }
}

/// After an import of `project` into `dir`: merges the one `.knxkeys` next to
/// the project into `bussard.keys` (issue #241 item 2). Several exports are
/// listed and none is picked; without the password the command to run is
/// said. Never fails the import: a keyring that does not load is a warning.
/// No key material is ever said: addresses, counts and file names only.
pub fn import_neighbour(project: &Path, dir: &Path, out: &mut dyn Output) {
    let mut found = skeleton::neighbour_keyrings(project);
    match found.len() {
        0 => {}
        1 => {
            let file = found.remove(0);
            if !keyring_password_available() {
                out.say(&format!(
                    "Found the ETS keyring {}. To keep its keys in {}, set {KEYRING_PASSWORD_ENV} and run `bussard keys import {}` (the password is never stored).",
                    file.display(),
                    KeyStore::path(dir).display(),
                    file.display()
                ));
                return;
            }
            match import_keyring(dir, &file) {
                Ok((report, outcome)) => {
                    let what = match outcome {
                        SaveOutcome::Written { backup: false } => "created",
                        SaveOutcome::Written { backup: true } => "updated",
                        SaveOutcome::Unchanged => "already up to date",
                    };
                    out.say(&format!(
                        "Imported the ETS keyring {} into {} ({what}: {} device(s) added, {} tool key(s) rotated, {} group key(s) added, {} rotated). It is encrypted with {KEYRING_PASSWORD_ENV}; keep that password, bussard never stores it.",
                        file.display(),
                        KeyStore::path(dir).display(),
                        report.devices_added.len(),
                        report.tool_keys_rotated.len(),
                        report.group_keys_added.len(),
                        report.group_keys_rotated.len(),
                    ));
                    warn_diagnostics(&rekeyed_warnings(dir, &report), out);
                }
                Err(err) => out.warn(&format!(
                    "warning: the ETS keyring {} was not imported into the key store: {}",
                    file.display(),
                    error_chain(&err)
                )),
            }
        }
        _ => {
            out.say(
                "Found several ETS keyrings next to the project; import the current one with `bussard keys import <file>`:",
            );
            for p in &found {
                out.say(&format!("  {}", p.display()));
            }
        }
    }
}
