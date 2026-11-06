//! The keyring export of `bussard keys export` and `knx_export` (issue
//! #744): the key store `bussard.keys` written as a signed `.knxkeys` ETS
//! accepts, then read back and compared (issue #349). The import side is
//! [`crate::setup::import::import_keyring_with`].
//!
//! Nothing here reports key material: the report is addresses and counts,
//! and the password is never part of a message.

use std::collections::BTreeSet;
use std::path::Path;

use bussard_model::{GroupAddress, Model};
use bussard_project::keystore::{ExportCheck, KeyStore, KeyringExport};

use crate::setup::{Context as _, Output, SetupError};

/// Loads the store in `dir`, failing with a hint when there is none.
///
/// # Errors
///
/// No store, or it does not decrypt with `password`.
pub fn load_existing(dir: &Path, password: &str) -> Result<KeyStore, SetupError> {
    let path = KeyStore::path(dir);
    KeyStore::load(dir, password)
        .ctx(|| format!("loading the key store {}", path.display()))?
        .ok_or_else(|| {
            SetupError::Message(format!(
                "no key store at {}; create it with `bussard keys import <file.knxkeys>`",
                path.display()
            ))
        })
}

/// Writes the store in `dir` as a signed `.knxkeys` ETS accepts, records the
/// export's time (W040, issue #348) and reads the file back (issue #349).
/// An existing `file` is refused unless `force`.
///
/// # Errors
///
/// `file` exists without `force`, there is no store, or the export cannot be
/// built, written or read back.
pub fn export_keyring(
    dir: &Path,
    file: &Path,
    password: &str,
    force: bool,
    out: &mut dyn Output,
) -> Result<KeyringExport, SetupError> {
    if file.exists() && !force {
        return Err(SetupError::Message(format!(
            "{} exists; pass --force to overwrite it",
            file.display()
        )));
    }
    let store = load_existing(dir, password)?;
    let mut export = store
        .export_knxkeys(password)
        .ctx(|| "building the .knxkeys export".to_string())?;
    std::fs::write(file, &export.xml).ctx(|| format!("writing {}", file.display()))?;
    // The export's time, so `validate` can tell when the key store changed
    // after it (W040, issue #348).
    if let Err(err) = bussard_model::KeyStoreMeta::record_export(dir, file) {
        out.warn(&format!("warning: the export was not recorded: {err}"));
    }
    // Verified means read back and compared (issue #349): the file as written,
    // its signature checked, decrypted and its key set compared with the store.
    let written =
        std::fs::read_to_string(file).ctx(|| format!("reading {} back", file.display()))?;
    let check = store
        .check_export(&written, password)
        .ctx(|| format!("reading {} back", file.display()))?;
    export.read_back(&check);
    export.omitted_group_addresses = omitted_group_addresses(dir, &store, &check);
    Ok(export)
}

/// The group addresses the model marks secure or the store keys that the
/// export `check` read back does not carry, ascending. A model that does not
/// load contributes nothing (the store's own keys are still checked).
fn omitted_group_addresses(dir: &Path, store: &KeyStore, check: &ExportCheck) -> Vec<GroupAddress> {
    let mut wanted: BTreeSet<GroupAddress> = store.group_keys.keys().copied().collect();
    if let Ok(model) = Model::load(dir) {
        wanted.extend(
            model
                .groups
                .groups
                .iter()
                .filter(|(_, g)| g.secure)
                .map(|(ga, _)| *ga),
        );
    }
    wanted
        .into_iter()
        .filter(|ga| !check.group_addresses.contains(ga))
        .collect()
}
