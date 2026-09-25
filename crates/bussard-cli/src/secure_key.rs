//! The CLI's KNX Data Secure tool-key surface (`--keyring`, `--tool-key`;
//! issue #71).
//!
//! The resolver and the secure-layer builder live in
//! [`bussard_service::secure`] so the MCP server (and any other surface) uses
//! the same code; this module re-exports them under the names the device
//! commands already use, plus the operator-facing hints for a device that may
//! be Data Secure-activated.

use std::path::Path;

use anyhow::Context;
use bussard_model::IndividualAddress;
use bussard_service::GroupKeys;

pub use bussard_service::secure::{
    KEYRING_PASSWORD_ENV, SecureKeyError, SecureMaterial, ToolKeySource, layer, model_activated,
};

/// [`bussard_service::secure::resolve`], timed as the `--timing` phase
/// `tool keys` (issue #214).
///
/// # Errors
///
/// As [`bussard_service::secure::resolve`].
pub fn resolve(
    target: IndividualAddress,
    source: ToolKeySource<'_>,
    activated: bool,
) -> Result<Option<bussard_secure::Key16>, SecureKeyError> {
    crate::timing::time("tool keys", || {
        bussard_service::secure::resolve(target, source, activated)
    })
}

/// [`bussard_service::secure::resolve_material`], timed as the `--timing`
/// phase `tool keys` (issue #214).
///
/// # Errors
///
/// As [`bussard_service::secure::resolve_material`].
pub fn resolve_material(
    target: IndividualAddress,
    source: ToolKeySource<'_>,
    activated: bool,
) -> Result<SecureMaterial, SecureKeyError> {
    crate::timing::time("tool keys", || {
        bussard_service::secure::resolve_material(target, source, activated)
    })
}

/// The guidance for a device without a tool key that may be Data Secure-activated
/// (issue #71, spec §6.4).
pub(crate) fn no_key_guidance() -> &'static str {
    "if this device is KNX Data Secure-activated it refuses unsecured management — pass its \
     tool key with --keyring <file.knxkeys> (password in BUSSARD_KEYRING_PASSWORD; a keyring \
     that does not list the device only opens the tunnel, so export a current one from ETS), \
     or --tool-key <32 hex> for a test device"
}

/// Adds KNX Data Secure guidance to a failed management session (issue #71,
/// spec §6.4).
///
/// An activated device drops a management APDU it cannot accept, which reaches
/// us as a disconnect or a silence — identical for "no tool key" and "wrong tool
/// key", so the hint names whichever cause is still open.
pub(crate) fn secure_hint(
    target: IndividualAddress,
    presented_tool_key: bool,
    err: anyhow::Error,
) -> anyhow::Error {
    if presented_tool_key {
        err.context(format!(
            "{target} did not answer the SECURED management access: either the tool key is not \
             this device's key, or the device is not security-activated and ignores A_SecureData \
             (retry without --keyring/--tool-key)"
        ))
    } else {
        err.context(format!("{target} did not answer: {}", no_key_guidance()))
    }
}

/// Loads the group keys of `--keyring` for secured group communication
/// (issue #172), or `None` without a keyring. The password comes from
/// [`KEYRING_PASSWORD_ENV`]; the error names the file, never a key.
pub fn group_keys(keyring: Option<&Path>) -> anyhow::Result<Option<GroupKeys>> {
    let Some(path) = keyring else {
        return Ok(None);
    };
    let keys = bussard_service::secure::load_group_keys(path)
        .with_context(|| format!("loading group keys from {}", path.display()))?;
    Ok(Some(keys))
}

/// The CLI's words for a secured GA without a group key.
pub fn no_group_key_hint(ga: bussard_model::GroupAddress, keyring_given: bool) -> String {
    if keyring_given {
        format!(
            "GA {ga} is secured (KNX Data Secure) but the keyring has no group key for it; \
             export a current keyring from ETS"
        )
    } else {
        format!(
            "GA {ga} is secured (KNX Data Secure, `secure: true` in groups.toml); pass \
             --keyring <file.knxkeys> with {KEYRING_PASSWORD_ENV} set to send it secured"
        )
    }
}
