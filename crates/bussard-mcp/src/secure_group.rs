//! KNX Data Secure group keys for the MCP server (issue #172).
//!
//! `bussard mcp --keyring` names an ETS `.knxkeys` export or the key store;
//! its group keys secure `knx_read_group` / `knx_write_group` on a secured GA
//! and decrypt secured telegrams re-decoded from a capture. The service
//! decrypts a keyring once per file content and password
//! ([`bussard_service::secure::load_keys`]): a key store changed by
//! `knx_set_group` with `secure` (issue #331) is loaded again, and a failed
//! load is not kept, so fixing `BUSSARD_KEYRING_PASSWORD` needs no restart.
//! Nothing here returns or logs key material.

use std::path::Path;
use std::sync::Arc;

use bussard_service::SecureGroupError;
use bussard_service::keys::KeyStore;

/// The error chain of `err` as one human reason (the file and the cause,
/// never a key).
fn reason(err: &dyn std::error::Error) -> String {
    let mut reason = err.to_string();
    let mut source = err.source();
    while let Some(inner) = source {
        reason.push_str(&format!(": {inner}"));
        source = inner.source();
    }
    reason
}

/// The decrypted keyring or key store, or `None` when the server has none.
///
/// # Errors
///
/// A human reason when the keyring cannot be loaded.
pub(crate) fn key_store(keyring: Option<&Path>) -> Result<Option<Arc<KeyStore>>, String> {
    keyring
        .map(|path| bussard_service::secure::load_keys(path).map_err(|e| reason(&e)))
        .transpose()
}

/// The sender admission evidence (issue #297) of the server's keyring: its
/// interface entries. Empty without a keyring. The decrypt is memoized per
/// process by the service, so this costs no second PBKDF2.
///
/// # Errors
///
/// A human reason (naming the file and the cause, never a key) when the
/// keyring cannot be loaded.
pub(crate) fn admission_evidence(
    keyring: Option<&Path>,
) -> Result<bussard_service::admission::AdmissionEvidence, String> {
    let Some(path) = keyring else {
        return Ok(Default::default());
    };
    bussard_service::secure::load_admission_evidence(path).map_err(|e| reason(&e))
}

/// The MCP words for a secured GA without a group key.
pub(crate) fn no_key_reason(err: &SecureGroupError) -> String {
    match err {
        SecureGroupError::NoKey {
            ga,
            keyring_given: true,
        } => format!("group address {ga} is secured but the server has no group key for it"),
        SecureGroupError::NoKey {
            ga,
            keyring_given: false,
        } => format!(
            "group address {ga} is secured: {} (restart `bussard mcp` with it)",
            bussard_service::guidance::group_key_hint()
        ),
    }
}
