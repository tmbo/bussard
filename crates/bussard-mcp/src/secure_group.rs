//! KNX Data Secure group keys for the MCP server (issue #172).
//!
//! `bussard mcp --keyring` names an ETS `.knxkeys` export; its group keys
//! secure `knx_read_group` / `knx_write_group` on a secured GA and decrypt
//! secured telegrams re-decoded from a capture. The keyring is decrypted once
//! per file version (PBKDF2 is deliberately slow) and cached; a keyring whose
//! modification time or size changes (the key store after `knx_set_group`
//! with `secure`, issue #331) is loaded again, and a failed load is not
//! cached, so fixing `BUSSARD_KEYRING_PASSWORD` needs no restart. Nothing here
//! returns or logs key material.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use bussard_service::{GroupKeys, SecureGroupError};

/// The version of a keyring file the cache holds keys for: its modification
/// time and size.
type FileVersion = (Option<std::time::SystemTime>, u64);

/// The cached keys of one keyring: the file version they were read from.
type CachedKeys = (FileVersion, Arc<GroupKeys>);

/// The decrypted group keys per keyring path, with the file version.
static CACHE: OnceLock<Mutex<HashMap<PathBuf, CachedKeys>>> = OnceLock::new();

/// The current version of the file at `path` (`(None, 0)` when unreadable).
fn file_version(path: &Path) -> FileVersion {
    std::fs::metadata(path)
        .map(|m| (m.modified().ok(), m.len()))
        .unwrap_or((None, 0))
}

/// The group keys of `keyring`, or `None` when the server has no keyring.
///
/// # Errors
///
/// A human reason (naming the file and the cause, never a key) when the
/// keyring cannot be loaded.
pub(crate) fn group_keys(keyring: Option<&Path>) -> Result<Option<Arc<GroupKeys>>, String> {
    let Some(path) = keyring else {
        return Ok(None);
    };
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let version = file_version(path);
    if let Some(keys) = cache.lock().ok().and_then(|c| {
        c.get(path)
            .filter(|(cached, _)| *cached == version)
            .map(|(_, keys)| Arc::clone(keys))
    }) {
        return Ok(Some(keys));
    }
    let keys = bussard_service::secure::load_group_keys(path)
        .map(Arc::new)
        .map_err(|e| {
            let mut reason = e.to_string();
            let mut source = std::error::Error::source(&e);
            while let Some(inner) = source {
                reason.push_str(&format!(": {inner}"));
                source = inner.source();
            }
            reason
        })?;
    if let Ok(mut c) = cache.lock() {
        c.insert(path.to_path_buf(), (version, Arc::clone(&keys)));
    }
    Ok(Some(keys))
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
    bussard_service::secure::load_admission_evidence(path).map_err(|e| {
        let mut reason = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(inner) = source {
            reason.push_str(&format!(": {inner}"));
            source = inner.source();
        }
        reason
    })
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
