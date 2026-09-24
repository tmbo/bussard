//! KNX Data Secure group keys for the MCP server (issue #172).
//!
//! `bussard mcp --keyring` names an ETS `.knxkeys` export; its group keys
//! secure `knx_read_group` / `knx_write_group` on a secured GA and decrypt
//! secured telegrams re-decoded from a capture. The keyring is decrypted once
//! per process (PBKDF2 is deliberately slow) and cached; a failed load is not
//! cached, so fixing `BUSSARD_KEYRING_PASSWORD` needs no restart. Nothing here
//! returns or logs key material.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use bussard_service::{GroupKeys, SecureGroupError};

/// The decrypted group keys per keyring path.
static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<GroupKeys>>>> = OnceLock::new();

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
    if let Some(keys) = cache.lock().ok().and_then(|c| c.get(path).cloned()) {
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
        c.insert(path.to_path_buf(), Arc::clone(&keys));
    }
    Ok(Some(keys))
}

/// The MCP words for a secured GA without a group key.
pub(crate) fn no_key_reason(err: &SecureGroupError) -> String {
    match err {
        SecureGroupError::NoKey {
            ga,
            keyring_given: true,
        } => format!(
            "GA {ga} is secured (KNX Data Secure) but the server's keyring has no group key \
             for it"
        ),
        SecureGroupError::NoKey {
            ga,
            keyring_given: false,
        } => format!(
            "GA {ga} is secured (KNX Data Secure); the server needs `bussard mcp --keyring \
             <file.knxkeys>` (password in BUSSARD_KEYRING_PASSWORD) to read or write it"
        ),
    }
}
