//! The CLI's KNX Data Secure tool-key surface (`--keyring`, `--tool-key`;
//! issue #71).
//!
//! The resolver and the secure-layer builder live in
//! [`bussard_service::secure`] so the MCP server (and any other surface) uses
//! the same code; this module re-exports them under the names the device
//! commands already use, plus the operator-facing hints for a device that may
//! be Data Secure-activated.

use bussard_model::IndividualAddress;

pub use bussard_service::secure::{
    KEYRING_PASSWORD_ENV, SecureMaterial, ToolKeySource, layer, resolve, resolve_material,
};

/// The guidance for a device without a tool key that may be Data Secure-activated
/// (issue #71, spec §6.4).
pub(crate) fn no_key_guidance() -> &'static str {
    "if this device is KNX Data Secure-activated it refuses unsecured management — pass its \
     tool key with --keyring <file.knxkeys> (password in BUSSARD_KEYRING_PASSWORD), or \
     --tool-key <32 hex> for a test device"
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
