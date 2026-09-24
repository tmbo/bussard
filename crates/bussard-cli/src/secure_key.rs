//! The CLI's KNX Data Secure tool-key surface (`--keyring`, `--tool-key`;
//! issue #71).
//!
//! The resolver and the secure-layer builder live in
//! [`bussard_service::secure`] so the MCP server (and any other surface) uses
//! the same code; this module re-exports them under the names the device
//! commands already use.

pub use bussard_service::secure::{
    KEYRING_PASSWORD_ENV, SecureMaterial, ToolKeySource, layer, resolve, resolve_material,
};
