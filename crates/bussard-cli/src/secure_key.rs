//! The CLI's words around KNX Data Secure (`--keyring`, `--tool-key`; issue
//! #71): the operator-facing hints for a device that may be Data
//! Secure-activated or a group address without a key, and the tunnelling
//! senders `admit_tunnel_senders` adds. The tool-key resolver and the
//! secure-layer builder are [`bussard_service::secure`]'s.

use anyhow::Context;
use bussard_model::IndividualAddress;
use bussard_service::secure::ToolKeySource;

/// The tunnelling addresses `[connection] admit_tunnel_senders` adds to a
/// Secure device's security individual address table (issue #297): every
/// tunnelling interface of the keyring or key store, ascending. Empty when the
/// option is off, the device is written in the clear (`secured` false), or no
/// keyring is given (a warning says so).
///
/// # Errors
///
/// A keyring that cannot be loaded.
pub fn admitted_tunnel(
    model: Option<&bussard_model::Model>,
    source: ToolKeySource<'_>,
    secured: bool,
) -> anyhow::Result<Vec<IndividualAddress>> {
    if !secured || !bussard_service::admission::admit_tunnel_senders(model) {
        return Ok(Vec::new());
    }
    let Some(path) = source.keyring else {
        eprintln!(
            "warning: admit_tunnel_senders is set but no keyring or key store is given; no \
             tunnelling address is admitted"
        );
        return Ok(Vec::new());
    };
    let evidence = bussard_service::secure::load_admission_evidence(path)
        .with_context(|| format!("loading the interfaces of {}", path.display()))?;
    let tunnel = evidence.tunnel_addresses();
    if tunnel.is_empty() {
        eprintln!(
            "warning: admit_tunnel_senders is set but {} lists no tunnelling interface",
            path.display()
        );
    }
    Ok(tunnel)
}

/// The guidance for a device without a tool key that may be Data Secure-activated
/// (issue #71, spec §6.4).
pub(crate) fn no_key_guidance() -> String {
    format!(
        "if this device is KNX Data Secure-activated it refuses unsecured management: {} (a \
         keyring that does not list the device only opens the tunnel)",
        bussard_service::guidance::tool_key_hint()
    )
}

/// A device without a tool key that refused plain access and answered under
/// its factory key (issue #532); the message says what that means.
#[derive(Debug)]
pub(crate) struct FactoryKeyAnswered(pub String);

impl std::fmt::Display for FactoryKeyAnswered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FactoryKeyAnswered {}

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
    // A device found on its factory key (issue #532) is named as such; the
    // "wrong key" guess does not apply.
    let factory = err.chain().any(|cause| {
        cause.is::<FactoryKeyAnswered>()
            || matches!(
                cause.downcast_ref::<bussard_mgmt::MgmtError>(),
                Some(bussard_mgmt::MgmtError::FactoryKeyActive { .. })
            )
            || matches!(
                cause.downcast_ref::<bussard_service::ServiceError>(),
                Some(bussard_service::ServiceError::Mgmt(
                    bussard_mgmt::MgmtError::FactoryKeyActive { .. }
                ))
            )
    });
    if factory {
        return err;
    }
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

/// The CLI's words for a secured GA without a group key.
pub fn no_group_key_hint(ga: bussard_model::GroupAddress, keyring_given: bool) -> String {
    if keyring_given {
        format!(
            "group address {ga} is secured but the ETS keyring has no group key for it; \
             export a current keyring from ETS"
        )
    } else {
        format!(
            "group address {ga} is secured (`secure = true` in groups.toml): {}",
            bussard_service::guidance::group_key_hint()
        )
    }
}

/// The group keys of the keyring at `keyring` as a [`GroupKeyring`] for
/// `monitor`, `capture` and `learn` (issue #172), announcing how many it
/// holds; `None` without a keyring. Loaded before connecting, so a wrong
/// password fails fast.
///
/// # Errors
///
/// A keyring that cannot be loaded.
pub fn group_keyring(
    keyring: Option<&std::path::Path>,
) -> anyhow::Result<Option<bussard_monitor::GroupKeyring>> {
    let Some(path) = keyring else {
        return Ok(None);
    };
    let store = bussard_service::secure::load_keys(path)
        .with_context(|| format!("loading group keys from {}", path.display()))?;
    eprintln!(
        "keyring: {} group key(s) for secured group telegrams",
        store.group_keys.len()
    );
    Ok(Some(bussard_monitor::GroupKeyring::new(store)))
}
