//! The one wording for conditions every surface reports (issue #228).
//!
//! bussard's CLI, the MCP server, `viz` and the libraries below them used to
//! word the same condition differently. Each condition has one constructor:
//! the key-material hints a transport or download error prints come from
//! `bussard_transport::guidance` (re-exported here), the rest are here.
//!
//! * missing key material: [`tunnel_credentials_hint`], [`tool_key_hint`],
//!   [`group_key_hint`] (all built on [`PASS_KEYRING`]);
//! * the real-gateway opt-in: [`opt_in_warning`]; the refusal itself is
//!   [`bussard_transport::write_gate::WriteGateRefused`];
//! * the missing keyring password: [`crate::secure::SecureKeyError::MissingPassword`].

pub use bussard_transport::guidance::{PASS_KEYRING, tool_key_hint, tunnel_credentials_hint};

/// What to pass when a secured group address needs its group key and bussard
/// has none.
pub fn group_key_hint() -> String {
    format!("{PASS_KEYRING} exported from ETS with the group key")
}

/// The warning a transmitting surface prints once when the operator opted in
/// to a real (non-loopback) gateway.
pub fn opt_in_warning(gateway: &str) -> String {
    format!("writing to non-loopback gateway {gateway} (opt-in acknowledged)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_key_hint_shares_the_keyring_wording() {
        assert!(group_key_hint().starts_with(PASS_KEYRING));
    }

    #[test]
    fn test_opt_in_warning_names_the_gateway() {
        assert_eq!(
            opt_in_warning("192.0.2.1:3671"),
            "writing to non-loopback gateway 192.0.2.1:3671 (opt-in acknowledged)"
        );
    }
}
