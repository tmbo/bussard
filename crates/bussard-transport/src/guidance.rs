//! The one wording for conditions every surface reports (issue #228).
//!
//! bussard's CLI, the MCP server, `viz` and the libraries below them used to
//! word the same condition differently. Each condition now has one
//! constructor here, in the lowest crate that reports it, so the transport,
//! the download engine, the service layer and every surface print the same
//! sentence. `bussard_service::guidance` re-exports this module.
//!
//! * missing key material: [`tunnel_credentials_hint`], [`tool_key_hint`],
//!   [`group_key_hint`] (all built on [`PASS_KEYRING`]);
//! * the real-gateway opt-in: [`opt_in_warning`]; the refusal itself is
//!   [`crate::write_gate::WriteGateRefused`];
//! * the missing keyring password: `bussard_service::secure::SecureKeyError::MissingPassword`.

/// How to hand bussard a keyring: the flag, and where its password comes
/// from. Every "no key material" hint starts with it.
pub const PASS_KEYRING: &str =
    "pass --keyring <file.knxkeys> (password in BUSSARD_KEYRING_PASSWORD)";

/// What to pass when an interface needs KNXnet/IP Secure tunnelling
/// credentials and bussard has none.
pub fn tunnel_credentials_hint() -> String {
    format!(
        "{PASS_KEYRING} exported from the ETS project that holds the interface's tunnelling \
         users, or --secure-user <id> --secure-password-env <VAR>"
    )
}

/// What to pass when a KNX Data Secure device needs its tool key and bussard
/// has none.
pub fn tool_key_hint() -> String {
    format!(
        "{PASS_KEYRING} exported from ETS with the device's tool key, or --tool-key <32 hex> for \
         a test device"
    )
}

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
    fn test_hints_share_the_keyring_wording() {
        for hint in [tunnel_credentials_hint(), tool_key_hint(), group_key_hint()] {
            assert!(hint.starts_with(PASS_KEYRING), "{hint}");
        }
    }

    #[test]
    fn test_secure_required_uses_the_tunnel_hint() {
        let err = crate::TransportError::SecureRequired {
            gateway: std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 3671),
            reason: "no credentials were given".to_string(),
        };
        assert!(
            err.to_string().ends_with(&tunnel_credentials_hint()),
            "{err}"
        );
    }

    #[test]
    fn test_opt_in_warning_names_the_gateway() {
        assert_eq!(
            opt_in_warning("192.0.2.1:3671"),
            "writing to non-loopback gateway 192.0.2.1:3671 (opt-in acknowledged)"
        );
    }
}
