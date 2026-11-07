//! The key-material hints the transport and download errors print (issue
//! #228).
//!
//! These sentences live here, in the lowest crate that reports them, because
//! [`crate::TransportError::SecureRequired`] and the download engine's
//! security-activated error carry them in their `Display`. Every other
//! surface wording is in `bussard_service::guidance`, which re-exports these.
//!
//! * missing key material: [`tunnel_credentials_hint`], [`tool_key_hint`]
//!   (both built on [`PASS_KEYRING`]);
//! * the real-gateway opt-in refusal is [`crate::write_gate::WriteGateRefused`].

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hints_share_the_keyring_wording() {
        for hint in [tunnel_credentials_hint(), tool_key_hint()] {
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
}
