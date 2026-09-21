//! Resolving the KNX Data Secure **tool key** for a management command
//! (issue #71, spec §2, §6.2).
//!
//! A security-activated device refuses plain management access: every APDU must
//! ride an `A_SecureData` (`0x03F1`) wrapper keyed by that device's tool key
//! (spec §5.7). This module turns the two CLI surfaces into the optional
//! [`Key16`] the management commands hand to
//! [`bussard_mgmt::SecureLayer`](bussard_mgmt::SecureLayer):
//!
//! - `--keyring <FILE>` — the **real flow**: the ETS `.knxkeys` export, decrypted
//!   with the password in `BUSSARD_KEYRING_PASSWORD` (never a CLI argument, spec
//!   §2.2), and the tool key looked up by the target's individual address.
//! - `--tool-key <32 hex>` — the **test/bench escape hatch**: a raw 16-byte key,
//!   for driving a simulator or a bench device with a synthetic key. Process
//!   arguments are visible to other users on the machine, so this is documented
//!   as unsuitable for a production key.
//!
//! Neither path ever prints, logs, or `Debug`-formats key material: every error
//! below names the *source* of the problem (file, address, length) and never the
//! bytes (spec §2.3).

use std::path::Path;

use anyhow::{Context, anyhow};
use bussard_model::IndividualAddress;
use bussard_secure::{DataSecureSession, Key16, SecurityAlgorithm, SequenceHighWater};

/// The environment variable carrying the `.knxkeys` password (spec §2.2).
///
/// Mirrors `BUSSARD_PROJECT_PASSWORD`: the password arrives out of band so it
/// never lands in a shell history, a process listing, or a config file.
pub const KEYRING_PASSWORD_ENV: &str = "BUSSARD_KEYRING_PASSWORD";

/// The two CLI sources of a tool key, as passed by a command's `run`.
///
/// Both `None` is the plain path: the command behaves exactly as it did before
/// KNX Secure existed (spec §6.4).
#[derive(Debug, Clone, Copy, Default)]
pub struct ToolKeySource<'a> {
    /// `--keyring <FILE>`: an ETS `.knxkeys` export; the password comes from
    /// [`KEYRING_PASSWORD_ENV`].
    pub keyring: Option<&'a Path>,
    /// `--tool-key <32 hex>`: a raw 16-byte key for tests and benches.
    pub tool_key: Option<&'a str>,
}

/// Resolves the tool key for `target`, or `None` for the plain path.
///
/// # Errors
///
/// - both surfaces given (clap also rejects this, but the check is kept here so
///   a library caller cannot silently pick one);
/// - `--keyring` without [`KEYRING_PASSWORD_ENV`], an unreadable file, a wrong
///   password, or no entry for `target`;
/// - `--tool-key` that is not exactly 32 hexadecimal characters.
///
/// No error message ever contains key bytes (spec §2.3).
pub fn resolve(
    target: IndividualAddress,
    source: ToolKeySource<'_>,
) -> anyhow::Result<Option<Key16>> {
    match (source.keyring, source.tool_key) {
        (Some(_), Some(_)) => Err(anyhow!(
            "--keyring and --tool-key are mutually exclusive: pass the keyring for a real \
             installation, or the raw tool key only for a test/bench device"
        )),
        (Some(path), None) => from_keyring(target, path).map(Some),
        (None, Some(hex)) => parse_hex_key(hex).map(Some),
        (None, None) => Ok(None),
    }
}

/// Loads `path`, decrypts it with the env password, and extracts `target`'s tool
/// key (spec §2.1: the keyring `ToolKey` is the device's management key).
fn from_keyring(target: IndividualAddress, path: &Path) -> anyhow::Result<Key16> {
    let password = std::env::var(KEYRING_PASSWORD_ENV).map_err(|_| {
        anyhow!(
            "the keyring password must be set in the {KEYRING_PASSWORD_ENV} environment \
             variable (never passed as a CLI argument)"
        )
    })?;
    let xml = std::fs::read_to_string(path)
        .with_context(|| format!("reading keyring {}", path.display()))?;
    let keyring = bussard_project::parse_keyring(&xml, &password)
        .with_context(|| format!("parsing keyring {}", path.display()))?;
    keyring.tool_key(target).cloned().ok_or_else(|| {
        anyhow!(
            "the keyring {} has no tool key for {target}: it lists {} device(s). A device is \
             only in the keyring once ETS has commissioned its security; an uncommissioned \
             device still takes its FDSK.",
            path.display(),
            keyring.devices.len()
        )
    })
}

/// Parses exactly 32 hexadecimal characters (an optional `0x` prefix is allowed,
/// matching `--bcu-key`) into a [`Key16`].
///
/// The error names the length or the offending position, never the input bytes.
fn parse_hex_key(raw: &str) -> anyhow::Result<Key16> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != 32 {
        return Err(anyhow!(
            "--tool-key must be exactly 32 hexadecimal characters (a 16-byte KNX Secure key); \
             got {} characters",
            hex.len()
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let pair = hex
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| anyhow!("--tool-key is not valid hexadecimal at character {}", i * 2))?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| {
            anyhow!(
                "--tool-key is not valid hexadecimal at character {} (the value is not echoed)",
                i * 2
            )
        })?;
    }
    Ok(Key16::new(bytes))
}

/// Builds the management connection's KNX Data Secure layer from an optional
/// tool key (spec §6.1): `None` is the plain path (byte-identical to a bussard
/// without KNX Secure), `Some` wraps every APDU in `A_SecureData`.
///
/// A fresh [`DataSecureSession`] is built per connect: its send
/// sequence is clock-seeded and monotonic (spec §5.8), so a reconnect after a
/// restart never replays a sequence the device already accepted.
pub fn layer(
    tool_key: &Option<Key16>,
    high_water: &SequenceHighWater,
) -> bussard_mgmt::SecureLayer {
    match tool_key {
        None => bussard_mgmt::SecureLayer::plain(),
        Some(key) => bussard_mgmt::SecureLayer::activated(
            DataSecureSession::new(key.clone())
                .with_algorithm(algorithm())
                .with_high_water(high_water.clone()),
        ),
    }
}

/// Environment variable selecting the CCM algorithm for wrapped management
/// APDUs: `auth` for authentication-only (the APDU rides in the clear under a
/// MAC), anything else (or unset) for the spec §6.2 default, authentication +
/// encryption.
///
/// It exists for the cross-implementation conformance loop, which exercises both
/// modes against the simulator (spec §12.2); a real flash never sets it.
const SECURE_ALGORITHM_ENV: &str = "BUSSARD_SECURE_ALGORITHM";

/// The CCM algorithm for wrapped management APDUs, honouring
/// [`SECURE_ALGORITHM_ENV`]. Default: authentication + encryption (spec §6.2).
fn algorithm() -> SecurityAlgorithm {
    match std::env::var(SECURE_ALGORITHM_ENV)
        .as_deref()
        .map(str::trim)
    {
        Ok("auth") | Ok("auth-only") => SecurityAlgorithm::AuthenticationOnly,
        _ => SecurityAlgorithm::AuthenticationEncryption,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ia(s: &str) -> IndividualAddress {
        s.parse().expect("a valid individual address")
    }

    #[test]
    fn test_resolve_none_is_the_plain_path() -> anyhow::Result<()> {
        assert!(resolve(ia("1.1.2"), ToolKeySource::default())?.is_none());
        Ok(())
    }

    #[test]
    fn test_resolve_parses_a_raw_tool_key() -> anyhow::Result<()> {
        let key = resolve(
            ia("1.1.2"),
            ToolKeySource {
                keyring: None,
                tool_key: Some("0102030405060708090a0b0c0d0e0f10"),
            },
        )?
        .expect("a key");
        assert_eq!(
            key,
            Key16::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        );
        Ok(())
    }

    #[test]
    fn test_resolve_accepts_a_0x_prefix() -> anyhow::Result<()> {
        let key = parse_hex_key("0x000102030405060708090A0B0C0D0E0F")?;
        assert_eq!(
            key,
            Key16::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        Ok(())
    }

    #[test]
    fn test_short_tool_key_is_rejected_without_echoing_it() {
        let err = parse_hex_key("0102").unwrap_err().to_string();
        assert!(err.contains("32 hexadecimal"), "{err}");
        assert!(!err.contains("0102"), "the key must never be echoed: {err}");
    }

    #[test]
    fn test_non_hex_tool_key_is_rejected_without_echoing_it() {
        let err = parse_hex_key("zz0102030405060708090a0b0c0d0e0f")
            .unwrap_err()
            .to_string();
        assert!(err.contains("hexadecimal"), "{err}");
        assert!(!err.contains("zz"), "the key must never be echoed: {err}");
    }

    #[test]
    fn test_both_surfaces_conflict() {
        let err = resolve(
            ia("1.1.2"),
            ToolKeySource {
                keyring: Some(Path::new("/nonexistent.knxkeys")),
                tool_key: Some("0102030405060708090a0b0c0d0e0f10"),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("mutually exclusive"), "{err}");
    }
}
