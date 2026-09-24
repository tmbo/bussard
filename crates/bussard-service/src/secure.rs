//! Resolving the KNX Data Secure **tool key** for a management session
//! (issue #71, spec §2, §6.2).
//!
//! A security-activated device refuses plain management access: every APDU must
//! ride an `A_SecureData` (`0x03F1`) wrapper keyed by that device's tool key
//! (spec §5.7). This module turns the two key sources into the optional
//! [`Key16`] a management session hands to
//! [`bussard_mgmt::SecureLayer`]:
//!
//! - a **keyring**: the ETS `.knxkeys` export, decrypted with the password in
//!   [`KEYRING_PASSWORD_ENV`] (never a command-line argument, spec §2.2), and the
//!   tool key looked up by the target's individual address. This is the real
//!   flow, available to every surface (the CLI's `--keyring`, the MCP server's
//!   `--keyring`).
//! - a **raw tool key**: 32 hexadecimal characters, for driving a simulator or a
//!   bench device with a synthetic key. Process arguments are visible to other
//!   users on the machine, so this is documented as unsuitable for a production
//!   key.
//!
//! Nothing here ever prints, logs, or `Debug`-formats key material: every error
//! names the *source* of the problem (file, address, length) and never the bytes
//! (spec §2.3).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bussard_model::{GroupAddress, IndividualAddress};
use bussard_secure::{DataSecureSession, Key16, SecurityAlgorithm, SequenceHighWater};

/// The environment variable carrying the `.knxkeys` password (spec §2.2).
///
/// Mirrors `BUSSARD_PROJECT_PASSWORD`: the password arrives out of band so it
/// never lands in a shell history, a process listing, or a config file.
pub const KEYRING_PASSWORD_ENV: &str = "BUSSARD_KEYRING_PASSWORD";

/// Environment variable selecting the CCM algorithm for wrapped management
/// APDUs: `auth` for authentication-only (the APDU rides in the clear under a
/// MAC), anything else (or unset) for the spec §6.2 default, authentication +
/// encryption.
///
/// It exists for the cross-implementation conformance loop, which exercises both
/// modes against the simulator (spec §12.2); a real flash never sets it.
pub const SECURE_ALGORITHM_ENV: &str = "BUSSARD_SECURE_ALGORITHM";

/// The two sources of a tool key, as a surface passes them.
///
/// Both `None` is the plain path: management behaves exactly as it did before
/// KNX Secure existed (spec §6.4).
#[derive(Debug, Clone, Copy, Default)]
pub struct ToolKeySource<'a> {
    /// An ETS `.knxkeys` export; the password comes from
    /// [`KEYRING_PASSWORD_ENV`].
    pub keyring: Option<&'a Path>,
    /// A raw 16-byte key as 32 hexadecimal characters, for tests and benches.
    pub tool_key: Option<&'a str>,
}

/// Why a tool key could not be resolved. No variant carries key bytes.
#[derive(Debug, thiserror::Error)]
pub enum SecureKeyError {
    /// Both a keyring and a raw tool key were given.
    #[error(
        "--keyring and --tool-key are mutually exclusive: pass the keyring for a real \
         installation, or the raw tool key only for a test/bench device"
    )]
    BothSources,
    /// A keyring was given but [`KEYRING_PASSWORD_ENV`] is not set.
    #[error(
        "the keyring password must be set in the {KEYRING_PASSWORD_ENV} environment \
         variable (never passed as a CLI argument)"
    )]
    MissingPassword,
    /// The keyring file could not be read.
    #[error("reading keyring {}", path.display())]
    Read {
        /// The keyring path.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The keyring did not decrypt or parse (a wrong password, a corrupt file).
    #[error("loading keyring {}", path.display())]
    Parse {
        /// The keyring path.
        path: PathBuf,
        /// The parse error.
        #[source]
        source: bussard_project::KeyringError,
    },
    /// The keyring has no tool key for the target device.
    #[error(
        "the keyring {} has no tool key for {target}: it lists {devices} device(s). A device is \
         only in the keyring once ETS has commissioned its security; an uncommissioned \
         device still takes its FDSK.",
        path.display()
    )]
    NoEntry {
        /// The keyring path.
        path: PathBuf,
        /// The device that has no entry.
        target: IndividualAddress,
        /// How many devices the keyring does list.
        devices: usize,
    },
    /// A raw tool key of the wrong length.
    #[error(
        "--tool-key must be exactly 32 hexadecimal characters (a 16-byte KNX Secure key); \
         got {0} characters"
    )]
    KeyLength(usize),
    /// A raw tool key with a non-hexadecimal character at this position.
    #[error("--tool-key is not valid hexadecimal at character {0} (the value is not echoed)")]
    KeyNotHex(usize),
}

/// Resolves the tool key for `target`, or `None` for the plain path.
///
/// # Errors
///
/// Both sources given, a keyring without [`KEYRING_PASSWORD_ENV`], an
/// unreadable file, a wrong password, no entry for `target`, or a raw key that
/// is not exactly 32 hexadecimal characters. No error message ever contains key
/// bytes (spec §2.3).
pub fn resolve(
    target: IndividualAddress,
    source: ToolKeySource<'_>,
) -> Result<Option<Key16>, SecureKeyError> {
    Ok(resolve_material(target, source)?.tool_key)
}

/// The Data Secure key material a secured download needs: the target's tool
/// key and, when it came from a keyring, the keyring's group keys (issue #156:
/// the group key table of the security object is built from them). `Debug` is
/// redacted by [`Key16`].
#[derive(Debug, Clone, Default)]
pub struct SecureMaterial {
    /// The target's tool key, or `None` for the plain path.
    pub tool_key: Option<Key16>,
    /// The keyring's group keys; `None` with a raw tool key (which carries
    /// none) or on the plain path.
    pub group_keys: Option<HashMap<GroupAddress, Key16>>,
    /// The keyring's per-device `SequenceNumber` (issue #181: the sequence a
    /// secured sender's security individual address table entry starts from);
    /// empty with a raw tool key or on the plain path.
    pub device_sequences: HashMap<IndividualAddress, u64>,
}

/// Like [`resolve`], but also returns the keyring's group keys. The keyring is
/// decrypted once.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_material(
    target: IndividualAddress,
    source: ToolKeySource<'_>,
) -> Result<SecureMaterial, SecureKeyError> {
    match (source.keyring, source.tool_key) {
        (Some(_), Some(_)) => Err(SecureKeyError::BothSources),
        (Some(path), None) => {
            let keyring = load_keyring(path)?;
            let tool_key = tool_key_from(&keyring, target, path)?;
            Ok(SecureMaterial {
                tool_key: Some(tool_key),
                group_keys: Some(keyring.group_keys.clone()),
                device_sequences: keyring.devices.iter().map(|d| (d.ia, d.seq)).collect(),
            })
        }
        (None, Some(hex)) => Ok(SecureMaterial {
            tool_key: Some(parse_hex_key(hex)?),
            group_keys: None,
            device_sequences: HashMap::new(),
        }),
        (None, None) => Ok(SecureMaterial::default()),
    }
}

/// Loads the keyring's **group keys** for secured group communication
/// (issue #172: `monitor`, `capture`, `read` and `write --keyring`). The
/// password comes from [`KEYRING_PASSWORD_ENV`].
///
/// # Errors
///
/// A missing password, an unreadable file, or a keyring that does not decrypt.
pub fn load_group_keys(path: &Path) -> Result<crate::group::GroupKeys, SecureKeyError> {
    Ok(load_keyring(path)?.group_keys)
}

/// Loads and decrypts `path` with the env password.
fn load_keyring(path: &Path) -> Result<bussard_project::Keyring, SecureKeyError> {
    let password =
        std::env::var(KEYRING_PASSWORD_ENV).map_err(|_| SecureKeyError::MissingPassword)?;
    let xml = std::fs::read_to_string(path).map_err(|source| SecureKeyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    bussard_project::parse_keyring(&xml, &password).map_err(|source| SecureKeyError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Extracts `target`'s tool key (spec §2.1: the keyring `ToolKey` is the
/// device's management key).
fn tool_key_from(
    keyring: &bussard_project::Keyring,
    target: IndividualAddress,
    path: &Path,
) -> Result<Key16, SecureKeyError> {
    keyring
        .tool_key(target)
        .cloned()
        .ok_or_else(|| SecureKeyError::NoEntry {
            path: path.to_path_buf(),
            target,
            devices: keyring.devices.len(),
        })
}

/// Parses exactly 32 hexadecimal characters (an optional `0x` prefix is allowed,
/// matching `--bcu-key`) into a [`Key16`].
///
/// The error names the length or the offending position, never the input bytes.
pub fn parse_hex_key(raw: &str) -> Result<Key16, SecureKeyError> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != 32 {
        return Err(SecureKeyError::KeyLength(hex.len()));
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let pair = hex
            .get(i * 2..i * 2 + 2)
            .ok_or(SecureKeyError::KeyNotHex(i * 2))?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| SecureKeyError::KeyNotHex(i * 2))?;
    }
    Ok(Key16::new(bytes))
}

/// Builds the management connection's KNX Data Secure layer from an optional
/// tool key (spec §6.1): `None` is the plain path (byte-identical to a bussard
/// without KNX Secure), `Some` wraps every APDU in `A_SecureData`.
///
/// A fresh [`DataSecureSession`] is built per connect: its send sequence is
/// clock-seeded and monotonic (spec §5.8), so a reconnect after a restart never
/// replays a sequence the device already accepted.
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

    fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    #[test]
    fn test_resolve_none_is_the_plain_path() -> Result<(), Box<dyn std::error::Error>> {
        assert!(resolve(ia("1.1.2")?, ToolKeySource::default())?.is_none());
        Ok(())
    }

    #[test]
    fn test_resolve_parses_a_raw_tool_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = resolve(
            ia("1.1.2")?,
            ToolKeySource {
                keyring: None,
                tool_key: Some("0102030405060708090a0b0c0d0e0f10"),
            },
        )?;
        assert_eq!(
            key,
            Some(Key16::new([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
            ]))
        );
        Ok(())
    }

    #[test]
    fn test_parse_hex_key_accepts_a_0x_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let key = parse_hex_key("0x000102030405060708090A0B0C0D0E0F")?;
        assert_eq!(
            key,
            Key16::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        Ok(())
    }

    #[test]
    fn test_parse_hex_key_short_is_rejected_without_echoing_it() {
        let err = parse_hex_key("0102").err().map(|e| e.to_string());
        let err = err.unwrap_or_default();
        assert!(err.contains("32 hexadecimal"), "{err}");
        assert!(!err.contains("0102"), "the key must never be echoed: {err}");
    }

    #[test]
    fn test_parse_hex_key_non_hex_is_rejected_without_echoing_it() {
        let err = parse_hex_key("zz0102030405060708090a0b0c0d0e0f")
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("hexadecimal"), "{err}");
        assert!(!err.contains("zz"), "the key must never be echoed: {err}");
    }

    #[test]
    fn test_resolve_both_sources_conflict() -> Result<(), Box<dyn std::error::Error>> {
        let err = resolve(
            ia("1.1.2")?,
            ToolKeySource {
                keyring: Some(Path::new("/nonexistent.knxkeys")),
                tool_key: Some("0102030405060708090a0b0c0d0e0f10"),
            },
        )
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(err.contains("mutually exclusive"), "{err}");
        Ok(())
    }
}
