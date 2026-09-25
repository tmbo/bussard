//! Resolving the KNX Data Secure **tool key** for a management session
//! (issue #71, spec §2, §6.2).
//!
//! A security-activated device refuses plain management access: every APDU must
//! ride an `A_SecureData` (`0x03F1`) wrapper keyed by that device's tool key
//! (spec §5.7). This module turns the two key sources into the optional
//! [`Key16`] a management session hands to
//! [`bussard_mgmt::SecureLayer`]:
//!
//! - a **keyring**: the key store `bussard.keys` (issue #241) or an ETS
//!   `.knxkeys` export, decrypted with the password in
//!   [`KEYRING_PASSWORD_ENV`] (never a command-line argument, spec §2.2), and the
//!   tool key looked up by the target's individual address. This is the real
//!   flow, available to every surface (the CLI's `--keyring`, the MCP server's
//!   `--keyring`).
//! - a **raw tool key**: 32 hexadecimal characters, for driving a simulator or a
//!   bench device with a synthetic key. Process arguments are visible to other
//!   users on the machine, so this is documented as unsuitable for a production
//!   key.
//!
//! A keyring serves two purposes (issue #189): its tunnelling users open a
//! KNXnet/IP Secure tunnel ([`tunnel_config`]), and its device entries carry
//! tool keys. A device the keyring does not list is managed in the clear
//! through that tunnel, unless the model records it as security-activated
//! (`security.activated: true`), in which case plain access cannot work and the
//! resolver refuses with [`SecureKeyError::NoEntry`]. See [`resolve_material`].
//!
//! Nothing here ever prints, logs, or `Debug`-formats key material: every error
//! names the *source* of the problem (file, address, length) and never the bytes
//! (spec §2.3).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    /// The key store (`bussard.keys`) did not decrypt or parse (a wrong
    /// password, a hand-edited file).
    #[error("loading the key store {}", path.display())]
    Store {
        /// The store path.
        path: PathBuf,
        /// The store error.
        #[source]
        source: bussard_project::KeyStoreError,
    },
    /// The keyring has no tool key for a target the model records as
    /// security-activated (a device the model does not mark activated is
    /// managed in the clear instead, issue #189).
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
    /// Only one of `--secure-user` / `--secure-password-env` was given.
    #[error(
        "--secure-user and --secure-password-env go together: the user id selects the \
         KNXnet/IP Secure tunnelling user, the environment variable holds its password"
    )]
    SecureFlagsIncomplete,
    /// The environment variable named by `--secure-password-env` is not set.
    #[error("--secure-password-env names {0}, but that environment variable is not set")]
    MissingTunnelPassword(String),
}

/// The sources of KNXnet/IP Secure tunnelling credentials a surface passes
/// (issue #71 Phase B).
#[derive(Debug, Clone, Copy, Default)]
pub struct TunnelCredentialSource<'a> {
    /// An ETS `.knxkeys` export listing the interface's tunnelling users.
    pub keyring: Option<&'a Path>,
    /// `--secure-user`: an explicit user id.
    pub user: Option<u8>,
    /// `--secure-password-env`: the environment variable with that user's
    /// password.
    pub password_env: Option<&'a str>,
}

/// Builds the KNXnet/IP Secure tunnelling configuration, or `None` for the
/// plain tunnel.
///
/// Explicit flags win and always open a secure session; the device
/// authentication code then comes from a keyring interface with the same user
/// id, if a keyring is also given. A keyring alone offers every tunnelling
/// user it lists (`Interface Type="Tunneling"` with a password) and the
/// transport picks the one for the gateway it reaches. Passwords stay
/// passwords here: the transport derives only the user it presents.
///
/// # Errors
///
/// Half of the explicit flags, an unset password variable, or a keyring that
/// cannot be read.
pub fn tunnel_config(
    source: TunnelCredentialSource<'_>,
) -> Result<Option<bussard_transport::SecureTunnelConfig>, SecureKeyError> {
    use bussard_transport::{SecureSource, SecureTunnelConfig, SecureUser};
    let keyring = match source.keyring {
        Some(path) => Some(load_keyring(path)?),
        None => None,
    };
    let secure_users = |k: &Arc<bussard_project::Keyring>| -> Vec<SecureUser> {
        k.interfaces
            .iter()
            .filter(|i| i.is_secure_tunnel())
            .filter_map(|i| {
                let password = i.password.clone()?;
                let host_code = i.host.and_then(|host| {
                    k.devices
                        .iter()
                        .find(|d| d.ia == host)
                        .and_then(|d| d.authentication.clone())
                });
                Some(SecureUser {
                    user_id: i.user_id,
                    password,
                    device_authentication_code: i.authentication.clone().or(host_code),
                    tunnel_ia: Some(i.ia.raw()),
                    host_ia: i.host.map(IndividualAddress::raw),
                })
            })
            .collect()
    };
    match (source.user, source.password_env) {
        (Some(user_id), Some(var)) => {
            let password = bussard_model::dotenv::var(var)
                .map(bussard_secure::Password::new)
                .map_err(|_| SecureKeyError::MissingTunnelPassword(var.to_string()))?;
            let from_keyring = keyring
                .as_ref()
                .map(secure_users)
                .unwrap_or_default()
                .into_iter()
                .find(|u| u.user_id == user_id);
            Ok(Some(SecureTunnelConfig::new(
                vec![SecureUser {
                    user_id,
                    password,
                    device_authentication_code: from_keyring
                        .as_ref()
                        .and_then(|u| u.device_authentication_code.clone()),
                    tunnel_ia: from_keyring.as_ref().and_then(|u| u.tunnel_ia),
                    host_ia: from_keyring.as_ref().and_then(|u| u.host_ia),
                }],
                SecureSource::Explicit,
            )))
        }
        (None, None) => {
            let users = keyring.as_ref().map(secure_users).unwrap_or_default();
            Ok(
                (!users.is_empty())
                    .then_some(SecureTunnelConfig::new(users, SecureSource::Keyring)),
            )
        }
        _ => Err(SecureKeyError::SecureFlagsIncomplete),
    }
}

/// Whether `model` records `target` as KNX Data Secure-activated
/// (`security.activated: true` in its device file). A device the model does not
/// know, or no model at all, is not activated.
pub fn model_activated(model: Option<&bussard_model::Model>, target: IndividualAddress) -> bool {
    model
        .and_then(|m| m.devices.get(&target))
        .and_then(|d| d.device.security.as_ref())
        .is_some_and(|s| s.activated)
}

/// Resolves the tool key for `target`, or `None` for the plain path.
///
/// `activated` is whether the model records `target` as security-activated
/// ([`model_activated`]); see [`resolve_material`] for the rule.
///
/// # Errors
///
/// Both sources given, a keyring without [`KEYRING_PASSWORD_ENV`], an
/// unreadable file, a wrong password, an activated `target` without a keyring
/// entry, or a raw key that is not exactly 32 hexadecimal characters. No error
/// message ever contains key bytes (spec §2.3).
pub fn resolve(
    target: IndividualAddress,
    source: ToolKeySource<'_>,
    activated: bool,
) -> Result<Option<Key16>, SecureKeyError> {
    Ok(resolve_material(target, source, activated)?.tool_key)
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
/// The rule for a keyring (issue #189):
///
/// - the keyring lists `target`: secured management with its tool key;
/// - the keyring does not list `target` and `activated` is false: the plain
///   path (`SecureMaterial::default()`). The keyring still serves the
///   KNXnet/IP Secure tunnel; the device is talked to in the clear through it;
/// - the keyring does not list `target` but `activated` is true: plain access
///   cannot reach an activated device, so this is [`SecureKeyError::NoEntry`].
///
/// A raw tool key is always used as given.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_material(
    target: IndividualAddress,
    source: ToolKeySource<'_>,
    activated: bool,
) -> Result<SecureMaterial, SecureKeyError> {
    ToolKeys::load(source)?.material(target, activated)
}

/// The tool-key sources of one command, loaded once (issue #203).
///
/// A command that touches many devices (`scan`, `audit --live`) must not
/// decrypt the keyring once per address; it loads a `ToolKeys` up front and asks
/// it per target. [`ToolKeys::material`] applies exactly the rule of
/// [`resolve_material`]. `Debug` prints only which sources are present.
#[derive(Default)]
pub struct ToolKeys {
    /// The decrypted keyring and the path it came from.
    keyring: Option<(PathBuf, Arc<bussard_project::Keyring>)>,
    /// A raw `--tool-key`.
    raw: Option<Key16>,
}

impl std::fmt::Debug for ToolKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolKeys")
            .field("keyring", &self.keyring.as_ref().map(|(path, _)| path))
            .field("raw_tool_key", &self.raw.is_some())
            .finish()
    }
}

impl ToolKeys {
    /// Loads the sources: decrypts the keyring (password from
    /// [`KEYRING_PASSWORD_ENV`]) or parses the raw key. Both `None` is the plain
    /// path.
    ///
    /// # Errors
    ///
    /// Both sources given, a keyring without its password, an unreadable or
    /// undecryptable keyring, or a malformed raw key. No error carries key
    /// bytes.
    pub fn load(source: ToolKeySource<'_>) -> Result<ToolKeys, SecureKeyError> {
        match (source.keyring, source.tool_key) {
            (Some(_), Some(_)) => Err(SecureKeyError::BothSources),
            (Some(path), None) => Ok(ToolKeys {
                keyring: Some((path.to_path_buf(), load_keyring(path)?)),
                raw: None,
            }),
            (None, Some(hex)) => Ok(ToolKeys {
                keyring: None,
                raw: Some(parse_hex_key(hex)?),
            }),
            (None, None) => Ok(ToolKeys::default()),
        }
    }

    /// Whether a keyring was given.
    pub fn keyring_given(&self) -> bool {
        self.keyring.is_some()
    }

    /// Whether a raw tool key was given.
    pub fn raw_given(&self) -> bool {
        self.raw.is_some()
    }

    /// Whether the keyring lists `target` (has a tool key for it). `false`
    /// without a keyring.
    pub fn lists(&self, target: IndividualAddress) -> bool {
        self.keyring
            .as_ref()
            .is_some_and(|(_, k)| k.tool_key(target).is_some())
    }

    /// The devices the keyring holds a tool key for, in keyring order; empty
    /// without a keyring.
    pub fn listed(&self) -> Vec<IndividualAddress> {
        self.keyring
            .as_ref()
            .map(|(_, k)| {
                k.devices
                    .iter()
                    .filter(|d| k.tool_key(d.ia).is_some())
                    .map(|d| d.ia)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The tool key for `target`: the raw key if one was given, else the
    /// keyring's entry for `target`, else `None`. Unlike
    /// [`material`](Self::material) this never fails: the caller decides what
    /// a missing key means.
    pub fn tool_key(&self, target: IndividualAddress) -> Option<Key16> {
        if let Some(raw) = &self.raw {
            return Some(raw.clone());
        }
        self.keyring
            .as_ref()
            .and_then(|(_, k)| k.tool_key(target).cloned())
    }

    /// The material for `target` under the rule of [`resolve_material`]:
    /// keyring-listed means secured, unlisted and not `activated` means plain,
    /// unlisted but `activated` is [`SecureKeyError::NoEntry`]. A raw key is
    /// always used.
    ///
    /// # Errors
    ///
    /// [`SecureKeyError::NoEntry`] for an activated target the keyring does not
    /// list.
    pub fn material(
        &self,
        target: IndividualAddress,
        activated: bool,
    ) -> Result<SecureMaterial, SecureKeyError> {
        if let Some(raw) = &self.raw {
            return Ok(SecureMaterial {
                tool_key: Some(raw.clone()),
                group_keys: None,
                device_sequences: HashMap::new(),
            });
        }
        let Some((path, keyring)) = &self.keyring else {
            return Ok(SecureMaterial::default());
        };
        if keyring.tool_key(target).is_none() && !activated {
            tracing::info!(
                "the keyring {} has no tool key for {target}; managing it in the clear",
                path.display()
            );
            return Ok(SecureMaterial::default());
        }
        let tool_key = tool_key_from(keyring, target, path)?;
        Ok(SecureMaterial {
            tool_key: Some(tool_key),
            group_keys: Some(keyring.group_keys.clone()),
            device_sequences: keyring.devices.iter().map(|d| (d.ia, d.seq)).collect(),
        })
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
    Ok(load_keyring(path)?.group_keys.clone())
}

/// What `bussard validate` and `knx_validate` check against the model for the
/// keyring at `path` (issue #205): missing, locked (no
/// [`KEYRING_PASSWORD_ENV`]; never prompts), unreadable, or the devices and
/// group addresses it holds keys for. Decrypts at most once (the process memo
/// applies) and returns addresses only, never a key. `source` names where the
/// path came from, for the messages.
pub fn keyring_facts(path: &Path, source: &str) -> bussard_model::KeyringFacts {
    use bussard_model::KeyringStatus;
    let status = if !path.is_file() {
        KeyringStatus::Missing
    } else if bussard_model::dotenv::var_os(KEYRING_PASSWORD_ENV).is_none() {
        KeyringStatus::Locked
    } else {
        match load_keyring(path) {
            Ok(keyring) => KeyringStatus::Loaded {
                tool_keys: keyring
                    .devices
                    .iter()
                    .filter(|d| keyring.tool_key(d.ia).is_some())
                    .map(|d| d.ia)
                    .collect(),
                group_keys: keyring.group_keys.keys().copied().collect(),
            },
            Err(err) => {
                let mut reason = err.to_string();
                let mut next = std::error::Error::source(&err);
                while let Some(cause) = next {
                    reason.push_str(&format!(": {cause}"));
                    next = cause.source();
                }
                KeyringStatus::Unreadable(reason)
            }
        }
    };
    bussard_model::KeyringFacts {
        path: path.to_path_buf(),
        source: source.to_string(),
        status,
    }
}

/// Loads and decrypts `path` with the env password, once per process for the
/// same file bytes and password (see [`keyring_memo`]).
fn load_keyring(path: &Path) -> Result<Arc<bussard_project::Keyring>, SecureKeyError> {
    let password = bussard_model::dotenv::var(KEYRING_PASSWORD_ENV)
        .map_err(|_| SecureKeyError::MissingPassword)?;
    load_keyring_with(path, &password)
}

/// [`load_keyring`] with the password given: reads `path` every time and
/// decrypts it only when its bytes or the password differ from the memoized
/// entry for that path.
fn load_keyring_with(
    path: &Path,
    password: &str,
) -> Result<Arc<bussard_project::Keyring>, SecureKeyError> {
    let xml = std::fs::read_to_string(path).map_err(|source| SecureKeyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let key = keyring_memo::key(&xml, password);
    if let Some(keyring) = keyring_memo::get(path, &key) {
        return Ok(keyring);
    }
    let started = std::time::Instant::now();
    // The key store (issue #241) is the same format with a `Format` marker;
    // it is served in the keyring shape, so every consumer reads it unchanged.
    let parsed = if bussard_project::keystore::is_keystore(&xml) {
        bussard_project::KeyStore::parse(&xml, password)
            .map(|store| store.to_keyring())
            .map_err(|source| SecureKeyError::Store {
                path: path.to_path_buf(),
                source,
            })
    } else {
        bussard_project::parse_keyring(&xml, password).map_err(|source| SecureKeyError::Parse {
            path: path.to_path_buf(),
            source,
        })
    };
    keyring_memo::record_decrypt(started.elapsed());
    let keyring = Arc::new(parsed?);
    keyring_memo::put(path, key, &keyring);
    Ok(keyring)
}

/// How many times this process has decrypted a keyring (one PBKDF2 each): a
/// debug counter for the start-up budget (issue #214); `bussard --timing`
/// prints it.
pub fn keyring_decrypt_count() -> usize {
    keyring_memo::DECRYPTS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The time this process spent decrypting keyrings (the sum over
/// [`keyring_decrypt_count`] decrypts); `bussard --timing` prints it as the
/// `keyring` phase.
pub fn keyring_decrypt_time() -> std::time::Duration {
    std::time::Duration::from_nanos(
        keyring_memo::DECRYPT_NANOS.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// The per-process memo of decrypted keyrings (issues #214, #215).
///
/// A CLI command resolved its keyring up to three times (the tunnel, the tool
/// key, the group keys) and the MCP server once per tool call, each a PBKDF2
/// with 65,536 iterations. The memo keeps the decrypted keyring of each file
/// keyed by the SHA-256 of the file bytes and of the password: every load
/// still reads the file, so an edited or replaced keyring (or another
/// password) misses and is decrypted again. Neither the password nor the file
/// is kept, only their digests and the decrypted keyring that commands held in
/// memory anyway.
mod keyring_memo {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use sha2::{Digest, Sha256};

    /// Decrypts so far (see [`super::keyring_decrypt_count`]).
    pub(super) static DECRYPTS: AtomicUsize = AtomicUsize::new(0);

    /// Nanoseconds spent in those decrypts (see
    /// [`super::keyring_decrypt_time`]).
    pub(super) static DECRYPT_NANOS: AtomicU64 = AtomicU64::new(0);

    /// Counts one decrypt that took `took`.
    pub(super) fn record_decrypt(took: std::time::Duration) {
        DECRYPTS.fetch_add(1, Ordering::Relaxed);
        let nanos = u64::try_from(took.as_nanos()).unwrap_or(u64::MAX);
        DECRYPT_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }

    /// The memo key: SHA-256 over the password digest and the file bytes.
    pub(super) type Key = [u8; 32];

    /// One memoized keyring per path.
    static ENTRIES: Mutex<Vec<(PathBuf, Key, Arc<bussard_project::Keyring>)>> =
        Mutex::new(Vec::new());

    /// The memo key for `xml` decrypted with `password`.
    pub(super) fn key(xml: &str, password: &str) -> Key {
        let mut hasher = Sha256::new();
        hasher.update(Sha256::digest(password.as_bytes()));
        hasher.update(xml.as_bytes());
        hasher.finalize().into()
    }

    /// The memoized keyring for `path`, if its key still matches.
    pub(super) fn get(path: &Path, key: &Key) -> Option<Arc<bussard_project::Keyring>> {
        let entries = ENTRIES.lock().ok()?;
        entries
            .iter()
            .find(|(p, k, _)| p == path && k == key)
            .map(|(_, _, keyring)| Arc::clone(keyring))
    }

    /// Memoizes `keyring` for `path`, replacing an older entry for it.
    pub(super) fn put(path: &Path, key: Key, keyring: &Arc<bussard_project::Keyring>) {
        let Ok(mut entries) = ENTRIES.lock() else {
            return;
        };
        entries.retain(|(p, _, _)| p != path);
        entries.push((path.to_path_buf(), key, Arc::clone(keyring)));
    }
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
    match bussard_model::dotenv::var(SECURE_ALGORITHM_ENV)
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
        assert!(resolve(ia("1.1.2")?, ToolKeySource::default(), false)?.is_none());
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
            false,
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
            false,
        )
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(err.contains("mutually exclusive"), "{err}");
        Ok(())
    }

    /// A synthetic keyring (the one `keyring_tunnel_only.rs` uses), made-up
    /// keys and password only.
    const KEYRING: &str = r#"<Keyring Project="Synthetic" CreatedBy="bussard-test" Created="2026-02-03T04:05:06" Signature="BwFnB3x3sq9qwzQsIIYDHQ==" xmlns="http://knx.org/xml/keyring/1">
  <Backbone MulticastAddress="224.0.23.12" Latency="1000" Key="XXLSoIYX1PClHpjLLr06xw==" />
  <Interface Type="Tunneling" Host="1.1.0" IndividualAddress="1.1.200" UserID="2" Password="CEuTO5HdZ/da1DOMrSJhAQZ94w6kq3rM2I2EFv/3fWw=" Authentication="fj0EBnFwaOJuRN85Aovn5Z8UU1ndm0p0F5tkraeg72Y=">
    <Group Address="2563" Senders="1.1.10" />
  </Interface>
  <GroupAddresses>
    <Group Address="2563" Key="9gsADI4+cx1p65cAhr5GDA==" />
  </GroupAddresses>
  <Devices>
    <Device IndividualAddress="1.1.10" ToolKey="4KejWFAOVLtfuK2uo4tiyA==" ManagementPassword="v66sERBaqXzGcl6zuAsdsA==" Authentication="Qoy1wZsb3MhAe+PdJd6p4uHl3mt02IukjeAPcy2BWrE=" SequenceNumber="42" />
  </Devices>
</Keyring>"#;

    /// The synthetic keyring's made-up password.
    const KEYRING_PASSWORD: &str = "synthetic-keyring-pw";

    #[test]
    fn test_load_keyring_with_decrypts_once_and_misses_on_a_changed_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("bussard-keyring-memo-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("keys.knxkeys");
        std::fs::write(&path, KEYRING)?;
        let first = load_keyring_with(&path, KEYRING_PASSWORD)?;
        let again = load_keyring_with(&path, KEYRING_PASSWORD)?;
        assert!(
            Arc::ptr_eq(&first, &again),
            "the second load is the memoized keyring"
        );
        // Another password misses (and fails to decrypt), never the memo.
        assert!(load_keyring_with(&path, "wrong-password").is_err());
        // A changed file misses and is decrypted again.
        std::fs::write(&path, format!("{KEYRING}\n"))?;
        let changed = load_keyring_with(&path, KEYRING_PASSWORD)?;
        assert!(
            !Arc::ptr_eq(&first, &changed),
            "an edited keyring is decrypted again"
        );
        assert_eq!(changed.group_keys.len(), first.group_keys.len());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// The key store `bussard.keys` loads through the same path and serves
    /// the same tool keys, group keys and tunnelling users (issue #241).
    #[test]
    fn test_load_keyring_with_reads_the_key_store() -> Result<(), Box<dyn std::error::Error>> {
        let dir =
            std::env::temp_dir().join(format!("bussard-keystore-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let keyring = bussard_project::parse_keyring(KEYRING, KEYRING_PASSWORD)?;
        let mut store = bussard_project::KeyStore::new("");
        store.merge_keyring(&keyring);
        store.save(&dir, KEYRING_PASSWORD)?;
        let path = bussard_project::KeyStore::path(&dir);
        let loaded = load_keyring_with(&path, KEYRING_PASSWORD)?;
        let ia: IndividualAddress = "1.1.10".parse()?;
        assert_eq!(loaded.tool_key(ia), keyring.tool_key(ia));
        assert_eq!(loaded.group_keys, keyring.group_keys);
        assert_eq!(loaded.interfaces.len(), keyring.interfaces.len());
        assert!(matches!(
            load_keyring_with(&path, "wrong-password"),
            Err(SecureKeyError::Store { .. })
        ));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
