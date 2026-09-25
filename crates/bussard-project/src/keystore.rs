//! The bussard key store, `bussard.keys` next to `bussard.lock` (issue #241).
//!
//! The store is bussard's own copy of the KNX Secure key material: the backbone
//! key, the KNXnet/IP Secure interfaces and their credentials, per-device tool
//! keys, management passwords, authentication codes, serial numbers and factory
//! keys (FDSK), and the group keys. It is git-tracked by design, so a checkout
//! recovers the whole installation, keys included.
//!
//! # Format
//!
//! The file is the `.knxkeys` dialect of spec §4 with a few extra attributes,
//! protected by the same scheme, with the same keyring password
//! (`BUSSARD_KEYRING_PASSWORD`):
//!
//! - the keyring key is `PBKDF2-HMAC-SHA256(password, "1.keyring.ets.knx.org",
//!   65536)` (spec §4.1);
//! - every key and password attribute is AES-128-CBC encrypted under it, with
//!   the IV `sha256(Created)[..16]` (spec §4.2, §4.3);
//! - the root `Signature` is the truncated SHA-256 over the canonical
//!   serialization, ending with the keyring key (spec §4.4), so it is both the
//!   password check and the tamper check.
//!
//! On top of an ETS export the store carries `Format="bussard.keys/1"` on the
//! root, and `SerialNumber` and `FDSK` (encrypted) on a `<Device>`, whose
//! `ToolKey` becomes optional (a device known only by its factory key). Group
//! addresses are written three-level (`1/2/3`) for readable diffs. `Created`
//! is fixed when the store is first written and password prefixes are keyed
//! and deterministic ([`bussard_secure::keyring_password_prefix`]), so an
//! unchanged key or password keeps its ciphertext and a diff shows only what
//! moved.
//!
//! bussard's own Data Secure send sequences are not stored: they are seeded
//! from the clock ([`bussard_secure::Sequence::seed`]). The `SequenceNumber`
//! an ETS export records per device is carried through verbatim for the
//! export and the security individual address table.
//!
//! # Key hygiene
//!
//! [`KeyStore`] and its children hold keys as [`Key16`] and passwords as
//! [`Password`], have redacting `Debug` impls and no `Serialize`. The
//! serializable views, [`KeyStoreSummary`] and [`ImportReport`], carry counts,
//! addresses and presence flags only.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use bussard_secure::crypto::latin1_bytes;
use bussard_secure::{
    CryptoError, Key16, Password, keyring_encrypt_key, keyring_encrypt_password,
    keyring_password_prefix, pbkdf2_key, random_bytes, salt,
};

use bussard_model::{GroupAddress, IndividualAddress};

use crate::keyring::{
    Backbone, KEY_LEN, Keyring, KeyringError, attr, canonical_serialization, created_iv,
    decrypt_key, optional_password, parse_ga, parse_ia, read_created, require, verify_signature,
};

/// The key store's file name, next to `bussard.lock`.
pub const KEYSTORE_FILE: &str = "bussard.keys";

/// The previous store, kept by every successful write until the next one.
pub const KEYSTORE_BACKUP_FILE: &str = "bussard.keys.bak";

/// The temporary file a write goes through before the rename.
const KEYSTORE_TEMP_FILE: &str = ".bussard.keys.tmp";

/// The `Format` attribute of the store's root element.
pub const KEYSTORE_FORMAT: &str = "bussard.keys/1";

/// The namespace of the store's root element.
const KEYSTORE_NAMESPACE: &str = "https://github.com/tmbo/bussard/xml/keys/1";

/// The namespace ETS writes on a `.knxkeys` root.
const KNXKEYS_NAMESPACE: &str = "http://knx.org/xml/keyring/1";

/// The header comment of the store file (not signed, spec §4.4).
const KEYSTORE_HEADER: &str = "<!-- bussard key store (issue #241). Encrypted with the keyring password \
(BUSSARD_KEYRING_PASSWORD) and git-tracked by design. Change it with `bussard keys`, \
not by hand: the signature covers every attribute. -->";

/// The length of a KNX serial number in bytes.
const SERIAL_LEN: usize = 6;

/// A KNX serial number (6 bytes: manufacturer id and device number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SerialNumber(pub [u8; SERIAL_LEN]);

impl std::fmt::Display for SerialNumber {
    /// Twelve upper-case hex digits, `00FA12345678`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for SerialNumber {
    type Err = String;

    /// Parses twelve hex digits, optionally split by `:` or `-`
    /// (`00FA:12345678`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex: String = s.chars().filter(|c| *c != ':' && *c != '-').collect();
        if hex.len() != SERIAL_LEN * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("not a 12-hex-digit serial number: {s:?}"));
        }
        let mut out = [0u8; SERIAL_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = hex.get(i * 2..i * 2 + 2).ok_or("short serial number")?;
            *byte = u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?;
        }
        Ok(SerialNumber(out))
    }
}

/// A KNXnet/IP (or USB) interface in the store and its credentials.
#[derive(Clone)]
pub struct StoreInterface {
    /// The `Type` attribute (`Tunneling`, `USB`, `Backbone`), empty if absent.
    pub interface_type: String,
    /// The interface's individual address (a tunnel address for a tunnelling
    /// user).
    pub ia: IndividualAddress,
    /// The individual address of the IP interface itself, if listed.
    pub host: Option<IndividualAddress>,
    /// The tunnel/management user id.
    pub user_id: u8,
    /// The user password (the session password).
    pub password: Option<Password>,
    /// The device authentication code.
    pub authentication: Option<Password>,
    /// The group addresses this interface may send to, with the raw ETS
    /// `Senders` attribute when present.
    pub gas: Vec<(GroupAddress, Option<String>)>,
}

impl StoreInterface {
    /// The merge identity of an interface: its type and address.
    fn identity(&self) -> (String, IndividualAddress) {
        (self.interface_type.to_ascii_lowercase(), self.ia)
    }

    /// Whether two interfaces carry the same attributes and credentials.
    fn same_as(&self, other: &StoreInterface) -> bool {
        self.interface_type == other.interface_type
            && self.ia == other.ia
            && self.host == other.host
            && self.user_id == other.user_id
            && self.password == other.password
            && self.authentication == other.authentication
            && self.gas == other.gas
    }
}

impl std::fmt::Debug for StoreInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreInterface")
            .field("interface_type", &self.interface_type)
            .field("ia", &self.ia)
            .field("host", &self.host)
            .field("user_id", &self.user_id)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "authentication",
                &self.authentication.as_ref().map(|_| "<redacted>"),
            )
            .field("gas", &self.gas.len())
            .finish()
    }
}

/// A device in the store: its tool key, identity and factory key.
#[derive(Clone, Default)]
pub struct StoreDevice {
    /// The tool key ETS (or bussard) set; `None` for a device known only by
    /// its factory key.
    pub tool_key: Option<Key16>,
    /// The device's serial number, when known.
    pub serial: Option<SerialNumber>,
    /// The factory default setup key, decoded from the device certificate.
    /// Never dropped by an import: it is the only way back into a
    /// factory-reset device.
    pub fdsk: Option<Key16>,
    /// The KNXnet/IP Secure management password (user id 1).
    pub management_password: Option<Password>,
    /// The KNXnet/IP Secure device authentication code.
    pub authentication: Option<Password>,
    /// The `SequenceNumber` the last ETS export recorded for this device,
    /// carried through for the export. bussard never seeds its own send
    /// sequence from it.
    pub ets_sequence: Option<u64>,
}

impl std::fmt::Debug for StoreDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreDevice")
            .field("tool_key", &self.tool_key.as_ref().map(|_| "<redacted>"))
            .field("serial", &self.serial.map(|s| s.to_string()))
            .field("fdsk", &self.fdsk.as_ref().map(|_| "<redacted>"))
            .field(
                "management_password",
                &self.management_password.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "authentication",
                &self.authentication.as_ref().map(|_| "<redacted>"),
            )
            .field("ets_sequence", &self.ets_sequence)
            .finish()
    }
}

/// The decrypted key store (see the module docs for the format).
pub struct KeyStore {
    /// The ETS project the keys belong to.
    pub project: String,
    /// The store's `Created` timestamp: fixed when the store is first written,
    /// it seeds the attribute IV (spec §4.2).
    pub created: String,
    /// The backbone (routing) key, multicast address and latency.
    pub backbone: Option<Backbone>,
    /// The interfaces and their credentials.
    pub interfaces: Vec<StoreInterface>,
    /// The devices by individual address.
    pub devices: BTreeMap<IndividualAddress, StoreDevice>,
    /// The group keys by group address.
    pub group_keys: BTreeMap<GroupAddress, Key16>,
}

impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore")
            .field("project", &self.project)
            .field("created", &self.created)
            .field("backbone", &self.backbone)
            .field("interfaces", &self.interfaces)
            .field("devices", &self.devices)
            .field(
                "group_keys",
                &format_args!("<{} redacted>", self.group_keys.len()),
            )
            .finish()
    }
}

/// An error reading, writing, importing into or exporting the key store.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// The store (or the `.knxkeys` it was built from) failed to parse,
    /// decrypt, or verify: a wrong password surfaces here as
    /// [`KeyringError::SignatureMismatch`].
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    /// A file could not be read or written.
    #[error("{action} {path}: {source}")]
    Io {
        /// What was being done.
        action: &'static str,
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A crypto primitive failed while encrypting.
    #[error("encrypting the key store: {0}")]
    Crypto(#[from] CryptoError),
    /// The file is not a bussard key store (or a newer format).
    #[error("{path} is not a {KEYSTORE_FORMAT} key store (Format = {found:?})")]
    Format {
        /// The file.
        path: PathBuf,
        /// The `Format` attribute found, if any.
        found: Option<String>,
    },
}

/// The outcome of [`KeyStore::save`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveOutcome {
    /// The store was written; the previous file (if any) is now the `.bak`.
    Written {
        /// Whether a previous store was kept as `bussard.keys.bak`.
        backup: bool,
    },
    /// The encrypted bytes were already on disk; nothing was touched.
    Unchanged,
}

/// How an import changed the backbone key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackboneChange {
    /// Neither side has a backbone.
    Absent,
    /// The export brought a backbone the store did not have.
    Added,
    /// The export's backbone key, address or latency differ; the store takes it.
    Changed,
    /// Same backbone on both sides, or none in the export (the store keeps its).
    Unchanged,
}

/// What an import of a `.knxkeys` export changed in the store. Addresses and
/// counts only; never a key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ImportReport {
    /// The project name of the export.
    pub project: String,
    /// The backbone key.
    pub backbone: BackboneChange,
    /// Devices new to the store.
    pub devices_added: Vec<String>,
    /// Devices whose tool key the export rotated.
    pub tool_keys_rotated: Vec<String>,
    /// Devices whose management password or authentication code changed.
    pub device_credentials_updated: Vec<String>,
    /// Devices whose recorded ETS sequence number changed.
    pub ets_sequences_updated: Vec<String>,
    /// Devices present on both sides with nothing changed.
    pub devices_unchanged: usize,
    /// Devices in the store but not in the export (kept).
    pub devices_kept: Vec<String>,
    /// Factory keys in the store after the import (never dropped).
    pub fdsks_kept: usize,
    /// Group keys new to the store.
    pub group_keys_added: Vec<String>,
    /// Group keys the export rotated.
    pub group_keys_rotated: Vec<String>,
    /// Group keys present on both sides and equal.
    pub group_keys_unchanged: usize,
    /// Group keys in the store but not in the export (kept).
    pub group_keys_kept: usize,
    /// Interfaces new to the store (`type address`).
    pub interfaces_added: Vec<String>,
    /// Interfaces whose credentials or attributes changed.
    pub interfaces_updated: Vec<String>,
    /// Interfaces present on both sides and equal.
    pub interfaces_unchanged: usize,
}

impl ImportReport {
    /// Whether the import changed anything in the store.
    pub fn changed(&self) -> bool {
        !matches!(
            self.backbone,
            BackboneChange::Absent | BackboneChange::Unchanged
        ) || !self.devices_added.is_empty()
            || !self.tool_keys_rotated.is_empty()
            || !self.device_credentials_updated.is_empty()
            || !self.ets_sequences_updated.is_empty()
            || !self.group_keys_added.is_empty()
            || !self.group_keys_rotated.is_empty()
            || !self.interfaces_added.is_empty()
            || !self.interfaces_updated.is_empty()
    }
}

/// A redaction-safe summary of the store: counts, addresses and presence
/// flags, never a key. Serializable for `bussard keys show --json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KeyStoreSummary {
    /// The ETS project the keys belong to.
    pub project: String,
    /// The store's `Created` timestamp.
    pub created: String,
    /// Whether a backbone key is present.
    pub has_backbone_key: bool,
    /// The backbone multicast address, when present.
    pub backbone_multicast: Option<String>,
    /// The devices.
    pub devices: Vec<DeviceSummary>,
    /// The interfaces.
    pub interfaces: Vec<InterfaceSummary>,
    /// The number of group keys.
    pub group_key_count: usize,
    /// The group addresses that have a key (three-level).
    pub group_keys: Vec<String>,
}

/// One device of a [`KeyStoreSummary`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeviceSummary {
    /// The individual address.
    pub address: String,
    /// The serial number, when known.
    pub serial: Option<String>,
    /// Whether a tool key is stored.
    pub has_tool_key: bool,
    /// Whether a factory key (FDSK) is stored.
    pub has_fdsk: bool,
    /// Whether a KNXnet/IP Secure management password is stored.
    pub has_management_password: bool,
    /// Whether a device authentication code is stored.
    pub has_authentication: bool,
}

/// One interface of a [`KeyStoreSummary`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InterfaceSummary {
    /// The interface type (`Tunneling`, `USB`, `Backbone`).
    pub interface_type: String,
    /// The interface (tunnel) address.
    pub address: String,
    /// The host device's address, when listed.
    pub host: Option<String>,
    /// The user id.
    pub user_id: u8,
    /// Whether a user password is stored.
    pub has_password: bool,
    /// Whether a device authentication code is stored.
    pub has_authentication: bool,
    /// How many group addresses the interface may send to.
    pub group_addresses: usize,
}

/// A `.knxkeys` export produced by [`KeyStore::export_knxkeys`].
pub struct KnxkeysExport {
    /// The signed XML document.
    pub xml: String,
    /// Devices left out because the store has no tool key for them (ETS
    /// requires one per `<Device>`).
    pub skipped_devices: Vec<IndividualAddress>,
    /// Devices written.
    pub devices: usize,
    /// Group keys written.
    pub group_keys: usize,
    /// Interfaces written.
    pub interfaces: usize,
}

impl std::fmt::Debug for KnxkeysExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnxkeysExport")
            .field("xml", &format_args!("<{} bytes>", self.xml.len()))
            .field("skipped_devices", &self.skipped_devices)
            .field("devices", &self.devices)
            .field("group_keys", &self.group_keys)
            .field("interfaces", &self.interfaces)
            .finish()
    }
}

impl KeyStore {
    /// An empty store for `project`, created now.
    pub fn new(project: &str) -> Self {
        KeyStore {
            project: project.to_string(),
            created: now_timestamp(),
            backbone: None,
            interfaces: Vec::new(),
            devices: BTreeMap::new(),
            group_keys: BTreeMap::new(),
        }
    }

    /// The path of the store in the model directory `dir`.
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(KEYSTORE_FILE)
    }

    /// The tool key of `ia`, if stored.
    pub fn tool_key(&self, ia: IndividualAddress) -> Option<&Key16> {
        self.devices.get(&ia).and_then(|d| d.tool_key.as_ref())
    }

    /// The group key of `ga`, if stored.
    pub fn group_key(&self, ga: GroupAddress) -> Option<&Key16> {
        self.group_keys.get(&ga)
    }

    /// Records a device's factory key and serial number (from its certificate).
    /// Returns whether anything changed.
    pub fn record_fdsk(
        &mut self,
        ia: IndividualAddress,
        serial: Option<SerialNumber>,
        fdsk: Key16,
    ) -> bool {
        let device = self.devices.entry(ia).or_default();
        let mut changed = false;
        if device.fdsk.as_ref() != Some(&fdsk) {
            device.fdsk = Some(fdsk);
            changed = true;
        }
        if serial.is_some() && device.serial != serial {
            device.serial = serial;
            changed = true;
        }
        changed
    }

    /// Loads the store from the model directory `dir`: `Ok(None)` when there
    /// is no `bussard.keys`.
    ///
    /// # Errors
    ///
    /// An unreadable file, a wrong password
    /// ([`KeyringError::SignatureMismatch`]), or a malformed store.
    pub fn load(dir: &Path, password: &str) -> Result<Option<Self>, KeyStoreError> {
        let path = Self::path(dir);
        let xml = match std::fs::read_to_string(&path) {
            Ok(xml) => xml,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(KeyStoreError::Io {
                    action: "reading",
                    path,
                    source,
                });
            }
        };
        Self::parse(&xml, password).map(Some).map_err(|e| match e {
            KeyStoreError::Format { found, .. } => KeyStoreError::Format { path, found },
            other => other,
        })
    }

    /// Parses and verifies a store from its XML text.
    ///
    /// # Errors
    ///
    /// A wrong password or tampered file
    /// ([`KeyringError::SignatureMismatch`]), a malformed document, or a file
    /// that is not a `bussard.keys/1` store.
    pub fn parse(xml: &str, password: &str) -> Result<Self, KeyStoreError> {
        let keyring_key = pbkdf2_key(&Zeroizing::new(latin1_bytes(password)), salt::KEYRING);
        let created = read_created(xml)?;
        let iv = created_iv(&created);
        verify_signature(xml, &keyring_key)?;
        parse_store(xml, &keyring_key, &iv)
    }

    /// Serializes and encrypts the store to its XML text.
    ///
    /// # Errors
    ///
    /// A string too long for the signature framing, or a crypto failure.
    pub fn to_xml(&self, password: &str) -> Result<String, KeyStoreError> {
        let keyring_key = pbkdf2_key(&Zeroizing::new(latin1_bytes(password)), salt::KEYRING);
        let iv = created_iv(&self.created);
        let mut w = XmlWriter::new(&keyring_key, iv, PrefixMode::Keyed);
        w.open(
            "Keyring",
            &[
                ("Project", self.project.clone()),
                ("CreatedBy", created_by()),
                ("Created", self.created.clone()),
                ("Format", KEYSTORE_FORMAT.to_string()),
                ("xmlns", KEYSTORE_NAMESPACE.to_string()),
            ],
            false,
        );
        self.write_body(&mut w, GaStyle::ThreeLevel, true)?;
        w.close("Keyring");
        sign(&w.finish(), &keyring_key, Some(KEYSTORE_HEADER))
    }

    /// Writes the store atomically into the model directory `dir`: the new
    /// file goes through a temporary file and a rename, and the previous
    /// store becomes `bussard.keys.bak`. Writes nothing when the encrypted
    /// bytes are unchanged.
    ///
    /// # Errors
    ///
    /// An I/O failure (the previous store is left in place) or an encryption
    /// failure.
    pub fn save(&self, dir: &Path, password: &str) -> Result<SaveOutcome, KeyStoreError> {
        let xml = self.to_xml(password)?;
        write_atomic(dir, &xml)
    }

    /// Merges a decrypted `.knxkeys` export into the store (issue #241):
    /// new devices, rotated tool keys, changed credentials and group keys are
    /// taken from the export; entries the export lacks are kept, and a factory
    /// key or serial number is never dropped.
    pub fn merge_keyring(&mut self, keyring: &Keyring) -> ImportReport {
        let mut report = ImportReport {
            project: keyring.project.clone(),
            backbone: BackboneChange::Absent,
            devices_added: Vec::new(),
            tool_keys_rotated: Vec::new(),
            device_credentials_updated: Vec::new(),
            ets_sequences_updated: Vec::new(),
            devices_unchanged: 0,
            devices_kept: Vec::new(),
            fdsks_kept: 0,
            group_keys_added: Vec::new(),
            group_keys_rotated: Vec::new(),
            group_keys_unchanged: 0,
            group_keys_kept: 0,
            interfaces_added: Vec::new(),
            interfaces_updated: Vec::new(),
            interfaces_unchanged: 0,
        };
        if !keyring.project.is_empty() {
            self.project = keyring.project.clone();
        }

        report.backbone = match (&self.backbone, &keyring.backbone) {
            (_, None) if self.backbone.is_some() => BackboneChange::Unchanged,
            (_, None) => BackboneChange::Absent,
            (None, Some(_)) => BackboneChange::Added,
            (Some(ours), Some(theirs)) => {
                if ours.key == theirs.key
                    && ours.multicast == theirs.multicast
                    && ours.latency_ms == theirs.latency_ms
                {
                    BackboneChange::Unchanged
                } else {
                    BackboneChange::Changed
                }
            }
        };
        if let Some(theirs) = &keyring.backbone {
            self.backbone = Some(Backbone {
                key: theirs.key.clone(),
                multicast: theirs.multicast,
                latency_ms: theirs.latency_ms,
            });
        }

        // Interfaces, by type and address.
        for theirs in &keyring.interfaces {
            let incoming = StoreInterface {
                interface_type: theirs.interface_type.clone(),
                ia: theirs.ia,
                host: theirs.host,
                user_id: theirs.user_id,
                password: theirs.password.clone(),
                authentication: theirs.authentication.clone(),
                gas: theirs
                    .gas
                    .iter()
                    .map(|ga| (*ga, theirs.group_senders.get(ga).cloned()))
                    .collect(),
            };
            let label = format!("{} {}", display_type(&incoming.interface_type), incoming.ia);
            match self
                .interfaces
                .iter_mut()
                .find(|i| i.identity() == incoming.identity())
            {
                Some(ours) if ours.same_as(&incoming) => report.interfaces_unchanged += 1,
                Some(ours) => {
                    *ours = incoming;
                    report.interfaces_updated.push(label);
                }
                None => {
                    self.interfaces.push(incoming);
                    report.interfaces_added.push(label);
                }
            }
        }

        // Devices, by individual address.
        let mut seen = std::collections::BTreeSet::new();
        for theirs in &keyring.devices {
            seen.insert(theirs.ia);
            let address = theirs.ia.to_string();
            let ours = match self.devices.get_mut(&theirs.ia) {
                Some(ours) => ours,
                None => {
                    self.devices.insert(
                        theirs.ia,
                        StoreDevice {
                            tool_key: Some(theirs.tool_key.clone()),
                            serial: None,
                            fdsk: None,
                            management_password: theirs.management_password.clone(),
                            authentication: theirs.authentication.clone(),
                            ets_sequence: Some(theirs.seq),
                        },
                    );
                    report.devices_added.push(address);
                    continue;
                }
            };
            let mut changed = false;
            if ours.tool_key.as_ref() != Some(&theirs.tool_key) {
                ours.tool_key = Some(theirs.tool_key.clone());
                report.tool_keys_rotated.push(address.clone());
                changed = true;
            }
            // A credential the export carries replaces ours; one it lacks is
            // kept (an export never removes what bussard recorded).
            let mut credentials = false;
            if let Some(pw) = &theirs.management_password
                && ours.management_password.as_ref() != Some(pw)
            {
                ours.management_password = Some(pw.clone());
                credentials = true;
            }
            if let Some(auth) = &theirs.authentication
                && ours.authentication.as_ref() != Some(auth)
            {
                ours.authentication = Some(auth.clone());
                credentials = true;
            }
            if credentials {
                report.device_credentials_updated.push(address.clone());
                changed = true;
            }
            if ours.ets_sequence != Some(theirs.seq) {
                ours.ets_sequence = Some(theirs.seq);
                report.ets_sequences_updated.push(address);
                changed = true;
            }
            if !changed {
                report.devices_unchanged += 1;
            }
        }
        report.devices_kept = self
            .devices
            .keys()
            .filter(|ia| !seen.contains(ia))
            .map(|ia| ia.to_string())
            .collect();
        report.fdsks_kept = self.devices.values().filter(|d| d.fdsk.is_some()).count();

        // Group keys, by group address.
        for (ga, key) in &keyring.group_keys {
            match self.group_keys.get(ga) {
                Some(ours) if ours == key => report.group_keys_unchanged += 1,
                Some(_) => {
                    self.group_keys.insert(*ga, key.clone());
                    report.group_keys_rotated.push(ga.to_string());
                }
                None => {
                    self.group_keys.insert(*ga, key.clone());
                    report.group_keys_added.push(ga.to_string());
                }
            }
        }
        report.group_keys_added.sort();
        report.group_keys_rotated.sort();
        report.group_keys_kept = self
            .group_keys
            .keys()
            .filter(|ga| !keyring.group_keys.contains_key(ga))
            .count();
        report
    }

    /// Builds a signed `.knxkeys` export ETS accepts (spec §4, issue #241):
    /// the ETS element and attribute set, raw group addresses, a fresh
    /// `Created` and random password prefixes, signed with the keyring key of
    /// `password`. Devices without a tool key are left out (listed in
    /// [`KnxkeysExport::skipped_devices`]); serial numbers and factory keys
    /// never leave the store.
    ///
    /// # Errors
    ///
    /// A string too long for the signature framing, or a crypto failure.
    pub fn export_knxkeys(&self, password: &str) -> Result<KnxkeysExport, KeyStoreError> {
        let keyring_key = pbkdf2_key(&Zeroizing::new(latin1_bytes(password)), salt::KEYRING);
        let created = now_timestamp();
        let iv = created_iv(&created);
        let mut w = XmlWriter::new(&keyring_key, iv, PrefixMode::Random);
        w.open(
            "Keyring",
            &[
                ("Project", self.project.clone()),
                ("CreatedBy", created_by()),
                ("Created", created),
                ("xmlns", KNXKEYS_NAMESPACE.to_string()),
            ],
            false,
        );
        self.write_body(&mut w, GaStyle::Raw, false)?;
        w.close("Keyring");
        let xml = sign(&w.finish(), &keyring_key, None)?;
        Ok(KnxkeysExport {
            xml,
            skipped_devices: self
                .devices
                .iter()
                .filter(|(_, d)| d.tool_key.is_none())
                .map(|(ia, _)| *ia)
                .collect(),
            devices: self
                .devices
                .values()
                .filter(|d| d.tool_key.is_some())
                .count(),
            group_keys: self.group_keys.len(),
            interfaces: self.interfaces.len(),
        })
    }

    /// The redaction-safe summary (counts, addresses, presence flags).
    pub fn summary(&self) -> KeyStoreSummary {
        KeyStoreSummary {
            project: self.project.clone(),
            created: self.created.clone(),
            has_backbone_key: self.backbone.is_some(),
            backbone_multicast: self.backbone.as_ref().map(|b| b.multicast.to_string()),
            devices: self
                .devices
                .iter()
                .map(|(ia, d)| DeviceSummary {
                    address: ia.to_string(),
                    serial: d.serial.map(|s| s.to_string()),
                    has_tool_key: d.tool_key.is_some(),
                    has_fdsk: d.fdsk.is_some(),
                    has_management_password: d.management_password.is_some(),
                    has_authentication: d.authentication.is_some(),
                })
                .collect(),
            interfaces: self
                .interfaces
                .iter()
                .map(|i| InterfaceSummary {
                    interface_type: i.interface_type.clone(),
                    address: i.ia.to_string(),
                    host: i.host.map(|h| h.to_string()),
                    user_id: i.user_id,
                    has_password: i.password.is_some(),
                    has_authentication: i.authentication.is_some(),
                    group_addresses: i.gas.len(),
                })
                .collect(),
            group_key_count: self.group_keys.len(),
            group_keys: self.group_keys.keys().map(|ga| ga.to_string()).collect(),
        }
    }

    /// Writes the backbone, interfaces, group keys and devices in ETS order.
    /// `store` adds the store-only attributes (`SerialNumber`, `FDSK`) and
    /// keeps tool-key-less devices.
    fn write_body(
        &self,
        w: &mut XmlWriter<'_>,
        ga_style: GaStyle,
        store: bool,
    ) -> Result<(), KeyStoreError> {
        if let Some(b) = &self.backbone {
            let key = w.key(&b.key)?;
            w.open(
                "Backbone",
                &[
                    ("MulticastAddress", b.multicast.to_string()),
                    ("Latency", b.latency_ms.to_string()),
                    ("Key", key),
                ],
                true,
            );
        }
        let mut interfaces: Vec<&StoreInterface> = self.interfaces.iter().collect();
        interfaces.sort_by_key(|i| (i.ia, i.user_id, i.interface_type.clone()));
        for i in interfaces {
            let mut attrs = Vec::new();
            if !i.interface_type.is_empty() {
                attrs.push(("Type", i.interface_type.clone()));
            }
            if let Some(host) = i.host {
                attrs.push(("Host", host.to_string()));
            }
            attrs.push(("IndividualAddress", i.ia.to_string()));
            attrs.push(("UserID", i.user_id.to_string()));
            let context = format!("Interface/{}/{}", i.ia, i.user_id);
            if let Some(pw) = &i.password {
                attrs.push(("Password", w.password(&format!("{context}/Password"), pw)?));
            }
            if let Some(auth) = &i.authentication {
                attrs.push((
                    "Authentication",
                    w.password(&format!("{context}/Authentication"), auth)?,
                ));
            }
            w.open("Interface", &attrs, i.gas.is_empty());
            if !i.gas.is_empty() {
                for (ga, senders) in &i.gas {
                    let mut attrs = vec![("Address", ga_style.render(*ga))];
                    if let Some(s) = senders {
                        attrs.push(("Senders", s.clone()));
                    }
                    w.open("Group", &attrs, true);
                }
                w.close("Interface");
            }
        }
        if !self.group_keys.is_empty() {
            w.open("GroupAddresses", &[], false);
            for (ga, key) in &self.group_keys {
                let key = w.key(key)?;
                w.open(
                    "Group",
                    &[("Address", ga_style.render(*ga)), ("Key", key)],
                    true,
                );
            }
            w.close("GroupAddresses");
        }
        let devices: Vec<(&IndividualAddress, &StoreDevice)> = self
            .devices
            .iter()
            .filter(|(_, d)| store || d.tool_key.is_some())
            .collect();
        if !devices.is_empty() {
            w.open("Devices", &[], false);
            for (ia, d) in devices {
                let mut attrs = vec![("IndividualAddress", ia.to_string())];
                if let Some(key) = &d.tool_key {
                    attrs.push(("ToolKey", w.key(key)?));
                }
                if store {
                    if let Some(serial) = d.serial {
                        attrs.push(("SerialNumber", serial.to_string()));
                    }
                    if let Some(fdsk) = &d.fdsk {
                        attrs.push(("FDSK", w.key(fdsk)?));
                    }
                }
                let context = format!("Device/{ia}");
                if let Some(pw) = &d.management_password {
                    attrs.push((
                        "ManagementPassword",
                        w.password(&format!("{context}/ManagementPassword"), pw)?,
                    ));
                }
                if let Some(auth) = &d.authentication {
                    attrs.push((
                        "Authentication",
                        w.password(&format!("{context}/Authentication"), auth)?,
                    ));
                }
                if let Some(seq) = d.ets_sequence {
                    attrs.push(("SequenceNumber", seq.to_string()));
                } else if !store {
                    attrs.push(("SequenceNumber", "0".to_string()));
                }
                w.open("Device", &attrs, true);
            }
            w.close("Devices");
        }
        Ok(())
    }
}

/// How group addresses are rendered.
#[derive(Clone, Copy)]
enum GaStyle {
    /// `1/2/3`, for readable store diffs.
    ThreeLevel,
    /// The raw 16-bit integer ETS writes (`2563`).
    Raw,
}

impl GaStyle {
    /// Renders `ga`.
    fn render(self, ga: GroupAddress) -> String {
        match self {
            GaStyle::ThreeLevel => ga.to_string(),
            GaStyle::Raw => ga.raw().to_string(),
        }
    }
}

/// Where the 8-byte password prefix comes from.
#[derive(Clone, Copy)]
enum PrefixMode {
    /// Keyed and deterministic, for the store's stable diffs.
    Keyed,
    /// Random, as ETS writes an export.
    Random,
}

/// A minimal XML writer that encrypts key and password attributes on the way.
struct XmlWriter<'k> {
    /// The document so far.
    out: String,
    /// The nesting depth, for indentation.
    depth: usize,
    /// The keyring key.
    keyring_key: &'k Key16,
    /// The attribute IV (from `Created`).
    iv: [u8; KEY_LEN],
    /// The password prefix mode.
    prefix: PrefixMode,
}

impl<'k> XmlWriter<'k> {
    /// A writer for one document.
    fn new(keyring_key: &'k Key16, iv: [u8; KEY_LEN], prefix: PrefixMode) -> Self {
        XmlWriter {
            out: String::new(),
            depth: 0,
            keyring_key,
            iv,
            prefix,
        }
    }

    /// The base64 ciphertext of a raw key attribute.
    fn key(&self, key: &Key16) -> Result<String, KeyStoreError> {
        Ok(BASE64.encode(keyring_encrypt_key(self.keyring_key, &self.iv, key)?))
    }

    /// The base64 ciphertext of a password attribute.
    fn password(&self, context: &str, password: &Password) -> Result<String, KeyStoreError> {
        let prefix = match self.prefix {
            PrefixMode::Keyed => keyring_password_prefix(self.keyring_key, context, password),
            PrefixMode::Random => random_bytes()?,
        };
        Ok(BASE64.encode(keyring_encrypt_password(
            self.keyring_key,
            &self.iv,
            &prefix,
            password,
        )?))
    }

    /// Opens an element (`empty` closes it right away).
    fn open(&mut self, name: &str, attrs: &[(&str, String)], empty: bool) {
        self.indent();
        self.out.push('<');
        self.out.push_str(name);
        for (key, value) in attrs {
            self.out.push(' ');
            self.out.push_str(key);
            self.out.push_str("=\"");
            escape_into(&mut self.out, value);
            self.out.push('"');
        }
        if empty {
            self.out.push_str(" />\n");
        } else {
            self.out.push_str(">\n");
            self.depth += 1;
        }
    }

    /// Closes an element.
    fn close(&mut self, name: &str) {
        self.depth = self.depth.saturating_sub(1);
        self.indent();
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push_str(">\n");
    }

    /// Indents two spaces per level.
    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
    }

    /// The document text.
    fn finish(self) -> String {
        self.out
    }
}

/// Escapes an attribute value (the five XML specials plus the whitespace a
/// conforming parser would otherwise normalize away).
fn escape_into(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
}

/// Signs a document whose root start tag has no `Signature` yet: computes
/// `sha256(canonical)[..16]` (spec §4.4) and splices it in as the first
/// attribute, behind the XML declaration and an optional comment.
fn sign(body: &str, keyring_key: &Key16, header: Option<&str>) -> Result<String, KeyStoreError> {
    let serialized = canonical_serialization(body, keyring_key)?;
    let signature = BASE64.encode(&Sha256::digest(serialized.as_slice())[..KEY_LEN]);
    let signed = body.replacen(
        "<Keyring ",
        &format!("<Keyring Signature=\"{signature}\" "),
        1,
    );
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    if let Some(header) = header {
        out.push_str(header);
        out.push('\n');
    }
    out.push_str(&signed);
    Ok(out)
}

/// The `CreatedBy` value bussard writes.
fn created_by() -> String {
    format!("bussard {}", env!("CARGO_PKG_VERSION"))
}

/// A display name for an interface type (`tunneling`, `usb`), or `interface`.
fn display_type(t: &str) -> String {
    if t.is_empty() {
        "interface".to_string()
    } else {
        t.to_ascii_lowercase()
    }
}

/// The current UTC time as `YYYY-MM-DDTHH:MM:SS`, the form of an ETS
/// `Created` attribute.
fn now_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs = i64::try_from(secs).unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Days since the Unix epoch to (year, month, day), Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Writes `xml` to `<dir>/bussard.keys` atomically, keeping the previous file
/// as `bussard.keys.bak`.
///
/// The new bytes go to a temporary file in the same directory and are synced;
/// the current store is copied to the backup (through its own temporary name,
/// so a half-written backup never replaces a good one); then the temporary
/// file is renamed over the store, so `bussard.keys` always holds either the
/// old or the new store.
fn write_atomic(dir: &Path, xml: &str) -> Result<SaveOutcome, KeyStoreError> {
    let path = dir.join(KEYSTORE_FILE);
    let io = |action: &'static str, path: &Path| {
        let path = path.to_path_buf();
        move |source| KeyStoreError::Io {
            action,
            path,
            source,
        }
    };
    let existing = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(io("reading", &path)(e)),
    };
    if existing.as_deref() == Some(xml.as_bytes()) {
        return Ok(SaveOutcome::Unchanged);
    }
    std::fs::create_dir_all(dir).map_err(io("creating", dir))?;

    let tmp = dir.join(KEYSTORE_TEMP_FILE);
    {
        let mut file = std::fs::File::create(&tmp).map_err(io("creating", &tmp))?;
        file.write_all(xml.as_bytes())
            .map_err(io("writing", &tmp))?;
        file.sync_all().map_err(io("syncing", &tmp))?;
    }
    let backup = if let Some(old) = existing {
        let bak = dir.join(KEYSTORE_BACKUP_FILE);
        let bak_tmp = dir.join(format!("{KEYSTORE_TEMP_FILE}.bak"));
        std::fs::write(&bak_tmp, old).map_err(io("writing", &bak_tmp))?;
        std::fs::rename(&bak_tmp, &bak).map_err(io("renaming to", &bak))?;
        true
    } else {
        false
    };
    std::fs::rename(&tmp, &path).map_err(io("renaming to", &path))?;
    Ok(SaveOutcome::Written { backup })
}

/// Walks a verified store document into a [`KeyStore`].
fn parse_store(
    xml: &str,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<KeyStore, KeyStoreError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut store = KeyStore {
        project: String::new(),
        created: String::new(),
        backbone: None,
        interfaces: Vec::new(),
        devices: BTreeMap::new(),
        group_keys: BTreeMap::new(),
    };
    let mut current: Option<StoreInterface> = None;
    let mut in_group_addresses = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|e| KeyringError::Xml(e.to_string()))?;
        let is_empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"Keyring" => {
                    let format = attr(&e, b"Format")?;
                    if format.as_deref() != Some(KEYSTORE_FORMAT) {
                        return Err(KeyStoreError::Format {
                            path: PathBuf::from(KEYSTORE_FILE),
                            found: format,
                        });
                    }
                    store.project = attr(&e, b"Project")?.unwrap_or_default();
                    store.created = attr(&e, b"Created")?.unwrap_or_default();
                }
                b"Backbone" => {
                    store.backbone = Some(parse_backbone(&e, keyring_key, iv)?);
                }
                b"Interface" => {
                    if let Some(done) = current.take() {
                        store.interfaces.push(done);
                    }
                    let iface = parse_interface(&e, keyring_key, iv)?;
                    if is_empty {
                        store.interfaces.push(iface);
                    } else {
                        current = Some(iface);
                    }
                }
                b"GroupAddresses" => in_group_addresses = !is_empty,
                b"Group" => {
                    let ga = parse_ga("Group/Address", &require(&e, b"Address", "Group")?)?;
                    if in_group_addresses {
                        let key =
                            decrypt_key(&e, b"Key", "GroupAddresses/Group/Key", keyring_key, iv)?;
                        store.group_keys.insert(ga, key);
                    } else if let Some(iface) = current.as_mut() {
                        iface.gas.push((ga, attr(&e, b"Senders")?));
                    }
                }
                b"Device" => {
                    let (ia, device) = parse_device(&e, keyring_key, iv)?;
                    store.devices.insert(ia, device);
                }
                _ => {}
            },
            Event::End(e) => match e.local_name().as_ref() {
                b"Interface" => {
                    if let Some(done) = current.take() {
                        store.interfaces.push(done);
                    }
                }
                b"GroupAddresses" => in_group_addresses = false,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    if let Some(done) = current.take() {
        store.interfaces.push(done);
    }
    Ok(store)
}

/// Parses a store `<Backbone>`.
fn parse_backbone(
    e: &BytesStart,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<Backbone, KeyringError> {
    let key = decrypt_key(e, b"Key", "Backbone/Key", keyring_key, iv)?;
    let multicast = require(e, b"MulticastAddress", "Backbone")?;
    let multicast: Ipv4Addr = multicast
        .parse()
        .map_err(|_| KeyringError::InvalidAttribute {
            attribute: "Backbone/MulticastAddress".to_string(),
            reason: format!("not an IPv4 address: {multicast:?}"),
        })?;
    let latency_ms = parse_number(attr(e, b"Latency")?, "Backbone/Latency")?.unwrap_or(0);
    Ok(Backbone {
        key,
        multicast,
        latency_ms,
    })
}

/// Parses a store `<Interface>` (its `<Group>` children follow).
fn parse_interface(
    e: &BytesStart,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<StoreInterface, KeyringError> {
    let ia = parse_ia(
        "Interface/IndividualAddress",
        &require(e, b"IndividualAddress", "Interface")?,
    )?;
    let host = match attr(e, b"Host")? {
        Some(s) => Some(parse_ia("Interface/Host", &s)?),
        None => None,
    };
    Ok(StoreInterface {
        interface_type: attr(e, b"Type")?.unwrap_or_default(),
        ia,
        host,
        user_id: parse_number(attr(e, b"UserID")?, "Interface/UserID")?.unwrap_or(0),
        password: optional_password(e, b"Password", "Interface/Password", keyring_key, iv)?,
        authentication: optional_password(
            e,
            b"Authentication",
            "Interface/Authentication",
            keyring_key,
            iv,
        )?,
        gas: Vec::new(),
    })
}

/// Parses a store `<Device>`.
fn parse_device(
    e: &BytesStart,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<(IndividualAddress, StoreDevice), KeyringError> {
    let ia = parse_ia(
        "Device/IndividualAddress",
        &require(e, b"IndividualAddress", "Device")?,
    )?;
    let tool_key = match attr(e, b"ToolKey")? {
        Some(_) => Some(decrypt_key(
            e,
            b"ToolKey",
            "Device/ToolKey",
            keyring_key,
            iv,
        )?),
        None => None,
    };
    let fdsk = match attr(e, b"FDSK")? {
        Some(_) => Some(decrypt_key(e, b"FDSK", "Device/FDSK", keyring_key, iv)?),
        None => None,
    };
    let serial =
        match attr(e, b"SerialNumber")? {
            Some(s) => Some(s.parse::<SerialNumber>().map_err(|reason| {
                KeyringError::InvalidAttribute {
                    attribute: "Device/SerialNumber".to_string(),
                    reason,
                }
            })?),
            None => None,
        };
    Ok((
        ia,
        StoreDevice {
            tool_key,
            serial,
            fdsk,
            management_password: optional_password(
                e,
                b"ManagementPassword",
                "Device/ManagementPassword",
                keyring_key,
                iv,
            )?,
            authentication: optional_password(
                e,
                b"Authentication",
                "Device/Authentication",
                keyring_key,
                iv,
            )?,
            ets_sequence: parse_number(attr(e, b"SequenceNumber")?, "Device/SequenceNumber")?,
        },
    ))
}

/// Parses an optional numeric attribute.
fn parse_number<T: std::str::FromStr>(
    value: Option<String>,
    attribute: &str,
) -> Result<Option<T>, KeyringError> {
    value
        .map(|s| {
            s.parse().map_err(|_| KeyringError::InvalidAttribute {
                attribute: attribute.to_string(),
                reason: format!("not a number: {s:?}"),
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::parse_keyring;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The password of the synthetic fixture (spec §12.3; never a real one).
    const PASSWORD: &str = "synthetic-keyring-pw";

    /// The committed synthetic keyring the secure tests share
    /// (`knx-sim/examples/secure/synthetic.knxkeys`): backbone `0x11 * 16`,
    /// group 1/2/3 `0x77 * 16`, device 1.1.10 tool key `0x42 * 16`, one
    /// tunnelling user at 1.1.200.
    const SYNTHETIC: &str = include_str!("../../../knx-sim/examples/secure/synthetic.knxkeys");

    fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    fn ga(s: &str) -> Result<GroupAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    /// A store imported from the synthetic fixture, plus an FDSK-only device.
    fn sample() -> Result<KeyStore, Box<dyn std::error::Error>> {
        let keyring = parse_keyring(SYNTHETIC, PASSWORD)?;
        let mut store = KeyStore::new("");
        store.merge_keyring(&keyring);
        store.record_fdsk(
            ia("1.1.20")?,
            Some("00FA:0000ABCD".parse()?),
            Key16::new([0x99; 16]),
        );
        Ok(store)
    }

    /// A fresh temp directory.
    fn temp_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-keystore-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn test_keystore_to_xml_round_trips() -> TestResult {
        let store = sample()?;
        let xml = store.to_xml(PASSWORD)?;
        let back = KeyStore::parse(&xml, PASSWORD)?;
        assert_eq!(back.project, "Synthetic");
        assert_eq!(back.created, store.created);
        let backbone = back.backbone.as_ref().ok_or("backbone")?;
        assert_eq!(backbone.key.bytes(), &[0x11; 16]);
        assert_eq!(backbone.latency_ms, 1000);
        assert_eq!(
            back.tool_key(ia("1.1.10")?).map(|k| *k.bytes()),
            Some([0x42; 16])
        );
        assert_eq!(
            back.group_key(ga("1/2/3")?).map(|k| *k.bytes()),
            Some([0x77; 16])
        );
        let fdsk_only = back.devices.get(&ia("1.1.20")?).ok_or("1.1.20")?;
        assert!(fdsk_only.tool_key.is_none());
        assert_eq!(
            fdsk_only.fdsk.as_ref().map(|k| *k.bytes()),
            Some([0x99; 16])
        );
        assert_eq!(
            fdsk_only.serial.map(|s| s.to_string()).as_deref(),
            Some("00FA0000ABCD")
        );
        let device = back.devices.get(&ia("1.1.10")?).ok_or("1.1.10")?;
        assert_eq!(device.ets_sequence, Some(42));
        assert!(device.management_password.is_some() && device.authentication.is_some());
        assert_eq!(back.interfaces.len(), 1);
        let iface = &back.interfaces[0];
        assert_eq!(
            iface.password.as_ref().map(Password::expose),
            Some("tunnel-user-pw")
        );
        assert_eq!(
            iface.authentication.as_ref().map(Password::expose),
            Some("device-auth-pw")
        );
        assert_eq!(iface.gas, vec![(ga("1/2/3")?, Some("1.1.10".to_string()))]);
        // Deterministic: the same store encrypts to the same bytes.
        assert_eq!(store.to_xml(PASSWORD)?, xml);
        assert_eq!(back.to_xml(PASSWORD)?, xml);
        Ok(())
    }

    #[test]
    fn test_keystore_parse_wrong_password_and_tamper() -> TestResult {
        let xml = sample()?.to_xml(PASSWORD)?;
        assert!(matches!(
            KeyStore::parse(&xml, "wrong"),
            Err(KeyStoreError::Keyring(KeyringError::SignatureMismatch))
        ));
        let tampered = xml.replacen(
            "IndividualAddress=\"1.1.10\"",
            "IndividualAddress=\"1.1.11\"",
            1,
        );
        assert_ne!(tampered, xml);
        assert!(matches!(
            KeyStore::parse(&tampered, PASSWORD),
            Err(KeyStoreError::Keyring(KeyringError::SignatureMismatch))
        ));
        Ok(())
    }

    #[test]
    fn test_keystore_parse_refuses_a_plain_knxkeys() {
        assert!(matches!(
            KeyStore::parse(SYNTHETIC, PASSWORD),
            Err(KeyStoreError::Format { found: None, .. })
        ));
    }

    #[test]
    fn test_export_knxkeys_round_trips_through_the_reader() -> TestResult {
        let store = sample()?;
        let export = store.export_knxkeys(PASSWORD)?;
        assert_eq!(export.skipped_devices, vec![ia("1.1.20")?]);
        assert_eq!(
            (export.devices, export.group_keys, export.interfaces),
            (1, 1, 1)
        );
        // The reader verifies the signature (spec §4.4) and decrypts it all.
        let keyring = parse_keyring(&export.xml, PASSWORD)?;
        assert_eq!(keyring.project, "Synthetic");
        assert_eq!(
            keyring.tool_key(ia("1.1.10")?).map(|k| *k.bytes()),
            Some([0x42; 16])
        );
        assert_eq!(
            keyring.group_key(ga("1/2/3")?).map(|k| *k.bytes()),
            Some([0x77; 16])
        );
        assert_eq!(keyring.devices[0].seq, 42);
        let original = parse_keyring(SYNTHETIC, PASSWORD)?;
        assert_eq!(
            keyring.interfaces[0].password,
            original.interfaces[0].password
        );
        assert_eq!(
            keyring.interfaces[0].authentication,
            original.interfaces[0].authentication
        );
        assert_eq!(
            keyring.devices[0].management_password,
            original.devices[0].management_password
        );
        assert_eq!(
            keyring.devices[0].authentication,
            original.devices[0].authentication
        );
        assert_eq!(
            keyring.interfaces[0]
                .group_senders
                .get(&ga("1/2/3")?)
                .map(String::as_str),
            Some("1.1.10")
        );
        // ETS shape: raw group addresses, the ETS namespace, no store extras.
        assert!(export.xml.contains("Address=\"2563\""));
        assert!(export.xml.contains(KNXKEYS_NAMESPACE));
        for extra in ["FDSK", "SerialNumber", "Format="] {
            assert!(
                !export.xml.contains(extra),
                "{extra} leaked into the export"
            );
        }
        // A wrong password does not verify.
        assert!(matches!(
            parse_keyring(&export.xml, "wrong"),
            Err(KeyringError::SignatureMismatch)
        ));
        Ok(())
    }

    #[test]
    fn test_merge_keyring_reports_new_rotated_and_keeps_fdsk() -> TestResult {
        let mut store = sample()?;
        // Re-importing the same export changes nothing.
        let same = store.merge_keyring(&parse_keyring(SYNTHETIC, PASSWORD)?);
        assert!(!same.changed(), "{same:?}");
        assert_eq!(same.devices_unchanged, 1);
        assert_eq!(same.devices_kept, vec!["1.1.20".to_string()]);
        assert_eq!(same.group_keys_unchanged, 1);
        assert_eq!(same.interfaces_unchanged, 1);
        assert_eq!(same.backbone, BackboneChange::Unchanged);

        // A newer export: 1.1.10's tool key rotated, the group key rotated,
        // a new device and a new group key, and 1.1.20 now has a tool key.
        let mut newer = KeyStore::new("Synthetic");
        newer.merge_keyring(&parse_keyring(SYNTHETIC, PASSWORD)?);
        newer
            .devices
            .get_mut(&ia("1.1.10")?)
            .ok_or("1.1.10")?
            .tool_key = Some(Key16::new([0x43; 16]));
        newer
            .group_keys
            .insert(ga("1/2/3")?, Key16::new([0x78; 16]));
        newer
            .group_keys
            .insert(ga("1/2/4")?, Key16::new([0x79; 16]));
        newer.devices.insert(
            ia("1.1.30")?,
            StoreDevice {
                tool_key: Some(Key16::new([0x30; 16])),
                ..StoreDevice::default()
            },
        );
        newer.devices.insert(
            ia("1.1.20")?,
            StoreDevice {
                tool_key: Some(Key16::new([0x20; 16])),
                ..StoreDevice::default()
            },
        );
        let export = newer.export_knxkeys(PASSWORD)?;
        let report = store.merge_keyring(&parse_keyring(&export.xml, PASSWORD)?);
        assert!(report.changed());
        assert_eq!(report.devices_added, vec!["1.1.30".to_string()]);
        assert_eq!(
            report.tool_keys_rotated,
            vec!["1.1.10".to_string(), "1.1.20".to_string()]
        );
        assert_eq!(report.group_keys_added, vec!["1/2/4".to_string()]);
        assert_eq!(report.group_keys_rotated, vec!["1/2/3".to_string()]);
        assert_eq!(report.fdsks_kept, 1);
        // The factory key and serial number survive the import.
        let d = store.devices.get(&ia("1.1.20")?).ok_or("1.1.20")?;
        assert_eq!(d.fdsk.as_ref().map(|k| *k.bytes()), Some([0x99; 16]));
        assert!(d.serial.is_some());
        assert_eq!(d.tool_key.as_ref().map(|k| *k.bytes()), Some([0x20; 16]));
        assert_eq!(
            store.tool_key(ia("1.1.10")?).map(|k| *k.bytes()),
            Some([0x43; 16])
        );
        Ok(())
    }

    #[test]
    fn test_merge_keyring_keeps_credentials_the_export_lacks() -> TestResult {
        let mut store = sample()?;
        let body = r#"<Keyring Project="Synthetic" Created="2026-05-06T07:08:09"><Devices><Device IndividualAddress="1.1.10" ToolKey="TOOLKEY" SequenceNumber="42" /></Devices></Keyring>"#;
        // Build the ToolKey ciphertext for 0x42 * 16 under this Created.
        let kk = pbkdf2_key(&latin1_bytes(PASSWORD), salt::KEYRING);
        let ct = BASE64.encode(keyring_encrypt_key(
            &kk,
            &created_iv("2026-05-06T07:08:09"),
            &Key16::new([0x42; 16]),
        )?);
        let body = body.replace("TOOLKEY", &ct);
        let xml = sign(&body, &kk, None)?;
        let report = store.merge_keyring(&parse_keyring(&xml, PASSWORD)?);
        assert!(!report.changed(), "{report:?}");
        let d = store.devices.get(&ia("1.1.10")?).ok_or("1.1.10")?;
        assert!(
            d.management_password.is_some(),
            "an absent credential is kept"
        );
        assert!(store.backbone.is_some(), "an absent backbone is kept");
        assert_eq!(report.group_keys_kept, 1);
        Ok(())
    }

    #[test]
    fn test_save_is_atomic_and_keeps_a_backup() -> TestResult {
        let dir = temp_dir("save")?;
        let mut store = sample()?;
        assert_eq!(
            store.save(&dir, PASSWORD)?,
            SaveOutcome::Written { backup: false }
        );
        assert!(!dir.join(KEYSTORE_BACKUP_FILE).exists());
        let first = std::fs::read_to_string(dir.join(KEYSTORE_FILE))?;
        // Same content: nothing is rewritten, no backup churn.
        assert_eq!(store.save(&dir, PASSWORD)?, SaveOutcome::Unchanged);
        store
            .group_keys
            .insert(ga("1/2/5")?, Key16::new([0x55; 16]));
        assert_eq!(
            store.save(&dir, PASSWORD)?,
            SaveOutcome::Written { backup: true }
        );
        assert_eq!(
            std::fs::read_to_string(dir.join(KEYSTORE_BACKUP_FILE))?,
            first
        );
        assert!(!dir.join(KEYSTORE_TEMP_FILE).exists());
        let loaded = KeyStore::load(&dir, PASSWORD)?.ok_or("store missing")?;
        assert_eq!(loaded.group_keys.len(), 2);
        // The backup is itself a valid store.
        let bak = std::fs::read_to_string(dir.join(KEYSTORE_BACKUP_FILE))?;
        assert_eq!(KeyStore::parse(&bak, PASSWORD)?.group_keys.len(), 1);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_load_missing_store_is_none() -> TestResult {
        let dir = temp_dir("missing")?;
        assert!(KeyStore::load(&dir, PASSWORD)?.is_none());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_unchanged_entries_keep_their_ciphertext() -> TestResult {
        let mut store = sample()?;
        let before = store.to_xml(PASSWORD)?;
        store
            .group_keys
            .insert(ga("1/2/5")?, Key16::new([0x55; 16]));
        let after = store.to_xml(PASSWORD)?;
        let lines = |s: &str| {
            s.lines()
                .map(str::to_string)
                .collect::<std::collections::BTreeSet<_>>()
        };
        let (b, a) = (lines(&before), lines(&after));
        // Only the signature line and the new group key line differ.
        assert_eq!(
            a.difference(&b).count(),
            2,
            "{:?}",
            a.difference(&b).collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn test_debug_and_json_carry_no_key_material() -> TestResult {
        let store = sample()?;
        let debug = format!("{store:?}");
        let json = serde_json::to_string(&store.summary())?;
        let report = serde_json::to_string(
            &KeyStore::new("x").merge_keyring(&parse_keyring(SYNTHETIC, PASSWORD)?),
        )?;
        for rendered in [&debug, &json, &report] {
            for leak in [
                "66, 66",
                "17, 17",
                "119, 119",
                "153, 153",
                "tunnel-user-pw",
                "device-auth-pw",
                "QkJC",
                "mZmZ",
            ] {
                assert!(!rendered.contains(leak), "leaked {leak} in {rendered}");
            }
        }
        assert!(debug.contains("<redacted>"));
        let summary = store.summary();
        assert_eq!(summary.group_keys, vec!["1/2/3".to_string()]);
        assert_eq!(summary.devices.len(), 2);
        assert!(
            summary
                .devices
                .iter()
                .any(|d| d.has_fdsk && !d.has_tool_key)
        );
        Ok(())
    }

    #[test]
    fn test_serial_number_parses_and_renders() -> TestResult {
        let s: SerialNumber = "00fa:1234abcd".parse()?;
        assert_eq!(s.to_string(), "00FA1234ABCD");
        assert!("00FA".parse::<SerialNumber>().is_err());
        assert!("00FA1234ABCZ".parse::<SerialNumber>().is_err());
        Ok(())
    }

    #[test]
    fn test_civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2018-01-05, the KNX Secure epoch: 17_536 days after 1970-01-01.
        assert_eq!(civil_from_days(17_536), (2018, 1, 5));
        assert_eq!(civil_from_days(20_721), (2026, 9, 25));
    }

    #[test]
    fn test_escape_round_trips_through_the_signature() -> TestResult {
        let mut store = KeyStore::new("A & B <\"quoted\">\n");
        store.group_keys.insert(ga("0/0/1")?, Key16::new([1; 16]));
        let back = KeyStore::parse(&store.to_xml(PASSWORD)?, PASSWORD)?;
        assert_eq!(back.project, store.project);
        Ok(())
    }
}
