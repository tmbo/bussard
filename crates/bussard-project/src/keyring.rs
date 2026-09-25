//! `.knxkeys` keyring parsing (issue #71, spec §4).
//!
//! A `.knxkeys` file is the ETS-exported bundle of KNX Secure key material: the
//! backbone (routing) key, per-interface tunnel/management credentials, per-device
//! tool keys, and per-group-address runtime keys. Sensitive attributes are
//! AES-128-CBC encrypted under a key derived from a keyring password (PBKDF2), and
//! the whole document is signed with a truncated SHA-256 over a canonical
//! serialization that ends with the password-derived key, so the signature
//! doubles as the password check (spec §4.4).
//!
//! This module decodes that format into a typed [`Keyring`] (spec §4.6):
//!
//! - [`parse_keyring`] derives the keyring key (§4.1), verifies the signature
//!   (§4.4), decrypts the encrypted attributes (§4.2, §4.3), and reads the raw
//!   keys directly.
//!
//! # Key hygiene (spec §2.3)
//!
//! Every field that holds key material is a [`bussard_secure::Key16`], which does
//! not derive a value-leaking `Debug` and is not serializable. The [`Keyring`]
//! and its children have hand-written [`std::fmt::Debug`] impls that redact key
//! material, and none of them implement `Serialize`/`Deserialize`. Nothing here
//! prints, logs, or serializes a key.
//!
//! No GPL source was consulted; the format is reimplemented from the public XKNX
//! reference and the KNX Secure specification.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use bussard_secure::crypto::latin1_bytes;
use bussard_secure::{Key16, Password, aes_cbc_decrypt, pbkdf2_key, salt};

use bussard_ets::attrs::{attr_value, attrs_map};
use bussard_model::{GroupAddress, IndividualAddress};

/// The number of bytes of raw key material in a KNX Secure key.
pub(crate) const KEY_LEN: usize = 16;

/// The number of leading bytes to skip when extracting a password from a
/// decrypted blob (spec §4.3): an 8-byte salt/prefix.
const EXTRACT_PREFIX_LEN: usize = 8;

/// The AES block size, and so the largest legal PKCS#7 pad length.
const AES_BLOCK_LEN: usize = 16;

/// Canonical-serialization marker byte for an element start (spec §4.4).
const ELEMENT_START: u8 = 0x01;

/// Canonical-serialization marker byte for an element end (spec §4.4).
const ELEMENT_END: u8 = 0x02;

/// The longest string the one-byte length prefix of the canonical serialization
/// can frame (spec §4.4).
const MAX_FRAMED_LEN: usize = u8::MAX as usize;

/// A parsed `.knxkeys` keyring (spec §4.6).
///
/// Holds the decrypted, typed key material. See the module docs for the hygiene
/// guarantees; this type is intentionally neither `Serialize` nor `Clone`, and
/// its `Debug` redacts all key material.
pub struct Keyring {
    /// The ETS project name from the root `Project` attribute (empty if absent).
    pub project: String,
    /// The keyring's `Created` timestamp attribute (the AES-CBC IV seed, §4.2).
    pub created: String,
    /// The backbone (routing/multicast) key material, if the keyring carries a
    /// `<Backbone>` element.
    pub backbone: Option<Backbone>,
    /// The tunnel/USB/backbone interfaces and their credentials.
    pub interfaces: Vec<Interface>,
    /// The per-device tool keys and sequence state.
    pub devices: Vec<Device>,
    /// The per-group-address runtime keys, keyed by group address.
    pub group_keys: HashMap<GroupAddress, Key16>,
}

impl Keyring {
    /// Looks up a device's tool key by individual address (spec §2.1 key
    /// selection: the tool key is the per-device management key).
    pub fn tool_key(&self, ia: IndividualAddress) -> Option<&Key16> {
        self.devices
            .iter()
            .find(|d| d.ia == ia)
            .map(|d| &d.tool_key)
    }

    /// Looks up a group runtime key by group address.
    pub fn group_key(&self, ga: GroupAddress) -> Option<&Key16> {
        self.group_keys.get(&ga)
    }
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
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

/// The backbone (routing/multicast) key material (spec §4.5).
pub struct Backbone {
    /// The multicast/routing key (decrypted from the AES-CBC `Key` attribute).
    pub key: Key16,
    /// The routing multicast address.
    pub multicast: Ipv4Addr,
    /// The routing latency tolerance, in milliseconds.
    pub latency_ms: u16,
}

impl std::fmt::Debug for Backbone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backbone")
            .field("key", &"<redacted>")
            .field("multicast", &self.multicast)
            .field("latency_ms", &self.latency_ms)
            .finish()
    }
}

/// A tunnel/USB/backbone interface and its credentials (spec §4.5).
///
/// For a KNXnet/IP Secure tunnelling interface (`Type="Tunneling"`) `ia` is the
/// tunnel address the interface assigns to this user, `host` the individual
/// address of the IP interface itself, `password` the tunnelling user's
/// password and `authentication` the interface's device authentication code
/// (issue #71 Phase B). The passwords are decrypted but not derived: PBKDF2 is
/// slow, so the transport derives only the user it presents
/// ([`Interface::user_key`], [`Interface::device_auth_key`]).
pub struct Interface {
    /// The `Type` attribute (`Tunneling`, `USB`, `Backbone`), empty if absent.
    pub interface_type: String,
    /// The interface's individual address.
    pub ia: IndividualAddress,
    /// The host device's individual address, if the `Host` attribute is present.
    pub host: Option<IndividualAddress>,
    /// The tunnel/management user id.
    pub user_id: u8,
    /// The decrypted user password (`Password`). `None` when the interface
    /// carries no `Password` (a USB interface, for example).
    pub password: Option<Password>,
    /// The decrypted device authentication code (`Authentication`). `None`
    /// when absent.
    pub authentication: Option<Password>,
    /// The group addresses this interface may send to.
    pub gas: Vec<GroupAddress>,
    /// The raw `Senders` attribute of each of those `<Group>` children, when
    /// present, kept so a key store export writes it back (issue #241).
    pub group_senders: HashMap<GroupAddress, String>,
}

impl Interface {
    /// Whether this is a tunnelling interface with a user password, i.e.
    /// usable for a KNXnet/IP Secure tunnel.
    pub fn is_secure_tunnel(&self) -> bool {
        self.interface_type.eq_ignore_ascii_case("Tunneling") && self.password.is_some()
    }

    /// The user-password key (PBKDF2 with the user-password salt), derived on
    /// demand.
    pub fn user_key(&self) -> Option<Key16> {
        self.password
            .as_ref()
            .map(|p| p.derive(salt::USER_PASSWORD))
    }

    /// The device-authentication key (PBKDF2 with the
    /// device-authentication-code salt), derived on demand.
    pub fn device_auth_key(&self) -> Option<Key16> {
        self.authentication
            .as_ref()
            .map(|p| p.derive(salt::DEVICE_AUTHENTICATION_CODE))
    }
}

impl std::fmt::Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("interface_type", &self.interface_type)
            .field("ia", &self.ia)
            .field("host", &self.host)
            .field("user_id", &self.user_id)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "authentication",
                &self.authentication.as_ref().map(|_| "<redacted>"),
            )
            .field("gas", &self.gas)
            .field("group_senders", &self.group_senders)
            .finish()
    }
}

/// A device's tool key and Data Secure sequence state (spec §4.5).
pub struct Device {
    /// The device's individual address.
    pub ia: IndividualAddress,
    /// The device's tool key (decrypted from the AES-CBC `ToolKey` attribute).
    pub tool_key: Key16,
    /// The device's last-known Data Secure sequence number (defaults to 0).
    pub seq: u64,
    /// The decrypted `ManagementPassword` (a KNXnet/IP Secure device's
    /// management user, user id 1), if present.
    pub management_password: Option<Password>,
    /// The decrypted `Authentication` (a KNXnet/IP Secure device's device
    /// authentication code), if present.
    pub authentication: Option<Password>,
}

impl Device {
    /// The device-authentication key (PBKDF2 with the
    /// device-authentication-code salt), derived on demand.
    pub fn device_auth_key(&self) -> Option<Key16> {
        self.authentication
            .as_ref()
            .map(|p| p.derive(salt::DEVICE_AUTHENTICATION_CODE))
    }
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("ia", &self.ia)
            .field("tool_key", &"<redacted>")
            .field("seq", &self.seq)
            .field(
                "management_password",
                &self.management_password.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "authentication",
                &self.authentication.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// An error parsing a `.knxkeys` keyring.
#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    /// The keyring XML could not be parsed.
    #[error("parsing .knxkeys XML: {0}")]
    Xml(String),
    /// A base64 attribute value could not be decoded.
    #[error("decoding base64 in .knxkeys attribute `{attribute}`: {source}")]
    Base64 {
        /// The attribute whose value failed to decode.
        attribute: String,
        /// The underlying decode error.
        source: base64::DecodeError,
    },
    /// A raw key attribute did not decode to exactly 16 bytes.
    #[error("`{attribute}` in .knxkeys is {found} bytes, expected {KEY_LEN}")]
    BadKeyLength {
        /// The attribute that was the wrong length.
        attribute: String,
        /// The number of bytes actually decoded.
        found: usize,
    },
    /// A required attribute was missing from an element.
    #[error("missing required attribute `{attribute}` on <{element}> in .knxkeys")]
    MissingAttribute {
        /// The element that lacked the attribute.
        element: String,
        /// The attribute that was missing.
        attribute: String,
    },
    /// An attribute value could not be parsed into its typed form.
    #[error("invalid value for `{attribute}` in .knxkeys: {reason}")]
    InvalidAttribute {
        /// The attribute with the bad value.
        attribute: String,
        /// A human description of why the value was rejected.
        reason: String,
    },
    /// A decrypted attribute blob was too short to extract a password from.
    #[error("decrypted `{attribute}` blob in .knxkeys is too short to extract a password")]
    ShortBlob {
        /// The attribute whose blob was too short.
        attribute: String,
    },
    /// A decrypted attribute blob did not carry valid PKCS#7 padding, so the
    /// plaintext is garbage — in practice the keyring password was wrong.
    #[error("decrypted `{attribute}` blob in .knxkeys has invalid PKCS#7 padding ({reason})")]
    BadPadding {
        /// The attribute whose blob was mis-padded.
        attribute: String,
        /// What was wrong with the padding.
        reason: String,
    },
    /// The keyring signature did not verify under the key derived from the given
    /// password (spec §4.4).
    ///
    /// The canonical serialization ends with that key, so a well-formed file
    /// reaching this point means the password is wrong (or the file was edited
    /// after export). Malformed files fail earlier with a parse variant.
    #[error(
        "wrong keyring password: the .knxkeys signature does not verify with the key derived from it (or the file was modified after export)"
    )]
    SignatureMismatch,
    /// A string in the signed content is too long for the one-byte length
    /// prefix of the canonical serialization (spec §4.4).
    #[error(
        "`{what}` in .knxkeys is {len} bytes; the signature framing allows at most {MAX_FRAMED_LEN}"
    )]
    FramedTooLong {
        /// What was being framed (element name, attribute name or value).
        what: String,
        /// The byte length of the offending string.
        len: usize,
    },
    /// A crypto primitive rejected its input while decrypting an attribute.
    #[error("decrypting a .knxkeys attribute: {0}")]
    Crypto(#[from] bussard_secure::CryptoError),
}

/// Parses and verifies a `.knxkeys` keyring from its XML text and password
/// (spec §4).
///
/// Steps: derive the keyring key (§4.1), verify the signature (§4.4), then walk
/// the document decrypting encrypted attributes (§4.2, §4.3) and reading raw keys
/// directly into a typed [`Keyring`] (§4.6).
///
/// # Errors
///
/// Returns [`KeyringError::SignatureMismatch`] if the password is wrong (or the
/// document was tampered with), and the various decode/parse variants for
/// malformed input.
pub fn parse_keyring(xml: &str, password: &str) -> Result<Keyring, KeyringError> {
    // The caller's password in its Latin-1 form is key material too; wipe the
    // intermediate buffer once the keyring key is derived (spec §2.3).
    let keyring_key = pbkdf2_key(&Zeroizing::new(latin1_bytes(password)), salt::KEYRING);

    // The `Created` attribute is the IV seed for every encrypted attribute
    // (§4.2), so we need it before decrypting anything. Read it up front.
    let created = read_created(xml)?;
    let iv = created_iv(&created);

    // Verify the signature before trusting the contents (§4.4).
    verify_signature(xml, &keyring_key)?;

    parse_body(xml, &keyring_key, &iv)
}

/// Reads the `Created` attribute off the root `<Keyring>` element (§4.2).
pub(crate) fn read_created(xml: &str) -> Result<String, KeyringError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if e.local_name().as_ref() == b"Keyring" {
                    return attr(&e, b"Created")?.ok_or_else(|| KeyringError::MissingAttribute {
                        element: "Keyring".to_string(),
                        attribute: "Created".to_string(),
                    });
                }
            }
            Ok(Event::Eof) => {
                return Err(KeyringError::Xml("no <Keyring> root element".to_string()));
            }
            Err(e) => return Err(KeyringError::Xml(e.to_string())),
            _ => {}
        }
    }
}

/// Derives the AES-CBC IV from the `Created` timestamp: `sha256(created)[..16]`
/// (spec §4.2).
pub(crate) fn created_iv(created: &str) -> [u8; KEY_LEN] {
    bussard_secure::keyring_iv(created)
}

/// Verifies the keyring signature (spec §4.4).
///
/// The signature is `sha256(canonical)[..16]`, compared in constant time against
/// the base64-decoded `Signature` attribute; see [`canonical_serialization`] for
/// the byte layout. Settled against a genuine ETS 6 export (issue #84).
pub(crate) fn verify_signature(xml: &str, keyring_key: &Key16) -> Result<(), KeyringError> {
    let signature = read_signature(xml)?;
    let serialized = canonical_serialization(xml, keyring_key)?;
    let digest = Sha256::digest(serialized.as_slice());
    if bussard_secure::crypto::constant_time_eq(&digest[..KEY_LEN], &signature) {
        Ok(())
    } else {
        Err(KeyringError::SignatureMismatch)
    }
}

/// Reads and base64-decodes the root `Signature` attribute (§4.4).
fn read_signature(xml: &str) -> Result<Vec<u8>, KeyringError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if e.local_name().as_ref() == b"Keyring" {
                    let sig =
                        attr(&e, b"Signature")?.ok_or_else(|| KeyringError::MissingAttribute {
                            element: "Keyring".to_string(),
                            attribute: "Signature".to_string(),
                        })?;
                    return BASE64
                        .decode(sig.as_bytes())
                        .map_err(|source| KeyringError::Base64 {
                            attribute: "Signature".to_string(),
                            source,
                        });
                }
            }
            Ok(Event::Eof) => {
                return Err(KeyringError::Xml("no <Keyring> root element".to_string()));
            }
            Err(e) => return Err(KeyringError::Xml(e.to_string())),
            _ => {}
        }
    }
}

/// Builds the canonical serialization the signature is computed over (§4.4).
///
/// A document-order walk over the elements. Every "string" below is framed as
/// one length byte followed by its UTF-8 bytes:
///
/// - element start: `0x01`, the element name, then for each attribute except
///   `xmlns`, `xmlns:*` and `Signature`, sorted by name (ordinal): the name,
///   then the (unescaped) value;
/// - element end: `0x02` (a self-closing element is a start plus an end);
/// - after the walk: the base64 of the 16-byte PBKDF2 keyring key.
///
/// Text content and comments are not signed. The buffer ends with key-derived
/// material, so it is wiped on drop.
pub(crate) fn canonical_serialization(
    xml: &str,
    keyring_key: &Key16,
) -> Result<Zeroizing<Vec<u8>>, KeyringError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => serialize_start(&e, &mut out)?,
            Ok(Event::Empty(e)) => {
                serialize_start(&e, &mut out)?;
                out.push(ELEMENT_END);
            }
            Ok(Event::End(_)) => out.push(ELEMENT_END),
            Ok(Event::Eof) => break,
            Err(e) => return Err(KeyringError::Xml(e.to_string())),
            _ => {}
        }
    }

    let key_b64 = Zeroizing::new(BASE64.encode(keyring_key.bytes()));
    push_framed(&mut out, key_b64.as_bytes(), "keyring key")?;
    Ok(out)
}

/// Emits an element start into the canonical buffer: the start marker, the
/// framed element name, then the framed attribute names and values sorted by
/// name, skipping `xmlns`, `xmlns:*` and `Signature` (§4.4).
fn serialize_start(e: &BytesStart, out: &mut Vec<u8>) -> Result<(), KeyringError> {
    out.push(ELEMENT_START);
    push_framed(out, e.name().as_ref(), "element name")?;

    let all = attrs_map(e, KEYRING_CONTEXT).map_err(xml_error)?;
    let mut attrs: Vec<(&[u8], &str)> = all
        .iter()
        .filter(|(key, _)| {
            !(*key == b"xmlns" || *key == b"Signature" || key.starts_with(b"xmlns:"))
        })
        .collect();
    attrs.sort_by(|a, b| a.0.cmp(b.0));

    for (key, value) in &attrs {
        let name = String::from_utf8_lossy(key);
        push_framed(out, key, &name)?;
        push_framed(out, value.as_bytes(), &name)?;
    }
    Ok(())
}

/// Appends one length-prefixed string (one length byte, then the bytes) to the
/// canonical buffer (§4.4).
fn push_framed(out: &mut Vec<u8>, bytes: &[u8], what: &str) -> Result<(), KeyringError> {
    let len = u8::try_from(bytes.len()).map_err(|_| KeyringError::FramedTooLong {
        what: what.to_string(),
        len: bytes.len(),
    })?;
    out.push(len);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Walks the keyring body, decrypting/reading each element into the typed model
/// (spec §4.5, §4.6).
fn parse_body(xml: &str, keyring_key: &Key16, iv: &[u8; KEY_LEN]) -> Result<Keyring, KeyringError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut project = String::new();
    let mut created = String::new();
    let mut backbone: Option<Backbone> = None;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut devices: Vec<Device> = Vec::new();
    let mut group_keys: HashMap<GroupAddress, Key16> = HashMap::new();

    // The interface currently being assembled (its child <Group> elements follow
    // the <Interface> start before the matching end).
    let mut current_interface: Option<Interface> = None;
    // Inside `<GroupAddresses>`, a `<Group>` carries a group key; inside an
    // `<Interface>` it names a GA the interface may send to.
    let mut in_group_addresses = false;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| KeyringError::Xml(e.to_string()))?;
        let is_empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(e) | Event::Empty(e) => {
                match e.local_name().as_ref() {
                    b"Keyring" => {
                        project = attr(&e, b"Project")?.unwrap_or_default();
                        created = attr(&e, b"Created")?.unwrap_or_default();
                    }
                    b"Backbone" => {
                        backbone = Some(parse_backbone(&e, keyring_key, iv)?);
                    }
                    b"Interface" => {
                        // A new <Interface> begins; flush any prior one (defensive,
                        // interfaces do not nest).
                        if let Some(iface) = current_interface.take() {
                            interfaces.push(iface);
                        }
                        let iface = parse_interface(&e, keyring_key, iv)?;
                        if is_empty {
                            interfaces.push(iface);
                        } else {
                            current_interface = Some(iface);
                        }
                    }
                    b"GroupAddresses" => {
                        in_group_addresses = !is_empty;
                    }
                    b"Group" => {
                        if in_group_addresses {
                            let (ga, key) = parse_group_key(&e, keyring_key, iv)?;
                            group_keys.insert(ga, key);
                        } else if let Some(iface) = current_interface.as_mut()
                            && let Some(addr) = attr(&e, b"Address")?
                        {
                            let ga = parse_ga("Interface/Group/Address", &addr)?;
                            iface.gas.push(ga);
                            if let Some(senders) = attr(&e, b"Senders")? {
                                iface.group_senders.insert(ga, senders);
                            }
                        }
                    }
                    b"Device" => {
                        devices.push(parse_device(&e, keyring_key, iv)?);
                    }
                    _ => {}
                }
            }
            Event::End(e) => match e.local_name().as_ref() {
                b"Interface" => {
                    if let Some(iface) = current_interface.take() {
                        interfaces.push(iface);
                    }
                }
                b"GroupAddresses" => in_group_addresses = false,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }

    // Flush a trailing interface if the document ended without an explicit end.
    if let Some(iface) = current_interface.take() {
        interfaces.push(iface);
    }

    Ok(Keyring {
        project,
        created,
        backbone,
        interfaces,
        devices,
        group_keys,
    })
}

/// Parses a `<Backbone>` element (§4.5).
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
    let latency_ms = match attr(e, b"Latency")? {
        Some(s) => s.parse().map_err(|_| KeyringError::InvalidAttribute {
            attribute: "Backbone/Latency".to_string(),
            reason: format!("not a u16: {s:?}"),
        })?,
        None => 0,
    };
    Ok(Backbone {
        key,
        multicast,
        latency_ms,
    })
}

/// Parses an `<Interface>` element's own attributes (§4.5). Child `<Group>`
/// elements are appended later by the walker.
fn parse_interface(
    e: &BytesStart,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<Interface, KeyringError> {
    let ia = parse_ia(
        "Interface/IndividualAddress",
        &require(e, b"IndividualAddress", "Interface")?,
    )?;
    let host = match attr(e, b"Host")? {
        Some(s) => Some(parse_ia("Interface/Host", &s)?),
        None => None,
    };
    let user_id = match attr(e, b"UserID")? {
        Some(s) => s.parse().map_err(|_| KeyringError::InvalidAttribute {
            attribute: "Interface/UserID".to_string(),
            reason: format!("not a u8: {s:?}"),
        })?,
        None => 0,
    };

    // The Password/Authentication attributes are encrypted; decrypt and extract
    // the password strings (§4.5). The keys are derived on demand (PBKDF2 is
    // slow and a keyring lists every tunnelling user). Both are optional: a USB
    // interface has neither.
    let password = optional_password(e, b"Password", "Interface/Password", keyring_key, iv)?;
    let authentication = optional_password(
        e,
        b"Authentication",
        "Interface/Authentication",
        keyring_key,
        iv,
    )?;

    Ok(Interface {
        interface_type: attr(e, b"Type")?.unwrap_or_default(),
        ia,
        host,
        user_id,
        password,
        authentication,
        gas: Vec::new(),
        group_senders: HashMap::new(),
    })
}

/// Parses a `<Device>` element (§4.5).
fn parse_device(
    e: &BytesStart,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<Device, KeyringError> {
    let ia = parse_ia(
        "Device/IndividualAddress",
        &require(e, b"IndividualAddress", "Device")?,
    )?;
    let tool_key = decrypt_key(e, b"ToolKey", "Device/ToolKey", keyring_key, iv)?;
    let seq = match attr(e, b"SequenceNumber")? {
        Some(s) => s.parse().map_err(|_| KeyringError::InvalidAttribute {
            attribute: "Device/SequenceNumber".to_string(),
            reason: format!("not a u64: {s:?}"),
        })?,
        None => 0,
    };
    let management_password = optional_password(
        e,
        b"ManagementPassword",
        "Device/ManagementPassword",
        keyring_key,
        iv,
    )?;
    let authentication = optional_password(
        e,
        b"Authentication",
        "Device/Authentication",
        keyring_key,
        iv,
    )?;
    Ok(Device {
        ia,
        tool_key,
        seq,
        management_password,
        authentication,
    })
}

/// Decrypts an optional encrypted password attribute into a [`Password`].
pub(crate) fn optional_password(
    e: &BytesStart,
    key: &[u8],
    attribute: &str,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<Option<Password>, KeyringError> {
    match attr(e, key)? {
        Some(_) => {
            let plain = decrypt_password(e, key, attribute, keyring_key, iv)?;
            Ok(Some(Password::new(plain.as_str())))
        }
        None => Ok(None),
    }
}

/// Parses a `<GroupAddresses>/<Group>` element into `(address, key)` (§4.5).
fn parse_group_key(
    e: &BytesStart,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<(GroupAddress, Key16), KeyringError> {
    let ga = parse_ga(
        "GroupAddresses/Group/Address",
        &require(e, b"Address", "Group")?,
    )?;
    let key = decrypt_key(e, b"Key", "GroupAddresses/Group/Key", keyring_key, iv)?;
    Ok((ga, key))
}

/// Reads a required attribute, erroring if absent.
pub(crate) fn require(e: &BytesStart, key: &[u8], element: &str) -> Result<String, KeyringError> {
    attr(e, key)?.ok_or_else(|| KeyringError::MissingAttribute {
        element: element.to_string(),
        attribute: String::from_utf8_lossy(key).into_owned(),
    })
}

/// Reads an encrypted key attribute (`ToolKey`, `Backbone/@Key`, group `@Key`)
/// and decrypts it to a 16-byte [`Key16`] (§4.2, §4.3).
///
/// The value is base64 of exactly one AES-128-CBC block (keyring key, IV from
/// `Created`), with no prefix and no padding, so it is not run through
/// [`extract_password`].
pub(crate) fn decrypt_key(
    e: &BytesStart,
    key: &[u8],
    attribute: &str,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<Key16, KeyringError> {
    let b64 = require(e, key, attribute)?;
    let ciphertext = BASE64
        .decode(b64.as_bytes())
        .map_err(|source| KeyringError::Base64 {
            attribute: attribute.to_string(),
            source,
        })?;
    if ciphertext.len() != KEY_LEN {
        return Err(KeyringError::BadKeyLength {
            attribute: attribute.to_string(),
            found: ciphertext.len(),
        });
    }
    let plaintext = Zeroizing::new(aes_cbc_decrypt(keyring_key, iv, &ciphertext)?);
    let mut arr = [0u8; KEY_LEN];
    arr.copy_from_slice(&plaintext[..KEY_LEN]);
    Ok(Key16::new(arr))
}

/// Decrypts an encrypted attribute and extracts the password string (§4.2, §4.3).
pub(crate) fn decrypt_password(
    e: &BytesStart,
    key: &[u8],
    attribute: &str,
    keyring_key: &Key16,
    iv: &[u8; KEY_LEN],
) -> Result<Zeroizing<String>, KeyringError> {
    let b64 = require(e, key, attribute)?;
    let ciphertext = BASE64
        .decode(b64.as_bytes())
        .map_err(|source| KeyringError::Base64 {
            attribute: attribute.to_string(),
            source,
        })?;
    // The plaintext holds the password in the clear; wipe it on the way out
    // (spec §2.3), as the derived `Key16`s already do.
    let plaintext = Zeroizing::new(aes_cbc_decrypt(keyring_key, iv, &ciphertext)?);
    extract_password(&plaintext, attribute)
}

/// Extracts a password from a decrypted blob (spec §4.3).
///
/// Skips the 8-byte salt/prefix, strips the PKCS#7 padding whose count is the
/// final byte, and decodes the remainder as UTF-8.
///
/// The padding is **validated**, not trusted: a valid PKCS#7 tail is 1..=16
/// bytes all equal to the count. A blob decrypted under the wrong key is
/// essentially random, so its last byte is as likely to be `0` (which used to
/// return the whole padded tail as the password) as anything else. Rejecting it
/// here turns "garbage password derived from a garbage key" into a clean error.
fn extract_password(data: &[u8], attribute: &str) -> Result<Zeroizing<String>, KeyringError> {
    if data.len() <= EXTRACT_PREFIX_LEN {
        return Err(KeyringError::ShortBlob {
            attribute: attribute.to_string(),
        });
    }
    let bad_padding = |reason: &str| KeyringError::BadPadding {
        attribute: attribute.to_string(),
        reason: reason.to_string(),
    };
    // `data` is non-empty (longer than the prefix), so `split_last` always
    // yields — no `.expect()` needed to say so.
    let (&last, _) = data
        .split_last()
        .ok_or_else(|| bad_padding("the blob is empty"))?;
    let pad = usize::from(last);
    if pad == 0 || pad > AES_BLOCK_LEN {
        return Err(bad_padding(&format!(
            "pad length {pad} is not 1..={AES_BLOCK_LEN}"
        )));
    }
    let end = data
        .len()
        .checked_sub(pad)
        .filter(|end| *end >= EXTRACT_PREFIX_LEN)
        .ok_or_else(|| KeyringError::ShortBlob {
            attribute: attribute.to_string(),
        })?;
    if data[end..].iter().any(|&b| b != last) {
        return Err(bad_padding("the padding bytes are not all equal"));
    }
    let bytes = Zeroizing::new(data[EXTRACT_PREFIX_LEN..end].to_vec());
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| KeyringError::InvalidAttribute {
            attribute: attribute.to_string(),
            reason: "decrypted password is not valid UTF-8".to_string(),
        })
}

/// Reads a single named attribute off an element as an owned `String`.
pub(crate) fn attr(e: &BytesStart, key: &[u8]) -> Result<Option<String>, KeyringError> {
    attr_value(e, key, KEYRING_CONTEXT).map_err(xml_error)
}

/// The context string handed to the shared attribute helpers; it only shows up
/// inside [`bussard_ets::EtsError`], which [`xml_error`] unwraps again.
const KEYRING_CONTEXT: &str = ".knxkeys";

/// Maps an attribute-helper error onto [`KeyringError::Xml`], carrying only the
/// underlying quick-xml message so the text matches what the keyring reported
/// before the helpers were shared.
fn xml_error(e: bussard_ets::EtsError) -> KeyringError {
    match e {
        bussard_ets::EtsError::XmlAttr { source, .. } => KeyringError::Xml(source.to_string()),
        bussard_ets::EtsError::Xml { source, .. } => KeyringError::Xml(source.to_string()),
        other => KeyringError::Xml(other.to_string()),
    }
}

/// Parses an individual address attribute value.
pub(crate) fn parse_ia(attribute: &str, value: &str) -> Result<IndividualAddress, KeyringError> {
    value.parse().map_err(|_| KeyringError::InvalidAttribute {
        attribute: attribute.to_string(),
        reason: format!("not an individual address: {value:?}"),
    })
}

/// Parses a group address attribute value: ETS writes the raw 16-bit integer
/// (`2563`); the three-level form (`1/2/3`) is accepted too.
pub(crate) fn parse_ga(attribute: &str, value: &str) -> Result<GroupAddress, KeyringError> {
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return value
            .parse::<u16>()
            .map(GroupAddress::from_raw)
            .map_err(|_| KeyringError::InvalidAttribute {
                attribute: attribute.to_string(),
                reason: format!("raw group address out of range: {value:?}"),
            });
    }
    value.parse().map_err(|_| KeyringError::InvalidAttribute {
        attribute: attribute.to_string(),
        reason: format!("not a group address: {value:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // SYNTHETIC fixtures, generated outside this crate by an independent
    // implementation of the documented algorithm (spec §4) with a made-up
    // password. They pin the byte layout: a regression in the canonicalization
    // or the key decryption fails these, which self-signed fixtures cannot do.
    // Never replace them with a real export.
    const PASSWORD: &str = "synthetic-keyring-pw";

    /// An empty keyring (no children), the same shape as an ETS export of a
    /// project without Secure devices.
    const EMPTY: &str = r#"<Keyring Project="Synthetic" CreatedBy="bussard-test" Created="2026-01-02T03:04:05" Signature="w3ZTlYHQfH8/GYKciFYCkA==" xmlns="http://knx.org/xml/keyring/1" />"#;

    /// A keyring with a backbone, a tunnelling interface, one group key and one
    /// device. Keys: backbone `0x11 * 16`, group 1/2/3 (raw 2563) `0x77 * 16`,
    /// tool key `0x42 * 16`; interface password `tunnel-user-pw`, device
    /// authentication `device-auth-pw`.
    const FULL: &str = r#"<Keyring Project="Synthetic" CreatedBy="bussard-test" Created="2026-02-03T04:05:06" Signature="BwFnB3x3sq9qwzQsIIYDHQ==" xmlns="http://knx.org/xml/keyring/1">
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

    fn keyring_key(password: &str) -> Key16 {
        pbkdf2_key(&latin1_bytes(password), salt::KEYRING)
    }

    /// Signs `body` (a keyring whose root has no `Signature`) with [`PASSWORD`]
    /// by splicing the computed signature into the root start tag. Only for
    /// structural tests; the byte layout itself is pinned by the fixtures.
    fn sign(body: &str) -> Result<String, KeyringError> {
        let serialized = canonical_serialization(body, &keyring_key(PASSWORD))?;
        let sig = BASE64.encode(&Sha256::digest(serialized.as_slice())[..KEY_LEN]);
        Ok(body.replacen("<Keyring ", &format!("<Keyring Signature=\"{sig}\" "), 1))
    }

    #[test]
    fn test_canonical_serialization_empty_keyring_layout() -> TestResult {
        let key = keyring_key(PASSWORD);
        let mut expected = vec![ELEMENT_START];
        // Element name, then attributes sorted by name; Signature and xmlns
        // are excluded. Each string is one length byte plus its bytes.
        for s in [
            "Keyring",
            "Created",
            "2026-01-02T03:04:05",
            "CreatedBy",
            "bussard-test",
            "Project",
            "Synthetic",
        ] {
            expected.push(u8::try_from(s.len())?);
            expected.extend_from_slice(s.as_bytes());
        }
        expected.push(ELEMENT_END);
        let key_b64 = BASE64.encode(key.bytes());
        expected.push(u8::try_from(key_b64.len())?);
        expected.extend_from_slice(key_b64.as_bytes());

        let serialized = canonical_serialization(EMPTY, &key)?;
        assert_eq!(serialized.as_slice(), expected.as_slice());
        Ok(())
    }

    #[test]
    fn test_parse_keyring_empty_verifies() -> TestResult {
        let keyring = parse_keyring(EMPTY, PASSWORD)?;
        assert_eq!(keyring.project, "Synthetic");
        assert_eq!(keyring.created, "2026-01-02T03:04:05");
        assert!(keyring.backbone.is_none());
        assert!(keyring.interfaces.is_empty());
        assert!(keyring.devices.is_empty());
        assert!(keyring.group_keys.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_keyring_attribute_order_is_irrelevant() -> TestResult {
        // The canonical form sorts attributes, so a reordered root verifies.
        let reordered = r#"<Keyring xmlns="http://knx.org/xml/keyring/1" Signature="w3ZTlYHQfH8/GYKciFYCkA==" Created="2026-01-02T03:04:05" Project="Synthetic" CreatedBy="bussard-test"></Keyring>"#;
        parse_keyring(reordered, PASSWORD)?;
        Ok(())
    }

    #[test]
    fn test_parse_keyring_full_decrypts_keys() -> TestResult {
        let keyring = parse_keyring(FULL, PASSWORD)?;
        assert_eq!(keyring.created, "2026-02-03T04:05:06");

        let backbone = keyring.backbone.as_ref().ok_or("backbone missing")?;
        assert_eq!(backbone.key.bytes(), &[0x11; 16]);
        assert_eq!(backbone.multicast, Ipv4Addr::new(224, 0, 23, 12));
        assert_eq!(backbone.latency_ms, 1000);

        let ga: GroupAddress = "1/2/3".parse()?;
        assert_eq!(keyring.group_key(ga).map(|k| *k.bytes()), Some([0x77; 16]));
        assert_eq!(keyring.group_keys.len(), 1);

        let ia: IndividualAddress = "1.1.10".parse()?;
        assert_eq!(keyring.tool_key(ia).map(|k| *k.bytes()), Some([0x42; 16]));
        assert_eq!(keyring.devices.len(), 1);
        assert_eq!(keyring.devices[0].seq, 42);
        Ok(())
    }

    #[test]
    fn test_parse_keyring_full_decrypts_interface_passwords() -> TestResult {
        let keyring = parse_keyring(FULL, PASSWORD)?;
        assert_eq!(keyring.interfaces.len(), 1);
        let iface = &keyring.interfaces[0];
        assert_eq!(iface.ia, "1.1.200".parse()?);
        assert_eq!(iface.host, Some("1.1.0".parse()?));
        assert_eq!(iface.user_id, 2);
        assert_eq!(iface.interface_type, "Tunneling");
        assert!(iface.is_secure_tunnel());
        let expected_user = pbkdf2_key(&latin1_bytes("tunnel-user-pw"), salt::USER_PASSWORD);
        let user_key = iface.user_key().ok_or("user key missing")?;
        assert_eq!(user_key.bytes(), expected_user.bytes());
        let expected_auth = pbkdf2_key(
            &latin1_bytes("device-auth-pw"),
            salt::DEVICE_AUTHENTICATION_CODE,
        );
        let device_auth = iface.device_auth_key().ok_or("device auth missing")?;
        assert_eq!(device_auth.bytes(), expected_auth.bytes());
        // The interface's <Group> child is a sending GA, not a group key.
        assert_eq!(iface.gas, vec!["1/2/3".parse::<GroupAddress>()?]);
        Ok(())
    }

    #[test]
    fn test_parse_keyring_full_decrypts_device_ip_secure_passwords() -> TestResult {
        let keyring = parse_keyring(FULL, PASSWORD)?;
        let device = &keyring.devices[0];
        assert!(device.management_password.is_some());
        let auth = device
            .authentication
            .as_ref()
            .ok_or("authentication missing")?;
        assert!(!auth.is_empty());
        assert!(device.device_auth_key().is_some());
        let rendered = format!("{device:?}");
        assert!(!rendered.contains("device-auth-pw"), "{rendered}");
        Ok(())
    }

    #[test]
    fn test_parse_keyring_wrong_password() {
        for xml in [EMPTY, FULL] {
            let err = parse_keyring(xml, "wrong-password").err();
            assert!(
                matches!(err, Some(KeyringError::SignatureMismatch)),
                "expected SignatureMismatch, got {err:?}"
            );
        }
        let message = KeyringError::SignatureMismatch.to_string();
        assert!(message.starts_with("wrong keyring password"), "{message}");
    }

    #[test]
    fn test_parse_keyring_tampered_content() {
        // Change a signed attribute value; the signature no longer verifies.
        let tampered = FULL.replacen("1.1.10\" ToolKey", "1.1.11\" ToolKey", 1);
        assert_ne!(tampered, FULL);
        let err = parse_keyring(&tampered, PASSWORD).err();
        assert!(
            matches!(err, Some(KeyringError::SignatureMismatch)),
            "expected SignatureMismatch, got {err:?}"
        );
    }

    #[test]
    fn test_parse_keyring_malformed_xml_is_a_parse_error() {
        // A broken file must not be reported as a wrong password.
        let broken = FULL.replacen("</Devices>", "</Devicez>", 1);
        let err = parse_keyring(&broken, PASSWORD).err();
        assert!(
            matches!(err, Some(KeyringError::Xml(_))),
            "expected Xml, got {err:?}"
        );
        let err = parse_keyring("<Keyring Created=\"x\" />", PASSWORD).err();
        assert!(
            matches!(err, Some(KeyringError::MissingAttribute { .. })),
            "expected MissingAttribute, got {err:?}"
        );
    }

    #[test]
    fn test_parse_keyring_usb_interface_without_credentials() -> TestResult {
        let xml = sign(
            r#"<Keyring Project="P" Created="2026-03-04T05:06:07"><Interface Type="USB" IndividualAddress="1.1.254" /></Keyring>"#,
        )?;
        let keyring = parse_keyring(&xml, PASSWORD)?;
        assert_eq!(keyring.interfaces.len(), 1);
        assert!(keyring.interfaces[0].password.is_none());
        assert!(keyring.interfaces[0].authentication.is_none());
        assert!(!keyring.interfaces[0].is_secure_tunnel());
        Ok(())
    }

    #[test]
    fn test_push_framed_rejects_long_strings() {
        let mut out = Vec::new();
        let long = vec![b'a'; MAX_FRAMED_LEN + 1];
        assert!(matches!(
            push_framed(&mut out, &long, "value"),
            Err(KeyringError::FramedTooLong { len: 256, .. })
        ));
    }

    #[test]
    fn test_parse_ga_accepts_raw_and_three_level() -> TestResult {
        assert_eq!(parse_ga("a", "2563")?, "1/2/3".parse()?);
        assert_eq!(parse_ga("a", "1/2/3")?, "1/2/3".parse()?);
        assert!(parse_ga("a", "70000").is_err());
        Ok(())
    }

    #[test]
    fn test_extract_password_strips_prefix_and_padding() -> TestResult {
        // 8-byte prefix + "hi" + PKCS#7 pad of 6.
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(b"hi");
        blob.extend(std::iter::repeat_n(6u8, 6));
        assert_eq!(extract_password(&blob, "test")?.as_str(), "hi");
        Ok(())
    }

    /// Regression: the pad length was read with `.expect()` (the only
    /// `.expect()` in library code) and then trusted. A blob decrypted under the
    /// wrong key is random, so `pad = 0` — which returned the entire padded tail
    /// as "the password" — and an inconsistent pad were both accepted, turning a
    /// wrong password into a silently wrong derived key.
    #[test]
    fn test_extract_password_rejects_invalid_pkcs7_padding() -> TestResult {
        let with_pad = |pad: &[u8]| {
            let mut blob = vec![0u8; EXTRACT_PREFIX_LEN];
            blob.extend_from_slice(b"hi");
            blob.extend_from_slice(pad);
            blob
        };

        // pad = 0 is never valid PKCS#7.
        assert!(
            matches!(
                extract_password(&with_pad(&[0u8; 6]), "test"),
                Err(KeyringError::BadPadding { .. })
            ),
            "pad 0 must be refused"
        );
        // pad > 16 is never valid either.
        let mut over = vec![0u8; EXTRACT_PREFIX_LEN];
        over.extend(std::iter::repeat_n(17u8, 17));
        assert!(
            matches!(
                extract_password(&over, "test"),
                Err(KeyringError::BadPadding { .. })
            ),
            "pad 17 must be refused"
        );
        assert!(
            matches!(
                extract_password(&with_pad(&[255u8; 6]), "test"),
                Err(KeyringError::BadPadding { .. })
            ),
            "pad 255 must be refused"
        );
        // A pad length that is in range but whose bytes disagree.
        assert!(
            matches!(
                extract_password(&with_pad(&[4, 4, 9, 4]), "test"),
                Err(KeyringError::BadPadding { .. })
            ),
            "inconsistent padding bytes must be refused"
        );
        // A pad that runs back into the 8-byte prefix is still ShortBlob.
        let mut short = vec![0u8; EXTRACT_PREFIX_LEN];
        short.extend(std::iter::repeat_n(16u8, 10));
        assert!(matches!(
            extract_password(&short, "test"),
            Err(KeyringError::ShortBlob { .. })
        ));
        // The boundary case that IS valid: a full 16-byte pad block.
        let mut full = vec![0u8; EXTRACT_PREFIX_LEN];
        full.extend_from_slice(b"hi");
        full.extend(std::iter::repeat_n(16u8, 16));
        assert_eq!(extract_password(&full, "test")?.as_str(), "hi");
        Ok(())
    }

    #[test]
    fn test_extract_password_rejects_short_blob() {
        assert!(matches!(
            extract_password(&[0u8; 4], "test"),
            Err(KeyringError::ShortBlob { .. })
        ));
    }

    #[test]
    fn test_debug_redacts_keys() -> TestResult {
        let keyring = parse_keyring(FULL, PASSWORD)?;
        let rendered = format!("{keyring:?}");
        assert!(rendered.contains("<redacted>"));
        // No raw key byte value should leak (0x42 = 66, 0x11 = 17, 0x77 = 119).
        for leak in ["66, 66", "17, 17", "119, 119", "0x42", "[66"] {
            assert!(!rendered.contains(leak), "leaked {leak}");
        }
        Ok(())
    }
}
