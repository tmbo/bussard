//! `.knxkeys` keyring parsing (issue #71, spec §4).
//!
//! A `.knxkeys` file is the ETS-exported bundle of KNX Secure key material: the
//! backbone (routing) key, per-interface tunnel/management credentials, per-device
//! tool keys, and per-group-address runtime keys. Sensitive attributes are
//! AES-128-CBC encrypted under a key derived from a keyring password (PBKDF2), and
//! the whole document is signed with a truncated SHA-256 over a canonical
//! serialization.
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

// quick-xml 0.41 deprecates `unescape_value` in favor of `normalized_value`;
// the rest of this crate deliberately uses the plain-unescape semantics (see
// `project.rs`), so we match that here.
#![allow(deprecated)]

use std::collections::HashMap;
use std::net::Ipv4Addr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use bussard_secure::crypto::latin1_bytes;
use bussard_secure::{Key16, aes_cbc_decrypt, pbkdf2_key, salt};

use bussard_model::{GroupAddress, IndividualAddress};

/// The number of bytes of raw key material in a KNX Secure key.
const KEY_LEN: usize = 16;

/// The number of leading bytes to skip when extracting a password from a
/// decrypted blob (spec §4.3): an 8-byte salt/prefix.
const EXTRACT_PREFIX_LEN: usize = 8;

/// The AES block size, and so the largest legal PKCS#7 pad length.
const AES_BLOCK_LEN: usize = 16;

/// A parsed `.knxkeys` keyring (spec §4.6).
///
/// Holds the decrypted, typed key material. See the module docs for the hygiene
/// guarantees; this type is intentionally neither `Serialize` nor `Clone`, and
/// its `Debug` redacts all key material.
pub struct Keyring {
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
    /// The multicast/routing key (raw 16 bytes, base64 in the XML).
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
pub struct Interface {
    /// The interface's individual address.
    pub ia: IndividualAddress,
    /// The host device's individual address, if the `Host` attribute is present.
    pub host: Option<IndividualAddress>,
    /// The tunnel/management user id.
    pub user_id: u8,
    /// The derived user-password key (from the decrypted `Password`, PBKDF2 with
    /// the user-password salt).
    pub user_key: Key16,
    /// The derived device-authentication key (from the decrypted `Authentication`,
    /// PBKDF2 with the device-authentication-code salt).
    pub device_auth: Key16,
    /// The group addresses this interface may send to.
    pub gas: Vec<GroupAddress>,
}

impl std::fmt::Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("ia", &self.ia)
            .field("host", &self.host)
            .field("user_id", &self.user_id)
            .field("user_key", &"<redacted>")
            .field("device_auth", &"<redacted>")
            .field("gas", &self.gas)
            .finish()
    }
}

/// A device's tool key and Data Secure sequence state (spec §4.5).
pub struct Device {
    /// The device's individual address.
    pub ia: IndividualAddress,
    /// The device's tool key (raw 16 bytes, base64 in the XML).
    pub tool_key: Key16,
    /// The device's last-known Data Secure sequence number (defaults to 0).
    pub seq: u64,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("ia", &self.ia)
            .field("tool_key", &"<redacted>")
            .field("seq", &self.seq)
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
    /// The keyring signature did not match: the password is wrong or the keyring
    /// was tampered with.
    ///
    /// Note (spec §4.4, `SEC-CAL:`): the exact canonicalization is not yet
    /// confirmed against a real ETS keyring, so a genuine keyring may report this
    /// even with the correct password until the canonicalization is calibrated.
    #[error(
        "the .knxkeys signature did not verify (wrong keyring password, or a canonicalization mismatch that needs calibration; see SEC-CAL in keyring.rs)"
    )]
    SignatureMismatch,
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
fn read_created(xml: &str) -> Result<String, KeyringError> {
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
fn created_iv(created: &str) -> [u8; KEY_LEN] {
    let digest = Sha256::digest(created.as_bytes());
    let mut iv = [0u8; KEY_LEN];
    iv.copy_from_slice(&digest[..KEY_LEN]);
    iv
}

/// Verifies the keyring signature (spec §4.4).
///
/// The canonical serialization is a SAX walk emitting element markers (`0x01`
/// start, `0x02` end) and attribute names + values (excluding `xmlns` and
/// `Signature`), followed by the base64 of the hashed keyring password. The
/// signature is `sha256(serialized)[..16]`, compared against the base64-decoded
/// `Signature` attribute.
///
// SEC-CAL: exact .knxkeys signature canonicalization byte order (verify against
// a real/synthetic keyring). This matches the XKNX reference as reasoned from the
// public source, and round-trips against our synthetic fixtures by construction,
// but the byte-exact ordering has not been confirmed against a genuine ETS export
// - a real keyring may need calibration here.
fn verify_signature(xml: &str, keyring_key: &Key16) -> Result<(), KeyringError> {
    let signature = read_signature(xml)?;
    let serialized = canonical_serialization(xml, keyring_key)?;
    let digest = Sha256::digest(&serialized);
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
fn canonical_serialization(xml: &str, keyring_key: &Key16) -> Result<Vec<u8>, KeyringError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut out: Vec<u8> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                out.push(0x01);
                serialize_attributes(&e, &mut out)?;
            }
            Ok(Event::Empty(e)) => {
                // An empty element is a start immediately followed by an end.
                out.push(0x01);
                serialize_attributes(&e, &mut out)?;
                out.push(0x02);
            }
            Ok(Event::End(_)) => {
                out.push(0x02);
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(KeyringError::Xml(e.to_string())),
            _ => {}
        }
    }

    // Append the base64 of the hashed keyring password (the derived keyring key).
    let key_b64 = BASE64.encode(keyring_key.bytes());
    out.extend_from_slice(key_b64.as_bytes());
    Ok(out)
}

/// Emits an element's attribute names and values into the canonical buffer,
/// skipping `xmlns` and `Signature` (§4.4).
fn serialize_attributes(e: &BytesStart, out: &mut Vec<u8>) -> Result<(), KeyringError> {
    for a in e.attributes() {
        let a = a.map_err(|source| KeyringError::Xml(source.to_string()))?;
        let key = a.key.as_ref();
        if key == b"xmlns" || key == b"Signature" || key.starts_with(b"xmlns:") {
            continue;
        }
        out.extend_from_slice(key);
        let value = a
            .unescape_value()
            .map_err(|source| KeyringError::Xml(source.to_string()))?;
        out.extend_from_slice(value.as_bytes());
    }
    Ok(())
}

/// Walks the keyring body, decrypting/reading each element into the typed model
/// (spec §4.5, §4.6).
fn parse_body(xml: &str, keyring_key: &Key16, iv: &[u8; KEY_LEN]) -> Result<Keyring, KeyringError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut created = String::new();
    let mut backbone: Option<Backbone> = None;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut devices: Vec<Device> = Vec::new();
    let mut group_keys: HashMap<GroupAddress, Key16> = HashMap::new();

    // The interface currently being assembled (its child <Group> elements follow
    // the <Interface> start before the matching end).
    let mut current_interface: Option<Interface> = None;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| KeyringError::Xml(e.to_string()))?;
        match event {
            Event::Start(e) | Event::Empty(e) => {
                match e.local_name().as_ref() {
                    b"Keyring" => {
                        created = attr(&e, b"Created")?.unwrap_or_default();
                    }
                    b"Backbone" => {
                        backbone = Some(parse_backbone(&e)?);
                    }
                    b"Interface" => {
                        // A new <Interface> begins; flush any prior one (defensive,
                        // interfaces do not nest).
                        if let Some(iface) = current_interface.take() {
                            interfaces.push(iface);
                        }
                        current_interface = Some(parse_interface(&e, keyring_key, iv)?);
                    }
                    b"Group" => {
                        // A <Group> child of the current <Interface>: a sending GA.
                        if let Some(iface) = current_interface.as_mut() {
                            if let Some(addr) = attr(&e, b"Address")? {
                                iface.gas.push(parse_ga("Group/Address", &addr)?);
                            }
                        }
                    }
                    b"Device" => {
                        devices.push(parse_device(&e)?);
                    }
                    b"GroupAddress" => {
                        let (ga, key) = parse_group_address(&e)?;
                        group_keys.insert(ga, key);
                    }
                    _ => {}
                }
            }
            Event::End(e) => {
                if e.local_name().as_ref() == b"Interface" {
                    if let Some(iface) = current_interface.take() {
                        interfaces.push(iface);
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    // Flush a trailing interface if the document ended without an explicit end
    // (empty <Interface/> elements are handled here).
    if let Some(iface) = current_interface.take() {
        interfaces.push(iface);
    }

    Ok(Keyring {
        created,
        backbone,
        interfaces,
        devices,
        group_keys,
    })
}

/// Parses a `<Backbone>` element (§4.5).
fn parse_backbone(e: &BytesStart) -> Result<Backbone, KeyringError> {
    let key = raw_key(e, b"Key", "Backbone/Key")?;
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

    // The Password/Authentication attributes are encrypted; decrypt, extract the
    // password string, then derive the key with the appropriate salt (§4.5, §3.4).
    let password = decrypt_password(e, b"Password", "Interface/Password", keyring_key, iv)?;
    let user_key = pbkdf2_key(
        &Zeroizing::new(latin1_bytes(&password)),
        salt::USER_PASSWORD,
    );

    let auth = decrypt_password(
        e,
        b"Authentication",
        "Interface/Authentication",
        keyring_key,
        iv,
    )?;
    let device_auth = pbkdf2_key(
        &Zeroizing::new(latin1_bytes(&auth)),
        salt::DEVICE_AUTHENTICATION_CODE,
    );

    Ok(Interface {
        ia,
        host,
        user_id,
        user_key,
        device_auth,
        gas: Vec::new(),
    })
}

/// Parses a `<Device>` element (§4.5).
fn parse_device(e: &BytesStart) -> Result<Device, KeyringError> {
    let ia = parse_ia(
        "Device/IndividualAddress",
        &require(e, b"IndividualAddress", "Device")?,
    )?;
    let tool_key = raw_key(e, b"ToolKey", "Device/ToolKey")?;
    let seq = match attr(e, b"SequenceNumber")? {
        Some(s) => s.parse().map_err(|_| KeyringError::InvalidAttribute {
            attribute: "Device/SequenceNumber".to_string(),
            reason: format!("not a u64: {s:?}"),
        })?,
        None => 0,
    };
    Ok(Device { ia, tool_key, seq })
}

/// Parses a top-level `<GroupAddress>` element into `(address, key)` (§4.5).
fn parse_group_address(e: &BytesStart) -> Result<(GroupAddress, Key16), KeyringError> {
    let ga = parse_ga(
        "GroupAddress/Address",
        &require(e, b"Address", "GroupAddress")?,
    )?;
    let key = raw_key(e, b"Key", "GroupAddress/Key")?;
    Ok((ga, key))
}

/// Reads a required attribute, erroring if absent.
fn require(e: &BytesStart, key: &[u8], element: &str) -> Result<String, KeyringError> {
    attr(e, key)?.ok_or_else(|| KeyringError::MissingAttribute {
        element: element.to_string(),
        attribute: String::from_utf8_lossy(key).into_owned(),
    })
}

/// Reads a base64 attribute and decodes it to a raw 16-byte [`Key16`] (§4.3:
/// raw keys are base64 → 16 bytes directly, not run through `extract_password`).
fn raw_key(e: &BytesStart, key: &[u8], attribute: &str) -> Result<Key16, KeyringError> {
    let b64 = require(e, key, attribute)?;
    let bytes = BASE64
        .decode(b64.as_bytes())
        .map_err(|source| KeyringError::Base64 {
            attribute: attribute.to_string(),
            source,
        })?;
    if bytes.len() != KEY_LEN {
        return Err(KeyringError::BadKeyLength {
            attribute: attribute.to_string(),
            found: bytes.len(),
        });
    }
    let mut arr = [0u8; KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(Key16::new(arr))
}

/// Decrypts an encrypted attribute and extracts the password string (§4.2, §4.3).
fn decrypt_password(
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
fn attr(e: &BytesStart, key: &[u8]) -> Result<Option<String>, KeyringError> {
    for a in e.attributes() {
        let a = a.map_err(|source| KeyringError::Xml(source.to_string()))?;
        if a.key.as_ref() == key {
            let v = a
                .unescape_value()
                .map_err(|source| KeyringError::Xml(source.to_string()))?;
            return Ok(Some(v.into_owned()));
        }
    }
    Ok(None)
}

/// Parses an individual address attribute value.
fn parse_ia(attribute: &str, value: &str) -> Result<IndividualAddress, KeyringError> {
    value.parse().map_err(|_| KeyringError::InvalidAttribute {
        attribute: attribute.to_string(),
        reason: format!("not an individual address: {value:?}"),
    })
}

/// Parses a group address attribute value.
fn parse_ga(attribute: &str, value: &str) -> Result<GroupAddress, KeyringError> {
    value.parse().map_err(|_| KeyringError::InvalidAttribute {
        attribute: attribute.to_string(),
        reason: format!("not a group address: {value:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_secure::aes_cbc_encrypt;

    const PASSWORD: &str = "test";
    const CREATED: &str = "2024-01-02T03:04:05";

    /// Base64-encodes a raw 16-byte key for embedding in a synthetic keyring.
    fn b64_key(bytes: [u8; 16]) -> String {
        BASE64.encode(bytes)
    }

    /// Encrypts a password into the keyring's encrypted-attribute base64 form:
    /// an 8-byte prefix + the UTF-8 password + PKCS#7 padding, AES-CBC-encrypted
    /// under the keyring key and the created-derived IV (spec §4.2, §4.3).
    fn encrypt_password(plaintext: &str, keyring_key: &Key16, iv: &[u8; 16]) -> String {
        let mut blob = Vec::new();
        // 8-byte salt/prefix (arbitrary in a synthetic fixture).
        blob.extend_from_slice(&[0xA5; EXTRACT_PREFIX_LEN]);
        blob.extend_from_slice(plaintext.as_bytes());
        // PKCS#7 pad to a 16-byte multiple.
        let pad = 16 - (blob.len() % 16);
        let pad = if pad == 0 { 16 } else { pad };
        blob.extend(std::iter::repeat_n(pad as u8, pad));
        let ct = aes_cbc_encrypt(keyring_key, iv, &blob).expect("synthetic encrypt");
        BASE64.encode(ct)
    }

    /// Builds a synthetic `.knxkeys` document with known fake keys, computing the
    /// signature via the same canonicalization the parser verifies (so it
    /// round-trips by construction — spec §12.3).
    fn synthetic_keyring(
        tool_key: [u8; 16],
        group_key: [u8; 16],
        user_password: &str,
        auth_password: &str,
    ) -> String {
        let keyring_key = pbkdf2_key(&latin1_bytes(PASSWORD), salt::KEYRING);
        let iv = created_iv(CREATED);

        let enc_pw = encrypt_password(user_password, &keyring_key, &iv);
        let enc_auth = encrypt_password(auth_password, &keyring_key, &iv);
        let backbone_key = b64_key([0x11; 16]);

        // Build the document body without the Signature attribute first, then
        // compute the signature over its canonical serialization, then splice
        // the Signature into the root element.
        let body = format!(
            r#"<Keyring Project="Synthetic" Created="{CREATED}">
  <Backbone Key="{backbone_key}" MulticastAddress="224.0.23.12" Latency="1000" />
  <Interface Type="Tunneling" IndividualAddress="1.1.200" Host="1.1.0" UserID="2" Password="{enc_pw}" Authentication="{enc_auth}">
    <Group Address="1/2/3" Senders="1.1.200" />
  </Interface>
  <Device IndividualAddress="1.1.10" ToolKey="{tool}" SequenceNumber="42" />
  <GroupAddress Address="1/2/3" Key="{gkey}" />
</Keyring>"#,
            tool = b64_key(tool_key),
            gkey = b64_key(group_key),
        );

        // Compute the signature over the canonical serialization of the body as
        // written (the root element carries no Signature attribute yet, so it is
        // naturally excluded).
        let serialized = canonical_serialization(&body, &keyring_key).expect("canonicalize");
        let sig = Sha256::digest(&serialized);
        let sig_b64 = BASE64.encode(&sig[..16]);

        // Splice the Signature attribute into the root element.
        body.replacen(
            r#"<Keyring Project="Synthetic""#,
            &format!(r#"<Keyring Signature="{sig_b64}" Project="Synthetic""#),
            1,
        )
    }

    #[test]
    fn test_parse_keyring_decrypts_tool_key() {
        let tool_key = [0x42; 16];
        let xml = synthetic_keyring(tool_key, [0x77; 16], "userpw", "authpw");
        let keyring = parse_keyring(&xml, PASSWORD).expect("parse");
        let ia: IndividualAddress = "1.1.10".parse().unwrap();
        assert_eq!(keyring.tool_key(ia).map(|k| *k.bytes()), Some(tool_key));
        assert_eq!(keyring.devices[0].seq, 42);
    }

    #[test]
    fn test_parse_keyring_extracts_user_password() {
        let xml = synthetic_keyring([0x42; 16], [0x77; 16], "userpw", "authpw");
        let keyring = parse_keyring(&xml, PASSWORD).expect("parse");
        // The parser should derive user_key = pbkdf2(user_password, USER_PASSWORD).
        let expected = pbkdf2_key(&latin1_bytes("userpw"), salt::USER_PASSWORD);
        assert_eq!(keyring.interfaces.len(), 1);
        assert_eq!(keyring.interfaces[0].user_key.bytes(), expected.bytes());
        // And device_auth = pbkdf2(auth_password, DEVICE_AUTHENTICATION_CODE).
        let expected_auth = pbkdf2_key(&latin1_bytes("authpw"), salt::DEVICE_AUTHENTICATION_CODE);
        assert_eq!(
            keyring.interfaces[0].device_auth.bytes(),
            expected_auth.bytes()
        );
        assert_eq!(keyring.interfaces[0].user_id, 2);
        assert_eq!(keyring.interfaces[0].host, Some("1.1.0".parse().unwrap()));
        // The child <Group> sending GA was captured.
        assert_eq!(keyring.interfaces[0].gas, vec!["1/2/3".parse().unwrap()]);
    }

    #[test]
    fn test_parse_keyring_reads_group_and_backbone_keys() {
        let group_key = [0x77; 16];
        let xml = synthetic_keyring([0x42; 16], group_key, "userpw", "authpw");
        let keyring = parse_keyring(&xml, PASSWORD).expect("parse");
        let ga: GroupAddress = "1/2/3".parse().unwrap();
        assert_eq!(keyring.group_key(ga).map(|k| *k.bytes()), Some(group_key));
        let backbone = keyring.backbone.expect("backbone present");
        assert_eq!(backbone.key.bytes(), &[0x11; 16]);
        assert_eq!(backbone.multicast, Ipv4Addr::new(224, 0, 23, 12));
        assert_eq!(backbone.latency_ms, 1000);
    }

    #[test]
    fn test_parse_keyring_signature_verifies() {
        // A well-formed synthetic keyring verifies with the correct password.
        let xml = synthetic_keyring([0x42; 16], [0x77; 16], "userpw", "authpw");
        assert!(parse_keyring(&xml, PASSWORD).is_ok());
    }

    #[test]
    fn test_parse_keyring_wrong_password() {
        let xml = synthetic_keyring([0x42; 16], [0x77; 16], "userpw", "authpw");
        let err = parse_keyring(&xml, "wrong-password").unwrap_err();
        assert!(
            matches!(err, KeyringError::SignatureMismatch),
            "expected SignatureMismatch, got {err:?}"
        );
    }

    #[test]
    fn test_parse_keyring_tampered_signature() {
        let xml = synthetic_keyring([0x42; 16], [0x77; 16], "userpw", "authpw");
        // Flip a character inside the Device element (a signed attribute value),
        // which invalidates the signature.
        let tampered = xml.replacen("1.1.10", "1.1.11", 1);
        let err = parse_keyring(&tampered, PASSWORD).unwrap_err();
        assert!(
            matches!(err, KeyringError::SignatureMismatch),
            "expected SignatureMismatch, got {err:?}"
        );
    }

    #[test]
    fn test_extract_password_strips_prefix_and_padding() {
        // 8-byte prefix + "hi" + PKCS#7 pad of 6.
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(b"hi");
        blob.extend(std::iter::repeat_n(6u8, 6));
        assert_eq!(
            extract_password(&blob, "test")
                .expect("valid padding")
                .as_str(),
            "hi"
        );
    }

    /// Regression: the pad length was read with `.expect()` (the only
    /// `.expect()` in library code) and then trusted. A blob decrypted under the
    /// wrong key is random, so `pad = 0` — which returned the entire padded tail
    /// as "the password" — and an inconsistent pad were both accepted, turning a
    /// wrong password into a silently wrong derived key.
    #[test]
    fn test_extract_password_rejects_invalid_pkcs7_padding() {
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
        assert_eq!(
            extract_password(&full, "test")
                .expect("a full pad block is valid")
                .as_str(),
            "hi"
        );
    }

    #[test]
    fn test_extract_password_rejects_short_blob() {
        assert!(matches!(
            extract_password(&[0u8; 4], "test"),
            Err(KeyringError::ShortBlob { .. })
        ));
    }

    #[test]
    fn test_debug_redacts_keys() {
        let xml = synthetic_keyring([0xAB; 16], [0xCD; 16], "userpw", "authpw");
        let keyring = parse_keyring(&xml, PASSWORD).expect("parse");
        let rendered = format!("{keyring:?}");
        assert!(rendered.contains("<redacted>") || rendered.contains("redacted"));
        // No raw key byte value should leak.
        assert!(!rendered.contains("ab, ab"));
        assert!(!rendered.contains("171"));
    }
}
