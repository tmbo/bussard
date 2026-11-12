//! A reader for the ETS keyring export (`.knxkeys`), for the `activated`
//! start state of a KNX Data Secure device (`security.keyring` in the config,
//! bussard issue #1054).
//!
//! The simulator holds synthetic keys only. A keyring it reads is the export of
//! a fabricated device (the synthetic product catalogue commits them under a
//! public password), never a user's installation. Only what a device's own
//! security state needs is read: the tool key and sending sequence of each
//! device, and the group keys.
//!
//! The format (`dev/knx-secure-spec.md` §4 in the bussard repository, from the
//! public XKNX reference): the keyring key is PBKDF2-HMAC-SHA256 of the
//! password (Latin-1) with the salt `1.keyring.ets.knx.org`, 65 536 rounds, 16
//! octets. A key attribute is base64 of one AES-128-CBC block under that key,
//! the IV the first 16 octets of SHA-256 over the root's `Created` attribute.
//! The signature is not checked: a wrong password shows as keys that do not
//! verify on the wire, and the simulator is not the place that vouches for a
//! keyring.

use std::collections::BTreeMap;

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit};
use base64::Engine;
use quick_xml::Reader;
use quick_xml::events::Event;
use sha2::{Digest, Sha256};

use super::Key16;

/// The PBKDF2 salt of the keyring password.
const SALT_KEYRING: &[u8] = b"1.keyring.ets.knx.org";

/// Errors reading a keyring.
#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    /// The XML did not parse.
    #[error("keyring XML: {0}")]
    Xml(#[from] quick_xml::Error),
    /// The root `Keyring` element or its `Created` attribute is missing.
    #[error("not an ETS keyring: no Keyring element with a Created attribute")]
    NotAKeyring,
    /// An encrypted key attribute is not base64 of one 16-octet block.
    #[error("keyring attribute {0} is not base64 of one 16-octet block")]
    BadKey(String),
    /// An address attribute does not parse.
    #[error("keyring address {0:?} does not parse")]
    BadAddress(String),
    /// A `SequenceNumber` attribute is not a number.
    #[error("keyring sequence number {0:?} is not a number")]
    BadSequence(String),
}

/// One `Device` of the keyring.
#[derive(Debug, Clone, Default)]
pub struct KeyringDevice {
    /// The individual address, raw.
    pub address: Option<u16>,
    /// The serial number, 6 octets.
    pub serial: Option<[u8; 6]>,
    /// The tool key ETS set.
    pub tool_key: Option<Key16>,
    /// The device's sending sequence number ETS recorded.
    pub sequence: Option<u64>,
}

/// The parts of a keyring a device's Data Secure state is built from.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    /// The devices, in document order.
    pub devices: Vec<KeyringDevice>,
    /// The group keys by raw group address.
    pub group_keys: BTreeMap<u16, Key16>,
}

impl Keyring {
    /// Reads and decrypts the keyring `xml` under `password`.
    pub fn parse(xml: &str, password: &str) -> Result<Self, KeyringError> {
        let xml = xml.trim_start_matches('\u{feff}');
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        let mut cipher: Option<(Aes128, [u8; 16])> = None;
        let mut in_group_addresses = false;
        let mut out = Keyring::default();
        loop {
            let event = reader.read_event_into(&mut buf)?;
            match &event {
                Event::Eof => break,
                Event::End(e) if e.name().as_ref() == b"GroupAddresses" => {
                    in_group_addresses = false;
                }
                Event::Start(e) | Event::Empty(e) => match e.name().as_ref() {
                    b"Keyring" => {
                        let created = attr(e, "Created").ok_or(KeyringError::NotAKeyring)?;
                        let key = crate::secure::ipsecure::pbkdf2_16(password, SALT_KEYRING);
                        let digest = Sha256::digest(created.as_bytes());
                        let mut iv = [0u8; 16];
                        iv.copy_from_slice(&digest[..16]);
                        cipher = Some((Aes128::new(&key.into()), iv));
                    }
                    b"GroupAddresses" => {
                        in_group_addresses = matches!(event, Event::Start(_));
                    }
                    b"Group" if in_group_addresses => {
                        let (Some(address), Some(key)) = (attr(e, "Address"), attr(e, "Key"))
                        else {
                            continue;
                        };
                        let cipher = cipher.as_ref().ok_or(KeyringError::NotAKeyring)?;
                        out.group_keys
                            .insert(group_address(&address)?, decrypt_key(cipher, &key)?);
                    }
                    b"Device" => {
                        let cipher = cipher.as_ref().ok_or(KeyringError::NotAKeyring)?;
                        let device = KeyringDevice {
                            address: attr(e, "IndividualAddress")
                                .map(|a| individual_address(&a))
                                .transpose()?,
                            serial: attr(e, "SerialNumber").and_then(|s| serial(&s)),
                            tool_key: attr(e, "ToolKey")
                                .map(|k| decrypt_key(cipher, &k))
                                .transpose()?,
                            sequence: attr(e, "SequenceNumber")
                                .map(|s| {
                                    s.trim()
                                        .parse::<u64>()
                                        .map_err(|_| KeyringError::BadSequence(s.clone()))
                                })
                                .transpose()?,
                        };
                        out.devices.push(device);
                    }
                    _ => {}
                },
                _ => {}
            }
            buf.clear();
        }
        if cipher.is_none() {
            return Err(KeyringError::NotAKeyring);
        }
        Ok(out)
    }

    /// The device at individual address `address`, else the one with serial
    /// number `serial`.
    pub fn device(&self, address: u16, serial: Option<[u8; 6]>) -> Option<&KeyringDevice> {
        self.devices
            .iter()
            .find(|d| d.address == Some(address))
            .or_else(|| serial.and_then(|s| self.devices.iter().find(|d| d.serial == Some(s))))
    }
}

/// The value of attribute `key` of `e`.
fn attr(e: &quick_xml::events::BytesStart<'_>, key: &str) -> Option<String> {
    e.attributes().flatten().find_map(|a| {
        (a.key.as_ref() == key.as_bytes()).then(|| String::from_utf8_lossy(&a.value).into_owned())
    })
}

/// Decrypts one key attribute: base64 of one AES-128-CBC block.
fn decrypt_key(cipher: &(Aes128, [u8; 16]), value: &str) -> Result<Key16, KeyringError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| KeyringError::BadKey(value.to_string()))?;
    let block: [u8; 16] = raw
        .try_into()
        .map_err(|_| KeyringError::BadKey(value.to_string()))?;
    let mut block = block.into();
    cipher.0.decrypt_block(&mut block);
    let mut key = [0u8; 16];
    for (k, (b, iv)) in key.iter_mut().zip(block.iter().zip(cipher.1.iter())) {
        *k = b ^ iv;
    }
    Ok(Key16::new(key))
}

/// A group address as the keyring writes it: the raw number (`2563`) or the
/// three-level form (`1/2/3`).
fn group_address(s: &str) -> Result<u16, KeyringError> {
    let bad = || KeyringError::BadAddress(s.to_string());
    if let Ok(raw) = s.trim().parse::<u16>() {
        return Ok(raw);
    }
    s.parse::<crate::wire::GroupAddress>()
        .map(|ga| ga.0)
        .map_err(|_| bad())
}

/// An individual address `a.l.d`.
fn individual_address(s: &str) -> Result<u16, KeyringError> {
    s.parse::<crate::wire::IndividualAddress>()
        .map(|ia| ia.0)
        .map_err(|_| KeyringError::BadAddress(s.to_string()))
}

/// A serial number as 12 hex characters.
fn serial(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();
    if s.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The committed synthetic keyring of the secure examples (made-up
    /// password, tool key 0x42 * 16 for 1.1.10, a group key for 1/2/3).
    fn synthetic() -> Result<String, std::io::Error> {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples/secure/synthetic.knxkeys"),
        )
    }

    #[test]
    fn test_keyring_parse_decrypts_the_tool_key_and_group_key() -> TestResult {
        let ring = Keyring::parse(&synthetic()?, "synthetic-keyring-pw")?;
        let device = ring.device(0x110A, None).ok_or("1.1.10 is missing")?;
        assert_eq!(device.tool_key, Key16::from_hex(&"42".repeat(16)));
        assert_eq!(device.sequence, Some(42));
        assert_eq!(ring.group_keys.len(), 1);
        assert!(ring.group_keys.contains_key(&0x0A03));
        Ok(())
    }

    #[test]
    fn test_keyring_parse_wrong_password_gives_other_keys() -> TestResult {
        let ring = Keyring::parse(&synthetic()?, "not-the-password")?;
        let device = ring.device(0x110A, None).ok_or("1.1.10 is missing")?;
        assert_ne!(device.tool_key, Key16::from_hex(&"42".repeat(16)));
        Ok(())
    }

    #[test]
    fn test_keyring_device_falls_back_to_the_serial_number() -> TestResult {
        let xml = "<Keyring Created=\"2026-01-01T00:00:00\"><Devices>\
                   <Device IndividualAddress=\"1.1.1\" SerialNumber=\"00FAD4730C98\" />\
                   </Devices></Keyring>";
        let ring = Keyring::parse(xml, "pw")?;
        let serial = [0x00, 0xFA, 0xD4, 0x73, 0x0C, 0x98];
        assert!(ring.device(0x1105, Some(serial)).is_some());
        assert!(ring.device(0x1105, None).is_none());
        Ok(())
    }

    #[test]
    fn test_keyring_parse_refuses_a_file_without_created() {
        assert!(matches!(
            Keyring::parse("<Keyring></Keyring>", "pw"),
            Err(KeyringError::NotAKeyring)
        ));
    }
}
