//! The KNX Secure device certificate text: the 36-character label that carries
//! a device's serial number and factory default setup key (FDSK), issue #728.
//!
//! The contract is `dev/enroll-protocol.md` ("Certificate text"); the test
//! vectors are `dev/enroll/vectors-v2.json`. In short: 36 characters of RFC
//! 4648 base32 (`A-Z`, `2-7`), printed as six groups of six separated by
//! dashes, decoded as a 180-bit big-endian number whose upper 176 bits are the
//! serial number (6 octets) and the FDSK (16 octets) and whose lower 4 bits are
//! a check, plain CRC-4 over the 22 octets (see [`crc4`]), confirmed on real
//! labels (#201).
//!
//! [`Certificate::decode`] reports a check mismatch in
//! [`Certificate::check_ok`] rather than as an error, so a caller can still
//! show the serial number; a label with a mismatch is not a valid certificate.
//!
//! # Key hygiene
//!
//! The FDSK is held as a [`Key16`]; [`Certificate`]'s `Debug` prints the
//! serial and the check only, and no error message quotes the label text (a
//! character of it is a part of the key).

use crate::key::Key16;

/// The number of characters of a normalized certificate.
pub const CERTIFICATE_LEN: usize = 36;

/// The RFC 4648 base32 alphabet.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The serial number and FDSK octets, before the check.
const DATA_LEN: usize = 22;

/// Why a text is not a certificate. The messages never quote the text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertificateError {
    /// The text does not have 36 characters once normalized.
    #[error(
        "a certificate is {CERTIFICATE_LEN} base32 characters (A-Z, 2-7, dashes and spaces \
         aside), this one has {found}"
    )]
    Length {
        /// The number of characters after normalization.
        found: usize,
    },
    /// A character outside the base32 alphabet.
    #[error(
        "character {position} of the certificate is not base32 (A-Z, 2-7); \
         0, 1 and 8 are read as O, I and B"
    )]
    Character {
        /// The 1-based position in the normalized text.
        position: usize,
    },
}

/// Normalizes a certificate as the page and bussard both do: drops whitespace
/// and `-`, uppercases, maps `0` to `O`, `1` to `I` and `8` to `B` (base32 has
/// none of them). The result is not checked; [`Certificate::decode`] does.
pub fn normalize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            '0' => 'O',
            '1' => 'I',
            '8' => 'B',
            other => other,
        })
        .collect()
}

/// The certificate check: plain CRC-4 over `data`, polynomial x^4 + x + 1
/// (`0x3`), init 0, MSB first (not reflected), no final XOR, computed
/// directly (not augmented). Not CRC-4/ITU, which is the reflected variant.
pub fn crc4(data: &[u8]) -> u8 {
    const POLY: u8 = 0x3;
    let mut crc: u8 = 0;
    for &byte in data {
        for bit in (0..8).rev() {
            let top = ((crc >> 3) & 1) ^ ((byte >> bit) & 1);
            crc = (crc << 1) & 0xF;
            if top == 1 {
                crc ^= POLY;
            }
        }
    }
    crc
}

/// A decoded device certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The serial number (manufacturer id, then the device number).
    pub serial: [u8; 6],
    /// The factory default setup key.
    pub fdsk: Key16,
    /// The 4-bit check the label carries.
    pub check: u8,
    /// Whether [`check`](Self::check) is the [`crc4`] of the serial and FDSK.
    /// A label without it is not a valid certificate.
    pub check_ok: bool,
}

impl std::fmt::Debug for Certificate {
    /// The serial and the check; the FDSK is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("serial", &serial_hex(&self.serial))
            .field("fdsk", &self.fdsk)
            .field("check", &self.check)
            .field("check_ok", &self.check_ok)
            .finish()
    }
}

/// Twelve upper-case hex digits of a serial number.
pub fn serial_hex(serial: &[u8; 6]) -> String {
    serial.iter().map(|b| format!("{b:02X}")).collect()
}

impl Certificate {
    /// Normalizes and decodes `text` (see the module docs). A check mismatch
    /// is reported in [`check_ok`](Self::check_ok), not as an error, so the
    /// caller can name the serial number when it refuses the label.
    ///
    /// # Errors
    ///
    /// The normalized text is not 36 characters, or has a character outside
    /// the base32 alphabet.
    pub fn decode(text: &str) -> Result<Self, CertificateError> {
        let normalized = zeroize::Zeroizing::new(normalize(text));
        let found = normalized.chars().count();
        if found != CERTIFICATE_LEN {
            return Err(CertificateError::Length { found });
        }
        // 180 bits into 23 octets: the 22 data octets, then the check in the
        // upper nibble of the last.
        let mut bits = zeroize::Zeroizing::new([0u8; DATA_LEN + 1]);
        for (i, ch) in normalized.bytes().enumerate() {
            let value = ALPHABET
                .iter()
                .position(|&a| a == ch)
                .ok_or(CertificateError::Character { position: i + 1 })?;
            for bit in 0..5 {
                if (value >> (4 - bit)) & 1 == 1 {
                    let n = i * 5 + bit;
                    bits[n / 8] |= 0x80 >> (n % 8);
                }
            }
        }
        let mut serial = [0u8; 6];
        serial.copy_from_slice(&bits[..6]);
        let mut fdsk = [0u8; 16];
        fdsk.copy_from_slice(&bits[6..DATA_LEN]);
        let check = bits[DATA_LEN] >> 4;
        let check_ok = crc4(&bits[..DATA_LEN]) == check;
        let certificate = Certificate {
            serial,
            fdsk: Key16::new(fdsk),
            check,
            check_ok,
        };
        zeroize::Zeroize::zeroize(&mut fdsk);
        Ok(certificate)
    }

    /// The label text for `serial` and `fdsk`, six dash-separated groups of
    /// six, with the [`crc4`] check. For tests and synthetic devices.
    pub fn encode(serial: &[u8; 6], fdsk: &Key16) -> String {
        let mut data = zeroize::Zeroizing::new([0u8; DATA_LEN + 1]);
        data[..6].copy_from_slice(serial);
        data[6..DATA_LEN].copy_from_slice(fdsk.bytes());
        data[DATA_LEN] = crc4(&data[..DATA_LEN]) << 4;
        let mut out = String::with_capacity(CERTIFICATE_LEN + 5);
        for i in 0..CERTIFICATE_LEN {
            let mut value = 0usize;
            for bit in 0..5 {
                let n = i * 5 + bit;
                value = (value << 1) | usize::from((data[n / 8] >> (7 - n % 8)) & 1);
            }
            if i > 0 && i % 6 == 0 {
                out.push('-');
            }
            out.push(char::from(ALPHABET[value]));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const VECTORS: &str = include_str!("../../../dev/enroll/vectors-v2.json");

    fn hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        (0..s.len())
            .step_by(2)
            .map(|i| Ok(u8::from_str_radix(s.get(i..i + 2).ok_or("odd hex")?, 16)?))
            .collect()
    }

    fn certificates() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let v: serde_json::Value = serde_json::from_str(VECTORS)?;
        Ok(v["certificates"].clone())
    }

    fn str_of(v: &serde_json::Value) -> Result<&str, Box<dyn std::error::Error>> {
        Ok(v.as_str().ok_or("not a string")?)
    }

    #[test]
    fn test_decode_valid_vectors() -> TestResult {
        let c = certificates()?;
        let valid = c["valid"].as_array().ok_or("no valid vectors")?;
        assert!(!valid.is_empty());
        for v in valid {
            let text = str_of(&v["text"])?;
            let cert = Certificate::decode(text)?;
            assert_eq!(cert.serial.to_vec(), hex(str_of(&v["serial"])?)?);
            assert_eq!(cert.fdsk.bytes().to_vec(), hex(str_of(&v["fdsk"])?)?);
            assert_eq!(u64::from(cert.check), v["check"].as_u64().ok_or("check")?);
            assert!(cert.check_ok);
        }
        Ok(())
    }

    #[test]
    fn test_encode_valid_vectors() -> TestResult {
        let c = certificates()?;
        for v in c["valid"].as_array().ok_or("no valid vectors")? {
            let serial: [u8; 6] = hex(str_of(&v["serial"])?)?
                .try_into()
                .map_err(|_| "serial length")?;
            let fdsk: [u8; 16] = hex(str_of(&v["fdsk"])?)?
                .try_into()
                .map_err(|_| "fdsk length")?;
            assert_eq!(
                Certificate::encode(&serial, &Key16::new(fdsk)),
                str_of(&v["text"])?
            );
        }
        Ok(())
    }

    #[test]
    fn test_normalize_vectors() -> TestResult {
        let c = certificates()?;
        for v in c["normalize"].as_array().ok_or("no normalize vectors")? {
            assert_eq!(normalize(str_of(&v["input"])?), str_of(&v["normalized"])?);
        }
        Ok(())
    }

    #[test]
    fn test_normalize_maps_lookalikes() {
        assert_eq!(normalize(" ab-0 1\t8z\n"), "ABOIBZ");
    }

    #[test]
    fn test_decode_bad_check_vectors_report_mismatch() -> TestResult {
        let c = certificates()?;
        for v in c["bad_check"].as_array().ok_or("no bad_check vectors")? {
            let cert = Certificate::decode(str_of(v)?)?;
            assert!(!cert.check_ok);
        }
        Ok(())
    }

    #[test]
    fn test_decode_malformed_vectors_refused() -> TestResult {
        let c = certificates()?;
        for v in c["malformed"].as_array().ok_or("no malformed vectors")? {
            let text = str_of(v)?;
            let err = Certificate::decode(text)
                .err()
                .ok_or("a malformed vector decoded")?;
            // The message never quotes the label.
            assert!(!err.to_string().contains(text));
        }
        Ok(())
    }

    #[test]
    fn test_decode_lookalike_digits_read_as_letters() -> TestResult {
        // The first vector with O, I and B typed as 0, 1 and 8 where it has them.
        let typed = "ad5aca-qdasqk-d1vdus-s2nj5i-vgvkxl-fnv2xr";
        let cert = Certificate::decode(typed)?;
        assert_eq!(serial_hex(&cert.serial), "00FA01020304");
        assert!(cert.check_ok);
        Ok(())
    }

    #[test]
    fn test_certificate_debug_redacts_fdsk() -> TestResult {
        let cert = Certificate::decode("AD5ACA-QDASQK-DIVDUS-S2NJ5I-VGVKXL-FNV2XR")?;
        let shown = format!("{cert:?}");
        assert!(shown.contains("00FA01020304"));
        assert!(!shown.to_ascii_uppercase().contains("A0A1A2"));
        assert!(shown.contains("redacted"));
        Ok(())
    }

    #[test]
    fn test_crc4_known_values() {
        assert_eq!(crc4(&[]), 0);
        // The plain (non-reflected) CRC-4 of "123456789"; CRC-4/ITU gives 0x7.
        assert_eq!(crc4(b"123456789"), 0xE);
        // The direct algorithm gives M(x) * x^4 mod (x^4 + x + 1); for M = 1
        // that is x + 1.
        assert_eq!(crc4(&[0x01]), 0x3);
    }
}
