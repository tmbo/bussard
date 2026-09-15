//! Datapoint types (DPTs).
//!
//! A DPT identifies how the bytes of a group-value telegram are interpreted,
//! e.g. `"1.001"` (boolean on/off) or `"9.001"` (2-byte float, °C).

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// Error parsing a [`Dpt`] from text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DptParseError {
    /// The string was empty or had more than one `.` separator.
    #[error("expected a DPT like \"9\" or \"1.001\", got {0:?}")]
    Shape(String),
    /// The main or sub number was not an integer.
    #[error("DPT {part} ({value:?}) is not a valid integer: {source}")]
    NotAnInteger {
        /// Which part failed (`main` or `sub`).
        part: &'static str,
        /// The offending text.
        value: String,
        /// Underlying integer-parse error.
        source: std::num::ParseIntError,
    },
}

/// The size of a DPT's on-the-wire payload.
///
/// Small DPTs (1/2/4-bit) live in the lower bits of a 6-bit APDU; larger ones
/// occupy whole bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduSize {
    /// A sub-byte payload of the given number of bits (1, 2 or 4).
    Bits(u8),
    /// A payload of the given whole number of bytes.
    Bytes(u8),
}

impl fmt::Display for ApduSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApduSize::Bits(1) => write!(f, "1 bit"),
            ApduSize::Bits(n) => write!(f, "{n} bits"),
            ApduSize::Bytes(1) => write!(f, "1 byte"),
            ApduSize::Bytes(n) => write!(f, "{n} bytes"),
        }
    }
}

/// A datapoint type identifier: a main number and an optional sub number.
///
/// Parses `"1.001"`, `"9"`, `"20.102"`. When displayed, the sub number is
/// zero-padded to three digits (`"1.001"`), matching ETS convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dpt {
    /// The DPT main number (the "DPST" family, e.g. `1`, `9`, `20`).
    pub main: u16,
    /// The DPT sub number, if given (e.g. `1` for `1.001`).
    pub sub: Option<u16>,
}

impl Dpt {
    /// Constructs a DPT from a main number and optional sub number.
    pub fn new(main: u16, sub: Option<u16>) -> Self {
        Self { main, sub }
    }

    /// The expected APDU payload size for known main types.
    ///
    /// Returns `None` for main types whose size bussard does not model.
    pub fn expected_size(&self) -> Option<ApduSize> {
        Some(match self.main {
            1 => ApduSize::Bits(1),
            2 => ApduSize::Bits(2),
            3 => ApduSize::Bits(4),
            4 => ApduSize::Bytes(1),
            5 => ApduSize::Bytes(1),
            6 => ApduSize::Bytes(1),
            7 => ApduSize::Bytes(2),
            8 => ApduSize::Bytes(2),
            9 => ApduSize::Bytes(2),
            10 => ApduSize::Bytes(3),
            11 => ApduSize::Bytes(3),
            12 => ApduSize::Bytes(4),
            13 => ApduSize::Bytes(4),
            14 => ApduSize::Bytes(4),
            16 => ApduSize::Bytes(14),
            17 => ApduSize::Bytes(1),
            18 => ApduSize::Bytes(1),
            20 => ApduSize::Bytes(1),
            232 => ApduSize::Bytes(3),
            _ => return None,
        })
    }
}

impl fmt::Display for Dpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.sub {
            Some(sub) => write!(f, "{}.{:03}", self.main, sub),
            None => write!(f, "{}", self.main),
        }
    }
}

impl FromStr for Dpt {
    type Err = DptParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(DptParseError::Shape(s.to_string()));
        }
        let mut parts = s.split('.');
        let main_raw = parts
            .next()
            .ok_or_else(|| DptParseError::Shape(s.to_string()))?;
        let sub_raw = parts.next();
        if parts.next().is_some() {
            return Err(DptParseError::Shape(s.to_string()));
        }
        let main = main_raw
            .parse()
            .map_err(|source| DptParseError::NotAnInteger {
                part: "main",
                value: main_raw.to_string(),
                source,
            })?;
        let sub = match sub_raw {
            None => None,
            Some(sr) => Some(sr.parse().map_err(|source| DptParseError::NotAnInteger {
                part: "sub",
                value: sr.to_string(),
                source,
            })?),
        };
        Ok(Self { main, sub })
    }
}

impl Serialize for Dpt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Dpt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_with_sub() {
        let d: Dpt = "1.001".parse().unwrap();
        assert_eq!(d.main, 1);
        assert_eq!(d.sub, Some(1));
        assert_eq!(d.to_string(), "1.001");
    }

    #[test]
    fn parse_without_sub() {
        let d: Dpt = "9".parse().unwrap();
        assert_eq!(d.main, 9);
        assert_eq!(d.sub, None);
        assert_eq!(d.to_string(), "9");
    }

    #[test]
    fn parse_large_sub() {
        let d: Dpt = "20.102".parse().unwrap();
        assert_eq!(d.to_string(), "20.102");
    }

    #[test]
    fn zero_pads_sub() {
        let d: Dpt = "5.1".parse().unwrap();
        assert_eq!(d.to_string(), "5.001");
    }

    #[test]
    fn bad_shapes() {
        assert!("".parse::<Dpt>().is_err());
        assert!("1.2.3".parse::<Dpt>().is_err());
        assert!("x".parse::<Dpt>().is_err());
    }

    #[test]
    fn sizes() {
        assert_eq!(
            "1.001".parse::<Dpt>().unwrap().expected_size(),
            Some(ApduSize::Bits(1))
        );
        assert_eq!(
            "3.007".parse::<Dpt>().unwrap().expected_size(),
            Some(ApduSize::Bits(4))
        );
        assert_eq!(
            "9.001".parse::<Dpt>().unwrap().expected_size(),
            Some(ApduSize::Bytes(2))
        );
        assert_eq!(
            "16.000".parse::<Dpt>().unwrap().expected_size(),
            Some(ApduSize::Bytes(14))
        );
        assert_eq!("99".parse::<Dpt>().unwrap().expected_size(), None);
    }
}
