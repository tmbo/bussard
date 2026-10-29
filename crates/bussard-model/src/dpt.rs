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
    /// A sub-byte payload of the given number of bits (1, 2, 3 or 4).
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

    /// Whether this DPT's value may be packed into the 6-bit "small" APDU form.
    ///
    /// The small form is legal ONLY for sub-byte DPTs — main 1 (1-bit), 2 and 23
    /// (2-bit), 31 (3-bit) and 3 (4-bit) — whose whole value fits in the APCI's
    /// low 6 bits (03_07_02 §1.3.1). A
    /// byte-sized-or-larger DPT (5.x, 6.x, 17.x, 18.x, 20.x, …) MUST be sent as a
    /// separate data octet even when its value happens to be `<= 0x3F`; packing it
    /// emits a malformed telegram the device misreads (issue #59). A DPT whose
    /// size bussard does not model is treated as NOT packable (send it whole).
    pub fn is_packable(&self) -> bool {
        matches!(self.expected_size(), Some(ApduSize::Bits(_)))
    }

    /// The expected APDU payload size for known main types.
    ///
    /// Covers every main type of the 03_07_02 §2 overview with a fixed width:
    /// the sub-octet B1, B2, B1U3, N2 and N3 types travel in the APCI's low
    /// bits (§1.3.1), every other type in whole octets as its section's format
    /// declares. Where a section's octet count disagrees with its own field
    /// layout (240.800, 249.600), the field layout wins.
    ///
    /// Returns `None` for the variable-length types (24.x, 28.x, 267.x and the
    /// 277..=284 energy registers) and for main types the standard does not
    /// define.
    pub fn expected_size(&self) -> Option<ApduSize> {
        let bytes = match self.main {
            1 => return Some(ApduSize::Bits(1)),
            2 | 23 => return Some(ApduSize::Bits(2)),
            31 => return Some(ApduSize::Bits(3)),
            3 => return Some(ApduSize::Bits(4)),
            4 | 5 | 6 | 17 | 18 | 20 | 21 | 25 | 26 | 236 | 238 => 1,
            7 | 8 | 9 | 22 | 200 | 201 | 202 | 204 | 207 | 211 | 217 | 234 | 237 | 239 | 244
            | 246 => 2,
            10 | 11 | 30 | 203 | 205 | 206 | 209 | 223 | 225 | 232 | 240 | 250 | 254 => 3,
            12 | 13 | 14 | 15 | 27 | 210 | 214 | 220 | 231 | 241 | 253 | 276 => 4,
            215 | 216 | 218 | 248 | 252 => 5,
            212 | 219 | 221 | 222 | 224 | 229 | 235 | 242 | 245 | 249 | 251 | 274 => 6,
            271 | 272 => 7,
            19 | 29 | 213 | 230 | 243 | 255 | 273 => 8,
            265 | 268 => 9,
            247 | 257 | 266 => 12,
            16 | 269 => 14,
            256 => 16,
            270 => 20,
            _ => return None,
        };
        Some(ApduSize::Bytes(bytes))
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
    fn parse_with_sub() -> Result<(), Box<dyn std::error::Error>> {
        let d: Dpt = "1.001".parse()?;
        assert_eq!(d.main, 1);
        assert_eq!(d.sub, Some(1));
        assert_eq!(d.to_string(), "1.001");
        Ok(())
    }

    #[test]
    fn parse_without_sub() -> Result<(), Box<dyn std::error::Error>> {
        let d: Dpt = "9".parse()?;
        assert_eq!(d.main, 9);
        assert_eq!(d.sub, None);
        assert_eq!(d.to_string(), "9");
        Ok(())
    }

    #[test]
    fn parse_large_sub() -> Result<(), Box<dyn std::error::Error>> {
        let d: Dpt = "20.102".parse()?;
        assert_eq!(d.to_string(), "20.102");
        Ok(())
    }

    #[test]
    fn zero_pads_sub() -> Result<(), Box<dyn std::error::Error>> {
        let d: Dpt = "5.1".parse()?;
        assert_eq!(d.to_string(), "5.001");
        Ok(())
    }

    #[test]
    fn bad_shapes() {
        assert!("".parse::<Dpt>().is_err());
        assert!("1.2.3".parse::<Dpt>().is_err());
        assert!("x".parse::<Dpt>().is_err());
    }

    #[test]
    fn sizes() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            "1.001".parse::<Dpt>()?.expected_size(),
            Some(ApduSize::Bits(1))
        );
        assert_eq!(
            "3.007".parse::<Dpt>()?.expected_size(),
            Some(ApduSize::Bits(4))
        );
        assert_eq!(
            "9.001".parse::<Dpt>()?.expected_size(),
            Some(ApduSize::Bytes(2))
        );
        assert_eq!(
            "16.000".parse::<Dpt>()?.expected_size(),
            Some(ApduSize::Bytes(14))
        );
        assert_eq!("99".parse::<Dpt>()?.expected_size(), None);
        Ok(())
    }

    #[test]
    fn test_expected_size_structured_and_sub_octet_families()
    -> Result<(), Box<dyn std::error::Error>> {
        for (dpt, size) in [
            ("23.001", ApduSize::Bits(2)),
            ("23.102", ApduSize::Bits(2)),
            ("31.101", ApduSize::Bits(3)),
            ("15.000", ApduSize::Bytes(4)),
            ("21.001", ApduSize::Bytes(1)),
            ("22.101", ApduSize::Bytes(2)),
            ("26.001", ApduSize::Bytes(1)),
            ("27.001", ApduSize::Bytes(4)),
            ("29.010", ApduSize::Bytes(8)),
            ("235.001", ApduSize::Bytes(6)),
            ("236.001", ApduSize::Bytes(1)),
            ("237.600", ApduSize::Bytes(2)),
            ("238.001", ApduSize::Bytes(1)),
            ("241.800", ApduSize::Bytes(4)),
            ("242.600", ApduSize::Bytes(6)),
            ("244.600", ApduSize::Bytes(2)),
            ("245.600", ApduSize::Bytes(6)),
            ("249.600", ApduSize::Bytes(6)),
            ("250.600", ApduSize::Bytes(3)),
            ("252.600", ApduSize::Bytes(5)),
            ("254.600", ApduSize::Bytes(3)),
        ] {
            assert_eq!(dpt.parse::<Dpt>()?.expected_size(), Some(size), "{dpt}");
        }
        // Variable-length strings have no fixed width.
        assert_eq!("24.001".parse::<Dpt>()?.expected_size(), None);
        assert_eq!("28.001".parse::<Dpt>()?.expected_size(), None);
        // 03_07_02 §1.3.1: sub-octet types are packed, octet types never.
        assert!("23.001".parse::<Dpt>()?.is_packable());
        assert!("31.101".parse::<Dpt>()?.is_packable());
        assert!(!"21.001".parse::<Dpt>()?.is_packable());
        Ok(())
    }

    #[test]
    fn packability_follows_dpt_width_not_value() -> Result<(), Box<dyn std::error::Error>> {
        // Only sub-byte DPTs (main 1/2/3) may pack into the 6-bit APDU (issue #59).
        for dpt in ["1.001", "2.001", "3.007"] {
            assert!(
                dpt.parse::<Dpt>()?.is_packable(),
                "{dpt} is sub-byte and packable"
            );
        }
        // Byte-sized-or-larger DPTs are never packable, even with small values.
        for dpt in ["5.001", "6.010", "9.001", "17.001", "18.001", "20.102"] {
            assert!(
                !dpt.parse::<Dpt>()?.is_packable(),
                "{dpt} is byte-sized and must NOT pack"
            );
        }
        // An unmodeled DPT is treated as not packable (send whole).
        assert!(!"99".parse::<Dpt>()?.is_packable());
        Ok(())
    }
}
