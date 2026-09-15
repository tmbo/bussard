//! Com-object flags.
//!
//! KNX com objects carry six flags: Communication, Read, Write, Transmit,
//! Update and Init. bussard represents them as a compact string in a fixed
//! `CRWTUI` order, e.g. `"CWTU"`.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    /// The set of com-object flags.
    ///
    /// Rendered and parsed in the fixed order `C R W T U I` (case-sensitive).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct Flags: u8 {
        /// Communication — the object participates in group communication at all.
        const COMMUNICATION = 0b0000_0001;
        /// Read — the object answers `GroupValueRead` requests.
        const READ          = 0b0000_0010;
        /// Write — the object accepts `GroupValueWrite` from the bus.
        const WRITE         = 0b0000_0100;
        /// Transmit — the object may send `GroupValueWrite` to the bus.
        const TRANSMIT      = 0b0000_1000;
        /// Update — the object updates its value from `GroupValueResponse`.
        const UPDATE        = 0b0001_0000;
        /// Init — the object reads its value from the bus at startup.
        const INIT          = 0b0010_0000;
    }
}

/// The canonical display/parse order: C, R, W, T, U, I.
const ORDER: [(char, Flags); 6] = [
    ('C', Flags::COMMUNICATION),
    ('R', Flags::READ),
    ('W', Flags::WRITE),
    ('T', Flags::TRANSMIT),
    ('U', Flags::UPDATE),
    ('I', Flags::INIT),
];

/// Error parsing a [`Flags`] string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlagsParseError {
    /// An unexpected character appeared (only `CRWTUI` are valid).
    #[error("unexpected character {found:?} in flags string {input:?} (valid: C R W T U I)")]
    UnexpectedChar {
        /// The offending character.
        found: char,
        /// The full input.
        input: String,
    },
    /// The same flag character appeared more than once.
    #[error("duplicate flag {found:?} in flags string {input:?}")]
    Duplicate {
        /// The repeated character.
        found: char,
        /// The full input.
        input: String,
    },
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (ch, flag) in ORDER {
            if self.contains(flag) {
                write!(f, "{ch}")?;
            }
        }
        Ok(())
    }
}

impl FromStr for Flags {
    type Err = FlagsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut flags = Flags::empty();
        for ch in s.chars() {
            let flag = ORDER
                .iter()
                .find(|(c, _)| *c == ch)
                .map(|(_, flag)| *flag)
                .ok_or_else(|| FlagsParseError::UnexpectedChar {
                    found: ch,
                    input: s.to_string(),
                })?;
            if flags.contains(flag) {
                return Err(FlagsParseError::Duplicate {
                    found: ch,
                    input: s.to_string(),
                });
            }
            flags.insert(flag);
        }
        Ok(flags)
    }
}

impl Serialize for Flags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Flags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_order() {
        let f: Flags = "CWTU".parse().unwrap();
        assert!(f.contains(Flags::COMMUNICATION));
        assert!(f.contains(Flags::WRITE));
        assert!(f.contains(Flags::TRANSMIT));
        assert!(f.contains(Flags::UPDATE));
        assert!(!f.contains(Flags::READ));
        // Display is always in canonical CRWTUI order.
        assert_eq!(f.to_string(), "CWTU");
    }

    #[test]
    fn reorders_on_display() {
        let f: Flags = "UTWC".parse().unwrap();
        assert_eq!(f.to_string(), "CWTU");
    }

    #[test]
    fn all_flags() {
        let f: Flags = "CRWTUI".parse().unwrap();
        assert_eq!(f, Flags::all());
        assert_eq!(f.to_string(), "CRWTUI");
    }

    #[test]
    fn empty() {
        let f: Flags = "".parse().unwrap();
        assert!(f.is_empty());
        assert_eq!(f.to_string(), "");
    }

    #[test]
    fn rejects_unknown_char() {
        assert!("CWZ".parse::<Flags>().is_err());
        // Case-sensitive: lowercase is invalid.
        assert!("cw".parse::<Flags>().is_err());
    }

    #[test]
    fn rejects_duplicate() {
        assert!("CC".parse::<Flags>().is_err());
    }
}
