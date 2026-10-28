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

/// A com-object's transmission priority: the 2-bit field of a group-object
/// descriptor (System B descriptor bits 9-8, System 7 CONFIG bits 1-0).
///
/// The codes are the standard's (Resources 3/5/1 §4.18.3.1.2.1 and Table 87):
/// `00` system, `01` normal, `10` urgent, `11` low. The product schema names
/// them by the ETS terms (`ComObjectPriority_t`): `Low`, `High` (the
/// standard's normal), `Alert` (urgent) and `System`. A product that declares
/// none gets [`Priority::Low`], the [`Default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Priority {
    /// System priority (`00`), reserved for management.
    System,
    /// ETS `High`, the standard's normal priority (`01`).
    High,
    /// ETS `Alert`, the standard's urgent priority (`10`).
    #[serde(rename = "Alert")]
    Alarm,
    /// Low priority (`11`), the group-communication default.
    #[default]
    Low,
}

impl Priority {
    /// The raw 2-bit priority code (`0`..=`3`). A System B descriptor word
    /// carries it in bits 9-8, a System 7 CONFIG octet in bits 1-0.
    pub fn code(self) -> u16 {
        match self {
            Priority::System => 0b00,
            Priority::High => 0b01,
            Priority::Alarm => 0b10,
            Priority::Low => 0b11,
        }
    }

    /// Parses the product schema's `Priority` attribute value (`Low`, `High`,
    /// `Alert`, `System`); `None` for anything else.
    pub fn from_ets(value: &str) -> Option<Priority> {
        match value.trim() {
            "Low" => Some(Priority::Low),
            "High" => Some(Priority::High),
            "Alert" => Some(Priority::Alarm),
            "System" => Some(Priority::System),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_order() -> Result<(), Box<dyn std::error::Error>> {
        let f: Flags = "CWTU".parse()?;
        assert!(f.contains(Flags::COMMUNICATION));
        assert!(f.contains(Flags::WRITE));
        assert!(f.contains(Flags::TRANSMIT));
        assert!(f.contains(Flags::UPDATE));
        assert!(!f.contains(Flags::READ));
        // Display is always in canonical CRWTUI order.
        assert_eq!(f.to_string(), "CWTU");
        Ok(())
    }

    #[test]
    fn reorders_on_display() -> Result<(), Box<dyn std::error::Error>> {
        let f: Flags = "UTWC".parse()?;
        assert_eq!(f.to_string(), "CWTU");
        Ok(())
    }

    #[test]
    fn all_flags() -> Result<(), Box<dyn std::error::Error>> {
        let f: Flags = "CRWTUI".parse()?;
        assert_eq!(f, Flags::all());
        assert_eq!(f.to_string(), "CRWTUI");
        Ok(())
    }

    #[test]
    fn empty() -> Result<(), Box<dyn std::error::Error>> {
        let f: Flags = "".parse()?;
        assert!(f.is_empty());
        assert_eq!(f.to_string(), "");
        Ok(())
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

    #[test]
    fn test_priority_from_ets_maps_the_schema_names_to_standard_codes() {
        assert_eq!(Priority::from_ets("Low").map(Priority::code), Some(0b11));
        assert_eq!(Priority::from_ets("High").map(Priority::code), Some(0b01));
        assert_eq!(Priority::from_ets("Alert").map(Priority::code), Some(0b10));
        assert_eq!(Priority::from_ets("System").map(Priority::code), Some(0b00));
        assert_eq!(Priority::from_ets("Urgent"), None);
        assert_eq!(Priority::default(), Priority::Low);
    }
}
