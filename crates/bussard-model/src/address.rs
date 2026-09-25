//! KNX addresses: group addresses and individual (physical) addresses.
//!
//! Both are 16-bit values with a conventional three-part textual form.
//! They (de)serialize as their string representation.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// Error parsing a KNX address from its textual form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressParseError {
    /// The string did not have the expected number of `/` or `.` separated parts.
    #[error("expected {expected}, got {found:?}")]
    Shape {
        /// Human description of the expected shape.
        expected: &'static str,
        /// The offending input.
        found: String,
    },
    /// One of the numeric components did not parse as an integer.
    #[error("component {index} ({value:?}) is not a valid integer: {source}")]
    NotAnInteger {
        /// Zero-based index of the component.
        index: usize,
        /// The offending component text.
        value: String,
        /// Underlying integer-parse error.
        source: std::num::ParseIntError,
    },
    /// One of the numeric components was outside its permitted range.
    #[error("{part} must be {min}..={max}, got {value}")]
    OutOfRange {
        /// Name of the component (e.g. `main`).
        part: &'static str,
        /// The out-of-range value.
        value: u32,
        /// Inclusive minimum.
        min: u32,
        /// Inclusive maximum.
        max: u32,
    },
}

fn parse_component(
    parts: &[&str],
    index: usize,
    part: &'static str,
    max: u32,
) -> Result<u16, AddressParseError> {
    let raw = parts[index];
    let value: u32 = raw
        .trim()
        .parse()
        .map_err(|source| AddressParseError::NotAnInteger {
            index,
            value: raw.to_string(),
            source,
        })?;
    if value > max {
        return Err(AddressParseError::OutOfRange {
            part,
            value,
            min: 0,
            max,
        });
    }
    Ok(value as u16)
}

/// A KNX group address (3-level form, e.g. `"3/0/4"`).
///
/// The three levels are main (0–31, 5 bits), middle (0–7, 3 bits) and
/// sub (0–255, 8 bits), packed into a single [`u16`].
///
/// `0/0/0` is reserved: it parses successfully but is flagged by validation
/// (rule `E012`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupAddress(u16);

impl GroupAddress {
    /// Maximum permitted value for the main group.
    pub const MAIN_MAX: u32 = 31;
    /// Maximum permitted value for the middle group.
    pub const MIDDLE_MAX: u32 = 7;
    /// Maximum permitted value for the sub group.
    pub const SUB_MAX: u32 = 255;

    /// Constructs a group address from its three levels, validating ranges.
    pub fn new(main: u8, middle: u8, sub: u8) -> Result<Self, AddressParseError> {
        if u32::from(main) > Self::MAIN_MAX {
            return Err(AddressParseError::OutOfRange {
                part: "main",
                value: u32::from(main),
                min: 0,
                max: Self::MAIN_MAX,
            });
        }
        if u32::from(middle) > Self::MIDDLE_MAX {
            return Err(AddressParseError::OutOfRange {
                part: "middle",
                value: u32::from(middle),
                min: 0,
                max: Self::MIDDLE_MAX,
            });
        }
        Ok(Self(
            (u16::from(main) << 11) | (u16::from(middle) << 8) | u16::from(sub),
        ))
    }

    /// Constructs a group address from its raw 16-bit representation.
    pub fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    /// The raw 16-bit representation.
    pub fn raw(self) -> u16 {
        self.0
    }

    /// The main group (0–31).
    pub fn main(self) -> u8 {
        (self.0 >> 11) as u8
    }

    /// The middle group (0–7).
    pub fn middle(self) -> u8 {
        ((self.0 >> 8) & 0x07) as u8
    }

    /// The sub group (0–255).
    pub fn sub(self) -> u8 {
        (self.0 & 0xff) as u8
    }

    /// Whether this is the reserved `0/0/0` address.
    pub fn is_reserved(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for GroupAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.main(), self.middle(), self.sub())
    }
}

impl FromStr for GroupAddress {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 3 {
            return Err(AddressParseError::Shape {
                expected: "a 3-level group address like \"3/0/4\" (main/middle/sub)",
                found: s.to_string(),
            });
        }
        let main = parse_component(&parts, 0, "main", Self::MAIN_MAX)?;
        let middle = parse_component(&parts, 1, "middle", Self::MIDDLE_MAX)?;
        let sub = parse_component(&parts, 2, "sub", Self::SUB_MAX)?;
        // Components are already range-checked, so the shifts are safe.
        Ok(Self((main << 11) | (middle << 8) | sub))
    }
}

impl Serialize for GroupAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for GroupAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

/// A KNX individual (physical) address (e.g. `"1.1.4"`).
///
/// The three parts are area (0–15, 4 bits), line (0–15, 4 bits) and
/// device (0–255, 8 bits), packed into a single [`u16`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IndividualAddress(u16);

impl IndividualAddress {
    /// Maximum permitted value for the area.
    pub const AREA_MAX: u32 = 15;
    /// Maximum permitted value for the line.
    pub const LINE_MAX: u32 = 15;
    /// Maximum permitted value for the device.
    pub const DEVICE_MAX: u32 = 255;

    /// Constructs an individual address from its three parts, validating ranges.
    pub fn new(area: u8, line: u8, device: u8) -> Result<Self, AddressParseError> {
        if u32::from(area) > Self::AREA_MAX {
            return Err(AddressParseError::OutOfRange {
                part: "area",
                value: u32::from(area),
                min: 0,
                max: Self::AREA_MAX,
            });
        }
        if u32::from(line) > Self::LINE_MAX {
            return Err(AddressParseError::OutOfRange {
                part: "line",
                value: u32::from(line),
                min: 0,
                max: Self::LINE_MAX,
            });
        }
        Ok(Self(
            (u16::from(area) << 12) | (u16::from(line) << 8) | u16::from(device),
        ))
    }

    /// Constructs an individual address from its raw 16-bit representation.
    pub fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    /// The raw 16-bit representation.
    pub fn raw(self) -> u16 {
        self.0
    }

    /// The area (0–15).
    pub fn area(self) -> u8 {
        (self.0 >> 12) as u8
    }

    /// The line (0–15).
    pub fn line(self) -> u8 {
        ((self.0 >> 8) & 0x0f) as u8
    }

    /// The device (0–255).
    pub fn device(self) -> u8 {
        (self.0 & 0xff) as u8
    }
}

impl fmt::Display for IndividualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.area(), self.line(), self.device())
    }
}

impl FromStr for IndividualAddress {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(AddressParseError::Shape {
                expected: "an individual address like \"1.1.4\" (area.line.device)",
                found: s.to_string(),
            });
        }
        let area = parse_component(&parts, 0, "area", Self::AREA_MAX)?;
        let line = parse_component(&parts, 1, "line", Self::LINE_MAX)?;
        let device = parse_component(&parts, 2, "device", Self::DEVICE_MAX)?;
        Ok(Self((area << 12) | (line << 8) | device))
    }
}

impl Serialize for IndividualAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IndividualAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_address_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let ga: GroupAddress = "3/0/4".parse()?;
        assert_eq!(ga.main(), 3);
        assert_eq!(ga.middle(), 0);
        assert_eq!(ga.sub(), 4);
        assert_eq!(ga.to_string(), "3/0/4");
        assert_eq!(ga.raw(), (3 << 11) | 4);
        Ok(())
    }

    #[test]
    fn group_address_max_values() -> Result<(), Box<dyn std::error::Error>> {
        let ga: GroupAddress = "31/7/255".parse()?;
        assert_eq!(ga.raw(), 0xffff);
        assert_eq!(ga.to_string(), "31/7/255");
        Ok(())
    }

    #[test]
    fn group_address_reserved() -> Result<(), Box<dyn std::error::Error>> {
        let ga: GroupAddress = "0/0/0".parse()?;
        assert!(ga.is_reserved());
        Ok(())
    }

    #[test]
    fn group_address_out_of_range() {
        assert!("32/0/0".parse::<GroupAddress>().is_err());
        assert!("0/8/0".parse::<GroupAddress>().is_err());
        assert!("0/0/256".parse::<GroupAddress>().is_err());
    }

    #[test]
    fn group_address_bad_shape() {
        assert!("3/0".parse::<GroupAddress>().is_err());
        assert!("3/0/4/5".parse::<GroupAddress>().is_err());
        assert!("abc".parse::<GroupAddress>().is_err());
    }

    #[test]
    fn group_address_ordering() -> Result<(), Box<dyn std::error::Error>> {
        let a: GroupAddress = "1/0/0".parse()?;
        let b: GroupAddress = "2/0/0".parse()?;
        assert!(a < b);
        Ok(())
    }

    #[test]
    fn individual_address_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let ia: IndividualAddress = "1.1.4".parse()?;
        assert_eq!(ia.area(), 1);
        assert_eq!(ia.line(), 1);
        assert_eq!(ia.device(), 4);
        assert_eq!(ia.to_string(), "1.1.4");
        Ok(())
    }

    #[test]
    fn individual_address_max() -> Result<(), Box<dyn std::error::Error>> {
        let ia: IndividualAddress = "15.15.255".parse()?;
        assert_eq!(ia.raw(), 0xffff);
        Ok(())
    }

    #[test]
    fn individual_address_out_of_range() {
        assert!("16.0.0".parse::<IndividualAddress>().is_err());
        assert!("0.16.0".parse::<IndividualAddress>().is_err());
        assert!("0.0.256".parse::<IndividualAddress>().is_err());
    }
}
