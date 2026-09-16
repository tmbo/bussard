//! KNX individual and group addresses.
//!
//! Both are 16-bit values on the wire. The interpretation (area/line/device vs
//! main/middle/sub) differs, and the destination-address-type bit in the cEMI
//! control field selects which meaning applies to the destination.

use std::fmt;

/// A 16-bit KNX individual (physical) address `area.line.device`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IndividualAddress(pub u16);

impl IndividualAddress {
    /// Build from `area` (0..=15), `line` (0..=15) and `device` (0..=255).
    pub const fn new(area: u8, line: u8, device: u8) -> Self {
        Self(((area as u16) << 12) | (((line as u16) & 0x0F) << 8) | device as u16)
    }

    /// The raw 16-bit value.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// The area nibble.
    pub const fn area(self) -> u8 {
        (self.0 >> 12) as u8
    }

    /// The line nibble.
    pub const fn line(self) -> u8 {
        ((self.0 >> 8) & 0x0F) as u8
    }

    /// The device byte.
    pub const fn device(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

impl fmt::Display for IndividualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.area(), self.line(), self.device())
    }
}

impl std::str::FromStr for IndividualAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(format!("individual address must be 'a.l.d', got {s:?}"));
        }
        let area: u8 = parts[0].parse().map_err(|_| format!("bad area in {s:?}"))?;
        let line: u8 = parts[1].parse().map_err(|_| format!("bad line in {s:?}"))?;
        let device: u8 = parts[2]
            .parse()
            .map_err(|_| format!("bad device in {s:?}"))?;
        if area > 15 || line > 15 {
            return Err(format!("area/line out of range in {s:?}"));
        }
        Ok(Self::new(area, line, device))
    }
}

/// A 16-bit KNX group address `main/middle/sub` (3-level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupAddress(pub u16);

impl GroupAddress {
    /// The raw 16-bit value.
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl fmt::Display for GroupAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let main = (self.0 >> 11) & 0x1F;
        let middle = (self.0 >> 8) & 0x07;
        let sub = self.0 & 0xFF;
        write!(f, "{main}/{middle}/{sub}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_individual_address_roundtrip() {
        let a = IndividualAddress::new(1, 1, 2);
        assert_eq!(a.raw(), 0x1102);
        assert_eq!(a.area(), 1);
        assert_eq!(a.line(), 1);
        assert_eq!(a.device(), 2);
        assert_eq!(a.to_string(), "1.1.2");
    }

    #[test]
    fn test_individual_address_from_str() -> Result<(), String> {
        let a: IndividualAddress = "1.1.2".parse()?;
        assert_eq!(a, IndividualAddress::new(1, 1, 2));
        assert!("1.1".parse::<IndividualAddress>().is_err());
        assert!("99.1.1".parse::<IndividualAddress>().is_err());
        Ok(())
    }
}
