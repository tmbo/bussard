//! Test helpers shared by the security object's unit tests: hex decoding and
//! a plain-APDU exchange with the object.

use super::{SecurityLimits, SecurityObject};
use crate::wire::apdu::Apci;

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Decode a hex string with optional spaces.
pub(super) fn hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

/// Feed a plain APDU (2 APCI octets + data, as in the capture) to the
/// object and return the plain response APDU (2 APCI octets + data).
pub(super) fn exchange(
    obj: &mut SecurityObject,
    apdu_hex: &str,
    limits: SecurityLimits,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let apdu = hex(apdu_hex)?;
    let apci10 = (u16::from(apdu[0] & 0x03) << 8) | u16::from(apdu[1]);
    let reply = obj
        .handle(Apci::from_u10(apci10), &apdu[2..], limits)?
        .ok_or("no reply")?;
    let v = reply.apci.to_u10();
    let mut out = vec![(v >> 8) as u8, (v & 0xFF) as u8];
    out.extend_from_slice(&reply.data);
    Ok(out)
}

pub(super) fn cmd(
    obj: &mut SecurityObject,
    apdu_hex: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    exchange(obj, apdu_hex, SecurityLimits::default())
}

pub(super) const UNLOAD: &str = "01d4 0011 001005 04000000000000000000";
pub(super) const START: &str = "01d4 0011 001005 01000000000000000000";
pub(super) const COMPLETE: &str = "01d4 0011 001005 02000000000000000000";

/// A PID 61 WriteCon of `count` flag octets (value 0x03) at `start`.
pub(super) fn go_flags_write(start: u16, count: u8) -> String {
    format!(
        "01ce 0011 00103d {count:02x} {start:04x} {}",
        "03".repeat(usize::from(count))
    )
}

/// A PID 53 WriteCon of one row naming address-table index `index`.
pub(super) fn group_key_write(row: u16, index: u16) -> String {
    format!(
        "01ce 0011 001035 01 {row:04x} {index:04x} {}",
        "a5".repeat(16)
    )
}
