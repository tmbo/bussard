//! A tiny, independent datapoint-type (DPT) codec for the stimulus and group
//! runtime.
//!
//! This is deliberately minimal: it covers only the DPTs the small-installation
//! example transmits — DPT 1.001 (1-bit boolean) and DPT 9.001 (2-octet KNX
//! float). It is a clean-room encoder written from the KNX datapoint-type spec,
//! not shared with the tool under test. The group runtime needs it only to turn
//! a scripted stimulus value string into the exact bytes a real device would put
//! on the bus, and to render a served value for logging.
//!
//! DPT 1.001 encodes into the low bit of a single octet (KNX 3/7/2 §1). DPT
//! 9.001 is the KNX 16-bit float `(0.01 · m) · 2^e` with a 4-bit exponent and a
//! sign-magnitude 11-bit mantissa (KNX 3/7/2 §9), big-endian.

/// Errors from encoding a stimulus value for a DPT.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DptError {
    /// The DPT is not one this minimal codec supports.
    #[error("unsupported DPT {0:?} (this codec handles 1.001 and 9.001)")]
    UnsupportedDpt(String),
    /// The value string could not be parsed for the DPT.
    #[error("cannot parse {value:?} as DPT {dpt}: {reason}")]
    BadValue {
        /// The DPT.
        dpt: String,
        /// The offending value string.
        value: String,
        /// Why it was rejected.
        reason: String,
    },
}

/// Encode a value string into KNX group-data octets for `dpt`.
///
/// Returns the raw payload octets a device would carry in an
/// `A_GroupValue_Write`/`_Response`. For a sub-byte DPT (1.001) that is a single
/// octet whose low bits hold the value; the transport layer decides whether to
/// pack it into the APCI. For DPT 9.001 it is the two big-endian float octets.
pub fn encode(dpt: &str, value: &str) -> Result<Vec<u8>, DptError> {
    match normalize(dpt) {
        Dpt::B1 => {
            let v = value.trim();
            let bit = match v {
                "1" | "true" | "on" | "On" | "ON" => 1u8,
                "0" | "false" | "off" | "Off" | "OFF" => 0u8,
                other => {
                    return Err(DptError::BadValue {
                        dpt: dpt.to_string(),
                        value: other.to_string(),
                        reason: "expected 0/1/on/off".into(),
                    });
                }
            };
            Ok(vec![bit])
        }
        Dpt::F16 => {
            let f: f64 = value.trim().parse().map_err(|_| DptError::BadValue {
                dpt: dpt.to_string(),
                value: value.to_string(),
                reason: "expected a number".into(),
            })?;
            Ok(encode_dpt9(f).to_vec())
        }
        Dpt::Unsupported => Err(DptError::UnsupportedDpt(dpt.to_string())),
    }
}

/// Decode group-data octets back into a human string for `dpt` (best-effort, for
/// logging). Unknown DPTs render as hex.
pub fn decode_to_string(dpt: &str, payload: &[u8]) -> String {
    match normalize(dpt) {
        Dpt::B1 => {
            let bit = payload.first().map(|b| b & 0x01).unwrap_or(0);
            if bit == 1 { "1".into() } else { "0".into() }
        }
        Dpt::F16 if payload.len() >= 2 => {
            format!("{:.2}", decode_dpt9([payload[0], payload[1]]))
        }
        _ => payload.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// True if `dpt` is a sub-byte type whose value packs into the APCI low bits
/// (DPT main 1/2/3). Only 1.001 is modelled here.
pub fn is_packable(dpt: &str) -> bool {
    matches!(normalize(dpt), Dpt::B1)
}

/// The DPTs this minimal codec understands.
enum Dpt {
    /// DPT 1.xxx — 1-bit boolean.
    B1,
    /// DPT 9.xxx — 2-octet KNX float.
    F16,
    /// Anything else.
    Unsupported,
}

fn normalize(dpt: &str) -> Dpt {
    let main = dpt.split('.').next().unwrap_or("");
    match main {
        "1" => Dpt::B1,
        "9" => Dpt::F16,
        _ => Dpt::Unsupported,
    }
}

/// Encode a float as a KNX DPT 9 2-octet value (big-endian).
///
/// Layout: `MEEEEMMM MMMMMMMM` — sign bit `M`(15), 4-bit exponent `E`(14..11),
/// 11-bit two's-complement-ish mantissa. Value = `0.01 · mantissa · 2^exponent`.
fn encode_dpt9(value: f64) -> [u8; 2] {
    // Clamp to the representable range of DPT 9 (roughly ±670760).
    let clamped = value.clamp(-671088.64, 670760.96);
    let mut mantissa = (clamped * 100.0).round() as i32;
    let mut exponent = 0u8;
    // Scale the mantissa into the signed 11-bit range [-2048, 2047].
    while !(-2048..=2047).contains(&mantissa) && exponent < 15 {
        mantissa /= 2;
        exponent += 1;
    }
    let sign = if mantissa < 0 { 0x8000u16 } else { 0 };
    let mant = (mantissa.unsigned_abs() & 0x07FF) as u16;
    let word = sign | ((exponent as u16) << 11) | mant;
    // Negative values use a sign bit with the magnitude, matching the KNX
    // sign-and-magnitude encoding used by common stacks.
    word.to_be_bytes()
}

/// Decode a KNX DPT 9 2-octet value (big-endian) back into a float.
fn decode_dpt9(bytes: [u8; 2]) -> f64 {
    let word = u16::from_be_bytes(bytes);
    let sign = (word & 0x8000) != 0;
    let exponent = ((word >> 11) & 0x0F) as u32;
    let mantissa = (word & 0x07FF) as i32;
    let m = if sign { mantissa - 2048 } else { mantissa };
    0.01 * (m as f64) * (1u32 << exponent) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_dpt1() -> Result<(), DptError> {
        assert_eq!(encode("1.001", "1")?, vec![1]);
        assert_eq!(encode("1.001", "0")?, vec![0]);
        assert_eq!(encode("1.001", "on")?, vec![1]);
        assert!(is_packable("1.001"));
        Ok(())
    }

    #[test]
    fn test_encode_dpt9_roundtrips() -> Result<(), DptError> {
        // 21.5 °C encodes and decodes back close to itself.
        let bytes = encode("9.001", "21.5")?;
        assert_eq!(bytes.len(), 2);
        let back: f64 = decode_to_string("9.001", &bytes).parse().unwrap_or(0.0);
        assert!((back - 21.5).abs() < 0.05, "got {back}");
        assert!(!is_packable("9.001"));
        Ok(())
    }

    #[test]
    fn test_encode_dpt9_known_vector() -> Result<(), DptError> {
        // 0 °C is 0x0000.
        assert_eq!(encode("9.001", "0")?, vec![0x00, 0x00]);
        Ok(())
    }

    #[test]
    fn test_unsupported_dpt() {
        assert!(matches!(
            encode("5.001", "50"),
            Err(DptError::UnsupportedDpt(_))
        ));
    }
}
