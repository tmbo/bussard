//! DPT value codecs: decoding raw group-value payloads into typed values.
//!
//! [`decode`] turns a `(Dpt, payload)` pair into a [`TypedValue`]; [`encode`]
//! does the reverse for the subset of DPTs where encoding is straightforward.
//! Anything unknown or malformed falls back to [`TypedValue::Raw`] on decode.

use std::fmt;

use crate::dpt::Dpt;

/// Error encoding a typed value into a payload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The value does not match the requested DPT.
    #[error("value {value} cannot be encoded as DPT {dpt}")]
    Mismatch {
        /// The requested DPT.
        dpt: String,
        /// Description of the value.
        value: String,
    },
    /// The value was outside the range representable by the DPT.
    #[error("value {value} is out of range for DPT {dpt}")]
    OutOfRange {
        /// The requested DPT.
        dpt: String,
        /// Description of the value.
        value: String,
    },
    /// Encoding for this DPT is not implemented.
    #[error("encoding DPT {dpt} is not supported")]
    Unsupported {
        /// The requested DPT.
        dpt: String,
    },
}

/// A decoded, typed group value.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    /// A boolean with a subtype-aware label (e.g. `On`/`Off`, `Up`/`Down`).
    Bool {
        /// The raw boolean.
        value: bool,
        /// Human label for the value under this subtype.
        label: &'static str,
    },
    /// A percentage (DPT 5.001), 0–100 %.
    Percent(f32),
    /// An unsigned integer with an optional unit.
    Unsigned {
        /// The value.
        value: u32,
        /// Unit label, if any (e.g. `"°"`).
        unit: Option<&'static str>,
    },
    /// A signed integer with an optional unit.
    Signed {
        /// The value.
        value: i64,
        /// Unit label, if any (e.g. `"Wh"`).
        unit: Option<&'static str>,
    },
    /// A floating-point value with an optional unit.
    Float {
        /// The value.
        value: f32,
        /// Unit label, if any (e.g. `"°C"`).
        unit: Option<&'static str>,
    },
    /// A control-dimming or control-blinds step (DPT 3.007 / 3.008).
    Step {
        /// Direction bit label (e.g. `"Increase"`/`"Decrease"`, `"Up"`/`"Down"`).
        direction: &'static str,
        /// The 3-bit step code (0 = break, 1..7 = number of intervals).
        step: u8,
    },
    /// A time of day with weekday (DPT 10.001).
    Time {
        /// Weekday 0 = no day, 1 = Monday … 7 = Sunday.
        weekday: u8,
        /// Hour 0–23.
        hour: u8,
        /// Minute 0–59.
        minute: u8,
        /// Second 0–59.
        second: u8,
    },
    /// A calendar date (DPT 11.001).
    Date {
        /// Day 1–31.
        day: u8,
        /// Month 1–12.
        month: u8,
        /// Full year (the DPT stores 0–99 with a pivot at 90).
        year: u16,
    },
    /// A text string (DPT 16.x), up to 14 characters.
    Text(String),
    /// A scene number (DPT 17.001), 0-based.
    Scene(u8),
    /// A scene control (DPT 18.001): activate or learn a scene.
    SceneControl {
        /// `true` = learn the scene, `false` = activate it.
        learn: bool,
        /// Scene number 0–63.
        scene: u8,
    },
    /// An HVAC operating mode (DPT 20.102).
    HvacMode(HvacMode),
    /// An RGB colour (DPT 232.600).
    Rgb {
        /// Red channel.
        r: u8,
        /// Green channel.
        g: u8,
        /// Blue channel.
        b: u8,
    },
    /// Fallback: the raw payload bytes as hex.
    Raw(Vec<u8>),
}

/// HVAC operating mode (DPT 20.102).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvacMode {
    /// Automatic mode.
    Auto,
    /// Comfort mode.
    Comfort,
    /// Standby mode.
    Standby,
    /// Economy / night setback.
    Economy,
    /// Building/frost protection.
    BuildingProtection,
    /// An unrecognised mode code.
    Unknown(u8),
}

impl fmt::Display for HvacMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HvacMode::Auto => write!(f, "Auto"),
            HvacMode::Comfort => write!(f, "Comfort"),
            HvacMode::Standby => write!(f, "Standby"),
            HvacMode::Economy => write!(f, "Economy"),
            HvacMode::BuildingProtection => write!(f, "Building Protection"),
            HvacMode::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

impl fmt::Display for TypedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypedValue::Bool { label, .. } => write!(f, "{label}"),
            TypedValue::Percent(p) => write!(f, "{p:.1} %"),
            TypedValue::Unsigned { value, unit } => match unit {
                Some(u) => write!(f, "{value} {u}"),
                None => write!(f, "{value}"),
            },
            TypedValue::Signed { value, unit } => match unit {
                Some(u) => write!(f, "{value} {u}"),
                None => write!(f, "{value}"),
            },
            TypedValue::Float { value, unit } => match unit {
                Some(u) => write!(f, "{value} {u}"),
                None => write!(f, "{value}"),
            },
            TypedValue::Step { direction, step } => {
                if *step == 0 {
                    write!(f, "{direction} break")
                } else {
                    write!(f, "{direction} step {step}")
                }
            }
            TypedValue::Time {
                weekday,
                hour,
                minute,
                second,
            } => {
                let day = match weekday {
                    1 => "Mon ",
                    2 => "Tue ",
                    3 => "Wed ",
                    4 => "Thu ",
                    5 => "Fri ",
                    6 => "Sat ",
                    7 => "Sun ",
                    _ => "",
                };
                write!(f, "{day}{hour:02}:{minute:02}:{second:02}")
            }
            TypedValue::Date { day, month, year } => write!(f, "{year:04}-{month:02}-{day:02}"),
            TypedValue::Text(s) => write!(f, "{s:?}"),
            TypedValue::Scene(n) => write!(f, "scene {n}"),
            TypedValue::SceneControl { learn, scene } => {
                if *learn {
                    write!(f, "learn scene {scene}")
                } else {
                    write!(f, "activate scene {scene}")
                }
            }
            TypedValue::HvacMode(m) => write!(f, "{m}"),
            TypedValue::Rgb { r, g, b } => write!(f, "#{r:02X}{g:02X}{b:02X}"),
            TypedValue::Raw(bytes) => {
                write!(f, "0x")?;
                for b in bytes {
                    write!(f, "{b:02X}")?;
                }
                Ok(())
            }
        }
    }
}

/// Returns the `(false_label, true_label)` for a DPT 1.x subtype.
fn bool_labels(sub: Option<u16>) -> (&'static str, &'static str) {
    match sub {
        Some(1) => ("Off", "On"),
        Some(2) => ("False", "True"),
        Some(3) => ("Disable", "Enable"),
        Some(5) => ("No Alarm", "Alarm"),
        Some(7) => ("Decrease", "Increase"),
        Some(8) => ("Up", "Down"),
        Some(9) => ("Open", "Closed"),
        Some(10) => ("Stop", "Start"),
        _ => ("0", "1"),
    }
}

/// Returns the unit label for a DPT 9.x subtype (2-byte float).
fn float16_unit(sub: Option<u16>) -> Option<&'static str> {
    match sub {
        Some(1) => Some("°C"),
        Some(4) => Some("lux"),
        Some(5) => Some("m/s"),
        Some(6) => Some("Pa"),
        Some(7) => Some("%"),
        Some(21) => Some("mA"),
        Some(28) => Some("km/h"),
        _ => None,
    }
}

/// Returns the unit label for a DPT 14.x subtype (IEEE float).
fn float32_unit(sub: Option<u16>) -> Option<&'static str> {
    match sub {
        Some(19) => Some("A"),
        Some(27) => Some("V"),
        Some(28) => Some("V"),
        Some(56) => Some("W"),
        Some(76) => Some("m³"),
        Some(68) => Some("°C"),
        _ => None,
    }
}

/// Decodes a KNX 2-byte float (DPT 9.x) from two bytes.
///
/// Layout: `SEEEEMMM MMMMMMMM` where S is the sign, E is a 4-bit exponent, and
/// M is an 11-bit two's-complement mantissa. The value is `0.01 * M * 2^E`.
fn decode_float16(hi: u8, lo: u8) -> f32 {
    let raw = ((hi as u16) << 8) | lo as u16;
    let sign = (raw & 0x8000) != 0;
    let exponent = ((raw >> 11) & 0x0f) as i32;
    let mantissa_raw = (raw & 0x07ff) as i32;
    // 11-bit two's-complement mantissa, with the sign bit applied.
    let mantissa = if sign {
        mantissa_raw - 2048
    } else {
        mantissa_raw
    };
    (0.01_f32) * (mantissa as f32) * (1u32 << exponent) as f32
}

/// Encodes a value into a KNX 2-byte float (DPT 9.x).
fn encode_float16(value: f32) -> Result<[u8; 2], ()> {
    // Representable range of DPT 9: mantissa in -2048..=2047, exponent 0..=15.
    let mut mantissa = (value * 100.0).round() as i32;
    let mut exponent = 0i32;
    while !(-2048..=2047).contains(&mantissa) {
        if exponent >= 15 {
            return Err(());
        }
        // Round-halves-away division by two to keep precision reasonable.
        mantissa = if mantissa >= 0 {
            (mantissa + 1) / 2
        } else {
            (mantissa - 1) / 2
        };
        exponent += 1;
    }
    let (sign, mant_bits) = if mantissa < 0 {
        (0x8000u16, (mantissa + 2048) as u16)
    } else {
        (0u16, mantissa as u16)
    };
    let raw = sign | ((exponent as u16) << 11) | (mant_bits & 0x07ff);
    Ok([(raw >> 8) as u8, (raw & 0xff) as u8])
}

/// Decodes a group-value payload into a [`TypedValue`] under the given DPT.
///
/// This never fails: unknown DPTs and size mismatches degrade to
/// [`TypedValue::Raw`] so the monitor keeps working against an incomplete
/// model.
pub fn decode(dpt: &Dpt, payload: &[u8]) -> TypedValue {
    decode_inner(dpt, payload).unwrap_or_else(|| TypedValue::Raw(payload.to_vec()))
}

/// The fallible inner decode; `None` means "fall back to raw".
fn decode_inner(dpt: &Dpt, payload: &[u8]) -> Option<TypedValue> {
    match dpt.main {
        1 => {
            let b = payload.first()?;
            let value = (b & 0x01) != 0;
            let (f, t) = bool_labels(dpt.sub);
            Some(TypedValue::Bool {
                value,
                label: if value { t } else { f },
            })
        }
        3 => {
            // 4-bit control: bit 3 direction, bits 0..2 step.
            let b = payload.first()? & 0x0f;
            let direction_bit = (b & 0x08) != 0;
            let step = b & 0x07;
            let direction = match dpt.sub {
                Some(8) => {
                    if direction_bit {
                        "Down"
                    } else {
                        "Up"
                    }
                }
                _ => {
                    if direction_bit {
                        "Increase"
                    } else {
                        "Decrease"
                    }
                }
            };
            Some(TypedValue::Step { direction, step })
        }
        5 => {
            let b = *payload.first()?;
            match dpt.sub {
                Some(1) => Some(TypedValue::Percent((b as f32) * 100.0 / 255.0)),
                Some(3) => Some(TypedValue::Unsigned {
                    value: ((b as u32) * 360 / 255),
                    unit: Some("°"),
                }),
                _ => Some(TypedValue::Unsigned {
                    value: b as u32,
                    unit: None,
                }),
            }
        }
        6 => {
            let b = *payload.first()? as i8;
            Some(TypedValue::Signed {
                value: b as i64,
                unit: None,
            })
        }
        7 => {
            let v = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
            Some(TypedValue::Unsigned {
                value: v as u32,
                unit: None,
            })
        }
        8 => {
            let v = i16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
            Some(TypedValue::Signed {
                value: v as i64,
                unit: None,
            })
        }
        9 => {
            let value = decode_float16(*payload.first()?, *payload.get(1)?);
            Some(TypedValue::Float {
                value,
                unit: float16_unit(dpt.sub),
            })
        }
        10 => {
            let b0 = *payload.first()?;
            let b1 = *payload.get(1)?;
            let b2 = *payload.get(2)?;
            Some(TypedValue::Time {
                weekday: (b0 >> 5) & 0x07,
                hour: b0 & 0x1f,
                minute: b1 & 0x3f,
                second: b2 & 0x3f,
            })
        }
        11 => {
            let day = *payload.first()? & 0x1f;
            let month = *payload.get(1)? & 0x0f;
            let yy = (*payload.get(2)? & 0x7f) as u16;
            // DPT 11.001 pivot: 0..=89 -> 2000+, 90..=99 -> 1900+.
            let year = if yy >= 90 { 1900 + yy } else { 2000 + yy };
            Some(TypedValue::Date { day, month, year })
        }
        12 => {
            let v = u32::from_be_bytes([
                *payload.first()?,
                *payload.get(1)?,
                *payload.get(2)?,
                *payload.get(3)?,
            ]);
            Some(TypedValue::Unsigned {
                value: v,
                unit: None,
            })
        }
        13 => {
            let v = i32::from_be_bytes([
                *payload.first()?,
                *payload.get(1)?,
                *payload.get(2)?,
                *payload.get(3)?,
            ]);
            let unit = match dpt.sub {
                Some(10) => Some("Wh"),
                Some(13) => Some("kWh"),
                _ => None,
            };
            Some(TypedValue::Signed {
                value: v as i64,
                unit,
            })
        }
        14 => {
            let v = f32::from_be_bytes([
                *payload.first()?,
                *payload.get(1)?,
                *payload.get(2)?,
                *payload.get(3)?,
            ]);
            Some(TypedValue::Float {
                value: v,
                unit: float32_unit(dpt.sub),
            })
        }
        16 => {
            // 14-char string; 16.000 ASCII, 16.001 ISO-8859-1 (Latin-1).
            let mut s = String::new();
            for &b in payload.iter().take(14) {
                if b == 0 {
                    break;
                }
                s.push(b as char); // Latin-1: byte value == code point.
            }
            Some(TypedValue::Text(s))
        }
        17 => {
            let scene = *payload.first()? & 0x3f;
            Some(TypedValue::Scene(scene))
        }
        18 => {
            let b = *payload.first()?;
            Some(TypedValue::SceneControl {
                learn: (b & 0x80) != 0,
                scene: b & 0x3f,
            })
        }
        20 => {
            let b = *payload.first()?;
            let mode = match b {
                0 => HvacMode::Auto,
                1 => HvacMode::Comfort,
                2 => HvacMode::Standby,
                3 => HvacMode::Economy,
                4 => HvacMode::BuildingProtection,
                other => HvacMode::Unknown(other),
            };
            Some(TypedValue::HvacMode(mode))
        }
        232 => Some(TypedValue::Rgb {
            r: *payload.first()?,
            g: *payload.get(1)?,
            b: *payload.get(2)?,
        }),
        _ => None,
    }
}

/// Encodes a [`TypedValue`] into a group-value payload under the given DPT.
///
/// Only the straightforward DPTs are supported; others return
/// [`EncodeError::Unsupported`].
pub fn encode(dpt: &Dpt, value: &TypedValue) -> Result<Vec<u8>, EncodeError> {
    let mismatch = || EncodeError::Mismatch {
        dpt: dpt.to_string(),
        value: value.to_string(),
    };
    match dpt.main {
        1 => match value {
            TypedValue::Bool { value, .. } => Ok(vec![*value as u8]),
            _ => Err(mismatch()),
        },
        5 => match (dpt.sub, value) {
            (Some(1), TypedValue::Percent(p)) => {
                if !(0.0..=100.0).contains(p) {
                    return Err(EncodeError::OutOfRange {
                        dpt: dpt.to_string(),
                        value: value.to_string(),
                    });
                }
                Ok(vec![(p * 255.0 / 100.0).round() as u8])
            }
            (_, TypedValue::Unsigned { value: v, .. }) if *v <= 255 => Ok(vec![*v as u8]),
            _ => Err(mismatch()),
        },
        6 => match value {
            TypedValue::Signed { value: v, .. } if (-128..=127).contains(v) => {
                Ok(vec![(*v as i8) as u8])
            }
            _ => Err(mismatch()),
        },
        7 => match value {
            TypedValue::Unsigned { value: v, .. } if *v <= 0xffff => {
                Ok((*v as u16).to_be_bytes().to_vec())
            }
            _ => Err(mismatch()),
        },
        8 => match value {
            TypedValue::Signed { value: v, .. } if (-32768..=32767).contains(v) => {
                Ok((*v as i16).to_be_bytes().to_vec())
            }
            _ => Err(mismatch()),
        },
        9 => {
            match value {
                TypedValue::Float { value: v, .. } => encode_float16(*v)
                    .map(|b| b.to_vec())
                    .map_err(|()| EncodeError::OutOfRange {
                        dpt: dpt.to_string(),
                        value: value.to_string(),
                    }),
                _ => Err(mismatch()),
            }
        }
        12 => match value {
            TypedValue::Unsigned { value: v, .. } => Ok(v.to_be_bytes().to_vec()),
            _ => Err(mismatch()),
        },
        13 => match value {
            TypedValue::Signed { value: v, .. }
                if (i32::MIN as i64..=i32::MAX as i64).contains(v) =>
            {
                Ok((*v as i32).to_be_bytes().to_vec())
            }
            _ => Err(mismatch()),
        },
        14 => match value {
            TypedValue::Float { value: v, .. } => Ok(v.to_be_bytes().to_vec()),
            _ => Err(mismatch()),
        },
        17 => match value {
            TypedValue::Scene(n) if *n <= 63 => Ok(vec![*n & 0x3f]),
            _ => Err(mismatch()),
        },
        232 => match value {
            TypedValue::Rgb { r, g, b } => Ok(vec![*r, *g, *b]),
            _ => Err(mismatch()),
        },
        _ => Err(EncodeError::Unsupported {
            dpt: dpt.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dpt(s: &str) -> Dpt {
        s.parse().unwrap()
    }

    #[test]
    fn bool_subtype_labels() {
        assert_eq!(
            decode(&dpt("1.001"), &[1]),
            TypedValue::Bool {
                value: true,
                label: "On"
            }
        );
        assert_eq!(
            decode(&dpt("1.008"), &[1]),
            TypedValue::Bool {
                value: true,
                label: "Down"
            }
        );
        assert_eq!(
            decode(&dpt("1.005"), &[1]),
            TypedValue::Bool {
                value: true,
                label: "Alarm"
            }
        );
        assert_eq!(
            decode(&dpt("1.005"), &[0]),
            TypedValue::Bool {
                value: false,
                label: "No Alarm"
            }
        );
    }

    #[test]
    fn control_dimming_and_blinds() {
        // 3.007 increase, 5 steps.
        assert_eq!(
            decode(&dpt("3.007"), &[0x0d]),
            TypedValue::Step {
                direction: "Increase",
                step: 5
            }
        );
        // 3.008 down.
        assert_eq!(
            decode(&dpt("3.008"), &[0x09]),
            TypedValue::Step {
                direction: "Down",
                step: 1
            }
        );
    }

    #[test]
    fn percent_scaling() {
        assert_eq!(decode(&dpt("5.001"), &[0]), TypedValue::Percent(0.0));
        assert_eq!(decode(&dpt("5.001"), &[255]), TypedValue::Percent(100.0));
        if let TypedValue::Percent(p) = decode(&dpt("5.001"), &[128]) {
            assert!((p - 50.196).abs() < 0.01);
        } else {
            panic!("expected percent");
        }
    }

    #[test]
    fn signed_byte() {
        assert_eq!(
            decode(&dpt("6.010"), &[0xff]),
            TypedValue::Signed {
                value: -1,
                unit: None
            }
        );
    }

    #[test]
    fn float16_reference_vectors() {
        // 0x0C1A = 21.00 °C (the canonical KNX example).
        if let TypedValue::Float { value, unit } = decode(&dpt("9.001"), &[0x0C, 0x1A]) {
            assert!((value - 21.0).abs() < 0.01, "got {value}");
            assert_eq!(unit, Some("°C"));
        } else {
            panic!("expected float");
        }
        // Zero.
        if let TypedValue::Float { value, .. } = decode(&dpt("9.001"), &[0x00, 0x00]) {
            assert_eq!(value, 0.0);
        } else {
            panic!("expected float");
        }
        // Negative: 0x8A24 ≈ -30.00 °C.
        if let TypedValue::Float { value, .. } = decode(&dpt("9.001"), &[0x8A, 0x24]) {
            assert!((value - (-30.0)).abs() < 0.5, "got {value}");
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn float16_roundtrip() {
        // DPT 9 quantizes more coarsely as magnitude grows (the exponent scales
        // the 0.01 resolution), so the tolerance is proportional to the value.
        for &t in &[0.0f32, 21.0, -30.0, 0.5, 100.0, -273.15] {
            let bytes = encode_float16(t).unwrap();
            let back = decode_float16(bytes[0], bytes[1]);
            let tol = 0.1_f32.max(t.abs() * 0.001);
            assert!((back - t).abs() <= tol, "roundtrip {t} -> {back}");
        }
    }

    #[test]
    fn u16_i16() {
        assert_eq!(
            decode(&dpt("7.001"), &[0x12, 0x34]),
            TypedValue::Unsigned {
                value: 0x1234,
                unit: None
            }
        );
        assert_eq!(
            decode(&dpt("8.001"), &[0xff, 0xff]),
            TypedValue::Signed {
                value: -1,
                unit: None
            }
        );
    }

    #[test]
    fn time_and_date() {
        // Monday 09:30:00 -> weekday 1 (0x20|9=0x29), 30, 0.
        assert_eq!(
            decode(&dpt("10.001"), &[0x29, 30, 0]),
            TypedValue::Time {
                weekday: 1,
                hour: 9,
                minute: 30,
                second: 0
            }
        );
        // 2024-12-31.
        assert_eq!(
            decode(&dpt("11.001"), &[31, 12, 24]),
            TypedValue::Date {
                day: 31,
                month: 12,
                year: 2024
            }
        );
        // 1995 (pivot).
        assert_eq!(
            decode(&dpt("11.001"), &[1, 1, 95]),
            TypedValue::Date {
                day: 1,
                month: 1,
                year: 1995
            }
        );
    }

    #[test]
    fn u32_i32_energy() {
        assert_eq!(
            decode(&dpt("13.013"), &[0x00, 0x00, 0x00, 0x0a]),
            TypedValue::Signed {
                value: 10,
                unit: Some("kWh")
            }
        );
    }

    #[test]
    fn ieee_float() {
        if let TypedValue::Float { value, .. } = decode(&dpt("14.076"), &[0x42, 0x28, 0x00, 0x00]) {
            assert!((value - 42.0).abs() < 0.001);
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn string_14_char() {
        let payload = b"Hello\0\0\0\0\0\0\0\0\0";
        assert_eq!(
            decode(&dpt("16.000"), payload),
            TypedValue::Text("Hello".to_string())
        );
    }

    #[test]
    fn scene_and_control() {
        assert_eq!(decode(&dpt("17.001"), &[5]), TypedValue::Scene(5));
        assert_eq!(
            decode(&dpt("18.001"), &[0x83]),
            TypedValue::SceneControl {
                learn: true,
                scene: 3
            }
        );
    }

    #[test]
    fn hvac_mode() {
        assert_eq!(
            decode(&dpt("20.102"), &[1]),
            TypedValue::HvacMode(HvacMode::Comfort)
        );
        assert_eq!(
            decode(&dpt("20.102"), &[4]),
            TypedValue::HvacMode(HvacMode::BuildingProtection)
        );
    }

    #[test]
    fn rgb() {
        assert_eq!(
            decode(&dpt("232.600"), &[0xff, 0x80, 0x00]),
            TypedValue::Rgb {
                r: 0xff,
                g: 0x80,
                b: 0x00
            }
        );
    }

    #[test]
    fn unknown_falls_back_to_raw() {
        assert_eq!(
            decode(&dpt("250"), &[1, 2, 3]),
            TypedValue::Raw(vec![1, 2, 3])
        );
    }

    #[test]
    fn short_payload_falls_back_to_raw() {
        // 9.x needs 2 bytes.
        assert_eq!(decode(&dpt("9.001"), &[1]), TypedValue::Raw(vec![1]));
    }

    #[test]
    fn encode_roundtrips() {
        let v = TypedValue::Bool {
            value: true,
            label: "On",
        };
        assert_eq!(encode(&dpt("1.001"), &v).unwrap(), vec![1]);

        let v = TypedValue::Percent(100.0);
        assert_eq!(encode(&dpt("5.001"), &v).unwrap(), vec![255]);

        let v = TypedValue::Scene(3);
        assert_eq!(encode(&dpt("17.001"), &v).unwrap(), vec![3]);

        let v = TypedValue::Rgb { r: 1, g: 2, b: 3 };
        assert_eq!(encode(&dpt("232.600"), &v).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn encode_out_of_range() {
        let v = TypedValue::Percent(150.0);
        assert!(matches!(
            encode(&dpt("5.001"), &v),
            Err(EncodeError::OutOfRange { .. })
        ));
    }

    #[test]
    fn encode_unsupported() {
        let v = TypedValue::Raw(vec![]);
        assert!(matches!(
            encode(&dpt("250"), &v),
            Err(EncodeError::Unsupported { .. })
        ));
    }
}
