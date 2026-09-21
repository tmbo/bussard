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

/// Error parsing a human-typed value into a [`TypedValue`] for a DPT.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseValueError {
    /// The input did not match any accepted form for this DPT. `accepted`
    /// describes what would have been valid.
    #[error("cannot parse {input:?} as DPT {dpt}: expected {accepted}")]
    Invalid {
        /// The DPT being parsed for.
        dpt: String,
        /// The offending input.
        input: String,
        /// A human description of the accepted forms.
        accepted: String,
    },
    /// The value parsed but fell outside the DPT's representable range.
    #[error("value {input:?} is out of range for DPT {dpt}: {range}")]
    OutOfRange {
        /// The DPT being parsed for.
        dpt: String,
        /// The offending input.
        input: String,
        /// A human description of the valid range.
        range: String,
    },
    /// bussard does not know how to parse human input for this DPT main type.
    #[error("parsing human input for DPT {dpt} is not supported")]
    Unsupported {
        /// The DPT being parsed for.
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
    /// A combined date and time (DPT 19.001), the 8-octet KNX `DateTime`.
    DateTime(DateTime),
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
    /// An RGBW colour (DPT 251.600).
    Rgbw(Rgbw),
    /// Fallback: the raw payload bytes as hex.
    Raw(Vec<u8>),
}

/// A combined date and time (DPT 19.001), the KNX 8-octet `DateTime`.
///
/// Per KNX 03/07/02 "Datapoint Types" (DPT 19.001 `DPT_DateTime`), the fields
/// carry an absolute date and time plus a block of validity/quality flags. The
/// individual `no_*` flags mark a component as "not present" (e.g. a device that
/// only sends a date sets `no_time`). `fault` reports a clock fault;
/// `working_day`/`no_working_day` encode the working-day state (both false =
/// "not used"); `summer_time` marks daylight-saving; `quality` and `sync_source`
/// come from the final octet's clock-quality bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    /// Full year (the wire stores `year - 1900`, so `0..=255` → `1900..=2155`).
    pub year: u16,
    /// Month 1–12.
    pub month: u8,
    /// Day of month 1–31.
    pub day: u8,
    /// Day of week: 0 = any/no day, 1 = Monday … 7 = Sunday.
    pub weekday: u8,
    /// Hour 0–24 (24 with minutes/seconds 0 denotes end-of-day).
    pub hour: u8,
    /// Minute 0–59.
    pub minute: u8,
    /// Second 0–59.
    pub second: u8,
    /// Clock fault: the date/time is unreliable.
    pub fault: bool,
    /// Working-day flag (meaningful only when `no_working_day` is false).
    pub working_day: bool,
    /// Working-day field is not valid / not used.
    pub no_working_day: bool,
    /// The year field is not valid.
    pub no_year: bool,
    /// The date fields (month/day) are not valid.
    pub no_date: bool,
    /// The day-of-week field is not valid.
    pub no_weekday: bool,
    /// The time fields (hour/minute/second) are not valid.
    pub no_time: bool,
    /// Standard/summer time: `true` = summer time (DST) is in effect.
    pub summer_time: bool,
    /// Clock quality bit from the final octet: `true` = the clock is
    /// synchronised to an external source.
    pub quality: bool,
    /// Synchronisation-source bit from the final octet (newer spec revisions):
    /// `true` = the clock-synchronisation signal is reliable.
    pub sync_source: bool,
}

/// An RGBW colour (DPT 251.600), four 8-bit channels plus per-channel validity.
///
/// Per KNX 03/07/02 (DPT 251.600 `DPT_Colour_RGBW`) the 6-octet payload carries
/// red/green/blue/white bytes, a reserved octet, then a validity octet whose low
/// nibble flags which channels are valid: bit 3 = red, bit 2 = green, bit 1 =
/// blue, bit 0 = white. A channel whose valid bit is clear should be ignored by
/// the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgbw {
    /// Red channel.
    pub r: u8,
    /// Green channel.
    pub g: u8,
    /// Blue channel.
    pub b: u8,
    /// White channel.
    pub w: u8,
    /// Red channel is valid.
    pub r_valid: bool,
    /// Green channel is valid.
    pub g_valid: bool,
    /// Blue channel is valid.
    pub b_valid: bool,
    /// White channel is valid.
    pub w_valid: bool,
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

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render present components; omit ones flagged not-valid. This mirrors
        // how `Time`/`Date` render and keeps a date-only or time-only telegram
        // honest instead of printing zeroed fields as if they were real.
        let day = match (self.no_weekday, self.weekday) {
            (false, 1) => "Mon ",
            (false, 2) => "Tue ",
            (false, 3) => "Wed ",
            (false, 4) => "Thu ",
            (false, 5) => "Fri ",
            (false, 6) => "Sat ",
            (false, 7) => "Sun ",
            _ => "",
        };
        if !self.no_date {
            let year = if self.no_year {
                "????".to_string()
            } else {
                format!("{:04}", self.year)
            };
            write!(f, "{year}-{:02}-{:02}", self.month, self.day)?;
            if !self.no_time {
                write!(f, " ")?;
            }
        }
        if !self.no_time {
            write!(
                f,
                "{day}{:02}:{:02}:{:02}",
                self.hour, self.minute, self.second
            )?;
        }
        if self.fault {
            write!(f, " (fault)")?;
        }
        Ok(())
    }
}

impl fmt::Display for Rgbw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show each channel, marking invalid ones with `--` rather than a bogus
        // value so a partial update (only some channels valid) reads correctly.
        let chan = |valid: bool, v: u8| -> String {
            if valid {
                format!("{v:02X}")
            } else {
                "--".to_string()
            }
        };
        write!(
            f,
            "RGBW({},{},{},{})",
            chan(self.r_valid, self.r),
            chan(self.g_valid, self.g),
            chan(self.b_valid, self.b),
            chan(self.w_valid, self.w),
        )
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
            TypedValue::DateTime(dt) => write!(f, "{dt}"),
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
            TypedValue::Rgbw(c) => write!(f, "{c}"),
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

/// The valid value range of DPT 9 (2-byte float `F16`), per the KNX standard
/// (03/07/02 "Datapoint Types", DPT 9 / KNX 2-octet float): the encoding is
/// `0.01 * M * 2^E` with the mantissa `M` in `-2048..=2047` and the exponent `E`
/// in `0..=15`. The published min/max are `-671088.64` (`M = -2048`, `E = 15`)
/// and `670433.28` (`M = 2046`, `E = 15`).
///
/// Note the max uses `M = 2046`, **not** `M = 2047`: the top positive code point
/// `M = 2047, E = 15` produces the raw pattern `0x7FFF`, which the standard
/// reserves as the "invalid data" marker rather than a number. So the largest
/// *valid* value is `0.01 * 2046 * 2^15 = 670433.28`, one mantissa step below
/// the raw-encoding ceiling of `670760.96`. Clamping `FLOAT16_MAX` here (rather
/// than at the raw ceiling) is what keeps a valid-looking input in
/// `670433.29..=670760.96` from rounding up onto `0x7FFF` and silently becoming
/// "invalid data" (issue #62). Computed rather than written as decimal literals
/// so the constants are exactly the nearest `f32` to those extremes.
const FLOAT16_MIN: f32 = 0.01 * -2048.0 * 32768.0;
const FLOAT16_MAX: f32 = 0.01 * 2046.0 * 32768.0;

/// Encodes a value into a KNX 2-byte float (DPT 9.x).
fn encode_float16(value: f32) -> Result<[u8; 2], ()> {
    // Reject non-finite (NaN/±Inf) and anything outside the representable range
    // *before* any integer math: `(value * 100.0).round() as i32` otherwise
    // saturates to `i32::MAX`/`i32::MIN` for huge inputs and the mantissa-
    // halving loop below then overflows on `mantissa ± 1` (panic in debug).
    if !value.is_finite() || !(FLOAT16_MIN..=FLOAT16_MAX).contains(&value) {
        return Err(());
    }
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
    // Defence in depth: 0x7FFF is the DPT 9 "invalid data" marker, never a value.
    // The `FLOAT16_MAX` cap above (mantissa <= 2046) already makes this pattern
    // unreachable for in-range inputs, but guard explicitly so a future change to
    // the range logic can never emit a payload that decodes as "invalid".
    if raw == 0x7FFF {
        return Err(());
    }
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
            let hi = *payload.first()?;
            let lo = *payload.get(1)?;
            // 0x7FFF is the DPT 9 "invalid data" sentinel (KNX spec): all sign,
            // exponent and mantissa bits set. Decoding it as a number yields a
            // meaningless ~670760.96, so instead fall back to `Raw` — the same
            // honest "uninterpretable payload" representation the decoder already
            // uses for unknown DPTs and size mismatches. The monitor renders it
            // as the raw hex bytes rather than a bogus temperature.
            if hi == 0x7F && lo == 0xFF {
                return None;
            }
            let value = decode_float16(hi, lo);
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
        // DPT 20 is a whole *family* of unrelated 1-octet enumerations
        // (20.001 SCLOMode, 20.102 HVACMode, 20.105 HVACContrMode, …). Only
        // 20.102 carries the HVAC operating mode; decoding every 20.x as an
        // HVAC mode rendered e.g. 20.105 value 1 as "Comfort". Other subtypes
        // have no modelled label set, so they decode as the raw enumeration
        // code (an unsigned byte) rather than a wrong name.
        20 if dpt.sub == Some(102) => {
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
        20 => {
            let b = *payload.first()?;
            Some(TypedValue::Unsigned {
                value: u32::from(b),
                unit: None,
            })
        }
        19 => {
            // DPT 19.001 DateTime: 8 octets. Layout per KNX 03/07/02:
            //   0: year - 1900
            //   1: bits 3-0 month (1-12)
            //   2: bits 4-0 day (1-31)
            //   3: bits 7-5 day-of-week (0..7), bits 4-0 hour (0-24)
            //   4: bits 5-0 minute (0-59)
            //   5: bits 5-0 second (0-59)
            //   6: flags F WD NWD NY ND NDoW NT SUTI (bit7..bit0)
            //   7: bit7 quality (clock sync), bit6 sync-source reliability
            let b0 = *payload.first()?;
            let b1 = *payload.get(1)?;
            let b2 = *payload.get(2)?;
            let b3 = *payload.get(3)?;
            let b4 = *payload.get(4)?;
            let b5 = *payload.get(5)?;
            let flags = *payload.get(6)?;
            let quality = *payload.get(7)?;
            Some(TypedValue::DateTime(DateTime {
                year: 1900 + b0 as u16,
                month: b1 & 0x0f,
                day: b2 & 0x1f,
                weekday: (b3 >> 5) & 0x07,
                hour: b3 & 0x1f,
                minute: b4 & 0x3f,
                second: b5 & 0x3f,
                fault: (flags & 0x80) != 0,
                working_day: (flags & 0x40) != 0,
                no_working_day: (flags & 0x20) != 0,
                no_year: (flags & 0x10) != 0,
                no_date: (flags & 0x08) != 0,
                no_weekday: (flags & 0x04) != 0,
                no_time: (flags & 0x02) != 0,
                summer_time: (flags & 0x01) != 0,
                quality: (quality & 0x80) != 0,
                sync_source: (quality & 0x40) != 0,
            }))
        }
        232 => Some(TypedValue::Rgb {
            r: *payload.first()?,
            g: *payload.get(1)?,
            b: *payload.get(2)?,
        }),
        251 => {
            // DPT 251.600 Colour RGBW: 6 octets — R, G, B, W, reserved, validity.
            // The validity octet's low nibble flags valid channels:
            //   bit3 = R, bit2 = G, bit1 = B, bit0 = W.
            let r = *payload.first()?;
            let g = *payload.get(1)?;
            let b = *payload.get(2)?;
            let w = *payload.get(3)?;
            // payload[4] is reserved and ignored on decode.
            let valid = *payload.get(5)?;
            Some(TypedValue::Rgbw(Rgbw {
                r,
                g,
                b,
                w,
                r_valid: (valid & 0x08) != 0,
                g_valid: (valid & 0x04) != 0,
                b_valid: (valid & 0x02) != 0,
                w_valid: (valid & 0x01) != 0,
            }))
        }
        _ => None,
    }
}

/// Parses human-typed text into a [`TypedValue`] appropriate for `dpt`.
///
/// This is the input side of the CLI `write` command and the MCP
/// `knx_write_group` tool: it turns friendly strings (`on`, `down`, `75%`,
/// `21.5°C`, `comfort`, a scene number) into the [`TypedValue`] that [`encode`]
/// serializes. Accepted forms, by DPT main type:
///
/// - **1.x** — `on`/`off`, `true`/`false`, `1`/`0`, and subtype words:
///   `up`/`down` (1.008), `open`/`closed` (1.009), `start`/`stop` (1.010),
///   `enable`/`disable` (1.003), `alarm`/`no-alarm` (1.005).
/// - **5.001** — a percentage: `75%` or a bare `0`–`100`.
/// - **5.003** — an angle `0`–`360` (bare number).
/// - **5.x** (other) — an integer `0`–`255`.
/// - **6.x** — a signed integer `-128`–`127`.
/// - **7.x** — an unsigned integer `0`–`65535`.
/// - **8.x** — a signed integer `-32768`–`32767`.
/// - **9.x** — a decimal, optionally with the subtype's unit suffix
///   (`21.5`, `21.5°C`).
/// - **12.x** — an unsigned integer `0`–`4294967295`.
/// - **13.x** — a signed 32-bit integer, optional unit suffix.
/// - **14.x** — a decimal (IEEE float), optional unit suffix.
/// - **17.001 / 18.001** — a scene number `0`–`63` (18.001 accepts a leading
///   `learn ` prefix).
/// - **20.102** — a mode name: `auto`, `comfort`, `standby`, `economy`,
///   `building-protection` (aliases `frost`, `protection`).
///
/// Errors name the DPT and the accepted forms so a caller (human or LLM) can
/// correct the input.
pub fn parse_value(dpt: &Dpt, input: &str) -> Result<TypedValue, ParseValueError> {
    let raw = input.trim();
    let invalid = |accepted: &str| ParseValueError::Invalid {
        dpt: dpt.to_string(),
        input: raw.to_string(),
        accepted: accepted.to_string(),
    };
    let out_of_range = |range: &str| ParseValueError::OutOfRange {
        dpt: dpt.to_string(),
        input: raw.to_string(),
        range: range.to_string(),
    };

    match dpt.main {
        1 => {
            let (false_label, true_label) = bool_labels(dpt.sub);
            let value = parse_bool(raw, dpt.sub)
                .ok_or_else(|| invalid(&bool_accepted(false_label, true_label)))?;
            Ok(TypedValue::Bool {
                value,
                label: if value { true_label } else { false_label },
            })
        }
        5 => match dpt.sub {
            Some(1) => {
                let p = parse_percent(raw)
                    .ok_or_else(|| invalid("a percentage like `75%` or a number 0-100"))?;
                if !(0.0..=100.0).contains(&p) {
                    return Err(out_of_range("0-100 %"));
                }
                Ok(TypedValue::Percent(p))
            }
            Some(3) => {
                let v = parse_uint(strip_unit(raw, Some("°")))
                    .ok_or_else(|| invalid("an angle 0-360"))?;
                if v > 360 {
                    return Err(out_of_range("0-360 degrees"));
                }
                Ok(TypedValue::Unsigned {
                    value: v as u32,
                    unit: Some("°"),
                })
            }
            _ => {
                let v = parse_uint(raw).ok_or_else(|| invalid("an integer 0-255"))?;
                if v > 255 {
                    return Err(out_of_range("0-255"));
                }
                Ok(TypedValue::Unsigned {
                    value: v as u32,
                    unit: None,
                })
            }
        },
        6 => {
            let v = parse_int(raw).ok_or_else(|| invalid("a signed integer -128..127"))?;
            if !(-128..=127).contains(&v) {
                return Err(out_of_range("-128..127"));
            }
            Ok(TypedValue::Signed {
                value: v,
                unit: None,
            })
        }
        7 => {
            let v = parse_uint(raw).ok_or_else(|| invalid("an unsigned integer 0-65535"))?;
            if v > 0xffff {
                return Err(out_of_range("0-65535"));
            }
            Ok(TypedValue::Unsigned {
                value: v as u32,
                unit: None,
            })
        }
        8 => {
            let v = parse_int(raw).ok_or_else(|| invalid("a signed integer -32768..32767"))?;
            if !(-32768..=32767).contains(&v) {
                return Err(out_of_range("-32768..32767"));
            }
            Ok(TypedValue::Signed {
                value: v,
                unit: None,
            })
        }
        9 => {
            let unit = float16_unit(dpt.sub);
            let v = parse_float(raw, unit)
                .ok_or_else(|| invalid("a decimal number (optionally with unit)"))?;
            // Confirm the value is representable by DPT 9's coarse encoding.
            if encode_float16(v).is_err() {
                return Err(out_of_range("roughly -671088.64 .. 670433.28"));
            }
            Ok(TypedValue::Float { value: v, unit })
        }
        12 => {
            let v = parse_uint(raw).ok_or_else(|| invalid("an unsigned integer 0-4294967295"))?;
            if v > u32::MAX as u64 {
                return Err(out_of_range("0-4294967295"));
            }
            Ok(TypedValue::Unsigned {
                value: v as u32,
                unit: None,
            })
        }
        13 => {
            let unit = match dpt.sub {
                Some(10) => Some("Wh"),
                Some(13) => Some("kWh"),
                _ => None,
            };
            let v = parse_int_with_unit(raw, unit)
                .ok_or_else(|| invalid("a signed 32-bit integer (optionally with unit)"))?;
            if !(i32::MIN as i64..=i32::MAX as i64).contains(&v) {
                return Err(out_of_range("-2147483648..2147483647"));
            }
            Ok(TypedValue::Signed { value: v, unit })
        }
        14 => {
            let unit = float32_unit(dpt.sub);
            let v = parse_float(raw, unit)
                .ok_or_else(|| invalid("a decimal number (optionally with unit)"))?;
            // Reject NaN/±Inf: they are valid IEEE bit patterns but not sensible
            // values to write, and `encode` refuses them too.
            if !v.is_finite() {
                return Err(out_of_range("a finite decimal number"));
            }
            Ok(TypedValue::Float { value: v, unit })
        }
        17 => {
            let v = parse_scene(raw).ok_or_else(|| invalid("a scene number 0-63"))?;
            if v > 63 {
                return Err(out_of_range("0-63"));
            }
            Ok(TypedValue::Scene(v))
        }
        18 => {
            let lower = raw.to_lowercase();
            let (learn, rest) = match lower.strip_prefix("learn") {
                Some(r) => (true, r.trim()),
                None => (false, lower.as_str()),
            };
            let v = parse_scene(rest)
                .ok_or_else(|| invalid("a scene number 0-63 (optionally prefixed `learn`)"))?;
            if v > 63 {
                return Err(out_of_range("0-63"));
            }
            Ok(TypedValue::SceneControl { learn, scene: v })
        }
        20 if dpt.sub == Some(102) => {
            let mode = parse_hvac_mode(raw).ok_or_else(|| {
                invalid("one of auto, comfort, standby, economy, building-protection")
            })?;
            Ok(TypedValue::HvacMode(mode))
        }
        // Any other 20.x enumeration: bussard models no label set for it, so
        // only the raw enumeration code is accepted (see the decode arm).
        20 => {
            let v: u32 = raw
                .trim()
                .parse()
                .map_err(|_| invalid("an enumeration code 0-255"))?;
            if v > 255 {
                return Err(out_of_range("0-255"));
            }
            Ok(TypedValue::Unsigned {
                value: v,
                unit: None,
            })
        }
        _ => Err(ParseValueError::Unsupported {
            dpt: dpt.to_string(),
        }),
    }
}

/// Parses a boolean from human text, honoring the DPT 1.x subtype's word pair.
fn parse_bool(input: &str, sub: Option<u16>) -> Option<bool> {
    let s = input.trim().to_lowercase();
    // Universal forms first.
    match s.as_str() {
        "on" | "true" | "1" | "yes" => return Some(true),
        "off" | "false" | "0" | "no" => return Some(false),
        _ => {}
    }
    // Subtype-specific words. The `true` word maps to the raw bit 1.
    let (false_word, true_word): (&[&str], &[&str]) = match sub {
        Some(3) => (&["disable"], &["enable"]),
        Some(5) => (&["no-alarm", "no alarm", "noalarm"], &["alarm"]),
        Some(8) => (&["up"], &["down"]),
        Some(9) => (&["open"], &["closed", "close"]),
        Some(10) => (&["stop"], &["start"]),
        _ => (&[], &[]),
    };
    if true_word.contains(&s.as_str()) {
        return Some(true);
    }
    if false_word.contains(&s.as_str()) {
        return Some(false);
    }
    None
}

/// A human description of the accepted words for a 1.x subtype.
fn bool_accepted(false_label: &str, true_label: &str) -> String {
    format!("on/off, true/false, 1/0, or {true_label}/{false_label}")
}

/// Parses a percentage: `75%`, `75 %`, or a bare `0`–`100`.
fn parse_percent(input: &str) -> Option<f32> {
    let s = input.trim().trim_end_matches('%').trim();
    s.parse::<f32>().ok()
}

/// Parses a non-negative integer (rejecting a leading sign).
fn parse_uint(input: &str) -> Option<u64> {
    input.trim().parse::<u64>().ok()
}

/// Parses a signed integer.
fn parse_int(input: &str) -> Option<i64> {
    input.trim().parse::<i64>().ok()
}

/// Parses a signed integer, tolerating a trailing known unit suffix.
fn parse_int_with_unit(input: &str, unit: Option<&str>) -> Option<i64> {
    let s = strip_unit(input.trim(), unit);
    s.trim().parse::<i64>().ok()
}

/// Parses a scene number, tolerating a leading `scene ` word.
fn parse_scene(input: &str) -> Option<u8> {
    let s = input.trim().to_lowercase();
    let s = s.strip_prefix("scene").map(str::trim).unwrap_or(s.as_str());
    s.trim().parse::<u8>().ok()
}

/// Parses a float, tolerating a trailing known unit suffix (`21.5°C` → `21.5`).
fn parse_float(input: &str, unit: Option<&str>) -> Option<f32> {
    let s = strip_unit(input.trim(), unit);
    s.trim().parse::<f32>().ok()
}

/// Strips a trailing unit suffix (case-insensitive) if present; otherwise
/// returns the input unchanged. Also strips a few common bare unit letters so
/// that, e.g., `21.5C` works as well as `21.5°C`.
fn strip_unit<'a>(input: &'a str, unit: Option<&str>) -> &'a str {
    if let Some(u) = unit {
        if let Some(stripped) = strip_suffix_ci(input, u) {
            return stripped;
        }
        // `°C` also matches a bare `C`, `m/s` a bare unit, etc.: try the unit
        // without a leading degree sign.
        if let Some(bare) = u.strip_prefix('°') {
            if let Some(stripped) = strip_suffix_ci(input, bare) {
                return stripped;
            }
        }
    }
    // A lone trailing degree sign (e.g. an angle `45°`) is always tolerated.
    input.strip_suffix('°').unwrap_or(input)
}

/// ASCII-case-insensitive `strip_suffix`.
///
/// Unit suffixes are always ASCII (`C`, `%`, `m/s`, `mA`, …), so comparing on
/// raw bytes with ASCII case folding is sufficient — and, unlike the old
/// `to_lowercase()`-then-slice approach, it can never split a multi-byte UTF-8
/// character. That old version paniced on inputs like `"21.5\u{212A}"` (the
/// Kelvin sign, whose lowercase `k` is one byte shorter than the three-byte
/// original), because it sliced the *original* string by the *lowercased*
/// length, landing mid-character.
fn strip_suffix_ci<'a>(input: &'a str, suffix: &str) -> Option<&'a str> {
    let (ib, sb) = (input.as_bytes(), suffix.as_bytes());
    if ib.len() < sb.len() {
        return None;
    }
    let split = ib.len() - sb.len();
    if ib[split..].eq_ignore_ascii_case(sb) {
        // `split` is a valid char boundary: `suffix` is ASCII, so its bytes only
        // match trailing ASCII bytes of `input`, which are always boundaries.
        Some(&input[..split])
    } else {
        None
    }
}

/// Parses an HVAC operating mode name (DPT 20.102).
fn parse_hvac_mode(input: &str) -> Option<HvacMode> {
    match input
        .trim()
        .to_lowercase()
        .replace(['_', ' '], "-")
        .as_str()
    {
        "auto" | "automatic" => Some(HvacMode::Auto),
        "comfort" => Some(HvacMode::Comfort),
        "standby" => Some(HvacMode::Standby),
        "economy" | "night" | "eco" => Some(HvacMode::Economy),
        "building-protection" | "frost" | "protection" | "frost-protection" => {
            Some(HvacMode::BuildingProtection)
        }
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
            // 5.003 angle: degrees 0..=360 map onto a single raw byte 0..=255,
            // the inverse of the `b * 360 / 255` decode scaling. Encoding is
            // therefore lossy (quantized to ~1.41°/step) but round-trips within
            // one raw step.
            (Some(3), TypedValue::Unsigned { value: v, .. }) => {
                if *v > 360 {
                    return Err(EncodeError::OutOfRange {
                        dpt: dpt.to_string(),
                        value: value.to_string(),
                    });
                }
                Ok(vec![(*v as f32 * 255.0 / 360.0).round() as u8])
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
            // Reject non-finite (NaN/±Inf) on encode: a NaN/Inf write is almost
            // always a typo'd input rather than an intended bus value, and it
            // makes parse->encode->decode round-trips well-defined. Decode stays
            // lenient (any 4 bytes are a valid IEEE float, including NaN/Inf).
            TypedValue::Float { value: v, .. } if v.is_finite() => Ok(v.to_be_bytes().to_vec()),
            TypedValue::Float { value: v, .. } => Err(EncodeError::OutOfRange {
                dpt: dpt.to_string(),
                value: v.to_string(),
            }),
            _ => Err(mismatch()),
        },
        17 => match value {
            TypedValue::Scene(n) if *n <= 63 => Ok(vec![*n & 0x3f]),
            _ => Err(mismatch()),
        },
        18 => match value {
            TypedValue::SceneControl { learn, scene } if *scene <= 63 => {
                let mut b = scene & 0x3f;
                if *learn {
                    b |= 0x80;
                }
                Ok(vec![b])
            }
            _ => Err(mismatch()),
        },
        20 => match value {
            // The HVAC mode is 20.102's label set; refuse to write it under a
            // different 20.x subtype, whose codes mean something else entirely.
            TypedValue::HvacMode(mode) if dpt.sub == Some(102) => {
                let code = match mode {
                    HvacMode::Auto => 0,
                    HvacMode::Comfort => 1,
                    HvacMode::Standby => 2,
                    HvacMode::Economy => 3,
                    HvacMode::BuildingProtection => 4,
                    HvacMode::Unknown(v) => *v,
                };
                Ok(vec![code])
            }
            // A raw enumeration code, for the 20.x subtypes with no label set.
            TypedValue::Unsigned { value: v, .. } if dpt.sub != Some(102) => {
                if *v > 255 {
                    return Err(EncodeError::OutOfRange {
                        dpt: dpt.to_string(),
                        value: value.to_string(),
                    });
                }
                Ok(vec![*v as u8])
            }
            _ => Err(mismatch()),
        },
        19 => match value {
            TypedValue::DateTime(dt) => encode_datetime(dt).map_err(|()| EncodeError::OutOfRange {
                dpt: dpt.to_string(),
                value: value.to_string(),
            }),
            _ => Err(mismatch()),
        },
        232 => match value {
            TypedValue::Rgb { r, g, b } => Ok(vec![*r, *g, *b]),
            _ => Err(mismatch()),
        },
        251 => match value {
            TypedValue::Rgbw(c) => {
                let valid = (u8::from(c.r_valid) << 3)
                    | (u8::from(c.g_valid) << 2)
                    | (u8::from(c.b_valid) << 1)
                    | u8::from(c.w_valid);
                // Octet 4 is reserved and sent as 0.
                Ok(vec![c.r, c.g, c.b, c.w, 0x00, valid])
            }
            _ => Err(mismatch()),
        },
        _ => Err(EncodeError::Unsupported {
            dpt: dpt.to_string(),
        }),
    }
}

/// Encodes a [`DateTime`] into the 8-octet DPT 19.001 payload.
///
/// Rejects field values the wire cannot represent (year outside 1900..=2155,
/// out-of-range month/day/hour/minute/second) so a malformed value never
/// silently truncates into a different date.
fn encode_datetime(dt: &DateTime) -> Result<Vec<u8>, ()> {
    if !(1900..=2155).contains(&dt.year)
        || dt.month > 12
        || dt.day > 31
        || dt.weekday > 7
        || dt.hour > 24
        || dt.minute > 59
        || dt.second > 59
    {
        return Err(());
    }
    let b0 = (dt.year - 1900) as u8;
    let b1 = dt.month & 0x0f;
    let b2 = dt.day & 0x1f;
    let b3 = ((dt.weekday & 0x07) << 5) | (dt.hour & 0x1f);
    let b4 = dt.minute & 0x3f;
    let b5 = dt.second & 0x3f;
    let flags = (u8::from(dt.fault) << 7)
        | (u8::from(dt.working_day) << 6)
        | (u8::from(dt.no_working_day) << 5)
        | (u8::from(dt.no_year) << 4)
        | (u8::from(dt.no_date) << 3)
        | (u8::from(dt.no_weekday) << 2)
        | (u8::from(dt.no_time) << 1)
        | u8::from(dt.summer_time);
    let quality = (u8::from(dt.quality) << 7) | (u8::from(dt.sync_source) << 6);
    Ok(vec![b0, b1, b2, b3, b4, b5, flags, quality])
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

    // ---- parse_value ------------------------------------------------------

    #[test]
    fn parse_bool_universal_and_subtype_words() {
        // Universal on/off/true/false/1/0.
        for (input, expect) in [
            ("on", true),
            ("On", true),
            ("TRUE", true),
            ("1", true),
            ("yes", true),
            ("off", false),
            ("false", false),
            ("0", false),
            ("no", false),
        ] {
            match parse_value(&dpt("1.001"), input).unwrap() {
                TypedValue::Bool { value, .. } => assert_eq!(value, expect, "{input}"),
                other => panic!("expected bool for {input}, got {other:?}"),
            }
        }

        // Subtype words carry the right label.
        assert_eq!(
            parse_value(&dpt("1.008"), "down").unwrap(),
            TypedValue::Bool {
                value: true,
                label: "Down"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.008"), "up").unwrap(),
            TypedValue::Bool {
                value: false,
                label: "Up"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.009"), "closed").unwrap(),
            TypedValue::Bool {
                value: true,
                label: "Closed"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.010"), "start").unwrap(),
            TypedValue::Bool {
                value: true,
                label: "Start"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.003"), "enable").unwrap(),
            TypedValue::Bool {
                value: true,
                label: "Enable"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.005"), "no-alarm").unwrap(),
            TypedValue::Bool {
                value: false,
                label: "No Alarm"
            }
        );
    }

    #[test]
    fn parse_bool_rejects_garbage() {
        let err = parse_value(&dpt("1.001"), "maybe").unwrap_err();
        assert!(matches!(err, ParseValueError::Invalid { .. }));
        // The wrong subtype word does not leak across subtypes.
        assert!(parse_value(&dpt("1.001"), "down").is_err());
    }

    #[test]
    fn parse_percent_forms_and_range() {
        assert_eq!(
            parse_value(&dpt("5.001"), "75%").unwrap(),
            TypedValue::Percent(75.0)
        );
        assert_eq!(
            parse_value(&dpt("5.001"), "0").unwrap(),
            TypedValue::Percent(0.0)
        );
        assert_eq!(
            parse_value(&dpt("5.001"), "100 %").unwrap(),
            TypedValue::Percent(100.0)
        );
        assert!(matches!(
            parse_value(&dpt("5.001"), "150"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        assert!(matches!(
            parse_value(&dpt("5.001"), "abc"),
            Err(ParseValueError::Invalid { .. })
        ));
    }

    #[test]
    fn parse_scaling_and_angle() {
        // 5.x generic scaling byte.
        assert_eq!(
            parse_value(&dpt("5.010"), "200").unwrap(),
            TypedValue::Unsigned {
                value: 200,
                unit: None
            }
        );
        assert!(parse_value(&dpt("5.010"), "300").is_err());
        // 5.003 angle with a stray degree sign.
        assert_eq!(
            parse_value(&dpt("5.003"), "180°").unwrap(),
            TypedValue::Unsigned {
                value: 180,
                unit: Some("°")
            }
        );
    }

    #[test]
    fn parse_signed_and_unsigned_ints() {
        assert_eq!(
            parse_value(&dpt("6.010"), "-5").unwrap(),
            TypedValue::Signed {
                value: -5,
                unit: None
            }
        );
        assert!(parse_value(&dpt("6.010"), "200").is_err());
        assert_eq!(
            parse_value(&dpt("7.001"), "1000").unwrap(),
            TypedValue::Unsigned {
                value: 1000,
                unit: None
            }
        );
        assert!(parse_value(&dpt("7.001"), "70000").is_err());
        assert_eq!(
            parse_value(&dpt("8.001"), "-1000").unwrap(),
            TypedValue::Signed {
                value: -1000,
                unit: None
            }
        );
        assert_eq!(
            parse_value(&dpt("12.001"), "4000000000").unwrap(),
            TypedValue::Unsigned {
                value: 4_000_000_000,
                unit: None
            }
        );
    }

    #[test]
    fn parse_float_with_unit_suffix() {
        // Bare decimal.
        assert_eq!(
            parse_value(&dpt("9.001"), "21.5").unwrap(),
            TypedValue::Float {
                value: 21.5,
                unit: Some("°C")
            }
        );
        // With the exact unit suffix.
        assert_eq!(
            parse_value(&dpt("9.001"), "21.5°C").unwrap(),
            TypedValue::Float {
                value: 21.5,
                unit: Some("°C")
            }
        );
        // With the bare unit letter.
        assert_eq!(
            parse_value(&dpt("9.001"), "21.5C").unwrap(),
            TypedValue::Float {
                value: 21.5,
                unit: Some("°C")
            }
        );
        // IEEE float (14.x).
        match parse_value(&dpt("14.056"), "1500 W").unwrap() {
            TypedValue::Float { value, unit } => {
                assert!((value - 1500.0).abs() < 0.001);
                assert_eq!(unit, Some("W"));
            }
            other => panic!("expected float, got {other:?}"),
        }
        assert!(parse_value(&dpt("9.001"), "hot").is_err());
    }

    #[test]
    fn parse_energy_with_unit() {
        assert_eq!(
            parse_value(&dpt("13.013"), "10 kWh").unwrap(),
            TypedValue::Signed {
                value: 10,
                unit: Some("kWh")
            }
        );
    }

    #[test]
    fn parse_scene_and_scene_control() {
        assert_eq!(
            parse_value(&dpt("17.001"), "5").unwrap(),
            TypedValue::Scene(5)
        );
        assert_eq!(
            parse_value(&dpt("17.001"), "scene 5").unwrap(),
            TypedValue::Scene(5)
        );
        assert!(parse_value(&dpt("17.001"), "64").is_err());
        assert_eq!(
            parse_value(&dpt("18.001"), "3").unwrap(),
            TypedValue::SceneControl {
                learn: false,
                scene: 3
            }
        );
        assert_eq!(
            parse_value(&dpt("18.001"), "learn 3").unwrap(),
            TypedValue::SceneControl {
                learn: true,
                scene: 3
            }
        );
    }

    /// Regression: every DPT 20.x used to decode/parse/encode as the 20.102
    /// HVAC operating mode, so e.g. 20.105 (HVAC controller mode) value 1
    /// rendered as "Comfort". Only 20.102 carries that label set; other
    /// subtypes fall back to the raw enumeration code.
    #[test]
    fn test_decode_dpt20_non_102_is_not_hvac_mode() {
        // 20.102 keeps the HVAC labels.
        assert_eq!(
            decode(&dpt("20.102"), &[1]),
            TypedValue::HvacMode(HvacMode::Comfort)
        );
        // 20.105 value 1 is "Heat" in its own enumeration, definitely not
        // "Comfort"; bussard models no labels for it, so it stays a raw code.
        assert_eq!(
            decode(&dpt("20.105"), &[1]),
            TypedValue::Unsigned {
                value: 1,
                unit: None
            }
        );
        // A bare `20` with no subtype is equally unidentified.
        assert_eq!(
            decode(&dpt("20"), &[3]),
            TypedValue::Unsigned {
                value: 3,
                unit: None
            }
        );
    }

    #[test]
    fn test_parse_value_dpt20_non_102_takes_raw_code() -> Result<(), ParseValueError> {
        assert_eq!(
            parse_value(&dpt("20.105"), "1")?,
            TypedValue::Unsigned {
                value: 1,
                unit: None
            }
        );
        // The HVAC words are 20.102's, not a generic 20.x vocabulary.
        assert!(parse_value(&dpt("20.105"), "comfort").is_err());
        assert!(parse_value(&dpt("20.105"), "256").is_err());
        Ok(())
    }

    #[test]
    fn test_encode_dpt20_non_102_rejects_hvac_mode() -> Result<(), EncodeError> {
        assert_eq!(
            encode(
                &dpt("20.105"),
                &TypedValue::Unsigned {
                    value: 1,
                    unit: None
                }
            )?,
            vec![1u8]
        );
        // Writing an HVAC mode under a non-HVAC 20.x subtype is a mistake.
        assert!(matches!(
            encode(&dpt("20.105"), &TypedValue::HvacMode(HvacMode::Comfort)),
            Err(EncodeError::Mismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn parse_hvac_modes() {
        assert_eq!(
            parse_value(&dpt("20.102"), "comfort").unwrap(),
            TypedValue::HvacMode(HvacMode::Comfort)
        );
        assert_eq!(
            parse_value(&dpt("20.102"), "building-protection").unwrap(),
            TypedValue::HvacMode(HvacMode::BuildingProtection)
        );
        assert_eq!(
            parse_value(&dpt("20.102"), "Frost").unwrap(),
            TypedValue::HvacMode(HvacMode::BuildingProtection)
        );
        assert!(parse_value(&dpt("20.102"), "tropical").is_err());
    }

    #[test]
    fn parse_unsupported_dpt() {
        assert!(matches!(
            parse_value(&dpt("250.001"), "1"),
            Err(ParseValueError::Unsupported { .. })
        ));
    }

    #[test]
    fn parse_9x_large_magnitude_is_out_of_range_not_panic() {
        // Huge finite and infinite inputs must return a clean OutOfRange rather
        // than overflowing inside encode_float16's range check.
        for input in ["1e9", "inf", "-1e9", "21474836.48", "1e30", "nan"] {
            assert!(
                matches!(
                    parse_value(&dpt("9.001"), input),
                    Err(ParseValueError::OutOfRange { .. })
                ),
                "9.001 {input:?} should be OutOfRange"
            );
        }
    }

    #[test]
    fn encode_float16_rejects_non_finite_and_out_of_range() {
        assert!(encode_float16(f32::NAN).is_err());
        assert!(encode_float16(f32::INFINITY).is_err());
        assert!(encode_float16(f32::NEG_INFINITY).is_err());
        assert!(encode_float16(FLOAT16_MAX * 2.0).is_err());
        assert!(encode_float16(FLOAT16_MIN * 2.0).is_err());
        // The extremes themselves are representable.
        assert!(encode_float16(FLOAT16_MAX).is_ok());
        assert!(encode_float16(FLOAT16_MIN).is_ok());
    }

    #[test]
    fn dpt14_rejects_non_finite_on_parse_and_encode() {
        for input in ["nan", "inf", "-inf"] {
            assert!(
                matches!(
                    parse_value(&dpt("14.056"), input),
                    Err(ParseValueError::OutOfRange { .. })
                ),
                "14.056 {input:?} should be OutOfRange"
            );
        }
        // A directly-constructed NaN/Inf float is rejected by encode.
        let nan = TypedValue::Float {
            value: f32::NAN,
            unit: None,
        };
        assert!(matches!(
            encode(&dpt("14.056"), &nan),
            Err(EncodeError::OutOfRange { .. })
        ));
        // Decode stays lenient: a NaN bit pattern still decodes to a Float.
        assert!(matches!(
            decode(&dpt("14.056"), &[0x7f, 0xc0, 0x00, 0x00]),
            TypedValue::Float { .. }
        ));
    }

    #[test]
    fn dpt5003_angle_encode_scaling_and_roundtrip() {
        // Angles above 255 now encode (previously Mismatch).
        let v = parse_value(&dpt("5.003"), "360").unwrap();
        assert_eq!(encode(&dpt("5.003"), &v).unwrap(), vec![255]);
        assert_eq!(
            encode(&dpt("5.003"), &parse_value(&dpt("5.003"), "0").unwrap()).unwrap(),
            vec![0]
        );
        assert_eq!(
            encode(&dpt("5.003"), &parse_value(&dpt("5.003"), "180").unwrap()).unwrap(),
            vec![128]
        );
        // Out of range still rejected.
        assert!(matches!(
            encode(
                &dpt("5.003"),
                &TypedValue::Unsigned {
                    value: 361,
                    unit: Some("°")
                }
            ),
            Err(EncodeError::OutOfRange { .. })
        ));
        // Round-trip within one raw step: decode(encode(v)) stays close, and
        // encode(decode(x)) is stable.
        for raw in [0u8, 1, 90, 128, 200, 255] {
            if let TypedValue::Unsigned { value: deg, .. } = decode(&dpt("5.003"), &[raw]) {
                let back = encode(
                    &dpt("5.003"),
                    &TypedValue::Unsigned {
                        value: deg,
                        unit: Some("°"),
                    },
                )
                .unwrap();
                assert!(
                    (back[0] as i16 - raw as i16).abs() <= 1,
                    "raw {raw} -> {deg}° -> {}",
                    back[0]
                );
            } else {
                panic!("expected unsigned angle");
            }
        }
    }

    #[test]
    fn strip_suffix_ci_handles_non_ascii_input_without_panic() {
        // U+212A KELVIN SIGN lowercases to a 1-byte 'k' (shorter than its 3-byte
        // original), which used to make the old slice-by-lowercased-length code
        // panic. It must simply not match the ASCII "°C" suffix now.
        let kelvin = "21.5\u{212A}";
        assert_eq!(strip_suffix_ci(kelvin, "C"), None);
        assert_eq!(strip_suffix_ci(kelvin, "°C"), None);
        // parse_value must not panic on it either.
        assert!(parse_value(&dpt("9.001"), kelvin).is_err());
        // Normal ASCII suffix stripping still works, case-insensitively.
        assert_eq!(strip_suffix_ci("21.5c", "C"), Some("21.5"));
        assert_eq!(strip_suffix_ci("1500W", "w"), Some("1500"));
    }

    #[test]
    fn dpt9_invalid_sentinel_decodes_to_raw() {
        // 0x7FFF is the DPT 9 "invalid data" sentinel: surface it as Raw, not a
        // bogus ~670760 float.
        assert_eq!(
            decode(&dpt("9.001"), &[0x7F, 0xFF]),
            TypedValue::Raw(vec![0x7F, 0xFF])
        );
        // A neighbouring value is still a normal float.
        assert!(matches!(
            decode(&dpt("9.001"), &[0x7F, 0xFE]),
            TypedValue::Float { .. }
        ));
    }

    #[test]
    fn dpt9_real_max_encodes_and_is_not_the_invalid_sentinel() {
        // Per KNX 03/07/02, DPT 9's valid max is 670433.28 (M=2046, E=15). It
        // must encode successfully and must NOT collide with the 0x7FFF
        // "invalid data" marker.
        let bytes = encode_float16(FLOAT16_MAX).expect("real max is representable");
        assert_ne!(
            bytes,
            [0x7F, 0xFF],
            "max must not encode to the invalid marker"
        );
        // Raw is M=2046, E=15, sign=0: (15<<11)|2046 = 0x7FFE.
        assert_eq!(bytes, [0x7F, 0xFE]);
        // Decoding it back yields ~670433.28.
        let back = decode_float16(bytes[0], bytes[1]);
        assert!((back - 670433.28).abs() <= 1.0, "got {back}");
    }

    #[test]
    fn dpt9_between_real_max_and_raw_ceiling_is_out_of_range() {
        // Values in the gap (670433.29 .. 670760.96) used to round up onto
        // 0x7FFF (the invalid marker). They must now be rejected as OutOfRange
        // rather than silently becoming "invalid data".
        for v in [670450.0_f32, 670500.0, 670597.0, 670760.0] {
            assert!(
                encode_float16(v).is_err(),
                "{v} sits above the real DPT 9 max and must be rejected"
            );
            assert!(
                matches!(
                    parse_value(&dpt("9.001"), &v.to_string()),
                    Err(ParseValueError::OutOfRange { .. })
                ),
                "parse {v} should be OutOfRange"
            );
        }
        // Just above the real max via the encode() surface too.
        let v = TypedValue::Float {
            value: 670500.0,
            unit: Some("°C"),
        };
        assert!(matches!(
            encode(&dpt("9.001"), &v),
            Err(EncodeError::OutOfRange { .. })
        ));
    }

    #[test]
    fn dpt19_datetime_reference_vector() {
        // Reference vector per KNX 03/07/02 DPT 19.001 layout:
        // 2019-01-30 (Wed) 08:30:45, no flags, quality clear.
        //   year 2019 -> 119 (0x77), month 1, day 30, weekday Wed=3,
        //   hour 8 -> b3 = (3<<5)|8 = 0x68, min 30 (0x1E), sec 45 (0x2D).
        let payload = [0x77, 0x01, 0x1E, 0x68, 0x1E, 0x2D, 0x00, 0x00];
        let decoded = decode(&dpt("19.001"), &payload);
        let dt = match decoded {
            TypedValue::DateTime(dt) => dt,
            other => panic!("expected DateTime, got {other:?}"),
        };
        assert_eq!(dt.year, 2019);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 30);
        assert_eq!(dt.weekday, 3);
        assert_eq!(dt.hour, 8);
        assert_eq!(dt.minute, 30);
        assert_eq!(dt.second, 45);
        assert!(!dt.fault && !dt.no_time && !dt.no_date && !dt.summer_time);
        // Round-trips byte-for-byte.
        assert_eq!(encode(&dpt("19.001"), &decoded).unwrap(), payload);
        // Display shows both date and time with the weekday.
        assert_eq!(dt.to_string(), "2019-01-30 Wed 08:30:45");
    }

    #[test]
    fn dpt19_datetime_flags_roundtrip() {
        // Fault + summer time + working day set, quality + sync set.
        let payload = [0x7D, 0x0C, 0x19, 0xB0, 0x3B, 0x3B, 0xC1, 0xC0];
        let decoded = decode(&dpt("19.001"), &payload);
        let dt = match decoded {
            TypedValue::DateTime(dt) => dt,
            other => panic!("expected DateTime, got {other:?}"),
        };
        assert!(dt.fault, "F bit");
        assert!(dt.working_day, "WD bit");
        assert!(dt.summer_time, "SUTI bit");
        assert!(dt.quality, "quality bit");
        assert!(dt.sync_source, "sync-source bit");
        assert_eq!(dt.weekday, 5);
        assert_eq!(dt.hour, 16);
        assert_eq!(dt.year, 2025);
        assert_eq!(dt.month, 12);
        assert_eq!(dt.day, 25);
        // Byte-exact round-trip.
        assert_eq!(encode(&dpt("19.001"), &decoded).unwrap(), payload);
    }

    #[test]
    fn dpt19_encode_rejects_out_of_range_fields() {
        let bad = TypedValue::DateTime(DateTime {
            year: 1899, // below 1900
            month: 1,
            day: 1,
            weekday: 0,
            hour: 0,
            minute: 0,
            second: 0,
            fault: false,
            working_day: false,
            no_working_day: false,
            no_year: false,
            no_date: false,
            no_weekday: false,
            no_time: false,
            summer_time: false,
            quality: false,
            sync_source: false,
        });
        assert!(matches!(
            encode(&dpt("19.001"), &bad),
            Err(EncodeError::OutOfRange { .. })
        ));
    }

    #[test]
    fn dpt19_short_payload_falls_back_to_raw() {
        assert_eq!(
            decode(&dpt("19.001"), &[0x77, 0x01, 0x1E]),
            TypedValue::Raw(vec![0x77, 0x01, 0x1E])
        );
    }

    #[test]
    fn dpt251_rgbw_reference_vector() {
        // R=0x11 G=0x22 B=0x33 W=0x44, reserved=0x00, validity=0x0F (all valid).
        let payload = [0x11, 0x22, 0x33, 0x44, 0x00, 0x0F];
        let decoded = decode(&dpt("251.600"), &payload);
        let c = match decoded {
            TypedValue::Rgbw(c) => c,
            other => panic!("expected Rgbw, got {other:?}"),
        };
        assert_eq!((c.r, c.g, c.b, c.w), (0x11, 0x22, 0x33, 0x44));
        assert!(c.r_valid && c.g_valid && c.b_valid && c.w_valid);
        assert_eq!(encode(&dpt("251.600"), &decoded).unwrap(), payload);
        assert_eq!(c.to_string(), "RGBW(11,22,33,44)");
    }

    #[test]
    fn dpt251_rgbw_partial_validity() {
        // Only red and white valid: validity nibble = bit3|bit0 = 0x09.
        let payload = [0xFF, 0x00, 0x00, 0x80, 0x00, 0x09];
        let decoded = decode(&dpt("251.600"), &payload);
        let c = match decoded {
            TypedValue::Rgbw(c) => c,
            other => panic!("expected Rgbw, got {other:?}"),
        };
        assert!(c.r_valid && !c.g_valid && !c.b_valid && c.w_valid);
        // Invalid channels render as `--`.
        assert_eq!(c.to_string(), "RGBW(FF,--,--,80)");
        // Round-trips byte-for-byte (reserved octet preserved as 0).
        assert_eq!(encode(&dpt("251.600"), &decoded).unwrap(), payload);
    }

    #[test]
    fn dpt251_short_payload_falls_back_to_raw() {
        assert_eq!(
            decode(&dpt("251.600"), &[0x11, 0x22, 0x33]),
            TypedValue::Raw(vec![0x11, 0x22, 0x33])
        );
    }

    #[test]
    fn parse_encode_decode_roundtrip() {
        // parse -> encode -> decode should land back at (approximately) the same
        // value for a spread of DPTs.
        let cases: &[(&str, &str)] = &[
            ("1.001", "on"),
            ("1.008", "down"),
            ("5.001", "50%"),
            ("5.010", "200"),
            ("6.010", "-5"),
            ("7.001", "1000"),
            ("8.001", "-1000"),
            ("9.001", "21.5"),
            ("12.001", "70000"),
            ("13.013", "12345"),
            ("14.056", "1500"),
            ("17.001", "7"),
            ("18.001", "learn 9"),
            ("20.102", "comfort"),
        ];
        for (d, input) in cases {
            let dpt = dpt(d);
            let parsed =
                parse_value(&dpt, input).unwrap_or_else(|e| panic!("parse {input} as {d}: {e}"));
            let bytes =
                encode(&dpt, &parsed).unwrap_or_else(|e| panic!("encode {input} as {d}: {e}"));
            let back = decode(&dpt, &bytes);
            match (&parsed, &back) {
                (TypedValue::Float { value: a, .. }, TypedValue::Float { value: b, .. }) => {
                    let tol = 0.1_f32.max(a.abs() * 0.01);
                    assert!((a - b).abs() <= tol, "{d} {input}: {a} != {b}");
                }
                (TypedValue::Percent(a), TypedValue::Percent(b)) => {
                    assert!((a - b).abs() <= 0.5, "{d} {input}: {a} != {b}");
                }
                _ => assert_eq!(&parsed, &back, "{d} {input} roundtrip"),
            }
        }
    }
}
