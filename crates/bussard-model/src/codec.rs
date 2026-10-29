//! DPT value codecs: decoding raw group-value payloads into typed values.
//!
//! [`decode`] turns a `(Dpt, payload)` pair into a [`TypedValue`]; [`encode`]
//! does the reverse for the subset of DPTs where encoding is straightforward.
//! Anything unknown or malformed falls back to [`TypedValue::Raw`] on decode.

use std::fmt;

use crate::dpt::Dpt;
use crate::dpt_tables::{
    enum_code, enum_label, enum_table, flag_reserved_mask, flag_table, fold_word,
};

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
    /// A 1-bit controlled value (DPT 2.xxx, 03_07_02 §3.2): the control bit
    /// forces the value, without it the sender releases control.
    Control {
        /// `true` = control (the value is forced), `false` = no control.
        control: bool,
        /// The value bit, read like the matching 1.xxx sub-type.
        value: bool,
        /// Label of `value` under the matching 1.xxx sub-type.
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
    /// An exact fixed-point value: `count` steps of `10^-decimals` in `unit`.
    ///
    /// Used for the 7.x, 8.x and 13.x sub-types whose resolution is not 1
    /// (8.010 percent in 0.01 %, 7.003/7.004 and 8.003/8.004 time periods in
    /// 10 ms / 100 ms, 13.002 flow rate in 0.0001 m³/h). The wire carries the
    /// integer `count`; keeping it integral avoids float rounding on the
    /// 32-bit 13.002 range.
    Scaled {
        /// The raw count as it travels on the bus.
        count: i64,
        /// Number of decimal places one count represents (`2` = 0.01).
        decimals: u8,
        /// Unit label of the scaled value (e.g. `"%"`, `"s"`).
        unit: &'static str,
    },
    /// A control-dimming or control-blinds step (DPT 3.007 / 3.008).
    Step {
        /// Direction bit label (e.g. `"Increase"`/`"Decrease"`, `"Up"`/`"Down"`).
        direction: &'static str,
        /// The 3-bit step code: 0 = break, 1..=7 divide the 0..100 % range
        /// into `2^(code-1)` intervals (03_07_02 §3.3), so code 1 is one
        /// 100 % step and code 7 is 64 steps of 1.5625 %.
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
    /// A scene number (DPT 17.001): the transmitted field `0..=63`.
    ///
    /// Displayed and parsed counted from 1, the way ETS and Home Assistant
    /// number scenes (03_07_02 §3.19 NOTE 9): field 2 is `scene 3 (raw 2)`.
    Scene(u8),
    /// A scene control (DPT 18.001): activate or learn a scene.
    SceneControl {
        /// `true` = learn the scene, `false` = activate it.
        learn: bool,
        /// The transmitted scene field `0..=63`; displayed as `scene + 1`.
        scene: u8,
    },
    /// An HVAC operating mode (DPT 20.102).
    HvacMode(HvacMode),
    /// A value of a 20.xxx enumeration other than 20.102 (03_07_02 §3.21,
    /// §4.3, §6.3): the code and its label, `None` for a reserved code.
    Enum {
        /// The enumeration code on the wire.
        code: u8,
        /// The label of the code, `None` when the code is reserved.
        label: Option<&'static str>,
    },
    /// A bit set (DPT 21.xxx, 22.xxx) or a status-with-mode octet (6.020),
    /// shown as the names that apply.
    Flags {
        /// The raw bits (the low octet for an 8-bit set).
        bits: u16,
        /// The names of the set bits, in bit order; for 6.020 one entry per
        /// field.
        names: Vec<&'static str>,
    },
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
            TypedValue::Control { control, label, .. } => {
                if *control {
                    write!(f, "Control: {label}")
                } else {
                    write!(f, "No control")
                }
            }
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
            TypedValue::Scaled {
                count,
                decimals,
                unit,
            } => write!(f, "{} {unit}", format_fixed(*count, *decimals)),
            TypedValue::Step { direction, step } => match step_percent(*step) {
                Some(pct) => write!(f, "{direction} {pct} %"),
                None => write!(f, "{direction} break"),
            },
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
            // Scene numbers count from 1 on screen and the transmitted field
            // from 0 (03_07_02 §3.19 NOTE 9); show both.
            TypedValue::Scene(n) => write!(f, "scene {} (raw {n})", u16::from(*n) + 1),
            TypedValue::SceneControl { learn, scene } => {
                let verb = if *learn { "learn" } else { "activate" };
                write!(f, "{verb} scene {} (raw {scene})", u16::from(*scene) + 1)
            }
            TypedValue::HvacMode(m) => write!(f, "{m}"),
            TypedValue::Enum { code, label } => match label {
                Some(l) => write!(f, "{l}"),
                None => write!(f, "Unknown({code})"),
            },
            TypedValue::Flags { names, .. } => {
                if names.is_empty() {
                    write!(f, "none")
                } else {
                    write!(f, "{}", names.join(", "))
                }
            }
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

impl TypedValue {
    /// The scaled value of a [`TypedValue::Scaled`] as a float, `None` for
    /// every other variant.
    pub fn scaled_f64(&self) -> Option<f64> {
        match self {
            TypedValue::Scaled {
                count, decimals, ..
            } => Some(*count as f64 / 10f64.powi(i32::from(*decimals))),
            _ => None,
        }
    }
}

/// The size of one step of a 3.007/3.008 step code, in percent of the full
/// range: `100 / 2^(code-1)` (03_07_02 §3.3). `None` for code 0 (break) and
/// for codes above 7, which the 3-bit field cannot carry.
fn step_percent(code: u8) -> Option<f64> {
    (1..=7)
        .contains(&code)
        .then(|| 100.0 / f64::from(1u32 << (code - 1)))
}

/// The `(bit 0, bit 1)` direction labels of a DPT 3.x sub-type: 3.008 is
/// `Up`/`Down`, every other 3.x reads as 3.007 `Decrease`/`Increase`.
fn step_labels(sub: Option<u16>) -> (&'static str, &'static str) {
    match sub {
        Some(8) => ("Up", "Down"),
        _ => ("Decrease", "Increase"),
    }
}

/// Parses a 3.007/3.008 step: a direction word, then an optional amount.
///
/// Directions: `increase`/`decrease`, `up`/`down` (3.007 reads `up` as
/// increase, `dim up`/`dim down` too; 3.008 has `up` = bit 0, `down` = bit 1).
/// Amounts: a step size in percent that is one of 100, 50, 25, 12.5, 6.25,
/// 3.125 and 1.5625 (`25%`), a bare step code `0`-`7` (`3`, `step 3`), or
/// `break`/`stop`. No amount means code 1, one step over the whole range.
/// A bare `break`/`stop` is code 0 with the bit-0 direction.
fn parse_step(input: &str, sub: Option<u16>) -> Option<(bool, u8)> {
    let lower = input.trim().to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let (dir_words, rest): (usize, Option<bool>) = match words.as_slice() {
        ["dim", "up" | "brighter", ..] => (2, Some(true)),
        ["dim", "down" | "darker", ..] => (2, Some(false)),
        ["increase" | "brighter", ..] => (1, Some(true)),
        ["decrease" | "darker", ..] => (1, Some(false)),
        // 3.008: Up is bit 0, Down bit 1; on 3.007 `up` means brighter.
        ["up", ..] => (1, Some(sub != Some(8))),
        ["down", ..] => (1, Some(sub == Some(8))),
        ["break" | "stop"] => return Some((false, 0)),
        _ => (0, None),
    };
    let up = rest?;
    let amount: Vec<&str> = words[dir_words..]
        .iter()
        .copied()
        .filter(|w| *w != "step")
        .collect();
    let code = match amount.as_slice() {
        [] => 1,
        ["break" | "stop"] => 0,
        [one] => parse_step_amount(one)?,
        [n, "%"] => parse_step_amount(&format!("{n}%"))?,
        _ => return None,
    };
    Some((up, code))
}

/// A step amount: `25%` (a step size) or a bare code `0`-`7`.
fn parse_step_amount(word: &str) -> Option<u8> {
    if let Some(p) = word.strip_suffix('%') {
        let p: f64 = p.trim().parse().ok()?;
        return (1..=7u8).find(|c| step_percent(*c).is_some_and(|s| (s - p).abs() < 1e-6));
    }
    word.parse::<u8>().ok().filter(|c| *c <= 7)
}

/// Renders `count * 10^-decimals` exactly, e.g. `(5000, 2)` as `50.00`.
fn format_fixed(count: i64, decimals: u8) -> String {
    let sign = if count < 0 { "-" } else { "" };
    let abs = count.unsigned_abs();
    if decimals == 0 {
        return format!("{sign}{abs}");
    }
    let div = 10u64.pow(u32::from(decimals));
    let width = usize::from(decimals);
    format!("{sign}{}.{:0width$}", abs / div, abs % div)
}

/// Fixed-point scaling of a 7.x, 8.x or 13.x sub-type whose resolution is not
/// one count.
#[derive(Debug, Clone, Copy)]
struct Scaling {
    /// Decimal places one count represents.
    decimals: u8,
    /// Unit of the scaled value.
    unit: &'static str,
    /// A raw count the standard reserves for "invalid data".
    invalid: Option<i64>,
}

/// The scaling of `dpt`, if its resolution is not one count.
///
/// KNX 03_07_02 Datapoint Types v02.02.01: §3.8.2 (7.003 counts 10 ms, 7.004
/// counts 100 ms), §3.9.1 (8.010 `DPT_Percent_V16` counts 0.01 % and reserves
/// 7FFFh for invalid data), §3.9.2 (8.003 / 8.004 count 10 ms / 100 ms),
/// §3.14.1 (13.002 `DPT_FlowRate_m3/h` counts 0.0001 m³/h). Every other
/// sub-type in §3.8, §3.9, §3.13 and §3.14 has a resolution of one unit.
/// Time periods are shown in seconds, the spec's "Range" column unit.
fn scaling(dpt: &Dpt) -> Option<Scaling> {
    let (decimals, unit, invalid) = match (dpt.main, dpt.sub?) {
        (7, 3) | (8, 3) => (2, "s", None),
        (7, 4) | (8, 4) => (1, "s", None),
        (8, 10) => (2, "%", Some(0x7FFF)),
        (13, 2) => (4, "m³/h", None),
        _ => return None,
    };
    Some(Scaling {
        decimals,
        unit,
        invalid,
    })
}

/// The raw count range of the integer families that carry a [`Scaling`].
fn count_range(main: u16) -> Option<(i64, i64)> {
    match main {
        7 => Some((0, i64::from(u16::MAX))),
        8 => Some((i64::from(i16::MIN), i64::from(i16::MAX))),
        13 => Some((i64::from(i32::MIN), i64::from(i32::MAX))),
        _ => None,
    }
}

/// The writable count range of a scaled DPT: the family's range minus the
/// invalid marker when it sits on an end of the range.
fn writable_range(main: u16, sc: Scaling) -> Option<(i64, i64)> {
    let (lo, mut hi) = count_range(main)?;
    if sc.invalid == Some(hi) {
        hi -= 1;
    }
    Some((lo, hi))
}

/// Why [`parse_fixed`] refused its input.
#[derive(Debug, PartialEq, Eq)]
enum FixedError {
    /// Not a decimal number.
    Syntax,
    /// More significant decimal places than the resolution.
    Precision,
    /// Does not fit an `i64` count.
    Overflow,
}

/// Parses an exact decimal (`-1.25`, `50`, `+0.5`) into a count of
/// `10^-decimals` steps, refusing digits finer than one step rather than
/// rounding them away.
fn parse_fixed(input: &str, decimals: u8) -> Result<i64, FixedError> {
    let s = input.trim();
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (int, frac) = digits.split_once('.').unwrap_or((digits, ""));
    let all_digits = |t: &str| t.bytes().all(|b| b.is_ascii_digit());
    if (int.is_empty() && frac.is_empty()) || !all_digits(int) || !all_digits(frac) {
        return Err(FixedError::Syntax);
    }
    let d = usize::from(decimals);
    let (kept, dropped) = frac.split_at(frac.len().min(d));
    if dropped.bytes().any(|b| b != b'0') {
        return Err(FixedError::Precision);
    }
    let padding = std::iter::repeat_n(b'0', d - kept.len());
    let mut count: i64 = 0;
    for b in int.bytes().chain(kept.bytes()).chain(padding) {
        count = count
            .checked_mul(10)
            .and_then(|c| c.checked_add(i64::from(b - b'0')))
            .ok_or(FixedError::Overflow)?;
    }
    Ok(if neg { -count } else { count })
}

/// Parses human input for a scaled DPT into its raw count.
///
/// Accepts the scaled value with or without its unit (`50`, `50 %`, `1.5 s`,
/// `1.5s`); time periods also take milliseconds (`1500 ms`). A bare number is
/// in the scaled unit, never a raw count.
fn parse_scaled(input: &str, sc: Scaling) -> Result<i64, FixedError> {
    let s = input.trim();
    if sc.unit == "s"
        && let Some(ms) = strip_suffix_ci(s, "ms")
    {
        // One count is 10 ms (2 decimals) or 100 ms (1 decimal) here.
        let ms = parse_fixed(ms, 0)?;
        let per_count = 10i64.pow(3 - u32::from(sc.decimals));
        if ms % per_count != 0 {
            return Err(FixedError::Precision);
        }
        return Ok(ms / per_count);
    }
    let units: &[&str] = match sc.unit {
        "m³/h" => &["m³/h", "m3/h"],
        other => &[other],
    };
    let bare = units
        .iter()
        .find_map(|u| strip_suffix_ci(s, u))
        .unwrap_or(s);
    parse_fixed(bare, sc.decimals)
}

/// Returns the `(false_label, true_label)` for a DPT 1.x subtype.
///
/// The word pairs of KNX 03_07_02 Datapoint Types v02.02.01 §3.1 (1.001 to
/// 1.024) and 1.100 `DPT_Heat/Cool` from the §4 HVAC types. Note the pairs that
/// run opposite ways: 1.009 is 0 = open, 1 = close, while 1.019 is 0 = closed,
/// 1 = open. An unknown sub-type shows the bit.
fn bool_labels(sub: Option<u16>) -> (&'static str, &'static str) {
    match sub {
        Some(1) => ("Off", "On"),
        Some(2) => ("False", "True"),
        Some(3) => ("Disable", "Enable"),
        Some(4) => ("No ramp", "Ramp"),
        Some(5) => ("No Alarm", "Alarm"),
        Some(6) => ("Low", "High"),
        Some(7) => ("Decrease", "Increase"),
        Some(8) => ("Up", "Down"),
        Some(9) => ("Open", "Close"),
        Some(10) => ("Stop", "Start"),
        Some(11) => ("Inactive", "Active"),
        Some(12) => ("Not inverted", "Inverted"),
        Some(13) => ("Start/stop", "Cyclically"),
        Some(14) => ("Fixed", "Calculated"),
        Some(15) => ("No action", "Reset"),
        Some(16) => ("No action", "Acknowledge"),
        // 1.017: both values trigger and shall not be told apart (§3.1
        // footnote 1); the bit is shown so a capture still reads exactly.
        Some(17) => ("Trigger (raw 0)", "Trigger (raw 1)"),
        Some(18) => ("Not occupied", "Occupied"),
        Some(19) => ("Closed", "Open"),
        Some(21) => ("OR", "AND"),
        // 1.022 DPT_Scene_AB: shown as scenes 1 and 2 (03_07_02 §3.1
        // footnote 2), with the transmitted bit next to it.
        Some(22) => ("scene 1 (raw 0)", "scene 2 (raw 1)"),
        Some(23) => ("Up/Down only (shutter)", "Up/Down + Step/Stop (blind)"),
        Some(24) => ("Day", "Night"),
        Some(100) => ("Cooling", "Heating"),
        _ => ("0", "1"),
    }
}

/// The extra words [`parse_bool`] accepts for a DPT 1.x subtype, beside the
/// lowercased labels of [`bool_labels`]: `(words for 0, words for 1)`.
fn bool_aliases(sub: Option<u16>) -> (&'static [&'static str], &'static [&'static str]) {
    match sub {
        Some(5) => (&["no-alarm", "noalarm"], &[]),
        Some(9) => (&[], &["closed"]),
        Some(12) => (&["normal"], &[]),
        Some(13) => (&["start-stop", "start stop"], &["cyclic"]),
        Some(15) => (&["none"], &[]),
        Some(16) => (&["none"], &["ack"]),
        Some(17) => (&[], &["trigger"]),
        Some(18) => (&["unoccupied", "not-occupied", "vacant"], &[]),
        Some(19) => (&["close"], &[]),
        Some(21) => (&["or"], &["and"]),
        Some(23) => (&["shutter"], &["blind", "blinds"]),
        Some(100) => (&["cool", "cooling"], &["heat", "heating"]),
        _ => (&[], &[]),
    }
}

/// The unit of an integer sub-type of DPT 5, 6, 7, 8, 12 or 13, `None` when
/// the sub-type has none (or bussard does not know it).
///
/// KNX 03_07_02 Datapoint Types v02.02.01: §3.5 (5.004 %, 5.010 counter
/// pulses; 5.003 is decoded as a float, see [`decode`]), §3.6.1 (6.001 %,
/// 6.010 counter pulses), §3.8 (7.001 pulses, 7.002 ms, 7.005 s, 7.006 min,
/// 7.007 h, 7.011 mm, 7.012 mA, 7.013 lux; 7.600
/// `DPT_Absolute_Colour_Temperature` in K from the §1.4 overview), §3.9
/// (8.001 pulses, 8.002 ms, 8.005 s, 8.006 min, 8.007 h, 8.011 °, 8.012 m),
/// §3.13 (12.001 counter pulses, 12.100-12.102 s/min/h, 12.1200 l, 12.1201
/// m³) and §3.14 (13.001 counter pulses, 13.010-13.016 energy, 13.100 s,
/// 13.1200 l, 13.1201 m³). The 10 ms and 100 ms periods and the other scaled
/// sub-types carry their unit in [`scaling`] instead.
fn int_unit(main: u16, sub: Option<u16>) -> Option<&'static str> {
    let unit = match (main, sub?) {
        (5, 4) => "%",
        (5, 10) | (6, 10) | (7, 1) | (8, 1) | (12, 1) | (13, 1) => "pulses",
        (6, 1) => "%",
        (7, 2) | (8, 2) => "ms",
        (7, 5) | (8, 5) | (12, 100) | (13, 100) => "s",
        (7, 6) | (8, 6) | (12, 101) => "min",
        (7, 7) | (8, 7) | (12, 102) => "h",
        (7, 11) => "mm",
        (7, 12) => "mA",
        (7, 13) => "lux",
        (7, 600) => "K",
        (8, 11) => "°",
        (8, 12) => "m",
        (12, 1200) | (13, 1200) => "l",
        (12, 1201) | (13, 1201) => "m³",
        (13, 10) => "Wh",
        (13, 11) => "VAh",
        (13, 12) => "VARh",
        (13, 13) => "kWh",
        (13, 14) => "kVAh",
        (13, 15) => "kVARh",
        (13, 16) => "MWh",
        _ => return None,
    };
    Some(unit)
}

/// Returns the unit label for a DPT 9.x subtype (2-byte float), per the unit
/// column of KNX 03_07_02 §3.10 (9.001 to 9.030).
fn float16_unit(sub: Option<u16>) -> Option<&'static str> {
    let unit = match sub? {
        1 => "°C",
        2 => "K",
        3 => "K/h",
        4 => "lux",
        5 => "m/s",
        6 => "Pa",
        7 => "%",
        8 => "ppm",
        9 => "m³/h",
        10 => "s",
        11 => "ms",
        20 => "mV",
        21 => "mA",
        22 => "W/m²",
        23 => "K/%",
        24 => "kW",
        25 => "l/h",
        26 => "l/m²",
        27 => "°F",
        28 => "km/h",
        29 => "g/m³",
        30 => "µg/m³",
        _ => return None,
    };
    Some(unit)
}

/// Returns the unit label for a DPT 14.x subtype (IEEE float), per the unit
/// column of KNX 03_07_02 §3.15 (14.000 to 14.080) and the 14.1200/14.1201
/// volume flux types of the §1.4 overview. 14.005 amplitude and 14.057 power
/// factor have no unit.
fn float32_unit(sub: Option<u16>) -> Option<&'static str> {
    let unit = match sub? {
        0 => "m/s²",
        1 => "rad/s²",
        2 => "J/mol",
        3 => "1/s",
        4 => "mol",
        6 | 54 => "rad",
        7 | 55 => "°",
        8 => "J s",
        9 | 34 => "rad/s",
        10 => "m²",
        11 => "F",
        12 | 22 | 25 | 26 => "C/m²",
        13 => "C/m³",
        14 => "m²/N",
        15 => "S",
        16 => "S/m",
        17 => "kg/m³",
        18 | 24 => "C",
        19 | 50 => "A",
        20 => "A/m²",
        21 => "C m",
        23 => "V/m",
        27 | 28 | 30 => "V",
        29 | 47 => "A m²",
        31 | 37 | 40 | 79 => "J",
        32 | 78 => "N",
        33 => "Hz",
        35 | 71 => "J/K",
        36 | 56 => "W",
        38 | 59 | 60 => "Ω",
        39 => "m",
        41 => "cd/m²",
        42 => "lm",
        43 => "cd",
        44 | 49 => "A/m",
        45 => "Wb",
        46 | 48 => "T",
        51 => "kg",
        52 => "kg/s",
        53 => "N s",
        58 | 66 => "Pa",
        61 => "Ω m",
        62 => "H",
        63 => "sr",
        64 => "W/m²",
        65 => "m/s",
        67 => "N/m",
        68 => "°C",
        69 | 70 => "K",
        72 => "W/(m K)",
        73 => "V/K",
        74 => "s",
        75 => "N m",
        76 => "m³",
        77 => "m³/s",
        80 => "VA",
        1200 => "m³/h",
        1201 => "l/s",
        _ => return None,
    };
    Some(unit)
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

/// A value that is not representable as a KNX 2-byte float (DPT 9.x): either
/// non-finite, or outside `-671088.64..=670433.28` (the maximum stops one
/// mantissa step below the raw encoding ceiling of 670760.96 so a value can
/// never round up onto `0x7FFF`, the DPT-9 "invalid data" marker).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("value is not representable as a KNX 2-byte float (DPT 9)")]
pub struct Float16RangeError;

/// The raw 16-bit DPT 9 pattern nearest to `value`, or `None` when `value` is
/// not finite or lies outside the two octets' raw range.
///
/// 03_07_02 §3.10 defines the value as `0.01 * M * 2^E`, `M` in
/// `-2048..=2047`, `E` in `0..=15`. The code is the smallest exponent whose
/// mantissa fits, with the mantissa `value * 100 / 2^E` rounded once, ties to
/// even. A larger exponent only has a coarser grid, so the smallest fitting
/// one holds the nearest code; rounding once (issue #493) is what keeps it
/// nearest, where halving an already rounded mantissa per exponent step drifted
/// up to two resolution steps. Ties go to even like ETS does for parameter
/// images (issue #89), so a group value and a parameter octet pair agree.
///
/// This does not refuse `7F FF` (the group-value "invalid data" marker):
/// [`encode_float16`] does, and `bussard-prod` decides it per parameter type.
/// It is the single DPT 9 rounding rule in the workspace.
pub fn encode_float16_raw(value: f64) -> Option<u16> {
    if !value.is_finite() {
        return None;
    }
    let scaled = value * 100.0;
    let (exponent, mantissa) = (0u16..=15).find_map(|e| {
        let m = (scaled / f64::from(1u32 << e)).round_ties_even();
        (-2048.0..=2047.0).contains(&m).then_some((e, m as i32))
    })?;
    let (sign, bits) = if mantissa < 0 {
        (0x8000u16, (mantissa + 2048) as u16)
    } else {
        (0u16, mantissa as u16)
    };
    Some(sign | (exponent << 11) | (bits & 0x07ff))
}

/// Encodes a value into a KNX 2-byte float (DPT 9.x), big-endian.
///
/// The code is the nearest representable one (see [`encode_float16_raw`],
/// which `bussard-prod` shares for `<TypeFloat Encoding="DPT 9">` parameter
/// images, so an image byte and a bus byte can never disagree).
pub fn encode_float16(value: f32) -> Result<[u8; 2], Float16RangeError> {
    // Reject non-finite (NaN/±Inf) and anything above the largest valid value
    // up front: the top raw pattern 0x7FFF is the "invalid data" marker.
    if !value.is_finite() || !(FLOAT16_MIN..=FLOAT16_MAX).contains(&value) {
        return Err(Float16RangeError);
    }
    let raw = encode_float16_raw(f64::from(value)).ok_or(Float16RangeError)?;
    // Defence in depth: 0x7FFF is the DPT 9 "invalid data" marker, never a value.
    // The `FLOAT16_MAX` cap above (mantissa <= 2046) already makes this pattern
    // unreachable for in-range inputs, but guard explicitly so a future change to
    // the range logic can never emit a payload that decodes as "invalid".
    if raw == 0x7FFF {
        return Err(Float16RangeError);
    }
    Ok(raw.to_be_bytes())
}

/// Generic bit names for a 21.xxx / 22.xxx sub-type bussard has no table for.
const BIT_NAMES: [&str; 16] = [
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10", "b11", "b12", "b13",
    "b14", "b15",
];

/// The names of the set bits of a 21.xxx (B8) or 22.xxx (B16) value, in bit
/// order. Reserved bits are left out here and reported by [`validity_note`].
/// 22.101 bit 8 is HeatCoolMode (03_07_02 §4.5.2): it is named either way.
fn flag_names(main: u16, sub: Option<u16>, bits: u16) -> Vec<&'static str> {
    let width: u16 = if main == 22 { 16 } else { 8 };
    let table = sub.and_then(|s| flag_table(main, s));
    let mut names = Vec::new();
    for bit in 0..width {
        let set = bits & (1 << bit) != 0;
        if main == 22 && sub == Some(101) && bit == 8 {
            names.push(if set { "Heating" } else { "Cooling" });
            continue;
        }
        if !set {
            continue;
        }
        match table {
            Some(t) => {
                if let Some(name) = t.get(usize::from(bit)).filter(|n| !n.is_empty()) {
                    names.push(*name);
                }
            }
            None => names.push(BIT_NAMES[usize::from(bit)]),
        }
    }
    names
}

/// The fields of a 6.020 `DPT_Status_Mode3` octet (03_07_02 §3.7): status
/// bits a..e in bits 7..3, where 0 means set and 1 clear, then the one-hot
/// mode in bits 2..0 (001b mode 0, 010b mode 1, 100b mode 2).
fn status_mode3_names(b: u8) -> Vec<&'static str> {
    const SET: [&str; 5] = ["A set", "B set", "C set", "D set", "E set"];
    const CLEAR: [&str; 5] = ["A clear", "B clear", "C clear", "D clear", "E clear"];
    let mut names: Vec<&'static str> = (0..5)
        .map(|i| {
            if b & (0x80 >> i) == 0 {
                SET[i]
            } else {
                CLEAR[i]
            }
        })
        .collect();
    names.push(match b & 0x07 {
        0b001 => "mode 0",
        0b010 => "mode 1",
        0b100 => "mode 2",
        _ => "mode invalid",
    });
    names
}

/// Decodes a group-value payload into a [`TypedValue`] under the given DPT.
///
/// This never fails: unknown DPTs and size mismatches degrade to
/// [`TypedValue::Raw`] so the monitor keeps working against an incomplete
/// model.
pub fn decode(dpt: &Dpt, payload: &[u8]) -> TypedValue {
    decode_inner(dpt, payload).unwrap_or_else(|| TypedValue::Raw(payload.to_vec()))
}

/// Why a conforming receiver would drop this payload, or `None` when it is
/// well-formed for `dpt`.
///
/// KNX 03_07_01 Interworking Model v02.01.01 §2.4: a receiver checks that a
/// reserved field has its specified value (0) and that an enumeration value is
/// supported, and otherwise ignores the whole value; a numeric value outside
/// its range may be ignored or clamped. [`decode`] still returns its best
/// reading of such a payload; this note says that the bus devices will not act
/// on it. A payload too short for the DPT is the size check's business, not
/// this one's, and yields `None`.
pub fn validity_note(dpt: &Dpt, payload: &[u8]) -> Option<String> {
    let problems = validity_problems(dpt, payload);
    if problems.is_empty() {
        return None;
    }
    Some(format!(
        "DPT {dpt}: {}; a conforming receiver ignores this value (KNX 03_07_01 §2.4)",
        problems.join(", ")
    ))
}

/// The individual findings behind [`validity_note`].
fn validity_problems(dpt: &Dpt, payload: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut reserved = |what: &str, value: u8, mask: u8| {
        if value & mask != 0 {
            out.push(format!("reserved bits {:#04x} of {what} set", value & mask));
        }
    };
    let byte = |i: usize| payload.get(i).copied();
    match (dpt.main, dpt.sub) {
        // 5.006 DPT_Tariff (03_07_02 §3.5.2.2): 255 shall be ignored.
        (5, Some(6)) => {
            if byte(0) == Some(255) {
                return vec!["tariff 255 is reserved".to_string()];
            }
        }
        // 6.020 (§3.7): the mode field is one-hot.
        (6, Some(20)) => {
            if let Some(b) = byte(0)
                && !matches!(b & 0x07, 0b001 | 0b010 | 0b100)
            {
                return vec![format!("mode field {:03b}b is not one-hot", b & 0x07)];
            }
        }
        // 10.001 (§3.11): r r in front of minutes and seconds, hour 0..23.
        (10, _) => {
            let (Some(b0), Some(b1), Some(b2)) = (byte(0), byte(1), byte(2)) else {
                return out;
            };
            reserved("the minutes octet", b1, 0xC0);
            reserved("the seconds octet", b2, 0xC0);
            range(&mut out, "hour", b0 & 0x1F, 0, 23);
            range(&mut out, "minutes", b1 & 0x3F, 0, 59);
            range(&mut out, "seconds", b2 & 0x3F, 0, 59);
        }
        // 11.001 (§3.12): r3 day, r4 month, r1 year; day 1..31, month 1..12,
        // year 0..99.
        (11, _) => {
            let (Some(b0), Some(b1), Some(b2)) = (byte(0), byte(1), byte(2)) else {
                return out;
            };
            reserved("the day octet", b0, 0xE0);
            reserved("the month octet", b1, 0xF0);
            reserved("the year octet", b2, 0x80);
            range(&mut out, "day", b0 & 0x1F, 1, 31);
            range(&mut out, "month", b1 & 0x0F, 1, 12);
            range(&mut out, "year", b2 & 0x7F, 0, 99);
        }
        // 17.001 (§3.18): r r SceneNumber.
        (17, _) => {
            if let Some(b) = byte(0) {
                reserved("the scene octet", b, 0xC0);
            }
        }
        // 18.001 (§3.19): C r SceneNumber; bit 6 is the worked example of
        // 03_07_01 §2.4.
        (18, _) => {
            if let Some(b) = byte(0) {
                reserved("the scene octet", b, 0x40);
            }
        }
        // 19.001 (§3.20 and Notes 11, 15): reserved high bits, hour 24 only as
        // 24:00:00, the low six bits of the last octet reserved.
        (19, _) => {
            if payload.len() < 8 {
                return out;
            }
            let flags = payload[6];
            reserved("the month octet", payload[1], 0xF0);
            reserved("the day octet", payload[2], 0xE0);
            reserved("the minutes octet", payload[4], 0xC0);
            reserved("the seconds octet", payload[5], 0xC0);
            reserved("the quality octet", payload[7], 0x3F);
            if flags & 0x08 == 0 {
                range(&mut out, "month", payload[1] & 0x0F, 1, 12);
                range(&mut out, "day", payload[2] & 0x1F, 1, 31);
            }
            if flags & 0x02 == 0 {
                let (h, m, sec) = (payload[3] & 0x1F, payload[4] & 0x3F, payload[5] & 0x3F);
                range(&mut out, "hour", h, 0, 24);
                range(&mut out, "minutes", m, 0, 59);
                range(&mut out, "seconds", sec, 0, 59);
                if h == 24 && (m != 0 || sec != 0) {
                    out.push("hour 24 with non-zero minutes or seconds".to_string());
                }
            }
        }
        // The 20.xxx enumerations: a code outside the value list is reserved
        // (03_07_01 §2.4 rule 3).
        (20, Some(sub)) => {
            if let Some(b) = byte(0)
                && enum_table(sub).is_some()
                && enum_label(sub, b).is_none()
            {
                return vec![format!("code {b} is reserved")];
            }
        }
        (21, Some(sub)) => {
            if let Some(b) = byte(0) {
                // The mask of an 8-bit set fits one octet.
                let mask = flag_reserved_mask(21, sub).to_be_bytes()[1];
                reserved("the bit set", b, mask);
            }
        }
        (22, Some(sub)) => {
            if let (Some(hi), Some(lo)) = (byte(0), byte(1)) {
                let [mhi, mlo] = flag_reserved_mask(22, sub).to_be_bytes();
                reserved("the high octet", hi, mhi);
                reserved("the low octet", lo, mlo);
            }
        }
        _ => {}
    }
    out
}

/// Records `name` = `value` when it is outside `lo..=hi`.
fn range(out: &mut Vec<String>, name: &str, value: u8, lo: u8, hi: u8) {
    if !(lo..=hi).contains(&value) {
        out.push(format!("{name} {value} is outside {lo}..{hi}"));
    }
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
        2 => {
            // B2 (03_07_02 §3.2): bit 1 the control flag, bit 0 the value of
            // the 1.xxx sub-type with the same number (2.001 follows 1.001).
            let b = payload.first()?;
            let value = (b & 0x01) != 0;
            let (f, t) = bool_labels(dpt.sub);
            Some(TypedValue::Control {
                control: (b & 0x02) != 0,
                value,
                label: if value { t } else { f },
            })
        }
        3 => {
            // 4-bit control (03_07_02 §3.3): bit 3 direction, bits 0..2 the
            // step code.
            let b = payload.first()? & 0x0f;
            let (zero, one) = step_labels(dpt.sub);
            let direction = if (b & 0x08) != 0 { one } else { zero };
            Some(TypedValue::Step {
                direction,
                step: b & 0x07,
            })
        }
        5 => {
            let b = *payload.first()?;
            match dpt.sub {
                Some(1) => Some(TypedValue::Percent((b as f32) * 100.0 / 255.0)),
                // 5.003: 0..255 spans 0..360 ° (03_07_02 §3.5.1, about 1.4 °
                // per step); shown to one decimal rather than truncated.
                Some(3) => Some(TypedValue::Float {
                    value: (f32::from(b) * 3600.0 / 255.0).round() / 10.0,
                    unit: Some("°"),
                }),
                _ => Some(TypedValue::Unsigned {
                    value: b as u32,
                    unit: int_unit(5, dpt.sub),
                }),
            }
        }
        // 6.020 DPT_Status_Mode3 (03_07_02 §3.7): five status bits a..e
        // (bit 7..3, 0 = set, 1 = clear) and a one-hot mode in bits 2..0.
        6 if dpt.sub == Some(20) => {
            let b = *payload.first()?;
            Some(TypedValue::Flags {
                bits: u16::from(b),
                names: status_mode3_names(b),
            })
        }
        6 => {
            let b = *payload.first()? as i8;
            Some(TypedValue::Signed {
                value: b as i64,
                unit: int_unit(6, dpt.sub),
            })
        }
        7 => {
            let v = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
            if let Some(sc) = scaling(dpt) {
                return Some(TypedValue::Scaled {
                    count: i64::from(v),
                    decimals: sc.decimals,
                    unit: sc.unit,
                });
            }
            Some(TypedValue::Unsigned {
                value: v as u32,
                unit: int_unit(7, dpt.sub),
            })
        }
        8 => {
            let v = i16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
            if let Some(sc) = scaling(dpt) {
                // 8.010 reserves 7FFFh for invalid data (03_07_02 §3.9.1):
                // fall back to `Raw` like the DPT 9 sentinel.
                if sc.invalid == Some(i64::from(v)) {
                    return None;
                }
                return Some(TypedValue::Scaled {
                    count: i64::from(v),
                    decimals: sc.decimals,
                    unit: sc.unit,
                });
            }
            Some(TypedValue::Signed {
                value: v as i64,
                unit: int_unit(8, dpt.sub),
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
                unit: int_unit(12, dpt.sub),
            })
        }
        13 => {
            let v = i32::from_be_bytes([
                *payload.first()?,
                *payload.get(1)?,
                *payload.get(2)?,
                *payload.get(3)?,
            ]);
            if let Some(sc) = scaling(dpt) {
                return Some(TypedValue::Scaled {
                    count: i64::from(v),
                    decimals: sc.decimals,
                    unit: sc.unit,
                });
            }
            Some(TypedValue::Signed {
                value: v as i64,
                unit: int_unit(13, dpt.sub),
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
            if let Some(sub) = dpt.sub
                && enum_table(sub).is_some()
            {
                return Some(TypedValue::Enum {
                    code: b,
                    label: enum_label(sub, b),
                });
            }
            Some(TypedValue::Unsigned {
                value: u32::from(b),
                unit: None,
            })
        }
        21 => {
            let b = *payload.first()?;
            Some(TypedValue::Flags {
                bits: u16::from(b),
                names: flag_names(21, dpt.sub, u16::from(b)),
            })
        }
        22 => {
            let bits = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
            Some(TypedValue::Flags {
                bits,
                names: flag_names(22, dpt.sub, bits),
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
/// - **1.x** — `on`/`off`, `true`/`false`, `1`/`0`, and the word pair of the
///   sub-type (03_07_02 §3.1, and 1.100): `up`/`down` (1.008), `open`/`close`
///   (1.009), `closed`/`open` (1.019), `occupied`/`not occupied` (1.018),
///   `day`/`night` (1.024), `heating`/`cooling` (1.100), `active`/`inactive`
///   (1.011), `trigger` (1.017), `reset` (1.015), `ack` (1.016), and so on.
/// - **2.x** — `control <value>` (or `force <value>`) with the matching 1.x
///   word (`control on`, 2.008 `control down`), and `release` or
///   `no control` to drop the control bit.
/// - **3.007 / 3.008** — a direction and an optional step: `increase 25%`,
///   `up`, `dim up`, `down 50%`, `decrease 3` (the step code), `break`,
///   `stop`. The step is the size of one step in percent (100, 50, 25,
///   12.5, 6.25, 3.125, 1.5625) or the code 1-7; no step means 100 %.
/// - **5.001** — a percentage: `75%` or a bare `0`–`100`.
/// - **5.003** — an angle `0`–`360`, decimals allowed (`22.5`, `90°`).
/// - **5.x** (other) — an integer `0`–`255`.
/// - **6.x** — a signed integer `-128`–`127`.
/// - **7.x** — an unsigned integer `0`–`65535`.
/// - **8.x** — a signed integer `-32768`–`32767`.
/// - Every integer and float sub-type with a unit takes the unit as a suffix
///   (`6500 K` on 7.600, `3600 s` on 13.100, `2 K` on 9.002, `50 %` on
///   5.004); a bare number is in the same unit.
/// - **7.003 / 7.004 / 8.003 / 8.004** — a time period in seconds
///   (`1.5`, `1.5 s`) or milliseconds (`1500 ms`), a multiple of the 10 ms or
///   100 ms resolution.
/// - **8.010** — a percentage `-327.68`–`327.66` in steps of 0.01 (`50 %`).
/// - **13.002** — a flow rate in m³/h in steps of 0.0001 (`1.5 m³/h`).
/// - **9.x** — a decimal, optionally with the subtype's unit suffix
///   (`21.5`, `21.5°C`).
/// - **12.x** — an unsigned integer `0`–`4294967295`.
/// - **13.x** — a signed 32-bit integer, optional unit suffix.
/// - **14.x** — a decimal (IEEE float), optional unit suffix.
/// - **17.001 / 18.001** — a scene number `1`–`64` counted like ETS and Home
///   Assistant (`scene 3` sends field 2, 03_07_02 §3.19 NOTE 9), or the field
///   itself as `raw 0`–`raw 63`; 18.001 accepts a leading `learn` or
///   `activate`.
/// - **1.022** — scene `1` or `2` (`scene a`/`scene b`, or the bit as
///   `raw 0`/`raw 1`).
/// - **20.102** — a mode name: `auto`, `comfort`, `standby`, `economy`,
///   `building-protection` (aliases `frost`, `protection`).
/// - **20.xxx** (the enumerations of 03_07_02 §3.21, §4.3, §6.3) — the label
///   (`cool` on 20.105, `fan only`) or its code; a reserved code is refused.
/// - **21.xxx / 22.xxx** — `none`, or the names of the set bits joined by
///   `,` (`Fault, InAlarm` on 21.001).
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

    if let Some(sc) = scaling(dpt)
        && let Some((lo, hi)) = writable_range(dpt.main, sc)
    {
        let step = format_fixed(1, sc.decimals);
        let accepted = format!(
            "a number in {} with at most {} decimals",
            sc.unit, sc.decimals
        );
        let range = format!(
            "{}..{} {} in steps of {step}",
            format_fixed(lo, sc.decimals),
            format_fixed(hi, sc.decimals),
            sc.unit
        );
        let count = match parse_scaled(raw, sc) {
            Ok(c) => c,
            Err(FixedError::Syntax) => return Err(invalid(&accepted)),
            Err(FixedError::Precision) => {
                return Err(invalid(&format!("{accepted}, a multiple of {step}")));
            }
            Err(FixedError::Overflow) => return Err(out_of_range(&range)),
        };
        if !(lo..=hi).contains(&count) {
            return Err(out_of_range(&range));
        }
        return Ok(TypedValue::Scaled {
            count,
            decimals: sc.decimals,
            unit: sc.unit,
        });
    }

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
        2 => {
            let (false_label, true_label) = bool_labels(dpt.sub);
            let (control, value) = parse_control(raw, dpt.sub).ok_or_else(|| {
                invalid(&format!(
                    "`control <value>` with {} or {} (or on/off), or `release`/`no control`",
                    true_label.to_lowercase(),
                    false_label.to_lowercase()
                ))
            })?;
            Ok(TypedValue::Control {
                control,
                value,
                label: if value { true_label } else { false_label },
            })
        }
        3 => {
            let (zero, one) = step_labels(dpt.sub);
            let (bit, step) = parse_step(raw, dpt.sub).ok_or_else(|| {
                invalid(&format!(
                    "a direction ({} or {}) and an optional step size \
                     (100%, 50%, 25%, 12.5%, 6.25%, 3.125%, 1.5625%) or code 1-7, \
                     or `break`/`stop`",
                    one.to_lowercase(),
                    zero.to_lowercase()
                ))
            })?;
            Ok(TypedValue::Step {
                direction: if bit { one } else { zero },
                step,
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
                let v = parse_float(raw, Some("°"))
                    .filter(|v| v.is_finite())
                    .ok_or_else(|| invalid("an angle 0-360 (`90`, `90°`, `22.5`)"))?;
                if !(0.0..=360.0).contains(&v) {
                    return Err(out_of_range("0-360 degrees"));
                }
                Ok(TypedValue::Float {
                    value: v,
                    unit: Some("°"),
                })
            }
            _ => {
                let unit = int_unit(5, dpt.sub);
                let v = parse_uint(strip_unit(raw, unit))
                    .ok_or_else(|| invalid("an integer 0-255 (optionally with unit)"))?;
                if v > 255 {
                    return Err(out_of_range("0-255"));
                }
                Ok(TypedValue::Unsigned {
                    value: v as u32,
                    unit,
                })
            }
        },
        6 => {
            let unit = int_unit(6, dpt.sub);
            let v = parse_int_with_unit(raw, unit)
                .ok_or_else(|| invalid("a signed integer -128..127 (optionally with unit)"))?;
            if !(-128..=127).contains(&v) {
                return Err(out_of_range("-128..127"));
            }
            Ok(TypedValue::Signed { value: v, unit })
        }
        7 => {
            let unit = int_unit(7, dpt.sub);
            let v = parse_uint(strip_unit(raw, unit))
                .ok_or_else(|| invalid("an unsigned integer 0-65535 (optionally with unit)"))?;
            if v > 0xffff {
                return Err(out_of_range("0-65535"));
            }
            Ok(TypedValue::Unsigned {
                value: v as u32,
                unit,
            })
        }
        8 => {
            let unit = int_unit(8, dpt.sub);
            let v = parse_int_with_unit(raw, unit).ok_or_else(|| {
                invalid("a signed integer -32768..32767 (optionally with unit)")
            })?;
            if !(-32768..=32767).contains(&v) {
                return Err(out_of_range("-32768..32767"));
            }
            Ok(TypedValue::Signed { value: v, unit })
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
            let unit = int_unit(12, dpt.sub);
            let v = parse_uint(strip_unit(raw, unit)).ok_or_else(|| {
                invalid("an unsigned integer 0-4294967295 (optionally with unit)")
            })?;
            if v > u32::MAX as u64 {
                return Err(out_of_range("0-4294967295"));
            }
            Ok(TypedValue::Unsigned {
                value: v as u32,
                unit,
            })
        }
        13 => {
            let unit = int_unit(13, dpt.sub);
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
            let v = parse_scene(raw)
                .ok_or_else(|| invalid("a scene number 1-64, or `raw 0`-`raw 63`"))?
                .map_err(|()| out_of_range("scene 1-64 (raw 0-63)"))?;
            Ok(TypedValue::Scene(v))
        }
        18 => {
            let lower = raw.to_lowercase();
            let (learn, rest) = match lower.strip_prefix("learn") {
                Some(r) => (true, r.trim()),
                None => (false, lower.as_str()),
            };
            let rest = rest.strip_prefix("activate").map_or(rest, str::trim);
            let v = parse_scene(rest)
                .ok_or_else(|| {
                    invalid(
                        "a scene number 1-64 or `raw 0`-`raw 63`, optionally prefixed \
                         `learn` or `activate`",
                    )
                })?
                .map_err(|()| out_of_range("scene 1-64 (raw 0-63)"))?;
            Ok(TypedValue::SceneControl { learn, scene: v })
        }
        20 if dpt.sub == Some(102) => {
            let mode = parse_hvac_mode(raw).ok_or_else(|| {
                invalid("one of auto, comfort, standby, economy, building-protection")
            })?;
            Ok(TypedValue::HvacMode(mode))
        }
        20 if dpt.sub.and_then(enum_table).is_some() => {
            let sub = dpt.sub.unwrap_or_default();
            let table = enum_table(sub).unwrap_or_default();
            let words: Vec<&str> = table.iter().map(|(_, l)| *l).collect();
            let code = enum_code(sub, raw)
                .or_else(|| {
                    raw.parse::<u8>()
                        .ok()
                        .filter(|c| enum_label(sub, *c).is_some())
                })
                .ok_or_else(|| {
                    invalid(&format!(
                        "one of {} (or its code)",
                        words.join(", ").to_lowercase()
                    ))
                })?;
            Ok(TypedValue::Enum {
                code,
                label: enum_label(sub, code),
            })
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
        21 | 22 if dpt.sub.and_then(|s| flag_table(dpt.main, s)).is_some() => {
            let bits = parse_flags(raw, dpt.main, dpt.sub).ok_or_else(|| {
                invalid(&format!(
                    "`none` or a comma-separated list of {}",
                    flag_table(dpt.main, dpt.sub.unwrap_or_default())
                        .unwrap_or_default()
                        .iter()
                        .filter(|n| !n.is_empty())
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
            Ok(TypedValue::Flags {
                bits,
                names: flag_names(dpt.main, dpt.sub, bits),
            })
        }
        _ => Err(ParseValueError::Unsupported {
            dpt: dpt.to_string(),
        }),
    }
}

/// Parses a 21.xxx / 22.xxx bit set from its names: `none`, or names joined
/// by `,` or `+` (`Fault, InAlarm`). On 22.101 `Cooling` is bit 8 clear and
/// `Heating` bit 8 set.
fn parse_flags(input: &str, main: u16, sub: Option<u16>) -> Option<u16> {
    let table = flag_table(main, sub?)?;
    let folded = fold_word(input);
    if folded == "none" || folded.is_empty() {
        return Some(0);
    }
    let mut bits = 0u16;
    for word in input.split([',', '+']) {
        let word = fold_word(word);
        if word.is_empty() || (main == 22 && sub == Some(101) && word == "cooling") {
            continue;
        }
        let bit = table
            .iter()
            .position(|n| !n.is_empty() && fold_word(n) == word)?;
        bits |= 1 << bit;
    }
    Some(bits)
}

/// Parses a boolean from human text, honoring the DPT 1.x subtype's word pair.
fn parse_bool(input: &str, sub: Option<u16>) -> Option<bool> {
    let s = input.trim().to_lowercase();
    // 1.022 numbers its two scenes 1 and 2 (03_07_02 §3.1 footnote 2), so a
    // bare number is a scene number, not the bit; `raw 0`/`raw 1` is the bit.
    if sub == Some(22) {
        let compact = s.split_whitespace().collect::<Vec<_>>().join(" ");
        match compact.as_str() {
            "1" | "scene 1" | "a" | "scene a" | "raw 0" => return Some(false),
            "2" | "scene 2" | "b" | "scene b" | "raw 1" => return Some(true),
            "0" => return None,
            _ => {}
        }
    }
    // Universal forms first.
    match s.as_str() {
        "on" | "true" | "1" | "yes" => return Some(true),
        "off" | "false" | "0" | "no" => return Some(false),
        _ => {}
    }
    // Subtype words: the labels themselves (`occupied`, `night`), then the
    // aliases. Labels that are a bare bit (`0`/`1`) were handled above.
    let (false_label, true_label) = bool_labels(sub);
    let (false_alias, true_alias) = bool_aliases(sub);
    if s == true_label.to_lowercase() || true_alias.contains(&s.as_str()) {
        return Some(true);
    }
    if s == false_label.to_lowercase() || false_alias.contains(&s.as_str()) {
        return Some(false);
    }
    None
}

/// Parses a 2.x controlled value into `(control, value)`.
///
/// `control on`, `force down`, `forced off` set the control bit with the
/// 1.x value word; `release`, `no control`, `uncontrolled` clear both bits.
fn parse_control(input: &str, sub: Option<u16>) -> Option<(bool, bool)> {
    let s = input.trim().to_lowercase();
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if matches!(
        s.as_str(),
        "release" | "released" | "no control" | "no-control" | "uncontrolled"
    ) {
        return Some((false, false));
    }
    let rest = ["control:", "control", "forced", "force"]
        .iter()
        .find_map(|p| s.strip_prefix(p))?;
    Some((true, parse_bool(rest, sub)?))
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

/// Parses a signed integer, tolerating a trailing known unit suffix.
fn parse_int_with_unit(input: &str, unit: Option<&str>) -> Option<i64> {
    let s = strip_unit(input.trim(), unit);
    s.trim().parse::<i64>().ok()
}

/// Parses a scene as the transmitted field `0..=63`.
///
/// `3` and `scene 3` are scene numbers counted from 1, as ETS and Home
/// Assistant show them (03_07_02 §3.19 NOTE 9), and travel as field 2;
/// `raw 2` (or `scene raw 2`) is the field itself. `None` for text that is
/// not a scene, `Some(Err(()))` for a number out of range. The display form
/// `scene 3 (raw 2)` parses too, when its two numbers agree.
fn parse_scene(input: &str) -> Option<Result<u8, ()>> {
    let lower = input.trim().to_lowercase();
    if let Some((head, tail)) = lower.split_once('(') {
        let field = parse_scene_number(&format!(
            "raw {}",
            tail.strip_suffix(')')?.trim().strip_prefix("raw")?
        ))?;
        let number = parse_scene_number(head)?;
        return (field == number).then_some(field);
    }
    parse_scene_number(&lower)
}

/// [`parse_scene`] without the display form's `(raw N)` suffix.
fn parse_scene_number(input: &str) -> Option<Result<u8, ()>> {
    let s = input.trim().to_lowercase();
    let s = s.strip_prefix("scene").map(str::trim).unwrap_or(s.as_str());
    if let Some(field) = s.strip_prefix("raw") {
        let n = field.trim().parse::<u16>().ok()?;
        return Some(u8::try_from(n).ok().filter(|n| *n <= 63).ok_or(()));
    }
    let n = s.trim().parse::<u16>().ok()?;
    Some(if (1..=64).contains(&n) {
        Ok((n - 1) as u8)
    } else {
        Err(())
    })
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
        // The ASCII spelling of a unit with a superscript or micro sign:
        // `m3/h` for `m³/h`, `W/m2` for `W/m²`, `ug/m3` for `µg/m³`.
        let ascii = u.replace('³', "3").replace('²', "2").replace('µ', "u");
        if ascii != u
            && let Some(stripped) = strip_suffix_ci(input, &ascii)
        {
            return stripped;
        }
        // `°C` also matches a bare `C`, `m/s` a bare unit, etc.: try the unit
        // without a leading degree sign.
        if let Some(bare) = u.strip_prefix('°')
            && let Some(stripped) = strip_suffix_ci(input, bare)
        {
            return stripped;
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
    if let Some(sc) = scaling(dpt)
        && let Some((lo, hi)) = writable_range(dpt.main, sc)
    {
        // A scaled sub-type takes only its scaled value: a bare `Signed` or
        // `Unsigned` count would be ambiguous (50 meaning 50 % or 0.50 %).
        let TypedValue::Scaled {
            count, decimals, ..
        } = value
        else {
            return Err(mismatch());
        };
        if *decimals != sc.decimals {
            return Err(mismatch());
        }
        if !(lo..=hi).contains(count) {
            return Err(EncodeError::OutOfRange {
                dpt: dpt.to_string(),
                value: value.to_string(),
            });
        }
        return Ok(match dpt.main {
            7 => (*count as u16).to_be_bytes().to_vec(),
            8 => (*count as i16).to_be_bytes().to_vec(),
            _ => (*count as i32).to_be_bytes().to_vec(),
        });
    }
    match dpt.main {
        1 => match value {
            TypedValue::Bool { value, .. } => Ok(vec![*value as u8]),
            _ => Err(mismatch()),
        },
        2 => match value {
            TypedValue::Control { control, value, .. } => {
                Ok(vec![(u8::from(*control) << 1) | u8::from(*value)])
            }
            _ => Err(mismatch()),
        },
        3 => match value {
            TypedValue::Step { direction, step } => {
                let (zero, one) = step_labels(dpt.sub);
                let bit = if *direction == one {
                    0x08
                } else if *direction == zero {
                    0x00
                } else {
                    return Err(mismatch());
                };
                if *step > 7 {
                    return Err(EncodeError::OutOfRange {
                        dpt: dpt.to_string(),
                        value: value.to_string(),
                    });
                }
                Ok(vec![bit | step])
            }
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
            (Some(3), TypedValue::Float { value: v, .. }) => {
                if !(0.0..=360.0).contains(v) {
                    return Err(EncodeError::OutOfRange {
                        dpt: dpt.to_string(),
                        value: value.to_string(),
                    });
                }
                Ok(vec![(v * 255.0 / 360.0).round() as u8])
            }
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
                    .map_err(|_| EncodeError::OutOfRange {
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
            TypedValue::Enum { code, .. } if dpt.sub != Some(102) => Ok(vec![*code]),
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
        21 => match value {
            TypedValue::Flags { bits, .. } => {
                let b = u8::try_from(*bits).map_err(|_| EncodeError::OutOfRange {
                    dpt: dpt.to_string(),
                    value: value.to_string(),
                })?;
                Ok(vec![b])
            }
            _ => Err(mismatch()),
        },
        22 => match value {
            TypedValue::Flags { bits, .. } => Ok(bits.to_be_bytes().to_vec()),
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
        s.parse().expect("test fixture")
    }

    #[test]
    fn test_bool_labels_cover_standard_subtypes() -> Result<(), Box<dyn std::error::Error>> {
        // (sub-type, 0-word, 1-word): every row of 03_07_02 §3.1 plus 1.100.
        let rows: &[(&str, &str, &str)] = &[
            ("1.001", "Off", "On"),
            ("1.002", "False", "True"),
            ("1.003", "Disable", "Enable"),
            ("1.004", "No ramp", "Ramp"),
            ("1.005", "No Alarm", "Alarm"),
            ("1.006", "Low", "High"),
            ("1.007", "Decrease", "Increase"),
            ("1.008", "Up", "Down"),
            ("1.009", "Open", "Close"),
            ("1.010", "Stop", "Start"),
            ("1.011", "Inactive", "Active"),
            ("1.012", "Not inverted", "Inverted"),
            ("1.013", "Start/stop", "Cyclically"),
            ("1.014", "Fixed", "Calculated"),
            ("1.015", "No action", "Reset"),
            ("1.016", "No action", "Acknowledge"),
            ("1.017", "Trigger (raw 0)", "Trigger (raw 1)"),
            ("1.018", "Not occupied", "Occupied"),
            ("1.019", "Closed", "Open"),
            ("1.021", "OR", "AND"),
            ("1.022", "scene 1 (raw 0)", "scene 2 (raw 1)"),
            ("1.023", "Up/Down only (shutter)", "Up/Down + Step/Stop (blind)"),
            ("1.024", "Day", "Night"),
            ("1.100", "Cooling", "Heating"),
        ];
        for (sub, zero, one) in rows {
            let d = dpt(sub);
            for (bit, label) in [(false, *zero), (true, *one)] {
                let payload = [u8::from(bit)];
                assert_eq!(
                    decode(&d, &payload),
                    TypedValue::Bool { value: bit, label },
                    "{sub} bit {bit}"
                );
                // The label is accepted back as input and encodes the bit.
                let typed = parse_value(&d, &label.to_lowercase())?;
                assert_eq!(encode(&d, &typed)?, payload.to_vec(), "{sub} {label}");
            }
        }
        Ok(())
    }

    #[test]
    fn test_parse_value_bool_subtype_words() -> Result<(), Box<dyn std::error::Error>> {
        let cases: &[(&str, &str, bool)] = &[
            ("1.018", "occupied", true),
            ("1.018", "unoccupied", false),
            ("1.019", "closed", false),
            ("1.019", "open", true),
            ("1.024", "night", true),
            ("1.024", "Day", false),
            ("1.100", "heat", true),
            ("1.100", "cooling", false),
            ("1.016", "ack", true),
            ("1.015", "reset", true),
            ("1.017", "trigger", true),
            ("1.011", "active", true),
            ("1.006", "high", true),
            ("1.021", "and", true),
            ("1.023", "blind", true),
        ];
        for (sub, input, bit) in cases {
            match parse_value(&dpt(sub), input)? {
                TypedValue::Bool { value, .. } => assert_eq!(value, *bit, "{sub} {input}"),
                other => return Err(format!("{sub} {input}: {other:?}").into()),
            }
        }
        assert!(parse_value(&dpt("1.024"), "occupied").is_err());
        Ok(())
    }

    #[test]
    fn test_decode_units_cover_subtypes() -> Result<(), Box<dyn std::error::Error>> {
        // (DPT, payload, display): one row per sub-type with a unit in
        // 03_07_02 §3.5, §3.6, §3.8, §3.9, §3.10, §3.13, §3.14 and §3.15.
        let rows: &[(&str, &[u8], &str)] = &[
            ("5.004", &[0x32], "50 %"),
            ("5.010", &[7], "7 pulses"),
            ("6.001", &[0xF6], "-10 %"),
            ("6.010", &[3], "3 pulses"),
            ("7.001", &[0, 5], "5 pulses"),
            ("7.002", &[0x01, 0xF4], "500 ms"),
            ("7.005", &[0x0E, 0x10], "3600 s"),
            ("7.006", &[0, 90], "90 min"),
            ("7.007", &[0, 24], "24 h"),
            ("7.011", &[0x05, 0xDC], "1500 mm"),
            ("7.012", &[0, 20], "20 mA"),
            ("7.013", &[0x01, 0xF4], "500 lux"),
            ("7.600", &[0x19, 0x64], "6500 K"),
            ("8.002", &[0xFF, 0x9C], "-100 ms"),
            ("8.005", &[0, 60], "60 s"),
            ("8.006", &[0, 5], "5 min"),
            ("8.007", &[0, 2], "2 h"),
            ("8.011", &[0, 90], "90 °"),
            ("8.012", &[0, 12], "12 m"),
            ("9.002", &[0x07, 0xD0], "20 K"),
            ("9.003", &[0x00, 0x64], "1 K/h"),
            ("9.008", &[0x07, 0xD0], "20 ppm"),
            ("9.009", &[0x00, 0x64], "1 m³/h"),
            ("9.010", &[0x00, 0x64], "1 s"),
            ("9.011", &[0x00, 0x64], "1 ms"),
            ("9.020", &[0x00, 0x64], "1 mV"),
            ("9.022", &[0x00, 0x64], "1 W/m²"),
            ("9.023", &[0x00, 0x64], "1 K/%"),
            ("9.024", &[0x00, 0x64], "1 kW"),
            ("9.025", &[0x00, 0x64], "1 l/h"),
            ("9.026", &[0x00, 0x64], "1 l/m²"),
            ("9.027", &[0x00, 0x64], "1 °F"),
            ("9.029", &[0x00, 0x64], "1 g/m³"),
            ("9.030", &[0x00, 0x64], "1 µg/m³"),
            ("12.001", &[0, 0, 0, 9], "9 pulses"),
            ("12.100", &[0, 0, 0x0E, 0x10], "3600 s"),
            ("12.101", &[0, 0, 0, 60], "60 min"),
            ("12.102", &[0, 0, 0, 12], "12 h"),
            ("13.001", &[0, 0, 0, 9], "9 pulses"),
            ("13.010", &[0, 0, 0, 9], "9 Wh"),
            ("13.011", &[0, 0, 0, 9], "9 VAh"),
            ("13.012", &[0, 0, 0, 9], "9 VARh"),
            ("13.013", &[0, 0, 0, 9], "9 kWh"),
            ("13.014", &[0, 0, 0, 9], "9 kVAh"),
            ("13.015", &[0, 0, 0, 9], "9 kVARh"),
            ("13.016", &[0, 0, 0, 9], "9 MWh"),
            ("13.100", &[0, 0, 0x0E, 0x10], "3600 s"),
            ("14.007", &1.5f32.to_be_bytes(), "1.5 °"),
            ("14.033", &50f32.to_be_bytes(), "50 Hz"),
            ("14.057", &0.5f32.to_be_bytes(), "0.5"),
            ("14.080", &100f32.to_be_bytes(), "100 VA"),
        ];
        for (sub, payload, shown) in rows {
            let d = dpt(sub);
            let value = decode(&d, payload);
            assert_eq!(value.to_string(), *shown, "{sub}");
            // The display form, unit and all, parses back to the same octets.
            let typed = parse_value(&d, shown)?;
            assert_eq!(encode(&d, &typed)?, payload.to_vec(), "{sub} {shown}");
        }
        // Every 9.xxx and 14.xxx sub-type of §3.10 / §3.15 has a unit except
        // 14.005 amplitude and 14.057 power factor.
        for sub in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30] {
            assert!(float16_unit(Some(sub)).is_some(), "9.{sub:03}");
        }
        for sub in (0..=80).filter(|s| *s != 5 && *s != 57) {
            assert!(float32_unit(Some(sub)).is_some(), "14.{sub:03}");
        }
        Ok(())
    }

    #[test]
    fn test_parse_value_unit_suffix() -> Result<(), Box<dyn std::error::Error>> {
        for (sub, input, payload) in [
            ("7.600", "6500 K", vec![0x19, 0x64]),
            ("7.600", "6500", vec![0x19, 0x64]),
            ("9.002", "2 K", vec![0x00, 0xC8]),
            ("13.100", "3600 s", vec![0, 0, 0x0E, 0x10]),
            ("9.009", "1 m3/h", vec![0x00, 0x64]),
            ("5.004", "50%", vec![0x32]),
        ] {
            let d = dpt(sub);
            assert_eq!(encode(&d, &parse_value(&d, input)?)?, payload, "{sub} {input}");
        }
        // A wrong unit is refused rather than ignored.
        assert!(parse_value(&dpt("7.600"), "6500 s").is_err());
        Ok(())
    }

    #[test]
    fn test_decode_angle_one_decimal() -> Result<(), Box<dyn std::error::Error>> {
        let d = dpt("5.003");
        assert_eq!(decode(&d, &[0x80]).to_string(), "180.7 °");
        assert_eq!(decode(&d, &[0x01]).to_string(), "1.4 °");
        assert_eq!(decode(&d, &[0xFF]).to_string(), "360 °");
        // Every code survives decode then parse then encode.
        for raw in 0u8..=255 {
            let shown = decode(&d, &[raw]).to_string();
            assert_eq!(encode(&d, &parse_value(&d, &shown)?)?, vec![raw], "{shown}");
        }
        Ok(())
    }

    #[test]
    fn test_decode_enum_subtypes() -> Result<(), Box<dyn std::error::Error>> {
        // (DPT, code, label): the sub-types the corpus declares.
        let rows: &[(&str, u8, &str)] = &[
            ("20.001", 2, "master"),
            ("20.003", 1, "standby"),
            ("20.103", 1, "LegioProtect"),
            ("20.105", 3, "Cool"),
            ("20.105", 20, "NoDem"),
            ("20.107", 2, "HeatingOnly"),
            ("20.108", 5, "Heat/Cool changeover"),
            ("20.111", 2, "running in intervals"),
            ("20.112", 1, "master"),
            ("20.602", 1, "0.7 s"),
            ("20.609", 7, "LED, leading"),
            ("20.610", 3, "detection not possible or error"),
            ("20.611", 1, "Start Function Test"),
        ];
        for (sub, code, label) in rows {
            let d = dpt(sub);
            let v = decode(&d, &[*code]);
            assert_eq!(v.to_string(), *label, "{sub} {code}");
            assert_eq!(encode(&d, &parse_value(&d, label)?)?, vec![*code], "{sub}");
        }
        // Reserved codes stay visible as Unknown(n).
        assert_eq!(decode(&dpt("20.105"), &[18]).to_string(), "Unknown(18)");
        assert_eq!(decode(&dpt("20.611"), &[0]).to_string(), "Unknown(0)");
        // A sub-type without a table still decodes the bare code.
        assert_eq!(decode(&dpt("20.999"), &[7]).to_string(), "7");
        Ok(())
    }

    #[test]
    fn test_parse_value_enum_words() -> Result<(), Box<dyn std::error::Error>> {
        let d = dpt("20.105");
        assert_eq!(
            parse_value(&d, "cool")?,
            TypedValue::Enum {
                code: 3,
                label: Some("Cool")
            }
        );
        assert_eq!(encode(&d, &parse_value(&d, "cool")?)?, vec![3]);
        assert_eq!(encode(&d, &parse_value(&d, "fan_only")?)?, vec![9]);
        assert_eq!(encode(&d, &parse_value(&d, "6")?)?, vec![6]);
        // A reserved code or an unknown word is refused.
        assert!(parse_value(&d, "18").is_err());
        assert!(parse_value(&d, "comfort").is_err());
        Ok(())
    }

    #[test]
    fn test_decode_flag_sets() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(decode(&dpt("21.001"), &[0x0A]).to_string(), "Fault, InAlarm");
        assert_eq!(decode(&dpt("21.001"), &[0x00]).to_string(), "none");
        assert_eq!(
            decode(&dpt("21.601"), &[0x24]).to_string(),
            "Overcurrent, LampFailure"
        );
        assert_eq!(decode(&dpt("21.106"), &[0x06]).to_string(), "FanActive, Heat");
        // 22.101 bit 8 is HeatCoolMode: named either way.
        assert_eq!(decode(&dpt("22.101"), &[0x01, 0x01]).to_string(), "Fault, Heating");
        assert_eq!(decode(&dpt("22.101"), &[0x20, 0x00]).to_string(), "Cooling, FrostAlarm");
        assert_eq!(decode(&dpt("22.100"), &[0x00, 0x02]).to_string(), "DHWLoadActive");
        // A sub-type without a table names the bits.
        assert_eq!(decode(&dpt("21.999"), &[0x81]).to_string(), "b0, b7");
        // Names parse back to the same octets.
        let d = dpt("21.001");
        assert_eq!(encode(&d, &parse_value(&d, "Fault, InAlarm")?)?, vec![0x0A]);
        assert_eq!(encode(&d, &parse_value(&d, "none")?)?, vec![0x00]);
        let d = dpt("22.101");
        assert_eq!(encode(&d, &parse_value(&d, "Fault, Heating")?)?, vec![0x01, 0x01]);
        assert!(parse_value(&dpt("21.001"), "Bogus").is_err());
        Ok(())
    }

    #[test]
    fn test_decode_status_mode3() {
        // 0x81: a = 1 (clear), b..e = 0 (set), mode bits 001b = mode 0.
        assert_eq!(
            decode(&dpt("6.020"), &[0x81]).to_string(),
            "A clear, B set, C set, D set, E set, mode 0"
        );
        assert_eq!(
            decode(&dpt("6.020"), &[0xFC]).to_string(),
            "A clear, B clear, C clear, D clear, E clear, mode 2"
        );
        assert_eq!(
            decode(&dpt("6.020"), &[0x03]).to_string(),
            "A set, B set, C set, D set, E set, mode invalid"
        );
    }

    #[test]
    fn test_validity_note_reserved_and_range() {
        let note = |d: &str, p: &[u8]| validity_note(&dpt(d), p);
        assert!(note("18.001", &[0x45]).is_some_and(|n| n.contains("0x40")));
        assert!(note("17.001", &[0xC1]).is_some());
        assert!(note("10.001", &[0x18, 0, 0]).is_some_and(|n| n.contains("hour 24")));
        assert!(note("10.001", &[0x0C, 0x40, 0]).is_some_and(|n| n.contains("minutes octet")));
        assert!(note("11.001", &[0x01, 0x00, 0x18]).is_some_and(|n| n.contains("month 0")));
        assert!(note("11.001", &[0x01, 0x01, 0x64]).is_some_and(|n| n.contains("year 100")));
        assert!(
            note("19.001", &[0x7D, 1, 1, 0x18, 0, 5, 0, 0])
                .is_some_and(|n| n.contains("hour 24 with non-zero"))
        );
        assert!(note("19.001", &[0x7D, 1, 1, 0x18, 0, 0, 0, 0]).is_none());
        assert!(note("19.001", &[0x7D, 1, 1, 0x0C, 0, 0, 0, 0x81]).is_some());
        assert!(note("5.006", &[0xFF]).is_some());
        assert!(note("5.006", &[0xFE]).is_none());
        assert!(note("20.102", &[0x05]).is_some());
        assert!(note("20.102", &[0x04]).is_none());
        assert!(note("21.001", &[0x20]).is_some());
        assert!(note("22.101", &[0x80, 0x00]).is_some());
        assert!(note("6.020", &[0x83]).is_some());
        // Well-formed values and short payloads carry no note.
        assert!(note("18.001", &[0x85]).is_none());
        assert!(note("10.001", &[0x2C, 0x1E, 0x3B]).is_none());
        assert!(note("10.001", &[0x2C]).is_none());
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
    fn test_decode_dpt2_control() {
        assert_eq!(
            decode(&dpt("2.001"), &[0b11]),
            TypedValue::Control {
                control: true,
                value: true,
                label: "On"
            }
        );
        assert_eq!(decode(&dpt("2.001"), &[0b11]).to_string(), "Control: On");
        assert_eq!(decode(&dpt("2.001"), &[0b00]).to_string(), "No control");
        assert_eq!(decode(&dpt("2.008"), &[0b11]).to_string(), "Control: Down");
        assert_eq!(decode(&dpt("2.008"), &[0b10]).to_string(), "Control: Up");
    }

    #[test]
    fn test_parse_value_dpt2_control_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let d1 = dpt("2.001");
        for (input, byte) in [
            ("control on", 0b11),
            ("control off", 0b10),
            ("force on", 0b11),
            ("Control: On", 0b11),
            ("release", 0b00),
            ("no control", 0b00),
        ] {
            let v = parse_value(&d1, input)?;
            assert_eq!(encode(&d1, &v)?, vec![byte], "{input}");
        }
        for byte in 0u8..=3 {
            let v = decode(&d1, &[byte]);
            // Without control the value bit carries nothing; it encodes as 0.
            let want = if byte & 0b10 == 0 { 0 } else { byte };
            assert_eq!(encode(&d1, &parse_value(&d1, &v.to_string())?)?, vec![want]);
        }
        let d8 = dpt("2.008");
        assert_eq!(encode(&d8, &parse_value(&d8, "control down")?)?, vec![0b11]);
        assert_eq!(encode(&d8, &parse_value(&d8, "control up")?)?, vec![0b10]);
        assert!(parse_value(&d8, "control sideways").is_err());
        assert!(parse_value(&d1, "on").is_err());
        Ok(())
    }

    #[test]
    fn test_parse_value_dpt3_step_forms() -> Result<(), Box<dyn std::error::Error>> {
        let step = |direction, step| TypedValue::Step { direction, step };
        let d7 = dpt("3.007");
        assert_eq!(parse_value(&d7, "increase 25%")?, step("Increase", 3));
        assert_eq!(parse_value(&d7, "increase 100%")?, step("Increase", 1));
        assert_eq!(parse_value(&d7, "up 1")?, step("Increase", 1));
        assert_eq!(parse_value(&d7, "up")?, step("Increase", 1));
        assert_eq!(parse_value(&d7, "dim up")?, step("Increase", 1));
        assert_eq!(parse_value(&d7, "Decrease 1.5625 %")?, step("Decrease", 7));
        assert_eq!(parse_value(&d7, "decrease step 2")?, step("Decrease", 2));
        assert_eq!(parse_value(&d7, "break")?, step("Decrease", 0));
        assert_eq!(parse_value(&d7, "stop")?, step("Decrease", 0));
        assert_eq!(parse_value(&d7, "increase stop")?, step("Increase", 0));
        let d8 = dpt("3.008");
        assert_eq!(parse_value(&d8, "down 50%")?, step("Down", 2));
        assert_eq!(parse_value(&d8, "up")?, step("Up", 1));
        // A step size the 3-bit code cannot express is refused.
        assert!(parse_value(&d7, "increase 30%").is_err());
        assert!(parse_value(&d7, "increase 8").is_err());
        assert!(parse_value(&d7, "sideways").is_err());
        Ok(())
    }

    #[test]
    fn test_encode_dpt3_step() -> Result<(), Box<dyn std::error::Error>> {
        let d7 = dpt("3.007");
        let v = TypedValue::Step {
            direction: "Increase",
            step: 3,
        };
        assert_eq!(encode(&d7, &v)?, vec![0x0B]);
        assert_eq!(encode(&d7, &parse_value(&d7, "break")?)?, vec![0x00]);
        let d8 = dpt("3.008");
        assert_eq!(encode(&d8, &parse_value(&d8, "down 50%")?)?, vec![0x0A]);
        // A 3.007 label under 3.008 is a mismatch, not a guess.
        assert!(matches!(encode(&d8, &v), Err(EncodeError::Mismatch { .. })));
        // Round trip over every code.
        for b in 0u8..=0x0F {
            assert_eq!(encode(&d7, &decode(&d7, &[b]))?, vec![b]);
            assert_eq!(encode(&d8, &decode(&d8, &[b]))?, vec![b]);
        }
        Ok(())
    }

    #[test]
    fn test_display_dpt3_step_percent() {
        let d7 = dpt("3.007");
        assert_eq!(decode(&d7, &[0x0B]).to_string(), "Increase 25 %");
        assert_eq!(decode(&d7, &[0x09]).to_string(), "Increase 100 %");
        assert_eq!(decode(&d7, &[0x07]).to_string(), "Decrease 1.5625 %");
        assert_eq!(decode(&d7, &[0x00]).to_string(), "Decrease break");
        assert_eq!(decode(&dpt("3.008"), &[0x0A]).to_string(), "Down 50 %");
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
                unit: Some("pulses")
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
    fn float16_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        // DPT 9 quantizes more coarsely as magnitude grows (the exponent scales
        // the 0.01 resolution), so the tolerance is proportional to the value.
        for &t in &[0.0f32, 21.0, -30.0, 0.5, 100.0, -273.15] {
            let bytes = encode_float16(t)?;
            let back = decode_float16(bytes[0], bytes[1]);
            let tol = 0.1_f32.max(t.abs() * 0.001);
            assert!((back - t).abs() <= tol, "roundtrip {t} -> {back}");
        }
        Ok(())
    }

    #[test]
    fn test_encode_float16_nearest_code_examples() -> Result<(), Float16RangeError> {
        // Issue #493: halving a rounded mantissa per exponent step drifted.
        // 50.01: M = 1250, E = 2 (50.00), not 1251 (50.04). The issue text
        // gives 0x0CE2, which is E = 1 (25.00); E = 2 is 0x14E2.
        assert_eq!(encode_float16(50.01)?, [0x14, 0xE2]);
        // 1000.33: M = 1563, E = 6 (1000.32), not 1564 (1000.96).
        assert_eq!(encode_float16(1000.33)?, [0x36, 0x1B]);
        // -2621.45: M = -2048, E = 7 (-2621.44), not M = -1025, E = 8.
        assert_eq!(encode_float16(-2621.45)?, [0xB8, 0x00]);
        // A tie goes to the even mantissa, like ETS's parameter images (#89):
        // 1000 lux is 100000 / 64 = 1562.5 -> 1562.
        assert_eq!(encode_float16(1000.0)?, [0x36, 0x1A]);
        Ok(())
    }

    /// The distance from `x` to the nearest valid DPT 9 code, found by trying
    /// the two mantissas around `x` at every exponent (independent of the
    /// encoder's smallest-exponent search).
    fn nearest_float16_distance(x: f64) -> f64 {
        let mut best = f64::INFINITY;
        for e in 0..=15u32 {
            let step = f64::from(1u32 << e) / 100.0;
            let q = x / step;
            for m in [q.floor(), q.ceil()] {
                let m = m.clamp(-2048.0, 2047.0);
                if e == 15 && m == 2047.0 {
                    continue; // 0x7FFF, the invalid marker
                }
                best = best.min((m * step - x).abs());
            }
        }
        best
    }

    #[test]
    fn test_encode_float16_never_further_than_nearest_code() -> Result<(), Float16RangeError> {
        // Deterministic pseudo-random inputs over every exponent's range.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for i in 0..200_000u32 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let unit = (state >> 11) as f64 / (1u64 << 53) as f64; // 0..1
            let e = i % 16;
            let mag = unit * 2048.0 * f64::from(1u32 << e) / 100.0;
            let v = if state & 1 == 0 { mag } else { -mag } as f32;
            if !(FLOAT16_MIN..=FLOAT16_MAX).contains(&v) {
                continue;
            }
            let b = encode_float16(v)?;
            let got = f64::from(decode_float16(b[0], b[1]));
            let x = f64::from(v);
            let want = nearest_float16_distance(x);
            // Tolerance for the f32 decode of large values only.
            let tol = 1e-6 * x.abs().max(1.0);
            assert!(
                (got - x).abs() <= want + tol,
                "{v}: encoded {:02X}{:02X} = {got}, nearest is {want} away",
                b[0],
                b[1]
            );
        }
        Ok(())
    }

    #[test]
    fn u16_i16() {
        assert_eq!(
            decode(&dpt("7.001"), &[0x12, 0x34]),
            TypedValue::Unsigned {
                value: 0x1234,
                unit: Some("pulses")
            }
        );
        assert_eq!(
            decode(&dpt("8.001"), &[0xff, 0xff]),
            TypedValue::Signed {
                value: -1,
                unit: Some("pulses")
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
    fn test_decode_scene_displays_one_based_and_raw() {
        // 03_07_02 §3.19 NOTE 9: field 2 is ETS's scene 3.
        assert_eq!(
            decode(&dpt("18.001"), &[0x02]).to_string(),
            "activate scene 3 (raw 2)"
        );
        assert_eq!(
            decode(&dpt("18.001"), &[0x80]).to_string(),
            "learn scene 1 (raw 0)"
        );
        assert_eq!(
            decode(&dpt("17.001"), &[63]).to_string(),
            "scene 64 (raw 63)"
        );
        assert_eq!(decode(&dpt("1.022"), &[0]).to_string(), "scene 1 (raw 0)");
    }

    #[test]
    fn test_parse_value_scene_one_based() -> Result<(), Box<dyn std::error::Error>> {
        let d18 = dpt("18.001");
        assert_eq!(encode(&d18, &parse_value(&d18, "scene 3")?)?, vec![0x02]);
        assert_eq!(encode(&d18, &parse_value(&d18, "3")?)?, vec![0x02]);
        assert_eq!(encode(&d18, &parse_value(&d18, "raw 2")?)?, vec![0x02]);
        assert_eq!(
            encode(&d18, &parse_value(&d18, "learn scene 1")?)?,
            vec![0x80]
        );
        assert_eq!(
            encode(&d18, &parse_value(&d18, "activate scene 64")?)?,
            vec![0x3F]
        );
        assert!(matches!(
            parse_value(&d18, "scene 0"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        assert!(matches!(
            parse_value(&d18, "raw 64"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        let d17 = dpt("17.001");
        assert_eq!(encode(&d17, &parse_value(&d17, "scene 1")?)?, vec![0x00]);
        assert_eq!(encode(&d17, &parse_value(&d17, "raw 0")?)?, vec![0x00]);
        // The display form parses back to the same field.
        let shown = decode(&d17, &[7]).to_string();
        assert_eq!(encode(&d17, &parse_value(&d17, &shown)?)?, vec![7]);
        let d22 = dpt("1.022");
        assert_eq!(encode(&d22, &parse_value(&d22, "scene 2")?)?, vec![1]);
        assert_eq!(encode(&d22, &parse_value(&d22, "1")?)?, vec![0]);
        assert_eq!(encode(&d22, &parse_value(&d22, "raw 1")?)?, vec![1]);
        assert!(parse_value(&d22, "0").is_err());
        Ok(())
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
    fn encode_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
        let v = TypedValue::Bool {
            value: true,
            label: "On",
        };
        assert_eq!(encode(&dpt("1.001"), &v)?, vec![1]);

        let v = TypedValue::Percent(100.0);
        assert_eq!(encode(&dpt("5.001"), &v)?, vec![255]);

        let v = TypedValue::Scene(3);
        assert_eq!(encode(&dpt("17.001"), &v)?, vec![3]);

        let v = TypedValue::Rgb { r: 1, g: 2, b: 3 };
        assert_eq!(encode(&dpt("232.600"), &v)?, vec![1, 2, 3]);
        Ok(())
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
    fn parse_bool_universal_and_subtype_words() -> Result<(), Box<dyn std::error::Error>> {
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
            match parse_value(&dpt("1.001"), input)? {
                TypedValue::Bool { value, .. } => assert_eq!(value, expect, "{input}"),
                other => panic!("expected bool for {input}, got {other:?}"),
            }
        }

        // Subtype words carry the right label.
        assert_eq!(
            parse_value(&dpt("1.008"), "down")?,
            TypedValue::Bool {
                value: true,
                label: "Down"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.008"), "up")?,
            TypedValue::Bool {
                value: false,
                label: "Up"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.009"), "closed")?,
            TypedValue::Bool {
                value: true,
                label: "Close"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.010"), "start")?,
            TypedValue::Bool {
                value: true,
                label: "Start"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.003"), "enable")?,
            TypedValue::Bool {
                value: true,
                label: "Enable"
            }
        );
        assert_eq!(
            parse_value(&dpt("1.005"), "no-alarm")?,
            TypedValue::Bool {
                value: false,
                label: "No Alarm"
            }
        );
        Ok(())
    }

    #[test]
    fn parse_bool_rejects_garbage() -> Result<(), Box<dyn std::error::Error>> {
        let err = parse_value(&dpt("1.001"), "maybe")
            .err()
            .ok_or("expected an error")?;
        assert!(matches!(err, ParseValueError::Invalid { .. }));
        // The wrong subtype word does not leak across subtypes.
        assert!(parse_value(&dpt("1.001"), "down").is_err());
        Ok(())
    }

    #[test]
    fn parse_percent_forms_and_range() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse_value(&dpt("5.001"), "75%")?,
            TypedValue::Percent(75.0)
        );
        assert_eq!(parse_value(&dpt("5.001"), "0")?, TypedValue::Percent(0.0));
        assert_eq!(
            parse_value(&dpt("5.001"), "100 %")?,
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
        Ok(())
    }

    #[test]
    fn parse_scaling_and_angle() -> Result<(), Box<dyn std::error::Error>> {
        // 5.x generic scaling byte.
        assert_eq!(
            parse_value(&dpt("5.010"), "200")?,
            TypedValue::Unsigned {
                value: 200,
                unit: Some("pulses")
            }
        );
        assert!(parse_value(&dpt("5.010"), "300").is_err());
        // 5.003 angle with a stray degree sign.
        assert_eq!(
            parse_value(&dpt("5.003"), "180°")?,
            TypedValue::Float {
                value: 180.0,
                unit: Some("°")
            }
        );
        Ok(())
    }

    #[test]
    fn parse_signed_and_unsigned_ints() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse_value(&dpt("6.010"), "-5")?,
            TypedValue::Signed {
                value: -5,
                unit: Some("pulses")
            }
        );
        assert!(parse_value(&dpt("6.010"), "200").is_err());
        assert_eq!(
            parse_value(&dpt("7.001"), "1000")?,
            TypedValue::Unsigned {
                value: 1000,
                unit: Some("pulses")
            }
        );
        assert!(parse_value(&dpt("7.001"), "70000").is_err());
        assert_eq!(
            parse_value(&dpt("8.001"), "-1000")?,
            TypedValue::Signed {
                value: -1000,
                unit: Some("pulses")
            }
        );
        assert_eq!(
            parse_value(&dpt("12.001"), "4000000000")?,
            TypedValue::Unsigned {
                value: 4_000_000_000,
                unit: Some("pulses")
            }
        );
        Ok(())
    }

    #[test]
    fn parse_float_with_unit_suffix() -> Result<(), Box<dyn std::error::Error>> {
        // Bare decimal.
        assert_eq!(
            parse_value(&dpt("9.001"), "21.5")?,
            TypedValue::Float {
                value: 21.5,
                unit: Some("°C")
            }
        );
        // With the exact unit suffix.
        assert_eq!(
            parse_value(&dpt("9.001"), "21.5°C")?,
            TypedValue::Float {
                value: 21.5,
                unit: Some("°C")
            }
        );
        // With the bare unit letter.
        assert_eq!(
            parse_value(&dpt("9.001"), "21.5C")?,
            TypedValue::Float {
                value: 21.5,
                unit: Some("°C")
            }
        );
        // IEEE float (14.x).
        match parse_value(&dpt("14.056"), "1500 W")? {
            TypedValue::Float { value, unit } => {
                assert!((value - 1500.0).abs() < 0.001);
                assert_eq!(unit, Some("W"));
            }
            other => panic!("expected float, got {other:?}"),
        }
        assert!(parse_value(&dpt("9.001"), "hot").is_err());
        Ok(())
    }

    #[test]
    fn parse_energy_with_unit() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse_value(&dpt("13.013"), "10 kWh")?,
            TypedValue::Signed {
                value: 10,
                unit: Some("kWh")
            }
        );
        Ok(())
    }

    #[test]
    fn parse_scene_and_scene_control() -> Result<(), Box<dyn std::error::Error>> {
        // Scene numbers count from 1 (03_07_02 §3.19 NOTE 9).
        assert_eq!(parse_value(&dpt("17.001"), "5")?, TypedValue::Scene(4));
        assert_eq!(
            parse_value(&dpt("17.001"), "scene 5")?,
            TypedValue::Scene(4)
        );
        assert!(parse_value(&dpt("17.001"), "65").is_err());
        assert!(parse_value(&dpt("17.001"), "0").is_err());
        assert_eq!(
            parse_value(&dpt("18.001"), "3")?,
            TypedValue::SceneControl {
                learn: false,
                scene: 2
            }
        );
        assert_eq!(
            parse_value(&dpt("18.001"), "learn 3")?,
            TypedValue::SceneControl {
                learn: true,
                scene: 2
            }
        );
        Ok(())
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
        // "Comfort" (#500).
        assert_eq!(
            decode(&dpt("20.105"), &[1]),
            TypedValue::Enum {
                code: 1,
                label: Some("Heat")
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
            TypedValue::Enum {
                code: 1,
                label: Some("Heat")
            }
        );
        // A sub-type without a table takes the bare code.
        assert_eq!(
            parse_value(&dpt("20.999"), "1")?,
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
    fn parse_hvac_modes() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse_value(&dpt("20.102"), "comfort")?,
            TypedValue::HvacMode(HvacMode::Comfort)
        );
        assert_eq!(
            parse_value(&dpt("20.102"), "building-protection")?,
            TypedValue::HvacMode(HvacMode::BuildingProtection)
        );
        assert_eq!(
            parse_value(&dpt("20.102"), "Frost")?,
            TypedValue::HvacMode(HvacMode::BuildingProtection)
        );
        assert!(parse_value(&dpt("20.102"), "tropical").is_err());
        Ok(())
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
    fn dpt5003_angle_encode_scaling_and_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        // Angles above 255 now encode (previously Mismatch).
        let v = parse_value(&dpt("5.003"), "360")?;
        assert_eq!(encode(&dpt("5.003"), &v)?, vec![255]);
        assert_eq!(
            encode(&dpt("5.003"), &parse_value(&dpt("5.003"), "0")?)?,
            vec![0]
        );
        assert_eq!(
            encode(&dpt("5.003"), &parse_value(&dpt("5.003"), "180")?)?,
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
        // encode(decode(x)) is exact now that decode keeps one decimal.
        for raw in [0u8, 1, 90, 128, 200, 255] {
            let back = encode(&dpt("5.003"), &decode(&dpt("5.003"), &[raw]))?;
            assert_eq!(back, vec![raw]);
        }
        Ok(())
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
    fn dpt19_datetime_reference_vector() -> Result<(), Box<dyn std::error::Error>> {
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
        assert_eq!(encode(&dpt("19.001"), &decoded)?, payload);
        // Display shows both date and time with the weekday.
        assert_eq!(dt.to_string(), "2019-01-30 Wed 08:30:45");
        Ok(())
    }

    #[test]
    fn dpt19_datetime_flags_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
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
        assert_eq!(encode(&dpt("19.001"), &decoded)?, payload);
        Ok(())
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
    fn dpt251_rgbw_reference_vector() -> Result<(), Box<dyn std::error::Error>> {
        // R=0x11 G=0x22 B=0x33 W=0x44, reserved=0x00, validity=0x0F (all valid).
        let payload = [0x11, 0x22, 0x33, 0x44, 0x00, 0x0F];
        let decoded = decode(&dpt("251.600"), &payload);
        let c = match decoded {
            TypedValue::Rgbw(c) => c,
            other => panic!("expected Rgbw, got {other:?}"),
        };
        assert_eq!((c.r, c.g, c.b, c.w), (0x11, 0x22, 0x33, 0x44));
        assert!(c.r_valid && c.g_valid && c.b_valid && c.w_valid);
        assert_eq!(encode(&dpt("251.600"), &decoded)?, payload);
        assert_eq!(c.to_string(), "RGBW(11,22,33,44)");
        Ok(())
    }

    #[test]
    fn dpt251_rgbw_partial_validity() -> Result<(), Box<dyn std::error::Error>> {
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
        assert_eq!(encode(&dpt("251.600"), &decoded)?, payload);
        Ok(())
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

    #[test]
    fn test_decode_scaled_percent_v16() -> Result<(), Box<dyn std::error::Error>> {
        let v = decode(&dpt("8.010"), &[0x13, 0x88]);
        assert_eq!(
            v,
            TypedValue::Scaled {
                count: 5000,
                decimals: 2,
                unit: "%"
            }
        );
        assert_eq!(v.to_string(), "50.00 %");
        assert_eq!(v.scaled_f64(), Some(50.0));
        assert_eq!(decode(&dpt("8.010"), &[0xEC, 0x78]).to_string(), "-50.00 %");
        // 7FFFh is the 8.010 invalid marker (03_07_02 §3.9.1): Raw, not 327.67 %.
        assert_eq!(
            decode(&dpt("8.010"), &[0x7F, 0xFF]),
            TypedValue::Raw(vec![0x7F, 0xFF])
        );
        // 8.001 is a plain count and keeps 7FFFh as a number.
        assert_eq!(
            decode(&dpt("8.001"), &[0x7F, 0xFF]),
            TypedValue::Signed {
                value: 32767,
                unit: Some("pulses")
            }
        );
        Ok(())
    }

    #[test]
    fn test_encode_scaled_percent_v16() -> Result<(), Box<dyn std::error::Error>> {
        let d = dpt("8.010");
        assert_eq!(encode(&d, &parse_value(&d, "50 %")?)?, vec![0x13, 0x88]);
        assert_eq!(encode(&d, &parse_value(&d, "50%")?)?, vec![0x13, 0x88]);
        assert_eq!(encode(&d, &parse_value(&d, "50")?)?, vec![0x13, 0x88]);
        assert_eq!(encode(&d, &parse_value(&d, "-327.68")?)?, vec![0x80, 0x00]);
        assert_eq!(encode(&d, &parse_value(&d, "327.66 %")?)?, vec![0x7F, 0xFE]);
        // 327.67 % would be the invalid marker; never write it.
        assert!(matches!(
            parse_value(&d, "327.67"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        assert!(matches!(
            parse_value(&d, "400 %"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        // Finer than 0.01 % is refused, not rounded.
        assert!(matches!(
            parse_value(&d, "50.005"),
            Err(ParseValueError::Invalid { .. })
        ));
        assert!(matches!(
            encode(
                &d,
                &TypedValue::Scaled {
                    count: 0x7FFF,
                    decimals: 2,
                    unit: "%"
                }
            ),
            Err(EncodeError::OutOfRange { .. })
        ));
        // A raw count is ambiguous for a scaled sub-type and refused.
        assert!(matches!(
            encode(
                &d,
                &TypedValue::Signed {
                    value: 50,
                    unit: None
                }
            ),
            Err(EncodeError::Mismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_decode_scaled_time_periods() {
        assert_eq!(decode(&dpt("7.004"), &[0, 10]).to_string(), "1.0 s");
        assert_eq!(decode(&dpt("7.004"), &[0, 10]).scaled_f64(), Some(1.0));
        assert_eq!(decode(&dpt("7.003"), &[0, 150]).to_string(), "1.50 s");
        assert_eq!(decode(&dpt("8.003"), &[0xFF, 0x9C]).to_string(), "-1.00 s");
        assert_eq!(decode(&dpt("8.004"), &[0, 15]).to_string(), "1.5 s");
        // Resolution-1 sub-types stay plain counts, with their unit (#501).
        assert_eq!(
            decode(&dpt("7.005"), &[0, 10]),
            TypedValue::Unsigned {
                value: 10,
                unit: Some("s")
            }
        );
    }

    #[test]
    fn test_parse_value_scaled_time_periods() -> Result<(), Box<dyn std::error::Error>> {
        let d = dpt("7.004");
        assert_eq!(encode(&d, &parse_value(&d, "1.0 s")?)?, vec![0, 10]);
        assert_eq!(encode(&d, &parse_value(&d, "1.5s")?)?, vec![0, 15]);
        assert_eq!(encode(&d, &parse_value(&d, "1500 ms")?)?, vec![0, 15]);
        assert_eq!(encode(&d, &parse_value(&d, "6553.5")?)?, vec![0xFF, 0xFF]);
        assert!(matches!(
            parse_value(&d, "6553.6"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        assert!(matches!(
            parse_value(&d, "-1 s"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        assert!(matches!(
            parse_value(&d, "1550 ms"),
            Err(ParseValueError::Invalid { .. })
        ));
        let d = dpt("7.003");
        assert_eq!(encode(&d, &parse_value(&d, "1.5 s")?)?, vec![0, 150]);
        assert_eq!(encode(&d, &parse_value(&d, "20 ms")?)?, vec![0, 2]);
        let d = dpt("8.003");
        assert_eq!(encode(&d, &parse_value(&d, "-1 s")?)?, vec![0xFF, 0x9C]);
        let d = dpt("8.004");
        assert_eq!(encode(&d, &parse_value(&d, "-3276.8")?)?, vec![0x80, 0x00]);
        assert!(matches!(
            parse_value(&d, "3276.8"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        assert!(matches!(
            parse_value(&d, "abc"),
            Err(ParseValueError::Invalid { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_decode_scaled_flow_rate() -> Result<(), Box<dyn std::error::Error>> {
        let d = dpt("13.002");
        let v = decode(&d, &10000i32.to_be_bytes());
        assert_eq!(v.to_string(), "1.0000 m³/h");
        assert_eq!(v.scaled_f64(), Some(1.0));
        assert_eq!(
            encode(&d, &parse_value(&d, "1.0 m³/h")?)?,
            vec![0, 0, 0x27, 0x10]
        );
        assert_eq!(
            encode(&d, &parse_value(&d, "1 m3/h")?)?,
            vec![0, 0, 0x27, 0x10]
        );
        // The full 32-bit range round-trips exactly (no f32 rounding).
        let max = parse_value(&d, "214748.3647")?;
        assert_eq!(encode(&d, &max)?, i32::MAX.to_be_bytes().to_vec());
        assert_eq!(decode(&d, &i32::MAX.to_be_bytes()), max);
        assert!(matches!(
            parse_value(&d, "214748.3648"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        assert!(matches!(
            parse_value(&d, "99999999999999999999"),
            Err(ParseValueError::OutOfRange { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_parse_fixed_exact_decimals() {
        assert_eq!(parse_fixed("1.5", 2), Ok(150));
        assert_eq!(parse_fixed("-0.01", 2), Ok(-1));
        assert_eq!(parse_fixed("+.5", 1), Ok(5));
        assert_eq!(parse_fixed("2.500", 1), Ok(25));
        assert_eq!(parse_fixed("2.55", 1), Err(FixedError::Precision));
        assert_eq!(parse_fixed("", 1), Err(FixedError::Syntax));
        assert_eq!(parse_fixed("1e3", 1), Err(FixedError::Syntax));
        assert_eq!(parse_fixed("1.2.3", 1), Err(FixedError::Syntax));
    }
}
