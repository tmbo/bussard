//! Minimal, dependency-free RFC3339 UTC time formatting and parsing.
//!
//! The store needs a stable, lexicographically-sortable text timestamp and the
//! ability to read it back; the pretty formatter needs a `HH:MM:SS.mmm` clock.
//! Rather than pull a date-time crate (whose recent versions require a newer
//! toolchain), this module converts a [`SystemTime`] to/from a civil UTC time
//! using the standard proleptic-Gregorian day-count algorithms.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A civil UTC date-time broken out into fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    /// Full year (e.g. 2026).
    pub year: i64,
    /// Month 1–12.
    pub month: u32,
    /// Day of month 1–31.
    pub day: u32,
    /// Hour 0–23.
    pub hour: u32,
    /// Minute 0–59.
    pub minute: u32,
    /// Second 0–59.
    pub second: u32,
    /// Millisecond 0–999.
    pub millis: u32,
}

/// Converts a `SystemTime` into civil UTC fields.
///
/// Times before the Unix epoch clamp to the epoch (the monitor never sees them).
pub fn to_civil(ts: SystemTime) -> Civil {
    let dur = ts.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let total_secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();

    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let hour = (secs_of_day / 3600) as u32;
    let minute = ((secs_of_day % 3600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;

    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        millis,
    }
}

/// Days since the Unix epoch → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since the Unix epoch for a (year, month, day). Inverse of the above.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Formats a `SystemTime` as an RFC3339 UTC string with millisecond precision,
/// e.g. `2026-09-15T12:34:56.789Z`.
pub fn to_rfc3339(ts: SystemTime) -> String {
    let c = to_civil(ts);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second, c.millis
    )
}

/// Formats the `HH:MM:SS.mmm` UTC wall-clock portion of a `SystemTime`.
pub fn to_clock(ts: SystemTime) -> String {
    let c = to_civil(ts);
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        c.hour, c.minute, c.second, c.millis
    )
}

/// Parses an RFC3339 UTC timestamp produced by [`to_rfc3339`] back into a
/// `SystemTime`. Tolerates a trailing `Z` and optional fractional seconds;
/// anything unparseable defaults to the Unix epoch.
pub fn from_rfc3339(s: &str) -> SystemTime {
    parse_rfc3339(s).unwrap_or(UNIX_EPOCH)
}

/// The fallible inner parse.
fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    // Expected shape: YYYY-MM-DDTHH:MM:SS[.fff]Z
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let time = rest.strip_suffix('Z').unwrap_or(rest);

    let mut dp = date.split('-');
    let year: i64 = dp.next()?.parse().ok()?;
    let month: u32 = dp.next()?.parse().ok()?;
    let day: u32 = dp.next()?.parse().ok()?;

    let (hms, frac) = match time.split_once('.') {
        Some((hms, frac)) => (hms, Some(frac)),
        None => (time, None),
    };
    let mut tp = hms.split(':');
    let hour: u32 = tp.next()?.parse().ok()?;
    let minute: u32 = tp.next()?.parse().ok()?;
    let second: u32 = tp.next()?.parse().ok()?;

    let millis: u32 = match frac {
        Some(f) => {
            // Take up to three fractional digits, right-padding to milliseconds.
            let digits: String = f.chars().take_while(|c| c.is_ascii_digit()).collect();
            let mut m = 0u32;
            for (i, ch) in digits.chars().take(3).enumerate() {
                let d = ch.to_digit(10)?;
                m += d * 10u32.pow(2 - i as u32);
            }
            m
        }
        None => 0,
    };

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64;
    if secs < 0 {
        return Some(UNIX_EPOCH);
    }
    Some(UNIX_EPOCH + Duration::new(secs as u64, millis * 1_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats() {
        assert_eq!(to_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(to_clock(UNIX_EPOCH), "00:00:00.000");
    }

    #[test]
    fn known_instant() {
        // 2026-09-15T12:34:56.789Z.
        let secs = days_from_civil(2026, 9, 15) * 86_400 + 12 * 3600 + 34 * 60 + 56;
        let ts = UNIX_EPOCH + Duration::new(secs as u64, 789_000_000);
        assert_eq!(to_rfc3339(ts), "2026-09-15T12:34:56.789Z");
        assert_eq!(to_clock(ts), "12:34:56.789");
    }

    #[test]
    fn millis_render() {
        let ts = UNIX_EPOCH + Duration::from_millis(1_500);
        assert_eq!(to_rfc3339(ts), "1970-01-01T00:00:01.500Z");
    }

    #[test]
    fn roundtrip_various() {
        for &(secs, ms) in &[(0u64, 0u32), (1_726_403_696, 789), (1_000, 0), (86_400, 1)] {
            let ts = UNIX_EPOCH + Duration::new(secs, ms * 1_000_000);
            let text = to_rfc3339(ts);
            let back = from_rfc3339(&text);
            assert_eq!(back, ts, "roundtrip {text}");
        }
    }

    #[test]
    fn parse_tolerates_no_fraction() {
        let ts = from_rfc3339("2024-12-31T23:59:59Z");
        assert_eq!(to_rfc3339(ts), "2024-12-31T23:59:59.000Z");
    }

    #[test]
    fn parse_garbage_is_epoch() {
        assert_eq!(from_rfc3339("not a date"), UNIX_EPOCH);
    }
}
