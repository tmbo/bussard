//! The line scan: sequential device discovery on one line (issues #45, #203,
//! #747).
//!
//! Sweeps `LINE.from` … `LINE.to` one connection at a time (TP1 etiquette:
//! most gateways will not multiplex connection-oriented sessions), reading
//! each responding device's mask version, manufacturer, serial and order info
//! with [`identity::probe_classified`]. [`cross_reference`] then sets the
//! responders against the model: which are known, which are unexpected, and
//! which model devices did not answer.
//!
//! `bussard scan` and the MCP server's `knx_find_devices` both run
//! [`sweep`]; the CLI prints the table and the tool returns JSON, and each
//! reports progress through the [`SweepEvent`] callback.

use std::path::Path;
use std::time::{Duration, Instant};

use bussard_mgmt::Timeouts;
use bussard_model::IndividualAddress;
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::schema::Device;
use bussard_secure::Key16;

use crate::bus::{Authorize, BusService, L4Options, SourcePolicy};
use crate::identity::{self, Identity, ProbeMiss, SecureStatus};

/// Environment variable that overrides the per-attempt discovery timeout in
/// milliseconds. Set only by integration tests to keep a mock sweep fast;
/// unset in normal use so the standard [`Timeouts::discovery`] budget
/// applies.
pub const DISCOVERY_MS_ENV: &str = "BUSSARD_SCAN_DISCOVERY_MS";

/// Per-address time budget used to estimate the sweep duration up front. A
/// present device answers in well under this; an absent one costs about
/// `2 × discovery ack_timeout` on an interface that reports no negative
/// `L_Data.con` (with one, tens of milliseconds, issue #45). The estimate
/// stays the worst case.
pub const PER_ADDRESS_ESTIMATE: Duration = Duration::from_millis(3200);

/// The discovery timeout budget, honouring [`DISCOVERY_MS_ENV`] when set.
pub fn discovery_timeouts() -> Timeouts {
    match bussard_model::dotenv::var(DISCOVERY_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(ms) => Timeouts {
            ack_timeout: Duration::from_millis(ms),
            max_repetitions: 0,
            response_timeout: Duration::from_millis(ms),
            // Discovery: a negative con classifies absent (issue #45).
            absent_on_negative_confirmation: true,
        },
        None => Timeouts::discovery(),
    }
}

/// The session options of a probe: the sweep's checked source, the discovery
/// timeouts, and no authorize at connect (the probe authorizes after the
/// descriptor read, as ETS does).
pub fn probe_options(source: IndividualAddress) -> L4Options {
    L4Options {
        source: SourcePolicy::Known(source),
        timeouts: discovery_timeouts(),
        authorize: Authorize::Skip,
        ..L4Options::default()
    }
}

/// Why a line could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineError {
    /// Fewer than two dot-separated parts.
    #[error("invalid line {0:?}; expected area.line like \"1.1\"")]
    Shape(String),
    /// The area part is not a number.
    #[error("invalid area in {0:?}")]
    Area(String),
    /// The line part is not a number.
    #[error("invalid line in {0:?}")]
    Line(String),
    /// The area or the line is above 15.
    #[error("area and line must each be 0–15 (got {0:?})")]
    Range(String),
}

/// Parses a `area.line` (e.g. `1.1`) or a full `area.line.device` (ignoring
/// the device part) into `(area, line)`.
///
/// # Errors
///
/// A [`LineError`] naming what is wrong with `line`.
pub fn parse_line(line: &str) -> Result<(u8, u8), LineError> {
    let parts: Vec<&str> = line.split('.').collect();
    if parts.len() < 2 {
        return Err(LineError::Shape(line.to_string()));
    }
    let area: u8 = parts[0]
        .parse()
        .map_err(|_| LineError::Area(line.to_string()))?;
    let line_no: u8 = parts[1]
        .parse()
        .map_err(|_| LineError::Line(line.to_string()))?;
    if area > 15 || line_no > 15 {
        return Err(LineError::Range(line.to_string()));
    }
    Ok((area, line_no))
}

/// The addresses one sweep probes: `area.line.from` … `area.line.to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineRange {
    /// The area.
    pub area: u8,
    /// The line.
    pub line: u8,
    /// The first device number.
    pub from: u8,
    /// The last device number (inclusive).
    pub to: u8,
}

impl LineRange {
    /// How many addresses the range holds (zero when `from > to`).
    pub fn count(&self) -> usize {
        if self.from > self.to {
            0
        } else {
            usize::from(self.to - self.from) + 1
        }
    }

    /// Whether `address` is one of the range's addresses.
    pub fn contains(&self, address: IndividualAddress) -> bool {
        address.area() == self.area
            && address.line() == self.line
            && (self.from..=self.to).contains(&address.device())
    }

    /// The worst-case sweep time ([`PER_ADDRESS_ESTIMATE`] per address).
    pub fn estimate(&self) -> Duration {
        PER_ADDRESS_ESTIMATE * u32::try_from(self.count()).unwrap_or(u32::MAX)
    }
}

/// How one swept address turned out, and how long its probe took (issue
/// #45).
#[derive(Debug, Clone, Copy)]
pub struct AddressTiming {
    /// The probed address.
    pub address: IndividualAddress,
    /// How long the probe took.
    pub elapsed: Duration,
    /// `None` for a found device, the reason otherwise.
    pub miss: Option<ProbeMiss>,
}

impl AddressTiming {
    /// The stable `--json` spelling of the outcome.
    pub fn outcome(&self) -> &'static str {
        self.miss.map(ProbeMiss::as_str).unwrap_or("present")
    }
}

/// What a sweep produced: the responders plus the per-address timing.
#[derive(Debug, Default)]
pub struct Sweep {
    /// The devices that answered, in address order.
    pub found: Vec<Found>,
    /// One row per probed address.
    pub timings: Vec<AddressTiming>,
    /// The sweep's wall-clock time.
    pub elapsed: Duration,
}

impl Sweep {
    /// How many addresses a given miss classified.
    pub fn count(&self, miss: ProbeMiss) -> usize {
        self.timings.iter().filter(|t| t.miss == Some(miss)).count()
    }

    /// The one-line summary: "N addresses in T s (absent by negative
    /// confirmation: M, by timeout: K)".
    pub fn summary(&self) -> String {
        format!(
            "{} addresses in {:.1} s (absent by negative confirmation: {}, by timeout: {})",
            self.timings.len(),
            self.elapsed.as_secs_f64(),
            self.count(ProbeMiss::NegativeConfirmation),
            self.count(ProbeMiss::Timeout)
        )
    }

    /// The `timing` object of `scan --json` (issue #45): the summary counts
    /// plus one row per swept address with its probe time and outcome.
    pub fn timing_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "addresses": self.timings.len(),
            "total_ms": self.elapsed.as_millis(),
            "absent_negative_confirmation": self.count(ProbeMiss::NegativeConfirmation),
            "absent_timeout": self.count(ProbeMiss::Timeout),
            "refused": self.count(ProbeMiss::Refused),
            "per_address": self
                .timings
                .iter()
                .map(|t| json!({
                    "address": t.address.to_string(),
                    "ms": t.elapsed.as_millis(),
                    "outcome": t.outcome(),
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// A single discovered device and everything read from it.
#[derive(Debug, Clone)]
pub struct Found {
    /// The device address.
    pub address: IndividualAddress,
    /// The mask version.
    pub mask: u16,
    /// The KNX manufacturer id, when readable.
    pub manufacturer_id: Option<u16>,
    /// The serial number, when readable.
    pub serial: Option<Vec<u8>>,
    /// The order info, when readable.
    pub order: Option<String>,
    /// How the device was identified with respect to KNX Data Secure
    /// (issue #203).
    pub secure: SecureStatus,
    /// Its identity against `bussard.lock` (issue #228, item 5), filled in
    /// after the sweep with [`observe_identity`].
    pub identity: Option<IdentityCheck>,
}

impl Found {
    /// A found device from a probe's identity and status.
    pub fn from_identity(identity: Identity, secure: SecureStatus) -> Found {
        Found {
            address: identity.address,
            mask: identity.mask,
            manufacturer_id: identity.manufacturer_id,
            serial: identity.serial,
            order: identity.order,
            secure,
            identity: None,
        }
    }

    /// The system type of the mask, `-` for a mask a Data Secure device
    /// hides.
    pub fn system_type(&self) -> &'static str {
        if self.secure.activated() && self.mask == identity::HIDDEN_MASK {
            "-"
        } else {
            bussard_mgmt::system_type(self.mask)
        }
    }
}

/// The row label of a Data Secure-activated device (issue #203); `None` for a
/// plain device.
pub fn secure_label(status: SecureStatus) -> Option<&'static str> {
    match status {
        SecureStatus::Plain => None,
        SecureStatus::Activated => Some("Data Secure activated"),
        SecureStatus::ActivatedNoKey => {
            Some("Data Secure activated (mask hidden), no tool key in the keyring")
        }
        SecureStatus::KeyRefused => {
            Some("Data Secure activated (mask hidden), the keyring's tool key was not accepted")
        }
    }
}

/// What the sweep reports while it runs.
#[derive(Debug, Clone, Copy)]
pub enum SweepEvent<'a> {
    /// The sweep is about to probe `address`; `found` devices answered so
    /// far.
    Probing {
        /// The address probed next.
        address: IndividualAddress,
        /// Devices found so far.
        found: usize,
    },
    /// The probe of one address ended; `found` devices answered so far.
    Probed {
        /// How the address turned out.
        timing: &'a AddressTiming,
        /// Devices found so far, this one included.
        found: usize,
    },
}

/// Sweeps every device address of `range`, returning the responders.
///
/// One [`BusService`] is shared for the whole sweep; each probe leases it
/// for its connection-oriented session (TP1 etiquette: one open connection
/// at a time), releasing the lease before the next address. `source` is the
/// checked source address; `key_for` gives the tool key of a keyring-listed
/// address; `on_event` hears each probe start and end.
pub async fn sweep(
    service: &BusService,
    range: LineRange,
    source: IndividualAddress,
    key_for: &(dyn Fn(IndividualAddress) -> Option<Key16> + Sync),
    on_event: &mut (dyn FnMut(SweepEvent<'_>) + Send),
) -> Sweep {
    let started = Instant::now();
    let mut found = Vec::new();
    let mut timings = Vec::new();
    if range.from <= range.to {
        for device in range.from..=range.to {
            let addr = match IndividualAddress::new(range.area, range.line, device) {
                Ok(a) => a,
                Err(_) => continue,
            };
            on_event(SweepEvent::Probing {
                address: addr,
                found: found.len(),
            });
            let probe_started = Instant::now();
            let outcome =
                identity::probe_classified(service, addr, &probe_options(source), key_for(addr))
                    .await;
            let miss = match outcome {
                Ok((identity, status)) => {
                    found.push(Found::from_identity(identity, status));
                    None
                }
                Err(miss) => Some(miss),
            };
            let timing = AddressTiming {
                address: addr,
                elapsed: probe_started.elapsed(),
                miss,
            };
            on_event(SweepEvent::Probed {
                timing: &timing,
                found: found.len(),
            });
            timings.push(timing);
        }
    }
    Sweep {
        found,
        timings,
        elapsed: started.elapsed(),
    }
}

/// The swept devices set against the model.
#[derive(Debug)]
pub struct ScanReport {
    /// The responders.
    pub found: Vec<Found>,
    /// Addresses that responded but are not in the model.
    pub not_in_model: Vec<IndividualAddress>,
    /// Model devices (name) that did not respond, keyed by address.
    pub missing: Vec<(IndividualAddress, String)>,
    /// Whether a model was loaded at all (drives cross-reference columns).
    pub have_model: bool,
    /// The number of devices in the loaded model's inventory. Zero with
    /// `have_model` true means a model loaded but has no `devices/*.toml`:
    /// the missing/known cross-reference is then vacuous and must not be
    /// reported as "all model devices responded" (issue #30).
    pub model_device_count: usize,
}

impl ScanReport {
    /// Whether a responder is a model device: `None` without a model.
    pub fn known(&self, address: IndividualAddress) -> Option<bool> {
        self.have_model
            .then(|| !self.not_in_model.contains(&address))
    }
}

/// Cross-references the discovered devices against the loaded model. Every
/// model device that did not answer is listed as missing, on any line; a
/// caller that reports only the swept range filters `missing` with
/// [`LineRange::contains`].
pub fn cross_reference(found: Vec<Found>, model: Option<&bussard_model::Model>) -> ScanReport {
    let have_model = model.is_some();
    let mut not_in_model = Vec::new();
    let mut missing = Vec::new();

    if let Some(model) = model {
        for f in &found {
            if !model.devices.contains_key(&f.address) {
                not_in_model.push(f.address);
            }
        }
        for (addr, loaded) in &model.devices {
            if !found.iter().any(|f| &f.address == addr) {
                missing.push((*addr, loaded.device.name.clone()));
            }
        }
    }

    let model_device_count = model.map(|m| m.devices.len()).unwrap_or(0);

    ScanReport {
        found,
        not_in_model,
        missing,
        have_model,
        model_device_count,
    }
}

/// The identity verdict for a device a probe read only the mask of (`scan`,
/// `assign`, `audit --live`), with the application id the stored facts carry
/// for it. Stored facts under another mask are stale: they are removed, so
/// the next connection reads them again (the facts refresh of a command that
/// opens no management connection).
pub fn observe_identity(
    dir: &Path,
    model_loaded: bool,
    target: IndividualAddress,
    mask: u16,
    device: Option<&Device>,
) -> IdentityCheck {
    let mask_text = bussard_model::facts::format_mask(mask);
    let stored = if model_loaded {
        bussard_model::facts::load_facts(dir, target).ok().flatten()
    } else {
        None
    };
    let application_id = match stored {
        Some(record) if record.mask.eq_ignore_ascii_case(&mask_text) => record.application_id,
        Some(_) if mask != identity::HIDDEN_MASK => {
            let _ = std::fs::remove_file(bussard_model::facts::facts_path(dir, target));
            None
        }
        _ => None,
    };
    IdentityCheck::compare(
        device,
        ReportedIdentity {
            mask: mask_text,
            application_id,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_accepts_area_line() -> Result<(), LineError> {
        assert_eq!(parse_line("1.1")?, (1, 1));
        assert_eq!(parse_line("15.15")?, (15, 15));
        // A full address ignores the device part.
        assert_eq!(parse_line("2.3.55")?, (2, 3));
        Ok(())
    }

    #[test]
    fn test_parse_line_rejects_bad_input() {
        assert!(matches!(parse_line("1"), Err(LineError::Shape(_))));
        assert!(matches!(parse_line("16.1"), Err(LineError::Range(_))));
        assert!(matches!(parse_line("x.y"), Err(LineError::Area(_))));
    }

    #[test]
    fn test_line_range_count_and_estimate() {
        let full = LineRange {
            area: 1,
            line: 1,
            from: 0,
            to: 255,
        };
        assert_eq!(full.count(), 256);
        assert_eq!(full.estimate(), PER_ADDRESS_ESTIMATE * 256);
        let empty = LineRange {
            from: 5,
            to: 4,
            ..full
        };
        assert_eq!(empty.count(), 0);
    }

    #[test]
    fn test_line_range_contains_only_its_addresses() -> Result<(), String> {
        let range = LineRange {
            area: 1,
            line: 1,
            from: 3,
            to: 6,
        };
        let ia = |s: &str| s.parse::<IndividualAddress>().map_err(|e| e.to_string());
        assert!(range.contains(ia("1.1.3")?));
        assert!(range.contains(ia("1.1.6")?));
        assert!(!range.contains(ia("1.1.7")?));
        assert!(!range.contains(ia("1.2.4")?));
        Ok(())
    }
}
