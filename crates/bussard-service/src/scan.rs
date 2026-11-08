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
//! reports progress through the [`WalkEvent`] callback.

use std::path::Path;
use std::time::{Duration, Instant};

use bussard_mgmt::Timeouts;
use bussard_model::IndividualAddress;
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::schema::Device;
use bussard_secure::Key16;

use crate::bus::{BusService, L4Options};
use crate::identity::{self, Identity, ProbeMiss, SecureStatus};
use crate::line::{WalkEvent, walk};

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
    // Discovery: a negative con classifies absent (issue #45).
    bussard_model::dotenv::duration_ms(DISCOVERY_MS_ENV)
        .map_or_else(Timeouts::discovery, |wait| Timeouts::uniform(wait, 0, true))
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

    /// The range's addresses, in order.
    pub fn addresses(&self) -> Vec<IndividualAddress> {
        if self.from > self.to {
            return Vec::new();
        }
        (self.from..=self.to)
            .filter_map(|device| IndividualAddress::new(self.area, self.line, device).ok())
            .collect()
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

/// The row label of a secured device (issue #203); `None` for a
/// plain device.
pub fn secure_label(status: SecureStatus) -> Option<&'static str> {
    match status {
        SecureStatus::Plain => None,
        SecureStatus::Activated => Some("secured"),
        SecureStatus::ActivatedNoKey => {
            Some("secured, bussard has no tool key for it, so its product was not read")
        }
        SecureStatus::KeyRefused => Some("secured, did not accept the tool key bussard has for it"),
    }
}

/// What one probe of a sweep returned: the device, or why there was none.
pub type ProbeOutcome = Result<(Identity, SecureStatus), ProbeMiss>;

/// Sweeps every device address of `range`, returning the responders.
///
/// One [`BusService`] is shared for the whole sweep; each probe leases it
/// for its connection-oriented session (TP1 etiquette: one open connection
/// at a time), releasing the lease before the next address. `source` is the
/// checked source address; `key_for` gives the tool key of a keyring-listed
/// address; `on_event` hears each probe start and end ([`walk`]).
pub async fn sweep(
    service: &BusService,
    range: LineRange,
    source: IndividualAddress,
    key_for: &(dyn Fn(IndividualAddress) -> Option<Key16> + Sync),
    on_event: &mut (dyn FnMut(WalkEvent<'_, ProbeOutcome>) + Send),
) -> Sweep {
    let started = Instant::now();
    let options = L4Options::discovery(source);
    let walked = walk(
        &range.addresses(),
        Result::is_ok,
        |addr| identity::probe_classified(service, addr, &options, key_for(addr)),
        on_event,
    )
    .await;
    let mut found = Vec::new();
    let mut timings = Vec::with_capacity(walked.len());
    for step in walked {
        let miss = match step.outcome {
            Ok((identity, status)) => {
                found.push(Found::from_identity(identity, status));
                None
            }
            Err(miss) => Some(miss),
        };
        timings.push(AddressTiming {
            address: step.address,
            elapsed: step.elapsed,
            miss,
        });
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

/// One probed address of a scan: how long the probe took and its outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AddressRow {
    /// The address.
    pub address: String,
    /// The probe time in milliseconds.
    pub ms: u128,
    /// `present`, or why nothing answered.
    pub outcome: &'static str,
}

/// The timing of a scan (issue #45): the counts and one row per address.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanTiming {
    /// Addresses probed.
    pub addresses: usize,
    /// The sweep's wall-clock time in milliseconds.
    pub total_ms: u128,
    /// Addresses the interface reported absent at once.
    pub absent_negative_confirmation: usize,
    /// Addresses that did not answer in time.
    pub absent_timeout: usize,
    /// Addresses that refused the connection.
    pub refused: usize,
    /// One row per probed address.
    pub per_address: Vec<AddressRow>,
}

impl ScanTiming {
    /// The timing of `swept`.
    pub fn of(swept: &Sweep) -> ScanTiming {
        ScanTiming {
            addresses: swept.timings.len(),
            total_ms: swept.elapsed.as_millis(),
            absent_negative_confirmation: swept.count(ProbeMiss::NegativeConfirmation),
            absent_timeout: swept.count(ProbeMiss::Timeout),
            refused: swept.count(ProbeMiss::Refused),
            per_address: swept
                .timings
                .iter()
                .map(|t| AddressRow {
                    address: t.address.to_string(),
                    ms: t.elapsed.as_millis(),
                    outcome: t.outcome(),
                })
                .collect(),
        }
    }
}

/// One device that answered a scan, name first.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanDevice {
    /// Its name in the project.
    pub name: Option<String>,
    /// Its address.
    pub address: String,
    /// Whether the project has it (`None` without a project).
    pub known: Option<bool>,
    /// Its mask, hex.
    pub mask: String,
    /// The system the mask names.
    pub system_type: &'static str,
    /// Its manufacturer.
    pub manufacturer: Option<String>,
    /// Its manufacturer id, `0x0083`.
    pub manufacturer_id: Option<String>,
    /// Its order number.
    pub order_number: Option<String>,
    /// Its serial, hex.
    pub serial: Option<String>,
    /// How it was read with respect to KNX Data Secure, for an activated
    /// device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<&'static str>,
    /// What that means, for an activated device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<&'static str>,
    /// Its identity against `bussard.lock`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityCheck>,
}

/// A project device that did not answer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Missing {
    /// Its name.
    pub name: String,
    /// Its address.
    pub address: String,
}

/// A line scan (`bussard scan --json`, the result of a `knx_find_devices`
/// job) in one shape (issue #904).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanOutcome {
    /// Always `true`: the sweep ran.
    pub ok: bool,
    /// The line, `1.1`.
    pub line: String,
    /// The first device number probed.
    pub from: u8,
    /// The last device number probed.
    pub to: u8,
    /// The devices that answered.
    pub devices: Vec<ScanDevice>,
    /// How many devices the project has (0 without one).
    pub model_device_count: usize,
    /// Responders the project does not have.
    pub not_in_model: Vec<String>,
    /// Project devices in the probed range that did not answer.
    pub missing_from_bus: Vec<Missing>,
    /// The timing.
    pub timing: ScanTiming,
}

impl ScanOutcome {
    /// The scan of `range` that found `report` (identities filled in) in
    /// `timing`; `model` names the devices.
    pub fn new(
        range: LineRange,
        report: &ScanReport,
        timing: ScanTiming,
        model: Option<&bussard_model::Model>,
    ) -> ScanOutcome {
        let name_of = |addr: IndividualAddress| -> Option<String> {
            model?
                .devices
                .get(&addr)
                .map(|d| d.device.name.clone())
                .filter(|n| !n.is_empty())
        };
        ScanOutcome {
            ok: true,
            line: format!("{}.{}", range.area, range.line),
            from: range.from,
            to: range.to,
            devices: report
                .found
                .iter()
                .map(|f| ScanDevice {
                    name: name_of(f.address),
                    address: f.address.to_string(),
                    known: report.known(f.address),
                    mask: format!("{:04X}", f.mask),
                    system_type: f.system_type(),
                    manufacturer: f.manufacturer_id.map(bussard_mgmt::manufacturers::display),
                    manufacturer_id: f.manufacturer_id.map(|id| format!("{id:#06X}")),
                    order_number: f.order.clone(),
                    serial: f.serial.as_deref().map(bussard_model::text::hex),
                    secure: f.secure.activated().then(|| f.secure.as_str()),
                    secure_note: secure_label(f.secure).filter(|_| f.secure.activated()),
                    identity: f.identity.clone(),
                })
                .collect(),
            model_device_count: report.model_device_count,
            not_in_model: report
                .not_in_model
                .iter()
                .map(ToString::to_string)
                .collect(),
            missing_from_bus: report
                .missing
                .iter()
                .filter(|(addr, _)| range.contains(*addr))
                .map(|(addr, name)| Missing {
                    name: name.clone(),
                    address: addr.to_string(),
                })
                .collect(),
            timing,
        }
    }
}

impl crate::report::Report for ScanOutcome {
    const SCHEMA: u32 = 2;

    fn summary(&self, _model: &bussard_model::Model) -> Option<String> {
        let line = &self.line;
        let probed = self.timing.addresses;
        let answered: Vec<String> = self
            .devices
            .iter()
            .map(|d| match &d.name {
                Some(name) => format!("{name} ({})", d.address),
                None => format!("{} (not in the model)", d.address),
            })
            .collect();
        let mut out = if answered.is_empty() {
            format!("No device answered on line {line} ({probed} addresses probed).")
        } else {
            format!(
                "{} device(s) answered on line {line} ({probed} addresses probed): {}.",
                answered.len(),
                answered.join(", ")
            )
        };
        if !self.missing_from_bus.is_empty() {
            let names: Vec<String> = self
                .missing_from_bus
                .iter()
                .map(|m| {
                    if m.name.is_empty() {
                        m.address.clone()
                    } else {
                        format!("{} ({})", m.name, m.address)
                    }
                })
                .collect();
            out.push_str(&format!(
                " {} model device(s) in the scanned range did not answer: {}.",
                names.len(),
                names.join(", ")
            ));
        }
        Some(out)
    }

    fn next_step(&self) -> Option<String> {
        Some(
            "Tell the human the summary and the devices by name. knx_show_device with `live: \
             true` reads one device's live status (identity, and for an IP interface its IP \
             settings and tunnels)."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
