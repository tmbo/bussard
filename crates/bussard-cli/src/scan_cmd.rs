//! The `bussard scan` subcommand: sequential device discovery on one line.
//!
//! Sweeps `LINE.0` … `LINE.255` one connection at a time (TP1 etiquette — most
//! gateways will not multiplex connection-oriented sessions), reading each
//! responding device's mask version, manufacturer, serial and order info. When a
//! model directory is present it cross-references the discovered devices against
//! `devices/*.toml`: which are known, which are unexpected, and which model
//! devices did not answer. That delta is the command's real value.
//!
//! The address range can be narrowed with `--from`/`--to` (defaults `0`/`255`),
//! which cuts the sweep time when you already know the device numbers of
//! interest — a full line is 256 serial probes. An absent address costs tens of
//! milliseconds on an interface that reports a negative `L_Data.con`, and up to
//! a couple of seconds (the ACK timeout and its repetition) on one that does not
//! (issue #45). The summary and `--json`'s `timing` say which applied.
//!
//! It always exits 0 — it is a report, not a check.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use bussard_mgmt::{DeviceConnection, L4Channel, Timeouts, manufacturers, system_type};
use bussard_model::IndividualAddress;
use bussard_secure::Key16;
use bussard_service::identity::{self, Identity, ProbeMiss, SecureStatus};
use bussard_service::secure::ToolKeys;
use bussard_service::{Authorize, BusService, L4Options, SourcePolicy, WritePolicy};

use crate::assign_cmd::hex;
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, load_model_required, open_service, resolve_config,
};

/// Environment variable that overrides the per-attempt discovery timeout in
/// milliseconds. Set only by the integration test to keep a full-line mock sweep
/// fast; unset in normal use so the standard [`Timeouts::discovery`] budget
/// applies.
const DISCOVERY_MS_ENV: &str = "BUSSARD_SCAN_DISCOVERY_MS";

/// The discovery timeout budget, honouring [`DISCOVERY_MS_ENV`] when set.
pub(crate) fn discovery_timeouts() -> Timeouts {
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

/// Per-address time budget used to estimate the sweep duration up front. A
/// present device answers in well under this; an absent one costs about
/// `2 × discovery ack_timeout` on an interface that reports no negative
/// `L_Data.con` (with one, tens of milliseconds, issue #45). The estimate stays
/// the worst case.
const PER_ADDRESS_ESTIMATE: Duration = Duration::from_millis(3200);

/// How one swept address turned out, and how long its probe took (issue #45).
#[derive(Debug, Clone, Copy)]
struct AddressTiming {
    address: IndividualAddress,
    elapsed: Duration,
    /// `None` for a found device, the reason otherwise.
    miss: Option<ProbeMiss>,
}

impl AddressTiming {
    /// The stable `--json` spelling of the outcome.
    fn outcome(&self) -> &'static str {
        self.miss.map(ProbeMiss::as_str).unwrap_or("present")
    }
}

/// What a sweep produced: the responders plus the per-address timing.
#[derive(Debug, Default)]
struct Sweep {
    found: Vec<Found>,
    timings: Vec<AddressTiming>,
    elapsed: Duration,
}

impl Sweep {
    /// How many addresses a given miss classified.
    fn count(&self, miss: ProbeMiss) -> usize {
        self.timings.iter().filter(|t| t.miss == Some(miss)).count()
    }

    /// The one-line summary: "N addresses in T s (absent by negative
    /// confirmation: M, by timeout: K)".
    fn summary(&self) -> String {
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
pub(crate) struct Found {
    pub(crate) address: IndividualAddress,
    pub(crate) mask: u16,
    pub(crate) manufacturer_id: Option<u16>,
    pub(crate) serial: Option<Vec<u8>>,
    pub(crate) order: Option<String>,
    /// How the device was identified with respect to KNX Data Secure
    /// (issue #203).
    pub(crate) secure: SecureStatus,
    /// Its identity against `bussard.lock` (issue #228, item 5), filled in
    /// after the sweep.
    pub(crate) identity: Option<bussard_model::identity::IdentityCheck>,
}

impl Found {
    /// A found device from a probe's identity and status.
    fn from_identity(identity: Identity, secure: SecureStatus) -> Found {
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
}

/// The row label of a Data Secure-activated device (issue #203); `None` for a
/// plain device.
pub(crate) fn secure_label(status: SecureStatus) -> Option<&'static str> {
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

/// The final cross-referenced report.
struct Report {
    found: Vec<Found>,
    /// Addresses that responded but are not in the model.
    not_in_model: Vec<IndividualAddress>,
    /// Model devices (name) that did not respond, keyed by address.
    missing: Vec<(IndividualAddress, String)>,
    /// Whether a model was loaded at all (drives cross-reference columns).
    have_model: bool,
    /// The number of devices in the loaded model's inventory. Zero with
    /// `have_model` true means a model loaded but has no `devices/*.toml` — the
    /// missing/known cross-reference is then vacuous and must not be reported as
    /// "all model devices responded" (issue #30).
    model_device_count: usize,
}

/// Runs `bussard scan`.
pub fn run(
    line: &str,
    from: u8,
    to: u8,
    dir: &Path,
    json: bool,
    keyring: Option<&Path>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let (area, line_no) = parse_line(line)?;
    if from > to {
        return Err(anyhow!(
            "invalid range: --from {from} is greater than --to {to}"
        ));
    }
    // A management command: a present-but-broken model is a hard error.
    let model = load_model_required(dir)?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // The keyring's tool keys (issue #203): a listed device is identified over
    // A_SecureData. Decrypted once for the whole sweep.
    let keys = ToolKeys::load(crate::secure_key::ToolKeySource {
        keyring,
        tool_key: None,
    })
    .context("loading the keyring for scan")?;
    // Only a listed address gets a key; any other device is read in the clear
    // (an activated one then shows the hidden mask and its label).
    let key_for = |addr: IndividualAddress| -> Option<Key16> {
        keys.lists(addr).then(|| keys.tool_key(addr)).flatten()
    };

    // Up-front estimate (address count × per-address budget).
    let count = to as u32 - from as u32 + 1;
    let estimate = PER_ADDRESS_ESTIMATE * count;
    eprintln!(
        "scanning line {area}.{line_no}.{from}–{to} sequentially — estimated up to {}m{:02}s on TP1",
        estimate.as_secs() / 60,
        estimate.as_secs() % 60
    );

    let runtime = tokio::runtime::Runtime::new()?;
    let swept = runtime.block_on(async move {
        // Read-only on the bus. Present the tunnel-assigned individual address
        // as the source; devices ignore connection-oriented frames from any
        // other source, and the gateway only routes replies back to the
        // assigned address (issue #30). Fall back to 0.0.255 on a routing
        // transport that assigns none.
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let source = checked_source_or_close(&service, &overrides).await?;
        // Guard the sweep with Ctrl-C: on interrupt, stop sweeping and fall
        // through to a clean close so the gateway tunnel slot is released
        // rather than leaked (~2 min hold) — see issue #31.
        let swept = tokio::select! {
            swept = sweep(&service, area, line_no, from, to, source, json, &key_for) => swept,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Sweep::default()
            }
        };
        service.close().await;
        anyhow::Ok(swept)
    })?;

    let timing = timing_json(&swept);
    let mut report = cross_reference(swept.found, model.as_ref());
    // The identity verdict per device, against the lock and the stored facts
    // (issue #228, item 5); stale facts are dropped for the next connection.
    for f in &mut report.found {
        let device = model
            .as_ref()
            .and_then(|m| m.devices.get(&f.address))
            .map(|d| &d.device);
        f.identity = Some(crate::device_facts::observe(
            dir,
            model.is_some(),
            f.address,
            f.mask,
            device,
        ));
    }

    if json {
        print_json(&report, timing)?;
    } else {
        print_table(&report);
    }
    Ok(ExitCode::SUCCESS)
}

/// Sweeps every device address on the line, returning the responders.
///
/// One [`Bus`] is shared for the whole sweep; each probe leases it for its
/// connection-oriented session (TP1 etiquette — one open connection at a time),
/// releasing the lease before the next address. `key_for` gives the tool key
/// of a keyring-listed address.
#[allow(clippy::too_many_arguments)] // one call site; the sweep's inputs, spelled out
async fn sweep(
    service: &BusService,
    area: u8,
    line_no: u8,
    from: u8,
    to: u8,
    source: IndividualAddress,
    json: bool,
    key_for: &dyn Fn(IndividualAddress) -> Option<Key16>,
) -> Sweep {
    let started = Instant::now();
    let mut found = Vec::new();
    let mut timings = Vec::new();
    // Progress to stderr (issue #147): a line rewritten in place, or the live
    // view on an interactive terminal.
    let display = crate::progress::SweepDisplay::new(
        "scanning",
        usize::from(to.saturating_sub(from)) + 1,
        json,
    );
    for device in from..=to {
        let addr = match IndividualAddress::new(area, line_no, device) {
            Ok(a) => a,
            Err(_) => continue,
        };
        display.probing(addr, found.len());

        let probe_started = Instant::now();
        let outcome =
            identity::probe_classified(service, addr, &probe_options(source), key_for(addr)).await;
        let miss = match outcome {
            Ok((identity, status)) => {
                found.push(Found::from_identity(identity, status));
                None
            }
            Err(miss) => Some(miss),
        };
        timings.push(AddressTiming {
            address: addr,
            elapsed: probe_started.elapsed(),
            miss,
        });
        display.advance();
    }
    display.finish();
    let swept = Sweep {
        found,
        timings,
        elapsed: started.elapsed(),
    };
    eprintln!(
        "\rscan complete: {} device(s) found; {}",
        swept.found.len(),
        swept.summary()
    );
    swept
}

/// The `timing` object of `--json` (issue #45): the summary counts plus one row
/// per swept address with its probe time and outcome.
fn timing_json(swept: &Sweep) -> serde_json::Value {
    use serde_json::json;
    json!({
        "addresses": swept.timings.len(),
        "total_ms": swept.elapsed.as_millis(),
        "absent_negative_confirmation": swept.count(ProbeMiss::NegativeConfirmation),
        "absent_timeout": swept.count(ProbeMiss::Timeout),
        "refused": swept.count(ProbeMiss::Refused),
        "per_address": swept
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

/// The session options of a probe: the sweep's checked source, the discovery
/// timeouts, and no authorize at connect (the probe authorizes after the
/// descriptor read, as ETS does).
pub(crate) fn probe_options(source: IndividualAddress) -> L4Options {
    L4Options {
        source: SourcePolicy::Known(source),
        timeouts: discovery_timeouts(),
        authorize: Authorize::Skip,
        ..L4Options::default()
    }
}

/// Probes one address in the clear: connect, read the descriptor, and, if
/// present, best-effort read manufacturer/serial/order. Returns `None` for an
/// absent or refusing device. A Data Secure-activated device answers mask
/// `FFFF`; the row is then [`SecureStatus::ActivatedNoKey`].
pub(crate) async fn probe(
    service: &BusService,
    addr: IndividualAddress,
    source: IndividualAddress,
) -> Option<Found> {
    probe_with_key(service, addr, source, None).await
}

/// [`probe`] with the address's tool key, if the keyring lists it: the
/// descriptor and the property reads then ride A_SecureData (issue #203).
pub(crate) async fn probe_with_key(
    service: &BusService,
    addr: IndividualAddress,
    source: IndividualAddress,
    tool_key: Option<Key16>,
) -> Option<Found> {
    let (identity, status) =
        identity::probe(service, addr, &probe_options(source), tool_key).await?;
    Some(Found::from_identity(identity, status))
}

/// Reads a 2-byte property as a `u16`, returning `None` on any failure.
pub(crate) async fn read_u16<Ch: L4Channel>(
    dev: &mut DeviceConnection<Ch>,
    pid: u8,
) -> Option<u16> {
    match dev.read_device_property(pid).await {
        Ok(bytes) if bytes.len() >= 2 => Some(u16::from_be_bytes([bytes[0], bytes[1]])),
        _ => None,
    }
}

/// Cross-references the discovered devices against the loaded model.
fn cross_reference(found: Vec<Found>, model: Option<&bussard_model::Model>) -> Report {
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

    Report {
        found,
        not_in_model,
        missing,
        have_model,
        model_device_count,
    }
}

/// Parses a `area.line` (e.g. `1.1`) or a full `area.line.device` (ignoring the
/// device part) into `(area, line)`.
pub(crate) fn parse_line(line: &str) -> anyhow::Result<(u8, u8)> {
    let parts: Vec<&str> = line.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow!(
            "invalid line {line:?}; expected area.line like \"1.1\""
        ));
    }
    let area: u8 = parts[0]
        .parse()
        .map_err(|_| anyhow!("invalid area in {line:?}"))?;
    let line_no: u8 = parts[1]
        .parse()
        .map_err(|_| anyhow!("invalid line in {line:?}"))?;
    if area > 15 || line_no > 15 {
        return Err(anyhow!("area and line must each be 0–15 (got {line:?})"));
    }
    Ok((area, line_no))
}

/// Prints the aligned table plus a summary.
fn print_table(report: &Report) {
    if report.found.is_empty() {
        println!("no devices responded");
    } else {
        // Precompute the model-status column when a model is loaded.
        println!(
            "{:<9}  {:<6}  {:<9}  {:<14}  {:<16}  {:<5}",
            "IA", "MASK", "SYSTEM", "MANUFACTURER", "ORDER", "MODEL"
        );
        for f in &report.found {
            let manufacturer = f
                .manufacturer_id
                .map(manufacturers::display)
                .unwrap_or_else(|| "-".to_string());
            let order = f.order.clone().unwrap_or_else(|| "-".to_string());
            let status = if !report.have_model {
                "-".to_string()
            } else if report.not_in_model.contains(&f.address) {
                "NOT in model".to_string()
            } else {
                "known".to_string()
            };
            let system = if f.secure.activated() && f.mask == identity::HIDDEN_MASK {
                "-"
            } else {
                system_type(f.mask)
            };
            let label = secure_label(f.secure)
                .map(|l| format!("  {l}"))
                .unwrap_or_default();
            println!(
                "{:<9}  {:04X}    {:<9}  {:<14}  {:<16}  {}{label}",
                f.address.to_string(),
                f.mask,
                system,
                manufacturer,
                order,
                status
            );
        }
    }

    println!();
    println!("{} device(s) responded", report.found.len());
    for f in &report.found {
        if let Some(check) = f.identity.as_ref().filter(|c| c.is_drift()) {
            println!("{}", crate::device_facts::identity_line(f.address, check));
        }
    }
    for f in &report.found {
        if let Some(check) = f.identity.as_ref().filter(|c| c.is_drift()) {
            println!("{}", crate::device_facts::identity_line(f.address, check));
        }
    }
    if report.have_model {
        if report.model_device_count == 0 {
            // A model loaded but has no device inventory: the cross-reference is
            // vacuous. Say so rather than the misleading "all responded" (#30).
            println!(
                "model has no device inventory (no devices/*.toml); cannot cross-reference — run `bussard import` or add device files"
            );
        } else {
            println!("{} not in model", report.not_in_model.len());
            if report.missing.is_empty() {
                println!("all model devices on this line responded");
            } else {
                println!("{} model device(s) did NOT respond:", report.missing.len());
                for (addr, name) in &report.missing {
                    println!("  {addr}  {name}");
                }
            }
        }
    }
}

/// Prints a stable JSON array of the discovered devices plus the model delta
/// and the sweep's `timing` (issue #45).
fn print_json(report: &Report, timing: serde_json::Value) -> anyhow::Result<()> {
    use serde_json::json;
    let devices: Vec<_> = report
        .found
        .iter()
        .map(|f| {
            let status = if !report.have_model {
                serde_json::Value::Null
            } else if report.not_in_model.contains(&f.address) {
                json!("not_in_model")
            } else {
                json!("known")
            };
            let mut row = json!({
                "address": f.address.to_string(),
                "mask": format!("{:04X}", f.mask),
                "system_type": system_type(f.mask),
                "manufacturer_id": f.manufacturer_id.map(|id| format!("{id:#06X}")),
                "manufacturer": f.manufacturer_id.map(manufacturers::display),
                "serial": f.serial.as_deref().map(hex),
                "order": f.order,
                "model_status": status,
            });
            // A plain device's row is unchanged; an activated one says how it
            // was read (issue #203).
            if f.secure.activated() {
                row["secure"] = json!(f.secure.as_str());
            }
            if let Some(identity) = &f.identity {
                row["identity"] = json!(identity);
            }
            row
        })
        .collect();

    let out = json!({
        "found": devices,
        "model_device_count": report.model_device_count,
        "not_in_model": report.not_in_model.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "missing_from_bus": report
            .missing
            .iter()
            .map(|(a, name)| json!({ "address": a.to_string(), "name": name }))
            .collect::<Vec<_>>(),
        "timing": timing,
    });
    crate::output::print(crate::output::schema::SCAN, &out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_accepts_area_line() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_line("1.1")?, (1, 1));
        assert_eq!(parse_line("15.15")?, (15, 15));
        // A full address ignores the device part.
        assert_eq!(parse_line("2.3.55")?, (2, 3));
        Ok(())
    }

    #[test]
    fn parse_line_rejects_bad_input() {
        assert!(parse_line("1").is_err());
        assert!(parse_line("16.1").is_err());
        assert!(parse_line("x.y").is_err());
    }

    #[test]
    fn hex_formats_lowercase() {
        assert_eq!(hex(&[0xDE, 0xAD]), "dead");
    }

    // --- cross_reference regression coverage (issue #30) ---

    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Device, Groups, Links};
    use bussard_model::{LoadedDevice, Model};

    fn ia(s: &str) -> IndividualAddress {
        s.parse().expect("test fixture")
    }

    /// Builds a model whose `devices` map contains exactly `addrs`.
    fn model_with_devices(addrs: &[&str]) -> Model {
        let mut devices = BTreeMap::new();
        for a in addrs {
            let addr = ia(a);
            devices.insert(
                addr,
                LoadedDevice {
                    device: Device {
                        address: addr,
                        name: format!("dev {a}"),
                        description: None,
                        location: None,
                        replaced: None,
                        product: None,
                        channels: BTreeMap::new(),
                        parameters: BTreeMap::new(),
                        module_bases: Default::default(),
                        com_objects: BTreeMap::new(),
                        security: None,
                        application_override: None,
                        lock: Default::default(),
                    },
                    file_stem: a.to_string(),
                },
            );
        }
        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups: BTreeMap::new(),
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices,
        }
    }

    fn found_at(addr: &str) -> Found {
        Found {
            address: ia(addr),
            mask: 0x07B0,
            manufacturer_id: None,
            serial: None,
            order: None,
            secure: SecureStatus::Plain,
            identity: None,
        }
    }

    /// The live shape from issue #30: a 46-device model is loaded and exactly
    /// one of those devices responds (the rest were silent because of the
    /// source-IA bug). The missing list MUST name the other 45 — it was empty
    /// in the field, which this test guards against.
    #[test]
    fn cross_reference_lists_all_non_responders() {
        let addrs: Vec<String> = (1..=46u16).map(|n| format!("1.1.{n}")).collect();
        let addr_refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
        let model = model_with_devices(&addr_refs);

        // Only 1.1.1 answered; it IS a model device, so it is "known".
        let report = cross_reference(vec![found_at("1.1.1")], Some(&model));

        assert!(report.have_model);
        assert!(
            report.not_in_model.is_empty(),
            "the sole responder is in the model, so nothing is unexpected"
        );
        assert_eq!(
            report.missing.len(),
            45,
            "the 45 silent model devices must all be listed as missing"
        );
        // The responder itself is not listed as missing.
        assert!(
            !report.missing.iter().any(|(a, _)| *a == ia("1.1.1")),
            "the device that responded must not be in the missing list"
        );
    }

    /// A responder that is *not* in the model is reported as not_in_model, and
    /// every model device is missing.
    #[test]
    fn cross_reference_flags_unexpected_and_all_missing() {
        let model = model_with_devices(&["1.1.4", "1.1.20"]);
        // The IP interface (1.1.200) answered but is not modelled.
        let report = cross_reference(vec![found_at("1.1.200")], Some(&model));
        assert_eq!(report.not_in_model, vec![ia("1.1.200")]);
        assert_eq!(report.missing.len(), 2, "both model devices are missing");
    }

    /// Without a model, there is no cross-reference at all.
    #[test]
    fn cross_reference_without_model_has_no_delta() {
        let report = cross_reference(vec![found_at("1.1.1")], None);
        assert!(!report.have_model);
        assert!(report.not_in_model.is_empty());
        assert!(report.missing.is_empty());
    }
}
