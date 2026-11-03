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

use anyhow::{Context, anyhow};
use bussard_mgmt::{DeviceConnection, L4Channel, Timeouts, manufacturers, system_type};
use bussard_model::IndividualAddress;
use bussard_secure::Key16;
use bussard_service::BusService;
use bussard_service::identity;
use bussard_service::scan::{self, LineRange, ScanReport, Sweep, SweepEvent};
use bussard_service::secure::ToolKeys;
use bussard_service::{L4Options, WritePolicy};

pub(crate) use bussard_service::scan::{Found, secure_label};

use crate::assign_cmd::hex;
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, load_model_required, open_service, resolve_config,
};

/// The discovery timeout budget ([`scan::discovery_timeouts`]), honouring
/// `BUSSARD_SCAN_DISCOVERY_MS` when set.
pub(crate) fn discovery_timeouts() -> Timeouts {
    scan::discovery_timeouts()
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
    let range = LineRange {
        area,
        line: line_no,
        from,
        to,
    };
    let estimate = range.estimate();
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
            swept = sweep(&service, range, source, json, &key_for) => swept,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Sweep::default()
            }
        };
        service.close().await;
        anyhow::Ok(swept)
    })?;

    let timing = swept.timing_json();
    let mut report = scan::cross_reference(swept.found, model.as_ref());
    // The identity verdict per device, against the lock and the stored facts
    // (issue #228, item 5); stale facts are dropped for the next connection.
    for f in &mut report.found {
        let device = model
            .as_ref()
            .and_then(|m| m.devices.get(&f.address))
            .map(|d| &d.device);
        f.identity = Some(scan::observe_identity(
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

/// Sweeps every device address of `range` with [`scan::sweep`], showing the
/// progress on stderr (issue #147): a line rewritten in place, or the live
/// view on an interactive terminal. `key_for` gives the tool key of a
/// keyring-listed address.
async fn sweep(
    service: &BusService,
    range: LineRange,
    source: IndividualAddress,
    json: bool,
    key_for: &(dyn Fn(IndividualAddress) -> Option<Key16> + Sync),
) -> Sweep {
    let display = crate::progress::SweepDisplay::new("scanning", range.count(), json);
    let swept = scan::sweep(service, range, source, key_for, &mut |event| match event {
        SweepEvent::Probing { address, found } => display.probing(address, found),
        SweepEvent::Probed { .. } => display.advance(),
    })
    .await;
    display.finish();
    eprintln!(
        "\rscan complete: {} device(s) found; {}",
        swept.found.len(),
        swept.summary()
    );
    swept
}

/// The session options of a probe ([`scan::probe_options`]).
pub(crate) fn probe_options(source: IndividualAddress) -> L4Options {
    scan::probe_options(source)
}

/// Probes one address in the clear: connect, read the descriptor, and, if
/// present, best-effort read manufacturer/serial/order. Returns `None` for an
/// absent or refusing device. A Data Secure-activated device answers mask
/// `FFFF`; the row is then [`identity::SecureStatus::ActivatedNoKey`].
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

/// Parses a `area.line` (e.g. `1.1`) or a full `area.line.device` (ignoring the
/// device part) into `(area, line)` ([`scan::parse_line`]).
pub(crate) fn parse_line(line: &str) -> anyhow::Result<(u8, u8)> {
    Ok(scan::parse_line(line)?)
}

/// Prints the aligned table plus a summary.
fn print_table(report: &ScanReport) {
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
            let system = f.system_type();
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
fn print_json(report: &ScanReport, timing: serde_json::Value) -> anyhow::Result<()> {
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
    use bussard_service::identity::SecureStatus;

    #[test]
    fn parse_line_keeps_the_service_messages() {
        let err = parse_line("16.1").err().map(|e| e.to_string());
        assert_eq!(
            err.as_deref(),
            Some("area and line must each be 0–15 (got \"16.1\")")
        );
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
                        knxnet: None,
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
        let report = scan::cross_reference(vec![found_at("1.1.1")], Some(&model));

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
        let report = scan::cross_reference(vec![found_at("1.1.200")], Some(&model));
        assert_eq!(report.not_in_model, vec![ia("1.1.200")]);
        assert_eq!(report.missing.len(), 2, "both model devices are missing");
    }

    /// Without a model, there is no cross-reference at all.
    #[test]
    fn cross_reference_without_model_has_no_delta() {
        let report = scan::cross_reference(vec![found_at("1.1.1")], None);
        assert!(!report.have_model);
        assert!(report.not_in_model.is_empty());
        assert!(report.missing.is_empty());
    }
}
