//! The `bussard scan` subcommand: sequential device discovery on one line.
//!
//! Sweeps `LINE.0` … `LINE.255` one connection at a time (TP1 etiquette — most
//! gateways will not multiplex connection-oriented sessions), reading each
//! responding device's mask version, manufacturer, serial and order info. When a
//! model directory is present it cross-references the discovered devices against
//! `devices/*.yaml`: which are known, which are unexpected, and which model
//! devices did not answer. That delta is the command's real value.
//!
//! The address range can be narrowed with `--from`/`--to` (defaults `0`/`255`),
//! which cuts the sweep time when you already know the device numbers of
//! interest — a full line is 256 serial probes, each costing up to a couple of
//! seconds on an absent address.
//!
//! It always exits 0 — it is a report, not a check.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::anyhow;
use bussard_bus::{Bus, BusHandle};
use bussard_mgmt::apci::{PID_MANUFACTURER_ID, PID_ORDER_INFO, PID_SERIAL_NUMBER};
use bussard_mgmt::{
    DeviceConnection, L4Channel, LeaseChannel, Timeouts, manufacturers, system_type,
};
use bussard_model::IndividualAddress;

use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, load_model_required, resolve_config,
};

/// Environment variable that overrides the per-attempt discovery timeout in
/// milliseconds. Set only by the integration test to keep a full-line mock sweep
/// fast; unset in normal use so the standard [`Timeouts::discovery`] budget
/// applies.
const DISCOVERY_MS_ENV: &str = "BUSSARD_SCAN_DISCOVERY_MS";

/// The discovery timeout budget, honouring [`DISCOVERY_MS_ENV`] when set.
fn discovery_timeouts() -> Timeouts {
    match std::env::var(DISCOVERY_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(ms) => Timeouts {
            ack_timeout: Duration::from_millis(ms),
            max_repetitions: 0,
            response_timeout: Duration::from_millis(ms),
        },
        None => Timeouts::discovery(),
    }
}

/// Per-address time budget used to estimate the sweep duration up front. A
/// present device answers in well under this; an absent one costs about
/// `2 × discovery ack_timeout`.
const PER_ADDRESS_ESTIMATE: Duration = Duration::from_millis(3200);

/// A single discovered device and everything read from it.
#[derive(Debug, Clone)]
struct Found {
    address: IndividualAddress,
    mask: u16,
    manufacturer_id: Option<u16>,
    serial: Option<Vec<u8>>,
    order: Option<String>,
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
    /// `have_model` true means a model loaded but has no `devices/*.yaml` — the
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

    // Up-front estimate (address count × per-address budget).
    let count = to as u32 - from as u32 + 1;
    let estimate = PER_ADDRESS_ESTIMATE * count;
    eprintln!(
        "scanning line {area}.{line_no}.{from}–{to} sequentially — estimated up to {}m{:02}s on TP1",
        estimate.as_secs() / 60,
        estimate.as_secs() % 60
    );

    let runtime = tokio::runtime::Runtime::new()?;
    let found = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        // Present the tunnel-assigned individual address as the source; devices
        // ignore connection-oriented frames from any other source, and the
        // gateway only routes replies back to the assigned address (issue #30).
        // Fall back to 0.0.255 on a routing transport that assigns none. The
        // actor may still be connecting; group_source reads the assigned IA once
        // it is up (the first probe waits on the lease anyway).
        handle
            .wait_connected(std::time::Duration::from_secs(10))
            .await;
        let source = checked_source_or_close(&handle, &overrides).await?;
        // Guard the sweep with Ctrl-C: on interrupt, stop sweeping and fall
        // through to a clean `handle.close()` so the gateway tunnel slot is
        // released rather than leaked (~2 min hold) — see issue #31.
        let found = tokio::select! {
            found = sweep(&handle, area, line_no, from, to, source) => found,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Vec::new()
            }
        };
        let _ = handle.close().await;
        anyhow::Ok(found)
    })?;

    let report = cross_reference(found, model.as_ref());

    if json {
        print_json(&report)?;
    } else {
        print_table(&report);
    }
    Ok(ExitCode::SUCCESS)
}

/// Sweeps every device address on the line, returning the responders.
///
/// One [`Bus`] is shared for the whole sweep; each probe leases it for its
/// connection-oriented session (TP1 etiquette — one open connection at a time),
/// releasing the lease before the next address.
async fn sweep(
    handle: &BusHandle,
    area: u8,
    line_no: u8,
    from: u8,
    to: u8,
    source: IndividualAddress,
) -> Vec<Found> {
    let mut found = Vec::new();
    for device in from..=to {
        let addr = match IndividualAddress::new(area, line_no, device) {
            Ok(a) => a,
            Err(_) => continue,
        };
        // Progress line to stderr, rewritten in place.
        eprint!("\rscanning {addr}…  {} found   ", found.len());
        let _ = std::io::stderr().flush();

        if let Some(dev) = probe(handle, addr, source).await {
            found.push(dev);
        }
    }
    eprintln!(
        "\rscan complete: {} device(s) found            ",
        found.len()
    );
    found
}

/// Probes one address: lease the bus, connect, read the descriptor, and — if
/// present — best-effort read manufacturer/serial/order. Returns `None` for an
/// absent or refusing device. The lease is released when the [`LeaseChannel`] is
/// dropped at the end of this function.
async fn probe(
    handle: &BusHandle,
    addr: IndividualAddress,
    source: IndividualAddress,
) -> Option<Found> {
    let lease = handle.lease().await.ok()?;
    let channel = LeaseChannel::new(lease);
    let mut dev = DeviceConnection::connect_with(channel, addr, source, discovery_timeouts())
        .await
        .ok()?;

    let mask = match dev.device_descriptor().await {
        Ok(mask) => mask,
        Err(err) => {
            // Present-but-refusing devices are logged but not listed as found
            // (we could not read a descriptor). Absent devices are silent.
            if err.device_present() {
                tracing::debug!("{addr} is present but refused the descriptor read: {err}");
            }
            let _ = dev.disconnect().await;
            return None;
        }
    };

    // Authorize the session with the free-access key, exactly as ETS does right
    // after the descriptor read (issue #52 finding #1). Done only for a present
    // device (after the descriptor read succeeds), so an absent address is not
    // charged an extra authorize timeout. Best-effort: a device that does not
    // implement authorize is tolerated; a genuine access-denied is logged and the
    // probe continues (scan reads are best-effort regardless).
    if let Err(err) = dev.authorize(bussard_mgmt::apci::FREE_ACCESS_KEY).await {
        tracing::debug!("{addr} authorize (free access) did not grant: {err}");
    }

    // Best-effort property reads: any failure just leaves the field empty.
    let manufacturer_id = read_u16(&mut dev, PID_MANUFACTURER_ID).await;
    let serial = dev
        .read_device_property(PID_SERIAL_NUMBER)
        .await
        .ok()
        .filter(|v| !v.is_empty());
    let order = dev
        .read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| clean_ascii(&v))
        .filter(|s| !s.is_empty());

    let _ = dev.disconnect().await;
    Some(Found {
        address: addr,
        mask,
        manufacturer_id,
        serial,
        order,
    })
}

/// Reads a 2-byte property as a `u16`, returning `None` on any failure.
async fn read_u16<Ch: L4Channel>(dev: &mut DeviceConnection<Ch>, pid: u8) -> Option<u16> {
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
fn parse_line(line: &str) -> anyhow::Result<(u8, u8)> {
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

/// Cleans a raw property value to printable ASCII, trimming trailing NULs/space.
fn clean_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| *b as char)
        .collect();
    s.trim().to_string()
}

/// Formats a byte slice as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
            println!(
                "{:<9}  {:04X}    {:<9}  {:<14}  {:<16}  {}",
                f.address.to_string(),
                f.mask,
                system_type(f.mask),
                manufacturer,
                order,
                status
            );
        }
    }

    println!();
    println!("{} device(s) responded", report.found.len());
    if report.have_model {
        if report.model_device_count == 0 {
            // A model loaded but has no device inventory: the cross-reference is
            // vacuous. Say so rather than the misleading "all responded" (#30).
            println!(
                "model has no device inventory (no devices/*.yaml); cannot cross-reference — run `bussard import` or add device files"
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

/// Prints a stable JSON array of the discovered devices plus the model delta.
fn print_json(report: &Report) -> anyhow::Result<()> {
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
            json!({
                "address": f.address.to_string(),
                "mask": format!("{:04X}", f.mask),
                "system_type": system_type(f.mask),
                "manufacturer_id": f.manufacturer_id.map(|id| format!("{id:#06X}")),
                "manufacturer": f.manufacturer_id.map(manufacturers::display),
                "serial": f.serial.as_deref().map(hex),
                "order": f.order,
                "model_status": status,
            })
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
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_accepts_area_line() {
        assert_eq!(parse_line("1.1").unwrap(), (1, 1));
        assert_eq!(parse_line("15.15").unwrap(), (15, 15));
        // A full address ignores the device part.
        assert_eq!(parse_line("2.3.55").unwrap(), (2, 3));
    }

    #[test]
    fn parse_line_rejects_bad_input() {
        assert!(parse_line("1").is_err());
        assert!(parse_line("16.1").is_err());
        assert!(parse_line("x.y").is_err());
    }

    #[test]
    fn clean_ascii_strips_control_and_nul() {
        assert_eq!(clean_ascii(b"ABB/S 1.1\0\0"), "ABB/S 1.1");
        assert_eq!(clean_ascii(&[0x01, 0x02]), "");
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
        s.parse().unwrap()
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
                        product: None,
                        channels: BTreeMap::new(),
                        parameters: BTreeMap::new(),
                        module_bases: Default::default(),
                        com_objects: BTreeMap::new(),
                        security: None,
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
