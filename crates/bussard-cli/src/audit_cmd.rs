//! The `bussard audit` subcommand: what the installation holds and what
//! bussard can do with it (issue #93).
//!
//! The static part reads only the model. The live part (`--live`) is read tier:
//! it asks the interface to describe itself (tunnel slots, issue #105), listens
//! to the bus for `--window` seconds, then probes each modelled device with the
//! `scan` machinery, one address at a time and paced like the MCP read limiter.
//! It never sends a group telegram.
//!
//! The report itself is built by [`bussard_mcp::tools_audit`], the same code the
//! `knx_audit` MCP tool uses; this module gathers the live inputs and renders
//! the text form from the JSON, so text, `--json` and MCP cannot disagree.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bussard_bus::{Bus, BusHandle, ops};
use bussard_mcp::tools_audit::{self, SampledTelegram};
use bussard_model::{IndividualAddress, Model};
use bussard_transport::cemi::{Apdu, Destination, MessageCode};
use bussard_transport::{BusConnection, ConnectionConfig, Transport, TransportKind};
use serde_json::{Value, json};

use crate::conn_cmd::{ConnOverrides, load_model_required, resolve_config};
use crate::secure_key::KEYRING_PASSWORD_ENV;

/// Options for one `bussard audit` run.
pub struct AuditOptions<'a> {
    /// Emit JSON instead of the text report.
    pub json: bool,
    /// Add the live part (gateway, traffic sample, scan delta).
    pub live: bool,
    /// The traffic-sample window for `--live`.
    pub window: Duration,
    /// A `.knxkeys` keyring to check Secure devices against.
    pub keyring: Option<&'a Path>,
}

/// Runs `bussard audit`. Exits 0 on a completed audit, whatever it found.
pub fn run(
    dir: &Path,
    options: AuditOptions<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "`bussard audit` needs a model; none was found at {} (run `bussard init` or \
             `bussard import` first)",
            dir.display()
        );
    };

    let keyring_devices = match options.keyring {
        Some(path) => Some(keyring_devices(path)?),
        None => None,
    };
    let mut report = tools_audit::static_report(&model, keyring_devices.as_deref());

    if options.live {
        let config = resolve_config(Some(&model), &overrides)?;
        let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
        report["live"] = runtime.block_on(live_report(&model, config, options.window))?;
    }

    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_text(&report));
    }
    Ok(ExitCode::SUCCESS)
}

/// Decrypts the keyring and lists the devices it holds a tool key for.
fn keyring_devices(path: &Path) -> anyhow::Result<Vec<IndividualAddress>> {
    let password = std::env::var(KEYRING_PASSWORD_ENV).map_err(|_| {
        anyhow!(
            "the keyring password must be set in the {KEYRING_PASSWORD_ENV} environment \
             variable (never passed as a CLI argument)"
        )
    })?;
    let xml = std::fs::read_to_string(path)
        .with_context(|| format!("reading keyring {}", path.display()))?;
    let keyring = bussard_project::parse_keyring(&xml, &password)
        .with_context(|| format!("parsing keyring {}", path.display()))?;
    Ok(keyring.devices.iter().map(|d| d.ia).collect())
}

/// Gathers the live section: gateway description, traffic sample, scan delta.
async fn live_report(
    model: &Model,
    config: ConnectionConfig,
    window: Duration,
) -> anyhow::Result<Value> {
    // 1. The interface's own description: one UDP exchange, no tunnel slot.
    let is_tunnel = config.transport == TransportKind::Tunnel;
    let gateway = match (is_tunnel, config.gateway) {
        (true, Some(endpoint)) => {
            match bussard_transport::describe_gateway(endpoint, Duration::from_secs(2)).await {
                Ok(d) => tools_audit::gateway_report(Some(endpoint), Ok(&d)),
                Err(err) => tools_audit::gateway_report(Some(endpoint), Err(err.to_string())),
            }
        }
        _ => tools_audit::gateway_report(
            None,
            Err("routing transport: there is no tunnelling interface to describe".to_string()),
        ),
    };

    // 2. A full interface must fail loudly with its own exit code, not as a
    //    silent reconnect loop: probe one tunnel connect first (issue #105).
    if is_tunnel {
        match Transport::connect(&config).await {
            Ok(conn) => {
                let _ = conn.close().await;
            }
            Err(err @ bussard_transport::TransportError::NoMoreConnections) => {
                return Err(anyhow::Error::new(err));
            }
            Err(err) => {
                return Err(anyhow::Error::new(err).context("connecting to the gateway"));
            }
        }
    }

    let (handle, _task) = Bus::connect(config);
    if !handle.wait_connected(Duration::from_secs(10)).await {
        let _ = handle.close().await;
        bail!("the bus did not connect within 10 s; the live audit needs a working gateway");
    }

    // 3. Listen first, so the sample is not polluted by our own probes (which
    //    are individually addressed anyway).
    eprintln!("sampling bus traffic for {} s…", window.as_secs());
    let telegrams = sample_traffic(&handle, window).await;
    let traffic = tools_audit::traffic_report(model, window, &telegrams);

    // 4. Probe each modelled device, line by line.
    let scan = scan_model_devices(&handle, model).await;
    let _ = handle.close().await;

    Ok(json!({
        "bus": { "state": "connected" },
        "gateway": gateway,
        "scan": scan,
        "traffic": traffic,
    }))
}

/// Collects the group telegrams indicated on the bus for `window`.
///
/// Only `L_Data.ind` frames count: the gateway's `L_Data.con` echo of our own
/// requests is not bus traffic.
async fn sample_traffic(handle: &BusHandle, window: Duration) -> Vec<SampledTelegram> {
    let mut sub = handle.subscribe();
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let frame = match tokio::time::timeout_at(deadline, sub.recv()).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        if frame.message_code != MessageCode::LDataInd {
            continue;
        }
        let cemi = &frame.frame.frame;
        let Destination::Group(ga) = cemi.destination else {
            continue;
        };
        let payload = match &cemi.apdu {
            Apdu::GroupValueWrite(data) | Apdu::GroupValueResponse(data) => data.bytes(),
            Apdu::GroupValueRead => Vec::new(),
            _ => continue,
        };
        out.push(SampledTelegram {
            at: frame.frame.received_at,
            source: cemi.source,
            ga,
            payload,
            repeat_flag: cemi.control1.repeated,
        });
    }
    out
}

/// Probes every modelled device and reports the delta per line.
///
/// Probes are sequential (one connection-oriented session at a time, TP1
/// etiquette) and spaced by the MCP read limiter's minimum interval.
async fn scan_model_devices(handle: &BusHandle, model: &Model) -> Value {
    let source = ops::group_source(handle);
    let mut lines: BTreeMap<(u8, u8), Vec<Value>> = BTreeMap::new();
    let mut not_answering: BTreeMap<(u8, u8), Vec<Value>> = BTreeMap::new();
    let mut answered_count = 0usize;

    for (addr, loaded) in &model.devices {
        eprint!("\rprobing {addr}…   ");
        let started = tokio::time::Instant::now();
        let found = crate::scan_cmd::probe(handle, *addr, source).await;
        let key = (addr.area(), addr.line());
        let model_mask = loaded.device.product.as_ref().and_then(|p| p.mask.clone());
        match found {
            Some(f) => {
                answered_count += 1;
                let bus_mask = format!("{:04X}", f.mask);
                let mismatch = model_mask
                    .as_deref()
                    .map(|m| {
                        !m.trim()
                            .trim_start_matches("0x")
                            .eq_ignore_ascii_case(&bus_mask)
                    })
                    .unwrap_or(false);
                lines.entry(key).or_default().push(json!({
                    "address": addr.to_string(),
                    "name": loaded.device.name,
                    "mask": bus_mask,
                    "model_mask": model_mask,
                    "mask_mismatch": mismatch,
                    "bussard_can": bussard_mgmt::MaskProfile::from_mask(f.mask).capabilities().summary(),
                }));
            }
            None => not_answering.entry(key).or_default().push(json!({
                "address": addr.to_string(),
                "name": loaded.device.name,
            })),
        }
        // Pace like the MCP read limiter: never faster than one probe per
        // READ_MIN_INTERVAL.
        let elapsed = started.elapsed();
        if elapsed < bussard_mcp::READ_MIN_INTERVAL {
            tokio::time::sleep(bussard_mcp::READ_MIN_INTERVAL - elapsed).await;
        }
    }
    eprintln!(
        "\rprobed {} modelled device(s)          ",
        model.devices.len()
    );

    let mut keys: Vec<(u8, u8)> = lines.keys().chain(not_answering.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();
    let per_line: Vec<Value> = keys
        .into_iter()
        .map(|key| {
            json!({
                "line": format!("{}.{}", key.0, key.1),
                "answered": lines.remove(&key).unwrap_or_default(),
                "not_answering": not_answering.remove(&key).unwrap_or_default(),
            })
        })
        .collect();

    json!({
        "probed": model.devices.len(),
        "answered": answered_count,
        "lines": per_line,
        "note": "only modelled addresses are probed; devices on the bus but not in the model \
                 show up as unknown sources in the traffic sample, or with `bussard scan`",
    })
}

/// Renders the text report from the audit JSON.
pub fn render_text(report: &Value) -> String {
    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    let model = &report["model"];

    line("== Model ==".to_string());
    line(format!(
        "project: {}   imported from: {}",
        text_or(&model["project"], "(not recorded)"),
        text_or(&model["imported_from"], "(not recorded)")
    ));
    line(format!(
        "{} device(s), {} group address(es), {} link(s)",
        model["devices"], model["group_addresses"], model["links"]
    ));
    for l in array(&model["devices_per_line"]) {
        line(format!(
            "  line {}: {} device(s)",
            text_or(&l["line"], "?"),
            l["devices"]
        ));
    }
    line(String::new());

    line("== Model gaps ==".to_string());
    list_section(
        &mut line,
        "devices without a name",
        &model["devices_without_name"],
    );
    list_section(
        &mut line,
        "devices without a location",
        &model["devices_without_location"],
    );
    list_section(
        &mut line,
        "GAs without a DPT",
        &model["group_addresses_without_dpt"],
    );
    list_section(
        &mut line,
        "GAs without a name",
        &model["group_addresses_without_name"],
    );
    let unknown_objects: Vec<Value> = array(&model["links_to_unknown_objects"])
        .iter()
        .map(|l| {
            json!(format!(
                "{} object {}",
                text_or(&l["device"], "?"),
                l["object"]
            ))
        })
        .collect();
    list_section(
        &mut line,
        "links to unknown com-objects",
        &Value::Array(unknown_objects),
    );
    list_section(
        &mut line,
        "links for devices without a device file",
        &model["links_to_unknown_devices"],
    );
    line(String::new());

    line("== Findings (one-sided links) ==".to_string());
    let findings = array(&model["findings"]);
    if findings.is_empty() {
        line("none".to_string());
    }
    for f in findings {
        line(format!("  {}", text_or(&f["message"], "?")));
    }
    line(format!(
        "info: {} unlinked com-object(s) and {} unused GA(s) (normal, not problems)",
        model["info"]["unlinked_com_objects"], model["info"]["unused_group_addresses"]
    ));
    line(String::new());

    line("== Devices per mask ==".to_string());
    for m in array(&report["masks"]) {
        let devices: Vec<String> = array(&m["devices"])
            .iter()
            .map(|d| text_or(d, "?"))
            .collect();
        line(format!(
            "  {} {} ({} device(s)): bussard can: {}",
            text_or(&m["mask"], "----"),
            text_or(&m["family"], "?"),
            devices.len(),
            text_or(&m["bussard_can"], "?")
        ));
        line(format!("      {}", devices.join(", ")));
    }
    line(String::new());

    line("== KNX Secure ==".to_string());
    let secure = &report["secure"];
    let secure_devices = array(&secure["devices"]);
    if secure_devices.is_empty() {
        line("no Secure-capable devices in the model".to_string());
    }
    for d in secure_devices {
        let entry = match d["keyring_entry"].as_bool() {
            Some(true) => "keyring: tool key present",
            Some(false) => "keyring: NO tool key",
            None => "keyring: not checked (pass --keyring)",
        };
        line(format!(
            "  {} {}  {}  {}",
            text_or(&d["address"], "?"),
            text_or(&d["name"], ""),
            if d["activated"].as_bool() == Some(true) {
                "activated"
            } else {
                "capable"
            },
            entry
        ));
    }
    list_section(
        &mut line,
        "protected GAs",
        &model["protected_group_addresses"],
    );

    let live = &report["live"];
    if !live.is_null() {
        line(String::new());
        line("== Gateway ==".to_string());
        let gw = &live["gateway"];
        if let Some(err) = gw["error"].as_str() {
            line(format!("  description unavailable: {err}"));
        } else {
            line(format!(
                "  {} ({}, IA {})",
                text_or(&gw["name"], "KNXnet/IP interface"),
                text_or(&gw["endpoint"], "?"),
                text_or(&gw["individual_address"], "?")
            ));
            match (gw["tunnels"].as_u64(), gw["tunnels_in_use"].as_u64()) {
                (Some(n), Some(m)) => line(format!("  {n} tunnels, {m} in use")),
                (Some(n), None) => line(format!("  {n} tunnels (usage not reported)")),
                _ => line("  tunnel slots not reported by this interface".to_string()),
            }
        }

        line(String::new());
        line("== Scan delta ==".to_string());
        let scan = &live["scan"];
        line(format!(
            "  {} of {} modelled device(s) answered",
            scan["answered"], scan["probed"]
        ));
        for l in array(&scan["lines"]) {
            line(format!("  line {}:", text_or(&l["line"], "?")));
            for d in array(&l["answered"]) {
                let mismatch = if d["mask_mismatch"].as_bool() == Some(true) {
                    format!(" (model says {})", text_or(&d["model_mask"], "?"))
                } else {
                    String::new()
                };
                line(format!(
                    "    {} answered, mask {}{}",
                    text_or(&d["address"], "?"),
                    text_or(&d["mask"], "?"),
                    mismatch
                ));
            }
            for d in array(&l["not_answering"]) {
                line(format!(
                    "    {} {} did NOT answer",
                    text_or(&d["address"], "?"),
                    text_or(&d["name"], "")
                ));
            }
        }

        line(String::new());
        line("== Traffic sample ==".to_string());
        let traffic = &live["traffic"];
        line(format!(
            "  {} group telegram(s) in {} s",
            traffic["telegrams"], traffic["window_seconds"]
        ));
        for g in array(&traffic["per_ga"]) {
            line(format!(
                "    {} {}: {} telegram(s), {} repeated ({:.0}%)",
                text_or(&g["ga"], "?"),
                text_or(&g["name"], ""),
                g["telegrams"],
                g["repeated"],
                g["repeat_rate"].as_f64().unwrap_or(0.0) * 100.0
            ));
        }
        let orphans: Vec<Value> = array(&traffic["sender_no_listener"])
            .iter()
            .map(|g| g["ga"].clone())
            .collect();
        list_section(
            &mut line,
            "GAs sent on the bus with no listener in the model",
            &Value::Array(orphans),
        );
        list_section(
            &mut line,
            "sources not in the model",
            &traffic["unknown_sources"],
        );
    }
    out
}

/// A JSON string field, or `default` when null/absent.
fn text_or(value: &Value, default: &str) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => default.to_string(),
        other => other.to_string(),
    }
}

/// A JSON array's items, or empty.
fn array(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

/// Prints `label: none` or `label (N): a, b, c`.
fn list_section(line: &mut impl FnMut(String), label: &str, items: &Value) {
    let items: Vec<String> = array(items).iter().map(|v| text_or(v, "?")).collect();
    if items.is_empty() {
        line(format!("{label}: none"));
    } else {
        line(format!("{label} ({}): {}", items.len(), items.join(", ")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_text_static_report_has_every_section() {
        let model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: Default::default(),
        };
        let report = tools_audit::static_report(&model, None);
        let text = render_text(&report);
        for section in [
            "== Model ==",
            "== Model gaps ==",
            "== Findings (one-sided links) ==",
            "== Devices per mask ==",
            "== KNX Secure ==",
            "protected GAs: none",
        ] {
            assert!(text.contains(section), "missing {section}:\n{text}");
        }
        assert!(
            !text.contains("== Gateway =="),
            "static report has no live part"
        );
    }
}
