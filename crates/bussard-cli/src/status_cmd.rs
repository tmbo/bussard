//! `bussard status <ADDRESS>`: the live state of one device, read over the bus
//! (issue #391). Without an address `status` is the model's change summary
//! ([`crate::history_cmd::run_status`]).
//!
//! It prints the device's mask and its identity against `bussard.lock`, and
//! for a KNX IP interface or router the KNXnet/IP parameter object (object type
//! 11): the IP address in use and how it was assigned, the configured
//! method and static settings, the MAC address, the friendly name, the
//! tunnelling addresses, the capabilities and the device state. What it read
//! is kept with the device facts (`.bussard/facts/<ia>.toml`) and compared
//! with the device file's `[knxnet]` table.
//!
//! Read-only on the bus: a descriptor read, the facts reads `describe` makes
//! (without the property descriptions) and property value reads. No
//! KNXnet/IP Secure property (PID 91 and up) is read. On a Data Secure device
//! read with its tool key, the security failures log, report and report
//! control (PID 55, 57, 58) are read too (issue #533).
//!
//! The session's reads and the report live in [`bussard_service::status`],
//! which `knx_show_device {live: true}` calls too (issue #747).

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::IndividualAddress;
use bussard_model::knxnet::KnxnetFacts;
use bussard_service::status::{StatusReport, read_live_status, status_report};
use bussard_service::{L4Options, SourcePolicy, WritePolicy};

use crate::conn_cmd::{ConnOverrides, load_model_required, open_service, resolve_config};
use crate::style::Style;

/// Runs `bussard status <ADDRESS>`.
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    refresh_facts: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    let model = load_model_required(dir)?;
    let activated = crate::secure_key::model_activated(model.as_ref(), target);
    let (tool_key, factory_key) =
        crate::secure_key::resolve_session_keys(target, tool_key_source, activated)?;
    let presented_tool_key = tool_key.is_some();
    let config = resolve_config(model.as_ref(), &overrides)?;
    let mut facts = crate::device_facts::cache(dir, model.is_some(), refresh_facts);
    let authorize = crate::device_facts::read_only_authorize(&mut facts, target);

    let runtime = tokio::runtime::Runtime::new()?;
    let read = runtime
        .block_on(async move {
            let service = open_service(config, WritePolicy::ReadOnly).await?;
            let options = L4Options {
                source: SourcePolicy::Check {
                    skip: overrides.skip_address_check,
                },
                tool_key,
                factory_key,
                high_water: bussard_secure::SequenceHighWater::new(),
                authorize,
                ..L4Options::default()
            };
            let outcome = service
                .with_l4(target, &options, async |l4| {
                    read_live_status(l4, &facts)
                        .await
                        .map_err(anyhow::Error::from)
                })
                .await;
            service.close().await;
            outcome
        })
        .map_err(|err| crate::secure_key::secure_hint(target, presented_tool_key, err))?;

    let device = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .map(|d| &d.device);
    let report = status_report(target, device, &read);
    if json {
        crate::output::print(crate::output::schema::STATUS_DEVICE, &report)?;
    } else {
        print_text(target, &report, read.knxnet_error.as_deref());
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints the report as text.
fn print_text(target: IndividualAddress, report: &StatusReport, knxnet_error: Option<&str>) {
    print!(
        "{}",
        render_text(target, report, knxnet_error, Style::stdout())
    );
}

/// The heading line of one device in `status` and `describe`:
/// `Device 1.1.4 Kitchen actuator` in bold, then `mask 07B0 (System B)` dim.
pub(crate) fn device_heading(
    address: &str,
    name: Option<&str>,
    mask: &str,
    system_type: &str,
    style: Style,
) -> String {
    let name = name
        .filter(|n| !n.trim().is_empty())
        .map(|n| format!(" {}", n.trim()))
        .unwrap_or_default();
    format!(
        "{}  {}\n",
        style.bold(&format!("Device {address}{name}")),
        style.dim(&format!("mask {mask} ({system_type})"))
    )
}

/// The report as text: the heading, the identity, the KNXnet/IP section
/// against the device file, the Data Secure state.
fn render_text(
    target: IndividualAddress,
    report: &StatusReport,
    knxnet_error: Option<&str>,
    style: Style,
) -> String {
    let mut out = device_heading(
        &report.address,
        report.name.as_deref(),
        &report.mask,
        &report.system_type,
        style,
    );
    if let Some(identity) = &report.identity {
        let line = crate::device_facts::identity_line(target, identity);
        let line = if identity.is_drift() {
            style.warn(&line)
        } else {
            line
        };
        out.push_str(&format!("  {line}\n"));
    }
    match (&report.knxnet, knxnet_error) {
        (Some(k), _) => {
            out.push_str(&render_knxnet(k, style));
            match (&report.model_knxnet, report.knxnet_drift.is_empty()) {
                (Some(_), true) => out.push_str(&format!(
                    "  {}\n",
                    style.ok(&format!(
                        "[knxnet] in devices/{target}.toml matches the device"
                    ))
                )),
                (Some(_), false) => {
                    out.push_str(&format!(
                        "  {}\n",
                        style.warn(&format!(
                            "[knxnet] in devices/{target}.toml differs from the device:"
                        ))
                    ));
                    for line in &report.knxnet_drift {
                        out.push_str(&format!("    - {line}\n"));
                    }
                }
                (None, _) => {}
            }
        }
        (None, Some(err)) => out.push_str(&format!(
            "  {}\n",
            style.warn(&format!("KNXnet/IP parameter object: not read ({err})"))
        )),
        (None, None) => out.push_str(&format!(
            "  {}\n",
            style.dim("no KNXnet/IP parameter object (not an IP interface)")
        )),
    }
    if let Some(diag) = &report.security {
        out.push_str(&format!("  {}\n", style.bold("KNX Data Secure")));
        for line in diag.lines() {
            out.push_str(&format!("    {line}\n"));
        }
    }
    out
}

/// The KNXnet/IP section `status` and `describe` share: a bold heading,
/// then aligned dim labels.
pub(crate) fn render_knxnet(k: &KnxnetFacts, style: Style) -> String {
    let at = k
        .object_index
        .map(|i| format!("object {i}"))
        .unwrap_or_else(|| "object type 11".to_string());
    let mut out = format!(
        "  {} {}\n",
        style.bold("KNXnet/IP"),
        style.dim(&format!("({at}, read {})", k.read_at))
    );
    let lines = k.lines();
    let width = lines
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    for (label, value) in lines {
        let pad = " ".repeat(width.saturating_sub(label.chars().count()));
        out.push_str(&format!("    {}{pad}  {value}\n", style.dim(label)));
    }
    out
}
