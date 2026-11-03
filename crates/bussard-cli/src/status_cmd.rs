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
    let name = report
        .name
        .as_deref()
        .map(|n| format!(", {n}"))
        .unwrap_or_default();
    println!(
        "device {} — mask {} ({}){name}",
        report.address, report.mask, report.system_type
    );
    if let Some(identity) = &report.identity {
        println!("  {}", crate::device_facts::identity_line(target, identity));
    }
    match (&report.knxnet, knxnet_error) {
        (Some(k), _) => {
            print_knxnet(k);
            match (&report.model_knxnet, report.knxnet_drift.is_empty()) {
                (Some(_), true) => {
                    println!("  [knxnet] in devices/{target}.toml matches the device")
                }
                (Some(_), false) => {
                    println!("  [knxnet] in devices/{target}.toml differs from the device:");
                    for line in &report.knxnet_drift {
                        println!("    - {line}");
                    }
                }
                (None, _) => {}
            }
        }
        (None, Some(err)) => println!("  KNXnet/IP parameter object: not read ({err})"),
        (None, None) => println!("  no KNXnet/IP parameter object (not an IP interface)"),
    }
    if let Some(diag) = &report.security {
        println!("  KNX Data Secure:");
        for line in diag.lines() {
            println!("    {line}");
        }
    }
}

/// Prints the KNXnet/IP section `status` and `describe` share.
pub(crate) fn print_knxnet(k: &KnxnetFacts) {
    let at = k
        .object_index
        .map(|i| format!("object {i}"))
        .unwrap_or_else(|| "object type 11".to_string());
    println!("  KNXnet/IP ({at}, read {}):", k.read_at);
    let lines = k.lines();
    let width = lines
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);
    for (label, value) in lines {
        println!("    {label:<width$}  {value}");
    }
}
