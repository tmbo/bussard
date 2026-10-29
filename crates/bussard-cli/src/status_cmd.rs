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
//! KNXnet/IP Secure property (PID 91 and up) is read.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use bussard_mgmt::{Layer4Connection, system_type};
use bussard_model::IndividualAddress;
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::knxnet::{KnxnetConfig, KnxnetFacts};
use bussard_service::{FactsCache, FactsWant, L4Options, SourcePolicy, WritePolicy};

use crate::conn_cmd::{ConnOverrides, load_model_required, open_service, resolve_config};

/// The `status <ADDRESS> --json` report.
#[derive(Debug, serde::Serialize)]
struct Report {
    /// The device address.
    address: String,
    /// The device's name in the model, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// The mask version, `0021`.
    mask: String,
    /// The system type of the mask.
    system_type: String,
    /// The identity verdict against `bussard.lock`.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<IdentityCheck>,
    /// What the KNXnet/IP parameter object reported; absent on a device
    /// without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    knxnet: Option<KnxnetFacts>,
    /// The device file's `[knxnet]` table, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    model_knxnet: Option<KnxnetConfig>,
    /// Where the device differs from `[knxnet]`, one sentence each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    knxnet_drift: Vec<String>,
}

/// What the session read.
struct Read {
    mask: u16,
    application_id: Option<String>,
    knxnet: Option<KnxnetFacts>,
    /// Why the KNXnet/IP object could not be read, when it could not.
    knxnet_error: Option<String>,
}

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
                .with_l4(target, &options, async |l4| read_device(l4, &facts).await)
                .await;
            service.close().await;
            outcome
        })
        .map_err(|err| crate::secure_key::secure_hint(target, presented_tool_key, err))?;

    let device = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .map(|d| &d.device);
    let identity = IdentityCheck::compare(
        device,
        ReportedIdentity {
            mask: bussard_model::facts::format_mask(read.mask),
            application_id: read.application_id.clone(),
        },
    );
    let model_knxnet = device.and_then(|d| d.knxnet.clone());
    let knxnet_drift = match (&read.knxnet, &model_knxnet) {
        (Some(facts), Some(config)) => facts.drift(config),
        _ => Vec::new(),
    };
    let report = Report {
        address: target.to_string(),
        name: device.map(|d| d.name.clone()).filter(|n| !n.is_empty()),
        mask: bussard_model::facts::format_mask(read.mask),
        system_type: system_type(read.mask).to_string(),
        identity: Some(identity),
        knxnet: read.knxnet,
        model_knxnet,
        knxnet_drift,
    };
    if json {
        crate::output::print(crate::output::schema::STATUS_DEVICE, &report)?;
    } else {
        print_text(target, &report, read.knxnet_error.as_deref());
    }
    Ok(ExitCode::SUCCESS)
}

/// The descriptor, the device facts (object table, application id) and the
/// KNXnet/IP parameter object, which is stored with the facts.
async fn read_device<Ch: bussard_mgmt::L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
) -> anyhow::Result<Read> {
    let target = l4.target();
    let mask = bussard_mgmt::read_device_descriptor(l4)
        .await
        .with_context(|| format!("reading the device descriptor of {target}"))?;
    if mask == bussard_service::identity::HIDDEN_MASK {
        return Err(anyhow!(
            "{target} hides its mask (FFFF): it is KNX Secure-activated and refuses plain \
             management"
        ));
    }
    let mut established = facts
        .establish(l4, mask, FactsWant::Table)
        .await
        .with_context(|| format!("reading the interface objects of {target}"))?;
    let application_id = established
        .record
        .as_ref()
        .and_then(|r| r.application_id.clone());
    let (knxnet, knxnet_error) =
        match bussard_service::knxnet::read_knxnet_with_facts(l4, facts, &mut established).await {
            Ok(knxnet) => (knxnet, None),
            Err(err) => (None, Some(err.to_string())),
        };
    Ok(Read {
        mask,
        application_id,
        knxnet,
        knxnet_error,
    })
}

/// Prints the report as text.
fn print_text(target: IndividualAddress, report: &Report, knxnet_error: Option<&str>) {
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
