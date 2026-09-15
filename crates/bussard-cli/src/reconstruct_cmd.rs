//! The `bussard reconstruct` subcommand — read a device's tables back over the
//! bus and diff them against the model.
//!
//! Connects to a single System B (mask `07B0`) device, reads its group-address
//! and association tables via interface-object properties (see
//! [`bussard_mgmt::tables`]), resolves them to com-object → GA assignments, and
//! diffs the result against the model's `links.yaml` entry for that device.
//!
//! The command is **read-only on the bus**: it only ever sends
//! `A_DeviceDescriptor_Read`, `A_PropertyValue_Read` and (on the fallback path)
//! `A_Memory_Read`.
//!
//! ## What the diff can and cannot see
//!
//! The address + association tables recover *which* GAs each com-object is
//! linked to, but not the transmit direction: the send/listen distinction lives
//! in the group object table's flags, which many devices do not expose readably.
//! The diff therefore compares **GA sets per object** — a model `send:` and a
//! model `listen:` entry are treated alike.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_mgmt::tables::{DeviceTables, TablesError, read_tables};
use bussard_mgmt::{Layer4Connection, system_type};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_transport::{BusConnection, Transport};

use crate::conn_cmd::{ConnOverrides, load_model_optional, resolve_config};

/// The fallback source individual address when the transport assigns none
/// (routing, or a gateway that reports `0.0.0`). On a tunnel the
/// gateway-assigned address is used instead — devices commonly ignore
/// connection-oriented management frames from any other source.
const FALLBACK_SOURCE_IA: &str = "0.0.255";

/// One (object, GA) pair in the diff.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
struct ObjectGa {
    /// The com-object number.
    object: u16,
    /// The group address, formatted `main/middle/sub`.
    ga: String,
}

/// The full report, shaped for both the text and `--json` outputs.
#[derive(Debug, serde::Serialize)]
struct Report {
    /// The device address.
    address: String,
    /// The mask version, formatted `07B0`.
    mask: String,
    /// Human-readable system type for the mask.
    system_type: String,
    /// Which read path produced each table (`"property"` or `"memory"`).
    table_source: BTreeMap<String, String>,
    /// Every GA in the device's address table, in table order.
    addresses: Vec<String>,
    /// The raw association table as (tsap, asap) pairs.
    associations: Vec<Association>,
    /// Per-path notes from the table reader.
    notes: Vec<String>,
    /// Com-object → GAs as resolved from the tables, keyed by object number.
    objects: BTreeMap<u16, Vec<String>>,
    /// The model diff, when a model with links for this device was loaded.
    diff: Option<Diff>,
}

/// A raw association table entry.
#[derive(Debug, serde::Serialize)]
struct Association {
    /// Index into the address table (1-based).
    tsap: u16,
    /// The com-object number domain (see [`bussard_mgmt::tables`]).
    asap: u16,
}

/// The (object, GA)-level diff against the model.
#[derive(Debug, serde::Serialize)]
struct Diff {
    /// Pairs present both on the device and in the model.
    matches: Vec<ObjectGa>,
    /// Pairs the device has but the model does not.
    on_device_not_in_model: Vec<ObjectGa>,
    /// Pairs the model has but the device does not.
    in_model_not_on_device: Vec<ObjectGa>,
    /// The limitation note about send/listen.
    note: &'static str,
}

/// The limitation baked into every diff.
const DIRECTION_NOTE: &str = "send/listen direction is not recoverable from the address and \
     association tables alone (the transmit flag lives in the group object table); the diff \
     compares GA sets per object";

/// Runs `bussard reconstruct`.
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let mut bus = Transport::connect(&config)
            .await
            .context("opening the bus connection")?;
        // Present the tunnel-assigned address as the source — devices commonly
        // ignore management frames from any other address.
        let source = bus
            .assigned_individual_address()
            .map(IndividualAddress::from_raw)
            .unwrap_or_else(|| FALLBACK_SOURCE_IA.parse().expect("valid source IA"));
        let mut l4 = Layer4Connection::connect(&mut bus, target, source)
            .await
            .context("opening the device connection")?;
        let result = read_tables(&mut l4).await;
        let _ = l4.disconnect().await;
        let _ = bus.close().await;
        anyhow::Ok(result)
    })?;

    let read = match result {
        Ok(read) => read,
        Err(TablesError::UnsupportedMask { address, mask }) => {
            eprintln!(
                "{address} reports mask {mask:04X} ({}) — `bussard reconstruct` supports \
                 System B (mask 07B0) only for now",
                system_type(mask)
            );
            return Ok(ExitCode::FAILURE);
        }
        Err(err) => {
            return Err(anyhow::Error::new(err).context("reading device tables"));
        }
    };

    let report = build_report(target, &read, model.as_ref());
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text(&report);
    }
    Ok(ExitCode::SUCCESS)
}

/// Assembles the report: raw inventory, resolved objects, and the model diff.
fn build_report(target: IndividualAddress, read: &DeviceTables, model: Option<&Model>) -> Report {
    // Resolved (object → GA set) from the device tables.
    let mut device_objects: BTreeMap<u16, BTreeSet<GroupAddress>> = BTreeMap::new();
    for link in &read.resolved {
        device_objects
            .entry(link.object)
            .or_default()
            .insert(link.ga);
    }

    // The model's (object → GA set) for this device, send and listen merged.
    let model_objects: Option<BTreeMap<u16, BTreeSet<GroupAddress>>> = model.map(|m| {
        let mut map: BTreeMap<u16, BTreeSet<GroupAddress>> = BTreeMap::new();
        if let Some(links) = m.links.links.get(&target) {
            for link in links {
                let entry = map.entry(link.object).or_default();
                entry.extend(link.send);
                entry.extend(link.listen.iter().copied());
            }
        }
        map
    });

    let diff = model_objects.map(|model_objects| diff_objects(&device_objects, &model_objects));

    Report {
        address: target.to_string(),
        mask: format!("{:04X}", read.mask),
        system_type: system_type(read.mask).to_string(),
        table_source: read
            .sources
            .iter()
            .map(|(table, source)| (table.to_string(), source.to_string()))
            .collect(),
        addresses: read.addresses.iter().map(|ga| ga.to_string()).collect(),
        associations: read
            .associations
            .iter()
            .map(|&(tsap, asap)| Association { tsap, asap })
            .collect(),
        notes: read.notes.clone(),
        objects: device_objects
            .iter()
            .map(|(obj, gas)| (*obj, gas.iter().map(|ga| ga.to_string()).collect()))
            .collect(),
        diff,
    }
}

/// Computes the (object, GA)-pair diff between device and model.
fn diff_objects(
    device: &BTreeMap<u16, BTreeSet<GroupAddress>>,
    model: &BTreeMap<u16, BTreeSet<GroupAddress>>,
) -> Diff {
    let pairs = |map: &BTreeMap<u16, BTreeSet<GroupAddress>>| -> BTreeSet<(u16, GroupAddress)> {
        map.iter()
            .flat_map(|(obj, gas)| gas.iter().map(|ga| (*obj, *ga)).collect::<Vec<_>>())
            .collect()
    };
    let dev = pairs(device);
    let mdl = pairs(model);
    let to_vec = |set: Vec<&(u16, GroupAddress)>| -> Vec<ObjectGa> {
        set.into_iter()
            .map(|&(object, ga)| ObjectGa {
                object,
                ga: ga.to_string(),
            })
            .collect()
    };
    Diff {
        matches: to_vec(dev.intersection(&mdl).collect()),
        on_device_not_in_model: to_vec(dev.difference(&mdl).collect()),
        in_model_not_on_device: to_vec(mdl.difference(&dev).collect()),
        note: DIRECTION_NOTE,
    }
}

/// Prints the human-readable report with the diff prominent.
fn print_text(report: &Report) {
    println!(
        "device {} — mask {} ({})",
        report.address, report.mask, report.system_type
    );
    for (table, source) in &report.table_source {
        println!("  {table} table read via {source}");
    }
    for note in &report.notes {
        println!("  note: {note}");
    }
    println!(
        "\ninventory: {} group address(es), {} association(s), {} linked object(s)",
        report.addresses.len(),
        report.associations.len(),
        report.objects.len()
    );
    for (object, gas) in &report.objects {
        println!("  object {object:>4}: {}", gas.join(", "));
    }

    let Some(diff) = &report.diff else {
        println!("\nno model loaded — skipping the diff");
        return;
    };
    println!(
        "\ndiff against the model ({} match, {} only on device, {} only in model):",
        diff.matches.len(),
        diff.on_device_not_in_model.len(),
        diff.in_model_not_on_device.len()
    );
    if diff.on_device_not_in_model.is_empty() && diff.in_model_not_on_device.is_empty() {
        println!("  device tables and model links agree");
    }
    for pair in &diff.on_device_not_in_model {
        println!(
            "  + on device, not in model: object {:>4} → {}",
            pair.object, pair.ga
        );
    }
    for pair in &diff.in_model_not_on_device {
        println!(
            "  - in model, not on device: object {:>4} → {}",
            pair.object, pair.ga
        );
    }
    println!("  note: {}", diff.note);
}
