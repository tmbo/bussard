//! The `bussard reconstruct` subcommand — read a device's tables back over the
//! bus and diff them against the model.
//!
//! Connects to a single device, reads its group-address and association tables,
//! resolves them to com-object → GA assignments, and diffs the result against the
//! model's `links.yaml` entry for that device. **System B** (mask `x7B0`) serves
//! those tables as interface-object properties (see [`bussard_mgmt::tables`]);
//! **System 7** (mask `0705` / `0701`) keeps them in absolute memory at `0x4000`
//! / `0x4201` and is read by [`bussard_download::tables_sys7`] (issue #91). The
//! report and the diff below are the same for both.
//!
//! The command is **read-only on the bus**: it only ever sends
//! `A_DeviceDescriptor_Read`, `A_Authorize_Request`, `A_PropertyValue_Read` and
//! (on the System 7 and System B fallback paths) `A_Memory_Read`.
//!
//! A KNX Data Secure-activated device answers the plain descriptor read with
//! mask `FFFF` and refuses the rest. With `--keyring` / `--tool-key` (issue
//! #170) the session is opened through [`bussard_service::BusService::with_l4`]
//! with the device's tool key, so every APDU above, the descriptor read
//! included, rides `A_SecureData` and the device reports its real mask.
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
use std::time::Duration;

use anyhow::{Context, anyhow};
use bussard_mgmt::apci::{PID_MANUFACTURER_ID, PID_ORDER_INFO, PID_SERIAL_NUMBER};
use bussard_mgmt::tables::{DeviceTables, read_tables};
use bussard_mgmt::{MaskProfile, manufacturers, system_type};
use bussard_model::schema::{
    BussardConfig, ComObject, Connection as ModelConnection, Device, Group, Groups, Link, Links,
    Product, Transport as ModelTransport,
};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress, LoadedDevice, Model};
use bussard_service::{Authorize, BusService, L4Options, ServiceError, SourcePolicy, WritePolicy};
use bussard_transport::TransportKind;

use crate::assign_cmd::{clean_ascii, hex};
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, load_model_optional, load_model_required, open_service,
    resolve_config,
};
use crate::scan_cmd::{discovery_timeouts, parse_line, read_u16};

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
    /// The parameter read-back (issue #119), when a product file was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<crate::param_readback::Readback>,
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
    selection: crate::param_readback::Selection<'_>,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    // A management command: a present-but-broken model is a hard error.
    let model = load_model_required(dir)?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // The product file the parameter read-back decodes with (issue #119).
    let product = crate::param_readback::resolve(dir, selection, model.as_ref(), target)?;
    let model_ref = model.as_ref();
    let product_ref = product.as_ref();

    let (read_result, params) = crate::plan_cmd::read_device(
        config,
        target,
        &overrides,
        tool_key_source,
        product_ref,
        model_ref,
    )?;
    let live = match read_result {
        crate::plan_cmd::LiveRead::Tables(live) => live,
        crate::plan_cmd::LiveRead::UnsupportedMask { address, mask } => {
            crate::plan_cmd::report_unsupported_mask("reconstruct", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let read = live.tables();

    let mut report = build_report(target, read, model.as_ref());
    report.parameters = params;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text(&report);
        match &report.parameters {
            Some(params) => crate::param_readback::print_text(params, target),
            None => crate::param_readback::print_missing_product_note(model.as_ref(), target),
        }
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
        parameters: None,
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

// ===========================================================================
// Line mode: `bussard reconstruct --line 1.1 --out <fresh-dir>`
//
// Sweeps a whole line like `bussard scan` (short discovery timeouts, one
// connection at a time, progress on stderr), reads every System B device's
// tables, and synthesizes a fresh, ETS-less model into `--out`:
//
//   groups.toml            — every GA seen across all tables, placeholder names,
//                            no DPT (validation warns W011; that is honest).
//   links.yaml             — object → GA sets. Direction is unrecoverable from
//                            the tables, so every GA is recorded as `listen:`.
//   devices/<ia>-reconstructed.yaml — mask + best-effort product block; a
//                            minimal `com_objects:` stub per linked object so
//                            the model validates (the flags/DPTs are placeholders).
//   bussard.toml           — the connection actually used for the sweep.
//
// Every synthesized file carries a reconstruction banner injected after
// `Model::save` (which emits its own import-oriented headers) that says the
// model came from table read-back and that names, DPTs and directions still
// need human/monitor annotation.
// ===========================================================================

/// Per-address budget for the up-front estimate (duplicated from `scan_cmd`).
const PER_ADDRESS_ESTIMATE: Duration = Duration::from_millis(3200);

/// The reconstruction banner injected atop every synthesized file. It states
/// the provenance (table read-back, not ETS) and the three things a human or
/// the monitor must still supply: names, DPTs and send/listen directions.
const RECONSTRUCT_BANNER: &str = "\
# ⚠ RECONSTRUCTED from on-device table read-back (`bussard reconstruct --line`).
#
# This model was synthesized WITHOUT an ETS project, by reading each System B
# device's group-address and association tables over the bus. It is a scaffold,
# not ground truth:
#   • GA and com-object names are placeholders — annotate them (watch the bus
#     with `bussard monitor`, then name what you observe).
#   • DPTs are unknown (groups.toml carries no `dpt:`; validation warns W011).
#   • send/listen DIRECTION is not recoverable from these tables (the transmit
#     flag lives in the group object table), so every GA is recorded as `listen:`.
#   • com-object flags are placeholder `CW` stubs so the model validates.
# Verify against reality before treating this as the source of truth.
#
";

/// A device that responded to the line sweep. System B devices carry read
/// tables; everything else is recorded as a stub (mask only, tables skipped).
struct LineDevice {
    address: IndividualAddress,
    mask: u16,
    manufacturer_id: Option<u16>,
    serial: Option<Vec<u8>>,
    order: Option<String>,
    /// The read tables, present only for System B devices.
    tables: Option<DeviceTables>,
    /// Why the tables were skipped (non-System-B, or a read error), if skipped.
    skipped: Option<String>,
}

/// The line-mode summary, shaped for both text and `--json`.
#[derive(serde::Serialize)]
struct LineSummary {
    line: String,
    out: String,
    /// Devices whose tables were read (System B).
    devices_read: usize,
    /// Devices recorded as a stub (mask noted, tables skipped).
    devices_skipped: usize,
    /// Total responders on the line.
    devices_found: usize,
    /// Distinct group addresses across all read tables.
    group_addresses: usize,
    /// Total (object → GA) links synthesized.
    links: usize,
    /// Per-device breakdown.
    device_details: Vec<LineDeviceDetail>,
}

/// One device row in the line-mode summary.
#[derive(serde::Serialize)]
struct LineDeviceDetail {
    address: String,
    mask: String,
    system_type: String,
    /// `"read"` for System B devices, `"stub"` otherwise.
    status: &'static str,
    /// The skip reason, when the device was recorded as a stub.
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_reason: Option<String>,
    /// Distinct GAs read from this device (0 for stubs).
    group_addresses: usize,
    /// Links synthesized for this device (0 for stubs).
    links: usize,
}

/// Runs `bussard reconstruct --line`.
pub fn run_line(
    line: &str,
    from: u8,
    to: u8,
    out: Option<&Path>,
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
    let out = out.ok_or_else(|| {
        anyhow!(
            "--out <dir> is required in line mode (the fresh model directory to synthesize into)"
        )
    })?;
    ensure_empty_out(out)?;

    // The model dir here only supplies connection defaults; the synthesized
    // model is written to --out, never merged into it. A present-but-broken
    // model dir is still a hard error.
    let model = load_model_required(dir)?;
    crate::history_cmd::capture_external_edit(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;

    let count = to as u32 - from as u32 + 1;
    let estimate = PER_ADDRESS_ESTIMATE * count;
    eprintln!(
        "sweeping line {area}.{line_no}.{from}–{to} sequentially — estimated up to {}m{:02}s on TP1",
        estimate.as_secs() / 60,
        estimate.as_secs() % 60
    );

    // The sweep's runtime block consumes what it captures, but `overrides` is
    // still needed afterwards to seed the synthesized model's connection block.
    let conn = overrides.clone();
    let runtime = tokio::runtime::Runtime::new()?;
    let found = runtime.block_on(async move {
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let source = checked_source_or_close(&service, &conn).await?;
        let found = tokio::select! {
            found = sweep_line(&service, area, line_no, from, to, source, json) => found,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Vec::new()
            }
        };
        service.close().await;
        anyhow::Ok(found)
    })?;

    let model = synthesize_model(&found, &overrides, dir);
    model
        .save(out)
        .with_context(|| format!("writing the reconstructed model to {}", out.display()))?;
    inject_reconstruct_banners(out)?;
    // `--out` must be empty, so there is no prior state to preserve; the
    // snapshot records the reconstructed model itself as the baseline the next
    // edit is measured against (issue #110).
    crate::history_cmd::snapshot(
        out,
        bussard_model::history::SnapshotReason::new("reconstruct")
            .with_args([line.to_string()])
            .with_result("the model reconstructed from the line sweep"),
    );

    let summary = build_summary(line, out, &found, &model);
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_line_summary(&summary);
    }
    Ok(ExitCode::SUCCESS)
}

/// Fails if `out` exists and is a non-empty directory (or a file). Reconstruction
/// must never merge into an existing model.
fn ensure_empty_out(out: &Path) -> anyhow::Result<()> {
    if !out.exists() {
        return Ok(());
    }
    if out.is_file() {
        return Err(anyhow!(
            "--out {} is a file; expected a fresh (absent or empty) directory",
            out.display()
        ));
    }
    let mut entries = std::fs::read_dir(out)
        .with_context(|| format!("reading {}", out.display()))?
        .filter_map(Result::ok);
    if entries.next().is_some() {
        return Err(anyhow!(
            "--out {} is not empty; reconstruction never merges into an existing model \
             (choose a fresh directory)",
            out.display()
        ));
    }
    Ok(())
}

/// Sweeps the line, returning every responder with its tables (System B) or a
/// stub (everything else). One [`Bus`] is shared; each probe leases it.
async fn sweep_line(
    service: &BusService,
    area: u8,
    line_no: u8,
    from: u8,
    to: u8,
    source: IndividualAddress,
    json: bool,
) -> Vec<LineDevice> {
    let mut found = Vec::new();
    // Progress to stderr (issue #147): a line rewritten in place, or the live
    // view on an interactive terminal.
    let display = crate::progress::SweepDisplay::new(
        "reconstructing",
        usize::from(to.saturating_sub(from)) + 1,
        json,
    );
    for device in from..=to {
        let Ok(addr) = IndividualAddress::new(area, line_no, device) else {
            continue;
        };
        display.probing(addr, found.len());
        if let Some(dev) = probe_line(service, addr, source).await {
            found.push(dev);
        }
        display.advance();
    }
    display.finish();
    eprintln!(
        "\rsweep complete: {} device(s) found            ",
        found.len()
    );
    found
}

/// Probes one address: descriptor first; System B → read tables; anything else
/// → best-effort product identity, recorded as a stub. Returns `None` for an
/// absent or refusing device.
async fn probe_line(
    service: &BusService,
    addr: IndividualAddress,
    source: IndividualAddress,
) -> Option<LineDevice> {
    let options = L4Options {
        source: SourcePolicy::Known(source),
        timeouts: discovery_timeouts(),
        authorize: Authorize::Skip,
        ..L4Options::default()
    };
    let (mask, manufacturer_id, serial, order) = service
        .with_device(addr, &options, async |dev| {
            let mask = match dev.device_descriptor().await {
                Ok(mask) => mask,
                Err(err) => {
                    if err.device_present() {
                        tracing::debug!("{addr} present but refused the descriptor read: {err}");
                    }
                    return Ok(None);
                }
            };
            // Best-effort product identity for every responder (System B or not).
            let manufacturer_id = read_u16(dev, PID_MANUFACTURER_ID).await;
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
            Ok::<_, ServiceError>(Some((mask, manufacturer_id, serial, order)))
        })
        .await
        .ok()
        .flatten()?;

    // System B → read tables over a fresh Layer 4 session; others → stub. The
    // profile makes this medium-agnostic: 07B0 (TP1), 57B0 (KNX-IP) and 27B0
    // (RF) are all read, not just TP1.
    let (tables, skipped) = if MaskProfile::from_mask(mask).is_system_b() {
        match read_line_tables(service, addr, source).await {
            Ok(t) => (Some(t), None),
            Err(err) => (None, Some(format!("System B table read failed: {err}"))),
        }
    } else {
        (
            None,
            Some("not System B; tables skipped, recorded as a device stub".to_string()),
        )
    };

    Some(LineDevice {
        address: addr,
        mask,
        manufacturer_id,
        serial,
        order,
        tables,
        skipped,
    })
}

/// Opens a fresh connection-oriented session and reads the device's tables.
async fn read_line_tables(
    service: &BusService,
    addr: IndividualAddress,
    source: IndividualAddress,
) -> anyhow::Result<DeviceTables> {
    let options = L4Options {
        source: SourcePolicy::Known(source),
        // Authorize (free access) before reading, as ETS does (issue #52
        // finding #1).
        authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
        ..L4Options::default()
    };
    let result = service
        .with_l4(addr, &options, async |l4| {
            Ok::<_, ServiceError>(read_tables(l4).await)
        })
        .await
        .map_err(|e| anyhow!("{e}"))?;
    result.map_err(|e| anyhow!("{e}"))
}

/// Placeholder flags for a reconstructed com-object: `CW` keeps the model
/// ERROR-free (C is required for a linked object; W avoids the listen-only
/// W008 warning) while being honestly minimal — the real flags are unknown.
fn placeholder_flags() -> Flags {
    Flags::COMMUNICATION | Flags::WRITE
}

/// Synthesizes a fresh [`Model`] from the swept devices.
///
/// - `groups.toml`: every GA seen across all read tables, named
///   `GA <addr> (reconstructed)`, no DPT.
/// - `links.yaml`: object → GA set per device, every GA as `listen:` (direction
///   is unrecoverable).
/// - `devices/<ia>-reconstructed.yaml`: mask + best-effort product block; a
///   placeholder `com_objects:` stub per linked object so validation passes.
/// - `bussard.toml`: the connection actually used for the sweep.
fn synthesize_model(found: &[LineDevice], overrides: &ConnOverrides, dir: &Path) -> Model {
    let mut groups: BTreeMap<GroupAddress, Group> = BTreeMap::new();
    let mut links: BTreeMap<IndividualAddress, Vec<Link>> = BTreeMap::new();
    let mut devices: BTreeMap<IndividualAddress, LoadedDevice> = BTreeMap::new();

    for dev in found {
        // The product block is best-effort for every responder.
        let product = build_product(dev);

        let mut com_objects: BTreeMap<u16, ComObject> = BTreeMap::new();
        if let Some(tables) = &dev.tables {
            // object → GA set from the resolved links.
            let mut per_object: BTreeMap<u16, BTreeSet<GroupAddress>> = BTreeMap::new();
            for link in &tables.resolved {
                per_object.entry(link.object).or_default().insert(link.ga);
                groups
                    .entry(link.ga)
                    .or_insert_with(|| reconstructed_group(link.ga));
            }
            // Also register any address-table GA that carried no association, so
            // groups.toml is the honest union of everything seen.
            for ga in &tables.addresses {
                groups
                    .entry(*ga)
                    .or_insert_with(|| reconstructed_group(*ga));
            }

            let mut device_links = Vec::with_capacity(per_object.len());
            for (object, gas) in per_object {
                com_objects.insert(
                    object,
                    ComObject {
                        dpt: None,
                        size: Some("unknown".to_string()),
                        flags: placeholder_flags(),
                        reference: None,
                        channel: None,
                        secure: false,
                        function: None,
                        key: None,
                        text: None,
                    },
                );
                device_links.push(Link {
                    object,
                    name: None,
                    send: None,
                    listen: gas.into_iter().collect(),
                });
            }
            if !device_links.is_empty() {
                links.insert(dev.address, device_links);
            }
        }

        let device = Device {
            address: dev.address,
            name: format!("{} (reconstructed)", dev.address),
            description: Some(reconstruct_note(dev)),
            location: None,
            replaced: None,
            product,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects,
            // KNX Secure state comes only from the knxproj importer (issue #71).
            security: None,
            application_override: None,
            lock: Default::default(),
        };
        devices.insert(
            dev.address,
            LoadedDevice {
                device,
                file_stem: format!("{}-reconstructed", dev.address),
            },
        );
    }

    Model {
        config: model_config(overrides, dir),
        groups: Groups {
            project: Some("reconstructed (no ETS project)".to_string()),
            imported_from: None,
            ranges: BTreeMap::new(),
            groups,
        },
        links: Links { links },
        devices,
    }
}

/// A placeholder [`Group`] for a reconstructed GA: name only, no DPT.
fn reconstructed_group(ga: GroupAddress) -> Group {
    Group {
        name: format!("GA {ga} (reconstructed)"),
        dpt: None::<Dpt>,
        description: None,
        protected: false,
        secure: false,
    }
}

/// A per-device description line noting mask/system and, for stubs, why the
/// tables were skipped.
fn reconstruct_note(dev: &LineDevice) -> String {
    match &dev.skipped {
        Some(reason) => format!(
            "reconstructed stub — mask {:04X} ({}); {reason}",
            dev.mask,
            system_type(dev.mask)
        ),
        None => format!(
            "reconstructed from table read-back — mask {:04X} ({})",
            dev.mask,
            system_type(dev.mask)
        ),
    }
}

/// Builds the best-effort product block from the read identity.
fn build_product(dev: &LineDevice) -> Option<Product> {
    let manufacturer = dev.manufacturer_id.map(manufacturers::display);
    let order_number = dev.order.clone();
    let mask = Some(format!("{:04X}", dev.mask));
    // Stash the serial in hardware_ref (best-effort provenance; no other slot).
    let hardware_ref = dev.serial.as_deref().map(|s| format!("serial:{}", hex(s)));
    if manufacturer.is_none() && order_number.is_none() && hardware_ref.is_none() {
        // Still record the mask — it decides the read path in later phases.
        return Some(Product {
            manufacturer: None,
            manufacturer_ref: None,
            order_number: None,
            hardware_ref: None,
            application_ref: None,
            mask,
        });
    }
    Some(Product {
        manufacturer,
        manufacturer_ref: None,
        order_number,
        hardware_ref,
        application_ref: None,
        mask,
    })
}

/// Builds the `bussard.toml` config recording the connection actually used.
fn model_config(overrides: &ConnOverrides, dir: &Path) -> BussardConfig {
    // Reuse the resolved transport shape. Fall back to the input model's config
    // for the gateway/multicast text when no override was given.
    let base = load_model_optional(dir).map(|m| m.config.connection);
    let resolved = resolve_config(None, overrides);
    // The keyring setting is the operator's, not derived from the connection
    // used: carry it over from the input model.
    let keyring = base.as_ref().and_then(|c| c.keyring.clone());

    let connection = match resolved {
        Ok(cfg) if cfg.transport == TransportKind::Routing => ModelConnection {
            transport: ModelTransport::Routing,
            gateway: None,
            multicast: Some(cfg.multicast.to_string()),
            keyring,
        },
        Ok(cfg) => ModelConnection {
            transport: ModelTransport::Tunnel,
            gateway: cfg.gateway.map(|g| g.to_string()),
            multicast: None,
            keyring,
        },
        // No override resolvable on its own (e.g. tunnel with no gateway flag):
        // fall back to whatever the input model had.
        Err(_) => base.unwrap_or_default(),
    };
    BussardConfig {
        connection,
        // Reconstruction infers nothing about project lint policy.
        lint: None,
    }
}

/// Prepends [`RECONSTRUCT_BANNER`] to every synthesized YAML file, after
/// `Model::save` has written its own headers (post-serialization injection,
/// like the loader does for the com-objects marker). Idempotent enough for the
/// one-shot save: the banner is added exactly once here.
fn inject_reconstruct_banners(out: &Path) -> anyhow::Result<()> {
    let mut files = vec![
        out.join("bussard.toml"),
        out.join("groups.toml"),
        out.join("links.yaml"),
    ];
    let devices_dir = out.join("devices");
    if let Ok(rd) = std::fs::read_dir(&devices_dir) {
        for entry in rd.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                files.push(path);
            }
        }
    }
    for path in files {
        if !path.exists() {
            continue;
        }
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        std::fs::write(&path, format!("{RECONSTRUCT_BANNER}{body}"))
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

/// Builds the line-mode summary from the swept devices and synthesized model.
fn build_summary(line: &str, out: &Path, found: &[LineDevice], model: &Model) -> LineSummary {
    let mut details = Vec::with_capacity(found.len());
    let mut read = 0usize;
    let mut skipped = 0usize;
    for dev in found {
        let (status, gas, dev_links) = match &dev.tables {
            Some(tables) => {
                read += 1;
                let gas: BTreeSet<GroupAddress> = tables
                    .resolved
                    .iter()
                    .map(|l| l.ga)
                    .chain(tables.addresses.iter().copied())
                    .collect();
                let links = model
                    .links
                    .links
                    .get(&dev.address)
                    .map(Vec::len)
                    .unwrap_or(0);
                ("read", gas.len(), links)
            }
            None => {
                skipped += 1;
                ("stub", 0, 0)
            }
        };
        details.push(LineDeviceDetail {
            address: dev.address.to_string(),
            mask: format!("{:04X}", dev.mask),
            system_type: system_type(dev.mask).to_string(),
            status,
            skip_reason: dev.skipped.clone(),
            group_addresses: gas,
            links: dev_links,
        });
    }

    LineSummary {
        line: line.to_string(),
        out: out.display().to_string(),
        devices_read: read,
        devices_skipped: skipped,
        devices_found: found.len(),
        group_addresses: model.groups.groups.len(),
        links: model.links.links.values().map(Vec::len).sum(),
        device_details: details,
    }
}

/// Prints the human-readable line-mode summary with next steps.
fn print_line_summary(s: &LineSummary) {
    println!("reconstructed line {} into {}", s.line, s.out);
    println!(
        "\n{} device(s) responded: {} read (System B), {} recorded as stubs",
        s.devices_found, s.devices_read, s.devices_skipped
    );
    for d in &s.device_details {
        match d.status {
            "read" => println!(
                "  {}  mask {} ({})  — {} GA(s), {} link(s)",
                d.address, d.mask, d.system_type, d.group_addresses, d.links
            ),
            _ => println!(
                "  {}  mask {} ({})  — stub: {}",
                d.address,
                d.mask,
                d.system_type,
                d.skip_reason.as_deref().unwrap_or("tables skipped")
            ),
        }
    }
    println!(
        "\nsynthesized {} group address(es) and {} link(s)",
        s.group_addresses, s.links
    );
    println!("\nnext steps:");
    println!(
        "  • names & DPTs are placeholders — run `bussard monitor --dir {}` to observe live",
        s.out
    );
    println!("    traffic and name what each GA does; add `dpt:` in groups.toml as you learn it.");
    println!(
        "  • send/listen direction is unknown (all GAs recorded as listen) — correct it as you"
    );
    println!("    observe which object transmits.");
    println!(
        "  • run `bussard validate --dir {}` — W011 (no DPT) warnings are expected and honest.",
        s.out
    );
}
