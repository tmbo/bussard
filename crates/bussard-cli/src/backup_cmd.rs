//! The `bussard backup` subcommand — snapshot every device in the installation
//! (issue #96).
//!
//! `apply` backs up the one device it is about to write. `flash` backs up
//! nothing. This command backs up everything, before anything has been touched:
//! for every device in the model it reads the group-address and association
//! tables and, where bussard can bound the read from the device itself, the
//! writable parameter memory, and writes one JSON file per device plus a
//! `manifest.json` describing the run.
//!
//! # Read-only, and provably so
//!
//! `backup` sends `A_DeviceDescriptor_Read`, `A_Authorize_Request`,
//! `A_PropertyValue_Read` and `A_Memory_Read` — nothing else. It never writes a
//! property, a load control or a byte of memory, so it is safe to run against a
//! live installation, and the mock-gateway test fails the run if a single write
//! APDU reaches the device.
//!
//! # Which devices, and what "skipped" means
//!
//! The targets come from the model: every device, every device on `--line`, or
//! the individual addresses named on the command line. A device whose mask is
//! outside the System B / System 7 families cannot have its tables read, and is
//! recorded in the manifest as `skipped` with the reason. It is never silently
//! dropped: an owner reading the manifest must be able to see exactly which
//! devices are not covered. A device nothing answers for is `unreachable`: listed,
//! but not a failure, because a switched-off device cannot be backed up. A device
//! that answered and whose read then broke is `failed`, and makes the command
//! exit non-zero.
//!
//! # Connection shape
//!
//! One bus connection for the whole run, leased per device exactly as
//! `bussard scan` and `reconstruct --line` do, so the run is serialised against
//! the rest of the bus rather than opening a connection per device in parallel.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{Context, anyhow, bail};
use bussard_download::backup::{
    BackupManifest, BackupStatus, DeviceBackup, ManifestEntry, ParameterMemory, ParameterStatus,
    backups_root, encode_hex, rfc3339_utc, timestamp_dir_name, write_device_backup, write_manifest,
};
use bussard_mgmt::apci::PID_ORDER_INFO;
use bussard_mgmt::{
    L4Channel, Layer4Connection, MaskProfile, Timeouts, read_mcb_table, read_memory_range,
    read_table_reference, system_type,
};
use bussard_model::{IndividualAddress, Model};
use bussard_service::{
    Authorize, BusService, Device, L4Options, ServiceError, SourcePolicy, WritePolicy,
};

use crate::assign_cmd::clean_ascii;
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, gateway_display, load_model_required, open_service,
    resolve_config, session_error_detail,
};
use crate::plan_cmd::{self, LiveRead};

/// The largest parameter image `backup` will pull off a device.
///
/// The extent comes from the device's own `PID_MCB_TABLE`, so a corrupt or
/// unwritten MCB could otherwise ask bussard to read megabytes of memory one
/// 12-octet telegram at a time. 64 KiB is comfortably above every parameter
/// image in the product corpus and bounded enough that a nonsense value fails
/// fast instead of hanging the run.
const MAX_PARAMETER_BYTES: usize = 64 * 1024;

/// Runs `bussard backup`.
#[allow(clippy::too_many_arguments)] // one command's worth of flags; a struct would only move them
pub fn run(
    addresses: &[String],
    line: Option<&str>,
    out: Option<&Path>,
    dir: &Path,
    json: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "`bussard backup` needs the model to know which devices to read; \
             none was loaded from {}",
            dir.display()
        );
    };
    let targets = select_targets(&model, addresses, line)?;
    if targets.is_empty() {
        bail!(
            "no devices to back up: the model in {} has no matching device files",
            dir.display()
        );
    }
    let config = resolve_config(Some(&model), &overrides)?;
    let gateway = gateway_display(&config);
    // The targets the model records as security-activated: a keyring without
    // their entry is an error for them, while any other device the keyring does
    // not list is read in the clear (issue #189).
    let activated: std::collections::BTreeSet<IndividualAddress> = targets
        .iter()
        .copied()
        .filter(|&t| crate::secure_key::model_activated(Some(&model), t))
        .collect();

    let started = SystemTime::now();
    let out_dir: PathBuf = match out {
        Some(p) => p.to_path_buf(),
        None => backups_root(dir).join(timestamp_dir_name(started)),
    };

    eprintln!(
        "backing up {} device(s) via {gateway} into {}",
        targets.len(),
        out_dir.display()
    );

    let runtime = tokio::runtime::Runtime::new()?;
    let captured = runtime.block_on(async move {
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let source = checked_source_or_close(&service, &overrides).await?;
        let captured = tokio::select! {
            captured = capture_all(&service, source, &targets, &activated, tool_key_source) => captured,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Vec::new()
            }
        };
        service.close().await;
        anyhow::Ok(captured)
    })?;

    let mut manifest = BackupManifest::new(gateway, started);
    for capture in &captured {
        let mut entry = capture.entry.clone();
        if let Some(backup) = &capture.backup {
            let path = write_device_backup(&out_dir, backup)
                .context("writing a device backup (the run is not usable without it)")?;
            entry.file = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
        }
        manifest.devices.push(entry);
    }
    let manifest_path = write_manifest(&out_dir, &manifest).context("writing the manifest")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
    } else {
        print_text(&manifest, &out_dir, &manifest_path);
    }

    if manifest.any_failed() {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// One device's outcome: the manifest row, plus the backup to write when there
/// is one.
struct Capture {
    /// The manifest row (always present, whatever happened).
    entry: ManifestEntry,
    /// The device's backup, when its tables were read.
    backup: Option<DeviceBackup>,
}

/// Resolves the devices to back up: the explicit addresses, the model devices on
/// `--line`, or every model device.
fn select_targets(
    model: &Model,
    addresses: &[String],
    line: Option<&str>,
) -> anyhow::Result<Vec<IndividualAddress>> {
    if !addresses.is_empty() {
        let mut out = Vec::with_capacity(addresses.len());
        for raw in addresses {
            out.push(
                raw.parse::<IndividualAddress>()
                    .with_context(|| format!("parsing device address {raw:?}"))?,
            );
        }
        out.sort_unstable();
        out.dedup();
        return Ok(out);
    }
    let all = model.devices.keys().copied();
    match line {
        Some(line) => {
            let (area, line_no) = parse_line(line)?;
            Ok(all
                .filter(|ia| ia.area() == area && ia.line() == line_no)
                .collect())
        }
        None => Ok(all.collect()),
    }
}

/// Parses `area.line` (e.g. `1.1`) into its two parts.
fn parse_line(line: &str) -> anyhow::Result<(u8, u8)> {
    let parts: Vec<&str> = line.split('.').collect();
    if parts.len() != 2 {
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
        return Err(anyhow!("area and line must each be 0-15 (got {line:?})"));
    }
    Ok((area, line_no))
}

/// Reads every target in turn over one bus connection, leasing it per device.
async fn capture_all(
    service: &BusService,
    source: IndividualAddress,
    targets: &[IndividualAddress],
    activated: &std::collections::BTreeSet<IndividualAddress>,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
) -> Vec<Capture> {
    let mut out = Vec::with_capacity(targets.len());
    for (n, &target) in targets.iter().enumerate() {
        eprintln!("[{}/{}] reading {target}…", n + 1, targets.len());
        let is_activated = activated.contains(&target);
        out.push(capture_one(service, source, target, is_activated, tool_key_source).await);
    }
    out
}

/// Reads one device: identity, tables, and (where bounded) parameter memory.
async fn capture_one(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    activated: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
) -> Capture {
    let tool_key = match crate::secure_key::resolve(target, tool_key_source, activated) {
        Ok(key) => key,
        Err(err) => return Capture::failed(target, format!("resolving the tool key: {err}")),
    };
    // Presence first, on the fast discovery budget `scan` uses: an absent device
    // is ruled out in about three seconds instead of the full management budget.
    let mask = match probe_mask(service, source, target).await {
        Probe::Present(mask) => mask,
        Probe::Absent => return Capture::unreachable(target),
        Probe::Error(detail) => return Capture::failed(target, detail),
    };

    // Then a fresh session on the normal budget for the reads themselves, as
    // `reconstruct --line` does after its descriptor probe.
    // Authorize with the free-access key before reading, as ETS does and as
    // System 7 requires before any memory access. Best-effort on a read-only run.
    let options = L4Options {
        source: SourcePolicy::Known(source),
        tool_key,
        high_water: bussard_secure::SequenceHighWater::new(),
        authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
        ..L4Options::default()
    };
    let session = service
        .with_device(target, &options, async |dev| {
            Ok::<_, ServiceError>(read_one(dev, target).await)
        })
        .await;
    match session {
        Ok(capture) => {
            tracing::debug!("{target} answered the presence probe with mask {mask:04X}");
            capture
        }
        Err(err) => Capture::failed(target, session_error_detail(&err)),
    }
}

/// Reads one device's identity, tables and parameter memory on an open,
/// authorized session.
async fn read_one(dev: &mut Device, target: IndividualAddress) -> Capture {
    let order = dev
        .read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| clean_ascii(&v))
        .filter(|s| !s.is_empty());

    let read_at = SystemTime::now();
    let live = plan_cmd::read_live_tables(dev.l4_mut()).await;
    match live {
        Err(err) => Capture::failed(target, format!("reading the tables: {err:#}")),
        Ok(LiveRead::UnsupportedMask { mask, .. }) => Capture {
            entry: ManifestEntry {
                address: target.to_string(),
                status: BackupStatus::Skipped,
                mask: Some(format!("{mask:04X}")),
                system_type: Some(system_type(mask).to_string()),
                application: None,
                order_number: order.clone(),
                read_time: Some(rfc3339_utc(read_at)),
                file: None,
                parameters: None,
                detail: Some(format!(
                    "unsupported mask {mask:04X} ({}): bussard reads tables for the System B \
                     (x7B0) and System 7 (0705 / 0701) families",
                    system_type(mask)
                )),
            },
            backup: None,
        },
        Ok(LiveRead::Tables(live)) => {
            let tables = live.tables().clone();
            let sys7 = live.sys7().cloned();
            let (application, parameters, parameter_status) =
                read_application_state(dev.l4_mut(), tables.mask).await;
            let backup = DeviceBackup::capture(target, &tables, sys7.as_ref(), parameters, read_at);
            Capture {
                entry: ManifestEntry {
                    address: target.to_string(),
                    status: BackupStatus::BackedUp,
                    mask: Some(format!("{:04X}", tables.mask)),
                    system_type: Some(system_type(tables.mask).to_string()),
                    application,
                    order_number: order.clone(),
                    read_time: Some(rfc3339_utc(read_at)),
                    file: None,
                    parameters: Some(parameter_status),
                    detail: None,
                },
                backup: Some(backup),
            }
        }
    }
}

/// The outcome of the fast presence probe.
enum Probe {
    /// The device answered its descriptor read with this mask.
    Present(u16),
    /// Nothing answered.
    Absent,
    /// Something answered, but not usably.
    Error(String),
}

/// Reads the device descriptor on the discovery budget.
async fn probe_mask(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
) -> Probe {
    let options = L4Options {
        source: SourcePolicy::Known(source),
        timeouts: Timeouts::discovery(),
        authorize: Authorize::Skip,
        ..L4Options::default()
    };
    let session = service
        .with_device(target, &options, async |dev| {
            Ok::<_, ServiceError>(match dev.device_descriptor().await {
                Ok(mask) => Probe::Present(mask),
                Err(err) if !err.device_present() => Probe::Absent,
                Err(err) => Probe::Error(format!("reading the device descriptor: {err}")),
            })
        })
        .await;
    match session {
        Ok(probe) => probe,
        Err(ServiceError::Mgmt(err)) if !err.device_present() => Probe::Absent,
        Err(err) => Probe::Error(session_error_detail(&err)),
    }
}

impl Capture {
    /// A model device nothing answered for.
    fn unreachable(target: IndividualAddress) -> Capture {
        let mut capture = Capture::failed(
            target,
            "no answer at this address (switched off, disconnected, or removed)".to_string(),
        );
        capture.entry.status = BackupStatus::Unreachable;
        capture
    }

    /// A device that answered, but whose read failed.
    fn failed(target: IndividualAddress, detail: String) -> Capture {
        Capture {
            entry: ManifestEntry {
                address: target.to_string(),
                status: BackupStatus::Failed,
                mask: None,
                system_type: None,
                application: None,
                order_number: None,
                read_time: Some(rfc3339_utc(SystemTime::now())),
                file: None,
                parameters: None,
                detail: Some(detail),
            },
            backup: None,
        }
    }
}

/// Reads the resident application identity and, where bussard can bound the
/// read, the writable parameter memory.
///
/// # Where the bounds come from
///
/// On **System B** the parameter image is the application-program object's
/// relative segment, and the device reports both ends of it: element 1 of
/// `PID_TABLE_REFERENCE` is the base the device placed the segment at (the same
/// value a `WriteRelMem` flash step resolves its write address from), and the
/// first `PID_MCB_TABLE` entry's segment size is its length. So the whole image
/// `flash` would rewrite can be read back without any vendor product data.
///
/// On **System 7** the parameter image sits at the fixed LSM 3 address
/// (`0x4400`), but its extent lives only in the product's `.knxprod` — the
/// device reports no segment size. Reading an arbitrary window of neighbouring
/// memory would be a guess, so the parameter memory is reported as not captured,
/// with that reason, rather than silently omitted.
async fn read_application_state<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    mask: u16,
) -> (Option<String>, Option<ParameterMemory>, ParameterStatus) {
    if !MaskProfile::from_mask(mask).is_system_b() {
        return (
            None,
            None,
            ParameterStatus::not_captured(
                "System 7 reports no segment size for its parameter image (LSM 3 at 0x4400); \
                 its extent comes from the product data, so bussard will not guess a read length",
            ),
        );
    }
    let app_obj = match bussard_download::discover_application_object(l4).await {
        Ok(obj) => obj,
        Err(err) => {
            return (
                None,
                None,
                ParameterStatus::not_captured(format!(
                    "no application-program interface object to read the parameter segment from: \
                     {err}"
                )),
            );
        }
    };
    let application = bussard_mgmt::read_program_version(l4, app_obj)
        .await
        .ok()
        .flatten()
        .map(|id| bussard_download::format_app_id(&id));

    let base = match read_table_reference(l4, app_obj).await {
        Ok(base) => base,
        Err(err) => {
            return (
                application,
                None,
                ParameterStatus::not_captured(format!(
                    "object {app_obj} did not answer PID_TABLE_REFERENCE (the segment base): {err}"
                )),
            );
        }
    };
    let length = match read_mcb_table(l4, app_obj, 0, 1, None).await {
        Ok(entries) => entries
            .first()
            .map(|e| e.segment_size as usize)
            .unwrap_or(0),
        Err(err) => {
            return (
                application,
                None,
                ParameterStatus::not_captured(format!(
                    "object {app_obj} did not answer PID_MCB_TABLE (the segment size): {err}"
                )),
            );
        }
    };
    if length == 0 {
        return (
            application,
            None,
            ParameterStatus::not_captured(format!(
                "object {app_obj} reports a zero-octet segment: nothing has been downloaded to it"
            )),
        );
    }
    if length > MAX_PARAMETER_BYTES {
        return (
            application,
            None,
            ParameterStatus::not_captured(format!(
                "object {app_obj} reports a {length}-octet segment, above the \
                 {MAX_PARAMETER_BYTES}-octet backup limit; refusing to stream it"
            )),
        );
    }
    match read_memory_range(l4, base, length).await {
        Ok(bytes) => {
            let status = ParameterStatus::captured(base, bytes.len());
            (
                application,
                Some(ParameterMemory {
                    base,
                    length: bytes.len(),
                    bytes: encode_hex(&bytes),
                    source: format!(
                        "System B application segment (object {app_obj}, \
                         PID_TABLE_REFERENCE + PID_MCB_TABLE)"
                    ),
                }),
                status,
            )
        }
        Err(err) => (
            application,
            None,
            ParameterStatus::not_captured(format!(
                "reading {length} octet(s) at {base:#X} failed: {err}"
            )),
        ),
    }
}

/// Prints the per-device table and the run summary.
fn print_text(manifest: &BackupManifest, out_dir: &Path, manifest_path: &Path) {
    println!();
    for entry in &manifest.devices {
        let mask = entry.mask.as_deref().unwrap_or("----");
        println!("  {:<10} {mask}  {}", entry.address, entry.status);
        if let Some(detail) = &entry.detail {
            println!("      {detail}");
        }
        if let Some(p) = &entry.parameters {
            match (p.captured, p.length, &p.reason) {
                (true, Some(len), _) => println!("      parameters: {len} octet(s)"),
                (false, _, Some(reason)) => println!("      parameters: not captured: {reason}"),
                _ => {}
            }
        }
    }
    let totals = manifest.totals();
    println!(
        "\n{} backed up, {} skipped, {} unreachable, {} failed",
        totals.get("backed_up").copied().unwrap_or(0),
        totals.get("skipped").copied().unwrap_or(0),
        totals.get("unreachable").copied().unwrap_or(0),
        totals.get("failed").copied().unwrap_or(0),
    );
    println!("backup directory: {}", out_dir.display());
    println!("manifest: {}", manifest_path.display());
    println!(
        "\nrestore one device with `bussard restore {} <ia>`",
        out_dir.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::LoadedDevice;
    use bussard_model::schema::Device;

    fn model_with(addrs: &[&str]) -> Model {
        let mut model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: Default::default(),
        };
        for s in addrs {
            let Ok(addr) = s.parse::<IndividualAddress>() else {
                continue;
            };
            model.devices.insert(
                addr,
                LoadedDevice {
                    device: Device {
                        address: addr,
                        name: s.to_string(),
                        description: None,
                        location: None,
                        product: None,
                        replaced: None,
                        channels: Default::default(),
                        parameters: Default::default(),
                        module_bases: Default::default(),
                        com_objects: Default::default(),
                        security: None,
                        application_override: None,
                        lock: Default::default(),
                    },
                    file_stem: s.to_string(),
                },
            );
        }
        model
    }

    #[test]
    fn test_select_targets_defaults_to_every_model_device() -> Result<(), Box<dyn std::error::Error>>
    {
        let model = model_with(&["1.1.4", "1.2.7", "2.1.1"]);
        let targets = select_targets(&model, &[], None)?;
        assert_eq!(targets.len(), 3);
        Ok(())
    }

    #[test]
    fn test_select_targets_line_filters_the_model() -> Result<(), Box<dyn std::error::Error>> {
        let model = model_with(&["1.1.4", "1.2.7", "2.1.1"]);
        let targets = select_targets(&model, &[], Some("1.1"))?;
        assert_eq!(targets, vec!["1.1.4".parse::<IndividualAddress>()?]);
        Ok(())
    }

    #[test]
    fn test_select_targets_explicit_addresses_win() -> Result<(), Box<dyn std::error::Error>> {
        let model = model_with(&["1.1.4"]);
        let targets = select_targets(&model, &["1.1.9".to_string()], Some("1.1"))?;
        assert_eq!(targets, vec!["1.1.9".parse::<IndividualAddress>()?]);
        Ok(())
    }

    #[test]
    fn test_parse_line_rejects_nonsense() {
        assert!(parse_line("1").is_err());
        assert!(parse_line("16.1").is_err());
        assert!(parse_line("1.1.4").is_err());
    }
}
