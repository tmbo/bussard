//! Backing devices up: the reads behind `bussard backup` and
//! `knx_backup_device` (issues #96, #717).
//!
//! For every target this reads the group-address and association tables and,
//! where bussard can bound the read from the device itself, the writable
//! parameter memory, and returns one [`DeviceCapture`] per device: the
//! manifest row and, when the tables were read, the backup to write.
//! [`write_backup_run`] then writes one JSON file per device plus a
//! `manifest.json` describing the run.
//!
//! # Read-only, and provably so
//!
//! A backup sends `A_DeviceDescriptor_Read`, `A_Authorize_Request`,
//! `A_PropertyValue_Read` and `A_Memory_Read`, nothing else. It never writes a
//! property, a load control or a byte of memory, so it is safe to run against
//! a live installation.
//!
//! # Which devices, and what "skipped" means
//!
//! A device whose mask is outside the System B / System 7 families cannot have
//! its tables read, and is recorded as `skipped` with the reason. It is never
//! silently dropped. A device nothing answers for is `unreachable`: listed,
//! but not a failure. A device that answered and whose read then broke is
//! `failed`.
//!
//! # Connection shape
//!
//! One bus connection for the whole run, leased per device, so the run is
//! serialised against the rest of the bus rather than opening a connection
//! per device in parallel. Each device gets a presence probe on the caller's
//! discovery budget first, then a fresh session on the normal budget.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bussard_download::backup::{
    BackupError, BackupManifest, BackupStatus, DeviceBackup, ManifestEntry, ParameterMemory,
    ParameterStatus, backups_root, encode_hex, rfc3339_utc, timestamp_dir_name,
    write_device_backup, write_manifest,
};
use bussard_download::{LiveRead, Sys7TableBases};
use bussard_mgmt::apci::PID_ORDER_INFO;
use bussard_mgmt::{
    L4Channel, Layer4Connection, MaskProfile, Timeouts, read_mcb_table, read_memory_range,
    read_table_reference, system_type,
};
use bussard_model::{IndividualAddress, Model};
use bussard_secure::Key16;

use crate::secure::SecureKeyError;
use crate::{Authorize, BusService, Device, FactsCache, L4Options, ServiceError, SourcePolicy};

/// The largest parameter image a backup will pull off a device.
///
/// The extent comes from the device's own `PID_MCB_TABLE`, so a corrupt or
/// unwritten MCB could otherwise ask bussard to read megabytes of memory one
/// 12-octet telegram at a time. 64 KiB is comfortably above every parameter
/// image in the product corpus and bounded enough that a nonsense value fails
/// fast instead of hanging the run.
pub const MAX_PARAMETER_BYTES: usize = 64 * 1024;

/// Why the targets of a backup could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// An address argument is not an individual address.
    #[error("parsing device address {0:?}")]
    Address(String),
    /// A `--line` argument is not `area.line`.
    #[error("invalid line {0:?}; expected area.line like \"1.1\"")]
    Line(String),
    /// The area or line is out of range.
    #[error("area and line must each be 0-15 (got {0:?})")]
    LineRange(String),
}

/// Resolves the devices to back up: the explicit `addresses` (sorted, without
/// duplicates), else the model devices on `line`, else every model device.
///
/// # Errors
///
/// [`TargetError`] for an address or line that does not parse.
pub fn select_targets(
    model: &Model,
    addresses: &[String],
    line: Option<&str>,
) -> Result<Vec<IndividualAddress>, TargetError> {
    if !addresses.is_empty() {
        let mut out = Vec::with_capacity(addresses.len());
        for raw in addresses {
            out.push(
                raw.trim()
                    .parse::<IndividualAddress>()
                    .map_err(|_| TargetError::Address(raw.clone()))?,
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
///
/// # Errors
///
/// [`TargetError::Line`] or [`TargetError::LineRange`].
pub fn parse_line(line: &str) -> Result<(u8, u8), TargetError> {
    let parts: Vec<&str> = line.split('.').collect();
    if parts.len() != 2 {
        return Err(TargetError::Line(line.to_string()));
    }
    let area: u8 = parts[0]
        .parse()
        .map_err(|_| TargetError::Line(line.to_string()))?;
    let line_no: u8 = parts[1]
        .parse()
        .map_err(|_| TargetError::Line(line.to_string()))?;
    if area > 15 || line_no > 15 {
        return Err(TargetError::LineRange(line.to_string()));
    }
    Ok((area, line_no))
}

/// Where a backup run started at `started` goes by default:
/// `<dir>/captures/backups/<timestamp>`.
pub fn default_out_dir(dir: &Path, started: SystemTime) -> PathBuf {
    backups_root(dir).join(timestamp_dir_name(started))
}

/// One device's outcome: the manifest row, plus the backup to write when
/// there is one.
#[derive(Debug, Clone)]
pub struct DeviceCapture {
    /// The manifest row (always present, whatever happened).
    pub entry: ManifestEntry,
    /// The device's backup, when its tables were read.
    pub backup: Option<DeviceBackup>,
}

/// What a running backup reports, for a surface that shows progress.
#[derive(Debug)]
pub enum BackupProgress<'a> {
    /// The `index`-th of `total` targets (1-based) is being read.
    Reading {
        /// 1-based position of the target.
        index: usize,
        /// How many targets the run has.
        total: usize,
        /// The device.
        target: IndividualAddress,
    },
    /// A device's read ended (whatever the outcome).
    Captured(&'a DeviceCapture),
}

/// Resolves the Data Secure tool key of a device: the device and whether the
/// model records it as security-activated, to the key or the plain path.
pub type ToolKeyFn<'a> =
    &'a (dyn Fn(IndividualAddress, bool) -> Result<Option<Key16>, SecureKeyError> + Sync);

/// Whether a device's application leaves `SupportsExtendedMemoryServices`
/// unset, so memory above `0xFFFF` is read with `A_UserMemory_Read` (issue
/// #472). Consulted only for a segment above `0xFFFF`.
pub type UserMemoryFn<'a> = &'a (dyn Fn(IndividualAddress) -> bool + Sync);

/// The context of one backup run.
#[derive(Clone, Copy)]
pub struct BackupInputs<'a> {
    /// The model the devices' identity is compared with and their activation
    /// is read from.
    pub model: &'a Model,
    /// The checked source address of the run.
    pub source: IndividualAddress,
    /// The device facts store (issue #209).
    pub facts: &'a FactsCache,
    /// The budget of the presence probe (`scan`'s discovery budget).
    pub probe_timeouts: Timeouts,
    /// The tool key resolver.
    pub tool_key: ToolKeyFn<'a>,
    /// The `A_UserMemory_Read` choice per device.
    pub user_memory_above_64k: UserMemoryFn<'a>,
}

/// Reads every target in turn over one bus connection, leasing it per device,
/// and reports each step to `progress`.
pub async fn capture_devices(
    service: &BusService,
    inputs: BackupInputs<'_>,
    targets: &[IndividualAddress],
    progress: &mut (dyn FnMut(BackupProgress<'_>) + Send),
) -> Vec<DeviceCapture> {
    let mut out = Vec::with_capacity(targets.len());
    for (n, &target) in targets.iter().enumerate() {
        progress(BackupProgress::Reading {
            index: n + 1,
            total: targets.len(),
            target,
        });
        let capture = capture_one(service, inputs, target).await;
        progress(BackupProgress::Captured(&capture));
        out.push(capture);
    }
    out
}

/// Writes the captures of a run into `out_dir`: one file per backed-up device
/// and the `manifest.json` naming them. Returns the manifest and its path.
///
/// # Errors
///
/// [`BackupError`] when a file cannot be written: the run is not usable
/// without it.
pub fn write_backup_run(
    out_dir: &Path,
    gateway: impl Into<String>,
    started: SystemTime,
    captures: &[DeviceCapture],
) -> Result<(BackupManifest, PathBuf), BackupError> {
    let mut manifest = BackupManifest::new(gateway, started);
    for capture in captures {
        let mut entry = capture.entry.clone();
        if let Some(backup) = &capture.backup {
            let path = write_device_backup(out_dir, backup)?;
            entry.file = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
        }
        manifest.devices.push(entry);
    }
    let manifest_path = write_manifest(out_dir, &manifest)?;
    Ok((manifest, manifest_path))
}

/// Reads one device: identity, tables, and (where bounded) parameter memory.
async fn capture_one(
    service: &BusService,
    inputs: BackupInputs<'_>,
    target: IndividualAddress,
) -> DeviceCapture {
    let activated = crate::secure::model_activated(Some(inputs.model), target);
    let tool_key = match (inputs.tool_key)(target, activated) {
        Ok(key) => key,
        Err(err) => {
            return DeviceCapture::failed(target, format!("resolving the tool key: {err}"));
        }
    };
    // Presence first, on the fast discovery budget: an absent device is ruled
    // out in about three seconds instead of the full management budget.
    let mask = match probe_mask(service, inputs.source, target, inputs.probe_timeouts).await {
        Probe::Present(mask) => mask,
        Probe::Absent => return DeviceCapture::unreachable(target),
        Probe::Error(detail) => return DeviceCapture::failed(target, detail),
    };

    // Then a fresh session on the normal budget for the reads themselves.
    // Authorize with the free-access key before reading, as ETS does and as
    // System 7 requires before any memory access. Best-effort on a read-only
    // run.
    let options = L4Options {
        source: SourcePolicy::Known(inputs.source),
        tool_key,
        high_water: bussard_secure::SequenceHighWater::new(),
        authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
        ..L4Options::default()
    };
    let device = inputs.model.devices.get(&target).map(|d| &d.device);
    let user_memory = inputs.user_memory_above_64k;
    let session = service
        .with_device(target, &options, async |dev| {
            // The facts seed the connection, so the table reader skips its
            // walk, and give the identity verdict.
            let check = match crate::identify(dev.l4_mut(), inputs.facts, device).await {
                Ok(identified) => identified.check,
                Err(err) => {
                    tracing::debug!("{target} device facts: {err}");
                    None
                }
            };
            let mut capture = read_one(dev, target, || user_memory(target)).await;
            capture.entry.identity = check;
            Ok::<_, ServiceError>(capture)
        })
        .await;
    match session {
        Ok(capture) => {
            tracing::debug!("{target} answered the presence probe with mask {mask:04X}");
            capture
        }
        Err(err) => DeviceCapture::failed(target, session_error_detail(&err)),
    }
}

/// A session error in the words of a manifest row.
fn session_error_detail(err: &ServiceError) -> String {
    match err {
        ServiceError::Lease(cause) => format!("leasing the bus: {cause}"),
        other => format!("connecting: {other}"),
    }
}

/// The printable ASCII of a property value up to its first NUL, trimmed.
fn clean_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| *b as char)
        .collect();
    s.trim().to_string()
}

/// Reads one device's identity, tables and parameter memory on an open,
/// authorized session.
async fn read_one(
    dev: &mut Device,
    target: IndividualAddress,
    user_memory: impl FnOnce() -> bool,
) -> DeviceCapture {
    let order = dev
        .read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| clean_ascii(&v))
        .filter(|s| !s.is_empty());

    let read_at = SystemTime::now();
    let live = bussard_download::read_live_tables_at(dev.l4_mut(), Sys7TableBases::default()).await;
    match live {
        Err(err) => DeviceCapture::failed(target, format!("reading the tables: {err}")),
        Ok(LiveRead::UnsupportedMask { mask, .. }) => DeviceCapture {
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
                identity: None,
            },
            backup: None,
        },
        Ok(LiveRead::Tables(live)) => {
            let tables = live.tables().clone();
            let sys7 = live.sys7().cloned();
            let (application, parameters, parameter_status) =
                read_application_state(dev.l4_mut(), tables.mask, user_memory).await;
            let backup = DeviceBackup::capture(target, &tables, sys7.as_ref(), parameters, read_at);
            DeviceCapture {
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
                    identity: None,
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
    timeouts: Timeouts,
) -> Probe {
    let options = L4Options {
        source: SourcePolicy::Known(source),
        timeouts,
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

impl DeviceCapture {
    /// A device nothing answered for.
    fn unreachable(target: IndividualAddress) -> DeviceCapture {
        let mut capture = DeviceCapture::failed(
            target,
            "no answer at this address (switched off, disconnected, or removed)".to_string(),
        );
        capture.entry.status = BackupStatus::Unreachable;
        capture
    }

    /// A device that answered, but whose read failed.
    fn failed(target: IndividualAddress, detail: String) -> DeviceCapture {
        DeviceCapture {
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
                identity: None,
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
/// `PID_TABLE_REFERENCE` is the base the device placed the segment at, and the
/// first `PID_MCB_TABLE` entry's segment size is its length. So the whole
/// image `flash` would rewrite can be read back without any vendor product
/// data.
///
/// On **System 7** the parameter image sits at the fixed LSM 3 address
/// (`0x4400`), but its extent lives only in the product's `.knxprod`: the
/// device reports no segment size. Reading an arbitrary window of neighbouring
/// memory would be a guess, so the parameter memory is reported as not
/// captured, with that reason, rather than silently omitted.
async fn read_application_state<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    mask: u16,
    user_memory: impl FnOnce() -> bool,
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
    // A segment above 0xFFFF is read with A_UserMemory_Read when the device's
    // application does not announce extended memory services, as ETS does
    // (issue #472). Only then is the product data consulted.
    if bussard_mgmt::select_extended_memory(base, length) {
        l4.set_user_memory_above_64k(user_memory());
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

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::LoadedDevice;
    use bussard_model::schema::Device as ModelDevice;

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
                    device: ModelDevice {
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
                        knxnet: None,
                        lock: Default::default(),
                    },
                    file_stem: s.to_string(),
                },
            );
        }
        model
    }

    #[test]
    fn test_select_targets_defaults_to_every_model_device() -> Result<(), TargetError> {
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

    #[test]
    fn test_clean_ascii_stops_at_nul() {
        assert_eq!(clean_ascii(b" 2CHANG.01\0junk"), "2CHANG.01");
    }
}
