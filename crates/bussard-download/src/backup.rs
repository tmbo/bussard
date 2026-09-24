//! The on-disk device backup format shared by `bussard apply`, `bussard backup`
//! and `bussard restore` (issue #96).
//!
//! `apply` has always written a JSON snapshot of a device's pre-write state
//! before it touches a load state. That snapshot is the only thing standing
//! between an owner and an unrecoverable device, so it is worth having exactly
//! one definition of it: this module. `apply` writes it, `bussard backup` writes
//! one per device plus a [`BackupManifest`], and `bussard restore` reads it back
//! and turns it into the [`DesiredTables`] the apply machinery already knows how
//! to write.
//!
//! # What a backup holds
//!
//! - the device's mask and individual address;
//! - the group-address table and the association table exactly as read;
//! - the resolved `(com-object, GA)` links, for human review;
//! - on System 7, the group-object descriptor image and where it sat, because
//!   those octets share the `0x4000` region with the address table and `apply`
//!   rewrites them verbatim (see [`crate::apply_sys7`]);
//! - optionally the device's writable **parameter memory**, when bussard can
//!   bound the read from the device itself (see [`ParameterMemory`]).
//!
//! # What it does not hold
//!
//! The application image. Re-flashing is `bussard flash` with the vendor
//! `.knxprod`; a backup that pretended to carry a vendor image would be both
//! enormous and a licence problem.
//!
//! Everything here is pure file and data handling — no bus I/O.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bussard_mgmt::tables::DeviceTables;
use bussard_model::{GroupAddress, IndividualAddress};
use serde::{Deserialize, Serialize};

use crate::compute::DesiredTables;
use crate::tables_sys7::Sys7LiveTables;

/// The file name of the per-run manifest inside a `bussard backup` directory.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Anything that can go wrong reading or writing a backup.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// A filesystem operation failed.
    #[error("{path}: {source}")]
    Io {
        /// The path being read, written or created.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A backup file could not be parsed as JSON in this format.
    #[error("{path} is not a bussard device backup: {source}")]
    Decode {
        /// The offending file.
        path: PathBuf,
        /// The serde failure.
        #[source]
        source: serde_json::Error,
    },
    /// A backup parsed, but carries a value bussard cannot use.
    #[error("{path}: {reason}")]
    Malformed {
        /// The offending file.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
    /// Serialising a backup or manifest failed.
    #[error("serialising the backup: {0}")]
    Encode(#[source] serde_json::Error),
    /// No backup for the requested device exists in the directory.
    #[error("no backup for {address} in {dir} (expected a file named {address}-<timestamp>.json)")]
    NotFound {
        /// The directory searched.
        dir: PathBuf,
        /// The device looked for.
        address: IndividualAddress,
    },
}

/// One association-table entry as stored in a backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociationEntry {
    /// The 1-based index into the group-address table.
    pub tsap: u16,
    /// The com-object number.
    pub asap: u16,
}

/// One resolved `(com-object, group address)` link as stored in a backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEntry {
    /// The com-object number.
    pub object: u16,
    /// The group address, formatted `main/middle/sub`.
    pub ga: String,
}

/// The System 7 specifics a backup carries alongside the shared table view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sys7Detail {
    /// The device's own individual address, as stored in address-table slot 0
    /// (four hex digits).
    pub own_ia: String,
    /// Where the group-object descriptor table started inside the `0x4000`
    /// region (four hex digits).
    pub group_object_base: String,
    /// The group-object table image exactly as read, hex-encoded.
    pub group_object_image: String,
}

/// A device's writable parameter memory, when bussard could bound the read.
///
/// On **System B** the parameter image lives in the application-program object's
/// relative segment. Both ends of that segment are readable from the device
/// itself — `PID_TABLE_REFERENCE` gives the base the device placed it at and
/// `PID_MCB_TABLE` gives its size — so `bussard backup` can capture it without
/// any vendor product data.
///
/// On **System 7** the parameter image sits at the fixed LSM 3 address
/// (`0x4400`), but nothing on the device reports its extent: the length comes
/// from the product's `.knxprod`. Rather than read an arbitrary window of
/// neighbouring memory, `bussard backup` records the parameter memory as not
/// captured and says so in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterMemory {
    /// The absolute device address the image starts at.
    pub base: u32,
    /// The image length in octets.
    pub length: usize,
    /// The image, hex-encoded (uppercase, no separators).
    pub bytes: String,
    /// Where the extent came from, e.g. `"System B application segment
    /// (PID_TABLE_REFERENCE + PID_MCB_TABLE)"`.
    pub source: String,
}

impl ParameterMemory {
    /// The decoded image octets.
    pub fn octets(&self) -> Option<Vec<u8>> {
        decode_hex(&self.bytes)
    }
}

/// One device's complete backup: the JSON `apply` has always written, plus the
/// optional parameter memory `bussard backup` adds.
///
/// The field order is the serialised order, and it is deliberately unchanged
/// from the pre-issue-96 `apply` backup so older files still read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBackup {
    /// The device's individual address.
    pub address: String,
    /// The mask version, four hex digits.
    pub mask: String,
    /// When the device was read, as seconds since the Unix epoch.
    pub unix_timestamp: u64,
    /// When the device was read, as an RFC3339 UTC timestamp. Absent in backups
    /// written before issue #96.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_time: Option<String>,
    /// The System 7 detail, or `null` on System B.
    pub system7: Option<Sys7Detail>,
    /// The group-address table in table order.
    pub addresses: Vec<String>,
    /// The association table in table order.
    pub associations: Vec<AssociationEntry>,
    /// The resolved `(object, GA)` links.
    pub resolved: Vec<ResolvedEntry>,
    /// Per-path notes from the table reader.
    pub notes: Vec<String>,
    /// The device's parameter memory, when it was captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ParameterMemory>,
}

impl DeviceBackup {
    /// Builds a backup from a live table read.
    ///
    /// `sys7` carries the System 7 group-object image when the device is System
    /// 7; `parameters` is the captured parameter memory, when there is one.
    pub fn capture(
        address: IndividualAddress,
        live: &DeviceTables,
        sys7: Option<&Sys7LiveTables>,
        parameters: Option<ParameterMemory>,
        read_at: SystemTime,
    ) -> DeviceBackup {
        DeviceBackup {
            address: address.to_string(),
            mask: format!("{:04X}", live.mask),
            unix_timestamp: unix_seconds(read_at),
            read_time: Some(rfc3339_utc(read_at)),
            system7: sys7.map(|s7| Sys7Detail {
                own_ia: format!("{:04X}", s7.own_ia),
                group_object_base: format!("{:04X}", s7.group_object_base),
                group_object_image: encode_hex(&s7.group_object_image),
            }),
            addresses: live.addresses.iter().map(|g| g.to_string()).collect(),
            associations: live
                .associations
                .iter()
                .map(|&(tsap, asap)| AssociationEntry { tsap, asap })
                .collect(),
            resolved: live
                .resolved
                .iter()
                .map(|l| ResolvedEntry {
                    object: l.object,
                    ga: l.ga.to_string(),
                })
                .collect(),
            notes: live.notes.clone(),
            parameters,
        }
    }

    /// The device address this backup was taken from.
    pub fn device_address(&self, path: &Path) -> Result<IndividualAddress, BackupError> {
        self.address.parse().map_err(|_| BackupError::Malformed {
            path: path.to_path_buf(),
            reason: format!("{:?} is not an individual address", self.address),
        })
    }

    /// The mask version this backup was taken from.
    pub fn mask_version(&self, path: &Path) -> Result<u16, BackupError> {
        u16::from_str_radix(&self.mask, 16).map_err(|_| BackupError::Malformed {
            path: path.to_path_buf(),
            reason: format!("{:?} is not a four-hex-digit mask version", self.mask),
        })
    }

    /// The backed-up tables as the [`DesiredTables`] the apply machinery writes.
    ///
    /// This is what makes `bussard restore` the same command as `bussard apply`
    /// with a different source of truth: the tables recorded here replace the
    /// ones computed from `links.yaml`, and everything downstream — the plan, the
    /// confirmation, the write, the read-back verify — is unchanged.
    pub fn desired_tables(&self, path: &Path) -> Result<DesiredTables, BackupError> {
        let mut addresses = Vec::with_capacity(self.addresses.len());
        for raw in &self.addresses {
            let ga: GroupAddress = raw.parse().map_err(|_| BackupError::Malformed {
                path: path.to_path_buf(),
                reason: format!("{raw:?} in `addresses` is not a group address"),
            })?;
            addresses.push(ga);
        }
        let associations = self
            .associations
            .iter()
            .map(|a| (a.tsap, a.asap))
            .collect::<Vec<_>>();
        // A TSAP that indexes past the address table would write an association
        // table pointing at nothing. Refuse here rather than on the device.
        for &(tsap, asap) in &associations {
            if tsap == 0 || usize::from(tsap) > addresses.len() {
                return Err(BackupError::Malformed {
                    path: path.to_path_buf(),
                    reason: format!(
                        "association (tsap {tsap}, asap {asap}) indexes outside the {}-entry \
                         address table",
                        addresses.len()
                    ),
                });
            }
        }
        Ok(DesiredTables {
            addresses,
            associations,
        })
    }
}

/// Whether a device was backed up, skipped, or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStatus {
    /// The device answered and its tables were written to a file.
    BackedUp,
    /// The device answered with a mask bussard cannot read tables for. Listed,
    /// never omitted.
    Skipped,
    /// The device answered, but a read failed part-way. Makes `backup` exit
    /// non-zero.
    Failed,
    /// Nothing answered at the device's address. Listed so the gap is visible,
    /// but not a failure of the run: a device that is switched off or removed
    /// cannot be backed up, and saying so is the correct outcome.
    Unreachable,
}

impl std::fmt::Display for BackupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupStatus::BackedUp => write!(f, "backed up"),
            BackupStatus::Skipped => write!(f, "skipped"),
            BackupStatus::Failed => write!(f, "failed"),
            BackupStatus::Unreachable => write!(f, "unreachable"),
        }
    }
}

/// Whether a device's parameter memory was captured, and why not when it was not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterStatus {
    /// Whether the parameter memory is in the device's backup file.
    pub captured: bool,
    /// The absolute base address the image starts at, when captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<u32>,
    /// The image length in octets, when captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    /// Why nothing was captured, when it was not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ParameterStatus {
    /// A captured image at `base` of `length` octets.
    pub fn captured(base: u32, length: usize) -> ParameterStatus {
        ParameterStatus {
            captured: true,
            base: Some(base),
            length: Some(length),
            reason: None,
        }
    }

    /// Nothing captured, for the stated reason.
    pub fn not_captured(reason: impl Into<String>) -> ParameterStatus {
        ParameterStatus {
            captured: false,
            base: None,
            length: None,
            reason: Some(reason.into()),
        }
    }
}

/// One device's row in a [`BackupManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// The device's individual address.
    pub address: String,
    /// What happened to it.
    pub status: BackupStatus,
    /// The mask version it reported, four hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
    /// The human-readable system type for that mask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_type: Option<String>,
    /// The resident application identity (`PID_PROGRAM_VERSION`), rendered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// The device's order number (`PID_ORDER_INFO`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_number: Option<String>,
    /// When the device was read, RFC3339 UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_time: Option<String>,
    /// The backup file, relative to the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Whether the parameter memory was captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ParameterStatus>,
    /// The skip or failure reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The per-run manifest written beside the device backups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Always `"bussard"`, so a stray file is identifiable.
    pub tool: String,
    /// The bussard version that took the backup.
    pub version: String,
    /// When the run started, RFC3339 UTC.
    pub created: String,
    /// The gateway the run went through.
    pub gateway: String,
    /// One row per device the run considered, in address order.
    pub devices: Vec<ManifestEntry>,
}

impl BackupManifest {
    /// Starts a manifest for a run through `gateway` at `created`.
    pub fn new(gateway: impl Into<String>, created: SystemTime) -> BackupManifest {
        BackupManifest {
            tool: "bussard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            created: rfc3339_utc(created),
            gateway: gateway.into(),
            devices: Vec::new(),
        }
    }

    /// How many devices ended in each status.
    pub fn totals(&self) -> BTreeMap<&'static str, usize> {
        let mut out: BTreeMap<&'static str, usize> = BTreeMap::new();
        for entry in &self.devices {
            let key = match entry.status {
                BackupStatus::BackedUp => "backed_up",
                BackupStatus::Skipped => "skipped",
                BackupStatus::Failed => "failed",
                BackupStatus::Unreachable => "unreachable",
            };
            *out.entry(key).or_default() += 1;
        }
        out
    }

    /// Whether any device failed — the non-zero-exit condition for `backup`.
    pub fn any_failed(&self) -> bool {
        self.devices
            .iter()
            .any(|d| d.status == BackupStatus::Failed)
    }
}

/// The conventional backup root inside a model directory:
/// `<dir>/captures/backups`.
pub fn backups_root(model_dir: &Path) -> PathBuf {
    model_dir.join("captures").join("backups")
}

/// The file name a device's backup takes inside a backup directory.
pub fn device_backup_file_name(address: &str, unix_timestamp: u64) -> String {
    format!("{address}-{unix_timestamp}.json")
}

/// Writes one device's backup into `dir`, creating the directory if needed, and
/// returns the file written.
pub fn write_device_backup(dir: &Path, backup: &DeviceBackup) -> Result<PathBuf, BackupError> {
    std::fs::create_dir_all(dir).map_err(|source| BackupError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let path = dir.join(device_backup_file_name(
        &backup.address,
        backup.unix_timestamp,
    ));
    let body = serde_json::to_string_pretty(backup).map_err(BackupError::Encode)?;
    std::fs::write(&path, body).map_err(|source| BackupError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

/// The parameter memory a parameter-only download is about to rewrite, saved
/// before the first write (issue #119).
///
/// Kept apart from [`DeviceBackup`] (which `bussard restore` rewrites tables
/// from) in its own directory, [`parameter_backups_dir`], so a table restore can
/// never pick it up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterBackup {
    /// The device's individual address.
    pub address: String,
    /// The mask version, four hex digits.
    pub mask: String,
    /// The application program the parameters belong to.
    pub application: String,
    /// When the memory was read, as seconds since the Unix epoch.
    pub unix_timestamp: u64,
    /// When the memory was read, as an RFC3339 UTC timestamp.
    pub read_time: String,
    /// Every parameter region, as read.
    pub regions: Vec<ParameterMemory>,
}

/// Where parameter backups live: `<model dir>/captures/backups/parameters`.
pub fn parameter_backups_dir(model_dir: &Path) -> PathBuf {
    backups_root(model_dir).join("parameters")
}

/// Writes a [`ParameterBackup`] into `dir` as `<address>-<unix time>.json`,
/// creating the directory if needed, and returns the file written.
pub fn write_parameter_backup(
    dir: &Path,
    backup: &ParameterBackup,
) -> Result<PathBuf, BackupError> {
    std::fs::create_dir_all(dir).map_err(|source| BackupError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let path = dir.join(device_backup_file_name(
        &backup.address,
        backup.unix_timestamp,
    ));
    let body = serde_json::to_string_pretty(backup).map_err(BackupError::Encode)?;
    std::fs::write(&path, body).map_err(|source| BackupError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

/// Reads one device's backup back from disk.
pub fn read_device_backup(path: &Path) -> Result<DeviceBackup, BackupError> {
    let body = std::fs::read_to_string(path).map_err(|source| BackupError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&body).map_err(|source| BackupError::Decode {
        path: path.to_path_buf(),
        source,
    })
}

/// Writes the run manifest into `dir`.
pub fn write_manifest(dir: &Path, manifest: &BackupManifest) -> Result<PathBuf, BackupError> {
    std::fs::create_dir_all(dir).map_err(|source| BackupError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let path = dir.join(MANIFEST_FILE);
    let body = serde_json::to_string_pretty(manifest).map_err(BackupError::Encode)?;
    std::fs::write(&path, body).map_err(|source| BackupError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

/// Reads a run manifest back from a backup directory.
pub fn read_manifest(dir: &Path) -> Result<BackupManifest, BackupError> {
    let path = dir.join(MANIFEST_FILE);
    let body = std::fs::read_to_string(&path).map_err(|source| BackupError::Io {
        path: path.clone(),
        source,
    })?;
    serde_json::from_str(&body).map_err(|source| BackupError::Decode { path, source })
}

/// Finds the newest backup for `address` in `dir`.
///
/// A backup directory holds one file per device, named
/// `<ia>-<unix timestamp>.json`; when a device was captured more than once the
/// highest timestamp wins, so `restore` always offers the most recent state.
pub fn find_device_backup(dir: &Path, address: IndividualAddress) -> Result<PathBuf, BackupError> {
    let prefix = format!("{address}-");
    let entries = std::fs::read_dir(dir).map_err(|source| BackupError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(ts) = stem.strip_prefix(&prefix) else {
            continue;
        };
        let ts: u64 = ts.parse().unwrap_or(0);
        if best.as_ref().is_none_or(|(seen, _)| ts >= *seen) {
            best = Some((ts, path));
        }
    }
    best.map(|(_, path)| path).ok_or(BackupError::NotFound {
        dir: dir.to_path_buf(),
        address,
    })
}

/// Whether `<model dir>/captures/backups` holds at least one installation-wide
/// backup — a subdirectory carrying a [`MANIFEST_FILE`].
///
/// `apply` uses this to nudge an owner who has never run `bussard backup`: a
/// per-device pre-write snapshot is not the same safety net as a snapshot of the
/// whole installation taken before anything was touched.
pub fn has_installation_backup(model_dir: &Path) -> bool {
    let root = backups_root(model_dir);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.path().join(MANIFEST_FILE).is_file())
}

/// Uppercase hex with no separators — the encoding every byte string in a backup
/// uses.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// The inverse of [`encode_hex`]; `None` for an odd length or a non-hex digit.
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Seconds since the Unix epoch, clamped at the epoch for a clock before it.
pub fn unix_seconds(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Formats a `SystemTime` as an RFC3339 UTC timestamp, e.g.
/// `2026-09-22T10:15:00Z`.
///
/// Kept here rather than pulled from a date-time crate: this is the whole of what
/// the format needs, and `bussard-download` must not grow a dependency for it.
/// The civil-from-days conversion is Howard Hinnant's, the same one
/// `bussard-monitor` uses for its capture timestamps.
pub fn rfc3339_utc(ts: SystemTime) -> String {
    let secs = unix_seconds(ts) as i64;
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// A compact, sortable UTC stamp for a backup directory name, e.g.
/// `20260922T101500Z`.
pub fn timestamp_dir_name(ts: SystemTime) -> String {
    let secs = unix_seconds(ts) as i64;
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Days since the Unix epoch to `(year, month, day)` (Howard Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_mgmt::tables::{ResolvedLink, TableSource};

    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap_or_else(|_| GroupAddress::from_raw(0))
    }

    fn live() -> DeviceTables {
        DeviceTables {
            mask: 0x07B0,
            addresses: vec![ga("1/2/0"), ga("1/2/1")],
            associations: vec![(1, 20), (2, 21)],
            resolved: vec![
                ResolvedLink {
                    object: 20,
                    ga: ga("1/2/0"),
                },
                ResolvedLink {
                    object: 21,
                    ga: ga("1/2/1"),
                },
            ],
            sources: vec![("addresses", TableSource::Property)],
            notes: vec!["read via properties".to_string()],
        }
    }

    #[test]
    fn test_capture_round_trips_through_json() -> Result<(), Box<dyn std::error::Error>> {
        let addr: IndividualAddress = "1.1.4".parse()?;
        let at = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let backup = DeviceBackup::capture(addr, &live(), None, None, at);
        let text = serde_json::to_string_pretty(&backup)?;
        let back: DeviceBackup = serde_json::from_str(&text)?;
        assert_eq!(back, backup);
        // The legacy key order and the always-present `system7: null` are part of
        // the format older `apply` backups were written in.
        assert!(text.contains("\"system7\": null"), "{text}");
        Ok(())
    }

    #[test]
    fn test_desired_tables_reproduces_the_backed_up_tables()
    -> Result<(), Box<dyn std::error::Error>> {
        let addr: IndividualAddress = "1.1.4".parse()?;
        let backup = DeviceBackup::capture(addr, &live(), None, None, SystemTime::now());
        let desired = backup.desired_tables(Path::new("mem"))?;
        assert_eq!(desired.addresses, live().addresses);
        assert_eq!(desired.associations, live().associations);
        // A restore of a fresh backup onto the unchanged device is a no-op plan.
        let report = crate::plan::plan(&live(), &desired);
        assert!(report.is_noop(), "{report:?}");
        Ok(())
    }

    #[test]
    fn test_desired_tables_refuses_an_out_of_range_tsap() {
        let backup = DeviceBackup {
            address: "1.1.4".to_string(),
            mask: "07B0".to_string(),
            unix_timestamp: 0,
            read_time: None,
            system7: None,
            addresses: vec!["1/2/0".to_string()],
            associations: vec![AssociationEntry { tsap: 9, asap: 20 }],
            resolved: Vec::new(),
            notes: Vec::new(),
            parameters: None,
        };
        match backup.desired_tables(Path::new("mem")) {
            Err(err) => assert!(err.to_string().contains("indexes outside"), "{err}"),
            Ok(other) => panic!("a tsap past the address table must be refused, got {other:?}"),
        }
    }

    #[test]
    fn test_hex_round_trip() {
        let bytes = vec![0x00, 0x0F, 0xA5, 0xFF];
        assert_eq!(encode_hex(&bytes), "000FA5FF");
        assert_eq!(decode_hex("000FA5FF"), Some(bytes));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("0G"), None);
    }

    #[test]
    fn test_rfc3339_and_dir_name_are_utc() {
        let ts = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        assert_eq!(rfc3339_utc(ts), "2026-09-21T14:13:20Z");
        assert_eq!(timestamp_dir_name(ts), "20260921T141320Z");
    }
}
