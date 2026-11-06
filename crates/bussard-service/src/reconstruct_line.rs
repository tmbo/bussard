//! The line form of reconstruct (issue #748): `bussard reconstruct --line 1.1
//! --out <fresh-dir>` and `knx_reconstruct_device` with `line`.
//!
//! Sweeps a whole line like `bussard scan` (short discovery timeouts, one
//! connection at a time), reads every System B device's tables, and
//! synthesizes a fresh, ETS-less model:
//!
//! ```text
//! groups.toml       every GA seen across all tables, placeholder names, no
//!                   DPT (validation warns W011; that is honest).
//! devices/<ia>.toml object -> GA sets. Direction is unrecoverable from the
//!                   tables, so every GA is recorded as `listen`.
//! bussard.lock      mask + best-effort product facts; a minimal com-object
//!                   stub per linked object so the model validates.
//! bussard.toml      the connection the surface passes in.
//! ```
//!
//! Every synthesized hand-editable file carries [`RECONSTRUCT_BANNER`],
//! injected after [`Model::save`] by [`inject_reconstruct_banners`]. The sweep
//! is read-only on the bus; the only files written are in the fresh output
//! directory. The sweep never prints: progress goes to a [`WalkEvent`] callback.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bussard_mgmt::tables::{DeviceTables, read_tables};
use bussard_mgmt::{MaskProfile, manufacturers, system_type};
use bussard_model::schema::{
    BussardConfig, ComObject, Device, Group, Groups, Link, Links, Product,
};
use bussard_model::text::hex;
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress, LoadedDevice, Model};

use crate::identity::{Identity, read_identity};
use crate::line::{WalkEvent, walk};
use crate::scan::LineRange;
use crate::{BusService, L4Options, ServiceError};

pub use crate::scan::PER_ADDRESS_ESTIMATE;

/// The reconstruction banner injected atop every synthesized file. It states
/// the provenance (table read-back, not ETS) and the three things a human or
/// the monitor must still supply: names, DPTs and send/listen directions.
pub const RECONSTRUCT_BANNER: &str = "\
# ⚠ RECONSTRUCTED from on-device table read-back (`bussard reconstruct --line`).
#
# This model was synthesized WITHOUT an ETS project, by reading each System B
# device's group-address and association tables over the bus. It is a scaffold,
# not ground truth:
#   • GA and com-object names are placeholders — annotate them (watch the bus
#     with `bussard monitor`, then name what you observe).
#   • DPTs are unknown (groups.toml carries no `dpt`; validation warns W011).
#   • send/listen DIRECTION is not recoverable from these tables (the transmit
#     flag lives in the group object table), so every GA is recorded as `listen`.
#   • com-object flags are placeholder `CW` stubs so the model validates.
# Verify against reality before treating this as the source of truth.
#
";

/// A file the line reconstruction could not read or write.
#[derive(Debug, thiserror::Error)]
pub enum ReconstructLineError {
    /// A file or directory could not be read.
    #[error("reading {}", path.display())]
    Read {
        /// The path.
        path: PathBuf,
        /// The cause.
        #[source]
        source: std::io::Error,
    },
    /// A file could not be written.
    #[error("writing {}", path.display())]
    Write {
        /// The path.
        path: PathBuf,
        /// The cause.
        #[source]
        source: std::io::Error,
    },
}

/// What the output directory of a reconstruction holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutDir {
    /// Absent or an empty directory: usable.
    Fresh,
    /// A file, not a directory.
    File,
    /// A directory with entries: reconstruction never merges into a model.
    NotEmpty,
}

/// Classifies `out` as a reconstruction target.
///
/// # Errors
///
/// The directory exists but cannot be listed.
pub fn check_out_dir(out: &Path) -> Result<OutDir, ReconstructLineError> {
    if !out.exists() {
        return Ok(OutDir::Fresh);
    }
    if out.is_file() {
        return Ok(OutDir::File);
    }
    let mut entries = std::fs::read_dir(out)
        .map_err(|source| ReconstructLineError::Read {
            path: out.to_path_buf(),
            source,
        })?
        .filter_map(Result::ok);
    Ok(if entries.next().is_some() {
        OutDir::NotEmpty
    } else {
        OutDir::Fresh
    })
}

/// A device that responded to the line sweep. System B devices carry read
/// tables; everything else is recorded as a stub (mask only, tables skipped).
#[derive(Debug, Clone)]
pub struct LineDevice {
    /// The responder's individual address.
    pub address: IndividualAddress,
    /// The mask version it reported.
    pub mask: u16,
    /// `PID_MANUFACTURER_ID`, when it answered.
    pub manufacturer_id: Option<u16>,
    /// `PID_SERIAL_NUMBER`, when it answered.
    pub serial: Option<Vec<u8>>,
    /// `PID_ORDER_INFO` as ASCII, when it answered.
    pub order: Option<String>,
    /// The read tables, present only for System B devices.
    pub tables: Option<DeviceTables>,
    /// Why the tables were skipped (non-System-B, or a read error), if skipped.
    pub skipped: Option<String>,
}

/// Sweeps `range`, returning every responder with its tables (System B) or
/// a stub (everything else). One session at a time, each on its own lease;
/// read-only on the bus. `on_event` hears each probe start and end
/// ([`walk`]).
pub async fn sweep_line(
    service: &BusService,
    range: LineRange,
    source: IndividualAddress,
    on_event: &mut (dyn FnMut(WalkEvent<'_, Option<LineDevice>>) + Send),
) -> Vec<LineDevice> {
    walk(
        &range.addresses(),
        Option::is_some,
        |addr| probe_line(service, addr, source),
        on_event,
    )
    .await
    .into_iter()
    .filter_map(|step| step.outcome)
    .collect()
}

/// Probes one address: descriptor first; System B → read tables; anything else
/// → best-effort product identity, recorded as a stub. Returns `None` for an
/// absent or refusing device.
async fn probe_line(
    service: &BusService,
    addr: IndividualAddress,
    source: IndividualAddress,
) -> Option<LineDevice> {
    let options = L4Options::discovery(source);
    // Best-effort product identity for every responder (System B or not).
    let identity = service
        .with_l4(addr, &options, async |l4| {
            Ok::<_, ServiceError>(read_identity(l4, true).await.ok())
        })
        .await
        .ok()
        .flatten()?;
    let Identity {
        mask,
        manufacturer_id,
        serial,
        order,
        ..
    } = identity;

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
) -> Result<DeviceTables, String> {
    let options = L4Options::read_only(source);
    let result = service
        .with_l4(addr, &options, async |l4| {
            Ok::<_, ServiceError>(read_tables(l4).await)
        })
        .await
        .map_err(|e| e.to_string())?;
    result.map_err(|e| e.to_string())
}

/// Placeholder flags for a reconstructed com-object: `CW` keeps the model
/// ERROR-free (C is required for a linked object; W avoids the listen-only
/// W008 warning) while being honestly minimal — the real flags are unknown.
fn placeholder_flags() -> Flags {
    Flags::COMMUNICATION | Flags::WRITE
}

/// Synthesizes a fresh [`Model`] from the swept devices, with `config` as its
/// `bussard.toml`.
///
/// - `groups.toml`: every GA seen across all read tables, named
///   `GA <addr> (reconstructed)`, no DPT.
/// - `devices/<ia>.toml`: object → GA set per device, every GA as `listen`
///   (direction is unrecoverable).
/// - `bussard.lock`: mask + best-effort product facts; a placeholder com-object
///   stub per linked object so validation passes.
pub fn synthesize_model(found: &[LineDevice], config: BussardConfig) -> Model {
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
            knxnet: None,
            lock: Default::default(),
        };
        devices.insert(
            dev.address,
            LoadedDevice {
                device,
                file_stem: dev.address.to_string(),
            },
        );
    }

    Model {
        config,
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

/// Prepends [`RECONSTRUCT_BANNER`] to every synthesized hand-editable file
/// (`bussard.toml`, `groups.toml`, `devices/*.toml`) after `Model::save`. A
/// TOML comment block at the top is inert, and a later save keeps it. The
/// generated `bussard.lock` keeps its own header. One-shot: the banner is added
/// exactly once here.
///
/// # Errors
///
/// A synthesized file that cannot be read or rewritten.
pub fn inject_reconstruct_banners(out: &Path) -> Result<(), ReconstructLineError> {
    let mut files = vec![out.join("bussard.toml"), out.join("groups.toml")];
    let devices_dir = out.join("devices");
    if let Ok(rd) = std::fs::read_dir(&devices_dir) {
        for entry in rd.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                files.push(path);
            }
        }
    }
    for path in files {
        if !path.exists() {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|source| ReconstructLineError::Read {
            path: path.clone(),
            source,
        })?;
        std::fs::write(&path, format!("{RECONSTRUCT_BANNER}{body}"))
            .map_err(|source| ReconstructLineError::Write { path, source })?;
    }
    Ok(())
}

/// The line-mode summary, shaped for both text and JSON.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LineSummary {
    /// The line as the caller named it.
    pub line: String,
    /// The output directory.
    pub out: String,
    /// Devices whose tables were read (System B).
    pub devices_read: usize,
    /// Devices recorded as a stub (mask noted, tables skipped).
    pub devices_skipped: usize,
    /// Total responders on the line.
    pub devices_found: usize,
    /// Distinct group addresses across all read tables.
    pub group_addresses: usize,
    /// Total (object → GA) links synthesized.
    pub links: usize,
    /// Per-device breakdown.
    pub device_details: Vec<LineDeviceDetail>,
}

/// One device row in the line-mode summary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LineDeviceDetail {
    /// The device's individual address.
    pub address: String,
    /// Its mask, four hex digits.
    pub mask: String,
    /// The mask's system type in words.
    pub system_type: String,
    /// `"read"` for System B devices, `"stub"` otherwise.
    pub status: &'static str,
    /// The skip reason, when the device was recorded as a stub.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Distinct GAs read from this device (0 for stubs).
    pub group_addresses: usize,
    /// Links synthesized for this device (0 for stubs).
    pub links: usize,
}

/// Builds the line-mode summary from the swept devices and synthesized model.
pub fn build_summary(line: &str, out: &Path, found: &[LineDevice], model: &Model) -> LineSummary {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_formats_lowercase() {
        assert_eq!(hex(&[0xDE, 0xAD]), "dead");
    }

    #[test]
    fn test_check_out_dir_classifies() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = std::env::temp_dir().join(format!("bussard-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(check_out_dir(&tmp)?, OutDir::Fresh);
        std::fs::create_dir_all(&tmp)?;
        assert_eq!(check_out_dir(&tmp)?, OutDir::Fresh);
        std::fs::write(tmp.join("x"), "y")?;
        assert_eq!(check_out_dir(&tmp)?, OutDir::NotEmpty);
        assert_eq!(check_out_dir(&tmp.join("x"))?, OutDir::File);
        std::fs::remove_dir_all(&tmp)?;
        Ok(())
    }
}
