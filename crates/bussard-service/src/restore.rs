//! Replaying a parameter backup onto a device (issue #290): the plan behind
//! `bussard restore --parameters` and the MCP tool `knx_restore_parameters`.
//!
//! Every `apply`, `flash --parameters-only` and `knx_apply_device` writes the
//! device's parameter memory to `<dir>/captures/backups/parameters/` before
//! its first write. A restore puts that memory back with the parameter-only
//! download the apply used ([`FlashPlan::parameters_only`], then
//! [`FlashPlan::restoring`]), so it writes nothing an apply could not:
//!
//! - **Identity.** The backup must be of this device, its application and its
//!   mask: a backup of another application or mask is refused before anything
//!   is planned (the octets would mean something else).
//! - **The placed-octet rule.** Only the octets a parameter is placed in
//!   under the model's configuration are compared and written, the same set
//!   an apply writes, so a restore puts back everything an apply changed and
//!   nothing ETS's download would leave alone.
//! - **Device-managed octets are skipped.** An `Access="None"` value the
//!   application owns at runtime (a download flag) keeps the device's value.
//! - **Verify.** The write is [`crate::download::write_parameters`], read back
//!   like an apply's.
//!
//! The surfaces keep the usual gates: the real-gateway opt-in, the
//! confirmation (CLI) or the plan digest and an explicit yes (MCP), and the
//! parameter-only identity gate, which refuses a device that does not run the
//! application (a factory-fresh or unloaded device needs `bussard flash`).

use std::collections::BTreeMap;

use bussard_download::backup::ParameterBackup;
use bussard_download::{FlashPlan, PartialPlanError, attribute_octets, device_managed_octets};
use bussard_model::{IndividualAddress, Model};
use bussard_prod::ApplicationProgram;

use crate::params::{OctetAttribution, ParamDetail, TargetLabel, model_images, octet_ranges};

/// Why a parameter backup cannot be restored onto a device.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestoreError {
    /// The backup was taken of another device.
    #[error("the backup is of {backup}, not {device}; restore a backup of {device}")]
    Address {
        /// The backup's address.
        backup: String,
        /// The device being restored.
        device: String,
    },
    /// The backup's application is not the one the device runs.
    #[error(
        "the backup holds the parameters of application {backup}, but {device_address} runs \
         {device}; its octets would mean other parameters there. Restore a backup taken with \
         {device}, or flash the device with the application first"
    )]
    Application {
        /// The backup's application id.
        backup: String,
        /// The application the device runs (the one bussard.lock pins).
        device: String,
        /// The device's address.
        device_address: String,
    },
    /// The backup was taken on another mask.
    #[error(
        "the backup was read from a device with mask {backup}, but {device_address} reports \
         mask {device}; refusing to replay it"
    )]
    Mask {
        /// The backup's mask, four hex digits.
        backup: String,
        /// The device's mask, four hex digits.
        device: String,
        /// The device's address.
        device_address: String,
    },
    /// A backup region is not a parameter segment of the application on the
    /// device.
    #[error(
        "the backup's region at {base:#X} is not a parameter segment the application has on \
         the device (the device's segments sit at {device}); refusing to replay it"
    )]
    Region {
        /// The region's base address.
        base: u32,
        /// The device's segment addresses, in words.
        device: String,
    },
    /// A backup region's length is not the device segment's.
    #[error(
        "the backup's region at {base:#X} holds {backup} octets, the device's parameter segment \
         there {device}; refusing to replay it"
    )]
    Length {
        /// The region's base address.
        base: u32,
        /// The backup's length.
        backup: usize,
        /// The device segment's length.
        device: usize,
    },
    /// A backup region's octets are not valid hex.
    #[error("the backup's region at {base:#X} does not decode as hex octets")]
    Undecodable {
        /// The region's base address.
        base: u32,
    },
    /// The parameter-only download could not be cut.
    #[error("{0}")]
    Partial(#[from] PartialPlanError),
}

/// The plan of replaying a parameter backup.
pub struct RestorePlan {
    /// The download that writes the backup's octets, `None` when the device
    /// already holds them.
    pub partial: Option<FlashPlan>,
    /// How many octets the download writes.
    pub octets: usize,
    /// Every run the restore writes, and every run where the backup differs
    /// from the device but the restore leaves the device's value
    /// (`written: false`: no parameter placed there under the model's
    /// configuration, or a device-managed value), with the parameters behind
    /// it. The `model` side of each parameter is the backup's value.
    pub octet_ranges: Vec<OctetAttribution>,
    /// The plan's notes, ready to print.
    pub notes: Vec<String>,
}

impl RestorePlan {
    /// The plan in words: what is written, what is left, the notes.
    pub fn render_text(&self, target: IndividualAddress) -> String {
        let mut out = String::new();
        let written: Vec<&OctetAttribution> =
            self.octet_ranges.iter().filter(|r| r.written).collect();
        let left: Vec<&OctetAttribution> =
            self.octet_ranges.iter().filter(|r| !r.written).collect();
        if self.octets == 0 {
            out.push_str(&format!(
                "{target} already holds the backup's parameter octets; nothing to write\n"
            ));
        } else {
            out.push_str(&format!(
                "writes {} parameter octet(s) to {target}:\n",
                self.octets
            ));
            for r in &written {
                out.push_str(&format!("  ~ {}\n", r.sentence));
            }
        }
        if !left.is_empty() {
            out.push_str("leaves as the device holds them:\n");
            for r in &left {
                out.push_str(&format!("  = {}\n", r.sentence));
                if let Some(why) = &r.explanation {
                    out.push_str(&format!("    {why}\n"));
                }
            }
        }
        for note in &self.notes {
            out.push_str(&format!("note: {note}\n"));
        }
        out
    }

    /// The one question to ask before the write.
    pub fn question(&self, target: IndividualAddress, gateway: &str) -> String {
        format!(
            "restore {} parameter octet(s) from the backup to {target} via {gateway}?",
            self.octets
        )
    }
}

/// Checks that `backup` is of `target`, its application and its mask, as
/// `detail` (the device's parameter read-back) found them.
///
/// # Errors
///
/// [`RestoreError::Address`], [`RestoreError::Application`] or
/// [`RestoreError::Mask`].
pub fn check_identity(
    target: IndividualAddress,
    detail: &ParamDetail,
    backup: &ParameterBackup,
) -> Result<(), RestoreError> {
    if backup.address.trim() != target.to_string() {
        return Err(RestoreError::Address {
            backup: backup.address.clone(),
            device: target.to_string(),
        });
    }
    let app = &detail.plan.identity.id;
    if !backup.application.trim().eq_ignore_ascii_case(app) {
        return Err(RestoreError::Application {
            backup: backup.application.clone(),
            device: app.clone(),
            device_address: target.to_string(),
        });
    }
    let mask = format!("{:04X}", detail.plan.device_mask);
    if !backup.mask.trim().eq_ignore_ascii_case(&mask) {
        return Err(RestoreError::Mask {
            backup: backup.mask.clone(),
            device: mask,
            device_address: target.to_string(),
        });
    }
    Ok(())
}

/// The backup's memory per code segment, matched to the device's parameter
/// regions by base address.
fn backup_memory(
    detail: &ParamDetail,
    backup: &ParameterBackup,
) -> Result<BTreeMap<String, Vec<u8>>, RestoreError> {
    let mut out = BTreeMap::new();
    for region in &backup.regions {
        let Some(device) = detail.regions.values().find(|r| r.address == region.base) else {
            let device = detail
                .regions
                .values()
                .map(|r| format!("{:#X}", r.address))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(RestoreError::Region {
                base: region.base,
                device,
            });
        };
        let bytes = region
            .octets()
            .ok_or(RestoreError::Undecodable { base: region.base })?;
        if bytes.len() != device.bytes.len() {
            return Err(RestoreError::Length {
                base: region.base,
                backup: bytes.len(),
                device: device.bytes.len(),
            });
        }
        out.insert(device.segment_id.clone(), bytes);
    }
    Ok(out)
}

/// Plans replaying `backup` onto `target`, whose parameter memory `detail`
/// read: the identity check, then the parameter-only download rewritten to
/// the backup's octets on the placed, not device-managed octets (module
/// docs).
///
/// # Errors
///
/// A [`RestoreError`] naming why the backup does not fit the device.
pub fn build_restore_plan(
    app: &ApplicationProgram,
    model: Option<&Model>,
    target: IndividualAddress,
    detail: &ParamDetail,
    backup: &ParameterBackup,
) -> Result<RestorePlan, RestoreError> {
    check_identity(target, detail, backup)?;
    let wanted = backup_memory(detail, backup)?;
    let (overrides, bases) = bussard_download::model_parameters(model, target);
    let managed = device_managed_octets(app, &overrides, &bases);
    let partial = detail
        .plan
        .parameters_only(&detail.regions)?
        .restoring(&wanted, &managed);
    let current = bussard_download::regions_memory(&detail.regions);
    let attribute = |changed: &BTreeMap<String, Vec<(usize, u8)>>| {
        attribute_octets(
            app,
            &overrides,
            &bases,
            &current,
            &model_images(&partial, changed),
            changed,
        )
    };
    let written = attribute(&partial.changed_bits());
    let left = attribute(&partial.unwritten_bits());
    let device = model
        .and_then(|m| m.devices.get(&target))
        .map(|d| &d.device);
    let octet_ranges = octet_ranges(device, &written, &left, TargetLabel::Backup);
    let octets = partial.changed_octets();
    let mut notes = Vec::new();
    let skipped: usize = octet_ranges
        .iter()
        .filter(|r| !r.written)
        .map(|r| r.length)
        .sum();
    if skipped > 0 {
        notes.push(format!(
            "{skipped} octet(s) of the backup differ from the device where the restore leaves \
             the device's value: no parameter is placed there under the model's configuration \
             (ETS does not write such an octet in a download), or the application owns the \
             value at runtime"
        ));
    }
    Ok(RestorePlan {
        partial: (octets > 0).then_some(partial),
        octets,
        octet_ranges,
        notes,
    })
}
