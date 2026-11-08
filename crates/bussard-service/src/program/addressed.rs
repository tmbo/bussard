//! The outcome of giving a device its address (issue #904): `bussard
//! assign --json`, and the results of `knx_add_device`, `knx_replace_device`
//! and each device of `knx_commission_line`, in one shape.
//!
//! [`AddressOutcome`] is the only definition of the keys; the chat
//! envelope (`summary`, `next_step`) comes from its [`Report`] methods.

use std::path::Path;

use bussard_model::Model;
use serde::Serialize;

use super::adopt::Adopted;
use super::assign::Assigned;
use super::outcome::{Verdict, WriteOutcome};
use crate::assign::{Verified, hex};
use crate::report::Report;

/// What the read-back at the new address reported.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeviceReadback {
    /// The mask, hex.
    pub mask: Option<String>,
    /// The KNX manufacturer id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer_id: Option<u16>,
    /// The serial number, hex.
    pub serial: Option<String>,
    /// The order number the device reports.
    pub order_number: Option<String>,
    /// How it was read with respect to KNX Data Secure: `plain`,
    /// `activated`, `activated_no_key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<String>,
    /// Whether the device confirmed leaving programming mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programming_mode_cleared: Option<bool>,
}

impl DeviceReadback {
    /// What `v` read.
    pub fn of(v: &Verified) -> DeviceReadback {
        DeviceReadback {
            mask: v.mask.map(|m| format!("{m:04X}")),
            manufacturer_id: v.manufacturer_id,
            serial: v.serial.as_deref().map(hex),
            order_number: v.order.clone(),
            secure: Some(v.secure.as_str().to_string()),
            programming_mode_cleared: Some(v.programming_mode_cleared),
        }
    }

    /// Only the mask and the serial (what a mismatching device reported).
    pub fn identity(v: &Verified) -> DeviceReadback {
        DeviceReadback {
            mask: v.mask.map(|m| format!("{m:04X}")),
            serial: v.serial.as_deref().map(hex),
            ..DeviceReadback::default()
        }
    }
}

/// The product data an added device got.
#[derive(Debug, Clone, Serialize)]
pub struct ProductSummary {
    /// The product's name.
    pub name: String,
    /// The application program.
    pub application: String,
    /// How many com-objects it has.
    pub com_objects: usize,
}

/// One com-object of an added device, in the order a human wires them.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectRow {
    /// The object number.
    pub object: u16,
    /// Its text from the product data.
    pub text: Option<String>,
    /// Its DPT.
    pub dpt: Option<String>,
    /// Its flags.
    pub flags: String,
    /// The device-file table it is wired in.
    pub table: String,
    /// The key it is wired under.
    pub key: String,
}

/// What adopting a KNX Data Secure-activated device recorded.
#[derive(Debug, Clone, Serialize)]
pub struct SecureRecorded {
    /// Links recorded.
    pub links: usize,
    /// Parameters recorded.
    pub parameters: usize,
    /// The secured group objects.
    pub secure_objects: Vec<u16>,
    /// The secured group addresses.
    pub secure_groups: Vec<String>,
    /// Why a part is missing.
    pub notes: Vec<String>,
}

/// The record of a replacement in the project.
#[derive(Debug, Clone, Serialize)]
pub struct Recorded {
    /// When, RFC 3339.
    pub replaced: String,
    /// The device file that records it.
    pub device_file: String,
    /// Whether the serial in `bussard.lock` changed.
    pub serial_recorded: bool,
}

/// Which flow addressed the device; it picks the words of the summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AddressFlow {
    /// `bussard assign`.
    #[default]
    Assign,
    /// `knx_add_device` (`bussard adopt`).
    Add,
    /// `knx_replace_device` (`bussard replace`).
    Replace,
}

/// A device given its address (see the module docs). Every field but the
/// address and the verdict is there only when the flow has it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AddressOutcome {
    /// The verdict: `ok`, `verified`, and why not.
    #[serde(flatten)]
    pub verdict: Verdict,
    /// `done` once the job ended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// The device's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its address now (empty before the device was identified).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub address: String,
    /// Where it answered the programming-mode broadcast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The resolved gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// The address was written (`false`: the device kept it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned: Option<bool>,
    /// Whether anything was written (a refusal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
    /// The read-back at the new address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readback: Option<DeviceReadback>,
    /// The device file written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_file: Option<String>,
    /// The product data attached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<ProductSummary>,
    /// The com-objects to wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<Vec<ObjectRow>>,
    /// What a Data Secure adoption recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<SecureRecorded>,
    /// A replacement: whether its application was loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flashed: Option<bool>,
    /// A replacement: the write of the application and links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write: Option<WriteOutcome>,
    /// A replacement: its record in the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded: Option<Recorded>,
    /// What the human should know.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// The flow, for the summary's words.
    #[serde(skip)]
    pub flow: AddressFlow,
}

impl AddressOutcome {
    /// The address write `assigned` and its read-back.
    pub fn of(assigned: &Assigned) -> AddressOutcome {
        AddressOutcome {
            verdict: Verdict {
                ok: assigned.matches_identified,
                verified: assigned.matches_identified,
                ..Verdict::default()
            },
            address: assigned.target.to_string(),
            from: Some(assigned.current.to_string()),
            assigned: Some(assigned.written),
            readback: Some(DeviceReadback::of(&assigned.verified)),
            ..AddressOutcome::default()
        }
    }

    /// An added device (`knx_add_device`): the address, the product data,
    /// the objects to wire and its device file, relative to `dir`.
    pub fn added(adopted: &Adopted, dir: &Path, notes: Vec<String>) -> AddressOutcome {
        let selected = adopted.selected.as_ref();
        let path = &adopted.path;
        AddressOutcome {
            step: Some("done".to_string()),
            name: Some(adopted.device.name.clone()),
            device_file: Some(path.strip_prefix(dir).unwrap_or(path).display().to_string()),
            product: selected.map(|s| ProductSummary {
                name: s.display_name(),
                application: s.application_ref.clone(),
                com_objects: s.com_objects.len(),
            }),
            objects: Some(
                crate::adopt::flow::useful_objects(&adopted.device, selected)
                    .into_iter()
                    .take(8)
                    .map(|o| ObjectRow {
                        object: o.number,
                        text: o.text,
                        dpt: o.dpt.map(|d| d.to_string()),
                        flags: o.flags.to_string(),
                        table: o.table,
                        key: o.key,
                    })
                    .collect(),
            ),
            secure: adopted.secure.as_ref().map(|s| SecureRecorded {
                links: s.links,
                parameters: s.parameters,
                secure_objects: s.adoption.secure_objects.iter().copied().collect(),
                secure_groups: s
                    .adoption
                    .secure_groups
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                notes: s.notes.clone(),
            }),
            notes,
            flow: AddressFlow::Add,
            ..AddressOutcome::of(&adopted.assigned)
        }
    }

    /// A refusal before anything was written.
    pub fn refused(address: impl ToString, reason: impl Into<String>) -> AddressOutcome {
        AddressOutcome {
            verdict: Verdict::refused(reason),
            address: address.to_string(),
            written: Some(false),
            ..AddressOutcome::default()
        }
    }

    /// The summary of an added device.
    fn added_summary(&self) -> String {
        let name = self.name.as_deref().unwrap_or("The device");
        let target = &self.address;
        let from = self.from.as_deref().unwrap_or("?");
        let what = if self.assigned == Some(true) {
            format!("now answers at {target} (was {from})")
        } else {
            format!("answers at {target}")
        };
        let check = if self.verdict.verified {
            "the read-back there matches the identified serial and mask"
        } else {
            "but the read-back there does NOT match the identified serial or mask"
        };
        format!(
            "{name} ({target}) {what}; {check}; its device file is {}.",
            self.device_file.as_deref().unwrap_or("not written")
        )
    }

    /// The summary of a replacement.
    fn replaced_summary(&self) -> String {
        let name = self.name.as_deref().unwrap_or("The device");
        let target = &self.address;
        let how = match (&self.write, self.flashed) {
            (None, _) => {
                "it already held the model's application, parameters and links".to_string()
            }
            (Some(_), Some(true)) => {
                "the application was loaded with the model's parameters and links".to_string()
            }
            (Some(_), _) => "the parameters and links in your project were written".to_string(),
        };
        format!(
            "{name} ({target}) is replaced: the device that was at {} now answers at {target}, \
             {how}, and the read-back matches your project{}.",
            self.from.as_deref().unwrap_or("?"),
            if self.recorded.is_some() {
                "; the replacement is recorded in the device file and bussard.lock"
            } else {
                ", but the record in the model failed (see notes)"
            }
        )
    }
}

impl Report for AddressOutcome {
    /// `bussard assign --json` prints this shape.
    const SCHEMA: u32 = 2;

    fn summary(&self, _model: &Model) -> Option<String> {
        if !self.verdict.ok && self.step.is_none() {
            return None;
        }
        match self.flow {
            AddressFlow::Add if self.step.is_some() => Some(self.added_summary()),
            AddressFlow::Replace if self.verdict.ok => Some(self.replaced_summary()),
            _ => None,
        }
    }

    fn next_step(&self) -> Option<String> {
        let target = &self.address;
        match self.flow {
            AddressFlow::Add if self.step.is_some() => Some(match (&self.secure, &self.product) {
                (Some(_), _) => format!(
                    "Tell the human the summary. Its links and parameters are in the model \
                     now; knx_plan_device for {target} should report nothing to do."
                ),
                (None, Some(_)) => format!(
                    "Tell the human the summary, then name the device and its room \
                     (knx_rename_device or the device file) and wire its group objects: \
                     `objects` lists them, transmit-capable first. knx_plan_device and \
                     knx_apply_device for {target} write the links; a factory-fresh device \
                     needs its application loaded first (the plan says so)."
                ),
                (None, None) => format!(
                    "Tell the human the summary. It has no product data yet: knx_import_file \
                     with its .knxprod attaches it; then wire its group objects and plan \
                     {target}."
                ),
            }),
            AddressFlow::Replace if self.verdict.ok => Some(format!(
                "Tell the human the summary. knx_plan_device for {target} should report \
                 nothing to do; a fresh knx_backup_device run keeps the new device's state."
            )),
            _ => None,
        }
    }
}
