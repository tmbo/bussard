//! Group-address reservations and the Data Secure switch of a group in one
//! shape each (issue #904): `bussard groups reserve --json` and
//! `knx_reserve_groups`; `bussard groups secure --json`.

use bussard_model::change::ChangeSet;
use bussard_model::scaffold::ScaffoldReport;
use bussard_model::{Change, IndividualAddress};
use serde::Serialize;

use crate::report::Report;

/// One group address a reservation added.
#[derive(Debug, Clone, Serialize)]
pub struct ReservedGroup {
    /// The address.
    pub address: String,
    /// Its generated name.
    pub name: String,
    /// Its DPT.
    pub dpt: String,
}

/// The project's validation counts.
#[derive(Debug, Clone, Serialize)]
pub struct Counts {
    /// Errors.
    pub errors: usize,
    /// Warnings.
    pub warnings: usize,
}

/// A reservation of group addresses for a room or a plan.
#[derive(Debug, Clone, Serialize)]
pub struct ReserveReport {
    /// The room, for a CLI reservation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// The numbering scheme.
    pub scheme: String,
    /// `groups.toml`.
    pub file: String,
    /// How many addresses were added.
    pub added_count: usize,
    /// The addresses added.
    pub added: Vec<ReservedGroup>,
    /// The scheme was written to `bussard.toml`.
    pub lint_config_written: bool,
    /// The history snapshot before the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// The project's validation after it.
    pub validation: Counts,
}

impl ReserveReport {
    /// The reservation `report` under `scheme` into `file`.
    pub fn new(
        scheme: &str,
        file: &std::path::Path,
        report: &ScaffoldReport,
        lint_config_written: bool,
        (errors, warnings): (usize, usize),
    ) -> ReserveReport {
        let added: Vec<ReservedGroup> = report
            .added
            .iter()
            .map(|a| ReservedGroup {
                address: a.address.to_string(),
                name: a.name.clone(),
                dpt: a.dpt.to_string(),
            })
            .collect();
        ReserveReport {
            room: None,
            scheme: scheme.to_string(),
            file: file.display().to_string(),
            added_count: added.len(),
            added,
            lint_config_written,
            snapshot: None,
            validation: Counts { errors, warnings },
        }
    }
}

impl Report for ReserveReport {
    const SCHEMA: u32 = 2;
}

/// The com-objects of one device a Data Secure switch flags.
#[derive(Debug, Clone, Serialize)]
pub struct SecuredDevice {
    /// The device.
    pub address: String,
    /// Its com-objects.
    pub objects: Vec<u16>,
}

/// `bussard groups secure --json`: a group switched to or from Data Secure.
#[derive(Debug, Clone, Serialize)]
pub struct GroupSecureReport {
    /// The group address.
    pub ga: String,
    /// Whether it runs secured now.
    pub secure: bool,
    /// The changes to the project.
    pub changes: Vec<Change>,
    /// What happened to the group key.
    pub group_key: String,
    /// The devices whose objects changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<SecuredDevice>>,
    /// The devices to plan and write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_devices: Option<Vec<String>>,
    /// The history snapshot before the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// Whether the snapshot keeps a copy of the key store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_keeps_key_store: Option<bool>,
    /// A note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GroupSecureReport {
    /// The switch of `ga` with `changes`, the key `group_key` in words.
    pub fn new(ga: impl ToString, secure: bool, changes: &ChangeSet, group_key: &str) -> Self {
        GroupSecureReport {
            ga: ga.to_string(),
            secure,
            changes: changes.changes.clone(),
            group_key: group_key.to_string(),
            devices: None,
            plan_devices: None,
            snapshot: None,
            snapshot_keeps_key_store: None,
            note: None,
        }
    }

    /// With the devices whose objects changed and the ones to write.
    pub fn with_devices(
        mut self,
        devices: &std::collections::BTreeMap<IndividualAddress, std::collections::BTreeSet<u16>>,
        plan: &[IndividualAddress],
    ) -> Self {
        self.devices = Some(secured_devices(devices));
        self.plan_devices = Some(plan.iter().map(ToString::to_string).collect());
        self
    }
}

/// The devices of a Data Secure switch with their objects.
pub fn secured_devices(
    devices: &std::collections::BTreeMap<IndividualAddress, std::collections::BTreeSet<u16>>,
) -> Vec<SecuredDevice> {
    devices
        .iter()
        .map(|(ia, objects)| SecuredDevice {
            address: ia.to_string(),
            objects: objects.iter().copied().collect(),
        })
        .collect()
}

impl Report for GroupSecureReport {
    const SCHEMA: u32 = 2;
}
