//! The plan of one device write, in the model's vocabulary.
//!
//! `bussard plan`, `bussard apply` and the MCP `knx_plan_device` tool all show
//! the same thing: what writing the model to one device changes, as sentences
//! that name objects and parameters by the keys the device file uses, grouped
//! by channel, followed by what stays unchanged, what is written, where the
//! backup goes, and the one question `apply` asks.
//!
//! ```text
//! 1.1.47 Jalousieaktor Kind 2
//!   channel a-1 (Fenster Süd)
//!     + langzeitbetrieb now listens on 0/1/3 (Jalousie Auf/Ab)
//!     ~ status-position sends 0/1/4, was 0/1/9
//!     ~ betriebsart = Jalousie, was Rollladen
//!   unchanged: 3 objects, 41 parameters
//!   writes: address table (4 entries), association table (5 entries), 1 parameter octet
//!   backup: knx/captures/backups/
//! ```
//!
//! [`state_hash`] fingerprints the device state the plan was computed from
//! (the raw tables, plus the parameter memory when it was read), so an apply
//! can refuse when the device moved since the plan a human approved.

use std::collections::{BTreeMap, BTreeSet};

use bussard_model::{GroupAddress, IndividualAddress, Model};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::param_plan::ParamRegions;
use crate::plan::PlanReport;
use crate::program::LiveTables;

/// What a change does to its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ChangeMark {
    /// Something the device gains (`+`).
    #[serde(rename = "+")]
    Added,
    /// Something the device loses (`-`).
    #[serde(rename = "-")]
    Removed,
    /// Something the device has that takes another value (`~`).
    #[serde(rename = "~")]
    Changed,
}

impl ChangeMark {
    /// The one-character mark the text rendering uses.
    pub fn symbol(self) -> char {
        match self {
            ChangeMark::Added => '+',
            ChangeMark::Removed => '-',
            ChangeMark::Changed => '~',
        }
    }
}

/// What a change is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSubject {
    /// A com object's links (the tables).
    Object,
    /// A parameter value (the parameter memory).
    Parameter,
}

/// One line of a device plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanChange {
    /// `+`, `-` or `~`.
    pub mark: ChangeMark,
    /// Object or parameter.
    pub subject: ChangeSubject,
    /// The channel handle the subject belongs to, `None` at device level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The key the device file uses (`langzeitbetrieb`, `betriebsart`), or
    /// `object <n>` for an object the lock gives no key.
    pub key: String,
    /// The com-object number, for an object change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<u16>,
    /// The sentence without its mark: `langzeitbetrieb now listens on 0/1/3
    /// (Jalousie Auf/Ab)`.
    pub sentence: String,
}

impl PlanChange {
    /// The line as printed: `+ langzeitbetrieb now listens on 0/1/3 (…)`.
    pub fn line(&self) -> String {
        format!("{} {}", self.mark.symbol(), self.sentence)
    }
}

/// What the write consists of.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PlanWrites {
    /// The address table entry count after the write, when the tables are
    /// written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_table: Option<usize>,
    /// The association table entry count after the write, when the tables
    /// are written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub association_table: Option<usize>,
    /// How many parameter octets differ and are written.
    pub parameter_octets: usize,
}

impl PlanWrites {
    /// Whether nothing is written.
    pub fn is_empty(&self) -> bool {
        self.address_table.is_none() && self.parameter_octets == 0
    }

    /// `address table (4 entries), association table (5 entries), 1 parameter
    /// octet`, or `nothing`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(n) = self.address_table {
            parts.push(format!("address table ({})", entries(n)));
        }
        if let Some(n) = self.association_table {
            parts.push(format!("association table ({})", entries(n)));
        }
        if self.parameter_octets > 0 {
            parts.push(format!(
                "{} parameter octet{}",
                self.parameter_octets,
                if self.parameter_octets == 1 { "" } else { "s" }
            ));
        }
        if parts.is_empty() {
            "nothing".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// `1 entry` / `4 entries`.
fn entries(n: usize) -> String {
    format!("{n} entr{}", if n == 1 { "y" } else { "ies" })
}

/// The plan of writing the model to one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DevicePlan {
    /// The device.
    pub address: String,
    /// The device's name in the model.
    pub name: String,
    /// The resolved gateway the write goes through.
    pub gateway: String,
    /// The changes, device-level first, then by channel.
    pub changes: Vec<PlanChange>,
    /// The channel names, keyed by handle, for the group headers.
    pub channels: BTreeMap<String, String>,
    /// Linked objects whose links stay as they are.
    pub unchanged_objects: usize,
    /// Parameters that already hold the model's value; `None` when the
    /// parameter memory was not compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unchanged_parameters: Option<usize>,
    /// What is written.
    pub writes: PlanWrites,
    /// Where the pre-write backup goes.
    pub backup_dir: String,
    /// Why part of the device was not compared (no product data, another
    /// application on the device, …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// The fingerprint of the device state the plan was computed from.
    pub state_hash: String,
}

impl DevicePlan {
    /// Whether writing the model changes nothing on the device.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.writes.is_empty()
    }

    /// The number of changes the question counts.
    pub fn change_count(&self) -> usize {
        self.changes.len()
    }

    /// `apply these 3 changes to 1.1.47 through 192.168.1.74:3671?`
    pub fn question(&self) -> String {
        let n = self.change_count();
        format!(
            "apply {} to {} through {}?",
            if n == 1 {
                "this change".to_string()
            } else {
                format!("these {n} changes")
            },
            self.address,
            self.gateway
        )
    }

    /// The text rendering (see the module docs). An empty plan is the single
    /// line `<ia> matches the model; nothing to write`, plus the notes.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        if self.is_empty() {
            out.push_str(&format!(
                "{} matches the model; nothing to write\n",
                self.address
            ));
            for note in &self.notes {
                out.push_str(&format!("  note: {note}\n"));
            }
            return out;
        }
        if self.name.trim().is_empty() {
            out.push_str(&format!("{}\n", self.address));
        } else {
            out.push_str(&format!("{} {}\n", self.address, self.name.trim()));
        }
        let mut current: Option<Option<&str>> = None;
        for change in &self.changes {
            let channel = change.channel.as_deref();
            if current != Some(channel) {
                if let Some(handle) = channel {
                    match self.channels.get(handle).map(|n| n.trim()) {
                        Some(name) if !name.is_empty() && name != handle => {
                            out.push_str(&format!("  channel {handle} ({name})\n"));
                        }
                        _ => out.push_str(&format!("  channel {handle}\n")),
                    }
                }
                current = Some(channel);
            }
            let indent = if channel.is_some() { "    " } else { "  " };
            out.push_str(&format!("{indent}{}\n", change.line()));
        }
        let objects = format!(
            "{} object{}",
            self.unchanged_objects,
            if self.unchanged_objects == 1 { "" } else { "s" }
        );
        match self.unchanged_parameters {
            Some(p) => out.push_str(&format!(
                "  unchanged: {objects}, {p} parameter{}\n",
                if p == 1 { "" } else { "s" }
            )),
            None => out.push_str(&format!("  unchanged: {objects}\n")),
        }
        out.push_str(&format!("  writes: {}\n", self.writes.describe()));
        out.push_str(&format!("  backup: {}\n", self.backup_dir));
        for note in &self.notes {
            out.push_str(&format!("  note: {note}\n"));
        }
        out
    }
}

/// How the model names a group address mid-sentence: `0/1/3 (Jalousie Auf/Ab)`,
/// or the bare address when `groups.toml` gives it no name.
fn ga_label(model: &Model, ga: GroupAddress) -> String {
    match model.groups.groups.get(&ga).map(|g| g.name.trim()) {
        Some(name) if !name.is_empty() => format!("{ga} ({name})"),
        _ => ga.to_string(),
    }
}

/// The object changes of a table plan, as sentences, and how many linked
/// objects stay unchanged.
///
/// Each object the plan touches is described against the model's link for it:
/// a gained listening address is `+ <key> now listens on …`, a gained sending
/// address `+ <key> now sends …`, a sending address that replaces one the
/// device had `~ <key> sends <new>, was <old>`, and an address only the device
/// has `- <key> no longer uses …`.
pub fn object_changes(
    model: &Model,
    target: IndividualAddress,
    report: &PlanReport,
) -> (Vec<PlanChange>, usize) {
    let device = model.devices.get(&target).map(|d| &d.device);
    let links = model.links.links.get(&target);
    let mut adds: BTreeMap<u16, Vec<GroupAddress>> = BTreeMap::new();
    let mut rems: BTreeMap<u16, Vec<GroupAddress>> = BTreeMap::new();
    for p in &report.additions {
        adds.entry(p.object).or_default().push(p.ga);
    }
    for p in &report.removals {
        rems.entry(p.object).or_default().push(p.ga);
    }
    let touched: BTreeSet<u16> = adds.keys().chain(rems.keys()).copied().collect();
    let mut changes = Vec::new();
    for object in &touched {
        let co = device.and_then(|d| d.com_objects.get(object));
        let key = co
            .and_then(|c| c.key.clone())
            .unwrap_or_else(|| format!("object {object}"));
        let channel = co
            .and_then(|c| c.channel.as_deref())
            .and_then(|id| device.map(|d| d.channel_handle(id)));
        let send = links
            .and_then(|l| l.iter().find(|l| l.object == *object))
            .and_then(|l| l.send);
        let mut added = adds.remove(object).unwrap_or_default();
        let mut removed = rems.remove(object).unwrap_or_default();
        let change = |mark, sentence: String| PlanChange {
            mark,
            subject: ChangeSubject::Object,
            channel: channel.clone(),
            key: key.clone(),
            object: Some(*object),
            sentence,
        };
        if let Some(send) = send
            && let Some(pos) = added.iter().position(|g| *g == send)
            && !removed.is_empty()
        {
            added.remove(pos);
            let was = removed.remove(0);
            changes.push(change(
                ChangeMark::Changed,
                format!("{key} sends {send}, was {was}"),
            ));
        }
        for ga in added {
            let verb = if Some(ga) == send {
                "now sends"
            } else {
                "now listens on"
            };
            changes.push(change(
                ChangeMark::Added,
                format!("{key} {verb} {}", ga_label(model, ga)),
            ));
        }
        for ga in removed {
            changes.push(change(
                ChangeMark::Removed,
                format!("{key} no longer uses {}", ga_label(model, ga)),
            ));
        }
    }
    let unchanged: BTreeSet<u16> = report
        .unchanged
        .iter()
        .map(|p| p.object)
        .filter(|o| !touched.contains(o))
        .collect();
    (changes, unchanged.len())
}

/// Sorts changes into the rendering order: device level first, then by channel
/// handle; objects before parameters inside each group, in the order given.
pub fn sort_changes(changes: &mut [PlanChange]) {
    changes.sort_by(|a, b| {
        let subject = |c: &PlanChange| matches!(c.subject, ChangeSubject::Parameter);
        (&a.channel, subject(a)).cmp(&(&b.channel, subject(b)))
    });
}

/// Feeds a length-prefixed byte string into a hash, so field boundaries are
/// unambiguous.
fn put(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// The fingerprint of a device's state as read: SHA-256 over the raw tables
/// (mask, group addresses, associations, and on System 7 the region layout
/// the write depends on) and, when it was read, the parameter memory (each
/// region's segment, base and octets), as lowercase hex.
///
/// `plan --json` prints it; `apply --plan <hash>` and `knx_apply_device`
/// with `plan_hash` recompute it from a fresh read and refuse on a mismatch.
pub fn state_hash(live: &LiveTables, params: Option<&ParamRegions>) -> String {
    let tables = live.tables();
    let mut h = Sha256::new();
    put(&mut h, b"bussard-device-state-v1");
    put(&mut h, &tables.mask.to_be_bytes());
    let addresses: Vec<u8> = tables
        .addresses
        .iter()
        .flat_map(|ga| ga.raw().to_be_bytes())
        .collect();
    put(&mut h, &addresses);
    let associations: Vec<u8> = tables
        .associations
        .iter()
        .flat_map(|(tsap, asap)| {
            let mut pair = tsap.to_be_bytes().to_vec();
            pair.extend_from_slice(&asap.to_be_bytes());
            pair
        })
        .collect();
    put(&mut h, &associations);
    match live.sys7() {
        Some(s7) => {
            put(&mut h, b"sys7");
            put(&mut h, &s7.address_base.to_be_bytes());
            put(&mut h, &s7.association_base.to_be_bytes());
            put(&mut h, &s7.own_ia.to_be_bytes());
            put(&mut h, &s7.group_object_base.to_be_bytes());
            put(&mut h, &s7.group_object_image);
        }
        None => put(&mut h, b"system-b"),
    }
    match params {
        Some(regions) => {
            put(&mut h, b"parameters");
            for (segment, region) in regions {
                put(&mut h, segment.as_bytes());
                put(&mut h, &region.address.to_be_bytes());
                put(&mut h, &region.bytes);
            }
        }
        None => put(&mut h, b"no-parameters"),
    }
    let bytes: [u8; 32] = h.finalize().into();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::param_plan::ParamRegion;
    use crate::plan::ObjectGa;
    use bussard_mgmt::tables::DeviceTables;
    use bussard_model::LoadedDevice;
    use bussard_model::schema::{Channel, ComObject, Device, Group, Link};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn live(addresses: &[u16]) -> LiveTables {
        LiveTables::SystemB(DeviceTables {
            mask: 0x07B0,
            addresses: addresses
                .iter()
                .map(|&raw| GroupAddress::from_raw(raw))
                .collect(),
            associations: vec![(1, 20)],
            resolved: Vec::new(),
            sources: Vec::new(),
            notes: Vec::new(),
        })
    }

    #[test]
    fn test_state_hash_covers_tables_and_parameters() {
        let a = live(&[0x0A00]);
        let b = live(&[0x0A01]);
        assert_eq!(state_hash(&a, None), state_hash(&a, None));
        assert_ne!(state_hash(&a, None), state_hash(&b, None));
        let mut regions = ParamRegions::new();
        regions.insert(
            "RS-2".to_string(),
            ParamRegion {
                segment_id: "RS-2".to_string(),
                address: 0x4006,
                bytes: vec![7, 0],
            },
        );
        let with = state_hash(&a, Some(&regions));
        assert_ne!(with, state_hash(&a, None));
        if let Some(r) = regions.get_mut("RS-2") {
            r.bytes[0] = 12;
        }
        assert_ne!(with, state_hash(&a, Some(&regions)));
        assert_eq!(with.len(), 64);
    }

    fn model() -> Result<(Model, IndividualAddress), Box<dyn std::error::Error>> {
        let ia: IndividualAddress = "1.1.47".parse()?;
        let mut device = Device {
            address: ia,
            name: "Jalousieaktor".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects: BTreeMap::new(),
            application_override: None,
            lock: Default::default(),
            security: None,
        };
        device.channels.insert(
            "CH-1".to_string(),
            Channel {
                name: "Fenster Süd".to_string(),
                key: Some("a-1".to_string()),
                ..Channel::default()
            },
        );
        for (n, key) in [(144u16, "langzeitbetrieb"), (162, "status-position")] {
            device.com_objects.insert(
                n,
                ComObject {
                    key: Some(key.to_string()),
                    channel: Some("CH-1".to_string()),
                    ..ComObject::default()
                },
            );
        }
        let mut model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: BTreeMap::new(),
        };
        model.devices.insert(
            ia,
            LoadedDevice {
                device,
                file_stem: ia.to_string(),
            },
        );
        model.links.links.insert(
            ia,
            vec![
                Link {
                    object: 144,
                    name: None,
                    send: None,
                    listen: vec!["0/1/3".parse()?],
                },
                Link {
                    object: 162,
                    name: None,
                    send: Some("0/1/4".parse()?),
                    listen: Vec::new(),
                },
            ],
        );
        model.groups.groups.insert(
            "0/1/3".parse()?,
            Group {
                name: "Jalousie Auf/Ab".to_string(),
                dpt: None,
                description: None,
                protected: false,
                secure: false,
            },
        );
        Ok((model, ia))
    }

    #[test]
    fn test_object_changes_speak_the_device_file_keys() -> TestResult {
        let (model, ia) = model()?;
        let pair = |object, ga: &str| -> Result<ObjectGa, Box<dyn std::error::Error>> {
            Ok(ObjectGa {
                object,
                ga: ga.parse()?,
            })
        };
        let report = PlanReport {
            unchanged: vec![pair(170, "0/1/7")?],
            additions: vec![pair(144, "0/1/3")?, pair(162, "0/1/4")?],
            removals: vec![pair(162, "0/1/9")?, pair(99, "0/1/8")?],
            resulting_address_count: 3,
            resulting_association_count: 3,
            current_address_count: 3,
            current_association_count: 3,
            load_steps: Vec::new(),
        };
        let (mut changes, unchanged) = object_changes(&model, ia, &report);
        sort_changes(&mut changes);
        let lines: Vec<String> = changes.iter().map(PlanChange::line).collect();
        assert_eq!(
            lines,
            vec![
                "- object 99 no longer uses 0/1/8",
                "+ langzeitbetrieb now listens on 0/1/3 (Jalousie Auf/Ab)",
                "~ status-position sends 0/1/4, was 0/1/9",
            ]
        );
        assert_eq!(unchanged, 1);
        let plan = DevicePlan {
            address: ia.to_string(),
            name: "Jalousieaktor".to_string(),
            gateway: "127.0.0.1:3671".to_string(),
            channels: BTreeMap::from([("a-1".to_string(), "Fenster Süd".to_string())]),
            changes,
            unchanged_objects: unchanged,
            unchanged_parameters: None,
            writes: PlanWrites {
                address_table: Some(3),
                association_table: Some(3),
                parameter_octets: 0,
            },
            backup_dir: "knx/captures/backups/".to_string(),
            notes: Vec::new(),
            state_hash: String::new(),
        };
        assert_eq!(
            plan.render_text(),
            "1.1.47 Jalousieaktor\n\
             \x20 - object 99 no longer uses 0/1/8\n\
             \x20 channel a-1 (Fenster Süd)\n\
             \x20   + langzeitbetrieb now listens on 0/1/3 (Jalousie Auf/Ab)\n\
             \x20   ~ status-position sends 0/1/4, was 0/1/9\n\
             \x20 unchanged: 1 object\n\
             \x20 writes: address table (3 entries), association table (3 entries)\n\
             \x20 backup: knx/captures/backups/\n"
        );
        assert_eq!(
            plan.question(),
            "apply these 3 changes to 1.1.47 through 127.0.0.1:3671?"
        );
        Ok(())
    }
}
