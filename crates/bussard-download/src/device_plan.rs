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
    /// The KNX Data Secure security object: the security individual address
    /// table (PID 54, issue #297), the group key table (PID 53) and the
    /// group-object security flags (PID 61, issue #331).
    Security,
    /// The KNXnet/IP parameter object of an IP interface: the `[knxnet]`
    /// table of its device file (issue #391).
    Interface,
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
    /// The security object is reprogrammed for a change of its own (the
    /// tunnelling addresses `admit_tunnel_senders` admits, issue #297, or a
    /// group address that leaves or joins Data Secure, issue #331); the
    /// tables are then rewritten too, since the security object is written
    /// inside the table download.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub security_object: bool,
    /// The parameter values change the group-object table, so the write is
    /// a full application download (`method: flash`): the whole image and
    /// the tables, whatever else differs (issue #326).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_image: Option<FullImage>,
    /// The System 7 objects whose communication flag the write switches, so
    /// that the flag follows the links (the CONFIG octet of each descriptor in
    /// the group-object table, see [`crate::sys7_flag_writes`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub communication_flags: Vec<u16>,
    /// The properties of the KNXnet/IP parameter object the write sets, by
    /// PID in write order (issue #391).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interface_properties: Vec<u8>,
    /// The write ends with a basic restart: a System 7 table write, as ETS's
    /// table-only downloads do (see [`crate::apply_sys7`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub restart: bool,
    /// The System B group-object table is reloaded from the image the full
    /// flash writes, because the device's differs from it (issue #540, see
    /// [`crate::object_table`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_object_table: Option<ObjectTableWrite>,
}

/// A System B group-object table reload, for the plan's `writes` line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ObjectTableWrite {
    /// The table's entry count after the write.
    pub entries: usize,
    /// The objects whose descriptor changes, ascending.
    pub objects: Vec<u16>,
}

impl ObjectTableWrite {
    /// `group-object table (12 entries; object 7 changes)`.
    pub fn describe(&self) -> String {
        let objects: Vec<String> = self.objects.iter().map(u16::to_string).collect();
        match objects.len() {
            0 => format!("group-object table ({})", entries(self.entries)),
            1 => format!(
                "group-object table ({}; object {} changes)",
                entries(self.entries),
                objects[0]
            ),
            _ => format!(
                "group-object table ({}; objects {} change)",
                entries(self.entries),
                objects.join(", ")
            ),
        }
    }
}

/// What a full application download writes, for the plan's `writes` line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FullImage {
    /// The memory segments the image writes, app-relative (`AS-4800`), in
    /// download order. Empty until the image is built (a CLI plan names the
    /// download, `bussard flash` builds it).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub segments: Vec<String>,
    /// The address table entry count after the download.
    pub address_table: usize,
    /// The association table entry count after the download.
    pub association_table: usize,
    /// Whether the tables' contents change, or are rewritten as they are.
    pub tables_change: bool,
}

impl FullImage {
    /// `full image (segments AS-4400, AS-4800), tables rewritten (unchanged:
    /// 4 addresses, 5 associations)`.
    pub fn describe(&self) -> String {
        let image = if self.segments.is_empty() {
            "full image".to_string()
        } else {
            format!(
                "full image (segment{} {})",
                if self.segments.len() == 1 { "" } else { "s" },
                self.segments.join(", ")
            )
        };
        let tables = if self.tables_change {
            format!(
                "tables rewritten (address table ({}), association table ({}))",
                entries(self.address_table),
                entries(self.association_table)
            )
        } else {
            format!(
                "tables rewritten (unchanged: {} address{}, {} association{})",
                self.address_table,
                if self.address_table == 1 { "" } else { "es" },
                self.association_table,
                if self.association_table == 1 { "" } else { "s" }
            )
        };
        format!("{image}, {tables}")
    }
}

impl PlanWrites {
    /// Whether nothing is written.
    pub fn is_empty(&self) -> bool {
        self.address_table.is_none()
            && self.parameter_octets == 0
            && !self.security_object
            && self.full_image.is_none()
            && self.interface_properties.is_empty()
            && self.communication_flags.is_empty()
            && self.group_object_table.is_none()
    }

    /// `address table (4 entries), association table (5 entries), 1 parameter
    /// octet`, `full image (segments …), tables rewritten (…)` for a full
    /// download, or `nothing`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(full) = &self.full_image {
            parts.push(full.describe());
            if self.security_object {
                parts.push("security object (PID 53, 54, 61)".to_string());
            }
            return parts.join(", ");
        }
        // The group-object table is loaded first (issue #540).
        if let Some(table) = &self.group_object_table {
            parts.push(table.describe());
        }
        if let Some(n) = self.address_table {
            parts.push(format!("address table ({})", entries(n)));
        }
        if let Some(n) = self.association_table {
            parts.push(format!("association table ({})", entries(n)));
        }
        if self.security_object {
            parts.push("security object (PID 53, 54, 61)".to_string());
        }
        if !self.communication_flags.is_empty() {
            let objects: Vec<String> = self
                .communication_flags
                .iter()
                .map(u16::to_string)
                .collect();
            parts.push(format!(
                "communication flag{} (object{} {})",
                if objects.len() == 1 { "" } else { "s" },
                if objects.len() == 1 { "" } else { "s" },
                objects.join(", ")
            ));
        }
        if self.parameter_octets > 0 {
            parts.push(format!(
                "{} parameter octet{}",
                self.parameter_octets,
                if self.parameter_octets == 1 { "" } else { "s" }
            ));
        }
        if !self.interface_properties.is_empty() {
            let pids: Vec<String> = self
                .interface_properties
                .iter()
                .map(|p| format!("PID {p}"))
                .collect();
            parts.push(format!("KNXnet/IP parameter object ({})", pids.join(", ")));
        }
        if parts.is_empty() {
            return "nothing".to_string();
        }
        let parts = parts.join(", ");
        if self.restart {
            format!("{parts}, then a restart")
        } else {
            parts
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
            // An interface plan (issue #391) compares no objects.
            None if self.unchanged_objects == 0 && !self.writes.interface_properties.is_empty() => {
            }
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
    state_hash_with(live, params, None)
}

/// [`state_hash`] that also covers the System B group-object table as read
/// (issue #540): `object_table` is the octets read
/// ([`crate::LiveObjectTable::image`]). `None` hashes as [`state_hash`].
pub fn state_hash_with(
    live: &LiveTables,
    params: Option<&ParamRegions>,
    object_table: Option<&[u8]>,
) -> String {
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
            match s7.group_object_base {
                Some(base) => put(&mut h, &base.to_be_bytes()),
                None => put(&mut h, b"no-object-table"),
            }
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
    // Only a read table is hashed, so every hash computed without one stays
    // what it was.
    if let Some(image) = object_table {
        put(&mut h, b"object-table");
        put(&mut h, image);
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
            group_objects: None,
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
            knxnet: None,
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
                security_object: false,
                full_image: None,
                interface_properties: Vec::new(),
                communication_flags: Vec::new(),
                restart: false,
                group_object_table: None,
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

    /// A System 7 communication-flag change is a write of its own.
    #[test]
    fn test_plan_writes_describe_communication_flags() {
        // A flag-only write (tables already match) is a write, and says so.
        let mut writes = PlanWrites {
            communication_flags: vec![32],
            ..PlanWrites::default()
        };
        assert!(!writes.is_empty());
        assert_eq!(writes.describe(), "communication flag (object 32)");
        writes.address_table = Some(6);
        writes.association_table = Some(6);
        writes.communication_flags = vec![32, 33];
        assert_eq!(
            writes.describe(),
            "address table (6 entries), association table (6 entries), \
             communication flags (objects 32, 33)"
        );
        // A System 7 table write ends with a restart, and says so.
        writes.restart = true;
        assert_eq!(
            writes.describe(),
            "address table (6 entries), association table (6 entries), \
             communication flags (objects 32, 33), then a restart"
        );
    }

    /// Issue #540: a System B group-object table reload is a write of its
    /// own, named first (it is loaded before the link tables).
    #[test]
    fn test_plan_writes_describe_a_group_object_table_reload() {
        let mut writes = PlanWrites {
            group_object_table: Some(ObjectTableWrite {
                entries: 12,
                objects: vec![7],
            }),
            ..PlanWrites::default()
        };
        assert!(!writes.is_empty());
        assert_eq!(
            writes.describe(),
            "group-object table (12 entries; object 7 changes)"
        );
        writes.address_table = Some(3);
        writes.association_table = Some(4);
        writes.group_object_table = Some(ObjectTableWrite {
            entries: 12,
            objects: vec![7, 9],
        });
        assert_eq!(
            writes.describe(),
            "group-object table (12 entries; objects 7, 9 change), address table (3 entries), \
             association table (4 entries)"
        );
    }

    /// Issue #540: the group-object table as read is part of the state hash,
    /// and a hash without one is the plain [`state_hash`].
    #[test]
    fn test_state_hash_with_covers_the_object_table() {
        let a = live(&[0x0A00]);
        assert_eq!(state_hash_with(&a, None, None), state_hash(&a, None));
        let one = state_hash_with(&a, None, Some(&[0, 1, 0x18, 0]));
        assert_ne!(one, state_hash(&a, None));
        assert_ne!(one, state_hash_with(&a, None, Some(&[0, 1, 0x1C, 0])));
    }

    /// Issue #326: a full download with parameter changes and unchanged
    /// links says what it writes, never "nothing".
    #[test]
    fn test_plan_writes_describe_a_full_image() {
        let mut writes = PlanWrites {
            full_image: Some(FullImage {
                segments: vec!["AS-4400".to_string(), "AS-4800".to_string()],
                address_table: 12,
                association_table: 1,
                tables_change: false,
            }),
            ..PlanWrites::default()
        };
        assert!(!writes.is_empty());
        assert_eq!(
            writes.describe(),
            "full image (segments AS-4400, AS-4800), tables rewritten (unchanged: 12 \
             addresses, 1 association)"
        );
        if let Some(full) = writes.full_image.as_mut() {
            full.segments = Vec::new();
            full.tables_change = true;
        }
        assert_eq!(
            writes.describe(),
            "full image, tables rewritten (address table (12 entries), association table (1 \
             entry))"
        );
    }
}
