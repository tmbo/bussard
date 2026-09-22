//! Generating the handover documentation folder from the model (issue #97).
//!
//! The KNX guidelines prescribe a documentation folder for every installation: a
//! device list, a group-address list, a function description per room, the
//! gateway details, and a change log. Integrators build it by hand and dread
//! redoing it after every change. Everything it needs is already in the model,
//! so bussard renders it.
//!
//! The pipeline is two steps, deliberately separated so the structured form is
//! also the `--json` output:
//!
//! 1. [`InstallationDoc::build`] projects a [`Model`] (plus the cached
//!    [`ProductModels`], when present) into a flat, sorted document model.
//! 2. [`InstallationDoc::render`] turns that into a set of [`DocFile`]s, either
//!    Markdown or self-contained HTML.
//!
//! # Determinism
//!
//! The output is byte-identical across runs on an unchanged model: every
//! collection is walked in sorted order (the model's own `BTreeMap`s), nothing
//! carries a timestamp, and the only external input is `git log`, which is a
//! function of the repository state. That makes the folder committable and its
//! diffs reviewable, which is the whole point of regenerating it after every
//! change.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::address::GroupAddress;
use crate::loader::Model;
use crate::param_model::ProductModels;
use crate::schema::Transport;

/// How many commits the change log carries. Enough to see the recent history of
/// an installation without turning the folder into a repository mirror.
const CHANGELOG_LIMIT: usize = 50;

/// The rendered output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocFormat {
    /// Markdown, one `.md` file per section.
    Markdown,
    /// Self-contained HTML, one `.html` file per section.
    Html,
}

/// An error writing the rendered documentation to disk.
#[derive(Debug, thiserror::Error)]
pub enum DocError {
    /// A file or directory could not be written.
    #[error("writing {path}: {source}")]
    Io {
        /// The path being written.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// One rendered documentation file: its path relative to the output directory,
/// and its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocFile {
    /// The path relative to the output directory, e.g. `rooms/eg-kitchen.md`.
    pub path: String,
    /// The file's full contents.
    pub content: String,
}

/// The connection details, taken from `bussard.yaml`.
///
/// Carries the gateway endpoint only. bussard never stores credentials in the
/// model, and this projection would be the one place they could leak into a
/// committed folder, so it is defined by what it *excludes*: no keyring path, no
/// password, no tool key, no BCU key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionDoc {
    /// `tunnel` or `routing`.
    pub transport: String,
    /// The tunnelling gateway `host:port`, when configured.
    pub gateway: Option<String>,
    /// The routing multicast `addr:port`, when configured.
    pub multicast: Option<String>,
}

/// A reference to a group address, with its name when the model names one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupRef {
    /// The group address, e.g. `1/0/10`.
    pub address: String,
    /// The group's display name, when `groups.yaml` names it.
    pub name: Option<String>,
}

impl GroupRef {
    /// The display form: `Name (1/0/10)`, or just the address when unnamed.
    pub fn display(&self) -> String {
        match &self.name {
            Some(name) => format!("{name} ({})", self.address),
            None => self.address.clone(),
        }
    }
}

/// One com object on a device, with the group addresses it is linked to and a
/// plain-language sentence describing what it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectDoc {
    /// The com-object number (the stable ETS handle).
    pub number: u16,
    /// The display name: the link's name, else `com object <n>`.
    pub name: String,
    /// The datapoint type, when known.
    pub dpt: Option<String>,
    /// The com-object flags, e.g. `CWTU`.
    pub flags: String,
    /// The sending group address, when the object has one.
    pub send: Option<GroupRef>,
    /// The listening group addresses.
    pub listen: Vec<GroupRef>,
    /// A sentence describing the object for a reader with no KNX knowledge.
    pub sentence: String,
}

/// A named channel on a device, with the com objects that belong to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChannelDoc {
    /// The channel key used in the device file.
    pub key: String,
    /// The channel's display name.
    pub name: String,
    /// The com objects assigned to this channel, by object number.
    pub objects: Vec<ObjectDoc>,
}

/// One configured parameter on a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParameterDoc {
    /// The device-file parameter key (`<slug>@<ref-id>`).
    pub key: String,
    /// The human part of the key (the slug before `@`).
    pub label: String,
    /// The configured value.
    pub value: String,
    /// The vendor default, when a cached product model supplies one.
    pub default: Option<String>,
}

/// One device, as the documentation describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceDoc {
    /// The individual address, e.g. `1.1.4`.
    pub address: String,
    /// The display name.
    pub name: String,
    /// The free-text description from the device file.
    pub description: Option<String>,
    /// The floor, when the device file records one.
    pub floor: Option<String>,
    /// The room, when the device file records one.
    pub room: Option<String>,
    /// The manufacturer name, else the manufacturer ref.
    pub manufacturer: Option<String>,
    /// The order number.
    pub order_number: Option<String>,
    /// The application program ref.
    pub application: Option<String>,
    /// The mask version, e.g. `07B0`.
    pub mask: Option<String>,
    /// The KNX Secure status: `activated`, `capable` or `no`.
    pub secure: String,
    /// The device's named channels, with their objects.
    pub channels: Vec<ChannelDoc>,
    /// Com objects that belong to no channel.
    pub other_objects: Vec<ObjectDoc>,
    /// The parameters configured in the device file.
    pub parameters: Vec<ParameterDoc>,
}

/// One end of a group-address link: a device and one of its com objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    /// The device's individual address.
    pub device: String,
    /// The device's display name.
    pub device_name: String,
    /// The com-object number.
    pub object: u16,
    /// The com-object's display name.
    pub object_name: String,
}

impl Endpoint {
    /// The display form: `Device name (1.1.4) / object name`.
    pub fn display(&self) -> String {
        format!(
            "{} ({}) / {}",
            self.device_name, self.device, self.object_name
        )
    }
}

/// One group address, with who writes to it and who listens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupDoc {
    /// The group address, e.g. `1/0/10`.
    pub address: String,
    /// The display name.
    pub name: String,
    /// The datapoint type, when known.
    pub dpt: Option<String>,
    /// The free-text description.
    pub description: Option<String>,
    /// Whether the group is guarded against casual writes.
    pub protected: bool,
    /// The objects that send on this address.
    pub senders: Vec<Endpoint>,
    /// The objects that listen on this address.
    pub listeners: Vec<Endpoint>,
}

/// One room sheet: a floor/room pair and the devices installed there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoomDoc {
    /// The filename stem, e.g. `eg-kitchen`.
    pub slug: String,
    /// The floor, or `unassigned`.
    pub floor: String,
    /// The room, or `unassigned`.
    pub room: String,
    /// The individual addresses of the devices in this room, sorted.
    pub devices: Vec<String>,
}

/// One entry of the change log, read from `git log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeEntry {
    /// The abbreviated commit hash.
    pub commit: String,
    /// The author date, `YYYY-MM-DD`.
    pub date: String,
    /// The commit subject line.
    pub subject: String,
}

/// The whole documentation set, projected from the model.
///
/// This is also the shape `bussard doc --json` emits, so it is the stable
/// machine-readable contract: an assistant can answer "what is on 1/0/10?" from
/// it without re-deriving anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallationDoc {
    /// The project name from `groups.yaml`, when it carries one.
    pub project: Option<String>,
    /// The connection details, credentials excluded.
    pub connection: ConnectionDoc,
    /// Every device, sorted by individual address.
    pub devices: Vec<DeviceDoc>,
    /// Every group address, sorted.
    pub groups: Vec<GroupDoc>,
    /// One entry per floor/room pair that has devices, sorted by slug.
    pub rooms: Vec<RoomDoc>,
    /// The recent commits touching the model directory, newest first. Empty when
    /// the directory is not a git repository or `git` is not installed.
    pub changelog: Vec<ChangeEntry>,
}

impl InstallationDoc {
    /// Projects a model into the documentation set.
    ///
    /// `dir` is the model directory: it is used only to read the change log from
    /// git. `products` supplies the vendor defaults shown beside configured
    /// parameter values; an empty set simply omits them.
    pub fn build(model: &Model, products: &ProductModels, dir: &Path) -> Self {
        let group_names: BTreeMap<GroupAddress, String> = model
            .groups
            .groups
            .iter()
            .map(|(ga, g)| (*ga, g.name.clone()))
            .collect();

        let devices: Vec<DeviceDoc> = model
            .devices
            .values()
            .map(|loaded| device_doc(model, products, &group_names, &loaded.device))
            .collect();

        Self {
            project: model.groups.project.clone(),
            connection: connection_doc(model),
            groups: group_docs(model, &devices),
            rooms: room_docs(&devices),
            devices,
            changelog: changelog(dir),
        }
    }

    /// Renders the documentation set into files, in the requested format.
    ///
    /// The returned paths are relative to the output directory and sorted, so
    /// writing them is a straight loop and two runs write the same bytes.
    pub fn render(&self, format: DocFormat) -> Vec<DocFile> {
        let mut pages: Vec<(String, String)> = vec![
            ("index".to_string(), self.index_markdown()),
            ("devices".to_string(), self.devices_markdown()),
            ("groups".to_string(), self.groups_markdown()),
            ("connection".to_string(), self.connection_markdown()),
            ("changelog".to_string(), self.changelog_markdown()),
        ];
        let by_address: BTreeMap<&str, &DeviceDoc> = self
            .devices
            .iter()
            .map(|d| (d.address.as_str(), d))
            .collect();
        for room in &self.rooms {
            pages.push((
                format!("rooms/{}", room.slug),
                self.room_markdown(room, &by_address),
            ));
        }

        pages
            .into_iter()
            .map(|(stem, markdown)| match format {
                DocFormat::Markdown => DocFile {
                    path: format!("{stem}.md"),
                    content: markdown,
                },
                DocFormat::Html => DocFile {
                    path: format!("{stem}.html"),
                    content: html_page(&first_heading(&markdown), &markdown),
                },
            })
            .collect()
    }

    // --- page renderers ---------------------------------------------------

    fn index_markdown(&self) -> String {
        let mut out = String::new();
        let title = self
            .project
            .clone()
            .unwrap_or_else(|| "KNX installation".to_string());
        let _ = writeln!(out, "# {title}\n");
        let _ = writeln!(
            out,
            "Handover documentation generated by `bussard doc` from the model. \
             Regenerate it after every change; the output is deterministic, so the \
             diff shows exactly what moved.\n"
        );
        let _ = writeln!(out, "## Contents\n");
        let _ = writeln!(
            out,
            "- [Devices](devices.md): {} device(s), with address, product and mask.",
            self.devices.len()
        );
        let _ = writeln!(
            out,
            "- [Group addresses](groups.md): {} address(es), with senders and listeners.",
            self.groups.len()
        );
        let _ = writeln!(
            out,
            "- [Connection](connection.md): how bussard reaches the bus."
        );
        let _ = writeln!(
            out,
            "- [Change log](changelog.md): recent commits to the model."
        );
        if self.rooms.is_empty() {
            let _ = writeln!(
                out,
                "\nNo room is recorded on any device, so there are no room sheets. Add a `location:` block to a device file to get one."
            );
        } else {
            let _ = writeln!(out, "\n## Rooms\n");
            for room in &self.rooms {
                let _ = writeln!(
                    out,
                    "- [{} / {}](rooms/{}.md): {} device(s).",
                    room.floor,
                    room.room,
                    room.slug,
                    room.devices.len()
                );
            }
        }
        out
    }

    fn devices_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Devices\n");
        if self.devices.is_empty() {
            let _ = writeln!(out, "The model contains no devices.");
            return out;
        }
        let _ = writeln!(
            out,
            "| Address | Name | Location | Manufacturer | Order number | Application | Mask | Secure |"
        );
        let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
        for d in &self.devices {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                d.address,
                cell(Some(&d.name)),
                cell(location_text(d).as_deref()),
                cell(d.manufacturer.as_deref()),
                cell(d.order_number.as_deref()),
                cell(d.application.as_deref()),
                cell(d.mask.as_deref()),
                d.secure,
            );
        }
        out
    }

    fn groups_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Group addresses\n");
        if self.groups.is_empty() {
            let _ = writeln!(out, "The model contains no group addresses.");
            return out;
        }
        let _ = writeln!(
            out,
            "| Address | Name | DPT | Description | Protected | Senders | Listeners |"
        );
        let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- |");
        for g in &self.groups {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} |",
                g.address,
                cell(Some(&g.name)),
                cell(g.dpt.as_deref()),
                cell(g.description.as_deref()),
                if g.protected { "yes" } else { "no" },
                endpoints_cell(&g.senders),
                endpoints_cell(&g.listeners),
            );
        }
        out
    }

    fn connection_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Connection\n");
        let _ = writeln!(
            out,
            "How bussard reaches the bus, from `bussard.yaml`. No credentials are \
             recorded here or anywhere else in the model: keyring passwords, tool \
             keys and BCU keys live outside it.\n"
        );
        let _ = writeln!(out, "| Setting | Value |");
        let _ = writeln!(out, "| --- | --- |");
        let _ = writeln!(out, "| Transport | {} |", self.connection.transport);
        let _ = writeln!(
            out,
            "| Gateway | {} |",
            cell(self.connection.gateway.as_deref())
        );
        let _ = writeln!(
            out,
            "| Multicast | {} |",
            cell(self.connection.multicast.as_deref())
        );
        out
    }

    fn changelog_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Change log\n");
        if self.changelog.is_empty() {
            let _ = writeln!(
                out,
                "No change log: the model directory is not a git repository, or git \
                 is not available. Put the model in git to get one."
            );
            return out;
        }
        let _ = writeln!(
            out,
            "The most recent {} commit(s) touching the model, newest first.\n",
            self.changelog.len()
        );
        let _ = writeln!(out, "| Date | Commit | Change |");
        let _ = writeln!(out, "| --- | --- | --- |");
        for entry in &self.changelog {
            let _ = writeln!(
                out,
                "| {} | `{}` | {} |",
                entry.date,
                entry.commit,
                escape_cell(&entry.subject)
            );
        }
        out
    }

    fn room_markdown(&self, room: &RoomDoc, by_address: &BTreeMap<&str, &DeviceDoc>) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# {} / {}\n", room.floor, room.room);
        let _ = writeln!(
            out,
            "What each device in this room does. Group addresses are the numbers in \
             brackets; the names are the ones from the group-address plan.\n"
        );
        for address in &room.devices {
            let Some(device) = by_address.get(address.as_str()) else {
                continue;
            };
            let _ = writeln!(out, "## {} ({})\n", device.name, device.address);
            if let Some(description) = &device.description {
                let _ = writeln!(out, "{description}\n");
            }
            if device.channels.is_empty() && device.other_objects.is_empty() {
                let _ = writeln!(
                    out,
                    "This device has no com objects in the model, so nothing is \
                     documented for it yet.\n"
                );
                continue;
            }
            for channel in &device.channels {
                let _ = writeln!(out, "### {}\n", channel.name);
                for object in &channel.objects {
                    let _ = writeln!(out, "- {}", object.sentence);
                }
                let _ = writeln!(out);
            }
            if !device.other_objects.is_empty() {
                if !device.channels.is_empty() {
                    let _ = writeln!(out, "### Other functions\n");
                }
                for object in &device.other_objects {
                    let _ = writeln!(out, "- {}", object.sentence);
                }
                let _ = writeln!(out);
            }
        }
        out
    }
}

/// Writes rendered files under `out`, creating directories as needed.
pub fn write_files(files: &[DocFile], out: &Path) -> Result<(), DocError> {
    for file in files {
        let path = out.join(&file.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| DocError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        std::fs::write(&path, &file.content).map_err(|source| DocError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

fn connection_doc(model: &Model) -> ConnectionDoc {
    let connection = &model.config.connection;
    ConnectionDoc {
        transport: match connection.transport {
            Transport::Tunnel => "tunnel".to_string(),
            Transport::Routing => "routing".to_string(),
        },
        gateway: connection.gateway.clone(),
        multicast: connection.multicast.clone(),
    }
}

fn device_doc(
    model: &Model,
    products: &ProductModels,
    group_names: &BTreeMap<GroupAddress, String>,
    device: &crate::schema::Device,
) -> DeviceDoc {
    let links = model.links.links.get(&device.address);
    let link_by_object: BTreeMap<u16, &crate::schema::Link> = links
        .map(|ls| ls.iter().map(|l| (l.object, l)).collect())
        .unwrap_or_default();

    // Every object the device knows about: the generated com-object table plus
    // any object that only `links.yaml` mentions (a hand-written link on a device
    // whose table was never imported).
    let mut numbers: Vec<u16> = device.com_objects.keys().copied().collect();
    numbers.extend(link_by_object.keys().copied());
    numbers.sort_unstable();
    numbers.dedup();

    let mut by_channel: BTreeMap<String, Vec<ObjectDoc>> = BTreeMap::new();
    let mut other_objects = Vec::new();
    for number in numbers {
        let com = device.com_objects.get(&number);
        let link = link_by_object.get(&number).copied();
        let doc = object_doc(number, com, link, group_names);
        match com.and_then(|c| c.channel.clone()) {
            Some(channel) => by_channel.entry(channel).or_default().push(doc),
            None => other_objects.push(doc),
        }
    }

    let channels: Vec<ChannelDoc> = by_channel
        .into_iter()
        .map(|(key, objects)| ChannelDoc {
            name: device
                .channels
                .get(&key)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| format!("Channel {key}")),
            key,
            objects,
        })
        .collect();

    let product_model = device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref())
        .and_then(|app| products.get(app));

    let parameters: Vec<ParameterDoc> = device
        .parameters
        .iter()
        .map(|(key, value)| ParameterDoc {
            label: key
                .split_once('@')
                .map_or(key.clone(), |(slug, _)| slug.replace('-', " ")),
            default: product_model.and_then(|m| {
                crate::param_model::key_to_param_id(key)
                    .and_then(|id| m.parameters.get(&id).and_then(|p| p.default.clone()))
            }),
            key: key.clone(),
            value: value.clone(),
        })
        .collect();

    let product = device.product.as_ref();
    DeviceDoc {
        address: device.address.to_string(),
        name: device.name.clone(),
        description: device.description.clone(),
        floor: device.location.as_ref().and_then(|l| l.floor.clone()),
        room: device.location.as_ref().and_then(|l| l.room.clone()),
        manufacturer: product.and_then(|p| {
            p.manufacturer
                .clone()
                .or_else(|| p.manufacturer_ref.clone())
        }),
        order_number: product.and_then(|p| p.order_number.clone()),
        application: product.and_then(|p| p.application_ref.clone()),
        mask: product.and_then(|p| p.mask.clone()),
        secure: match device.security.as_ref() {
            Some(s) if s.activated => "activated".to_string(),
            Some(s) if s.secure_capable => "capable".to_string(),
            _ => "no".to_string(),
        },
        channels,
        other_objects,
        parameters,
    }
}

fn object_doc(
    number: u16,
    com: Option<&crate::schema::ComObject>,
    link: Option<&crate::schema::Link>,
    group_names: &BTreeMap<GroupAddress, String>,
) -> ObjectDoc {
    let name = link
        .and_then(|l| l.name.clone())
        .unwrap_or_else(|| format!("com object {number}"));
    let send = link
        .and_then(|l| l.send)
        .map(|ga| group_ref(ga, group_names));
    let listen: Vec<GroupRef> = link
        .map(|l| {
            l.listen
                .iter()
                .map(|ga| group_ref(*ga, group_names))
                .collect()
        })
        .unwrap_or_default();
    let dpt = com.and_then(|c| c.dpt).map(|d| d.to_string());
    let sentence = sentence(&name, com.and_then(|c| c.dpt), send.as_ref(), &listen);
    ObjectDoc {
        number,
        name,
        dpt,
        flags: com.map(|c| c.flags.to_string()).unwrap_or_default(),
        send,
        listen,
        sentence,
    }
}

fn group_ref(ga: GroupAddress, group_names: &BTreeMap<GroupAddress, String>) -> GroupRef {
    GroupRef {
        address: ga.to_string(),
        name: group_names.get(&ga).cloned(),
    }
}

fn group_docs(model: &Model, devices: &[DeviceDoc]) -> Vec<GroupDoc> {
    // Index the endpoints per GA once, from the device projections (so the object
    // names match what the room sheets say).
    let mut senders: BTreeMap<String, Vec<Endpoint>> = BTreeMap::new();
    let mut listeners: BTreeMap<String, Vec<Endpoint>> = BTreeMap::new();
    for device in devices {
        for object in device
            .channels
            .iter()
            .flat_map(|c| &c.objects)
            .chain(&device.other_objects)
        {
            let endpoint = Endpoint {
                device: device.address.clone(),
                device_name: device.name.clone(),
                object: object.number,
                object_name: object.name.clone(),
            };
            if let Some(send) = &object.send {
                senders
                    .entry(send.address.clone())
                    .or_default()
                    .push(endpoint.clone());
            }
            for listen in &object.listen {
                listeners
                    .entry(listen.address.clone())
                    .or_default()
                    .push(endpoint.clone());
            }
        }
    }

    model
        .groups
        .groups
        .iter()
        .map(|(ga, group)| {
            let address = ga.to_string();
            GroupDoc {
                senders: senders.get(&address).cloned().unwrap_or_default(),
                listeners: listeners.get(&address).cloned().unwrap_or_default(),
                address,
                name: group.name.clone(),
                dpt: group.dpt.map(|d| d.to_string()),
                description: group.description.clone(),
                protected: group.protected,
            }
        })
        .collect()
}

fn room_docs(devices: &[DeviceDoc]) -> Vec<RoomDoc> {
    let mut by_room: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for device in devices {
        if device.floor.is_none() && device.room.is_none() {
            continue;
        }
        let floor = device
            .floor
            .clone()
            .unwrap_or_else(|| "unassigned".to_string());
        let room = device
            .room
            .clone()
            .unwrap_or_else(|| "unassigned".to_string());
        by_room
            .entry((floor, room))
            .or_default()
            .push(device.address.clone());
    }
    by_room
        .into_iter()
        .map(|((floor, room), mut addresses)| {
            addresses.sort();
            RoomDoc {
                slug: format!("{}-{}", slug(&floor), slug(&room)),
                floor,
                room,
                devices: addresses,
            }
        })
        .collect()
}

/// Reads the recent commits touching `dir` from git.
///
/// Best-effort and silent: a directory that is not a repository, a `git` that is
/// not installed, or any non-zero exit simply yields no change log. Nothing from
/// the environment reaches the argument list, and the output is parsed by the
/// tab-separated format git was asked for.
fn changelog(dir: &Path) -> Vec<ChangeEntry> {
    let inside = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output();
    match inside {
        Ok(out) if out.status.success() => {}
        _ => return Vec::new(),
    }

    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "log",
            &format!("--max-count={CHANGELOG_LIMIT}"),
            "--date=short",
            "--pretty=format:%h\t%ad\t%s",
            "--",
            ".",
        ])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            Some(ChangeEntry {
                commit: parts.next()?.to_string(),
                date: parts.next()?.to_string(),
                subject: parts.next()?.to_string(),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plain language
// ---------------------------------------------------------------------------

/// Builds the plain-language sentence for one com object.
///
/// The shape follows the owner guide's wording rule: name what the thing does
/// first, then where the feedback comes from, and never assume the reader knows
/// what a com object or a flag is.
fn sentence(
    name: &str,
    dpt: Option<crate::dpt::Dpt>,
    send: Option<&GroupRef>,
    listen: &[GroupRef],
) -> String {
    match (send, listen.is_empty()) {
        (Some(send), true) => format!("{name} {} {}.", verb(dpt), send.display()),
        (Some(send), false) => format!(
            "{name} {} {}; status from {}.",
            verb(dpt),
            send.display(),
            join_display(listen)
        ),
        (None, false) => format!("{name} follows {}.", join_display(listen)),
        (None, true) => format!("{name} is not linked to a group address."),
    }
}

/// The verb that makes a com object's function readable without KNX knowledge,
/// chosen from the datapoint type's main number.
fn verb(dpt: Option<crate::dpt::Dpt>) -> &'static str {
    match dpt.map(|d| d.main) {
        Some(1) => "switches",
        Some(3) => "dims",
        Some(5) => "sets the level of",
        Some(9) => "reports",
        Some(17) | Some(18) => "recalls a scene on",
        Some(20) => "sets the mode of",
        _ => "controls",
    }
}

fn join_display(refs: &[GroupRef]) -> String {
    let parts: Vec<String> = refs.iter().map(GroupRef::display).collect();
    match parts.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, head)) => format!("{} and {last}", head.join(", ")),
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// The device's location as one string, or `None` when it records neither.
fn location_text(device: &DeviceDoc) -> Option<String> {
    match (&device.floor, &device.room) {
        (None, None) => None,
        (Some(floor), None) => Some(floor.clone()),
        (None, Some(room)) => Some(room.clone()),
        (Some(floor), Some(room)) => Some(format!("{floor} / {room}")),
    }
}

/// A table cell: the value, or an em-free placeholder when absent.
fn cell(value: Option<&str>) -> String {
    match value {
        Some(v) if !v.is_empty() => escape_cell(v),
        _ => "-".to_string(),
    }
}

/// Escapes the one character that would break a Markdown table row.
fn escape_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn endpoints_cell(endpoints: &[Endpoint]) -> String {
    if endpoints.is_empty() {
        return "-".to_string();
    }
    escape_cell(
        &endpoints
            .iter()
            .map(Endpoint::display)
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Turns a floor or room name into a filename-safe slug.
fn slug(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = true;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unnamed".to_string()
    } else {
        out
    }
}

/// The text of the document's first `# ` heading, used as the HTML title.
fn first_heading(markdown: &str) -> String {
    markdown
        .lines()
        .find_map(|line| line.strip_prefix("# "))
        .unwrap_or("bussard")
        .to_string()
}

// ---------------------------------------------------------------------------
// Markdown to HTML
// ---------------------------------------------------------------------------

/// Wraps rendered HTML in a self-contained page.
///
/// The style sheet is inline on purpose: each page must open from the file
/// system with no server and no assets beside it, because that is how a handover
/// folder is actually read.
fn html_page(title: &str, markdown: &str) -> String {
    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{}</title>\n\
         <style>\n{}\n</style>\n\
         </head>\n\
         <body>\n<main>\n{}</main>\n</body>\n</html>\n",
        escape_html(title),
        STYLE,
        markdown_to_html(markdown)
    )
}

/// The inline style sheet for the HTML pages: the viz server's palette, reduced
/// to what a static document needs.
const STYLE: &str = "\
:root { color-scheme: light dark; --fg: #1b1f24; --bg: #ffffff; --muted: #5c6773; --line: #d8dee4; --accent: #0b6bcb; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6edf3; --bg: #0d1117; --muted: #8b949e; --line: #30363d; --accent: #58a6ff; }
}
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.6 system-ui, -apple-system, \"Segoe UI\", sans-serif; }
main { max-width: 60rem; margin: 0 auto; padding: 2rem 1rem 4rem; }
h1, h2, h3 { line-height: 1.25; }
h1 { border-bottom: 1px solid var(--line); padding-bottom: .3rem; }
a { color: var(--accent); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em; background: color-mix(in srgb, var(--fg) 8%, transparent); padding: .1em .35em; border-radius: 4px; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .95rem; }
th, td { border: 1px solid var(--line); padding: .4rem .6rem; text-align: left; vertical-align: top; }
th { background: color-mix(in srgb, var(--fg) 6%, transparent); }
ul { padding-left: 1.2rem; }
p { margin: .8rem 0; }";

/// Converts the Markdown subset this module emits into HTML.
///
/// The subset is fixed and small — headings, paragraphs, unordered lists, pipe
/// tables, and inline bold/code/links — so a dedicated converter is a few dozen
/// lines and costs no dependency. Anything outside the subset is passed through
/// as escaped text rather than guessed at.
fn markdown_to_html(markdown: &str) -> String {
    let mut out = String::new();
    let lines: Vec<&str> = markdown.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_end();

        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("### ") {
            let _ = writeln!(out, "<h3>{}</h3>", inline(rest));
            i += 1;
        } else if let Some(rest) = trimmed.strip_prefix("## ") {
            let _ = writeln!(out, "<h2>{}</h2>", inline(rest));
            i += 1;
        } else if let Some(rest) = trimmed.strip_prefix("# ") {
            let _ = writeln!(out, "<h1>{}</h1>", inline(rest));
            i += 1;
        } else if is_table_row(trimmed) && i + 1 < lines.len() && is_table_divider(lines[i + 1]) {
            let header = table_cells(trimmed);
            i += 2;
            let _ = writeln!(out, "<table>");
            let _ = write!(out, "<thead><tr>");
            for cell in header {
                let _ = write!(out, "<th>{}</th>", inline(&cell));
            }
            let _ = writeln!(out, "</tr></thead>");
            let _ = writeln!(out, "<tbody>");
            while i < lines.len() && is_table_row(lines[i].trim_end()) {
                let _ = write!(out, "<tr>");
                for cell in table_cells(lines[i].trim_end()) {
                    let _ = write!(out, "<td>{}</td>", inline(&cell));
                }
                let _ = writeln!(out, "</tr>");
                i += 1;
            }
            let _ = writeln!(out, "</tbody></table>");
        } else if trimmed.starts_with("- ") {
            let _ = writeln!(out, "<ul>");
            while i < lines.len() {
                let Some(item) = lines[i].trim_end().strip_prefix("- ") else {
                    break;
                };
                let _ = writeln!(out, "<li>{}</li>", inline(item));
                i += 1;
            }
            let _ = writeln!(out, "</ul>");
        } else {
            // A paragraph: consecutive non-empty, non-structural lines.
            let mut paragraph = Vec::new();
            while i < lines.len() {
                let current = lines[i].trim_end();
                if current.is_empty()
                    || current.starts_with('#')
                    || current.starts_with("- ")
                    || is_table_row(current)
                {
                    break;
                }
                paragraph.push(current.trim());
                i += 1;
            }
            let _ = writeln!(out, "<p>{}</p>", inline(&paragraph.join(" ")));
        }
    }
    out
}

fn is_table_row(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('|') && trimmed.ends_with('|') && trimmed.len() > 1
}

fn is_table_divider(line: &str) -> bool {
    is_table_row(line)
        && line
            .trim()
            .trim_matches('|')
            .split('|')
            .all(|c| !c.trim().is_empty() && c.trim().chars().all(|ch| ch == '-' || ch == ':'))
}

fn table_cells(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    let inner = &trimmed[1..trimmed.len() - 1];
    // Split on unescaped pipes, honouring the `\|` escape `escape_cell` writes.
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            if ch != '|' {
                current.push('\\');
            }
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '|' {
            cells.push(current.trim().to_string());
            current = String::new();
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    cells.push(current.trim().to_string());
    cells
}

/// Converts inline Markdown (bold, code, links) to HTML, escaping everything
/// else. Link targets ending in `.md` are rewritten to `.html` so the HTML
/// folder links within itself.
fn inline(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '`' {
            if let Some(end) = find_char(&chars, i + 1, '`') {
                let code: String = chars[i + 1..end].iter().collect();
                let _ = write!(out, "<code>{}</code>", escape_html(&code));
                i = end + 1;
                continue;
            }
        }
        if ch == '*' && i + 1 < chars.len() && chars[i + 1] == '*' {
            if let Some(end) = find_pair(&chars, i + 2) {
                let bold: String = chars[i + 2..end].iter().collect();
                let _ = write!(out, "<strong>{}</strong>", escape_html(&bold));
                i = end + 2;
                continue;
            }
        }
        if ch == '[' {
            if let Some(close) = find_char(&chars, i + 1, ']') {
                if close + 1 < chars.len() && chars[close + 1] == '(' {
                    if let Some(paren) = find_char(&chars, close + 2, ')') {
                        let label: String = chars[i + 1..close].iter().collect();
                        let target: String = chars[close + 2..paren].iter().collect();
                        let target = match target.strip_suffix(".md") {
                            Some(stem) => format!("{stem}.html"),
                            None => target,
                        };
                        let _ = write!(
                            out,
                            "<a href=\"{}\">{}</a>",
                            escape_html(&target),
                            escape_html(&label)
                        );
                        i = paren + 1;
                        continue;
                    }
                }
            }
        }
        out.push_str(&escape_char(ch));
        i += 1;
    }
    out
}

fn find_char(chars: &[char], from: usize, needle: char) -> Option<usize> {
    (from..chars.len()).find(|&i| chars[i] == needle)
}

fn find_pair(chars: &[char], from: usize) -> Option<usize> {
    (from..chars.len().saturating_sub(1)).find(|&i| chars[i] == '*' && chars[i + 1] == '*')
}

fn escape_char(ch: char) -> String {
    match ch {
        '&' => "&amp;".to_string(),
        '<' => "&lt;".to_string(),
        '>' => "&gt;".to_string(),
        '"' => "&quot;".to_string(),
        other => other.to_string(),
    }
}

fn escape_html(text: &str) -> String {
    text.chars().map(escape_char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ComObject, Device, Link};

    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("test group address parses")
    }

    fn named(address: &str, name: &str) -> GroupRef {
        GroupRef {
            address: address.to_string(),
            name: Some(name.to_string()),
        }
    }

    #[test]
    fn test_sentence_send_and_status() {
        let send = named("1/0/10", "Kitchen ceiling light");
        let listen = vec![GroupRef {
            address: "1/0/12".to_string(),
            name: None,
        }];
        let s = sentence(
            "Rocker 1",
            Some(crate::dpt::Dpt::new(1, Some(1))),
            Some(&send),
            &listen,
        );
        assert_eq!(
            s,
            "Rocker 1 switches Kitchen ceiling light (1/0/10); status from 1/0/12."
        );
    }

    #[test]
    fn test_sentence_listen_only_and_unlinked() {
        let listen = vec![named("1/0/10", "Kitchen ceiling light")];
        assert_eq!(
            sentence(
                "Relay A",
                Some(crate::dpt::Dpt::new(1, None)),
                None,
                &listen
            ),
            "Relay A follows Kitchen ceiling light (1/0/10)."
        );
        assert_eq!(
            sentence("Relay B", None, None, &[]),
            "Relay B is not linked to a group address."
        );
    }

    #[test]
    fn test_slug_filename_safe() {
        assert_eq!(slug("EG"), "eg");
        assert_eq!(slug("Wohnzimmer / Küche"), "wohnzimmer-k-che");
        assert_eq!(slug("!!!"), "unnamed");
    }

    #[test]
    fn test_markdown_to_html_table_and_list() {
        let md = "# Title\n\nSome text.\n\n| A | B |\n| --- | --- |\n| 1 | 2 |\n\n- one\n- two\n";
        let html = markdown_to_html(md);
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<p>Some text.</p>"));
        assert!(html.contains("<th>A</th>"));
        assert!(html.contains("<td>2</td>"));
        assert!(html.contains("<li>one</li>"));
    }

    #[test]
    fn test_inline_rewrites_md_links_to_html() {
        assert_eq!(
            inline("see [Devices](devices.md)"),
            "see <a href=\"devices.html\">Devices</a>"
        );
        assert_eq!(inline("a < b & c"), "a &lt; b &amp; c");
    }

    #[test]
    fn test_object_doc_degrades_to_addresses() -> Result<(), Box<dyn std::error::Error>> {
        let link = Link {
            object: 3,
            name: None,
            send: Some(ga("1/0/10")),
            listen: Vec::new(),
        };
        let com = ComObject {
            dpt: Some("1.001".parse()?),
            ..Default::default()
        };
        let doc = object_doc(3, Some(&com), Some(&link), &BTreeMap::new());
        assert_eq!(doc.name, "com object 3");
        assert_eq!(doc.sentence, "com object 3 switches 1/0/10.");
        Ok(())
    }

    #[test]
    fn test_room_docs_skip_devices_without_location() {
        let mut device = DeviceDoc {
            address: "1.1.1".to_string(),
            name: "Button".to_string(),
            description: None,
            floor: None,
            room: None,
            manufacturer: None,
            order_number: None,
            application: None,
            mask: None,
            secure: "no".to_string(),
            channels: Vec::new(),
            other_objects: Vec::new(),
            parameters: Vec::new(),
        };
        assert!(room_docs(std::slice::from_ref(&device)).is_empty());
        device.room = Some("Küche".to_string());
        let rooms = room_docs(std::slice::from_ref(&device));
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].slug, "unassigned-k-che");
        assert_eq!(rooms[0].floor, "unassigned");
    }

    #[test]
    fn test_device_doc_groups_objects_by_channel() -> Result<(), Box<dyn std::error::Error>> {
        let mut device = Device {
            address: "1.1.1".parse()?,
            name: "Push button".to_string(),
            description: None,
            location: None,
            product: None,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects: BTreeMap::new(),
            security: None,
        };
        device.channels.insert(
            "ch1".to_string(),
            crate::schema::Channel {
                name: "Rocker 1".to_string(),
            },
        );
        device.com_objects.insert(
            1,
            ComObject {
                dpt: Some("1.001".parse()?),
                channel: Some("ch1".to_string()),
                ..Default::default()
            },
        );
        device.com_objects.insert(2, ComObject::default());

        let mut model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: BTreeMap::new(),
        };
        model.links.links.insert(
            device.address,
            vec![Link {
                object: 1,
                name: Some("Rocker 1 left".to_string()),
                send: Some(ga("1/0/10")),
                listen: Vec::new(),
            }],
        );

        let doc = device_doc(&model, &ProductModels::default(), &BTreeMap::new(), &device);
        assert_eq!(doc.channels.len(), 1);
        assert_eq!(doc.channels[0].name, "Rocker 1");
        assert_eq!(doc.channels[0].objects.len(), 1);
        assert_eq!(doc.channels[0].objects[0].name, "Rocker 1 left");
        assert_eq!(doc.other_objects.len(), 1);
        Ok(())
    }
}
