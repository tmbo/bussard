//! The read-only views of the project the chat asks for (issue #904):
//! `knx_project_summary`, `knx_model_lookup`, `knx_get_group` and
//! `knx_get_device`, one `Serialize` struct each.

use std::collections::BTreeMap;

use bussard_model::capabilities::Capability;
use bussard_model::{GroupAddress, IndividualAddress, Model, ProductModels, Severity};
use serde::Serialize;
use serde_json::Value;

use crate::report::Report;

/// A room and how many devices it has.
#[derive(Debug, Clone, Serialize)]
pub struct RoomCount {
    /// The floor.
    pub floor: String,
    /// The room.
    pub room: String,
    /// Devices there.
    pub device_count: usize,
}

/// A group-address main range and its name.
#[derive(Debug, Clone, Serialize)]
pub struct MainRange {
    /// The main group.
    pub main: String,
    /// Its name.
    pub name: String,
}

/// The project's counts.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectCounts {
    /// Devices.
    pub devices: usize,
    /// Group addresses.
    pub group_addresses: usize,
    /// Links.
    pub links: usize,
}

/// The project's validation counts.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationCounts {
    /// Errors.
    pub errors: usize,
    /// Warnings.
    pub warnings: usize,
}

/// `knx_project_summary`: the project at a glance.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectSummary {
    /// The project's name.
    pub project: Option<String>,
    /// Where it was imported from.
    pub imported_from: Option<String>,
    /// The counts.
    pub counts: ProjectCounts,
    /// The rooms and their device counts.
    pub rooms: Vec<RoomCount>,
    /// The group-address main ranges.
    pub ga_main_ranges: Vec<MainRange>,
    /// The bus connection as the server reports it.
    pub bus: Value,
    /// The validation counts.
    pub validation: ValidationCounts,
    /// What the server may do, by tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<Value>,
    /// What the assistant may do here, in one paragraph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<String>,
}

impl ProjectSummary {
    /// The summary of `model`, with the bus status `bus`.
    pub fn of(model: &Model, bus: Value) -> ProjectSummary {
        let mut locations: BTreeMap<(String, String), usize> = BTreeMap::new();
        for loaded in model.devices.values() {
            if let Some(loc) = &loaded.device.location {
                let floor = loc.floor.clone().unwrap_or_default();
                let room = loc.room.clone().unwrap_or_default();
                if !floor.is_empty() || !room.is_empty() {
                    *locations.entry((floor, room)).or_insert(0) += 1;
                }
            }
        }
        let mut ga_main_ranges: Vec<MainRange> = model
            .groups
            .ranges
            .iter()
            .filter(|(k, _)| !k.contains('/'))
            .map(|(k, r)| MainRange {
                main: k.clone(),
                name: r.name.clone(),
            })
            .collect();
        ga_main_ranges.sort_by(|a, b| a.main.cmp(&b.main));
        let diags = bussard_model::validate(model);
        let count = |s: Severity| diags.iter().filter(|d| d.severity == s).count();
        ProjectSummary {
            project: model.groups.project.clone(),
            imported_from: model.groups.imported_from.clone(),
            counts: ProjectCounts {
                devices: model.devices.len(),
                group_addresses: model.groups.groups.len(),
                links: model.links.links.values().map(Vec::len).sum(),
            },
            rooms: locations
                .into_iter()
                .map(|((floor, room), device_count)| RoomCount {
                    floor,
                    room,
                    device_count,
                })
                .collect(),
            ga_main_ranges,
            bus,
            validation: ValidationCounts {
                errors: count(Severity::Error),
                warnings: count(Severity::Warning),
            },
            server: None,
            capabilities: None,
        }
    }
}

impl Report for ProjectSummary {
    const SCHEMA: u32 = 1;
}

/// A group address a lookup found.
#[derive(Debug, Clone, Serialize)]
pub struct GroupHit {
    /// The address.
    pub address: String,
    /// Its name.
    pub name: String,
    /// Its DPT.
    pub dpt: Option<String>,
}

/// A device a lookup found.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceHit {
    /// Its address.
    pub ia: String,
    /// Its name.
    pub name: String,
    /// Its floor.
    pub floor: String,
    /// Its room.
    pub room: String,
}

/// A com-object a lookup found.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectHit {
    /// Its device.
    pub device_ia: String,
    /// The device's name.
    pub device_name: Option<String>,
    /// Its channel's handle.
    pub channel: Option<String>,
    /// Its number.
    pub object: u16,
    /// Its key.
    pub key: Option<String>,
    /// Its link name.
    pub name: String,
    /// The vendor's text.
    pub text: Option<String>,
    /// The vendor's function text.
    pub function: Option<String>,
    /// The group addresses it is linked to.
    pub linked_gas: Vec<String>,
}

/// A channel a lookup found.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelHit {
    /// Its device.
    pub device_ia: String,
    /// The device's name.
    pub device_name: String,
    /// Its handle.
    pub channel: String,
    /// Its number.
    pub number: Option<u32>,
    /// The vendor's text.
    pub text: Option<String>,
    /// The user's name.
    pub name: String,
    /// Its com-objects.
    pub objects: Vec<u16>,
}

/// `knx_model_lookup`: what a search over the project found.
#[derive(Debug, Clone, Serialize)]
pub struct LookupReport {
    /// The search.
    pub query: String,
    /// Group addresses.
    pub groups: Vec<GroupHit>,
    /// Devices.
    pub devices: Vec<DeviceHit>,
    /// Com-objects.
    pub objects: Vec<ObjectHit>,
    /// Channels.
    pub channels: Vec<ChannelHit>,
    /// The functions the installed devices can provide.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<Capability>>,
}

impl Report for LookupReport {
    const SCHEMA: u32 = 1;
}

impl LookupReport {
    /// A case-insensitive substring search over group names and addresses,
    /// device names, addresses and rooms, com-objects and channels; at most
    /// `limit` hits per kind.
    pub fn search(model: &Model, query: &str, limit: usize) -> LookupReport {
        let q = query.to_lowercase();
        let hit = |s: &str| s.to_lowercase().contains(&q);
        let hit_opt = |s: Option<&str>| s.is_some_and(|s| !s.is_empty() && hit(s));

        let groups: Vec<GroupHit> = model
            .groups
            .groups
            .iter()
            .filter(|(ga, g)| hit(&g.name) || hit(&ga.to_string()))
            .take(limit)
            .map(|(ga, g)| GroupHit {
                address: ga.to_string(),
                name: g.name.clone(),
                dpt: g.dpt.map(|d| d.to_string()),
            })
            .collect();

        let devices: Vec<DeviceHit> = model
            .devices
            .iter()
            .map(|(ia, loaded)| {
                let dev = &loaded.device;
                let place = |f: fn(&bussard_model::schema::Location) -> Option<String>| {
                    dev.location.as_ref().and_then(f).unwrap_or_default()
                };
                DeviceHit {
                    ia: ia.to_string(),
                    name: dev.name.clone(),
                    floor: place(|l| l.floor.clone()),
                    room: place(|l| l.room.clone()),
                }
            })
            .filter(|d| hit(&d.name) || hit(&d.ia) || (!d.room.is_empty() && hit(&d.room)))
            .take(limit)
            .collect();

        let mut objects = Vec::new();
        let mut ias: Vec<&IndividualAddress> = model
            .devices
            .keys()
            .chain(model.links.links.keys())
            .collect();
        ias.sort();
        ias.dedup();
        'outer: for ia in ias {
            let device = model.devices.get(ia).map(|d| &d.device);
            let links = model.links.links.get(ia).map(Vec::as_slice).unwrap_or(&[]);
            let mut numbers: Vec<u16> = device
                .map(|d| d.com_objects.keys().copied().collect())
                .unwrap_or_default();
            numbers.extend(links.iter().map(|l| l.object));
            numbers.sort_unstable();
            numbers.dedup();
            for number in numbers {
                let co = device.and_then(|d| d.com_objects.get(&number));
                let link = links.iter().find(|l| l.object == number);
                let name = link.and_then(|l| l.name.as_deref());
                let text = co.and_then(|c| c.text.as_deref());
                let function = co.and_then(|c| c.function.as_deref());
                let key = co.and_then(|c| c.key.as_deref());
                if !(hit_opt(name) || hit_opt(text) || hit_opt(function) || hit_opt(key)) {
                    continue;
                }
                if objects.len() >= limit {
                    break 'outer;
                }
                let mut linked: Vec<String> = Vec::new();
                if let Some(link) = link {
                    if let Some(send) = &link.send {
                        linked.push(send.to_string());
                    }
                    linked.extend(link.listen.iter().map(ToString::to_string));
                }
                objects.push(ObjectHit {
                    device_ia: ia.to_string(),
                    device_name: device.map(|d| d.name.clone()),
                    channel: co
                        .and_then(|c| c.channel.as_deref())
                        .zip(device)
                        .map(|(id, d)| d.channel_handle(id)),
                    object: number,
                    key: key.map(str::to_string),
                    name: name.unwrap_or_default().to_string(),
                    text: text.map(str::to_string),
                    function: function.map(str::to_string),
                    linked_gas: linked,
                });
            }
        }

        let mut channels = Vec::new();
        'channels: for (ia, loaded) in &model.devices {
            let dev = &loaded.device;
            for (id, ch) in &dev.channels {
                let handle = dev.channel_handle(id);
                if !(hit_opt(ch.text.as_deref()) || hit_opt(Some(&ch.name)) || hit(&handle)) {
                    continue;
                }
                if channels.len() >= limit {
                    break 'channels;
                }
                channels.push(ChannelHit {
                    device_ia: ia.to_string(),
                    device_name: dev.name.clone(),
                    channel: handle,
                    number: ch.number,
                    text: ch.text.clone(),
                    name: ch.name.clone(),
                    objects: dev
                        .com_objects
                        .iter()
                        .filter(|(_, o)| o.channel.as_deref() == Some(id.as_str()))
                        .map(|(n, _)| *n)
                        .collect(),
                });
            }
        }

        LookupReport {
            query: query.to_string(),
            groups,
            devices,
            objects,
            channels,
            capabilities: None,
        }
    }
}

/// A group address as the project names it.
#[derive(Debug, Clone, Serialize)]
pub struct GroupFacts {
    /// Its name.
    pub name: String,
    /// Its DPT.
    pub dpt: Option<String>,
    /// Its description.
    pub description: Option<String>,
}

/// A link to a group address.
#[derive(Debug, Clone, Serialize)]
pub struct GroupLink {
    /// The device.
    pub device_ia: String,
    /// Its name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// The com-object.
    pub object: u16,
    /// Its link name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_name: Option<String>,
    /// `send` or `listen`.
    pub role: &'static str,
    /// The device's room (the homeowner's view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// The com-object in words (the homeowner's view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

/// `knx_get_group`: one group address, its links and its last telegram.
#[derive(Debug, Clone, Serialize)]
pub struct GroupView {
    /// The address.
    pub address: String,
    /// Whether the project has it.
    pub found: bool,
    /// What the project says about it.
    pub group: Option<GroupFacts>,
    /// Every link to it.
    pub links: Vec<GroupLink>,
    /// The last telegram seen on it, as `monitor --json` prints it.
    pub last_telegram: Option<Value>,
}

impl Report for GroupView {
    const SCHEMA: u32 = 1;
}

impl GroupView {
    /// The homeowner's view: each link with the device's room and the
    /// object in words, and the last telegram without its wire detail.
    pub fn plain(mut self, model: &Model) -> GroupView {
        for link in &mut self.links {
            if let Ok(ia) = link.device_ia.parse::<IndividualAddress>() {
                link.room = crate::report::room_of(model, ia);
                link.what = Some(crate::report::object_phrase(model, ia, link.object));
            }
        }
        if let Some(Value::Object(last)) = self.last_telegram.as_mut() {
            for key in [
                "apci",
                "payload",
                "dest_type",
                "secure_seq",
                "secure_raw",
                "secure_status",
            ] {
                last.remove(key);
            }
            last.retain(|_, v| match v {
                Value::Null => false,
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => !a.is_empty(),
                _ => true,
            });
        }
        self
    }

    /// `ga` in `model`, with the last telegram `last`.
    pub fn of(model: &Model, ga: GroupAddress, last: Option<Value>) -> GroupView {
        let group = model.groups.groups.get(&ga);
        let mut links = Vec::new();
        for (ia, dev_links) in &model.links.links {
            let dev = model.devices.get(ia);
            for link in dev_links {
                let sends = link.send == Some(ga);
                if !sends && !link.listen.contains(&ga) {
                    continue;
                }
                links.push(GroupLink {
                    device_ia: ia.to_string(),
                    device_name: dev.map(|d| d.device.name.clone()),
                    object: link.object,
                    object_name: link.name.clone(),
                    role: if sends { "send" } else { "listen" },
                    room: None,
                    what: None,
                });
            }
        }
        GroupView {
            address: ga.to_string(),
            found: group.is_some(),
            group: group.map(|g| GroupFacts {
                name: g.name.clone(),
                dpt: g.dpt.map(|d| d.to_string()),
                description: g.description.clone(),
            }),
            links,
            last_telegram: last,
        }
    }
}

/// One link of a device.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceLink {
    /// The com-object.
    pub object: u16,
    /// The link name.
    pub name: Option<String>,
    /// The group address it sends to.
    pub send: Option<String>,
    /// The group addresses it listens to.
    pub listen: Vec<String>,
}

/// A calculation output with its computed value (issue #712).
#[derive(Debug, Clone, Serialize)]
pub struct ComputedParameter {
    /// The device-file key.
    pub key: String,
    /// The value a download writes.
    pub value: String,
    /// The calculation's id.
    pub computed_by: String,
}

/// `knx_get_device`: one device file and its links.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    /// The address.
    pub address: String,
    /// Whether the project has it.
    pub found: bool,
    /// The device file's stem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_stem: Option<String>,
    /// The device as the file holds it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<Value>,
    /// ETS-internal parameters left out (or counted, with `technical`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden_parameters: Option<usize>,
    /// The links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<DeviceLink>>,
    /// The calculation outputs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub computed_parameters: Vec<ComputedParameter>,
}

impl Report for DeviceInfo {
    const SCHEMA: u32 = 1;
}

/// Whether a device-file parameter key is an ETS-internal value the device
/// file does not show.
fn technical_param_key(key: &str) -> bool {
    bussard_model::is_hidden_mem_key(key) || key.starts_with(&bussard_model::label_mem_key(""))
}

impl DeviceInfo {
    /// Device `ia` of `model`; without `technical` the ETS-internal
    /// parameters are left out.
    pub fn of(
        model: &Model,
        products: &ProductModels,
        ia: IndividualAddress,
        technical: bool,
    ) -> DeviceInfo {
        let Some(loaded) = model.devices.get(&ia) else {
            return DeviceInfo {
                address: ia.to_string(),
                found: false,
                file_stem: None,
                device: None,
                hidden_parameters: None,
                links: None,
                computed_parameters: Vec::new(),
            };
        };
        let dev = &loaded.device;
        let mut device_value = serde_json::to_value(dev).unwrap_or_default();
        let mut hidden = 0usize;
        if let Some(params) = device_value
            .get_mut("parameters")
            .and_then(Value::as_object_mut)
        {
            let before = params.len();
            if !technical {
                params.retain(|k, _| !technical_param_key(k));
            }
            hidden = if technical {
                params.keys().filter(|k| technical_param_key(k)).count()
            } else {
                before - params.len()
            };
        }
        let links = model
            .links
            .links
            .get(&ia)
            .map(|dev_links| {
                dev_links
                    .iter()
                    .map(|link| DeviceLink {
                        object: link.object,
                        name: link.name.clone(),
                        send: link.send.map(|g| g.to_string()),
                        listen: link.listen.iter().map(ToString::to_string).collect(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        DeviceInfo {
            address: ia.to_string(),
            found: true,
            file_stem: Some(loaded.file_stem.clone()),
            device: Some(device_value),
            hidden_parameters: Some(hidden),
            links: Some(links),
            computed_parameters: computed(dev, products, technical),
        }
    }
}

/// The calculation outputs of `device` with their computed values.
fn computed(
    device: &bussard_model::schema::Device,
    products: &ProductModels,
    technical: bool,
) -> Vec<ComputedParameter> {
    let Some(product) = device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref())
        .and_then(|app| products.get(app))
        .filter(|p| !p.calculations.is_empty())
    else {
        return Vec::new();
    };
    bussard_model::device_view::Evaluated::of_device(product, device)
        .computed_parameters()
        .into_iter()
        .map(|(reference, (calc, value))| {
            let key = match device.lock.parameters.get(&reference) {
                Some(locked) if locked.key.contains('@') => locked.key.clone(),
                Some(locked) => format!("{}@{reference}", locked.key),
                None => reference,
            };
            ComputedParameter {
                key,
                value,
                computed_by: calc,
            }
        })
        .filter(|c| technical || !technical_param_key(&c.key))
        .collect()
}
