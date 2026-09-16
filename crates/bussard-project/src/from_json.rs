//! The `--from-json` escape hatch: build a [`Model`] from an `xknxproject`
//! JSON dump.
//!
//! This is both a convenience (import without the encrypted archive) and the
//! shape the test oracle uses. Only the fields the model needs are read; the
//! dump's many other fields are ignored.

use std::collections::BTreeMap;

use serde::Deserialize;

use bussard_model::loader::{LoadedDevice, Model};
use bussard_model::schema::{
    BussardConfig, ComObject, Device, Group, Groups, Link, Links, Product, Range,
};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress};

use crate::error::{ImportError, Result};

/// The subset of an xknxproject dump we consume.
#[derive(Debug, Deserialize)]
struct Dump {
    #[serde(default)]
    info: Info,
    #[serde(default)]
    group_addresses: BTreeMap<String, JsonGroupAddress>,
    #[serde(default)]
    group_ranges: BTreeMap<String, JsonRange>,
    #[serde(default)]
    devices: BTreeMap<String, JsonDevice>,
    #[serde(default)]
    communication_objects: BTreeMap<String, JsonComObject>,
}

#[derive(Debug, Default, Deserialize)]
struct Info {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JsonGroupAddress {
    name: String,
    address: String,
    #[serde(default)]
    dpt: Option<JsonDpt>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JsonRange {
    name: String,
    #[serde(default)]
    group_ranges: BTreeMap<String, JsonRange>,
}

#[derive(Debug, Deserialize)]
struct JsonDpt {
    main: u16,
    #[serde(default)]
    sub: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct JsonDevice {
    name: String,
    individual_address: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    manufacturer_name: Option<String>,
    #[serde(default)]
    order_number: Option<String>,
    #[serde(default)]
    application: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JsonComObject {
    number: u16,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    name: Option<String>,
    device_address: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    dpts: Vec<JsonDpt>,
    #[serde(default)]
    object_size: Option<String>,
    #[serde(default)]
    flags: JsonFlags,
    #[serde(default)]
    group_address_links: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct JsonFlags {
    #[serde(default)]
    read: bool,
    #[serde(default)]
    write: bool,
    #[serde(default)]
    communication: bool,
    #[serde(default)]
    update: bool,
    #[serde(default)]
    read_on_init: bool,
    #[serde(default)]
    transmit: bool,
}

impl JsonFlags {
    fn to_flags(&self) -> Flags {
        let mut f = Flags::empty();
        if self.communication {
            f |= Flags::COMMUNICATION;
        }
        if self.read {
            f |= Flags::READ;
        }
        if self.write {
            f |= Flags::WRITE;
        }
        if self.transmit {
            f |= Flags::TRANSMIT;
        }
        if self.update {
            f |= Flags::UPDATE;
        }
        if self.read_on_init {
            f |= Flags::INIT;
        }
        f
    }
}

impl JsonDpt {
    fn to_dpt(&self) -> Dpt {
        Dpt::new(self.main, self.sub)
    }
}

/// Builds a [`Model`] from an xknxproject JSON dump string.
pub fn model_from_json(json: &str) -> Result<Model> {
    let dump: Dump = serde_json::from_str(json).map_err(|source| ImportError::Json {
        path: "<json>".into(),
        source,
    })?;

    // Group addresses.
    let mut group_map: BTreeMap<GroupAddress, Group> = BTreeMap::new();
    for ga in dump.group_addresses.values() {
        let address: GroupAddress = ga.address.parse().map_err(|e| ImportError::Malformed {
            context: "JSON group address".to_string(),
            message: format!("invalid GA {:?}: {e}", ga.address),
        })?;
        group_map.insert(
            address,
            Group {
                name: ga.name.clone(),
                dpt: ga.dpt.as_ref().map(JsonDpt::to_dpt),
                description: ga.description.clone().filter(|s| !s.is_empty()),
                ..Default::default()
            },
        );
    }

    // Ranges (flattened from the two-level tree).
    let mut ranges: BTreeMap<String, Range> = BTreeMap::new();
    for (key, r) in &dump.group_ranges {
        ranges.insert(
            key.clone(),
            Range {
                name: r.name.clone(),
            },
        );
        for (subkey, sr) in &r.group_ranges {
            ranges.insert(
                subkey.clone(),
                Range {
                    name: sr.name.clone(),
                },
            );
        }
    }

    // Devices.
    let mut devices: BTreeMap<IndividualAddress, LoadedDevice> = BTreeMap::new();
    let mut links: BTreeMap<IndividualAddress, Vec<Link>> = BTreeMap::new();

    for dev in dump.devices.values() {
        let address: IndividualAddress =
            dev.individual_address
                .parse()
                .map_err(|e| ImportError::Malformed {
                    context: "JSON device".to_string(),
                    message: format!("invalid IA {:?}: {e}", dev.individual_address),
                })?;

        let product = build_product(dev);
        let device = Device {
            address,
            name: dev.name.clone(),
            description: dev.description.clone().filter(|s| !s.is_empty()),
            location: None,
            product,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            // The JSON (xknxproject) path carries no ModuleInstance base data.
            module_bases: BTreeMap::new(),
            com_objects: BTreeMap::new(),
        };
        let file_stem = format!("{address}-{}", crate::build::slugify(&device.name));
        devices.insert(address, LoadedDevice { device, file_stem });
        links.insert(address, Vec::new());
    }

    // Com-objects → per-device com_objects table + links.
    for co in dump.communication_objects.values() {
        let address: IndividualAddress =
            co.device_address
                .parse()
                .map_err(|e| ImportError::Malformed {
                    context: "JSON com object".to_string(),
                    message: format!("invalid device IA {:?}: {e}", co.device_address),
                })?;

        let dpt = co.dpts.first().map(JsonDpt::to_dpt);
        let name = co
            .text
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| co.name.clone().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| format!("Object {}", co.number));

        // Resolve link GAs (they are already 3-level strings).
        let mut gas: Vec<GroupAddress> = Vec::new();
        for link in &co.group_address_links {
            let ga: GroupAddress = link.parse().map_err(|e| ImportError::Malformed {
                context: "JSON com object link".to_string(),
                message: format!("invalid GA {link:?}: {e}"),
            })?;
            gas.push(ga);
        }

        if let Some(dev) = devices.get_mut(&address) {
            // Size is derived from the DPT on demand; only stored when there is
            // no DPT at all, normalized to lowercase (issue #17). The name lives
            // in links.yaml only (issue #19), not on the com-object.
            let size = match dpt {
                Some(_) => None,
                None => co
                    .object_size
                    .as_deref()
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty()),
            };
            dev.device.com_objects.insert(
                co.number,
                ComObject {
                    dpt,
                    size,
                    flags: co.flags.to_flags(),
                    reference: None,
                    channel: co.channel.clone().filter(|s| !s.is_empty()),
                },
            );
        }

        if !gas.is_empty() {
            // Only a transmit-capable object gets a `send` GA; otherwise all of
            // its GAs are `listen` (consistent with validation rule E007).
            let (send, listen) = if co.flags.transmit {
                (Some(gas[0]), gas[1..].to_vec())
            } else {
                (None, gas.clone())
            };
            let entry = links.entry(address).or_default();
            entry.push(Link {
                object: co.number,
                name: Some(name),
                send,
                listen,
            });
        }
    }

    // Sort and drop empty link lists.
    let links: BTreeMap<IndividualAddress, Vec<Link>> = links
        .into_iter()
        .filter_map(|(ia, mut v)| {
            if v.is_empty() {
                None
            } else {
                v.sort_by_key(|l| l.object);
                Some((ia, v))
            }
        })
        .collect();

    let groups = Groups {
        project: dump.info.name.clone(),
        imported_from: None,
        ranges,
        groups: group_map,
    };

    Ok(Model {
        config: BussardConfig::default(),
        groups,
        links: Links { links },
        devices,
    })
}

fn build_product(dev: &JsonDevice) -> Option<Product> {
    let manufacturer_ref = dev
        .application
        .as_deref()
        .and_then(|a| a.split('_').next())
        .map(str::to_string);
    let p = Product {
        manufacturer: dev.manufacturer_name.clone().filter(|s| !s.is_empty()),
        manufacturer_ref,
        order_number: dev.order_number.clone().filter(|s| !s.is_empty()),
        hardware_ref: None,
        application_ref: dev.application.clone().filter(|s| !s.is_empty()),
        mask: None,
    };
    if p.manufacturer.is_none()
        && p.manufacturer_ref.is_none()
        && p.order_number.is_none()
        && p.application_ref.is_none()
    {
        None
    } else {
        Some(p)
    }
}
