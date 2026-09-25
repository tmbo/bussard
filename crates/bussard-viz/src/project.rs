//! The pure `Model` -> JSON projection served at `GET /api/model`.
//!
//! This module is deliberately free of any I/O, async, or bus state: it takes a
//! loaded [`Model`] and produces the canonical JSON contract the frontend builds
//! against (see the crate docs). The projection is computed once per process (the
//! model is immutable for the server's lifetime) and cached in the app state.
//!
//! ## Contract highlights
//!
//! * `com_objects` on a device is the **union** of the device's own
//!   `com_objects` map keys and the object numbers appearing in that device's
//!   device-file links. A link-only object (present in links but not in the
//!   device's com-object table) is emitted with `null` `dpt`/`flags`.
//! * A group address that appears **only** in links (never declared in
//!   `groups.toml`) is synthesized into `groups` with `name: null`, so the
//!   frontend's problems panel can surface it.
//! * `senders`/`listeners` on a group are derived from the links: a device is a
//!   sender of `ga` if one of its objects has `send == ga`, and a listener if
//!   `ga` is in that object's `listen` list.
//! * KNX Data Secure, read-only (issue #205): a device carries its model
//!   `security` block (`activated`, `secure_commissioning`, `secure_capable`,
//!   `has_fdsk_certificate`; `null` without one), a group its `secure` flag,
//!   and a com-object `secure` when it is marked secure or linked to a secure
//!   group. Flags only: the model holds no key material.
//! * Parameter values (issue #259), read-only: each channel carries the
//!   `parameters` the device file sets in it, and the device carries its
//!   device-level ones. A row has the file `key`, the vendor `text`, the
//!   `value` (the choice label for an enumeration, when the product model
//!   has one), the vendor `default` and `non_default`. The rows come from
//!   [`bussard_model::device_view`], the same data `bussard device` prints;
//!   without the product model (`.bussard/models/<application>.yaml`) `text`,
//!   `default` and `non_default` are `null`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use bussard_model::device_view::{DEVICE_SCOPE, ParamRow, device_view};
use bussard_model::schema::{ComObject, Device, Link};
use bussard_model::{
    GroupAddress, IndividualAddress, Model, ProductModels, is_hidden_mem_key, label_mem_key,
};
use serde_json::{Value, json};

/// Builds the canonical `/api/model` JSON projection from a loaded model.
///
/// The result is a single JSON object with the keys `project`, `stats`,
/// `ranges`, `devices`, `groups` and `analysis`, exactly as documented in the
/// frontend contract. `analysis` is [`bussard_model::analyze`]'s output (the
/// Problems panel's findings and neutral info). See the module docs for the
/// projection rules.
pub fn project_model(model: &Model) -> Value {
    project_model_with(model, &ProductModels::default())
}

/// The product models the devices of `model` pin, read from the model
/// directory `dir` (`.bussard/models/<application>.yaml`). Missing or
/// unreadable files are simply absent. `import-product` writes these files in
/// the lock's language, so their texts and choice labels match the device
/// files.
pub fn product_models_for(model: &Model, dir: &Path) -> ProductModels {
    let apps: BTreeSet<String> = model
        .devices
        .values()
        .filter_map(|d| d.device.product.as_ref()?.application_ref.clone())
        .collect();
    ProductModels::load_apps(dir, apps.iter().map(String::as_str))
}

/// [`project_model`] with the vendor texts, choice labels and defaults of
/// `products` joined onto the parameter values.
pub fn project_model_with(model: &Model, products: &ProductModels) -> Value {
    let ranges = project_ranges(model);
    let devices = project_devices(model, products);
    let groups = project_groups(model);

    let link_count: usize = model.links.links.values().map(Vec::len).sum();

    // The Problems panel renders this rather than recomputing it in the
    // browser, so `bussard audit` and viz share one analysis code path.
    let analysis = serde_json::to_value(bussard_model::analyze(model)).unwrap_or(Value::Null);

    json!({
        "project": model.groups.project,
        "stats": {
            "devices": model.devices.len(),
            "groups": model.groups.groups.len(),
            "links": link_count,
        },
        "ranges": ranges,
        "devices": devices,
        "groups": groups,
        "analysis": analysis,
    })
}

/// Projects the named ranges (`groups.toml` `ranges:`) into a stable array.
///
/// Each entry carries the raw `key` (`"3"` or `"3/2"`), the parsed `main` and
/// optional `middle` numbers, and the `name`. Keys that are neither a bare main
/// nor a `main/middle` pair are skipped (the model never emits them).
fn project_ranges(model: &Model) -> Vec<Value> {
    model
        .groups
        .ranges
        .iter()
        .filter_map(|(key, range)| {
            let (main, middle) = parse_range_key(key)?;
            Some(json!({
                "key": key,
                "main": main,
                "middle": middle,
                "name": range.name,
            }))
        })
        .collect()
}

/// Parses a range key of the form `"3"` (main only) or `"3/2"` (main/middle).
///
/// Returns `(main, Some(middle))` for a two-part key and `(main, None)` for a
/// one-part key. Anything else yields `None`.
fn parse_range_key(key: &str) -> Option<(u8, Option<u8>)> {
    let mut parts = key.split('/');
    let main = parts.next()?.parse::<u8>().ok()?;
    match parts.next() {
        None => Some((main, None)),
        Some(mid) => {
            let middle = mid.parse::<u8>().ok()?;
            // A well-formed key has at most two parts.
            if parts.next().is_some() {
                return None;
            }
            Some((main, Some(middle)))
        }
    }
}

/// Projects every device, in address order, with its channels and com-objects.
fn project_devices(model: &Model, products: &ProductModels) -> Vec<Value> {
    model
        .devices
        .iter()
        .map(|(addr, loaded)| project_device(model, products, *addr, &loaded.device))
        .collect()
}

/// The parameter rows of one scope of a device: a channel id, or `None` for
/// the device level. The channel's label parameter (its value is the channel
/// name) and hidden values (never shown in ETS) are left out.
fn project_parameters(
    model: &Model,
    products: &ProductModels,
    addr: IndividualAddress,
    channel: Option<&str>,
) -> Vec<Value> {
    let scope = channel.unwrap_or(DEVICE_SCOPE);
    let Ok(view) = device_view(model, products, addr, Some(scope)) else {
        return Vec::new();
    };
    let Some(scope) = view.scope else {
        return Vec::new();
    };
    scope
        .parameters
        .iter()
        .filter(|p| !is_hidden_mem_key(&p.key) && p.key != label_mem_key(&p.reference))
        .map(project_parameter)
        .collect()
}

/// One parameter row as the inspector shows it.
fn project_parameter(p: &ParamRow) -> Value {
    json!({
        "key": p.key,
        "text": p.text,
        "value": p.value,
        "default": p.default,
        "non_default": p.at_default.map(|d| !d),
    })
}

/// Projects a single device: identity, location, product, channels, and the
/// union com-object list.
fn project_device(
    model: &Model,
    products: &ProductModels,
    addr: IndividualAddress,
    device: &Device,
) -> Value {
    let channels: Vec<Value> = device
        .channels
        .iter()
        .map(|(key, channel)| {
            json!({
                "key": key,
                "name": channel.name,
                "parameters": project_parameters(model, products, addr, Some(key)),
            })
        })
        .collect();
    let parameters = project_parameters(model, products, addr, None);

    let product = device.product.as_ref().and_then(|p| {
        // Emit product only when there is at least a manufacturer or order
        // number to show; a fully-empty product block projects to null.
        if p.manufacturer.is_none() && p.order_number.is_none() {
            None
        } else {
            Some(json!({
                "manufacturer": p.manufacturer,
                "order_number": p.order_number,
            }))
        }
    });

    let (floor, room) = match &device.location {
        Some(loc) => (loc.floor.clone(), loc.room.clone()),
        None => (None, None),
    };

    let com_objects = project_com_objects(model, addr, device);

    // KNX Data Secure (issue #205), read-only: the device's security state as
    // the model records it. Flags and counts only; the model holds no key.
    let security = device.security.as_ref().map(|s| {
        json!({
            "activated": s.activated,
            "secure_commissioning": s.secure_commissioning,
            "secure_capable": s.secure_capable,
            "has_fdsk_certificate": s.has_fdsk_certificate,
        })
    });

    json!({
        "address": addr.to_string(),
        "name": device.name,
        "description": device.description,
        "floor": floor,
        "room": room,
        "product": product,
        "security": security,
        "channels": channels,
        "parameters": parameters,
        "com_objects": com_objects,
    })
}

/// Projects a device's com-objects as the union of its own com-object table and
/// the object numbers referenced by its links (in its device file).
///
/// For each object number, `name`/`send`/`listen` come from the matching link
/// (the informational name lives only in links); `dpt`/`flags`/`channel` come
/// from the device's com-object table. A link-only object (no table entry) is
/// emitted with `null` `dpt`/`flags`/`channel`.
fn project_com_objects(model: &Model, addr: IndividualAddress, device: &Device) -> Vec<Value> {
    let links: &[Link] = model
        .links
        .links
        .get(&addr)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    // The union of object numbers from both sources, deduplicated and ordered.
    let mut numbers: BTreeSet<u16> = device.com_objects.keys().copied().collect();
    for link in links {
        numbers.insert(link.object);
    }

    numbers
        .into_iter()
        .map(|number| {
            let com: Option<&ComObject> = device.com_objects.get(&number);
            let link: Option<&Link> = links.iter().find(|l| l.object == number);

            // Name: prefer the link's informational name, then fall back to the
            // owning channel's name, then the device name.
            let name = link
                .and_then(|l| l.name.clone())
                .or_else(|| {
                    com.and_then(|c| c.channel.as_ref())
                        .and_then(|ch| device.channels.get(ch))
                        .map(|c| c.name.clone())
                })
                .or_else(|| Some(device.name.clone()));

            let dpt = com.and_then(|c| c.dpt).map(|d| d.to_string());
            let flags = com.map(|c| c.flags.to_string());
            // Secured: the object is marked secure, or one of its linked GAs is.
            let secure = com.is_some_and(|c| c.secure)
                || link.is_some_and(|l| {
                    l.send
                        .iter()
                        .chain(&l.listen)
                        .any(|ga| model.groups.groups.get(ga).is_some_and(|g| g.secure))
                });
            let channel = com.and_then(|c| c.channel.clone());
            let send = link.and_then(|l| l.send).map(|g| g.to_string());
            let listen: Vec<String> = link
                .map(|l| l.listen.iter().map(GroupAddress::to_string).collect())
                .unwrap_or_default();

            json!({
                "number": number,
                "name": name,
                "dpt": dpt,
                "flags": flags,
                "channel": channel,
                "send": send,
                "listen": listen,
                "secure": secure,
            })
        })
        .collect()
}

/// A sender or listener reference on a group address.
struct Endpoint {
    device: IndividualAddress,
    device_name: String,
    object: u16,
    object_name: Option<String>,
}

impl Endpoint {
    /// Projects the endpoint to its JSON object.
    fn to_json(&self) -> Value {
        json!({
            "device": self.device.to_string(),
            "device_name": self.device_name,
            "object": self.object,
            "object_name": self.object_name,
        })
    }
}

/// Projects every group address, including synthesized link-only GAs.
///
/// The output is ordered by group address. Declared groups (from `groups.toml`)
/// keep their `name`/`dpt`/`description`/`protected`; GAs that appear only in
/// links are synthesized with `name: null` and `protected: false`.
fn project_groups(model: &Model) -> Vec<Value> {
    // Build sender/listener indexes once by scanning every link.
    let mut senders: BTreeMap<GroupAddress, Vec<Endpoint>> = BTreeMap::new();
    let mut listeners: BTreeMap<GroupAddress, Vec<Endpoint>> = BTreeMap::new();

    for (addr, links) in &model.links.links {
        let device_name = model
            .devices
            .get(addr)
            .map(|d| d.device.name.clone())
            .unwrap_or_default();
        for link in links {
            if let Some(send) = link.send {
                senders.entry(send).or_default().push(Endpoint {
                    device: *addr,
                    device_name: device_name.clone(),
                    object: link.object,
                    object_name: link.name.clone(),
                });
            }
            for ga in &link.listen {
                listeners.entry(*ga).or_default().push(Endpoint {
                    device: *addr,
                    device_name: device_name.clone(),
                    object: link.object,
                    object_name: link.name.clone(),
                });
            }
        }
    }

    // The union of declared GAs and any GA that appears only in links.
    let mut addresses: BTreeSet<GroupAddress> = model.groups.groups.keys().copied().collect();
    addresses.extend(senders.keys().copied());
    addresses.extend(listeners.keys().copied());

    addresses
        .into_iter()
        .map(|ga| {
            let group = model.groups.groups.get(&ga);
            let name = group
                .map(|g| Value::from(g.name.clone()))
                .unwrap_or(Value::Null);
            let dpt = group
                .and_then(|g| g.dpt)
                .map(|d| Value::from(d.to_string()))
                .unwrap_or(Value::Null);
            let description = group
                .and_then(|g| g.description.clone())
                .map(Value::from)
                .unwrap_or(Value::Null);
            let protected = group.map(|g| g.protected).unwrap_or(false);
            let secure = group.is_some_and(|g| g.secure);

            let range_main = model
                .groups
                .ranges
                .get(&ga.main().to_string())
                .map(|r| Value::from(r.name.clone()))
                .unwrap_or(Value::Null);
            let range_middle = model
                .groups
                .ranges
                .get(&format!("{}/{}", ga.main(), ga.middle()))
                .map(|r| Value::from(r.name.clone()))
                .unwrap_or(Value::Null);

            let group_senders: Vec<Value> = senders
                .get(&ga)
                .map(|v| v.iter().map(Endpoint::to_json).collect())
                .unwrap_or_default();
            let group_listeners: Vec<Value> = listeners
                .get(&ga)
                .map(|v| v.iter().map(Endpoint::to_json).collect())
                .unwrap_or_default();

            json!({
                "address": ga.to_string(),
                "name": name,
                "dpt": dpt,
                "description": description,
                "protected": protected,
                "secure": secure,
                "main": ga.main(),
                "middle": ga.middle(),
                "sub": ga.sub(),
                "range": {
                    "main": range_main,
                    "middle": range_middle,
                },
                "senders": group_senders,
                "listeners": group_listeners,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::LoadedDevice;
    use bussard_model::schema::{
        BussardConfig, Channel, ComObject, Device, Group, Groups, Link, Links, Location, Product,
        Range,
    };

    fn ia(s: &str) -> IndividualAddress {
        s.parse().expect("valid IA")
    }
    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("valid GA")
    }

    /// A fixture model exercising every projection rule:
    /// * a declared GA `3/2/0` with a DPT and `protected`,
    /// * a device `1.1.30` with a com-object table entry (obj 3) and a link
    ///   (obj 3 sends `3/2/0`),
    /// * a link-only object (obj 9) whose `send` GA `4/0/0` is never declared in
    ///   groups.toml (must synthesize with name null),
    /// * a listener device `1.1.4` on `3/2/0`.
    fn fixture_model() -> Model {
        // Groups.
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/2/0"),
            Group {
                name: "Wind Alarm".to_string(),
                dpt: Some("1.005".parse().expect("dpt")),
                description: Some("wind alarm".to_string()),
                protected: true,
                secure: false,
            },
        );

        let mut ranges = BTreeMap::new();
        ranges.insert(
            "3".to_string(),
            Range {
                name: "Outdoor".to_string(),
            },
        );
        ranges.insert(
            "3/2".to_string(),
            Range {
                name: "Alarms".to_string(),
            },
        );

        // Device 1.1.30: sender.
        let mut ch = BTreeMap::new();
        ch.insert(
            "CH-1".to_string(),
            Channel {
                name: "Channel 1".to_string(),
                key: None,
                number: None,
                text: None,
            },
        );
        let mut com_objects = BTreeMap::new();
        com_objects.insert(
            3u16,
            ComObject {
                dpt: Some("1.005".parse().expect("dpt")),
                size: None,
                flags: "CWT".parse().expect("flags"),
                reference: None,
                channel: Some("CH-1".to_string()),
                secure: false,
                function: None,
                key: None,
                text: None,
            },
        );
        let sender = Device {
            address: ia("1.1.30"),
            name: "Weather Station".to_string(),
            description: None,
            location: Some(Location {
                floor: Some("Ground Floor".to_string()),
                room: Some("Utility Room".to_string()),
            }),
            replaced: None,
            product: Some(Product {
                manufacturer: Some("Meridian Sensors".to_string()),
                manufacturer_ref: None,
                order_number: Some("WS-3".to_string()),
                hardware_ref: None,
                application_ref: None,
                mask: None,
            }),
            channels: ch,
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects,
            security: None,
            application_override: None,
            lock: Default::default(),
        };

        // Device 1.1.4: listener, no product/location.
        let listener = Device {
            address: ia("1.1.4"),
            name: "Living Room Blind".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects: BTreeMap::new(),
            security: None,
            application_override: None,
            lock: Default::default(),
        };

        let mut devices = BTreeMap::new();
        devices.insert(
            ia("1.1.30"),
            LoadedDevice {
                device: sender,
                file_stem: "1.1.30-meteodata".to_string(),
            },
        );
        devices.insert(
            ia("1.1.4"),
            LoadedDevice {
                device: listener,
                file_stem: "1.1.4-jalousie".to_string(),
            },
        );

        // Links: 1.1.30 obj 3 sends 3/2/0; obj 9 (link-only) sends 4/0/0.
        // 1.1.4 obj 12 listens on 3/2/0.
        let mut links = BTreeMap::new();
        links.insert(
            ia("1.1.30"),
            vec![
                Link {
                    object: 3,
                    name: Some("Wind Alarm 1".to_string()),
                    send: Some(ga("3/2/0")),
                    listen: vec![],
                },
                Link {
                    object: 9,
                    name: Some("Undeclared out".to_string()),
                    send: Some(ga("4/0/0")),
                    listen: vec![],
                },
            ],
        );
        links.insert(
            ia("1.1.4"),
            vec![Link {
                object: 12,
                name: Some("Up/Down".to_string()),
                send: None,
                listen: vec![ga("3/2/0")],
            }],
        );

        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: Some("Home".to_string()),
                imported_from: None,
                ranges,
                groups,
            },
            links: Links { links },
            devices,
        }
    }

    #[test]
    fn test_project_model_stats() {
        let v = project_model(&fixture_model());
        assert_eq!(v["project"], "Home");
        assert_eq!(v["stats"]["devices"], 2);
        assert_eq!(v["stats"]["groups"], 1);
        // Three links total: two on 1.1.30, one on 1.1.4.
        assert_eq!(v["stats"]["links"], 3);
    }

    #[test]
    fn test_project_model_ranges() {
        let v = project_model(&fixture_model());
        let ranges = v["ranges"].as_array().expect("ranges array");
        // Ordered by BTreeMap key: "3" then "3/2".
        assert_eq!(ranges[0]["key"], "3");
        assert_eq!(ranges[0]["main"], 3);
        assert_eq!(ranges[0]["middle"], Value::Null);
        assert_eq!(ranges[0]["name"], "Outdoor");
        assert_eq!(ranges[1]["key"], "3/2");
        assert_eq!(ranges[1]["main"], 3);
        assert_eq!(ranges[1]["middle"], 2);
    }

    #[test]
    fn test_project_device_fields() {
        let v = project_model(&fixture_model());
        let devices = v["devices"].as_array().expect("devices array");
        // Ordered by IA: 1.1.4 then 1.1.30.
        let jalousie = &devices[0];
        assert_eq!(jalousie["address"], "1.1.4");
        assert_eq!(jalousie["floor"], Value::Null);
        assert_eq!(jalousie["room"], Value::Null);
        assert_eq!(jalousie["product"], Value::Null);

        let meteo = &devices[1];
        assert_eq!(meteo["address"], "1.1.30");
        assert_eq!(meteo["name"], "Weather Station");
        assert_eq!(meteo["floor"], "Ground Floor");
        assert_eq!(meteo["room"], "Utility Room");
        assert_eq!(meteo["product"]["manufacturer"], "Meridian Sensors");
        assert_eq!(meteo["product"]["order_number"], "WS-3");
        assert_eq!(meteo["channels"][0]["key"], "CH-1");
        assert_eq!(meteo["channels"][0]["name"], "Channel 1");
    }

    #[test]
    fn test_project_model_surfaces_data_secure_read_only() {
        let plain = project_model(&fixture_model());
        assert_eq!(plain["devices"][1]["security"], Value::Null);
        assert_eq!(plain["groups"][0]["secure"], false);

        let mut model = fixture_model();
        let ga_wind = ga("3/2/0");
        if let Some(group) = model.groups.groups.get_mut(&ga_wind) {
            group.secure = true;
        }
        if let Some(loaded) = model.devices.get_mut(&ia("1.1.30")) {
            loaded.device.security = Some(bussard_model::schema::DeviceSecurity {
                activated: true,
                secure_capable: true,
                sequence_number: Some(42),
                ..Default::default()
            });
        }
        let v = project_model(&model);
        let meteo = &v["devices"][1];
        assert_eq!(meteo["address"], "1.1.30");
        assert_eq!(meteo["security"]["activated"], true);
        assert_eq!(meteo["security"]["secure_capable"], true);
        assert_eq!(meteo["security"]["secure_commissioning"], false);
        // Flags only: no sequence number, nothing key-like.
        assert!(meteo["security"].get("sequence_number").is_none());
        let wind = v["groups"]
            .as_array()
            .and_then(|g| g.iter().find(|g| g["address"] == "3/2/0"))
            .cloned()
            .unwrap_or(Value::Null);
        assert_eq!(wind["secure"], true);
        // The com object linked to the secure GA is secured too.
        let secured: Vec<&Value> = meteo["com_objects"]
            .as_array()
            .map(|objs| objs.iter().filter(|o| o["secure"] == true).collect())
            .unwrap_or_default();
        assert!(!secured.is_empty(), "{meteo}");
    }

    #[test]
    fn test_project_com_objects_union_and_link_only() {
        let v = project_model(&fixture_model());
        let devices = v["devices"].as_array().expect("devices array");
        let meteo = &devices[1];
        let objs = meteo["com_objects"].as_array().expect("com_objects");
        // Union of table {3} and link objects {3, 9}, ordered => [3, 9].
        assert_eq!(objs.len(), 2);

        let obj3 = &objs[0];
        assert_eq!(obj3["number"], 3);
        assert_eq!(obj3["name"], "Wind Alarm 1");
        assert_eq!(obj3["dpt"], "1.005");
        assert_eq!(obj3["flags"], "CWT");
        assert_eq!(obj3["channel"], "CH-1");
        assert_eq!(obj3["send"], "3/2/0");
        assert!(obj3["listen"].as_array().expect("listen").is_empty());

        // Link-only object: null dpt/flags/channel, name from the link.
        let obj9 = &objs[1];
        assert_eq!(obj9["number"], 9);
        assert_eq!(obj9["name"], "Undeclared out");
        assert_eq!(obj9["dpt"], Value::Null);
        assert_eq!(obj9["flags"], Value::Null);
        assert_eq!(obj9["channel"], Value::Null);
        assert_eq!(obj9["send"], "4/0/0");
    }

    #[test]
    fn test_project_groups_declared_with_senders_listeners() {
        let v = project_model(&fixture_model());
        let groups = v["groups"].as_array().expect("groups array");
        // Ordered by GA: 3/2/0 then the synthesized 4/0/0.
        let g = &groups[0];
        assert_eq!(g["address"], "3/2/0");
        assert_eq!(g["name"], "Wind Alarm");
        assert_eq!(g["dpt"], "1.005");
        assert_eq!(g["description"], "wind alarm");
        assert_eq!(g["protected"], true);
        assert_eq!(g["main"], 3);
        assert_eq!(g["middle"], 2);
        assert_eq!(g["sub"], 0);
        assert_eq!(g["range"]["main"], "Outdoor");
        assert_eq!(g["range"]["middle"], "Alarms");

        let senders = g["senders"].as_array().expect("senders");
        assert_eq!(senders.len(), 1);
        assert_eq!(senders[0]["device"], "1.1.30");
        assert_eq!(senders[0]["device_name"], "Weather Station");
        assert_eq!(senders[0]["object"], 3);
        assert_eq!(senders[0]["object_name"], "Wind Alarm 1");

        let listeners = g["listeners"].as_array().expect("listeners");
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0]["device"], "1.1.4");
        assert_eq!(listeners[0]["object"], 12);
    }

    #[test]
    fn test_project_groups_synthesizes_link_only_ga() {
        let v = project_model(&fixture_model());
        let groups = v["groups"].as_array().expect("groups array");
        // 4/0/0 is referenced only by a link's `send`; it must be synthesized.
        let synth = groups
            .iter()
            .find(|g| g["address"] == "4/0/0")
            .expect("synthesized GA present");
        assert_eq!(synth["name"], Value::Null);
        assert_eq!(synth["dpt"], Value::Null);
        assert_eq!(synth["protected"], false);
        assert_eq!(synth["range"]["main"], Value::Null);
        // Its sender is 1.1.30 obj 9.
        assert_eq!(synth["senders"][0]["device"], "1.1.30");
        assert_eq!(synth["senders"][0]["object"], 9);
    }

    #[test]
    fn test_project_model_ships_the_shared_analysis() {
        let model = fixture_model();
        let json = project_model(&model);
        let expected =
            serde_json::to_value(bussard_model::analyze(&model)).expect("the analysis serializes");
        assert_eq!(json["analysis"], expected);
        // The frontend reads these exact keys.
        assert!(json["analysis"]["findings"].is_array());
        assert!(json["analysis"]["info"]["unlinked_com_objects"].is_number());
        assert!(json["analysis"]["info"]["unused_group_addresses"].is_number());
    }

    #[test]
    fn test_parse_range_key() {
        assert_eq!(parse_range_key("3"), Some((3, None)));
        assert_eq!(parse_range_key("3/2"), Some((3, Some(2))));
        assert_eq!(parse_range_key("3/2/1"), None);
        assert_eq!(parse_range_key("x"), None);
    }

    const PARAM_APP: &str = "M-00FA_A-0001-01-0001";

    /// A one-channel device with a device-level and a channel parameter, a
    /// channel label parameter and a hidden value, from texts.
    fn param_model() -> Result<Model, Box<dyn std::error::Error>> {
        let lock = format!(
            r#"version = 2

[[device]]
address = "1.1.9"
product = "BA-1"
application = "{PARAM_APP}"
channels = [
  {{ key = "k-1", id = "CH-1", text = "Kanal 1" }},
]
objects = [
  {{ number = 1, key = "fahren", channel = "k-1", dpt = "1.008", flags = "CW" }},
]
parameters = [
  {{ key = "sendeverzoegerung", ref = "P-1_R-1", param = "P-1" }},
  {{ key = "betriebsart", channel = "k-1", ref = "P-2_R-2", param = "P-2" }},
]
"#
        );
        let device = r#"address = "1.1.9"
name = "Blind"
product = "BA-1"

[parameters]
sendeverzoegerung = "10"

[channel.k-1]
name = "Wohnzimmer"
betriebsart = "Jalousie mit Lamellenverstellung"
fahren.listen = ["0/1/0"]
"#;
        let files: BTreeMap<String, String> = [
            ("bussard.lock".to_string(), lock),
            ("devices/1.1.9.toml".to_string(), device.to_string()),
        ]
        .into_iter()
        .collect();
        Ok(Model::from_texts(&files)?)
    }

    fn param_products() -> Result<ProductModels, Box<dyn std::error::Error>> {
        let yaml = format!(
            r#"parameters:
  - id: {PARAM_APP}_P-1
    text: "Sendeverzoegerung"
    type: !int
      min: 0
      max: 255
    default: "10"
  - id: {PARAM_APP}_P-2
    text: "Betriebsart"
    type: !enum
      values:
        - {{ value: 1, text: "Rollladen" }}
        - {{ value: 2, text: "Jalousie mit Lamellenverstellung" }}
    default: "1"
"#
        );
        let mut products = ProductModels::default();
        products.by_app_ref.insert(
            PARAM_APP.to_string(),
            bussard_model::ProductModel::from_yaml(&yaml, PARAM_APP)?,
        );
        Ok(products)
    }

    #[test]
    fn test_project_model_with_parameters_grouped_by_channel()
    -> Result<(), Box<dyn std::error::Error>> {
        let v = project_model_with(&param_model()?, &param_products()?);
        let device = &v["devices"][0];
        assert_eq!(device["channels"][0]["key"], "CH-1");
        let channel = device["channels"][0]["parameters"]
            .as_array()
            .ok_or("channel parameters")?;
        assert_eq!(channel.len(), 1, "{channel:?}");
        assert_eq!(channel[0]["key"], "betriebsart");
        assert_eq!(channel[0]["text"], "Betriebsart");
        assert_eq!(channel[0]["value"], "Jalousie mit Lamellenverstellung");
        assert_eq!(channel[0]["default"], "Rollladen");
        assert_eq!(channel[0]["non_default"], true);
        let top = device["parameters"].as_array().ok_or("device parameters")?;
        assert_eq!(top.len(), 1, "{top:?}");
        assert_eq!(top[0]["key"], "sendeverzoegerung");
        assert_eq!(top[0]["value"], "10");
        assert_eq!(top[0]["non_default"], false);
        Ok(())
    }

    #[test]
    fn test_project_model_parameters_without_product_model()
    -> Result<(), Box<dyn std::error::Error>> {
        let v = project_model(&param_model()?);
        let channel = &v["devices"][0]["channels"][0]["parameters"][0];
        assert_eq!(channel["key"], "betriebsart");
        assert_eq!(channel["value"], "Jalousie mit Lamellenverstellung");
        assert_eq!(channel["text"], Value::Null);
        assert_eq!(channel["default"], Value::Null);
        assert_eq!(channel["non_default"], Value::Null);
        Ok(())
    }
}
