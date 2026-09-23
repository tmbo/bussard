//! Pure tool logic: the JSON each read-only tool returns, built from the loaded
//! [`Model`] and a snapshot of the [`TelegramRing`].
//!
//! These functions take no rmcp types and do no I/O, so every tool's core can be
//! unit-tested against an in-code model and a hand-fed ring. The rmcp glue in
//! [`crate::server`] is a thin wrapper that calls these and boxes the result in
//! a `CallToolResult`.

use std::time::SystemTime;

use bussard_mgmt::PropertyDesc;
use bussard_model::codec::TypedValue;
use bussard_model::{Dpt, GroupAddress, IndividualAddress, Model};
use bussard_monitor::{DecodedTelegram, DestinationRef, Filter, TelegramRing, json_line};
use serde_json::{Value, json};

use crate::state::BusStatus;

/// Serializes one decoded telegram to the same JSON object the monitor's JSON
/// Lines format uses, so telegrams look identical across the CLI and MCP.
pub fn telegram_json(t: &DecodedTelegram) -> Value {
    // `json_line` is the single source of truth for the telegram schema; parse
    // its output back into a `Value` so we never drift from the monitor format.
    serde_json::from_str(&json_line(t)).unwrap_or_else(|_| json!({}))
}

/// `knx_project_summary`: project name, counts, rooms, GA ranges, bus status,
/// validation counts.
pub fn project_summary(model: &Model, bus: &BusStatus) -> Value {
    let device_count = model.devices.len();
    let ga_count = model.groups.groups.len();
    let link_count: usize = model.links.links.values().map(|v| v.len()).sum();

    // Floors/rooms with device counts, derived from device locations.
    let mut locations: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    for loaded in model.devices.values() {
        if let Some(loc) = &loaded.device.location {
            let floor = loc.floor.clone().unwrap_or_default();
            let room = loc.room.clone().unwrap_or_default();
            if !floor.is_empty() || !room.is_empty() {
                *locations.entry((floor, room)).or_insert(0) += 1;
            }
        }
    }
    let rooms: Vec<Value> = locations
        .into_iter()
        .map(
            |((floor, room), count)| json!({ "floor": floor, "room": room, "device_count": count }),
        )
        .collect();

    // GA main-range names from groups.yaml `ranges` (keyed "3" or "3/2").
    let mut main_ranges: Vec<Value> = model
        .groups
        .ranges
        .iter()
        .filter(|(k, _)| !k.contains('/'))
        .map(|(k, r)| json!({ "main": k, "name": r.name }))
        .collect();
    main_ranges.sort_by(|a, b| a["main"].as_str().cmp(&b["main"].as_str()));

    // Validation error/warning counts.
    let diags = bussard_model::validate(model);
    let errors = diags
        .iter()
        .filter(|d| d.severity == bussard_model::Severity::Error)
        .count();
    let warnings = diags
        .iter()
        .filter(|d| d.severity == bussard_model::Severity::Warning)
        .count();

    json!({
        "project": model.groups.project,
        "imported_from": model.groups.imported_from,
        "counts": {
            "devices": device_count,
            "group_addresses": ga_count,
            "links": link_count,
        },
        "rooms": rooms,
        "ga_main_ranges": main_ranges,
        "bus": bus.to_json(),
        "validation": {
            "errors": errors,
            "warnings": warnings,
        },
    })
}

/// `knx_model_lookup`: case-insensitive substring search over GA names +
/// addresses, device names + IAs, room names, and com-object names.
pub fn model_lookup(model: &Model, query: &str, limit: usize) -> Value {
    let q = query.to_lowercase();
    let hit = |s: &str| s.to_lowercase().contains(&q);

    // Group addresses.
    let mut groups = Vec::new();
    for (ga, group) in &model.groups.groups {
        if hit(&group.name) || hit(&ga.to_string()) {
            // Check the limit *before* pushing, so `limit == 0` yields zero
            // results rather than one (issue #39 off-by-one).
            if groups.len() >= limit {
                break;
            }
            groups.push(json!({
                "address": ga.to_string(),
                "name": group.name,
                "dpt": group.dpt.map(|d| d.to_string()),
            }));
        }
    }

    // Devices (by name, IA, or room).
    let mut devices = Vec::new();
    for (ia, loaded) in &model.devices {
        let dev = &loaded.device;
        let room = dev
            .location
            .as_ref()
            .and_then(|l| l.room.clone())
            .unwrap_or_default();
        let floor = dev
            .location
            .as_ref()
            .and_then(|l| l.floor.clone())
            .unwrap_or_default();
        if hit(&dev.name) || hit(&ia.to_string()) || (!room.is_empty() && hit(&room)) {
            if devices.len() >= limit {
                break;
            }
            devices.push(json!({
                "ia": ia.to_string(),
                "name": dev.name,
                "floor": floor,
                "room": room,
            }));
        }
    }

    // Com-objects (by name), with the GAs each is linked to. The name lives in
    // links.yaml only (issue #19).
    let mut objects = Vec::new();
    'outer: for (ia, links) in &model.links.links {
        for link in links {
            let obj_name = link.name.clone().unwrap_or_default();
            if hit(&obj_name) {
                if objects.len() >= limit {
                    break 'outer;
                }
                let mut linked: Vec<String> = Vec::new();
                if let Some(send) = &link.send {
                    linked.push(send.to_string());
                }
                linked.extend(link.listen.iter().map(|g| g.to_string()));
                objects.push(json!({
                    "device_ia": ia.to_string(),
                    "object": link.object,
                    "name": obj_name,
                    "linked_gas": linked,
                }));
            }
        }
    }

    json!({
        "query": query,
        "groups": groups,
        "devices": devices,
        "objects": objects,
    })
}

/// `knx_get_group`: the group entry, every link touching it, and the last seen
/// telegram from the ring (if any).
pub fn get_group(model: &Model, ring: &TelegramRing, ga: GroupAddress) -> Value {
    let group = model.groups.groups.get(&ga);

    // Every link that sends or listens on this GA. The com-object name lives in
    // links.yaml only (issue #19).
    let mut links = Vec::new();
    for (ia, dev_links) in &model.links.links {
        let dev = model.devices.get(ia);
        for link in dev_links {
            let sends = link.send == Some(ga);
            let listens = link.listen.contains(&ga);
            if !sends && !listens {
                continue;
            }
            let role = if sends { "send" } else { "listen" };
            links.push(json!({
                "device_ia": ia.to_string(),
                "device_name": dev.map(|d| d.device.name.clone()),
                "object": link.object,
                "object_name": link.name.clone(),
                "role": role,
            }));
        }
    }

    // Last seen telegram for this GA from the ring.
    let filter = Filter::parse(&ga.to_string()).unwrap_or_default();
    let last = ring
        .recent(&filter, Some(1))
        .into_iter()
        .find(|t| matches!(t.destination, DestinationRef::Group(g) if g == ga))
        .map(|t| telegram_json(&t));

    json!({
        "address": ga.to_string(),
        "found": group.is_some(),
        "group": group.map(|g| json!({
            "name": g.name,
            "dpt": g.dpt.map(|d| d.to_string()),
            "description": g.description,
        })),
        "links": links,
        "last_telegram": last,
    })
}

/// `knx_get_device`: the full device definition plus its links.
pub fn get_device(model: &Model, ia: IndividualAddress) -> Value {
    let Some(loaded) = model.devices.get(&ia) else {
        return json!({
            "address": ia.to_string(),
            "found": false,
        });
    };
    let dev = &loaded.device;

    // Serialize the whole device via serde (identity, product, location,
    // channels, com_objects) — the schema is already the on-disk shape.
    let device_value = serde_json::to_value(dev).unwrap_or_else(|_| json!({}));

    let links: Vec<Value> = model
        .links
        .links
        .get(&ia)
        .map(|dev_links| {
            dev_links
                .iter()
                .map(|link| {
                    json!({
                        "object": link.object,
                        "name": link.name,
                        "send": link.send.map(|g| g.to_string()),
                        "listen": link.listen.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    json!({
        "address": ia.to_string(),
        "found": true,
        "file_stem": loaded.file_stem,
        "device": device_value,
        "links": links,
    })
}

/// `knx_recent_telegrams`: recent telegrams from the ring, filtered, oldest→newest.
///
/// The ring's `recent` returns newest-first; we reverse so the caller reads a
/// chronological transcript ending in the most recent event.
pub fn recent_telegrams(
    ring: &TelegramRing,
    filter: &Filter,
    since: Option<SystemTime>,
    limit: usize,
) -> Vec<DecodedTelegram> {
    let mut out = ring.recent(filter, None);
    // Apply the `since` cutoff (the ring has no time filter of its own).
    if let Some(cutoff) = since {
        out.retain(|t| t.timestamp >= cutoff);
    }
    out.truncate(limit);
    out.reverse(); // newest last
    out
}

/// `knx_validate`: diagnostics as JSON plus counts.
pub fn validate_result(model: &Model) -> Value {
    let diags = bussard_model::validate(model);
    let mut errors = 0usize;
    let mut warnings = 0usize;
    let mut infos = 0usize;
    let items: Vec<Value> = diags
        .iter()
        .map(|d| {
            match d.severity {
                bussard_model::Severity::Error => errors += 1,
                bussard_model::Severity::Warning => warnings += 1,
                bussard_model::Severity::Info => infos += 1,
            }
            json!({
                "code": d.code,
                "severity": d.severity.to_string(),
                "message": d.message,
                "location": d.location,
            })
        })
        .collect();

    json!({
        "diagnostics": items,
        "counts": {
            "errors": errors,
            "warnings": warnings,
            "infos": infos,
            "total": diags.len(),
        },
        "ok": errors == 0,
    })
}

/// Decodes a raw payload against a GA's DPT into a display string + typed JSON,
/// used by `knx_read_group` to render the response value.
pub fn decode_for_dpt(dpt: Option<Dpt>, payload: &[u8]) -> (Option<String>, Value) {
    match dpt {
        Some(d) => {
            let value = bussard_model::decode(&d, payload);
            (Some(value.to_string()), typed_value_json(&value))
        }
        None => (None, Value::Null),
    }
}

/// A human name for a well-known standardised interface-object type (KNX 3/5/1),
/// or `"?"`.
pub fn object_type_name(object_type: u16) -> &'static str {
    match object_type {
        0 => "device",
        1 => "address table",
        2 => "association table",
        3 => "application program",
        9 => "group object table",
        _ => "?",
    }
}

/// A human name for a well-known standardised PID, or `"?"`. Mirrors the CLI
/// `describe` naming so the MCP and CLI surfaces agree.
pub fn pid_name(pid: u8) -> &'static str {
    match pid {
        1 => "PID_OBJECT_TYPE",
        5 => "PID_LOAD_STATE_CONTROL",
        7 => "PID_TABLE_REFERENCE",
        11 => "PID_SERIAL_NUMBER",
        12 => "PID_MANUFACTURER_ID",
        15 => "PID_ORDER_INFO",
        23 => "PID_TABLE",
        27 => "PID_MCB_TABLE",
        54 => "PID_PROGMODE",
        56 => "PID_MAX_APDU_LENGTH",
        78 => "PID_HARDWARE_TYPE",
        _ => "?",
    }
}

/// Renders one enumerated interface object and its property descriptions to the
/// JSON shape the `knx_describe_device` tool returns (issue #72).
pub fn describe_object_json(index: u8, object_type: u16, properties: &[PropertyDesc]) -> Value {
    let props: Vec<Value> = properties
        .iter()
        .map(|p| {
            json!({
                "index": p.property_index,
                "pid": p.property_id,
                "name": pid_name(p.property_id),
                "pdt": format!("0x{:02X}", p.pdt),
                "writable": p.writable,
                "max_elements": p.max_elements,
                "read_level": p.read_level,
                "write_level": p.write_level,
            })
        })
        .collect();
    json!({
        "index": index,
        "object_type": object_type,
        "object_type_name": object_type_name(object_type),
        "properties": props,
    })
}

/// A structured JSON rendering of a [`TypedValue`] for tool responses.
pub(crate) fn typed_value_json(v: &TypedValue) -> Value {
    match v {
        TypedValue::Bool { value, label } => json!({ "bool": value, "label": label }),
        TypedValue::Percent(p) => json!({ "percent": p }),
        TypedValue::Unsigned { value, unit } => json!({ "unsigned": value, "unit": unit }),
        TypedValue::Signed { value, unit } => json!({ "signed": value, "unit": unit }),
        TypedValue::Float { value, unit } => json!({ "float": value, "unit": unit }),
        other => json!({ "display": other.to_string() }),
    }
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    //! A small in-code model + ring builders shared by the tool unit tests.

    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime};

    use bussard_model::schema::{
        BussardConfig, Channel, Device, Group, Groups, Link, Links, Location, Range,
    };
    use bussard_model::{GroupAddress, IndividualAddress, LoadedDevice, Model};
    use bussard_monitor::{ApciKind, DecodedTelegram, DestinationRef, TelegramRing};

    pub fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }
    pub fn ia(s: &str) -> IndividualAddress {
        s.parse().unwrap()
    }

    /// Two GAs (one with DPT), one device in a room, one send + one listen link.
    pub fn model() -> Model {
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/2/0"),
            Group {
                name: "Windalarm".to_string(),
                dpt: Some("1.005".parse().unwrap()),
                description: Some("wind alarm".to_string()),
                protected: true,
                secure: false,
            },
        );
        groups.insert(
            ga("3/0/4"),
            Group {
                name: "Living Room Blind Move".to_string(),
                dpt: Some("1.008".parse().unwrap()),
                description: None,
                protected: false,
                secure: false,
            },
        );

        let mut ranges = BTreeMap::new();
        ranges.insert(
            "3".to_string(),
            Range {
                name: "Verschattung".to_string(),
            },
        );

        let mut links = BTreeMap::new();
        links.insert(
            ia("1.1.30"),
            vec![Link {
                object: 3,
                name: Some("Windalarm 1".to_string()),
                send: Some(ga("3/2/0")),
                listen: vec![],
            }],
        );
        links.insert(
            ia("1.1.4"),
            vec![Link {
                object: 12,
                name: Some("A: Behang Auf/Ab".to_string()),
                send: None,
                listen: vec![ga("3/0/4")],
            }],
        );

        let mut channels = BTreeMap::new();
        channels.insert(
            "A".to_string(),
            Channel {
                name: "Raffstore Süd".to_string(),
            },
        );

        let mut devices = BTreeMap::new();
        devices.insert(
            ia("1.1.4"),
            LoadedDevice {
                device: Device {
                    address: ia("1.1.4"),
                    name: "Blind Actuator 4-fold".to_string(),
                    description: None,
                    location: Some(Location {
                        floor: Some("EG".to_string()),
                        room: Some("Wohnzimmer".to_string()),
                    }),
                    replaced: None,
                    product: None,
                    channels,
                    parameters: BTreeMap::new(),
                    module_bases: Default::default(),
                    com_objects: BTreeMap::new(),
                    security: None,
                },
                file_stem: "1.1.4-jalousieaktor".to_string(),
            },
        );
        devices.insert(
            ia("1.1.30"),
            LoadedDevice {
                device: Device {
                    address: ia("1.1.30"),
                    name: "Weather Station".to_string(),
                    description: None,
                    location: Some(Location {
                        floor: Some("Attic".to_string()),
                        room: Some("Utility Room".to_string()),
                    }),
                    replaced: None,
                    product: None,
                    channels: BTreeMap::new(),
                    parameters: BTreeMap::new(),
                    module_bases: Default::default(),
                    com_objects: BTreeMap::new(),
                    security: None,
                },
                file_stem: "1.1.30-wetterstation".to_string(),
            },
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

    /// A telegram to `dest` at `secs` past the epoch.
    pub fn tel(dest: &str, secs: u64) -> DecodedTelegram {
        DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
            source: ia("1.1.30"),
            source_name: Some("Weather Station".to_string()),
            destination: DestinationRef::Group(ga(dest)),
            destination_name: Some("Windalarm".to_string()),
            apci: ApciKind::Write,
            payload: vec![1],
            value: Some(bussard_model::codec::TypedValue::Bool {
                value: true,
                label: "Alarm",
            }),
            dpt: Some("1.005".parse().unwrap()),
            object_name: Some("Windalarm 1".to_string()),
            decode_note: None,
        }
    }

    pub fn ring_with(dests: &[(&str, u64)]) -> TelegramRing {
        let ring = TelegramRing::new();
        for (d, s) in dests {
            ring.push(tel(d, *s));
        }
        ring
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::*;
    use super::*;
    use crate::state::BusStatus;
    use bussard_transport::TransportKind;

    #[test]
    fn summary_counts_and_ranges() {
        let m = model();
        let bus = BusStatus::new(TransportKind::Tunnel);
        let v = project_summary(&m, &bus);
        assert_eq!(v["project"], "Home");
        assert_eq!(v["counts"]["devices"], 2);
        assert_eq!(v["counts"]["group_addresses"], 2);
        assert_eq!(v["counts"]["links"], 2);
        // Two rooms with one device each.
        assert_eq!(v["rooms"].as_array().unwrap().len(), 2);
        // One main range "3".
        assert_eq!(v["ga_main_ranges"][0]["main"], "3");
        assert_eq!(v["ga_main_ranges"][0]["name"], "Verschattung");
        // Bus starts connecting.
        assert_eq!(v["bus"]["state"], "connecting");
        assert_eq!(v["bus"]["transport"], "tunnel");
    }

    #[test]
    fn lookup_matches_across_kinds() {
        let m = model();
        // "wind" hits the GA name and the object name.
        let v = model_lookup(&m, "wind", 50);
        assert_eq!(v["groups"].as_array().unwrap().len(), 1);
        assert_eq!(v["groups"][0]["address"], "3/2/0");
        assert_eq!(v["objects"].as_array().unwrap().len(), 1);
        assert_eq!(v["objects"][0]["linked_gas"][0], "3/2/0");

        // A room-name match returns the device.
        let v = model_lookup(&m, "wohnzimmer", 50);
        assert_eq!(v["devices"].as_array().unwrap().len(), 1);
        assert_eq!(v["devices"][0]["ia"], "1.1.4");

        // An address substring match.
        let v = model_lookup(&m, "3/0/4", 50);
        assert_eq!(v["groups"][0]["address"], "3/0/4");
    }

    #[test]
    fn lookup_respects_limit() {
        let m = model();
        // Both GAs contain "3/" — limit to 1.
        let v = model_lookup(&m, "3/", 1);
        assert_eq!(v["groups"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn get_group_assembles_links_and_last_telegram() {
        let m = model();
        let ring = ring_with(&[("3/2/0", 100)]);
        let v = get_group(&m, &ring, ga("3/2/0"));
        assert_eq!(v["found"], true);
        assert_eq!(v["group"]["name"], "Windalarm");
        // The sending link is present with role "send".
        let links = v["links"].as_array().unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["device_ia"], "1.1.30");
        assert_eq!(links[0]["role"], "send");
        // Last telegram resolved.
        assert_eq!(v["last_telegram"]["destination"], "3/2/0");
    }

    #[test]
    fn get_group_listen_role() {
        let m = model();
        let ring = TelegramRing::new();
        let v = get_group(&m, &ring, ga("3/0/4"));
        let links = v["links"].as_array().unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["role"], "listen");
        assert_eq!(links[0]["object"], 12);
        assert!(v["last_telegram"].is_null());
    }

    #[test]
    fn get_device_full_and_links() {
        let m = model();
        let v = get_device(&m, ia("1.1.4"));
        assert_eq!(v["found"], true);
        assert_eq!(v["device"]["name"], "Blind Actuator 4-fold");
        assert_eq!(v["device"]["location"]["room"], "Wohnzimmer");
        assert_eq!(v["links"].as_array().unwrap().len(), 1);
        assert_eq!(v["links"][0]["listen"][0], "3/0/4");
    }

    #[test]
    fn get_device_not_found() {
        let m = model();
        let v = get_device(&m, ia("9.9.9"));
        assert_eq!(v["found"], false);
    }

    #[test]
    fn recent_filters_since_and_orders_chronologically() {
        let ring = ring_with(&[("3/2/0", 10), ("3/2/0", 20), ("3/2/0", 30)]);
        let filter = Filter::default();
        // No since: all three, newest last.
        let all = recent_telegrams(&ring, &filter, None, 50);
        assert_eq!(all.len(), 3);
        assert!(all[0].timestamp <= all[2].timestamp, "chronological");

        // Since t=20s: two remain.
        let since = Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(20));
        let filtered = recent_telegrams(&ring, &filter, since, 50);
        assert_eq!(filtered.len(), 2);

        // Limit to 1: newest only.
        let one = recent_telegrams(&ring, &filter, None, 1);
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn validate_shape_and_counts() {
        let m = model();
        let v = validate_result(&m);
        assert!(v["counts"]["total"].as_u64().is_some());
        assert!(v["diagnostics"].is_array());
        // A well-formed fixture: `ok` reflects zero errors.
        let errors = v["counts"]["errors"].as_u64().unwrap();
        assert_eq!(v["ok"], errors == 0);
    }

    #[test]
    fn decode_for_dpt_bool() {
        let (display, typed) = decode_for_dpt(Some("1.005".parse().unwrap()), &[1]);
        assert_eq!(display.as_deref(), Some("Alarm"));
        assert_eq!(typed["bool"], true);
        assert_eq!(typed["label"], "Alarm");

        let (display, typed) = decode_for_dpt(None, &[1]);
        assert!(display.is_none());
        assert!(typed.is_null());
    }
}
