//! `knx_model_lookup` over com-object and channel texts (issue #276): an
//! object without a link (the IPS300SREG mapper objects) is found by its
//! vendor text, a channel by its text, and each hit names the device, the
//! channel handle and the object number.

use std::collections::BTreeMap;

use bussard_mcp::tools::model_lookup;
use bussard_model::schema::{BussardConfig, Channel, ComObject, Device, Groups, Link, Links};
use bussard_model::{LoadedDevice, Model};
use bussard_testkit::{TestResult, ga, ia};

/// A device with one channel and the given `(number, key, text, function)`
/// objects in it.
fn device(
    address: &str,
    name: &str,
    channel: (&str, &str, &str),
    objects: &[(u16, &str, &str, &str)],
) -> TestResult<LoadedDevice> {
    let (id, handle, text) = channel;
    let com_objects = objects
        .iter()
        .map(|(n, key, text, function)| {
            (
                *n,
                ComObject {
                    key: Some(key.to_string()),
                    channel: Some(id.to_string()),
                    text: Some(text.to_string()),
                    function: Some(function.to_string()),
                    ..ComObject::default()
                },
            )
        })
        .collect();
    Ok(LoadedDevice {
        device: Device {
            address: ia(address)?,
            name: name.to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: BTreeMap::from([(
                id.to_string(),
                Channel {
                    name: text.to_string(),
                    key: Some(handle.to_string()),
                    number: Some(3),
                    text: Some(text.to_string()),
                },
            )]),
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects,
            security: None,
            application_override: None,
            lock: Default::default(),
        },
        file_stem: address.to_string(),
    })
}

fn fixture() -> TestResult<Model> {
    let mapper = device(
        "1.1.201",
        "IP interface",
        ("CH-3", "mapper-3", "Mapper"),
        &[
            (
                15,
                "mapper-objekt-1a",
                "Mapper Objekt 1A - 1 Bit",
                "Ein/Ausgang",
            ),
            (
                16,
                "mapper-objekt-1b",
                "Mapper Objekt 1B - 1 Bit",
                "Ein/Ausgang",
            ),
        ],
    )?;
    let taster = device(
        "1.1.16",
        "Taster Technikraum",
        ("CH-19", "tsm-taste-5-19", "TSM - Taste 5"),
        &[
            (85, "schalten", "TSM - Taste 5 - Ausgang", "Schalten"),
            (
                1049,
                "logikeingang-1",
                "TSM - Status-LED 1 - Eingang",
                "Logikeingang 1",
            ),
            (
                1050,
                "logikeingang-2",
                "TSM - Status-LED 1 - Eingang",
                "Logikeingang 2",
            ),
        ],
    )?;
    let links = BTreeMap::from([(
        ia("1.1.16")?,
        vec![Link {
            object: 85,
            name: Some("Zu Hause".to_string()),
            send: Some(ga("4/3/4")?),
            listen: vec![],
        }],
    )]);
    Ok(Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: None,
            imported_from: None,
            ranges: BTreeMap::new(),
            groups: BTreeMap::new(),
        },
        links: Links { links },
        devices: BTreeMap::from([(ia("1.1.201")?, mapper), (ia("1.1.16")?, taster)]),
    })
}

/// `(device, channel, object)` of each object hit.
fn object_hits(v: &serde_json::Value) -> Vec<(String, String, u64)> {
    v["objects"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|o| {
                    (
                        o["device_ia"].as_str().unwrap_or_default().to_string(),
                        o["channel"].as_str().unwrap_or_default().to_string(),
                        o["object"].as_u64().unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn test_model_lookup_finds_unlinked_objects_by_vendor_text() -> TestResult {
    let model = fixture()?;
    let v = model_lookup(&model, "mapper", 50);
    let hit = |n: u64| ("1.1.201".to_string(), "mapper-3".to_string(), n);
    assert_eq!(object_hits(&v), [hit(15), hit(16)], "{v}");
    assert_eq!(v["objects"][0]["text"], "Mapper Objekt 1A - 1 Bit", "{v}");
    assert_eq!(v["objects"][0]["linked_gas"], serde_json::json!([]), "{v}");
    // The channel matches by its text, with its objects.
    assert_eq!(v["channels"][0]["device_ia"], "1.1.201", "{v}");
    assert_eq!(v["channels"][0]["channel"], "mapper-3", "{v}");
    assert_eq!(
        v["channels"][0]["objects"],
        serde_json::json!([15, 16]),
        "{v}"
    );
    Ok(())
}

#[test]
fn test_model_lookup_matches_object_function_and_names_the_channel() -> TestResult {
    let model = fixture()?;
    let v = model_lookup(&model, "Logik", 50);
    let hit = |n: u64| ("1.1.16".to_string(), "tsm-taste-5-19".to_string(), n);
    assert_eq!(object_hits(&v), [hit(1049), hit(1050)], "{v}");
    assert_eq!(v["channels"], serde_json::json!([]), "{v}");
    Ok(())
}

#[test]
fn test_model_lookup_keeps_link_names_and_their_groups() -> TestResult {
    let model = fixture()?;
    let v = model_lookup(&model, "zu hause", 50);
    assert_eq!(
        object_hits(&v),
        [("1.1.16".to_string(), "tsm-taste-5-19".to_string(), 85)],
        "{v}"
    );
    assert_eq!(v["objects"][0]["name"], "Zu Hause", "{v}");
    assert_eq!(
        v["objects"][0]["linked_gas"],
        serde_json::json!(["4/3/4"]),
        "{v}"
    );
    // The limit bounds objects and channels alike.
    let v = model_lookup(&model, "e", 1);
    assert_eq!(v["objects"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(v["channels"].as_array().map(Vec::len), Some(1), "{v}");
    Ok(())
}
