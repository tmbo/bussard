//! Parameters at their vendor default (issue #276): the lock indexes every
//! parameter the configuration shows, a ref `Value` override counts as the
//! default, an internal `Access="None"` channel is not emitted, and
//! [`refresh_facts`] brings the lock up to date after an edit reveals
//! parameters and objects. Runs the fabricated `default_params.app.xml`.

use std::collections::{BTreeMap, BTreeSet};

use bussard_ets::application::parse_application_program;
use bussard_model::schema::Device;
use bussard_project::facts::{apply_facts, derive_facts, refresh_facts};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP_ID: &str = "M-00FA_A-00D2-10-0001";
const APP_XML: &[u8] = include_bytes!("fixtures/default_params.app.xml");

fn fresh_device() -> Result<Device, Box<dyn std::error::Error>> {
    Ok(Device {
        address: "1.1.9".parse()?,
        name: "fresh".into(),
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
    })
}

/// The lock's `(ref, key, default)` rows.
fn listed(device: &Device) -> Vec<(String, String, Option<String>)> {
    device
        .lock
        .parameters
        .iter()
        .map(|(r, p)| (r.clone(), p.key.clone(), p.default.clone()))
        .collect()
}

#[test]
fn test_apply_facts_indexes_parameters_at_their_default() -> TestResult {
    let app = parse_application_program(APP_ID, APP_XML)?;
    let facts = derive_facts(&app, &BTreeMap::new(), &Default::default());
    let mut device = fresh_device()?;
    apply_facts(&mut device, &app, &facts, &BTreeMap::new());

    // Nothing is stored, yet the four parameters channel 1 shows are listed.
    // The enable flag's ref overrides the parameter default 0 with 1, and the
    // lock carries that as the default; the others take the product model's.
    assert!(device.parameters.is_empty());
    let some = |s: &str| Some(s.to_string());
    let row = |r: &str, k: &str, d: Option<String>| (r.to_string(), k.to_string(), d);
    assert_eq!(
        listed(&device),
        [
            row("P-1_R-1", "enable-channel-1", some("1")),
            row("P-2_R-2", "enable-channel-2", None),
            row("P-3_R-3", "data-length-1", None),
            row("P-5_R-5", "polarity", None),
        ]
    );
    // Channel 1 being on shows object 1 in its 1-bit form.
    assert_eq!(
        device
            .com_objects
            .get(&1)
            .and_then(|o| o.reference.as_deref()),
        Some("O-1_R-1")
    );
    assert!(!device.com_objects.contains_key(&2));
    Ok(())
}

#[test]
fn test_derive_channels_skips_an_access_none_channel() -> TestResult {
    let app = parse_application_program(APP_ID, APP_XML)?;
    let facts = derive_facts(&app, &BTreeMap::new(), &Default::default());
    let channels: Vec<(&str, &str)> = facts
        .channels
        .iter()
        .map(|c| (c.key.as_str(), c.id.as_str()))
        .collect();
    // "Applikationsinstanzen" holds only an Access="None" parameter.
    assert_eq!(channels, [("mapper-1", "CH-1")]);
    Ok(())
}

#[test]
fn test_refresh_facts_adds_what_an_enable_flag_reveals() -> TestResult {
    let app = parse_application_program(APP_ID, APP_XML)?;
    let facts = derive_facts(&app, &BTreeMap::new(), &Default::default());
    let mut device = fresh_device()?;
    apply_facts(&mut device, &app, &facts, &BTreeMap::new());
    let handles_before: Vec<Option<String>> =
        device.channels.values().map(|c| c.key.clone()).collect();

    // The edit tool stores "enable channel 2 = on" and refreshes the facts.
    device
        .parameters
        .insert("enable-channel-2@P-2_R-2".to_string(), "1".to_string());
    let values: BTreeMap<String, String> =
        BTreeMap::from([("P-2_R-2".to_string(), "1".to_string())]);
    let facts = derive_facts(&app, &values, &Default::default());
    refresh_facts(&mut device, &facts, &BTreeSet::new());

    let keys: Vec<String> = listed(&device).into_iter().map(|(_, k, _)| k).collect();
    assert_eq!(
        keys,
        [
            "enable-channel-1",
            "enable-channel-2",
            "data-length-1",
            "data-length-2",
            "polarity"
        ]
    );
    assert_eq!(
        device
            .com_objects
            .get(&2)
            .and_then(|o| o.reference.as_deref()),
        Some("O-2_R-1")
    );
    let handles_after: Vec<Option<String>> =
        device.channels.values().map(|c| c.key.clone()).collect();
    assert_eq!(handles_before, handles_after);
    assert_eq!(device.parameters.len(), 1);

    // A data length change swaps the object's ref, size and DPT.
    let values: BTreeMap<String, String> = BTreeMap::from([
        ("P-2_R-2".to_string(), "1".to_string()),
        ("P-3_R-3".to_string(), "1".to_string()),
    ]);
    let facts = derive_facts(&app, &values, &Default::default());
    refresh_facts(&mut device, &facts, &BTreeSet::new());
    let object = device.com_objects.get(&1).ok_or("object 1 is gone")?;
    assert_eq!(object.reference.as_deref(), Some("O-1_R-2"));
    assert_eq!(object.dpt.map(|d| d.to_string()).as_deref(), Some("5.010"));

    // Switching channel 1 off hides object 1 and its parameters; a linked
    // object stays so the file's links remain readable.
    let values: BTreeMap<String, String> = BTreeMap::from([
        ("P-1_R-1".to_string(), "0".to_string()),
        ("P-2_R-2".to_string(), "1".to_string()),
    ]);
    let facts = derive_facts(&app, &values, &Default::default());
    refresh_facts(&mut device, &facts, &BTreeSet::from([1]));
    assert!(device.com_objects.contains_key(&1));
    let keys: Vec<String> = listed(&device).into_iter().map(|(_, k, _)| k).collect();
    assert_eq!(
        keys,
        ["enable-channel-1", "enable-channel-2", "data-length-2"]
    );
    refresh_facts(&mut device, &facts, &BTreeSet::new());
    assert!(!device.com_objects.contains_key(&1));
    Ok(())
}
