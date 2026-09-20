//! Re-import merge integration test (issue #9, part 2).
//!
//! Simulates the on-disk re-import flow end-to-end:
//!
//! 1. Save a base model to a `knx/` directory (the "first import").
//! 2. Hand-edit it on disk: rename a device, rename a group address, and change
//!    a *generated* com-object field (a DPT inside `com_objects:`).
//! 3. Re-import: load the hand-edited model from disk, `merge` a freshly-imported
//!    model into it, and save the result.
//! 4. Assert the hand-edited name survived, the hand-edited generated field was
//!    refreshed from the fresh import (and its divergence is *not* reported as a
//!    conflict, since generated data is owned by the import), while the group's
//!    hand-edited name survived and its difference *is* reported.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use bussard_model::schema::{ComObject, Device, Group, Groups, Links};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress, LoadedDevice, Model};

/// A fresh unique temp dir.
fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bussard-reimport-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn ia(s: &str) -> IndividualAddress {
    s.parse().expect("individual address")
}
fn ga(s: &str) -> GroupAddress {
    s.parse().expect("group address")
}

/// A device with one generated com-object (object 0) carrying a DPT.
fn device_with_comobject(addr: &str, name: &str, dpt: Dpt) -> LoadedDevice {
    let mut com_objects = BTreeMap::new();
    com_objects.insert(
        0u16,
        ComObject {
            dpt: Some(dpt),
            size: None,
            flags: Flags::default(),
            reference: None,
            channel: None,
        },
    );
    let device = Device {
        address: ia(addr),
        name: name.to_string(),
        description: None,
        location: None,
        product: None,
        channels: BTreeMap::new(),
        parameters: BTreeMap::new(),
        module_bases: BTreeMap::new(),
        com_objects,
        security: None,
    };
    let file_stem = format!("{addr}-{}", name.to_lowercase().replace(' ', "-"));
    LoadedDevice { device, file_stem }
}

fn model(devices: Vec<LoadedDevice>, groups: Groups) -> Model {
    let mut map = BTreeMap::new();
    for d in devices {
        map.insert(d.device.address, d);
    }
    Model {
        config: Default::default(),
        groups,
        links: Links::default(),
        devices: map,
    }
}

#[test]
fn test_reimport_preserves_hand_edits_and_refreshes_generated() -> anyhow::Result<()> {
    let dir = tmp("preserve");

    // --- Step 1: first import → save the base model. ---
    let mut base_groups = Groups::default();
    base_groups.groups.insert(
        ga("1/0/1"),
        Group {
            name: "Living room light".to_string(),
            dpt: Some(Dpt::new(1, Some(1))),
            description: None,
            protected: false,
        },
    );
    let base = model(
        vec![device_with_comobject(
            "1.1.4",
            "Switch Actuator",
            Dpt::new(1, Some(1)),
        )],
        base_groups,
    );
    base.save(&dir)?;

    // --- Step 2: hand-edit on disk. ---
    // Reload, rename the device + group, and tamper a *generated* com-object DPT.
    let mut edited = Model::load(&dir)?;
    let dev = edited.devices.get_mut(&ia("1.1.4")).expect("device");
    dev.device.name = "Wohnzimmer Schalter".to_string(); // hand-edited name
    dev.device
        .com_objects
        .get_mut(&0)
        .expect("com-object 0")
        .dpt = Some(Dpt::new(9, Some(1))); // hand-edited GENERATED field
    edited.groups.groups.get_mut(&ga("1/0/1")).expect("ga").name =
        "Deckenlicht Wohnzimmer".to_string(); // hand-edited group name
    edited.save(&dir)?;

    // --- Step 3: re-import. The fresh import has the ORIGINAL device/group names
    // (as ETS would export them) and a refreshed generated com-object table:
    // object 0's DPT is 5.001 and a new object 1 appears. ---
    let mut fresh_groups = Groups::default();
    fresh_groups.groups.insert(
        ga("1/0/1"),
        Group {
            name: "Living room light".to_string(),
            dpt: Some(Dpt::new(1, Some(1))),
            description: None,
            protected: false,
        },
    );
    let mut fresh_dev = device_with_comobject("1.1.4", "Switch Actuator", Dpt::new(5, Some(1)));
    fresh_dev.device.com_objects.insert(
        1u16,
        ComObject {
            dpt: Some(Dpt::new(5, Some(1))),
            size: None,
            flags: Flags::default(),
            reference: None,
            channel: None,
        },
    );
    let fresh = model(vec![fresh_dev], fresh_groups);

    let ours = Model::load(&dir)?;
    let (merged, report) = bussard_model::merge(&ours, &fresh);
    merged.save_pruning(&dir)?;

    // --- Step 4: assertions. ---
    let reloaded = Model::load(&dir)?;
    let dev = &reloaded.devices.get(&ia("1.1.4")).expect("device").device;

    // (a) The hand-edited device name survived the re-import.
    assert_eq!(dev.name, "Wohnzimmer Schalter");

    // (b) The generated com-object table was refreshed from the fresh import:
    //     object 0's DPT is now the fresh 5.001 (the hand-tamper was discarded),
    //     and the new object 1 appeared.
    assert_eq!(
        dev.com_objects
            .get(&0)
            .and_then(|c| c.dpt)
            .map(|d| d.to_string()),
        Some("5.001".to_string()),
        "generated com-object DPT should be refreshed to the import's value"
    );
    assert!(
        dev.com_objects.contains_key(&1),
        "new generated com-object should be added on re-import"
    );

    // (c) The hand-edited group name survived...
    assert_eq!(
        reloaded.groups.groups.get(&ga("1/0/1")).expect("ga").name,
        "Deckenlicht Wohnzimmer"
    );

    // (d) ...and the group-name divergence WAS reported as a conflict, while the
    //     generated com-object tamper was NOT (generated data is import-owned).
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "groups/1/0/1" && c.field == "name"),
        "the hand-edited group name should be reported as a conflict: {:?}",
        report.conflicts
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "devices/1.1.4" && c.field == "name"),
        "the hand-edited device name should be reported as a conflict"
    );
    // No conflict is raised for the generated com-object DPT.
    assert!(
        !report
            .conflicts
            .iter()
            .any(|c| c.field.contains("com_object")
                || c.field.contains("dpt") && c.path.starts_with("devices/")),
        "generated com-object changes must not be reported as conflicts"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}
