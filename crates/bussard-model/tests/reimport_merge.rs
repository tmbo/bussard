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

use bussard_model::schema::{Channel, ComObject, Device, Group, Groups, Links, Product};
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
            secure: false,
            function: None,
            key: None,
            text: None,
        },
    );
    let device = Device {
        address: ia(addr),
        name: name.to_string(),
        description: None,
        location: None,
        replaced: None,
        product: None,
        channels: BTreeMap::new(),
        parameters: BTreeMap::new(),
        module_bases: BTreeMap::new(),
        com_objects,
        security: None,
        application_override: None,
        lock: Default::default(),
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
            secure: false,
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
            secure: false,
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
            secure: false,
            function: None,
            key: None,
            text: None,
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

/// Regression: an ETS application upgrade left the model contradicting itself.
/// `merge` took the regenerated `parameters:`/`com_objects:` from the fresh
/// import but kept `product.application_ref`/`mask` (and the whole channel set)
/// from disk, so every fresh parameter key was read against the *old*
/// application program: `validate` reported E016 for all of them and the flasher
/// resolved the wrong product model. The generated identity now follows the
/// import, while the hand-authored name/order-number and channel names stay.
#[test]
fn test_reimport_takes_the_new_application_ref_with_the_new_tables() -> anyhow::Result<()> {
    let dir = tmp("appref");

    // On disk: the old application, a hand-named device and channel, and a
    // hand-corrected manufacturer/order number.
    let mut ours_dev = device_with_comobject("1.1.4", "Rollladen", Dpt::new(1, Some(8)));
    ours_dev.device.product = Some(Product {
        manufacturer: Some("Jung (corrected by hand)".to_string()),
        manufacturer_ref: Some("M-0004".to_string()),
        order_number: Some("2304.16REGHE".to_string()),
        hardware_ref: Some("M-0004_H-OLD".to_string()),
        application_ref: Some("M-0004_A-A011-12-OLD".to_string()),
        mask: Some("07B0".to_string()),
    });
    ours_dev.device.channels.insert(
        "ch1".to_string(),
        Channel {
            name: "Küche (hand-named)".to_string(),
            key: None,
            number: None,
            text: None,
        },
    );
    ours_dev.device.channels.insert(
        "ch9".to_string(),
        Channel {
            name: "Kanal der weggeht".to_string(),
            key: None,
            number: None,
            text: None,
        },
    );
    ours_dev
        .device
        .parameters
        .insert("windalarm@MD-1_P-3_R-7".to_string(), "1".to_string());
    let ours = model(vec![ours_dev], Groups::default());
    ours.save(&dir)?;

    // The fresh import: ETS upgraded the application program, which renamed the
    // parameter refs, moved the hardware, dropped a channel and added one.
    let mut fresh_dev = device_with_comobject("1.1.4", "Switch Actuator", Dpt::new(1, Some(8)));
    fresh_dev.device.product = Some(Product {
        manufacturer: Some("Jung".to_string()),
        manufacturer_ref: Some("M-0004".to_string()),
        order_number: Some("2304.16REGHE".to_string()),
        hardware_ref: Some("M-0004_H-NEW".to_string()),
        application_ref: Some("M-0004_A-A011-13-NEW".to_string()),
        mask: Some("27B0".to_string()),
    });
    fresh_dev.device.channels.insert(
        "ch1".to_string(),
        Channel {
            name: "Channel 1".to_string(),
            key: None,
            number: None,
            text: None,
        },
    );
    fresh_dev.device.channels.insert(
        "ch2".to_string(),
        Channel {
            name: "Channel 2".to_string(),
            key: None,
            number: None,
            text: None,
        },
    );
    fresh_dev
        .device
        .parameters
        .insert("windalarm@MD-1_P-4_R-9".to_string(), "1".to_string());
    // A com-object pointing at the channel the project dropped: after the merge
    // it must not dangle.
    fresh_dev.device.com_objects.insert(
        7u16,
        ComObject {
            dpt: Some(Dpt::new(1, Some(8))),
            size: None,
            flags: Flags::default(),
            reference: None,
            channel: Some("ch9".to_string()),
            secure: false,
            function: None,
            key: None,
            text: None,
        },
    );
    let fresh = model(vec![fresh_dev], Groups::default());

    let on_disk = Model::load(&dir)?;
    let (merged, report) = bussard_model::merge(&on_disk, &fresh);

    let dev = &merged.devices.get(&ia("1.1.4")).expect("device").device;
    let product = dev.product.as_ref().expect("product");

    // Generated identity follows the import — the tables were read out of it.
    assert_eq!(
        product.application_ref.as_deref(),
        Some("M-0004_A-A011-13-NEW")
    );
    assert_eq!(product.mask.as_deref(), Some("27B0"));
    assert_eq!(product.hardware_ref.as_deref(), Some("M-0004_H-NEW"));
    assert!(dev.parameters.contains_key("windalarm@MD-1_P-4_R-9"));

    // Hand-authored halves survive.
    assert_eq!(dev.name, "Rollladen");
    assert_eq!(
        product.manufacturer.as_deref(),
        Some("Jung (corrected by hand)")
    );
    assert_eq!(product.order_number.as_deref(), Some("2304.16REGHE"));

    // The channel SET is the project's, with hand-authored names kept.
    assert_eq!(
        dev.channels.keys().collect::<Vec<_>>(),
        vec!["ch1", "ch2"],
        "the channel set is generated: ch9 left, ch2 arrived"
    );
    assert_eq!(dev.channels["ch1"].name, "Küche (hand-named)");
    assert_eq!(dev.channels["ch2"].name, "Channel 2");

    // No com-object may point at a channel that is gone.
    for (number, co) in &dev.com_objects {
        if let Some(key) = &co.channel {
            assert!(
                dev.channels.contains_key(key),
                "com-object {number} points at missing channel {key}"
            );
        }
    }

    // The application move is reported as information, not as a kept conflict.
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("application_ref") && n.contains("M-0004_A-A011-13-NEW")),
        "the application-program change should be reported: {:?}",
        report.notes
    );
    assert!(
        report.notes.iter().any(|n| n.contains("ch9")),
        "the dropped channel should be reported: {:?}",
        report.notes
    );
    assert!(
        !report
            .conflicts
            .iter()
            .any(|c| c.field.contains("application_ref") || c.field.contains("mask")),
        "generated identity is not a hand-authored conflict: {:?}",
        report.conflicts
    );
    // The hand-corrected manufacturer is still a conflict (kept from disk).
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.field == "product.manufacturer"),
        "{:?}",
        report.conflicts
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// Hidden values (the lock's `hidden[]`: refs ETS stores that the configuration
/// does not show) are generated data. A re-import takes the import's set as a
/// whole: a changed value is replaced and one the project no longer holds is
/// dropped.
#[test]
fn test_reimport_takes_hidden_values_from_the_import() -> anyhow::Result<()> {
    let mut ours = device_with_comobject("1.1.4", "Switch Actuator", Dpt::new(1, Some(1)));
    ours.device
        .parameters
        .insert("hidden@P-4_R-6".into(), "30".into());
    ours.device
        .parameters
        .insert("hidden@P-9_R-12".into(), "1".into());
    let mut fresh = device_with_comobject("1.1.4", "Switch Actuator", Dpt::new(1, Some(1)));
    fresh
        .device
        .parameters
        .insert("hidden@P-4_R-6".into(), "12".into());

    let (merged, _) = bussard_model::merge(
        &model(vec![ours], Groups::default()),
        &model(vec![fresh], Groups::default()),
    );
    let dev = &merged.devices[&ia("1.1.4")].device;
    assert_eq!(
        dev.parameters.get("hidden@P-4_R-6").map(String::as_str),
        Some("12")
    );
    assert!(!dev.parameters.contains_key("hidden@P-9_R-12"));
    assert_eq!(dev.parameters.len(), 1, "{:?}", dev.parameters);

    // The lock the merge saves lists exactly the import's values.
    let texts = merged.to_texts()?;
    let lock = &texts["bussard.lock"];
    assert!(
        lock.contains(r#"{ ref = "P-4_R-6", value = "12" }"#),
        "{lock}"
    );
    assert!(!lock.contains("P-9_R-12"), "{lock}");
    let (_, dev) = texts
        .iter()
        .find(|(k, _)| k.starts_with("devices/"))
        .ok_or_else(|| anyhow::anyhow!("no device file"))?;
    assert!(!dev.contains("hidden"), "{dev}");
    Ok(())
}

/// Regression: product data arriving on a re-import derives a real handle for
/// a channel that used to be id-keyed (its device file used the vendor's
/// channel id as the `[channel.*]` table name, its object numeric). Before the
/// fix, the old id-keyed table survived the save next to the new derived one,
/// linking every one of its objects twice (a real import saw 164 such
/// duplicates). The channel and object *sets* come from the import; only the
/// channel's hand-set `name` carries over.
#[test]
fn test_reimport_gives_an_id_keyed_channel_its_derived_handle() -> anyhow::Result<()> {
    let dir = tmp("id-keyed-channel");

    // ours: unkeyed channel "MD-3_M-18_MI-1_CH-25", numeric object key 144,
    // with a hand-set channel name.
    let mut ours_dev = device_with_comobject("1.1.47", "Heizungsaktor", Dpt::new(1, Some(8)));
    ours_dev.device.channels.insert(
        "MD-3_M-18_MI-1_CH-25".to_string(),
        Channel {
            name: "Süd".to_string(),
            key: None,
            number: None,
            text: None,
        },
    );
    ours_dev.device.com_objects.insert(
        144u16,
        ComObject {
            dpt: Some(Dpt::new(1, Some(8))),
            size: None,
            flags: Flags::default(),
            reference: None,
            channel: Some("MD-3_M-18_MI-1_CH-25".to_string()),
            secure: false,
            function: None,
            key: None,
            text: None,
        },
    );
    let mut ours = model(vec![ours_dev], Groups::default());
    ours.links.links.insert(
        ia("1.1.47"),
        vec![bussard_model::schema::Link {
            object: 144,
            name: None,
            send: None,
            listen: vec![ga("0/1/3")],
        }],
    );
    ours.save(&dir)?;

    // theirs: same channel id, now with a derived handle and a named object.
    let mut fresh_dev = device_with_comobject("1.1.47", "Heizungsaktor", Dpt::new(1, Some(8)));
    fresh_dev.device.channels.insert(
        "MD-3_M-18_MI-1_CH-25".to_string(),
        Channel {
            name: "Relaisausgänge 1/2".to_string(),
            key: Some("relaisausgaenge-1".to_string()),
            number: Some(1),
            text: Some("Relaisausgänge 1/2".to_string()),
        },
    );
    fresh_dev.device.com_objects.insert(
        144u16,
        ComObject {
            dpt: Some(Dpt::new(1, Some(8))),
            size: None,
            flags: Flags::default(),
            reference: None,
            channel: Some("MD-3_M-18_MI-1_CH-25".to_string()),
            secure: false,
            function: None,
            key: Some("langzeitbetrieb".to_string()),
            text: Some("Langzeitbetrieb".to_string()),
        },
    );
    let mut fresh = model(vec![fresh_dev], Groups::default());
    fresh.links.links.insert(
        ia("1.1.47"),
        vec![bussard_model::schema::Link {
            object: 144,
            name: None,
            send: None,
            listen: vec![ga("0/1/3")],
        }],
    );

    let on_disk = Model::load(&dir)?;
    let (merged, report) = bussard_model::merge(&on_disk, &fresh);

    // The merged model has exactly one channel, under the id, with the
    // derived handle and ours' name kept.
    let dev = &merged.devices[&ia("1.1.47")].device;
    assert_eq!(dev.channels.len(), 1, "{:?}", dev.channels);
    let ch = &dev.channels["MD-3_M-18_MI-1_CH-25"];
    assert_eq!(ch.key.as_deref(), Some("relaisausgaenge-1"));
    assert_eq!(ch.name, "Süd");
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.field == "channels.MD-3_M-18_MI-1_CH-25.name"),
        "the hand-set channel name differing from the fresh text should be reported: {:?}",
        report.conflicts
    );

    // Saving must not leave the old id-keyed table behind: one channel table,
    // its object linked once.
    merged.save_pruning(&dir)?;
    let text = fs::read_to_string(dir.join("devices/1.1.47.toml"))?;
    assert_eq!(text.matches("[channel.").count(), 1, "{text}");
    assert!(!text.contains("MD-3_M-18_MI-1_CH-25"), "{text}");
    assert_eq!(text.matches("0/1/3").count(), 1, "{text}");

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A stored parameter's value is hand-authored and survives a re-import that
/// gives the same ref a different key (a fresh derivation, or a page
/// requalification): it is matched by ref, not by the key text, so a rename
/// does not lose it or leave it duplicated under the old key.
#[test]
fn test_reimport_keeps_a_parameter_value_by_ref_across_a_key_rename() -> anyhow::Result<()> {
    let mut ours = device_with_comobject("1.1.4", "Switch Actuator", Dpt::new(1, Some(1)));
    ours.device
        .parameters
        .insert("windalarm@MD-1_P-3_R-45".to_string(), "1".to_string());

    let mut fresh = device_with_comobject("1.1.4", "Switch Actuator", Dpt::new(1, Some(1)));
    // Same ref, a different (freshly derived) key and a different value, as
    // ETS's project currently states it.
    fresh
        .device
        .parameters
        .insert("windalarm-1@MD-1_P-3_R-45".to_string(), "0".to_string());

    let (merged, _) = bussard_model::merge(
        &model(vec![ours], Groups::default()),
        &model(vec![fresh], Groups::default()),
    );
    let dev = &merged.devices[&ia("1.1.4")].device;
    // The fresh key spelling is used...
    assert!(!dev.parameters.contains_key("windalarm@MD-1_P-3_R-45"));
    // ...but the hand-set value survived under it.
    assert_eq!(
        dev.parameters.get("windalarm-1@MD-1_P-3_R-45"),
        Some(&"1".to_string())
    );
    Ok(())
}

/// A com-object the project no longer defines is dropped like a channel that
/// left the project, and the drop is noted rather than silent.
#[test]
fn test_reimport_notes_a_dropped_com_object() -> anyhow::Result<()> {
    let mut ours = device_with_comobject("1.1.4", "Switch Actuator", Dpt::new(1, Some(1)));
    ours.device.com_objects.insert(
        5u16,
        ComObject {
            dpt: Some(Dpt::new(1, Some(1))),
            size: None,
            flags: Flags::default(),
            reference: None,
            channel: None,
            secure: false,
            function: None,
            key: None,
            text: None,
        },
    );
    let fresh = device_with_comobject("1.1.4", "Switch Actuator", Dpt::new(1, Some(1)));

    let (merged, report) = bussard_model::merge(
        &model(vec![ours], Groups::default()),
        &model(vec![fresh], Groups::default()),
    );
    let dev = &merged.devices[&ia("1.1.4")].device;
    assert!(!dev.com_objects.contains_key(&5));
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("com-object 5") && n.contains("dropped")),
        "{:?}",
        report.notes
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Issue #235: links the project dropped, and fresh vs re-import equality.
// ---------------------------------------------------------------------------

use bussard_model::reconcile::{Side, resolve_all};
use bussard_model::schema::{DeviceSecurity, Link, LockedParameter};

/// A push-button device (1.1.17) with three channels, each holding a
/// `schalten` object, and a device-level `regenalarm` object (138). `drop`
/// leaves out the listed object numbers, as a project whose parameters hide
/// them would.
fn push_button(drop: &[u16]) -> LoadedDevice {
    let mut channels = BTreeMap::new();
    let mut com_objects = BTreeMap::new();
    for (n, (id, handle)) in [
        ("CH-1", "tsm-taste-1"),
        ("CH-2", "tsm-taste-2"),
        ("CH-3", "tsm-taste-3"),
    ]
    .into_iter()
    .enumerate()
    {
        let text = format!("Taste {}", n + 1);
        channels.insert(
            id.to_string(),
            Channel {
                name: text.clone(),
                key: Some(handle.to_string()),
                number: Some(n as u32 + 1),
                text: Some(text),
            },
        );
        let number = 65 + 8 * n as u16;
        com_objects.insert(
            number,
            ComObject {
                dpt: Some(Dpt::new(1, Some(1))),
                channel: Some(id.to_string()),
                key: Some("schalten".to_string()),
                text: Some("Schalten".to_string()),
                ..ComObject::default()
            },
        );
    }
    com_objects.insert(
        138,
        ComObject {
            dpt: Some(Dpt::new(1, Some(5))),
            key: Some("regenalarm".to_string()),
            text: Some("Regenalarm".to_string()),
            ..ComObject::default()
        },
    );
    for n in drop {
        com_objects.remove(n);
    }
    let device = Device {
        address: ia("1.1.17"),
        name: "Tastsensor".to_string(),
        description: None,
        location: None,
        replaced: None,
        product: Some(Product {
            manufacturer: None,
            order_number: Some("6108/07".to_string()),
            manufacturer_ref: None,
            hardware_ref: None,
            application_ref: None,
            mask: None,
        }),
        channels,
        parameters: BTreeMap::new(),
        module_bases: BTreeMap::new(),
        com_objects,
        security: Some(DeviceSecurity {
            activated: true,
            secure_commissioning: true,
            ..DeviceSecurity::default()
        }),
        application_override: None,
        lock: Default::default(),
    };
    LoadedDevice {
        device,
        file_stem: "1.1.17".to_string(),
    }
}

/// A link entry.
fn link(object: u16, send: Option<&str>, listen: &[&str]) -> Link {
    Link {
        object,
        name: None,
        send: send.map(ga),
        listen: listen.iter().map(|g| ga(g)).collect(),
    }
}

/// A model holding one device and its links.
fn with_links(device: LoadedDevice, links: Vec<Link>) -> Model {
    let address = device.device.address;
    let mut m = model(vec![device], Groups::default());
    if !links.is_empty() {
        m.links.links.insert(address, links);
    }
    m
}

/// Every model file under `dir`, keyed by relative path (`.bussard/` and the
/// product store are not model files).
fn model_files(dir: &std::path::Path) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for rel in ["bussard.toml", "groups.toml", "bussard.lock"] {
        if let Ok(text) = fs::read_to_string(dir.join(rel)) {
            out.insert(rel.to_string(), text);
        }
    }
    for entry in fs::read_dir(dir.join("devices"))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        out.insert(format!("devices/{name}"), fs::read_to_string(entry.path())?);
    }
    Ok(out)
}

/// Runs the on-disk re-import of `fresh` into a model first written from
/// `first` (and optionally hand-edited through `edit`), settling every
/// conflict with `side`. Returns the re-import directory, the merge report
/// and the files a fresh import of `fresh` writes.
fn reimport(
    tag: &str,
    first: &Model,
    edit: impl FnOnce(&std::path::Path) -> anyhow::Result<()>,
    fresh: &Model,
    side: Side,
) -> anyhow::Result<(
    PathBuf,
    bussard_model::MergeReport,
    BTreeMap<String, String>,
)> {
    let dir = tmp(tag);
    first.save(&dir)?;
    edit(&dir)?;
    let mut ours = Model::load(&dir)?;
    bussard_model::normalize_spellings(&mut ours, fresh);
    let (mut merged, report) = bussard_model::merge(&ours, fresh);
    resolve_all(&mut merged, fresh, &report.conflicts, side);
    merged.save_pruning_as_import(&dir)?;

    let fresh_dir = tmp(&format!("{tag}-fresh"));
    fresh.save(&fresh_dir)?;
    let fresh_files = model_files(&fresh_dir)?;
    let _ = fs::remove_dir_all(&fresh_dir);
    Ok((dir, report, fresh_files))
}

/// Asserts `dir` holds exactly `fresh`, byte for byte, and loads without an
/// unknown-key error.
fn assert_same_as_fresh(
    dir: &std::path::Path,
    fresh: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let got = model_files(dir)?;
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        fresh.keys().collect::<Vec<_>>()
    );
    for (rel, text) in fresh {
        assert_eq!(
            got.get(rel),
            Some(text),
            "{rel} differs from a fresh import"
        );
    }
    let loaded = Model::load(dir)?;
    let unknown: Vec<_> = bussard_model::validate::validate_in_dir(&loaded, dir)
        .into_iter()
        .filter(|d| d.code == "E023")
        .collect();
    assert!(unknown.is_empty(), "{unknown:?}");
    Ok(())
}

/// A link that moves from one channel's object to another's, where the old
/// object leaves the project, is gone from the old channel after a
/// `--theirs` re-import: no stale `schalten.send` survives under the channel
/// that lost it (the key no longer resolves there, it did in the old lock).
#[test]
fn test_reimport_link_moving_between_channels_leaves_no_stale_key() -> anyhow::Result<()> {
    let first = with_links(push_button(&[]), vec![link(73, Some("4/2/20"), &[])]);
    let fresh = with_links(push_button(&[73]), vec![link(81, Some("4/2/20"), &[])]);
    let (dir, _, fresh_files) = reimport("moved", &first, |_| Ok(()), &fresh, Side::Theirs)?;
    let text = fs::read_to_string(dir.join("devices/1.1.17.toml"))?;
    assert_eq!(text.matches("4/2/20").count(), 1, "{text}");
    assert_same_as_fresh(&dir, &fresh_files)?;
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A link the project dropped from an object it still has is a conflict (the
/// model cannot tell it from a hand-added link); `--theirs` removes it and the
/// result equals a fresh import.
#[test]
fn test_reimport_theirs_removes_a_dropped_link() -> anyhow::Result<()> {
    let first = with_links(
        push_button(&[]),
        vec![
            link(65, Some("0/0/3"), &["0/0/4"]),
            link(73, Some("4/2/20"), &[]),
        ],
    );
    let fresh = with_links(push_button(&[]), vec![link(73, Some("4/2/20"), &[])]);
    let (dir, report, fresh_files) = reimport("dropped", &first, |_| Ok(()), &fresh, Side::Theirs)?;
    let fields: Vec<(&str, &str)> = report
        .conflicts
        .iter()
        .map(|c| (c.path.as_str(), c.field.as_str()))
        .collect();
    assert!(fields.contains(&("links/1.1.17#65", "send")), "{fields:?}");
    assert!(
        fields.contains(&("links/1.1.17#65", "listen")),
        "{fields:?}"
    );
    assert_same_as_fresh(&dir, &fresh_files)?;
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A parameter going back to its default removes it from the project, and the
/// object it enabled (with its `[links]` entry) goes with it.
#[test]
fn test_reimport_parameter_back_to_default_drops_its_link() -> anyhow::Result<()> {
    let mut device = push_button(&[]);
    device
        .device
        .parameters
        .insert("regenalarm@P-9_R-9".to_string(), "1".to_string());
    let first = with_links(device, vec![link(138, None, &["4/1/8"])]);
    let fresh = with_links(push_button(&[138]), vec![]);
    let (dir, report, fresh_files) = reimport("default", &first, |_| Ok(()), &fresh, Side::Theirs)?;
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("com-object 138") && n.contains("dropped")),
        "{:?}",
        report.notes
    );
    let text = fs::read_to_string(dir.join("devices/1.1.17.toml"))?;
    assert!(!text.contains("regenalarm"), "{text}");
    assert_same_as_fresh(&dir, &fresh_files)?;
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A link added by hand to an object the project has but does not link is
/// kept with `--mine` (reported as a conflict) and removed with `--theirs`.
#[test]
fn test_reimport_mine_keeps_a_hand_added_link() -> anyhow::Result<()> {
    let base = with_links(push_button(&[]), vec![link(73, Some("4/2/20"), &[])]);
    let add = |dir: &std::path::Path| -> anyhow::Result<()> {
        let path = dir.join("devices/1.1.17.toml");
        let text = fs::read_to_string(&path)?;
        anyhow::ensure!(!text.contains("[channel.tsm-taste-1]"), "{text}");
        fs::write(
            &path,
            format!("{text}\n[channel.tsm-taste-1]\nschalten.send = \"1/2/3\"\n"),
        )?;
        Ok(())
    };

    let (dir, report, _) = reimport("mine", &base, add, &base, Side::Mine)?;
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "links/1.1.17#65" && c.field == "send" && c.ours == "1/2/3"),
        "{:?}",
        report.conflicts
    );
    let text = fs::read_to_string(dir.join("devices/1.1.17.toml"))?;
    assert!(text.contains("schalten.send = \"1/2/3\""), "{text}");
    let _ = fs::remove_dir_all(&dir);

    let (dir, _, fresh_files) = reimport("mine-theirs", &base, add, &base, Side::Theirs)?;
    assert_same_as_fresh(&dir, &fresh_files)?;
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A re-import writes the same bytes as a fresh import of the same project,
/// even when the file on disk came from an older writer: sections in another
/// order (`[security]` after the channels) and a parameter under its
/// `<slug>@<ref>` escape key that the lock now names.
#[test]
fn test_reimport_writes_the_same_bytes_as_a_fresh_import() -> anyhow::Result<()> {
    let mut device = push_button(&[]);
    device
        .device
        .parameters
        .insert("regenalarm@P-9_R-9".to_string(), "1".to_string());
    let first = with_links(device.clone(), vec![link(73, Some("4/2/20"), &[])]);
    let mut named = device;
    named.device.lock.parameters.insert(
        "P-9_R-9".to_string(),
        LockedParameter {
            key: "regenalarm".to_string(),
            channel: None,
            param: None,
        },
    );
    let fresh = with_links(named, vec![link(73, Some("4/2/20"), &[])]);
    let older = |dir: &std::path::Path| -> anyhow::Result<()> {
        let path = dir.join("devices/1.1.17.toml");
        let text = fs::read_to_string(&path)?;
        let security = "[security]\nactivated = true\nsecure_commissioning = true\n\n";
        anyhow::ensure!(text.contains(security), "{text}");
        let moved = format!("{}\n{}", text.replace(security, ""), security.trim_end());
        fs::write(&path, format!("{moved}\n"))?;
        Ok(())
    };
    let (dir, report, fresh_files) = reimport("bytes", &first, older, &fresh, Side::Theirs)?;
    assert!(!report.has_conflicts(), "{:?}", report.conflicts);
    assert_same_as_fresh(&dir, &fresh_files)?;
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}
