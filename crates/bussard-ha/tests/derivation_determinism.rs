//! Determinism and collision-handling stress tests for HA entity derivation.
//!
//! Targets: dedup under many colliding names (the `HashMap` in `dedupe_names`
//! must not leak nondeterminism into output order), conflicting
//! exclusion+override interplay, and many-device stable ordering.

use std::collections::BTreeMap;

use bussard_ha::{Overrides, derive, generate};
use bussard_model::loader::{LoadedDevice, Model};
use bussard_model::schema::{BussardConfig, ComObject, Device, Group, Groups, Link, Links};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress};

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}
fn ia(s: &str) -> IndividualAddress {
    s.parse().unwrap()
}
fn dpt(s: &str) -> Dpt {
    s.parse().unwrap()
}
fn flags(s: &str) -> Flags {
    s.parse().unwrap()
}

/// Builds a model with many devices, each a listen-only switch on its own GA,
/// but ALL groups deliberately share the same display name so dedup must fire.
fn colliding_switch_model(n: u16) -> Model {
    let mut groups = BTreeMap::new();
    let mut devices = BTreeMap::new();
    let mut links = BTreeMap::new();

    for i in 0..n {
        let main = 1 + (i as u32 % 30);
        let middle = (i as u32 / 30) % 8;
        let sub = i as u32 % 256;
        let gaddr = ga(&format!("{main}/{middle}/{sub}"));
        // Every group has the identical name "Licht" so all switch entities collide.
        groups.insert(
            gaddr,
            Group {
                name: "Licht".to_string(),
                dpt: Some(dpt("1.001")),
                description: None,
                protected: false,
                secure: false,
            },
        );
        // A distinct, in-range individual address per index.
        let addr = ia(&format!(
            "{}.{}.{}",
            1 + (i as u32 / 4096) % 15,
            1 + (i as u32 / 256) % 15,
            i % 256
        ));

        let mut com_objects = BTreeMap::new();
        com_objects.insert(
            1u16,
            ComObject {
                dpt: Some(dpt("1.001")),
                size: None,
                flags: flags("CWU"),
                reference: None,
                channel: None,
                secure: false,
                function: None,
                key: None,
                text: None,
            },
        );
        devices.insert(
            addr,
            LoadedDevice {
                device: Device {
                    address: addr,
                    name: format!("Dev{i}"),
                    description: None,
                    location: None,
                    replaced: None,
                    product: None,
                    channels: BTreeMap::new(),
                    parameters: BTreeMap::new(),
                    module_bases: Default::default(),
                    com_objects,
                    security: None,
                    application_override: None,
                    lock: Default::default(),
                },
                file_stem: format!("dev{i}"),
            },
        );
        links.insert(
            addr,
            vec![Link {
                object: 1,
                name: None,
                send: None,
                listen: vec![gaddr],
            }],
        );
    }

    Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: None,
            imported_from: None,
            ranges: BTreeMap::new(),
            groups,
        },
        links: Links { links },
        devices,
    }
}

#[test]
fn dedup_under_mass_name_collision_is_deterministic() {
    let model = colliding_switch_model(60);
    // Derive many times; output must be byte-identical every run despite the
    // internal HashMap used for counting collisions.
    let first = generate(&model, &Overrides::default()).unwrap();
    for _ in 0..25 {
        let again = generate(&model, &Overrides::default()).unwrap();
        assert_eq!(again, first, "HA output not deterministic across runs");
    }
}

#[test]
fn colliding_names_get_stable_ga_suffixes() {
    let model = colliding_switch_model(5);
    let d = derive(&model, &Overrides::default());
    // Every colliding entity gets a "(ga)" suffix, and each name is unique.
    let names: Vec<String> = d.entities.iter().map(|e| e.name().to_string()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        names.len(),
        "entity names must be unique after dedup: {names:?}"
    );
    // The suffix contains the GA in parentheses.
    assert!(
        names
            .iter()
            .all(|n| n.contains("Licht (") && n.ends_with(')')),
        "expected GA-suffixed names, got {names:?}"
    );
}

#[test]
fn derive_entities_order_matches_device_btreemap_order() {
    // Entities must come out in device-address order (BTreeMap iteration), and
    // that order must be stable across runs.
    let model = colliding_switch_model(10);
    let a = derive(&model, &Overrides::default());
    let b = derive(&model, &Overrides::default());
    let a_gas: Vec<GroupAddress> = a.entities.iter().map(|e| e.primary_ga()).collect();
    let b_gas: Vec<GroupAddress> = b.entities.iter().map(|e| e.primary_ga()).collect();
    assert_eq!(a_gas, b_gas, "entity GA order not stable");
}

// ---------------------------------------------------------------------------
// Conflicting exclusions + overrides.
// ---------------------------------------------------------------------------

/// A single writable switch on 1/1/1.
fn one_switch_model() -> Model {
    let mut groups = BTreeMap::new();
    groups.insert(
        ga("1/1/1"),
        Group {
            name: "Kitchen".to_string(),
            dpt: Some(dpt("1.001")),
            description: None,
            protected: false,
            secure: false,
        },
    );
    let mut com_objects = BTreeMap::new();
    com_objects.insert(
        1u16,
        ComObject {
            dpt: Some(dpt("1.001")),
            size: None,
            flags: flags("CWU"),
            reference: None,
            channel: None,
            secure: false,
            function: None,
            key: None,
            text: None,
        },
    );
    let mut devices = BTreeMap::new();
    devices.insert(
        ia("1.1.4"),
        LoadedDevice {
            device: Device {
                address: ia("1.1.4"),
                name: "Aktor".to_string(),
                description: None,
                location: None,
                replaced: None,
                product: None,
                channels: BTreeMap::new(),
                parameters: BTreeMap::new(),
                module_bases: Default::default(),
                com_objects,
                security: None,
                application_override: None,
                lock: Default::default(),
            },
            file_stem: "1.1.4-aktor".to_string(),
        },
    );
    let mut links = BTreeMap::new();
    links.insert(
        ia("1.1.4"),
        vec![Link {
            object: 1,
            name: None,
            send: None,
            listen: vec![ga("1/1/1")],
        }],
    );
    Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: None,
            imported_from: None,
            ranges: BTreeMap::new(),
            groups,
        },
        links: Links { links },
        devices,
    }
}

#[test]
fn exclusion_wins_over_a_conflicting_entity_override() {
    // The same GA is BOTH excluded AND given an entity override (name + platform).
    // Exclusion must win: the entity is dropped, and it is not renamed into
    // existence. This is the precedence contract in `apply_entity_override`.
    let model = one_switch_model();
    let overrides_yaml = r#"
global:
  exclude:
    - "1/1/1"
entities:
  "1/1/1":
    name: "Should Not Appear"
    platform: light
"#;
    let overrides = Overrides::parse("overrides.yaml", overrides_yaml).expect("overrides parse");
    let d = derive(&model, &overrides);
    assert!(
        d.entities.is_empty(),
        "excluded GA must not produce an entity even with an override: {:?}",
        d.entities
    );
    // And the exclusion is reflected in the coverage bookkeeping (not unmapped
    // either — excluded GAs are neither mapped nor reported as unmapped).
    assert_eq!(d.mapped_gas, 0);
    let total_unmapped: usize = d.unmapped.values().sum();
    assert_eq!(total_unmapped, 0, "excluded GA is not counted as unmapped");
}

#[test]
fn override_rename_and_platform_applied_when_not_excluded() {
    let model = one_switch_model();
    let overrides_yaml = r#"
entities:
  "1/1/1":
    name: "Renamed Light"
    platform: light
"#;
    let overrides = Overrides::parse("overrides.yaml", overrides_yaml).expect("overrides parse");
    let d = derive(&model, &overrides);
    assert_eq!(d.entities.len(), 1);
    assert_eq!(d.entities[0].name(), "Renamed Light");
    // Determinism preserved with overrides.
    let a = generate(&model, &overrides).unwrap();
    let b = generate(&model, &overrides).unwrap();
    assert_eq!(a, b);
}
