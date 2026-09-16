//! Heuristic derivation tests over small, fabricated models.
//!
//! Every model here is hand-built (never copied from the real `knx/` fixture)
//! so the assertions are legible and stable. Each test targets one heuristic:
//! cover assembly, switch/light, brightness promotion, sensor typing,
//! binary_sensor, exclusions, override precedence, unmapped reporting, and
//! determinism.

use std::collections::BTreeMap;

use bussard_ha::{Overrides, derive, generate};
use bussard_model::loader::{LoadedDevice, Model};
use bussard_model::schema::{
    BussardConfig, ComObject, Device, Group, Groups, Link, Links, Location,
};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress};

// --- builders -------------------------------------------------------------

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

/// A minimal builder for a single-device model.
struct ModelBuilder {
    groups: BTreeMap<GroupAddress, Group>,
    device: Device,
    links: Vec<Link>,
}

impl ModelBuilder {
    fn new(addr: &str, name: &str, room: Option<&str>) -> Self {
        Self {
            groups: BTreeMap::new(),
            device: Device {
                address: ia(addr),
                name: name.to_string(),
                description: None,
                location: room.map(|r| Location {
                    floor: None,
                    room: Some(r.to_string()),
                }),
                product: None,
                channels: BTreeMap::new(),
                parameters: BTreeMap::new(),
                com_objects: BTreeMap::new(),
            },
            links: Vec::new(),
        }
    }

    fn group(mut self, addr: &str, name: &str, d: &str) -> Self {
        self.groups.insert(
            ga(addr),
            Group {
                name: name.to_string(),
                dpt: Some(dpt(d)),
                description: None,
                ..Default::default()
            },
        );
        self
    }

    /// Adds a com-object and its link in one call.
    fn object(
        mut self,
        number: u16,
        d: &str,
        fl: &str,
        channel: Option<&str>,
        send: Option<&str>,
        listen: &[&str],
    ) -> Self {
        self.device.com_objects.insert(
            number,
            ComObject {
                dpt: Some(dpt(d)),
                size: None,
                flags: flags(fl),
                reference: None,
                channel: channel.map(str::to_string),
            },
        );
        self.links.push(Link {
            object: number,
            name: Some(format!("obj {number}")),
            send: send.map(ga),
            listen: listen.iter().map(|s| ga(s)).collect(),
        });
        self
    }

    fn build(self) -> Model {
        let mut devices = BTreeMap::new();
        let addr = self.device.address;
        devices.insert(
            addr,
            LoadedDevice {
                device: self.device,
                file_stem: "dev".to_string(),
            },
        );
        let mut links = BTreeMap::new();
        links.insert(addr, self.links);
        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups: self.groups,
            },
            links: Links { links },
            devices,
        }
    }
}

// --- tests ----------------------------------------------------------------

#[test]
fn cover_cluster_assembly() {
    // A jalousie channel: 1.008 up/down (W), 1.007 step/stop (W),
    // 5.001 position setpoint (W), 5.001 position status (T).
    let model = ModelBuilder::new("1.1.4", "Aktor", Some("Wohnzimmer"))
        .group("1/2/0", "Raffstore Wohnen Auf/Ab", "1.008")
        .group("1/2/1", "Raffstore Wohnen Schritt", "1.007")
        .group("1/2/2", "Raffstore Wohnen Position", "5.001")
        .group("1/2/3", "Raffstore Wohnen Position Status", "5.001")
        .object(20, "1.008", "CWU", Some("A"), None, &["1/2/0"])
        .object(21, "1.007", "CWU", Some("A"), None, &["1/2/1"])
        .object(22, "5.001", "CWU", Some("A"), None, &["1/2/2"])
        .object(38, "5.001", "CRTU", Some("A"), Some("1/2/3"), &[])
        .build();

    let d = derive(&model, &Overrides::default());
    assert_eq!(d.entities.len(), 1, "one cover entity");
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("cover:"));
    assert!(yaml.contains("move_long_address: 1/2/0"));
    assert!(yaml.contains("move_short_address: 1/2/1"));
    assert!(yaml.contains("position_address: 1/2/2"));
    assert!(yaml.contains("position_state_address: 1/2/3"));
    // Raffstore -> blind device_class.
    assert!(yaml.contains("device_class: blind"));
}

#[test]
fn switch_with_status() {
    let model = ModelBuilder::new("1.1.5", "Schaltaktor", Some("Küche"))
        .group("0/0/1", "Licht Küche schalten", "1.001")
        .group("0/0/2", "Licht Küche Status", "1.001")
        .object(1, "1.001", "CWU", Some("A"), None, &["0/0/1"])
        .object(2, "1.001", "CRTU", Some("A"), Some("0/0/2"), &[])
        .build();

    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("switch:"));
    assert!(yaml.contains("address: 0/0/1"));
    assert!(yaml.contains("state_address: 0/0/2"));
    assert!(!yaml.contains("light:"));
}

#[test]
fn dimmer_channel_becomes_light_with_brightness() {
    // 1.001 switch (W) + 1.001 status (T) + 5.001 brightness (W) + 5.001
    // brightness status (T) on one channel -> a light with brightness.
    let model = ModelBuilder::new("1.1.8", "Dimmaktor", Some("Wohnen"))
        .group("1/1/0", "Licht schalten", "1.001")
        .group("1/1/1", "Licht Status", "1.001")
        .group("1/1/3", "Licht Helligkeit", "5.001")
        .group("1/1/4", "Licht Helligkeit Status", "5.001")
        .object(31, "1.001", "CWU", Some("CH-1"), None, &["1/1/0"])
        .object(32, "1.001", "CRTU", Some("CH-1"), Some("1/1/1"), &[])
        .object(35, "5.001", "CWU", Some("CH-1"), None, &["1/1/3"])
        .object(36, "5.001", "CRTU", Some("CH-1"), Some("1/1/4"), &[])
        .build();

    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("light:"));
    assert!(yaml.contains("brightness_address: 1/1/3"));
    assert!(yaml.contains("brightness_state_address: 1/1/4"));
    assert!(!yaml.contains("switch:"));
}

#[test]
fn sensor_typing_by_dpt() {
    let model = ModelBuilder::new("1.1.202", "Wetterstation", Some("Dach"))
        .group("4/1/0", "Temperatur", "9.001")
        .group("4/1/1", "Helligkeit", "9.004")
        .group("4/1/2", "Windgeschwindigkeit", "9.005")
        .group("4/1/3", "Luftfeuchte", "9.007")
        .object(0, "9.001", "CRT", None, Some("4/1/0"), &[])
        .object(1, "9.004", "CRT", None, Some("4/1/1"), &[])
        .object(2, "9.005", "CRT", None, Some("4/1/2"), &[])
        .object(3, "9.007", "CRT", None, Some("4/1/3"), &[])
        .build();

    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("type: temperature"));
    assert!(yaml.contains("type: illuminance"));
    assert!(yaml.contains("type: wind_speed_ms"));
    assert!(yaml.contains("type: humidity"));
}

#[test]
fn binary_sensor_device_class_from_dpt_and_name() {
    let model = ModelBuilder::new("1.1.30", "Wetterstation", None)
        .group("3/2/0", "Windalarm", "1.005")
        .group("4/2/0", "Fenster Bad", "1.019")
        .object(3, "1.005", "CRT", None, Some("3/2/0"), &[])
        .object(4, "1.019", "CRT", None, Some("4/2/0"), &[])
        .build();

    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("binary_sensor:"));
    // 1.005 alarm -> problem; 1.019 -> window.
    assert!(yaml.contains("device_class: problem"), "{yaml}");
    assert!(yaml.contains("device_class: window"), "{yaml}");
}

#[test]
fn exclusions_skip_gas() {
    let model = ModelBuilder::new("1.1.5", "Aktor", None)
        .group("0/0/1", "Licht schalten", "1.001")
        .group("8/0/0", "Zentral", "1.001")
        .object(1, "1.001", "CWU", None, None, &["0/0/1"])
        .object(2, "1.001", "CWU", None, None, &["8/0/0"])
        .build();

    let text = "global:\n  exclude:\n    - \"8/\"\n";
    let ov = Overrides::parse("ha.yaml", text).unwrap();
    let d = derive(&model, &ov);
    assert_eq!(d.entities.len(), 1, "the 8/ GA is excluded");
    // Excluded GAs are not counted as unmapped either.
    assert!(!d.unmapped.contains_key(&Some(1)) || d.unmapped[&Some(1)] == 0);
    let yaml = generate(&model, &ov).unwrap();
    assert!(!yaml.contains("8/0/0"));
}

#[test]
fn override_promotes_switch_to_light_and_renames() {
    let model = ModelBuilder::new("1.1.5", "Aktor", None)
        .group("0/0/1", "Licht schalten", "1.001")
        .object(1, "1.001", "CWU", None, None, &["0/0/1"])
        .build();

    let text = r#"
entities:
  "0/0/1":
    platform: light
    name: "Kitchen ceiling"
    device_class: outlet
"#;
    let ov = Overrides::parse("ha.yaml", text).unwrap();
    let yaml = generate(&model, &ov).unwrap();
    assert!(yaml.contains("light:"), "{yaml}");
    assert!(yaml.contains("name: Kitchen ceiling"));
    assert!(!yaml.contains("switch:"));
}

#[test]
fn global_default_light_platform() {
    let model = ModelBuilder::new("1.1.5", "Aktor", None)
        .group("0/0/1", "Licht schalten", "1.001")
        .object(1, "1.001", "CWU", None, None, &["0/0/1"])
        .build();

    let ov = Overrides::parse(
        "ha.yaml",
        "global:\n  default_platform_for_switches: light\n",
    )
    .unwrap();
    let yaml = generate(&model, &ov).unwrap();
    assert!(yaml.contains("light:"));
    assert!(!yaml.contains("switch:"));
}

#[test]
fn unmapped_reporting() {
    // A 20.102 HVAC-mode GA and an unnamed-DPT GA both unmap.
    let model = ModelBuilder::new("1.1.2", "Heizung", None)
        .group("0/3/1", "Betriebsart", "20.102")
        .object(1, "20.102", "CWU", None, None, &["0/3/1"])
        .build();

    let d = derive(&model, &Overrides::default());
    assert_eq!(d.entities.len(), 0);
    assert_eq!(d.unmapped.get(&Some(20)).copied(), Some(1));
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("# unmapped:"));
    assert!(yaml.contains("dpt 20: 1"));
}

#[test]
fn determinism_two_runs_byte_equal() {
    let model = ModelBuilder::new("1.1.5", "Aktor", Some("Küche"))
        .group("0/0/1", "Licht A", "1.001")
        .group("0/0/3", "Licht B", "1.001")
        .group("4/1/0", "Temp", "9.001")
        .object(1, "1.001", "CWU", None, None, &["0/0/1"])
        .object(3, "1.001", "CWU", None, None, &["0/0/3"])
        .object(5, "9.001", "CRT", None, Some("4/1/0"), &[])
        .build();

    let a = generate(&model, &Overrides::default()).unwrap();
    let b = generate(&model, &Overrides::default()).unwrap();
    assert_eq!(a, b, "output must be byte-identical across runs");
    // Header present, footer present.
    assert!(a.starts_with("# generated by bussard ha-config"));
    assert!(a.contains("# summary"));
}

#[test]
fn no_duplicate_entity_for_shared_command_ga() {
    // An actuator switches 0/0/1 (W) and reports 0/0/2 (T). A push-button module
    // *sends* 0/0/1 (T). Only one switch entity should result, not a switch plus
    // a binary_sensor on 0/0/1.
    let mut model = ModelBuilder::new("1.1.5", "Aktor", None)
        .group("0/0/1", "Licht schalten", "1.001")
        .group("0/0/2", "Licht Status", "1.001")
        .object(1, "1.001", "CWU", Some("A"), None, &["0/0/1"])
        .object(2, "1.001", "CRTU", Some("A"), Some("0/0/2"), &[])
        .build();

    // Add a push-button device sending 0/0/1.
    let pb = Device {
        address: ia("1.1.10"),
        name: "Taster".to_string(),
        description: None,
        location: None,
        product: None,
        channels: BTreeMap::new(),
        parameters: BTreeMap::new(),
        com_objects: {
            let mut m = BTreeMap::new();
            m.insert(
                7,
                ComObject {
                    dpt: Some(dpt("1.001")),
                    size: None,
                    flags: flags("CRT"),
                    reference: None,
                    channel: None,
                },
            );
            m
        },
    };
    model.devices.insert(
        ia("1.1.10"),
        LoadedDevice {
            device: pb,
            file_stem: "pb".to_string(),
        },
    );
    model.links.links.insert(
        ia("1.1.10"),
        vec![Link {
            object: 7,
            name: None,
            send: Some(ga("0/0/1")),
            listen: vec![],
        }],
    );

    let d = derive(&model, &Overrides::default());
    assert_eq!(d.entities.len(), 1, "exactly one entity for the shared GA");
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("switch:"));
    assert!(!yaml.contains("binary_sensor:"));
}

#[test]
fn yaml_round_trips() {
    let model = ModelBuilder::new("1.1.4", "Aktor", Some("Wohnen"))
        .group("1/2/0", "Raffstore Auf/Ab", "1.008")
        .group("1/2/1", "Raffstore Schritt", "1.007")
        .group("4/1/0", "Temp", "9.001")
        .object(20, "1.008", "CWU", Some("A"), None, &["1/2/0"])
        .object(21, "1.007", "CWU", Some("A"), None, &["1/2/1"])
        .object(5, "9.001", "CRT", None, Some("4/1/0"), &[])
        .build();

    let yaml = generate(&model, &Overrides::default()).unwrap();
    // The emitted YAML must parse back cleanly (comments are ignored by YAML).
    let value: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
    assert!(value.get("knx").is_some(), "top-level knx key present");
}

#[test]
fn merge_attaches_ga_and_clears_unmapped() {
    // A switch on 0/0/1 with no derived state GA. An unmapped 1.001 status GA
    // 0/0/9 (belonging to no object) is merged onto the switch: it must become
    // the switch's state_address and drop out of the unmapped summary.
    let model = ModelBuilder::new("1.1.5", "Aktor", None)
        .group("0/0/1", "Licht schalten", "1.001")
        .group("0/0/9", "Licht Status extern", "1.001")
        .object(1, "1.001", "CWU", None, None, &["0/0/1"])
        .build();

    let text = r#"
entities:
  "0/0/1":
    merge: ["0/0/9"]
"#;
    let ov = Overrides::parse("ha.yaml", text).unwrap();
    let d = derive(&model, &ov);
    // The merged GA is now consumed, so nothing 1.x remains unmapped.
    assert!(
        d.unmapped.get(&Some(1)).copied().unwrap_or(0) == 0,
        "merged GA should not be unmapped: {:?}",
        d.unmapped
    );
    let yaml = generate(&model, &ov).unwrap();
    assert!(yaml.contains("switch:"), "{yaml}");
    // 0/0/9 wired as the free state slot.
    assert!(yaml.contains("state_address: 0/0/9"), "{yaml}");
}

#[test]
fn exclusion_wins_over_merge_and_warns_unmapped() {
    // 0/0/9 is both listed in `merge` and excluded by prefix "0/0/9". Exclusion
    // wins: the merge is ignored. Because the GA is excluded it also does NOT
    // appear in the unmapped footer (exclusions are dropped from that summary),
    // and it is never wired as a state address.
    let model = ModelBuilder::new("1.1.5", "Aktor", None)
        .group("0/0/1", "Licht schalten", "1.001")
        .group("0/0/9", "Licht Status extern", "1.001")
        .object(1, "1.001", "CWU", None, None, &["0/0/1"])
        .build();

    let text = r#"
global:
  exclude:
    - "0/0/9"
entities:
  "0/0/1":
    merge: ["0/0/9"]
"#;
    let ov = Overrides::parse("ha.yaml", text).unwrap();
    let yaml = generate(&model, &ov).unwrap();
    // Exclusion wins: the excluded GA is never wired.
    assert!(
        !yaml.contains("0/0/9"),
        "excluded GA must not appear: {yaml}"
    );
    // And excluded GAs are not counted as unmapped.
    let d = derive(&model, &ov);
    assert_eq!(
        d.unmapped.get(&Some(1)).copied().unwrap_or(0),
        0,
        "excluded GA is neither mapped nor unmapped"
    );
}

#[test]
fn cover_requires_command_ga_not_a_button_sender() {
    // An actuator owns the cover channel: 1.008 up/down command (W). A separate
    // push-button *sends* 1.008 on a different GA (T-only). The button must not
    // anchor a cover of its own; only the actuator's cover is produced.
    let mut model = ModelBuilder::new("1.1.4", "Jalousieaktor", Some("Wohnen"))
        .group("1/2/0", "Raffstore Auf/Ab", "1.008")
        .object(20, "1.008", "CWU", Some("A"), None, &["1/2/0"])
        .build();

    // Push-button that only transmits a 1.008 up/down telegram on 1/2/5.
    model = {
        let pb = Device {
            address: ia("1.1.10"),
            name: "Taster".to_string(),
            description: None,
            location: None,
            product: None,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            com_objects: {
                let mut m = BTreeMap::new();
                m.insert(
                    7,
                    ComObject {
                        dpt: Some(dpt("1.008")),
                        size: None,
                        flags: flags("CRT"),
                        reference: None,
                        channel: None,
                    },
                );
                m
            },
        };
        model.devices.insert(
            ia("1.1.10"),
            LoadedDevice {
                device: pb,
                file_stem: "pb".to_string(),
            },
        );
        model.groups.groups.insert(
            ga("1/2/5"),
            Group {
                name: "Taster Auf/Ab".to_string(),
                dpt: Some(dpt("1.008")),
                description: None,
                ..Default::default()
            },
        );
        model.links.links.insert(
            ia("1.1.10"),
            vec![Link {
                object: 7,
                name: None,
                send: Some(ga("1/2/5")),
                listen: vec![],
            }],
        );
        model
    };

    let d = derive(&model, &Overrides::default());
    let covers: Vec<_> = d
        .entities
        .iter()
        .filter(|e| matches!(e, bussard_ha::entities::Entity::Cover(_)))
        .collect();
    assert_eq!(covers.len(), 1, "only the actuator anchors a cover");
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("move_long_address: 1/2/0"), "{yaml}");
    // The button's send-only GA does not become a second cover.
    assert!(!yaml.contains("move_long_address: 1/2/5"), "{yaml}");
}

#[test]
fn cover_wires_position_5001_and_angle_5003() {
    // A jalousie channel with a 5.001 position (command + state) AND a 5.003 slat
    // angle (command + state). Position and angle must land in their own slots,
    // never cross-mapped.
    let model = ModelBuilder::new("1.1.4", "Aktor", Some("Wohnen"))
        .group("1/2/0", "Raffstore Auf/Ab", "1.008")
        .group("1/2/2", "Raffstore Position", "5.001")
        .group("1/2/3", "Raffstore Position Status", "5.001")
        .group("1/2/4", "Raffstore Lamelle", "5.003")
        .group("1/2/5", "Raffstore Lamelle Status", "5.003")
        .object(20, "1.008", "CWU", Some("A"), None, &["1/2/0"])
        .object(22, "5.001", "CWU", Some("A"), None, &["1/2/2"])
        .object(23, "5.001", "CRTU", Some("A"), Some("1/2/3"), &[])
        .object(24, "5.003", "CWU", Some("A"), None, &["1/2/4"])
        .object(25, "5.003", "CRTU", Some("A"), Some("1/2/5"), &[])
        .build();

    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("position_address: 1/2/2"), "{yaml}");
    assert!(yaml.contains("position_state_address: 1/2/3"), "{yaml}");
    assert!(yaml.contains("angle_address: 1/2/4"), "{yaml}");
    assert!(yaml.contains("angle_state_address: 1/2/5"), "{yaml}");
    // The 5.003 angle GAs must not have been mis-wired as position.
    assert!(!yaml.contains("position_address: 1/2/4"), "{yaml}");
}

// --- climate --------------------------------------------------------------

use bussard_ha::entities::{Climate, Entity};

/// Adds a climate room's group addresses to a builder (name-based; climate is
/// correlated by room name, so no com-objects are required for these GAs).
fn climate_room(mut b: ModelBuilder, room: &str, base: &str) -> ModelBuilder {
    // base like "0/3/" so we can lay out a room at contiguous addresses.
    let g = |b: ModelBuilder, off: u16, suffix: &str, d: &str| -> ModelBuilder {
        b.group(&format!("{base}{off}"), &format!("{room} {suffix}"), d)
    };
    b = g(b, 0, "Isttemperatur", "9.001");
    b = g(b, 1, "Solltemperatur Basis", "9.001");
    b = g(b, 2, "Betriebsmodus Vorgabe", "20.102");
    b = g(b, 3, "Betriebsmodus Zwang", "20.102");
    b = g(b, 4, "Soll-Temperatur aktuell", "9.001");
    b = g(b, 5, "Sollwertverschiebung", "9.002");
    b = g(b, 6, "Stellgröße Heizen/Kühlen", "5.001");
    b = g(b, 8, "Sollwertverschiebung Status", "9.002");
    b
}

fn only_climate(model: &Model, ov: &Overrides) -> Vec<Climate> {
    derive(model, ov)
        .entities
        .into_iter()
        .filter_map(|e| match e {
            Entity::Climate(c) => Some(c),
            _ => None,
        })
        .collect()
}

#[test]
fn climate_full_cluster_central_heating_mapping() {
    // Central-heating installation: the operation mode (Betriebsmodus) is the
    // control; temperature and valve are read-only telemetry. Setpoint shift and
    // target temperature are deliberately NOT wired (no HA key that invites a
    // temperature change).
    let model = climate_room(
        ModelBuilder::new("1.1.2", "Heizung", None),
        "Büro UG",
        "0/3/",
    )
    .build();
    let cs = only_climate(&model, &Overrides::default());
    assert_eq!(cs.len(), 1);
    let c = &cs[0];
    // The control.
    assert_eq!(c.operation_mode_address, Some(ga("0/3/2")));
    // Read-only telemetry.
    assert_eq!(c.temperature_address, Some(ga("0/3/0")));
    assert_eq!(c.command_value_state_address, Some(ga("0/3/6")));
    // Deliberately unwired.
    assert_eq!(c.setpoint_shift_address, None);
    assert_eq!(c.setpoint_shift_state_address, None);
    assert_eq!(c.setpoint_shift_mode, None);
    assert_eq!(c.target_temperature_state_address, None);
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("climate:"), "{yaml}");
    assert!(
        !yaml.contains("setpoint_shift"),
        "no setpoint wiring: {yaml}"
    );
    assert!(
        !yaml.contains("target_temperature"),
        "no target temp: {yaml}"
    );
}

#[test]
fn climate_minimal_mode_only_anchors() {
    // A room with only an operation-mode command still anchors a climate entity.
    let model = ModelBuilder::new("1.1.2", "Heizung", None)
        .group("0/3/2", "Büro UG Betriebsmodus Vorgabe", "20.102")
        .build();
    let cs = only_climate(&model, &Overrides::default());
    assert_eq!(cs.len(), 1);
    assert_eq!(cs[0].operation_mode_address, Some(ga("0/3/2")));
    assert!(cs[0].temperature_address.is_none());
}

#[test]
fn climate_setpoint_shift_alone_does_not_anchor() {
    // Setpoint shift is not a control in a central-heating install, so a
    // setpoint-shift GA alone (no operation mode) does NOT anchor a climate
    // entity — it falls through to the sensor pass.
    let model = ModelBuilder::new("1.1.2", "Heizung", None)
        .group("0/3/5", "Büro UG Sollwertverschiebung", "9.002")
        .object(1, "9.002", "CRT", None, Some("0/3/5"), &[])
        .build();
    assert!(only_climate(&model, &Overrides::default()).is_empty());
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(!yaml.contains("climate:"), "{yaml}");
    // It became a plain 2-byte-float sensor instead.
    assert!(yaml.contains("sensor:"), "{yaml}");
}

#[test]
fn climate_lone_temperature_does_not_anchor() {
    // A room with only a temperature GA (no mode, no shift) is NOT a climate
    // entity; it falls through to the sensor pass.
    let model = ModelBuilder::new("1.1.2", "Fühler", None)
        .group("0/3/0", "Küche Isttemperatur", "9.001")
        .object(1, "9.001", "CRT", None, Some("0/3/0"), &[])
        .build();
    assert!(only_climate(&model, &Overrides::default()).is_empty());
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(!yaml.contains("climate:"), "{yaml}");
    // It became a temperature sensor instead.
    assert!(yaml.contains("type: temperature"), "{yaml}");
}

#[test]
fn climate_temperature_correlation_hit_and_miss() {
    // Two rooms share one model. Room A has a mode command (anchors) and a
    // temperature that correlates by name. Room B has only a temperature (no
    // anchor) -> its temperature must NOT be pulled into room A.
    let model = ModelBuilder::new("1.1.2", "Heizung", None)
        .group("0/3/2", "Büro UG Betriebsmodus Vorgabe", "20.102")
        .group("0/3/0", "Büro UG Isttemperatur", "9.001")
        .group("0/3/20", "Garage Isttemperatur", "9.001")
        .object(9, "9.001", "CRT", None, Some("0/3/20"), &[])
        .build();
    let cs = only_climate(&model, &Overrides::default());
    assert_eq!(cs.len(), 1);
    // Correlation hit: Büro UG temperature wired.
    assert_eq!(cs[0].temperature_address, Some(ga("0/3/0")));
    // Correlation miss: Garage temperature is a different room -> not wired here.
    assert_ne!(cs[0].temperature_address, Some(ga("0/3/20")));
    // And it survives as its own sensor.
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(yaml.contains("state_address: 0/3/20"), "{yaml}");
}

#[test]
fn climate_zwang_recognised_unwired_and_noted() {
    // The forced-mode (Zwang) GA is recognised but has no HA schema key: it is
    // left unwired (still counted as unmapped dpt-20) and surfaced as a footer
    // note.
    let model = ModelBuilder::new("1.1.2", "Heizung", None)
        .group("0/3/2", "Büro UG Betriebsmodus Vorgabe", "20.102")
        .group("0/3/3", "Büro UG Betriebsmodus Zwang", "20.102")
        .build();
    let d = derive(&model, &Overrides::default());
    // Zwang is not wired onto the climate entity.
    let cs: Vec<_> = d
        .entities
        .iter()
        .filter_map(|e| match e {
            Entity::Climate(c) => Some(c),
            _ => None,
        })
        .collect();
    assert_eq!(cs.len(), 1);
    assert!(
        !Entity::Climate(cs[0].clone())
            .all_gas()
            .contains(&ga("0/3/3"))
    );
    // Zwang remains unmapped (dpt 20) and a note is emitted.
    assert_eq!(d.unmapped.get(&Some(20)).copied(), Some(1));
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(
        yaml.contains("# note: climate 'Büro UG': forced-mode"),
        "{yaml}"
    );
    assert!(yaml.contains("dpt 20: 1"), "{yaml}");
}

#[test]
fn climate_claims_valve_before_percent_sensor() {
    // The 5.001 valve GA is *sent* by a heating-actuator object, so without the
    // climate pass it would become a `percent` sensor. Climate runs first and
    // claims it — no percent sensor on that GA.
    let model = ModelBuilder::new("1.1.2", "Heizaktor", None)
        .group("0/3/2", "Büro UG Betriebsmodus Vorgabe", "20.102")
        .group("0/3/6", "Büro UG Stellgröße Heizen/Kühlen", "5.001")
        .object(21, "5.001", "CRT", None, Some("0/3/6"), &[])
        .build();
    let d = derive(&model, &Overrides::default());
    // Valve is the climate command_value_state_address.
    let c = d
        .entities
        .iter()
        .find_map(|e| match e {
            Entity::Climate(c) => Some(c),
            _ => None,
        })
        .unwrap();
    assert_eq!(c.command_value_state_address, Some(ga("0/3/6")));
    // No sensor on 0/3/6.
    let has_percent_sensor = d
        .entities
        .iter()
        .any(|e| matches!(e, Entity::Sensor(s) if s.state_address == ga("0/3/6")));
    assert!(
        !has_percent_sensor,
        "valve must not also be a percent sensor"
    );
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(!yaml.contains("type: percent"), "{yaml}");
}

#[test]
fn climate_determinism_multiple_rooms() {
    let model = climate_room(
        climate_room(
            ModelBuilder::new("1.1.2", "Heizung", None),
            "Büro UG",
            "0/3/",
        ),
        "Schlafen",
        "1/4/",
    )
    .build();
    let a = generate(&model, &Overrides::default()).unwrap();
    let b = generate(&model, &Overrides::default()).unwrap();
    assert_eq!(a, b, "climate output must be byte-identical across runs");
    assert_eq!(only_climate(&model, &Overrides::default()).len(), 2);
}

#[test]
fn climate_name_override_and_exclusion() {
    // Name override applies (keyed by the anchor / operation_mode GA). Excluding
    // the anchor GA drops the whole climate entity.
    let model = climate_room(
        ModelBuilder::new("1.1.2", "Heizung", None),
        "Büro UG",
        "0/3/",
    )
    .build();

    let text = r#"
entities:
  "0/3/2":
    name: "Office climate"
"#;
    let ov = Overrides::parse("ha.yaml", text).unwrap();
    let cs = only_climate(&model, &ov);
    assert_eq!(cs.len(), 1);
    assert_eq!(cs[0].name, "Office climate");

    // Excluding the anchor (operation-mode) GA removes the whole climate entity:
    // the operation mode is the only anchor, so nothing is left to control.
    let ov2 = Overrides::parse("ha.yaml", "global:\n  exclude:\n    - \"0/3/2\"\n").unwrap();
    assert!(only_climate(&model, &ov2).is_empty());
}

#[test]
fn climate_merge_wires_extra_state_ga() {
    // A mode-only room; merge an external target-temperature-state GA. It fills
    // the first free climate state slot (temperature) and drops from unmapped.
    let model = ModelBuilder::new("1.1.2", "Heizung", None)
        .group("0/3/2", "Büro UG Betriebsmodus Vorgabe", "20.102")
        .group("0/3/99", "Büro UG Fühler extern", "9.001")
        .build();
    let text = r#"
entities:
  "0/3/2":
    merge: ["0/3/99"]
"#;
    let ov = Overrides::parse("ha.yaml", text).unwrap();
    let cs = only_climate(&model, &ov);
    assert_eq!(cs.len(), 1);
    assert_eq!(cs[0].temperature_address, Some(ga("0/3/99")));
    let d = derive(&model, &ov);
    assert_eq!(
        d.unmapped.get(&Some(9)).copied().unwrap_or(0),
        0,
        "merged GA claimed"
    );
}

#[test]
fn status_only_object_is_not_a_switch() {
    // A 1.001 object that only transmits status (T, no W) must not become a
    // switch — it is a binary_sensor.
    let model = ModelBuilder::new("1.1.30", "Melder", None)
        .group("4/4/0", "Bewegung", "1.001")
        .object(1, "1.001", "CRT", None, Some("4/4/0"), &[])
        .build();
    let yaml = generate(&model, &Overrides::default()).unwrap();
    assert!(!yaml.contains("switch:"), "{yaml}");
    assert!(yaml.contains("binary_sensor:"), "{yaml}");
}
