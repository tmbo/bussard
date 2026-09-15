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
