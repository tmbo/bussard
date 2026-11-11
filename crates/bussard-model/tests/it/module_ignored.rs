//! Issue #1050: values stored for module refs the configuration does not
//! reach go through the same visibility and ignored-override rule as
//! application refs.
//!
//! The product model is a fabrication: "Funktion" picks one blinds module
//! instance (`MD-3_M-18`) or two switch instances (`MD-4_M-19`, `MD-4_M-20`,
//! whose "Adresse" has a `BaseValue` argument of 5 and 7); "Helligkeit
//! senden" enables a `<Repeat>` of "Anzahl Zusatz" `MD-5` instances. The
//! blinds body places "Fahrzeit" only for "Rollladen" and `<Assign>`s it
//! unconditionally; its "Reserve" is placed nowhere. The switch body has a
//! channel label text parameter. The device runs "1 x Jalousie" with
//! "Betriebsart" = "Jalousie".

use std::collections::BTreeMap;

use bussard_model::device_view::{DeviceAnalysis, IgnoredOverride};
use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-00FA_A-1050-10-0000";

const PRODUCT: &str = r#"{
  "parameters": {
    "P-1": {
      "kind": {"Enum": {"values": [0, 1]}},
      "default": "0",
      "text": "Funktion",
      "labels": [[0, "1 x Jalousie"], [1, "2 x Schalten"]],
      "refs": ["P-1_R-1"],
      "enum_values": [
        {"value": 0, "text": "1 x Jalousie", "default_text": "1 x Jalousie"},
        {"value": 1, "text": "2 x Schalten", "default_text": "2 x Schalten"}
      ]
    },
    "P-2": {
      "kind": {"Enum": {"values": [0, 1]}},
      "default": "0",
      "text": "Helligkeit senden",
      "labels": [[0, "nein"], [1, "ja"]],
      "refs": ["P-2_R-2"],
      "enum_values": [
        {"value": 0, "text": "nein", "default_text": "nein"},
        {"value": 1, "text": "ja", "default_text": "ja"}
      ]
    },
    "P-3": {
      "kind": {"Int": {"min": 0, "max": 9, "signed": false}},
      "default": "1",
      "text": "Anzahl Zusatz",
      "refs": ["P-3_R-3"]
    },
    "MD-3_P-14": {
      "kind": {"Enum": {"values": [1, 2]}},
      "default": "1",
      "text": "Betriebsart",
      "labels": [[1, "Rollladen"], [2, "Jalousie"]],
      "refs": ["MD-3_P-14_R-14"],
      "enum_values": [
        {"value": 1, "text": "Rollladen", "default_text": "Rollladen"},
        {"value": 2, "text": "Jalousie", "default_text": "Jalousie"}
      ]
    },
    "MD-3_P-16": {
      "kind": {"Int": {"min": 0, "max": 255, "signed": false}},
      "default": "0",
      "text": "Fahrzeit",
      "refs": ["MD-3_P-16_R-16"]
    },
    "MD-3_P-17": {
      "kind": {"Int": {"min": 0, "max": 255, "signed": false}},
      "default": "0",
      "text": "Reserve",
      "refs": ["MD-3_P-17_R-17"]
    },
    "MD-4_P-12": {
      "kind": {"Enum": {"values": [0, 1]}},
      "default": "0",
      "text": "Treppenhausfunktion",
      "labels": [[0, "gesperrt"], [1, "freigegeben"]],
      "refs": ["MD-4_P-12_R-12"],
      "enum_values": [
        {"value": 0, "text": "gesperrt", "default_text": "gesperrt"},
        {"value": 1, "text": "freigegeben", "default_text": "freigegeben"}
      ]
    },
    "MD-4_P-13": {
      "kind": {"Int": {"min": 0, "max": 255, "signed": false}},
      "default": "0",
      "text": "Adresse",
      "base_value": "MD-4_A-1",
      "refs": ["MD-4_P-13_R-13"]
    },
    "MD-4_P-18": {
      "kind": {"Text": {"len": 20}},
      "default": "",
      "text": "Kanalname",
      "refs": ["MD-4_P-18_R-18"]
    },
    "MD-5_P-50": {
      "kind": {"Int": {"min": 0, "max": 255, "signed": false}},
      "default": "0",
      "text": "Zusatzwert",
      "refs": ["MD-5_P-50_R-50"]
    }
  },
  "program_id": "M-00FA_A-1050-10-0000",
  "dynamic": [
    {
      "channel": {
        "id": "CH-1",
        "text": "Allgemein",
        "number": 1,
        "nodes": [{"p": "P-1_R-1"}, {"p": "P-2_R-2"}, {"p": "P-3_R-3"}]
      }
    },
    {
      "choose": {
        "ref": "P-1_R-1",
        "when": [
          {"test": "0", "nodes": [{"module": {"id": "MD-3_M-18", "def": "MD-3"}}]},
          {
            "test": "1",
            "nodes": [
              {"module": {"id": "MD-4_M-19", "def": "MD-4", "args": {"MD-4_A-1": 5}}},
              {"module": {"id": "MD-4_M-20", "def": "MD-4", "args": {"MD-4_A-1": 7}}}
            ]
          }
        ]
      }
    },
    {
      "choose": {
        "ref": "P-2_R-2",
        "when": [
          {
            "test": "1",
            "nodes": [
              {
                "repeat": {
                  "id": "X-1",
                  "ref": "P-3_R-3",
                  "nodes": [{"module": {"id": "MD-5_M-30", "def": "MD-5"}}]
                }
              }
            ]
          }
        ]
      }
    }
  ],
  "module_dynamics": {
    "MD-3": [
      {
        "channel": {
          "id": "MD-3_CH-25",
          "text": "Relaisausgänge",
          "number": 25,
          "nodes": [
            {"p": "MD-3_P-14_R-14"},
            {"assign": {"target": "MD-3_P-16_R-16", "value": "9"}},
            {"choose": {"ref": "MD-3_P-14_R-14", "when": [{"test": "1", "nodes": [{"p": "MD-3_P-16_R-16"}]}]}}
          ]
        }
      }
    ],
    "MD-4": [
      {
        "channel": {
          "id": "MD-4_CH-1",
          "text": "Relaisausgang",
          "number": 1,
          "nodes": [{"p": "MD-4_P-18_R-18"}, {"p": "MD-4_P-12_R-12"}, {"p": "MD-4_P-13_R-13"}]
        }
      }
    ],
    "MD-5": [
      {
        "channel": {
          "id": "MD-5_CH-1",
          "text": "Zusatz",
          "number": 1,
          "nodes": [{"p": "MD-5_P-50_R-50"}]
        }
      }
    ]
  },
  "parameter_refs": {
    "P-1_R-1": {"parameter": "P-1"},
    "P-2_R-2": {"parameter": "P-2"},
    "P-3_R-3": {"parameter": "P-3"},
    "MD-3_P-14_R-14": {"parameter": "MD-3_P-14"},
    "MD-3_P-16_R-16": {"parameter": "MD-3_P-16"},
    "MD-3_P-17_R-17": {"parameter": "MD-3_P-17"},
    "MD-4_P-12_R-12": {"parameter": "MD-4_P-12"},
    "MD-4_P-13_R-13": {"parameter": "MD-4_P-13"},
    "MD-4_P-18_R-18": {"parameter": "MD-4_P-18"},
    "MD-5_P-50_R-50": {"parameter": "MD-5_P-50"}
  }
}
"#;

const LOCK: &str = r#"version = 3

[[device]]
address = "1.1.47"
product = "2300"
application = "M-00FA_A-1050-10-0000"
mask = "07B0"
channels = [
  { key = "allgemein-1", id = "CH-1", number = 1, text = "Allgemein" },
  { key = "relaisausgaenge-1", id = "MD-3_M-18_MI-1_CH-25", number = 25, text = "Relaisausgänge" },
  { key = "relaisausgang-1", id = "MD-4_M-19_MI-1_CH-1", number = 1, text = "Relaisausgang", label_ref = "MD-4_M-19_MI-1_P-18_R-18" },
]
parameters = [
  { key = "funktion", channel = "allgemein-1", ref = "P-1_R-1", param = "P-1" },
  { key = "helligkeit-senden", channel = "allgemein-1", ref = "P-2_R-2", param = "P-2" },
  { key = "betriebsart", channel = "relaisausgaenge-1", ref = "MD-3_M-18_MI-1_P-14_R-14", param = "MD-3_P-14" },
]
"#;

const DEVICE: &str = r#"address = "1.1.47"
name = "Jalousieaktor"
product = "2300"

[channel.allgemein-1]
funktion = "1 x Jalousie"

[channel.relaisausgaenge-1]
betriebsart = "Jalousie"
"#;

fn ia() -> Result<IndividualAddress, Box<dyn std::error::Error>> {
    Ok("1.1.47".parse()?)
}

fn products() -> Result<ProductModels, Box<dyn std::error::Error>> {
    let mut products = ProductModels::default();
    products.insert(
        APP.to_string(),
        serde_json::from_str::<ProductModel>(PRODUCT)?,
    );
    Ok(products)
}

/// The model with `stored` added to the device's values (`key@ref` keys).
fn model(stored: &[(&str, &str)]) -> Result<Model, Box<dyn std::error::Error>> {
    let files: BTreeMap<String, String> = [
        ("bussard.lock", LOCK),
        ("devices/1.1.47.toml", DEVICE),
        ("bussard.toml", "[connection]\ntransport = \"tunnel\"\n"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let mut model = Model::from_texts(&files)?;
    let device = &mut model.devices.get_mut(&ia()?).ok_or("no device")?.device;
    for (key, value) in stored {
        device
            .parameters
            .insert((*key).to_string(), (*value).to_string());
    }
    Ok(model)
}

fn ignored(stored: &[(&str, &str)]) -> Result<Vec<IgnoredOverride>, Box<dyn std::error::Error>> {
    let model = model(stored)?;
    Ok(DeviceAnalysis::new(&model, &products()?, ia()?)?.ignored_overrides())
}

#[test]
fn test_ignored_overrides_module_enum_label_at_default_is_not_reported() -> TestResult {
    let at_default = ignored(&[("t@MD-4_M-19_MI-1_P-12_R-12", "gesperrt")])?;
    assert!(at_default.is_empty(), "{at_default:?}");
    let other = ignored(&[("t@MD-4_M-19_MI-1_P-12_R-12", "freigegeben")])?;
    assert_eq!(other.len(), 1, "{other:?}");
    assert_eq!(other[0].value, "freigegeben");
    assert_eq!(other[0].needs, "Funktion = 2 x Schalten");
    Ok(())
}

#[test]
fn test_ignored_overrides_module_default_takes_the_base_value_argument() -> TestResult {
    // `MD-4_M-20` passes 7: its default "Adresse" is 0 + 7.
    let at_default = ignored(&[("a@MD-4_M-20_MI-1_P-13_R-13", "7")])?;
    assert!(at_default.is_empty(), "{at_default:?}");
    let bare = ignored(&[("a@MD-4_M-20_MI-1_P-13_R-13", "0")])?;
    let refs: Vec<&str> = bare.iter().map(|i| i.reference.as_str()).collect();
    assert_eq!(refs, ["MD-4_M-20_MI-1_P-13_R-13"]);
    Ok(())
}

#[test]
fn test_ignored_overrides_module_assign_target_in_a_reached_instance() -> TestResult {
    // The blinds instance is reached and its `<Assign>` sets "Fahrzeit",
    // which "Jalousie" does not show: the image writes the assigned 9.
    let got = ignored(&[("f@MD-3_M-18_MI-1_P-16_R-16", "3")])?;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].needs, "Betriebsart = Rollladen");
    Ok(())
}

#[test]
fn test_ignored_overrides_module_unplaced_ref_is_not_reported() -> TestResult {
    let got = ignored(&[("r@MD-3_M-18_MI-1_P-17_R-17", "4")])?;
    assert!(got.is_empty(), "{got:?}");
    Ok(())
}

#[test]
fn test_ignored_overrides_module_in_a_repeat_names_its_conditions() -> TestResult {
    let got = ignored(&[("z@MD-5_M-30_MI-2_P-50_R-50", "3")])?;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(
        got[0].needs,
        "Helligkeit senden = ja and Anzahl Zusatz >= 2"
    );
    // With the repeat enabled, the second instance still needs the count.
    let got = ignored(&[
        ("z@MD-5_M-30_MI-2_P-50_R-50", "3"),
        ("helligkeit-senden@P-2_R-2", "ja"),
    ])?;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].needs, "Anzahl Zusatz >= 2");
    let got = ignored(&[
        ("z@MD-5_M-30_MI-2_P-50_R-50", "3"),
        ("helligkeit-senden@P-2_R-2", "ja"),
        ("anzahl@P-3_R-3", "2"),
    ])?;
    assert!(got.is_empty(), "{got:?}");
    Ok(())
}

#[test]
fn test_ignored_overrides_module_channel_label_is_not_reported() -> TestResult {
    let got = ignored(&[("name@MD-4_M-19_MI-1_P-18_R-18", "Licht")])?;
    assert!(got.is_empty(), "{got:?}");
    Ok(())
}

#[test]
fn test_visibility_covers_module_refs() -> TestResult {
    let model = model(&[("t@MD-4_M-19_MI-1_P-12_R-12", "freigegeben")])?;
    let seen = DeviceAnalysis::new(&model, &products()?, ia()?)?.visibility();
    let unreached = seen
        .get("MD-4_M-19_MI-1_P-12_R-12")
        .ok_or("no unreached entry")?;
    assert!(!unreached.shown);
    assert_eq!(unreached.needs.as_deref(), Some("Funktion = 2 x Schalten"));
    assert_eq!(unreached.now.as_deref(), Some("Funktion is 1 x Jalousie"));
    let reached = seen
        .get("MD-3_M-18_MI-1_P-14_R-14")
        .ok_or("no reached entry")?;
    assert!(reached.shown && reached.needs.is_none());
    let hidden = seen
        .get("MD-3_M-18_MI-1_P-16_R-16")
        .ok_or("no assign target entry")?;
    assert_eq!(hidden.condition.as_deref(), Some("Betriebsart = Rollladen"));
    Ok(())
}
