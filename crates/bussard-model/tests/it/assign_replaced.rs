//! Issue #1070: a stored value a reached `<Assign>` replaces is named, with
//! the value the `<Assign>` puts in its place, what it copies and its
//! condition, by the evaluator, the device view and the ignored-value list.
//!
//! The product model mirrors the synthetic product `syn-assign-rewrite`
//! (#1054): "Chore interval" sits on the general page; a choose on
//! "Operating mode" shows "Nap length" when `on` and `<Assign>`s "Delay (s)"
//! to "Chore interval" when `automatic`. ETS shows and downloads the
//! assigned value (capture `syn-assign-rewrite/params`).

use std::collections::BTreeMap;

use bussard_model::device_view::DeviceAnalysis;
use bussard_model::dynamic::evaluate_dynamic;
use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-00FA_A-27B3-10-0000";

const PRODUCT: &str = r#"{
  "parameters": {
    "P-1": {
      "kind": {"Enum": {"values": [0, 1, 2]}},
      "default": "1",
      "text": "Operating mode",
      "labels": [[0, "off"], [1, "on"], [2, "automatic"]],
      "refs": ["P-1_R-1"],
      "enum_values": [
        {"value": 0, "text": "off", "default_text": "off"},
        {"value": 1, "text": "on", "default_text": "on"},
        {"value": 2, "text": "automatic", "default_text": "automatic"}
      ]
    },
    "P-2": {
      "kind": {"Int": {"min": 0, "max": 65535, "signed": false}},
      "default": "300",
      "text": "Delay (s)",
      "refs": ["P-2_R-2"]
    },
    "P-3": {
      "kind": {"Int": {"min": 0, "max": 65535, "signed": false}},
      "default": "4660",
      "text": "Chore interval",
      "refs": ["P-3_R-3"]
    },
    "P-4": {
      "kind": {"Int": {"min": 0, "max": 65535, "signed": false}},
      "default": "60",
      "text": "Nap length",
      "refs": ["P-4_R-4"]
    }
  },
  "program_id": "M-00FA_A-27B3-10-0000",
  "dynamic": [
    {
      "block": {
        "id": "PB-1",
        "name": "general",
        "text": "General",
        "nodes": [
          {"p": "P-1_R-1"},
          {"p": "P-2_R-2"},
          {"p": "P-3_R-3"},
          {
            "choose": {
              "ref": "P-1_R-1",
              "when": [
                {"test": "1", "nodes": [{"p": "P-4_R-4"}]},
                {"test": "2", "nodes": [{"assign": {"target": "P-3_R-3", "source": "P-2_R-2"}}]}
              ]
            }
          }
        ]
      }
    }
  ],
  "parameter_refs": {
    "P-1_R-1": {"parameter": "P-1"},
    "P-2_R-2": {"parameter": "P-2"},
    "P-3_R-3": {"parameter": "P-3"},
    "P-4_R-4": {"parameter": "P-4"}
  }
}
"#;

const LOCK: &str = r#"version = 3

[[device]]
address = "1.1.1"
product = "NEST-ROTA"
application = "M-00FA_A-27B3-10-0000"
mask = "07B0"
parameters = [
  { key = "operating-mode", ref = "P-1_R-1", param = "P-1" },
  { key = "delay-s", ref = "P-2_R-2", param = "P-2" },
  { key = "chore-interval", ref = "P-3_R-3", param = "P-3" },
  { key = "nap-length", ref = "P-4_R-4", param = "P-4" },
]
"#;

fn ia() -> Result<IndividualAddress, Box<dyn std::error::Error>> {
    Ok("1.1.1".parse()?)
}

fn product() -> Result<ProductModel, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str::<ProductModel>(PRODUCT)?)
}

fn products() -> Result<ProductModels, Box<dyn std::error::Error>> {
    let mut products = ProductModels::default();
    products.insert(APP.to_string(), product()?);
    Ok(products)
}

/// The model whose device stores `params` (TOML lines under `[parameters]`).
fn model(params: &str) -> Result<Model, Box<dyn std::error::Error>> {
    let device = format!(
        "address = \"1.1.1\"\nname = \"Chore rota\"\nproduct = \"NEST-ROTA\"\n\n[parameters]\n{params}"
    );
    let files: BTreeMap<String, String> = [
        ("bussard.lock", LOCK.to_string()),
        ("devices/1.1.1.toml", device),
        (
            "bussard.toml",
            "[connection]\ntransport = \"tunnel\"\n".to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    Ok(Model::from_texts(&files)?)
}

#[test]
fn test_evaluate_dynamic_assigned_overrides_records_source_and_condition() -> TestResult {
    let overrides: BTreeMap<String, String> =
        [("P-1_R-1", "2"), ("P-3_R-3", "1000"), ("P-4_R-4", "7")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
    let config = evaluate_dynamic(&product()?, &overrides);
    assert_eq!(
        config.assigned_overrides.len(),
        1,
        "{:?}",
        config.assigned_overrides
    );
    let o = &config.assigned_overrides[0];
    assert_eq!(o.param_ref, "P-3_R-3");
    assert_eq!(
        (o.overridden.as_str(), o.assigned.as_str()),
        ("1000", "300")
    );
    assert_eq!(o.source, Some((String::new(), "P-2_R-2".to_string())));
    let conditions: Vec<(&str, &str)> = o
        .conditions
        .iter()
        .map(|c| (c.param_ref.as_str(), c.value.as_str()))
        .collect();
    assert_eq!(conditions, [("P-1_R-1", "2")]);
    Ok(())
}

#[test]
fn test_assigned_overrides_names_the_assign_and_its_condition() -> TestResult {
    let model = model("chore-interval = 1000\nnap-length = 7\noperating-mode = \"automatic\"\n")?;
    let products = products()?;
    let analysis = DeviceAnalysis::new(&model, &products, ia()?)?;
    let assigned = analysis.assigned_overrides();
    assert_eq!(assigned.len(), 1, "{assigned:?}");
    let a = &assigned[0];
    assert_eq!(a.key, "chore-interval");
    assert_eq!(a.reference, "P-3_R-3");
    assert_eq!((a.value.as_str(), a.assigned.as_str()), ("1000", "300"));
    assert_eq!(a.source.as_deref(), Some("Delay (s)"));
    assert_eq!(a.condition.as_deref(), Some("Operating mode = automatic"));
    assert_eq!(
        a.sentence(),
        "`chore-interval` = 1000 replaced by 300: an `<Assign>` copies Delay (s) \
         while Operating mode = automatic"
    );
    // Named once: the ignored list keeps only the hidden "Nap length".
    let ignored: Vec<String> = analysis
        .ignored_overrides()
        .into_iter()
        .map(|i| i.key)
        .collect();
    assert_eq!(ignored, ["nap-length"]);
    Ok(())
}

#[test]
fn test_assigned_overrides_value_equal_to_the_assign_is_not_reported() -> TestResult {
    let model = model("chore-interval = 300\noperating-mode = \"automatic\"\n")?;
    let products = products()?;
    let analysis = DeviceAnalysis::new(&model, &products, ia()?)?;
    assert!(analysis.assigned_overrides().is_empty());
    assert!(analysis.ignored_overrides().is_empty());
    Ok(())
}

#[test]
fn test_assigned_overrides_unreached_assign_is_not_reported() -> TestResult {
    // "on" shows "Nap length" and reaches no `<Assign>`: 1000 is written.
    let model = model("chore-interval = 1000\noperating-mode = \"on\"\n")?;
    let products = products()?;
    let analysis = DeviceAnalysis::new(&model, &products, ia()?)?;
    assert!(analysis.assigned_overrides().is_empty());
    assert!(analysis.ignored_overrides().is_empty());
    Ok(())
}

#[test]
fn test_assigned_overrides_of_matches_the_analysis() -> TestResult {
    let model = model("chore-interval = 1000\noperating-mode = \"automatic\"\n")?;
    let device = &model.devices.get(&ia()?).ok_or("no device")?.device;
    let got = bussard_model::device_view::assigned_overrides_of(device, &product()?);
    let products = products()?;
    let want = DeviceAnalysis::new(&model, &products, ia()?)?.assigned_overrides();
    assert_eq!(got, want);
    assert_eq!(got.len(), 1, "{got:?}");
    // A device that stores no `<Assign>` target is not evaluated.
    let bare = model_without_target()?;
    let device = &bare.devices.get(&ia()?).ok_or("no device")?.device;
    assert!(bussard_model::device_view::assigned_overrides_of(device, &product()?).is_empty());
    Ok(())
}

fn model_without_target() -> Result<Model, Box<dyn std::error::Error>> {
    model("operating-mode = \"automatic\"\n")
}
