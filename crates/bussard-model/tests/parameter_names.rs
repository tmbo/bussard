//! Parameter changes read the parameter's text from a cached product model
//! (issue #99), and keep the key-derived label without one.

use std::collections::BTreeMap;

use bussard_model::Model;
use bussard_model::change::{describe, name_parameters};
use bussard_model::param_model::{ProductModel, ProductModels};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-0083_A-1";

/// A one-device model with the night-setback parameter at `value`.
fn model(value: &str) -> Result<Model, Box<dyn std::error::Error>> {
    let device = format!(
        "address = \"1.1.4\"\nname = \"Thermostat\"\napplication = \"{APP}\"\n\n\
         [parameters]\n\"nachtabsenkung@P-1312_R-2140\" = \"{value}\"\n"
    );
    let mut files = BTreeMap::new();
    files.insert("devices/1.1.4.toml".to_string(), device);
    Ok(Model::from_texts(&files)?)
}

#[test]
fn test_name_parameters_uses_the_product_model_text() -> TestResult {
    let (old, new) = (model("2")?, model("3")?);
    let mut changes = describe(&old, &new);
    assert_eq!(changes.len(), 1);
    assert!(
        changes.changes[0].sentence.starts_with("Nachtabsenkung on"),
        "{}",
        changes.changes[0].sentence
    );

    // Without a product model the label stays.
    name_parameters(&mut changes, [&new, &old], &ProductModels::default());
    assert!(changes.changes[0].sentence.starts_with("Nachtabsenkung on"));

    let yaml = format!(
        "parameters:\n  - id: {APP}_P-1312\n    text: Night setback\n    type: !int\n      min: 0\n"
    );
    let mut products = ProductModels::default();
    products
        .by_app_ref
        .insert(APP.to_string(), ProductModel::from_yaml(&yaml, APP)?);
    name_parameters(&mut changes, [&new, &old], &products);
    assert_eq!(
        changes.changes[0].sentence,
        "Night setback on Thermostat (1.1.4): 2 to 3."
    );
    Ok(())
}
