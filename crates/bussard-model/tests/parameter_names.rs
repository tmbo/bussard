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

/// An enum product model for [`APP`]: parameter `P-1312` with two members.
fn enum_products() -> Result<ProductModels, Box<dyn std::error::Error>> {
    let yaml = format!(
        "parameters:\n  - id: {APP}_P-1312\n    text: Funktion\n    type: !enum\n      values:\n        \
         - {{ value: 0, text: Kurzer Tastendruck }}\n        \
         - {{ value: 5, text: Kurzer und langer Tastendruck }}\n"
    );
    let mut products = ProductModels::default();
    products
        .by_app_ref
        .insert(APP.to_string(), ProductModel::from_yaml(&yaml, APP)?);
    Ok(products)
}

/// Issue #279: a label on one side and its code on the other name the same
/// member, so they are no change; a real change reads as labels with codes.
#[test]
fn test_settle_parameters_normalises_label_and_code() -> TestResult {
    let products = enum_products()?;
    // (old value, new value, the expected sentence or None for no change)
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("Kurzer und langer Tastendruck", "5", None),
        ("5", "Kurzer und langer Tastendruck", None),
        (
            "0",
            "5",
            Some(
                "Funktion on Thermostat (1.1.4): Kurzer Tastendruck (0) to Kurzer und langer \
                 Tastendruck (5).",
            ),
        ),
        (
            "Kurzer Tastendruck",
            "5",
            Some(
                "Funktion on Thermostat (1.1.4): Kurzer Tastendruck (0) to Kurzer und langer \
                 Tastendruck (5).",
            ),
        ),
        // Not a member: the value stays as written.
        (
            "0",
            "9",
            Some("Funktion on Thermostat (1.1.4): Kurzer Tastendruck (0) to 9."),
        ),
    ];
    for (from, to, want) in cases {
        let (old, new) = (model(from)?, model(to)?);
        let mut changes = describe(&old, &new);
        assert_eq!(changes.len(), 1, "{from} -> {to}: the raw strings differ");
        name_parameters(&mut changes, [&new, &old], &products);
        let got: Vec<&str> = changes
            .changes
            .iter()
            .map(|c| c.sentence.as_str())
            .collect();
        let want: Vec<&str> = want.iter().copied().collect();
        assert_eq!(got, want, "{from} -> {to}");
    }
    Ok(())
}
