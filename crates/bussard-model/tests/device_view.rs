//! `bussard device` / `knx_show_device`: what a device offers, in the device
//! file's words, from the lock and the product model.

use std::collections::BTreeMap;

use bussard_model::device_view::{DEVICE_SCOPE, ViewError, device_view};
use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-0004_A-20DE-22-C7D8-O000A";

const LOCK: &str = r#"version = 2

[[device]]
address = "1.1.47"
product = "230021SU"
application = "M-0004_A-20DE-22-C7D8-O000A"
mask = "07B0"
channels = [
  { key = "a-1", id = "MD-3_M-18_MI-1_CH-25", number = 1, text = "Jalousie 1", base = 2915 },
]
objects = [
  { number = 138, key = "in-betrieb", text = "Allgemein", function = "In Betrieb", dpt = "1.002", flags = "CRT" },
  { number = 144, key = "langzeitbetrieb", channel = "a-1", text = "Jalousie 1", function = "Langzeitbetrieb", dpt = "1.008", flags = "CWU" },
  { number = 162, key = "status-position", channel = "a-1", dpt = "5.001", flags = "CRT" },
]
parameters = [
  { key = "regenalarm", ref = "P-19_R-38", param = "P-19" },
  { key = "betriebsart", channel = "a-1", ref = "MD-3_M-18_MI-1_P-14_R-14", param = "MD-3_P-14" },
  { key = "fahrzeit", channel = "a-1", ref = "MD-3_M-18_MI-1_P-15_R-15", param = "MD-3_P-15" },
]
"#;

const DEVICE: &str = r#"address = "1.1.47"
name = "Jalousieaktor Kind 2"
product = "230021SU"

[links]
in-betrieb.send = "4/1/2"

[channel.a-1]
name = "Fenster Süd"
betriebsart = "2"
langzeitbetrieb.listen = ["0/1/3"]
"#;

const PRODUCT: &str = r#"identity:
  id: M-0004_A-20DE-22-C7D8-O000A
parameters:
  - id: M-0004_A-20DE-22-C7D8-O000A_MD-3_P-14
    text: Betriebsart
    type: !enum
      values:
        - { value: 1, text: Rollladen }
        - { value: 2, text: Jalousie }
    default: "1"
  - id: M-0004_A-20DE-22-C7D8-O000A_MD-3_P-15
    text: Fahrzeit
    type: !int
      min: 1
      max: 600
    default: "60"
  - id: M-0004_A-20DE-22-C7D8-O000A_P-19
    text: Regenalarm
    type: !enum
      values:
        - { value: 0, text: Nein }
        - { value: 1, text: Ja }
    default: "0"
"#;

fn model() -> Result<Model, Box<dyn std::error::Error>> {
    let files: BTreeMap<String, String> = [
        ("bussard.lock", LOCK),
        ("devices/1.1.47.toml", DEVICE),
        ("bussard.toml", "[connection]\ntransport = \"tunnel\"\n"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    Ok(Model::from_texts(&files)?)
}

fn products() -> Result<ProductModels, Box<dyn std::error::Error>> {
    let mut products = ProductModels::default();
    products
        .by_app_ref
        .insert(APP.to_string(), ProductModel::from_yaml(PRODUCT, APP)?);
    Ok(products)
}

fn ia() -> Result<IndividualAddress, Box<dyn std::error::Error>> {
    Ok("1.1.47".parse()?)
}

#[test]
fn test_device_view_lists_the_channels() -> TestResult {
    let view = device_view(&model()?, &products()?, ia()?, None)?;
    assert_eq!(view.channels.len(), 1);
    let ch = &view.channels[0];
    assert_eq!(ch.handle, "a-1");
    assert_eq!(ch.text.as_deref(), Some("Jalousie 1"));
    assert_eq!(ch.name.as_deref(), Some("Fenster Süd"));
    assert_eq!((ch.parameters, ch.objects), (2, 2));
    assert_eq!(view.device_level, (1, 1));
    let text = view.render_table();
    assert!(text.contains("a-1"), "{text}");
    assert!(text.contains("Fenster Süd"), "{text}");
    assert!(
        text.contains("device level: 1 parameter(s), 1 object(s)"),
        "{text}"
    );
    let toml = view.render_toml();
    assert!(
        toml.contains("[channel.a-1]   # Jalousie 1\nname = \"Fenster Süd\"\n"),
        "{toml}"
    );
    Ok(())
}

#[test]
fn test_device_view_details_a_channel() -> TestResult {
    let view = device_view(&model()?, &products()?, ia()?, Some("a-1"))?;
    let scope = view.scope.as_ref().ok_or("no scope")?;
    let betriebsart = scope
        .parameters
        .iter()
        .find(|p| p.key == "betriebsart")
        .ok_or("betriebsart")?;
    assert_eq!(betriebsart.value.as_deref(), Some("Jalousie"));
    assert_eq!(betriebsart.default.as_deref(), Some("Rollladen"));
    assert_eq!(betriebsart.at_default, Some(false));
    assert_eq!(betriebsart.choices, vec!["Rollladen", "Jalousie"]);
    let fahrzeit = scope
        .parameters
        .iter()
        .find(|p| p.key == "fahrzeit")
        .ok_or("fahrzeit")?;
    assert_eq!(fahrzeit.value, None);
    assert_eq!(fahrzeit.at_default, Some(true));
    assert_eq!(fahrzeit.range.as_deref(), Some("1..600"));
    let objects: Vec<(&str, u16, &str)> = scope
        .objects
        .iter()
        .map(|o| (o.key.as_str(), o.number, o.flags.as_str()))
        .collect();
    assert_eq!(
        objects,
        vec![
            ("langzeitbetrieb", 144, "CWU"),
            ("status-position", 162, "CRT")
        ]
    );
    assert_eq!(scope.objects[0].listen, vec!["0/1/3"]);

    let text = view.render_table();
    assert!(text.contains("Rollladen | Jalousie"), "{text}");
    assert!(text.contains("listens on 0/1/3"), "{text}");

    let toml = view.render_toml();
    assert_eq!(
        toml,
        "# devices/1.1.47.toml: Jalousieaktor Kind 2; uncomment what you want to set\n\
         \n\
         [channel.a-1]   # Jalousie 1\n\
         name = \"Fenster Süd\"\n\
         betriebsart = \"Jalousie\"   # Betriebsart: Rollladen | Jalousie\n\
         # fahrzeit = \"60\"   # Fahrzeit: 1..600\n\
         langzeitbetrieb.listen = [\"0/1/3\"]   # CWU Langzeitbetrieb, Jalousie 1, 1.008\n\
         # status-position.send = \"\"   # CRT 5.001\n"
    );
    // The snippet is valid TOML.
    toml::from_str::<toml::Table>(&toml)?;
    Ok(())
}

#[test]
fn test_device_view_device_scope_and_errors() -> TestResult {
    let view = device_view(&model()?, &products()?, ia()?, Some(DEVICE_SCOPE))?;
    let scope = view.scope.as_ref().ok_or("no scope")?;
    assert_eq!(scope.parameters[0].key, "regenalarm");
    assert_eq!(scope.objects[0].send.as_deref(), Some("4/1/2"));
    let toml = view.render_toml();
    assert!(
        toml.contains("[parameters]\n# regenalarm = \"Nein\""),
        "{toml}"
    );
    assert!(
        toml.contains("[links]\nin-betrieb.send = \"4/1/2\""),
        "{toml}"
    );

    let err = device_view(&model()?, &products()?, ia()?, Some("b-9")).err();
    assert!(matches!(err, Some(ViewError::NoChannel { .. })), "{err:?}");
    Ok(())
}

#[test]
fn test_device_view_without_product_data_says_so() -> TestResult {
    let view = device_view(&model()?, &ProductModels::default(), ia()?, Some("a-1"))?;
    assert!(!view.product_model);
    assert!(
        view.notes[0].contains("no product data"),
        "{:?}",
        view.notes
    );
    let scope = view.scope.as_ref().ok_or("no scope")?;
    // The lock still lists every parameter; the value is what the file says.
    assert_eq!(scope.parameters.len(), 2);
    let betriebsart = &scope.parameters[0];
    assert_eq!(betriebsart.value.as_deref(), Some("2"));
    assert_eq!(betriebsart.at_default, None);
    assert!(betriebsart.choices.is_empty());
    Ok(())
}
