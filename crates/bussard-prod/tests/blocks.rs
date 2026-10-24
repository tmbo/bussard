//! The `blocks:` section of a product model (issue #298), from the fabricated
//! System 7 application `fixtures/blocks_app.xml`: three universal channels
//! as ETS parameter pages behind "enable" parameters, C behind B, and B's
//! objects on a page of their own.
//!
//! The written model is pinned in
//! `crates/bussard-model/tests/fixtures/blocks_app.yaml`, which the
//! device-view, lookup and MCP tests read. Regenerate it with
//! `BUSSARD_BLESS=1 cargo nextest run -p bussard-prod -E 'test(written_model)'`.

use std::path::PathBuf;

use bussard_model::blocks::BlockKind;
use bussard_model::param_model::{MODEL_FORMAT, model_is_current};
use bussard_prod::product_model::write_product_models;
use bussard_prod::{ApplicationProgram, ProductData, parse_application_program};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-00FA_A-0298-10-0000";

fn app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
    Ok(parse_application_program(
        APP,
        include_bytes!("fixtures/blocks_app.xml"),
    )?)
}

#[test]
fn test_blocks_for_records_pages_gates_and_objects() -> TestResult {
    let blocks = bussard_prod::blocks::blocks_for(&app()?);
    let ids: Vec<&str> = blocks.iter().map(|b| b.id.as_str()).collect();
    assert_eq!(ids, ["CH-0", "PB-1", "PB-10", "PB-20", "PB-21", "PB-30"]);

    let channel = &blocks[0];
    assert_eq!(channel.kind, BlockKind::Channel);
    assert_eq!(channel.text.as_deref(), Some("Generic"));
    assert_eq!(channel.objects, ["O-0_R-0"]);

    let general = &blocks[1];
    assert_eq!(general.text.as_deref(), Some("General"));
    assert_eq!(general.parent.as_deref(), Some("CH-0"));
    assert_eq!(general.parameters, ["P-1_R-1", "P-2_R-2", "P-3_R-3"]);

    // A page titled by a parameter ref takes that parameter's text; its
    // condition is the enable parameter, its objects those the defaults show.
    let a = &blocks[2];
    assert_eq!(a.text.as_deref(), Some("Universal channel A: function"));
    assert_eq!(a.name.as_deref(), Some("ChannelA"));
    assert_eq!(a.channel.as_deref(), Some("CH-0"));
    assert_eq!(a.when.len(), 1);
    assert_eq!(
        (a.when[0].reference.as_str(), a.when[0].test.as_str()),
        ("P-1_R-1", "1")
    );
    assert_eq!(
        a.parameters,
        [
            "P-11_R-11",
            "P-12_R-12",
            "P-13_R-15",
            "P-13_R-13",
            "P-14_R-14"
        ]
    );
    // The dusk threshold sits under the channel function's choice inside
    // the page (issue #315); the function itself under none.
    let dusk: Vec<(&str, &str)> = a
        .parameter_when
        .get("P-12_R-12")
        .map(|gates| {
            gates
                .iter()
                .map(|g| (g.reference.as_str(), g.test.as_str()))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(dusk, [("P-11_R-11", "1")]);
    assert!(!a.parameter_when.contains_key("P-11_R-11"));
    // The wind threshold sits behind the wind function and "If temperature"
    // = Wind (issue #326).
    let wind: Vec<(&str, &str)> = a
        .parameter_when
        .get("P-14_R-14")
        .map(|gates| {
            gates
                .iter()
                .map(|g| (g.reference.as_str(), g.test.as_str()))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(wind, [("P-11_R-11", "3"), ("P-13_R-13", "4")]);
    assert_eq!(a.objects, ["O-1_R-1"]);

    // The objects page: the default function shows O-2_R-2; the default
    // branch's ref is recorded as another branch's.
    let objects_b = &blocks[4];
    assert_eq!(objects_b.objects, ["O-2_R-2"]);
    assert_eq!(objects_b.other_objects, ["O-2_R-3"]);

    // Channel C sits behind both B's and C's switches.
    let c = &blocks[5];
    let gates: Vec<(&str, &str)> = c
        .when
        .iter()
        .map(|g| (g.reference.as_str(), g.test.as_str()))
        .collect();
    assert_eq!(gates, [("P-2_R-2", "1"), ("P-3_R-3", "1")]);
    Ok(())
}

/// Issue #326: a `ParameterRef` `Value` that differs from its parameter's
/// default is carried into the model, so the page evaluator resolves a
/// condition on it as the download side does. A ref without one, or whose
/// parameter has no ref of the kind, is not listed.
#[test]
fn test_ref_values_for_carries_ref_level_values() -> TestResult {
    let app = app()?;
    let blocks = bussard_prod::blocks::blocks_for(&app);
    let values = bussard_prod::blocks::ref_values_for(&app, &blocks);
    assert_eq!(
        values.into_iter().collect::<Vec<_>>(),
        [("P-13_R-13".to_string(), "4".to_string())]
    );
    Ok(())
}

#[test]
fn test_written_model_matches_the_fixture() -> TestResult {
    let dir = tempfile::tempdir()?;
    let product = ProductData {
        applications: vec![app()?],
        ..ProductData::default()
    };
    write_product_models(&product, dir.path())?;
    let path = dir
        .path()
        .join(".bussard/models")
        .join(format!("{APP}.yaml"));
    assert!(model_is_current(&path), "model_format: {MODEL_FORMAT}");
    let written = std::fs::read_to_string(&path)?;

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../bussard-model/tests/fixtures/blocks_app.yaml");
    if std::env::var_os("BUSSARD_BLESS").is_some() {
        std::fs::write(&fixture, &written)?;
    }
    let pinned = std::fs::read_to_string(&fixture)?;
    assert_eq!(
        written, pinned,
        "the emitter changed; regenerate the fixture with BUSSARD_BLESS=1"
    );

    let model = bussard_model::ProductModel::from_yaml(&written, APP)?;
    assert_eq!(model.blocks.len(), 6);
    assert_eq!(model.ref_default("P-13_R-13"), Some("4"));
    assert_eq!(model.ref_default("P-13_R-15"), Some("2"));
    assert_eq!(model.ref_default("P-11_R-11"), Some("1"));
    assert_eq!(
        model
            .object_def("O-2_R-3")
            .and_then(|o| o.function.as_deref()),
        Some("Value")
    );
    Ok(())
}

#[test]
fn test_model_of_an_older_format_is_not_current() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("old.yaml");
    std::fs::write(&path, "# banner\nidentity:\n  id: X\n")?;
    assert!(!model_is_current(&path));
    std::fs::write(&path, format!("# banner\nmodel_format: {MODEL_FORMAT}\n"))?;
    assert!(model_is_current(&path));
    Ok(())
}
