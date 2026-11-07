//! The ETS pages of a product model (issue #298), from the fabricated
//! System 7 application `fixtures/blocks_app.xml`: three universal channels
//! as ETS parameter pages behind "enable" parameters, C behind B, and B's
//! objects on a page of their own.
//!
//! The written model is pinned in
//! `crates/bussard-model/tests/fixtures/blocks_app.json`, which the
//! device-view, lookup and MCP tests read. Regenerate it with
//! `BUSSARD_BLESS=1 cargo nextest run -p bussard-prod -E 'test(written_model)'`.

use std::path::PathBuf;

use bussard_model::blocks::BlockKind;
use bussard_model::dynamic::{RefIndex, WhenTest};
use bussard_model::param_model::{cached_product_model, product_model_is_current};
use bussard_product::product_model::{product_model, write_product_models};
use bussard_product::{ApplicationProgram, ProductData, parse_application_program};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-00FA_A-0298-10-0000";

fn app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
    Ok(parse_application_program(
        APP,
        include_bytes!("../fixtures/blocks_app.xml"),
    )?)
}

/// The product model the importer writes for the fixture.
fn written_model() -> Result<bussard_model::ProductModel, Box<dyn std::error::Error>> {
    let product = ProductData {
        applications: vec![app()?],
        ..ProductData::default()
    };
    Ok(product_model(&product.applications[0], &product))
}

/// The conditions in front of the one app-level occurrence of `reference`
/// inside its innermost container, as (controlling ref, test).
fn gates_inside(index: &RefIndex, reference: &str) -> Vec<(String, String)> {
    index
        .parameter(reference)
        .iter()
        .chain(index.com_object(reference))
        .filter(|o| o.module_def.is_none())
        .flat_map(|o| o.gates[o.container_gates..].iter())
        .map(|g| {
            let test = match &g.test {
                WhenTest::Values(v) => v.iter().map(i64::to_string).collect::<Vec<_>>().join(" "),
                WhenTest::Default => "default".to_string(),
                other => format!("{other:?}"),
            };
            (g.param_ref_id.clone(), test)
        })
        .collect()
}

/// The pages derived from the written model's Dynamic tree (issue #345;
/// before format 6 the importer wrote them as `blocks:`).
#[test]
fn test_model_blocks_records_pages_gates_and_objects() -> TestResult {
    let model = written_model()?;
    let blocks = model.blocks();
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
    // condition is the enable parameter.
    let a = &blocks[2];
    assert_eq!(a.text.as_deref(), Some("Universal channel A: function"));
    assert_eq!(a.name.as_deref(), Some("ChannelA"));
    assert_eq!(a.channel.as_deref(), Some("CH-0"));
    assert_eq!(a.when.len(), 1);
    assert_eq!(
        (a.when[0].param_ref_id.as_str(), a.when[0].test_text()),
        ("P-1_R-1", "1".to_string())
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
    let index = RefIndex::new(&model);
    let pair = |r: &str, t: &str| (r.to_string(), t.to_string());
    assert_eq!(gates_inside(&index, "P-12_R-12"), [pair("P-11_R-11", "1")]);
    assert!(gates_inside(&index, "P-11_R-11").is_empty());
    // The wind threshold sits behind the wind function and "If temperature"
    // = Wind (issue #326).
    assert_eq!(
        gates_inside(&index, "P-14_R-14"),
        [pair("P-11_R-11", "3"), pair("P-13_R-13", "4")]
    );
    assert_eq!(a.objects, ["O-1_R-1"]);

    // The objects page holds both branches' objects: the default function
    // shows O-2_R-2, the default branch holds O-2_R-3.
    let objects_b = &blocks[4];
    assert_eq!(objects_b.objects, ["O-2_R-2", "O-2_R-3"]);
    assert_eq!(gates_inside(&index, "O-2_R-2"), [pair("P-21_R-21", "1")]);
    assert_eq!(
        gates_inside(&index, "O-2_R-3"),
        [pair("P-21_R-21", "default")]
    );

    // Channel C sits behind both B's and C's switches.
    let c = &blocks[5];
    let gates: Vec<(&str, String)> = c
        .when
        .iter()
        .map(|g| (g.param_ref_id.as_str(), g.test_text()))
        .collect();
    assert_eq!(
        gates,
        [("P-2_R-2", "1".to_string()), ("P-3_R-3", "1".to_string())]
    );
    Ok(())
}

/// Issue #326: a `ParameterRef` `Value` that differs from its parameter's
/// default is carried into the model (on the ref, format 6), so the
/// evaluator resolves a condition on it as the download side does. A ref
/// without one takes its parameter's default.
#[test]
fn test_model_carries_ref_level_values() -> TestResult {
    let model = written_model()?;
    let values: Vec<(&str, &str)> = model
        .parameter_refs
        .iter()
        .filter_map(|(r, d)| Some((r.as_str(), d.value.as_deref()?)))
        .collect();
    assert_eq!(values, [("P-13_R-13", "4")]);
    Ok(())
}

/// The import writes each model where the next command reads it.
#[test]
fn test_write_product_models_leaves_a_current_model() -> TestResult {
    let dir = tempfile::tempdir()?;
    let product = ProductData {
        applications: vec![app()?],
        ..ProductData::default()
    };
    assert_eq!(
        write_product_models(&product, dir.path())?,
        [format!("{APP}.json")]
    );
    assert!(product_model_is_current(dir.path(), APP));
    let stored = cached_product_model(dir.path(), APP).ok_or("the model reads back")?;
    assert_eq!(
        format!("{stored:?}"),
        format!("{:?}", product_model(&product.applications[0], &product))
    );
    Ok(())
}

#[test]
fn test_written_model_matches_the_fixture() -> TestResult {
    let written = serde_json::to_value(written_model()?)?;
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../bussard-model/tests/fixtures/blocks_app.json");
    if std::env::var_os("BUSSARD_BLESS").is_some() {
        std::fs::write(&fixture, serde_json::to_string_pretty(&written)? + "\n")?;
    }
    let pinned: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&fixture)?)?;
    assert_eq!(
        written, pinned,
        "the model changed; regenerate the fixture with BUSSARD_BLESS=1"
    );

    let model: bussard_model::ProductModel = serde_json::from_value(pinned)?;
    assert_eq!(model.blocks().len(), 6);
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
