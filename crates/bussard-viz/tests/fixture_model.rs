//! Guards the checked-in frontend fixture, `assets/fixture-model.json`.
//!
//! That file is embedded in every release binary (`assets.rs`) and served at
//! `/assets/fixture-model.json`, so it must stay **synthetic**: it once held a
//! dump of a real installation, with its room names, device names and complete
//! group-address plan. The fixture is now generated from
//! `fixtures/demo-model/`, an invented model checked in next to it.
//!
//! Two properties are asserted here:
//!
//! 1. the embedded JSON is exactly what `examples/dump_fixture.rs` produces from
//!    `fixtures/demo-model/`, so the two can never drift apart silently; and
//! 2. the fixture still describes the demo house and is pure ASCII — a cheap,
//!    hard-to-fool tripwire for "someone regenerated it against `knx/` again".

use std::path::PathBuf;

use bussard_model::Model;
use bussard_viz::assets;
use bussard_viz::project::project_model;

/// The synthetic model directory the fixture is generated from.
fn demo_model_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("demo-model")
}

/// The embedded fixture body.
fn embedded() -> &'static str {
    assets::asset("fixture-model.json")
        .expect("fixture-model.json is an embedded asset")
        .body
}

#[test]
fn test_fixture_model_matches_demo_model_projection() -> Result<(), Box<dyn std::error::Error>> {
    let model = Model::load(&demo_model_dir())?;
    let expected = format!(
        "{}\n",
        serde_json::to_string_pretty(&project_model(&model))?
    );

    assert_eq!(
        embedded(),
        expected,
        "assets/fixture-model.json is stale. Regenerate it with:\n  \
         cargo run -p bussard-viz --example dump_fixture -- \
         crates/bussard-viz/fixtures/demo-model > crates/bussard-viz/assets/fixture-model.json"
    );
    Ok(())
}

#[test]
fn test_fixture_model_is_the_synthetic_demo_house() -> Result<(), Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(embedded())?;

    assert_eq!(
        value["project"], "Demo House",
        "the shipped fixture must be the synthetic demo model, never a real installation"
    );

    // The demo model is deliberately all-ASCII. A dump of a real (German-named)
    // installation is not, so this catches the obvious accident cheaply.
    if let Some((index, ch)) = embedded().char_indices().find(|(_, c)| !c.is_ascii()) {
        panic!(
            "fixture-model.json contains the non-ASCII character {ch:?} at byte {index}; \
             the shipped fixture must be the synthetic demo model, not a dump of a real \
             installation"
        );
    }
    Ok(())
}
