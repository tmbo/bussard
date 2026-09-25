//! Dumps the `/api/model` projection of a model directory to stdout as
//! pretty-printed JSON.
//!
//! Used to (re)generate `assets/fixture-model.json` from the **synthetic**
//! `fixtures/demo-model/` directory, so the frontend and its self-test page
//! build against the exact projection the server serves. Run with:
//!
//! ```text
//! cargo run -p bussard-viz --example dump_fixture -- \
//!   crates/bussard-viz/fixtures/demo-model \
//!   > crates/bussard-viz/assets/fixture-model.json
//! ```
//!
//! Never regenerate the checked-in fixture from a real `knx/` directory: the
//! projection carries that building's room names, device names and complete
//! group-address plan, and the file is embedded in every release binary and
//! served at `/assets/fixture-model.json`. `tests/fixture_model.rs` fails if the
//! shipped fixture stops being the demo model.

use std::path::PathBuf;

use bussard_model::Model;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Default to the synthetic fixture, never to the operator's real `knx/`.
    let dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("crates/bussard-viz/fixtures/demo-model"));
    let model = Model::load(&dir)?;
    // The demo model ships its own synthetic product model under
    // `.bussard/models/`, so the fixture carries vendor texts and defaults.
    let products = bussard_viz::project::product_models_for(&model, &dir);
    let projection = bussard_viz::project::project_model_with(&model, &products);
    println!("{}", serde_json::to_string_pretty(&projection)?);
    Ok(())
}
