//! Dumps the `/api/model` projection of a model directory to stdout as
//! pretty-printed JSON.
//!
//! Used to (re)generate `assets/fixture-model.json` from the real `knx/`
//! directory so the frontend and its self-test page build against the exact
//! projection the server serves. Run with:
//!
//! ```text
//! cargo run -p bussard-viz --example dump_fixture -- knx
//! ```

use std::path::PathBuf;

use bussard_model::Model;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("knx"));
    let model = Model::load(&dir)?;
    let projection = bussard_viz::project::project_model(&model);
    println!("{}", serde_json::to_string_pretty(&projection)?);
    Ok(())
}
