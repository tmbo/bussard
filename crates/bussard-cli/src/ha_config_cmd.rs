//! The `bussard ha-config` subcommand — Home Assistant KNX config generation.
//!
//! Loads the model (and optional `ha.yaml` overrides) from `dir`, derives the
//! Home Assistant `knx:` entities heuristically, and writes the YAML to `out`
//! (or stdout when `out` is `None`).

use std::path::Path;
use std::process::ExitCode;

use bussard_ha::{Overrides, generate};
use bussard_model::Model;

/// Generates the Home Assistant KNX integration YAML from the model.
pub fn run(dir: &Path, out: Option<&Path>) -> anyhow::Result<ExitCode> {
    let model = Model::load(dir)?;
    let overrides = Overrides::load(dir)?;
    let yaml = generate(&model, &overrides)?;

    match out {
        Some(path) => {
            std::fs::write(path, &yaml)
                .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
            eprintln!("wrote Home Assistant config to {}", path.display());
        }
        None => print!("{yaml}"),
    }
    Ok(ExitCode::SUCCESS)
}
