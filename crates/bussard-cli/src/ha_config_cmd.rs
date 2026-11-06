//! The `bussard ha-config` subcommand — Home Assistant KNX config generation.
//!
//! Loads the model (and optional `ha.toml` overrides) from `dir`, derives the
//! Home Assistant `knx:` entities heuristically, and writes the YAML to `out`
//! (or stdout when `out` is `None`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bussard_ha::{Overrides, generate};
use bussard_model::Model;

use crate::cli::{Resolved, Run};

/// `bussard ha-config`.
#[derive(Debug, clap::Args)]
pub(crate) struct HaConfigArgs {
    /// Output file (default: stdout).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

impl Run for HaConfigArgs {
    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(g.dir(), self.out.as_deref())
    }
}

/// Generates the Home Assistant KNX integration YAML from the model.
fn run(dir: &Path, out: Option<&Path>) -> anyhow::Result<ExitCode> {
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
