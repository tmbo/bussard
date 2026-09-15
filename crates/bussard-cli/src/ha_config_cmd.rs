//! The `bussard ha-config` subcommand — Home Assistant KNX config generation.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

/// Generates the Home Assistant KNX integration YAML from the model.
#[expect(unused_variables, reason = "stub — implementation tracked in #15")]
pub fn run(dir: &Path, out: Option<&Path>) -> anyhow::Result<ExitCode> {
    bail!("`bussard ha-config` is not implemented yet (https://github.com/tmbo/bussard/issues/15)")
}
