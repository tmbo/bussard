//! The `bussard init` subcommand — from-scratch onboarding.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

/// Creates a fresh `knx/` model directory: discovers gateways, writes the
/// skeleton, and prints next steps.
#[expect(unused_variables, reason = "stub — implementation tracked in #21")]
pub fn run(dir: &Path, gateway: Option<&str>, routing: bool) -> anyhow::Result<ExitCode> {
    bail!("`bussard init` is not implemented yet (https://github.com/tmbo/bussard/issues/21)")
}
