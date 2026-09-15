//! The `bussard assign` subcommand — individual address assignment via
//! programming mode.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

use crate::conn_cmd::ConnOverrides;

/// Assigns an individual address to the device in programming mode.
#[expect(unused_variables, reason = "stub — implementation tracked in #22")]
pub fn run(
    address: Option<&str>,
    dir: &Path,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    bail!("`bussard assign` is not implemented yet (https://github.com/tmbo/bussard/issues/22)")
}
