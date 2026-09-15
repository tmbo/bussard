//! The `bussard apply` subcommand — write planned changes to a device.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

use crate::conn_cmd::ConnOverrides;

/// Applies the model's link tables to a device (plan, confirm, write, verify).
#[expect(unused_variables, reason = "stub — phase-2 downloader")]
pub fn run(
    address: &str,
    dir: &Path,
    yes: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    bail!("`bussard apply` is not implemented yet")
}
