//! The `bussard plan` subcommand — diff the model against live device state.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

use crate::conn_cmd::ConnOverrides;

/// Reads a device's live tables and shows what `apply` would change.
#[expect(unused_variables, reason = "stub — phase-2 downloader")]
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    bail!("`bussard plan` is not implemented yet")
}
