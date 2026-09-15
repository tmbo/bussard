//! The `bussard scan` subcommand — device discovery on a line.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

use crate::conn_cmd::ConnOverrides;

/// Scans a line for devices: mask version, manufacturer, order number.
#[expect(unused_variables, reason = "stub — implementation tracked in #10")]
pub fn run(
    line: &str,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    bail!("`bussard scan` is not implemented yet (https://github.com/tmbo/bussard/issues/10)")
}
