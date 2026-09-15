//! The `bussard reconstruct` subcommand — read a device's tables back over the
//! bus and diff them against the model.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

use crate::conn_cmd::ConnOverrides;

/// Reads a device's group/association/com-object tables and compares them with
/// the model's links.
#[expect(unused_variables, reason = "stub — implementation tracked in #23")]
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    bail!(
        "`bussard reconstruct` is not implemented yet (https://github.com/tmbo/bussard/issues/23)"
    )
}
