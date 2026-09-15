//! The `bussard adopt` subcommand — the guided new-device flow.

use std::path::Path;
use std::process::ExitCode;

use anyhow::bail;

use crate::conn_cmd::ConnOverrides;

/// Guides a new device from programming mode to a configured model entry.
#[expect(unused_variables, reason = "stub — implementation tracked in #26")]
pub fn run(
    product: Option<&Path>,
    dir: &Path,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    bail!("`bussard adopt` is not implemented yet (https://github.com/tmbo/bussard/issues/26)")
}
