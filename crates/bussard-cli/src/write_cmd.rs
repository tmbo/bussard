//! The `bussard write` subcommand — group value write.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

use crate::conn_cmd::ConnOverrides;

/// Sends a `GroupValueWrite` to the bus.
#[expect(unused_variables, reason = "stub — implementation tracked in #12")]
pub fn run(
    ga: &str,
    value: &str,
    dpt: Option<&str>,
    force: bool,
    dir: &Path,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    bail!("`bussard write` is not implemented yet (https://github.com/tmbo/bussard/issues/12)")
}
