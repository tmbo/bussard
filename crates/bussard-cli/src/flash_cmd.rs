//! The `bussard flash` subcommand — first application download into a
//! factory-fresh device (phase 3).

use std::path::Path;
use std::process::ExitCode;

use anyhow::bail;

use crate::conn_cmd::ConnOverrides;

/// Flashes an application program from vendor product data into a device.
#[expect(unused_variables, reason = "stub — implementation tracked in #43")]
pub fn run(
    address: &str,
    product: &Path,
    application: Option<&str>,
    dir: &Path,
    yes: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    bail!("`bussard flash` is not implemented yet (https://github.com/tmbo/bussard/issues/43)")
}
