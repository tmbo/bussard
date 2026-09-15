//! The `bussard import-product` subcommand — generate device models from
//! vendor `.knxprod` product data.

use std::path::Path;

use anyhow::bail;
use std::process::ExitCode;

/// Imports a `.knxprod`: caches it under `<dir>/vendor/` and generates a
/// device model under `<dir>/models/`.
#[expect(unused_variables, reason = "stub — implementation tracked in #25")]
pub fn run(file: &Path, dir: &Path) -> anyhow::Result<ExitCode> {
    bail!(
        "`bussard import-product` is not implemented yet (https://github.com/tmbo/bussard/issues/25)"
    )
}
