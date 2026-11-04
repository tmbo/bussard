//! `bussard import <file.bussard>` (issue #111).
//!
//! A bundle into a directory without a model is extracted byte for byte,
//! history included. A bundle into an existing model runs the same merge as a
//! `.knxproj` re-import: generated data follows the bundle, hand-authored
//! fields stay local, and every disagreement is printed as a sentence.
//! `--mine`, `--theirs` and `--interactive` settle those disagreements. The
//! flow is [`bussard_service::files::import::import_bundle`], shared with the
//! MCP tool `knx_import_file`.

use std::path::Path;
use std::process::ExitCode;

use crate::console::Console;

pub use bussard_service::files::import::ConflictChoice;

/// Runs `bussard import <file.bussard>`.
pub fn run_bundle(path: &Path, dir: &Path, choice: ConflictChoice) -> anyhow::Result<ExitCode> {
    let outcome = bussard_service::files::import::import_bundle(
        path,
        dir,
        choice,
        &mut Console,
        &mut Console,
    )?;
    Ok(crate::import_cmd::exit_code(&outcome))
}
