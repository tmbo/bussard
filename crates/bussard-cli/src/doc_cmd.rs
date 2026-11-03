//! The `bussard doc` subcommand — generated installation documentation (#97).
//!
//! Renders the handover folder the KNX guidelines prescribe straight out of the
//! model: a device list, a group-address list, a room sheet per floor/room, the
//! connection details, and a change log from git. The rendering lives in
//! [`bussard_model::doc`]; this module is the thin CLI edge that loads the
//! model, picks a format, and writes the files.
//!
//! The output is deterministic, so the folder can be committed and regenerated
//! after every change: the diff then shows exactly what moved.

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::doc::DocFormat;

/// Renders the documentation for the model in `dir`.
///
/// With `json`, the structured document model goes to stdout and nothing is
/// written to disk. Otherwise the rendered files are written under `out` and the
/// paths are listed on stdout.
pub fn run(dir: &Path, out: &Path, format: DocFormat, json: bool) -> anyhow::Result<ExitCode> {
    if json {
        let doc = bussard_service::files::export::doc_model(dir)?;
        let text = crate::output::render(crate::output::schema::DOC, &doc)
            .context("serializing the documentation model to JSON")?;
        println!("{text}");
        return Ok(ExitCode::SUCCESS);
    }

    let files = bussard_service::files::export::doc(dir, out, format)?;
    println!("wrote {} file(s) to {}:", files.len(), out.display());
    for file in &files {
        println!("  {file}");
    }
    Ok(ExitCode::SUCCESS)
}
