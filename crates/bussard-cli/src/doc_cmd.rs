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
use bussard_model::doc::{DocFormat, InstallationDoc, write_files};
use bussard_model::{Model, ProductModels};

/// Renders the documentation for the model in `dir`.
///
/// With `json`, the structured document model goes to stdout and nothing is
/// written to disk. Otherwise the rendered files are written under `out` and the
/// paths are listed on stdout.
pub fn run(dir: &Path, out: &Path, format: DocFormat, json: bool) -> anyhow::Result<ExitCode> {
    let model =
        Model::load(dir).with_context(|| format!("loading the model from {}", dir.display()))?;
    let products = ProductModels::load(dir);
    let doc = InstallationDoc::build(&model, &products, dir);

    if json {
        let text = crate::output::render(crate::output::schema::DOC, &doc)
            .context("serializing the documentation model to JSON")?;
        println!("{text}");
        return Ok(ExitCode::SUCCESS);
    }

    let files = doc.render(format);
    write_files(&files, out)
        .with_context(|| format!("writing the documentation to {}", out.display()))?;

    println!("wrote {} file(s) to {}:", files.len(), out.display());
    for file in &files {
        println!("  {}", file.path);
    }
    Ok(ExitCode::SUCCESS)
}
