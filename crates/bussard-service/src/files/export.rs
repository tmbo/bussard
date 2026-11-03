//! The exports: the `.bussard` bundle (`bussard export`, issue #111), the
//! group plan for ETS (`bussard export-groups`, issue #104) and the handover
//! documentation (`bussard doc`, issue #97). The keyring export is in
//! [`super::keyring`].

use std::path::{Path, PathBuf};

use bussard_model::bundle::{self, BundleManifest, ExportOptions};
use bussard_model::doc::{DocFormat, InstallationDoc, write_files};
use bussard_model::{Model, ProductModels, to_ets_csv, to_ets_xml};

use crate::setup::{Context as _, SetupError};

/// Writes the model in `dir` and (with `include_history`) its history as one
/// `.bussard` file at `out`, or next to the model directory named after it
/// and today's date. Returns the path written and the manifest.
///
/// # Errors
///
/// The model cannot be read or the bundle written.
pub fn bundle(
    dir: &Path,
    out: Option<&Path>,
    include_history: bool,
) -> Result<(PathBuf, BundleManifest), SetupError> {
    let out = out.map_or_else(|| bundle::default_bundle_path(dir), Path::to_path_buf);
    let manifest = bundle::export(dir, &out, ExportOptions { include_history })
        .ctx(|| format!("exporting {}", dir.display()))?;
    Ok((out, manifest))
}

/// The group-plan formats ETS's *Group Addresses -> Import* accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupFormat {
    /// The three-level CSV ETS exports and imports (BOM, semicolon separated).
    EtsCsv,
    /// The `GroupAddress-Export` XML document.
    EtsXml,
}

impl GroupFormat {
    /// How a sentence names the format.
    pub fn label(self) -> &'static str {
        match self {
            GroupFormat::EtsCsv => "ETS CSV",
            GroupFormat::EtsXml => "ETS XML",
        }
    }
}

/// Writes the group-address plan of the model in `dir` to `out` in `format`.
/// Returns how many group addresses it holds.
///
/// # Errors
///
/// The model does not load, or the file cannot be written.
pub fn groups(dir: &Path, format: GroupFormat, out: &Path) -> Result<usize, SetupError> {
    let model = Model::load(dir).ctx(|| format!("loading {}", dir.display()))?;
    let body = match format {
        GroupFormat::EtsCsv => to_ets_csv(&model.groups),
        GroupFormat::EtsXml => to_ets_xml(&model.groups),
    };
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ctx(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(out, body.as_bytes()).ctx(|| format!("writing {}", out.display()))?;
    Ok(model.groups.groups.len())
}

/// Builds the installation documentation of the model in `dir`.
///
/// # Errors
///
/// The model does not load.
pub fn doc_model(dir: &Path) -> Result<InstallationDoc, SetupError> {
    let model = Model::load(dir).ctx(|| format!("loading the model from {}", dir.display()))?;
    let products = ProductModels::load(dir);
    Ok(InstallationDoc::build(&model, &products, dir))
}

/// Renders the installation documentation of the model in `dir` in `format`
/// and writes the files under `out`. Returns the written paths, relative to
/// `out`.
///
/// # Errors
///
/// The model does not load, or a file cannot be written.
pub fn doc(dir: &Path, out: &Path, format: DocFormat) -> Result<Vec<String>, SetupError> {
    let files = doc_model(dir)?.render(format);
    write_files(&files, out).ctx(|| format!("writing the documentation to {}", out.display()))?;
    Ok(files.into_iter().map(|f| f.path).collect())
}
