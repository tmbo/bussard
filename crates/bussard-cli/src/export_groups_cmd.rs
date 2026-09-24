//! The `bussard export-groups` subcommand (issue #104).
//!
//! Writes the group-address plan in one of the two formats ETS's
//! *Group Addresses -> Import* accepts, so names and DPTs curated in bussard can
//! go back to the integrator's ETS project. See [`bussard_model::ets_export`]
//! for the exact shapes.

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::{Model, to_ets_csv, to_ets_xml};

/// The export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    /// The three-level CSV ETS exports and imports (BOM, semicolon separated).
    EtsCsv,
    /// The `GroupAddress-Export` XML document.
    EtsXml,
}

/// Runs the export-groups command.
pub fn run(dir: &Path, format: ExportFormat, out: &Path) -> anyhow::Result<ExitCode> {
    let model = Model::load(dir).with_context(|| format!("loading {}", dir.display()))?;

    let body = match format {
        ExportFormat::EtsCsv => to_ets_csv(&model.groups),
        ExportFormat::EtsXml => to_ets_xml(&model.groups),
    };

    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(out, body.as_bytes()).with_context(|| format!("writing {}", out.display()))?;

    let label = match format {
        ExportFormat::EtsCsv => "ETS CSV",
        ExportFormat::EtsXml => "ETS XML",
    };
    println!(
        "Wrote {} group address(es) to {} ({label}).",
        model.groups.groups.len(),
        out.display()
    );
    println!("Import it in ETS: Group Addresses -> Import, then pick this file.");

    Ok(ExitCode::SUCCESS)
}
