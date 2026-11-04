//! The `bussard export-groups` subcommand (issue #104).
//!
//! Writes the group-address plan in one of the two formats ETS's
//! *Group Addresses -> Import* accepts, so names and DPTs curated in bussard can
//! go back to the integrator's ETS project. See [`bussard_model::ets_export`]
//! for the exact shapes.

use std::path::Path;
use std::process::ExitCode;

use bussard_service::files::export::GroupFormat;

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
    let format = match format {
        ExportFormat::EtsCsv => GroupFormat::EtsCsv,
        ExportFormat::EtsXml => GroupFormat::EtsXml,
    };
    let count = bussard_service::files::export::groups(dir, format, out)?;
    println!(
        "Wrote {count} group address(es) to {} ({}).",
        out.display(),
        format.label()
    );
    println!("Import it in ETS: Group Addresses -> Import, then pick this file.");

    Ok(ExitCode::SUCCESS)
}
