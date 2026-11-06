//! The `bussard export-groups` subcommand (issue #104).
//!
//! Writes the group-address plan in one of the two formats ETS's
//! *Group Addresses -> Import* accepts, so names and DPTs curated in bussard can
//! go back to the integrator's ETS project. See [`bussard_model::ets_export`]
//! for the exact shapes.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bussard_service::files::export::GroupFormat;

use crate::cli::{Resolved, Run};

/// The export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    /// The three-level CSV ETS exports and imports (BOM, semicolon separated).
    EtsCsv,
    /// The `GroupAddress-Export` XML document.
    EtsXml,
}

/// `bussard export-groups`.
#[derive(Debug, clap::Args)]
pub(crate) struct ExportGroupsArgs {
    /// The export format.
    #[arg(long, value_enum)]
    format: ExportFormat,
    /// The file to write.
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
}

impl Run for ExportGroupsArgs {
    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(g.dir(), self.format, &self.out)
    }
}

/// Runs the export-groups command.
fn run(dir: &Path, format: ExportFormat, out: &Path) -> anyhow::Result<ExitCode> {
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
