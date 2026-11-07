//! The `bussard import-product` subcommand: record vendor product data in the
//! model's product store and generate its product models.
//!
//! Reads a `.knxprod` (see `bussard-prod`), stores the original byte-identical
//! under `<dir>/products/` (retained model data, see
//! [`crate::product_store`]), pins it in `bussard.lock`, and writes one
//! machine-generated product model per ApplicationProgram under
//! `<dir>/.bussard/model-cache/` (regenerated from the archive whenever it is
//! missing).
//!
//! An ETS project export (`.knxproj`) also carries the product data of every
//! device in the project. Each application program is extracted from it once
//! into its own archive under `products/` (`<application-id>.knxprod`,
//! see [`bussard_product::extract_from_project`]); the export itself is never
//! copied.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::bail;
use bussard_product::ProductIndex;
use bussard_service::files::products as files;
use bussard_service::setup::products;

use crate::cli::{Resolved, Run};
use crate::console::Console;

pub(crate) use bussard_service::files::products::is_project_export;

/// `bussard import-product`.
#[derive(Debug, clap::Args)]
pub(crate) struct ImportProductArgs {
    /// The `.knxprod` or `.knxproj` file to import (positional mode).
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,
    /// Look the `.knxprod` up in the pointer index by order number and
    /// download it from the vendor (with confirmation).
    #[arg(long, value_name = "ORDER", conflicts_with = "file")]
    order_number: Option<String>,
    /// Download the vendor product data without asking. Without a
    /// terminal and without this flag the download is refused. Only
    /// meaningful with `--order-number`.
    #[arg(long)]
    yes_download: bool,
    /// When the `.knxprod` is a ZIP wrapping several inner `.knxprod` files,
    /// select which one to import (by entry or file name). Ignored for a
    /// plain `.knxprod` or a single-inner wrapper.
    #[arg(long, value_name = "NAME")]
    inner: Option<String>,
    /// List the product-data pointer index and exit.
    #[arg(long, conflicts_with_all = ["file", "order_number"])]
    list: bool,
}

impl Run for ImportProductArgs {
    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(
            self.file.as_deref(),
            g.dir(),
            self.order_number.as_deref(),
            self.yes_download,
            self.inner.as_deref(),
            self.list,
        )
    }
}

/// Dispatches the three `import-product` modes:
///
/// * `--list`: print the pointer index and exit.
/// * `--order-number`: look the file up in the index, confirm, download,
///   verify, then run the normal import on the downloaded file.
/// * positional FILE: run the normal import on a local `.knxprod`.
fn run(
    file: Option<&Path>,
    dir: &Path,
    order_number: Option<&str>,
    yes_download: bool,
    inner: Option<&str>,
    list: bool,
) -> anyhow::Result<ExitCode> {
    if list {
        return run_list();
    }
    if let Some(order) = order_number {
        return run_order_number(order, dir, yes_download, inner);
    }
    match file {
        Some(f) => run_file(f, dir, inner),
        None => bail!(
            "nothing to import: give a .knxprod FILE, --order-number <ORDER> to \
             download from the index, or --list to show the index"
        ),
    }
}

/// Prints the pointer index in a compact table.
fn run_list() -> anyhow::Result<ExitCode> {
    let index = load_index()?;
    if index.entries.is_empty() {
        println!("The product-data pointer index is empty.");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "Product-data pointer index ({} entr{}):",
        index.entries.len(),
        if index.entries.len() == 1 { "y" } else { "ies" }
    );
    println!();
    for e in &index.entries {
        println!("{} — {}", e.manufacturer, e.name);
        println!("  order numbers: {}", e.order_numbers.join(", "));
        println!("  file: {} ({} bytes)", e.filename, e.size);
        println!("  from: {}", e.url);
        if let Some(notes) = &e.notes {
            println!("  notes: {notes}");
        }
        println!();
    }
    println!("Import one with:  bussard import-product --order-number <ORDER> [--yes-download]");
    Ok(ExitCode::SUCCESS)
}

/// `--order-number`: looks the file up in the index, confirms, downloads,
/// verifies and imports it
/// ([`bussard_service::files::products::import_product_order`]).
fn run_order_number(
    order: &str,
    dir: &Path,
    yes_download: bool,
    inner: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let mut prompt = crate::confirm::Answers {
        yes_download,
        ..Default::default()
    };
    match files::import_product_order(order, dir, inner, &mut prompt, &mut Console)? {
        files::OrderImport::Declined => Ok(ExitCode::FAILURE),
        files::OrderImport::Imported(_) => Ok(ExitCode::SUCCESS),
    }
}

/// Loads and parses the pointer index
/// ([`bussard_service::setup::products::load_index`]).
pub(crate) fn load_index() -> anyhow::Result<ProductIndex> {
    Ok(products::load_index()?)
}

/// Runs the normal import on a local `.knxprod` file (positional mode,
/// [`bussard_service::files::products::import_product_file`]).
fn run_file(file: &Path, dir: &Path, inner: Option<&str>) -> anyhow::Result<ExitCode> {
    files::import_product_file(file, dir, inner, &mut Console)?;
    Ok(ExitCode::SUCCESS)
}
