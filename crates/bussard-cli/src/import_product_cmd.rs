//! The `bussard import-product` subcommand: record vendor product data in the
//! model's product store and generate its product models.
//!
//! Reads a `.knxprod` (see `bussard-prod`), stores the original byte-identical
//! under `<dir>/products/` (retained model data, see
//! [`crate::product_store`]), pins it in `bussard.lock`, and writes one
//! machine-generated product model per ApplicationProgram under
//! `<dir>/.bussard/models/` (regenerated from the archive whenever it is
//! missing).
//!
//! An ETS project export (`.knxproj`) also carries the product data of every
//! device in the project. Each application program is extracted from it once
//! into its own archive under `products/` (`<application-id>.knxprod`,
//! see [`bussard_prod::extract_from_project`]); the export itself is never
//! copied.

use std::path::Path;
use std::process::ExitCode;

use anyhow::bail;
use bussard_prod::{ProductData, ProductIndex};
use bussard_service::files::products as files;
use bussard_service::setup::products;
use bussard_service::setup::{DownloadAnswer, DownloadPrompt, SetupError};

use crate::console::Console;

pub(crate) use bussard_service::files::products::is_project_export;

/// Dispatches the three `import-product` modes:
///
/// * `--list`: print the pointer index and exit.
/// * `--order-number`: look the file up in the index, confirm, download,
///   verify, then run the normal import on the downloaded file.
/// * positional FILE: run the normal import on a local `.knxprod`.
pub fn run(
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
    let mut prompt = OrderPrompt { yes_download };
    match files::import_product_order(order, dir, inner, &mut prompt, &mut Console)? {
        files::OrderImport::Declined => Ok(ExitCode::FAILURE),
        files::OrderImport::Imported(_) => Ok(ExitCode::SUCCESS),
    }
}

/// The download question of `--order-number`: asked on a TTY; without one it
/// needs `--yes-download` (the one download-consent flag, `crate::confirm`).
struct OrderPrompt {
    /// `--yes-download`.
    yes_download: bool,
}

impl DownloadPrompt for OrderPrompt {
    fn download(&mut self, question: &str, _files: usize) -> Result<DownloadAnswer, SetupError> {
        Ok(
            match crate::confirm::download(self.yes_download, question)
                .map_err(SetupError::source)?
            {
                crate::confirm::Download::Yes => DownloadAnswer::Yes,
                crate::confirm::Download::No => DownloadAnswer::No,
                crate::confirm::Download::NoTerminal => {
                    DownloadAnswer::Refused(crate::confirm::download_refusal("this file"))
                }
            },
        )
    }
}

/// Loads and parses the pointer index
/// ([`bussard_service::setup::products::load_index`]).
pub(crate) fn load_index() -> anyhow::Result<ProductIndex> {
    Ok(products::load_index()?)
}

/// Writes one model file per application program under
/// `<dir>/.bussard/models/` (see [`bussard_prod::product_model`]).
pub(crate) fn write_product_models(
    product: &ProductData,
    dir: &Path,
) -> anyhow::Result<Vec<String>> {
    Ok(products::write_product_models(product, dir)?)
}

/// Runs the normal import on a local `.knxprod` file (positional mode,
/// [`bussard_service::files::products::import_product_file`]).
fn run_file(file: &Path, dir: &Path, inner: Option<&str>) -> anyhow::Result<ExitCode> {
    files::import_product_file(file, dir, inner, &mut Console)?;
    Ok(ExitCode::SUCCESS)
}
