//! Product data fetches itself (the `import` and `adopt` download step).
//!
//! `apply` and `flash` need the vendor's `.knxprod` for a device's order
//! number under `<dir>/vendor/`, and `validate` reads the product models under
//! `<dir>/models/`. `import` and `adopt` know the order numbers, so they look
//! every one without product data up in the pointer index (the same one
//! `import-product --order-number` uses), ask once for the whole list,
//! download, verify, cache and generate the models, and name what they could
//! not find with the sentence that says where to get it.
//!
//! The download is injectable for tests: `BUSSARD_PRODUCT_INDEX` points at
//! another index, whose entries may use `file://` URLs; `--no-download` skips
//! the step entirely.

use std::path::Path;

use bussard_service::setup::{DownloadAnswer, DownloadPrompt, SetupError};

pub(crate) use bussard_service::setup::products::Outcome;

/// How the caller answers the one download question.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Consent {
    /// `--yes-download`: download without asking.
    pub yes_download: bool,
    /// `--no-download`: never download; report what is missing.
    pub no_download: bool,
}

impl DownloadPrompt for Consent {
    fn skip_downloads(&self) -> Option<String> {
        self.no_download.then(|| "--no-download".to_string())
    }

    fn download(&mut self, question: &str, files: usize) -> Result<DownloadAnswer, SetupError> {
        match crate::confirm::download(self.yes_download, question).map_err(SetupError::source)? {
            crate::confirm::Download::Yes => Ok(DownloadAnswer::Yes),
            crate::confirm::Download::No => Ok(DownloadAnswer::No),
            crate::confirm::Download::NoTerminal => Ok(DownloadAnswer::Refused(
                crate::confirm::download_refusal(&format!("{files} file(s)")),
            )),
        }
    }
}

/// Looks every order number in `orders` without product data up in the
/// index, asks once for the whole list, downloads, caches under
/// `<dir>/products/` and generates the models
/// ([`bussard_service::setup::products::fetch_missing`]).
///
/// Never fails the caller's command over a download: a refusal or a failed
/// download is reported in the [`Outcome`] and the command continues without
/// that product's data.
pub(crate) fn fetch_missing(
    dir: &Path,
    orders: &[String],
    mut consent: Consent,
) -> anyhow::Result<Outcome> {
    Ok(bussard_service::setup::products::fetch_missing(
        dir,
        orders,
        &mut consent,
        &mut crate::console::Console,
    )?)
}

/// Prints the end-of-command report: one sentence per order number without
/// product data.
pub(crate) fn print_missing(outcome: &Outcome, dir: &Path) {
    bussard_service::setup::products::report_missing(outcome, dir, &mut crate::console::Console);
}
