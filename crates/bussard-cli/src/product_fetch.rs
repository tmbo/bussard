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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use bussard_prod::{DownloadConsent, normalize_order_number};

/// How the caller answers the one download question.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Consent {
    /// `--yes`: download without asking.
    pub yes: bool,
    /// `--no-download`: never download; report what is missing.
    pub no_download: bool,
}

/// What the download step did.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    /// The order numbers now backed by a cached archive, with its path.
    pub fetched: Vec<(String, PathBuf)>,
    /// Order numbers the index does not know.
    pub not_found: Vec<String>,
    /// Order numbers the index knows but that were not downloaded (declined,
    /// `--no-download`, no terminal to ask on, or the download failed), with
    /// why.
    pub not_fetched: Vec<(String, String)>,
}

impl Outcome {
    /// Every order number that still has no product data.
    pub(crate) fn missing(&self) -> BTreeSet<String> {
        self.not_found
            .iter()
            .cloned()
            .chain(self.not_fetched.iter().map(|(o, _)| o.clone()))
            .collect()
    }
}

/// The normalized order numbers the product models under `<dir>/models/`
/// cover (what `import-product` generated them for).
pub(crate) fn cached_orders(dir: &Path) -> BTreeSet<String> {
    #[derive(serde::Deserialize)]
    struct Orders {
        #[serde(default)]
        order_numbers: Vec<String>,
    }
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(dir.join("models")) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(orders) = serde_norway::from_str::<Orders>(&text) {
            out.extend(
                orders
                    .order_numbers
                    .iter()
                    .map(|o| normalize_order_number(o)),
            );
        }
    }
    out
}

/// The sentence for an order number bussard could not find product data for.
pub(crate) fn not_found_sentence(order: &str, dir: &Path) -> String {
    format!(
        "{order}: not in bussard's product index. Download the product data (.knxprod) from \
         the manufacturer's website (or export it from ETS's catalog), then run `bussard \
         import-product <file> --dir {}`.",
        dir.display()
    )
}

/// Looks every order number in `orders` without product data up in the
/// index, asks once for the whole list, downloads, caches under
/// `<dir>/vendor/` and generates the models.
///
/// Never fails the caller's command over a download: a refusal or a failed
/// download is reported in the [`Outcome`] and the command continues without
/// that product's data.
pub(crate) fn fetch_missing(
    dir: &Path,
    orders: &[String],
    consent: Consent,
) -> anyhow::Result<Outcome> {
    let cached = cached_orders(dir);
    let mut seen = BTreeSet::new();
    let missing: Vec<String> = orders
        .iter()
        .map(|o| o.trim().to_string())
        .filter(|o| !o.is_empty())
        .filter(|o| !cached.contains(&normalize_order_number(o)))
        .filter(|o| seen.insert(normalize_order_number(o)))
        .collect();
    let mut outcome = Outcome::default();
    if missing.is_empty() {
        return Ok(outcome);
    }
    let index = crate::import_product_cmd::load_index()?;
    // Group the order numbers by the archive that serves them: one download
    // often covers a whole product family.
    let mut downloads: Vec<(&bussard_prod::IndexEntry, Vec<String>)> = Vec::new();
    for order in &missing {
        match index.lookup(order) {
            Some(entry) => match downloads.iter_mut().find(|(e, _)| e.url == entry.url) {
                Some((_, list)) => list.push(order.clone()),
                None => downloads.push((entry, vec![order.clone()])),
            },
            None => outcome.not_found.push(order.clone()),
        }
    }
    if downloads.is_empty() {
        return Ok(outcome);
    }
    let not_fetched = |why: &str, outcome: &mut Outcome, downloads: &[(_, Vec<String>)]| {
        for (_, list) in downloads {
            for order in list {
                outcome.not_fetched.push((order.clone(), why.to_string()));
            }
        }
    };
    if consent.no_download {
        not_fetched("--no-download", &mut outcome, &downloads);
        return Ok(outcome);
    }

    let total: u64 = downloads.iter().map(|(e, _)| e.size).sum();
    println!(
        "product data missing for {} order number(s); bussard's product index has {} \
         download(s) for them:",
        missing.len(),
        downloads.len()
    );
    for (entry, list) in &downloads {
        println!(
            "  {}: {} {} ({} bytes from {})",
            list.join(", "),
            entry.manufacturer,
            entry.name,
            entry.size,
            entry.url
        );
    }
    println!(
        "These are copyrighted vendor files; they are cached under {} and never committed.",
        dir.join("vendor").display()
    );
    let question = format!(
        "download {} file(s) ({:.1} MB) now?",
        downloads.len(),
        total as f64 / 1_000_000.0
    );
    let agreed = if consent.yes {
        true
    } else if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        crate::confirm::ask(&question)?
    } else {
        println!("no terminal to ask on: pass --yes to download, --no-download to skip");
        false
    };
    if !agreed {
        not_fetched("not downloaded", &mut outcome, &downloads);
        return Ok(outcome);
    }
    for (entry, list) in downloads {
        let result =
            crate::import_product_cmd::fetch_to_vendor(entry, dir, DownloadConsent::granted())
                .and_then(|path| {
                    crate::import_product_cmd::generate_models(&path, dir)
                        .map(|models| (path, models))
                });
        match result {
            Ok((path, models)) => {
                println!("  cached {} ({} model(s))", path.display(), models.len());
                for order in list {
                    outcome.fetched.push((order, path.clone()));
                }
            }
            Err(err) => {
                eprintln!("  download of {} failed: {err:#}", entry.filename);
                for order in list {
                    outcome
                        .not_fetched
                        .push((order, format!("the download failed: {err:#}")));
                }
            }
        }
    }
    Ok(outcome)
}

/// Prints the end-of-command report: one sentence per order number without
/// product data.
pub(crate) fn print_missing(outcome: &Outcome, dir: &Path) {
    if outcome.not_found.is_empty() && outcome.not_fetched.is_empty() {
        return;
    }
    println!("product data still missing:");
    for order in &outcome.not_found {
        println!("  {}", not_found_sentence(order, dir));
    }
    for (order, why) in &outcome.not_fetched {
        println!(
            "  {order}: in bussard's product index but {why}; run `bussard import-product \
             --order-number {order} --dir {}` to fetch it.",
            dir.display()
        );
    }
}
