//! Product-data reading for the CLI (issue #214): parse only the application
//! program a command needs, through the parsed-product cache under
//! `<model dir>/.bussard/products/` (see [`bussard_prod::cache`]).
//!
//! The cache is used when the command has a model directory; setting
//! `BUSSARD_PRODUCT_CACHE=off` disables it (the archive is then parsed every
//! time, as before).

use std::path::Path;

use bussard_prod::{AppSelection, ProductCatalog, ProductData};

#[cfg(test)]
use bussard_prod::product_model::cache_dir;

/// Reads `path` (a `.knxprod`, a wrapper with `inner`, or a `.knxproj`),
/// parsing only what `select` picks, through the cache of the model at `dir`
/// ([`bussard_service::params::read_product`]). The time it took is a
/// `--timing` phase.
///
/// # Errors
///
/// As [`bussard_prod::read_knxprod`].
pub fn read(
    path: &Path,
    inner: Option<&str>,
    dir: &Path,
    language: Option<&str>,
    select: impl FnOnce(&ProductCatalog) -> AppSelection,
) -> bussard_prod::Result<ProductData> {
    bussard_service::params::read_product(path, inner, dir, language, select, Some(record_parse))
}

/// Records one product parse as the `product parse` `--timing` phase.
pub fn record_parse(took: std::time::Duration, detail: String) {
    crate::timing::record("product parse", took, detail);
}

pub use bussard_service::params::{model_language, order_refs, select_id};

/// The selection of the one program `wanted` names, by the rule of
/// [`select_application`] (the exact id, else the one program with the same
/// manufacturer, number and version). Anything that rule would refuse selects
/// every program, so the refusal reads exactly as before.
pub fn by_application(catalog: &ProductCatalog, wanted: &str) -> AppSelection {
    match select_id(catalog, wanted) {
        Some(id) => AppSelection::Only(vec![id]),
        None => AppSelection::All,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_prod::product_model::CACHE_ENV;

    fn catalog(ids: &[&str]) -> ProductCatalog {
        ProductCatalog {
            application_ids: ids.iter().map(|s| s.to_string()).collect(),
            ..ProductCatalog::default()
        }
    }

    #[test]
    fn test_by_application_exact_and_same_program() {
        let cat = catalog(&["M-0004_A-A011-13-400D-O000A", "M-0004_A-B022-10-1111-O000A"]);
        assert_eq!(
            by_application(&cat, "M-0004_A-A011-13-400D-O000A"),
            AppSelection::Only(vec!["M-0004_A-A011-13-400D-O000A".to_string()])
        );
        // Another build hash of the same program (issue #142).
        assert_eq!(
            by_application(&cat, "M-0004_A-A011-13-60BC-O000A"),
            AppSelection::Only(vec!["M-0004_A-A011-13-400D-O000A".to_string()])
        );
    }

    #[test]
    fn test_by_application_unknown_selects_all() {
        let cat = catalog(&["M-0004_A-A011-13-400D-O000A"]);
        assert_eq!(
            by_application(&cat, "M-0083_A-0001-10-0000"),
            AppSelection::All
        );
    }

    #[test]
    fn test_order_refs_normalizes() {
        let mut cat = catalog(&["M-0083_A-0001-10-0000"]);
        cat.hardware.order_to_apps.insert(
            "AKK-0216.03".to_string(),
            vec!["M-0083_A-0001-10-0000".to_string()],
        );
        assert_eq!(
            order_refs(&cat, " akk-0216.03 "),
            vec!["M-0083_A-0001-10-0000".to_string()]
        );
        assert!(order_refs(&cat, "OTHER").is_empty());
    }

    #[test]
    fn test_cache_dir_needs_a_model_directory() -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("bussard-product-cache-{}", std::process::id()));
        std::fs::create_dir_all(&root)?;
        assert!(cache_dir(&root.join("absent")).is_none());
        if std::env::var(CACHE_ENV).is_err() {
            assert_eq!(
                cache_dir(&root),
                Some(root.join(".bussard").join("products"))
            );
        }
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }
}
