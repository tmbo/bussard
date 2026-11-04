//! Manufacturer names: one lookup for every place that shows a manufacturer.
//!
//! KNX assigns each manufacturer a numeric id (the value behind
//! `PID_MANUFACTURER_ID`). A name comes from, in order:
//!
//! 1. the manufacturer list of the imported ETS master data
//!    (`products/manufacturers.toml`, see
//!    [`bussard_model::manufacturer_names`]), installed for this process by
//!    [`load_model_dir`] or [`install`];
//! 2. the small built-in table [`MANUFACTURERS`];
//! 3. otherwise `unknown manufacturer (0x0048)`.
//!
//! Ids are the public KNX manufacturer numbers.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::RwLock;

/// The manufacturer list of the model this process works on (issue #788).
static PROJECT: RwLock<BTreeMap<u16, String>> = RwLock::new(BTreeMap::new());

/// Common KNX manufacturer ids and their display names: the fallback when the
/// model has no imported manufacturer list or it lacks an id.
pub const MANUFACTURERS: &[(u16, &str)] = &[
    (0x0001, "Siemens"),
    (0x0002, "ABB"),
    (0x0004, "Jung"),
    (0x0006, "Berker"),
    (0x0009, "GIRA"),
    (0x000C, "Merten"),
    (0x0016, "Legrand"),
    (0x0018, "Busch-Jaeger"),
    (0x0021, "Hager"),
    (0x0025, "Steinel"),
    (0x0028, "Theben"),
    (0x0069, "Helios"),
    // 0x00FA is the KNX Association itself; KNX Virtual's simulated devices
    // report it (observed live 2026-09-16).
    (0x00FA, "KNX Association"),
    (0x0083, "MDT"),
];

/// Installs `names` (numeric id to name) as the project's manufacturer list
/// for this process, replacing any list installed before.
pub fn install(names: BTreeMap<u16, String>) {
    let mut project = PROJECT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *project = names;
}

/// Reads the manufacturer list of the model in `dir` and installs it (see
/// [`install`]). A model without a list installs the empty one; a list that
/// does not read keeps the installed one and is logged.
pub fn load_model_dir(dir: &Path) {
    match bussard_model::manufacturer_names::load(dir) {
        Ok(names) => install(names),
        Err(err) => tracing::warn!("ignoring the manufacturer list: {err}"),
    }
}

/// Looks up a manufacturer name by id: the project's list first, then the
/// built-in table; `None` if neither knows it.
pub fn name(id: u16) -> Option<String> {
    let project = PROJECT
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(name) = project.get(&id) {
        return Some(name.clone());
    }
    builtin_name(id).map(str::to_string)
}

/// Looks a manufacturer up in the built-in table only.
pub fn builtin_name(id: u16) -> Option<&'static str> {
    MANUFACTURERS
        .iter()
        .find_map(|(k, v)| (*k == id).then_some(*v))
}

/// Formats a manufacturer id as its name (see [`name`]), or
/// `unknown manufacturer (0x0048)` if no list knows it.
pub fn display(id: u16) -> String {
    match name(id) {
        Some(n) => n,
        None => format!("unknown manufacturer (0x{id:04X})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The install test touches only ids the other tests do not check, so the
    // process-wide list cannot race them under a threaded `cargo test`.

    #[test]
    fn test_name_builtin_ids_map_to_names() {
        assert_eq!(name(0x0004).as_deref(), Some("Jung"));
        assert_eq!(name(0x0083).as_deref(), Some("MDT"));
        assert_eq!(display(0x0002), "ABB");
    }

    #[test]
    fn test_display_unknown_id_names_it_unknown() {
        assert_eq!(name(0xABCD), None);
        assert_eq!(display(0xABCD), "unknown manufacturer (0xABCD)");
    }

    #[test]
    fn test_install_project_list_comes_first() {
        install(BTreeMap::from([
            (0x0001, "Siemens Schweiz".to_string()),
            (0x0048, "Example Maker".to_string()),
        ]));
        assert_eq!(display(0x0001), "Siemens Schweiz");
        assert_eq!(display(0x0048), "Example Maker");
        // The built-in table still answers what the list does not name.
        assert_eq!(display(0x0002), "ABB");
        install(BTreeMap::new());
        assert_eq!(display(0x0048), "unknown manufacturer (0x0048)");
    }
}
