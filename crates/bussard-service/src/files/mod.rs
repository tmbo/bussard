//! Importing and exporting model files outside the first setup: the one copy
//! behind the CLI's `import` (re-import and bundles), `import-product`,
//! `keys`, `export`, `export-groups` and `doc`, and the MCP tools
//! `knx_import_file` and `knx_export` (issues #743, #744).
//!
//! The flows build on the pieces of [`crate::setup`] (the product store, the
//! download step, the history snapshots, the fresh import write) and report
//! the same way: every line goes to a [`crate::observer::ProgressSink`], every
//! question to a prompt trait the surface implements. The CLI prints and asks
//! on the terminal; the MCP tools collect the lines and answer from their
//! arguments.
//!
//! - [`products`]: `import-product` of a local `.knxprod` or an index entry.
//! - [`import`]: writing an imported model over an existing one (the merge
//!   and its conflicts), a `.bussard` bundle.
//! - [`keyring`]: the keyring export and its read-back. No key material is
//!   ever reported.
//! - [`export`]: the bundle, the group plan for ETS and the handover
//!   documentation.

pub mod export;
pub mod import;
pub mod keyring;
pub mod products;
pub mod report;

use std::path::Path;

/// The kind of file an import reads, from its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// An ETS project export, `.knxproj`.
    Project,
    /// A bussard bundle, `.bussard`.
    Bundle,
    /// Vendor product data, `.knxprod`.
    Product,
    /// An ETS keyring export, `.knxkeys`.
    Keyring,
}

impl FileKind {
    /// The kind of `path` by its extension (case-insensitive), or `None`.
    pub fn of(path: &Path) -> Option<FileKind> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "knxproj" => FileKind::Project,
            "bussard" => FileKind::Bundle,
            "knxprod" => FileKind::Product,
            "knxkeys" => FileKind::Keyring,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_kind_of_dispatches_on_the_extension() {
        assert_eq!(
            FileKind::of(Path::new("a/House.KNXPROJ")),
            Some(FileKind::Project)
        );
        assert_eq!(FileKind::of(Path::new("h.bussard")), Some(FileKind::Bundle));
        assert_eq!(
            FileKind::of(Path::new("p.knxprod")),
            Some(FileKind::Product)
        );
        assert_eq!(
            FileKind::of(Path::new("k.knxkeys")),
            Some(FileKind::Keyring)
        );
        assert_eq!(FileKind::of(Path::new("d.json")), None);
        assert_eq!(FileKind::of(Path::new("notes.txt")), None);
        assert_eq!(FileKind::of(Path::new("noext")), None);
    }
}
