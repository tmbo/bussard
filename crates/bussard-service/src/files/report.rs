//! The import and export of project files in one shape (issue #904): the
//! CLI's `keys import`, `keys export` and `export --json` print a
//! [`FileOutcome`], and `knx_import_file` and `knx_export` return the same
//! object plus the chat envelope.

use std::path::Path;

use bussard_model::Model;
use bussard_model::bundle::BundleManifest;
use bussard_project::keystore::{ImportReport, KeyringExport, SaveOutcome};
use serde::Serialize;

use crate::model_edit::DiagnosticRow;
use crate::report::{Report, is_false};

/// One import or export of a project file. Every field but the verdict and
/// the path is there only when the flow has it.
#[derive(Clone, Default, Serialize)]
pub struct FileOutcome {
    /// It worked (an export: and the file was verified, for a keyring).
    pub ok: bool,
    /// A policy or a check refused it; nothing was written.
    #[serde(skip_serializing_if = "is_false")]
    pub refused: bool,
    /// Why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What was imported: `project`, `bundle`, `product` or `keyring`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// What was exported: `bundle`, `groups`, `doc` or `keyring`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    /// The file read or written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The order number a product import fetched for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_number: Option<String>,
    /// The key store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// Files were written (false for a no-op).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
    /// The key store was backed up first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<bool>,
    /// A re-import merged into the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merged: Option<bool>,
    /// Hand-edited fields that differ from the incoming side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<usize>,
    /// Those kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kept: Option<usize>,
    /// The key store changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    /// What a keyring import changed (counts and addresses, never a key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ImportReport>,
    /// The product models generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
    /// The bundle written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<BundleManifest>,
    /// The group addresses written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    /// Their format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// The documentation files written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<String>>,
    /// The keyring written (counts and addresses, never a key).
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub keyring: Option<KeyringExport>,
    /// What a keyring import's new keys mean for the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<DiagnosticRow>>,
    /// What the flow said, line by line.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sentences: Vec<String>,
    /// A note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The sentence for the human.
    #[serde(skip)]
    pub said: Option<String>,
}

/// What a keyring never shows.
const NO_KEYS: &str = "key material is never returned";

impl FileOutcome {
    /// A refusal: nothing was written; `sentences` is what the flow said
    /// before it stopped.
    pub fn refused(reason: impl Into<String>, sentences: Vec<String>) -> FileOutcome {
        FileOutcome {
            refused: true,
            reason: Some(reason.into()),
            sentences,
            ..FileOutcome::default()
        }
    }

    /// A keyring merged from `path` into the store of `dir`.
    pub fn keyring_imported(
        dir: &Path,
        path: &Path,
        report: ImportReport,
        outcome: SaveOutcome,
        warnings: &[bussard_model::Diagnostic],
    ) -> FileOutcome {
        let what = match outcome {
            SaveOutcome::Written { backup: false } => "created",
            SaveOutcome::Written { backup: true } => "updated",
            SaveOutcome::Unchanged => "already up to date",
        };
        let said = format!(
            "Merged the ETS keyring {} into the key store bussard.keys ({what}): {} device(s) \
             added, {} tool key(s) rotated, {} group key(s) added, {} rotated.",
            file_name(path),
            report.devices_added.len(),
            report.tool_keys_rotated.len(),
            report.group_keys_added.len(),
            report.group_keys_rotated.len(),
        );
        FileOutcome {
            ok: true,
            kind: Some("keyring".to_string()),
            path: Some(path.display().to_string()),
            store: Some(crate::keys::KeyStore::path(dir).display().to_string()),
            written: Some(matches!(outcome, SaveOutcome::Written { .. })),
            backup: Some(matches!(outcome, SaveOutcome::Written { backup: true })),
            changed: Some(report.changed()),
            report: Some(report),
            warnings: Some(
                warnings
                    .iter()
                    .map(|d| DiagnosticRow {
                        code: d.code.to_string(),
                        message: d.message.clone(),
                        location: d.location.clone(),
                    })
                    .collect(),
            ),
            note: Some(NO_KEYS.to_string()),
            said: Some(said),
            ..FileOutcome::default()
        }
    }

    /// The keyring `export` written to `out`; `sentences` is what the export
    /// said.
    pub fn keyring_exported(
        out: &Path,
        export: KeyringExport,
        sentences: Vec<String>,
    ) -> FileOutcome {
        let said = if export.verified {
            format!(
                "Wrote {}: {} device(s), {} group key(s), {} interface(s), read back and \
                 verified; keep it out of git.",
                out.display(),
                export.devices,
                export.group_keys,
                export.interfaces
            )
        } else {
            format!(
                "Wrote {}, but it does not carry the key store's keys: do not hand it on.",
                out.display()
            )
        };
        FileOutcome {
            ok: export.verified,
            what: Some("keyring".to_string()),
            path: Some(out.display().to_string()),
            keyring: Some(export),
            sentences,
            note: Some(NO_KEYS.to_string()),
            said: Some(said),
            ..FileOutcome::default()
        }
    }

    /// The bundle written to `path`.
    pub fn bundle_exported(path: &Path, manifest: BundleManifest) -> FileOutcome {
        let said = format!(
            "Wrote the bundle {}: {} device(s), {} group address(es), {} history snapshot(s); \
             it never contains vendor product data, keyrings or passwords.",
            path.display(),
            manifest.devices,
            manifest.group_addresses,
            manifest.history_snapshots
        );
        FileOutcome {
            ok: true,
            what: Some("bundle".to_string()),
            path: Some(path.display().to_string()),
            manifest: Some(manifest),
            said: Some(said),
            ..FileOutcome::default()
        }
    }

    /// `count` group addresses written to `out` in `format`.
    pub fn groups_exported(out: &Path, count: usize, format: &str) -> FileOutcome {
        FileOutcome {
            ok: true,
            what: Some("groups".to_string()),
            path: Some(out.display().to_string()),
            count: Some(count),
            format: Some(format.to_string()),
            said: Some(format!(
                "Wrote {count} group address(es) to {} ({format}); in ETS: Group Addresses -> \
                 Import, then pick this file.",
                out.display()
            )),
            ..FileOutcome::default()
        }
    }

    /// The documentation `files` written to `out`.
    pub fn doc_exported(out: &Path, files: Vec<String>) -> FileOutcome {
        FileOutcome {
            ok: true,
            what: Some("doc".to_string()),
            path: Some(out.display().to_string()),
            said: Some(format!(
                "Wrote {} documentation file(s) to {}: {}.",
                files.len(),
                out.display(),
                files.join(", ")
            )),
            files: Some(files),
            ..FileOutcome::default()
        }
    }

    /// A project or bundle (`source`) imported from `path` into `dir`.
    pub fn model_imported(
        source: &str,
        path: &Path,
        dir: &Path,
        outcome: &crate::files::import::ImportOutcome,
        sentences: Vec<String>,
    ) -> FileOutcome {
        let name = file_name(path);
        let counts = Model::load(dir)
            .ok()
            .map(|m| (m.devices.len(), m.groups.groups.len()));
        let mut said = match (outcome.written, counts) {
            (false, _) => format!("The model already matched {name}; no file was written."),
            (true, Some((devices, groups))) => format!(
                "Imported {name} into the model: {devices} device(s), {groups} group \
                 address(es)."
            ),
            (true, None) => format!("Imported {name} into the model."),
        };
        if outcome.unresolved {
            said.push_str(&format!(
                " {} hand-edited field(s) differ from the {source} and were kept; pass theirs: \
                 true to take the {source}'s values.",
                outcome.kept
            ));
        }
        FileOutcome {
            ok: true,
            kind: Some(source.to_string()),
            path: Some(path.display().to_string()),
            written: Some(outcome.written),
            merged: Some(outcome.merged),
            conflicts: Some(outcome.conflicts),
            kept: Some(outcome.kept),
            sentences,
            said: Some(said),
            ..FileOutcome::default()
        }
    }

    /// A product archive stored (`stored` in words) with its generated
    /// `models`.
    pub fn product_imported(
        stored: &str,
        models: Vec<String>,
        sentences: Vec<String>,
    ) -> FileOutcome {
        FileOutcome {
            ok: true,
            kind: Some("product".to_string()),
            said: Some(format!(
                "{stored}; generated {} product model(s): {}.",
                models.len(),
                models.join(", ")
            )),
            models: Some(models),
            sentences,
            ..FileOutcome::default()
        }
    }
}

impl Report for FileOutcome {
    const SCHEMA: u32 = 2;

    fn summary(&self, _model: &Model) -> Option<String> {
        self.said.clone()
    }
}

/// The file name of `path`, or the path when it has none.
fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}
