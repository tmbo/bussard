//! A diff between two projects in one shape (issue #904): `bussard diff
//! --json` and `knx_diff_project`.

use bussard_model::Change;
use bussard_model::bundle::BundleManifest;
use bussard_model::change::ChangeSet;
use bussard_model::checklist::Checklist;
use serde::Serialize;

use crate::report::Report;

/// What the other side of a chat diff was read from.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum DiffSource {
    /// A `.bussard` bundle.
    Bundle {
        /// Its manifest.
        manifest: Box<BundleManifest>,
    },
    /// An ETS `.knxproj`.
    Knxproj,
}

/// The changes from one project to another.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectDiffReport {
    /// Always `true`.
    pub ok: bool,
    /// The first side.
    pub from: String,
    /// The second side.
    pub to: String,
    /// What the second side was read from, when it is a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<DiffSource>,
    /// How many changes.
    pub count: usize,
    /// The changes in one line.
    pub summary: String,
    /// A protected group address is among them.
    pub touches_protected: bool,
    /// One sentence per change.
    pub sentences: Vec<String>,
    /// The changes.
    pub changes: Vec<Change>,
}

impl ProjectDiffReport {
    /// The `changes` from `from` to `to`.
    pub fn new(from: impl Into<String>, to: impl Into<String>, changes: &ChangeSet) -> Self {
        ProjectDiffReport {
            ok: true,
            from: from.into(),
            to: to.into(),
            source: None,
            count: changes.len(),
            summary: if changes.is_empty() {
                "no differences".to_string()
            } else {
                changes.summary()
            },
            touches_protected: changes.touches_protected(),
            sentences: changes.changes.iter().map(|c| c.sentence.clone()).collect(),
            changes: changes.changes.clone(),
        }
    }
}

impl Report for ProjectDiffReport {
    const SCHEMA: u32 = 2;
}

/// `bussard diff --checklist --json`: the checklist of what to redo in ETS.
#[derive(Debug, Clone, Serialize)]
pub struct ChecklistReport {
    /// The first side.
    pub from: String,
    /// The second side.
    pub to: String,
    /// The checklist.
    #[serde(flatten)]
    pub checklist: Checklist,
}

impl Report for ChecklistReport {
    const SCHEMA: u32 = 2;
}
