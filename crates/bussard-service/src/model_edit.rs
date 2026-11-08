//! The results of the project-file tools in one shape each (issue #904): an
//! edit ([`EditOutcome`]), a change set between two states of the project
//! ([`ChangeReport`], `bussard status --json`, `show --json` and
//! `knx_describe_change`), the snapshot list ([`HistoryReport`], `bussard
//! history --json` and `knx_history`) and an undo ([`UndoReport`]).

use std::collections::BTreeSet;

use bussard_model::change::{ChangeKind, ChangeSet, summarize};
use bussard_model::text::join_and;
use bussard_model::validate::Severity;
use bussard_model::{Change, Diagnostic, IndividualAddress, Model};
use serde::Serialize;

use crate::history::HistoryRow;
use crate::report::{Report, device_phrase};

/// The most changes an edit or undo result lists (issue #279): a result the
/// client has to spill to a file helps nobody.
pub const MAX_RESULT_CHANGES: usize = 50;

/// The most changes `knx_describe_change` lists.
pub const MAX_DESCRIBED_CHANGES: usize = 200;

/// The most diagnostics of one kind a [`Validation`] lists; the counts stay
/// exact and `knx_validate` lists them all.
pub const MAX_RESULT_DIAGNOSTICS: usize = 20;

/// The devices a change set needs pushed (its link, device and parameter
/// changes), by address.
pub fn devices_to_push(changes: &ChangeSet) -> BTreeSet<IndividualAddress> {
    changes
        .changes
        .iter()
        .filter(|c| {
            matches!(
                c.kind,
                ChangeKind::LinkAdded
                    | ChangeKind::LinkRemoved
                    | ChangeKind::DeviceAdded
                    | ChangeKind::DeviceProductChanged
                    | ChangeKind::ObjectSecurityChanged
                    | ChangeKind::InterfaceChanged
                    | ChangeKind::ParameterChanged
            )
        })
        .filter_map(|c| c.device.as_deref()?.parse().ok())
        .collect()
}

/// The homeowner's sentence about a change of the project: what changes,
/// then which devices still need a push. `models` are the new side, then the
/// old.
pub fn edit_summary(changes: &ChangeSet, models: [&Model; 2]) -> String {
    let mut out = summarize(changes, models);
    if changes.is_empty() {
        return out;
    }
    let devices = devices_to_push(changes);
    out.push(' ');
    if devices.is_empty() {
        out.push_str(
            "Nothing to push: this only changes names, rooms or notes in the model, which no \
             device stores.",
        );
    } else {
        let names: Vec<String> = devices
            .iter()
            .map(|ia| {
                let model = if models[0].devices.contains_key(ia) {
                    models[0]
                } else {
                    models[1]
                };
                device_phrase(model, *ia)
            })
            .collect();
        let verb = if names.len() == 1 { "needs" } else { "need" };
        out.push_str(&format!(
            "No device has it yet: {} {verb} to be written before the house behaves this way.",
            join_and(&names)
        ));
    }
    out
}

/// The first `max` changes (protected ones first) as sentences and as
/// structured changes, and a note when some were left out.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Capped {
    /// One sentence per change.
    pub sentences: Vec<String>,
    /// The changes.
    pub detail: Vec<Change>,
    /// What was left out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<String>,
}

impl Capped {
    /// The first `max` of `changes`; `None` lists all.
    pub fn of(changes: &ChangeSet, max: Option<usize>) -> Capped {
        let mut ordered: Vec<&Change> = changes.changes.iter().collect();
        ordered.sort_by_key(|c| !c.touches_protected);
        let total = ordered.len();
        let max = max.unwrap_or(total);
        let detail: Vec<Change> = ordered.into_iter().take(max).cloned().collect();
        Capped {
            sentences: detail.iter().map(|c| c.sentence.clone()).collect(),
            detail,
            truncated: (total > max).then(|| {
                format!(
                    "showing {max} of {total} changes; knx_describe_change with this result's \
                     snapshot as `from` lists them"
                )
            }),
        }
    }
}

/// One diagnostic in a [`Validation`].
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticRow {
    /// Its code.
    pub code: String,
    /// Its message.
    pub message: String,
    /// Where.
    pub location: String,
}

/// What validating the project after an edit found (issue #279).
#[derive(Debug, Clone, Serialize)]
pub struct Validation {
    /// No error.
    pub ok: bool,
    /// The project's errors after the edit.
    pub errors: Vec<DiagnosticRow>,
    /// How many errors.
    pub error_count: usize,
    /// The warnings the edit added.
    pub new_warnings: Vec<DiagnosticRow>,
    /// How many warnings in all.
    pub warning_count: usize,
    /// Whether the lists stop short.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// One line for the human.
    pub for_the_human: String,
}

impl Validation {
    /// The validation of the project after an edit (`after`) against before
    /// it (`before`): its errors, and only the warnings the edit added.
    pub fn new(before: &[Diagnostic], after: &[Diagnostic]) -> Validation {
        let key = |d: &Diagnostic| (d.code.to_string(), d.location.clone(), d.message.clone());
        let row = |d: &&Diagnostic| DiagnosticRow {
            code: d.code.to_string(),
            message: d.message.clone(),
            location: d.location.clone(),
        };
        let earlier: BTreeSet<(String, String, String)> = before
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .map(key)
            .collect();
        let errors: Vec<&Diagnostic> = after
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        let warnings: Vec<&Diagnostic> = after
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect();
        let new_warnings: Vec<&Diagnostic> = warnings
            .iter()
            .copied()
            .filter(|d| !earlier.contains(&key(d)))
            .collect();
        let capped = errors.len() > MAX_RESULT_DIAGNOSTICS
            || new_warnings.len() > MAX_RESULT_DIAGNOSTICS;
        let mut out = Validation {
            ok: errors.is_empty(),
            errors: errors.iter().take(MAX_RESULT_DIAGNOSTICS).map(row).collect(),
            error_count: errors.len(),
            new_warnings: new_warnings
                .iter()
                .take(MAX_RESULT_DIAGNOSTICS)
                .map(row)
                .collect(),
            warning_count: warnings.len(),
            note: capped.then(|| {
                format!(
                    "listing at most {MAX_RESULT_DIAGNOSTICS} errors and \
                     {MAX_RESULT_DIAGNOSTICS} new warnings ({} errors, {} new warnings in all); \
                     knx_validate lists every one",
                    errors.len(),
                    new_warnings.len()
                )
            }),
            for_the_human: String::new(),
        };
        out.for_the_human = for_the_human(out.error_count, out.new_warnings.len());
        out
    }
}

/// The one line a validation gives the human: whether the project has
/// problems that stop a push, and whether the edit added notes.
pub fn for_the_human(errors: usize, new_warnings: usize) -> String {
    match (errors, new_warnings) {
        (0, 0) => "No problems.".to_string(),
        (0, 1) => "One new note about the model (types or naming); harmless, it can be \
                   tidied later."
            .to_string(),
        (0, n) => format!(
            "{n} new notes about the model (types or naming); harmless, they can be tidied \
             later."
        ),
        (1, _) => "The model has one problem that has to be fixed before a device can be \
                   written."
            .to_string(),
        (n, _) => format!(
            "The model has {n} problems that have to be fixed before a device can be written."
        ),
    }
}

/// An edit of the project files (the `knx_set_*`, `knx_add_link`,
/// `knx_remove_*`, `knx_scaffold_groups`, `knx_reserve_groups` tools).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EditOutcome {
    /// Always `true`: the edit was saved (or there was nothing to save).
    pub ok: bool,
    /// The history snapshot taken before the edit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// A protected group address is among the changes.
    pub touches_protected: bool,
    /// The group addresses declared in `groups.toml` with the edit.
    pub groups_declared: Vec<String>,
    /// The project's validation after the edit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<Validation>,
    /// The changes as sentences (capped).
    pub changes: Vec<String>,
    /// The same changes, structured.
    pub detail: Vec<Change>,
    /// What the cap left out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<String>,
    /// What the edit revealed or that nothing was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// What a tool adds of its own (the key store of a security change).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
    /// The homeowner's sentence, from [`edit_summary`].
    #[serde(skip)]
    pub said: Option<String>,
    /// What to do next at this server's tier.
    #[serde(skip)]
    pub next: Option<String>,
}

impl EditOutcome {
    /// An edit that changed `changes`, saved after `snapshot`.
    pub fn new(snapshot: impl ToString, changes: &ChangeSet) -> EditOutcome {
        let capped = Capped::of(changes, Some(MAX_RESULT_CHANGES));
        EditOutcome {
            ok: true,
            snapshot: Some(snapshot.to_string()),
            touches_protected: changes.touches_protected(),
            changes: capped.sentences,
            detail: capped.detail,
            truncated: capped.truncated,
            ..EditOutcome::default()
        }
    }

    /// An edit the project already held: nothing was written.
    pub fn unchanged() -> EditOutcome {
        EditOutcome {
            ok: true,
            note: Some("the model already said that; nothing was written".to_string()),
            ..EditOutcome::default()
        }
    }
}

impl Report for EditOutcome {
    const SCHEMA: u32 = 1;

    fn summary(&self, _model: &Model) -> Option<String> {
        self.said.clone()
    }

    fn next_step(&self) -> Option<String> {
        self.next.clone()
    }
}

/// A change set between two states of the project: `bussard status --json`
/// (since the last snapshot), `bussard show --json` (one snapshot or two)
/// and `knx_describe_change`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChangeReport {
    /// Always `true`.
    pub ok: bool,
    /// The snapshot compared against (`status`, `knx_describe_change`).
    pub base: Option<String>,
    /// The earlier snapshot (`show`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The later snapshot (`show`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Why the later snapshot was taken (`show`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How many changes.
    pub count: usize,
    /// A protected group address is among them.
    pub touches_protected: bool,
    /// One sentence per change (capped for chat).
    pub sentences: Vec<String>,
    /// The changes.
    pub changes: Vec<Change>,
    /// What the cap left out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<String>,
    /// That nothing here reached a device, or why there is nothing.
    pub note: String,
    /// The homeowner's sentence.
    #[serde(skip)]
    pub said: Option<String>,
}

impl ChangeReport {
    /// The changes since `base`, at most `max` listed (`None`: all).
    pub fn new(base: Option<String>, changes: &ChangeSet, max: Option<usize>) -> ChangeReport {
        let capped = Capped::of(changes, max);
        ChangeReport {
            ok: true,
            base,
            count: changes.len(),
            touches_protected: changes.touches_protected(),
            sentences: capped.sentences,
            changes: capped.detail,
            truncated: capped.truncated,
            note: "Nothing here has reached any device: these are model files only.".to_string(),
            ..ChangeReport::default()
        }
    }

    /// No snapshot to compare against.
    pub fn no_history() -> ChangeReport {
        ChangeReport {
            ok: true,
            note: "no history snapshot yet, so there is nothing to compare against".to_string(),
            ..ChangeReport::default()
        }
    }
}

impl Report for ChangeReport {
    const SCHEMA: u32 = 2;

    fn summary(&self, _model: &Model) -> Option<String> {
        self.said.clone()
    }
}

/// The snapshot list, oldest first (`bussard history --json`,
/// `knx_history`).
#[derive(Debug, Clone, Serialize)]
pub struct HistoryReport {
    /// Always `true`.
    pub ok: bool,
    /// How many snapshots are listed.
    pub count: usize,
    /// The snapshots.
    pub snapshots: Vec<HistoryRow>,
}

impl HistoryReport {
    /// The list `rows`.
    pub fn new(rows: Vec<HistoryRow>) -> HistoryReport {
        HistoryReport {
            ok: true,
            count: rows.len(),
            snapshots: rows,
        }
    }
}

impl Report for HistoryReport {
    const SCHEMA: u32 = 2;
}

/// An undo of the project files (`bussard undo --json`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct UndoReport {
    /// Always `true`.
    pub ok: bool,
    /// The snapshot put back, `None` when nothing was restored.
    pub restored: Option<String>,
    /// When it was taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// The snapshot of the files before the undo.
    pub undo_snapshot: Option<String>,
    /// Why nothing was restored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The changes the undo made.
    pub changes: Vec<Change>,
    /// What the key store did with the undo, when it did anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_store: Option<serde_json::Value>,
}

impl Report for UndoReport {
    const SCHEMA: u32 = 2;
}
