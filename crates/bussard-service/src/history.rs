//! The project history for both surfaces (issue #903): the snapshot list
//! ([`list`]), the change one snapshot made ([`show`]) and the undo that puts
//! the model files back to a snapshot ([`undo`]), with the key store
//! following a group address whose Data Secure state the undo flips (issue
//! #331).
//!
//! `bussard history`, `show` and `undo` and the MCP `knx_history` and
//! `knx_undo` render these outcomes. Files only: nothing here touches the bus.

use std::ops::Range;
use std::path::Path;

use bussard_model::Model;
use bussard_model::change::{ChangeSet, describe};
use bussard_model::history::{History, HistoryError, Snapshot, SnapshotId};

/// One row of the snapshot list, oldest first.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryRow {
    /// The 1-based position in the whole list (`bussard show <n>`).
    pub index: usize,
    /// The snapshot id.
    pub id: SnapshotId,
    /// When it was taken, RFC3339 in UTC.
    pub created_at: String,
    /// The command that took it.
    pub command: String,
    /// The command's arguments.
    pub args: Vec<String>,
    /// The gateway a bus write went to, when one did.
    pub gateway: Option<String>,
    /// The outcome note.
    pub result: String,
    /// The plain-language summary of what it changed.
    pub summary: String,
}

/// Why the history could not be read, or an undo or show failed.
#[derive(Debug, thiserror::Error)]
pub enum HistoryFlowError {
    /// The snapshot list could not be read.
    #[error("the history could not be read: {0}")]
    List(#[source] HistoryError),
    /// The undo target could not be found.
    #[error("the history could not be read: {0}")]
    Target(#[source] HistoryError),
    /// The snapshot named does not exist.
    #[error(transparent)]
    Resolve(HistoryError),
    /// A snapshot's model does not load.
    #[error("snapshot {id} does not load: {source}")]
    Load {
        /// The snapshot.
        id: SnapshotId,
        /// Why.
        #[source]
        source: HistoryError,
    },
    /// The restore failed.
    #[error("the restore failed: {0}")]
    Restore(#[source] HistoryError),
}

impl HistoryFlowError {
    /// The underlying history error.
    pub fn history_error(&self) -> &HistoryError {
        match self {
            HistoryFlowError::List(e)
            | HistoryFlowError::Target(e)
            | HistoryFlowError::Resolve(e)
            | HistoryFlowError::Restore(e)
            | HistoryFlowError::Load { source: e, .. } => e,
        }
    }
}

/// The snapshot rows of `dir`, the last `last` of them (all when `None`).
///
/// # Errors
///
/// [`HistoryFlowError::List`] when the history cannot be read.
pub fn list(dir: &Path, last: Option<usize>) -> Result<Vec<HistoryRow>, HistoryFlowError> {
    let history = History::open(dir);
    let snapshots = history.list().map_err(HistoryFlowError::List)?;
    let start = last.map_or(0, |n| snapshots.len().saturating_sub(n));
    let range: Range<usize> = start..snapshots.len();
    let summaries = history.summaries(&snapshots, range.clone());
    Ok(snapshots[range]
        .iter()
        .zip(summaries)
        .enumerate()
        .map(|(offset, (snapshot, summary))| HistoryRow {
            index: start + offset + 1,
            id: snapshot.id.clone(),
            created_at: snapshot.manifest.created_at.clone(),
            command: snapshot.manifest.reason.command.clone(),
            args: snapshot.manifest.reason.args.clone(),
            gateway: snapshot.manifest.gateway.clone(),
            result: snapshot.manifest.result.clone(),
            summary,
        })
        .collect())
}

/// The change one snapshot introduced, or the change between two.
#[derive(Debug, Clone)]
pub struct Shown {
    /// The earlier snapshot, `None` for the very first one.
    pub from: Option<Snapshot>,
    /// The later snapshot.
    pub to: Snapshot,
    /// The change from `from` (or an empty model) to `to`.
    pub changes: ChangeSet,
}

/// The change `first` introduced against the snapshot before it, or with
/// `second` the change from `first` to `second`. `None` without history.
///
/// # Errors
///
/// The history cannot be read, a snapshot is not found or does not load.
pub fn show(
    dir: &Path,
    first: &str,
    second: Option<&str>,
) -> Result<Option<Shown>, HistoryFlowError> {
    let history = History::open(dir);
    let snapshots = history.list().map_err(HistoryFlowError::List)?;
    if snapshots.is_empty() {
        return Ok(None);
    }
    let resolve = |spec: &str| history.resolve(spec).map_err(HistoryFlowError::Resolve);
    let (from, to) = match second {
        Some(second) => (Some(resolve(first)?), resolve(second)?),
        None => {
            let to = resolve(first)?;
            let index = snapshots.iter().position(|s| s.id == to.id).unwrap_or(0);
            let from = index.checked_sub(1).and_then(|i| snapshots.get(i)).cloned();
            (from, to)
        }
    };
    let load = |id: &SnapshotId| {
        history.load(id).map_err(|source| HistoryFlowError::Load {
            id: id.clone(),
            source,
        })
    };
    let old = match &from {
        Some(snapshot) => load(&snapshot.id)?,
        None => empty_model(),
    };
    let new = load(&to.id)?;
    let changes = describe(&old, &new);
    Ok(Some(Shown { from, to, changes }))
}

/// What an undo did.
#[derive(Debug)]
pub enum UndoOutcome {
    /// There is no snapshot yet.
    NoHistory,
    /// The model files already match every snapshot.
    NothingToUndo,
    /// The model files were restored.
    Restored(Box<Undone>),
}

/// A restored snapshot.
#[derive(Debug)]
pub struct Undone {
    /// The snapshot put back.
    pub target: Snapshot,
    /// The snapshot of the state before the undo, so an undo can be undone.
    pub undo_snapshot: SnapshotId,
    /// The working model before the undo, when it loaded.
    pub before: Option<Model>,
    /// The model restored.
    pub restored: Model,
    /// What the undo reverted: the working model against the snapshot.
    pub changes: ChangeSet,
    /// The key store following the Data Secure state the undo flipped
    /// (issue #331); `None` when no group address changed its state.
    pub key_store: Option<KeyStoreFollow>,
}

/// The key store following a model restore (issue #331): the sentences of
/// what it changed, or why it did not follow.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KeyStoreFollow {
    /// Whether the key store followed.
    pub ok: bool,
    /// What changed in the key store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentences: Option<Vec<String>>,
    /// Why the key store did not follow, and how to fix it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Restores the key store after the model went from `before` to `after` by
/// putting back the snapshot `from` (its key store copy) with the state before
/// kept as `kept` (issue #331). `None` when no group address changed its Data
/// Secure state; `what` names the operation in the failure sentence
/// (`undo`, `discard`).
pub fn follow_keys(
    dir: &Path,
    from: &SnapshotId,
    kept: &SnapshotId,
    before: &Model,
    after: &Model,
    what: &str,
) -> Option<KeyStoreFollow> {
    if crate::group_security::security_changes(before, after).is_empty() {
        return None;
    }
    let history = History::open(dir);
    let password = bussard_model::dotenv::var(crate::secure::KEYRING_PASSWORD_ENV).ok();
    Some(
        match crate::group_security::restore_group_keys(
            dir,
            &history.snapshot_dir(from),
            Some(&history.snapshot_dir(kept)),
            before,
            after,
            password.as_deref(),
        ) {
            Ok(notes) => KeyStoreFollow {
                ok: true,
                sentences: Some(notes),
                reason: None,
            },
            Err(err) => KeyStoreFollow {
                ok: false,
                sentences: None,
                reason: Some(format!(
                    "the project files are restored, but the key store did not follow: {err}. Fix \
                     that and run `bussard groups secure <GA> on|off` for the group addresses \
                     whose security the {what} changed."
                )),
            },
        },
    )
}

/// Puts the model files back to the snapshot `target` names (its id or its
/// number), by default the newest one that differs from the working files,
/// which reverts the last change. The state before is itself snapshotted.
///
/// Files only: devices keep their tables until a plan and an apply.
///
/// # Errors
///
/// The history cannot be read, the snapshot is not found or does not load,
/// or the restore fails.
pub fn undo(dir: &Path, target: Option<&str>) -> Result<UndoOutcome, HistoryFlowError> {
    let history = History::open(dir);
    let snapshots = history.list().map_err(HistoryFlowError::List)?;
    if snapshots.is_empty() {
        return Ok(UndoOutcome::NoHistory);
    }
    let target = match target {
        Some(spec) => history.resolve(spec).map_err(HistoryFlowError::Resolve)?,
        None => match history.undo_target().map_err(HistoryFlowError::Target)? {
            Some(snapshot) => snapshot,
            None => return Ok(UndoOutcome::NothingToUndo),
        },
    };
    // What the restore reverts, in the owner's words: the working model as
    // it is now, against the snapshot about to be put back.
    let before = Model::load(dir).ok();
    let restored = history
        .load(&target.id)
        .map_err(|source| HistoryFlowError::Load {
            id: target.id.clone(),
            source,
        })?;
    let changes = before
        .as_ref()
        .map(|b| describe(b, &restored))
        .unwrap_or_default();
    let undo_snapshot = history
        .restore(&target.id)
        .map_err(HistoryFlowError::Restore)?;
    // A group address whose Data Secure state the undo flips gets its key
    // back from the snapshot's key store copy, or loses it (issue #331).
    let key_store = before
        .as_ref()
        .and_then(|b| follow_keys(dir, &target.id, &undo_snapshot, b, &restored, "undo"));
    Ok(UndoOutcome::Restored(Box::new(Undone {
        target,
        undo_snapshot,
        before,
        restored,
        changes,
        key_store,
    })))
}

/// An empty model, the "before" of the very first snapshot.
pub fn empty_model() -> Model {
    Model {
        config: bussard_model::schema::BussardConfig::default(),
        groups: bussard_model::schema::Groups::default(),
        links: bussard_model::schema::Links::default(),
        devices: std::collections::BTreeMap::new(),
    }
}
