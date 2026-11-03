//! The model edits this server session made that no device has received yet
//! (issue #279).
//!
//! `knx_plan_device` used to report `pending_model_changes` as the whole
//! working model against the latest history snapshot: every device, every
//! edit since the snapshot, and (before snapshots translated enum labels)
//! every labelled parameter of the house. The assistant needs something
//! narrower: what this session changed on the device it is about to program
//! and has not pushed yet. This module keeps that, per device:
//!
//! - every successful model edit records the sentences that reach a device
//!   (links and parameters) under each device they name, with the history
//!   snapshot taken before it;
//! - a successful `knx_apply_device`, or a plan that finds the device already
//!   holding the model, clears the device (only its link sentences when the
//!   parameters were not compared);
//! - `knx_undo` to snapshot `S` drops every entry taken at or after `S` (those
//!   edits are reverted in the files). A device the undo changes that had no
//!   such entry (its edit was applied already, or predates the session) gets
//!   the undo itself as its pending edit, because the device now differs from
//!   the files.
//!
//! Group-address edits (`groups.toml`) are kept too, per group address, so
//! `knx_discard_edits` can drop them; no device stores them, so no apply
//! clears them and the plan never lists them. A device's name or room is not
//! recorded: no device stores it.
//!
//! `knx_discard_edits` drops one subject's entries (issue #305) and keeps them
//! aside under the snapshot it took first: a `knx_undo` to that snapshot puts
//! them back as they were.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use bussard_model::{ChangeKind, ChangeSet, GroupAddress, IndividualAddress};
use serde::Serialize;

/// One unapplied edit of one subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingEdit {
    /// The history snapshot taken before the edit (`knx_undo` takes it).
    pub snapshot: String,
    /// The tool that made the edit.
    pub tool: String,
    /// The edit's sentences about this subject.
    pub sentences: Vec<String>,
    /// Per sentence, whether it is a parameter change (a plan that did not
    /// compare the parameters leaves those pending).
    #[serde(skip)]
    parameter: Vec<bool>,
}

/// What a pending edit is about: one device or one group address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subject {
    /// A device (its links and parameters).
    Device(IndividualAddress),
    /// A group address in `groups.toml`.
    Group(GroupAddress),
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Subject::Device(ia) => write!(f, "{ia}"),
            Subject::Group(ga) => write!(f, "{ga}"),
        }
    }
}

/// Edits `knx_discard_edits` dropped, kept for an undo of the discard.
#[derive(Debug, Clone)]
struct Discarded {
    /// The snapshot the discard took before it wrote.
    snapshot: String,
    /// The subject the edits were about.
    subject: Subject,
    /// The dropped edits, oldest first.
    edits: Vec<PendingEdit>,
}

/// The tables behind [`SessionEdits`].
#[derive(Debug, Default)]
struct Table {
    /// Unapplied edits per device.
    devices: BTreeMap<IndividualAddress, Vec<PendingEdit>>,
    /// Edits per group address.
    groups: BTreeMap<GroupAddress, Vec<PendingEdit>>,
    /// What discards dropped, newest last.
    discarded: Vec<Discarded>,
}

impl Table {
    /// The entries of `subject`, created on demand.
    fn entry(&mut self, subject: Subject) -> &mut Vec<PendingEdit> {
        match subject {
            Subject::Device(ia) => self.devices.entry(ia).or_default(),
            Subject::Group(ga) => self.groups.entry(ga).or_default(),
        }
    }
}

/// The unapplied edits of this session, by device and group address. Cheap to
/// clone; clones share one table.
#[derive(Debug, Clone, Default)]
pub struct SessionEdits {
    edits: Arc<Mutex<Table>>,
}

impl SessionEdits {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// The table, recovering from a poisoned lock (it holds plain data).
    fn table(&self) -> MutexGuard<'_, Table> {
        self.edits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records the edit `tool` made behind `snapshot`: its sentences, under
    /// each device and group address a change names.
    pub fn record(&self, snapshot: &str, tool: &str, changes: &ChangeSet) {
        let mut table = self.table();
        for (subject, (sentences, parameter)) in by_subject(changes) {
            table.entry(subject).push(PendingEdit {
                snapshot: snapshot.to_string(),
                tool: tool.to_string(),
                sentences,
                parameter,
            });
        }
    }

    /// The unapplied edits of `ia`, oldest first.
    pub fn for_device(&self, ia: IndividualAddress) -> Vec<PendingEdit> {
        self.pending(Subject::Device(ia))
    }

    /// The pending edits of `subject`, oldest first.
    pub fn pending(&self, subject: Subject) -> Vec<PendingEdit> {
        let table = self.table();
        let found = match subject {
            Subject::Device(ia) => table.devices.get(&ia),
            Subject::Group(ga) => table.groups.get(&ga),
        };
        found.cloned().unwrap_or_default()
    }

    /// Drops every pending edit of `subject`, keeping them aside under
    /// `snapshot` (the one the discard took first, `None` when it wrote
    /// nothing) so an undo to it brings them back. Returns the dropped edits.
    pub fn discard(&self, subject: Subject, snapshot: Option<&str>) -> Vec<PendingEdit> {
        let mut table = self.table();
        let edits = match subject {
            Subject::Device(ia) => table.devices.remove(&ia),
            Subject::Group(ga) => table.groups.remove(&ga),
        }
        .unwrap_or_default();
        if let (false, Some(snapshot)) = (edits.is_empty(), snapshot) {
            table.discarded.push(Discarded {
                snapshot: snapshot.to_string(),
                subject,
                edits: edits.clone(),
            });
        }
        edits
    }

    /// Forgets `ia`'s edits: the device now holds the model's links, and its
    /// parameters too when `parameters` (else the parameter sentences stay).
    pub fn applied(&self, ia: IndividualAddress, parameters: bool) {
        let mut table = self.table();
        if parameters {
            table.devices.remove(&ia);
            return;
        }
        if let Some(edits) = table.devices.get_mut(&ia) {
            for edit in edits.iter_mut() {
                let kept: Vec<(String, bool)> = edit
                    .sentences
                    .drain(..)
                    .zip(edit.parameter.drain(..))
                    .filter(|(_, p)| *p)
                    .collect();
                (edit.sentences, edit.parameter) = kept.into_iter().unzip();
            }
            edits.retain(|e| !e.sentences.is_empty());
            if edits.is_empty() {
                table.devices.remove(&ia);
            }
        }
    }

    /// Accounts for an undo that restored `restored` and changed the files by
    /// `changes`; `undo_snapshot` is the snapshot the undo took first.
    pub fn undone(&self, restored: &str, undo_snapshot: &str, changes: &ChangeSet) {
        let mut table = self.table();
        let mut reverted: Vec<IndividualAddress> = Vec::new();
        for (ia, edits) in table.devices.iter_mut() {
            let before = edits.len();
            // Snapshot ids sort chronologically: an edit behind `restored` or
            // a later snapshot is reverted by the restore.
            edits.retain(|e| e.snapshot.as_str() < restored);
            if edits.len() != before {
                reverted.push(*ia);
            }
        }
        table.devices.retain(|_, edits| !edits.is_empty());
        for edits in table.groups.values_mut() {
            edits.retain(|e| e.snapshot.as_str() < restored);
        }
        table.groups.retain(|_, edits| !edits.is_empty());

        // A discard at or after `restored` is reverted: what it dropped is
        // back in the files, so it is pending again, as it was.
        let (back, kept): (Vec<Discarded>, Vec<Discarded>) = std::mem::take(&mut table.discarded)
            .into_iter()
            .partition(|d| d.snapshot.as_str() >= restored);
        table.discarded = kept;
        for discarded in back {
            let edits: Vec<PendingEdit> = discarded
                .edits
                .into_iter()
                .filter(|e| e.snapshot.as_str() < restored)
                .collect();
            if edits.is_empty() {
                continue;
            }
            if let Subject::Device(ia) = discarded.subject {
                reverted.push(ia);
            }
            let entry = table.entry(discarded.subject);
            entry.extend(edits);
            entry.sort_by(|a, b| a.snapshot.cmp(&b.snapshot));
        }

        for (subject, (sentences, parameter)) in by_subject(changes) {
            let Subject::Device(ia) = subject else {
                // No device stores a group address's metadata: an undo of
                // one leaves nothing to push.
                continue;
            };
            if reverted.contains(&ia) {
                continue;
            }
            table.entry(subject).push(PendingEdit {
                snapshot: undo_snapshot.to_string(),
                tool: "knx_undo".to_string(),
                sentences,
                parameter,
            });
        }
    }
}

/// The sentences of `changes` by subject: the ones that reach a device (links
/// and parameters) under the device each names, the `groups.toml` ones under
/// their group address; each with whether it is a parameter change.
fn by_subject(changes: &ChangeSet) -> BTreeMap<Subject, (Vec<String>, Vec<bool>)> {
    let mut out: BTreeMap<Subject, (Vec<String>, Vec<bool>)> = BTreeMap::new();
    for change in &changes.changes {
        let subject = match change.kind {
            ChangeKind::ParameterChanged
            | ChangeKind::LinkAdded
            | ChangeKind::LinkRemoved
            | ChangeKind::ObjectSecurityChanged
            | ChangeKind::InterfaceChanged => change
                .device
                .as_deref()
                .and_then(|d| d.parse::<IndividualAddress>().ok())
                .map(Subject::Device),
            ChangeKind::GroupAdded
            | ChangeKind::GroupRemoved
            | ChangeKind::GroupRenamed
            | ChangeKind::GroupDptChanged
            | ChangeKind::GroupDescriptionChanged
            | ChangeKind::GroupProtectionChanged
            | ChangeKind::GroupSecurityChanged => change
                .group
                .as_deref()
                .and_then(|g| g.parse::<GroupAddress>().ok())
                .map(Subject::Group),
            _ => None,
        };
        let Some(subject) = subject else {
            continue;
        };
        let (sentences, kinds) = out.entry(subject).or_default();
        sentences.push(change.sentence.clone());
        kinds.push(change.kind == ChangeKind::ParameterChanged);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as Map;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The device file of `ia` with parameter `x` at `value` and, when
    /// `linked`, object 1 listening to 1/2/0.
    fn file(ia: &str, value: &str, linked: bool) -> String {
        let links = if linked {
            "\n[links]\n1.listen = [\"1/2/0\"]\n"
        } else {
            ""
        };
        format!(
            "address = \"{ia}\"\nname = \"Dev\"\n\n[parameters]\n\"x@P-1_R-1\" = \"{value}\"\n{links}"
        )
    }

    /// The change set from `old` to `new` device files, by address.
    fn changes(
        old: &[(&str, String)],
        new: &[(&str, String)],
    ) -> Result<ChangeSet, Box<dyn std::error::Error>> {
        let map = |files: &[(&str, String)]| -> Map<String, String> {
            files
                .iter()
                .map(|(ia, text)| (format!("devices/{ia}.toml"), text.clone()))
                .collect()
        };
        Ok(bussard_model::describe(
            &bussard_model::Model::from_texts(&map(old))?,
            &bussard_model::Model::from_texts(&map(new))?,
        ))
    }

    #[test]
    fn test_session_edits_record_apply_and_undo() -> TestResult {
        let edits = SessionEdits::new();
        let (a, b): (IndividualAddress, IndividualAddress) = ("1.1.4".parse()?, "1.1.5".parse()?);
        assert!(edits.for_device(a).is_empty());

        let set = |ia: &str, from: &str, to: &str| {
            changes(&[(ia, file(ia, from, false))], &[(ia, file(ia, to, false))])
        };
        edits.record(
            "20261001T100000Z-1",
            "knx_set_parameter",
            &set("1.1.4", "1", "2")?,
        );
        edits.record(
            "20261001T100100Z-2",
            "knx_set_parameter",
            &set("1.1.5", "1", "2")?,
        );
        edits.record(
            "20261001T100200Z-3",
            "knx_set_parameter",
            &set("1.1.4", "2", "3")?,
        );
        assert_eq!(edits.for_device(a).len(), 2);
        assert_eq!(edits.for_device(b).len(), 1);
        assert_eq!(edits.for_device(a)[0].tool, "knx_set_parameter");
        assert_eq!(edits.for_device(a)[1].sentences, ["X on Dev: 2 to 3."]);

        // A rename reaches no device and is not recorded.
        let rename = changes(
            &[("1.1.4", file("1.1.4", "3", false))],
            &[(
                "1.1.4",
                file("1.1.4", "3", false).replace("\"Dev\"", "\"Hall\""),
            )],
        )?;
        assert_eq!(rename.len(), 1);
        edits.record("20261001T100250Z-3a", "knx_set_device", &rename);
        assert_eq!(edits.for_device(a).len(), 2);

        // Applying 1.1.5 clears it only.
        edits.applied(b, true);
        assert!(edits.for_device(b).is_empty());
        assert_eq!(edits.for_device(a).len(), 2);

        // Undoing the last edit of 1.1.4 drops it and records nothing new.
        edits.undone(
            "20261001T100200Z-3",
            "20261001T100300Z-4",
            &set("1.1.4", "3", "2")?,
        );
        assert_eq!(edits.for_device(a).len(), 1);

        // Undoing the applied edit of 1.1.5 leaves the device behind the
        // files: the undo is pending.
        edits.undone(
            "20261001T100100Z-2",
            "20261001T100400Z-5",
            &set("1.1.5", "2", "1")?,
        );
        let pending = edits.for_device(b);
        assert_eq!(pending.len(), 1, "{pending:?}");
        assert_eq!(pending[0].tool, "knx_undo");
        assert_eq!(pending[0].snapshot, "20261001T100400Z-5");
        Ok(())
    }

    /// A plan that did not compare the parameters clears only the links.
    #[test]
    fn test_session_edits_links_only_apply_keeps_parameters() -> TestResult {
        let edits = SessionEdits::new();
        let a: IndividualAddress = "1.1.4".parse()?;
        let both = changes(
            &[("1.1.4", file("1.1.4", "1", false))],
            &[("1.1.4", file("1.1.4", "2", true))],
        )?;
        assert_eq!(both.len(), 2, "{both:?}");
        edits.record("20261001T100000Z-1", "knx_set_parameter", &both);
        edits.applied(a, false);
        let pending = edits.for_device(a);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].sentences, ["X on Dev: 1 to 2."]);
        edits.applied(a, true);
        assert!(edits.for_device(a).is_empty());
        Ok(())
    }

    /// A discard drops one device's edits only; an undo to the discard's
    /// snapshot puts them back as they were, not as an undo entry.
    #[test]
    fn test_session_edits_discard_and_undo_restores() -> TestResult {
        let edits = SessionEdits::new();
        let (a, b): (IndividualAddress, IndividualAddress) = ("1.1.4".parse()?, "1.1.5".parse()?);
        let set = |ia: &str, from: &str, to: &str| {
            changes(&[(ia, file(ia, from, false))], &[(ia, file(ia, to, false))])
        };
        edits.record(
            "20261001T100000Z-1",
            "knx_set_parameter",
            &set("1.1.4", "1", "2")?,
        );
        edits.record(
            "20261001T100100Z-2",
            "knx_set_parameter",
            &set("1.1.5", "1", "2")?,
        );

        let dropped = edits.discard(Subject::Device(a), Some("20261001T100200Z-3"));
        assert_eq!(dropped.len(), 1);
        assert!(edits.for_device(a).is_empty());
        assert_eq!(edits.for_device(b).len(), 1);
        assert!(
            edits
                .discard(Subject::Device(a), Some("20261001T100250Z-3a"))
                .is_empty()
        );

        edits.undone(
            "20261001T100200Z-3",
            "20261001T100300Z-4",
            &set("1.1.4", "1", "2")?,
        );
        let back = edits.for_device(a);
        assert_eq!(back.len(), 1, "{back:?}");
        assert_eq!(back[0].tool, "knx_set_parameter");
        assert_eq!(back[0].snapshot, "20261001T100000Z-1");
        assert_eq!(edits.for_device(b).len(), 1);
        Ok(())
    }
}
