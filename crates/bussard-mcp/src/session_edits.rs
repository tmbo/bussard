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
//! An edit to `groups.toml`, a device's name or its room is not recorded: no
//! device stores it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use bussard_model::{ChangeKind, ChangeSet, IndividualAddress};
use serde::Serialize;

/// One unapplied edit of one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingEdit {
    /// The history snapshot taken before the edit (`knx_undo` takes it).
    pub snapshot: String,
    /// The tool that made the edit.
    pub tool: String,
    /// The edit's sentences about this device.
    pub sentences: Vec<String>,
    /// Per sentence, whether it is a parameter change (a plan that did not
    /// compare the parameters leaves those pending).
    #[serde(skip)]
    parameter: Vec<bool>,
}

/// The unapplied edits of this session, by device. Cheap to clone; clones
/// share one table.
#[derive(Debug, Clone, Default)]
pub struct SessionEdits {
    edits: Arc<Mutex<BTreeMap<IndividualAddress, Vec<PendingEdit>>>>,
}

impl SessionEdits {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// The table, recovering from a poisoned lock (it holds plain data).
    fn table(&self) -> MutexGuard<'_, BTreeMap<IndividualAddress, Vec<PendingEdit>>> {
        self.edits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records the edit `tool` made behind `snapshot`: its sentences, under
    /// each device a change names.
    pub fn record(&self, snapshot: &str, tool: &str, changes: &ChangeSet) {
        let mut table = self.table();
        for (ia, (sentences, parameter)) in by_device(changes) {
            table.entry(ia).or_default().push(PendingEdit {
                snapshot: snapshot.to_string(),
                tool: tool.to_string(),
                sentences,
                parameter,
            });
        }
    }

    /// The unapplied edits of `ia`, oldest first.
    pub fn for_device(&self, ia: IndividualAddress) -> Vec<PendingEdit> {
        self.table().get(&ia).cloned().unwrap_or_default()
    }

    /// Forgets `ia`'s edits: the device now holds the model's links, and its
    /// parameters too when `parameters` (else the parameter sentences stay).
    pub fn applied(&self, ia: IndividualAddress, parameters: bool) {
        let mut table = self.table();
        if parameters {
            table.remove(&ia);
            return;
        }
        if let Some(edits) = table.get_mut(&ia) {
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
                table.remove(&ia);
            }
        }
    }

    /// Accounts for an undo that restored `restored` and changed the files by
    /// `changes`; `undo_snapshot` is the snapshot the undo took first.
    pub fn undone(&self, restored: &str, undo_snapshot: &str, changes: &ChangeSet) {
        let mut table = self.table();
        let mut reverted: Vec<IndividualAddress> = Vec::new();
        for (ia, edits) in table.iter_mut() {
            let before = edits.len();
            // Snapshot ids sort chronologically: an edit behind `restored` or
            // a later snapshot is reverted by the restore.
            edits.retain(|e| e.snapshot.as_str() < restored);
            if edits.len() != before {
                reverted.push(*ia);
            }
        }
        table.retain(|_, edits| !edits.is_empty());
        for (ia, (sentences, parameter)) in by_device(changes) {
            if reverted.contains(&ia) {
                continue;
            }
            table.entry(ia).or_default().push(PendingEdit {
                snapshot: undo_snapshot.to_string(),
                tool: "knx_undo".to_string(),
                sentences,
                parameter,
            });
        }
    }
}

/// The sentences of `changes` that reach a device (links and parameters),
/// grouped by the device each names, each with whether it is a parameter
/// change.
fn by_device(changes: &ChangeSet) -> BTreeMap<IndividualAddress, (Vec<String>, Vec<bool>)> {
    let mut out: BTreeMap<IndividualAddress, (Vec<String>, Vec<bool>)> = BTreeMap::new();
    for change in &changes.changes {
        let parameter = match change.kind {
            ChangeKind::ParameterChanged => true,
            ChangeKind::LinkAdded | ChangeKind::LinkRemoved => false,
            _ => continue,
        };
        let Some(ia) = change
            .device
            .as_deref()
            .and_then(|d| d.parse::<IndividualAddress>().ok())
        else {
            continue;
        };
        let (sentences, kinds) = out.entry(ia).or_default();
        sentences.push(change.sentence.clone());
        kinds.push(parameter);
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
        assert_eq!(
            edits.for_device(a)[1].sentences,
            ["X on Dev (1.1.4): 2 to 3."]
        );

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
        assert_eq!(pending[0].sentences, ["X on Dev (1.1.4): 1 to 2."]);
        edits.applied(a, true);
        assert!(edits.for_device(a).is_empty());
        Ok(())
    }
}
