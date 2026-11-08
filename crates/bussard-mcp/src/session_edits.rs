//! The model edits this server session made that a device has not received
//! yet (issues #279, #941).
//!
//! Every write to the model files takes a history snapshot first, so what is
//! pending on a device is read from the history, not kept in a ledger: the
//! device's changes from the first snapshot taken after it last held the
//! model (this session's start, or the last apply or plan that found it
//! matching) to the files now ([`History::since`]). An undo or a discard
//! changes the files and so what is pending, with nothing to account for.
//!
//! A plan that did not compare the parameters marks the links only: the
//! parameter changes stay pending from the earlier mark. A group address has
//! no apply, so its edits count from the session's start; no device stores
//! them, and the plan never lists them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use bussard_model::history::{History, Since, SnapshotId};
use bussard_model::{ChangeKind, IndividualAddress, Model};

pub use bussard_model::history::Subject;

/// Where a device last held the model: the newest snapshot then.
#[derive(Debug, Clone, Default)]
struct Marks {
    /// Its links.
    links: Option<SnapshotId>,
    /// Its parameters.
    parameters: Option<SnapshotId>,
}

/// The session's start and the devices it applied, by the newest snapshot
/// at the time. Cheap to clone; clones share one table.
#[derive(Debug, Clone)]
pub struct SessionEdits {
    /// The model directory.
    dir: PathBuf,
    /// The newest snapshot when the session started.
    start: Option<SnapshotId>,
    /// Per device, where it last held the model.
    applied: Arc<Mutex<BTreeMap<IndividualAddress, Marks>>>,
}

impl SessionEdits {
    /// A session on the model in `dir`, starting now.
    pub fn new(dir: &Path) -> Self {
        SessionEdits {
            dir: dir.to_path_buf(),
            start: History::open(dir).latest_id().ok().flatten(),
            applied: Arc::default(),
        }
    }

    /// The table, recovering from a poisoned lock (it holds plain data).
    fn table(&self) -> MutexGuard<'_, BTreeMap<IndividualAddress, Marks>> {
        self.applied
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records that `ia` holds the model's links now, and its parameters too
    /// when `parameters`.
    pub fn applied(&self, ia: IndividualAddress, parameters: bool) {
        let now = History::open(&self.dir).latest_id().ok().flatten();
        let mut table = self.table();
        let marks = table.entry(ia).or_default();
        if parameters {
            marks.parameters = now.clone();
        }
        marks.links = now;
    }

    /// The sentences of what this session changed on `ia` and the device has
    /// not received, oldest mark first.
    pub fn for_device(&self, ia: IndividualAddress) -> Vec<String> {
        let Ok(current) = Model::load(&self.dir) else {
            return Vec::new();
        };
        self.since(Subject::Device(ia), &current)
            .into_iter()
            .flat_map(|since| since.changes.changes)
            .map(|change| change.sentence)
            .collect()
    }

    /// `subject`'s changes since this session last saw it match: one entry,
    /// or two for a device whose links were applied later than its
    /// parameters (the links' entry holds no parameter change, the
    /// parameters' entry nothing else). Empty when nothing is pending.
    pub fn since(&self, subject: Subject, current: &Model) -> Vec<Since> {
        let marks = match subject {
            Subject::Device(ia) => self.table().get(&ia).cloned(),
            Subject::Group(_) => None,
        };
        let (links, parameters) = match marks {
            Some(Marks { links, parameters }) => (links, parameters.or(self.start.clone())),
            None => (self.start.clone(), self.start.clone()),
        };
        let history = History::open(&self.dir);
        let found = |mark: Option<&SnapshotId>| -> Option<Since> {
            let mut since = history.since(mark, current, subject).ok()??;
            crate::tools_model::settle_changes(
                &self.dir,
                &mut since.changes,
                [current, &since.model],
            );
            Some(since)
        };
        let mut out: Vec<Since> = Vec::new();
        if links == parameters {
            out.extend(found(links.as_ref()));
        } else {
            let is_parameter = |kind: ChangeKind| kind == ChangeKind::ParameterChanged;
            for (mark, parameter) in [(parameters.as_ref(), true), (links.as_ref(), false)] {
                if let Some(mut since) = found(mark) {
                    since
                        .changes
                        .changes
                        .retain(|c| is_parameter(c.kind) == parameter);
                    out.push(since);
                }
            }
            out.sort_by(|a, b| a.base.cmp(&b.base));
        }
        out.retain(|since| !since.changes.is_empty());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::history::SnapshotReason;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The device file of 1.1.4 with parameter `x` at `value` and, when
    /// `linked`, object 1 listening to 1/2/0.
    fn file(value: &str, linked: bool) -> String {
        let links = if linked {
            "\n[links]\n1.listen = [\"1/2/0\"]\n"
        } else {
            ""
        };
        format!(
            "address = \"1.1.4\"\nname = \"Dev\"\n\n[parameters]\n\"x@P-1_R-1\" = \"{value}\"\n{links}"
        )
    }

    /// Writes 1.1.4's file after a snapshot, as every model edit does.
    fn edit(dir: &Path, text: &str) -> Result<SnapshotId, Box<dyn std::error::Error>> {
        let id = History::open(dir).snapshot(SnapshotReason::new("mcp knx_set_parameter"))?;
        std::fs::write(dir.join("devices/1.1.4.toml"), text)?;
        Ok(id)
    }

    fn model_dir() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir_all(dir.path().join("devices"))?;
        std::fs::write(dir.path().join("devices/1.1.4.toml"), file("1", false))?;
        Ok(dir)
    }

    #[test]
    fn test_session_edits_pending_follows_the_history() -> TestResult {
        let dir = model_dir()?;
        let edits = SessionEdits::new(dir.path());
        let ia: IndividualAddress = "1.1.4".parse()?;
        assert!(edits.for_device(ia).is_empty(), "a fresh session");

        edit(dir.path(), &file("2", false))?;
        let first = edit(dir.path(), &file("3", false))?;
        assert_eq!(edits.for_device(ia), ["X on Dev: 1 to 3."]);

        // Applying clears it; a later edit is pending from there.
        edits.applied(ia, true);
        assert!(edits.for_device(ia).is_empty());
        edit(dir.path(), &file("4", false))?;
        assert_eq!(edits.for_device(ia), ["X on Dev: 3 to 4."]);

        // Undoing to before the apply leaves the device ahead of the files.
        History::open(dir.path()).restore(&first)?;
        assert_eq!(edits.for_device(ia), ["X on Dev: 3 to 2."]);
        Ok(())
    }

    /// A plan that did not compare the parameters clears only the links.
    #[test]
    fn test_session_edits_links_only_apply_keeps_parameters() -> TestResult {
        let dir = model_dir()?;
        let edits = SessionEdits::new(dir.path());
        let ia: IndividualAddress = "1.1.4".parse()?;
        edit(dir.path(), &file("2", true))?;
        assert_eq!(edits.for_device(ia).len(), 2);
        edits.applied(ia, false);
        assert_eq!(edits.for_device(ia), ["X on Dev: 1 to 2."]);
        edits.applied(ia, true);
        assert!(edits.for_device(ia).is_empty());
        Ok(())
    }
}
