//! Built-in history and undo for the model directory (issue #110).
//!
//! bussard owns its own history, so an owner who does not use git can still ask
//! "what changed last Tuesday, put it back". Every command that writes model
//! files (or the bus) takes a snapshot first; an edit made outside bussard — in
//! an editor, or by an assistant writing YAML — is captured as an
//! `external edit` snapshot at the start of the next command, so nothing is
//! lost.
//!
//! # Layout
//!
//! ```text
//! knx/.bussard/history/20260922T101112Z-001/
//!   manifest.json     # reason, gateway, result, version, created_at
//!   bussard.yaml
//!   groups.yaml
//!   links.yaml
//!   devices/*.yaml
//! ```
//!
//! A house model is well under a megabyte, so a snapshot is a full copy with no
//! dependency on git or on a diff format. The snapshot id sorts
//! lexicographically in chronological order.
//!
//! # What is never copied
//!
//! Only the four model inputs above. `models/`, `vendor/`, `captures/`,
//! keyrings, `.knxproj` and `.knxprod` files are vendor-derived, local or
//! secret (see `docs/product-data.md`), and never enter a snapshot.
//!
//! # What undo does not do
//!
//! [`History::restore`] changes **files only**. Devices keep whatever is in
//! their tables until a human runs `bussard plan` and `bussard apply`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::change::{ChangeSet, describe};
use crate::loader::{LoadError, Model};

/// The directory, relative to the model directory, that holds the history.
pub const HISTORY_DIR: &str = ".bussard/history";

/// The manifest filename inside a snapshot.
const MANIFEST: &str = "manifest.json";

/// The model files a snapshot copies. Everything else in the model directory is
/// local, vendor-derived or secret and is never snapshotted.
pub(crate) const MODEL_FILES: [&str; 3] = ["bussard.yaml", "groups.yaml", "links.yaml"];

/// An error reading or writing the history.
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    /// An I/O error on a history or model file.
    #[error("history: {path}: {source}")]
    Io {
        /// The path being read or written.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A manifest could not be read or written as JSON.
    #[error("history: manifest {path}: {source}")]
    Manifest {
        /// The manifest file.
        path: PathBuf,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// A snapshot's model files did not load.
    #[error("history: loading snapshot {id}: {source}")]
    Load {
        /// The snapshot id.
        id: String,
        /// The underlying error.
        source: LoadError,
    },
    /// No snapshot matches the given id or index.
    #[error("history: no snapshot {spec} (run `bussard history` to list them)")]
    NoSuchSnapshot {
        /// What the caller asked for.
        spec: String,
    },
    /// The history is empty, so there is nothing to compare or restore.
    #[error("history: no snapshots yet in {}", dir.display())]
    Empty {
        /// The history directory.
        dir: PathBuf,
    },
}

/// A snapshot identifier: `<UTC timestamp>-<seq>`, e.g. `20260922T101112Z-001`.
///
/// Ids sort lexicographically in chronological order, so a directory listing is
/// already a timeline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SnapshotId(String);

impl SnapshotId {
    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a snapshot was taken: the command and the arguments that triggered it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    /// The command name, e.g. `apply`, `import`, `mcp knx_set_group`,
    /// `external edit` or `undo`.
    pub command: String,
    /// The arguments that command ran with, already stringified.
    #[serde(default)]
    pub args: Vec<String>,
}

/// A snapshot manifest: why, against which gateway, and what came of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The command and arguments that triggered the snapshot.
    pub reason: Reason,
    /// The gateway a bus write went to, when one did.
    #[serde(default)]
    pub gateway: Option<String>,
    /// A short outcome note, e.g. `before apply`.
    #[serde(default)]
    pub result: String,
    /// The bussard version that wrote the snapshot.
    #[serde(default)]
    pub bussard_version: String,
    /// When the snapshot was taken, RFC3339 in UTC.
    #[serde(default)]
    pub created_at: String,
}

/// The reason to record with a snapshot, built fluently at the call site.
///
/// ```
/// use bussard_model::history::SnapshotReason;
/// let reason = SnapshotReason::new("apply")
///     .with_args(["1.1.4"])
///     .with_gateway(Some("127.0.0.1:3671".to_string()))
///     .with_result("before writing the device tables");
/// assert_eq!(reason.command, "apply");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotReason {
    /// The command name.
    pub command: String,
    /// The command's arguments.
    pub args: Vec<String>,
    /// The gateway, when the command wrote to the bus.
    pub gateway: Option<String>,
    /// A short outcome note.
    pub result: String,
}

impl SnapshotReason {
    /// A reason for `command` with no arguments, gateway or result yet.
    pub fn new(command: impl Into<String>) -> Self {
        SnapshotReason {
            command: command.into(),
            args: Vec::new(),
            gateway: None,
            result: String::new(),
        }
    }

    /// Records the command's arguments.
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Records the gateway a bus write went to.
    pub fn with_gateway(mut self, gateway: Option<String>) -> Self {
        self.gateway = gateway;
        self
    }

    /// Records a short outcome note.
    pub fn with_result(mut self, result: impl Into<String>) -> Self {
        self.result = result.into();
        self
    }

    /// Turns the reason into a manifest, stamping the time and version.
    fn into_manifest(self, created_at: String) -> Manifest {
        Manifest {
            reason: Reason {
                command: self.command,
                args: self.args,
            },
            gateway: self.gateway,
            result: self.result,
            bussard_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at,
        }
    }
}

/// One snapshot on disk: its id and manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// The snapshot id (also its directory name).
    pub id: SnapshotId,
    /// The manifest recorded with it.
    pub manifest: Manifest,
}

/// The working model measured against the latest snapshot.
#[derive(Debug, Clone)]
pub struct Pending {
    /// The snapshot the working model was compared against, if any.
    pub base: Option<SnapshotId>,
    /// The changes made since that snapshot.
    pub changes: ChangeSet,
}

/// The history of one model directory.
#[derive(Debug, Clone)]
pub struct History {
    dir: PathBuf,
    history_dir: PathBuf,
}

impl History {
    /// Opens (but does not create) the history of the model directory `dir`.
    ///
    /// Nothing is written until the first [`snapshot`](History::snapshot), so a
    /// read-only command leaves no trace.
    pub fn open(dir: &Path) -> Self {
        History {
            dir: dir.to_path_buf(),
            history_dir: dir.join(HISTORY_DIR),
        }
    }

    /// Whether the model directory holds any model file at all
    /// (`bussard.yaml`, `groups.yaml`, `links.yaml` or a `devices/*.yaml`).
    ///
    /// The hooks use it to stay silent for a directory that has no model yet,
    /// so they never create one.
    pub fn has_model_files(&self) -> bool {
        MODEL_FILES.iter().any(|name| self.dir.join(name).is_file())
            || device_files(&self.dir.join("devices")).is_ok_and(|files| !files.is_empty())
    }

    /// The model directory this history belongs to.
    pub fn model_dir(&self) -> &Path {
        &self.dir
    }

    /// The `.bussard/history` directory, whether or not it exists yet.
    pub fn history_dir(&self) -> &Path {
        &self.history_dir
    }

    /// The directory holding one snapshot's files.
    pub fn snapshot_dir(&self, id: &SnapshotId) -> PathBuf {
        self.history_dir.join(id.as_str())
    }

    /// Copies the current model files into a new snapshot and returns its id.
    ///
    /// Only `bussard.yaml`, `groups.yaml`, `links.yaml` and `devices/*.yaml` are
    /// copied; product data, captures, keyrings and project files never are.
    pub fn snapshot(&self, reason: SnapshotReason) -> Result<SnapshotId, HistoryError> {
        let now = SystemTime::now();
        let id = self.next_id(now)?;
        let target = self.snapshot_dir(&id);
        create_dir(&target)?;

        for name in MODEL_FILES {
            let source = self.dir.join(name);
            if source.is_file() {
                copy(&source, &target.join(name))?;
            }
        }
        let devices = self.dir.join("devices");
        if devices.is_dir() {
            let target_devices = target.join("devices");
            create_dir(&target_devices)?;
            for name in device_files(&devices)? {
                copy(&devices.join(&name), &target_devices.join(&name))?;
            }
        }

        let manifest = reason.into_manifest(rfc3339(now));
        let path = target.join(MANIFEST);
        let text =
            serde_json::to_string_pretty(&manifest).map_err(|source| HistoryError::Manifest {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, format!("{text}\n")).map_err(|source| HistoryError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(id)
    }

    /// Every snapshot, oldest first.
    ///
    /// A directory without a readable manifest is skipped rather than failing
    /// the listing: a half-written snapshot must not break `bussard history`.
    pub fn list(&self) -> Result<Vec<Snapshot>, HistoryError> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.history_dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(source) => {
                return Err(HistoryError::Io {
                    path: self.history_dir.clone(),
                    source,
                });
            }
        };
        let mut ids: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        ids.sort();
        for id in ids {
            let id = SnapshotId(id);
            if let Ok(manifest) = self.read_manifest(&id) {
                out.push(Snapshot { id, manifest });
            }
        }
        Ok(out)
    }

    /// The most recent snapshot, if there is one.
    pub fn latest(&self) -> Result<Option<Snapshot>, HistoryError> {
        Ok(self.list()?.pop())
    }

    /// Loads the model as it was at a snapshot.
    pub fn load(&self, id: &SnapshotId) -> Result<Model, HistoryError> {
        let dir = self.snapshot_dir(id);
        if !dir.is_dir() {
            return Err(HistoryError::NoSuchSnapshot {
                spec: id.to_string(),
            });
        }
        Model::load(&dir).map_err(|source| HistoryError::Load {
            id: id.to_string(),
            source,
        })
    }

    /// Loads the model currently in the working directory.
    pub fn working_model(&self) -> Result<Model, LoadError> {
        Model::load(&self.dir)
    }

    /// Resolves a user-typed snapshot specification: either a full id, or a
    /// 1-based index into [`list`](History::list) (`1` is the oldest).
    pub fn resolve(&self, spec: &str) -> Result<Snapshot, HistoryError> {
        let snapshots = self.list()?;
        if snapshots.is_empty() {
            return Err(HistoryError::Empty {
                dir: self.history_dir.clone(),
            });
        }
        if let Some(found) = snapshots.iter().find(|s| s.id.as_str() == spec) {
            return Ok(found.clone());
        }
        if let Ok(index) = spec.parse::<usize>()
            && index >= 1
            && index <= snapshots.len()
        {
            return Ok(snapshots[index - 1].clone());
        }
        Err(HistoryError::NoSuchSnapshot {
            spec: spec.to_string(),
        })
    }

    /// The working model measured against the latest snapshot.
    ///
    /// With no snapshot yet, the base is `None` and the change set is empty:
    /// there is no baseline to compare against, and inventing one would report
    /// the whole model as new.
    pub fn pending(&self) -> Result<Pending, HistoryError> {
        let Some(latest) = self.latest()? else {
            return Ok(Pending {
                base: None,
                changes: ChangeSet::default(),
            });
        };
        let old = self.load(&latest.id)?;
        let new = self.working_model().map_err(|source| HistoryError::Load {
            id: "working model".to_string(),
            source,
        })?;
        Ok(Pending {
            base: Some(latest.id),
            changes: describe(&old, &new),
        })
    }

    /// The snapshot a bare `undo` restores: the newest one whose model differs
    /// from the working model.
    ///
    /// Snapshots are taken *before* a command writes, so after a model edit the
    /// newest snapshot is the state the edit replaced, and after a bus-only
    /// command (`apply`, `flash`) it equals the working files. Skipping the
    /// snapshots identical to the working model makes one `undo` revert exactly
    /// the last change in both cases, and a second `undo` revert the first.
    /// `None` when every snapshot matches the working model (nothing to undo).
    pub fn undo_target(&self) -> Result<Option<Snapshot>, HistoryError> {
        let working = self.working_model().map_err(|source| HistoryError::Load {
            id: "working model".to_string(),
            source,
        })?;
        for snapshot in self.list()?.into_iter().rev() {
            if self.load(&snapshot.id)? != working {
                return Ok(Some(snapshot));
            }
        }
        Ok(None)
    }

    /// Records an `external edit` snapshot when the working model differs from
    /// the latest snapshot, so an edit made outside bussard is never lost.
    ///
    /// Returns the new snapshot's id when one was taken. A working model that
    /// does not load is left alone (`Ok(None)`): the command that follows will
    /// report the parse error properly.
    pub fn snapshot_if_changed_externally(&self) -> Result<Option<SnapshotId>, HistoryError> {
        // No model here (a command run with the default `--dir knx` somewhere
        // else): record nothing, and above all create nothing.
        if !self.has_model_files() {
            return Ok(None);
        }
        let Ok(working) = self.working_model() else {
            return Ok(None);
        };
        match self.latest()? {
            Some(latest) => {
                let old = self.load(&latest.id)?;
                if old == working {
                    return Ok(None);
                }
                let reason = SnapshotReason::new("external edit")
                    .with_result("model files changed outside bussard");
                Ok(Some(self.snapshot(reason)?))
            }
            None => {
                let reason = SnapshotReason::new("external edit")
                    .with_result("baseline recorded (no earlier snapshot)");
                Ok(Some(self.snapshot(reason)?))
            }
        }
    }

    /// Restores the working model files to a snapshot.
    ///
    /// Takes an `undo` snapshot of the current state first (so an undo is itself
    /// undoable), then copies the snapshot's files over the working ones and
    /// removes device files the snapshot did not have. **Files only** — devices
    /// keep their tables until a human runs `plan` and `apply`.
    ///
    /// Returns the id of the `undo` snapshot it took first.
    pub fn restore(&self, id: &SnapshotId) -> Result<SnapshotId, HistoryError> {
        let source_dir = self.snapshot_dir(id);
        if !source_dir.is_dir() {
            return Err(HistoryError::NoSuchSnapshot {
                spec: id.to_string(),
            });
        }
        let undo = self.snapshot(
            SnapshotReason::new("undo")
                .with_args([id.to_string()])
                .with_result(format!("state before restoring {id}")),
        )?;

        for name in MODEL_FILES {
            let from = source_dir.join(name);
            if from.is_file() {
                copy(&from, &self.dir.join(name))?;
            }
        }

        let source_devices = source_dir.join("devices");
        let target_devices = self.dir.join("devices");
        let wanted: BTreeSet<String> = if source_devices.is_dir() {
            device_files(&source_devices)?.into_iter().collect()
        } else {
            BTreeSet::new()
        };
        if !wanted.is_empty() {
            create_dir(&target_devices)?;
        }
        for name in &wanted {
            copy(&source_devices.join(name), &target_devices.join(name))?;
        }
        if target_devices.is_dir() {
            for name in device_files(&target_devices)? {
                if !wanted.contains(&name) {
                    let path = target_devices.join(&name);
                    fs::remove_file(&path).map_err(|source| HistoryError::Io { path, source })?;
                }
            }
        }
        Ok(undo)
    }

    /// Reads one snapshot's manifest.
    fn read_manifest(&self, id: &SnapshotId) -> Result<Manifest, HistoryError> {
        let path = self.snapshot_dir(id).join(MANIFEST);
        let text = fs::read_to_string(&path).map_err(|source| HistoryError::Io {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|source| HistoryError::Manifest { path, source })
    }

    /// The next free snapshot id for `now`: the UTC timestamp plus a sequence
    /// number that disambiguates snapshots taken in the same second.
    fn next_id(&self, now: SystemTime) -> Result<SnapshotId, HistoryError> {
        let stamp = compact_stamp(now);
        let mut seq = 1u32;
        loop {
            let id = SnapshotId(format!("{stamp}-{seq:03}"));
            if !self.snapshot_dir(&id).exists() {
                return Ok(id);
            }
            seq += 1;
            if seq > 999 {
                return Err(HistoryError::Io {
                    path: self.history_dir.clone(),
                    source: std::io::Error::other(
                        "more than 999 snapshots in one second; refusing to add another",
                    ),
                });
            }
        }
    }
}

/// Records an `external edit` snapshot for the model in `dir` when it differs
/// from the latest snapshot. The one-line form commands call at startup.
pub fn snapshot_if_changed_externally(dir: &Path) -> Result<Option<SnapshotId>, HistoryError> {
    History::open(dir).snapshot_if_changed_externally()
}

/// The `*.yaml` / `*.yml` filenames in a `devices/` directory, sorted.
fn device_files(dir: &Path) -> Result<Vec<String>, HistoryError> {
    let entries = fs::read_dir(dir).map_err(|source| HistoryError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut out: Vec<String> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "yaml" || e == "yml")
        })
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
        .collect();
    out.sort();
    Ok(out)
}

/// Creates a directory and every missing parent.
fn create_dir(path: &Path) -> Result<(), HistoryError> {
    fs::create_dir_all(path).map_err(|source| HistoryError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Copies one file, naming the destination in any error.
fn copy(from: &Path, to: &Path) -> Result<(), HistoryError> {
    fs::copy(from, to)
        .map(|_| ())
        .map_err(|source| HistoryError::Io {
            path: to.to_path_buf(),
            source,
        })
}

// ---------------------------------------------------------------------------
// Time formatting.
//
// The same std-only civil-time conversion the monitor uses for its timestamps
// (`bussard_monitor::timefmt`), repeated here because the model crate sits below
// the monitor in the dependency order and no date-time crate is warranted.
// ---------------------------------------------------------------------------

/// `20260922T101112Z` — the sortable stamp a snapshot id starts with.
fn compact_stamp(ts: SystemTime) -> String {
    let (year, month, day, hour, minute, second) = civil(ts);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// `2026-09-22T10:11:12Z` — the manifest's `created_at`.
pub(crate) fn rfc3339(ts: SystemTime) -> String {
    let (year, month, day, hour, minute, second) = civil(ts);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Breaks a `SystemTime` into UTC civil fields. Times before the Unix epoch
/// clamp to the epoch.
fn civil(ts: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let secs = ts
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    (
        year,
        month,
        day,
        (rest / 3600) as u32,
        ((rest % 3600) / 60) as u32,
        (rest % 60) as u32,
    )
}

/// Days since the Unix epoch → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh temp model directory with one group and one device.
    fn model_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-history-{tag}-{}-{:?}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("devices"))?;
        fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"3/0/4\":\n    name: Blind\n    dpt: \"1.008\"\n",
        )?;
        fs::write(dir.join("links.yaml"), "links: {}\n")?;
        fs::write(
            dir.join("devices").join("1.1.4-blind.yaml"),
            "address: \"1.1.4\"\nname: Blind actuator\n",
        )?;
        Ok(dir)
    }

    #[test]
    fn test_snapshot_copies_only_the_model_files() -> Result<(), Box<dyn std::error::Error>> {
        let dir = model_dir("copies")?;
        fs::create_dir_all(dir.join("vendor"))?;
        fs::write(dir.join("vendor").join("secret.knxprod"), "binary")?;
        fs::create_dir_all(dir.join("captures"))?;
        fs::write(dir.join("captures").join("bus.sqlite"), "db")?;

        let history = History::open(&dir);
        let id = history.snapshot(SnapshotReason::new("import").with_args(["home.knxproj"]))?;
        let snap = history.snapshot_dir(&id);
        assert!(snap.join("groups.yaml").is_file());
        assert!(snap.join("devices").join("1.1.4-blind.yaml").is_file());
        assert!(
            !snap.join("vendor").exists(),
            "vendor data must never be snapshotted"
        );
        assert!(
            !snap.join("captures").exists(),
            "captures must never be snapshotted"
        );

        let listed = history.list()?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].manifest.reason.command, "import");
        assert_eq!(listed[0].manifest.reason.args, vec!["home.knxproj"]);

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_external_edit_is_captured_once() -> Result<(), Box<dyn std::error::Error>> {
        let dir = model_dir("external")?;
        let history = History::open(&dir);
        assert!(
            history.snapshot_if_changed_externally()?.is_some(),
            "baseline"
        );
        assert!(
            history.snapshot_if_changed_externally()?.is_none(),
            "no change"
        );

        fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"3/0/4\":\n    name: Kitchen blind\n    dpt: \"1.008\"\n",
        )?;
        assert!(
            history.snapshot_if_changed_externally()?.is_some(),
            "edit captured"
        );
        assert_eq!(history.list()?.len(), 2);

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_restore_puts_the_files_back_and_snapshots_first()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = model_dir("restore")?;
        let history = History::open(&dir);
        let first = history.snapshot(SnapshotReason::new("import"))?;

        fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"3/0/4\":\n    name: Kitchen blind\n    dpt: \"1.008\"\n",
        )?;
        fs::write(
            dir.join("devices").join("1.1.9-new.yaml"),
            "address: \"1.1.9\"\nname: New device\n",
        )?;

        let undo = history.restore(&first)?;
        assert_ne!(undo, first);
        let restored = Model::load(&dir)?;
        let ga: crate::GroupAddress = "3/0/4".parse()?;
        assert_eq!(restored.groups.groups[&ga].name, "Blind");
        assert!(
            !dir.join("devices").join("1.1.9-new.yaml").exists(),
            "a device file the snapshot did not have must be removed"
        );
        assert_eq!(history.list()?.len(), 2, "the undo itself is a snapshot");

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_pending_describes_the_working_edit() -> Result<(), Box<dyn std::error::Error>> {
        let dir = model_dir("pending")?;
        let history = History::open(&dir);
        history.snapshot(SnapshotReason::new("import"))?;
        fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"3/0/4\":\n    name: Kitchen blind\n    dpt: \"1.008\"\n",
        )?;
        let pending = history.pending()?;
        assert!(pending.base.is_some());
        assert_eq!(pending.changes.len(), 1);
        assert!(
            pending.changes.changes[0]
                .sentence
                .contains("Kitchen blind")
        );

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_resolve_accepts_an_index_or_an_id() -> Result<(), Box<dyn std::error::Error>> {
        let dir = model_dir("resolve")?;
        let history = History::open(&dir);
        let first = history.snapshot(SnapshotReason::new("import"))?;
        assert_eq!(history.resolve("1")?.id, first);
        assert_eq!(history.resolve(first.as_str())?.id, first);
        assert!(history.resolve("7").is_err());

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_snapshot_if_changed_externally_never_creates_a_model_dir()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-history-absent-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let history = History::open(&dir);
        assert!(!history.has_model_files());
        assert!(history.snapshot_if_changed_externally()?.is_none());
        assert!(!dir.exists(), "a hook must not create a model directory");
        Ok(())
    }

    #[test]
    fn test_stamp_formats_are_utc_and_sortable() {
        let ts = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        assert_eq!(compact_stamp(ts), "20260921T141320Z");
        assert_eq!(rfc3339(ts), "2026-09-21T14:13:20Z");
    }
}
