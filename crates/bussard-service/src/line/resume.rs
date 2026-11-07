//! The resume record of a whole-line apply (issue #903): every device
//! outcome is written to `<dir>/captures/apply-line-<line>.json` as it
//! happens, so a tunnel drop, a killed process or a Ctrl-C leaves a record of
//! what was already written, and `bussard apply --line <line> --resume`
//! skips the finished devices without touching the bus. A run that ends with
//! no failures deletes the file.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use bussard_model::IndividualAddress;

use super::{DeviceStatus, LineOutcome, LineTarget};

/// The state-file format version, bumped if the shape ever changes.
const STATE_VERSION: u32 = 1;

/// One device's persisted outcome.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceRecord {
    /// The status key (`applied`, `unchanged`, `skipped`, `failed`).
    pub status: String,
    /// How many link changes were written.
    #[serde(default)]
    pub changes: usize,
    /// The skip or failure reason.
    #[serde(default)]
    pub detail: Option<String>,
    /// When this outcome was recorded (seconds since the Unix epoch).
    #[serde(default)]
    pub unix: u64,
}

impl DeviceRecord {
    /// Whether a later resume may skip this device untouched.
    pub fn is_finished(&self) -> bool {
        self.status != "failed"
    }
}

/// What a whole-line apply has already done.
///
/// It is rewritten after every device, so a process killed at any point
/// leaves a truthful record.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LineState {
    /// The format version.
    pub version: u32,
    /// The line this run covers, e.g. `1.1`.
    pub line: String,
    /// The gateway the run wrote through, for the operator's benefit.
    pub gateway: String,
    /// When the run started (seconds since the Unix epoch).
    pub started_unix: u64,
    /// When the file was last written.
    pub updated_unix: u64,
    /// Whether every device reached a finished state.
    pub completed: bool,
    /// Per-device outcomes, keyed by individual address.
    pub devices: BTreeMap<String, DeviceRecord>,
}

/// How [`LineState::open`] found the state file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// No file, no resume asked: a fresh run.
    Fresh,
    /// Resumed the recorded run with this many devices already done.
    Resumed(usize),
    /// A resume was asked but no run is recorded: a fresh run.
    NothingToResume,
    /// A recorded run was replaced by a fresh one (no resume asked).
    Replaced,
}

impl LineState {
    /// A fresh state for a run over `line` through `gateway`.
    pub fn new(line: &str, gateway: &str) -> Self {
        let now = unix_now();
        LineState {
            version: STATE_VERSION,
            line: line.to_string(),
            gateway: gateway.to_string(),
            started_unix: now,
            updated_unix: now,
            completed: false,
            devices: BTreeMap::new(),
        }
    }

    /// The state file for `line` under the model directory `dir`.
    pub fn path(dir: &Path, line: &str) -> PathBuf {
        dir.join("captures").join(format!("apply-line-{line}.json"))
    }

    /// Loads the run recorded at `path` when `resume`, else starts a fresh
    /// one; [`Opened`] says which, so the surface can tell the operator that
    /// a leftover run exists.
    pub fn open(path: &Path, line: &str, gateway: &str, resume: bool) -> (LineState, Opened) {
        let existing = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<LineState>(&text).ok());
        match (resume, existing) {
            (true, Some(mut state)) => {
                let done = state.devices.values().filter(|r| r.is_finished()).count();
                state.gateway = gateway.to_string();
                state.completed = false;
                (state, Opened::Resumed(done))
            }
            (true, None) => (LineState::new(line, gateway), Opened::NothingToResume),
            (false, Some(_)) => (LineState::new(line, gateway), Opened::Replaced),
            (false, None) => (LineState::new(line, gateway), Opened::Fresh),
        }
    }

    /// Whether the record has `address` as finished.
    pub fn is_done(&self, address: IndividualAddress) -> bool {
        self.devices
            .get(&address.to_string())
            .is_some_and(DeviceRecord::is_finished)
    }

    /// The outcome of a target the record has as finished: skipped, without
    /// touching the bus.
    pub fn done_earlier(target: &LineTarget) -> LineOutcome {
        LineOutcome {
            address: target.address,
            name: target.name.clone(),
            mask: None,
            status: DeviceStatus::Skipped("done in an earlier run".to_string()),
            report: None,
            fingerprint: None,
            backup: None,
        }
    }

    /// Records `outcome` and writes the file to `path`.
    ///
    /// # Errors
    ///
    /// The file could not be written.
    pub fn record(&mut self, outcome: &LineOutcome, path: &Path) -> io::Result<()> {
        self.devices.insert(
            outcome.address.to_string(),
            DeviceRecord {
                status: outcome.status.key().to_string(),
                changes: outcome.status.changes(),
                detail: outcome.status.detail().map(str::to_string),
                unix: unix_now(),
            },
        );
        self.write(path)
    }

    /// Ends the run: a run where `all_done` deletes the file at `path`, any
    /// other keeps it for a resume and returns `true`.
    ///
    /// # Errors
    ///
    /// The kept file could not be written.
    pub fn finish(&mut self, all_done: bool, path: &Path) -> io::Result<bool> {
        self.completed = all_done;
        if all_done {
            let _ = std::fs::remove_file(path);
            return Ok(false);
        }
        self.write(path)?;
        Ok(true)
    }

    /// Writes the file to `path`, creating `captures/` if needed.
    fn write(&mut self, path: &Path) -> io::Result<()> {
        self.updated_unix = unix_now();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)
    }
}

/// Seconds since the Unix epoch, or 0 if the clock is before it.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn record(status: &str) -> DeviceRecord {
        DeviceRecord {
            status: status.to_string(),
            changes: 0,
            detail: None,
            unix: 0,
        }
    }

    #[test]
    fn test_path_names_the_line() {
        let path = LineState::path(Path::new("knx"), "1.1");
        assert!(path.ends_with("captures/apply-line-1.1.json"), "{path:?}");
    }

    #[test]
    fn test_is_done_only_for_finished_records() -> R {
        let mut state = LineState::new("1.1", "127.0.0.1:3671");
        state.devices.insert("1.1.4".to_string(), record("applied"));
        state.devices.insert("1.1.5".to_string(), record("failed"));
        assert!(state.is_done("1.1.4".parse()?));
        assert!(!state.is_done("1.1.5".parse()?));
        assert!(!state.is_done("1.1.6".parse()?));
        Ok(())
    }

    #[test]
    fn test_open_resumes_a_kept_run_and_finish_retires_it() -> R {
        let dir = std::env::temp_dir().join(format!("bussard-line-resume-{}", std::process::id()));
        let path = LineState::path(&dir, "1.1");
        let (mut state, opened) = LineState::open(&path, "1.1", "gw", true);
        assert_eq!(opened, Opened::NothingToResume);
        state.devices.insert("1.1.4".to_string(), record("applied"));
        state.devices.insert("1.1.5".to_string(), record("failed"));
        assert!(state.finish(false, &path)?);
        let (state, opened) = LineState::open(&path, "1.1", "gw2", true);
        assert_eq!(opened, Opened::Resumed(1));
        assert_eq!(state.gateway, "gw2");
        let (mut state, opened) = LineState::open(&path, "1.1", "gw", false);
        assert_eq!(opened, Opened::Replaced);
        assert!(!state.finish(true, &path)?);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
