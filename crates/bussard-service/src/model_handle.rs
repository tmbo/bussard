//! A shared model that notices when its files on disk change.
//!
//! The MCP and viz servers are long-lived: a session can run for hours while
//! the human edits `knx/` in another window. A model loaded once at startup
//! means a `protected: true` added to `groups.toml` mid-session does not protect
//! anything until a restart, and a corrected `dpt:` is not used either. That is
//! a safety gate that silently lags the source of truth.
//!
//! [`ModelHandle`] fixes it without a background task: readers call
//! [`current`](ModelHandle::current), which re-stats the model directory at most
//! once per [`RECHECK_INTERVAL`] and reloads only when the fingerprint (file
//! count, newest modification time, total size) actually changed. A reload that
//! fails keeps the previous model and logs a warning, so a half-saved file never
//! leaves the server without one. An explicit reload that must report the error
//! (viz's `POST /api/reload`) loads the model itself and calls
//! [`install`](ModelHandle::install).
//!
//! The CLI loads the model once per invocation and does not need this.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use bussard_model::Model;

/// How often the directory may be re-stat'ed. Tool calls are frequent and a
/// human edit is not, so a short debounce keeps the stat cost negligible while
/// still picking an edit up within a couple of calls.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// A cheap summary of the model directory's state on disk: how many files it
/// holds and the newest modification time among them. Any edit, addition or
/// removal changes one of the two.
type Fingerprint = (usize, SystemTime, u64);

/// The current model plus the disk state it was loaded from.
struct Snapshot {
    model: Arc<Model>,
    fingerprint: Fingerprint,
    /// When the fingerprint was last computed.
    checked: Instant,
    /// Bumped on every successful reload; `1` for the initial load.
    version: u64,
}

/// A shared, self-refreshing handle to the loaded model.
///
/// Cloning is cheap (an `Arc`). See the module docs for why this exists.
#[derive(Clone)]
pub struct ModelHandle {
    /// The directory to watch; `None` for a fixed model that never reloads.
    dir: Option<PathBuf>,
    inner: Arc<RwLock<Snapshot>>,
}

impl ModelHandle {
    /// Wraps an already-loaded model as version 1 and watches `dir` for
    /// changes, fingerprinting it now.
    pub fn new(dir: PathBuf, model: Model) -> Self {
        let fingerprint = fingerprint(&dir);
        ModelHandle {
            dir: Some(dir),
            inner: Arc::new(RwLock::new(Snapshot {
                model: Arc::new(model),
                fingerprint,
                checked: Instant::now(),
                version: 1,
            })),
        }
    }

    /// Wraps a model that never reloads from disk (version 1). For in-code
    /// models in tests, and for a surface that only reloads on request through
    /// [`install`](Self::install).
    pub fn fixed(model: Model) -> Self {
        ModelHandle {
            dir: None,
            inner: Arc::new(RwLock::new(Snapshot {
                model: Arc::new(model),
                fingerprint: (0, SystemTime::UNIX_EPOCH, 0),
                checked: Instant::now(),
                version: 1,
            })),
        }
    }

    /// The current model, reloading first if the directory changed.
    ///
    /// Cheap in the common case: a debounce means at most one `stat` sweep per
    /// [`RECHECK_INTERVAL`], and a sweep that finds nothing new does no I/O
    /// beyond that.
    pub fn current(&self) -> Arc<Model> {
        {
            let snapshot = self.read();
            if snapshot.checked.elapsed() < RECHECK_INTERVAL {
                return snapshot.model.clone();
            }
        }
        self.refresh()
    }

    /// The version of the current snapshot: `1` at startup, bumped on every
    /// successful reload. Exposed so status tools can report model freshness.
    pub fn version(&self) -> u64 {
        self.read().version
    }

    /// The current model and its version, read together (after the same
    /// debounced change check as [`current`](Self::current)), so a caller that
    /// caches something derived from the model can key it on the version.
    pub fn snapshot(&self) -> (Arc<Model>, u64) {
        let model = self.current();
        let snapshot = self.read();
        if Arc::ptr_eq(&model, &snapshot.model) {
            (model, snapshot.version)
        } else {
            // A reload landed between the two reads; report the newer pair.
            (snapshot.model.clone(), snapshot.version)
        }
    }

    /// Installs `model` as the next version, whatever the directory holds, and
    /// returns the new version.
    ///
    /// For an explicit reload that loaded (and validated) the model itself and
    /// must report a load error to its caller instead of keeping it quiet.
    pub fn install(&self, model: impl Into<Arc<Model>>) -> u64 {
        let fingerprint = self.dir.as_deref().map(fingerprint);
        let mut snapshot = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshot.model = model.into();
        if let Some(fingerprint) = fingerprint {
            snapshot.fingerprint = fingerprint;
        }
        snapshot.checked = Instant::now();
        snapshot.version += 1;
        snapshot.version
    }

    /// Forces a re-read of the directory now, bypassing the debounce.
    ///
    /// Used after this process itself wrote the model (the MCP model-edit
    /// tools), so the very next tool call serves what was just saved instead of
    /// a copy up to [`RECHECK_INTERVAL`] old.
    pub fn reload(&self) -> Arc<Model> {
        self.refresh()
    }

    /// Re-stats the directory and reloads when the fingerprint changed.
    fn refresh(&self) -> Arc<Model> {
        let Some(dir) = self.dir.as_deref() else {
            return self.read().model.clone();
        };
        let current = fingerprint(dir);

        let mut snapshot = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshot.checked = Instant::now();
        if current == snapshot.fingerprint {
            return snapshot.model.clone();
        }

        match Model::load(dir) {
            Ok(model) => {
                snapshot.model = Arc::new(model);
                snapshot.fingerprint = current;
                snapshot.version += 1;
                tracing::info!(
                    "model reloaded from {} (version {})",
                    dir.display(),
                    snapshot.version
                );
            }
            Err(err) => {
                // Keep serving the model we have. Record the fingerprint anyway
                // so a file that stays broken is not re-read on every call; the
                // next real edit changes it again and we retry.
                snapshot.fingerprint = current;
                tracing::warn!(
                    "model at {} changed but failed to reload ({err}); \
                     keeping the previously loaded model",
                    dir.display()
                );
            }
        }
        snapshot.model.clone()
    }

    /// Reads the snapshot, recovering a poisoned lock so one panicking writer
    /// cannot wedge every reader.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Snapshot> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Fingerprints a model directory: the number of model files, the newest
/// modification time among them, and their total size in bytes.
///
/// Covers `bussard.toml`, `groups.toml`, `bussard.lock`, `tests.toml`,
/// `ha.toml` and every file under `devices/`. An unreadable directory fingerprints as `(0, UNIX_EPOCH, 0)`,
/// which simply means "nothing changed" until it becomes readable again.
fn fingerprint(dir: &Path) -> Fingerprint {
    let mut count = 0usize;
    let mut newest = SystemTime::UNIX_EPOCH;
    // Total size as a third component: two writes inside one filesystem
    // timestamp tick (coarse on Windows) would otherwise be indistinguishable.
    let mut total_len = 0u64;

    let mut visit = |path: &Path| {
        if let Ok(meta) = std::fs::metadata(path)
            && meta.is_file()
        {
            count += 1;
            total_len += meta.len();
            if let Ok(modified) = meta.modified()
                && modified > newest
            {
                newest = modified;
            }
        }
    };

    for name in bussard_model::loader::MODEL_FILES {
        visit(&dir.join(name));
    }
    if let Ok(entries) = std::fs::read_dir(dir.join("devices")) {
        for entry in entries.flatten() {
            visit(&entry.path());
        }
    }

    (count, newest, total_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// A fresh temp directory holding a one-group model.
    fn model_dir(tag: &str) -> TestResult<PathBuf> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-service-model-{tag}-{}-{:?}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("groups.toml"),
            "groups = [{ address = \"3/0/4\", name = \"Blind\", dpt = \"1.008\" }]\n",
        )?;
        Ok(dir)
    }

    fn handle_for(dir: &Path) -> TestResult<ModelHandle> {
        let model = Model::load(dir)?;
        Ok(ModelHandle::new(dir.to_path_buf(), model))
    }

    #[test]
    fn test_current_picks_up_a_protected_flag_added_on_disk() -> TestResult {
        let dir = model_dir("protected")?;
        let handle = handle_for(&dir)?;
        let ga: bussard_model::GroupAddress = "3/0/4".parse()?;
        assert!(!handle.current().groups.groups[&ga].protected);

        std::fs::write(
            dir.join("groups.toml"),
            "groups = [{ address = \"3/0/4\", name = \"Blind\", dpt = \"1.008\", protected = true }]\n",
        )?;
        // Force the debounce to have elapsed by refreshing directly.
        let model = handle.refresh();
        assert!(
            model.groups.groups[&ga].protected,
            "a protected flag added on disk must take effect without a restart"
        );
        assert_eq!(handle.version(), 2);

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_unchanged_directory_does_not_bump_the_version() -> TestResult {
        let dir = model_dir("unchanged")?;
        let handle = handle_for(&dir)?;
        handle.refresh();
        handle.refresh();
        assert_eq!(handle.version(), 1);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_broken_model_keeps_the_previous_one() -> TestResult {
        let dir = model_dir("broken")?;
        let handle = handle_for(&dir)?;
        let ga: bussard_model::GroupAddress = "3/0/4".parse()?;

        // Duplicate keys: the TOML no longer parses.
        std::fs::write(
            dir.join("groups.toml"),
            "project = \"a\"\nproject = \"b\"\ngroups = [{ address = \"3/0/4\", name = \"a\" }]\n",
        )?;
        let model = handle.refresh();
        assert!(
            model.groups.groups.contains_key(&ga),
            "a broken model on disk must never replace a good one"
        );
        assert_eq!(handle.version(), 1);

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_install_bumps_the_version_and_serves_the_new_model() -> TestResult {
        let dir = model_dir("install")?;
        let handle = handle_for(&dir)?;
        std::fs::write(
            dir.join("groups.toml"),
            "groups = [{ address = \"3/0/5\", name = \"Other\" }]\n",
        )?;
        let version = handle.install(Model::load(&dir)?);
        assert_eq!(version, 2);
        let (model, v) = handle.snapshot();
        assert_eq!(v, 2);
        assert!(model.groups.groups.contains_key(&"3/0/5".parse()?));
        // The installed model matches the disk, so a refresh does not reload.
        handle.refresh();
        assert_eq!(handle.version(), 2);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_fixed_handle_never_reloads() -> TestResult {
        let dir = model_dir("fixed")?;
        let handle = ModelHandle::fixed(Model::load(&dir)?);
        std::fs::write(dir.join("groups.toml"), "groups = []\n")?;
        let model = handle.refresh();
        assert_eq!(model.groups.groups.len(), 1);
        assert_eq!(handle.version(), 1);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
