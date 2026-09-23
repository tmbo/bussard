//! A model that notices when its files on disk change.
//!
//! The MCP server is long-lived: an agent session can run for hours while the
//! human edits `knx/` in another window. The model used to be loaded once at
//! startup and never again, so a `protected: true` added to `groups.yaml`
//! mid-session did not protect anything until the server was restarted, and a
//! corrected `dpt:` was not used either. That is a safety gate that silently
//! lags the source of truth.
//!
//! [`ModelHandle`] fixes it without a background task: readers call
//! [`current`](ModelHandle::current), which re-stats the model directory at most
//! once per [`RECHECK_INTERVAL`] and reloads only when the fingerprint (file
//! count plus newest modification time) actually changed. A reload that fails
//! keeps the previous model and logs a warning, so a half-saved file never
//! leaves the server without one — the same fail-closed rule the viz server's
//! `POST /api/reload` follows.

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
    dir: PathBuf,
    inner: Arc<RwLock<Snapshot>>,
}

impl ModelHandle {
    /// Wraps an already-loaded model as version 1, fingerprinting `dir` now.
    pub fn new(dir: PathBuf, model: Model) -> Self {
        let fingerprint = fingerprint(&dir);
        ModelHandle {
            dir,
            inner: Arc::new(RwLock::new(Snapshot {
                model: Arc::new(model),
                fingerprint,
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
        let current = fingerprint(&self.dir);

        let mut snapshot = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshot.checked = Instant::now();
        if current == snapshot.fingerprint {
            return snapshot.model.clone();
        }

        match Model::load(&self.dir) {
            Ok(model) => {
                snapshot.model = Arc::new(model);
                snapshot.fingerprint = current;
                snapshot.version += 1;
                tracing::info!(
                    "model reloaded from {} (version {})",
                    self.dir.display(),
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
                    self.dir.display()
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
/// Covers `bussard.yaml`, `groups.yaml`, `links.yaml`, `ha.yaml` and every file
/// under `devices/`. An unreadable directory fingerprints as `(0, UNIX_EPOCH, 0)`,
/// which simply means "nothing changed" until it becomes readable again.
fn fingerprint(dir: &Path) -> Fingerprint {
    let mut count = 0usize;
    let mut newest = SystemTime::UNIX_EPOCH;
    // Total size as a third component: two writes inside one filesystem
    // timestamp tick (coarse on Windows) would otherwise be indistinguishable.
    let mut total_len = 0u64;

    let mut visit = |path: &Path| {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.is_file() {
                count += 1;
                total_len += meta.len();
                if let Ok(modified) = meta.modified() {
                    if modified > newest {
                        newest = modified;
                    }
                }
            }
        }
    };

    for name in ["bussard.yaml", "groups.yaml", "links.yaml", "ha.yaml"] {
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

    /// A fresh temp directory holding a one-group model.
    fn model_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bussard-mcp-model-{tag}-{}-{:?}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"3/0/4\":\n    name: Blind\n    dpt: \"1.008\"\n",
        )
        .expect("write groups.yaml");
        dir
    }

    fn handle_for(dir: &Path) -> ModelHandle {
        let model = Model::load(dir).expect("model loads");
        ModelHandle::new(dir.to_path_buf(), model)
    }

    #[test]
    fn test_current_picks_up_a_protected_flag_added_on_disk()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = model_dir("protected");
        let handle = handle_for(&dir);
        let ga: bussard_model::GroupAddress = "3/0/4".parse()?;
        assert!(!handle.current().groups.groups[&ga].protected);

        std::fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"3/0/4\":\n    name: Blind\n    dpt: \"1.008\"\n    protected: true\n",
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
    fn test_unchanged_directory_does_not_bump_the_version() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = model_dir("unchanged");
        let handle = handle_for(&dir);
        handle.refresh();
        handle.refresh();
        assert_eq!(handle.version(), 1);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_broken_model_keeps_the_previous_one() -> Result<(), Box<dyn std::error::Error>> {
        let dir = model_dir("broken");
        let handle = handle_for(&dir);
        let ga: bussard_model::GroupAddress = "3/0/4".parse()?;

        // Duplicate keys: the YAML no longer parses.
        std::fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"3/0/4\":\n    name: a\n  \"3/0/4\":\n    name: b\n",
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
}
