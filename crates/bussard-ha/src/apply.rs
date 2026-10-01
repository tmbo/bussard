//! Writing the KNX YAML Home Assistant reads (issue #280).
//!
//! [`write_with_backup`] keeps the file's current bytes under
//! `<model dir>/captures/backups/ha/<unix seconds>.yaml`, then replaces the
//! file atomically: the new text goes to a temporary file beside it, is
//! flushed to disk, takes over the old file's permissions and is renamed over
//! it. A reader (Home Assistant reloading) sees the old file or the new one,
//! never half of either. Nothing else is written.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// An error writing the file or its backup.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The backup could not be written, so the file was not touched.
    #[error("writing the backup {path}: {source}")]
    Backup {
        /// The backup path.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The new file could not be written; the old one is unchanged.
    #[error("writing {path}: {source}")]
    Write {
        /// The target path.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
}

/// The backup directory inside a model directory: `<dir>/captures/backups/ha`.
pub fn backup_dir(model_dir: &Path) -> PathBuf {
    model_dir.join("captures").join("backups").join("ha")
}

/// Backs `current` up under [`backup_dir`] (named by `now` in Unix seconds,
/// with `-2`, `-3` appended on a clash), then replaces `target` with `text`
/// atomically. Returns the backup path.
///
/// # Errors
///
/// [`ApplyError::Backup`] before anything else is touched;
/// [`ApplyError::Write`] when the replacement fails (the old file stays).
pub fn write_with_backup(
    model_dir: &Path,
    target: &Path,
    current: &[u8],
    text: &str,
    now: SystemTime,
) -> Result<PathBuf, ApplyError> {
    let dir = backup_dir(model_dir);
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = |source| ApplyError::Backup {
        path: dir.clone(),
        source,
    };
    std::fs::create_dir_all(&dir).map_err(backup)?;
    let mut path = dir.join(format!("{seconds}.yaml"));
    let mut n = 1;
    while path.exists() {
        n += 1;
        path = dir.join(format!("{seconds}-{n}.yaml"));
    }
    std::fs::write(&path, current).map_err(|source| ApplyError::Backup {
        path: path.clone(),
        source,
    })?;
    replace_atomically(target, text.as_bytes()).map_err(|source| ApplyError::Write {
        path: target.to_path_buf(),
        source,
    })?;
    Ok(path)
}

/// Writes `bytes` to a temporary file beside `target` and renames it over
/// `target`, keeping `target`'s permissions.
fn replace_atomically(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "knx.yaml".to_string());
    let tmp = parent.join(format!(".{name}.bussard-{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if let Ok(meta) = std::fs::metadata(target) {
            std::fs::set_permissions(&tmp, meta.permissions())?;
        }
        std::fs::rename(&tmp, target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_write_with_backup_keeps_the_old_bytes_and_replaces_the_file() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let model = tmp.path().join("knx");
        let target = tmp.path().join("ha").join("knx.yaml");
        std::fs::create_dir_all(target.parent().ok_or("parent")?)?;
        std::fs::write(&target, "knx:\n")?;
        let now = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let first = write_with_backup(&model, &target, b"knx:\n", "knx:\n  light: []\n", now)?;
        assert_eq!(first, backup_dir(&model).join("1700000000.yaml"));
        assert_eq!(std::fs::read_to_string(&first)?, "knx:\n");
        assert_eq!(std::fs::read_to_string(&target)?, "knx:\n  light: []\n");
        let second = write_with_backup(&model, &target, b"x", "y", now)?;
        assert_eq!(second, backup_dir(&model).join("1700000000-2.yaml"));
        let leftovers: Vec<_> = std::fs::read_dir(target.parent().ok_or("parent")?)?
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        Ok(())
    }
}
