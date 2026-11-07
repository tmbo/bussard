//! A process-wide memo of values derived from files, each valid while its
//! file keeps its size and modification time (issues #339, #367).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

/// The identity of a file on disk: its length and modification time. A
/// rewrite changes at least one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    mtime: Option<SystemTime>,
}

impl Stamp {
    /// The stamp of the file at `path`, if it exists.
    fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Stamp {
            len: meta.len(),
            mtime: meta.modified().ok(),
        })
    }
}

/// Values derived from files, by path, each with the stamp it was derived at.
pub(crate) struct StampedMemo<T> {
    entries: Mutex<Vec<(PathBuf, Stamp, T)>>,
}

impl<T: Clone> StampedMemo<T> {
    /// An empty memo.
    pub(crate) const fn new() -> Self {
        StampedMemo {
            entries: Mutex::new(Vec::new()),
        }
    }

    /// The entries; a poisoned lock still holds whole entries.
    fn entries(&self) -> MutexGuard<'_, Vec<(PathBuf, Stamp, T)>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The value of `path`: memoized when the file is unchanged since, else
    /// `derive`d and memoized, unless the file changed under `derive` or
    /// `derive` failed.
    pub(crate) fn get_or_try_insert<E>(
        &self,
        path: &Path,
        derive: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let stamp = Stamp::of(path);
        if let Some(stamp) = stamp
            && let Some((_, _, value)) = self
                .entries()
                .iter()
                .find(|(p, s, _)| p == path && *s == stamp)
        {
            return Ok(value.clone());
        }
        let value = derive()?;
        if stamp.is_some() && Stamp::of(path) == stamp {
            self.put_at(path, stamp, value.clone());
        }
        Ok(value)
    }

    /// Memoizes `value` as derived from `path` as it is now.
    pub(crate) fn put(&self, path: &Path, value: T) {
        self.put_at(path, Stamp::of(path), value);
    }

    fn put_at(&self, path: &Path, stamp: Option<Stamp>, value: T) {
        let Some(stamp) = stamp else { return };
        let mut entries = self.entries();
        entries.retain(|(p, _, _)| p != path);
        entries.push((path.to_path_buf(), stamp, value));
    }

    /// Drops the entry of `path`.
    #[cfg(test)]
    pub(crate) fn forget(&self, path: &Path) {
        self.entries().retain(|(p, _, _)| p != path);
    }
}
