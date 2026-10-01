//! Host-local ownership marks (issue #287).
//!
//! Two bussard processes on one host that both open a KNXnet/IP Secure tunnel
//! with the first tunnelling user of the key store collide on an interface
//! that holds one session per user. A [`HostLock`] is a small file that names
//! the process (and the instance inside it) holding a resource: the tunnel
//! marks the user it authenticated as, and `bussard mcp` marks that it serves
//! a model directory.
//!
//! The marks are advisory. A lock whose process is gone is stale and is
//! replaced; nothing ever refuses to run because of one. The file holds one
//! line, `<pid> <token>`: the token tells two instances inside one process
//! apart (two buses in one test, say).
//!
//! Whether a pid is alive is asked of the kernel on Unix (`kill(pid, 0)`).
//! Elsewhere every recorded pid counts as alive, so a stale lock there only
//! reorders the user choice until the file is replaced.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Counts the locks this process created, for unique tokens.
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// The process (and instance) that holds a lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holder {
    /// The holder's process id.
    pub pid: u32,
}

/// A held lock file. Dropping it removes the file, if it is still ours.
#[derive(Debug)]
pub struct HostLock {
    path: PathBuf,
    token: String,
}

impl HostLock {
    /// Takes the lock at `path`, creating its directory.
    ///
    /// Returns `Ok(Err(holder))` when a live process (or another instance in
    /// this one) holds it. A lock left by a process that is gone, or one that
    /// cannot be parsed, is replaced.
    ///
    /// # Errors
    ///
    /// The directory or the file cannot be created or read.
    pub fn try_acquire(path: &Path) -> io::Result<Result<HostLock, Holder>> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let token = format!(
            "{}-{}",
            std::process::id(),
            NEXT_TOKEN.fetch_add(1, Ordering::Relaxed)
        );
        // Two rounds: a stale lock is removed once, then created afresh.
        for _ in 0..2 {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    writeln!(file, "{} {token}", std::process::id())?;
                    return Ok(Ok(HostLock {
                        path: path.to_path_buf(),
                        token,
                    }));
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    if let Some(holder) = live_holder(path) {
                        return Ok(Err(holder));
                    }
                    // Stale or unreadable: replace it. A concurrent remover
                    // is fine, the next create_new decides.
                    match std::fs::remove_file(path) {
                        Ok(()) => {}
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                        Err(err) => return Err(err),
                    }
                }
                Err(err) => return Err(err),
            }
        }
        match live_holder(path) {
            Some(holder) => Ok(Err(holder)),
            None => Err(io::Error::other(format!(
                "could not take the lock {}",
                path.display()
            ))),
        }
    }

    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HostLock {
    fn drop(&mut self) {
        // Remove the file only while it still carries our token: a process
        // that replaced it (after wrongly taking us for stale) keeps its own.
        if read_lock(&self.path).is_some_and(|(_, token)| token == self.token) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The live process holding the lock at `path`, if any. A missing,
/// unparsable or stale file has none.
pub fn live_holder(path: &Path) -> Option<Holder> {
    let (pid, _) = read_lock(path)?;
    pid_alive(pid).then_some(Holder { pid })
}

/// The live holders of the locks in `dir` whose file name starts with
/// `prefix`, except `own`. Stale locks found on the way are removed.
pub fn live_holders(dir: &Path, prefix: &str, own: Option<&HostLock>) -> Vec<Holder> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut holders = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let named = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(prefix) && n.ends_with(".lock"));
        if !named || own.is_some_and(|own| own.path == path) {
            continue;
        }
        match live_holder(&path) {
            Some(holder) => holders.push(holder),
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    holders.sort_by_key(|h| h.pid);
    holders.dedup();
    holders
}

/// Reads `<pid> <token>` from a lock file.
fn read_lock(path: &Path) -> Option<(u32, String)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut parts = text.split_whitespace();
    let pid = parts.next()?.parse().ok()?;
    let token = parts.next()?.to_string();
    Some((pid, token))
}

/// Whether process `pid` exists. This process always does.
pub fn pid_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    alive(pid)
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    match rustix::process::test_kill_process(pid) {
        Ok(()) => true,
        // The process exists but belongs to another user.
        Err(err) => err == rustix::io::Errno::PERM,
    }
}

#[cfg(not(unix))]
fn alive(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_try_acquire_second_instance_sees_the_first() -> TestResult {
        let dir = tempdir()?;
        let path = dir.join("a.lock");
        let first = HostLock::try_acquire(&path)?;
        assert!(first.is_ok());
        let second = HostLock::try_acquire(&path)?;
        assert_eq!(
            second.err(),
            Some(Holder {
                pid: std::process::id()
            })
        );
        drop(first);
        assert!(!path.exists(), "dropping the lock removes the file");
        assert!(HostLock::try_acquire(&path)?.is_ok());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_try_acquire_replaces_a_stale_lock() -> TestResult {
        let dir = tempdir()?;
        let path = dir.join("b.lock");
        std::fs::create_dir_all(&dir)?;
        // A pid far above any real one (pid_max is at most 2^22 on Linux and
        // 99998 on macOS) stands for a process that is gone.
        std::fs::write(&path, "999999999 gone-1\n")?;
        let lock = HostLock::try_acquire(&path)?;
        #[cfg(unix)]
        assert!(lock.is_ok(), "a dead pid's lock is replaced");
        drop(lock);
        std::fs::write(&path, "garbage")?;
        assert!(HostLock::try_acquire(&path)?.is_ok(), "unparsable is stale");
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_live_holders_skips_own_and_removes_stale() -> TestResult {
        let dir = tempdir()?;
        let own = HostLock::try_acquire(&dir.join("mcp-own.lock"))?
            .map_err(|h| format!("held by {}", h.pid))?;
        let other = HostLock::try_acquire(&dir.join("mcp-other.lock"))?
            .map_err(|h| format!("held by {}", h.pid))?;
        std::fs::write(dir.join("mcp-stale.lock"), "999999999 gone-1\n")?;
        let holders = live_holders(&dir, "mcp-", Some(&own));
        assert!(holders.contains(&Holder {
            pid: std::process::id()
        }));
        // Only Unix can tell the dead pid apart; elsewhere it counts as live.
        #[cfg(unix)]
        {
            assert_eq!(holders.len(), 1, "{holders:?}");
            assert!(!dir.join("mcp-stale.lock").exists());
        }
        drop(other);
        #[cfg(unix)]
        assert!(live_holders(&dir, "mcp-", Some(&own)).is_empty());
        drop(own);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// A fresh directory under the system temp dir (no tempfile dependency).
    fn tempdir() -> io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-host-lock-{}-{}",
            std::process::id(),
            NEXT_TOKEN.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}
