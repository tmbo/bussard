//! Which `bussard mcp` processes serve a model directory on this host
//! (issue #287).
//!
//! Claude Desktop starts two server processes for one configured entry (the
//! app and its remote-devices bridge). Each opens its own bus connection, and
//! before the tunnel-user locks both could take the key store's first user.
//! The server marks itself in `<dir>/.bussard/instances/` while it runs and
//! warns at start about another live one; it never refuses to start, since
//! the second process is legitimate.

use std::path::{Path, PathBuf};

use bussard_transport::host_lock::{self, HostLock};

/// The prefix of an instance lock file.
const PREFIX: &str = "mcp-";

/// The directory of the instance marks for `dir`.
fn instances_dir(dir: &Path) -> PathBuf {
    dir.join(".bussard").join("instances")
}

/// Marks this process as serving `dir` and warns about every other live
/// `bussard mcp` doing the same. The mark lasts as long as the returned lock;
/// `None` when the directory cannot be written (nothing to warn about then).
pub fn register(dir: &Path) -> Option<HostLock> {
    let path = instances_dir(dir).join(format!("{PREFIX}{}.lock", std::process::id()));
    let lock = match HostLock::try_acquire(&path) {
        Ok(Ok(lock)) => lock,
        Ok(Err(_)) | Err(_) => return None,
    };
    for holder in host_lock::live_holders(&instances_dir(dir), PREFIX, Some(&lock)) {
        tracing::warn!(
            "another bussard mcp (pid {}) serves the model directory {} on this host; both \
             hold their own bus connection. That is expected when the client starts two \
             servers for one entry; each picks a different tunnelling user from the key \
             store when it lists several",
            holder.pid,
            dir.display()
        );
    }
    Some(lock)
}

/// The pids of the other live `bussard mcp` processes serving `dir`.
pub fn other_instances(dir: &Path) -> Vec<u32> {
    let own = std::process::id();
    host_lock::live_holders(&instances_dir(dir), PREFIX, None)
        .into_iter()
        .map(|h| h.pid)
        .filter(|&pid| pid != own)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_marks_this_process_and_hides_it_from_others() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let lock = register(dir.path()).ok_or_else(|| anyhow::anyhow!("no lock"))?;
        assert!(lock.path().exists());
        assert!(
            other_instances(dir.path()).is_empty(),
            "this process is not another"
        );
        // A live foreign pid (the parent shell, say) would be listed; a dead
        // one is cleaned up.
        std::fs::write(
            instances_dir(dir.path()).join("mcp-999999999.lock"),
            "999999999 gone-1\n",
        )?;
        #[cfg(unix)]
        assert!(other_instances(dir.path()).is_empty());
        drop(lock);
        Ok(())
    }
}
