//! A restart a table write left unsent (issue #1095).
//!
//! The System B partial download of the three tables ends with a restart.
//! When the tables verified but the restart could not be sent, was refused,
//! was not confirmed, or was left to a parameter download that then failed,
//! the device holds the tables and the procedure is unfinished. A plan of the
//! device would otherwise find the tables matching and say there is nothing
//! to do. This module keeps one marker file per device under
//! `<dir>/.bussard/restart-pending/`, so the next plan offers the restart and
//! the next apply sends it. The directory is disposable state: losing it
//! loses only the reminder, never a device write.

use std::path::{Path, PathBuf};

use bussard_model::IndividualAddress;

/// The marker file of `target` in the model directory `dir`.
fn marker(dir: &Path, target: IndividualAddress) -> PathBuf {
    dir.join(".bussard")
        .join("restart-pending")
        .join(target.to_string())
}

/// Records that `target`'s restart is pending, with `why` (one line).
///
/// # Errors
///
/// The marker could not be written.
pub fn mark(dir: &Path, target: IndividualAddress, why: &str) -> std::io::Result<()> {
    let path = marker(dir, target);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{why}\n"))
}

/// Clears `target`'s pending restart; a missing marker is not an error.
///
/// # Errors
///
/// The marker exists and could not be removed.
pub fn clear(dir: &Path, target: IndividualAddress) -> std::io::Result<()> {
    match std::fs::remove_file(marker(dir, target)) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

/// Why `target`'s restart is pending, `None` when it is not.
pub fn pending(dir: &Path, target: IndividualAddress) -> Option<String> {
    std::fs::read_to_string(marker(dir, target))
        .ok()
        .map(|why| why.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("bussard-pending-{}", std::process::id()));
        let target: IndividualAddress = "1.1.7".parse()?;
        assert_eq!(pending(&dir, target), None);
        mark(&dir, target, "the restart could not be sent")?;
        assert_eq!(
            pending(&dir, target).as_deref(),
            Some("the restart could not be sent")
        );
        clear(&dir, target)?;
        clear(&dir, target)?;
        assert_eq!(pending(&dir, target), None);
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
