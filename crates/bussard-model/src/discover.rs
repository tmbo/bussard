//! Model directory discovery (issue #228).
//!
//! A command that reads an existing model and is given no `--dir` (and no
//! `BUSSARD_DIR`) finds the model the way `git` and `cargo` find their roots:
//! it looks in the working directory first, then walks up the parents.
//! `bussard.toml` is the marker because `bussard init` always writes it.

use std::path::{Path, PathBuf};

use crate::loader::CONFIG_FILE;

/// The model directory name every command used before discovery existed, and
/// still the default when nothing is found (and for commands that create a
/// model: `init`, `import`).
pub const DEFAULT_MODEL_DIR: &str = "knx";

/// Finds the model directory for a command started in `start`.
///
/// In order:
///
/// 1. `start` itself when it holds `bussard.toml` (the command runs inside the
///    model);
/// 2. `start/knx` when that directory exists (the repository root, the layout
///    every command defaulted to before discovery);
/// 3. each parent of `start`, nearest first: the parent itself when it holds
///    `bussard.toml`, else its `knx/` when that holds `bussard.toml`.
///
/// Returns `None` when none matches; the caller then falls back to
/// [`DEFAULT_MODEL_DIR`], so the "no model" errors stay as they were. The
/// first two answers are returned relative to `start` (`.` and `knx` when
/// `start` is `.`); a parent is returned as an absolute path.
#[must_use]
pub fn discover(start: &Path) -> Option<PathBuf> {
    if start.join(CONFIG_FILE).is_file() {
        return Some(start.to_path_buf());
    }
    let knx = rel_join(start, DEFAULT_MODEL_DIR);
    if knx.is_dir() {
        return Some(knx);
    }
    let absolute = std::path::absolute(start).ok()?;
    absolute.ancestors().skip(1).find_map(|dir| {
        if dir.join(CONFIG_FILE).is_file() {
            return Some(dir.to_path_buf());
        }
        let nested = dir.join(DEFAULT_MODEL_DIR);
        nested.join(CONFIG_FILE).is_file().then_some(nested)
    })
}

/// `start/name`, spelled `name` when `start` is the working directory, so a
/// discovered `knx` prints exactly as the old default did.
fn rel_join(start: &Path, name: &str) -> PathBuf {
    if start.as_os_str().is_empty() || start == Path::new(".") {
        PathBuf::from(name)
    } else {
        start.join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A fresh, empty scratch directory for one test.
    fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
        let dir =
            std::env::temp_dir().join(format!("bussard-discover-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        // Resolve symlinks (macOS /var -> /private/var) so answers compare.
        std::fs::canonicalize(&dir)
    }

    #[test]
    fn test_discover_cwd_is_the_model() -> TestResult {
        let root = scratch("cwd-model")?;
        std::fs::write(root.join(CONFIG_FILE), "")?;
        assert_eq!(discover(&root), Some(root.clone()));
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn test_discover_cwd_holds_knx() -> TestResult {
        let root = scratch("cwd-knx")?;
        std::fs::create_dir_all(root.join("knx"))?;
        assert_eq!(discover(&root), Some(root.join("knx")));
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn test_discover_cwd_is_a_subdirectory_of_the_model() -> TestResult {
        let root = scratch("subdir")?;
        std::fs::write(root.join(CONFIG_FILE), "")?;
        let deep = root.join("devices").join("nested");
        std::fs::create_dir_all(&deep)?;
        assert_eq!(discover(&deep), Some(root.clone()));
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn test_discover_parent_holds_knx_model() -> TestResult {
        let root = scratch("parent-knx")?;
        std::fs::create_dir_all(root.join("knx"))?;
        std::fs::write(root.join("knx").join(CONFIG_FILE), "")?;
        let docs = root.join("docs");
        std::fs::create_dir_all(&docs)?;
        assert_eq!(discover(&docs), Some(root.join("knx")));
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn test_discover_no_model_anywhere() -> TestResult {
        let root = scratch("none")?;
        let deep = root.join("a").join("b");
        std::fs::create_dir_all(&deep)?;
        // The temp dir's own parents hold no model on a sane machine; guard
        // anyway so a stray `bussard.toml` there does not fail the test.
        let stray = root
            .ancestors()
            .skip(1)
            .any(|d| d.join(CONFIG_FILE).is_file() || d.join("knx").join(CONFIG_FILE).is_file());
        if !stray {
            assert_eq!(discover(&deep), None);
        }
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn test_discover_relative_start_keeps_old_spelling() {
        assert_eq!(rel_join(Path::new("."), "knx"), PathBuf::from("knx"));
        assert_eq!(rel_join(Path::new(""), "knx"), PathBuf::from("knx"));
        assert_eq!(rel_join(Path::new("a"), "knx"), PathBuf::from("a/knx"));
    }
}
