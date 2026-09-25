//! Model directory discovery (issue #228).
//!
//! A command that reads an existing model and is given no `--dir` (and no
//! `BUSSARD_DIR`) finds the model the way `git` and `cargo` find their roots:
//! it looks in the working directory first, then walks up the parents.
//! `bussard.toml` is the marker because `bussard init` always writes it. When
//! nothing is found, every command works in the current directory
//! ([`DEFAULT_MODEL_DIR`]).

use std::path::{Path, PathBuf};

use crate::loader::CONFIG_FILE;

/// The model directory when discovery finds nothing, and the one `init` and
/// `import` create or update without `--dir`: the current directory.
pub const DEFAULT_MODEL_DIR: &str = ".";

/// The conventional model subdirectory of a repository root (`./knx`), which
/// discovery also looks for.
pub const NESTED_MODEL_DIR: &str = "knx";

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
/// [`DEFAULT_MODEL_DIR`], the current directory. The
/// first two answers are returned relative to `start` (`.` and `knx` when
/// `start` is `.`); a parent is returned as an absolute path.
#[must_use]
pub fn discover(start: &Path) -> Option<PathBuf> {
    if start.join(CONFIG_FILE).is_file() {
        return Some(start.to_path_buf());
    }
    let knx = rel_join(start, NESTED_MODEL_DIR);
    if knx.is_dir() {
        return Some(knx);
    }
    let absolute = std::path::absolute(start).ok()?;
    absolute.ancestors().skip(1).find_map(|dir| {
        if dir.join(CONFIG_FILE).is_file() {
            return Some(dir.to_path_buf());
        }
        let nested = dir.join(NESTED_MODEL_DIR);
        nested.join(CONFIG_FILE).is_file().then_some(nested)
    })
}

/// Whether `dir` holds a model: `bussard.toml`, `groups.toml`, `bussard.lock`
/// or a `devices/` directory (or the legacy YAML files, so their error still
/// surfaces). An absent directory, or one with none of these, is no model:
/// with the current directory as the default (issue #251 follow-up), a
/// command started in an unrelated directory must say so rather than treat it
/// as an empty model.
#[must_use]
pub fn is_model_dir(dir: &Path) -> bool {
    [
        CONFIG_FILE,
        "groups.toml",
        "bussard.lock",
        "devices",
        "bussard.yaml",
        "groups.yaml",
        "links.yaml",
    ]
    .iter()
    .any(|name| dir.join(name).exists())
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
    fn test_is_model_dir_needs_a_model_file() -> TestResult {
        let root = scratch("is-model")?;
        assert!(!is_model_dir(&root.join("absent")));
        std::fs::write(root.join("README.md"), "")?;
        assert!(!is_model_dir(&root));
        std::fs::write(root.join(CONFIG_FILE), "")?;
        assert!(is_model_dir(&root));
        std::fs::remove_dir_all(&root)?;
        Ok(())
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
