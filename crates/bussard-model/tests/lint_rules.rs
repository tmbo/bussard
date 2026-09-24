//! Integration tests for the opt-in topology and convention lints (issue #102).
//!
//! Two guarantees are asserted here:
//!
//! 1. Every `L0xx` code has a fixture that triggers exactly it.
//! 2. No model in the repository that lacks a `lint:` block gains a lint
//!    warning, so turning the feature on cannot change an existing project.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

use bussard_model::{Model, validate_in_dir};

/// Every lint code, with the fixture directory named after it.
const CODES: &[&str] = &[
    "L001", "L002", "L003", "L004", "L005", "L006", "L007", "L008",
];

/// The `tests/fixtures/lint` directory.
fn lint_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lint")
}

/// The repository root (three levels above this crate's manifest).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The `L0xx` codes a directory's model produces.
fn lint_codes(dir: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let model = Model::load(dir)?;
    Ok(validate_in_dir(&model, dir)
        .into_iter()
        .filter(|d| d.code.starts_with('L'))
        .map(|d| d.code.to_string())
        .collect())
}

#[test]
fn test_every_lint_code_has_a_fixture_that_triggers_it() -> Result<(), Box<dyn Error>> {
    for code in CODES {
        let dir = lint_fixtures().join(code);
        assert!(dir.is_dir(), "missing fixture directory for {code}");
        let codes = lint_codes(&dir)?;
        let expected: BTreeSet<String> = [(*code).to_string()].into_iter().collect();
        assert_eq!(
            codes, expected,
            "fixture {code} must trigger exactly {code}"
        );
    }
    Ok(())
}

/// Collects every directory under `root` that holds a `groups.toml`, skipping
/// build output and VCS metadata.
fn model_dirs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut has_groups = false;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), "target" | ".git" | "node_modules") {
                continue;
            }
            subdirs.push(path);
        } else if name == "groups.toml" {
            has_groups = true;
        }
    }
    if has_groups {
        out.push(root.to_path_buf());
    }
    for sub in subdirs {
        model_dirs(&sub, out);
    }
}

#[test]
fn test_models_without_a_lint_block_gain_no_warnings() -> Result<(), Box<dyn Error>> {
    let mut dirs = Vec::new();
    model_dirs(&repo_root(), &mut dirs);
    assert!(
        dirs.len() >= 3,
        "expected to find several fixture models, found {dirs:?}"
    );

    let mut checked = 0usize;
    for dir in dirs {
        let Ok(model) = Model::load(&dir) else {
            continue;
        };
        if model.config.lint.is_some() {
            continue;
        }
        checked += 1;
        let codes = lint_codes(&dir)?;
        assert!(
            codes.is_empty(),
            "{} has no lint: block but produced {codes:?}",
            dir.display()
        );
    }
    assert!(checked >= 2, "expected to check several lint-free models");
    Ok(())
}
