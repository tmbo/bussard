//! A clean ETS import validates clean (issue #348): `bussard import` of every
//! corpus project, then `bussard validate`, reports zero errors and zero
//! warnings, unless the project's expectation file lists them.
//!
//! Gated on `BUSSARD_ETS_PROJECTS`, a directory of `.knxproj` exports (else
//! the single export `BUSSARD_ETS_PROJECT` names), and skips green without
//! it. A project is imported with `BUSSARD_PROJECT_PASSWORD`; a keyring
//! `<stem>.knxkeys` next to it is imported into the key store with
//! `BUSSARD_KEYRING_PASSWORD`, so the keyring rules run against it.
//!
//! A project with a genuine problem at the ETS level (a device ETS set up for
//! Secure but never downloaded, a group address without a type) carries an
//! expectation file: `<stem>.expect` next to the export, else
//! `tests/fixtures/import-clean/<stem>.expect` with every character outside
//! `[A-Za-z0-9._-]` of the stem replaced by `_`. One `CODE location` line per
//! expected error or warning, `#` starts a comment. The test fails on a
//! diagnostic the file does not list and on a listed one that is gone, so the
//! file stays accurate. The corpus is only read: each export is copied into a
//! temporary directory first.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The corpus exports, or `None` when the corpus is not configured.
fn corpus() -> TestResult<Option<Vec<PathBuf>>> {
    if let Some(dir) = std::env::var_os("BUSSARD_ETS_PROJECTS") {
        let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "knxproj"))
            .collect();
        found.sort();
        return Ok(Some(found));
    }
    Ok(std::env::var_os("BUSSARD_ETS_PROJECT").map(|p| vec![PathBuf::from(p)]))
}

/// The stem with every character outside `[A-Za-z0-9._-]` replaced by `_`.
fn sanitized(stem: &str) -> String {
    stem.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The expected `CODE location` lines of `project`: its `.expect` file next to
/// it, else the committed one, else none.
fn expectations(project: &Path) -> TestResult<BTreeSet<String>> {
    let stem = project
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("project file has no stem")?;
    let beside = project.with_extension("expect");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/import-clean")
        .join(format!("{}.expect", sanitized(stem)));
    let file = [beside, committed].into_iter().find(|p| p.is_file());
    let Some(file) = file else {
        return Ok(BTreeSet::new());
    };
    Ok(std::fs::read_to_string(&file)?
        .lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Imports `project` into a fresh temporary model and returns the errors and
/// warnings of `validate` as `CODE location` lines.
fn import_and_validate(project: &Path, work: &Path) -> TestResult<BTreeSet<String>> {
    let stem = project
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("project file has no stem")?;
    let source = work.join("source");
    std::fs::create_dir_all(&source)?;
    let copy = source.join("project.knxproj");
    std::fs::copy(project, &copy)?;
    let keyring = project.with_file_name(format!("{stem}.knxkeys"));
    if keyring.is_file() {
        std::fs::copy(&keyring, source.join("project.knxkeys"))?;
    }
    let model = work.join("model");
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("import")
        .arg(&copy)
        .args(["--yes", "--dir"])
        .arg(&model)
        .current_dir(work)
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "import of {} failed: {}",
            project.display(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["validate", "--json", "--dir"])
        .arg(&model)
        .current_dir(work)
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(doc["diagnostics"]
        .as_array()
        .ok_or("validate --json prints a diagnostics array")?
        .iter()
        .filter(|d| d["severity"] != "info")
        .map(|d| {
            format!(
                "{} {}",
                d["code"].as_str().unwrap_or_default(),
                d["location"].as_str().unwrap_or_default()
            )
        })
        .collect())
}

#[test]
fn test_import_corpus_validates_clean() -> TestResult {
    let Some(projects) = corpus()? else {
        eprintln!("skipping: set BUSSARD_ETS_PROJECTS (or BUSSARD_ETS_PROJECT) to run");
        return Ok(());
    };
    let mut failures = Vec::new();
    for project in &projects {
        let work = std::env::temp_dir().join(format!(
            "bussard-import-clean-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let found = import_and_validate(project, &work)?;
        let expected = expectations(project)?;
        let unexpected: Vec<&String> = found.difference(&expected).collect();
        let gone: Vec<&String> = expected.difference(&found).collect();
        if !unexpected.is_empty() || !gone.is_empty() {
            failures.push(format!(
                "{}: unexpected {unexpected:?}, expected but gone {gone:?}",
                project.display()
            ));
        }
        let _ = std::fs::remove_dir_all(&work);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}
