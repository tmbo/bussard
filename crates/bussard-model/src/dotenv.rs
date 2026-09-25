//! `BUSSARD_*` variables from a `.env` file (issue #251).
//!
//! bussard reads one `.env` file so the keyring and project passwords and the
//! other `BUSSARD_*` settings do not have to be exported before every command.
//! The CLI finds the file ([`find`]), reads it ([`read`]) and installs its
//! values once at start-up ([`install`]); every reader of a `BUSSARD_*`
//! variable then asks [`var`] / [`var_os`] instead of `std::env`.
//!
//! The rules:
//!
//! * Lookup order: `<model dir>/.env`, then `.env` in the directory that holds
//!   the model directory, then `.env` in the working directory. The first file
//!   found is used; files are never merged.
//! * A variable present in the process environment wins over the file, even
//!   when it is empty.
//! * Only `BUSSARD_*` keys are applied. [`NEVER_FROM_FILE`] lists the keys a
//!   file may not set at all: `BUSSARD_ALLOW_REAL_GATEWAY` stays flag-only or
//!   explicitly exported, so a `.env` can never open the write gate.
//! * Syntax: `KEY=value`, an optional `export ` prefix, `#` comment lines,
//!   blank lines, single or double quotes around the value. An unquoted value
//!   ends at ` #` (a trailing comment). No interpolation, no escapes.
//!
//! * [`DISABLE_ENV`] (`BUSSARD_NO_DOTENV=1`, process environment only) skips
//!   the file.
//!
//! No function here prints or logs a value.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The file name looked up in each candidate directory.
pub const FILE_NAME: &str = ".env";

/// The only key prefix a `.env` may set.
pub const PREFIX: &str = "BUSSARD_";

/// `BUSSARD_*` keys a `.env` may never set. `BUSSARD_ALLOW_REAL_GATEWAY`
/// opts a write in to a real gateway; that stays an explicit act (the flag or
/// an exported variable), so the file is ignored for it.
pub const NEVER_FROM_FILE: &[&str] = &["BUSSARD_ALLOW_REAL_GATEWAY"];

/// Set to `1` in the process environment, this skips the `.env` entirely
/// (hermetic scripts and test harnesses). A `.env` cannot set it.
pub const DISABLE_ENV: &str = "BUSSARD_NO_DOTENV";

/// Whether [`DISABLE_ENV`] is `1` in the process environment.
#[must_use]
pub fn disabled() -> bool {
    std::env::var_os(DISABLE_ENV).is_some_and(|value| value == "1")
}

/// The values installed from the `.env` file, set once per process.
static FILE_VALUES: OnceLock<BTreeMap<String, String>> = OnceLock::new();

/// Parses `.env` text into its `BUSSARD_*` assignments, in file order.
///
/// Keys without the [`PREFIX`], lines without `=`, and keys that are not
/// plain identifiers are skipped. CRLF line ends are accepted.
#[must_use]
pub fn parse(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            let valid = key.starts_with(PREFIX)
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            valid.then(|| (key.to_string(), unquote(value.trim()).to_string()))
        })
        .collect()
}

/// The value without its quotes; an unquoted value without its trailing
/// ` #` comment.
fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(rest) = value.strip_prefix(quote) {
            return rest.find(quote).map_or(rest, |end| &rest[..end]);
        }
    }
    value
        .find(" #")
        .or_else(|| value.find("\t#"))
        .map_or(value, |end| value[..end].trim_end())
}

/// The candidate `.env` files for `model_dir` and the working directory
/// `cwd`, in lookup order: the model directory, its parent, then `cwd`.
/// Duplicates (a model directory that is `cwd`) are listed once.
#[must_use]
pub fn candidates(model_dir: &Path, cwd: &Path) -> Vec<PathBuf> {
    let parent = match model_dir.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        // A relative single-component dir (`knx`) lives in `cwd`.
        _ => cwd.to_path_buf(),
    };
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in [model_dir, parent.as_path(), cwd] {
        let file = dir.join(FILE_NAME);
        let same = |seen: &PathBuf| {
            seen == &file || (std::path::absolute(seen).ok() == std::path::absolute(&file).ok())
        };
        if !out.iter().any(same) {
            out.push(file);
        }
    }
    out
}

/// The `.env` file to use: the first of [`candidates`] that is a file.
#[must_use]
pub fn find(model_dir: &Path, cwd: &Path) -> Option<PathBuf> {
    candidates(model_dir, cwd)
        .into_iter()
        .find(|file| file.is_file())
}

/// Reads and parses the `.env` file at `path`.
///
/// # Errors
///
/// The I/O error of reading the file (it names no value).
pub fn read(path: &Path) -> std::io::Result<Vec<(String, String)>> {
    Ok(parse(&std::fs::read_to_string(path)?))
}

/// What [`install`] did with a file's assignments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Installed {
    /// Keys taken from the file (not set in the process environment).
    pub applied: Vec<String>,
    /// Keys the process environment already sets; the file lost.
    pub shadowed: Vec<String>,
    /// Keys in [`NEVER_FROM_FILE`]; ignored.
    pub refused: Vec<String>,
}

/// Installs `pairs` as the process's `.env` values. A later duplicate key in
/// the file wins over an earlier one, as in a shell. Only the first call per
/// process takes effect; a later call changes nothing and returns an empty
/// report.
pub fn install(pairs: Vec<(String, String)>) -> Installed {
    let mut report = Installed::default();
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in pairs {
        if NEVER_FROM_FILE.contains(&key.as_str()) {
            report.refused.push(key);
        } else if std::env::var_os(&key).is_some() {
            report.shadowed.push(key);
        } else {
            values.insert(key, value);
        }
    }
    report.applied = values.keys().cloned().collect();
    for list in [&mut report.shadowed, &mut report.refused] {
        list.sort();
        list.dedup();
    }
    if FILE_VALUES.set(values).is_err() {
        return Installed::default();
    }
    report
}

/// `std::env::var` with the installed `.env` values as the fallback: the
/// process environment wins (even an empty value), else the file.
///
/// # Errors
///
/// [`std::env::VarError::NotPresent`] when neither sets `name`,
/// [`std::env::VarError::NotUnicode`] for a non-UTF-8 process value.
pub fn var(name: &str) -> Result<String, std::env::VarError> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => file_value(name)
            .map(str::to_string)
            .ok_or(std::env::VarError::NotPresent),
        other => other,
    }
}

/// `std::env::var_os` with the installed `.env` values as the fallback.
#[must_use]
pub fn var_os(name: &str) -> Option<OsString> {
    std::env::var_os(name).or_else(|| file_value(name).map(OsString::from))
}

/// The installed `.env` value of `name`, ignoring the process environment.
fn file_value(name: &str) -> Option<&'static str> {
    FILE_VALUES.get()?.get(name).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn pairs(text: &str) -> Vec<(String, String)> {
        parse(text)
    }

    fn kv(key: &str, value: &str) -> (String, String) {
        (key.to_string(), value.to_string())
    }

    /// A fresh, empty scratch directory for one test.
    fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
        let dir =
            std::env::temp_dir().join(format!("bussard-dotenv-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::canonicalize(&dir)
    }

    #[test]
    fn test_parse_plain_and_export_prefix() {
        assert_eq!(
            pairs("BUSSARD_A=1\nexport BUSSARD_B=two\n"),
            vec![kv("BUSSARD_A", "1"), kv("BUSSARD_B", "two")]
        );
    }

    #[test]
    fn test_parse_quotes_keep_inner_text() {
        assert_eq!(
            pairs("BUSSARD_A=\"a b # c\"\nBUSSARD_B='x=y'\nBUSSARD_C=\"\"\n"),
            vec![
                kv("BUSSARD_A", "a b # c"),
                kv("BUSSARD_B", "x=y"),
                kv("BUSSARD_C", "")
            ]
        );
    }

    #[test]
    fn test_parse_quoted_value_with_trailing_comment() {
        assert_eq!(
            pairs("BUSSARD_A=\"v\" # note\n"),
            vec![kv("BUSSARD_A", "v")]
        );
    }

    #[test]
    fn test_parse_comments_and_blank_lines() {
        assert_eq!(
            pairs("# header\n\n   \n  # BUSSARD_X=1\nBUSSARD_A=v # note\nBUSSARD_B=p#ss\n"),
            vec![kv("BUSSARD_A", "v"), kv("BUSSARD_B", "p#ss")]
        );
    }

    #[test]
    fn test_parse_ignores_non_bussard_keys() {
        assert_eq!(
            pairs("HA_TOKEN=secret\nPATH=/x\nBUSSARDX=1\nBUSSARD_OK=1\nBUSSARD_BAD KEY=1\n"),
            vec![kv("BUSSARD_OK", "1")]
        );
    }

    #[test]
    fn test_parse_crlf_line_ends() {
        assert_eq!(
            pairs("BUSSARD_A=1\r\nBUSSARD_B=\"q\"\r\n"),
            vec![kv("BUSSARD_A", "1"), kv("BUSSARD_B", "q")]
        );
    }

    #[test]
    fn test_parse_no_interpolation() {
        assert_eq!(
            pairs("BUSSARD_A=$HOME/${USER}\n"),
            vec![kv("BUSSARD_A", "$HOME/${USER}")]
        );
    }

    #[test]
    fn test_parse_spaces_around_equals_and_missing_equals() {
        assert_eq!(
            pairs("BUSSARD_A = spaced \nBUSSARD_B\n"),
            vec![kv("BUSSARD_A", "spaced")]
        );
    }

    #[test]
    fn test_candidates_order_model_parent_cwd() {
        let got = candidates(Path::new("/r/knx"), Path::new("/w"));
        assert_eq!(
            got,
            vec![
                PathBuf::from("/r/knx/.env"),
                PathBuf::from("/r/.env"),
                PathBuf::from("/w/.env")
            ]
        );
    }

    #[test]
    fn test_candidates_relative_default_dir_dedups_cwd() {
        let got = candidates(Path::new("knx"), Path::new("."));
        assert_eq!(
            got,
            vec![PathBuf::from("knx/.env"), PathBuf::from("./.env")]
        );
    }

    #[test]
    fn test_find_prefers_model_dir() -> TestResult {
        let root = scratch("model-first")?;
        let model = root.join("knx");
        let cwd = root.join("work");
        std::fs::create_dir_all(&model)?;
        std::fs::create_dir_all(&cwd)?;
        for dir in [&model, &root, &cwd] {
            std::fs::write(dir.join(FILE_NAME), "BUSSARD_A=1\n")?;
        }
        assert_eq!(find(&model, &cwd), Some(model.join(FILE_NAME)));
        std::fs::remove_file(model.join(FILE_NAME))?;
        assert_eq!(find(&model, &cwd), Some(root.join(FILE_NAME)));
        std::fs::remove_file(root.join(FILE_NAME))?;
        assert_eq!(find(&model, &cwd), Some(cwd.join(FILE_NAME)));
        std::fs::remove_file(cwd.join(FILE_NAME))?;
        assert_eq!(find(&model, &cwd), None);
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn test_find_ignores_a_directory_named_env() -> TestResult {
        let root = scratch("env-dir")?;
        let model = root.join("knx");
        std::fs::create_dir_all(model.join(FILE_NAME))?;
        std::fs::write(root.join(FILE_NAME), "BUSSARD_A=1\n")?;
        assert_eq!(find(&model, &root), Some(root.join(FILE_NAME)));
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    /// The one test that installs: the install is once per process, and
    /// nextest runs each test in its own process.
    #[test]
    fn test_install_precedence_and_refusal() -> TestResult {
        // A key no test process exports.
        let exported = std::env::vars()
            .map(|(key, _)| key)
            .find(|key| key.starts_with(PREFIX));
        let mut input = vec![
            kv("BUSSARD_DOTENV_TEST_ONLY", "from-file"),
            kv("BUSSARD_ALLOW_REAL_GATEWAY", "1"),
        ];
        if let Some(key) = &exported {
            input.push(kv(key, "from-file"));
        }
        let report = install(input);
        assert_eq!(report.applied, vec!["BUSSARD_DOTENV_TEST_ONLY".to_string()]);
        assert_eq!(
            report.refused,
            vec!["BUSSARD_ALLOW_REAL_GATEWAY".to_string()]
        );
        assert_eq!(var("BUSSARD_DOTENV_TEST_ONLY")?, "from-file");
        assert_eq!(
            var_os("BUSSARD_DOTENV_TEST_ONLY"),
            Some(OsString::from("from-file"))
        );
        // The refused key never reaches the fallback.
        assert_eq!(file_value("BUSSARD_ALLOW_REAL_GATEWAY"), None);
        if let Some(key) = &exported {
            assert_eq!(report.shadowed, vec![key.clone()]);
            assert_eq!(var_os(key), std::env::var_os(key));
        }
        // A second install changes nothing.
        let again = install(vec![kv("BUSSARD_DOTENV_TEST_ONLY", "other")]);
        assert_eq!(again, Installed::default());
        assert_eq!(var("BUSSARD_DOTENV_TEST_ONLY")?, "from-file");
        Ok(())
    }
}
